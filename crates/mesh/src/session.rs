//! One replication exchange over an authenticated channel: drives
//! `core::mesh::proto::Session`, applies its `Commit` through the store, mints
//! fork reports, and hands `Direct` messages to [`crate::directs`].
//!
//! A writer thread sends frames while this thread reads: both sides stream at
//! once (push-pull), and two blocking writers could otherwise fill each
//! other's socket buffers and wait forever. The store is locked only around
//! each step of the state machine, never across network I/O.
//!
//! Bounds: the read timeout is the idle timeout (30 s), the exchange ends at
//! the wall-time limit (10 min), frames are ≤ 1 MiB (`wire`), and the state
//! machine bounds everything it stages (`proto::Limits`).

use crate::directs;
use crate::error::{NetError, NetResult};
use crate::node::MeshNode;
use crate::wire::{FrameReader, FrameWriter};
use api_tracker_core::mesh::kinds::ForkReport;
use api_tracker_core::mesh::proto::{Action, Body, CloseReason, DirectMsg, Frame, Limits, Session};
use api_tracker_core::mesh::store::{Draft, ForkEvidence, HlcPolicy, MeshStore};
use api_tracker_core::mesh::DeviceId;
use serde::Serialize;
use std::sync::mpsc;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }
}

/// What one exchange did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExchangeReport {
    pub peer: DeviceId,
    pub direction: Direction,
    /// Items (main path and repair) this side committed from the peer.
    pub items_in: u64,
    /// Items this side sent.
    pub items_out: u64,
    pub duration_ms: u64,
    /// `None` when both sides finished; otherwise a static reason.
    pub aborted: Option<&'static str>,
}

/// Mint a `fork.report` unless the roster already records the fork at this
/// seq or lower (PROTOCOL.md §7.2).
pub(crate) fn report_fork(node: &MeshNode, ev: ForkEvidence) -> NetResult<()> {
    let mut store = node.store();
    if store
        .state()
        .roster
        .fork_seq(&ev.origin)
        .is_some_and(|f| f <= ev.seq)
    {
        return Ok(());
    }
    let report = ForkReport {
        device: ev.origin,
        seq: ev.seq,
        hash_a: ev.ours,
        hash_b: ev.theirs,
    };
    store.mint(
        node.keys().signing_key(),
        Draft::of(&report, HlcPolicy::Now),
    )?;
    Ok(())
}

/// Run one exchange to completion (or to its first error) on `reader` and
/// `writer`, with `peer` already authenticated.
pub fn exchange(
    node: &MeshNode,
    mut reader: FrameReader,
    writer: FrameWriter,
    peer: DeviceId,
    direction: Direction,
) -> ExchangeReport {
    let started = Instant::now();
    let limits = node.limits();
    let mut report = ExchangeReport {
        peer,
        direction,
        items_in: 0,
        items_out: 0,
        duration_ms: 0,
        aborted: None,
    };
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let writer_thread = std::thread::spawn(move || {
        let mut writer = writer;
        for frame in rx {
            if writer.send(&frame).is_err() {
                break;
            }
        }
        writer.shutdown();
    });
    let mut held_keys: Vec<DirectMsg> = Vec::new();
    let result = (|| -> NetResult<()> {
        reader.set_read_timeout(Some(limits.idle_timeout))?;
        let mut session = Session::new(Limits::default(), Some(peer));
        let mut actions = {
            let store = node.store();
            session.start(&*store)
        };
        // Every session carries this side's current access key, so a
        // rotation reaches every member through whoever it talks to.
        let (epoch, key) = node.access_keys()?.current;
        actions.extend(session.direct(DirectMsg::AccessKeyUpdate { epoch, key }));
        loop {
            let mut done = false;
            for act in actions {
                match act {
                    Action::Send(f) => {
                        if let Body::Items(i) = &f.body {
                            report.items_out += i.batch.len() as u64;
                        }
                        let bytes = f
                            .encode()
                            .map_err(|_| NetError::Session("a frame did not encode"))?;
                        tx.send(bytes)
                            .map_err(|_| NetError::Session("the connection closed"))?;
                    }
                    Action::Commit(batch) => {
                        let n = (batch.items.len() + batch.repair.len()) as u64;
                        let out = node.store().commit(batch)?;
                        report.items_in += n;
                        for ev in out.forks {
                            report_fork(node, ev)?;
                        }
                    }
                    Action::ForkDetected(ev) => report_fork(node, ev)?,
                    Action::Direct(msg) => held_keys.extend(directs::handle(node, peer, msg)?),
                    Action::Close(CloseReason::Done) => done = true,
                    Action::Close(CloseReason::PeerBye(_)) => {
                        return Err(NetError::Session("the peer ended the exchange"))
                    }
                    Action::Close(CloseReason::Aborted(why)) => return Err(NetError::Session(why)),
                }
            }
            if done {
                return Ok(());
            }
            if started.elapsed() > limits.max_session {
                return Err(NetError::Session("the exchange took too long"));
            }
            let bytes = reader.recv().map_err(|e| match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    NetError::Session("the peer went idle")
                }
                std::io::ErrorKind::InvalidData => NetError::Session("a malformed frame"),
                _ => NetError::Session("the connection closed"),
            })?;
            let frame =
                Frame::decode(&bytes).map_err(|_| NetError::Session("a malformed frame"))?;
            actions = {
                let store = node.store();
                session.on_frame(frame, &*store)
            };
        }
    })();
    drop(tx);
    let _ = writer_thread.join();
    // Now that whatever the peer sent is committed, the roster knows the
    // removals that justify a rotated key (or the key stays unapplied).
    for msg in held_keys {
        let _ = directs::apply_access_key(node, msg);
    }
    report.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if let Err(e) = result {
        report.aborted = Some(e.log_text());
    }
    report
}
