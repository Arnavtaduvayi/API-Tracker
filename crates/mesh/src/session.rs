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
use api_tracker_core::mesh::chain::Hash32;
use api_tracker_core::mesh::kinds::ForkReport;
use api_tracker_core::mesh::peers::HelloRecord;
use api_tracker_core::mesh::proto::{Action, Body, CloseReason, DirectMsg, Frame, Limits, Session};
use api_tracker_core::mesh::store::{Draft, ForkEvidence, HlcPolicy, MeshStore};
use api_tracker_core::mesh::{DeviceId, MeshError, VersionVector};
use serde::Serialize;
use std::collections::BTreeMap;
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
    /// The peer's `Hello` beside this side's state then (lag and digest
    /// figures for `status` and `doctor`), once the peer's `Hello` arrived.
    #[serde(skip)]
    pub hello: Option<HelloRecord>,
}

/// Mint a `fork.report` unless the roster already records the fork at this
/// seq or lower (PROTOCOL.md §7.2). While this device waits to recover its
/// own items (a rollback hold), the report is left for a later exchange,
/// which detects the fork again: minting now could reuse a seq a peer holds.
pub(crate) fn report_fork(node: &MeshNode, ev: ForkEvidence) -> NetResult<()> {
    let mut store = node.store();
    if store.rollback_hold().is_some() {
        return Ok(());
    }
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
        hello: None,
    };
    let mut report_hello = None;
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
    let mut rollback_notice = false;
    let result = (|| -> NetResult<()> {
        reader.set_read_timeout(Some(limits.idle_timeout))?;
        let mut session = Session::new(Limits::default(), Some(peer));
        let (mut actions, ours) = {
            let store = node.store();
            let ours: (VersionVector, BTreeMap<DeviceId, Hash32>) = (
                store.vv().clone(),
                store
                    .vv()
                    .iter()
                    .map(|(o, _)| (*o, store.origin_digest(o)))
                    .collect(),
            );
            (session.start(&*store), ours)
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
                    Action::Direct(msg) => {
                        rollback_notice |= matches!(msg, DirectMsg::RollbackNotice { .. });
                        held_keys.extend(directs::handle(node, peer, msg)?);
                    }
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
            if report_hello.is_none() {
                report_hello = session
                    .peer_hello()
                    .map(|h| hello_record(node, &ours.0, &ours.1, &h.vv, &h.digests));
            }
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
    match result {
        // A completed exchange in which the peer did not report a rollback
        // again settles its earlier report (it holds nothing past this
        // device's log any more). A repeated report stays until the items
        // are back: one exchange carries at most 50 000 of them.
        Ok(()) if !rollback_notice => {
            let _ = node.store().settle_rollback_holds(peer);
        }
        Ok(()) => {}
        Err(e) => report.aborted = Some(e.log_text()),
    }
    report.hello = report_hello.map(|mut h| {
        h.completed = report.aborted.is_none();
        h
    });
    report
}

/// The lag and digest record of one exchange (`core::mesh::peers`).
fn hello_record(
    node: &MeshNode,
    our_vv: &VersionVector,
    our_digests: &BTreeMap<DeviceId, Hash32>,
    peer_vv: &VersionVector,
    peer_digests: &BTreeMap<DeviceId, Hash32>,
) -> HelloRecord {
    let digest_mismatches = our_vv
        .iter()
        .filter(|(o, s)| peer_vv.get(o) == **s && peer_digests.get(*o) != our_digests.get(*o))
        .map(|(o, _)| *o)
        .collect();
    HelloRecord {
        at_ms: node.clock().now_ms(),
        completed: false,
        peer_vv: peer_vv.iter().map(|(o, s)| (*o, *s)).collect(),
        our_vv: our_vv.iter().map(|(o, s)| (*o, *s)).collect(),
        digest_mismatches,
    }
}

/// Whether an error means this device may not mint now (a hold or an
/// untrusted identity), as opposed to a failure worth reporting.
pub fn is_mint_refusal(e: &NetError) -> bool {
    matches!(
        e,
        NetError::Core(api_tracker_core::CoreError::Mesh(
            MeshError::RollbackHold | MeshError::IdentityMismatch(_) | MeshError::Forked
        ))
    )
}
