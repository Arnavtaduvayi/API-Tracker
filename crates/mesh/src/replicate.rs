//! A one-shot outbound exchange (`tethra mesh replicate --peer`, and each
//! exchange of a node's round), and what every exchange records: a row of
//! `mesh_exchange_log` and the peer's last `Hello` (lag, `core::mesh::peers`).

use crate::error::{NetError, NetResult};
use crate::handshake;
use crate::node::MeshNode;
use crate::session::{exchange, Direction, ExchangeReport};
use crate::wire;
use api_tracker_core::mesh::membership::{self, ExchangeRecord};
use api_tracker_core::mesh::peers;
use std::net::{TcpStream, ToSocketAddrs};

/// Record an exchange; a failure to log never fails the exchange.
pub(crate) fn log(node: &MeshNode, report: &ExchangeReport) {
    let rec = ExchangeRecord {
        peer_device: Some(report.peer),
        direction: report.direction.as_str(),
        items_in: report.items_in,
        items_out: report.items_out,
        result: if report.aborted.is_none() {
            "ok"
        } else {
            "aborted"
        },
        error: report.aborted,
    };
    let store = node.store();
    let _ = membership::log_exchange(store.connection(), &rec);
    if let Some(hello) = &report.hello {
        let _ = peers::record_hello(store.connection(), &report.peer, hello);
    }
}

/// Prepare an authenticated stream for an exchange: idle timeouts, halves.
pub(crate) fn channel(
    stream: TcpStream,
    state: snow::StatelessTransportState,
    node: &MeshNode,
) -> NetResult<(wire::FrameReader, wire::FrameWriter)> {
    stream.set_read_timeout(Some(node.limits().idle_timeout))?;
    stream.set_write_timeout(Some(node.limits().idle_timeout))?;
    Ok(wire::split(stream, state)?)
}

/// The first of `socks` that accepts a TCP connection.
pub(crate) fn connect_any(
    socks: &[std::net::SocketAddr],
    timeout: std::time::Duration,
    last: &mut NetError,
) -> Option<TcpStream> {
    for s in socks {
        match TcpStream::connect_timeout(s, timeout) {
            Ok(stream) => return Some(stream),
            Err(e) => *last = e.into(),
        }
    }
    None
}

/// Dial `addr`, authenticate, run one exchange. The current access key is
/// tried first, then the previous one while it is in its 30-day grace period
/// (the peer may not have heard of a rotation yet).
pub fn replicate_once(node: &MeshNode, addr: &str) -> NetResult<ExchangeReport> {
    let socks: Vec<_> = addr
        .to_socket_addrs()
        .map_err(|_| NetError::Io(std::io::ErrorKind::NotFound))?
        .collect();
    let keys = node.access_keys()?;
    let mut last = NetError::Io(std::io::ErrorKind::NotFound);
    for (_, key) in std::iter::once(&keys.current).chain(keys.previous.as_ref()) {
        // Every resolved address (`localhost` is [::1] and 127.0.0.1).
        let Some(mut stream) = connect_any(&socks, node.limits().handshake_timeout, &mut last)
        else {
            continue;
        };
        match handshake::initiate(&mut stream, node, key) {
            Ok((state, peer)) => {
                let (r, w) = channel(stream, state, node)?;
                let report = exchange(node, r, w, peer, Direction::Outbound);
                log(node, &report);
                return Ok(report);
            }
            Err(e @ NetError::Handshake(_)) | Err(e @ NetError::Io(_)) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// What [`replicate_known_peers`] did.
#[derive(Clone, Debug, serde::Serialize)]
pub struct OneShotReport {
    pub exchanges: Vec<crate::instance::ExchangeSummary>,
    /// Problems before the exchanges (usage not published, caps not
    /// reconciled); static text and error messages, never values.
    pub notes: Vec<String>,
}

/// Exchange once with `peer`, or with every known peer address, without a
/// running node (`tethra mesh replicate` and the desktop's "Replicate now"
/// when no node runs for the data directory). Usage is published and spend
/// caps reconciled first, so the exchanges carry fresh figures; a failure
/// there is a note, not an error. With no peer to dial nothing is done and
/// `exchanges` is empty.
pub fn replicate_known_peers(
    vault: &api_tracker_core::vault::UnlockedVault,
    data_dir: &std::path::Path,
    peer: Option<String>,
) -> NetResult<OneShotReport> {
    let addrs = match peer {
        Some(p) => vec![p],
        None => vault.mesh_peers()?.into_iter().map(|r| r.addr).collect(),
    };
    let mut notes = Vec::new();
    if addrs.is_empty() {
        return Ok(OneShotReport {
            exchanges: Vec::new(),
            notes,
        });
    }
    if let Err(e) = vault.mesh_publish() {
        notes.push(format!("usage was not published: {e}"));
    }
    let probe = crate::node::GatewaySocket::for_vault(vault, data_dir);
    if let Err(e) = vault.mesh_cap_reconcile(&probe) {
        notes.push(format!("spend caps were not reconciled: {e}"));
    }
    let node = MeshNode::open(
        vault,
        std::sync::Arc::new(api_tracker_core::mesh::clock::SystemClock),
        crate::node::TransportLimits::default(),
    )?;
    let exchanges = addrs
        .into_iter()
        .map(|addr| match replicate_once(&node, &addr) {
            Ok(r) => crate::instance::ExchangeSummary {
                addr,
                device: Some(r.peer),
                items_in: r.items_in,
                items_out: r.items_out,
                duration_ms: r.duration_ms,
                error: r.aborted.map(str::to_owned),
            },
            Err(e) => crate::instance::ExchangeSummary {
                addr,
                device: None,
                items_in: 0,
                items_out: 0,
                duration_ms: 0,
                error: Some(e.to_string()),
            },
        })
        .collect();
    Ok(OneShotReport { exchanges, notes })
}

/// Leave the mesh (`tethra mesh leave`, the desktop's "Leave mesh"), after
/// the caller's confirmation. Reauthenticated in core
/// (`UnlockedVault::mesh_leave`). Tries to hand this device's self-removal
/// to a peer first: `extra_peers` (given explicitly), then the addresses the
/// other active devices published, one exchange each until one completes;
/// then wipes every local mesh row and the identity marker. Stop any node
/// running for this data directory first.
pub fn leave_mesh(
    vault: &api_tracker_core::vault::UnlockedVault,
    master_password: &api_tracker_core::secret::SecretString,
    extra_peers: Vec<String>,
) -> NetResult<api_tracker_core::vault::MeshLeaveReport> {
    use api_tracker_core::mesh::store::MeshStore;
    let mut peers = extra_peers;
    {
        let store = vault.mesh_open_store()?;
        let state = store.state();
        for (d, _) in state.roster.known() {
            if *d == store.self_id() || !state.roster.is_active(d) {
                continue;
            }
            if let Some(info) = state.device_info.value(d, &state.roster) {
                peers.extend(info.listen_addrs.iter().cloned());
            }
        }
    }
    Ok(vault.mesh_leave(master_password, &mut |_store| {
        let Ok(node) = MeshNode::open(
            vault,
            std::sync::Arc::new(api_tracker_core::mesh::clock::SystemClock),
            crate::node::TransportLimits::default(),
        ) else {
            return false;
        };
        peers
            .iter()
            .any(|p| replicate_once(&node, p).is_ok_and(|r| r.aborted.is_none()))
    })?)
}
