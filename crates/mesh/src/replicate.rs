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
