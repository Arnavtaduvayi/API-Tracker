//! The loopback listener: bind, accept, cap, dispatch, shut down.
//!
//! SI-1 is enforced structurally — the bind address is a hard-coded loopback
//! constant with no configuration surface, and a source-level guard test
//! fails the build if a wildcard address ever appears in this crate.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use api_tracker_core::error::{CoreError, Result};

use crate::forward::{self, BodyTap, Gateway, NoTap};
use crate::record::counters;

/// Builds the bounded usage tap for a provider's declared response shape,
/// given whether the response is a stream and whether it is compressed.
pub type TapFactory = Arc<dyn Fn(&str, bool, bool) -> Box<dyn BodyTap> + Send + Sync>;

/// The production tap factory: a bounded extractor for a provider shape the
/// manifest declares, and nothing at all for any other shape.
pub fn usage_tap_factory() -> TapFactory {
    Arc::new(|shape: &str, streaming: bool, compressed: bool| {
        match crate::usage::Shape::parse(shape) {
            Some(shape) => Box::new(crate::usage::UsageExtractor::new(
                shape, streaming, compressed,
            )) as Box<dyn BodyTap>,
            None => Box::new(NoTap) as Box<dyn BodyTap>,
        }
    })
}

/// How often the accept loop wakes to observe the shutdown flag.
///
/// This is also the worst-case ACCEPT latency for a fresh connection (the
/// listener is non-blocking so shutdown stays observable without a signal
/// dependency). Phase 3 perf measurement showed the original 50ms adding
/// ~25ms average connection-setup latency for non-pooled clients (curl,
/// one-shot scripts); 5ms keeps the idle wake cost negligible while making
/// connection setup imperceptible. Keep-alive SDK traffic never sees this.
const ACCEPT_POLL: Duration = Duration::from_millis(5);

/// How long a clean stop waits for in-flight exchanges before abandoning
/// them. Long enough that a normal streamed response completes; short enough
/// that one stuck peer cannot hold the process open.
pub const SHUTDOWN_DRAIN: Duration = Duration::from_secs(30);

/// The ONLY address this gateway ever binds. Not configurable, by design.
pub const BIND_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A bound, not-yet-serving listener. Binding separately from serving lets
/// the caller learn the actual port (port 0 = ephemeral) and lets `enable`
/// fail honestly on `EADDRINUSE` instead of a service crash-loop.
#[derive(Debug)]
pub struct Listener {
    listener: TcpListener,
    port: u16,
}

impl Listener {
    pub fn bind(port: u16) -> Result<Self> {
        let addr = SocketAddr::new(BIND_IP, port);
        let listener = TcpListener::bind(addr).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                CoreError::InvalidInput(format!(
                    "loopback port {port} is already in use; another process holds it"
                ))
            } else {
                CoreError::Io(e)
            }
        })?;
        let port = listener.local_addr().map_err(CoreError::Io)?.port();
        listener.set_nonblocking(true).map_err(CoreError::Io)?;
        Ok(Self { listener, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Serve until `gateway.shutdown` is set. Each connection is handled on its
/// own thread; connections over the cap receive an immediate 503 rather than
/// queueing without bound (SI-14).
pub fn serve(gateway: Gateway, listener: Listener) {
    serve_with_taps(
        gateway,
        listener,
        Arc::new(|_shape: &str, _streaming: bool, _compressed: bool| {
            Box::new(NoTap) as Box<dyn BodyTap>
        }),
    )
}

/// Like [`serve`], with a factory that builds the bounded usage tap for a
/// provider's declared response shape.
pub fn serve_with_taps(gateway: Gateway, listener: Listener, tap_factory: TapFactory) {
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();
    loop {
        if gateway.shutdown.load(Ordering::Relaxed) {
            break;
        }
        match listener.listener.accept() {
            Ok((stream, peer)) => {
                if !peer.ip().is_loopback() {
                    // Unreachable through a loopback bind, but refused
                    // explicitly so the invariant does not depend on the OS.
                    drop(stream);
                    continue;
                }
                let in_flight = gateway.connections.fetch_add(1, Ordering::AcqRel) + 1;
                if in_flight > gateway.max_connections {
                    gateway.connections.fetch_sub(1, Ordering::AcqRel);
                    gateway.sink.count("", counters::CONNECTION_CAP_REACHED);
                    reject_over_cap(stream);
                    continue;
                }
                let gw = gateway.clone();
                let taps = tap_factory.clone();
                match thread::Builder::new()
                    .name("tethra-gateway-conn".into())
                    .spawn(move || {
                        let _guard = ConnectionGuard(gw.connections.clone());
                        let _ = stream.set_nonblocking(false);
                        forward::serve_connection(&gw, stream, &*taps);
                    }) {
                    Ok(h) => handles.push(h),
                    Err(_) => {
                        gateway.connections.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                handles.retain(|h| !h.is_finished());
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(_) => thread::sleep(ACCEPT_POLL),
        }
    }
    // Graceful shutdown: stop accepting, then let in-flight exchanges finish
    // so a clean stop never severs a streaming response mid-body. The drain
    // is BOUNDED: every connection already carries read and write timeouts,
    // so a well-behaved exchange finishes quickly, and a stuck one must not
    // hold the process open forever. Threads still running at the deadline
    // are abandoned (their sockets close when the process exits) and the
    // count is reported rather than hidden.
    let deadline = Instant::now() + SHUTDOWN_DRAIN;
    let mut abandoned = 0usize;
    for h in handles {
        loop {
            if h.is_finished() {
                let _ = h.join();
                break;
            }
            if Instant::now() >= deadline {
                abandoned += 1;
                break;
            }
            thread::sleep(ACCEPT_POLL);
        }
    }
    if abandoned > 0 {
        gateway
            .sink
            .count("", counters::SHUTDOWN_ABANDONED_CONNECTIONS);
    }
}

struct ConnectionGuard(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reject_over_cap(mut stream: TcpStream) {
    let body = b"tethra-gateway: too many concurrent connections; try again shortly.\n";
    let head = format!(
        "HTTP/1.1 503 Service Unavailable\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.set_nonblocking(false);
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_is_loopback_and_reports_its_port() {
        let l = Listener::bind(0).unwrap();
        let addr = l.listener.local_addr().unwrap();
        assert!(
            addr.ip().is_loopback(),
            "the listener must be loopback-only"
        );
        assert_eq!(addr.port(), l.port());
        assert_ne!(l.port(), 0);
    }

    #[test]
    fn a_held_port_reports_an_actionable_error_not_a_panic() {
        let first = Listener::bind(0).unwrap();
        let port = first.port();
        let err = Listener::bind(port).unwrap_err();
        assert!(format!("{err}").contains("already in use"), "got: {err}");
    }
}
