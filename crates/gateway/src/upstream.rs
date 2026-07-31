//! Upstream connections: two-phase SSRF validation, fully-verified TLS, and
//! per-(client connection, route) socket ownership.
//!
//! **Two-phase SSRF (SI-3).** `check_authority` alone cannot classify a DNS
//! name, so a split-horizon internal FQDN with a public certificate would
//! otherwise reach the private network. Every connection therefore resolves
//! ONCE, filters every resolved address through `check_resolved`, and dials a
//! validated `SocketAddr` — never re-resolving between check and connect
//! (DNS rebinding closed, mirroring observe RO-5).
//!
//! **Per-(connection, route) sockets (ADR 0019 D2).** Path-prefix routing is
//! per REQUEST, so an upstream socket is keyed by (client connection,
//! resolved route) and dialed only AFTER the head is parsed. A kept-alive
//! client that sends `/openai/...` then `/anthropic/...` gets two separate
//! upstream sockets, so provider B's credential is never written into
//! provider A's TLS session.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use api_tracker_core::error::{CoreError, Result};
use api_tracker_observe::policy;
use rustls::{ClientConnection, StreamOwned};

use crate::routes::UpstreamOrigin;

/// How long to wait for the TCP connect to one validated address.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upstream response idle timeout, reset per received byte. Deliberately
/// long: reasoning models can think for minutes before the first token.
pub const UPSTREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
/// Short read budget for an `Expect: 100-continue` interim response, restored
/// to `UPSTREAM_IDLE_TIMEOUT` before the final read so an upstream that skips
/// the interim cannot deadlock the exchange, and a slow real response is not
/// killed.
pub const INTERIM_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Upstream sockets kept alive per client connection. A client that rotates
/// through more routes than this evicts the least-recently-used socket rather
/// than growing without bound.
pub const MAX_UPSTREAMS_PER_CONNECTION: usize = 4;

/// Resolve a host to policy-validated addresses. Phase one is the literal
/// authority check; phase two filters every resolved address.
pub fn resolve_validated(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    resolve_validated_with(host, port, system_resolver)
}

/// The system resolver used in production.
fn system_resolver(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    (host, port).to_socket_addrs().map(|it| it.collect())
}

/// [`resolve_validated`] with an injectable resolver.
///
/// The seam exists because phase two is otherwise UNTESTABLE: every literal
/// that phase one already denies (IP literals, single-label names, metadata
/// names) never reaches the resolved-address filter, so a test built from
/// literals proves nothing about the post-DNS check — which is the entire
/// point of SI-3 (a split-horizon internal FQDN with a public certificate
/// resolves to a private address and must be refused AFTER DNS). Tests pass
/// a stub resolver; production passes the system one.
pub fn resolve_validated_with(
    host: &str,
    port: u16,
    resolve: impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
) -> Result<Vec<SocketAddr>> {
    let allow = policy::AllowList::new();
    // Phase one: the literal authority.
    if !policy::check_authority(host, port, &allow).is_allowed() {
        return Err(CoreError::InvalidInput(format!(
            "destination '{host}' is not routable"
        )));
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    // Resolve ONCE. Everything after this dials an address from THIS list;
    // re-resolving between check and connect is what DNS rebinding exploits.
    let resolved = resolve(bare, port)
        .map_err(|_| CoreError::Network(format!("could not resolve '{host}'")))?;
    // Phase two: every resolved address, independently.
    let validated: Vec<SocketAddr> = resolved
        .into_iter()
        .filter(|addr| policy::check_resolved(addr.ip(), false).is_allowed())
        .collect();
    if validated.is_empty() {
        return Err(CoreError::InvalidInput(format!(
            "every address for '{host}' is denied by the destination policy"
        )));
    }
    Ok(validated)
}

fn connect_any(addrs: &[SocketAddr]) -> Option<TcpStream> {
    for addr in addrs {
        if let Ok(stream) = TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            let _ = stream.set_nodelay(true);
            return Some(stream);
        }
    }
    None
}

/// The transport under an upstream connection.
///
/// Production always uses `Tls`. `Plain` exists so the exchange engine can be
/// exercised against synthetic loopback upstreams without weakening the SSRF
/// policy or shipping a permissive TLS verifier; it is reachable only through
/// [`InsecurePlainConnectorForTests`], which no production module names (a
/// source-level guard test asserts this).
enum Transport {
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    Plain(TcpStream),
}

impl Transport {
    fn sock(&self) -> &TcpStream {
        match self {
            Transport::Tls(s) => &s.sock,
            Transport::Plain(s) => s,
        }
    }
}

/// A live connection to one upstream origin.
pub struct Upstream {
    pub origin: UpstreamOrigin,
    transport: Transport,
    /// Bytes already read from this upstream past the end of the previous
    /// response. They belong to THIS socket's next response — never to the
    /// client connection — so they travel with the socket into the pool.
    pending: zeroize::Zeroizing<Vec<u8>>,
}

/// How a route's upstream connection is established. The gateway holds one
/// of these for its whole lifetime; swapping it is not a runtime decision.
pub trait UpstreamConnector: Send + Sync {
    fn connect(&self, origin: &UpstreamOrigin) -> Result<Upstream>;
}

/// The production connector: two-phase SSRF validation, then a normal
/// certificate-verified TLS handshake using the already-audited observe
/// client config (webpki roots, ALPN http/1.1). There is no permissive-
/// verifier code path anywhere in this crate (SI-5, source-guard enforced).
#[derive(Debug, Default, Clone, Copy)]
pub struct TlsConnector;

impl UpstreamConnector for TlsConnector {
    fn connect(&self, origin: &UpstreamOrigin) -> Result<Upstream> {
        let addrs = resolve_validated(&origin.host, origin.port)?;
        let tcp = connect_any(&addrs)
            .ok_or_else(|| CoreError::Network(format!("could not connect to '{}'", origin.host)))?;
        tcp.set_read_timeout(Some(UPSTREAM_IDLE_TIMEOUT))
            .map_err(CoreError::Io)?;
        tcp.set_write_timeout(Some(UPSTREAM_IDLE_TIMEOUT))
            .map_err(CoreError::Io)?;
        // An IPv6 literal origin is stored bracketed (`[2606:...]`) because
        // that is its authority form, but `ServerName` wants the bare
        // address; passing the brackets through fails every such connection.
        let sni_host = origin
            .host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let server_name = rustls_pki_types::ServerName::try_from(sni_host).map_err(|_| {
            CoreError::InvalidInput(format!("invalid server name '{}'", origin.host))
        })?;
        let config = api_tracker_observe::tls::upstream_client_config();
        let conn = ClientConnection::new(config, server_name)
            .map_err(|e| CoreError::Network(format!("TLS setup failed: {e}")))?;
        Ok(Upstream {
            origin: origin.clone(),
            transport: Transport::Tls(Box::new(StreamOwned::new(conn, tcp))),
            pending: zeroize::Zeroizing::new(Vec::new()),
        })
    }
}

/// TEST-ONLY connector: plain TCP to a loopback synthetic upstream, with NO
/// TLS and NO destination policy. It exists so HTTP framing semantics (which
/// are transport-independent) can be tested end to end against local mock
/// providers. It is never referenced by any production module.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy)]
pub struct InsecurePlainConnectorForTests;

impl UpstreamConnector for InsecurePlainConnectorForTests {
    fn connect(&self, origin: &UpstreamOrigin) -> Result<Upstream> {
        let addr: SocketAddr = format!("{}:{}", origin.host, origin.port)
            .parse()
            .map_err(|_| CoreError::InvalidInput("test connector needs an IP literal".into()))?;
        if !addr.ip().is_loopback() {
            return Err(CoreError::InvalidInput(
                "the test connector only reaches loopback".into(),
            ));
        }
        let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(CoreError::Io)?;
        tcp.set_nodelay(true).ok();
        tcp.set_read_timeout(Some(UPSTREAM_IDLE_TIMEOUT))
            .map_err(CoreError::Io)?;
        tcp.set_write_timeout(Some(UPSTREAM_IDLE_TIMEOUT))
            .map_err(CoreError::Io)?;
        Ok(Upstream {
            origin: origin.clone(),
            transport: Transport::Plain(tcp),
            pending: zeroize::Zeroizing::new(Vec::new()),
        })
    }
}

impl Upstream {
    pub fn set_read_timeout(&self, timeout: Duration) {
        let _ = self.transport.sock().set_read_timeout(Some(timeout));
    }

    /// Take the bytes already read past the previous response on this socket.
    pub fn take_pending(&mut self) -> zeroize::Zeroizing<Vec<u8>> {
        std::mem::replace(&mut self.pending, zeroize::Zeroizing::new(Vec::new()))
    }

    /// Stash bytes read past a response so the socket's next read sees them.
    pub fn set_pending(&mut self, pending: zeroize::Zeroizing<Vec<u8>>) {
        self.pending = pending;
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Best-effort liveness probe before reusing a cached socket: an upstream
    /// that closed its side while the connection sat idle must be redialed
    /// rather than written to (the teardown-mismatch finding). Unexpected
    /// readable data on an idle upstream is also treated as dead, since it
    /// means the two sides disagree about message boundaries.
    pub fn looks_alive(&self) -> bool {
        if self.has_pending() {
            // Bytes already buffered from this socket mean the previous
            // response did not end where its framing said it did. Treat the
            // socket as unusable rather than risk a response/request desync.
            return false;
        }
        let sock = self.transport.sock();
        if sock.set_nonblocking(true).is_err() {
            return false;
        }
        let mut probe = [0u8; 1];
        let alive = match sock.peek(&mut probe) {
            Ok(0) => false,
            Ok(_) => false,
            Err(e) => matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        };
        if sock.set_nonblocking(false).is_err() {
            return false;
        }
        alive
    }

    pub fn shutdown(&mut self) {
        let _ = self.transport.sock().shutdown(std::net::Shutdown::Both);
    }
}

impl Read for Upstream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.transport {
            Transport::Tls(s) => s.read(buf),
            Transport::Plain(s) => s.read(buf),
        }
    }
}

impl Write for Upstream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.transport {
            Transport::Tls(s) => s.write(buf),
            Transport::Plain(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.transport {
            Transport::Tls(s) => s.flush(),
            Transport::Plain(s) => s.flush(),
        }
    }
}

/// The upstream sockets owned by ONE client connection, keyed by route
/// prefix. Nothing is shared between client connections, and a socket for
/// route A is never used for a request routed to B.
#[derive(Default)]
pub struct UpstreamPool {
    by_route: HashMap<String, Upstream>,
    order: Vec<String>,
}

impl UpstreamPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the cached upstream for `route`, if it is still usable. The
    /// caller re-inserts it after a successful exchange.
    pub fn take(&mut self, route: &str, origin: &UpstreamOrigin) -> Option<Upstream> {
        let cached = self.by_route.remove(route)?;
        self.order.retain(|r| r != route);
        // A route whose origin changed (config reload) must never reuse the
        // socket dialed to the old origin.
        if &cached.origin != origin || !cached.looks_alive() {
            return None;
        }
        Some(cached)
    }

    pub fn put(&mut self, route: &str, upstream: Upstream) {
        if self.order.len() >= MAX_UPSTREAMS_PER_CONNECTION {
            if let Some(evict) = self.order.first().cloned() {
                self.order.remove(0);
                if let Some(mut old) = self.by_route.remove(&evict) {
                    old.shutdown();
                }
            }
        }
        self.by_route.insert(route.to_string(), upstream);
        self.order.push(route.to_string());
    }

    pub fn len(&self) -> usize {
        self.by_route.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_route.is_empty()
    }

    pub fn shutdown_all(&mut self) {
        for (_, mut u) in self.by_route.drain() {
            u.shutdown();
        }
        self.order.clear();
    }
}

impl Drop for UpstreamPool {
    fn drop(&mut self) {
        self.shutdown_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn stub(addrs: Vec<IpAddr>) -> impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>> {
        move |_host, port| Ok(addrs.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
    }

    #[test]
    fn phase_one_refuses_literals_and_bad_ports_before_any_dns() {
        // These never reach the resolver: a stub that PANICS proves it.
        let never = |_: &str, _: u16| -> std::io::Result<Vec<SocketAddr>> {
            panic!("phase one must reject before resolving")
        };
        for (host, port) in [
            ("127.0.0.1", 443u16),
            ("localhost", 443),
            ("10.0.0.5", 443),
            ("169.254.169.254", 443),
            ("metadata.google.internal", 443),
            ("api.openai.com", 8443), // policy allows only 80/443
        ] {
            assert!(
                resolve_validated_with(host, port, never).is_err(),
                "{host}:{port} must be refused in phase one"
            );
        }
    }

    #[test]
    fn phase_two_refuses_a_public_name_that_resolves_into_the_private_network() {
        // The real SI-3 case: a multi-label, public-LOOKING name that phase
        // one cannot classify, whose DNS answer is internal. This is the
        // split-horizon / rebinding attack, and only the post-DNS filter
        // catches it.
        for private in [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            // IPv4-mapped IPv6 loopback: the classifier must unwrap it.
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
        ] {
            let err = resolve_validated_with("internal.corp.example.com", 443, stub(vec![private]))
                .unwrap_err();
            assert!(
                format!("{err}").contains("denied by the destination policy"),
                "{private} must be refused AFTER dns, got: {err}"
            );
        }
    }

    #[test]
    fn phase_two_filters_rather_than_merely_rejecting() {
        // A dual-stack answer mixing a private and a public address must
        // yield ONLY the public one — proving the filter runs per address,
        // not just an all-or-nothing check.
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let addrs = resolve_validated_with(
            "api.example.com",
            443,
            stub(vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), public]),
        )
        .unwrap();
        assert_eq!(addrs.len(), 1, "the private address must be filtered out");
        assert_eq!(addrs[0].ip(), public);
        assert_eq!(addrs[0].port(), 443);
    }

    #[test]
    fn a_public_answer_passes_and_preserves_resolution_order() {
        let a = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let b = IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0, 0, 0, 0x1));
        let addrs = resolve_validated_with("api.example.com", 443, stub(vec![a, b])).unwrap();
        assert_eq!(addrs.iter().map(|s| s.ip()).collect::<Vec<_>>(), vec![a, b]);
    }

    #[test]
    fn an_empty_or_failing_resolution_is_an_error_not_an_empty_dial_list() {
        assert!(resolve_validated_with("api.example.com", 443, stub(vec![])).is_err());
        assert!(resolve_validated_with("api.example.com", 443, |_, _| {
            Err(std::io::Error::other("dns down"))
        })
        .is_err());
    }

    #[test]
    fn the_system_resolver_path_still_refuses_loopback_names() {
        // End-to-end through the real resolver (no network needed).
        assert!(resolve_validated("localhost", 443).is_err());
        assert!(resolve_validated("127.0.0.1", 443).is_err());
    }
}
