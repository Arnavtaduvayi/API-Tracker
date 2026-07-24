//! The loopback-only interception proxy.
//!
//! Binds `127.0.0.1:0`, authenticates each client with a per-session token,
//! enforces the destination policy on every CONNECT target (before AND after
//! DNS), and — in metadata mode — terminates TLS for the child using a
//! CA-minted leaf, relays each HTTP/1.1 request/response while extracting only
//! sanitized metadata, and forwards to the real provider over a fully-verified
//! upstream TLS connection. Connection-only mode and h2-only clients get an
//! opaque byte tunnel with connection-level metadata only.
//!
//! Observed metadata is delivered to an [`ObservationSink`]; this module never
//! touches the database, and the only wire-derived strings that leave it are
//! the sanitized host + path template inside an
//! [`ObservedRequest`](api_tracker_core::runtime::model::ObservedRequest).

use crate::ca::CertAuthority;
use crate::{clienthello, policy, relay, tls, wire};
use api_tracker_core::runtime::model::{
    ContentKind, HttpMethod, ObservationMode, ObservationSource, ObservedRequest, Protocol,
    TransportError,
};
use api_tracker_core::runtime::sanitize;
use api_tracker_core::secret::SecretString;
use base64::Engine;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const IO_TIMEOUT: Duration = Duration::from_secs(90);
const ACCEPT_POLL: Duration = Duration::from_millis(50);
const PEEK_BUF: usize = 8 * 1024;
/// Poll interval for the single-threaded post-upgrade opaque relay (WebSocket).
const WS_POLL: Duration = Duration::from_millis(100);
/// Absolute wall-clock deadline to finish reading a request head, independent of
/// the per-read idle timeout — bounds a pre-auth Slowloris that dribbles bytes
/// just under the idle timeout to hold a connection slot indefinitely.
const HEAD_DEADLINE: Duration = Duration::from_secs(15);
/// Per-read timeout during the untrusted pre-auth head read; shorter than
/// `HEAD_DEADLINE` so the read loop wakes to observe the absolute deadline.
const PREAUTH_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Receives observed metadata from the proxy. Implementations must be
/// non-blocking-friendly (the proxy calls them on worker threads) and must
/// never receive anything but sanitized metadata.
pub trait ObservationSink: Send + Sync {
    fn record(&self, observed: ObservedRequest);
    fn note_compat(&self, check: &str, status: &str, detail: &str);
    fn mark_partial(&self, reason: &str);
}

/// A sink that discards everything (tests, connection-only smoke).
pub struct NoopSink;
impl ObservationSink for NoopSink {
    fn record(&self, _o: ObservedRequest) {}
    fn note_compat(&self, _c: &str, _s: &str, _d: &str) {}
    fn mark_partial(&self, _r: &str) {}
}

/// Configuration for a running proxy.
pub struct ProxyConfig {
    pub mode: ObservationMode,
    /// Required for `Metadata` mode; ignored otherwise.
    pub ca: Option<Arc<CertAuthority>>,
    /// The per-session proxy token (compared constant-time; never logged).
    pub token: String,
    pub allowlist: policy::AllowList,
    pub max_connections: usize,
    pub sink: Arc<dyn ObservationSink>,
    /// Upstream TLS trust override. `None` (the production default) uses the
    /// bundled `webpki-roots` with full verification. Integration tests set
    /// this to a config trusting a local test CA — still FULL verification,
    /// just against a different root. There is no "accept invalid" path.
    pub upstream_config: Option<Arc<rustls::ClientConfig>>,
}

/// A running worker: its join handle plus a clone of the client socket, so
/// teardown can force-close a worker that is blocked in a socket read/write
/// (workers only observe the shutdown flag between requests; a blocked read
/// would otherwise stall `stop()` behind the 90s idle timeout — or indefinitely
/// under a Slowloris that keeps resetting it).
struct Worker {
    handle: JoinHandle<()>,
    client: TcpStream,
}

/// A running proxy. Dropping it (or calling [`RunningProxy::shutdown`]) stops
/// the listener, force-closes in-flight client sockets, and signals workers to
/// stop.
pub struct RunningProxy {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    listener_handle: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<Worker>>>,
}

impl RunningProxy {
    /// The `Basic` proxy-auth header the child must present.
    pub fn expected_auth(token: &str) -> String {
        let raw = format!("tethra:{token}");
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
        )
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Bind and start the listener thread.
    pub fn start(config: ProxyConfig) -> api_tracker_core::error::Result<Self> {
        let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
            .map_err(api_tracker_core::error::CoreError::Io)?;
        let addr = listener
            .local_addr()
            .map_err(api_tracker_core::error::CoreError::Io)?;
        listener
            .set_nonblocking(true)
            .map_err(api_tracker_core::error::CoreError::Io)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let workers: Arc<Mutex<Vec<Worker>>> = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let config = Arc::new(config);

        let sd = shutdown.clone();
        let wk = workers.clone();
        let listener_handle = thread::spawn(move || {
            for stream in listener.incoming() {
                if sd.load(Ordering::Relaxed) {
                    break;
                }
                match stream {
                    Ok(client) => {
                        if active.load(Ordering::Relaxed) >= config.max_connections {
                            // Over the connection cap: tell well-behaved clients
                            // to retry, then close. (The absolute head deadline
                            // plus force-close on teardown keep an unauthenticated
                            // client from squatting a slot indefinitely.)
                            let mut c = client;
                            let _ = c.set_write_timeout(Some(ACCEPT_POLL));
                            let _ = write_all_ok(
                                &mut c,
                                b"HTTP/1.1 503 Service Unavailable\r\n\
                                  Content-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                            drop(c);
                            continue;
                        }
                        active.fetch_add(1, Ordering::Relaxed);
                        let cfg = config.clone();
                        let sd2 = sd.clone();
                        let active2 = active.clone();
                        // Keep a clone of the client socket so teardown can
                        // force-close a blocked worker (see `Worker`).
                        let client_for_registry = client.try_clone().ok();
                        let handle = thread::spawn(move || {
                            let _guard = CountGuard(active2);
                            let _ = client.set_nonblocking(false);
                            let _ = client.set_read_timeout(Some(IO_TIMEOUT));
                            let _ = client.set_write_timeout(Some(IO_TIMEOUT));
                            // A panic in one connection must not take down the
                            // listener or leak a half-open verified connection.
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    handle_client(client, &cfg, &sd2)
                                }));
                            if result.is_err() {
                                cfg.sink.note_compat(
                                    "proxy_internal_error",
                                    "error",
                                    "a connection handler panicked; connection dropped",
                                );
                                cfg.sink.mark_partial("proxy_internal_error");
                            }
                        });
                        if let Some(client) = client_for_registry {
                            let mut w = wk.lock().expect("workers lock");
                            // Reap finished workers so the registry stays bounded
                            // by concurrency, not by cumulative connection count.
                            w.retain(|worker| !worker.handle.is_finished());
                            w.push(Worker { handle, client });
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL);
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            shutdown,
            listener_handle: Some(listener_handle),
            workers,
        })
    }

    /// Stop accepting, signal workers, and join with a bounded deadline.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.listener_handle.take() {
            let _ = h.join();
        }
        let workers: Vec<Worker> = {
            let mut w = self.workers.lock().expect("workers lock");
            std::mem::take(&mut *w)
        };
        // Force-close each in-flight client socket FIRST so any worker blocked
        // in a socket read/write returns immediately, then join. Without this a
        // worker parked in a (Slowloris-extended) head read or a long opaque
        // tunnel would stall teardown — and thus session finalization and the
        // CLI's exit — for as long as the peer keeps the connection alive.
        for w in &workers {
            let _ = w.client.shutdown(std::net::Shutdown::Both);
        }
        for w in workers {
            let _ = w.handle.join();
        }
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        if self.listener_handle.is_some() {
            self.stop();
        }
    }
}

struct CountGuard(Arc<AtomicUsize>);
impl Drop for CountGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn write_all_ok<W: Write>(w: &mut W, bytes: &[u8]) -> bool {
    w.write_all(bytes).and_then(|_| w.flush()).is_ok()
}

/// Top-level per-connection handling: authenticate, then dispatch.
fn handle_client(mut client: TcpStream, cfg: &ProxyConfig, shutdown: &AtomicBool) {
    // Pre-auth read: a short per-read timeout plus an absolute deadline bound
    // an unauthenticated Slowloris to ~HEAD_DEADLINE, so it cannot squat a
    // connection slot (and thus deny the monitored child capacity) for weeks.
    let _ = client.set_read_timeout(Some(PREAUTH_READ_TIMEOUT));
    let head_read = wire::read_request_head_deadline(&mut client, Instant::now() + HEAD_DEADLINE);
    // Restore the normal idle timeout for the authenticated session.
    let _ = client.set_read_timeout(Some(IO_TIMEOUT));
    let (head, raw_head, leftover) = match head_read {
        Ok(v) => v,
        Err(_) => return,
    };

    // Proxy authentication (constant-time). A missing/wrong token gets a bare
    // 407 with nothing logged about the token.
    let expected = RunningProxy::expected_auth(&cfg.token);
    let presented = head.proxy_authorization.clone().unwrap_or_default();
    if !SecretString::from(presented.as_str()).ct_eq(&SecretString::from(expected.as_str())) {
        let _ = write_all_ok(
            &mut client,
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"tethra\"\r\n\
              Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }

    if head.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(client, &head, cfg, shutdown);
    } else if head.target.starts_with("http://") {
        handle_plain(client, &head, &raw_head, leftover, cfg);
    } else {
        let _ = write_all_ok(
            &mut client,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    }
}

/// Resolve `host:port` and return the first address that passes the policy.
fn resolve_validated(
    host: &str,
    port: u16,
    allow: &policy::AllowList,
) -> Result<SocketAddr, policy::DenyReason> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let allowlisted = allow.contains(host, port) || allow.contains(bare, port);
    // Resolve ONCE; connect only to a validated resolved address (no second
    // resolution → no DNS-rebinding window).
    let addrs = (bare, port)
        .to_socket_addrs()
        .map_err(|_| policy::DenyReason::BadHostname)?;
    for addr in addrs {
        if policy::check_resolved(addr.ip(), allowlisted).is_allowed() {
            return Ok(addr);
        }
    }
    Err(policy::DenyReason::Private)
}

fn handle_connect(
    mut client: TcpStream,
    head: &wire::RequestHead,
    cfg: &ProxyConfig,
    shutdown: &AtomicBool,
) {
    let Some((host, port)) = wire::parse_authority(&head.target) else {
        let _ = write_all_ok(
            &mut client,
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
        );
        return;
    };

    // Policy on the literal authority first.
    if let policy::Verdict::Deny(reason) = policy::check_authority(&host, port, &cfg.allowlist) {
        cfg.sink
            .note_compat("ssrf_policy", "blocked", reason.as_str());
        let _ = write_all_ok(
            &mut client,
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }

    let addr = match resolve_validated(&host, port, &cfg.allowlist) {
        Ok(a) => a,
        Err(reason) => {
            cfg.sink
                .note_compat("ssrf_policy", "blocked", reason.as_str());
            let _ = write_all_ok(
                &mut client,
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return;
        }
    };

    // Accept the tunnel.
    if !write_all_ok(&mut client, b"HTTP/1.1 200 Connection Established\r\n\r\n") {
        return;
    }

    let connect_started = Instant::now();
    let upstream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => {
            record_transport(
                cfg,
                &host,
                port,
                Protocol::ConnectTunnel,
                TransportError::Refused,
                connect_started,
            );
            return;
        }
    };
    let _ = upstream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = upstream.set_write_timeout(Some(IO_TIMEOUT));

    // Connection-only mode, or an h2-only client, gets an opaque tunnel.
    if cfg.mode != ObservationMode::Metadata || cfg.ca.is_none() {
        opaque_tunnel(
            client,
            upstream,
            &host,
            port,
            cfg,
            ObservationSource::ConnectionOnly,
        );
        return;
    }

    // Peek the ClientHello (do not consume) to get SNI + ALPN.
    let mut peek = [0u8; PEEK_BUF];
    let n = client.peek(&mut peek).unwrap_or(0);
    let info = clienthello::parse(&peek[..n]);
    if info.is_h2_only() {
        cfg.sink.note_compat(
            "http2",
            "opaque",
            "client offered only HTTP/2; tunnelled without decoding",
        );
        cfg.sink.mark_partial("h2_only_client");
        opaque_tunnel(
            client,
            upstream,
            &host,
            port,
            cfg,
            ObservationSource::ConnectionOnly,
        );
        return;
    }
    let sni = info.sni.clone().unwrap_or_else(|| host.clone());
    let ca = cfg.ca.as_ref().expect("checked");
    intercept_https(client, upstream, &host, port, &sni, ca, cfg, shutdown);
}

/// Record a bare transport-level event (connection-only, or a failed connect).
fn record_transport(
    cfg: &ProxyConfig,
    host: &str,
    port: u16,
    protocol: Protocol,
    transport: TransportError,
    started: Instant,
) {
    cfg.sink.record(ObservedRequest {
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase(),
        port,
        method: HttpMethod::Connect,
        path_template: "/:connect".to_string(),
        template_confidence: api_tracker_core::providers::Confidence::Low,
        status_code: None,
        req_content_kind: None,
        resp_content_kind: None,
        had_authorization: false,
        latency_ms: Some(started.elapsed().as_millis() as i64),
        request_bytes: None,
        response_bytes: None,
        protocol,
        observation_source: ObservationSource::ConnectionOnly,
        transport_error: transport,
    });
}

/// Bidirectional raw byte relay (opaque tunnel). Records a single connection-
/// level event with byte counts; NO http status/method/path (honestly null).
fn opaque_tunnel(
    client: TcpStream,
    upstream: TcpStream,
    host: &str,
    port: u16,
    cfg: &ProxyConfig,
    source: ObservationSource,
) {
    let started = Instant::now();
    let (mut c_read, mut c_write) = match (client.try_clone(), client) {
        (Ok(a), b) => (a, b),
        _ => return,
    };
    let (mut u_read, mut u_write) = match (upstream.try_clone(), upstream) {
        (Ok(a), b) => (a, b),
        _ => return,
    };

    let up_bytes = Arc::new(AtomicUsize::new(0));
    let up_bytes2 = up_bytes.clone();
    let t = thread::spawn(move || {
        let n = copy_raw(&mut c_read, &mut u_write);
        let _ = u_write.shutdown(std::net::Shutdown::Write);
        up_bytes2.store(n, Ordering::Relaxed);
    });
    let down = copy_raw(&mut u_read, &mut c_write);
    let _ = c_write.shutdown(std::net::Shutdown::Write);
    let _ = t.join();

    cfg.sink.record(ObservedRequest {
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase(),
        port,
        method: HttpMethod::Connect,
        path_template: "/:connect".to_string(),
        template_confidence: api_tracker_core::providers::Confidence::Low,
        status_code: None,
        req_content_kind: None,
        resp_content_kind: None,
        had_authorization: false,
        latency_ms: Some(started.elapsed().as_millis() as i64),
        request_bytes: Some(up_bytes.load(Ordering::Relaxed) as i64),
        response_bytes: Some(down as i64),
        protocol: Protocol::ConnectTunnel,
        observation_source: source,
        transport_error: TransportError::None,
    });
}

fn copy_raw<R: Read, W: Write>(src: &mut R, dst: &mut W) -> usize {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0;
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
                total += n;
            }
            Err(_) => break,
        }
    }
    let _ = dst.flush();
    total
}

#[allow(clippy::too_many_arguments)]
fn intercept_https(
    client: TcpStream,
    upstream: TcpStream,
    host: &str,
    port: u16,
    sni: &str,
    ca: &Arc<CertAuthority>,
    cfg: &ProxyConfig,
    shutdown: &AtomicBool,
) {
    let handshake_started = Instant::now();
    // Downstream: present a CA-minted leaf for the SNI host.
    let server_config = match tls::server_config_for_host(ca, sni) {
        Ok(c) => c,
        Err(_) => return,
    };
    let server_conn = match rustls::ServerConnection::new(server_config) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut client_tls = rustls::StreamOwned::new(server_conn, client);

    // Upstream: connect TLS to the REAL provider, fully verified against
    // webpki-roots. Verify against the real hostname, not the SNI the client
    // sent (they are normally the same).
    let bare_host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let server_name = match rustls_pki_types::ServerName::try_from(bare_host.clone()) {
        Ok(n) => n,
        Err(_) => return,
    };
    let upstream_config = cfg
        .upstream_config
        .clone()
        .unwrap_or_else(tls::upstream_client_config);
    let up_conn = match rustls::ClientConnection::new(upstream_config, server_name) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut upstream_tls = rustls::StreamOwned::new(up_conn, upstream);

    // Drive the upstream handshake once so a bad provider cert surfaces as a
    // TLS error rather than a mysterious hang. Classify the failure: only an
    // actual certificate-verification error is UpstreamCertInvalid (which the
    // alerts layer turns into corporate-root advice); a reset/timeout/other
    // TLS error must not be misdiagnosed as a cert problem.
    if let Err(e) = upstream_tls.flush() {
        record_transport(
            cfg,
            &bare_host,
            port,
            Protocol::Http11,
            classify_upstream_handshake_error(&e),
            handshake_started,
        );
        return;
    }

    let mut carry: Vec<u8> = Vec::new();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let (req_head, raw_req, req_leftover) =
            match wire::read_request_head_from(&mut client_tls, std::mem::take(&mut carry)) {
                Ok(v) => v,
                Err(_) => break, // client closed or timed out
            };

        let request_started = Instant::now();
        // Forward the request head verbatim upstream, then stream the body.
        if upstream_tls.write_all(&raw_req).is_err() {
            record_transport(
                cfg,
                &bare_host,
                port,
                Protocol::Http11,
                TransportError::Reset,
                request_started,
            );
            break;
        }
        let req_framing = req_head.body_framing();
        let (req_body_bytes, req_carry) = match relay::relay_body(
            &mut client_tls,
            &mut upstream_tls,
            req_framing,
            req_leftover,
        ) {
            Ok(v) => v,
            Err(_) => break,
        };
        let _ = upstream_tls.flush();

        // Read the response head, forward verbatim, stream the body.
        let (resp_head, raw_resp, resp_leftover) = match wire::read_response_head(&mut upstream_tls)
        {
            Ok(v) => v,
            Err(_) => {
                record_transport(
                    cfg,
                    &bare_host,
                    port,
                    Protocol::Http11,
                    TransportError::Reset,
                    request_started,
                );
                break;
            }
        };
        let latency_ms = request_started.elapsed().as_millis() as i64;
        if client_tls.write_all(&raw_resp).is_err() {
            break;
        }

        // WebSocket / protocol upgrade: after forwarding the 101 head, the rest
        // is an opaque bidirectional stream we do not decode.
        if resp_head.status == 101 {
            let _ = client_tls.write_all(&resp_leftover);
            record_http(
                cfg,
                &bare_host,
                port,
                &req_head,
                &req_head.target,
                &resp_head,
                latency_ms,
                raw_req.len() as u64 + req_body_bytes,
                raw_resp.len() as u64,
                Protocol::Websocket,
                ObservationSource::UpgradeThenOpaque,
            );
            // The upgraded connection is now an opaque bidirectional stream we
            // do not decode: flag partial coverage honestly, then relay bytes
            // both ways so the child's WebSocket keeps working end to end
            // (previously copy_between_tls was a no-op and the socket died
            // milliseconds after a successful upgrade).
            cfg.sink.note_compat(
                "websocket",
                "opaque",
                "101 upgrade tunnelled bidirectionally without decoding frames",
            );
            cfg.sink.mark_partial("websocket_opaque");
            // Any client bytes already read past the upgrade request head belong
            // to the upstream direction; forward them before the opaque relay.
            let _ = upstream_tls.write_all(&req_carry);
            let _ = upstream_tls.flush();
            let _ = client_tls.flush();
            // Short read timeout so one thread can service both directions; a
            // read timeout means "no data this round", not an error.
            let _ = client_tls.sock.set_read_timeout(Some(WS_POLL));
            let _ = upstream_tls.sock.set_read_timeout(Some(WS_POLL));
            copy_between_tls(&mut client_tls, &mut upstream_tls, shutdown);
            break;
        }

        let resp_framing = resp_head.body_framing(&req_head.method);
        let (resp_body_bytes, resp_carry) = match relay::relay_body(
            &mut upstream_tls,
            &mut client_tls,
            resp_framing,
            resp_leftover,
        ) {
            Ok(v) => v,
            Err(_) => {
                // Still record what we saw (status is known).
                record_http(
                    cfg,
                    &bare_host,
                    port,
                    &req_head,
                    &req_head.target,
                    &resp_head,
                    latency_ms,
                    raw_req.len() as u64 + req_body_bytes,
                    raw_resp.len() as u64,
                    Protocol::Http11,
                    ObservationSource::Intercept,
                );
                break;
            }
        };
        let _ = client_tls.flush();

        record_http(
            cfg,
            &bare_host,
            port,
            &req_head,
            &req_head.target,
            &resp_head,
            latency_ms,
            raw_req.len() as u64 + req_body_bytes,
            raw_resp.len() as u64 + resp_body_bytes,
            proto_of(req_head.version),
            ObservationSource::Intercept,
        );

        // Close the connection if either side signalled it. Carry over any
        // pipelined request bytes (req_carry after a no-body request; resp_carry
        // belongs to the upstream side and is unused for the next client read).
        let _ = resp_carry;
        if req_head.connection_close || resp_head.connection_close {
            break;
        }
        carry = req_carry;
    }
}

fn proto_of(v: wire::HttpVersion) -> Protocol {
    match v {
        wire::HttpVersion::Http10 => Protocol::Http10,
        wire::HttpVersion::Http11 => Protocol::Http11,
    }
}

/// Opaque bidirectional relay between two already-established TLS streams
/// (post-upgrade, e.g. WebSocket). Frames are never decoded — this only keeps
/// the child's upgraded connection alive end to end. Because a rustls
/// `StreamOwned` cannot be split across threads, both directions are serviced
/// from one thread using the short socket read timeout set by the caller: a
/// timed-out/would-block read is "no data this round", any buffered plaintext
/// is returned before the socket is touched, and a clean `Ok(0)` or a real
/// error on either side ends the relay. The `shutdown` flag lets session
/// teardown end an idle tunnel promptly.
fn copy_between_tls<A: Read + Write, B: Read + Write>(a: &mut A, b: &mut B, shutdown: &AtomicBool) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        // a -> b
        match a.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if b.write_all(&buf[..n]).and_then(|_| b.flush()).is_err() {
                    break;
                }
            }
            Err(e) if is_would_block(&e) => {}
            Err(_) => break,
        }
        // b -> a
        match b.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if a.write_all(&buf[..n]).and_then(|_| a.flush()).is_err() {
                    break;
                }
            }
            Err(e) if is_would_block(&e) => {}
            Err(_) => break,
        }
    }
}

/// A read timeout or non-blocking would-block: not a fatal error, just "no data
/// available right now".
fn is_would_block(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Classify an upstream TLS handshake/IO failure. rustls surfaces certificate
/// verification failures as `InvalidData` wrapping a `rustls::Error`; only that
/// certificate family should be reported as `UpstreamCertInvalid` (the signal
/// the alerts layer turns into "add your corporate root" advice). Everything
/// else — resets, timeouts, other TLS protocol errors — is a plain transport
/// failure so ordinary network flakiness is not misdiagnosed as a bad cert.
fn classify_upstream_handshake_error(e: &std::io::Error) -> TransportError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => TransportError::Timeout,
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::UnexpectedEof => TransportError::Reset,
        ErrorKind::InvalidData => {
            let is_cert = e
                .get_ref()
                .map(|inner| {
                    let s = inner.to_string().to_ascii_lowercase();
                    s.contains("certificate")
                        || s.contains("unknown issuer")
                        || s.contains("unknownissuer")
                        || s.contains("invalid peer")
                })
                .unwrap_or(false);
            if is_cert {
                TransportError::UpstreamCertInvalid
            } else {
                TransportError::Reset
            }
        }
        _ => TransportError::Reset,
    }
}

#[allow(clippy::too_many_arguments)]
fn record_http(
    cfg: &ProxyConfig,
    connect_host: &str,
    port: u16,
    req: &wire::RequestHead,
    // The origin-form target to sanitize. For intercepted CONNECT traffic this
    // is the tunneled request's own target (already origin-form); for the plain
    // path it is the origin-form path extracted from the absolute-form target,
    // NOT the absolute-form `req.target` (which sanitizes to "/:redacted").
    effective_target: &str,
    resp: &wire::ResponseHead,
    latency_ms: i64,
    request_bytes: u64,
    response_bytes: u64,
    protocol: Protocol,
    source: ObservationSource,
) {
    // Record the policy-validated CONNECT authority as the host, never the
    // client-supplied Host header (`req.host`): that is an unvalidated,
    // spoofable request-header VALUE, and trusting it would (a) let arbitrary
    // header bytes reach the inventory `host` column and (b) attribute traffic
    // to a host that was never resolved or policy-checked. `connect_host` is
    // already port-stripped by every caller; strip IPv6 brackets to match the
    // normalization used by `record_transport`/`opaque_tunnel`.
    let host = connect_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let (path_template, confidence) = sanitize::sanitize_path(effective_target);
    cfg.sink.record(ObservedRequest {
        host,
        port,
        method: HttpMethod::parse(&req.method),
        path_template,
        template_confidence: confidence,
        status_code: Some(resp.status),
        req_content_kind: req.content_type.as_deref().map(ContentKind::classify),
        resp_content_kind: resp.content_type.as_deref().map(ContentKind::classify),
        had_authorization: req.had_authorization,
        latency_ms: Some(latency_ms),
        request_bytes: Some(request_bytes as i64),
        response_bytes: Some(response_bytes as i64),
        protocol,
        observation_source: source,
        transport_error: TransportError::None,
    });
}

/// Plain HTTP (absolute-form) proxying: rewrite to origin-form, drop proxy
/// headers, forward, and record metadata.
fn handle_plain(
    mut client: TcpStream,
    head: &wire::RequestHead,
    raw_head: &[u8],
    leftover: Vec<u8>,
    cfg: &ProxyConfig,
) {
    let Some((host, port, path)) = wire::split_absolute_form(&head.target) else {
        let _ = write_all_ok(
            &mut client,
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
        );
        return;
    };
    if let policy::Verdict::Deny(reason) = policy::check_authority(&host, port, &cfg.allowlist) {
        cfg.sink
            .note_compat("ssrf_policy", "blocked", reason.as_str());
        let _ = write_all_ok(
            &mut client,
            b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    let addr = match resolve_validated(&host, port, &cfg.allowlist) {
        Ok(a) => a,
        Err(reason) => {
            cfg.sink
                .note_compat("ssrf_policy", "blocked", reason.as_str());
            let _ = write_all_ok(
                &mut client,
                b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n",
            );
            return;
        }
    };
    let mut upstream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(_) => {
            record_transport(
                cfg,
                &host,
                port,
                Protocol::PlainHttp,
                TransportError::Refused,
                Instant::now(),
            );
            let _ = write_all_ok(
                &mut client,
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
            );
            return;
        }
    };
    let _ = upstream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = upstream.set_write_timeout(Some(IO_TIMEOUT));

    // Rewrite the request line to origin-form and drop hop-by-hop proxy headers,
    // forwarding every other header (Authorization included) verbatim.
    let rewritten = rewrite_plain_request(raw_head, &head.method, &path);
    let started = Instant::now();
    if upstream.write_all(&rewritten).is_err() {
        return;
    }
    let (req_body, _c) =
        match relay::relay_body(&mut client, &mut upstream, head.body_framing(), leftover) {
            Ok(v) => v,
            Err(_) => return,
        };
    let _ = upstream.flush();

    let (resp_head, raw_resp, resp_leftover) = match wire::read_response_head(&mut upstream) {
        Ok(v) => v,
        Err(_) => {
            record_transport(
                cfg,
                &host,
                port,
                Protocol::PlainHttp,
                TransportError::Reset,
                started,
            );
            return;
        }
    };
    let latency_ms = started.elapsed().as_millis() as i64;
    if client.write_all(&raw_resp).is_err() {
        return;
    }
    // Relay the RESPONSE body upstream -> client (src=upstream, dst=client).
    // Reversing these starves the client and writes the response back to the
    // server; the request relay above is the opposite direction on purpose.
    let (resp_body, _c2) = relay::relay_body(
        &mut upstream,
        &mut client,
        BodyFramingResp(&resp_head, &head.method),
        resp_leftover,
    )
    .unwrap_or((0, Vec::new()));

    record_http(
        cfg,
        &host,
        port,
        head,
        &path,
        &resp_head,
        latency_ms,
        rewritten.len() as u64 + req_body,
        raw_resp.len() as u64 + resp_body,
        Protocol::PlainHttp,
        ObservationSource::Intercept,
    );
}

/// Helper so `relay_body` can be called with a response-derived framing.
#[allow(non_snake_case)]
fn BodyFramingResp(resp: &wire::ResponseHead, method: &str) -> wire::BodyFraming {
    resp.body_framing(method)
}

/// Rewrite an absolute-form plain-HTTP request head to origin-form for
/// forwarding to the upstream.
///
/// Only the request line (absolute-form -> origin-form) and hop-by-hop proxy
/// headers change: `Proxy-Authorization`/`Proxy-Connection` (which we consumed
/// for the local proxy auth and must never leak upstream) and `Connection` (we
/// force a single request per connection) are dropped. EVERY other header the
/// child sent — `Authorization`, `X-Api-Key`, `User-Agent`, `Accept`, cookies,
/// content framing — is forwarded byte-for-byte from the raw head, so observing
/// a request does not silently change its semantics (previously all headers
/// except Host/Content-*/Content-Type were dropped, breaking authenticated
/// plain-HTTP calls).
fn rewrite_plain_request(raw_head: &[u8], method: &str, origin_path: &str) -> Vec<u8> {
    let mut out = format!("{method} {origin_path} HTTP/1.1\r\n").into_bytes();
    // Iterate the raw head's lines (byte-exact; heads are ASCII). Skip the
    // original request line, forward header lines verbatim except the ones we
    // must strip, and stop at the blank line terminating the head.
    let mut lines = raw_head.split(|&b| b == b'\n');
    let _ = lines.next(); // original request line
    for raw_line in lines {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            break; // CRLFCRLF: end of head
        }
        let name = match line.iter().position(|&b| b == b':') {
            Some(i) => &line[..i],
            None => line,
        };
        if name.eq_ignore_ascii_case(b"proxy-authorization")
            || name.eq_ignore_ascii_case(b"proxy-connection")
            || name.eq_ignore_ascii_case(b"connection")
        {
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_auth_is_basic_base64() {
        let a = RunningProxy::expected_auth("TESTTOKEN123");
        assert!(a.starts_with("Basic "));
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(a.trim_start_matches("Basic "))
            .unwrap();
        assert_eq!(decoded, b"tethra:TESTTOKEN123");
    }

    #[test]
    fn resolve_validated_blocks_loopback_literal() {
        let allow = policy::AllowList::new();
        assert!(resolve_validated("127.0.0.1", 443, &allow).is_err());
        assert!(resolve_validated("[::1]", 443, &allow).is_err());
    }

    #[test]
    fn rewrite_uses_origin_form_drops_proxy_headers_and_preserves_the_rest() {
        // Absolute-form request head as received by the plain-HTTP path.
        let raw = b"GET http://example.com/a?b=c HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Authorization: Bearer sk-LIVE-KEY\r\n\
                    Proxy-Authorization: Basic SECRETTOKEN\r\n\
                    Proxy-Connection: keep-alive\r\n\
                    User-Agent: curl/8.0\r\n\
                    Accept: application/json\r\n\r\n";
        let out = String::from_utf8(rewrite_plain_request(raw, "GET", "/a?b=c")).unwrap();
        // Origin-form request line.
        assert!(out.starts_with("GET /a?b=c HTTP/1.1\r\n"));
        // Proxy-* headers and the session token are stripped, never leaked
        // upstream.
        assert!(!out.to_lowercase().contains("proxy-authorization"));
        assert!(!out.to_lowercase().contains("proxy-connection"));
        assert!(!out.contains("SECRETTOKEN"));
        // Every other header the child sent is forwarded verbatim — regression
        // for the bug where Authorization (and everything but Host/Content-*)
        // was silently dropped, breaking authenticated plain-HTTP calls.
        assert!(out.contains("Host: example.com\r\n"));
        assert!(out.contains("Authorization: Bearer sk-LIVE-KEY\r\n"));
        assert!(out.contains("User-Agent: curl/8.0\r\n"));
        assert!(out.contains("Accept: application/json\r\n"));
        // Exactly one Connection header, forced to close.
        assert_eq!(out.to_lowercase().matches("connection:").count(), 1);
        assert!(out.trim_end().ends_with("Connection: close"));
    }

    #[test]
    fn request_head_debug_redacts_query_and_proxy_token() {
        let head = wire::RequestHead {
            method: "POST".into(),
            target: "/v1/x?token=SUPERSECRET".into(),
            version: wire::HttpVersion::Http11,
            host: Some("api.example.com".into()),
            content_length: None,
            chunked: false,
            connection_close: false,
            had_authorization: true,
            content_type: None,
            upgrade: None,
            proxy_authorization: Some("Basic PROXYTOKEN".into()),
        };
        let dbg = format!("{head:?}");
        assert!(
            !dbg.contains("SUPERSECRET"),
            "query leaked into Debug: {dbg}"
        );
        assert!(
            !dbg.contains("PROXYTOKEN"),
            "token leaked into Debug: {dbg}"
        );
        assert!(dbg.contains("/v1/x"));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn classify_upstream_error_only_certs_are_cert_invalid() {
        use std::io::{Error, ErrorKind};
        // A genuine cert error (rustls surfaces as InvalidData wrapping a msg).
        let cert = Error::new(
            ErrorKind::InvalidData,
            "invalid peer certificate: UnknownIssuer",
        );
        assert_eq!(
            classify_upstream_handshake_error(&cert),
            TransportError::UpstreamCertInvalid
        );
        // A reset is a reset, not a cert problem.
        let reset = Error::from(ErrorKind::ConnectionReset);
        assert_eq!(
            classify_upstream_handshake_error(&reset),
            TransportError::Reset
        );
        // A timeout is a timeout.
        let to = Error::from(ErrorKind::TimedOut);
        assert_eq!(
            classify_upstream_handshake_error(&to),
            TransportError::Timeout
        );
        // A non-cert TLS protocol error is not misreported as a cert problem.
        let proto = Error::new(
            ErrorKind::InvalidData,
            "received fatal alert: HandshakeFailure",
        );
        assert_eq!(
            classify_upstream_handshake_error(&proto),
            TransportError::Reset
        );
    }
}
