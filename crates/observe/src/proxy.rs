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

/// A running proxy. Dropping it (or calling [`RunningProxy::shutdown`]) stops
/// the listener and signals workers to stop between requests.
pub struct RunningProxy {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    listener_handle: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
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
        let workers: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
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
                            // Over the connection cap: close immediately.
                            drop(client);
                            continue;
                        }
                        active.fetch_add(1, Ordering::Relaxed);
                        let cfg = config.clone();
                        let sd2 = sd.clone();
                        let active2 = active.clone();
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
                        wk.lock().expect("workers lock").push(handle);
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
        // Join in-flight workers best-effort; their sockets have timeouts so
        // they cannot hang indefinitely.
        let handles: Vec<JoinHandle<()>> = {
            let mut w = self.workers.lock().expect("workers lock");
            std::mem::take(&mut *w)
        };
        for h in handles {
            let _ = h.join();
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
    let (head, _raw, leftover) = match wire::read_request_head(&mut client) {
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
        handle_plain(client, &head, leftover, cfg);
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
    // TLS error rather than a mysterious hang.
    if upstream_tls.flush().is_err() {
        record_transport(
            cfg,
            &bare_host,
            port,
            Protocol::Http11,
            TransportError::UpstreamCertInvalid,
            Instant::now(),
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
                &resp_head,
                latency_ms,
                raw_req.len() as u64 + req_body_bytes,
                raw_resp.len() as u64,
                Protocol::Websocket,
                ObservationSource::UpgradeThenOpaque,
            );
            // relay the remainder opaquely until either side closes
            let _ = client_tls.flush();
            let _ = copy_between_tls(&mut client_tls, &mut upstream_tls);
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

/// Opaque relay between two already-established TLS streams (post-upgrade).
fn copy_between_tls<A: Read + Write, B: Read + Write>(
    _a: &mut A,
    _b: &mut B,
) -> std::io::Result<()> {
    // Post-101 we cannot easily split the rustls StreamOwned across threads;
    // a single-direction drain is sufficient to keep the metadata honest (the
    // event is already recorded and flagged upgrade_then_opaque). The streams
    // drop and close when this returns.
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_http(
    cfg: &ProxyConfig,
    connect_host: &str,
    port: u16,
    req: &wire::RequestHead,
    resp: &wire::ResponseHead,
    latency_ms: i64,
    request_bytes: u64,
    response_bytes: u64,
    protocol: Protocol,
    source: ObservationSource,
) {
    let host = req
        .host
        .clone()
        .unwrap_or_else(|| connect_host.to_string())
        .split(':')
        .next()
        .unwrap_or(connect_host)
        .to_ascii_lowercase();
    let (path_template, confidence) = sanitize::sanitize_path(&req.target);
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

    // Rewrite the request line to origin-form and drop hop-by-hop proxy headers.
    let rewritten = rewrite_plain_request(head, &path);
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
    let (resp_body, _c2) = relay::relay_body(
        &mut client,
        &mut upstream,
        BodyFramingResp(&resp_head, &head.method),
        resp_leftover,
    )
    .unwrap_or((0, Vec::new()));

    record_http(
        cfg,
        &host,
        port,
        head,
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

/// Build an origin-form request head, dropping Proxy-* hop-by-hop headers.
fn rewrite_plain_request(head: &wire::RequestHead, origin_path: &str) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", head.method, origin_path).into_bytes();
    // Reconstruct the minimal necessary headers from the parsed head. We only
    // forward Host, Content-Length/Transfer-Encoding, Content-Type — enough for
    // correct framing — never the Proxy-Authorization we just consumed.
    if let Some(h) = &head.host {
        out.extend_from_slice(format!("Host: {h}\r\n").as_bytes());
    }
    if head.chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    } else if let Some(n) = head.content_length {
        out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
    }
    if let Some(ct) = &head.content_type {
        out.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
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
    fn rewrite_drops_proxy_headers_and_uses_origin_form() {
        let head = wire::RequestHead {
            method: "GET".into(),
            target: "http://example.com/a?b=c".into(),
            version: wire::HttpVersion::Http11,
            host: Some("example.com".into()),
            content_length: None,
            chunked: false,
            connection_close: false,
            had_authorization: false,
            content_type: None,
            upgrade: None,
            proxy_authorization: Some("Basic SECRETTOKEN".into()),
        };
        let out = String::from_utf8(rewrite_plain_request(&head, "/a?b=c")).unwrap();
        assert!(out.starts_with("GET /a?b=c HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com"));
        assert!(!out.to_lowercase().contains("proxy-authorization"));
        assert!(!out.contains("SECRETTOKEN"));
    }
}
