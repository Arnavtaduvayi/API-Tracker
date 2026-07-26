//! The forwarding engine: one client connection, many requests, per-route
//! upstreams, streamed bodies, and honest local diagnostics.
//!
//! Ordering of the request gate is deliberate and security-relevant:
//! version → method/target form → Host → browser-write → path → route.
//! Browser rejection precedes routing so a web page cannot learn which
//! providers are configured from the difference between 403 and 404, and
//! unknown prefixes and unknown link slugs return an IDENTICAL 404 for the
//! same reason (SI-4, THREAT_MODEL GW-2).

use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use api_tracker_core::error::CoreError;
use api_tracker_core::runtime::model::{ContentKind, HttpMethod, TransportError};
use api_tracker_core::runtime::sanitize;
use api_tracker_core::{clock, providers};
use api_tracker_observe::relay;
use zeroize::Zeroizing;

use crate::head::{self, Carryover, Framing, HeadRead, HttpVersion, RequestHead};
use crate::record::{
    counters, AttributionInput, Completion, ExchangeRecord, ObservationSink, UsageObservation,
};
use crate::routes::{LinkInfo, Route, RouteState, RouteTarget, Unforwardable};
use crate::upstream::{
    TlsConnector, UpstreamConnector, UpstreamPool, INTERIM_READ_TIMEOUT, UPSTREAM_IDLE_TIMEOUT,
};

/// Absolute budget for reading a request head (anti-Slowloris).
pub const CLIENT_HEAD_DEADLINE: Duration = Duration::from_secs(15);
/// Per-read budget while reading a head; deliberately shorter than the
/// deadline so the read loop wakes to observe it.
pub const CLIENT_HEAD_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Idle budget while streaming a request body from the client.
pub const CLIENT_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Idle budget on a kept-alive connection between requests.
pub const CLIENT_KEEPALIVE_IDLE: Duration = Duration::from_secs(120);
/// Concurrent client connections; further connections get 503 immediately
/// rather than queueing without bound.
pub const MAX_CONNECTIONS: usize = 128;

/// A tap fed with response body bytes AS THEY STREAM, for bounded usage
/// extraction. It never buffers the body and never affects the relay.
pub trait BodyTap {
    fn feed(&mut self, bytes: &[u8]);
    /// What the tap extracted, if anything.
    fn finish(&mut self) -> Option<UsageObservation> {
        None
    }
}

/// The no-op tap used when extraction is off or unsupported.
pub struct NoTap;
impl BodyTap for NoTap {
    fn feed(&mut self, _bytes: &[u8]) {}
}

/// A `Write` that forwards to `inner` and mirrors every written byte into a
/// tap. Only bytes actually written downstream are tapped, so the tap can
/// never observe more than the client did.
struct TeeWriter<'a, W: Write> {
    inner: W,
    tap: &'a mut dyn BodyTap,
}

impl<W: Write> Write for TeeWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.tap.feed(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Everything a connection handler needs. Cheap to clone (all `Arc`).
#[derive(Clone)]
pub struct Gateway {
    pub routes: Arc<RouteState>,
    pub sink: Arc<dyn ObservationSink>,
    /// The loopback port this listener is bound to, for the Host gate.
    pub port: u16,
    /// Recording paused by the control plane: forwarding is untouched, only
    /// observation hand-off is skipped.
    pub recording_paused: Arc<AtomicBool>,
    pub shutdown: Arc<AtomicBool>,
    pub connections: Arc<AtomicUsize>,
    pub max_connections: usize,
    /// Whether bounded usage extraction is enabled (Stage E).
    pub extraction_enabled: bool,
    /// How upstream connections are established. Production is always
    /// `TlsConnector` (two-phase SSRF + verified TLS); the field exists so
    /// the exchange engine is transport-generic and testable against local
    /// synthetic providers.
    pub connector: Arc<dyn UpstreamConnector>,
}

impl Gateway {
    pub fn new(routes: Arc<RouteState>, sink: Arc<dyn ObservationSink>, port: u16) -> Self {
        Self {
            routes,
            sink,
            port,
            recording_paused: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(AtomicUsize::new(0)),
            max_connections: MAX_CONNECTIONS,
            extraction_enabled: true,
            connector: Arc::new(TlsConnector),
        }
    }

    fn emit(&self, record: ExchangeRecord) {
        if self.recording_paused.load(Ordering::Relaxed) {
            return;
        }
        self.sink.record(record);
    }
}

/// Local diagnostic responses. These are written ONLY before any upstream
/// response byte has reached the client: once provider streaming starts the
/// gateway never injects an unrelated synthetic body.
fn local_response(client: &mut TcpStream, status: u16, reason: &str, message: &str) {
    let body = format!("tethra-gateway: {message}\n");
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = client.write_all(head.as_bytes());
    let _ = client.write_all(body.as_bytes());
    let _ = client.flush();
}

/// The identical answer for an unregistered prefix AND an unknown link slug,
/// so a caller cannot probe which providers or projects are configured.
fn respond_unknown_route(client: &mut TcpStream) {
    local_response(
        client,
        404,
        "Not Found",
        "no route is registered for this path. \
         List routes with `tethra gateway status`, or add one with \
         `tethra gateway route add <provider>`. Nothing was forwarded.",
    );
}

fn method_of(m: &str) -> HttpMethod {
    HttpMethod::parse(m)
}

/// Whether the request looks like it came from a web page rather than an SDK.
///
/// `Sec-Fetch-*` are forbidden header names a page cannot set, and no SDK
/// sends them; `Origin`/`Referer` likewise. The final clause closes the
/// CORS-simple-request write primitive: a `text/plain` (or form) POST fires
/// with no preflight, so a body-carrying request with a safelisted
/// Content-Type and NO credential header is refused (THREAT_MODEL GW-2).
fn looks_like_browser_write(head: &RequestHead) -> bool {
    if head.has_header("origin") || head.has_header("referer") {
        return true;
    }
    if head.has_header("sec-fetch-site") || head.has_header("sec-fetch-dest") {
        return true;
    }
    if head
        .header_str("sec-fetch-mode")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("no-cors"))
    {
        return true;
    }
    if !head.had_authorization {
        if let Some(ct) = head.header_str("content-type") {
            let base = ct
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if matches!(
                base.as_str(),
                "text/plain" | "application/x-www-form-urlencoded" | "multipart/form-data"
            ) {
                return true;
            }
        }
    }
    false
}

/// The Host header must case-insensitively equal this gateway's own loopback
/// authority. A foreign or absent Host is refused (SI-4).
fn host_is_ours(head: &RequestHead, port: u16) -> bool {
    let hosts = [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    let mut seen = None;
    for f in &head.headers {
        if f.lower == "host" {
            if seen.is_some() {
                return false; // duplicate Host is a desync primitive
            }
            seen = f.value_str().map(|v| v.trim().to_ascii_lowercase());
            if seen.is_none() {
                return false;
            }
        }
    }
    seen.is_some_and(|h| hosts.iter().any(|ours| ours.eq_ignore_ascii_case(&h)))
}

/// Reject traversal and parser-disagreement shapes before any prefix strip.
fn path_is_safe(path: &str) -> bool {
    if !path.starts_with('/') || path.contains('\\') {
        return false;
    }
    if path.split('/').any(|seg| seg == "." || seg == "..") {
        return false;
    }
    // A percent-encoded dot is the traversal primitive an upstream might
    // decode after the gateway stripped the prefix.
    let lower = path.to_ascii_lowercase();
    !lower.contains("%2e")
}

struct Resolution<'t> {
    route: &'t Route,
    link: Option<&'t LinkInfo>,
    upstream_path: String,
}

fn split_segment(rest: &str) -> (&str, &str) {
    match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    }
}

fn normalize_tail(tail: &str) -> String {
    if tail.is_empty() {
        "/".to_string()
    } else {
        tail.to_string()
    }
}

fn resolve<'t>(table: &'t crate::routes::RouteTable, path: &str) -> Option<Resolution<'t>> {
    let rest = path.strip_prefix('/')?;
    let (first, tail) = split_segment(rest);
    if first == "p" {
        let after = tail.strip_prefix('/')?;
        let (slug, tail2) = split_segment(after);
        let link = table.link(slug)?;
        let after2 = tail2.strip_prefix('/')?;
        let (prefix, tail3) = split_segment(after2);
        let route = table.route(prefix)?;
        // A slug is scoped to exactly one route; crossing them resolves to
        // nothing rather than silently attributing traffic to the wrong
        // project.
        if link.route_prefix != route.prefix {
            return None;
        }
        Some(Resolution {
            route,
            link: Some(link),
            upstream_path: normalize_tail(tail3),
        })
    } else {
        let route = table.route(first)?;
        Some(Resolution {
            route,
            link: None,
            upstream_path: normalize_tail(tail),
        })
    }
}

/// What the connection loop should do after one request.
enum Next {
    KeepAlive(Carryover),
    Close,
}

/// Serve one accepted client connection to completion.
pub fn serve_connection(
    gw: &Gateway,
    mut client: TcpStream,
    tap_factory: &dyn Fn(&str) -> Box<dyn BodyTap>,
) {
    // Loopback-only: refuse any peer that is not on the loopback interface,
    // belt-and-braces over the loopback bind (SI-1/D11).
    match client.peer_addr() {
        Ok(peer) if peer.ip().is_loopback() => {}
        _ => return,
    }
    let _ = client.set_nodelay(true);
    let mut pool = UpstreamPool::new();
    let mut carry: Carryover = Zeroizing::new(Vec::new());
    let mut first = true;

    loop {
        if gw.shutdown.load(Ordering::Relaxed) {
            break;
        }
        let idle = if first {
            CLIENT_HEAD_READ_TIMEOUT
        } else {
            // A kept-alive connection may legitimately sit idle between
            // requests; the absolute head deadline still bounds a partial
            // head once bytes start arriving.
            CLIENT_KEEPALIVE_IDLE
        };
        let _ = client.set_read_timeout(Some(idle));
        let deadline = Instant::now() + CLIENT_HEAD_DEADLINE + idle;
        let read = head::read_request_head(&mut client, std::mem::take(&mut carry), Some(deadline));
        first = false;
        let (head, body_carry) = match read {
            Ok(Some(v)) => v,
            Ok(None) => break, // clean close
            Err(CoreError::Io(_)) => break,
            Err(_) => {
                // A malformed or smuggling-shaped head: refuse and close.
                // Nothing is forwarded and no observation row is written.
                gw.sink.count("", counters::REJECTED_LOCALLY);
                local_response(
                    &mut client,
                    400,
                    "Bad Request",
                    "the request head was malformed or used an ambiguous framing \
                     (Content-Length + Transfer-Encoding, duplicate Content-Length, \
                     bare LF, or line folding). Nothing was forwarded.",
                );
                break;
            }
        };
        let _ = client.set_read_timeout(Some(CLIENT_BODY_IDLE_TIMEOUT));
        match handle_request(gw, &mut client, &mut pool, head, body_carry, tap_factory) {
            Next::KeepAlive(next) => carry = next,
            Next::Close => break,
        }
    }
    pool.shutdown_all();
    let _ = client.shutdown(std::net::Shutdown::Both);
}

fn handle_request(
    gw: &Gateway,
    client: &mut TcpStream,
    pool: &mut UpstreamPool,
    head: RequestHead,
    body_carry: Carryover,
    tap_factory: &dyn Fn(&str) -> Box<dyn BodyTap>,
) -> Next {
    // --- request gate (order is security-relevant; see module docs) ---

    if head.version == HttpVersion::Http10 {
        // A 1.0 client cannot be sent a chunked response, and the gateway
        // will not buffer a whole body to compute a length.
        local_response(
            client,
            505,
            "HTTP Version Not Supported",
            "HTTP/1.0 clients are not supported; use HTTP/1.1.",
        );
        gw.sink.count("", counters::REJECTED_LOCALLY);
        return Next::Close;
    }
    if head.method.eq_ignore_ascii_case("CONNECT") {
        local_response(
            client,
            405,
            "Method Not Allowed",
            "this is not a forward proxy: CONNECT tunnels are never accepted.",
        );
        gw.sink.count("", counters::REJECTED_LOCALLY);
        return Next::Close;
    }
    if head.target.contains("://") || !head.target.starts_with('/') {
        // Absolute-form and authority-form targets are how a forward proxy
        // is asked to reach an arbitrary host. This is not one (SI-2).
        local_response(
            client,
            400,
            "Bad Request",
            "only origin-form request targets are accepted; this gateway forwards \
             only to its registered provider routes.",
        );
        gw.sink.count("", counters::REJECTED_LOCALLY);
        return Next::Close;
    }
    if head.has_header("upgrade") {
        local_response(
            client,
            501,
            "Not Implemented",
            "protocol upgrades (WebSocket, HTTP/2 over cleartext) are not supported \
             by the local gateway in v1.",
        );
        gw.sink.count("", counters::REJECTED_LOCALLY);
        return Next::Close;
    }
    if !host_is_ours(&head, gw.port) {
        local_response(
            client,
            400,
            "Bad Request",
            "the Host header must be this gateway's own loopback authority.",
        );
        gw.sink.count("", counters::REJECTED_LOCALLY);
        return Next::Close;
    }
    if looks_like_browser_write(&head) {
        // A rejected browser request writes NO observation row, no alert, and
        // no per-route counter — only this single global counter, so a page
        // cannot manufacture inventory entries or fingerprint the config.
        gw.sink.count("", counters::REJECTED_BROWSER_ORIGIN);
        local_response(
            client,
            403,
            "Forbidden",
            "requests that look browser-originated are refused. The local gateway \
             serves SDK and CLI traffic only.",
        );
        return Next::Close;
    }
    if !path_is_safe(head.path_only()) {
        local_response(
            client,
            400,
            "Bad Request",
            "the request path contains traversal or encoded-traversal segments.",
        );
        gw.sink.count("", counters::REJECTED_LOCALLY);
        return Next::Close;
    }

    // --- routing ---

    let table = gw.routes.table();
    let Some(res) = resolve(&table, head.path_only()) else {
        gw.sink.count("", counters::UNKNOWN_ROUTE);
        respond_unknown_route(client);
        return Next::Close;
    };
    let origin = match &res.route.target {
        RouteTarget::Ready(origin) => origin.clone(),
        RouteTarget::Unforwardable(why) => {
            gw.sink
                .count(&res.route.prefix, counters::ROUTE_UNAVAILABLE);
            let detail = match why {
                Unforwardable::MacKeyUnavailable => {
                    "this custom-origin route cannot be verified because the vault has \
                     been locked since this gateway started. Unlock Tethra once to \
                     re-enable it; provider routes keep working."
                }
                Unforwardable::MacMismatch => {
                    "this custom-origin route failed its integrity check and will not \
                     be forwarded. Re-register the route in Tethra."
                }
            };
            local_response(client, 503, "Service Unavailable", detail);
            return Next::Close;
        }
    };

    // --- record scaffolding (metadata only; no wire strings) ---

    let at = clock::now_rfc3339();
    let started = Instant::now();
    let (path_template, template_confidence) = sanitize::sanitize_path(&res.upstream_path);
    let mut record = ExchangeRecord {
        at,
        route_prefix: res.route.prefix.clone(),
        provider_id: res.route.provider_id.clone(),
        project_id: res.link.map(|l| l.project_id.clone()),
        host: origin.host.clone(),
        port: origin.port,
        method: method_of(&head.method),
        path_template,
        template_confidence,
        status_code: None,
        req_content_kind: head.header_str("content-type").map(ContentKind::classify),
        resp_content_kind: None,
        had_authorization: head.had_authorization,
        latency_ms: None,
        ttfb_ms: None,
        request_bytes: None,
        response_bytes: None,
        transport_error: TransportError::None,
        completion: Completion::Completed,
        attribution_input: AttributionInput::NoCredentialPresent,
        digest: None,
        usage: None,
    };
    if res.link.is_none() {
        gw.sink
            .count(&res.route.prefix, counters::UNLINKED_REQUESTS);
    }

    // Query is forwarded to the provider but NEVER persisted: it is appended
    // to the wire target only, after the stored template was computed above.
    let upstream_target = match head.query() {
        Some(q) => format!("{}?{}", res.upstream_path, q),
        None => res.upstream_path.clone(),
    };

    let shape = res.route.usage_shape.clone();
    let extraction_on = gw.extraction_enabled && !shape.is_empty();
    let mut tap = if extraction_on {
        tap_factory(&shape)
    } else {
        Box::new(NoTap) as Box<dyn BodyTap>
    };

    let outcome = forward_exchange(
        gw,
        client,
        pool,
        &head,
        body_carry,
        &res.route.prefix,
        &origin,
        &upstream_target,
        extraction_on,
        tap.as_mut(),
        &mut record,
    );

    record.latency_ms = Some(started.elapsed().as_millis() as i64);
    record.usage = tap.finish();
    if let Some(usage) = &record.usage {
        if usage.dropped_events > 0 {
            gw.sink
                .count(&res.route.prefix, counters::USAGE_EVENTS_DROPPED);
        }
        if usage.model_rejected {
            gw.sink.count(&res.route.prefix, counters::MODEL_REJECTED);
        }
    }
    gw.emit(record);
    outcome
}

/// Provider pricing is not consulted here: the writer thread does that off
/// the forwarding path.
#[allow(clippy::too_many_arguments)]
fn forward_exchange(
    gw: &Gateway,
    client: &mut TcpStream,
    pool: &mut UpstreamPool,
    head: &RequestHead,
    body_carry: Carryover,
    route_prefix: &str,
    origin: &crate::routes::UpstreamOrigin,
    upstream_target: &str,
    force_identity: bool,
    tap: &mut dyn BodyTap,
    record: &mut ExchangeRecord,
) -> Next {
    // 1. Upstream socket for THIS route (never shared across routes).
    let cached = pool.take(route_prefix, origin);
    let was_cached = cached.is_some();
    let mut upstream = match cached {
        Some(u) => u,
        None => match gw.connector.connect(origin) {
            Ok(u) => u,
            Err(e) => {
                record.transport_error = classify_connect_error(&e);
                record.completion = Completion::UpstreamFailed;
                local_response(
                    client,
                    502,
                    "Bad Gateway",
                    "could not reach the provider. Nothing about this request was \
                     modified; retry, or check your network.",
                );
                return Next::Close;
            }
        },
    };

    // 2. Upstream head, rebuilt canonically from parsed fields.
    let out_head =
        head::build_upstream_head(head, upstream_target, &origin.host, true, force_identity);
    if upstream
        .write_all(&out_head)
        .and_then(|_| upstream.flush())
        .is_err()
    {
        // A cached socket may have died between the liveness probe and the
        // write. Redial once — nothing of the body has been sent yet, so
        // this is not a retry of a non-idempotent request.
        if !was_cached {
            record.transport_error = TransportError::Reset;
            record.completion = Completion::UpstreamFailed;
            local_response(
                client,
                502,
                "Bad Gateway",
                "the provider connection failed.",
            );
            return Next::Close;
        }
        upstream = match gw.connector.connect(origin) {
            Ok(u) => u,
            Err(e) => {
                record.transport_error = classify_connect_error(&e);
                record.completion = Completion::UpstreamFailed;
                local_response(client, 502, "Bad Gateway", "could not reach the provider.");
                return Next::Close;
            }
        };
        if upstream
            .write_all(&out_head)
            .and_then(|_| upstream.flush())
            .is_err()
        {
            record.transport_error = TransportError::Reset;
            record.completion = Completion::UpstreamFailed;
            local_response(
                client,
                502,
                "Bad Gateway",
                "the provider connection failed.",
            );
            return Next::Close;
        }
    }

    // Bytes previously read past this socket's last response belong to THIS
    // socket, never to the client connection.
    let mut resp_carry: Carryover = upstream.take_pending();
    let mut skip_body = false;
    let mut final_head: Option<Box<head::ResponseHead>> = None;

    // 3. Expect: 100-continue — read the interim BEFORE relaying the body,
    //    under a short budget, then restore the long budget so a slow real
    //    response is never killed.
    if head.expects_continue {
        upstream.set_read_timeout(INTERIM_READ_TIMEOUT);
        let deadline = Instant::now() + INTERIM_READ_TIMEOUT;
        let read = head::read_response_head_deadline(
            &mut upstream,
            std::mem::take(&mut resp_carry),
            Some(deadline),
        );
        upstream.set_read_timeout(UPSTREAM_IDLE_TIMEOUT);
        match read {
            Ok(HeadRead::Complete(h, carry)) => {
                resp_carry = carry;
                if h.status == 100 {
                    let interim = head::build_client_interim_head(&h);
                    if client
                        .write_all(&interim)
                        .and_then(|_| client.flush())
                        .is_err()
                    {
                        record.completion = Completion::ClientDisconnected;
                        record.transport_error = TransportError::Reset;
                        return Next::Close;
                    }
                } else {
                    // A final response instead of the interim (e.g. 417/401):
                    // the body is never sent, and the client connection is
                    // not reusable because its unsent body would desync.
                    skip_body = true;
                    final_head = Some(h);
                }
            }
            Ok(HeadRead::TimedOut(partial)) => {
                // The upstream never answered the expectation. RFC 9110 says
                // proceed with the body; the partial bytes are preserved so
                // the connection does not desynchronize.
                resp_carry = partial;
            }
            Err(_) => {
                record.transport_error = TransportError::Reset;
                record.completion = Completion::UpstreamDisconnected;
                local_response(
                    client,
                    502,
                    "Bad Gateway",
                    "the provider closed the connection before responding.",
                );
                return Next::Close;
            }
        }
    }

    // 4. Stream the request body (never buffered; the blocking copy IS the
    //    backpressure). Body bytes past this message stay in `client_carry`
    //    for the next request on a kept-alive connection.
    let mut client_carry: Vec<u8> = Vec::new();
    if !skip_body {
        match relay::relay_body(
            client,
            &mut upstream,
            head.framing.to_relay(),
            body_carry.to_vec(),
        ) {
            Ok((bytes, carry)) => {
                record.request_bytes = Some(bytes as i64);
                client_carry = carry;
            }
            Err(_) => {
                record.completion = Completion::ClientDisconnected;
                record.transport_error = TransportError::Reset;
                return Next::Close;
            }
        }
    } else {
        record.request_bytes = Some(0);
    }

    // 5. Response heads, relaying any further 1xx interims verbatim.
    let ttfb_start = Instant::now();
    let resp = match final_head {
        Some(h) => h,
        None => loop {
            match head::read_response_head(&mut upstream, std::mem::take(&mut resp_carry)) {
                Ok((h, carry)) => {
                    resp_carry = carry;
                    if (100..200).contains(&h.status) {
                        let interim = head::build_client_interim_head(&h);
                        if client
                            .write_all(&interim)
                            .and_then(|_| client.flush())
                            .is_err()
                        {
                            record.completion = Completion::ClientDisconnected;
                            record.transport_error = TransportError::Reset;
                            return Next::Close;
                        }
                        continue;
                    }
                    break Box::new(h);
                }
                Err(_) => {
                    // Nothing has been written to the client yet, so a local
                    // diagnostic here cannot corrupt a provider stream.
                    record.transport_error = TransportError::Reset;
                    record.completion = Completion::UpstreamDisconnected;
                    local_response(
                        client,
                        502,
                        "Bad Gateway",
                        "the provider closed the connection before sending a response.",
                    );
                    return Next::Close;
                }
            }
        },
    };
    record.ttfb_ms = Some(ttfb_start.elapsed().as_millis() as i64);
    record.status_code = Some(resp.status);
    record.resp_content_kind = resp.header_str("content-type").map(ContentKind::classify);

    let framing = resp.framing(&head.method);
    // A connection-close-delimited body is connection-terminal: the client
    // must be told to close, because the gateway cannot re-frame it.
    let terminal_framing = matches!(framing, Framing::UntilClose);
    let client_keep_alive = !head.client_wants_close
        && !terminal_framing
        && !skip_body
        && !gw.shutdown.load(Ordering::Relaxed);

    let out = head::build_client_response_head(&resp, framing, client_keep_alive);
    if client.write_all(&out).and_then(|_| client.flush()).is_err() {
        record.completion = Completion::ClientDisconnected;
        record.transport_error = TransportError::Reset;
        return Next::Close;
    }

    // 6. Stream the response body through the bounded tap.
    let mut tee = TeeWriter {
        inner: &mut *client,
        tap,
    };
    let relayed = relay::relay_body(
        &mut upstream,
        &mut tee,
        framing.to_relay(),
        std::mem::take(&mut resp_carry).to_vec(),
    );
    let (body_bytes, upstream_leftover) = match relayed {
        Ok(v) => v,
        Err(_) => {
            // Mid-stream failure: the provider's response has already begun,
            // so NO synthetic body is injected. The connection is torn down
            // and the truncation is recorded honestly.
            record.completion = Completion::Truncated;
            record.transport_error = TransportError::Reset;
            return Next::Close;
        }
    };
    record.response_bytes = Some(body_bytes as i64);
    upstream.set_pending(Zeroizing::new(upstream_leftover));

    // A Content-Length body that ended early is a truncation, not a success.
    if let Framing::ContentLength(declared) = framing {
        if body_bytes < declared {
            record.completion = Completion::Truncated;
            record.transport_error = TransportError::Reset;
            return Next::Close;
        }
    }
    if terminal_framing {
        record.completion = Completion::Completed;
        return Next::Close;
    }

    // 7. Upstream reuse: an upstream that wants to close is dropped WITHOUT
    //    tearing down the kept-alive client (the teardown-mismatch fix).
    if !resp.upstream_wants_close && !skip_body {
        pool.put(route_prefix, upstream);
    } else {
        upstream.shutdown();
    }

    if client_keep_alive {
        // Only the CLIENT-side leftover seeds the next request head.
        Next::KeepAlive(Zeroizing::new(client_carry))
    } else {
        Next::Close
    }
}

fn classify_connect_error(e: &CoreError) -> TransportError {
    match e {
        CoreError::Network(msg) if msg.contains("resolve") => TransportError::Dns,
        CoreError::Network(_) => TransportError::Refused,
        CoreError::InvalidInput(_) => TransportError::ProxyError,
        _ => TransportError::Refused,
    }
}

/// The pricing/provider metadata a record needs, resolved off the hot path.
pub fn provider_display_name(provider_id: &str) -> String {
    providers::find(provider_id)
        .map(|m| m.name.clone())
        .unwrap_or_else(|| provider_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_traversal_shapes_are_refused() {
        assert!(path_is_safe("/openai/v1/chat/completions"));
        assert!(path_is_safe("/openai"));
        assert!(!path_is_safe("openai/v1"));
        assert!(!path_is_safe("/openai/../anthropic/x"));
        assert!(!path_is_safe("/openai/./x"));
        assert!(!path_is_safe("/openai/%2e%2e/anthropic"));
        assert!(!path_is_safe("/openai/%2E%2E/anthropic"));
        assert!(!path_is_safe("/openai\\..\\anthropic"));
    }

    #[test]
    fn segment_splitting_never_matches_a_prefix_by_substring() {
        assert_eq!(split_segment("openai/v1/x"), ("openai", "/v1/x"));
        assert_eq!(split_segment("openai"), ("openai", ""));
        assert_eq!(split_segment("openai2/x"), ("openai2", "/x"));
        assert_eq!(normalize_tail(""), "/");
        assert_eq!(normalize_tail("/v1/x"), "/v1/x");
    }
}
