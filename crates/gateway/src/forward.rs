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
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use api_tracker_core::error::CoreError;
use api_tracker_core::runtime::model::{ContentKind, HttpMethod, TransportError};
use api_tracker_core::runtime::sanitize;
use api_tracker_core::secret::SecretBytes;
use api_tracker_core::{clock, providers};
use zeroize::Zeroizing;

use crate::attribution;
use crate::head::{self, Carryover, Framing, HeadRead, HttpVersion, RequestHead};
use crate::record::{counters, Completion, ExchangeRecord, ObservationSink, UsageObservation};
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

/// Absolute ceiling on how long ONE request body may take to arrive, however
/// steadily it trickles (`SEC-02`).
///
/// The idle timeout above bounds the gap between two reads; it does not bound
/// the total, so a client sending one byte every five seconds held a
/// connection open for as long as it liked. Generous enough for a real upload
/// over a slow link, far below "forever". Applies to the REQUEST body only —
/// a streaming response is a legitimate long-lived read and is not bounded by
/// this.
///
/// This bounds ONE request. On its own it bounds nothing about a CONNECTION:
/// it is re-armed per request, so it is clamped by
/// `CLIENT_CONNECTION_TIME_BUDGET` below (`NEW-48`).
pub const CLIENT_BODY_DEADLINE: Duration = Duration::from_secs(300);
/// Idle budget on a kept-alive connection between requests.
pub const CLIENT_KEEPALIVE_IDLE: Duration = Duration::from_secs(120);
/// Budget for one blocking write toward the client. Bounds a client that
/// stops reading mid-response.
pub const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(120);
/// Concurrent client connections; further connections get 503 immediately
/// rather than queueing without bound.
pub const MAX_CONNECTIONS: usize = 128;

/// Cumulative ceiling on CLIENT-PACED time for one CONNECTION (`SEC-02`,
/// `NEW-48`). This is the bound that makes slot residency stateable at all.
///
/// Every client-facing budget above is per REQUEST and is re-armed from
/// `Instant::now()` on each keep-alive iteration, so a client that keeps
/// *completing* slow work is never idle and never out of time. The audit held
/// one of `MAX_CONNECTIONS` slots for 422 seconds across twenty slow bodies on
/// a single connection, and would have held it for as long as it cared to: the
/// bound was not merely large, it was not expressible. This budget is charged
/// cumulatively across every request the connection serves and is never
/// renewed.
///
/// Only client-paced time is charged: idling between requests, reading a
/// request head, reading a request body. Upstream-paced time — connecting to
/// the provider, waiting for its response head, streaming its response body —
/// is deliberately NOT charged, because the origin comes from the route table
/// and never from the request, so a client cannot lengthen it. Charging it
/// would truncate a long model completion, which is the one thing this fix
/// must not do.
///
/// 600s covers one full `CLIENT_BODY_DEADLINE` upload plus a retry, or several
/// minutes of pooled idling; an SDK connection spends milliseconds per request
/// in the charged phases.
///
/// The budget is observed BETWEEN phases, so residency overshoots it by at
/// most one in-flight idle budget: `CLIENT_KEEPALIVE_IDLE` (120s) if the wait
/// for the next head was running, or `CLIENT_BODY_IDLE_TIMEOUT` (60s) if the
/// body relay was. The head deadline is deliberately NOT clamped to the
/// remaining budget — clamping could expire mid-head and turn a legitimately
/// arriving request into a spurious 400. **The worst case is therefore 720s,
/// not 600s, and every document that states a bound must state 720s.** An
/// attacker who dribbles is worth nothing after that, so holding 128 slots
/// means re-opening 128 connections every twelve minutes, each subject to the
/// 15s first-head deadline.
pub const CLIENT_CONNECTION_TIME_BUDGET: Duration = Duration::from_secs(600);

/// Absolute age past which a connection serves no NEW request (`NEW-48`).
///
/// Enforced at the top of the keep-alive loop and folded into the keep-alive
/// decision — never mid-exchange. A hard wall-clock lifetime would sever a
/// legitimate long SSE completion, which is precisely the failure this whole
/// design exists to avoid; applied between requests it means "this connection
/// will not serve another", the preceding response carries `Connection: close`
/// and the client reconnects transparently.
///
/// It bounds the one residency channel the time budget cannot see: a
/// connection kept alive indefinitely by work that is legitimately UNCHARGED.
/// Back-to-back multi-minute streaming completions spend almost no client-paced
/// time, so a single socket could otherwise be reused for days. That is not an
/// attack — which is why the bound is an hour rather than minutes, and why it
/// never interrupts the exchange in progress — but "forever" is not a number a
/// document can state. One hour matches nginx's `keepalive_time` default.
pub const CLIENT_CONNECTION_MAX_AGE: Duration = Duration::from_secs(3600);

/// Requests served on one keep-alive connection before it is closed cleanly.
///
/// Belt-and-braces, not the primary defence — the time budget and the maximum
/// age above are what bound a slot. A cap forces periodic reconnection, which
/// re-arms the 15s first-head deadline and lets the connection cap rebalance
/// across clients rather than being permanently owned by whoever connected
/// first. 10_000 is five times the busiest single-socket loop in this
/// repository's own perf suite and ten times nginx's `keepalive_requests`
/// default, so no legitimate client meets it by accident.
pub const MAX_REQUESTS_PER_CONNECTION: u32 = 10_000;

// There is deliberately NO cumulative request-body BYTE ceiling. A slot is the
// scarce resource here, not bandwidth: the body relay is a blocking copy, so a
// client uploading at line rate is using the gateway for its purpose and frees
// the slot by finishing. A byte cap would break repeated large uploads on a
// pooled connection (audio transcription, file endpoints) and would bound
// nothing that CLIENT_CONNECTION_TIME_BUDGET does not already bound. Recorded
// here so the omission reads as a decision rather than an oversight.

/// The per-connection bounds, as data rather than as literals in the engine.
///
/// Production values are the module constants above; `Gateway::new` is the
/// only constructor, there is no setter, no environment variable and no
/// configuration file, so a user cannot weaken a bound the documentation
/// promises. The struct exists so the connection engine can be driven at
/// millisecond scale by tests WITHOUT a `#[cfg(test)]` branch — `NEW-51` is
/// exactly the failure where the tested code and the shipped code are not the
/// same code, and a test-only shortcut would reintroduce it while appearing to
/// fix it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnLimits {
    pub head_deadline: Duration,
    pub head_read_timeout: Duration,
    pub keepalive_idle: Duration,
    pub body_idle: Duration,
    pub body_deadline: Duration,
    pub client_time_budget: Duration,
    pub max_age: Duration,
    pub max_requests: u32,
}

impl Default for ConnLimits {
    fn default() -> Self {
        Self {
            head_deadline: CLIENT_HEAD_DEADLINE,
            head_read_timeout: CLIENT_HEAD_READ_TIMEOUT,
            keepalive_idle: CLIENT_KEEPALIVE_IDLE,
            body_idle: CLIENT_BODY_IDLE_TIMEOUT,
            body_deadline: CLIENT_BODY_DEADLINE,
            client_time_budget: CLIENT_CONNECTION_TIME_BUDGET,
            max_age: CLIENT_CONNECTION_MAX_AGE,
            max_requests: MAX_REQUESTS_PER_CONNECTION,
        }
    }
}

/// Per-CONNECTION resource state (`SEC-02` / `NEW-48`) — the accumulator whose
/// absence was the defect.
///
/// `serve_connection` previously carried no state that outlived a request
/// other than the upstream pool and the carryover buffer, so nothing could
/// possibly accumulate and every bound restarted at each keep-alive iteration.
/// This is the one place connection-scoped cost is remembered.
struct ConnBudget {
    limits: ConnLimits,
    opened: Instant,
    /// Cumulative time spent waiting on the CLIENT: idle between requests,
    /// reading a request head, reading a request body. Response streaming is
    /// upstream-paced and is never added here — see
    /// `CLIENT_CONNECTION_TIME_BUDGET`.
    client_time: Duration,
    requests: u32,
}

impl ConnBudget {
    fn new(limits: ConnLimits) -> Self {
        Self {
            limits,
            opened: Instant::now(),
            client_time: Duration::ZERO,
            requests: 0,
        }
    }

    /// What is left of the connection's client-paced allowance. A per-request
    /// deadline is clamped to this so completing a request cannot renew it.
    fn remaining_client_time(&self) -> Duration {
        self.limits
            .client_time_budget
            .saturating_sub(self.client_time)
    }

    fn charge(&mut self, spent: Duration) {
        self.client_time = self.client_time.saturating_add(spent);
    }

    fn count_request(&mut self) {
        self.requests = self.requests.saturating_add(1);
    }

    /// Whether this connection may begin ANOTHER request.
    ///
    /// Consulted only between exchanges — at the top of the keep-alive loop
    /// and when deciding whether the response head says `keep-alive` or
    /// `close`. Never mid-exchange: an in-flight response, which may be a
    /// legitimate multi-minute stream, is finished intact.
    fn may_serve_another(&self) -> bool {
        !self.remaining_client_time().is_zero()
            && self.opened.elapsed() < self.limits.max_age
            && self.requests < self.limits.max_requests
    }
}

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
    /// Per-connection time/count bounds. Defaults to the module constants;
    /// carried as data so the connection engine is testable at millisecond
    /// scale without a production-path branch (`ConnLimits`).
    pub limits: ConnLimits,
    /// Whether bounded usage extraction is enabled (Stage E).
    pub extraction_enabled: bool,
    /// How upstream connections are established. Production is always
    /// `TlsConnector` (two-phase SSRF + verified TLS); the field exists so
    /// the exchange engine is transport-generic and testable against local
    /// synthetic providers.
    pub connector: Arc<dyn UpstreamConnector>,
    /// The matching-only keyed-fingerprint key, present ONLY when an
    /// unlocked-vault session pushed it over the authenticated control
    /// channel (SI-21). Absent here means attribution degrades honestly to
    /// `unavailable_no_key` — it never blocks or fails forwarding.
    pub matching_key: Arc<RwLock<Option<SecretBytes>>>,
    /// The listener-identity probe key, derived from the per-boot nonce
    /// (`control::probe_key_from_nonce`, D11). Not a secret capability in
    /// itself — it can only ANSWER challenges, never authorize anything —
    /// but present only when the service wired it at boot.
    pub probe_key: Arc<RwLock<Option<[u8; 32]>>>,
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
            limits: ConnLimits::default(),
            extraction_enabled: true,
            connector: Arc::new(TlsConnector),
            matching_key: Arc::new(RwLock::new(None)),
            probe_key: Arc::new(RwLock::new(None)),
        }
    }

    /// Install or clear the matching-only fingerprint key. Clearing drops the
    /// old key, which zeroizes it (`SecretBytes` is `ZeroizeOnDrop`).
    pub fn set_matching_key(&self, key: Option<SecretBytes>) {
        *self.matching_key.write().expect("matching key lock") = key;
    }

    /// Install the listener-identity probe key for this boot.
    pub fn set_probe_key(&self, key: Option<[u8; 32]>) {
        *self.probe_key.write().expect("probe key lock") = key;
    }

    pub fn has_matching_key(&self) -> bool {
        self.matching_key
            .read()
            .expect("matching key lock")
            .is_some()
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

/// Answer the listener-identity probe (`GET /_tethra/probe?c=<hex>`, D11).
///
/// Challenge–response: the caller derives the expected proof from the 0600
/// nonce file and compares. The nonce itself never crosses this socket, and
/// the response carries nothing but the proof and the version — no routes,
/// no projects, no configuration. Probe requests write NO observation row
/// and bump NO counter: they are local diagnostics, not traffic.
fn respond_probe(gw: &Gateway, client: &mut TcpStream, head: &RequestHead) {
    if !head.method.eq_ignore_ascii_case("GET") {
        local_response(
            client,
            405,
            "Method Not Allowed",
            "the probe endpoint accepts GET only.",
        );
        return;
    }
    // The challenge is the query's `c` parameter: 2..=64 hex characters.
    let challenge_hex = head
        .target
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or("")
        .split('&')
        .find_map(|kv| kv.strip_prefix("c="))
        .unwrap_or("");
    let challenge: Option<Vec<u8>> =
        if challenge_hex.is_empty() || challenge_hex.len() > 64 || challenge_hex.len() % 2 != 0 {
            None
        } else {
            (0..challenge_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&challenge_hex[i..i + 2], 16).ok())
                .collect()
        };
    let Some(challenge) = challenge else {
        local_response(
            client,
            400,
            "Bad Request",
            "the probe challenge must be `?c=<2..64 hex characters>`.",
        );
        return;
    };
    let proof = match *gw.probe_key.read().expect("probe key lock") {
        Some(key) => crate::control::probe_proof(&key, &challenge),
        None => "unavailable".to_string(),
    };
    let body = format!(
        "tethra-gateway-probe\nversion: {}\nproof: {proof}\n",
        env!("CARGO_PKG_VERSION")
    );
    let head_out = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = client.write_all(head_out.as_bytes());
    let _ = client.write_all(body.as_bytes());
    let _ = client.flush();
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
    let lower = path.to_ascii_lowercase();
    // Percent-encoded separators and dots are the traversal primitives an
    // upstream might decode AFTER the gateway stripped the prefix. The
    // earlier gate rejected only `%2e`, so `..%2f` passed: the segment is
    // neither exactly `..` nor contains `%2e`, yet an upstream that decodes
    // `%2f` to `/` reads it as `../`. `%25` (an encoded percent) is rejected
    // too, since it enables the double-encoded spelling `%252e`.
    //
    // This is defense in depth, NOT what prevents crossing origins — the
    // upstream origin is bound to the registered route and is never derived
    // from the forwarded path, so none of these can reach a different
    // provider. What they can do is confuse the provider's own routing, and
    // no legitimate provider path needs an encoded separator in a segment.
    if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
        return false;
    }
    if lower.contains("%25") {
        return false;
    }
    // Belt and braces for the shapes above: no segment may contain a `..`
    // run at all, however it is spelled around.
    !path.split('/').any(|seg| seg.contains(".."))
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
    tap_factory: &dyn Fn(&str, bool, bool) -> Box<dyn BodyTap>,
) {
    // Loopback-only: refuse any peer that is not on the loopback interface,
    // belt-and-braces over the loopback bind (SI-1/D11).
    match client.peer_addr() {
        Ok(peer) if peer.ip().is_loopback() => {}
        _ => return,
    }
    let _ = client.set_nodelay(true);
    // A client that opens a connection and then stops READING would
    // otherwise block a worker thread, an upstream socket, and a
    // connection-cap slot indefinitely: a blocking write has no other bound.
    // The budget is generous enough for a slow but real consumer of a
    // streamed response.
    let _ = client.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT));
    let mut pool = UpstreamPool::new();
    let mut carry: Carryover = Zeroizing::new(Vec::new());
    let mut first = true;
    // SEC-02 / NEW-48: the only state that outlives a request and therefore
    // the only place a CONNECTION-scoped bound can live. The slot is held for
    // the whole of `serve_connection` and nothing outside it can reclaim one.
    let mut budget = ConnBudget::new(gw.limits);

    loop {
        if gw.shutdown.load(Ordering::Relaxed) {
            break;
        }
        // Retirement is decided BETWEEN requests only, so nothing in flight is
        // ever truncated. Closing here is byte-identical to the existing idle
        // close below: no request has been read, so no 400 is manufactured for
        // a request nobody made. Whenever the bound was already visible while
        // the previous response head was being built, that response said
        // `Connection: close` and this is merely the client's own close
        // arriving first.
        if !budget.may_serve_another() {
            break;
        }
        // The per-read timeout is short so the loop wakes to observe the
        // absolute deadline. A FIRST request must complete its head within
        // CLIENT_HEAD_DEADLINE (that bound is what stops a Slowloris); a
        // kept-alive connection gets CLIENT_KEEPALIVE_IDLE for the whole head,
        // idle wait included, because the deadline is armed before the read
        // and is not re-armed when the first byte lands.
        let _ = client.set_read_timeout(Some(gw.limits.head_read_timeout));
        let idle_budget = if first {
            gw.limits.head_deadline
        } else {
            gw.limits.keepalive_idle
        };
        let deadline = Instant::now() + idle_budget;
        // Head-phase time — the idle wait included — is client-paced and is
        // charged. Without this, dribbling a HEAD for a full keep-alive idle
        // budget per request renews connection residency exactly the way
        // NEW-48 describes for bodies, and the body budget alone would not
        // notice. The head DEADLINE is deliberately not clamped to what is
        // left: clamping could expire in the middle of a head that is
        // legitimately arriving and turn it into a spurious 400, so the
        // overshoot of at most one idle budget is stated instead of
        // engineered away.
        let head_started = Instant::now();
        let read = head::read_request_head(&mut client, std::mem::take(&mut carry), Some(deadline));
        budget.charge(head_started.elapsed());
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
        budget.count_request();
        let _ = client.set_read_timeout(Some(gw.limits.body_idle));
        match handle_request(
            gw,
            &mut client,
            &mut pool,
            head,
            body_carry,
            tap_factory,
            &mut budget,
        ) {
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
    tap_factory: &dyn Fn(&str, bool, bool) -> Box<dyn BodyTap>,
    budget: &mut ConnBudget,
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
    // Absolute-form is `scheme://host/...` in the TARGET, before any `?`. A
    // query value that merely CONTAINS a URL (`?callback=https://...`) is an
    // ordinary origin-form request and must not be refused.
    if !head.target.starts_with('/') || head.path_only().contains("://") {
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

    // --- reserved local namespace (never forwarded, never recorded) ---

    if head.path_only() == "/_tethra/probe" {
        respond_probe(gw, client, &head);
        return Next::Close;
    }
    if head.path_only().starts_with("/_tethra/") || head.path_only() == "/_tethra" {
        // Byte-identical to an unknown route: the reserved namespace must
        // not be enumerable beyond the one documented probe path.
        gw.sink.count("", counters::UNKNOWN_ROUTE);
        respond_unknown_route(client);
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
    // `sanitize_path` is the ONLY wire-to-stored-string transformation, and
    // it runs over the route-stripped path with query and fragment already
    // severed by `path_only()` (SI-10).
    let (path_template, template_confidence) = sanitize::sanitize_path(&res.upstream_path);
    // The credential value is read ONLY here, only from a recognized header,
    // hashed under the vault's keyed-fingerprint key into a digest, and
    // dropped. The table lookup happens on the writer thread.
    let (attribution_input, digest) = {
        let key = gw.matching_key.read().expect("matching key lock");
        attribution::digest_request(key.as_ref(), &head)
    };
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
        attribution_input,
        digest,
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
        &shape,
        tap_factory,
        &mut record,
        budget,
    );

    record.latency_ms = Some(started.elapsed().as_millis() as i64);
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
    usage_shape: &str,
    tap_factory: &dyn Fn(&str, bool, bool) -> Box<dyn BodyTap>,
    record: &mut ExchangeRecord,
    budget: &mut ConnBudget,
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
    if let Err(e) = upstream.write_all(&out_head).and_then(|_| upstream.flush()) {
        record.transport_error = classify_io_error(&e);
        // A cached socket may have died between the liveness probe and the
        // write. Redial once — nothing of the body has been sent yet, so
        // this is not a retry of a non-idempotent request.
        if !was_cached {
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
        if let Err(e) = upstream.write_all(&out_head).and_then(|_| upstream.flush()) {
            record.transport_error = classify_io_error(&e);
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
                // ANY 1xx is informational, not an answer: a 103 Early
                // Hints (emitted by several CDN-fronted origins) reaching
                // the else branch as a "final response" would silently drop
                // the request body and hand the client an informational
                // status as its answer.
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
                // proceed with the body — but a CONFORMING client is waiting
                // for the interim before sending it, so proceeding without
                // telling the client leaves both sides waiting until the
                // 60-second client-body idle timeout. Synthesize the interim
                // the upstream owed, which is exactly what RFC 9110 §10.1.1
                // permits a proxy to do when the upstream does not respond.
                let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                let _ = client.flush();
                // the partial bytes are preserved so
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
        // SEC-02 / NEW-48: the ceiling on THIS upload is the per-request
        // deadline CLAMPED by whatever is left of the connection's budget.
        // Computing it from `Instant::now()` and the constant alone was the
        // whole defect: this runs once per keep-alive iteration, so twenty
        // sequential slow bodies each received a fresh 300 seconds and the
        // connection was never idle, holding a slot for as long as the client
        // cared to keep completing requests.
        let remaining = budget.remaining_client_time();
        // Which of the two bounds is the binding one, so the record can say
        // "your upload was too slow" rather than "this connection is spent"
        // (NEW-52) — they call for different fixes by the caller.
        let connection_bound = remaining < gw.limits.body_deadline;
        let body_started = Instant::now();
        let body_deadline = body_started + std::cmp::min(gw.limits.body_deadline, remaining);
        // The reader is scoped to the relay itself so the error paths below
        // still see the raw stream and can answer on it; `stop` is copied out
        // by value before the borrow ends.
        let (relayed, stop) = {
            let mut bounded = crate::stream::DeadlineReader::new(&mut *client, body_deadline);
            let out = match head.framing {
                Framing::None => Ok((0u64, body_carry.to_vec())),
                // Strict CRLF chunk framing toward the upstream: a bare-LF chunk
                // body is REJECTED, never forwarded (SI-15). `observe::relay`
                // deliberately tolerates bare LF — safe for the observation
                // proxy, a smuggling primitive for a gateway.
                Framing::Chunked => crate::stream::relay_chunked_strict(
                    &mut bounded,
                    &mut upstream,
                    body_carry.to_vec(),
                    None,
                ),
                Framing::ContentLength(n) => crate::stream::relay_plain(
                    &mut bounded,
                    &mut upstream,
                    Some(n),
                    body_carry.to_vec(),
                    None,
                ),
                Framing::UntilClose => crate::stream::relay_plain(
                    &mut bounded,
                    &mut upstream,
                    None,
                    body_carry.to_vec(),
                    None,
                ),
            };
            (out, bounded.stop())
        };
        // Charged on the success path AND the failure path: an upload that
        // ended badly still occupied the slot for as long as it ran. The
        // measurement spans the upstream writes too, which is conservative in
        // the safe direction — a stalled upstream can only shorten the
        // connection's remaining allowance, never lengthen it.
        budget.charge(body_started.elapsed());
        match relayed {
            Ok((bytes, carry)) => {
                record.request_bytes = Some(bytes as i64);
                client_carry = carry;
                // A client that declared N bytes and sent fewer leaves the
                // upstream waiting for a body that will never arrive: the
                // exchange is over, not merely slow.
                if let Framing::ContentLength(declared) = head.framing {
                    if bytes < declared {
                        record.completion = Completion::ClientDisconnected;
                        record.transport_error = TransportError::Reset;
                        return Next::Close;
                    }
                }
            }
            Err(e) => {
                let malformed = matches!(e, CoreError::InvalidInput(_));
                // NEW-52: "we cut this client off at a limit we chose" and
                // "this client went away" were recorded identically, as
                // ClientDisconnected + Reset, so nobody could tell a policy
                // decision from a peer failure — and the client was reset
                // without ever being told which had happened. Only the
                // client-side reader can attribute a stop, because an error
                // raised WRITING to the upstream surfaces on this same
                // `Result` and must not be mistaken for either.
                let limit_hit = if malformed {
                    None
                } else {
                    match stop {
                        crate::stream::ReaderStop::DeadlineExceeded if connection_bound => {
                            Some(Completion::ConnectionBudgetExceeded)
                        }
                        crate::stream::ReaderStop::DeadlineExceeded => {
                            Some(Completion::ClientBodyDeadlineExceeded)
                        }
                        crate::stream::ReaderStop::IdleTimeout => {
                            Some(Completion::ClientBodyIdleTimeout)
                        }
                        crate::stream::ReaderStop::None | crate::stream::ReaderStop::Failed => None,
                    }
                };
                record.completion = match (malformed, limit_hit) {
                    (true, _) => Completion::RejectedLocally,
                    (false, Some(imposed)) => imposed,
                    (false, None) => Completion::ClientDisconnected,
                };
                record.transport_error = if limit_hit.is_some() {
                    TransportError::Timeout
                } else {
                    TransportError::Reset
                };
                if malformed {
                    // Nothing has been written to the CLIENT yet, so a local
                    // diagnostic is safe here. Note this says nothing about
                    // the upstream: the head and the chunks preceding the
                    // malformed one were already relayed, which is why the
                    // message below does not claim the request "was not
                    // forwarded".
                    gw.sink.count(route_prefix, counters::REJECTED_LOCALLY);
                    local_response(
                        client,
                        400,
                        "Bad Request",
                        "the chunked request body used ambiguous framing (bare LF, a \
                         chunk extension, or a malformed terminator). The exchange was \
                         aborted; the upstream connection is closed without a complete \
                         body, so the request cannot have been applied as a whole — but \
                         part of it may already have reached the provider.",
                    );
                } else if limit_hit.is_some() {
                    // Safe here and ONLY here: the request-body phase has
                    // written no byte of the provider's answer, so the "never
                    // inject a synthetic body once provider streaming started"
                    // rule is not in play (an Expect interim may legally
                    // precede a final status). A client that was cut off by
                    // our own limit is told so instead of being reset in
                    // silence.
                    local_response(
                        client,
                        408,
                        "Request Timeout",
                        "the request body did not finish within the upload deadline, or \
                         within this connection's total client-time budget. The exchange \
                         was aborted; the provider connection is closed without a \
                         complete body, so the request cannot have been applied as a \
                         whole — but part of it may already have reached the provider. \
                         Retry on a new connection.",
                    );
                }
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
        && !gw.shutdown.load(Ordering::Relaxed)
        // NEW-48: a connection that has reached one of its per-connection
        // bounds is TOLD to close, on an otherwise entirely normal response,
        // rather than discovering it later as a silent close mid-pool. The
        // check belongs here and not in the body relay: this exchange, and any
        // response streaming that follows, completes intact.
        && budget.may_serve_another();

    let out = head::build_client_response_head(&resp, framing, client_keep_alive);
    if client.write_all(&out).and_then(|_| client.flush()).is_err() {
        record.completion = Completion::ClientDisconnected;
        record.transport_error = TransportError::Reset;
        return Next::Close;
    }

    // 6. Stream the response body through the bounded tap. The extraction
    //    mode is decided from the response's OWN declared headers: a
    //    compressed body is counted `unsupported_shape` rather than scanned,
    //    because the relay never decompresses (zip-bomb surface).
    //
    //    Nothing from here on is charged to `budget`, deliberately (SEC-02 /
    //    NEW-48). This loop blocks on the UPSTREAM socket, whose origin comes
    //    from the route table and never from the request, so its pace is not
    //    attacker-controlled and a limit here would buy no availability while
    //    truncating an eight-minute model completion. Request upload and
    //    response streaming are different questions and get different answers:
    //    the upload is bounded absolutely and cumulatively; the response is
    //    bounded only per-read (UPSTREAM_IDLE_TIMEOUT) and per-write toward a
    //    client that stopped reading (CLIENT_WRITE_TIMEOUT).
    let (streaming, compressed) = crate::usage::mode_for_response(
        resp.header_str("content-type"),
        resp.header_str("content-encoding"),
    );
    let mut tap: Box<dyn BodyTap> = if force_identity {
        tap_factory(usage_shape, streaming, compressed)
    } else {
        Box::new(NoTap)
    };
    // For a chunked response the tap must see DECODED bytes: feeding it the
    // raw framing would splice chunk-size lines into the middle of SSE events
    // and break extraction on exactly the streaming responses it exists for.
    let carry_in = std::mem::take(&mut resp_carry).to_vec();
    let relayed = match framing {
        Framing::Chunked => crate::stream::relay_chunked_strict(
            &mut upstream,
            &mut *client,
            carry_in,
            Some(tap.as_mut()),
        ),
        Framing::ContentLength(n) => crate::stream::relay_plain(
            &mut upstream,
            &mut *client,
            Some(n),
            carry_in,
            Some(tap.as_mut()),
        ),
        Framing::UntilClose => crate::stream::relay_plain(
            &mut upstream,
            &mut *client,
            None,
            carry_in,
            Some(tap.as_mut()),
        ),
        Framing::None => Ok((0, carry_in)),
    };
    let (body_bytes, upstream_leftover) = match relayed {
        Ok(v) => v,
        Err(_) => {
            // Mid-stream failure: the provider's response has already begun,
            // so NO synthetic body is injected. The connection is torn down
            // and the truncation is recorded honestly. Whatever the tap saw
            // before the break is still reported, labeled partial by the
            // completion state.
            record.usage = tap.finish();
            record.completion = Completion::Truncated;
            record.transport_error = TransportError::Reset;
            return Next::Close;
        }
    };
    record.usage = tap.finish();
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
        // A certificate the gateway refused to trust is NOT a generic reset:
        // conflating them would hide the one failure a user must act on.
        CoreError::Network(msg) if msg.contains("TLS") || msg.contains("certificate") => {
            TransportError::UpstreamCertInvalid
        }
        CoreError::Network(_) => TransportError::Refused,
        CoreError::InvalidInput(_) => TransportError::ProxyError,
        _ => TransportError::Refused,
    }
}

/// Classify a failure on an already-connected upstream. rustls surfaces
/// certificate and handshake failures on the first read/write rather than at
/// construction, so this is where most of them actually land.
pub(crate) fn classify_io_error(e: &std::io::Error) -> TransportError {
    let text = e.to_string();
    if text.contains("certificate")
        || text.contains("CertNotValid")
        || text.contains("UnknownIssuer")
        || text.contains("BadCertificate")
        || text.contains("CertExpired")
    {
        TransportError::UpstreamCertInvalid
    } else if matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        TransportError::Timeout
    } else {
        TransportError::Reset
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

    /// The limits a `Gateway` actually runs with must be the constants the
    /// documentation quotes. `ConnLimits` exists so tests can shorten these;
    /// this is the guard that a future edit to a constant, or to a `Default`
    /// field, cannot silently make the shipped bound differ from the stated
    /// one — the one real hazard of carrying limits as data.
    #[test]
    fn production_limits_are_exactly_the_documented_constants() {
        let l = ConnLimits::default();
        assert_eq!(l.head_deadline, CLIENT_HEAD_DEADLINE);
        assert_eq!(l.head_read_timeout, CLIENT_HEAD_READ_TIMEOUT);
        assert_eq!(l.keepalive_idle, CLIENT_KEEPALIVE_IDLE);
        assert_eq!(l.body_idle, CLIENT_BODY_IDLE_TIMEOUT);
        assert_eq!(l.body_deadline, CLIENT_BODY_DEADLINE);
        assert_eq!(l.client_time_budget, CLIENT_CONNECTION_TIME_BUDGET);
        assert_eq!(l.max_age, CLIENT_CONNECTION_MAX_AGE);
        assert_eq!(l.max_requests, MAX_REQUESTS_PER_CONNECTION);

        // A `Gateway` built the only way one can be built carries them.
        let gw = Gateway::new(
            Arc::new(RouteState::from_table_for_test(
                crate::routes::RouteTable::default(),
            )),
            Arc::new(crate::record::NullSink),
            7,
        );
        assert_eq!(gw.limits, ConnLimits::default());

        // The cumulative budget must be able to absorb a whole legitimate
        // upload, or a single large request would be unservable.
        assert!(l.client_time_budget >= l.body_deadline);
        // And the connection must be retired for age long before an unbounded
        // number of idle cycles, each just short of the idle timeout, could
        // accumulate silently.
        assert!(l.max_age > l.keepalive_idle);
    }

    #[test]
    fn a_connection_budget_is_cumulative_and_never_renewed_by_a_completed_request() {
        // The property NEW-48 is about, at the level of the accumulator
        // itself: charging twice adds, it does not reset.
        let limits = ConnLimits {
            client_time_budget: Duration::from_millis(100),
            max_age: Duration::from_secs(3600),
            max_requests: 3,
            ..ConnLimits::default()
        };
        let mut budget = ConnBudget::new(limits);
        assert!(budget.may_serve_another());
        budget.charge(Duration::from_millis(60));
        assert_eq!(budget.remaining_client_time(), Duration::from_millis(40));
        budget.charge(Duration::from_millis(60));
        assert!(
            budget.remaining_client_time().is_zero(),
            "a second slow request must draw on the SAME budget"
        );
        assert!(!budget.may_serve_another());

        // The request cap retires a connection that is otherwise free.
        let mut budget = ConnBudget::new(limits);
        for _ in 0..3 {
            assert!(budget.may_serve_another());
            budget.count_request();
        }
        assert!(!budget.may_serve_another());
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
