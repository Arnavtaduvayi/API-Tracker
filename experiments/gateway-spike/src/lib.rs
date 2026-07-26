//! Feasibility spike for the Tethra Local Gateway.
//!
//! This is NOT production code. It exists to answer, with runnable evidence,
//! the feasibility questions in docs/gateway/HANDOFF_PHASE_1.md:
//!
//! 1. Can a blocking, thread-per-connection forwarder built on the existing
//!    `api-tracker-observe` wire/relay primitives stream SSE incrementally
//!    (no whole-body buffering, no added latency)?
//! 2. Are headers, status codes, and provider errors preserved verbatim?
//! 3. Can request bodies stream upstream without buffering?
//! 4. Can `Expect: 100-continue` interim responses be relayed on a 1:1
//!    client-connection/upstream-connection mapping?
//! 5. Can usage metadata be extracted from SSE responses with a BOUNDED
//!    buffer (never retaining the body)?
//! 6. Can the observation queue stay bounded WITHOUT ever blocking the
//!    forwarding path (drop-with-counter, unlike observe's blocking sink)?
//! 7. Does forwarding work with no database and no vault at all?
//! 8. Can credential attribution work with only the vault's keyed
//!    fingerprint key (matching-only, zeroized on drop)?
//! 9. Does the existing SSRF policy reject unsafe upstream route targets?
//!
//! The forwarder here is transport-generic (`Read + Write`) so tests exercise
//! real streaming semantics over plain TCP; production upstream connections
//! use rustls exactly as `observe::proxy::intercept_https` already does.

#![forbid(unsafe_code)]

use api_tracker_core::error::{CoreError, Result};
use api_tracker_observe::relay;
use api_tracker_observe::wire;
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Hop-by-hop headers a gateway must not forward (RFC 9110 §7.6.1), plus the
/// proxy-specific pair. `Host` is dropped separately (it is rewritten).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// Outcome summary of one forwarded exchange (spike-level detail only).
#[derive(Debug)]
pub struct ForwardSummary {
    pub status: u16,
    pub response_body_bytes: u64,
}

/// Rewrite a raw client request head for upstream forwarding:
/// - strip the `/{route}` prefix from the request target
/// - drop hop-by-hop headers and any header named by `Connection`
/// - replace `Host` with the upstream authority
///
/// Everything else (header order, casing, values, framing headers) is
/// preserved verbatim so the upstream sees the request the client built.
pub fn rewrite_head(raw_head: &[u8], route_prefix: &str, upstream_host: &str) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(raw_head)
        .map_err(|_| CoreError::InvalidInput("non-utf8 request head".into()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| CoreError::InvalidInput("empty head".into()))?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or_else(|| CoreError::InvalidInput("no method".into()))?;
    let target = parts
        .next()
        .ok_or_else(|| CoreError::InvalidInput("no target".into()))?;
    let version = parts
        .next()
        .ok_or_else(|| CoreError::InvalidInput("no version".into()))?;

    let upstream_path = strip_route_prefix(target, route_prefix)
        .ok_or_else(|| CoreError::InvalidInput("target does not match route".into()))?;

    // Headers named in `Connection: ...` are also hop-by-hop.
    let mut connection_named: Vec<String> = Vec::new();
    for line in text.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("connection") {
                connection_named.extend(
                    value
                        .split(',')
                        .map(|t| t.trim().to_ascii_lowercase())
                        .filter(|t| !t.is_empty()),
                );
            }
        }
    }

    let mut out = String::new();
    out.push_str(method);
    out.push(' ');
    out.push_str(&upstream_path);
    out.push(' ');
    out.push_str(version);
    out.push_str("\r\n");
    out.push_str("Host: ");
    out.push_str(upstream_host);
    out.push_str("\r\n");
    for line in lines {
        if line.is_empty() {
            continue; // terminator; re-added below
        }
        let Some((name, _)) = line.split_once(':') else {
            return Err(CoreError::InvalidInput("malformed header line".into()));
        };
        let lname = name.trim().to_ascii_lowercase();
        if lname == "host" || HOP_BY_HOP.contains(&lname.as_str()) {
            continue;
        }
        if connection_named.iter().any(|t| t == &lname) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    Ok(out.into_bytes())
}

/// `/openai/v1/chat` with prefix `openai` → `/v1/chat`. Query preserved.
/// Exact-prefix requests (`/openai`) map to `/`.
fn strip_route_prefix(target: &str, route: &str) -> Option<String> {
    let want = format!("/{route}");
    if target == want {
        return Some("/".to_string());
    }
    let rest = target.strip_prefix(&want)?;
    if rest.starts_with('/') || rest.starts_with('?') {
        let path = if rest.starts_with('?') {
            format!("/{rest}")
        } else {
            rest.to_string()
        };
        return Some(path);
    }
    None // `/openai2/...` must NOT match route `openai`
}

/// Does the raw head carry `Expect: 100-continue`?
fn expects_continue(raw_head: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(raw_head) else {
        return false;
    };
    text.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(n, v)| {
            n.trim().eq_ignore_ascii_case("expect") && v.trim().eq_ignore_ascii_case("100-continue")
        })
    })
}

/// A `Write` that forwards to `inner` and mirrors every written byte into a
/// tap callback. Used to feed the bounded usage extractor DURING the relay
/// without any additional buffering of the body itself.
pub struct TeeWriter<'a, W: Write> {
    inner: W,
    tap: &'a mut dyn FnMut(&[u8]),
}

impl<'a, W: Write> TeeWriter<'a, W> {
    pub fn new(inner: W, tap: &'a mut dyn FnMut(&[u8])) -> Self {
        Self { inner, tap }
    }
}

impl<W: Write> Write for TeeWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        (self.tap)(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Forward exactly one exchange: client request → upstream, upstream response
/// → client, streaming both directions via the observe relay (bounded, no body
/// accumulation). `tap` sees the response body bytes as they stream (for the
/// bounded usage extractor).
///
/// 1xx interim responses are relayed to the client and reading continues until
/// a final response arrives. With `Expect: 100-continue` the interim response
/// is read BEFORE relaying the request body (mirroring the production plan; a
/// production upstream socket additionally uses a short read timeout so an
/// upstream that skips the interim response cannot deadlock the exchange).
pub fn forward_once<C: Read + Write, U: Read + Write>(
    client: &mut C,
    upstream: &mut U,
    route_prefix: &str,
    upstream_host: &str,
    tap: &mut dyn FnMut(&[u8]),
) -> Result<ForwardSummary> {
    let (req_head, raw_head, leftover) = wire::read_request_head(client)?;
    let out_head = rewrite_head(&raw_head, route_prefix, upstream_host)?;
    upstream.write_all(&out_head).map_err(CoreError::Io)?;
    upstream.flush().map_err(CoreError::Io)?;

    let mut req_leftover = leftover;
    // Bytes read from the upstream past a response head. `observe::wire`'s
    // `read_response_head` has NO seedable variant and discards this, which the
    // adversarial review proved hangs the exchange whenever an upstream
    // coalesces `100 Continue` + the final response into one TCP segment. The
    // production gateway ships a seedable response-head reader; the spike proves
    // the fix here with `read_response_head_seeded`.
    let mut resp_carry: Vec<u8> = Vec::new();

    if expects_continue(&raw_head) {
        // Read the interim response first; only relay the body once upstream
        // says 100 (or abandon it on an immediate final response).
        let (head, raw, resp_leftover) =
            read_response_head_seeded(upstream, std::mem::take(&mut resp_carry))?;
        if head.status == 100 {
            client.write_all(&raw).map_err(CoreError::Io)?;
            client.flush().map_err(CoreError::Io)?;
            // CRITICAL: keep any coalesced bytes for the next head read.
            resp_carry = resp_leftover;
        } else {
            // Final response without wanting the body (e.g. 417/401).
            return relay_final_response(
                client,
                upstream,
                head,
                raw,
                resp_leftover,
                &req_head.method,
                tap,
            );
        }
    }

    let (_req_bytes, _carry) = relay::relay_body(
        client,
        upstream,
        req_head.body_framing(),
        std::mem::take(&mut req_leftover),
    )?;

    // Read response(s); relay any further 1xx interim heads verbatim, always
    // seeding the next read with the previous read's carryover.
    loop {
        let (head, raw, resp_leftover) =
            read_response_head_seeded(upstream, std::mem::take(&mut resp_carry))?;
        if (100..200).contains(&head.status) {
            client.write_all(&raw).map_err(CoreError::Io)?;
            client.flush().map_err(CoreError::Io)?;
            resp_carry = resp_leftover;
            continue;
        }
        return relay_final_response(
            client,
            upstream,
            head,
            raw,
            resp_leftover,
            &req_head.method,
            tap,
        );
    }
}

/// Seedable response-head reader: like `observe::wire::read_response_head` but
/// accepts bytes already read from the upstream (the fix the review requires;
/// the production crate adds this to `wire` proper). Parses one status line +
/// headers with httparse, returns the head, the raw head bytes, and any bytes
/// past the head (the start of the body, or a coalesced next head).
fn read_response_head_seeded<R: Read>(
    r: &mut R,
    initial: Vec<u8>,
) -> Result<(wire::ResponseHead, Vec<u8>, Vec<u8>)> {
    // If `initial` already contains a complete head, a Chain lets the existing
    // reader consume it first without a blocking read on the socket.
    let mut chained = std::io::Cursor::new(initial).chain(r);
    wire::read_response_head(&mut chained)
}

fn relay_final_response<C: Read + Write, U: Read>(
    client: &mut C,
    upstream: &mut U,
    head: wire::ResponseHead,
    raw_head: Vec<u8>,
    leftover: Vec<u8>,
    request_method: &str,
    tap: &mut dyn FnMut(&[u8]),
) -> Result<ForwardSummary> {
    client.write_all(&raw_head).map_err(CoreError::Io)?;
    client.flush().map_err(CoreError::Io)?;
    let framing = head.body_framing(request_method);
    let mut tee = TeeWriter::new(&mut *client, tap);
    let (body_bytes, _carry) = relay::relay_body(upstream, &mut tee, framing, leftover)?;
    Ok(ForwardSummary {
        status: head.status,
        response_body_bytes: body_bytes,
    })
}

// ---------------------------------------------------------------------------
// Bounded SSE usage extraction
// ---------------------------------------------------------------------------

/// Incremental SSE scanner that extracts token-usage metadata from a streamed
/// response while holding AT MOST `cap` bytes of any single event, and nothing
/// of the rest of the body. Feed it the bytes as they relay; it never sees the
/// stream again.
///
/// Recognizes (spike scope) the OpenAI shape: a terminal chunk carrying a
/// `"usage": {...}` object, plus `"model"` from any chunk. Oversized events
/// are discarded wholesale and flagged, never partially parsed.
pub struct SseUsageExtractor {
    cap: usize,
    line: Vec<u8>,
    event_data: Vec<u8>,
    oversized: bool,
    dropped_events: u64,
    pub model: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

impl SseUsageExtractor {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            line: Vec::new(),
            event_data: Vec::new(),
            oversized: false,
            dropped_events: 0,
            model: None,
            input_tokens: None,
            output_tokens: None,
        }
    }

    /// Peak transient memory the extractor may hold.
    pub fn bound(&self) -> usize {
        self.cap * 2 // current line + accumulated event data, each capped
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                let line = std::mem::take(&mut self.line);
                self.on_line(&line);
            } else {
                if self.line.len() >= self.cap {
                    // Pathological line: poison the current event, keep
                    // scanning for the next blank line without retaining data.
                    self.oversized = true;
                    self.line.clear();
                    continue;
                }
                self.line.push(b);
            }
        }
    }

    fn on_line(&mut self, line: &[u8]) {
        let line = if line.ends_with(b"\r") {
            &line[..line.len() - 1]
        } else {
            line
        };
        if line.is_empty() {
            // Event boundary.
            let data = std::mem::take(&mut self.event_data);
            let oversized = std::mem::replace(&mut self.oversized, false);
            if oversized {
                self.dropped_events += 1;
            } else if !data.is_empty() {
                self.on_event(&data);
            }
            return;
        }
        if self.oversized {
            return;
        }
        if let Some(rest) = line.strip_prefix(b"data:") {
            let rest = if rest.first() == Some(&b' ') {
                &rest[1..]
            } else {
                rest
            };
            if self.event_data.len() + rest.len() + 1 > self.cap {
                self.oversized = true;
                self.event_data.clear();
                return;
            }
            if !self.event_data.is_empty() {
                self.event_data.push(b'\n');
            }
            self.event_data.extend_from_slice(rest);
        }
        // Non-`data:` fields (event:, id:, retry:, comments) are ignored.
    }

    fn on_event(&mut self, data: &[u8]) {
        if data == b"[DONE]" {
            return;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
            return;
        };
        if self.model.is_none() {
            if let Some(m) = v.get("model").and_then(|m| m.as_str()) {
                self.model = Some(m.to_string());
            }
        }
        if let Some(u) = v.get("usage").filter(|u| !u.is_null()) {
            self.input_tokens = u.get("prompt_tokens").and_then(|t| t.as_u64());
            self.output_tokens = u.get("completion_tokens").and_then(|t| t.as_u64());
        }
    }
}

// ---------------------------------------------------------------------------
// Locked-vault credential attribution via the keyed fingerprint
// ---------------------------------------------------------------------------

/// Attribution states the gateway must distinguish (docs/gateway brief).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    Matched(String),
    Unmatched,
    AmbiguousDuplicate(Vec<String>),
    NoCredentialPresent,
    UnavailableVaultLocked,
}

/// Matching-only credential attributor. Holds the vault's BLAKE3 fingerprint
/// key (which can hash but can never decrypt anything — see
/// `crates/core/src/reuse.rs` and ADR 0005) plus the public
/// `credentials.fingerprint` column values. The key is zeroized on drop.
pub struct FingerprintMatcher {
    key: Option<Zeroizing<[u8; 32]>>,
    /// (fingerprint, credential_id) — fingerprints are already public DB rows.
    table: Vec<(Vec<u8>, String)>,
}

impl FingerprintMatcher {
    pub fn without_key(table: Vec<(Vec<u8>, String)>) -> Self {
        Self { key: None, table }
    }

    pub fn with_key(key: [u8; 32], table: Vec<(Vec<u8>, String)>) -> Self {
        Self {
            key: Some(Zeroizing::new(key)),
            table,
        }
    }

    /// Drop the key (monitoring disabled / gateway stopping): zeroizes.
    pub fn clear_key(&mut self) {
        self.key = None;
    }

    /// Attribute one observed auth-HEADER value (e.g. the full
    /// `Authorization: Bearer sk-...` value, or an `x-api-key` value). The
    /// value is borrowed for the duration of the hash and never retained.
    ///
    /// The stored fingerprint is computed over the credential VALUE the user
    /// saved (`sk-...`), not the header value, so a raw hash of
    /// `"Bearer sk-..."` would NEVER match — the adversarial review's
    /// `auth-header-value-is-not-the-credential-value` finding. We therefore
    /// try both the scheme-stripped and the raw-trimmed forms (two
    /// constant-cost lookups) so both storage conventions match.
    pub fn attribute(&self, auth_value: Option<&str>) -> Attribution {
        let Some(value) = auth_value else {
            return Attribution::NoCredentialPresent;
        };
        let Some(key) = &self.key else {
            return Attribution::UnavailableVaultLocked;
        };
        for candidate in credential_candidates(value) {
            let fp = blake3::keyed_hash(key, candidate.as_bytes());
            let matches: Vec<&String> = self
                .table
                .iter()
                .filter(|(stored, _)| stored.len() == 32 && blake3_eq(stored, fp.as_bytes()))
                .map(|(_, id)| id)
                .collect();
            match matches.len() {
                0 => continue,
                1 => return Attribution::Matched(matches[0].clone()),
                _ => {
                    return Attribution::AmbiguousDuplicate(matches.into_iter().cloned().collect())
                }
            }
        }
        Attribution::Unmatched
    }
}

/// The credential-value forms to try for one auth-header value: the
/// scheme-stripped form (`Authorization: Bearer <v>` → `<v>`) and the
/// whole trimmed value (covers `x-api-key`, `api-key`, `x-goog-api-key`,
/// and stored-with-scheme edge cases). `Basic` is out of scope (v1).
fn credential_candidates(header_value: &str) -> Vec<String> {
    let trimmed = header_value.trim();
    let mut out = Vec::with_capacity(2);
    for scheme in ["bearer ", "token "] {
        if trimmed.len() >= scheme.len() && trimmed[..scheme.len()].eq_ignore_ascii_case(scheme) {
            out.push(trimmed[scheme.len()..].trim().to_string());
        }
    }
    out.push(trimmed.to_string());
    out
}

fn blake3_eq(a: &[u8], b: &[u8; 32]) -> bool {
    // Production uses subtle::ConstantTimeEq (the repo's standard primitive)
    // and resolves the match on the writer thread, not the forwarding path —
    // per the review's constant-time-claim finding. This hand-rolled equality
    // is spike-only.
    if a.len() != 32 {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Framing validation (request-smuggling defence the review requires)
// ---------------------------------------------------------------------------

/// Reject a request head that a proxy must not forward: Transfer-Encoding and
/// Content-Length together, multiple/duplicate Content-Length fields,
/// non-`1*DIGIT` Content-Length, or any bare CR/LF (bare-LF header injection).
/// The production gateway REGENERATES framing headers from the validated
/// result rather than copying them verbatim; this predicate is the gate.
pub fn framing_is_forwardable(raw_head: &[u8]) -> bool {
    // Reject bare LF (not preceded by CR) and bare CR (not followed by LF):
    // httparse tolerates bare-LF line endings, but the head rewriter splits on
    // CRLF, so a mixed head could smuggle a second message. Require strict CRLF.
    for i in 0..raw_head.len() {
        match raw_head[i] {
            b'\n' if i == 0 || raw_head[i - 1] != b'\r' => return false,
            b'\r' if i + 1 >= raw_head.len() || raw_head[i + 1] != b'\n' => return false,
            _ => {}
        }
    }

    let text = match std::str::from_utf8(raw_head) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let mut content_lengths: Vec<&str> = Vec::new();
    let mut has_te = false;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_lengths.push(value);
        } else if name == "transfer-encoding" {
            has_te = true;
            // chunked must be the sole/final coding; anything else is rejected.
            if !value.eq_ignore_ascii_case("chunked") {
                return false;
            }
        }
    }
    if content_lengths.len() > 1 {
        return false; // duplicate Content-Length
    }
    if let Some(cl) = content_lengths.first() {
        if has_te {
            return false; // CL + TE together
        }
        // 1*DIGIT only: reject "+5", "5, 5", "0x10", empty.
        if cl.is_empty() || !cl.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Route target validation (SSRF / open-relay defence reusing observe policy)
// ---------------------------------------------------------------------------

/// Validate a candidate upstream route origin the way the production gateway
/// will: https only, port 443 only, and the observe SSRF policy (loopback,
/// private ranges, link-local, CGNAT, cloud-metadata names all denied).
pub fn validate_route_origin(origin: &str) -> std::result::Result<(String, u16), String> {
    let rest = origin
        .strip_prefix("https://")
        .ok_or_else(|| "route origins must be https".to_string())?;
    if rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err("route origins must be a bare authority (no path)".to_string());
    }
    let (host, port) = if rest.starts_with('[') {
        // Bracketed IPv6 literal, optionally with a port.
        match rest.split_once("]:") {
            Some((h, p)) => {
                let port: u16 = p.parse().map_err(|_| "invalid port".to_string())?;
                (format!("{h}]"), port)
            }
            None => (rest.to_string(), 443),
        }
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p.parse().map_err(|_| "invalid port".to_string())?;
                (h.to_string(), port)
            }
            None => (rest.to_string(), 443),
        }
    };
    if port != 443 {
        return Err("route origins must use port 443".to_string());
    }
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    let allow = api_tracker_observe::policy::AllowList::new();
    let verdict = api_tracker_observe::policy::check_authority(&host, port, &allow);
    if !verdict.is_allowed() {
        return Err("denied by SSRF policy".to_string());
    }
    Ok((host, port))
}
