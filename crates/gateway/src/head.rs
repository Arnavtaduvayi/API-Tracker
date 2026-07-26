//! Bounded HTTP/1.1 head reading, strict framing validation, and canonical
//! head regeneration.
//!
//! This is deliberately NOT `observe::wire`. Two requirements the observe
//! layer does not meet force a gateway-local reader (ADR 0019 D2/D7):
//!
//! 1. **Zeroization.** The gateway is the terminating server for requests
//!    carrying live third-party credentials; `wire`'s buffers are plain
//!    `Vec<u8>`. Every head buffer here is `Zeroizing`, allocated ONCE at
//!    `MAX_HEAD` capacity so growth never leaves an un-zeroed copy behind.
//!    This is best-effort in-process hygiene (SI-7) — swap and core dumps are
//!    documented out of scope.
//! 2. **Seedable response heads.** A coalesced `100 Continue` + final
//!    response in one TCP segment loses the final head unless the bytes read
//!    past the interim seed the next parse (the Phase 1 hang blocker).
//!
//! Everything is rebuilt from PARSED fields with canonical CRLF; the raw
//! bytes are never spliced into the forwarded message, so a head that
//! httparse tolerates but a downstream parser would read differently cannot
//! survive (request smuggling is REJECTED, never normalized — SI-15).

use std::io::Read;
use std::time::Instant;

use api_tracker_core::error::{CoreError, Result};
use zeroize::Zeroizing;

/// Max bytes of a single message head (matches `observe::wire::MAX_HEAD`).
pub const MAX_HEAD: usize = 32 * 1024;
/// Max header fields in one head.
pub const MAX_HEADERS: usize = 100;
/// Max bytes of a request target (request line minus method and version).
pub const MAX_TARGET: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

/// Body framing decided from VALIDATED fields (never from raw bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    None,
    ContentLength(u64),
    Chunked,
    /// Response only: body runs until the connection closes.
    UntilClose,
}

impl Framing {
    /// The equivalent `observe::relay` framing, so the audited streaming
    /// relay can be reused verbatim.
    pub fn to_relay(self) -> api_tracker_observe::wire::BodyFraming {
        use api_tracker_observe::wire::BodyFraming as B;
        match self {
            Framing::None => B::None,
            Framing::ContentLength(n) => B::ContentLength(n),
            Framing::Chunked => B::Chunked,
            Framing::UntilClose => B::UntilClose,
        }
    }
}

/// One header field. Names are non-secret; VALUES may be credentials, so they
/// live in `Zeroizing` for the lifetime of the exchange and are never
/// formatted by `Debug`.
pub struct HeaderField {
    pub name: String,
    pub lower: String,
    pub value: Zeroizing<Vec<u8>>,
}

impl HeaderField {
    /// The value as UTF-8, if it is valid UTF-8. Callers must treat the
    /// result as secret for credential-bearing headers.
    pub fn value_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }
}

impl std::fmt::Debug for HeaderField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print a header value: any one of them may be a credential.
        f.debug_struct("HeaderField")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: HttpVersion,
    pub headers: Vec<HeaderField>,
    pub framing: Framing,
    pub client_wants_close: bool,
    pub expects_continue: bool,
    /// Presence only — the value is read only transiently for attribution
    /// and never stored (SI-8).
    pub had_authorization: bool,
}

impl std::fmt::Debug for RequestHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The target carries the raw query string, so only the path portion
        // is printable — mirroring `observe::wire`'s redaction pattern.
        let path = self
            .target
            .split(['?', '#'])
            .next()
            .unwrap_or("")
            .to_string();
        f.debug_struct("RequestHead")
            .field("method", &self.method)
            .field("path", &path)
            .field("headers", &self.headers.len())
            .field("framing", &self.framing)
            .finish_non_exhaustive()
    }
}

impl RequestHead {
    pub fn header(&self, lower_name: &str) -> Option<&HeaderField> {
        self.headers.iter().find(|h| h.lower == lower_name)
    }
    pub fn header_str(&self, lower_name: &str) -> Option<&str> {
        self.header(lower_name).and_then(|h| h.value_str())
    }
    pub fn has_header(&self, lower_name: &str) -> bool {
        self.headers.iter().any(|h| h.lower == lower_name)
    }
    /// Path with query and fragment severed — the ONLY form that may reach a
    /// stored string (via `sanitize_path`).
    pub fn path_only(&self) -> &str {
        self.target.split(['?', '#']).next().unwrap_or("")
    }
    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, q)| q)
    }
}

#[derive(Debug)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub version: HttpVersion,
    pub headers: Vec<HeaderField>,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub upstream_wants_close: bool,
}

impl ResponseHead {
    pub fn header_str(&self, lower_name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.lower == lower_name)
            .and_then(|h| h.value_str())
    }

    /// Response framing per RFC 9112 §6.3, decided from validated fields.
    pub fn framing(&self, request_method: &str) -> Framing {
        if request_method.eq_ignore_ascii_case("HEAD")
            || (100..200).contains(&self.status)
            || self.status == 204
            || self.status == 304
        {
            return Framing::None;
        }
        if self.chunked {
            return Framing::Chunked;
        }
        match self.content_length {
            Some(n) => Framing::ContentLength(n),
            // Neither framing header: the body is delimited by connection
            // close, which is connection-terminal for the gateway.
            None => Framing::UntilClose,
        }
    }
}

/// Bytes read past the end of a head (the start of a body, or a coalesced
/// next head). Zeroized because a request carryover is body bytes.
pub type Carryover = Zeroizing<Vec<u8>>;

fn head_buffer(initial: Carryover) -> Zeroizing<Vec<u8>> {
    // One allocation at the maximum head size: `Vec` growth would reallocate
    // and leave the old (credential-bearing) bytes un-zeroed on the heap.
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_HEAD));
    buf.extend_from_slice(&initial);
    buf
}

fn is_would_block(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Read one request head, bounded in size and (optionally) by an absolute
/// deadline. The caller must set a per-read socket timeout shorter than the
/// deadline so the loop wakes to observe it (the `observe::wire` contract).
///
/// `Ok(None)` means the peer closed cleanly before sending any byte of a
/// head — the ordinary end of a kept-alive connection, distinct from a
/// protocol error (which the caller answers with 400).
pub fn read_request_head<R: Read>(
    r: &mut R,
    initial: Carryover,
    deadline: Option<Instant>,
) -> Result<Option<(RequestHead, Carryover)>> {
    let mut buf = head_buffer(initial);
    let mut tmp = Zeroizing::new(vec![0u8; 4096]);
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                validate_raw_head(&buf[..n])?;
                let method = req.method.unwrap_or("").to_string();
                let target = req.path.unwrap_or("").to_string();
                if target.len() > MAX_TARGET {
                    return Err(CoreError::InvalidInput("request target too long".into()));
                }
                validate_token(&method, "method")?;
                validate_target_charset(&target)?;
                let version = match req.version {
                    Some(0) => HttpVersion::Http10,
                    _ => HttpVersion::Http11,
                };
                let fields = collect_headers(req.headers)?;
                let framing = validate_request_framing(&fields)?;
                let client_wants_close = wants_close(&fields, version);
                let expects_continue = fields.iter().any(|h| {
                    h.lower == "expect"
                        && h.value_str()
                            .is_some_and(|v| v.trim().eq_ignore_ascii_case("100-continue"))
                });
                let had_authorization = fields.iter().any(|h| {
                    matches!(
                        h.lower.as_str(),
                        "authorization" | "x-api-key" | "x-goog-api-key" | "api-key"
                    )
                });
                let carry = Zeroizing::new(buf[n..].to_vec());
                return Ok(Some((
                    RequestHead {
                        method,
                        target,
                        version,
                        headers: fields,
                        framing,
                        client_wants_close,
                        expects_continue,
                        had_authorization,
                    },
                    carry,
                )));
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Err(CoreError::InvalidInput("malformed request head".into())),
        }
        if buf.len() >= MAX_HEAD {
            return Err(CoreError::InvalidInput("request head exceeds limit".into()));
        }
        if let Some(d) = deadline {
            if Instant::now() >= d {
                return if buf.is_empty() {
                    // The peer sent nothing at all: an idle kept-alive
                    // connection timing out, indistinguishable from a clean
                    // close. Answering a 400 to a request nobody made would
                    // be noise, so this reports "no request" instead.
                    Ok(None)
                } else {
                    // A PARTIAL head past the deadline is the Slowloris case
                    // and is a hard error.
                    Err(CoreError::InvalidInput(
                        "request head not completed before deadline".into(),
                    ))
                };
            }
        }
        let want = std::cmp::min(tmp.len(), MAX_HEAD - buf.len());
        let n = match r.read(&mut tmp[..want]) {
            Ok(n) => n,
            Err(e) if deadline.is_some() && is_would_block(&e) => continue,
            Err(e) => return Err(CoreError::Io(e)),
        };
        if n == 0 {
            return if buf.is_empty() {
                Ok(None) // clean end of a kept-alive connection
            } else {
                Err(CoreError::InvalidInput(
                    "connection closed before request head completed".into(),
                ))
            };
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// The outcome of a deadline-bounded response-head read.
pub enum HeadRead {
    Complete(Box<ResponseHead>, Carryover),
    /// The deadline passed with an incomplete head. The bytes read so far are
    /// returned so the next attempt can seed with them — losing them would
    /// desynchronize the connection.
    TimedOut(Carryover),
}

/// Read one response head, SEEDED with bytes already read from the upstream.
/// Seeding is what keeps a coalesced `100 Continue` + final response from
/// losing the final head (the Phase 1 hang blocker).
pub fn read_response_head<R: Read>(
    r: &mut R,
    initial: Carryover,
) -> Result<(ResponseHead, Carryover)> {
    match read_response_head_deadline(r, initial, None)? {
        HeadRead::Complete(head, carry) => Ok((*head, carry)),
        HeadRead::TimedOut(_) => unreachable!("no deadline was set"),
    }
}

/// Deadline-bounded seeded response-head read. With `deadline` set, the
/// caller must also set a per-read socket timeout so the loop wakes.
pub fn read_response_head_deadline<R: Read>(
    r: &mut R,
    initial: Carryover,
    deadline: Option<Instant>,
) -> Result<HeadRead> {
    let mut buf = head_buffer(initial);
    let mut tmp = Zeroizing::new(vec![0u8; 4096]);
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                validate_raw_head(&buf[..n])?;
                let status = resp.code.unwrap_or(0);
                if !(100..=599).contains(&status) {
                    return Err(CoreError::InvalidInput("invalid response status".into()));
                }
                let reason = resp
                    .reason
                    .filter(|r| {
                        r.len() <= 128 && r.bytes().all(|b| b == b'\t' || (0x20..0x7f).contains(&b))
                    })
                    .unwrap_or("")
                    .to_string();
                let version = match resp.version {
                    Some(0) => HttpVersion::Http10,
                    _ => HttpVersion::Http11,
                };
                let fields = collect_headers(resp.headers)?;
                let (content_length, chunked) = validate_response_framing(&fields)?;
                let upstream_wants_close = wants_close(&fields, version);
                let carry = Zeroizing::new(buf[n..].to_vec());
                return Ok(HeadRead::Complete(
                    Box::new(ResponseHead {
                        status,
                        reason,
                        version,
                        headers: fields,
                        content_length,
                        chunked,
                        upstream_wants_close,
                    }),
                    carry,
                ));
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Err(CoreError::InvalidInput("malformed response head".into())),
        }
        if buf.len() >= MAX_HEAD {
            return Err(CoreError::InvalidInput(
                "response head exceeds limit".into(),
            ));
        }
        if let Some(d) = deadline {
            if Instant::now() >= d {
                return Ok(HeadRead::TimedOut(buf));
            }
        }
        let want = std::cmp::min(tmp.len(), MAX_HEAD - buf.len());
        let n = match r.read(&mut tmp[..want]) {
            Ok(n) => n,
            Err(e) if deadline.is_some() && is_would_block(&e) => continue,
            Err(e) => return Err(CoreError::Io(e)),
        };
        if n == 0 {
            return Err(if buf.is_empty() {
                CoreError::InvalidInput("no response".into())
            } else {
                CoreError::InvalidInput("connection closed before response head completed".into())
            });
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Strict line-ending and structure validation over the RAW head bytes.
///
/// httparse tolerates bare LF; a gateway must not, because a downstream or
/// upstream parser that disagrees about where a message ends is exactly the
/// request-smuggling primitive. Obsolete line folding is rejected for the
/// same reason.
fn validate_raw_head(raw: &[u8]) -> Result<()> {
    let bad = |what: &str| Err(CoreError::InvalidInput(format!("malformed head: {what}")));
    for (i, b) in raw.iter().enumerate() {
        match b {
            b'\n' if i == 0 || raw[i - 1] != b'\r' => return bad("bare LF"),
            b'\r' if i + 1 >= raw.len() || raw[i + 1] != b'\n' => return bad("bare CR"),
            0x00 => return bad("NUL byte"),
            _ => {}
        }
    }
    // Obsolete folding: a header line continued with leading SP/HTAB.
    let mut idx = 0usize;
    while let Some(pos) = find(&raw[idx..], b"\r\n") {
        let next = idx + pos + 2;
        if next >= raw.len() {
            break;
        }
        if raw[next] == b' ' || raw[next] == b'\t' {
            return bad("obsolete line folding");
        }
        idx = next;
    }
    Ok(())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn collect_headers(headers: &[httparse::Header<'_>]) -> Result<Vec<HeaderField>> {
    let mut out = Vec::with_capacity(headers.len());
    for h in headers {
        if h.name.is_empty() {
            continue;
        }
        validate_token(h.name, "header name")?;
        // A CR or LF inside a value would inject a header line on rebuild.
        if h.value
            .iter()
            .any(|b| *b == b'\r' || *b == b'\n' || *b == 0)
        {
            return Err(CoreError::InvalidInput(
                "header value contains a control character".into(),
            ));
        }
        out.push(HeaderField {
            name: h.name.to_string(),
            lower: h.name.to_ascii_lowercase(),
            value: Zeroizing::new(h.value.to_vec()),
        });
    }
    if out.len() > MAX_HEADERS {
        return Err(CoreError::InvalidInput("too many header fields".into()));
    }
    Ok(out)
}

/// RFC 9110 token: visible ASCII minus separators.
fn validate_token(s: &str, what: &str) -> Result<()> {
    const SEPARATORS: &[u8] = b"()<>@,;:\\\"/[]?={} \t";
    if s.is_empty() || s.len() > 256 {
        return Err(CoreError::InvalidInput(format!("invalid {what}")));
    }
    for b in s.bytes() {
        if !(0x21..0x7f).contains(&b) || SEPARATORS.contains(&b) {
            return Err(CoreError::InvalidInput(format!("invalid {what}")));
        }
    }
    Ok(())
}

/// The request target must be printable ASCII with no spaces or controls;
/// anything else is a parser-disagreement primitive.
fn validate_target_charset(target: &str) -> Result<()> {
    if target.is_empty() {
        return Err(CoreError::InvalidInput("empty request target".into()));
    }
    for b in target.bytes() {
        if !(0x21..0x7f).contains(&b) {
            return Err(CoreError::InvalidInput(
                "request target contains an invalid character".into(),
            ));
        }
    }
    Ok(())
}

/// Request framing validation: Transfer-Encoding and Content-Length together,
/// duplicate or non-`1*DIGIT` Content-Length, and any Transfer-Encoding whose
/// final coding is not `chunked` are hard errors (400 + close), never
/// normalized-and-forwarded.
fn validate_request_framing(fields: &[HeaderField]) -> Result<Framing> {
    let (cl, te) = framing_headers(fields)?;
    match (cl, te) {
        (Some(_), Some(_)) => Err(CoreError::InvalidInput(
            "both Content-Length and Transfer-Encoding present".into(),
        )),
        (Some(n), None) => Ok(Framing::ContentLength(n)),
        (None, Some(())) => Ok(Framing::Chunked),
        (None, None) => Ok(Framing::None),
    }
}

/// Response framing validation, returning the validated (content_length,
/// chunked) pair. A response carrying both is an upstream desync attempt and
/// is refused before any byte reaches the client.
fn validate_response_framing(fields: &[HeaderField]) -> Result<(Option<u64>, bool)> {
    let (cl, te) = framing_headers(fields)?;
    if cl.is_some() && te.is_some() {
        return Err(CoreError::InvalidInput(
            "response has both Content-Length and Transfer-Encoding".into(),
        ));
    }
    Ok((cl, te.is_some()))
}

#[allow(clippy::type_complexity)]
fn framing_headers(fields: &[HeaderField]) -> Result<(Option<u64>, Option<()>)> {
    let mut content_length: Option<u64> = None;
    let mut seen_cl = false;
    let mut chunked = false;
    for f in fields {
        match f.lower.as_str() {
            "content-length" => {
                if seen_cl {
                    return Err(CoreError::InvalidInput("duplicate Content-Length".into()));
                }
                seen_cl = true;
                let v = f
                    .value_str()
                    .ok_or_else(|| CoreError::InvalidInput("non-utf8 Content-Length".into()))?
                    .trim();
                // 1*DIGIT only: rejects "5, 5", "+5", "0x10", "", and any
                // value a lenient parser would read differently.
                if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(CoreError::InvalidInput("invalid Content-Length".into()));
                }
                content_length = Some(
                    v.parse::<u64>()
                        .map_err(|_| CoreError::InvalidInput("invalid Content-Length".into()))?,
                );
            }
            "transfer-encoding" => {
                if chunked {
                    return Err(CoreError::InvalidInput(
                        "multiple Transfer-Encoding fields".into(),
                    ));
                }
                let v = f
                    .value_str()
                    .ok_or_else(|| CoreError::InvalidInput("non-utf8 Transfer-Encoding".into()))?;
                // Only a lone `chunked` is accepted: `chunked, gzip` (chunked
                // not final), `gzip` alone, and `identity` are all refused
                // rather than guessed at.
                if !v.trim().eq_ignore_ascii_case("chunked") {
                    return Err(CoreError::InvalidInput(
                        "unsupported Transfer-Encoding".into(),
                    ));
                }
                chunked = true;
            }
            _ => {}
        }
    }
    Ok((content_length, chunked.then_some(())))
}

fn wants_close(fields: &[HeaderField], version: HttpVersion) -> bool {
    for f in fields {
        if f.lower == "connection" {
            if let Some(v) = f.value_str() {
                let v = v.to_ascii_lowercase();
                if v.split(',').any(|t| t.trim() == "close") {
                    return true;
                }
                if v.split(',').any(|t| t.trim() == "keep-alive") {
                    return false;
                }
            }
        }
    }
    version == HttpVersion::Http10
}

/// Hop-by-hop headers a gateway must not forward (RFC 9110 §7.6.1) plus the
/// proxy-specific pair. `Host` is handled separately (rewritten).
pub const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Header tokens named by a `Connection:` field are hop-by-hop too.
pub fn connection_named(fields: &[HeaderField]) -> Vec<String> {
    let mut out = Vec::new();
    for f in fields {
        if f.lower == "connection" {
            if let Some(v) = f.value_str() {
                out.extend(
                    v.split(',')
                        .map(|t| t.trim().to_ascii_lowercase())
                        .filter(|t| !t.is_empty()),
                );
            }
        }
    }
    out
}

/// Build the upstream request head from PARSED fields with canonical CRLF.
///
/// Framing headers are REGENERATED from the validated value (never copied),
/// so the gateway and the upstream provably agree on where the body ends.
/// `Cookie` is stripped in this direction (SI-4a) — cookies ignore port, so
/// the loopback listener shares 127.0.0.1's jar with every local dev server,
/// and no API SDK depends on them.
pub fn build_upstream_head(
    head: &RequestHead,
    upstream_target: &str,
    upstream_host: &str,
    keep_alive: bool,
    force_identity_encoding: bool,
) -> Zeroizing<Vec<u8>> {
    let named = connection_named(&head.headers);
    let mut out = Zeroizing::new(Vec::with_capacity(1024));
    out.extend_from_slice(head.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(upstream_target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(upstream_host.as_bytes());
    out.extend_from_slice(b"\r\n");
    for f in &head.headers {
        if f.lower == "host"
            || f.lower == "cookie"
            || f.lower == "content-length"
            || HOP_BY_HOP.contains(&f.lower.as_str())
            || named.contains(&f.lower)
        {
            continue;
        }
        if force_identity_encoding && f.lower == "accept-encoding" {
            continue;
        }
        out.extend_from_slice(f.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&f.value);
        out.extend_from_slice(b"\r\n");
    }
    if force_identity_encoding {
        // A compressed response defeats a bounded tail scan, and the relay
        // never decompresses (zip-bomb surface). Documented wire change.
        out.extend_from_slice(b"Accept-Encoding: identity\r\n");
    }
    match head.framing {
        Framing::ContentLength(n) => {
            out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
        }
        Framing::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
        Framing::None | Framing::UntilClose => {}
    }
    out.extend_from_slice(if keep_alive {
        b"Connection: keep-alive\r\n".as_slice()
    } else {
        b"Connection: close\r\n".as_slice()
    });
    out.extend_from_slice(b"\r\n");
    out
}

/// Response headers the gateway must not relay to the client.
///
/// `Set-Cookie` is stripped for the same port-blind cookie-jar reason as
/// `Cookie`; `Access-Control-*` is stripped so a provider's CORS headers can
/// never make the loopback endpoint readable to a web page (SI-4).
fn strip_from_response(lower: &str, named: &[String]) -> bool {
    lower == "set-cookie"
        || lower.starts_with("access-control-")
        || lower == "content-length"
        || HOP_BY_HOP.contains(&lower)
        || lower.starts_with("proxy-")
        || named.iter().any(|t| t == lower)
}

/// Build the client-facing response head from PARSED fields. The framing
/// headers and `Connection` are regenerated from the gateway's own decisions.
pub fn build_client_response_head(
    head: &ResponseHead,
    framing: Framing,
    keep_alive: bool,
) -> Zeroizing<Vec<u8>> {
    let named = connection_named(&head.headers);
    let mut out = Zeroizing::new(Vec::with_capacity(1024));
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(head.status.to_string().as_bytes());
    if !head.reason.is_empty() {
        out.push(b' ');
        out.extend_from_slice(head.reason.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    for f in &head.headers {
        if strip_from_response(&f.lower, &named) {
            continue;
        }
        out.extend_from_slice(f.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&f.value);
        out.extend_from_slice(b"\r\n");
    }
    match framing {
        Framing::ContentLength(n) => {
            out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
        }
        Framing::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
        Framing::UntilClose => {}
        Framing::None => {
            // A bodyless response still describes the body the equivalent GET
            // would return (RFC 9110 §9.3.2 for HEAD, §15.4.5 for 304), so the
            // declared length is preserved even though no body follows. 1xx
            // and 204 must carry no content length at all.
            if !(100..200).contains(&head.status) && head.status != 204 {
                if let Some(n) = head.content_length {
                    out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
                } else if head.chunked {
                    out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
                }
            }
        }
    }
    out.extend_from_slice(if keep_alive {
        b"Connection: keep-alive\r\n".as_slice()
    } else {
        b"Connection: close\r\n".as_slice()
    });
    out.extend_from_slice(b"\r\n");
    out
}

/// Relay an interim (1xx) response head to the client, sanitized the same way
/// as a final head. Interim heads carry no body.
pub fn build_client_interim_head(head: &ResponseHead) -> Zeroizing<Vec<u8>> {
    let named = connection_named(&head.headers);
    let mut out = Zeroizing::new(Vec::with_capacity(128));
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(head.status.to_string().as_bytes());
    if !head.reason.is_empty() {
        out.push(b' ');
        out.extend_from_slice(head.reason.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    for f in &head.headers {
        if strip_from_response(&f.lower, &named) {
            continue;
        }
        out.extend_from_slice(f.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&f.value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn read_req(raw: &[u8]) -> Result<RequestHead> {
        let mut c = Cursor::new(raw.to_vec());
        read_request_head(&mut c, Zeroizing::new(Vec::new()), None)
            .map(|v| v.expect("head present").0)
    }

    #[test]
    fn well_formed_heads_parse_with_their_framing() {
        let h = read_req(b"POST /openai/v1/x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n")
            .unwrap();
        assert_eq!(h.framing, Framing::ContentLength(5));
        assert_eq!(h.method, "POST");
        assert_eq!(h.path_only(), "/openai/v1/x");

        let h =
            read_req(b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        assert_eq!(h.framing, Framing::Chunked);

        let h = read_req(b"GET /x?q=secret HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();
        assert_eq!(h.framing, Framing::None);
        assert_eq!(h.path_only(), "/x");
        assert_eq!(h.query(), Some("q=secret"));
        // Debug must never print query material.
        assert!(!format!("{h:?}").contains("secret"));
    }

    #[test]
    fn smuggling_shapes_are_rejected() {
        for bad in [
            &b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5, 5\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0x10\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length:  \r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST /x HTTP/1.1\nHost: h\nX-Evil: 1\n\n",
            b"POST /x HTTP/1.1\r\nHost: h\r\n X-Folded: 1\r\n\r\n",
        ] {
            assert!(
                read_req(bad).is_err(),
                "must reject: {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn oversized_and_overcounted_heads_are_rejected() {
        let mut raw = b"GET /x HTTP/1.1\r\nHost: h\r\n".to_vec();
        for i in 0..(MAX_HEADERS + 20) {
            raw.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        assert!(read_req(&raw).is_err(), "header count must be bounded");

        let mut raw = b"GET /x HTTP/1.1\r\nHost: h\r\nX-Big: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_HEAD + 1024));
        raw.extend_from_slice(b"\r\n\r\n");
        assert!(read_req(&raw).is_err(), "head size must be bounded");
    }

    #[test]
    fn upstream_head_is_rebuilt_canonically() {
        let h = read_req(
            b"POST /openai/v1/chat HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n\
              Authorization: Bearer FAKE-TEST-NOT-A-REAL-KEY\r\n\
              Cookie: session=abc\r\nConnection: keep-alive, X-Drop\r\n\
              X-Drop: 1\r\nContent-Length: 2\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        let out = build_upstream_head(&h, "/v1/chat", "api.openai.com", true, false);
        let text = String::from_utf8(out.to_vec()).unwrap();
        assert!(text.starts_with("POST /v1/chat HTTP/1.1\r\nHost: api.openai.com\r\n"));
        assert!(text.contains("Authorization: Bearer FAKE-TEST-NOT-A-REAL-KEY\r\n"));
        assert!(text.contains("Accept: */*\r\n"));
        assert!(!text.contains("Cookie"), "cookies are stripped");
        assert!(!text.contains("X-Drop"), "Connection-named headers dropped");
        assert_eq!(text.matches("Content-Length: 2").count(), 1);
        assert_eq!(text.matches("Connection: ").count(), 1);
        assert!(text.ends_with("\r\n\r\n"));
        assert!(
            !text.contains("127.0.0.1"),
            "client Host is never forwarded"
        );
    }

    #[test]
    fn identity_encoding_replaces_client_accept_encoding() {
        let h =
            read_req(b"GET /x HTTP/1.1\r\nHost: h\r\nAccept-Encoding: gzip, br\r\n\r\n").unwrap();
        let out = build_upstream_head(&h, "/x", "api.openai.com", true, true);
        let text = String::from_utf8(out.to_vec()).unwrap();
        assert!(text.contains("Accept-Encoding: identity\r\n"));
        assert!(!text.contains("gzip"));
    }

    #[test]
    fn response_head_is_sanitized() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                    Set-Cookie: a=b\r\nAccess-Control-Allow-Origin: *\r\n\
                    Connection: keep-alive, X-Drop\r\nX-Drop: 1\r\nKeep-Alive: timeout=5\r\n\
                    x-request-id: req_abc\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut c = Cursor::new(raw.to_vec());
        let (head, _) = read_response_head(&mut c, Zeroizing::new(Vec::new())).unwrap();
        assert_eq!(head.status, 200);
        assert!(head.chunked);
        let out = build_client_response_head(&head, Framing::Chunked, false);
        let text = String::from_utf8(out.to_vec()).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("x-request-id: req_abc\r\n"));
        assert!(text.contains("Content-Type: text/event-stream\r\n"));
        assert!(!text.contains("Set-Cookie"));
        assert!(!text.contains("Access-Control"));
        assert!(!text.contains("X-Drop"));
        assert!(!text.contains("Keep-Alive"));
        assert!(text.contains("Transfer-Encoding: chunked\r\n"));
        assert!(text.contains("Connection: close\r\n"));
    }

    #[test]
    fn response_framing_follows_rfc_and_rejects_conflicts() {
        let mk = |raw: &[u8]| {
            let mut c = Cursor::new(raw.to_vec());
            read_response_head(&mut c, Zeroizing::new(Vec::new()))
        };
        let (h, _) = mk(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(h.framing("GET"), Framing::None);
        let (h, _) = mk(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n").unwrap();
        assert_eq!(h.framing("HEAD"), Framing::None);
        assert_eq!(h.framing("GET"), Framing::ContentLength(7));
        let (h, _) = mk(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n").unwrap();
        assert_eq!(h.framing("GET"), Framing::None);
        let (h, _) = mk(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        assert_eq!(h.framing("GET"), Framing::UntilClose);
        assert!(
            mk(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n")
                .is_err()
        );
    }

    #[test]
    fn seeded_response_read_handles_a_coalesced_interim_and_final() {
        // The exact packet shape that dropped the final head in Phase 1.
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone";
        let mut c = Cursor::new(raw.to_vec());
        let (interim, carry) = read_response_head(&mut c, Zeroizing::new(Vec::new())).unwrap();
        assert_eq!(interim.status, 100);
        assert!(
            !carry.is_empty(),
            "the coalesced bytes must be carried over"
        );
        // No further bytes are available from the reader; the final head must
        // come entirely from the carryover.
        let (final_head, body) = read_response_head(&mut c, carry).unwrap();
        assert_eq!(final_head.status, 200);
        assert_eq!(&body[..], b"done");
    }

    #[test]
    fn carryover_from_a_request_head_is_the_body_start() {
        let mut c = Cursor::new(
            b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhelloEXTRA".to_vec(),
        );
        let (head, carry) = read_request_head(&mut c, Zeroizing::new(Vec::new()), None)
            .unwrap()
            .expect("head present");
        assert_eq!(head.framing, Framing::ContentLength(5));
        assert_eq!(&carry[..], b"helloEXTRA");
    }
}
