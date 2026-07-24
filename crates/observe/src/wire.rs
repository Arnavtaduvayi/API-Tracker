//! Bounded HTTP/1.x head parsing.
//!
//! We parse ONLY message heads (request line / status line + headers), never
//! bodies. From a head we extract the small set of framing-relevant and
//! metadata facts we need — method, target, version, host, body framing,
//! whether an `Authorization` header was present (a boolean; the value is never
//! read), and the coarse content type. Bodies are streamed by
//! [`crate::relay`], never accumulated here.
//!
//! Heads are bounded (`MAX_HEAD` total, `MAX_HEADERS` count); an oversized head
//! is a hard error (Slowloris / oversized-header defence).

use api_tracker_core::error::{CoreError, Result};
use std::io::Read;
use std::time::Instant;

/// Maximum bytes of a single message head.
pub const MAX_HEAD: usize = 32 * 1024;
/// Maximum number of header fields.
pub const MAX_HEADERS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    fn from_httparse(v: Option<u8>) -> Self {
        match v {
            Some(0) => HttpVersion::Http10,
            _ => HttpVersion::Http11,
        }
    }
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body.
    None,
    /// Exactly N bytes.
    ContentLength(u64),
    /// Chunked transfer-encoding.
    Chunked,
    /// Until the connection closes (response only).
    UntilClose,
}

#[derive(Clone)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: HttpVersion,
    pub host: Option<String>,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub connection_close: bool,
    pub had_authorization: bool,
    pub content_type: Option<String>,
    pub upgrade: Option<String>,
    /// The `Proxy-Authorization` value, used ONLY for the proxy auth check and
    /// then dropped. Never stored, never logged.
    pub proxy_authorization: Option<String>,
}

// Manual Debug: `target` carries the raw query string and `proxy_authorization`
// embeds the per-session proxy token. Redact both so a future `{:?}` (error
// context, log line) can never print secret material. There is no Debug sink in
// the hot path today; this makes that safe by construction.
impl std::fmt::Debug for RequestHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path_only = self.target.split(['?', '#']).next().unwrap_or(&self.target);
        f.debug_struct("RequestHead")
            .field("method", &self.method)
            .field("target", &format_args!("{path_only}?<redacted>"))
            .field("version", &self.version)
            .field("host", &self.host)
            .field("content_length", &self.content_length)
            .field("chunked", &self.chunked)
            .field("connection_close", &self.connection_close)
            .field("had_authorization", &self.had_authorization)
            .field("content_type", &self.content_type)
            .field("upgrade", &self.upgrade)
            .field(
                "proxy_authorization",
                &self.proxy_authorization.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl RequestHead {
    pub fn body_framing(&self) -> BodyFraming {
        if self.method.eq_ignore_ascii_case("CONNECT") {
            return BodyFraming::None;
        }
        if self.chunked {
            return BodyFraming::Chunked;
        }
        match self.content_length {
            Some(n) => BodyFraming::ContentLength(n),
            None => BodyFraming::None,
        }
    }

    pub fn is_websocket_upgrade(&self) -> bool {
        self.upgrade
            .as_deref()
            .map(|u| u.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub status: u16,
    pub version: HttpVersion,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub connection_close: bool,
    pub content_type: Option<String>,
}

impl ResponseHead {
    /// Response body framing, given the request method (HEAD responses and
    /// 1xx/204/304 have no body regardless of headers).
    pub fn body_framing(&self, request_method: &str) -> BodyFraming {
        if request_method.eq_ignore_ascii_case("HEAD")
            || matches!(self.status, 100..=199 | 204 | 304)
        {
            return BodyFraming::None;
        }
        if self.chunked {
            return BodyFraming::Chunked;
        }
        match self.content_length {
            Some(n) => BodyFraming::ContentLength(n),
            None => BodyFraming::UntilClose,
        }
    }
}

fn header_ci<'a>(headers: &'a [httparse::Header<'a>], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value)
}

fn header_str(headers: &[httparse::Header<'_>], name: &str) -> Option<String> {
    header_ci(headers, name).and_then(|v| std::str::from_utf8(v).ok().map(|s| s.trim().to_string()))
}

fn is_chunked(headers: &[httparse::Header<'_>]) -> bool {
    header_ci(headers, "transfer-encoding")
        .and_then(|v| std::str::from_utf8(v).ok())
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
}

fn connection_close(headers: &[httparse::Header<'_>], version: HttpVersion) -> bool {
    match header_ci(headers, "connection").and_then(|v| std::str::from_utf8(v).ok()) {
        Some(v) => {
            let v = v.to_ascii_lowercase();
            if v.contains("close") {
                true
            } else if v.contains("keep-alive") {
                false
            } else {
                version == HttpVersion::Http10
            }
        }
        None => version == HttpVersion::Http10,
    }
}

/// Read bytes until a complete message head is parsed. Returns the parsed head,
/// the RAW head bytes (for verbatim forwarding), and any leftover bytes already
/// read past the head (the start of the body).
pub fn read_request_head<R: Read>(r: &mut R) -> Result<(RequestHead, Vec<u8>, Vec<u8>)> {
    read_head_inner(r, Vec::new(), None)
}

/// Like [`read_request_head`], but seeds the parse buffer with `initial` bytes
/// carried over from a previous message on a kept-alive connection.
pub fn read_request_head_from<R: Read>(
    r: &mut R,
    initial: Vec<u8>,
) -> Result<(RequestHead, Vec<u8>, Vec<u8>)> {
    read_head_inner(r, initial, None)
}

/// Like [`read_request_head`], but also fails once `deadline` passes, an
/// absolute wall-clock bound on completing the head that is independent of the
/// per-read idle timeout. Used for the untrusted pre-auth read so a Slowloris
/// dribbling bytes just under the idle timeout cannot hold a connection slot
/// indefinitely. The caller must set a per-read timeout shorter than the
/// deadline so the loop wakes to observe it.
pub fn read_request_head_deadline<R: Read>(
    r: &mut R,
    deadline: Instant,
) -> Result<(RequestHead, Vec<u8>, Vec<u8>)> {
    read_head_inner(r, Vec::new(), Some(deadline))
}

fn read_head_inner<R: Read>(
    r: &mut R,
    initial: Vec<u8>,
    deadline: Option<Instant>,
) -> Result<(RequestHead, Vec<u8>, Vec<u8>)> {
    let mut buf: Vec<u8> = initial;
    let mut tmp = [0u8; 4096];
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                let version = HttpVersion::from_httparse(req.version);
                let method = req.method.unwrap_or("").to_string();
                let target = req.path.unwrap_or("").to_string();
                let hs = req.headers;
                let content_length = header_str(hs, "content-length").and_then(|v| v.parse().ok());
                let chunked = is_chunked(hs);
                let close = connection_close(hs, version);
                let had_authorization = header_ci(hs, "authorization").is_some();
                let content_type = header_str(hs, "content-type");
                let upgrade = header_str(hs, "upgrade");
                let host = header_str(hs, "host");
                let proxy_authorization = header_str(hs, "proxy-authorization");
                let raw_head = buf[..n].to_vec();
                let leftover = buf[n..].to_vec();
                return Ok((
                    RequestHead {
                        method,
                        target,
                        version,
                        host,
                        content_length,
                        chunked,
                        connection_close: close,
                        had_authorization,
                        content_type,
                        upgrade,
                        proxy_authorization,
                    },
                    raw_head,
                    leftover,
                ));
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Err(CoreError::InvalidInput("malformed request head".into())),
        }
        if buf.len() > MAX_HEAD {
            return Err(CoreError::InvalidInput("request head exceeds limit".into()));
        }
        if let Some(d) = deadline {
            if Instant::now() >= d {
                return Err(CoreError::InvalidInput(
                    "request head not completed before deadline".into(),
                ));
            }
        }
        let n = match r.read(&mut tmp) {
            Ok(n) => n,
            // With a deadline set, an idle-timeout read is not fatal: loop to
            // re-check the absolute deadline (the caller sets a short per-read
            // timeout so the loop wakes to observe it).
            Err(e) if deadline.is_some() && is_would_block(&e) => continue,
            Err(e) => return Err(CoreError::Io(e)),
        };
        if n == 0 {
            return Err(CoreError::InvalidInput(
                "connection closed before request head completed".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn is_would_block(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Read a complete response head. Returns the head, RAW head bytes, and
/// leftover body bytes.
pub fn read_response_head<R: Read>(r: &mut R) -> Result<(ResponseHead, Vec<u8>, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(&buf) {
            Ok(httparse::Status::Complete(n)) => {
                let version = HttpVersion::from_httparse(resp.version);
                let status = resp.code.unwrap_or(0);
                let hs = resp.headers;
                let content_length = header_str(hs, "content-length").and_then(|v| v.parse().ok());
                let chunked = is_chunked(hs);
                let close = connection_close(hs, version);
                let content_type = header_str(hs, "content-type");
                let raw_head = buf[..n].to_vec();
                let leftover = buf[n..].to_vec();
                return Ok((
                    ResponseHead {
                        status,
                        version,
                        content_length,
                        chunked,
                        connection_close: close,
                        content_type,
                    },
                    raw_head,
                    leftover,
                ));
            }
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Err(CoreError::InvalidInput("malformed response head".into())),
        }
        if buf.len() > MAX_HEAD {
            return Err(CoreError::InvalidInput(
                "response head exceeds limit".into(),
            ));
        }
        let n = r.read(&mut tmp).map_err(CoreError::Io)?;
        if n == 0 {
            if buf.is_empty() {
                return Err(CoreError::InvalidInput("no response".into()));
            }
            return Err(CoreError::InvalidInput(
                "connection closed before response head completed".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Parse a CONNECT authority (`host:port`) into `(host, port)`.
pub fn parse_authority(target: &str) -> Option<(String, u16)> {
    // IPv6 literal in brackets: [::1]:443
    if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        let port: u16 = port.parse().ok()?;
        return Some((format!("[{host}]"), port));
    }
    let (host, port) = target.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

/// Split an absolute-form request target (`http://host[:port]/path`) into
/// `(host, port, origin_form_path)`.
pub fn split_absolute_form(target: &str) -> Option<(String, u16, String)> {
    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_a_request_head_and_leftover_body() {
        let raw = b"POST /v1/chat?k=SECRET HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-SECRET\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let mut c = Cursor::new(raw.to_vec());
        let (head, raw_head, leftover) = read_request_head(&mut c).unwrap();
        assert!(raw_head.starts_with(b"POST /v1/chat"));
        assert_eq!(head.method, "POST");
        assert_eq!(head.target, "/v1/chat?k=SECRET"); // raw; sanitized elsewhere
        assert_eq!(head.host.as_deref(), Some("api.openai.com"));
        assert!(head.had_authorization);
        assert_eq!(head.content_length, Some(5));
        assert_eq!(
            head.content_type.as_deref(),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(head.body_framing(), BodyFraming::ContentLength(5));
        assert_eq!(leftover, b"helloEXTRA");
    }

    #[test]
    fn parses_response_head_framing() {
        let raw = b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut c = Cursor::new(raw.to_vec());
        let (head, _raw, _leftover) = read_response_head(&mut c).unwrap();
        assert_eq!(head.status, 429);
        assert!(head.chunked);
        assert_eq!(head.body_framing("GET"), BodyFraming::Chunked);
        // HEAD + 204 + 304 have no body regardless
        assert_eq!(head.body_framing("HEAD"), BodyFraming::None);
    }

    #[test]
    fn oversized_head_is_rejected() {
        let mut big = b"GET / HTTP/1.1\r\n".to_vec();
        while big.len() < MAX_HEAD + 1024 {
            big.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        big.extend_from_slice(b"\r\n");
        let mut c = Cursor::new(big);
        assert!(read_request_head(&mut c).is_err());
    }

    #[test]
    fn connect_authority_parsing() {
        assert_eq!(
            parse_authority("api.openai.com:443"),
            Some(("api.openai.com".into(), 443))
        );
        assert_eq!(parse_authority("[::1]:8443"), Some(("[::1]".into(), 8443)));
        assert_eq!(parse_authority("nope"), None);
    }

    #[test]
    fn absolute_form_parsing() {
        assert_eq!(
            split_absolute_form("http://example.com/v1/x?y=z"),
            Some(("example.com".into(), 80, "/v1/x?y=z".into()))
        );
        assert_eq!(
            split_absolute_form("http://example.com:8080/a"),
            Some(("example.com".into(), 8080, "/a".into()))
        );
    }

    #[test]
    fn no_response_bytes_errors() {
        let mut c = Cursor::new(Vec::new());
        assert!(read_response_head(&mut c).is_err());
    }

    /// A reader that yields scripted chunks; an empty chunk (and everything past
    /// the script) is a would-block, i.e. an idle read timeout.
    struct SlowReader {
        chunks: Vec<Vec<u8>>,
        idx: usize,
    }
    impl Read for SlowReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.idx >= self.chunks.len() {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            let c = self.chunks[self.idx].clone();
            self.idx += 1;
            if c.is_empty() {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            let n = c.len().min(buf.len());
            buf[..n].copy_from_slice(&c[..n]);
            Ok(n)
        }
    }

    #[test]
    fn deadline_read_tolerates_would_block_then_completes() {
        // Partial head, an idle read (would-block), then the terminator.
        let mut r = SlowReader {
            chunks: vec![
                b"GET /p?x=1 HTTP/1.1\r\nHost: h\r\n".to_vec(),
                Vec::new(), // would-block: must NOT be fatal with a live deadline
                b"\r\n".to_vec(),
            ],
            idx: 0,
        };
        let (head, _raw, leftover) =
            read_request_head_deadline(&mut r, Instant::now() + std::time::Duration::from_secs(5))
                .expect("head should complete before the deadline");
        assert_eq!(head.target, "/p?x=1");
        assert_eq!(head.host.as_deref(), Some("h"));
        assert!(leftover.is_empty());
    }

    #[test]
    fn deadline_read_fails_when_head_never_completes() {
        // A Slowloris: a partial head then idle forever. The absolute deadline
        // must fire rather than holding the connection indefinitely.
        let mut r = SlowReader {
            chunks: vec![b"GET / HTTP/1.1\r\n".to_vec()],
            idx: 0,
        };
        let start = Instant::now();
        let res = read_request_head_deadline(&mut r, start + std::time::Duration::from_millis(50));
        assert!(res.is_err(), "expected a deadline error");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "deadline should fire promptly"
        );
    }
}
