//! Minimal, allocation-light TLS ClientHello sniffer.
//!
//! The proxy `peek`s (does not consume) the first bytes a client sends after a
//! CONNECT and parses out the SNI hostname and the offered ALPN protocols.
//! That is enough to decide whether to intercept (the client will speak
//! HTTP/1.1) or fall back to an opaque tunnel (an h2-only client we do not
//! decode). Because we only peek, the real rustls handshake re-reads the same
//! bytes.
//!
//! This parser is deliberately defensive: any bounds problem stops parsing and
//! returns whatever was found so far. It never panics and never allocates
//! beyond the extracted strings.

/// What we could learn from a (possibly truncated) ClientHello.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// True if the buffer began with a TLS handshake record.
    pub is_tls_handshake: bool,
    /// The SNI hostname, if present.
    pub sni: Option<String>,
    /// The ALPN protocol identifiers the client offered, in order.
    pub alpn: Vec<Vec<u8>>,
}

impl ClientHelloInfo {
    /// Whether we should intercept (speak HTTP/1.1) rather than opaquely
    /// tunnel. We intercept when the client offered no ALPN (it will accept
    /// whatever we negotiate, defaulting to HTTP/1.1) or explicitly offered
    /// `http/1.1`. An h2-only client is tunnelled.
    pub fn wants_http1(&self) -> bool {
        self.alpn.is_empty() || self.alpn.iter().any(|p| p == b"http/1.1")
    }

    /// True when the client offered ALPN but only HTTP/2 (or other non-1.1)
    /// protocols — the case we tunnel opaquely and flag as partial.
    pub fn is_h2_only(&self) -> bool {
        !self.alpn.is_empty() && !self.alpn.iter().any(|p| p == b"http/1.1")
    }
}

/// A tiny forward-only byte reader that yields `None` on any short read.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<usize> {
        let hi = self.u8()? as usize;
        let lo = self.u8()? as usize;
        Some((hi << 8) | lo)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
}

/// Parse a peeked buffer. Never panics.
pub fn parse(buf: &[u8]) -> ClientHelloInfo {
    let mut info = ClientHelloInfo::default();
    // TLS record header: content_type(1) legacy_version(2) length(2).
    let mut r = Reader::new(buf);
    match r.u8() {
        Some(0x16) => info.is_tls_handshake = true, // handshake
        _ => return info,
    }
    if r.skip(2).is_none() {
        return info;
    }
    let Some(rec_len) = r.u16() else { return info };
    // Restrict parsing to this record (clamped to what we actually peeked).
    let Some(record) = r.take(rec_len.min(r.remaining())) else {
        return info;
    };
    let _ = parse_handshake(record, &mut info);
    info
}

fn parse_handshake(record: &[u8], info: &mut ClientHelloInfo) -> Option<()> {
    let mut r = Reader::new(record);
    // handshake_type(1) must be client_hello(1); length(3) is skipped.
    if r.u8()? != 0x01 {
        return None;
    }
    r.skip(3)?;
    // client_version(2) + random(32)
    r.skip(2 + 32)?;
    // session_id
    let sid = r.u8()? as usize;
    r.skip(sid)?;
    // cipher_suites
    let cs = r.u16()?;
    r.skip(cs)?;
    // compression_methods
    let comp = r.u8()? as usize;
    r.skip(comp)?;
    // extensions (may be absent on very old hellos)
    let ext_total = match r.u16() {
        Some(n) => n,
        None => return Some(()),
    };
    let ext_bytes = r.take(ext_total.min(r.remaining()))?;
    parse_extensions(ext_bytes, info);
    Some(())
}

fn parse_extensions(ext_bytes: &[u8], info: &mut ClientHelloInfo) {
    let mut e = Reader::new(ext_bytes);
    while e.remaining() >= 4 {
        let Some(ext_type) = e.u16() else { break };
        let Some(ext_len) = e.u16() else { break };
        let Some(data) = e.take(ext_len) else { break };
        match ext_type {
            0x0000 => {
                if let Some(name) = parse_sni(data) {
                    info.sni = Some(name);
                }
            }
            0x0010 => {
                info.alpn = parse_alpn(data);
            }
            _ => {}
        }
    }
}

fn parse_sni(data: &[u8]) -> Option<String> {
    let mut r = Reader::new(data);
    let _list_len = r.u16()?;
    // one or more entries: name_type(1) + name_len(2) + name
    while r.remaining() >= 3 {
        let name_type = r.u8()?;
        let name_len = r.u16()?;
        let name = r.take(name_len)?;
        if name_type == 0x00 {
            // host_name; must be valid UTF-8/ASCII
            if let Ok(s) = std::str::from_utf8(name) {
                return Some(s.to_ascii_lowercase());
            }
        }
    }
    None
}

fn parse_alpn(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    if r.u16().is_none() {
        return out; // no protocol_name_list length
    }
    while r.remaining() >= 1 {
        let Some(len) = r.u8() else { break };
        let Some(name) = r.take(len as usize) else {
            break;
        };
        if !name.is_empty() {
            out.push(name.to_vec());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConfig, ClientConnection, RootCertStore};
    use std::sync::Arc;

    /// Produce a real ClientHello using rustls, so the parser is tested against
    /// exactly the bytes it will see in production.
    fn real_client_hello(server: &str, alpn: &[&[u8]]) -> Vec<u8> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let name = server.to_string().try_into().unwrap();
        let mut conn = ClientConnection::new(Arc::new(config), name).unwrap();
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).unwrap();
        buf
    }

    #[test]
    fn extracts_sni_and_alpn_from_a_real_hello() {
        let hello = real_client_hello("api.openai.com", &[b"h2", b"http/1.1"]);
        let info = parse(&hello);
        assert!(info.is_tls_handshake);
        assert_eq!(info.sni.as_deref(), Some("api.openai.com"));
        assert_eq!(info.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert!(info.wants_http1());
        assert!(!info.is_h2_only());
    }

    #[test]
    fn detects_h2_only_client() {
        let hello = real_client_hello("grpc.example.com", &[b"h2"]);
        let info = parse(&hello);
        assert_eq!(info.sni.as_deref(), Some("grpc.example.com"));
        assert!(info.is_h2_only());
        assert!(!info.wants_http1());
    }

    #[test]
    fn no_alpn_means_intercept() {
        let hello = real_client_hello("api.stripe.com", &[]);
        let info = parse(&hello);
        assert_eq!(info.sni.as_deref(), Some("api.stripe.com"));
        assert!(info.alpn.is_empty());
        assert!(info.wants_http1());
    }

    #[test]
    fn non_tls_input_is_rejected_without_panic() {
        assert!(!parse(b"GET / HTTP/1.1\r\n").is_tls_handshake);
        assert!(!parse(&[]).is_tls_handshake);
        assert!(!parse(&[0x16, 0x03]).sni.is_some()); // truncated, no panic
    }

    #[test]
    fn truncated_hello_does_not_panic() {
        let hello = real_client_hello("api.openai.com", &[b"http/1.1"]);
        for cut in 0..hello.len() {
            let _ = parse(&hello[..cut]); // must never panic
        }
    }
}
