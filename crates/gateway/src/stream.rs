//! Strict chunked-body relay.
//!
//! `observe::relay` accepts a bare `\n` as a chunk-line terminator and echoes
//! it verbatim. For the observation proxy — which relays between a client and
//! the origin that client chose — that is harmless. For a GATEWAY it is not:
//! a client and an upstream that disagree about where a chunked body ends is
//! the classic LF-chunk smuggling primitive, and SI-15 requires the gateway
//! to REJECT malformed framing rather than forward it.
//!
//! This relay therefore requires strict CRLF, bounds the chunk-size line,
//! rejects chunk extensions it cannot vouch for, and — the second reason it
//! exists — feeds the usage tap the DECODED chunk data rather than the raw
//! framing bytes, so a chunked SSE stream extracts exactly like an
//! unchunked one.

use std::io::{Read, Write};

use api_tracker_core::error::{CoreError, Result};

use crate::forward::BodyTap;

/// Copy buffer, matching `observe::relay`'s fixed 16 KiB.
const BUF: usize = 16 * 1024;
/// Max bytes in a chunk-size line (including any extension).
pub const MAX_CHUNK_LINE: usize = 1024;
/// Max trailer section size after the terminal chunk.
pub const MAX_TRAILER: usize = 8 * 1024;

/// A bounded reader over `src` seeded with `initial`, tracking bytes not yet
/// consumed so they can be handed back as carryover.
struct Source<'a, R: Read> {
    src: &'a mut R,
    buf: Vec<u8>,
    pos: usize,
}

impl<'a, R: Read> Source<'a, R> {
    fn new(src: &'a mut R, initial: Vec<u8>) -> Self {
        Self {
            src,
            buf: initial,
            pos: 0,
        }
    }

    fn fill(&mut self) -> Result<bool> {
        let mut tmp = [0u8; BUF];
        let n = self.src.read(&mut tmp).map_err(CoreError::Io)?;
        if n == 0 {
            return Ok(false);
        }
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(true)
    }

    fn peek(&mut self) -> Result<Option<u8>> {
        while self.pos >= self.buf.len() {
            if !self.fill()? {
                return Ok(None);
            }
        }
        Ok(Some(self.buf[self.pos]))
    }

    fn next_byte(&mut self) -> Result<Option<u8>> {
        let b = self.peek()?;
        if b.is_some() {
            self.pos += 1;
        }
        Ok(b)
    }

    /// Take up to `want` buffered-or-read bytes.
    fn take(&mut self, want: usize) -> Result<Vec<u8>> {
        while self.pos >= self.buf.len() {
            if !self.fill()? {
                return Ok(Vec::new());
            }
        }
        let end = std::cmp::min(self.buf.len(), self.pos + want);
        let out = self.buf[self.pos..end].to_vec();
        self.pos = end;
        Ok(out)
    }

    fn carryover(self) -> Vec<u8> {
        self.buf[self.pos..].to_vec()
    }
}

/// Read one line terminated by a STRICT CRLF, echoing it verbatim to `dst`.
/// A bare LF or a bare CR is a hard error (SI-15).
fn read_line_strict<R: Read, W: Write>(
    src: &mut Source<'_, R>,
    dst: &mut W,
    max: usize,
    counted: &mut u64,
) -> Result<Vec<u8>> {
    let mut line = Vec::with_capacity(32);
    loop {
        let Some(b) = src.next_byte()? else {
            return Err(CoreError::InvalidInput("eof in chunk framing".into()));
        };
        *counted += 1;
        if b == b'\r' {
            let Some(next) = src.next_byte()? else {
                return Err(CoreError::InvalidInput(
                    "eof after CR in chunk framing".into(),
                ));
            };
            *counted += 1;
            if next != b'\n' {
                return Err(CoreError::InvalidInput(
                    "bare CR in chunk framing (strict CRLF required)".into(),
                ));
            }
            dst.write_all(&line).map_err(CoreError::Io)?;
            dst.write_all(b"\r\n").map_err(CoreError::Io)?;
            return Ok(line);
        }
        if b == b'\n' {
            // httparse and some relays tolerate this; a gateway must not.
            return Err(CoreError::InvalidInput(
                "bare LF in chunk framing (strict CRLF required)".into(),
            ));
        }
        if line.len() >= max {
            return Err(CoreError::InvalidInput("chunk line too long".into()));
        }
        line.push(b);
    }
}

/// Parse a chunk-size line: `1*HEXDIG [ chunk-ext ]`.
///
/// Chunk extensions are rejected rather than forwarded: they are unused by
/// every provider API, and a parser that disagrees about where an extension
/// ends is another framing-desync primitive.
fn parse_chunk_size(line: &[u8]) -> Result<u64> {
    if line.is_empty() || line.len() > 16 {
        return Err(CoreError::InvalidInput("malformed chunk size".into()));
    }
    let text = std::str::from_utf8(line)
        .map_err(|_| CoreError::InvalidInput("non-utf8 chunk size".into()))?;
    if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CoreError::InvalidInput(
            "chunk size must be plain hex with no extension".into(),
        ));
    }
    u64::from_str_radix(text, 16).map_err(|_| CoreError::InvalidInput("bad chunk size".into()))
}

/// Relay a chunked body with strict framing, echoing every byte verbatim to
/// `dst` while feeding only the DECODED chunk data to `tap`.
///
/// Returns `(bytes_relayed_including_framing, carryover)`.
pub fn relay_chunked_strict<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    initial: Vec<u8>,
    mut tap: Option<&mut dyn BodyTap>,
) -> Result<(u64, Vec<u8>)> {
    let mut source = Source::new(src, initial);
    let mut relayed = 0u64;
    loop {
        let line = read_line_strict(&mut source, dst, MAX_CHUNK_LINE, &mut relayed)?;
        let size = parse_chunk_size(&line)?;
        if size == 0 {
            // Terminal chunk: relay the (possibly empty) trailer section,
            // still requiring strict CRLF, then the final blank line.
            let mut trailer_bytes = 0usize;
            loop {
                let trailer = read_line_strict(&mut source, dst, MAX_CHUNK_LINE, &mut relayed)?;
                if trailer.is_empty() {
                    break;
                }
                trailer_bytes += trailer.len();
                if trailer_bytes > MAX_TRAILER {
                    return Err(CoreError::InvalidInput("chunk trailer too large".into()));
                }
            }
            dst.flush().ok();
            return Ok((relayed, source.carryover()));
        }
        // Chunk data, streamed in bounded pieces.
        let mut remaining = size;
        while remaining > 0 {
            let want = std::cmp::min(BUF as u64, remaining) as usize;
            let piece = source.take(want)?;
            if piece.is_empty() {
                return Err(CoreError::InvalidInput("eof mid chunk".into()));
            }
            dst.write_all(&piece).map_err(CoreError::Io)?;
            if let Some(t) = tap.as_deref_mut() {
                t.feed(&piece);
            }
            remaining -= piece.len() as u64;
            relayed += piece.len() as u64;
        }
        // The CRLF that terminates the chunk data.
        let after = read_line_strict(&mut source, dst, 1, &mut relayed)?;
        if !after.is_empty() {
            return Err(CoreError::InvalidInput("malformed chunk terminator".into()));
        }
    }
}

/// Relay a Content-Length or until-close body, feeding the tap the same
/// bytes (there is no framing to strip). Returns `(bytes, carryover)`.
///
/// Truncation is REPORTED, not hidden: an early EOF returns the bytes
/// actually relayed, and the caller compares against the declared length.
pub fn relay_plain<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    limit: Option<u64>,
    initial: Vec<u8>,
    mut tap: Option<&mut dyn BodyTap>,
) -> Result<(u64, Vec<u8>)> {
    let mut relayed = 0u64;
    let mut carryover = Vec::new();
    if !initial.is_empty() {
        let take = match limit {
            Some(n) => std::cmp::min(initial.len() as u64, n) as usize,
            None => initial.len(),
        };
        dst.write_all(&initial[..take]).map_err(CoreError::Io)?;
        if let Some(t) = tap.as_deref_mut() {
            t.feed(&initial[..take]);
        }
        relayed += take as u64;
        carryover = initial[take..].to_vec();
    }
    let mut buf = [0u8; BUF];
    loop {
        if let Some(n) = limit {
            if relayed >= n {
                break;
            }
        }
        let want = match limit {
            Some(n) => std::cmp::min(BUF as u64, n - relayed) as usize,
            None => BUF,
        };
        let read = src.read(&mut buf[..want]).map_err(CoreError::Io)?;
        if read == 0 {
            break; // EOF: the caller decides whether this is truncation
        }
        dst.write_all(&buf[..read]).map_err(CoreError::Io)?;
        if let Some(t) = tap.as_deref_mut() {
            t.feed(&buf[..read]);
        }
        relayed += read as u64;
    }
    dst.flush().ok();
    Ok((relayed, carryover))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct CollectTap(Vec<u8>);
    impl BodyTap for CollectTap {
        fn feed(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    fn relay(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let mut src = Cursor::new(input.to_vec());
        let mut dst = Vec::new();
        let mut tap = CollectTap(Vec::new());
        let (_, carry) = relay_chunked_strict(&mut src, &mut dst, Vec::new(), Some(&mut tap))?;
        Ok((dst, tap.0, carry))
    }

    #[test]
    fn well_formed_chunked_bodies_relay_verbatim_and_decode_for_the_tap() {
        let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (out, decoded, carry) = relay(input).unwrap();
        assert_eq!(out, input, "framing must be echoed byte-for-byte");
        assert_eq!(decoded, b"hello world", "the tap sees DECODED data only");
        assert!(carry.is_empty());
    }

    #[test]
    fn trailers_relay_and_are_bounded() {
        let input = b"3\r\nabc\r\n0\r\nX-Trailer: t\r\n\r\n";
        let (out, decoded, _) = relay(input).unwrap();
        assert_eq!(out, input);
        assert_eq!(decoded, b"abc");

        let mut huge = b"0\r\n".to_vec();
        for i in 0..600 {
            huge.extend_from_slice(format!("X-T{i}: {}\r\n", "v".repeat(20)).as_bytes());
        }
        huge.extend_from_slice(b"\r\n");
        assert!(
            relay(&huge).is_err(),
            "an oversized trailer must be refused"
        );
    }

    #[test]
    fn bare_lf_framing_is_rejected_not_forwarded() {
        // The LF-chunk smuggling primitive: REJECTED (SI-15), which is the
        // behavior `observe::relay` deliberately does not implement.
        for bad in [
            &b"5\nhello\n0\n\n"[..],
            b"5\r\nhello\n0\r\n\r\n",
            b"5\r\nhello\r\n0\n\r\n",
            b"5\rhello\r\n0\r\n\r\n",
        ] {
            let err = relay(bad).unwrap_err();
            assert!(
                format!("{err}").contains("chunk framing") || format!("{err}").contains("chunk"),
                "must reject bare-LF/CR framing, got: {err}"
            );
        }
    }

    #[test]
    fn chunk_extensions_and_malformed_sizes_are_rejected() {
        for bad in [
            &b"5;ext=1\r\nhello\r\n0\r\n\r\n"[..], // extension
            b"0x5\r\nhello\r\n0\r\n\r\n",          // not plain hex
            b"+5\r\nhello\r\n0\r\n\r\n",
            b"\r\nhello\r\n0\r\n\r\n", // empty size
            b"ffffffffffffffffff\r\n", // absurd size line
        ] {
            assert!(
                relay(bad).is_err(),
                "must reject: {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn an_oversized_chunk_size_line_is_bounded() {
        let mut bad = vec![b'a'; MAX_CHUNK_LINE + 100];
        bad.extend_from_slice(b"\r\n");
        assert!(relay(&bad).is_err());
    }

    #[test]
    fn a_mid_chunk_eof_is_an_error_not_a_silent_short_body() {
        let err = relay(b"10\r\nonly-a-few\r\n").unwrap_err();
        assert!(format!("{err}").contains("eof"), "got: {err}");
    }

    #[test]
    fn a_malformed_chunk_terminator_is_rejected() {
        // Data not followed by CRLF.
        assert!(relay(b"5\r\nhelloXX0\r\n\r\n").is_err());
    }

    #[test]
    fn bytes_past_the_terminal_chunk_become_carryover() {
        let input = b"3\r\nabc\r\n0\r\n\r\nGET /next HTTP/1.1\r\n";
        let (_, decoded, carry) = relay(input).unwrap();
        assert_eq!(decoded, b"abc");
        assert_eq!(carry, b"GET /next HTTP/1.1\r\n");
    }

    #[test]
    fn plain_relay_reports_truncation_and_carries_over_extra() {
        let mut src = Cursor::new(b"hello".to_vec());
        let mut dst = Vec::new();
        let (n, _) = relay_plain(&mut src, &mut dst, Some(100), Vec::new(), None).unwrap();
        assert_eq!(n, 5, "an early EOF reports the bytes actually relayed");
        assert_eq!(dst, b"hello");

        let mut src = Cursor::new(Vec::new());
        let mut dst = Vec::new();
        let (n, carry) =
            relay_plain(&mut src, &mut dst, Some(3), b"abcEXTRA".to_vec(), None).unwrap();
        assert_eq!(n, 3);
        assert_eq!(dst, b"abc");
        assert_eq!(carry, b"EXTRA");
    }

    #[test]
    fn plain_relay_feeds_the_tap_every_relayed_byte() {
        let mut src = Cursor::new(b"world".to_vec());
        let mut dst = Vec::new();
        let mut tap = CollectTap(Vec::new());
        let (n, _) =
            relay_plain(&mut src, &mut dst, None, b"hello ".to_vec(), Some(&mut tap)).unwrap();
        assert_eq!(n, 11);
        assert_eq!(tap.0, b"hello world");
        assert_eq!(dst, b"hello world");
    }
}
