//! Streaming, backpressured body relay.
//!
//! Bodies are copied from source to destination over a fixed 16 KiB buffer.
//! Because the copy is blocking, a slow reader naturally throttles a fast
//! writer — that IS the backpressure, and there is nowhere for a whole body to
//! accumulate. We never look at body bytes; for chunked bodies we parse only
//! the chunk *framing* (sizes) so we know where the message ends, and echo
//! every byte through verbatim.
//!
//! Each relay returns `(bytes_relayed, carryover)` where `carryover` is any
//! bytes read past the end of this message (the start of the next one on a
//! kept-alive connection), so no data is lost between messages.

use crate::wire::BodyFraming;
use api_tracker_core::error::{CoreError, Result};
use std::io::{Read, Write};

const BUF: usize = 16 * 1024;
const MAX_CHUNK_HEADER: usize = 1024;

/// A source that yields `initial` bytes first, then reads from `src`, keeping a
/// small internal buffer. Its unread tail is the carryover.
struct Source<'a, R: Read> {
    buf: Vec<u8>,
    pos: usize,
    src: &'a mut R,
}

impl<'a, R: Read> Source<'a, R> {
    fn new(initial: Vec<u8>, src: &'a mut R) -> Self {
        Self {
            buf: initial,
            pos: 0,
            src,
        }
    }

    /// Ensure the internal buffer has unread bytes; returns false at EOF.
    fn ensure(&mut self) -> Result<bool> {
        if self.pos < self.buf.len() {
            return Ok(true);
        }
        let mut tmp = [0u8; BUF];
        let n = self.src.read(&mut tmp).map_err(CoreError::Io)?;
        if n == 0 {
            return Ok(false);
        }
        self.buf = tmp[..n].to_vec();
        self.pos = 0;
        Ok(true)
    }

    fn byte(&mut self) -> Result<Option<u8>> {
        if !self.ensure()? {
            return Ok(None);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(b))
    }

    fn carryover(self) -> Vec<u8> {
        self.buf[self.pos..].to_vec()
    }
}

/// Relay a body per `framing`, writing `initial` (leftover already read past the
/// head) first.
pub fn relay_body<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    framing: BodyFraming,
    initial: Vec<u8>,
) -> Result<(u64, Vec<u8>)> {
    match framing {
        BodyFraming::None => {
            // No body: `initial` belongs to the NEXT message. Carry it over.
            Ok((0, initial))
        }
        BodyFraming::ContentLength(n) => relay_content_length(src, dst, n, initial),
        BodyFraming::Chunked => relay_chunked(src, dst, initial),
        BodyFraming::UntilClose => relay_until_close(src, dst, initial),
    }
}

fn relay_content_length<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    n: u64,
    initial: Vec<u8>,
) -> Result<(u64, Vec<u8>)> {
    let mut remaining = n;
    let from_initial = std::cmp::min(initial.len() as u64, remaining) as usize;
    if from_initial > 0 {
        dst.write_all(&initial[..from_initial])
            .map_err(CoreError::Io)?;
    }
    remaining -= from_initial as u64;
    let carryover = initial[from_initial..].to_vec();

    let mut buf = [0u8; BUF];
    while remaining > 0 {
        let want = std::cmp::min(BUF as u64, remaining) as usize;
        let read = src.read(&mut buf[..want]).map_err(CoreError::Io)?;
        if read == 0 {
            break; // upstream closed early; relay what we have
        }
        dst.write_all(&buf[..read]).map_err(CoreError::Io)?;
        remaining -= read as u64;
    }
    dst.flush().ok();
    Ok((n - remaining, carryover))
}

fn relay_until_close<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    initial: Vec<u8>,
) -> Result<(u64, Vec<u8>)> {
    let mut total = initial.len() as u64;
    if !initial.is_empty() {
        dst.write_all(&initial).map_err(CoreError::Io)?;
    }
    let mut buf = [0u8; BUF];
    loop {
        let read = src.read(&mut buf).map_err(CoreError::Io)?;
        if read == 0 {
            break;
        }
        dst.write_all(&buf[..read]).map_err(CoreError::Io)?;
        total += read as u64;
    }
    dst.flush().ok();
    Ok((total, Vec::new()))
}

/// Relay a chunked body, echoing all bytes verbatim while parsing only the
/// chunk framing to find the terminal 0-length chunk.
fn relay_chunked<R: Read, W: Write>(
    src: &mut R,
    dst: &mut W,
    initial: Vec<u8>,
) -> Result<(u64, Vec<u8>)> {
    let mut s = Source::new(initial, src);
    let mut relayed: u64 = 0;
    loop {
        // chunk-size line
        let line = read_line_echo(&mut s, dst, &mut relayed)?;
        let size = parse_chunk_size(&line)?;
        if size == 0 {
            // trailer headers until an empty line
            loop {
                let trailer = read_line_echo(&mut s, dst, &mut relayed)?;
                if trailer == b"\r\n" || trailer == b"\n" {
                    break;
                }
            }
            break;
        }
        // chunk data + trailing CRLF
        copy_n_echo(&mut s, dst, size, &mut relayed)?;
        let crlf = read_line_echo(&mut s, dst, &mut relayed)?;
        if crlf != b"\r\n" && crlf != b"\n" {
            return Err(CoreError::InvalidInput("malformed chunk terminator".into()));
        }
    }
    dst.flush().ok();
    Ok((relayed, s.carryover()))
}

fn read_line_echo<R: Read, W: Write>(
    s: &mut Source<'_, R>,
    dst: &mut W,
    relayed: &mut u64,
) -> Result<Vec<u8>> {
    let mut line = Vec::with_capacity(16);
    loop {
        let b = s
            .byte()?
            .ok_or_else(|| CoreError::InvalidInput("eof in chunk framing".into()))?;
        dst.write_all(&[b]).map_err(CoreError::Io)?;
        *relayed += 1;
        line.push(b);
        if line.ends_with(b"\n") {
            return Ok(line);
        }
        if line.len() > MAX_CHUNK_HEADER {
            return Err(CoreError::InvalidInput("chunk header too long".into()));
        }
    }
}

fn copy_n_echo<R: Read, W: Write>(
    s: &mut Source<'_, R>,
    dst: &mut W,
    mut n: usize,
    relayed: &mut u64,
) -> Result<()> {
    while n > 0 {
        if s.pos >= s.buf.len() && !s.ensure()? {
            return Err(CoreError::InvalidInput("eof mid chunk".into()));
        }
        let avail = &s.buf[s.pos..];
        let take = std::cmp::min(avail.len(), n);
        dst.write_all(&avail[..take]).map_err(CoreError::Io)?;
        s.pos += take;
        n -= take;
        *relayed += take as u64;
    }
    Ok(())
}

fn parse_chunk_size(line: &[u8]) -> Result<usize> {
    // strip CRLF and any ";ext" then parse hex
    let s = std::str::from_utf8(line)
        .map_err(|_| CoreError::InvalidInput("non-utf8 chunk size".into()))?;
    let s = s.trim_end_matches(['\r', '\n']);
    let hex = s.split(';').next().unwrap_or("").trim();
    usize::from_str_radix(hex, 16).map_err(|_| CoreError::InvalidInput("bad chunk size".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn content_length_relay_exact_with_carryover() {
        // body is 5 bytes; the reader also holds the next request.
        let mut src = Cursor::new(b"world NEXTREQ".to_vec());
        let mut dst = Vec::new();
        let (n, carry) = relay_body(
            &mut src,
            &mut dst,
            BodyFraming::ContentLength(5),
            b"hello".to_vec(),
        )
        .unwrap();
        // initial already had the whole 5-byte body
        assert_eq!(n, 5);
        assert_eq!(dst, b"hello");
        assert_eq!(carry, b""); // nothing past body in initial
    }

    #[test]
    fn content_length_streams_from_source() {
        let mut src = Cursor::new(b"0123456789".to_vec());
        let mut dst = Vec::new();
        let (n, _c) = relay_body(
            &mut src,
            &mut dst,
            BodyFraming::ContentLength(10),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(n, 10);
        assert_eq!(dst, b"0123456789");
    }

    #[test]
    fn chunked_relay_echoes_verbatim_and_stops_at_terminal() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\nAFTER".to_vec();
        let mut src = Cursor::new(body);
        let mut dst = Vec::new();
        let (n, carry) = relay_body(&mut src, &mut dst, BodyFraming::Chunked, Vec::new()).unwrap();
        assert_eq!(dst, b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        assert_eq!(
            carry, b"AFTER",
            "bytes after the terminal chunk are carryover"
        );
        assert!(n > 0);
    }

    #[test]
    fn chunked_with_initial_leftover() {
        // the head-read already grabbed the first chunk
        let mut src = Cursor::new(b" world\r\n0\r\n\r\n".to_vec());
        let mut dst = Vec::new();
        let (_n, carry) = relay_body(
            &mut src,
            &mut dst,
            BodyFraming::Chunked,
            b"5\r\nhello\r\n6\r\n".to_vec(),
        )
        .unwrap();
        assert_eq!(dst, b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        assert_eq!(carry, b"");
    }

    #[test]
    fn until_close_reads_to_eof() {
        let mut src = Cursor::new(b"streamed response body".to_vec());
        let mut dst = Vec::new();
        let (n, carry) = relay_body(
            &mut src,
            &mut dst,
            BodyFraming::UntilClose,
            b"prefix ".to_vec(),
        )
        .unwrap();
        assert_eq!(dst, b"prefix streamed response body");
        assert_eq!(n, dst.len() as u64);
        assert!(carry.is_empty());
    }

    #[test]
    fn none_framing_carries_leftover_as_next_message() {
        let mut src = Cursor::new(Vec::new());
        let mut dst = Vec::new();
        let (n, carry) = relay_body(
            &mut src,
            &mut dst,
            BodyFraming::None,
            b"GET /next HTTP/1.1\r\n".to_vec(),
        )
        .unwrap();
        assert_eq!(n, 0);
        assert!(dst.is_empty());
        assert_eq!(carry, b"GET /next HTTP/1.1\r\n");
    }
}
