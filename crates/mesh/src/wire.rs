//! Bytes on the wire (PROTOCOL.md §9 "Transport").
//!
//! 1. **Preamble**, 16 bytes, the only thing read before the handshake starts:
//!    `"TMSH"`, version `1`, kind (`'S'` session or `'P'` pairing), two zero
//!    bytes, then 8 bytes: zero for a session, the invite hint for pairing.
//!    Anything else closes the connection.
//! 2. **Noise messages**: a `u16` big-endian length, then the message. While
//!    the handshake runs, a message over 1 KiB closes the connection
//!    (MESH-SI-2: nothing larger is parsed before authentication).
//! 3. **Frames** after the handshake: a `u32` big-endian length (≤ 1 MiB) and
//!    the frame bytes, split across Noise transport messages of at most
//!    65 535 bytes and reassembled under a hard cap. An oversize or
//!    undecryptable message closes the session.

use snow::StatelessTransportState;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

pub const MAGIC: &[u8; 4] = b"TMSH";
pub const VERSION: u8 = 1;
pub const PREAMBLE_LEN: usize = 16;
pub const MAX_HANDSHAKE_MSG: usize = 1024;
pub const MAX_NOISE_MSG: usize = 65_535;
const TAG_LEN: usize = 16;
const MAX_PLAIN_CHUNK: usize = MAX_NOISE_MSG - TAG_LEN;
/// The largest application frame (`core::mesh::proto` frames are ≤ 1 MiB).
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preamble {
    Session,
    Pair { hint: [u8; 8] },
}

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

pub fn write_preamble(w: &mut impl Write, p: Preamble) -> io::Result<()> {
    let mut b = [0u8; PREAMBLE_LEN];
    b[..4].copy_from_slice(MAGIC);
    b[4] = VERSION;
    match p {
        Preamble::Session => b[5] = b'S',
        Preamble::Pair { hint } => {
            b[5] = b'P';
            b[8..].copy_from_slice(&hint);
        }
    }
    w.write_all(&b)
}

pub fn read_preamble(r: &mut impl Read) -> io::Result<Preamble> {
    let mut b = [0u8; PREAMBLE_LEN];
    r.read_exact(&mut b)?;
    if &b[..4] != MAGIC || b[4] != VERSION || b[6] != 0 || b[7] != 0 {
        return Err(invalid("not a Tethra Mesh connection"));
    }
    let mut hint = [0u8; 8];
    hint.copy_from_slice(&b[8..]);
    match b[5] {
        b'S' if hint == [0; 8] => Ok(Preamble::Session),
        b'P' => Ok(Preamble::Pair { hint }),
        _ => Err(invalid("not a Tethra Mesh connection")),
    }
}

pub fn write_msg(w: &mut impl Write, msg: &[u8]) -> io::Result<()> {
    let len = u16::try_from(msg.len()).map_err(|_| invalid("Noise message too large"))?;
    let mut buf = Vec::with_capacity(2 + msg.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(msg);
    w.write_all(&buf)
}

/// Read one length-prefixed Noise message of at most `max` bytes.
pub fn read_msg(r: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut l = [0u8; 2];
    r.read_exact(&mut l)?;
    let len = usize::from(u16::from_be_bytes(l));
    if len > max {
        return Err(invalid("Noise message over the limit"));
    }
    let mut msg = vec![0u8; len];
    r.read_exact(&mut msg)?;
    Ok(msg)
}

/// The sending half of an established Noise channel.
pub struct FrameWriter {
    stream: TcpStream,
    state: Arc<StatelessTransportState>,
    nonce: u64,
}

/// The receiving half.
pub struct FrameReader {
    stream: TcpStream,
    state: Arc<StatelessTransportState>,
    nonce: u64,
    buf: Vec<u8>,
}

/// Split an established channel into halves that can run on two threads.
pub fn split(
    stream: TcpStream,
    state: StatelessTransportState,
) -> io::Result<(FrameReader, FrameWriter)> {
    let state = Arc::new(state);
    let w = stream.try_clone()?;
    Ok((
        FrameReader {
            stream,
            state: state.clone(),
            nonce: 0,
            buf: Vec::new(),
        },
        FrameWriter {
            stream: w,
            state,
            nonce: 0,
        },
    ))
}

impl FrameWriter {
    pub fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        if frame.len() > MAX_FRAME {
            return Err(invalid("frame over the limit"));
        }
        let mut plain = Vec::with_capacity(4 + frame.len());
        plain.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        plain.extend_from_slice(frame);
        let mut out = vec![0u8; MAX_NOISE_MSG];
        for chunk in plain.chunks(MAX_PLAIN_CHUNK) {
            let n = self
                .state
                .write_message(self.nonce, chunk, &mut out)
                .map_err(|_| invalid("encryption failed"))?;
            self.nonce += 1;
            write_msg(&mut self.stream, &out[..n])?;
        }
        self.stream.flush()
    }

    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Write);
    }
}

impl FrameReader {
    pub fn set_read_timeout(&self, t: Option<std::time::Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(t)
    }

    /// The next complete frame.
    pub fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut plain = vec![0u8; MAX_NOISE_MSG];
        loop {
            if self.buf.len() >= 4 {
                let len = u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes")) as usize;
                if len > MAX_FRAME {
                    return Err(invalid("frame over the limit"));
                }
                if self.buf.len() >= 4 + len {
                    let frame = self.buf[4..4 + len].to_vec();
                    self.buf.drain(..4 + len);
                    return Ok(frame);
                }
            }
            let msg = read_msg(&mut self.stream, MAX_NOISE_MSG)?;
            let n = self
                .state
                .read_message(self.nonce, &msg, &mut plain)
                .map_err(|_| invalid("a message did not decrypt"))?;
            self.nonce += 1;
            if self.buf.len() + n > 4 + MAX_FRAME + MAX_NOISE_MSG {
                return Err(invalid("frame over the limit"));
            }
            self.buf.extend_from_slice(&plain[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preambles_round_trip_and_anything_else_is_refused() {
        for p in [Preamble::Session, Preamble::Pair { hint: [9; 8] }] {
            let mut b = Vec::new();
            write_preamble(&mut b, p).unwrap();
            assert_eq!(b.len(), PREAMBLE_LEN);
            assert_eq!(read_preamble(&mut b.as_slice()).unwrap(), p);
        }
        let mut b = Vec::new();
        write_preamble(&mut b, Preamble::Session).unwrap();
        for i in 0..8 {
            let mut bad = b.clone();
            bad[i] ^= 0x20;
            assert!(read_preamble(&mut bad.as_slice()).is_err(), "byte {i}");
        }
        let mut s_with_hint = b.clone();
        s_with_hint[12] = 1;
        assert!(read_preamble(&mut s_with_hint.as_slice()).is_err());
        assert!(read_preamble(&mut &b"GET / HTTP/1.1\r\n"[..]).is_err());
    }

    #[test]
    fn handshake_messages_over_the_cap_are_refused() {
        let mut b = Vec::new();
        write_msg(&mut b, &[0u8; 2000]).unwrap();
        assert!(read_msg(&mut b.as_slice(), MAX_HANDSHAKE_MSG).is_err());
        let mut b = Vec::new();
        write_msg(&mut b, &[7u8; 100]).unwrap();
        assert_eq!(
            read_msg(&mut b.as_slice(), MAX_HANDSHAKE_MSG).unwrap(),
            vec![7u8; 100]
        );
    }
}
