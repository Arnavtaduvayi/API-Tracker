//! Bounds and pre-authentication behaviour over real sockets (MESH-SI-2,
//! MESH-SI-8). Everything binds 127.0.0.1:0.

mod common;

use api_tracker_core::mesh::clock::SystemClock;
use api_tracker_mesh::wire::{self, Preamble, MAX_HANDSHAKE_MSG};
use api_tracker_mesh::{handshake, noise, TransportLimits};
use common::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Everything the server sends until it closes (or `limit` passes).
fn drain(s: &mut TcpStream, limit: Duration) -> (Vec<u8>, Duration) {
    s.set_read_timeout(Some(limit)).unwrap();
    let started = Instant::now();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    (out, started.elapsed())
}

fn short(limits: TransportLimits) -> TransportLimits {
    TransportLimits {
        handshake_timeout: Duration::from_millis(300),
        idle_timeout: Duration::from_millis(300),
        ..limits
    }
}

#[test]
fn the_documented_bounds_are_the_defaults() {
    let l = TransportLimits::default();
    assert_eq!(l.handshake_timeout, Duration::from_secs(5));
    assert_eq!(l.idle_timeout, Duration::from_secs(30));
    assert_eq!(l.max_session, Duration::from_secs(600));
    assert_eq!(l.max_sessions, 8);
    assert_eq!(l.handshakes_per_ip_per_minute, 10);
    assert_eq!(wire::MAX_FRAME, 1 << 20);
    assert_eq!(MAX_HANDSHAKE_MSG, 1024);
}

#[test]
fn garbage_before_the_handshake_gets_nothing_back() {
    let a = genesis("dev-a");
    let server = start(&a);
    let mut s = TcpStream::connect(server.addr).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let (got, _) = drain(&mut s, Duration::from_secs(5));
    assert!(got.is_empty(), "the server answered {} bytes", got.len());
}

#[test]
fn a_malformed_handshake_message_gets_nothing_back() {
    let a = genesis("dev-a");
    let server = start(&a);
    let mut s = TcpStream::connect(server.addr).unwrap();
    wire::write_preamble(&mut s, Preamble::Session).unwrap();
    wire::write_msg(&mut s, &[0x41; 48]).unwrap();
    let (got, _) = drain(&mut s, Duration::from_secs(5));
    assert!(got.is_empty());
    // An oversize handshake message is refused before it is read.
    let mut s = TcpStream::connect(server.addr).unwrap();
    wire::write_preamble(&mut s, Preamble::Session).unwrap();
    let _ = s.write_all(&[0xff, 0xff]);
    let (got, _) = drain(&mut s, Duration::from_secs(5));
    assert!(got.is_empty());
}

#[test]
fn a_wrong_access_key_fails_at_message_one_and_reveals_no_static_key() {
    let a = genesis("dev-a");
    let server = start(&a);
    let noise_pub = server.node.keys().noise_pub();
    let mesh = *server.node.mesh_id().as_bytes();
    let mut secret = [7u8; 32];
    secret[0] &= 248;
    let mut hs = noise::session(&mesh, &[0x13; 32], &secret, true).unwrap();
    let mut buf = [0u8; MAX_HANDSHAKE_MSG];
    let n = hs.write_message(&[], &mut buf).unwrap();
    let mut s = TcpStream::connect(server.addr).unwrap();
    wire::write_preamble(&mut s, Preamble::Session).unwrap();
    wire::write_msg(&mut s, &buf[..n]).unwrap();
    let (got, _) = drain(&mut s, Duration::from_secs(5));
    assert!(got.is_empty(), "the responder sent {} bytes", got.len());
    assert!(!got.windows(32).any(|w| w == noise_pub.0));
    // The right key does get message 2 (so the test above means something).
    let key = server.node.access_keys().unwrap().current.1;
    let mut hs = noise::session(&mesh, key.expose(), &secret, true).unwrap();
    let n = hs.write_message(&[], &mut buf).unwrap();
    let mut s = TcpStream::connect(server.addr).unwrap();
    wire::write_preamble(&mut s, Preamble::Session).unwrap();
    wire::write_msg(&mut s, &buf[..n]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let m2 = wire::read_msg(&mut s, MAX_HANDSHAKE_MSG).unwrap();
    assert!(!m2.is_empty());
    // Its static key travels encrypted, never in the clear.
    assert!(!m2.windows(32).any(|w| w == noise_pub.0));
}

#[test]
fn a_slowloris_handshake_is_closed_at_the_handshake_timeout() {
    let a = genesis("dev-a");
    let server = serve_with(&a, Arc::new(SystemClock), short(test_limits()));
    let mut s = TcpStream::connect(server.addr).unwrap();
    s.write_all(b"TMSH").unwrap(); // part of a preamble, then nothing
    let (got, took) = drain(&mut s, Duration::from_secs(5));
    assert!(got.is_empty());
    assert!(took < Duration::from_secs(3), "closed after {took:?}");
}

#[test]
fn an_idle_session_is_closed() {
    let (_a, _sa, b) = pair_of();
    // A server with a short idle timeout on B's side.
    let sb = serve_with(&b, Arc::new(SystemClock), short(test_limits()));
    let na = node(&_a);
    let mut s = TcpStream::connect(sb.addr).unwrap();
    let key = na.access_keys().unwrap().current.1;
    let (state, _peer) = handshake::initiate(&mut s, &na, &key).unwrap();
    let (mut reader, _writer) = wire::split(s, state).unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let started = Instant::now();
    // The server sends its Hello and Direct, then gives up on us.
    while reader.recv().is_ok() {}
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn an_oversize_frame_closes_the_session() {
    let (a, server, b) = pair_of();
    let nb = node(&b);
    let mut s = TcpStream::connect(server.addr).unwrap();
    let key = nb.access_keys().unwrap().current.1;
    let (state, _) = handshake::initiate(&mut s, &nb, &key).unwrap();
    // A frame header announcing 2 MiB, encrypted correctly.
    let mut out = vec![0u8; 128];
    let n = state
        .write_message(0, &(2u32 << 20).to_be_bytes(), &mut out)
        .unwrap();
    wire::write_msg(&mut s, &out[..n]).unwrap();
    let b_id = nb.self_id();
    wait_until(
        || {
            a.vault
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM mesh_exchange_log
                     WHERE peer_device = ?1 AND result = 'aborted' AND error = 'a malformed frame'",
                    [b_id.to_hex()],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
                == 1
        },
        "the oversize frame to end the exchange",
    );
}

#[test]
fn more_than_the_session_limit_are_refused() {
    let a = genesis("dev-a");
    let limits = TransportLimits {
        handshake_timeout: Duration::from_secs(3),
        ..test_limits()
    };
    let server = serve_with(&a, Arc::new(SystemClock), limits);
    let held: Vec<TcpStream> = (0..8)
        .map(|_| TcpStream::connect(server.addr).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    let mut ninth = TcpStream::connect(server.addr).unwrap();
    let (got, took) = drain(&mut ninth, Duration::from_secs(2));
    assert!(got.is_empty());
    assert!(
        took < Duration::from_secs(1),
        "refused at once, not after {took:?}"
    );
    drop(held);
    let stats = server.stop();
    assert!(stats.refused_busy.load(Ordering::Relaxed) >= 1);
}

#[test]
fn a_handshake_flood_from_one_address_is_rate_limited() {
    let a = genesis("dev-a");
    let limits = TransportLimits {
        handshakes_per_ip_per_minute: 3,
        handshake_timeout: Duration::from_millis(500),
        ..TransportLimits::default()
    };
    let server = serve_with(&a, Arc::new(SystemClock), limits);
    let conns: Vec<TcpStream> = (0..6)
        .map(|_| TcpStream::connect(server.addr).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    drop(conns);
    let stats = server.stop();
    assert_eq!(stats.accepted.load(Ordering::Relaxed), 3);
    assert_eq!(stats.refused_rate.load(Ordering::Relaxed), 3);
}
