//! Shared harness for gateway integration tests.
//!
//! Every "provider" here is a local synthetic listener. No test makes a live
//! provider call or uses a real credential; the only key-shaped strings are
//! unmistakably fake (`FAKE-TEST-...`).

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_tracker_core::db;
use api_tracker_gateway::forward::{BodyTap, Gateway};
use api_tracker_gateway::record::{ExchangeRecord, ObservationSink};
use api_tracker_gateway::routes::{Route, RouteState, RouteTable, RouteTarget, UpstreamOrigin};
use api_tracker_gateway::server::{self, Listener};
use api_tracker_gateway::upstream::InsecurePlainConnectorForTests;
use rusqlite::Connection;

/// An unmistakably fake credential value, used wherever a test needs one.
pub const FAKE_KEY: &str = "FAKE-TEST-NOT-A-REAL-KEY-0000000000000001";

/// A sink that records everything, for assertions.
#[derive(Default)]
pub struct CollectingSink {
    pub records: Mutex<Vec<ExchangeRecord>>,
    pub counters: Mutex<Vec<(String, String)>>,
}

impl ObservationSink for CollectingSink {
    fn record(&self, record: ExchangeRecord) {
        self.records.lock().unwrap().push(record);
    }
    fn count(&self, route_prefix: &str, counter: &str) {
        self.counters
            .lock()
            .unwrap()
            .push((route_prefix.to_string(), counter.to_string()));
    }
}

impl CollectingSink {
    pub fn records(&self) -> Vec<ExchangeRecord> {
        self.records.lock().unwrap().clone()
    }
    pub fn counter_count(&self, route: &str, counter: &str) -> usize {
        self.counters
            .lock()
            .unwrap()
            .iter()
            .filter(|(r, c)| r == route && c == counter)
            .count()
    }
    pub fn has_counter(&self, counter: &str) -> bool {
        self.counters
            .lock()
            .unwrap()
            .iter()
            .any(|(_, c)| c == counter)
    }
    pub fn total_counters(&self) -> usize {
        self.counters.lock().unwrap().len()
    }
}

/// A migrated on-disk vault database with a project row.
pub fn test_db(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("vault.db");
    let mut conn = db::open(&path).unwrap();
    db::migrate(&mut conn).unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('vault_id', 'vault-test-0001')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO projects (id, name, description, notes, environments, archived,
             created_at, updated_at, wrapped_project_key, key_wrap_mode)
         VALUES ('p1', 'app', '', '', 'development', 0,
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', x'00', 'vault')",
        [],
    )
    .unwrap();
    path
}

pub fn open_db(path: &std::path::Path) -> Connection {
    db::open(path).unwrap()
}

/// Build a route table in memory pointing at synthetic local upstreams.
///
/// The production loader refuses loopback origins (SSRF policy), which is
/// exactly right — so tests construct the snapshot directly rather than
/// weakening the policy. This is the ONLY place a loopback "origin" exists,
/// and it never travels through `validate_origin`.
pub fn direct_route_state(routes: Vec<(&str, &str, u16, &str)>) -> Arc<RouteState> {
    let mut table = RouteTable::default();
    for (prefix, provider, port, shape) in routes {
        table.insert_for_test(Route {
            prefix: prefix.to_string(),
            provider_id: provider.to_string(),
            target: RouteTarget::Ready(UpstreamOrigin {
                host: "127.0.0.1".to_string(),
                port,
            }),
            custom: false,
            usage_shape: shape.to_string(),
        });
    }
    Arc::new(RouteState::from_table_for_test(table))
}

/// A running gateway on an ephemeral loopback port.
pub struct RunningGateway {
    pub port: u16,
    pub sink: Arc<CollectingSink>,
    pub gateway: Gateway,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl RunningGateway {
    pub fn start(routes: Arc<RouteState>) -> Self {
        Self::start_with_taps(
            routes,
            Arc::new(|_: &str, _: bool, _: bool| {
                Box::new(api_tracker_gateway::forward::NoTap) as Box<dyn BodyTap>
            }),
        )
    }

    pub fn start_with_taps(routes: Arc<RouteState>, taps: server::TapFactory) -> Self {
        let sink = Arc::new(CollectingSink::default());
        let listener = Listener::bind(0).unwrap();
        let port = listener.port();
        let mut gateway = Gateway::new(routes, sink.clone(), port);
        // Synthetic upstreams are plain-TCP loopback listeners: the HTTP
        // framing semantics under test are transport-independent, and the
        // production SSRF policy (which refuses loopback) stays intact.
        gateway.connector = Arc::new(InsecurePlainConnectorForTests);
        let gw = gateway.clone();
        let handle = std::thread::spawn(move || server::serve_with_taps(gw, listener, taps));
        Self {
            port,
            sink,
            gateway,
            handle: Some(handle),
        }
    }

    pub fn connect(&self) -> TcpStream {
        let s = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.set_nodelay(true).unwrap();
        s
    }

    pub fn authority(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Wait until `n` records have been observed (or the deadline passes).
    pub fn wait_records(&self, n: usize) -> Vec<ExchangeRecord> {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let records = self.sink.records();
            if records.len() >= n || std::time::Instant::now() > deadline {
                return records;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn stop(&mut self) {
        self.gateway.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for RunningGateway {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A synthetic upstream: a plain-TCP listener running a scripted handler.
/// (The gateway's TLS client path is exercised separately; these tests focus
/// on HTTP framing semantics, which are transport-independent.)
pub struct MockUpstream {
    pub port: u16,
    pub requests: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MockUpstream {
    /// `handler` is called per accepted connection with the socket.
    pub fn start<F>(handler: F) -> Self
    where
        F: Fn(&mut TcpStream, Arc<Mutex<Vec<Vec<u8>>>>) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (r, s) = (requests.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            let handler = Arc::new(handler);
            let mut conns: Vec<std::thread::JoinHandle<()>> = Vec::new();
            while !s.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        sock.set_nonblocking(false).unwrap();
                        sock.set_read_timeout(Some(Duration::from_secs(20)))
                            .unwrap();
                        let h = handler.clone();
                        let r = r.clone();
                        conns.push(std::thread::spawn(move || h(&mut sock, r)));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
                conns.retain(|c| !c.is_finished());
            }
            for c in conns {
                let _ = c.join();
            }
        });
        Self {
            port,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    pub fn first_request(&self) -> String {
        let r = self.requests.lock().unwrap();
        String::from_utf8_lossy(r.first().map(|v| v.as_slice()).unwrap_or(&[])).to_string()
    }

    pub fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Read an entire request head from a socket, returning the raw bytes.
pub fn read_head(sock: &mut TcpStream) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                got.extend_from_slice(&buf[..n]);
                if got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    got
}

/// Read exactly `n` more body bytes after a head.
pub fn read_exact_body(sock: &mut TcpStream, already: &[u8], n: usize) -> Vec<u8> {
    let head_end = already
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(already.len());
    let mut body = already[head_end..].to_vec();
    while body.len() < n {
        let mut buf = [0u8; 1024];
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => body.extend_from_slice(&buf[..k]),
            Err(_) => break,
        }
    }
    body
}

/// Read everything the peer sends until it closes.
pub fn read_to_close(sock: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    out
}

/// Read exactly `n` bytes from a socket (test client side).
pub fn read_n(sock: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match sock.read(&mut out[got..]) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(_) => break,
        }
    }
    out.truncate(got);
    out
}

/// Read a full HTTP response (head + Content-Length body) from a socket.
pub fn read_response(sock: &mut TcpStream) -> String {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                got.extend_from_slice(&buf[..n]);
                if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&got[..i]).to_string();
                    if let Some(cl) = content_length_of(&head) {
                        if got.len() >= i + 4 + cl {
                            break;
                        }
                    } else if !head.to_lowercase().contains("transfer-encoding") {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&got).to_string()
}

pub fn content_length_of(head: &str) -> Option<usize> {
    head.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
}

/// Write a request to the gateway.
pub fn send(sock: &mut TcpStream, raw: &str) {
    sock.write_all(raw.as_bytes()).unwrap();
    sock.flush().unwrap();
}

/// A canned handler that replies with a fixed byte string after consuming a
/// head (and an optional body length).
pub fn canned(
    response: &'static [u8],
    body_len: usize,
) -> impl Fn(&mut TcpStream, Arc<Mutex<Vec<Vec<u8>>>>) + Send + Sync + 'static {
    move |sock, requests| {
        let head = read_head(sock);
        let body = read_exact_body(sock, &head, body_len);
        let mut full = head.clone();
        full.extend_from_slice(&body[..]);
        requests.lock().unwrap().push(full);
        let _ = sock.write_all(response);
        let _ = sock.flush();
    }
}
