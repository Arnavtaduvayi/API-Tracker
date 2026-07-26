//! Gateway performance measurements against LOCAL synthetic upstreams.
//!
//! Run explicitly (never in CI):
//!   cargo test -p api-tracker-gateway --test perf --release -- --ignored --nocapture
//! or `bash scripts/gateway_perf.sh`, which captures the structured `PERF`
//! lines these tests print.
//!
//! Honesty notes: synthetic upstreams ride the transport-generic test seam
//! (the production SSRF policy refuses loopback origins BY DESIGN — SI-3 —
//! so a packaged gateway cannot forward to a local fake, and these numbers
//! come from the same forwarding engine compiled in release mode instead).
//! "Added" latency compares a direct client→upstream exchange against
//! client→gateway→upstream on the same machine, same handler. Numbers are
//! machine-dependent; the recorded results name the machine.

mod common;

use common::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FAKE_KEY_HDR: &str = "Authorization: Bearer FAKE-TEST-NOT-A-REAL-KEY-0000000000000001";

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn stats(mut samples: Vec<u128>) -> (u128, u128, u128) {
    samples.sort_unstable();
    (
        percentile(&samples, 50.0),
        percentile(&samples, 95.0),
        percentile(&samples, 99.0),
    )
}

/// Self-observation of process RSS/CPU/threads via `ps` (macOS + Linux).
fn process_sample(label: &str) {
    let pid = std::process::id().to_string();
    let rss = std::process::Command::new("ps")
        .args(["-o", "rss=,%cpu=", "-p", &pid])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    #[cfg(target_os = "macos")]
    let threads = std::process::Command::new("ps")
        .args(["-M", "-p", &pid])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .count()
                .saturating_sub(1)
        })
        .unwrap_or(0);
    #[cfg(not(target_os = "macos"))]
    let threads = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Threads:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<usize>().ok())
        })
        .unwrap_or(0);
    println!("PERF process {label} rss_kb_cpu=[{rss}] threads={threads}");
}

/// A keep-alive upstream: answers every request on the connection with the
/// same canned response.
fn keepalive_upstream(
    response: &'static [u8],
    body_len: usize,
) -> impl Fn(&mut TcpStream, Arc<Mutex<Vec<Vec<u8>>>>) + Send + Sync + 'static {
    move |sock, _requests| loop {
        let head = read_head(sock);
        if head.is_empty() {
            return;
        }
        let _body = read_exact_body(sock, &head, body_len);
        if sock.write_all(response).is_err() {
            return;
        }
        let _ = sock.flush();
    }
}

fn timed_roundtrips(
    connect: impl Fn() -> TcpStream,
    request: &str,
    n: usize,
    expected_suffix: &str,
) -> Vec<u128> {
    let mut sock = connect();
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        send(&mut sock, request);
        let resp = read_keepalive_response(&mut sock);
        samples.push(start.elapsed().as_micros());
        assert!(
            resp.ends_with(expected_suffix),
            "bad response: {:.120}",
            resp
        );
    }
    samples
}

/// Read one keep-alive response (Content-Length framed).
fn read_keepalive_response(sock: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 16384];
    let mut body_len: Option<usize> = None;
    let mut head_end = 0usize;
    loop {
        if let Some(len) = body_len {
            if buf.len() >= head_end + len {
                break;
            }
        } else if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            head_end = pos + 4;
            let head = String::from_utf8_lossy(&buf[..pos]);
            body_len = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse().ok());
            if body_len.is_none() {
                body_len = Some(0);
            }
            continue;
        }
        match sock.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn small_request(authority: &str, path: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\n{FAKE_KEY_HDR}\r\n\
         Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
    )
}

// ---------------------------------------------------------------------------

#[test]
#[ignore = "performance measurement; run via scripts/gateway_perf.sh"]
fn perf_small_json_added_latency() {
    const N: usize = 400;
    let up = MockUpstream::start(keepalive_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"ok\":true,\"n\":1}",
        2,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));

    let direct = timed_roundtrips(
        || {
            let s = TcpStream::connect(("127.0.0.1", up.port)).unwrap();
            s.set_nodelay(true).unwrap();
            s
        },
        &small_request(&format!("127.0.0.1:{}", up.port), "/v1/chat/completions"),
        N,
        "{\"ok\":true,\"n\":1}",
    );
    let through = timed_roundtrips(
        || gw.connect(),
        &small_request(&gw.authority(), "/openai/v1/chat/completions"),
        N,
        "{\"ok\":true,\"n\":1}",
    );
    let (d50, d95, d99) = stats(direct);
    let (g50, g95, g99) = stats(through);
    println!("PERF small_json n={N} direct_us p50={d50} p95={d95} p99={d99}");
    println!("PERF small_json n={N} gateway_us p50={g50} p95={g95} p99={g99}");
    println!(
        "PERF small_json added_us p50={} p95={}",
        g50.saturating_sub(d50),
        g95.saturating_sub(d95)
    );
    process_sample("small_json");
}

#[test]
#[ignore = "performance measurement; run via scripts/gateway_perf.sh"]
fn perf_large_json_download() {
    const SIZE: usize = 8 * 1024 * 1024;
    static BODY: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let body = BODY.get_or_init(|| {
        let mut b = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {SIZE}\r\n\r\n"
        )
        .into_bytes();
        b.extend(std::iter::repeat_n(b'x', SIZE));
        b
    });
    let up = MockUpstream::start(keepalive_upstream(body.as_slice(), 2));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));

    let report = |label: &str, port: u16, path: &str, authority: String| {
        let mut samples = Vec::new();
        for _ in 0..3 {
            let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
            sock.set_nodelay(true).unwrap();
            let start = Instant::now();
            send(
                &mut sock,
                &format!(
                    "POST {path} HTTP/1.1\r\nHost: {authority}\r\n{FAKE_KEY_HDR}\r\n\
                     Content-Length: 2\r\n\r\n{{}}"
                ),
            );
            let resp = read_keepalive_response(&mut sock);
            samples.push(start.elapsed().as_millis());
            assert!(resp.len() > SIZE, "truncated download in {label}");
        }
        samples.sort_unstable();
        println!(
            "PERF large_download_{label} size_mb=8 runs=3 median_ms={} max_ms={}",
            samples[1], samples[2]
        );
    };
    report(
        "direct",
        up.port,
        "/v1/files",
        format!("127.0.0.1:{}", up.port),
    );
    report("gateway", gw.port, "/openai/v1/files", gw.authority());
    process_sample("large_download");
}

#[test]
#[ignore = "performance measurement; run via scripts/gateway_perf.sh"]
fn perf_sse_first_token_and_long_stream() {
    const EVENTS: usize = 200;
    let sse = |sock: &mut TcpStream, _r: Arc<Mutex<Vec<Vec<u8>>>>| {
        let head = read_head(sock);
        if head.is_empty() {
            return;
        }
        let _ = read_exact_body(sock, &head, 2);
        let _ = sock.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
              Transfer-Encoding: chunked\r\n\r\n",
        );
        let _ = sock.flush();
        for i in 0..EVENTS {
            let event = format!("data: {{\"i\":{i}}}\n\n");
            let chunk = format!("{:x}\r\n{event}\r\n", event.len());
            if sock.write_all(chunk.as_bytes()).is_err() {
                return;
            }
            let _ = sock.flush();
            // 2ms inter-event spacing: a realistic token cadence.
            std::thread::sleep(Duration::from_millis(2));
        }
        let _ = sock.write_all(b"0\r\n\r\n");
        let _ = sock.flush();
    };
    let up = MockUpstream::start(sse);
    let gw = RunningGateway::start(direct_route_state(vec![(
        "openai", "openai", up.port, "openai",
    )]));

    let measure = |port: u16, path: &str, authority: String| -> (u128, u128, usize) {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        sock.set_nodelay(true).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let start = Instant::now();
        send(
            &mut sock,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: {authority}\r\n{FAKE_KEY_HDR}\r\n\
                 Content-Length: 2\r\n\r\n{{}}"
            ),
        );
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let mut first_event_us = 0u128;
        loop {
            match sock.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if first_event_us == 0 && find_subslice(&buf, b"data:").is_some() {
                        first_event_us = start.elapsed().as_micros();
                    }
                    if find_subslice(&buf, b"0\r\n\r\n").is_some()
                        || find_subslice(&buf, format!("\"i\":{}", EVENTS - 1).as_bytes()).is_some()
                    {
                        // Allow the terminal chunk to drain.
                        if find_subslice(&buf, b"0\r\n\r\n").is_some() {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let total = start.elapsed().as_micros();
        let events = buf.windows(5).filter(|w| w == b"data:").count();
        (first_event_us, total, events)
    };

    let (d_first, d_total, d_events) = measure(
        up.port,
        "/v1/chat/completions",
        format!("127.0.0.1:{}", up.port),
    );
    let (g_first, g_total, g_events) =
        measure(gw.port, "/openai/v1/chat/completions", gw.authority());
    assert_eq!(d_events, EVENTS, "direct stream complete");
    assert_eq!(
        g_events, EVENTS,
        "every SSE event must relay through the gateway (streaming correctness)"
    );
    println!("PERF sse events={EVENTS} direct first_event_us={d_first} total_us={d_total}");
    println!("PERF sse events={EVENTS} gateway first_event_us={g_first} total_us={g_total}");
    println!(
        "PERF sse added first_event_us={} total_us={}",
        g_first.saturating_sub(d_first),
        g_total.saturating_sub(d_total)
    );
}

#[test]
#[ignore = "performance measurement; run via scripts/gateway_perf.sh"]
fn perf_request_upload() {
    const SIZE: usize = 4 * 1024 * 1024;
    let up = MockUpstream::start(keepalive_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        SIZE,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let payload = "y".repeat(SIZE);

    let measure = |label: &str, port: u16, path: &str, authority: String| {
        let mut samples = Vec::new();
        for _ in 0..3 {
            let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
            sock.set_nodelay(true).unwrap();
            let start = Instant::now();
            send(
                &mut sock,
                &format!(
                    "POST {path} HTTP/1.1\r\nHost: {authority}\r\n{FAKE_KEY_HDR}\r\n\
                     Content-Length: {SIZE}\r\n\r\n{payload}"
                ),
            );
            let resp = read_keepalive_response(&mut sock);
            samples.push(start.elapsed().as_millis());
            assert!(resp.ends_with("ok"), "{label} upload failed");
        }
        samples.sort_unstable();
        println!(
            "PERF upload_{label} size_mb=4 runs=3 median_ms={} max_ms={}",
            samples[1], samples[2]
        );
    };
    measure(
        "direct",
        up.port,
        "/v1/files",
        format!("127.0.0.1:{}", up.port),
    );
    measure("gateway", gw.port, "/openai/v1/files", gw.authority());
}

#[test]
#[ignore = "performance measurement; run via scripts/gateway_perf.sh"]
fn perf_concurrent_requests() {
    const CLIENTS: usize = 12;
    const PER_CLIENT: usize = 25;
    let up = MockUpstream::start(keepalive_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        2,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let gw = Arc::new(gw);

    let start = Instant::now();
    let mut handles = Vec::new();
    let all_samples = Arc::new(Mutex::new(Vec::new()));
    for _ in 0..CLIENTS {
        let gw = gw.clone();
        let sink = all_samples.clone();
        handles.push(std::thread::spawn(move || {
            let samples = timed_roundtrips(
                || gw.connect(),
                &small_request(&gw.authority(), "/openai/v1/chat/completions"),
                PER_CLIENT,
                "ok",
            );
            sink.lock().unwrap().extend(samples);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let wall = start.elapsed();
    let samples = all_samples.lock().unwrap().clone();
    let (p50, p95, p99) = stats(samples);
    let total = CLIENTS * PER_CLIENT;
    println!(
        "PERF concurrent clients={CLIENTS} per_client={PER_CLIENT} total={total} \
         wall_ms={} rps={:.0} p50_us={p50} p95_us={p95} p99_us={p99}",
        wall.as_millis(),
        total as f64 / wall.as_secs_f64()
    );
    process_sample("concurrent");
}

#[test]
#[ignore = "performance measurement; run via scripts/gateway_perf.sh"]
fn perf_slow_client_and_slow_upstream() {
    // Slow upstream: 300ms think time before the response bytes.
    let slow_up = MockUpstream::start(move |sock: &mut TcpStream, _r| {
        let head = read_head(sock);
        if head.is_empty() {
            return;
        }
        let _ = read_exact_body(sock, &head, 2);
        std::thread::sleep(Duration::from_millis(300));
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![(
        "openai",
        "openai",
        slow_up.port,
        "",
    )]));
    let start = Instant::now();
    let mut sock = gw.connect();
    send(
        &mut sock,
        &small_request(&gw.authority(), "/openai/v1/chat/completions"),
    );
    let resp = read_keepalive_response(&mut sock);
    assert!(resp.ends_with("ok"));
    println!(
        "PERF slow_upstream think_ms=300 total_ms={} (added ≈ total - 300)",
        start.elapsed().as_millis()
    );

    // Slow client: 2 MiB response read at ~4KiB/2ms. The gateway must relay
    // without buffering the body and finish when the client finishes.
    const SIZE: usize = 2 * 1024 * 1024;
    static BODY: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let body = BODY.get_or_init(|| {
        let mut b = format!("HTTP/1.1 200 OK\r\nContent-Length: {SIZE}\r\n\r\n").into_bytes();
        b.extend(std::iter::repeat_n(b'z', SIZE));
        b
    });
    let up = MockUpstream::start(keepalive_upstream(body.as_slice(), 2));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut sock = gw.connect();
    let start = Instant::now();
    send(
        &mut sock,
        &small_request(&gw.authority(), "/openai/v1/chat/completions"),
    );
    let mut got = 0usize;
    let mut tmp = [0u8; 4096];
    loop {
        match sock.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                got += n;
                if got >= SIZE {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(_) => break,
        }
    }
    assert!(got >= SIZE, "slow client still received the whole body");
    println!(
        "PERF slow_client size_mb=2 read_pace=4KiB/2ms total_ms={}",
        start.elapsed().as_millis()
    );
    process_sample("slow_paths");
}

#[test]
#[ignore = "performance measurement; run via scripts/gateway_perf.sh"]
fn perf_connection_churn() {
    const CONNS: usize = 300;
    let up = MockUpstream::start(keepalive_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        2,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));

    let measure = |label: &str, port: u16, path: &str, authority: String| {
        let start = Instant::now();
        for _ in 0..CONNS {
            let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
            sock.set_nodelay(true).unwrap();
            send(
                &mut sock,
                &format!(
                    "POST {path} HTTP/1.1\r\nHost: {authority}\r\n{FAKE_KEY_HDR}\r\n\
                     Connection: close\r\nContent-Length: 2\r\n\r\n{{}}"
                ),
            );
            let resp = read_response(&mut sock);
            assert!(resp.ends_with("ok"));
        }
        println!(
            "PERF churn_{label} conns={CONNS} wall_ms={} per_conn_us={}",
            start.elapsed().as_millis(),
            start.elapsed().as_micros() / CONNS as u128
        );
    };
    measure("direct", up.port, "/v1/x", format!("127.0.0.1:{}", up.port));
    measure("gateway", gw.port, "/openai/v1/x", gw.authority());
}

#[test]
#[ignore = "performance measurement; run via scripts/gateway_perf.sh"]
fn perf_queue_and_database_pressure() {
    // A REAL writer behind the forwarding path: every exchange becomes a
    // database row, so this measures observation-queue behavior and
    // database pressure end to end. Uses the transport seam for the
    // upstream (SI-3 refuses loopback in production).
    use api_tracker_gateway::forward::Gateway;
    use api_tracker_gateway::server::{self, Listener};
    use api_tracker_gateway::upstream::InsecurePlainConnectorForTests;
    use api_tracker_gateway::writer::Writer;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    {
        let mut conn = api_tracker_core::db::open(&db_path).unwrap();
        api_tracker_core::db::migrate(&mut conn).unwrap();
    }
    let writer = Writer::start(&db_path, "perf-boot".into());
    let state = writer.state();
    let sink = writer.sink();

    let up = MockUpstream::start(keepalive_upstream(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        2,
    ));
    let routes = direct_route_state(vec![("openai", "openai", up.port, "")]);
    let listener = Listener::bind(0).unwrap();
    let port = listener.port();
    let mut gateway = Gateway::new(routes, sink, port);
    gateway.connector = Arc::new(InsecurePlainConnectorForTests);
    let gw = gateway.clone();
    let taps = Arc::new(|_: &str, _: bool, _: bool| {
        Box::new(api_tracker_gateway::forward::NoTap)
            as Box<dyn api_tracker_gateway::forward::BodyTap>
    });
    let _serve = std::thread::spawn(move || server::serve_with_taps(gw, listener, taps));

    const REQUESTS: usize = 2000;
    let authority = format!("127.0.0.1:{port}");
    let request = small_request(&authority, "/openai/v1/chat/completions");

    // Phase 1: healthy database.
    let start = Instant::now();
    let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_nodelay(true).unwrap();
    for _ in 0..REQUESTS {
        send(&mut sock, &request);
        let _ = read_keepalive_response(&mut sock);
    }
    let forward_wall = start.elapsed();

    // Drain: wait until the writer has accounted for every event.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let accounted = state.written() + state.dropped();
        if accounted >= REQUESTS as u64 || Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!(
        "PERF queue_pressure requests={REQUESTS} forward_wall_ms={} written={} dropped={} \
         persist_failures={} (forwarding never waits on the writer)",
        forward_wall.as_millis(),
        state.written(),
        state.dropped(),
        state.persist_failures.load(Ordering::Relaxed),
    );

    // Phase 2: database pressure — hold an exclusive lock while traffic
    // flows; forwarding must be unaffected and failures accounted.
    let lock_conn = api_tracker_core::db::open(&db_path).unwrap();
    lock_conn.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let start = Instant::now();
    for _ in 0..200 {
        send(&mut sock, &request);
        let _ = read_keepalive_response(&mut sock);
    }
    let locked_wall = start.elapsed();
    std::thread::sleep(Duration::from_secs(6)); // let the writer hit the lock
    lock_conn.execute_batch("ROLLBACK").unwrap();
    println!(
        "PERF db_pressure requests=200 forward_wall_ms={} (db exclusively locked) \
         persist_failures_now={} dropped_now={}",
        locked_wall.as_millis(),
        state.persist_failures.load(Ordering::Relaxed),
        state.dropped(),
    );
    process_sample("queue_db_pressure");
}
