//! Per-CONNECTION resource limits, driven end to end (`SEC-02`, `NEW-48`,
//! `NEW-51`, `NEW-52`, `NEW-54`).
//!
//! `NEW-51`: SEC-02 shipped with unit coverage of `DeadlineReader` against a
//! `&[u8]` and nothing else, so deleting the wiring in `forward.rs` left every
//! test green — the guard covered the primitive, not its use, which is exactly
//! the class of defect `NEW-48` turned out to be. Every test in this file
//! drives the real `serve_connection` over a real loopback `TcpStream` against
//! a synthetic upstream, so the wiring itself is what is under test.
//!
//! The bounds are shortened through `ConnLimits`, which is DATA on `Gateway`
//! rather than a `#[cfg(test)]` branch: the code path exercised here is
//! byte-for-byte the shipped one, and a test-only shortcut would have
//! reintroduced NEW-51 while appearing to close it. The property under test —
//! "a cumulative budget is enforced and completing a request does not renew
//! it" — is scale-free, so a 700 ms budget pins it exactly as a 600 s one
//! does. Assertions are on EVENTS (a status line, a recorded completion, a
//! socket that closed) and on upper bounds an order of magnitude above the
//! configured limit, never on an exact instant.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use api_tracker_core::runtime::model::TransportError;
use api_tracker_gateway::forward::ConnLimits;
use api_tracker_gateway::record::Completion;

use common::{
    direct_route_state, read_exact_body, read_head, read_response, read_to_close, send,
    MockUpstream, RunningGateway,
};

/// Test-scale limits with every bound held far out of the way. Each test
/// overrides exactly the one it is exercising, so a failure names the bound.
fn wide_open() -> ConnLimits {
    ConnLimits {
        head_deadline: Duration::from_secs(10),
        // Short enough that the head loop wakes to observe millisecond-scale
        // deadlines, the same relationship the production 5 s / 15 s pair has.
        head_read_timeout: Duration::from_millis(20),
        keepalive_idle: Duration::from_secs(10),
        body_idle: Duration::from_secs(10),
        body_deadline: Duration::from_secs(10),
        client_time_budget: Duration::from_secs(60),
        max_age: Duration::from_secs(60),
        max_requests: 10_000,
    }
}

/// An upstream that serves MANY requests on one socket, as a real provider
/// does. The gateway pools upstream connections across keep-alive requests, so
/// a one-shot handler would end the test at request two for reasons that have
/// nothing to do with the limits under test.
fn pooled_upstream(
    body_len: usize,
    response: &'static [u8],
) -> impl Fn(&mut TcpStream, Arc<Mutex<Vec<Vec<u8>>>>) + Send + Sync + 'static {
    move |sock, requests| loop {
        let head = read_head(sock);
        if head.is_empty() {
            break;
        }
        let body = read_exact_body(sock, &head, body_len);
        let mut full = head.clone();
        full.extend_from_slice(&body);
        requests.lock().unwrap().push(full);
        if sock.write_all(response).is_err() || sock.flush().is_err() {
            break;
        }
    }
}

const OK_EMPTY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

fn get(gw: &RunningGateway) -> String {
    format!(
        "GET /openai/v1/x HTTP/1.1\r\nHost: {}\r\n\r\n",
        gw.authority()
    )
}

fn post_head(gw: &RunningGateway, len: u64) -> String {
    format!(
        "POST /openai/v1/x HTTP/1.1\r\nHost: {}\r\nContent-Length: {len}\r\n\r\n",
        gw.authority()
    )
}

/// Dribble one byte at a time until the peer refuses the write or `budget`
/// elapses. Returns whether the gateway ended the connection on its own.
fn dribble_until_refused(sock: &mut TcpStream, gap: Duration, budget: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < budget {
        if sock.write_all(b"x").is_err() || sock.flush().is_err() {
            return true;
        }
        std::thread::sleep(gap);
    }
    false
}

/// Read a chunked response through its terminal chunk.
fn read_chunked_to_end(sock: &mut TcpStream) -> String {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                got.extend_from_slice(&buf[..n]);
                if got.windows(5).any(|w| w == b"0\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&got).to_string()
}

// --- the request-upload policy -------------------------------------------

/// `NEW-54`: no shipped test ever drove a slow BODY at a live gateway; the
/// only slow-path coverage was head-phase Slowloris. A body that never ends
/// must be ended by the gateway, not by the client losing interest.
#[test]
fn a_never_ending_request_body_is_ended_at_the_absolute_upload_deadline() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        // Never answers: only the gateway's own bound can end this.
        let _ = read_to_close(sock);
    });
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            body_deadline: Duration::from_millis(250),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    send(&mut c, &post_head(&gw, 1_000_000));
    // The response arrives while the client is still writing, so it is read on
    // a clone: a reset provoked by our own later writes must not be able to
    // discard bytes the gateway already sent.
    let mut reader = c.try_clone().unwrap();
    let start = Instant::now();
    let rx = std::thread::spawn(move || (read_to_close(&mut reader), start.elapsed()));
    dribble_until_refused(&mut c, Duration::from_millis(20), Duration::from_secs(4));
    let (raw, elapsed) = rx.join().unwrap();

    let resp = String::from_utf8_lossy(&raw).to_string();
    assert!(
        resp.starts_with("HTTP/1.1 408"),
        "a body past its absolute deadline must be answered, not silently reset: {resp:.200?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the deadline was 250ms; the connection survived {elapsed:?}"
    );
}

/// Control: the bound must not be satisfiable by refusing every slow upload.
/// A genuinely slow but finite body inside the budget completes normally.
#[test]
fn control_a_slow_but_finite_upload_inside_the_budget_completes() {
    let up = MockUpstream::start(common::canned(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        10,
    ));
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            body_deadline: Duration::from_secs(5),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    send(&mut c, &post_head(&gw, 10));
    for _ in 0..10 {
        c.write_all(b"z").unwrap();
        c.flush().unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    let resp = read_response(&mut c);
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp:?}");

    let records = gw.wait_records(1);
    assert_eq!(records[0].completion, Completion::Completed);
    assert_eq!(records[0].request_bytes, Some(10));
}

/// **The `NEW-48` regression test.** The audit held one of 128 slots for
/// 422 seconds by sending twenty slow bodies on ONE connection: each request
/// COMPLETED, so the connection was never idle, and each got a fresh
/// `CLIENT_BODY_DEADLINE`. This fails on the pre-fix engine, which serves
/// every one of the ten requests below.
#[test]
fn slow_bodies_on_one_connection_cannot_renew_the_connection_budget() {
    let up = MockUpstream::start(pooled_upstream(5, OK_EMPTY));
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            // Each individual body finishes inside its own deadline, exactly
            // as the audit's did — so only a CUMULATIVE bound can end this.
            body_deadline: Duration::from_millis(400),
            client_time_budget: Duration::from_millis(700),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    let start = Instant::now();
    let mut served = 0usize;
    for _ in 0..10 {
        if c.write_all(post_head(&gw, 5).as_bytes()).is_err() || c.flush().is_err() {
            break;
        }
        let mut sent = true;
        for _ in 0..5 {
            if c.write_all(b"z").is_err() || c.flush().is_err() {
                sent = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !sent {
            break;
        }
        let resp = read_response(&mut c);
        if !resp.starts_with("HTTP/1.1 200") {
            break;
        }
        served += 1;
        if resp.to_ascii_lowercase().contains("connection: close") {
            break;
        }
    }

    assert!(
        served >= 1,
        "the control property still holds: a slow body inside the budget is served"
    );
    assert!(
        served <= 4,
        "~250ms of client-paced time per request against a 700ms connection budget \
         must retire the connection after a handful of requests; it served {served}, \
         which is the unbounded-residency behaviour NEW-48 measured"
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "took {:?}",
        start.elapsed()
    );
}

/// Idle time is client-paced and draws on the same budget. Without this a
/// client cycles cheap requests with gaps just short of `keepalive_idle` and
/// holds a slot forever while looking perfectly well-behaved.
#[test]
fn idle_time_between_requests_draws_on_the_same_connection_budget() {
    let up = MockUpstream::start(pooled_upstream(0, OK_EMPTY));
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            // Any ONE gap is comfortably legal; two of them are not.
            keepalive_idle: Duration::from_secs(3),
            client_time_budget: Duration::from_millis(700),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    send(&mut c, &get(&gw));
    let first = read_response(&mut c);
    assert!(first.starts_with("HTTP/1.1 200"), "{first:?}");
    assert!(first
        .to_ascii_lowercase()
        .contains("connection: keep-alive"));

    std::thread::sleep(Duration::from_millis(400));
    send(&mut c, &get(&gw));
    let second = read_response(&mut c);
    assert!(
        second
            .to_ascii_lowercase()
            .contains("connection: keep-alive"),
        "one 400ms gap is well inside a 700ms budget: {second:?}"
    );

    std::thread::sleep(Duration::from_millis(400));
    send(&mut c, &get(&gw));
    let third = read_response(&mut c);
    assert!(
        third.starts_with("HTTP/1.1 200"),
        "the request that crosses the budget is still answered in full: {third:?}"
    );
    assert!(
        third.to_ascii_lowercase().contains("connection: close"),
        "800ms of cumulative idle against a 700ms budget must retire the \
         connection, and the client must be TOLD rather than reset later: {third:?}"
    );
    assert!(
        read_to_close(&mut c).is_empty(),
        "nothing follows a Connection: close"
    );
}

/// An idle connection closes silently. A budget check placed after a partial
/// read rather than at the top of the loop would answer 400 to a request
/// nobody made.
#[test]
fn an_idle_connection_is_closed_silently_without_a_spurious_400() {
    let up = MockUpstream::start(pooled_upstream(0, OK_EMPTY));
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            keepalive_idle: Duration::from_millis(200),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    send(&mut c, &get(&gw));
    let first = read_response(&mut c);
    assert!(first.starts_with("HTTP/1.1 200"), "{first:?}");

    let start = Instant::now();
    let rest = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert_eq!(rest, "", "an idle close must be silent, got {rest:?}");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "the idle budget was 200ms; the connection lingered {:?}",
        start.elapsed()
    );
}

// --- the retirement policy ------------------------------------------------

#[test]
fn a_connection_is_retired_after_the_maximum_number_of_requests() {
    let up = MockUpstream::start(pooled_upstream(0, OK_EMPTY));
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            max_requests: 3,
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    for i in 1..=3 {
        send(&mut c, &get(&gw));
        let resp = read_response(&mut c).to_ascii_lowercase();
        assert!(resp.starts_with("http/1.1 200"), "request {i}: {resp:?}");
        if i < 3 {
            assert!(
                resp.contains("connection: keep-alive"),
                "request {i} is inside the cap: {resp:?}"
            );
        } else {
            assert!(
                resp.contains("connection: close"),
                "the request that reaches the cap is answered in full and marked \
                 close: {resp:?}"
            );
        }
    }
    let _ = c.write_all(get(&gw).as_bytes());
    let _ = c.flush();
    assert!(
        read_to_close(&mut c).is_empty(),
        "a fourth request must not be served on a retired connection"
    );
}

/// Age is enforced BETWEEN requests only. A wall-clock lifetime applied
/// mid-exchange would truncate the very streaming responses this gateway
/// exists to carry, so the exchange that crosses the age is completed in full
/// and merely marked `close`.
#[test]
fn a_connection_past_its_maximum_age_finishes_its_exchange_and_is_told_to_close() {
    let up = MockUpstream::start(pooled_upstream(
        0,
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    ));
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            max_age: Duration::from_millis(200),
            keepalive_idle: Duration::from_secs(5),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    send(&mut c, &get(&gw));
    let first = read_response(&mut c);
    assert!(
        first
            .to_ascii_lowercase()
            .contains("connection: keep-alive"),
        "a young connection is reusable: {first:?}"
    );

    std::thread::sleep(Duration::from_millis(300));
    send(&mut c, &get(&gw));
    let second = read_response(&mut c);
    assert!(second.starts_with("HTTP/1.1 200"), "{second:?}");
    assert!(
        second.ends_with("hello"),
        "the exchange that crosses the age limit is never cut short: {second:?}"
    );
    assert!(
        second.to_ascii_lowercase().contains("connection: close"),
        "{second:?}"
    );
    assert!(read_to_close(&mut c).is_empty());
}

// --- the response-streaming exclusion ------------------------------------

/// **The anti-regression guard.** A streaming response is upstream-paced: the
/// gateway blocks on the PROVIDER socket, whose origin comes from the route
/// table and never from the request, so no client can lengthen this phase.
/// Charging it — or implementing the fix as a wall-clock connection lifetime —
/// would truncate a long model completion. This test fails loudly if anyone
/// does.
#[test]
fn a_streaming_response_outlives_the_connection_time_budget_and_the_maximum_age() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
              Transfer-Encoding: chunked\r\n\r\n",
        );
        let _ = sock.flush();
        for i in 0..10 {
            let event = format!("data: {{\"n\":{i}}}\n\n");
            let _ = sock.write_all(format!("{:x}\r\n", event.len()).as_bytes());
            let _ = sock.write_all(event.as_bytes());
            let _ = sock.write_all(b"\r\n");
            let _ = sock.flush();
            std::thread::sleep(Duration::from_millis(80));
        }
        let _ = sock.write_all(b"0\r\n\r\n");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            // Both bounds expire long before the ~800ms stream finishes.
            client_time_budget: Duration::from_millis(300),
            body_deadline: Duration::from_millis(300),
            max_age: Duration::from_millis(500),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    send(&mut c, &get(&gw));
    let resp = read_chunked_to_end(&mut c);
    for i in 0..10 {
        assert!(
            resp.contains(&format!("\"n\":{i}")),
            "event {i} was lost — the request-upload budget must never reach the \
             response phase: {resp:.400?}"
        );
    }
    assert!(resp.ends_with("0\r\n\r\n"), "the stream was truncated");

    let records = gw.wait_records(1);
    assert_eq!(
        records[0].completion,
        Completion::Completed,
        "a stream that outran every client-paced bound is still a complete exchange"
    );
    let ttfb = records[0].ttfb_ms.expect("ttfb");
    let latency = records[0].latency_ms.expect("latency");
    assert!(
        ttfb < latency,
        "the response must stream rather than buffer: ttfb {ttfb}ms vs latency {latency}ms"
    );
}

/// Upstream-paced time is not charged. A provider that takes longer than the
/// whole connection budget to answer must not consume the client's allowance,
/// or a slow provider would silently break keep-alive.
#[test]
fn upstream_paced_time_is_not_charged_to_the_connection_budget() {
    let up = MockUpstream::start(|sock, requests| loop {
        let head = read_head(sock);
        if head.is_empty() {
            break;
        }
        requests.lock().unwrap().push(head);
        // Far longer than the client-time budget configured below.
        std::thread::sleep(Duration::from_millis(600));
        if sock.write_all(OK_EMPTY).is_err() || sock.flush().is_err() {
            break;
        }
    });
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            client_time_budget: Duration::from_millis(400),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    send(&mut c, &get(&gw));
    let first = read_response(&mut c);
    assert!(first.starts_with("HTTP/1.1 200"), "{first:?}");
    assert!(
        first
            .to_ascii_lowercase()
            .contains("connection: keep-alive"),
        "600ms of PROVIDER time must not spend a 400ms CLIENT budget: {first:?}"
    );

    send(&mut c, &get(&gw));
    let second = read_response(&mut c);
    assert!(
        second.starts_with("HTTP/1.1 200"),
        "the connection must still be usable after a slow provider: {second:?}"
    );
}

// --- slot accounting ------------------------------------------------------

/// The slot is held for the whole of `serve_connection` and nothing outside it
/// can reclaim one, so a connection the budget never retires is a permanently
/// lost slot. This drives cap exhaustion and recovery through the budget.
#[test]
fn a_slot_held_by_a_never_ending_body_is_released_by_the_budget_and_reusable() {
    let (tx, rx) = mpsc::channel::<()>();
    let tx = Arc::new(Mutex::new(tx));
    let up = MockUpstream::start(
        move |sock: &mut TcpStream, requests: Arc<Mutex<Vec<Vec<u8>>>>| {
            let head = read_head(sock);
            let text = String::from_utf8_lossy(&head).to_string();
            requests.lock().unwrap().push(head);
            // A handshake, not a sleep: the slot is provably occupied once the
            // attacker's head has reached the provider.
            let _ = tx.lock().unwrap().send(());
            if text.contains("Content-Length: 1000000") {
                let _ = read_to_close(sock);
            } else {
                let _ = sock.write_all(OK_EMPTY);
                let _ = sock.flush();
            }
        },
    );
    let gw = RunningGateway::start_configured(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        Arc::new(|_: &str, _: bool, _: bool| {
            Box::new(api_tracker_gateway::forward::NoTap)
                as Box<dyn api_tracker_gateway::forward::BodyTap>
        }),
        |g| {
            g.max_connections = 1;
            g.limits = ConnLimits {
                // The per-request deadline is deliberately far too generous to
                // save the slot: only the CONNECTION budget can give it back,
                // so this fails if the per-connection wiring is removed.
                body_deadline: Duration::from_secs(10),
                client_time_budget: Duration::from_millis(400),
                ..wide_open()
            };
        },
    );

    let authority = gw.authority();
    let port = gw.port;
    let hog = std::thread::spawn(move || {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let _ = c.write_all(
            format!(
                "POST /openai/v1/x HTTP/1.1\r\nHost: {authority}\r\n\
                 Content-Length: 1000000\r\n\r\n"
            )
            .as_bytes(),
        );
        let _ = c.flush();
        dribble_until_refused(&mut c, Duration::from_millis(20), Duration::from_secs(6))
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the slow-body request must reach the provider");

    let mut over = TcpStream::connect(("127.0.0.1", gw.port)).unwrap();
    over.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let refused = String::from_utf8_lossy(&read_to_close(&mut over)).to_string();
    assert!(
        refused.starts_with("HTTP/1.1 503"),
        "with the only slot held, a further connection fails closed: {refused:?}"
    );

    assert!(
        hog.join().unwrap(),
        "the gateway must end the never-ending body itself"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut recovered = String::new();
    while Instant::now() < deadline {
        let mut c = TcpStream::connect(("127.0.0.1", gw.port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        send(
            &mut c,
            &format!(
                "GET /openai/v1/x HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                gw.authority()
            ),
        );
        recovered = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
        if recovered.starts_with("HTTP/1.1 200") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        recovered.starts_with("HTTP/1.1 200"),
        "the slot must come back once the budget retires the connection: {recovered:?}"
    );
}

// --- honest recording (NEW-52) --------------------------------------------

/// `NEW-52`: a deadline expiry was recorded as `ClientDisconnected` + `Reset`,
/// byte-identical to the peer vanishing, with no answer on the wire. An
/// operator could not tell "our limit cut this client off" from "this client
/// died", which are different problems with different fixes. Both cases run
/// here so the two are asserted to DIFFER, not merely to have some value.
#[test]
fn a_body_deadline_expiry_is_recorded_and_answered_apart_from_a_client_disconnect() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = read_to_close(sock);
    });
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            body_deadline: Duration::from_millis(250),
            ..wide_open()
        },
    );

    // (a) The gateway's own limit ends the upload.
    let mut cut = gw.connect();
    send(&mut cut, &post_head(&gw, 1_000_000));
    let mut reader = cut.try_clone().unwrap();
    let rx = std::thread::spawn(move || read_to_close(&mut reader));
    dribble_until_refused(&mut cut, Duration::from_millis(20), Duration::from_secs(4));
    let cut_wire = String::from_utf8_lossy(&rx.join().unwrap()).to_string();

    // (b) The peer vanishes mid-body, having promised more than it sent.
    // Half-closing is what "the client went away" looks like on the wire, and
    // is deliberately NOT the same event as the client merely going quiet —
    // that is `ClientBodyIdleTimeout`, covered separately.
    let mut gone = gw.connect();
    send(&mut gone, &post_head(&gw, 100));
    gone.write_all(b"0123456789").unwrap();
    gone.flush().unwrap();
    gone.shutdown(std::net::Shutdown::Write).unwrap();
    let vanished_wire = String::from_utf8_lossy(&read_to_close(&mut gone)).to_string();
    drop(gone);

    let records = gw.wait_records(2);
    assert_eq!(records.len(), 2, "both exchanges must be recorded");

    assert_eq!(
        records[0].completion,
        Completion::ClientBodyDeadlineExceeded
    );
    assert_eq!(records[0].transport_error, TransportError::Timeout);
    assert!(cut_wire.starts_with("HTTP/1.1 408"), "{cut_wire:.200?}");

    assert_eq!(records[1].completion, Completion::ClientDisconnected);
    assert_eq!(records[1].transport_error, TransportError::Reset);
    assert!(
        !vanished_wire.contains("408"),
        "there is nobody left to answer a client that went away: {vanished_wire:?}"
    );

    assert_ne!(
        records[0].completion, records[1].completion,
        "the whole point of NEW-52: these two must not be the same row"
    );
    assert!(!records[0].completion.is_complete_coverage());
    assert!(!records[1].completion.is_complete_coverage());
}

/// The two gateway-imposed bounds are themselves distinct: "your upload was
/// too slow" and "this connection is spent" call for different fixes by the
/// caller (send less, versus reconnect).
#[test]
fn a_body_cut_by_the_connection_budget_is_recorded_apart_from_its_own_deadline() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = read_to_close(sock);
    });
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            // The per-request deadline is generous; the CONNECTION budget is
            // what runs out, so it is the binding bound.
            body_deadline: Duration::from_secs(10),
            client_time_budget: Duration::from_millis(250),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    send(&mut c, &post_head(&gw, 1_000_000));
    let mut reader = c.try_clone().unwrap();
    let rx = std::thread::spawn(move || read_to_close(&mut reader));
    dribble_until_refused(&mut c, Duration::from_millis(20), Duration::from_secs(4));
    let wire = String::from_utf8_lossy(&rx.join().unwrap()).to_string();

    let records = gw.wait_records(1);
    assert_eq!(
        records[0].completion,
        Completion::ConnectionBudgetExceeded,
        "the connection budget, not the 10s request deadline, ended this"
    );
    assert_eq!(records[0].transport_error, TransportError::Timeout);
    assert!(records[0].completion.is_gateway_imposed_limit());
    assert!(wire.starts_with("HTTP/1.1 408"), "{wire:.200?}");
}

/// A client that stops sending without disconnecting is neither a disconnect
/// nor a deadline expiry: the per-read idle timeout is its own bound and gets
/// its own row.
#[test]
fn a_client_that_stalls_mid_body_is_recorded_as_an_idle_timeout() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = read_to_close(sock);
    });
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            // The idle bound fires long before the absolute one.
            body_idle: Duration::from_millis(150),
            body_deadline: Duration::from_secs(10),
            client_time_budget: Duration::from_secs(10),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    send(&mut c, &post_head(&gw, 100));
    c.write_all(b"0123456789").unwrap();
    c.flush().unwrap();
    // Then say nothing at all, while staying connected.
    let wire = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();

    let records = gw.wait_records(1);
    assert_eq!(records[0].completion, Completion::ClientBodyIdleTimeout);
    assert_eq!(records[0].transport_error, TransportError::Timeout);
    assert!(
        wire.starts_with("HTTP/1.1 408"),
        "a client that is still there is told why: {wire:.200?}"
    );
}

/// An upstream failure must not be attributed to a client-facing bound. The
/// only thing that can report one is the client-side reader, so an error
/// raised anywhere else stays what it was.
#[test]
fn an_upstream_that_disconnects_is_not_recorded_as_a_client_limit() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        // Close without answering.
        let _ = sock.shutdown(std::net::Shutdown::Both);
    });
    let gw = RunningGateway::start_with_limits(
        direct_route_state(vec![("openai", "openai", up.port, "")]),
        ConnLimits {
            client_time_budget: Duration::from_millis(300),
            ..wide_open()
        },
    );

    let mut c = gw.connect();
    send(&mut c, &get(&gw));
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp:.200?}");

    let records = gw.wait_records(1);
    assert_eq!(records[0].completion, Completion::UpstreamDisconnected);
    assert!(
        !records[0].completion.is_gateway_imposed_limit(),
        "a provider failure must never be labelled as our own limit"
    );
}
