//! Forwarding-engine integration tests (TEST_PLAN §1 and §2).
//!
//! Every upstream is a local synthetic listener. No real credential, no live
//! provider call, no network egress.

mod common;

use common::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use api_tracker_core::runtime::model::TransportError;
use api_tracker_gateway::record::Completion;

// ---------------------------------------------------------------------------
// §1 HTTP correctness
// ---------------------------------------------------------------------------

#[test]
fn content_length_exchange_relays_verbatim_and_records_metadata() {
    let up = MockUpstream::start(canned(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"ok\":true,\"n\":1}",
        2,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "POST /openai/v1/chat/completions HTTP/1.1\r\nHost: {}\r\n\
             Authorization: Bearer {FAKE_KEY}\r\nContent-Type: application/json\r\n\
             Content-Length: 2\r\n\r\n{{}}",
            gw.authority()
        ),
    );
    let resp = read_response(&mut c);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "got: {resp}");
    assert!(resp.contains("Content-Type: application/json\r\n"));
    assert!(resp.ends_with("{\"ok\":true,\"n\":1}"));

    // The upstream saw the prefix stripped, the Host rewritten, and the
    // credential passed through untouched.
    let req = up.first_request();
    assert!(
        req.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"),
        "got: {req}"
    );
    assert!(req.contains("Host: 127.0.0.1\r\n"));
    assert!(req.contains(&format!("Authorization: Bearer {FAKE_KEY}")));

    let records = gw.wait_records(1);
    let r = &records[0];
    assert_eq!(r.status_code, Some(200));
    assert_eq!(r.route_prefix, "openai");
    assert_eq!(r.path_template, "/v1/chat/completions");
    assert_eq!(r.request_bytes, Some(2));
    assert_eq!(r.response_bytes, Some(17));
    assert!(r.had_authorization);
    assert_eq!(r.completion, Completion::Completed);
    assert!(r.latency_ms.is_some() && r.ttfb_ms.is_some());
}

#[test]
fn keep_alive_serves_multiple_requests_on_one_client_connection() {
    let up = MockUpstream::start(|sock, requests| {
        // Serve two keep-alive requests on this upstream socket.
        for _ in 0..2 {
            let head = read_head(sock);
            if head.is_empty() {
                return;
            }
            requests.lock().unwrap().push(head);
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            let _ = sock.flush();
        }
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    for _ in 0..2 {
        send(
            &mut c,
            &format!(
                "GET /openai/v1/models HTTP/1.1\r\nHost: {}\r\n\r\n",
                gw.authority()
            ),
        );
        let resp = read_response(&mut c);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
        assert!(resp.contains("Connection: keep-alive"));
    }
    assert_eq!(up.request_count(), 2, "the upstream socket was reused");
    assert_eq!(gw.wait_records(2).len(), 2);
}

#[test]
fn chunked_response_framing_and_trailers_relay_verbatim() {
    let raw: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\
        Retry-After: 7\r\nx-request-id: req_abc123\r\nTransfer-Encoding: chunked\r\n\r\n\
        1a\r\n{\"error\":\"rate_limited\"}\r\n\r\n0\r\nX-Trailer: t\r\n\r\n";
    let up = MockUpstream::start(canned(raw, 0));
    let gw = RunningGateway::start(direct_route_state(vec![(
        "anthropic",
        "anthropic",
        up.port,
        "",
    )]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /anthropic/v1/models HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            gw.authority()
        ),
    );
    let got = read_to_close(&mut c);
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(text.contains("Retry-After: 7\r\n"));
    assert!(text.contains("x-request-id: req_abc123\r\n"));
    assert!(text.contains("Transfer-Encoding: chunked\r\n"));
    // The body and its chunk framing are byte-identical, and an ordinary
    // trailer is relayed.
    let body_start = text.find("\r\n\r\n").unwrap() + 4;
    assert_eq!(
        &got[body_start..],
        b"1a\r\n{\"error\":\"rate_limited\"}\r\n\r\n0\r\nX-Trailer: t\r\n\r\n"
    );

    let r = &gw.wait_records(1)[0];
    assert_eq!(r.status_code, Some(429));
}

#[test]
fn sse_streams_incrementally_rather_than_buffering_the_whole_response() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
        );
        let _ = sock.flush();
        for e in [
            &b"data: {\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n"[..],
            b"data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n",
            b"data: [DONE]\n\n",
        ] {
            let _ = sock.write_all(e);
            let _ = sock.flush();
            std::thread::sleep(Duration::from_millis(120));
        }
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    let start = Instant::now();
    send(
        &mut c,
        &format!(
            "POST /openai/v1/chat HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n",
            gw.authority()
        ),
    );

    let mut arrivals: Vec<(Duration, Vec<u8>)> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => arrivals.push((start.elapsed(), buf[..n].to_vec())),
            Err(_) => break,
        }
    }
    let first_event = arrivals
        .iter()
        .find(|(_, b)| b.windows(6).any(|w| w == b"data: "))
        .expect("the client received SSE events")
        .0;
    let last = arrivals.last().unwrap().0;
    assert!(
        last - first_event >= Duration::from_millis(150),
        "events must arrive spread over time (streamed), not buffered: \
         first {first_event:?}, last {last:?}"
    );

    let r = &gw.wait_records(1)[0];
    // Time-to-first-byte must reflect the provider's own latency, not the
    // whole stream duration.
    assert!(
        r.ttfb_ms.unwrap() < r.latency_ms.unwrap(),
        "ttfb {:?} must precede total {:?}",
        r.ttfb_ms,
        r.latency_ms
    );
    assert_eq!(r.completion, Completion::Completed);
}

#[test]
fn request_bodies_stream_upstream_without_buffering() {
    let arrivals: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
    let a = arrivals.clone();
    let up = MockUpstream::start(move |sock, requests| {
        let start = Instant::now();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    a.lock().unwrap().push(start.elapsed());
                    got.extend_from_slice(&buf[..n]);
                    if got.ends_with(b"0\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        requests.lock().unwrap().push(got);
        let _ =
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "POST /openai/v1/audio HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n",
            gw.authority()
        ),
    );
    std::thread::sleep(Duration::from_millis(40));
    c.write_all(b"5\r\nhello\r\n").unwrap();
    c.flush().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    c.write_all(b"6\r\n world\r\n0\r\n\r\n").unwrap();
    c.flush().unwrap();
    let _ = read_to_close(&mut c);

    let arrivals = arrivals.lock().unwrap().clone();
    let span = *arrivals.last().unwrap() - arrivals[0];
    assert!(
        span >= Duration::from_millis(150),
        "body bytes must arrive incrementally (span {span:?}), not in one flush"
    );
    assert!(up.first_request().ends_with("0\r\n\r\n"));
}

#[test]
fn cross_route_requests_never_share_an_upstream_socket() {
    // The highest-severity test: a kept-alive client that switches providers
    // must reach TWO distinct upstreams, and provider B's credential must
    // never be written into provider A's connection.
    let a_key = "FAKE-TEST-NOT-A-REAL-KEY-AAAA";
    let b_key = "FAKE-TEST-NOT-A-REAL-KEY-BBBB";
    let up_a = MockUpstream::start(|sock, requests| loop {
        let head = read_head(sock);
        if head.is_empty() {
            return;
        }
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA");
        let _ = sock.flush();
    });
    let up_b = MockUpstream::start(|sock, requests| loop {
        let head = read_head(sock);
        if head.is_empty() {
            return;
        }
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![
        ("openai", "openai", up_a.port, ""),
        ("anthropic", "anthropic", up_b.port, ""),
    ]));

    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {a_key}\r\n\r\n",
            gw.authority()
        ),
    );
    assert!(read_response(&mut c).ends_with('A'));
    send(
        &mut c,
        &format!("GET /anthropic/v1/models HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {b_key}\r\n\r\n", gw.authority()),
    );
    assert!(read_response(&mut c).ends_with('B'));
    // And back to the first route.
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {a_key}\r\n\r\n",
            gw.authority()
        ),
    );
    assert!(read_response(&mut c).ends_with('A'));

    let seen_a = up_a.requests.lock().unwrap().clone();
    let seen_b = up_b.requests.lock().unwrap().clone();
    let text_a = String::from_utf8_lossy(&seen_a.concat()).to_string();
    let text_b = String::from_utf8_lossy(&seen_b.concat()).to_string();
    assert!(text_a.contains(a_key), "route A saw its own credential");
    assert!(text_b.contains(b_key), "route B saw its own credential");
    assert!(
        !text_a.contains(b_key),
        "provider B's credential must NEVER reach provider A's connection"
    );
    assert!(
        !text_b.contains(a_key),
        "provider A's credential must NEVER reach provider B's connection"
    );
    assert_eq!(seen_a.len(), 2, "route A's socket was reused, not redialed");
    assert_eq!(seen_b.len(), 1);
}

#[test]
fn expect_100_continue_relays_the_interim_before_the_body() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        let _ = sock.flush();
        let mut body = vec![0u8; 5];
        let _ = sock.read_exact(&mut body);
        requests.lock().unwrap().push(body);
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!("POST /openai/v1/files HTTP/1.1\r\nHost: {}\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n", gw.authority()),
    );
    let interim = read_n(&mut c, 25);
    assert!(
        interim.starts_with(b"HTTP/1.1 100 Continue"),
        "client must receive the interim: {:?}",
        String::from_utf8_lossy(&interim)
    );
    c.write_all(b"hello").unwrap();
    c.flush().unwrap();
    let rest = read_to_close(&mut c);
    assert!(String::from_utf8_lossy(&rest).starts_with("HTTP/1.1 200 OK"));
    let seen = up.requests.lock().unwrap().clone();
    assert_eq!(seen[1], b"hello");
}

#[test]
fn a_coalesced_100_continue_and_final_response_does_not_hang() {
    // The Phase 1 hang blocker: both heads in ONE write, before the body.
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone",
        );
        let _ = sock.flush();
        let mut body = vec![0u8; 5];
        let _ = sock.read_exact(&mut body);
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!("POST /openai/v1/files HTTP/1.1\r\nHost: {}\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n", gw.authority()),
    );
    let interim = read_n(&mut c, 25);
    assert!(interim.starts_with(b"HTTP/1.1 100 Continue"));
    c.write_all(b"hello").unwrap();
    c.flush().unwrap();
    let rest = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        rest.starts_with("HTTP/1.1 200 OK"),
        "the coalesced final response must reach the client, got {rest:?}"
    );
    assert!(rest.ends_with("done"));
}

#[test]
fn a_final_response_instead_of_the_interim_skips_the_body() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(
            b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno",
        );
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!("POST /openai/v1/files HTTP/1.1\r\nHost: {}\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n", gw.authority()),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(resp.starts_with("HTTP/1.1 417"), "got: {resp}");
    // The client connection is NOT reusable: its unsent body would desync.
    assert!(resp.contains("Connection: close"));
    let r = &gw.wait_records(1)[0];
    assert_eq!(r.status_code, Some(417));
    assert_eq!(r.request_bytes, Some(0));
}

#[test]
fn an_upstream_that_never_answers_the_expectation_proceeds_with_the_body() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        // Deliberately silent past the interim budget, then read the body.
        let mut body = vec![0u8; 5];
        let _ = sock.read_exact(&mut body);
        requests.lock().unwrap().push(body);
        let _ =
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    send(
        &mut c,
        &format!("POST /openai/v1/files HTTP/1.1\r\nHost: {}\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello", gw.authority()),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    // The gateway synthesizes the interim the upstream owed (RFC 9110
    // §10.1.1) before proceeding, so a client that WAS waiting is released.
    assert!(
        resp.starts_with("HTTP/1.1 100 Continue\r\n\r\n"),
        "the interim must be synthesized; got: {resp}"
    );
    assert!(resp.contains("HTTP/1.1 200 OK"), "no deadlock; got: {resp}");
    let seen = up.requests.lock().unwrap().clone();
    assert_eq!(seen[1], b"hello");
}

/// The case the test above could not reach: a CONFORMING client that
/// withholds its body until it sees the interim. Without a synthesized
/// `100 Continue` both sides wait — the gateway for a body the client is not
/// sending, the client for an interim the upstream never sent — until the
/// 60-second client-body idle timeout fires.
#[test]
fn a_client_waiting_for_the_interim_is_released_when_the_upstream_is_silent() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        // Never answers the expectation; reads the body once it arrives.
        let mut body = vec![0u8; 5];
        let _ = sock.read_exact(&mut body);
        requests.lock().unwrap().push(body);
        let _ =
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    // Head only — the body is withheld, exactly as RFC 9110 says a client
    // using Expect: 100-continue may do.
    send(
        &mut c,
        &format!(
            "POST /openai/v1/files HTTP/1.1\r\nHost: {}\r\n\
             Expect: 100-continue\r\nContent-Length: 5\r\n\r\n",
            gw.authority()
        ),
    );

    // Read just the interim head, well inside the 60s body-idle timeout.
    let mut interim = [0u8; 25];
    let started = std::time::Instant::now();
    let n = {
        use std::io::Read;
        c.read(&mut interim).unwrap()
    };
    let waited = started.elapsed();
    let text = String::from_utf8_lossy(&interim[..n]).to_string();
    assert!(
        text.starts_with("HTTP/1.1 100 Continue"),
        "the client must receive an interim rather than block; got: {text:?}"
    );
    assert!(
        waited < Duration::from_secs(30),
        "the interim must arrive on the upstream-interim budget (~5s), not the \
         60s body-idle timeout; waited {waited:?}"
    );

    // Now the client sends its body and the exchange completes.
    send(&mut c, "hello");
    let rest = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(rest.contains("HTTP/1.1 200 OK"), "got: {rest}");
    let seen = up.requests.lock().unwrap().clone();
    assert_eq!(seen[1], b"hello");
}

/// A trailer naming a header the gateway strips from the RESPONSE HEAD must
/// not arrive through the trailer section instead. SI-4/SI-4a state the
/// strip unconditionally; the trailer section was relayed verbatim.
#[test]
fn chunked_trailers_are_filtered_like_the_response_head() {
    let raw: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\
        Trailer: Set-Cookie\r\n\r\n\
        2\r\nhi\r\n0\r\n\
        Set-Cookie: sid=CANARY-TRAILER-COOKIE\r\n\
        Access-Control-Allow-Origin: *\r\n\
        X-Keep: yes\r\n\r\n";
    let up = MockUpstream::start(canned(raw, 0));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            gw.authority()
        ),
    );
    let text = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        !text.contains("CANARY-TRAILER-COOKIE"),
        "a Set-Cookie trailer must be stripped like a Set-Cookie header: {text}"
    );
    assert!(
        !text
            .to_ascii_lowercase()
            .contains("access-control-allow-origin"),
        "CORS headers must not reach the client through a trailer: {text}"
    );
    assert!(
        text.contains("X-Keep: yes"),
        "an ordinary trailer must still be relayed: {text}"
    );
    assert!(text.contains("hi"), "the body must still arrive: {text}");
}

#[test]
fn cookies_and_cors_headers_are_stripped_in_both_directions() {
    let up = MockUpstream::start(canned(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: sess=leak\r\n\
          Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\n\
          Keep-Alive: timeout=5\r\nProxy-Authenticate: x\r\nConnection: close\r\n\r\nok",
        0,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {}\r\nCookie: local=devserver\r\n\r\n",
            gw.authority()
        ),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(!resp.contains("Set-Cookie"), "Set-Cookie must be stripped");
    assert!(
        !resp.contains("Access-Control"),
        "CORS headers must be stripped"
    );
    assert!(!resp.contains("Keep-Alive:"));
    assert!(!resp.contains("Proxy-Authenticate"));
    assert!(
        !up.first_request().contains("Cookie:"),
        "Cookie must be stripped"
    );
}

#[test]
fn provider_error_statuses_and_redirects_relay_verbatim_and_are_never_followed() {
    for (raw, expect) in [
        (&b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..], 401u16),
        (b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 403),
        (b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 500),
        (b"HTTP/1.1 302 Found\r\nLocation: https://evil.example.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 302),
        (b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 307),
    ] {
        let up = MockUpstream::start(canned(raw, 0));
        let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
        let mut c = gw.connect();
        send(
            &mut c,
            &format!(
                "GET /openai/v1/models HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                gw.authority()
            ),
        );
        let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
        assert!(
            resp.starts_with(&format!("HTTP/1.1 {expect}")),
            "status must relay verbatim, got: {resp}"
        );
        if expect == 302 {
            // A redirect is handed to the client untouched; the gateway never
            // follows it (that would escape the route policy).
            assert!(resp.contains("Location: https://evil.example.com/"));
            assert_eq!(up.request_count(), 1, "the redirect must not be followed");
        }
        let r = &gw.wait_records(1)[0];
        assert_eq!(r.status_code, Some(expect));
    }
}

#[test]
fn an_upstream_close_before_any_response_byte_yields_a_local_502() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = sock.shutdown(std::net::Shutdown::Both);
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(resp.starts_with("HTTP/1.1 502"), "got: {resp}");
    assert!(
        resp.contains("tethra-gateway:"),
        "the diagnostic is local and labeled"
    );
    let r = &gw.wait_records(1)[0];
    assert_eq!(r.completion, Completion::UpstreamDisconnected);
    assert_eq!(r.transport_error, TransportError::Reset);
    assert_eq!(r.status_code, None);
}

#[test]
fn a_truncated_content_length_body_is_terminal_and_recorded_honestly() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        // Declares 100 bytes, sends 4, then closes.
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshor");
        let _ = sock.flush();
        let _ = sock.shutdown(std::net::Shutdown::Both);
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    // The provider's stream already began, so NO synthetic body was injected
    // afterwards: the client sees exactly the truncated bytes.
    assert!(resp.ends_with("shor"), "got: {resp:?}");
    assert!(!resp.contains("tethra-gateway:"));
    let r = &gw.wait_records(1)[0];
    assert_eq!(r.completion, Completion::Truncated);
    assert!(!r.completion.is_complete_coverage());
}

#[test]
fn an_until_close_response_is_connection_terminal() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        // Neither Content-Length nor Transfer-Encoding: close-delimited.
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nstreamed");
        let _ = sock.flush();
        let _ = sock.shutdown(std::net::Shutdown::Both);
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/x HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        resp.contains("Connection: close"),
        "must force close: {resp}"
    );
    assert!(resp.ends_with("streamed"));
    assert_eq!(gw.wait_records(1)[0].completion, Completion::Completed);
}

#[test]
fn head_and_204_responses_carry_no_body() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        let is_head = head.starts_with(b"HEAD ");
        requests.lock().unwrap().push(head);
        if is_head {
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\nConnection: close\r\n\r\n");
        } else {
            let _ = sock.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        }
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));

    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "HEAD /openai/v1/x HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            gw.authority()
        ),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("Content-Length: 42"));
    assert!(
        resp.ends_with("\r\n\r\n"),
        "HEAD must have no body: {resp:?}"
    );

    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "DELETE /openai/v1/x HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            gw.authority()
        ),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(resp.starts_with("HTTP/1.1 204"));
    assert!(resp.ends_with("\r\n\r\n"));
}

#[test]
fn a_client_that_disconnects_mid_response_is_recorded_and_tears_down_the_upstream() {
    // The upstream reports back how its write loop ended, so the teardown is
    // asserted rather than assumed.
    let torn_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = torn_down.clone();
    let up = MockUpstream::start(move |sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4000000\r\n\r\n");
        let _ = sock.flush();
        let chunk = vec![b'x'; 8192];
        for _ in 0..500 {
            if sock.write_all(&chunk).is_err() {
                // The gateway closed this socket because its client vanished.
                flag.store(true, Ordering::Relaxed);
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/big HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    let mut buf = [0u8; 1024];
    let _ = c.read(&mut buf);
    drop(c); // disconnect mid-response

    let records = gw.wait_records(1);
    let r = &records[0];
    assert!(
        matches!(
            r.completion,
            Completion::ClientDisconnected | Completion::Truncated
        ),
        "a client disconnect must be recorded honestly, got {:?}",
        r.completion
    );
    assert!(
        !r.completion.is_complete_coverage(),
        "a partial exchange must never claim complete coverage"
    );
    assert_eq!(
        r.status_code,
        Some(200),
        "the head was seen before the break"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    while !torn_down.load(Ordering::Relaxed) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        torn_down.load(Ordering::Relaxed),
        "the upstream socket must be torn down when the client disconnects, \
         not left draining the provider's response into nothing"
    );
}

#[test]
fn graceful_shutdown_lets_an_in_flight_exchange_finish() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        std::thread::sleep(Duration::from_millis(300));
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/slow HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    // Signal shutdown only once the exchange is genuinely in flight (the
    // upstream has the request): a connection still sitting in the accept
    // backlog is legitimately dropped by a stop, which is a different case.
    let deadline = Instant::now() + Duration::from_secs(5);
    while up.request_count() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    gw.gateway.shutdown.store(true, Ordering::Relaxed);
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        resp.starts_with("HTTP/1.1 200 OK") && resp.ends_with("done"),
        "a clean stop must not sever an in-flight exchange: {resp:?}"
    );
}

// ---------------------------------------------------------------------------
// §2 Smuggling and robustness
// ---------------------------------------------------------------------------

fn assert_rejected(gw: &RunningGateway, raw: &str, status: &str, upstream: &MockUpstream) {
    let mut c = gw.connect();
    c.write_all(raw.as_bytes()).unwrap();
    c.flush().unwrap();
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        resp.starts_with(&format!("HTTP/1.1 {status}")),
        "expected {status} for {:?}, got {resp:?}",
        &raw[..raw.len().min(70)]
    );
    assert_eq!(
        upstream.request_count(),
        0,
        "nothing may be forwarded for a rejected request"
    );
}

#[test]
fn smuggling_and_malformed_heads_are_rejected_with_400_and_nothing_forwarded() {
    let up = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let auth = gw.authority();
    for raw in [
        format!("POST /openai/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello"),
        format!("POST /openai/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"),
        format!("POST /openai/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 5, 5\r\n\r\nhello"),
        format!("POST /openai/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: +5\r\n\r\nhello"),
        format!("POST /openai/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 0x10\r\n\r\nhello"),
        format!("POST /openai/x HTTP/1.1\r\nHost: {auth}\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n"),
        format!("POST /openai/x HTTP/1.1\r\nHost: {auth}\r\nTransfer-Encoding: gzip\r\n\r\n"),
        format!("POST /openai/x HTTP/1.1\nHost: {auth}\nX-Evil: 1\n\n"),
        format!("POST /openai/x HTTP/1.1\r\nHost: {auth}\r\n X-Folded: 1\r\n\r\n"),
    ] {
        assert_rejected(&gw, &raw, "400", &up);
    }
    assert!(gw.sink.has_counter("rejected_locally"));
    assert!(
        gw.sink.records().is_empty(),
        "a locally-rejected request writes no observation row"
    );
}

#[test]
fn lf_only_chunk_framing_is_rejected_and_nothing_reaches_the_upstream() {
    // SI-15: bare-LF chunk framing is the classic smuggling primitive. The
    // gateway REJECTS it with a 400; it does not normalize it into CRLF and
    // it does not forward it verbatim. `observe::relay` tolerates bare LF
    // (safe for the observation proxy), which is exactly why the gateway
    // carries its own strict chunked relay.
    let up = MockUpstream::start(|sock, requests| {
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = sock.read(&mut buf) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.ends_with(b"0\r\n\r\n") {
                break;
            }
        }
        requests.lock().unwrap().push(got);
        let _ =
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "POST /openai/x HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\n0\n\n",
            gw.authority()
        ),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        resp.starts_with("HTTP/1.1 400"),
        "bare-LF chunk framing must be REJECTED, got: {resp:?}"
    );
    let seen = up.first_request();
    assert!(
        !seen.contains("hello"),
        "no chunk data may reach the upstream after a framing rejection: {seen:?}"
    );
    assert!(
        !seen.contains("5\r\nhello\r\n"),
        "and it must never be normalized into valid CRLF framing"
    );
}

#[test]
fn chunk_extensions_and_malformed_terminators_are_rejected() {
    let up = MockUpstream::start(canned(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        0,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    for body in [
        "5;ext=1\r\nhello\r\n0\r\n\r\n",
        "0x5\r\nhello\r\n0\r\n\r\n",
        "5\r\nhelloXX0\r\n\r\n",
    ] {
        let mut c = gw.connect();
        send(
            &mut c,
            &format!(
                "POST /openai/x HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n{body}",
                gw.authority()
            ),
        );
        let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
        assert!(
            resp.starts_with("HTTP/1.1 400"),
            "chunked body {body:?} must be rejected, got {resp:?}"
        );
    }
}

#[test]
fn oversized_and_overcounted_heads_are_bounded() {
    let up = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let auth = gw.authority();

    let mut raw = format!("GET /openai/x HTTP/1.1\r\nHost: {auth}\r\n");
    for i in 0..150 {
        raw.push_str(&format!("X-H{i}: v\r\n"));
    }
    raw.push_str("\r\n");
    assert_rejected(&gw, &raw, "400", &up);

    let mut raw = format!("GET /openai/x HTTP/1.1\r\nHost: {auth}\r\nX-Big: ");
    raw.push_str(&"a".repeat(64 * 1024));
    raw.push_str("\r\n\r\n");
    let mut c = gw.connect();
    let _ = c.write_all(raw.as_bytes());
    let _ = c.flush();
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        resp.is_empty() || resp.starts_with("HTTP/1.1 400"),
        "an oversized head must be refused, got {resp:?}"
    );
    assert_eq!(up.request_count(), 0);
}

#[test]
fn connect_absolute_form_upgrade_and_http10_are_refused() {
    let up = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let auth = gw.authority();
    for (raw, status) in [
        (format!("CONNECT evil.example.com:443 HTTP/1.1\r\nHost: {auth}\r\n\r\n"), "405"),
        (format!("GET http://evil.example.com/ HTTP/1.1\r\nHost: {auth}\r\n\r\n"), "400"),
        (format!("GET https://evil.example.com/x HTTP/1.1\r\nHost: {auth}\r\n\r\n"), "400"),
        (format!("OPTIONS * HTTP/1.1\r\nHost: {auth}\r\n\r\n"), "400"),
        (format!("GET /openai/x HTTP/1.1\r\nHost: {auth}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"), "501"),
        (format!("GET /openai/x HTTP/1.0\r\nHost: {auth}\r\n\r\n"), "505"),
    ] {
        assert_rejected(&gw, &raw, status, &up);
    }
}

#[test]
fn the_host_gate_accepts_only_this_gateways_own_loopback_authority() {
    let up = MockUpstream::start(canned(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        0,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let port = gw.port;
    for bad in [
        "GET /openai/x HTTP/1.1\r\n\r\n".to_string(),
        "GET /openai/x HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_string(),
        format!("GET /openai/x HTTP/1.1\r\nHost: localhost.evil.com:{port}\r\n\r\n"),
        format!(
            "GET /openai/x HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            port.wrapping_add(1)
        ),
        "GET /openai/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_string(),
        format!("GET /openai/x HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nHost: evil.com\r\n\r\n"),
    ] {
        assert_rejected(&gw, &bad, "400", &up);
    }
    // The three accepted forms, case-insensitively.
    for good in [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("LOCALHOST:{port}"),
        format!("[::1]:{port}"),
    ] {
        let mut c = gw.connect();
        send(
            &mut c,
            &format!("GET /openai/x HTTP/1.1\r\nHost: {good}\r\nConnection: close\r\n\r\n"),
        );
        let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "{good} must be accepted, got {resp:?}"
        );
    }
}

#[test]
fn browser_originated_requests_are_refused_and_leave_only_one_counter() {
    let up = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let auth = gw.authority();
    for raw in [
        // The CORS-simple write primitive: text/plain POST, no preflight.
        format!("POST /openai/v1/chat HTTP/1.1\r\nHost: {auth}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}"),
        format!("POST /openai/v1/chat HTTP/1.1\r\nHost: {auth}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 2\r\n\r\na="),
        format!("GET /openai/v1/models HTTP/1.1\r\nHost: {auth}\r\nOrigin: https://evil.example.com\r\n\r\n"),
        format!("GET /openai/v1/models HTTP/1.1\r\nHost: {auth}\r\nReferer: https://evil.example.com/\r\n\r\n"),
        format!("GET /openai/v1/models HTTP/1.1\r\nHost: {auth}\r\nSec-Fetch-Site: cross-site\r\n\r\n"),
        format!("GET /openai/v1/models HTTP/1.1\r\nHost: {auth}\r\nSec-Fetch-Mode: no-cors\r\n\r\n"),
    ] {
        assert_rejected(&gw, &raw, "403", &up);
    }
    // Exactly one global counter per rejection, no route counter, no rows.
    assert_eq!(gw.sink.counter_count("", "rejected_browser_origin"), 6);
    assert_eq!(
        gw.sink.total_counters(),
        6,
        "no other counter may be bumped"
    );
    assert!(
        gw.sink.records().is_empty(),
        "no observation row for a rejected page request"
    );

    // A legitimate multipart upload WITH a credential is not a browser write.
    let mut c = gw.connect();
    send(
        &mut c,
        &format!("POST /openai/v1/audio HTTP/1.1\r\nHost: {auth}\r\nAuthorization: Bearer {FAKE_KEY}\r\nContent-Type: multipart/form-data; boundary=x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "SDK uploads must still work: {resp}"
    );
}

#[test]
fn unknown_prefixes_unknown_slugs_and_traversal_never_forward() {
    let up = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let auth = gw.authority();

    let mut responses = Vec::new();
    for path in [
        "/nope/v1/x",
        "/openai2/v1/x",                                   // prefix confusion
        "/p/deadbeefdeadbeefdeadbeefdeadbeef/openai/v1/x", // unknown slug
        "/",
        "/p",
        "/p/",
    ] {
        let mut c = gw.connect();
        send(
            &mut c,
            &format!("GET {path} HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        );
        let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
        assert!(resp.starts_with("HTTP/1.1 404"), "{path} => {resp:?}");
        responses.push(resp);
    }
    // Unknown prefix and unknown slug must be INDISTINGUISHABLE.
    assert_eq!(
        responses[0], responses[2],
        "unknown prefix and unknown slug must return an identical 404"
    );

    for path in ["/openai/../anthropic/x", "/openai/%2e%2e/x", "/openai/./x"] {
        let mut c = gw.connect();
        send(
            &mut c,
            &format!("GET {path} HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        );
        let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
        assert!(resp.starts_with("HTTP/1.1 400"), "{path} => {resp:?}");
    }
    assert_eq!(up.request_count(), 0, "nothing may be forwarded");
}

#[test]
fn bare_prefix_and_query_only_tails_map_to_the_root_path() {
    let up = MockUpstream::start(|sock, requests| loop {
        let head = read_head(sock);
        if head.is_empty() {
            return;
        }
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let auth = gw.authority();
    for (path, expect) in [
        ("/openai", "GET / HTTP/1.1"),
        ("/openai/", "GET / HTTP/1.1"),
        (
            "/openai/v1/models?limit=5",
            "GET /v1/models?limit=5 HTTP/1.1",
        ),
    ] {
        let mut c = gw.connect();
        send(
            &mut c,
            &format!("GET {path} HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        );
        let _ = read_response(&mut c);
        let seen = up.requests.lock().unwrap().last().cloned().unwrap();
        let text = String::from_utf8_lossy(&seen).to_string();
        assert!(text.starts_with(expect), "{path} => {text:?}");
    }
    // The query reached the provider but is NEVER in a stored template.
    let records = gw.wait_records(3);
    assert!(records.iter().all(|r| !r.path_template.contains("limit")));
    assert!(records.iter().all(|r| !r.path_template.contains('?')));
}

#[test]
fn the_connection_cap_answers_503_without_unbounded_queueing() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        std::thread::sleep(Duration::from_millis(800));
        let _ =
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    });
    let mut gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    gw.gateway.max_connections = 2;
    // Restart the server thread with the lowered cap.
    gw.stop();
    let listener = api_tracker_gateway::server::Listener::bind(0).unwrap();
    let port = listener.port();
    let mut gateway = gw.gateway.clone();
    gateway.port = port;
    gateway.max_connections = 2;
    gateway.shutdown.store(false, Ordering::Relaxed);
    let g2 = gateway.clone();
    let handle = std::thread::spawn(move || api_tracker_gateway::server::serve(g2, listener));

    let auth = format!("127.0.0.1:{port}");
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        send(
            &mut c,
            &format!("GET /openai/x HTTP/1.1\r\nHost: {auth}\r\nConnection: close\r\n\r\n"),
        );
        held.push(c);
    }
    std::thread::sleep(Duration::from_millis(200));
    let mut over = TcpStream::connect(("127.0.0.1", port)).unwrap();
    over.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let resp = String::from_utf8_lossy(&read_to_close(&mut over)).to_string();
    assert!(
        resp.starts_with("HTTP/1.1 503"),
        "over-cap connections get an immediate 503, got {resp:?}"
    );

    // After the in-flight ones finish, the cap releases.
    for mut c in held {
        let _ = read_to_close(&mut c);
    }
    std::thread::sleep(Duration::from_millis(200));
    let mut again = TcpStream::connect(("127.0.0.1", port)).unwrap();
    again
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    send(
        &mut again,
        &format!("GET /openai/x HTTP/1.1\r\nHost: {auth}\r\nConnection: close\r\n\r\n"),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut again)).to_string();
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "cap must release: {resp:?}"
    );

    gateway.shutdown.store(true, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn a_slowloris_head_is_dropped_at_the_deadline() {
    let up = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    c.set_read_timeout(Some(Duration::from_secs(40))).unwrap();
    c.write_all(b"GET /openai/x HTTP/1.1\r\n").unwrap();
    c.flush().unwrap();
    let start = Instant::now();
    // Dribble a header byte at a time, forever — the absolute deadline must
    // end it regardless of per-read activity.
    let mut ended = false;
    for _ in 0..200 {
        if c.write_all(b"X").is_err() || c.flush().is_err() {
            ended = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
        if start.elapsed() > Duration::from_secs(30) {
            break;
        }
    }
    let mut buf = [0u8; 64];
    let read = c.read(&mut buf);
    ended |=
        matches!(read, Ok(0)) || read.is_err() || String::from_utf8_lossy(&buf).contains("400");
    assert!(ended, "a dribbling head must be dropped at the deadline");
    assert!(start.elapsed() < Duration::from_secs(35));
    assert_eq!(up.request_count(), 0);
}

// ---------------------------------------------------------------------------
// Named TEST_PLAN items the adversarial re-review found had no shipped test
// ---------------------------------------------------------------------------

#[test]
fn a_non_100_interim_is_relayed_not_mistaken_for_the_final_response() {
    // 103 Early Hints during the Expect window. Treating it as final would
    // silently drop the request body and hand the client an informational
    // status as its answer.
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n");
        let _ = sock.flush();
        std::thread::sleep(Duration::from_millis(30));
        let _ = sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        let _ = sock.flush();
        let mut body = vec![0u8; 5];
        let _ = sock.read_exact(&mut body);
        requests.lock().unwrap().push(body);
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "POST /openai/v1/files HTTP/1.1\r\nHost: {}\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
            gw.authority()
        ),
    );
    // The 103 arrives first and is relayed as an interim.
    let early = read_n(&mut c, 26);
    assert!(
        early.starts_with(b"HTTP/1.1 103"),
        "the 103 must be relayed to the client: {:?}",
        String::from_utf8_lossy(&early)
    );
    c.write_all(b"hello").unwrap();
    c.flush().unwrap();
    let rest = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        rest.contains("HTTP/1.1 200 OK") && rest.ends_with("done"),
        "the real final response must follow, got {rest:?}"
    );
    let seen = up.requests.lock().unwrap().clone();
    assert_eq!(seen[1], b"hello", "the request body must still be sent");
    let r = &gw.wait_records(1)[0];
    assert_eq!(
        r.status_code,
        Some(200),
        "103 must not be recorded as the answer"
    );
    assert_eq!(r.request_bytes, Some(5));
}

#[test]
fn an_upstream_close_between_requests_is_redialed_without_disturbing_the_client() {
    // Upstream teardown mismatch (TEST_PLAN §1): the provider hangs up
    // between two keep-alive requests. The client connection must survive
    // and the second request must reach a freshly dialed socket.
    let connections = Arc::new(Mutex::new(0usize));
    let counter = connections.clone();
    let up = MockUpstream::start(move |sock, requests| {
        *counter.lock().unwrap() += 1;
        let head = read_head(sock);
        if head.is_empty() {
            return;
        }
        requests.lock().unwrap().push(head);
        // Answer once, then hang up WITHOUT saying Connection: close, so the
        // gateway believes the socket is reusable and must discover it is not.
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = sock.flush();
        std::thread::sleep(Duration::from_millis(50));
        let _ = sock.shutdown(std::net::Shutdown::Both);
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/a HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    assert!(read_response(&mut c).ends_with("ok"));
    // Let the upstream's close land before the second request.
    std::thread::sleep(Duration::from_millis(200));
    send(
        &mut c,
        &format!(
            "GET /openai/v1/b HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            gw.authority()
        ),
    );
    let second = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        second.starts_with("HTTP/1.1 200 OK"),
        "an upstream close must never tear down a kept-alive client: {second:?}"
    );
    assert_eq!(
        *connections.lock().unwrap(),
        2,
        "the dead upstream must be redialed, not reused"
    );
    assert_eq!(gw.wait_records(2).len(), 2);
}

#[test]
fn a_mid_chunk_upstream_eof_is_terminal_and_recorded_as_truncated() {
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        // Declares a 100-byte chunk, sends 4 bytes, then vanishes.
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\nshor");
        let _ = sock.flush();
        let _ = sock.shutdown(std::net::Shutdown::Both);
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/x HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(
        !resp.contains("tethra-gateway:"),
        "no synthetic body may be injected into a started provider stream"
    );
    let r = &gw.wait_records(1)[0];
    assert_eq!(r.completion, Completion::Truncated);
}

#[test]
fn a_304_response_carries_no_body_and_keeps_the_connection_usable() {
    let up = MockUpstream::start(|sock, requests| loop {
        let head = read_head(sock);
        if head.is_empty() {
            return;
        }
        requests.lock().unwrap().push(head);
        let _ = sock
            .write_all(b"HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\nContent-Length: 99\r\n\r\n");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/x HTTP/1.1\r\nHost: {}\r\nIf-None-Match: \"abc\"\r\n\r\n",
            gw.authority()
        ),
    );
    // Read only the head. `read_response` would honor the upstream's bogus
    // `Content-Length: 99` and block on a body that (correctly) never
    // arrives, turning this test into a 20 s read-timeout wait that loaded
    // CI runners can exceed (it failed exactly that way on the PR #15 merge
    // commit). Body absence is proven deterministically below instead: any
    // wrongly-relayed body byte would sit in the stream ahead of the second
    // response and corrupt its status line.
    let resp = String::from_utf8_lossy(&read_head(&mut c)).to_string();
    assert!(resp.starts_with("HTTP/1.1 304"), "got: {resp:?}");
    assert!(resp.contains("ETag: \"abc\""));
    assert!(resp.ends_with("\r\n\r\n"), "head terminated: {resp:?}");
    assert!(resp.contains("Connection: keep-alive"));
    // The connection really is still usable — and the stream position is
    // exactly at the end of the 304 head (no body bytes were relayed).
    send(
        &mut c,
        &format!(
            "GET /openai/v1/y HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            gw.authority()
        ),
    );
    let second = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        second.starts_with("HTTP/1.1 304"),
        "a relayed 304 body byte would corrupt this parse: {second:?}"
    );
}

#[test]
fn the_reserved_prefix_namespace_is_never_routable() {
    // `p` and `_tethra` are reserved (the link form and the probe path), so
    // a route can never shadow them and a request for them 404s.
    let up = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    for path in ["/_tethra/nonce", "/_tethra", "/p/x/y"] {
        let mut c = gw.connect();
        send(
            &mut c,
            &format!("GET {path} HTTP/1.1\r\nHost: {}\r\n\r\n", gw.authority()),
        );
        let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
        assert!(resp.starts_with("HTTP/1.1 404"), "{path} => {resp:?}");
    }
    assert_eq!(up.request_count(), 0);
}

#[test]
fn an_unknown_route_performs_no_dns_and_opens_no_socket() {
    // A gateway with a route whose "origin" is an unroutable port: if an
    // unknown prefix caused any connection attempt, this test would see it.
    let up = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let before = up.request_count();
    for path in [
        "/unknown/v1/x",
        "/openai2/x",
        "/p/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/openai/x",
    ] {
        let mut c = gw.connect();
        send(
            &mut c,
            &format!("GET {path} HTTP/1.1\r\nHost: {}\r\n\r\n", gw.authority()),
        );
        let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
        assert!(resp.starts_with("HTTP/1.1 404"));
    }
    assert_eq!(
        up.request_count(),
        before,
        "nothing may be dialed for a 404"
    );
    assert!(
        gw.sink.records().is_empty(),
        "a 404 writes no observation row"
    );
}

#[test]
fn a_query_containing_a_url_is_forwarded_not_refused_as_absolute_form() {
    // Absolute-form detection must look at the PATH, not the whole target:
    // `?callback=https://...` is an ordinary origin-form request.
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ =
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/x?callback=https://example.com/cb HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    let resp = read_response(&mut c);
    assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp:?}");
    assert!(up
        .first_request()
        .starts_with("GET /v1/x?callback=https://example.com/cb HTTP/1.1"));
    // And the query is still absent from the stored template.
    let r = &gw.wait_records(1)[0];
    assert_eq!(r.path_template, "/v1/x");
}

#[test]
fn an_idle_keep_alive_connection_closes_silently_without_a_spurious_400() {
    // A client that opens a connection, sends one request, then goes quiet
    // must not be answered with a 400 for a request it never made.
    let up = MockUpstream::start(|sock, requests| loop {
        let head = read_head(sock);
        if head.is_empty() {
            return;
        }
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/x HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    assert!(read_response(&mut c).ends_with("ok"));
    // Now go quiet and close from our side; the gateway must not have queued
    // a 400 for us.
    c.set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let mut buf = [0u8; 256];
    let extra = match c.read(&mut buf) {
        Ok(0) => Vec::new(),
        Ok(n) => buf[..n].to_vec(),
        Err(_) => Vec::new(),
    };
    assert!(
        extra.is_empty(),
        "an idle connection must receive nothing, got {:?}",
        String::from_utf8_lossy(&extra)
    );
}

#[test]
fn slow_streams_do_not_accumulate_and_a_multi_megabyte_body_relays_intact() {
    // Backpressure: the blocking copy loop is the bound. A 8 MiB body must
    // arrive intact through a fixed 16 KiB relay buffer.
    const SIZE: usize = 8 * 1024 * 1024;
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        requests.lock().unwrap().push(head);
        let _ = sock.write_all(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {SIZE}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        let chunk = vec![b'z'; 64 * 1024];
        let mut sent = 0;
        while sent < SIZE {
            if sock.write_all(&chunk).is_err() {
                return;
            }
            sent += chunk.len();
        }
        let _ = sock.flush();
    });
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/big HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    // Read slowly, in small reads, to exercise backpressure.
    let mut total = 0usize;
    let mut buf = [0u8; 4096];
    let mut head_done = false;
    loop {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !head_done {
                    head_done = true;
                    // Subtract the head from the first read.
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    if let Some(i) = text.find("\r\n\r\n") {
                        total += n - (i + 4);
                        continue;
                    }
                }
                total += n;
            }
            Err(_) => break,
        }
    }
    assert_eq!(total, SIZE, "the whole body must relay intact");
    let r = &gw.wait_records(1)[0];
    assert_eq!(r.response_bytes, Some(SIZE as i64));
    assert_eq!(r.completion, Completion::Completed);
}

// ---------------------------------------------------------------------------
// Listener-identity probe (`/_tethra/probe`, ADR 0019 D11)
// ---------------------------------------------------------------------------

#[test]
fn probe_answers_a_challenge_only_this_data_dirs_nonce_can_verify() {
    use api_tracker_gateway::control;

    let dir = tempfile::tempdir().unwrap();
    let nonce = control::write_nonce(dir.path()).unwrap();
    let gw = RunningGateway::start(direct_route_state(vec![]));
    gw.gateway
        .set_probe_key(Some(control::probe_key_from_nonce(&nonce)));

    // The high-level verifier: reads the 0600 nonce file, sends a random
    // challenge, checks the proof.
    match control::verify_listener(dir.path(), gw.port) {
        control::ListenerIdentity::Verified { version } => {
            assert_eq!(version, env!("CARGO_PKG_VERSION"));
        }
        other => panic!("expected Verified, got {other:?}"),
    }

    // A DIFFERENT data directory's nonce must not verify this listener —
    // that is exactly the port-squatter/stale-port diagnosis.
    let foreign = tempfile::tempdir().unwrap();
    control::write_nonce(foreign.path()).unwrap();
    assert_eq!(
        control::verify_listener(foreign.path(), gw.port),
        control::ListenerIdentity::NotOurs
    );

    // No listener at all is its own verdict.
    let unused_port = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        l.local_addr().unwrap().port()
    };
    assert_eq!(
        control::verify_listener(dir.path(), unused_port),
        control::ListenerIdentity::NoListener
    );

    // Probes are diagnostics, not traffic: no observation records.
    std::thread::sleep(Duration::from_millis(100));
    assert!(gw.sink.records().is_empty(), "probes must not be recorded");
}

#[test]
fn probe_rejects_bad_methods_and_hides_the_rest_of_the_reserved_namespace() {
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", 1, "")]));
    gw.gateway.set_probe_key(Some([7u8; 32]));

    // Non-GET is refused.
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "POST /_tethra/probe?c=aabb HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n",
            gw.authority()
        ),
    );
    assert!(read_response(&mut c).starts_with("HTTP/1.1 405 "));

    // A missing or malformed challenge is a 400.
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /_tethra/probe HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    assert!(read_response(&mut c).starts_with("HTTP/1.1 400 "));

    // Every OTHER path under the reserved namespace answers byte-identically
    // to an unknown route, so the namespace is not enumerable.
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /_tethra/other HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    let reserved = read_response(&mut c);
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /no-such-route/x HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    let unknown = read_response(&mut c);
    assert_eq!(reserved, unknown);

    // A browser-shaped probe is refused by the gate that runs FIRST: the
    // reserved namespace grants no exception to the browser policy.
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /_tethra/probe?c=aabb HTTP/1.1\r\nHost: {}\r\nOrigin: http://evil.example\r\n\r\n",
            gw.authority()
        ),
    );
    assert!(read_response(&mut c).starts_with("HTTP/1.1 403 "));
}

#[test]
fn probe_without_a_wired_key_says_unavailable_rather_than_lying() {
    let gw = RunningGateway::start(direct_route_state(vec![]));
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /_tethra/probe?c=aabbccdd HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    let resp = read_response(&mut c);
    assert!(resp.starts_with("HTTP/1.1 200 "));
    assert!(resp.contains("proof: unavailable"), "{resp}");
}

/// Ambiguous encodings of a traversal are rejected explicitly rather than
/// forwarded and left to the provider to interpret.
///
/// The audit found `..%2f` passed the gate: the segment is neither exactly
/// `..` nor contains `%2e`. It could not cross origins — the upstream origin
/// is bound to the registered route and never derived from the path — but the
/// documented reason for that safety was the traversal parser, which was
/// wrong. Both are now true: the parser rejects these, AND origin binding is
/// what actually prevents crossing.
#[test]
fn ambiguous_encoded_traversals_are_rejected_before_forwarding() {
    let up = MockUpstream::start(canned(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        0,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));

    for path in [
        "/openai/..%2fadmin",       // encoded slash after literal dots
        "/openai/..%2Fadmin",       // uppercase spelling
        "/openai/..%5cadmin",       // encoded backslash
        "/openai/%2e%2e/admin",     // fully encoded dots (already rejected)
        "/openai/%252e%252e/admin", // double-encoded
        "/openai/a..b/%2fadmin",    // dot-run inside a longer segment
    ] {
        let mut c = gw.connect();
        send(
            &mut c,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                gw.authority()
            ),
        );
        let text = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
        assert!(
            text.starts_with("HTTP/1.1 400 "),
            "{path} must be rejected locally, got: {text}"
        );
    }
    assert_eq!(
        up.request_count(),
        0,
        "no ambiguous traversal may reach the upstream at all"
    );

    // A legitimate provider path with percent-encoding that is NOT a
    // separator or dot still works — the gate must not break real traffic.
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models/gpt%2D4o HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            gw.authority()
        ),
    );
    let ok = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(
        ok.starts_with("HTTP/1.1 200 "),
        "an ordinary encoded character must still forward, got: {ok}"
    );
    assert_eq!(up.request_count(), 1);
    assert!(up.first_request().contains("/v1/models/gpt%2D4o"));
}
