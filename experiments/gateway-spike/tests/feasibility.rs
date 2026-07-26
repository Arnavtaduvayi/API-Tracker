//! Feasibility evidence for the Local Gateway architecture phase.
//!
//! Each test answers one question from docs/gateway/HANDOFF_PHASE_1.md.
//! Mock upstreams are plain-TCP loopback servers; the forwarder is
//! transport-generic, and production upstream TLS reuses the already-shipped
//! rustls client path in crates/observe.

use gateway_spike::{
    forward_once, framing_is_forwardable, validate_route_origin, Attribution, FingerprintMatcher,
    SseUsageExtractor,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Read from `r` until the connection closes, recording (elapsed, chunk) pairs.
fn read_all_timed(r: &mut TcpStream, start: Instant) -> Vec<(Duration, Vec<u8>)> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.push((start.elapsed(), buf[..n].to_vec())),
            Err(_) => break,
        }
    }
    out
}

/// Spawn a gateway thread that accepts ONE client connection, connects to
/// `upstream_addr`, and forwards one exchange with an SSE usage extractor
/// attached. Returns (gateway_addr, join handle yielding the extractor).
fn spawn_gateway(
    upstream_addr: std::net::SocketAddr,
    route: &'static str,
    upstream_host: &'static str,
) -> (
    std::net::SocketAddr,
    std::thread::JoinHandle<SseUsageExtractor>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        let mut upstream = TcpStream::connect(upstream_addr).unwrap();
        let mut extractor = SseUsageExtractor::new(128 * 1024);
        {
            let mut tap = |bytes: &[u8]| extractor.feed(bytes);
            forward_once(&mut client, &mut upstream, route, upstream_host, &mut tap).unwrap();
        }
        extractor
    });
    (addr, handle)
}

/// Q1 + Q5: SSE streams incrementally through the blocking relay (events reach
/// the client while the upstream is still producing), and the bounded
/// extractor pulls model + token usage out of the stream in flight.
#[test]
fn sse_streams_incrementally_and_usage_extracts() {
    // Mock upstream: close-delimited SSE (no Content-Length, Connection: close).
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_thread = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        // Consume the ENTIRE request (head + the 2-byte body) so closing the
        // socket later yields a clean FIN, not an RST for unread data.
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = s.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
            if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                if got.len() >= i + 4 + 2 {
                    break;
                }
            }
        }
        let head = String::from_utf8_lossy(&got).to_string();
        s.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        s.flush().unwrap();
        let events: [&[u8]; 4] = [
            b"data: {\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n",
            b"data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n",
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":34,\"total_tokens\":46}}\n\n",
            b"data: [DONE]\n\n",
        ];
        for e in events {
            s.write_all(e).unwrap();
            s.flush().unwrap();
            std::thread::sleep(Duration::from_millis(120));
        }
        head
    });

    let (gw_addr, gw) = spawn_gateway(upstream_addr, "openai", "mock.upstream");
    let start = Instant::now();
    let mut client = TcpStream::connect(gw_addr).unwrap();
    client
        .write_all(
            b"POST /openai/v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nAuthorization: Bearer FAKE-TEST-NOT-A-REAL-KEY\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .unwrap();
    let chunks = read_all_timed(&mut client, start);
    let upstream_head = upstream_thread.join().unwrap();
    let extractor = gw.join().unwrap();

    // The head was rewritten: route prefix stripped, Host replaced.
    assert!(
        upstream_head.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"),
        "prefix must be stripped: {upstream_head}"
    );
    assert!(upstream_head.contains("Host: mock.upstream\r\n"));
    assert!(upstream_head.contains("Authorization: Bearer FAKE-TEST-NOT-A-REAL-KEY"));

    // Streaming: the first event must arrive well before the last was even
    // sent (total send span >= 3*120ms). A buffering forwarder would deliver
    // everything at once at the end.
    let body_bytes: Vec<u8> = chunks.iter().flat_map(|(_, b)| b.clone()).collect();
    let body_text = String::from_utf8_lossy(&body_bytes);
    let first_event_at = chunks
        .iter()
        .find(|(_, b)| b.windows(6).any(|w| w == b"data: "))
        .map(|(t, _)| *t)
        .expect("client received SSE events");
    let last_at = chunks.last().map(|(t, _)| *t).unwrap();
    assert!(
        last_at - first_event_at >= Duration::from_millis(200),
        "events must arrive spread over time (streamed), got first at {first_event_at:?}, last at {last_at:?}"
    );
    assert!(body_text.contains("data: [DONE]"));

    // In-flight bounded extraction saw the model and the usage event.
    assert_eq!(extractor.model.as_deref(), Some("gpt-4o-mini"));
    assert_eq!(extractor.input_tokens, Some(12));
    assert_eq!(extractor.output_tokens, Some(34));
}

/// Q2: provider error statuses, headers, and bodies are preserved verbatim,
/// including chunked framing echoed byte-for-byte.
#[test]
fn provider_errors_headers_and_chunked_framing_preserved() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let raw_response = b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nRetry-After: 7\r\nx-request-id: req_abc123\r\nTransfer-Encoding: chunked\r\n\r\n1a\r\n{\"error\":\"rate_limited\"}\r\n\r\n0\r\n\r\n";
    let upstream_thread = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        let mut head = vec![0u8; 4096];
        let _ = s.read(&mut head).unwrap();
        s.write_all(raw_response).unwrap();
        s.flush().unwrap();
    });

    let (gw_addr, gw) = spawn_gateway(upstream_addr, "anthropic", "mock.upstream");
    let mut client = TcpStream::connect(gw_addr).unwrap();
    client
        .write_all(b"GET /anthropic/v1/models HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n\r\n")
        .unwrap();
    let start = Instant::now();
    let chunks = read_all_timed(&mut client, start);
    upstream_thread.join().unwrap();
    let _ = gw.join().unwrap();

    let received: Vec<u8> = chunks.into_iter().flat_map(|(_, b)| b).collect();
    assert_eq!(
        received.as_slice(),
        raw_response.as_slice(),
        "status line, headers, and chunked body must relay verbatim"
    );
}

/// Q3: request bodies stream upstream as the client produces them; the
/// gateway does not wait for the full body before forwarding.
#[test]
fn request_body_streams_upstream_incrementally() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_thread = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        let start = Instant::now();
        let mut arrivals: Vec<Duration> = Vec::new();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        // Read until the terminal chunk arrives.
        loop {
            let n = s.read(&mut buf).unwrap();
            arrivals.push(start.elapsed());
            got.extend_from_slice(&buf[..n]);
            if got.windows(7).any(|w| w == b"0\r\n\r\n\r\n") || got.ends_with(b"0\r\n\r\n") {
                break;
            }
        }
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        (arrivals, got)
    });

    let (gw_addr, gw) = spawn_gateway(upstream_addr, "openai", "mock.upstream");
    let mut client = TcpStream::connect(gw_addr).unwrap();
    client
        .write_all(b"POST /openai/v1/audio HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nTransfer-Encoding: chunked\r\n\r\n")
        .unwrap();
    client.flush().unwrap();
    std::thread::sleep(Duration::from_millis(30));
    client.write_all(b"5\r\nhello\r\n").unwrap();
    client.flush().unwrap();
    std::thread::sleep(Duration::from_millis(180));
    client.write_all(b"6\r\n world\r\n0\r\n\r\n").unwrap();
    client.flush().unwrap();

    let start = Instant::now();
    let _ = read_all_timed(&mut client, start);
    let (arrivals, got) = upstream_thread.join().unwrap();
    let _ = gw.join().unwrap();

    assert!(
        got.ends_with(b"0\r\n\r\n"),
        "upstream saw the full chunked body"
    );
    let span = *arrivals.last().unwrap() - arrivals[0];
    assert!(
        span >= Duration::from_millis(120),
        "body bytes must arrive incrementally (span {span:?}), not in one buffered flush"
    );
}

/// Q4: `Expect: 100-continue` — the interim response is read from upstream and
/// relayed to the client BEFORE the request body is relayed, on a plain 1:1
/// connection mapping.
#[test]
fn expect_100_continue_interim_relayed() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_thread = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        // Read only the head, then send the interim response.
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        s.flush().unwrap();
        // Now the body should arrive.
        let mut body = vec![0u8; 5];
        s.read_exact(&mut body).unwrap();
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone")
            .unwrap();
        body
    });

    let (gw_addr, gw) = spawn_gateway(upstream_addr, "openai", "mock.upstream");
    let mut client = TcpStream::connect(gw_addr).unwrap();
    client
        .write_all(b"POST /openai/v1/files HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
        .unwrap();
    client.flush().unwrap();
    // Wait for the interim response before sending the body (per RFC 9110).
    let mut interim = vec![0u8; 25];
    client.read_exact(&mut interim).unwrap();
    assert!(
        interim.starts_with(b"HTTP/1.1 100 Continue"),
        "client must receive the relayed interim response, got {:?}",
        String::from_utf8_lossy(&interim)
    );
    client.write_all(b"hello").unwrap();
    client.flush().unwrap();
    let start = Instant::now();
    let rest = read_all_timed(&mut client, start);
    let body = upstream_thread.join().unwrap();
    let _ = gw.join().unwrap();

    assert_eq!(body, b"hello");
    let received: Vec<u8> = rest.into_iter().flat_map(|(_, b)| b).collect();
    assert!(String::from_utf8_lossy(&received).starts_with("HTTP/1.1 200 OK"));
}

/// Q7 (route snapshot / vault independence): the entire forward path above ran
/// with no database, no vault, and no key material — by construction. This
/// test additionally proves the observation hand-off NEVER blocks forwarding:
/// a full bounded queue drops (and counts) instead of applying backpressure.
#[test]
fn observation_queue_never_blocks_forwarding() {
    let (tx, rx) = mpsc::sync_channel::<[u8; 1024]>(8);
    let consumer = std::thread::spawn(move || {
        let mut received = 0u64;
        for _ in rx.iter() {
            received += 1;
            std::thread::sleep(Duration::from_millis(1));
        }
        received
    });

    let mut dropped = 0u64;
    let mut sent = 0u64;
    let start = Instant::now();
    for _ in 0..1_000 {
        match tx.try_send([0u8; 1024]) {
            Ok(()) => sent += 1,
            Err(mpsc::TrySendError::Full(_)) => dropped += 1,
            Err(mpsc::TrySendError::Disconnected(_)) => unreachable!(),
        }
    }
    let elapsed = start.elapsed();
    drop(tx);
    let received = consumer.join().unwrap();

    assert_eq!(sent + dropped, 1_000);
    assert!(dropped > 0, "the slow consumer must force drops");
    assert_eq!(received, sent, "everything accepted is eventually written");
    assert!(
        elapsed < Duration::from_millis(200),
        "try_send must never block the forwarding path (took {elapsed:?})"
    );
}

/// Q8: credential attribution with ONLY the vault's keyed fingerprint key —
/// all five states, exact agreement with core's fingerprint construction, and
/// key zeroization on clear.
#[test]
fn fingerprint_attribution_states_match_core() {
    use api_tracker_core::secret::{SecretBytes, SecretString};

    let key = [7u8; 32];
    let val_a = "FAKE-TEST-NOT-A-REAL-KEY-AAAA";
    let val_b = "FAKE-TEST-NOT-A-REAL-KEY-BBBB";
    let val_c = "FAKE-TEST-NOT-A-REAL-KEY-CCCC";

    // Cross-check: the spike's hash must equal core's reuse::fingerprint.
    let core_fp = api_tracker_core::reuse::fingerprint(
        &SecretBytes::new(key.to_vec()),
        &SecretString::from(val_a),
    )
    .unwrap();
    let spike_fp = blake3::keyed_hash(&key, val_a.trim().as_bytes());
    assert_eq!(core_fp, spike_fp.as_bytes().to_vec());

    let fp = |v: &str| {
        blake3::keyed_hash(&key, v.trim().as_bytes())
            .as_bytes()
            .to_vec()
    };
    let table = vec![
        (fp(val_a), "cred-a".to_string()),
        (fp(val_b), "cred-b1".to_string()),
        (fp(val_b), "cred-b2".to_string()), // same value stored twice
    ];

    let mut m = FingerprintMatcher::with_key(key, table.clone());
    assert_eq!(
        m.attribute(Some(val_a)),
        Attribution::Matched("cred-a".into())
    );
    assert_eq!(
        m.attribute(Some(&format!("{val_a}  \n"))),
        Attribution::Matched("cred-a".into()),
        "trimming must match core's semantics"
    );
    assert_eq!(
        m.attribute(Some(val_b)),
        Attribution::AmbiguousDuplicate(vec!["cred-b1".into(), "cred-b2".into()])
    );
    assert_eq!(m.attribute(Some(val_c)), Attribution::Unmatched);
    assert_eq!(m.attribute(None), Attribution::NoCredentialPresent);

    // The header case the review flagged: `Authorization: Bearer <key>` must
    // match a fingerprint stored over the bare `<key>`. A raw hash of the whole
    // header value would report Unmatched (a false "shadow credential" alarm).
    assert_eq!(
        m.attribute(Some(&format!("Bearer {val_a}"))),
        Attribution::Matched("cred-a".into()),
        "the Bearer scheme token must be stripped before hashing"
    );
    assert_eq!(
        m.attribute(Some(&format!("bearer   {val_a}"))),
        Attribution::Matched("cred-a".into()),
        "scheme match is case-insensitive and tolerates OWS"
    );

    // Monitoring disabled / gateway stopping: the key is dropped (zeroized by
    // the Zeroizing wrapper) and attribution degrades honestly.
    m.clear_key();
    assert_eq!(
        m.attribute(Some(val_a)),
        Attribution::UnavailableVaultLocked
    );
}

/// Retires the review's `no-response-head-carryover` BLOCKER: when an upstream
/// coalesces `100 Continue` and the final response into ONE TCP segment, the
/// seedable response-head reader must not lose the final head (which would hang
/// the exchange). The mock writes both heads in a single `write_all` and does
/// NOT pause, unlike the original 100-continue mock.
#[test]
fn coalesced_100_continue_does_not_hang() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_thread = std::thread::spawn(move || {
        let (mut s, _) = upstream.accept().unwrap();
        // Read the head (up to the terminator) then the 5-byte body.
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        // Coalesce the interim AND the final response into ONE write, BEFORE
        // reading the body — the exact packet shape that dropped the final head.
        s.write_all(
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone",
        )
        .unwrap();
        s.flush().unwrap();
        let mut body = vec![0u8; 5];
        s.read_exact(&mut body).unwrap();
        body
    });

    let (gw_addr, gw) = spawn_gateway(upstream_addr, "openai", "mock.upstream");
    let mut client = TcpStream::connect(gw_addr).unwrap();
    client
        .write_all(b"POST /openai/v1/files HTTP/1.1\r\nHost: 127.0.0.1:8787\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
        .unwrap();
    client.flush().unwrap();
    // Receive the interim, send the body, then read the final response.
    let mut interim = vec![0u8; 25];
    client.read_exact(&mut interim).unwrap();
    assert!(interim.starts_with(b"HTTP/1.1 100 Continue"));
    client.write_all(b"hello").unwrap();
    client.flush().unwrap();
    let start = Instant::now();
    let rest = read_all_timed(&mut client, start);
    let body = upstream_thread.join().unwrap();
    let _ = gw.join().unwrap();

    assert_eq!(body, b"hello");
    let received: Vec<u8> = rest.into_iter().flat_map(|(_, b)| b).collect();
    assert!(
        String::from_utf8_lossy(&received).starts_with("HTTP/1.1 200 OK"),
        "the coalesced final response must reach the client, got {:?}",
        String::from_utf8_lossy(&received)
    );
    assert!(String::from_utf8_lossy(&received).ends_with("done"));
}

/// Retires the review's request-smuggling findings: the framing validator
/// rejects CL+TE, duplicate/malformed Content-Length, non-chunked TE, and
/// bare-LF line endings (bare-LF header injection), and accepts well-formed
/// heads. The production gateway calls this BEFORE forwarding and regenerates
/// framing headers from the validated result.
#[test]
fn framing_validator_rejects_smuggling_shapes() {
    // Well-formed heads pass.
    assert!(framing_is_forwardable(
        b"POST /openai/v1/x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n"
    ));
    assert!(framing_is_forwardable(
        b"POST /openai/v1/x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
    ));
    assert!(framing_is_forwardable(
        b"GET /openai/v1/x HTTP/1.1\r\nHost: h\r\n\r\n"
    ));

    // Every smuggling shape is rejected.
    for bad in [
        &b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
            [..],
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5, 5\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: +5\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0x10\r\n\r\n",
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        // Bare-LF header injection: httparse tolerates it; we must not.
        b"POST /x HTTP/1.1\nHost: h\nX-Evil: 1\n\n",
    ] {
        assert!(
            !framing_is_forwardable(bad),
            "must reject: {:?}",
            String::from_utf8_lossy(bad)
        );
    }
}

/// Q9: the route registry validation rejects every unsafe upstream shape using
/// the already-shipped observe SSRF policy.
#[test]
fn route_validation_blocks_unsafe_origins() {
    assert!(validate_route_origin("https://api.openai.com").is_ok());
    assert!(validate_route_origin("https://api.anthropic.com:443").is_ok());
    assert!(validate_route_origin("https://myref.supabase.co").is_ok());

    for bad in [
        "http://api.openai.com",            // not https
        "https://api.openai.com:8443",      // non-443 port
        "https://127.0.0.1",                // loopback
        "https://[::1]",                    // v6 loopback
        "https://10.0.0.5",                 // RFC1918
        "https://169.254.169.254",          // link-local / metadata IP
        "https://metadata.google.internal", // metadata name
        "https://api.openai.com/v1",        // path not allowed
        "https://",                         // empty host
    ] {
        assert!(
            validate_route_origin(bad).is_err(),
            "{bad} must be rejected"
        );
    }
}

/// Bounded-memory proof for the extractor: a pathological multi-megabyte SSE
/// event is discarded (counted) without ever holding more than the cap, and a
/// later well-formed usage event still parses.
#[test]
fn sse_extractor_is_bounded_under_pathological_input() {
    let cap = 128 * 1024;
    let mut ex = SseUsageExtractor::new(cap);
    // One 10 MiB line, fed in 64 KiB pieces.
    let piece = vec![b'x'; 64 * 1024];
    ex.feed(b"data: ");
    for _ in 0..160 {
        ex.feed(&piece);
    }
    ex.feed(b"\n\n");
    assert_eq!(ex.dropped_events(), 1, "oversized event must be dropped");
    assert!(ex.bound() <= 2 * cap);

    ex.feed(b"data: {\"model\":\"claude-sonnet-4-5\",\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":9}}\n\n");
    assert_eq!(ex.model.as_deref(), Some("claude-sonnet-4-5"));
    assert_eq!(ex.input_tokens, Some(3));
    assert_eq!(ex.output_tokens, Some(9));
}

/// Documented current behavior (hardening item for the production crate):
/// wire.rs resolves a head carrying BOTH Transfer-Encoding: chunked and
/// Content-Length in favor of chunked. RFC 9112 §6.3 requires a proxy to
/// treat this as an error or strip Content-Length; the production gateway
/// will REJECT such requests outright (request-smuggling defence). This test
/// pins today's behavior so the hardening delta is explicit.
#[test]
fn wire_prefers_chunked_when_both_present_hardening_needed() {
    use api_tracker_observe::wire;
    let raw = b"POST /openai/v1/x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut c = std::io::Cursor::new(raw.to_vec());
    let (head, _, _) = wire::read_request_head(&mut c).unwrap();
    assert_eq!(head.body_framing(), wire::BodyFraming::Chunked);
    assert_eq!(head.content_length, Some(5));
    // Both fields are visible to the caller, so the gateway CAN and WILL
    // reject the combination before forwarding.
    assert!(head.chunked);
}
