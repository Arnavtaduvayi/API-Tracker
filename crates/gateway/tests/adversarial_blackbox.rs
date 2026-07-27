//! Black-box adversarial battery: 16 wire-level attack categories.
//!
//! ORIGIN: written by the independent final reviewer of `feat/local-gateway`
//! (audit branch `audit/lg-final-independent-20260726`, proposal commit
//! 17ef76a), deliberately WITHOUT reading the shipped assertions first, so it
//! is not a paraphrase of the implementation's own tests. Adopted here
//! unchanged in substance during audit remediation so the coverage survives
//! on the branch rather than only in a review artifact.
//!
//! Every case sends raw bytes at a live gateway and asserts on the wire
//! response and on what the synthetic upstream actually received.
//!
//! The rule for every assertion below: it must FAIL if the gateway is
//! vulnerable. "It did not crash" is never an assertion.
//!
//! Categories: absolute-form open relay, CONNECT, authority-form,
//! protocol-relative targets, foreign Host authorities, prefix and encoding
//! confusion, request smuggling (19 shapes), CRLF injection, redirect
//! following, oversized request heads, header floods, Slowloris, connection
//! limits, truncated upstream responses, missing upstream responses, browser
//! drive-by behavior, cookie stripping, and cross-route credential isolation
//! over keep-alive.
//!
//! Do not weaken these to keep CI green. If one starts failing, the gateway
//! changed, not the test.

mod common;

use common::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const FAKE: &str = "sk-proj-FAKE-AUDIT-0000000000000000000000000000";

/// A gateway with one route to a synthetic upstream that echoes 200 and
/// records what it saw. `n` = how many connections the upstream will serve.
fn gw_with_upstream(n: usize) -> (RunningGateway, MockUpstream) {
    let up = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 0));
    let port = up.port;
    let gw = RunningGateway::start(direct_route_state(vec![
        ("openai", "openai", port, ""),
        ("anthropic", "anthropic", port, ""),
    ]));
    let _ = n;
    (gw, up)
}

fn status_of(resp: &str) -> u16 {
    resp.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Send a raw request, read whatever comes back (possibly nothing).
fn probe(gw: &RunningGateway, raw: &str) -> String {
    let mut c = gw.connect();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = c.write_all(raw.as_bytes());
    let _ = c.flush();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > 65536 {
                    break;
                }
                if out.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

// ---------------------------------------------------------------------------
// Open relay / proxy-shape refusal
// ---------------------------------------------------------------------------

#[test]
fn audit_absolute_form_and_connect_never_reach_an_upstream() {
    let (gw, up) = gw_with_upstream(4);
    let auth = gw.authority();

    let cases = [
        // Absolute-form target: the classic open-proxy request.
        format!("GET http://evil.example.com/steal HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        format!("GET https://api.openai.com/v1/models HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        // Absolute-form naming a REGISTERED origin — the subtle variant.
        format!("POST http://127.0.0.1:1/openai/v1/x HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        // CONNECT tunnel.
        format!("CONNECT evil.example.com:443 HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        // Authority-form without CONNECT.
        format!("GET evil.example.com:443 HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        // Protocol-relative target.
        format!("GET //evil.example.com/x HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
    ];

    for raw in &cases {
        let resp = probe(&gw, raw);
        let st = status_of(&resp);
        assert!(
            st == 0 || (400..=599).contains(&st),
            "proxy-shaped request was not refused: {raw:?} -> {resp:?}"
        );
        assert!(
            !resp.contains("\r\n\r\nok"),
            "a proxy-shaped request was FORWARDED: {raw:?} -> {resp:?}"
        );
    }

    // The decisive assertion: the upstream received nothing at all.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        up.request_count(),
        0,
        "an open-relay shape reached the upstream: {:?}",
        up.first_request()
    );
}

// ---------------------------------------------------------------------------
// Host-header gate
// ---------------------------------------------------------------------------

#[test]
fn audit_host_header_override_is_refused_and_never_selects_the_upstream() {
    let (gw, up) = gw_with_upstream(8);
    let port = gw.port;

    // Every one of these is a FOREIGN authority: none may be accepted.
    // (Values that merely carry surrounding OWS are excluded on purpose —
    // RFC 9110 strips trailing OWS, so accepting them after a trim is correct
    // and is verified separately below.)
    let bad_hosts = [
        "evil.example.com".to_string(),
        format!("evil.example.com:{port}"),
        format!("localhost.evil.example.com:{port}"),
        format!("127.0.0.1.evil.example.com:{port}"),
        format!("evil.example.com:{port}@127.0.0.1:{port}"),
        "127.0.0.1".to_string(),           // no port
        "localhost".to_string(),           // no port
        format!("127.0.0.1:{}", port + 1), // wrong port
        format!("127.0.0.2:{port}"),       // loopback range but not ours
        format!("[::1]:{}", port + 1),
        String::new(), // empty
    ];

    for h in &bad_hosts {
        let raw = format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {h}\r\nAuthorization: Bearer {FAKE}\r\n\r\n"
        );
        let resp = probe(&gw, &raw);
        assert!(
            !resp.contains("\r\n\r\nok"),
            "foreign Host {h:?} was accepted and forwarded: {resp:?}"
        );
    }

    // Duplicate Host is a desync primitive and must be refused outright.
    let dup = format!(
        "GET /openai/v1/models HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nHost: evil.example.com\r\n\r\n"
    );
    let resp = probe(&gw, &dup);
    assert!(
        !resp.contains("\r\n\r\nok"),
        "duplicate Host was accepted: {resp:?}"
    );

    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        up.request_count(),
        0,
        "a foreign/duplicate Host reached the upstream"
    );
}

// ---------------------------------------------------------------------------
// Path-prefix and encoded-path confusion
// ---------------------------------------------------------------------------

#[test]
fn audit_prefix_and_encoding_confusion_cannot_reach_or_escape_a_route() {
    let (gw, up) = gw_with_upstream(16);
    let auth = gw.authority();

    // Shapes that must NOT match route "openai" at all.
    let must_not_match = [
        "/openai2/v1/models",
        "/openaiX",
        "/openai-v2/x",
        "/OPENAI/v1/models",   // case: route ids are lowercase
        "/%6fpenai/v1/models", // percent-encoded 'o'
        "/openai%2fv1/models", // encoded slash inside the first segment
        "//openai/v1/models",  // empty first segment
        "/./openai/v1/models",
        "/openai/../anthropic/v1/x",
        "/openai/%2e%2e/anthropic/v1/x",
        "/p/deadbeef/openai/v1/models", // unknown slug
        "/",
        "",
    ];

    let mut statuses = Vec::new();
    for p in &must_not_match {
        let raw =
            format!("GET {p} HTTP/1.1\r\nHost: {auth}\r\nAuthorization: Bearer {FAKE}\r\n\r\n");
        let resp = probe(&gw, &raw);
        assert!(
            !resp.contains("\r\n\r\nok"),
            "path {p:?} was routed and forwarded: {resp:?}"
        );
        statuses.push((p, status_of(&resp)));
    }

    // Unknown prefix and unknown slug must be INDISTINGUISHABLE (SI-4): a page
    // must not be able to enumerate which providers/projects are configured.
    let unknown_prefix = probe(
        &gw,
        &format!("GET /nosuchroute/v1/x HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
    );
    let unknown_slug = probe(
        &gw,
        &format!(
            "GET /p/00000000000000000000000000000000/openai/v1/x HTTP/1.1\r\nHost: {auth}\r\n\r\n"
        ),
    );
    assert_eq!(
        status_of(&unknown_prefix),
        status_of(&unknown_slug),
        "unknown prefix and unknown slug return different statuses:\n{unknown_prefix:?}\n{unknown_slug:?}"
    );
    assert_eq!(
        unknown_prefix, unknown_slug,
        "unknown prefix and unknown slug are byte-distinguishable (an enumeration oracle):\n{unknown_prefix:?}\n{unknown_slug:?}"
    );

    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        up.request_count(),
        0,
        "a confusion shape reached the upstream: {:?} (statuses: {statuses:?})",
        up.first_request()
    );
}

/// AUDIT FINDING (characterisation, not an exploit).
///
/// Encoded-slash traversal (`..%2f`): REJECTED at the gate, and — the
/// property that actually matters — unable to cross origins even if it were
/// not.
///
/// As originally written by the auditor this was a CHARACTERISATION test: it
/// pinned that `path_is_safe` did NOT catch this shape (`"..%2fanthropic"` is
/// one segment, is not equal to `".."`, and contains no `%2e`), while noting
/// that the request still could not reach another route's origin because the
/// upstream is bound to the route and never derived from the path. It closed
/// by saying rejection "is the stricter and preferable outcome; update this
/// characterisation test".
///
/// Remediation took that option: the gate now rejects `%2f`, `%5c`, `%25`,
/// and any segment containing a `..` run. Both facts are asserted here, and
/// they are independent — the origin-binding property is what prevents
/// crossing, and it is checked separately so a future relaxation of the gate
/// cannot silently take the real defense with it.
#[test]
fn audit_encoded_slash_traversal_is_rejected_and_cannot_cross_origins() {
    let up_a = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 0));
    let up_b = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 0));
    let (pa, pb) = (up_a.port, up_b.port);
    let gw = RunningGateway::start(direct_route_state(vec![
        ("openai", "openai", pa, ""),
        ("anthropic", "anthropic", pb, ""),
    ]));
    let auth = gw.authority();

    let resp = probe(
        &gw,
        &format!("GET /openai/..%2fanthropic/v1/x HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
    );
    std::thread::sleep(Duration::from_millis(300));

    // Fact 1: the gate rejects it locally.
    assert_eq!(
        status_of(&resp),
        400,
        "an ambiguous encoded traversal must be rejected before forwarding"
    );
    // Fact 2 (independent of Fact 1): it reached NEITHER upstream. Crossing
    // origins is prevented by route-bound origins, not by the parser — so
    // this must keep holding even if the gate is ever relaxed.
    assert_eq!(
        up_b.request_count(),
        0,
        "an encoded-slash traversal CROSSED ORIGINS into another route: {:?}",
        up_b.first_request()
    );
    assert_eq!(
        up_a.request_count(),
        0,
        "a rejected request must not be forwarded to its own route either"
    );
}

/// The origin-binding property on its own, with a shape the gate ALLOWS.
///
/// This is the assertion that carries the real security claim: whatever the
/// path says, the upstream comes from the registered route. Kept separate
/// from the traversal test above so tightening or loosening the parser can
/// never be mistaken for changing this.
#[test]
fn audit_a_path_naming_another_route_still_reaches_only_its_own_origin() {
    let up_a = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 0));
    let up_b = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 0));
    let (pa, pb) = (up_a.port, up_b.port);
    let gw = RunningGateway::start(direct_route_state(vec![
        ("openai", "openai", pa, ""),
        ("anthropic", "anthropic", pb, ""),
    ]));
    let auth = gw.authority();

    // A perfectly ordinary path that merely MENTIONS the other route.
    let resp = probe(
        &gw,
        &format!("GET /openai/anthropic/v1/messages HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
    );
    std::thread::sleep(Duration::from_millis(300));

    assert_eq!(status_of(&resp), 200);
    assert_eq!(
        up_b.request_count(),
        0,
        "the path must never select the upstream"
    );
    assert_eq!(up_a.request_count(), 1);
    let seen = up_a.first_request();
    assert!(
        seen.starts_with("GET /anthropic/v1/messages "),
        "the tail is forwarded verbatim to the ROUTE's origin: {seen:?}"
    );
}

// ---------------------------------------------------------------------------
// Request smuggling: framing ambiguity must be REJECTED, not normalized
// ---------------------------------------------------------------------------

#[test]
fn audit_every_smuggling_shape_is_rejected_and_nothing_is_forwarded() {
    let (gw, up) = gw_with_upstream(32);
    let auth = gw.authority();

    let smuggles: Vec<(&str, String)> = vec![
        (
            "TE+CL together",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /anthropic/v1/y HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        ),
        (
            "duplicate conflicting CL",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 6\r\nContent-Length: 5\r\n\r\nAAAAAA"),
        ),
        (
            "duplicate identical CL",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 6\r\nContent-Length: 6\r\n\r\nAAAAAA"),
        ),
        (
            "CL list form \"5, 5\"",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 5, 5\r\n\r\nAAAAA"),
        ),
        (
            "CL with plus sign",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: +5\r\n\r\nAAAAA"),
        ),
        (
            "CL hex",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 0x10\r\n\r\nAAAAA"),
        ),
        (
            "CL with trailing junk",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 5abc\r\n\r\nAAAAA"),
        ),
        (
            "CL negative",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: -1\r\n\r\n"),
        ),
        (
            "TE not final coding",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n"),
        ),
        (
            "TE duplicated header",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        ),
        (
            "TE unknown coding",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n"),
        ),
        (
            "TE obfuscated name (space before colon)",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nTransfer-Encoding : chunked\r\nContent-Length: 5\r\n\r\nAAAAA"),
        ),
        (
            "bare-LF request line",
            format!("POST /openai/v1/x HTTP/1.1\nHost: {auth}\nContent-Length: 5\n\nAAAAA"),
        ),
        (
            "bare-LF header terminator only",
            format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Length: 5\n\r\nAAAAA"),
        ),
        (
            "bare-CR inside a header value",
            format!("GET /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nX-Audit: a\rb\r\n\r\n"),
        ),
        (
            "NUL inside a header value",
            format!("GET /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nX-Audit: a\0b\r\n\r\n"),
        ),
        (
            "obs-fold continuation line",
            format!("GET /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nX-Audit: a\r\n\tb\r\n\r\n"),
        ),
        (
            "HTTP/1.0 client (cannot frame a chunked response)",
            format!("GET /openai/v1/x HTTP/1.0\r\nHost: {auth}\r\n\r\n"),
        ),
        (
            "upgrade / websocket",
            format!("GET /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
        ),
    ];

    for (name, raw) in &smuggles {
        let resp = probe(&gw, raw);
        assert!(
            !resp.contains("\r\n\r\nok"),
            "smuggling shape {name:?} was FORWARDED to the upstream: {resp:?}"
        );
        let st = status_of(&resp);
        assert!(
            st == 0 || (400..=599).contains(&st),
            "smuggling shape {name:?} got a success status {st}: {resp:?}"
        );
    }

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        up.request_count(),
        0,
        "a smuggling shape reached the upstream: {:?}",
        up.first_request()
    );
}

/// The smuggled second request must not appear on the upstream connection even
/// if the first is somehow accepted: assert on the bytes the upstream saw.
#[test]
fn audit_a_smuggled_second_request_never_appears_upstream() {
    let (gw, up) = gw_with_upstream(4);
    let auth = gw.authority();
    let raw = format!(
        "POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\n\
         Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n\
         0\r\n\r\nGET /anthropic/v1/SMUGGLED HTTP/1.1\r\nHost: {auth}\r\n\r\n"
    );
    let _ = probe(&gw, &raw);
    std::thread::sleep(Duration::from_millis(300));
    for req in 0..up.request_count() {
        let _ = req;
    }
    if up.request_count() > 0 {
        let seen = up.first_request();
        assert!(
            !seen.contains("SMUGGLED"),
            "the smuggled request reached the upstream: {seen:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Header injection / CRLF into the rebuilt head
// ---------------------------------------------------------------------------

#[test]
fn audit_crlf_in_path_or_header_cannot_inject_a_header_upstream() {
    let (gw, up) = gw_with_upstream(4);
    let auth = gw.authority();

    // Encoded CRLF in the path: if the gateway ever percent-decodes before
    // rebuilding the head, this injects a header upstream.
    let cases = [
        format!("GET /openai/v1/x%0d%0aX-Injected:%20yes HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        format!("GET /openai/v1/x%0aX-Injected:%20yes HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
        format!(
            "GET /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nX-Try: v%0d%0aX-Injected: yes\r\n\r\n"
        ),
    ];
    for raw in &cases {
        let _ = probe(&gw, raw);
    }
    std::thread::sleep(Duration::from_millis(300));
    let seen = up.first_request();
    // The injection succeeds only if `X-Injected` appears as its own HEADER
    // LINE. Appearing inside the still-percent-encoded request target is the
    // CORRECT outcome: the gateway must not percent-decode before rebuilding.
    let lower = seen.to_ascii_lowercase();
    assert!(
        !lower.contains("\r\nx-injected"),
        "a header was injected into the upstream head: {seen:?}"
    );
    // And confirm the mechanism: the target was forwarded still-encoded.
    if !seen.is_empty() {
        assert!(
            seen.contains("%0d%0a") || seen.contains("%0a") || !seen.contains("X-Injected"),
            "the gateway appears to have percent-decoded the request target: {seen:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Redirects must be relayed, never followed
// ---------------------------------------------------------------------------

#[test]
fn audit_a_redirect_to_an_unregistered_origin_is_relayed_never_followed() {
    let up = MockUpstream::start(canned(
        b"HTTP/1.1 302 Found\r\nLocation: https://evil.example.com/harvest\r\nContent-Length: 0\r\n\r\n",
        0,
    ));
    let port = up.port;
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", port, "")]));
    let auth = gw.authority();

    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {auth}\r\nAuthorization: Bearer {FAKE}\r\n\r\n"
        ),
    );
    let resp = read_response(&mut c);
    assert_eq!(
        status_of(&resp),
        302,
        "the redirect was not relayed verbatim: {resp:?}"
    );
    assert!(
        resp.contains("evil.example.com"),
        "the Location header was not relayed: {resp:?}"
    );
    // Exactly ONE upstream exchange: following the redirect would be a second.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        up.request_count(),
        1,
        "the gateway appears to have FOLLOWED the redirect"
    );
}

// ---------------------------------------------------------------------------
// Bounds: oversized head, too many headers, Slowloris, connection cap
// ---------------------------------------------------------------------------

#[test]
fn audit_oversized_head_and_header_flood_are_bounded() {
    let (gw, up) = gw_with_upstream(4);
    let auth = gw.authority();

    // A head far past any sane bound.
    let big = "x".repeat(200_000);
    let raw = format!("GET /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nX-Big: {big}\r\n\r\n");
    let resp = probe(&gw, &raw);
    assert!(
        !resp.contains("\r\n\r\nok"),
        "a 200 KiB head was forwarded: {resp:?}"
    );

    // 500 headers.
    let mut flood = format!("GET /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\n");
    for i in 0..500 {
        flood.push_str(&format!("X-H{i}: v\r\n"));
    }
    flood.push_str("\r\n");
    let resp = probe(&gw, &flood);
    assert!(
        !resp.contains("\r\n\r\nok"),
        "a 500-header request was forwarded: {resp:?}"
    );

    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(up.request_count(), 0, "an oversized head reached upstream");
}

#[test]
fn audit_slowloris_is_dropped_within_the_documented_deadline() {
    let (gw, _up) = gw_with_upstream(2);
    let auth = gw.authority();
    let mut c = gw.connect();
    c.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    // Send a partial head and then dribble one byte every 500 ms, forever.
    let _ = c.write_all(format!("GET /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\n").as_bytes());
    let _ = c.flush();
    let start = Instant::now();
    let mut dropped = false;
    for _ in 0..120 {
        if c.write_all(b"X").is_err() || c.flush().is_err() {
            dropped = true;
            break;
        }
        let mut buf = [0u8; 64];
        match c.read(&mut buf) {
            Ok(0) => {
                dropped = true;
                break;
            }
            Ok(_) => {
                dropped = true;
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => {
                dropped = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
        if start.elapsed() > Duration::from_secs(45) {
            break;
        }
    }
    assert!(
        dropped,
        "a Slowloris connection was still alive after {:?} — no head deadline fired",
        start.elapsed()
    );
}

#[test]
fn audit_connection_cap_answers_503_and_never_grows_unbounded() {
    let (gw, _up) = gw_with_upstream(1);
    // Hold many idle connections open. The documented cap is 128.
    let mut held = Vec::new();
    for _ in 0..200 {
        match TcpStream::connect(("127.0.0.1", gw.port)) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(Duration::from_millis(400)));
                held.push(s)
            }
            Err(_) => break,
        }
    }
    // At least one connection past the cap must be told 503 (or closed),
    // rather than silently queued forever.
    let mut over_cap_refused = 0;
    for s in held.iter_mut().skip(130) {
        let mut buf = [0u8; 256];
        match s.read(&mut buf) {
            Ok(0) => over_cap_refused += 1,
            Ok(n) => {
                let t = String::from_utf8_lossy(&buf[..n]).to_string();
                if t.contains("503") {
                    over_cap_refused += 1;
                }
            }
            Err(_) => {}
        }
    }
    assert!(
        over_cap_refused > 0,
        "no connection past the documented 128 cap was refused with 503 or closed"
    );
    drop(held);
}

// ---------------------------------------------------------------------------
// Provider misbehaviour: partial response, mid-stream disconnect
// ---------------------------------------------------------------------------

#[test]
fn audit_a_truncated_upstream_body_is_terminal_and_never_reported_as_success() {
    // Declares 100 bytes, sends 10, then closes.
    let up = MockUpstream::start(|sock: &mut TcpStream, reqs| {
        let head = read_head(sock);
        reqs.lock().unwrap().push(head);
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789");
        let _ = sock.flush();
        // Close without sending the remaining 90 bytes.
    });
    let port = up.port;
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", port, "")]));
    let auth = gw.authority();

    let mut c = gw.connect();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    send(
        &mut c,
        &format!("GET /openai/v1/models HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
    );
    let got = read_to_close(&mut c);
    let text = String::from_utf8_lossy(&got).to_string();

    // The client must NOT be able to mistake a truncated body for a complete
    // one: the connection must be closed (not kept alive for a next request).
    if let Some(i) = text.find("\r\n\r\n") {
        let body = &text[i + 4..];
        assert!(
            body.len() < 100,
            "the gateway invented body bytes the upstream never sent"
        );
    }
    // And the recorded outcome must not be a clean success.
    let recs = gw.wait_records(1);
    assert!(!recs.is_empty(), "a truncated exchange was never recorded");
    let r = &recs[0];
    assert!(
        r.completion != api_tracker_gateway::record::Completion::Completed,
        "a truncated upstream body was recorded as a COMPLETE exchange: {r:?}"
    );
}

#[test]
fn audit_upstream_closing_before_any_byte_yields_502_not_a_silent_drop() {
    let up = MockUpstream::start(|sock: &mut TcpStream, reqs| {
        let head = read_head(sock);
        reqs.lock().unwrap().push(head);
        // Close immediately, sending nothing.
        let _ = sock.shutdown(std::net::Shutdown::Both);
    });
    let port = up.port;
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", port, "")]));
    let auth = gw.authority();
    let mut c = gw.connect();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    send(
        &mut c,
        &format!("GET /openai/v1/models HTTP/1.1\r\nHost: {auth}\r\n\r\n"),
    );
    let got = read_to_close(&mut c);
    let text = String::from_utf8_lossy(&got).to_string();
    assert!(
        text.starts_with("HTTP/1.1 502"),
        "an upstream that closed before responding did not produce a 502: {text:?}"
    );
}

// ---------------------------------------------------------------------------
// Browser drive-by
// ---------------------------------------------------------------------------

#[test]
fn audit_browser_shaped_requests_are_refused_and_leave_no_observation_row() {
    let (gw, up) = gw_with_upstream(8);
    let auth = gw.authority();

    let browser_shapes = [
        format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nOrigin: https://evil.example.com\r\nContent-Length: 2\r\n\r\n{{}}"),
        format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nReferer: https://evil.example.com/\r\nContent-Length: 2\r\n\r\n{{}}"),
        format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nSec-Fetch-Mode: no-cors\r\nContent-Length: 2\r\n\r\n{{}}"),
        format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nSec-Fetch-Site: cross-site\r\nContent-Length: 2\r\n\r\n{{}}"),
        // The CORS-simple write primitive: text/plain POST, no credential.
        format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}"),
        format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Type: text/plain;charset=UTF-8\r\nContent-Length: 2\r\n\r\n{{}}"),
        format!("POST /openai/v1/x HTTP/1.1\r\nHost: {auth}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 2\r\n\r\n{{}}"),
    ];

    for raw in &browser_shapes {
        let resp = probe(&gw, raw);
        assert!(
            !resp.contains("\r\n\r\nok"),
            "a browser-shaped request was forwarded: {raw:?} -> {resp:?}"
        );
    }

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        up.request_count(),
        0,
        "a browser-shaped request reached the upstream"
    );
    // SI-4: rejected browser requests write NO observation row.
    assert!(
        gw.sink.records().is_empty(),
        "a rejected browser request produced an observation row: {:?}",
        gw.sink.records()
    );
}

// ---------------------------------------------------------------------------
// Cookies must not cross in either direction
// ---------------------------------------------------------------------------

#[test]
fn audit_cookies_are_stripped_in_both_directions() {
    let up = MockUpstream::start(canned(
        b"HTTP/1.1 200 OK\r\nSet-Cookie: sess=abc; Path=/\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 2\r\n\r\nok",
        0,
    ));
    let port = up.port;
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", port, "")]));
    let auth = gw.authority();
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {auth}\r\n\
             Authorization: Bearer {FAKE}\r\nCookie: other_app_session=SECRETCOOKIE\r\n\r\n"
        ),
    );
    let resp = read_response(&mut c);
    assert!(
        !resp.to_ascii_lowercase().contains("set-cookie"),
        "Set-Cookie was relayed to the client: {resp:?}"
    );
    assert!(
        !resp.to_ascii_lowercase().contains("access-control-"),
        "Access-Control-* was relayed to the client (loopback becomes browser-readable): {resp:?}"
    );
    std::thread::sleep(Duration::from_millis(200));
    let seen = up.first_request();
    assert!(
        !seen.to_ascii_lowercase().contains("cookie:"),
        "the client Cookie header was forwarded upstream: {seen:?}"
    );
    assert!(
        seen.contains(FAKE),
        "the caller's own credential was NOT passed through (pass-through is the design): {seen:?}"
    );
}

// ---------------------------------------------------------------------------
// Cross-route credential isolation — the highest-severity property
// ---------------------------------------------------------------------------

#[test]
fn audit_two_routes_on_one_keepalive_connection_never_share_an_upstream_socket() {
    // Two DISTINCT upstreams, each recording what it received.
    let up_a = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 0));
    let up_b = MockUpstream::start(canned(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 0));
    let (pa, pb) = (up_a.port, up_b.port);
    let gw = RunningGateway::start(direct_route_state(vec![
        ("openai", "openai", pa, ""),
        ("anthropic", "anthropic", pb, ""),
    ]));
    let auth = gw.authority();

    let key_a = "sk-proj-FAKE-OPENAI-KEY-AAAAAAAAAAAAAAAAAAAAAA";
    let key_b = "sk-ant-FAKE-ANTHROPIC-KEY-BBBBBBBBBBBBBBBBBBBB";

    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {auth}\r\nAuthorization: Bearer {key_a}\r\n\r\n"
        ),
    );
    let r1 = read_response(&mut c);
    assert_eq!(status_of(&r1), 200, "first request failed: {r1:?}");

    // Same client connection, different provider route.
    send(
        &mut c,
        &format!(
            "GET /anthropic/v1/messages HTTP/1.1\r\nHost: {auth}\r\nx-api-key: {key_b}\r\n\r\n"
        ),
    );
    let r2 = read_response(&mut c);
    assert_eq!(status_of(&r2), 200, "second request failed: {r2:?}");

    std::thread::sleep(Duration::from_millis(300));
    let a_saw = up_a.first_request();
    let b_saw = up_b.first_request();

    assert!(
        !a_saw.contains(key_b),
        "the ANTHROPIC key was written into the OPENAI upstream connection: {a_saw:?}"
    );
    assert!(
        !b_saw.contains(key_a),
        "the OPENAI key was written into the ANTHROPIC upstream connection: {b_saw:?}"
    );
    assert!(a_saw.contains(key_a), "openai upstream: {a_saw:?}");
    assert!(b_saw.contains(key_b), "anthropic upstream: {b_saw:?}");
}
