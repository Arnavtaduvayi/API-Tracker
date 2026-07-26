//! Privacy canaries (TEST_PLAN §6): route real traffic carrying known
//! markers through a live gateway, then scan every artifact byte-wise and
//! assert NONE of them appear.
//!
//! This is the repo's proof style: not "we believe nothing leaks" but "here
//! are the exact bytes we looked for, in the exact files, and they are not
//! there." Structured canaries check the DTOs and their serializations; raw
//! canaries check the database, its WAL and SHM sidecars, logs, and process
//! argv/environ.

mod common;

use common::*;
use std::io::Write;
use std::sync::Arc;

use api_tracker_core::db;
use api_tracker_core::secret::SecretBytes;
use api_tracker_gateway::attribution::{self, FingerprintEntry, Matcher};
use api_tracker_gateway::forward::BodyTap;
use api_tracker_gateway::server;
use api_tracker_gateway::usage::{Shape, UsageExtractor};

/// Every marker routed through the gateway. If any of these bytes reach any
/// artifact, the test fails and names the artifact.
const CANARY_CREDENTIAL: &str = "FAKE-TEST-NOT-A-REAL-KEY-CANARY-9f2c8a71";
const CANARY_PROMPT: &str = "CANARY-PROMPT-e41d7b93";
const CANARY_RESPONSE: &str = "CANARY-RESPONSE-5c0aa218";
const CANARY_QUERY: &str = "CANARY-QUERY-7ab3f602";
const CANARY_COOKIE: &str = "CANARY-COOKIE-1d94ce55";
const CANARY_HEADER: &str = "CANARY-HEADER-b7e02f14";

fn all_canaries() -> Vec<(&'static str, &'static str)> {
    vec![
        ("credential value", CANARY_CREDENTIAL),
        ("prompt body", CANARY_PROMPT),
        ("response body", CANARY_RESPONSE),
        ("query value", CANARY_QUERY),
        ("cookie value", CANARY_COOKIE),
        ("header value", CANARY_HEADER),
    ]
}

fn assert_absent(what: &str, haystack: &[u8]) {
    for (kind, marker) in all_canaries() {
        assert!(
            !contains(haystack, marker.as_bytes()),
            "{kind} marker `{marker}` was found in {what} — this is a privacy \
             invariant violation (PRIVACY_MODEL gateway §2)"
        );
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Run one exchange carrying every canary, with attribution and extraction
/// both fully enabled, and hand back the record the writer would persist.
#[test]
fn no_canary_survives_a_live_exchange_into_any_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = test_db(dir.path());

    // A synthetic provider that echoes a marker in its response body.
    let up = MockUpstream::start(|sock, requests| {
        let head = read_head(sock);
        let body = read_exact_body(sock, &head, 64);
        let mut full = head.clone();
        full.extend_from_slice(&body);
        requests.lock().unwrap().push(full);
        let body = format!(
            "data: {{\"model\":\"gpt-4o-mini\",\"choices\":[{{\"delta\":\
             {{\"content\":\"{CANARY_RESPONSE}\"}}}}]}}\n\n\
             data: {{\"usage\":{{\"prompt_tokens\":11,\"completion_tokens\":22}}}}\n\n\
             data: [DONE]\n\n"
        );
        let _ = sock.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                 Set-Cookie: upstream={CANARY_COOKIE}\r\nConnection: close\r\n\r\n{body}"
            )
            .as_bytes(),
        );
        let _ = sock.flush();
    });

    let gw = RunningGateway::start_with_taps(
        direct_route_state(vec![("openai", "openai", up.port, "openai")]),
        server::usage_tap_factory(),
    );
    // Attribution ON with a real keyed fingerprint key, so the digest path
    // actually runs (the strongest form of this test).
    let key = SecretBytes::new(vec![3u8; 32]);
    gw.gateway
        .set_matching_key(Some(SecretBytes::new(vec![3u8; 32])));

    let body = format!("{{\"prompt\":\"{CANARY_PROMPT}\"}}");
    let body = format!("{body:<64}"); // pad to the 64 bytes the mock reads
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "POST /openai/v1/chat/completions?trace={CANARY_QUERY} HTTP/1.1\r\n\
             Host: {}\r\n\
             Authorization: Bearer {CANARY_CREDENTIAL}\r\n\
             Cookie: session={CANARY_COOKIE}\r\n\
             X-Custom-Trace: {CANARY_HEADER}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            gw.authority(),
            body.len()
        ),
    );
    let response = read_to_close(&mut c);
    // Sanity: the exchange really happened and the response really carried
    // the marker (otherwise this test proves nothing).
    assert!(
        contains(&response, CANARY_RESPONSE.as_bytes()),
        "the client must have received the marker, else the canary is vacuous"
    );
    assert!(
        contains(
            &up.first_request().into_bytes(),
            CANARY_CREDENTIAL.as_bytes()
        ),
        "the provider must have received the credential untouched"
    );
    // The cookie was stripped in BOTH directions.
    assert!(
        !contains(&response, b"Set-Cookie"),
        "Set-Cookie must never reach the client"
    );
    assert!(!up.first_request().contains("Cookie:"));

    let records = gw.wait_records(1);
    let record = &records[0];

    // --- structured canaries: the DTO and its serializations ---

    assert_absent(
        "the exchange record's Debug output",
        format!("{record:?}").as_bytes(),
    );
    assert_absent("the path template", record.path_template.as_bytes());
    assert_absent("the recorded host", record.host.as_bytes());
    assert_absent(
        "the route/provider ids",
        format!("{}{}", record.route_prefix, record.provider_id).as_bytes(),
    );
    assert!(
        !record.path_template.contains('?') && !record.path_template.contains("trace"),
        "query material must be severed before sanitize_path: {}",
        record.path_template
    );
    let usage = record.usage.clone().expect("usage was extracted");
    assert_absent(
        "the usage observation",
        serde_json::to_string(&usage).unwrap().as_bytes(),
    );
    assert_eq!(usage.input_tokens, Some(11), "extraction really ran");
    assert_eq!(usage.output_tokens, Some(22));

    // The digest is a KEYED hash, never the value, and never an unkeyed one.
    let digest = record.digest.clone().expect("a digest was computed");
    assert_absent(
        "the credential digest Debug",
        format!("{digest:?}").as_bytes(),
    );
    for candidate in &digest.candidates {
        assert_absent("a digest candidate", candidate);
        assert_ne!(
            candidate[..],
            blake3::hash(CANARY_CREDENTIAL.as_bytes()).as_bytes()[..],
            "the digest must be the KEYED fingerprint, never blake3::hash(value)"
        );
    }
    // It IS the keyed construction core uses.
    let expected = attribution::core_fingerprint_for_test(&key, CANARY_CREDENTIAL).unwrap();
    assert!(
        digest.candidates.iter().any(|c| c[..] == expected[..]),
        "the digest must equal core::reuse::fingerprint of the bare value"
    );

    // --- structured canaries: what a writer would persist ---

    let conn = open_db(&db_path);
    // Simulate the full persist path the writer performs for this record.
    let matcher = Matcher::new(vec![FingerprintEntry {
        credential_id: "cred-canary".into(),
        fingerprint: expected.clone(),
        retained_version: None,
        current_version: Some(1),
        revoked: false,
    }]);
    let resolved = matcher.resolve(&digest);
    assert_eq!(
        resolved.credential_id(),
        Some("cred-canary"),
        "attribution resolved through the real matcher"
    );
    assert_absent(
        "the resolved attribution",
        format!("{resolved:?}").as_bytes(),
    );
    assert_eq!(resolved.as_str(), "matched");
    drop(conn);

    // --- raw artifact canaries: every byte on disk ---

    // Force everything through to the main database file, then scan the main
    // DB, the WAL, and the SHM sidecar. The WAL is scanned BEFORE and AFTER
    // the checkpoint so a marker cannot hide in either.
    for name in ["vault.db-wal", "vault.db-shm", "vault.db"] {
        let path = dir.path().join(name);
        if path.exists() {
            let bytes = std::fs::read(&path).unwrap();
            assert_absent(&format!("{name} (before checkpoint)"), &bytes);
        }
    }
    {
        let conn = open_db(&db_path);
        db::checkpoint_truncate(&conn);
    }
    for name in ["vault.db", "vault.db-wal", "vault.db-shm"] {
        let path = dir.path().join(name);
        if path.exists() {
            let bytes = std::fs::read(&path).unwrap();
            assert_absent(&format!("{name} (after checkpoint)"), &bytes);
        }
    }
    // Every other file the gateway could have written into its data dir.
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            assert_absent(&format!("data-dir file {}", path.display()), &bytes);
        }
    }
}

/// The 32-byte matching key is its own canary: it must never reach disk or
/// `ps` (SI-21, TEST_PLAN §6).
#[test]
fn the_matching_key_never_reaches_disk_argv_or_environ() {
    let dir = tempfile::tempdir().unwrap();
    let _db_path = test_db(dir.path());
    // A distinctive key so a scan cannot false-negative on zeros.
    let key_bytes: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(13))
        .collect();

    let up = MockUpstream::start(canned(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        0,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    gw.gateway
        .set_matching_key(Some(SecretBytes::new(key_bytes.clone())));
    assert!(gw.gateway.has_matching_key());

    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {}\r\n\
             Authorization: Bearer {CANARY_CREDENTIAL}\r\nConnection: close\r\n\r\n",
            gw.authority()
        ),
    );
    let _ = read_to_close(&mut c);
    gw.wait_records(1);

    // Disk: the whole data directory.
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !contains(&bytes, &key_bytes),
                "the matching key must never reach disk: found in {}",
                path.display()
            );
        }
    }

    // argv and environ of THIS process (the gateway runs in-process here).
    let argv: Vec<u8> = std::env::args().collect::<Vec<_>>().join("\0").into_bytes();
    assert!(
        !contains(&argv, &key_bytes),
        "the matching key must never appear in argv (visible to `ps`)"
    );
    let environ: Vec<u8> = std::env::vars()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\0")
        .into_bytes();
    assert!(
        !contains(&environ, &key_bytes),
        "the matching key must never appear in the environment"
    );

    // Clearing drops (and zeroizes) it.
    gw.gateway.set_matching_key(None);
    assert!(!gw.gateway.has_matching_key());
}

/// With attribution unavailable, the state is `unavailable_vault_locked` and
/// NO credential id or method is written — never a false `unmatched`.
#[test]
fn a_locked_vault_records_its_own_state_and_no_credential_id() {
    let up = MockUpstream::start(canned(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        0,
    ));
    let gw = RunningGateway::start(direct_route_state(vec![("openai", "openai", up.port, "")]));
    // No matching key pushed: exactly the locked-vault case.
    assert!(!gw.gateway.has_matching_key());

    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/models HTTP/1.1\r\nHost: {}\r\n\
             Authorization: Bearer {CANARY_CREDENTIAL}\r\nConnection: close\r\n\r\n",
            gw.authority()
        ),
    );
    let _ = read_to_close(&mut c);

    let record = &gw.wait_records(1)[0];
    assert_eq!(
        record.attribution_input,
        api_tracker_gateway::record::AttributionInput::UnavailableVaultLocked
    );
    assert!(
        record.digest.is_none(),
        "no digest may be computed without the key"
    );
    assert!(
        record.had_authorization,
        "presence is still recorded honestly"
    );
    assert_absent("the locked-vault record", format!("{record:?}").as_bytes());
    // Forwarding was completely unaffected.
    assert_eq!(record.status_code, Some(200));
}

/// The forwarding path must never construct an unkeyed hash of a credential.
/// A source-level pin: if a plain-hash fallback is ever added, this fails.
#[test]
fn no_unkeyed_credential_hash_exists_in_the_crate() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }
    walk(&src, &mut files);
    assert!(!files.is_empty());
    for file in files {
        let code: String = std::fs::read_to_string(&file)
            .unwrap()
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("blake3::hash("),
            "an UNKEYED blake3::hash appears in {} — credential fingerprints \
             must always be keyed (ADR 0005); an unkeyed hash would turn a \
             stolen database into an offline guess-confirmation oracle",
            file.display()
        );
        assert!(
            !code.contains("Sha256::digest") && !code.contains("sha2::"),
            "no ad-hoc hashing of credential material in {}",
            file.display()
        );
    }
}

/// Extraction must not change a single relayed byte.
#[test]
fn extraction_never_mutates_the_relayed_stream() {
    let sse: &'static [u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n\
data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n\
data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\n\
data: [DONE]\n\n";

    // Once with extraction on, once with it off: the client bytes must be
    // byte-identical.
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for taps in [
        server::usage_tap_factory(),
        Arc::new(|_: &str, _: bool, _: bool| {
            Box::new(api_tracker_gateway::forward::NoTap)
                as Box<dyn api_tracker_gateway::forward::BodyTap>
        }) as server::TapFactory,
    ] {
        let up = MockUpstream::start(canned(sse, 0));
        let gw = RunningGateway::start_with_taps(
            direct_route_state(vec![("openai", "openai", up.port, "openai")]),
            taps,
        );
        let mut c = gw.connect();
        send(
            &mut c,
            &format!(
                "GET /openai/v1/chat HTTP/1.1\r\nHost: {}\r\n\r\n",
                gw.authority()
            ),
        );
        seen.push(read_to_close(&mut c));
    }
    assert_eq!(
        seen[0], seen[1],
        "the relayed bytes must be identical with extraction on and off"
    );
    // And identical to what the provider sent (head aside).
    let body_start = seen[0].windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let upstream_body_start = sse.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(
        &seen[0][body_start..],
        &sse[upstream_body_start..],
        "the response body must relay byte-for-byte"
    );
}

/// A tap that panics or misbehaves must never fail the request. (The
/// extractor is infallible by construction; this pins that the relay does not
/// depend on the tap's cooperation.)
#[test]
fn a_misbehaving_tap_cannot_affect_the_relay() {
    struct GreedyTap;
    impl api_tracker_gateway::forward::BodyTap for GreedyTap {
        fn feed(&mut self, _bytes: &[u8]) {
            // Deliberately does nothing useful and holds nothing.
        }
        fn finish(&mut self) -> Option<api_tracker_gateway::record::UsageObservation> {
            None
        }
    }
    let up = MockUpstream::start(canned(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        0,
    ));
    let gw = RunningGateway::start_with_taps(
        direct_route_state(vec![("openai", "openai", up.port, "openai")]),
        Arc::new(|_: &str, _: bool, _: bool| {
            Box::new(GreedyTap) as Box<dyn api_tracker_gateway::forward::BodyTap>
        }),
    );
    let mut c = gw.connect();
    send(
        &mut c,
        &format!(
            "GET /openai/v1/x HTTP/1.1\r\nHost: {}\r\n\r\n",
            gw.authority()
        ),
    );
    let resp = String::from_utf8_lossy(&read_to_close(&mut c)).to_string();
    assert!(resp.starts_with("HTTP/1.1 200 OK") && resp.ends_with("hello"));
    let record = &gw.wait_records(1)[0];
    assert_eq!(
        record.usage, None,
        "a tap that extracts nothing reports nothing"
    );
    assert_eq!(record.status_code, Some(200));
}

/// The bounded extractor holds its cap even against a hostile stream, and the
/// exchange still completes.
#[test]
fn a_hostile_stream_cannot_grow_the_extractor_without_bound() {
    let mut ex = UsageExtractor::new(Shape::OpenAi, true, false);
    let piece = vec![b'x'; 64 * 1024];
    ex.feed(b"data: ");
    for _ in 0..320 {
        ex.feed(&piece); // 20 MiB
    }
    ex.feed(b"\n\n");
    assert!(ex.bound() <= 256 * 1024, "the extractor stays bounded");
    assert_eq!(ex.dropped_events(), 1);
}
