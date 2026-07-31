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
use api_tracker_gateway::upstream::InsecurePlainConnectorForTests;
use api_tracker_gateway::usage::{Shape, UsageExtractor};

/// A deterministic restore-record key for tests.
///
/// Fixed rather than random so a single test can seal on `apply_link` and
/// open on `unlink` and get the same key both times — and unmistakably fake,
/// like every other credential in this suite.
fn restore_crypto() -> api_tracker_core::envrestore::RestoreCrypto {
    api_tracker_core::envrestore::RestoreCrypto::new(
        "vault-test-0001".to_string(),
        api_tracker_core::secret::SecretBytes::new(vec![0x2au8; 32]),
    )
}

/// Every marker routed through the gateway. If any of these bytes reach any
/// artifact, the test fails and names the artifact.
const CANARY_CREDENTIAL: &str = "FAKE-TEST-NOT-A-REAL-KEY-CANARY-9f2c8a71";
const CANARY_PROMPT: &str = "CANARY-PROMPT-e41d7b93";
const CANARY_RESPONSE: &str = "CANARY-RESPONSE-5c0aa218";
const CANARY_QUERY: &str = "CANARY-QUERY-7ab3f602";
const CANARY_COOKIE: &str = "CANARY-COOKIE-1d94ce55";
const CANARY_HEADER: &str = "CANARY-HEADER-b7e02f14";

/// Markers planted in a project's `.env` rather than in traffic. The `.env`
/// link writer records what it overwrites in `gateway_project_links
/// .prior_env_json`, which is a PLAINTEXT column — so a prior value carrying
/// key material must never reach it (ZFT-016).
const CANARY_ENV_QUERY: &str = "sk-QUERYCANARY-3f7a19d4c8e25b60";
const CANARY_ENV_PATH: &str = "9f2c8a71e45b30d6PATHCANARY4b8e";

fn all_canaries() -> Vec<(&'static str, &'static str)> {
    vec![
        ("credential value", CANARY_CREDENTIAL),
        ("prompt body", CANARY_PROMPT),
        ("response body", CANARY_RESPONSE),
        ("query value", CANARY_QUERY),
        ("cookie value", CANARY_COOKIE),
        ("header value", CANARY_HEADER),
        (".env query-string value", CANARY_ENV_QUERY),
        (".env URL-path value", CANARY_ENV_PATH),
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

/// Caps that keep the sweep bounded (NEW-53). A data directory this deep or
/// this wide means something is wrong, and a sweep that silently stopped at a
/// cap would be a canary that quietly stopped looking — so breaching either
/// cap FAILS the test rather than truncating the walk.
const SWEEP_MAX_DEPTH: usize = 16;
const SWEEP_MAX_FILES: usize = 4096;

/// Recursively scan every byte the gateway left under `root`.
///
/// NEW-53: this sweep used to read ONE directory level, so anything the
/// gateway wrote into a subdirectory was outside every canary in this file —
/// most importantly `<data-dir>/logs/gateway.log`, which is exactly the
/// artifact a leaked credential would land in, and exactly what these canaries
/// exist to catch. A one-level `read_dir` could not have failed on it.
///
/// Bounded on purpose: the walk never follows a symlink, because a link
/// planted in the data directory would drag the scan across the whole
/// filesystem and turn a privacy canary into an unbounded disk read. A link's
/// own content is its target path, so that is scanned; a link that points back
/// inside `root` costs nothing, since the walk reaches the real file on its
/// own.
///
/// Returns the number of regular files read, so callers can assert the sweep
/// was not vacuous.
fn sweep_data_dir(root: &std::path::Path, what: &str) -> usize {
    sweep_data_dir_with(root, what, &mut assert_absent)
}

/// `sweep_data_dir` with a caller-supplied check, for canaries that are not in
/// `all_canaries()` (the matching key is its own canary, SI-21).
fn sweep_data_dir_with(
    root: &std::path::Path,
    what: &str,
    check: &mut dyn FnMut(&str, &[u8]),
) -> usize {
    let mut scanned = 0usize;
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = pending.pop() {
        assert!(
            depth <= SWEEP_MAX_DEPTH,
            "{what}: {} is deeper than the sweep's {SWEEP_MAX_DEPTH}-level cap, \
             so bytes below it would go unscanned",
            dir.display()
        );
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            // `symlink_metadata` describes the link itself; `metadata` would
            // follow it and could report a directory living outside `root`.
            let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
            if kind.is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                check(
                    &format!("{what}: symlink target of {}", path.display()),
                    target.as_os_str().as_encoded_bytes(),
                );
                continue;
            }
            // The name is an artifact too: a marker used as a filename leaks
            // just as loudly as one written inside a file.
            if let Some(name) = path.file_name() {
                check(
                    &format!("{what}: the name of {}", path.display()),
                    name.as_encoded_bytes(),
                );
            }
            if kind.is_dir() {
                pending.push((path, depth + 1));
            } else if kind.is_file() {
                let bytes = std::fs::read(&path).unwrap();
                check(&format!("{what}: {}", path.display()), &bytes);
                scanned += 1;
                assert!(
                    scanned <= SWEEP_MAX_FILES,
                    "{what}: more than {SWEEP_MAX_FILES} files under {}; the \
                     sweep would no longer be bounded",
                    root.display()
                );
            }
        }
    }
    scanned
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
    //
    // NOTE ON SCOPE (audit remediation): this test's gateway uses an
    // in-memory `CollectingSink`, so NOTHING it forwarded was ever written to
    // the database scanned below. The scan therefore proves only that the
    // canaries are absent from the schema and the seed row — which is worth
    // asserting, but is not a persistence canary. The REAL persistence path
    // (Writer -> runtime_request_events / gateway_usage_* / counters) is
    // scanned by `no_canary_survives_the_real_persistence_path` below, which
    // drives an actual `Writer` and flushes before reading the files.

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
    // Every other file the gateway could have written into its data dir, at
    // ANY depth — `logs/gateway.log` lives one level down (NEW-53).
    let scanned = sweep_data_dir(dir.path(), "the data directory");
    assert!(scanned >= 1, "scanning nothing is not a pass");
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

    // Disk: the whole data directory, recursively (NEW-53).
    let scanned = sweep_data_dir_with(dir.path(), "the data directory", &mut |where_, bytes| {
        assert!(
            !contains(bytes, &key_bytes),
            "the matching key must never reach disk: found in {where_}"
        );
    });
    assert!(scanned >= 1, "scanning nothing is not a pass");

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

/// With attribution unavailable, the state is `unavailable_no_key` and
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
        api_tracker_gateway::record::AttributionInput::UnavailableNoKey
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

/// The canary that scans what a REAL writer actually persisted.
///
/// The audit found the flagship raw-artifact scan vacuous: the exchange under
/// test used an in-memory sink, so the database it scanned had never received
/// the record. This test closes that by running the genuine persistence path
/// — `Writer::start` -> `WriterSink` -> `process_batch` -> the runtime and
/// gateway tables — flushing it, and only then reading every byte on disk.
///
/// It is written so that it CANNOT pass vacuously: it asserts the row count
/// went up before it scans, so a writer that silently persisted nothing fails
/// here rather than reporting a clean scan.
#[test]
fn no_canary_survives_the_real_persistence_path() {
    use api_tracker_gateway::writer::{Writer, DRAIN_TIMEOUT};

    let dir = tempfile::tempdir().unwrap();
    let db_path = test_db(dir.path());

    // A synthetic upstream that echoes a canary-bearing response body.
    let up = MockUpstream::start(move |sock, requests| {
        use std::io::Read;
        let mut buf = vec![0u8; 8192];
        let n = sock.read(&mut buf).unwrap_or(0);
        requests.lock().unwrap().push(buf[..n].to_vec());
        let body = format!("{{\"text\":\"{CANARY_RESPONSE}\"}}");
        let _ = sock.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Set-Cookie: sid={CANARY_COOKIE}\r\n\
                 X-Canary: {CANARY_HEADER}\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
    });

    // The REAL writer, against the real database.
    let mut writer = Writer::start(&db_path, "canary-boot".into());
    let sink = writer.sink();
    // A route WITH a project link: unlinked traffic is counted, not recorded,
    // so without the link there would be nothing persisted to scan.
    const SLUG: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut table = api_tracker_gateway::routes::RouteTable::default();
    table.insert_for_test(api_tracker_gateway::routes::Route {
        prefix: "openai".into(),
        provider_id: "openai".into(),
        target: api_tracker_gateway::routes::RouteTarget::Ready(
            api_tracker_gateway::routes::UpstreamOrigin {
                host: "127.0.0.1".into(),
                port: up.port,
            },
        ),
        custom: false,
        usage_shape: "openai".into(),
    });
    table.insert_link_for_test(api_tracker_gateway::routes::LinkInfo {
        project_id: "p1".into(),
        route_prefix: "openai".into(),
        link_slug: SLUG.into(),
    });
    let routes = Arc::new(api_tracker_gateway::routes::RouteState::from_table_for_test(table));
    // Bind FIRST: the Host gate compares against the gateway's own declared
    // port, so it must be the real bound one.
    let listener = api_tracker_gateway::server::Listener::bind(0).unwrap();
    let port = listener.port();
    let mut gw = api_tracker_gateway::forward::Gateway::new(routes, sink.clone(), port);
    // Synthetic upstreams are plain-TCP loopback listeners, exactly as in the
    // rest of the suite; the production SSRF policy (which refuses loopback)
    // is untouched.
    gw.connector = Arc::new(InsecurePlainConnectorForTests);
    let gw = gw;
    let serve_gw = gw.clone();
    let handle = std::thread::spawn(move || {
        server::serve_with_taps(serve_gw, listener, server::usage_tap_factory())
    });

    // One exchange carrying every canary the gateway could possibly see.
    {
        use std::io::Read;
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let body = format!("{{\"prompt\":\"{CANARY_PROMPT}\"}}");
        write!(
            c,
            "POST /p/{SLUG}/openai/v1/chat/completions?key={CANARY_QUERY} HTTP/1.1\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Authorization: Bearer {CANARY_CREDENTIAL}\r\n\
             Cookie: sid={CANARY_COOKIE}\r\n\
             X-Canary: {CANARY_HEADER}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut got = String::new();
        let _ = c.read_to_string(&mut got);
        assert!(
            got.starts_with("HTTP/1.1 200 "),
            "precondition: the exchange must succeed, got: {got:?}"
        );
    }

    // Drain the writer so the row is committed before anything is read.
    assert!(
        sink.flush(DRAIN_TIMEOUT),
        "the writer must drain; an undrained queue would make the scan vacuous"
    );
    gw.shutdown
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = handle.join();
    writer.stop();

    // ANTI-VACUITY GATE: the scan below is meaningless unless the writer
    // really wrote. This is the assertion whose absence made the original
    // canary unable to fail.
    let conn = open_db(&db_path);
    let events: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM runtime_request_events WHERE observation_source = 'gateway'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        events >= 1,
        "no gateway event was persisted, so scanning the database proves \
         nothing — this is the vacuity the audit found"
    );
    db::checkpoint_truncate(&conn);
    drop(conn);

    // Now scan every byte the run left on disk.
    let mut scanned = 0usize;
    for name in ["vault.db", "vault.db-wal", "vault.db-shm"] {
        let path = dir.path().join(name);
        if path.exists() {
            let bytes = std::fs::read(&path).unwrap();
            assert_absent(&format!("{name} (real persistence path)"), &bytes);
            scanned += 1;
        }
    }
    scanned += sweep_data_dir(dir.path(), "the data directory (real persistence path)");
    assert!(
        scanned >= 2,
        "expected to scan at least the database and one sidecar/file; \
         scanning nothing is not a pass"
    );
}

/// The `.env` link writer's restore record is a PLAINTEXT column, and the
/// allowlist that decides what may go into it originally inspected only the
/// URL's authority. Everything after the host — path, query, fragment — was
/// waved through, so a base URL that carried its key in a query string was
/// written verbatim into `vault.db`; the audit recovered `sk-QUERYCANARY-…`
/// from the raw file at a byte offset (ZFT-016).
///
/// This drives the real plan → apply path against a real database and then
/// reads every byte the run left on disk.
#[test]
fn no_env_value_canary_survives_the_link_writers_restore_record() {
    use api_tracker_gateway::envlink::{self, LinkRequest, LinkWarning};

    let dir = tempfile::tempdir().unwrap();
    let db_path = test_db(dir.path());
    let conn = open_db(&db_path);
    api_tracker_gateway::routes::add_manifest_route(&conn, "openai", "openai").unwrap();
    let mut config = api_tracker_gateway::store::load_config(&conn).unwrap();
    config.port = Some(49723);
    api_tracker_gateway::store::save_config(&conn, &config).unwrap();

    // Both declared OpenAI variables already hold a base URL that hides key
    // material AFTER the authority: one in a query string, one in a path
    // segment. Each host says "example", which is exactly what made the old
    // masking rule print them in full as well.
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let env = project.join(".env");
    std::fs::write(
        &env,
        format!(
            "OPENAI_BASE_URL=https://api.example.com/v1?api_key={CANARY_ENV_QUERY}\n\
             OPENAI_API_BASE=https://gw.example.com/{CANARY_ENV_PATH}/v1\n"
        ),
    )
    .unwrap();

    let req = LinkRequest {
        project_id: "p1".into(),
        project_name: "app".into(),
        route_prefix: "openai".into(),
        project_dir: Some(project.clone()),
        files: vec![env.clone()],
        var_override: None,
    };
    let plan = envlink::plan_link(&conn, &req).unwrap();

    // The consent diff is shown on stdout and across IPC before anything is
    // written, so it is an artifact too.
    assert_absent("the link plan's diff", plan.files[0].diff.as_bytes());
    assert_absent(
        "the serialized link plan",
        serde_json::to_string(&plan).unwrap().as_bytes(),
    );
    envlink::apply_link(&conn, Some(&restore_crypto()), &req, &plan).unwrap();

    // ANTI-VACUITY GATE: scanning the database proves nothing unless the
    // restore record really was written to it.
    let stored: String = conn
        .query_row(
            "SELECT prior_env_json FROM gateway_project_links WHERE project_id = 'p1'",
            [],
            |r| r.get(0),
        )
        .expect("apply must have written a restore record");
    assert!(
        stored.contains("OPENAI_BASE_URL") && stored.contains("prior_withheld"),
        "the record must really describe these variables, else the scan is \
         vacuous: {stored}"
    );
    assert_absent("the stored prior_env_json", stored.as_bytes());
    // The file itself was still rewritten, so the feature works — this is a
    // privacy test, not an "it did nothing" test.
    assert!(std::fs::read_to_string(&env)
        .unwrap()
        .contains("OPENAI_BASE_URL=http://127.0.0.1:49723/p/"));

    db::checkpoint_truncate(&conn);
    drop(conn);

    // Recursive (NEW-53): the rewritten `.env` itself lives at
    // `<data-dir>/proj/.env`, one level below the root the old sweep read, so
    // the file this test is actually about was never scanned at all.
    let scanned = sweep_data_dir(dir.path(), "the data directory (link writer)");
    assert!(scanned >= 1, "scanning nothing is not a pass");

    // Recording must be VISIBLE, not silent. The value is kept — sealed —
    // so the user gets their automatic restore back, and they are told BEFORE
    // they confirm that their existing value is being recorded.
    //
    // This assertion used to require `PriorValueWithheld`. Under ADR 0028
    // nothing is withheld when a key is available: the protection is
    // encryption, not refusal, so the honest disclosure changed with it.
    for var in ["OPENAI_BASE_URL", "OPENAI_API_BASE"] {
        assert!(
            plan.warnings
                .iter()
                .any(|w| matches!(w, LinkWarning::ExistingValueRecorded { key, .. } if key == var)),
            "{var}'s prior value was recorded but the user was never told: {:?}",
            plan.warnings
        );
    }
    assert!(
        stored.contains("\"sealed\""),
        "and the record must hold ciphertext, not a withheld marker: {stored}"
    );
}

/// Negative control for the sweep's REACH (NEW-53).
///
/// The audit found the raw-artifact sweep read a single directory level, so
/// `<data-dir>/logs/gateway.log` — the gateway's own log, and the likeliest
/// place for a credential to surface — was never scanned. A credential written
/// there would have been reported as a clean scan by every canary above.
///
/// This plants a credential in exactly that path and asserts the sweep fails.
/// It also pins that the root holds no files at all, so the only way to reach
/// the planted marker is by descending: a regression to a one-level `read_dir`
/// cannot pass this test, it can only report a vacuous clean sweep.
#[test]
#[should_panic(expected = "privacy invariant violation")]
fn the_sweep_reaches_a_canary_planted_in_a_nested_log_file() {
    let dir = tempfile::tempdir().unwrap();
    let logs = dir.path().join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(
        logs.join("gateway.log"),
        format!(
            "2026-01-01T00:00:00Z forward openai 200 \
             authorization=\"Bearer {CANARY_CREDENTIAL}\"\n"
        ),
    )
    .unwrap();

    let top_level_files = std::fs::read_dir(dir.path())
        .unwrap()
        .filter(|e| e.as_ref().unwrap().path().is_file())
        .count();
    assert_eq!(
        top_level_files, 0,
        "the planted marker must be reachable ONLY by recursion, else this \
         control would pass even with the old one-level sweep"
    );

    sweep_data_dir(dir.path(), "a data directory with a nested gateway log");
}

/// The recursion is bounded (NEW-53): it descends the data directory to any
/// realistic depth, but a symlink is read as a link and never traversed. A
/// followed link would walk the whole filesystem from a temp directory and
/// would make the canary sweep unbounded; here the link points at a directory
/// holding a marker, so a sweep that followed it would fail this test.
#[test]
fn the_sweep_descends_but_never_follows_a_symlink_out_of_the_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("not-ours.txt"),
        format!("{CANARY_PROMPT} {CANARY_CREDENTIAL}"),
    )
    .unwrap();

    std::fs::write(dir.path().join("vault.db"), b"clean").unwrap();
    let nested = dir.path().join("logs").join("archive").join("2026");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(dir.path().join("logs").join("gateway.log"), b"clean").unwrap();
    std::fs::write(nested.join("gateway.log.1"), b"clean").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();

    let scanned = sweep_data_dir(dir.path(), "a nested data directory");
    assert_eq!(
        scanned, 3,
        "the sweep must read every regular file it owns (3 levels deep) and \
         nothing beyond the data directory"
    );
}

/// Negative control for the canary machinery itself: `assert_absent` must
/// FAIL when a canary really is present. Without this, a broken matcher would
/// make every canary test above pass silently.
#[test]
#[should_panic(expected = "privacy invariant violation")]
fn the_canary_scanner_fails_when_a_canary_is_actually_present() {
    let planted = format!("harmless prefix {CANARY_PROMPT} harmless suffix");
    assert_absent("a deliberately planted canary", planted.as_bytes());
}
