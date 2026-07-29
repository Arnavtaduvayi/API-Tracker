//! `ENC-01` regression suite: a GUI-only user's legacy plaintext gets re-sealed.
//!
//! # The gap
//!
//! New rollback values are encrypted unconditionally, and provably so
//! (`restore_record_privacy.rs`). Rows written by an EARLIER build still hold
//! the value in plaintext in `gateway_project_links.prior_env_json`, a plain
//! `TEXT` column, and only one thing ever rewrites them: the scrub that runs
//! at unlock.
//!
//! ADR 0028 stated that scrub runs in "`Ctx::unlocked`, and the desktop's
//! unlocked commands", and that this closes the observation that a GUI-only
//! user never ran it. **The desktop call site did not exist.** The only keyed
//! caller was `apps/cli/src/ctx.rs`, so the one persona the ADR names as the
//! reason the feature exists — someone who never opens a terminal — was the
//! one persona whose `RA-006` plaintext stayed in `vault.db` indefinitely.
//!
//! # What is asserted
//!
//! The migration is driven through `envlink::upgrade_restore_records`, which
//! is now the single function BOTH front ends call, and the canary is hunted
//! in raw bytes across the database, its WAL and its SHM — the same sweep
//! that found the original `RA-006` value at a byte offset. Undo is exercised
//! afterwards, because a migration that protects a value by destroying the
//! user's ability to restore it has not fixed anything.

use api_tracker_core::db;
use api_tracker_core::envrestore::RestoreCrypto;
use api_tracker_core::secret::SecretBytes;
use api_tracker_gateway::envlink;
use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// Unmistakably fake, and shaped like the credential the original finding was
/// about (a Supabase service-role JWT).
const CANARY: &str = "eyJFAKE.ROLLBACK-CANARY-MUST-NEVER-PERSIST-9d2f.SIGNATURE";

fn restore_crypto() -> RestoreCrypto {
    RestoreCrypto::new(
        "vault-test-0001".to_string(),
        SecretBytes::new(vec![0x2au8; 32]),
    )
}

fn migrated(path: &Path) -> Connection {
    let mut conn = db::open(path).unwrap();
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
    conn
}

/// A **pre-v16 shaped** link row: `prior_env_json` at version 1, carrying the
/// value in the clear. This is what an upgrading user's vault actually holds;
/// it is written as raw JSON because no current build can produce it.
fn plant_legacy_row(conn: &Connection, env_path: &Path, key: &str, value: &str) {
    let doc = serde_json::json!({
        "v": 1,
        "port": 49723,
        "files": [{
            "path": env_path.display().to_string(),
            "existed": true,
            "vars": [{ "key": key, "prior": value, "written": "http://127.0.0.1:49723/openai/slug-legacy" }]
        }]
    });
    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, created_at, updated_at)
         VALUES ('openai','openai',1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gateway_project_links (link_slug, project_id, route_prefix, created_at,
             prior_env_json)
         VALUES ('slug-legacy','p1','openai','2026-01-01T00:00:00Z', ?1)",
        [doc.to_string()],
    )
    .unwrap();
}

fn surfaces(dir: &Path) -> Vec<PathBuf> {
    let db = dir.join("vault.db");
    vec![
        db.clone(),
        PathBuf::from(format!("{}-wal", db.display())),
        PathBuf::from(format!("{}-shm", db.display())),
    ]
}

/// Raw-BYTE sweep. A value can survive in a freed page or an uncheckpointed
/// WAL frame long after the row that held it is gone — which is exactly how
/// the original canary was recovered.
fn surfaces_containing(dir: &Path, needle: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for path in surfaces(dir) {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
            hits.push(path.display().to_string());
        }
    }
    hits
}

fn stored_json(conn: &Connection) -> String {
    conn.query_row(
        "SELECT prior_env_json FROM gateway_project_links WHERE link_slug = 'slug-legacy'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn meta(conn: &Connection, key: &str) -> Option<String> {
    use rusqlite::OptionalExtension;
    conn.query_row("SELECT value FROM vault_meta WHERE key = ?1", [key], |r| {
        r.get(0)
    })
    .optional()
    .unwrap()
}

// ---------------------------------------------------------------------------

/// The headline: a legacy plaintext value is re-sealed, and the canary is
/// gone from every on-disk surface.
#[test]
fn a_legacy_plaintext_rollback_value_is_re_sealed_and_leaves_no_bytes_behind() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    let env = dir.path().join(".env");
    std::fs::write(&env, format!("OPENAI_BASE_URL={CANARY}\n")).unwrap();
    plant_legacy_row(&conn, &env, "OPENAI_BASE_URL", CANARY);

    // Precondition: the plaintext really is there, and findable.
    assert!(
        stored_json(&conn).contains(CANARY),
        "the fixture must actually plant plaintext"
    );
    db::checkpoint_truncate(&conn);
    assert!(
        !surfaces_containing(dir.path(), CANARY).is_empty(),
        "precondition: the canary must be readable on disk BEFORE the migration, \
         or this test proves nothing"
    );

    let crypto = restore_crypto();
    let rewritten = envlink::scrub_stored_prior_env_once(&conn, Some(&crypto)).unwrap();
    assert_eq!(rewritten, 1, "exactly the one legacy row was rewritten");

    let after = stored_json(&conn);
    assert!(
        !after.contains(CANARY),
        "the active row must no longer carry the value in the clear: {after}"
    );
    assert!(
        after.contains("sealed"),
        "and it must carry a sealed replacement instead: {after}"
    );

    let hits = surfaces_containing(dir.path(), CANARY);
    assert!(
        hits.is_empty(),
        "the canary is still readable in {hits:?} — `secure_delete` plus the WAL \
         checkpoint are supposed to leave no copy in the database, its WAL or its SHM"
    );
}

/// The migration must not be a data-destroying "fix": undo has to keep
/// working, byte for byte.
#[test]
fn undo_still_restores_byte_for_byte_after_the_migration() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    let env = dir.path().join(".env");
    std::fs::write(&env, format!("OPENAI_BASE_URL={CANARY}\n")).unwrap();
    plant_legacy_row(&conn, &env, "OPENAI_BASE_URL", CANARY);

    let crypto = restore_crypto();
    envlink::scrub_stored_prior_env_once(&conn, Some(&crypto)).unwrap();

    // Re-open the sealed record the way unlink does and prove the original
    // value comes back out intact.
    let json = stored_json(&conn);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed["v"], 2,
        "the record is upgraded to the sealed version"
    );
    let sealed = &parsed["files"][0]["vars"][0]["sealed"];
    assert!(!sealed.is_null(), "the value must be sealed, not dropped");
    assert!(
        parsed["files"][0]["vars"][0]["prior"].is_null(),
        "and the plaintext field must be gone"
    );
    assert!(
        parsed["files"][0]["vars"][0]["prior_withheld"] != serde_json::json!(true),
        "a keyed migration must RE-SEAL, never withhold — withholding would cost \
         the user their undo"
    );
}

/// Running it twice is harmless, and the second pass does no work at all.
#[test]
fn the_migration_is_idempotent_and_does_not_rescan_once_complete() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    let env = dir.path().join(".env");
    plant_legacy_row(&conn, &env, "OPENAI_BASE_URL", CANARY);
    let crypto = restore_crypto();

    assert_eq!(
        envlink::scrub_stored_prior_env_once(&conn, Some(&crypto)).unwrap(),
        1
    );
    let after_first = stored_json(&conn);

    for pass in 2..=4 {
        assert_eq!(
            envlink::scrub_stored_prior_env_once(&conn, Some(&crypto)).unwrap(),
            0,
            "pass {pass} must be a no-op: the marker exists, so nothing is rescanned"
        );
        assert_eq!(
            stored_json(&conn),
            after_first,
            "pass {pass} must not rewrite the sealed record again"
        );
    }
}

/// The migration records what it did, so a later build can tell "migrated by
/// the v1 rule" from "never migrated" without re-reading every link row.
#[test]
fn the_migration_records_its_version_and_status() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    let env = dir.path().join(".env");
    plant_legacy_row(&conn, &env, "OPENAI_BASE_URL", CANARY);

    assert_eq!(meta(&conn, "envlink_prior_scrub_v1"), None);
    envlink::scrub_stored_prior_env_once(&conn, Some(&restore_crypto())).unwrap();

    assert!(
        meta(&conn, "envlink_prior_scrub_v1").is_some(),
        "a completion marker must be recorded"
    );
    assert_eq!(
        meta(&conn, "envlink_prior_scrub_version").as_deref(),
        Some("2")
    );
    assert_eq!(
        meta(&conn, "envlink_prior_scrub_rows").as_deref(),
        Some("1")
    );
    // The status must not carry the thing it protected.
    for key in [
        "envlink_prior_scrub_v1",
        "envlink_prior_scrub_version",
        "envlink_prior_scrub_rows",
    ] {
        let v = meta(&conn, key).unwrap_or_default();
        assert!(!v.contains(CANARY), "status key {key} leaked the value");
    }
}

/// A locked start — no key — must change nothing and must NOT mark the
/// migration done, so the next unlocked run still performs it.
#[test]
fn a_locked_start_neither_corrupts_the_row_nor_claims_completion() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    let env = dir.path().join(".env");
    plant_legacy_row(&conn, &env, "OPENAI_BASE_URL", CANARY);
    let before = stored_json(&conn);

    assert_eq!(
        envlink::scrub_stored_prior_env_once(&conn, None).unwrap(),
        0,
        "with no key there is nothing safe to do"
    );
    assert_eq!(
        stored_json(&conn),
        before,
        "the record must be byte-identical: redacting here would destroy the \
         user's undo to solve a problem a later unlock can solve properly"
    );
    assert_eq!(
        meta(&conn, "envlink_prior_scrub_v1"),
        None,
        "and it must NOT be marked done, or the work would be skipped forever"
    );

    // The deferred work is then completed by the first keyed run — which is
    // the resume path.
    assert_eq!(
        envlink::scrub_stored_prior_env_once(&conn, Some(&restore_crypto())).unwrap(),
        1,
        "the next unlocked run picks up exactly what was deferred"
    );
}

/// An interrupted migration resumes: a vault with legacy rows and no marker
/// is migrated on the next pass, whatever happened before.
#[test]
fn an_interrupted_migration_resumes_on_the_next_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    let env = dir.path().join(".env");
    plant_legacy_row(&conn, &env, "OPENAI_BASE_URL", CANARY);

    // A second legacy row, so "half done" is expressible.
    let doc = serde_json::json!({
        "v": 1, "port": 49723,
        "files": [{ "path": env.display().to_string(), "existed": true,
                    "vars": [{ "key": "OTHER_URL", "prior": CANARY, "written": "http://127.0.0.1:49723/anthropic/slug-two" }] }]
    });
    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, created_at, updated_at)
         VALUES ('anthropic','anthropic',1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gateway_project_links (link_slug, project_id, route_prefix, created_at,
             prior_env_json)
         VALUES ('slug-two','p1','anthropic','2026-01-01T00:00:00Z', ?1)",
        [doc.to_string()],
    )
    .unwrap();

    // Simulate an interruption: the transaction aborted, so NO marker was
    // written even though the process had started work.
    assert_eq!(meta(&conn, "envlink_prior_scrub_v1"), None);

    let crypto = restore_crypto();
    let rewritten = envlink::scrub_stored_prior_env_once(&conn, Some(&crypto)).unwrap();
    assert_eq!(rewritten, 2, "the resumed pass covers BOTH rows");

    let remaining: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM gateway_project_links WHERE prior_env_json LIKE '%\"prior\"%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 0, "no legacy plaintext field may remain");
    db::checkpoint_truncate(&conn);
    assert!(
        surfaces_containing(dir.path(), CANARY).is_empty(),
        "and no copy of either value may remain on disk"
    );
}

/// A row this build cannot parse is left exactly as it is, and does not stop
/// the rest of the migration. A half-understood rewrite is worse than a value
/// this build will refuse to read anyway.
#[test]
fn a_corrupt_legacy_row_fails_safely_without_blocking_the_others() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    let env = dir.path().join(".env");
    plant_legacy_row(&conn, &env, "OPENAI_BASE_URL", CANARY);

    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, created_at, updated_at)
         VALUES ('anthropic','anthropic',1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),
                ('groq','groq',1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gateway_project_links (link_slug, project_id, route_prefix, created_at,
             prior_env_json)
         VALUES ('slug-corrupt','p1','anthropic','2026-01-01T00:00:00Z', '{not valid json')",
        [],
    )
    .unwrap();
    // …and one written by a NEWER build, which this one must not touch either.
    conn.execute(
        "INSERT INTO gateway_project_links (link_slug, project_id, route_prefix, created_at,
             prior_env_json)
         VALUES ('slug-future','p1','groq','2026-01-01T00:00:00Z',
                 '{\"v\":99,\"port\":1,\"files\":[]}')",
        [],
    )
    .unwrap();

    let rewritten = envlink::scrub_stored_prior_env_once(&conn, Some(&restore_crypto()))
        .expect("a corrupt row must not fail the migration");
    assert_eq!(rewritten, 1, "only the row it understood was rewritten");

    let corrupt: String = conn
        .query_row(
            "SELECT prior_env_json FROM gateway_project_links WHERE link_slug = 'slug-corrupt'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(corrupt, "{not valid json", "left byte-identical");
    let future: String = conn
        .query_row(
            "SELECT prior_env_json FROM gateway_project_links WHERE link_slug = 'slug-future'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        future.contains("\"v\":99"),
        "a newer record is not downgraded"
    );
}

/// Both front ends must reach the migration through the SAME function.
///
/// This is the `ENC-01` finding stated as a test: the ADR claimed two call
/// sites and only one existed. A grep is a blunt instrument, but it is the
/// instrument that would have caught this — and a missing call site is
/// exactly what no unit test can observe.
#[test]
fn both_front_ends_call_the_shared_migration() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let desktop = std::fs::read_to_string(root.join("apps/desktop/src-tauri/src/main.rs"))
        .expect("the desktop entry point must exist");
    let cli = std::fs::read_to_string(root.join("apps/cli/src/ctx.rs"))
        .expect("the CLI context must exist");

    assert!(
        desktop.contains("envlink::upgrade_restore_records"),
        "the DESKTOP has no call site for the legacy-rollback migration — this is \
         ENC-01 exactly: ADR 0028 says it runs in the desktop's unlocked commands, \
         and a GUI-only user is the persona the feature exists for"
    );
    assert!(
        cli.contains("envlink::upgrade_restore_records"),
        "the CLI must reach the migration through the shared function too, so the \
         two cannot diverge again"
    );
    // And it must be on the UNLOCK path, not somewhere a user may never reach.
    let unlock = desktop
        .split("fn vault_unlock")
        .nth(1)
        .expect("vault_unlock must exist");
    let body_end = unlock.find("\n#[tauri::command]").unwrap_or(unlock.len());
    assert!(
        unlock[..body_end].contains("upgrade_restore_records"),
        "the migration must run from vault_unlock — the only moment a key is \
         definitionally available"
    );
}

/// Negative control: the sweep can find a planted needle, so an empty result
/// above means it looked rather than that it is broken.
#[test]
fn control_the_disk_sweep_can_find_a_planted_needle() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES ('planted', ?1)",
        [CANARY],
    )
    .unwrap();
    db::checkpoint_truncate(&conn);
    assert!(
        !surfaces_containing(dir.path(), CANARY).is_empty(),
        "the sweep must be able to find a value that IS on disk"
    );
}
