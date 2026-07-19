//! Migration and data-safety tests: populated old-schema vaults upgrading
//! to the current schema (sequentially and directly), interrupted and
//! corrupted migrations, future-schema refusal, and full backup/restore
//! completeness. Fake data only; every database lives in a temp directory.

mod common;

use api_tracker_core::db;
use api_tracker_core::error::CoreError;
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, VaultPaths};
use common::{add_key, add_project, new_vault};
use rusqlite::Connection;

const FAKE_KEY: &str = "sk-proj-FAKE0000000000000000000000000000FAKE";

/// Open a fresh file-backed DB migrated up to (and including) `version`.
fn db_at_version(path: &std::path::Path, version: i64) -> Connection {
    let mut conn = db::open(path).unwrap();
    let upto = db::MIGRATIONS
        .iter()
        .position(|m| m.version == version)
        .expect("known version");
    db::migrate_with(&mut conn, &db::MIGRATIONS[..=upto]).unwrap();
    assert_eq!(db::user_version(&conn).unwrap(), version);
    conn
}

/// Insert a minimal but realistic data set using only v1-era tables.
/// (Crypto blobs are fabricated — migrations never read them.)
fn populate_v1(conn: &Connection) {
    conn.execute_batch(
        "INSERT INTO vault_meta (key, value) VALUES ('vault_id', 'test-vault-0001');
         INSERT INTO projects (id, name, description, notes, environments, archived,
             created_at, updated_at, wrapped_project_key, key_wrap_mode)
         VALUES ('p1', 'app', '', '', 'development', 0,
             '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', x'00112233', 'vault');
         INSERT INTO project_repos (project_id, path) VALUES ('p1', '/tmp/repo');
         INSERT INTO credentials (id, project_id, provider, name, environment,
             credential_type, ciphertext, fingerprint, masked_value, created_at,
             updated_at, docs_url, notes, manually_disabled, revoked, marked_invalid,
             possibly_exposed, exposure_note)
         VALUES ('c1', 'p1', 'openai', 'main', 'development', '', x'deadbeef',
             x'0102030405', 'sk-...AKE', '2026-01-01T00:00:00Z',
             '2026-01-01T00:00:00Z', '', '', 0, 0, 0, 0, '');
         INSERT INTO audit_events (at, event, project_id, credential_id, detail)
         VALUES ('2026-01-01T00:00:00Z', 'credential_created', 'p1', 'c1', '');",
    )
    .unwrap();
}

fn assert_v1_data_survived(conn: &Connection) {
    assert_eq!(
        db::user_version(conn).unwrap(),
        db::current_schema_version()
    );
    let name: String = conn
        .query_row("SELECT name FROM projects WHERE id='p1'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(name, "app");
    let (cred_name, value_version, provider_expires): (String, i64, Option<String>) = conn
        .query_row(
            "SELECT name, value_version, provider_expires_at FROM credentials WHERE id='c1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(cred_name, "main");
    assert_eq!(value_version, 1, "added columns must carry their defaults");
    assert_eq!(provider_expires, None);
    let ciphertext: Vec<u8> = conn
        .query_row(
            "SELECT ciphertext FROM credentials WHERE id='c1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ciphertext, vec![0xde, 0xad, 0xbe, 0xef]);
    let audits: i64 = conn
        .query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))
        .unwrap();
    assert!(audits >= 1);
}

#[test]
fn populated_v1_database_upgrades_directly_to_current() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.db");
    {
        let conn = db_at_version(&path, 1);
        populate_v1(&conn);
    }
    let mut conn = db::open(&path).unwrap();
    db::migrate(&mut conn).unwrap();
    assert_v1_data_survived(&conn);
}

#[test]
fn populated_v1_database_upgrades_sequentially_one_version_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seq.db");
    {
        let conn = db_at_version(&path, 1);
        populate_v1(&conn);
    }
    // Apply each migration individually, reopening the file between steps
    // (each reopen is a fresh process's view of the database).
    for (i, m) in db::MIGRATIONS.iter().enumerate() {
        let mut conn = db::open(&path).unwrap();
        db::migrate_with(&mut conn, &db::MIGRATIONS[..=i]).unwrap();
        assert_eq!(db::user_version(&conn).unwrap(), m.version);
    }
    let conn = db::open(&path).unwrap();
    assert_v1_data_survived(&conn);
}

#[test]
fn populated_v5_and_v6_tables_survive_the_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v6.db");
    {
        let conn = db_at_version(&path, 6);
        populate_v1(&conn);
        conn.execute_batch(
            "INSERT INTO credential_versions (credential_id, version, ciphertext,
                 masked_value, fingerprint, created_at)
             VALUES ('c1', 1, x'aa', 'sk-...old', x'bb', '2026-01-02T00:00:00Z');
             INSERT INTO destinations (id, kind, name, config, created_at, updated_at)
             VALUES ('d1', 'github_actions', 'ci', '{}',
                 '2026-01-02T00:00:00Z', '2026-01-02T00:00:00Z');
             INSERT INTO credential_destinations (credential_id, destination_id, secret_name)
             VALUES ('c1', 'd1', 'OPENAI_API_KEY');
             INSERT INTO sync_plans (id, credential_id, to_version, created_at)
             VALUES ('sp1', 'c1', 2, '2026-01-02T00:00:00Z');
             INSERT INTO rotations (id, credential_id, provider, state, mode,
                 created_at, updated_at)
             VALUES ('r1', 'c1', 'openai', 'planned', 'api_create',
                 '2026-01-02T00:00:00Z', '2026-01-02T00:00:00Z');
             INSERT INTO access_grants (id, project_id, expires_at, created_at)
             VALUES ('g1', 'p1', '2026-01-03T00:00:00Z', '2026-01-02T00:00:00Z');
             INSERT INTO rotation_schedules (credential_id, interval_days, next_due_at,
                 created_at)
             VALUES ('c1', 90, '2026-04-01T00:00:00Z', '2026-01-02T00:00:00Z');",
        )
        .unwrap();
    }
    let mut conn = db::open(&path).unwrap();
    db::migrate(&mut conn).unwrap();
    assert_v1_data_survived(&conn);
    for (table, expected) in [
        ("credential_versions", 1i64),
        ("destinations", 1),
        ("credential_destinations", 1),
        ("sync_plans", 1),
        ("rotations", 1),
        ("access_grants", 1),
        ("rotation_schedules", 1),
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, expected, "{table} rows must survive the upgrade");
    }
}

#[test]
fn v7_backfills_first_seen_for_preexisting_provider_entities() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("backfill.db");
    {
        let conn = db_at_version(&path, 6);
        conn.execute(
            "INSERT INTO provider_side_keys (provider, api_key_id, name, redacted_value, synced_at)
             VALUES ('openai', 'key_old', 'old', 'sk-...x', '2026-06-01T00:00:00Z')",
            [],
        )
        .unwrap();
    }
    let mut conn = db::open(&path).unwrap();
    db::migrate(&mut conn).unwrap();
    // Pre-existing rows are backfilled with the epoch so the upgrade cannot
    // flood users with "new provider key appeared" alerts.
    let first_seen: String = conn
        .query_row(
            "SELECT first_seen_at FROM provider_side_keys WHERE api_key_id='key_old'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(first_seen, "1970-01-01T00:00:00Z");
}

#[test]
fn interrupted_migration_resumes_where_it_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("interrupted.db");
    {
        // "Crash" after v4 committed: the connection is simply dropped.
        let conn = db_at_version(&path, 4);
        populate_v1(&conn);
    }
    // A later open resumes the chain from v4 and completes it.
    let mut conn = db::open(&path).unwrap();
    db::migrate(&mut conn).unwrap();
    assert_v1_data_survived(&conn);
}

#[test]
fn corrupted_inputs_fail_loudly_and_roll_back() {
    // Garbage bytes: not a database at all.
    let dir = tempfile::tempdir().unwrap();
    let garbage = dir.path().join("garbage.db");
    std::fs::write(&garbage, b"this is not a sqlite database, not even close").unwrap();
    let result = db::open(&garbage).and_then(|mut c| db::migrate(&mut c));
    assert!(result.is_err(), "garbage input must be refused");

    // A structurally valid database whose schema was corrupted (a required
    // table dropped): the failing migration rolls back and the version
    // does not advance past the last good migration.
    let broken = dir.path().join("broken.db");
    {
        let conn = db_at_version(&broken, 4);
        conn.execute_batch("DROP TABLE credentials").unwrap();
    }
    let mut conn = db::open(&broken).unwrap();
    let err = db::migrate(&mut conn).unwrap_err();
    assert!(err.to_string().contains("credentials") || matches!(err, CoreError::Db(_)));
    // v5 (the first migration touching `credentials`) must not have been
    // recorded as applied.
    assert_eq!(db::user_version(&conn).unwrap(), 4);
}

#[test]
fn future_schema_databases_are_refused_including_via_unlock() {
    let dir = tempfile::tempdir().unwrap();

    // Plain database path.
    let path = dir.path().join("future.db");
    {
        let conn = db::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
    }
    let mut conn = db::open(&path).unwrap();
    let err = db::migrate(&mut conn).unwrap_err();
    assert!(
        matches!(
            err,
            CoreError::SchemaTooNew {
                found: 99,
                supported: _
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("newer version"));

    // Through the real vault path: a vault stamped by a "newer build" must
    // refuse to unlock instead of opening read/write.
    let vault_dir = dir.path().join("vault");
    let paths = VaultPaths::new(vault_dir);
    let master = SecretString::from("future-schema-master-01");
    drop(vault::create_vault(&paths, &master).unwrap());
    {
        let conn = db::open(&paths.db_path()).unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
    }
    let err = vault::unlock_vault(&paths, &master).unwrap_err();
    assert!(matches!(err, CoreError::SchemaTooNew { .. }), "{err}");
}

#[test]
fn backup_captures_every_table_and_restore_preserves_all_rows() {
    let (dir, _paths, mut v) = new_vault();
    let project = add_project(&mut v, "app");
    let (cred, _) = add_key(&mut v, "app", "openai", FAKE_KEY, Environment::Production);

    // Touch as many subsystems as the public API allows, so the backup has
    // rows in tables from every schema era.
    let master = common::master_pw();
    v.replace_credential_value(
        "app/openai",
        &master,
        SecretString::from("sk-proj-FAKE-replacement-value-000002"),
    )
    .unwrap(); // credential_versions
    v.add_suppression("supkey", "manual", "x.env", "fixture")
        .unwrap();
    v.watch_docs("openai", "https://platform.openai.com/docs/changelog")
        .unwrap(); // doc_watches
    v.set_env_mapping(&project.id, &cred.id, "OPENAI_API_KEY")
        .unwrap();
    v.notification_channel_add(
        "hook",
        &SecretString::from("https://hooks.example.invalid/T/FAKE-token-0001"),
        "high",
    )
    .unwrap(); // notification_channels (encrypted URL blob)
    v.destination_add(
        "github_actions",
        "ci",
        serde_json::json!({"owner":"o","repo":"r"}),
        Some(&SecretString::from(
            "ghp_FAKE0000000000000000000000000000000000",
        )),
    )
    .unwrap(); // destinations (encrypted auth blob)
    v.access_grant_create(&project.id, "", &[], 60, 1, None, None)
        .unwrap(); // access_grants
    v.usage_record_manual(
        &cred.id,
        Some("gpt-4o"),
        1000,
        2000,
        "2026-07-01T00:00:00Z",
        "2026-07-02T00:00:00Z",
    )
    .unwrap(); // usage_snapshots
    v.run_monitor().unwrap(); // alerts (+ activity)

    // Every user table in the source must exist in the restored copy with
    // the same row count.
    let table_counts = |conn: &Connection| -> Vec<(String, i64)> {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        names
            .into_iter()
            .map(|n| {
                let count: i64 = conn
                    .query_row(&format!("SELECT COUNT(*) FROM \"{n}\""), [], |r| r.get(0))
                    .unwrap();
                (n, count)
            })
            .collect()
    };
    let original_counts = table_counts(v.connection());
    assert!(
        original_counts.iter().filter(|(_, c)| *c > 0).count() >= 12,
        "the fixture must populate a broad slice of the schema: {original_counts:?}"
    );

    let backup_password = SecretString::from("completeness-backup-pw-01");
    let backup_path = dir.path().join("full.backup");
    let info =
        api_tracker_core::backup::create_backup(&v, &backup_path, &backup_password, false).unwrap();
    assert_eq!(info.format_version, 2);
    assert_eq!(info.credential_count, 1);

    // No plaintext secret material in the backup file.
    let raw = std::fs::read_to_string(&backup_path).unwrap();
    for secret in [
        FAKE_KEY,
        "sk-proj-FAKE-replacement-value-000002",
        "FAKE-token-0001",
        "ghp_FAKE0000000000000000000000000000000000",
    ] {
        assert!(!raw.contains(secret), "backup leaks {secret}");
    }

    let restored_paths = VaultPaths::new(dir.path().join("restored"));
    api_tracker_core::backup::restore_backup(
        &backup_path,
        &backup_password,
        &restored_paths,
        false,
    )
    .unwrap();
    let mut restored = vault::unlock_vault(&restored_paths, &master).unwrap();
    let restored_counts = table_counts(restored.connection());
    // The audit trail gains a restore marker; every other table matches
    // exactly.
    for (name, count) in &original_counts {
        let restored_count = restored_counts
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| *c)
            .unwrap_or(-1);
        if name == "audit_events" {
            assert!(restored_count >= *count, "audit trail must be preserved");
        } else {
            assert_eq!(
                restored_count, *count,
                "table '{name}' must survive backup/restore"
            );
        }
    }

    // The restored vault is fully functional: reveal works and version
    // history (for rollback) is intact.
    let revealed = restored.reveal_credential("app/openai", &master).unwrap();
    assert_eq!(revealed.expose(), "sk-proj-FAKE-replacement-value-000002");
    let versions = restored
        .credential_version_history("app/openai", &master)
        .unwrap();
    assert!(
        !versions.is_empty(),
        "retained versions must survive restore"
    );
}
