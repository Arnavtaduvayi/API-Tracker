//! Schema v20 guarantees (ADR 0029).
//!
//! Deliberately a NEW file rather than additions to `migration_safety.rs`:
//! `scripts/smoke.sh` greps that suite for `test result: ok. 9`, so adding a
//! test there would break the smoke gate rather than extend it.

use api_tracker_core::db;
use rusqlite::Connection;

fn mem() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    db::migrate(&mut conn).unwrap();
    conn.pragma_update(None, "foreign_keys", 1).unwrap();
    conn.execute(
        "INSERT INTO projects (id, name, created_at, updated_at, wrapped_project_key, key_wrap_mode)
         VALUES ('p1', 'web', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', X'00', 'vault')",
        [],
    )
    .unwrap();
    conn
}

fn columns(conn: &Connection, table: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
        .unwrap();
    let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
    rows.map(Result::unwrap).collect()
}

#[test]
fn v20_is_the_current_version_and_migrations_stay_append_only() {
    let conn = mem();
    assert_eq!(db::user_version(&conn).unwrap(), 20);
    assert_eq!(db::current_schema_version(), 20);
    // The released prefix must be untouched: versions are contiguous from 1 and
    // strictly increasing, which is what makes replaying a prefix meaningful for
    // backup restore.
    let versions: Vec<i64> = db::MIGRATIONS.iter().map(|m| m.version).collect();
    assert_eq!(versions, (1..=20).collect::<Vec<_>>());
}

#[test]
fn the_new_tables_are_strict() {
    let conn = mem();
    for table in ["project_folder_links", "detected_credentials"] {
        let strict: i64 = conn
            .query_row(
                "SELECT strict FROM pragma_table_list WHERE name = ?1",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(strict, 1, "{table} must be STRICT like every other table");
    }
}

/// The structural guarantee: there is nowhere for a secret to go. A column added
/// later whose name suggests otherwise fails this test rather than quietly
/// widening what the table can hold.
#[test]
fn detected_credentials_has_no_column_that_could_hold_a_value() {
    let conn = mem();
    let cols = columns(&conn, "detected_credentials");
    for col in &cols {
        let c = col.to_lowercase();
        assert!(
            !c.contains("value")
                && !c.contains("secret")
                && !c.contains("ciphertext")
                && !c.contains("plaintext")
                && !c.contains("token")
                && !c.contains("key_material"),
            "detected_credentials.{col} could hold a credential value"
        );
    }
    // And the column set is exactly what ADR 0029 D6 describes.
    assert_eq!(
        cols,
        vec![
            "id",
            "project_id",
            "env_var",
            "suggested_provider",
            "suggested_name",
            "suggested_environment",
            "source_kind",
            "source_file",
            "status",
            "resolved_credential_id",
            "first_detected_at",
            "last_detected_at",
            "row_version",
        ]
    );
}

#[test]
fn a_project_has_at_most_one_folder_link() {
    let conn = mem();
    conn.execute(
        "INSERT INTO project_folder_links (project_id, folder_path, linked_at)
         VALUES ('p1', '/a', '2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    let second = conn.execute(
        "INSERT INTO project_folder_links (project_id, folder_path, linked_at)
         VALUES ('p1', '/b', '2026-01-01T00:00:00Z')",
        [],
    );
    assert!(
        second.is_err(),
        "project_id is the PRIMARY KEY, so a second folder must be rejected"
    );
}

#[test]
fn an_unrecognized_detection_status_is_rejected() {
    let conn = mem();
    let bad = conn.execute(
        "INSERT INTO detected_credentials
            (id, project_id, env_var, source_kind, status, first_detected_at, last_detected_at)
         VALUES ('d1','p1','X','env_file','banana','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        [],
    );
    assert!(bad.is_err(), "the CHECK must keep an unknown status out");
}

#[test]
fn completed_without_its_credential_is_unrepresentable() {
    let conn = mem();
    let bad = conn.execute(
        "INSERT INTO detected_credentials
            (id, project_id, env_var, source_kind, status, first_detected_at, last_detected_at)
         VALUES ('d1','p1','X','env_file','completed','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        [],
    );
    assert!(
        bad.is_err(),
        "'completed' means the value is in the vault, so it needs the vault row"
    );
}

#[test]
fn the_same_variable_in_two_files_is_two_findings() {
    let conn = mem();
    let insert = |id: &str, file: &str| {
        conn.execute(
            "INSERT INTO detected_credentials
                (id, project_id, env_var, source_kind, source_file, status,
                 first_detected_at, last_detected_at)
             VALUES (?1,'p1','OPENAI_API_KEY','env_file',?2,'pending',
                     '2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
            rusqlite::params![id, file],
        )
    };
    insert("d1", ".env").unwrap();
    insert("d2", ".env.production").unwrap();
    assert!(insert("d3", ".env").is_err(), "the UNIQUE key must hold");
}

/// Foreign keys are enforced on every connection, so a child key without an
/// index makes SQLite full-scan the child once per deleted parent row — the cost
/// migration v14 exists to fix for `gateway_usage_events`.
#[test]
fn every_new_foreign_key_child_column_is_indexed() {
    let conn = mem();
    let indexed = |table: &str, column: &str| -> bool {
        let mut stmt = conn
            .prepare(&format!("SELECT name FROM pragma_index_list('{table}')"))
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        names.iter().any(|idx| {
            let mut s = conn
                .prepare(&format!("SELECT name FROM pragma_index_info('{idx}')"))
                .unwrap();
            let hit = s
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(Result::unwrap)
                .any(|c| c == column);
            hit
        })
    };
    assert!(indexed("detected_credentials", "project_id"));
    assert!(indexed("detected_credentials", "resolved_credential_id"));
    assert!(
        indexed("gateway_usage_events", "project_id"),
        "the project activity window needs a (project_id, at) index"
    );
    // Both tables are windowed by (project, time). v16's composite has
    // observation_source between the two columns a range needs, so it cannot
    // serve a query that does not also constrain the source — which is every
    // query the live surface issues.
    let composite = |table: &str, a: &str, b: &str| -> bool {
        let mut stmt = conn
            .prepare(&format!("SELECT name FROM pragma_index_list('{table}')"))
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        names.iter().any(|idx| {
            let mut s = conn
                .prepare(&format!("SELECT name FROM pragma_index_info('{idx}')"))
                .unwrap();
            let cols: Vec<String> = s
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            cols.len() >= 2 && cols[0] == a && cols[1] == b
        })
    };
    assert!(
        composite("runtime_request_events", "project_id", "at"),
        "the live series needs (project_id, at) with `at` immediately after"
    );
    assert!(
        composite("gateway_usage_events", "project_id", "at"),
        "the cost window needs (project_id, at) with `at` immediately after"
    );
}

#[test]
fn deleting_a_project_leaves_no_orphan_linkage_or_detection() {
    let conn = mem();
    conn.execute(
        "INSERT INTO project_folder_links (project_id, folder_path, linked_at)
         VALUES ('p1', '/a', '2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO detected_credentials
            (id, project_id, env_var, source_kind, status, first_detected_at, last_detected_at)
         VALUES ('d1','p1','X','env_file','pending','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    conn.execute("DELETE FROM projects WHERE id = 'p1'", [])
        .unwrap();
    let links: i64 = conn
        .query_row("SELECT COUNT(*) FROM project_folder_links", [], |r| {
            r.get(0)
        })
        .unwrap();
    let dets: i64 = conn
        .query_row("SELECT COUNT(*) FROM detected_credentials", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!((links, dets), (0, 0));
}

/// A v19 database with rows must upgrade without losing them.
#[test]
fn a_populated_v19_database_upgrades_to_v20() {
    let mut conn = Connection::open_in_memory().unwrap();
    // Versions are contiguous from 1 (asserted above), so the first 19 entries
    // ARE v1..v19 — the same released prefix `backup::restore` replays.
    db::migrate_with(&mut conn, &db::MIGRATIONS[..19]).unwrap();
    assert_eq!(db::user_version(&conn).unwrap(), 19);
    conn.execute(
        "INSERT INTO projects (id, name, created_at, updated_at, wrapped_project_key, key_wrap_mode)
         VALUES ('p1', 'web', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', X'00', 'vault')",
        [],
    )
    .unwrap();

    db::migrate(&mut conn).unwrap();
    assert_eq!(db::user_version(&conn).unwrap(), 20);
    let kept: i64 = conn
        .query_row("SELECT COUNT(*) FROM projects", [], |r| r.get(0))
        .unwrap();
    assert_eq!(kept, 1, "the upgrade must preserve existing rows");
    // And the new tables are usable immediately.
    conn.execute(
        "INSERT INTO project_folder_links (project_id, folder_path, linked_at)
         VALUES ('p1', '/a', '2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
}
