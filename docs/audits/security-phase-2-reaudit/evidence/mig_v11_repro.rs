//! Independent re-audit reproduction: migration v11 on a REAL pre-v11 fixture.
//! Uses the actual core migration code (api_tracker_core::db) — not a copy.

use api_tracker_core::db::{self, MIGRATIONS};
use api_tracker_core::inject::{terminate_verified, TerminationOutcome};
use rusqlite::Connection;

fn cols(conn: &Connection, table: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .unwrap();
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows
}

fn uv(conn: &Connection) -> i64 {
    db::user_version(conn).unwrap()
}

fn main() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prev11.sqlite");
    let mut conn = Connection::open(&path).unwrap();
    conn.pragma_update(None, "foreign_keys", 0).unwrap();

    // ---- Build a REAL pre-v11 (v10) database via the actual migration code.
    assert_eq!(MIGRATIONS.len(), 11, "expected 11 migrations at HEAD");
    db::migrate_with(&mut conn, &MIGRATIONS[..10]).unwrap();
    assert_eq!(uv(&conn), 10, "fixture must be at schema v10");
    let before = cols(&conn, "process_sessions");
    assert!(
        !before.contains(&"proc_identity".to_string()),
        "v10 must NOT have proc_identity yet; had {before:?}"
    );
    assert!(
        before.contains(&"pid".to_string()) && before.contains(&"grant_id".to_string()),
        "v10 process_sessions must already have pid+grant_id (v6); had {before:?}"
    );

    // ---- Insert a realistic pre-v11 running session row (a dead launcher's
    //      leftover: open row, recorded pid, no identity column at all).
    conn.execute(
        "INSERT INTO process_sessions
            (id, project_id, started_at, command, injected_vars, pid, grant_id)
         VALUES ('sess-legacy','proj','2026-01-01T00:00:00Z','demo','OPENAI_API_KEY',4242,'grant-1')",
        [],
    )
    .unwrap();

    // ---- Migrate the real fixture forward to v11 (full migrate()).
    db::migrate(&mut conn).unwrap();
    assert_eq!(uv(&conn), 11, "must reach v11");
    assert_eq!(uv(&conn), db::current_schema_version(), "== current version");
    let after = cols(&conn, "process_sessions");
    assert!(
        after.contains(&"proc_identity".to_string()),
        "v11 must add proc_identity; had {after:?}"
    );

    // ---- No data loss; the migrated legacy row is intact; identity is NULL.
    let (pid, grant, cmd, injected, ident): (i64, String, String, String, Option<String>) = conn
        .query_row(
            "SELECT pid, grant_id, command, injected_vars, proc_identity
               FROM process_sessions WHERE id='sess-legacy'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(pid, 4242);
    assert_eq!(grant, "grant-1");
    assert_eq!(cmd, "demo");
    assert_eq!(injected, "OPENAI_API_KEY");
    assert_eq!(ident, None, "pre-v11 row must have NULL proc_identity");

    // ---- A migrated pre-v11 row (NULL identity) is REFUSED termination.
    let outcome = terminate_verified(pid, ident.as_deref());
    assert!(
        matches!(outcome, TerminationOutcome::Refused { .. }),
        "pre-v11 row without identity must be refused, got {outcome:?}"
    );

    // ---- Idempotency: re-running migrate at v11 is a clean no-op.
    db::migrate(&mut conn).unwrap();
    assert_eq!(uv(&conn), 11);

    // ---- Reopen the file (simulate a restart) and migrate again: no-op, data intact.
    drop(conn);
    let mut conn2 = Connection::open(&path).unwrap();
    db::migrate(&mut conn2).unwrap();
    assert_eq!(uv(&conn2), 11);
    let n: i64 = conn2
        .query_row("SELECT count(*) FROM process_sessions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "row survived restart+remigrate");

    // ---- Schema-too-new refusal: a DB stamped v99 must be refused, not written.
    let dir2 = tempfile::tempdir().unwrap();
    let mut newer = Connection::open(dir2.path().join("newer.sqlite")).unwrap();
    db::migrate(&mut newer).unwrap();
    newer.pragma_update(None, "user_version", 99i64).unwrap();
    match db::migrate(&mut newer) {
        Err(e) => {
            let s = format!("{e:?}");
            assert!(s.contains("SchemaTooNew"), "expected SchemaTooNew, got {s}");
            println!("schema-too-new correctly refused: {s}");
        }
        Ok(()) => panic!("a v99 DB must be refused as schema-too-new"),
    }

    println!("MIG-V11-REPRO: ALL ASSERTIONS PASSED");
}
