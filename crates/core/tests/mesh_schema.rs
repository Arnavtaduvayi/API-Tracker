//! Tethra Mesh storage schema (Increment 03, ADR 0031): migration v21, its
//! constraints, the background-process schema check, and what a backup
//! restore does to mesh state (MESH-SI-5). Fake data only; every database
//! lives in a temp directory.
//!
//! These live here, not in `migration_safety.rs`, because `scripts/smoke.sh`
//! pins that file at exactly nine tests.

mod common;

use api_tracker_core::backup;
use api_tracker_core::db;
use api_tracker_core::error::CoreError;
use api_tracker_core::mesh::dot::{DeviceId, MarkerNonce};
use api_tracker_core::mesh::marker::{self, MarkerContents, MarkerRemoval};
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, VaultPaths};
use common::{add_project, master_pw, new_vault};
use rusqlite::Connection;

fn db_at_version(path: &std::path::Path, version: i64) -> Connection {
    let mut conn = db::open(path).unwrap();
    let upto = db::MIGRATIONS
        .iter()
        .position(|m| m.version == version)
        .expect("known version");
    db::migrate_with(&mut conn, &db::MIGRATIONS[..=upto]).unwrap();
    conn
}

fn mesh_tables(conn: &Connection) -> Vec<String> {
    let mut st = conn
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name LIKE 'mesh\\_%' ESCAPE '\\' ORDER BY name",
        )
        .unwrap();
    st.query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |r| {
        r.get(0)
    })
    .unwrap()
}

const V21_TABLES: &[&str] = &[
    "mesh_access_keys",
    "mesh_cap_escrow",
    "mesh_dots",
    "mesh_exchange_log",
    "mesh_fork_evidence",
    "mesh_invites",
    "mesh_items",
    "mesh_meta",
    "mesh_peers",
    "mesh_project_bindings",
    "mesh_publish_cursor",
    "mesh_self",
    "mesh_share_imports",
    "mesh_vv",
];

#[test]
fn v21_applies_on_a_populated_v20_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v20.db");
    {
        let conn = db_at_version(&path, 20);
        conn.execute_batch(
            "INSERT INTO projects (id, name, description, notes, environments, archived,
                 created_at, updated_at, wrapped_project_key, key_wrap_mode)
             VALUES ('p1', 'app', '', '', 'development', 0,
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', x'00112233', 'vault');
             INSERT INTO gateway_config (id, enabled, port, created_at, updated_at)
             VALUES ('gateway', 1, 49723, '2026-07-26T00:00:00Z', '2026-07-26T00:00:00Z');",
        )
        .unwrap();
        assert!(mesh_tables(&conn).is_empty());
    }
    let mut conn = db::open(&path).unwrap();
    db::migrate(&mut conn).unwrap();
    assert!(db::user_version(&conn).unwrap() >= 21);
    assert_eq!(mesh_tables(&conn), V21_TABLES);
    // Existing rows survive; the new switch defaults to off.
    let (name, port, enforcement): (String, i64, i64) = conn
        .query_row(
            "SELECT p.name, g.port, g.cap_enforcement FROM projects p, gateway_config g",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((name.as_str(), port, enforcement), ("app", 49723, 0));
}

#[test]
fn every_mesh_table_is_strict() {
    let (_dir, _paths, v) = new_vault();
    let conn = v.connection();
    for t in mesh_tables(conn) {
        let strict: i64 = conn
            .query_row(
                "SELECT strict FROM pragma_table_list WHERE name = ?1",
                [&t],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(strict, 1, "{t} must be STRICT");
    }
    // STRICT means wrong types are refused, not coerced.
    let err = conn.execute(
        "INSERT INTO mesh_vv (origin, max_seq) VALUES ('0123456789abcdef0123456789abcdef', 'x')",
        [],
    );
    assert!(err.is_err());
}

#[test]
fn enum_and_shape_checks_reject_bad_values() {
    let (_dir, _paths, v) = new_vault();
    let conn = v.connection();
    let id = "0123456789abcdef0123456789abcdef";
    let rejected = [
        "INSERT INTO mesh_peers (addr, source) VALUES ('127.0.0.1:1', 'carrier-pigeon')".to_owned(),
        format!(
            "INSERT INTO mesh_cap_escrow (id, cap_id, month, to_device, amount_micros, state,
                 created_at, updated_at)
             VALUES ('e1', '{id}', '2026-10', 'burn', 5, 'lost', 'x', 'x')"
        ),
        format!(
            "INSERT INTO mesh_cap_escrow (id, cap_id, month, to_device, amount_micros, state,
                 created_at, updated_at)
             VALUES ('e2', '{id}', '2026-10', 'burn', 0, 'pending', 'x', 'x')"
        ),
        "INSERT INTO mesh_exchange_log (at, direction, result) VALUES ('x', 'sideways', 'ok')"
            .to_owned(),
        "INSERT INTO mesh_exchange_log (at, direction, result) VALUES ('x', 'inbound', 'meh')"
            .to_owned(),
        format!("INSERT INTO mesh_vv (origin, max_seq) VALUES ('{id}', 0)"),
        "INSERT INTO mesh_vv (origin, max_seq) VALUES ('short', 1)".to_owned(),
        format!(
            "INSERT INTO mesh_dots (origin, seq, hash, chain) VALUES ('{id}', 1, x'00', x'00')"
        ),
        "INSERT INTO mesh_access_keys (epoch, wrapped_key, created_at) VALUES (0, x'00', 'x')"
            .to_owned(),
        "INSERT INTO gateway_config (id, enabled, cap_enforcement, created_at, updated_at)
         VALUES ('gateway', 0, 2, 'x', 'x')"
            .to_owned(),
    ];
    for sql in &rejected {
        assert!(conn.execute(sql, []).is_err(), "accepted: {sql}");
    }
    // The state enum on the identity row.
    let mut ok = format!(
        "INSERT INTO mesh_self (id, mesh_id, genesis_device, device_id, device_name, sign_pub,
             noise_pub, seal_pub, wrapped_sign_key, wrapped_noise_key, wrapped_seal_key,
             access_key_epoch, marker_nonce, state, created_at)
         VALUES ('self', '{id}', '{id}', '{id}', 'dev', '{k}', '{k}', '{k}', x'00', x'00',
             x'00', 1, '{id}', 'STATE', 'x')",
        k = "a".repeat(64)
    );
    assert!(conn.execute(&ok.replace("STATE", "dormant"), []).is_err());
    ok = ok.replace("STATE", "active");
    conn.execute(&ok, []).unwrap();
    // At most one identity row.
    assert!(conn.execute(&ok.replace("'self'", "'other'"), []).is_err());
}

#[test]
fn deleting_a_local_project_unbinds_it() {
    let (_dir, _paths, mut v) = new_vault();
    let project = add_project(&mut v, "app");
    let conn = v.connection();
    conn.execute(
        "INSERT INTO mesh_project_bindings (local_project_id, mesh_project_id, bound_at)
         VALUES (?1, '0123456789abcdef0123456789abcdef', 'x')",
        [&project.id],
    )
    .unwrap();
    assert_eq!(count(conn, "mesh_project_bindings"), 1);
    conn.execute("DELETE FROM projects WHERE id = ?1", [&project.id])
        .unwrap();
    assert_eq!(count(conn, "mesh_project_bindings"), 0);
}

#[test]
fn background_processes_accept_v21_and_refuse_an_unmigrated_database() {
    let (_dir, paths, v) = new_vault();
    drop(v);
    let conn = db::open_at_current_version(&paths.db_path()).unwrap();
    assert_eq!(
        db::user_version(&conn).unwrap(),
        db::current_schema_version()
    );
    // An installed gateway from before v21 sees a newer schema and refuses
    // (the documented upgrade behaviour); the mirror image is a v20 file
    // under this build, which it also refuses rather than migrating.
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("v20.db");
    drop(db_at_version(&old, 20));
    assert!(matches!(
        db::open_at_current_version(&old),
        Err(CoreError::SchemaNotCurrent { found: 20, .. })
    ));
}

/// Fill every local-only mesh table with a row, on a vault in a mesh.
fn populate_mesh(v: &vault::UnlockedVault, project_id: &str) {
    v.mesh_init("source-device").unwrap();
    v.connection()
        .execute_batch(&format!(
            "INSERT INTO mesh_peers (addr, source) VALUES ('127.0.0.1:7420', 'manual');
             INSERT INTO mesh_invites (token_hash, created_at, expires_at)
             VALUES (x'{h}', 'x', 'x');
             INSERT INTO mesh_project_bindings (local_project_id, mesh_project_id, bound_at)
             VALUES ('{project_id}', '{id}', 'x');
             INSERT INTO mesh_publish_cursor (local_project_id, day, provider_id, model,
                 requests, updated_at)
             VALUES ('{project_id}', '2026-10-27', 'openai', 'gpt-x', 3, 'x');
             INSERT INTO mesh_cap_escrow (id, cap_id, month, to_device, amount_micros, state,
                 created_at, updated_at)
             VALUES ('e1', '{id}', '2026-10', 'burn', 5, 'pending', 'x', 'x');
             INSERT INTO mesh_exchange_log (at, direction, result)
             VALUES ('x', 'outbound', 'ok');
             INSERT INTO gateway_config (id, enabled, cap_enforcement, created_at, updated_at)
             VALUES ('gateway', 1, 1, 'x', 'x');",
            h = "ab".repeat(32),
            id = "0123456789abcdef0123456789abcdef",
        ))
        .unwrap();
}

#[test]
fn backup_then_restore_wipes_mesh_state_and_mints_nothing() {
    let (dir, paths, mut v) = new_vault();
    let project = add_project(&mut v, "app");
    populate_mesh(&v, &project.id);
    let source_marker = marker::read(&paths.data_dir).unwrap().unwrap();
    for t in V21_TABLES {
        if !["mesh_fork_evidence", "mesh_share_imports"].contains(t) {
            assert!(count(v.connection(), t) > 0, "{t} is populated");
        }
    }
    let backup_pw = SecretString::from("mesh-backup-password-01");
    let file = dir.path().join("mesh.backup");
    backup::create_backup(&v, &file, &backup_pw, false).unwrap();

    let target = VaultPaths::new(dir.path().join("restored"));
    let info = backup::restore_backup(&file, &backup_pw, &target, false).unwrap();
    let wipe = info.mesh_wipe.unwrap();
    assert_eq!(wipe.identity, Some(source_marker.device_id));
    assert!(wipe.rows_deleted > 0);
    assert_eq!(wipe.marker, MarkerRemoval::Absent, "a fresh directory");

    let restored = vault::unlock_vault(&target, &master_pw()).unwrap();
    let conn = restored.connection();
    for t in mesh_tables(conn) {
        assert_eq!(count(conn, &t), 0, "{t} survived the restore");
    }
    let enforcement: i64 = conn
        .query_row("SELECT cap_enforcement FROM gateway_config", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(enforcement, 0, "enforcement is local and starts off");
    assert!(!restored.mesh_status().unwrap().initialized);
    assert!(marker::read(&target.data_dir).unwrap().is_none());
    let audited: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE event = 'mesh_identity_wiped'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(audited, 1);
    // The source is untouched: still in its mesh, marker in place.
    assert!(v.mesh_status().unwrap().initialized);
    assert_eq!(marker::read(&paths.data_dir).unwrap(), Some(source_marker));
    // And the restored vault can start a new mesh with a new identity.
    let fresh = restored.mesh_init("restored-device").unwrap();
    assert_ne!(fresh.device_id, source_marker.device_id);
}

#[test]
fn restore_removes_the_marker_only_when_it_names_the_wiped_identity() {
    let (dir, paths, v) = new_vault();
    v.mesh_init("device-a").unwrap();
    let mine = marker::read(&paths.data_dir).unwrap().unwrap();
    let backup_pw = SecretString::from("mesh-backup-password-02");
    let file = dir.path().join("a.backup");
    backup::create_backup(&v, &file, &backup_pw, false).unwrap();
    drop(v);

    // Restoring this device's own backup over itself: the marker names the
    // wiped identity, so it goes.
    let info = backup::restore_backup(&file, &backup_pw, &paths, true).unwrap();
    assert_eq!(info.mesh_wipe.unwrap().marker, MarkerRemoval::Removed);
    assert!(marker::read(&paths.data_dir).unwrap().is_none());

    // Restoring it into a directory whose marker names another identity:
    // left in place, and reported.
    let other = VaultPaths::new(dir.path().join("other"));
    std::fs::create_dir_all(&other.data_dir).unwrap();
    let foreign = MarkerContents::new(
        DeviceId::from_bytes([3; 16]),
        MarkerNonce::from_bytes([3; 16]),
        64,
    );
    marker::write(&other.data_dir, &foreign).unwrap();
    let info = backup::restore_backup(&file, &backup_pw, &other, false).unwrap();
    let wipe = info.mesh_wipe.unwrap();
    assert_eq!(wipe.identity, Some(mine.device_id));
    assert_eq!(wipe.marker, MarkerRemoval::LeftInPlace);
    assert_eq!(marker::read(&other.data_dir).unwrap(), Some(foreign));
}
