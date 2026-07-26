//! Gateway-side schema behavior: the exact-version open helper the service
//! depends on (KNOWN_CONFLICTS C15), concurrent desktop/CLI access, v13
//! failure atomicity, and the new enum encodings (TEST_PLAN §8).

use api_tracker_core::db;
use api_tracker_core::error::CoreError;
use api_tracker_core::runtime::model::{AttributionConfidence, ObservationSource};
use rusqlite::Connection;

#[test]
fn open_at_current_version_gates_every_schema_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");

    // Missing database: a distinct, actionable error (fresh boot with the
    // vault deleted must degrade recording, not create a stray file).
    match db::open_at_current_version(&path) {
        Err(CoreError::VaultNotFound(_)) => {}
        other => panic!("missing db must be VaultNotFound, got {other:?}"),
    }
    assert!(!path.exists(), "the check must not create the database");

    // Older schema (migrations pending): refused — the background service
    // never migrates (that is the enable/unlock flow's job).
    {
        let mut conn = db::open(&path).unwrap();
        let upto = db::MIGRATIONS.len() - 2;
        db::migrate_with(&mut conn, &db::MIGRATIONS[..=upto]).unwrap();
    }
    match db::open_at_current_version(&path) {
        Err(CoreError::SchemaNotCurrent { found, supported }) => {
            assert_eq!(found, db::MIGRATIONS[db::MIGRATIONS.len() - 2].version);
            assert_eq!(supported, db::current_schema_version());
        }
        other => panic!("older schema must be SchemaNotCurrent, got {other:?}"),
    }

    // Current schema: opens.
    {
        let mut conn = db::open(&path).unwrap();
        db::migrate(&mut conn).unwrap();
    }
    db::open_at_current_version(&path).expect("current schema must open");

    // Newer schema (this binary outlived by an app upgrade): refused.
    {
        let conn = db::open(&path).unwrap();
        conn.pragma_update(None, "user_version", db::current_schema_version() + 1)
            .unwrap();
    }
    match db::open_at_current_version(&path) {
        Err(CoreError::SchemaTooNew { .. }) => {}
        other => panic!("newer schema must be SchemaTooNew, got {other:?}"),
    }
}

#[test]
fn concurrent_connections_read_and_write_gateway_tables() {
    // The desktop app, CLI, and gateway writer share vault.db through WAL
    // with a busy timeout; concurrent gateway-table access must not error.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    {
        let mut conn = db::open(&path).unwrap();
        db::migrate(&mut conn).unwrap();
    }
    let writer = db::open(&path).unwrap();
    let reader = db::open(&path).unwrap();

    for i in 0..50 {
        api_tracker_gateway::store::bump_counter(
            &writer,
            "openai",
            "2026-07-26",
            "unlinked_requests",
            1,
        )
        .unwrap();
        let seen =
            api_tracker_gateway::store::counter_total(&reader, "openai", "unlinked_requests")
                .unwrap();
        assert_eq!(seen, i + 1, "reader must see committed writer state");
    }

    let config = api_tracker_gateway::store::load_config(&reader).unwrap();
    assert!(!config.enabled);
}

#[test]
fn v13_migration_failure_rolls_back_atomically() {
    // Simulate a v12 database where v13 cannot apply (a conflicting object
    // squats one of the new table names): the migration must fail loudly and
    // leave user_version at 12 — never a half-applied schema.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    {
        let mut conn = db::open(&path).unwrap();
        let v12 = db::MIGRATIONS
            .iter()
            .position(|m| m.version == 12)
            .expect("v12 exists");
        db::migrate_with(&mut conn, &db::MIGRATIONS[..=v12]).unwrap();
        conn.execute_batch("CREATE TABLE gateway_config (squatter TEXT);")
            .unwrap();
    }
    let mut conn = db::open(&path).unwrap();
    assert!(db::migrate(&mut conn).is_err(), "v13 must fail loudly");
    assert_eq!(db::user_version(&conn).unwrap(), 12);
    // None of the OTHER v13 objects exist (single-transaction rollback).
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='table' AND name IN
               ('gateway_routes', 'gateway_project_links', 'gateway_usage_events',
                'gateway_usage_daily', 'gateway_route_counters')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 0,
        "a failed v13 must leave no partial gateway schema"
    );
}

#[test]
fn new_enum_variants_have_stable_db_encodings() {
    assert_eq!(ObservationSource::Gateway.as_str(), "gateway");
    assert_eq!(
        ObservationSource::from_db("gateway"),
        Some(ObservationSource::Gateway)
    );
    // Existing encodings unchanged (compatibility).
    for (variant, s) in [
        (ObservationSource::Intercept, "intercept"),
        (ObservationSource::ConnectionOnly, "connection_only"),
        (ObservationSource::UpgradeThenOpaque, "upgrade_then_opaque"),
    ] {
        assert_eq!(variant.as_str(), s);
        assert_eq!(ObservationSource::from_db(s), Some(variant));
    }

    assert_eq!(
        AttributionConfidence::MatchedFingerprint.as_str(),
        "matched_fingerprint"
    );
    assert_eq!(
        AttributionConfidence::from_db("matched_fingerprint"),
        Some(AttributionConfidence::MatchedFingerprint)
    );
    // serde serializes as the db string.
    assert_eq!(
        serde_json::to_string(&ObservationSource::Gateway).unwrap(),
        "\"gateway\""
    );
    assert_eq!(
        serde_json::to_string(&AttributionConfidence::MatchedFingerprint).unwrap(),
        "\"matched_fingerprint\""
    );
}

#[test]
fn fresh_database_migrates_to_head_with_gateway_schema() {
    let mut conn = Connection::open_in_memory().unwrap();
    db::migrate(&mut conn).unwrap();
    assert_eq!(
        db::user_version(&conn).unwrap(),
        db::current_schema_version()
    );
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='table' AND name LIKE 'gateway_%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 6, "all six gateway tables exist on a fresh migrate");
}
