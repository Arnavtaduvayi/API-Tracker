//! Route table and SSRF tests (TEST_PLAN §3): manifest seeding, custom
//! origins, MAC tamper-evidence, locked startup, disabled/duplicate routes,
//! reload-on-change, and last-known-good retention.

use api_tracker_core::error::CoreError;
use api_tracker_core::secret::SecretBytes;
use api_tracker_core::{db, providers};
use api_tracker_gateway::routes::{self, RouteTarget, Unforwardable};
use rusqlite::Connection;

fn migrated(path: &std::path::Path) -> Connection {
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

fn mac_key() -> SecretBytes {
    SecretBytes::new(vec![9u8; 32])
}

#[test]
fn manifest_seeding_resolves_openai_and_anthropic_from_compiled_manifests() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    routes::add_manifest_route(&conn, "openai", "openai").unwrap();
    routes::add_manifest_route(&conn, "anthropic", "anthropic").unwrap();

    let table = routes::load_route_table(&conn, None).unwrap();
    let openai = table.route("openai").expect("openai route");
    match &openai.target {
        RouteTarget::Ready(origin) => {
            assert_eq!(origin.host, "api.openai.com");
            assert_eq!(origin.port, 443);
        }
        other => panic!("manifest route must be ready, got {other:?}"),
    }
    assert_eq!(openai.usage_shape, "openai");
    assert!(!openai.custom);
    let anthropic = table.route("anthropic").expect("anthropic route");
    match &anthropic.target {
        RouteTarget::Ready(origin) => assert_eq!(origin.host, "api.anthropic.com"),
        other => panic!("expected ready, got {other:?}"),
    }
    assert_eq!(anthropic.usage_shape, "anthropic");

    // The manifests themselves declare the client-side .env shape.
    let m = providers::find("openai").unwrap();
    let g = m.gateway.as_ref().unwrap();
    assert_eq!(g.base_path, "/v1");
    assert!(g.env_vars.contains(&"OPENAI_BASE_URL".to_string()));
    let m = providers::find("anthropic").unwrap();
    assert_eq!(m.gateway.as_ref().unwrap().base_path, "");

    // Providers without a fixed origin refuse manifest routes honestly.
    match routes::add_manifest_route(&conn, "supa", "supabase") {
        Err(CoreError::Unsupported { .. }) => {}
        other => panic!("supabase has no [gateway]; got {other:?}"),
    }
}

#[test]
fn a_direct_update_of_a_manifest_route_row_cannot_redirect_it() {
    // The route-row-tampering blocker (ADR 0019 D3): origins are never
    // obeyed from the DB for manifest routes.
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    routes::add_manifest_route(&conn, "openai", "openai").unwrap();

    // The CHECK constraints refuse a partial custom-origin write...
    assert!(conn
        .execute(
            "UPDATE gateway_routes SET custom_origin = 'evil.example.com'
             WHERE route_prefix = 'openai'",
            [],
        )
        .is_err());

    // ...and rewriting provider_id points at the compiled-in manifest of
    // that provider (or nothing), never at an attacker string.
    conn.execute(
        "UPDATE gateway_routes SET provider_id = 'evil' WHERE route_prefix = 'openai'",
        [],
    )
    .unwrap();
    let table = routes::load_route_table(&conn, None).unwrap();
    assert!(
        table.route("openai").is_none(),
        "unknown provider loads nothing"
    );
    assert!(table
        .skipped
        .iter()
        .any(|(p, why)| p == "openai" && why.contains("unknown provider")));
}

#[test]
fn custom_routes_are_mac_bound_and_tamper_evident() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    let key = mac_key();
    routes::add_custom_route(&conn, "supa", "supabase", "https://myref.supabase.co", &key).unwrap();

    // With the key: ready.
    let table = routes::load_route_table(&conn, Some(&key)).unwrap();
    match &table.route("supa").unwrap().target {
        RouteTarget::Ready(origin) => assert_eq!(origin.host, "myref.supabase.co"),
        other => panic!("expected ready, got {other:?}"),
    }

    // Locked startup (no key pushed yet): present but unforwardable — 503,
    // while manifest routes would keep forwarding.
    let table = routes::load_route_table(&conn, None).unwrap();
    assert_eq!(
        table.route("supa").unwrap().target,
        RouteTarget::Unforwardable(Unforwardable::MacKeyUnavailable)
    );

    // Tamper with the origin: the MAC no longer verifies. Forwards nowhere.
    conn.execute(
        "UPDATE gateway_routes SET custom_origin = 'attacker.example.com'
         WHERE route_prefix = 'supa'",
        [],
    )
    .unwrap();
    let table = routes::load_route_table(&conn, Some(&key)).unwrap();
    assert_eq!(
        table.route("supa").unwrap().target,
        RouteTarget::Unforwardable(Unforwardable::MacMismatch)
    );

    // Same for every other MAC-bound field.
    conn.execute(
        "UPDATE gateway_routes SET custom_origin = 'myref.supabase.co',
             custom_origin_consent_at = '2020-01-01T00:00:00Z'
         WHERE route_prefix = 'supa'",
        [],
    )
    .unwrap();
    let table = routes::load_route_table(&conn, Some(&key)).unwrap();
    assert_eq!(
        table.route("supa").unwrap().target,
        RouteTarget::Unforwardable(Unforwardable::MacMismatch)
    );

    // A wrong key never verifies either.
    let table = routes::load_route_table(&conn, Some(&SecretBytes::new(vec![7u8; 32]))).unwrap();
    assert_eq!(
        table.route("supa").unwrap().target,
        RouteTarget::Unforwardable(Unforwardable::MacMismatch)
    );
}

#[test]
fn a_valid_mac_over_a_denied_origin_still_does_not_forward() {
    // Defense in depth: even a correctly-MAC'd row is re-checked against the
    // destination policy at load. Forge the row directly with a "valid" MAC
    // over a loopback origin.
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    let key = mac_key();
    let mac = routes::route_mac(
        &key,
        "vault-test-0001",
        "supabase",
        "127.0.0.1",
        443,
        "2026-07-26T00:00:00Z",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, custom_origin,
             custom_origin_port, custom_origin_mac, custom_origin_consent_at,
             created_at, updated_at)
         VALUES ('supa', 'supabase', 1, '127.0.0.1', 443, ?1,
             '2026-07-26T00:00:00Z', '2026-07-26T00:00:00Z', '2026-07-26T00:00:00Z')",
        rusqlite::params![&mac[..]],
    )
    .unwrap();
    let table = routes::load_route_table(&conn, Some(&key)).unwrap();
    assert!(table.route("supa").is_none(), "denied origin must not load");
    assert!(table.skipped.iter().any(|(p, _)| p == "supa"));
}

#[test]
fn origin_validation_rejects_every_unsafe_shape() {
    for bad in [
        "http://api.openai.com",            // not https
        "https://api.openai.com:8443",      // non-443 port
        "https://127.0.0.1",                // loopback
        "https://[::1]",                    // v6 loopback
        "https://10.0.0.5",                 // RFC1918
        "https://169.254.169.254",          // link-local / metadata IP
        "https://100.64.0.1",               // CGNAT
        "https://metadata.google.internal", // metadata name
        "https://api.openai.com/v1",        // path not allowed
        "https://api.openai.com?x=1",       // query not allowed
        "https://api.openai.com#f",         // fragment not allowed
        "https://user@api.openai.com",      // userinfo not allowed
        "https://user:pw@api.openai.com",   // userinfo not allowed
        "https://",                         // empty host
        "https://internal",                 // single-label name
        "https://printer.local",            // mDNS
    ] {
        assert!(
            routes::validate_origin(bad).is_err(),
            "{bad} must be rejected"
        );
    }
    assert_eq!(
        routes::validate_origin("https://api.openai.com").unwrap(),
        ("api.openai.com".to_string(), 443)
    );
    assert_eq!(
        routes::validate_origin("https://api.anthropic.com:443").unwrap(),
        ("api.anthropic.com".to_string(), 443)
    );
}

#[test]
fn prefix_validation_rejects_reserved_and_malformed_prefixes() {
    for bad in [
        "",
        "p",
        "_tethra",
        "P",
        "open ai",
        "open/ai",
        "-x",
        "9x",
        "openai?",
        "a-very-long-prefix-that-goes-past-the-limit",
    ] {
        assert!(
            routes::validate_route_prefix(bad).is_err(),
            "prefix '{bad}' must be rejected"
        );
    }
    routes::validate_route_prefix("openai").unwrap();
    routes::validate_route_prefix("my-supabase2").unwrap();
}

#[test]
fn duplicate_disabled_and_removed_routes_behave() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    routes::add_manifest_route(&conn, "openai", "openai").unwrap();
    match routes::add_manifest_route(&conn, "openai", "openai") {
        Err(CoreError::AlreadyExists { .. }) => {}
        other => panic!("duplicate prefix must be rejected, got {other:?}"),
    }

    assert!(routes::set_route_enabled(&conn, "openai", false).unwrap());
    let table = routes::load_route_table(&conn, None).unwrap();
    assert!(
        table.route("openai").is_none(),
        "disabled routes match nothing"
    );
    assert_eq!(
        table.disabled, 1,
        "status must be able to tell 'disabled' apart from 'removed'"
    );

    assert!(routes::set_route_enabled(&conn, "openai", true).unwrap());
    let table = routes::load_route_table(&conn, None).unwrap();
    assert!(table.route("openai").is_some());
    assert_eq!(table.disabled, 0);

    assert!(routes::remove_route(&conn, "openai").unwrap());
    assert!(!routes::remove_route(&conn, "openai").unwrap());
    let table = routes::load_route_table(&conn, None).unwrap();
    assert!(table.is_empty());
    assert_eq!(table.disabled, 0, "a removed route is not 'disabled'");
}

#[test]
fn project_links_use_128_bit_random_slugs_and_cascade_with_routes() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    routes::add_manifest_route(&conn, "openai", "openai").unwrap();

    let slug = routes::add_project_link(&conn, "p1", "openai").unwrap();
    assert_eq!(slug.len(), 32, "16 CSPRNG bytes hex-encoded");
    assert!(slug.chars().all(|c| c.is_ascii_hexdigit()));

    let slug2 = routes::add_project_link(&conn, "p1", "openai");
    match slug2 {
        Err(CoreError::AlreadyExists { .. }) => {}
        other => panic!("double link must be rejected, got {other:?}"),
    }
    match routes::add_project_link(&conn, "p1", "missing") {
        Err(CoreError::NotFound { .. }) => {}
        other => panic!("link to unknown route must be rejected, got {other:?}"),
    }

    let table = routes::load_route_table(&conn, None).unwrap();
    let link = table.link(&slug).expect("slug resolves");
    assert_eq!(link.project_id, "p1");
    assert_eq!(link.route_prefix, "openai");

    // Removing the route cascades the link away.
    routes::remove_route(&conn, "openai").unwrap();
    let table = routes::load_route_table(&conn, None).unwrap();
    assert!(table.link(&slug).is_none());
}

#[test]
fn route_state_polls_changes_and_keeps_last_known_good() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    let conn = migrated(&db_path);
    routes::add_manifest_route(&conn, "openai", "openai").unwrap();

    let state = routes::RouteState::new(&db_path);
    assert!(!state.degraded());
    assert!(state.table().route("openai").is_some());

    // Another connection commits a change; polling picks it up.
    routes::add_manifest_route(&conn, "anthropic", "anthropic").unwrap();
    state.reload_if_changed();
    assert!(state.table().route("anthropic").is_some());

    // Deleted route stops matching after the poll.
    routes::remove_route(&conn, "anthropic").unwrap();
    state.reload_if_changed();
    assert!(state.table().route("anthropic").is_none());

    // Database vanishes (vault deleted / replaced): forwarding must keep the
    // last-known-good snapshot and flag degraded.
    drop(conn);
    std::fs::remove_file(&db_path).unwrap();
    std::fs::remove_file(dir.path().join("vault.db-wal")).ok();
    std::fs::remove_file(dir.path().join("vault.db-shm")).ok();
    state.reload();
    assert!(state.degraded());
    assert!(
        state.table().route("openai").is_some(),
        "last-known-good table must survive DB loss"
    );
}

#[test]
fn concurrent_route_updates_never_corrupt_the_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("vault.db");
    {
        let conn = migrated(&db_path);
        routes::add_manifest_route(&conn, "openai", "openai").unwrap();
    }
    let state = std::sync::Arc::new(routes::RouteState::new(&db_path));

    let writer = {
        let db_path = db_path.clone();
        std::thread::spawn(move || {
            let conn = db::open(&db_path).unwrap();
            for i in 0..20 {
                let prefix = format!("r{i}");
                routes::add_manifest_route(&conn, &prefix, "anthropic").unwrap();
                if i % 2 == 0 {
                    routes::set_route_enabled(&conn, &prefix, false).unwrap();
                }
            }
        })
    };
    let poller = {
        let state = state.clone();
        std::thread::spawn(move || {
            for _ in 0..50 {
                state.reload_if_changed();
                // Every observed snapshot is internally consistent: any
                // present route resolves to a validated target.
                let table = state.table();
                for route in table.iter_routes() {
                    match &route.target {
                        RouteTarget::Ready(o) => assert_eq!(o.port, 443),
                        RouteTarget::Unforwardable(_) => {}
                    }
                }
                std::thread::yield_now();
            }
        })
    };
    writer.join().unwrap();
    poller.join().unwrap();
    state.reload();
    let table = state.table();
    assert!(table.route("openai").is_some());
    assert!(table.route("r1").is_some());
    assert!(table.route("r0").is_none(), "disabled while iterating");
}

#[test]
fn writes_are_audited() {
    let dir = tempfile::tempdir().unwrap();
    let conn = migrated(&dir.path().join("vault.db"));
    routes::add_manifest_route(&conn, "openai", "openai").unwrap();
    let slug = routes::add_project_link(&conn, "p1", "openai").unwrap();
    routes::remove_project_link(&conn, "p1", "openai").unwrap();
    routes::remove_route(&conn, "openai").unwrap();
    let events: Vec<String> = conn
        .prepare("SELECT event FROM audit_events ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    for expected in [
        "gateway_route_added",
        "gateway_project_linked",
        "gateway_project_unlinked",
        "gateway_route_removed",
    ] {
        assert!(
            events.iter().any(|e| e == expected),
            "missing audit {expected}"
        );
    }
    // The audit detail carries identifiers only — never the slug (it is a
    // routing capability) and never secret material.
    let details: Vec<String> = conn
        .prepare("SELECT detail FROM audit_events")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(!details.iter().any(|d| d.contains(&slug)));
}
