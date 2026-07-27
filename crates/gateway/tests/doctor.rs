//! Doctor-engine tests: every diagnosis is derived from injected or
//! temp-dir state — the host machine's real service registration is never
//! consulted (that is `diagnose_with`'s reason to exist).

use std::path::Path;

use api_tracker_core::db;
use api_tracker_gateway::doctor::{self, Severity};
use api_tracker_gateway::lifecycle::{OsWillRun, ServiceStatus};
#[cfg(unix)]
use api_tracker_gateway::service::Service;
use api_tracker_gateway::{control, routes, store};
use rusqlite::Connection;

fn uninstalled_service() -> ServiceStatus {
    ServiceStatus {
        platform: "macos-launch-agent",
        installed: false,
        definition_path: "/tmp/none.plist".into(),
        definition: None,
        matches_data_dir: false,
        binary_exists: false,
        binary_version: None,
        registered: false,
        running: false,
        pid: None,
        os_will_run: OsWillRun::No,
        owned_artifacts: vec![],
        notes: vec![],
    }
}

fn installed_service(data_dir: &Path) -> ServiceStatus {
    ServiceStatus {
        installed: true,
        matches_data_dir: true,
        binary_exists: true,
        binary_version: Some(env!("CARGO_PKG_VERSION").into()),
        registered: true,
        os_will_run: OsWillRun::Yes,
        definition: Some(api_tracker_gateway::lifecycle::Definition {
            binary: data_dir.join("bin/tethra-gateway-x"),
            data_dir: data_dir.to_path_buf(),
        }),
        ..uninstalled_service()
    }
}

fn vault_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
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

fn ids(report: &doctor::Doctor) -> Vec<&'static str> {
    report.findings.iter().map(|f| f.id).collect()
}

#[test]
fn an_empty_directory_diagnoses_as_not_installed() {
    let dir = vault_dir();
    let report = doctor::diagnose_with(dir.path(), uninstalled_service());
    assert!(ids(&report).contains(&"not_installed"));
    assert!(ids(&report).contains(&"database_unavailable"));
    assert!(report.gateway.is_none());
}

#[test]
fn installed_but_stopped_and_linked_projects_at_risk_are_diagnosed() {
    let dir = vault_dir();
    let conn = migrated(&dir.path().join("vault.db"));
    routes::add_manifest_route(&conn, "openai", "openai").unwrap();
    let mut config = store::load_config(&conn).unwrap();
    config.port = Some(49_723);
    config.enabled = false;
    store::save_config(&conn, &config).unwrap();

    // A linked project whose .env points at the (stopped) gateway.
    let env = dir.path().join("app.env");
    std::fs::write(&env, "").unwrap();
    let req = api_tracker_gateway::envlink::LinkRequest {
        project_id: "p1".into(),
        project_name: "app".into(),
        route_prefix: "openai".into(),
        project_dir: None,
        files: vec![env.clone()],
        var_override: None,
    };
    let plan = api_tracker_gateway::envlink::plan_link(&conn, &req).unwrap();
    api_tracker_gateway::envlink::apply_link(&conn, &req, &plan).unwrap();
    drop(conn);

    let report = doctor::diagnose_with(dir.path(), installed_service(dir.path()));
    let found = ids(&report);
    assert!(found.contains(&"installed_but_stopped"), "{found:?}");
    assert!(found.contains(&"linked_projects_at_risk"), "{found:?}");
    assert!(report.links[0]
        .issues
        .iter()
        .any(|i| i.contains("connection-refused")));
    assert!(report.overall >= Severity::Warn);
}

// The control channel is Unix-only (SI-21: Windows refuses rather than
// TCP-fallback), so a diagnosis of a LIVE gateway can only be exercised on
// Unix. Windows coverage is the compile of this file plus the injected-state
// tests above.
#[cfg(unix)]
#[test]
fn a_live_gateway_reports_running_forwarding_and_recording() {
    let dir = vault_dir();
    let conn = migrated(&dir.path().join("vault.db"));
    routes::add_manifest_route(&conn, "openai", "openai").unwrap();
    drop(conn);

    let service = Service::start(dir.path(), 0).unwrap();
    let port = service.port();
    let conn = db::open(&dir.path().join("vault.db")).unwrap();
    let mut config = store::load_config(&conn).unwrap();
    config.port = Some(port);
    config.enabled = true;
    store::save_config(&conn, &config).unwrap();
    drop(conn);

    let report = doctor::diagnose_with(dir.path(), installed_service(dir.path()));
    let found = ids(&report);
    assert!(found.contains(&"running"), "{found:?}");
    assert!(found.contains(&"forwarding_active"), "{found:?}");
    assert!(found.contains(&"recording_active"), "{found:?}");
    assert!(
        found.contains(&"vault_locked_attribution"),
        "no key pushed → attribution off: {found:?}"
    );
    assert!(matches!(
        report.listener,
        Some(control::ListenerIdentity::Verified { .. })
    ));

    drop(service);
}

#[test]
fn a_port_squatter_is_a_port_collision_error() {
    let dir = vault_dir();
    let conn = migrated(&dir.path().join("vault.db"));
    // Persist a port, then let a FOREIGN listener squat on it.
    let squatter = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = squatter.local_addr().unwrap().port();
    let mut config = store::load_config(&conn).unwrap();
    config.port = Some(port);
    store::save_config(&conn, &config).unwrap();
    drop(conn);
    // A nonce file exists (as after a crash), so verification runs and fails.
    control::write_nonce(dir.path()).unwrap();

    let report = doctor::diagnose_with(dir.path(), uninstalled_service());
    let found = ids(&report);
    assert!(found.contains(&"port_collision"), "{found:?}");
    assert_eq!(report.overall, Severity::Error);
    let f = report
        .findings
        .iter()
        .find(|f| f.id == "port_collision")
        .unwrap();
    assert!(f.repair.is_some(), "collisions must carry a repair action");
}

#[cfg(unix)]
#[test]
fn a_stale_nonce_diagnoses_control_auth_failure_and_stale_paths_are_reported() {
    let dir = vault_dir();
    let conn = migrated(&dir.path().join("vault.db"));
    drop(conn);
    let service = Service::start(dir.path(), 0).unwrap();
    let port = service.port();
    let conn = db::open(&dir.path().join("vault.db")).unwrap();
    let mut config = store::load_config(&conn).unwrap();
    config.port = Some(port);
    store::save_config(&conn, &config).unwrap();
    drop(conn);

    // Corrupt the nonce file: the control channel must refuse, and doctor
    // must call that out rather than reporting a healthy gateway.
    std::fs::write(
        dir.path().join("gateway.nonce"),
        "ffffffffffffffffffffffffffffffff",
    )
    .unwrap();
    let report = doctor::diagnose_with(dir.path(), installed_service(dir.path()));
    let found = ids(&report);
    assert!(found.contains(&"control_auth_failed"), "{found:?}");
    drop(service);

    // A service whose definition points elsewhere / whose binary is gone.
    let mut stale = installed_service(dir.path());
    stale.matches_data_dir = false;
    let report = doctor::diagnose_with(dir.path(), stale);
    assert!(ids(&report).contains(&"stale_service_path"));

    let mut missing = installed_service(dir.path());
    missing.binary_exists = false;
    let report = doctor::diagnose_with(dir.path(), missing);
    assert!(ids(&report).contains(&"service_binary_missing"));
}
