//! Diagnosis engine (TEST_PLAN §5): each diagnosis id has a positive and
//! negative fixture; ranking is stable; the all-clear case is explicit.

mod common;

use api_tracker_gateway::doctor;
use api_tracker_tracking::detect::{detect, DetectionInput};
use api_tracker_tracking::diagnose::{diagnose_with, DiagnosisSeverity};
use api_tracker_tracking::state::{self, PlanSummary, TrackingState};
use common::*;
use tempfile::TempDir;

fn doctor_fixture(findings: Vec<doctor::Finding>) -> doctor::Doctor {
    doctor::Doctor {
        overall: doctor::Severity::Ok,
        findings,
        service: service_running(),
        gateway: None,
        listener: None,
        configured_port: Some(49152),
        enabled: true,
        links: Vec::new(),
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

fn finding(id: &'static str) -> doctor::Finding {
    doctor::Finding {
        id,
        severity: doctor::Severity::Info,
        title: id.to_string(),
        detail: format!("fixture detail for {id}"),
        repair: None,
    }
}

/// A setup whose detection ran over `dir`.
fn setup_for(conn: &rusqlite::Connection, dir: &TempDir) -> state::TrackingSetup {
    insert_project(conn, "p1", "one");
    let detection = detect(
        conn,
        &DetectionInput {
            folder: dir.path(),
            project_id: None,
        },
    )
    .unwrap();
    let setup = state::upsert_setup(
        conn,
        "p1",
        &detection.folder,
        TrackingState::AwaitingFirstRequest,
        &serde_json::to_string(&detection).unwrap(),
    )
    .unwrap();
    state::record_applied(
        conn,
        &setup.id,
        &PlanSummary {
            providers: vec!["openai".to_string()],
            links: vec!["openai".to_string()],
            port: 49152,
            ..Default::default()
        },
    )
    .unwrap();
    state::get_setup(conn, &setup.id).unwrap().unwrap()
}

#[test]
fn a_stopped_gateway_is_the_top_ranked_error() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let setup = setup_for(&conn, &dir);
    let report = doctor_fixture(vec![finding("installed_but_stopped")]);
    let out = diagnose_with(&conn, &setup, &report).unwrap();
    assert_eq!(out[0].id, "gateway_unavailable");
    assert_eq!(out[0].severity, DiagnosisSeverity::Error);
    // The restart hint is suppressed while a hard error explains the gap.
    assert!(!out.iter().any(|d| d.id == "not_restarted"));
}

#[test]
fn a_healthy_gateway_leads_with_the_restart_hint() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let setup = setup_for(&conn, &dir);
    let report = doctor_fixture(vec![finding("running")]);
    let out = diagnose_with(&conn, &setup, &report).unwrap();
    assert_eq!(out[0].id, "not_restarted");
}

#[test]
fn docker_compose_is_reported_live_and_absent_when_removed() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    std::fs::write(dir.path().join("docker-compose.yml"), "services: {}\n").unwrap();
    let setup = setup_for(&conn, &dir);
    let report = doctor_fixture(vec![finding("running")]);
    let out = diagnose_with(&conn, &setup, &report).unwrap();
    assert!(out.iter().any(|d| d.id == "docker_compose"));

    // Re-checked live: removing the file removes the diagnosis even with
    // stale detection JSON.
    std::fs::remove_file(dir.path().join("docker-compose.yml")).unwrap();
    let out2 = diagnose_with(&conn, &setup, &report).unwrap();
    assert!(!out2.iter().any(|d| d.id == "docker_compose"));
}

#[test]
fn an_override_in_a_later_loaded_file_is_flagged() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    std::fs::write(
        dir.path().join(".env.production"),
        "OPENAI_BASE_URL=https://api.openai.com/v1\n",
    )
    .unwrap();
    let setup = setup_for(&conn, &dir);
    let report = doctor_fixture(vec![finding("running")]);
    let out = diagnose_with(&conn, &setup, &report).unwrap();
    let hit = out
        .iter()
        .find(|d| d.id == "var_overridden")
        .expect("override flagged");
    assert!(hit.message.contains(".env.production"), "{}", hit.message);
}

#[test]
fn no_dotenv_loader_is_flagged_only_when_provably_absent() {
    let (_db, conn) = test_conn();
    // Loader present → no flag.
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let setup = setup_for(&conn, &dir);
    let report = doctor_fixture(vec![finding("running")]);
    let out = diagnose_with(&conn, &setup, &report).unwrap();
    assert!(!out.iter().any(|d| d.id == "no_dotenv_loader"));

    // Loader absent → flagged.
    let (_db2, conn2) = test_conn();
    let dir2 = TempDir::new().unwrap();
    write_project(
        dir2.path(),
        &[
            (".env", &format!("OPENAI_API_KEY={FAKE_OPENAI_KEY}\n")),
            ("package.json", r#"{ "dependencies": { "openai": "^4" } }"#),
        ],
    );
    let setup2 = setup_for(&conn2, &dir2);
    let out2 = diagnose_with(&conn2, &setup2, &doctor_fixture(vec![finding("running")])).unwrap();
    assert!(out2.iter().any(|d| d.id == "no_dotenv_loader"));
}

#[test]
fn all_clear_is_explicit_when_everything_checks_out() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let setup = setup_for(&conn, &dir);
    let report = doctor_fixture(vec![finding("running"), finding("forwarding_active")]);
    let out = diagnose_with(&conn, &setup, &report).unwrap();
    let last = out.last().unwrap();
    assert_eq!(last.id, "all_clear");
    assert!(last.message.contains("checks out"));
}

#[test]
fn link_drift_for_this_project_is_an_error() {
    let (_db, conn) = test_conn();
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let setup = setup_for(&conn, &dir);
    let mut report = doctor_fixture(vec![finding("running")]);
    report.links.push(doctor::LinkHealth {
        project_id: "p1".to_string(),
        route_prefix: "openai".to_string(),
        env_path: Some("/tmp/x/.env".to_string()),
        env_file_exists: true,
        env_points_at_gateway: false,
        issues: vec!["the gateway line was hand-edited or restored".to_string()],
    });
    let out = diagnose_with(&conn, &setup, &report).unwrap();
    let drift = out.iter().find(|d| d.id == "env_drifted").expect("drift");
    assert_eq!(drift.severity, DiagnosisSeverity::Error);

    // Another project's drift is not this setup's problem.
    let mut other = doctor_fixture(vec![finding("running")]);
    other.links.push(doctor::LinkHealth {
        project_id: "someone-else".to_string(),
        route_prefix: "openai".to_string(),
        env_path: None,
        env_file_exists: false,
        env_points_at_gateway: false,
        issues: vec![],
    });
    let out2 = diagnose_with(&conn, &setup, &other).unwrap();
    assert!(!out2.iter().any(|d| d.id == "env_drifted"));
}
