//! Vault-lock lifecycle: an active observed run must be interrupted — the proxy
//! shut down and the monitored child terminated — when the vault is locked
//! (session file deleted) or auto-locks (deadline / session-file expiry), and
//! must otherwise finish normally. Uses a real (fast-KDF) temp vault, a
//! long-lived synthetic child, and connection mode (no CA needed; still starts
//! the loopback proxy and exercises the full interruptible wait + teardown).
//!
//! Unix-only: spawns the standard `sleep` binary as the tracked child so
//! `terminate_verified` signals it directly (no orphaned grandchild). Observe's
//! own tests are wired into the Linux CI job.

#![cfg(unix)]

use api_tracker_core::runtime::model::ObservationMode;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, NewProject, UnlockedVault, VaultPaths};
use api_tracker_observe::session::{run_monitored, LockPolicy, RunParams};
use std::process::Command;
use std::time::Duration;

fn fast_vault(dir: &std::path::Path) -> UnlockedVault {
    // Debug-only weak KDF so vault creation is fast in tests.
    std::env::set_var("API_TRACKER_INSECURE_FAST_KDF", "1");
    let paths = VaultPaths::new(dir.to_path_buf());
    vault::create_vault(&paths, &SecretString::from("test-master-password")).unwrap()
}

fn params(project_id: &str, lock: LockPolicy) -> RunParams {
    RunParams {
        project_id: project_id.to_string(),
        mode: ObservationMode::Connection,
        source: "test".into(),
        command_label: "sleep".into(),
        credential_names: vec![],
        injected: vec![],
        allowlist: vec![],
        lock,
    }
}

/// A long-lived child that is the tracked pid itself (so verified termination
/// signals it directly — no orphan).
fn sleeper(secs: u32) -> Command {
    let mut c = Command::new("sleep");
    c.arg(secs.to_string());
    c
}

#[test]
fn manual_lock_interrupts_active_run_and_terminates_child() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fast_vault(dir.path());
    let project = v
        .create_project(NewProject {
            name: "app".into(),
            ..Default::default()
        })
        .unwrap();

    // A watched session file that does not exist → the first poll tick reads
    // it as MISSING → a manual lock, interrupting the run almost immediately.
    let lock = LockPolicy {
        session_file: Some(dir.path().join("no-such-session.json")),
        max_run: None,
    };
    let outcome = run_monitored(&v, params(&project.id, lock), sleeper(30), "sleep").unwrap();

    assert_eq!(outcome.interrupt_reason.as_deref(), Some("vault_locked"));
    // The child (the tracked `sleep` pid) was signalled, not left running.
    let term = outcome.child_termination.unwrap();
    assert!(
        term.contains("SIGTERM") || term.contains("already exited"),
        "unexpected child termination outcome: {term}"
    );

    let row = v.observe_session(&outcome.session_id).unwrap();
    assert_eq!(row.status, "interrupted");
    assert_eq!(row.interrupt_reason.as_deref(), Some("vault_locked"));

    // No detached proxy remains and the port is reusable: a second run starts
    // and interrupts cleanly too (proving nothing from run #1 survived).
    let lock2 = LockPolicy {
        session_file: Some(dir.path().join("still-none.json")),
        max_run: None,
    };
    let out2 = run_monitored(&v, params(&project.id, lock2), sleeper(30), "sleep").unwrap();
    assert_eq!(out2.interrupt_reason.as_deref(), Some("vault_locked"));
    assert_ne!(out2.session_id, outcome.session_id);
}

#[test]
fn auto_lock_deadline_interrupts_active_run() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fast_vault(dir.path());
    let project = v
        .create_project(NewProject {
            name: "app".into(),
            ..Default::default()
        })
        .unwrap();

    // A short wall-clock cap (the inline-password auto-lock backstop) fires
    // within a couple of poll ticks.
    let lock = LockPolicy {
        session_file: None,
        max_run: Some(Duration::from_millis(50)),
    };
    let outcome = run_monitored(&v, params(&project.id, lock), sleeper(30), "sleep").unwrap();

    assert_eq!(outcome.interrupt_reason.as_deref(), Some("auto_lock"));
    let row = v.observe_session(&outcome.session_id).unwrap();
    assert_eq!(row.status, "interrupted");
    assert_eq!(row.interrupt_reason.as_deref(), Some("auto_lock"));
}

#[test]
fn deleting_the_session_file_mid_run_interrupts_as_manual_lock() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fast_vault(dir.path());
    let project = v
        .create_project(NewProject {
            name: "app".into(),
            ..Default::default()
        })
        .unwrap();

    // Start with a present, non-expiring session file, then delete it from
    // another thread mid-run — exactly what `api-tracker lock` does.
    let session_path = dir.path().join("session.json");
    std::fs::write(
        &session_path,
        br#"{"session_id":"s","created_at":"2020-01-01T00:00:00Z","expires_at":null,"ttl_minutes":0,"payload_b64":"AA=="}"#,
    )
    .unwrap();
    let to_delete = session_path.clone();
    let deleter = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        let _ = std::fs::remove_file(&to_delete);
    });

    let lock = LockPolicy {
        session_file: Some(session_path),
        max_run: None,
    };
    let outcome = run_monitored(&v, params(&project.id, lock), sleeper(30), "sleep").unwrap();
    deleter.join().unwrap();

    assert_eq!(outcome.interrupt_reason.as_deref(), Some("vault_locked"));
    let row = v.observe_session(&outcome.session_id).unwrap();
    assert_eq!(row.status, "interrupted");
}

#[test]
fn normal_child_exit_completes_and_is_not_interrupted() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = fast_vault(dir.path());
    let project = v
        .create_project(NewProject {
            name: "app".into(),
            ..Default::default()
        })
        .unwrap();

    // The child exits on its own before any lock fires; the policy would fire
    // only far in the future, so the run must finish "completed", not
    // interrupted (a completed run is never relabeled).
    let lock = LockPolicy {
        session_file: None,
        max_run: Some(Duration::from_secs(3600)),
    };
    let outcome = run_monitored(&v, params(&project.id, lock), sleeper(0), "sleep").unwrap();

    assert_eq!(outcome.interrupt_reason, None);
    assert!(outcome.child_termination.is_none());
    let row = v.observe_session(&outcome.session_id).unwrap();
    assert_eq!(row.status, "completed");
    assert_eq!(row.interrupt_reason, None);
}
