//! PI-02 / CONC-11 / CLI-03 / RA-1 regression suite: process identity must
//! be verified before termination.
//!
//! Property under test: a recorded PID is signalled ONLY when the process
//! identity captured at launch (start time + executable, via the platform
//! probe) still matches immediately before signalling. A stale row, a
//! recycled PID, a tampered record, or a missing identity is refused —
//! never signalled. An already-exited process is reported truthfully.
//!
//! Baseline evidence: at `033f747` (pre-fix) the stale-PID test in this
//! file's original form killed the unrelated decoy process
//! (`docs/remediation-phase-2/evidence/pi02_baseline_fail.log.txt`).
//!
//! Every "unrelated process" here is a decoy `sleep` the test itself
//! spawns, so the suite never signals anything outside the test.

#![cfg(unix)]

mod common;

use api_tracker_core::inject::{
    probe_process_identity, terminate_verified, IdentityProbe, TerminationOutcome,
};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn spawn_decoy() -> Child {
    Command::new("sleep")
        .arg("300")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn decoy sleep")
}

/// Poll the decoy for up to `window`; returns true if it is still running.
fn still_running(child: &mut Child, window: Duration) -> bool {
    let deadline = Instant::now() + window;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => return false,
            None if Instant::now() >= deadline => return true,
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

fn reap(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Insert a session row directly (simulating a stale or tampered database
/// record — exactly the state a dead launcher or a hostile edit leaves).
fn insert_session_row(
    conn: &rusqlite::Connection,
    id: &str,
    pid: i64,
    proc_identity: Option<&str>,
) {
    conn.execute(
        "INSERT INTO process_sessions
             (id, project_id, started_at, command, injected_vars, pid, proc_identity)
         VALUES (?1, 'proj', '2026-01-01T00:00:00Z', 'demo', '', ?2, ?3)",
        rusqlite::params![id, pid, proc_identity],
    )
    .expect("insert session row");
}

fn audit_kinds(conn: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT event FROM audit_events ORDER BY rowid")
        .expect("prepare audit query");
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query audit");
    rows.filter_map(|r| r.ok()).collect()
}

#[test]
fn stale_pid_record_with_no_identity_is_refused() {
    let (_dir, _paths, vault) = common::new_vault();
    let mut decoy = spawn_decoy();
    insert_session_row(
        vault.connection(),
        "sess-stale",
        i64::from(decoy.id()),
        None,
    );

    let (_, _, outcome) = vault
        .terminate_process_session("sess-stale")
        .expect("terminate resolves the session");

    let alive = still_running(&mut decoy, Duration::from_millis(1000));
    reap(decoy);
    assert!(
        matches!(outcome, TerminationOutcome::Refused { .. }),
        "a record with no launch identity must be refused, got {outcome:?}"
    );
    assert!(alive, "the unrelated process holding the PID must survive");
    assert!(
        audit_kinds(vault.connection())
            .iter()
            .any(|k| k == "process_session_termination_refused"),
        "the refusal must be audited"
    );
}

#[test]
fn same_pid_with_fabricated_identity_is_refused() {
    let (_dir, _paths, vault) = common::new_vault();
    let mut decoy = spawn_decoy();
    insert_session_row(
        vault.connection(),
        "sess-forged",
        i64::from(decoy.id()),
        Some("unix:lstart=Thu Jan  1 00:00:00 1970;comm=not-the-decoy"),
    );

    let (_, _, outcome) = vault
        .terminate_process_session("sess-forged")
        .expect("terminate resolves the session");

    let alive = still_running(&mut decoy, Duration::from_millis(1000));
    reap(decoy);
    assert!(
        matches!(outcome, TerminationOutcome::Refused { .. }),
        "a mismatched identity must be refused, got {outcome:?}"
    );
    assert!(
        alive,
        "the process must not be signalled on identity mismatch"
    );
}

#[test]
fn pid_reused_by_a_different_process_is_refused() {
    // Deterministic recycled-PID simulation that does NOT depend on
    // `ps lstart` timing resolution (RA2-6): the earlier `sleep`-based
    // variant waited one wall-clock second and assumed the impostor's
    // `lstart` would therefore differ — but `ps lstart` has one-second
    // resolution with jiffies→wall-clock rounding slop, so on the Linux CI
    // runner the impostor could observe the SAME `lstart`+`comm` and the
    // production check correctly (per its documented same-second-recycle
    // residual) returned Signalled, failing the test intermittently.
    //
    // Here the recorded launch identity is a REAL probe of one executable
    // (`cat`), and the recorded PID is then held by a DIFFERENT live
    // executable (`sleep`). Their observed identities differ by `comm`
    // regardless of start-time rounding, so the mismatch is guaranteed. We
    // assert the two identities genuinely differ BEFORE asserting the
    // refusal, so this test can never make a false "refused" claim. The
    // accepted-on-identity-match case is covered separately by
    // `correct_matching_process_is_signalled_and_audited`.
    let (_dir, _paths, vault) = common::new_vault();

    // A real launch identity captured from one executable; the process then
    // exits so its PID may be recycled by an unrelated process.
    let mut original = Command::new("cat")
        .stdin(Stdio::piped()) // blocks on an open stdin → stays alive to be probed
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn original decoy (cat)");
    let recorded_identity = match probe_process_identity(i64::from(original.id())) {
        IdentityProbe::Found(identity) => identity,
        other => panic!("probe of a live child must find it, got {other:?}"),
    };
    let _ = original.kill();
    let _ = original.wait();

    // A DIFFERENT live executable now holds a recorded PID; its identity is
    // read straight from the production probe (real data on both sides).
    let mut impostor = spawn_decoy(); // `sleep`
    let impostor_identity = match probe_process_identity(i64::from(impostor.id())) {
        IdentityProbe::Found(identity) => identity,
        other => panic!("probe of a live child must find it, got {other:?}"),
    };

    // Deterministic precondition: a genuine identity mismatch (different
    // `comm`), never a same-identity coincidence. `cat` vs `sleep` differ by
    // executable on every supported platform, so this always holds; if it
    // ever did not, we refuse to assert a false security property.
    assert_ne!(
        recorded_identity, impostor_identity,
        "the recorded and current identities must genuinely differ to exercise \
         reuse (recorded={recorded_identity:?}, current={impostor_identity:?})"
    );

    insert_session_row(
        vault.connection(),
        "sess-reused",
        i64::from(impostor.id()),
        Some(&recorded_identity),
    );

    let (_, _, outcome) = vault
        .terminate_process_session("sess-reused")
        .expect("terminate resolves the session");

    let alive = still_running(&mut impostor, Duration::from_millis(1000));
    reap(impostor);
    assert!(
        matches!(outcome, TerminationOutcome::Refused { .. }),
        "a recycled PID whose identity differs must fail the identity match, got {outcome:?}"
    );
    assert!(
        alive,
        "the unrelated process now holding the PID must survive"
    );
}

#[test]
fn correct_matching_process_is_signalled_and_audited() {
    let (_dir, _paths, vault) = common::new_vault();
    let decoy = spawn_decoy();
    let conn = vault.connection();
    let session = api_tracker_core::inject::start_session(conn, "proj", "demo", &[]).unwrap();
    // The production capture path: identity probed while the child handle
    // is held (exactly what `run` does via record_session_pid).
    api_tracker_core::inject::set_session_pid(conn, &session, decoy.id(), None).unwrap();

    let (_, pid, outcome) = vault
        .terminate_process_session(&session)
        .expect("terminate resolves the session");

    assert_eq!(pid, i64::from(decoy.id()));
    assert_eq!(
        outcome,
        TerminationOutcome::Signalled,
        "a live child with matching identity must be signalled"
    );
    let mut decoy = decoy;
    let status = decoy.wait().expect("decoy must exit after SIGTERM");
    assert!(!status.success(), "the decoy must have been terminated");
    assert!(
        audit_kinds(vault.connection())
            .iter()
            .any(|k| k == "process_session_terminated"),
        "the successful termination must be audited"
    );
}

#[test]
fn already_exited_process_is_reported_truthfully_and_row_closed() {
    let (_dir, _paths, vault) = common::new_vault();
    let decoy = spawn_decoy();
    let conn = vault.connection();
    let session = api_tracker_core::inject::start_session(conn, "proj", "demo", &[]).unwrap();
    api_tracker_core::inject::set_session_pid(conn, &session, decoy.id(), None).unwrap();
    reap(decoy); // process is gone before the termination request

    let (_, _, outcome) = vault
        .terminate_process_session(&session)
        .expect("terminate resolves the session");

    assert_eq!(
        outcome,
        TerminationOutcome::AlreadyExited,
        "a definitively-gone process must be reported already exited"
    );
    // The row is closed truthfully so listings stop claiming it runs.
    let sessions = vault.list_process_sessions(50, false).unwrap();
    let row = sessions.iter().find(|s| s.id == session).unwrap();
    assert!(row.ended_at.is_some(), "already-exited row must be closed");
    // A second request now refuses: the session has ended.
    assert!(vault.terminate_process_session(&session).is_err());
}

#[test]
fn non_positive_pids_are_refused_at_every_layer() {
    // Shared implementation, called by every entry point.
    for pid in [0i64, -1, -12345, i64::MIN] {
        let outcome = terminate_verified(pid, Some("unix:lstart=x;comm=y"));
        assert!(
            matches!(outcome, TerminationOutcome::Refused { .. }),
            "pid {pid} must be refused before any signal"
        );
    }
    // Vault entry point with corrupted rows.
    let (_dir, _paths, vault) = common::new_vault();
    for (row_id, pid) in [("sess-zero", 0i64), ("sess-neg", -7)] {
        insert_session_row(vault.connection(), row_id, pid, Some("unix:tampered"));
        let (_, _, outcome) = vault
            .terminate_process_session(row_id)
            .expect("terminate resolves the session");
        assert!(
            matches!(outcome, TerminationOutcome::Refused { .. }),
            "corrupted pid {pid} must be refused at the vault entry point"
        );
    }
}

#[test]
fn tampered_record_pointing_at_a_system_process_is_refused() {
    // A hostile edit pointing the record at PID 1 (launchd/init) must be
    // refused by the identity check — the fabricated identity cannot match
    // the real system process.
    let (_dir, _paths, vault) = common::new_vault();
    insert_session_row(
        vault.connection(),
        "sess-tampered",
        1,
        Some("unix:lstart=Thu Jan  1 00:00:00 1970;comm=sleep"),
    );
    let (_, _, outcome) = vault
        .terminate_process_session("sess-tampered")
        .expect("terminate resolves the session");
    assert!(
        matches!(outcome, TerminationOutcome::Refused { .. }),
        "a tampered record naming a system process must be refused, got {outcome:?}"
    );
}

#[test]
fn identity_recorded_on_another_platform_is_refused() {
    // A vault copied from a Windows machine carries `win:`-prefixed
    // identities; on Unix these can never match a live probe and must be
    // refused rather than signalled.
    let (_dir, _paths, vault) = common::new_vault();
    let mut decoy = spawn_decoy();
    insert_session_row(
        vault.connection(),
        "sess-crossplat",
        i64::from(decoy.id()),
        Some("win:20260101000000.000000|sleep.exe"),
    );
    let (_, _, outcome) = vault
        .terminate_process_session("sess-crossplat")
        .expect("terminate resolves the session");
    let alive = still_running(&mut decoy, Duration::from_millis(1000));
    reap(decoy);
    assert!(
        matches!(outcome, TerminationOutcome::Refused { .. }),
        "a cross-platform identity must never match, got {outcome:?}"
    );
    assert!(alive);
}

#[test]
fn descendants_of_the_recorded_process_are_not_signalled() {
    // Documented limitation (PI-03 remains open): only the recorded process
    // is signalled — a grandchild it spawned survives. This test pins the
    // documented behavior so any future change to descendant handling is a
    // deliberate one.
    let (_dir, _paths, vault) = common::new_vault();
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("grandchild.pid");
    let script = format!("sleep 300 & echo $! > '{}'; wait", pid_file.display());
    let shell = Command::new("sh")
        .args(["-c", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn shell decoy");

    // Deterministic sync: wait (bounded) for the grandchild PID file.
    let deadline = Instant::now() + Duration::from_secs(5);
    let grandchild_pid: i64 = loop {
        if let Ok(text) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = text.trim().parse() {
                break pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "grandchild pid file never appeared"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    let conn = vault.connection();
    let session = api_tracker_core::inject::start_session(conn, "proj", "demo", &[]).unwrap();
    api_tracker_core::inject::set_session_pid(conn, &session, shell.id(), None).unwrap();

    let (_, _, outcome) = vault.terminate_process_session(&session).unwrap();
    assert_eq!(outcome, TerminationOutcome::Signalled);
    let mut shell = shell;
    let _ = shell.wait();

    // The grandchild survives the recorded process's termination.
    let grandchild_alive = matches!(
        probe_process_identity(grandchild_pid),
        IdentityProbe::Found(_)
    );
    // Clean up the grandchild regardless of the assertion.
    let _ = Command::new("kill")
        .arg(grandchild_pid.to_string())
        .status();
    assert!(
        grandchild_alive,
        "descendants are documented as NOT signalled; only the recorded process is"
    );
}

#[test]
fn probe_reports_own_process_and_definitively_gone_process() {
    let own = i64::from(std::process::id());
    assert!(
        matches!(probe_process_identity(own), IdentityProbe::Found(_)),
        "probing our own live process must find an identity"
    );
    let child = spawn_decoy();
    let pid = i64::from(child.id());
    reap(child);
    assert_eq!(
        probe_process_identity(pid),
        IdentityProbe::NotFound,
        "probing a reaped child must be definitively not-found"
    );
    assert_eq!(probe_process_identity(0), IdentityProbe::Unverifiable);
    assert_eq!(probe_process_identity(-5), IdentityProbe::Unverifiable);
}
