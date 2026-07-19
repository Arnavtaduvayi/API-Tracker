//! RA-1 / CLI-03 / PI-02 regression: `access end --kill` must route through
//! the vault's verified termination, not an inline `kill`.
//!
//! At the Phase-2 baseline (`033f747`) this path spawned
//! `kill <pid>` directly on every PID recorded under the grant — bypassing
//! the `pid <= 0` guard AND any identity verification, so a stale row whose
//! PID had been recycled killed an unrelated process. After the fix the
//! path uses `terminate_process_session`, which refuses a record whose
//! launch identity cannot be confirmed.
//!
//! The "unrelated process" is a decoy `sleep` this test spawns itself.

#![cfg(unix)]

use assert_cmd::Command;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const MASTER_PW: &str = "end-kill-guard-master-password-01";

fn cli(data_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("api-tracker").unwrap();
    cmd.env_clear()
        .env("API_TRACKER_DIR", data_dir)
        .env("API_TRACKER_INSECURE_FAST_KDF", "1")
        .env("API_TRACKER_PASSWORD", MASTER_PW);
    cmd
}

fn spawn_decoy() -> Child {
    std::process::Command::new("sleep")
        .arg("300")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn decoy sleep")
}

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

#[test]
fn end_kill_refuses_a_stale_session_record_instead_of_killing_blind() {
    let dir = TempDir::new().unwrap();
    let data_dir = dir.path().join("data");
    cli(&data_dir).arg("init").assert().success();
    cli(&data_dir)
        .args(["project", "create", "app"])
        .assert()
        .success();

    let out = cli(&data_dir)
        .args(["access", "grant", "--project", "app", "--label", "t"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let grant_id = stdout
        .lines()
        .find_map(|l| {
            l.strip_prefix("Grant ")
                .and_then(|r| r.strip_suffix(" created."))
        })
        .expect("grant id in output")
        .to_string();

    let mut decoy = spawn_decoy();

    // A stale session row recorded under the grant: the launcher died, the
    // PID has been recycled (the decoy stands in for the unrelated process),
    // and no launch identity can vouch for it.
    let db = api_tracker_core::vault::VaultPaths::new(data_dir.clone()).db_path();
    let conn = rusqlite::Connection::open(db).expect("open vault db");
    let project_id: String = conn
        .query_row("SELECT id FROM projects LIMIT 1", [], |r| r.get(0))
        .expect("project id");
    conn.execute(
        "INSERT INTO process_sessions
             (id, project_id, started_at, command, injected_vars, pid, grant_id)
         VALUES ('sess-stale-cli', ?1, '2026-01-01T00:00:00Z', 'demo', '', ?2, ?3)",
        rusqlite::params![project_id, i64::from(decoy.id()), grant_id],
    )
    .expect("insert stale session row");
    drop(conn);

    let out = cli(&data_dir)
        .args(["access", "end", &grant_id, "--kill", "--yes"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();

    let alive = still_running(&mut decoy, Duration::from_millis(1000));
    let _ = decoy.kill();
    let _ = decoy.wait();

    assert!(
        stdout.contains("refused"),
        "end --kill must report the refusal, got:\n{stdout}"
    );
    assert!(
        alive,
        "end --kill signalled an unverified stale PID (RA-1 regression)"
    );
}
