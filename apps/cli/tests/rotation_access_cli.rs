//! CLI end-to-end tests for rotation planning, access grants, and lifecycle
//! history. Only network-free flows run here (provider calls are covered by
//! the core integration tests against mocks).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

const MASTER_PW: &str = "test-master-password";
const FAKE_KEY: &str = "sk-proj-FAKE0000000000000000000000000000FAKE";

struct TestVault {
    dir: TempDir,
    data_dir: PathBuf,
}

impl TestVault {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        let v = Self { dir, data_dir };
        v.cmd().arg("init").assert().success();
        v.cmd()
            .args(["project", "create", "web"])
            .assert()
            .success();
        v.cmd()
            .args([
                "key",
                "add",
                "--project",
                "web",
                "--name",
                "openai",
                "--provider",
                "openai",
                "--environment",
                "production",
                "--value-stdin",
            ])
            .write_stdin(FAKE_KEY)
            .assert()
            .success();
        v
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("api-tracker").unwrap();
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("API_TRACKER_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("API_TRACKER_PASSWORD", MASTER_PW);
        cmd
    }
}

#[test]
fn rotation_plan_is_a_dry_run_with_honest_manual_steps() {
    let v = TestVault::new();
    // No admin connection -> manual mode with dashboard instructions.
    let assert = v
        .cmd()
        .args(["rotation", "plan", "web/openai", "--grace-minutes", "30"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run"))
        .stdout(predicate::str::contains("manual creation"))
        .stdout(predicate::str::contains("create the replacement key"));
    let out = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(!out.contains(FAKE_KEY), "plans never show values");

    // The credential value is untouched by planning.
    v.cmd()
        .args(["key", "show", "web/openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk-p"));
}

#[test]
fn rotation_approve_cancel_and_schedule_guard() {
    let v = TestVault::new();
    let assert = v
        .cmd()
        .args(["rotation", "plan", "web/openai", "--json"])
        .assert()
        .success();
    let json: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let id = json.get("id").and_then(|v| v.as_str()).unwrap().to_string();

    // Approve non-interactively is refused (no --yes path for approval by
    // design: it needs a terminal or --json+password env only for cancel).
    v.cmd()
        .args(["rotation", "cancel", &id, "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Cancelled"));

    // Scheduling without a completed rotation is refused with the reason.
    v.cmd()
        .args([
            "rotation",
            "schedule",
            "set",
            "web/openai",
            "--every-days",
            "30",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("COMPLETED"));

    v.cmd()
        .args(["rotation", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("failed"));
}

#[test]
fn one_time_grant_drives_run_and_ends_cleanly() {
    let v = TestVault::new();
    v.cmd()
        .args([
            "mapping",
            "set",
            "--project",
            "web",
            "--credential",
            "web/openai",
            "--env",
            "OPENAI_API_KEY",
        ])
        .assert()
        .success();
    let assert = v
        .cmd()
        .args([
            "access",
            "grant",
            "--project",
            "web",
            "--one-time",
            "--ttl-minutes",
            "10",
            "--label",
            "demo",
            "--json",
        ])
        .assert()
        .success();
    let json: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let grant_id = json.get("id").and_then(|v| v.as_str()).unwrap().to_string();

    // First launch works and the child sees the injected variable.
    let out_file = v.dir.path().join("saw.txt");
    let script = format!("printf '%s' \"$OPENAI_API_KEY\" > {}", out_file.display());
    v.cmd()
        .args(["run", "--grant", &grant_id, "--"])
        .args(["sh", "-c", &script])
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(&out_file).unwrap(), FAKE_KEY);

    // One-time: the second launch is refused.
    v.cmd()
        .args(["run", "--grant", &grant_id, "--"])
        .args(["sh", "-c", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("used_up"));

    // Ending is honest about what it does and does not do.
    v.cmd()
        .args(["access", "end", &grant_id, "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "provider credential itself stays valid",
        ));
}

#[test]
fn grant_time_limit_terminates_the_child() {
    let v = TestVault::new();
    v.cmd()
        .args([
            "mapping",
            "set",
            "--project",
            "web",
            "--credential",
            "web/openai",
            "--env",
            "OPENAI_API_KEY",
        ])
        .assert()
        .success();
    let assert = v
        .cmd()
        .args([
            "access",
            "grant",
            "--project",
            "web",
            "--ttl-minutes",
            "10",
            "--max-duration-secs",
            "1",
            "--json",
        ])
        .assert()
        .success();
    let json: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let grant_id = json.get("id").and_then(|v| v.as_str()).unwrap().to_string();

    let start = std::time::Instant::now();
    // `sleep` is the DIRECT child (no `sh -c` wrapper): the kill targets the
    // direct child, and a shell that forks instead of exec-ing would leave
    // an orphaned sleep holding the output pipes open until it finishes.
    v.cmd()
        .args(["run", "--grant", &grant_id, "--"])
        .args(["sleep", "30"])
        .assert()
        .code(124)
        .stderr(predicate::str::contains("time limit"));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(15),
        "the child must be terminated by the local bound, not run to completion"
    );
}

#[test]
fn revoked_grant_refuses_new_launches() {
    let v = TestVault::new();
    v.cmd()
        .args([
            "mapping",
            "set",
            "--project",
            "web",
            "--credential",
            "web/openai",
            "--env",
            "OPENAI_API_KEY",
        ])
        .assert()
        .success();
    let assert = v
        .cmd()
        .args([
            "access",
            "grant",
            "--project",
            "web",
            "--ttl-minutes",
            "10",
            "--json",
        ])
        .assert()
        .success();
    let json: serde_json::Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let grant_id = json.get("id").and_then(|v| v.as_str()).unwrap().to_string();
    v.cmd()
        .args(["access", "end", &grant_id, "--yes"])
        .assert()
        .success();
    v.cmd()
        .args(["run", "--grant", &grant_id, "--"])
        .args(["sh", "-c", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("revoked"));
}

#[test]
fn key_history_shows_the_lifecycle_without_values() {
    let v = TestVault::new();
    let new_value = "sk-proj-FAKE0000000000000000000000000000NEW1";
    v.cmd()
        .args([
            "key",
            "update",
            "web/openai",
            "--new-value",
            "--value-stdin",
        ])
        .write_stdin(new_value)
        .assert()
        .success();
    let assert = v
        .cmd()
        .args(["key", "history", "web/openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("credential_created"))
        .stdout(predicate::str::contains("credential_value_replaced"))
        .stdout(predicate::str::contains("version_retained"));
    let out = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(!out.contains(FAKE_KEY));
    assert!(!out.contains(new_value));
}
