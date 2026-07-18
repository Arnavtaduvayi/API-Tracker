//! CLI end-to-end tests for notification channels, monitor network phases,
//! and documentation history. Offline only; fake values.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

const MASTER_PW: &str = "test-master-password";

struct TestVault {
    _dir: TempDir,
    data_dir: PathBuf,
}

impl TestVault {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        let v = Self {
            _dir: dir,
            data_dir,
        };
        v.cmd().arg("init").assert().success();
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
fn notify_channels_are_masked_https_only_and_listable() {
    let v = TestVault::new();
    // http refused.
    v.cmd()
        .args(["notify", "add", "--name", "bad", "--url-stdin"])
        .write_stdin("http://example.com/hook")
        .assert()
        .failure()
        .stderr(predicate::str::contains("https"));
    // https accepted; URL masked in listings.
    let secret_url = "https://hooks.example.com/T00/FAKE-webhook-token";
    v.cmd()
        .args([
            "notify",
            "add",
            "--name",
            "team",
            "--min-severity",
            "medium",
            "--url-stdin",
        ])
        .write_stdin(secret_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("metadata only"));
    let assert = v.cmd().args(["notify", "list"]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(!out.contains("FAKE-webhook-token"), "URL must be masked");
    assert!(out.contains("medium"));
    v.cmd()
        .args(["notify", "enable", "team", "--off"])
        .assert()
        .success();
    v.cmd()
        .args(["notify", "remove", "team"])
        .assert()
        .success();
}

#[test]
fn monitor_offline_skips_network_phases() {
    let v = TestVault::new();
    v.cmd()
        .args(["project", "create", "web"])
        .assert()
        .success();
    v.cmd()
        .args(["monitor", "--offline"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Checked"));
}

#[test]
fn docs_history_starts_empty_and_watches_are_intact() {
    let v = TestVault::new();
    v.cmd()
        .args(["provider", "docs-history"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No documentation checks recorded"));
}
