//! End-to-end CLI tests for milestone 2: providers, scanning, hooks, alerts,
//! monitoring, and doc watches. Fake credentials only.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use tempfile::TempDir;

const MASTER_PW: &str = "test-master-password";
const FAKE_OPENAI: &str = "sk-proj-FAKE0000000000000000000000000000FAKE";

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

    fn root(&self) -> &Path {
        self._dir.path()
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("api-tracker").unwrap();
        cmd.env_clear()
            .env("API_TRACKER_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("API_TRACKER_PASSWORD", MASTER_PW);
        cmd
    }

    fn cmd_no_password(&self) -> Command {
        let mut cmd = Command::cargo_bin("api-tracker").unwrap();
        cmd.env_clear()
            .env("API_TRACKER_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1");
        cmd
    }
}

fn git_available() -> bool {
    StdCommand::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git(dir: &Path, args: &[&str]) {
    let out = StdCommand::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_repo(dir: &Path) {
    git(dir, &["init"]);
    git(dir, &["config", "user.email", "t@example.com"]);
    git(dir, &["config", "user.name", "T"]);
    git(dir, &["config", "commit.gpgsign", "false"]);
}

// ---- Provider catalog ----

#[test]
fn provider_catalog_commands() {
    let v = TestVault::new();
    v.cmd_no_password()
        .args(["provider", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("openai"))
        .stdout(predicate::str::contains("anthropic"))
        .stdout(predicate::str::contains("Capability support varies"));

    v.cmd_no_password()
        .args(["provider", "show", "stripe"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stripe"))
        .stdout(predicate::str::contains("dashboard.stripe.com"));

    v.cmd_no_password()
        .args(["provider", "capabilities", "openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("validate credential"))
        // Honesty: unsupported/manual capabilities stay labeled as such.
        .stdout(predicate::str::contains("manual action required"))
        .stdout(predicate::str::contains("admin credential"));

    // The not-yet-implemented label still appears where it is true.
    v.cmd_no_password()
        .args(["provider", "capabilities", "supabase"])
        .assert()
        .success()
        .stdout(predicate::str::contains("supported, not implemented"));

    v.cmd_no_password()
        .args(["provider", "docs", "anthropic"])
        .assert()
        .success()
        .stdout(predicate::str::contains("docs.anthropic.com"));

    // JSON works and is honest about no implementation.
    v.cmd_no_password()
        .args(["provider", "capabilities", "github", "--json"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("supported_not_implemented")
                .or(predicate::str::contains("manual_only")),
        );
}

// ---- Scanning + matching + exposure (the acceptance path) ----

#[test]
fn acceptance_scan_match_expose_hook_flow() {
    if !git_available() {
        eprintln!("git unavailable; skipping");
        return;
    }
    let v = TestVault::new();
    v.cmd()
        .args(["project", "create", "web", "--env", "production"])
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
        .write_stdin(FAKE_OPENAI)
        .assert()
        .success();

    // A repo containing the same secret, staged.
    let repo = v.root().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_repo(&repo);
    std::fs::write(repo.join(".env"), format!("OPENAI_API_KEY={FAKE_OPENAI}\n")).unwrap();
    git(&repo, &["add", ".env"]);

    // Staged scan: high-confidence, redacted, matched to the vault.
    let assert = v
        .cmd()
        .args(["scan", "--staged"])
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains("high"))
        .stdout(predicate::str::contains("IN VAULT: matches 'web/openai'"))
        .stdout(predicate::str::contains(FAKE_OPENAI).not());
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        !out.contains(FAKE_OPENAI),
        "scan output must not leak the secret"
    );

    // The matched credential is now marked possibly exposed.
    v.cmd()
        .args(["key", "status", "web/openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("possibly exposed"));

    // Install the hook and confirm a real commit is blocked, then unblocked.
    v.cmd()
        .args(["hooks", "install"])
        .arg(&repo)
        .assert()
        .success();
    v.cmd()
        .args(["hooks", "status"])
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains("Installed"));

    // Put the api-tracker binary on PATH for the hook, pointed at this vault.
    let bin_dir = assert_cmd::cargo::cargo_bin("api-tracker")
        .parent()
        .unwrap()
        .to_path_buf();
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let blocked = StdCommand::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["commit", "-m", "leak"])
        .env("PATH", &path_env)
        .env("API_TRACKER_DIR", &v.data_dir)
        .env("API_TRACKER_INSECURE_FAST_KDF", "1")
        .output()
        .unwrap();
    assert!(
        !blocked.status.success(),
        "commit with a secret must be blocked"
    );
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("blocking commit"));

    // Remove the secret, re-stage: the commit proceeds.
    std::fs::write(repo.join(".env"), "OPENAI_API_KEY=\n").unwrap();
    git(&repo, &["add", ".env"]);
    let ok = StdCommand::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["commit", "-m", "clean"])
        .env("PATH", &path_env)
        .env("API_TRACKER_DIR", &v.data_dir)
        .env("API_TRACKER_INSECURE_FAST_KDF", "1")
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "clean commit must proceed: {}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // Hook removes cleanly.
    v.cmd()
        .args(["hooks", "remove"])
        .arg(&repo)
        .assert()
        .success();
    v.cmd()
        .args(["hooks", "status"])
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains("Absent"));
}

#[test]
fn scan_fixture_repo_and_suppress() {
    if !git_available() {
        return;
    }
    let v = TestVault::new();
    // Copy the committed fixture into a temp repo.
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/leaky-repo");
    let repo = v.root().join("fixture-repo");
    std::fs::create_dir_all(&repo).unwrap();
    for entry in std::fs::read_dir(&fixture).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), repo.join(entry.file_name())).unwrap();
    }
    init_repo(&repo);
    git(&repo, &["add", "."]);

    let assert = v
        .cmd()
        .args(["scan", "--staged"])
        .arg(&repo)
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // Three real fakes flagged, placeholders and publishable key ignored.
    assert!(out.contains("openai"), "openai key flagged");
    assert!(out.contains("github"), "github token flagged");
    assert!(out.contains("stripe"), "stripe key flagged");
    assert!(
        !out.contains("your-key-here"),
        "placeholder must not be flagged"
    );
    assert!(
        !out.contains("pk_live_"),
        "publishable key must not be flagged"
    );

    // Suppress the openai finding by its key, then confirm it disappears.
    let key_line = out.lines().find(|l| l.contains("suppress add")).unwrap();
    let key = key_line.split_whitespace().nth(3).unwrap();
    v.cmd()
        .args([
            "suppress",
            "add",
            key,
            "--reason",
            "fixture, obviously fake",
        ])
        .assert()
        .success();
    v.cmd()
        .args(["suppress", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("fixture"));
}

#[test]
fn scan_reports_nothing_on_a_clean_tree() {
    let v = TestVault::new();
    let clean = v.root().join("clean");
    std::fs::create_dir_all(&clean).unwrap();
    std::fs::write(clean.join("main.rs"), "fn main() { println!(\"hi\"); }\n").unwrap();
    v.cmd()
        .args(["scan"])
        .arg(&clean)
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets found"));
}

// ---- Monitoring + alerts ----

#[test]
fn monitor_and_alerts_lifecycle() {
    let v = TestVault::new();
    v.cmd()
        .args(["project", "create", "app"])
        .assert()
        .success();
    v.cmd()
        .args([
            "key",
            "add",
            "--project",
            "app",
            "--name",
            "old",
            "--environment",
            "production",
            "--expires",
            "2020-01-01",
            "--value-stdin",
        ])
        .write_stdin(FAKE_OPENAI)
        .assert()
        .success();

    v.cmd()
        .args(["monitor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("new alert"));

    let assert = v.cmd().args(["alerts", "list"]).assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("expired"), "expired alert listed");
    let id = out
        .lines()
        .find(|l| l.contains("expired"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap()
        .to_string();

    v.cmd()
        .args(["alerts", "acknowledge", &id])
        .assert()
        .success();
    v.cmd().args(["alerts", "resolve", &id]).assert().success();
    v.cmd()
        .args(["alerts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("expired").not());
}

// ---- Documentation watches ----

#[test]
fn doc_watch_register_and_status() {
    let v = TestVault::new();
    v.cmd()
        .args([
            "provider",
            "watch-docs",
            "openai",
            "--url",
            "https://example.com/openai/auth",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Watching"));

    v.cmd()
        .args(["provider", "docs-status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("example.com/openai/auth"))
        .stdout(predicate::str::contains("never checked"));

    v.cmd()
        .args([
            "provider",
            "unwatch-docs",
            "openai",
            "https://example.com/openai/auth",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stopped watching"));
}
