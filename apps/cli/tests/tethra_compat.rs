//! Rebrand compatibility tests: the preferred `tethra` binary and the
//! legacy `api-tracker` binary are the same program sharing the same vault,
//! and the `TETHRA_*` environment variables take precedence over the legacy
//! `API_TRACKER_*` names without breaking either. All credential values are
//! obvious fakes.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const MASTER_PW: &str = "test-master-password";
const FAKE_KEY: &str = "FAKE-TEST-NOT-A-REAL-KEY-COMPAT1";

struct TestVault {
    _dir: TempDir,
    data_dir: std::path::PathBuf,
}

/// Which binary and which env-var generation a command should use.
#[derive(Clone, Copy)]
enum Flavor {
    /// `tethra` binary + `TETHRA_*` variables.
    Preferred,
    /// `api-tracker` binary + `API_TRACKER_*` variables.
    Legacy,
}

impl Flavor {
    fn bin(self) -> &'static str {
        match self {
            Flavor::Preferred => "tethra",
            Flavor::Legacy => "api-tracker",
        }
    }
    fn var(self, suffix: &str) -> String {
        match self {
            Flavor::Preferred => format!("TETHRA_{suffix}"),
            Flavor::Legacy => format!("API_TRACKER_{suffix}"),
        }
    }
}

impl TestVault {
    fn empty() -> Self {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        Self {
            _dir: dir,
            data_dir,
        }
    }

    fn new(flavor: Flavor) -> Self {
        let vault = Self::empty();
        vault.cmd(flavor).arg("init").assert().success();
        vault
    }

    fn cmd(&self, flavor: Flavor) -> Command {
        let mut cmd = Command::cargo_bin(flavor.bin()).unwrap();
        cmd.env_clear()
            .env(flavor.var("DIR"), &self.data_dir)
            .env(flavor.var("INSECURE_FAST_KDF"), "1")
            .env(flavor.var("PASSWORD"), MASTER_PW);
        cmd
    }
}

fn add_key(vault: &TestVault, flavor: Flavor) {
    vault
        .cmd(flavor)
        .args(["project", "create", "compat-app"])
        .assert()
        .success();
    vault
        .cmd(flavor)
        .args([
            "key",
            "add",
            "--project",
            "compat-app",
            "--name",
            "compat-key",
            "--value-stdin",
        ])
        .write_stdin(FAKE_KEY)
        .assert()
        .success();
}

#[test]
fn tethra_binary_full_lifecycle() {
    let vault = TestVault::new(Flavor::Preferred);
    add_key(&vault, Flavor::Preferred);
    vault
        .cmd(Flavor::Preferred)
        .args(["key", "list", "--project", "compat-app"])
        .assert()
        .success()
        .stdout(predicate::str::contains("compat-key"))
        .stdout(predicate::str::contains(FAKE_KEY).not());
}

#[test]
fn legacy_binary_opens_a_vault_created_by_tethra() {
    // A vault created with the preferred binary + TETHRA_* vars is fully
    // usable through the legacy binary + API_TRACKER_* vars, and vice versa.
    let vault = TestVault::new(Flavor::Preferred);
    add_key(&vault, Flavor::Preferred);
    vault
        .cmd(Flavor::Legacy)
        .args(["key", "list", "--project", "compat-app"])
        .assert()
        .success()
        .stdout(predicate::str::contains("compat-key"));
}

#[test]
fn tethra_binary_opens_a_vault_created_by_legacy() {
    let vault = TestVault::new(Flavor::Legacy);
    add_key(&vault, Flavor::Legacy);
    vault
        .cmd(Flavor::Preferred)
        .args(["key", "list", "--project", "compat-app"])
        .assert()
        .success()
        .stdout(predicate::str::contains("compat-key"));
}

#[test]
fn wrong_password_is_rejected_under_both_flavors() {
    let vault = TestVault::new(Flavor::Preferred);
    for flavor in [Flavor::Preferred, Flavor::Legacy] {
        let mut cmd = Command::cargo_bin(flavor.bin()).unwrap();
        cmd.env_clear()
            .env(flavor.var("DIR"), &vault.data_dir)
            .env(flavor.var("INSECURE_FAST_KDF"), "1")
            .env(flavor.var("PASSWORD"), "wrong-password-123");
        cmd.args(["project", "list"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("incorrect password"));
    }
}

#[test]
fn tethra_password_wins_over_legacy_password() {
    // Both variables set: TETHRA_PASSWORD (correct) must win over a wrong
    // legacy value — and the correct legacy value must NOT rescue a wrong
    // preferred value.
    let vault = TestVault::new(Flavor::Preferred);
    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("TETHRA_DIR", &vault.data_dir)
        .env("TETHRA_INSECURE_FAST_KDF", "1")
        .env("TETHRA_PASSWORD", MASTER_PW)
        .env("API_TRACKER_PASSWORD", "wrong-password-123");
    cmd.args(["project", "list"]).assert().success();

    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("TETHRA_DIR", &vault.data_dir)
        .env("TETHRA_INSECURE_FAST_KDF", "1")
        .env("TETHRA_PASSWORD", "wrong-password-123")
        .env("API_TRACKER_PASSWORD", MASTER_PW);
    cmd.args(["project", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("incorrect password"));
}

#[test]
fn legacy_dir_alone_still_locates_the_vault() {
    let vault = TestVault::new(Flavor::Preferred);
    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("API_TRACKER_DIR", &vault.data_dir)
        .env("API_TRACKER_INSECURE_FAST_KDF", "1")
        .env("API_TRACKER_PASSWORD", MASTER_PW);
    cmd.args(["project", "list"]).assert().success();
}

#[test]
fn conflicting_dir_vars_warn_and_prefer_tethra_dir() {
    // TETHRA_DIR and API_TRACKER_DIR set to DIFFERENT paths: the preferred
    // location is used and a clear warning names both; the two are never
    // silently combined.
    let vault = TestVault::new(Flavor::Preferred);
    let other = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("TETHRA_DIR", &vault.data_dir)
        .env("API_TRACKER_DIR", other.path())
        .env("TETHRA_INSECURE_FAST_KDF", "1")
        .env("TETHRA_PASSWORD", MASTER_PW);
    cmd.args(["project", "list"]).assert().success().stderr(
        predicate::str::contains("TETHRA_DIR and API_TRACKER_DIR are both set and differ")
            .and(predicate::str::contains("using TETHRA_DIR")),
    );
}

#[test]
fn matching_dir_vars_do_not_warn() {
    let vault = TestVault::new(Flavor::Preferred);
    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("TETHRA_DIR", &vault.data_dir)
        .env("API_TRACKER_DIR", &vault.data_dir)
        .env("TETHRA_INSECURE_FAST_KDF", "1")
        .env("TETHRA_PASSWORD", MASTER_PW);
    cmd.args(["project", "list"])
        .assert()
        .success()
        .stderr(predicate::str::contains("both set and differ").not());
}

#[test]
fn session_export_prints_both_lines_and_both_work() {
    let vault = TestVault::new(Flavor::Preferred);
    let assert = vault
        .cmd(Flavor::Preferred)
        .args(["unlock", "--print-export"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let legacy_token = out
        .lines()
        .find_map(|l| l.strip_prefix("export API_TRACKER_SESSION=\""))
        .and_then(|s| s.strip_suffix('"'))
        .expect("legacy export line printed")
        .to_owned();
    let preferred_token = out
        .lines()
        .find_map(|l| l.strip_prefix("export TETHRA_SESSION=\""))
        .and_then(|s| s.strip_suffix('"'))
        .expect("preferred export line printed")
        .to_owned();
    assert_eq!(legacy_token, preferred_token, "one session, one token");

    // The session works through either variable name, with no password set.
    for (bin, var) in [
        ("tethra", "TETHRA_SESSION"),
        ("api-tracker", "API_TRACKER_SESSION"),
    ] {
        let mut cmd = Command::cargo_bin(bin).unwrap();
        cmd.env_clear()
            .env("TETHRA_DIR", &vault.data_dir)
            .env("TETHRA_INSECURE_FAST_KDF", "1")
            .env(var, &preferred_token);
        cmd.args(["project", "list"]).assert().success();
    }
}

#[test]
fn empty_preferred_session_is_no_session_not_a_fallback() {
    // TETHRA_SESSION present-but-empty means "no session" — it must not
    // fall through to a legacy variable holding a stale/invalid token, and
    // with no password set the command fails with the unlock hint.
    let vault = TestVault::new(Flavor::Preferred);
    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("TETHRA_DIR", &vault.data_dir)
        .env("TETHRA_INSECURE_FAST_KDF", "1")
        .env("TETHRA_SESSION", "")
        .env("API_TRACKER_SESSION", "not-a-valid-token");
    cmd.args(["project", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("tethra unlock"));
}

#[test]
fn help_usage_matches_the_invoked_binary_name() {
    // clap derives the usage line from argv[0], so each entry point shows
    // its own name: no confusing rename for legacy users, and the preferred
    // binary is fully Tethra-branded.
    for (bin, usage) in [
        ("tethra", "Usage: tethra"),
        ("api-tracker", "Usage: api-tracker"),
    ] {
        let mut cmd = Command::cargo_bin(bin).unwrap();
        cmd.env_clear();
        cmd.arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains(usage));
    }
}

#[test]
fn run_scrubs_both_prefixes_from_children() {
    // `tethra run` must scrub TETHRA_* and API_TRACKER_* secrets from the
    // child while keeping the child-safe *_DIR / *_INSECURE_FAST_KDF pairs.
    let vault = TestVault::new(Flavor::Preferred);
    add_key(&vault, Flavor::Preferred);
    let mut cmd = vault.cmd(Flavor::Preferred);
    cmd.env("API_TRACKER_PASSWORD", MASTER_PW)
        .env("TETHRA_BACKUP_PASSWORD", "fake-backup-pw-000")
        .env("API_TRACKER_BACKUP_PASSWORD", "fake-backup-pw-000")
        .args([
            "run",
            "--project",
            "compat-app",
            "--credential",
            "compat-key",
            "--env",
            "COMPAT_KEY",
            "--",
            "/usr/bin/env",
        ]);
    let assert = cmd.assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for leaked in [
        "TETHRA_PASSWORD=",
        "API_TRACKER_PASSWORD=",
        "TETHRA_BACKUP_PASSWORD=",
        "API_TRACKER_BACKUP_PASSWORD=",
        "TETHRA_SESSION=",
        "API_TRACKER_SESSION=",
    ] {
        assert!(
            !out.contains(leaked),
            "{leaked} must be scrubbed from the child environment"
        );
    }
    assert!(
        out.contains("TETHRA_DIR="),
        "child keeps the data-dir override so nested tethra calls work"
    );
}

#[test]
fn stale_session_falls_back_to_password_when_available() {
    // An old script pattern: eval the dual export, `lock`, then
    // `unset API_TRACKER_SESSION` only — leaving a revoked token in
    // TETHRA_SESSION. With a password variable set, commands must fall back
    // to the password rather than wedge on the stale session.
    let vault = TestVault::new(Flavor::Preferred);
    let assert = vault
        .cmd(Flavor::Preferred)
        .args(["unlock", "--print-export"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let token = out
        .lines()
        .find_map(|l| l.strip_prefix("export TETHRA_SESSION=\""))
        .and_then(|s| s.strip_suffix('"'))
        .unwrap()
        .to_owned();
    vault.cmd(Flavor::Preferred).arg("lock").assert().success();

    // Stale token + password: succeeds via the password fallback.
    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("TETHRA_DIR", &vault.data_dir)
        .env("TETHRA_INSECURE_FAST_KDF", "1")
        .env("TETHRA_SESSION", &token)
        .env("TETHRA_PASSWORD", MASTER_PW);
    cmd.args(["project", "list"]).assert().success();

    // Stale token + WRONG password: the password error is reported.
    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("TETHRA_DIR", &vault.data_dir)
        .env("TETHRA_INSECURE_FAST_KDF", "1")
        .env("TETHRA_SESSION", &token)
        .env("TETHRA_PASSWORD", "wrong-password-123");
    cmd.args(["project", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("incorrect password"));

    // Stale token and NO password: still rejected with the session error.
    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("TETHRA_DIR", &vault.data_dir)
        .env("TETHRA_INSECURE_FAST_KDF", "1")
        .env("TETHRA_SESSION", &token);
    cmd.args(["project", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unlock"));
}
