//! Gateway CLI end-to-end tests. Offline; fake values; no real service is
//! ever installed (install itself is exercised only through its refusal
//! paths — the mocked lifecycle engine has its own suite in the gateway
//! crate, and real launchd behavior is packaged-validation evidence).

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
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        let v = Self {
            _dir: dir,
            data_dir,
        };
        v.cmd().arg("init").assert().success();
        v
    }

    /// An isolated fake HOME so lifecycle code can never see (let alone
    /// touch) the real ~/Library/LaunchAgents or ~/.config/systemd.
    fn home(&self) -> PathBuf {
        self.data_dir.parent().unwrap().join("home")
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("tethra").unwrap();
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home())
            .env("TETHRA_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("TETHRA_PASSWORD", MASTER_PW);
        cmd
    }
}

#[test]
fn service_probe_prints_the_marker_and_touches_nothing() {
    let dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("TETHRA_DIR", dir.path().join("never-created"))
        .args(["gateway", "service-probe"])
        .assert()
        .success()
        .stdout(predicate::str::contains("tethra-gateway-service-probe"));
    assert!(
        !dir.path().join("never-created").exists(),
        "the probe must not create a data directory or database"
    );
}

#[test]
fn status_and_doctor_work_without_a_vault_password_and_are_honest_when_absent() {
    let v = TestVault::new();
    // No TETHRA_PASSWORD in the environment: status/doctor stay lock-free.
    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", v.home())
        .env("TETHRA_DIR", &v.data_dir)
        .args(["gateway", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not installed"))
        .stdout(predicate::str::contains("gateway     not running"));

    let mut cmd = Command::cargo_bin("tethra").unwrap();
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", v.home())
        .env("TETHRA_DIR", &v.data_dir)
        .args(["--json", "gateway", "doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"not_installed\""));
}

#[test]
fn route_enable_disable_and_list_reflect_state() {
    let v = TestVault::new();
    v.cmd()
        .args(["gateway", "route", "add", "openai"])
        .assert()
        .success();
    v.cmd()
        .args(["gateway", "route", "disable", "openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("disabled"));
    v.cmd()
        .args(["gateway", "route", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DISABLED"));
    v.cmd()
        .args(["gateway", "route", "enable", "openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("enabled"));
    v.cmd()
        .args(["gateway", "route", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("api.openai.com"));
    // Unknown prefixes answer without side effects.
    v.cmd()
        .args(["gateway", "route", "enable", "missing"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no route"));
}

#[test]
fn link_previews_a_diff_confirms_writes_and_unlink_restores() {
    let v = TestVault::new();
    v.cmd()
        .args(["project", "create", "app"])
        .assert()
        .success();
    v.cmd()
        .args(["gateway", "route", "add", "openai"])
        .assert()
        .success();
    // A persisted port is required for a stable base URL; without one the
    // link refuses with an actionable message.
    let env_file = v.data_dir.join("app.env");
    std::fs::write(
        &env_file,
        "OPENAI_BASE_URL=https://corp.example/v1\nAPP=1\n",
    )
    .unwrap();
    v.cmd()
        .args([
            "gateway",
            "link",
            "--project",
            "app",
            "--route",
            "openai",
            "--env-file",
            env_file.to_str().unwrap(),
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("port"));

    // Persist a port the way serve/install would.
    v.cmd()
        .args(["gateway", "serve", "--port", "0"]) // binds ephemeral, persists
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .interrupted();

    // Dry run: shows the exact URL, changes nothing.
    let before = std::fs::read_to_string(&env_file).unwrap();
    v.cmd()
        .args([
            "gateway",
            "link",
            "--project",
            "app",
            "--route",
            "openai",
            "--env-file",
            env_file.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("http://127.0.0.1:"))
        .stdout(predicate::str::contains("dry run"));
    assert_eq!(std::fs::read_to_string(&env_file).unwrap(), before);

    // Real link with --yes.
    v.cmd()
        .args([
            "gateway",
            "link",
            "--project",
            "app",
            "--route",
            "openai",
            "--env-file",
            env_file.to_str().unwrap(),
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("linked"));
    let written = std::fs::read_to_string(&env_file).unwrap();
    assert!(written.contains("# tethra-gateway route: openai (project: app)"));
    assert!(written.contains("OPENAI_BASE_URL=http://127.0.0.1:"));
    assert!(written.contains("NO_PROXY=127.0.0.1,localhost,::1"));
    assert!(written.contains("APP=1"), "user content preserved");

    // Unlink restores the original values exactly.
    v.cmd()
        .args([
            "gateway",
            "unlink",
            "--project",
            "app",
            "--route",
            "openai",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("unlinked"));
    assert_eq!(std::fs::read_to_string(&env_file).unwrap(), before);
}

#[test]
fn start_and_restart_refuse_honestly_when_nothing_is_installed() {
    let v = TestVault::new();
    v.cmd()
        .args(["gateway", "start"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no gateway service is installed"));
    v.cmd()
        .args(["gateway", "restart"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no gateway service"));
    // stop is a no-op, not an error, when nothing runs.
    v.cmd()
        .args(["gateway", "stop"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing to stop"));
}

#[test]
fn install_requires_confirmation_and_run_is_an_alias_for_serve() {
    let v = TestVault::new();
    // Without --yes on a non-TTY, install must refuse before touching
    // anything (the confirm gate).
    v.cmd()
        .args(["gateway", "install"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--yes"));

    // `gateway run` (the documented verb) is the same command as serve
    // (HANDOFF_PHASE_2 D4 resolution).
    v.cmd()
        .args(["gateway", "run", "--port", "0"])
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .interrupted();
}

#[test]
fn link_hint_uses_the_route_providers_variables_not_the_prefix() {
    // Regression for the Phase 2 bug where the .env variable lookup used
    // the ROUTE PREFIX instead of the route's provider id.
    let v = TestVault::new();
    v.cmd()
        .args(["project", "create", "app"])
        .assert()
        .success();
    v.cmd()
        .args(["gateway", "route", "add", "openai", "--prefix", "oai"])
        .assert()
        .success();
    v.cmd()
        .args(["gateway", "serve", "--port", "0"])
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .interrupted();
    let env_file = v.data_dir.join("app.env");
    std::fs::write(&env_file, "").unwrap();
    v.cmd()
        .args([
            "gateway",
            "link",
            "--project",
            "app",
            "--route",
            "oai",
            "--env-file",
            env_file.to_str().unwrap(),
            "--yes",
        ])
        .assert()
        .success();
    let written = std::fs::read_to_string(&env_file).unwrap();
    assert!(
        written.contains("OPENAI_BASE_URL=http://127.0.0.1:") && written.contains("/p/"),
        "provider-declared variables must be written for a custom prefix: {written}"
    );
    assert!(
        written.contains("/oai/v1"),
        "the URL carries the route prefix: {written}"
    );
}
