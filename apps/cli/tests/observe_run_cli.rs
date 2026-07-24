//! CLI end-to-end tests for runtime observability. A monitored run of a no-op
//! child exercises the whole orchestration (CA generation, session lifecycle,
//! scoped-trust setup, teardown) without needing real network traffic; the
//! `observe` subcommands are exercised against the resulting state. All values
//! are obvious fakes and every run is fully offline.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const MASTER_PW: &str = "test-master-password";

struct V {
    _dir: TempDir,
    data_dir: std::path::PathBuf,
}

impl V {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        let v = Self { _dir: dir, data_dir };
        v.cmd().arg("init").assert().success();
        v
    }
    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("api-tracker").unwrap();
        c.env_clear()
            .env("API_TRACKER_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("API_TRACKER_PASSWORD", MASTER_PW);
        c
    }
    /// `run` requires at least one credential; add one and map it to an env var.
    fn add_cred(&self, project: &str, name: &str, provider: &str, env: &str) {
        self.cmd()
            .args(["key", "add", "--project", project, "--name", name, "--provider", provider, "--value-stdin"])
            .write_stdin("FAKE-TEST-NOT-A-REAL-KEY-000001")
            .assert()
            .success();
        self.cmd()
            .args(["mapping", "set", "--project", project, "--credential", name, "--env", env])
            .assert()
            .success();
    }
}

#[cfg(unix)]
#[test]
fn monitored_run_creates_a_session_and_generates_a_ca() {
    let v = V::new();
    v.cmd().args(["project", "create", "web"]).assert().success();
    v.add_cred("web", "k", "openai", "OPENAI_API_KEY");

    // Metadata mode: a no-op child. Exercises CA generation + full lifecycle.
    v.cmd()
        .args(["run", "--observe=metadata", "--project", "web", "--", "sh", "-c", "true"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Observing this run in metadata mode"))
        .stderr(predicate::str::contains("Metadata only"));

    // A completed session now exists.
    v.cmd()
        .args(["observe", "sessions"])
        .assert()
        .success()
        .stdout(predicate::str::contains("completed"));

    // The local CA was generated and stored.
    v.cmd()
        .args(["observe", "cert", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Local CA present"))
        .stdout(predicate::str::contains("fingerprint"));

    // Diagnostics run and never suggest disabling verification.
    v.cmd()
        .args(["observe", "diagnostics"])
        .assert()
        .success()
        .stdout(predicate::str::contains("loopback_bind"))
        .stdout(predicate::str::contains("upstream_tls_verification"));
}

#[cfg(unix)]
#[test]
fn connection_mode_needs_no_certificate() {
    let v = V::new();
    v.cmd().args(["project", "create", "svc"]).assert().success();
    v.add_cred("svc", "k", "openai", "OPENAI_API_KEY");

    v.cmd()
        .args(["run", "--observe=connection", "--project", "svc", "--", "sh", "-c", "true"])
        .assert()
        .success()
        .stderr(predicate::str::contains("connection mode"));

    // Connection mode does not generate a CA.
    v.cmd()
        .args(["observe", "cert", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No local CA yet"));
}

#[test]
fn observe_subcommands_work_on_an_empty_vault() {
    let v = V::new();

    v.cmd()
        .args(["observe", "overview"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No API traffic observed yet"));

    v.cmd()
        .args(["observe", "settings", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("default mode:"))
        .stdout(predicate::str::contains("7 days"));

    v.cmd()
        .args(["observe", "settings", "set", "--event-days", "14", "--aggregate-days", "180"])
        .assert()
        .success();

    v.cmd()
        .args(["observe", "settings", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("14 days"));

    // JSON mode is available.
    v.cmd()
        .args(["--json", "observe", "sessions"])
        .assert()
        .success()
        .stdout(predicate::str::contains("["));
}

#[test]
fn non_observed_run_is_unchanged() {
    // Regression: a plain `run` (no --observe) must behave exactly as before.
    let v = V::new();
    v.cmd().args(["project", "create", "p"]).assert().success();
    v.add_cred("p", "k", "openai", "OPENAI_API_KEY");
    v.cmd()
        .args(["run", "--project", "p", "--", "sh", "-c", "true"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Child process exited with code 0"));
    // No observation session was created for a non-observed run.
    v.cmd()
        .args(["observe", "sessions"])
        .assert()
        .success()
        .stdout(predicate::str::contains("completed").not());
}
