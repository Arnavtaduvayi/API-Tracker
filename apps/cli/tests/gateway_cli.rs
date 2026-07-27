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

    /// `gateway status --json`, parsed. This is also how the tests learn the
    /// resolved service name and definition path without duplicating the
    /// platform naming rules — if the CLI stopped reporting them, every
    /// caller below would fail loudly rather than silently skip.
    fn status_json(&self) -> serde_json::Value {
        let out = self
            .cmd()
            .args(["--json", "gateway", "status"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice(&out).expect("gateway status --json emits JSON")
    }
}

/// Plant a service definition in THIS environment's slot that points at a
/// DIFFERENT data directory — exactly what a second Tethra environment (or a
/// data directory that moved) leaves behind, and the condition under which
/// `stop`/`restart`/`disable`/`uninstall` used to act on the other
/// installation's job.
///
/// Only the file-based platforms are exercised: macOS and Linux keep the
/// definition under the test's isolated `HOME`, so nothing outside the temp
/// tree is ever written and no service manager is ever invoked. The Windows
/// definition is an HKCU registry value, which a test must not create, so
/// that platform is covered by the gateway crate's mocked lifecycle suite.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn plant_foreign_definition(v: &TestVault, other_data_dir: &std::path::Path) -> PathBuf {
    let status = v.status_json();
    let service = &status["service"];
    let path = PathBuf::from(
        service["definition_path"]
            .as_str()
            .expect("status reports the definition path"),
    );
    let name = service["service_name"]
        .as_str()
        .expect("status reports the resolved service name");
    assert!(
        path.starts_with(v.home()),
        "the test must never write outside its isolated HOME: {path:?}"
    );
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let other = other_data_dir.display();

    #[cfg(target_os = "macos")]
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{name}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{other}/bin/tethra-gateway-0.1.0</string>
		<string>gateway</string>
		<string>serve</string>
		<string>--service</string>
		<string>--data-dir</string>
		<string>{other}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
"#
    );
    #[cfg(target_os = "linux")]
    let body = format!(
        "[Unit]\nDescription=Tethra Local Gateway ({name})\n\n[Service]\nType=simple\n\
         ExecStart=\"{other}/bin/tethra-gateway-0.1.0\" gateway serve --service \
         --data-dir \"{other}\"\n\n[Install]\nWantedBy=default.target\n"
    );

    std::fs::write(&path, body).unwrap();
    path
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
fn status_and_doctor_name_the_service_and_the_installation() {
    // Two Tethra environments on one account control two different launchd
    // labels / systemd units / registry values. Without the resolved name
    // and the installation id in the output there is no way to tell which
    // one a command just acted on — or to inspect it by hand.
    let v = TestVault::new();
    let status = v.status_json();
    let name = status["service"]["service_name"].as_str().unwrap();
    let id = status["service"]["installation_id"].as_str().unwrap();
    assert!(
        !name.is_empty(),
        "the resolved service name must be reported"
    );
    assert!(
        !id.is_empty() && name.contains(id),
        "the service name must carry this installation's id: {name} / {id}"
    );

    // Human output carries both, even with nothing installed: the name is
    // the slot this data directory WOULD claim.
    v.cmd()
        .args(["gateway", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("  name      {name}")))
        .stdout(predicate::str::contains(format!("  id        {id}")));

    v.cmd()
        .args(["gateway", "doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("service identity"))
        .stdout(predicate::str::contains(format!("  name      {name}")))
        .stdout(predicate::str::contains(format!("  id        {id}")));

    // A second data directory under the same HOME must resolve to a
    // DIFFERENT job, or the namespacing is not doing anything.
    let other = TestVault::new();
    let other_name = other.status_json()["service"]["service_name"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        name, other_name,
        "two data directories must control two different services"
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn lifecycle_verbs_refuse_a_service_that_belongs_to_another_data_directory() {
    // ZFT-014: these verbs gated only on `installed` and acted on whatever
    // job held the slot; `uninstall` additionally deleted the other
    // environment's definition file.
    let v = TestVault::new();
    let other_dir = v.home().join("other-tethra-data");
    std::fs::create_dir_all(&other_dir).unwrap();
    let definition = plant_foreign_definition(&v, &other_dir);
    let planted = std::fs::read(&definition).unwrap();
    let other = other_dir.display().to_string();

    for args in [
        vec!["gateway", "stop"],
        vec!["gateway", "start"],
        vec!["gateway", "restart"],
        vec!["gateway", "disable", "--yes"],
        vec!["gateway", "uninstall", "--yes"],
        vec!["gateway", "repair", "--yes"],
    ] {
        let label = args.join(" ");
        v.cmd()
            .args(&args)
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("different Tethra data directory")
                    .and(predicate::str::contains(other.clone())),
            )
            .stderr(predicate::str::contains("--data-dir"));
        // Nothing may have been torn down, and above all the other
        // environment's definition must still be there, byte for byte.
        assert_eq!(
            std::fs::read(&definition).unwrap(),
            planted,
            "`{label}` must not touch another installation's definition"
        );
    }

    // The refusal is also visible before the user runs anything.
    v.cmd()
        .args(["gateway", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("DIFFERENT data"))
        .stdout(predicate::str::contains(other.clone()));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn install_force_discloses_what_it_replaces_and_still_needs_confirmation() {
    let v = TestVault::new();
    let other_dir = v.home().join("other-tethra-data");
    std::fs::create_dir_all(&other_dir).unwrap();
    let definition = plant_foreign_definition(&v, &other_dir);
    let planted = std::fs::read(&definition).unwrap();
    let other = other_dir.display().to_string();
    let service_name = v.status_json()["service"]["service_name"]
        .as_str()
        .unwrap()
        .to_string();

    // Without --force: refuse immediately, BEFORE the consent wall, the
    // vault unlock, and the port binding the engine's own refusal would
    // otherwise have wasted.
    v.cmd()
        .args(["gateway", "install", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("different Tethra data directory"))
        .stderr(predicate::str::contains(other.clone()))
        .stdout(predicate::str::contains("Tethra can run a local background gateway").not());

    // With --force but without --yes: the replacement is spelled out (other
    // data directory AND service name), and the run still stops at the
    // confirmation. Nothing is installed and the planted definition stands.
    v.cmd()
        .args(["gateway", "install", "--force"])
        .assert()
        .failure()
        .stdout(predicate::str::contains(
            "REPLACES an existing service definition",
        ))
        .stdout(predicate::str::contains(other.clone()))
        .stdout(predicate::str::contains(service_name))
        .stderr(predicate::str::contains("--yes"));
    assert_eq!(
        std::fs::read(&definition).unwrap(),
        planted,
        "a --force run that was never confirmed must replace nothing"
    );
    assert!(
        !v.data_dir.join("bin").exists(),
        "no helper binary may be installed before the replacement is confirmed"
    );
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
