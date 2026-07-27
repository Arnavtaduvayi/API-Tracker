//! `tethra track` CLI behavior (TEST_PLAN §6). Offline; fake values; no
//! real service is ever installed (dry-run and the no-detection/undo
//! paths only — the full apply engine is covered by the tracking crate's
//! mock-ops suites and the packaged validation script).

#![cfg(unix)]

use assert_cmd::Command;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const MASTER_PW: &str = "test-master-password";
const FAKE_OPENAI_KEY: &str = "sk-proj-FAKE-TEST-KEY-0000000000000001";

struct TestVault {
    _dir: TempDir,
    data_dir: PathBuf,
}

impl TestVault {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        let tv = TestVault {
            _dir: dir,
            data_dir,
        };
        tv.cmd().arg("init").assert().success();
        tv
    }

    /// An isolated fake HOME so lifecycle code can never see (let alone
    /// touch) the real ~/Library/LaunchAgents or ~/.config/systemd.
    fn home(&self) -> PathBuf {
        self._dir.path().join("home")
    }

    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("tethra").unwrap();
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.home())
            .env("TETHRA_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("TETHRA_PASSWORD", MASTER_PW);
        c
    }

    fn project_dir(&self) -> PathBuf {
        let p = self._dir.path().join("myapp");
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}

fn write_fixture(dir: &Path) {
    std::fs::write(
        dir.join(".env"),
        format!("OPENAI_API_KEY={FAKE_OPENAI_KEY}\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{ "dependencies": { "openai": "^4.0.0", "dotenv": "^16.0.0" } }"#,
    )
    .unwrap();
}

#[test]
fn dry_run_shows_the_plan_and_writes_nothing() {
    let tv = TestVault::new();
    let dir = tv.project_dir();
    write_fixture(&dir);
    let env_before = std::fs::read_to_string(dir.join(".env")).unwrap();

    let assert = tv
        .cmd()
        .args(["track", "--dry-run"])
        .arg(&dir)
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(out.contains("Detected:"), "{out}");
    assert!(out.contains("openai"), "{out}");
    assert!(out.contains("OPENAI_BASE_URL"), "diff shown: {out}");
    assert!(out.contains("Dry run: nothing was changed."), "{out}");

    // Nothing changed on disk or in the DB.
    assert_eq!(
        std::fs::read_to_string(dir.join(".env")).unwrap(),
        env_before
    );
    let status = tv
        .cmd()
        .args(["track", "status"])
        .arg(&dir)
        .assert()
        .code(2);
    let sout = String::from_utf8_lossy(&status.get_output().stdout).to_string();
    assert!(sout.contains("not configured"), "{sout}");
    // A dry run must not even create the project.
    let projects = tv.cmd().args(["project", "list"]).assert().success();
    let plist = String::from_utf8_lossy(&projects.get_output().stdout).to_string();
    assert!(
        !plist.contains("myapp"),
        "dry-run created a project: {plist}"
    );
}

#[test]
fn no_detection_exits_2_with_honest_guidance() {
    let tv = TestVault::new();
    let dir = tv.project_dir();
    // Empty folder: nothing to detect.
    let assert = tv.cmd().arg("track").arg(&dir).assert().code(2);
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(out.contains("No trackable APIs detected"), "{out}");
    assert!(out.contains("nothing executed or uploaded"), "{out}");
}

#[test]
fn track_never_prints_shell_export_choreography() {
    let tv = TestVault::new();
    let dir = tv.project_dir();
    write_fixture(&dir);
    let assert = tv
        .cmd()
        .args(["track", "--dry-run"])
        .arg(&dir)
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    for needle in ["--print-export", "eval \"$(", "export TETHRA_SESSION"] {
        assert!(!out.contains(needle) && !err.contains(needle), "{needle}");
    }
}

#[test]
fn no_secret_value_appears_in_track_output() {
    let tv = TestVault::new();
    let dir = tv.project_dir();
    write_fixture(&dir);
    let assert = tv
        .cmd()
        .args(["track", "--dry-run"])
        .arg(&dir)
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        !out.contains(FAKE_OPENAI_KEY),
        "the key value leaked into track output"
    );
}

#[test]
fn status_and_undo_are_honest_when_nothing_is_configured() {
    let tv = TestVault::new();
    let dir = tv.project_dir();
    tv.cmd()
        .args(["track", "status"])
        .arg(&dir)
        .assert()
        .code(2)
        .stdout(predicates::str::contains("not configured"));
    tv.cmd()
        .args(["track", "undo", "--yes"])
        .arg(&dir)
        .assert()
        .success()
        .stdout(predicates::str::contains("nothing to undo"));
}

#[test]
fn ambiguous_folder_registration_is_an_explicit_error() {
    let tv = TestVault::new();
    let dir = tv.project_dir();
    write_fixture(&dir);
    let dir_str = dir.canonicalize().unwrap().display().to_string();
    for name in ["app-one", "app-two"] {
        tv.cmd()
            .args(["project", "create", name, "--repo", &dir_str])
            .assert()
            .success();
    }
    let assert = tv
        .cmd()
        .args(["track", "--dry-run"])
        .arg(&dir)
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(err.contains("more than one project"), "{err}");
    assert!(err.contains("--project"), "{err}");
}

#[test]
fn explicit_project_selects_the_named_one() {
    let tv = TestVault::new();
    let dir = tv.project_dir();
    write_fixture(&dir);
    tv.cmd()
        .args(["project", "create", "chosen-app"])
        .assert()
        .success();
    let assert = tv
        .cmd()
        .args(["track", "--dry-run", "--project", "chosen-app"])
        .arg(&dir)
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(out.contains("chosen-app"), "{out}");
}

#[test]
fn track_json_status_shape_is_stable() {
    let tv = TestVault::new();
    let dir = tv.project_dir();
    write_fixture(&dir);
    // Unconfigured: exit 2, human message (status only emits JSON once a
    // setup exists — pin that behavior too).
    tv.cmd()
        .args(["--json", "track", "status"])
        .arg(&dir)
        .assert()
        .code(2);
}

#[test]
fn track_help_documents_the_one_command_flow() {
    let tv = TestVault::new();
    let assert = tv.cmd().args(["track", "--help"]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    for needle in ["--dry-run", "--project", "status", "doctor", "undo"] {
        assert!(out.contains(needle), "missing {needle} in help: {out}");
    }
}
