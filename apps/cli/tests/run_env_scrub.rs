//! PI-01 / CLI-01 regression: `api-tracker run` must scrub every API
//! Tracker authentication/password/session variable from the injected
//! child's environment — deny-by-default over the whole `API_TRACKER_`
//! prefix — while explicitly mapped credential variables and the child-safe
//! metadata (`API_TRACKER_DIR`) still arrive. At baseline `7d81090` the
//! enumerated scrub list missed `API_TRACKER_NEW_PASSWORD`, leaking a
//! master password to any launched process (and any future variable would
//! have leaked the same way).
//!
//! The child prints its own environment; sentinels are unmistakably fake
//! and never passed as command-line arguments.

#![cfg(unix)]

use assert_cmd::Command;
use std::collections::HashMap;
use tempfile::TempDir;

const MASTER_PW: &str = "run-scrub-master-password-01";
const FAKE_KEY: &str = "FAKE-TEST-NOT-A-REAL-KEY-SCRUB01";

/// Sentinel values for every sensitive Tethra variable a parent shell
/// might hold, plus a hypothetical future variable proving deny-by-default.
/// (`API_TRACKER_SESSION` is exercised separately with a REAL token — the
/// CLI validates it before running, so a sentinel would refuse the launch.)
const SENSITIVE: &[(&str, &str)] = &[
    ("API_TRACKER_NEW_PASSWORD", "SENTINEL-NEW-PASSWORD-000001"),
    ("API_TRACKER_PROJECT_PASSWORD", "SENTINEL-PROJECT-PW-000001"),
    ("API_TRACKER_BACKUP_PASSWORD", "SENTINEL-BACKUP-PW-000001"),
    (
        "API_TRACKER_PROVIDER_ADMIN_KEY",
        "SENTINEL-ADMIN-KEY-000001",
    ),
    ("API_TRACKER_DESTINATION_AUTH", "SENTINEL-DEST-AUTH-000001"),
    ("API_TRACKER_FUTURE_SECRET", "SENTINEL-FUTURE-VAR-000001"),
];

fn cmd(data_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("api-tracker").unwrap();
    cmd.env_clear()
        .env("API_TRACKER_DIR", data_dir)
        .env("API_TRACKER_INSECURE_FAST_KDF", "1")
        .env("API_TRACKER_PASSWORD", MASTER_PW);
    cmd
}

#[test]
fn injected_child_sees_mapped_credentials_but_no_api_tracker_auth_vars() {
    let dir = TempDir::new().unwrap();
    let data_dir = dir.path().join("data");
    cmd(&data_dir).arg("init").assert().success();
    cmd(&data_dir)
        .args(["project", "create", "app"])
        .assert()
        .success();
    cmd(&data_dir)
        .args([
            "key",
            "add",
            "--project",
            "app",
            "--name",
            "main-key",
            "--value-stdin",
        ])
        .write_stdin(FAKE_KEY)
        .assert()
        .success();

    // A real session token, as an eval'd `unlock --print-export` would
    // leave in the parent shell (the CLI validates the token, so only a
    // genuine one exercises the leak path).
    let unlock = cmd(&data_dir)
        .args(["unlock", "--print-export"])
        .output()
        .unwrap();
    assert!(unlock.status.success());
    let export = String::from_utf8(unlock.stdout).unwrap();
    let session_token = export
        .lines()
        .find_map(|l| l.strip_prefix("export API_TRACKER_SESSION=\""))
        .and_then(|s| s.strip_suffix('"'))
        .expect("unlock --print-export output shape")
        .to_owned();

    // The parent environment carries every sensitive variable; the child
    // prints its environment for inspection.
    let mut run = cmd(&data_dir);
    run.env("API_TRACKER_SESSION", &session_token);
    for (name, value) in SENSITIVE {
        run.env(name, value);
    }
    let output = run
        .args([
            "run",
            "--project",
            "app",
            "--credential",
            "main-key",
            "--env",
            "OPENAI_API_KEY",
            "--",
            "/usr/bin/env",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "run must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let child_env = String::from_utf8(output.stdout).unwrap();
    let vars: HashMap<&str, &str> = child_env
        .lines()
        .filter_map(|l| l.split_once('='))
        .collect();

    // The explicitly mapped credential arrives.
    assert_eq!(
        vars.get("OPENAI_API_KEY"),
        Some(&FAKE_KEY),
        "the mapped credential variable must be injected"
    );
    // Child-safe metadata is preserved (a child that itself runs
    // `api-tracker` must reach the same vault).
    assert!(
        vars.contains_key("API_TRACKER_DIR"),
        "API_TRACKER_DIR is classified child-safe and must survive"
    );

    // No Tethra authentication material of any kind reaches the child:
    // not the scripting master password, not the live session token, and
    // none of the sensitive set.
    assert!(
        !vars.contains_key("API_TRACKER_PASSWORD"),
        "PI-01 regression: the master password variable reached the child"
    );
    assert!(
        !vars.contains_key("API_TRACKER_SESSION"),
        "PI-01 regression: the session token variable reached the child"
    );
    assert!(
        !child_env.contains(&session_token),
        "PI-01 regression: the session token value appears in the child environment"
    );
    for (name, value) in SENSITIVE {
        assert!(
            !vars.contains_key(name),
            "PI-01 regression: {name} reached the injected child's environment"
        );
        assert!(
            !child_env.contains(value),
            "PI-01 regression: the value of {name} appears in the child environment"
        );
    }
    assert!(
        !child_env.contains(MASTER_PW),
        "PI-01 regression: the master password value appears in the child environment"
    );

    // Deny-by-default: no API_TRACKER_* variable other than the child-safe
    // allowlist survives at all.
    for name in vars.keys().filter(|n| n.starts_with("API_TRACKER_")) {
        assert!(
            api_tracker_core::inject::CHILD_SAFE_ENV.contains(name),
            "unexpected Tethra variable in the child environment: {name}"
        );
    }
}
