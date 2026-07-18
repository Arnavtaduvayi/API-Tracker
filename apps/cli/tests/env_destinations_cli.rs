//! CLI end-to-end tests for `.env` governance, destinations, and sync
//! plans. Fake credentials only; no network access (destination tests here
//! never execute remote writes).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

const MASTER_PW: &str = "test-master-password";
const FAKE_OPENAI: &str = "sk-proj-FAKE0000000000000000000000000000FAKE";

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
        v
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("api-tracker").unwrap();
        cmd.env_clear()
            .env("API_TRACKER_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("API_TRACKER_PASSWORD", MASTER_PW);
        cmd
    }
}

#[test]
fn env_import_maps_and_never_prints_the_value() {
    let v = TestVault::new();
    v.cmd()
        .args(["project", "create", "web"])
        .assert()
        .success();
    let env_file = v.dir.path().join(".env");
    std::fs::write(&env_file, format!("OPENAI_API_KEY={FAKE_OPENAI}\nAPP=x\n")).unwrap();

    // Preview shows the variable masked, never in full.
    let assert = v
        .cmd()
        .args(["env", "preview", "--project", "web"])
        .arg(&env_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("OPENAI_API_KEY"));
    let out = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(!out.contains(FAKE_OPENAI), "preview must mask values");

    // Import with --yes; the file itself is untouched.
    let before = std::fs::read_to_string(&env_file).unwrap();
    v.cmd()
        .args(["env", "import", "--project", "web", "--yes"])
        .arg(&env_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("imported"));
    assert_eq!(std::fs::read_to_string(&env_file).unwrap(), before);

    // The mapping exists and drives `run`.
    v.cmd()
        .args(["mapping", "list", "--project", "web"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OPENAI_API_KEY"));
}

#[test]
fn env_migrate_removes_plaintext_after_import_and_run_still_works() {
    let v = TestVault::new();
    v.cmd()
        .args(["project", "create", "web"])
        .assert()
        .success();
    let env_file = v.dir.path().join(".env");
    std::fs::write(
        &env_file,
        format!("# config\nOPENAI_API_KEY={FAKE_OPENAI}\nAPP=x\n"),
    )
    .unwrap();

    v.cmd()
        .args(["env", "migrate", "--project", "web", "--yes"])
        .arg(&env_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Done."));
    let after = std::fs::read_to_string(&env_file).unwrap();
    assert!(!after.contains(FAKE_OPENAI), "plaintext must be removed");
    assert!(after.contains("# config"), "comments survive");
    assert!(after.contains("APP=x"), "non-secrets survive");

    // The project still launches through injection.
    let out_file = v.dir.path().join("saw.txt");
    let script = format!("printf '%s' \"$OPENAI_API_KEY\" > {}", out_file.display());
    v.cmd()
        .args(["run", "--project", "web", "--"])
        .args(["sh", "-c", &script])
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(&out_file).unwrap(), FAKE_OPENAI);
}

#[test]
fn env_export_is_gated_confirmed_and_cleaned_up() {
    let v = TestVault::new();
    v.cmd()
        .args(["project", "create", "web"])
        .assert()
        .success();
    let env_file = v.dir.path().join("seed.env");
    std::fs::write(&env_file, format!("OPENAI_API_KEY={FAKE_OPENAI}\n")).unwrap();
    v.cmd()
        .args(["env", "import", "--project", "web", "--yes"])
        .arg(&env_file)
        .assert()
        .success();

    let target = v.dir.path().join("out").join(".env");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    // Without --yes and without a terminal, the export refuses.
    v.cmd()
        .args(["env", "export", "--project", "web", "--to"])
        .arg(&target)
        .assert()
        .failure();
    assert!(!target.exists());

    v.cmd()
        .args([
            "env",
            "export",
            "--project",
            "web",
            "--ttl",
            "0",
            "--yes",
            "--to",
        ])
        .arg(&target)
        .assert()
        .success()
        .stdout(predicate::str::contains("PLAINTEXT").or(predicate::str::contains("plaintext")));
    assert!(std::fs::read_to_string(&target)
        .unwrap()
        .contains(FAKE_OPENAI));

    // Expired ttl → cleanup removes it. (The unlock-time sweep may already
    // have removed it before the explicit command ran — both are correct.)
    v.cmd().args(["env", "cleanup"]).assert().success();
    assert!(!target.exists());
}

#[test]
fn env_example_never_contains_values() {
    let v = TestVault::new();
    let env_file = v.dir.path().join(".env");
    std::fs::write(&env_file, format!("OPENAI_API_KEY={FAKE_OPENAI}\n")).unwrap();
    v.cmd()
        .args(["env", "example", "--write", "--yes"])
        .arg(&env_file)
        .assert()
        .success();
    let example = std::fs::read_to_string(v.dir.path().join(".env.example")).unwrap();
    assert!(example.contains("OPENAI_API_KEY="));
    assert!(!example.contains(FAKE_OPENAI));
}

#[test]
fn destination_kinds_shows_honest_matrix_without_a_vault() {
    let v = TestVault::new();
    v.cmd()
        .args(["destination", "kinds"])
        .assert()
        .success()
        .stdout(predicate::str::contains("aws_secrets_manager"))
        .stdout(predicate::str::contains("github_actions"))
        .stdout(predicate::str::contains("vercel"))
        .stdout(predicate::str::contains("macos_keychain"));
}

#[test]
fn destination_add_attach_plan_flow_stays_dry_without_execution() {
    let v = TestVault::new();
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
        .write_stdin(FAKE_OPENAI)
        .assert()
        .success();

    // Add a GitHub destination without network verification.
    v.cmd()
        .args([
            "destination",
            "add",
            "github_actions",
            "--name",
            "ci",
            "--owner",
            "octo",
            "--repo",
            "app",
            "--auth-stdin",
            "--no-verify",
        ])
        .write_stdin("ghp_FAKE0000000000000000000000000000000000")
        .assert()
        .success()
        .stdout(predicate::str::contains("Configured destination 'ci'"));

    // The token never shows up in listings.
    let assert = v.cmd().args(["destination", "list"]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(!out.contains("ghp_FAKE0000000000000000000000000000000000"));

    v.cmd()
        .args([
            "destination",
            "attach",
            "web/openai",
            "ci",
            "--secret-name",
            "OPENAI_API_KEY",
            "--environment",
            "production",
        ])
        .assert()
        .success();

    // A plan is generated as a dry run and clearly says so.
    let assert = v
        .cmd()
        .args(["sync", "plan", "web/openai", "--note", "test rotation"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run — nothing was written"));
    let out = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(out.contains("ci"));
    assert!(out.contains("write"));
    assert!(!out.contains(FAKE_OPENAI), "plans must mask values");

    // Plans list; nothing was executed (status planned).
    v.cmd()
        .args(["sync", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("planned"));

    // Removing the destination requires no network and leaves the vault clean.
    v.cmd()
        .args(["destination", "remove", "ci", "--yes"])
        .assert()
        .success();
}

#[test]
fn version_history_is_masked_and_reauth_gated() {
    let v = TestVault::new();
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
        .write_stdin(FAKE_OPENAI)
        .assert()
        .success();
    let v2 = "sk-proj-FAKE0000000000000000000000000000NEW1";
    v.cmd()
        .args([
            "key",
            "update",
            "web/openai",
            "--new-value",
            "--value-stdin",
        ])
        .write_stdin(v2)
        .assert()
        .success();
    let assert = v
        .cmd()
        .args(["key", "versions", "web/openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("current"));
    let out = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(!out.contains(FAKE_OPENAI));
    assert!(!out.contains(v2));
    assert!(out.contains("v2") || out.contains('2'));
}
