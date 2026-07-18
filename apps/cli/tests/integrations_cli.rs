//! CLI end-to-end tests for milestone 3: validation, usage, budgets,
//! activity, and secure process injection. Fake credentials only.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
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

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("api-tracker").unwrap();
        cmd.env_clear()
            .env("API_TRACKER_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("API_TRACKER_PASSWORD", MASTER_PW);
        cmd
    }

    fn add_key(&self, project: &str, name: &str, provider: &str, value: &str) {
        let _ = self.cmd().args(["project", "create", project]).assert();
        self.cmd()
            .args([
                "key",
                "add",
                "--project",
                project,
                "--name",
                name,
                "--provider",
                provider,
                "--environment",
                "production",
                "--value-stdin",
            ])
            .write_stdin(value)
            .assert()
            .success();
    }
}

#[test]
fn run_injects_exactly_one_credential_and_never_writes_it() {
    let v = TestVault::new();
    v.add_key("web", "openai", "openai", FAKE_OPENAI);

    // The child echoes the injected variable into a file we control, proving
    // the child received it. (In real use nothing writes it; this is the test
    // harness capturing the child's own environment.)
    let out_file = v._dir.path().join("child-saw.txt");
    let script = format!("printf '%s' \"$OPENAI_API_KEY\" > {}", out_file.display());

    v.cmd()
        .args([
            "run",
            "--project",
            "web",
            "--credential",
            "web/openai",
            "--env",
            "OPENAI_API_KEY",
            "--",
            "sh",
            "-c",
            &script,
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Injecting 1 credential"))
        // The value itself is never printed by api-tracker.
        .stderr(predicate::str::contains(FAKE_OPENAI).not())
        .stdout(predicate::str::contains(FAKE_OPENAI).not());

    // The child genuinely received the credential.
    let seen = std::fs::read_to_string(&out_file).unwrap();
    assert_eq!(
        seen, FAKE_OPENAI,
        "child process must receive the injected value"
    );

    // The value is NOT stored anywhere in the vault data dir in plaintext,
    // and no .env was written.
    assert!(!v.data_dir.join(".env").exists());
    for entry in walk(&v.data_dir) {
        if let Ok(bytes) = std::fs::read(&entry) {
            assert!(
                !contains(&bytes, FAKE_OPENAI.as_bytes()),
                "plaintext secret found in {}",
                entry.display()
            );
        }
    }
}

#[test]
fn run_does_not_leak_vault_password_to_child() {
    let v = TestVault::new();
    v.add_key("web", "openai", "openai", FAKE_OPENAI);

    // The child records whether it can see API Tracker's own master password
    // in its environment. It must not — env_remove strips it before spawn.
    let out_file = v._dir.path().join("child-pw.txt");
    let script = format!(
        "printf '%s' \"${{API_TRACKER_PASSWORD:-<absent>}}\" > {}",
        out_file.display()
    );
    v.cmd()
        .args([
            "run",
            "--project",
            "web",
            "--credential",
            "web/openai",
            "--env",
            "OPENAI_API_KEY",
            "--",
            "sh",
            "-c",
            &script,
        ])
        .assert()
        .success();

    let seen = std::fs::read_to_string(&out_file).unwrap();
    assert_eq!(
        seen, "<absent>",
        "child must not inherit the vault master password"
    );
}

#[test]
fn run_refuses_credential_from_another_project() {
    let v = TestVault::new();
    v.add_key("web", "openai", "openai", FAKE_OPENAI);
    v.add_key(
        "other",
        "stripe",
        "stripe",
        "sk_live_OTHER0000000000000000000000",
    );

    v.cmd()
        .args([
            "run",
            "--project",
            "web",
            "--credential",
            "other/stripe",
            "--env",
            "X",
            "--",
            "true",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in project"));
}

#[test]
fn run_propagates_child_exit_code() {
    let v = TestVault::new();
    v.add_key("web", "openai", "openai", FAKE_OPENAI);
    v.cmd()
        .args([
            "run",
            "--project",
            "web",
            "--credential",
            "web/openai",
            "--env",
            "K",
            "--",
            "sh",
            "-c",
            "exit 7",
        ])
        .assert()
        .code(7);
}

#[test]
fn mapping_config_drives_run_without_explicit_flags() {
    let v = TestVault::new();
    v.add_key("web", "openai", "openai", FAKE_OPENAI);
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
    v.cmd()
        .args(["mapping", "list", "--project", "web"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OPENAI_API_KEY"));

    let out_file = v._dir.path().join("mapped.txt");
    let script = format!("printf '%s' \"$OPENAI_API_KEY\" > {}", out_file.display());
    v.cmd()
        .args(["run", "--project", "web", "--", "sh", "-c", &script])
        .assert()
        .success();
    assert_eq!(std::fs::read_to_string(&out_file).unwrap(), FAKE_OPENAI);
}

#[test]
fn usage_record_report_and_budget_alert() {
    let v = TestVault::new();
    v.add_key("app", "key", "openai", FAKE_OPENAI);

    // Manual usage: 1M in + 1M out on gpt-4o = $12.50 estimated.
    v.cmd()
        .args([
            "usage",
            "record",
            "--credential",
            "app/key",
            "--model",
            "gpt-4o",
            "--input-tokens",
            "1000000",
            "--output-tokens",
            "1000000",
        ])
        .assert()
        .success();

    v.cmd()
        .args(["usage", "report", "--credential", "app/key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Estimated cost: $12.50"))
        .stdout(predicate::str::contains("estimated"));

    // Set a $5 budget; monitor raises an over-budget alert.
    v.cmd()
        .args([
            "budget",
            "set",
            "--credential",
            "app/key",
            "--amount",
            "5.00",
        ])
        .assert()
        .success();
    v.cmd()
        .args(["budget", "show", "--credential", "app/key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OVER BUDGET"));
    v.cmd().arg("monitor").assert().success();
    v.cmd()
        .args(["alerts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("over_budget"));
}

#[test]
fn provider_capabilities_are_honestly_labeled() {
    let v = TestVault::new();
    // Validation is now implemented; permission changes remain manual.
    v.cmd()
        .args(["provider", "capabilities", "github"])
        .assert()
        .success()
        .stdout(predicate::str::contains("validate credential"))
        .stdout(predicate::str::contains("implemented"))
        .stdout(predicate::str::contains("manual action required"));
}

#[test]
fn activity_records_injection_sessions() {
    let v = TestVault::new();
    v.add_key("web", "openai", "openai", FAKE_OPENAI);
    v.cmd()
        .args([
            "run",
            "--project",
            "web",
            "--credential",
            "web/openai",
            "--env",
            "K",
            "--",
            "true",
        ])
        .assert()
        .success();
    v.cmd()
        .args(["activity", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("injection"))
        .stdout(predicate::str::contains(FAKE_OPENAI).not());
}

fn walk(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// OpenAI administrative connection (milestone: real usage sync)
// ---------------------------------------------------------------------------

const FAKE_ADMIN: &str = "sk-admin-FAKE-TEST-NOT-A-REAL-KEY-000000000001";

#[test]
fn openai_admin_connect_status_disconnect_never_reveal_the_key() {
    let v = TestVault::new();

    // Connect non-interactively: the key arrives via the environment and is
    // stored WITHOUT a live validation request (--no-verify).
    v.cmd()
        .env("API_TRACKER_PROVIDER_ADMIN_KEY", FAKE_ADMIN)
        .args([
            "provider",
            "connect",
            "openai",
            "--no-verify",
            "--org",
            "test-org",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Connected OpenAI"))
        .stdout(predicate::str::contains(FAKE_ADMIN).not())
        .stderr(predicate::str::contains("ADMINISTRATIVE"))
        .stderr(predicate::str::contains(FAKE_ADMIN).not());

    // Status shows a masked key, the org label, and staleness info — never
    // the value, in either text or JSON output.
    v.cmd()
        .args(["provider", "connection-status", "openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("administrative"))
        .stdout(predicate::str::contains("test-org"))
        .stdout(predicate::str::contains(FAKE_ADMIN).not());
    v.cmd()
        .args(["--json", "provider", "connection-status", "openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains(FAKE_ADMIN).not());

    // The key is nowhere on disk in plaintext.
    for f in walk(&v.data_dir) {
        let bytes = std::fs::read(&f).unwrap_or_default();
        assert!(
            !contains(&bytes, FAKE_ADMIN.as_bytes()),
            "admin key stored in plaintext in {}",
            f.display()
        );
    }

    // Disconnect requires confirmation (--yes) and reauthentication (the
    // master password comes from the environment here).
    v.cmd()
        .args(["provider", "disconnect", "openai", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Disconnected OpenAI"));
    v.cmd()
        .args(["provider", "connection-status", "openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("(not connected)"));
}

#[test]
fn usage_report_filters_by_source_and_provider() {
    let v = TestVault::new();
    v.add_key("app", "key", "openai", FAKE_OPENAI);
    v.cmd()
        .args([
            "usage",
            "record",
            "--credential",
            "app/key",
            "--model",
            "gpt-4o",
            "--input-tokens",
            "1000000",
            "--output-tokens",
            "1000000",
        ])
        .assert()
        .success();

    // Manual rows appear under --source manual but not --source provider.
    v.cmd()
        .args([
            "usage",
            "report",
            "--provider",
            "openai",
            "--source",
            "manual",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Estimated cost: $12.50"))
        .stdout(predicate::str::contains("manual"));
    v.cmd()
        .args([
            "usage",
            "report",
            "--provider",
            "openai",
            "--source",
            "provider",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Snapshots:      0"));
    v.cmd()
        .args(["usage", "report", "--source", "nonsense"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown --source"));
}

#[test]
fn budget_cost_source_is_configurable() {
    let v = TestVault::new();
    v.cmd()
        .args(["budget", "source"])
        .assert()
        .success()
        .stdout(predicate::str::contains("best_available"));
    v.cmd()
        .args(["budget", "source", "provider_reported"])
        .assert()
        .success()
        .stdout(predicate::str::contains("provider_reported"));
    v.cmd()
        .args(["budget", "source", "bogus"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown cost source"));
}

#[test]
fn provider_keys_listing_guides_before_first_sync() {
    let v = TestVault::new();
    v.cmd()
        .args(["provider", "keys", "openai"])
        .assert()
        .success()
        .stdout(predicate::str::contains("provider sync openai"));
}
