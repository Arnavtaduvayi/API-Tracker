//! End-to-end CLI tests. Each test gets an isolated vault directory; the
//! weakened test KDF profile (debug builds only) keeps Argon2id fast. All
//! credential values are obvious fakes.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const MASTER_PW: &str = "test-master-password";
const PROJECT_PW: &str = "test-project-password";
const BACKUP_PW: &str = "test-backup-password";
const FAKE_KEY_1: &str = "FAKE-TEST-NOT-A-REAL-KEY-000001";
const FAKE_KEY_2: &str = "FAKE-TEST-NOT-A-REAL-KEY-000002";

struct TestVault {
    _dir: TempDir,
    data_dir: std::path::PathBuf,
}

impl TestVault {
    /// Fresh directory, no vault yet.
    fn empty() -> Self {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        Self {
            _dir: dir,
            data_dir,
        }
    }

    /// Fresh directory with an initialized vault.
    fn new() -> Self {
        let vault = Self::empty();
        vault.cmd().arg("init").assert().success();
        vault
    }

    /// A command with a clean environment: master password provided via env
    /// (the CLI's documented non-interactive mode).
    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("api-tracker").unwrap();
        cmd.env_clear()
            .env("API_TRACKER_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1")
            .env("API_TRACKER_PASSWORD", MASTER_PW);
        cmd
    }

    /// A command with no password in the environment.
    fn cmd_no_password(&self) -> Command {
        let mut cmd = Command::cargo_bin("api-tracker").unwrap();
        cmd.env_clear()
            .env("API_TRACKER_DIR", &self.data_dir)
            .env("API_TRACKER_INSECURE_FAST_KDF", "1");
        cmd
    }

    fn add_project(&self, name: &str) {
        self.cmd()
            .args(["project", "create", name])
            .assert()
            .success();
    }

    fn add_key(&self, project: &str, name: &str, value: &str, environment: &str) {
        self.cmd()
            .args([
                "key",
                "add",
                "--project",
                project,
                "--name",
                name,
                "--environment",
                environment,
                "--value-stdin",
            ])
            .write_stdin(value)
            .assert()
            .success();
    }
}

#[test]
fn init_creates_vault_and_refuses_second_init() {
    let vault = TestVault::empty();
    vault
        .cmd()
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault created"))
        .stdout(predicate::str::contains("unrecoverable"));
    assert!(vault.data_dir.join("vault.db").exists());
    vault
        .cmd()
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn doctor_reports_vault_health() {
    let vault = TestVault::new();
    vault
        .cmd()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault exists:    yes"))
        .stdout(predicate::str::contains("DB integrity:    ok"));
}

#[test]
fn locked_vault_requires_unlock_or_password() {
    let vault = TestVault::new();
    vault
        .cmd_no_password()
        .args(["project", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("locked"));
}

#[test]
fn wrong_master_password_is_rejected() {
    let vault = TestVault::new();
    vault
        .cmd()
        .env("API_TRACKER_PASSWORD", "wrong-password-123")
        .args(["project", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("incorrect password"));
}

#[test]
fn project_and_credential_workflow_with_redaction() {
    let vault = TestVault::new();
    vault
        .cmd()
        .args([
            "project",
            "create",
            "backend",
            "--description",
            "the API",
            "--env",
            "production",
            "--env",
            "development",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created project 'backend'"));

    vault
        .cmd()
        .args(["project", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("backend"))
        .stdout(predicate::str::contains("production"));

    vault
        .cmd()
        .args([
            "key",
            "add",
            "--project",
            "backend",
            "--name",
            "openai-main",
            "--provider",
            "openai",
            "--environment",
            "production",
            "--expires",
            "2031-01-01",
            "--value-stdin",
        ])
        .write_stdin(FAKE_KEY_1)
        .assert()
        .success()
        .stdout(predicate::str::contains("Added credential"))
        .stdout(predicate::str::contains(FAKE_KEY_1).not());

    // Listings and detail views never contain the secret.
    for args in [
        vec!["key", "list"],
        vec!["key", "list", "--project", "backend"],
        vec!["key", "show", "backend/openai-main"],
        vec!["key", "status", "backend/openai-main"],
        vec!["key", "list", "--json"],
        vec!["key", "show", "backend/openai-main", "--json"],
    ] {
        let assert = vault.cmd().args(&args).assert().success();
        let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
        assert!(!out.contains(FAKE_KEY_1), "secret leaked via {args:?}");
        assert!(!out.contains(FAKE_KEY_2), "secret leaked via {args:?}");
    }

    vault
        .cmd()
        .args(["key", "show", "backend/openai-main"])
        .assert()
        .success()
        .stdout(predicate::str::contains("FAKE…01 (masked)"));

    // Status is explainable.
    vault
        .cmd()
        .args(["key", "status", "backend/openai-main"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Primary status: unknown"))
        .stdout(predicate::str::contains("Reason:"))
        .stdout(predicate::str::contains("Source:"));

    // Reveal prints exactly the value (with reauthentication via env).
    vault
        .cmd()
        .args(["key", "reveal", "backend/openai-main"])
        .assert()
        .success()
        .stdout(predicate::str::diff(format!("{FAKE_KEY_1}\n")))
        .stderr(predicate::str::contains("Reauthentication"));

    // Manual marks flow into status.
    vault
        .cmd()
        .args([
            "key",
            "update",
            "backend/openai-main",
            "--mark-valid",
            "--mark-used-now",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("status: active"));

    // Metadata edits.
    vault
        .cmd()
        .args([
            "key",
            "update",
            "backend/openai-main",
            "--expires",
            "2020-01-01",
        ])
        .assert()
        .success();
    vault
        .cmd()
        .args(["key", "status", "backend/openai-main"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Primary status: expired"));

    // Removal requires confirmation; --yes bypasses.
    vault
        .cmd()
        .args(["key", "remove", "backend/openai-main"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--yes"));
    vault
        .cmd()
        .args(["key", "remove", "backend/openai-main", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Deleted"));
}

#[test]
fn duplicate_detection_warns_and_supports_references() {
    let vault = TestVault::new();
    vault.add_project("web-prod");
    vault.add_project("experiments");
    vault.add_key("web-prod", "stripe", FAKE_KEY_1, "production");

    // Non-interactive duplicate add aborts with guidance.
    vault
        .cmd()
        .args([
            "key",
            "add",
            "--project",
            "experiments",
            "--name",
            "stripe-copy",
            "--environment",
            "development",
            "--value-stdin",
        ])
        .write_stdin(FAKE_KEY_1)
        .assert()
        .failure()
        .stderr(predicate::str::contains("reuse detected"))
        .stderr(predicate::str::contains(
            "production credential shared with development",
        ))
        .stderr(predicate::str::contains("web-prod/stripe"))
        .stderr(predicate::str::contains("--link-to"));

    // Explicit duplicate storage still warns.
    vault
        .cmd()
        .args([
            "key",
            "add",
            "--project",
            "experiments",
            "--name",
            "stripe-copy",
            "--environment",
            "development",
            "--value-stdin",
            "--allow-duplicate",
        ])
        .write_stdin(FAKE_KEY_1)
        .assert()
        .success()
        .stderr(predicate::str::contains("reuse detected"));

    // Both credentials now show the shared status.
    vault
        .cmd()
        .args(["key", "status", "web-prod/stripe"])
        .assert()
        .success()
        .stdout(predicate::str::contains("shared across projects"))
        .stdout(predicate::str::contains("experiments"));

    // An intentional reference stores no second copy and lists as a link.
    vault
        .cmd()
        .args([
            "key",
            "add",
            "--project",
            "experiments",
            "--name",
            "stripe-ref",
            "--link-to",
            "web-prod/stripe",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("reference"))
        .stdout(predicate::str::contains("no secret value was duplicated"));
    vault
        .cmd()
        .args(["key", "list", "--project", "experiments"])
        .assert()
        .success()
        .stdout(predicate::str::contains("→ web-prod/stripe"));

    // Revealing the reference yields the source value.
    vault
        .cmd()
        .args(["key", "reveal", "experiments/stripe-ref"])
        .assert()
        .success()
        .stdout(predicate::str::diff(format!("{FAKE_KEY_1}\n")));

    // The source cannot be deleted while referenced.
    vault
        .cmd()
        .args(["key", "remove", "web-prod/stripe", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("referenced"));
}

#[test]
fn session_unlock_use_lock_cycle() {
    let vault = TestVault::new();
    vault.add_project("alpha");

    // Unlock produces an exportable session token.
    let assert = vault
        .cmd()
        .args(["unlock", "--print-export"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let token = out
        .trim()
        .strip_prefix("export API_TRACKER_SESSION=\"")
        .and_then(|s| s.strip_suffix('"'))
        .expect("export line")
        .to_owned();
    assert!(!token.is_empty());

    // The session works without any password in the environment.
    vault
        .cmd_no_password()
        .env("API_TRACKER_SESSION", &token)
        .args(["project", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alpha"));

    // A wrong token does not.
    vault
        .cmd_no_password()
        .env(
            "API_TRACKER_SESSION",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .args(["project", "list"])
        .assert()
        .failure();

    // Lock destroys the session.
    vault.cmd_no_password().arg("lock").assert().success();
    vault
        .cmd_no_password()
        .env("API_TRACKER_SESSION", &token)
        .args(["project", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unlock"));
}

#[test]
fn project_unlock_without_a_session_is_rejected_not_silently_dropped() {
    // In env-password mode there is no session to persist the unlocked key
    // into, so `project unlock` must error instead of claiming success and
    // then leaving the credential unreachable.
    let vault = TestVault::new();
    vault.add_project("secure");
    vault.add_key("secure", "api", FAKE_KEY_1, "production");
    vault
        .cmd()
        .env("API_TRACKER_PROJECT_PASSWORD", PROJECT_PW)
        .args(["project", "lock", "secure"])
        .assert()
        .success();
    vault
        .cmd()
        .env("API_TRACKER_PROJECT_PASSWORD", PROJECT_PW)
        .args(["project", "unlock", "secure"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("session"));
}

#[test]
fn link_to_rejects_flags_that_would_be_ignored() {
    let vault = TestVault::new();
    vault.add_project("main");
    vault.add_project("spinoff");
    vault.add_key("main", "src", FAKE_KEY_1, "production");
    vault
        .cmd()
        .args([
            "key",
            "add",
            "--project",
            "spinoff",
            "--name",
            "ref",
            "--link-to",
            "main/src",
            "--expires",
            "2030-01-01",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("do not apply to a reference"))
        .stderr(predicate::str::contains("--expires"));
}

#[test]
fn project_password_lock_via_session() {
    let vault = TestVault::new();
    vault.add_project("secure");
    vault.add_key("secure", "api", FAKE_KEY_1, "production");

    // Set the project password (also locks it immediately).
    vault
        .cmd()
        .env("API_TRACKER_PROJECT_PASSWORD", PROJECT_PW)
        .args(["project", "lock", "secure"])
        .assert()
        .success()
        .stdout(predicate::str::contains("password-locked"));

    // Reveal now fails: the project key is locked behind the project password.
    vault
        .cmd()
        .args(["key", "reveal", "secure/api"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("password-locked"));

    // Unlock the project inside a session so the state persists across
    // commands.
    let assert = vault
        .cmd()
        .args(["unlock", "--print-export"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let token = out
        .trim()
        .strip_prefix("export API_TRACKER_SESSION=\"")
        .and_then(|s| s.strip_suffix('"'))
        .unwrap()
        .to_owned();

    vault
        .cmd()
        .env("API_TRACKER_SESSION", &token)
        .env("API_TRACKER_PROJECT_PASSWORD", "wrong-project-password")
        .args(["project", "unlock", "secure"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("incorrect password"));

    vault
        .cmd()
        .env("API_TRACKER_SESSION", &token)
        .env("API_TRACKER_PROJECT_PASSWORD", PROJECT_PW)
        .args(["project", "unlock", "secure"])
        .assert()
        .success();

    // The unlock persisted into the session: reveal now works.
    vault
        .cmd()
        .env("API_TRACKER_SESSION", &token)
        .args(["key", "reveal", "secure/api"])
        .assert()
        .success()
        .stdout(predicate::str::diff(format!("{FAKE_KEY_1}\n")));

    // Locking the project again removes access.
    vault
        .cmd()
        .env("API_TRACKER_SESSION", &token)
        .args(["project", "lock", "secure"])
        .assert()
        .success();
    vault
        .cmd()
        .env("API_TRACKER_SESSION", &token)
        .args(["key", "reveal", "secure/api"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("password-locked"));
}

#[test]
fn archive_hides_project_from_default_listing() {
    let vault = TestVault::new();
    vault.add_project("old-thing");
    vault
        .cmd()
        .args(["project", "archive", "old-thing"])
        .assert()
        .success();
    vault
        .cmd()
        .args(["project", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("old-thing").not());
    vault
        .cmd()
        .args(["project", "list", "--archived"])
        .assert()
        .success()
        .stdout(predicate::str::contains("old-thing"));
    vault
        .cmd()
        .args(["project", "restore", "old-thing"])
        .assert()
        .success();
    vault
        .cmd()
        .args(["project", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("old-thing"));
}

#[test]
fn backup_create_verify_restore() {
    let vault = TestVault::new();
    vault.add_project("alpha");
    vault.add_key("alpha", "api", FAKE_KEY_1, "development");

    let backup_path = vault._dir.path().join("backup.json");
    vault
        .cmd()
        .env("API_TRACKER_BACKUP_PASSWORD", BACKUP_PW)
        .args(["backup", "create"])
        .arg(&backup_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Backup written"));

    // The backup file never contains the plaintext secret.
    let raw = std::fs::read_to_string(&backup_path).unwrap();
    assert!(!raw.contains(FAKE_KEY_1));

    vault
        .cmd_no_password()
        .env("API_TRACKER_BACKUP_PASSWORD", BACKUP_PW)
        .args(["backup", "verify"])
        .arg(&backup_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Backup is valid"));

    // Wrong backup password fails verification.
    vault
        .cmd_no_password()
        .env("API_TRACKER_BACKUP_PASSWORD", "wrong-password-123")
        .args(["backup", "verify"])
        .arg(&backup_path)
        .assert()
        .failure();

    // Restore into a brand-new data directory.
    let restored = TestVault::empty();
    restored
        .cmd_no_password()
        .env("API_TRACKER_BACKUP_PASSWORD", BACKUP_PW)
        .args(["backup", "restore"])
        .arg(&backup_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Restored 1 project(s)"));

    // The restored vault opens with the original master password.
    restored
        .cmd()
        .args(["key", "reveal", "alpha/api"])
        .assert()
        .success()
        .stdout(predicate::str::diff(format!("{FAKE_KEY_1}\n")));

    // Restoring over an existing vault requires --force.
    restored
        .cmd_no_password()
        .env("API_TRACKER_BACKUP_PASSWORD", BACKUP_PW)
        .args(["backup", "restore"])
        .arg(&backup_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));
    restored
        .cmd_no_password()
        .env("API_TRACKER_BACKUP_PASSWORD", BACKUP_PW)
        .args(["backup", "restore", "--force", "--yes"])
        .arg(&backup_path)
        .assert()
        .success();
}

#[test]
fn settings_show_and_set() {
    let vault = TestVault::new();
    vault
        .cmd()
        .args(["settings", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("auto_lock_minutes = 15"));
    vault
        .cmd()
        .args(["settings", "set", "auto_lock_minutes", "5"])
        .assert()
        .success();
    vault
        .cmd()
        .args(["settings", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("auto_lock_minutes = 5"));
    vault
        .cmd()
        .args(["settings", "set", "nonsense", "5"])
        .assert()
        .failure();
}

#[test]
fn provider_catalog_is_honest_about_capabilities() {
    let vault = TestVault::empty();
    vault
        .cmd_no_password()
        .args(["provider", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("openai"))
        .stdout(predicate::str::contains("anthropic"))
        .stdout(predicate::str::contains("not implemented yet"));
}

#[test]
fn cli_reads_a_vault_created_through_the_core_library() {
    // The desktop app uses the core library directly; this proves both
    // frontends share one vault format.
    use api_tracker_core::model::Environment;
    use api_tracker_core::secret::SecretString;
    use api_tracker_core::vault::{AddCredential, NewProject, VaultPaths};

    std::env::set_var("API_TRACKER_INSECURE_FAST_KDF", "1");
    let vault = TestVault::empty();
    let paths = VaultPaths::new(vault.data_dir.clone());
    let mut core_vault =
        api_tracker_core::vault::create_vault(&paths, &SecretString::from(MASTER_PW)).unwrap();
    core_vault
        .create_project(NewProject {
            name: "from-desktop".into(),
            ..Default::default()
        })
        .unwrap();
    core_vault
        .add_credential(AddCredential {
            project: "from-desktop".into(),
            provider: "github".into(),
            name: "token".into(),
            environment: Environment::Development,
            value: SecretString::from(FAKE_KEY_2),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    drop(core_vault);

    vault
        .cmd()
        .args(["key", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("from-desktop/token"));
    vault
        .cmd()
        .args(["key", "reveal", "from-desktop/token"])
        .assert()
        .success()
        .stdout(predicate::str::diff(format!("{FAKE_KEY_2}\n")));
}
