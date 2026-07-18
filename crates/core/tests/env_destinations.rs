//! Integration tests for `.env` governance, credential version history,
//! destinations, and synchronization plans. All credentials are fake; all
//! network traffic goes through `MockHttpClient`; all files live in
//! isolated temporary directories.

mod common;

use api_tracker_core::destinations::{CommandRunner, DestSupport};
use api_tracker_core::envgov::{CleanupOutcome, DriftKind, EnvFileClass, GitStatus};
use api_tracker_core::http::MockHttpClient;
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use common::{add_key, add_project, master_pw, new_vault};
use std::cell::RefCell;

const FAKE_OPENAI: &str = "sk-proj-FAKE00000000000000000000000000000001";
const FAKE_STRIPE: &str = "sk_test_FAKEFAKEFAKEFAKEFAKEFAKE01";

/// A scripted runner so keychain paths are testable off-macOS.
struct NullRunner;
impl CommandRunner for NullRunner {
    fn run(
        &self,
        _program: &str,
        _args: &[&str],
        _stdin: Option<&[u8]>,
    ) -> api_tracker_core::error::Result<(i32, Vec<u8>, Vec<u8>)> {
        Ok((0, Vec::new(), Vec::new()))
    }
}

fn write_repo_env(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

// -------------------------------------------------------------------------
// .env governance
// -------------------------------------------------------------------------

#[test]
fn preview_classifies_variables_without_exposing_values() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    let file = write_repo_env(
        repo.path(),
        ".env",
        &format!("OPENAI_API_KEY={FAKE_OPENAI}\nAPP_NAME=demo\nPLACEHOLDER_KEY=changeme-please\n"),
    );
    add_project(&mut vault, "app");
    let preview = vault.env_preview("app", &file).unwrap();
    assert_eq!(preview.len(), 3);
    let openai = preview.iter().find(|v| v.key == "OPENAI_API_KEY").unwrap();
    assert!(openai.looks_secret);
    assert_eq!(openai.provider.as_deref(), Some("openai"));
    assert!(!openai.is_placeholder);
    let app = preview.iter().find(|v| v.key == "APP_NAME").unwrap();
    assert!(!app.looks_secret);
    // No preview ever contains a full value.
    let serialized = serde_json::to_string(&preview).unwrap();
    assert!(!serialized.contains(FAKE_OPENAI));
}

#[test]
fn import_is_selective_creates_mappings_and_never_duplicates() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    let file = write_repo_env(
        repo.path(),
        ".env.production",
        &format!("OPENAI_API_KEY={FAKE_OPENAI}\nSTRIPE_SECRET_KEY={FAKE_STRIPE}\nAPP_NAME=demo\n"),
    );
    add_project(&mut vault, "app");

    // Default selection imports only scanner-flagged secrets.
    let outcomes = vault.env_import("app", &file, None, None).unwrap();
    let imported: Vec<_> = outcomes.iter().filter(|o| o.action == "imported").collect();
    assert_eq!(imported.len(), 2, "{outcomes:?}");
    // Environment inferred from the file name.
    let creds = vault.list_credentials(Some("app")).unwrap();
    assert!(creds
        .iter()
        .all(|c| c.environment == Environment::Production));
    // Mappings were created for injection.
    let mappings = vault.list_env_mappings("app").unwrap();
    assert_eq!(mappings.len(), 2);

    // Re-import: the same values are recognized, not copied again.
    let again = vault.env_import("app", &file, None, None).unwrap();
    assert!(again.iter().all(|o| o.action != "imported"), "{again:?}");
    assert_eq!(vault.list_credentials(Some("app")).unwrap().len(), 2);

    // Values are recoverable through reveal (round trip).
    let revealed = vault
        .reveal_credential("app/openai-api-key", &master_pw())
        .unwrap();
    assert_eq!(revealed.expose(), FAKE_OPENAI);
}

#[test]
fn import_refuses_templates_and_skips_placeholders() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    let template = write_repo_env(repo.path(), ".env.example", "OPENAI_API_KEY=\n");
    add_project(&mut vault, "app");
    assert!(vault.env_import("app", &template, None, None).is_err());

    let file = write_repo_env(
        repo.path(),
        ".env",
        "STRIPE_SECRET_KEY=your-stripe-key-here\n",
    );
    let outcomes = vault
        .env_import("app", &file, Some(&["STRIPE_SECRET_KEY".to_string()]), None)
        .unwrap();
    assert_eq!(outcomes[0].action, "skipped");
    assert!(outcomes[0].note.contains("placeholder"));
}

#[test]
fn discovery_reports_class_environment_and_git_status() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    write_repo_env(repo.path(), ".env", "A=1\n");
    write_repo_env(repo.path(), ".env.example", "A=\n");
    write_repo_env(repo.path(), ".env.test", "B=2\n");
    let project = add_project(&mut vault, "app");
    vault
        .update_project(
            &project.id,
            api_tracker_core::vault::UpdateProject {
                add_repo_paths: vec![repo.path().to_string_lossy().into_owned()],
                ..Default::default()
            },
        )
        .unwrap();
    let found = vault.env_discover(Some("app"), None).unwrap();
    assert_eq!(found.len(), 3);
    let by_name = |n: &str| found.iter().find(|f| f.rel_path == n).unwrap();
    assert_eq!(by_name(".env").class, EnvFileClass::Values);
    assert_eq!(by_name(".env.example").class, EnvFileClass::Template);
    assert_eq!(by_name(".env.test").environment, Some(Environment::Test));
    assert_eq!(by_name(".env").git_status, GitStatus::NotInRepo);
}

#[test]
fn drift_detects_diverged_unmapped_production_and_copied_values() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    let project = add_project(&mut vault, "app");
    vault
        .update_project(
            &project.id,
            api_tracker_core::vault::UpdateProject {
                add_repo_paths: vec![repo.path().to_string_lossy().into_owned()],
                ..Default::default()
            },
        )
        .unwrap();

    // A mapped credential whose file copy diverged.
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "openai-main",
        FAKE_OPENAI,
        Environment::Development,
    );
    vault
        .set_env_mapping("app", &cred.id, "OPENAI_API_KEY")
        .unwrap();
    // A production credential whose value is pasted into dev + test files.
    add_key(
        &mut vault,
        "app",
        "stripe-live",
        FAKE_STRIPE,
        Environment::Production,
    );
    write_repo_env(
        repo.path(),
        ".env.development",
        &format!("OPENAI_API_KEY=sk-proj-FAKE-DIVERGED-000000000000000000\nSTRIPE_SECRET_KEY={FAKE_STRIPE}\nROGUE_TOKEN=ghp_FAKE0000000000000000000000000000000000\n"),
    );
    write_repo_env(
        repo.path(),
        ".env.test",
        &format!("STRIPE_SECRET_KEY={FAKE_STRIPE}\n"),
    );

    let findings = vault.env_drift("app").unwrap();
    let kinds: Vec<DriftKind> = findings.iter().map(|f| f.kind).collect();
    assert!(
        kinds.contains(&DriftKind::ValueDiffersFromVault),
        "{findings:?}"
    );
    assert!(kinds.contains(&DriftKind::UnmappedSecret), "{findings:?}");
    assert!(
        kinds.contains(&DriftKind::ProductionValueInDevFile),
        "{findings:?}"
    );
    assert!(
        kinds.contains(&DriftKind::SameValueInMultipleFiles),
        "{findings:?}"
    );
    // Findings never leak the values themselves.
    let serialized = serde_json::to_string(&findings).unwrap();
    assert!(!serialized.contains(FAKE_STRIPE));
    assert!(!serialized.contains("FAKE-DIVERGED"));
}

#[test]
fn example_generation_and_diff_stay_secret_free() {
    let values = api_tracker_core::envfile::EnvDocument::parse(&format!(
        "# main config\nOPENAI_API_KEY={FAKE_OPENAI}\nAPP_NAME=demo\n"
    ));
    let generated = api_tracker_core::envgov::generate_example(&values, None);
    assert!(!generated.contains(FAKE_OPENAI));
    assert!(generated.contains("OPENAI_API_KEY="));
    assert!(generated.contains("APP_NAME="));
    let diff = api_tracker_core::envgov::render_diff(".env.example", "", &generated);
    assert!(!diff.contains(FAKE_OPENAI));
}

#[test]
fn export_requires_reauth_writes_atomically_and_cleans_up() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "openai-main",
        FAKE_OPENAI,
        Environment::Development,
    );
    vault
        .set_env_mapping("app", &cred.id, "OPENAI_API_KEY")
        .unwrap();
    let target = repo.path().join(".env");

    // Wrong password is refused.
    let wrong = SecretString::from("not-the-master-password");
    assert!(vault
        .env_export("app", &target, None, &wrong, false, None)
        .is_err());
    assert!(!target.exists());

    // Correct password exports with 0600 and records the export.
    let report = vault
        .env_export("app", &target, None, &master_pw(), false, Some(60))
        .unwrap();
    assert_eq!(report.var_names, vec!["OPENAI_API_KEY".to_string()]);
    assert!(report.expires_at.is_some());
    let content = std::fs::read_to_string(&target).unwrap();
    assert!(content.contains(&format!("OPENAI_API_KEY={FAKE_OPENAI}")));
    assert!(content.contains("PLAINTEXT"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // A second export refuses to overwrite without the explicit flag.
    assert!(vault
        .env_export("app", &target, None, &master_pw(), false, None)
        .is_err());
    assert!(vault
        .env_export("app", &target, None, &master_pw(), true, Some(60))
        .is_ok());

    // Cleanup with `all` removes the file and marks the record.
    let results = vault.env_cleanup(true, false).unwrap();
    assert!(results
        .iter()
        .any(|r| r.outcome == CleanupOutcome::Removed || r.outcome == CleanupOutcome::AlreadyGone));
    assert!(!target.exists());
    assert!(vault.env_exports(false).unwrap().is_empty());
}

#[test]
fn cleanup_refuses_modified_files_without_force() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "openai-main",
        FAKE_OPENAI,
        Environment::Development,
    );
    vault
        .set_env_mapping("app", &cred.id, "OPENAI_API_KEY")
        .unwrap();
    let target = repo.path().join(".env");
    vault
        .env_export("app", &target, None, &master_pw(), false, Some(0))
        .unwrap();
    // The user edited the exported file after export.
    std::fs::write(&target, "OPENAI_API_KEY=changed-by-user\nEXTRA=1\n").unwrap();
    let results = vault.env_cleanup(true, false).unwrap();
    assert_eq!(results[0].outcome, CleanupOutcome::ModifiedSinceExport);
    assert!(target.exists(), "modified file must survive without force");
    let results = vault.env_cleanup(true, true).unwrap();
    assert_eq!(results[0].outcome, CleanupOutcome::Removed);
    assert!(!target.exists());
}

#[test]
fn export_refuses_git_tracked_targets() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        assert!(std::process::Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(args)
            .output()
            .unwrap()
            .status
            .success());
    };
    run(&["init", "-q"]);
    run(&["config", "user.email", "t@example.invalid"]);
    run(&["config", "user.name", "t"]);
    std::fs::write(repo.path().join(".env"), "OLD=1\n").unwrap();
    run(&["add", "-f", ".env"]);
    run(&["commit", "-q", "-m", "tracked env"]);

    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "openai-main",
        FAKE_OPENAI,
        Environment::Development,
    );
    vault
        .set_env_mapping("app", &cred.id, "OPENAI_API_KEY")
        .unwrap();
    let err = vault
        .env_export(
            "app",
            &repo.path().join(".env"),
            None,
            &master_pw(),
            true,
            None,
        )
        .unwrap_err();
    assert!(err.to_string().contains("tracked"));
}

// -------------------------------------------------------------------------
// Credential version history
// -------------------------------------------------------------------------

#[test]
fn replacing_a_value_retains_versions_and_history_is_reauth_gated() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "openai-main",
        FAKE_OPENAI,
        Environment::Development,
    );
    let v2 = "sk-proj-FAKE00000000000000000000000000000002";
    vault
        .replace_credential_value(&cred.id, &master_pw(), SecretString::from(v2))
        .unwrap();
    let wrong = SecretString::from("not-the-master-password");
    assert!(vault.credential_version_history(&cred.id, &wrong).is_err());
    let history = vault
        .credential_version_history(&cred.id, &master_pw())
        .unwrap();
    assert_eq!(history.len(), 2);
    assert!(history[0].current && history[0].version == 2);
    assert!(!history[1].current && history[1].version == 1);
    // Masked values only — never the plaintext.
    let serialized = serde_json::to_string(&history).unwrap();
    assert!(!serialized.contains(FAKE_OPENAI));
    assert!(!serialized.contains(v2));
}

#[test]
fn deleting_a_credential_purges_its_version_history() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "openai-main",
        FAKE_OPENAI,
        Environment::Development,
    );
    vault
        .replace_credential_value(
            &cred.id,
            &master_pw(),
            SecretString::from("sk-proj-FAKE00000000000000000000000000000002"),
        )
        .unwrap();
    vault.delete_credential(&cred.id).unwrap();
    let count: i64 = vault
        .connection()
        .query_row(
            "SELECT count(*) FROM credential_versions WHERE credential_id = ?1",
            [&cred.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

// -------------------------------------------------------------------------
// Destinations
// -------------------------------------------------------------------------

#[test]
fn destination_add_encrypts_auth_and_removal_requires_reauth() {
    let (_dir, paths, vault) = new_vault();
    let token = "vercel-FAKE-token-0000000000";
    let dest = vault
        .destination_add(
            "vercel",
            "my-site",
            serde_json::json!({"project_id": "prj_1"}),
            Some(&SecretString::from(token)),
        )
        .unwrap();
    assert_eq!(dest.kind, "vercel");
    assert!(dest.auth_masked.is_some());
    // The token exists nowhere in plaintext inside the database file.
    drop(vault);
    let raw = std::fs::read(paths.db_path()).unwrap();
    let needle = token.as_bytes();
    assert!(
        !raw.windows(needle.len()).any(|w| w == needle),
        "destination token must be encrypted at rest"
    );
    let vault = api_tracker_core::vault::unlock_vault(&paths, &master_pw()).unwrap();
    let wrong = SecretString::from("not-the-master-password");
    assert!(vault.destination_remove("my-site", &wrong).is_err());
    assert!(vault.destination_remove("my-site", &master_pw()).is_ok());
    assert!(vault.destination_list().unwrap().is_empty());
}

#[test]
fn destination_catalog_is_honest_and_local_kinds_are_not_addable() {
    let (_dir, _paths, vault) = new_vault();
    assert!(vault
        .destination_add("vault", "x", serde_json::json!({}), None)
        .is_err());
    assert!(vault
        .destination_add("nonsense", "x", serde_json::json!({}), None)
        .is_err());
    let gh = api_tracker_core::destinations::kind_info("github_actions").unwrap();
    assert_eq!(gh.capabilities.read, DestSupport::Unsupported);
}

#[test]
fn sync_plan_writes_verifies_and_handles_partial_failure_with_retry() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "stripe-live",
        FAKE_STRIPE,
        Environment::Production,
    );
    // Two destinations: Vercel (will fail first) and GitHub (succeeds).
    vault
        .destination_add(
            "vercel",
            "site",
            serde_json::json!({"project_id": "prj_1"}),
            Some(&SecretString::from("vercel-FAKE-token")),
        )
        .unwrap();
    vault
        .destination_add(
            "github_actions",
            "ci",
            serde_json::json!({"owner": "octo", "repo": "app"}),
            Some(&SecretString::from(
                "ghp_FAKE0000000000000000000000000000000000",
            )),
        )
        .unwrap();
    vault
        .destination_attach(&cred.id, "site", "STRIPE_SECRET_KEY", "production")
        .unwrap();
    vault
        .destination_attach(&cred.id, "ci", "STRIPE_SECRET_KEY", "production")
        .unwrap();

    // Rotate the value so the plan has a from-version for rollback.
    let new_value = "sk_test_FAKEFAKEFAKEFAKEFAKEFAKE02";
    vault
        .replace_credential_value(&cred.id, &master_pw(), SecretString::from(new_value))
        .unwrap();

    let plan = vault
        .sync_plan_create(&cred.id, "rotate stripe key")
        .unwrap();
    assert_eq!(plan.status, "planned");
    assert_eq!(plan.to_version, 2);
    assert_eq!(plan.from_version, Some(1));
    let write_steps: Vec<_> = plan.steps.iter().filter(|s| s.action == "write").collect();
    assert_eq!(write_steps.len(), 2);
    assert!(write_steps.iter().all(|s| s.rollback_available));

    // Dry run changed nothing: no HTTP client was ever invoked so far.
    // Execute: GitHub succeeds (public key + 201), Vercel fails with 403.
    use base64::Engine;
    let pk = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let http = MockHttpClient::new(vec![
        // ci (github): public key, then PUT created
        MockHttpClient::json_response(&format!(r#"{{"key_id":"k1","key":"{pk}"}}"#)),
        api_tracker_core::http::HttpResponse {
            status: 204,
            headers: vec![],
            body: Vec::new(),
        },
        // ci verification: existence check
        MockHttpClient::json_response(r#"{"name":"STRIPE_SECRET_KEY"}"#),
        // site (vercel): 403
        api_tracker_core::http::HttpResponse {
            status: 403,
            headers: vec![],
            body: br#"{"error":{"code":"forbidden"}}"#.to_vec(),
        },
    ]);
    let wrong = SecretString::from("not-the-master-password");
    assert!(vault
        .sync_plan_execute(&plan.id, None, &wrong, &http, &NullRunner)
        .is_err());
    let executed = vault
        .sync_plan_execute(&plan.id, None, &master_pw(), &http, &NullRunner)
        .unwrap();
    assert_eq!(executed.status, "partially_failed");
    let gh_step = executed
        .steps
        .iter()
        .find(|s| s.destination_name == "ci")
        .unwrap();
    assert_eq!(gh_step.status, "executed");
    let vercel_step = executed
        .steps
        .iter()
        .find(|s| s.destination_name == "site")
        .unwrap();
    assert_eq!(vercel_step.status, "failed");
    // Failure details never contain the secret.
    assert!(!vercel_step.detail.contains(new_value));

    // Retry just the failed destination — now it succeeds.
    let http = MockHttpClient::new(vec![
        MockHttpClient::json_response(r#"{"created":{}}"#),
        MockHttpClient::json_response(r#"{"envs":[{"id":"e1","key":"STRIPE_SECRET_KEY"}]}"#),
    ]);
    let retried = vault
        .sync_plan_execute(&plan.id, Some("site"), &master_pw(), &http, &NullRunner)
        .unwrap();
    assert_eq!(retried.status, "executed");

    // Attachments now record the synced version.
    let attachments = vault.destination_attachments(Some(&cred.id)).unwrap();
    assert!(attachments.iter().all(|a| a.last_synced_version == Some(2)));
}

#[test]
fn stale_plans_are_refused_and_rollback_restores_the_old_version() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "stripe-live",
        FAKE_STRIPE,
        Environment::Production,
    );
    vault
        .destination_add(
            "github_actions",
            "ci",
            serde_json::json!({"owner": "octo", "repo": "app"}),
            Some(&SecretString::from(
                "ghp_FAKE0000000000000000000000000000000000",
            )),
        )
        .unwrap();
    vault
        .destination_attach(&cred.id, "ci", "STRIPE_KEY", "production")
        .unwrap();
    let v2 = "sk_test_FAKEFAKEFAKEFAKEFAKEFAKE02";
    vault
        .replace_credential_value(&cred.id, &master_pw(), SecretString::from(v2))
        .unwrap();
    let plan = vault.sync_plan_create(&cred.id, "").unwrap();

    // The credential changes again -> the plan is stale and refuses to run.
    vault
        .replace_credential_value(
            &cred.id,
            &master_pw(),
            SecretString::from("sk_test_FAKEFAKEFAKEFAKEFAKEFAKE03"),
        )
        .unwrap();
    let http = MockHttpClient::new(vec![]);
    let err = vault
        .sync_plan_execute(&plan.id, None, &master_pw(), &http, &NullRunner)
        .unwrap_err();
    assert!(err.to_string().contains("changed since"));
    assert_eq!(vault.sync_plan_get(&plan.id).unwrap().status, "stale");

    // A fresh plan executes, then rolls back to the previous version.
    use base64::Engine;
    let pk = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let plan = vault.sync_plan_create(&cred.id, "").unwrap();
    assert_eq!(plan.from_version, Some(2));
    let http = MockHttpClient::new(vec![
        MockHttpClient::json_response(&format!(r#"{{"key_id":"k1","key":"{pk}"}}"#)),
        api_tracker_core::http::HttpResponse {
            status: 204,
            headers: vec![],
            body: Vec::new(),
        },
        MockHttpClient::json_response(r#"{"name":"STRIPE_KEY"}"#),
    ]);
    vault
        .sync_plan_execute(&plan.id, None, &master_pw(), &http, &NullRunner)
        .unwrap();

    let http = MockHttpClient::new(vec![
        MockHttpClient::json_response(&format!(r#"{{"key_id":"k1","key":"{pk}"}}"#)),
        api_tracker_core::http::HttpResponse {
            status: 204,
            headers: vec![],
            body: Vec::new(),
        },
    ]);
    let rolled = vault
        .sync_plan_rollback(&plan.id, None, &master_pw(), &http, &NullRunner)
        .unwrap();
    assert_eq!(rolled.status, "rolled_back");
    let step = &rolled.steps[0];
    assert_eq!(step.status, "rolled_back");
    assert!(step.detail.contains("rolled back to v2"));
    let attachments = vault.destination_attachments(Some(&cred.id)).unwrap();
    assert_eq!(attachments[0].last_synced_version, Some(2));
    assert_eq!(attachments[0].drift, "rolled_back");
}

#[test]
fn sync_plan_includes_reexport_steps_and_rewrites_export_files() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "openai-main",
        FAKE_OPENAI,
        Environment::Development,
    );
    vault
        .set_env_mapping("app", &cred.id, "OPENAI_API_KEY")
        .unwrap();
    let target = repo.path().join(".env");
    vault
        .env_export("app", &target, None, &master_pw(), false, None)
        .unwrap();

    let v2 = "sk-proj-FAKE00000000000000000000000000000002";
    vault
        .replace_credential_value(&cred.id, &master_pw(), SecretString::from(v2))
        .unwrap();
    let plan = vault.sync_plan_create(&cred.id, "").unwrap();
    let reexport = plan
        .steps
        .iter()
        .find(|s| s.action == "reexport")
        .expect("a live export must appear in the plan");
    assert!(reexport.destination_name.ends_with(".env"));
    // Mappings appear as an informational no-op step.
    assert!(plan.steps.iter().any(|s| s.action == "none"));

    let http = MockHttpClient::new(vec![]);
    let executed = vault
        .sync_plan_execute(&plan.id, None, &master_pw(), &http, &NullRunner)
        .unwrap();
    assert_eq!(executed.status, "executed");
    let content = std::fs::read_to_string(&target).unwrap();
    assert!(content.contains(v2), "export must carry the new value");
    assert!(!content.contains(FAKE_OPENAI));
}

#[test]
fn keychain_destination_round_trips_through_a_scripted_runner() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "openai-main",
        FAKE_OPENAI,
        Environment::Development,
    );
    // The keychain kind can only be *configured* on macOS; the adapter logic
    // itself is platform-independent and scripted here.
    if !cfg!(target_os = "macos") {
        return;
    }
    struct RecordingRunner {
        stored: RefCell<Option<String>>,
    }
    impl CommandRunner for RecordingRunner {
        fn run(
            &self,
            _program: &str,
            args: &[&str],
            stdin: Option<&[u8]>,
        ) -> api_tracker_core::error::Result<(i32, Vec<u8>, Vec<u8>)> {
            if args == ["-i"] {
                let cmd = String::from_utf8_lossy(stdin.unwrap()).into_owned();
                let value = cmd.split(" -w ").nth(1).unwrap().trim();
                *self.stored.borrow_mut() = Some(value.trim_matches('"').replace("\\\"", "\""));
                Ok((0, Vec::new(), Vec::new()))
            } else if args.first() == Some(&"find-generic-password") && args.contains(&"-w") {
                let value = self.stored.borrow().clone().unwrap_or_default();
                Ok((0, format!("{value}\n").into_bytes(), Vec::new()))
            } else {
                Ok((0, Vec::new(), Vec::new()))
            }
        }
    }
    vault
        .destination_add("macos_keychain", "kc", serde_json::json!({}), None)
        .unwrap();
    vault
        .destination_attach(&cred.id, "kc", "OPENAI_API_KEY", "development")
        .unwrap();
    let plan = vault.sync_plan_create(&cred.id, "").unwrap();
    let runner = RecordingRunner {
        stored: RefCell::new(None),
    };
    let http = MockHttpClient::new(vec![]);
    let executed = vault
        .sync_plan_execute(&plan.id, None, &master_pw(), &http, &runner)
        .unwrap();
    assert_eq!(executed.status, "executed");
    // Read-back verification matched the vault fingerprint.
    let attachments = vault.destination_attachments(Some(&cred.id)).unwrap();
    assert_eq!(attachments[0].drift, "in_sync");
}
