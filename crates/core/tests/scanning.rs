//! Integration tests for milestone 2: repository scanning + vault matching,
//! monitoring/alerts, and documentation watching.

mod common;

use api_tracker_core::alerts;
use api_tracker_core::docwatch::{CheckResult, FetchOutcome, MockFetcher};
use api_tracker_core::model::Environment;
use api_tracker_core::providers::Confidence;
use api_tracker_core::secret::SecretString;
use api_tracker_core::status::Status;
use api_tracker_core::vault::AddCredential;
use api_tracker_core::{gitrepo, hooks};
use common::*;
use std::process::Command;

// A fake but pattern-shaped OpenAI project key (obviously not real).
const FAKE_OPENAI: &str = "sk-proj-FAKE0000000000000000000000000000FAKE";

fn git(dir: &std::path::Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn init_repo(dir: &std::path::Path) {
    git(dir, &["init"]);
    git(dir, &["config", "user.email", "test@example.com"]);
    git(dir, &["config", "user.name", "Test"]);
}

fn add_openai_key(vault: &mut api_tracker_core::vault::UnlockedVault, project: &str, name: &str) {
    vault
        .add_credential(AddCredential {
            project: project.into(),
            provider: "openai".into(),
            name: name.into(),
            environment: Environment::Production,
            value: SecretString::from(FAKE_OPENAI),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
}

#[test]
fn staged_scan_matches_vault_and_marks_exposed() {
    if !gitrepo::git_available() {
        eprintln!("git not available; skipping");
        return;
    }
    let (dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web");
    add_openai_key(&mut vault, "web", "openai-main");

    // A repo with the same secret staged in a .env file.
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_repo(&repo);
    std::fs::write(repo.join(".env"), format!("OPENAI_API_KEY={FAKE_OPENAI}\n")).unwrap();
    git(&repo, &["add", ".env"]);

    let findings = vault.scan_staged(&repo).unwrap();
    assert_eq!(findings.len(), 1, "expected one high-confidence finding");
    let finding = &findings[0];
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(finding.provider.as_deref(), Some("openai"));
    assert_eq!(finding.file, ".env");
    assert_eq!(finding.line, 1);
    // The finding never carries the plaintext in its serialized form.
    let json = serde_json::to_string(finding).unwrap();
    assert!(!json.contains(FAKE_OPENAI));
    assert!(json.contains(&finding.redacted));
    // It matched the vault credential.
    let m = finding
        .vault_match
        .as_ref()
        .expect("should match the vault credential");
    assert_eq!(m.credential_name, "openai-main");
    assert_eq!(m.project_name, "web");

    // Marking exposed sets the credential status.
    let affected = vault.mark_findings_exposed(&findings).unwrap();
    assert_eq!(affected.len(), 1);
    let cred = vault.get_credential("web/openai-main").unwrap();
    assert_eq!(cred.status.primary, Status::PossiblyExposed);
    assert!(cred.exposure_note.contains(".env"));
}

#[test]
fn suppression_hides_a_finding() {
    if !gitrepo::git_available() {
        return;
    }
    let (dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web");

    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_repo(&repo);
    std::fs::write(repo.join(".env"), format!("OPENAI_API_KEY={FAKE_OPENAI}\n")).unwrap();
    git(&repo, &["add", ".env"]);

    let findings = vault.scan_staged(&repo).unwrap();
    assert_eq!(findings.len(), 1);
    let key = findings[0].suppression_key.clone();

    // A reason is required.
    assert!(vault
        .add_suppression(&key, "openai-project-key", ".env", "  ")
        .is_err());
    vault
        .add_suppression(
            &key,
            "openai-project-key",
            ".env",
            "test fixture, not a real key",
        )
        .unwrap();

    let after = vault.scan_staged(&repo).unwrap();
    assert!(after.is_empty(), "suppressed finding should be hidden");
    assert_eq!(vault.list_suppressions().unwrap().len(), 1);
}

#[test]
fn working_tree_scan_finds_secrets_and_skips_binaries() {
    let (dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web");
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("node_modules")).unwrap();
    std::fs::write(tree.join(".env"), format!("OPENAI_API_KEY={FAKE_OPENAI}\n")).unwrap();
    // Should be skipped: dependency dir and a binary file.
    std::fs::write(
        tree.join("node_modules/leak.env"),
        format!("OPENAI_API_KEY={FAKE_OPENAI}\n"),
    )
    .unwrap();
    std::fs::write(tree.join("logo.png"), [0u8, 1, 2, 3]).unwrap();

    let findings = vault.scan_working_tree(&tree).unwrap();
    assert_eq!(
        findings.len(),
        1,
        "only the top-level .env should be scanned"
    );
    assert_eq!(findings[0].file, ".env");
}

#[test]
fn history_scan_detects_committed_secret() {
    if !gitrepo::git_available() {
        return;
    }
    let (dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_repo(&repo);
    std::fs::write(
        repo.join("config.yaml"),
        format!("openai_key: {FAKE_OPENAI}\n"),
    )
    .unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "add config"]);
    // Remove it in the working tree, but it stays in history.
    std::fs::remove_file(repo.join("config.yaml")).unwrap();

    let outcome = vault.scan_history(&repo, Some(10)).unwrap();
    assert!(outcome.complete, "a small history scan must be complete");
    assert!(outcome
        .findings
        .iter()
        .any(|f| f.provider.as_deref() == Some("openai")));
    assert!(outcome.findings[0].file.contains("config.yaml"));
}

#[test]
fn hook_blocks_and_unblocks_via_scanner() {
    // End-to-end at the core level: install a hook, verify status, and prove
    // the staged scan flips from finding→clean as the secret is removed.
    if !gitrepo::git_available() {
        return;
    }
    let (dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_repo(&repo);

    assert_eq!(
        hooks::install(&repo, false).unwrap(),
        hooks::HookState::Installed
    );
    assert_eq!(
        hooks::status(&repo).unwrap().state,
        hooks::HookState::Installed
    );

    std::fs::write(repo.join(".env"), format!("OPENAI_API_KEY={FAKE_OPENAI}\n")).unwrap();
    git(&repo, &["add", ".env"]);
    let findings = vault.scan_staged(&repo).unwrap();
    assert!(
        findings.iter().any(|f| f.confidence == Confidence::High),
        "commit would be blocked"
    );

    // Remove the secret and re-stage: clean.
    std::fs::write(repo.join(".env"), "OPENAI_API_KEY=\n").unwrap();
    git(&repo, &["add", ".env"]);
    let findings = vault.scan_staged(&repo).unwrap();
    assert!(findings.is_empty(), "commit would now proceed");

    assert_eq!(hooks::remove(&repo).unwrap(), hooks::HookState::Absent);
}

#[test]
fn monitor_generates_and_resolves_alerts() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    // An expired credential (user-entered past date).
    vault
        .add_credential(AddCredential {
            project: "app".into(),
            provider: "openai".into(),
            name: "old".into(),
            environment: Environment::Production,
            value: SecretString::from(FAKE_KEY_1),
            credential_type: None,
            key_created_at: None,
            expires_at: Some("2020-01-01".into()),
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();

    let summary = vault.run_monitor().unwrap();
    assert!(summary.alerts_created >= 1);
    let open = alerts::list(vault.connection(), false).unwrap();
    assert!(open.iter().any(|a| a.kind == "expired"));

    // Re-running is idempotent (dedup): no new alert for the same condition.
    let summary2 = vault.run_monitor().unwrap();
    assert_eq!(summary2.alerts_created, 0);

    // Fix the expiry; the alert auto-resolves on the next run.
    let expired = vault.get_credential("app/old").unwrap();
    vault
        .update_credential(
            &expired.id,
            api_tracker_core::vault::UpdateCredential {
                expires_at: Some(Some("2035-01-01".into())),
                ..Default::default()
            },
        )
        .unwrap();
    let summary3 = vault.run_monitor().unwrap();
    assert!(summary3.alerts_resolved >= 1);
    assert!(!alerts::list(vault.connection(), false)
        .unwrap()
        .iter()
        .any(|a| a.kind == "expired"));
}

#[test]
fn monitor_flags_reuse_and_alert_lifecycle() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "prod");
    add_project(&mut vault, "dev");
    add_openai_key(&mut vault, "prod", "shared");
    // Same value in a development project.
    vault
        .add_credential(AddCredential {
            project: "dev".into(),
            provider: "openai".into(),
            name: "shared-copy".into(),
            environment: Environment::Development,
            value: SecretString::from(FAKE_OPENAI),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();

    vault.run_monitor().unwrap();
    let open = alerts::list(vault.connection(), false).unwrap();
    assert!(
        open.iter().any(|a| a.kind == "production_in_development"),
        "prod-in-dev reuse should alert"
    );

    // Acknowledge then resolve the first alert.
    let id = open[0].id.clone();
    let acked = alerts::acknowledge(vault.connection(), &id).unwrap();
    assert!(acked.acknowledged_at.is_some());
    let resolved = alerts::resolve(vault.connection(), &id).unwrap();
    assert!(resolved.resolved_at.is_some());
}

#[test]
fn reuse_alerts_survive_a_password_locked_project_across_monitor_runs() {
    // Regression: run_monitor must compute reuse from the stored fingerprint,
    // not by decrypting values — otherwise a still-valid reuse alert for a
    // password-locked (locked) project would be spuriously auto-resolved.
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "prod");
    add_project(&mut vault, "dev");
    add_openai_key(&mut vault, "prod", "shared");
    vault
        .add_credential(AddCredential {
            project: "dev".into(),
            provider: "openai".into(),
            name: "copy".into(),
            environment: Environment::Development,
            value: SecretString::from(FAKE_OPENAI),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();

    vault.run_monitor().unwrap();
    assert!(alerts::list(vault.connection(), false)
        .unwrap()
        .iter()
        .any(|a| a.kind == "production_in_development"));

    // Lock the prod project (drop its key from the session), then re-run.
    vault
        .set_project_password("prod", &SecretString::from(PROJECT_PW), &master_pw())
        .unwrap();
    vault.lock_project("prod").unwrap();
    vault.run_monitor().unwrap();

    // The reuse alert must still be open — the condition still holds even
    // though the project's value cannot be decrypted this session.
    assert!(
        alerts::list(vault.connection(), false)
            .unwrap()
            .iter()
            .any(|a| a.kind == "production_in_development"),
        "reuse alert must not be auto-resolved just because a project is locked"
    );
}

#[test]
fn documentation_change_raises_an_alert() {
    let (_dir, _paths, vault) = new_vault();
    let url = "https://example.com/docs/auth";
    vault.watch_docs("openai", url).unwrap();

    let fetcher = MockFetcher::with(
        url,
        vec![
            FetchOutcome::Body {
                bytes: b"v1".to_vec(),
                etag: None,
                last_modified: None,
            },
            FetchOutcome::Body {
                bytes: b"v2".to_vec(),
                etag: None,
                last_modified: None,
            },
        ],
    );

    let (r1, _) = vault.check_doc_watch(&fetcher, url).unwrap();
    assert_eq!(r1, CheckResult::FirstCapture);
    // First capture does not alert; a subsequent change does.
    assert!(!alerts::list(vault.connection(), false)
        .unwrap()
        .iter()
        .any(|a| a.kind == "documentation_changed"));

    let (r2, _) = vault.check_doc_watch(&fetcher, url).unwrap();
    assert_eq!(r2, CheckResult::Changed);
    let open = alerts::list(vault.connection(), false).unwrap();
    assert!(open.iter().any(|a| a.kind == "documentation_changed"));
}
