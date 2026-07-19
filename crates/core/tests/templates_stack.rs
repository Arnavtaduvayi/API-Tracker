//! Integration tests for project templates and local stack detection
//! through the vault: application, example generation, detection with
//! evidence, preference learning, and reset/deletion of learned data.

mod common;

use api_tracker_core::model::Environment;
use common::*;
use std::path::Path;

#[test]
fn template_apply_creates_project_and_records_application() {
    let (_dir, _paths, mut vault) = new_vault();
    let outcome = vault
        .template_apply("fullstack-saas", "my-saas", None)
        .unwrap();
    assert_eq!(outcome.project.name, "my-saas");
    // Environments come from the template.
    assert!(outcome
        .project
        .environments
        .contains(&Environment::Production));
    assert!(outcome
        .project
        .environments
        .contains(&Environment::Development));
    // The application is recorded and repeatable (idempotent upsert).
    let applied = vault.project_templates("my-saas").unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].0, "fullstack-saas");
    vault
        .template_apply("fullstack-saas", "my-saas", None)
        .unwrap();
    assert_eq!(vault.project_templates("my-saas").unwrap().len(), 1);
    // Next steps name explicit commands; nothing created credentials.
    assert!(outcome.next_steps.iter().any(|s| s.contains("key add")));
    assert_eq!(vault.list_credentials(Some("my-saas")).unwrap().len(), 0);
    // Unknown templates are rejected.
    assert!(vault.template_apply("no-such", "x", None).is_err());
}

#[test]
fn template_apply_writes_example_but_never_overwrites() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    let outcome = vault
        .template_apply("stripe-app", "shop", Some(repo.path()))
        .unwrap();
    let path = outcome.example_path.clone().unwrap();
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("STRIPE_SECRET_KEY=\n"));
    // Every non-comment assignment is empty — names only.
    for line in written.lines() {
        if !line.starts_with('#') {
            if let Some((_, v)) = line.split_once('=') {
                assert!(v.is_empty(), "value present in example: {line}");
            }
        }
    }
    // A second write into the same directory refuses to clobber.
    let err = vault
        .template_apply("stripe-app", "shop", Some(repo.path()))
        .unwrap_err();
    assert!(err.to_string().contains("merge"), "unexpected: {err}");
}

#[test]
fn stack_detection_learns_and_forgets_locally() {
    let (_dir, _paths, vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(
        repo.path().join("package.json"),
        r#"{"dependencies":{"openai":"^4","next":"^15","stripe":"^17","@supabase/supabase-js":"^2"}}"#,
    )
    .unwrap();

    let report = vault.stack_detect_path(repo.path()).unwrap();
    assert!(!report.signals.is_empty());
    // The composite SaaS suggestion appears alongside the parts.
    assert!(report
        .suggestions
        .iter()
        .any(|s| s.template_id == "fullstack-saas"));
    let openai = report
        .suggestions
        .iter()
        .find(|s| s.template_id == "openai-app")
        .unwrap();
    assert!(openai.evidence.iter().any(|e| e.contains("package.json")));

    // Dismiss one suggestion; it stays listed but marked.
    vault
        .stack_decide(repo.path(), "stripe-app", "dismissed")
        .unwrap();
    let report = vault.stack_detect_path(repo.path()).unwrap();
    let stripe = report
        .suggestions
        .iter()
        .find(|s| s.template_id == "stripe-app")
        .unwrap();
    assert_eq!(stripe.prior_decision.as_deref(), Some("dismissed"));

    // Confirm another; it is remembered and boosted.
    vault
        .stack_decide(repo.path(), "openai-app", "confirmed")
        .unwrap();
    let report = vault.stack_detect_path(repo.path()).unwrap();
    let openai = report
        .suggestions
        .iter()
        .find(|s| s.template_id == "openai-app")
        .unwrap();
    assert_eq!(openai.prior_decision.as_deref(), Some("confirmed"));

    // The learned data is enumerable and deletable — per repo and entirely.
    assert_eq!(vault.stack_preferences().unwrap().len(), 2);
    assert_eq!(vault.stack_preferences_reset(Some(repo.path())).unwrap(), 2);
    assert_eq!(vault.stack_preferences().unwrap().len(), 0);
    vault
        .stack_decide(repo.path(), "openai-app", "confirmed")
        .unwrap();
    assert_eq!(vault.stack_preferences_reset(None).unwrap(), 1);

    // Invalid decisions and unknown templates are rejected.
    assert!(vault
        .stack_decide(repo.path(), "openai-app", "maybe")
        .is_err());
    assert!(vault
        .stack_decide(repo.path(), "not-a-template", "confirmed")
        .is_err());
}

#[test]
fn stack_detection_over_project_repositories() {
    let (_dir, _paths, mut vault) = new_vault();
    let repo = tempfile::tempdir().unwrap();
    std::fs::write(
        repo.path().join("requirements.txt"),
        "anthropic==0.40.0\nfastapi>=0.100\n",
    )
    .unwrap();
    vault
        .create_project(api_tracker_core::vault::NewProject {
            name: "py-svc".into(),
            repo_paths: vec![repo.path().display().to_string()],
            ..Default::default()
        })
        .unwrap();
    let reports = vault.stack_detect_project("py-svc").unwrap();
    assert_eq!(reports.len(), 1);
    assert!(reports[0]
        .suggestions
        .iter()
        .any(|s| s.template_id == "anthropic-app"));
    assert!(reports[0]
        .suggestions
        .iter()
        .any(|s| s.template_id == "python-backend"));
    // A nonexistent path errors clearly on the direct entry point.
    assert!(vault
        .stack_detect_path(Path::new("/definitely/not/here"))
        .is_err());
}
