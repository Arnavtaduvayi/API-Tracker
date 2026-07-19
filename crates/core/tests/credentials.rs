//! Project and credential workflows: CRUD, password locks, reuse detection,
//! references, statuses, and redaction guarantees.

mod common;

use api_tracker_core::model::Environment;
use api_tracker_core::reuse::ReuseKind;
use api_tracker_core::secret::{SecretString, REDACTED};
use api_tracker_core::status::Status;
use api_tracker_core::vault::{
    self, AddCredential, AddReference, NewProject, UpdateCredential, UpdateProject,
};
use api_tracker_core::CoreError;
use common::*;

#[test]
fn project_crud_lifecycle() {
    let (_dir, _paths, mut vault) = new_vault();
    let project = vault
        .create_project(NewProject {
            name: "backend".into(),
            description: "the API".into(),
            notes: "notes here".into(),
            environments: vec![Environment::Development, Environment::Production],
            repo_paths: vec!["/tmp/example-repo".into()],
        })
        .unwrap();
    assert_eq!(project.environments.len(), 2);
    assert_eq!(project.repo_paths, vec!["/tmp/example-repo".to_owned()]);
    assert!(!project.password_locked);
    assert!(project.unlocked);

    // Duplicate names (case-insensitive) are rejected.
    let err = vault
        .create_project(NewProject {
            name: "BACKEND".into(),
            ..Default::default()
        })
        .unwrap_err();
    assert!(matches!(err, CoreError::AlreadyExists { .. }));

    // Slash is reserved for selectors.
    let err = vault
        .create_project(NewProject {
            name: "a/b".into(),
            ..Default::default()
        })
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));

    let updated = vault
        .update_project(
            "backend",
            UpdateProject {
                description: Some("updated".into()),
                add_repo_paths: vec!["/tmp/second-repo".into()],
                remove_repo_paths: vec!["/tmp/example-repo".into()],
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(updated.description, "updated");
    assert_eq!(updated.repo_paths, vec!["/tmp/second-repo".to_owned()]);

    let archived = vault.set_project_archived("backend", true).unwrap();
    assert!(archived.archived);
    assert_eq!(vault.list_projects(false).unwrap().len(), 0);
    assert_eq!(vault.list_projects(true).unwrap().len(), 1);
    let restored = vault.set_project_archived("backend", false).unwrap();
    assert!(!restored.archived);
}

#[test]
fn credential_lifecycle_with_metadata() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, warnings) = vault
        .add_credential(AddCredential {
            project: "app".into(),
            provider: "Anthropic".into(),
            name: "claude-key".into(),
            environment: Environment::Production,
            value: SecretString::from(FAKE_KEY_1),
            credential_type: None,
            key_created_at: Some("2026-01-01".into()),
            expires_at: Some("2030-01-01".into()),
            docs_url: "https://docs.anthropic.com".into(),
            notes: "the main key".into(),
        })
        .unwrap();
    assert!(warnings.is_empty());
    assert_eq!(cred.provider, "anthropic");
    assert_eq!(cred.masked_value, "FAKE…01");
    assert_eq!(cred.key_created_at.as_deref(), Some("2026-01-01T00:00:00Z"));

    // Selector by project/name.
    let by_selector = vault.get_credential("app/claude-key").unwrap();
    assert_eq!(by_selector.id, cred.id);

    // Metadata update + manual marks.
    let updated = vault
        .update_credential(
            "app/claude-key",
            UpdateCredential {
                notes: Some("rotated soon".into()),
                mark_used_now: true,
                mark_validated: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(updated.notes, "rotated soon");
    assert!(updated.last_used_at.is_some());
    assert!(updated.last_validated_at.is_some());
    assert_eq!(updated.status.primary, Status::Active);

    // Reveal requires the correct master password.
    let err = vault
        .reveal_credential("app/claude-key", &SecretString::from("wrong-password-123"))
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword));
    let revealed = vault
        .reveal_credential("app/claude-key", &master_pw())
        .unwrap();
    assert_eq!(revealed.expose(), FAKE_KEY_1);

    // Replace the value (reauthenticated).
    let (replaced, _) = vault
        .replace_credential_value(
            "app/claude-key",
            &master_pw(),
            SecretString::from(FAKE_KEY_2),
        )
        .unwrap();
    assert_eq!(replaced.masked_value, "FAKE…02");
    let revealed = vault
        .reveal_credential("app/claude-key", &master_pw())
        .unwrap();
    assert_eq!(revealed.expose(), FAKE_KEY_2);

    // Delete.
    vault.delete_credential("app/claude-key").unwrap();
    assert!(matches!(
        vault.get_credential("app/claude-key").unwrap_err(),
        CoreError::NotFound { .. }
    ));
}

#[test]
fn duplicate_names_within_project_rejected_and_selectors_disambiguate() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "one");
    add_project(&mut vault, "two");
    add_key(
        &mut vault,
        "one",
        "shared-name",
        FAKE_KEY_1,
        Environment::Development,
    );
    add_key(
        &mut vault,
        "two",
        "shared-name",
        FAKE_KEY_2,
        Environment::Development,
    );

    // Same name in the same project is rejected.
    let err = vault
        .add_credential(AddCredential {
            project: "one".into(),
            provider: "openai".into(),
            name: "SHARED-NAME".into(),
            environment: Environment::Development,
            value: SecretString::from("FAKE-TEST-NOT-A-REAL-KEY-000003"),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap_err();
    assert!(matches!(err, CoreError::AlreadyExists { .. }));

    // A bare ambiguous name errors; project/name works.
    assert!(matches!(
        vault.get_credential("shared-name").unwrap_err(),
        CoreError::Ambiguous { .. }
    ));
    assert!(vault.get_credential("one/shared-name").is_ok());
}

#[test]
fn short_project_password_is_rejected() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "secure");
    let err = vault
        .set_project_password("secure", &SecretString::from("elevenchars"), &master_pw())
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));
    assert!(!vault.get_project("secure").unwrap().password_locked);
}

#[test]
fn project_password_lock_flow() {
    let (_dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "secure");
    add_key(
        &mut vault,
        "secure",
        "api",
        FAKE_KEY_1,
        Environment::Production,
    );

    vault
        .set_project_password("secure", &SecretString::from(PROJECT_PW), &master_pw())
        .unwrap();
    // Still unlocked in this session (we just set the password).
    assert!(vault.get_project("secure").unwrap().unlocked);
    assert!(vault.reveal_credential("secure/api", &master_pw()).is_ok());

    // Lock: the key is dropped from the session.
    vault.lock_project("secure").unwrap();
    assert!(!vault.get_project("secure").unwrap().unlocked);
    let err = vault
        .reveal_credential("secure/api", &master_pw())
        .unwrap_err();
    assert!(matches!(err, CoreError::ProjectLocked(_)));
    // Adding to a locked project also fails: encryption needs the key.
    let err = vault
        .add_credential(AddCredential {
            project: "secure".into(),
            provider: "openai".into(),
            name: "another".into(),
            environment: Environment::Development,
            value: SecretString::from(FAKE_KEY_2),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap_err();
    assert!(matches!(err, CoreError::ProjectLocked(_)));

    // Wrong project password.
    let err = vault
        .unlock_project("secure", &SecretString::from("wrong-password-123"))
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword));

    // Correct password unlocks.
    vault
        .unlock_project("secure", &SecretString::from(PROJECT_PW))
        .unwrap();
    assert!(vault.get_project("secure").unwrap().unlocked);
    assert_eq!(
        vault
            .reveal_credential("secure/api", &master_pw())
            .unwrap()
            .expose(),
        FAKE_KEY_1
    );

    // The lock survives a vault re-open.
    vault.lock();
    let mut vault = vault::unlock_vault(&paths, &master_pw()).unwrap();
    assert!(!vault.get_project("secure").unwrap().unlocked);
    assert!(matches!(
        vault
            .reveal_credential("secure/api", &master_pw())
            .unwrap_err(),
        CoreError::ProjectLocked(_)
    ));

    // Removing the password requires knowing it.
    let err = vault
        .remove_project_password("secure", &SecretString::from("wrong-password-123"))
        .unwrap_err();
    assert!(matches!(err, CoreError::WrongPassword));
    vault
        .remove_project_password("secure", &SecretString::from(PROJECT_PW))
        .unwrap();
    assert!(vault.get_project("secure").unwrap().unlocked);
    assert!(vault.reveal_credential("secure/api", &master_pw()).is_ok());
}

#[test]
fn reuse_detection_and_classification() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web-prod");
    add_project(&mut vault, "experiments");

    add_key(
        &mut vault,
        "web-prod",
        "stripe",
        FAKE_KEY_1,
        Environment::Production,
    );

    // Pre-check before storing (what UIs call first).
    let warnings = vault
        .check_reuse(
            "experiments",
            Environment::Development,
            &SecretString::from(FAKE_KEY_1),
        )
        .unwrap();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].kind, ReuseKind::ProductionSharedWithDevelopment);
    assert!(warnings[0].message.contains("web-prod/stripe"));
    assert!(!warnings[0].recommendation.is_empty());

    // Storing anyway returns the same warning.
    let (cred, warnings) = add_key(
        &mut vault,
        "experiments",
        "stripe-copy",
        FAKE_KEY_1,
        Environment::Development,
    );
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].kind, ReuseKind::ProductionSharedWithDevelopment);

    // Both records now carry the shared-across-projects status.
    assert_eq!(cred.status.primary, Status::SharedAcrossProjects);
    let original = vault.get_credential("web-prod/stripe").unwrap();
    assert!(original
        .status
        .findings
        .iter()
        .any(|f| f.status == Status::SharedAcrossProjects && f.reason.contains("experiments")));

    // Duplicate inside the same project.
    let (_, warnings) = add_key(
        &mut vault,
        "web-prod",
        "stripe-again",
        FAKE_KEY_1,
        Environment::Production,
    );
    assert!(warnings
        .iter()
        .any(|w| w.kind == ReuseKind::DuplicateInProject));

    // Unrelated value: no warnings.
    let (_, warnings) = add_key(
        &mut vault,
        "experiments",
        "other",
        FAKE_KEY_2,
        Environment::Development,
    );
    assert!(warnings.is_empty());
}

#[test]
fn intentional_references_share_one_encrypted_value() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "main");
    add_project(&mut vault, "spinoff");
    let (source, _) = add_key(
        &mut vault,
        "main",
        "shared-api",
        FAKE_KEY_1,
        Environment::Production,
    );

    let reference = vault
        .add_credential_reference(AddReference {
            project: "spinoff".into(),
            source: "main/shared-api".into(),
            name: "shared-api".into(),
            environment: Environment::Production,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    assert!(reference.is_reference);
    assert_eq!(reference.linked_target.as_deref(), Some("main/shared-api"));
    assert_eq!(reference.masked_value, source.masked_value);

    // Revealing the reference resolves to the source value.
    let revealed = vault
        .reveal_credential("spinoff/shared-api", &master_pw())
        .unwrap();
    assert_eq!(revealed.expose(), FAKE_KEY_1);

    // Reference sharing is reported as intentional.
    let warnings = vault
        .check_reuse(
            "main",
            Environment::Production,
            &SecretString::from(FAKE_KEY_1),
        )
        .unwrap();
    assert!(warnings
        .iter()
        .any(|w| w.kind == ReuseKind::IntentionalReference));

    // A reference to a reference resolves to the root record.
    let second_ref = vault
        .add_credential_reference(AddReference {
            project: "spinoff".into(),
            source: "spinoff/shared-api".into(),
            name: "chained".into(),
            environment: Environment::Production,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    assert_eq!(
        second_ref.linked_credential_id.as_deref(),
        Some(source.id.as_str())
    );

    // Value replacement must happen on the source, not the reference.
    let err = vault
        .replace_credential_value(
            "spinoff/shared-api",
            &master_pw(),
            SecretString::from(FAKE_KEY_2),
        )
        .unwrap_err();
    assert!(matches!(err, CoreError::InvalidInput(_)));

    // The source cannot be deleted while references exist.
    let err = vault.delete_credential("main/shared-api").unwrap_err();
    assert!(matches!(err, CoreError::HasLinkedReferences(2)));
    vault.delete_credential("spinoff/chained").unwrap();
    vault.delete_credential("spinoff/shared-api").unwrap();
    vault.delete_credential("main/shared-api").unwrap();
}

#[test]
fn replacing_a_source_value_keeps_references_consistent() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "main");
    add_project(&mut vault, "spinoff");
    add_key(
        &mut vault,
        "main",
        "shared",
        FAKE_KEY_1,
        Environment::Production,
    );
    vault
        .add_credential_reference(AddReference {
            project: "spinoff".into(),
            source: "main/shared".into(),
            name: "borrowed".into(),
            environment: Environment::Production,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();

    // Rotate the source value.
    vault
        .replace_credential_value("main/shared", &master_pw(), SecretString::from(FAKE_KEY_2))
        .unwrap();

    // The reference now reveals the new value...
    assert_eq!(
        vault
            .reveal_credential("spinoff/borrowed", &master_pw())
            .unwrap()
            .expose(),
        FAKE_KEY_2
    );
    // ...and its mask and reuse status track the new value, not the old one.
    let reference = vault.get_credential("spinoff/borrowed").unwrap();
    assert_eq!(reference.masked_value, "FAKE…02");
    let source = vault.get_credential("main/shared").unwrap();
    assert_eq!(source.status.primary, Status::SharedAcrossProjects);
    // The retired old value is no longer reported as in use anywhere.
    let stale_warnings = vault
        .check_reuse(
            "main",
            Environment::Production,
            &SecretString::from(FAKE_KEY_1),
        )
        .unwrap();
    assert!(
        stale_warnings.is_empty(),
        "the old value must no longer match any record"
    );
}

#[test]
fn failed_validation_does_not_produce_a_contradictory_active_finding() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "key",
        FAKE_KEY_1,
        Environment::Development,
    );
    let updated = vault
        .update_credential(
            &cred.id,
            UpdateCredential {
                mark_validated: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(updated.status.primary, Status::Invalid);
    assert!(
        !updated
            .status
            .findings
            .iter()
            .any(|f| f.status == Status::Active),
        "a failed validation must not also report the credential as active"
    );
}

#[test]
fn reference_reveal_requires_source_project_unlocked() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "vault-locked");
    add_project(&mut vault, "consumer");
    add_key(
        &mut vault,
        "vault-locked",
        "src",
        FAKE_KEY_1,
        Environment::Production,
    );
    vault
        .add_credential_reference(AddReference {
            project: "consumer".into(),
            source: "vault-locked/src".into(),
            name: "borrowed".into(),
            environment: Environment::Development,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    vault
        .set_project_password(
            "vault-locked",
            &SecretString::from(PROJECT_PW),
            &master_pw(),
        )
        .unwrap();
    vault.lock_project("vault-locked").unwrap();

    let err = vault
        .reveal_credential("consumer/borrowed", &master_pw())
        .unwrap_err();
    assert!(matches!(err, CoreError::ProjectLocked(_)));
}

#[test]
fn expired_and_expiring_statuses_flow_through() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "times");
    let (expired, _) = vault
        .add_credential(AddCredential {
            project: "times".into(),
            provider: "github".into(),
            name: "old-token".into(),
            environment: Environment::Development,
            value: SecretString::from(FAKE_KEY_1),
            credential_type: None,
            key_created_at: None,
            expires_at: Some("2020-01-01".into()),
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    assert_eq!(expired.status.primary, Status::Expired);
    let finding = &expired.status.findings[0];
    assert!(finding.reason.contains("2020-01-01"));
    assert_eq!(finding.source, "user-entered expiration date");

    let (disabled, _) = add_key(
        &mut vault,
        "times",
        "disabled",
        FAKE_KEY_2,
        Environment::Test,
    );
    let disabled = vault
        .update_credential(
            &disabled.id,
            UpdateCredential {
                disabled: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(disabled.status.primary, Status::ManuallyDisabled);

    let flagged = vault
        .update_credential(
            &disabled.id,
            UpdateCredential {
                disabled: Some(false),
                possibly_exposed: Some(true),
                exposure_note: Some("found in an old gist".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(flagged.status.primary, Status::PossiblyExposed);
    assert!(flagged
        .status
        .findings
        .iter()
        .any(|f| f.reason.contains("old gist")));
}

#[test]
fn secrets_never_appear_in_listings_errors_or_serialized_output() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "leaktest");
    add_key(
        &mut vault,
        "leaktest",
        "canary",
        FAKE_KEY_1,
        Environment::Production,
    );

    // Listing and JSON serialization contain the mask, never the value.
    let credentials = vault.list_credentials(Some("leaktest")).unwrap();
    let json = serde_json::to_string(&credentials).unwrap();
    assert!(
        !json.contains(FAKE_KEY_1),
        "serialized listing must not contain the secret"
    );
    assert!(json.contains("FAKE…01"));

    let detail = vault.get_credential("leaktest/canary").unwrap();
    let debug = format!("{detail:?}");
    assert!(
        !debug.contains(FAKE_KEY_1),
        "debug output must not contain the secret"
    );

    // The revealed value redacts itself in Display/Debug/serde.
    let revealed = vault
        .reveal_credential("leaktest/canary", &master_pw())
        .unwrap();
    assert_eq!(format!("{revealed}"), REDACTED);
    assert_eq!(format!("{revealed:?}"), REDACTED);
    assert_eq!(
        serde_json::to_string(&revealed).unwrap(),
        format!("\"{REDACTED}\"")
    );

    // Errors produced around secret handling never embed the value.
    let err = vault
        .reveal_credential("leaktest/canary", &SecretString::from("wrong-password-123"))
        .unwrap_err();
    assert!(!format!("{err} {err:?}").contains(FAKE_KEY_1));
    let err = vault
        .add_credential(AddCredential {
            project: "leaktest".into(),
            provider: "openai".into(),
            name: "canary".into(), // duplicate name -> error
            environment: Environment::Production,
            value: SecretString::from(FAKE_KEY_1),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap_err();
    assert!(!format!("{err} {err:?}").contains(FAKE_KEY_1));

    // Audit events never contain secret values.
    let audit_json = serde_json::to_string(&vault.recent_audit_events(100).unwrap()).unwrap();
    assert!(!audit_json.contains(FAKE_KEY_1));
}

#[test]
fn credentials_are_encrypted_at_rest() {
    let (_dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "rest");
    add_key(
        &mut vault,
        "rest",
        "api",
        FAKE_KEY_1,
        Environment::Development,
    );
    vault.lock();

    let raw = std::fs::read(paths.db_path()).unwrap();
    let needle = FAKE_KEY_1.as_bytes();
    let found = raw.windows(needle.len()).any(|w| w == needle);
    assert!(
        !found,
        "the plaintext credential value must not appear in the database file"
    );
}
