//! Integration tests for milestone 3: connectors, usage, cost, budgets,
//! permissions, activity, and process injection — all through the vault, with
//! mocked HTTP so no live credentials are needed.

mod common;

use api_tracker_core::budget;
use api_tracker_core::http::MockHttpClient;
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::status::Status;
use api_tracker_core::usage;
use api_tracker_core::vault::AddCredential;
use common::*;

const FAKE_GH: &str = "ghp_FAKE0000000000000000000000000000000000";

fn add_github(vault: &mut api_tracker_core::vault::UnlockedVault, project: &str, name: &str) {
    vault
        .add_credential(AddCredential {
            project: project.into(),
            provider: "github".into(),
            name: name.into(),
            environment: Environment::Production,
            value: SecretString::from(FAKE_GH),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
}

#[test]
fn validate_credential_records_result() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web");
    add_github(&mut vault, "web", "gh");

    // Valid: 200 with a login.
    let ok = MockHttpClient::with(200, vec![], r#"{"login":"octocat"}"#);
    let r = vault.validate_credential("web/gh", &ok).unwrap();
    assert!(r.valid);
    assert!(r.detail.contains("octocat"));
    assert_eq!(
        vault.get_credential("web/gh").unwrap().status.primary,
        Status::Active
    );

    // Invalid: 401 marks the credential invalid.
    let bad = MockHttpClient::with(401, vec![], "");
    let r = vault.validate_credential("web/gh", &bad).unwrap();
    assert!(!r.valid);
    assert_eq!(
        vault.get_credential("web/gh").unwrap().status.primary,
        Status::Invalid
    );
}

#[test]
fn permission_sync_normalizes_github_scopes() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web");
    add_github(&mut vault, "web", "gh");

    let mock = MockHttpClient::with(
        200,
        vec![("X-OAuth-Scopes".into(), "repo, read:org, admin:org".into())],
        r#"{"login":"x"}"#,
    );
    let perms = vault.sync_permissions("web/gh", &mock).unwrap();
    assert_eq!(perms.raw_scopes, vec!["repo", "read:org", "admin:org"]);
    assert!(perms.normalized.admin.contains(&"admin:org".to_string()));
    assert!(perms.normalized.sensitive.contains(&"repo".to_string()));
    assert_eq!(perms.precision, "exact_credential");

    // Persisted and retrievable.
    let loaded = vault.get_permissions("web/gh").unwrap().unwrap();
    assert_eq!(loaded.raw_scopes.len(), 3);
}

#[test]
fn metadata_fetch_never_serializes_the_secret() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web");
    add_github(&mut vault, "web", "gh");
    let mock = MockHttpClient::with(
        200,
        vec![("X-OAuth-Scopes".into(), "repo".into())],
        r#"{"login":"octocat","id":42,"created_at":"2020-01-01T00:00:00Z"}"#,
    );
    let meta = vault.fetch_metadata("web/gh", &mock).unwrap();
    let json = serde_json::to_string(&meta).unwrap();
    assert!(
        !json.contains(FAKE_GH),
        "metadata must not contain the secret"
    );
    assert!(meta
        .fields
        .iter()
        .any(|(k, v)| k == "login" && v == "octocat"));
    assert!(meta.fields.iter().any(|(k, _)| k == "token_scopes"));
}

#[test]
fn usage_sync_records_account_level_snapshots() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "ai");
    // An admin credential + connect it for OpenAI.
    vault
        .add_credential(AddCredential {
            project: "ai".into(),
            provider: "openai".into(),
            name: "admin".into(),
            environment: Environment::Production,
            value: SecretString::from("sk-admin-FAKE0000000000000000000000000000"),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    vault.provider_connect("openai", "ai/admin").unwrap();

    let fixture = r#"{"data":[
        {"start_time":1751328000,"end_time":1751414400,"results":[
            {"input_tokens":1000,"output_tokens":500,"num_model_requests":3}
        ]}
    ]}"#;
    let mock = MockHttpClient::json(fixture);
    let report = vault.usage_sync("openai", &mock, 7).unwrap();
    assert_eq!(report.usage_rows, 1);
    // Only one response was queued, so provider-reported costs were
    // unavailable — a noted condition, not a sync failure.
    assert_eq!(report.cost_rows, 0);
    assert!(report.notes.iter().any(|n| n.contains("costs")));

    let status = vault.provider_connection_status("openai").unwrap();
    assert_eq!(status.last_status, "ok");
    assert!(status.connected);
    assert!(status.last_success_at.is_some());
    // The synced usage is account-level, not attributable to a credential.
    let totals =
        usage::totals_since(vault.connection(), "2000-01-01T00:00:00Z", None, None).unwrap();
    assert_eq!(totals.input_tokens, 1000);
    assert!(totals.has_inexact_attribution);
    assert_eq!(
        totals.coarsest_attribution.as_deref(),
        Some("provider_account")
    );

    // Re-syncing the same window must not double-count: prior synced snapshots
    // are replaced, so totals stay put rather than doubling.
    let mock = MockHttpClient::json(fixture);
    vault.usage_sync("openai", &mock, 7).unwrap();
    let totals =
        usage::totals_since(vault.connection(), "2000-01-01T00:00:00Z", None, None).unwrap();
    assert_eq!(totals.input_tokens, 1000, "re-sync double-counted usage");
}

#[test]
fn manual_usage_estimates_cost_and_budget_triggers_over_budget_alert() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    vault
        .add_credential(AddCredential {
            project: "app".into(),
            provider: "openai".into(),
            name: "key".into(),
            environment: Environment::Production,
            value: SecretString::from("sk-proj-FAKE0000000000000000000000000000"),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();

    // Record a manual usage snapshot in the current period: 1M in + 1M out on
    // gpt-4o ($2.50 + $10.00 = $12.50 estimated).
    let now = api_tracker_core::clock::now();
    let start = budget::period_start(now);
    vault
        .usage_record_manual(
            "app/key",
            Some("gpt-4o"),
            1_000_000,
            1_000_000,
            &start,
            &start,
        )
        .unwrap();

    // Credential report shows the estimated cost.
    let report = vault.credential_budget_report("app/key").unwrap();
    assert_eq!(report.estimated_cost_micros, 12_500_000);
    assert!(report.used_is_estimated);

    // Set a $5 budget and run the monitor -> over-budget alert.
    vault
        .set_credential_budget_dollars("app/key", Some("5.00"))
        .unwrap();
    vault.run_monitor().unwrap();
    let open = api_tracker_core::alerts::list(vault.connection(), false).unwrap();
    assert!(
        open.iter().any(|a| a.kind == "over_budget"),
        "over-budget alert expected"
    );
}

#[test]
fn injection_builds_env_for_only_requested_project_credentials() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "web");
    add_project(&mut vault, "other");
    vault
        .add_credential(AddCredential {
            project: "web".into(),
            provider: "openai".into(),
            name: "openai".into(),
            environment: Environment::Production,
            value: SecretString::from("sk-proj-WEBKEY000000000000000000000000000"),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    vault
        .add_credential(AddCredential {
            project: "other".into(),
            provider: "stripe".into(),
            name: "stripe".into(),
            environment: Environment::Production,
            value: SecretString::from("sk_live_OTHERKEY0000000000000000000000"),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();

    // Inject exactly one credential from 'web'.
    let (env, session) = vault
        .build_injection(
            "web",
            &[("web/openai".to_string(), "OPENAI_API_KEY".to_string())],
            "npm run dev",
        )
        .unwrap();
    assert_eq!(env.len(), 1);
    assert_eq!(env[0].0, "OPENAI_API_KEY");
    assert_eq!(
        env[0].1.expose(),
        "sk-proj-WEBKEY000000000000000000000000000"
    );

    // A credential from another project is refused.
    let err = vault
        .build_injection(
            "web",
            &[("other/stripe".to_string(), "STRIPE".to_string())],
            "x",
        )
        .unwrap_err();
    assert!(matches!(err, api_tracker_core::CoreError::InvalidInput(_)));

    // The session was recorded (names only, no values).
    vault.end_process_session(&session, Some(0)).unwrap();
    let sessions = vault.list_process_sessions(10, false).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].injected_vars, "OPENAI_API_KEY");
    assert_eq!(sessions[0].exit_code, Some(0));
    let json = serde_json::to_string(&sessions).unwrap();
    assert!(
        !json.contains("WEBKEY"),
        "session record must not contain a secret value"
    );
}

#[test]
fn unsupported_capability_reports_official_link() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "pay");
    vault
        .add_credential(AddCredential {
            project: "pay".into(),
            provider: "stripe".into(),
            name: "key".into(),
            environment: Environment::Production,
            value: SecretString::from("sk_live_FAKE00000000000000000000000000"),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    let mock = MockHttpClient::json("{}");
    // Stripe permissions are dashboard-only.
    let err = vault.sync_permissions("pay/key", &mock).unwrap_err();
    match err {
        api_tracker_core::CoreError::Unsupported { provider, hint, .. } => {
            assert_eq!(provider, "stripe");
            assert!(hint.contains("stripe.com"));
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}
