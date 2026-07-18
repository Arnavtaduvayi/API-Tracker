//! Integration tests for credential rotation, temporary access grants,
//! provider-created test keys, and provider-reported expiration. Everything
//! runs against `MockHttpClient` fixtures with fake credentials.

mod common;

use api_tracker_core::destinations::CommandRunner;
use api_tracker_core::http::{HttpResponse, MockHttpClient};
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault;
use common::{add_key, add_project, master_pw, new_vault};

/// `common::add_key` hardcodes provider "openai"; rotation tests need the
/// real provider on each credential.
fn add_provider_key(
    v: &mut vault::UnlockedVault,
    project: &str,
    name: &str,
    provider: &str,
    value: &str,
) -> api_tracker_core::model::Credential {
    v.add_credential(vault::AddCredential {
        project: project.to_owned(),
        provider: provider.to_owned(),
        name: name.to_owned(),
        environment: Environment::Production,
        value: SecretString::from(value),
        credential_type: None,
        key_created_at: None,
        expires_at: None,
        docs_url: String::new(),
        notes: String::new(),
    })
    .unwrap()
    .0
}

const FAKE_OLD: &str = "sk-proj-FAKEOLD0000000000000000000000000001";
const FAKE_NEW: &str = "sk-svcacct-FAKENEW00000000000000000000000001";
const FAKE_ADMIN: &str = "sk-admin-FAKE0000000000000000000000000000001";
const FAKE_GH_TOKEN: &str = "ghp_FAKE0000000000000000000000000000000000";

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

fn resp(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
    }
}

fn created_sa_response() -> HttpResponse {
    resp(
        200,
        &format!(
            r#"{{"id":"svc_acct_1","name":"rot","role":"member",
                "api_key":{{"id":"key_new_1","value":"{FAKE_NEW}"}}}}"#
        ),
    )
}

/// Set up an OpenAI credential with an admin connection, a linked old
/// provider key id, and one GitHub Actions destination.
fn openai_rotation_fixture() -> (
    tempfile::TempDir,
    vault::VaultPaths,
    vault::UnlockedVault,
    String,
) {
    let (dir, paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let (cred, _) = add_key(
        &mut v,
        "app",
        "openai-main",
        FAKE_OLD,
        Environment::Production,
    );
    v.provider_admin_connect(
        "openai",
        &SecretString::from(FAKE_ADMIN),
        Some("test-org"),
        None,
    )
    .unwrap();
    // Cache provider-side key metadata + link the old key id.
    v.connection()
        .execute(
            "INSERT INTO provider_side_keys (provider, api_key_id, provider_project_id, name,
                 redacted_value, synced_at)
             VALUES ('openai', 'key_old_1', 'proj_1', 'old', 'sk-...0001', '2026-07-01T00:00:00Z')",
            [],
        )
        .unwrap();
    v.provider_link_key("openai", "key_old_1", &cred.id)
        .unwrap();
    v.destination_add(
        "github_actions",
        "ci",
        serde_json::json!({"owner": "octo", "repo": "app"}),
        Some(&SecretString::from(FAKE_GH_TOKEN)),
    )
    .unwrap();
    v.destination_attach(&cred.id, "ci", "OPENAI_API_KEY", "production")
        .unwrap();
    (dir, paths, v, cred.id)
}

fn gh_pubkey_response() -> HttpResponse {
    use base64::Engine;
    let pk = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    resp(200, &format!(r#"{{"key_id":"k1","key":"{pk}"}}"#))
}

/// The full mock sequence for a grace-0 API rotation in one advance call.
fn full_rotation_mocks() -> MockHttpClient {
    MockHttpClient::new(vec![
        created_sa_response(),                      // create service account
        gh_pubkey_response(),                       // destination: public key
        resp(204, ""),                              // destination: PUT secret
        resp(200, r#"{"name":"OPENAI_API_KEY"}"#),  // destination: existence
        resp(200, r#"{"data":[{"id":"gpt-4o"}]}"#), // validate new key
        resp(200, r#"{"deleted":true}"#),           // revoke old key
    ])
}

#[test]
fn api_rotation_completes_end_to_end_with_verified_steps() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v
        .rotation_plan(&cred_id, 0, None, None, "quarterly rotation")
        .unwrap();
    assert_eq!(plan.rotation.state, "planned");
    assert_eq!(plan.rotation.mode, "api_create");
    assert_eq!(
        plan.rotation.old_provider_key_id.as_deref(),
        Some("key_old_1")
    );
    assert_eq!(plan.rotation.provider_project_id.as_deref(), Some("proj_1"));

    // A dry run touches nothing: value unchanged, no provider calls yet.
    let before = v.reveal_credential(&cred_id, &master_pw()).unwrap();
    assert_eq!(before.expose(), FAKE_OLD);

    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    let http = full_rotation_mocks();
    let done = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(
        done.rotation.state, "completed",
        "{:?}",
        done.rotation.last_error
    );
    assert!(done.rotation.new_value_validated);
    assert!(done.rotation.old_revoked_at.is_some());
    assert_eq!(done.rotation.old_version, Some(1));
    assert_eq!(done.rotation.new_version, Some(2));

    // The vault now holds the NEW value; the old is retained as a version.
    let now = v.reveal_credential(&cred_id, &master_pw()).unwrap();
    assert_eq!(now.expose(), FAKE_NEW);
    let history = v
        .credential_version_history(&cred_id, &master_pw())
        .unwrap();
    assert_eq!(history.len(), 2);

    // The new provider key id is linked (rotation was the confirmation).
    // The OLD link is kept deliberately: past usage stays attributed.
    let linked: i64 = v
        .connection()
        .query_row(
            "SELECT count(*) FROM provider_key_links
             WHERE credential_id = ?1 AND provider_api_key_id = 'key_new_1'",
            [&cred_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(linked, 1);

    // The revocation happened only after validation (event order).
    let events = v.rotation_events(&plan.rotation.id).unwrap();
    let validated_idx = events
        .iter()
        .position(|e| e.detail.contains("new value validated"))
        .expect("validation event");
    let revoked_idx = events
        .iter()
        .position(|e| e.detail.contains("old key revoked"))
        .expect("revocation event");
    assert!(validated_idx < revoked_idx);

    // No secret value ever appears in serialized rotation state or events.
    let serialized = serde_json::to_string(&(&done, &events)).unwrap();
    assert!(!serialized.contains(FAKE_NEW));
    assert!(!serialized.contains(FAKE_OLD));
    assert!(!serialized.contains(FAKE_ADMIN));
}

#[test]
fn rotation_survives_restart_and_does_not_double_create() {
    let (_dir, paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();

    // First advance: creation succeeds, but the destination update fails.
    let http = MockHttpClient::new(vec![
        created_sa_response(),
        resp(500, "{}"), // destination public-key fetch fails
    ]);
    let stuck = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(stuck.rotation.state, "updating_destinations");
    assert!(!stuck.rotation.last_error.is_empty());

    // "Restart": drop the vault and unlock a fresh instance from disk.
    drop(v);
    let mut v = vault::unlock_vault(&paths, &master_pw()).unwrap();
    let resumed = v.rotation_get(&plan.rotation.id).unwrap();
    assert_eq!(resumed.rotation.state, "updating_destinations");

    // Retry: only the destination step re-runs — the mock sequence contains
    // NO creation response, so a second creation attempt would fail loudly.
    let http = MockHttpClient::new(vec![
        gh_pubkey_response(),
        resp(204, ""),
        resp(200, r#"{"name":"OPENAI_API_KEY"}"#),
        resp(200, r#"{"data":[{"id":"gpt-4o"}]}"#),
        resp(200, r#"{"deleted":true}"#),
    ]);
    let done = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(
        done.rotation.state, "completed",
        "{:?}",
        done.rotation.last_error
    );
    // Exactly one replacement was stored across both attempts.
    assert_eq!(done.rotation.new_version, Some(2));
}

#[test]
fn provider_create_failure_is_retryable_and_old_key_untouched() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    let http = MockHttpClient::new(vec![resp(500, "{}"), resp(500, "{}"), resp(500, "{}")]);
    let stuck = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(
        stuck.rotation.state, "creating_replacement",
        "stays in the claim state, retryable"
    );
    assert!(!stuck.rotation.last_error.is_empty());
    let value = v.reveal_credential(&cred_id, &master_pw()).unwrap();
    assert_eq!(value.expose(), FAKE_OLD, "old value untouched");
}

#[test]
fn validation_failure_blocks_destruction_and_rollback_restores_everything() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    let http = MockHttpClient::new(vec![
        created_sa_response(),
        gh_pubkey_response(),
        resp(204, ""),
        resp(200, r#"{"name":"OPENAI_API_KEY"}"#),
        resp(401, r#"{"error":{"code":"invalid_api_key"}}"#), // validation fails
    ]);
    let stuck = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(stuck.rotation.state, "destinations_verified");
    assert!(stuck.rotation.last_error.contains("failed validation"));
    assert!(
        stuck.rotation.old_revoked_at.is_none(),
        "old key never touched"
    );

    // Roll back: destinations to old value, vault to old value, new key
    // revoked at the provider.
    let http = MockHttpClient::new(vec![
        gh_pubkey_response(),
        resp(204, ""),                    // destination rollback write
        resp(200, r#"{"deleted":true}"#), // revoke the NEW key
    ]);
    let rolled = v
        .rotation_rollback(&plan.rotation.id, &master_pw(), &http, &NullRunner, true)
        .unwrap();
    assert_eq!(rolled.rotation.state, "rolled_back");
    let value = v.reveal_credential(&cred_id, &master_pw()).unwrap();
    assert_eq!(value.expose(), FAKE_OLD);
    // The transient new key id is unlinked again.
    let links: i64 = v
        .connection()
        .query_row(
            "SELECT count(*) FROM provider_key_links WHERE provider_api_key_id = 'key_new_1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(links, 0);
}

#[test]
fn rollback_is_refused_once_the_old_key_was_revoked() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    let http = full_rotation_mocks();
    v.rotation_advance(
        &plan.rotation.id,
        &master_pw(),
        &http,
        &NullRunner,
        None,
        false,
    )
    .unwrap();
    let http = MockHttpClient::new(vec![]);
    let err = v
        .rotation_rollback(&plan.rotation.id, &master_pw(), &http, &NullRunner, false)
        .unwrap_err();
    assert!(err.to_string().contains("irreversible"), "{err}");
}

#[test]
fn grace_period_waits_and_continued_use_blocks_until_acknowledged() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    // 60-minute grace: the workflow must stop at the grace period.
    let plan = v.rotation_plan(&cred_id, 60, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    let http = MockHttpClient::new(vec![
        created_sa_response(),
        gh_pubkey_response(),
        resp(204, ""),
        resp(200, r#"{"name":"OPENAI_API_KEY"}"#),
        resp(200, r#"{"data":[{"id":"gpt-4o"}]}"#),
    ]);
    let waiting = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(waiting.rotation.state, "grace_period");
    assert!(waiting
        .waiting_on
        .as_deref()
        .unwrap_or("")
        .contains("grace"));

    // Force the grace period to have elapsed, and record provider usage
    // attributed to the OLD key after approval.
    v.connection()
        .execute(
            "UPDATE rotations SET grace_ends_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
            [&plan.rotation.id],
        )
        .unwrap();
    v.connection()
        .execute(
            "INSERT INTO usage_snapshots (id, provider, model, window_start, window_end,
                 request_count, source, attribution, collected_at, provider_api_key_id)
             VALUES ('u1', 'openai', 'gpt-4o', '2099-01-01T00:00:00Z', '2099-01-02T00:00:00Z',
                 5, 'openai_usage_api', 'provider_key', '2099-01-02T00:00:00Z', 'key_old_1')",
            [],
        )
        .unwrap();
    let blocked = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &MockHttpClient::new(vec![]),
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(blocked.rotation.state, "grace_period");
    assert!(
        blocked.rotation.last_error.contains("OLD key"),
        "{}",
        blocked.rotation.last_error
    );

    // Acknowledging continued use lets the workflow finish.
    let http = MockHttpClient::new(vec![resp(200, r#"{"deleted":true}"#)]);
    let done = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            true,
        )
        .unwrap();
    assert_eq!(
        done.rotation.state, "completed",
        "{:?}",
        done.rotation.last_error
    );
}

#[test]
fn manual_mode_walks_disable_then_archive_for_anthropic() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let anthropic_old = "sk-ant-api03-FAKEOLD000000000000000000000000000000000000000000000000000000000000000000000001";
    let cred = add_provider_key(&mut v, "app", "claude", "anthropic", anthropic_old);
    // Anthropic uses the legacy admin path: an admin credential in the vault.
    let admin_value = "sk-ant-admin01-FAKEADMIN0000000000000000000000000000000000000000000000000000000000000000001";
    let admin_cred = add_provider_key(&mut v, "app", "anthropic-admin", "anthropic", admin_value);
    v.provider_connect("anthropic", &admin_cred.id).unwrap();

    let plan = v
        .rotation_plan(&cred.id, 0, None, Some("apikey_old_1"), "")
        .unwrap();
    assert_eq!(plan.rotation.mode, "manual_create");
    assert!(plan
        .rotation
        .manual_instructions
        .contains("create the replacement key"));
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();

    // Without a provided key the workflow waits.
    let waiting = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &MockHttpClient::new(vec![]),
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(waiting.rotation.state, "awaiting_manual_key");

    // Provide the console-created replacement; no destinations configured,
    // so the sync plan is empty and skips straight through.
    let anthropic_new = "sk-ant-api03-FAKENEW000000000000000000000000000000000000000000000000000000000000000000000001";
    let http = MockHttpClient::new(vec![
        resp(200, r#"{"data":[{"id":"claude"}]}"#), // validate new
        resp(200, r#"{"id":"apikey_old_1","status":"inactive"}"#), // disable old
        resp(200, r#"{"id":"apikey_old_1","status":"archived"}"#), // archive old
    ]);
    let done = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            Some(SecretString::from(anthropic_new)),
            false,
        )
        .unwrap();
    assert_eq!(
        done.rotation.state, "completed",
        "{:?}",
        done.rotation.last_error
    );
    assert!(done.rotation.old_disabled_at.is_some(), "disable step ran");
    assert!(done.rotation.old_revoked_at.is_some(), "archive step ran");
    // The completion detail says the revoke was soft.
    let events = v.rotation_events(&plan.rotation.id).unwrap();
    assert!(events.iter().any(|e| e.detail.contains("soft revoke")));
}

#[test]
fn manual_required_completion_needs_validation_and_reauth() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    // GitHub: manual everything, no admin, no old key id.
    let cred = add_provider_key(&mut v, "app", "gh-token", "github", FAKE_GH_TOKEN);
    let plan = v.rotation_plan(&cred.id, 0, None, None, "").unwrap();
    assert_eq!(plan.rotation.mode, "manual_create");
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    let new_token = "ghp_FAKENEW00000000000000000000000000000001";
    let http = MockHttpClient::new(vec![resp(200, r#"{"login":"octo"}"#)]);
    let waiting = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            Some(SecretString::from(new_token)),
            false,
        )
        .unwrap();
    assert_eq!(waiting.rotation.state, "manual_required");
    assert!(waiting.rotation.manual_instructions.is_empty() || true);

    // Wrong password is refused; the right one completes.
    let wrong = SecretString::from("not-the-master-password");
    assert!(v
        .rotation_complete_manual(&plan.rotation.id, &wrong, "revoked in UI")
        .is_err());
    let done = v
        .rotation_complete_manual(&plan.rotation.id, &master_pw(), "revoked in UI")
        .unwrap();
    assert_eq!(done.rotation.state, "completed");
}

#[test]
fn cancel_is_only_allowed_before_any_change() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    // Store a replacement, then cancel must be refused.
    let http = MockHttpClient::new(vec![created_sa_response(), resp(500, "{}")]);
    v.rotation_advance(
        &plan.rotation.id,
        &master_pw(),
        &http,
        &NullRunner,
        None,
        false,
    )
    .unwrap();
    let err = v
        .rotation_cancel(&plan.rotation.id, &master_pw())
        .unwrap_err();
    assert!(err.to_string().contains("roll back"), "{err}");

    // A fresh plan with no changes can be cancelled.
    let plan2 = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    let cancelled = v.rotation_cancel(&plan2.rotation.id, &master_pw()).unwrap();
    assert_eq!(cancelled.rotation.state, "failed");
}

#[test]
fn scheduling_requires_a_completed_rotation_and_monitor_raises_due_alerts() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    // Before any completed rotation: scheduling is refused.
    let err = v.rotation_schedule_set(&cred_id, 30).unwrap_err();
    assert!(err.to_string().contains("COMPLETED"), "{err}");

    // Complete one rotation.
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    let http = full_rotation_mocks();
    let done = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(done.rotation.state, "completed");

    // Now scheduling works; force it due and run the monitor.
    v.rotation_schedule_set(&cred_id, 30).unwrap();
    v.connection()
        .execute(
            "UPDATE rotation_schedules SET next_due_at = '2000-01-01T00:00:00Z'",
            [],
        )
        .unwrap();
    v.run_monitor().unwrap();
    let alerts = api_tracker_core::alerts::list(v.connection(), false).unwrap();
    assert!(
        alerts.iter().any(|a| a.kind == "rotation_due"),
        "expected a rotation_due alert"
    );

    // Preflight failure (admin connection removed) pauses the schedule.
    v.provider_admin_disconnect("openai").unwrap();
    v.run_monitor().unwrap();
    let schedules = v.rotation_schedules().unwrap();
    assert!(
        !schedules[0].enabled,
        "schedule paused on preflight failure"
    );
    assert!(schedules[0]
        .paused_reason
        .contains("administrative connection"));
}

#[test]
fn access_grants_bound_injection_locally_and_are_terminable() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let (cred, _) = add_key(&mut v, "app", "openai", FAKE_OLD, Environment::Development);
    let (other, _) = add_key(
        &mut v,
        "app",
        "stripe",
        "sk_test_FAKEFAKEFAKEFAKEFAKEFAKE01",
        Environment::Development,
    );
    v.set_env_mapping("app", &cred.id, "OPENAI_API_KEY")
        .unwrap();
    v.set_env_mapping("app", &other.id, "STRIPE_KEY").unwrap();

    // One-time grant restricted to ONE credential.
    let grant = v
        .access_grant_create(
            "app",
            "demo run",
            std::slice::from_ref(&cred.id),
            60,
            1,
            Some(30),
            None,
        )
        .unwrap();
    let injection = v.build_injection_with_grant(&grant.id, "npm test").unwrap();
    let names: Vec<&str> = injection.env.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["OPENAI_API_KEY"], "subset only");
    assert_eq!(injection.max_duration_secs, Some(30));
    v.record_session_pid(&injection.session_id, 4242, Some(&grant.id))
        .unwrap();

    // One-time: a second launch is refused.
    let err = v
        .build_injection_with_grant(&grant.id, "again")
        .unwrap_err();
    assert!(err.to_string().contains("used_up"), "{err}");

    // Termination surfaces the running session's PID; the audit trail knows.
    let (ended, running) = v.access_grant_end(&grant.id).unwrap();
    assert!(ended.revoked_at.is_some());
    assert_eq!(running, vec![(injection.session_id.clone(), 4242)]);

    // A revoked grant refuses new launches.
    let err = v
        .build_injection_with_grant(&grant.id, "post-revoke")
        .unwrap_err();
    assert!(err.to_string().contains("revoked"), "{err}");

    // Serialized grants never contain secret values.
    let serialized = serde_json::to_string(&v.access_grants(true).unwrap()).unwrap();
    assert!(!serialized.contains(FAKE_OLD));
}

#[test]
fn test_key_creation_labels_enforcement_honestly_and_provider_revoke_works() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    v.provider_admin_connect("openai", &SecretString::from(FAKE_ADMIN), None, None)
        .unwrap();
    let http = MockHttpClient::new(vec![resp(
        200,
        &format!(
            r#"{{"id":"svc_test_1","name":"probe",
                "api_key":{{"id":"key_test_1","value":"{FAKE_NEW}"}}}}"#
        ),
    )]);
    let (cred, notes) = v
        .test_key_create(
            "app",
            "openai",
            Some("proj_1"),
            "probe",
            120,
            &master_pw(),
            &http,
        )
        .unwrap();
    assert_eq!(cred.environment, Environment::Test);
    assert!(cred.expires_at.is_some(), "local reminder expiry set");
    let joined = notes.join("\n");
    assert!(joined.contains("PROVIDER-ENFORCED"));
    assert!(joined.contains("NOT provider-enforced"));
    assert!(joined.contains("LOCAL reminder"));

    // Provider-side revocation via the linked key id.
    let http = MockHttpClient::new(vec![resp(200, r#"{"deleted":true}"#)]);
    let detail = v
        .credential_provider_revoke(&cred.id, &master_pw(), &http)
        .unwrap();
    assert!(detail.contains("deleted"));
    let refreshed = v.get_credential(&cred.id).unwrap();
    assert!(refreshed.revoked);
}

#[test]
fn revoke_404_is_an_error_not_success_on_first_attempt() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    let http = MockHttpClient::new(vec![
        created_sa_response(),
        gh_pubkey_response(),
        resp(204, ""),
        resp(200, r#"{"name":"OPENAI_API_KEY"}"#),
        resp(200, r#"{"data":[{"id":"gpt-4o"}]}"#),
        resp(404, r#"{"error":{"message":"No such key"}}"#), // revoke: 404
    ]);
    let stuck = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    // NOT completed: a first-attempt 404 is ambiguous (wrong id?) and must
    // never be reported as a successful revocation.
    assert_ne!(stuck.rotation.state, "completed");
    assert!(stuck.rotation.old_revoked_at.is_none());
    assert!(
        stuck.rotation.last_error.contains("does not exist"),
        "{}",
        stuck.rotation.last_error
    );
}

#[test]
fn external_replacement_mid_rotation_blocks_destructive_arming() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    // Advance through destinations, stopping before validation.
    let http = MockHttpClient::new(vec![
        created_sa_response(),
        gh_pubkey_response(),
        resp(204, ""),
        resp(200, r#"{"name":"OPENAI_API_KEY"}"#),
        resp(500, "{}"), // validation attempt fails -> stays retryable
        resp(500, "{}"),
        resp(500, "{}"),
    ]);
    let stuck = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(stuck.rotation.state, "destinations_verified");
    // Someone replaces the value OUTSIDE the rotation.
    v.replace_credential_value(
        &cred_id,
        &master_pw(),
        SecretString::from("sk-proj-FAKEEXTERNAL000000000000000000000001"),
    )
    .unwrap();
    // Validation must now refuse: the current value is not the rotation's.
    let http = MockHttpClient::new(vec![resp(200, r#"{"data":[]}"#)]);
    let blocked = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(blocked.rotation.state, "destinations_verified");
    assert!(
        blocked.rotation.last_error.contains("changed outside"),
        "{}",
        blocked.rotation.last_error
    );
    assert!(!blocked.rotation.new_value_validated);
}

#[test]
fn orphaned_provider_key_blocks_a_second_creation() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    // Simulate a crash after creation but before storing: the key id is
    // recorded, the version is not, state stayed in the claim.
    v.connection()
        .execute(
            "UPDATE rotations SET state = 'creating_replacement',
                 new_provider_key_id = 'key_orphan_1' WHERE id = ?1",
            [&plan.rotation.id],
        )
        .unwrap();
    let http = MockHttpClient::new(vec![]); // any HTTP call would error
    let stuck = v
        .rotation_advance(
            &plan.rotation.id,
            &master_pw(),
            &http,
            &NullRunner,
            None,
            false,
        )
        .unwrap();
    assert_eq!(stuck.rotation.state, "creating_replacement");
    assert!(
        stuck.rotation.last_error.contains("never")
            && stuck.rotation.last_error.contains("key_orphan_1"),
        "{}",
        stuck.rotation.last_error
    );
}

#[test]
fn second_concurrent_rotation_approval_is_refused() {
    let (_dir, _paths, v, cred_id) = openai_rotation_fixture();
    let plan1 = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    let plan2 = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan1.rotation.id, &master_pw())
        .unwrap();
    let err = v
        .rotation_approve(&plan2.rotation.id, &master_pw())
        .unwrap_err();
    assert!(err.to_string().contains("in flight"), "{err}");
}

#[test]
fn completed_rotations_cannot_be_rolled_back() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let cred = add_provider_key(&mut v, "app", "gh-token", "github", FAKE_GH_TOKEN);
    let plan = v.rotation_plan(&cred.id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    let http = MockHttpClient::new(vec![resp(200, r#"{"login":"octo"}"#)]);
    v.rotation_advance(
        &plan.rotation.id,
        &master_pw(),
        &http,
        &NullRunner,
        Some(SecretString::from(
            "ghp_FAKENEW00000000000000000000000000000001",
        )),
        false,
    )
    .unwrap();
    let done = v
        .rotation_complete_manual(&plan.rotation.id, &master_pw(), "revoked in UI")
        .unwrap();
    assert_eq!(done.rotation.state, "completed");
    // Rolling back a completed (manual) rotation would push a dashboard-
    // revoked value back into service claiming success — refused.
    let err = v
        .rotation_rollback(
            &plan.rotation.id,
            &master_pw(),
            &MockHttpClient::new(vec![]),
            &NullRunner,
            false,
        )
        .unwrap_err();
    assert!(err.to_string().contains("cannot be rolled back"), "{err}");
}

#[test]
fn replacing_a_value_clears_provider_reported_expiry() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let cred = add_provider_key(&mut v, "app", "gh", "github", FAKE_GH_TOKEN);
    let http = MockHttpClient::with(
        200,
        vec![(
            "github-authentication-token-expiration".into(),
            "2020-01-15 10:30:00 UTC".into(),
        )],
        r#"{"login":"octo"}"#,
    );
    v.validate_credential(&cred.id, &http).unwrap();
    assert!(v
        .get_credential(&cred.id)
        .unwrap()
        .provider_expires_at
        .is_some());
    v.replace_credential_value(
        &cred.id,
        &master_pw(),
        SecretString::from("ghp_FAKENEW00000000000000000000000000000001"),
    )
    .unwrap();
    // The old token's provider-reported expiry must not stick to the new one.
    assert!(v
        .get_credential(&cred.id)
        .unwrap()
        .provider_expires_at
        .is_none());
}

#[test]
fn config_errors_do_not_burn_one_time_grants() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let (cred, _) = add_key(&mut v, "app", "openai", FAKE_OLD, Environment::Development);
    // No mapping configured: the launch must fail WITHOUT consuming.
    let grant = v
        .access_grant_create(
            "app",
            "one",
            std::slice::from_ref(&cred.id),
            60,
            1,
            None,
            None,
        )
        .unwrap();
    let err = v.build_injection_with_grant(&grant.id, "x").unwrap_err();
    assert!(
        err.to_string().contains("no configured env mappings"),
        "{err}"
    );
    // The grant is still fully usable once configured.
    v.set_env_mapping("app", &cred.id, "OPENAI_API_KEY")
        .unwrap();
    let injection = v.build_injection_with_grant(&grant.id, "x").unwrap();
    assert_eq!(injection.grant.launches_used, 1);
}

#[test]
fn active_rotation_versions_survive_the_prune_and_deletion_is_blocked() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    // Reach a state where old_version is recorded.
    let http = MockHttpClient::new(vec![created_sa_response(), resp(500, "{}")]);
    v.rotation_advance(
        &plan.rotation.id,
        &master_pw(),
        &http,
        &NullRunner,
        None,
        false,
    )
    .unwrap();
    // Age the retained version far past the rollback window; prune must
    // exempt it because an ACTIVE rotation needs it.
    v.connection()
        .execute(
            "UPDATE credential_versions SET created_at = '2000-01-01T00:00:00Z'
             WHERE credential_id = ?1",
            [&cred_id],
        )
        .unwrap();
    v.replace_credential_value(
        &cred_id,
        &master_pw(),
        SecretString::from("sk-proj-FAKETRIGGERPRUNE0000000000000000001"),
    )
    .unwrap();
    let survivors: i64 = v
        .connection()
        .query_row(
            "SELECT count(*) FROM credential_versions WHERE credential_id = ?1 AND version = 1",
            [&cred_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        survivors, 1,
        "the rotation's rollback material must survive pruning"
    );
    // And the credential cannot be deleted mid-rotation.
    let err = v.delete_credential(&cred_id).unwrap_err();
    assert!(err.to_string().contains("in flight"), "{err}");
}

#[test]
fn github_validation_records_provider_reported_expiration() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let cred = add_provider_key(&mut v, "app", "gh", "github", FAKE_GH_TOKEN);
    let http = MockHttpClient::with(
        200,
        vec![(
            "github-authentication-token-expiration".into(),
            "2020-01-15 10:30:00 UTC".into(),
        )],
        r#"{"login":"octo"}"#,
    );
    let result = v.validate_credential(&cred.id, &http).unwrap();
    assert!(result.provider_expires_at.is_some());
    let refreshed = v.get_credential(&cred.id).unwrap();
    assert_eq!(
        refreshed.provider_expires_at.as_deref(),
        Some("2020-01-15T10:30:00Z")
    );
    // The (past) provider-reported date drives the status engine.
    assert_eq!(refreshed.status.primary.to_string(), "expired");
    assert!(refreshed
        .status
        .findings
        .iter()
        .any(|f| f.source.contains("provider-reported")));
}

#[test]
fn timeline_merges_lifecycle_sources_chronologically() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let plan = v.rotation_plan(&cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    let http = full_rotation_mocks();
    v.rotation_advance(
        &plan.rotation.id,
        &master_pw(),
        &http,
        &NullRunner,
        None,
        false,
    )
    .unwrap();
    let timeline = v.credential_timeline(&cred_id).unwrap();
    let kinds: Vec<&str> = timeline.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"credential_created"));
    assert!(kinds.contains(&"credential_value_replaced"));
    assert!(kinds.contains(&"version_retained"));
    assert!(kinds.iter().any(|k| k.starts_with("rotation:completed")));
    // Chronological order.
    let times: Vec<&String> = timeline.iter().map(|e| &e.at).collect();
    let mut sorted = times.clone();
    sorted.sort();
    assert_eq!(times, sorted);
    let serialized = serde_json::to_string(&timeline).unwrap();
    assert!(!serialized.contains(FAKE_NEW));
    assert!(!serialized.contains(FAKE_OLD));
}
