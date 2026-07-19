//! DEST-01 / DEST-03 vault-level regression: drift results and sync-step
//! verification must be truthful. Provider/transport failures are never
//! converted into "missing"; unqueryable destinations are explicit; a step
//! whose verification failed is never stamped verified.
//!
//! All network traffic goes through `MockHttpClient`; no real destination
//! is ever contacted; all credentials are unmistakably fake.

mod common;

use api_tracker_core::destinations::CommandRunner;
use api_tracker_core::http::{HttpResponse, MockHttpClient};
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use common::{add_key, add_project, master_pw, new_vault};

const FAKE_STRIPE: &str = "sk_test_FAKEFAKEFAKEFAKEFAKEFAKE01";

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

fn status_response(status: u16) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![],
        body: b"{}".to_vec(),
    }
}

/// Vault + credential attached to a GitHub Actions destination (existence-
/// only verification), ready for drift checks.
fn github_setup() -> (
    tempfile::TempDir,
    api_tracker_core::vault::VaultPaths,
    api_tracker_core::vault::UnlockedVault,
    api_tracker_core::model::Credential,
) {
    let (dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "stripe",
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
    (dir, paths, vault, cred)
}

#[test]
fn auth_error_during_drift_is_unknown_never_missing_and_not_verified() {
    let (_dir, _paths, vault, cred) = github_setup();
    // GitHub drift: read() is write-only (no HTTP), exists() GETs → 401.
    let http = MockHttpClient::new(vec![status_response(401)]);
    let outcomes = vault
        .destination_drift_check(Some(&cred.id), &http, &NullRunner)
        .unwrap();
    assert_eq!(outcomes.len(), 1);
    let a = &outcomes[0];
    assert!(
        a.checked,
        "an auth failure still counts as a completed check attempt"
    );
    assert_eq!(
        a.attachment.drift, "unknown",
        "an auth failure must be UNKNOWN, never 'missing' (DEST-01)"
    );
    assert!(
        a.attachment.last_verified_at.is_none(),
        "an unverifiable check must not stamp last_verified_at"
    );
}

#[test]
fn transport_failure_during_drift_is_unknown_never_missing() {
    let (_dir, _paths, vault, cred) = github_setup();
    let http = MockHttpClient::with_network_failures(1, vec![]);
    let outcomes = vault
        .destination_drift_check(Some(&cred.id), &http, &NullRunner)
        .unwrap();
    assert_eq!(outcomes[0].attachment.drift, "unknown");
    assert!(outcomes[0].attachment.last_verified_at.is_none());
}

#[test]
fn definitive_absence_is_missing_and_verified() {
    let (_dir, _paths, vault, cred) = github_setup();
    let http = MockHttpClient::new(vec![HttpResponse {
        status: 404,
        headers: vec![],
        body: Vec::new(),
    }]);
    let outcomes = vault
        .destination_drift_check(Some(&cred.id), &http, &NullRunner)
        .unwrap();
    assert_eq!(
        outcomes[0].attachment.drift, "missing",
        "a definitive 404 IS absence — that verdict must be kept"
    );
    assert!(
        outcomes[0].attachment.last_verified_at.is_some(),
        "a definitive verdict is a real verification"
    );
}

#[test]
fn failed_check_preserves_prior_drift_verdict_history() {
    // First check: definitive missing (verified). Second check: 500 error.
    // The second check must not erase the fact that the first one verified,
    // and must not present the old verdict as newly verified.
    let (_dir, _paths, vault, cred) = github_setup();
    let http = MockHttpClient::new(vec![HttpResponse {
        status: 404,
        headers: vec![],
        body: Vec::new(),
    }]);
    let first = vault
        .destination_drift_check(Some(&cred.id), &http, &NullRunner)
        .unwrap();
    let first_verified = first[0]
        .attachment
        .last_verified_at
        .clone()
        .expect("verified");

    let http = MockHttpClient::new(vec![status_response(500)]);
    let second = vault
        .destination_drift_check(Some(&cred.id), &http, &NullRunner)
        .unwrap();
    assert_eq!(second[0].attachment.drift, "unknown");
    assert_eq!(
        second[0].attachment.last_verified_at.as_deref(),
        Some(first_verified.as_str()),
        "a failed check must not advance last_verified_at"
    );
}

#[test]
fn sync_step_is_never_verified_when_existence_check_fails() {
    // The write succeeds, but the verification GET returns 401: the step
    // must NOT be stamped verified, and the plan must not report clean
    // execution.
    let (_dir, _paths, mut vault, cred) = github_setup();
    let v2 = "sk_test_FAKEFAKEFAKEFAKEFAKEFAKE02";
    vault
        .replace_credential_value(&cred.id, &master_pw(), SecretString::from(v2))
        .unwrap();
    let plan = vault.sync_plan_create(&cred.id, "").unwrap();

    use base64::Engine;
    let pk = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let http = MockHttpClient::new(vec![
        MockHttpClient::json_response(&format!(r#"{{"key_id":"k1","key":"{pk}"}}"#)),
        HttpResponse {
            status: 204,
            headers: vec![],
            body: Vec::new(),
        },
        status_response(401), // verification GET fails
    ]);
    let result = vault.sync_plan_execute(&plan.id, None, &master_pw(), &http, &NullRunner);

    let stored = vault.sync_plan_get(&plan.id).unwrap();
    let step = &stored.steps[0];
    assert!(
        step.verified_at.is_none(),
        "a step whose verification failed must never be stamped verified \
         (got verified_at={:?}, execute result ok={})",
        step.verified_at,
        result.is_ok()
    );
    assert_ne!(
        stored.status, "executed",
        "the plan must not present itself as cleanly executed"
    );
}
