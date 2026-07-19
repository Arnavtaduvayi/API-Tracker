//! ROT-001 / ROT-010 regression: an ambiguous revoke outcome must converge
//! to a truthful terminal or manual-recovery state — never falsely restore a
//! deleted key, falsely claim revocation, or permanently wedge the rotation.
//!
//! Scenarios (all mocked; no live provider):
//! - revoke succeeds but the response is LOST (transport error), retry 404
//!   → completes (the buried attempt marker is recovered; the key is gone).
//! - crash after `old_revoked_at` is persisted, before completion
//!   → restart completes idempotently (no second revoke call).
//! - a first 404 with NO prior attempt (genuine wrong-key ambiguity)
//!   → routed to manual_required, never a false success; manual completion
//!   converges.
//! - permanent-delete provider (OpenAI): rollback after a revoke ATTEMPT is
//!   refused so it cannot redeploy a likely-deleted key.
//!
//! At baseline `7d81090`: the lost-response case wedges OLD_DISABLED forever
//! (the marker is buried, so the retried 404 is refused as "wrong key id"),
//! and the only exit — rollback — restores the deleted key and reports a
//! clean ROLLED_BACK. Deterministic control-flow evidence:
//! ../API-Tracker-deep-audit/docs/audits/evidence/ROT-001_RESOLUTION.md.

mod common;

use api_tracker_core::destinations::CommandRunner;
use api_tracker_core::error::{CoreError, Result};
use api_tracker_core::http::{HttpClient, HttpRequest, HttpResponse, MockHttpClient};
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, UnlockedVault, VaultPaths};
use common::{add_key, add_project, master_pw, new_vault};
use std::cell::RefCell;
use std::collections::VecDeque;

const FAKE_OLD: &str = "sk-proj-FAKEOLD0000000000000000000000000001";
const FAKE_NEW: &str = "sk-svcacct-FAKENEW00000000000000000000000001";
const FAKE_ADMIN: &str = "sk-admin-FAKE0000000000000000000000000000001";
const FAKE_GH_TOKEN: &str = "ghp_FAKE0000000000000000000000000000000000";

struct NullRunner;
impl CommandRunner for NullRunner {
    fn run(&self, _p: &str, _a: &[&str], _s: Option<&[u8]>) -> Result<(i32, Vec<u8>, Vec<u8>)> {
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

/// One scripted outcome for a single HTTP send.
enum Step {
    Reply(HttpResponse),
    /// A lost/failed response: the provider may have acted, but we get a
    /// transport error (the ROT-001 trigger).
    NetworkError,
}

/// An HTTP client that serves a fixed script of replies and transport errors
/// in order — lets a test place a NetworkError exactly on the revoke send.
struct ScriptedHttp {
    steps: RefCell<VecDeque<Step>>,
}

impl ScriptedHttp {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: RefCell::new(steps.into()),
        }
    }
}

impl HttpClient for ScriptedHttp {
    fn send(&self, _req: &HttpRequest) -> Result<HttpResponse> {
        match self.steps.borrow_mut().pop_front() {
            Some(Step::Reply(r)) => Ok(r),
            Some(Step::NetworkError) => {
                Err(CoreError::Network("mock: simulated lost response".into()))
            }
            None => Err(CoreError::InvalidInput(
                "mock: no more scripted steps".into(),
            )),
        }
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

fn gh_pubkey_response() -> HttpResponse {
    use base64::Engine;
    let pk = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    resp(200, &format!(r#"{{"key_id":"k1","key":"{pk}"}}"#))
}

/// The five successful pre-revoke steps (create → destinations → validate).
fn pre_revoke_steps() -> Vec<Step> {
    vec![
        Step::Reply(created_sa_response()),
        Step::Reply(gh_pubkey_response()),
        Step::Reply(resp(204, "")),
        Step::Reply(resp(200, r#"{"name":"OPENAI_API_KEY"}"#)),
        Step::Reply(resp(200, r#"{"data":[{"id":"gpt-4o"}]}"#)),
    ]
}

fn openai_rotation_fixture() -> (tempfile::TempDir, VaultPaths, UnlockedVault, String) {
    let (dir, paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let (cred, _) = add_key(
        &mut v,
        "app",
        "openai-main",
        FAKE_OLD,
        Environment::Production,
    );
    v.provider_admin_connect("openai", &SecretString::from(FAKE_ADMIN), Some("org"), None)
        .unwrap();
    v.connection()
        .execute(
            "INSERT INTO provider_side_keys (provider, api_key_id, provider_project_id, name,
                 redacted_value, synced_at)
             VALUES ('openai','key_old_1','proj_1','old','sk-...0001','2026-07-01T00:00:00Z')",
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

fn approved_rotation(v: &mut UnlockedVault, cred_id: &str) -> String {
    let plan = v.rotation_plan(cred_id, 0, None, None, "").unwrap();
    v.rotation_approve(&plan.rotation.id, &master_pw()).unwrap();
    plan.rotation.id
}

fn advance(v: &mut UnlockedVault, id: &str, http: &dyn HttpClient) -> vault::RotationView {
    v.rotation_advance(id, &master_pw(), http, &NullRunner, None, false)
        .unwrap()
}

#[test]
fn lost_revoke_response_then_404_converges_to_completed() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let id = approved_rotation(&mut v, &cred_id);

    // Advance to the revoke, whose send is a LOST response (transport error):
    // the provider may have deleted the key, but we never saw the reply.
    let mut steps = pre_revoke_steps();
    steps.push(Step::NetworkError);
    let stuck = advance(&mut v, &id, &ScriptedHttp::new(steps));
    assert_eq!(
        stuck.rotation.state, "old_disabled",
        "{:?}",
        stuck.rotation.last_error
    );
    assert!(stuck.rotation.old_revoked_at.is_none());

    // Retry: the provider now answers 404 (key already gone). The buried
    // attempt marker is recovered (full-log scan), so this is a completed
    // retry — not a false "wrong key id" refusal that would wedge forever.
    let http = MockHttpClient::new(vec![resp(404, r#"{"error":{"message":"No such key"}}"#)]);
    let done = advance(&mut v, &id, &http);
    assert_eq!(
        done.rotation.state, "completed",
        "{:?}",
        done.rotation.last_error
    );
    assert!(done.rotation.old_revoked_at.is_some());
    let events = v.rotation_events(&id).unwrap();
    assert!(events.iter().any(|e| e.detail.contains("completed retry")));
}

#[test]
fn crash_after_old_revoked_at_completes_on_restart_without_recalling_revoke() {
    let (_dir, paths, mut v, cred_id) = openai_rotation_fixture();
    let id = approved_rotation(&mut v, &cred_id);

    // Drive to OLD_DISABLED with the revoke send lost (so we stop there),
    // then simulate the crash window: old_revoked_at is persisted but the
    // state never advanced to completed.
    let mut steps = pre_revoke_steps();
    steps.push(Step::NetworkError);
    let stuck = advance(&mut v, &id, &ScriptedHttp::new(steps));
    assert_eq!(stuck.rotation.state, "old_disabled");
    v.connection()
        .execute(
            "UPDATE rotations SET old_revoked_at = ?1 WHERE id = ?2",
            rusqlite::params!["2026-07-19T00:00:00Z", id],
        )
        .unwrap();

    // "Restart" from disk.
    drop(v);
    let mut v = vault::unlock_vault(&paths, &master_pw()).unwrap();

    // The next advance must NOT call revoke again (a permanent-delete provider
    // would 404 and wedge). The mock has NO revoke response queued; a second
    // call would error. Idempotent completion instead.
    let http = MockHttpClient::new(vec![]);
    let done = advance(&mut v, &id, &http);
    assert_eq!(
        done.rotation.state, "completed",
        "{:?}",
        done.rotation.last_error
    );
    let events = v.rotation_events(&id).unwrap();
    assert!(events
        .iter()
        .any(|e| e.detail.contains("already revoked (recovered)")));
}

#[test]
fn first_404_without_attempt_routes_to_manual_required_and_completes() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let id = approved_rotation(&mut v, &cred_id);

    // A clean first attempt that gets a 404 (no prior attempt marker) — a
    // wrong key id would look identical, so it must not be a false success.
    let mut steps = pre_revoke_steps();
    steps.push(Step::Reply(resp(
        404,
        r#"{"error":{"message":"No such key"}}"#,
    )));
    let routed = advance(&mut v, &id, &ScriptedHttp::new(steps));
    assert_eq!(routed.rotation.state, "manual_required");
    assert!(routed.rotation.old_revoked_at.is_none());

    // The rotation is NOT wedged: manual completion (reauth) converges.
    let done = v
        .rotation_complete_manual(&id, &master_pw(), "verified old key gone in console")
        .unwrap();
    assert_eq!(done.rotation.state, "completed");
}

#[test]
fn rollback_after_revoke_attempt_on_permanent_delete_provider_is_refused() {
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let id = approved_rotation(&mut v, &cred_id);

    // Reach OLD_DISABLED with the revoke send lost: a revoke was ATTEMPTED
    // against OpenAI (permanent delete), so the old key may already be gone.
    let mut steps = pre_revoke_steps();
    steps.push(Step::NetworkError);
    let stuck = advance(&mut v, &id, &ScriptedHttp::new(steps));
    assert_eq!(stuck.rotation.state, "old_disabled");
    assert!(stuck.rotation.old_revoked_at.is_none());

    // Rollback must refuse: restoring the old key could redeploy a dead
    // credential and misreport a clean rollback.
    let http = MockHttpClient::new(vec![]);
    let err = v
        .rotation_rollback(&id, &master_pw(), &http, &NullRunner, false)
        .unwrap_err();
    match err {
        CoreError::InvalidInput(m) => {
            assert!(m.contains("permanently DELETES"), "{m}");
            assert!(m.contains("dead credential"), "{m}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // The rotation is untouched by the refused rollback (still recoverable
    // forward via complete-manual).
    let after = v.rotation_get(&id).unwrap();
    assert_eq!(after.rotation.state, "old_disabled");
}

#[test]
fn rollback_before_any_revoke_attempt_is_still_allowed() {
    // The permanent-delete guard must not block a legitimate rollback taken
    // BEFORE any revoke was attempted (the old key is untouched).
    let (_dir, _paths, mut v, cred_id) = openai_rotation_fixture();
    let id = approved_rotation(&mut v, &cred_id);

    // Advance with destinations executed but validation failing, so the
    // rotation stops at destinations_verified — destinations WERE executed
    // (so there is something to roll back) but no revoke was ever attempted.
    let http = MockHttpClient::new(vec![
        created_sa_response(),
        gh_pubkey_response(),
        resp(204, ""),
        resp(200, r#"{"name":"OPENAI_API_KEY"}"#),
        resp(401, r#"{"error":{"code":"invalid_api_key"}}"#), // validation fails
    ]);
    let stuck = advance(&mut v, &id, &http);
    assert_eq!(stuck.rotation.state, "destinations_verified");
    assert!(v
        .rotation_get(&id)
        .unwrap()
        .rotation
        .old_revoked_at
        .is_none());

    // No revoke was ever attempted, so the permanent-delete guard must NOT
    // fire: rollback proceeds (restores the old value/destinations, then
    // revokes the new key).
    let http = MockHttpClient::new(vec![
        gh_pubkey_response(),             // destination rollback: public key
        resp(204, ""),                    // destination rollback: write old value
        resp(200, r#"{"deleted":true}"#), // revoke the NEW key
    ]);
    let rolled = v
        .rotation_rollback(&id, &master_pw(), &http, &NullRunner, true)
        .unwrap();
    assert_eq!(
        rolled.rotation.state, "rolled_back",
        "{:?}",
        rolled.rotation.last_error
    );
    // The vault value is back to the original.
    let value = v.reveal_credential(&cred_id, &master_pw()).unwrap();
    assert_eq!(value.expose(), FAKE_OLD);
}
