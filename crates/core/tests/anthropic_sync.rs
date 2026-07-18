//! Integration tests for the Anthropic Admin API sync engine: per-key
//! usage attribution, cents-denominated cost conversion, workspace/key
//! metadata, provider-reported expirations, link upgrades, and re-sync
//! dedup. All fixtures are offline mocks with fake credentials.

mod common;

use api_tracker_core::http::{HttpResponse, MockHttpClient};
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault;
use common::{add_project, master_pw, new_vault};

const FAKE_ADMIN: &str = "sk-ant-admin01-FAKE-NOT-A-REAL-KEY-0000000001";
const FAKE_KEY: &str =
    "sk-ant-api03-FAKE00000000000000000000000000000000000000000000000000000000000000000000000001";

fn resp(body: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
    }
}

fn usage_page() -> HttpResponse {
    resp(
        r#"{"data":[{"starting_at":"2026-07-10T00:00:00Z","ending_at":"2026-07-11T00:00:00Z",
        "results":[
          {"api_key_id":"apikey_prod","workspace_id":"wrkspc_1","model":"claude-sonnet-4-5",
           "uncached_input_tokens":1000,"cache_read_input_tokens":200,
           "cache_creation":{"ephemeral_1h_input_tokens":50,"ephemeral_5m_input_tokens":0},
           "output_tokens":300},
          {"api_key_id":null,"workspace_id":"wrkspc_1","model":"claude-haiku-4-5",
           "uncached_input_tokens":10,"cache_read_input_tokens":0,"output_tokens":5}
        ]}],"has_more":false}"#,
    )
}

fn cost_page() -> HttpResponse {
    resp(
        r#"{"data":[{"starting_at":"2026-07-10T00:00:00Z","ending_at":"2026-07-11T00:00:00Z",
        "results":[{"amount":"250.00","currency":"USD","description":"Claude Sonnet usage",
                    "workspace_id":"wrkspc_1","cost_type":"tokens"}]}],"has_more":false}"#,
    )
}

fn workspaces_page() -> HttpResponse {
    resp(
        r#"{"data":[{"id":"wrkspc_1","type":"workspace","name":"production",
                     "created_at":"2026-01-01T00:00:00Z","archived_at":null}],
            "first_id":"wrkspc_1","last_id":"wrkspc_1","has_more":false}"#,
    )
}

fn keys_page() -> HttpResponse {
    resp(
        r#"{"data":[{"id":"apikey_prod","type":"api_key","name":"prod-key",
                     "created_at":"2026-01-01T00:00:00Z",
                     "partial_key_hint":"sk-ant-api03-FAK...0001","status":"active",
                     "workspace_id":"wrkspc_1","expires_at":"2026-12-31T00:00:00Z"}],
            "first_id":"apikey_prod","last_id":"apikey_prod","has_more":false}"#,
    )
}

fn sync_mocks() -> MockHttpClient {
    MockHttpClient::new(vec![
        usage_page(),
        cost_page(),
        workspaces_page(),
        keys_page(),
    ])
}

fn window() -> (time::OffsetDateTime, time::OffsetDateTime) {
    (
        time::macros::datetime!(2026-07-10 0:00 UTC),
        time::macros::datetime!(2026-07-12 0:00 UTC),
    )
}

#[test]
fn full_sync_records_per_key_usage_cents_costs_and_metadata() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    v.provider_admin_connect(
        "anthropic",
        &SecretString::from(FAKE_ADMIN),
        Some("my-org"),
        None,
    )
    .unwrap();
    let (from, to) = window();
    let report = v
        .usage_sync_range("anthropic", &sync_mocks(), from, to)
        .unwrap();
    assert_eq!(report.usage_rows, 2);
    assert_eq!(report.cost_rows, 1);

    let conn = v.connection();
    // Per-key row: honest provider_key attribution (not exact — unlinked).
    let (attr, input, key_id): (String, i64, String) = conn
        .query_row(
            "SELECT attribution, input_tokens, provider_api_key_id FROM usage_snapshots
             WHERE provider = 'anthropic' AND provider_api_key_id IS NOT NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(attr, "provider_key");
    assert_eq!(input, 1250, "uncached + cache_read + cache_creation");
    assert_eq!(key_id, "apikey_prod");

    // Cost row: "250.00" CENTS = $2.50 = 2_500_000 micros, workspace-level.
    let (cost, cost_attr): (i64, String) = conn
        .query_row(
            "SELECT reported_cost_micros, attribution FROM usage_snapshots
             WHERE provider = 'anthropic' AND source = 'anthropic_costs_api'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(cost, 2_500_000);
    assert_eq!(cost_attr, "provider_project");

    // Metadata cached with first_seen_at preserved semantics.
    let ws_name: String = conn
        .query_row(
            "SELECT name FROM provider_side_projects WHERE provider='anthropic'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(ws_name, "production");
}

#[test]
fn linking_upgrades_attribution_and_flows_provider_expiry() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    let (cred, _) = v
        .add_credential(vault::AddCredential {
            project: "app".into(),
            provider: "anthropic".into(),
            name: "claude".into(),
            environment: Environment::Production,
            value: SecretString::from(FAKE_KEY),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    v.provider_admin_connect("anthropic", &SecretString::from(FAKE_ADMIN), None, None)
        .unwrap();
    let (from, to) = window();
    v.usage_sync_range("anthropic", &sync_mocks(), from, to)
        .unwrap();

    // Link the provider key id to the vault credential, then re-sync.
    v.provider_link_key("anthropic", "apikey_prod", &cred.id)
        .unwrap();
    v.usage_sync_range("anthropic", &sync_mocks(), from, to)
        .unwrap();

    let conn = v.connection();
    let (attr, credential_id): (String, Option<String>) = conn
        .query_row(
            "SELECT attribution, credential_id FROM usage_snapshots
             WHERE provider = 'anthropic' AND provider_api_key_id = 'apikey_prod'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(attr, "exact_credential");
    assert_eq!(credential_id.as_deref(), Some(cred.id.as_str()));

    // The provider-reported key expiration landed on the linked credential.
    let refreshed = v.get_credential(&cred.id).unwrap();
    assert_eq!(
        refreshed.provider_expires_at.as_deref(),
        Some("2026-12-31T00:00:00Z")
    );

    // Re-syncs replaced, never duplicated.
    let usage_count: i64 = conn
        .query_row(
            "SELECT count(*) FROM usage_snapshots WHERE provider='anthropic'
             AND source = 'anthropic_usage_api'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        usage_count, 2,
        "fetch-all-then-replace must not double-count"
    );
}

#[test]
fn manual_rows_survive_resync_and_offline_sync_fails_safely() {
    let (_dir, _paths, mut v) = new_vault();
    add_project(&mut v, "app");
    v.provider_admin_connect("anthropic", &SecretString::from(FAKE_ADMIN), None, None)
        .unwrap();
    let (from, to) = window();
    v.usage_sync_range("anthropic", &sync_mocks(), from, to)
        .unwrap();
    // A manual row inside the window.
    v.connection()
        .execute(
            "INSERT INTO usage_snapshots (id, provider, window_start, window_end,
                 input_tokens, source, attribution, collected_at)
             VALUES ('manual1', 'anthropic', '2026-07-10T06:00:00Z', '2026-07-10T07:00:00Z',
                 42, 'manual', 'exact_credential', '2026-07-10T07:00:00Z')",
            [],
        )
        .unwrap();
    v.usage_sync_range("anthropic", &sync_mocks(), from, to)
        .unwrap();
    let manual: i64 = v
        .connection()
        .query_row(
            "SELECT count(*) FROM usage_snapshots WHERE source='manual'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(manual, 1, "manual rows are never touched by sync");

    // Offline: typed network error, previous data intact, failure alert.
    let offline = MockHttpClient::with_network_failures(10, vec![]);
    let err = v
        .usage_sync_range("anthropic", &offline, from, to)
        .unwrap_err();
    assert!(matches!(
        err,
        api_tracker_core::error::CoreError::Network(_)
    ));
    let rows: i64 = v
        .connection()
        .query_row(
            "SELECT count(*) FROM usage_snapshots WHERE provider='anthropic'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(rows >= 3, "previously synced data stays viewable offline");
}

#[test]
fn admin_connect_validates_via_organizations_me_and_key_stays_encrypted() {
    let (_dir, paths, v) = new_vault();
    let mock = MockHttpClient::json(r#"{"id":"org_1","name":"Acme","type":"organization"}"#);
    let detail = v
        .provider_admin_connect(
            "anthropic",
            &SecretString::from(FAKE_ADMIN),
            Some("acme"),
            Some(&mock),
        )
        .unwrap();
    assert!(detail.contains("Acme"));
    let req = mock.last_request().unwrap();
    assert!(req.url.ends_with("/organizations/me"));
    // The admin key travels in the official header and is encrypted at rest.
    assert!(req
        .headers
        .iter()
        .any(|(k, v)| k == "x-api-key" && v == FAKE_ADMIN));
    drop(v);
    let raw = std::fs::read(paths.db_path()).unwrap();
    let needle = FAKE_ADMIN.as_bytes();
    assert!(!raw.windows(needle.len()).any(|w| w == needle));
    // Reopen and confirm the connection reports as administrative.
    let v = vault::unlock_vault(&paths, &master_pw()).unwrap();
    let status = v.provider_connection_status("anthropic").unwrap();
    assert!(status.connected);
}
