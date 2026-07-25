//! End-to-end tests for the OpenAI usage/cost synchronization connector
//! (ADR 0011), entirely through the vault with mocked HTTP fixtures.
//! No real credentials, no network. Fixture ids are clearly synthetic.

mod common;

use api_tracker_core::db;
use api_tracker_core::http::{HttpResponse, MockHttpClient};
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::usage;
use api_tracker_core::vault::UnlockedVault;
use api_tracker_core::CoreError;
use common::*;

const FAKE_ADMIN: &str = "sk-admin-FAKE-TEST-NOT-A-REAL-KEY-000000000001";
/// A fake workload key whose prefix/suffix line up with the fixture
/// `redacted_value` below ("sk-proj-FAK...4321").
const FAKE_WORKLOAD: &str = "sk-proj-FAKE-TEST-NOT-REAL-000000000000004321";

fn ok(body: &str) -> HttpResponse {
    MockHttpClient::json_response(body)
}

/// Bucket window entirely inside the current month (30 minutes ago → now),
/// so month-to-date queries include it.
// The synthetic usage window used by every mock in this file. It is memoized
// for the life of the test PROCESS so that all reads return the SAME window:
// `usage_sync` replaces rows for the exact window it syncs, and the
// "overlapping window replaces the old rows" scenario relies on the re-sync
// hitting the identical window. Re-reading `clock::now()` per call is
// second-granular, so two reads separated by real work (a full mock sync + DB
// writes) can straddle a 1-second boundary and yield different windows — a
// latent race that surfaced on the slower Windows CI runner
// (docs/observability/audit/PR13_CI_FAILURE_ANALYSIS.md). No test asserts the
// window's absolute recency (all query `usage_totals("2000-01-01…")`), and
// staleness tests age `last_success_at` independently, so pinning is
// behaviour-preserving and removes the nondeterminism.
fn bucket_times() -> (i64, i64) {
    use std::sync::OnceLock;
    static WINDOW: OnceLock<(i64, i64)> = OnceLock::new();
    *WINDOW.get_or_init(|| {
        let now = api_tracker_core::clock::now().unix_timestamp();
        (now - 1800, now)
    })
}

fn usage_page(ws: i64, we: i64) -> String {
    format!(
        r#"{{"object":"page","data":[
            {{"object":"bucket","start_time":{ws},"end_time":{we},"results":[
                {{"object":"organization.usage.completions.result",
                 "input_tokens":1000000,"output_tokens":1000000,"num_model_requests":42,
                 "project_id":"proj_synthetic_a","api_key_id":"key_synthetic_1",
                 "model":"gpt-4o"}},
                {{"object":"organization.usage.completions.result",
                 "input_tokens":500,"output_tokens":100,"num_model_requests":2,
                 "project_id":"proj_synthetic_b","api_key_id":null,"model":null}}
            ]}}],"has_more":false,"next_page":null}}"#
    )
}

fn costs_page(ws: i64, we: i64) -> String {
    format!(
        r#"{{"object":"page","data":[
            {{"object":"bucket","start_time":{ws},"end_time":{we},"results":[
                {{"object":"organization.costs.result",
                 "amount":{{"value":12.34,"currency":"usd"}},
                 "line_item":"gpt-4o, input","project_id":"proj_synthetic_a",
                 "api_key_id":"key_synthetic_1"}},
                {{"object":"organization.costs.result",
                 "amount":{{"value":2.5,"currency":"usd"}},
                 "line_item":null,"project_id":"proj_synthetic_b","api_key_id":null}}
            ]}}],"has_more":false,"next_page":null}}"#
    )
}

const PROJECTS_PAGE: &str = r#"{"object":"list","data":[
    {"id":"proj_synthetic_a","name":"Synthetic A","status":"active"}],
    "first_id":"proj_synthetic_a","last_id":"proj_synthetic_a","has_more":false}"#;

const KEYS_PAGE: &str = r#"{"object":"list","data":[
    {"object":"organization.project.api_key","id":"key_synthetic_1","name":"app key",
     "redacted_value":"sk-proj-FAK...4321","created_at":1751328000,"last_used_at":null}],
    "first_id":"key_synthetic_1","last_id":"key_synthetic_1","has_more":false}"#;

/// The full response queue for one successful sync, in request order:
/// usage → costs → projects → per-project keys.
fn full_sync_queue() -> Vec<HttpResponse> {
    let (ws, we) = bucket_times();
    vec![
        ok(&usage_page(ws, we)),
        ok(&costs_page(ws, we)),
        ok(PROJECTS_PAGE),
        ok(KEYS_PAGE),
    ]
}

fn connect_openai(vault: &UnlockedVault) {
    let mock = MockHttpClient::json(r#"{"object":"list","data":[],"has_more":false}"#);
    vault
        .provider_admin_connect(
            "openai",
            &SecretString::from(FAKE_ADMIN),
            Some("synthetic-org"),
            Some(&mock),
        )
        .unwrap();
}

fn run_full_sync(vault: &UnlockedVault) -> api_tracker_core::vault::SyncReport {
    let mock = MockHttpClient::new(full_sync_queue());
    vault.usage_sync("openai", &mock, 30).unwrap()
}

#[test]
fn admin_connection_is_encrypted_masked_and_removable() {
    let (dir, paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    connect_openai(&vault);

    let status = vault.provider_connection_status("openai").unwrap();
    assert!(status.connected);
    assert_eq!(status.org_label.as_deref(), Some("synthetic-org"));
    assert!(status.connected_at.is_some());
    let masked = status.admin_key_masked.clone().unwrap();
    assert!(!masked.contains(FAKE_ADMIN));
    assert!(masked.len() < FAKE_ADMIN.len() / 2);

    // The admin key exists nowhere in plaintext inside the data directory.
    drop(vault);
    let mut found = false;
    for entry in walk(&dir.path().to_path_buf()) {
        let bytes = std::fs::read(&entry).unwrap_or_default();
        if bytes
            .windows(FAKE_ADMIN.len())
            .any(|w| w == FAKE_ADMIN.as_bytes())
        {
            found = true;
        }
    }
    assert!(!found, "the admin key was stored in plaintext");

    // Disconnect deletes the connection outright.
    let vault = api_tracker_core::vault::unlock_vault(&paths, &master_pw()).unwrap();
    assert!(vault
        .provider_admin_disconnect("openai", &master_pw())
        .unwrap());
    let status = vault.provider_connection_status("openai").unwrap();
    assert!(!status.connected);
    assert!(status.admin_key_masked.is_none());
}

fn walk(dir: &std::path::PathBuf) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn connect_rejects_an_invalid_admin_key_without_storing_it() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let mock = MockHttpClient::with(401, vec![], "");
    let err = vault
        .provider_admin_connect("openai", &SecretString::from(FAKE_ADMIN), None, Some(&mock))
        .unwrap_err();
    assert!(matches!(err, CoreError::ProviderAuth { .. }));
    assert!(!err.to_string().contains(FAKE_ADMIN));
    let status = vault.provider_connection_status("openai").unwrap();
    assert!(!status.connected);
}

#[test]
fn full_sync_records_usage_costs_metadata_and_checkpoints() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    connect_openai(&vault);
    let report = run_full_sync(&vault);
    assert_eq!(report.usage_rows, 2);
    assert_eq!(report.cost_rows, 2);
    assert!(
        report.notes.is_empty(),
        "unexpected notes: {:?}",
        report.notes
    );

    let (totals, rows) = vault
        .usage_report(
            "2000-01-01T00:00:00Z",
            None,
            None,
            Some("openai"),
            usage::SourceFilter::All,
        )
        .unwrap();
    assert_eq!(totals.snapshots, 4);
    // Tokens come only from usage rows.
    assert_eq!(totals.input_tokens, 1_000_500);
    assert_eq!(totals.request_count, 44);
    // Provider-reported cost comes only from cost rows ($12.34 + $2.50).
    assert_eq!(totals.reported_cost_micros, 14_840_000);
    // The gpt-4o usage row got a local estimate ($2.50/M in + $10/M out).
    assert_eq!(totals.estimated_cost_micros, 12_500_000);
    assert_eq!(totals.reported_currencies, vec!["USD".to_string()]);
    assert!(!totals.has_non_usd_reported);

    // Dimensions and attribution are preserved per row, never invented.
    let keyed_usage = rows
        .iter()
        .find(|r| r.provider_api_key_id.is_some() && r.reported_cost_micros.is_none())
        .unwrap();
    assert_eq!(keyed_usage.attribution, "provider_key");
    assert_eq!(
        keyed_usage.provider_project_id.as_deref(),
        Some("proj_synthetic_a")
    );
    assert_eq!(
        keyed_usage.provider_account_id.as_deref(),
        Some("synthetic-org")
    );
    assert_eq!(keyed_usage.source, "openai_usage_api");
    let unkeyed_usage = rows
        .iter()
        .find(|r| r.provider_api_key_id.is_none() && r.reported_cost_micros.is_none())
        .unwrap();
    assert_eq!(unkeyed_usage.attribution, "provider_project");
    assert!(unkeyed_usage.model.is_none());
    assert!(unkeyed_usage.estimated_cost_micros.is_none());
    let cost_row = rows
        .iter()
        .find(|r| r.reported_cost_micros == Some(12_340_000))
        .unwrap();
    assert_eq!(cost_row.line_item.as_deref(), Some("gpt-4o, input"));
    assert_eq!(cost_row.currency, "USD");
    assert!(cost_row.estimated_cost_micros.is_none());
    assert_eq!(cost_row.source, "openai_costs_api");

    // Provider-side metadata was cached and the keys overview sees it.
    let keys = vault.provider_keys_overview("openai").unwrap();
    let k = keys
        .iter()
        .find(|k| k.api_key_id == "key_synthetic_1")
        .unwrap();
    assert_eq!(k.name, "app key");
    assert_eq!(k.provider_project_name.as_deref(), Some("Synthetic A"));
    assert!(k.linked_credential_id.is_none());
    assert!(k.usage_rows > 0);

    // Checkpoints exist for both endpoint kinds.
    let n: i64 = vault
        .connection()
        .query_row(
            "SELECT count(*) FROM provider_sync_state WHERE provider = 'openai'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 2);
    let status = vault.provider_connection_status("openai").unwrap();
    assert_eq!(status.last_status, "ok");
    assert!(!status.stale);
}

#[test]
fn repeated_and_overlapping_syncs_do_not_double_count() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    connect_openai(&vault);
    run_full_sync(&vault);
    let before = vault
        .usage_totals("2000-01-01T00:00:00Z", None, None)
        .unwrap();

    // Same window again.
    run_full_sync(&vault);
    let after = vault
        .usage_totals("2000-01-01T00:00:00Z", None, None)
        .unwrap();
    assert_eq!(
        before.input_tokens, after.input_tokens,
        "usage double-counted"
    );
    assert_eq!(
        before.reported_cost_micros, after.reported_cost_micros,
        "reported cost double-counted"
    );
    assert_eq!(before.snapshots, after.snapshots);

    // Overlapping window with revised numbers replaces the old rows.
    let (ws, we) = bucket_times();
    let revised = usage_page(ws, we).replace("1000000", "2000000");
    let mock = MockHttpClient::new(vec![
        ok(&revised),
        ok(&costs_page(ws, we)),
        ok(PROJECTS_PAGE),
        ok(KEYS_PAGE),
    ]);
    vault.usage_sync("openai", &mock, 30).unwrap();
    let reconciled = vault
        .usage_totals("2000-01-01T00:00:00Z", None, None)
        .unwrap();
    assert_eq!(reconciled.input_tokens, 2_000_500);
    assert_eq!(reconciled.snapshots, before.snapshots);
}

#[test]
fn manual_usage_is_never_touched_by_sync() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    add_key(
        &mut vault,
        "app",
        "main",
        FAKE_WORKLOAD,
        Environment::Development,
    );
    connect_openai(&vault);

    let now = api_tracker_core::clock::now_rfc3339();
    vault
        .usage_record_manual("app/main", Some("gpt-4o"), 1000, 500, &now, &now)
        .unwrap();
    run_full_sync(&vault);
    run_full_sync(&vault);

    let (_totals, rows) = vault
        .usage_report(
            "2000-01-01T00:00:00Z",
            None,
            None,
            Some("openai"),
            usage::SourceFilter::Manual,
        )
        .unwrap();
    assert_eq!(rows.len(), 1, "the manual snapshot was lost or duplicated");
    assert_eq!(rows[0].source, "manual");
    assert_eq!(rows[0].attribution, "exact_credential");
}

#[test]
fn linking_a_provider_key_upgrades_attribution_and_unlinking_downgrades() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    let (cred, _) = add_key(
        &mut vault,
        "app",
        "main",
        FAKE_WORKLOAD,
        Environment::Development,
    );
    connect_openai(&vault);
    run_full_sync(&vault);

    // The overview suggests the matching credential from the provider's
    // redacted value — but nothing is linked automatically.
    let keys = vault.provider_keys_overview("openai").unwrap();
    let k = keys
        .iter()
        .find(|k| k.api_key_id == "key_synthetic_1")
        .unwrap();
    assert!(k.linked_credential_id.is_none());
    assert_eq!(k.suggested_credential.as_deref(), Some("app/main"));

    // Confirm the association: existing rows are re-attributed.
    let updated = vault
        .provider_link_key("openai", "key_synthetic_1", "app/main")
        .unwrap();
    assert!(updated >= 2, "usage and cost rows should be re-attributed");
    let (totals, rows) = vault
        .usage_report(
            "2000-01-01T00:00:00Z",
            Some("app/main"),
            None,
            Some("openai"),
            usage::SourceFilter::Provider,
        )
        .unwrap();
    assert!(totals.snapshots >= 2);
    assert!(rows.iter().all(|r| r.attribution == "exact_credential"));
    assert!(rows
        .iter()
        .all(|r| r.credential_id.as_deref() == Some(cred.id.as_str())));

    // A later sync keeps the link applied to fresh rows.
    run_full_sync(&vault);
    let (totals_after, _) = vault
        .usage_report(
            "2000-01-01T00:00:00Z",
            Some("app/main"),
            None,
            Some("openai"),
            usage::SourceFilter::Provider,
        )
        .unwrap();
    assert_eq!(totals_after.snapshots, totals.snapshots);

    // Unlink honestly downgrades to provider-key attribution.
    vault
        .provider_unlink_key("openai", "key_synthetic_1")
        .unwrap();
    let (totals_unlinked, _) = vault
        .usage_report(
            "2000-01-01T00:00:00Z",
            Some("app/main"),
            None,
            Some("openai"),
            usage::SourceFilter::Provider,
        )
        .unwrap();
    assert_eq!(totals_unlinked.snapshots, 0);
    let keys = vault.provider_keys_overview("openai").unwrap();
    let k = keys
        .iter()
        .find(|k| k.api_key_id == "key_synthetic_1")
        .unwrap();
    assert!(k.linked_credential_id.is_none());
}

#[test]
fn linking_requires_a_same_provider_credential() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    vault
        .add_credential(api_tracker_core::vault::AddCredential {
            project: "app".into(),
            provider: "github".into(),
            name: "gh".into(),
            environment: Environment::Development,
            value: SecretString::from("ghp_FAKE0000000000000000000000000000000000"),
            credential_type: None,
            key_created_at: None,
            expires_at: None,
            docs_url: String::new(),
            notes: String::new(),
        })
        .unwrap();
    connect_openai(&vault);
    let err = vault
        .provider_link_key("openai", "key_synthetic_1", "app/gh")
        .unwrap_err();
    assert!(err.to_string().contains("github"));
}

#[test]
fn budgets_choose_reported_or_estimated_without_double_counting() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    add_key(
        &mut vault,
        "app",
        "main",
        FAKE_WORKLOAD,
        Environment::Development,
    );
    connect_openai(&vault);
    vault
        .provider_link_key("openai", "key_synthetic_1", "app/main")
        .unwrap();
    run_full_sync(&vault);
    vault
        .set_credential_budget_dollars("app/main", Some("5.00"))
        .unwrap();

    // Both a $12.34 provider-reported cost row and a $12.50 estimate exist
    // for the linked key. best_available must pick reported — never the sum.
    let report = vault.credential_budget_report("app/main").unwrap();
    assert_eq!(report.reported_cost_micros, 12_340_000);
    assert_eq!(report.estimated_cost_micros, 12_500_000);
    assert_eq!(report.used_micros, 12_340_000);
    assert!(!report.used_is_estimated);
    assert!(report.over_budget);

    vault
        .set_budget_cost_source(usage::CostSource::Estimated)
        .unwrap();
    let report = vault.credential_budget_report("app/main").unwrap();
    assert_eq!(report.used_micros, 12_500_000);
    assert!(report.used_is_estimated);
    assert_eq!(report.cost_source, "estimated");

    vault
        .set_budget_cost_source(usage::CostSource::ProviderReported)
        .unwrap();
    let report = vault.credential_budget_report("app/main").unwrap();
    assert_eq!(report.used_micros, 12_340_000);
}

#[test]
fn auth_failure_marks_connection_invalid_and_raises_an_alert() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    connect_openai(&vault);
    let mock = MockHttpClient::with(401, vec![], "");
    let err = vault.usage_sync("openai", &mock, 30).unwrap_err();
    assert!(matches!(err, CoreError::ProviderAuth { .. }));

    let status = vault.provider_connection_status("openai").unwrap();
    assert_eq!(status.last_status, "invalid");
    assert!(status.last_failure_at.is_some());
    assert!(!status.last_error.contains(FAKE_ADMIN));

    let alerts = api_tracker_core::alerts::list(vault.connection(), false).unwrap();
    let alert = alerts
        .iter()
        .find(|a| a.kind == "provider_connection_invalid")
        .expect("connection-invalid alert");
    assert!(!alert.detail.contains(FAKE_ADMIN));
}

#[test]
fn offline_sync_fails_safely_and_previous_data_stays_viewable() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    connect_openai(&vault);
    run_full_sync(&vault);
    let before = vault
        .usage_totals("2000-01-01T00:00:00Z", None, None)
        .unwrap();

    // Every request fails at the transport layer (offline).
    let mock = MockHttpClient::with_network_failures(10, vec![]);
    let err = vault.usage_sync("openai", &mock, 30).unwrap_err();
    assert!(matches!(err, CoreError::Network(_)));

    // Nothing was deleted or partially written; offline viewing still works.
    let after = vault
        .usage_totals("2000-01-01T00:00:00Z", None, None)
        .unwrap();
    assert_eq!(before.snapshots, after.snapshots);
    assert_eq!(before.reported_cost_micros, after.reported_cost_micros);

    let alerts = api_tracker_core::alerts::list(vault.connection(), false).unwrap();
    assert!(alerts.iter().any(|a| a.kind == "provider_sync_failed"));

    // A later successful sync resolves the failure alert.
    run_full_sync(&vault);
    let alerts = api_tracker_core::alerts::list(vault.connection(), false).unwrap();
    assert!(!alerts.iter().any(|a| a.kind == "provider_sync_failed"));
}

#[test]
fn monitor_flags_stale_data_unmatched_keys_and_unmapped_projects() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    add_key(
        &mut vault,
        "app",
        "main",
        FAKE_WORKLOAD,
        Environment::Development,
    );
    connect_openai(&vault);
    run_full_sync(&vault);

    // Freshly synced: not stale; unmatched key + unmapped project alerts
    // exist because nothing is linked and proj_synthetic_b cost >= $1.
    vault.run_monitor().unwrap();
    let alerts = api_tracker_core::alerts::list(vault.connection(), false).unwrap();
    assert!(!alerts.iter().any(|a| a.kind == "provider_data_stale"));
    assert!(alerts.iter().any(|a| a.kind == "unmatched_provider_key"));
    assert!(alerts
        .iter()
        .any(|a| a.kind == "unmapped_provider_project" && a.title.contains("proj_synthetic_b")));

    // Linking the key resolves its unmatched alert on the next run.
    vault
        .provider_link_key("openai", "key_synthetic_1", "app/main")
        .unwrap();
    vault.run_monitor().unwrap();
    let alerts = api_tracker_core::alerts::list(vault.connection(), false).unwrap();
    assert!(!alerts.iter().any(|a| a.kind == "unmatched_provider_key"));

    // Age the last success beyond the staleness threshold (default 3 days).
    vault
        .connection()
        .execute(
            "UPDATE provider_connections SET last_success_at = '2000-01-01T00:00:00Z'
             WHERE provider = 'openai'",
            [],
        )
        .unwrap();
    let status = vault.provider_connection_status("openai").unwrap();
    assert!(status.stale);
    vault.run_monitor().unwrap();
    let alerts = api_tracker_core::alerts::list(vault.connection(), false).unwrap();
    assert!(alerts.iter().any(|a| a.kind == "provider_data_stale"));
}

#[test]
fn migration_v4_upgrades_a_v3_database() {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    // Apply everything up to v3, then the full set.
    db::migrate_with(&mut conn, &db::MIGRATIONS[..3]).unwrap();
    assert_eq!(db::user_version(&conn).unwrap(), 3);
    db::migrate(&mut conn).unwrap();
    assert_eq!(
        db::user_version(&conn).unwrap(),
        db::current_schema_version()
    );
    for table in [
        "provider_key_links",
        "provider_side_projects",
        "provider_side_keys",
        "provider_sync_state",
    ] {
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "missing table {table}");
    }
    // New columns exist on the upgraded tables.
    conn.execute(
        "INSERT INTO provider_connections (provider, admin_key_masked, last_error)
         VALUES ('openai', 'sk-a…01', '')",
        [],
    )
    .unwrap();
}

#[test]
fn non_usd_costs_are_kept_but_never_mixed_into_usd_totals() {
    let (_dir, _paths, mut vault) = new_vault();
    add_project(&mut vault, "app");
    connect_openai(&vault);
    let (ws, we) = bucket_times();
    let eur_costs = costs_page(ws, we).replace(r#""currency":"usd""#, r#""currency":"eur""#);
    let mock = MockHttpClient::new(vec![
        ok(&usage_page(ws, we)),
        ok(&eur_costs),
        ok(PROJECTS_PAGE),
        ok(KEYS_PAGE),
    ]);
    vault.usage_sync("openai", &mock, 30).unwrap();
    let (totals, rows) = vault
        .usage_report(
            "2000-01-01T00:00:00Z",
            None,
            None,
            Some("openai"),
            usage::SourceFilter::All,
        )
        .unwrap();
    assert_eq!(
        totals.reported_cost_micros, 0,
        "non-USD mixed into USD totals"
    );
    assert!(totals.has_non_usd_reported);
    assert!(totals.reported_currencies.contains(&"EUR".to_string()));
    // The rows themselves keep their currency and amount faithfully.
    assert!(rows
        .iter()
        .any(|r| r.currency == "EUR" && r.reported_cost_micros == Some(12_340_000)));
}
