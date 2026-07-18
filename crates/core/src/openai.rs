//! OpenAI Admin API synchronization engine (ADR 0011).
//!
//! Talks only to the officially documented organization endpoints:
//! - `GET /v1/organization/usage/completions` — token usage, daily buckets,
//!   grouped by `project_id × api_key_id × model`, cursor pagination.
//! - `GET /v1/organization/costs` — provider-reported spend, daily buckets,
//!   grouped by `project_id × api_key_id × line_item`.
//! - `GET /v1/organization/projects` and
//!   `GET /v1/organization/projects/{id}/api_keys` — provider-side metadata
//!   (ids, names, redacted values only — never secrets).
//!
//! All requests require an OpenAI **Admin API key** and are sent directly
//! from the user's device. The admin key travels only in the Authorization
//! header; it is never logged, and error values carry status text only.
//! Every dimension is recorded exactly as the provider reported it — missing
//! dimensions stay `None`, and attribution never claims more precision than
//! the response contains.

use crate::clock;
use crate::error::{CoreError, Result};
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::secret::SecretString;
use crate::usage::{self, Attribution, NewUsageSnapshot};

pub const PROVIDER: &str = "openai";
/// Source tag for token-usage rows synced from the Usage API.
pub const USAGE_SOURCE: &str = "openai_usage_api";
/// Source tag for provider-reported cost rows synced from the Costs API.
pub const COSTS_SOURCE: &str = "openai_costs_api";

const BASE: &str = "https://api.openai.com/v1";
/// Hard cap on pages fetched per endpoint per sync — a defense against a
/// runaway pagination loop, far above any realistic response size.
const MAX_PAGES: usize = 200;
/// Extra attempts per page on transient failures (network, 429, 5xx).
const RETRIES_PER_PAGE: u32 = 2;
/// Longest we honor a Retry-After header for, in seconds.
const MAX_RETRY_AFTER_SECS: u64 = 30;

fn get(url: &str, admin: &SecretString) -> HttpRequest {
    HttpRequest::get(url).header("Authorization", format!("Bearer {}", admin.expose()))
}

/// Send with bounded retries on transient failures. 401/403 map to
/// [`CoreError::ProviderAuth`]; a persistent 429 maps to
/// [`CoreError::ProviderRateLimited`].
fn send_checked(http: &dyn HttpClient, req: &HttpRequest) -> Result<HttpResponse> {
    let mut last_err: Option<CoreError> = None;
    for attempt in 0..=RETRIES_PER_PAGE {
        match http.send(req) {
            Err(CoreError::Network(msg)) => {
                last_err = Some(CoreError::Network(msg));
            }
            Err(other) => return Err(other),
            Ok(resp) => match resp.status {
                401 => {
                    return Err(CoreError::ProviderAuth {
                        provider: PROVIDER.into(),
                        detail: "401 unauthorized — the admin key was rejected".into(),
                    });
                }
                403 => {
                    return Err(CoreError::ProviderAuth {
                        provider: PROVIDER.into(),
                        detail: "403 forbidden — the key lacks the required admin permission"
                            .into(),
                    });
                }
                429 => {
                    let retry_after = resp
                        .header("retry-after")
                        .and_then(|v| v.trim().parse::<u64>().ok());
                    last_err = Some(CoreError::ProviderRateLimited {
                        provider: PROVIDER.into(),
                        retry_after_secs: retry_after,
                    });
                    if attempt < RETRIES_PER_PAGE {
                        let wait = retry_after.unwrap_or(2).min(MAX_RETRY_AFTER_SECS);
                        std::thread::sleep(std::time::Duration::from_secs(wait));
                    }
                    continue;
                }
                s if (500..600).contains(&s) => {
                    last_err = Some(CoreError::Provider(format!(
                        "OpenAI returned server error {s}"
                    )));
                }
                _ => return Ok(resp),
            },
        }
        if attempt < RETRIES_PER_PAGE {
            std::thread::sleep(std::time::Duration::from_millis(500 * (attempt as u64 + 1)));
        }
    }
    Err(last_err.unwrap_or_else(|| CoreError::Provider("request failed".into())))
}

fn parse_json(resp: &HttpResponse) -> Result<serde_json::Value> {
    serde_json::from_slice(&resp.body).map_err(|e| {
        CoreError::Provider(format!(
            "could not parse the OpenAI response (status {}): {e}",
            resp.status
        ))
    })
}

fn require_success(resp: &HttpResponse, what: &str) -> Result<()> {
    if resp.is_success() {
        return Ok(());
    }
    Err(CoreError::Provider(format!(
        "OpenAI returned status {} for {what}",
        resp.status
    )))
}

fn unix_to_rfc3339(unix: i64) -> String {
    clock::to_rfc3339(
        time::OffsetDateTime::from_unix_timestamp(unix).unwrap_or_else(|_| clock::now()),
    )
}

fn opt_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn opt_i64(v: &serde_json::Value, key: &str) -> Option<i64> {
    v.get(key).and_then(|x| x.as_i64())
}

/// The honest attribution for a row given the dimensions the provider
/// actually returned. Linking to a local credential (which upgrades
/// `ProviderKey` to `ExactCredential`) happens in the vault, never here.
fn attribution_for(api_key_id: Option<&str>, project_id: Option<&str>) -> Attribution {
    if api_key_id.is_some() {
        Attribution::ProviderKey
    } else if project_id.is_some() {
        Attribution::ProviderProject
    } else {
        Attribution::ProviderAccount
    }
}

/// Validate an admin key with the cheapest authenticated admin read.
/// Returns a short human-readable detail on success.
pub fn validate_admin_key(http: &dyn HttpClient, admin: &SecretString) -> Result<String> {
    let req = get(&format!("{BASE}/organization/projects?limit=1"), admin);
    let resp = send_checked(http, &req)?;
    require_success(&resp, "the admin connection test")?;
    Ok("the admin key was accepted by the OpenAI organization API".to_string())
}

/// One page-following fetch over a Usage-API-shaped endpoint
/// (`object: "page"`, `data: [bucket]`, `has_more`, `next_page`).
/// Returns every bucket across all pages.
fn fetch_paged_buckets(
    http: &dyn HttpClient,
    admin: &SecretString,
    base_url: &str,
    what: &str,
) -> Result<Vec<serde_json::Value>> {
    let mut buckets = Vec::new();
    let mut page: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let url = match &page {
            Some(cursor) => format!("{base_url}&page={cursor}"),
            None => base_url.to_string(),
        };
        let resp = send_checked(http, &get(&url, admin))?;
        require_success(&resp, what)?;
        let json = parse_json(&resp)?;
        if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
            buckets.extend(data.iter().cloned());
        } else {
            return Err(CoreError::Provider(format!(
                "the OpenAI {what} response has no 'data' array (unsupported response shape)"
            )));
        }
        let has_more = json
            .get("has_more")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !has_more {
            return Ok(buckets);
        }
        page = json
            .get("next_page")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if page.is_none() {
            // has_more without a cursor: stop rather than loop forever.
            return Ok(buckets);
        }
    }
    Err(CoreError::Provider(format!(
        "the OpenAI {what} pagination exceeded {MAX_PAGES} pages; aborting the sync"
    )))
}

/// Fetch completions token usage for [start, end) grouped by
/// project × API key × model, as normalized snapshots.
pub fn fetch_usage(
    http: &dyn HttpClient,
    admin: &SecretString,
    start_unix: i64,
    end_unix: i64,
) -> Result<Vec<NewUsageSnapshot>> {
    let url = format!(
        "{BASE}/organization/usage/completions?start_time={start_unix}&end_time={end_unix}\
         &bucket_width=1d&limit=31\
         &group_by=project_id&group_by=api_key_id&group_by=model"
    );
    let buckets = fetch_paged_buckets(http, admin, &url, "usage query")?;
    let mut rows = Vec::new();
    for bucket in &buckets {
        let ws = opt_i64(bucket, "start_time").unwrap_or(start_unix);
        let we = opt_i64(bucket, "end_time").unwrap_or(ws);
        let Some(results) = bucket.get("results").and_then(|r| r.as_array()) else {
            continue;
        };
        for r in results {
            let project_id = opt_str(r, "project_id");
            let api_key_id = opt_str(r, "api_key_id");
            let input = opt_i64(r, "input_tokens").unwrap_or(0);
            let output = opt_i64(r, "output_tokens").unwrap_or(0);
            let mut snap =
                NewUsageSnapshot::new(PROVIDER, &unix_to_rfc3339(ws), &unix_to_rfc3339(we));
            snap.model = opt_str(r, "model");
            snap.input_tokens = Some(input);
            snap.output_tokens = Some(output);
            snap.total_tokens = Some(input + output);
            snap.request_count = opt_i64(r, "num_model_requests");
            snap.attribution = attribution_for(api_key_id.as_deref(), project_id.as_deref());
            snap.provider_project_id = project_id;
            snap.provider_api_key_id = api_key_id;
            snap.source = USAGE_SOURCE.to_string();
            rows.push(snap);
        }
    }
    Ok(rows)
}

/// Fetch provider-reported costs for [start, end) grouped by
/// project × API key × line item, as normalized snapshots. Amounts are
/// preserved exactly as reported (value + currency); invalid amounts
/// (negative, non-finite, overflowing) abort the sync instead of storing
/// garbage.
pub fn fetch_costs(
    http: &dyn HttpClient,
    admin: &SecretString,
    start_unix: i64,
    end_unix: i64,
) -> Result<Vec<NewUsageSnapshot>> {
    let url = format!(
        "{BASE}/organization/costs?start_time={start_unix}&end_time={end_unix}\
         &bucket_width=1d&limit=180\
         &group_by=project_id&group_by=api_key_id&group_by=line_item"
    );
    let buckets = fetch_paged_buckets(http, admin, &url, "costs query")?;
    let mut rows = Vec::new();
    for bucket in &buckets {
        let ws = opt_i64(bucket, "start_time").unwrap_or(start_unix);
        let we = opt_i64(bucket, "end_time").unwrap_or(ws);
        let Some(results) = bucket.get("results").and_then(|r| r.as_array()) else {
            continue;
        };
        for r in results {
            let Some(amount) = r.get("amount") else {
                continue;
            };
            let value = amount.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let currency = amount
                .get("currency")
                .and_then(|v| v.as_str())
                .unwrap_or("usd")
                .to_uppercase();
            let project_id = opt_str(r, "project_id");
            let api_key_id = opt_str(r, "api_key_id");
            let mut snap =
                NewUsageSnapshot::new(PROVIDER, &unix_to_rfc3339(ws), &unix_to_rfc3339(we));
            snap.reported_cost_micros = Some(usage::micros_from_decimal(value)?);
            snap.currency = currency;
            snap.line_item = opt_str(r, "line_item");
            snap.attribution = attribution_for(api_key_id.as_deref(), project_id.as_deref());
            snap.provider_project_id = project_id;
            snap.provider_api_key_id = api_key_id;
            snap.source = COSTS_SOURCE.to_string();
            rows.push(snap);
        }
    }
    Ok(rows)
}

/// A provider-side project (non-secret metadata).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderSideProject {
    pub id: String,
    pub name: String,
    pub status: String,
}

/// A provider-side API key (non-secret metadata; the provider returns only a
/// redacted value).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderSideKey {
    pub id: String,
    pub provider_project_id: Option<String>,
    pub name: String,
    pub redacted_value: String,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}

/// One page-following fetch over a list-shaped admin endpoint
/// (`object: "list"`, `data`, `has_more`, `last_id` + `after` cursor).
fn fetch_list(
    http: &dyn HttpClient,
    admin: &SecretString,
    base_url: &str,
    what: &str,
) -> Result<Vec<serde_json::Value>> {
    let mut items = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let url = match &after {
            Some(cursor) => format!("{base_url}&after={cursor}"),
            None => base_url.to_string(),
        };
        let resp = send_checked(http, &get(&url, admin))?;
        require_success(&resp, what)?;
        let json = parse_json(&resp)?;
        let Some(data) = json.get("data").and_then(|d| d.as_array()) else {
            return Err(CoreError::Provider(format!(
                "the OpenAI {what} response has no 'data' array (unsupported response shape)"
            )));
        };
        items.extend(data.iter().cloned());
        let has_more = json
            .get("has_more")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        after = json
            .get("last_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if !has_more || after.is_none() {
            return Ok(items);
        }
    }
    Err(CoreError::Provider(format!(
        "the OpenAI {what} pagination exceeded {MAX_PAGES} pages; aborting"
    )))
}

/// List the organization's projects (id, name, status).
pub fn fetch_projects(
    http: &dyn HttpClient,
    admin: &SecretString,
) -> Result<Vec<ProviderSideProject>> {
    let url = format!("{BASE}/organization/projects?limit=100");
    let items = fetch_list(http, admin, &url, "project listing")?;
    Ok(items
        .iter()
        .filter_map(|p| {
            Some(ProviderSideProject {
                id: opt_str(p, "id")?,
                name: opt_str(p, "name").unwrap_or_default(),
                status: opt_str(p, "status").unwrap_or_default(),
            })
        })
        .collect())
}

/// List a project's API keys (ids, names, redacted values — no secrets).
pub fn fetch_project_keys(
    http: &dyn HttpClient,
    admin: &SecretString,
    project_id: &str,
) -> Result<Vec<ProviderSideKey>> {
    let url = format!("{BASE}/organization/projects/{project_id}/api_keys?limit=100");
    let items = fetch_list(http, admin, &url, "project API-key listing")?;
    Ok(items
        .iter()
        .filter_map(|k| {
            Some(ProviderSideKey {
                id: opt_str(k, "id")?,
                provider_project_id: Some(project_id.to_string()),
                name: opt_str(k, "name").unwrap_or_default(),
                redacted_value: opt_str(k, "redacted_value").unwrap_or_default(),
                created_at: opt_i64(k, "created_at").map(unix_to_rfc3339),
                last_used_at: opt_i64(k, "last_used_at").map(unix_to_rfc3339),
            })
        })
        .collect())
}

/// A key created via the Admin API. The plaintext value is returned by
/// OpenAI exactly once (at creation) and is moved straight into the vault.
pub struct CreatedServiceAccountKey {
    pub value: SecretString,
    pub api_key_id: String,
    pub service_account_id: String,
    pub detail: String,
}

fn post_json(url: &str, admin: &SecretString, body: serde_json::Value) -> HttpRequest {
    HttpRequest::with_method(crate::http::Method::Post, url)
        .header("Authorization", format!("Bearer {}", admin.expose()))
        .header("content-type", "application/json")
        .body(body.to_string().into_bytes())
}

/// Create a service account (and its API key) inside a provider project.
/// `POST /v1/organization/projects/{id}/service_accounts` — the officially
/// documented way to create a workload key programmatically. User keys
/// cannot be created via API (dashboard only), and the response's
/// `api_key.value` is shown only once.
pub fn create_service_account_key(
    http: &dyn HttpClient,
    admin: &SecretString,
    project_id: &str,
    name: &str,
) -> Result<CreatedServiceAccountKey> {
    let url = format!("{BASE}/organization/projects/{project_id}/service_accounts");
    let resp = send_checked(
        http,
        &post_json(&url, admin, serde_json::json!({ "name": name })),
    )?;
    require_success(&resp, "service-account creation")?;
    let json = parse_json(&resp)?;
    let service_account_id = opt_str(&json, "id")
        .ok_or_else(|| CoreError::Provider("service-account response is missing its id".into()))?;
    let api_key = json
        .get("api_key")
        .ok_or_else(|| CoreError::Provider("service-account response has no api_key".into()))?;
    let value = api_key
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CoreError::Provider(
                "the creation response did not include the key value (it is only \
                 returned once, at creation)"
                    .into(),
            )
        })?;
    let api_key_id = opt_str(api_key, "id").ok_or_else(|| {
        CoreError::Provider("service-account key response is missing the key id".into())
    })?;
    Ok(CreatedServiceAccountKey {
        value: SecretString::new(value.to_string()),
        api_key_id,
        service_account_id,
        detail: format!("created service account '{name}' in project {project_id}"),
    })
}

/// Permanently delete a project API key by id.
/// `DELETE /v1/organization/projects/{id}/api_keys/{key_id}`. OpenAI has no
/// disable state — deletion is the only programmatic kill switch.
pub fn delete_project_api_key(
    http: &dyn HttpClient,
    admin: &SecretString,
    project_id: &str,
    key_id: &str,
) -> Result<String> {
    let url = format!("{BASE}/organization/projects/{project_id}/api_keys/{key_id}");
    let req = HttpRequest::with_method(crate::http::Method::Delete, url)
        .header("Authorization", format!("Bearer {}", admin.expose()));
    let resp = send_checked(http, &req)?;
    if resp.status == 404 {
        // Idempotent: already gone is success for a revocation retry.
        return Ok(format!("key {key_id} was already deleted"));
    }
    require_success(&resp, "project API-key deletion")?;
    let deleted = parse_json(&resp)
        .ok()
        .and_then(|j| j.get("deleted").and_then(|d| d.as_bool()))
        .unwrap_or(true);
    if !deleted {
        return Err(CoreError::Provider(format!(
            "OpenAI did not confirm deletion of key {key_id}"
        )));
    }
    Ok(format!("deleted project API key {key_id}"))
}

/// True when a provider-listed redacted value (e.g. `sk-...abc1`) is
/// consistent with a full secret value. This is *suggestion evidence only*:
/// a match is strong but not proof, so it never links automatically.
pub fn redacted_value_matches(redacted: &str, full: &str) -> bool {
    if redacted.is_empty() || full.is_empty() || !redacted.contains("...") {
        return false;
    }
    let mut parts = redacted.splitn(2, "...");
    let prefix = parts.next().unwrap_or_default();
    let suffix = parts.next().unwrap_or_default();
    if prefix.is_empty() && suffix.is_empty() {
        return false;
    }
    full.len() >= prefix.len() + suffix.len() && full.starts_with(prefix) && full.ends_with(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttpClient;

    const FAKE_ADMIN: &str = "FAKE-TEST-ADMIN-NOT-A-REAL-KEY-0001";

    fn admin() -> SecretString {
        SecretString::from(FAKE_ADMIN)
    }

    #[test]
    fn usage_two_pages_are_followed_and_grouped_dimensions_kept() {
        let page1 = r#"{"object":"page","data":[
            {"object":"bucket","start_time":1751328000,"end_time":1751414400,"results":[
                {"input_tokens":1000,"output_tokens":500,"num_model_requests":3,
                 "project_id":"proj_synthetic_a","api_key_id":"key_synthetic_1","model":"gpt-4o"}
            ]}],"has_more":true,"next_page":"cursor_abc"}"#;
        let page2 = r#"{"object":"page","data":[
            {"object":"bucket","start_time":1751414400,"end_time":1751500800,"results":[
                {"input_tokens":10,"output_tokens":5,"num_model_requests":1,
                 "project_id":"proj_synthetic_a","api_key_id":null,"model":null}
            ]}],"has_more":false,"next_page":null}"#;
        let mock = MockHttpClient::new(vec![
            crate::http::HttpResponse {
                status: 200,
                headers: vec![],
                body: page1.as_bytes().to_vec(),
            },
            crate::http::HttpResponse {
                status: 200,
                headers: vec![],
                body: page2.as_bytes().to_vec(),
            },
        ]);
        let rows = fetch_usage(&mock, &admin(), 1751328000, 1751500800).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].provider_api_key_id.as_deref(),
            Some("key_synthetic_1")
        );
        assert_eq!(rows[0].attribution, Attribution::ProviderKey);
        assert_eq!(rows[0].model.as_deref(), Some("gpt-4o"));
        assert_eq!(rows[0].total_tokens, Some(1500));
        // Second row has no api_key_id → honestly project-level.
        assert_eq!(rows[1].attribution, Attribution::ProviderProject);
        assert!(rows[1].provider_api_key_id.is_none());
        // The second request carried the pagination cursor.
        let reqs = mock.requests.borrow();
        assert!(reqs[1].url.contains("page=cursor_abc"));
        // And the first asked for the grouped dimensions and window.
        assert!(reqs[0].url.contains("group_by=api_key_id"));
        assert!(reqs[0].url.contains("start_time=1751328000"));
        assert!(reqs[0].url.contains("end_time=1751500800"));
    }

    #[test]
    fn usage_401_maps_to_provider_auth() {
        let mock = MockHttpClient::with(401, vec![], "");
        let err = fetch_usage(&mock, &admin(), 0, 1).unwrap_err();
        assert!(matches!(err, CoreError::ProviderAuth { .. }));
        // The error text never contains the admin key.
        assert!(!err.to_string().contains(FAKE_ADMIN));
    }

    #[test]
    fn usage_403_maps_to_provider_auth() {
        let mock = MockHttpClient::with(403, vec![], "");
        let err = fetch_usage(&mock, &admin(), 0, 1).unwrap_err();
        assert!(matches!(err, CoreError::ProviderAuth { .. }));
    }

    #[test]
    fn usage_429_retries_then_reports_rate_limit() {
        let resp429 = || crate::http::HttpResponse {
            status: 429,
            headers: vec![("Retry-After".into(), "0".into())],
            body: Vec::new(),
        };
        let mock = MockHttpClient::new(vec![resp429(), resp429(), resp429()]);
        let err = fetch_usage(&mock, &admin(), 0, 1).unwrap_err();
        assert!(matches!(err, CoreError::ProviderRateLimited { .. }));
        assert_eq!(mock.requests.borrow().len(), 3);
    }

    #[test]
    fn usage_recovers_after_transient_500() {
        let ok = r#"{"object":"page","data":[],"has_more":false,"next_page":null}"#;
        let mock = MockHttpClient::new(vec![
            crate::http::HttpResponse {
                status: 500,
                headers: vec![],
                body: Vec::new(),
            },
            crate::http::HttpResponse {
                status: 200,
                headers: vec![],
                body: ok.as_bytes().to_vec(),
            },
        ]);
        let rows = fetch_usage(&mock, &admin(), 0, 1).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn usage_empty_window_is_ok() {
        let mock = MockHttpClient::json(
            r#"{"object":"page","data":[],"has_more":false,"next_page":null}"#,
        );
        let rows = fetch_usage(&mock, &admin(), 0, 1).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn usage_malformed_response_is_a_clear_error() {
        let mock = MockHttpClient::json(r#"{"unexpected":"shape"}"#);
        let err = fetch_usage(&mock, &admin(), 0, 1).unwrap_err();
        assert!(err.to_string().contains("unsupported response shape"));
        let mock = MockHttpClient::with(200, vec![], "not-json");
        let err = fetch_usage(&mock, &admin(), 0, 1).unwrap_err();
        assert!(err.to_string().contains("could not parse"));
    }

    #[test]
    fn costs_preserve_amount_currency_and_line_item() {
        let body = r#"{"object":"page","data":[
            {"object":"bucket","start_time":1751328000,"end_time":1751414400,"results":[
                {"object":"organization.costs.result",
                 "amount":{"value":0.06,"currency":"usd"},
                 "line_item":"gpt-4o, input","project_id":"proj_synthetic_a",
                 "api_key_id":"key_synthetic_1"}
            ]}],"has_more":false,"next_page":null}"#;
        let mock = MockHttpClient::json(body);
        let rows = fetch_costs(&mock, &admin(), 1751328000, 1751414400).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reported_cost_micros, Some(60_000));
        assert_eq!(rows[0].currency, "USD");
        assert_eq!(rows[0].line_item.as_deref(), Some("gpt-4o, input"));
        assert_eq!(rows[0].attribution, Attribution::ProviderKey);
        assert!(rows[0].estimated_cost_micros.is_none());
        assert_eq!(rows[0].source, COSTS_SOURCE);
    }

    #[test]
    fn costs_reject_negative_and_non_finite_amounts() {
        let body = r#"{"object":"page","data":[
            {"object":"bucket","start_time":0,"end_time":1,"results":[
                {"amount":{"value":-5.0,"currency":"usd"}}
            ]}],"has_more":false,"next_page":null}"#;
        let mock = MockHttpClient::json(body);
        let err = fetch_costs(&mock, &admin(), 0, 1).unwrap_err();
        assert!(err.to_string().contains("negative"));
    }

    #[test]
    fn costs_without_key_or_project_are_account_level() {
        let body = r#"{"object":"page","data":[
            {"object":"bucket","start_time":0,"end_time":1,"results":[
                {"amount":{"value":1.0,"currency":"usd"},"line_item":null,
                 "project_id":null,"api_key_id":null}
            ]}],"has_more":false,"next_page":null}"#;
        let mock = MockHttpClient::json(body);
        let rows = fetch_costs(&mock, &admin(), 0, 1).unwrap();
        assert_eq!(rows[0].attribution, Attribution::ProviderAccount);
        assert!(rows[0].provider_project_id.is_none());
    }

    #[test]
    fn projects_and_keys_follow_list_pagination() {
        let p1 = r#"{"object":"list","data":[{"id":"proj_synthetic_a","name":"Synthetic A","status":"active"}],
                     "first_id":"proj_synthetic_a","last_id":"proj_synthetic_a","has_more":true}"#;
        let p2 = r#"{"object":"list","data":[{"id":"proj_synthetic_b","name":"Synthetic B","status":"active"}],
                     "first_id":"proj_synthetic_b","last_id":"proj_synthetic_b","has_more":false}"#;
        let mock = MockHttpClient::new(vec![
            crate::http::HttpResponse {
                status: 200,
                headers: vec![],
                body: p1.as_bytes().to_vec(),
            },
            crate::http::HttpResponse {
                status: 200,
                headers: vec![],
                body: p2.as_bytes().to_vec(),
            },
        ]);
        let projects = fetch_projects(&mock, &admin()).unwrap();
        assert_eq!(projects.len(), 2);
        assert!(mock.requests.borrow()[1]
            .url
            .contains("after=proj_synthetic_a"));

        let keys_body = r#"{"object":"list","data":[
            {"id":"key_synthetic_1","name":"ci key","redacted_value":"sk-FAKE...0001",
             "created_at":1751328000,"last_used_at":null}],
            "first_id":"key_synthetic_1","last_id":"key_synthetic_1","has_more":false}"#;
        let mock = MockHttpClient::json(keys_body);
        let keys = fetch_project_keys(&mock, &admin(), "proj_synthetic_a").unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].redacted_value, "sk-FAKE...0001");
        assert_eq!(
            keys[0].provider_project_id.as_deref(),
            Some("proj_synthetic_a")
        );
    }

    #[test]
    fn validate_admin_key_accepts_and_rejects() {
        let mock = MockHttpClient::json(r#"{"object":"list","data":[],"has_more":false}"#);
        assert!(validate_admin_key(&mock, &admin()).is_ok());
        let mock = MockHttpClient::with(401, vec![], "");
        assert!(matches!(
            validate_admin_key(&mock, &admin()),
            Err(CoreError::ProviderAuth { .. })
        ));
    }

    #[test]
    fn redacted_match_requires_prefix_and_suffix() {
        assert!(redacted_value_matches(
            "sk-FAKE...0001",
            "sk-FAKE-TEST-NOT-REAL-0001"
        ));
        assert!(!redacted_value_matches(
            "sk-FAKE...9999",
            "sk-FAKE-TEST-NOT-REAL-0001"
        ));
        assert!(!redacted_value_matches("", "sk-x"));
        assert!(!redacted_value_matches("sk-noellipsis", "sk-noellipsis"));
    }

    #[test]
    fn admin_key_never_appears_in_error_text() {
        for status in [400u16, 500, 503] {
            let mock = MockHttpClient::with(status, vec![], "");
            if let Err(e) = fetch_usage(&mock, &admin(), 0, 1) {
                assert!(!e.to_string().contains(FAKE_ADMIN));
            }
        }
    }
}
