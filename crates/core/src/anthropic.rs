//! Anthropic Admin API synchronization engine.
//!
//! Talks only to the officially documented organization endpoints
//! (verified against the official API reference, 2026-07-18):
//! - `GET /v1/organizations/usage_report/messages` — token usage, daily
//!   buckets, grouped by `api_key_id × workspace_id × model` (per-key
//!   grouping is officially supported), cursor pagination
//!   (`has_more`/`next_page` → `page`).
//! - `GET /v1/organizations/cost_report` — provider-reported spend, daily
//!   buckets only, grouped by `workspace_id × description`. **Amounts are
//!   decimal strings in CENTS** (documented: "123.45" in USD = $1.23) —
//!   converted to integer micro-units with guards, never assumed dollars.
//! - `GET /v1/organizations/workspaces`, `GET /v1/organizations/api_keys`
//!   — provider-side metadata (ids, names, status, partial key hints, and
//!   provider-reported `expires_at`), `first_id`/`last_id`/`has_more`
//!   pagination.
//! - `GET /v1/organizations/me` — admin-key validation.
//!
//! All requests need an Anthropic **Admin key** (`sk-ant-admin...`) in the
//! `x-api-key` header and are sent directly from the user's device. The key
//! is never logged; missing dimensions stay `None`; attribution never
//! claims more precision than the response contains. Costs cannot be
//! grouped per key (documented limitation) — cost rows are workspace-level
//! at best and are never divided among keys.

use crate::clock;
use crate::error::{CoreError, Result};
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::openai::{ProviderSideKey, ProviderSideProject};
use crate::secret::SecretString;
use crate::usage::{Attribution, NewUsageSnapshot};

pub const PROVIDER: &str = "anthropic";
pub const USAGE_SOURCE: &str = "anthropic_usage_api";
pub const COSTS_SOURCE: &str = "anthropic_costs_api";

const BASE: &str = "https://api.anthropic.com/v1";
const MAX_PAGES: usize = 200;

fn get(url: &str, admin: &SecretString) -> HttpRequest {
    HttpRequest::get(url)
        .header("x-api-key", admin.expose())
        .header("anthropic-version", "2023-06-01")
}

fn send_checked(http: &dyn HttpClient, req: &HttpRequest) -> Result<HttpResponse> {
    let resp = http.send(req)?;
    match resp.status {
        401 | 403 => Err(CoreError::ProviderAuth {
            provider: PROVIDER.into(),
            detail: format!(
                "status {} — an ADMIN key (sk-ant-admin...) with organization access is required",
                resp.status
            ),
        }),
        429 => Err(CoreError::ProviderRateLimited {
            provider: PROVIDER.into(),
            retry_after_secs: resp
                .header("retry-after")
                .and_then(|v| v.trim().parse::<u64>().ok()),
        }),
        s if (500..600).contains(&s) => Err(CoreError::Provider(format!(
            "Anthropic returned server error {s}"
        ))),
        _ => Ok(resp),
    }
}

fn parse_json(resp: &HttpResponse) -> Result<serde_json::Value> {
    serde_json::from_slice(&resp.body).map_err(|e| {
        CoreError::Provider(format!(
            "could not parse the Anthropic response (status {}): {e}",
            resp.status
        ))
    })
}

fn require_success(resp: &HttpResponse, what: &str) -> Result<()> {
    if resp.is_success() {
        return Ok(());
    }
    Err(CoreError::Provider(format!(
        "Anthropic returned status {} for {what}",
        resp.status
    )))
}

/// Convert a documented cents-denominated decimal string ("123.45" cents)
/// to integer micro-units (1 cent = 10_000 micros). Rejects non-finite,
/// negative, and overflowing values — the sync fails loudly rather than
/// storing garbage.
pub fn cents_str_to_micros(amount: &str) -> Result<i64> {
    let value: f64 = amount.trim().parse().map_err(|_| {
        CoreError::Provider(format!(
            "unparseable cost amount from Anthropic: '{amount}'"
        ))
    })?;
    if !value.is_finite() || value < 0.0 {
        return Err(CoreError::Provider(format!(
            "invalid cost amount from Anthropic: '{amount}'"
        )));
    }
    let micros = value * 10_000.0;
    if micros > i64::MAX as f64 / 2.0 {
        return Err(CoreError::Provider(
            "cost amount from Anthropic overflows".into(),
        ));
    }
    Ok(micros.round() as i64)
}

/// Validate an admin key with the cheapest authenticated admin read.
pub fn validate_admin_key(http: &dyn HttpClient, admin: &SecretString) -> Result<String> {
    let resp = send_checked(http, &get(&format!("{BASE}/organizations/me"), admin))?;
    require_success(&resp, "the admin connection test")?;
    let json = parse_json(&resp)?;
    let name = json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("organization");
    Ok(format!(
        "the admin key was accepted by the Anthropic organization API ({name})"
    ))
}

/// Follow `has_more`/`next_page` pagination over a report endpoint.
fn fetch_report_buckets(
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
        let Some(data) = json.get("data").and_then(|d| d.as_array()) else {
            return Err(CoreError::Provider(format!(
                "the Anthropic {what} response has no 'data' array"
            )));
        };
        buckets.extend(data.iter().cloned());
        if !json
            .get("has_more")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Ok(buckets);
        }
        page = json
            .get("next_page")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if page.is_none() {
            return Ok(buckets);
        }
    }
    Err(CoreError::Provider(format!(
        "the Anthropic {what} pagination exceeded {MAX_PAGES} pages; aborting"
    )))
}

fn opt_str(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn opt_i64(v: &serde_json::Value, key: &str) -> i64 {
    v.get(key).and_then(|x| x.as_i64()).unwrap_or(0)
}

fn attribution_for(api_key_id: Option<&str>, workspace_id: Option<&str>) -> Attribution {
    if api_key_id.is_some() {
        Attribution::ProviderKey
    } else if workspace_id.is_some() {
        Attribution::ProviderProject
    } else {
        Attribution::ProviderAccount
    }
}

/// Fetch daily token usage grouped by `api_key_id × workspace_id × model`.
/// Input tokens are recorded as uncached + cache_read + cache_creation
/// (both TTLs), mirroring "input includes cached" elsewhere; the raw
/// breakdown drives nothing silently.
pub fn fetch_usage(
    http: &dyn HttpClient,
    admin: &SecretString,
    from: time::OffsetDateTime,
    to: time::OffsetDateTime,
) -> Result<Vec<NewUsageSnapshot>> {
    let url = format!(
        "{BASE}/organizations/usage_report/messages?starting_at={}&ending_at={}&bucket_width=1d\
         &limit=31&group_by[]=api_key_id&group_by[]=workspace_id&group_by[]=model",
        clock::to_rfc3339(from),
        clock::to_rfc3339(to),
    );
    let buckets = fetch_report_buckets(http, admin, &url, "usage report")?;
    let mut out = Vec::new();
    for bucket in &buckets {
        let ws = opt_str(bucket, "starting_at").unwrap_or_default();
        let we = opt_str(bucket, "ending_at").unwrap_or_else(|| ws.clone());
        let Some(results) = bucket.get("results").and_then(|r| r.as_array()) else {
            continue;
        };
        for r in results {
            let api_key_id = opt_str(r, "api_key_id");
            let workspace_id = opt_str(r, "workspace_id");
            let uncached = opt_i64(r, "uncached_input_tokens");
            let cache_read = opt_i64(r, "cache_read_input_tokens");
            let cache_creation = r
                .get("cache_creation")
                .map(|c| {
                    opt_i64(c, "ephemeral_1h_input_tokens")
                        + opt_i64(c, "ephemeral_5m_input_tokens")
                })
                .unwrap_or(0);
            let input = uncached + cache_read + cache_creation;
            let output = opt_i64(r, "output_tokens");
            let mut snap = NewUsageSnapshot::new(PROVIDER, &ws, &we);
            snap.model = opt_str(r, "model");
            snap.input_tokens = Some(input);
            snap.output_tokens = Some(output);
            snap.total_tokens = Some(input + output);
            snap.source = USAGE_SOURCE.to_string();
            snap.attribution = attribution_for(api_key_id.as_deref(), workspace_id.as_deref());
            snap.provider_api_key_id = api_key_id;
            snap.provider_project_id = workspace_id;
            out.push(snap);
        }
    }
    Ok(out)
}

/// Fetch daily provider-reported costs grouped by `workspace_id ×
/// description`. Per-key cost grouping does not exist (documented); cost
/// rows are never attributed below workspace level.
pub fn fetch_costs(
    http: &dyn HttpClient,
    admin: &SecretString,
    from: time::OffsetDateTime,
    to: time::OffsetDateTime,
) -> Result<Vec<NewUsageSnapshot>> {
    let url = format!(
        "{BASE}/organizations/cost_report?starting_at={}&ending_at={}&bucket_width=1d\
         &group_by[]=workspace_id&group_by[]=description",
        clock::to_rfc3339(from),
        clock::to_rfc3339(to),
    );
    let buckets = fetch_report_buckets(http, admin, &url, "cost report")?;
    let mut out = Vec::new();
    for bucket in &buckets {
        let ws = opt_str(bucket, "starting_at").unwrap_or_default();
        let we = opt_str(bucket, "ending_at").unwrap_or_else(|| ws.clone());
        let Some(results) = bucket.get("results").and_then(|r| r.as_array()) else {
            continue;
        };
        for r in results {
            let amount = r.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
            let currency = opt_str(r, "currency").unwrap_or_else(|| "USD".to_string());
            let workspace_id = opt_str(r, "workspace_id");
            let mut snap = NewUsageSnapshot::new(PROVIDER, &ws, &we);
            snap.reported_cost_micros = Some(cents_str_to_micros(amount)?);
            snap.currency = currency.to_uppercase();
            snap.line_item = opt_str(r, "description");
            snap.model = opt_str(r, "model");
            snap.source = COSTS_SOURCE.to_string();
            snap.attribution = attribution_for(None, workspace_id.as_deref());
            snap.provider_project_id = workspace_id;
            out.push(snap);
        }
    }
    Ok(out)
}

/// Follow `first_id`/`last_id`/`has_more` pagination over a list endpoint.
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
            Some(cursor) => format!("{base_url}&after_id={cursor}"),
            None => base_url.to_string(),
        };
        let resp = send_checked(http, &get(&url, admin))?;
        require_success(&resp, what)?;
        let json = parse_json(&resp)?;
        let Some(data) = json.get("data").and_then(|d| d.as_array()) else {
            return Err(CoreError::Provider(format!(
                "the Anthropic {what} response has no 'data' array"
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
        "the Anthropic {what} pagination exceeded {MAX_PAGES} pages; aborting"
    )))
}

/// Workspaces (Anthropic's provider-project analog): id, name, status.
pub fn fetch_workspaces(
    http: &dyn HttpClient,
    admin: &SecretString,
) -> Result<Vec<ProviderSideProject>> {
    let url = format!("{BASE}/organizations/workspaces?limit=100&include_archived=true");
    let items = fetch_list(http, admin, &url, "workspace listing")?;
    Ok(items
        .iter()
        .filter_map(|w| {
            Some(ProviderSideProject {
                id: opt_str(w, "id")?,
                name: opt_str(w, "name").unwrap_or_default(),
                status: if w.get("archived_at").map(|v| !v.is_null()).unwrap_or(false) {
                    "archived".to_string()
                } else {
                    "active".to_string()
                },
            })
        })
        .collect())
}

/// Organization API keys: ids, names, status, partial hints, and the
/// provider-reported `expires_at` (returned alongside, never invented).
pub fn fetch_api_keys(
    http: &dyn HttpClient,
    admin: &SecretString,
) -> Result<Vec<(ProviderSideKey, Option<String>)>> {
    let url = format!("{BASE}/organizations/api_keys?limit=100");
    let items = fetch_list(http, admin, &url, "API-key listing")?;
    Ok(items
        .iter()
        .filter_map(|k| {
            let key = ProviderSideKey {
                id: opt_str(k, "id")?,
                provider_project_id: opt_str(k, "workspace_id"),
                name: opt_str(k, "name").unwrap_or_default(),
                redacted_value: opt_str(k, "partial_key_hint").unwrap_or_default(),
                created_at: opt_str(k, "created_at"),
                last_used_at: None,
            };
            let expires_at = opt_str(k, "expires_at");
            Some((key, expires_at))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttpClient;

    const FAKE_ADMIN: &str = "sk-ant-admin01-FAKE-NOT-A-REAL-KEY-0000000001";

    #[test]
    fn cents_conversion_matches_the_documented_semantics() {
        // Documented: "123.45" in USD represents $1.23 (i.e. 123.45 cents).
        assert_eq!(cents_str_to_micros("123.45").unwrap(), 1_234_500);
        assert_eq!(cents_str_to_micros("0").unwrap(), 0);
        assert_eq!(cents_str_to_micros("100").unwrap(), 1_000_000); // $1
        assert!(cents_str_to_micros("-5").is_err());
        assert!(cents_str_to_micros("NaN").is_err());
        assert!(cents_str_to_micros("garbage").is_err());
    }

    #[test]
    fn usage_pagination_and_per_key_grouping_are_honored() {
        let admin = SecretString::from(FAKE_ADMIN);
        let page1 = r#"{"data":[{"starting_at":"2026-07-01T00:00:00Z","ending_at":"2026-07-02T00:00:00Z",
            "results":[{"api_key_id":"apikey_1","workspace_id":"wrkspc_1","model":"claude-sonnet-4-5",
                        "uncached_input_tokens":100,"cache_read_input_tokens":50,
                        "cache_creation":{"ephemeral_1h_input_tokens":10,"ephemeral_5m_input_tokens":5},
                        "output_tokens":40}]}],
            "has_more":true,"next_page":"cursor2"}"#;
        let page2 = r#"{"data":[{"starting_at":"2026-07-02T00:00:00Z","ending_at":"2026-07-03T00:00:00Z",
            "results":[{"api_key_id":null,"workspace_id":null,"model":null,
                        "uncached_input_tokens":7,"cache_read_input_tokens":0,
                        "output_tokens":3}]}],
            "has_more":false,"next_page":null}"#;
        let mock = MockHttpClient::new(vec![
            MockHttpClient::json_response(page1),
            MockHttpClient::json_response(page2),
        ]);
        let rows = fetch_usage(
            &mock,
            &admin,
            time::macros::datetime!(2026-07-01 0:00 UTC),
            time::macros::datetime!(2026-07-03 0:00 UTC),
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        let per_key = &rows[0];
        assert_eq!(per_key.provider_api_key_id.as_deref(), Some("apikey_1"));
        assert_eq!(per_key.attribution, Attribution::ProviderKey);
        assert_eq!(per_key.input_tokens, Some(165)); // 100 + 50 + 10 + 5
        assert_eq!(per_key.output_tokens, Some(40));
        let org_level = &rows[1];
        assert_eq!(org_level.attribution, Attribution::ProviderAccount);
        // Pagination passed the cursor.
        let requests = mock.requests.borrow();
        assert!(requests[1].url.contains("page=cursor2"));
        // Per-key grouping was requested and the admin key went in the
        // official header, never a query string.
        assert!(requests[0].url.contains("group_by[]=api_key_id"));
        assert!(!requests[0].url.contains(FAKE_ADMIN));
    }

    #[test]
    fn costs_are_cents_and_never_per_key() {
        let admin = SecretString::from(FAKE_ADMIN);
        let body = r#"{"data":[{"starting_at":"2026-07-01T00:00:00Z","ending_at":"2026-07-02T00:00:00Z",
            "results":[{"amount":"123.45","currency":"USD","description":"Claude Sonnet usage",
                        "workspace_id":"wrkspc_1","cost_type":"tokens","model":"claude-sonnet-4-5"}]}],
            "has_more":false}"#;
        let mock = MockHttpClient::json(body);
        let rows = fetch_costs(
            &mock,
            &admin,
            time::macros::datetime!(2026-07-01 0:00 UTC),
            time::macros::datetime!(2026-07-02 0:00 UTC),
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        // "123.45" CENTS = $1.2345 = 1_234_500 micros — not dollars.
        assert_eq!(rows[0].reported_cost_micros, Some(1_234_500));
        assert_eq!(rows[0].attribution, Attribution::ProviderProject);
        assert_eq!(rows[0].provider_api_key_id, None);
        let requests = mock.requests.borrow();
        assert!(
            !requests[0].url.contains("api_key_id"),
            "no per-key cost grouping exists"
        );
    }

    #[test]
    fn key_listing_captures_provider_reported_expiry() {
        let admin = SecretString::from(FAKE_ADMIN);
        let body = r#"{"data":[
            {"id":"apikey_1","type":"api_key","name":"prod","created_at":"2026-01-01T00:00:00Z",
             "partial_key_hint":"sk-ant-api03-R2D...igAA","status":"active",
             "workspace_id":"wrkspc_1","expires_at":"2026-12-31T00:00:00Z"},
            {"id":"apikey_2","type":"api_key","name":"never","created_at":"2026-01-01T00:00:00Z",
             "partial_key_hint":"sk-ant-api03-C3P...oAA","status":"active",
             "workspace_id":null,"expires_at":null}],
            "first_id":"apikey_1","last_id":"apikey_2","has_more":false}"#;
        let mock = MockHttpClient::json(body);
        let keys = fetch_api_keys(&mock, &admin).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].1.as_deref(), Some("2026-12-31T00:00:00Z"));
        assert_eq!(keys[1].1, None);
        assert_eq!(keys[0].0.provider_project_id.as_deref(), Some("wrkspc_1"));
    }

    #[test]
    fn auth_errors_demand_an_admin_key_and_never_leak_it() {
        let admin = SecretString::from(FAKE_ADMIN);
        let mock =
            MockHttpClient::with(401, vec![], r#"{"error":{"type":"authentication_error"}}"#);
        let err = validate_admin_key(&mock, &admin).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("ADMIN key"), "{text}");
        assert!(!text.contains(FAKE_ADMIN));
    }
}
