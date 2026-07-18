//! Provider connectors: officially-documented, safely-implementable network
//! calls, built directly from the user's device.
//!
//! Each connector implements only what a provider genuinely supports and what
//! can be developed and tested without committing real credentials — request
//! construction and response parsing are exercised against fixtures through
//! the mockable [`crate::http::HttpClient`]. Capabilities a connector does not
//! implement return [`CoreError::Unsupported`] with the official management
//! hint, so nothing is ever faked. Usage attribution is reported honestly:
//! organization/project data is never presented as exact per-key usage.

use crate::error::{CoreError, Result};
use crate::http::{HttpClient, HttpRequest};
use crate::providers;
use crate::secret::SecretString;
use crate::usage::{Attribution, NewUsageSnapshot};
use serde::Serialize;

/// The result of validating a credential.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub status: u16,
    pub detail: String,
}

/// Provider-side metadata discovered for a credential (non-secret).
#[derive(Debug, Clone, Serialize)]
pub struct FetchedMetadata {
    pub fields: Vec<(String, String)>,
    pub source: String,
}

/// Raw scopes fetched for a credential.
#[derive(Debug, Clone, Serialize)]
pub struct FetchedPermissions {
    pub raw_scopes: Vec<String>,
    pub precision: String,
    pub confidence: String,
    pub source: String,
}

/// Usage fetched from a provider, with honest attribution.
#[derive(Debug, Clone)]
pub struct FetchedUsage {
    pub snapshots: Vec<NewUsageSnapshot>,
    pub attribution: Attribution,
    pub source: String,
}

/// A provider connector. Default methods report the capability as
/// unsupported; each provider overrides only what it truly implements.
pub trait Connector {
    fn id(&self) -> &'static str;

    fn validate(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<ValidationResult>;

    fn fetch_metadata(
        &self,
        _http: &dyn HttpClient,
        _secret: &SecretString,
    ) -> Result<FetchedMetadata> {
        Err(self.unsupported("fetch_metadata"))
    }

    fn fetch_permissions(
        &self,
        _http: &dyn HttpClient,
        _secret: &SecretString,
    ) -> Result<FetchedPermissions> {
        Err(self.unsupported("read_permissions"))
    }

    /// Fetch usage over the last `since_days` days. Requires an admin/org
    /// credential for providers whose usage APIs are admin-only.
    fn fetch_usage(
        &self,
        _http: &dyn HttpClient,
        _admin_secret: &SecretString,
        _since_days: u32,
    ) -> Result<FetchedUsage> {
        Err(self.unsupported("fetch_usage"))
    }

    fn unsupported(&self, capability: &'static str) -> CoreError {
        let hint = providers::find(self.id())
            .map(|m| format!("use the official page: {}", m.manage_url))
            .unwrap_or_else(|| "no official programmatic method".to_string());
        CoreError::Unsupported {
            provider: self.id().to_string(),
            capability,
            hint,
        }
    }
}

/// The connector for a provider id, if one exists.
pub fn for_provider(provider: &str) -> Option<Box<dyn Connector>> {
    match provider.to_lowercase().as_str() {
        "github" => Some(Box::new(GitHub)),
        "openai" => Some(Box::new(OpenAi)),
        "anthropic" => Some(Box::new(Anthropic)),
        "stripe" => Some(Box::new(Stripe)),
        "supabase" => Some(Box::new(Supabase)),
        _ => None,
    }
}

fn parse_json(body: &[u8]) -> Result<serde_json::Value> {
    serde_json::from_slice(body)
        .map_err(|e| CoreError::Provider(format!("could not parse provider response: {e}")))
}

fn unix_days_ago(days: u32) -> i64 {
    (crate::clock::now() - time::Duration::days(i64::from(days))).unix_timestamp()
}

// ---------------------------------------------------------------------------
// GitHub — the richest no-admin, exact-credential connector.
// ---------------------------------------------------------------------------

pub struct GitHub;

impl GitHub {
    fn user_request(secret: &SecretString) -> HttpRequest {
        HttpRequest::get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {}", secret.expose()))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }
}

impl Connector for GitHub {
    fn id(&self) -> &'static str {
        "github"
    }

    fn validate(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<ValidationResult> {
        let resp = http.send(&Self::user_request(secret))?;
        let detail = if resp.is_success() {
            let json = parse_json(&resp.body).unwrap_or(serde_json::Value::Null);
            match json.get("login").and_then(|v| v.as_str()) {
                Some(login) => format!("authenticated as {login}"),
                None => "authenticated".to_string(),
            }
        } else if resp.status == 401 {
            "the token was rejected (401)".to_string()
        } else {
            format!("unexpected status {}", resp.status)
        };
        Ok(ValidationResult {
            valid: resp.is_success(),
            status: resp.status,
            detail,
        })
    }

    fn fetch_metadata(
        &self,
        http: &dyn HttpClient,
        secret: &SecretString,
    ) -> Result<FetchedMetadata> {
        let resp = http.send(&Self::user_request(secret))?;
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "GitHub returned status {} when fetching metadata",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let mut fields = Vec::new();
        for key in ["login", "id", "name", "type", "created_at"] {
            if let Some(v) = json.get(key) {
                let s = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                if !s.is_empty() && s != "null" {
                    fields.push((key.to_string(), s));
                }
            }
        }
        if let Some(scopes) = resp.header("x-oauth-scopes") {
            fields.push(("token_scopes".to_string(), scopes.to_string()));
        }
        Ok(FetchedMetadata {
            fields,
            source: "GitHub GET /user".to_string(),
        })
    }

    fn fetch_permissions(
        &self,
        http: &dyn HttpClient,
        secret: &SecretString,
    ) -> Result<FetchedPermissions> {
        let resp = http.send(&Self::user_request(secret))?;
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "GitHub returned status {} when reading scopes",
                resp.status
            )));
        }
        match resp.header("x-oauth-scopes") {
            Some(raw) => {
                let scopes: Vec<String> = raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                Ok(FetchedPermissions {
                    raw_scopes: scopes,
                    precision: "exact_credential".to_string(),
                    confidence: "high".to_string(),
                    source: "GitHub X-OAuth-Scopes header".to_string(),
                })
            }
            // Fine-grained tokens do not expose scopes via a header.
            None => Ok(FetchedPermissions {
                raw_scopes: Vec::new(),
                precision: "exact_credential".to_string(),
                confidence: "low".to_string(),
                source: "GitHub (fine-grained token scopes are not API-readable)".to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// OpenAI — validate (no admin) + usage (admin, account level).
// ---------------------------------------------------------------------------

pub struct OpenAi;

impl Connector for OpenAi {
    fn id(&self) -> &'static str {
        "openai"
    }

    fn validate(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<ValidationResult> {
        let req = HttpRequest::get("https://api.openai.com/v1/models")
            .header("Authorization", format!("Bearer {}", secret.expose()));
        let resp = http.send(&req)?;
        let detail = if resp.is_success() {
            let n = parse_json(&resp.body)
                .ok()
                .and_then(|j| j.get("data").and_then(|d| d.as_array()).map(|a| a.len()))
                .unwrap_or(0);
            format!("accepted; {n} models visible")
        } else if resp.status == 401 {
            "the key was rejected (401 invalid_api_key)".to_string()
        } else {
            format!("unexpected status {}", resp.status)
        };
        Ok(ValidationResult {
            valid: resp.is_success(),
            status: resp.status,
            detail,
        })
    }

    fn fetch_usage(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        since_days: u32,
    ) -> Result<FetchedUsage> {
        let start = unix_days_ago(since_days);
        let url = format!(
            "https://api.openai.com/v1/organization/usage/completions?start_time={start}&bucket_width=1d"
        );
        let req = HttpRequest::get(url)
            .header("Authorization", format!("Bearer {}", admin_secret.expose()));
        let resp = http.send(&req)?;
        if resp.status == 401 {
            return Err(CoreError::Provider(
                "the OpenAI usage API needs an admin key (401)".to_string(),
            ));
        }
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "OpenAI usage status {}",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let mut snapshots = Vec::new();
        if let Some(buckets) = json.get("data").and_then(|d| d.as_array()) {
            for b in buckets {
                let ws = b
                    .get("start_time")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(start);
                let we = b.get("end_time").and_then(|v| v.as_i64()).unwrap_or(ws);
                let mut input = 0i64;
                let mut output = 0i64;
                let mut requests = 0i64;
                if let Some(results) = b.get("results").and_then(|r| r.as_array()) {
                    for r in results {
                        input += r.get("input_tokens").and_then(|v| v.as_i64()).unwrap_or(0);
                        output += r.get("output_tokens").and_then(|v| v.as_i64()).unwrap_or(0);
                        requests += r
                            .get("num_model_requests")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                    }
                }
                let mut snap = NewUsageSnapshot::new(
                    "openai",
                    &crate::clock::to_rfc3339(unix_to_time(ws)),
                    &crate::clock::to_rfc3339(unix_to_time(we)),
                );
                snap.input_tokens = Some(input);
                snap.output_tokens = Some(output);
                snap.total_tokens = Some(input + output);
                snap.request_count = Some(requests);
                // Org-wide totals: NOT attributable to a single key.
                snap.attribution = Attribution::ProviderAccount;
                snapshots.push(snap);
            }
        }
        Ok(FetchedUsage {
            snapshots,
            attribution: Attribution::ProviderAccount,
            source: "OpenAI Usage API (organization level)".to_string(),
        })
    }
}

fn unix_to_time(unix: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(unix).unwrap_or_else(|_| crate::clock::now())
}

// ---------------------------------------------------------------------------
// Anthropic — validate (no admin) + usage (admin, account level).
// ---------------------------------------------------------------------------

pub struct Anthropic;

impl Connector for Anthropic {
    fn id(&self) -> &'static str {
        "anthropic"
    }

    fn validate(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<ValidationResult> {
        let req = HttpRequest::get("https://api.anthropic.com/v1/models")
            .header("x-api-key", secret.expose())
            .header("anthropic-version", "2023-06-01");
        let resp = http.send(&req)?;
        let detail = if resp.is_success() {
            "accepted".to_string()
        } else if resp.status == 401 {
            "the key was rejected (401 authentication_error)".to_string()
        } else {
            format!("unexpected status {}", resp.status)
        };
        Ok(ValidationResult {
            valid: resp.is_success(),
            status: resp.status,
            detail,
        })
    }

    fn fetch_usage(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        since_days: u32,
    ) -> Result<FetchedUsage> {
        let start = unix_days_ago(since_days);
        let url = format!(
            "https://api.anthropic.com/v1/organizations/usage_report/messages?starting_at={start}&bucket_width=1d"
        );
        let req = HttpRequest::get(url)
            .header("x-api-key", admin_secret.expose())
            .header("anthropic-version", "2023-06-01");
        let resp = http.send(&req)?;
        if resp.status == 401 {
            return Err(CoreError::Provider(
                "the Anthropic usage API needs an admin key (401)".to_string(),
            ));
        }
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "Anthropic usage status {}",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let mut snapshots = Vec::new();
        if let Some(buckets) = json.get("data").and_then(|d| d.as_array()) {
            for b in buckets {
                let ws = b
                    .get("starting_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let we = b.get("ending_at").and_then(|v| v.as_str()).unwrap_or(ws);
                let mut input = 0i64;
                let mut output = 0i64;
                if let Some(results) = b.get("results").and_then(|r| r.as_array()) {
                    for r in results {
                        input += r
                            .get("uncached_input_tokens")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0)
                            + r.get("input_tokens").and_then(|v| v.as_i64()).unwrap_or(0);
                        output += r.get("output_tokens").and_then(|v| v.as_i64()).unwrap_or(0);
                    }
                }
                let mut snap = NewUsageSnapshot::new("anthropic", ws, we);
                snap.input_tokens = Some(input);
                snap.output_tokens = Some(output);
                snap.total_tokens = Some(input + output);
                snap.attribution = Attribution::ProviderAccount;
                snapshots.push(snap);
            }
        }
        Ok(FetchedUsage {
            snapshots,
            attribution: Attribution::ProviderAccount,
            source: "Anthropic Usage Report (organization level)".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Stripe — validate + minimal metadata (livemode).
// ---------------------------------------------------------------------------

pub struct Stripe;

impl Stripe {
    fn balance_request(secret: &SecretString) -> HttpRequest {
        // Stripe uses HTTP Basic auth with the secret key as the username.
        use base64::Engine;
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:", secret.expose()));
        HttpRequest::get("https://api.stripe.com/v1/balance")
            .header("Authorization", format!("Basic {basic}"))
    }
}

impl Connector for Stripe {
    fn id(&self) -> &'static str {
        "stripe"
    }

    fn validate(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<ValidationResult> {
        let resp = http.send(&Self::balance_request(secret))?;
        let detail = if resp.is_success() {
            let live = parse_json(&resp.body)
                .ok()
                .and_then(|j| j.get("livemode").and_then(|v| v.as_bool()))
                .map(|l| if l { "live-mode key" } else { "test-mode key" })
                .unwrap_or("accepted");
            format!("accepted ({live})")
        } else if resp.status == 401 {
            "the key was rejected (401)".to_string()
        } else {
            format!("unexpected status {}", resp.status)
        };
        Ok(ValidationResult {
            valid: resp.is_success(),
            status: resp.status,
            detail,
        })
    }

    fn fetch_metadata(
        &self,
        http: &dyn HttpClient,
        secret: &SecretString,
    ) -> Result<FetchedMetadata> {
        let resp = http.send(&Self::balance_request(secret))?;
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "Stripe status {}",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let mut fields = Vec::new();
        if let Some(live) = json.get("livemode").and_then(|v| v.as_bool()) {
            fields.push(("livemode".to_string(), live.to_string()));
        }
        // Available balance currencies, if present (non-secret).
        if let Some(avail) = json.get("available").and_then(|a| a.as_array()) {
            let currencies: Vec<String> = avail
                .iter()
                .filter_map(|e| {
                    e.get("currency")
                        .and_then(|c| c.as_str())
                        .map(|s| s.to_uppercase())
                })
                .collect();
            if !currencies.is_empty() {
                fields.push(("balance_currencies".to_string(), currencies.join(", ")));
            }
        }
        Ok(FetchedMetadata {
            fields,
            source: "Stripe GET /v1/balance".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Supabase — validate a personal access token + list projects (metadata).
// ---------------------------------------------------------------------------

pub struct Supabase;

impl Supabase {
    fn projects_request(secret: &SecretString) -> HttpRequest {
        HttpRequest::get("https://api.supabase.com/v1/projects")
            .header("Authorization", format!("Bearer {}", secret.expose()))
    }
}

impl Connector for Supabase {
    fn id(&self) -> &'static str {
        "supabase"
    }

    fn validate(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<ValidationResult> {
        // Validates a Supabase personal access token (sbp_...) via the
        // Management API. Project anon/service keys are validated differently
        // (against the project URL), which this connector does not attempt.
        let resp = http.send(&Self::projects_request(secret))?;
        let detail = if resp.is_success() {
            let n = parse_json(&resp.body)
                .ok()
                .and_then(|j| j.as_array().map(|a| a.len()))
                .unwrap_or(0);
            format!("accepted; {n} project(s) visible")
        } else if resp.status == 401 {
            "the token was rejected (401)".to_string()
        } else {
            format!(
                "unexpected status {} (project keys are validated against the project URL)",
                resp.status
            )
        };
        Ok(ValidationResult {
            valid: resp.is_success(),
            status: resp.status,
            detail,
        })
    }

    fn fetch_metadata(
        &self,
        http: &dyn HttpClient,
        secret: &SecretString,
    ) -> Result<FetchedMetadata> {
        let resp = http.send(&Self::projects_request(secret))?;
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "Supabase status {}",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let mut fields = Vec::new();
        if let Some(arr) = json.as_array() {
            fields.push(("project_count".to_string(), arr.len().to_string()));
            let names: Vec<String> = arr
                .iter()
                .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(str::to_string))
                .take(10)
                .collect();
            if !names.is_empty() {
                fields.push(("projects".to_string(), names.join(", ")));
            }
        }
        Ok(FetchedMetadata {
            fields,
            source: "Supabase Management GET /v1/projects".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttpClient;

    const FAKE: &str = "FAKE-TEST-NOT-A-REAL-KEY-000001";

    #[test]
    fn github_validate_parses_login() {
        let mock = MockHttpClient::with(
            200,
            vec![("X-OAuth-Scopes".into(), "repo, read:org".into())],
            r#"{"login":"octocat","id":1}"#,
        );
        let r = GitHub.validate(&mock, &SecretString::from(FAKE)).unwrap();
        assert!(r.valid);
        assert!(r.detail.contains("octocat"));
        // The Authorization header carried the token opaquely.
        let req = mock.last_request().unwrap();
        assert!(req.headers.iter().any(|(k, _)| k == "Authorization"));
    }

    #[test]
    fn github_validate_rejects_401() {
        let mock = MockHttpClient::with(401, vec![], "");
        let r = GitHub.validate(&mock, &SecretString::from(FAKE)).unwrap();
        assert!(!r.valid);
        assert_eq!(r.status, 401);
    }

    #[test]
    fn github_permissions_from_scope_header() {
        let mock = MockHttpClient::with(
            200,
            vec![("X-OAuth-Scopes".into(), "repo, workflow, admin:org".into())],
            r#"{"login":"x"}"#,
        );
        let p = GitHub
            .fetch_permissions(&mock, &SecretString::from(FAKE))
            .unwrap();
        assert_eq!(p.raw_scopes, vec!["repo", "workflow", "admin:org"]);
        assert_eq!(p.precision, "exact_credential");
        assert_eq!(p.confidence, "high");
    }

    #[test]
    fn github_fine_grained_has_no_readable_scopes() {
        let mock = MockHttpClient::with(200, vec![], r#"{"login":"x"}"#);
        let p = GitHub
            .fetch_permissions(&mock, &SecretString::from(FAKE))
            .unwrap();
        assert!(p.raw_scopes.is_empty());
        assert_eq!(p.confidence, "low");
    }

    #[test]
    fn openai_validate_counts_models() {
        let mock = MockHttpClient::json(r#"{"data":[{"id":"gpt-4o"},{"id":"o4-mini"}]}"#);
        let r = OpenAi.validate(&mock, &SecretString::from(FAKE)).unwrap();
        assert!(r.valid);
        assert!(r.detail.contains("2 models"));
    }

    #[test]
    fn openai_usage_parses_org_level_and_is_not_exact() {
        let fixture = r#"{"data":[
            {"start_time":1751328000,"end_time":1751414400,"results":[
                {"input_tokens":1000,"output_tokens":500,"num_model_requests":3}
            ]}
        ]}"#;
        let mock = MockHttpClient::json(fixture);
        let u = OpenAi
            .fetch_usage(&mock, &SecretString::from(FAKE), 7)
            .unwrap();
        assert_eq!(u.attribution, Attribution::ProviderAccount);
        assert_eq!(u.snapshots.len(), 1);
        assert_eq!(u.snapshots[0].input_tokens, Some(1000));
        assert_eq!(u.snapshots[0].total_tokens, Some(1500));
        assert!(!u.attribution.is_exact());
    }

    #[test]
    fn openai_usage_requires_admin_on_401() {
        let mock = MockHttpClient::with(401, vec![], "");
        let err = OpenAi
            .fetch_usage(&mock, &SecretString::from(FAKE), 7)
            .unwrap_err();
        assert!(matches!(err, CoreError::Provider(_)));
    }

    #[test]
    fn stripe_validate_reports_livemode() {
        let mock = MockHttpClient::json(r#"{"livemode":true,"available":[{"currency":"usd"}]}"#);
        let r = Stripe.validate(&mock, &SecretString::from(FAKE)).unwrap();
        assert!(r.valid);
        assert!(r.detail.contains("live-mode"));
    }

    #[test]
    fn unsupported_capabilities_point_to_official_page() {
        let mock = MockHttpClient::json("{}");
        // Stripe permissions are dashboard-only.
        let err = Stripe
            .fetch_permissions(&mock, &SecretString::from(FAKE))
            .unwrap_err();
        match err {
            CoreError::Unsupported {
                provider,
                capability,
                hint,
            } => {
                assert_eq!(provider, "stripe");
                assert_eq!(capability, "read_permissions");
                assert!(hint.contains("stripe.com"));
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn registry_resolves_known_providers() {
        assert!(for_provider("github").is_some());
        assert!(for_provider("OpenAI").is_some());
        assert!(for_provider("unknown").is_none());
    }
}
