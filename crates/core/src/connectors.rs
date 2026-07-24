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
    /// Expiration REPORTED BY THE PROVIDER during validation (e.g. GitHub's
    /// token-expiration header), RFC 3339. None when the provider reports
    /// nothing — which is not the same as "never expires".
    pub provider_expires_at: Option<String>,
}

/// Provider-side metadata discovered for a credential (non-secret).
#[derive(Debug, Clone, Serialize)]
pub struct FetchedMetadata {
    pub fields: Vec<(String, String)>,
    pub source: String,
}

/// Provider-account identity fetched from an official endpoint. Only what
/// the provider actually reported is present; nothing is derived from the
/// appearance of a credential, and no login/password material is involved.
#[derive(Debug, Clone, Serialize)]
pub struct AccountInfo {
    /// The provider's own account/organization id.
    pub account_id: Option<String>,
    /// Account email, when the provider reports one.
    pub email: Option<String>,
    /// Account/organization display name or login.
    pub name: Option<String>,
    /// Plan or tier, when the provider reports one.
    pub plan: Option<String>,
    /// The official endpoint this came from.
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

/// A credential newly created at the provider. The value is returned by the
/// provider exactly once, at creation; it goes straight into the vault.
pub struct CreatedCredential {
    pub value: SecretString,
    /// Provider-side id of the new key (for linking and later revocation).
    pub provider_key_id: Option<String>,
    /// Provider-side id of a service account that owns the key, if any.
    pub service_account_id: Option<String>,
    pub provider_project_id: Option<String>,
    pub credential_type: &'static str,
    pub detail: String,
}

/// One provider-side key, as listed by an administrative API (non-secret).
#[derive(Debug, Clone, Serialize)]
pub struct ProviderKeyListing {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: Option<String>,
    /// A redacted hint of the value, when the provider shows one.
    pub redacted_hint: String,
}

/// Parameters for creating a credential at the provider.
#[derive(Debug, Clone)]
pub struct CreateParams {
    pub name: String,
    /// Provider-side project (OpenAI project id, Supabase project ref).
    pub provider_project_id: Option<String>,
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

    /// Fetch the account identity the credential belongs to, where an
    /// official endpoint reports one. Never inferred from the credential's
    /// appearance.
    fn fetch_account(&self, _http: &dyn HttpClient, _secret: &SecretString) -> Result<AccountInfo> {
        Err(self.unsupported("fetch_account"))
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

    /// Create a credential at the provider (admin credential required).
    fn create_credential(
        &self,
        _http: &dyn HttpClient,
        _admin_secret: &SecretString,
        _params: &CreateParams,
    ) -> Result<CreatedCredential> {
        Err(self.unsupported("create_credential"))
    }

    /// Disable (deactivate without deleting) a provider-side key by id.
    fn disable_credential(
        &self,
        _http: &dyn HttpClient,
        _admin_secret: &SecretString,
        _provider_project_id: Option<&str>,
        _provider_key_id: &str,
    ) -> Result<String> {
        Err(self.unsupported("disable_credential"))
    }

    /// Revoke (permanently delete or archive) a provider-side key by id.
    fn revoke_credential(
        &self,
        _http: &dyn HttpClient,
        _admin_secret: &SecretString,
        _provider_project_id: Option<&str>,
        _provider_key_id: &str,
    ) -> Result<String> {
        Err(self.unsupported("revoke_credential"))
    }

    /// List provider-side keys (admin credential required) so the user can
    /// pick the id of an existing key for disable/revoke.
    fn list_keys(
        &self,
        _http: &dyn HttpClient,
        _admin_secret: &SecretString,
        _provider_project_id: Option<&str>,
    ) -> Result<Vec<ProviderKeyListing>> {
        Err(self.unsupported("list_keys"))
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

/// GitHub's expiration header is either RFC 3339 or
/// `YYYY-MM-DD HH:MM:SS UTC`; both are normalized to RFC 3339.
fn parse_github_expiration(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if crate::clock::parse_rfc3339(raw).is_ok() {
        return Some(raw.to_string());
    }
    let cleaned = raw.strip_suffix(" UTC").unwrap_or(raw);
    let fmt = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    time::PrimitiveDateTime::parse(cleaned, &fmt)
        .ok()
        .map(|dt| crate::clock::to_rfc3339(dt.assume_utc()))
}

/// Read the `role` claim from a legacy Supabase JWT (anon / service_role).
/// The claim is the key's own self-description; no verification is implied.
fn legacy_jwt_role(value: &str) -> Option<String> {
    use base64::Engine;
    if !value.starts_with("eyJ") {
        return None;
    }
    let payload = value.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let role = json.get("role")?.as_str()?;
    match role {
        "anon" => Some("anon_key".to_string()),
        "service_role" => Some("service_role_key".to_string()),
        // Unknown roles are shown, but bounded and stripped of anything
        // non-printable (a crafted JWT must not inject terminal escapes).
        other => Some(
            other
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .take(64)
                .collect(),
        ),
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
        let mut detail = if resp.is_success() {
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
        // GitHub reports a token's expiration in an official response header
        // (fine-grained PATs and classic PATs with an expiry). This is a
        // PROVIDER-enforced expiration, recorded verbatim.
        let provider_expires_at = resp
            .header("github-authentication-token-expiration")
            .and_then(parse_github_expiration);
        if let Some(expiry) = &provider_expires_at {
            detail.push_str(&format!("; provider-reported expiration {expiry}"));
        }
        Ok(ValidationResult {
            valid: resp.is_success(),
            status: resp.status,
            detail,
            provider_expires_at,
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

    /// Account identity from the official `GET /user` endpoint. The email
    /// and plan appear only with sufficient scope (classic `user` scope);
    /// absent fields stay absent rather than being guessed.
    fn fetch_account(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<AccountInfo> {
        let resp = http.send(&Self::user_request(secret))?;
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "GitHub returned status {} when fetching the account",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let str_of = |k: &str| {
            json.get(k)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        Ok(AccountInfo {
            account_id: json
                .get("id")
                .and_then(|v| v.as_i64())
                .map(|i| i.to_string()),
            email: str_of("email"),
            name: str_of("login"),
            plan: json
                .get("plan")
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            source: "GitHub GET /user".to_string(),
        })
    }

    /// Metered usage from the Enhanced Billing platform. Requires a
    /// FINE-GRAINED token with "Plan" (read) — classic PATs are not
    /// documented to work; failures say so instead of guessing.
    /// Account-level only, never per token.
    fn fetch_usage(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        _since_days: u32,
    ) -> Result<FetchedUsage> {
        let resp = http.send(&Self::user_request(admin_secret))?;
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "GitHub rejected the token (status {})",
                resp.status
            )));
        }
        let login = parse_json(&resp.body)?
            .get("login")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| CoreError::Provider("GitHub /user returned no login".into()))?;
        let now = crate::clock::now();
        let url = format!(
            "https://api.github.com/users/{login}/settings/billing/usage?year={}&month={}",
            now.year(),
            now.month() as u8
        );
        let req = HttpRequest::get(url)
            .header("Authorization", format!("Bearer {}", admin_secret.expose()))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "tethra");
        let resp = http.send(&req)?;
        if resp.status == 403 || resp.status == 404 {
            return Err(CoreError::Unsupported {
                provider: "github".into(),
                capability: "fetch_usage",
                hint: "the billing usage API needs a FINE-GRAINED token with 'Plan' (read) \
                       permission and the enhanced billing platform; classic PATs are not \
                       documented to work"
                    .into(),
            });
        }
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "GitHub billing usage returned status {}",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let mut snapshots = Vec::new();
        if let Some(items) = json.get("usageItems").and_then(|v| v.as_array()) {
            for item in items {
                let date = item
                    .get("date")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                // Normalize plain dates to RFC 3339 day windows so GitHub
                // rows compare like every other source.
                let window_start = format!("{date}T00:00:00Z");
                let window_end = crate::clock::parse_rfc3339(&window_start)
                    .map(|t| crate::clock::to_rfc3339(t + time::Duration::days(1)))
                    .unwrap_or_else(|_| window_start.clone());
                let mut snap = NewUsageSnapshot::new("github", &window_start, &window_end);
                snap.quantity = item.get("quantity").and_then(|v| v.as_f64());
                snap.unit = item
                    .get("unitType")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                snap.line_item = Some(format!(
                    "{}/{}",
                    item.get("product").and_then(|v| v.as_str()).unwrap_or("?"),
                    item.get("sku").and_then(|v| v.as_str()).unwrap_or("?")
                ));
                if let Some(net) = item.get("netAmount").and_then(|v| v.as_f64()) {
                    snap.reported_cost_micros = Some(crate::usage::micros_from_decimal(net)?);
                }
                snap.source = "github_billing_api".to_string();
                // The billing platform reports per ACCOUNT, never per token.
                snap.attribution = Attribution::ProviderAccount;
                snap.provider_account_id = Some(login.clone());
                snapshots.push(snap);
            }
        }
        Ok(FetchedUsage {
            snapshots,
            attribution: Attribution::ProviderAccount,
            source: "GitHub Enhanced Billing usage (account level, CURRENT billing month \
                     only regardless of the requested window)"
                .to_string(),
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
            provider_expires_at: None,
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

    fn create_credential(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        params: &CreateParams,
    ) -> Result<CreatedCredential> {
        let project_id = params.provider_project_id.as_deref().ok_or_else(|| {
            CoreError::InvalidInput(
                "OpenAI key creation needs a provider project id (see `provider projects`)".into(),
            )
        })?;
        let created = crate::openai::create_service_account_key(
            http,
            admin_secret,
            project_id,
            &params.name,
        )?;
        Ok(CreatedCredential {
            value: created.value,
            provider_key_id: Some(created.api_key_id),
            service_account_id: Some(created.service_account_id),
            provider_project_id: Some(project_id.to_string()),
            credential_type: "service_account_key",
            detail: created.detail,
        })
    }

    fn revoke_credential(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        provider_project_id: Option<&str>,
        provider_key_id: &str,
    ) -> Result<String> {
        let project_id = provider_project_id.ok_or_else(|| {
            CoreError::InvalidInput(
                "OpenAI key deletion needs the provider project id the key belongs to".into(),
            )
        })?;
        crate::openai::delete_project_api_key(http, admin_secret, project_id, provider_key_id)
    }

    fn list_keys(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        provider_project_id: Option<&str>,
    ) -> Result<Vec<ProviderKeyListing>> {
        let projects: Vec<String> = match provider_project_id {
            Some(p) => vec![p.to_string()],
            None => crate::openai::fetch_projects(http, admin_secret)?
                .into_iter()
                .map(|p| p.id)
                .collect(),
        };
        let mut out = Vec::new();
        for project in projects {
            for key in crate::openai::fetch_project_keys(http, admin_secret, &project)? {
                out.push(ProviderKeyListing {
                    id: key.id,
                    name: key.name,
                    status: format!("project {project}"),
                    created_at: key.created_at,
                    redacted_hint: key.redacted_value,
                });
            }
        }
        Ok(out)
    }
}

fn unix_to_time(unix: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(unix).unwrap_or_else(|_| crate::clock::now())
}

// ---------------------------------------------------------------------------
// Anthropic — validate (no admin) + usage (admin, account level) + key
// disable/archive via the Admin API. Keys cannot be CREATED via API
// (console only) and there is no hard delete — archive is the soft revoke.
// ---------------------------------------------------------------------------

pub struct Anthropic;

impl Anthropic {
    fn admin_request(url: &str, admin: &SecretString) -> HttpRequest {
        HttpRequest::get(url)
            .header("x-api-key", admin.expose())
            .header("anthropic-version", "2023-06-01")
    }

    /// `POST /v1/organizations/api_keys/{id}` with a status update — the
    /// documented Admin API way to deactivate/archive a key. `pub(crate)`
    /// so rotation rollback can re-enable a disabled key.
    pub(crate) fn set_key_status(
        http: &dyn HttpClient,
        admin: &SecretString,
        key_id: &str,
        status: &str,
    ) -> Result<String> {
        let url = format!("https://api.anthropic.com/v1/organizations/api_keys/{key_id}");
        let body = serde_json::json!({ "status": status });
        let req = HttpRequest::with_method(crate::http::Method::Post, url)
            .header("x-api-key", admin.expose())
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .body(body.to_string().into_bytes());
        let resp = http.send(&req)?;
        if resp.status == 401 || resp.status == 403 {
            return Err(CoreError::ProviderAuth {
                provider: "anthropic".into(),
                detail: format!(
                    "status {} — an ADMIN key (sk-ant-admin...) is required",
                    resp.status
                ),
            });
        }
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "Anthropic returned status {} updating key {key_id}",
                resp.status
            )));
        }
        let confirmed = parse_json(&resp.body)
            .ok()
            .and_then(|j| j.get("status").and_then(|v| v.as_str()).map(str::to_string));
        match confirmed {
            Some(now) if now == status => Ok(format!("key {key_id} is now '{now}'")),
            Some(now) => Err(CoreError::Provider(format!(
                "Anthropic reports key {key_id} as '{now}', not the requested '{status}'"
            ))),
            None => Err(CoreError::Provider(
                "Anthropic did not confirm the key status".into(),
            )),
        }
    }
}

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
            provider_expires_at: None,
        })
    }

    fn fetch_usage(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        since_days: u32,
    ) -> Result<FetchedUsage> {
        // Anthropic's usage API wants an RFC-3339 `starting_at`, not a Unix
        // timestamp (unlike OpenAI's `start_time`).
        let start_iso = crate::clock::to_rfc3339(unix_to_time(unix_days_ago(since_days)));
        let url = format!(
            "https://api.anthropic.com/v1/organizations/usage_report/messages?starting_at={start_iso}&bucket_width=1d"
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

    fn disable_credential(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        _provider_project_id: Option<&str>,
        provider_key_id: &str,
    ) -> Result<String> {
        Self::set_key_status(http, admin_secret, provider_key_id, "inactive")
    }

    /// Anthropic has no hard delete: `archived` is the documented terminal
    /// state and is reported as such (soft revoke), never as deletion.
    fn revoke_credential(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        _provider_project_id: Option<&str>,
        provider_key_id: &str,
    ) -> Result<String> {
        Self::set_key_status(http, admin_secret, provider_key_id, "archived")
            .map(|d| format!("{d} (soft revoke — Anthropic has no hard delete)"))
    }

    fn list_keys(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        _provider_project_id: Option<&str>,
    ) -> Result<Vec<ProviderKeyListing>> {
        let url = "https://api.anthropic.com/v1/organizations/api_keys?limit=100";
        let resp = http.send(&Self::admin_request(url, admin_secret))?;
        if resp.status == 401 || resp.status == 403 {
            return Err(CoreError::ProviderAuth {
                provider: "anthropic".into(),
                detail: format!(
                    "status {} — an ADMIN key is required to list keys",
                    resp.status
                ),
            });
        }
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "Anthropic returned status {} listing keys",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let mut out = Vec::new();
        if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
            for k in data {
                let Some(id) = k.get("id").and_then(|v| v.as_str()) else {
                    continue;
                };
                out.push(ProviderKeyListing {
                    id: id.to_string(),
                    name: k
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    status: k
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    created_at: k
                        .get("created_at")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    redacted_hint: k
                        .get("partial_key_hint")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                });
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Stripe — validate + minimal metadata (livemode).
// ---------------------------------------------------------------------------

pub struct Stripe;

impl Stripe {
    fn account_request(secret: &SecretString) -> HttpRequest {
        use base64::Engine;
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:", secret.expose()));
        HttpRequest::get("https://api.stripe.com/v1/account")
            .header("Authorization", format!("Basic {basic}"))
    }

    fn balance_request(secret: &SecretString) -> HttpRequest {
        // Stripe uses HTTP Basic auth with the secret key as the username.
        use base64::Engine;
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:", secret.expose()));
        HttpRequest::get("https://api.stripe.com/v1/balance")
            .header("Authorization", format!("Basic {basic}"))
    }
}

impl Stripe {
    fn events_request(secret: &SecretString, url: &str) -> HttpRequest {
        use base64::Engine;
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:", secret.expose()));
        HttpRequest::get(url).header("Authorization", format!("Basic {basic}"))
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
            provider_expires_at: None,
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

    /// Account identity from the official `GET /v1/account` endpoint (the
    /// account the secret key belongs to).
    fn fetch_account(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<AccountInfo> {
        let resp = http.send(&Self::account_request(secret))?;
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "Stripe returned status {} when fetching the account",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let name = json
            .get("business_profile")
            .and_then(|b| b.get("name"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                json.get("settings")
                    .and_then(|s| s.get("dashboard"))
                    .and_then(|d| d.get("display_name"))
                    .and_then(|v| v.as_str())
            })
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        Ok(AccountInfo {
            account_id: json.get("id").and_then(|v| v.as_str()).map(str::to_string),
            email: json
                .get("email")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            name,
            plan: None, // Stripe has no plan concept for API accounts.
            source: "Stripe GET /v1/account".to_string(),
        })
    }

    /// Daily account-activity aggregates from the official Events API
    /// (30-day retention). Stripe has no per-key request-log API — the
    /// dashboard is the only place for that — so this is ACCOUNT-level
    /// activity, recorded in events (never forced into tokens).
    fn fetch_usage(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        since_days: u32,
    ) -> Result<FetchedUsage> {
        let since_days = since_days.min(30); // documented retention
        let created_gte =
            (crate::clock::now() - time::Duration::days(i64::from(since_days))).unix_timestamp();
        const MAX_PAGES: usize = 100;
        let mut counts: std::collections::BTreeMap<(String, String), i64> =
            std::collections::BTreeMap::new();
        let mut starting_after: Option<String> = None;
        let mut pages = 0usize;
        loop {
            pages += 1;
            if pages > MAX_PAGES {
                return Err(CoreError::Provider(format!(
                    "the Stripe events listing exceeded {MAX_PAGES} pages; narrow the window \
                     (events would otherwise be silently truncated)"
                )));
            }
            let mut url =
                format!("https://api.stripe.com/v1/events?limit=100&created[gte]={created_gte}");
            if let Some(cursor) = &starting_after {
                url.push_str(&format!("&starting_after={cursor}"));
            }
            let resp = http.send(&Self::events_request(admin_secret, &url))?;
            if resp.status == 401 {
                return Err(CoreError::Provider(
                    "Stripe rejected the secret key (401)".into(),
                ));
            }
            if !resp.is_success() {
                return Err(CoreError::Provider(format!(
                    "Stripe events returned status {}",
                    resp.status
                )));
            }
            let json = parse_json(&resp.body)?;
            let Some(data) = json.get("data").and_then(|v| v.as_array()) else {
                return Err(CoreError::Provider(
                    "Stripe events response has no data".into(),
                ));
            };
            let mut last_id = None;
            for event in data {
                let Some(created) = event.get("created").and_then(|v| v.as_i64()) else {
                    continue; // no timestamp — cannot bucket honestly
                };
                let day = crate::clock::to_rfc3339(
                    unix_to_time(created).replace_time(time::Time::MIDNIGHT),
                );
                let family = event
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .split('.')
                    .next()
                    .unwrap_or("unknown")
                    .to_string();
                *counts.entry((day, family)).or_insert(0) += 1;
                last_id = event.get("id").and_then(|v| v.as_str()).map(str::to_string);
            }
            let has_more = json
                .get("has_more")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !has_more || last_id.is_none() {
                break;
            }
            starting_after = last_id;
        }
        let mut snapshots = Vec::new();
        for ((day, family), count) in counts {
            let day_end = crate::clock::to_rfc3339(
                crate::clock::parse_rfc3339(&day).unwrap_or_else(|_| crate::clock::now())
                    + time::Duration::days(1),
            );
            let mut snap = NewUsageSnapshot::new("stripe", &day, &day_end);
            snap.quantity = Some(count as f64);
            snap.unit = Some("events".to_string());
            snap.line_item = Some(family);
            snap.source = "stripe_events".to_string();
            snap.attribution = Attribution::ProviderAccount;
            snapshots.push(snap);
        }
        Ok(FetchedUsage {
            snapshots,
            attribution: Attribution::ProviderAccount,
            source: "Stripe Events API (account activity, 30-day retention)".to_string(),
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

    fn bearer(req: HttpRequest, secret: &SecretString) -> HttpRequest {
        req.header("Authorization", format!("Bearer {}", secret.expose()))
    }

    fn need_ref(provider_project_id: Option<&str>) -> Result<&str> {
        provider_project_id.ok_or_else(|| {
            CoreError::InvalidInput(
                "Supabase key operations need the project ref (the id in your project URL)".into(),
            )
        })
    }
}

impl Connector for Supabase {
    fn id(&self) -> &'static str {
        "supabase"
    }

    fn validate(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<ValidationResult> {
        // Only a Supabase personal/management access token (sbp_...) can be
        // validated via the Management API. Project anon/service/sb_secret_
        // keys are validated against the *project* REST URL, which this
        // connector does not have — so we do NOT test them (and must not mark
        // them invalid) and instead report the limitation.
        if !secret.expose().trim_start().starts_with("sbp_") {
            return Err(CoreError::Unsupported {
                provider: "supabase".into(),
                capability: "validate_credential",
                hint: "only a personal access token (sbp_...) can be validated here; project \
                       anon/service keys are validated against your project's REST URL"
                    .into(),
            });
        }
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
            provider_expires_at: None,
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

    /// Organization identity from the official `GET /v1/organizations`
    /// endpoint (personal access token). When the token sees several
    /// organizations, no single id is claimed — the count is reported
    /// instead of guessing which one "the" account is.
    fn fetch_account(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<AccountInfo> {
        let req = HttpRequest::get("https://api.supabase.com/v1/organizations")
            .header("Authorization", format!("Bearer {}", secret.expose()));
        let resp = http.send(&req)?;
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "Supabase returned status {} when listing organizations",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let orgs: Vec<(Option<String>, Option<String>)> = json
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|o| {
                        (
                            o.get("id").and_then(|v| v.as_str()).map(str::to_string),
                            o.get("name").and_then(|v| v.as_str()).map(str::to_string),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (account_id, name) = match orgs.as_slice() {
            [(id, name)] => (id.clone(), name.clone()),
            [] => (None, None),
            many => (None, Some(format!("{} organizations visible", many.len()))),
        };
        Ok(AccountInfo {
            account_id,
            email: None, // the organizations endpoint reports no email
            name,
            plan: None, // plan is not part of the documented listing
            source: "Supabase Management GET /v1/organizations".to_string(),
        })
    }

    /// A Supabase key's privilege is fixed by its TYPE, which the key format
    /// itself declares (documented prefixes; legacy JWTs carry a `role`
    /// claim). No network call is needed — this reads the key's own
    /// self-description, never guessing.
    fn fetch_permissions(
        &self,
        _http: &dyn HttpClient,
        secret: &SecretString,
    ) -> Result<FetchedPermissions> {
        let value = secret.expose().trim();
        let (scope, source) = if value.starts_with("sbp_") {
            ("personal_access_token", "Supabase key format (sbp_ prefix)")
        } else if value.starts_with("sb_secret_") {
            ("secret_key", "Supabase key format (sb_secret_ prefix)")
        } else if value.starts_with("sb_publishable_") {
            (
                "publishable_key",
                "Supabase key format (sb_publishable_ prefix)",
            )
        } else if let Some(role) = legacy_jwt_role(value) {
            return Ok(FetchedPermissions {
                raw_scopes: vec![role],
                precision: "exact_credential".to_string(),
                confidence: "high".to_string(),
                source: "Supabase legacy JWT role claim".to_string(),
            });
        } else {
            return Err(CoreError::Unsupported {
                provider: "supabase".into(),
                capability: "read_permissions",
                hint: "unrecognized key format; check the key type in the dashboard".into(),
            });
        };
        Ok(FetchedPermissions {
            raw_scopes: vec![scope.to_string()],
            precision: "exact_credential".to_string(),
            confidence: "high".to_string(),
            source: source.to_string(),
        })
    }

    /// `POST /v1/projects/{ref}/api-keys` creates a new-format secret key.
    /// Requires a personal access token (sbp_...). The key value is
    /// returned at creation.
    fn create_credential(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        params: &CreateParams,
    ) -> Result<CreatedCredential> {
        let project_ref = Self::need_ref(params.provider_project_id.as_deref())?;
        let url = format!("https://api.supabase.com/v1/projects/{project_ref}/api-keys");
        let body = serde_json::json!({ "type": "secret", "name": params.name });
        let req = Self::bearer(
            HttpRequest::with_method(crate::http::Method::Post, url)
                .header("content-type", "application/json")
                .body(body.to_string().into_bytes()),
            admin_secret,
        );
        let resp = http.send(&req)?;
        if resp.status == 401 || resp.status == 403 {
            return Err(CoreError::ProviderAuth {
                provider: "supabase".into(),
                detail: format!(
                    "status {} — a personal access token is required",
                    resp.status
                ),
            });
        }
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "Supabase returned status {} creating the key",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let value = json
            .get("api_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                CoreError::Provider("the creation response did not include the key value".into())
            })?;
        let id = json.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
            CoreError::Provider("the creation response is missing the key id".into())
        })?;
        Ok(CreatedCredential {
            value: SecretString::new(value.to_string()),
            provider_key_id: Some(id.to_string()),
            service_account_id: None,
            provider_project_id: Some(project_ref.to_string()),
            credential_type: "secret_key",
            detail: format!(
                "created secret key '{}' in project {project_ref}",
                params.name
            ),
        })
    }

    /// `DELETE /v1/projects/{ref}/api-keys/{id}` permanently revokes a
    /// new-format key. Legacy anon/service_role JWTs cannot be revoked this
    /// way (dashboard only).
    fn revoke_credential(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        provider_project_id: Option<&str>,
        provider_key_id: &str,
    ) -> Result<String> {
        let project_ref = Self::need_ref(provider_project_id)?;
        let url = format!(
            "https://api.supabase.com/v1/projects/{project_ref}/api-keys/{provider_key_id}"
        );
        let req = Self::bearer(
            HttpRequest::with_method(crate::http::Method::Delete, url),
            admin_secret,
        );
        let resp = http.send(&req)?;
        if resp.status == 404 {
            // See openai::delete_project_api_key: a 404 is ambiguous between
            // "already deleted" and "wrong id"; never blindly a success.
            return Err(CoreError::NotFound {
                kind: "provider key",
                ident: provider_key_id.to_string(),
            });
        }
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "Supabase returned status {} deleting key {provider_key_id}",
                resp.status
            )));
        }
        Ok(format!("deleted key {provider_key_id}"))
    }

    fn list_keys(
        &self,
        http: &dyn HttpClient,
        admin_secret: &SecretString,
        provider_project_id: Option<&str>,
    ) -> Result<Vec<ProviderKeyListing>> {
        let project_ref = Self::need_ref(provider_project_id)?;
        let url = format!("https://api.supabase.com/v1/projects/{project_ref}/api-keys");
        let resp = http.send(&Self::bearer(HttpRequest::get(url), admin_secret))?;
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "Supabase returned status {} listing keys",
                resp.status
            )));
        }
        let json = parse_json(&resp.body)?;
        let mut out = Vec::new();
        if let Some(arr) = json.as_array() {
            for k in arr {
                let Some(id) = k.get("id").and_then(|v| v.as_str()) else {
                    continue;
                };
                out.push(ProviderKeyListing {
                    id: id.to_string(),
                    name: k
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    status: k
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    created_at: None,
                    redacted_hint: String::new(),
                });
            }
        }
        Ok(out)
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
    fn anthropic_usage_sends_rfc3339_starting_at() {
        let mock = MockHttpClient::json(r#"{"data":[]}"#);
        Anthropic
            .fetch_usage(&mock, &SecretString::from(FAKE), 7)
            .unwrap();
        let url = mock.last_request().unwrap().url;
        // Must be an RFC-3339 datetime, not a bare Unix integer.
        assert!(url.contains("starting_at="));
        let value = url
            .split("starting_at=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        assert!(
            value.contains('T') && value.ends_with('Z'),
            "starting_at was '{value}'"
        );
    }

    #[test]
    fn supabase_does_not_reject_project_keys_as_invalid() {
        let mock = MockHttpClient::json("[]");
        // A service_role JWT is not a PAT — validating it must not return
        // valid=false (which would mark it invalid); it reports Unsupported.
        let err = Supabase
            .validate(&mock, &SecretString::from("eyJhbGciOiJI-service-role-jwt"))
            .unwrap_err();
        assert!(matches!(err, CoreError::Unsupported { .. }));
        // A PAT (sbp_) is validated normally.
        let mock = MockHttpClient::json("[]");
        let r = Supabase
            .validate(&mock, &SecretString::from("sbp_FAKE0000"))
            .unwrap();
        assert!(r.valid);
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

    #[test]
    fn github_billing_usage_preserves_units_and_account_attribution() {
        let mock = MockHttpClient::new(vec![
            MockHttpClient::json_response(r#"{"login":"octo"}"#),
            MockHttpClient::json_response(
                r#"{"usageItems":[
                    {"date":"2026-07-01","product":"actions","sku":"actions_linux",
                     "quantity":120,"unitType":"minutes","pricePerUnit":0.008,
                     "grossAmount":0.96,"discountAmount":0,"netAmount":0.96,
                     "repositoryName":"octo/app"}]}"#,
            ),
        ]);
        let usage = GitHub
            .fetch_usage(
                &mock,
                &SecretString::from("github_pat_FAKE0000000000000000000000000000000000000000000000000000000000000000000000000001"),
                30,
            )
            .unwrap();
        assert_eq!(usage.snapshots.len(), 1);
        let snap = &usage.snapshots[0];
        assert_eq!(snap.quantity, Some(120.0));
        assert_eq!(snap.unit.as_deref(), Some("minutes"));
        assert_eq!(snap.line_item.as_deref(), Some("actions/actions_linux"));
        assert_eq!(snap.reported_cost_micros, Some(960_000)); // $0.96
        assert_eq!(snap.attribution, Attribution::ProviderAccount);
        assert!(
            snap.input_tokens.is_none(),
            "minutes are never forced into tokens"
        );
    }

    #[test]
    fn github_billing_403_explains_fine_grained_requirement() {
        let mock = MockHttpClient::new(vec![
            MockHttpClient::json_response(r#"{"login":"octo"}"#),
            crate::http::HttpResponse {
                status: 403,
                headers: vec![],
                body: b"{}".to_vec(),
            },
        ]);
        let err = GitHub
            .fetch_usage(
                &mock,
                &SecretString::from("ghp_FAKE0000000000000000000000000000000000"),
                30,
            )
            .unwrap_err();
        assert!(err.to_string().contains("FINE-GRAINED"), "{err}");
    }

    #[test]
    fn stripe_events_aggregate_daily_families_with_pagination() {
        let mock = MockHttpClient::new(vec![
            MockHttpClient::json_response(
                r#"{"object":"list","has_more":true,"data":[
                    {"id":"evt_1","type":"charge.succeeded","created":1767225600},
                    {"id":"evt_2","type":"charge.failed","created":1767225700}]}"#,
            ),
            MockHttpClient::json_response(
                r#"{"object":"list","has_more":false,"data":[
                    {"id":"evt_3","type":"customer.created","created":1767312000}]}"#,
            ),
        ]);
        let usage = Stripe
            .fetch_usage(
                &mock,
                &SecretString::from("sk_test_FAKEFAKEFAKEFAKEFAKEFAKE01"),
                30,
            )
            .unwrap();
        // charge x2 on day one, customer x1 on day two.
        assert_eq!(usage.snapshots.len(), 2);
        let charge = usage
            .snapshots
            .iter()
            .find(|s| s.line_item.as_deref() == Some("charge"))
            .unwrap();
        assert_eq!(charge.quantity, Some(2.0));
        assert_eq!(charge.unit.as_deref(), Some("events"));
        assert_eq!(charge.attribution, Attribution::ProviderAccount);
        // The cursor was passed on page two.
        let requests = mock.requests.borrow();
        assert!(requests[1].url.contains("starting_after=evt_2"));
    }
}
