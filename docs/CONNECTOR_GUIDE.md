# Provider Connector Development Guide

A connector implements the officially-documented, safely-testable network
calls for one provider. Connectors live in `crates/core/src/connectors.rs` and
implement the `Connector` trait. Everything is testable offline through the
mockable `HttpClient` — **do not require live credentials for builds or tests**.

## 1. Add or update the manifest

Edit `provider-manifests/<id>.toml` (see `docs/CONTRIBUTING.md`). Set each
capability's `support` honestly: only mark a capability `implemented` once your
connector actually performs it and a fixture test covers it. Keep the
`requires_admin_credential` and `attribution` flags accurate.

## 2. Implement the trait

```rust
pub struct MyProvider;

impl Connector for MyProvider {
    fn id(&self) -> &'static str { "myprovider" }

    fn validate(&self, http: &dyn HttpClient, secret: &SecretString) -> Result<ValidationResult> {
        let req = HttpRequest::get("https://api.example.com/v1/whoami")
            .header("Authorization", format!("Bearer {}", secret.expose()));
        let resp = http.send(&req)?;
        Ok(ValidationResult {
            valid: resp.is_success(),
            status: resp.status,
            detail: if resp.is_success() { "accepted".into() } else { "rejected".into() },
        })
    }
    // Override fetch_metadata / fetch_permissions / fetch_usage only for what
    // the provider genuinely supports. The defaults return Unsupported with
    // the official management link.
}
```

Register it in `for_provider()`.

## Rules

- **Never invent capabilities.** If a provider cannot expose usage per key,
  report the coarsest supported level (`Attribution::ProviderAccount` /
  `ProviderProject`) — never `ExactCredential`.
- **Never log or serialize secrets.** The secret is passed in request headers
  only; results are non-secret. `Finding`/metadata/usage structs must not carry
  the plaintext.
- **Use official endpoints and docs.** No undocumented/private APIs.
- **Handle non-2xx as data**, not a hard error — inspect `resp.status`
  (`HttpClient` returns the status; 401 usually means "rejected" or "needs an
  admin key").
- **Bound the response** — the real `UreqClient` caps the body; keep parsers
  defensive (`serde_json::Value`, tolerate missing fields).
- **Permission changes**: only implement if the provider has a safe, documented
  per-key method. Then require reauthentication + explicit confirmation, send
  the request from the device, re-read and verify the result, and record an
  audit event. Otherwise leave it manual.

## 3. Test with fixtures

Add tests using `MockHttpClient::json(...)` / `MockHttpClient::with(status,
headers, body)` with a realistic fixture response. Assert on the parsed result
**and** that the secret never appears in serialized output. Optionally add a
live check behind a `#[ignore]` test that reads a credential from the
environment — never commit a real credential.

## 4. Wire it through the vault

The vault exposes `validate_credential`, `fetch_metadata`, `sync_permissions`,
and `usage_sync` which decrypt in-process and call your connector. Usage sync
records normalized snapshots with your reported attribution and a locally
estimated cost (from `pricing`). No connector code touches the database
directly.

## 5. Detailed sync engines (beyond the trait)

The `Connector` trait covers single-request capabilities. A provider with a
richer official surface can get a dedicated engine module instead —
`crates/core/src/openai.rs` (ADR 0011) is the template: explicit sync
windows, cursor pagination with a page cap, bounded retries honoring
`Retry-After`, typed auth/rate-limit/network errors, grouped dimensions
stored exactly as reported, provider-reported costs kept separate from local
estimates, and fetch-all-then-replace transactional writes so re-syncs never
double-count. The vault dispatches to the engine in `usage_sync_range`; the
generic trait path remains the fallback for everyone else. The same honesty
rules apply — record only the dimensions the response actually contains.
