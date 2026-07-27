//! Route-origin trust: separating *detection evidence* from *authorization
//! to send API traffic somewhere* (ADR 0024).
//!
//! The audit's second blocking finding was that a repository containing no
//! secret at all — just a committed `package.json` and a committed
//! `SUPABASE_URL` — caused Tethra to create a MAC-authenticated, enabled
//! route from the user's local gateway to an attacker-chosen host, and to
//! rewrite the app's `.env` so its credential flowed through it. The
//! security document promised "an explicit checkbox (never part of
//! Confirmed auto-config)". The CLI had no checkbox at all, and the desktop
//! shipped it pre-checked with the origin pre-filled (ZFT-004).
//!
//! The gateway's transport defences were never the problem: `validate_origin`
//! correctly refused loopback, plaintext HTTP, private networks and cloud
//! metadata, and still does. What regressed is *provenance* — the one input
//! those defences cannot judge. A host can be perfectly well-formed, public,
//! HTTPS and still be the attacker's.
//!
//! ## The trust model
//!
//! Project content may *suggest* that an API exists. It may never *authorize*
//! Tethra to forward credentials to an arbitrary destination.
//!
//! * [`OriginTrust::BuiltInManifest`] — the origin is a compiled-in value
//!   from a Tethra provider manifest. The repository cannot influence it, so
//!   it may be configured automatically. This is what keeps the
//!   zero-friction promise intact for OpenAI, Anthropic and the rest.
//! * [`OriginTrust::PreviouslyApproved`] — this exact origin was approved by
//!   this user before and is recorded in authenticated vault state. It may be
//!   reused without asking again. Any change to the origin voids it.
//! * [`OriginTrust::RepositoryDiscovered`] — read out of project content.
//!   Never enabled without a deliberate, per-origin decision. `--yes` does
//!   not grant it and a general "Start tracking" click does not either.
//!
//! ## Tamper evidence
//!
//! An approval is only worth as much as its storage. Each record carries a
//! keyed BLAKE3 MAC over its identity fields, computed with the vault's
//! route MAC key — the same key the gateway already uses to bind
//! custom-origin routes. A row edited in `vault.db` fails verification and
//! is treated as absent, so tampering downgrades to "ask the user again"
//! rather than to "silently trusted".

use api_tracker_core::secret::SecretBytes;
use api_tracker_core::{clock, CoreError, Result};
use api_tracker_gateway::routes;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Why a destination may (or may not) be configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OriginTrust {
    /// Shipped in a Tethra provider manifest. Automatic.
    BuiltInManifest,
    /// This exact origin was approved before, by this user, in this vault.
    PreviouslyApproved { approved_at: String },
    /// Read from project content. Requires explicit approval.
    RepositoryDiscovered,
}

impl OriginTrust {
    /// Whether Tethra may create and enable a route to this origin without
    /// asking. The single place that decision is made.
    pub fn may_configure_without_asking(&self) -> bool {
        match self {
            OriginTrust::BuiltInManifest => true,
            OriginTrust::PreviouslyApproved { .. } => true,
            OriginTrust::RepositoryDiscovered => false,
        }
    }
}

/// How a destination is reachable. Shown at the consent point so the user
/// can tell `api.openai.com` from `internal.corp.example`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkClass {
    /// A public, routable host.
    Public,
    /// Loopback, private, link-local or cloud-metadata. The gateway refuses
    /// these outright; the classification exists so a refusal can explain
    /// itself instead of just failing.
    Restricted,
}

/// Everything a user needs in order to decide whether to allow one
/// destination. Assembled once and rendered identically by the CLI and the
/// desktop, so the two consent surfaces cannot drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginApprovalRequest {
    pub provider_id: String,
    pub provider_display_name: String,
    /// The full origin, exactly as it will be registered.
    pub origin: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub network_class: NetworkClass,
    /// Which project file the origin was read from, and under which
    /// variable — the "why Tethra detected it" the user needs to judge it.
    pub source_file: Option<String>,
    pub source_var: Option<String>,
    /// Whether approving this means a stored credential will be forwarded
    /// to that host.
    pub forwards_credentials: bool,
    pub trust: OriginTrust,
}

impl OriginApprovalRequest {
    /// The one-line question, in the product's own vocabulary. Used by both
    /// the CLI prompt and the desktop checkbox label.
    pub fn question(&self) -> String {
        format!(
            "Allow this project to send API traffic through {}?",
            self.origin
        )
    }

    /// The disclosure lines shown under the question, in a fixed order.
    pub fn disclosure(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.push(format!(
            "Destination: {} (host {}, port {})",
            self.origin, self.host, self.port
        ));
        out.push(format!("Provider: {}", self.provider_display_name));
        match (&self.source_var, &self.source_file) {
            (Some(var), Some(file)) => out.push(format!(
                "Why Tethra suggests it: {var} in {file} — this value comes from the project, \
                 not from Tethra"
            )),
            _ => out.push(
                "Why Tethra suggests it: read from this project's configuration, not from Tethra"
                    .to_string(),
            ),
        }
        out.push(if self.forwards_credentials {
            "If you allow it, requests carrying this project's API credential will be forwarded \
             to that host."
                .to_string()
        } else {
            "Requests will be forwarded to that host.".to_string()
        });
        out.push(match self.network_class {
            NetworkClass::Public => "The host is a public internet address.".to_string(),
            NetworkClass::Restricted => {
                "The host is loopback, private or otherwise restricted — Tethra will refuse it."
                    .to_string()
            }
        });
        out
    }
}

/// Build the approval request for one repository-discovered origin.
///
/// Returns an error when the origin fails the gateway's unchanged
/// destination policy, so a refusal happens before the user is asked to
/// approve something that could never work.
pub fn describe(
    provider_id: &str,
    provider_display_name: &str,
    origin: &str,
    source_file: Option<&str>,
    source_var: Option<&str>,
    forwards_credentials: bool,
    trust: OriginTrust,
) -> Result<OriginApprovalRequest> {
    let (host, port) = routes::validate_origin(origin)?;
    Ok(OriginApprovalRequest {
        provider_id: provider_id.to_string(),
        provider_display_name: provider_display_name.to_string(),
        origin: origin.to_string(),
        scheme: "https".to_string(),
        host,
        port,
        // `validate_origin` already refused everything non-public, so
        // reaching here means the host passed the destination policy.
        network_class: NetworkClass::Public,
        source_file: source_file.map(str::to_string),
        source_var: source_var.map(str::to_string),
        forwards_credentials,
        trust,
    })
}

// ---------------------------------------------------------------------------
// The approval store
// ---------------------------------------------------------------------------

/// Canonical form for comparison and storage.
///
/// Approval is granted for one exact destination. Case-folding the host is
/// the only normalization applied — anything more would let a different
/// destination match an approval the user never gave.
pub fn canonicalize(origin: &str) -> Result<String> {
    let (host, port) = routes::validate_origin(origin)?;
    Ok(format!("https://{host}:{port}"))
}

/// Keyed MAC over an approval's identity fields, in the same
/// length-prefixed, domain-separated shape the gateway uses for route MACs
/// (`routes::route_mac`). Changing ANY field in the database invalidates it.
fn approval_mac(
    key: &SecretBytes,
    vault_id: &str,
    canonical: &str,
    provider_id: &str,
    at: &str,
) -> Result<String> {
    let key: &[u8; 32] = key.expose().try_into().map_err(|_| CoreError::Crypto {
        context: "gateway MAC key length",
    })?;
    let mut message = Vec::with_capacity(128);
    message.extend_from_slice(b"tethra:origin-approval-mac:v1");
    for field in [vault_id, canonical, provider_id, at] {
        message.extend_from_slice(&(field.len() as u64).to_le_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    Ok(blake3::keyed_hash(key, &message).to_hex().to_string())
}

/// One stored approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovedOrigin {
    pub origin: String,
    pub provider_id: String,
    pub approved_at: String,
}

/// Record the user's approval of one exact origin.
///
/// `mac_key` is the vault's route MAC key, so recording an approval
/// requires an unlocked vault — the same bar as creating the route itself.
pub fn approve(
    conn: &Connection,
    vault_id: &str,
    mac_key: &SecretBytes,
    origin: &str,
    provider_id: &str,
) -> Result<ApprovedOrigin> {
    let canonical = canonicalize(origin)?;
    let at = clock::now_rfc3339();
    let mac = approval_mac(mac_key, vault_id, &canonical, provider_id, &at)?;
    conn.execute(
        "INSERT INTO tracking_approved_origins (origin, provider_id, approved_at, mac)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(origin, provider_id) DO UPDATE SET
             approved_at = excluded.approved_at,
             mac = excluded.mac",
        params![canonical, provider_id, at, mac],
    )?;
    Ok(ApprovedOrigin {
        origin: canonical,
        provider_id: provider_id.to_string(),
        approved_at: at,
    })
}

/// Whether this exact origin is already approved for this provider.
///
/// A row whose MAC does not verify is treated as ABSENT: tampering with
/// `vault.db` downgrades to "ask again", never to "silently trusted".
pub fn is_approved(
    conn: &Connection,
    vault_id: &str,
    mac_key: &SecretBytes,
    origin: &str,
    provider_id: &str,
) -> Result<Option<ApprovedOrigin>> {
    let Ok(canonical) = canonicalize(origin) else {
        return Ok(None);
    };
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT approved_at, mac FROM tracking_approved_origins
             WHERE origin = ?1 AND provider_id = ?2",
            params![canonical, provider_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((approved_at, stored_mac)) = row else {
        return Ok(None);
    };
    let expected = approval_mac(mac_key, vault_id, &canonical, provider_id, &approved_at)?;
    // Constant-time comparison: the MAC is a secret-derived value.
    use subtle::ConstantTimeEq;
    if expected.as_bytes().ct_eq(stored_mac.as_bytes()).unwrap_u8() != 1 {
        return Ok(None);
    }
    Ok(Some(ApprovedOrigin {
        origin: canonical,
        provider_id: provider_id.to_string(),
        approved_at,
    }))
}

/// Every approval this vault holds, for the settings surface. Rows whose
/// MAC does not verify are reported as tampered rather than hidden.
pub fn list(
    conn: &Connection,
    vault_id: &str,
    mac_key: &SecretBytes,
) -> Result<(Vec<ApprovedOrigin>, usize)> {
    let mut stmt = conn.prepare(
        "SELECT origin, provider_id, approved_at, mac FROM tracking_approved_origins
         ORDER BY approved_at DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    let mut tampered = 0usize;
    use subtle::ConstantTimeEq;
    for row in rows {
        let (origin, provider_id, approved_at, mac) = row?;
        let expected = approval_mac(mac_key, vault_id, &origin, &provider_id, &approved_at)?;
        if expected.as_bytes().ct_eq(mac.as_bytes()).unwrap_u8() == 1 {
            out.push(ApprovedOrigin {
                origin,
                provider_id,
                approved_at,
            });
        } else {
            tampered += 1;
        }
    }
    Ok((out, tampered))
}

/// Withdraw an approval.
pub fn revoke(conn: &Connection, origin: &str, provider_id: &str) -> Result<bool> {
    let canonical = canonicalize(origin).unwrap_or_else(|_| origin.to_string());
    let n = conn.execute(
        "DELETE FROM tracking_approved_origins WHERE origin = ?1 AND provider_id = ?2",
        params![canonical, provider_id],
    )?;
    Ok(n > 0)
}

/// The refusal message used when a non-interactive caller reaches an
/// unapproved repository-discovered origin.
///
/// One shared string so the CLI, the desktop and the docs cannot describe
/// the rule differently.
pub fn refusal(origin: &str, provider_id: &str) -> CoreError {
    CoreError::InvalidInput(format!(
        "'{provider_id}' would send API traffic to {origin}, a destination read from this \
         project's own files rather than from Tethra. Approving a destination is a separate \
         decision from approving the setup, so --yes does not grant it. Re-run interactively, \
         or pass --allow-origin {origin} to approve exactly this destination."
    ))
}
