//! Destination adapters: where credential VALUES are deployed.
//!
//! A **provider** connector (`connectors.rs`) manages a credential at its
//! issuer (validate, usage, metadata). A **destination** adapter manages
//! where the value is *deployed* (a CI secret store, a cloud secret manager,
//! the OS keychain, an exported `.env` file). The two are deliberately
//! separate systems.
//!
//! Honesty rules mirror the provider catalog: every destination kind reports
//! its capabilities explicitly, nothing is claimed that is not implemented,
//! and all requests go directly from the local machine. Destination
//! administrative credentials (cloud keys, tokens) are stored encrypted in
//! the vault and never logged or displayed.

use crate::error::{CoreError, Result};
use crate::http::{HttpClient, HttpRequest, Method};
use crate::secret::SecretString;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use uuid::Uuid;

/// Support level for one destination capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestSupport {
    Implemented,
    /// The destination offers it, Tethra does not implement it yet.
    SupportedNotImplemented,
    /// The destination itself cannot do this.
    Unsupported,
    /// Implemented, but not on this platform.
    PlatformUnavailable,
}

/// The explicit capability matrix every destination kind must report.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct DestCapabilities {
    /// Read the stored value back (for drift verification).
    pub read: DestSupport,
    /// Create or update the stored value.
    pub write: DestSupport,
    /// Remove the stored value.
    pub delete: DestSupport,
    /// The destination keeps its own version history.
    pub versioning: DestSupport,
    /// A failed/unwanted write can be rolled back (destination-side history
    /// or a re-write of the locally retained previous version).
    pub rollback: DestSupport,
    /// A write can be verified afterwards (value read-back or existence).
    pub validation: DestSupport,
}

/// Static description of a destination kind.
#[derive(Debug, Clone, Serialize)]
pub struct DestinationKindInfo {
    pub kind: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// What authentication the destination needs (honest, specific).
    pub auth: &'static str,
    pub platforms: &'static str,
    /// Current implementation status, in plain words.
    pub status: &'static str,
    pub capabilities: DestCapabilities,
    /// How a write is verified: value read-back or existence only.
    pub verify_method: &'static str,
    /// Plan/tier the destination requires, if any.
    pub required_plan: &'static str,
    /// Possible charges from using this destination.
    pub charges: &'static str,
    /// Automated-test coverage status (fixtures vs live).
    pub testing: &'static str,
    /// Required configuration fields for `destination add`.
    pub config_help: &'static str,
}

/// All destination kinds, implemented or not — the catalog never overstates.
pub fn catalog() -> &'static [DestinationKindInfo] {
    const IMPL: DestSupport = DestSupport::Implemented;
    const UNSUP: DestSupport = DestSupport::Unsupported;
    static CATALOG: &[DestinationKindInfo] = &[
        DestinationKindInfo {
            kind: "vault",
            name: "Tethra local vault",
            description: "The encrypted local vault itself — the source of truth every plan starts from.",
            auth: "master password (already required)",
            platforms: "all",
            status: "always present; not configurable as a target",
            capabilities: DestCapabilities {
                read: IMPL,
                write: IMPL,
                delete: IMPL,
                versioning: IMPL,
                rollback: IMPL,
                validation: IMPL,
            },
            verify_method: "value read-back (it is the source of truth)",
            required_plan: "none",
            charges: "none",
            testing: "covered by the full core test suite",
            config_help: "none — the vault is implicit",
        },
        DestinationKindInfo {
            kind: "env_mapping",
            name: "Local environment mappings",
            description: "Injection mappings used by `api-tracker run`. They reference the vault at run time, so a value change needs no write here.",
            auth: "none (local)",
            platforms: "all",
            status: "implemented; value changes propagate automatically at injection time",
            capabilities: DestCapabilities {
                read: UNSUP,
                write: IMPL,
                delete: IMPL,
                versioning: UNSUP,
                rollback: UNSUP,
                validation: IMPL,
            },
            verify_method: "n/a — resolved from the vault at injection time",
            required_plan: "none",
            charges: "none",
            testing: "covered by injection tests",
            config_help: "none — managed via `api-tracker mapping`",
        },
        DestinationKindInfo {
            kind: "env_export",
            name: "Exported .env file",
            description: "A plaintext .env file previously written by `api-tracker env export`. Value changes require an explicit re-export.",
            auth: "master password reauthentication per export",
            platforms: "all",
            status: "implemented; tracked per exported file with drift detection",
            capabilities: DestCapabilities {
                read: IMPL,
                write: IMPL,
                delete: IMPL,
                versioning: UNSUP,
                rollback: IMPL,
                validation: IMPL,
            },
            verify_method: "value read-back (file re-read + fingerprint compare)",
            required_plan: "none",
            charges: "none",
            testing: "covered by env-governance tests",
            config_help: "none — created by `api-tracker env export`",
        },
        DestinationKindInfo {
            kind: "macos_keychain",
            name: "macOS Keychain",
            description: "Generic passwords in the login keychain via the system `security` tool.",
            auth: "none beyond the OS session (Keychain may prompt)",
            platforms: "macOS only",
            status: if cfg!(target_os = "macos") {
                "implemented on this platform"
            } else {
                "implemented, but unavailable on this platform"
            },
            capabilities: DestCapabilities {
                read: if cfg!(target_os = "macos") {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
                write: if cfg!(target_os = "macos") {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
                delete: if cfg!(target_os = "macos") {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
                versioning: UNSUP,
                rollback: IMPL,
                validation: if cfg!(target_os = "macos") {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
            },
            verify_method: "value read-back via the security tool",
            required_plan: "none",
            charges: "none",
            testing: "fixture-tested through a scripted runner; exercised on macOS",
            config_help: "optional: account (default 'api-tracker')",
        },
        DestinationKindInfo {
            kind: "linux_secret_service",
            name: "Linux Secret Service",
            description: "Items in the session Secret Service (GNOME Keyring / KWallet) via libsecret's secret-tool; the value is passed on stdin, never as an argument.",
            auth: "none beyond the OS session (the keyring may prompt to unlock)",
            platforms: "Linux only (needs secret-tool and a session Secret Service)",
            status: if cfg!(target_os = "linux") {
                "implemented on this platform (needs the libsecret-tools package)"
            } else {
                "implemented, but unavailable on this platform"
            },
            capabilities: DestCapabilities {
                read: if cfg!(target_os = "linux") {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
                write: if cfg!(target_os = "linux") {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
                delete: if cfg!(target_os = "linux") {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
                versioning: UNSUP,
                rollback: IMPL,
                validation: if cfg!(target_os = "linux") {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
            },
            verify_method: "value read-back via secret-tool lookup",
            required_plan: "none",
            charges: "none",
            testing: "fixture-tested through a scripted runner; not yet exercised against a live Secret Service",
            config_help: "optional: service (default 'api-tracker')",
        },
        DestinationKindInfo {
            kind: "windows_credential_manager",
            name: "Windows Credential Manager",
            description: "Generic credentials for the current user via the Win32 credential API (CredWrite/CredRead/CredDelete).",
            auth: "none beyond the Windows session (current-user store)",
            platforms: "Windows only",
            status: if cfg!(windows) {
                "implemented on this platform (compile-verified; not yet exercised by CI on Windows)"
            } else {
                "implemented, but unavailable on this platform"
            },
            capabilities: DestCapabilities {
                read: if cfg!(windows) {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
                write: if cfg!(windows) {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
                delete: if cfg!(windows) {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
                versioning: UNSUP,
                rollback: IMPL,
                validation: if cfg!(windows) {
                    DestSupport::Implemented
                } else {
                    DestSupport::PlatformUnavailable
                },
            },
            verify_method: "value read-back via CredRead",
            required_plan: "none",
            charges: "none",
            testing: "portable naming logic unit-tested; the keyring-backed adapter compiles and core tests run on Windows in CI, not yet exercised against a live Credential Manager by CI",
            config_help: "none",
        },
        DestinationKindInfo {
            kind: "aws_secrets_manager",
            name: "AWS Secrets Manager",
            description: "Secrets in AWS Secrets Manager via the official API (SigV4-signed, direct from this machine).",
            auth: "IAM access key id + secret access key (stored encrypted in the vault); needs secretsmanager:GetSecretValue/PutSecretValue/CreateSecret/DescribeSecret",
            platforms: "all",
            status: "implemented (delete schedules the 30-day recovery window; RestoreSecret can cancel); verified against recorded API fixtures, not yet against a live AWS account",
            capabilities: DestCapabilities {
                read: IMPL,
                write: IMPL,
                delete: IMPL, // DeleteSecret with the 30-day recovery window
                versioning: IMPL,
                rollback: IMPL,
                validation: IMPL,
            },
            verify_method: "value read-back (GetSecretValue + fingerprint compare)",
            required_plan: "any AWS account",
            charges: "AWS Secrets Manager bills ~$0.40/secret/month (prorated) + $0.05 per 10k API calls",
            testing: "fixture-tested incl. the official SigV4 vector; live verification via scripts/live_verify_aws.sh (opt-in)",
            config_help: "region (e.g. us-east-1)",
        },
        DestinationKindInfo {
            kind: "github_actions",
            name: "GitHub Actions repository secrets",
            description: "Repository secrets via the official REST API (libsodium sealed-box encryption to the repository public key).",
            auth: "fine-grained PAT or classic token with repo admin:secrets access (stored encrypted in the vault)",
            platforms: "all",
            status: "implemented; GitHub never returns secret values, so verification is existence-only",
            capabilities: DestCapabilities {
                read: UNSUP,
                write: IMPL,
                delete: IMPL,
                versioning: UNSUP,
                rollback: IMPL,
                validation: IMPL,
            },
            verify_method: "existence only (GitHub never returns secret values)",
            required_plan: "any plan (private repos need admin access to the repo)",
            charges: "none",
            testing: "fixture-tested; live verification via scripts/live_verify_github_actions.sh (opt-in)",
            config_help: "owner, repo",
        },
        DestinationKindInfo {
            kind: "vercel",
            name: "Vercel environment variables",
            description: "Project environment variables via the official Vercel REST API.",
            auth: "Vercel access token (stored encrypted in the vault)",
            platforms: "all",
            status: "implemented; encrypted variables are write-only at Vercel, so verification is existence-only",
            capabilities: DestCapabilities {
                read: UNSUP,
                write: IMPL,
                delete: IMPL,
                versioning: UNSUP,
                rollback: IMPL,
                validation: IMPL,
            },
            verify_method: "existence only (encrypted variables are write-only at Vercel)",
            required_plan: "any plan",
            charges: "none",
            testing: "fixture-tested; live verification via scripts/live_verify_vercel.sh (opt-in)",
            config_help: "project_id; optional: team_id, targets (default production,preview,development)",
        },
    ];
    CATALOG
}

pub fn kind_info(kind: &str) -> Result<&'static DestinationKindInfo> {
    catalog()
        .iter()
        .find(|k| k.kind == kind)
        .ok_or_else(|| CoreError::InvalidInput(format!("unknown destination kind '{kind}'")))
}

/// Destination kinds the user can configure with `destination add`.
pub fn configurable_kinds() -> Vec<&'static str> {
    catalog()
        .iter()
        .filter(|k| !matches!(k.kind, "vault" | "env_mapping" | "env_export"))
        .map(|k| k.kind)
        .collect()
}

// ---------------------------------------------------------------------------
// Configured destinations (rows in `destinations`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Destination {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub config: serde_json::Value,
    pub auth_masked: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_verified_at: Option<String>,
    pub last_error: String,
}

fn dest_from_row(r: &Row<'_>) -> rusqlite::Result<Destination> {
    let config_raw: String = r.get(3)?;
    Ok(Destination {
        id: r.get(0)?,
        kind: r.get(1)?,
        name: r.get(2)?,
        config: serde_json::from_str(&config_raw).unwrap_or(serde_json::Value::Null),
        auth_masked: r.get(4)?,
        created_at: r.get(5)?,
        updated_at: r.get(6)?,
        last_verified_at: r.get(7)?,
        last_error: r.get(8)?,
    })
}

const DEST_COLUMNS: &str =
    "id, kind, name, config, auth_masked, created_at, updated_at, last_verified_at, last_error";

pub fn insert(
    conn: &Connection,
    kind: &str,
    name: &str,
    config: &serde_json::Value,
    auth_ciphertext: Option<&[u8]>,
    auth_masked: Option<&str>,
) -> Result<String> {
    kind_info(kind)?;
    if !configurable_kinds().contains(&kind) {
        return Err(CoreError::InvalidInput(format!(
            "'{kind}' is a built-in local destination and cannot be added manually"
        )));
    }
    let id = Uuid::new_v4().to_string();
    let now = crate::clock::now_rfc3339();
    conn.execute(
        "INSERT INTO destinations (id, kind, name, config, auth_ciphertext, auth_masked, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![id, kind, name, config.to_string(), auth_ciphertext, auth_masked, now],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            CoreError::AlreadyExists {
                kind: "destination",
                ident: name.to_string(),
            }
        }
        other => other.into(),
    })?;
    Ok(id)
}

pub fn list(conn: &Connection) -> Result<Vec<Destination>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {DEST_COLUMNS} FROM destinations ORDER BY name"
    ))?;
    let rows = stmt.query_map([], dest_from_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn get(conn: &Connection, ident: &str) -> Result<Destination> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {DEST_COLUMNS} FROM destinations WHERE id = ?1 OR name = ?1 COLLATE NOCASE"
    ))?;
    stmt.query_row([ident], dest_from_row)
        .optional()?
        .ok_or_else(|| CoreError::NotFound {
            kind: "destination",
            ident: ident.to_string(),
        })
}

pub fn auth_ciphertext(conn: &Connection, id: &str) -> Result<Option<Vec<u8>>> {
    Ok(conn.query_row(
        "SELECT auth_ciphertext FROM destinations WHERE id = ?1",
        [id],
        |r| r.get(0),
    )?)
}

pub fn remove(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM destinations WHERE id = ?1", [id])?;
    Ok(())
}

pub fn record_test(conn: &Connection, id: &str, error: Option<&str>) -> Result<()> {
    let now = crate::clock::now_rfc3339();
    match error {
        None => conn.execute(
            "UPDATE destinations SET last_verified_at = ?1, last_error = '', updated_at = ?1
             WHERE id = ?2",
            params![now, id],
        )?,
        Some(e) => conn.execute(
            "UPDATE destinations SET last_error = ?1, updated_at = ?2 WHERE id = ?3",
            params![e, now, id],
        )?,
    };
    Ok(())
}

/// A credential attached to a destination under a secret name.
#[derive(Debug, Clone, Serialize)]
pub struct Attachment {
    pub credential_id: String,
    pub credential_name: String,
    pub project_name: String,
    pub destination_id: String,
    pub destination_name: String,
    pub destination_kind: String,
    pub secret_name: String,
    pub environment: String,
    pub last_synced_version: Option<i64>,
    pub last_synced_at: Option<String>,
    pub last_verified_at: Option<String>,
    pub drift: String,
}

/// A conservative secret-name shape every implemented destination accepts
/// (GitHub: alphanumeric/underscore; Vercel: env-var names; AWS and the
/// keychain are broader). Also keeps names inert inside URL paths.
pub fn valid_secret_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false)
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn attach(
    conn: &Connection,
    credential_id: &str,
    destination_id: &str,
    secret_name: &str,
    environment: &str,
) -> Result<()> {
    if !valid_secret_name(secret_name) {
        return Err(CoreError::InvalidInput(format!(
            "'{secret_name}' is not a valid secret name (letters, digits, '_', starting with \
             a letter or '_')"
        )));
    }
    conn.execute(
        "INSERT INTO credential_destinations (credential_id, destination_id, secret_name, environment)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (credential_id, destination_id, secret_name)
         DO UPDATE SET environment = excluded.environment",
        params![credential_id, destination_id, secret_name, environment],
    )?;
    Ok(())
}

pub fn detach(
    conn: &Connection,
    credential_id: &str,
    destination_id: &str,
    secret_name: Option<&str>,
) -> Result<usize> {
    let n = match secret_name {
        Some(name) => conn.execute(
            "DELETE FROM credential_destinations
             WHERE credential_id = ?1 AND destination_id = ?2 AND secret_name = ?3",
            params![credential_id, destination_id, name],
        )?,
        None => conn.execute(
            "DELETE FROM credential_destinations
             WHERE credential_id = ?1 AND destination_id = ?2",
            params![credential_id, destination_id],
        )?,
    };
    Ok(n)
}

const ATTACHMENT_QUERY: &str =
    "SELECT cd.credential_id, c.name, p.name, cd.destination_id, d.name, d.kind,
        cd.secret_name, cd.environment, cd.last_synced_version, cd.last_synced_at,
        cd.last_verified_at, cd.drift
 FROM credential_destinations cd
 JOIN credentials c ON c.id = cd.credential_id
 JOIN projects p ON p.id = c.project_id
 JOIN destinations d ON d.id = cd.destination_id";

fn attachment_from_row(r: &Row<'_>) -> rusqlite::Result<Attachment> {
    Ok(Attachment {
        credential_id: r.get(0)?,
        credential_name: r.get(1)?,
        project_name: r.get(2)?,
        destination_id: r.get(3)?,
        destination_name: r.get(4)?,
        destination_kind: r.get(5)?,
        secret_name: r.get(6)?,
        environment: r.get(7)?,
        last_synced_version: r.get(8)?,
        last_synced_at: r.get(9)?,
        last_verified_at: r.get(10)?,
        drift: r.get(11)?,
    })
}

pub fn attachments_for_credential(
    conn: &Connection,
    credential_id: &str,
) -> Result<Vec<Attachment>> {
    let mut stmt = conn.prepare(&format!(
        "{ATTACHMENT_QUERY} WHERE cd.credential_id = ?1 ORDER BY d.name, cd.secret_name"
    ))?;
    let rows = stmt.query_map([credential_id], attachment_from_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn all_attachments(conn: &Connection) -> Result<Vec<Attachment>> {
    let mut stmt = conn.prepare(&format!(
        "{ATTACHMENT_QUERY} ORDER BY d.name, cd.secret_name"
    ))?;
    let rows = stmt.query_map([], attachment_from_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn record_sync(
    conn: &Connection,
    credential_id: &str,
    destination_id: &str,
    secret_name: &str,
    version: i64,
    drift: &str,
) -> Result<()> {
    let now = crate::clock::now_rfc3339();
    conn.execute(
        "UPDATE credential_destinations
         SET last_synced_version = ?1, last_synced_at = ?2, drift = ?3
         WHERE credential_id = ?4 AND destination_id = ?5 AND secret_name = ?6",
        params![
            version,
            now,
            drift,
            credential_id,
            destination_id,
            secret_name
        ],
    )?;
    Ok(())
}

pub fn record_verify(
    conn: &Connection,
    credential_id: &str,
    destination_id: &str,
    secret_name: &str,
    drift: &str,
) -> Result<()> {
    let now = crate::clock::now_rfc3339();
    if drift == "unknown" {
        // The check reached no verdict: record that the state is unknown,
        // but never advance `last_verified_at` — a failed check must not
        // masquerade as a fresh verification (DEST-03).
        conn.execute(
            "UPDATE credential_destinations
             SET drift = ?1
             WHERE credential_id = ?2 AND destination_id = ?3 AND secret_name = ?4",
            params![drift, credential_id, destination_id, secret_name],
        )?;
        return Ok(());
    }
    conn.execute(
        "UPDATE credential_destinations
         SET last_verified_at = ?1, drift = ?2
         WHERE credential_id = ?3 AND destination_id = ?4 AND secret_name = ?5",
        params![now, drift, credential_id, destination_id, secret_name],
    )?;
    Ok(())
}

/// One attachment's result from a drift check: the (refreshed) attachment
/// plus whether THIS run actually checked it. `checked == false` means the
/// destination could not be loaded or its adapter could not be constructed;
/// the attachment's stored drift/verified timestamps are prior state, not
/// fresh verification (DEST-03). Serialized flat so the attachment fields
/// stay top-level for existing consumers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DriftCheckOutcome {
    #[serde(flatten)]
    pub attachment: Attachment,
    pub checked: bool,
    /// Why the check could not run (no secret material ever included).
    pub check_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Adapter trait
// ---------------------------------------------------------------------------

/// Runtime interface every remote/OS destination implements. Local kinds
/// (`vault`, `env_mapping`, `env_export`) are handled by the vault directly.
pub trait DestinationAdapter {
    fn kind(&self) -> &'static str;
    /// Create or update the named secret. Returns a short receipt note.
    fn write(&self, secret_name: &str, value: &SecretString) -> Result<String>;
    /// Read the stored value back, where the destination supports it.
    /// `Ok(None)` means the destination is write-only (not an error).
    fn read(&self, secret_name: &str) -> Result<Option<SecretString>>;
    /// Whether the named secret exists; `Ok(None)` when undeterminable.
    fn exists(&self, secret_name: &str) -> Result<Option<bool>>;
    fn delete(&self, secret_name: &str) -> Result<()>;
    /// Verify authentication/reachability. Returns a human detail line.
    fn test(&self) -> Result<String>;
}

/// Runs external commands (the macOS `security` tool) — mockable for tests.
pub trait CommandRunner {
    /// Run `program` with `args`, optionally writing `stdin`. Returns
    /// (exit code, stdout, stderr). Implementations must never log inputs.
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)>;
}

pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new(program)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CoreError::InvalidInput(format!("could not run {program}: {e}")))?;
        if let (Some(mut handle), Some(bytes)) = (child.stdin.take(), stdin) {
            handle.write_all(bytes)?;
            drop(handle);
        }
        let out = child.wait_with_output()?;
        Ok((out.status.code().unwrap_or(-1), out.stdout, out.stderr))
    }
}

// ---------------------------------------------------------------------------
// macOS Keychain (generic passwords via `security`)
// ---------------------------------------------------------------------------

pub struct MacKeychainDestination<'a> {
    pub runner: &'a dyn CommandRunner,
    /// Keychain account name; the secret name becomes the service.
    pub account: String,
}

fn keychain_quote(value: &str) -> Result<String> {
    if value.chars().any(|c| c.is_control()) {
        return Err(CoreError::InvalidInput(
            "values with control characters cannot be stored via the security tool".into(),
        ));
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(CoreError::InvalidInput(format!(
            "'{name}' is not a safe secret name (letters, digits, '_', '-', '.')"
        )));
    }
    Ok(())
}

impl DestinationAdapter for MacKeychainDestination<'_> {
    fn kind(&self) -> &'static str {
        "macos_keychain"
    }

    fn write(&self, secret_name: &str, value: &SecretString) -> Result<String> {
        check_name(secret_name)?;
        check_name(&self.account)?;
        // `security -i` reads commands from stdin, so the value never appears
        // in the process argument list (visible via `ps`).
        let command = format!(
            "add-generic-password -U -s {} -a {} -w {}\n",
            keychain_quote(secret_name)?,
            keychain_quote(&self.account)?,
            keychain_quote(value.expose())?,
        );
        let (code, _out, err) = self
            .runner
            .run("security", &["-i"], Some(command.as_bytes()))?;
        if code != 0 {
            return Err(CoreError::Provider(format!(
                "security add-generic-password failed (exit {code}): {}",
                String::from_utf8_lossy(&err).trim()
            )));
        }
        Ok(format!(
            "stored keychain item service={secret_name} account={}",
            self.account
        ))
    }

    fn read(&self, secret_name: &str) -> Result<Option<SecretString>> {
        check_name(secret_name)?;
        check_name(&self.account)?;
        let (code, out, _err) = self.runner.run(
            "security",
            &[
                "find-generic-password",
                "-s",
                secret_name,
                "-a",
                &self.account,
                "-w",
            ],
            None,
        )?;
        // 44 = errSecItemNotFound. Anything else nonzero (locked keychain,
        // denied prompt) is an ERROR, not "absent" — conflating them would
        // record false `missing` drift for a present secret.
        if code == 44 {
            return Ok(Some(SecretString::new(String::new()))); // absent
        }
        if code != 0 {
            return Err(CoreError::Provider(format!(
                "security find-generic-password failed (exit {code}); is the keychain locked?"
            )));
        }
        let value = String::from_utf8_lossy(&out)
            .trim_end_matches('\n')
            .to_string();
        Ok(Some(SecretString::new(value)))
    }

    fn exists(&self, secret_name: &str) -> Result<Option<bool>> {
        check_name(secret_name)?;
        check_name(&self.account)?;
        let (code, _out, _err) = self.runner.run(
            "security",
            &[
                "find-generic-password",
                "-s",
                secret_name,
                "-a",
                &self.account,
            ],
            None,
        )?;
        match code {
            0 => Ok(Some(true)),
            44 => Ok(Some(false)),
            other => Err(CoreError::Provider(format!(
                "security find-generic-password failed (exit {other}); is the keychain locked?"
            ))),
        }
    }

    fn delete(&self, secret_name: &str) -> Result<()> {
        check_name(secret_name)?;
        check_name(&self.account)?;
        let (code, _out, err) = self.runner.run(
            "security",
            &[
                "delete-generic-password",
                "-s",
                secret_name,
                "-a",
                &self.account,
            ],
            None,
        )?;
        if code != 0 {
            return Err(CoreError::Provider(format!(
                "security delete-generic-password failed (exit {code}): {}",
                String::from_utf8_lossy(&err).trim()
            )));
        }
        Ok(())
    }

    fn test(&self) -> Result<String> {
        let (code, _out, _err) = self.runner.run("security", &["list-keychains"], None)?;
        if code != 0 {
            return Err(CoreError::Provider(
                "the security tool is not usable in this session".into(),
            ));
        }
        Ok("security tool reachable; keychain access will prompt as needed".into())
    }
}

// ---------------------------------------------------------------------------
// Linux Secret Service (freedesktop.org) via the `secret-tool` CLI
// ---------------------------------------------------------------------------

/// Secrets in the session's Secret Service (GNOME Keyring / KWallet with
/// the freedesktop bridge) through `secret-tool` from libsecret. The value
/// is passed on **stdin** (secret-tool's documented store mode), never as
/// an argument. Items are keyed by `service`/`secret` attributes.
pub struct SecretServiceDestination<'a> {
    pub runner: &'a dyn CommandRunner,
    /// The `service` attribute grouping this app's items.
    pub service: String,
}

impl SecretServiceDestination<'_> {
    fn attrs<'x>(&'x self, secret_name: &'x str) -> [&'x str; 4] {
        ["service", &self.service, "secret", secret_name]
    }
}

impl DestinationAdapter for SecretServiceDestination<'_> {
    fn kind(&self) -> &'static str {
        "linux_secret_service"
    }

    fn write(&self, secret_name: &str, value: &SecretString) -> Result<String> {
        check_name(secret_name)?;
        check_name(&self.service)?;
        let label = format!("--label={}/{}", self.service, secret_name);
        let a = self.attrs(secret_name);
        let args = ["store", &label, a[0], a[1], a[2], a[3]];
        // The value goes to secret-tool on stdin (its documented
        // non-interactive mode) so it never appears in an argument list.
        let (code, _out, err) =
            self.runner
                .run("secret-tool", &args, Some(value.expose().as_bytes()))?;
        if code != 0 {
            return Err(CoreError::Provider(format!(
                "secret-tool store failed (exit {code}): {}",
                String::from_utf8_lossy(&err).trim()
            )));
        }
        Ok(format!(
            "stored Secret Service item {}/{secret_name}",
            self.service
        ))
    }

    fn read(&self, secret_name: &str) -> Result<Option<SecretString>> {
        check_name(secret_name)?;
        check_name(&self.service)?;
        let a = self.attrs(secret_name);
        let (code, out, err) =
            self.runner
                .run("secret-tool", &["lookup", a[0], a[1], a[2], a[3]], None)?;
        if code == 0 {
            let value = String::from_utf8_lossy(&out)
                .trim_end_matches('\n')
                .to_string();
            return Ok(Some(SecretString::new(value)));
        }
        // secret-tool exits nonzero both for "not found" (silently) and for
        // real failures (locked collection, no session bus — with stderr).
        // Distinguish on stderr so a locked keyring is never misreported as
        // an absent secret.
        let err_text = String::from_utf8_lossy(&err).trim().to_string();
        if err_text.is_empty() {
            return Ok(Some(SecretString::new(String::new()))); // absent
        }
        Err(CoreError::Provider(format!(
            "secret-tool lookup failed (exit {code}): {err_text}"
        )))
    }

    fn exists(&self, secret_name: &str) -> Result<Option<bool>> {
        let value = self.read(secret_name)?;
        Ok(value.map(|v| !v.expose().is_empty()))
    }

    fn delete(&self, secret_name: &str) -> Result<()> {
        check_name(secret_name)?;
        check_name(&self.service)?;
        let a = self.attrs(secret_name);
        let (code, _out, err) =
            self.runner
                .run("secret-tool", &["clear", a[0], a[1], a[2], a[3]], None)?;
        let err_text = String::from_utf8_lossy(&err).trim().to_string();
        // Clearing an absent item is success (idempotent); real failures
        // carry stderr.
        if code != 0 && !err_text.is_empty() {
            return Err(CoreError::Provider(format!(
                "secret-tool clear failed (exit {code}): {err_text}"
            )));
        }
        Ok(())
    }

    fn test(&self) -> Result<String> {
        check_name(&self.service)?;
        let (code, _out, err) =
            self.runner
                .run("secret-tool", &["search", "service", &self.service], None)?;
        let err_text = String::from_utf8_lossy(&err).trim().to_string();
        if code != 0 && !err_text.is_empty() {
            return Err(CoreError::Provider(format!(
                "the Secret Service is not reachable (exit {code}): {err_text}"
            )));
        }
        Ok("secret-tool reachable; the session Secret Service will prompt as needed".into())
    }
}

// ---------------------------------------------------------------------------
// Windows Credential Manager (generic credentials via the Win32 API)
// ---------------------------------------------------------------------------

/// Build (and validate) the Credential Manager target name for a secret.
/// Portable so the naming contract is unit-tested on every platform.
pub fn wincred_target(secret_name: &str) -> Result<String> {
    check_name(secret_name)?;
    Ok(format!("api-tracker/{secret_name}"))
}

/// Generic credentials in the current user's Windows Credential Manager
/// (CredWrite/CredRead/CredDelete under the hood). The Win32 FFI lives in
/// the audited `keyring` crate — this crate stays `forbid(unsafe_code)`.
/// Compiled only on Windows; the catalog reports the kind as
/// platform-unavailable elsewhere.
#[cfg(windows)]
pub struct WindowsCredentialDestination;

#[cfg(windows)]
impl WindowsCredentialDestination {
    fn entry(secret_name: &str) -> Result<keyring::Entry> {
        let target = wincred_target(secret_name)?;
        keyring::Entry::new(&target, "api-tracker")
            .map_err(|e| CoreError::Provider(format!("Credential Manager entry failed: {e}")))
    }
}

#[cfg(windows)]
impl DestinationAdapter for WindowsCredentialDestination {
    fn kind(&self) -> &'static str {
        "windows_credential_manager"
    }

    fn write(&self, secret_name: &str, value: &SecretString) -> Result<String> {
        Self::entry(secret_name)?
            .set_password(value.expose())
            .map_err(|e| CoreError::Provider(format!("Credential Manager write failed: {e}")))?;
        Ok(format!(
            "stored Credential Manager entry {}",
            wincred_target(secret_name)?
        ))
    }

    fn read(&self, secret_name: &str) -> Result<Option<SecretString>> {
        match Self::entry(secret_name)?.get_password() {
            Ok(v) => Ok(Some(SecretString::new(v))),
            Err(keyring::Error::NoEntry) => Ok(Some(SecretString::new(String::new()))),
            Err(e) => Err(CoreError::Provider(format!(
                "Credential Manager read failed: {e}"
            ))),
        }
    }

    fn exists(&self, secret_name: &str) -> Result<Option<bool>> {
        let value = self.read(secret_name)?;
        Ok(value.map(|v| !v.expose().is_empty()))
    }

    fn delete(&self, secret_name: &str) -> Result<()> {
        match Self::entry(secret_name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()), // idempotent
            Err(e) => Err(CoreError::Provider(format!(
                "Credential Manager delete failed: {e}"
            ))),
        }
    }

    fn test(&self) -> Result<String> {
        // Reading a definitely-absent probe entry proves the API is
        // reachable without creating anything.
        self.read("api-tracker-availability-probe")?;
        Ok("Windows Credential Manager reachable for this user".into())
    }
}

// ---------------------------------------------------------------------------
// AWS Secrets Manager (SigV4-signed official API)
// ---------------------------------------------------------------------------

pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    pub session_token: Option<SecretString>,
}

impl AwsCredentials {
    /// Parse the encrypted auth payload:
    /// `{"access_key_id":"...","secret_access_key":"...","session_token":null}`.
    pub fn from_json(raw: &SecretString) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct Raw {
            access_key_id: String,
            secret_access_key: String,
            #[serde(default)]
            session_token: Option<String>,
        }
        let parsed: Raw = serde_json::from_str(raw.expose()).map_err(|_| {
            CoreError::InvalidInput(
                "AWS auth must be JSON with access_key_id and secret_access_key".into(),
            )
        })?;
        Ok(Self {
            access_key_id: parsed.access_key_id,
            secret_access_key: SecretString::new(parsed.secret_access_key),
            session_token: parsed.session_token.map(SecretString::new),
        })
    }
}

/// AWS Signature Version 4 (HMAC-SHA256), per the official signing process.
pub mod sigv4 {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn sha256_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    /// Split an https URL into (host, path, query).
    fn split_url(url: &str) -> Result<(String, String, String)> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| CoreError::InvalidInput("sigv4: only https URLs".into()))?;
        let (host, path_query) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (path, query) = match path_query.find('?') {
            Some(i) => (&path_query[..i], &path_query[i + 1..]),
            None => (path_query, ""),
        };
        Ok((host.to_string(), path.to_string(), query.to_string()))
    }

    fn canonical_query(query: &str) -> String {
        if query.is_empty() {
            return String::new();
        }
        let mut pairs: Vec<&str> = query.split('&').collect();
        pairs.sort_unstable();
        pairs.join("&")
    }

    /// Sign `req` in place, adding `x-amz-date`, optional
    /// `x-amz-security-token`, and `authorization` headers.
    pub fn sign(
        req: &mut HttpRequest,
        creds: &AwsCredentials,
        region: &str,
        service: &str,
        timestamp: time::OffsetDateTime,
    ) -> Result<()> {
        let amz_date = timestamp
            .format(&time::format_description::well_known::Iso8601::DATE_TIME)
            .ok()
            .and_then(|_| {
                // AWS wants the compact form YYYYMMDD'T'HHMMSS'Z'.
                let f =
                    time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");
                timestamp.format(&f).ok()
            })
            .ok_or_else(|| CoreError::InvalidInput("sigv4: bad timestamp".into()))?;
        let date_stamp = &amz_date[..8];

        let (host, path, query) = split_url(&req.url)?;
        let payload_hash = sha256_hex(req.body.as_deref().unwrap_or(b""));

        // Canonical headers: host + x-amz-date (+ security token) + any
        // existing content-type / x-amz-target headers, lowercased, sorted.
        let mut headers: Vec<(String, String)> = vec![
            ("host".into(), host.clone()),
            ("x-amz-date".into(), amz_date.clone()),
        ];
        for (name, value) in &req.headers {
            let lower = name.to_ascii_lowercase();
            if lower == "content-type" || lower.starts_with("x-amz-") {
                headers.push((lower, value.trim().to_string()));
            }
        }
        if let Some(token) = &creds.session_token {
            headers.push(("x-amz-security-token".into(), token.expose().to_string()));
        }
        headers.sort();
        let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let signed_headers: String = headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");

        let method = match req.method {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        };
        let canonical_request = format!(
            "{method}\n{path}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            canonical_query(&query)
        );
        let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );

        let k_date = hmac(
            format!("AWS4{}", creds.secret_access_key.expose()).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac(&k_date, region.as_bytes());
        let k_service = hmac(&k_region, service.as_bytes());
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            creds.access_key_id
        );
        req.headers.push(("x-amz-date".into(), amz_date));
        if let Some(token) = &creds.session_token {
            req.headers
                .push(("x-amz-security-token".into(), token.expose().to_string()));
        }
        req.headers.push(("authorization".into(), authorization));
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The documented AWS SigV4 example: GET iam ListUsers with the
        /// published example credentials and timestamp. The expected
        /// signature is the one in the official signing walkthrough.
        #[test]
        fn matches_the_official_iam_example_vector() {
            let creds = AwsCredentials {
                access_key_id: "AKIDEXAMPLE".into(),
                secret_access_key: SecretString::new(
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
                ),
                session_token: None,
            };
            let mut req = HttpRequest::with_method(
                Method::Get,
                "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
            )
            .header(
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            );
            let ts = time::macros::datetime!(2015-08-30 12:36:00 UTC);
            sign(&mut req, &creds, "us-east-1", "iam", ts).unwrap();
            let auth = req
                .headers
                .iter()
                .find(|(k, _)| k == "authorization")
                .map(|(_, v)| v.clone())
                .unwrap();
            assert!(
                auth.contains(
                    "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
                ),
                "got: {auth}"
            );
            assert!(auth.contains("SignedHeaders=content-type;host;x-amz-date"));
        }

        #[test]
        fn signature_never_contains_the_secret_key() {
            let creds = AwsCredentials {
                access_key_id: "AKIDEXAMPLE".into(),
                secret_access_key: SecretString::new("FAKEFAKEFAKEFAKEFAKEFAKE".into()),
                session_token: None,
            };
            let mut req = HttpRequest::with_method(
                Method::Post,
                "https://secretsmanager.us-east-1.amazonaws.com/",
            )
            .body(b"{}".to_vec());
            sign(
                &mut req,
                &creds,
                "us-east-1",
                "secretsmanager",
                time::macros::datetime!(2026-01-01 0:00:00 UTC),
            )
            .unwrap();
            let all = format!("{:?}", req.headers);
            assert!(!all.contains("FAKEFAKEFAKEFAKEFAKEFAKE"));
        }
    }
}

pub struct AwsSecretsManagerDestination<'a> {
    pub http: &'a dyn HttpClient,
    pub creds: AwsCredentials,
    pub region: String,
}

/// An AWS region is `[a-z0-9-]+` (e.g. `us-east-1`). The region is
/// interpolated into the request AUTHORITY, so a value carrying a URL
/// delimiter (`/`, `?`, `#`, `@`, `:`) could otherwise steer the connection
/// — and the plaintext secret and session token it carries — to another
/// host. Reject anything that is not a plain region label.
fn valid_aws_region(region: &str) -> bool {
    !region.is_empty()
        && region.len() <= 64
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl AwsSecretsManagerDestination<'_> {
    fn call(&self, target: &str, body: serde_json::Value) -> Result<HttpResponse2> {
        if !valid_aws_region(&self.region) {
            return Err(CoreError::InvalidInput(format!(
                "invalid AWS region {:?}: expected a plain region label like us-east-1",
                self.region
            )));
        }
        let url = format!("https://secretsmanager.{}.amazonaws.com/", self.region);
        let mut req = HttpRequest::with_method(Method::Post, url)
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-target", format!("secretsmanager.{target}"))
            .body(body.to_string().into_bytes());
        sigv4::sign(
            &mut req,
            &self.creds,
            &self.region,
            "secretsmanager",
            crate::clock::now(),
        )?;
        let resp = self.http.send(&req)?;
        let parsed: serde_json::Value =
            serde_json::from_slice(&resp.body).unwrap_or(serde_json::Value::Null);
        Ok(HttpResponse2 {
            status: resp.status,
            json: parsed,
        })
    }
}

/// A parsed JSON response (internal helper).
pub struct HttpResponse2 {
    pub status: u16,
    pub json: serde_json::Value,
}

impl HttpResponse2 {
    fn error_type(&self) -> &str {
        self.json
            .get("__type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }
}

impl DestinationAdapter for AwsSecretsManagerDestination<'_> {
    fn kind(&self) -> &'static str {
        "aws_secrets_manager"
    }

    fn write(&self, secret_name: &str, value: &SecretString) -> Result<String> {
        let resp = self.call(
            "PutSecretValue",
            serde_json::json!({ "SecretId": secret_name, "SecretString": value.expose() }),
        )?;
        if resp.status == 400 && resp.error_type().contains("ResourceNotFoundException") {
            let created = self.call(
                "CreateSecret",
                serde_json::json!({ "Name": secret_name, "SecretString": value.expose() }),
            )?;
            if !(200..300).contains(&created.status) {
                return Err(CoreError::Provider(format!(
                    "CreateSecret failed ({}): {}",
                    created.status,
                    created.error_type()
                )));
            }
            return Ok(format!("created secret '{secret_name}'"));
        }
        if !(200..300).contains(&resp.status) {
            if resp.status == 403 {
                return Err(CoreError::ProviderAuth {
                    provider: "aws_secrets_manager".into(),
                    detail: resp.error_type().to_string(),
                });
            }
            return Err(CoreError::Provider(format!(
                "PutSecretValue failed ({}): {}",
                resp.status,
                resp.error_type()
            )));
        }
        let version = resp
            .json
            .get("VersionId")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        Ok(format!(
            "put new version {version} of secret '{secret_name}'"
        ))
    }

    fn read(&self, secret_name: &str) -> Result<Option<SecretString>> {
        let resp = self.call(
            "GetSecretValue",
            serde_json::json!({ "SecretId": secret_name }),
        )?;
        if resp.status == 400 && resp.error_type().contains("ResourceNotFoundException") {
            return Ok(Some(SecretString::new(String::new())));
        }
        if !(200..300).contains(&resp.status) {
            return Err(CoreError::Provider(format!(
                "GetSecretValue failed ({}): {}",
                resp.status,
                resp.error_type()
            )));
        }
        Ok(resp
            .json
            .get("SecretString")
            .and_then(|v| v.as_str())
            .map(|s| SecretString::new(s.to_string())))
    }

    fn exists(&self, secret_name: &str) -> Result<Option<bool>> {
        let resp = self.call(
            "DescribeSecret",
            serde_json::json!({ "SecretId": secret_name }),
        )?;
        // Only ResourceNotFoundException is a definitive "absent"; a 2xx is
        // a definitive "present". Access denial, throttling, server errors,
        // and unrecognized responses are ERRORS, never absence (DEST-01).
        if resp.status == 400 && resp.error_type().contains("ResourceNotFoundException") {
            return Ok(Some(false));
        }
        if (200..300).contains(&resp.status) {
            return Ok(Some(true));
        }
        if resp.status == 403 {
            return Err(CoreError::ProviderAuth {
                provider: "aws_secrets_manager".into(),
                detail: resp.error_type().to_string(),
            });
        }
        Err(CoreError::Provider(format!(
            "DescribeSecret failed ({}): {}; existence is undetermined",
            resp.status,
            resp.error_type()
        )))
    }

    /// Schedule deletion with the default 30-day recovery window (the AWS
    /// default). The secret is recoverable via RestoreSecret until the
    /// DeletionDate; `ForceDeleteWithoutRecovery` is deliberately never
    /// sent — an irreversible immediate delete has no place in an
    /// automated path. Deleting an already-absent secret succeeds
    /// (idempotent), matching the other adapters.
    fn delete(&self, secret_name: &str) -> Result<()> {
        let resp = self.call(
            "DeleteSecret",
            serde_json::json!({ "SecretId": secret_name, "RecoveryWindowInDays": 30 }),
        )?;
        if resp.status == 400 && resp.error_type().contains("ResourceNotFoundException") {
            return Ok(());
        }
        if resp.status == 403 {
            return Err(CoreError::ProviderAuth {
                provider: "aws_secrets_manager".into(),
                detail: resp.error_type().to_string(),
            });
        }
        if !(200..300).contains(&resp.status) {
            return Err(CoreError::Provider(format!(
                "DeleteSecret failed ({}): {}",
                resp.status,
                resp.error_type()
            )));
        }
        Ok(())
    }

    fn test(&self) -> Result<String> {
        let resp = self.call("ListSecrets", serde_json::json!({ "MaxResults": 1 }))?;
        if resp.status == 403 {
            return Err(CoreError::ProviderAuth {
                provider: "aws_secrets_manager".into(),
                detail: resp.error_type().to_string(),
            });
        }
        if !(200..300).contains(&resp.status) {
            return Err(CoreError::Provider(format!(
                "ListSecrets failed ({}): {}",
                resp.status,
                resp.error_type()
            )));
        }
        Ok(format!(
            "authenticated to Secrets Manager in {}",
            self.region
        ))
    }
}

// ---------------------------------------------------------------------------
// GitHub Actions repository secrets
// ---------------------------------------------------------------------------

pub struct GithubActionsDestination<'a> {
    pub http: &'a dyn HttpClient,
    pub token: SecretString,
    pub owner: String,
    pub repo: String,
}

impl GithubActionsDestination<'_> {
    fn request(&self, method: Method, path: &str) -> HttpRequest {
        HttpRequest::with_method(
            method,
            format!(
                "https://api.github.com/repos/{}/{}{path}",
                self.owner, self.repo
            ),
        )
        .header("authorization", format!("Bearer {}", self.token.expose()))
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", "2022-11-28")
        .header("user-agent", "api-tracker")
    }

    /// Encrypt `value` to the repository public key with a libsodium sealed
    /// box (the format the GitHub API requires).
    fn seal(&self, public_key_b64: &str, value: &SecretString) -> Result<String> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let key_bytes: Vec<u8> = engine.decode(public_key_b64).map_err(|_| {
            CoreError::Provider("GitHub returned an invalid repository public key".into())
        })?;
        let key: [u8; 32] = key_bytes.try_into().map_err(|_| {
            CoreError::Provider("GitHub repository public key is not 32 bytes".into())
        })?;
        let pk = crypto_box::PublicKey::from(key);
        let sealed = pk
            .seal(&mut crypto_box::aead::OsRng, value.expose().as_bytes())
            .map_err(|_| CoreError::Provider("sealed-box encryption failed".into()))?;
        Ok(engine.encode(sealed))
    }
}

impl DestinationAdapter for GithubActionsDestination<'_> {
    fn kind(&self) -> &'static str {
        "github_actions"
    }

    fn write(&self, secret_name: &str, value: &SecretString) -> Result<String> {
        let resp = self
            .http
            .send(&self.request(Method::Get, "/actions/secrets/public-key"))?;
        if resp.status == 401 || resp.status == 403 {
            return Err(CoreError::ProviderAuth {
                provider: "github_actions".into(),
                detail: format!("status {}", resp.status),
            });
        }
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "could not fetch the repository public key (status {})",
                resp.status
            )));
        }
        let parsed: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|_| CoreError::Provider("invalid public-key response".into()))?;
        let key_id = parsed
            .get("key_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CoreError::Provider("public-key response missing key_id".into()))?;
        let key = parsed
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CoreError::Provider("public-key response missing key".into()))?;
        let encrypted = self.seal(key, value)?;
        let body = serde_json::json!({ "encrypted_value": encrypted, "key_id": key_id });
        let put = self
            .request(Method::Put, &format!("/actions/secrets/{secret_name}"))
            .header("content-type", "application/json")
            .body(body.to_string().into_bytes());
        let resp = self.http.send(&put)?;
        match resp.status {
            201 => Ok(format!("created repository secret '{secret_name}'")),
            204 => Ok(format!("updated repository secret '{secret_name}'")),
            401 | 403 => Err(CoreError::ProviderAuth {
                provider: "github_actions".into(),
                detail: format!("status {}", resp.status),
            }),
            other => Err(CoreError::Provider(format!(
                "storing the secret failed (status {other})"
            ))),
        }
    }

    fn read(&self, _secret_name: &str) -> Result<Option<SecretString>> {
        Ok(None) // GitHub never returns secret values.
    }

    fn exists(&self, secret_name: &str) -> Result<Option<bool>> {
        let resp = self
            .http
            .send(&self.request(Method::Get, &format!("/actions/secrets/{secret_name}")))?;
        // Only definitive answers become existence verdicts: 2xx = present,
        // 404 = absent. Auth, rate-limit, and server failures are ERRORS —
        // converting them into "absent" produced false `missing` drift
        // (DEST-01) and invited destructive re-writes.
        match resp.status {
            s if (200..300).contains(&s) => Ok(Some(true)),
            404 => Ok(Some(false)),
            401 | 403 => Err(CoreError::ProviderAuth {
                provider: "github_actions".into(),
                detail: format!("status {}", resp.status),
            }),
            other => Err(CoreError::Provider(format!(
                "checking the secret failed (status {other}); existence is undetermined"
            ))),
        }
    }

    fn delete(&self, secret_name: &str) -> Result<()> {
        let resp = self
            .http
            .send(&self.request(Method::Delete, &format!("/actions/secrets/{secret_name}")))?;
        if resp.status == 204 || resp.status == 404 {
            return Ok(());
        }
        Err(CoreError::Provider(format!(
            "deleting the secret failed (status {})",
            resp.status
        )))
    }

    fn test(&self) -> Result<String> {
        let resp = self
            .http
            .send(&self.request(Method::Get, "/actions/secrets/public-key"))?;
        match resp.status {
            200 => Ok(format!(
                "authenticated; can manage secrets on {}/{}",
                self.owner, self.repo
            )),
            401 | 403 => Err(CoreError::ProviderAuth {
                provider: "github_actions".into(),
                detail: format!("status {}", resp.status),
            }),
            404 => Err(CoreError::Provider(
                "repository not found (or the token cannot see it)".into(),
            )),
            other => Err(CoreError::Provider(format!("unexpected status {other}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Vercel project environment variables
// ---------------------------------------------------------------------------

pub struct VercelDestination<'a> {
    pub http: &'a dyn HttpClient,
    pub token: SecretString,
    pub project_id: String,
    pub team_id: Option<String>,
    pub targets: Vec<String>,
}

impl VercelDestination<'_> {
    fn url(&self, path: &str) -> String {
        let mut url = format!("https://api.vercel.com{path}");
        if let Some(team) = &self.team_id {
            url.push_str(if path.contains('?') { "&" } else { "?" });
            url.push_str(&format!("teamId={team}"));
        }
        url
    }

    fn request(&self, method: Method, url: String) -> HttpRequest {
        HttpRequest::with_method(method, url)
            .header("authorization", format!("Bearer {}", self.token.expose()))
            .header("content-type", "application/json")
    }

    /// Resolve THIS destination's variable: the entry whose key matches AND
    /// whose target set equals the destination's configured targets AND
    /// which is not scoped to a custom environment. A Vercel project can
    /// hold several variables with the same key for different targets —
    /// key-only matching once deleted or "verified" whichever the API
    /// listed first (DEST-02). Returns:
    /// - `Ok(Some(id))` — exactly one matching identity
    /// - `Ok(None)` with `other_targets == false` — no variable with the key
    /// - `Err` on transport/HTTP/parse failure or ambiguity
    fn resolve_env_identity(&self, secret_name: &str) -> Result<VercelResolution> {
        let resp = self.http.send(&self.request(
            Method::Get,
            self.url(&format!("/v9/projects/{}/env", self.project_id)),
        ))?;
        if !resp.is_success() {
            return Err(CoreError::Provider(format!(
                "listing environment variables failed (status {})",
                resp.status
            )));
        }
        let parsed: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|_| CoreError::Provider("invalid env list response".into()))?;
        let empty = Vec::new();
        let envs = parsed
            .get("envs")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty);
        let mut want: Vec<&str> = self.targets.iter().map(|s| s.as_str()).collect();
        want.sort_unstable();

        let mut exact: Vec<String> = Vec::new();
        let mut key_matches = 0usize;
        for entry in envs {
            if entry.get("key").and_then(|k| k.as_str()) != Some(secret_name) {
                continue;
            }
            key_matches += 1;
            // A variable scoped to a custom environment is a different
            // identity even when its standard targets line up.
            let custom_scoped = entry
                .get("customEnvironmentIds")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            if custom_scoped {
                continue;
            }
            let mut targets: Vec<&str> = entry
                .get("target")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
                .unwrap_or_default();
            targets.sort_unstable();
            if targets == want {
                if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
                    exact.push(id.to_string());
                }
            }
        }
        match exact.len() {
            0 => Ok(VercelResolution {
                id: None,
                other_targets: key_matches > 0,
            }),
            1 => Ok(VercelResolution {
                id: exact.into_iter().next(),
                other_targets: false,
            }),
            n => Err(CoreError::Provider(format!(
                "'{secret_name}' is ambiguous: {n} variables share this key AND \
                 target set; refusing to guess which one is this destination's"
            ))),
        }
    }
}

/// Outcome of resolving a Vercel variable identity.
struct VercelResolution {
    /// The uniquely matching variable id, when one exists.
    id: Option<String>,
    /// The key exists in the project, but only for OTHER targets or custom
    /// environments — a different identity this destination must not touch.
    other_targets: bool,
}

impl DestinationAdapter for VercelDestination<'_> {
    fn kind(&self) -> &'static str {
        "vercel"
    }

    fn write(&self, secret_name: &str, value: &SecretString) -> Result<String> {
        let body = serde_json::json!({
            "key": secret_name,
            "value": value.expose(),
            "type": "encrypted",
            "target": self.targets,
        });
        let req = self
            .request(
                Method::Post,
                self.url(&format!(
                    "/v10/projects/{}/env?upsert=true",
                    self.project_id
                )),
            )
            .body(body.to_string().into_bytes());
        let resp = self.http.send(&req)?;
        match resp.status {
            200 | 201 => Ok(format!(
                "set '{secret_name}' for targets {}",
                self.targets.join(",")
            )),
            401 | 403 => Err(CoreError::ProviderAuth {
                provider: "vercel".into(),
                detail: format!("status {}", resp.status),
            }),
            other => Err(CoreError::Provider(format!(
                "setting the variable failed (status {other})"
            ))),
        }
    }

    fn read(&self, _secret_name: &str) -> Result<Option<SecretString>> {
        Ok(None) // encrypted variables are write-only through this API
    }

    /// True only when THIS destination's variable (key + exact target set)
    /// exists — a same-key variable for other targets is not it (DEST-02).
    fn exists(&self, secret_name: &str) -> Result<Option<bool>> {
        Ok(Some(self.resolve_env_identity(secret_name)?.id.is_some()))
    }

    fn delete(&self, secret_name: &str) -> Result<()> {
        let resolution = self.resolve_env_identity(secret_name)?;
        let Some(id) = resolution.id else {
            if resolution.other_targets {
                // Deleting by bare key would destroy a DIFFERENT target's
                // variable — fail safe instead (DEST-02).
                return Err(CoreError::Provider(format!(
                    "'{secret_name}' exists only for other targets/environments in this \
                     project; refusing to delete a variable this destination does not manage"
                )));
            }
            return Ok(()); // already absent: idempotent
        };
        let resp = self.http.send(&self.request(
            Method::Delete,
            self.url(&format!("/v9/projects/{}/env/{id}", self.project_id)),
        ))?;
        // 404: the variable vanished between the list and the DELETE —
        // already gone is the requested end state.
        if resp.is_success() || resp.status == 404 {
            return Ok(());
        }
        Err(CoreError::Provider(format!(
            "deleting the variable failed (status {})",
            resp.status
        )))
    }

    fn test(&self) -> Result<String> {
        let resp = self.http.send(&self.request(
            Method::Get,
            self.url(&format!("/v9/projects/{}", self.project_id)),
        ))?;
        match resp.status {
            200 => Ok(format!(
                "authenticated; project {} reachable",
                self.project_id
            )),
            401 | 403 => Err(CoreError::ProviderAuth {
                provider: "vercel".into(),
                detail: format!("status {}", resp.status),
            }),
            404 => Err(CoreError::Provider("project not found".into())),
            other => Err(CoreError::Provider(format!("unexpected status {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpResponse, MockHttpClient};
    use std::cell::RefCell;

    #[test]
    fn aws_region_rejects_url_delimiters() {
        // Legitimate regions pass.
        for ok in ["us-east-1", "eu-west-2", "ap-southeast-1"] {
            assert!(valid_aws_region(ok), "{ok} should be valid");
        }
        // Anything that could steer the request authority off-host is refused.
        for bad in [
            "",
            "evil.com?",
            "evil.com#",
            "foo/bar",
            "us-east-1@evil.com",
            "us-east-1:443",
            "US-EAST-1",
            "us_east_1",
            "region with space",
        ] {
            assert!(!valid_aws_region(bad), "{bad:?} must be rejected");
        }
    }

    fn github_adapter(http: &MockHttpClient) -> GithubActionsDestination<'_> {
        GithubActionsDestination {
            http,
            token: SecretString::from("ghp_FAKE0000000000000000000000000000000000"),
            owner: "octo".into(),
            repo: "app".into(),
        }
    }

    fn aws_adapter(http: &MockHttpClient) -> AwsSecretsManagerDestination<'_> {
        AwsSecretsManagerDestination {
            http,
            creds: AwsCredentials {
                access_key_id: "AKIAFAKE".into(),
                secret_access_key: SecretString::from("FAKE-secret"),
                session_token: None,
            },
            region: "us-east-1".into(),
        }
    }

    fn vercel_adapter<'a>(http: &'a MockHttpClient, targets: &[&str]) -> VercelDestination<'a> {
        VercelDestination {
            http,
            token: SecretString::from("FAKE-vercel-token"),
            project_id: "prj_fake".into(),
            team_id: None,
            targets: targets.iter().map(|s| s.to_string()).collect(),
        }
    }

    // ---------------------------------------------------------------- DEST-01

    #[test]
    fn github_exists_never_converts_errors_into_missing() {
        // Auth, rate-limit, and server failures mean "could not determine",
        // NEVER "the secret is absent" — a false `missing` triggers false
        // drift and invites destructive re-writes.
        for status in [401u16, 403, 429, 500] {
            let http = MockHttpClient::new(vec![HttpResponse {
                status,
                headers: vec![],
                body: b"{}".to_vec(),
            }]);
            let err = github_adapter(&http).exists("NAME").expect_err(&format!(
                "status {status} must be an error, not an existence verdict"
            ));
            let msg = err.to_string();
            assert!(!msg.contains("ghp_FAKE"), "no token in errors: {msg}");
        }
        // Only a definitive 404 is "absent"; a definitive 2xx is "present".
        let http = MockHttpClient::new(vec![HttpResponse {
            status: 404,
            headers: vec![],
            body: Vec::new(),
        }]);
        assert_eq!(github_adapter(&http).exists("NAME").unwrap(), Some(false));
        let http = MockHttpClient::json(r#"{"name":"NAME"}"#);
        assert_eq!(github_adapter(&http).exists("NAME").unwrap(), Some(true));
        // Transport failure propagates as an error.
        let http = MockHttpClient::with_network_failures(1, vec![]);
        assert!(github_adapter(&http).exists("NAME").is_err());
    }

    #[test]
    fn aws_exists_never_converts_errors_into_missing() {
        // Only ResourceNotFoundException is "absent".
        let http = MockHttpClient::new(vec![HttpResponse {
            status: 400,
            headers: vec![],
            body: br#"{"__type":"ResourceNotFoundException"}"#.to_vec(),
        }]);
        assert_eq!(aws_adapter(&http).exists("name").unwrap(), Some(false));
        let http = MockHttpClient::json(r#"{"ARN":"arn:aws:fake"}"#);
        assert_eq!(aws_adapter(&http).exists("name").unwrap(), Some(true));
        // 403 / throttling / server errors / unrecognized 400s are errors.
        for (status, body) in [
            (403u16, r#"{"__type":"AccessDeniedException"}"#),
            (400, r#"{"__type":"ThrottlingException"}"#),
            (500, r#"{"__type":"InternalServiceError"}"#),
            (400, "not-json-at-all"),
        ] {
            let http = MockHttpClient::new(vec![HttpResponse {
                status,
                headers: vec![],
                body: body.as_bytes().to_vec(),
            }]);
            assert!(
                aws_adapter(&http).exists("name").is_err(),
                "status {status} body {body} must be an error, not an existence verdict"
            );
        }
    }

    // ---------------------------------------------------------------- DEST-02

    fn vercel_env_list(envs: &str) -> String {
        format!(r#"{{"envs":[{envs}]}}"#)
    }

    #[test]
    fn vercel_identity_is_key_plus_targets() {
        let two_targets = vercel_env_list(
            r#"{"id":"id_prod","key":"K","target":["production"],"type":"encrypted"},
               {"id":"id_dev","key":"K","target":["development"],"type":"encrypted"}"#,
        );
        // The production-targeted destination sees ONLY its own variable…
        let http = MockHttpClient::json(&two_targets);
        assert_eq!(
            vercel_adapter(&http, &["production"]).exists("K").unwrap(),
            Some(true)
        );
        // …and a preview-targeted destination does not claim it exists.
        let http = MockHttpClient::json(&two_targets);
        assert_eq!(
            vercel_adapter(&http, &["preview"]).exists("K").unwrap(),
            Some(false)
        );
    }

    #[test]
    fn vercel_delete_targets_exactly_its_own_variable() {
        let two_targets = vercel_env_list(
            r#"{"id":"id_prod","key":"K","target":["production"],"type":"encrypted"},
               {"id":"id_dev","key":"K","target":["development"],"type":"encrypted"}"#,
        );
        let http = MockHttpClient::new(vec![
            HttpResponse {
                status: 200,
                headers: vec![],
                body: two_targets.clone().into_bytes(),
            },
            HttpResponse {
                status: 200,
                headers: vec![],
                body: b"{}".to_vec(),
            },
        ]);
        vercel_adapter(&http, &["development"]).delete("K").unwrap();
        let requests = http.requests.borrow();
        let delete_req = requests.last().expect("a DELETE was issued");
        assert!(
            delete_req.url.contains("/env/id_dev"),
            "must delete the DEVELOPMENT variable, got {}",
            delete_req.url
        );
        assert!(
            !delete_req.url.contains("id_prod"),
            "the production variable must never be touched"
        );
    }

    #[test]
    fn vercel_delete_refuses_other_targets_variable() {
        // The key exists, but only for targets this destination does not
        // manage: deleting would destroy someone else's variable.
        let other = vercel_env_list(
            r#"{"id":"id_prod","key":"K","target":["production"],"type":"encrypted"}"#,
        );
        let http = MockHttpClient::json(&other);
        let err = vercel_adapter(&http, &["development"])
            .delete("K")
            .expect_err("deleting another target's variable must be refused");
        assert!(err.to_string().contains("target"), "{err}");
        // Only the list request happened — no DELETE.
        assert_eq!(http.requests.borrow().len(), 1);
    }

    #[test]
    fn vercel_delete_ambiguous_identity_fails_safe() {
        let dup = vercel_env_list(
            r#"{"id":"id_a","key":"K","target":["production"],"type":"encrypted"},
               {"id":"id_b","key":"K","target":["production"],"type":"encrypted"}"#,
        );
        let http = MockHttpClient::json(&dup);
        let err = vercel_adapter(&http, &["production"])
            .delete("K")
            .expect_err("two identical identities is ambiguous; refuse");
        assert!(err.to_string().contains("ambiguous"), "{err}");
        assert_eq!(http.requests.borrow().len(), 1, "no DELETE was issued");
    }

    #[test]
    fn vercel_custom_environment_variables_are_a_different_identity() {
        let custom = vercel_env_list(
            r#"{"id":"id_c","key":"K","target":["production"],"type":"encrypted",
                "customEnvironmentIds":["env_custom"]}"#,
        );
        let http = MockHttpClient::json(&custom);
        assert_eq!(
            vercel_adapter(&http, &["production"]).exists("K").unwrap(),
            Some(false),
            "a custom-environment variable is not this destination's variable"
        );
    }

    #[test]
    fn vercel_absent_delete_is_idempotent_and_stale_id_race_is_tolerated() {
        // Absent: no DELETE issued, Ok.
        let http = MockHttpClient::json(&vercel_env_list(""));
        vercel_adapter(&http, &["production"]).delete("K").unwrap();
        assert_eq!(http.requests.borrow().len(), 1);
        // Stale id (deleted between list and DELETE): 404 is already-gone.
        let one = vercel_env_list(
            r#"{"id":"id_x","key":"K","target":["production"],"type":"encrypted"}"#,
        );
        let http = MockHttpClient::new(vec![
            HttpResponse {
                status: 200,
                headers: vec![],
                body: one.into_bytes(),
            },
            HttpResponse {
                status: 404,
                headers: vec![],
                body: Vec::new(),
            },
        ]);
        vercel_adapter(&http, &["production"])
            .delete("K")
            .expect("a variable that vanished between list and delete is already gone");
    }

    #[test]
    fn vercel_exists_propagates_list_failures_and_malformed_responses() {
        let http = MockHttpClient::new(vec![HttpResponse {
            status: 500,
            headers: vec![],
            body: Vec::new(),
        }]);
        assert!(vercel_adapter(&http, &["production"]).exists("K").is_err());
        let http = MockHttpClient::json("this is not json");
        assert!(vercel_adapter(&http, &["production"]).exists("K").is_err());
    }

    #[test]
    fn aws_call_refuses_a_malicious_region_before_any_request() {
        let http = MockHttpClient::json("{}");
        let dest = AwsSecretsManagerDestination {
            http: &http,
            creds: AwsCredentials {
                access_key_id: "AKIAFAKE".into(),
                secret_access_key: SecretString::from("FAKE-secret"),
                session_token: None,
            },
            region: "evil.com?".into(),
        };
        let err = dest
            .write("name", &SecretString::from("sk-FAKE"))
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidInput(_)), "{err}");
        // The guard fires before any network request is attempted.
        assert!(http.last_request().is_none());
    }

    #[test]
    fn catalog_reports_every_kind_with_capabilities() {
        let kinds: Vec<&str> = catalog().iter().map(|k| k.kind).collect();
        assert_eq!(
            kinds,
            vec![
                "vault",
                "env_mapping",
                "env_export",
                "macos_keychain",
                "linux_secret_service",
                "windows_credential_manager",
                "aws_secrets_manager",
                "github_actions",
                "vercel"
            ]
        );
        // Honesty: GitHub/Vercel must never claim value read-back.
        let gh = kind_info("github_actions").unwrap();
        assert_eq!(gh.capabilities.read, DestSupport::Unsupported);
        let vercel = kind_info("vercel").unwrap();
        assert_eq!(vercel.capabilities.read, DestSupport::Unsupported);
        // AWS delete is implemented with recovery-window semantics, and the
        // status says so.
        let aws = kind_info("aws_secrets_manager").unwrap();
        assert_eq!(aws.capabilities.delete, DestSupport::Implemented);
        assert!(aws.status.contains("recovery window"));
    }

    #[test]
    fn local_kinds_cannot_be_added_manually() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::db::migrate_with(&mut { conn }, crate::db::MIGRATIONS).ok();
        // (connection dropped; this test only checks the guard)
        assert!(!configurable_kinds().contains(&"vault"));
        assert!(!configurable_kinds().contains(&"env_mapping"));
        assert!(configurable_kinds().contains(&"aws_secrets_manager"));
    }

    type RecordedCall = (String, Vec<String>, Option<Vec<u8>>);
    type RunResult = (i32, Vec<u8>, Vec<u8>);

    struct ScriptedRunner {
        pub calls: RefCell<Vec<RecordedCall>>,
        pub results: RefCell<Vec<RunResult>>,
    }

    impl CommandRunner for ScriptedRunner {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            stdin: Option<&[u8]>,
        ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
            self.calls.borrow_mut().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
                stdin.map(|b| b.to_vec()),
            ));
            Ok(self.results.borrow_mut().remove(0))
        }
    }

    #[test]
    fn keychain_write_goes_through_stdin_never_argv() {
        let runner = ScriptedRunner {
            calls: RefCell::new(Vec::new()),
            results: RefCell::new(vec![(0, Vec::new(), Vec::new())]),
        };
        let dest = MacKeychainDestination {
            runner: &runner,
            account: "api-tracker".into(),
        };
        let value = SecretString::new("sk-test-FAKE-keychain-value".into());
        dest.write("OPENAI_API_KEY", &value).unwrap();
        let calls = runner.calls.borrow();
        let (program, args, stdin) = &calls[0];
        assert_eq!(program, "security");
        assert_eq!(args, &vec!["-i".to_string()]);
        // The secret must be on stdin, never in the argument list.
        assert!(String::from_utf8_lossy(stdin.as_ref().unwrap())
            .contains("sk-test-FAKE-keychain-value"));
        assert!(!args.iter().any(|a| a.contains("sk-test-FAKE")));
    }

    #[test]
    fn keychain_distinguishes_not_found_from_errors() {
        // exit 44 = errSecItemNotFound -> absent; other nonzero -> error
        // (a locked keychain must not be recorded as `missing` drift).
        let runner = ScriptedRunner {
            calls: RefCell::new(Vec::new()),
            results: RefCell::new(vec![
                (44, Vec::new(), Vec::new()),
                (1, Vec::new(), b"keychain locked".to_vec()),
            ]),
        };
        let dest = MacKeychainDestination {
            runner: &runner,
            account: "api-tracker".into(),
        };
        assert_eq!(dest.exists("MISSING_KEY").unwrap(), Some(false));
        assert!(dest.exists("ANY_KEY").is_err());
    }

    #[test]
    fn attach_rejects_unsafe_secret_names() {
        assert!(valid_secret_name("OPENAI_API_KEY"));
        assert!(valid_secret_name("_private"));
        assert!(!valid_secret_name("has/slash"));
        assert!(!valid_secret_name("has space"));
        assert!(!valid_secret_name("1starts-with-digit"));
        assert!(!valid_secret_name("query?injection"));
        assert!(!valid_secret_name(""));
    }

    #[test]
    fn keychain_quoting_escapes_and_rejects_control_chars() {
        assert_eq!(keychain_quote("ab\"c").unwrap(), "\"ab\\\"c\"");
        assert_eq!(keychain_quote("a\\b").unwrap(), "\"a\\\\b\"");
        assert!(keychain_quote("bad\nvalue").is_err());
    }

    #[test]
    fn github_write_seals_and_puts_with_key_id() {
        // A real X25519 public key (any 32 bytes form a valid point input).
        use base64::Engine;
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let mock = MockHttpClient::new(vec![
            MockHttpClient::json_response(&format!(
                r#"{{"key_id":"568250167242549743","key":"{pk_b64}"}}"#
            )),
            crate::http::HttpResponse {
                status: 201,
                headers: vec![],
                body: Vec::new(),
            },
        ]);
        let dest = GithubActionsDestination {
            http: &mock,
            token: SecretString::new("ghp_FAKE0000000000000000000000000000000000".into()),
            owner: "octo".into(),
            repo: "hello".into(),
        };
        let receipt = dest
            .write("MY_SECRET", &SecretString::new("super-secret-FAKE".into()))
            .unwrap();
        assert!(receipt.contains("created"));
        let requests = mock.requests.borrow();
        assert_eq!(requests.len(), 2);
        let put = &requests[1];
        assert_eq!(put.method, Method::Put);
        assert!(put
            .url
            .ends_with("/repos/octo/hello/actions/secrets/MY_SECRET"));
        let body = String::from_utf8_lossy(put.body.as_ref().unwrap()).into_owned();
        // The plaintext must never appear in the request body — only the
        // sealed-box ciphertext does.
        assert!(!body.contains("super-secret-FAKE"));
        assert!(body.contains("568250167242549743"));
        assert!(body.contains("encrypted_value"));
    }

    #[test]
    fn vercel_write_upserts_and_delete_looks_up_id() {
        let mock = MockHttpClient::new(vec![
            MockHttpClient::json_response(r#"{"created":{}}"#),
            MockHttpClient::json_response(
                r#"{"envs":[{"id":"env_123","key":"MY_SECRET","target":["preview","production"]}]}"#,
            ),
            MockHttpClient::json_response(r#"{}"#),
        ]);
        let dest = VercelDestination {
            http: &mock,
            token: SecretString::new("vercel-FAKE-token".into()),
            project_id: "prj_abc".into(),
            team_id: Some("team_x".into()),
            targets: vec!["production".into(), "preview".into()],
        };
        dest.write("MY_SECRET", &SecretString::new("v-FAKE".into()))
            .unwrap();
        dest.delete("MY_SECRET").unwrap();
        let requests = mock.requests.borrow();
        assert!(requests[0]
            .url
            .contains("/v10/projects/prj_abc/env?upsert=true"));
        assert!(requests[0].url.contains("teamId=team_x"));
        assert_eq!(requests[2].method, Method::Delete);
        assert!(requests[2].url.contains("/env/env_123"));
    }

    #[test]
    fn aws_write_creates_when_missing() {
        let mock = MockHttpClient::new(vec![
            crate::http::HttpResponse {
                status: 400,
                headers: vec![],
                body: br#"{"__type":"ResourceNotFoundException"}"#.to_vec(),
            },
            MockHttpClient::json_response(r#"{"ARN":"arn:aws:...","Name":"MY_SECRET"}"#),
        ]);
        let dest = AwsSecretsManagerDestination {
            http: &mock,
            creds: AwsCredentials {
                access_key_id: "AKIAFAKEFAKEFAKEFAKE".into(),
                secret_access_key: SecretString::new("FAKE-secret-access-key".into()),
                session_token: None,
            },
            region: "us-east-1".into(),
        };
        let receipt = dest
            .write("MY_SECRET", &SecretString::new("aws-value-FAKE".into()))
            .unwrap();
        assert!(receipt.contains("created"));
        let requests = mock.requests.borrow();
        assert_eq!(requests.len(), 2);
        // Both requests are signed and the signing key never appears.
        for req in requests.iter() {
            let auth = req
                .headers
                .iter()
                .find(|(k, _)| k == "authorization")
                .map(|(_, v)| v.clone())
                .unwrap();
            assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAFAKEFAKEFAKEFAKE/"));
            assert!(!auth.contains("FAKE-secret-access-key"));
        }
    }

    fn aws_dest(mock: &MockHttpClient) -> AwsSecretsManagerDestination<'_> {
        AwsSecretsManagerDestination {
            http: mock,
            creds: AwsCredentials {
                access_key_id: "AKIAFAKEFAKEFAKEFAKE".into(),
                secret_access_key: SecretString::new("FAKE-secret-access-key".into()),
                session_token: None,
            },
            region: "us-east-1".into(),
        }
    }

    #[test]
    fn aws_delete_uses_the_recovery_window_and_never_forces() {
        let mock = MockHttpClient::new(vec![MockHttpClient::json_response(
            r#"{"ARN":"arn:aws:...","Name":"MY_SECRET","DeletionDate":1.75e9}"#,
        )]);
        aws_dest(&mock).delete("MY_SECRET").unwrap();
        let requests = mock.requests.borrow();
        assert_eq!(requests.len(), 1);
        let target = requests[0]
            .headers
            .iter()
            .find(|(k, _)| k == "x-amz-target")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(target.ends_with("DeleteSecret"));
        let body = String::from_utf8(requests[0].body.clone().unwrap_or_default()).unwrap();
        assert!(body.contains("\"RecoveryWindowInDays\":30"));
        // The irreversible force-delete flag is never sent.
        assert!(!body.contains("ForceDeleteWithoutRecovery"));
    }

    #[test]
    fn aws_delete_is_idempotent_for_missing_secrets() {
        let mock = MockHttpClient::new(vec![crate::http::HttpResponse {
            status: 400,
            headers: vec![],
            body: br#"{"__type":"ResourceNotFoundException"}"#.to_vec(),
        }]);
        aws_dest(&mock).delete("GONE").unwrap();
    }

    #[test]
    fn secret_service_round_trips_via_stdin_and_attributes() {
        let runner = ScriptedRunner {
            calls: RefCell::new(Vec::new()),
            results: RefCell::new(vec![
                (0, Vec::new(), Vec::new()),              // store
                (0, b"the-value\n".to_vec(), Vec::new()), // lookup
                (0, Vec::new(), Vec::new()),              // clear
            ]),
        };
        let dest = SecretServiceDestination {
            runner: &runner,
            service: "api-tracker".into(),
        };
        dest.write("MY_SECRET", &SecretString::new("the-value".into()))
            .unwrap();
        assert_eq!(
            dest.read("MY_SECRET").unwrap().unwrap().expose(),
            "the-value"
        );
        dest.delete("MY_SECRET").unwrap();
        let calls = runner.calls.borrow();
        // The value travels on stdin, never in the argument list.
        let (prog, args, stdin) = &calls[0];
        assert_eq!(prog, "secret-tool");
        assert_eq!(args[0], "store");
        assert!(args.iter().all(|a| !a.contains("the-value")));
        assert_eq!(stdin.as_deref(), Some(b"the-value".as_slice()));
        // Attribute pairs identify the item.
        assert!(args.contains(&"service".to_string()));
        assert!(args.contains(&"MY_SECRET".to_string()));
    }

    #[test]
    fn secret_service_distinguishes_absent_from_errors() {
        // Nonzero exit with EMPTY stderr = absent (secret-tool's silent
        // not-found); nonzero WITH stderr = a real failure (locked keyring).
        let runner = ScriptedRunner {
            calls: RefCell::new(Vec::new()),
            results: RefCell::new(vec![
                (1, Vec::new(), Vec::new()),
                (1, Vec::new(), b"error: cannot unlock collection".to_vec()),
            ]),
        };
        let dest = SecretServiceDestination {
            runner: &runner,
            service: "api-tracker".into(),
        };
        let absent = dest.read("MISSING").unwrap().unwrap();
        assert!(absent.expose().is_empty());
        assert!(dest.read("LOCKED").is_err());
    }

    #[test]
    fn wincred_target_names_are_validated() {
        assert_eq!(
            wincred_target("MY_SECRET").unwrap(),
            "api-tracker/MY_SECRET"
        );
        assert!(wincred_target("bad name with spaces").is_err());
        assert!(wincred_target("").is_err());
        assert!(wincred_target("evil;rm -rf").is_err());
    }

    #[test]
    fn platform_gated_kinds_report_honestly() {
        let by_kind = |k: &str| kind_info(k).unwrap();
        let lss = by_kind("linux_secret_service");
        let win = by_kind("windows_credential_manager");
        if !cfg!(target_os = "linux") {
            assert_eq!(lss.capabilities.write, DestSupport::PlatformUnavailable);
        }
        if !cfg!(windows) {
            assert_eq!(win.capabilities.write, DestSupport::PlatformUnavailable);
        }
        // Every kind now declares the extended honesty fields.
        for k in catalog() {
            assert!(!k.verify_method.is_empty(), "{} verify", k.kind);
            assert!(!k.required_plan.is_empty(), "{} plan", k.kind);
            assert!(!k.charges.is_empty(), "{} charges", k.kind);
            assert!(!k.testing.is_empty(), "{} testing", k.kind);
        }
    }
}
