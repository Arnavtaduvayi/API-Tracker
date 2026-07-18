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
    /// The destination offers it, API Tracker does not implement it yet.
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
            name: "API Tracker local vault",
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
            config_help: "optional: account (default 'api-tracker')",
        },
        DestinationKindInfo {
            kind: "aws_secrets_manager",
            name: "AWS Secrets Manager",
            description: "Secrets in AWS Secrets Manager via the official API (SigV4-signed, direct from this machine).",
            auth: "IAM access key id + secret access key (stored encrypted in the vault); needs secretsmanager:GetSecretValue/PutSecretValue/CreateSecret/DescribeSecret",
            platforms: "all",
            status: "implemented; verified against recorded API fixtures, not yet against a live AWS account",
            capabilities: DestCapabilities {
                read: IMPL,
                write: IMPL,
                delete: DestSupport::SupportedNotImplemented,
                versioning: IMPL,
                rollback: IMPL,
                validation: IMPL,
            },
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

pub fn attach(
    conn: &Connection,
    credential_id: &str,
    destination_id: &str,
    secret_name: &str,
    environment: &str,
) -> Result<()> {
    if secret_name.trim().is_empty() {
        return Err(CoreError::InvalidInput(
            "secret name must not be empty".into(),
        ));
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
    conn.execute(
        "UPDATE credential_destinations
         SET last_verified_at = ?1, drift = ?2
         WHERE credential_id = ?3 AND destination_id = ?4 AND secret_name = ?5",
        params![now, drift, credential_id, destination_id, secret_name],
    )?;
    Ok(())
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
        if code != 0 {
            return Ok(Some(SecretString::new(String::new()))); // absent
        }
        let value = String::from_utf8_lossy(&out)
            .trim_end_matches('\n')
            .to_string();
        Ok(Some(SecretString::new(value)))
    }

    fn exists(&self, secret_name: &str) -> Result<Option<bool>> {
        check_name(secret_name)?;
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
        Ok(Some(code == 0))
    }

    fn delete(&self, secret_name: &str) -> Result<()> {
        check_name(secret_name)?;
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

impl AwsSecretsManagerDestination<'_> {
    fn call(&self, target: &str, body: serde_json::Value) -> Result<HttpResponse2> {
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
        if resp.status == 400 && resp.error_type().contains("ResourceNotFoundException") {
            return Ok(Some(false));
        }
        Ok(Some((200..300).contains(&resp.status)))
    }

    fn delete(&self, _secret_name: &str) -> Result<()> {
        Err(CoreError::Unsupported {
            provider: "aws_secrets_manager".into(),
            capability: "delete",
            hint: "deletion (with its recovery window) is not implemented yet; delete in the AWS console".into(),
        })
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
        Ok(Some(resp.is_success()))
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

    fn find_env_id(&self, secret_name: &str) -> Result<Option<String>> {
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
        let id = parsed
            .get("envs")
            .and_then(|v| v.as_array())
            .and_then(|envs| {
                envs.iter()
                    .find(|e| e.get("key").and_then(|k| k.as_str()) == Some(secret_name))
            })
            .and_then(|e| e.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Ok(id)
    }
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

    fn exists(&self, secret_name: &str) -> Result<Option<bool>> {
        Ok(Some(self.find_env_id(secret_name)?.is_some()))
    }

    fn delete(&self, secret_name: &str) -> Result<()> {
        let Some(id) = self.find_env_id(secret_name)? else {
            return Ok(());
        };
        let resp = self.http.send(&self.request(
            Method::Delete,
            self.url(&format!("/v9/projects/{}/env/{id}", self.project_id)),
        ))?;
        if resp.is_success() {
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
    use crate::http::MockHttpClient;
    use std::cell::RefCell;

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
        // AWS delete is declared not-implemented, matching the adapter.
        let aws = kind_info("aws_secrets_manager").unwrap();
        assert_eq!(
            aws.capabilities.delete,
            DestSupport::SupportedNotImplemented
        );
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
            MockHttpClient::json_response(r#"{"envs":[{"id":"env_123","key":"MY_SECRET"}]}"#),
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
}
