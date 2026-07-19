//! Encrypted vault backups.
//!
//! A backup is a JSON file: a plaintext header (format, version, KDF
//! parameters, salt) plus one AEAD envelope containing the full serialized
//! vault content — including the wrapped keys from `vault_meta`, so a
//! restored vault unlocks with the master password the vault had when the
//! backup was created. The whole payload is encrypted with a key derived
//! from a backup password chosen at creation time.
//!
//! Format versions:
//! - **v2 (current)**: the payload carries EVERY user table generically
//!   (name + columns + rows), enumerated from the live schema. New tables
//!   added by future migrations are included automatically — the backup can
//!   never silently fall out of sync with the schema again. The plaintext
//!   `version` field is bound into the AEAD associated data, so a tampered
//!   header cannot re-route the payload to another parser.
//! - **v1 (read-only)**: a typed payload of the five original core tables
//!   (vault meta, projects, repos, credentials, audit events). Restoring a
//!   v1 backup preserves that data; anything a v1-era build never captured
//!   (post-v1 subsystems) was not in the file to begin with.
//!
//! A backup whose payload schema is OLDER than this build restores fine:
//! the schema is rebuilt at the payload's version, rows are imported, and
//! the normal migrations then upgrade it to current. A payload schema
//! NEWER than this build is refused.
//!
//! Recovery limitations (documented in README/SECURITY):
//! - Restoring requires the backup password.
//! - Unlocking the restored vault requires the master password from backup
//!   time. There is no bypass; losing both passwords makes the data
//!   unrecoverable by design.

use crate::clock;
use crate::crypto::{self, aad, KdfParams};
use crate::db;
use crate::error::{CoreError, Result};
use crate::secret::SecretString;
use crate::session;
use crate::vault::{UnlockedVault, VaultPaths};
use base64::Engine;
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const BACKUP_FORMAT: &str = "api-tracker-backup";
/// The version new backups are written at. Version 1 remains readable.
pub const BACKUP_VERSION: u32 = 2;

#[derive(Serialize, Deserialize)]
struct BackupFile {
    format: String,
    version: u32,
    vault_id: String,
    created_at: String,
    kdf: KdfParams,
    salt_hex: String,
    payload_b64: String,
}

// ---------------------------------------------------------------------------
// v2 payload: every user table, generically.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct BackupPayloadV2 {
    schema_version: i64,
    tables: Vec<TableExport>,
}

#[derive(Serialize, Deserialize)]
struct TableExport {
    name: String,
    columns: Vec<String>,
    rows: Vec<Vec<Cell>>,
}

/// One SQLite value. Externally tagged so integer/real round-trips are
/// unambiguous; blobs travel base64-encoded.
#[derive(Serialize, Deserialize)]
enum Cell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(String),
}

impl Cell {
    fn from_value_ref(v: ValueRef<'_>) -> Result<Self> {
        Ok(match v {
            ValueRef::Null => Cell::Null,
            ValueRef::Integer(i) => Cell::Int(i),
            ValueRef::Real(f) => Cell::Real(f),
            ValueRef::Text(t) => Cell::Text(
                std::str::from_utf8(t)
                    .map_err(|_| CoreError::VaultCorrupted("non-UTF-8 text column"))?
                    .to_owned(),
            ),
            ValueRef::Blob(b) => Cell::Blob(base64::engine::general_purpose::STANDARD.encode(b)),
        })
    }

    fn into_sql_value(self) -> Result<rusqlite::types::Value> {
        use rusqlite::types::Value;
        Ok(match self {
            Cell::Null => Value::Null,
            Cell::Int(i) => Value::Integer(i),
            Cell::Real(f) => Value::Real(f),
            Cell::Text(t) => Value::Text(t),
            Cell::Blob(b64) => Value::Blob(
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| {
                        CoreError::BackupInvalid("blob cell is not valid base64".into())
                    })?,
            ),
        })
    }
}

/// Quote an identifier for use in generated SQL. Table/column names come
/// from our own schema (via `sqlite_master`) or from a decrypted backup
/// payload; quoting plus a character allowlist keeps generated statements
/// inert even against a crafted payload.
fn checked_ident(name: &str) -> Result<String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(CoreError::BackupInvalid(format!(
            "invalid identifier in backup payload: {name:?}"
        )));
    }
    Ok(format!("\"{name}\""))
}

fn collect_payload_v2(conn: &Connection) -> Result<BackupPayloadV2> {
    let schema_version = db::user_version(conn)?;
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let names: Vec<String> = stmt
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;

    let mut tables = Vec::with_capacity(names.len());
    for name in names {
        let quoted = checked_ident(&name)?;
        let mut stmt = conn.prepare(&format!("SELECT * FROM {quoted}"))?;
        let columns: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
        let column_count = columns.len();
        let rows: Vec<Vec<Cell>> = stmt
            .query_and_then([], |row| {
                (0..column_count)
                    .map(|i| Cell::from_value_ref(row.get_ref(i)?))
                    .collect::<Result<Vec<Cell>>>()
            })?
            .collect::<Result<_>>()?;
        tables.push(TableExport {
            name,
            columns,
            rows,
        });
    }
    Ok(BackupPayloadV2 {
        schema_version,
        tables,
    })
}

// ---------------------------------------------------------------------------
// v1 payload (read-only legacy format): the five original core tables.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct BackupPayloadV1 {
    schema_version: i64,
    vault_meta: Vec<(String, String)>,
    projects: Vec<ProjectExportV1>,
    project_repos: Vec<(String, String)>,
    credentials: Vec<CredentialExportV1>,
    audit_events: Vec<AuditExportV1>,
}

#[derive(Serialize, Deserialize)]
struct ProjectExportV1 {
    id: String,
    name: String,
    description: String,
    notes: String,
    environments: String,
    archived: bool,
    created_at: String,
    updated_at: String,
    wrapped_project_key_hex: String,
    key_wrap_mode: String,
    project_kdf_params: Option<String>,
    project_salt_hex: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CredentialExportV1 {
    id: String,
    project_id: String,
    provider: String,
    name: String,
    environment: String,
    credential_type: String,
    ciphertext_hex: Option<String>,
    linked_credential_id: Option<String>,
    fingerprint_hex: String,
    masked_value: String,
    created_at: String,
    updated_at: String,
    key_created_at: Option<String>,
    expires_at: Option<String>,
    last_validated_at: Option<String>,
    last_used_at: Option<String>,
    docs_url: String,
    notes: String,
    manually_disabled: bool,
    revoked: bool,
    marked_invalid: bool,
    possibly_exposed: bool,
    exposure_note: String,
}

#[derive(Serialize, Deserialize)]
struct AuditExportV1 {
    at: String,
    event: String,
    project_id: Option<String>,
    credential_id: Option<String>,
    detail: String,
}

enum Payload {
    V1(BackupPayloadV1),
    V2(BackupPayloadV2),
}

impl Payload {
    fn schema_version(&self) -> i64 {
        match self {
            Payload::V1(p) => p.schema_version,
            Payload::V2(p) => p.schema_version,
        }
    }

    fn table_len(&self, table: &str) -> usize {
        match self {
            Payload::V1(p) => match table {
                "projects" => p.projects.len(),
                "credentials" => p.credentials.len(),
                _ => 0,
            },
            Payload::V2(p) => p
                .tables
                .iter()
                .find(|t| t.name == table)
                .map(|t| t.rows.len())
                .unwrap_or(0),
        }
    }
}

/// Non-secret summary of a backup, returned by create/verify/restore.
#[derive(Debug, Clone, Serialize)]
pub struct BackupInfo {
    pub path: String,
    pub vault_id: String,
    pub created_at: String,
    pub schema_version: i64,
    pub format_version: u32,
    pub project_count: usize,
    pub credential_count: usize,
}

/// Create an encrypted backup file. Never overwrites unless `overwrite`.
pub fn create_backup(
    vault: &UnlockedVault,
    path: &Path,
    backup_password: &SecretString,
    overwrite: bool,
) -> Result<BackupInfo> {
    if backup_password.expose().len() < crate::vault::MIN_PASSWORD_LEN {
        return Err(CoreError::InvalidInput(format!(
            "the backup password must be at least {} characters",
            crate::vault::MIN_PASSWORD_LEN
        )));
    }
    if path.exists() && !overwrite {
        return Err(CoreError::AlreadyExists {
            kind: "backup file",
            ident: path.display().to_string(),
        });
    }
    let payload = collect_payload_v2(vault.connection())?;
    let payload_json = serde_json::to_vec(&payload)?;
    let kdf = KdfParams::recommended();
    let salt = crypto::new_salt();
    let key = crypto::derive_key(backup_password, &salt, &kdf)?;
    let envelope = crypto::encrypt(&key, &aad::backup_v2(vault.vault_id()), &payload_json)?;
    let created_at = clock::now_rfc3339();
    let file = BackupFile {
        format: BACKUP_FORMAT.to_owned(),
        version: BACKUP_VERSION,
        vault_id: vault.vault_id().to_owned(),
        created_at: created_at.clone(),
        kdf,
        salt_hex: hex::encode(&salt),
        payload_b64: base64::engine::general_purpose::STANDARD.encode(&envelope),
    };
    std::fs::write(path, serde_json::to_string_pretty(&file)?)?;
    crate::audit::record(
        vault.connection(),
        "backup_created",
        None,
        None,
        &format!("path={}", path.display()),
    )?;
    Ok(BackupInfo {
        path: path.display().to_string(),
        vault_id: file.vault_id,
        created_at,
        schema_version: payload.schema_version,
        format_version: BACKUP_VERSION,
        project_count: payload
            .tables
            .iter()
            .find(|t| t.name == "projects")
            .map(|t| t.rows.len())
            .unwrap_or(0),
        credential_count: payload
            .tables
            .iter()
            .find(|t| t.name == "credentials")
            .map(|t| t.rows.len())
            .unwrap_or(0),
    })
}

fn read_and_decrypt(path: &Path, backup_password: &SecretString) -> Result<(BackupFile, Payload)> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CoreError::BackupInvalid(format!("no file at {}", path.display()))
        } else {
            e.into()
        }
    })?;
    let file: BackupFile = serde_json::from_str(&raw)
        .map_err(|_| CoreError::BackupInvalid("not an API Tracker backup file".into()))?;
    if file.format != BACKUP_FORMAT {
        return Err(CoreError::BackupInvalid(
            "unrecognized format marker".into(),
        ));
    }
    if file.version == 0 || file.version > BACKUP_VERSION {
        return Err(CoreError::BackupInvalid(format!(
            "backup format version {} is not supported by this build (up to {BACKUP_VERSION})",
            file.version
        )));
    }
    let salt = hex::decode(&file.salt_hex)
        .map_err(|_| CoreError::BackupInvalid("salt is not valid hex".into()))?;
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(&file.payload_b64)
        .map_err(|_| CoreError::BackupInvalid("payload is not valid base64".into()))?;
    let key = crypto::derive_key(backup_password, &salt, &file.kdf)?;
    let context_aad = if file.version == 1 {
        aad::backup(&file.vault_id)
    } else {
        aad::backup_v2(&file.vault_id)
    };
    let plaintext = crypto::decrypt(
        &key,
        &context_aad,
        &envelope,
        "backup (wrong backup password, corruption, or tampering)",
    )?;
    let payload = if file.version == 1 {
        Payload::V1(
            serde_json::from_slice(plaintext.expose())
                .map_err(|_| CoreError::BackupInvalid("decrypted payload is malformed".into()))?,
        )
    } else {
        Payload::V2(
            serde_json::from_slice(plaintext.expose())
                .map_err(|_| CoreError::BackupInvalid("decrypted payload is malformed".into()))?,
        )
    };
    Ok((file, payload))
}

fn info_for(path: &Path, file: &BackupFile, payload: &Payload) -> BackupInfo {
    BackupInfo {
        path: path.display().to_string(),
        vault_id: file.vault_id.clone(),
        created_at: file.created_at.clone(),
        schema_version: payload.schema_version(),
        format_version: file.version,
        project_count: payload.table_len("projects"),
        credential_count: payload.table_len("credentials"),
    }
}

/// Decrypt and validate a backup without restoring it.
pub fn verify_backup(path: &Path, backup_password: &SecretString) -> Result<BackupInfo> {
    let (file, payload) = read_and_decrypt(path, backup_password)?;
    if payload.schema_version() > db::current_schema_version() {
        return Err(CoreError::BackupInvalid(format!(
            "backup uses database schema v{} but this build supports up to v{}",
            payload.schema_version(),
            db::current_schema_version()
        )));
    }
    Ok(info_for(path, &file, &payload))
}

/// Restore a backup into `target`. Refuses to overwrite an existing vault
/// unless `force`; with `force`, the current vault database is renamed
/// aside (never silently destroyed). Older-schema backups are imported at
/// their own schema version and then migrated forward to current.
pub fn restore_backup(
    path: &Path,
    backup_password: &SecretString,
    target: &VaultPaths,
    force: bool,
) -> Result<BackupInfo> {
    let (file, payload) = read_and_decrypt(path, backup_password)?;
    if payload.schema_version() > db::current_schema_version() {
        return Err(CoreError::BackupInvalid(format!(
            "backup uses database schema v{} but this build supports up to v{}",
            payload.schema_version(),
            db::current_schema_version()
        )));
    }
    let info = info_for(path, &file, &payload);
    let db_path = target.db_path();
    if db_path.exists() {
        if !force {
            return Err(CoreError::VaultExists(db_path));
        }
        let timestamp = clock::now().unix_timestamp().to_string();
        let aside = target
            .data_dir
            .join(format!("vault.db.replaced-{timestamp}"));
        std::fs::rename(&db_path, &aside)?;
        // Move the WAL/SHM sidecars alongside the renamed database instead of
        // deleting them: a live connection may hold committed-but-uncheckpointed
        // transactions in the WAL, and SQLite associates `<db>-wal`/`<db>-shm`
        // with the database by name, so the aside copy stays complete and
        // openable. (Deleting them would silently discard those transactions.)
        for suffix in ["-wal", "-shm"] {
            let side = target.data_dir.join(format!("vault.db{suffix}"));
            if side.exists() {
                let aside_side = target
                    .data_dir
                    .join(format!("vault.db.replaced-{timestamp}{suffix}"));
                std::fs::rename(&side, &aside_side)?;
            }
        }
    }
    std::fs::create_dir_all(&target.data_dir)?;
    crate::vault::restrict_data_dir_permissions(&target.data_dir)?;
    let mut conn = db::open(&db_path)?;
    match payload {
        Payload::V2(payload) => restore_v2(&mut conn, payload)?,
        Payload::V1(payload) => restore_v1(&mut conn, payload)?,
    }
    // Any pre-existing session belongs to the replaced vault.
    session::destroy(target)?;
    crate::audit::record(&conn, "vault_restored_from_backup", None, None, "")?;
    Ok(info)
}

/// v2 restore: rebuild the schema at the payload's version, import every
/// table, then run the normal migrations forward to current.
fn restore_v2(conn: &mut Connection, payload: BackupPayloadV2) -> Result<()> {
    let upto = db::MIGRATIONS
        .iter()
        .position(|m| m.version == payload.schema_version)
        .ok_or_else(|| {
            CoreError::BackupInvalid(format!(
                "backup schema v{} does not correspond to any known migration",
                payload.schema_version
            ))
        })?;
    db::migrate_with(conn, &db::MIGRATIONS[..=upto])?;
    {
        let tx = conn.transaction()?;
        tx.execute_batch("PRAGMA defer_foreign_keys = ON")?;
        for table in payload.tables {
            let quoted = checked_ident(&table.name)?;
            if table.rows.is_empty() {
                continue;
            }
            let columns = table
                .columns
                .iter()
                .map(|c| checked_ident(c))
                .collect::<Result<Vec<_>>>()?
                .join(", ");
            let placeholders = (1..=table.columns.len())
                .map(|i| format!("?{i}"))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!("INSERT INTO {quoted} ({columns}) VALUES ({placeholders})");
            let mut stmt = tx.prepare(&sql).map_err(|_| {
                CoreError::BackupInvalid(format!(
                    "backup table '{}' does not match schema v{}",
                    table.name, payload.schema_version
                ))
            })?;
            for row in table.rows {
                if row.len() != table.columns.len() {
                    return Err(CoreError::BackupInvalid(format!(
                        "row width mismatch in table '{}'",
                        table.name
                    )));
                }
                let values = row
                    .into_iter()
                    .map(Cell::into_sql_value)
                    .collect::<Result<Vec<_>>>()?;
                stmt.execute(rusqlite::params_from_iter(values))?;
            }
        }
        tx.commit()?;
    }
    // Upgrade an older-schema import to the current schema.
    db::migrate(conn)?;
    Ok(())
}

/// v1 restore: the typed five-table import. Every column it names exists in
/// all later schemas (added columns carry defaults), so the import runs
/// against the CURRENT schema directly.
fn restore_v1(conn: &mut Connection, payload: BackupPayloadV1) -> Result<()> {
    db::migrate(conn)?;
    let tx = conn.transaction()?;
    tx.execute_batch("PRAGMA defer_foreign_keys = ON")?;
    for (key, value) in &payload.vault_meta {
        tx.execute(
            "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
    }
    for p in &payload.projects {
        tx.execute(
            "INSERT INTO projects (id, name, description, notes, environments, archived,
             created_at, updated_at, wrapped_project_key, key_wrap_mode,
             project_kdf_params, project_salt)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                p.id,
                p.name,
                p.description,
                p.notes,
                p.environments,
                p.archived,
                p.created_at,
                p.updated_at,
                hex::decode(&p.wrapped_project_key_hex)
                    .map_err(|_| CoreError::BackupInvalid("project key hex".into()))?,
                p.key_wrap_mode,
                p.project_kdf_params,
                p.project_salt_hex
                    .as_ref()
                    .map(hex::decode)
                    .transpose()
                    .map_err(|_| CoreError::BackupInvalid("project salt hex".into()))?,
            ],
        )?;
    }
    for (project_id, repo_path) in &payload.project_repos {
        tx.execute(
            "INSERT INTO project_repos (project_id, path) VALUES (?1, ?2)",
            params![project_id, repo_path],
        )?;
    }
    for c in &payload.credentials {
        tx.execute(
            "INSERT INTO credentials (id, project_id, provider, name, environment,
             credential_type, ciphertext, linked_credential_id, fingerprint, masked_value,
             created_at, updated_at, key_created_at, expires_at, last_validated_at,
             last_used_at, docs_url, notes, manually_disabled, revoked, marked_invalid,
             possibly_exposed, exposure_note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
             ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
            params![
                c.id,
                c.project_id,
                c.provider,
                c.name,
                c.environment,
                c.credential_type,
                c.ciphertext_hex
                    .as_ref()
                    .map(hex::decode)
                    .transpose()
                    .map_err(|_| CoreError::BackupInvalid("credential ciphertext hex".into()))?,
                c.linked_credential_id,
                hex::decode(&c.fingerprint_hex)
                    .map_err(|_| CoreError::BackupInvalid("fingerprint hex".into()))?,
                c.masked_value,
                c.created_at,
                c.updated_at,
                c.key_created_at,
                c.expires_at,
                c.last_validated_at,
                c.last_used_at,
                c.docs_url,
                c.notes,
                c.manually_disabled,
                c.revoked,
                c.marked_invalid,
                c.possibly_exposed,
                c.exposure_note,
            ],
        )?;
    }
    for a in &payload.audit_events {
        tx.execute(
            "INSERT INTO audit_events (at, event, project_id, credential_id, detail)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![a.at, a.event, a.project_id, a.credential_id, a.detail],
        )?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a FORMAT-V1 backup file exactly as a pre-v2 build would have,
    /// from the given payload. Used to prove legacy backups keep restoring.
    pub(super) fn write_v1_backup_file(
        path: &Path,
        vault_id: &str,
        backup_password: &SecretString,
        payload: &BackupPayloadV1,
    ) {
        let payload_json = serde_json::to_vec(payload).unwrap();
        let kdf = KdfParams::recommended();
        let salt = crypto::new_salt();
        let key = crypto::derive_key(backup_password, &salt, &kdf).unwrap();
        let envelope = crypto::encrypt(&key, &aad::backup(vault_id), &payload_json).unwrap();
        let file = BackupFile {
            format: BACKUP_FORMAT.to_owned(),
            version: 1,
            vault_id: vault_id.to_owned(),
            created_at: clock::now_rfc3339(),
            kdf,
            salt_hex: hex::encode(&salt),
            payload_b64: base64::engine::general_purpose::STANDARD.encode(&envelope),
        };
        std::fs::write(path, serde_json::to_string_pretty(&file).unwrap()).unwrap();
    }

    /// Read the five core tables of a REAL vault into a v1-format payload,
    /// stamped with an arbitrary (older) schema version.
    pub(super) fn v1_payload_from_vault(
        conn: &Connection,
        claimed_schema_version: i64,
    ) -> BackupPayloadV1 {
        let mut stmt = conn
            .prepare("SELECT key, value FROM vault_meta ORDER BY key")
            .unwrap();
        let vault_meta: Vec<(String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, name, description, notes, environments, archived, created_at,
                 updated_at, wrapped_project_key, key_wrap_mode, project_kdf_params,
                 project_salt FROM projects",
            )
            .unwrap();
        let projects: Vec<ProjectExportV1> = stmt
            .query_map([], |r| {
                Ok(ProjectExportV1 {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    notes: r.get(3)?,
                    environments: r.get(4)?,
                    archived: r.get(5)?,
                    created_at: r.get(6)?,
                    updated_at: r.get(7)?,
                    wrapped_project_key_hex: hex::encode(r.get::<_, Vec<u8>>(8)?),
                    key_wrap_mode: r.get(9)?,
                    project_kdf_params: r.get(10)?,
                    project_salt_hex: r.get::<_, Option<Vec<u8>>>(11)?.map(hex::encode),
                })
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, project_id, provider, name, environment, credential_type,
                 ciphertext, linked_credential_id, fingerprint, masked_value, created_at,
                 updated_at, key_created_at, expires_at, last_validated_at, last_used_at,
                 docs_url, notes, manually_disabled, revoked, marked_invalid,
                 possibly_exposed, exposure_note FROM credentials",
            )
            .unwrap();
        let credentials: Vec<CredentialExportV1> = stmt
            .query_map([], |r| {
                Ok(CredentialExportV1 {
                    id: r.get(0)?,
                    project_id: r.get(1)?,
                    provider: r.get(2)?,
                    name: r.get(3)?,
                    environment: r.get(4)?,
                    credential_type: r.get(5)?,
                    ciphertext_hex: r.get::<_, Option<Vec<u8>>>(6)?.map(hex::encode),
                    linked_credential_id: r.get(7)?,
                    fingerprint_hex: hex::encode(r.get::<_, Vec<u8>>(8)?),
                    masked_value: r.get(9)?,
                    created_at: r.get(10)?,
                    updated_at: r.get(11)?,
                    key_created_at: r.get(12)?,
                    expires_at: r.get(13)?,
                    last_validated_at: r.get(14)?,
                    last_used_at: r.get(15)?,
                    docs_url: r.get(16)?,
                    notes: r.get(17)?,
                    manually_disabled: r.get(18)?,
                    revoked: r.get(19)?,
                    marked_invalid: r.get(20)?,
                    possibly_exposed: r.get(21)?,
                    exposure_note: r.get(22)?,
                })
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        BackupPayloadV1 {
            schema_version: claimed_schema_version,
            vault_meta,
            projects,
            project_repos: Vec::new(),
            credentials,
            audit_events: Vec::new(),
        }
    }

    #[test]
    fn legacy_v1_format_backup_restores_and_upgrades() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("orig"));
        let master = SecretString::from("legacy-master-password-01");
        let mut vault = crate::vault::create_vault(&paths, &master).unwrap();
        let project = vault
            .create_project(crate::vault::NewProject {
                name: "app".into(),
                ..Default::default()
            })
            .unwrap();
        vault
            .add_credential(crate::vault::AddCredential {
                project: project.id.clone(),
                provider: "openai".into(),
                name: "main".into(),
                environment: crate::model::Environment::Development,
                value: SecretString::from("sk-proj-FAKE-legacy-backup-test-0001"),
                credential_type: None,
                key_created_at: None,
                expires_at: None,
                docs_url: String::new(),
                notes: String::new(),
            })
            .unwrap();

        // A v1-format backup claiming an OLDER schema (v5), exactly as the
        // v0.2-era builds wrote them.
        let backup_password = SecretString::from("legacy-backup-password-01");
        let payload = v1_payload_from_vault(vault.connection(), 5);
        let file_path = dir.path().join("legacy.backup");
        write_v1_backup_file(&file_path, vault.vault_id(), &backup_password, &payload);

        let info = verify_backup(&file_path, &backup_password).unwrap();
        assert_eq!(info.format_version, 1);
        assert_eq!(info.schema_version, 5);

        // Restore into a clean directory; the vault must unlock with the
        // original master password, reveal the credential, and sit at the
        // CURRENT schema (upgrade-after-restore).
        let restored_paths = VaultPaths::new(dir.path().join("restored"));
        restore_backup(&file_path, &backup_password, &restored_paths, false).unwrap();
        let mut restored = crate::vault::unlock_vault(&restored_paths, &master).unwrap();
        assert_eq!(
            db::user_version(restored.connection()).unwrap(),
            db::current_schema_version()
        );
        let revealed = restored.reveal_credential("app/main", &master).unwrap();
        assert_eq!(revealed.expose(), "sk-proj-FAKE-legacy-backup-test-0001");
    }

    #[test]
    fn future_format_and_future_schema_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("v"));
        let master = SecretString::from("future-master-password-01");
        let vault = crate::vault::create_vault(&paths, &master).unwrap();
        let backup_password = SecretString::from("future-backup-password-01");
        let file_path = dir.path().join("b.backup");
        create_backup(&vault, &file_path, &backup_password, false).unwrap();

        // Future FORMAT version in the plaintext header -> refused before
        // any decryption is attempted.
        let raw = std::fs::read_to_string(&file_path).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        parsed["version"] = serde_json::json!(BACKUP_VERSION + 1);
        let future_path = dir.path().join("future-format.backup");
        std::fs::write(&future_path, serde_json::to_string(&parsed).unwrap()).unwrap();
        let err = verify_backup(&future_path, &backup_password).unwrap_err();
        assert!(matches!(err, CoreError::BackupInvalid(_)), "{err}");

        // Tampering the header version to v1 must fail authentication (the
        // format version is bound into the AAD), not silently re-parse.
        parsed["version"] = serde_json::json!(1);
        let demoted_path = dir.path().join("demoted.backup");
        std::fs::write(&demoted_path, serde_json::to_string(&parsed).unwrap()).unwrap();
        let err = verify_backup(&demoted_path, &backup_password).unwrap_err();
        assert!(matches!(err, CoreError::Crypto { .. }), "{err}");

        // Future SCHEMA version inside an authentic v1 payload -> refused.
        let payload = v1_payload_from_vault(vault.connection(), db::current_schema_version() + 10);
        let future_schema_path = dir.path().join("future-schema.backup");
        write_v1_backup_file(
            &future_schema_path,
            vault.vault_id(),
            &backup_password,
            &payload,
        );
        let err = verify_backup(&future_schema_path, &backup_password).unwrap_err();
        assert!(
            err.to_string().contains("schema"),
            "must name the schema problem: {err}"
        );
        let err = restore_backup(
            &future_schema_path,
            &backup_password,
            &VaultPaths::new(dir.path().join("nope")),
            false,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::BackupInvalid(_)), "{err}");
    }
}
