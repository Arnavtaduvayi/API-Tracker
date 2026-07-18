//! Encrypted vault backups.
//!
//! A backup is a JSON file: a plaintext header (format, version, KDF
//! parameters, salt) plus one AEAD envelope containing the full serialized
//! vault content — including the wrapped keys from `vault_meta`, so a
//! restored vault unlocks with the master password the vault had when the
//! backup was created. The whole payload is encrypted with a key derived
//! from a backup password chosen at creation time.
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
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const BACKUP_FORMAT: &str = "api-tracker-backup";
pub const BACKUP_VERSION: u32 = 1;

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

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    schema_version: i64,
    vault_meta: Vec<(String, String)>,
    projects: Vec<ProjectExport>,
    project_repos: Vec<(String, String)>,
    credentials: Vec<CredentialExport>,
    audit_events: Vec<AuditExport>,
}

#[derive(Serialize, Deserialize)]
struct ProjectExport {
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
struct CredentialExport {
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
struct AuditExport {
    at: String,
    event: String,
    project_id: Option<String>,
    credential_id: Option<String>,
    detail: String,
}

/// Non-secret summary of a backup, returned by create/verify/restore.
#[derive(Debug, Clone, Serialize)]
pub struct BackupInfo {
    pub path: String,
    pub vault_id: String,
    pub created_at: String,
    pub schema_version: i64,
    pub project_count: usize,
    pub credential_count: usize,
}

fn collect_payload(vault: &UnlockedVault) -> Result<BackupPayload> {
    let conn = vault.connection();
    let schema_version = db::user_version(conn)?;

    let mut stmt = conn.prepare("SELECT key, value FROM vault_meta ORDER BY key")?;
    let vault_meta: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut stmt = conn.prepare(
        "SELECT id, name, description, notes, environments, archived, created_at, updated_at,
         wrapped_project_key, key_wrap_mode, project_kdf_params, project_salt FROM projects",
    )?;
    let projects: Vec<ProjectExport> = stmt
        .query_map([], |r| {
            Ok(ProjectExport {
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
        })?
        .collect::<rusqlite::Result<_>>()?;

    let mut stmt = conn.prepare("SELECT project_id, path FROM project_repos")?;
    let project_repos: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut stmt = conn.prepare(
        "SELECT id, project_id, provider, name, environment, credential_type, ciphertext,
         linked_credential_id, fingerprint, masked_value, created_at, updated_at,
         key_created_at, expires_at, last_validated_at, last_used_at, docs_url, notes,
         manually_disabled, revoked, marked_invalid, possibly_exposed, exposure_note
         FROM credentials",
    )?;
    let credentials: Vec<CredentialExport> = stmt
        .query_map([], |r| {
            Ok(CredentialExport {
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
        })?
        .collect::<rusqlite::Result<_>>()?;

    let mut stmt =
        conn.prepare("SELECT at, event, project_id, credential_id, detail FROM audit_events")?;
    let audit_events: Vec<AuditExport> = stmt
        .query_map([], |r| {
            Ok(AuditExport {
                at: r.get(0)?,
                event: r.get(1)?,
                project_id: r.get(2)?,
                credential_id: r.get(3)?,
                detail: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;

    Ok(BackupPayload {
        schema_version,
        vault_meta,
        projects,
        project_repos,
        credentials,
        audit_events,
    })
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
    let payload = collect_payload(vault)?;
    let payload_json = serde_json::to_vec(&payload)?;
    let kdf = KdfParams::recommended();
    let salt = crypto::new_salt();
    let key = crypto::derive_key(backup_password, &salt, &kdf)?;
    let envelope = crypto::encrypt(&key, &aad::backup(vault.vault_id()), &payload_json)?;
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
        project_count: payload.projects.len(),
        credential_count: payload.credentials.len(),
    })
}

fn read_and_decrypt(
    path: &Path,
    backup_password: &SecretString,
) -> Result<(BackupFile, BackupPayload)> {
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
    if file.version != BACKUP_VERSION {
        return Err(CoreError::BackupInvalid(format!(
            "backup version {} is not supported by this build (expected {BACKUP_VERSION})",
            file.version
        )));
    }
    let salt = hex::decode(&file.salt_hex)
        .map_err(|_| CoreError::BackupInvalid("salt is not valid hex".into()))?;
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(&file.payload_b64)
        .map_err(|_| CoreError::BackupInvalid("payload is not valid base64".into()))?;
    let key = crypto::derive_key(backup_password, &salt, &file.kdf)?;
    let plaintext = crypto::decrypt(
        &key,
        &aad::backup(&file.vault_id),
        &envelope,
        "backup (wrong backup password, corruption, or tampering)",
    )?;
    let payload: BackupPayload = serde_json::from_slice(plaintext.expose())
        .map_err(|_| CoreError::BackupInvalid("decrypted payload is malformed".into()))?;
    Ok((file, payload))
}

/// Decrypt and validate a backup without restoring it.
pub fn verify_backup(path: &Path, backup_password: &SecretString) -> Result<BackupInfo> {
    let (file, payload) = read_and_decrypt(path, backup_password)?;
    if payload.schema_version > db::current_schema_version() {
        return Err(CoreError::BackupInvalid(format!(
            "backup uses database schema v{} but this build supports up to v{}",
            payload.schema_version,
            db::current_schema_version()
        )));
    }
    Ok(BackupInfo {
        path: path.display().to_string(),
        vault_id: file.vault_id,
        created_at: file.created_at,
        schema_version: payload.schema_version,
        project_count: payload.projects.len(),
        credential_count: payload.credentials.len(),
    })
}

/// Restore a backup into `target`. Refuses to overwrite an existing vault
/// unless `force`; with `force`, the current vault database is renamed
/// aside (never silently destroyed).
pub fn restore_backup(
    path: &Path,
    backup_password: &SecretString,
    target: &VaultPaths,
    force: bool,
) -> Result<BackupInfo> {
    let info = verify_backup(path, backup_password)?;
    let (_file, payload) = read_and_decrypt(path, backup_password)?;
    if payload.schema_version != db::current_schema_version() {
        return Err(CoreError::BackupInvalid(format!(
            "backup schema v{} cannot be restored by this build (expected v{})",
            payload.schema_version,
            db::current_schema_version()
        )));
    }
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
    db::migrate(&mut conn)?;
    {
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
                        .map_err(|_| CoreError::BackupInvalid(
                            "credential ciphertext hex".into()
                        ))?,
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
    }
    // Any pre-existing session belongs to the replaced vault.
    session::destroy(target)?;
    crate::audit::record(&conn, "vault_restored_from_backup", None, None, "")?;
    Ok(info)
}
