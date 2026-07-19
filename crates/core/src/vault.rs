//! The encrypted vault: key hierarchy, projects, and credentials.
//!
//! Key hierarchy (docs/decisions/0003-vault-key-hierarchy.md):
//!
//! ```text
//! master password ──Argon2id──▶ KEK ──wraps──▶ vault key (random 32B)
//! vault key ──wraps──▶ fingerprint key (random 32B)
//! vault key ──wraps──▶ project key (random 32B per project)
//!   password-locked projects add an inner wrap:
//!   vault key ──wraps──▶ [ project-password KEK ──wraps──▶ project key ]
//! project key ──encrypts──▶ each credential value
//! ```
//!
//! Passwords are never stored. A wrong password surfaces as an AEAD
//! authentication failure when unwrapping, so no separate password hash is
//! kept. Every wrap is bound to AAD naming the vault/project it belongs to.

use crate::alerts;
use crate::audit;
use crate::clock;
use crate::crypto::{self, aad, KdfParams};
use crate::db;
use crate::error::{CoreError, Result};
use crate::model::{mask_value, Credential, Environment, Project};
use crate::reuse::{self, ReuseMatch, ReuseWarning};
use crate::scanner;
use crate::secret::{SecretBytes, SecretString};
use crate::session::{self, SessionKeys, SessionToken};
use crate::settings::VaultSettings;
use crate::status::{self, StatusInputs};
use crate::usage;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use uuid::Uuid;

/// Minimum length for newly chosen master, project, and backup passwords.
/// Enforced only when a password is *set* — existing vaults, projects, and
/// backups created under an older, shorter policy still unlock and restore.
/// A multi-word passphrase well beyond this minimum is recommended; length
/// is the primary defense the user controls, on top of Argon2id stretching.
pub const MIN_PASSWORD_LEN: usize = 12;
/// Retained versions an ACTIVE rotation still needs for rollback are exempt
/// from every prune (count cap, rollback window, unlock sweep).
const VERSION_PRUNE_ROTATION_EXEMPTION: &str = " AND NOT EXISTS (
    SELECT 1 FROM rotations r
    WHERE r.credential_id = credential_versions.credential_id
      AND r.old_version = credential_versions.version
      AND r.state NOT IN ('completed', 'rolled_back', 'failed', 'planned'))";
const DB_FILE: &str = "vault.db";
const SESSION_FILE: &str = "session.json";

/// Filesystem locations for one vault.
#[derive(Debug, Clone)]
pub struct VaultPaths {
    pub data_dir: PathBuf,
}

impl VaultPaths {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join(DB_FILE)
    }

    pub fn session_path(&self) -> PathBuf {
        self.data_dir.join(SESSION_FILE)
    }

    pub fn vault_exists(&self) -> bool {
        self.db_path().exists()
    }
}

/// Default shared data directory for the desktop app and CLI.
/// `API_TRACKER_DIR` overrides it (used by tests and power users).
pub fn default_data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("API_TRACKER_DIR") {
        return Ok(PathBuf::from(dir));
    }
    directories::ProjectDirs::from("", "", "api-tracker")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .ok_or_else(|| {
            CoreError::InvalidInput(
                "could not determine a data directory; set API_TRACKER_DIR".to_owned(),
            )
        })
}

fn validate_password(password: &SecretString, what: &str) -> Result<()> {
    if password.expose().len() < MIN_PASSWORD_LEN {
        return Err(CoreError::InvalidInput(format!(
            "{what} must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT value FROM vault_meta WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()?)
}

fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn meta_require(conn: &Connection, key: &'static str) -> Result<String> {
    meta_get(conn, key)?.ok_or(CoreError::VaultCorrupted("missing vault metadata"))
}

#[cfg(unix)]
fn restrict_dir_permissions(dir: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_dir: &std::path::Path) -> Result<()> {
    Ok(())
}

/// Restrict the vault data directory to the current user (0700 on Unix).
/// Exposed so backup restore applies the same protection as vault creation.
pub fn restrict_data_dir_permissions(dir: &std::path::Path) -> Result<()> {
    restrict_dir_permissions(dir)
}

/// Create a brand-new vault. Fails if one already exists (never silently
/// overwrites).
pub fn create_vault(paths: &VaultPaths, master_password: &SecretString) -> Result<UnlockedVault> {
    validate_password(master_password, "the master password")?;
    if paths.vault_exists() {
        return Err(CoreError::VaultExists(paths.db_path()));
    }
    std::fs::create_dir_all(&paths.data_dir)?;
    restrict_dir_permissions(&paths.data_dir)?;

    let mut conn = db::open(&paths.db_path())?;
    db::migrate(&mut conn)?;

    let vault_id = Uuid::new_v4().to_string();
    let kdf = KdfParams::recommended();
    let salt = crypto::new_salt();
    let kek = crypto::derive_key(master_password, &salt, &kdf)?;
    let vault_key = crypto::new_key();
    let fingerprint_key = crypto::new_key();

    let wrapped_vault_key = crypto::encrypt(&kek, &aad::vault_key(&vault_id), vault_key.expose())?;
    let wrapped_fingerprint_key = crypto::encrypt(
        &vault_key,
        &aad::fingerprint_key(&vault_id),
        fingerprint_key.expose(),
    )?;

    meta_set(&conn, "vault_id", &vault_id)?;
    meta_set(&conn, "created_at", &clock::now_rfc3339())?;
    meta_set(&conn, "crypto_version", &crypto::CRYPTO_VERSION.to_string())?;
    meta_set(&conn, "kdf_params", &serde_json::to_string(&kdf)?)?;
    meta_set(&conn, "master_salt", &hex::encode(&salt))?;
    meta_set(&conn, "wrapped_vault_key", &hex::encode(&wrapped_vault_key))?;
    meta_set(
        &conn,
        "wrapped_fingerprint_key",
        &hex::encode(&wrapped_fingerprint_key),
    )?;

    let settings = VaultSettings::default();
    settings.save(&conn)?;
    audit::record(&conn, "vault_created", None, None, "")?;

    Ok(UnlockedVault {
        conn,
        vault_id,
        vault_key,
        fingerprint_key,
        project_keys: HashMap::new(),
        settings,
        paths: paths.clone(),
    })
}

fn load_master_wrap(conn: &Connection) -> Result<(String, KdfParams, Vec<u8>, Vec<u8>)> {
    let vault_id = meta_require(conn, "vault_id")?;
    let kdf: KdfParams = serde_json::from_str(&meta_require(conn, "kdf_params")?)?;
    let salt = hex::decode(meta_require(conn, "master_salt")?)
        .map_err(|_| CoreError::VaultCorrupted("master salt is not valid hex"))?;
    let wrapped = hex::decode(meta_require(conn, "wrapped_vault_key")?)
        .map_err(|_| CoreError::VaultCorrupted("wrapped vault key is not valid hex"))?;
    Ok((vault_id, kdf, salt, wrapped))
}

/// Unlock an existing vault with the master password.
pub fn unlock_vault(paths: &VaultPaths, master_password: &SecretString) -> Result<UnlockedVault> {
    if !paths.vault_exists() {
        return Err(CoreError::VaultNotFound(paths.db_path()));
    }
    let mut conn = db::open(&paths.db_path())?;
    db::migrate(&mut conn)?;

    let (vault_id, kdf, salt, wrapped) = load_master_wrap(&conn)?;
    let kek = crypto::derive_key(master_password, &salt, &kdf)?;
    let vault_key = crypto::decrypt(&kek, &aad::vault_key(&vault_id), &wrapped, "vault key")
        .map_err(|_| CoreError::WrongPassword)?;

    let fingerprint_key = unwrap_fingerprint_key(&conn, &vault_id, &vault_key)?;
    let settings = VaultSettings::load(&conn)?;
    audit::record(&conn, "vault_unlocked", None, None, "")?;
    // Best-effort sweeps on unlock: expired temporary exports and retained
    // versions past the rollback window (secure_delete overwrites pages).
    let _ = crate::envgov::cleanup_exports(&conn, false, false, &clock::now_rfc3339());
    if settings.rollback_window_days > 0 {
        let cutoff = clock::to_rfc3339(
            clock::now() - time::Duration::days(i64::from(settings.rollback_window_days)),
        );
        let _ = conn.execute(
            &format!(
                "DELETE FROM credential_versions WHERE created_at < ?1{}",
                VERSION_PRUNE_ROTATION_EXEMPTION
            ),
            [&cutoff],
        );
    }

    Ok(UnlockedVault {
        conn,
        vault_id,
        vault_key,
        fingerprint_key,
        project_keys: HashMap::new(),
        settings,
        paths: paths.clone(),
    })
}

fn unwrap_fingerprint_key(
    conn: &Connection,
    vault_id: &str,
    vault_key: &SecretBytes,
) -> Result<SecretBytes> {
    let wrapped = hex::decode(meta_require(conn, "wrapped_fingerprint_key")?)
        .map_err(|_| CoreError::VaultCorrupted("wrapped fingerprint key is not valid hex"))?;
    crypto::decrypt(
        vault_key,
        &aad::fingerprint_key(vault_id),
        &wrapped,
        "fingerprint key",
    )
}

/// Resume an unlocked state from a CLI session token (see session.rs).
pub fn resume_session(paths: &VaultPaths, token: &SessionToken) -> Result<UnlockedVault> {
    if !paths.vault_exists() {
        return Err(CoreError::VaultNotFound(paths.db_path()));
    }
    let mut conn = db::open(&paths.db_path())?;
    db::migrate(&mut conn)?;
    let keys = session::load_and_refresh(paths, token)?;
    let vault_id = meta_require(&conn, "vault_id")?;
    // Validate that the session's vault key actually belongs to this vault
    // (this fails if the vault was replaced since the session started).
    let fingerprint_key = unwrap_fingerprint_key(&conn, &vault_id, &keys.vault_key)
        .map_err(|_| CoreError::SessionInvalid)?;
    let settings = VaultSettings::load(&conn)?;
    Ok(UnlockedVault {
        conn,
        vault_id,
        vault_key: keys.vault_key,
        fingerprint_key,
        project_keys: keys.project_keys,
        settings,
        paths: paths.clone(),
    })
}

/// New-project parameters.
#[derive(Debug, Clone, Default)]
pub struct NewProject {
    pub name: String,
    pub description: String,
    pub notes: String,
    pub environments: Vec<Environment>,
    pub repo_paths: Vec<String>,
}

/// Project metadata updates; `None` leaves a field unchanged.
#[derive(Debug, Clone, Default)]
pub struct UpdateProject {
    pub name: Option<String>,
    pub description: Option<String>,
    pub notes: Option<String>,
    pub environments: Option<Vec<Environment>>,
    pub add_repo_paths: Vec<String>,
    pub remove_repo_paths: Vec<String>,
}

/// New-credential parameters. Dates accept `YYYY-MM-DD` or RFC 3339.
#[derive(Debug)]
pub struct AddCredential {
    pub project: String,
    pub provider: String,
    pub name: String,
    pub environment: Environment,
    pub value: SecretString,
    pub credential_type: Option<String>,
    pub key_created_at: Option<String>,
    pub expires_at: Option<String>,
    pub docs_url: String,
    pub notes: String,
}

/// Parameters for an intentional reference to an existing credential's value.
#[derive(Debug, Clone)]
pub struct AddReference {
    pub project: String,
    pub source: String,
    pub name: String,
    pub environment: Environment,
    pub docs_url: String,
    pub notes: String,
}

/// Credential metadata updates; `None` leaves a field unchanged and
/// `Some(None)` clears an optional field.
#[derive(Debug, Clone, Default)]
pub struct UpdateCredential {
    pub name: Option<String>,
    pub provider: Option<String>,
    pub environment: Option<Environment>,
    pub key_created_at: Option<Option<String>>,
    pub expires_at: Option<Option<String>>,
    pub docs_url: Option<String>,
    pub notes: Option<String>,
    pub mark_used_now: bool,
    /// `Some(true)`: record a successful validation now. `Some(false)`:
    /// record that validation failed (marks the credential invalid).
    pub mark_validated: Option<bool>,
    pub disabled: Option<bool>,
    pub revoked: Option<bool>,
    pub possibly_exposed: Option<bool>,
    pub exposure_note: Option<String>,
}

struct ProjectRow {
    id: String,
    name: String,
    description: String,
    notes: String,
    environments_json: String,
    archived: bool,
    created_at: String,
    updated_at: String,
    wrapped_project_key: Vec<u8>,
    key_wrap_mode: String,
    project_kdf_params: Option<String>,
    project_salt: Option<Vec<u8>>,
}

struct CredentialRow {
    id: String,
    project_id: String,
    provider: String,
    name: String,
    environment: String,
    credential_type: String,
    ciphertext: Option<Vec<u8>>,
    linked_credential_id: Option<String>,
    fingerprint: Vec<u8>,
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
    provider_expires_at: Option<String>,
}

const CREDENTIAL_COLUMNS: &str = "id, project_id, provider, name, environment, credential_type, \
     ciphertext, linked_credential_id, fingerprint, masked_value, created_at, updated_at, \
     key_created_at, expires_at, last_validated_at, last_used_at, docs_url, notes, \
     manually_disabled, revoked, marked_invalid, possibly_exposed, exposure_note, \
     provider_expires_at";

fn credential_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialRow> {
    Ok(CredentialRow {
        id: row.get(0)?,
        project_id: row.get(1)?,
        provider: row.get(2)?,
        name: row.get(3)?,
        environment: row.get(4)?,
        credential_type: row.get(5)?,
        ciphertext: row.get(6)?,
        linked_credential_id: row.get(7)?,
        fingerprint: row.get(8)?,
        masked_value: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        key_created_at: row.get(12)?,
        expires_at: row.get(13)?,
        last_validated_at: row.get(14)?,
        last_used_at: row.get(15)?,
        docs_url: row.get(16)?,
        notes: row.get(17)?,
        manually_disabled: row.get(18)?,
        revoked: row.get(19)?,
        marked_invalid: row.get(20)?,
        possibly_exposed: row.get(21)?,
        exposure_note: row.get(22)?,
        provider_expires_at: row.get(23)?,
    })
}

const PROJECT_COLUMNS: &str = "id, name, description, notes, environments, archived, created_at, \
     updated_at, wrapped_project_key, key_wrap_mode, project_kdf_params, project_salt";

fn project_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRow> {
    Ok(ProjectRow {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        notes: row.get(3)?,
        environments_json: row.get(4)?,
        archived: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        wrapped_project_key: row.get(8)?,
        key_wrap_mode: row.get(9)?,
        project_kdf_params: row.get(10)?,
        project_salt: row.get(11)?,
    })
}

/// An unlocked vault. Dropping it zeroizes all key material.
pub struct UnlockedVault {
    conn: Connection,
    vault_id: String,
    vault_key: SecretBytes,
    fingerprint_key: SecretBytes,
    /// Session-unlocked keys of password-locked projects.
    project_keys: HashMap<String, SecretBytes>,
    settings: VaultSettings,
    paths: VaultPaths,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose key material; only non-secret identifiers.
        f.debug_struct("UnlockedVault")
            .field("vault_id", &self.vault_id)
            .field("data_dir", &self.paths.data_dir)
            .finish_non_exhaustive()
    }
}

impl UnlockedVault {
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    /// Read-only database access for diagnostics and backups.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn settings(&self) -> &VaultSettings {
        &self.settings
    }

    pub fn update_settings(&mut self, settings: VaultSettings) -> Result<()> {
        settings.save(&self.conn)?;
        self.settings = settings;
        audit::record(&self.conn, "settings_updated", None, None, "")?;
        Ok(())
    }

    /// Re-verify the master password (reauthentication for sensitive
    /// actions). Runs the full Argon2id derivation.
    pub fn verify_master_password(&self, master_password: &SecretString) -> Result<()> {
        let (vault_id, kdf, salt, wrapped) = load_master_wrap(&self.conn)?;
        let kek = crypto::derive_key(master_password, &salt, &kdf)?;
        crypto::decrypt(&kek, &aad::vault_key(&vault_id), &wrapped, "vault key")
            .map_err(|_| CoreError::WrongPassword)?;
        Ok(())
    }

    /// Explicitly lock: consume and drop (zeroization happens on drop).
    pub fn lock(self) {}

    pub(crate) fn export_session_keys(&self) -> SessionKeys {
        SessionKeys {
            vault_key: self.vault_key.clone(),
            project_keys: self.project_keys.clone(),
        }
    }

    /// Persist a CLI session for this unlocked vault.
    pub fn save_session(&self, token: &SessionToken) -> Result<()> {
        session::save(
            &self.paths,
            token,
            &self.export_session_keys(),
            self.settings.auto_lock_minutes,
        )
    }

    // ------------------------------------------------------------------
    // Projects
    // ------------------------------------------------------------------

    fn project_row_by_ident(&self, ident: &str) -> Result<ProjectRow> {
        let by_id = self
            .conn
            .query_row(
                &format!("SELECT {PROJECT_COLUMNS} FROM projects WHERE id = ?1"),
                [ident],
                project_row,
            )
            .optional()?;
        if let Some(row) = by_id {
            return Ok(row);
        }
        self.conn
            .query_row(
                &format!("SELECT {PROJECT_COLUMNS} FROM projects WHERE name = ?1 COLLATE NOCASE"),
                [ident],
                project_row,
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound {
                kind: "project",
                ident: ident.to_owned(),
            })
    }

    fn project_name_taken(&self, name: &str, exclude_id: Option<&str>) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT count(*) FROM projects WHERE name = ?1 COLLATE NOCASE AND id != ?2",
            params![name, exclude_id.unwrap_or("")],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    fn repo_paths(&self, project_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path FROM project_repos WHERE project_id = ?1 ORDER BY path")?;
        let rows = stmt.query_map([project_id], |r| r.get(0))?;
        let mut paths = Vec::new();
        for p in rows {
            paths.push(p?);
        }
        Ok(paths)
    }

    fn project_model(&self, row: &ProjectRow) -> Result<Project> {
        let environments: Vec<Environment> = serde_json::from_str(&row.environments_json)?;
        let credential_count: i64 = self.conn.query_row(
            "SELECT count(*) FROM credentials WHERE project_id = ?1",
            [&row.id],
            |r| r.get(0),
        )?;
        let password_locked = row.key_wrap_mode == "vault+password";
        Ok(Project {
            id: row.id.clone(),
            name: row.name.clone(),
            description: row.description.clone(),
            notes: row.notes.clone(),
            environments,
            repo_paths: self.repo_paths(&row.id)?,
            archived: row.archived,
            password_locked,
            unlocked: !password_locked || self.project_keys.contains_key(&row.id),
            created_at: row.created_at.clone(),
            updated_at: row.updated_at.clone(),
            credential_count,
        })
    }

    pub fn create_project(&mut self, new: NewProject) -> Result<Project> {
        let name = new.name.trim().to_owned();
        if name.is_empty() {
            return Err(CoreError::InvalidInput(
                "project name must not be empty".into(),
            ));
        }
        if name.contains('/') {
            return Err(CoreError::InvalidInput(
                "project names must not contain '/' (it is used as a selector separator)".into(),
            ));
        }
        if self.project_name_taken(&name, None)? {
            return Err(CoreError::AlreadyExists {
                kind: "project",
                ident: name,
            });
        }
        let id = Uuid::new_v4().to_string();
        let project_key = crypto::new_key();
        let wrapped = crypto::encrypt(
            &self.vault_key,
            &aad::project_key(&self.vault_id, &id),
            project_key.expose(),
        )?;
        let now = clock::now_rfc3339();
        let mut environments = new.environments;
        environments.sort();
        environments.dedup();
        self.conn.execute(
            "INSERT INTO projects (id, name, description, notes, environments, archived,
             created_at, updated_at, wrapped_project_key, key_wrap_mode)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, 'vault')",
            params![
                id,
                name,
                new.description.trim(),
                new.notes,
                serde_json::to_string(&environments)?,
                now,
                now,
                wrapped,
            ],
        )?;
        let mut repos: Vec<String> = new.repo_paths;
        repos.sort();
        repos.dedup();
        for repo in &repos {
            self.conn.execute(
                "INSERT OR IGNORE INTO project_repos (project_id, path) VALUES (?1, ?2)",
                params![id, repo],
            )?;
        }
        audit::record(
            &self.conn,
            "project_created",
            Some(&id),
            None,
            &format!("name={name}"),
        )?;
        let row = self.project_row_by_ident(&id)?;
        self.project_model(&row)
    }

    pub fn list_projects(&self, include_archived: bool) -> Result<Vec<Project>> {
        let sql = if include_archived {
            format!("SELECT {PROJECT_COLUMNS} FROM projects ORDER BY name")
        } else {
            format!("SELECT {PROJECT_COLUMNS} FROM projects WHERE archived = 0 ORDER BY name")
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: Vec<ProjectRow> = stmt
            .query_map([], project_row)?
            .collect::<rusqlite::Result<_>>()?;
        rows.iter().map(|row| self.project_model(row)).collect()
    }

    pub fn get_project(&self, ident: &str) -> Result<Project> {
        let row = self.project_row_by_ident(ident)?;
        self.project_model(&row)
    }

    pub fn update_project(&mut self, ident: &str, update: UpdateProject) -> Result<Project> {
        let row = self.project_row_by_ident(ident)?;
        let mut changed: Vec<&str> = Vec::new();
        if let Some(name) = &update.name {
            let name = name.trim();
            if name.is_empty() {
                return Err(CoreError::InvalidInput(
                    "project name must not be empty".into(),
                ));
            }
            if name.contains('/') {
                return Err(CoreError::InvalidInput(
                    "project names must not contain '/' (it is used as a selector separator)"
                        .into(),
                ));
            }
            if self.project_name_taken(name, Some(&row.id))? {
                return Err(CoreError::AlreadyExists {
                    kind: "project",
                    ident: name.to_owned(),
                });
            }
            self.conn.execute(
                "UPDATE projects SET name = ?1 WHERE id = ?2",
                params![name, row.id],
            )?;
            changed.push("name");
        }
        if let Some(description) = &update.description {
            self.conn.execute(
                "UPDATE projects SET description = ?1 WHERE id = ?2",
                params![description.trim(), row.id],
            )?;
            changed.push("description");
        }
        if let Some(notes) = &update.notes {
            self.conn.execute(
                "UPDATE projects SET notes = ?1 WHERE id = ?2",
                params![notes, row.id],
            )?;
            changed.push("notes");
        }
        if let Some(environments) = &update.environments {
            let mut envs = environments.clone();
            envs.sort();
            envs.dedup();
            self.conn.execute(
                "UPDATE projects SET environments = ?1 WHERE id = ?2",
                params![serde_json::to_string(&envs)?, row.id],
            )?;
            changed.push("environments");
        }
        for repo in &update.add_repo_paths {
            self.conn.execute(
                "INSERT OR IGNORE INTO project_repos (project_id, path) VALUES (?1, ?2)",
                params![row.id, repo],
            )?;
            changed.push("repos");
        }
        for repo in &update.remove_repo_paths {
            self.conn.execute(
                "DELETE FROM project_repos WHERE project_id = ?1 AND path = ?2",
                params![row.id, repo],
            )?;
            changed.push("repos");
        }
        if !changed.is_empty() {
            self.conn.execute(
                "UPDATE projects SET updated_at = ?1 WHERE id = ?2",
                params![clock::now_rfc3339(), row.id],
            )?;
            changed.dedup();
            audit::record(
                &self.conn,
                "project_updated",
                Some(&row.id),
                None,
                &format!("fields={}", changed.join(",")),
            )?;
        }
        self.get_project(&row.id)
    }

    pub fn set_project_archived(&mut self, ident: &str, archived: bool) -> Result<Project> {
        let row = self.project_row_by_ident(ident)?;
        self.conn.execute(
            "UPDATE projects SET archived = ?1, updated_at = ?2 WHERE id = ?3",
            params![archived, clock::now_rfc3339(), row.id],
        )?;
        audit::record(
            &self.conn,
            if archived {
                "project_archived"
            } else {
                "project_restored"
            },
            Some(&row.id),
            None,
            "",
        )?;
        self.get_project(&row.id)
    }

    /// The decrypted key for a project. Fails with [`CoreError::ProjectLocked`]
    /// for password-locked projects that have not been unlocked this session.
    fn project_key_for_row(&self, row: &ProjectRow) -> Result<SecretBytes> {
        match row.key_wrap_mode.as_str() {
            "vault" => crypto::decrypt(
                &self.vault_key,
                &aad::project_key(&self.vault_id, &row.id),
                &row.wrapped_project_key,
                "project key",
            ),
            "vault+password" => self
                .project_keys
                .get(&row.id)
                .cloned()
                .ok_or_else(|| CoreError::ProjectLocked(row.name.clone())),
            _ => Err(CoreError::VaultCorrupted("unknown project key wrap mode")),
        }
    }

    /// Add (or change) a project password. The project key gets an inner
    /// password wrap; losing the password makes the project's credential
    /// values unrecoverable (documented recovery limitation).
    pub fn set_project_password(&mut self, ident: &str, password: &SecretString) -> Result<()> {
        validate_password(password, "the project password")?;
        let row = self.project_row_by_ident(ident)?;
        let project_key = self.project_key_for_row(&row)?;
        let kdf = KdfParams::recommended();
        let salt = crypto::new_salt();
        let kek = crypto::derive_key(password, &salt, &kdf)?;
        let inner = crypto::encrypt(
            &kek,
            &aad::project_key_password(&self.vault_id, &row.id),
            project_key.expose(),
        )?;
        let outer = crypto::encrypt(
            &self.vault_key,
            &aad::project_key(&self.vault_id, &row.id),
            &inner,
        )?;
        self.conn.execute(
            "UPDATE projects SET wrapped_project_key = ?1, key_wrap_mode = 'vault+password',
             project_kdf_params = ?2, project_salt = ?3, updated_at = ?4 WHERE id = ?5",
            params![
                outer,
                serde_json::to_string(&kdf)?,
                salt,
                clock::now_rfc3339(),
                row.id
            ],
        )?;
        // The caller just proved knowledge of the password; keep it unlocked
        // for this session.
        self.project_keys.insert(row.id.clone(), project_key);
        audit::record(&self.conn, "project_password_set", Some(&row.id), None, "")?;
        Ok(())
    }

    fn unwrap_project_key_with_password(
        &self,
        row: &ProjectRow,
        password: &SecretString,
    ) -> Result<SecretBytes> {
        let (Some(kdf_json), Some(salt)) = (&row.project_kdf_params, &row.project_salt) else {
            return Err(CoreError::VaultCorrupted(
                "password-locked project is missing KDF data",
            ));
        };
        let kdf: KdfParams = serde_json::from_str(kdf_json)?;
        let inner = crypto::decrypt(
            &self.vault_key,
            &aad::project_key(&self.vault_id, &row.id),
            &row.wrapped_project_key,
            "project key (outer wrap)",
        )?;
        let kek = crypto::derive_key(password, salt, &kdf)?;
        crypto::decrypt(
            &kek,
            &aad::project_key_password(&self.vault_id, &row.id),
            inner.expose(),
            "project key",
        )
        .map_err(|_| CoreError::WrongPassword)
    }

    /// Unlock a password-locked project for this session.
    pub fn unlock_project(&mut self, ident: &str, password: &SecretString) -> Result<Project> {
        let row = self.project_row_by_ident(ident)?;
        if row.key_wrap_mode != "vault+password" {
            return Err(CoreError::InvalidInput(format!(
                "project '{}' has no password lock",
                row.name
            )));
        }
        let project_key = self.unwrap_project_key_with_password(&row, password)?;
        self.project_keys.insert(row.id.clone(), project_key);
        audit::record(&self.conn, "project_unlocked", Some(&row.id), None, "")?;
        self.project_model(&row)
    }

    /// Drop a password-locked project's key from this session.
    pub fn lock_project(&mut self, ident: &str) -> Result<Project> {
        let row = self.project_row_by_ident(ident)?;
        if row.key_wrap_mode != "vault+password" {
            return Err(CoreError::InvalidInput(format!(
                "project '{}' has no password lock; `project lock` first sets one with a password",
                row.name
            )));
        }
        self.project_keys.remove(&row.id);
        audit::record(&self.conn, "project_locked", Some(&row.id), None, "")?;
        self.project_model(&row)
    }

    /// Remove a project's password lock (requires the current project
    /// password, proving authorization).
    pub fn remove_project_password(&mut self, ident: &str, password: &SecretString) -> Result<()> {
        let row = self.project_row_by_ident(ident)?;
        if row.key_wrap_mode != "vault+password" {
            return Err(CoreError::InvalidInput(format!(
                "project '{}' has no password lock",
                row.name
            )));
        }
        let project_key = self.unwrap_project_key_with_password(&row, password)?;
        let wrapped = crypto::encrypt(
            &self.vault_key,
            &aad::project_key(&self.vault_id, &row.id),
            project_key.expose(),
        )?;
        self.conn.execute(
            "UPDATE projects SET wrapped_project_key = ?1, key_wrap_mode = 'vault',
             project_kdf_params = NULL, project_salt = NULL, updated_at = ?2 WHERE id = ?3",
            params![wrapped, clock::now_rfc3339(), row.id],
        )?;
        self.project_keys.remove(&row.id);
        audit::record(
            &self.conn,
            "project_password_removed",
            Some(&row.id),
            None,
            "",
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Credentials
    // ------------------------------------------------------------------

    fn credential_row_by_id(&self, id: &str) -> Result<Option<CredentialRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {CREDENTIAL_COLUMNS} FROM credentials WHERE id = ?1"),
                [id],
                credential_row,
            )
            .optional()?)
    }

    /// Resolve `<id>`, `<project>/<name>`, or a vault-unique credential name.
    fn resolve_credential(&self, selector: &str) -> Result<CredentialRow> {
        if let Some(row) = self.credential_row_by_id(selector)? {
            return Ok(row);
        }
        if let Some((project_ident, name)) = selector.split_once('/') {
            let project = self.project_row_by_ident(project_ident)?;
            return self
                .conn
                .query_row(
                    &format!(
                        "SELECT {CREDENTIAL_COLUMNS} FROM credentials
                         WHERE project_id = ?1 AND name = ?2 COLLATE NOCASE"
                    ),
                    params![project.id, name],
                    credential_row,
                )
                .optional()?
                .ok_or_else(|| CoreError::NotFound {
                    kind: "credential",
                    ident: selector.to_owned(),
                });
        }
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {CREDENTIAL_COLUMNS} FROM credentials WHERE name = ?1 COLLATE NOCASE"
        ))?;
        let rows: Vec<CredentialRow> = stmt
            .query_map([selector], credential_row)?
            .collect::<rusqlite::Result<_>>()?;
        match rows.len() {
            0 => Err(CoreError::NotFound {
                kind: "credential",
                ident: selector.to_owned(),
            }),
            1 => Ok(rows.into_iter().next().expect("length checked")),
            _ => Err(CoreError::Ambiguous {
                kind: "credential",
                ident: selector.to_owned(),
            }),
        }
    }

    fn project_name_of(&self, project_id: &str) -> Result<String> {
        Ok(self.conn.query_row(
            "SELECT name FROM projects WHERE id = ?1",
            [project_id],
            |r| r.get(0),
        )?)
    }

    /// Other credentials sharing a fingerprint.
    fn find_reuse_matches(
        &self,
        fingerprint: &[u8],
        exclude_credential: Option<&str>,
    ) -> Result<Vec<ReuseMatch>> {
        let mut stmt = self.conn.prepare(
            "SELECT c.id, c.name, c.project_id, p.name, c.environment,
                    c.linked_credential_id IS NOT NULL
             FROM credentials c JOIN projects p ON p.id = c.project_id
             WHERE c.fingerprint = ?1 AND c.id != ?2
             ORDER BY p.name, c.name",
        )?;
        let rows = stmt.query_map(
            params![fingerprint, exclude_credential.unwrap_or("")],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, bool>(5)?,
                ))
            },
        )?;
        let mut matches = Vec::new();
        for row in rows {
            let (credential_id, credential_name, project_id, project_name, environment, is_ref) =
                row?;
            matches.push(ReuseMatch {
                credential_id,
                credential_name,
                project_id,
                project_name,
                environment: environment.parse()?,
                is_reference: is_ref,
            });
        }
        Ok(matches)
    }

    /// Check a value for reuse *before* storing it, so callers can let the
    /// user choose between a copy, a reference, or aborting.
    pub fn check_reuse(
        &self,
        project: &str,
        environment: Environment,
        value: &SecretString,
    ) -> Result<Vec<ReuseWarning>> {
        let project = self.project_row_by_ident(project)?;
        let fp = reuse::fingerprint(&self.fingerprint_key, value)?;
        let matches = self.find_reuse_matches(&fp, None)?;
        Ok(reuse::classify(&project.id, environment, matches))
    }

    pub fn add_credential(
        &mut self,
        add: AddCredential,
    ) -> Result<(Credential, Vec<ReuseWarning>)> {
        let project = self.project_row_by_ident(&add.project)?;
        if project.archived {
            return Err(CoreError::InvalidInput(format!(
                "project '{}' is archived; restore it before adding credentials",
                project.name
            )));
        }
        let name = add.name.trim().to_owned();
        if name.is_empty() {
            return Err(CoreError::InvalidInput(
                "credential name must not be empty".into(),
            ));
        }
        if add.value.expose().trim().is_empty() {
            return Err(CoreError::InvalidInput(
                "credential value must not be empty".into(),
            ));
        }
        self.ensure_credential_name_free(&project.id, &name, None)?;

        let project_key = self.project_key_for_row(&project)?;
        let fp = reuse::fingerprint(&self.fingerprint_key, &add.value)?;
        let warnings = reuse::classify(
            &project.id,
            add.environment,
            self.find_reuse_matches(&fp, None)?,
        );
        let id = Uuid::new_v4().to_string();
        let ciphertext = crypto::encrypt(
            &project_key,
            &aad::credential_value(&self.vault_id, &project.id, &id),
            add.value.expose().trim().as_bytes(),
        )?;
        let now = clock::now_rfc3339();
        let key_created_at = parse_optional_date(add.key_created_at.as_deref())?;
        let expires_at = parse_optional_date(add.expires_at.as_deref())?;
        self.conn.execute(
            "INSERT INTO credentials (id, project_id, provider, name, environment,
             credential_type, ciphertext, fingerprint, masked_value, created_at, updated_at,
             key_created_at, expires_at, docs_url, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                id,
                project.id,
                crate::providers::normalize(&add.provider),
                name,
                add.environment.as_str(),
                add.credential_type.unwrap_or_else(|| "api_key".to_owned()),
                ciphertext,
                fp,
                mask_value(add.value.expose()),
                now,
                now,
                key_created_at,
                expires_at,
                add.docs_url.trim(),
                add.notes,
            ],
        )?;
        audit::record(
            &self.conn,
            "credential_created",
            Some(&project.id),
            Some(&id),
            &format!("name={name}"),
        )?;
        Ok((self.get_credential(&id)?, warnings))
    }

    fn ensure_credential_name_free(
        &self,
        project_id: &str,
        name: &str,
        exclude_id: Option<&str>,
    ) -> Result<()> {
        let count: i64 = self.conn.query_row(
            "SELECT count(*) FROM credentials
             WHERE project_id = ?1 AND name = ?2 COLLATE NOCASE AND id != ?3",
            params![project_id, name, exclude_id.unwrap_or("")],
            |r| r.get(0),
        )?;
        if count > 0 {
            return Err(CoreError::AlreadyExists {
                kind: "credential",
                ident: name.to_owned(),
            });
        }
        Ok(())
    }

    /// Store an intentional reference to an existing credential's encrypted
    /// value instead of a second copy of the secret.
    pub fn add_credential_reference(&mut self, add: AddReference) -> Result<Credential> {
        let project = self.project_row_by_ident(&add.project)?;
        if project.archived {
            return Err(CoreError::InvalidInput(format!(
                "project '{}' is archived; restore it before adding credentials",
                project.name
            )));
        }
        let source = self.resolve_credential(&add.source)?;
        // References always point at the value-bearing record.
        let root = match &source.linked_credential_id {
            Some(target) => self
                .credential_row_by_id(target)?
                .ok_or(CoreError::VaultCorrupted("reference target is missing"))?,
            None => source,
        };
        if root.ciphertext.is_none() {
            return Err(CoreError::InvalidLink(
                "the reference target does not store a value".into(),
            ));
        }
        let name = add.name.trim().to_owned();
        if name.is_empty() {
            return Err(CoreError::InvalidInput(
                "credential name must not be empty".into(),
            ));
        }
        self.ensure_credential_name_free(&project.id, &name, None)?;
        let id = Uuid::new_v4().to_string();
        let now = clock::now_rfc3339();
        self.conn.execute(
            "INSERT INTO credentials (id, project_id, provider, name, environment,
             credential_type, linked_credential_id, fingerprint, masked_value,
             created_at, updated_at, docs_url, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                id,
                project.id,
                root.provider,
                name,
                add.environment.as_str(),
                root.credential_type,
                root.id,
                root.fingerprint,
                root.masked_value,
                now,
                now,
                add.docs_url.trim(),
                add.notes,
            ],
        )?;
        audit::record(
            &self.conn,
            "credential_reference_created",
            Some(&project.id),
            Some(&id),
            &format!("target={}", root.id),
        )?;
        self.get_credential(&id)
    }

    /// Reuse info for one credential: names of other projects sharing the
    /// fingerprint, and whether any of the sharing records is a reference.
    fn sharing_info(&self, row: &CredentialRow) -> Result<(Vec<String>, bool)> {
        let matches = self.find_reuse_matches(&row.fingerprint, Some(&row.id))?;
        let mut projects: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut any_reference = row.linked_credential_id.is_some();
        for m in &matches {
            if m.is_reference {
                any_reference = true;
            }
            if m.project_id != row.project_id && seen.insert(m.project_id.clone()) {
                projects.push(m.project_name.clone());
            }
        }
        Ok((projects, any_reference))
    }

    fn credential_model(&self, row: &CredentialRow) -> Result<Credential> {
        let project_name = self.project_name_of(&row.project_id)?;
        let (shared_with, sharing_is_reference) = self.sharing_info(row)?;
        let environment: Environment = row.environment.parse()?;
        let linked_target = match &row.linked_credential_id {
            Some(target_id) => {
                let target = self
                    .credential_row_by_id(target_id)?
                    .ok_or(CoreError::VaultCorrupted("reference target is missing"))?;
                Some(format!(
                    "{}/{}",
                    self.project_name_of(&target.project_id)?,
                    target.name
                ))
            }
            None => None,
        };
        let inputs = StatusInputs {
            created_at: clock::parse_rfc3339(&row.created_at)?,
            expires_at: parse_optional_ts(row.expires_at.as_deref())?,
            provider_expires_at: parse_optional_ts(row.provider_expires_at.as_deref())?,
            last_validated_at: parse_optional_ts(row.last_validated_at.as_deref())?,
            last_used_at: parse_optional_ts(row.last_used_at.as_deref())?,
            manually_disabled: row.manually_disabled,
            revoked: row.revoked,
            marked_invalid: row.marked_invalid,
            possibly_exposed: row.possibly_exposed,
            exposure_note: &row.exposure_note,
            shared_with_projects: &shared_with,
            sharing_is_reference,
            environment,
        };
        let status = status::evaluate(&inputs, &self.settings, clock::now());
        Ok(Credential {
            id: row.id.clone(),
            project_id: row.project_id.clone(),
            project_name,
            provider: row.provider.clone(),
            name: row.name.clone(),
            environment,
            credential_type: row.credential_type.clone(),
            masked_value: row.masked_value.clone(),
            is_reference: row.linked_credential_id.is_some(),
            linked_credential_id: row.linked_credential_id.clone(),
            linked_target,
            created_at: row.created_at.clone(),
            updated_at: row.updated_at.clone(),
            key_created_at: row.key_created_at.clone(),
            expires_at: row.expires_at.clone(),
            provider_expires_at: row.provider_expires_at.clone(),
            last_validated_at: row.last_validated_at.clone(),
            last_used_at: row.last_used_at.clone(),
            docs_url: row.docs_url.clone(),
            notes: row.notes.clone(),
            manually_disabled: row.manually_disabled,
            revoked: row.revoked,
            marked_invalid: row.marked_invalid,
            possibly_exposed: row.possibly_exposed,
            exposure_note: row.exposure_note.clone(),
            status,
        })
    }

    pub fn list_credentials(&self, project: Option<&str>) -> Result<Vec<Credential>> {
        let rows: Vec<CredentialRow> = match project {
            Some(ident) => {
                let project = self.project_row_by_ident(ident)?;
                let mut stmt = self.conn.prepare(&format!(
                    "SELECT {CREDENTIAL_COLUMNS} FROM credentials
                     WHERE project_id = ?1 ORDER BY name"
                ))?;
                let rows = stmt.query_map([&project.id], credential_row)?;
                rows.collect::<rusqlite::Result<_>>()?
            }
            None => {
                let mut stmt = self.conn.prepare(&format!(
                    "SELECT {CREDENTIAL_COLUMNS} FROM credentials ORDER BY project_id, name"
                ))?;
                let rows = stmt.query_map([], credential_row)?;
                rows.collect::<rusqlite::Result<_>>()?
            }
        };
        rows.iter().map(|row| self.credential_model(row)).collect()
    }

    pub fn get_credential(&self, selector: &str) -> Result<Credential> {
        let row = self.resolve_credential(selector)?;
        self.credential_model(&row)
    }

    /// Decrypt and return a credential value. Requires the master password
    /// again (reauthentication), even in an unlocked session.
    pub fn reveal_credential(
        &mut self,
        selector: &str,
        master_password: &SecretString,
    ) -> Result<SecretString> {
        self.verify_master_password(master_password)?;
        let requested = self.resolve_credential(selector)?;
        let root = match &requested.linked_credential_id {
            Some(target) => self
                .credential_row_by_id(target)?
                .ok_or(CoreError::VaultCorrupted("reference target is missing"))?,
            None => requested.clone_row(),
        };
        let ciphertext = root.ciphertext.as_deref().ok_or(CoreError::VaultCorrupted(
            "credential is missing its ciphertext",
        ))?;
        let project = self.project_row_by_ident(&root.project_id)?;
        let project_key = self.project_key_for_row(&project)?;
        let plaintext = crypto::decrypt(
            &project_key,
            &aad::credential_value(&self.vault_id, &root.project_id, &root.id),
            ciphertext,
            "credential value",
        )?;
        let value = String::from_utf8(plaintext.expose().to_vec())
            .map_err(|_| CoreError::VaultCorrupted("credential value is not valid UTF-8"))?;
        audit::record(
            &self.conn,
            "credential_revealed",
            Some(&requested.project_id),
            Some(&requested.id),
            "",
        )?;
        Ok(SecretString::new(value))
    }

    pub fn update_credential(
        &mut self,
        selector: &str,
        update: UpdateCredential,
    ) -> Result<Credential> {
        let row = self.resolve_credential(selector)?;
        let mut changed: Vec<&str> = Vec::new();
        if let Some(name) = &update.name {
            let name = name.trim();
            if name.is_empty() {
                return Err(CoreError::InvalidInput(
                    "credential name must not be empty".into(),
                ));
            }
            self.ensure_credential_name_free(&row.project_id, name, Some(&row.id))?;
            self.conn.execute(
                "UPDATE credentials SET name = ?1 WHERE id = ?2",
                params![name, row.id],
            )?;
            changed.push("name");
        }
        if let Some(provider) = &update.provider {
            self.conn.execute(
                "UPDATE credentials SET provider = ?1 WHERE id = ?2",
                params![crate::providers::normalize(provider), row.id],
            )?;
            changed.push("provider");
        }
        if let Some(environment) = update.environment {
            self.conn.execute(
                "UPDATE credentials SET environment = ?1 WHERE id = ?2",
                params![environment.as_str(), row.id],
            )?;
            changed.push("environment");
        }
        if let Some(value) = &update.key_created_at {
            self.conn.execute(
                "UPDATE credentials SET key_created_at = ?1 WHERE id = ?2",
                params![parse_optional_date(value.as_deref())?, row.id],
            )?;
            changed.push("key_created_at");
        }
        if let Some(value) = &update.expires_at {
            self.conn.execute(
                "UPDATE credentials SET expires_at = ?1 WHERE id = ?2",
                params![parse_optional_date(value.as_deref())?, row.id],
            )?;
            changed.push("expires_at");
        }
        if let Some(docs_url) = &update.docs_url {
            self.conn.execute(
                "UPDATE credentials SET docs_url = ?1 WHERE id = ?2",
                params![docs_url.trim(), row.id],
            )?;
            changed.push("docs_url");
        }
        if let Some(notes) = &update.notes {
            self.conn.execute(
                "UPDATE credentials SET notes = ?1 WHERE id = ?2",
                params![notes, row.id],
            )?;
            changed.push("notes");
        }
        if update.mark_used_now {
            self.conn.execute(
                "UPDATE credentials SET last_used_at = ?1 WHERE id = ?2",
                params![clock::now_rfc3339(), row.id],
            )?;
            changed.push("last_used_at");
        }
        if let Some(valid) = update.mark_validated {
            self.conn.execute(
                "UPDATE credentials SET last_validated_at = ?1, marked_invalid = ?2 WHERE id = ?3",
                params![clock::now_rfc3339(), !valid, row.id],
            )?;
            changed.push(if valid {
                "validated_ok"
            } else {
                "validated_failed"
            });
        }
        if let Some(disabled) = update.disabled {
            self.conn.execute(
                "UPDATE credentials SET manually_disabled = ?1 WHERE id = ?2",
                params![disabled, row.id],
            )?;
            changed.push("manually_disabled");
            // Record the exact disable/enable time so usage-after-disabled can
            // compare against it (updated_at is bumped by any edit).
            crate::activity::record(
                &self.conn,
                "credential_state",
                if disabled {
                    "credential_disabled"
                } else {
                    "credential_enabled"
                },
                Some(&row.id),
                Some(&row.project_id),
                if disabled {
                    "credential marked disabled"
                } else {
                    "credential re-enabled"
                },
                "",
            )?;
        }
        if let Some(revoked) = update.revoked {
            self.conn.execute(
                "UPDATE credentials SET revoked = ?1 WHERE id = ?2",
                params![revoked, row.id],
            )?;
            changed.push("revoked");
        }
        if let Some(exposed) = update.possibly_exposed {
            let note = update.exposure_note.clone().unwrap_or_default();
            self.conn.execute(
                "UPDATE credentials SET possibly_exposed = ?1, exposure_note = ?2 WHERE id = ?3",
                params![exposed, if exposed { note } else { String::new() }, row.id],
            )?;
            changed.push("possibly_exposed");
        } else if let Some(note) = &update.exposure_note {
            self.conn.execute(
                "UPDATE credentials SET exposure_note = ?1 WHERE id = ?2",
                params![note, row.id],
            )?;
            changed.push("exposure_note");
        }
        if !changed.is_empty() {
            self.conn.execute(
                "UPDATE credentials SET updated_at = ?1 WHERE id = ?2",
                params![clock::now_rfc3339(), row.id],
            )?;
            audit::record(
                &self.conn,
                "credential_updated",
                Some(&row.project_id),
                Some(&row.id),
                &format!("fields={}", changed.join(",")),
            )?;
        }
        self.get_credential(&row.id)
    }

    /// Replace the stored secret value (reauthentication required).
    pub fn replace_credential_value(
        &mut self,
        selector: &str,
        master_password: &SecretString,
        new_value: SecretString,
    ) -> Result<(Credential, Vec<ReuseWarning>)> {
        self.verify_master_password(master_password)?;
        let row = self.resolve_credential(selector)?;
        if row.linked_credential_id.is_some() {
            return Err(CoreError::InvalidInput(
                "this record is a reference; replace the value on the credential it points to"
                    .into(),
            ));
        }
        if new_value.expose().trim().is_empty() {
            return Err(CoreError::InvalidInput(
                "credential value must not be empty".into(),
            ));
        }
        let project = self.project_row_by_ident(&row.project_id)?;
        let project_key = self.project_key_for_row(&project)?;
        let fp = reuse::fingerprint(&self.fingerprint_key, &new_value)?;
        let environment: Environment = row.environment.parse()?;
        let warnings = reuse::classify(
            &row.project_id,
            environment,
            self.find_reuse_matches(&fp, Some(&row.id))?,
        );
        let ciphertext = crypto::encrypt(
            &project_key,
            &aad::credential_value(&self.vault_id, &row.project_id, &row.id),
            new_value.expose().trim().as_bytes(),
        )?;
        let masked = mask_value(new_value.expose());
        let now = clock::now_rfc3339();
        // Retain the outgoing value as an encrypted version so destination
        // synchronization can roll back (see docs/decisions/0012).
        let retained = self.retain_credential_version(&row, &project_key, "value replaced")?;
        // The new value's provider-reported expiration is unknown until the
        // next validation; carrying the OLD value's expiry over would report
        // a false "expired".
        self.conn.execute(
            "UPDATE credentials SET ciphertext = ?1, fingerprint = ?2, masked_value = ?3,
             updated_at = ?4, value_version = ?5, provider_expires_at = NULL WHERE id = ?6",
            params![ciphertext, fp, masked, now, retained + 1, row.id],
        )?;
        // References carry a copy of the source's fingerprint and mask so they
        // can display and participate in reuse detection without decrypting;
        // keep them consistent with the new value.
        self.conn.execute(
            "UPDATE credentials SET fingerprint = ?1, masked_value = ?2, updated_at = ?3
             WHERE linked_credential_id = ?4",
            params![fp, masked, now, row.id],
        )?;
        audit::record(
            &self.conn,
            "credential_value_replaced",
            Some(&row.project_id),
            Some(&row.id),
            "",
        )?;
        Ok((self.get_credential(&row.id)?, warnings))
    }

    /// Delete a credential. Refuses while other records reference it or a
    /// rotation is in flight (deleting would cascade away the tracking of a
    /// still-live provider-side key).
    pub fn delete_credential(&mut self, selector: &str) -> Result<Credential> {
        let row = self.resolve_credential(selector)?;
        let active_rotations: i64 = self.conn.query_row(
            "SELECT count(*) FROM rotations WHERE credential_id = ?1
             AND state NOT IN ('completed', 'rolled_back', 'failed', 'planned')",
            [&row.id],
            |r| r.get(0),
        )?;
        if active_rotations > 0 {
            return Err(CoreError::InvalidInput(
                "a rotation for this credential is in flight; complete, roll back, or \
                 cancel it before deleting"
                    .into(),
            ));
        }
        let reference_count: i64 = self.conn.query_row(
            "SELECT count(*) FROM credentials WHERE linked_credential_id = ?1",
            [&row.id],
            |r| r.get(0),
        )?;
        if reference_count > 0 {
            return Err(CoreError::HasLinkedReferences(reference_count as usize));
        }
        let model = self.credential_model(&row)?;
        self.conn
            .execute("DELETE FROM credentials WHERE id = ?1", [&row.id])?;
        audit::record(
            &self.conn,
            "credential_deleted",
            Some(&row.project_id),
            Some(&row.id),
            &format!("name={}", row.name),
        )?;
        Ok(model)
    }

    pub fn recent_audit_events(&self, limit: u32) -> Result<Vec<audit::AuditEvent>> {
        audit::list(&self.conn, limit)
    }

    // ------------------------------------------------------------------
    // Milestone 2: repository scanning, monitoring, and doc watching
    // ------------------------------------------------------------------

    /// Run the detection engine over scan units, match each finding against
    /// the vault (by keyed fingerprint), and drop suppressed findings.
    fn scan_units(&self, units: Vec<crate::gitrepo::ScanUnit>) -> Result<Vec<scanner::Finding>> {
        let suppressed = self.suppression_keys()?;
        let mut out = Vec::new();
        for unit in units {
            let options = scanner::ScanOptions {
                entropy: !scanner::skip_entropy_for(&unit.label),
            };
            for mut finding in scanner::scan_text(&unit.content, &unit.label, &options) {
                if suppressed.contains(&finding.suppression_key) {
                    continue;
                }
                finding.vault_match = self.match_finding(&finding)?;
                out.push(finding);
            }
        }
        Ok(out)
    }

    fn match_finding(&self, finding: &scanner::Finding) -> Result<Option<scanner::VaultMatch>> {
        let fp = reuse::fingerprint(&self.fingerprint_key, &finding.secret)?;
        let matches = self.find_reuse_matches(&fp, None)?;
        let Some(primary) = matches.first() else {
            return Ok(None);
        };
        // The value-bearing record (skip references) is the identity.
        let root = matches.iter().find(|m| !m.is_reference).unwrap_or(primary);
        let mut other_projects: Vec<String> = matches
            .iter()
            .filter(|m| m.project_id != root.project_id)
            .map(|m| m.project_name.clone())
            .collect();
        other_projects.sort();
        other_projects.dedup();
        Ok(Some(scanner::VaultMatch {
            credential_id: root.credential_id.clone(),
            credential_name: root.credential_name.clone(),
            project_id: root.project_id.clone(),
            project_name: root.project_name.clone(),
            other_projects,
        }))
    }

    /// Scan a working-tree directory or single file.
    pub fn scan_working_tree(&self, path: &std::path::Path) -> Result<Vec<scanner::Finding>> {
        let units = crate::gitrepo::working_tree_units(path)?;
        self.scan_units(units)
    }

    /// Scan the staged changes of a Git repository.
    pub fn scan_staged(&self, repo: &std::path::Path) -> Result<Vec<scanner::Finding>> {
        let root = crate::gitrepo::repo_root(repo)?;
        let units = crate::gitrepo::staged_units(&root)?;
        self.scan_units(units)
    }

    /// Scan Git history (last `n` commits, or all when `None`).
    pub fn scan_history(
        &self,
        repo: &std::path::Path,
        n: Option<usize>,
    ) -> Result<Vec<scanner::Finding>> {
        let root = crate::gitrepo::repo_root(repo)?;
        let units = crate::gitrepo::history_added_units(&root, n)?;
        self.scan_units(units)
    }

    /// Mark every credential matched by a scan finding as possibly exposed,
    /// recording where. Returns the affected credential ids. Never touches
    /// files or provider state.
    pub fn mark_findings_exposed(&self, findings: &[scanner::Finding]) -> Result<Vec<String>> {
        let mut affected = Vec::new();
        for finding in findings {
            if let Some(m) = &finding.vault_match {
                if affected.contains(&m.credential_id) {
                    continue;
                }
                let note = format!(
                    "matched during a repository scan in {} (line {})",
                    finding.file, finding.line
                );
                self.conn.execute(
                    "UPDATE credentials SET possibly_exposed = 1, exposure_note = ?1,
                     updated_at = ?2 WHERE id = ?3",
                    params![note, clock::now_rfc3339(), m.credential_id],
                )?;
                audit::record(
                    &self.conn,
                    "credential_marked_exposed",
                    Some(&m.project_id),
                    Some(&m.credential_id),
                    "source=repository_scan",
                )?;
                affected.push(m.credential_id.clone());
            }
        }
        Ok(affected)
    }

    fn suppression_keys(&self) -> Result<std::collections::HashSet<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT suppression_key FROM scan_suppressions")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut set = std::collections::HashSet::new();
        for r in rows {
            set.insert(r?);
        }
        Ok(set)
    }

    /// Record a local suppression for a finding (requires a reason).
    pub fn add_suppression(
        &self,
        suppression_key: &str,
        rule: &str,
        path: &str,
        reason: &str,
    ) -> Result<()> {
        if reason.trim().is_empty() {
            return Err(CoreError::InvalidInput(
                "a suppression reason is required".into(),
            ));
        }
        self.conn.execute(
            "INSERT INTO scan_suppressions (id, suppression_key, rule, path, reason, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(suppression_key) DO UPDATE SET reason = excluded.reason",
            params![
                Uuid::new_v4().to_string(),
                suppression_key,
                rule,
                path,
                reason.trim(),
                clock::now_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Remove a suppression so its finding is reported again by future
    /// scans (including the pre-commit hook).
    pub fn remove_suppression(&self, suppression_key: &str) -> Result<()> {
        let removed = self.conn.execute(
            "DELETE FROM scan_suppressions WHERE suppression_key = ?1",
            [suppression_key],
        )?;
        if removed == 0 {
            return Err(CoreError::NotFound {
                kind: "suppression",
                ident: suppression_key.to_string(),
            });
        }
        audit::record(
            &self.conn,
            "suppression_removed",
            None,
            None,
            &format!("key={suppression_key}"),
        )?;
        Ok(())
    }

    pub fn list_suppressions(&self) -> Result<Vec<Suppression>> {
        let mut stmt = self.conn.prepare(
            "SELECT suppression_key, rule, path, reason, created_at
             FROM scan_suppressions ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Suppression {
                suppression_key: r.get(0)?,
                rule: r.get(1)?,
                path: r.get(2)?,
                reason: r.get(3)?,
                created_at: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Run monitoring checks: generate/refresh alerts from credential status
    /// and reuse, and auto-resolve conditions that no longer hold.
    pub fn run_monitor(&self) -> Result<MonitorSummary> {
        let now = clock::now_rfc3339();
        let cost_source = self.budget_cost_source()?;
        let credentials = self.list_credentials(None)?;
        let mut active_keys: Vec<String> = Vec::new();
        let mut created = 0usize;

        for cred in &credentials {
            let mut new_alerts = crate::monitor::credential_alerts(cred, &now);
            // Reuse alerts are computed from the STORED fingerprint, not by
            // decrypting the value. This works for password-locked projects
            // too (so their still-valid reuse alerts are not spuriously
            // auto-resolved) and avoids decrypting every credential on every
            // scheduled run.
            if !cred.is_reference {
                if let Some(row) = self.credential_row_by_id(&cred.id)? {
                    let matches = self.find_reuse_matches(&row.fingerprint, Some(&cred.id))?;
                    let warnings = reuse::classify(&cred.project_id, cred.environment, matches);
                    new_alerts.extend(crate::monitor::reuse_alerts(cred, &warnings, &now));
                }
            }
            // Activity-based rules (usage vs credential state): cost spikes
            // and usage-after-disabled. These use stored usage snapshots.
            let label = format!("{}/{}", cred.project_name, cred.name);
            if let Some(a) = crate::activity::cost_spike_alert(&self.conn, &cred.id, &label)? {
                new_alerts.push(a);
            }
            let disabled_since = crate::activity::last_disabled_at(&self.conn, &cred.id)?;
            if let Some(a) = crate::activity::usage_after_disabled_alert(
                &self.conn,
                &cred.id,
                &label,
                cred.manually_disabled,
                disabled_since.as_deref(),
            )? {
                new_alerts.push(a);
            }
            // Credential-level budget.
            let creport =
                crate::budget::credential_report(&self.conn, &cred.id, &label, cost_source)?;
            if let Some(a) = crate::budget::over_budget_alert(&creport, Some(&cred.id)) {
                new_alerts.push(a);
            }

            for alert in new_alerts {
                active_keys.push(alert.dedup_key.clone());
                if alerts::upsert(&self.conn, &alert)? {
                    created += 1;
                }
            }
        }

        // Project-level budgets.
        for project in self.list_projects(false)? {
            let report = crate::budget::project_report(&self.conn, &project.id, cost_source)?;
            if let Some(alert) = crate::budget::over_budget_alert(&report, None) {
                active_keys.push(alert.dedup_key.clone());
                if alerts::upsert(&self.conn, &alert)? {
                    created += 1;
                }
            }
        }

        // Provider connections: stale synced data, unmatched provider-side
        // API keys with usage, and unmapped provider projects with cost.
        for alert in self.provider_connection_alerts(&now)? {
            active_keys.push(alert.dedup_key.clone());
            if alerts::upsert(&self.conn, &alert)? {
                created += 1;
            }
        }

        // Rotation schedules that are due (preflight-checked) and rotations
        // stuck mid-flight. Scheduling never executes anything by itself —
        // it raises an alert (and, in the desktop app, a notification) and
        // pauses on preflight failure. No destructive action is queued.
        for alert in self.rotation_monitor_alerts(&now)? {
            active_keys.push(alert.dedup_key.clone());
            if alerts::upsert(&self.conn, &alert)? {
                created += 1;
            }
        }

        // Incremental scan of registered repositories: only NEW commits
        // since the last monitor run are examined (one `git rev-parse` per
        // repo when nothing changed). Local-only, like all scanning.
        // Findings (vault-matched or not) raise an alert; silent coverage
        // gaps are not acceptable in a security tool.
        let _ = self.prune_observability_state();
        let mut repos_scanned = 0usize;
        let mut repo_findings = 0usize;
        if let Ok(reports) = self.scan_repos_incremental() {
            for report in &reports {
                repos_scanned += 1;
                repo_findings += report.findings;
                if report.findings > 0 {
                    let alert = alerts::NewAlert {
                        kind: alerts::AlertKind::PossibleExposure,
                        severity: alerts::Severity::High,
                        dedup_key: format!(
                            "repo_scan_findings:{}:{}",
                            report.repo_path, report.head_commit
                        ),
                        title: format!(
                            "likely secret(s) in new commits: {}",
                            report.repo_path
                        ),
                        detail: format!(
                            "{} finding(s) in commits up to {} (background incremental                              scan). Run `api-tracker scan {}` for details; detection is                              best-effort, never perfect.",
                            report.findings, report.head_commit, report.repo_path
                        ),
                        evidence: format!(
                            "repo={} head={} findings={}",
                            report.repo_path, report.head_commit, report.findings
                        ),
                        confidence: crate::providers::Confidence::Medium,
                        recommended_action:
                            "inspect the findings; rotate anything real and scrub history"
                                .into(),
                        project_id: None,
                        credential_id: None,
                        observed_at: now.clone(),
                    };
                    active_keys.push(alert.dedup_key.clone());
                    if alerts::upsert(&self.conn, &alert)? {
                        created += 1;
                    }
                }
            }
        }

        // Expanded explainable observability rules (request spikes, dormant
        // activation, auth failures, first-seen provider entities, unusual
        // model/time, destination drift, rotations needing attention,
        // expired grants).
        {
            let labels: HashMap<String, String> = credentials
                .iter()
                .map(|c| (c.id.clone(), format!("{}/{}", c.project_name, c.name)))
                .collect();
            let label_of = |id: &str| labels.get(id).cloned().unwrap_or_else(|| id.to_string());
            for alert in crate::observe::alerts(&self.conn, clock::now(), &label_of)? {
                active_keys.push(alert.dedup_key.clone());
                if alerts::upsert(&self.conn, &alert)? {
                    created += 1;
                }
            }
        }

        let mut managed = crate::monitor::managed_credential_kinds();
        managed.extend(crate::activity::managed_kinds());
        managed.extend([
            alerts::AlertKind::ProviderDataStale,
            alerts::AlertKind::UnmatchedProviderKey,
            alerts::AlertKind::UnmappedProviderProject,
            alerts::AlertKind::RotationDue,
            alerts::AlertKind::RotationStuck,
        ]);
        managed.extend(crate::observe::managed_kinds());
        let resolved = alerts::auto_resolve_stale(&self.conn, &managed, &active_keys)?;
        Ok(MonitorSummary {
            repos_scanned,
            repo_findings,
            checked: credentials.len(),
            alerts_created: created,
            alerts_resolved: resolved,
            open_alerts: alerts::open_count(&self.conn)? as usize,
        })
    }

    /// One full monitor cycle — the shared orchestration both frontends use:
    /// the local rules pass (`run_monitor`), then, when transports are
    /// provided, the best-effort network phases (due documentation checks
    /// and webhook notification delivery). Records when the cycle ran and
    /// whether it succeeded so both frontends can display it
    /// (`monitor_status`). Network-phase failures never fail the cycle.
    pub fn run_monitor_cycle(
        &self,
        network: Option<(
            &dyn crate::docwatch::DocFetcher,
            &dyn crate::http::HttpClient,
        )>,
    ) -> Result<MonitorCycleReport> {
        let started = clock::now_rfc3339();
        meta_set(&self.conn, "monitor_last_run_at", &started)?;
        let summary = match self.run_monitor() {
            Ok(s) => s,
            Err(e) => {
                let _ = meta_set(&self.conn, "monitor_last_failure_at", &started);
                let _ = meta_set(&self.conn, "monitor_last_error", &e.to_string());
                return Err(e);
            }
        };
        let mut doc_checks = 0usize;
        let mut webhooks_delivered = 0usize;
        if let Some((fetcher, http)) = network {
            if let Ok(results) = self.check_due_doc_watches(fetcher) {
                doc_checks = results.len();
            }
            webhooks_delivered = self.deliver_notifications(http).unwrap_or(0);
        }
        let finished = clock::now_rfc3339();
        meta_set(&self.conn, "monitor_last_success_at", &finished)?;
        meta_set(&self.conn, "monitor_last_error", "")?;
        meta_set(
            &self.conn,
            "monitor_last_detail",
            &format!(
                "checked {} credential(s); {} new alert(s), {} resolved; {} doc check(s); \
                 {} webhook delivery(ies){}",
                summary.checked,
                summary.alerts_created,
                summary.alerts_resolved,
                doc_checks,
                webhooks_delivered,
                if network.is_none() {
                    " (offline: network phases skipped)"
                } else {
                    ""
                }
            ),
        )?;
        Ok(MonitorCycleReport {
            summary,
            doc_checks,
            webhooks_delivered,
            offline: network.is_none(),
        })
    }

    /// When monitoring last ran and how it went (no run is performed).
    /// All fields are empty/None before the first recorded cycle.
    pub fn monitor_status(&self) -> Result<MonitorStatus> {
        Ok(MonitorStatus {
            last_run_at: meta_get(&self.conn, "monitor_last_run_at")?,
            last_success_at: meta_get(&self.conn, "monitor_last_success_at")?,
            last_failure_at: meta_get(&self.conn, "monitor_last_failure_at")?,
            last_error: meta_get(&self.conn, "monitor_last_error")?.unwrap_or_default(),
            last_detail: meta_get(&self.conn, "monitor_last_detail")?.unwrap_or_default(),
        })
    }

    /// Provider-connection monitoring rules: stale synced data, unmatched
    /// provider-side API keys that carry usage, and unmapped provider
    /// projects with month-to-date reported cost above a conservative
    /// threshold ($1.00, documented). Explainable and evidence-backed only.
    fn provider_connection_alerts(&self, now: &str) -> Result<Vec<alerts::NewAlert>> {
        use crate::providers::Confidence;
        const UNMAPPED_PROJECT_COST_THRESHOLD_MICROS: i64 = 1_000_000;
        let mut out = Vec::new();
        for status in self.provider_connections()? {
            if !status.connected {
                continue;
            }
            let provider = status.provider.clone();
            if status.stale {
                out.push(alerts::NewAlert {
                    kind: alerts::AlertKind::ProviderDataStale,
                    severity: alerts::Severity::Low,
                    dedup_key: format!("provider_data_stale:{provider}"),
                    title: format!("{provider} usage data is stale"),
                    detail: format!(
                        "the last successful synchronization was {}; the staleness threshold \
                         is {} day(s)",
                        status.last_success_at.as_deref().unwrap_or("never"),
                        self.settings.provider_stale_days
                    ),
                    evidence: format!(
                        "last success: {}; last failure: {}",
                        status.last_success_at.as_deref().unwrap_or("never"),
                        status.last_failure_at.as_deref().unwrap_or("never")
                    ),
                    confidence: Confidence::High,
                    recommended_action: format!("run `provider sync {provider}`"),
                    project_id: None,
                    credential_id: None,
                    observed_at: now.to_string(),
                });
            }
            for key in self.provider_keys_overview(&provider)? {
                if key.linked_credential_id.is_none() && key.usage_rows > 0 {
                    out.push(alerts::NewAlert {
                        kind: alerts::AlertKind::UnmatchedProviderKey,
                        severity: alerts::Severity::Low,
                        dedup_key: format!("unmatched_provider_key:{provider}:{}", key.api_key_id),
                        title: format!(
                            "{provider} API key {} has usage but no local credential link",
                            key.api_key_id
                        ),
                        detail: format!(
                            "{} synced usage/cost row(s) are attributed to this provider-side \
                             key; they are shown at provider-key level, not against any local \
                             credential",
                            key.usage_rows
                        ),
                        evidence: format!(
                            "provider key name: '{}'; redacted value: '{}'",
                            key.name, key.redacted_value
                        ),
                        confidence: Confidence::High,
                        recommended_action: format!(
                            "link it if it is yours: `provider link {provider} {} --credential \
                             <project/name>`",
                            key.api_key_id
                        ),
                        project_id: None,
                        credential_id: None,
                        observed_at: now.to_string(),
                    });
                }
            }
            for proj in self.provider_projects_overview(&provider)? {
                if !proj.has_linked_usage
                    && proj.reported_cost_micros_month >= UNMAPPED_PROJECT_COST_THRESHOLD_MICROS
                {
                    out.push(alerts::NewAlert {
                        kind: alerts::AlertKind::UnmappedProviderProject,
                        severity: alerts::Severity::Medium,
                        dedup_key: format!(
                            "unmapped_provider_project:{provider}:{}",
                            proj.provider_project_id
                        ),
                        title: format!(
                            "{provider} project '{}' has cost but no local mapping",
                            if proj.name.is_empty() {
                                proj.provider_project_id.clone()
                            } else {
                                proj.name.clone()
                            }
                        ),
                        detail: format!(
                            "{} provider-reported this month; none of its usage is linked to a \
                             local credential",
                            usage::format_micros(proj.reported_cost_micros_month)
                        ),
                        evidence: format!(
                            "provider project id: {}; threshold: {}",
                            proj.provider_project_id,
                            usage::format_micros(UNMAPPED_PROJECT_COST_THRESHOLD_MICROS)
                        ),
                        confidence: Confidence::High,
                        recommended_action:
                            "review the provider project and link its API keys to local \
                             credentials where they are yours"
                                .into(),
                        project_id: None,
                        credential_id: None,
                        observed_at: now.to_string(),
                    });
                }
            }
        }
        Ok(out)
    }

    // --- Documentation watches ---

    pub fn watch_docs(&self, provider: &str, url: &str) -> Result<crate::docwatch::DocWatch> {
        crate::docwatch::add_watch(&self.conn, provider, url)
    }

    pub fn unwatch_docs(&self, url: &str) -> Result<bool> {
        crate::docwatch::remove_watch(&self.conn, url)
    }

    pub fn list_doc_watches(&self) -> Result<Vec<crate::docwatch::DocWatch>> {
        crate::docwatch::list(&self.conn)
    }

    pub fn list_doc_watches_for(&self, provider: &str) -> Result<Vec<crate::docwatch::DocWatch>> {
        crate::docwatch::list_for_provider(&self.conn, provider)
    }

    /// Check one watched URL, and raise a `DocumentationChanged` alert if it
    /// changed. Returns the check result and the refreshed watch.
    pub fn check_doc_watch(
        &self,
        fetcher: &dyn crate::docwatch::DocFetcher,
        url: &str,
    ) -> Result<(crate::docwatch::CheckResult, crate::docwatch::DocWatch)> {
        let (result, watch) = crate::docwatch::check_watch(&self.conn, fetcher, url)?;
        let outcome = match result {
            crate::docwatch::CheckResult::FirstCapture => "first_capture",
            crate::docwatch::CheckResult::Unchanged => "unchanged",
            crate::docwatch::CheckResult::Changed => "changed",
            crate::docwatch::CheckResult::Failed => "failed",
        };
        crate::docwatch::record_history(
            &self.conn,
            url,
            &watch.provider,
            outcome,
            &watch.last_status,
        )?;
        if result == crate::docwatch::CheckResult::Changed {
            let now = clock::now_rfc3339();
            alerts::upsert(
                &self.conn,
                &alerts::NewAlert {
                    kind: alerts::AlertKind::DocumentationChanged,
                    severity: alerts::Severity::Info,
                    dedup_key: format!("docchange:{url}"),
                    title: format!("{} documentation changed", watch.provider),
                    detail: format!(
                        "the tracked content at {url} changed. A page change does not necessarily mean a breaking API change."
                    ),
                    evidence: format!("content hash differs; last changed {}", now),
                    confidence: crate::providers::Confidence::Medium,
                    recommended_action: "review the official page linked in this alert".into(),
                    project_id: None,
                    credential_id: None,
                    observed_at: now,
                },
            )?;
        }
        Ok((result, watch))
    }

    // ------------------------------------------------------------------
    // Milestone 3: provider connectors, usage, cost, permissions, activity
    // ------------------------------------------------------------------

    /// Decrypt a credential's value in-process (resolves references, respects
    /// project locks). No reauth: the vault is already unlocked and the value
    /// is used directly (a provider request), not revealed to the user.
    fn decrypt_value(&self, selector: &str) -> Result<SecretString> {
        let requested = self.resolve_credential(selector)?;
        let root = match &requested.linked_credential_id {
            Some(target) => self
                .credential_row_by_id(target)?
                .ok_or(CoreError::VaultCorrupted("reference target is missing"))?,
            None => requested,
        };
        let ciphertext = root.ciphertext.as_deref().ok_or(CoreError::VaultCorrupted(
            "credential is missing its ciphertext",
        ))?;
        let project = self.project_row_by_ident(&root.project_id)?;
        let project_key = self.project_key_for_row(&project)?;
        let plaintext = crypto::decrypt(
            &project_key,
            &aad::credential_value(&self.vault_id, &root.project_id, &root.id),
            ciphertext,
            "credential value",
        )?;
        let value = String::from_utf8(plaintext.expose().to_vec())
            .map_err(|_| CoreError::VaultCorrupted("credential value is not valid UTF-8"))?;
        Ok(SecretString::new(value))
    }

    fn connector_for(&self, provider: &str) -> Result<Box<dyn crate::connectors::Connector>> {
        crate::connectors::for_provider(provider).ok_or_else(|| CoreError::Unsupported {
            provider: provider.to_string(),
            capability: "connector",
            hint: "no connector is implemented for this provider".into(),
        })
    }

    /// Validate a credential against its provider. Records the outcome
    /// (last validated / marked invalid) and an audit event.
    pub fn validate_credential(
        &mut self,
        selector: &str,
        http: &dyn crate::http::HttpClient,
    ) -> Result<crate::connectors::ValidationResult> {
        let cred = self.get_credential(selector)?;
        let connector = self.connector_for(&cred.provider)?;
        let value = self.decrypt_value(selector)?;
        let result = connector.validate(http, &value)?;
        self.update_credential(
            &cred.id,
            UpdateCredential {
                mark_validated: Some(result.valid),
                ..Default::default()
            },
        )?;
        if let Some(expiry) = &result.provider_expires_at {
            self.conn.execute(
                "UPDATE credentials SET provider_expires_at = ?1 WHERE id = ?2",
                params![expiry, cred.id],
            )?;
        }
        audit::record(
            &self.conn,
            "credential_validated",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!("valid={}", result.valid),
        )?;
        Ok(result)
    }

    /// Fetch provider-side metadata for a credential (non-secret).
    pub fn fetch_metadata(
        &self,
        selector: &str,
        http: &dyn crate::http::HttpClient,
    ) -> Result<crate::connectors::FetchedMetadata> {
        let cred = self.get_credential(selector)?;
        let connector = self.connector_for(&cred.provider)?;
        let value = self.decrypt_value(selector)?;
        connector.fetch_metadata(http, &value)
    }

    /// Synchronize a credential's permissions (read-only) and store them.
    pub fn sync_permissions(
        &self,
        selector: &str,
        http: &dyn crate::http::HttpClient,
    ) -> Result<crate::permissions::StoredPermissions> {
        let cred = self.get_credential(selector)?;
        let connector = self.connector_for(&cred.provider)?;
        let value = self.decrypt_value(selector)?;
        let fetched = connector.fetch_permissions(http, &value)?;
        let normalized = crate::permissions::normalize_for(&cred.provider, &fetched.raw_scopes);
        audit::record(
            &self.conn,
            "permission_snapshot",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!(
                "scopes={} source={}",
                fetched.raw_scopes.len(),
                fetched.source
            ),
        )?;
        crate::permissions::store(
            &self.conn,
            &cred.id,
            &fetched.raw_scopes,
            &normalized,
            &fetched.source,
            &fetched.precision,
            &fetched.confidence,
        )?;
        audit::record(
            &self.conn,
            "permissions_synced",
            Some(&cred.project_id),
            Some(&cred.id),
            "",
        )?;
        crate::permissions::load(&self.conn, &cred.id)?.ok_or(CoreError::VaultCorrupted(
            "permissions vanished after store",
        ))
    }

    pub fn get_permissions(
        &self,
        selector: &str,
    ) -> Result<Option<crate::permissions::StoredPermissions>> {
        let cred = self.get_credential(selector)?;
        crate::permissions::load(&self.conn, &cred.id)
    }

    /// Legacy connection path: reference a vault credential as the provider's
    /// admin key for usage sync. The dedicated administrative connection
    /// ([`Self::provider_admin_connect`]) is preferred; this remains for
    /// existing vaults and providers without a dedicated flow.
    pub fn provider_connect(&self, provider: &str, admin_selector: &str) -> Result<()> {
        let provider = crate::providers::normalize(provider);
        let cred = self.get_credential(admin_selector)?;
        self.conn.execute(
            "INSERT INTO provider_connections (provider, admin_credential_id, last_status)
             VALUES (?1, ?2, 'connected')
             ON CONFLICT(provider) DO UPDATE SET admin_credential_id = excluded.admin_credential_id",
            params![provider, cred.id],
        )?;
        audit::record(
            &self.conn,
            "provider_connected",
            None,
            Some(&cred.id),
            &format!("provider={provider}"),
        )?;
        Ok(())
    }

    /// Store a dedicated administrative provider connection. The admin key is
    /// encrypted under the vault key (never a project key, never plaintext),
    /// is validated against the provider before being stored, and can only be
    /// replaced or removed — never displayed. Only OpenAI has a dedicated
    /// admin flow today.
    ///
    /// Callers (CLI/desktop) must reauthenticate the master password before
    /// invoking this for a replacement, and must never log the key.
    pub fn provider_admin_connect(
        &self,
        provider: &str,
        admin_key: &SecretString,
        org_label: Option<&str>,
        http: Option<&dyn crate::http::HttpClient>,
    ) -> Result<String> {
        let provider = crate::providers::normalize(provider);
        if admin_key.expose().trim().is_empty() {
            return Err(CoreError::InvalidInput(
                "the administrative key must not be empty".into(),
            ));
        }
        if provider != crate::openai::PROVIDER && provider != crate::anthropic::PROVIDER {
            return Err(CoreError::Unsupported {
                provider,
                capability: "admin_connection",
                hint: "a dedicated administrative connection is implemented for OpenAI and \
                       Anthropic; use `provider connect <provider> --credential <vault \
                       credential>` otherwise"
                    .into(),
            });
        }
        // Validate before storing so a mistyped key is never persisted.
        // `http: None` (explicit user opt-out, e.g. offline setup) stores the
        // key unvalidated and says so.
        let detail = match http {
            Some(http) if provider == crate::anthropic::PROVIDER => {
                crate::anthropic::validate_admin_key(http, admin_key)?
            }
            Some(http) => crate::openai::validate_admin_key(http, admin_key)?,
            None => "stored without validation (verification was skipped)".to_string(),
        };
        let ciphertext = crypto::encrypt(
            &self.vault_key,
            &aad::provider_admin(&self.vault_id, &provider),
            admin_key.expose().as_bytes(),
        )?;
        let masked = mask_value(admin_key.expose());
        let now = clock::now_rfc3339();
        self.conn.execute(
            "INSERT INTO provider_connections
                 (provider, admin_key_ciphertext, admin_key_masked, org_label, connected_at,
                  last_status, detail, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5, 'connected', ?6, '')
             ON CONFLICT(provider) DO UPDATE SET
                 admin_key_ciphertext = excluded.admin_key_ciphertext,
                 admin_key_masked = excluded.admin_key_masked,
                 org_label = excluded.org_label,
                 connected_at = excluded.connected_at,
                 last_status = 'connected',
                 detail = excluded.detail,
                 last_error = ''",
            params![provider, ciphertext, masked, org_label, now, detail],
        )?;
        audit::record(
            &self.conn,
            "provider_admin_connected",
            None,
            None,
            &format!("provider={provider} org={}", org_label.unwrap_or("-")),
        )?;
        Ok(detail)
    }

    /// Remove a provider connection entirely: the encrypted admin key (or the
    /// legacy credential reference) and the connection state are deleted.
    /// Previously synchronized usage snapshots are kept for offline viewing.
    /// Callers must confirm and reauthenticate first.
    pub fn provider_admin_disconnect(&self, provider: &str) -> Result<bool> {
        let provider = crate::providers::normalize(provider);
        let n = self.conn.execute(
            "DELETE FROM provider_connections WHERE provider = ?1",
            [&provider],
        )?;
        if n > 0 {
            audit::record(
                &self.conn,
                "provider_admin_disconnected",
                None,
                None,
                &format!("provider={provider}"),
            )?;
        }
        Ok(n > 0)
    }

    /// Decrypt the administrative secret for a provider: the dedicated
    /// admin-connection key if present, else the legacy referenced credential.
    fn provider_admin_secret(&self, provider: &str) -> Result<SecretString> {
        let row: Option<(Option<Vec<u8>>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT admin_key_ciphertext, admin_credential_id
                 FROM provider_connections WHERE provider = ?1",
                [provider],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            Some((Some(ciphertext), _)) => {
                let plaintext = crypto::decrypt(
                    &self.vault_key,
                    &aad::provider_admin(&self.vault_id, provider),
                    &ciphertext,
                    "provider admin key",
                )?;
                let value = String::from_utf8(plaintext.expose().to_vec())
                    .map_err(|_| CoreError::VaultCorrupted("admin key is not valid UTF-8"))?;
                Ok(SecretString::new(value))
            }
            Some((None, Some(credential_id))) => self.decrypt_value(&credential_id),
            _ => Err(CoreError::InvalidInput(format!(
                "no administrative connection for {provider}; run `provider connect {provider}`"
            ))),
        }
    }

    /// Live connection test against the provider using the stored admin key.
    /// Callers must reauthenticate first. Updates the stored status.
    pub fn provider_admin_test(
        &self,
        provider: &str,
        http: &dyn crate::http::HttpClient,
    ) -> Result<String> {
        let provider = crate::providers::normalize(provider);
        let admin = self.provider_admin_secret(&provider)?;
        if provider != crate::openai::PROVIDER && provider != crate::anthropic::PROVIDER {
            return Err(CoreError::Unsupported {
                provider,
                capability: "admin_connection_test",
                hint: "connection tests are implemented for the providers with dedicated \
                       admin connections (OpenAI and Anthropic)"
                    .into(),
            });
        }
        let now = clock::now_rfc3339();
        let validation = if provider == crate::anthropic::PROVIDER {
            crate::anthropic::validate_admin_key(http, &admin)
        } else {
            crate::openai::validate_admin_key(http, &admin)
        };
        match validation {
            Ok(detail) => {
                self.conn.execute(
                    "UPDATE provider_connections SET last_status = 'connected', detail = ?1,
                     last_error = '' WHERE provider = ?2",
                    params![detail, provider],
                )?;
                Ok(detail)
            }
            Err(e) => {
                self.conn.execute(
                    "UPDATE provider_connections SET last_status = 'invalid',
                     last_failure_at = ?1, last_error = ?2 WHERE provider = ?3",
                    params![now, e.to_string(), provider],
                )?;
                Err(e)
            }
        }
    }

    /// Connection status for a provider (no secrets; the key is masked).
    pub fn provider_connection_status(&self, provider: &str) -> Result<ProviderConnection> {
        let provider = crate::providers::normalize(provider);
        let row = self
            .conn
            .query_row(
                "SELECT admin_credential_id, last_synced_at, last_status, detail,
                        admin_key_ciphertext IS NOT NULL, admin_key_masked, org_label,
                        connected_at, last_success_at, last_failure_at, last_error
                 FROM provider_connections WHERE provider = ?1",
                [&provider],
                |r| {
                    let admin_credential_id: Option<String> = r.get(0)?;
                    let has_admin_key: bool = r.get(4)?;
                    Ok(ProviderConnection {
                        provider: provider.clone(),
                        connected: has_admin_key || admin_credential_id.is_some(),
                        admin_credential_id,
                        last_synced_at: r.get(1)?,
                        last_status: r.get(2)?,
                        detail: r.get(3)?,
                        admin_key_masked: r.get(5)?,
                        org_label: r.get(6)?,
                        connected_at: r.get(7)?,
                        last_success_at: r.get(8)?,
                        last_failure_at: r.get(9)?,
                        last_error: r.get(10)?,
                        stale: false,
                    })
                },
            )
            .optional()?;
        let mut status = row.unwrap_or(ProviderConnection {
            provider,
            connected: false,
            admin_credential_id: None,
            last_synced_at: None,
            last_status: "never".into(),
            detail: String::new(),
            admin_key_masked: None,
            org_label: None,
            connected_at: None,
            last_success_at: None,
            last_failure_at: None,
            last_error: String::new(),
            stale: false,
        });
        status.stale = self.connection_is_stale(&status);
        Ok(status)
    }

    fn connection_is_stale(&self, status: &ProviderConnection) -> bool {
        let days = self.settings.provider_stale_days;
        if !status.connected || days == 0 {
            return false;
        }
        let threshold = clock::to_rfc3339(clock::now() - time::Duration::days(i64::from(days)));
        match (&status.last_success_at, &status.connected_at) {
            (Some(ok), _) => ok < &threshold,
            // Never synced successfully: stale once the connection itself is
            // older than the threshold (grace period for fresh connections).
            (None, Some(connected)) => connected < &threshold,
            (None, None) => true,
        }
    }

    /// All provider connections (for monitoring and UI).
    pub fn provider_connections(&self) -> Result<Vec<ProviderConnection>> {
        let mut stmt = self
            .conn
            .prepare("SELECT provider FROM provider_connections ORDER BY provider")?;
        let providers: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<_>>()?;
        providers
            .iter()
            .map(|p| self.provider_connection_status(p))
            .collect()
    }

    /// Synchronize usage looking back `since_days` days from now.
    pub fn usage_sync(
        &self,
        provider: &str,
        http: &dyn crate::http::HttpClient,
        since_days: u32,
    ) -> Result<SyncReport> {
        let to = clock::now();
        let from = to - time::Duration::days(i64::from(since_days.max(1)));
        self.usage_sync_range(provider, http, from, to)
    }

    /// Synchronize usage using the stored checkpoint: the first sync covers a
    /// conservative default window (30 days); later syncs re-fetch from two
    /// days before the last successful window end, reconciling late-arriving
    /// provider data without re-downloading the full history.
    pub fn usage_sync_default(
        &self,
        provider: &str,
        http: &dyn crate::http::HttpClient,
    ) -> Result<SyncReport> {
        const DEFAULT_DAYS: i64 = 30;
        const OVERLAP_DAYS: i64 = 2;
        let provider_norm = crate::providers::normalize(provider);
        let to = clock::now();
        let default_from = to - time::Duration::days(DEFAULT_DAYS);
        let from = match self.sync_checkpoint(&provider_norm, "usage")? {
            Some((_, window_end)) => {
                let cp = clock::parse_rfc3339(&window_end)?;
                let overlapped = cp - time::Duration::days(OVERLAP_DAYS);
                if overlapped < default_from || overlapped > to {
                    default_from
                } else {
                    overlapped
                }
            }
            None => default_from,
        };
        self.usage_sync_range(provider, http, from, to)
    }

    fn sync_checkpoint(&self, provider: &str, kind: &str) -> Result<Option<(String, String)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT window_start, window_end FROM provider_sync_state
                 WHERE provider = ?1 AND kind = ?2",
                params![provider, kind],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// Synchronize provider usage and (where supported) provider-reported
    /// costs for an explicit window. All pages are fetched before anything is
    /// written; the replacement of previously synced rows and the insertion
    /// of fresh rows happen in one transaction, so a failed or interrupted
    /// sync changes nothing and can be retried safely. Manual snapshots are
    /// never touched.
    pub fn usage_sync_range(
        &self,
        provider: &str,
        http: &dyn crate::http::HttpClient,
        from: time::OffsetDateTime,
        to: time::OffsetDateTime,
    ) -> Result<SyncReport> {
        let provider = crate::providers::normalize(provider);
        if from >= to {
            return Err(CoreError::InvalidInput(
                "the sync window start must be before its end".into(),
            ));
        }
        let admin_secret = self.provider_admin_secret(&provider)?;
        let result = if provider == crate::openai::PROVIDER {
            self.openai_sync(http, &admin_secret, from, to)
        } else if provider == crate::anthropic::PROVIDER {
            self.anthropic_sync(http, &admin_secret, from, to)
        } else {
            self.legacy_connector_sync(&provider, http, &admin_secret, from, to)
        };
        let now = clock::now_rfc3339();
        match result {
            Ok(report) => {
                self.conn.execute(
                    "UPDATE provider_connections SET last_synced_at = ?1, last_success_at = ?1,
                     last_status = 'ok', detail = ?2, last_error = '' WHERE provider = ?3",
                    params![
                        now,
                        format!(
                            "{} usage row(s), {} provider-reported cost row(s)",
                            report.usage_rows, report.cost_rows
                        ),
                        provider
                    ],
                )?;
                // A successful sync resolves prior sync-failure alerts.
                self.conn.execute(
                    "UPDATE alerts SET resolved_at = ?1 WHERE resolved_at IS NULL
                     AND dedup_key IN (?2, ?3)",
                    params![
                        now,
                        format!("provider_sync_failed:{provider}"),
                        format!("provider_connection_invalid:{provider}"),
                    ],
                )?;
                crate::activity::record(
                    &self.conn,
                    "provider_usage",
                    "usage_sync",
                    None,
                    None,
                    &format!(
                        "{provider}: {} usage row(s), {} cost row(s)",
                        report.usage_rows, report.cost_rows
                    ),
                    "",
                )?;
                Ok(report)
            }
            Err(e) => {
                let (status_label, alert) = match &e {
                    CoreError::ProviderAuth { .. } => (
                        "invalid",
                        Some(alerts::NewAlert {
                            kind: alerts::AlertKind::ProviderConnectionInvalid,
                            severity: alerts::Severity::High,
                            dedup_key: format!("provider_connection_invalid:{provider}"),
                            title: format!("The {provider} administrative connection is invalid"),
                            detail: e.to_string(),
                            evidence: "the provider rejected the stored admin credential".into(),
                            confidence: crate::providers::Confidence::High,
                            recommended_action: format!(
                                "reconnect with a valid admin key: `provider connect {provider}`"
                            ),
                            project_id: None,
                            credential_id: None,
                            observed_at: now.clone(),
                        }),
                    ),
                    // A missing connection is user guidance, not an alert.
                    CoreError::InvalidInput(_) => ("error", None),
                    _ => (
                        "error",
                        Some(alerts::NewAlert {
                            kind: alerts::AlertKind::ProviderSyncFailed,
                            severity: alerts::Severity::Medium,
                            dedup_key: format!("provider_sync_failed:{provider}"),
                            title: format!("{provider} usage synchronization failed"),
                            detail: e.to_string(),
                            evidence: "the most recent synchronization attempt failed".into(),
                            confidence: crate::providers::Confidence::High,
                            recommended_action:
                                "check the network connection and retry; previously synced data \
                                 remains available offline"
                                    .into(),
                            project_id: None,
                            credential_id: None,
                            observed_at: now.clone(),
                        }),
                    ),
                };
                self.conn.execute(
                    "UPDATE provider_connections SET last_synced_at = ?1, last_failure_at = ?1,
                     last_status = ?2, last_error = ?3 WHERE provider = ?4",
                    params![now, status_label, e.to_string(), provider],
                )?;
                if let Some(a) = alert {
                    alerts::upsert(&self.conn, &a)?;
                }
                Err(e)
            }
        }
    }

    /// The OpenAI-specific sync: grouped usage + provider-reported costs +
    /// provider-side metadata, applied transactionally (ADR 0011).
    fn openai_sync(
        &self,
        http: &dyn crate::http::HttpClient,
        admin_secret: &SecretString,
        from: time::OffsetDateTime,
        to: time::OffsetDateTime,
    ) -> Result<SyncReport> {
        use crate::openai;
        let provider = openai::PROVIDER;
        let (from_unix, to_unix) = (from.unix_timestamp(), to.unix_timestamp());
        let mut notes = Vec::new();

        // Fetch everything (all pages) before writing anything. Usage is the
        // primary payload: its failure fails the sync. Costs are fetched
        // independently — cost data being unavailable while usage is
        // available is a supported, noted condition, not a sync failure (its
        // checkpoint is then left untouched so a later sync retries it).
        let mut usage_rows = openai::fetch_usage(http, admin_secret, from_unix, to_unix)?;
        let (mut cost_rows, costs_ok) =
            match openai::fetch_costs(http, admin_secret, from_unix, to_unix) {
                Ok(rows) => (rows, true),
                Err(e) => {
                    notes.push(format!("provider-reported costs are unavailable: {e}"));
                    (Vec::new(), false)
                }
            };

        // Provider-side metadata is best-effort: an admin key without the
        // api_keys read scope must not fail the usage sync.
        let mut side_projects = Vec::new();
        let mut side_keys = Vec::new();
        match openai::fetch_projects(http, admin_secret) {
            Ok(projects) => {
                const MAX_KEY_LISTINGS: usize = 50;
                if projects.len() > MAX_KEY_LISTINGS {
                    notes.push(format!(
                        "only the first {MAX_KEY_LISTINGS} of {} provider projects had their \
                         API keys listed",
                        projects.len()
                    ));
                }
                for p in projects.iter().take(MAX_KEY_LISTINGS) {
                    match openai::fetch_project_keys(http, admin_secret, &p.id) {
                        Ok(keys) => side_keys.extend(keys),
                        Err(e) => {
                            notes.push(format!(
                                "could not list API keys for provider project {}: {e}",
                                p.id
                            ));
                            break;
                        }
                    }
                }
                side_projects = projects;
            }
            Err(e) => notes.push(format!("provider project metadata unavailable: {e}")),
        }

        // Confirmed provider-key links upgrade rows to exact local
        // attribution. Unlinked rows keep their provider-side level.
        let links = self.provider_key_link_map(provider)?;
        for row in usage_rows.iter_mut().chain(cost_rows.iter_mut()) {
            if let Some(key_id) = &row.provider_api_key_id {
                if let Some((credential_id, project_id)) = links.get(key_id) {
                    row.credential_id = Some(credential_id.clone());
                    row.project_id = Some(project_id.clone());
                    row.attribution = usage::Attribution::ExactCredential;
                }
            }
            if row.provider_account_id.is_none() {
                row.provider_account_id = self.provider_org_label(provider)?;
            }
        }

        // Local estimates only where the model is known — never for cost
        // rows, which carry the provider-reported amount instead.
        for row in usage_rows.iter_mut() {
            if let (Some(model), Some(inp), Some(out)) =
                (&row.model, row.input_tokens, row.output_tokens)
            {
                if let Some(est) =
                    crate::pricing::estimate_token_cost(&self.conn, provider, model, inp, out)?
                {
                    row.estimated_cost_micros = Some(est.micros);
                }
            }
        }

        let usage_count = usage_rows.len();
        let cost_count = cost_rows.len();
        let now = clock::now_rfc3339();
        let tx = self.conn.unchecked_transaction()?;
        // Replace previously synced rows covering the re-reported buckets so
        // repeated and overlapping syncs never double-count. The deletion
        // range comes from the buckets the provider actually returned.
        if let (Some(min_start), Some(max_end)) = (
            usage_rows.iter().map(|s| s.window_start.clone()).min(),
            usage_rows.iter().map(|s| s.window_end.clone()).max(),
        ) {
            tx.execute(
                "DELETE FROM usage_snapshots
                 WHERE provider = ?1 AND source != 'manual' AND source != ?2
                 AND window_start >= ?3 AND window_start < ?4",
                params![provider, openai::COSTS_SOURCE, min_start, max_end],
            )?;
        }
        if let (Some(min_start), Some(max_end)) = (
            cost_rows.iter().map(|s| s.window_start.clone()).min(),
            cost_rows.iter().map(|s| s.window_end.clone()).max(),
        ) {
            tx.execute(
                "DELETE FROM usage_snapshots
                 WHERE provider = ?1 AND source = ?2
                 AND window_start >= ?3 AND window_start < ?4",
                params![provider, openai::COSTS_SOURCE, min_start, max_end],
            )?;
        }
        for row in usage_rows.iter().chain(cost_rows.iter()) {
            usage::record(&tx, row)?;
        }
        for p in &side_projects {
            tx.execute(
                "INSERT INTO provider_side_projects
                 (provider, project_id, name, status, synced_at, first_seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(provider, project_id) DO UPDATE SET
                 name = excluded.name, status = excluded.status, synced_at = excluded.synced_at,
                 first_seen_at = COALESCE(provider_side_projects.first_seen_at, excluded.first_seen_at)",
                params![provider, p.id, p.name, p.status, now],
            )?;
        }
        for k in &side_keys {
            tx.execute(
                "INSERT INTO provider_side_keys
                 (provider, api_key_id, provider_project_id, name, redacted_value,
                  created_at, last_used_at, synced_at, first_seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
                 ON CONFLICT(provider, api_key_id) DO UPDATE SET
                 provider_project_id = excluded.provider_project_id, name = excluded.name,
                 redacted_value = excluded.redacted_value, created_at = excluded.created_at,
                 last_used_at = excluded.last_used_at, synced_at = excluded.synced_at,
                 first_seen_at = COALESCE(provider_side_keys.first_seen_at, excluded.first_seen_at)",
                params![
                    provider,
                    k.id,
                    k.provider_project_id,
                    k.name,
                    k.redacted_value,
                    k.created_at,
                    k.last_used_at,
                    now
                ],
            )?;
        }
        let (from_s, to_s) = (clock::to_rfc3339(from), clock::to_rfc3339(to));
        let mut checkpoint_kinds = vec!["usage"];
        if costs_ok {
            checkpoint_kinds.push("costs");
        }
        for kind in checkpoint_kinds {
            tx.execute(
                "INSERT INTO provider_sync_state (provider, kind, window_start, window_end, synced_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(provider, kind) DO UPDATE SET
                 window_start = excluded.window_start, window_end = excluded.window_end,
                 synced_at = excluded.synced_at",
                params![provider, kind, from_s, to_s, now],
            )?;
        }
        tx.commit()?;
        Ok(SyncReport {
            provider: provider.to_string(),
            usage_rows: usage_count,
            cost_rows: cost_count,
            window_start: from_s,
            window_end: to_s,
            notes,
        })
    }

    /// The Anthropic Admin API sync engine: per-key daily usage (grouped
    /// api_key_id × workspace_id × model), workspace-level cost report
    /// (cents-denominated, converted with guards), workspace + key
    /// metadata, and provider-reported key expirations. Mirrors the
    /// fetch-all-then-replace semantics of `openai_sync`.
    fn anthropic_sync(
        &self,
        http: &dyn crate::http::HttpClient,
        admin_secret: &SecretString,
        from: time::OffsetDateTime,
        to: time::OffsetDateTime,
    ) -> Result<SyncReport> {
        use crate::anthropic;
        let provider = anthropic::PROVIDER;
        let mut notes = Vec::new();

        let mut usage_rows = anthropic::fetch_usage(http, admin_secret, from, to)?;
        let (mut cost_rows, costs_ok) = match anthropic::fetch_costs(http, admin_secret, from, to) {
            Ok(rows) => (rows, true),
            Err(e) => {
                notes.push(format!("provider-reported costs are unavailable: {e}"));
                (Vec::new(), false)
            }
        };

        // Provider-side metadata is best-effort.
        let mut side_projects = Vec::new();
        let mut side_keys: Vec<crate::openai::ProviderSideKey> = Vec::new();
        let mut key_expiries: Vec<(String, Option<String>)> = Vec::new();
        match anthropic::fetch_workspaces(http, admin_secret) {
            Ok(workspaces) => side_projects = workspaces,
            Err(e) => notes.push(format!("workspace metadata unavailable: {e}")),
        }
        let mut key_expiry_known = false;
        match anthropic::fetch_api_keys(http, admin_secret) {
            Ok(keys) => {
                key_expiry_known = true;
                for (key, expires_at) in keys {
                    // None is meaningful too: a removed/extended expiry must
                    // clear the stale local value.
                    key_expiries.push((key.id.clone(), expires_at));
                    side_keys.push(key);
                }
            }
            Err(e) => notes.push(format!("API-key metadata unavailable: {e}")),
        }

        // Confirmed links upgrade rows to exact local attribution; cost
        // rows carry no key dimension (documented) and stay coarse.
        let links = self.provider_key_link_map(provider)?;
        for row in usage_rows.iter_mut() {
            if let Some(key_id) = &row.provider_api_key_id {
                if let Some((credential_id, project_id)) = links.get(key_id) {
                    row.credential_id = Some(credential_id.clone());
                    row.project_id = Some(project_id.clone());
                    row.attribution = usage::Attribution::ExactCredential;
                }
            }
            if row.provider_account_id.is_none() {
                row.provider_account_id = self.provider_org_label(provider)?;
            }
        }
        for row in cost_rows.iter_mut() {
            if row.provider_account_id.is_none() {
                row.provider_account_id = self.provider_org_label(provider)?;
            }
        }
        for row in usage_rows.iter_mut() {
            if let (Some(model), Some(inp), Some(out)) =
                (&row.model, row.input_tokens, row.output_tokens)
            {
                if let Some(est) =
                    crate::pricing::estimate_token_cost(&self.conn, provider, model, inp, out)?
                {
                    row.estimated_cost_micros = Some(est.micros);
                }
            }
        }

        let usage_count = usage_rows.len();
        let cost_count = cost_rows.len();
        let now = clock::now_rfc3339();
        let tx = self.conn.unchecked_transaction()?;
        if let (Some(min_start), Some(max_end)) = (
            usage_rows.iter().map(|s| s.window_start.clone()).min(),
            usage_rows.iter().map(|s| s.window_end.clone()).max(),
        ) {
            tx.execute(
                "DELETE FROM usage_snapshots
                 WHERE provider = ?1 AND source != 'manual' AND source != ?2
                 AND window_start >= ?3 AND window_start < ?4",
                params![provider, anthropic::COSTS_SOURCE, min_start, max_end],
            )?;
        }
        if let (Some(min_start), Some(max_end)) = (
            cost_rows.iter().map(|s| s.window_start.clone()).min(),
            cost_rows.iter().map(|s| s.window_end.clone()).max(),
        ) {
            tx.execute(
                "DELETE FROM usage_snapshots
                 WHERE provider = ?1 AND source = ?2
                 AND window_start >= ?3 AND window_start < ?4",
                params![provider, anthropic::COSTS_SOURCE, min_start, max_end],
            )?;
        }
        for row in usage_rows.iter().chain(cost_rows.iter()) {
            usage::record(&tx, row)?;
        }
        for p in &side_projects {
            tx.execute(
                "INSERT INTO provider_side_projects
                 (provider, project_id, name, status, synced_at, first_seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(provider, project_id) DO UPDATE SET
                 name = excluded.name, status = excluded.status, synced_at = excluded.synced_at,
                 first_seen_at = COALESCE(provider_side_projects.first_seen_at, excluded.first_seen_at)",
                params![provider, p.id, p.name, p.status, now],
            )?;
        }
        for k in &side_keys {
            tx.execute(
                "INSERT INTO provider_side_keys
                 (provider, api_key_id, provider_project_id, name, redacted_value,
                  created_at, last_used_at, synced_at, first_seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
                 ON CONFLICT(provider, api_key_id) DO UPDATE SET
                 provider_project_id = excluded.provider_project_id, name = excluded.name,
                 redacted_value = excluded.redacted_value, created_at = excluded.created_at,
                 last_used_at = excluded.last_used_at, synced_at = excluded.synced_at,
                 first_seen_at = COALESCE(provider_side_keys.first_seen_at, excluded.first_seen_at)",
                params![
                    provider,
                    k.id,
                    k.provider_project_id,
                    k.name,
                    k.redacted_value,
                    k.created_at,
                    k.last_used_at,
                    now
                ],
            )?;
        }
        // Provider-reported key expirations flow onto LINKED credentials
        // (recorded verbatim from the provider, never invented; a listing
        // WITHOUT an expiry clears any stale local value).
        if key_expiry_known {
            for (key_id, expiry) in &key_expiries {
                if let Some((credential_id, _)) = links.get(key_id) {
                    tx.execute(
                        "UPDATE credentials SET provider_expires_at = ?1 WHERE id = ?2",
                        params![expiry, credential_id],
                    )?;
                }
            }
        }
        let (from_s, to_s) = (clock::to_rfc3339(from), clock::to_rfc3339(to));
        let mut checkpoint_kinds = vec!["usage"];
        if costs_ok {
            checkpoint_kinds.push("costs");
        }
        for kind in checkpoint_kinds {
            tx.execute(
                "INSERT INTO provider_sync_state (provider, kind, window_start, window_end, synced_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(provider, kind) DO UPDATE SET
                 window_start = excluded.window_start, window_end = excluded.window_end,
                 synced_at = excluded.synced_at",
                params![provider, kind, from_s, to_s, now],
            )?;
        }
        tx.commit()?;
        Ok(SyncReport {
            provider: provider.to_string(),
            usage_rows: usage_count,
            cost_rows: cost_count,
            window_start: from_s,
            window_end: to_s,
            notes,
        })
    }

    /// The pre-existing single-request connector sync for providers without a
    /// detailed engine (e.g. Anthropic org totals). Unchanged semantics.
    fn legacy_connector_sync(
        &self,
        provider: &str,
        http: &dyn crate::http::HttpClient,
        admin_secret: &SecretString,
        from: time::OffsetDateTime,
        to: time::OffsetDateTime,
    ) -> Result<SyncReport> {
        let connector = self.connector_for(provider)?;
        let since_days = ((to - from).whole_days().max(1)) as u32;
        let fetched = connector.fetch_usage(http, admin_secret, since_days)?;
        let tx = self.conn.unchecked_transaction()?;
        if let Some(earliest) = fetched.snapshots.iter().map(|s| &s.window_start).min() {
            tx.execute(
                "DELETE FROM usage_snapshots
                 WHERE provider = ?1 AND source != 'manual' AND window_start >= ?2",
                params![provider, earliest],
            )?;
        }
        let mut count = 0;
        for mut snap in fetched.snapshots {
            snap.source = fetched.source.clone();
            if let (Some(model), Some(inp), Some(out)) =
                (&snap.model, snap.input_tokens, snap.output_tokens)
            {
                if let Some(est) =
                    crate::pricing::estimate_token_cost(&tx, provider, model, inp, out)?
                {
                    snap.estimated_cost_micros = Some(est.micros);
                }
            }
            usage::record(&tx, &snap)?;
            count += 1;
        }
        tx.commit()?;
        Ok(SyncReport {
            provider: provider.to_string(),
            usage_rows: count,
            cost_rows: 0,
            window_start: clock::to_rfc3339(from),
            window_end: clock::to_rfc3339(to),
            notes: Vec::new(),
        })
    }

    fn provider_org_label(&self, provider: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT org_label FROM provider_connections WHERE provider = ?1",
                [provider],
                |r| r.get(0),
            )
            .optional()?
            .flatten())
    }

    /// provider_api_key_id -> (credential_id, project_id) for confirmed links.
    fn provider_key_link_map(&self, provider: &str) -> Result<HashMap<String, (String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT l.provider_api_key_id, l.credential_id, c.project_id
             FROM provider_key_links l JOIN credentials c ON c.id = l.credential_id
             WHERE l.provider = ?1",
        )?;
        let rows = stmt.query_map([provider], |r| {
            Ok((
                r.get::<_, String>(0)?,
                (r.get::<_, String>(1)?, r.get::<_, String>(2)?),
            ))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            map.insert(k, v);
        }
        Ok(map)
    }

    /// Confirm an association between a provider-side API-key id and a local
    /// credential. Retroactively upgrades matching synced rows to exact
    /// attribution. Returns the number of rows re-attributed.
    pub fn provider_link_key(
        &self,
        provider: &str,
        api_key_id: &str,
        credential_selector: &str,
    ) -> Result<usize> {
        let provider = crate::providers::normalize(provider);
        let cred = self.get_credential(credential_selector)?;
        if !cred.provider.eq_ignore_ascii_case(&provider) {
            return Err(CoreError::InvalidInput(format!(
                "credential '{}' belongs to provider '{}', not '{provider}'",
                cred.name, cred.provider
            )));
        }
        let now = clock::now_rfc3339();
        self.conn.execute(
            "INSERT INTO provider_key_links
             (provider, provider_api_key_id, credential_id, source, evidence, created_at)
             VALUES (?1, ?2, ?3, 'user_confirmed', ?4, ?5)
             ON CONFLICT(provider, provider_api_key_id) DO UPDATE SET
             credential_id = excluded.credential_id, source = excluded.source,
             evidence = excluded.evidence, created_at = excluded.created_at",
            params![
                provider,
                api_key_id,
                cred.id,
                format!(
                    "confirmed by the user for '{}/{}'",
                    cred.project_name, cred.name
                ),
                now
            ],
        )?;
        let updated = self.conn.execute(
            "UPDATE usage_snapshots SET credential_id = ?1, project_id = ?2,
             attribution = 'exact_credential'
             WHERE provider = ?3 AND provider_api_key_id = ?4 AND source != 'manual'",
            params![cred.id, cred.project_id, provider, api_key_id],
        )?;
        audit::record(
            &self.conn,
            "provider_key_linked",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!("provider={provider} api_key_id={api_key_id} rows={updated}"),
        )?;
        Ok(updated)
    }

    /// Remove a provider-key association and honestly downgrade the affected
    /// rows back to provider-side attribution.
    pub fn provider_unlink_key(&self, provider: &str, api_key_id: &str) -> Result<usize> {
        let provider = crate::providers::normalize(provider);
        let removed = self.conn.execute(
            "DELETE FROM provider_key_links WHERE provider = ?1 AND provider_api_key_id = ?2",
            params![provider, api_key_id],
        )?;
        if removed == 0 {
            return Ok(0);
        }
        let updated = self.conn.execute(
            "UPDATE usage_snapshots SET credential_id = NULL, project_id = NULL,
             attribution = 'provider_key'
             WHERE provider = ?1 AND provider_api_key_id = ?2 AND source != 'manual'",
            params![provider, api_key_id],
        )?;
        audit::record(
            &self.conn,
            "provider_key_unlinked",
            None,
            None,
            &format!("provider={provider} api_key_id={api_key_id} rows={updated}"),
        )?;
        Ok(updated)
    }

    /// Overview of every provider-side API key seen (from metadata and from
    /// synced usage), with link status and — for unlinked keys — a suggestion
    /// computed by matching the provider's redacted value against decryptable
    /// vault credentials. Suggestions are evidence for the user to confirm;
    /// they are never applied automatically.
    pub fn provider_keys_overview(&self, provider: &str) -> Result<Vec<ProviderKeyOverview>> {
        let provider = crate::providers::normalize(provider);
        let links = self.provider_key_link_map(&provider)?;
        let mut out: Vec<ProviderKeyOverview> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        let mut stmt = self.conn.prepare(
            "SELECT k.api_key_id, k.name, k.redacted_value, k.provider_project_id, p.name
             FROM provider_side_keys k
             LEFT JOIN provider_side_projects p
               ON p.provider = k.provider AND p.project_id = k.provider_project_id
             WHERE k.provider = ?1 ORDER BY k.api_key_id",
        )?;
        let rows = stmt.query_map([&provider], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        for row in rows {
            let (id, name, redacted, project_id, project_name) = row?;
            seen.insert(id.clone());
            out.push(ProviderKeyOverview {
                provider: provider.clone(),
                api_key_id: id,
                name,
                redacted_value: redacted,
                provider_project_id: project_id,
                provider_project_name: project_name,
                linked_credential_id: None,
                linked_credential: None,
                link_source: None,
                usage_rows: 0,
                suggested_credential_id: None,
                suggested_credential: None,
                note: String::new(),
            });
        }
        // Keys that appear in synced usage but not in metadata.
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT provider_api_key_id FROM usage_snapshots
             WHERE provider = ?1 AND provider_api_key_id IS NOT NULL AND source != 'manual'",
        )?;
        let ids = stmt.query_map([&provider], |r| r.get::<_, String>(0))?;
        for id in ids {
            let id = id?;
            if seen.insert(id.clone()) {
                out.push(ProviderKeyOverview {
                    provider: provider.clone(),
                    api_key_id: id,
                    name: String::new(),
                    redacted_value: String::new(),
                    provider_project_id: None,
                    provider_project_name: None,
                    linked_credential_id: None,
                    linked_credential: None,
                    link_source: None,
                    usage_rows: 0,
                    suggested_credential_id: None,
                    suggested_credential: None,
                    note: "seen in synced usage; not in the provider's key metadata".into(),
                });
            }
        }
        // Usage row counts, links, and suggestions.
        let openai_credentials: Vec<Credential> = self
            .list_credentials(None)?
            .into_iter()
            .filter(|c| c.provider.eq_ignore_ascii_case(&provider) && !c.is_reference)
            .collect();
        let mut locked_note = false;
        for entry in out.iter_mut() {
            entry.usage_rows = self.conn.query_row(
                "SELECT count(*) FROM usage_snapshots
                 WHERE provider = ?1 AND provider_api_key_id = ?2 AND source != 'manual'",
                params![provider, entry.api_key_id],
                |r| r.get(0),
            )?;
            if let Some((credential_id, _)) = links.get(&entry.api_key_id) {
                entry.linked_credential_id = Some(credential_id.clone());
                if let Some(c) = openai_credentials.iter().find(|c| &c.id == credential_id) {
                    entry.linked_credential = Some(format!("{}/{}", c.project_name, c.name));
                }
                entry.link_source = self
                    .conn
                    .query_row(
                        "SELECT source FROM provider_key_links
                         WHERE provider = ?1 AND provider_api_key_id = ?2",
                        params![provider, entry.api_key_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                continue;
            }
            if entry.redacted_value.is_empty() {
                continue;
            }
            let mut matches = Vec::new();
            for cred in &openai_credentials {
                match self.decrypt_value(&cred.id) {
                    Ok(value) => {
                        if crate::openai::redacted_value_matches(
                            &entry.redacted_value,
                            value.expose(),
                        ) {
                            matches.push(cred);
                        }
                    }
                    Err(CoreError::ProjectLocked(_)) => locked_note = true,
                    Err(_) => {}
                }
            }
            match matches.as_slice() {
                [only] => {
                    entry.suggested_credential_id = Some(only.id.clone());
                    entry.suggested_credential =
                        Some(format!("{}/{}", only.project_name, only.name));
                    entry.note =
                        "the provider's redacted value matches this vault credential; confirm \
                         to link"
                            .into();
                }
                [] => {}
                _ => {
                    entry.note =
                        "several vault credentials match the redacted value; link manually".into();
                }
            }
        }
        if locked_note {
            for entry in out.iter_mut() {
                if entry.linked_credential_id.is_none() && entry.suggested_credential_id.is_none() {
                    if !entry.note.is_empty() {
                        entry.note.push_str("; ");
                    }
                    entry
                        .note
                        .push_str("credentials in password-locked projects were not checked");
                }
            }
        }
        Ok(out)
    }

    /// Provider-side projects with month-to-date reported cost and whether
    /// any of their usage is linked to a local credential. Unmapped projects
    /// stay visible instead of being hidden or force-joined.
    pub fn provider_projects_overview(
        &self,
        provider: &str,
    ) -> Result<Vec<ProviderProjectOverview>> {
        let provider = crate::providers::normalize(provider);
        let month_start = crate::budget::period_start(clock::now());
        let mut stmt = self.conn.prepare(
            "SELECT ids.provider_project_id,
                    COALESCE(p.name, ''),
                    COALESCE((SELECT SUM(u.reported_cost_micros) FROM usage_snapshots u
                        WHERE u.provider = ?1 AND u.provider_project_id = ids.provider_project_id
                        AND u.reported_cost_micros IS NOT NULL AND u.currency = 'USD'
                        AND u.window_start >= ?2), 0),
                    EXISTS(SELECT 1 FROM usage_snapshots u2
                        WHERE u2.provider = ?1 AND u2.provider_project_id = ids.provider_project_id
                        AND u2.credential_id IS NOT NULL)
             FROM (SELECT DISTINCT provider_project_id FROM usage_snapshots
                   WHERE provider = ?1 AND provider_project_id IS NOT NULL
                   UNION SELECT project_id FROM provider_side_projects WHERE provider = ?1) ids
             LEFT JOIN provider_side_projects p
               ON p.provider = ?1 AND p.project_id = ids.provider_project_id
             ORDER BY 3 DESC",
        )?;
        let rows = stmt.query_map(params![provider, month_start], |r| {
            Ok(ProviderProjectOverview {
                provider_project_id: r.get(0)?,
                name: r.get(1)?,
                reported_cost_micros_month: r.get(2)?,
                has_linked_usage: r.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// The budget cost source configured for this vault.
    pub fn budget_cost_source(&self) -> Result<usage::CostSource> {
        Ok(meta_get(&self.conn, "budget_cost_source")?
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(usage::CostSource::BestAvailable))
    }

    pub fn set_budget_cost_source(&self, source: usage::CostSource) -> Result<()> {
        meta_set(&self.conn, "budget_cost_source", source.as_str())?;
        audit::record(
            &self.conn,
            "settings_updated",
            None,
            None,
            &format!("budget_cost_source={}", source.as_str()),
        )?;
        Ok(())
    }

    /// Record a usage snapshot manually (user-supplied), attributed to a
    /// credential/project, with a locally-estimated cost.
    pub fn usage_record_manual(
        &self,
        credential_selector: &str,
        model: Option<&str>,
        input_tokens: i64,
        output_tokens: i64,
        window_start: &str,
        window_end: &str,
    ) -> Result<String> {
        let cred = self.get_credential(credential_selector)?;
        let mut snap = usage::NewUsageSnapshot::new(&cred.provider, window_start, window_end);
        snap.credential_id = Some(cred.id.clone());
        snap.project_id = Some(cred.project_id.clone());
        snap.model = model.map(str::to_string);
        snap.input_tokens = Some(input_tokens);
        snap.output_tokens = Some(output_tokens);
        snap.total_tokens = Some(input_tokens + output_tokens);
        snap.source = "manual".into();
        snap.attribution = usage::Attribution::ExactCredential;
        if let Some(m) = model {
            if let Some(est) = crate::pricing::estimate_token_cost(
                &self.conn,
                &cred.provider,
                m,
                input_tokens,
                output_tokens,
            )? {
                snap.estimated_cost_micros = Some(est.micros);
            }
        }
        usage::record(&self.conn, &snap)
    }

    pub fn usage_totals(
        &self,
        since: &str,
        credential_selector: Option<&str>,
        project: Option<&str>,
    ) -> Result<usage::UsageTotals> {
        let cred_id = match credential_selector {
            Some(s) => Some(self.get_credential(s)?.id),
            None => None,
        };
        let proj_id = match project {
            Some(p) => Some(self.project_row_by_ident(p)?.id),
            None => None,
        };
        usage::totals_since(&self.conn, since, cred_id.as_deref(), proj_id.as_deref())
    }

    /// A detailed usage report: totals plus the matching snapshots, with
    /// provider/source filters resolved from user-facing selectors.
    pub fn usage_report(
        &self,
        since: &str,
        credential_selector: Option<&str>,
        project: Option<&str>,
        provider: Option<&str>,
        source: usage::SourceFilter,
    ) -> Result<(usage::UsageTotals, Vec<usage::UsageSnapshot>)> {
        let cred_id = match credential_selector {
            Some(s) => Some(self.get_credential(s)?.id),
            None => None,
        };
        let proj_id = match project {
            Some(p) => Some(self.project_row_by_ident(p)?.id),
            None => None,
        };
        let filter = usage::UsageFilter {
            since: Some(since.to_string()),
            until: None,
            credential_id: cred_id,
            project_id: proj_id,
            provider: provider.map(crate::providers::normalize),
            source,
        };
        Ok((
            usage::totals(&self.conn, &filter)?,
            usage::list(&self.conn, &filter)?,
        ))
    }

    pub fn set_project_budget_dollars(&self, project: &str, dollars: Option<&str>) -> Result<()> {
        let project = self.project_row_by_ident(project)?;
        let micros = match dollars {
            Some(d) => Some(crate::pricing::dollars_to_micros(d)?),
            None => None,
        };
        crate::budget::set_project_budget(&self.conn, &project.id, micros)
    }

    pub fn set_credential_budget_dollars(
        &self,
        selector: &str,
        dollars: Option<&str>,
    ) -> Result<()> {
        let cred = self.get_credential(selector)?;
        let micros = match dollars {
            Some(d) => Some(crate::pricing::dollars_to_micros(d)?),
            None => None,
        };
        crate::budget::set_credential_budget(&self.conn, &cred.id, micros)
    }

    pub fn project_budget_report(&self, project: &str) -> Result<crate::budget::BudgetReport> {
        let project = self.project_row_by_ident(project)?;
        crate::budget::project_report(&self.conn, &project.id, self.budget_cost_source()?)
    }

    pub fn credential_budget_report(&self, selector: &str) -> Result<crate::budget::BudgetReport> {
        let cred = self.get_credential(selector)?;
        crate::budget::credential_report(
            &self.conn,
            &cred.id,
            &format!("{}/{}", cred.project_name, cred.name),
            self.budget_cost_source()?,
        )
    }

    pub fn activity_list(
        &self,
        limit: u32,
        credential_selector: Option<&str>,
    ) -> Result<Vec<crate::activity::ActivityEvent>> {
        let cred_id = match credential_selector {
            Some(s) => Some(self.get_credential(s)?.id),
            None => None,
        };
        crate::activity::list(&self.conn, limit, cred_id.as_deref())
    }

    pub fn pricing_catalog(&self) -> Result<Vec<crate::pricing::PricingRecord>> {
        crate::pricing::catalog(&self.conn)
    }

    pub fn set_pricing_override(
        &self,
        provider: &str,
        model: &str,
        input_dollars_per_m: &str,
        output_dollars_per_m: &str,
        note: &str,
    ) -> Result<()> {
        crate::pricing::set_override(
            &self.conn,
            provider,
            model,
            crate::pricing::dollars_to_micros(input_dollars_per_m)?,
            crate::pricing::dollars_to_micros(output_dollars_per_m)?,
            note,
        )
    }

    // --- Process injection ---

    pub fn set_env_mapping(&self, project: &str, selector: &str, env_var: &str) -> Result<()> {
        let project = self.project_row_by_ident(project)?;
        let cred = self.get_credential(selector)?;
        if cred.project_id != project.id {
            return Err(CoreError::InvalidInput(
                "the credential is not in that project".into(),
            ));
        }
        crate::inject::set_mapping(&self.conn, &project.id, &cred.id, env_var)
    }

    pub fn remove_env_mapping(&self, project: &str, env_var: &str) -> Result<bool> {
        let project = self.project_row_by_ident(project)?;
        crate::inject::remove_mapping(&self.conn, &project.id, env_var)
    }

    pub fn list_env_mappings(&self, project: &str) -> Result<Vec<crate::inject::EnvMapping>> {
        let project = self.project_row_by_ident(project)?;
        crate::inject::list_mappings(&self.conn, &project.id)
    }

    /// Build the environment variables to inject for a project run. Only the
    /// requested credentials of THAT project are decrypted — never unrelated
    /// ones. `explicit` pairs (credential selector, env var) override/augment
    /// the project's configured mappings. Returns the env pairs plus a started
    /// process-session id; the caller spawns the child and calls
    /// [`end_process_session`].
    pub fn build_injection(
        &self,
        project: &str,
        explicit: &[(String, String)],
        command_label: &str,
    ) -> Result<(Vec<(String, SecretString)>, String)> {
        let project_row = self.project_row_by_ident(project)?;
        // Resolve the set of (env_var -> credential_id) from config + explicit.
        let mut wanted: Vec<(String, String)> = Vec::new(); // (env_var, credential_id)
        for m in crate::inject::list_mappings(&self.conn, &project_row.id)? {
            wanted.push((m.env_var, m.credential_id));
        }
        for (selector, env_var) in explicit {
            if !crate::inject::valid_env_name(env_var) {
                return Err(CoreError::InvalidInput(format!(
                    "'{env_var}' is not a valid environment-variable name"
                )));
            }
            let cred = self.get_credential(selector)?;
            if cred.project_id != project_row.id {
                return Err(CoreError::InvalidInput(format!(
                    "credential '{selector}' is not in project '{}'; refusing to inject unrelated credentials",
                    project_row.name
                )));
            }
            // Explicit mapping wins over a configured one for the same var.
            wanted.retain(|(v, _)| v != env_var);
            wanted.push((env_var.clone(), cred.id));
        }
        if wanted.is_empty() {
            return Err(CoreError::InvalidInput(
                "no credentials to inject; pass --credential/--env or configure mappings".into(),
            ));
        }
        let mut env = Vec::new();
        for (var, cred_id) in &wanted {
            // Decrypt strictly within this project.
            let cred = self
                .credential_row_by_id(cred_id)?
                .ok_or(CoreError::VaultCorrupted(
                    "mapping references a missing credential",
                ))?;
            if cred.project_id != project_row.id {
                return Err(CoreError::InvalidInput(
                    "a mapping references a credential outside this project".into(),
                ));
            }
            let value = self.decrypt_value(cred_id)?;
            env.push((var.clone(), value));
        }
        let var_names: Vec<String> = env.iter().map(|(v, _)| v.clone()).collect();
        let session =
            crate::inject::start_session(&self.conn, &project_row.id, command_label, &var_names)?;
        audit::record(
            &self.conn,
            "process_injection_started",
            Some(&project_row.id),
            None,
            &format!("vars={}", var_names.join(",")),
        )?;
        crate::activity::record(
            &self.conn,
            "process_session",
            "injection",
            None,
            Some(&project_row.id),
            command_label,
            &format!("vars={}", var_names.join(",")),
        )?;
        Ok((env, session))
    }

    pub fn end_process_session(&self, session_id: &str, exit_code: Option<i32>) -> Result<()> {
        crate::inject::end_session(&self.conn, session_id, exit_code)
    }

    pub fn list_process_sessions(
        &self,
        limit: u32,
        active_only: bool,
    ) -> Result<Vec<crate::inject::ProcessSession>> {
        crate::inject::list_sessions(&self.conn, limit, active_only)
    }

    /// Terminate a recorded injection session's process (best-effort local
    /// SIGTERM to the PID recorded at spawn). This is a LOCAL control: it
    /// cannot claw back values the process already received and never
    /// touches the provider credential. Refuses sessions that already ended
    /// or that recorded no PID. The session row itself is closed by the
    /// launching `run` process when the child exits.
    pub fn terminate_process_session(&self, ident: &str) -> Result<(String, i64, bool)> {
        let session = crate::inject::get_session(&self.conn, ident)?;
        if session.ended_at.is_some() {
            return Err(CoreError::InvalidInput(format!(
                "session {} already ended",
                session.id
            )));
        }
        let Some(pid) = session.pid else {
            return Err(CoreError::InvalidInput(format!(
                "session {} recorded no PID (started by an older build?)",
                session.id
            )));
        };
        let signalled = crate::inject::terminate_pid(pid);
        audit::record(
            &self.conn,
            "process_session_terminated",
            None,
            None,
            &format!("session={} pid={pid} signalled={signalled}", session.id),
        )?;
        Ok((session.id, pid, signalled))
    }

    // ------------------------------------------------------------------
    // Credential version history (docs/decisions/0012)
    // ------------------------------------------------------------------

    fn value_version_of(&self, credential_id: &str) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT value_version FROM credentials WHERE id = ?1",
            [credential_id],
            |r| r.get(0),
        )?)
    }

    /// Retain `row`'s current value as an encrypted version row (AAD-bound to
    /// the version number). Returns the retained version number. Old versions
    /// beyond the retention window are pruned.
    fn retain_credential_version(
        &self,
        row: &CredentialRow,
        project_key: &SecretBytes,
        reason: &str,
    ) -> Result<i64> {
        const KEEP_VERSIONS: i64 = 10;
        let version = self.value_version_of(&row.id)?;
        let ciphertext = row.ciphertext.as_deref().ok_or(CoreError::VaultCorrupted(
            "credential is missing its ciphertext",
        ))?;
        let plaintext = crypto::decrypt(
            project_key,
            &aad::credential_value(&self.vault_id, &row.project_id, &row.id),
            ciphertext,
            "credential value",
        )?;
        let versioned = crypto::encrypt(
            project_key,
            &aad::credential_version(&self.vault_id, &row.project_id, &row.id, version),
            plaintext.expose(),
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO credential_versions
             (credential_id, version, ciphertext, masked_value, fingerprint, created_at, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.id,
                version,
                versioned,
                row.masked_value,
                row.fingerprint,
                clock::now_rfc3339(),
                reason,
            ],
        )?;
        self.conn.execute(
            &format!(
                "DELETE FROM credential_versions WHERE credential_id = ?1 AND version <= ?2{}",
                VERSION_PRUNE_ROTATION_EXEMPTION
            ),
            params![row.id, version - KEEP_VERSIONS],
        )?;
        // Rollback window: versions older than the configured window are
        // pruned too (secure_delete overwrites the freed pages). 0 disables
        // age-based pruning; the count cap above always applies.
        let window_days = self.settings.rollback_window_days;
        if window_days > 0 {
            let cutoff =
                clock::to_rfc3339(clock::now() - time::Duration::days(i64::from(window_days)));
            self.conn.execute(
                &format!(
                    "DELETE FROM credential_versions WHERE credential_id = ?1 AND created_at < ?2{}",
                    VERSION_PRUNE_ROTATION_EXEMPTION
                ),
                params![row.id, cutoff],
            )?;
        }
        Ok(version)
    }

    /// List retained versions (masked values only). Reauthentication-gated:
    /// history is sensitive metadata about rotation cadence.
    pub fn credential_version_history(
        &self,
        selector: &str,
        master_password: &SecretString,
    ) -> Result<Vec<CredentialVersionInfo>> {
        self.verify_master_password(master_password)?;
        let row = self.resolve_credential(selector)?;
        let current_version = self.value_version_of(&row.id)?;
        let mut out = vec![CredentialVersionInfo {
            version: current_version,
            masked_value: row.masked_value.clone(),
            created_at: row.updated_at.clone(),
            reason: "current value".into(),
            current: true,
        }];
        let mut stmt = self.conn.prepare(
            "SELECT version, masked_value, created_at, reason FROM credential_versions
             WHERE credential_id = ?1 ORDER BY version DESC",
        )?;
        let rows = stmt.query_map([&row.id], |r| {
            Ok(CredentialVersionInfo {
                version: r.get(0)?,
                masked_value: r.get(1)?,
                created_at: r.get(2)?,
                reason: r.get(3)?,
                current: false,
            })
        })?;
        for r in rows {
            out.push(r?);
        }
        audit::record(
            &self.conn,
            "credential_versions_viewed",
            Some(&row.project_id),
            Some(&row.id),
            "",
        )?;
        Ok(out)
    }

    /// Decrypt a retained version's value (for destination rollback). The
    /// caller is responsible for reauthentication.
    fn decrypt_credential_version(
        &self,
        credential_id: &str,
        version: i64,
    ) -> Result<SecretString> {
        let row = self
            .credential_row_by_id(credential_id)?
            .ok_or(CoreError::NotFound {
                kind: "credential",
                ident: credential_id.to_string(),
            })?;
        if self.value_version_of(credential_id)? == version {
            let project = self.project_row_by_ident(&row.project_id)?;
            let project_key = self.project_key_for_row(&project)?;
            let ciphertext = row.ciphertext.as_deref().ok_or(CoreError::VaultCorrupted(
                "credential is missing its ciphertext",
            ))?;
            let plaintext = crypto::decrypt(
                &project_key,
                &aad::credential_value(&self.vault_id, &row.project_id, &row.id),
                ciphertext,
                "credential value",
            )?;
            return Ok(SecretString::new(
                String::from_utf8(plaintext.expose().to_vec()).map_err(|_| {
                    CoreError::VaultCorrupted("credential value is not valid UTF-8")
                })?,
            ));
        }
        let ciphertext: Vec<u8> = self
            .conn
            .query_row(
                "SELECT ciphertext FROM credential_versions
                 WHERE credential_id = ?1 AND version = ?2",
                params![credential_id, version],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(CoreError::NotFound {
                kind: "credential version",
                ident: format!("{credential_id}@v{version}"),
            })?;
        let project = self.project_row_by_ident(&row.project_id)?;
        let project_key = self.project_key_for_row(&project)?;
        let plaintext = crypto::decrypt(
            &project_key,
            &aad::credential_version(&self.vault_id, &row.project_id, credential_id, version),
            &ciphertext,
            "credential version",
        )?;
        Ok(SecretString::new(
            String::from_utf8(plaintext.expose().to_vec())
                .map_err(|_| CoreError::VaultCorrupted("credential value is not valid UTF-8"))?,
        ))
    }

    // ------------------------------------------------------------------
    // .env governance (docs/decisions/0012)
    // ------------------------------------------------------------------

    /// Discover environment files across a project's registered repositories
    /// (or an explicit path).
    pub fn env_discover(
        &self,
        project: Option<&str>,
        path: Option<&std::path::Path>,
    ) -> Result<Vec<crate::envgov::EnvFileInfo>> {
        let mut roots: Vec<PathBuf> = Vec::new();
        if let Some(path) = path {
            roots.push(path.to_path_buf());
        }
        if let Some(project) = project {
            let row = self.project_row_by_ident(project)?;
            let model = self.project_model(&row)?;
            roots.extend(model.repo_paths.iter().map(PathBuf::from));
        }
        if roots.is_empty() {
            return Err(CoreError::InvalidInput(
                "no repositories to search; register one on the project or pass a path".into(),
            ));
        }
        let mut out = Vec::new();
        for root in roots {
            out.extend(crate::envgov::discover(&root)?);
        }
        Ok(out)
    }

    /// Preview a `.env` file: classified variables, masked values only.
    pub fn env_preview(
        &self,
        project: &str,
        file: &std::path::Path,
    ) -> Result<Vec<crate::envgov::VarPreview>> {
        let project_row = self.project_row_by_ident(project)?;
        let content = std::fs::read_to_string(file)?;
        let doc = crate::envfile::EnvDocument::parse(&content);
        let label = file.to_string_lossy();
        let findings = scanner::scan_text(&content, &label, &scanner::ScanOptions::default());
        let mappings: HashMap<String, String> =
            crate::inject::list_mappings(&self.conn, &project_row.id)?
                .into_iter()
                .map(|m| (m.env_var, m.credential_name))
                .collect();
        let mut out = Vec::new();
        for entry in doc.entries() {
            let finding = findings.iter().find(|f| f.line == entry.line);
            let value = &entry.value;
            let is_placeholder = scanner::is_placeholder_value(value.expose());
            let vault_credential = if value.expose().trim().is_empty() {
                None
            } else {
                let fp = reuse::fingerprint(&self.fingerprint_key, value)?;
                self.find_reuse_matches(&fp, None)?
                    .first()
                    .map(|m| format!("{}/{}", m.project_name, m.credential_name))
            };
            out.push(crate::envgov::VarPreview {
                key: entry.key.clone(),
                line: entry.line,
                masked: entry.masked(),
                provider: finding.and_then(|f| f.provider.clone()),
                looks_secret: finding.is_some(),
                is_placeholder,
                vault_credential,
                mapped_credential: mappings.get(&entry.key).cloned(),
            });
        }
        Ok(out)
    }

    /// Import selected variables from a `.env` file into the vault and map
    /// them for injection. Never modifies the file.
    pub fn env_import(
        &mut self,
        project: &str,
        file: &std::path::Path,
        select: Option<&[String]>,
        environment: Option<Environment>,
    ) -> Result<Vec<EnvImportOutcome>> {
        let project_row = self.project_row_by_ident(project)?;
        let content = std::fs::read_to_string(file)?;
        let doc = crate::envfile::EnvDocument::parse(&content);
        let file_name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if crate::envgov::classify_file_name(&file_name)
            == Some(crate::envgov::EnvFileClass::Template)
        {
            return Err(CoreError::InvalidInput(format!(
                "'{file_name}' is a template file (names only); import a values file instead"
            )));
        }
        let environment = environment
            .or_else(|| crate::envgov::environment_from_name(&file_name))
            .unwrap_or(Environment::Development);
        let label = file.to_string_lossy();
        let findings = scanner::scan_text(&content, &label, &scanner::ScanOptions::default());
        let mut outcomes = Vec::new();
        let selected: Option<HashSet<&str>> =
            select.map(|keys| keys.iter().map(|k| k.as_str()).collect());
        let entries: Vec<_> = doc.entries().cloned().collect();
        for entry in &entries {
            let key = entry.key.as_str();
            let finding = findings.iter().find(|f| f.line == entry.line);
            let wanted = match &selected {
                Some(keys) => keys.contains(key),
                // Default selection: values the scanner flags as likely
                // secrets (placeholders and empties never qualify).
                None => finding.is_some(),
            };
            if !wanted {
                continue;
            }
            if entry.value.expose().trim().is_empty() {
                outcomes.push(EnvImportOutcome {
                    key: entry.key.clone(),
                    action: "skipped".into(),
                    credential: None,
                    note: "empty value".into(),
                });
                continue;
            }
            if scanner::is_placeholder_value(entry.value.expose()) {
                outcomes.push(EnvImportOutcome {
                    key: entry.key.clone(),
                    action: "skipped".into(),
                    credential: None,
                    note: "placeholder value".into(),
                });
                continue;
            }
            let fp = reuse::fingerprint(&self.fingerprint_key, &entry.value)?;
            let matches = self.find_reuse_matches(&fp, None)?;
            if let Some(m) = matches.iter().find(|m| m.project_id == project_row.id) {
                // Same value already stored in this project: map, don't copy.
                crate::inject::set_mapping(&self.conn, &project_row.id, &m.credential_id, key)?;
                outcomes.push(EnvImportOutcome {
                    key: entry.key.clone(),
                    action: "mapped_existing".into(),
                    credential: Some(m.credential_name.clone()),
                    note: "value already stored in this project; mapped for injection".into(),
                });
                continue;
            }
            if let Some(m) = matches.first() {
                outcomes.push(EnvImportOutcome {
                    key: entry.key.clone(),
                    action: "skipped".into(),
                    credential: Some(format!("{}/{}", m.project_name, m.credential_name)),
                    note: "value already stored in another project; add a reference with \
                           `key add --link-to` instead of a second copy"
                        .into(),
                });
                continue;
            }
            let provider = finding
                .and_then(|f| f.provider.clone())
                .unwrap_or_else(|| "other".to_string());
            let base_name = entry.key.to_ascii_lowercase().replace('_', "-");
            let mut name = base_name.clone();
            let mut n = 1;
            while self
                .ensure_credential_name_free(&project_row.id, &name, None)
                .is_err()
            {
                n += 1;
                name = format!("{base_name}-{n}");
            }
            let (credential, _warnings) = self.add_credential(AddCredential {
                project: project_row.id.clone(),
                provider,
                name: name.clone(),
                value: entry.value.clone(),
                environment,
                credential_type: None,
                key_created_at: None,
                expires_at: None,
                docs_url: String::new(),
                notes: format!("Imported from {file_name}"),
            })?;
            crate::inject::set_mapping(&self.conn, &project_row.id, &credential.id, key)?;
            outcomes.push(EnvImportOutcome {
                key: entry.key.clone(),
                action: "imported".into(),
                credential: Some(name),
                note: "stored encrypted and mapped for injection".into(),
            });
        }
        audit::record(
            &self.conn,
            "env_imported",
            Some(&project_row.id),
            None,
            &format!(
                "file={file_name} imported={}",
                outcomes
                    .iter()
                    .filter(|o| o.action == "imported" || o.action == "mapped_existing")
                    .count()
            ),
        )?;
        Ok(outcomes)
    }

    /// Detect drift between a project's `.env` files, its vault credentials,
    /// and its injection mappings.
    pub fn env_drift(&self, project: &str) -> Result<Vec<crate::envgov::DriftFinding>> {
        use crate::envgov::{DriftFinding, DriftKind, EnvFileClass};
        let project_row = self.project_row_by_ident(project)?;
        let model = self.project_model(&project_row)?;
        let mappings = crate::inject::list_mappings(&self.conn, &project_row.id)?;
        let mut findings = Vec::new();
        // fingerprint -> (file rel path, key) occurrences across all files
        let mut value_sites: HashMap<Vec<u8>, Vec<(String, String)>> = HashMap::new();
        let mut seen_vars: HashSet<String> = HashSet::new();
        let mut template_vars: HashSet<String> = HashSet::new();

        for repo in &model.repo_paths {
            let root = std::path::Path::new(repo);
            for info in crate::envgov::discover(root)? {
                let file_path = std::path::Path::new(&info.path);
                let content = std::fs::read_to_string(file_path).unwrap_or_default();
                let doc = crate::envfile::EnvDocument::parse(&content);
                if info.class == EnvFileClass::Template {
                    for entry in doc.entries() {
                        template_vars.insert(entry.key.clone());
                    }
                    continue;
                }
                let findings_in_file =
                    scanner::scan_text(&content, &info.rel_path, &scanner::ScanOptions::default());
                for entry in doc.entries() {
                    seen_vars.insert(entry.key.clone());
                    if entry.value.expose().trim().is_empty()
                        || scanner::is_placeholder_value(entry.value.expose())
                    {
                        continue;
                    }
                    let fp = reuse::fingerprint(&self.fingerprint_key, &entry.value)?;
                    value_sites
                        .entry(fp.clone())
                        .or_default()
                        .push((info.rel_path.clone(), entry.key.clone()));
                    let matches = self.find_reuse_matches(&fp, None)?;
                    let mapping = mappings.iter().find(|m| m.env_var == entry.key);
                    match (mapping, matches.is_empty()) {
                        (Some(mapping), _) => {
                            // Mapped variable: does the file's value still
                            // match the mapped credential's current value?
                            let mapped_fp: Vec<u8> = self.conn.query_row(
                                "SELECT fingerprint FROM credentials WHERE id = ?1",
                                [&mapping.credential_id],
                                |r| r.get(0),
                            )?;
                            if mapped_fp != fp {
                                findings.push(DriftFinding {
                                    kind: DriftKind::ValueDiffersFromVault,
                                    file: info.rel_path.clone(),
                                    key: entry.key.clone(),
                                    credential: Some(mapping.credential_name.clone()),
                                    detail: format!(
                                        "the value in {} does not match vault credential '{}'",
                                        info.rel_path, mapping.credential_name
                                    ),
                                    recommendation:
                                        "choose the source of truth: re-import the file value or \
                                         re-export the vault value"
                                            .into(),
                                });
                            }
                        }
                        (None, true) => {
                            let is_secret = findings_in_file.iter().any(|f| f.line == entry.line);
                            if is_secret {
                                findings.push(DriftFinding {
                                    kind: DriftKind::UnmappedSecret,
                                    file: info.rel_path.clone(),
                                    key: entry.key.clone(),
                                    credential: None,
                                    detail: format!(
                                        "{} holds a likely secret that is not in the vault",
                                        info.rel_path
                                    ),
                                    recommendation:
                                        "import it (`api-tracker env import`) and remove the \
                                         plaintext copy"
                                            .into(),
                                });
                            }
                        }
                        (None, false) => {
                            // Known value, but no mapping for this variable.
                            let m = &matches[0];
                            if m.environment == Environment::Production
                                && matches!(
                                    info.environment,
                                    Some(Environment::Development) | Some(Environment::Test)
                                )
                            {
                                findings.push(DriftFinding {
                                    kind: DriftKind::ProductionValueInDevFile,
                                    file: info.rel_path.clone(),
                                    key: entry.key.clone(),
                                    credential: Some(m.credential_name.clone()),
                                    detail: format!(
                                        "production credential '{}' appears in {}",
                                        m.credential_name, info.rel_path
                                    ),
                                    recommendation:
                                        "use a separate development credential; rotate the \
                                         production key if it was shared"
                                            .into(),
                                });
                            }
                        }
                    }
                    // Production credential in a dev-classified file also
                    // applies when the variable IS mapped.
                    if let Some(mapping) = mapping {
                        let env: String = self.conn.query_row(
                            "SELECT environment FROM credentials WHERE id = ?1",
                            [&mapping.credential_id],
                            |r| r.get(0),
                        )?;
                        if env == Environment::Production.as_str()
                            && matches!(
                                info.environment,
                                Some(Environment::Development) | Some(Environment::Test)
                            )
                        {
                            findings.push(DriftFinding {
                                kind: DriftKind::ProductionValueInDevFile,
                                file: info.rel_path.clone(),
                                key: entry.key.clone(),
                                credential: Some(mapping.credential_name.clone()),
                                detail: format!(
                                    "production credential '{}' is written into {}",
                                    mapping.credential_name, info.rel_path
                                ),
                                recommendation: "keep production values out of development \
                                                 files; use `api-tracker run` instead"
                                    .into(),
                            });
                        }
                    }
                }
            }
        }
        for (_fp, sites) in value_sites.iter().filter(|(_, s)| s.len() > 1) {
            let files: HashSet<&str> = sites.iter().map(|(f, _)| f.as_str()).collect();
            if files.len() > 1 {
                findings.push(crate::envgov::DriftFinding {
                    kind: DriftKind::SameValueInMultipleFiles,
                    file: sites[0].0.clone(),
                    key: sites[0].1.clone(),
                    credential: None,
                    detail: format!(
                        "the same value appears in {} files: {}",
                        files.len(),
                        sites
                            .iter()
                            .map(|(f, k)| format!("{f} ({k})"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    recommendation: "issue separate credentials per environment so one leak \
                                     does not compromise every environment"
                        .into(),
                });
            }
        }
        for var in &template_vars {
            if !seen_vars.contains(var) && !mappings.iter().any(|m| &m.env_var == var) {
                findings.push(crate::envgov::DriftFinding {
                    kind: DriftKind::MissingExpectedVariable,
                    file: String::new(),
                    key: var.clone(),
                    credential: None,
                    detail: format!(
                        "'{var}' is listed in a template (.env.example) but is neither mapped \
                         nor present in any values file"
                    ),
                    recommendation: "add the credential to the vault and map it, or remove it \
                                     from the template"
                        .into(),
                });
            }
        }
        for mapping in &mappings {
            if !seen_vars.contains(&mapping.env_var) {
                findings.push(crate::envgov::DriftFinding {
                    kind: DriftKind::MappingNotInFiles,
                    file: String::new(),
                    key: mapping.env_var.clone(),
                    credential: Some(mapping.credential_name.clone()),
                    detail: format!(
                        "mapping '{}' is not written in any .env file",
                        mapping.env_var
                    ),
                    recommendation: "expected when the project runs via `api-tracker run` — \
                                     no action needed; otherwise export explicitly"
                        .into(),
                });
            }
        }
        Ok(findings)
    }

    /// Explicit, reauthentication-gated export of mapped credentials to a
    /// physical `.env` file. Atomic, owner-only permissions, never silently
    /// overwrites, `.gitignore`-checked, redacted audit trail.
    #[allow(clippy::too_many_arguments)]
    pub fn env_export(
        &mut self,
        project: &str,
        path: &std::path::Path,
        vars: Option<&[String]>,
        master_password: &SecretString,
        overwrite: bool,
        ttl_minutes: Option<u64>,
    ) -> Result<EnvExportReport> {
        self.verify_master_password(master_password)?;
        let project_row = self.project_row_by_ident(project)?;
        let mappings = crate::inject::list_mappings(&self.conn, &project_row.id)?;
        let selected: Vec<_> = match vars {
            Some(names) => {
                let mut chosen = Vec::new();
                for name in names {
                    let m = mappings
                        .iter()
                        .find(|m| &m.env_var == name)
                        .ok_or_else(|| {
                            CoreError::InvalidInput(format!(
                                "no mapping for '{name}' in project '{}'",
                                project_row.name
                            ))
                        })?;
                    chosen.push(m.clone());
                }
                chosen
            }
            None => mappings.clone(),
        };
        if selected.is_empty() {
            return Err(CoreError::InvalidInput(
                "no mapped variables to export; configure mappings first".into(),
            ));
        }
        // Ten years, in minutes: anything longer is a typo, and absurd
        // values would overflow the expiry timestamp.
        const MAX_TTL_MINUTES: u64 = 10 * 365 * 24 * 60;
        if ttl_minutes.is_some_and(|ttl| ttl > MAX_TTL_MINUTES) {
            return Err(CoreError::InvalidInput(
                "--ttl is larger than ten years; pick a realistic lifetime".into(),
            ));
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        // Canonicalize so the recorded path is absolute: re-export and
        // cleanup must never resolve it against a different working
        // directory later.
        let parent = parent.canonicalize().map_err(|e| {
            CoreError::InvalidInput(format!("cannot access {}: {e}", parent.display()))
        })?;
        let path = &parent.join(path.file_name().ok_or_else(|| {
            CoreError::InvalidInput("the export target must be a file path".into())
        })?);
        if path.exists() && !overwrite {
            return Err(CoreError::InvalidInput(format!(
                "{} already exists; pass the overwrite flag to replace it",
                path.display()
            )));
        }
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let git_status = crate::envgov::gitignore_protects(&parent, &file_name);
        if git_status == crate::envgov::GitStatus::Tracked {
            return Err(CoreError::InvalidInput(format!(
                "{} is tracked by Git; exporting secrets into a tracked file would commit \
                 them. Untrack it (git rm --cached) and gitignore it first",
                path.display()
            )));
        }
        let mut doc = crate::envfile::EnvDocument::parse(
            "# Written by `api-tracker env export`. This file contains PLAINTEXT secrets.\n\
             # Prefer `api-tracker run`, which injects credentials without a file.\n",
        );
        let mut var_names = Vec::new();
        for mapping in &selected {
            let value = self.decrypt_value(&mapping.credential_id)?;
            doc.set(&mapping.env_var, value);
            var_names.push(mapping.env_var.clone());
        }
        let content = doc.render();
        if overwrite {
            crate::envgov::atomic_write(path, &content)?;
        } else {
            // No-clobber create: closes the race between the exists() check
            // above and the write (a file appearing in between is an error,
            // not silently replaced).
            crate::envgov::write_new(path, &content)?;
        }
        let expires_at = ttl_minutes.map(|minutes| {
            clock::rfc3339_after(std::time::Duration::from_secs(minutes.saturating_mul(60)))
        });
        let export_id = crate::envgov::record_export(
            &self.conn,
            &project_row.id,
            path,
            &var_names,
            &crate::envgov::content_hash(&content),
            expires_at.as_deref(),
        )?;
        audit::record(
            &self.conn,
            "env_exported",
            Some(&project_row.id),
            None,
            &format!(
                "path={} vars={} temporary={}",
                path.display(),
                var_names.join(","),
                expires_at.is_some()
            ),
        )?;
        let mut warnings =
            vec!["the exported file contains plaintext secrets; delete it when done".to_string()];
        if git_status == crate::envgov::GitStatus::Untracked {
            warnings.push(format!(
                "{} is NOT covered by .gitignore — add it before committing anything",
                path.display()
            ));
        }
        Ok(EnvExportReport {
            export_id,
            path: path.to_string_lossy().into_owned(),
            var_names,
            git_status,
            expires_at,
            warnings,
        })
    }

    /// Remove expired temporary exports (`all` removes every recorded
    /// export). Files modified since export are skipped unless `force`.
    pub fn env_cleanup(&self, all: bool, force: bool) -> Result<Vec<crate::envgov::CleanupResult>> {
        let results =
            crate::envgov::cleanup_exports(&self.conn, all, force, &clock::now_rfc3339())?;
        for result in &results {
            if result.outcome == crate::envgov::CleanupOutcome::Removed {
                audit::record(
                    &self.conn,
                    "env_export_cleaned",
                    None,
                    None,
                    &format!("path={}", result.path),
                )?;
            }
        }
        Ok(results)
    }

    /// Recorded exports (metadata only; values are never stored).
    pub fn env_exports(&self, include_cleaned: bool) -> Result<Vec<crate::envgov::EnvExport>> {
        crate::envgov::list_exports(&self.conn, include_cleaned)
    }

    // ------------------------------------------------------------------
    // Incremental repository monitoring (local Git only)
    // ------------------------------------------------------------------

    /// Scan only the commits added since the last monitor run, per
    /// registered repository. First sight of a repo records its HEAD as the
    /// baseline WITHOUT scanning history (on-demand `scan --history` covers
    /// that explicitly). Findings are matched against the vault and marked
    /// possibly exposed exactly like on-demand scans.
    pub fn scan_repos_incremental(&self) -> Result<Vec<RepoScanReport>> {
        let mut reports = Vec::new();
        let mut paths: Vec<String> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT DISTINCT path FROM project_repos ORDER BY path")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            for r in rows {
                paths.push(r?);
            }
        }
        for path in paths {
            let repo = std::path::Path::new(&path);
            if !repo.exists() {
                continue;
            }
            let Ok(head) = crate::gitrepo::head_commit(repo) else {
                continue; // not a repo / no commits — nothing to monitor
            };
            let last: Option<String> = self
                .conn
                .query_row(
                    "SELECT last_scanned_commit FROM repo_scan_state WHERE repo_path = ?1",
                    [&path],
                    |r| r.get(0),
                )
                .optional()?;
            let findings_count = match &last {
                None => 0, // baseline only
                Some(last) if last == &head => continue,
                Some(last) => {
                    // History rewritten or range unreadable: re-baseline
                    // rather than failing the whole monitor run — but say
                    // so, because commits in the unread range were NOT
                    // scanned.
                    let (units, range_ok) =
                        match crate::gitrepo::range_added_units(repo, last, &head) {
                            Ok(units) => (units, true),
                            Err(_) => (Vec::new(), false),
                        };
                    if !range_ok {
                        let _ = alerts::upsert(
                            &self.conn,
                            &alerts::NewAlert {
                                kind: alerts::AlertKind::PossibleExposure,
                                severity: alerts::Severity::Medium,
                                dedup_key: format!("repo_rebaselined:{path}:{head}"),
                                title: format!("repository re-baselined: {path}"),
                                detail: format!(
                                    "the commit range {last}..{head} could not be read                                      (history rewritten, or git failed). Commits in that                                      range were NOT scanned; run `api-tracker scan                                      --history` if secrets may have landed there."
                                ),
                                evidence: format!("last={last} head={head}"),
                                confidence: crate::providers::Confidence::Medium,
                                recommended_action:
                                    "run an explicit history scan of this repository".into(),
                                project_id: None,
                                credential_id: None,
                                observed_at: clock::now_rfc3339(),
                            },
                        );
                    }
                    let mut findings = Vec::new();
                    for unit in &units {
                        let options = scanner::ScanOptions {
                            entropy: !scanner::skip_entropy_for(&unit.label),
                        };
                        findings.extend(scanner::scan_text(&unit.content, &unit.label, &options));
                    }
                    let suppressions = load_suppression_keys(&self.conn)?;
                    findings.retain(|f| !suppressions.contains(&f.suppression_key));
                    let matches: Vec<_> = findings
                        .iter()
                        .map(|f| self.match_finding(f))
                        .collect::<Result<_>>()?;
                    for (finding, matched) in findings.iter_mut().zip(matches) {
                        finding.vault_match = matched;
                    }
                    let count = findings.len();
                    if count > 0 {
                        // Vault-matched findings mark the credential exposed
                        // (same path as on-demand scans).
                        let _ = self.mark_findings_exposed(&findings);
                        audit::record(
                            &self.conn,
                            "background_scan_findings",
                            None,
                            None,
                            &format!("repo={path} new_commits_findings={count}"),
                        )?;
                    }
                    count
                }
            };
            self.conn.execute(
                "INSERT INTO repo_scan_state (repo_path, last_scanned_commit, last_scan_at, last_findings)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (repo_path) DO UPDATE SET
                     last_scanned_commit = excluded.last_scanned_commit,
                     last_scan_at = excluded.last_scan_at,
                     last_findings = excluded.last_findings",
                params![path, head, clock::now_rfc3339(), findings_count as i64],
            )?;
            reports.push(RepoScanReport {
                repo_path: path,
                head_commit: head,
                findings: findings_count,
                baseline_only: last.is_none(),
            });
        }
        Ok(reports)
    }

    // ------------------------------------------------------------------
    // Scheduled documentation checks + change history
    // ------------------------------------------------------------------

    /// Check every documentation watch that is due per the configured
    /// interval. Failures preserve prior state (offline-safe); returns
    /// (url, outcome) pairs for reporting.
    pub fn check_due_doc_watches(
        &self,
        fetcher: &dyn crate::docwatch::DocFetcher,
    ) -> Result<Vec<(String, String)>> {
        let due = crate::docwatch::due_watches(&self.conn, self.settings.docwatch_interval_hours)?;
        let mut out = Vec::new();
        for url in due {
            let outcome = match self.check_doc_watch(fetcher, &url) {
                Ok((crate::docwatch::CheckResult::FirstCapture, _)) => "first_capture".to_string(),
                Ok((crate::docwatch::CheckResult::Unchanged, _)) => "unchanged".to_string(),
                Ok((crate::docwatch::CheckResult::Changed, _)) => "changed".to_string(),
                Ok((crate::docwatch::CheckResult::Failed, _)) => "failed".to_string(),
                Err(e) => format!("error: {e}"),
            };
            out.push((url, outcome));
        }
        Ok(out)
    }

    /// Sweep bookkeeping rows that would otherwise grow forever: doc-watch
    /// history beyond 200 entries per URL, and scan state for repository
    /// paths no longer registered on any project.
    fn prune_observability_state(&self) -> Result<()> {
        self.conn.execute(
            "DELETE FROM doc_watch_history WHERE id IN (
                 SELECT id FROM (
                     SELECT id, ROW_NUMBER() OVER (
                         PARTITION BY url ORDER BY id DESC) AS rn
                     FROM doc_watch_history)
                 WHERE rn > 200)",
            [],
        )?;
        self.conn.execute(
            "DELETE FROM repo_scan_state WHERE repo_path NOT IN (
                 SELECT DISTINCT path FROM project_repos)",
            [],
        )?;
        Ok(())
    }

    pub fn doc_watch_history(
        &self,
        url: Option<&str>,
        limit: u32,
    ) -> Result<Vec<crate::docwatch::HistoryEntry>> {
        crate::docwatch::history(&self.conn, url, limit)
    }

    // ------------------------------------------------------------------
    // Notification channels (user-configured webhooks; optional)
    // ------------------------------------------------------------------

    /// Configure a webhook channel. The URL is encrypted under the vault
    /// key (it may embed a user-chosen token) and masked for display.
    pub fn notification_channel_add(
        &self,
        name: &str,
        url: &SecretString,
        min_severity: &str,
    ) -> Result<crate::notify::NotificationChannel> {
        let url_trim = url.expose().trim();
        crate::notify::validate_webhook_url(url_trim)?;
        if !matches!(
            min_severity,
            "info" | "low" | "medium" | "high" | "critical"
        ) {
            return Err(CoreError::InvalidInput(format!(
                "'{min_severity}' is not a severity (info/low/medium/high/critical)"
            )));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let ciphertext = crypto::encrypt(
            &self.vault_key,
            &aad::notification_channel(&self.vault_id, &id),
            url_trim.as_bytes(),
        )?;
        // Reuse the id we encrypted under: insert with that exact id.
        self.conn
            .execute(
                "INSERT INTO notification_channels
                 (id, name, kind, url_ciphertext, url_masked, min_severity, created_at)
             VALUES (?1, ?2, 'webhook', ?3, ?4, ?5, ?6)",
                params![
                    id,
                    name,
                    ciphertext,
                    mask_value(url_trim),
                    min_severity,
                    clock::now_rfc3339()
                ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(err, _)
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    CoreError::AlreadyExists {
                        kind: "notification channel",
                        ident: name.to_string(),
                    }
                }
                other => other.into(),
            })?;
        audit::record(
            &self.conn,
            "notification_channel_added",
            None,
            None,
            &format!("name={name} min_severity={min_severity}"),
        )?;
        crate::notify::get(&self.conn, &id)
    }

    /// Delivery/failure history for webhook notifications: one recorded
    /// event per attempt (channel name, alert kind, outcome — never the
    /// URL, never secret values).
    pub fn notification_history(&self, limit: u32) -> Result<Vec<crate::activity::ActivityEvent>> {
        crate::activity::list_by_kind(&self.conn, "webhook_delivery", limit)
    }

    pub fn notification_channels(&self) -> Result<Vec<crate::notify::NotificationChannel>> {
        crate::notify::list(&self.conn)
    }

    pub fn notification_channel_remove(&self, ident: &str) -> Result<()> {
        let channel = crate::notify::get(&self.conn, ident)?;
        crate::notify::remove(&self.conn, &channel.id)?;
        audit::record(
            &self.conn,
            "notification_channel_removed",
            None,
            None,
            &format!("name={}", channel.name),
        )?;
        Ok(())
    }

    pub fn notification_channel_enable(&self, ident: &str, enabled: bool) -> Result<()> {
        let channel = crate::notify::get(&self.conn, ident)?;
        crate::notify::set_enabled(&self.conn, &channel.id, enabled)
    }

    fn notification_channel_url(&self, id: &str) -> Result<SecretString> {
        let ciphertext = crate::notify::url_ciphertext(&self.conn, id)?;
        let plaintext = crypto::decrypt(
            &self.vault_key,
            &aad::notification_channel(&self.vault_id, id),
            &ciphertext,
            "notification channel URL",
        )?;
        Ok(SecretString::new(
            String::from_utf8(plaintext.expose().to_vec())
                .map_err(|_| CoreError::VaultCorrupted("channel URL is not valid UTF-8"))?,
        ))
    }

    /// Send a test payload through one channel (no secrets, clearly a test).
    pub fn notification_channel_test(
        &self,
        ident: &str,
        http: &dyn crate::http::HttpClient,
    ) -> Result<String> {
        let channel = crate::notify::get(&self.conn, ident)?;
        let url = self.notification_channel_url(&channel.id)?;
        let now = clock::now_rfc3339();
        let payload = crate::notify::NotificationPayload {
            source: "api-tracker",
            kind: "test",
            severity: "info",
            title: "API Tracker test notification",
            detail: "channel connectivity test — no alert condition exists",
            recommended_action: "none",
            observed_at: &now,
        };
        match crate::notify::deliver_webhook(http, url.expose(), &payload) {
            Ok(detail) => {
                crate::notify::record_delivery(&self.conn, &channel.id, None)?;
                Ok(detail)
            }
            Err(e) => {
                crate::notify::record_delivery(&self.conn, &channel.id, Some(&e.to_string()))?;
                Err(e)
            }
        }
    }

    /// Deliver open alerts at or above each channel's severity floor that
    /// were observed within the last hour (the monitor cadence). Payloads
    /// carry alert metadata only. Failures are recorded per channel and
    /// never fail the caller.
    pub fn deliver_notifications(&self, http: &dyn crate::http::HttpClient) -> Result<usize> {
        let channels: Vec<_> = crate::notify::list(&self.conn)?
            .into_iter()
            .filter(|c| c.enabled)
            .collect();
        if channels.is_empty() {
            return Ok(0);
        }
        let hour_ago = clock::to_rfc3339(clock::now() - time::Duration::hours(1));
        let open = alerts::list(&self.conn, false)?;
        let mut delivered = 0usize;
        for channel in &channels {
            let floor = crate::notify::severity_rank(&channel.min_severity);
            let url = match self.notification_channel_url(&channel.id) {
                Ok(url) => url,
                Err(e) => {
                    let _ = crate::notify::record_delivery(
                        &self.conn,
                        &channel.id,
                        Some(&e.to_string()),
                    );
                    continue;
                }
            };
            let mut channel_error: Option<String> = None;
            for alert in &open {
                if alert.observed_at < hour_ago {
                    continue;
                }
                // Stored severities are already lowercase strings.
                if crate::notify::severity_rank(&alert.severity) < floor {
                    continue;
                }
                // Once per alert per channel: deliver only when the alert is
                // new to this channel or its severity escalated. Failures do
                // not mark the alert delivered, so they are retried next run.
                if !crate::notify::should_deliver(
                    &self.conn,
                    &channel.id,
                    &alert.id,
                    &alert.severity,
                )? {
                    continue;
                }
                let payload = crate::notify::NotificationPayload {
                    source: "api-tracker",
                    kind: &alert.kind,
                    severity: &alert.severity,
                    title: &alert.title,
                    detail: &alert.detail,
                    recommended_action: &alert.recommended_action,
                    observed_at: &alert.observed_at,
                };
                match crate::notify::deliver_webhook(http, url.expose(), &payload) {
                    Ok(_) => {
                        delivered += 1;
                        crate::notify::mark_delivered(
                            &self.conn,
                            &channel.id,
                            &alert.id,
                            &alert.severity,
                        )?;
                        let _ = crate::activity::record(
                            &self.conn,
                            "notification",
                            "webhook_delivery",
                            None,
                            None,
                            &format!("channel={} alert={} delivered", channel.name, alert.kind),
                            &format!("severity={}", alert.severity),
                        );
                    }
                    Err(e) => {
                        channel_error = Some(e.to_string());
                        // Delivery errors carry status text only, never the URL.
                        let _ = crate::activity::record(
                            &self.conn,
                            "notification",
                            "webhook_delivery",
                            None,
                            None,
                            &format!("channel={} alert={} FAILED: {e}", channel.name, alert.kind),
                            &format!("severity={}", alert.severity),
                        );
                        break; // one failure: stop hammering this channel
                    }
                }
            }
            let _ =
                crate::notify::record_delivery(&self.conn, &channel.id, channel_error.as_deref());
        }
        Ok(delivered)
    }

    // ------------------------------------------------------------------
    // Destinations (docs/decisions/0012)
    // ------------------------------------------------------------------

    /// Configure a destination. `auth` (a token, or JSON for AWS) is
    /// encrypted under the vault key and is write-only thereafter.
    pub fn destination_add(
        &self,
        kind: &str,
        name: &str,
        config: serde_json::Value,
        auth: Option<&SecretString>,
    ) -> Result<crate::destinations::Destination> {
        let info = crate::destinations::kind_info(kind)?;
        if matches!(
            info.capabilities.write,
            crate::destinations::DestSupport::PlatformUnavailable
        ) {
            return Err(CoreError::Unsupported {
                provider: kind.to_string(),
                capability: "destination",
                hint: format!("{} is not available on this platform", info.name),
            });
        }
        let name = name.trim();
        if name.is_empty() {
            return Err(CoreError::InvalidInput(
                "destination name must not be empty".into(),
            ));
        }
        // Encrypt after the id is known (the AAD binds vault + destination).
        let id = crate::destinations::insert(&self.conn, kind, name, &config, None, None)?;
        if let Some(auth) = auth {
            if auth.expose().trim().is_empty() {
                return Err(CoreError::InvalidInput(
                    "the destination credential must not be empty".into(),
                ));
            }
            let ciphertext = crypto::encrypt(
                &self.vault_key,
                &aad::destination_auth(&self.vault_id, &id),
                auth.expose().as_bytes(),
            )?;
            self.conn.execute(
                "UPDATE destinations SET auth_ciphertext = ?1, auth_masked = ?2 WHERE id = ?3",
                params![ciphertext, mask_value(auth.expose()), id],
            )?;
        }
        audit::record(
            &self.conn,
            "destination_added",
            None,
            None,
            &format!("kind={kind} name={name}"),
        )?;
        crate::destinations::get(&self.conn, &id)
    }

    /// Remove a destination. Reauthentication-gated: it may hold an
    /// administrative credential and drop deployed-secret bookkeeping.
    pub fn destination_remove(
        &self,
        ident: &str,
        master_password: &SecretString,
    ) -> Result<crate::destinations::Destination> {
        self.verify_master_password(master_password)?;
        let dest = crate::destinations::get(&self.conn, ident)?;
        crate::destinations::remove(&self.conn, &dest.id)?;
        audit::record(
            &self.conn,
            "destination_removed",
            None,
            None,
            &format!("kind={} name={}", dest.kind, dest.name),
        )?;
        Ok(dest)
    }

    pub fn destination_list(&self) -> Result<Vec<crate::destinations::Destination>> {
        crate::destinations::list(&self.conn)
    }

    pub fn destination_get(&self, ident: &str) -> Result<crate::destinations::Destination> {
        crate::destinations::get(&self.conn, ident)
    }

    fn destination_auth_secret(
        &self,
        dest: &crate::destinations::Destination,
    ) -> Result<Option<SecretString>> {
        let Some(ciphertext) = crate::destinations::auth_ciphertext(&self.conn, &dest.id)? else {
            return Ok(None);
        };
        let plaintext = crypto::decrypt(
            &self.vault_key,
            &aad::destination_auth(&self.vault_id, &dest.id),
            &ciphertext,
            "destination credential",
        )?;
        Ok(Some(SecretString::new(
            String::from_utf8(plaintext.expose().to_vec()).map_err(|_| {
                CoreError::VaultCorrupted("destination credential is not valid UTF-8")
            })?,
        )))
    }

    /// Build the runtime adapter for a configured destination.
    fn destination_adapter<'a>(
        &self,
        dest: &crate::destinations::Destination,
        http: &'a dyn crate::http::HttpClient,
        runner: &'a dyn crate::destinations::CommandRunner,
    ) -> Result<Box<dyn crate::destinations::DestinationAdapter + 'a>> {
        use crate::destinations as d;
        let cfg = |key: &str| -> Option<String> {
            dest.config
                .get(key)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };
        let auth = self.destination_auth_secret(dest)?;
        let need_auth = || {
            auth.clone().ok_or_else(|| {
                CoreError::InvalidInput(format!(
                    "destination '{}' has no stored credential; re-add it with one",
                    dest.name
                ))
            })
        };
        match dest.kind.as_str() {
            "macos_keychain" => {
                if !cfg!(target_os = "macos") {
                    return Err(CoreError::Unsupported {
                        provider: dest.kind.clone(),
                        capability: "destination",
                        hint: "the macOS Keychain is only available on macOS".into(),
                    });
                }
                Ok(Box::new(d::MacKeychainDestination {
                    runner,
                    account: cfg("account").unwrap_or_else(|| "api-tracker".to_string()),
                }))
            }
            "aws_secrets_manager" => {
                let region = cfg("region").ok_or_else(|| {
                    CoreError::InvalidInput("AWS destination config needs a region".into())
                })?;
                Ok(Box::new(d::AwsSecretsManagerDestination {
                    http,
                    creds: d::AwsCredentials::from_json(&need_auth()?)?,
                    region,
                }))
            }
            "github_actions" => Ok(Box::new(d::GithubActionsDestination {
                http,
                token: need_auth()?,
                owner: cfg("owner").ok_or_else(|| {
                    CoreError::InvalidInput("GitHub destination config needs owner".into())
                })?,
                repo: cfg("repo").ok_or_else(|| {
                    CoreError::InvalidInput("GitHub destination config needs repo".into())
                })?,
            })),
            "vercel" => {
                let targets = dest
                    .config
                    .get("targets")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| {
                        vec![
                            "production".to_string(),
                            "preview".to_string(),
                            "development".to_string(),
                        ]
                    });
                Ok(Box::new(d::VercelDestination {
                    http,
                    token: need_auth()?,
                    project_id: cfg("project_id").ok_or_else(|| {
                        CoreError::InvalidInput("Vercel destination config needs project_id".into())
                    })?,
                    team_id: cfg("team_id"),
                    targets,
                }))
            }
            other => Err(CoreError::Unsupported {
                provider: other.to_string(),
                capability: "destination",
                hint: "this destination kind has no runtime adapter".into(),
            }),
        }
    }

    /// Verify a destination's authentication/reachability.
    pub fn destination_test(
        &self,
        ident: &str,
        http: &dyn crate::http::HttpClient,
        runner: &dyn crate::destinations::CommandRunner,
    ) -> Result<String> {
        let dest = crate::destinations::get(&self.conn, ident)?;
        let adapter = self.destination_adapter(&dest, http, runner)?;
        match adapter.test() {
            Ok(detail) => {
                crate::destinations::record_test(&self.conn, &dest.id, None)?;
                Ok(detail)
            }
            Err(e) => {
                crate::destinations::record_test(&self.conn, &dest.id, Some(&e.to_string()))?;
                Err(e)
            }
        }
    }

    /// Attach a credential to a destination under a secret name.
    pub fn destination_attach(
        &self,
        credential: &str,
        destination: &str,
        secret_name: &str,
        environment: &str,
    ) -> Result<()> {
        let cred = self.resolve_credential(credential)?;
        let dest = crate::destinations::get(&self.conn, destination)?;
        crate::destinations::attach(&self.conn, &cred.id, &dest.id, secret_name, environment)?;
        audit::record(
            &self.conn,
            "destination_attached",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!("destination={} secret={secret_name}", dest.name),
        )?;
        Ok(())
    }

    pub fn destination_detach(
        &self,
        credential: &str,
        destination: &str,
        secret_name: Option<&str>,
    ) -> Result<usize> {
        let cred = self.resolve_credential(credential)?;
        let dest = crate::destinations::get(&self.conn, destination)?;
        let n = crate::destinations::detach(&self.conn, &cred.id, &dest.id, secret_name)?;
        if n > 0 {
            audit::record(
                &self.conn,
                "destination_detached",
                Some(&cred.project_id),
                Some(&cred.id),
                &format!("destination={}", dest.name),
            )?;
        }
        Ok(n)
    }

    pub fn destination_attachments(
        &self,
        credential: Option<&str>,
    ) -> Result<Vec<crate::destinations::Attachment>> {
        match credential {
            Some(selector) => {
                let cred = self.resolve_credential(selector)?;
                crate::destinations::attachments_for_credential(&self.conn, &cred.id)
            }
            None => crate::destinations::all_attachments(&self.conn),
        }
    }

    // ------------------------------------------------------------------
    // Synchronization plans (docs/decisions/0012)
    // ------------------------------------------------------------------

    fn validation_for_kind(kind: &str) -> (String, bool) {
        match crate::destinations::kind_info(kind) {
            Ok(info) => {
                let validation = match (info.capabilities.read, info.capabilities.validation) {
                    (crate::destinations::DestSupport::Implemented, _) => {
                        "value read-back and fingerprint comparison".to_string()
                    }
                    (_, crate::destinations::DestSupport::Implemented) => {
                        "existence check (the destination never returns values)".to_string()
                    }
                    _ => "none available".to_string(),
                };
                let writable = matches!(
                    info.capabilities.write,
                    crate::destinations::DestSupport::Implemented
                );
                (validation, writable)
            }
            Err(_) => ("none available".to_string(), false),
        }
    }

    /// Generate (but do not execute) a synchronization plan for a
    /// credential's current value. This is the dry run every rollout starts
    /// from.
    pub fn sync_plan_create(
        &self,
        credential: &str,
        note: &str,
    ) -> Result<crate::syncplan::SyncPlan> {
        let cred = self.resolve_credential(credential)?;
        if cred.linked_credential_id.is_some() {
            return Err(CoreError::InvalidInput(
                "this record is a reference; plan against the credential it points to".into(),
            ));
        }
        let to_version = self.value_version_of(&cred.id)?;
        let from_version: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(version) FROM credential_versions WHERE credential_id = ?1",
                [&cred.id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let mut steps = Vec::new();
        let mut manual_steps = Vec::new();
        for attachment in crate::destinations::attachments_for_credential(&self.conn, &cred.id)? {
            let (validation, writable) = Self::validation_for_kind(&attachment.destination_kind);
            let action =
                if writable {
                    crate::syncplan::ACTION_WRITE
                } else {
                    manual_steps.push(format!(
                    "update '{}' at destination '{}' by hand (kind '{}' has no implemented write)",
                    attachment.secret_name, attachment.destination_name, attachment.destination_kind
                ));
                    crate::syncplan::ACTION_MANUAL
                };
            steps.push(crate::syncplan::SyncStep {
                destination_id: attachment.destination_id,
                destination_name: attachment.destination_name,
                destination_kind: attachment.destination_kind,
                secret_name: attachment.secret_name,
                environment: attachment.environment,
                action: action.to_string(),
                status: crate::syncplan::STEP_PLANNED.to_string(),
                detail: String::new(),
                validation,
                rollback_available: from_version.is_some() && writable,
                executed_at: None,
                verified_at: None,
                rolled_back_at: None,
            });
        }
        // Injection mappings resolve the vault value at run time: include an
        // informational no-op step so the plan is complete and honest.
        let mapping_count: i64 = self.conn.query_row(
            "SELECT count(*) FROM credential_env_mappings WHERE credential_id = ?1",
            [&cred.id],
            |r| r.get(0),
        )?;
        if mapping_count > 0 {
            steps.push(crate::syncplan::SyncStep {
                destination_id: "env_mapping".into(),
                destination_name: "local environment mappings".into(),
                destination_kind: "env_mapping".into(),
                secret_name: format!("{mapping_count} mapping(s)"),
                environment: String::new(),
                action: crate::syncplan::ACTION_NONE.into(),
                status: crate::syncplan::STEP_PLANNED.into(),
                detail: "`api-tracker run` always injects the current vault value".into(),
                validation: "not needed (resolved at injection time)".into(),
                rollback_available: false,
                executed_at: None,
                verified_at: None,
                rolled_back_at: None,
            });
        }
        // Live exported .env files that carry a variable mapped to this
        // credential must be re-exported.
        for export in crate::envgov::list_exports(&self.conn, false)? {
            let vars: Vec<&str> = export.var_names.split(',').collect();
            let mapped: Vec<String> = self
                .conn
                .prepare(
                    "SELECT env_var FROM credential_env_mappings
                     WHERE credential_id = ?1 AND project_id = ?2",
                )?
                .query_map(params![cred.id, export.project_id], |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<std::result::Result<_, _>>()?;
            if mapped.iter().any(|v| vars.contains(&v.as_str())) {
                steps.push(crate::syncplan::SyncStep {
                    destination_id: format!("env_export:{}", export.id),
                    destination_name: export.path.clone(),
                    destination_kind: "env_export".into(),
                    secret_name: mapped.join(","),
                    environment: String::new(),
                    action: crate::syncplan::ACTION_REEXPORT.into(),
                    status: crate::syncplan::STEP_PLANNED.into(),
                    detail: "re-write the exported file with the new value".into(),
                    validation: "file content hash comparison".into(),
                    rollback_available: from_version.is_some(),
                    executed_at: None,
                    verified_at: None,
                    rolled_back_at: None,
                });
            }
        }
        let plan_id = crate::syncplan::insert_plan(
            &self.conn,
            &cred.id,
            from_version,
            to_version,
            note,
            &steps,
        )?;
        audit::record(
            &self.conn,
            "sync_plan_created",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!("plan={plan_id} steps={}", steps.len()),
        )?;
        self.sync_plan_get(&plan_id)
    }

    /// Load a plan with display fields and affected projects recomputed.
    pub fn sync_plan_get(&self, plan_id: &str) -> Result<crate::syncplan::SyncPlan> {
        let stored = crate::syncplan::load_plan(&self.conn, plan_id)?;
        self.hydrate_plan(stored)
    }

    fn hydrate_plan(
        &self,
        stored: crate::syncplan::StoredPlan,
    ) -> Result<crate::syncplan::SyncPlan> {
        let cred =
            self.credential_row_by_id(&stored.credential_id)?
                .ok_or(CoreError::NotFound {
                    kind: "credential",
                    ident: stored.credential_id.clone(),
                })?;
        let project = self.project_row_by_ident(&cred.project_id)?;
        let mut affected: Vec<String> = vec![project.name.clone()];
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT p.name FROM credentials c JOIN projects p ON p.id = c.project_id
             WHERE c.linked_credential_id = ?1",
        )?;
        let rows = stmt.query_map([&cred.id], |r| r.get::<_, String>(0))?;
        for r in rows {
            let name = r?;
            if !affected.contains(&name) {
                affected.push(name);
            }
        }
        let from_masked: Option<String> = match stored.from_version {
            Some(v) => self
                .conn
                .query_row(
                    "SELECT masked_value FROM credential_versions
                     WHERE credential_id = ?1 AND version = ?2",
                    params![stored.credential_id, v],
                    |r| r.get(0),
                )
                .optional()?,
            None => None,
        };
        let mut manual_steps = Vec::new();
        let steps: Vec<crate::syncplan::SyncStep> = stored
            .steps
            .into_iter()
            .map(|s| {
                let (name, kind) =
                    if let Some(export_id) = s.destination_id.strip_prefix("env_export:") {
                        let path: Option<String> = self
                            .conn
                            .query_row(
                                "SELECT path FROM env_exports WHERE id = ?1",
                                [export_id],
                                |r| r.get(0),
                            )
                            .optional()
                            .ok()
                            .flatten();
                        (
                            path.unwrap_or_else(|| s.destination_id.clone()),
                            "env_export".to_string(),
                        )
                    } else if s.destination_id == "env_mapping" {
                        (
                            "local environment mappings".to_string(),
                            "env_mapping".to_string(),
                        )
                    } else {
                        match crate::destinations::get(&self.conn, &s.destination_id) {
                            Ok(d) => (d.name, d.kind),
                            Err(_) => (
                                format!("{} (removed)", s.destination_id),
                                "removed".to_string(),
                            ),
                        }
                    };
                let (validation, writable) = Self::validation_for_kind(&kind);
                if s.action == crate::syncplan::ACTION_MANUAL {
                    manual_steps.push(format!(
                        "update '{}' at destination '{name}' by hand",
                        s.secret_name
                    ));
                }
                crate::syncplan::SyncStep {
                    destination_id: s.destination_id,
                    destination_name: name,
                    destination_kind: kind.clone(),
                    secret_name: s.secret_name,
                    environment: s.environment,
                    action: s.action.clone(),
                    status: s.status,
                    detail: s.detail,
                    validation: match (s.action.as_str(), kind.as_str()) {
                        ("none", _) => "not needed (resolved at injection time)".to_string(),
                        ("reexport", _) => "file content hash comparison".to_string(),
                        _ => validation,
                    },
                    rollback_available: stored.from_version.is_some()
                        && writable
                        && s.action == crate::syncplan::ACTION_WRITE
                        || (s.action == crate::syncplan::ACTION_REEXPORT
                            && stored.from_version.is_some()),
                    executed_at: s.executed_at,
                    verified_at: s.verified_at,
                    rolled_back_at: s.rolled_back_at,
                }
            })
            .collect();
        let current_version = self.value_version_of(&stored.credential_id)?;
        let status = if stored.status == crate::syncplan::PLAN_PLANNED
            && current_version != stored.to_version
        {
            crate::syncplan::PLAN_STALE.to_string()
        } else {
            stored.status
        };
        Ok(crate::syncplan::SyncPlan {
            id: stored.id,
            credential_id: stored.credential_id,
            credential_name: cred.name,
            project_name: project.name,
            from_version: stored.from_version,
            from_masked,
            to_version: stored.to_version,
            to_masked: cred.masked_value,
            created_at: stored.created_at,
            status,
            note: stored.note,
            affected_projects: affected,
            manual_steps,
            steps,
        })
    }

    pub fn sync_plans(
        &self,
        credential: Option<&str>,
        limit: u32,
    ) -> Result<Vec<crate::syncplan::SyncPlan>> {
        let credential_id = match credential {
            Some(selector) => Some(self.resolve_credential(selector)?.id),
            None => None,
        };
        let stored = crate::syncplan::list_plans(&self.conn, credential_id.as_deref(), limit)?;
        stored.into_iter().map(|p| self.hydrate_plan(p)).collect()
    }

    /// Execute a plan's pending (or previously failed — retry) steps.
    /// Reauthentication-gated; never runs automatically.
    pub fn sync_plan_execute(
        &mut self,
        plan_id: &str,
        only_destination: Option<&str>,
        master_password: &SecretString,
        http: &dyn crate::http::HttpClient,
        runner: &dyn crate::destinations::CommandRunner,
    ) -> Result<crate::syncplan::SyncPlan> {
        self.verify_master_password(master_password)?;
        let stored = crate::syncplan::load_plan(&self.conn, plan_id)?;
        let current_version = self.value_version_of(&stored.credential_id)?;
        if current_version != stored.to_version {
            crate::syncplan::update_plan_status(&self.conn, plan_id, crate::syncplan::PLAN_STALE)?;
            return Err(CoreError::InvalidInput(format!(
                "the credential changed since this plan was created (now v{current_version}, \
                 plan targets v{}); generate a new plan",
                stored.to_version
            )));
        }
        let value = self.decrypt_credential_version(&stored.credential_id, stored.to_version)?;
        let cred =
            self.credential_row_by_id(&stored.credential_id)?
                .ok_or(CoreError::NotFound {
                    kind: "credential",
                    ident: stored.credential_id.clone(),
                })?;
        for step in &stored.steps {
            if let Some(only) = only_destination {
                let matches_dest = step.destination_id == only
                    || crate::destinations::get(&self.conn, &step.destination_id)
                        .map(|d| d.name.eq_ignore_ascii_case(only))
                        .unwrap_or(false);
                if !matches_dest {
                    continue;
                }
            }
            if !matches!(
                step.status.as_str(),
                crate::syncplan::STEP_PLANNED | crate::syncplan::STEP_FAILED
            ) {
                continue;
            }
            if step.action == crate::syncplan::ACTION_MANUAL {
                // A manual step cannot be executed programmatically; mark it
                // skipped (with the reason) instead of failing forever.
                crate::syncplan::update_step(
                    &self.conn,
                    plan_id,
                    &step.destination_id,
                    &step.secret_name,
                    crate::syncplan::STEP_SKIPPED,
                    "manual step — perform it by hand, then verify with `destination drift`",
                )?;
                continue;
            }
            let outcome = self.execute_step(&stored, step, &cred, &value, http, runner);
            match outcome {
                Ok(detail) => crate::syncplan::update_step(
                    &self.conn,
                    plan_id,
                    &step.destination_id,
                    &step.secret_name,
                    crate::syncplan::STEP_EXECUTED,
                    &detail,
                )?,
                Err(e) => crate::syncplan::update_step(
                    &self.conn,
                    plan_id,
                    &step.destination_id,
                    &step.secret_name,
                    crate::syncplan::STEP_FAILED,
                    &e.to_string(),
                )?,
            }
        }
        let refreshed = crate::syncplan::load_plan(&self.conn, plan_id)?;
        let any_failed = refreshed
            .steps
            .iter()
            .any(|s| s.status == crate::syncplan::STEP_FAILED);
        let all_done = refreshed.steps.iter().all(|s| {
            matches!(
                s.status.as_str(),
                crate::syncplan::STEP_EXECUTED | crate::syncplan::STEP_SKIPPED
            )
        });
        let status = if any_failed {
            crate::syncplan::PLAN_PARTIAL
        } else if all_done {
            crate::syncplan::PLAN_EXECUTED
        } else {
            crate::syncplan::PLAN_PLANNED
        };
        crate::syncplan::update_plan_status(&self.conn, plan_id, status)?;
        audit::record(
            &self.conn,
            "sync_plan_executed",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!("plan={plan_id} status={status}"),
        )?;
        self.sync_plan_get(plan_id)
    }

    fn execute_step(
        &self,
        plan: &crate::syncplan::StoredPlan,
        step: &crate::syncplan::StoredStep,
        cred: &CredentialRow,
        value: &SecretString,
        http: &dyn crate::http::HttpClient,
        runner: &dyn crate::destinations::CommandRunner,
    ) -> Result<String> {
        match step.action.as_str() {
            crate::syncplan::ACTION_NONE => {
                Ok("no write needed; mappings resolve the current value".into())
            }
            crate::syncplan::ACTION_MANUAL => Err(CoreError::Unsupported {
                provider: step.destination_id.clone(),
                capability: "write",
                hint: "this step must be performed by hand".into(),
            }),
            crate::syncplan::ACTION_REEXPORT => {
                let export_id = step
                    .destination_id
                    .strip_prefix("env_export:")
                    .ok_or_else(|| CoreError::VaultCorrupted("malformed re-export step"))?;
                self.rewrite_export(export_id, &cred.id, value)
            }
            crate::syncplan::ACTION_WRITE => {
                let dest = crate::destinations::get(&self.conn, &step.destination_id)?;
                let adapter = self.destination_adapter(&dest, http, runner)?;
                let receipt = adapter.write(&step.secret_name, value)?;
                // Verify: read-back where supported, else existence.
                let drift = match adapter.read(&step.secret_name)? {
                    Some(stored_value) if !stored_value.expose().is_empty() => {
                        let stored_fp = reuse::fingerprint(&self.fingerprint_key, &stored_value)?;
                        if stored_fp == cred.fingerprint {
                            "in_sync"
                        } else {
                            "drifted"
                        }
                    }
                    _ => match adapter.exists(&step.secret_name)? {
                        Some(true) => "present_unverifiable",
                        Some(false) => "missing",
                        None => "unknown",
                    },
                };
                crate::destinations::record_sync(
                    &self.conn,
                    &cred.id,
                    &dest.id,
                    &step.secret_name,
                    plan.to_version,
                    drift,
                )?;
                crate::syncplan::mark_step_verified(
                    &self.conn,
                    &plan.id,
                    &step.destination_id,
                    &step.secret_name,
                )?;
                if drift == "drifted" {
                    return Err(CoreError::Provider(format!(
                        "wrote '{}' but the read-back value does not match",
                        step.secret_name
                    )));
                }
                Ok(format!("{receipt}; verification: {drift}"))
            }
            other => Err(CoreError::InvalidInput(format!(
                "unknown step action '{other}'"
            ))),
        }
    }

    /// Re-write one recorded export file with the given value substituted
    /// for this credential's mapped variables.
    fn rewrite_export(
        &self,
        export_id: &str,
        credential_id: &str,
        value: &SecretString,
    ) -> Result<String> {
        let (path, project_id, recorded_hash): (String, String, String) = self
            .conn
            .query_row(
                "SELECT path, project_id, content_hash FROM env_exports
                 WHERE id = ?1 AND cleaned_at IS NULL",
                [export_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(CoreError::NotFound {
                kind: "export",
                ident: export_id.to_string(),
            })?;
        let path = PathBuf::from(path);
        if !path.exists() {
            return Err(CoreError::InvalidInput(format!(
                "{} no longer exists; clean up the export record",
                path.display()
            )));
        }
        let content = std::fs::read_to_string(&path)?;
        if crate::envgov::content_hash(&content) != recorded_hash {
            return Err(CoreError::InvalidInput(format!(
                "{} changed since it was exported; refusing to rewrite it — \
                 re-export explicitly (`env export --overwrite`) if intended",
                path.display()
            )));
        }
        let mut doc = crate::envfile::EnvDocument::parse(&content);
        let vars: Vec<String> = self
            .conn
            .prepare(
                "SELECT env_var FROM credential_env_mappings
                 WHERE credential_id = ?1 AND project_id = ?2",
            )?
            .query_map(params![credential_id, project_id], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<std::result::Result<_, _>>()?;
        let mut updated = 0;
        for var in &vars {
            if doc.get(var).is_some() {
                doc.set(var, value.clone());
                updated += 1;
            }
        }
        let rendered = doc.render();
        crate::envgov::atomic_write(&path, &rendered)?;
        self.conn.execute(
            "UPDATE env_exports SET content_hash = ?1 WHERE id = ?2",
            params![crate::envgov::content_hash(&rendered), export_id],
        )?;
        Ok(format!(
            "re-exported {updated} variable(s) into {}",
            path.display()
        ))
    }

    /// Roll executed steps back to the plan's `from_version` where supported.
    pub fn sync_plan_rollback(
        &mut self,
        plan_id: &str,
        only_destination: Option<&str>,
        master_password: &SecretString,
        http: &dyn crate::http::HttpClient,
        runner: &dyn crate::destinations::CommandRunner,
    ) -> Result<crate::syncplan::SyncPlan> {
        self.verify_master_password(master_password)?;
        let stored = crate::syncplan::load_plan(&self.conn, plan_id)?;
        let from_version = stored.from_version.ok_or_else(|| {
            CoreError::InvalidInput("this plan has no previous version to roll back to".into())
        })?;
        let old_value = self.decrypt_credential_version(&stored.credential_id, from_version)?;
        let cred =
            self.credential_row_by_id(&stored.credential_id)?
                .ok_or(CoreError::NotFound {
                    kind: "credential",
                    ident: stored.credential_id.clone(),
                })?;
        let mut rolled_back_any = false;
        for step in &stored.steps {
            if let Some(only) = only_destination {
                let matches_dest = step.destination_id == only
                    || crate::destinations::get(&self.conn, &step.destination_id)
                        .map(|d| d.name.eq_ignore_ascii_case(only))
                        .unwrap_or(false);
                if !matches_dest {
                    continue;
                }
            }
            if step.status != crate::syncplan::STEP_EXECUTED {
                continue;
            }
            let outcome: Result<String> = match step.action.as_str() {
                crate::syncplan::ACTION_WRITE => {
                    let dest = crate::destinations::get(&self.conn, &step.destination_id)?;
                    let adapter = self.destination_adapter(&dest, http, runner)?;
                    let receipt = adapter.write(&step.secret_name, &old_value)?;
                    crate::destinations::record_sync(
                        &self.conn,
                        &cred.id,
                        &dest.id,
                        &step.secret_name,
                        from_version,
                        "rolled_back",
                    )?;
                    Ok(receipt)
                }
                crate::syncplan::ACTION_REEXPORT => {
                    let export_id = step
                        .destination_id
                        .strip_prefix("env_export:")
                        .ok_or_else(|| CoreError::VaultCorrupted("malformed re-export step"))?;
                    self.rewrite_export(export_id, &cred.id, &old_value)
                }
                _ => Ok("nothing to roll back".into()),
            };
            match outcome {
                Ok(detail) => {
                    rolled_back_any = true;
                    crate::syncplan::update_step(
                        &self.conn,
                        plan_id,
                        &step.destination_id,
                        &step.secret_name,
                        crate::syncplan::STEP_ROLLED_BACK,
                        &format!("rolled back to v{from_version}: {detail}"),
                    )?
                }
                Err(e) => crate::syncplan::update_step(
                    &self.conn,
                    plan_id,
                    &step.destination_id,
                    &step.secret_name,
                    crate::syncplan::STEP_FAILED,
                    &format!("rollback failed: {e}"),
                )?,
            }
        }
        // Never report a rollback that did not happen: the plan status only
        // changes when at least one step actually rolled back.
        if !rolled_back_any {
            return Err(CoreError::InvalidInput(
                "no executed step matched — nothing was rolled back (check the \
                 --destination filter and step statuses)"
                    .into(),
            ));
        }
        crate::syncplan::update_plan_status(
            &self.conn,
            plan_id,
            crate::syncplan::PLAN_ROLLED_BACK,
        )?;
        audit::record(
            &self.conn,
            "sync_plan_rolled_back",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!("plan={plan_id} to_version={from_version}"),
        )?;
        self.sync_plan_get(plan_id)
    }

    /// Check every attachment (optionally one credential's) for drift.
    pub fn destination_drift_check(
        &self,
        credential: Option<&str>,
        http: &dyn crate::http::HttpClient,
        runner: &dyn crate::destinations::CommandRunner,
    ) -> Result<Vec<crate::destinations::Attachment>> {
        let attachments = self.destination_attachments(credential)?;
        for attachment in &attachments {
            let Ok(dest) = crate::destinations::get(&self.conn, &attachment.destination_id) else {
                continue;
            };
            let Ok(adapter) = self.destination_adapter(&dest, http, runner) else {
                continue;
            };
            let cred_fp: Vec<u8> = self.conn.query_row(
                "SELECT fingerprint FROM credentials WHERE id = ?1",
                [&attachment.credential_id],
                |r| r.get(0),
            )?;
            let drift = match adapter.read(&attachment.secret_name) {
                Ok(Some(value)) if !value.expose().is_empty() => {
                    let fp = reuse::fingerprint(&self.fingerprint_key, &value)?;
                    if fp == cred_fp {
                        "in_sync"
                    } else {
                        "drifted"
                    }
                }
                Ok(_) => match adapter.exists(&attachment.secret_name) {
                    Ok(Some(true)) => "present_unverifiable",
                    Ok(Some(false)) => "missing",
                    _ => "unknown",
                },
                Err(_) => "unknown",
            };
            crate::destinations::record_verify(
                &self.conn,
                &attachment.credential_id,
                &attachment.destination_id,
                &attachment.secret_name,
                drift,
            )?;
        }
        self.destination_attachments(credential)
    }

    // ------------------------------------------------------------------
    // Credential rotation (docs/decisions/0013)
    // ------------------------------------------------------------------

    /// True when the provider can CREATE a replacement key via API and an
    /// administrative connection is available to do it.
    fn rotation_mode_for(&self, provider: &str) -> Result<(&'static str, String)> {
        let manifest = crate::providers::find(provider);
        let manage_url = manifest
            .as_ref()
            .map(|m| m.manage_url.clone())
            .unwrap_or_default();
        let api_create = manifest
            .as_ref()
            .map(|m| {
                matches!(
                    m.capabilities.create_credential.support,
                    crate::providers::SupportLevel::Implemented
                )
            })
            .unwrap_or(false);
        let has_admin = self.provider_admin_secret(provider).is_ok();
        if api_create && has_admin {
            Ok((crate::rotation::MODE_API, manage_url))
        } else {
            Ok((crate::rotation::MODE_MANUAL, manage_url))
        }
    }

    /// Build a rotation dry run: capability check, destination inspection,
    /// mode determination. Writes nothing anywhere and changes no state
    /// beyond recording the plan itself.
    #[allow(clippy::too_many_arguments)]
    pub fn rotation_plan(
        &self,
        credential: &str,
        grace_minutes: i64,
        provider_project_id: Option<&str>,
        old_provider_key_id: Option<&str>,
        note: &str,
    ) -> Result<RotationView> {
        let cred = self.resolve_credential(credential)?;
        if cred.linked_credential_id.is_some() {
            return Err(CoreError::InvalidInput(
                "this record is a reference; rotate the credential it points to".into(),
            ));
        }
        if !(0..=60 * 24 * 90).contains(&grace_minutes) {
            return Err(CoreError::InvalidInput(
                "the grace period must be between 0 minutes and 90 days".into(),
            ));
        }
        let (mode, manage_url) = self.rotation_mode_for(&cred.provider)?;
        // Old provider-side key id: explicit option, else a confirmed link.
        let link_count: i64 = self.conn.query_row(
            "SELECT count(*) FROM provider_key_links WHERE provider = ?1 AND credential_id = ?2",
            params![cred.provider, cred.id],
            |r| r.get(0),
        )?;
        let old_key_id: Option<String> = match old_provider_key_id {
            Some(id) => Some(id.to_string()),
            // Deterministic: the NEWEST link is the currently-live key
            // (older links are kept for historical usage attribution).
            None => self
                .conn
                .query_row(
                    "SELECT provider_api_key_id FROM provider_key_links
                     WHERE provider = ?1 AND credential_id = ?2
                     ORDER BY created_at DESC LIMIT 1",
                    params![cred.provider, cred.id],
                    |r| r.get(0),
                )
                .optional()?,
        };
        // Provider project for API creation: explicit option, else derived
        // from the linked old key's cached metadata.
        let project_id: Option<String> = match provider_project_id {
            Some(p) => Some(p.to_string()),
            None => match &old_key_id {
                Some(key) => self
                    .conn
                    .query_row(
                        "SELECT provider_project_id FROM provider_side_keys
                         WHERE provider = ?1 AND api_key_id = ?2",
                        params![cred.provider, key],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten(),
                None => None,
            },
        };
        let manifest = crate::providers::find(&cred.provider);
        let can_disable = manifest
            .as_ref()
            .map(|m| {
                matches!(
                    m.capabilities.disable_credential.support,
                    crate::providers::SupportLevel::Implemented
                )
            })
            .unwrap_or(false);
        let can_revoke = manifest
            .as_ref()
            .map(|m| {
                matches!(
                    m.capabilities.revoke_credential.support,
                    crate::providers::SupportLevel::Implemented
                )
            })
            .unwrap_or(false);
        let mut manual = Vec::new();
        if mode == crate::rotation::MODE_MANUAL {
            manual.push(format!(
                "create the replacement key yourself at {manage_url}, then run \
                 `rotation provide-key` with the new value"
            ));
        }
        if link_count > 1 && old_provider_key_id.is_none() {
            manual.push(format!(
                "{link_count} provider-side key ids are linked to this credential (older \
                 links are kept for usage history); the NEWEST was selected as the old \
                 key — verify with `provider list-keys` or pass --old-key-id explicitly"
            ));
        }
        if old_key_id.is_none() && (can_disable || can_revoke) {
            manual.push(
                "no provider-side key id is linked for the OLD key; link one \
                 (`provider link`) or pass --old-key-id, otherwise disabling/revoking \
                 the old key stays manual"
                    .to_string(),
            );
        }
        if !can_disable && !can_revoke {
            manual.push(format!(
                "this provider has no API disable/revoke — after the grace period, \
                 revoke the old key yourself at {manage_url} and run \
                 `rotation complete-manual`"
            ));
        }
        let id = crate::rotation::insert(
            &self.conn,
            &cred.id,
            &cred.provider,
            mode,
            note,
            grace_minutes,
            old_key_id.as_deref(),
            project_id.as_deref(),
            &manual.join("\n"),
        )?;
        audit::record(
            &self.conn,
            "rotation_planned",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!("rotation={id} mode={mode}"),
        )?;
        self.rotation_get(&id)
    }

    /// Approve a planned rotation (reauthentication + explicit user action).
    pub fn rotation_approve(
        &self,
        id: &str,
        master_password: &SecretString,
    ) -> Result<RotationView> {
        self.verify_master_password(master_password)?;
        let rot = crate::rotation::load(&self.conn, id)?;
        if rot.state != crate::rotation::PLANNED {
            return Err(CoreError::InvalidInput(format!(
                "rotation {id} is '{}', not awaiting approval",
                rot.state
            )));
        }
        let other_active: i64 = self.conn.query_row(
            "SELECT count(*) FROM rotations WHERE credential_id = ?1 AND id != ?2
             AND state NOT IN (?3, ?4, ?5, ?6)",
            params![
                rot.credential_id,
                id,
                crate::rotation::COMPLETED,
                crate::rotation::ROLLED_BACK,
                crate::rotation::FAILED,
                crate::rotation::PLANNED
            ],
            |r| r.get(0),
        )?;
        if other_active > 0 {
            return Err(CoreError::InvalidInput(
                "another rotation for this credential is already in flight; finish, roll \
                 back, or cancel it first"
                    .into(),
            ));
        }
        crate::rotation::set_field(&self.conn, id, "approved_at", Some(&clock::now_rfc3339()))?;
        crate::rotation::set_state(
            &self.conn,
            id,
            crate::rotation::PLANNED,
            crate::rotation::APPROVED,
            "user approved",
        )?;
        let cred = self
            .credential_row_by_id(&rot.credential_id)?
            .ok_or(CoreError::NotFound {
                kind: "credential",
                ident: rot.credential_id.clone(),
            })?;
        audit::record(
            &self.conn,
            "rotation_approved",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!("rotation={id}"),
        )?;
        self.rotation_get(id)
    }

    /// Advance a rotation as far as it can go right now. Idempotent: every
    /// step re-checks recorded state, so calling again after a crash, a
    /// failure, or a restart continues where it left off. Returns with
    /// `waiting_on` set when the workflow needs time or user action.
    #[allow(clippy::too_many_arguments)]
    pub fn rotation_advance(
        &mut self,
        id: &str,
        master_password: &SecretString,
        http: &dyn crate::http::HttpClient,
        runner: &dyn crate::destinations::CommandRunner,
        provide_value: Option<SecretString>,
        acknowledge_continued_use: bool,
    ) -> Result<RotationView> {
        self.verify_master_password(master_password)?;
        let mut provide_value = provide_value;
        // A bounded loop: each iteration performs at most one step.
        for _ in 0..12 {
            let rot = crate::rotation::load(&self.conn, id)?;
            match rot.state.as_str() {
                crate::rotation::PLANNED => {
                    return Err(CoreError::InvalidInput(
                        "the rotation is a dry run; approve it first (`rotation approve`)".into(),
                    ));
                }
                crate::rotation::APPROVED => {
                    if rot.mode == crate::rotation::MODE_API {
                        if provide_value.is_some() {
                            return Err(CoreError::InvalidInput(
                                "this rotation creates the replacement via the provider API; \
                                 a provided value is not applicable"
                                    .into(),
                            ));
                        }
                        // CAS claim BEFORE the provider call: a concurrent
                        // advance cannot also enter creation.
                        crate::rotation::set_state(
                            &self.conn,
                            id,
                            crate::rotation::APPROVED,
                            crate::rotation::CREATING_REPLACEMENT,
                            "claimed for provider-side key creation",
                        )?;
                    } else if let Some(value) = provide_value.take() {
                        let detail =
                            self.rotation_store_replacement(&rot, master_password, value)?;
                        crate::rotation::set_state(
                            &self.conn,
                            id,
                            crate::rotation::APPROVED,
                            crate::rotation::REPLACEMENT_STORED,
                            &detail,
                        )?;
                    } else {
                        crate::rotation::set_state(
                            &self.conn,
                            id,
                            crate::rotation::APPROVED,
                            crate::rotation::AWAITING_MANUAL_KEY,
                            "waiting for the manually created replacement key",
                        )?;
                        return self.rotation_get(id);
                    }
                }
                crate::rotation::CREATING_REPLACEMENT => {
                    // Orphan guard: a key was created at the provider but the
                    // store never completed (crash in between). Creating
                    // again would orphan a live key whose value is shown
                    // exactly once — surface it instead.
                    if rot.new_provider_key_id.is_some() && rot.new_version.is_none() {
                        crate::rotation::record_error(
                            &self.conn,
                            id,
                            &format!(
                                "a provider key ({}) was created but its value was never \
                                 stored (it is shown only once, at creation). Revoke that \
                                 key at the provider, clear it with `rotation cancel`, and \
                                 plan again",
                                rot.new_provider_key_id.as_deref().unwrap_or("?")
                            ),
                        )?;
                        return self.rotation_get(id);
                    }
                    // Claim the creation via CAS BEFORE the provider HTTP call.
                    // Only the process that wins this transition performs the
                    // (non-idempotent) create; a concurrent advance sees the
                    // row already moved and stops with "changed concurrently"
                    // rather than creating a second live key.
                    crate::rotation::set_state(
                        &self.conn,
                        id,
                        crate::rotation::CREATING_REPLACEMENT,
                        crate::rotation::CREATING_IN_PROGRESS,
                        "claimed the provider-side key creation",
                    )?;
                }
                crate::rotation::CREATING_IN_PROGRESS => {
                    // Same orphan guard for the crash-after-create-before-store
                    // window while holding the transient state.
                    if rot.new_provider_key_id.is_some() && rot.new_version.is_none() {
                        crate::rotation::record_error(
                            &self.conn,
                            id,
                            &format!(
                                "a provider key ({}) was created but its value was never \
                                 stored (it is shown only once, at creation). Revoke that \
                                 key at the provider, clear it with `rotation cancel`, and \
                                 plan again",
                                rot.new_provider_key_id.as_deref().unwrap_or("?")
                            ),
                        )?;
                        return self.rotation_get(id);
                    }
                    match self.rotation_create_replacement(&rot, master_password, http) {
                        Ok(detail) => crate::rotation::set_state(
                            &self.conn,
                            id,
                            crate::rotation::CREATING_IN_PROGRESS,
                            crate::rotation::REPLACEMENT_STORED,
                            &detail,
                        )?,
                        Err(e) => {
                            crate::rotation::record_error(&self.conn, id, &e.to_string())?;
                            return self.rotation_get(id);
                        }
                    }
                }
                crate::rotation::AWAITING_MANUAL_KEY => {
                    let Some(value) = provide_value.take() else {
                        return self.rotation_get(id);
                    };
                    let detail = self.rotation_store_replacement(&rot, master_password, value)?;
                    crate::rotation::set_state(
                        &self.conn,
                        id,
                        crate::rotation::AWAITING_MANUAL_KEY,
                        crate::rotation::REPLACEMENT_STORED,
                        &detail,
                    )?;
                }
                crate::rotation::REPLACEMENT_STORED => {
                    let plan =
                        self.sync_plan_create(&rot.credential_id, &format!("rotation {id}"))?;
                    crate::rotation::set_field(&self.conn, id, "sync_plan_id", Some(&plan.id))?;
                    crate::rotation::set_state(
                        &self.conn,
                        id,
                        crate::rotation::REPLACEMENT_STORED,
                        crate::rotation::UPDATING_DESTINATIONS,
                        &format!(
                            "sync plan {} created ({} step(s))",
                            plan.id,
                            plan.steps.len()
                        ),
                    )?;
                }
                crate::rotation::UPDATING_DESTINATIONS => {
                    let plan_id = rot
                        .sync_plan_id
                        .clone()
                        .ok_or(CoreError::VaultCorrupted("rotation lost its sync plan id"))?;
                    match self.sync_plan_execute(&plan_id, None, master_password, http, runner) {
                        Ok(plan) if plan.status == crate::syncplan::PLAN_EXECUTED => {
                            crate::rotation::set_state(
                                &self.conn,
                                id,
                                crate::rotation::UPDATING_DESTINATIONS,
                                crate::rotation::DESTINATIONS_VERIFIED,
                                "every destination step executed and verified",
                            )?;
                        }
                        Ok(plan) => {
                            crate::rotation::record_error(
                                &self.conn,
                                id,
                                &format!(
                                    "destination sync is '{}'; fix the failing destination and \
                                     advance again (only failed steps re-run)",
                                    plan.status
                                ),
                            )?;
                            return self.rotation_get(id);
                        }
                        Err(e) => {
                            crate::rotation::record_error(&self.conn, id, &e.to_string())?;
                            return self.rotation_get(id);
                        }
                    }
                }
                crate::rotation::DESTINATIONS_VERIFIED => {
                    // The value being validated must be THIS rotation's
                    // replacement — a concurrent manual replacement must not
                    // be able to arm the destructive steps.
                    let current = self.value_version_of(&rot.credential_id)?;
                    if Some(current) != rot.new_version {
                        crate::rotation::record_error(
                            &self.conn,
                            id,
                            &format!(
                                "the credential changed outside this rotation (now v{current}, \
                                 the rotation stored v{}); refusing to continue — roll back \
                                 or plan a fresh rotation",
                                rot.new_version.unwrap_or(-1)
                            ),
                        )?;
                        return self.rotation_get(id);
                    }
                    // Validate the NEW value against the provider before any
                    // destructive step becomes possible.
                    match self.validate_credential(&rot.credential_id, http) {
                        Ok(result) if result.valid => {
                            crate::rotation::mark_new_value_validated(&self.conn, id)?;
                            let ends = clock::rfc3339_after(std::time::Duration::from_secs(
                                (rot.grace_minutes.max(0) as u64) * 60,
                            ));
                            crate::rotation::set_field(
                                &self.conn,
                                id,
                                "grace_ends_at",
                                Some(&ends),
                            )?;
                            crate::rotation::set_state(
                                &self.conn,
                                id,
                                crate::rotation::DESTINATIONS_VERIFIED,
                                crate::rotation::GRACE_PERIOD,
                                &format!(
                                    "new value validated ({}); grace/overlap until {ends}",
                                    result.detail
                                ),
                            )?;
                        }
                        Ok(result) => {
                            crate::rotation::record_error(
                                &self.conn,
                                id,
                                &format!(
                                    "the NEW value failed validation ({}); the old key is \
                                     untouched — retry, or roll back",
                                    result.detail
                                ),
                            )?;
                            return self.rotation_get(id);
                        }
                        Err(e) => {
                            crate::rotation::record_error(&self.conn, id, &e.to_string())?;
                            return self.rotation_get(id);
                        }
                    }
                }
                crate::rotation::GRACE_PERIOD => {
                    if let Some(ends) = &rot.grace_ends_at {
                        // Parse-and-compare: RFC 3339 strings with different
                        // fractional widths do not always order textually.
                        let ends_at = clock::parse_rfc3339(ends)?;
                        if clock::now() < ends_at {
                            return self.rotation_get(id);
                        }
                    }
                    // Continued-use detection where provider data exists.
                    if let (Some(old_key), false) =
                        (&rot.old_provider_key_id, acknowledge_continued_use)
                    {
                        let since = rot
                            .approved_at
                            .clone()
                            .unwrap_or_else(|| rot.created_at.clone());
                        // Daily buckets: compare against the approval DAY so
                        // the bucket containing the approval moment counts
                        // (false positives possible; that is the safe side).
                        let (used, fresh): (i64, i64) = self.conn.query_row(
                            "SELECT
                                 count(*) FILTER (WHERE window_start >= date(?3)),
                                 count(*) FILTER (WHERE collected_at >= ?3)
                             FROM usage_snapshots
                             WHERE provider = ?1 AND provider_api_key_id = ?2
                               AND source != 'manual'",
                            params![rot.provider, old_key, since],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )?;
                        if used > 0 {
                            crate::rotation::record_error(
                                &self.conn,
                                id,
                                "provider usage data shows activity attributed to the OLD key \
                                 on/after the approval day (daily buckets — same-day rows may \
                                 predate the switch). Verify every consumer moved, run \
                                 `provider sync` for fresh data, then advance with \
                                 --acknowledge-continued-use",
                            )?;
                            return self.rotation_get(id);
                        }
                        if fresh == 0 {
                            // Zero rows is only meaningful with fresh data;
                            // say so rather than implying "no use".
                            crate::rotation::record_event_note(
                                &self.conn,
                                id,
                                "continued-use could not be assessed: no provider usage data \
                                 was collected after approval (run `provider sync` for a real \
                                 signal)",
                            )?;
                        }
                    }
                    if !self.rotation_disable_old(&rot, id, http)? {
                        // The disable call failed (error recorded, retryable).
                        return self.rotation_get(id);
                    }
                }
                crate::rotation::OLD_DISABLED => {
                    if !rot.new_value_validated {
                        crate::rotation::record_error(
                            &self.conn,
                            id,
                            "refusing to revoke: the new value was never validated",
                        )?;
                        return self.rotation_get(id);
                    }
                    match self.rotation_revoke_old(&rot, id, http) {
                        Ok(true) => {
                            self.rotation_complete(&rot, id)?;
                            return self.rotation_get(id);
                        }
                        Ok(false) => return self.rotation_get(id), // manual_required
                        Err(e) => {
                            crate::rotation::record_error(&self.conn, id, &e.to_string())?;
                            return self.rotation_get(id);
                        }
                    }
                }
                _ => return self.rotation_get(id),
            }
        }
        self.rotation_get(id)
    }

    /// API-mode replacement: create at the provider, store encrypted, link.
    fn rotation_create_replacement(
        &mut self,
        rot: &crate::rotation::Rotation,
        master_password: &SecretString,
        http: &dyn crate::http::HttpClient,
    ) -> Result<String> {
        // Idempotency guard: if a new version was already stored (crash after
        // storing, before the state write), do not create a second key.
        if rot.new_version.is_some() {
            return Ok("replacement already stored (recovered)".into());
        }
        let admin = self.provider_admin_secret(&rot.provider)?;
        let cred = self
            .credential_row_by_id(&rot.credential_id)?
            .ok_or(CoreError::NotFound {
                kind: "credential",
                ident: rot.credential_id.clone(),
            })?;
        let connector = self.connector_for(&rot.provider)?;
        let created = connector.create_credential(
            http,
            &admin,
            &crate::connectors::CreateParams {
                name: format!("api-tracker-rotation-{}", &rot.id[..8]),
                provider_project_id: rot.provider_project_id.clone(),
            },
        )?;
        let detail = created.detail.clone();
        if let Some(key_id) = &created.provider_key_id {
            crate::rotation::set_field(&self.conn, &rot.id, "new_provider_key_id", Some(key_id))?;
            self.cache_created_key(&rot.provider, key_id, &created)?;
        }
        let stored = self.rotation_store_replacement(rot, master_password, created.value)?;
        // The rotation itself is the user's confirmation for linking the new
        // provider-side key id to this credential.
        if let Some(key_id) = &created.provider_key_id {
            let _ = self.provider_link_key(&rot.provider, key_id, &cred.id);
        }
        Ok(format!("{detail}; {stored}"))
    }

    /// Store the replacement value (retaining the old version) and record
    /// old/new version numbers on the rotation.
    fn rotation_store_replacement(
        &mut self,
        rot: &crate::rotation::Rotation,
        master_password: &SecretString,
        value: SecretString,
    ) -> Result<String> {
        // Idempotency: a crash between store and the state write must not
        // store (and version-shift) a second time on replay.
        let fresh = crate::rotation::load(&self.conn, &rot.id)?;
        if fresh.new_version.is_some() {
            return Ok("replacement already stored (recovered)".into());
        }
        if value.expose().trim().is_empty() {
            return Err(CoreError::InvalidInput(
                "the replacement value must not be empty".into(),
            ));
        }
        let old_version = self.value_version_of(&rot.credential_id)?;
        let (cred, _warnings) =
            self.replace_credential_value(&rot.credential_id, master_password, value)?;
        let new_version = self.value_version_of(&cred.id)?;
        crate::rotation::set_versions(&self.conn, &rot.id, Some(old_version), new_version)?;
        Ok(format!(
            "replacement stored encrypted (v{old_version} retained → v{new_version})"
        ))
    }

    /// Disable the old key where the provider supports it; otherwise move on
    /// honestly (OpenAI/Supabase have no disable state). Returns whether the
    /// state advanced (false = failed, error recorded, retryable).
    fn rotation_disable_old(
        &mut self,
        rot: &crate::rotation::Rotation,
        id: &str,
        http: &dyn crate::http::HttpClient,
    ) -> Result<bool> {
        let can_disable = crate::providers::find(&rot.provider)
            .map(|m| {
                matches!(
                    m.capabilities.disable_credential.support,
                    crate::providers::SupportLevel::Implemented
                )
            })
            .unwrap_or(false);
        match (&rot.old_provider_key_id, can_disable) {
            (Some(old_key), true) => {
                let admin = self.provider_admin_secret(&rot.provider)?;
                let connector = self.connector_for(&rot.provider)?;
                match connector.disable_credential(
                    http,
                    &admin,
                    rot.provider_project_id.as_deref(),
                    old_key,
                ) {
                    Ok(detail) => {
                        crate::rotation::set_field(
                            &self.conn,
                            id,
                            "old_disabled_at",
                            Some(&clock::now_rfc3339()),
                        )?;
                        crate::rotation::set_state(
                            &self.conn,
                            id,
                            crate::rotation::GRACE_PERIOD,
                            crate::rotation::OLD_DISABLED,
                            &format!("old key disabled: {detail}"),
                        )?;
                    }
                    Err(e) => {
                        crate::rotation::record_error(&self.conn, id, &e.to_string())?;
                        return Ok(false);
                    }
                }
            }
            _ => {
                crate::rotation::set_state(
                    &self.conn,
                    id,
                    crate::rotation::GRACE_PERIOD,
                    crate::rotation::OLD_DISABLED,
                    "provider has no separate disable step (or no key id); proceeding to \
                     revocation",
                )?;
            }
        }
        Ok(true)
    }

    /// Revoke the old key. Returns Ok(true) when revoked, Ok(false) when the
    /// workflow must wait for manual action.
    fn rotation_revoke_old(
        &mut self,
        rot: &crate::rotation::Rotation,
        id: &str,
        http: &dyn crate::http::HttpClient,
    ) -> Result<bool> {
        let can_revoke = crate::providers::find(&rot.provider)
            .map(|m| {
                matches!(
                    m.capabilities.revoke_credential.support,
                    crate::providers::SupportLevel::Implemented
                )
            })
            .unwrap_or(false);
        match (&rot.old_provider_key_id, can_revoke) {
            (Some(old_key), true) => {
                let admin = self.provider_admin_secret(&rot.provider)?;
                let connector = self.connector_for(&rot.provider)?;
                // A durable marker BEFORE the call: if the process dies after
                // the provider deleted the key but before we recorded it, the
                // retry can distinguish "already deleted by us" from "wrong
                // key id" when the provider answers 404. Only an attempt with
                // NO recorded outcome counts (the crash window) — an attempt
                // that concluded in a not-found error must not convert a
                // later 404 into success.
                let attempted_before = crate::rotation::events(&self.conn, id)?
                    .last()
                    .map(|e| e.detail.starts_with("attempting revocation of old key"))
                    .unwrap_or(false);
                crate::rotation::record_event_note(
                    &self.conn,
                    id,
                    &format!("attempting revocation of old key {old_key}"),
                )?;
                let detail = match connector.revoke_credential(
                    http,
                    &admin,
                    rot.provider_project_id.as_deref(),
                    old_key,
                ) {
                    Ok(detail) => detail,
                    Err(CoreError::NotFound { .. }) if attempted_before => {
                        format!(
                            "the provider no longer knows key {old_key}; a prior recorded \
                             attempt makes this a completed retry"
                        )
                    }
                    Err(CoreError::NotFound { .. }) => {
                        crate::rotation::record_error(
                            &self.conn,
                            id,
                            &format!(
                                "the provider says key {old_key} does not exist — a wrong key \
                                 id or project would look exactly like this. Verify with \
                                 `provider list-keys` before retrying; nothing was marked \
                                 revoked"
                            ),
                        )?;
                        return Ok(false);
                    }
                    Err(e) => return Err(e),
                };
                crate::rotation::set_field(
                    &self.conn,
                    id,
                    "old_revoked_at",
                    Some(&clock::now_rfc3339()),
                )?;
                crate::rotation::clear_error(&self.conn, id)?;
                crate::rotation::record_event_note(
                    &self.conn,
                    id,
                    &format!("old key revoked: {detail}"),
                )?;
                Ok(true)
            }
            _ => {
                let manage = crate::providers::find(&rot.provider)
                    .map(|m| m.manage_url.clone())
                    .unwrap_or_default();
                crate::rotation::set_state(
                    &self.conn,
                    id,
                    crate::rotation::OLD_DISABLED,
                    crate::rotation::MANUAL_REQUIRED,
                    &format!(
                        "revoke the old key yourself at {manage}, then run \
                         `rotation complete-manual {id}`"
                    ),
                )?;
                Ok(false)
            }
        }
    }

    fn rotation_complete(&self, rot: &crate::rotation::Rotation, id: &str) -> Result<()> {
        crate::rotation::set_state(
            &self.conn,
            id,
            crate::rotation::OLD_DISABLED,
            crate::rotation::COMPLETED,
            "rotation completed",
        )?;
        crate::rotation::schedule_mark_completed(&self.conn, &rot.credential_id, id)?;
        let cred = self.credential_row_by_id(&rot.credential_id)?;
        audit::record(
            &self.conn,
            "rotation_completed",
            cred.as_ref().map(|c| c.project_id.as_str()),
            Some(&rot.credential_id),
            &format!("rotation={id}"),
        )?;
        Ok(())
    }

    /// The user confirms they performed the remaining manual provider-side
    /// steps (e.g. dashboard revocation). Reauthentication-gated.
    pub fn rotation_complete_manual(
        &self,
        id: &str,
        master_password: &SecretString,
        confirmation_note: &str,
    ) -> Result<RotationView> {
        self.verify_master_password(master_password)?;
        let rot = crate::rotation::load(&self.conn, id)?;
        if !matches!(
            rot.state.as_str(),
            crate::rotation::MANUAL_REQUIRED | crate::rotation::GRACE_PERIOD
        ) {
            return Err(CoreError::InvalidInput(format!(
                "rotation {id} is '{}'; only manual-required (or grace) rotations can be \
                 completed manually",
                rot.state
            )));
        }
        if !rot.new_value_validated {
            return Err(CoreError::InvalidInput(
                "refusing: the new value was never validated against the provider".into(),
            ));
        }
        crate::rotation::set_state(
            &self.conn,
            id,
            &rot.state,
            crate::rotation::COMPLETED,
            &format!("completed after manual provider-side action: {confirmation_note}"),
        )?;
        crate::rotation::schedule_mark_completed(&self.conn, &rot.credential_id, id)?;
        let cred = self.credential_row_by_id(&rot.credential_id)?;
        audit::record(
            &self.conn,
            "rotation_completed",
            cred.as_ref().map(|c| c.project_id.as_str()),
            Some(&rot.credential_id),
            &format!("rotation={id} manual"),
        )?;
        self.rotation_get(id)
    }

    /// Cancel a rotation that has not yet touched anything destructive.
    pub fn rotation_cancel(
        &self,
        id: &str,
        master_password: &SecretString,
    ) -> Result<RotationView> {
        self.verify_master_password(master_password)?;
        let rot = crate::rotation::load(&self.conn, id)?;
        if rot.old_disabled_at.is_some() || rot.old_revoked_at.is_some() {
            return Err(CoreError::InvalidInput(
                "the old key was already disabled/revoked; use rollback or complete manually"
                    .into(),
            ));
        }
        if rot.new_version.is_some() {
            return Err(CoreError::InvalidInput(
                "a replacement was already stored; roll back instead of cancelling".into(),
            ));
        }
        crate::rotation::set_state(
            &self.conn,
            id,
            &rot.state,
            crate::rotation::FAILED,
            "cancelled by the user before any change",
        )?;
        self.rotation_get(id)
    }

    /// Roll a rotation back: destinations to the old version, the vault
    /// value to the old value, re-enable a disabled old key where the
    /// provider supports it, and optionally revoke the key we created.
    #[allow(clippy::too_many_arguments)]
    pub fn rotation_rollback(
        &mut self,
        id: &str,
        master_password: &SecretString,
        http: &dyn crate::http::HttpClient,
        runner: &dyn crate::destinations::CommandRunner,
        revoke_new_key: bool,
    ) -> Result<RotationView> {
        self.verify_master_password(master_password)?;
        let rot = crate::rotation::load(&self.conn, id)?;
        if rot.old_revoked_at.is_some() {
            return Err(CoreError::InvalidInput(
                "the old key was REVOKED — that is irreversible at every current provider. \
                 The new key must stay in service; treat this as forward-fix territory"
                    .into(),
            ));
        }
        // A COMPLETED rotation cannot be rolled back: on the manual path the
        // old key was revoked in the dashboard (we cannot know it is alive),
        // and "un-completing" a rotation would misrepresent history either
        // way. Forward-fix with a fresh rotation instead.
        if matches!(
            rot.state.as_str(),
            crate::rotation::COMPLETED | crate::rotation::ROLLED_BACK
        ) {
            return Err(CoreError::InvalidInput(format!(
                "rotation {id} is '{}'; a finished rotation cannot be rolled back — plan a \
                 fresh rotation instead",
                rot.state
            )));
        }
        let Some(old_version) = rot.old_version else {
            return Err(CoreError::InvalidInput(
                "nothing to roll back: no replacement was stored".into(),
            ));
        };
        // Decrypt the rollback material BEFORE entering ROLLING_BACK, so a
        // missing/pruned version cannot wedge the rotation in that state.
        let current = self.value_version_of(&rot.credential_id)?;
        let old_value = if Some(current) == rot.new_version {
            Some(self.decrypt_credential_version(&rot.credential_id, old_version)?)
        } else {
            None
        };
        crate::rotation::set_state(
            &self.conn,
            id,
            &rot.state,
            crate::rotation::ROLLING_BACK,
            "",
        )?;
        let mut notes: Vec<String> = Vec::new();
        let mut failures = 0usize;
        // 1. Re-enable the old key FIRST where disable is reversible
        //    (Anthropic) — destinations must not be pointed back at a key
        //    that is still disabled.
        if rot.old_disabled_at.is_some() {
            if let Some(old_key) = &rot.old_provider_key_id {
                let admin = self.provider_admin_secret(&rot.provider)?;
                if rot.provider == "anthropic" {
                    match crate::connectors::Anthropic::set_key_status(
                        http, &admin, old_key, "active",
                    ) {
                        Ok(d) => notes.push(format!("old key re-enabled: {d}")),
                        Err(e) => {
                            failures += 1;
                            notes.push(format!("old key re-enable FAILED: {e}"));
                        }
                    }
                }
            }
        }
        // 2. Vault value back to the old version (bumps a fresh version —
        //    the change stays auditable rather than rewriting history).
        match old_value {
            Some(value) => {
                self.replace_credential_value(&rot.credential_id, master_password, value)?;
                notes.push(format!("vault value restored from v{old_version}"));
            }
            None => notes.push(format!(
                "vault value left as-is (v{current} is not the rotation's v{})",
                rot.new_version.unwrap_or(-1)
            )),
        }
        // 3. Destinations back via the rotation's sync plan.
        if let Some(plan_id) = &rot.sync_plan_id {
            match self.sync_plan_rollback(plan_id, None, master_password, http, runner) {
                Ok(_) => notes.push("destinations rolled back".into()),
                Err(e) => {
                    failures += 1;
                    notes.push(format!("destination rollback FAILED: {e}"));
                }
            }
        }
        // 4. Optionally revoke the key this rotation created.
        if revoke_new_key {
            if let Some(new_key) = &rot.new_provider_key_id {
                let admin = self.provider_admin_secret(&rot.provider)?;
                let connector = self.connector_for(&rot.provider)?;
                match connector.revoke_credential(
                    http,
                    &admin,
                    rot.provider_project_id.as_deref(),
                    new_key,
                ) {
                    Ok(d) => {
                        let _ = self.provider_unlink_key(&rot.provider, new_key);
                        notes.push(format!("new key revoked: {d}"));
                    }
                    Err(e) => {
                        failures += 1;
                        notes.push(format!("new key revocation FAILED: {e}"));
                    }
                }
            }
        }
        // A partially failed rollback must not present as clean: it lands in
        // manual_required with the failures front and center.
        if failures > 0 {
            crate::rotation::set_state(
                &self.conn,
                id,
                crate::rotation::ROLLING_BACK,
                crate::rotation::MANUAL_REQUIRED,
                &format!(
                    "rollback PARTIALLY FAILED ({failures} step(s)): {}",
                    notes.join("; ")
                ),
            )?;
            crate::rotation::record_error(
                &self.conn,
                id,
                &format!("rollback partially failed: {}", notes.join("; ")),
            )?;
        } else {
            crate::rotation::set_state(
                &self.conn,
                id,
                crate::rotation::ROLLING_BACK,
                crate::rotation::ROLLED_BACK,
                &notes.join("; "),
            )?;
        }
        let cred = self.credential_row_by_id(&rot.credential_id)?;
        audit::record(
            &self.conn,
            "rotation_rolled_back",
            cred.as_ref().map(|c| c.project_id.as_str()),
            Some(&rot.credential_id),
            &format!("rotation={id} failures={failures}"),
        )?;
        self.rotation_get(id)
    }

    pub fn rotation_get(&self, id: &str) -> Result<RotationView> {
        let rot = crate::rotation::load(&self.conn, id)?;
        self.hydrate_rotation(rot)
    }

    pub fn rotations(&self, credential: Option<&str>, limit: u32) -> Result<Vec<RotationView>> {
        let credential_id = match credential {
            Some(selector) => Some(self.resolve_credential(selector)?.id),
            None => None,
        };
        crate::rotation::list(&self.conn, credential_id.as_deref(), limit)?
            .into_iter()
            .map(|r| self.hydrate_rotation(r))
            .collect()
    }

    pub fn rotation_events(&self, id: &str) -> Result<Vec<crate::rotation::RotationEvent>> {
        crate::rotation::load(&self.conn, id)?; // 404 check
        crate::rotation::events(&self.conn, id)
    }

    fn hydrate_rotation(&self, rot: crate::rotation::Rotation) -> Result<RotationView> {
        let (credential_name, project_name) = match self.credential_row_by_id(&rot.credential_id)? {
            Some(row) => (row.name.clone(), self.project_name_of(&row.project_id)?),
            None => ("(deleted)".into(), String::new()),
        };
        let waiting_on = match rot.state.as_str() {
            crate::rotation::PLANNED => Some("approval (`rotation approve`)".to_string()),
            crate::rotation::AWAITING_MANUAL_KEY => {
                Some("the manually created replacement key (`rotation provide-key`)".to_string())
            }
            crate::rotation::GRACE_PERIOD => rot.grace_ends_at.clone().map(|ends| {
                if clock::now_rfc3339() < ends {
                    format!("grace/overlap period until {ends}")
                } else if !rot.last_error.is_empty() {
                    "resolution of the continued-use warning".to_string()
                } else {
                    "the next advance".to_string()
                }
            }),
            crate::rotation::MANUAL_REQUIRED => Some("manual provider-side action".to_string()),
            _ if !rot.last_error.is_empty() => Some("a retry after the recorded error".to_string()),
            _ => None,
        };
        Ok(RotationView {
            rotation: rot,
            credential_name,
            project_name,
            waiting_on,
        })
    }

    // ------------------------------------------------------------------
    // Scheduled rotation (intent only; execution is always human-approved)
    // ------------------------------------------------------------------

    /// Enable a rotation schedule. Only allowed after a manually approved
    /// rotation has COMPLETED for this credential, so the combination is
    /// proven to work end to end.
    pub fn rotation_schedule_set(&self, credential: &str, interval_days: i64) -> Result<()> {
        let cred = self.resolve_credential(credential)?;
        let completed: i64 = self.conn.query_row(
            "SELECT count(*) FROM rotations WHERE credential_id = ?1 AND state = ?2",
            params![cred.id, crate::rotation::COMPLETED],
            |r| r.get(0),
        )?;
        if completed == 0 {
            return Err(CoreError::InvalidInput(
                "scheduling needs one manually approved, successfully COMPLETED rotation for \
                 this credential first — so the provider/destination combination is proven"
                    .into(),
            ));
        }
        crate::rotation::schedule_set(&self.conn, &cred.id, interval_days)?;
        audit::record(
            &self.conn,
            "rotation_scheduled",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!("every {interval_days} day(s)"),
        )?;
        Ok(())
    }

    pub fn rotation_schedule_remove(&self, credential: &str) -> Result<bool> {
        let cred = self.resolve_credential(credential)?;
        crate::rotation::schedule_remove(&self.conn, &cred.id)
    }

    pub fn rotation_schedules(&self) -> Result<Vec<crate::rotation::RotationSchedule>> {
        crate::rotation::schedules(&self.conn)
    }

    /// Monitor rules for rotation: due schedules (with preflight) and
    /// rotations stuck with an error for more than a day.
    fn rotation_monitor_alerts(&self, now: &str) -> Result<Vec<alerts::NewAlert>> {
        use crate::providers::Confidence;
        let mut out = Vec::new();
        for schedule in crate::rotation::schedules(&self.conn)? {
            if !schedule.enabled || schedule.next_due_at.as_str() > now {
                continue;
            }
            let Some(cred) = self.credential_row_by_id(&schedule.credential_id)? else {
                continue;
            };
            // Preflight: the pieces the PROVEN rotation path needs must
            // still be present. The proven path is the mode of the last
            // completed rotation (falling back silently from API to manual
            // would change the workflow fundamentally).
            let mut problems = Vec::new();
            let proven_mode: Option<String> = self
                .conn
                .query_row(
                    "SELECT mode FROM rotations WHERE credential_id = ?1 AND state = ?2
                     ORDER BY created_at DESC LIMIT 1",
                    params![cred.id, crate::rotation::COMPLETED],
                    |r| r.get(0),
                )
                .optional()?;
            if proven_mode.as_deref() == Some(crate::rotation::MODE_API)
                && self.provider_admin_secret(&cred.provider).is_err()
            {
                problems.push("the administrative connection is gone");
            }
            if cred.revoked {
                problems.push("the credential is marked revoked");
            }
            let has_active: i64 = self.conn.query_row(
                "SELECT count(*) FROM rotations WHERE credential_id = ?1
                 AND state NOT IN (?2, ?3, ?4, ?5)",
                params![
                    cred.id,
                    crate::rotation::COMPLETED,
                    crate::rotation::ROLLED_BACK,
                    crate::rotation::FAILED,
                    crate::rotation::PLANNED
                ],
                |r| r.get(0),
            )?;
            if has_active > 0 {
                continue; // a rotation is already in flight
            }
            let label = format!("{}/{}", self.project_name_of(&cred.project_id)?, cred.name);
            if problems.is_empty() {
                out.push(alerts::NewAlert {
                    kind: alerts::AlertKind::RotationDue,
                    severity: alerts::Severity::High,
                    dedup_key: format!("rotation_due:{}", cred.id),
                    title: format!("scheduled rotation due: {label}"),
                    detail: format!(
                        "the rotation schedule (every {} day(s)) is due since {}. Nothing runs automatically: start it with `rotation plan {label}` and approve it.",
                        schedule.interval_days, schedule.next_due_at
                    ),
                    evidence: format!("next_due_at={}", schedule.next_due_at),
                    confidence: Confidence::High,
                    recommended_action: "plan, review, and approve the rotation".into(),
                    project_id: Some(cred.project_id.clone()),
                    credential_id: Some(cred.id.clone()),
                    observed_at: now.to_string(),
                });
            } else {
                // Preflight failed: pause the schedule and say why.
                let reason = problems.join("; ");
                crate::rotation::schedule_pause(&self.conn, &cred.id, &reason)?;
                out.push(alerts::NewAlert {
                    kind: alerts::AlertKind::RotationDue,
                    severity: alerts::Severity::High,
                    dedup_key: format!("rotation_due:{}", cred.id),
                    title: format!("scheduled rotation PAUSED: {label}"),
                    detail: format!(
                        "the schedule came due but preflight failed: {reason}. The schedule is paused; fix the problem and re-enable it with `rotation schedule`."
                    ),
                    evidence: reason.clone(),
                    confidence: Confidence::High,
                    recommended_action: "fix the preflight problem, then re-enable the schedule"
                        .into(),
                    project_id: Some(cred.project_id.clone()),
                    credential_id: Some(cred.id.clone()),
                    observed_at: now.to_string(),
                });
            }
        }
        // Stuck rotations: active, error recorded, untouched for 24h+.
        let day_ago = clock::to_rfc3339(clock::now() - time::Duration::days(1));
        for rot in crate::rotation::active(&self.conn)? {
            if rot.updated_at < day_ago {
                let cred_label = self
                    .credential_row_by_id(&rot.credential_id)?
                    .map(|c| c.name)
                    .unwrap_or_else(|| rot.credential_id.clone());
                out.push(alerts::NewAlert {
                    kind: alerts::AlertKind::RotationStuck,
                    severity: alerts::Severity::Medium,
                    dedup_key: format!("rotation_stuck:{}", rot.id),
                    title: format!("rotation stuck: {cred_label}"),
                    detail: format!(
                        "rotation {} has been '{}' since {}{}. Resume it with `rotation advance`, or roll it back.",
                        rot.id,
                        rot.state,
                        rot.updated_at,
                        if rot.last_error.is_empty() {
                            String::new()
                        } else {
                            format!(" (last error: {})", rot.last_error)
                        }
                    ),
                    evidence: format!("state={} updated_at={}", rot.state, rot.updated_at),
                    confidence: Confidence::High,
                    recommended_action: "advance, roll back, or cancel the rotation".into(),
                    project_id: None,
                    credential_id: Some(rot.credential_id.clone()),
                    observed_at: now.to_string(),
                });
            }
        }
        Ok(out)
    }

    // ------------------------------------------------------------------
    // Temporary local access grants (docs/decisions/0013)
    // ------------------------------------------------------------------

    /// Create a temporary access grant. This is a LOCAL control: it bounds
    /// what `run` will inject on this machine; it never constrains the
    /// provider-side credential.
    #[allow(clippy::too_many_arguments)]
    pub fn access_grant_create(
        &self,
        project: &str,
        label: &str,
        credentials: &[String],
        ttl_minutes: u64,
        max_launches: i64,
        max_duration_secs: Option<i64>,
        budget_warn_dollars: Option<&str>,
    ) -> Result<crate::access::AccessGrant> {
        let project_row = self.project_row_by_ident(project)?;
        let mut credential_ids = Vec::new();
        for selector in credentials {
            let cred = self.resolve_credential(selector)?;
            if cred.project_id != project_row.id {
                return Err(CoreError::InvalidInput(format!(
                    "credential '{selector}' is not in project '{}'",
                    project_row.name
                )));
            }
            credential_ids.push(cred.id);
        }
        let budget_warn_micros = budget_warn_dollars
            .map(crate::pricing::dollars_to_micros)
            .transpose()?;
        let id = crate::access::insert(
            &self.conn,
            &project_row.id,
            label,
            &credential_ids,
            ttl_minutes,
            max_launches,
            max_duration_secs,
            budget_warn_micros,
        )?;
        audit::record(
            &self.conn,
            "access_grant_created",
            Some(&project_row.id),
            None,
            &format!(
                "grant={id} ttl_minutes={ttl_minutes} max_launches={max_launches} credentials={}",
                credential_ids.len()
            ),
        )?;
        crate::access::get(&self.conn, &id)
    }

    pub fn access_grants(&self, include_inactive: bool) -> Result<Vec<crate::access::AccessGrant>> {
        crate::access::list(&self.conn, include_inactive)
    }

    /// Revoke a grant immediately. Returns the running injection sessions
    /// launched under it (id, pid) so the caller can terminate them. The
    /// caller must be honest: values already injected into a process stay
    /// in that process's environment until it exits.
    pub fn access_grant_end(
        &self,
        id: &str,
    ) -> Result<(crate::access::AccessGrant, Vec<(String, i64)>)> {
        let grant = crate::access::revoke(&self.conn, id)?;
        let running = crate::inject::running_sessions_for_grant(&self.conn, id)?;
        audit::record(
            &self.conn,
            "access_grant_revoked",
            Some(&grant.project_id),
            None,
            &format!("grant={id} running_sessions={}", running.len()),
        )?;
        Ok((grant, running))
    }

    /// Build an injection under a grant: validates and atomically consumes a
    /// launch, restricts credentials to the grant's subset, and returns any
    /// advisory budget warning. The caller records the child PID afterwards.
    pub fn build_injection_with_grant(
        &self,
        grant_id: &str,
        command_label: &str,
    ) -> Result<GrantInjection> {
        // Validate everything BEFORE consuming a launch: a configuration
        // error must not burn a one-time grant.
        let grant = crate::access::get(&self.conn, grant_id)?;
        let project_row = self.project_row_by_ident(&grant.project_id)?;
        // Resolve the env mapping set, filtered to the grant's credentials.
        let mappings = crate::inject::list_mappings(&self.conn, &project_row.id)?;
        let selected: Vec<_> = if grant.credential_ids.is_empty() {
            mappings
        } else {
            let allowed: HashSet<&str> = grant.credential_ids.iter().map(|s| s.as_str()).collect();
            mappings
                .into_iter()
                .filter(|m| allowed.contains(m.credential_id.as_str()))
                .collect()
        };
        if selected.is_empty() {
            return Err(CoreError::InvalidInput(
                "the grant matches no configured env mappings; map its credentials first (`mapping set`)"
                    .into(),
            ));
        }
        // Everything validated — NOW atomically consume a launch (this also
        // re-checks expiry/revocation/launch caps in its WHERE clause).
        let grant = crate::access::consume_launch(&self.conn, grant_id)?;
        // Decrypt exactly the selected mappings — never the whole project.
        let mut env: Vec<(String, SecretString)> = Vec::new();
        for mapping in &selected {
            let value = self.decrypt_value(&mapping.credential_id)?;
            env.push((mapping.env_var.clone(), value));
        }
        let var_names: Vec<String> = env.iter().map(|(v, _)| v.clone()).collect();
        let session_id = crate::inject::start_session(
            &self.conn,
            &project_row.id,
            &format!("[grant {grant_id}] {command_label}"),
            &var_names,
        )?;
        audit::record(
            &self.conn,
            "process_injection_started",
            Some(&project_row.id),
            None,
            &format!("grant={grant_id} vars={}", var_names.join(",")),
        )?;
        self.conn.execute(
            "UPDATE process_sessions SET grant_id = ?1 WHERE id = ?2",
            params![grant_id, session_id],
        )?;
        // Advisory budget warning where activity data exists (local,
        // advisory-only — it does not and cannot stop provider-side spend).
        let mut warnings = Vec::new();
        if let Some(warn_at) = grant.budget_warn_micros {
            let cost_source = self.budget_cost_source()?;
            let mut total: i64 = 0;
            let credential_ids: Vec<String> = if grant.credential_ids.is_empty() {
                selected.iter().map(|m| m.credential_id.clone()).collect()
            } else {
                grant.credential_ids.clone()
            };
            for cred_id in &credential_ids {
                let report =
                    crate::budget::credential_report(&self.conn, cred_id, cred_id, cost_source)?;
                total += report.used_micros;
            }
            if total >= warn_at {
                warnings.push(format!(
                    "ADVISORY: month-to-date recorded cost for the granted credential(s) is {} — at or past the grant's warning threshold {}. This is a local observation only; it does not cap provider-side spend.",
                    crate::usage::format_micros(total),
                    crate::usage::format_micros(warn_at)
                ));
            }
        }
        let max_duration_secs = grant.max_duration_secs;
        Ok(GrantInjection {
            env,
            session_id,
            grant,
            max_duration_secs,
            warnings,
        })
    }

    /// Record the spawned child PID for a session (termination support).
    pub fn record_session_pid(
        &self,
        session_id: &str,
        pid: u32,
        grant_id: Option<&str>,
    ) -> Result<()> {
        crate::inject::set_session_pid(&self.conn, session_id, pid, grant_id)
    }

    // ------------------------------------------------------------------
    // Provider-created test keys + provider-side revocation
    // ------------------------------------------------------------------

    /// Create a provider-side key for quick testing and store it encrypted.
    /// Reauthentication-gated (it creates real provider-side material).
    /// Returns the credential plus honest enforcement notes.
    #[allow(clippy::too_many_arguments)]
    pub fn test_key_create(
        &mut self,
        project: &str,
        provider: &str,
        provider_project_id: Option<&str>,
        name: &str,
        ttl_minutes: u64,
        master_password: &SecretString,
        http: &dyn crate::http::HttpClient,
    ) -> Result<(Credential, Vec<String>)> {
        self.verify_master_password(master_password)?;
        if ttl_minutes == 0 || ttl_minutes > 60 * 24 * 90 {
            return Err(CoreError::InvalidInput(
                "the test-key reminder lifetime must be between 1 minute and 90 days".into(),
            ));
        }
        let provider = crate::providers::normalize(provider);
        let admin = self.provider_admin_secret(&provider)?;
        let connector = self.connector_for(&provider)?;
        let created = connector.create_credential(
            http,
            &admin,
            &crate::connectors::CreateParams {
                name: name.to_string(),
                provider_project_id: provider_project_id.map(str::to_string),
            },
        )?;
        let expires = clock::rfc3339_after(std::time::Duration::from_secs(ttl_minutes * 60));
        if let Some(key_id) = &created.provider_key_id {
            self.cache_created_key(&provider, key_id, &created)?;
        }
        let created_key_id = created.provider_key_id.clone();
        let created_detail = created.detail.clone();

        let (credential, _warnings) = self.add_credential(AddCredential {
            project: project.to_string(),
            provider: provider.clone(),
            name: name.to_string(),
            environment: Environment::Test,
            value: created.value,
            credential_type: Some(created.credential_type.to_string()),
            key_created_at: None,
            expires_at: Some(expires.clone()),
            docs_url: String::new(),
            notes: format!(
                "Test key created by API Tracker ({created_detail}). The expiration is a \
                 LOCAL reminder — this provider's keys stay valid until revoked."
            ),
        })?;
        if let Some(key_id) = &created_key_id {
            let _ = self.provider_link_key(&provider, key_id, &credential.id);
        }
        audit::record(
            &self.conn,
            "test_key_created",
            Some(&credential.project_id),
            Some(&credential.id),
            &format!("provider={provider} ttl_minutes={ttl_minutes}"),
        )?;
        let notes = vec![
            format!(
                "PROVIDER-ENFORCED: the key is scoped to provider project '{}' — usage and cost are attributable there.",
                created.provider_project_id.as_deref().unwrap_or("?")
            ),
            format!(
                "NOT provider-enforced: the {ttl_minutes}-minute expiry is a LOCAL reminder. The provider key remains valid until you revoke it (`key provider-revoke {}/{}`).",
                credential.project_name, credential.name
            ),
            "ADVISORY-ONLY: budget warnings observe recorded usage; they cannot cap spend."
                .to_string(),
        ];
        Ok((credential, notes))
    }

    /// Remember a key we created (id, project, name) so later operations —
    /// revocation in particular — know which provider project it lives in.
    fn cache_created_key(
        &self,
        provider: &str,
        key_id: &str,
        created: &crate::connectors::CreatedCredential,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO provider_side_keys
                 (provider, api_key_id, provider_project_id, name, redacted_value, synced_at)
             VALUES (?1, ?2, ?3, ?4, '', ?5)",
            params![
                provider,
                key_id,
                created.provider_project_id,
                created.detail,
                clock::now_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Revoke a credential AT THE PROVIDER (via its linked provider-side key
    /// id) and mark it revoked locally. Reauthentication-gated; the caller
    /// must confirm first — this is destructive and usually irreversible.
    pub fn credential_provider_revoke(
        &mut self,
        selector: &str,
        master_password: &SecretString,
        http: &dyn crate::http::HttpClient,
    ) -> Result<String> {
        self.verify_master_password(master_password)?;
        let cred = self.resolve_credential(selector)?;
        let key_id: Option<String> = self
            .conn
            .query_row(
                "SELECT provider_api_key_id FROM provider_key_links
                 WHERE provider = ?1 AND credential_id = ?2
                 ORDER BY created_at DESC LIMIT 1",
                params![cred.provider, cred.id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(key_id) = key_id else {
            let manage = crate::providers::find(&cred.provider)
                .map(|m| m.manage_url.clone())
                .unwrap_or_default();
            return Err(CoreError::InvalidInput(format!(
                "no provider-side key id is linked to this credential; link one (`provider link`) or revoke it at {manage}"
            )));
        };
        let project_id: Option<String> = self
            .conn
            .query_row(
                "SELECT provider_project_id FROM provider_side_keys
                 WHERE provider = ?1 AND api_key_id = ?2",
                params![cred.provider, key_id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let admin = self.provider_admin_secret(&cred.provider)?;
        let connector = self.connector_for(&cred.provider)?;
        let detail = connector.revoke_credential(http, &admin, project_id.as_deref(), &key_id)?;
        self.update_credential(
            &cred.id,
            UpdateCredential {
                revoked: Some(true),
                ..Default::default()
            },
        )?;
        audit::record(
            &self.conn,
            "credential_provider_revoked",
            Some(&cred.project_id),
            Some(&cred.id),
            &format!("provider_key={key_id}"),
        )?;
        Ok(detail)
    }

    /// Fetch fresh permissions WITHOUT storing them, alongside the stored
    /// snapshot — the before/after diff for permission review.
    pub fn permissions_preview(
        &self,
        selector: &str,
        http: &dyn crate::http::HttpClient,
    ) -> Result<(
        Option<crate::permissions::StoredPermissions>,
        crate::connectors::FetchedPermissions,
        crate::permissions::NormalizedPermissions,
    )> {
        let cred = self.get_credential(selector)?;
        let stored = crate::permissions::load(&self.conn, &cred.id)?;
        let connector = self.connector_for(&cred.provider)?;
        let value = self.decrypt_value(selector)?;
        let fetched = connector.fetch_permissions(http, &value)?;
        let normalized = crate::permissions::normalize_for(&cred.provider, &fetched.raw_scopes);
        Ok((stored, fetched, normalized))
    }

    /// List provider-side keys via the administrative connection (for
    /// picking an old key id before rotation/disable/revoke).
    pub fn provider_list_keys(
        &self,
        provider: &str,
        provider_project_id: Option<&str>,
        http: &dyn crate::http::HttpClient,
    ) -> Result<Vec<crate::connectors::ProviderKeyListing>> {
        let provider = crate::providers::normalize(provider);
        let admin = self.provider_admin_secret(&provider)?;
        let connector = self.connector_for(&provider)?;
        connector.list_keys(http, &admin, provider_project_id)
    }

    // ------------------------------------------------------------------
    // Credential lifecycle timeline
    // ------------------------------------------------------------------

    /// A merged, chronological lifecycle view for one credential: audit
    /// events (creation, replacement, validation, reveal, export,
    /// permission snapshots, destination sync, rotation milestones),
    /// activity events (disable/enable), retained versions, and rotation
    /// transitions. Metadata only — never values.
    pub fn credential_timeline(&self, selector: &str) -> Result<Vec<TimelineEvent>> {
        let cred = self.resolve_credential(selector)?;
        let mut out: Vec<TimelineEvent> = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT at, event, detail FROM audit_events WHERE credential_id = ?1
             ORDER BY at",
        )?;
        let rows = stmt.query_map([&cred.id], |r| {
            Ok(TimelineEvent {
                at: r.get(0)?,
                kind: r.get(1)?,
                detail: r.get(2)?,
                source: "audit".into(),
            })
        })?;
        for r in rows {
            out.push(r?);
        }
        let mut stmt = self.conn.prepare(
            "SELECT at, kind, detail FROM activity_events WHERE credential_id = ?1
             ORDER BY at",
        )?;
        let rows = stmt.query_map([&cred.id], |r| {
            Ok(TimelineEvent {
                at: r.get(0)?,
                kind: r.get(1)?,
                detail: r.get(2)?,
                source: "activity".into(),
            })
        })?;
        for r in rows {
            out.push(r?);
        }
        let mut stmt = self.conn.prepare(
            "SELECT created_at, version, reason FROM credential_versions
             WHERE credential_id = ?1 ORDER BY version",
        )?;
        let rows = stmt.query_map([&cred.id], |r| {
            let version: i64 = r.get(1)?;
            let reason: String = r.get(2)?;
            Ok(TimelineEvent {
                at: r.get(0)?,
                kind: "version_retained".into(),
                detail: format!("v{version} retained ({reason})"),
                source: "versions".into(),
            })
        })?;
        for r in rows {
            out.push(r?);
        }
        let mut stmt = self.conn.prepare(
            "SELECT e.at, e.to_state, e.detail FROM rotation_events e
             JOIN rotations r ON r.id = e.rotation_id
             WHERE r.credential_id = ?1 ORDER BY e.at",
        )?;
        let rows = stmt.query_map([&cred.id], |r| {
            let state: String = r.get(1)?;
            Ok(TimelineEvent {
                at: r.get(0)?,
                kind: format!("rotation:{state}"),
                detail: r.get(2)?,
                source: "rotation".into(),
            })
        })?;
        for r in rows {
            out.push(r?);
        }
        out.sort_by(|a, b| a.at.cmp(&b.at));
        Ok(out)
    }
}

/// A grant-authorized injection, ready to spawn. Debug omits the env.
pub struct GrantInjection {
    pub env: Vec<(String, SecretString)>,
    pub session_id: String,
    pub grant: crate::access::AccessGrant,
    pub max_duration_secs: Option<i64>,
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for GrantInjection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantInjection")
            .field("session_id", &self.session_id)
            .field("grant", &self.grant.id)
            .field(
                "env_vars",
                &self.env.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Result of one repository's incremental background scan.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RepoScanReport {
    pub repo_path: String,
    pub head_commit: String,
    pub findings: usize,
    pub baseline_only: bool,
}

/// One event in a credential's merged lifecycle timeline (metadata only).
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimelineEvent {
    pub at: String,
    pub kind: String,
    pub detail: String,
    pub source: String,
}

/// A rotation with display context and what it is waiting on.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RotationView {
    #[serde(flatten)]
    pub rotation: crate::rotation::Rotation,
    pub credential_name: String,
    pub project_name: String,
    pub waiting_on: Option<String>,
}

/// A provider connection's stored state (no secrets; the key is masked).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderConnection {
    pub provider: String,
    /// True when either a dedicated admin key or a legacy credential
    /// reference is configured.
    pub connected: bool,
    /// Masked preview of the dedicated administrative key, if one is stored.
    pub admin_key_masked: Option<String>,
    /// Legacy: the vault credential referenced as the admin key.
    pub admin_credential_id: Option<String>,
    pub org_label: Option<String>,
    pub connected_at: Option<String>,
    pub last_synced_at: Option<String>,
    pub last_success_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub last_error: String,
    pub last_status: String,
    pub detail: String,
    /// True when synced data is older than the configured staleness window.
    pub stale: bool,
}

/// The outcome of one provider synchronization.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncReport {
    pub provider: String,
    pub usage_rows: usize,
    pub cost_rows: usize,
    pub window_start: String,
    pub window_end: String,
    /// Non-fatal limitations encountered (e.g. metadata unavailable).
    pub notes: Vec<String>,
}

/// A provider-side API key with its local link state and any suggestion.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderKeyOverview {
    pub provider: String,
    pub api_key_id: String,
    pub name: String,
    pub redacted_value: String,
    pub provider_project_id: Option<String>,
    pub provider_project_name: Option<String>,
    pub linked_credential_id: Option<String>,
    /// "project/name" label of the linked credential.
    pub linked_credential: Option<String>,
    /// How the link was established (e.g. `user_confirmed`).
    pub link_source: Option<String>,
    pub usage_rows: i64,
    pub suggested_credential_id: Option<String>,
    pub suggested_credential: Option<String>,
    pub note: String,
}

/// A provider-side project with month-to-date reported cost and mapping state.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderProjectOverview {
    pub provider_project_id: String,
    pub name: String,
    pub reported_cost_micros_month: i64,
    pub has_linked_usage: bool,
}

/// Read suppression keys directly from a database connection, without
/// unlocking the vault. Used by the pre-commit hook, which must run during a
/// commit without prompting for the master password. Suppression keys carry
/// no secret material.
/// One entry in a credential's version history (masked values only).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CredentialVersionInfo {
    pub version: i64,
    pub masked_value: String,
    pub created_at: String,
    pub reason: String,
    pub current: bool,
}

/// The result of importing (or skipping) one `.env` variable.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnvImportOutcome {
    pub key: String,
    /// `imported`, `mapped_existing`, or `skipped`.
    pub action: String,
    pub credential: Option<String>,
    pub note: String,
}

/// The result of an explicit `.env` export (no values).
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnvExportReport {
    pub export_id: String,
    pub path: String,
    pub var_names: Vec<String>,
    pub git_status: crate::envgov::GitStatus,
    pub expires_at: Option<String>,
    pub warnings: Vec<String>,
}

pub fn load_suppression_keys(conn: &Connection) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare("SELECT suppression_key FROM scan_suppressions")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut set = HashSet::new();
    for r in rows {
        set.insert(r?);
    }
    Ok(set)
}

/// A stored scan suppression (no secret material).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Suppression {
    pub suppression_key: String,
    pub rule: String,
    pub path: String,
    pub reason: String,
    pub created_at: String,
}

/// Summary of a monitoring run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MonitorSummary {
    /// Registered repositories examined this run (incremental).
    pub repos_scanned: usize,
    /// Findings in newly scanned commits across those repositories.
    pub repo_findings: usize,
    pub checked: usize,
    pub alerts_created: usize,
    pub alerts_resolved: usize,
    pub open_alerts: usize,
}

/// Result of one full monitor cycle (local rules + optional network phases).
#[derive(Debug, Clone, serde::Serialize)]
pub struct MonitorCycleReport {
    pub summary: MonitorSummary,
    pub doc_checks: usize,
    pub webhooks_delivered: usize,
    /// True when the network phases were skipped (no transports provided).
    pub offline: bool,
}

/// When monitoring last ran and how it went. Timestamps are RFC 3339.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MonitorStatus {
    pub last_run_at: Option<String>,
    pub last_success_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub last_error: String,
    pub last_detail: String,
}

impl CredentialRow {
    fn clone_row(&self) -> CredentialRow {
        CredentialRow {
            id: self.id.clone(),
            project_id: self.project_id.clone(),
            provider: self.provider.clone(),
            name: self.name.clone(),
            environment: self.environment.clone(),
            credential_type: self.credential_type.clone(),
            ciphertext: self.ciphertext.clone(),
            linked_credential_id: self.linked_credential_id.clone(),
            fingerprint: self.fingerprint.clone(),
            masked_value: self.masked_value.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            key_created_at: self.key_created_at.clone(),
            expires_at: self.expires_at.clone(),
            last_validated_at: self.last_validated_at.clone(),
            last_used_at: self.last_used_at.clone(),
            docs_url: self.docs_url.clone(),
            notes: self.notes.clone(),
            manually_disabled: self.manually_disabled,
            revoked: self.revoked,
            marked_invalid: self.marked_invalid,
            possibly_exposed: self.possibly_exposed,
            exposure_note: self.exposure_note.clone(),
            provider_expires_at: self.provider_expires_at.clone(),
        }
    }
}

fn parse_optional_date(value: Option<&str>) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => Ok(Some(clock::to_rfc3339(clock::parse_user_date(s)?))),
    }
}

fn parse_optional_ts(value: Option<&str>) -> Result<Option<time::OffsetDateTime>> {
    match value {
        None => Ok(None),
        Some(s) => Ok(Some(clock::parse_rfc3339(s)?)),
    }
}
