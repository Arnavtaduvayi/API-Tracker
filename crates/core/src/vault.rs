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
}

const CREDENTIAL_COLUMNS: &str = "id, project_id, provider, name, environment, credential_type, \
     ciphertext, linked_credential_id, fingerprint, masked_value, created_at, updated_at, \
     key_created_at, expires_at, last_validated_at, last_used_at, docs_url, notes, \
     manually_disabled, revoked, marked_invalid, possibly_exposed, exposure_note";

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
        self.conn.execute(
            "UPDATE credentials SET ciphertext = ?1, fingerprint = ?2, masked_value = ?3,
             updated_at = ?4 WHERE id = ?5",
            params![ciphertext, fp, masked, now, row.id],
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

    /// Delete a credential. Refuses while other records reference it.
    pub fn delete_credential(&mut self, selector: &str) -> Result<Credential> {
        let row = self.resolve_credential(selector)?;
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
    pub fn mark_findings_exposed(&mut self, findings: &[scanner::Finding]) -> Result<Vec<String>> {
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

        let mut managed = crate::monitor::managed_credential_kinds();
        managed.extend(crate::activity::managed_kinds());
        managed.extend([
            alerts::AlertKind::ProviderDataStale,
            alerts::AlertKind::UnmatchedProviderKey,
            alerts::AlertKind::UnmappedProviderProject,
        ]);
        let resolved = alerts::auto_resolve_stale(&self.conn, &managed, &active_keys)?;
        Ok(MonitorSummary {
            checked: credentials.len(),
            alerts_created: created,
            alerts_resolved: resolved,
            open_alerts: alerts::open_count(&self.conn)? as usize,
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
        let normalized = match cred.provider.as_str() {
            "github" => crate::permissions::normalize_github(&fetched.raw_scopes),
            _ => crate::permissions::NormalizedPermissions {
                summary: "raw scopes only (no provider-specific normalization)".into(),
                ..Default::default()
            },
        };
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
        if provider != crate::openai::PROVIDER {
            return Err(CoreError::Unsupported {
                provider,
                capability: "admin_connection",
                hint: "a dedicated administrative connection is only implemented for OpenAI; \
                       use `provider connect <provider> --credential <vault credential>`"
                    .into(),
            });
        }
        // Validate before storing so a mistyped key is never persisted.
        // `http: None` (explicit user opt-out, e.g. offline setup) stores the
        // key unvalidated and says so.
        let detail = match http {
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
        if provider != crate::openai::PROVIDER {
            return Err(CoreError::Unsupported {
                provider,
                capability: "admin_connection_test",
                hint: "connection tests are only implemented for OpenAI".into(),
            });
        }
        let now = clock::now_rfc3339();
        match crate::openai::validate_admin_key(http, &admin) {
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
                "INSERT INTO provider_side_projects (provider, project_id, name, status, synced_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(provider, project_id) DO UPDATE SET
                 name = excluded.name, status = excluded.status, synced_at = excluded.synced_at",
                params![provider, p.id, p.name, p.status, now],
            )?;
        }
        for k in &side_keys {
            tx.execute(
                "INSERT INTO provider_side_keys
                 (provider, api_key_id, provider_project_id, name, redacted_value,
                  created_at, last_used_at, synced_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(provider, api_key_id) DO UPDATE SET
                 provider_project_id = excluded.provider_project_id, name = excluded.name,
                 redacted_value = excluded.redacted_value, created_at = excluded.created_at,
                 last_used_at = excluded.last_used_at, synced_at = excluded.synced_at",
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

    pub fn list_process_sessions(&self, limit: u32) -> Result<Vec<crate::inject::ProcessSession>> {
        crate::inject::list_sessions(&self.conn, limit)
    }
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
    pub checked: usize,
    pub alerts_created: usize,
    pub alerts_resolved: usize,
    pub open_alerts: usize,
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
