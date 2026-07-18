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

use crate::audit;
use crate::clock;
use crate::crypto::{self, aad, KdfParams};
use crate::db;
use crate::error::{CoreError, Result};
use crate::model::{mask_value, Credential, Environment, Project};
use crate::reuse::{self, ReuseMatch, ReuseWarning};
use crate::secret::{SecretBytes, SecretString};
use crate::session::{self, SessionKeys, SessionToken};
use crate::settings::VaultSettings;
use crate::status::{self, StatusInputs};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use uuid::Uuid;

pub const MIN_PASSWORD_LEN: usize = 8;
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
        self.conn.execute(
            "UPDATE credentials SET ciphertext = ?1, fingerprint = ?2, masked_value = ?3,
             updated_at = ?4 WHERE id = ?5",
            params![
                ciphertext,
                fp,
                mask_value(new_value.expose()),
                clock::now_rfc3339(),
                row.id
            ],
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
