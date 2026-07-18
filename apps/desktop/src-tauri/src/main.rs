//! API Tracker desktop backend: thin Tauri commands over `api-tracker-core`.
//!
//! All business logic and cryptography live in the shared core crate. This
//! layer only manages the unlocked-vault state (with inactivity auto-lock),
//! converts between frontend DTOs and core types, and implements the
//! clipboard integration. Credential values cross the IPC boundary only for
//! the explicit `credential_reveal`/`credential_copy`/add/replace commands.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use api_tracker_core::backup;
use api_tracker_core::error::CoreError;
use api_tracker_core::model::{Credential, Environment, Project};
use api_tracker_core::providers::{ProviderInfo, PROVIDERS};
use api_tracker_core::reuse::ReuseWarning;
use api_tracker_core::secret::SecretString;
use api_tracker_core::settings::VaultSettings;
use api_tracker_core::vault::{
    self, AddCredential, AddReference, NewProject, UnlockedVault, UpdateCredential, UpdateProject,
    VaultPaths,
};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::State;
use zeroize::Zeroizing;

/// Error DTO for the frontend: stable machine code + human message. Never
/// contains secret material (guaranteed by `CoreError`'s constructors).
#[derive(Debug, Clone, Serialize)]
struct ErrDto {
    code: String,
    message: String,
}

impl From<CoreError> for ErrDto {
    fn from(err: CoreError) -> Self {
        Self {
            code: err.code().to_owned(),
            message: err.to_string(),
        }
    }
}

fn locked_err() -> ErrDto {
    ErrDto::from(CoreError::VaultLocked)
}

type CmdResult<T> = Result<T, ErrDto>;

struct VaultSlot {
    vault: Option<UnlockedVault>,
    last_activity: Instant,
}

struct AppState {
    slot: Mutex<VaultSlot>,
    data_dir: PathBuf,
}

impl AppState {
    fn paths(&self) -> VaultPaths {
        VaultPaths::new(self.data_dir.clone())
    }
}

/// Run `f` against the unlocked vault, enforcing inactivity auto-lock.
fn with_vault<T>(
    state: &AppState,
    f: impl FnOnce(&mut UnlockedVault) -> Result<T, CoreError>,
) -> CmdResult<T> {
    let mut slot = state.slot.lock().expect("vault state mutex poisoned");
    let auto_lock_minutes = match slot.vault.as_ref() {
        None => return Err(locked_err()),
        Some(vault) => vault.settings().auto_lock_minutes,
    };
    if auto_lock_minutes > 0
        && slot.last_activity.elapsed() >= Duration::from_secs(u64::from(auto_lock_minutes) * 60)
    {
        slot.vault = None; // drop -> keys zeroized
        return Err(locked_err());
    }
    slot.last_activity = Instant::now();
    let vault = slot.vault.as_mut().expect("checked above");
    f(vault).map_err(Into::into)
}

#[derive(Serialize)]
struct VaultStatusDto {
    exists: bool,
    unlocked: bool,
    data_dir: String,
}

#[tauri::command]
fn vault_status(state: State<'_, AppState>) -> CmdResult<VaultStatusDto> {
    let mut slot = state.slot.lock().expect("vault state mutex poisoned");
    // Apply auto-lock on status polls too, so the UI locks visibly.
    if let Some(vault) = slot.vault.as_ref() {
        let minutes = vault.settings().auto_lock_minutes;
        if minutes > 0
            && slot.last_activity.elapsed() >= Duration::from_secs(u64::from(minutes) * 60)
        {
            slot.vault = None;
        }
    }
    Ok(VaultStatusDto {
        exists: state.paths().vault_exists(),
        unlocked: slot.vault.is_some(),
        data_dir: state.data_dir.display().to_string(),
    })
}

#[tauri::command]
fn vault_create(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = SecretString::new(password);
    let vault = vault::create_vault(&state.paths(), &password)?;
    let mut slot = state.slot.lock().expect("vault state mutex poisoned");
    slot.vault = Some(vault);
    slot.last_activity = Instant::now();
    Ok(())
}

#[tauri::command]
fn vault_unlock(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = SecretString::new(password);
    let vault = vault::unlock_vault(&state.paths(), &password)?;
    let mut slot = state.slot.lock().expect("vault state mutex poisoned");
    slot.vault = Some(vault);
    slot.last_activity = Instant::now();
    Ok(())
}

#[tauri::command]
fn vault_lock(state: State<'_, AppState>) -> CmdResult<()> {
    let mut slot = state.slot.lock().expect("vault state mutex poisoned");
    slot.vault = None;
    Ok(())
}

#[tauri::command]
fn reauth(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| vault.verify_master_password(&password))
}

#[tauri::command]
fn settings_get(state: State<'_, AppState>) -> CmdResult<VaultSettings> {
    with_vault(&state, |vault| Ok(vault.settings().clone()))
}

#[tauri::command]
fn settings_set(state: State<'_, AppState>, settings: VaultSettings) -> CmdResult<()> {
    with_vault(&state, |vault| vault.update_settings(settings))
}

#[tauri::command]
fn providers_list() -> Vec<&'static ProviderInfo> {
    PROVIDERS.iter().collect()
}

#[tauri::command]
fn project_list(state: State<'_, AppState>, include_archived: bool) -> CmdResult<Vec<Project>> {
    with_vault(&state, |vault| vault.list_projects(include_archived))
}

#[tauri::command]
fn project_get(state: State<'_, AppState>, ident: String) -> CmdResult<Project> {
    with_vault(&state, |vault| vault.get_project(&ident))
}

#[tauri::command]
fn project_create(
    state: State<'_, AppState>,
    name: String,
    description: String,
    notes: String,
    environments: Vec<Environment>,
    repo_paths: Vec<String>,
) -> CmdResult<Project> {
    with_vault(&state, |vault| {
        vault.create_project(NewProject {
            name,
            description,
            notes,
            environments,
            repo_paths,
        })
    })
}

#[tauri::command]
fn project_update(
    state: State<'_, AppState>,
    ident: String,
    name: String,
    description: String,
    notes: String,
    environments: Vec<Environment>,
    repo_paths: Vec<String>,
) -> CmdResult<Project> {
    with_vault(&state, |vault| {
        // The UI sends the full desired repo list; diff it against the
        // current one.
        let current = vault.get_project(&ident)?;
        let add: Vec<String> = repo_paths
            .iter()
            .filter(|p| !current.repo_paths.contains(p))
            .cloned()
            .collect();
        let remove: Vec<String> = current
            .repo_paths
            .iter()
            .filter(|p| !repo_paths.contains(p))
            .cloned()
            .collect();
        vault.update_project(
            &ident,
            UpdateProject {
                name: Some(name),
                description: Some(description),
                notes: Some(notes),
                environments: Some(environments),
                add_repo_paths: add,
                remove_repo_paths: remove,
            },
        )
    })
}

#[tauri::command]
fn project_set_archived(
    state: State<'_, AppState>,
    ident: String,
    archived: bool,
) -> CmdResult<Project> {
    with_vault(&state, |vault| vault.set_project_archived(&ident, archived))
}

#[tauri::command]
fn project_set_password(
    state: State<'_, AppState>,
    ident: String,
    password: String,
) -> CmdResult<()> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| {
        vault.set_project_password(&ident, &password)
    })
}

#[tauri::command]
fn project_remove_password(
    state: State<'_, AppState>,
    ident: String,
    password: String,
) -> CmdResult<()> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| {
        vault.remove_project_password(&ident, &password)
    })
}

#[tauri::command]
fn project_unlock(
    state: State<'_, AppState>,
    ident: String,
    password: String,
) -> CmdResult<Project> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| vault.unlock_project(&ident, &password))
}

#[tauri::command]
fn project_lock(state: State<'_, AppState>, ident: String) -> CmdResult<Project> {
    with_vault(&state, |vault| vault.lock_project(&ident))
}

#[tauri::command]
fn credential_list(
    state: State<'_, AppState>,
    project: Option<String>,
) -> CmdResult<Vec<Credential>> {
    with_vault(&state, |vault| vault.list_credentials(project.as_deref()))
}

#[tauri::command]
fn credential_get(state: State<'_, AppState>, selector: String) -> CmdResult<Credential> {
    with_vault(&state, |vault| vault.get_credential(&selector))
}

#[tauri::command]
fn credential_check_reuse(
    state: State<'_, AppState>,
    project: String,
    environment: Environment,
    value: String,
) -> CmdResult<Vec<ReuseWarning>> {
    let value = SecretString::new(value);
    with_vault(&state, |vault| {
        vault.check_reuse(&project, environment, &value)
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn credential_add(
    state: State<'_, AppState>,
    project: String,
    provider: String,
    name: String,
    environment: Environment,
    value: String,
    key_created_at: Option<String>,
    expires_at: Option<String>,
    docs_url: String,
    notes: String,
) -> CmdResult<Credential> {
    let value = SecretString::new(value);
    with_vault(&state, |vault| {
        let (credential, _warnings) = vault.add_credential(AddCredential {
            project,
            provider,
            name,
            environment,
            value,
            credential_type: None,
            key_created_at,
            expires_at,
            docs_url,
            notes,
        })?;
        Ok(credential)
    })
}

#[tauri::command]
fn credential_add_reference(
    state: State<'_, AppState>,
    project: String,
    source: String,
    name: String,
    environment: Environment,
    docs_url: String,
    notes: String,
) -> CmdResult<Credential> {
    with_vault(&state, |vault| {
        vault.add_credential_reference(AddReference {
            project,
            source,
            name,
            environment,
            docs_url,
            notes,
        })
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn credential_update(
    state: State<'_, AppState>,
    selector: String,
    name: String,
    provider: String,
    environment: Environment,
    key_created_at: Option<String>,
    expires_at: Option<String>,
    docs_url: String,
    notes: String,
) -> CmdResult<Credential> {
    with_vault(&state, |vault| {
        vault.update_credential(
            &selector,
            UpdateCredential {
                name: Some(name),
                provider: Some(provider),
                environment: Some(environment),
                key_created_at: Some(key_created_at),
                expires_at: Some(expires_at),
                docs_url: Some(docs_url),
                notes: Some(notes),
                ..Default::default()
            },
        )
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn credential_mark(
    state: State<'_, AppState>,
    selector: String,
    mark_used_now: Option<bool>,
    mark_validated: Option<bool>,
    disabled: Option<bool>,
    revoked: Option<bool>,
    possibly_exposed: Option<bool>,
    exposure_note: Option<String>,
) -> CmdResult<Credential> {
    with_vault(&state, |vault| {
        vault.update_credential(
            &selector,
            UpdateCredential {
                mark_used_now: mark_used_now.unwrap_or(false),
                mark_validated,
                disabled,
                revoked,
                possibly_exposed,
                exposure_note,
                ..Default::default()
            },
        )
    })
}

#[tauri::command]
fn credential_replace_value(
    state: State<'_, AppState>,
    selector: String,
    password: String,
    value: String,
) -> CmdResult<Vec<ReuseWarning>> {
    let password = SecretString::new(password);
    let value = SecretString::new(value);
    with_vault(&state, |vault| {
        let (_credential, warnings) =
            vault.replace_credential_value(&selector, &password, value)?;
        Ok(warnings)
    })
}

#[tauri::command]
fn credential_delete(state: State<'_, AppState>, selector: String) -> CmdResult<()> {
    with_vault(&state, |vault| {
        vault.delete_credential(&selector)?;
        Ok(())
    })
}

/// Reveal is the one command that intentionally returns plaintext to the UI.
/// It re-verifies the master password first (reauthentication).
#[tauri::command]
fn credential_reveal(
    state: State<'_, AppState>,
    selector: String,
    password: String,
) -> CmdResult<String> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| {
        let value = vault.reveal_credential(&selector, &password)?;
        Ok(value.expose().to_owned())
    })
}

/// Copy a value to the system clipboard after reauthentication; the
/// plaintext never reaches the frontend. Best-effort clipboard clear after
/// the configured delay. Returns the clear delay in seconds (0 = disabled).
#[tauri::command]
fn credential_copy(
    state: State<'_, AppState>,
    selector: String,
    password: String,
) -> CmdResult<u32> {
    let password = SecretString::new(password);
    let (value, clear_after) = with_vault(&state, |vault| {
        let value = vault.reveal_credential(&selector, &password)?;
        Ok((
            Zeroizing::new(value.expose().to_owned()),
            vault.settings().clipboard_clear_seconds,
        ))
    })?;
    let mut clipboard = arboard::Clipboard::new().map_err(|e| ErrDto {
        code: "clipboard_error".into(),
        message: format!("could not access the clipboard: {e}"),
    })?;
    clipboard.set_text(value.as_str()).map_err(|e| ErrDto {
        code: "clipboard_error".into(),
        message: format!("could not write to the clipboard: {e}"),
    })?;
    if clear_after > 0 {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(u64::from(clear_after)));
            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                // Only clear if the clipboard still holds our value.
                if clipboard.get_text().map(|t| t == *value).unwrap_or(false) {
                    let _ = clipboard.set_text("");
                }
            }
        });
    }
    Ok(clear_after)
}

#[tauri::command]
fn backup_create(
    state: State<'_, AppState>,
    path: String,
    master_password: String,
    backup_password: String,
    overwrite: bool,
) -> CmdResult<backup::BackupInfo> {
    let master_password = SecretString::new(master_password);
    let backup_password = SecretString::new(backup_password);
    with_vault(&state, |vault| {
        vault.verify_master_password(&master_password)?;
        backup::create_backup(
            vault,
            std::path::Path::new(&path),
            &backup_password,
            overwrite,
        )
    })
}

#[tauri::command]
fn backup_verify(
    _state: State<'_, AppState>,
    path: String,
    backup_password: String,
) -> CmdResult<backup::BackupInfo> {
    let backup_password = SecretString::new(backup_password);
    backup::verify_backup(std::path::Path::new(&path), &backup_password).map_err(Into::into)
}

#[tauri::command]
fn backup_restore(
    state: State<'_, AppState>,
    path: String,
    backup_password: String,
    force: bool,
) -> CmdResult<backup::BackupInfo> {
    let backup_password = SecretString::new(backup_password);
    let info = backup::restore_backup(
        std::path::Path::new(&path),
        &backup_password,
        &state.paths(),
        force,
    )?;
    // Only after a successful restore: drop the old in-memory session. The
    // restored vault requires a fresh unlock with its own master password.
    // (On failure we leave the current session intact so the user is not
    // bounced to the unlock screen for a restore that never happened.)
    {
        let mut slot = state.slot.lock().expect("vault state mutex poisoned");
        slot.vault = None;
    }
    Ok(info)
}

fn main() {
    let data_dir = vault::default_data_dir().expect("could not determine the data directory");
    tauri::Builder::default()
        .manage(AppState {
            slot: Mutex::new(VaultSlot {
                vault: None,
                last_activity: Instant::now(),
            }),
            data_dir,
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            vault_create,
            vault_unlock,
            vault_lock,
            reauth,
            settings_get,
            settings_set,
            providers_list,
            project_list,
            project_get,
            project_create,
            project_update,
            project_set_archived,
            project_set_password,
            project_remove_password,
            project_unlock,
            project_lock,
            credential_list,
            credential_get,
            credential_check_reuse,
            credential_add,
            credential_add_reference,
            credential_update,
            credential_mark,
            credential_replace_value,
            credential_delete,
            credential_reveal,
            credential_copy,
            backup_create,
            backup_verify,
            backup_restore,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the API Tracker desktop app");
}
