//! API Tracker desktop backend: thin Tauri commands over `api-tracker-core`.
//!
//! All business logic and cryptography live in the shared core crate. This
//! layer only manages the unlocked-vault state (with inactivity auto-lock),
//! converts between frontend DTOs and core types, and implements the
//! clipboard integration. Credential values cross the IPC boundary only for
//! the explicit `credential_reveal`/`credential_copy`/add/replace commands.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use api_tracker_core::backup;
use api_tracker_core::docwatch::{DocWatch, HttpFetcher};
use api_tracker_core::error::CoreError;
use api_tracker_core::http::UreqClient;
use api_tracker_core::model::{Credential, Environment, Project};
use api_tracker_core::providers::{self, ProviderManifest};
use api_tracker_core::reuse::ReuseWarning;
use api_tracker_core::scanner::Finding;
use api_tracker_core::secret::SecretString;
use api_tracker_core::settings::VaultSettings;
use api_tracker_core::vault::{
    self, AddCredential, AddReference, NewProject, ProviderConnection, UnlockedVault,
    UpdateCredential, UpdateProject, VaultPaths,
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
    with_vault_impl(state, true, f)
}

/// Like `with_vault`, but does NOT count as user activity. Background work
/// (the periodic monitor timer) must use this, or it would keep refreshing
/// the activity clock and defeat inactivity auto-lock.
fn with_vault_background<T>(
    state: &AppState,
    f: impl FnOnce(&mut UnlockedVault) -> Result<T, CoreError>,
) -> CmdResult<T> {
    with_vault_impl(state, false, f)
}

fn with_vault_impl<T>(
    state: &AppState,
    touch_activity: bool,
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
    if touch_activity {
        slot.last_activity = Instant::now();
    }
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
fn providers_list() -> Vec<&'static ProviderManifest> {
    providers::manifests().iter().collect()
}

#[tauri::command]
fn provider_get(id: String) -> CmdResult<&'static ProviderManifest> {
    providers::find(&id).ok_or_else(|| ErrDto {
        code: "not_found".into(),
        message: format!("unknown provider '{id}'"),
    })
}

// --- Scanning + hooks ---

#[tauri::command]
fn scan_path(
    state: State<'_, AppState>,
    path: String,
    mode: String,
    mark_exposed: bool,
) -> CmdResult<Vec<Finding>> {
    let p = std::path::PathBuf::from(&path);
    with_vault(&state, |vault| {
        let mut findings = match mode.as_str() {
            "staged" => vault.scan_staged(&p)?,
            "history" => vault.scan_history(&p, Some(50))?,
            _ => vault.scan_working_tree(&p)?,
        };
        if mark_exposed {
            vault.mark_findings_exposed(&findings)?;
        }
        findings.sort_by_key(|f| std::cmp::Reverse(f.confidence));
        Ok(findings)
    })
}

#[tauri::command]
fn suppression_add(
    state: State<'_, AppState>,
    suppression_key: String,
    path: String,
    reason: String,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        vault.add_suppression(&suppression_key, "manual", &path, &reason)
    })
}

#[tauri::command]
fn hook_status(path: String) -> CmdResult<api_tracker_core::hooks::HookStatus> {
    api_tracker_core::hooks::status(std::path::Path::new(&path)).map_err(Into::into)
}

#[tauri::command]
fn hook_install(path: String, force: bool) -> CmdResult<api_tracker_core::hooks::HookStatus> {
    api_tracker_core::hooks::install(std::path::Path::new(&path), force)?;
    api_tracker_core::hooks::status(std::path::Path::new(&path)).map_err(Into::into)
}

#[tauri::command]
fn hook_remove(path: String) -> CmdResult<api_tracker_core::hooks::HookStatus> {
    api_tracker_core::hooks::remove(std::path::Path::new(&path))?;
    api_tracker_core::hooks::status(std::path::Path::new(&path)).map_err(Into::into)
}

// --- Monitoring + alerts ---

#[tauri::command]
fn monitor_run(state: State<'_, AppState>) -> CmdResult<api_tracker_core::vault::MonitorSummary> {
    with_vault(&state, |vault| vault.run_monitor())
}

/// Local monitoring plus the network phases, mirroring the CLI's
/// `monitor run`: due documentation checks and webhook notification
/// delivery are best-effort and never fail the run (offline-safe).
#[derive(Serialize)]
struct FullMonitorReport {
    summary: api_tracker_core::vault::MonitorSummary,
    doc_checks: usize,
    delivered: usize,
    /// Severities of alerts created by this run (severities only — titles
    /// could name credentials and this feeds OS notifications).
    new_alert_severities: Vec<String>,
}

/// Runs as background work: it enforces auto-lock but does not refresh the
/// activity clock, so a periodic timer cannot keep the vault open forever.
#[tauri::command]
fn monitor_run_full(state: State<'_, AppState>) -> CmdResult<FullMonitorReport> {
    with_vault_background(&state, |vault| {
        let before: std::collections::HashSet<String> =
            api_tracker_core::alerts::list(vault.connection(), false)?
                .into_iter()
                .map(|a| a.id)
                .collect();
        let summary = vault.run_monitor()?;
        let fetcher = HttpFetcher::new();
        let doc_checks = vault
            .check_due_doc_watches(&fetcher)
            .map(|results| results.len())
            .unwrap_or(0);
        let http = UreqClient::new();
        let delivered = vault.deliver_notifications(&http).unwrap_or(0);
        let new_alert_severities = if summary.alerts_created > 0 {
            api_tracker_core::alerts::list(vault.connection(), false)?
                .into_iter()
                .filter(|a| !before.contains(&a.id))
                .map(|a| a.severity)
                .collect()
        } else {
            Vec::new()
        };
        Ok(FullMonitorReport {
            summary,
            doc_checks,
            delivered,
            new_alert_severities,
        })
    })
}

#[tauri::command]
fn alerts_list(
    state: State<'_, AppState>,
    include_resolved: bool,
) -> CmdResult<Vec<api_tracker_core::alerts::Alert>> {
    with_vault(&state, |vault| {
        api_tracker_core::alerts::list(vault.connection(), include_resolved)
    })
}

#[tauri::command]
fn alert_acknowledge(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<api_tracker_core::alerts::Alert> {
    with_vault(&state, |vault| {
        api_tracker_core::alerts::acknowledge(vault.connection(), &id)
    })
}

#[tauri::command]
fn alert_resolve(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<api_tracker_core::alerts::Alert> {
    with_vault(&state, |vault| {
        api_tracker_core::alerts::resolve(vault.connection(), &id)
    })
}

// --- Documentation watches ---

#[tauri::command]
fn doc_watch_add(state: State<'_, AppState>, provider: String, url: String) -> CmdResult<DocWatch> {
    with_vault(&state, |vault| vault.watch_docs(&provider, &url))
}

#[tauri::command]
fn doc_watch_remove(state: State<'_, AppState>, url: String) -> CmdResult<bool> {
    with_vault(&state, |vault| vault.unwatch_docs(&url))
}

#[tauri::command]
fn doc_watch_list(state: State<'_, AppState>) -> CmdResult<Vec<DocWatch>> {
    with_vault(&state, |vault| vault.list_doc_watches())
}

/// Check a single watched URL now (network request). Returns the refreshed
/// watch; a change also raises an alert in the vault.
#[tauri::command]
fn doc_watch_check(state: State<'_, AppState>, url: String) -> CmdResult<DocWatch> {
    let fetcher = HttpFetcher::new();
    with_vault(&state, |vault| {
        let (_result, watch) = vault.check_doc_watch(&fetcher, &url)?;
        Ok(watch)
    })
}

/// Documentation-check history (validators and outcomes only — never page
/// content).
#[tauri::command]
fn doc_watch_history(
    state: State<'_, AppState>,
    url: Option<String>,
    limit: u32,
) -> CmdResult<Vec<api_tracker_core::docwatch::HistoryEntry>> {
    with_vault(&state, |vault| {
        vault.doc_watch_history(url.as_deref(), limit)
    })
}

// --- Notification channels (user-configured webhooks) ---

/// The URL may embed a user-chosen token, so it is wrapped in a
/// SecretString immediately, stored encrypted, and never logged or
/// returned; the frontend only ever sees the masked form.
#[tauri::command]
fn notification_channel_add(
    state: State<'_, AppState>,
    name: String,
    url: String,
    min_severity: String,
) -> CmdResult<api_tracker_core::notify::NotificationChannel> {
    let url = SecretString::new(url);
    with_vault(&state, |vault| {
        vault.notification_channel_add(&name, &url, &min_severity)
    })
}

#[tauri::command]
fn notification_channels(
    state: State<'_, AppState>,
) -> CmdResult<Vec<api_tracker_core::notify::NotificationChannel>> {
    with_vault(&state, |vault| vault.notification_channels())
}

#[tauri::command]
fn notification_channel_remove(state: State<'_, AppState>, ident: String) -> CmdResult<()> {
    with_vault(&state, |vault| vault.notification_channel_remove(&ident))
}

#[tauri::command]
fn notification_channel_enable(
    state: State<'_, AppState>,
    ident: String,
    enabled: bool,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        vault.notification_channel_enable(&ident, enabled)
    })
}

/// Send a clearly-labeled test payload through one channel (network).
#[tauri::command]
fn notification_channel_test(state: State<'_, AppState>, ident: String) -> CmdResult<String> {
    let http = UreqClient::new();
    with_vault(&state, |vault| {
        vault.notification_channel_test(&ident, &http)
    })
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

// --- Milestone 3: connectors, usage, budgets, permissions, activity ---

#[tauri::command]
fn credential_validate(
    state: State<'_, AppState>,
    selector: String,
) -> CmdResult<api_tracker_core::connectors::ValidationResult> {
    let http = UreqClient::new();
    with_vault(&state, |vault| vault.validate_credential(&selector, &http))
}

#[tauri::command]
fn credential_metadata(
    state: State<'_, AppState>,
    selector: String,
) -> CmdResult<api_tracker_core::connectors::FetchedMetadata> {
    let http = UreqClient::new();
    with_vault(&state, |vault| vault.fetch_metadata(&selector, &http))
}

#[tauri::command]
fn credential_permissions(
    state: State<'_, AppState>,
    selector: String,
    sync: bool,
) -> CmdResult<Option<api_tracker_core::permissions::StoredPermissions>> {
    let http = UreqClient::new();
    with_vault(&state, |vault| {
        if sync {
            Ok(Some(vault.sync_permissions(&selector, &http)?))
        } else {
            vault.get_permissions(&selector)
        }
    })
}

#[tauri::command]
fn provider_connect(
    state: State<'_, AppState>,
    provider: String,
    credential: String,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        vault.provider_connect(&provider, &credential)
    })
}

/// Store the provider's administrative key (encrypted in the vault). When a
/// connection already exists, replacing it requires reauthentication, so
/// `password` must be provided in that case.
#[tauri::command]
fn provider_admin_connect(
    state: State<'_, AppState>,
    provider: String,
    admin_key: String,
    org: Option<String>,
    password: Option<String>,
) -> CmdResult<String> {
    let admin_key = SecretString::new(admin_key);
    let http = UreqClient::new();
    with_vault(&state, |vault| {
        if vault.provider_connection_status(&provider)?.connected {
            let password = password.ok_or_else(|| {
                api_tracker_core::CoreError::InvalidInput(
                    "reauthentication is required to replace the administrative connection".into(),
                )
            })?;
            vault.verify_master_password(&SecretString::new(password))?;
        }
        vault.provider_admin_connect(&provider, &admin_key, org.as_deref(), Some(&http))
    })
}

/// Remove the administrative connection (requires reauthentication).
#[tauri::command]
fn provider_admin_disconnect(
    state: State<'_, AppState>,
    provider: String,
    password: String,
) -> CmdResult<bool> {
    with_vault(&state, |vault| {
        vault.verify_master_password(&SecretString::new(password))?;
        vault.provider_admin_disconnect(&provider)
    })
}

/// Live connection test (requires reauthentication).
#[tauri::command]
fn provider_admin_test(
    state: State<'_, AppState>,
    provider: String,
    password: String,
) -> CmdResult<String> {
    let http = UreqClient::new();
    with_vault(&state, |vault| {
        vault.verify_master_password(&SecretString::new(password))?;
        vault.provider_admin_test(&provider, &http)
    })
}

#[tauri::command]
fn provider_sync(
    state: State<'_, AppState>,
    provider: String,
    days: Option<u32>,
    from: Option<String>,
    to: Option<String>,
) -> CmdResult<api_tracker_core::vault::SyncReport> {
    let http = UreqClient::new();
    with_vault(&state, |vault| {
        if let Some(from) = &from {
            let from_ts = api_tracker_core::clock::parse_user_date(from)?;
            let to_ts = match &to {
                Some(t) => api_tracker_core::clock::parse_user_date(t)?,
                None => api_tracker_core::clock::now(),
            };
            vault.usage_sync_range(&provider, &http, from_ts, to_ts)
        } else if let Some(days) = days {
            vault.usage_sync(&provider, &http, days)
        } else {
            vault.usage_sync_default(&provider, &http)
        }
    })
}

#[tauri::command]
fn provider_connection_status(
    state: State<'_, AppState>,
    provider: String,
) -> CmdResult<ProviderConnection> {
    with_vault(&state, |vault| vault.provider_connection_status(&provider))
}

#[tauri::command]
fn provider_keys(
    state: State<'_, AppState>,
    provider: String,
) -> CmdResult<Vec<api_tracker_core::vault::ProviderKeyOverview>> {
    with_vault(&state, |vault| vault.provider_keys_overview(&provider))
}

#[tauri::command]
fn provider_projects(
    state: State<'_, AppState>,
    provider: String,
) -> CmdResult<Vec<api_tracker_core::vault::ProviderProjectOverview>> {
    with_vault(&state, |vault| vault.provider_projects_overview(&provider))
}

#[tauri::command]
fn provider_link_key(
    state: State<'_, AppState>,
    provider: String,
    api_key_id: String,
    credential: String,
) -> CmdResult<usize> {
    with_vault(&state, |vault| {
        vault.provider_link_key(&provider, &api_key_id, &credential)
    })
}

#[tauri::command]
fn provider_unlink_key(
    state: State<'_, AppState>,
    provider: String,
    api_key_id: String,
) -> CmdResult<usize> {
    with_vault(&state, |vault| {
        vault.provider_unlink_key(&provider, &api_key_id)
    })
}

#[tauri::command]
fn usage_report(
    state: State<'_, AppState>,
    project: Option<String>,
    credential: Option<String>,
) -> CmdResult<api_tracker_core::usage::UsageTotals> {
    let start = api_tracker_core::budget::period_start(api_tracker_core::clock::now());
    with_vault(&state, |vault| {
        vault.usage_totals(&start, credential.as_deref(), project.as_deref())
    })
}

/// Individual usage records (current month) with provider/source filters,
/// for the detailed usage listing.
#[tauri::command]
fn usage_records(
    state: State<'_, AppState>,
    project: Option<String>,
    credential: Option<String>,
    provider: Option<String>,
    source: String,
) -> CmdResult<Vec<api_tracker_core::usage::UsageSnapshot>> {
    let source = match source.as_str() {
        "provider" => api_tracker_core::usage::SourceFilter::Provider,
        "manual" => api_tracker_core::usage::SourceFilter::Manual,
        _ => api_tracker_core::usage::SourceFilter::All,
    };
    let start = api_tracker_core::budget::period_start(api_tracker_core::clock::now());
    with_vault(&state, |vault| {
        let (_totals, rows) = vault.usage_report(
            &start,
            credential.as_deref(),
            project.as_deref(),
            provider.as_deref(),
            source,
        )?;
        Ok(rows)
    })
}

#[tauri::command]
fn budget_cost_source_get(state: State<'_, AppState>) -> CmdResult<String> {
    with_vault(&state, |vault| {
        Ok(vault.budget_cost_source()?.as_str().to_string())
    })
}

#[tauri::command]
fn budget_cost_source_set(state: State<'_, AppState>, value: String) -> CmdResult<()> {
    with_vault(&state, |vault| {
        let source: api_tracker_core::usage::CostSource = value.parse()?;
        vault.set_budget_cost_source(source)
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn usage_record_manual(
    state: State<'_, AppState>,
    credential: String,
    model: Option<String>,
    input_tokens: i64,
    output_tokens: i64,
) -> CmdResult<()> {
    let now = api_tracker_core::clock::now_rfc3339();
    with_vault(&state, |vault| {
        vault.usage_record_manual(
            &credential,
            model.as_deref(),
            input_tokens,
            output_tokens,
            &now,
            &now,
        )?;
        Ok(())
    })
}

#[tauri::command]
fn budget_set(
    state: State<'_, AppState>,
    project: Option<String>,
    credential: Option<String>,
    amount: Option<String>,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        if let Some(p) = &project {
            vault.set_project_budget_dollars(p, amount.as_deref())
        } else if let Some(c) = &credential {
            vault.set_credential_budget_dollars(c, amount.as_deref())
        } else {
            Err(CoreError::InvalidInput(
                "pass a project or credential".into(),
            ))
        }
    })
}

#[tauri::command]
fn budget_report(
    state: State<'_, AppState>,
    project: Option<String>,
    credential: Option<String>,
) -> CmdResult<api_tracker_core::budget::BudgetReport> {
    with_vault(&state, |vault| {
        if let Some(p) = &project {
            vault.project_budget_report(p)
        } else if let Some(c) = &credential {
            vault.credential_budget_report(c)
        } else {
            Err(CoreError::InvalidInput(
                "pass a project or credential".into(),
            ))
        }
    })
}

#[tauri::command]
fn activity_list(
    state: State<'_, AppState>,
    credential: Option<String>,
    limit: u32,
) -> CmdResult<Vec<api_tracker_core::activity::ActivityEvent>> {
    with_vault(&state, |vault| {
        vault.activity_list(limit, credential.as_deref())
    })
}

// --- .env governance, credential versions, destinations, sync plans ---

#[tauri::command]
fn env_discover(
    state: State<'_, AppState>,
    project: Option<String>,
    path: Option<String>,
) -> CmdResult<Vec<api_tracker_core::envgov::EnvFileInfo>> {
    with_vault(&state, |vault| {
        vault.env_discover(
            project.as_deref(),
            path.as_deref().map(std::path::Path::new),
        )
    })
}

#[tauri::command]
fn env_preview(
    state: State<'_, AppState>,
    project: String,
    file: String,
) -> CmdResult<Vec<api_tracker_core::envgov::VarPreview>> {
    with_vault(&state, |vault| {
        vault.env_preview(&project, std::path::Path::new(&file))
    })
}

#[tauri::command]
fn env_import(
    state: State<'_, AppState>,
    project: String,
    file: String,
    keys: Option<Vec<String>>,
) -> CmdResult<Vec<api_tracker_core::vault::EnvImportOutcome>> {
    with_vault(&state, |vault| {
        vault.env_import(&project, std::path::Path::new(&file), keys.as_deref(), None)
    })
}

#[tauri::command]
fn env_drift(
    state: State<'_, AppState>,
    project: String,
) -> CmdResult<Vec<api_tracker_core::envgov::DriftFinding>> {
    with_vault(&state, |vault| vault.env_drift(&project))
}

/// A proposed `.env.example` update: names and comments only, never values.
#[derive(Serialize)]
struct EnvExampleProposal {
    proposed: String,
    diff: String,
    example_path: String,
    changed: bool,
}

/// Compute (without writing) the `.env.example` sibling for a values file.
/// Purely local file work; no vault access and no secret values involved —
/// the proposal carries variable names only and the diff is masked.
#[tauri::command]
fn env_example_preview(file: String) -> CmdResult<EnvExampleProposal> {
    use api_tracker_core::{envfile::EnvDocument, envgov};
    let file = PathBuf::from(&file);
    let inner = || -> Result<EnvExampleProposal, CoreError> {
        let content = std::fs::read_to_string(&file)?;
        let values = EnvDocument::parse(&content);
        let example_path = file
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(".env.example");
        let existing = std::fs::read_to_string(&example_path)
            .ok()
            .map(|text| EnvDocument::parse(&text));
        let old = existing.as_ref().map(|d| d.render()).unwrap_or_default();
        let proposed = envgov::generate_example(&values, existing.as_ref());
        let diff = envgov::render_diff(".env.example", &old, &proposed);
        let changed = old != proposed;
        Ok(EnvExampleProposal {
            proposed,
            diff,
            example_path: example_path.display().to_string(),
            changed,
        })
    };
    inner().map_err(Into::into)
}

/// Write a previously previewed `.env.example` (atomic, owner-only).
#[tauri::command]
fn env_example_write(example_path: String, content: String) -> CmdResult<()> {
    api_tracker_core::envgov::atomic_write(std::path::Path::new(&example_path), &content)
        .map_err(Into::into)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn env_export(
    state: State<'_, AppState>,
    project: String,
    path: String,
    vars: Option<Vec<String>>,
    password: String,
    overwrite: bool,
    ttl_minutes: Option<u64>,
) -> CmdResult<api_tracker_core::vault::EnvExportReport> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| {
        vault.env_export(
            &project,
            std::path::Path::new(&path),
            vars.as_deref(),
            &password,
            overwrite,
            ttl_minutes,
        )
    })
}

#[tauri::command]
fn env_cleanup(
    state: State<'_, AppState>,
    all: bool,
    force: bool,
) -> CmdResult<Vec<api_tracker_core::envgov::CleanupResult>> {
    with_vault(&state, |vault| vault.env_cleanup(all, force))
}

#[tauri::command]
fn env_exports_list(
    state: State<'_, AppState>,
) -> CmdResult<Vec<api_tracker_core::envgov::EnvExport>> {
    with_vault(&state, |vault| vault.env_exports(false))
}

/// Version history is reauthentication-gated: it reveals rotation cadence.
#[tauri::command]
fn credential_versions(
    state: State<'_, AppState>,
    id: String,
    password: String,
) -> CmdResult<Vec<api_tracker_core::vault::CredentialVersionInfo>> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| {
        vault.credential_version_history(&id, &password)
    })
}

#[tauri::command]
fn destination_catalog() -> Vec<&'static api_tracker_core::destinations::DestinationKindInfo> {
    api_tracker_core::destinations::catalog().iter().collect()
}

/// The destination credential (`auth`) is encrypted in the vault and is
/// write-only thereafter; it never crosses back to the frontend.
#[tauri::command]
fn destination_add(
    state: State<'_, AppState>,
    kind: String,
    name: String,
    config: serde_json::Value,
    auth: Option<String>,
) -> CmdResult<api_tracker_core::destinations::Destination> {
    let auth = auth.map(SecretString::new);
    with_vault(&state, |vault| {
        vault.destination_add(&kind, &name, config, auth.as_ref())
    })
}

/// Removing a destination is reauthentication-gated (it may hold an
/// administrative credential and deployed-secret bookkeeping).
#[tauri::command]
fn destination_remove(
    state: State<'_, AppState>,
    ident: String,
    password: String,
) -> CmdResult<api_tracker_core::destinations::Destination> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| vault.destination_remove(&ident, &password))
}

#[tauri::command]
fn destination_list(
    state: State<'_, AppState>,
) -> CmdResult<Vec<api_tracker_core::destinations::Destination>> {
    with_vault(&state, |vault| vault.destination_list())
}

#[tauri::command]
fn destination_test(state: State<'_, AppState>, ident: String) -> CmdResult<String> {
    let http = UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    with_vault(&state, |vault| {
        vault.destination_test(&ident, &http, &runner)
    })
}

#[tauri::command]
fn destination_attach(
    state: State<'_, AppState>,
    credential: String,
    destination: String,
    secret_name: String,
    environment: String,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        vault.destination_attach(&credential, &destination, &secret_name, &environment)
    })
}

#[tauri::command]
fn destination_detach(
    state: State<'_, AppState>,
    credential: String,
    destination: String,
    secret_name: Option<String>,
) -> CmdResult<usize> {
    with_vault(&state, |vault| {
        vault.destination_detach(&credential, &destination, secret_name.as_deref())
    })
}

#[tauri::command]
fn destination_attachments(
    state: State<'_, AppState>,
    credential: Option<String>,
) -> CmdResult<Vec<api_tracker_core::destinations::Attachment>> {
    with_vault(&state, |vault| {
        vault.destination_attachments(credential.as_deref())
    })
}

#[tauri::command]
fn destination_drift_check(
    state: State<'_, AppState>,
    credential: Option<String>,
) -> CmdResult<Vec<api_tracker_core::destinations::Attachment>> {
    let http = UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    with_vault(&state, |vault| {
        vault.destination_drift_check(credential.as_deref(), &http, &runner)
    })
}

/// Generate a plan (dry run). Nothing is written until `sync_plan_execute`.
#[tauri::command]
fn sync_plan_create(
    state: State<'_, AppState>,
    credential: String,
    note: String,
) -> CmdResult<api_tracker_core::syncplan::SyncPlan> {
    with_vault(&state, |vault| vault.sync_plan_create(&credential, &note))
}

#[tauri::command]
fn sync_plan_get(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<api_tracker_core::syncplan::SyncPlan> {
    with_vault(&state, |vault| vault.sync_plan_get(&id))
}

#[tauri::command]
fn sync_plans_list(
    state: State<'_, AppState>,
    credential: Option<String>,
    limit: u32,
) -> CmdResult<Vec<api_tracker_core::syncplan::SyncPlan>> {
    with_vault(&state, |vault| {
        vault.sync_plans(credential.as_deref(), limit)
    })
}

/// Execute a plan's pending or failed steps (retry re-runs failed steps).
/// Reauthentication-gated; never runs automatically.
#[tauri::command]
fn sync_plan_execute(
    state: State<'_, AppState>,
    id: String,
    only_destination: Option<String>,
    password: String,
) -> CmdResult<api_tracker_core::syncplan::SyncPlan> {
    let password = SecretString::new(password);
    let http = UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    with_vault(&state, |vault| {
        vault.sync_plan_execute(&id, only_destination.as_deref(), &password, &http, &runner)
    })
}

/// Roll executed steps back to the plan's previous version (where one is
/// retained). Reauthentication-gated.
#[tauri::command]
fn sync_plan_rollback(
    state: State<'_, AppState>,
    id: String,
    only_destination: Option<String>,
    password: String,
) -> CmdResult<api_tracker_core::syncplan::SyncPlan> {
    let password = SecretString::new(password);
    let http = UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    with_vault(&state, |vault| {
        vault.sync_plan_rollback(&id, only_destination.as_deref(), &password, &http, &runner)
    })
}

// --- Rotation, temporary access grants, test keys, lifecycle ---

#[tauri::command]
fn rotation_plan(
    state: State<'_, AppState>,
    credential: String,
    grace_minutes: i64,
    provider_project: Option<String>,
    old_key_id: Option<String>,
    note: String,
) -> CmdResult<vault::RotationView> {
    with_vault(&state, |vault| {
        vault.rotation_plan(
            &credential,
            grace_minutes,
            provider_project.as_deref(),
            old_key_id.as_deref(),
            &note,
        )
    })
}

#[tauri::command]
fn rotation_approve(
    state: State<'_, AppState>,
    id: String,
    password: String,
) -> CmdResult<vault::RotationView> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| vault.rotation_approve(&id, &password))
}

/// Advance a rotation as far as it can go. `provide_value` carries the
/// manually created replacement key (awaiting_manual_key state only); it is
/// wrapped in a SecretString immediately and never logged or echoed back.
#[tauri::command]
fn rotation_advance(
    state: State<'_, AppState>,
    id: String,
    password: String,
    provide_value: Option<String>,
    acknowledge_continued_use: bool,
) -> CmdResult<vault::RotationView> {
    let password = SecretString::new(password);
    let provide_value = provide_value.map(SecretString::new);
    let http = UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    with_vault(&state, |vault| {
        vault.rotation_advance(
            &id,
            &password,
            &http,
            &runner,
            provide_value,
            acknowledge_continued_use,
        )
    })
}

#[tauri::command]
fn rotation_rollback(
    state: State<'_, AppState>,
    id: String,
    password: String,
    revoke_new: bool,
) -> CmdResult<vault::RotationView> {
    let password = SecretString::new(password);
    let http = UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    with_vault(&state, |vault| {
        vault.rotation_rollback(&id, &password, &http, &runner, revoke_new)
    })
}

#[tauri::command]
fn rotation_complete_manual(
    state: State<'_, AppState>,
    id: String,
    password: String,
    note: String,
) -> CmdResult<vault::RotationView> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| {
        vault.rotation_complete_manual(&id, &password, &note)
    })
}

#[tauri::command]
fn rotation_cancel(
    state: State<'_, AppState>,
    id: String,
    password: String,
) -> CmdResult<vault::RotationView> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| vault.rotation_cancel(&id, &password))
}

#[tauri::command]
fn rotation_get(state: State<'_, AppState>, id: String) -> CmdResult<vault::RotationView> {
    with_vault(&state, |vault| vault.rotation_get(&id))
}

#[tauri::command]
fn rotations_list(
    state: State<'_, AppState>,
    credential: Option<String>,
    limit: u32,
) -> CmdResult<Vec<vault::RotationView>> {
    with_vault(&state, |vault| {
        vault.rotations(credential.as_deref(), limit)
    })
}

#[tauri::command]
fn rotation_events(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<Vec<api_tracker_core::rotation::RotationEvent>> {
    with_vault(&state, |vault| vault.rotation_events(&id))
}

#[tauri::command]
fn rotation_schedule_set(
    state: State<'_, AppState>,
    credential: String,
    every_days: i64,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        vault.rotation_schedule_set(&credential, every_days)
    })
}

#[tauri::command]
fn rotation_schedule_remove(state: State<'_, AppState>, credential: String) -> CmdResult<bool> {
    with_vault(&state, |vault| vault.rotation_schedule_remove(&credential))
}

#[tauri::command]
fn rotation_schedules(
    state: State<'_, AppState>,
) -> CmdResult<Vec<api_tracker_core::rotation::RotationSchedule>> {
    with_vault(&state, |vault| vault.rotation_schedules())
}

/// An access grant plus its computed status ("active", "expired",
/// "used_up", "revoked") so the UI reuses core's status logic.
#[derive(Serialize)]
struct AccessGrantDto {
    #[serde(flatten)]
    grant: api_tracker_core::access::AccessGrant,
    status: &'static str,
}

impl From<api_tracker_core::access::AccessGrant> for AccessGrantDto {
    fn from(grant: api_tracker_core::access::AccessGrant) -> Self {
        let status = grant.status(&api_tracker_core::clock::now_rfc3339());
        Self { grant, status }
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn access_grant_create(
    state: State<'_, AppState>,
    project: String,
    label: String,
    credentials: Vec<String>,
    ttl_minutes: u64,
    max_launches: i64,
    max_duration_secs: Option<i64>,
    budget_warn: Option<String>,
) -> CmdResult<AccessGrantDto> {
    with_vault(&state, |vault| {
        let grant = vault.access_grant_create(
            &project,
            &label,
            &credentials,
            ttl_minutes,
            max_launches,
            max_duration_secs,
            budget_warn.as_deref(),
        )?;
        Ok(grant.into())
    })
}

#[tauri::command]
fn access_grants(
    state: State<'_, AppState>,
    include_inactive: bool,
) -> CmdResult<Vec<AccessGrantDto>> {
    with_vault(&state, |vault| {
        Ok(vault
            .access_grants(include_inactive)?
            .into_iter()
            .map(Into::into)
            .collect())
    })
}

#[derive(Serialize)]
struct RunningSessionDto {
    session_id: String,
    pid: i64,
}

#[derive(Serialize)]
struct GrantEndDto {
    grant: AccessGrantDto,
    running: Vec<RunningSessionDto>,
}

/// End a grant: new launches are refused immediately. The desktop app does
/// NOT terminate processes — it surfaces the recorded running PIDs so the
/// user can decide (the CLI's `access end --kill` sends SIGTERM).
#[tauri::command]
fn access_grant_end(state: State<'_, AppState>, id: String) -> CmdResult<GrantEndDto> {
    with_vault(&state, |vault| {
        let (grant, running) = vault.access_grant_end(&id)?;
        Ok(GrantEndDto {
            grant: grant.into(),
            running: running
                .into_iter()
                .map(|(session_id, pid)| RunningSessionDto { session_id, pid })
                .collect(),
        })
    })
}

#[tauri::command]
fn credential_timeline(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<Vec<vault::TimelineEvent>> {
    with_vault(&state, |vault| vault.credential_timeline(&id))
}

#[derive(Serialize)]
struct PermissionsPreviewDto {
    stored: Option<api_tracker_core::permissions::StoredPermissions>,
    fetched: api_tracker_core::connectors::FetchedPermissions,
    normalized: api_tracker_core::permissions::NormalizedPermissions,
}

/// Fetch fresh permissions WITHOUT storing them, alongside the stored
/// snapshot — the before/after diff for permission review.
#[tauri::command]
fn permissions_preview(state: State<'_, AppState>, id: String) -> CmdResult<PermissionsPreviewDto> {
    let http = UreqClient::new();
    with_vault(&state, |vault| {
        let (stored, fetched, normalized) = vault.permissions_preview(&id, &http)?;
        Ok(PermissionsPreviewDto {
            stored,
            fetched,
            normalized,
        })
    })
}

/// Live provider-side key listing via the administrative connection (for
/// picking the OLD key id before a rotation).
#[tauri::command]
fn provider_list_keys(
    state: State<'_, AppState>,
    provider: String,
    provider_project: Option<String>,
) -> CmdResult<Vec<api_tracker_core::connectors::ProviderKeyListing>> {
    let http = UreqClient::new();
    with_vault(&state, |vault| {
        vault.provider_list_keys(&provider, provider_project.as_deref(), &http)
    })
}

#[derive(Serialize)]
struct TestKeyDto {
    credential: Credential,
    /// Honest enforcement notes: what the provider enforces vs. what is only
    /// a local reminder. Rendered verbatim by the UI.
    notes: Vec<String>,
}

/// Create a REAL provider-side test key (reauthentication-gated).
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn test_key_create(
    state: State<'_, AppState>,
    project: String,
    provider: String,
    provider_project: Option<String>,
    name: String,
    ttl_minutes: u64,
    password: String,
) -> CmdResult<TestKeyDto> {
    let password = SecretString::new(password);
    let http = UreqClient::new();
    with_vault(&state, |vault| {
        let (credential, notes) = vault.test_key_create(
            &project,
            &provider,
            provider_project.as_deref(),
            &name,
            ttl_minutes,
            &password,
            &http,
        )?;
        Ok(TestKeyDto { credential, notes })
    })
}

/// Revoke a credential AT THE PROVIDER (usually irreversible) and mark it
/// revoked locally. Reauthentication-gated; the UI must confirm first.
#[tauri::command]
fn credential_provider_revoke(
    state: State<'_, AppState>,
    id: String,
    password: String,
) -> CmdResult<String> {
    let password = SecretString::new(password);
    let http = UreqClient::new();
    with_vault(&state, |vault| {
        vault.credential_provider_revoke(&id, &password, &http)
    })
}

fn main() {
    let data_dir = vault::default_data_dir().expect("could not determine the data directory");
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
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
            provider_get,
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
            scan_path,
            suppression_add,
            hook_status,
            hook_install,
            hook_remove,
            monitor_run,
            monitor_run_full,
            alerts_list,
            alert_acknowledge,
            alert_resolve,
            doc_watch_add,
            doc_watch_remove,
            doc_watch_list,
            doc_watch_check,
            doc_watch_history,
            notification_channel_add,
            notification_channels,
            notification_channel_remove,
            notification_channel_enable,
            notification_channel_test,
            credential_validate,
            credential_metadata,
            credential_permissions,
            provider_connect,
            provider_admin_connect,
            provider_admin_disconnect,
            provider_admin_test,
            provider_sync,
            provider_connection_status,
            provider_keys,
            provider_projects,
            provider_link_key,
            provider_unlink_key,
            usage_records,
            budget_cost_source_get,
            budget_cost_source_set,
            usage_report,
            usage_record_manual,
            budget_set,
            budget_report,
            activity_list,
            backup_create,
            backup_verify,
            backup_restore,
            env_discover,
            env_preview,
            env_import,
            env_drift,
            env_example_preview,
            env_example_write,
            env_export,
            env_cleanup,
            env_exports_list,
            credential_versions,
            destination_catalog,
            destination_add,
            destination_remove,
            destination_list,
            destination_test,
            destination_attach,
            destination_detach,
            destination_attachments,
            destination_drift_check,
            sync_plan_create,
            sync_plan_get,
            sync_plans_list,
            sync_plan_execute,
            sync_plan_rollback,
            rotation_plan,
            rotation_approve,
            rotation_advance,
            rotation_rollback,
            rotation_complete_manual,
            rotation_cancel,
            rotation_get,
            rotations_list,
            rotation_events,
            rotation_schedule_set,
            rotation_schedule_remove,
            rotation_schedules,
            access_grant_create,
            access_grants,
            access_grant_end,
            credential_timeline,
            permissions_preview,
            provider_list_keys,
            test_key_create,
            credential_provider_revoke,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the API Tracker desktop app");
}
