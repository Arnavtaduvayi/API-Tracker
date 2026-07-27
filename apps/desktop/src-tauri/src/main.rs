//! Tethra desktop backend: thin Tauri commands over `api-tracker-core`.
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

/// One in-flight "Track API activity" flow: the scan result and the plan
/// built from it. Held in Rust because a `LinkPlan`'s file contents and
/// digest deliberately never cross the IPC boundary — the frontend sees
/// the rendered diff, the backend applies exactly the previewed plan.
struct TrackingSession {
    detection: tracking_detect::ProjectDetection,
    project: tracking_plan::ProjectRef,
    plan: Option<tracking_plan::TrackingPlan>,
    /// Destinations read out of this project's own files that the user has
    /// explicitly approved in THIS review, keyed by provider.
    ///
    /// Repository content may suggest a destination; it may never authorize
    /// one (ADR 0024). The desktop's only way to fill this map is
    /// `tracking_origin_approve`, driven by a per-origin checkbox that
    /// starts unchecked. "Start tracking" reads the map — it can never add
    /// to it, which is what makes approving the setup and approving a
    /// destination two separate decisions (ZFT-004).
    approved_origins: std::collections::BTreeMap<String, String>,
}

/// State of the unsigned-build foreground fallback (`gateway serve` as a
/// child of this app).
#[derive(Default)]
struct ForegroundGateway {
    child: Option<std::process::Child>,
    /// Set when a child we started is no longer running. The dashboard must
    /// be able to tell "never started" from "started and died", because the
    /// second one means tracking silently stopped (ZFT-031).
    exited: Option<String>,
}

struct AppState {
    slot: Mutex<VaultSlot>,
    data_dir: PathBuf,
    tracking: Mutex<Option<TrackingSession>>,
    /// A foreground `gateway serve` child (the unsigned-build fallback).
    /// Killed explicitly on `RunEvent::Exit`: `std::process::Child` does
    /// NOT kill on drop, so without that the child outlived the app while
    /// the UI promised "tracking pauses when Tethra closes" (ZFT-021).
    foreground_gateway: Mutex<ForegroundGateway>,
}

impl AppState {
    fn paths(&self) -> VaultPaths {
        VaultPaths::new(self.data_dir.clone())
    }
}

/// Install the custom-origin route verification key into a running gateway
/// (ADR 0021).
///
/// Without this a custom-origin route (a Supabase per-project host, say)
/// loads but cannot be verified, so it answers 503 forever — and the 503 text
/// told the user to unlock the vault, which did nothing because nothing
/// installed the key. Called on unlock, on route add/enable, and when the
/// routes panel loads.
///
/// Not reauth-gated: this key verifies route integrity only. It is not
/// derived from the fingerprint key, cannot decrypt anything, and cannot
/// confirm a guess about a credential. Best-effort — a stopped gateway is
/// the normal case. `mint` creates the key when the vault has never had one;
/// pass false so an unrelated command never mints route-signing material.
fn install_gateway_route_key(state: &AppState, vault: &mut UnlockedVault, mint: bool) {
    if !gw_control::instance_is_live(&state.data_dir) {
        return;
    }
    if !mint && !gw_routes::route_key_exists(vault.connection()).unwrap_or(false) {
        return;
    }
    if let Ok(key) = vault.gateway_route_mac_key() {
        let _ = gw_control::push_route_key(&state.data_dir, &key);
    }
}

/// Signal a running gateway that the vault locked (ADR 0020, SI-9).
///
/// The matching key is a vault-derived guess-confirmation oracle over every
/// in-scope fingerprint (THREAT_MODEL GW-6); the push-key consent copy
/// promises it is "dropped on stop, revoke, or lock". Every desktop lock
/// path — explicit lock, both inactivity auto-lock paths, backup restore,
/// and app exit — must send this signal.
///
/// The POLICY lives in the gateway service (`service::lock_disposition`), so
/// the frontend only reports the event plus the locking session's auto-lock
/// duration (`None` when it could not be read — the service then applies the
/// 8-hour retention cap, or revokes immediately when the consented
/// keep-while-locked toggle is OFF, which is the default). Best-effort by
/// construction: no running gateway, no control socket, or a Windows build
/// (no control channel, hence no resident key) must never make locking fail.
fn notify_gateway_vault_locked(data_dir: &std::path::Path, ttl_minutes: Option<u32>) {
    let _ = gw_control::notify_vault_locked(data_dir, ttl_minutes);
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
        // Take the vault out and drop it AFTER releasing the mutex: the
        // drop checkpoints the WAL (bounded, but it can wait for a
        // concurrent reader), and holding the state mutex through that
        // would stall every other vault command.
        let expired = slot.vault.take(); // drop -> keys zeroized
        drop(slot);
        drop(expired);
        notify_gateway_vault_locked(&state.data_dir, Some(auto_lock_minutes));
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
    let mut auto_locked_minutes = None;
    if let Some(vault) = slot.vault.as_ref() {
        let minutes = vault.settings().auto_lock_minutes;
        if minutes > 0
            && slot.last_activity.elapsed() >= Duration::from_secs(u64::from(minutes) * 60)
        {
            slot.vault = None;
            auto_locked_minutes = Some(minutes);
        }
    }
    if let Some(minutes) = auto_locked_minutes {
        notify_gateway_vault_locked(&state.data_dir, Some(minutes));
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
    drop(slot);
    // A re-authorized session cancels any pending keep-while-locked
    // retention deadline in a running gateway (ADR 0020). No credential-
    // bearing key material moves: the matching key stays revoked until the
    // user explicitly re-pushes it through the reauth-gated flow.
    let _ = gw_control::notify_vault_unlocked(&state.data_dir);
    // Custom-origin routes, by contrast, become forwardable again here
    // (ADR 0021) — the user already consented to them, and the key involved
    // verifies route integrity only.
    let _ = with_vault(&state, |vault| {
        install_gateway_route_key(&state, vault, false);
        Ok(())
    });
    Ok(())
}

#[tauri::command]
fn vault_lock(state: State<'_, AppState>) -> CmdResult<()> {
    let mut slot = state.slot.lock().expect("vault state mutex poisoned");
    // Drop after releasing the mutex — the drop checkpoints the WAL and can
    // briefly wait for a concurrent reader.
    let minutes = slot.vault.as_ref().map(|v| v.settings().auto_lock_minutes);
    let vault = slot.vault.take();
    drop(slot);
    drop(vault);
    notify_gateway_vault_locked(&state.data_dir, minutes);
    Ok(())
}

#[tauri::command]
fn reauth(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| vault.verify_master_password(&password))
}

#[tauri::command]
fn vault_change_password(
    state: State<'_, AppState>,
    current: String,
    new: String,
) -> CmdResult<()> {
    let current = SecretString::new(current);
    let new = SecretString::new(new);
    with_vault(&state, |vault| vault.change_master_password(&current, &new))
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

#[derive(Serialize)]
struct ScanPathReport {
    findings: Vec<Finding>,
    /// False when a history scan hit a time/size limit — the result is then
    /// NOT a clean full scan and the warnings say what was skipped.
    coverage_complete: bool,
    coverage_warnings: Vec<String>,
}

#[tauri::command]
fn scan_path(
    state: State<'_, AppState>,
    path: String,
    mode: String,
    mark_exposed: bool,
    history_depth: Option<u32>,
) -> CmdResult<ScanPathReport> {
    let p = std::path::PathBuf::from(&path);
    // Collect content OUTSIDE the vault lock: git subprocess time (bounded
    // but potentially minutes on a big history) must not stall every other
    // vault command behind the shared mutex (CONC-06/CONC-01).
    let (units, complete, warnings) = match mode.as_str() {
        "staged" => {
            let root = api_tracker_core::gitrepo::repo_root(&p).map_err(ErrDto::from)?;
            (
                api_tracker_core::gitrepo::staged_units(&root).map_err(ErrDto::from)?,
                true,
                Vec::new(),
            )
        }
        // Depth is user-chosen; None scans the FULL history.
        "history" => {
            let root = api_tracker_core::gitrepo::repo_root(&p).map_err(ErrDto::from)?;
            let scan = api_tracker_core::gitrepo::history_added_units(
                &root,
                history_depth.map(|n| n as usize),
            )
            .map_err(ErrDto::from)?;
            (scan.units, scan.complete, scan.warnings)
        }
        _ => (
            api_tracker_core::gitrepo::working_tree_units(&p).map_err(ErrDto::from)?,
            true,
            Vec::new(),
        ),
    };
    with_vault(&state, |vault| {
        let mut findings = vault.scan_units(units)?;
        if mark_exposed {
            vault.mark_findings_exposed(&findings)?;
        }
        findings.sort_by_key(|f| std::cmp::Reverse(f.confidence));
        Ok(ScanPathReport {
            findings,
            coverage_complete: complete,
            coverage_warnings: warnings,
        })
    })
}

/// Re-verify a repository's outstanding exposure alerts with a full scan,
/// resolving them only if it is clean AND complete (OBS-001). Exposure
/// alerts never auto-resolve on their own; this is the qualifying clean
/// re-scan. The slow git collection runs outside the vault lock.
#[tauri::command]
fn scan_reverify(
    state: State<'_, AppState>,
    path: String,
) -> CmdResult<api_tracker_core::vault::RepoReverifyReport> {
    let p = std::path::PathBuf::from(&path);
    let collected = api_tracker_core::gitrepo::collect_full_repo_scan(&p).map_err(ErrDto::from)?;
    with_vault(&state, |vault| {
        vault.reverify_repo_exposure_collected(&p, collected)
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
fn suppression_list(
    state: State<'_, AppState>,
) -> CmdResult<Vec<api_tracker_core::vault::Suppression>> {
    with_vault(&state, |vault| vault.list_suppressions())
}

#[tauri::command]
fn suppression_remove(state: State<'_, AppState>, suppression_key: String) -> CmdResult<()> {
    with_vault(&state, |vault| vault.remove_suppression(&suppression_key))
}

#[tauri::command]
fn hook_status(path: String) -> CmdResult<api_tracker_core::hooks::HookStatus> {
    api_tracker_core::hooks::status(std::path::Path::new(&path)).map_err(Into::into)
}

// hook_install/hook_remove write to a repo's `.git/hooks`, so they are gated
// behind an unlocked vault: a locked session must not mutate the filesystem.
#[tauri::command]
fn hook_install(
    state: State<'_, AppState>,
    path: String,
    force: bool,
) -> CmdResult<api_tracker_core::hooks::HookStatus> {
    with_vault(&state, |_vault| {
        api_tracker_core::hooks::install(std::path::Path::new(&path), force)?;
        api_tracker_core::hooks::status(std::path::Path::new(&path))
    })
}

#[tauri::command]
fn hook_remove(
    state: State<'_, AppState>,
    path: String,
) -> CmdResult<api_tracker_core::hooks::HookStatus> {
    with_vault(&state, |_vault| {
        api_tracker_core::hooks::remove(std::path::Path::new(&path))?;
        api_tracker_core::hooks::status(std::path::Path::new(&path))
    })
}

// --- Monitoring + alerts ---

#[tauri::command]
fn monitor_status(state: State<'_, AppState>) -> CmdResult<api_tracker_core::vault::MonitorStatus> {
    with_vault(&state, |vault| vault.monitor_status())
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
        let fetcher = HttpFetcher::new();
        let http = UreqClient::new();
        // Shared core orchestration: local rules + best-effort network
        // phases, recording last-run status for `monitor_status`.
        let report = vault.run_monitor_cycle(Some((&fetcher, &http)))?;
        let new_alert_severities = if report.summary.alerts_created > 0 {
            api_tracker_core::alerts::list(vault.connection(), false)?
                .into_iter()
                .filter(|a| !before.contains(&a.id))
                .map(|a| a.severity)
                .collect()
        } else {
            Vec::new()
        };
        Ok(FullMonitorReport {
            summary: report.summary,
            doc_checks: report.doc_checks,
            delivered: report.webhooks_delivered,
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
    master: String,
) -> CmdResult<()> {
    let password = SecretString::new(password);
    let master = SecretString::new(master);
    with_vault(&state, |vault| {
        vault.set_project_password(&ident, &password, &master)
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

/// Delete a credential. Reauthenticated in core (IPC-02): the React confirm
/// dialog is UX only — the master-password re-verification below is the
/// authorization, so a direct `invoke` cannot delete without it.
#[tauri::command]
fn credential_delete(
    state: State<'_, AppState>,
    selector: String,
    password: String,
) -> CmdResult<()> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| {
        vault.delete_credential(&selector, &password)?;
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
    let minutes = {
        let mut slot = state.slot.lock().expect("vault state mutex poisoned");
        let minutes = slot.vault.as_ref().map(|v| v.settings().auto_lock_minutes);
        slot.vault = None;
        minutes
    };
    // This is a lock event too — and the OLD vault's matching key must not
    // stay resident in the gateway to attribute traffic against a vault that
    // may no longer even exist (ADR 0020).
    notify_gateway_vault_locked(&state.data_dir, minutes);
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
        // Reauth is enforced in core (a direct invoke cannot bypass it).
        vault.provider_admin_disconnect(&provider, &SecretString::new(password))
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
fn pricing_records(
    state: State<'_, AppState>,
    all: bool,
) -> CmdResult<Vec<api_tracker_core::pricing::PricingRecord>> {
    with_vault(&state, |vault| {
        if all {
            vault.pricing_catalog()
        } else {
            vault.pricing_effective(&api_tracker_core::clock::now_rfc3339())
        }
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn pricing_set_override(
    state: State<'_, AppState>,
    provider: String,
    model: String,
    input: Option<String>,
    output: Option<String>,
    cached_input: Option<String>,
    per_request: Option<String>,
    unit: Option<String>,
    note: Option<String>,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        let parse =
            |v: &Option<String>| -> Result<Option<i64>, api_tracker_core::error::CoreError> {
                match v.as_deref().map(str::trim) {
                    None | Some("") => Ok(None),
                    Some(s) => Ok(Some(api_tracker_core::pricing::dollars_to_micros(s)?)),
                }
            };
        let unit = match unit.as_deref() {
            None | Some("") | Some("tokens") => api_tracker_core::pricing::Unit::Tokens,
            Some("requests") => api_tracker_core::pricing::Unit::Requests,
            Some(other) => {
                return Err(api_tracker_core::error::CoreError::InvalidInput(format!(
                    "unknown unit '{other}'"
                )))
            }
        };
        let spec = api_tracker_core::pricing::OverrideSpec {
            unit: Some(unit),
            input_price_per_m_micros: parse(&input)?,
            cached_input_price_per_m_micros: parse(&cached_input)?,
            output_price_per_m_micros: parse(&output)?,
            batch_input_price_per_m_micros: None,
            batch_output_price_per_m_micros: None,
            per_request_micros: parse(&per_request)?,
            effective_from: None,
            note: note.unwrap_or_default(),
        };
        vault.set_pricing_override(&provider, &model, spec)
    })
}

#[tauri::command]
fn pricing_remove_override(
    state: State<'_, AppState>,
    provider: String,
    model: String,
) -> CmdResult<usize> {
    with_vault(&state, |vault| {
        vault.remove_pricing_override(&provider, &model)
    })
}

#[tauri::command]
fn pricing_import(
    state: State<'_, AppState>,
    json: String,
) -> CmdResult<api_tracker_core::pricing::ImportOutcome> {
    with_vault(&state, |vault| vault.pricing_import(&json))
}

#[tauri::command]
fn pricing_export(state: State<'_, AppState>, provider: Option<String>) -> CmdResult<String> {
    with_vault(&state, |vault| vault.pricing_export(provider.as_deref()))
}

#[tauri::command]
fn provider_account_sync(
    state: State<'_, AppState>,
    provider: String,
) -> CmdResult<api_tracker_core::connectors::AccountInfo> {
    with_vault(&state, |vault| {
        let http = api_tracker_core::http::UreqClient::new();
        vault.provider_account_sync(&provider, &http)
    })
}

#[tauri::command]
fn template_list() -> Vec<api_tracker_core::templates::Template> {
    api_tracker_core::templates::catalog()
}

#[tauri::command]
fn template_apply(
    state: State<'_, AppState>,
    template_id: String,
    project: String,
    write_example_dir: Option<String>,
) -> CmdResult<api_tracker_core::vault::TemplateApplyOutcome> {
    with_vault(&state, |vault| {
        vault.template_apply(
            &template_id,
            &project,
            write_example_dir.as_deref().map(std::path::Path::new),
        )
    })
}

#[tauri::command]
fn stack_detect(
    state: State<'_, AppState>,
    project: Option<String>,
    repo: Option<String>,
) -> CmdResult<Vec<api_tracker_core::stackdetect::DetectionReport>> {
    with_vault(&state, |vault| match (project, repo) {
        (_, Some(repo)) => Ok(vec![vault.stack_detect_path(std::path::Path::new(&repo))?]),
        (Some(project), None) => vault.stack_detect_project(&project),
        (None, None) => Err(api_tracker_core::error::CoreError::InvalidInput(
            "pass a project or a repository path".into(),
        )),
    })
}

#[tauri::command]
fn stack_decide(
    state: State<'_, AppState>,
    repo: String,
    template_id: String,
    decision: String,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        vault.stack_decide(std::path::Path::new(&repo), &template_id, &decision)
    })
}

#[tauri::command]
fn stack_prefs(
    state: State<'_, AppState>,
) -> CmdResult<Vec<api_tracker_core::vault::StackPreference>> {
    with_vault(&state, |vault| vault.stack_preferences())
}

#[tauri::command]
fn stack_prefs_reset(state: State<'_, AppState>, repo: Option<String>) -> CmdResult<usize> {
    with_vault(&state, |vault| {
        vault.stack_preferences_reset(repo.as_deref().map(std::path::Path::new))
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
///
/// Gated behind an unlocked vault (`with_vault`): these commands read and
/// write arbitrary host paths, so — even though they touch no vault data —
/// they must not be callable while the vault is locked. That bounds the
/// filesystem-write primitive to a trusted, unlocked session.
#[tauri::command]
fn env_example_preview(state: State<'_, AppState>, file: String) -> CmdResult<EnvExampleProposal> {
    use api_tracker_core::{envfile::EnvDocument, envgov};
    let file = PathBuf::from(&file);
    with_vault(&state, |_vault| {
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
    })
}

/// Write a previously previewed `.env.example` (names only, never values).
/// Authorized and confined in core: reauthentication, plus containment of
/// the target to a `.env.example` inside one of the project's registered
/// repositories (IPC-01/FS-09). The React confirmation dialog is UX only —
/// it is NOT the authorization; the master password re-verification in core
/// is. Returns the canonical path written.
#[tauri::command]
fn env_example_write(
    state: State<'_, AppState>,
    project: String,
    example_path: String,
    content: String,
    password: String,
) -> CmdResult<String> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| {
        vault
            .env_example_write(
                &project,
                std::path::Path::new(&example_path),
                &content,
                &password,
            )
            .map(|p| p.display().to_string())
    })
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
fn destination_delete_secret(
    state: State<'_, AppState>,
    ident: String,
    secret_name: String,
    password: String,
) -> CmdResult<String> {
    let http = UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    with_vault(&state, |vault| {
        vault.destination_delete_secret(
            &ident,
            &secret_name,
            &SecretString::new(password.clone()),
            &http,
            &runner,
        )
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
) -> CmdResult<Vec<api_tracker_core::destinations::DriftCheckOutcome>> {
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
fn access_sessions(
    state: State<'_, AppState>,
    include_ended: bool,
    limit: u32,
) -> CmdResult<Vec<api_tracker_core::inject::ProcessSession>> {
    with_vault(&state, |vault| {
        vault.list_process_sessions(limit, !include_ended)
    })
}

#[derive(Serialize)]
struct SessionKillDto {
    session_id: String,
    pid: i64,
    /// True only when the launch identity matched and the signal was
    /// accepted. `outcome` carries the truthful detail (refused / already
    /// exited / signal failed) for display.
    signalled: bool,
    outcome: api_tracker_core::inject::TerminationOutcome,
    outcome_text: String,
}

/// Best-effort local SIGTERM to a recorded session PID. The recorded launch
/// identity is re-verified in core immediately before signalling; a PID that
/// can no longer be confirmed (reuse, tampering, no recorded identity) is
/// refused. The frontend must confirm first; this is a local control and
/// never touches the provider.
#[tauri::command]
fn access_session_kill(state: State<'_, AppState>, id: String) -> CmdResult<SessionKillDto> {
    with_vault(&state, |vault| {
        let (session_id, pid, outcome) = vault.terminate_process_session(&id)?;
        Ok(SessionKillDto {
            session_id,
            pid,
            signalled: outcome == api_tracker_core::inject::TerminationOutcome::Signalled,
            outcome_text: outcome.describe(),
            outcome,
        })
    })
}

#[tauri::command]
fn notification_history(
    state: State<'_, AppState>,
    limit: u32,
) -> CmdResult<Vec<api_tracker_core::activity::ActivityEvent>> {
    with_vault(&state, |vault| vault.notification_history(limit))
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

// --- Runtime API observability (metadata only) ---

use api_tracker_core::runtime::aggregate;
use api_tracker_core::runtime::model as obs_model;

/// A service plus its metrics, for the overview dashboard.
#[derive(Serialize)]
struct ObserveServiceOverview {
    #[serde(flatten)]
    service: obs_model::ObservedServiceRow,
    metrics: aggregate::Metrics,
}

#[tauri::command]
fn observe_overview(state: State<'_, AppState>) -> CmdResult<Vec<ObserveServiceOverview>> {
    with_vault(&state, |vault| {
        let mut out = Vec::new();
        for service in vault.observe_services()? {
            let metrics = aggregate::service_metrics(vault.connection(), &service.id, None)?;
            out.push(ObserveServiceOverview { service, metrics });
        }
        Ok(out)
    })
}

#[tauri::command]
fn observe_services(state: State<'_, AppState>) -> CmdResult<Vec<obs_model::ObservedServiceRow>> {
    with_vault(&state, |vault| vault.observe_services())
}

#[tauri::command]
fn observe_service(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<obs_model::ObservedServiceRow> {
    with_vault(&state, |vault| vault.observe_service(&id))
}

#[tauri::command]
fn observe_service_metrics(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<aggregate::Metrics> {
    with_vault(&state, |vault| {
        aggregate::service_metrics(vault.connection(), &id, None)
    })
}

#[tauri::command]
fn observe_service_endpoints(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<Vec<obs_model::ObservedEndpointRow>> {
    with_vault(&state, |vault| vault.observe_service_endpoints(&id))
}

#[tauri::command]
fn observe_service_events(
    state: State<'_, AppState>,
    id: String,
    limit: u32,
) -> CmdResult<Vec<obs_model::RuntimeEventRow>> {
    with_vault(&state, |vault| vault.observe_service_events(&id, limit))
}

#[tauri::command]
fn observe_sessions(
    state: State<'_, AppState>,
    project: Option<String>,
    limit: u32,
) -> CmdResult<Vec<obs_model::ObservationSessionRow>> {
    with_vault(&state, |vault| {
        vault.observe_sessions(project.as_deref(), limit)
    })
}

#[tauri::command]
fn observe_session(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<obs_model::ObservationSessionRow> {
    with_vault(&state, |vault| vault.observe_session(&id))
}

#[tauri::command]
fn observe_session_metrics(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<aggregate::Metrics> {
    with_vault(&state, |vault| {
        aggregate::session_metrics(vault.connection(), &vault.observe_session(&id)?.id)
    })
}

#[tauri::command]
fn observe_session_events(
    state: State<'_, AppState>,
    id: String,
    limit: u32,
) -> CmdResult<Vec<obs_model::RuntimeEventRow>> {
    with_vault(&state, |vault| vault.observe_session_events(&id, limit))
}

#[tauri::command]
fn observe_session_attributions(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<Vec<obs_model::CredentialAttributionRow>> {
    with_vault(&state, |vault| vault.observe_session_attributions(&id))
}

#[tauri::command]
fn observe_session_compat(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<Vec<obs_model::CompatibilityResultRow>> {
    with_vault(&state, |vault| vault.observe_session_compat(&id))
}

#[tauri::command]
fn observe_credential_activity(
    state: State<'_, AppState>,
    selector: String,
    limit: u32,
) -> CmdResult<Vec<obs_model::CredentialAttributionRow>> {
    with_vault(&state, |vault| {
        vault.observe_credential_activity(&selector, limit)
    })
}

#[tauri::command]
fn observe_cert_status(
    state: State<'_, AppState>,
) -> CmdResult<api_tracker_core::runtime::store::CertStatus> {
    with_vault(&state, |vault| vault.observe_ca_status())
}

/// Rotate the local CA. Reauthenticated in core (the CA removal verifies the
/// master password); generation happens in the observe crate.
#[tauri::command]
fn observe_cert_rotate(
    state: State<'_, AppState>,
    password: String,
) -> CmdResult<api_tracker_core::runtime::store::CertStatus> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| {
        vault.observe_ca_remove(&password)?;
        let g = api_tracker_observe::ca::generate_ca(vault.vault_id())?;
        vault.observe_ca_store(
            &g.cert_pem,
            &g.key_der,
            &g.fingerprint_sha256,
            &g.serial_hex,
            &g.not_after,
        )?;
        vault.observe_ca_status()
    })
}

#[tauri::command]
fn observe_cert_remove(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| vault.observe_ca_remove(&password))
}

/// Mode C: install the CA into the OS trust store. Reauthenticated; the OS
/// shows its own prompt (never suppressed).
#[tauri::command]
fn observe_cert_install_system(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| {
        vault.verify_master_password(&password)?;
        let (pem, _key, _fp) = vault
            .observe_ca_material()?
            .ok_or_else(|| CoreError::InvalidInput("no local CA yet".into()))?;
        let dir = vault.paths().data_dir.clone();
        api_tracker_observe::systemtrust::install(&dir, &pem)?;
        vault
            .observe_ca_set_system_trust("installed", Some(&api_tracker_core::clock::now_rfc3339()))
    })
}

#[tauri::command]
fn observe_cert_uninstall_system(state: State<'_, AppState>) -> CmdResult<()> {
    with_vault(&state, |vault| {
        api_tracker_observe::systemtrust::remove()?;
        vault.observe_ca_set_system_trust("absent", None)
    })
}

#[tauri::command]
fn observe_settings_get(
    state: State<'_, AppState>,
) -> CmdResult<api_tracker_core::runtime::settings::ObservabilitySettings> {
    with_vault(&state, |vault| vault.observe_settings())
}

#[tauri::command]
fn observe_settings_set(
    state: State<'_, AppState>,
    default_mode: Option<String>,
    event_days: Option<u32>,
    aggregate_days: Option<u32>,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        let mut s = vault.observe_settings()?;
        if let Some(m) = default_mode {
            s.default_mode = obs_model::ObservationMode::parse(&m)
                .ok_or_else(|| CoreError::InvalidInput(format!("invalid mode '{m}'")))?;
        }
        if let Some(d) = event_days {
            s.event_retention_days = d;
        }
        if let Some(d) = aggregate_days {
            s.aggregate_retention_days = d;
        }
        vault.observe_settings_set(&s)
    })
}

#[tauri::command]
fn observe_diagnostics(
    state: State<'_, AppState>,
) -> CmdResult<Vec<api_tracker_observe::diagnostics::Check>> {
    with_vault(&state, |vault| {
        let present = vault.observe_ca_status()?.present;
        Ok(api_tracker_observe::diagnostics::run(present))
    })
}

#[tauri::command]
fn observe_delete_session(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    with_vault(&state, |vault| vault.observe_delete_session(&id))
}

/// Delete ALL observability data (reauthenticated in core).
#[tauri::command]
fn observe_delete_all(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = SecretString::new(password);
    with_vault(&state, |vault| vault.observe_delete_all(&password))
}

#[tauri::command]
fn observe_allowlist(
    state: State<'_, AppState>,
    project: String,
) -> CmdResult<Vec<(String, u16, String)>> {
    with_vault(&state, |vault| vault.observe_allowlist(&project))
}

#[tauri::command]
fn observe_allowlist_add(
    state: State<'_, AppState>,
    project: String,
    host: String,
    port: u16,
    note: String,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        vault.observe_allowlist_add(&project, &host, port, &note)
    })
}

#[tauri::command]
fn observe_allowlist_remove(
    state: State<'_, AppState>,
    project: String,
    host: String,
    port: u16,
) -> CmdResult<bool> {
    with_vault(&state, |vault| {
        vault.observe_allowlist_remove(&project, &host, port)
    })
}

// ---------------------------------------------------------------------------
// Local Gateway (ADR 0019, Phase 3)
//
// Status/doctor/start/stop/restart/repair are deliberately LOCK-FREE: they
// never touch the vault slot, so a locked desktop still sees and controls
// the gateway (PRODUCT_BEHAVIOR — the lock screen carries a status strip).
// Everything that writes configuration, route rows, or project .env files
// goes through with_vault. The desktop performs no silent install: the
// consent dialog in the UI calls gateway_install only after an explicit
// user action.
// ---------------------------------------------------------------------------

use api_tracker_gateway::{
    control as gw_control, doctor as gw_doctor, envlink, lifecycle as gw_lifecycle,
    routes as gw_routes, store as gw_store,
};
use api_tracker_tracking::{
    apply as tracking_apply, detect as tracking_detect, diagnose as tracking_diagnose,
    origin as tracking_origin, plan as tracking_plan, state as tracking_state,
    undo as tracking_undo, verify as tracking_verify,
};

#[tauri::command]
fn gateway_doctor(state: State<'_, AppState>) -> CmdResult<gw_doctor::Doctor> {
    Ok(gw_doctor::diagnose(&state.data_dir))
}

/// Locate a `tethra` CLI binary this machine can run, verified by its
/// service-probe output. The app BUNDLES the CLI as a Tauri sidecar
/// (ADR 0022 D4, closes gateway OPEN_DECISIONS O10), so the bundled copy
/// — always version-matched to this build — is the first candidate; every
/// pre-existing fallback (installed service copy, PATH, the usual homes)
/// is kept for dev builds and unusual installs.
fn locate_cli(data_dir: &std::path::Path) -> Option<PathBuf> {
    let exe = format!("tethra{}", std::env::consts::EXE_SUFFIX);
    let mut candidates: Vec<PathBuf> = Vec::new();
    // The bundled sidecar, beside this executable.
    if let Ok(current) = std::env::current_exe() {
        candidates.extend(gw_lifecycle::bundled_helper_candidate(&current));
    }
    // An already-installed service binary works too (repair path).
    if let Ok(entries) = std::fs::read_dir(gw_lifecycle::bin_dir(data_dir)) {
        for e in entries.flatten() {
            candidates.push(e.path());
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            candidates.push(dir.join(&exe));
        }
    }
    // Finder-launched apps see a minimal PATH; check the usual homes.
    for fixed in ["/usr/local/bin", "/opt/homebrew/bin"] {
        candidates.push(PathBuf::from(fixed).join(&exe));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        for rel in [".local/bin", "bin", ".cargo/bin"] {
            candidates.push(home.join(rel).join(&exe));
        }
    }
    candidates
        .into_iter()
        .find(|c| gw_lifecycle::helper_answers_probe(&gw_lifecycle::HostRunner, c))
}

#[tauri::command]
fn gateway_locate_cli(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    Ok(locate_cli(&state.data_dir).map(|p| p.display().to_string()))
}

#[tauri::command]
fn gateway_install(
    state: State<'_, AppState>,
    force: bool,
) -> CmdResult<gw_lifecycle::InstallReport> {
    let Some(source) = locate_cli(&state.data_dir) else {
        return Err(ErrDto {
            code: "cli_not_found".into(),
            message: "the helper that runs tracking could not be found or executed. \
                      It normally ships inside the app — reinstalling Tethra restores \
                      it. (Advanced: a `tethra` CLI on PATH also works.)"
                .into(),
        });
    };
    // The stable port is chosen and persisted BEFORE the service starts
    // (the service reads it from the database at boot — ADR 0019 O3).
    with_vault(&state, |vault| {
        let mut config = gw_store::load_config(vault.connection())?;
        if config.port.is_none() {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(CoreError::Io)?;
            config.port = Some(listener.local_addr().map_err(CoreError::Io)?.port());
        }
        gw_store::save_config(vault.connection(), &config)
    })?;

    // The slow OS work happens OUTSIDE the vault mutex.
    let lc = gw_lifecycle::Lifecycle::for_host(&state.data_dir).map_err(ErrDto::from)?;
    let report = lc.install(&source, force).map_err(ErrDto::from)?;

    with_vault(&state, |vault| {
        let mut config = gw_store::load_config(vault.connection())?;
        config.enabled = true;
        config.service_version = Some(env!("CARGO_PKG_VERSION").to_string());
        gw_store::save_config(vault.connection(), &config)?;
        api_tracker_core::audit::record(
            vault.connection(),
            "gateway_service_installed",
            None,
            None,
            &format!("definition={}", report.definition),
        )
    })?;
    Ok(report)
}

#[tauri::command]
fn gateway_disable(
    state: State<'_, AppState>,
    keep_env: bool,
) -> CmdResult<gw_lifecycle::DisableReport> {
    let lc = gw_lifecycle::Lifecycle::for_host(&state.data_dir).map_err(ErrDto::from)?;
    with_vault(&state, |vault| lc.disable(vault.connection(), keep_env))
}

#[tauri::command]
fn gateway_uninstall(
    state: State<'_, AppState>,
    keep_env: bool,
) -> CmdResult<gw_lifecycle::UninstallReport> {
    let lc = gw_lifecycle::Lifecycle::for_host(&state.data_dir).map_err(ErrDto::from)?;
    with_vault(&state, |vault| lc.uninstall(vault.connection(), keep_env))
}

#[tauri::command]
fn gateway_start(state: State<'_, AppState>) -> CmdResult<()> {
    let lc = gw_lifecycle::Lifecycle::for_host(&state.data_dir).map_err(ErrDto::from)?;
    if !lc.status().installed {
        return Err(ErrDto {
            code: "not_installed".into(),
            message: "no gateway service is installed".into(),
        });
    }
    lc.start().map_err(ErrDto::from)
}

#[tauri::command]
fn gateway_stop(state: State<'_, AppState>) -> CmdResult<()> {
    // Prefer the graceful control-plane drain (clean exit = not respawned);
    // fall back to the service manager.
    if gw_control::instance_is_live(&state.data_dir) {
        if let Ok(nonce) = gw_control::read_nonce(&state.data_dir) {
            if let Ok(gw_control::Response::Ok) = gw_control::send(
                &state.data_dir,
                &gw_control::Request::Shutdown {
                    nonce: nonce.to_string(),
                },
            ) {
                return Ok(());
            }
        }
    }
    let lc = gw_lifecycle::Lifecycle::for_host(&state.data_dir).map_err(ErrDto::from)?;
    if !lc.status().installed {
        return Ok(()); // nothing to stop
    }
    lc.stop().map_err(ErrDto::from)
}

#[tauri::command]
fn gateway_restart(state: State<'_, AppState>) -> CmdResult<()> {
    let lc = gw_lifecycle::Lifecycle::for_host(&state.data_dir).map_err(ErrDto::from)?;
    lc.restart().map_err(ErrDto::from)
}

#[tauri::command]
fn gateway_repair(state: State<'_, AppState>) -> CmdResult<gw_lifecycle::InstallReport> {
    let Some(source) = locate_cli(&state.data_dir) else {
        return Err(ErrDto {
            code: "cli_not_found".into(),
            message: "repair needs the bundled tracking helper and it could not be found \
                      or executed; reinstalling Tethra restores it."
                .into(),
        });
    };
    let lc = gw_lifecycle::Lifecycle::for_host(&state.data_dir).map_err(ErrDto::from)?;
    lc.repair(&source).map_err(ErrDto::from)
}

#[derive(Serialize)]
struct GatewayRouteDto {
    prefix: String,
    provider_id: String,
    origin: Option<String>,
    custom: bool,
    enabled: bool,
    available: bool,
    unavailable_reason: Option<String>,
}

#[derive(Serialize)]
struct GatewayRouteListDto {
    routes: Vec<GatewayRouteDto>,
    skipped: Vec<(String, String)>,
}

#[tauri::command]
fn gateway_route_list(state: State<'_, AppState>) -> CmdResult<GatewayRouteListDto> {
    // Lock-free: routes are non-secret configuration, and the panel must
    // render while the vault is locked.
    let conn = api_tracker_core::db::open_at_current_version(&state.paths().db_path())
        .map_err(ErrDto::from)?;
    // Verify custom routes with the real key when a vault session exists.
    // Loading with `None` unconditionally — what shipped before — made a
    // just-added custom route always display "unavailable", contradicting a
    // running gateway that was forwarding it perfectly well.
    let key = with_vault(&state, |vault| vault.gateway_route_mac_key()).ok();
    let table = gw_routes::load_route_table(&conn, key.as_ref()).map_err(ErrDto::from)?;
    let verifiable = key.is_some();
    let mut routes: Vec<GatewayRouteDto> = table
        .iter_routes()
        .map(|r| {
            let (available, origin, why) = match &r.target {
                gw_routes::RouteTarget::Ready(o) => (true, Some(o.host.clone()), None),
                gw_routes::RouteTarget::Unforwardable(
                    gw_routes::Unforwardable::MacKeyUnavailable,
                ) if !verifiable => (
                    false,
                    None,
                    Some(
                        "cannot be verified from this view while the vault is locked —                          a running gateway may still be forwarding it; check Status"
                            .to_string(),
                    ),
                ),
                gw_routes::RouteTarget::Unforwardable(w) => (false, None, Some(format!("{w:?}"))),
            };
            GatewayRouteDto {
                prefix: r.prefix.clone(),
                provider_id: r.provider_id.clone(),
                origin,
                custom: r.custom,
                enabled: true,
                available,
                unavailable_reason: why,
            }
        })
        .collect();
    let mut stmt = conn
        .prepare("SELECT route_prefix, provider_id FROM gateway_routes WHERE enabled = 0")
        .map_err(|e| ErrDto::from(CoreError::from(e)))?;
    let disabled: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(|e| ErrDto::from(CoreError::from(e)))?
        .collect::<Result<_, _>>()
        .map_err(|e| ErrDto::from(CoreError::from(e)))?;
    for (prefix, provider_id) in disabled {
        routes.push(GatewayRouteDto {
            prefix,
            provider_id,
            origin: None,
            custom: false,
            enabled: false,
            available: false,
            unavailable_reason: Some("disabled".into()),
        });
    }
    routes.sort_by(|a, b| a.prefix.cmp(&b.prefix));
    Ok(GatewayRouteListDto {
        routes,
        skipped: table.skipped.clone(),
    })
}

/// Ask a running gateway to re-read routes now (best-effort).
fn gateway_nudge(data_dir: &std::path::Path) {
    if !gw_control::instance_is_live(data_dir) {
        return;
    }
    if let Ok(nonce) = gw_control::read_nonce(data_dir) {
        let _ = gw_control::send(
            data_dir,
            &gw_control::Request::ReloadRoutes {
                nonce: nonce.to_string(),
            },
        );
    }
}

#[tauri::command]
fn gateway_route_add(
    state: State<'_, AppState>,
    provider: String,
    prefix: Option<String>,
    origin: Option<String>,
) -> CmdResult<()> {
    let prefix = prefix.unwrap_or_else(|| provider.clone());
    let custom = origin.is_some();
    with_vault(&state, |vault| {
        match &origin {
            Some(origin) => {
                let key = vault.gateway_route_mac_key()?;
                gw_routes::add_custom_route(vault.connection(), &prefix, &provider, origin, &key)?;
            }
            None => gw_routes::add_manifest_route(vault.connection(), &prefix, &provider)?,
        }
        // The route the user just created must be usable NOW, not after a
        // future unlock (ADR 0021). Minting is correct here: adding a custom
        // route is the moment the route key legitimately comes into being.
        if custom {
            install_gateway_route_key(&state, vault, true);
        }
        Ok(())
    })?;
    gateway_nudge(&state.data_dir);
    Ok(())
}

#[tauri::command]
fn gateway_route_remove(state: State<'_, AppState>, prefix: String) -> CmdResult<bool> {
    let removed = with_vault(&state, |vault| {
        gw_routes::remove_route(vault.connection(), &prefix)
    })?;
    gateway_nudge(&state.data_dir);
    Ok(removed)
}

#[tauri::command]
fn gateway_route_set_enabled(
    state: State<'_, AppState>,
    prefix: String,
    enabled: bool,
) -> CmdResult<bool> {
    let changed = with_vault(&state, |vault| {
        let changed = gw_routes::set_route_enabled(vault.connection(), &prefix, enabled)?;
        if enabled {
            install_gateway_route_key(&state, vault, false);
        }
        Ok(changed)
    })?;
    gateway_nudge(&state.data_dir);
    Ok(changed)
}

fn link_request(
    vault: &UnlockedVault,
    project: &str,
    route: &str,
    env_files: &[String],
    dir: &Option<String>,
    var: &Option<String>,
) -> Result<envlink::LinkRequest, CoreError> {
    let proj = vault.get_project(project)?;
    let project_dir = dir.as_ref().map(PathBuf::from).or_else(|| {
        if env_files.is_empty() && proj.repo_paths.len() == 1 {
            Some(PathBuf::from(&proj.repo_paths[0]))
        } else {
            None
        }
    });
    Ok(envlink::LinkRequest {
        project_id: proj.id,
        project_name: proj.name,
        route_prefix: route.to_string(),
        project_dir,
        files: env_files.iter().map(PathBuf::from).collect(),
        var_override: var.clone(),
    })
}

#[tauri::command]
fn gateway_link_plan(
    state: State<'_, AppState>,
    project: String,
    route: String,
    env_files: Vec<String>,
    dir: Option<String>,
    var: Option<String>,
) -> CmdResult<envlink::LinkPlan> {
    with_vault(&state, |vault| {
        let req = link_request(vault, &project, &route, &env_files, &dir, &var)?;
        envlink::plan_link(vault.connection(), &req)
    })
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn gateway_link_apply(
    state: State<'_, AppState>,
    project: String,
    route: String,
    env_files: Vec<String>,
    dir: Option<String>,
    var: Option<String>,
    slug: String,
    digest: String,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        let req = link_request(vault, &project, &route, &env_files, &dir, &var)?;
        // Re-plan with the previewed slug and refuse if anything changed
        // underneath the dialog the user confirmed.
        let plan = envlink::plan_link_with_slug(vault.connection(), &req, &slug)?;
        if plan.digest != digest {
            return Err(CoreError::InvalidInput(
                "the environment files changed since the preview; re-open the link \
                 dialog to see the current diff"
                    .into(),
            ));
        }
        envlink::apply_link(vault.connection(), &req, &plan)?;
        Ok(())
    })?;
    // The running gateway must resolve the new link slug immediately, not
    // after its 5s poll — otherwise the just-linked SDK gets a 404.
    gateway_nudge(&state.data_dir);
    Ok(())
}

#[tauri::command]
fn gateway_unlink(
    state: State<'_, AppState>,
    project: String,
    route: String,
) -> CmdResult<envlink::UnlinkReport> {
    let report = with_vault(&state, |vault| {
        let proj = vault.get_project(&project)?;
        let link = gw_routes::find_project_link(vault.connection(), &proj.id, &route)?;
        match link {
            Some(row) if row.prior_env_json.is_some() => {
                envlink::unlink(vault.connection(), &proj.id, &route)
            }
            Some(_) => {
                gw_routes::remove_project_link(vault.connection(), &proj.id, &route)?;
                Ok(envlink::UnlinkReport {
                    route_prefix: route.clone(),
                    project_id: proj.id,
                    outcomes: vec![],
                    complete: true,
                })
            }
            None => Err(CoreError::NotFound {
                kind: "gateway project link",
                ident: format!("{project}:{route}"),
            }),
        }
    });
    // Drop the removed link slug from a running gateway's snapshot now.
    gateway_nudge(&state.data_dir);
    report
}

#[tauri::command]
fn gateway_push_key(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = SecretString::new(password);
    // Reauth is enforced by core: gateway_matching_key verifies the master
    // password itself (the dialog is UX, not authorization — IPC-02).
    let key = with_vault(&state, |vault| vault.gateway_matching_key(&password))?;
    let nonce = gw_control::read_nonce(&state.data_dir).map_err(ErrDto::from)?;
    let hex = Zeroizing::new(
        key.expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    match gw_control::send(
        &state.data_dir,
        &gw_control::Request::PushKey {
            nonce: nonce.to_string(),
            key_hex: hex.to_string(),
        },
    )
    .map_err(ErrDto::from)?
    {
        gw_control::Response::Ok => Ok(()),
        gw_control::Response::Error { code, message } => Err(ErrDto { code, message }),
        other => Err(ErrDto {
            code: "protocol".into(),
            message: format!("unexpected control response: {other:?}"),
        }),
    }
}

#[tauri::command]
fn gateway_match_while_locked_get(state: State<'_, AppState>) -> CmdResult<bool> {
    with_vault(&state, |vault| {
        gw_store::load_config(vault.connection()).map(|c| c.match_while_locked)
    })
}

/// Flip the consented keep-matching-while-locked toggle (ADR 0020).
///
/// Enabling grants a RETAINED capability (the matching key survives vault
/// lock, bounded by the auto-lock duration capped at 8 hours), so it is
/// reauth-gated exactly like the key push itself. Disabling needs no reauth
/// and, per SI-9 ("dropped on ... toggle-off"), immediately revokes any
/// resident key best-effort.
#[tauri::command]
fn gateway_match_while_locked_set(
    state: State<'_, AppState>,
    enabled: bool,
    password: Option<String>,
) -> CmdResult<()> {
    with_vault(&state, |vault| {
        if enabled {
            let Some(password) = password.as_deref() else {
                return Err(CoreError::InvalidInput(
                    "enabling keep-while-locked requires the master password".into(),
                ));
            };
            let password = SecretString::new(password.to_string());
            vault.verify_master_password(&password)?;
        }
        gw_store::set_match_while_locked(vault.connection(), enabled)
    })?;
    if !enabled {
        let _ = gw_control::send_revoke_key(&state.data_dir);
    }
    Ok(())
}

#[tauri::command]
fn gateway_revoke_key(state: State<'_, AppState>) -> CmdResult<()> {
    let nonce = gw_control::read_nonce(&state.data_dir).map_err(ErrDto::from)?;
    match gw_control::send(
        &state.data_dir,
        &gw_control::Request::RevokeKey {
            nonce: nonce.to_string(),
        },
    )
    .map_err(ErrDto::from)?
    {
        gw_control::Response::Ok => Ok(()),
        gw_control::Response::Error { code, message } => Err(ErrDto { code, message }),
        other => Err(ErrDto {
            code: "protocol".into(),
            message: format!("unexpected control response: {other:?}"),
        }),
    }
}

#[tauri::command]
fn gateway_activity(
    state: State<'_, AppState>,
    since: Option<String>,
) -> CmdResult<gw_store::GatewayActivitySummary> {
    // Lock-free: gateway activity is non-secret metadata, and the panel
    // must render while the vault is locked.
    let conn = api_tracker_core::db::open_at_current_version(&state.paths().db_path())
        .map_err(ErrDto::from)?;
    gw_store::gateway_activity_summary(&conn, since.as_deref()).map_err(ErrDto::from)
}

/// Locally observed gateway traffic for ONE project.
///
/// `GatewayActivitySummary` has no project dimension, so with two or more
/// tracked projects the dashboard could not answer "which project generated
/// this?" (ZFT-029). `runtime_request_events` already carries `project_id`
/// (indexed), so the dimension exists in the data — only the read was
/// missing.
#[derive(Serialize)]
struct ProjectActivityDto {
    project_id: String,
    /// The project's name, or `None` when the project row is gone but its
    /// events remain. Rendered as an explicit "removed project" rather than
    /// as a blank.
    project_name: Option<String>,
    total_requests: i64,
    success_count: i64,
    error_count: i64,
    transport_error_count: i64,
    first_event_at: Option<String>,
    last_event_at: Option<String>,
}

/// Per-project totals over the same window and the same rows as
/// `gateway_activity`, so the parts and the whole cannot disagree.
///
/// Lock-free for the same reason `gateway_activity` is: this is non-secret
/// request metadata and the panel must render while the vault is locked.
/// Project NAMES are not secret either — they are already listed unlocked
/// by the tracked-projects panel.
#[tauri::command]
fn gateway_activity_by_project(
    state: State<'_, AppState>,
    since: Option<String>,
) -> CmdResult<Vec<ProjectActivityDto>> {
    let conn = api_tracker_core::db::open_at_current_version(&state.paths().db_path())
        .map_err(ErrDto::from)?;
    let since_clause = since.unwrap_or_default();
    let read = || -> Result<Vec<ProjectActivityDto>, CoreError> {
        let mut stmt = conn.prepare(
            "SELECT e.project_id, p.name,
                    COUNT(*),
                    COALESCE(SUM(CASE WHEN e.status_code BETWEEN 200 AND 399 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN e.status_code >= 400 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN e.transport_error != 'none' THEN 1 ELSE 0 END), 0),
                    MIN(e.at), MAX(e.at)
             FROM runtime_request_events e
             LEFT JOIN projects p ON p.id = e.project_id
             WHERE e.observation_source = 'gateway' AND e.at >= ?1
             GROUP BY e.project_id
             ORDER BY 3 DESC",
        )?;
        let mut out = Vec::new();
        let rows = stmt.query_map([&since_clause], |r| {
            Ok(ProjectActivityDto {
                project_id: r.get(0)?,
                project_name: r.get(1)?,
                total_requests: r.get(2)?,
                success_count: r.get(3)?,
                error_count: r.get(4)?,
                transport_error_count: r.get(5)?,
                first_event_at: r.get(6)?,
                last_event_at: r.get(7)?,
            })
        })?;
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    };
    read().map_err(ErrDto::from)
}

#[tauri::command]
fn credential_activity_sources(
    state: State<'_, AppState>,
    selector: String,
) -> CmdResult<api_tracker_core::runtime::store::CredentialActivitySources> {
    with_vault(&state, |vault| {
        let credential = vault.get_credential(&selector)?;
        api_tracker_core::runtime::store::credential_activity_sources(
            vault.connection(),
            &credential.id,
        )
    })
}

#[tauri::command]
fn gateway_recording(state: State<'_, AppState>, pause: bool) -> CmdResult<()> {
    let nonce = gw_control::read_nonce(&state.data_dir).map_err(ErrDto::from)?;
    let request = if pause {
        gw_control::Request::PauseRecording {
            nonce: nonce.to_string(),
        }
    } else {
        gw_control::Request::ResumeRecording {
            nonce: nonce.to_string(),
        }
    };
    match gw_control::send(&state.data_dir, &request).map_err(ErrDto::from)? {
        gw_control::Response::Ok => Ok(()),
        gw_control::Response::Error { code, message } => Err(ErrDto { code, message }),
        other => Err(ErrDto {
            code: "protocol".into(),
            message: format!("unexpected control response: {other:?}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Track API activity (ADR 0022)
//
// Thin wrappers over the shared `api-tracker-tracking` orchestrator — the
// same engine `tethra track` drives, so the desktop and CLI cannot drift.
// The in-flight scan and plan live in `AppState.tracking`: a `LinkPlan`
// carries file contents and the digest that binds apply to exactly what
// was previewed, and neither belongs on the IPC boundary.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TrackingScanDto {
    folder: String,
    project_name: String,
    project_exists: bool,
    providers: Vec<TrackingProviderDto>,
    scanned_files: u32,
    skipped_oversized: u32,
    env_files: Vec<String>,
    /// Already-configured providers (a re-run over an existing setup).
    already_tracking: bool,
    /// The honest headline: every integration the scan saw, in exactly one
    /// bucket, rendered by the shared `CoverageSummary` so the desktop and
    /// the CLI cannot describe the same scan differently (ZFT-010).
    coverage_lines: Vec<String>,
    coverage: TrackingCoverageDto,
    /// Secret-shaped variables with no Tethra provider definition. Names and
    /// files only — a value is never carried here.
    unrecognized: Vec<TrackingUnrecognizedDto>,
    /// What the scan could NOT inspect, if anything.
    scan_gaps: Option<String>,
    git_warnings: Vec<String>,
}

#[derive(Serialize)]
struct TrackingCoverageDto {
    total: usize,
    tracked_automatically: usize,
    needs_origin_confirmation: usize,
    detected_unsupported: usize,
    unrecognized: usize,
    low_confidence: usize,
}

#[derive(Serialize)]
struct TrackingUnrecognizedDto {
    var: String,
    file: String,
    name_hint: Option<String>,
}

#[derive(Serialize)]
struct TrackingProviderDto {
    provider_id: String,
    display_name: String,
    confidence: String,
    /// "automatic" | "needs_origin_confirm" | "needs_origin_input" |
    /// "unsupported"
    configurability: String,
    inferred_origin: Option<String>,
    evidence: Vec<String>,
    limitations: Vec<String>,
    credential_candidates: Vec<String>,
    /// Pre-selected in the review screen. False for every destination read
    /// from project content — those are approved one at a time, or not at
    /// all.
    selected_by_default: bool,
    /// Whether this provider's destination needs a separate per-origin
    /// approval before it can be planned at all.
    needs_origin_approval: bool,
    /// Why Tethra cannot observe this provider, when it cannot.
    unsupported_reason: Option<String>,
}

#[derive(Serialize)]
struct TrackingPlanDto {
    project_name: String,
    creates_project: bool,
    service_actions: Vec<String>,
    routes: Vec<String>,
    files: Vec<TrackingFileDto>,
    warnings: Vec<String>,
    restart_expected: bool,
    port: u16,
    providers: Vec<String>,
}

#[derive(Serialize)]
struct TrackingFileDto {
    path: String,
    exists: bool,
    changed: bool,
    diff: String,
}

fn confidence_str(c: tracking_detect::DetectionConfidence) -> String {
    c.label().to_string()
}

fn configurability_str(c: &tracking_detect::Configurability) -> (String, Option<String>) {
    match c {
        tracking_detect::Configurability::Automatic => ("automatic".into(), None),
        tracking_detect::Configurability::NeedsOriginConfirm { inferred_origin } => {
            ("needs_origin_confirm".into(), Some(inferred_origin.clone()))
        }
        tracking_detect::Configurability::NeedsOriginInput => ("needs_origin_input".into(), None),
        tracking_detect::Configurability::Unsupported { .. } => ("unsupported".into(), None),
    }
}

/// The unsupported reason as a sentence. The frontend never sees the enum
/// token: a user reading "no_configurable_base_url" learns nothing (ZFT-030).
fn unsupported_reason_sentence(c: &tracking_detect::Configurability) -> Option<String> {
    match c {
        tracking_detect::Configurability::Unsupported { reason } => Some(match reason {
            tracking_detect::UnsupportedReason::NoConfigurableBaseUrl => {
                "This provider's SDK reads no base-URL setting, so Tethra has no way to route \
                 its traffic through the local service. Nothing about your setup is wrong."
                    .to_string()
            }
            tracking_detect::UnsupportedReason::UnknownProvider => {
                "Tethra has no provider definition for this service yet, so it does not know \
                 where its traffic goes or how to recognise it."
                    .to_string()
            }
        }),
        _ => None,
    }
}

/// The `BaseUrlVar` evidence behind an inferred origin: which file and which
/// variable the destination was read from. This is the "why Tethra suggests
/// it" half of the disclosure, and the shared `origin::describe` renders it.
fn origin_source_of(p: &tracking_detect::ProviderDetection) -> Option<(String, String)> {
    p.evidence.iter().find_map(|e| match e {
        tracking_detect::Evidence::BaseUrlVar { var, file } => Some((var.clone(), file.clone())),
        _ => None,
    })
}

/// Scan a user-selected folder and start a tracking session.
#[tauri::command]
fn tracking_scan(state: State<'_, AppState>, folder: String) -> CmdResult<TrackingScanDto> {
    let folder_path = PathBuf::from(&folder);
    let (detection, project, already_tracking) = with_vault(&state, |vault| {
        let ids = vault::projects_for_folder(vault.connection(), &folder_path)?;
        let project = match ids.first() {
            Some(id) => {
                let p = vault.get_project(id)?;
                tracking_plan::ProjectRef {
                    id: Some(p.id),
                    name: p.name,
                }
            }
            None => tracking_plan::ProjectRef {
                id: None,
                name: folder_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("tracked-project")
                    .to_string(),
            },
        };
        let detection = tracking_detect::detect(
            vault.connection(),
            &tracking_detect::DetectionInput {
                folder: &folder_path,
                project_id: project.id.as_deref(),
            },
        )?;
        let already = match &project.id {
            Some(id) => tracking_state::find_setup(vault.connection(), id, &detection.folder)?
                .map(|s| s.applied_at.is_some())
                .unwrap_or(false),
            None => false,
        };
        Ok((detection, project, already))
    })?;

    // `Selections::defaults` covers only manifest-origin providers. Anything
    // whose destination was read from the project is absent by construction,
    // so `selected_by_default` is false for it and the review screen renders
    // its checkbox unchecked (ADR 0024, ZFT-004).
    let defaults = tracking_plan::Selections::defaults(&detection);
    let pending: std::collections::BTreeSet<String> =
        tracking_plan::Selections::pending_origin_approvals(&detection)
            .into_iter()
            .map(|(provider_id, _)| provider_id)
            .collect();
    let dto = TrackingScanDto {
        folder: detection.folder.display().to_string(),
        project_name: project.name.clone(),
        project_exists: project.id.is_some(),
        providers: detection
            .providers
            .iter()
            .map(|p| {
                let (configurability, inferred_origin) = configurability_str(&p.configurability);
                TrackingProviderDto {
                    provider_id: p.provider_id.clone(),
                    display_name: p.display_name.clone(),
                    confidence: confidence_str(p.confidence),
                    configurability,
                    inferred_origin,
                    evidence: p.evidence.iter().map(|e| e.describe()).collect(),
                    limitations: p.limitations.clone(),
                    credential_candidates: p.credential_candidates.clone(),
                    selected_by_default: defaults.include.contains(&p.provider_id),
                    needs_origin_approval: pending.contains(&p.provider_id)
                        || matches!(
                            p.configurability,
                            tracking_detect::Configurability::NeedsOriginInput
                        ),
                    unsupported_reason: unsupported_reason_sentence(&p.configurability),
                }
            })
            .collect(),
        scanned_files: detection.scanned_files,
        skipped_oversized: detection.skipped_oversized,
        env_files: detection
            .env_files
            .iter()
            .map(|f| f.rel_path.clone())
            .collect(),
        already_tracking,
        coverage_lines: detection.coverage.lines(),
        coverage: TrackingCoverageDto {
            total: detection.coverage.total(),
            tracked_automatically: detection.coverage.tracked_automatically,
            needs_origin_confirmation: detection.coverage.needs_origin_confirmation,
            detected_unsupported: detection.coverage.detected_unsupported,
            unrecognized: detection.coverage.unrecognized,
            low_confidence: detection.coverage.low_confidence,
        },
        unrecognized: detection
            .unrecognized
            .iter()
            .map(|u| TrackingUnrecognizedDto {
                var: u.var.clone(),
                file: u.file.clone(),
                name_hint: u.name_hint.clone(),
            })
            .collect(),
        scan_gaps: detection.accounting.describe_gaps(),
        git_warnings: detection.accounting.git_warnings.clone(),
    };
    *state.tracking.lock().unwrap() = Some(TrackingSession {
        detection,
        project,
        plan: None,
        // A new scan starts with nothing approved. Approvals never carry
        // over from a previous folder.
        approved_origins: std::collections::BTreeMap::new(),
    });
    Ok(dto)
}

// --- repository-discovered destinations (ADR 0024) -------------------------

/// One destination the user is being asked to allow. Every field comes from
/// the shared `origin::OriginApprovalRequest`, including the question and the
/// ordered disclosure lines, so the CLI prompt and the desktop checkbox
/// cannot describe the same destination differently.
#[derive(Serialize)]
struct TrackingOriginRequestDto {
    provider_id: String,
    provider_display_name: String,
    origin: String,
    scheme: String,
    host: String,
    port: u16,
    /// "public" | "restricted"
    network_class: String,
    source_file: Option<String>,
    source_var: Option<String>,
    forwards_credentials: bool,
    /// "built_in_manifest" | "previously_approved" | "repository_discovered"
    trust: String,
    question: String,
    disclosure: Vec<String>,
    /// A prior approval of this exact origin, if one is recorded and its MAC
    /// verifies. Presentation only — it still starts unchecked.
    previously_approved_at: Option<String>,
    /// Approved in THIS review. The checkbox's checked state.
    approved_now: bool,
    /// Set when the destination fails the gateway's unchanged destination
    /// policy, so the screen explains a refusal instead of offering a
    /// checkbox that could never work.
    refusal: Option<String>,
}

fn origin_request_dto(
    request: &tracking_origin::OriginApprovalRequest,
    previously_approved_at: Option<String>,
    approved_now: bool,
) -> TrackingOriginRequestDto {
    TrackingOriginRequestDto {
        provider_id: request.provider_id.clone(),
        provider_display_name: request.provider_display_name.clone(),
        origin: request.origin.clone(),
        scheme: request.scheme.clone(),
        host: request.host.clone(),
        port: request.port,
        network_class: match request.network_class {
            tracking_origin::NetworkClass::Public => "public".to_string(),
            tracking_origin::NetworkClass::Restricted => "restricted".to_string(),
        },
        source_file: request.source_file.clone(),
        source_var: request.source_var.clone(),
        forwards_credentials: request.forwards_credentials,
        trust: match request.trust {
            tracking_origin::OriginTrust::BuiltInManifest => "built_in_manifest".to_string(),
            tracking_origin::OriginTrust::PreviouslyApproved { .. } => {
                "previously_approved".to_string()
            }
            tracking_origin::OriginTrust::RepositoryDiscovered => {
                "repository_discovered".to_string()
            }
        },
        question: request.question(),
        disclosure: request.disclosure(),
        previously_approved_at,
        approved_now,
        refusal: None,
    }
}

/// Every repository-discovered destination in the current session, with the
/// full disclosure the user needs in order to decide.
///
/// Called once when the review screen renders. Each entry becomes one
/// checkbox that starts UNCHECKED — including one the user approved in a
/// previous session: the prior approval is shown as context, never as a
/// silent pre-tick.
#[tauri::command]
fn tracking_origin_requests(
    state: State<'_, AppState>,
) -> CmdResult<Vec<TrackingOriginRequestDto>> {
    let (pending, approved_now, detection) = {
        let guard = state.tracking.lock().unwrap();
        let Some(session) = guard.as_ref() else {
            return Err(ErrDto {
                code: "no_session".into(),
                message: "no folder has been scanned yet".into(),
            });
        };
        (
            tracking_plan::Selections::pending_origin_approvals(&session.detection),
            session.approved_origins.clone(),
            session.detection.clone(),
        )
    };
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    with_vault(&state, |vault| {
        let vault_id = gw_routes::vault_id(vault.connection())?;
        let mac_key = vault.gateway_route_mac_key().ok();
        let mut out = Vec::new();
        for (provider_id, inferred) in pending {
            let detected = detection
                .providers
                .iter()
                .find(|p| p.provider_id == provider_id);
            let display = detected
                .map(|p| p.display_name.clone())
                .unwrap_or_else(|| provider_id.clone());
            let source = detected.and_then(origin_source_of);
            match tracking_origin::describe(
                &provider_id,
                &display,
                &inferred,
                source.as_ref().map(|(_, f)| f.as_str()),
                source.as_ref().map(|(v, _)| v.as_str()),
                true,
                tracking_origin::OriginTrust::RepositoryDiscovered,
            ) {
                Ok(request) => {
                    let prior = mac_key.as_ref().and_then(|k| {
                        tracking_origin::is_approved(
                            vault.connection(),
                            &vault_id,
                            k,
                            &inferred,
                            &provider_id,
                        )
                        .ok()
                        .flatten()
                    });
                    out.push(origin_request_dto(
                        &request,
                        prior.map(|p| p.approved_at),
                        approved_now
                            .get(&provider_id)
                            .is_some_and(|o| o == &inferred),
                    ));
                }
                // A destination the gateway would refuse is still listed —
                // silently dropping it would leave the user wondering why a
                // detected API vanished.
                Err(e) => out.push(TrackingOriginRequestDto {
                    provider_id: provider_id.clone(),
                    provider_display_name: display,
                    origin: inferred.clone(),
                    scheme: "https".into(),
                    host: String::new(),
                    port: 0,
                    network_class: "restricted".into(),
                    source_file: source.as_ref().map(|(_, f)| f.clone()),
                    source_var: source.as_ref().map(|(v, _)| v.clone()),
                    forwards_credentials: true,
                    trust: "repository_discovered".into(),
                    question: format!("Tethra will not send traffic to {inferred}."),
                    disclosure: Vec::new(),
                    previously_approved_at: None,
                    approved_now: false,
                    refusal: Some(e.to_string()),
                }),
            }
        }
        Ok(out)
    })
}

/// Record the user's approval of one exact destination for this review.
///
/// This is the ONLY way a repository-discovered origin enters a desktop
/// plan. It is deliberately a separate command from `tracking_plan_build`
/// and `tracking_apply`: neither of those can approve anything, so clicking
/// "Start tracking" cannot approve a destination the user did not tick.
///
/// The approval is held in the session only. It is written to the vault
/// (MAC-bound, `origin::approve`) after a successful apply — the same point
/// the CLI persists it — so a review the user abandons leaves no trace.
#[tauri::command]
fn tracking_origin_approve(
    state: State<'_, AppState>,
    provider_id: String,
    origin: String,
) -> CmdResult<TrackingOriginRequestDto> {
    let mut guard = state.tracking.lock().unwrap();
    let Some(session) = guard.as_mut() else {
        return Err(ErrDto {
            code: "no_session".into(),
            message: "no folder has been scanned yet".into(),
        });
    };
    let detected = session
        .detection
        .providers
        .iter()
        .find(|p| p.provider_id == provider_id)
        .ok_or_else(|| ErrDto {
            code: "not_detected".into(),
            message: format!("'{provider_id}' was not detected in the scanned folder"),
        })?;
    // A repository-discovered origin is approvable only as the exact value
    // that was detected. For a provider whose origin could not be inferred
    // the user types the destination, which is a first-hand decision rather
    // than one the repository proposed.
    match &detected.configurability {
        tracking_detect::Configurability::NeedsOriginConfirm { inferred_origin } => {
            if inferred_origin != &origin {
                return Err(ErrDto {
                    code: "origin_mismatch".into(),
                    message: format!(
                        "approval is granted for one exact destination; {inferred_origin} was \
                         detected but {origin} was submitted"
                    ),
                });
            }
        }
        tracking_detect::Configurability::NeedsOriginInput => {}
        _ => {
            return Err(ErrDto {
                code: "not_approvable".into(),
                message: format!(
                    "'{provider_id}' does not use a destination read from this project, so there \
                     is nothing to approve"
                ),
            })
        }
    }
    let source = origin_source_of(detected);
    let display = detected.display_name.clone();
    let request = tracking_origin::describe(
        &provider_id,
        &display,
        &origin,
        source.as_ref().map(|(_, f)| f.as_str()),
        source.as_ref().map(|(v, _)| v.as_str()),
        true,
        tracking_origin::OriginTrust::RepositoryDiscovered,
    )
    .map_err(ErrDto::from)?;
    session
        .approved_origins
        .insert(provider_id.clone(), origin.clone());
    Ok(origin_request_dto(&request, None, true))
}

/// Withdraw an approval given in this review (the checkbox went back off,
/// or the typed destination changed).
#[tauri::command]
fn tracking_origin_revoke(state: State<'_, AppState>, provider_id: String) -> CmdResult<()> {
    let mut guard = state.tracking.lock().unwrap();
    let Some(session) = guard.as_mut() else {
        return Err(ErrDto {
            code: "no_session".into(),
            message: "no folder has been scanned yet".into(),
        });
    };
    session.approved_origins.remove(&provider_id);
    Ok(())
}

/// Build the combined plan for the current session's selections.
///
/// Takes provider ids only. Destinations are NOT a parameter: a
/// repository-discovered origin can reach a plan solely through
/// `Selections::approve_origin`, fed from the session approvals that
/// `tracking_origin_approve` records. The previous signature accepted an
/// `origins` list from the frontend, which meant the IPC boundary — not the
/// user — decided where traffic goes (ZFT-004).
#[tauri::command]
fn tracking_plan_build(
    state: State<'_, AppState>,
    providers: Vec<String>,
) -> CmdResult<TrackingPlanDto> {
    let mut guard = state.tracking.lock().unwrap();
    let Some(session) = guard.as_mut() else {
        return Err(ErrDto {
            code: "no_session".into(),
            message: "no folder has been scanned yet".into(),
        });
    };
    let mut selections = tracking_plan::Selections::default();
    for provider in providers {
        let detected = session
            .detection
            .providers
            .iter()
            .find(|p| p.provider_id == provider);
        let needs_origin = matches!(
            detected.map(|p| &p.configurability),
            Some(tracking_detect::Configurability::NeedsOriginConfirm { .. })
                | Some(tracking_detect::Configurability::NeedsOriginInput)
        );
        if needs_origin {
            // Refuse rather than silently drop: a provider the user ticked
            // that quietly vanished from the plan would be worse than an
            // error, because the review screen would still show it selected.
            let Some(origin) = session.approved_origins.get(&provider) else {
                let inferred = match detected.map(|p| &p.configurability) {
                    Some(tracking_detect::Configurability::NeedsOriginConfirm {
                        inferred_origin,
                    }) => inferred_origin.clone(),
                    _ => "its destination".to_string(),
                };
                return Err(ErrDto::from(tracking_origin::refusal(&inferred, &provider)));
            };
            selections.approve_origin(&provider, origin);
        } else {
            selections.include.insert(provider);
        }
    }
    let service = gw_lifecycle::Lifecycle::for_host(&state.data_dir)
        .map(|lc| lc.status())
        .map_err(ErrDto::from)?;
    let port_now = with_vault(&state, |vault| {
        Ok(gw_store::load_config(vault.connection())?.port)
    })?;
    let listener_live = matches!(
        gw_control::verify_listener(&state.data_dir, port_now.unwrap_or(0)),
        gw_control::ListenerIdentity::Verified { .. }
    );
    let plan = with_vault(&state, |vault| {
        tracking_plan::ensure_port(vault.connection())?;
        tracking_plan::plan(
            vault.connection(),
            &session.detection,
            &selections,
            session.project.clone(),
            &service,
            listener_live,
        )
    })?;
    let dto = TrackingPlanDto {
        project_name: plan.project.name.clone(),
        creates_project: plan.project.id.is_none(),
        service_actions: plan
            .service_actions
            .iter()
            .map(|a| match a {
                tracking_plan::ServiceAction::InstallService => {
                    "Install and start the local tracking service".to_string()
                }
                tracking_plan::ServiceAction::StartService => {
                    "Start the local tracking service".to_string()
                }
                tracking_plan::ServiceAction::RepairService { installed, current } => {
                    format!("Update the tracking helper ({installed} → {current})")
                }
                tracking_plan::ServiceAction::AlreadyRunning => {
                    "Local tracking service is already running".to_string()
                }
            })
            .collect(),
        routes: plan
            .route_actions
            .iter()
            .map(|a| match a {
                tracking_plan::RouteAction::CreateCustomRoute { prefix, origin, .. } => {
                    format!("{prefix} → {origin}")
                }
                other => other.prefix().to_string(),
            })
            .collect(),
        files: plan
            .link_plans
            .iter()
            .flat_map(|lp| lp.files.iter())
            .map(|f| TrackingFileDto {
                path: f.path.clone(),
                exists: f.exists,
                changed: f.changed,
                diff: f.diff.clone(),
            })
            .collect(),
        warnings: plan.warnings.iter().map(|w| w.describe()).collect(),
        restart_expected: !matches!(
            plan.restart_expectation,
            tracking_plan::RestartExpectation::NotNeeded
        ),
        port: plan.port,
        providers: plan
            .route_actions
            .iter()
            .map(|a| a.provider_id().to_string())
            .collect(),
    };
    session.plan = Some(plan);
    Ok(dto)
}

#[derive(Serialize)]
struct TrackingApplyDto {
    steps: Vec<TrackingStepDto>,
    state: String,
    setup_id: Option<String>,
    install_blocked: bool,
    attribution_enabled: bool,
    failed: bool,
    restart_expected: bool,
}

#[derive(Serialize)]
struct TrackingStepDto {
    title: String,
    /// "done" | "skipped" | "failed"
    outcome: String,
    detail: String,
}

/// Apply the previewed plan. `password` (optional) enables credential
/// attribution in the same step — ADR 0020's reauth requirement, moved
/// into the Start-tracking confirmation instead of a later dialog.
#[tauri::command]
fn tracking_apply(
    state: State<'_, AppState>,
    password: Option<String>,
) -> CmdResult<TrackingApplyDto> {
    let (detection, plan, approved_origins) = {
        let guard = state.tracking.lock().unwrap();
        let Some(session) = guard.as_ref() else {
            return Err(ErrDto {
                code: "no_session".into(),
                message: "no tracking plan has been previewed yet".into(),
            });
        };
        let Some(plan) = session.plan.clone() else {
            return Err(ErrDto {
                code: "no_plan".into(),
                message: "no tracking plan has been previewed yet".into(),
            });
        };
        (
            session.detection.clone(),
            plan,
            session.approved_origins.clone(),
        )
    };
    let helper = locate_cli(&state.data_dir).ok_or_else(|| ErrDto {
        code: "cli_not_found".into(),
        message: "the helper that runs tracking could not be found or executed. It \
                  normally ships inside the app — reinstalling Tethra restores it."
            .into(),
    })?;
    let ops = tracking_apply::HostServiceOps {
        data_dir: state.data_dir.clone(),
        helper_source: helper,
        port: plan.port,
    };
    let options = tracking_apply::ApplyOptions {
        master_password: password.map(SecretString::new),
    };
    let report = with_vault(&state, |vault| {
        let report = tracking_apply::apply(vault, &detection, &plan, &options, &ops);
        // Persist the destination approvals only once the setup they were
        // given for actually succeeded — the same point the CLI persists
        // them. An abandoned or failed review leaves no approval behind, so
        // "you approved this before" can never be shown for a decision that
        // never took effect. Best-effort: a failure here costs one re-ask.
        if report.failed_step().is_none() && !approved_origins.is_empty() {
            if let (Ok(key), Ok(vault_id)) = (
                vault.gateway_route_mac_key(),
                gw_routes::vault_id(vault.connection()),
            ) {
                for (provider_id, origin) in &approved_origins {
                    let _ = tracking_origin::approve(
                        vault.connection(),
                        &vault_id,
                        &key,
                        origin,
                        provider_id,
                    );
                }
            }
        }
        Ok(report)
    })?;
    Ok(TrackingApplyDto {
        steps: report
            .steps
            .iter()
            .map(|s| {
                let (outcome, detail) = match &s.outcome {
                    tracking_apply::StepOutcome::Done { detail } => ("done", detail.clone()),
                    tracking_apply::StepOutcome::Skipped { reason } => ("skipped", reason.clone()),
                    tracking_apply::StepOutcome::Failed { error } => ("failed", error.clone()),
                };
                TrackingStepDto {
                    title: s.title.to_string(),
                    outcome: outcome.to_string(),
                    detail,
                }
            })
            .collect(),
        state: report.state.as_str().to_string(),
        failed: report.failed_step().is_some(),
        setup_id: report.setup_id.clone(),
        install_blocked: report.install_blocked,
        attribution_enabled: report.attribution_enabled,
        restart_expected: !matches!(
            plan.restart_expectation,
            tracking_plan::RestartExpectation::NotNeeded
        ),
    })
}

#[derive(Serialize)]
struct TrackingStatusDto {
    setup_id: String,
    state: String,
    project_id: String,
    folder: String,
    /// "observed" | "partial" | "waiting" | "not_watchable"
    watch: String,
    observed_provider: Option<String>,
    observed_latency_ms: Option<i64>,
    observed_model: Option<String>,
    providers: Vec<TrackingFreshnessDto>,
    attribution_paused: bool,
    /// What is true NOW. Rendered under its own heading, never merged with
    /// the history below it (ZFT-005).
    health: TrackingHealthDto,
    /// What was true before. Facts that survive the session — shown
    /// alongside present health, never instead of it.
    history: TrackingHistoryDto,
}

/// `state::CurrentHealth`, flattened for the UI: a machine tag for styling
/// and a finished sentence for the user. The sentence comes from the shared
/// `CurrentHealth::describe`, so no internal token is ever rendered
/// (ZFT-030), and `currently_working` comes from
/// `CurrentHealth::is_currently_working`, which is deliberately narrow —
/// "verified previously, gateway down" is not a success.
#[derive(Serialize)]
struct TrackingHealthDto {
    kind: String,
    sentence: String,
    currently_working: bool,
}

#[derive(Serialize)]
struct TrackingHistoryDto {
    first_verified_at: Option<String>,
    last_observed_at: Option<String>,
    verification_session: Option<String>,
    config_generation: i64,
    /// The one-line history sentence, or `None` when this setup has never
    /// been verified — in which case the UI must say exactly that rather
    /// than render an empty section.
    sentence: Option<String>,
}

fn health_kind(health: &tracking_state::CurrentHealth) -> &'static str {
    use tracking_state::CurrentHealth as H;
    match health {
        H::VerifiedAndActive => "verified_and_active",
        H::PartiallyTracked { .. } => "partially_tracked",
        H::VerifiedPreviouslyGatewayDown => "verified_previously_gateway_down",
        H::VerifiedPreviouslyIdle { .. } => "verified_previously_idle",
        H::WaitingForFirstRequest => "waiting_for_first_request",
        H::NeedsRestart => "needs_restart",
        H::ConfigurationChanged { .. } => "configuration_changed",
        H::GatewayUnavailable => "gateway_unavailable",
        H::NeedsAttention { .. } => "needs_attention",
        H::AttributionPaused => "attribution_paused",
        H::NotConfigured => "not_configured",
        H::Unsupported => "unsupported",
    }
}

fn health_dto(health: &tracking_state::CurrentHealth) -> TrackingHealthDto {
    TrackingHealthDto {
        kind: health_kind(health).to_string(),
        sentence: health.describe(),
        currently_working: health.is_currently_working(),
    }
}

fn history_dto(history: &tracking_state::VerificationHistory) -> TrackingHistoryDto {
    let sentence = match (&history.first_verified_at, &history.last_observed_at) {
        (Some(first), Some(last)) => Some(format!(
            "First verified {first}. Most recent observation in this configuration: {last}."
        )),
        (Some(first), None) => Some(format!(
            "First verified {first}. Nothing has been observed since the configuration last \
             changed."
        )),
        (None, Some(last)) => Some(format!("Last observed {last}.")),
        (None, None) => None,
    };
    TrackingHistoryDto {
        first_verified_at: history.first_verified_at.clone(),
        last_observed_at: history.last_observed_at.clone(),
        verification_session: history.verification_session.clone(),
        config_generation: history.config_generation,
        sentence,
    }
}

/// Probe whether this vault's gateway is answering right now.
///
/// `GatewayLiveness::Unknown` is the honest answer when we did not probe;
/// `refresh_with` treats it as "cannot confirm health", so historical facts
/// survive but present-tense claims do not.
fn gateway_liveness(state: &AppState) -> tracking_state::GatewayLiveness {
    let port = match api_tracker_core::db::open_at_current_version(&state.paths().db_path())
        .ok()
        .and_then(|conn| gw_store::load_config(&conn).ok())
        .and_then(|c| c.port)
    {
        Some(port) => port,
        None => return tracking_state::GatewayLiveness::Down,
    };
    match gw_control::verify_listener(&state.data_dir, port) {
        gw_control::ListenerIdentity::Verified { .. } => tracking_state::GatewayLiveness::Verified,
        _ => tracking_state::GatewayLiveness::Down,
    }
}

#[derive(Serialize)]
struct TrackingFreshnessDto {
    provider_id: String,
    last_observed_at: Option<String>,
}

/// One poll of the tracking state (the UI drives the cadence).
#[tauri::command]
fn tracking_status(state: State<'_, AppState>, setup_id: String) -> CmdResult<TrackingStatusDto> {
    let attribution_paused = attribution_is_paused(&state);
    let liveness = gateway_liveness(&state);
    with_vault(&state, |vault| {
        let mut setup = tracking_state::get_setup(vault.connection(), &setup_id)?.ok_or(
            CoreError::NotFound {
                kind: "tracking setup",
                ident: setup_id.clone(),
            },
        )?;
        let status = tracking_verify::check_traffic(vault.connection(), &mut setup)?;
        // Derived AFTER `check_traffic`, which re-derives the row itself:
        // health must describe the row the user is about to be shown, and
        // this pass is the one that knows whether the gateway answered.
        let report = tracking_state::refresh_with(vault.connection(), &mut setup, liveness)?;
        let (watch, exchange, freshness) = match status {
            tracking_verify::WatchStatus::Observed {
                exchange,
                freshness,
            } => ("observed", exchange, freshness),
            tracking_verify::WatchStatus::PartiallyObserved {
                exchange,
                freshness,
            } => ("partial", exchange, freshness),
            tracking_verify::WatchStatus::Waiting => ("waiting", None, Vec::new()),
            tracking_verify::WatchStatus::NotWatchable { .. } => {
                ("not_watchable", None, Vec::new())
            }
        };
        Ok(TrackingStatusDto {
            setup_id: setup.id.clone(),
            state: setup.state.as_str().to_string(),
            project_id: setup.project_id.clone(),
            folder: setup.folder_path.clone(),
            watch: watch.to_string(),
            observed_provider: exchange
                .as_ref()
                .map(|e| e.provider_id.clone().unwrap_or_else(|| e.host.clone())),
            observed_latency_ms: exchange.as_ref().and_then(|e| e.latency_ms),
            observed_model: exchange.as_ref().and_then(|e| e.model.clone()),
            providers: freshness
                .into_iter()
                .map(|f| TrackingFreshnessDto {
                    provider_id: f.provider_id,
                    last_observed_at: f.last_observed_at,
                })
                .collect(),
            attribution_paused,
            health: health_dto(&report.current),
            history: history_dto(&report.history),
        })
    })
}

/// Attribution is "paused" when the gateway is live and forwarding but
/// holds no matching key — traffic is still recorded (SI-11/12/13).
fn attribution_is_paused(state: &AppState) -> bool {
    if !gw_control::instance_is_live(&state.data_dir) {
        return false;
    }
    let Ok(nonce) = gw_control::read_nonce(&state.data_dir) else {
        return false;
    };
    match gw_control::send(
        &state.data_dir,
        &gw_control::Request::Status {
            nonce: nonce.to_string(),
        },
    ) {
        Ok(gw_control::Response::Status(status)) => {
            !status.matching_key_present || status.matching_key_expired
        }
        _ => false,
    }
}

/// Every tracking setup, for the dashboard's per-project cards.
#[tauri::command]
fn tracking_list(state: State<'_, AppState>) -> CmdResult<Vec<TrackingStatusDto>> {
    let attribution_paused = attribution_is_paused(&state);
    // Probed once for the whole list rather than per setup: the answer is a
    // property of the machine, and the dashboard must be able to say "this
    // was verified before, but nothing is listening now" — which it cannot
    // do from `GatewayLiveness::Unknown`.
    let liveness = gateway_liveness(&state);
    with_vault(&state, |vault| {
        let mut out = Vec::new();
        for mut setup in tracking_state::list_setups(vault.connection())? {
            let report = tracking_state::refresh_with(vault.connection(), &mut setup, liveness)?;
            out.push(TrackingStatusDto {
                setup_id: setup.id.clone(),
                state: setup.state.as_str().to_string(),
                project_id: setup.project_id.clone(),
                folder: setup.folder_path.clone(),
                watch: match setup.state {
                    tracking_state::TrackingState::TrafficObserved => "observed",
                    tracking_state::TrackingState::PartiallyObserved => "partial",
                    _ => "waiting",
                }
                .to_string(),
                observed_provider: None,
                observed_latency_ms: None,
                observed_model: None,
                providers: report
                    .freshness
                    .iter()
                    .map(|f| TrackingFreshnessDto {
                        provider_id: f.provider_id.clone(),
                        last_observed_at: f.last_observed_at.clone(),
                    })
                    .collect(),
                attribution_paused,
                health: health_dto(&report.current),
                history: history_dto(&report.history),
            });
        }
        Ok(out)
    })
}

#[derive(Serialize)]
struct TrackingDiagnosisDto {
    id: String,
    severity: String,
    message: String,
}

#[tauri::command]
fn tracking_diagnose(
    state: State<'_, AppState>,
    setup_id: String,
) -> CmdResult<Vec<TrackingDiagnosisDto>> {
    let data_dir = state.data_dir.clone();
    with_vault(&state, |vault| {
        let setup = tracking_state::get_setup(vault.connection(), &setup_id)?.ok_or(
            CoreError::NotFound {
                kind: "tracking setup",
                ident: setup_id.clone(),
            },
        )?;
        let diagnoses = tracking_diagnose::diagnose(vault.connection(), &data_dir, &setup)?;
        Ok(diagnoses
            .into_iter()
            .map(|d| TrackingDiagnosisDto {
                id: d.id.to_string(),
                severity: format!("{:?}", d.severity).to_lowercase(),
                message: d.message,
            })
            .collect())
    })
}

#[derive(Serialize)]
struct TrackingUndoDto {
    complete: bool,
    restored: Vec<String>,
    removed_routes: Vec<String>,
    kept_routes: Vec<String>,
}

#[tauri::command]
fn tracking_undo(state: State<'_, AppState>, setup_id: String) -> CmdResult<TrackingUndoDto> {
    let data_dir = state.data_dir.clone();
    let report = with_vault(&state, |vault| {
        let setup = tracking_state::get_setup(vault.connection(), &setup_id)?.ok_or(
            CoreError::NotFound {
                kind: "tracking setup",
                ident: setup_id.clone(),
            },
        )?;
        tracking_undo::undo(vault.connection(), &setup)
    })?;
    // Let a running service drop the removed links immediately.
    if let Ok(nonce) = gw_control::read_nonce(&data_dir) {
        let _ = gw_control::send(
            &data_dir,
            &gw_control::Request::ReloadRoutes {
                nonce: nonce.to_string(),
            },
        );
    }
    Ok(TrackingUndoDto {
        complete: report.complete,
        restored: report
            .links
            .iter()
            .flat_map(|l| l.outcomes.iter())
            .map(|o| format!("{o:?}"))
            .collect(),
        removed_routes: report.removed_routes.clone(),
        kept_routes: report
            .kept_routes
            .iter()
            .map(|(route, why)| format!("{route} ({why})"))
            .collect(),
    })
}

/// The unsigned-build fallback: run the bundled helper in the foreground
/// (`gateway serve`) so tracking works while Tethra is open. Same `serve`
/// path a CLI user runs; no new gateway mode, no elevation.
#[tauri::command]
fn tracking_foreground_start(state: State<'_, AppState>) -> CmdResult<()> {
    let mut guard = state.foreground_gateway.lock().unwrap();
    if guard.child.is_some() {
        return Ok(());
    }
    let helper = locate_cli(&state.data_dir).ok_or_else(|| ErrDto {
        code: "cli_not_found".into(),
        message: "the tracking helper could not be found or executed.".into(),
    })?;
    let child = std::process::Command::new(helper)
        .args(["gateway", "serve"])
        .arg("--data-dir")
        .arg(&state.data_dir)
        .spawn()
        .map_err(|e| ErrDto {
            code: "spawn_failed".into(),
            message: format!("could not start the foreground tracking service: {e}"),
        })?;
    guard.child = Some(child);
    guard.exited = None;
    Ok(())
}

#[derive(Serialize)]
struct ForegroundStatusDto {
    /// A foreground helper we started is running right now.
    active: bool,
    /// A foreground helper we started is no longer running. Distinct from
    /// `active == false` with `stopped == false`, which means one was never
    /// started and the background service is what is (or is not) running.
    stopped: bool,
    /// Why, when we know. Never a bare enum token.
    detail: Option<String>,
}

/// Whether the foreground fallback is the thing currently running (the
/// dashboard says "tracking pauses when Tethra closes").
///
/// Returns three distinguishable outcomes rather than a bool. The dashboard
/// used to collapse a failed check into `false`, which renders identically
/// to "the background service is running" — so a user whose foreground
/// helper had died was told nothing at all (ZFT-031).
#[tauri::command]
fn tracking_foreground_active(state: State<'_, AppState>) -> CmdResult<ForegroundStatusDto> {
    let mut guard = state.foreground_gateway.lock().unwrap();
    match guard.child.as_mut() {
        Some(child) => match child.try_wait() {
            Ok(Some(status)) => {
                guard.child = None;
                let detail = format!(
                    "The helper that was tracking while Tethra is open exited ({status}). \
                     Traffic is not being recorded until it is started again."
                );
                guard.exited = Some(detail.clone());
                Ok(ForegroundStatusDto {
                    active: false,
                    stopped: true,
                    detail: Some(detail),
                })
            }
            Ok(None) => Ok(ForegroundStatusDto {
                active: true,
                stopped: false,
                detail: None,
            }),
            // We cannot tell whether it is alive. Saying "not running" would
            // be a claim we cannot support, so report the uncertainty.
            Err(e) => Ok(ForegroundStatusDto {
                active: false,
                stopped: true,
                detail: Some(format!(
                    "The state of the foreground tracking helper could not be read: {e}"
                )),
            }),
        },
        None => Ok(ForegroundStatusDto {
            active: false,
            stopped: guard.exited.is_some(),
            detail: guard.exited.clone(),
        }),
    }
}

/// Stop the foreground helper this app started.
///
/// Called on `RunEvent::Exit` and from the dashboard. `std::process::Child`
/// does not kill on drop, so nothing else ends this process: without this
/// the helper kept forwarding — and kept a resident matching key — after the
/// app that promised "tracking pauses when Tethra closes" was gone
/// (ZFT-021).
fn stop_foreground_gateway(state: &AppState) {
    let mut guard = match state.foreground_gateway.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(mut child) = guard.child.take() {
        let _ = child.kill();
        // Reap it so the helper cannot linger as a zombie holding the
        // loopback port against the next start.
        let _ = child.wait();
        guard.exited = Some(
            "The foreground tracking helper was stopped because Tethra is closing.".to_string(),
        );
    }
}

#[tauri::command]
fn tracking_foreground_stop(state: State<'_, AppState>) -> CmdResult<()> {
    stop_foreground_gateway(&state);
    Ok(())
}

/// Resume credential attribution after a lock (Journey B). Same reauth
/// gate as every other matching-key push.
#[tauri::command]
fn tracking_resume_attribution(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = SecretString::new(password);
    let key = with_vault(&state, |vault| vault.gateway_matching_key(&password))?;
    let ops = tracking_apply::HostServiceOps {
        data_dir: state.data_dir.clone(),
        helper_source: PathBuf::new(),
        port: 0,
    };
    tracking_apply::ServiceOps::push_matching_key(&ops, key).map_err(ErrDto::from)
}

fn main() {
    // Absolutize for the same reason the CLI does: this path is baked into
    // the installed service's argv, and service managers start with a working
    // directory of `/`.
    let data_dir = vault::default_data_dir().expect("could not determine the data directory");
    let data_dir = std::path::absolute(&data_dir).unwrap_or(data_dir);
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            slot: Mutex::new(VaultSlot {
                vault: None,
                last_activity: Instant::now(),
            }),
            data_dir,
            tracking: Mutex::new(None),
            foreground_gateway: Mutex::new(ForegroundGateway::default()),
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            vault_create,
            vault_unlock,
            vault_lock,
            vault_change_password,
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
            scan_reverify,
            suppression_add,
            suppression_list,
            suppression_remove,
            hook_status,
            hook_install,
            hook_remove,
            monitor_status,
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
            notification_history,
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
            pricing_records,
            pricing_set_override,
            pricing_remove_override,
            pricing_import,
            pricing_export,
            provider_account_sync,
            template_list,
            template_apply,
            stack_detect,
            stack_decide,
            stack_prefs,
            stack_prefs_reset,
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
            destination_delete_secret,
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
            access_sessions,
            access_session_kill,
            credential_timeline,
            permissions_preview,
            provider_list_keys,
            test_key_create,
            credential_provider_revoke,
            observe_overview,
            observe_services,
            observe_service,
            observe_service_metrics,
            observe_service_endpoints,
            observe_service_events,
            observe_sessions,
            observe_session,
            observe_session_metrics,
            observe_session_events,
            observe_session_attributions,
            observe_session_compat,
            observe_credential_activity,
            observe_cert_status,
            observe_cert_rotate,
            observe_cert_remove,
            observe_cert_install_system,
            observe_cert_uninstall_system,
            observe_settings_get,
            observe_settings_set,
            observe_diagnostics,
            observe_delete_session,
            observe_delete_all,
            observe_allowlist,
            observe_allowlist_add,
            observe_allowlist_remove,
            gateway_doctor,
            gateway_locate_cli,
            gateway_install,
            gateway_disable,
            gateway_uninstall,
            gateway_start,
            gateway_stop,
            gateway_restart,
            gateway_repair,
            gateway_route_list,
            gateway_route_add,
            gateway_route_remove,
            gateway_route_set_enabled,
            gateway_link_plan,
            gateway_link_apply,
            gateway_unlink,
            gateway_push_key,
            gateway_revoke_key,
            gateway_match_while_locked_get,
            gateway_match_while_locked_set,
            gateway_recording,
            tracking_scan,
            tracking_origin_requests,
            tracking_origin_approve,
            tracking_origin_revoke,
            tracking_plan_build,
            tracking_apply,
            tracking_status,
            tracking_list,
            tracking_diagnose,
            tracking_undo,
            tracking_foreground_start,
            tracking_foreground_active,
            tracking_foreground_stop,
            tracking_resume_attribution,
            gateway_activity,
            gateway_activity_by_project,
            credential_activity_sources,
        ])
        .build(tauri::generate_context!())
        .expect("error while running the Tethra desktop app")
        .run(|app_handle, event| {
            // Quitting the app ends the in-memory vault session — a lock
            // event like any other (ADR 0020). Without this, a resident
            // matching key would outlive the session that authorized it
            // whenever the user simply closes Tethra. Best-effort; a
            // crashed/killed process skips this (THREAT_MODEL GW-6).
            if let tauri::RunEvent::Exit = event {
                use tauri::Manager as _;
                let state: State<'_, AppState> = app_handle.state();
                let minutes = {
                    let mut slot = state.slot.lock().expect("vault state mutex poisoned");
                    let minutes = slot.vault.as_ref().map(|v| v.settings().auto_lock_minutes);
                    slot.vault = None;
                    minutes
                };
                notify_gateway_vault_locked(&state.data_dir, minutes);
                // The foreground fallback is a CHILD of this app, and the UI
                // promises "tracking pauses when Tethra closes". Nothing else
                // ends it — `Child` has no kill-on-drop — so the promise is
                // only true because of this line (ZFT-021).
                stop_foreground_gateway(&state);
            }
        });
}
