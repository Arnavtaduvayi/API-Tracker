//! Tethra Mesh shared projects, cross-device usage and spend caps for the
//! desktop (Increment 10, ADR 0031/0032). Thin wrappers over
//! `api-tracker-core`, beside the device commands in `mesh_cmds.rs`; no
//! business logic here or in TypeScript.
//!
//! - Binding is never automatic (MESH-SI-13): every bind is one explicit
//!   command for one local project.
//! - Usage figures are core's report as is: per device, with freshness and
//!   honesty labels, never summed with provider-reported cost (MESH-SI-11,
//!   gateway SI-19).
//! - Dollar amounts arrive as text and are parsed by core
//!   (`pricing::dollars_to_micros`), the CLI's parser.
//! - Enforcement on this device is reauthenticated in core
//!   (`UnlockedVault::mesh_cap_enforce`).
//! - Reads a page polls (`mesh_projects_list`, `mesh_usage_report` and
//!   `mesh_caps_list` without `publish`/`reconcile`) use
//!   `with_vault_background` and write nothing.
//! - No analytics (MESH-SI-14).

// Contract stubs (Increment 10): every body below is replaced, and this
// allow removed, before the increment's final commit.
#![allow(dead_code)]

use super::{AppState, CmdResult, ErrDto};
use api_tracker_core::mesh::caps::ops::CapChanged;
use api_tracker_core::mesh::caps::{CapCreated, CapReport};
use api_tracker_core::mesh::projects::MeshProjectRow;
use api_tracker_core::mesh::usage::UsageReport;
use serde::{Deserialize, Serialize};
use tauri::State;

fn not_implemented() -> ErrDto {
    ErrDto {
        code: "NotImplementedYet".into(),
        message: "this mesh command is not built yet".into(),
    }
}

/// `mesh_project_share`: the new mesh project, bound to the local one.
#[derive(Serialize)]
pub(crate) struct MeshShareDto {
    pub mesh_project_id: String,
    pub name: String,
}

/// `mesh_project_merge`: which project the other now folds into.
#[derive(Serialize)]
pub(crate) struct MeshMergeDto {
    pub root: String,
    pub merged: String,
}

/// Which usage `mesh_usage_report` reports. Every field is optional; parsed
/// by core (`Month::parse`, `Day::parse`, `projects::resolve`).
#[derive(Deserialize)]
pub(crate) struct MeshUsageFilterDto {
    /// A mesh project id (or unique prefix); `None` for every project.
    pub project: Option<String>,
    /// `YYYY-MM`; the current UTC month when absent.
    pub month: Option<String>,
    /// `YYYY-MM-DD`; wins over `month`.
    pub day: Option<String>,
}

/// `mesh_usage_report`: core's report (flattened), plus why this device's
/// own usage was not published first, when `publish` was asked and failed.
#[derive(Serialize)]
pub(crate) struct MeshUsageDto {
    #[serde(flatten)]
    pub report: UsageReport,
    pub publish_error: Option<String>,
}

/// `mesh_caps_list` / `mesh_cap_rights`: core's report (flattened), plus why
/// the reconciler did not run first, when `reconcile` was asked and failed.
#[derive(Serialize)]
pub(crate) struct MeshCapsDto {
    #[serde(flatten)]
    pub report: CapReport,
    pub reconcile_error: Option<String>,
}

/// `mesh_cap_reclaim`: the devices asked to give rights back.
#[derive(Serialize)]
pub(crate) struct MeshReclaimDto {
    pub cap_id: String,
    pub devices: Vec<String>,
}

/// `mesh_cap_enforce`: the caps whose switch changed on this device.
#[derive(Serialize)]
pub(crate) struct MeshEnforceDto {
    pub caps: Vec<String>,
    pub on: bool,
}

#[tauri::command]
pub(crate) fn mesh_projects_list(state: State<'_, AppState>) -> CmdResult<Vec<MeshProjectRow>> {
    let _ = &state;
    Err(not_implemented())
}

/// Share a local project with the mesh: a new mesh project with its name,
/// bound here.
#[tauri::command]
pub(crate) fn mesh_project_share(
    state: State<'_, AppState>,
    local_project_id: String,
) -> CmdResult<MeshShareDto> {
    let _ = (&state, &local_project_id);
    Err(not_implemented())
}

/// Bind a mesh project to a local project on this device only. Explicit,
/// never automatic.
#[tauri::command]
pub(crate) fn mesh_project_bind(
    state: State<'_, AppState>,
    mesh_project_id: String,
    local_project_id: String,
) -> CmdResult<String> {
    let _ = (&state, &mesh_project_id, &local_project_id);
    Err(not_implemented())
}

/// Returns whether a binding was removed.
#[tauri::command]
pub(crate) fn mesh_project_unbind(
    state: State<'_, AppState>,
    local_project_id: String,
) -> CmdResult<bool> {
    let _ = (&state, &local_project_id);
    Err(not_implemented())
}

#[tauri::command]
pub(crate) fn mesh_project_rename(
    state: State<'_, AppState>,
    mesh_project_id: String,
    name: String,
) -> CmdResult<String> {
    let _ = (&state, &mesh_project_id, &name);
    Err(not_implemented())
}

#[tauri::command]
pub(crate) fn mesh_project_archive(
    state: State<'_, AppState>,
    mesh_project_id: String,
) -> CmdResult<String> {
    let _ = (&state, &mesh_project_id);
    Err(not_implemented())
}

/// The UI confirms first. Refused by core when both projects have caps.
#[tauri::command]
pub(crate) fn mesh_project_merge(
    state: State<'_, AppState>,
    a: String,
    b: String,
) -> CmdResult<MeshMergeDto> {
    let _ = (&state, &a, &b);
    Err(not_implemented())
}

/// `publish: true` publishes this device's usage first (a write; for an
/// explicit refresh), `false` only reads (safe to poll).
#[tauri::command]
pub(crate) fn mesh_usage_report(
    state: State<'_, AppState>,
    filter: MeshUsageFilterDto,
    publish: bool,
) -> CmdResult<MeshUsageDto> {
    let _ = (
        &state,
        &filter.project,
        &filter.month,
        &filter.day,
        &publish,
    );
    Err(not_implemented())
}

/// `reconcile: true` runs the cap reconciler first (a write; on open and
/// after an action), `false` only reads (safe to poll).
#[tauri::command]
pub(crate) fn mesh_caps_list(
    state: State<'_, AppState>,
    reconcile: bool,
) -> CmdResult<MeshCapsDto> {
    let _ = (&state, &reconcile);
    Err(not_implemented())
}

/// `monthly_usd` is text such as `"25"` or `"12.50"`.
#[tauri::command]
pub(crate) fn mesh_cap_create(
    state: State<'_, AppState>,
    mesh_project_id: String,
    monthly_usd: String,
) -> CmdResult<CapCreated> {
    let _ = (&state, &mesh_project_id, &monthly_usd);
    Err(not_implemented())
}

/// On the owner a raise mints; elsewhere it is a labelled local override
/// for this month (the UI explains and confirms first).
#[tauri::command]
pub(crate) fn mesh_cap_raise(
    state: State<'_, AppState>,
    cap_id: String,
    usd: String,
) -> CmdResult<CapChanged> {
    let _ = (&state, &cap_id, &usd);
    Err(not_implemented())
}

/// Lower the monthly target to `usd` (the UI confirms first).
#[tauri::command]
pub(crate) fn mesh_cap_lower(
    state: State<'_, AppState>,
    cap_id: String,
    usd: String,
) -> CmdResult<CapChanged> {
    let _ = (&state, &cap_id, &usd);
    Err(not_implemented())
}

/// One cap's report with its per-device rights (reconciles first).
#[tauri::command]
pub(crate) fn mesh_cap_rights(
    state: State<'_, AppState>,
    cap_id: String,
) -> CmdResult<MeshCapsDto> {
    let _ = (&state, &cap_id);
    Err(not_implemented())
}

/// Owner only: ask holders to give unspent rights back (every other device,
/// or `from_device`).
#[tauri::command]
pub(crate) fn mesh_cap_reclaim(
    state: State<'_, AppState>,
    cap_id: String,
    from_device: Option<String>,
) -> CmdResult<MeshReclaimDto> {
    let _ = (&state, &cap_id, &from_device);
    Err(not_implemented())
}

/// Reauthenticated in core. `cap_id: None` means every cap (`--all`).
#[tauri::command]
pub(crate) fn mesh_cap_enforce(
    state: State<'_, AppState>,
    master_password: String,
    cap_id: Option<String>,
    on: bool,
) -> CmdResult<MeshEnforceDto> {
    let _ = (&state, &master_password, &cap_id, &on);
    Err(not_implemented())
}
