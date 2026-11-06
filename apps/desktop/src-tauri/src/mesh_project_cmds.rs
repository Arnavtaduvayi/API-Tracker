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

use super::{with_vault, with_vault_background, AppState, CmdResult};
use api_tracker_core::error::CoreError;
use api_tracker_core::mesh::caps::ops::CapChanged;
use api_tracker_core::mesh::caps::{self, CapCreated, CapReport};
use api_tracker_core::mesh::kinds::{Day, Month};
use api_tracker_core::mesh::projects::{self, MeshProjectRow};
use api_tracker_core::mesh::usage::{UsageFilter, UsageReport};
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::UnlockedVault;
use api_tracker_mesh::node::GatewaySocket;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tauri::State;

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

/// An optional usage-filter field: trimmed, and absent when blank (a blank
/// field only ever widens a read to its default).
fn given(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// A dollar amount in micro-USD, parsed by core as the CLI does
/// (`mesh cap … <usd>`); core refuses zero itself.
fn micros(usd: &str) -> Result<u64, CoreError> {
    let m = api_tracker_core::pricing::dollars_to_micros(usd)?;
    Ok(u64::try_from(m).unwrap_or(0))
}

/// The usage filter, validated before anything is written. The wording
/// matches the CLI's (`--day must be YYYY-MM-DD`).
fn usage_filter(v: &UnlockedVault, f: &MeshUsageFilterDto) -> Result<UsageFilter, CoreError> {
    let mut filter = UsageFilter::default();
    if let Some(d) = given(f.day.as_deref()) {
        filter.day = Some(
            Day::parse(d)
                .ok_or_else(|| CoreError::InvalidInput("day must be YYYY-MM-DD".into()))?,
        );
    }
    if let Some(m) = given(f.month.as_deref()) {
        filter.month = Some(
            Month::parse(m)
                .ok_or_else(|| CoreError::InvalidInput("month must be YYYY-MM".into()))?,
        );
    }
    if let Some(p) = given(f.project.as_deref()) {
        filter.project = Some(projects::resolve(&v.mesh_open_store()?, p)?);
    }
    Ok(filter)
}

/// The caps report after running the reconciler (as `tethra mesh cap show`
/// does). Core already tolerates a rollback hold or a fork there; any other
/// reconciler failure still shows the figures this device has, read only,
/// with the reason in `reconcile_error`. An error the read hits as well (not
/// in a mesh, no such cap) is the command's error.
fn reconciled_report(
    v: &UnlockedVault,
    data_dir: &Path,
    cap: Option<&str>,
) -> Result<MeshCapsDto, CoreError> {
    let probe = GatewaySocket::for_vault(v, data_dir);
    match v.mesh_caps(cap, None, &probe) {
        Ok(report) => Ok(MeshCapsDto {
            report,
            reconcile_error: None,
        }),
        Err(e) => {
            let store = v.mesh_open_store()?;
            let only = match cap {
                Some(c) => Some(caps::resolve(&store, c)?),
                None => None,
            };
            Ok(MeshCapsDto {
                report: caps::report(&store, only, None)?,
                reconcile_error: Some(e.to_string()),
            })
        }
    }
}

#[tauri::command]
pub(crate) fn mesh_projects_list(state: State<'_, AppState>) -> CmdResult<Vec<MeshProjectRow>> {
    with_vault_background(&state, |v| v.mesh_projects())
}

/// Share a local project with the mesh: a new mesh project with its name,
/// bound here.
#[tauri::command]
pub(crate) fn mesh_project_share(
    state: State<'_, AppState>,
    local_project_id: String,
) -> CmdResult<MeshShareDto> {
    let (id, name) = with_vault(&state, |v| v.mesh_project_share(&local_project_id))?;
    Ok(MeshShareDto {
        mesh_project_id: id.to_hex(),
        name,
    })
}

/// Bind a mesh project to a local project on this device only. Explicit,
/// never automatic.
#[tauri::command]
pub(crate) fn mesh_project_bind(
    state: State<'_, AppState>,
    mesh_project_id: String,
    local_project_id: String,
) -> CmdResult<String> {
    let id = with_vault(&state, |v| {
        v.mesh_project_bind(&mesh_project_id, &local_project_id)
    })?;
    Ok(id.to_hex())
}

/// Returns whether a binding was removed.
#[tauri::command]
pub(crate) fn mesh_project_unbind(
    state: State<'_, AppState>,
    local_project_id: String,
) -> CmdResult<bool> {
    with_vault(&state, |v| v.mesh_project_unbind(&local_project_id))
}

#[tauri::command]
pub(crate) fn mesh_project_rename(
    state: State<'_, AppState>,
    mesh_project_id: String,
    name: String,
) -> CmdResult<String> {
    let id = with_vault(&state, |v| v.mesh_project_rename(&mesh_project_id, &name))?;
    Ok(id.to_hex())
}

#[tauri::command]
pub(crate) fn mesh_project_archive(
    state: State<'_, AppState>,
    mesh_project_id: String,
) -> CmdResult<String> {
    let id = with_vault(&state, |v| v.mesh_project_archive(&mesh_project_id))?;
    Ok(id.to_hex())
}

/// The UI confirms first. Refused by core when both projects have caps.
#[tauri::command]
pub(crate) fn mesh_project_merge(
    state: State<'_, AppState>,
    a: String,
    b: String,
) -> CmdResult<MeshMergeDto> {
    let (root, merged) = with_vault(&state, |v| v.mesh_project_merge(&a, &b))?;
    Ok(MeshMergeDto {
        root: root.to_hex(),
        merged: merged.to_hex(),
    })
}

/// `publish: true` publishes this device's usage first (a write; for an
/// explicit refresh), `false` only reads (safe to poll).
#[tauri::command]
pub(crate) fn mesh_usage_report(
    state: State<'_, AppState>,
    filter: MeshUsageFilterDto,
    publish: bool,
) -> CmdResult<MeshUsageDto> {
    if publish {
        with_vault(&state, |v| {
            let f = usage_filter(v, &filter)?;
            // As `tethra mesh usage`: a failed publish is a note beside the
            // figures already published, not a failure.
            let publish_error = v.mesh_publish().err().map(|e| e.to_string());
            Ok(MeshUsageDto {
                report: v.mesh_usage(&f)?,
                publish_error,
            })
        })
    } else {
        with_vault_background(&state, |v| {
            let f = usage_filter(v, &filter)?;
            Ok(MeshUsageDto {
                report: v.mesh_usage(&f)?,
                publish_error: None,
            })
        })
    }
}

/// `reconcile: true` runs the cap reconciler first (a write; on open and
/// after an action), `false` only reads (safe to poll).
#[tauri::command]
pub(crate) fn mesh_caps_list(
    state: State<'_, AppState>,
    reconcile: bool,
) -> CmdResult<MeshCapsDto> {
    if reconcile {
        with_vault(&state, |v| reconciled_report(v, &state.data_dir, None))
    } else {
        with_vault_background(&state, |v| {
            Ok(MeshCapsDto {
                report: caps::report(&v.mesh_open_store()?, None, None)?,
                reconcile_error: None,
            })
        })
    }
}

/// `monthly_usd` is text such as `"25"` or `"12.50"`.
#[tauri::command]
pub(crate) fn mesh_cap_create(
    state: State<'_, AppState>,
    mesh_project_id: String,
    monthly_usd: String,
) -> CmdResult<CapCreated> {
    with_vault(&state, |v| {
        let amount = micros(&monthly_usd)?;
        let probe = GatewaySocket::for_vault(v, &state.data_dir);
        v.mesh_cap_create(&mesh_project_id, amount, &probe)
    })
}

/// On the owner a raise mints; elsewhere it is a labelled local override
/// for this month (the UI explains and confirms first).
#[tauri::command]
pub(crate) fn mesh_cap_raise(
    state: State<'_, AppState>,
    cap_id: String,
    usd: String,
) -> CmdResult<CapChanged> {
    with_vault(&state, |v| {
        let amount = micros(&usd)?;
        let probe = GatewaySocket::for_vault(v, &state.data_dir);
        v.mesh_cap_raise(&cap_id, amount, &probe)
    })
}

/// Lower the monthly target to `usd` (the UI confirms first).
#[tauri::command]
pub(crate) fn mesh_cap_lower(
    state: State<'_, AppState>,
    cap_id: String,
    usd: String,
) -> CmdResult<CapChanged> {
    with_vault(&state, |v| {
        let target = micros(&usd)?;
        let probe = GatewaySocket::for_vault(v, &state.data_dir);
        v.mesh_cap_lower(&cap_id, target, &probe)
    })
}

/// One cap's report with its per-device rights (reconciles first).
#[tauri::command]
pub(crate) fn mesh_cap_rights(
    state: State<'_, AppState>,
    cap_id: String,
) -> CmdResult<MeshCapsDto> {
    with_vault(&state, |v| {
        reconciled_report(v, &state.data_dir, Some(&cap_id))
    })
}

/// Owner only: ask holders to give unspent rights back (every other device,
/// or `from_device`).
#[tauri::command]
pub(crate) fn mesh_cap_reclaim(
    state: State<'_, AppState>,
    cap_id: String,
    from_device: Option<String>,
) -> CmdResult<MeshReclaimDto> {
    // Passed as is: a blank device is refused by core, never widened to
    // "every device".
    let (id, devices) = with_vault(&state, |v| {
        v.mesh_cap_reclaim(&cap_id, from_device.as_deref())
    })?;
    Ok(MeshReclaimDto {
        cap_id: id.to_hex(),
        devices: devices.iter().map(|d| d.to_hex()).collect(),
    })
}

/// Reauthenticated in core. `cap_id: None` means every cap (`--all`); a
/// blank id is passed as is (core refuses it), never read as "every cap".
#[tauri::command]
pub(crate) fn mesh_cap_enforce(
    state: State<'_, AppState>,
    master_password: String,
    cap_id: Option<String>,
    on: bool,
) -> CmdResult<MeshEnforceDto> {
    let master_password = SecretString::new(master_password);
    let changed = with_vault(&state, |v| {
        v.mesh_cap_enforce(&master_password, cap_id.as_deref(), on)
    })?;
    Ok(MeshEnforceDto {
        caps: changed.iter().map(|c| c.to_hex()).collect(),
        on,
    })
}
