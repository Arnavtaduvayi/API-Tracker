//! Tethra Mesh commands for the desktop (Increment 09, ADR 0031): the device
//! workflow without the CLI. Thin wrappers over `api-tracker-core` (identity,
//! membership, settings, reauthentication) and `api-tracker-mesh` (pairing,
//! exchanges, the in-process node); no business logic here.
//!
//! - Reauthentication is enforced in core (`mesh_invite_create`,
//!   `mesh_device_remove`, `mesh_leave`, `mesh_node_settings_set` when it
//!   widens the LAN surface); these wrappers only pass the password through.
//! - The node runs in-process ([`api_tracker_mesh::supervisor`]), started
//!   after unlock when "Run mesh while Tethra is open" is on and stopped on
//!   every lock path and on exit; keys never go to a child process.
//! - The invite string is the only bearer secret that crosses IPC, once.
//!   No key material ever does.
//! - No analytics (MESH-SI-14).

// Contract stubs (Increment 09): every body below is replaced, and this
// allow removed, before the increment's final commit.
#![allow(dead_code)]

use super::{AppState, CmdResult, ErrDto};
use api_tracker_core::mesh::doctor::Severity;
use api_tracker_core::mesh::identity::MeshStatus;
use api_tracker_core::mesh::membership::DeviceRow;
use api_tracker_core::mesh::node_settings::NodeSettings;
use api_tracker_core::mesh::peers::{PeerLag, PeerRow, PeerSource};
use api_tracker_core::vault::MeshLeaveReport;
use api_tracker_mesh::doctor::DoctorReport;
use api_tracker_mesh::instance::{ExchangeSummary, NodeStatus};
use api_tracker_mesh::supervisor::{StartOutcome, SupervisorState};
use serde::Serialize;
use tauri::State;

fn not_implemented() -> ErrDto {
    ErrDto {
        code: "NotImplementedYet".into(),
        message: "this mesh command is not built yet".into(),
    }
}

/// `mesh_status`: this device's mesh identity (flattened `MeshStatus`:
/// `initialized`, then the detail fields when initialized) and its node.
#[derive(Serialize)]
pub(crate) struct MeshStatusDto {
    #[serde(flatten)]
    pub status: MeshStatus,
    pub node: MeshNodeDto,
}

/// The node, as the Devices view shows it.
#[derive(Serialize)]
pub(crate) struct MeshNodeDto {
    /// This app's in-process node: `running` (its status), `stopping`,
    /// `last_error` (why the last start failed), `last_stop`.
    #[serde(flatten)]
    pub app: SupervisorState,
    /// A node another process runs for this data directory (`tethra mesh
    /// serve`), when this app runs none.
    pub external: Option<NodeStatus>,
}

/// `mesh_init`: the new mesh, public parts only.
#[derive(Serialize)]
pub(crate) struct MeshInitDto {
    pub mesh_id: String,
    pub device_id: String,
    pub device_name: String,
    pub created_at: String,
}

/// `mesh_invite_create`: the invite string, shown once. A bearer secret for
/// its lifetime; the frontend drops it when its dialog closes.
#[derive(Serialize)]
pub(crate) struct MeshInviteDto {
    pub invite: String,
    pub expires_at: String,
    pub ttl_minutes: u32,
    /// The node addresses the invite names (where the new device dials).
    pub addresses: Vec<String>,
}

/// `mesh_join`.
#[derive(Serialize)]
pub(crate) struct MeshJoinDto {
    pub mesh_id: String,
    pub device_id: String,
    pub device_name: String,
    pub items_in: u64,
    pub first_exchange_completed: bool,
    /// False: the inviter's key did not match its roster entry; the UI tells
    /// the user to leave and pair again from a device they trust.
    pub inviter_verified: bool,
}

/// `mesh_devices`: one roster entry (flattened `DeviceRow`) with its health.
#[derive(Serialize)]
pub(crate) struct MeshDeviceDto {
    #[serde(flatten)]
    pub row: DeviceRow,
    /// `core::mesh::membership::is_stale`: an active device not exchanged
    /// with for over 24 h, or never.
    pub stale: bool,
    /// From its last `Hello` (`core::mesh::peers::lag`), if any.
    pub lag: Option<PeerLag>,
}

/// `mesh_device_remove`.
#[derive(Serialize)]
pub(crate) struct MeshRemoveDto {
    pub removed: String,
    pub access_key_epoch: u32,
}

/// `mesh_peers_list`: one dialled address (flattened `PeerRow`).
#[derive(Serialize)]
pub(crate) struct MeshPeerDto {
    #[serde(flatten)]
    pub row: PeerRow,
    pub device_name: Option<String>,
    /// `core::mesh::peers::backoff_until` (approximate; the node jitters).
    pub backoff_until: Option<String>,
}

/// `mesh_peer_add`.
#[derive(Serialize)]
pub(crate) struct MeshPeerAddDto {
    pub addr: String,
    pub added: bool,
}

/// `mesh_peer_remove`.
#[derive(Serialize)]
pub(crate) struct MeshPeerRemoveDto {
    pub removed: bool,
    pub source: Option<PeerSource>,
}

/// `mesh_replicate_now`.
#[derive(Serialize)]
pub(crate) struct MeshReplicateDto {
    /// `"app_node"` (this app's node ran the round), `"external_node"` (a
    /// `tethra mesh serve` for this data directory did), or `"one_shot"`
    /// (no node runs: one exchange per known peer address).
    pub via: &'static str,
    pub exchanges: Vec<ExchangeSummary>,
    pub repairs_changed: u64,
    /// Problems before the exchanges (usage not published, caps not
    /// reconciled).
    pub notes: Vec<String>,
}

/// `mesh_doctor`: the findings and the worst severity.
#[derive(Serialize)]
pub(crate) struct MeshDoctorDto {
    pub worst: Severity,
    #[serde(flatten)]
    pub report: DoctorReport,
}

/// `mesh_node_set_settings`: the stored settings and what the node did.
#[derive(Serialize)]
pub(crate) struct MeshNodeSettingsDto {
    pub settings: NodeSettings,
    /// What the node did after the change (`None` when it was not tried).
    pub outcome: Option<StartOutcome>,
    /// Why the node did not start, when it did not. The settings are saved
    /// either way.
    pub start_error: Option<String>,
}

#[tauri::command]
pub(crate) fn mesh_status(state: State<'_, AppState>) -> CmdResult<MeshStatusDto> {
    let _ = &state;
    Err(not_implemented())
}

#[tauri::command]
pub(crate) fn mesh_init(state: State<'_, AppState>, name: String) -> CmdResult<MeshInitDto> {
    let _ = (&state, &name);
    Err(not_implemented())
}

/// Reauthenticated in core. Needs a running node (this app's or another
/// process's) to name its addresses; refused before any token is made
/// otherwise.
#[tauri::command]
pub(crate) fn mesh_invite_create(
    state: State<'_, AppState>,
    master_password: String,
    ttl_minutes: Option<u32>,
) -> CmdResult<MeshInviteDto> {
    let _ = (&state, &master_password, &ttl_minutes);
    Err(not_implemented())
}

/// Network I/O (the pairing handshake and first exchange): runs off the
/// main thread.
#[tauri::command(async)]
pub(crate) fn mesh_join(
    state: State<'_, AppState>,
    invite: String,
    name: String,
) -> CmdResult<MeshJoinDto> {
    let _ = (&state, &invite, &name);
    Err(not_implemented())
}

#[tauri::command]
pub(crate) fn mesh_devices(state: State<'_, AppState>) -> CmdResult<Vec<MeshDeviceDto>> {
    let _ = &state;
    Err(not_implemented())
}

/// Renames this device (a device can rename only itself).
#[tauri::command]
pub(crate) fn mesh_device_rename(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    let _ = (&state, &name);
    Err(not_implemented())
}

/// Reauthenticated in core; the UI confirms first.
#[tauri::command]
pub(crate) fn mesh_device_remove(
    state: State<'_, AppState>,
    master_password: String,
    device_id: String,
) -> CmdResult<MeshRemoveDto> {
    let _ = (&state, &master_password, &device_id);
    Err(not_implemented())
}

/// Reauthenticated in core; the UI confirms first. Stops this app's node,
/// tries to deliver the self-removal, wipes the local mesh state.
#[tauri::command(async)]
pub(crate) fn mesh_leave(
    state: State<'_, AppState>,
    master_password: String,
) -> CmdResult<MeshLeaveReport> {
    let _ = (&state, &master_password);
    Err(not_implemented())
}

#[tauri::command]
pub(crate) fn mesh_peers_list(state: State<'_, AppState>) -> CmdResult<Vec<MeshPeerDto>> {
    let _ = &state;
    Err(not_implemented())
}

#[tauri::command]
pub(crate) fn mesh_peer_add(state: State<'_, AppState>, addr: String) -> CmdResult<MeshPeerAddDto> {
    let _ = (&state, &addr);
    Err(not_implemented())
}

#[tauri::command]
pub(crate) fn mesh_peer_remove(
    state: State<'_, AppState>,
    addr: String,
) -> CmdResult<MeshPeerRemoveDto> {
    let _ = (&state, &addr);
    Err(not_implemented())
}

/// Network I/O: runs off the main thread, and never holds the vault while
/// a node's round runs.
#[tauri::command(async)]
pub(crate) fn mesh_replicate_now(
    state: State<'_, AppState>,
    peer: Option<String>,
) -> CmdResult<MeshReplicateDto> {
    let _ = (&state, &peer);
    Err(not_implemented())
}

#[tauri::command]
pub(crate) fn mesh_doctor(state: State<'_, AppState>) -> CmdResult<MeshDoctorDto> {
    let _ = &state;
    Err(not_implemented())
}

#[tauri::command]
pub(crate) fn mesh_node_get_settings(state: State<'_, AppState>) -> CmdResult<NodeSettings> {
    let _ = &state;
    Err(not_implemented())
}

/// Widening the LAN surface needs `master_password` (core refuses with
/// `mesh_reauth_required` without it, `wrong_password` with a wrong one).
/// Then brings the in-process node in line with the new settings.
#[tauri::command]
pub(crate) fn mesh_node_set_settings(
    state: State<'_, AppState>,
    settings: NodeSettings,
    master_password: Option<String>,
) -> CmdResult<MeshNodeSettingsDto> {
    let _ = (&state, &settings, &master_password);
    Err(not_implemented())
}
