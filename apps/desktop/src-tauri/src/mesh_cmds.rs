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
//! - The reads a live Devices page may refresh on a timer (`mesh_status`,
//!   `mesh_devices`, `mesh_peers_list`, `mesh_node_get_settings`) use
//!   `with_vault_background`, so a timer cannot keep refreshing the
//!   inactivity clock and defeat auto-lock (the rule in main.rs).
//! - No analytics (MESH-SI-14).

use super::{with_vault, with_vault_background, AppState, CmdResult, ErrDto};
use api_tracker_core::error::CoreError;
use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::doctor::Severity;
use api_tracker_core::mesh::identity::MeshStatus;
use api_tracker_core::mesh::invite::format_invite;
use api_tracker_core::mesh::membership::{self, DeviceRow};
use api_tracker_core::mesh::node_settings::NodeSettings;
use api_tracker_core::mesh::peers::{self, PeerLag, PeerRow, PeerSource};
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::mesh::DeviceId;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::MeshLeaveReport;
use api_tracker_mesh::doctor::{DoctorOptions, DoctorReport};
use api_tracker_mesh::instance::{self, ExchangeSummary, NodeStatus, Request, Response};
use api_tracker_mesh::replicate::{leave_mesh, replicate_known_peers};
use api_tracker_mesh::runtime::NodeLog;
use api_tracker_mesh::supervisor::{sync_with_settings, StartOutcome, SupervisorState, STOP_WAIT};
use api_tracker_mesh::{NetError, TransportLimits};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tauri::State;

/// The most node addresses an invite names (core's `invite::MAX_ADDRS`; a
/// node publishes up to 16). The first ones are the addresses it listens on
/// first.
const INVITE_MAX_ADDRS: usize = 8;

/// Where the in-process node reports events: stderr. The node only ever
/// reports static text and ids (never keys, tokens or values).
pub(crate) fn mesh_log() -> Option<NodeLog> {
    Some(Arc::new(|m: &str| eprintln!("mesh: {m}")))
}

/// A network-layer error for the frontend. `NetError`'s messages are static
/// text and identifiers by construction (`crates/mesh/src/error.rs`); a core
/// error keeps its own code.
fn net_err(e: NetError) -> ErrDto {
    match e {
        NetError::Core(c) => ErrDto::from(c),
        other => ErrDto {
            code: "mesh_network".into(),
            message: other.to_string(),
        },
    }
}

fn now_ms() -> u64 {
    SystemClock.now_ms()
}

/// Bring this app's node in line with the stored settings after an unlock
/// (`vault_unlock`), while the unlocked vault is held, so a lock that
/// follows always finds the node. Best effort: a failure never fails the
/// unlock; the supervisor records it and `mesh_status` shows it.
pub(crate) fn start_node_after_unlock(state: &AppState) {
    let _ = with_vault(state, |v| {
        if let Err(e) = sync_with_settings(&state.mesh_node, v, &state.data_dir, mesh_log()) {
            eprintln!("mesh: the node did not start: {e}");
        }
        Ok(())
    });
}

/// Stop this app's node before a backup restore replaces the data
/// directory under it, waiting (bounded) for it to finish. `Err` when it is
/// still stopping; nothing was restored then.
pub(crate) fn stop_node_for_restore(state: &AppState) -> CmdResult<()> {
    if state.mesh_node.stop_and_wait(STOP_WAIT) {
        Ok(())
    } else {
        Err(ErrDto {
            code: "mesh_node_stopping".into(),
            message: "The mesh node is still finishing an exchange; try the restore again in a \
                      moment. Nothing was restored."
                .into(),
        })
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
    let status = with_vault_background(&state, |v| v.mesh_status())?;
    // Outside the vault slot: the control socket is I/O.
    let app = state.mesh_node.state();
    // This app's node answers the data directory's control socket too, so
    // ask it only when this app runs none.
    let external = if app.running.is_none() {
        instance::status(&state.data_dir)
    } else {
        None
    };
    Ok(MeshStatusDto {
        status,
        node: MeshNodeDto { app, external },
    })
}

#[tauri::command]
pub(crate) fn mesh_init(state: State<'_, AppState>, name: String) -> CmdResult<MeshInitDto> {
    let info = with_vault(&state, |v| v.mesh_init(&name))?;
    Ok(MeshInitDto {
        mesh_id: info.mesh_id.to_hex(),
        device_id: info.device_id.to_hex(),
        device_name: info.device_name,
        created_at: info.created_at,
    })
}

/// The addresses a new device dials: those the running node (this app's,
/// else another process's for this data directory) publishes.
fn node_addresses(state: &AppState) -> CmdResult<Vec<String>> {
    let running = state
        .mesh_node
        .state()
        .running
        .or_else(|| instance::status(&state.data_dir));
    let Some(node) = running else {
        return Err(ErrDto {
            code: "mesh_node_not_running".into(),
            message: "Start the mesh node first (turn on \"Run mesh while Tethra is open\" \
                      with a listen address): the new device pairs by connecting to it."
                .into(),
        });
    };
    let mut addrs = node.advertised;
    if addrs.is_empty() {
        return Err(ErrDto {
            code: "mesh_node_no_address".into(),
            message: "The mesh node publishes no address another device could reach. Give it \
                      a listen address on an interface the other device can reach, then try \
                      again."
                .into(),
        });
    }
    addrs.truncate(INVITE_MAX_ADDRS);
    Ok(addrs)
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
    let master_password = SecretString::new(master_password);
    // A locked app answers "locked", not whether a node runs.
    with_vault(&state, |_| Ok(()))?;
    let addresses = node_addresses(&state)?;
    let inv = with_vault(&state, |v| {
        v.mesh_invite_create(&master_password, ttl_minutes)
    })?;
    let text =
        format_invite(&inv.token, &addresses).map_err(|e| ErrDto::from(CoreError::from(e)))?;
    Ok(MeshInviteDto {
        invite: text.expose().to_owned(),
        expires_at: inv.expires_at,
        ttl_minutes: inv.ttl_minutes,
        addresses,
    })
}

/// Network I/O (the pairing handshake and first exchange): runs off the
/// main thread.
#[tauri::command(async)]
pub(crate) fn mesh_join(
    state: State<'_, AppState>,
    invite: String,
    name: String,
) -> CmdResult<MeshJoinDto> {
    // The invite is a bearer secret until it is used: wiped when dropped.
    let invite = zeroize::Zeroizing::new(invite);
    let joined = with_vault(&state, |v| {
        Ok(api_tracker_mesh::pair::join(
            v,
            invite.trim(),
            &name,
            Arc::new(SystemClock),
            TransportLimits::default(),
        ))
    })?;
    let report = joined.map_err(net_err)?;
    Ok(MeshJoinDto {
        mesh_id: report.info.mesh_id.to_hex(),
        device_id: report.info.device_id.to_hex(),
        device_name: report.info.device_name,
        items_in: report.exchange.items_in,
        first_exchange_completed: report.exchange.aborted.is_none(),
        inviter_verified: report.inviter_verified,
    })
}

#[tauri::command]
pub(crate) fn mesh_devices(state: State<'_, AppState>) -> CmdResult<Vec<MeshDeviceDto>> {
    let now = now_ms();
    with_vault_background(&state, |v| {
        let rows = v.mesh_devices()?;
        let store = v.mesh_open_store()?;
        let hello = peers::hello_records(store.connection())?;
        let vv = store.vv();
        Ok(rows
            .into_iter()
            .map(|row| MeshDeviceDto {
                stale: membership::is_stale(&row, now),
                lag: hello.get(&row.device_id).map(|r| peers::lag(r, vv)),
                row,
            })
            .collect())
    })
}

/// Renames this device (a device can rename only itself).
#[tauri::command]
pub(crate) fn mesh_device_rename(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    with_vault(&state, |v| v.mesh_device_rename(&name))
}

/// Reauthenticated in core; the UI confirms first.
#[tauri::command]
pub(crate) fn mesh_device_remove(
    state: State<'_, AppState>,
    master_password: String,
    device_id: String,
) -> CmdResult<MeshRemoveDto> {
    let master_password = SecretString::new(master_password);
    let (removed, access_key_epoch) = with_vault(&state, |v| {
        v.mesh_device_remove(&master_password, &device_id)
    })?;
    Ok(MeshRemoveDto {
        removed: removed.to_hex(),
        access_key_epoch,
    })
}

/// Reauthenticated in core; the UI confirms first. Stops this app's node,
/// tries to deliver the self-removal, wipes the local mesh state.
#[tauri::command(async)]
pub(crate) fn mesh_leave(
    state: State<'_, AppState>,
    master_password: String,
) -> CmdResult<MeshLeaveReport> {
    let master_password = SecretString::new(master_password);
    // A wrong password changes nothing, not even the node.
    with_vault(&state, |v| v.verify_master_password(&master_password))?;
    if !state.mesh_node.is_running() && instance::running_pid(&state.data_dir).is_some() {
        return Err(ErrDto {
            code: "mesh_external_node".into(),
            message: "A mesh node started from the command line is running for this data \
                      directory. Stop it with `tethra mesh stop`, then leave again."
                .into(),
        });
    }
    // The node writes the rows the leave wipes: it must be gone first.
    if !state.mesh_node.stop_and_wait(STOP_WAIT) {
        return Err(ErrDto {
            code: "mesh_node_stopping".into(),
            message: "The mesh node is still finishing an exchange; try leaving again in a \
                      moment. Nothing was changed."
                .into(),
        });
    }
    let left = with_vault(&state, |v| {
        let left = leave_mesh(v, &master_password, Vec::new());
        if left.is_err() {
            // Still in the mesh: run the node again if the settings say so.
            let _ = sync_with_settings(&state.mesh_node, v, &state.data_dir, mesh_log());
        }
        Ok(left)
    })?;
    left.map_err(net_err)
}

#[tauri::command]
pub(crate) fn mesh_peers_list(state: State<'_, AppState>) -> CmdResult<Vec<MeshPeerDto>> {
    let now = now_ms();
    with_vault_background(&state, |v| {
        let names: BTreeMap<DeviceId, String> = v
            .mesh_devices()?
            .into_iter()
            .filter_map(|d| d.name.map(|n| (d.device_id, n)))
            .collect();
        Ok(v.mesh_peers()?
            .into_iter()
            .map(|row| MeshPeerDto {
                device_name: row.device_id.and_then(|d| names.get(&d).cloned()),
                backoff_until: peers::backoff_until(&row, now),
                row,
            })
            .collect())
    })
}

#[tauri::command]
pub(crate) fn mesh_peer_add(state: State<'_, AppState>, addr: String) -> CmdResult<MeshPeerAddDto> {
    let (addr, added) = with_vault(&state, |v| v.mesh_peer_add(&addr))?;
    Ok(MeshPeerAddDto { addr, added })
}

#[tauri::command]
pub(crate) fn mesh_peer_remove(
    state: State<'_, AppState>,
    addr: String,
) -> CmdResult<MeshPeerRemoveDto> {
    let source = with_vault(&state, |v| v.mesh_peer_remove(&addr))?;
    Ok(MeshPeerRemoveDto {
        removed: source.is_some(),
        source,
    })
}

/// A node's answer to `ReplicateNow`.
fn replicated(via: &'static str, response: Response) -> CmdResult<MeshReplicateDto> {
    match response {
        Response::Replicated {
            exchanges,
            repairs_changed,
        } => Ok(MeshReplicateDto {
            via,
            exchanges,
            repairs_changed,
            notes: Vec::new(),
        }),
        Response::Error { message, .. } => Err(ErrDto {
            code: "mesh_node".into(),
            message,
        }),
        _ => Err(ErrDto {
            code: "mesh_node".into(),
            message: "the mesh node gave an unexpected answer".into(),
        }),
    }
}

/// Network I/O: runs off the main thread, and never holds the vault while
/// a node's round runs.
#[tauri::command(async)]
pub(crate) fn mesh_replicate_now(
    state: State<'_, AppState>,
    peer: Option<String>,
) -> CmdResult<MeshReplicateDto> {
    with_vault(&state, |_| Ok(()))?;
    if let Some(response) = state.mesh_node.replicate_now(peer.clone(), false) {
        return replicated("app_node", response);
    }
    if instance::running_pid(&state.data_dir).is_some() {
        let response = instance::request(
            &state.data_dir,
            |nonce| Request::ReplicateNow {
                nonce,
                peer: peer.clone(),
                repair: false,
            },
            instance::REPLICATE_WAIT,
        )
        .map_err(net_err)?;
        return replicated("external_node", response);
    }
    // No node: one exchange per known address, from this command. This
    // needs the vault for the exchanges' keys.
    let report = with_vault(&state, |v| {
        Ok(replicate_known_peers(v, &state.data_dir, peer))
    })?
    .map_err(net_err)?;
    if report.exchanges.is_empty() {
        return Err(ErrDto {
            code: "mesh_no_peers".into(),
            message: "No peer is known yet. Add a peer address, or start the node so this \
                      device learns the addresses your other devices publish."
                .into(),
        });
    }
    Ok(MeshReplicateDto {
        via: "one_shot",
        exchanges: report.exchanges,
        repairs_changed: 0,
        notes: report.notes,
    })
}

#[tauri::command]
pub(crate) fn mesh_doctor(state: State<'_, AppState>) -> CmdResult<MeshDoctorDto> {
    let report = with_vault(&state, |v| {
        Ok(api_tracker_mesh::doctor::run(
            v,
            &state.data_dir,
            Arc::new(SystemClock),
            DoctorOptions::default(),
        ))
    })?
    .map_err(net_err)?;
    Ok(MeshDoctorDto {
        worst: report.worst(),
        report,
    })
}

#[tauri::command]
pub(crate) fn mesh_node_get_settings(state: State<'_, AppState>) -> CmdResult<NodeSettings> {
    with_vault_background(&state, |v| v.mesh_node_settings())
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
    let master_password = master_password.map(SecretString::new);
    let (settings, synced) = with_vault(&state, |v| {
        let stored = v.mesh_node_settings_set(master_password.as_ref(), &settings)?;
        let synced = sync_with_settings(&state.mesh_node, v, &state.data_dir, mesh_log());
        Ok((stored, synced))
    })?;
    let (outcome, start_error) = match synced {
        Ok(o) => (Some(o), None),
        Err(e) => (None, Some(e.to_string())),
    };
    Ok(MeshNodeSettingsDto {
        settings,
        outcome,
        start_error,
    })
}
