//! Tethra Mesh opt-in credential sharing for the desktop (Increment 11, ADR
//! 0033). Thin wrappers over `api-tracker-core`, beside `mesh_cmds.rs` and
//! `mesh_project_cmds.rs`; no business logic here or in TypeScript.
//!
//! - Share, reseal and import reauthenticate in core
//!   (`UnlockedVault::{mesh_credential_share, mesh_credential_reseal,
//!   mesh_credential_import}`); the dialogs are UX only.
//! - No command returns a credential value or sealed bytes: the list carries
//!   names, devices and share ids; an import returns the masked model.
//! - Nothing is automatic (MESH-SI-13): every share, import, reseal and
//!   revoke is one explicit command. The polled list (`purge = false`) uses
//!   `with_vault_background` and writes nothing.
//! - No analytics (MESH-SI-14).

use super::{with_vault, with_vault_background, AppState, CmdResult};
use api_tracker_core::error::CoreError;
use api_tracker_core::mesh::dot::DeviceId;
use api_tracker_core::mesh::share::{Recipients, RevokedShare, ShareReceipt, SharesList};
use api_tracker_core::model::Environment;
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{ImportOptions, ImportReceipt};
use tauri::State;

/// Shares addressed to and made by this device, and the reseal offers. With
/// `purge`, shares addressed to removed devices are collected first (on open
/// and after an action); without it, a background read that writes nothing.
#[tauri::command]
pub(crate) fn mesh_shares_list(state: State<'_, AppState>, purge: bool) -> CmdResult<SharesList> {
    if purge {
        with_vault(&state, |v| v.mesh_shares_list())
    } else {
        with_vault_background(&state, |v| v.mesh_shares_peek())
    }
}

/// `devices: None` is "all my current devices" (and a reseal offer for
/// devices paired later); `Some(ids)` exactly those devices. An empty list
/// is passed as is, and core refuses it: never widened to every device.
#[tauri::command]
pub(crate) fn mesh_credential_share(
    state: State<'_, AppState>,
    master_password: String,
    credential_id: String,
    devices: Option<Vec<String>>,
) -> CmdResult<ShareReceipt> {
    let master_password = SecretString::new(master_password);
    let recipients = match devices {
        None => Recipients::AllCurrent,
        Some(ids) => Recipients::Devices(
            ids.iter()
                .map(|d| {
                    DeviceId::parse(d.trim()).map_err(|_| {
                        CoreError::InvalidInput("a device id must be 32 hex characters".into())
                    })
                })
                .collect::<Result<_, _>>()
                .map_err(super::ErrDto::from)?,
        ),
    };
    with_vault(&state, |v| {
        v.mesh_credential_share(&master_password, &credential_id, recipients)
    })
}

/// Seal the current value to the devices the credential's reseal offer
/// names. Reauthenticated in core; nothing reseals on its own.
#[tauri::command]
pub(crate) fn mesh_credential_reseal(
    state: State<'_, AppState>,
    master_password: String,
    credential_id: String,
) -> CmdResult<ShareReceipt> {
    let master_password = SecretString::new(master_password);
    with_vault(&state, |v| {
        v.mesh_credential_reseal(&master_password, &credential_id)
    })
}

/// Import a share into a local project. Reauthenticated in core, which
/// verifies every sealed field against the signed envelope before anything
/// is stored. Returns the masked credential only.
#[tauri::command]
pub(crate) fn mesh_credential_import(
    state: State<'_, AppState>,
    master_password: String,
    share_id: String,
    local_project_id: String,
    replace: bool,
    environment: Option<String>,
) -> CmdResult<ImportReceipt> {
    let master_password = SecretString::new(master_password);
    with_vault(&state, |v| {
        let environment: Environment = match environment.as_deref().map(str::trim) {
            None | Some("") => Environment::Development,
            Some(e) => e.parse()?,
        };
        v.mesh_credential_import(
            &master_password,
            &share_id,
            &local_project_id,
            ImportOptions {
                replace,
                environment,
            },
        )
    })
}

/// Revoke one share (the UI confirms first). Does not revoke the credential
/// at its provider; a device that imported it keeps the value.
#[tauri::command]
pub(crate) fn mesh_share_revoke(
    state: State<'_, AppState>,
    share_id: String,
) -> CmdResult<Vec<RevokedShare>> {
    with_vault(&state, |v| v.mesh_share_revoke(&share_id))
}

/// Revoke every share this device made of one credential (the UI confirms
/// first).
#[tauri::command]
pub(crate) fn mesh_credential_revoke(
    state: State<'_, AppState>,
    credential_id: String,
) -> CmdResult<Vec<RevokedShare>> {
    with_vault(&state, |v| v.mesh_credential_revoke(&credential_id))
}
