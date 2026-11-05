//! Tethra Mesh credential sharing on the vault (Increment 11, DESIGN §D16,
//! ADR 0033). The protocol half (sealing, bindings, views, revocation, reseal
//! offers) is `crate::mesh::share`; this half holds what needs the vault: the
//! reauthentication, decrypting the value to share, unwrapping the sealing
//! key for an import, and storing an imported value through the existing
//! add and replace paths, re-encrypted under the target project's key.
//!
//! Every method that touches a value or the sealing key reauthenticates in
//! core (`verify_master_password`); neither the CLI, the Tauri wrapper nor
//! React repeats that check. Nothing returned carries a value or sealed
//! bytes; an imported credential is returned as its masked model.

use super::{AddCredential, UnlockedVault};
use crate::audit;
use crate::error::{CoreError, Result};
use crate::mesh::dot::{DeviceId, ShareId};
use crate::mesh::share::{
    self, Recipients, ResealOffer, RevokeTarget, RevokedShare, ShareReceipt, ShareSource,
    SharesList,
};
use crate::mesh::store::MeshStore;
use crate::mesh::MeshError;
use crate::model::{Credential, Environment};
use crate::reuse::ReuseWarning;
use crate::secret::SecretString;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

/// How an import stores the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportOptions {
    /// A credential with the share's name already exists in the target
    /// project: replace its value (the old value is kept as a version), as
    /// `key replace` does. Without it, such an import is refused.
    pub replace: bool,
    /// The environment of a newly created credential.
    pub environment: Environment,
}

/// What an import did. The credential is its masked model only.
#[derive(Clone, Debug, Serialize)]
pub struct ImportReceipt {
    pub credential: Credential,
    pub share_id: ShareId,
    pub sharer: DeviceId,
    pub sharer_name: Option<String>,
    /// An existing credential's value was replaced (and versioned).
    pub replaced: bool,
    pub reuse_warnings: Vec<ReuseWarning>,
}

fn short(id: &str) -> &str {
    &id[..8.min(id.len())]
}

impl UnlockedVault {
    /// Share one credential with paired devices (`tethra mesh credential
    /// share`). Reauthenticated. The credential's project must be bound to a
    /// mesh project, and a password-locked project must be unlocked in this
    /// session. The value is decrypted here, sealed to each recipient's
    /// sealing key inside `mesh::share::share`, and dropped before return.
    pub fn mesh_credential_share(
        &self,
        master_password: &SecretString,
        credential: &str,
        recipients: Recipients,
    ) -> Result<ShareReceipt> {
        self.verify_master_password(master_password)?;
        let all_current = matches!(recipients, Recipients::AllCurrent);
        self.share_credential(credential, &recipients, all_current)
    }

    /// Reseal a shared credential to the devices its reseal offer names
    /// (devices paired since a share to "all my current devices", and
    /// devices holding an older value version). Reauthenticated; never run
    /// by the node on its own.
    pub fn mesh_credential_reseal(
        &self,
        master_password: &SecretString,
        credential: &str,
    ) -> Result<ShareReceipt> {
        self.verify_master_password(master_password)?;
        let row = self.resolve_credential(credential)?;
        let offer = self.reseal_offer_for(&row.id)?.ok_or_else(|| {
            CoreError::InvalidInput(
                "every device this credential was shared with already has its current value".into(),
            )
        })?;
        let all_current = {
            let store = self.mesh_open_store()?;
            share::all_current(store.connection(), &offer.credential_ref)?
        };
        self.share_credential(&row.id, &Recipients::Devices(offer.devices()), all_current)
    }

    fn reseal_offer_for(&self, credential_id: &str) -> Result<Option<ResealOffer>> {
        let store = self.mesh_open_store()?;
        Ok(share::reseal_offers(&store)?
            .into_iter()
            .find(|o| o.credential_id == credential_id))
    }

    /// The shared half of share and reseal, after reauthentication.
    fn share_credential(
        &self,
        credential: &str,
        recipients: &Recipients,
        all_current: bool,
    ) -> Result<ShareReceipt> {
        let row = self.resolve_credential(credential)?;
        if row.linked_credential_id.is_some() {
            return Err(CoreError::InvalidInput(
                "this record is a reference; share the credential it points to".into(),
            ));
        }
        let mesh_project = crate::mesh::projects::bindings(&self.conn)?
            .get(&row.project_id)
            .copied()
            .ok_or(MeshError::ProjectNotBound)?;
        share::check_source(&row.name, &row.provider, 0)?;
        let value_version = self.value_version_of(&row.id)?;
        // Fails with ProjectLocked for a locked password-protected project.
        let value = self.decrypt_credential_value(&row)?;
        let keys = self.mesh_keys()?;
        let mut store = self.mesh_open_store()?;
        let receipt = share::share(
            &mut store,
            keys.signing_key(),
            &ShareSource {
                project_id: &row.project_id,
                credential_id: &row.id,
                credential_name: &row.name,
                provider: &row.provider,
                value_version: u64::try_from(value_version).unwrap_or(0),
                mesh_project,
                value: &value,
            },
            recipients,
            all_current,
        )?;
        // The audit row committed with the share items (`share::share`).
        drop(value);
        Ok(receipt)
    }

    /// Every share addressed to or made by this device, and the reseal
    /// offers (`tethra mesh credential list`). No values. Shares addressed
    /// to removed devices are collected first.
    pub fn mesh_shares_list(&self) -> Result<SharesList> {
        let mut store = self.mesh_open_store()?;
        share::purge(&mut store)?;
        share::list(&store)
    }

    /// Collect held shares addressed to removed devices (the node's round
    /// hook does this every round; a one-shot exchange does it first).
    /// Returns how many items went.
    pub fn mesh_share_purge(&self) -> Result<usize> {
        share::purge(&mut self.mesh_open_store()?)
    }

    /// The same list without the purge: a read that writes nothing (the
    /// desktop's polled view).
    pub fn mesh_shares_peek(&self) -> Result<SharesList> {
        share::list(&self.mesh_open_store()?)
    }

    /// Import share `share_ident` (its id or a unique prefix) into local
    /// project `local_project` (`tethra mesh credential import`).
    /// Reauthenticated. The sealing private key is unwrapped for this call
    /// only (MESH-SI-7); the box is opened, every bound field checked against
    /// the signed envelope and its signer, and the value stored through the
    /// existing add (or, with `replace`, replace-and-version) path under the
    /// target project's key, together with the local import record.
    pub fn mesh_credential_import(
        &mut self,
        master_password: &SecretString,
        share_ident: &str,
        local_project: &str,
        opts: ImportOptions,
    ) -> Result<ImportReceipt> {
        self.verify_master_password(master_password)?;
        let store = self.mesh_open_store()?;
        let me = store.self_id();
        let mesh = store.genesis().mesh_id;
        let incoming = share::find_incoming(store.state(), me, share_ident)?;
        let sharer_name = store
            .state()
            .device_info
            .value(&incoming.sharer, &store.state().roster)
            .map(|v| v.name.clone());
        drop(store);
        let share_id = incoming.value.share_id;
        let already: Option<String> = self
            .conn
            .query_row(
                "SELECT credential_id FROM mesh_share_imports WHERE share_id = ?1",
                [share_id.to_hex()],
                |r| r.get(0),
            )
            .optional()?;
        if already.is_some() {
            return Err(CoreError::InvalidInput(
                "this share is already imported here (`tethra mesh credential list` shows where)"
                    .into(),
            ));
        }
        let project = self.project_row_by_ident(local_project)?;
        let existing: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT id, provider FROM credentials
                 WHERE project_id = ?1 AND name = ?2 COLLATE NOCASE",
                params![project.id, incoming.value.credential_name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((_, provider)) = &existing {
            if !opts.replace {
                return Err(CoreError::InvalidInput(format!(
                    "project '{}' already has a credential named '{}'; import with --replace to \
                     replace its value (the old value is kept as a version)",
                    project.name, incoming.value.credential_name
                )));
            }
            // The name comes from another device: it never picks a credential
            // of another provider to overwrite.
            if *provider != crate::providers::normalize(&incoming.value.provider) {
                return Err(CoreError::InvalidInput(format!(
                    "project '{}' has a credential named '{}' for provider '{}', but this share \
                     is for provider '{}'; nothing was replaced. Import it into another project",
                    project.name, incoming.value.credential_name, provider, incoming.value.provider
                )));
            }
        }
        let existing = existing.map(|(id, _)| id);
        // The sealing key lives only for the open; the value only until the
        // vault has re-encrypted it under the project key.
        let opened = {
            let seal =
                crate::mesh::identity::load_seal_key(&self.conn, &self.vault_key, &self.vault_id)?;
            share::open_incoming(&seal, mesh, me, &incoming)?
        };
        let sharer_short = incoming.sharer.to_hex();
        let detail = format!(
            "share {} from device {}",
            short(&share_id.to_hex()),
            short(&sharer_short)
        );
        let record = |conn: &rusqlite::Connection, credential_id: &str| -> Result<()> {
            conn.execute(
                "INSERT INTO mesh_share_imports (share_id, credential_id, imported_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    share_id.to_hex(),
                    credential_id,
                    crate::clock::now_rfc3339()
                ],
            )?;
            audit::record(
                conn,
                "mesh_credential_imported",
                Some(&project.id),
                Some(credential_id),
                &detail,
            )?;
            Ok(())
        };
        let (credential, reuse_warnings, replaced) = match existing {
            Some(id) => {
                let (c, w) = self.replace_value_with(
                    &id,
                    opened.value,
                    "replaced by a mesh credential share",
                    record,
                )?;
                (c, w, true)
            }
            None => {
                let (c, w) = self.add_credential_with(
                    AddCredential {
                        project: project.id.clone(),
                        provider: incoming.value.provider.clone(),
                        name: incoming.value.credential_name.clone(),
                        environment: opts.environment,
                        value: opened.value,
                        credential_type: None,
                        key_created_at: None,
                        expires_at: None,
                        docs_url: String::new(),
                        notes: format!(
                            "Imported from device {} through Tethra Mesh.",
                            short(&sharer_short)
                        ),
                    },
                    record,
                )?;
                (c, w, false)
            }
        };
        Ok(ImportReceipt {
            credential,
            share_id,
            sharer: incoming.sharer,
            sharer_name,
            replaced,
            reuse_warnings,
        })
    }

    /// Revoke one share, by its id or a unique prefix (`tethra mesh
    /// credential revoke <share>`). Confirmed by the caller. Revoking does
    /// not revoke the credential at its provider, and a device that imported
    /// it keeps the value: rotate it to cut that device off.
    pub fn mesh_share_revoke(&self, share_ident: &str) -> Result<Vec<RevokedShare>> {
        let keys = self.mesh_keys()?;
        let mut store = self.mesh_open_store()?;
        let id = share::resolve_live_share(&store, share_ident)?;
        // The audit rows commit with the tombstones (`share::revoke`).
        share::revoke(&mut store, keys.signing_key(), RevokeTarget::Share(id))
    }

    /// How many live (not revoked) shares this device made of local
    /// credential `credential_id`; 0 when it never shared it or is not in a
    /// mesh. `delete_credential` refuses while any exist: the delete would
    /// cascade away `mesh_share_outgoing`, the only link from the shares'
    /// reference back to this credential, leaving them live on their
    /// recipients and unrevocable by credential from here.
    pub(super) fn live_outgoing_shares(&self, credential_id: &str) -> Result<usize> {
        let Some(cref) = share::outgoing_ref(&self.conn, credential_id)? else {
            return Ok(0);
        };
        if crate::mesh::identity::self_info(&self.conn)?.is_none() {
            return Ok(0);
        }
        let store = self.mesh_open_store()?;
        Ok(share::list(&store)?
            .outgoing
            .iter()
            .filter(|r| r.credential_ref == cref && !r.revoked)
            .count())
    }

    /// Revoke every live share this device made of local credential
    /// `credential` (`tethra mesh credential revoke --credential`).
    pub fn mesh_credential_revoke(&self, credential: &str) -> Result<Vec<RevokedShare>> {
        let row = self.resolve_credential(credential)?;
        let cref = share::outgoing_ref(&self.conn, &row.id)?.ok_or_else(|| {
            CoreError::InvalidInput("this credential was never shared from this device".into())
        })?;
        let keys = self.mesh_keys()?;
        let mut store = self.mesh_open_store()?;
        share::revoke(
            &mut store,
            keys.signing_key(),
            RevokeTarget::Credential(cref),
        )
    }
}
