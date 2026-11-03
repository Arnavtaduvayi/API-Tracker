//! Opt-in credential sharing (Increment 11, DESIGN §D16, ADR 0033).
//!
//! The user shares **one** credential with specific paired devices. For each
//! recipient the sharer mints a `share.sealed` item: signed by the sharer
//! like every item, carrying a `crypto_box` sealed box to the recipient's
//! sealing key. The box holds a JSON plaintext that repeats every field of
//! the signed envelope (mesh, share id, credential name, provider, value
//! version, recipient) plus the sharer and the value. Sealed boxes are
//! anonymous, so after opening one the recipient checks every repeated field
//! against the signed envelope and its signer ([`verify_bindings`]); without
//! that, a member could re-wrap another device's box, or seal a value of its
//! own under another device's name, and plant it in a third device's vault.
//!
//! Nothing here is automatic (MESH-SI-13): sharing, importing and resealing
//! each need the master password, checked by the `UnlockedVault` methods
//! that call this module (`vault/mesh_share.rs`). The value exists in
//! plaintext only inside [`share`] (while sealing, in zeroizing buffers) and
//! inside [`open`] (while importing); the sealing private key only inside the
//! import (MESH-SI-7). Revoking a share is a tombstone: it never revokes the
//! credential at its provider, and a device keeps whatever it imported.
//!
//! Shares addressed to a removed device are hidden by the views and
//! collected from storage ([`purge`], PROTOCOL.md §8.4 (b)).

use super::crdt::lww_map::LwwEntry;
use super::crdt::Admit;
use super::dot::{CredentialRef, DeviceId, MeshId, MeshProjectId, ShareId};
use super::error::MeshError;
use super::kinds::{ShareRevoke, ShareSealed, MAX_NAME_BYTES, MAX_SEALED_BYTES};
use super::sign::{PublicKeyBytes, SigningKeyPair};
use super::sqlite_store::SqliteStore;
use super::store::{Draft, HlcPolicy, MeshStore};
use super::views::{SealedValue, ShareWinner, State};
use crate::error::{CoreError, Result};
use crate::secret::SecretString;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use zeroize::Zeroizing;

/// The longest credential value accepted for sharing. The sealed box (the
/// JSON-escaped value and bound fields, plus 48 bytes of box overhead) must
/// also fit the 16 KiB a `share.sealed` may carry (`kinds::MAX_SEALED_BYTES`),
/// which [`seal_to`] checks: a value near this size that needs heavy JSON
/// escaping is refused there.
pub const MAX_VALUE_BYTES: usize = 15 * 1024;

/// Who receives a share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recipients {
    /// Every active device other than this one, and later ones as a reseal
    /// offer (never automatically).
    AllCurrent,
    /// These devices only.
    Devices(Vec<DeviceId>),
}

/// The local credential being shared. `value` is exposed only while sealing.
pub struct ShareSource<'a> {
    /// The local project, for the audit row.
    pub project_id: &'a str,
    pub credential_id: &'a str,
    pub credential_name: &'a str,
    pub provider: &'a str,
    pub value_version: u64,
    pub mesh_project: MeshProjectId,
    pub value: &'a SecretString,
}

/// One recipient of a share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SharedTo {
    pub device_id: DeviceId,
    pub device_name: Option<String>,
    pub share_id: ShareId,
}

/// What [`share`] did. No value, no sealed bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ShareReceipt {
    pub credential_ref: CredentialRef,
    pub credential_id: String,
    pub credential_name: String,
    pub provider: String,
    pub value_version: u64,
    pub mesh_project_id: MeshProjectId,
    /// "All my current devices" was chosen: devices paired later get a
    /// reseal offer.
    pub all_current: bool,
    pub recipients: Vec<SharedTo>,
}

/// The plaintext inside a sealed box, as the sharer writes it. Field order is
/// the struct's.
#[derive(Serialize)]
struct PlainOut<'a> {
    mesh_id: MeshId,
    share_id: ShareId,
    credential_name: &'a str,
    provider: &'a str,
    value_version: u64,
    recipient: DeviceId,
    sharer: DeviceId,
    value: &'a str,
}

/// The plaintext as the recipient reads it. Strings borrow from the opened
/// (zeroizing) buffer wherever JSON needs no unescaping.
#[derive(Deserialize)]
struct PlainIn<'a> {
    mesh_id: MeshId,
    share_id: ShareId,
    #[serde(borrow)]
    credential_name: Cow<'a, str>,
    #[serde(borrow)]
    provider: Cow<'a, str>,
    value_version: u64,
    recipient: DeviceId,
    sharer: DeviceId,
    #[serde(borrow)]
    value: Cow<'a, str>,
}

fn storage(what: &'static str) -> impl Fn(rusqlite::Error) -> MeshError {
    move |_| MeshError::Storage(what)
}

/// Seal `plain` to `seal_pub`. The JSON is written into a zeroizing buffer
/// reserved large enough that it never reallocates (a reallocation would
/// leave a copy of the value in freed memory).
fn seal_to(
    seal_pub: &PublicKeyBytes,
    plain: &PlainOut<'_>,
) -> std::result::Result<Vec<u8>, MeshError> {
    let escaped = 6 * (plain.value.len() + plain.credential_name.len() + plain.provider.len());
    let mut buf = Zeroizing::new(Vec::with_capacity(512 + escaped));
    serde_json::to_writer(&mut *buf, plain)
        .map_err(|_| MeshError::InvalidOperation("the share could not be encoded"))?;
    let sealed = crypto_box::PublicKey::from_bytes(seal_pub.0)
        .seal(&mut crypto_box::aead::OsRng, &buf)
        .map_err(|_| MeshError::InvalidOperation("the share could not be sealed"))?;
    if sealed.len() > MAX_SEALED_BYTES {
        return Err(MeshError::InvalidOperation(
            "the credential is too large to share",
        ));
    }
    Ok(sealed)
}

/// Open a sealed box with this device's sealing secret. The key is used
/// through `crypto_box::SecretKey` (zeroized on drop) and the plaintext is
/// returned in a zeroizing buffer.
fn open(
    seal_secret: &[u8; 32],
    sealed: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, MeshError> {
    let sk = crypto_box::SecretKey::from_slice(&seal_secret[..])
        .map_err(|_| MeshError::ShareUnreadable)?;
    sk.unseal(sealed)
        .map(Zeroizing::new)
        .map_err(|_| MeshError::ShareUnreadable)
}

/// Check every field the sealed plaintext repeats against the signed
/// envelope and its signer (ADR 0033). Anything else is a plant or a
/// corruption; the field names are static and no value is ever echoed.
fn verify_bindings(
    plain: &PlainIn<'_>,
    mesh: MeshId,
    me: DeviceId,
    sharer: DeviceId,
    outer: &SealedValue,
) -> std::result::Result<(), MeshError> {
    let mismatch = MeshError::ShareBindingMismatch;
    if plain.mesh_id != mesh {
        return Err(mismatch("mesh"));
    }
    if plain.share_id != outer.share_id {
        return Err(mismatch("share id"));
    }
    if plain.recipient != me {
        return Err(mismatch("recipient"));
    }
    if plain.sharer != sharer {
        return Err(mismatch("sharer"));
    }
    if plain.credential_name != outer.credential_name {
        return Err(mismatch("credential name"));
    }
    if plain.provider != outer.provider {
        return Err(mismatch("provider"));
    }
    if plain.value_version != outer.value_version {
        return Err(mismatch("value version"));
    }
    if plain.value.trim().is_empty() {
        return Err(mismatch("value"));
    }
    Ok(())
}

/// The value of an incoming share, opened and verified.
pub(crate) struct OpenedShare {
    pub value: SecretString,
}

/// Open the share `incoming` (addressed to this device) with the sealing
/// secret and verify its bindings. The plaintext buffer is zeroized before
/// this returns; the value moves into a `SecretString`.
pub(crate) fn open_incoming(
    seal_secret: &[u8; 32],
    mesh: MeshId,
    me: DeviceId,
    incoming: &Incoming,
) -> std::result::Result<OpenedShare, MeshError> {
    let plaintext = open(seal_secret, &incoming.value.sealed)?;
    // A serde error can quote its input; it is replaced by a static field.
    let plain: PlainIn<'_> = serde_json::from_slice(&plaintext)
        .map_err(|_| MeshError::ShareBindingMismatch("contents"))?;
    verify_bindings(&plain, mesh, me, incoming.sharer, &incoming.value)?;
    // An unescaped value is already its own allocation: move it into the
    // zeroizing wrapper instead of copying it. (The vault trims when it
    // stores the value.)
    let value = match plain.value {
        Cow::Owned(v) => SecretString::new(v),
        Cow::Borrowed(v) => SecretString::from(v),
    };
    Ok(OpenedShare { value })
}

/// A share addressed to this device that can be imported.
#[derive(Clone)]
pub(crate) struct Incoming {
    pub sharer: DeviceId,
    pub value: SealedValue,
}

/// Find incoming share `ident` (its id, or a unique prefix of at least 8 hex
/// characters) among the shares addressed to `me`. A revoked one is
/// [`MeshError::ShareRevoked`]; one made by a device since removed or forked
/// is [`MeshError::ShareFromRemovedDevice`]; one superseded by a newer share
/// of the same credential is not found.
pub(crate) fn find_incoming(state: &State, me: DeviceId, ident: &str) -> Result<Incoming> {
    let ident = ident.trim().to_ascii_lowercase();
    let not_found = || CoreError::NotFound {
        kind: "credential share",
        ident: ident.clone(),
    };
    if ident.len() < 8 || !ident.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(not_found());
    }
    let mut hits = Vec::new();
    for key in state.share_keys().into_iter().filter(|k| k.1 == me) {
        match state.share_at(&key) {
            Some(ShareWinner::Sealed { sharer, value, .. })
                if value.share_id.to_hex().starts_with(&ident) =>
            {
                // A device removed because it was lost or stolen may have
                // shared a value of its choosing before its removal.
                hits.push(if state.roster.is_active(&sharer) {
                    Ok(Incoming {
                        sharer,
                        value: value.clone(),
                    })
                } else {
                    Err(MeshError::ShareFromRemovedDevice)
                });
            }
            Some(ShareWinner::Revoked { share_id, .. })
                if share_id.to_hex().starts_with(&ident) =>
            {
                hits.push(Err(MeshError::ShareRevoked));
            }
            _ => {}
        }
    }
    match hits.len() {
        0 => Err(not_found()),
        1 => Ok(hits.remove(0)?),
        _ => Err(CoreError::InvalidInput(
            "several shares start with that; give more of the share id".into(),
        )),
    }
}

/// The credential reference this device uses for local credential
/// `credential_id`, if it ever shared it.
pub fn outgoing_ref(conn: &Connection, credential_id: &str) -> Result<Option<CredentialRef>> {
    let r: Option<String> = conn
        .query_row(
            "SELECT credential_ref FROM mesh_share_outgoing WHERE credential_id = ?1",
            [credential_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(r.and_then(|s| CredentialRef::parse(&s).ok()))
}

/// The local credential and intent behind credential reference `r`.
fn outgoing_row(conn: &Connection, r: &CredentialRef) -> Result<Option<(String, bool)>> {
    Ok(conn
        .query_row(
            "SELECT credential_id, all_current FROM mesh_share_outgoing WHERE credential_ref = ?1",
            [r.to_hex()],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
        )
        .optional()?)
}

/// This device's own admitted `share.sealed` entry at `key`, whether or not
/// it is the key's winner (another device's item at the key never hides
/// this device's share from it).
fn own_entry<'a>(
    state: &'a State,
    key: &(CredentialRef, DeviceId),
    me: &DeviceId,
) -> Option<&'a LwwEntry<SealedValue>> {
    state.shares_sealed.register(key).and_then(|r| {
        r.entries()
            .find(|(o, e)| *o == me && state.roster.admits(o, e.seq))
            .map(|(_, e)| e)
    })
}

/// Every key at which this device has an admitted share that no revoke
/// names: what it can still revoke.
fn own_live(state: &State, me: &DeviceId) -> Vec<((CredentialRef, DeviceId), SealedValue)> {
    state
        .share_keys()
        .into_iter()
        .filter(|k| !state.roster.is_removed(&k.1))
        .filter_map(|k| {
            let e = own_entry(state, &k, me)?;
            let v = &e.value.value;
            state
                .share_revoked_by(&k, &v.share_id)
                .is_none()
                .then(|| (k, v.clone()))
        })
        .collect()
}

fn device_name(state: &State, d: &DeviceId) -> Option<String> {
    state
        .device_info
        .value(d, &state.roster)
        .map(|v| v.name.clone())
        .or_else(|| state.roster.added_name(d).map(str::to_owned))
}

/// Who `recipients` means right now: active devices other than `me`.
fn resolve_recipients(
    state: &State,
    me: DeviceId,
    recipients: &Recipients,
) -> std::result::Result<Vec<DeviceId>, MeshError> {
    let roster = &state.roster;
    let mut out: Vec<DeviceId> = match recipients {
        Recipients::AllCurrent => roster
            .members()
            .copied()
            .filter(|d| *d != me && roster.is_active(d))
            .collect(),
        Recipients::Devices(list) => {
            for d in list {
                if *d == me {
                    return Err(MeshError::InvalidOperation(
                        "a device cannot share a credential with itself",
                    ));
                }
                if !roster.is_active(d) {
                    return Err(MeshError::NotAMember);
                }
            }
            list.clone()
        }
    };
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err(MeshError::InvalidOperation(
            "there is no other active device to share with; pair one first",
        ));
    }
    Ok(out)
}

/// Check what a share's envelope will carry, before the value is touched.
pub(crate) fn check_source(name: &str, provider: &str, value_len: usize) -> Result<()> {
    let valid_text = |s: &str, max: usize| {
        !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
    };
    if !valid_text(name, MAX_NAME_BYTES) {
        return Err(CoreError::InvalidInput(
            "a credential's name must be 1-128 bytes without control characters to share it".into(),
        ));
    }
    if provider.is_empty()
        || provider.len() > 64
        || !provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    {
        return Err(CoreError::InvalidInput(
            "this credential's provider name cannot be shared (it must be lowercase letters, \
             digits, '.', '_' or '-')"
                .into(),
        ));
    }
    if value_len > MAX_VALUE_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "this credential's value is too large to share (the limit is {MAX_VALUE_BYTES} bytes)"
        )));
    }
    Ok(())
}

/// Share `src` with `recipients`: one `share.sealed` per recipient, sealed
/// to its sealing key, minted in one transaction with the local record of
/// the intent (`all_current`). The caller has reauthenticated and decrypted
/// the value.
pub(crate) fn share(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    src: &ShareSource<'_>,
    recipients: &Recipients,
    all_current: bool,
) -> Result<ShareReceipt> {
    check_source(src.credential_name, src.provider, src.value.len())?;
    let me = store.self_id();
    let mesh = store.genesis().mesh_id;
    let mut receipt = ShareReceipt {
        credential_ref: CredentialRef::MIN,
        credential_id: src.credential_id.to_owned(),
        credential_name: src.credential_name.to_owned(),
        provider: src.provider.to_owned(),
        value_version: src.value_version,
        mesh_project_id: src.mesh_project,
        all_current,
        recipients: Vec::new(),
    };
    store.mint_with(signing, |conn, state| {
        if !state.roster.is_active(&me) {
            return Err(MeshError::NotActive);
        }
        let to = resolve_recipients(state, me, recipients)?;
        let existing: Option<String> = conn
            .query_row(
                "SELECT credential_ref FROM mesh_share_outgoing WHERE credential_id = ?1",
                [src.credential_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage("reading shared credentials"))?;
        let cref = match existing.and_then(|s| CredentialRef::parse(&s).ok()) {
            Some(r) => r,
            None => CredentialRef::random(),
        };
        receipt.credential_ref = cref;
        let mut drafts = Vec::with_capacity(to.len());
        for r in to {
            let keys = state.roster.keys(&r).ok_or(MeshError::NotAMember)?;
            let share_id = ShareId::random();
            let sealed = seal_to(
                &keys.seal_pub,
                &PlainOut {
                    mesh_id: mesh,
                    share_id,
                    credential_name: src.credential_name,
                    provider: src.provider,
                    value_version: src.value_version,
                    recipient: r,
                    sharer: me,
                    value: src.value.expose(),
                },
            )?;
            let item = ShareSealed {
                credential: cref,
                recipient: r,
                share_id,
                mesh_project_id: src.mesh_project,
                credential_name: src.credential_name.to_owned(),
                provider: src.provider.to_owned(),
                value_version: src.value_version,
                sealed,
            };
            drafts.push(Draft::of(
                &item,
                HlcPolicy::After(state.share_winning_hlc(&(cref, r))),
            ));
            receipt.recipients.push(SharedTo {
                device_id: r,
                device_name: device_name(state, &r),
                share_id,
            });
        }
        let now = crate::clock::now_rfc3339();
        conn.execute(
            "INSERT INTO mesh_share_outgoing
                 (credential_ref, credential_id, all_current, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(credential_ref) DO UPDATE
                 SET all_current = excluded.all_current, updated_at = excluded.updated_at",
            params![cref.to_hex(), src.credential_id, all_current, now],
        )
        .map_err(storage("recording the share"))?;
        crate::audit::record(
            conn,
            "mesh_credential_shared",
            Some(src.project_id),
            Some(src.credential_id),
            &format!(
                "sealed to {} device(s){}",
                receipt.recipients.len(),
                if all_current {
                    " (all current devices)"
                } else {
                    ""
                }
            ),
        )
        .map_err(|_| MeshError::Storage("recording the audit event"))?;
        Ok(drafts)
    })?;
    Ok(receipt)
}

/// What to revoke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeTarget {
    /// One share (one recipient).
    Share(ShareId),
    /// Every live share of one credential reference.
    Credential(CredentialRef),
}

/// One share a revoke covered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevokedShare {
    pub share_id: ShareId,
    pub credential_ref: CredentialRef,
    pub credential_name: String,
    pub recipient: DeviceId,
    pub recipient_name: Option<String>,
}

/// Resolve a share id or unique prefix (≥ 8 hex characters) among the live
/// (not revoked) shares **this device made**. Shares between other devices,
/// which this device only relays, are never matched.
pub fn resolve_live_share(store: &SqliteStore, ident: &str) -> Result<ShareId> {
    let ident = ident.trim().to_ascii_lowercase();
    let not_found = || CoreError::NotFound {
        kind: "credential share",
        ident: ident.clone(),
    };
    if ident.len() < 8 || !ident.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(not_found());
    }
    let mut hits: Vec<ShareId> = own_live(store.state(), &store.self_id())
        .into_iter()
        .map(|(_, v)| v.share_id)
        .filter(|id| id.to_hex().starts_with(&ident))
        .collect();
    hits.dedup();
    match hits.len() {
        0 => Err(not_found()),
        1 => Ok(hits[0]),
        _ => Err(CoreError::InvalidInput(
            "several shares start with that; give more of the share id".into(),
        )),
    }
}

/// Mint `share.revoke` tombstones for `target`, among the live shares this
/// device made. A revoke ends the share it names wherever it arrives; it
/// does not revoke the credential at its provider, and a device that
/// imported the value keeps it. Revoking one share of an "all current
/// devices" credential turns the intent into an explicit list (no reseal
/// offer brings it back). The audit row commits with the tombstones.
pub(crate) fn revoke(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    target: RevokeTarget,
) -> Result<Vec<RevokedShare>> {
    let mut out = Vec::new();
    let me = store.self_id();
    store.mint_with(signing, |conn, state| {
        let mut drafts = Vec::new();
        let mut refs = Vec::new();
        for (key, value) in own_live(state, &me) {
            let hit = match target {
                RevokeTarget::Share(id) => value.share_id == id,
                RevokeTarget::Credential(r) => key.0 == r,
            };
            if !hit {
                continue;
            }
            let item = ShareRevoke {
                credential: key.0,
                recipient: key.1,
                share_id: value.share_id,
            };
            drafts.push(Draft::of(
                &item,
                HlcPolicy::After(state.share_winning_hlc(&key)),
            ));
            refs.push(key.0);
            out.push(RevokedShare {
                share_id: value.share_id,
                credential_ref: key.0,
                credential_name: value.credential_name.clone(),
                recipient: key.1,
                recipient_name: device_name(state, &key.1),
            });
        }
        if drafts.is_empty() {
            return Err(MeshError::InvalidOperation(
                "there is no live share to revoke there (it may already be revoked)",
            ));
        }
        for r in &out {
            crate::audit::record(
                conn,
                "mesh_share_revoked",
                None,
                None,
                &format!(
                    "share {} to device {}",
                    &r.share_id.to_hex()[..8],
                    &r.recipient.to_hex()[..8]
                ),
            )
            .map_err(|_| MeshError::Storage("recording the audit event"))?;
        }
        refs.sort();
        refs.dedup();
        for r in refs {
            conn.execute(
                "UPDATE mesh_share_outgoing SET all_current = 0, updated_at = ?2
                 WHERE credential_ref = ?1",
                params![r.to_hex(), crate::clock::now_rfc3339()],
            )
            .map_err(storage("recording the revoke"))?;
        }
        Ok(drafts)
    })?;
    Ok(out)
}

/// Stop storing shares addressed to removed devices and collect the ones
/// held (PROTOCOL.md §8.4 (b)). The node runs this every round; a command
/// that lists shares runs it first. Returns how many items went.
pub fn purge(store: &mut SqliteStore) -> Result<usize> {
    store.set_share_purge(true);
    let state = store.state();
    let any = state
        .share_keys()
        .iter()
        .any(|(_, r)| state.roster.is_removed(r));
    if !any {
        return Ok(0);
    }
    Ok(store.gc_shares()?)
}

/// What this device imported a share as.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportedAs {
    pub credential_id: String,
    pub credential_name: String,
    pub project_id: String,
    pub project_name: String,
    pub imported_at: String,
}

/// One share, as `mesh credential list` shows it. Never a value or sealed
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ShareRow {
    pub share_id: ShareId,
    pub credential_ref: CredentialRef,
    pub credential_name: String,
    pub provider: String,
    pub mesh_project_id: MeshProjectId,
    pub mesh_project_name: Option<String>,
    pub sharer: DeviceId,
    pub sharer_name: Option<String>,
    /// The sharer is still an active member. A share from a device since
    /// removed (or forked) cannot be imported.
    pub sharer_active: bool,
    pub recipient: DeviceId,
    pub recipient_name: Option<String>,
    pub value_version: u64,
    pub revoked: bool,
    pub revoked_by: Option<DeviceId>,
    /// Outgoing: another device's share holds this key now, so the recipient
    /// sees that one instead (a reseal puts this device's back).
    pub superseded_by: Option<DeviceId>,
    /// Incoming: what this device imported it as, if it did.
    pub imported: Option<ImportedAs>,
    /// Outgoing: the local credential it came from (if it still exists) and
    /// that credential's value version now.
    pub local_credential_id: Option<String>,
    pub current_value_version: Option<u64>,
}

/// A reseal this device could make (it needs the master password; nothing
/// reseals by itself).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResealOffer {
    pub credential_ref: CredentialRef,
    pub credential_id: String,
    pub credential_name: String,
    pub project_name: String,
    pub current_value_version: u64,
    /// Devices paired after a share to "all my current devices".
    pub new_devices: Vec<DeviceId>,
    /// Devices holding an older value version than the credential has now.
    pub stale_devices: Vec<DeviceId>,
}

impl ResealOffer {
    pub fn devices(&self) -> Vec<DeviceId> {
        let mut d: Vec<DeviceId> = self
            .new_devices
            .iter()
            .chain(&self.stale_devices)
            .copied()
            .collect();
        d.sort();
        d.dedup();
        d
    }
}

/// `mesh credential list`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SharesList {
    /// Shares addressed to this device.
    pub incoming: Vec<ShareRow>,
    /// Shares this device made.
    pub outgoing: Vec<ShareRow>,
    pub reseal_offers: Vec<ResealOffer>,
}

fn imported_as(conn: &Connection, share: &ShareId) -> Result<Option<ImportedAs>> {
    Ok(conn
        .query_row(
            "SELECT i.credential_id, c.name, c.project_id, p.name, i.imported_at
             FROM mesh_share_imports i
             JOIN credentials c ON c.id = i.credential_id
             JOIN projects p ON p.id = c.project_id
             WHERE i.share_id = ?1",
            [share.to_hex()],
            |r| {
                Ok(ImportedAs {
                    credential_id: r.get(0)?,
                    credential_name: r.get(1)?,
                    project_id: r.get(2)?,
                    project_name: r.get(3)?,
                    imported_at: r.get(4)?,
                })
            },
        )
        .optional()?)
}

fn value_version_of(conn: &Connection, credential_id: &str) -> Result<Option<u64>> {
    let v: Option<i64> = conn
        .query_row(
            "SELECT value_version FROM credentials WHERE id = ?1",
            [credential_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(v.map(|v| u64::try_from(v).unwrap_or(0)))
}

#[allow(clippy::too_many_arguments)]
fn row(
    store: &SqliteStore,
    key: &(CredentialRef, DeviceId),
    sharer: DeviceId,
    value: &SealedValue,
    revoked_by: Option<DeviceId>,
    superseded_by: Option<DeviceId>,
    incoming: bool,
) -> Result<ShareRow> {
    let state = store.state();
    let conn = store.connection();
    let local = if incoming {
        None
    } else {
        outgoing_row(conn, &key.0)?.map(|(id, _)| id)
    };
    let current = match &local {
        Some(id) => value_version_of(conn, id)?,
        None => None,
    };
    Ok(ShareRow {
        share_id: value.share_id,
        credential_ref: key.0,
        credential_name: value.credential_name.clone(),
        provider: value.provider.clone(),
        mesh_project_id: value.mesh_project_id,
        mesh_project_name: state
            .projects
            .value(&value.mesh_project_id, &state.roster)
            .map(|p| p.name.clone()),
        sharer,
        sharer_name: device_name(state, &sharer),
        sharer_active: state.roster.is_active(&sharer),
        recipient: key.1,
        recipient_name: device_name(state, &key.1),
        value_version: value.value_version,
        revoked: revoked_by.is_some(),
        revoked_by,
        superseded_by,
        imported: if incoming {
            imported_as(conn, &value.share_id)?
        } else {
            None
        },
        local_credential_id: local,
        current_value_version: current,
    })
}

/// Every share addressed to or made by this device, and the reseal offers.
/// Incoming: each key's winner (PROTOCOL.md §5.6), what an import opens.
/// Outgoing: this device's own entry at each key, whether or not another
/// device's item has superseded it there.
pub fn list(store: &SqliteStore) -> Result<SharesList> {
    let state = store.state();
    let me = store.self_id();
    let mut out = SharesList::default();
    for key in state.share_keys() {
        if key.1 == me {
            let (sharer, value, revoked_by) = match state.share_at(&key) {
                Some(ShareWinner::Sealed { sharer, value, .. }) => (sharer, value, None),
                Some(ShareWinner::Revoked {
                    revoker,
                    sealed: Some((sharer, value)),
                    ..
                }) => (sharer, value, Some(revoker)),
                _ => continue,
            };
            out.incoming
                .push(row(store, &key, sharer, value, revoked_by, None, true)?);
        } else if !state.roster.is_removed(&key.1) {
            let Some(e) = own_entry(state, &key, &me) else {
                continue;
            };
            let value = &e.value.value;
            let revoked_by = state.share_revoked_by(&key, &value.share_id);
            let superseded_by = match state.share_at(&key) {
                Some(ShareWinner::Sealed { sharer, .. })
                | Some(ShareWinner::Revoked {
                    sealed: Some((sharer, _)),
                    ..
                }) if sharer != me => Some(sharer),
                _ => None,
            };
            out.outgoing.push(row(
                store,
                &key,
                me,
                value,
                revoked_by,
                superseded_by,
                false,
            )?);
        }
    }
    out.reseal_offers = reseal_offers(store)?;
    Ok(out)
}

/// The reseals this device could make: for each credential it shared, the
/// active devices paired since a share to "all my current devices" (no
/// share entry of either kind for them yet), and the devices whose live
/// share from this device holds an older value version than the credential
/// has now, or has been superseded at its key by another device's item.
pub fn reseal_offers(store: &SqliteStore) -> Result<Vec<ResealOffer>> {
    let state = store.state();
    let conn = store.connection();
    let me = store.self_id();
    if !state.roster.is_active(&me) {
        return Ok(Vec::new());
    }
    let mut st = conn.prepare(
        "SELECT o.credential_ref, o.credential_id, o.all_current, c.name, p.name, c.value_version
         FROM mesh_share_outgoing o
         JOIN credentials c ON c.id = o.credential_id
         JOIN projects p ON p.id = c.project_id
         ORDER BY c.name",
    )?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, bool>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, i64>(5)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (cref, credential_id, all_current, name, project, version) = row?;
        let Ok(cref) = CredentialRef::parse(&cref) else {
            continue;
        };
        let version = u64::try_from(version).unwrap_or(0);
        let mut new_devices = Vec::new();
        let mut stale_devices = Vec::new();
        for d in state
            .roster
            .members()
            .copied()
            .filter(|d| *d != me && state.roster.is_active(d))
        {
            let key = (cref, d);
            match own_entry(state, &key, &me) {
                None => {
                    if all_current && state.share_at(&key).is_none() {
                        new_devices.push(d);
                    }
                }
                Some(e) => {
                    let v = &e.value.value;
                    if state.share_revoked_by(&key, &v.share_id).is_some() {
                        continue; // revoked on purpose: never offered again
                    }
                    let shadowed = matches!(
                        state.share_at(&key),
                        Some(ShareWinner::Sealed { sharer, .. }) if sharer != me
                    );
                    if v.value_version < version || shadowed {
                        stale_devices.push(d);
                    }
                }
            }
        }
        if !new_devices.is_empty() || !stale_devices.is_empty() {
            out.push(ResealOffer {
                credential_ref: cref,
                credential_id,
                credential_name: name,
                project_name: project,
                current_value_version: version,
                new_devices,
                stale_devices,
            });
        }
    }
    Ok(out)
}

/// Whether this device's shares of `credential_ref` were made to "all my
/// current devices".
pub(crate) fn all_current(conn: &Connection, credential_ref: &CredentialRef) -> Result<bool> {
    Ok(outgoing_row(conn, credential_ref)?.is_some_and(|(_, all)| all))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (MeshId, DeviceId, DeviceId, ShareId) {
        (
            MeshId::from_bytes([1; 16]),
            DeviceId::from_bytes([2; 16]),
            DeviceId::from_bytes([3; 16]),
            ShareId::from_bytes([4; 16]),
        )
    }

    fn outer(share_id: ShareId) -> SealedValue {
        SealedValue {
            share_id,
            mesh_project_id: MeshProjectId::from_bytes([5; 16]),
            credential_name: "OPENAI_API_KEY".into(),
            provider: "openai".into(),
            value_version: 3,
            sealed: Vec::new(),
        }
    }

    fn plain<'a>(mesh: MeshId, me: DeviceId, sharer: DeviceId, id: ShareId) -> PlainOut<'a> {
        PlainOut {
            mesh_id: mesh,
            share_id: id,
            credential_name: "OPENAI_API_KEY",
            provider: "openai",
            value_version: 3,
            recipient: me,
            sharer,
            value: "sk-test-FAKE-unit-canary-0001",
        }
    }

    /// Seal → open round trip with a fresh key pair; every bound field is
    /// checked and each one, changed alone, is refused by name.
    #[test]
    fn sealed_bindings_round_trip_and_each_field_is_checked() {
        let (mesh, me, sharer, id) = ids();
        let (secret, public) = crate::mesh::identity::x25519_generate();
        let sealed = seal_to(&public, &plain(mesh, me, sharer, id)).unwrap();
        let mut value = outer(id);
        value.sealed = sealed;
        let inc = Incoming {
            sharer,
            value: value.clone(),
        };
        let opened = open_incoming(&secret, mesh, me, &inc).unwrap();
        assert_eq!(opened.value.expose(), "sk-test-FAKE-unit-canary-0001");

        let cases: Vec<(&str, PlainOut<'_>)> = vec![
            (
                "mesh",
                PlainOut {
                    mesh_id: MeshId::from_bytes([9; 16]),
                    ..plain(mesh, me, sharer, id)
                },
            ),
            (
                "share id",
                PlainOut {
                    share_id: ShareId::from_bytes([9; 16]),
                    ..plain(mesh, me, sharer, id)
                },
            ),
            (
                "recipient",
                PlainOut {
                    recipient: sharer,
                    ..plain(mesh, me, sharer, id)
                },
            ),
            (
                "sharer",
                PlainOut {
                    sharer: me,
                    ..plain(mesh, me, sharer, id)
                },
            ),
            (
                "credential name",
                PlainOut {
                    credential_name: "OTHER",
                    ..plain(mesh, me, sharer, id)
                },
            ),
            (
                "provider",
                PlainOut {
                    provider: "anthropic",
                    ..plain(mesh, me, sharer, id)
                },
            ),
            (
                "value version",
                PlainOut {
                    value_version: 2,
                    ..plain(mesh, me, sharer, id)
                },
            ),
            (
                "value",
                PlainOut {
                    value: "  ",
                    ..plain(mesh, me, sharer, id)
                },
            ),
        ];
        for (field, p) in cases {
            let mut v = value.clone();
            v.sealed = seal_to(&public, &p).unwrap();
            let inc = Incoming { sharer, value: v };
            let err = open_incoming(&secret, mesh, me, &inc).err().unwrap();
            assert_eq!(err, MeshError::ShareBindingMismatch(field), "{field}");
            assert!(!err.to_string().contains("canary"));
        }
    }

    #[test]
    fn a_box_for_another_key_or_garbage_is_unreadable_without_echoing_it() {
        let (mesh, me, sharer, id) = ids();
        let (_, other_public) = crate::mesh::identity::x25519_generate();
        let (secret, public) = crate::mesh::identity::x25519_generate();
        let mut v = outer(id);
        v.sealed = seal_to(&other_public, &plain(mesh, me, sharer, id)).unwrap();
        let inc = Incoming {
            sharer,
            value: v.clone(),
        };
        assert_eq!(
            open_incoming(&secret, mesh, me, &inc).err(),
            Some(MeshError::ShareUnreadable)
        );
        // A box that opens but holds no JSON: a static error, no input echo.
        let junk = crypto_box::PublicKey::from_bytes(public.0)
            .seal(
                &mut crypto_box::aead::OsRng,
                b"{\"value\": \"sk-test-FAKE-unit-canary-0002\"",
            )
            .unwrap();
        let inc = Incoming {
            value: SealedValue { sealed: junk, ..v },
            ..inc
        };
        let err = open_incoming(&secret, mesh, me, &inc).err().unwrap();
        assert_eq!(err, MeshError::ShareBindingMismatch("contents"));
        assert!(!format!("{err} {err:?}").contains("canary"));
    }

    #[test]
    fn a_value_too_large_to_seal_is_refused_before_sealing() {
        assert!(check_source("K", "openai", MAX_VALUE_BYTES).is_ok());
        assert!(check_source("K", "openai", MAX_VALUE_BYTES + 1).is_err());
        assert!(check_source("K", "Open AI", 10).is_err());
        assert!(check_source("", "openai", 10).is_err());
        // The largest plain value seals; one that escapes past the item's
        // limit is refused, not truncated.
        let (mesh, me, sharer, id) = ids();
        let (_, public) = crate::mesh::identity::x25519_generate();
        let big = "a".repeat(MAX_VALUE_BYTES);
        let p = PlainOut {
            value: &big,
            ..plain(mesh, me, sharer, id)
        };
        assert!(seal_to(&public, &p).unwrap().len() <= MAX_SEALED_BYTES);
        let worst = "\u{1}".repeat(MAX_VALUE_BYTES);
        let p = PlainOut {
            value: &worst,
            ..plain(mesh, me, sharer, id)
        };
        assert!(matches!(
            seal_to(&public, &p),
            Err(MeshError::InvalidOperation(_))
        ));
    }
}
