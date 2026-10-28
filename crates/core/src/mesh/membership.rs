//! Membership (Increment 04, DESIGN §D10, PROTOCOL.md §9): invites, joining,
//! the inviter's single-use token claim, devices, rename, removal with
//! access-key rotation, leave, and the exchange log.
//!
//! [`MeshVault`] is the narrow capability a running node holds besides its
//! [`MeshKeys`](super::identity::MeshKeys): it can read and store mesh access
//! keys and read invite psks, all under the vault key, and nothing else. A
//! node runs only while the vault is unlocked (DESIGN §D5), in a process that
//! already holds that key.
//!
//! No network I/O here; `api-tracker-mesh` calls these functions.

use super::clock::Clock;
use super::dot::{DeviceId, MarkerNonce, MeshId};
use super::error::MeshError;
use super::identity::{self, MeshSelfInfo, FIRST_EPOCH};
use super::invite::{
    hint_of, AccessKey, InviteToken, PairAccept, PairRequest, DEFAULT_TTL_MINUTES, HINT_LEN,
    MAX_ATTEMPTS, MAX_TTL_MINUTES,
};
use super::kinds::{DeviceInfo, RosterAdd, RosterRemove};
use super::marker::{self, MarkerContents};
use super::sign::{derive_device_id, PublicKeyBytes, SigningKeyPair};
use super::sqlite_store::{self, MarkerConfig, SqliteStore, StoreParams};
use super::store::{Draft, GenesisInfo, HlcPolicy, MeshStore};
use crate::audit;
use crate::clock as wall;
use crate::crypto::{self, aad};
use crate::error::{CoreError, Result};
use crate::secret::{SecretBytes, REDACTED};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

/// How long the previous access key keeps working after a rotation.
pub const PREVIOUS_EPOCH_GRACE_MS: u64 = 30 * 24 * 3_600_000;
/// Rows kept in `mesh_exchange_log`.
const EXCHANGE_LOG_ROWS: i64 = 1_000;

fn short(d: &DeviceId) -> String {
    d.to_hex()[..8].to_owned()
}

/// A joiner's identity before the inviter has accepted it: keys generated,
/// nothing stored. Dropping it wipes the secrets.
pub struct PendingIdentity {
    name: String,
    signing: SigningKeyPair,
    noise_secret: Zeroizing<[u8; 32]>,
    noise_pub: PublicKeyBytes,
    seal_secret: Zeroizing<[u8; 32]>,
    seal_pub: PublicKeyBytes,
    device_id: DeviceId,
}

impl PendingIdentity {
    pub fn generate(name: &str) -> std::result::Result<Self, MeshError> {
        let name = identity::validate_device_name(name)?;
        let signing = SigningKeyPair::generate();
        let (noise_secret, noise_pub) = identity::x25519_generate();
        let (seal_secret, seal_pub) = identity::x25519_generate();
        let device_id = derive_device_id(&signing.public_key(), &noise_pub, &seal_pub);
        Ok(Self {
            name,
            signing,
            noise_secret,
            noise_pub,
            seal_secret,
            seal_pub,
            device_id,
        })
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The Noise static secret for the pairing handshake. Every call site is
    /// a deliberate exposure.
    pub fn expose_noise_secret(&self) -> &[u8; 32] {
        &self.noise_secret
    }

    pub fn request(&self) -> PairRequest {
        PairRequest {
            name: self.name.clone(),
            sign_pub: self.signing.public_key(),
            noise_pub: self.noise_pub,
            seal_pub: self.seal_pub,
        }
    }
}

impl std::fmt::Debug for PendingIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingIdentity")
            .field("device_id", &self.device_id)
            .field("secrets", &REDACTED)
            .finish()
    }
}

/// A created invite. The token is shown once, inside the invite string.
#[derive(Debug)]
pub struct Invite {
    pub token: InviteToken,
    pub expires_at: String,
    pub ttl_minutes: u32,
}

pub(crate) fn invite_create(
    conn: &Connection,
    vault_key: &SecretBytes,
    vault_id: &str,
    ttl_minutes: Option<u32>,
) -> Result<Invite> {
    if identity::read_self(conn)?.is_none() {
        return Err(MeshError::NotInitialized.into());
    }
    let ttl = ttl_minutes
        .unwrap_or(DEFAULT_TTL_MINUTES)
        .clamp(1, MAX_TTL_MINUTES);
    let token = InviteToken::generate();
    let hash = token.hash();
    let wrapped = crypto::encrypt(
        vault_key,
        &aad::mesh_invite_psk(vault_id, &hex::encode(hash)),
        &token.pairing_psk()[..],
    )?;
    let now = wall::now_rfc3339();
    let expires_at = wall::rfc3339_after(std::time::Duration::from_secs(u64::from(ttl) * 60));
    // Expired invites are useless; keep the table small.
    conn.execute(
        "DELETE FROM mesh_invites WHERE expires_at < ?1",
        [wall::rfc3339_minus_seconds(&now, 86_400)],
    )?;
    conn.execute(
        "INSERT INTO mesh_invites (token_hash, created_at, expires_at, attempts, wrapped_psk)
         VALUES (?1, ?2, ?3, 0, ?4)",
        params![hash.as_slice(), now, expires_at, wrapped],
    )?;
    audit::record(
        conn,
        "mesh_invite_created",
        None,
        None,
        &format!("expires {expires_at}"),
    )?;
    Ok(Invite {
        token,
        expires_at,
        ttl_minutes: ttl,
    })
}

/// Store a joiner's identity after the inviter accepted it (`mesh join`).
/// The joiner mints its `device.info`; its `roster.add` comes from the
/// inviter in the exchange that follows.
pub(crate) fn join(
    conn: &Connection,
    vault_key: &SecretBytes,
    vault_id: &str,
    data_dir: &Path,
    pending: &PendingIdentity,
    accept: &PairAccept,
    clock: Arc<dyn Clock>,
) -> Result<MeshSelfInfo> {
    let dev = pending.device_id.to_hex();
    let mesh_hex = accept.mesh_id.to_hex();
    let wrap = |aad: String, plain: &[u8]| crypto::encrypt(vault_key, &aad, plain);
    let wrapped_sign = wrap(
        aad::mesh_sign_key(vault_id, &dev),
        &pending.signing.expose_secret_bytes()[..],
    )?;
    let wrapped_noise = wrap(
        aad::mesh_noise_key(vault_id, &dev),
        &pending.noise_secret[..],
    )?;
    let wrapped_seal = wrap(aad::mesh_seal_key(vault_id, &dev), &pending.seal_secret[..])?;
    let wrapped_access = wrap(
        aad::mesh_access_key(vault_id, &mesh_hex, accept.access_epoch),
        &accept.access_key.expose()[..],
    )?;
    let nonce = MarkerNonce::random();
    let created_at = wall::now_rfc3339();
    let info = MeshSelfInfo {
        mesh_id: accept.mesh_id,
        genesis_device: accept.genesis,
        device_id: pending.device_id,
        device_name: pending.name.clone(),
        sign_pub: pending.signing.public_key(),
        noise_pub: pending.noise_pub,
        seal_pub: pending.seal_pub,
        access_key_epoch: accept.access_epoch,
        state: "active".into(),
        created_at: created_at.clone(),
    };
    conn.pragma_update(None, "synchronous", "FULL")?;
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    if identity::read_self(&tx)?.is_some() {
        return Err(MeshError::AlreadyInMesh.into());
    }
    identity::delete_mesh_rows(&tx)?;
    // A marker before this identity's first seq (its device.info, below).
    marker::write(data_dir, &MarkerContents::new(pending.device_id, nonce, 0))?;
    tx.execute(
        "INSERT INTO mesh_self (id, mesh_id, genesis_device, device_id, device_name, sign_pub,
             noise_pub, seal_pub, wrapped_sign_key, wrapped_noise_key, wrapped_seal_key,
             access_key_epoch, marker_nonce, state, created_at)
         VALUES ('self', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'active', ?13)",
        params![
            mesh_hex,
            accept.genesis.to_hex(),
            dev,
            pending.name,
            info.sign_pub.to_hex(),
            info.noise_pub.to_hex(),
            info.seal_pub.to_hex(),
            wrapped_sign,
            wrapped_noise,
            wrapped_seal,
            i64::from(accept.access_epoch),
            nonce.to_hex(),
            created_at,
        ],
    )?;
    tx.execute(
        "INSERT INTO mesh_access_keys (epoch, wrapped_key, created_at) VALUES (?1, ?2, ?3)",
        params![i64::from(accept.access_epoch), wrapped_access, created_at],
    )?;
    let params = StoreParams {
        genesis: GenesisInfo {
            mesh_id: accept.mesh_id,
            genesis: accept.genesis,
        },
        self_id: pending.device_id,
        marker: Some(MarkerConfig {
            data_dir: data_dir.to_path_buf(),
            nonce,
        }),
    };
    let device_info = DeviceInfo {
        device: pending.device_id,
        name: pending.name.clone(),
        listen_addrs: Vec::new(),
    };
    sqlite_store::mint_genesis(
        &tx,
        &params,
        clock,
        &pending.signing,
        vec![Draft::of(&device_info, HlcPolicy::After(None))],
    )?;
    audit::record(
        &tx,
        "mesh_device_joined",
        None,
        None,
        &format!(
            "this device {} joined mesh {} via {}",
            &dev[..8],
            &mesh_hex[..8],
            short(&accept.inviter)
        ),
    )?;
    tx.commit()?;
    Ok(info)
}

/// The vault-key capability a running node holds (see the module docs).
pub struct MeshVault {
    vault_key: SecretBytes,
    vault_id: String,
}

impl std::fmt::Debug for MeshVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshVault")
            .field("vault_id", &self.vault_id)
            .field("vault_key", &REDACTED)
            .finish()
    }
}

/// A live invite that matches a pairing hint.
pub struct InviteCandidate {
    pub token_hash: [u8; 32],
    pub psk: Zeroizing<[u8; 32]>,
}

/// The access keys a node may use: the current epoch, and the previous one
/// while it is in its 30-day grace period.
#[derive(Clone, Debug)]
pub struct AccessKeys {
    pub current: (u32, AccessKey),
    pub previous: Option<(u32, AccessKey)>,
}

impl MeshVault {
    pub(crate) fn new(vault_key: SecretBytes, vault_id: String) -> Self {
        Self {
            vault_key,
            vault_id,
        }
    }

    /// Live invites whose hint matches: unused, unexpired, under the attempt
    /// limit. Their psks are unwrapped for the pairing handshake.
    pub fn invite_candidates(
        &self,
        conn: &Connection,
        hint: &[u8; HINT_LEN],
    ) -> Result<Vec<InviteCandidate>> {
        let now = wall::now_rfc3339();
        let mut st = conn.prepare(
            "SELECT token_hash, wrapped_psk FROM mesh_invites
             WHERE used_at IS NULL AND expires_at > ?1 AND attempts < ?2
               AND wrapped_psk IS NOT NULL",
        )?;
        let rows = st
            .query_map(params![now, MAX_ATTEMPTS], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut out = Vec::new();
        for (hash, wrapped) in rows {
            let hash: [u8; 32] = hash
                .try_into()
                .map_err(|_| identity::corrupt("an invite hash is malformed"))?;
            if hint_of(&hash) != *hint {
                continue;
            }
            let psk = identity::unwrap32(
                &self.vault_key,
                &aad::mesh_invite_psk(&self.vault_id, &hex::encode(hash)),
                &wrapped,
                "mesh invite psk",
            )?;
            out.push(InviteCandidate {
                token_hash: hash,
                psk,
            });
        }
        Ok(out)
    }

    /// The current access key, and the previous one if it rotated less than
    /// 30 days ago by `now_ms`.
    pub fn access_keys(&self, conn: &Connection, now_ms: u64) -> Result<AccessKeys> {
        let row = identity::read_self(conn)?.ok_or(MeshError::NotInitialized)?;
        let epoch = row.info.access_key_epoch;
        let mesh = row.info.mesh_id.to_hex();
        let load = |e: u32| -> Result<Option<(AccessKey, String)>> {
            let found: Option<(Vec<u8>, String)> = conn
                .query_row(
                    "SELECT wrapped_key, created_at FROM mesh_access_keys WHERE epoch = ?1",
                    [i64::from(e)],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((wrapped, created)) = found else {
                return Ok(None);
            };
            let key = identity::unwrap32(
                &self.vault_key,
                &aad::mesh_access_key(&self.vault_id, &mesh, e),
                &wrapped,
                "mesh access key",
            )?;
            Ok(Some((AccessKey(key), created)))
        };
        let (current, rotated_at) = load(epoch)?
            .ok_or_else(|| identity::corrupt("the current mesh access key is missing"))?;
        // The previous key is the newest one below the current epoch (a device
        // that caught up across several rotations may not hold epoch − 1).
        let below: Option<i64> = conn.query_row(
            "SELECT MAX(epoch) FROM mesh_access_keys WHERE epoch < ?1",
            [i64::from(epoch)],
            |r| r.get(0),
        )?;
        let previous = match below.and_then(|e| u32::try_from(e).ok()) {
            Some(prev) => {
                let rotated_ms =
                    wall::parse_rfc3339(&rotated_at)?.unix_timestamp_nanos() / 1_000_000;
                let fresh = u64::try_from(rotated_ms)
                    .is_ok_and(|r| now_ms < r.saturating_add(PREVIOUS_EPOCH_GRACE_MS));
                if fresh {
                    load(prev)?.map(|(k, _)| (prev, k))
                } else {
                    None
                }
            }
            None => None,
        };
        Ok(AccessKeys {
            current: (epoch, current),
            previous,
        })
    }

    /// Store an access key a peer delivered (`AccessKeyUpdate`), applied
    /// only after the exchange that carried it has committed. Rules (ADR 0031
    /// R21):
    /// - every rotation is justified by a removal, so an epoch above
    ///   `max_epoch` (`1 + removals this device knows of`) is refused: a member
    ///   cannot jump the epoch (to `u32::MAX`, say) and block later
    ///   rotations, and a device never takes a removal's key before it knows
    ///   that removal;
    /// - a newer epoch replaces ours;
    /// - two keys for one epoch (concurrent rotations) resolve to the one with
    ///   the larger BLAKE3 hash, so every device converges on one.
    ///
    /// Returns whether this device's current key changed.
    pub fn accept_access_key(
        &self,
        conn: &Connection,
        epoch: u32,
        key: &AccessKey,
        max_epoch: u32,
    ) -> Result<bool> {
        if epoch > max_epoch {
            return Ok(false);
        }
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
        let row = identity::read_self(&tx)?.ok_or(MeshError::NotInitialized)?;
        let current = row.info.access_key_epoch;
        if epoch < current {
            return Ok(false);
        }
        if epoch == current {
            let wrapped: Vec<u8> = tx.query_row(
                "SELECT wrapped_key FROM mesh_access_keys WHERE epoch = ?1",
                [i64::from(epoch)],
                |r| r.get(0),
            )?;
            let ours = identity::unwrap32(
                &self.vault_key,
                &aad::mesh_access_key(&self.vault_id, &row.info.mesh_id.to_hex(), epoch),
                &wrapped,
                "mesh access key",
            )?;
            if blake3::hash(key.expose()).as_bytes() <= blake3::hash(&ours[..]).as_bytes() {
                return Ok(false);
            }
        }
        let wrapped = crypto::encrypt(
            &self.vault_key,
            &aad::mesh_access_key(&self.vault_id, &row.info.mesh_id.to_hex(), epoch),
            &key.expose()[..],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO mesh_access_keys (epoch, wrapped_key, created_at)
             VALUES (?1, ?2, ?3)",
            params![i64::from(epoch), wrapped, wall::now_rfc3339()],
        )?;
        tx.execute(
            "UPDATE mesh_self SET access_key_epoch = ?1",
            [i64::from(epoch)],
        )?;
        tx.commit()?;
        Ok(true)
    }
}

/// The highest access-key epoch this device may accept: one per removal it
/// knows of, above the first (see [`MeshVault::accept_access_key`]).
pub fn max_access_epoch(store: &SqliteStore) -> u32 {
    let removals = store.state().roster.cutoffs().count();
    FIRST_EPOCH.saturating_add(u32::try_from(removals).unwrap_or(u32::MAX))
}

/// Whether an invite can still be used: unused, unexpired, under the attempt
/// limit (the rule `invite_candidates` applies).
pub fn invite_is_live(conn: &Connection, token_hash: &[u8; 32]) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT used_at IS NULL AND expires_at > ?1 AND attempts < ?2
             FROM mesh_invites WHERE token_hash = ?3",
            params![wall::now_rfc3339(), MAX_ATTEMPTS, token_hash.as_slice()],
            |r| r.get::<_, bool>(0),
        )
        .optional()?
        .unwrap_or(false))
}

/// Count a failed pairing handshake against an invite (five end it).
pub fn record_failed_attempt(conn: &Connection, token_hash: &[u8; 32]) -> Result<()> {
    conn.execute(
        "UPDATE mesh_invites SET attempts = attempts + 1 WHERE token_hash = ?1",
        [token_hash.as_slice()],
    )?;
    Ok(())
}

/// The inviter's side of pairing, after the handshake proved the joiner
/// holds the token: claim the invite (single use, before replying), mint the
/// joiner's `roster.add`, and build the reply.
pub fn accept_pairing(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    token_hash: &[u8; 32],
    req: &PairRequest,
    remote_noise: &PublicKeyBytes,
    access: &(u32, AccessKey),
) -> Result<PairAccept> {
    let name = identity::validate_device_name(&req.name)?;
    if req.noise_pub != *remote_noise {
        return Err(
            MeshError::InviteRefused("the joiner's key does not match its handshake").into(),
        );
    }
    if !store.state().roster.is_active(&store.self_id()) {
        return Err(MeshError::NotActive.into());
    }
    let joiner = derive_device_id(&req.sign_pub, &req.noise_pub, &req.seal_pub);
    req.sign_pub.to_verifying_key()?;
    {
        let conn = store.connection();
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
        let row: Option<(Option<String>, String, i64)> = tx
            .query_row(
                "SELECT used_at, expires_at, attempts FROM mesh_invites WHERE token_hash = ?1",
                [token_hash.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let now = wall::now_rfc3339();
        match row {
            None => return Err(MeshError::InviteRefused("it is unknown").into()),
            Some((Some(_), _, _)) => {
                return Err(MeshError::InviteRefused("it was already used").into())
            }
            Some((_, expires, _)) if expires <= now => {
                return Err(MeshError::InviteRefused("it has expired").into())
            }
            Some((_, _, attempts)) if attempts >= i64::from(MAX_ATTEMPTS) => {
                return Err(MeshError::InviteRefused("it had too many failed attempts").into())
            }
            Some(_) => {}
        }
        tx.execute(
            "UPDATE mesh_invites SET used_at = ?1, used_by = ?2 WHERE token_hash = ?3",
            params![now, joiner.to_hex(), token_hash.as_slice()],
        )?;
        tx.commit()?;
    }
    let me = store.self_id();
    let add = RosterAdd {
        device: joiner,
        name,
        sign_pub: req.sign_pub,
        noise_pub: req.noise_pub,
        seal_pub: req.seal_pub,
        added_by: me,
    };
    store.mint(signing, Draft::of(&add, HlcPolicy::Now))?;
    audit::record(
        store.connection(),
        "mesh_device_joined",
        None,
        None,
        &format!("device {} paired by this device", short(&joiner)),
    )?;
    let g = store.genesis();
    Ok(PairAccept {
        mesh_id: g.mesh_id,
        genesis: g.genesis,
        inviter: me,
        access_epoch: access.0,
        access_key: access.1.clone(),
    })
}

/// One row of `mesh devices`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceRow {
    pub device_id: DeviceId,
    pub short_id: String,
    pub name: Option<String>,
    pub is_self: bool,
    pub added_by: Option<DeviceId>,
    pub member: bool,
    pub active: bool,
    pub removed: bool,
    pub cutoff_seq: Option<u64>,
    pub fork_seq: Option<u64>,
    /// The last successful exchange with it, from this device's log.
    pub last_exchange: Option<String>,
}

pub fn devices(store: &SqliteStore) -> Result<Vec<DeviceRow>> {
    let state = store.state();
    let roster = &state.roster;
    let me = store.self_id();
    let mut out = Vec::new();
    for (d, _) in roster.known() {
        let last: Option<String> = store.connection().query_row(
            "SELECT MAX(at) FROM mesh_exchange_log WHERE peer_device = ?1 AND result = 'ok'",
            [d.to_hex()],
            |r| r.get(0),
        )?;
        out.push(DeviceRow {
            device_id: *d,
            short_id: short(d),
            name: state
                .device_info
                .value(d, roster)
                .map(|v| v.name.clone())
                .or_else(|| roster.added_name(d).map(str::to_owned)),
            is_self: *d == me,
            added_by: roster.added_by(d),
            member: roster.is_member(d),
            active: roster.is_active(d),
            removed: roster.is_removed(d),
            cutoff_seq: roster.cutoff(d),
            fork_seq: roster.fork_seq(d),
            last_exchange: last,
        });
    }
    Ok(out)
}

/// Resolve a device by its full id or a unique prefix of at least 8 hex
/// characters, among the devices this one knows.
pub fn resolve_device(
    store: &SqliteStore,
    ident: &str,
) -> std::result::Result<DeviceId, MeshError> {
    let ident = ident.trim().to_ascii_lowercase();
    if ident.len() < 8 || !ident.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(MeshError::NotAMember);
    }
    let mut hits = store
        .state()
        .roster
        .known()
        .map(|(d, _)| *d)
        .filter(|d| d.to_hex().starts_with(&ident));
    match (hits.next(), hits.next()) {
        (Some(d), None) => Ok(d),
        _ => Err(MeshError::NotAMember),
    }
}

/// Rename this device: an LWW `device.info` that keeps its listen addresses.
pub(crate) fn rename(
    conn: &Connection,
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    name: &str,
) -> Result<()> {
    let name = identity::validate_device_name(name)?;
    let me = store.self_id();
    let (winner, addrs) = {
        let state = store.state();
        let reg = state.device_info.register(&me);
        (
            reg.and_then(|r| r.winning_hlc(&state.roster)),
            state
                .device_info
                .value(&me, &state.roster)
                .map(|v| v.listen_addrs.clone())
                .unwrap_or_default(),
        )
    };
    let info = DeviceInfo {
        device: me,
        name: name.clone(),
        listen_addrs: addrs,
    };
    store.mint(signing, Draft::of(&info, HlcPolicy::After(winner)))?;
    conn.execute("UPDATE mesh_self SET device_name = ?1", [name])?;
    Ok(())
}

/// The listen addresses this device's latest `device.info` publishes.
pub fn published_listen_addrs(store: &SqliteStore) -> Vec<String> {
    let me = store.self_id();
    let state = store.state();
    state
        .device_info
        .value(&me, &state.roster)
        .map(|v| v.listen_addrs.clone())
        .unwrap_or_default()
}

/// Publish the addresses a running node listens on (DESIGN §D13 "address
/// gossip"): an LWW `device.info` that keeps this device's name. Mints only
/// when they changed; returns whether it did. At most
/// [`super::kinds::MAX_LISTEN_ADDRS`] are kept.
pub fn publish_listen_addrs(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    addrs: &[String],
) -> Result<bool> {
    let mut addrs: Vec<String> = addrs.to_vec();
    addrs.dedup();
    addrs.truncate(super::kinds::MAX_LISTEN_ADDRS);
    let me = store.self_id();
    let (winner, current, name) = {
        let state = store.state();
        let current = state.device_info.value(&me, &state.roster);
        (
            state
                .device_info
                .register(&me)
                .and_then(|r| r.winning_hlc(&state.roster)),
            current.map(|v| v.listen_addrs.clone()),
            current
                .map(|v| v.name.clone())
                .or_else(|| state.roster.added_name(&me).map(str::to_owned)),
        )
    };
    if current.as_deref() == Some(addrs.as_slice()) {
        return Ok(false);
    }
    let name = match name {
        Some(n) => n,
        None => {
            identity::self_info(store.connection())?
                .ok_or(MeshError::NotInitialized)?
                .device_name
        }
    };
    let info = DeviceInfo {
        device: me,
        name,
        listen_addrs: addrs,
    };
    store.mint(signing, Draft::of(&info, HlcPolicy::After(winner)))?;
    Ok(true)
}

/// Remove another device: mint `roster.remove` with this device's view of
/// its log as the cutoff, and rotate the access key to a new epoch, which
/// sessions then deliver to every remaining member (PROTOCOL.md §9).
pub(crate) fn remove(
    conn: &Connection,
    vault_key: &SecretBytes,
    vault_id: &str,
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    target: DeviceId,
) -> Result<u32> {
    if target == store.self_id() {
        return Err(CoreError::InvalidInput(
            "to remove this device, leave the mesh instead".into(),
        ));
    }
    let roster = &store.state().roster;
    if !roster.is_known(&target) {
        return Err(MeshError::NotAMember.into());
    }
    if roster.is_removed(&target) {
        // Removing again would only rotate the key again for nothing.
        return Err(MeshError::AlreadyRemoved.into());
    }
    if !roster.is_active(&store.self_id()) {
        return Err(MeshError::NotActive.into());
    }
    // A member that keeps reporting a rollback that never comes back would
    // otherwise block its own removal (PROTOCOL.md §7.4).
    store.settle_rollback_holds(target)?;
    let cutoff = store.vv().get(&target);
    store.mint(
        signing,
        Draft::of(
            &RosterRemove {
                device: target,
                cutoff_seq: cutoff,
            },
            HlcPolicy::Now,
        ),
    )?;
    let epoch = rotate_access_key(conn, vault_key, vault_id)?;
    audit::record(
        conn,
        "mesh_device_removed",
        None,
        None,
        &format!(
            "device {} at cutoff {cutoff}; access key epoch {epoch}",
            short(&target)
        ),
    )?;
    Ok(epoch)
}

fn rotate_access_key(conn: &Connection, vault_key: &SecretBytes, vault_id: &str) -> Result<u32> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let row = identity::read_self(&tx)?.ok_or(MeshError::NotInitialized)?;
    let epoch = row
        .info
        .access_key_epoch
        .checked_add(1)
        .ok_or(MeshError::InvalidOperation("access-key epochs exhausted"))?;
    let key = identity::random_key();
    let wrapped = crypto::encrypt(
        vault_key,
        &aad::mesh_access_key(vault_id, &row.info.mesh_id.to_hex(), epoch),
        &key[..],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO mesh_access_keys (epoch, wrapped_key, created_at)
         VALUES (?1, ?2, ?3)",
        params![i64::from(epoch), wrapped, wall::now_rfc3339()],
    )?;
    tx.execute(
        "UPDATE mesh_self SET access_key_epoch = ?1",
        [i64::from(epoch)],
    )?;
    tx.commit()?;
    Ok(epoch)
}

/// Mint this device's self-removal (the first half of `mesh leave`).
pub(crate) fn mint_self_remove(store: &mut SqliteStore, signing: &SigningKeyPair) -> Result<()> {
    let me = store.self_id();
    let cutoff = store.vv().get(&me);
    store.mint(
        signing,
        Draft::of(
            &RosterRemove {
                device: me,
                cutoff_seq: cutoff,
            },
            HlcPolicy::Now,
        ),
    )?;
    Ok(())
}

/// One exchange, for `mesh_exchange_log` (kept to the last 1 000 rows).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExchangeRecord {
    pub peer_device: Option<DeviceId>,
    pub direction: &'static str,
    pub items_in: u64,
    pub items_out: u64,
    pub result: &'static str,
    /// A static description; never peer-supplied text.
    pub error: Option<&'static str>,
}

pub fn log_exchange(conn: &Connection, rec: &ExchangeRecord) -> Result<()> {
    conn.execute(
        "INSERT INTO mesh_exchange_log (peer_device, at, direction, items_in, items_out,
             result, error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            rec.peer_device.map(|d| d.to_hex()),
            wall::now_rfc3339(),
            rec.direction,
            i64::try_from(rec.items_in).unwrap_or(i64::MAX),
            i64::try_from(rec.items_out).unwrap_or(i64::MAX),
            rec.result,
            rec.error,
        ],
    )?;
    conn.execute(
        "DELETE FROM mesh_exchange_log WHERE id <= (SELECT MAX(id) FROM mesh_exchange_log) - ?1",
        [EXCHANGE_LOG_ROWS],
    )?;
    Ok(())
}

/// The mesh id and genesis of this device, for checks before pairing.
pub fn mesh_of(conn: &Connection) -> Result<Option<(MeshId, DeviceId)>> {
    Ok(identity::read_self(conn)?.map(|r| (r.info.mesh_id, r.info.genesis_device)))
}
