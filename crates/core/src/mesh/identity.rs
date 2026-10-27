//! A device's mesh identity (Increment 03, DESIGN §D5, ADR 0031).
//!
//! - [`init`] creates a mesh with this device as its genesis: a random
//!   `mesh_id`, an access key at epoch 1, and the device's three key pairs —
//!   Ed25519 for items, X25519 for the Noise transport, a separate X25519 for
//!   sealed credential shares. The device id is derived from the three
//!   public keys (R8). The private keys and the access key are encrypted
//!   under the vault key with AAD naming the vault and the device (or mesh
//!   and epoch). The genesis `roster.add` and `device.info` are minted in
//!   the same transaction that stores the identity, after the marker covers
//!   their seqs.
//! - [`load_keys`] returns the keys a running node holds ([`MeshKeys`]): the
//!   signing key, the Noise key and the current access key, in zeroizing
//!   buffers. It never returns the sealing key; only the reauth-gated import
//!   of Increment 11 unwraps that one (MESH-SI-7).
//! - [`on_restore`] and [`leave_local_wipe`] delete every row of every
//!   `mesh_*` table and turn cap enforcement off: a restored or departed vault
//!   must never act as the device it was copied from (MESH-SI-5). The marker
//!   is removed only when it names the identity that was wiped.
//!
//! Nothing here performs network I/O.

use super::clock::Clock;
use super::dot::{DeviceId, MarkerNonce, MeshId};
use super::error::MeshError;
use super::kinds::{DeviceInfo, RosterAdd, MAX_NAME_BYTES};
use super::marker::{self, MarkerContents, MarkerRemoval, MarkerStatus, SEQ_BLOCK};
use super::sign::{derive_device_id, PublicKeyBytes, SigningKeyPair};
use super::sqlite_store::{self, MarkerConfig, SqliteStore, StoreParams};
use super::store::{Draft, GenesisInfo, HlcPolicy, MeshStore};
use crate::audit;
use crate::clock as wall;
use crate::crypto::{self, aad};
use crate::db;
use crate::error::{CoreError, Result};
use crate::secret::{SecretBytes, REDACTED};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The longest device name, in characters. It also has to satisfy the
/// `roster.add`/`device.info` payload rules (at most 128 bytes, no control
/// characters).
pub const MAX_DEVICE_NAME_CHARS: usize = 64;
const FIRST_EPOCH: u32 = 1;

/// Trim and check a device name. It is shown to every paired device.
pub fn validate_device_name(name: &str) -> std::result::Result<String, MeshError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_DEVICE_NAME_CHARS
        || name.len() > MAX_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return Err(MeshError::InvalidDeviceName);
    }
    Ok(name.to_owned())
}

/// This device's identity row, public parts only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MeshSelfInfo {
    pub mesh_id: MeshId,
    pub genesis_device: DeviceId,
    pub device_id: DeviceId,
    pub device_name: String,
    pub sign_pub: PublicKeyBytes,
    pub noise_pub: PublicKeyBytes,
    pub seal_pub: PublicKeyBytes,
    pub access_key_epoch: u32,
    pub state: String,
    pub created_at: String,
}

/// The full `mesh_self` row (wrapped keys included; never serialized).
struct SelfRow {
    info: MeshSelfInfo,
    nonce: MarkerNonce,
    wrapped_sign: Vec<u8>,
    wrapped_noise: Vec<u8>,
}

impl SelfRow {
    fn params(&self, data_dir: &Path) -> StoreParams {
        StoreParams {
            genesis: GenesisInfo {
                mesh_id: self.info.mesh_id,
                genesis: self.info.genesis_device,
            },
            self_id: self.info.device_id,
            marker: Some(MarkerConfig {
                data_dir: data_dir.to_path_buf(),
                nonce: self.nonce,
            }),
        }
    }
}

fn corrupt(what: &'static str) -> CoreError {
    CoreError::VaultCorrupted(what)
}

fn read_self(conn: &Connection) -> Result<Option<SelfRow>> {
    let row = conn
        .query_row(
            "SELECT mesh_id, genesis_device, device_id, device_name, sign_pub, noise_pub,
                    seal_pub, access_key_epoch, state, created_at, marker_nonce,
                    wrapped_sign_key, wrapped_noise_key
             FROM mesh_self WHERE id = 'self'",
            [],
            |r| {
                Ok((
                    (
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                    ),
                    (
                        r.get::<_, i64>(7)?,
                        r.get::<_, String>(8)?,
                        r.get::<_, String>(9)?,
                        r.get::<_, String>(10)?,
                        r.get::<_, Vec<u8>>(11)?,
                        r.get::<_, Vec<u8>>(12)?,
                    ),
                ))
            },
        )
        .optional()?;
    let Some(((mesh, genesis, device, name, sign, noise, seal), rest)) = row else {
        return Ok(None);
    };
    let (epoch, state, created_at, nonce, wrapped_sign, wrapped_noise) = rest;
    let bad = |_| corrupt("the mesh identity row is malformed");
    Ok(Some(SelfRow {
        info: MeshSelfInfo {
            mesh_id: MeshId::parse(&mesh).map_err(bad)?,
            genesis_device: DeviceId::parse(&genesis).map_err(bad)?,
            device_id: DeviceId::parse(&device).map_err(bad)?,
            device_name: name,
            sign_pub: PublicKeyBytes::parse(&sign).map_err(bad)?,
            noise_pub: PublicKeyBytes::parse(&noise).map_err(bad)?,
            seal_pub: PublicKeyBytes::parse(&seal).map_err(bad)?,
            access_key_epoch: u32::try_from(epoch)
                .map_err(|_| corrupt("the mesh access-key epoch is out of range"))?,
            state,
            created_at,
        },
        nonce: MarkerNonce::parse(&nonce).map_err(bad)?,
        wrapped_sign,
        wrapped_noise,
    }))
}

/// This device's public identity, or `None` when it is not in a mesh.
pub fn self_info(conn: &Connection) -> Result<Option<MeshSelfInfo>> {
    Ok(read_self(conn)?.map(|r| r.info))
}

/// Clamp 32 random bytes into an X25519 secret (RFC 7748 §5). `snow` and
/// `crypto_box` clamp the same way, so the stored public key is the one both
/// derive.
fn clamp(s: &mut [u8; 32]) {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

/// The X25519 public key of a secret (`crypto_box` reuses curve25519-dalek).
pub fn x25519_public(secret: &[u8; 32]) -> PublicKeyBytes {
    PublicKeyBytes(
        crypto_box::SecretKey::from_bytes(*secret)
            .public_key()
            .to_bytes(),
    )
}

fn x25519_generate() -> (Zeroizing<[u8; 32]>, PublicKeyBytes) {
    let mut s = Zeroizing::new([0u8; 32]);
    getrandom::fill(s.as_mut()).expect("operating system RNG is unavailable");
    clamp(&mut s);
    let public = x25519_public(&s);
    (s, public)
}

fn random_key() -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    getrandom::fill(k.as_mut()).expect("operating system RNG is unavailable");
    k
}

fn unwrap32(
    vault_key: &SecretBytes,
    aad: &str,
    wrapped: &[u8],
    what: &'static str,
) -> Result<Zeroizing<[u8; 32]>> {
    let plain = crypto::decrypt(vault_key, aad, wrapped, what)?;
    if plain.len() != 32 {
        return Err(corrupt("a mesh key has the wrong length"));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(plain.expose());
    Ok(out)
}

/// Every `mesh_*` table, from the schema itself (later migrations' tables
/// included).
fn mesh_tables(conn: &Connection) -> Result<Vec<String>> {
    let mut st = conn.prepare(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name LIKE 'mesh\\_%' ESCAPE '\\' ORDER BY name",
    )?;
    let names = st
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    if names
        .iter()
        .any(|n| !n.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'))
    {
        return Err(corrupt("an unexpected mesh table name"));
    }
    Ok(names)
}

fn delete_mesh_rows(conn: &Connection) -> Result<u64> {
    let mut rows = 0u64;
    for t in mesh_tables(conn)? {
        rows += conn.execute(&format!("DELETE FROM \"{t}\""), [])? as u64;
    }
    Ok(rows)
}

/// Create a mesh with this device as its only member (`tethra mesh init`).
pub(crate) fn init(
    conn: &Connection,
    vault_key: &SecretBytes,
    vault_id: &str,
    data_dir: &Path,
    device_name: &str,
    clock: Arc<dyn Clock>,
) -> Result<MeshSelfInfo> {
    let name = validate_device_name(device_name)?;
    let signing = SigningKeyPair::generate();
    let (noise_secret, noise_pub) = x25519_generate();
    let (seal_secret, seal_pub) = x25519_generate();
    let sign_pub = signing.public_key();
    let device_id = derive_device_id(&sign_pub, &noise_pub, &seal_pub);
    let mesh_id = MeshId::random();
    let access_key = random_key();
    let nonce = MarkerNonce::random();
    let dev = device_id.to_hex();
    let wrapped_sign = crypto::encrypt(
        vault_key,
        &aad::mesh_sign_key(vault_id, &dev),
        &signing.expose_secret_bytes()[..],
    )?;
    let wrapped_noise = crypto::encrypt(
        vault_key,
        &aad::mesh_noise_key(vault_id, &dev),
        &noise_secret[..],
    )?;
    let wrapped_seal = crypto::encrypt(
        vault_key,
        &aad::mesh_seal_key(vault_id, &dev),
        &seal_secret[..],
    )?;
    drop(seal_secret);
    let wrapped_access = crypto::encrypt(
        vault_key,
        &aad::mesh_access_key(vault_id, &mesh_id.to_hex(), FIRST_EPOCH),
        &access_key[..],
    )?;
    let created_at = wall::now_rfc3339();
    let info = MeshSelfInfo {
        mesh_id,
        genesis_device: device_id,
        device_id,
        device_name: name.clone(),
        sign_pub,
        noise_pub,
        seal_pub,
        access_key_epoch: FIRST_EPOCH,
        state: "active".into(),
        created_at: created_at.clone(),
    };
    let params = StoreParams {
        genesis: GenesisInfo {
            mesh_id,
            genesis: device_id,
        },
        self_id: device_id,
        marker: Some(MarkerConfig {
            data_dir: data_dir.to_path_buf(),
            nonce,
        }),
    };

    conn.pragma_update(None, "synchronous", "FULL")?;
    // The write lock is held from the "not in a mesh yet" check to the
    // commit, so two concurrent inits cannot both pass it.
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    if read_self(&tx)?.is_some() {
        return Err(MeshError::AlreadyInMesh.into());
    }
    // Without an identity, any mesh rows are orphans (nothing can use them).
    delete_mesh_rows(&tx)?;
    // The marker must cover the genesis seqs before either is used.
    marker::write(data_dir, &MarkerContents::new(device_id, nonce, SEQ_BLOCK))?;
    tx.execute(
        "INSERT INTO mesh_self (id, mesh_id, genesis_device, device_id, device_name, sign_pub,
             noise_pub, seal_pub, wrapped_sign_key, wrapped_noise_key, wrapped_seal_key,
             access_key_epoch, marker_nonce, state, created_at)
         VALUES ('self', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'active', ?13)",
        params![
            mesh_id.to_hex(),
            dev,
            dev,
            name,
            sign_pub.to_hex(),
            noise_pub.to_hex(),
            seal_pub.to_hex(),
            wrapped_sign,
            wrapped_noise,
            wrapped_seal,
            i64::from(FIRST_EPOCH),
            nonce.to_hex(),
            created_at,
        ],
    )?;
    tx.execute(
        "INSERT INTO mesh_access_keys (epoch, wrapped_key, created_at) VALUES (?1, ?2, ?3)",
        params![i64::from(FIRST_EPOCH), wrapped_access, created_at],
    )?;
    let add = RosterAdd {
        device: device_id,
        name: name.clone(),
        sign_pub,
        noise_pub,
        seal_pub,
        added_by: device_id,
    };
    let device_info = DeviceInfo {
        device: device_id,
        name,
        listen_addrs: Vec::new(),
    };
    sqlite_store::mint_genesis(
        &tx,
        &params,
        clock,
        &signing,
        vec![
            Draft::of(&add, HlcPolicy::Now),
            Draft::of(&device_info, HlcPolicy::After(None)),
        ],
    )?;
    audit::record(
        &tx,
        "mesh_initialized",
        None,
        None,
        &format!("device {}", &dev[..8]),
    )?;
    tx.commit()?;
    Ok(info)
}

/// The keys a running node holds while the vault is unlocked (DESIGN §D5).
/// There is deliberately no sealing key here (MESH-SI-7).
pub struct MeshKeys {
    mesh_id: MeshId,
    genesis_device: DeviceId,
    device_id: DeviceId,
    signing: SigningKeyPair,
    noise_secret: Zeroizing<[u8; 32]>,
    noise_pub: PublicKeyBytes,
    access_key: Zeroizing<[u8; 32]>,
    access_epoch: u32,
}

impl MeshKeys {
    pub fn mesh_id(&self) -> MeshId {
        self.mesh_id
    }
    pub fn genesis_device(&self) -> DeviceId {
        self.genesis_device
    }
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
    /// The item-signing key (its `Debug` is redacted).
    pub fn signing_key(&self) -> &SigningKeyPair {
        &self.signing
    }
    /// The Noise static secret, for the transport (Increment 04). Every call
    /// site is a deliberate exposure.
    pub fn expose_noise_secret(&self) -> &[u8; 32] {
        &self.noise_secret
    }
    pub fn noise_pub(&self) -> PublicKeyBytes {
        self.noise_pub
    }
    /// The access key (the Noise psk of normal sessions). Every call site is
    /// a deliberate exposure.
    pub fn expose_access_key(&self) -> &[u8; 32] {
        &self.access_key
    }
    pub fn access_epoch(&self) -> u32 {
        self.access_epoch
    }
}

impl std::fmt::Debug for MeshKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshKeys")
            .field("device_id", &self.device_id)
            .field("signing", &self.signing)
            .field("noise_secret", &REDACTED)
            .field("noise_pub", &self.noise_pub)
            .field("access_key", &REDACTED)
            .field("access_epoch", &self.access_epoch)
            .finish()
    }
}

/// Unwrap the node's keys (signing, Noise, current access key) and check
/// each against the public key stored beside it.
pub(crate) fn load_keys(
    conn: &Connection,
    vault_key: &SecretBytes,
    vault_id: &str,
) -> Result<MeshKeys> {
    let row = read_self(conn)?.ok_or(MeshError::NotInitialized)?;
    let dev = row.info.device_id.to_hex();
    let sign = unwrap32(
        vault_key,
        &aad::mesh_sign_key(vault_id, &dev),
        &row.wrapped_sign,
        "mesh signing key",
    )?;
    let signing = SigningKeyPair::from_secret_bytes(&sign);
    if signing.public_key() != row.info.sign_pub {
        return Err(corrupt(
            "the mesh signing key does not match its public key",
        ));
    }
    let noise_secret = unwrap32(
        vault_key,
        &aad::mesh_noise_key(vault_id, &dev),
        &row.wrapped_noise,
        "mesh noise key",
    )?;
    if x25519_public(&noise_secret) != row.info.noise_pub {
        return Err(corrupt("the mesh Noise key does not match its public key"));
    }
    let epoch = row.info.access_key_epoch;
    let wrapped: Vec<u8> = conn
        .query_row(
            "SELECT wrapped_key FROM mesh_access_keys WHERE epoch = ?1",
            [i64::from(epoch)],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| corrupt("the mesh access key for the current epoch is missing"))?;
    let access_key = unwrap32(
        vault_key,
        &aad::mesh_access_key(vault_id, &row.info.mesh_id.to_hex(), epoch),
        &wrapped,
        "mesh access key",
    )?;
    Ok(MeshKeys {
        mesh_id: row.info.mesh_id,
        genesis_device: row.info.genesis_device,
        device_id: row.info.device_id,
        signing,
        noise_secret,
        noise_pub: row.info.noise_pub,
        access_key,
        access_epoch: epoch,
    })
}

/// Open this device's store on its own connection to `db_path`, or `None`
/// when it is not in a mesh.
pub fn open_store(
    db_path: &Path,
    data_dir: &Path,
    clock: Arc<dyn Clock>,
) -> Result<Option<SqliteStore>> {
    let conn = db::open_at_current_version(db_path)?;
    let Some(row) = read_self(&conn)? else {
        return Ok(None);
    };
    let params = row.params(data_dir);
    Ok(Some(SqliteStore::open(conn, params, clock)?))
}

/// One device in `status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceSummary {
    pub device_id: DeviceId,
    pub name: Option<String>,
    pub is_self: bool,
    pub member: bool,
    pub active: bool,
    pub removed: bool,
    pub cutoff_seq: Option<u64>,
    pub fork_seq: Option<u64>,
}

/// `tethra mesh status`. Nothing in it is secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MeshStatus {
    pub initialized: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub detail: Option<MeshStatusDetail>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MeshStatusDetail {
    pub mesh_id: MeshId,
    pub mesh_id_short: String,
    pub genesis_device: DeviceId,
    pub device_id: DeviceId,
    pub device_name: String,
    pub state: String,
    pub next_seq: u64,
    pub marker: MarkerStatus,
    /// Why the marker check failed, when it did. The node refuses to run then.
    pub marker_problem: Option<&'static str>,
    /// Another installation used this identity (a `fork.report` names it).
    pub self_forked: bool,
    pub roster_size: usize,
    pub devices: Vec<DeviceSummary>,
    pub vv: BTreeMap<DeviceId, u64>,
    pub items_by_kind: BTreeMap<String, u64>,
    pub rejected_items: u64,
    /// Origins whose items carried clocks beyond `now + 60 s`, with the
    /// largest skew seen (ms).
    pub clock_skew: BTreeMap<DeviceId, u64>,
    pub fork_evidence: usize,
    pub forked_devices: usize,
    pub regressions: u64,
    pub repairs_changed: u64,
}

impl MeshStatus {
    pub fn uninitialized() -> Self {
        Self {
            initialized: false,
            detail: None,
        }
    }
}

pub(crate) fn status(
    conn: &Connection,
    db_path: &Path,
    data_dir: &Path,
    clock: Arc<dyn Clock>,
) -> Result<MeshStatus> {
    let Some(row) = read_self(conn)? else {
        return Ok(MeshStatus::uninitialized());
    };
    let store = SqliteStore::open(db::open(db_path)?, row.params(data_dir), clock)?;
    let state = store.state();
    let roster = &state.roster;
    let me = row.info.device_id;
    let devices = roster
        .known()
        .map(|(d, _)| DeviceSummary {
            device_id: *d,
            name: state
                .device_info
                .value(d, roster)
                .map(|v| v.name.clone())
                .or_else(|| roster.added_name(d).map(str::to_owned)),
            is_self: *d == me,
            member: roster.is_member(d),
            active: roster.is_active(d),
            removed: roster.is_removed(d),
            cutoff_seq: roster.cutoff(d),
            fork_seq: roster.fork_seq(d),
        })
        .collect();
    let marker = store.marker_status()?;
    let stats = store.stats();
    let mesh_hex = row.info.mesh_id.to_hex();
    Ok(MeshStatus {
        initialized: true,
        detail: Some(MeshStatusDetail {
            mesh_id: row.info.mesh_id,
            mesh_id_short: mesh_hex[..8].to_owned(),
            genesis_device: row.info.genesis_device,
            device_id: me,
            device_name: row.info.device_name,
            state: row.info.state,
            next_seq: store.vv().get(&me) + 1,
            marker,
            marker_problem: marker.problem(),
            self_forked: roster.fork_seq(&me).is_some(),
            roster_size: roster.members().count(),
            devices,
            vv: store.vv().iter().map(|(o, s)| (*o, *s)).collect(),
            items_by_kind: store.items_by_kind()?,
            rejected_items: stats.rejected_items,
            clock_skew: stats.clock_skew.clone(),
            fork_evidence: stats.fork_evidence.len(),
            forked_devices: roster.forks().count(),
            regressions: stats.regressions.values().sum(),
            repairs_changed: stats.repairs_changed,
        }),
    })
}

/// What a wipe removed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WipeReport {
    /// The identity that was wiped, if there was one.
    pub identity: Option<DeviceId>,
    pub rows_deleted: u64,
    pub marker: MarkerRemoval,
}

fn wipe(conn: &Connection, data_dir: &Path) -> Result<WipeReport> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let identity = read_self(&tx)?.map(|r| r.info.device_id);
    let rows_deleted = delete_mesh_rows(&tx)?;
    tx.execute(
        "UPDATE gateway_config SET cap_enforcement = 0 WHERE cap_enforcement <> 0",
        [],
    )?;
    tx.commit()?;
    let marker = marker::remove_if_owned(data_dir, identity.as_ref())?;
    Ok(WipeReport {
        identity,
        rows_deleted,
        marker,
    })
}

/// Called by `backup::restore_backup` right after the restored rows are in:
/// a restored vault is a copy, so it keeps no mesh identity and must pair
/// again (DESIGN §D5). Works on every backup format; a backup without mesh
/// rows (v1, or made before v21) leaves nothing to delete. Never mints.
pub fn on_restore(conn: &Connection, data_dir: &Path) -> Result<WipeReport> {
    let report = wipe(conn, data_dir)?;
    if let Some(d) = report.identity {
        audit::record(
            conn,
            "mesh_identity_wiped",
            None,
            None,
            &format!("restored from backup; device {}", &d.to_hex()[..8]),
        )?;
    }
    Ok(report)
}

/// The local half of `mesh leave` (Increment 04): the same wipe.
pub fn leave_local_wipe(conn: &Connection, data_dir: &Path) -> Result<WipeReport> {
    wipe(conn, data_dir)
}

/// The marker check for a store that exists (used by `status` and, from
/// Increment 05, by the node before it starts).
pub fn preflight(store: &SqliteStore) -> std::result::Result<(), MeshError> {
    if let Some(e) = store.marker_status()?.to_error() {
        return Err(e);
    }
    if store.state().roster.fork_seq(&store.self_id()).is_some() {
        return Err(MeshError::Forked);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::clock::ManualClock;

    fn vault_db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = db::open(&dir.path().join("vault.db")).unwrap();
        db::migrate(&mut conn).unwrap();
        (dir, conn)
    }

    fn clock() -> Arc<dyn Clock> {
        Arc::new(ManualClock::new(1_700_000_000_000))
    }

    #[test]
    fn device_names_are_trimmed_and_bounded() {
        assert_eq!(validate_device_name("  laptop ").unwrap(), "laptop");
        assert!(validate_device_name("").is_err());
        assert!(validate_device_name("   ").is_err());
        assert!(validate_device_name("a\u{7}b").is_err());
        assert!(validate_device_name(&"x".repeat(64)).is_ok());
        assert!(validate_device_name(&"x".repeat(65)).is_err());
        // 64 characters but more than 128 bytes.
        assert!(validate_device_name(&"日".repeat(64)).is_err());
    }

    #[test]
    fn keys_round_trip_and_never_include_the_sealing_key() {
        let (dir, conn) = vault_db();
        let vk = crypto::new_key();
        let info = init(&conn, &vk, "vault-a", dir.path(), "dev-a", clock()).unwrap();
        let keys = load_keys(&conn, &vk, "vault-a").unwrap();
        assert_eq!(keys.device_id(), info.device_id);
        assert_eq!(keys.signing_key().public_key(), info.sign_pub);
        assert_eq!(x25519_public(keys.expose_noise_secret()), info.noise_pub);
        assert_eq!(keys.access_epoch(), 1);
        // The device id is derived from the three public keys (R8).
        assert_eq!(
            derive_device_id(&info.sign_pub, &info.noise_pub, &info.seal_pub),
            info.device_id
        );
        // The sealing secret exists (wrapped) but appears in no MeshKeys field.
        let wrapped_seal: Vec<u8> = conn
            .query_row("SELECT wrapped_seal_key FROM mesh_self", [], |r| r.get(0))
            .unwrap();
        let seal = unwrap32(
            &vk,
            &aad::mesh_seal_key("vault-a", &info.device_id.to_hex()),
            &wrapped_seal,
            "seal",
        )
        .unwrap();
        assert_eq!(x25519_public(&seal), info.seal_pub);
        let held: [&[u8; 32]; 3] = [
            &keys.signing_key().expose_secret_bytes(),
            keys.expose_noise_secret(),
            keys.expose_access_key(),
        ];
        assert!(held.iter().all(|k| **k != *seal));
        // Debug never prints secret material.
        let dbg = format!("{keys:?}");
        for secret in held.iter().map(hex::encode).chain([hex::encode(*seal)]) {
            assert!(!dbg.contains(&secret), "Debug leaks a key");
        }
        assert!(dbg.contains(REDACTED));
    }

    #[test]
    fn key_blobs_are_bound_to_their_vault_and_corruption_is_typed() {
        let (dir, conn) = vault_db();
        let vk = crypto::new_key();
        init(&conn, &vk, "vault-a", dir.path(), "dev-a", clock()).unwrap();
        // Same key bytes, different vault id: the AAD no longer matches.
        assert!(matches!(
            load_keys(&conn, &vk, "vault-b"),
            Err(CoreError::Crypto { .. })
        ));
        // A different vault key cannot open them either.
        assert!(load_keys(&conn, &crypto::new_key(), "vault-a").is_err());
        // A flipped byte in a blob is an authentication failure, not garbage.
        let mut blob: Vec<u8> = conn
            .query_row("SELECT wrapped_noise_key FROM mesh_self", [], |r| r.get(0))
            .unwrap();
        blob[30] ^= 0x01;
        conn.execute("UPDATE mesh_self SET wrapped_noise_key = ?1", [blob])
            .unwrap();
        assert!(matches!(
            load_keys(&conn, &vk, "vault-a"),
            Err(CoreError::Crypto { .. })
        ));
    }

    #[test]
    fn a_swapped_public_key_is_caught_when_the_keys_load() {
        let (dir, conn) = vault_db();
        let vk = crypto::new_key();
        init(&conn, &vk, "vault-a", dir.path(), "dev-a", clock()).unwrap();
        conn.execute(
            "UPDATE mesh_self SET noise_pub = ?1",
            [PublicKeyBytes([9; 32]).to_hex()],
        )
        .unwrap();
        assert!(matches!(
            load_keys(&conn, &vk, "vault-a"),
            Err(CoreError::VaultCorrupted(_))
        ));
    }

    #[test]
    fn init_mints_the_genesis_items_and_refuses_twice() {
        let (dir, conn) = vault_db();
        let vk = crypto::new_key();
        let info = init(&conn, &vk, "v", dir.path(), "dev-a", clock()).unwrap();
        assert_eq!(info.genesis_device, info.device_id);
        let st = status(&conn, &dir.path().join("vault.db"), dir.path(), clock()).unwrap();
        let d = st.detail.unwrap();
        assert_eq!(d.roster_size, 1);
        assert_eq!(d.next_seq, 3, "roster.add and device.info");
        assert_eq!(d.marker, MarkerStatus::Ok);
        assert_eq!(d.items_by_kind.get("roster.add"), Some(&1));
        assert_eq!(d.items_by_kind.get("device.info"), Some(&1));
        assert_eq!(d.devices[0].name.as_deref(), Some("dev-a"));
        assert!(d.devices[0].is_self && d.devices[0].active);
        let again = init(&conn, &vk, "v", dir.path(), "dev-b", clock());
        assert!(matches!(
            again,
            Err(CoreError::Mesh(MeshError::AlreadyInMesh))
        ));
        // The refused init left the identity and its marker alone.
        assert_eq!(self_info(&conn).unwrap().unwrap(), info);
        let m = marker::read(dir.path()).unwrap().unwrap();
        assert_eq!(m.device_id, info.device_id);
    }

    #[test]
    fn the_wipe_removes_every_mesh_row_and_only_its_own_marker() {
        let (dir, conn) = vault_db();
        let vk = crypto::new_key();
        let info = init(&conn, &vk, "v", dir.path(), "dev-a", clock()).unwrap();
        conn.execute(
            "INSERT INTO gateway_config (id, enabled, cap_enforcement, created_at, updated_at)
             VALUES ('gateway', 0, 1, 'x', 'x')",
            [],
        )
        .unwrap();
        let report = on_restore(&conn, dir.path()).unwrap();
        assert_eq!(report.identity, Some(info.device_id));
        assert!(report.rows_deleted > 0);
        assert_eq!(report.marker, MarkerRemoval::Removed);
        for t in mesh_tables(&conn).unwrap() {
            let n: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM \"{t}\""), [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0, "{t} still has rows");
        }
        let enforcement: i64 = conn
            .query_row("SELECT cap_enforcement FROM gateway_config", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(enforcement, 0);
        assert!(self_info(&conn).unwrap().is_none());

        // A marker naming another identity is left alone.
        let other = DeviceId::from_bytes([5; 16]);
        marker::write(
            dir.path(),
            &MarkerContents::new(other, MarkerNonce::from_bytes([6; 16]), 64),
        )
        .unwrap();
        init(&conn, &vk, "v", dir.path(), "dev-b", clock()).unwrap();
        // init replaced the marker with its own...
        let mine = marker::read(dir.path()).unwrap().unwrap();
        assert_ne!(mine.device_id, other);
        // ...and a foreign one written afterwards survives a wipe.
        marker::write(
            dir.path(),
            &MarkerContents::new(other, MarkerNonce::from_bytes([6; 16]), 64),
        )
        .unwrap();
        let report = leave_local_wipe(&conn, dir.path()).unwrap();
        assert_eq!(report.marker, MarkerRemoval::LeftInPlace);
        assert_eq!(marker::read(dir.path()).unwrap().unwrap().device_id, other);
    }
}
