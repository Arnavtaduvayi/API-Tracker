//! The storage interface the replication protocol runs against.
//!
//! [`MeshStore`] is what a device's mesh state looks like to the protocol:
//! the version vector, the dot log and chains, the held items, the views,
//! and two writes — [`MeshStore::commit`] (items received in a session) and
//! [`MeshStore::mint`] (a local write). Both are atomic: either everything in
//! them becomes visible, or nothing does.
//!
//! `memstore::MemStore` implements it in memory (Increment 02);
//! `sqlite_store::SqliteStore` implements it in SQLite (Increment 03).

use super::chain::Hash32;
use super::codec::ItemBody;
use super::dot::{DeviceId, MeshId};
use super::error::MeshError;
use super::hlc::Hlc;
use super::item::{ItemHash, SignedItem};
use super::kinds::TypedItem;
use super::sign::SigningKeyPair;
use super::views::State;
use super::vv::VersionVector;
use serde_json::Value;
use std::collections::BTreeMap;

/// What every member of one mesh knows from pairing (PROTOCOL.md §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisInfo {
    pub mesh_id: MeshId,
    /// The device that ran `mesh init`; its self-add is the root of trust.
    pub genesis: DeviceId,
}

/// An item that passed the ingest checks of PROTOCOL.md §3.3.
#[derive(Clone, Debug)]
pub struct VerifiedItem {
    pub item: SignedItem,
    pub body: ItemBody,
    pub typed: TypedItem,
}

/// Everything one session's `Commit` applies, in one transaction.
#[derive(Clone, Debug, Default)]
pub struct CommitBatch {
    /// Main-path items, each within its origin's committed range.
    pub items: Vec<VerifiedItem>,
    /// `(origin, seq, hash)` for dots in the committed ranges that no item in
    /// `items` carries (superseded at the sender).
    pub dots: Vec<(DeviceId, u64, ItemHash)>,
    /// The new VV entry for each origin committed on the main path. Every seq
    /// in `(vv[o], upto[o]]` must have a hash from `items` or `dots`.
    pub upto: VersionVector,
    /// Repair items: applied as entries only; they never touch the VV, the
    /// dot log or the chain (PROTOCOL.md §8.5).
    pub repair: Vec<VerifiedItem>,
}

/// Two different hashes for one dot (PROTOCOL.md §7.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkEvidence {
    pub origin: DeviceId,
    pub seq: u64,
    /// The hash in this device's dot log.
    pub ours: ItemHash,
    /// The other hash.
    pub theirs: ItemHash,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitOutcome {
    /// Items that became the latest for their `(kind, key, origin)`.
    pub stored: usize,
    /// Direct dot collisions found while committing.
    pub forks: Vec<ForkEvidence>,
    /// Owner-counter regressions (PROTOCOL.md §5.3).
    pub regressions: u64,
    /// Repair items that changed the stored state of an origin that is not
    /// forked — a bug signal (PROTOCOL.md §8.5).
    pub repairs_changed: u64,
}

/// Which HLC a minted item gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HlcPolicy {
    /// `hlc.now()`: counters, rights, roster items.
    Now,
    /// `hlc.local_write_ts(winner)`: a last-writer-wins write that must beat
    /// the value the user is looking at.
    After(Option<Hlc>),
}

/// A local write, before it has a seq, an HLC or a signature.
#[derive(Clone, Debug, PartialEq)]
pub struct Draft {
    pub kind: String,
    pub key: String,
    pub payload: Value,
    pub hlc: HlcPolicy,
}

impl Draft {
    pub fn of<K: super::kinds::ItemKind>(value: &K, hlc: HlcPolicy) -> Self {
        Self {
            kind: K::KIND.to_owned(),
            key: value.item_key(),
            payload: value.payload(),
            hlc,
        }
    }
}

/// Counters for `status` and `doctor`; never part of the replicated state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub rejected_items: u64,
    /// Largest flagged clock skew seen per origin, in ms.
    pub clock_skew: BTreeMap<DeviceId, u64>,
    pub regressions: BTreeMap<DeviceId, u64>,
    pub repairs_changed: u64,
    pub fork_evidence: Vec<ForkEvidence>,
}

pub trait MeshStore {
    fn genesis(&self) -> GenesisInfo;

    /// This device's id.
    fn self_id(&self) -> DeviceId;

    fn vv(&self) -> &VersionVector;

    fn state(&self) -> &State;

    fn stats(&self) -> &Stats;

    /// The hash in the dot log at `(origin, seq)`, for `1 ≤ seq ≤ vv[origin]`.
    fn dot_hash(&self, origin: &DeviceId, seq: u64) -> Option<ItemHash>;

    /// `chain(origin, seq)` for `0 ≤ seq ≤ vv[origin]` (PROTOCOL.md §7.1).
    fn chain_at(&self, origin: &DeviceId, seq: u64) -> Option<Hash32>;

    /// The digest of the items held for `origin` (PROTOCOL.md §8.5).
    fn origin_digest(&self, origin: &DeviceId) -> Hash32;

    /// The items held for `origin` with `from_exclusive < seq ≤ to_inclusive`,
    /// in seq order.
    fn held_items(
        &self,
        origin: &DeviceId,
        from_exclusive: u64,
        to_inclusive: u64,
    ) -> Vec<SignedItem>;

    /// Items this device has accepted from `origin` in the current hour of
    /// its clock (the ingest rate limit, PROTOCOL.md §3.3 check 6).
    fn ingest_rate_used(&self, origin: &DeviceId) -> u64;

    /// The local physical clock, in ms.
    fn now_ms(&self) -> u64;

    /// The HLC's high-water mark.
    fn hlc_last(&self) -> Hlc;

    /// Apply one session's commit atomically.
    fn commit(&mut self, batch: CommitBatch) -> Result<CommitOutcome, MeshError>;

    /// Allocate the next seq of this device, sign, and commit locally.
    fn mint(&mut self, key: &SigningKeyPair, draft: Draft) -> Result<SignedItem, MeshError>;

    /// Count items rejected at ingest.
    fn record_rejected(&mut self, n: u64);
}
