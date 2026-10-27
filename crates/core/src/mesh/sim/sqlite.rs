//! SQLite stores for the simulator: the store conformance suite (Increment
//! 03, DESIGN §D21 "Store conformance").
//!
//! Every simulated device gets its own directory holding a real `vault.db`
//! (migrated with every migration, so the mesh tables are exactly the
//! shipped schema) and a real identity marker. On top of the simulator's
//! faults this adds the ones only a database has:
//! - **a crash between commit chunks**: the store stops after some of a
//!   commit's transactions, the device goes down, and only what was
//!   committed survives;
//! - **a restart reopens from disk**: the connection is dropped and the store
//!   is rebuilt from the file, so every restart checks durability;
//! - **fork injection copies the data directory**: database and marker, the
//!   one copy the marker cannot catch.
//!
//! I/O lives here, not in the sans-IO protocol modules.

use crate::db;
use crate::mesh::chain::Hash32;
use crate::mesh::clock::Clock;
use crate::mesh::dot::{DeviceId, MarkerNonce};
use crate::mesh::error::MeshError;
use crate::mesh::hlc::Hlc;
use crate::mesh::item::{ItemHash, SignedItem};
use crate::mesh::marker::{self, MarkerContents};
use crate::mesh::sign::SigningKeyPair;
use crate::mesh::sim::rng::SplitMix64;
use crate::mesh::sim::world::{SimStore, StoreFactory};
use crate::mesh::sqlite_store::{MarkerConfig, SqliteStore, StoreParams, SIMULATED_CRASH};
use crate::mesh::store::{CommitBatch, CommitOutcome, Draft, GenesisInfo, MeshStore, Stats};
use crate::mesh::views::State;
use crate::mesh::vv::VersionVector;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const DB_FILE: &str = "vault.db";

/// Creates one SQLite-backed device per call, each in a fresh directory
/// under `base`.
pub struct SqliteFactory {
    base: PathBuf,
    next_dir: Arc<AtomicU64>,
    rng: SplitMix64,
    chunk_items: usize,
    commit_crash_pm: u64,
}

impl SqliteFactory {
    /// Devices live under `base` (the caller owns and removes it). `seed`
    /// drives the marker nonces and the store-level faults, independently of
    /// the world's own random stream.
    pub fn new(base: &Path, seed: u64) -> Self {
        Self {
            base: base.to_path_buf(),
            next_dir: Arc::new(AtomicU64::new(0)),
            rng: SplitMix64::new(seed ^ 0x5917_7E00_0000_0003),
            chunk_items: 1,
            commit_crash_pm: 30,
        }
    }

    /// Items and dots per commit chunk. 1 by default: every origin, and every
    /// repair item, is its own transaction, so every commit of more than one
    /// origin can crash part-way.
    pub fn chunk_items(mut self, n: usize) -> Self {
        self.chunk_items = n;
        self
    }

    /// Per mille of commits that crash after one of their chunks. Zero makes
    /// a SQLite run step for step identical to a `MemStore` run.
    pub fn commit_crash_pm(mut self, pm: u64) -> Self {
        self.commit_crash_pm = pm;
        self
    }
}

impl StoreFactory for SqliteFactory {
    type Store = SimSqlite;

    fn create(&mut self, genesis: GenesisInfo, id: DeviceId, clock: Arc<dyn Clock>) -> SimSqlite {
        let mut nonce = [0u8; 16];
        self.rng.fill_bytes(&mut nonce);
        let dir = fresh_dir(&self.base, &self.next_dir);
        let nonce = MarkerNonce::from_bytes(nonce);
        // What identity creation does: a marker before the first seq.
        marker::write(&dir, &MarkerContents::new(id, nonce, 0)).expect("marker");
        let params = StoreParams {
            genesis,
            self_id: id,
            marker: Some(MarkerConfig {
                data_dir: dir.clone(),
                nonce,
            }),
        };
        let mut conn = db::open(&dir.join(DB_FILE)).expect("open the device database");
        db::migrate(&mut conn).expect("migrate the device database");
        drop(conn);
        SimSqlite::open(
            dir,
            self.base.clone(),
            self.next_dir.clone(),
            params,
            clock,
            self.chunk_items,
            self.commit_crash_pm,
            self.rng.fork(),
        )
    }
}

fn fresh_dir(base: &Path, next: &AtomicU64) -> PathBuf {
    let n = next.fetch_add(1, Ordering::Relaxed);
    let dir = base.join(format!("device-{n:04}"));
    std::fs::create_dir_all(&dir).expect("create a device directory");
    dir
}

/// A SQLite-backed simulated device.
pub struct SimSqlite {
    store: SqliteStore,
    dir: PathBuf,
    base: PathBuf,
    next_dir: Arc<AtomicU64>,
    chunk_items: usize,
    commit_crash_pm: u64,
    rng: SplitMix64,
}

impl SimSqlite {
    #[allow(clippy::too_many_arguments)]
    fn open(
        dir: PathBuf,
        base: PathBuf,
        next_dir: Arc<AtomicU64>,
        params: StoreParams,
        clock: Arc<dyn Clock>,
        chunk_items: usize,
        commit_crash_pm: u64,
        rng: SplitMix64,
    ) -> Self {
        let store = open_store(&dir, params, clock, chunk_items);
        Self {
            store,
            dir,
            base,
            next_dir,
            chunk_items,
            commit_crash_pm,
            rng,
        }
    }

    pub fn store(&self) -> &SqliteStore {
        &self.store
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

fn open_store(
    dir: &Path,
    params: StoreParams,
    clock: Arc<dyn Clock>,
    chunk_items: usize,
) -> SqliteStore {
    let conn = db::open(&dir.join(DB_FILE)).expect("open the device database");
    let mut store = SqliteStore::open(conn, params, clock).expect("open the mesh store");
    store.set_chunk_items(chunk_items);
    store.relax_fsync_for_tests().expect("configure the store");
    store
}

impl MeshStore for SimSqlite {
    fn genesis(&self) -> GenesisInfo {
        self.store.genesis()
    }
    fn self_id(&self) -> DeviceId {
        self.store.self_id()
    }
    fn vv(&self) -> &VersionVector {
        self.store.vv()
    }
    fn state(&self) -> &State {
        self.store.state()
    }
    fn stats(&self) -> &Stats {
        self.store.stats()
    }
    fn dot_hash(&self, origin: &DeviceId, seq: u64) -> Result<Option<ItemHash>, MeshError> {
        self.store.dot_hash(origin, seq)
    }
    fn dot_hashes(
        &self,
        origin: &DeviceId,
        from_exclusive: u64,
        to_inclusive: u64,
    ) -> Result<Vec<(u64, ItemHash)>, MeshError> {
        self.store.dot_hashes(origin, from_exclusive, to_inclusive)
    }
    fn chain_at(&self, origin: &DeviceId, seq: u64) -> Result<Option<Hash32>, MeshError> {
        self.store.chain_at(origin, seq)
    }
    fn origin_digest(&self, origin: &DeviceId) -> Hash32 {
        self.store.origin_digest(origin)
    }
    fn held_items(
        &self,
        origin: &DeviceId,
        from_exclusive: u64,
        to_inclusive: u64,
    ) -> Result<Vec<SignedItem>, MeshError> {
        self.store.held_items(origin, from_exclusive, to_inclusive)
    }
    fn ingest_rate_used(&self, origin: &DeviceId) -> u64 {
        self.store.ingest_rate_used(origin)
    }
    fn now_ms(&self) -> u64 {
        self.store.now_ms()
    }
    fn hlc_last(&self) -> Hlc {
        self.store.hlc_last()
    }
    fn commit(&mut self, batch: CommitBatch) -> Result<CommitOutcome, MeshError> {
        // Only a commit of several origins (or of main-path items and
        // repair items) has more than one chunk to crash between.
        let mut origins: BTreeSet<DeviceId> = batch.items.iter().map(|v| v.body.origin).collect();
        origins.extend(batch.dots.iter().map(|d| d.0));
        origins.extend(batch.upto.iter().map(|(o, _)| *o));
        let parts = origins.len() + usize::from(!batch.repair.is_empty());
        if parts > 1 && self.commit_crash_pm > 0 && self.rng.chance(self.commit_crash_pm, 1000) {
            let after = 1 + self.rng.below(parts as u64 - 1) as usize;
            self.store.hooks().crash_after_chunks = Some(after);
        }
        self.store.commit(batch)
    }
    fn mint(&mut self, key: &SigningKeyPair, draft: Draft) -> Result<SignedItem, MeshError> {
        self.store.mint(key, draft)
    }
    fn record_rejected(&mut self, n: u64) {
        self.store.record_rejected(n)
    }
}

impl SimStore for SimSqlite {
    fn restart(&mut self, clock: Arc<dyn Clock>) {
        // A new connection reads only what is committed on disk; the old one
        // (no transaction open) is dropped by the assignment.
        let params = self.store.params().clone();
        self.store = open_store(&self.dir, params, clock, self.chunk_items);
    }

    fn clone_onto(&self, clock: Arc<dyn Clock>) -> Self {
        // Everything committed into the main file, then copy the directory.
        self.store
            .connection()
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .expect("checkpoint");
        let dir = fresh_dir(&self.base, &self.next_dir);
        std::fs::copy(self.dir.join(DB_FILE), dir.join(DB_FILE)).expect("copy the database");
        std::fs::create_dir_all(marker::mesh_dir(&dir)).expect("mesh dir");
        std::fs::copy(marker::marker_path(&self.dir), marker::marker_path(&dir))
            .expect("copy the marker");
        let mut params = self.store.params().clone();
        if let Some(m) = &mut params.marker {
            m.data_dir = dir.clone();
        }
        let mut rng = self.rng.clone();
        SimSqlite::open(
            dir,
            self.base.clone(),
            self.next_dir.clone(),
            params,
            clock,
            self.chunk_items,
            self.commit_crash_pm,
            rng.fork(),
        )
    }

    fn all_items(&self) -> Vec<SignedItem> {
        self.store.all_items().expect("read every item")
    }

    fn rebuild_views(&self) -> Result<State, MeshError> {
        self.store.rebuild_views()
    }

    fn holds(&self, hash: &ItemHash) -> bool {
        self.store.holds(hash).expect("read mesh_items")
    }

    fn injects_faults(&self) -> bool {
        self.commit_crash_pm > 0
    }

    fn calm(&mut self) {
        self.commit_crash_pm = 0;
    }

    fn is_simulated_crash(err: &MeshError) -> bool {
        *err == MeshError::Storage(SIMULATED_CRASH)
    }

    fn check_durable(&self) -> Result<(), String> {
        self.store.verify_against_disk()
    }
}
