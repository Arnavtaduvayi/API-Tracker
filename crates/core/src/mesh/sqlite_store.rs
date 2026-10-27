//! The SQLite [`MeshStore`] (Increment 03): the store every real device runs.
//!
//! **What lives where.** The item store (`mesh_items`), the version vector
//! (`mesh_vv`) and the dot log with its chain (`mesh_dots`) are on disk and
//! are read on demand: the dot log grows with every item any device ever
//! minted, so it is never loaded whole. In memory the store keeps what the
//! protocol reads by reference or on every `Hello` — the VV, the views
//! ([`State`], rebuilt from `mesh_items` at open), the counters, the HLC and
//! the per-origin digests — as a mirror of the database, never ahead of it
//! after a transaction ends.
//!
//! **The same commit as `MemStore`.** Validation is the shared
//! [`validate_commit`]; applying follows `MemStore::commit` step for step:
//! forks noted, main-path items applied as entries (HLC observed, rate
//! counted), each complete range's dots appended with their chain and its VV
//! advanced, then repair items as entries only. The conformance suite runs
//! the simulator over this store and checks it against the same oracle, and
//! with crashes disabled the two stores produce identical runs.
//!
//! **Chunked commits.** A large commit is split into several transactions so
//! no single one holds SQLite's write lock for long (the gateway writes to the
//! same database; DESIGN §D12). The rule: **a chunk holds whole origins.**
//! Every item, dot and VV entry of one origin lands in one transaction, so a
//! crash between chunks leaves exactly the state a smaller, valid commit (of
//! the origins already written) would have produced — every held item still
//! inside its origin's VV and dot log. Splitting one origin's range would not
//! be safe: a dot whose item was superseded later in the range would be
//! logged before the item that supersedes it. Repair items, which never touch
//! the VV or the dot log, come last, in batch order, split freely. The cost:
//! one origin's range — at most the session's 50 000 staged items and dots —
//! is one transaction.
//!
//! **Durability.** The store's connection runs `synchronous=FULL` (and
//! `fullfsync` on macOS), so every commit and mint is on disk when it
//! returns. `hlc_high_water` is written with every write transaction. Before a
//! mint uses a seq above the identity marker's mark, the marker is advanced a
//! block of 64 seqs (module `marker`).
//!
//! **Several processes.** Every write transaction (`BEGIN IMMEDIATE`) first
//! compares `mesh_meta.write_gen` with the generation this store last saw;
//! if another process wrote since, the mirror is reloaded inside the
//! transaction before anything is decided. A failed transaction reloads the
//! mirror too, so memory never runs ahead of the database.

use super::chain::Hash32;
use super::clock::Clock;
use super::codec::{ItemBody, MAX_SEQ};
use super::dot::{DeviceId, MarkerNonce};
use super::error::MeshError;
use super::hlc::{Hlc, HlcClock};
use super::item::{ItemHash, SignedItem};
use super::kinds::TypedItem;
use super::marker::{self, MarkerContents, MarkerStatus, SEQ_BLOCK};
use super::sign::SigningKeyPair;
use super::store::{
    validate_commit, CommitBatch, CommitOutcome, Draft, ForkEvidence, GenesisInfo, HlcPolicy,
    MeshStore, Stats, Validated, VerifiedItem, HOUR_MS,
};
use super::views::{self, State};
use super::vv::VersionVector;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

/// Items and dots per commit chunk (whole origins only; one origin larger
/// than this is still one chunk). ~2 000 rows keep a chunk well under the
/// 250 ms budget of DESIGN §D12 on a laptop SSD.
pub const DEFAULT_CHUNK_ITEMS: usize = 2_000;

/// The error a [`TestHooks::crash_after_chunks`] crash returns.
pub const SIMULATED_CRASH: &str = "simulated crash between commit chunks";

/// Where a store finds its identity marker, and the nonce the marker must
/// carry. `None` in [`StoreParams`] means no marker: only for stores that
/// never mint as a real device (tests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkerConfig {
    pub data_dir: PathBuf,
    pub nonce: MarkerNonce,
}

/// Everything a store needs besides its database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreParams {
    pub genesis: GenesisInfo,
    pub self_id: DeviceId,
    pub marker: Option<MarkerConfig>,
}

/// Fault injection for tests and the conformance simulator.
#[cfg(any(test, feature = "mesh-sim"))]
#[derive(Clone, Debug, Default)]
pub struct TestHooks {
    /// Fail the next main-path chunk after its items are written and before
    /// its dots and VV are; the transaction must roll back whole.
    pub fail_before_vv: bool,
    /// End the next commit after this many chunks have committed, as a crash
    /// would (`>= 1`). Returns [`MeshError::Storage`]`(`[`SIMULATED_CRASH`]`)`.
    pub crash_after_chunks: Option<usize>,
    /// Fail the next mint just before its transaction commits (after the
    /// marker was advanced, if it had to be).
    pub fail_mint_commit: bool,
}

/// The in-memory mirror of the database.
struct Mirror {
    genesis: GenesisInfo,
    self_id: DeviceId,
    vv: VersionVector,
    state: State,
    stats: Stats,
    digests: BTreeMap<DeviceId, Hash32>,
    /// Items accepted per origin in the current hour: `(hour, count)`.
    rate: BTreeMap<DeviceId, (u64, u64)>,
    hlc: HlcClock<Arc<dyn Clock>>,
    generation: i64,
    /// Origins whose digest or per-origin counters changed in the open
    /// transaction.
    dirty: BTreeSet<DeviceId>,
}

impl Mirror {
    fn new(genesis: GenesisInfo, self_id: DeviceId, clock: Arc<dyn Clock>) -> Self {
        Self {
            genesis,
            self_id,
            vv: VersionVector::new(),
            state: State::new(genesis),
            stats: Stats::default(),
            digests: BTreeMap::new(),
            rate: BTreeMap::new(),
            hlc: HlcClock::new(clock),
            generation: 0,
            dirty: BTreeSet::new(),
        }
    }
}

/// The marker reservation state of one store.
struct MarkerState {
    cfg: Option<MarkerConfig>,
    /// The highest seq known to be covered by the marker on disk.
    mark: u64,
    writes: u64,
}

impl MarkerState {
    /// Make sure the marker covers `seq` before it is used (DESIGN §D5):
    /// re-read it, require it to vouch for this database, and advance it by
    /// a block if needed. Every write is durable before this returns.
    fn reserve(&mut self, self_id: &DeviceId, seq: u64, last_seq: u64) -> Result<(), MeshError> {
        let Some(cfg) = &self.cfg else {
            return Ok(());
        };
        if seq <= self.mark {
            return Ok(());
        }
        let current = marker::read(&cfg.data_dir)?;
        let status = marker::classify(current.as_ref(), self_id, &cfg.nonce, last_seq);
        if let Some(e) = status.to_error() {
            return Err(e);
        }
        let on_disk = current.map_or(0, |c| c.seq_high_water);
        if on_disk >= seq {
            // Another store on this database reserved it already.
            self.mark = on_disk;
            return Ok(());
        }
        let mark = seq.saturating_add(SEQ_BLOCK - 1);
        marker::write(
            &cfg.data_dir,
            &MarkerContents::new(*self_id, cfg.nonce, mark),
        )?;
        self.mark = mark;
        self.writes += 1;
        Ok(())
    }
}

pub struct SqliteStore {
    conn: Connection,
    params: StoreParams,
    m: Mirror,
    marker: MarkerState,
    chunk_items: usize,
    #[cfg(any(test, feature = "mesh-sim"))]
    hooks: TestHooks,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore")
            .field("self_id", &self.m.self_id)
            .field("vv", &self.m.vv)
            .finish_non_exhaustive()
    }
}

// ------------------------------------------------------------------ helpers

fn sql(context: &'static str) -> impl FnOnce(rusqlite::Error) -> MeshError {
    move |e| {
        if matches!(
            e.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        ) {
            MeshError::Storage("the database stayed locked by another writer")
        } else {
            MeshError::Storage(context)
        }
    }
}

fn to_i64(v: u64) -> Result<i64, MeshError> {
    i64::try_from(v).map_err(|_| MeshError::Storage("a value is too large to store"))
}

/// A seq bound for a range query (stored seqs never exceed `MAX_SEQ`).
fn bound(v: u64) -> i64 {
    v.min(MAX_SEQ) as i64
}

fn to_u64(v: i64) -> Result<u64, MeshError> {
    u64::try_from(v).map_err(|_| MeshError::Storage("a stored value is negative"))
}

fn hash32(bytes: Vec<u8>) -> Result<[u8; 32], MeshError> {
    bytes
        .try_into()
        .map_err(|_| MeshError::Storage("a stored hash is not 32 bytes"))
}

fn meta_get(conn: &Connection, key: &str) -> Result<Option<i64>, MeshError> {
    conn.prepare_cached("SELECT value FROM mesh_meta WHERE key = ?1")
        .and_then(|mut st| st.query_row([key], |r| r.get::<_, i64>(0)).optional())
        .map_err(sql("reading mesh_meta"))
}

fn meta_set(conn: &Connection, key: &str, value: i64) -> Result<(), MeshError> {
    conn.prepare_cached(
        "INSERT INTO mesh_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .and_then(|mut st| st.execute(params![key, value]))
    .map(|_| ())
    .map_err(sql("writing mesh_meta"))
}

fn begin(conn: &Connection, behavior: TransactionBehavior) -> Result<Transaction<'_>, MeshError> {
    Transaction::new_unchecked(conn, behavior).map_err(sql("starting a transaction"))
}

fn dot_hash_in(conn: &Connection, o: &DeviceId, s: u64) -> Result<Option<ItemHash>, MeshError> {
    if s == 0 || s > MAX_SEQ {
        return Ok(None);
    }
    conn.prepare_cached("SELECT hash FROM mesh_dots WHERE origin = ?1 AND seq = ?2")
        .and_then(|mut st| {
            st.query_row(params![o.to_hex(), s as i64], |r| r.get::<_, Vec<u8>>(0))
                .optional()
        })
        .map_err(sql("reading the dot log"))?
        .map(|h| hash32(h).map(ItemHash))
        .transpose()
}

fn chain_in(conn: &Connection, o: &DeviceId, s: u64) -> Result<Option<Hash32>, MeshError> {
    if s == 0 {
        return Ok(Some(Hash32::ZERO));
    }
    if s > MAX_SEQ {
        return Ok(None);
    }
    conn.prepare_cached("SELECT chain FROM mesh_dots WHERE origin = ?1 AND seq = ?2")
        .and_then(|mut st| {
            st.query_row(params![o.to_hex(), s as i64], |r| r.get::<_, Vec<u8>>(0))
                .optional()
        })
        .map_err(sql("reading the dot log"))?
        .map(|h| hash32(h).map(Hash32))
        .transpose()
}

fn digest_in(conn: &Connection, o: &DeviceId) -> Result<Hash32, MeshError> {
    let mut st = conn
        .prepare_cached("SELECT hash FROM mesh_items WHERE origin = ?1")
        .map_err(sql("reading held items"))?;
    let rows = st
        .query_map([o.to_hex()], |r| r.get::<_, Vec<u8>>(0))
        .map_err(sql("reading held items"))?;
    let mut hashes = Vec::new();
    for h in rows {
        hashes.push(ItemHash(hash32(h.map_err(sql("reading held items"))?)?));
    }
    Ok(Hash32::digest_of(hashes))
}

/// Load the whole mirror from the database. The caller provides the
/// transaction that makes the reads one snapshot.
fn load(conn: &Connection, m: &mut Mirror) -> Result<(), MeshError> {
    let mut vv = VersionVector::new();
    {
        let mut st = conn
            .prepare("SELECT origin, max_seq FROM mesh_vv")
            .map_err(sql("reading mesh_vv"))?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(sql("reading mesh_vv"))?;
        for row in rows {
            let (o, s) = row.map_err(sql("reading mesh_vv"))?;
            vv.advance_to(DeviceId::parse(&o)?, to_u64(s)?);
        }
    }
    let mut state = State::new(m.genesis);
    let mut per_origin: BTreeMap<DeviceId, Vec<ItemHash>> = BTreeMap::new();
    {
        let mut st = conn
            .prepare("SELECT bytes FROM mesh_items ORDER BY origin, seq, hash")
            .map_err(sql("reading mesh_items"))?;
        let rows = st
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(sql("reading mesh_items"))?;
        for bytes in rows {
            let item = SignedItem::from_wire(&bytes.map_err(sql("reading mesh_items"))?)?;
            let body = item.decode_unverified()?;
            per_origin.entry(body.origin).or_default().push(item.hash());
            views::apply_stored(&mut state, &item)?;
        }
    }
    let digests = per_origin
        .into_iter()
        .map(|(o, hs)| (o, Hash32::digest_of(hs)))
        .collect();

    let mut stats = Stats::default();
    let mut rate: BTreeMap<DeviceId, (u64, u64)> = BTreeMap::new();
    let mut hlc_high_water = 0u64;
    let mut generation = 0i64;
    {
        let mut st = conn
            .prepare("SELECT key, value FROM mesh_meta")
            .map_err(sql("reading mesh_meta"))?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, rusqlite::types::Value>(1)?,
                ))
            })
            .map_err(sql("reading mesh_meta"))?;
        for row in rows {
            let (key, value) = row.map_err(sql("reading mesh_meta"))?;
            let rusqlite::types::Value::Integer(v) = value else {
                continue;
            };
            let origin = |prefix: &str| key.strip_prefix(prefix).map(DeviceId::parse);
            if key == "rejected_items" {
                stats.rejected_items = to_u64(v)?;
            } else if key == "repairs_changed" {
                stats.repairs_changed = to_u64(v)?;
            } else if key == "hlc_high_water" {
                hlc_high_water = to_u64(v)?;
            } else if key == "write_gen" {
                generation = v;
            } else if let Some(o) = origin("clock_skew/") {
                stats.clock_skew.insert(o?, to_u64(v)?);
            } else if let Some(o) = origin("regressions/") {
                stats.regressions.insert(o?, to_u64(v)?);
            } else if let Some(o) = origin("ingest_hour/") {
                rate.entry(o?).or_insert((0, 0)).0 = to_u64(v)?;
            } else if let Some(o) = origin("ingest_count/") {
                rate.entry(o?).or_insert((0, 0)).1 = to_u64(v)?;
            }
        }
    }
    {
        let mut st = conn
            .prepare("SELECT origin, seq, hash_a, hash_b FROM mesh_fork_evidence ORDER BY rowid")
            .map_err(sql("reading fork evidence"))?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(sql("reading fork evidence"))?;
        for row in rows {
            let (o, s, a, b) = row.map_err(sql("reading fork evidence"))?;
            stats.fork_evidence.push(ForkEvidence {
                origin: DeviceId::parse(&o)?,
                seq: to_u64(s)?,
                ours: ItemHash(hash32(a)?),
                theirs: ItemHash(hash32(b)?),
            });
        }
    }
    m.vv = vv;
    m.state = state;
    m.stats = stats;
    m.digests = digests;
    m.rate = rate;
    m.hlc.restore(Hlc::from_raw(hlc_high_water));
    m.generation = generation;
    m.dirty.clear();
    Ok(())
}

/// Reload the mirror if another process wrote since this store last did.
fn sync_generation(conn: &Connection, m: &mut Mirror) -> Result<(), MeshError> {
    if meta_get(conn, "write_gen")?.unwrap_or(0) != m.generation {
        load(conn, m)?;
    }
    Ok(())
}

/// Make `v` the held entry for its `(kind, key, origin)` if it supersedes the
/// current one (`MemStore::apply_entry`). Returns `(changed, regression)`.
fn apply_entry(
    conn: &Connection,
    m: &mut Mirror,
    v: &VerifiedItem,
    now_ms: u64,
) -> Result<(bool, bool), MeshError> {
    let (o, s, h) = (v.body.origin, v.body.seq, v.item.hash());
    let origin = o.to_hex();
    let seq = to_i64(s)?;
    let received_at = to_i64(now_ms).unwrap_or(i64::MAX);
    let old = conn
        .prepare_cached(
            "SELECT seq, hash FROM mesh_items WHERE kind = ?1 AND item_key = ?2 AND origin = ?3",
        )
        .and_then(|mut st| {
            st.query_row(params![v.body.kind, v.body.key, origin], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .optional()
        })
        .map_err(sql("reading mesh_items"))?;
    if let Some((os, oh)) = old {
        let old = (to_u64(os)?, ItemHash(hash32(oh)?));
        if old >= (s, h) {
            return Ok((false, false));
        }
        conn.prepare_cached("DELETE FROM mesh_items WHERE origin = ?1 AND seq = ?2 AND hash = ?3")
            .and_then(|mut st| st.execute(params![origin, os, old.1 .0.as_slice()]))
            .map_err(sql("superseding an item"))?;
    }
    conn.prepare_cached(
        "INSERT INTO mesh_items (origin, seq, hash, kind, item_key, bytes, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .and_then(|mut st| {
        st.execute(params![
            origin,
            seq,
            h.0.as_slice(),
            v.body.kind,
            v.body.key,
            v.item.to_wire(),
            received_at,
        ])
    })
    .map_err(sql("storing an item"))?;
    m.dirty.insert(o);
    let out = m.state.apply(&v.body, h, &v.typed);
    Ok((true, out.regression))
}

/// Append `hashes` to `o`'s dot log after its current VV, with their chain,
/// and advance the VV to the end of the range.
fn append_range(
    conn: &Connection,
    m: &mut Mirror,
    o: &DeviceId,
    hashes: &[ItemHash],
) -> Result<(), MeshError> {
    if hashes.is_empty() {
        return Ok(());
    }
    let cur = m.vv.get(o);
    let mut prev =
        chain_in(conn, o, cur)?.ok_or(MeshError::Storage("the dot log has a gap below the VV"))?;
    let origin = o.to_hex();
    let mut st = conn
        .prepare_cached("INSERT INTO mesh_dots (origin, seq, hash, chain) VALUES (?1, ?2, ?3, ?4)")
        .map_err(sql("extending the dot log"))?;
    let mut seq = cur;
    for h in hashes {
        seq += 1;
        let chain = prev.chain_next(h);
        st.execute(params![
            origin,
            to_i64(seq)?,
            h.0.as_slice(),
            chain.0.as_slice()
        ])
        .map_err(sql("extending the dot log"))?;
        prev = chain;
    }
    let top = to_i64(seq)?;
    conn.prepare_cached(
        "INSERT INTO mesh_vv (origin, max_seq) VALUES (?1, ?2)
         ON CONFLICT(origin) DO UPDATE SET max_seq = excluded.max_seq",
    )
    .and_then(|mut st| st.execute(params![origin, top]))
    .map_err(sql("advancing the VV"))?;
    m.vv.advance_to(*o, seq);
    m.dirty.insert(*o);
    Ok(())
}

fn note_fork(
    conn: &Connection,
    m: &mut Mirror,
    ev: ForkEvidence,
    now_ms: u64,
    out: &mut CommitOutcome,
) -> Result<(), MeshError> {
    if !m
        .stats
        .fork_evidence
        .iter()
        .any(|e| e.origin == ev.origin && e.seq == ev.seq)
    {
        conn.prepare_cached(
            "INSERT OR IGNORE INTO mesh_fork_evidence (origin, seq, hash_a, hash_b, seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .and_then(|mut st| {
            st.execute(params![
                ev.origin.to_hex(),
                ev.seq.min(MAX_SEQ) as i64,
                ev.ours.0.as_slice(),
                ev.theirs.0.as_slice(),
                now_ms.min(i64::MAX as u64) as i64,
            ])
        })
        .map_err(sql("recording fork evidence"))?;
        m.stats.fork_evidence.push(ev);
    }
    out.forks.push(ev);
    Ok(())
}

fn observe(m: &mut Mirror, body: &ItemBody) {
    let obs = m.hlc.observe(body.hlc);
    if obs.clamped {
        let e = m.stats.clock_skew.entry(body.origin).or_insert(0);
        *e = (*e).max(obs.skew_ms);
        m.dirty.insert(body.origin);
    }
}

/// Write everything the open transaction changed in the mirror's counters
/// and digests, the HLC high-water mark, and the next generation.
fn finish(conn: &Connection, m: &mut Mirror) -> Result<(), MeshError> {
    for o in std::mem::take(&mut m.dirty) {
        let hex = o.to_hex();
        let digest = digest_in(conn, &o)?;
        m.digests.insert(o, digest);
        if let Some(v) = m.stats.clock_skew.get(&o) {
            meta_set(conn, &format!("clock_skew/{hex}"), to_i64(*v)?)?;
        }
        if let Some(v) = m.stats.regressions.get(&o) {
            meta_set(conn, &format!("regressions/{hex}"), to_i64(*v)?)?;
        }
        if let Some((hour, count)) = m.rate.get(&o) {
            meta_set(conn, &format!("ingest_hour/{hex}"), to_i64(*hour)?)?;
            meta_set(conn, &format!("ingest_count/{hex}"), to_i64(*count)?)?;
        }
    }
    meta_set(conn, "repairs_changed", to_i64(m.stats.repairs_changed)?)?;
    meta_set(conn, "hlc_high_water", to_i64(m.hlc.last().raw())?)?;
    m.generation += 1;
    meta_set(conn, "write_gen", m.generation)
}

/// Mint one item inside an open write transaction (`MemStore::mint`).
fn mint_in(
    conn: &Connection,
    m: &mut Mirror,
    marker: &mut MarkerState,
    key: &SigningKeyPair,
    draft: Draft,
) -> Result<SignedItem, MeshError> {
    let me = m.self_id;
    let last = m.vv.get(&me);
    let seq = last + 1;
    if seq > MAX_SEQ {
        return Err(MeshError::InvalidOperation(
            "this device has used every seq",
        ));
    }
    marker.reserve(&me, seq, last)?;
    let hlc = match draft.hlc {
        HlcPolicy::Now => m.hlc.now(),
        HlcPolicy::After(winner) => m.hlc.local_write_ts(winner),
    };
    let body = ItemBody::new(
        m.genesis.mesh_id,
        me,
        seq,
        hlc,
        draft.kind,
        draft.key,
        draft.payload,
    );
    let typed = TypedItem::parse(&body)?;
    let item = SignedItem::sign(&body, key)?;
    let v = VerifiedItem {
        item: item.clone(),
        body,
        typed,
    };
    let now = m.hlc.clock().now_ms();
    let (_, regression) = apply_entry(conn, m, &v, now)?;
    if regression {
        *m.stats.regressions.entry(me).or_insert(0) += 1;
    }
    append_range(conn, m, &me, &[item.hash()])?;
    Ok(item)
}

/// Mint the first items of a new identity inside the caller's transaction
/// (`mesh init`), through exactly the code path every later mint takes. The
/// caller has already written the marker that covers these seqs.
pub(crate) fn mint_genesis(
    conn: &Connection,
    params: &StoreParams,
    clock: Arc<dyn Clock>,
    key: &SigningKeyPair,
    drafts: Vec<Draft>,
) -> Result<Vec<SignedItem>, MeshError> {
    let mut m = Mirror::new(params.genesis, params.self_id, clock);
    load(conn, &mut m)?;
    let mut marker = MarkerState {
        cfg: params.marker.clone(),
        mark: 0,
        writes: 0,
    };
    let mut out = Vec::with_capacity(drafts.len());
    for d in drafts {
        out.push(mint_in(conn, &mut m, &mut marker, key, d)?);
    }
    finish(conn, &mut m)?;
    Ok(out)
}

/// One transaction's share of a commit.
enum Chunk {
    /// Every item, dot and VV entry of some origins.
    Main(CommitBatch),
    /// Repair items, in batch order.
    Repair(Vec<VerifiedItem>),
}

/// Split a batch into chunks of whole origins, then repair items.
fn plan_chunks(batch: CommitBatch, limit: usize) -> Vec<Chunk> {
    let limit = limit.max(1);
    let mut by_origin: BTreeMap<DeviceId, CommitBatch> = BTreeMap::new();
    for v in batch.items {
        by_origin.entry(v.body.origin).or_default().items.push(v);
    }
    for d in batch.dots {
        by_origin.entry(d.0).or_default().dots.push(d);
    }
    for (o, s) in batch.upto.iter() {
        by_origin.entry(*o).or_default().upto.advance_to(*o, *s);
    }
    let mut chunks = Vec::new();
    let mut cur = CommitBatch::default();
    let mut n = 0usize;
    for (_, part) in by_origin {
        let size = part.items.len() + part.dots.len() + 1;
        if n > 0 && n + size > limit {
            chunks.push(Chunk::Main(std::mem::take(&mut cur)));
            n = 0;
        }
        cur.items.extend(part.items);
        cur.dots.extend(part.dots);
        cur.upto.join(&part.upto);
        n += size;
    }
    if n > 0 {
        chunks.push(Chunk::Main(cur));
    }
    let mut repair = batch.repair.into_iter().peekable();
    while repair.peek().is_some() {
        chunks.push(Chunk::Repair(repair.by_ref().take(limit).collect()));
    }
    chunks
}

// -------------------------------------------------------------------- store

impl SqliteStore {
    /// Open the store on `conn`, a connection to a database migrated to v21
    /// or later. Loads the mirror from disk.
    pub fn open(
        conn: Connection,
        params: StoreParams,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, MeshError> {
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(sql("configuring durability"))?;
        // macOS: make SQLite's syncs F_FULLFSYNC (a no-op elsewhere).
        conn.pragma_update(None, "fullfsync", true)
            .map_err(sql("configuring durability"))?;
        let mut m = Mirror::new(params.genesis, params.self_id, clock);
        {
            let tx = begin(&conn, TransactionBehavior::Deferred)?;
            load(&tx, &mut m)?;
            tx.commit().map_err(sql("reading the mesh store"))?;
        }
        // Trust the marker's mark only if the marker vouches for this
        // database as it is now. Otherwise start from 0, so the first mint
        // re-checks the marker and refuses: a rolled-back database still
        // names the right identity, and must not mint below the mark.
        let mark = match &params.marker {
            Some(cfg) => {
                let current = marker::read(&cfg.data_dir).ok().flatten();
                let last = m.vv.get(&params.self_id);
                match marker::classify(current.as_ref(), &params.self_id, &cfg.nonce, last) {
                    MarkerStatus::Ok => current.map_or(0, |c| c.seq_high_water),
                    _ => 0,
                }
            }
            None => 0,
        };
        Ok(Self {
            marker: MarkerState {
                cfg: params.marker.clone(),
                mark,
                writes: 0,
            },
            conn,
            params,
            m,
            chunk_items: DEFAULT_CHUNK_ITEMS,
            #[cfg(any(test, feature = "mesh-sim"))]
            hooks: TestHooks::default(),
        })
    }

    pub fn params(&self) -> &StoreParams {
        &self.params
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn into_connection(self) -> Connection {
        self.conn
    }

    /// Items and dots per commit chunk (whole origins only).
    pub fn set_chunk_items(&mut self, n: usize) {
        self.chunk_items = n.max(1);
    }

    /// Marker writes this store performed (one per block of 64 seqs).
    pub fn marker_writes(&self) -> u64 {
        self.marker.writes
    }

    /// This database's identity against its directory's marker.
    pub fn marker_status(&self) -> Result<MarkerStatus, MeshError> {
        match &self.params.marker {
            None => Ok(MarkerStatus::Missing),
            Some(cfg) => marker::check(
                &cfg.data_dir,
                &self.m.self_id,
                &cfg.nonce,
                self.m.vv.get(&self.m.self_id),
            ),
        }
    }

    #[cfg(any(test, feature = "mesh-sim"))]
    pub fn hooks(&mut self) -> &mut TestHooks {
        &mut self.hooks
    }

    /// Speed over power-loss durability, for the simulator only: keeps
    /// `synchronous=FULL` but drops macOS's F_FULLFSYNC.
    #[cfg(any(test, feature = "mesh-sim"))]
    pub fn relax_fsync_for_tests(&self) -> Result<(), MeshError> {
        self.conn
            .pragma_update(None, "fullfsync", false)
            .map_err(sql("configuring durability"))
    }

    /// Reload the mirror from disk (after a failed write, or on demand).
    pub fn reload(&mut self) -> Result<(), MeshError> {
        let tx = begin(&self.conn, TransactionBehavior::Deferred)?;
        load(&tx, &mut self.m)?;
        tx.commit().map_err(sql("reading the mesh store"))
    }

    /// The views recomputed from `mesh_items` alone (`doctor --rebuild`,
    /// simulator invariant 3).
    pub fn rebuild_views(&self) -> Result<State, MeshError> {
        let mut state = State::new(self.m.genesis);
        for item in self.all_items()? {
            views::apply_stored(&mut state, &item)?;
        }
        Ok(state)
    }

    /// Fold the stored items of `kinds` into the views again. Items of a kind
    /// this build did not understand were stored opaquely (DESIGN §D6); after
    /// an upgrade, opening the store materializes every kind it now knows,
    /// and this re-applies the named ones in place. Applying is a join, so
    /// re-applying what is already there changes nothing.
    pub fn rematerialize(&mut self, kinds: &[&str]) -> Result<usize, MeshError> {
        let mut n = 0;
        for kind in kinds {
            let items: Vec<SignedItem> = {
                let mut st = self
                    .conn
                    .prepare_cached("SELECT bytes FROM mesh_items WHERE kind = ?1")
                    .map_err(sql("reading mesh_items"))?;
                let rows = st
                    .query_map([kind], |r| r.get::<_, Vec<u8>>(0))
                    .map_err(sql("reading mesh_items"))?;
                let mut out = Vec::new();
                for b in rows {
                    out.push(SignedItem::from_wire(
                        &b.map_err(sql("reading mesh_items"))?,
                    )?);
                }
                out
            };
            for item in &items {
                views::apply_stored(&mut self.m.state, item)?;
            }
            n += items.len();
        }
        Ok(n)
    }

    /// Every held item, in `(origin, seq, hash)` order.
    pub fn all_items(&self) -> Result<Vec<SignedItem>, MeshError> {
        let mut st = self
            .conn
            .prepare_cached("SELECT bytes FROM mesh_items ORDER BY origin, seq, hash")
            .map_err(sql("reading mesh_items"))?;
        let rows = st
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(sql("reading mesh_items"))?;
        let mut out = Vec::new();
        for b in rows {
            out.push(SignedItem::from_wire(
                &b.map_err(sql("reading mesh_items"))?,
            )?);
        }
        Ok(out)
    }

    pub fn holds(&self, hash: &ItemHash) -> Result<bool, MeshError> {
        self.conn
            .prepare_cached("SELECT 1 FROM mesh_items WHERE hash = ?1 LIMIT 1")
            .and_then(|mut st| st.exists([hash.0.as_slice()]))
            .map_err(sql("reading mesh_items"))
    }

    /// Held items per kind (`status`).
    pub fn items_by_kind(&self) -> Result<BTreeMap<String, u64>, MeshError> {
        let mut st = self
            .conn
            .prepare_cached("SELECT kind, COUNT(*) FROM mesh_items GROUP BY kind")
            .map_err(sql("reading mesh_items"))?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(sql("reading mesh_items"))?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (k, n) = row.map_err(sql("reading mesh_items"))?;
            out.insert(k, to_u64(n)?);
        }
        Ok(out)
    }

    /// Compare the mirror with a fresh load of the database: the VV, the
    /// views, the digests and the fork evidence must be identical.
    pub fn verify_against_disk(&self) -> Result<(), String> {
        let mut fresh = Mirror::new(
            self.m.genesis,
            self.m.self_id,
            Arc::new(super::clock::ManualClock::new(0)),
        );
        let tx = begin(&self.conn, TransactionBehavior::Deferred).map_err(|e| e.to_string())?;
        load(&tx, &mut fresh).map_err(|e| e.to_string())?;
        drop(tx);
        if fresh.vv != self.m.vv {
            return Err("the VV in memory differs from the database".into());
        }
        if fresh.state != self.m.state {
            return Err("the views in memory differ from the database".into());
        }
        let digest = |m: &Mirror, o: &DeviceId| {
            m.digests
                .get(o)
                .copied()
                .unwrap_or_else(|| Hash32::digest_of([]))
        };
        let origins: BTreeSet<&DeviceId> =
            fresh.digests.keys().chain(self.m.digests.keys()).collect();
        if origins
            .iter()
            .any(|o| digest(&fresh, o) != digest(&self.m, o))
        {
            return Err("an origin digest in memory differs from the database".into());
        }
        let set = |m: &Mirror| -> BTreeSet<(DeviceId, u64)> {
            m.stats
                .fork_evidence
                .iter()
                .map(|e| (e.origin, e.seq))
                .collect()
        };
        if set(&fresh) != set(&self.m) {
            return Err("fork evidence in memory differs from the database".into());
        }
        // The dot log is dense and its chain consistent up to every VV entry.
        for (o, top) in self.m.vv.iter() {
            let mut prev = Hash32::ZERO;
            for s in 1..=*top {
                let (Ok(Some(h)), Ok(Some(c))) =
                    (dot_hash_in(&self.conn, o, s), chain_in(&self.conn, o, s))
                else {
                    return Err(format!("the dot log of {o} has a gap at {s}"));
                };
                if prev.chain_next(&h) != c {
                    return Err(format!("the chain of {o} is inconsistent at {s}"));
                }
                prev = c;
            }
        }
        Ok(())
    }

    /// Whether an armed crash is due now that `committed` chunks are durable
    /// (disarms it when it fires or when the commit ends).
    #[cfg(any(test, feature = "mesh-sim"))]
    fn crash_due(&mut self, committed: usize) -> bool {
        match self.hooks.crash_after_chunks {
            Some(k) if k == committed || committed == usize::MAX => {
                self.hooks.crash_after_chunks = None;
                committed != usize::MAX
            }
            _ => false,
        }
    }

    #[cfg(not(any(test, feature = "mesh-sim")))]
    fn crash_due(&mut self, _committed: usize) -> bool {
        false
    }

    /// Run one write transaction against the mirror; on any error the
    /// transaction rolls back and the mirror is reloaded from disk.
    fn write<T>(
        &mut self,
        f: impl FnOnce(&Connection, &mut Mirror, &mut MarkerState) -> Result<T, MeshError>,
    ) -> Result<T, MeshError> {
        let result = (|| {
            let tx = begin(&self.conn, TransactionBehavior::Immediate)?;
            sync_generation(&tx, &mut self.m)?;
            let out = f(&tx, &mut self.m, &mut self.marker)?;
            finish(&tx, &mut self.m)?;
            tx.commit().map_err(sql("committing"))?;
            Ok(out)
        })();
        if result.is_err() {
            // The mirror may hold changes the database rolled back.
            let _ = self.reload();
        }
        result
    }

    fn commit_chunk(
        &mut self,
        chunk: Chunk,
        validate_all: Option<&[Chunk]>,
        out: &mut CommitOutcome,
    ) -> Result<(), MeshError> {
        #[cfg(any(test, feature = "mesh-sim"))]
        let fail_before_vv = std::mem::take(&mut self.hooks.fail_before_vv);
        #[cfg(not(any(test, feature = "mesh-sim")))]
        let fail_before_vv = false;
        self.write(|tx, m, _| {
            let now = m.hlc.clock().now_ms();
            if let Some(all) = validate_all {
                // The whole batch, before anything is written: an invalid
                // batch changes nothing (per-origin checks, so checking each
                // chunk against the same state is checking the batch).
                for c in all {
                    if let Chunk::Main(b) = c {
                        validate_commit(b, &m.vv, |o, s| dot_hash_in(tx, o, s))?;
                    }
                }
            }
            match chunk {
                Chunk::Main(batch) => {
                    // Re-validated in this transaction: another process may
                    // have written since the batch was checked.
                    let Validated { ranges, forks } =
                        validate_commit(&batch, &m.vv, |o, s| dot_hash_in(tx, o, s))?;
                    for ev in forks {
                        note_fork(tx, m, ev, now, out)?;
                    }
                    let hour = now / HOUR_MS;
                    for v in &batch.items {
                        let o = v.body.origin;
                        observe(m, &v.body);
                        let (changed, regression) = apply_entry(tx, m, v, now)?;
                        out.stored += usize::from(changed);
                        if regression {
                            out.regressions += 1;
                            *m.stats.regressions.entry(o).or_insert(0) += 1;
                        }
                        let r = m.rate.entry(o).or_insert((hour, 0));
                        if r.0 != hour {
                            *r = (hour, 0);
                        }
                        r.1 += 1;
                        m.dirty.insert(o);
                    }
                    if fail_before_vv {
                        return Err(MeshError::Storage("injected failure before the VV update"));
                    }
                    for (o, hashes) in ranges {
                        append_range(tx, m, &o, &hashes)?;
                    }
                }
                Chunk::Repair(items) => {
                    for v in &items {
                        let (o, s) = (v.body.origin, v.body.seq);
                        if let Some(ours) = dot_hash_in(tx, &o, s)? {
                            if ours != v.item.hash() {
                                let ev = ForkEvidence {
                                    origin: o,
                                    seq: s,
                                    ours,
                                    theirs: v.item.hash(),
                                };
                                note_fork(tx, m, ev, now, out)?;
                            }
                        }
                        observe(m, &v.body);
                        let (changed, regression) = apply_entry(tx, m, v, now)?;
                        if changed {
                            out.stored += 1;
                            if m.state.roster.fork_seq(&o).is_none() {
                                out.repairs_changed += 1;
                                m.stats.repairs_changed += 1;
                            }
                        }
                        if regression {
                            out.regressions += 1;
                            *m.stats.regressions.entry(o).or_insert(0) += 1;
                            m.dirty.insert(o);
                        }
                    }
                }
            }
            Ok(())
        })
    }
}

impl MeshStore for SqliteStore {
    fn genesis(&self) -> GenesisInfo {
        self.m.genesis
    }

    fn self_id(&self) -> DeviceId {
        self.m.self_id
    }

    fn vv(&self) -> &VersionVector {
        &self.m.vv
    }

    fn state(&self) -> &State {
        &self.m.state
    }

    fn stats(&self) -> &Stats {
        &self.m.stats
    }

    fn dot_hash(&self, origin: &DeviceId, seq: u64) -> Result<Option<ItemHash>, MeshError> {
        dot_hash_in(&self.conn, origin, seq)
    }

    fn dot_hashes(
        &self,
        origin: &DeviceId,
        from_exclusive: u64,
        to_inclusive: u64,
    ) -> Result<Vec<(u64, ItemHash)>, MeshError> {
        if to_inclusive <= from_exclusive {
            return Ok(Vec::new());
        }
        let mut st = self
            .conn
            .prepare_cached(
                "SELECT seq, hash FROM mesh_dots
                 WHERE origin = ?1 AND seq > ?2 AND seq <= ?3 ORDER BY seq",
            )
            .map_err(sql("reading the dot log"))?;
        let rows = st
            .query_map(
                params![origin.to_hex(), bound(from_exclusive), bound(to_inclusive)],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(sql("reading the dot log"))?;
        let mut out = Vec::new();
        for row in rows {
            let (s, h) = row.map_err(sql("reading the dot log"))?;
            out.push((to_u64(s)?, ItemHash(hash32(h)?)));
        }
        Ok(out)
    }

    fn chain_at(&self, origin: &DeviceId, seq: u64) -> Result<Option<Hash32>, MeshError> {
        chain_in(&self.conn, origin, seq)
    }

    fn origin_digest(&self, origin: &DeviceId) -> Hash32 {
        self.m
            .digests
            .get(origin)
            .copied()
            .unwrap_or_else(|| Hash32::digest_of([]))
    }

    fn held_items(
        &self,
        origin: &DeviceId,
        from_exclusive: u64,
        to_inclusive: u64,
    ) -> Result<Vec<SignedItem>, MeshError> {
        if to_inclusive <= from_exclusive {
            return Ok(Vec::new());
        }
        let mut st = self
            .conn
            .prepare_cached(
                "SELECT bytes FROM mesh_items
                 WHERE origin = ?1 AND seq > ?2 AND seq <= ?3 ORDER BY seq, hash",
            )
            .map_err(sql("reading held items"))?;
        let rows = st
            .query_map(
                params![origin.to_hex(), bound(from_exclusive), bound(to_inclusive)],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map_err(sql("reading held items"))?;
        let mut out = Vec::new();
        for b in rows {
            out.push(SignedItem::from_wire(
                &b.map_err(sql("reading held items"))?,
            )?);
        }
        Ok(out)
    }

    fn ingest_rate_used(&self, origin: &DeviceId) -> u64 {
        let hour = self.now_ms() / HOUR_MS;
        match self.m.rate.get(origin) {
            Some((h, n)) if *h == hour => *n,
            _ => 0,
        }
    }

    fn now_ms(&self) -> u64 {
        self.m.hlc.clock().now_ms()
    }

    fn hlc_last(&self) -> Hlc {
        self.m.hlc.last()
    }

    fn commit(&mut self, batch: CommitBatch) -> Result<CommitOutcome, MeshError> {
        let chunks = plan_chunks(batch, self.chunk_items);
        let mut out = CommitOutcome::default();
        let mut pending = chunks.into_iter().enumerate().peekable();
        let mut rest: Vec<Chunk> = Vec::new();
        // The first chunk validates the whole batch; it needs to see the
        // others, so they are moved aside first.
        let Some((_, first)) = pending.next() else {
            return Ok(out);
        };
        rest.extend(pending.map(|(_, c)| c));
        self.commit_chunk(first, Some(&rest), &mut out)?;
        for (i, chunk) in rest.into_iter().enumerate() {
            if self.crash_due(i + 1) {
                return Err(MeshError::Storage(SIMULATED_CRASH));
            }
            self.commit_chunk(chunk, None, &mut out)?;
        }
        self.crash_due(usize::MAX);
        Ok(out)
    }

    fn mint(&mut self, key: &SigningKeyPair, draft: Draft) -> Result<SignedItem, MeshError> {
        #[cfg(any(test, feature = "mesh-sim"))]
        let fail = std::mem::take(&mut self.hooks.fail_mint_commit);
        #[cfg(not(any(test, feature = "mesh-sim")))]
        let fail = false;
        self.write(|tx, m, marker| {
            let item = mint_in(tx, m, marker, key, draft)?;
            if fail {
                return Err(MeshError::Storage(
                    "injected failure before the mint commits",
                ));
            }
            Ok(item)
        })
    }

    fn record_rejected(&mut self, n: u64) {
        if n == 0 {
            return;
        }
        self.m.stats.rejected_items += n;
        // A counter, not state: an atomic increment, no generation bump.
        let _ = self
            .conn
            .prepare_cached(
                "INSERT INTO mesh_meta (key, value) VALUES ('rejected_items', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = value + excluded.value",
            )
            .and_then(|mut st| st.execute([n.min(i64::MAX as u64) as i64]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::mesh::clock::ManualClock;
    use crate::mesh::codec::ItemBody;
    use crate::mesh::dot::{CapId, MeshId, MeshProjectId};
    use crate::mesh::kinds::{
        CapDef, Day, ForkReport, ItemKind, MeshSetting, ProjectMeta, RosterAdd, RosterRemove,
        UsageCounter, UsageKey, UsageTotals,
    };
    use crate::mesh::marker::MarkerStatus;
    use crate::mesh::proto::{Action, Frame, Limits, Session};
    use crate::mesh::sign::{derive_device_id, PublicKeyBytes};
    use crate::mesh::sim::rng::SplitMix64;
    use serde_json::json;
    use std::path::Path;

    const T0: u64 = 1_700_000_000_000;

    struct Dev {
        key: SigningKeyPair,
        id: DeviceId,
        store: SqliteStore,
        dir: PathBuf,
    }

    fn keys(seed: u8) -> (SigningKeyPair, DeviceId) {
        let key = SigningKeyPair::from_secret_bytes(&[seed; 32]);
        let id = derive_device_id(
            &key.public_key(),
            &PublicKeyBytes([seed; 32]),
            &PublicKeyBytes([seed ^ 0x55; 32]),
        );
        (key, id)
    }

    fn params(dir: &Path, g: GenesisInfo, id: DeviceId, nonce: u8) -> StoreParams {
        StoreParams {
            genesis: g,
            self_id: id,
            marker: Some(MarkerConfig {
                data_dir: dir.to_path_buf(),
                nonce: MarkerNonce::from_bytes([nonce; 16]),
            }),
        }
    }

    fn open_at(dir: &Path, p: StoreParams) -> SqliteStore {
        let conn = db::open(&dir.join("vault.db")).unwrap();
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(T0));
        SqliteStore::open(conn, p, clock).unwrap()
    }

    /// A device in its own directory, with the marker identity creation
    /// writes (mark 0).
    fn dev(root: &Path, seed: u8, genesis: Option<GenesisInfo>) -> Dev {
        let (key, id) = keys(seed);
        let g = genesis.unwrap_or(GenesisInfo {
            mesh_id: MeshId::from_bytes([7; 16]),
            genesis: id,
        });
        let dir = root.join(format!("dev-{seed}"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut conn = db::open(&dir.join("vault.db")).unwrap();
        db::migrate(&mut conn).unwrap();
        drop(conn);
        let p = params(&dir, g, id, seed);
        marker::write(
            &dir,
            &MarkerContents::new(id, MarkerNonce::from_bytes([seed; 16]), 0),
        )
        .unwrap();
        let store = open_at(&dir, p);
        store.relax_fsync_for_tests().unwrap();
        Dev {
            key,
            id,
            store,
            dir,
        }
    }

    fn add(by: &mut Dev, seed: u8) {
        let (k, id) = keys(seed);
        let a = RosterAdd {
            device: id,
            name: format!("dev {seed}"),
            sign_pub: k.public_key(),
            noise_pub: PublicKeyBytes([seed; 32]),
            seal_pub: PublicKeyBytes([seed ^ 0x55; 32]),
            added_by: by.id,
        };
        by.store
            .mint(&by.key, Draft::of(&a, HlcPolicy::Now))
            .unwrap();
    }

    fn setting(d: &mut Dev, name: &str, v: u64) -> SignedItem {
        let m = MeshSetting {
            name: name.into(),
            value: json!(v),
        };
        d.store
            .mint(&d.key, Draft::of(&m, HlcPolicy::After(None)))
            .unwrap()
    }

    /// A genesis device that added itself and a second device.
    fn pair(root: &Path) -> (Dev, Dev) {
        let mut g = dev(root, 1, None);
        let b = dev(root, 2, Some(g.store.genesis()));
        add(&mut g, 1);
        add(&mut g, 2);
        (g, b)
    }

    /// One complete session between `a` and `b`, applying commits.
    fn exchange(a: &mut Dev, b: &mut Dev) {
        let mut sa = Session::new(Limits::default(), Some(b.id));
        let mut sb = Session::new(Limits::default(), Some(a.id));
        let mut to_b: Vec<Frame> = Vec::new();
        let mut to_a: Vec<Frame> = Vec::new();
        let route = |acts: Vec<Action>, out: &mut Vec<Frame>, store: &mut SqliteStore| {
            for act in acts {
                match act {
                    Action::Send(f) => out.push(f),
                    Action::Commit(batch) => {
                        store.commit(batch).unwrap();
                    }
                    _ => {}
                }
            }
        };
        let acts = sa.start(&a.store);
        route(acts, &mut to_b, &mut a.store);
        let acts = sb.start(&b.store);
        route(acts, &mut to_a, &mut b.store);
        for _ in 0..1000 {
            if to_a.is_empty() && to_b.is_empty() {
                break;
            }
            for f in std::mem::take(&mut to_b) {
                let acts = sb.on_frame(f, &b.store);
                route(acts, &mut to_a, &mut b.store);
            }
            for f in std::mem::take(&mut to_a) {
                let acts = sa.on_frame(f, &a.store);
                route(acts, &mut to_b, &mut a.store);
            }
        }
    }

    /// The batch `b` would commit from `a` (one session, commit not applied).
    fn batch_from(a: &Dev, b: &Dev) -> CommitBatch {
        let mut sa = Session::new(Limits::default(), Some(b.id));
        let mut sb = Session::new(Limits::default(), Some(a.id));
        let mut to_b: Vec<Frame> = Vec::new();
        for act in sa.start(&a.store) {
            if let Action::Send(f) = act {
                to_b.push(f);
            }
        }
        let mut to_a: Vec<Frame> = sb
            .start(&b.store)
            .into_iter()
            .filter_map(|x| match x {
                Action::Send(f) => Some(f),
                _ => None,
            })
            .collect();
        for _ in 0..100 {
            for f in std::mem::take(&mut to_a) {
                for act in sa.on_frame(f, &a.store) {
                    if let Action::Send(f) = act {
                        to_b.push(f);
                    }
                }
            }
            for f in std::mem::take(&mut to_b) {
                for act in sb.on_frame(f, &b.store) {
                    match act {
                        Action::Commit(batch) => return batch,
                        Action::Send(f) => to_a.push(f),
                        _ => {}
                    }
                }
            }
        }
        panic!("no commit");
    }

    fn rows(s: &SqliteStore, table: &str) -> i64 {
        s.connection()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn a_failure_between_the_item_insert_and_the_vv_update_leaves_nothing() {
        let root = tempfile::tempdir().unwrap();
        let (mut g, mut b) = pair(root.path());
        for i in 0..10 {
            setting(&mut g, &format!("s{i}"), i);
        }
        let batch = batch_from(&g, &b);
        let before = (b.store.vv().clone(), b.store.state().clone());
        let (items, dots) = (rows(&b.store, "mesh_items"), rows(&b.store, "mesh_dots"));
        b.store.hooks().fail_before_vv = true;
        let err = b.store.commit(batch.clone()).unwrap_err();
        assert_eq!(
            err,
            MeshError::Storage("injected failure before the VV update")
        );
        // Nothing is visible: not on disk, not in memory.
        assert_eq!(rows(&b.store, "mesh_items"), items);
        assert_eq!(rows(&b.store, "mesh_dots"), dots);
        assert_eq!(rows(&b.store, "mesh_vv"), 0);
        assert_eq!((b.store.vv().clone(), b.store.state().clone()), before);
        b.store.verify_against_disk().unwrap();
        // The same batch then commits normally.
        b.store.commit(batch).unwrap();
        assert_eq!(b.store.vv(), g.store.vv());
        assert_eq!(b.store.state().expected(), g.store.state().expected());
        b.store.verify_against_disk().unwrap();
    }

    #[test]
    fn a_crash_between_chunks_keeps_whole_origins_only() {
        let root = tempfile::tempdir().unwrap();
        let (mut g, mut b) = pair(root.path());
        let mut c = dev(root.path(), 3, Some(g.store.genesis()));
        add(&mut g, 3);
        exchange(&mut g, &mut c);
        for i in 0..5 {
            setting(&mut g, &format!("g{i}"), i);
            setting(&mut c, &format!("c{i}"), i);
        }
        exchange(&mut g, &mut c);
        let batch = batch_from(&g, &b);
        b.store.set_chunk_items(1);
        b.store.hooks().crash_after_chunks = Some(1);
        let err = b.store.commit(batch).unwrap_err();
        assert_eq!(err, MeshError::Storage(SIMULATED_CRASH));
        // One origin made it, whole; the other is untouched.
        let origins: Vec<u64> = [g.id, c.id].iter().map(|o| b.store.vv().get(o)).collect();
        assert!(
            origins.contains(&0) && origins.iter().any(|s| *s > 0),
            "{origins:?}"
        );
        b.store.verify_against_disk().unwrap();
        // Reopen from disk, then finish with an ordinary session.
        let p = b.store.params().clone();
        b.store = open_at(&b.dir, p);
        b.store.verify_against_disk().unwrap();
        exchange(&mut g, &mut b);
        assert_eq!(b.store.vv(), g.store.vv());
        assert_eq!(b.store.state().expected(), g.store.state().expected());
    }

    #[test]
    fn a_second_hash_for_a_logged_dot_is_recorded_as_fork_evidence() {
        let root = tempfile::tempdir().unwrap();
        let (mut g, mut b) = pair(root.path());
        setting(&mut g, "x", 1);
        exchange(&mut g, &mut b);
        let top = g.store.vv().get(&g.id);
        // A second branch of g at its last seq (a clone of g minted it).
        let body = MeshSetting {
            name: "x".into(),
            value: json!(2),
        }
        .to_body(g.store.genesis().mesh_id, g.id, top, Hlc::new(T0, 9));
        let other = SignedItem::sign(&body, &g.key).unwrap();
        let typed = TypedItem::parse(&body).unwrap();
        let mut upto = VersionVector::new();
        upto.advance_to(g.id, top);
        let out = b
            .store
            .commit(CommitBatch {
                items: vec![VerifiedItem {
                    item: other.clone(),
                    body,
                    typed,
                }],
                dots: vec![],
                upto,
                repair: vec![],
            })
            .unwrap();
        assert_eq!(out.forks.len(), 1);
        let ev = out.forks[0];
        assert_eq!((ev.origin, ev.seq, ev.theirs), (g.id, top, other.hash()));
        assert_eq!(rows(&b.store, "mesh_fork_evidence"), 1);
        // The log was not extended or rewritten.
        assert_eq!(b.store.vv().get(&g.id), top);
        assert_eq!(b.store.dot_hash(&g.id, top).unwrap(), Some(ev.ours));
        // The evidence survives a reopen.
        let p = b.store.params().clone();
        b.store = open_at(&b.dir, p);
        assert_eq!(b.store.stats().fork_evidence, vec![ev]);
    }

    #[test]
    fn only_the_latest_item_per_key_is_held_and_removal_deletes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let (mut g, mut b) = pair(root.path());
        let project = MeshProjectId::from_bytes([3; 16]);
        for name in ["one", "two", "three"] {
            let p = ProjectMeta {
                project,
                name: name.into(),
                archived: false,
                merged_into: None,
            };
            b.store
                .mint(&b.key, Draft::of(&p, HlcPolicy::After(None)))
                .ok();
        }
        // b is not a member of its own store yet: exchange first.
        exchange(&mut g, &mut b);
        for name in ["one", "two", "three"] {
            let p = ProjectMeta {
                project,
                name: name.into(),
                archived: false,
                merged_into: None,
            };
            b.store
                .mint(&b.key, Draft::of(&p, HlcPolicy::After(None)))
                .unwrap();
        }
        let cap = CapDef {
            cap: CapId::from_bytes([4; 16]),
            mesh_project_id: project,
            owner_device: b.id,
            created_hlc: Hlc::new(T0, 0),
        };
        b.store
            .mint(&b.key, Draft::of(&cap, HlcPolicy::Now))
            .unwrap();
        exchange(&mut g, &mut b);
        let held = |s: &SqliteStore, kind: &str| -> i64 {
            s.connection()
                .query_row(
                    "SELECT COUNT(*) FROM mesh_items WHERE kind = ?1",
                    [kind],
                    |r| r.get(0),
                )
                .unwrap()
        };
        // Three project.meta writes by b for one key: one row.
        assert_eq!(held(&g.store, "project.meta"), 1);
        assert_eq!(held(&b.store, "project.meta"), 1);
        // Removing b keeps every item of b: its roster.add, its cap.def, its
        // project.meta (relayed, excluded from views by the cutoff).
        let roster_rows = held(&g.store, "roster.add");
        let r = RosterRemove {
            device: b.id,
            cutoff_seq: 1,
        };
        g.store.mint(&g.key, Draft::of(&r, HlcPolicy::Now)).unwrap();
        assert_eq!(held(&g.store, "roster.add"), roster_rows);
        assert_eq!(held(&g.store, "cap.def"), 1);
        assert_eq!(held(&g.store, "project.meta"), 1);
        assert!(g.store.state().roster.is_removed(&b.id));
        assert!(g
            .store
            .state()
            .projects
            .value(&project, &g.store.state().roster)
            .is_none());
        g.store.verify_against_disk().unwrap();
    }

    #[test]
    fn incremental_views_equal_a_rebuild_after_random_workloads() {
        let root = tempfile::tempdir().unwrap();
        let (mut g, mut b) = pair(root.path());
        exchange(&mut g, &mut b);
        let mut rng = SplitMix64::new(0x5EED);
        let projects: Vec<MeshProjectId> = (0..3)
            .map(|i| MeshProjectId::from_bytes([i + 10; 16]))
            .collect();
        for step in 0..300 {
            let d = if rng.bool() { &mut g } else { &mut b };
            match rng.below(4) {
                0 => {
                    setting(d, &format!("s{}", rng.below(4)), rng.below(100));
                }
                1 => {
                    let p = ProjectMeta {
                        project: *rng.choose(&projects).unwrap(),
                        name: format!("p{}", rng.below(9)),
                        archived: rng.chance(1, 4),
                        merged_into: None,
                    };
                    d.store
                        .mint(&d.key, Draft::of(&p, HlcPolicy::After(None)))
                        .unwrap();
                }
                2 => {
                    let key = UsageKey {
                        project: *rng.choose(&projects).unwrap(),
                        day: Day::parse("2026-10-27").unwrap(),
                        provider: "openai".into(),
                        model: "gpt-x".into(),
                    };
                    let me = d.id;
                    let cur = d.store.state().usage.get(&key, &me).map(|e| e.value.totals);
                    let mut t = cur.unwrap_or_default();
                    t.requests += 1 + rng.below(3);
                    let u = UsageCounter {
                        key,
                        epoch: 0,
                        totals: UsageTotals { ..t },
                    };
                    d.store.mint(&d.key, Draft::of(&u, HlcPolicy::Now)).unwrap();
                }
                _ => exchange(&mut g, &mut b),
            }
            if step % 50 == 0 {
                for s in [&g.store, &b.store] {
                    assert_eq!(&s.rebuild_views().unwrap(), s.state());
                    s.verify_against_disk().unwrap();
                }
            }
        }
        exchange(&mut g, &mut b);
        assert_eq!(g.store.state().expected(), b.store.state().expected());
        for s in [&g.store, &b.store] {
            assert_eq!(&s.rebuild_views().unwrap(), s.state());
            s.verify_against_disk().unwrap();
        }
    }

    #[test]
    fn unknown_kinds_are_stored_and_relayed_opaquely_then_rematerialized() {
        let root = tempfile::tempdir().unwrap();
        let (mut g, mut b) = pair(root.path());
        // An item of a kind this build does not know, from g.
        let top = g.store.vv().get(&g.id);
        let body = ItemBody::new(
            g.store.genesis().mesh_id,
            g.id,
            top + 1,
            Hlc::new(T0, 1),
            "zz.future",
            "k",
            json!({"anything": [1, 2, 3]}),
        );
        let unknown = SignedItem::sign(&body, &g.key).unwrap();
        let typed = TypedItem::parse(&body).unwrap();
        assert!(matches!(typed, TypedItem::Unknown));
        let mut upto = VersionVector::new();
        upto.advance_to(g.id, top + 1);
        g.store
            .commit(CommitBatch {
                items: vec![VerifiedItem {
                    item: unknown.clone(),
                    body,
                    typed,
                }],
                dots: vec![],
                upto,
                repair: vec![],
            })
            .unwrap();
        let state_before = g.store.state().clone();
        assert!(g.store.holds(&unknown.hash()).unwrap());
        // It is relayed to b byte for byte, and changes no view.
        exchange(&mut g, &mut b);
        assert!(b.store.holds(&unknown.hash()).unwrap());
        let relayed = b.store.held_items(&g.id, top, top + 1).unwrap();
        assert_eq!(relayed[0].to_wire(), unknown.to_wire());
        assert_eq!(g.store.state(), &state_before);
        assert_eq!(b.store.items_by_kind().unwrap().get("zz.future"), Some(&1));

        // Rematerializing: a build that did not understand `mesh.setting`
        // would have stored settings opaquely; folding the stored items of
        // that kind in brings the views to what a full rebuild gives.
        setting(&mut g, "retention_days", 30);
        let full = g.store.state().clone();
        g.store.m.state.settings = Default::default();
        assert_ne!(g.store.state(), &full);
        assert_eq!(g.store.rematerialize(&["mesh.setting"]).unwrap(), 1);
        assert_eq!(g.store.state(), &full);
        assert_eq!(g.store.rematerialize(&["zz.future"]).unwrap(), 1);
        assert_eq!(
            g.store.state(),
            &full,
            "an unknown kind still changes nothing"
        );
    }

    #[test]
    fn the_marker_is_advanced_one_block_ahead_and_durably_before_its_first_seq() {
        let root = tempfile::tempdir().unwrap();
        let mut g = dev(root.path(), 1, None);
        add(&mut g, 1);
        assert_eq!(g.store.marker_writes(), 1, "seq 1 needed the first block");
        assert_eq!(marker::read(&g.dir).unwrap().unwrap().seq_high_water, 64);
        for i in 2..=64 {
            setting(&mut g, "s", i);
        }
        assert_eq!(g.store.marker_writes(), 1, "seqs 2-64 are in that block");
        // Seq 65 needs the next block: the marker is written first, so even
        // when the mint itself fails, the mark already covers it.
        g.store.hooks().fail_mint_commit = true;
        let m = MeshSetting {
            name: "s".into(),
            value: json!(65),
        };
        assert!(g
            .store
            .mint(&g.key, Draft::of(&m, HlcPolicy::After(None)))
            .is_err());
        assert_eq!(g.store.marker_writes(), 2);
        assert_eq!(marker::read(&g.dir).unwrap().unwrap().seq_high_water, 128);
        assert_eq!(g.store.vv().get(&g.id), 64, "the failed mint left nothing");
        assert_eq!(g.store.marker_status().unwrap(), MarkerStatus::Ok);
        g.store
            .mint(&g.key, Draft::of(&m, HlcPolicy::After(None)))
            .unwrap();
        assert_eq!(g.store.marker_writes(), 2, "the retry reuses the block");
        assert_eq!(g.store.vv().get(&g.id), 65);
    }

    #[test]
    fn copies_and_rollbacks_are_detected_and_refuse_to_mint() {
        let root = tempfile::tempdir().unwrap();
        let mut g = dev(root.path(), 1, None);
        add(&mut g, 1);
        setting(&mut g, "s", 1);
        let db_file = g.dir.join("vault.db");
        g.store
            .connection()
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .unwrap();
        let snapshot = root.path().join("old.db");
        std::fs::copy(&db_file, &snapshot).unwrap();
        let p = g.store.params().clone();

        // Missing: the database copied into a directory with no marker.
        let copy = root.path().join("copy");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::copy(&snapshot, copy.join("vault.db")).unwrap();
        let mut cp = p.clone();
        cp.marker.as_mut().unwrap().data_dir = copy.clone();
        let mut copied = open_at(&copy, cp.clone());
        assert_eq!(copied.marker_status().unwrap(), MarkerStatus::Missing);
        let m = MeshSetting {
            name: "s".into(),
            value: json!(2),
        };
        assert!(matches!(
            copied.mint(&g.key, Draft::of(&m, HlcPolicy::After(None))),
            Err(MeshError::IdentityMismatch(_))
        ));

        // Mismatch: the copy's directory holds another identity's marker.
        marker::write(
            &copy,
            &MarkerContents::new(
                DeviceId::from_bytes([9; 16]),
                MarkerNonce::from_bytes([9; 16]),
                64,
            ),
        )
        .unwrap();
        assert_eq!(copied.marker_status().unwrap(), MarkerStatus::Mismatch);
        assert!(copied
            .mint(&g.key, Draft::of(&m, HlcPolicy::After(None)))
            .is_err());
        assert!(crate::mesh::identity::preflight(&copied).is_err());

        // Rolled back: the original keeps minting past two blocks, then its
        // database is replaced by the old copy.
        for i in 0..140 {
            setting(&mut g, "s", i);
        }
        assert!(marker::read(&g.dir).unwrap().unwrap().seq_high_water > 64 + 64);
        drop(g.store);
        for side in ["vault.db-wal", "vault.db-shm"] {
            let _ = std::fs::remove_file(g.dir.join(side));
        }
        std::fs::copy(&snapshot, &db_file).unwrap();
        let mut back = open_at(&g.dir, p);
        assert_eq!(back.marker_status().unwrap(), MarkerStatus::RolledBack);
        // Its next seq (3) is far below the mark; it must still refuse.
        assert!(matches!(
            back.mint(&g.key, Draft::of(&m, HlcPolicy::After(None))),
            Err(MeshError::IdentityMismatch(_))
        ));
        assert!(crate::mesh::identity::preflight(&back).is_err());
    }

    #[test]
    fn two_stores_on_one_database_never_reuse_a_seq() {
        let root = tempfile::tempdir().unwrap();
        let mut g = dev(root.path(), 1, None);
        add(&mut g, 1);
        let p = g.store.params().clone();
        let mut second = open_at(&g.dir, p);
        // The node (g.store) and a CLI command (second) mint in turn.
        let a = setting(&mut g, "a", 1);
        let m = MeshSetting {
            name: "b".into(),
            value: json!(2),
        };
        let b = second
            .mint(&g.key, Draft::of(&m, HlcPolicy::After(None)))
            .unwrap();
        let c = setting(&mut g, "c", 3);
        let seqs: Vec<u64> = [&a, &b, &c]
            .iter()
            .map(|i| i.decode_unverified().unwrap().seq)
            .collect();
        assert_eq!(seqs, vec![2, 3, 4]);
        g.store.verify_against_disk().unwrap();
        // `second` catches up on its next write or reload.
        second.reload().unwrap();
        assert_eq!(second.vv(), g.store.vv());
        assert_eq!(second.state(), g.store.state());
    }

    #[test]
    fn a_reopened_store_is_the_same_store() {
        let root = tempfile::tempdir().unwrap();
        let (mut g, mut b) = pair(root.path());
        for i in 0..20 {
            setting(&mut g, &format!("k{}", i % 5), i);
        }
        exchange(&mut g, &mut b);
        b.store.record_rejected(3);
        let before = (
            b.store.vv().clone(),
            b.store.state().clone(),
            b.store.hlc_last(),
            b.store.origin_digest(&g.id),
            b.store.ingest_rate_used(&g.id),
        );
        let p = b.store.params().clone();
        b.store = open_at(&b.dir, p);
        let after = (
            b.store.vv().clone(),
            b.store.state().clone(),
            b.store.hlc_last(),
            b.store.origin_digest(&g.id),
            b.store.ingest_rate_used(&g.id),
        );
        assert_eq!(before, after);
        assert_eq!(b.store.stats().rejected_items, 3);
    }

    #[test]
    fn a_device_reported_forked_does_not_pass_preflight() {
        let root = tempfile::tempdir().unwrap();
        let (mut g, mut b) = pair(root.path());
        exchange(&mut g, &mut b);
        assert!(crate::mesh::identity::preflight(&b.store).is_ok());
        let h = b.store.dot_hash(&g.id, 1).unwrap().unwrap();
        let report = ForkReport {
            device: b.id,
            seq: 1,
            hash_a: h,
            hash_b: ItemHash([1; 32]),
        };
        g.store
            .mint(&g.key, Draft::of(&report, HlcPolicy::Now))
            .unwrap();
        exchange(&mut g, &mut b);
        assert_eq!(
            crate::mesh::identity::preflight(&b.store),
            Err(MeshError::Forked)
        );
    }
}
