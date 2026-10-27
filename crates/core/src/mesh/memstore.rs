//! An in-memory [`MeshStore`] (Increment 02): what the simulator runs every
//! device on, and the reference the SQLite store must match (Increment 03).
//!
//! Atomicity: [`MemStore::commit`] validates the whole batch before it
//! changes anything; after validation nothing can fail, so a rejected commit
//! leaves the store exactly as it was.

use super::chain::Hash32;
use super::clock::Clock;
use super::codec::ItemBody;
use super::dot::DeviceId;
use super::error::MeshError;
use super::hlc::{Hlc, HlcClock};
use super::item::{ItemHash, SignedItem};
use super::kinds::TypedItem;
use super::sign::SigningKeyPair;
use super::store::{
    CommitBatch, CommitOutcome, Draft, ForkEvidence, GenesisInfo, HlcPolicy, MeshStore, Stats,
    VerifiedItem,
};
use super::views::{self, State};
use super::vv::VersionVector;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

const HOUR_MS: u64 = 3_600_000;

#[derive(Clone)]
pub struct MemStore {
    genesis: GenesisInfo,
    self_id: DeviceId,
    vv: VersionVector,
    /// Per origin, `(hash, chain)` for seq 1, 2, … (index = seq − 1).
    dots: BTreeMap<DeviceId, Vec<(ItemHash, Hash32)>>,
    /// Held items by `(origin, seq, hash)` — a fork can put two at one dot.
    held: BTreeMap<(DeviceId, u64, ItemHash), SignedItem>,
    /// The held entry for each `(kind, key, origin)`.
    latest: HashMap<(String, String, DeviceId), (u64, ItemHash)>,
    state: State,
    stats: Stats,
    hlc: HlcClock<Arc<dyn Clock>>,
    /// Items accepted per origin in the current hour: `(hour, count)`.
    rate: BTreeMap<DeviceId, (u64, u64)>,
}

impl MemStore {
    pub fn new(genesis: GenesisInfo, self_id: DeviceId, clock: Arc<dyn Clock>) -> Self {
        Self {
            genesis,
            self_id,
            vv: VersionVector::new(),
            dots: BTreeMap::new(),
            held: BTreeMap::new(),
            latest: HashMap::new(),
            state: State::new(genesis),
            stats: Stats::default(),
            hlc: HlcClock::new(clock),
            rate: BTreeMap::new(),
        }
    }

    /// A byte-for-byte copy running on another clock: what copying a data
    /// directory produces (the simulator's fork injection).
    pub fn clone_onto(&self, clock: Arc<dyn Clock>) -> Self {
        let mut copy = self.clone();
        let last = copy.hlc.last();
        copy.hlc = HlcClock::new(clock);
        copy.hlc.restore(last);
        copy
    }

    /// A restart: the clock is rebuilt and restored from the high-water mark.
    pub fn restart(&mut self, clock: Arc<dyn Clock>) {
        let last = self.hlc.last();
        self.hlc = HlcClock::new(clock);
        self.hlc.restore(last);
    }

    /// Every held item (for `views::rebuild` and invariant checks).
    pub fn all_items(&self) -> impl Iterator<Item = &SignedItem> {
        self.held.values()
    }

    pub fn holds(&self, hash: &ItemHash) -> bool {
        self.held.keys().any(|(_, _, h)| h == hash)
    }

    /// The views recomputed from the held items (simulator invariant 3).
    pub fn rebuild_views(&self) -> Result<State, MeshError> {
        views::rebuild(self.genesis, self.held.values())
    }

    fn entry_key(body: &ItemBody) -> (String, String, DeviceId) {
        (body.kind.clone(), body.key.clone(), body.origin)
    }

    /// Make `v` the held entry for its `(kind, key, origin)` if it supersedes
    /// the current one. Returns `(changed, regression)`.
    fn apply_entry(&mut self, v: &VerifiedItem) -> (bool, bool) {
        let key = Self::entry_key(&v.body);
        let new = (v.body.seq, v.item.hash());
        if let Some(old) = self.latest.get(&key).copied() {
            if old >= new {
                return (false, false);
            }
            self.held.remove(&(v.body.origin, old.0, old.1));
        }
        self.latest.insert(key, new);
        self.held
            .insert((v.body.origin, new.0, new.1), v.item.clone());
        let out = self.state.apply(&v.body, new.1, &v.typed);
        (true, out.regression)
    }

    fn push_dot(&mut self, origin: DeviceId, hash: ItemHash) {
        let log = self.dots.entry(origin).or_default();
        let prev = log.last().map_or(Hash32::ZERO, |(_, c)| *c);
        log.push((hash, prev.chain_next(&hash)));
    }

    fn note_fork(&mut self, ev: ForkEvidence, out: &mut CommitOutcome) {
        if !self
            .stats
            .fork_evidence
            .iter()
            .any(|e| e.origin == ev.origin && e.seq == ev.seq)
        {
            self.stats.fork_evidence.push(ev);
        }
        out.forks.push(ev);
    }

    fn observe(&mut self, body: &ItemBody) {
        let obs = self.hlc.observe(body.hlc);
        if obs.clamped {
            let e = self.stats.clock_skew.entry(body.origin).or_insert(0);
            *e = (*e).max(obs.skew_ms);
        }
    }

    /// Check a batch without changing anything. Returns the dot hashes to
    /// append for each origin whose committed range extends its log, and the
    /// forks the batch proves.
    ///
    /// Every hash the batch carries for a dot this store has already logged
    /// is compared with the log — items **and** dots. Another session may have
    /// extended the log since this one's `Hello` was compared, so a mismatch
    /// here is the last chance to see a second branch before it is appended
    /// on top of the first (PROTOCOL.md §7.2). Such an origin's log is not
    /// extended by this commit; its items still apply as entries, as repair
    /// would apply them.
    fn validate(&self, batch: &CommitBatch) -> Result<Validated, MeshError> {
        let mut incoming: BTreeMap<DeviceId, BTreeMap<u64, ItemHash>> = BTreeMap::new();
        let mut put = |o: DeviceId, s: u64, h: ItemHash| -> Result<(), MeshError> {
            match incoming.entry(o).or_default().insert(s, h) {
                Some(prev) if prev != h => Err(MeshError::InvalidOperation(
                    "commit carries two hashes for one dot",
                )),
                _ => Ok(()),
            }
        };
        for v in &batch.items {
            let (o, s) = (v.body.origin, v.body.seq);
            if s > self.vv.get(&o) && s > batch.upto.get(&o) {
                return Err(MeshError::InvalidOperation(
                    "commit item lies beyond its origin's committed range",
                ));
            }
            put(o, s, v.item.hash())?;
        }
        for (o, s, h) in &batch.dots {
            if *s >= 1 && *s <= batch.upto.get(o).max(self.vv.get(o)) {
                put(*o, *s, *h)?;
            }
        }
        let mut out = Validated::default();
        for (o, hashes) in &incoming {
            let cur = self.vv.get(o);
            for (s, h) in hashes.range(..=cur) {
                if let Some(ours) = self.dot_hash(o, *s) {
                    if ours != *h {
                        out.forks.push(ForkEvidence {
                            origin: *o,
                            seq: *s,
                            ours,
                            theirs: *h,
                        });
                        break;
                    }
                }
            }
        }
        for (o, upto) in batch.upto.iter() {
            let cur = self.vv.get(o);
            if *upto <= cur || out.forks.iter().any(|f| f.origin == *o) {
                continue;
            }
            let have = incoming.get(o);
            let mut hashes = Vec::with_capacity((*upto - cur) as usize);
            for s in cur + 1..=*upto {
                match have.and_then(|m| m.get(&s)) {
                    Some(h) => hashes.push(*h),
                    None => {
                        return Err(MeshError::InvalidOperation(
                            "commit is missing a dot in its range",
                        ))
                    }
                }
            }
            out.ranges.insert(*o, hashes);
        }
        Ok(out)
    }
}

#[derive(Default)]
struct Validated {
    ranges: BTreeMap<DeviceId, Vec<ItemHash>>,
    forks: Vec<ForkEvidence>,
}

impl MeshStore for MemStore {
    fn genesis(&self) -> GenesisInfo {
        self.genesis
    }

    fn self_id(&self) -> DeviceId {
        self.self_id
    }

    fn vv(&self) -> &VersionVector {
        &self.vv
    }

    fn state(&self) -> &State {
        &self.state
    }

    fn stats(&self) -> &Stats {
        &self.stats
    }

    fn dot_hash(&self, origin: &DeviceId, seq: u64) -> Option<ItemHash> {
        let i = usize::try_from(seq.checked_sub(1)?).ok()?;
        self.dots.get(origin)?.get(i).map(|(h, _)| *h)
    }

    fn chain_at(&self, origin: &DeviceId, seq: u64) -> Option<Hash32> {
        if seq == 0 {
            return Some(Hash32::ZERO);
        }
        let i = usize::try_from(seq - 1).ok()?;
        self.dots.get(origin)?.get(i).map(|(_, c)| *c)
    }

    fn origin_digest(&self, origin: &DeviceId) -> Hash32 {
        Hash32::digest_of(
            self.held
                .range((*origin, 0, ItemHash([0; 32]))..=(*origin, u64::MAX, ItemHash([0xff; 32])))
                .map(|((_, _, h), _)| *h),
        )
    }

    fn held_items(
        &self,
        origin: &DeviceId,
        from_exclusive: u64,
        to_inclusive: u64,
    ) -> Vec<SignedItem> {
        if to_inclusive <= from_exclusive {
            return Vec::new();
        }
        self.held
            .range(
                (*origin, from_exclusive + 1, ItemHash([0; 32]))
                    ..=(*origin, to_inclusive, ItemHash([0xff; 32])),
            )
            .map(|(_, i)| i.clone())
            .collect()
    }

    fn ingest_rate_used(&self, origin: &DeviceId) -> u64 {
        let hour = self.now_ms() / HOUR_MS;
        match self.rate.get(origin) {
            Some((h, n)) if *h == hour => *n,
            _ => 0,
        }
    }

    fn now_ms(&self) -> u64 {
        self.hlc.clock().now_ms()
    }

    fn hlc_last(&self) -> Hlc {
        self.hlc.last()
    }

    fn commit(&mut self, batch: CommitBatch) -> Result<CommitOutcome, MeshError> {
        let Validated { ranges, forks } = self.validate(&batch)?;
        // Nothing below can fail.
        let mut out = CommitOutcome::default();
        for ev in forks {
            self.note_fork(ev, &mut out);
        }
        let hour = self.now_ms() / HOUR_MS;
        for v in &batch.items {
            let o = v.body.origin;
            self.observe(&v.body);
            let (changed, regression) = self.apply_entry(v);
            out.stored += usize::from(changed);
            if regression {
                out.regressions += 1;
                *self.stats.regressions.entry(o).or_insert(0) += 1;
            }
            let r = self.rate.entry(o).or_insert((hour, 0));
            if r.0 != hour {
                *r = (hour, 0);
            }
            r.1 += 1;
        }
        for (o, hashes) in ranges {
            for h in hashes {
                self.push_dot(o, h);
            }
            let top = self.dots[&o].len() as u64;
            self.vv.advance_to(o, top);
        }
        for v in &batch.repair {
            let (o, s) = (v.body.origin, v.body.seq);
            if let Some(ours) = self.dot_hash(&o, s) {
                if ours != v.item.hash() {
                    self.note_fork(
                        ForkEvidence {
                            origin: o,
                            seq: s,
                            ours,
                            theirs: v.item.hash(),
                        },
                        &mut out,
                    );
                }
            }
            self.observe(&v.body);
            let (changed, regression) = self.apply_entry(v);
            if changed {
                out.stored += 1;
                if self.state.roster.fork_seq(&o).is_none() {
                    out.repairs_changed += 1;
                    self.stats.repairs_changed += 1;
                }
            }
            if regression {
                out.regressions += 1;
                *self.stats.regressions.entry(o).or_insert(0) += 1;
            }
        }
        Ok(out)
    }

    fn mint(&mut self, key: &SigningKeyPair, draft: Draft) -> Result<SignedItem, MeshError> {
        let seq = self.vv.get(&self.self_id) + 1;
        let hlc = match draft.hlc {
            HlcPolicy::Now => self.hlc.now(),
            HlcPolicy::After(winner) => self.hlc.local_write_ts(winner),
        };
        let body = ItemBody::new(
            self.genesis.mesh_id,
            self.self_id,
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
        let (_, regression) = self.apply_entry(&v);
        if regression {
            *self.stats.regressions.entry(self.self_id).or_insert(0) += 1;
        }
        self.push_dot(self.self_id, item.hash());
        self.vv.advance_to(self.self_id, seq);
        Ok(item)
    }

    fn record_rejected(&mut self, n: u64) {
        self.stats.rejected_items += n;
    }
}
