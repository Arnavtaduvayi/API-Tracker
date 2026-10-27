//! The deterministic network simulator (Increment 02, DESIGN §D21).
//!
//! One seed fixes everything: node keys, clock skews, the workload, network
//! faults, partitions, crashes and adversarial injections. Devices are real
//! [`MemStore`]s running real [`Session`]s; only the network and time are
//! simulated. A run ends with a fault-free quiescence phase, after which the
//! expensive invariants are checked, including convergence to an
//! independently written oracle.
//!
//! The world is generic over a [`StoreFactory`]: [`run`] uses [`MemStore`],
//! and the store conformance suite (Increment 03) runs the same world, the
//! same invariants and the same oracle over SQLite stores on disk, adding
//! crashes between commit chunks and restarts from disk.
//!
//! Replay: `MESH_SIM_SEED=<seed> MESH_SIM_STEPS=<steps>` re-runs exactly one
//! seed; the same seed always produces the same event trace hash.

use crate::mesh::chain::Hash32;
use crate::mesh::clock::{Clock, ManualClock};
use crate::mesh::crdt::bounded::BoundedCounter;
use crate::mesh::crdt::Admit;
use crate::mesh::dot::{CapId, CredentialRef, DeviceId, MeshId, MeshProjectId, ShareId};
use crate::mesh::error::MeshError;
use crate::mesh::hlc::{Hlc, MAX_DRIFT_MS};
use crate::mesh::item::{ItemHash, SignedItem};
use crate::mesh::kinds::{
    CapDef, CapRights, CapTarget, CapUsed, Day, DeviceInfo, ForkReport, ItemKind, MeshSetting,
    Month, ProjectMeta, Recipient, RosterAdd, RosterRemove, ShareRevoke, ShareSealed, UsageCounter,
    UsageKey, UsageTotals,
};
use crate::mesh::memstore::MemStore;
use crate::mesh::proto::{
    Action, Body, CloseReason, Commit, DirectMsg, Frame, Items, Limits, Session, B64,
};
use crate::mesh::sign::{derive_device_id, PublicKeyBytes, SigningKeyPair};
use crate::mesh::sim::oracle_api::{ExpectedShare, ExpectedState, OracleModel};
use crate::mesh::sim::rng::SplitMix64;
use crate::mesh::store::{Draft, ForkEvidence, GenesisInfo, HlcPolicy, MeshStore};
use crate::mesh::views::State;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

const T0: u64 = 1_700_000_000_000;
const IDLE_TIMEOUT_MS: u64 = 30_000;
const MAX_SESSIONS_PER_NODE: usize = 8;
const MAX_QUIESCE_ROUNDS: u32 = 16;
/// Catch-up rounds at the start of quiescence that still let stores inject
/// their own faults.
const CRASHY_CATCH_UP_ROUNDS: u32 = 2;
/// Nodes `0..CAP_DEVICES` take part in spend caps; they are never removed or
/// cloned, so cap safety is a property of honest operation (DESIGN §D21).
const CAP_DEVICES: usize = 3;

/// Network fault rates, per mille of frames (drop, duplicate, reorder) or of
/// steps (partition, crash).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Faults {
    pub drop_pm: u64,
    pub dup_pm: u64,
    pub reorder_pm: u64,
    pub max_delay_ms: u64,
    pub partition_pm: u64,
    pub crash_pm: u64,
}

impl Default for Faults {
    fn default() -> Self {
        Self {
            drop_pm: 15,
            dup_pm: 8,
            reorder_pm: 15,
            max_delay_ms: 200,
            partition_pm: 25,
            crash_pm: 15,
        }
    }
}

/// Which adversarial injections a run performs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Adversary {
    pub forged_origin: bool,
    pub replay: bool,
    pub fork: bool,
    pub huge_seq: bool,
    pub far_future_hlc: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimConfig {
    pub seed: u64,
    pub steps: u64,
    pub initial_nodes: usize,
    pub max_nodes: usize,
    pub faults: Faults,
    pub adversary: Adversary,
    /// Compare every device against the oracle at quiescence.
    pub check_oracle: bool,
}

impl SimConfig {
    /// The standard mix: 3-6 nodes, and adversaries chosen by the seed so
    /// every injection runs in a quarter to a half of all seeds.
    pub fn from_seed(seed: u64, steps: u64) -> Self {
        let mut r = SplitMix64::new(seed ^ 0x5EED_C0F1_6000_0000);
        let initial_nodes = 3 + r.below(4) as usize;
        Self {
            seed,
            steps,
            initial_nodes,
            max_nodes: (initial_nodes + 2).min(7),
            faults: Faults::default(),
            adversary: Adversary {
                forged_origin: r.chance(1, 2),
                replay: r.chance(1, 2),
                fork: r.chance(1, 3),
                huge_seq: r.chance(1, 3),
                far_future_hlc: r.chance(1, 3),
            },
            check_oracle: true,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimReport {
    pub trace_hash: Hash32,
    pub events: u64,
    pub mints: u64,
    pub sessions_done: u64,
    pub sessions_aborted: u64,
    pub forks_reported: u64,
    pub injections: u64,
    pub max_staged: usize,
    pub quiesce_rounds: u32,
    pub nodes: usize,
    /// Commits a store crashed in the middle of (SQLite conformance only).
    pub commit_crashes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimFailure {
    pub seed: u64,
    pub steps: u64,
    pub event: u64,
    pub invariant: &'static str,
    pub detail: String,
}

impl fmt::Display for SimFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MESH_SIM_SEED={} MESH_SIM_STEPS={}: invariant '{}' failed at event {}: {}",
            self.seed, self.steps, self.invariant, self.event, self.detail
        )
    }
}

/// What the simulator needs from a store beyond [`MeshStore`].
pub trait SimStore: MeshStore + Sized {
    /// A restart from whatever the store keeps durably.
    fn restart(&mut self, clock: Arc<dyn Clock>);
    /// A byte-for-byte copy of the device's data running on another clock:
    /// what copying a data directory produces (the fork injection).
    fn clone_onto(&self, clock: Arc<dyn Clock>) -> Self;
    /// Every held item.
    fn all_items(&self) -> Vec<SignedItem>;
    /// The views recomputed from the held items (invariant 3).
    fn rebuild_views(&self) -> Result<State, MeshError>;
    fn holds(&self, hash: &ItemHash) -> bool;
    /// Whether `err` is a crash the store simulated in the middle of a
    /// commit. The caller then treats the device as crashed.
    fn is_simulated_crash(_err: &MeshError) -> bool {
        false
    }
    /// Whether the store injects faults of its own (see [`Self::calm`]).
    fn injects_faults(&self) -> bool {
        false
    }
    /// Stop injecting store-level faults: quiescence is fault-free.
    fn calm(&mut self) {}
    /// Compare what the store keeps in memory with what a fresh open of its
    /// durable state would load.
    fn check_durable(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Creates one store per simulated device.
pub trait StoreFactory {
    type Store: SimStore;
    fn create(&mut self, genesis: GenesisInfo, id: DeviceId, clock: Arc<dyn Clock>) -> Self::Store;
}

/// In-memory stores: the default world.
pub struct MemFactory;

impl StoreFactory for MemFactory {
    type Store = MemStore;
    fn create(&mut self, genesis: GenesisInfo, id: DeviceId, clock: Arc<dyn Clock>) -> MemStore {
        MemStore::new(genesis, id, clock)
    }
}

impl SimStore for MemStore {
    fn restart(&mut self, clock: Arc<dyn Clock>) {
        MemStore::restart(self, clock)
    }
    fn clone_onto(&self, clock: Arc<dyn Clock>) -> Self {
        MemStore::clone_onto(self, clock)
    }
    fn all_items(&self) -> Vec<SignedItem> {
        MemStore::all_items(self).cloned().collect()
    }
    fn rebuild_views(&self) -> Result<State, MeshError> {
        MemStore::rebuild_views(self)
    }
    fn holds(&self, hash: &ItemHash) -> bool {
        MemStore::holds(self, hash)
    }
}

/// An oracle that predicts nothing, for runs with `check_oracle = false`.
pub struct NoOracle;

impl OracleModel for NoOracle {
    fn new(_genesis: &GenesisInfo) -> Self {
        NoOracle
    }
    fn observe_minted(&mut self, _item: &SignedItem) {}
    fn observe_unreached(&mut self, _item: &SignedItem) {}
    fn expected(&self) -> ExpectedState {
        ExpectedState::default()
    }
}

struct Node<S> {
    id: DeviceId,
    key: Arc<SigningKeyPair>,
    noise_pub: PublicKeyBytes,
    seal_pub: PublicKeyBytes,
    store: S,
    clock: Arc<ManualClock>,
    skew_ms: i64,
    alive: bool,
    cap_device: bool,
    clone_of: Option<usize>,
    mint_block: u64,
}

struct Sess {
    a: usize,
    b: usize,
    sa: Session,
    sb: Session,
    last_activity: u64,
}

struct InFlight {
    at: u64,
    order: u64,
    sid: u64,
    /// Deliver to side `a` (else `b`).
    to_a: bool,
    frame: Frame,
}

/// Pools the workload draws keys from, so writes collide.
struct Pools {
    projects: Vec<MeshProjectId>,
    caps: Vec<CapId>,
    months: Vec<Month>,
    days: Vec<Day>,
    creds: Vec<CredentialRef>,
}

struct World<F: StoreFactory> {
    cfg: SimConfig,
    factory: F,
    rng: SplitMix64,
    now: u64,
    genesis: GenesisInfo,
    nodes: Vec<Node<F::Store>>,
    sessions: BTreeMap<u64, Sess>,
    next_sid: u64,
    net: Vec<InFlight>,
    next_order: u64,
    groups: Option<Vec<u8>>,
    minted: Vec<SignedItem>,
    seen_by: HashMap<ItemHash, BTreeSet<usize>>,
    forged: HashSet<ItemHash>,
    huge: Vec<(DeviceId, u64)>,
    pools: Pools,
    trace: blake3::Hasher,
    event: u64,
    report: SimReport,
    limits: Limits,
}

type Res<T> = Result<T, SimFailure>;

impl<F: StoreFactory> World<F> {
    fn fail<T>(&self, invariant: &'static str, detail: impl Into<String>) -> Res<T> {
        Err(SimFailure {
            seed: self.cfg.seed,
            steps: self.cfg.steps,
            event: self.event,
            invariant,
            detail: detail.into(),
        })
    }

    fn log(&mut self, what: &str, a: u64, b: u64) {
        self.trace.update(what.as_bytes());
        self.trace.update(&a.to_le_bytes());
        self.trace.update(&b.to_le_bytes());
    }

    fn new(cfg: &SimConfig, factory: F) -> Res<Self> {
        let mut rng = SplitMix64::new(cfg.seed);
        let mut id_bytes = [0u8; 16];
        rng.fill_bytes(&mut id_bytes);
        let mesh_id = MeshId::from_bytes(id_bytes);
        let pool_id = |rng: &mut SplitMix64| {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            b
        };
        let pools = Pools {
            projects: (0..3)
                .map(|_| MeshProjectId::from_bytes(pool_id(&mut rng)))
                .collect(),
            caps: (0..2)
                .map(|_| CapId::from_bytes(pool_id(&mut rng)))
                .collect(),
            months: vec![
                Month::parse("2026-10").expect("valid"),
                Month::parse("2026-11").expect("valid"),
            ],
            days: vec![
                Day::parse("2026-10-25").expect("valid"),
                Day::parse("2026-10-26").expect("valid"),
            ],
            creds: (0..2)
                .map(|_| CredentialRef::from_bytes(pool_id(&mut rng)))
                .collect(),
        };
        let mut w = World {
            cfg: cfg.clone(),
            factory,
            rng,
            now: T0,
            genesis: GenesisInfo {
                mesh_id,
                genesis: DeviceId::MIN,
            },
            nodes: Vec::new(),
            sessions: BTreeMap::new(),
            next_sid: 0,
            net: Vec::new(),
            next_order: 0,
            groups: None,
            minted: Vec::new(),
            seen_by: HashMap::new(),
            forged: HashSet::new(),
            huge: Vec::new(),
            pools,
            trace: blake3::Hasher::new(),
            event: 0,
            report: SimReport::default(),
            limits: Limits::default(),
        };
        // The genesis device: keys first, because its id is derived from them.
        let g = w.make_node(true)?;
        w.genesis.genesis = w.nodes[g].id;
        for i in 0..w.nodes.len() {
            let (id, clock) = (w.nodes[i].id, w.nodes[i].clock.clone());
            w.nodes[i].store = w.factory.create(w.genesis, id, clock);
        }
        let add = w.roster_add_of(g, g);
        w.mint(g, &add, HlcPolicy::Now)?;
        for _ in 1..cfg.initial_nodes {
            w.join(g)?;
        }
        Ok(w)
    }

    fn make_node(&mut self, cap_device: bool) -> Res<usize> {
        let mut secret = [0u8; 32];
        self.rng.fill_bytes(&mut secret);
        let key = SigningKeyPair::from_secret_bytes(&secret);
        let mut nb = [0u8; 32];
        self.rng.fill_bytes(&mut nb);
        let mut sb = [0u8; 32];
        self.rng.fill_bytes(&mut sb);
        let (noise_pub, seal_pub) = (PublicKeyBytes(nb), PublicKeyBytes(sb));
        let id = derive_device_id(&key.public_key(), &noise_pub, &seal_pub);
        let idx = self.nodes.len();
        let skew_ms = if self.cfg.adversary.far_future_hlc && idx == 1 {
            10 * 60_000
        } else if self.cfg.adversary.far_future_hlc && idx == 2 {
            -10 * 60_000
        } else {
            self.rng.below(6_001) as i64 - 3_000
        };
        let clock = Arc::new(ManualClock::new(self.now.saturating_add_signed(skew_ms)));
        let store = self.factory.create(self.genesis, id, clock.clone());
        self.nodes.push(Node {
            id,
            key: Arc::new(key),
            noise_pub,
            seal_pub,
            store,
            clock,
            skew_ms,
            alive: true,
            cap_device,
            clone_of: None,
            mint_block: 0,
        });
        self.log("node", idx as u64, 0);
        Ok(idx)
    }

    fn roster_add_of(&self, by: usize, target: usize) -> RosterAdd {
        let t = &self.nodes[target];
        RosterAdd {
            device: t.id,
            name: format!("node {target}"),
            sign_pub: t.key.public_key(),
            noise_pub: t.noise_pub,
            seal_pub: t.seal_pub,
            added_by: self.nodes[by].id,
        }
    }

    /// Mint through a node's store and tell the oracle.
    fn mint<K: ItemKind>(&mut self, n: usize, value: &K, hlc: HlcPolicy) -> Res<SignedItem> {
        let node = &mut self.nodes[n];
        let before = node.store.hlc_last();
        let key = node.key.clone();
        let item = match node.store.mint(&key, Draft::of(value, hlc)) {
            Ok(i) => i,
            Err(e) => {
                return self.fail("mint", format!("node {n} could not mint {}: {e}", K::KIND))
            }
        };
        self.check_clock(n, before)?;
        self.seen_by.entry(item.hash()).or_default().insert(n);
        self.minted.push(item.clone());
        self.report.mints += 1;
        let h = item.hash();
        self.trace.update(&h.0);
        Ok(item)
    }

    /// Invariant 9: an observation never moves a node's HLC past
    /// `max(previous + 1, now + MAX_DRIFT)`.
    fn check_clock(&self, n: usize, before: Hlc) -> Res<()> {
        let node = &self.nodes[n];
        let bound = Hlc::new(node.clock.now_ms().saturating_add(MAX_DRIFT_MS), 0);
        let last = node.store.hlc_last();
        if last > before.successor().max(bound) {
            return self.fail(
                "9 clock safety",
                format!("node {n}: {last} > max({before}+1, {bound})"),
            );
        }
        Ok(())
    }

    fn set_clocks(&mut self) {
        for n in &self.nodes {
            n.clock.set(self.now.saturating_add_signed(n.skew_ms));
        }
    }

    fn is_active_self(&self, n: usize) -> bool {
        let node = &self.nodes[n];
        node.store.state().roster.is_active(&node.id)
    }

    /// May `a` and `b` run a session (MESH-SI-2)? Each side must consider the
    /// other active, unless it is still joining (pairing trusts the inviter).
    fn can_talk(&self, a: usize, b: usize) -> bool {
        if a == b || !self.nodes[a].alive || !self.nodes[b].alive {
            return false;
        }
        if self.nodes[a].id == self.nodes[b].id {
            return false;
        }
        if let Some(g) = &self.groups {
            // Nodes that joined after the partition started are in group 0.
            let group = |n: usize| g.get(n).copied().unwrap_or(0);
            if group(a) != group(b) {
                return false;
            }
        }
        let accepts = |x: usize, y: usize| {
            !self.is_active_self(x)
                && !self.nodes[x]
                    .store
                    .state()
                    .roster
                    .is_known(&self.nodes[x].id)
                || self.nodes[x]
                    .store
                    .state()
                    .roster
                    .is_active(&self.nodes[y].id)
        };
        accepts(a, b) && accepts(b, a)
    }

    fn sessions_of(&self, n: usize) -> usize {
        self.sessions
            .values()
            .filter(|s| s.a == n || s.b == n)
            .count()
    }

    // ------------------------------------------------------------- network

    fn start_session(&mut self, a: usize, b: usize) -> Res<()> {
        let sid = self.next_sid;
        self.next_sid += 1;
        let mut sa = Session::new(self.limits, Some(self.nodes[b].id));
        let mut sb = Session::new(self.limits, Some(self.nodes[a].id));
        let acts_a = sa.start(&self.nodes[a].store);
        let acts_b = sb.start(&self.nodes[b].store);
        self.sessions.insert(
            sid,
            Sess {
                a,
                b,
                sa,
                sb,
                last_activity: self.now,
            },
        );
        self.log("session", a as u64, b as u64);
        self.handle(sid, true, acts_a, true)?;
        self.handle(sid, false, acts_b, true)?;
        Ok(())
    }

    fn send(&mut self, sid: u64, from_a: bool, frame: Frame, faulty: bool) {
        let mut copies = 1;
        let mut delay = 1 + self.rng.below(self.cfg.faults.max_delay_ms.max(1));
        if faulty {
            let f = self.cfg.faults;
            if self.rng.chance(f.drop_pm, 1000) {
                self.log("drop", sid, frame.n);
                return;
            }
            if self.rng.chance(f.dup_pm, 1000) {
                copies = 2;
            }
            if self.rng.chance(f.reorder_pm, 1000) {
                delay += 1_000 + self.rng.below(2_000);
            }
        }
        for _ in 0..copies {
            let order = self.next_order;
            self.next_order += 1;
            self.net.push(InFlight {
                at: self.now + delay,
                order,
                sid,
                to_a: !from_a,
                frame: frame.clone(),
            });
            delay += 1 + self.rng.below(50);
        }
    }

    /// Process the actions side `from_a` of session `sid` produced.
    fn handle(&mut self, sid: u64, side_a: bool, actions: Vec<Action>, faulty: bool) -> Res<()> {
        let Some(s) = self.sessions.get(&sid) else {
            return Ok(());
        };
        let n = if side_a { s.a } else { s.b };
        for act in actions {
            match act {
                Action::Send(f) => self.send(sid, side_a, f, faulty),
                Action::Commit(batch) => {
                    let items: Vec<ItemHash> = batch
                        .items
                        .iter()
                        .chain(batch.repair.iter())
                        .map(|v| v.item.hash())
                        .collect();
                    let before = self.nodes[n].store.hlc_last();
                    let dots: Vec<(DeviceId, u64, ItemHash)> = batch
                        .items
                        .iter()
                        .chain(batch.repair.iter())
                        .map(|v| (v.body.origin, v.body.seq, v.item.hash()))
                        .collect();
                    let out = match self.nodes[n].store.commit(batch) {
                        Ok(o) => o,
                        Err(e) if F::Store::is_simulated_crash(&e) => {
                            return self.crash_mid_commit(n, &dots);
                        }
                        Err(e) => {
                            return self.fail(
                                "commit",
                                format!("node {n} refused a session's commit: {e}"),
                            )
                        }
                    };
                    self.check_clock(n, before)?;
                    for h in items {
                        if self.forged.contains(&h) {
                            return self
                                .fail("6 no forgery", format!("node {n} committed a forged item"));
                        }
                        self.seen_by.entry(h).or_default().insert(n);
                    }
                    for ev in out.forks {
                        self.report_fork(n, ev)?;
                    }
                }
                Action::ForkDetected(ev) => self.report_fork(n, ev)?,
                Action::Direct(DirectMsg::RollbackNotice { held_seq }) => {
                    let node = &mut self.nodes[n];
                    node.mint_block = node.mint_block.max(held_seq);
                }
                Action::Close(reason) => {
                    let Some(s) = self.sessions.get(&sid) else {
                        continue;
                    };
                    let side = if side_a { &s.sa } else { &s.sb };
                    let (rejected, staged) = (side.rejected(), side.max_staged_seen());
                    self.report.max_staged = self.report.max_staged.max(staged);
                    if staged > self.limits.max_staged {
                        return self.fail("8 bounds", format!("session staged {staged}"));
                    }
                    self.nodes[n].store.record_rejected(rejected);
                    match reason {
                        CloseReason::Done => {}
                        _ => self.report.sessions_aborted += 1,
                    }
                    let both = {
                        let s = &self.sessions[&sid];
                        s.sa.is_closed() && s.sb.is_closed()
                    };
                    if both {
                        self.sessions.remove(&sid);
                        if reason == CloseReason::Done {
                            self.report.sessions_done += 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// The store crashed between two of a commit's chunks: what it applied
    /// before the crash is durable, the rest is lost, and the device is down
    /// until a restart step reopens it.
    fn crash_mid_commit(&mut self, n: usize, batch: &[(DeviceId, u64, ItemHash)]) -> Res<()> {
        for (o, s, h) in batch {
            let st = &self.nodes[n].store;
            let reached = st.holds(h) || st.dot_hash(o, *s).ok().flatten() == Some(*h);
            if !reached {
                continue;
            }
            if self.forged.contains(h) {
                return self.fail("6 no forgery", format!("node {n} committed a forged item"));
            }
            self.seen_by.entry(*h).or_default().insert(n);
        }
        self.nodes[n].alive = false;
        let dead: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.a == n || s.b == n)
            .map(|(k, _)| *k)
            .collect();
        for sid in dead {
            self.sessions.remove(&sid);
            self.report.sessions_aborted += 1;
        }
        self.net.retain(|m| self.sessions.contains_key(&m.sid));
        self.report.commit_crashes += 1;
        self.log("commit-crash", n as u64, 0);
        Ok(())
    }

    fn report_fork(&mut self, n: usize, ev: ForkEvidence) -> Res<()> {
        let roster = &self.nodes[n].store.state().roster;
        if roster.fork_seq(&ev.origin).is_some_and(|f| f <= ev.seq) {
            return Ok(());
        }
        let report = ForkReport {
            device: ev.origin,
            seq: ev.seq,
            hash_a: ev.ours,
            hash_b: ev.theirs,
        };
        self.mint(n, &report, HlcPolicy::Now)?;
        self.report.forks_reported += 1;
        self.log("fork-report", n as u64, ev.seq);
        Ok(())
    }

    fn deliver_next(&mut self) -> Res<bool> {
        if self.net.is_empty() {
            return Ok(false);
        }
        let i = (0..self.net.len())
            .min_by_key(|&i| (self.net[i].at, self.net[i].order))
            .expect("non-empty");
        let m = self.net.swap_remove(i);
        self.now = self.now.max(m.at);
        self.set_clocks();
        self.log("deliver", m.sid, m.frame.n);
        let Some(s) = self.sessions.get_mut(&m.sid) else {
            return Ok(true);
        };
        s.last_activity = self.now;
        let (n, side) = if m.to_a {
            (s.a, &mut s.sa)
        } else {
            (s.b, &mut s.sb)
        };
        if !self.nodes[n].alive {
            return Ok(true);
        }
        let acts = side.on_frame(m.frame, &self.nodes[n].store);
        self.handle(m.sid, m.to_a, acts, true)?;
        Ok(true)
    }

    fn sweep_idle(&mut self) {
        let now = self.now;
        let idle: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| now.saturating_sub(s.last_activity) > IDLE_TIMEOUT_MS)
            .map(|(k, _)| *k)
            .collect();
        for sid in idle {
            self.sessions.remove(&sid);
            self.report.sessions_aborted += 1;
            self.log("timeout", sid, 0);
        }
        self.net.retain(|m| self.sessions.contains_key(&m.sid));
    }

    /// Run one session to completion with no faults (quiescence).
    fn run_sync(&mut self, a: usize, b: usize) -> Res<()> {
        let sid = self.next_sid;
        self.start_session(a, b)?;
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 100_000 {
                return self.fail("liveness", format!("session {a}<->{b} did not finish"));
            }
            let Some(i) = (0..self.net.len())
                .filter(|&i| self.net[i].sid == sid)
                .min_by_key(|&i| self.net[i].order)
            else {
                break;
            };
            let m = self.net.swap_remove(i);
            let Some(s) = self.sessions.get_mut(&m.sid) else {
                break;
            };
            let (n, side) = if m.to_a {
                (s.a, &mut s.sa)
            } else {
                (s.b, &mut s.sb)
            };
            let acts = side.on_frame(m.frame, &self.nodes[n].store);
            self.handle(m.sid, m.to_a, acts, false)?;
        }
        self.sessions.remove(&sid);
        self.net.retain(|m| m.sid != sid);
        Ok(())
    }

    // ------------------------------------------------------------ workload

    fn join(&mut self, inviter: usize) -> Res<()> {
        let cap = self.nodes.len() < CAP_DEVICES;
        let n = self.make_node(cap)?;
        let add = self.roster_add_of(inviter, n);
        self.mint(inviter, &add, HlcPolicy::Now)?;
        self.log("join", inviter as u64, n as u64);
        Ok(())
    }

    fn active_nodes(&self) -> Vec<usize> {
        (0..self.nodes.len())
            .filter(|&n| self.nodes[n].alive && self.is_active_self(n))
            .collect()
    }

    fn remove_random(&mut self) -> Res<()> {
        let active = self.active_nodes();
        let candidates: Vec<usize> = active
            .iter()
            .copied()
            .filter(|&n| !self.nodes[n].cap_device && self.nodes[n].clone_of.is_none())
            .filter(|&n| self.nodes.iter().all(|x| x.clone_of != Some(n)))
            .collect();
        let (Some(&target), Some(&by)) = (self.rng.choose(&candidates), self.rng.choose(&active))
        else {
            return Ok(());
        };
        if target == by {
            return Ok(());
        }
        let tid = self.nodes[target].id;
        let cutoff = self.nodes[by].store.vv().get(&tid);
        self.mint(
            by,
            &RosterRemove {
                device: tid,
                cutoff_seq: cutoff,
            },
            HlcPolicy::Now,
        )?;
        self.log("remove", by as u64, target as u64);
        Ok(())
    }

    fn workload(&mut self, n: usize) -> Res<()> {
        let node = &self.nodes[n];
        if !node.alive || !self.is_active_self(n) || node.store.vv().get(&node.id) < node.mint_block
        {
            return Ok(());
        }
        let me = node.id;
        let roster = node.store.state().roster.clone();
        match self.rng.below(20) {
            0..=3 => {
                let project = *self.rng.choose(&self.pools.projects).expect("pool");
                let winner = self.nodes[n]
                    .store
                    .state()
                    .projects
                    .register(&project)
                    .and_then(|r| r.winning_hlc(&roster));
                let names = ["Billing", "Search", "Infra", "Agents"];
                let merged_into = if self.rng.chance(1, 8) {
                    self.pools.projects.iter().copied().find(|p| *p != project)
                } else {
                    None
                };
                let v = ProjectMeta {
                    project,
                    name: (*self.rng.choose(&names).expect("names")).to_owned(),
                    archived: self.rng.chance(1, 5),
                    merged_into,
                };
                self.mint(n, &v, HlcPolicy::After(winner))?;
            }
            4..=8 => {
                let key = UsageKey {
                    project: *self.rng.choose(&self.pools.projects).expect("pool"),
                    day: *self.rng.choose(&self.pools.days).expect("pool"),
                    provider: (*self.rng.choose(&["openai", "anthropic"]).expect("p")).to_owned(),
                    model: (*self
                        .rng
                        .choose(&["gpt-x", "accounts/f/models/m"])
                        .expect("m"))
                    .to_owned(),
                };
                let cur = self.nodes[n]
                    .store
                    .state()
                    .usage
                    .get(&key, &me)
                    .map(|e| e.value.clone());
                let (epoch, mut t) =
                    cur.map_or((0, UsageTotals::default()), |c| (c.epoch, c.totals));
                let (epoch, t) = if self.rng.chance(1, 10) && t.requests > 0 {
                    (
                        epoch + 1,
                        UsageTotals {
                            requests: t.requests / 2,
                            ..UsageTotals::default()
                        },
                    )
                } else {
                    let r = 1 + self.rng.below(5);
                    t.requests += r;
                    t.priced_requests += r;
                    t.input_tokens += self.rng.below(1_000);
                    t.output_tokens += self.rng.below(500);
                    t.estimated_cost_micros += self.rng.below(10_000);
                    (epoch, t)
                };
                self.mint(
                    n,
                    &UsageCounter {
                        key,
                        epoch,
                        totals: t,
                    },
                    HlcPolicy::Now,
                )?;
            }
            9 => {
                let winner = self.nodes[n]
                    .store
                    .state()
                    .settings
                    .register(&"retention_days".to_owned())
                    .and_then(|r| r.winning_hlc(&roster));
                let v = MeshSetting {
                    name: "retention_days".into(),
                    value: serde_json::json!(30 + self.rng.below(400)),
                };
                self.mint(n, &v, HlcPolicy::After(winner))?;
            }
            10 => {
                let winner = self.nodes[n]
                    .store
                    .state()
                    .device_info
                    .register(&me)
                    .and_then(|r| r.winning_hlc(&roster));
                let v = DeviceInfo {
                    device: me,
                    name: format!("device {n}.{}", self.rng.below(9)),
                    listen_addrs: vec![format!("127.0.0.1:{}", 7000 + n)],
                };
                self.mint(n, &v, HlcPolicy::After(winner))?;
            }
            11..=17 if self.nodes[n].cap_device => self.cap_op(n)?,
            11..=17 => {}
            _ => self.share_op(n)?,
        }
        Ok(())
    }

    fn cap_op(&mut self, n: usize) -> Res<()> {
        let me = self.nodes[n].id;
        let roster = self.nodes[n].store.state().roster.clone();
        let cap = *self.rng.choose(&self.pools.caps).expect("pool");
        let month = *self.rng.choose(&self.pools.months).expect("pool");
        let state = self.nodes[n].store.state();
        let owner = state.cap_defs.register(&cap).and_then(|r| {
            let admitted: Vec<_> = r
                .entries()
                .filter(|(o, e)| roster.admits(o, e.seq))
                .collect();
            (admitted.len() == 1).then(|| admitted[0].1.value.value.owner_device)
        });
        let defined = state
            .cap_defs
            .register(&cap)
            .is_some_and(|r| r.entries().any(|(o, e)| roster.admits(o, e.seq)));
        let counter = state
            .cap_counters
            .get(&(cap, month))
            .cloned()
            .unwrap_or_else(BoundedCounter::new);
        let target_winner = state
            .cap_targets
            .register(&(cap, month))
            .and_then(|r| r.winning_hlc(&roster));
        let peers: Vec<DeviceId> = (0..self.nodes.len())
            .filter(|&i| self.nodes[i].cap_device && self.nodes[i].id != me)
            .map(|i| self.nodes[i].id)
            .collect();
        let x = 1 + self.rng.below(400);
        match self.rng.below(12) {
            0 if !defined => {
                let hlc = self.nodes[n].store.hlc_last();
                let def = CapDef {
                    cap,
                    mesh_project_id: *self.rng.choose(&self.pools.projects).expect("pool"),
                    owner_device: me,
                    created_hlc: hlc,
                };
                self.mint(n, &def, HlcPolicy::Now)?;
            }
            1 | 2 if owner == Some(me) => {
                if let Ok(v) = counter.prepare_mint(&me, 500 + x) {
                    let r = CapRights {
                        cap,
                        month,
                        to: Recipient::Device(me),
                        amount_micros: v,
                        is_override: false,
                    };
                    self.mint(n, &r, HlcPolicy::Now)?;
                }
            }
            3 if owner.is_some() && owner != Some(me) && self.rng.chance(1, 4) => {
                if let Ok(v) = counter.prepare_mint(&me, x) {
                    let r = CapRights {
                        cap,
                        month,
                        to: Recipient::Device(me),
                        amount_micros: v,
                        is_override: true,
                    };
                    self.mint(n, &r, HlcPolicy::Now)?;
                }
            }
            4 | 5 => {
                if let Some(&to) = self.rng.choose(&peers) {
                    if let Ok(v) = counter.prepare_transfer(&me, &to, x, &roster) {
                        let r = CapRights {
                            cap,
                            month,
                            to: Recipient::Device(to),
                            amount_micros: v,
                            is_override: false,
                        };
                        self.mint(n, &r, HlcPolicy::Now)?;
                    }
                }
            }
            6 => {
                if let Ok(v) = counter.prepare_burn(&me, x / 4 + 1, &roster) {
                    let r = CapRights {
                        cap,
                        month,
                        to: Recipient::Burn,
                        amount_micros: v,
                        is_override: false,
                    };
                    self.mint(n, &r, HlcPolicy::Now)?;
                }
            }
            7..=9 => {
                if let Ok(v) = counter.prepare_spend(&me, x, &roster) {
                    let u = CapUsed {
                        cap,
                        month,
                        epoch: 0,
                        used_micros: v,
                    };
                    self.mint(n, &u, HlcPolicy::Now)?;
                }
            }
            10 => {
                let t = CapTarget {
                    cap,
                    month,
                    target_micros: 1_000 + x * 10,
                };
                self.mint(n, &t, HlcPolicy::After(target_winner))?;
            }
            _ => {}
        }
        Ok(())
    }

    fn share_op(&mut self, n: usize) -> Res<()> {
        let roster = self.nodes[n].store.state().roster.clone();
        let members: Vec<DeviceId> = roster.members().copied().collect();
        let (Some(&recipient), Some(&credential)) = (
            self.rng.choose(&members),
            self.rng.choose(&self.pools.creds),
        ) else {
            return Ok(());
        };
        let key = (credential, recipient);
        let st = self.nodes[n].store.state();
        let w1 = st
            .shares_sealed
            .register(&key)
            .and_then(|r| r.winning_hlc(&roster));
        let w2 = st
            .shares_revoked
            .register(&key)
            .and_then(|r| r.winning_hlc(&roster));
        let winner = w1.max(w2);
        let mut sid = [0u8; 16];
        self.rng.fill_bytes(&mut sid);
        if self.rng.chance(1, 3) {
            let r = ShareRevoke {
                credential,
                recipient,
                share_id: ShareId::from_bytes(sid),
            };
            self.mint(n, &r, HlcPolicy::After(winner))?;
        } else {
            let mut sealed = vec![0u8; 16 + self.rng.below(48) as usize];
            self.rng.fill_bytes(&mut sealed);
            let s = ShareSealed {
                credential,
                recipient,
                share_id: ShareId::from_bytes(sid),
                mesh_project_id: *self.rng.choose(&self.pools.projects).expect("pool"),
                credential_name: "OPENAI_API_KEY".into(),
                provider: "openai".into(),
                value_version: 1 + self.rng.below(3),
                sealed,
            };
            self.mint(n, &s, HlcPolicy::After(winner))?;
        }
        Ok(())
    }

    // --------------------------------------------------------- adversaries

    fn fork_inject(&mut self) -> Res<()> {
        if self.nodes.iter().any(|n| n.clone_of.is_some()) || self.nodes.len() > self.cfg.max_nodes
        {
            return Ok(());
        }
        let candidates: Vec<usize> = self
            .active_nodes()
            .into_iter()
            .filter(|&n| !self.nodes[n].cap_device)
            .collect();
        let Some(&x) = self.rng.choose(&candidates) else {
            return Ok(());
        };
        let clock = Arc::new(ManualClock::new(self.nodes[x].clock.now_ms()));
        let store = self.nodes[x].store.clone_onto(clock.clone());
        let src = &self.nodes[x];
        let clone = Node {
            id: src.id,
            key: src.key.clone(),
            noise_pub: src.noise_pub,
            seal_pub: src.seal_pub,
            store,
            clock,
            skew_ms: src.skew_ms,
            alive: true,
            cap_device: false,
            clone_of: Some(x),
            mint_block: src.mint_block,
        };
        self.nodes.push(clone);
        self.report.injections += 1;
        self.log("fork", x as u64, 0);
        Ok(())
    }

    /// Feed crafted frames from `from` straight into a fresh session at `to`.
    fn inject_frames(&mut self, from: usize, to: usize, frames: Vec<Body>) -> Res<()> {
        let mut attacker = Session::new(self.limits, None);
        let mut frames_out: Vec<Frame> = Vec::new();
        for a in attacker.start(&self.nodes[from].store) {
            if let Action::Send(f) = a {
                frames_out.push(f);
            }
        }
        for body in frames {
            frames_out.push(Frame {
                n: frames_out.len() as u64,
                body,
            });
        }
        let mut victim = Session::new(self.limits, Some(self.nodes[from].id));
        let _ = victim.start(&self.nodes[to].store);
        let sid = self.next_sid;
        self.next_sid += 1;
        self.sessions.insert(
            sid,
            Sess {
                a: from,
                b: to,
                sa: Session::new(self.limits, None),
                sb: victim,
                last_activity: self.now,
            },
        );
        for f in frames_out {
            let Some(s) = self.sessions.get_mut(&sid) else {
                break;
            };
            let acts = s.sb.on_frame(f, &self.nodes[to].store);
            let kept: Vec<Action> = acts
                .into_iter()
                .filter(|a| !matches!(a, Action::Send(_)))
                .collect();
            self.handle(sid, false, kept, false)?;
        }
        self.sessions.remove(&sid);
        self.report.injections += 1;
        Ok(())
    }

    fn adversary_step(&mut self) -> Res<()> {
        let adv = self.cfg.adversary;
        let active = self.active_nodes();
        let (Some(&m), Some(&t)) = (self.rng.choose(&active), self.rng.choose(&active)) else {
            return Ok(());
        };
        if m == t || self.nodes[m].id == self.nodes[t].id {
            return Ok(());
        }
        match self.rng.below(4) {
            0 if adv.forged_origin => {
                // m signs an item claiming another device as origin.
                let Some(&v) = self.rng.choose(&active) else {
                    return Ok(());
                };
                let victim = self.nodes[v].id;
                if v == m || victim == self.nodes[m].id {
                    return Ok(());
                }
                let seq = self.nodes[t].store.vv().get(&victim) + 1;
                let body = DeviceInfo {
                    device: victim,
                    name: "forged".into(),
                    listen_addrs: vec![],
                }
                .to_body(self.genesis.mesh_id, victim, seq, Hlc::new(self.now, 0));
                let item = SignedItem::sign(&body, &self.nodes[m].key).expect("signable");
                self.forged.insert(item.hash());
                self.minted.push(item.clone());
                self.seen_by.entry(item.hash()).or_default().insert(m);
                let mut upto = crate::mesh::vv::VersionVector::new();
                upto.advance_to(victim, seq);
                let frames = vec![
                    Body::Items(Items {
                        batch: vec![B64(item.to_wire())],
                        dots: vec![],
                        repair: false,
                    }),
                    Body::Commit(Commit {
                        upto,
                        count: 1,
                        batch_hash: Hash32(*blake3::hash(&item.hash().0).as_bytes()),
                    }),
                ];
                self.log("forge", m as u64, t as u64);
                self.inject_frames(m, t, frames)?;
                if self.nodes[t].store.holds(&item.hash()) {
                    return self.fail("6 no forgery", "a forged item was stored");
                }
            }
            1 if adv.replay => {
                // Re-send an item t already accepted — often one it has since
                // superseded; nothing may change.
                let accepted: Vec<SignedItem> = self
                    .minted
                    .iter()
                    .filter(|i| {
                        i.decode_unverified().is_ok_and(|b| {
                            self.nodes[t]
                                .store
                                .dot_hash(&b.origin, b.seq)
                                .ok()
                                .flatten()
                                == Some(i.hash())
                        })
                    })
                    .cloned()
                    .collect();
                let Some(item) = self.rng.choose(&accepted).cloned() else {
                    return Ok(());
                };
                let body = item.decode_unverified().expect("stored items decode");
                let before = (
                    self.nodes[t].store.vv().clone(),
                    self.nodes[t].store.origin_digest(&body.origin),
                );
                let mut upto = crate::mesh::vv::VersionVector::new();
                upto.advance_to(body.origin, body.seq);
                let frames = vec![
                    Body::Items(Items {
                        batch: vec![B64(item.to_wire())],
                        dots: vec![],
                        repair: false,
                    }),
                    Body::Commit(Commit {
                        upto,
                        count: 1,
                        batch_hash: Hash32(*blake3::hash(&item.hash().0).as_bytes()),
                    }),
                ];
                self.log("replay", m as u64, t as u64);
                self.inject_frames(m, t, frames)?;
                let after = (
                    self.nodes[t].store.vv().clone(),
                    self.nodes[t].store.origin_digest(&body.origin),
                );
                if before != after {
                    return self.fail("replay", "replaying a committed item changed the store");
                }
            }
            2 if adv.huge_seq => {
                // m signs its own item far beyond its log.
                let me = self.nodes[m].id;
                let seq = self.nodes[m].store.vv().get(&me) + 1_000_000;
                let body = MeshSetting {
                    name: "huge".into(),
                    value: serde_json::json!(1),
                }
                .to_body(self.genesis.mesh_id, me, seq, Hlc::new(self.now, 0));
                let item = SignedItem::sign(&body, &self.nodes[m].key).expect("signable");
                self.huge.push((me, seq));
                self.minted.push(item.clone());
                self.seen_by.entry(item.hash()).or_default().insert(m);
                let mut upto = crate::mesh::vv::VersionVector::new();
                upto.advance_to(me, seq);
                let frames = vec![
                    Body::Items(Items {
                        batch: vec![B64(item.to_wire())],
                        dots: vec![],
                        repair: false,
                    }),
                    Body::Commit(Commit {
                        upto,
                        count: 1,
                        batch_hash: Hash32(*blake3::hash(&item.hash().0).as_bytes()),
                    }),
                ];
                self.log("huge", m as u64, t as u64);
                self.inject_frames(m, t, frames)?;
            }
            3 if adv.fork => self.fork_inject()?,
            _ => {}
        }
        Ok(())
    }

    // ---------------------------------------------------------------- run

    fn step(&mut self) -> Res<()> {
        self.event += 1;
        self.now += 1 + self.rng.below(50);
        self.set_clocks();
        let roll = self.rng.below(100);
        self.log("step", self.event, roll);
        match roll {
            0..=29 => {
                self.deliver_next()?;
            }
            30..=44 => {
                let n = self.nodes.len() as u64;
                let (a, b) = (self.rng.below(n) as usize, self.rng.below(n) as usize);
                if self.can_talk(a, b)
                    && self.sessions_of(a) < MAX_SESSIONS_PER_NODE
                    && self.sessions_of(b) < MAX_SESSIONS_PER_NODE
                {
                    self.start_session(a, b)?;
                }
            }
            45..=69 => {
                let n = self.rng.below(self.nodes.len() as u64) as usize;
                self.workload(n)?;
            }
            70..=77 => {
                self.now += self.rng.below(30_000);
                self.set_clocks();
                self.sweep_idle();
            }
            78..=80 => {
                if self.rng.chance(self.cfg.faults.partition_pm, 30) {
                    let groups: Vec<u8> = (0..self.nodes.len())
                        .map(|_| self.rng.below(2) as u8)
                        .collect();
                    self.log("partition", 0, 0);
                    self.groups = Some(groups);
                    let g = self.groups.clone().expect("set");
                    let group = |n: usize| g.get(n).copied().unwrap_or(0);
                    self.net.retain(|m| {
                        self.sessions
                            .get(&m.sid)
                            .is_some_and(|s| group(s.a) == group(s.b))
                    });
                } else {
                    self.log("heal", 0, 0);
                    self.groups = None;
                }
            }
            81..=83 => {
                let n = self.rng.below(self.nodes.len() as u64) as usize;
                if self.nodes[n].alive && self.rng.chance(self.cfg.faults.crash_pm, 30) {
                    self.nodes[n].alive = false;
                    let dead: Vec<u64> = self
                        .sessions
                        .iter()
                        .filter(|(_, s)| s.a == n || s.b == n)
                        .map(|(k, _)| *k)
                        .collect();
                    for sid in dead {
                        self.sessions.remove(&sid);
                        self.report.sessions_aborted += 1;
                    }
                    self.net.retain(|m| self.sessions.contains_key(&m.sid));
                    self.log("crash", n as u64, 0);
                } else if !self.nodes[n].alive {
                    self.nodes[n].alive = true;
                    let clock = self.nodes[n].clock.clone();
                    self.nodes[n].store.restart(clock);
                    self.log("restart", n as u64, 0);
                }
            }
            84 => {
                if self.nodes.len() < self.cfg.max_nodes {
                    let active = self.active_nodes();
                    if let Some(&inviter) = self.rng.choose(&active) {
                        self.join(inviter)?;
                    }
                }
            }
            85 => self.remove_random()?,
            86..=88 => self.adversary_step()?,
            _ => {
                self.deliver_next()?;
            }
        }
        Ok(())
    }

    fn revive_all(&mut self) {
        for n in 0..self.nodes.len() {
            if !self.nodes[n].alive {
                self.nodes[n].alive = true;
                let clock = self.nodes[n].clock.clone();
                self.nodes[n].store.restart(clock);
            }
        }
    }

    /// One fault-free exchange between every pair that may talk.
    fn all_pairs_round(&mut self) -> Res<()> {
        self.now += 60_000;
        self.set_clocks();
        let n = self.nodes.len();
        for a in 0..n {
            for b in a + 1..n {
                if self.can_talk(a, b) {
                    self.run_sync(a, b)?;
                }
            }
        }
        Ok(())
    }

    fn quiesce(&mut self) -> Res<()> {
        self.groups = None;
        self.net.clear();
        self.sessions.clear();
        self.revive_all();
        // Stores that inject their own faults (SQLite: crashes between
        // commit chunks) first catch up under them: the large, many-origin
        // commits of this phase are where a partial commit matters most.
        // Crashed devices restart from disk between rounds.
        if self.nodes.iter().any(|x| x.store.injects_faults()) {
            for _ in 0..CRASHY_CATCH_UP_ROUNDS {
                self.all_pairs_round()?;
                self.revive_all();
            }
        }
        for n in 0..self.nodes.len() {
            self.nodes[n].store.calm();
        }
        let mut stable = 0;
        let mut last_fp: Option<Vec<(crate::mesh::vv::VersionVector, usize)>> = None;
        for round in 0..MAX_QUIESCE_ROUNDS {
            self.report.quiesce_rounds = round + 1;
            self.all_pairs_round()?;
            let fp: Vec<_> = self
                .nodes
                .iter()
                .map(|x| (x.store.vv().clone(), x.store.all_items().len()))
                .collect();
            if last_fp.as_ref() == Some(&fp) {
                stable += 1;
                if stable >= 2 {
                    return Ok(());
                }
            } else {
                stable = 0;
            }
            last_fp = Some(fp);
        }
        self.fail(
            "liveness",
            "devices did not stop changing during quiescence",
        )
    }

    fn check_invariants<O: OracleModel>(&mut self) -> Res<()> {
        // Who is still in contact: active in the genesis device's roster.
        let reference = self.nodes[0].store.state().roster.clone();
        let active: Vec<usize> = (0..self.nodes.len())
            .filter(|&n| reference.is_active(&self.nodes[n].id) && self.nodes[n].clone_of.is_none())
            .filter(|&n| self.nodes.iter().all(|x| x.clone_of != Some(n)))
            .collect();

        // 3. incremental views == rebuild, on every device.
        for (i, node) in self.nodes.iter().enumerate() {
            let rebuilt = match node.store.rebuild_views() {
                Ok(s) => s,
                Err(e) => return self.fail("3 rebuild", format!("node {i}: {e}")),
            };
            if &rebuilt != node.store.state() {
                return self.fail(
                    "3 rebuild",
                    format!("node {i}: incremental views differ from a rebuild"),
                );
            }
            if let Err(e) = node.store.check_durable() {
                return self.fail("3 rebuild", format!("node {i}: {e}"));
            }
        }

        // 1. commit-only VV: every held item is covered by the VV and matches
        //    the dot log (forked origins excepted).
        for &i in &active {
            let st = &self.nodes[i].store;
            for item in st.all_items() {
                let b = item.decode_unverified().expect("held items decode");
                if st.state().roster.fork_seq(&b.origin).is_some() {
                    continue;
                }
                if b.seq > st.vv().get(&b.origin)
                    || st.dot_hash(&b.origin, b.seq).ok().flatten() != Some(item.hash())
                {
                    return self.fail(
                        "1 commit-only VV",
                        format!("node {i} holds {}:{} outside its log", b.origin, b.seq),
                    );
                }
            }
        }

        // 6. no forgery; huge seqs never advance a VV.
        for (i, node) in self.nodes.iter().enumerate() {
            if self.forged.iter().any(|h| node.store.holds(h)) {
                return self.fail("6 no forgery", format!("node {i} holds a forged item"));
            }
            for (o, s) in &self.huge {
                if node.store.vv().get(o) >= *s {
                    return self.fail(
                        "6 no forgery",
                        format!("node {i} advanced {o} to a forged huge seq"),
                    );
                }
            }
        }

        // 2. convergence among the devices in contact...
        let views: Vec<ExpectedState> = active
            .iter()
            .map(|&i| self.nodes[i].store.state().expected())
            .collect();
        for (k, v) in views.iter().enumerate().skip(1) {
            if *v != views[0] {
                return self.fail(
                    "2 convergence",
                    format!(
                        "node {} differs from node {}: {}{}",
                        active[k],
                        active[0],
                        diff(&views[0], v),
                        self.roster_detail(&[active[0], active[k]])
                    ),
                );
            }
        }

        // 4. removal exclusion: no LWW winner comes from above a cutoff.
        for &i in &active {
            let st = self.nodes[i].store.state();
            let r = &st.roster;
            let bad = |o: &DeviceId, s: u64| {
                r.cutoff(o).is_some_and(|c| s > c) || r.fork_seq(o).is_some_and(|f| s >= f)
            };
            for k in st.projects.keys() {
                if let Some((o, e)) = st.projects.register(k).and_then(|x| x.winner(r)) {
                    if bad(o, e.seq) {
                        return self.fail(
                            "4 removal exclusion",
                            format!("node {i}: project winner {o}:{}", e.seq),
                        );
                    }
                }
            }
        }

        // 5. fork detection. For each cloned device:
        //    - `true_d`: the first seq at which the source's and the clone's
        //      own dot logs differ — where the branches really diverged;
        //    - `visible`: the first seq at which devices in contact can see two
        //      hashes for one dot (their dot logs, and the items they hold).
        //      The earliest divergent dots may never reach a device in contact
        //      (both branch-holders cut off or forked), so this can be later.
        //    Every device in contact must record a fork seq f with
        //    true_d <= f <= visible: never earlier than the real divergence
        //    (no false report), and never later than devices in contact can
        //    see it. (f < visible is legitimate: a device that saw more, and
        //    has since been cut off, may have reported it while in contact.)
        let lost = self.lost_items(&active);
        let mut forked: BTreeMap<DeviceId, (u64, Option<u64>)> = BTreeMap::new();
        for node in &self.nodes {
            let Some(src) = node.clone_of else { continue };
            let (a, b) = (&self.nodes[src].store, &node.store);
            let o = node.id;
            let top = a.vv().get(&o).min(b.vv().get(&o));
            // If one log extends the other there is no divergence (yet).
            let Some(true_d) = (1..=top)
                .find(|s| a.dot_hash(&o, *s).ok().flatten() != b.dot_hash(&o, *s).ok().flatten())
            else {
                continue;
            };
            let mut seen: BTreeMap<u64, BTreeSet<ItemHash>> = BTreeMap::new();
            for &i in &active {
                let st = &self.nodes[i].store;
                let logged = match st.dot_hashes(&o, 0, st.vv().get(&o)) {
                    Ok(l) => l,
                    Err(e) => return self.fail("5 fork detection", format!("node {i}: {e}")),
                };
                for (s, h) in logged {
                    seen.entry(s).or_default().insert(h);
                }
                let held = match st.held_items(&o, 0, u64::MAX) {
                    Ok(h) => h,
                    Err(e) => return self.fail("5 fork detection", format!("node {i}: {e}")),
                };
                for it in held {
                    let b = it.decode_unverified().expect("held items decode");
                    seen.entry(b.seq).or_default().insert(it.hash());
                }
            }
            let visible = seen.iter().find(|(_, hs)| hs.len() > 1).map(|(s, _)| *s);
            forked.insert(o, (true_d, visible));
        }
        for &i in &active {
            let r = &self.nodes[i].store.state().roster;
            for (o, f) in r.forks() {
                match forked.get(o) {
                    Some((true_d, _)) if f >= true_d => {}
                    other => {
                        return self.fail(
                            "5 fork detection",
                            format!("node {i} records {o} forked at {f}; divergence {other:?}"),
                        )
                    }
                }
            }
            for (o, (_, visible)) in &forked {
                // Detection is owed only for a device still in contact — a
                // member that is not removed. A removed device, or one whose
                // adder was cut off before adding it, is refused by everyone,
                // so its branches may never meet.
                let in_contact = reference.is_member(o) && !reference.is_removed(o);
                if let Some(v) = visible {
                    if in_contact && r.fork_seq(o).is_none_or(|f| f > *v) {
                        return self.fail(
                            "5 fork detection",
                            format!(
                                "node {i} has fork seq {:?} for {o}; visible divergence {v}",
                                r.fork_seq(o)
                            ),
                        );
                    }
                }
            }
        }

        // 7. cap safety, on every device in contact.
        for (k, v) in views.iter().enumerate() {
            if let Err(e) = cap_safety(v) {
                return self.fail("7 cap safety", format!("node {}: {e}", active[k]));
            }
        }

        // 2. ...and convergence to the independent oracle.
        if self.cfg.check_oracle {
            let mut oracle = O::new(&self.genesis);
            for it in &self.minted {
                if lost.contains(&it.hash()) {
                    oracle.observe_unreached(it);
                } else {
                    oracle.observe_minted(it);
                }
            }
            let expected = oracle.expected();
            if let Err(e) = cap_safety(&expected) {
                return self.fail("7 cap safety", format!("oracle: {e}"));
            }
            if let Some(v) = views.first() {
                if *v != expected {
                    return self.fail(
                        "2 oracle",
                        format!("devices differ from the oracle: {}", diff(&expected, v)),
                    );
                }
            }
        }
        Ok(())
    }

    /// The roster items each of `nodes` holds, for a convergence failure.
    fn roster_detail(&self, nodes: &[usize]) -> String {
        let mut out = String::new();
        for &n in nodes {
            let st = &self.nodes[n].store;
            out.push_str(&format!("\n  node {n} vv {:?}:", st.vv()));
            for it in st.all_items() {
                let Ok(b) = it.decode_unverified() else {
                    continue;
                };
                if b.kind.starts_with("roster.") || b.kind == "fork.report" {
                    let logged = st.dot_hash(&b.origin, b.seq).ok().flatten() == Some(it.hash());
                    out.push_str(&format!(
                        "\n    {} {}:{} key {} logged={logged}",
                        b.kind,
                        &b.origin.to_hex()[..8],
                        b.seq,
                        &b.key[..8.min(b.key.len())]
                    ));
                }
            }
        }
        out
    }

    /// Items that never reached a device still in contact (PROTOCOL.md §5.6):
    /// neither the item nor its dot hash. An item superseded at its minter
    /// before it was sent is not lost when its hash travelled in the dot list
    /// of a later item — leaving it out would open a gap in the origin's
    /// dense prefix that no device sees.
    fn lost_items(&self, active: &[usize]) -> HashSet<ItemHash> {
        let ok: BTreeSet<usize> = active.iter().copied().collect();
        self.minted
            .iter()
            .filter(|i| {
                let h = i.hash();
                if self
                    .seen_by
                    .get(&h)
                    .is_some_and(|s| s.iter().any(|n| ok.contains(n)))
                {
                    return false;
                }
                let Ok(b) = i.decode_unverified() else {
                    return true;
                };
                !active.iter().any(|&n| {
                    self.nodes[n]
                        .store
                        .dot_hash(&b.origin, b.seq)
                        .ok()
                        .flatten()
                        == Some(h)
                })
            })
            .map(|i| i.hash())
            .collect()
    }
}

fn cap_safety(v: &ExpectedState) -> Result<(), String> {
    for ((cap, month), m) in &v.cap_months {
        let supply = i128::try_from(m.total_minted).unwrap_or(i128::MAX)
            - i128::try_from(m.total_burned).unwrap_or(i128::MAX);
        let used = i128::try_from(m.total_used).unwrap_or(i128::MAX);
        if used > supply {
            return Err(format!(
                "{cap}/{month}: used {used} > minted − burned {supply}"
            ));
        }
        for (d, r) in &m.devices {
            if r.avail < 0 {
                return Err(format!("{cap}/{month}: {d} has avail {}", r.avail));
            }
        }
    }
    Ok(())
}

/// A short description of the first difference between two states.
fn diff(a: &ExpectedState, b: &ExpectedState) -> String {
    macro_rules! field {
        ($f:ident) => {
            if a.$f != b.$f {
                let ka: BTreeSet<_> = a.$f.keys().collect();
                let kb: BTreeSet<_> = b.$f.keys().collect();
                if ka != kb {
                    return format!(
                        "{}: keys differ ({:?} vs {:?})",
                        stringify!($f),
                        ka.symmetric_difference(&kb).collect::<Vec<_>>(),
                        ""
                    );
                }
                for (k, va) in &a.$f {
                    if b.$f.get(k) != Some(va) {
                        return format!(
                            "{} at {:?}: {:?} vs {:?}",
                            stringify!($f),
                            k,
                            va,
                            b.$f.get(k)
                        );
                    }
                }
            }
        };
    }
    field!(devices);
    field!(device_info);
    field!(settings);
    field!(projects);
    field!(usage);
    field!(caps);
    field!(cap_months);
    if a.shares != b.shares {
        for (k, va) in &a.shares {
            if b.shares.get(k) != Some(va) {
                let show =
                    |s: Option<&ExpectedShare>| format!("{:?}", s.map(std::mem::discriminant));
                return format!(
                    "shares at {k:?}: {} vs {}",
                    show(Some(va)),
                    show(b.shares.get(k))
                );
            }
        }
        return "shares: keys differ".into();
    }
    "no difference".into()
}

/// Run one seed to completion on in-memory stores.
pub fn run<O: OracleModel>(cfg: &SimConfig) -> Result<SimReport, SimFailure> {
    run_with::<O, MemFactory>(cfg, MemFactory)
}

/// Run one seed to completion on the stores `factory` creates.
pub fn run_with<O: OracleModel, F: StoreFactory>(
    cfg: &SimConfig,
    factory: F,
) -> Result<SimReport, SimFailure> {
    let mut w = World::new(cfg, factory)?;
    for _ in 0..cfg.steps {
        w.step()?;
    }
    w.quiesce()?;
    w.check_invariants::<O>()?;
    let mut report = w.report.clone();
    report.events = w.event;
    report.nodes = w.nodes.len();
    report.trace_hash = Hash32(*w.trace.finalize().as_bytes());
    Ok(report)
}

/// The shortest step count (≤ `cfg.steps`) at which `cfg.seed` still fails,
/// found by bisection; `None` if the full run passes.
pub fn shrink<O: OracleModel>(cfg: &SimConfig) -> Option<SimFailure> {
    let mut failing = run::<O>(cfg).err()?;
    let (mut lo, mut hi) = (0u64, cfg.steps);
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        let probe = SimConfig {
            steps: mid,
            ..cfg.clone()
        };
        match run::<O>(&probe) {
            Err(f) => {
                hi = mid;
                failing = f;
            }
            Ok(_) => lo = mid,
        }
    }
    Some(failing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_run_without_faults_converges() {
        let cfg = SimConfig {
            faults: Faults {
                drop_pm: 0,
                dup_pm: 0,
                reorder_pm: 0,
                max_delay_ms: 20,
                partition_pm: 0,
                crash_pm: 0,
            },
            adversary: Adversary::default(),
            check_oracle: false,
            ..SimConfig::from_seed(7, 400)
        };
        let r = run::<NoOracle>(&cfg).unwrap_or_else(|f| panic!("{f}"));
        assert!(r.mints > 0 && r.sessions_done > 0, "{r:?}");
    }
}
