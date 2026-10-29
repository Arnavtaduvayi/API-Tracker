//! The spend-cap scenario family (Increment 07, DESIGN §D21): 3-5 devices
//! on real SQLite stores sharing one cap, running the **real** policy: the
//! reconciler (`caps::reconcile`), the local spend check (`caps::try_spend`,
//! whose allowed spend is then recorded in the device's gateway rollup, as
//! the gateway would) and rights requests carried as `Direct` frames inside
//! real `proto::Session` exchanges and answered by `caps::grant`.
//!
//! Time runs from 2027-01-18 in two-hour steps, so every run crosses day 20
//! (advance minting) and, with enough steps, the month boundary. A seed
//! picks the injections: partitions of every shape (always), the owner
//! offline across the boundary, two concurrent lowers on devices that
//! cannot see each other, a local override on a partitioned non-owner, the
//! owner's removal (the freeze), and a member forging an over-transfer it
//! has no rights for.
//!
//! Checked on every device's own view at every step: `Σ used ≤ minted −
//! burned` (overrides are mints), no device's own available amount below
//! zero, rights conservation (`Σ avail + Σ used = supply`), honest devices
//! never clamped, the forger never honoured beyond what it held. At the
//! end, after a fault-free quiescence: convergence of every device to the
//! independent oracle (which saw every item minted), cap safety in the
//! oracle's view, the lower settled, and liveness: no device below its
//! request threshold while another holds rights it could give.
//!
//! A failure prints `MESH_SIM_SEED=<seed> MESH_SIM_STEPS=<steps>`.

use crate::mesh::caps::policy;
use crate::mesh::caps::view::{CapInfo, Ledger};
use crate::mesh::caps::{self, AssumeNotRunning, RightsAsk, SpendDecision};
use crate::mesh::chain::Hash32;
use crate::mesh::clock::{Clock, ManualClock};
use crate::mesh::dot::{CapId, DeviceId, MeshId, MeshProjectId};
use crate::mesh::kinds::{
    CapRights, Day, ItemKind, Month, ProjectMeta, Recipient, RosterAdd, RosterRemove,
};
use crate::mesh::proto::{Action, DirectMsg, Frame, Limits, Session};
use crate::mesh::sign::{derive_device_id, PublicKeyBytes, SigningKeyPair};
use crate::mesh::sim::oracle::Oracle;
use crate::mesh::sim::oracle_api::OracleModel;
use crate::mesh::sim::rng::SplitMix64;
use crate::mesh::sim::sqlite::{SimSqlite, SqliteFactory};
use crate::mesh::sim::world::{cap_safety, diff, StoreFactory};
use crate::mesh::sqlite_store::SqliteStore;
use crate::mesh::store::{Draft, GenesisInfo, HlcPolicy, MeshStore};
use rusqlite::params;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

/// 2027-01-18T00:00:00Z.
const T0: u64 = 1_800_230_400_000;
const STEP_MS: u64 = 2 * 3_600_000;
/// The cap: $1 a month, so spends of up to 5 cents exhaust it.
const MONTHLY: u64 = 1_000_000;
const QUIESCE_ROUNDS: u32 = 8;
const QUIESCE_STEP_MS: u64 = 10 * 60_000;
const LOCAL_PROJECT: &str = "local-app";

/// What a run injects besides partitions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapsInjections {
    pub owner_offline_across_boundary: bool,
    pub concurrent_lowers: bool,
    pub partitioned_override: bool,
    pub owner_removal: bool,
    pub forged_transfer: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsConfig {
    pub seed: u64,
    pub steps: u64,
    /// Honest devices (3-5); a forger is one more.
    pub devices: usize,
    pub inject: CapsInjections,
}

impl CapsConfig {
    /// 3-5 devices; each injection in a third to a half of all seeds.
    pub fn from_seed(seed: u64, steps: u64) -> Self {
        let mut r = SplitMix64::new(seed ^ 0xCA95_5EED_0000_0007);
        Self {
            seed,
            steps,
            devices: 3 + r.below(3) as usize,
            inject: CapsInjections {
                owner_offline_across_boundary: r.chance(1, 2),
                concurrent_lowers: r.chance(1, 2),
                partitioned_override: r.chance(1, 2),
                owner_removal: r.chance(1, 3),
                forged_transfer: r.chance(1, 3),
            },
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapsReport {
    pub trace_hash: Hash32,
    pub exchanges: u64,
    pub spends_allowed: u64,
    pub spends_refused: u64,
    pub spent_micros: u64,
    pub grants: u64,
    pub granted_micros: u64,
    pub lowers: u64,
    pub overrides: u64,
    pub mints: u64,
    /// Whether the boundary check for an offline owner ran.
    pub boundary_checked: bool,
    pub frozen: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsFailure {
    pub seed: u64,
    pub steps: u64,
    pub step: u64,
    pub invariant: &'static str,
    pub detail: String,
}

impl fmt::Display for CapsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MESH_SIM_SEED={} MESH_SIM_STEPS={}: caps invariant '{}' failed at step {}: {}",
            self.seed, self.steps, self.invariant, self.step, self.detail
        )
    }
}

type Res<T> = Result<T, CapsFailure>;

struct Dev {
    id: DeviceId,
    key: SigningKeyPair,
    noise_pub: PublicKeyBytes,
    seal_pub: PublicKeyBytes,
    store: SimSqlite,
    clock: Arc<ManualClock>,
    skew_ms: i64,
    alive: bool,
    removed: bool,
    forger: bool,
    group: u8,
}

/// The steps at which injections happen.
#[derive(Default)]
struct Schedule {
    offline: Option<(u64, u64)>,
    lowers_at: Option<u64>,
    override_at: Option<u64>,
    removal_at: Option<u64>,
    forge_at: Option<u64>,
}

struct CapsWorld {
    cfg: CapsConfig,
    rng: SplitMix64,
    now: u64,
    devs: Vec<Dev>,
    project: MeshProjectId,
    cap: CapId,
    oracle: Oracle,
    trace: blake3::Hasher,
    step: u64,
    schedule: Schedule,
    forged: Option<(DeviceId, Month, u64)>,
    report: CapsReport,
}

fn step_of(ms: u64) -> u64 {
    ms.saturating_sub(T0) / STEP_MS
}

impl CapsWorld {
    fn fail<T>(&self, invariant: &'static str, detail: impl Into<String>) -> Res<T> {
        Err(CapsFailure {
            seed: self.cfg.seed,
            steps: self.cfg.steps,
            step: self.step,
            invariant,
            detail: detail.into(),
        })
    }

    fn log(&mut self, what: &str, a: u64, b: u64) {
        self.trace.update(what.as_bytes());
        self.trace.update(&a.to_le_bytes());
        self.trace.update(&b.to_le_bytes());
    }

    fn store(&self, n: usize) -> &SqliteStore {
        self.devs[n].store.sqlite()
    }

    fn honest(&self) -> Vec<usize> {
        (0..self.devs.len())
            .filter(|&n| !self.devs[n].forger && !self.devs[n].removed)
            .collect()
    }

    fn up(&self) -> Vec<usize> {
        (0..self.devs.len())
            .filter(|&n| self.devs[n].alive && !self.devs[n].removed)
            .collect()
    }

    /// Hand every newly minted item to the oracle.
    fn drain(&mut self) {
        for n in 0..self.devs.len() {
            let items = std::mem::take(&mut self.devs[n].store.sqlite_mut().hooks().minted);
            self.report.mints += items.len() as u64;
            for item in items {
                self.oracle.observe_minted(&item);
            }
        }
    }

    fn set_clocks(&mut self) {
        for d in &self.devs {
            d.clock.set(self.now.saturating_add_signed(d.skew_ms));
        }
    }

    fn new(cfg: &CapsConfig, base: &Path) -> Res<Self> {
        let mut rng = SplitMix64::new(cfg.seed);
        let mut factory = SqliteFactory::new(base, cfg.seed).commit_crash_pm(0);
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut b);
        let mesh_id = MeshId::from_bytes(b);
        rng.fill_bytes(&mut b);
        let project = MeshProjectId::from_bytes(b);
        let n = cfg.devices + usize::from(cfg.inject.forged_transfer);
        let mut keys = Vec::new();
        for i in 0..n {
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);
            let key = SigningKeyPair::from_secret_bytes(&secret);
            let (mut nb, mut sb) = ([0u8; 32], [0u8; 32]);
            rng.fill_bytes(&mut nb);
            rng.fill_bytes(&mut sb);
            let skew = if i == 0 {
                0
            } else {
                rng.below(4_001) as i64 - 2_000
            };
            keys.push((key, PublicKeyBytes(nb), PublicKeyBytes(sb), skew));
        }
        let ids: Vec<DeviceId> = keys
            .iter()
            .map(|(k, nb, sb, _)| derive_device_id(&k.public_key(), nb, sb))
            .collect();
        let genesis = GenesisInfo {
            mesh_id,
            genesis: ids[0],
        };
        let mut devs = Vec::new();
        for (i, (key, noise_pub, seal_pub, skew_ms)) in keys.into_iter().enumerate() {
            let clock = Arc::new(ManualClock::new(T0.saturating_add_signed(skew_ms)));
            let mut store = factory.create(genesis, ids[i], clock.clone());
            store.sqlite().no_sync_for_sim().expect("no sync");
            store.sqlite_mut().hooks().record_mints = true;
            devs.push(Dev {
                id: ids[i],
                key,
                noise_pub,
                seal_pub,
                store,
                clock,
                skew_ms,
                alive: true,
                removed: false,
                forger: i == cfg.devices,
                group: 0,
            });
        }
        let mut schedule = Schedule::default();
        let steps = cfg.steps.max(40);
        if cfg.inject.owner_offline_across_boundary {
            // From Jan 27 to Feb 4: offline at the boundary, but online
            // between day 20 and its departure.
            schedule.offline = Some((step_of(T0 + 9 * 86_400_000), step_of(T0 + 17 * 86_400_000)));
        }
        if cfg.inject.concurrent_lowers {
            schedule.lowers_at = Some(rng.range_inclusive(20, steps * 2 / 3));
        }
        if cfg.inject.partitioned_override {
            schedule.override_at = Some(rng.range_inclusive(10, steps - 10));
        }
        if cfg.inject.owner_removal {
            schedule.removal_at = Some(steps * 3 / 4 + rng.below(steps / 8 + 1));
        }
        if cfg.inject.forged_transfer {
            schedule.forge_at = Some(rng.range_inclusive(5, steps / 2));
        }
        let mut w = Self {
            cfg: cfg.clone(),
            rng,
            now: T0,
            devs,
            project,
            cap: CapId::MIN,
            oracle: Oracle::new(&genesis),
            trace: blake3::Hasher::new(),
            step: 0,
            schedule,
            forged: None,
            report: CapsReport::default(),
        };
        w.setup()?;
        Ok(w)
    }

    fn roster_add(&self, target: usize) -> RosterAdd {
        let t = &self.devs[target];
        RosterAdd {
            device: t.id,
            name: format!("device {target}"),
            sign_pub: t.key.public_key(),
            noise_pub: t.noise_pub,
            seal_pub: t.seal_pub,
            added_by: self.devs[0].id,
        }
    }

    fn mint_raw<K: ItemKind>(&mut self, n: usize, value: &K, hlc: HlcPolicy) -> Res<()> {
        let d = &mut self.devs[n];
        if let Err(e) = d.store.sqlite_mut().mint(&d.key, Draft::of(value, hlc)) {
            return self.fail("mint", format!("device {n}: {}: {e}", K::KIND));
        }
        self.drain();
        Ok(())
    }

    fn setup(&mut self) -> Res<()> {
        for t in 0..self.devs.len() {
            let add = self.roster_add(t);
            self.mint_raw(0, &add, HlcPolicy::Now)?;
        }
        let meta = ProjectMeta {
            project: self.project,
            name: "app".into(),
            archived: false,
            merged_into: None,
        };
        self.mint_raw(0, &meta, HlcPolicy::Now)?;
        for n in self.honest() {
            let conn = self.store(n).connection();
            let r = conn
                .execute(
                    "INSERT INTO projects (id, name, created_at, updated_at, wrapped_project_key,
                         key_wrap_mode)
                     VALUES (?1, 'app', 'x', 'x', X'00', 'vault')",
                    [LOCAL_PROJECT],
                )
                .and_then(|_| {
                    conn.execute(
                        "INSERT INTO mesh_project_bindings (local_project_id, mesh_project_id,
                             bound_at)
                         VALUES (?1, ?2, 'x')",
                        params![LOCAL_PROJECT, self.project.to_hex()],
                    )
                });
            if let Err(e) = r {
                return self.fail("setup", format!("device {n}: {e}"));
            }
        }
        self.full_round(false)?;
        self.full_round(false)?;
        let d = &mut self.devs[0];
        let created = caps::create(
            d.store.sqlite_mut(),
            &d.key,
            &AssumeNotRunning,
            &self.project,
            MONTHLY,
        );
        match created {
            Ok(c) => self.cap = c.cap_id,
            Err(e) => return self.fail("setup", format!("create: {e}")),
        }
        self.drain();
        self.full_round(false)
    }

    // ------------------------------------------------------------- exchanges

    fn route(
        &mut self,
        n: usize,
        acts: Vec<Action>,
        out: &mut Vec<Frame>,
        held: &mut Vec<RightsAsk>,
    ) -> Res<()> {
        for act in acts {
            match act {
                Action::Send(f) => out.push(f),
                Action::Commit(batch) => {
                    if let Err(e) = self.devs[n].store.sqlite_mut().commit(batch) {
                        return self.fail("commit", format!("device {n}: {e}"));
                    }
                }
                Action::Direct(DirectMsg::RightsRequest {
                    cap,
                    month,
                    want,
                    reclaim,
                }) => held.push(RightsAsk {
                    cap,
                    month,
                    want,
                    reclaim,
                }),
                Action::Direct(_) | Action::Close(_) => {}
                Action::ForkDetected(ev) => {
                    return self.fail("fork", format!("device {n}: {:?}", ev.origin));
                }
            }
        }
        Ok(())
    }

    fn asks(&mut self, n: usize, peer: DeviceId, session: &mut Session) -> Res<Vec<Action>> {
        if self.devs[n].forger {
            return Ok(Vec::new());
        }
        match caps::rights_requests(self.store(n), &peer) {
            Ok(asks) => Ok(asks
                .into_iter()
                .flat_map(|a| {
                    session.direct(DirectMsg::RightsRequest {
                        cap: a.cap,
                        month: a.month,
                        want: a.want,
                        reclaim: a.reclaim,
                    })
                })
                .collect()),
            Err(e) => self.fail("rights requests", format!("device {n}: {e}")),
        }
    }

    /// One complete session between `a` and `b`. With `asks`, each side
    /// sends its rights requests and answers the other's afterwards.
    fn exchange(&mut self, a: usize, b: usize, asks: bool) -> Res<()> {
        let (ia, ib) = (self.devs[a].id, self.devs[b].id);
        let mut sa = Session::new(Limits::default(), Some(ib));
        let mut sb = Session::new(Limits::default(), Some(ia));
        let (mut to_a, mut to_b) = (Vec::new(), Vec::new());
        let (mut held_a, mut held_b) = (Vec::new(), Vec::new());
        let acts = sa.start(self.store(a));
        self.route(a, acts, &mut to_b, &mut held_a)?;
        if asks {
            let acts = self.asks(a, ib, &mut sa)?;
            self.route(a, acts, &mut to_b, &mut held_a)?;
        }
        let acts = sb.start(self.store(b));
        self.route(b, acts, &mut to_a, &mut held_b)?;
        if asks {
            let acts = self.asks(b, ia, &mut sb)?;
            self.route(b, acts, &mut to_a, &mut held_b)?;
        }
        for _ in 0..10_000 {
            if to_a.is_empty() && to_b.is_empty() {
                break;
            }
            for f in std::mem::take(&mut to_b) {
                let acts = sb.on_frame(f, self.devs[b].store.sqlite());
                self.route(b, acts, &mut to_a, &mut held_b)?;
            }
            for f in std::mem::take(&mut to_a) {
                let acts = sa.on_frame(f, self.devs[a].store.sqlite());
                self.route(a, acts, &mut to_b, &mut held_a)?;
            }
        }
        if !(sa.is_closed() && sb.is_closed()) {
            return self.fail("exchange", format!("{a}<->{b} did not finish"));
        }
        self.report.exchanges += 1;
        self.log("exchange", a as u64, b as u64);
        for (n, peer) in [(a, ib), (b, ia)] {
            let at = crate::mesh::caps::period::rfc3339_of(self.devs[n].clock.now_ms());
            let r = self.store(n).connection().execute(
                "INSERT INTO mesh_exchange_log (peer_device, at, direction, result)
                 VALUES (?1, ?2, 'outbound', 'ok')",
                params![peer.to_hex(), at],
            );
            if let Err(e) = r {
                return self.fail("exchange log", e.to_string());
            }
        }
        for (n, held, peer) in [(a, held_a, ib), (b, held_b, ia)] {
            if self.devs[n].forger {
                continue;
            }
            for ask in held {
                let d = &mut self.devs[n];
                match caps::grant(d.store.sqlite_mut(), &d.key, &AssumeNotRunning, &peer, ask) {
                    Ok(0) => {}
                    Ok(g) => {
                        self.report.grants += 1;
                        self.report.granted_micros += g;
                        self.log("grant", n as u64, g);
                    }
                    Err(e) => return self.fail("grant", format!("device {n}: {e}")),
                }
            }
        }
        self.drain();
        Ok(())
    }

    /// Every pair of up devices exchanges once.
    fn full_round(&mut self, asks: bool) -> Res<()> {
        let up = self.up();
        for (i, &a) in up.iter().enumerate() {
            for &b in &up[i + 1..] {
                self.exchange(a, b, asks)?;
            }
        }
        Ok(())
    }

    // -------------------------------------------------------------- workload

    fn reconcile(&mut self, n: usize) -> Res<()> {
        let d = &mut self.devs[n];
        if let Err(e) = caps::reconcile(d.store.sqlite_mut(), &d.key, &AssumeNotRunning) {
            return self.fail("reconcile", format!("device {n}: {e}"));
        }
        self.drain();
        Ok(())
    }

    /// The gateway's half, as the workload: ask `try_spend`, and on yes,
    /// record the spend in the rollup the way the gateway writer does.
    fn spend(&mut self, n: usize, amount: u64) -> Res<()> {
        let now = self.devs[n].clock.now_ms();
        let month = crate::mesh::caps::period::month_of(now);
        let decision = match caps::try_spend(self.store(n), &self.cap, month, amount) {
            Ok(d) => d,
            Err(e) => return self.fail("try_spend", format!("device {n}: {e}")),
        };
        match decision {
            SpendDecision::Allowed { .. } => {
                let day = Day::from_unix_ms(now).to_string();
                let r = self.store(n).connection().execute(
                    "INSERT INTO gateway_usage_daily (day, provider_id, project_id, model,
                         request_count, usage_event_count, estimated_cost_micros, updated_at,
                         split_known)
                     VALUES (?1, 'openai', ?2, 'gpt-x', 1, 1, ?3, 'x', 1)
                     ON CONFLICT(day, provider_id, project_id, model) DO UPDATE SET
                         request_count = request_count + 1,
                         usage_event_count = usage_event_count + 1,
                         estimated_cost_micros = estimated_cost_micros + excluded.estimated_cost_micros",
                    params![day, LOCAL_PROJECT, amount as i64],
                );
                if let Err(e) = r {
                    return self.fail("spend", e.to_string());
                }
                self.report.spends_allowed += 1;
                self.report.spent_micros += amount;
                self.log("spend", n as u64, amount);
            }
            SpendDecision::Refused { .. } => {
                self.report.spends_refused += 1;
                self.log("refused", n as u64, amount);
            }
        }
        Ok(())
    }

    fn partition(&mut self, groups: u64) {
        for n in 0..self.devs.len() {
            self.devs[n].group = self.rng.below(groups) as u8;
        }
        self.log("partition", groups, 0);
    }

    fn heal(&mut self) {
        for d in &mut self.devs {
            d.group = 0;
        }
        self.log("heal", 0, 0);
    }

    fn scheduled(&mut self) -> Res<()> {
        let s = self.step;
        let owner = 0;
        if let Some((from, until)) = self.schedule.offline {
            if s == from && self.devs[owner].alive && !self.devs[owner].removed {
                // Make sure next month's shares reached everyone first.
                self.heal();
                self.full_round(true)?;
                self.full_round(false)?;
                self.devs[owner].alive = false;
                self.log("owner offline", s, 0);
            }
            if s == until && !self.devs[owner].removed {
                self.devs[owner].alive = true;
                self.log("owner online", s, 0);
            }
        }
        if self.schedule.lowers_at == Some(s) {
            let honest: Vec<usize> = self
                .honest()
                .into_iter()
                .filter(|&n| self.devs[n].alive)
                .collect();
            if honest.len() >= 2 {
                let x = honest[self.rng.below(honest.len() as u64) as usize];
                let mut y = x;
                while y == x {
                    y = honest[self.rng.below(honest.len() as u64) as usize];
                }
                self.partition(2);
                self.devs[x].group = 0;
                self.devs[y].group = 1;
                for n in [x, y] {
                    let pct = 30 + self.rng.below(60);
                    let d = &mut self.devs[n];
                    let now = d.clock.now_ms();
                    let month = crate::mesh::caps::period::month_of(now);
                    let current = crate::mesh::caps::view::scheduled_target(
                        d.store.sqlite().state(),
                        &self.cap,
                        month,
                    )
                    .unwrap_or(0);
                    let target = (current * pct / 100).max(MONTHLY / 10);
                    if target < current {
                        match caps::lower(
                            d.store.sqlite_mut(),
                            &d.key,
                            &AssumeNotRunning,
                            &self.cap,
                            target,
                        ) {
                            Ok(_) => {
                                self.report.lowers += 1;
                                self.log("lower", n as u64, target);
                            }
                            Err(e) => return self.fail("lower", format!("device {n}: {e}")),
                        }
                    }
                }
                self.drain();
            }
        }
        if self.schedule.override_at == Some(s) {
            let others: Vec<usize> = self
                .honest()
                .into_iter()
                .filter(|&n| n != owner && self.devs[n].alive)
                .collect();
            if let Some(&x) = self.rng.choose(&others) {
                self.partition(2);
                self.devs[owner].group = 0;
                self.devs[x].group = 1;
                let d = &mut self.devs[x];
                match caps::raise(
                    d.store.sqlite_mut(),
                    &d.key,
                    &AssumeNotRunning,
                    &self.cap,
                    MONTHLY / 5,
                ) {
                    Ok(_) => {
                        self.report.overrides += 1;
                        self.log("override", x as u64, MONTHLY / 5);
                    }
                    // The owner was removed already: the cap is frozen.
                    Err(e) if e.to_string().contains("frozen") => {}
                    Err(e) => return self.fail("override", format!("device {x}: {e}")),
                }
                self.drain();
            }
        }
        if self.schedule.forge_at == Some(s) {
            if let Some(f) = (0..self.devs.len()).find(|&n| self.devs[n].forger) {
                let victims: Vec<usize> = self.honest();
                let v = victims[self.rng.below(victims.len() as u64) as usize];
                let month = crate::mesh::caps::period::month_of(self.devs[f].clock.now_ms());
                let amount = 10 * MONTHLY;
                let rights = CapRights {
                    cap: self.cap,
                    month,
                    to: Recipient::Device(self.devs[v].id),
                    amount_micros: amount,
                    is_override: false,
                };
                self.mint_raw(f, &rights, HlcPolicy::Now)?;
                self.forged = Some((self.devs[f].id, month, amount));
                self.log("forge", f as u64, v as u64);
            }
        }
        if self.schedule.removal_at == Some(s) && !self.devs[owner].removed {
            // Decommission the owner: everyone has its whole log first, so
            // nothing it handed out is lost with it.
            self.heal();
            self.devs[owner].alive = true;
            self.full_round(true)?;
            self.full_round(false)?;
            self.devs[owner].alive = false;
            self.devs[owner].removed = true;
            let remover = 1;
            let cutoff = self.store(remover).vv().get(&self.devs[owner].id);
            let rm = RosterRemove {
                device: self.devs[owner].id,
                cutoff_seq: cutoff,
            };
            self.mint_raw(remover, &rm, HlcPolicy::Now)?;
            self.report.frozen = true;
            self.log("remove owner", cutoff, 0);
            // A frozen cap takes no new rights, not even an override.
            let d = &mut self.devs[remover];
            match caps::raise(
                d.store.sqlite_mut(),
                &d.key,
                &AssumeNotRunning,
                &self.cap,
                1,
            ) {
                Err(e) if e.to_string().contains("frozen") => {}
                other => {
                    return self.fail("freeze", format!("raise on a frozen cap: {other:?}"));
                }
            }
        }
        Ok(())
    }

    fn run_step(&mut self) -> Res<()> {
        self.now += STEP_MS;
        self.set_clocks();
        self.scheduled()?;
        if self.rng.chance(8, 100) {
            let groups = 2 + self.rng.below(2);
            self.partition(groups);
        } else if self.rng.chance(12, 100) {
            self.heal();
        }
        for n in self.up() {
            if self.devs[n].forger {
                continue;
            }
            self.reconcile(n)?;
            for _ in 0..self.rng.below(3) {
                let amount = 1 + self.rng.below(MONTHLY / 20);
                self.spend(n, amount)?;
            }
        }
        let up = self.up();
        for _ in 0..(1 + self.rng.below(4)) {
            if up.len() < 2 {
                break;
            }
            let a = up[self.rng.below(up.len() as u64) as usize];
            let b = up[self.rng.below(up.len() as u64) as usize];
            if a != b && self.devs[a].group == self.devs[b].group {
                self.exchange(a, b, true)?;
            }
        }
        self.boundary_check()?;
        self.check_views()
    }

    /// With the owner offline across the boundary, every other device holds
    /// next month's share on the first step of the new month.
    fn boundary_check(&mut self) -> Res<()> {
        let Some((from, until)) = self.schedule.offline else {
            return Ok(());
        };
        // Past the largest clock skew, so every device is in the new month.
        let month = crate::mesh::caps::period::month_of(self.now.saturating_sub(10_000));
        let started = crate::mesh::caps::period::month_of(T0);
        if self.report.boundary_checked
            || month == started
            || self.step <= from
            || self.step >= until
            || self.devs[0].alive
        {
            return Ok(());
        }
        self.report.boundary_checked = true;
        for n in self.honest().into_iter().filter(|&n| n != 0) {
            let s = self.store(n);
            let l = Ledger::of(s);
            let Some(c) = l.caps().into_iter().find(|c| c.cap_id == self.cap) else {
                return self.fail("advance minting", format!("device {n} has no cap"));
            };
            let m = l.month();
            let f = l.figures(&c, m);
            let avail = l.local_avail(&c, m, &f).unwrap_or(-1);
            if avail <= 0 {
                return self.fail(
                    "advance minting",
                    format!("device {n} holds {avail} for {m} with the owner offline"),
                );
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ invariants

    fn check_views(&self) -> Res<()> {
        for n in self.up() {
            if self.devs[n].forger {
                continue;
            }
            let s = self.store(n);
            let l = Ledger::of(s);
            for c in l.caps() {
                let m = l.month();
                for month in [Some(m), m.next()].into_iter().flatten() {
                    self.check_month(n, &l, &c, month)?;
                }
            }
        }
        Ok(())
    }

    fn check_month(&self, n: usize, l: &Ledger<'_>, c: &CapInfo, m: Month) -> Res<()> {
        let f = l.figures(c, m);
        let used = i128::try_from(f.view.total_used).unwrap_or(i128::MAX);
        if used > f.supply() {
            return self.fail(
                "7 cap safety",
                format!(
                    "device {n} {m}: used {used} > minted - burned {}",
                    f.supply()
                ),
            );
        }
        let me = f.device(&l.me);
        let local = l.local_avail(c, m, &f).unwrap_or(i128::MIN);
        if me.avail < 0 || local < 0 {
            return self.fail(
                "own avail",
                format!("device {n} {m}: view {} local {local}", me.avail),
            );
        }
        let sum: i128 = f.view.devices.values().map(|r| r.avail).sum();
        if sum + used != f.supply() {
            return self.fail(
                "conservation",
                format!(
                    "device {n} {m}: Σ avail {sum} + used {used} != supply {}",
                    f.supply()
                ),
            );
        }
        for (d, r) in &f.view.devices {
            let forger = self.forged.is_some_and(|(id, _, _)| id == *d);
            if !forger && r.clamped > 0 {
                return self.fail("clamp", format!("device {n} {m}: honest {d} clamped"));
            }
            if forger && r.sent + r.burned > r.minted + r.received {
                return self.fail(
                    "clamp",
                    format!("device {n} {m}: forger honoured beyond its rights"),
                );
            }
        }
        Ok(())
    }

    /// Fault-free quiescence, then the end-of-run checks.
    fn quiesce(&mut self) -> Res<()> {
        self.heal();
        for d in &mut self.devs {
            if !d.removed {
                d.alive = true;
            }
        }
        for _ in 0..QUIESCE_ROUNDS {
            self.now += QUIESCE_STEP_MS;
            self.set_clocks();
            for n in self.up() {
                if !self.devs[n].forger {
                    self.reconcile(n)?;
                }
            }
            self.full_round(true)?;
            self.check_views()?;
        }
        self.full_round(false)?;
        self.check_views()?;
        let expected = self.oracle.expected();
        if let Err(e) = cap_safety(&expected) {
            return self.fail("7 cap safety", format!("oracle: {e}"));
        }
        for n in self.up() {
            let got = self.store(n).state().expected();
            if got != expected {
                return self.fail(
                    "convergence",
                    format!("device {n}: {}", diff(&got, &expected)),
                );
            }
        }
        if let Some((forger, month, amount)) = self.forged {
            let m = expected.cap_months.get(&(self.cap, month));
            let r = m.and_then(|m| m.devices.get(&forger));
            let ok = r.is_some_and(|r| r.clamped + r.minted + r.received >= u128::from(amount));
            if !ok {
                return self.fail(
                    "clamp",
                    format!("the forged transfer was not clamped: {r:?}"),
                );
            }
        }
        self.settled()
    }

    /// After quiescence: a lower has settled (unless the cap is frozen and
    /// no owner is left to reclaim), and no device is below its request
    /// threshold while another could give.
    fn settled(&self) -> Res<()> {
        let up: Vec<usize> = self
            .up()
            .into_iter()
            .filter(|&n| !self.devs[n].forger)
            .collect();
        for &i in &up {
            let s = self.store(i);
            let l = Ledger::of(s);
            let Some(c) = l.caps().into_iter().find(|c| c.cap_id == self.cap) else {
                continue;
            };
            let m = l.month();
            let f = l.figures(&c, m);
            let Some(target) = f.target else {
                continue;
            };
            // Rights a device holds that does not run the policy (the
            // forger) cannot be burned or reclaimed by anyone else: the
            // decrease can settle only down to them.
            let stuck: u128 = f
                .view
                .devices
                .iter()
                .filter(|(d, _)| !up.iter().any(|&k| self.devs[k].id == **d))
                .map(|(_, r)| u128::try_from(r.avail.max(0)).unwrap_or(0))
                .sum();
            let pending = f.pending_decrease().saturating_sub(stuck);
            if pending > 0 && !c.frozen {
                return self.fail(
                    "lower settles",
                    format!("device {i}: pending decrease {pending} beyond {stuck} held by others"),
                );
            }
            if f.pending_decrease() > 0 {
                continue; // no rebalancing while the cap comes down
            }
            let n = l.active_devices().map(|a| a.len()).unwrap_or(1);
            let avail = l.local_avail(&c, m, &f).unwrap_or(0);
            if policy::wants(avail, policy::fair_share(target, n)).is_none() {
                continue;
            }
            for &j in up.iter().filter(|&&j| j != i) {
                let sj = self.store(j);
                let lj = Ledger::of(sj);
                let fj = lj.figures(&c, m);
                let nj = lj.active_devices().map(|a| a.len()).unwrap_or(1);
                let aj = lj.local_avail(&c, m, &fj).unwrap_or(0);
                let fair = policy::fair_share(fj.target.unwrap_or(0), nj);
                let give = policy::donatable(aj, fair, fj.overrides_of(&lj.me, &c.owner_device));
                if give > 0 {
                    return self.fail(
                        "liveness",
                        format!("device {i} holds {avail}, below its threshold, while device {j} could give {give}"),
                    );
                }
            }
        }
        Ok(())
    }

    fn run(mut self) -> Res<CapsReport> {
        for step in 0..self.cfg.steps {
            self.step = step;
            self.run_step()?;
        }
        self.quiesce()?;
        self.report.trace_hash = Hash32(*self.trace.finalize().as_bytes());
        Ok(self.report)
    }
}

/// Run one seed under `base` (a fresh directory the caller removes).
pub fn run_caps(cfg: &CapsConfig, base: &Path) -> Result<CapsReport, CapsFailure> {
    CapsWorld::new(cfg, base)?.run()
}
