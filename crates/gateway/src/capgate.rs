//! The spend-cap gate (Increment 08, ADR 0032; MESH-SI-9/10, SI-22): refuse
//! a request for a capped project once this device's rights for the month
//! are used up. Enforcement is local and opt-in per cap (`tethra mesh cap
//! enforce`); peers cannot switch it.
//!
//! **The hot path never touches the database or the network.** [`CapGate::
//! admit`] reads an `Arc` snapshot and atomics only. The existing route
//! poller rebuilds the snapshot every poll (`refresh`), from one read
//! transaction (`core::mesh::caps::gate::gate_snapshot`): this device's
//! rights, its open escrow, its rollup's month spend and what it published.
//!
//! **Spend is never missed and never counted twice.** Cost is known only
//! when a response completes, so a completed request's estimate is
//! *charged* in memory at once (`charged`), independent of the writer, which
//! may drop records under load (SI-12). When the writer commits that
//! record's row it adds the same amount to `persisted`. A snapshot reads
//! `persisted` **before** the database, so this device's spend is
//! `max(published, local_db + (charged − persisted_at_snapshot))`: a charge
//! persisted before the snapshot's read of `persisted` is in `local_db` and
//! not in the difference; one still in memory is in the difference only; one
//! persisted between the two reads is briefly in both, which only refuses
//! earlier, never later. The published figure is a floor taken after the
//! sum, so a charge moving from memory to the database never drops out. A
//! charge the writer drops (or that fails to persist) stays in memory and
//! marks the cap's accounting incomplete: after a restart it is gone.
//!
//! **Bounded overshoot.** Cost is known only afterwards, so every admitted
//! request *reserves* the cap's recent 95th-percentile request cost until it
//! completes. A request beside others in flight is admitted only while the
//! rights left after every reservation stay above the near-exhaustion margin
//! (twice that cost, or $0.50); a request alone in flight is admitted while
//! any rights remain. Near the cap that is one request at a time, and its
//! cost is the overshoot. A [`Ticket`] holds the reservation; dropping it
//! releases it, on every exit path.
//!
//! **Fail open, and say so.** No mesh, an unreadable or mismatched
//! database, or a snapshot older than 60 s: the gate admits everything and
//! reports why. An unpriced model, or a response without usage, is admitted
//! and counted (unpriced, unmetered), never charged.

use crate::record::{ExchangeRecord, UsageObservation};
use api_tracker_core::db;
use api_tracker_core::mesh::caps::gate::{
    self, GateCapStatus, GateRead, GateStatus, NEAR_EXHAUSTION_FLOOR_MICROS, SNAPSHOT_STALE_MS,
};
use api_tracker_core::mesh::dot::CapId;
use api_tracker_core::mesh::kinds::Month;
use api_tracker_core::pricing::{self, PricingRecord};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Recent request costs kept per cap for the reservation and the
/// near-exhaustion threshold.
const RECENT_COSTS: usize = 256;

/// Counters of one `(cap, month)` that outlive snapshots.
#[derive(Debug, Default)]
pub struct CapCounters {
    charged: AtomicU64,
    persisted: AtomicU64,
    /// Admitted requests not completed yet, and what they reserve.
    in_flight: AtomicU64,
    reserved: AtomicU64,
    incomplete: std::sync::atomic::AtomicBool,
    unpriced: AtomicU64,
    unmetered: AtomicU64,
    refused: AtomicU64,
    p95: AtomicU64,
    recent: Mutex<VecDeque<u64>>,
}

impl CapCounters {
    /// The writer committed a charged record's row.
    pub fn persisted(&self, micros: u64) {
        self.persisted.fetch_add(micros, Ordering::SeqCst);
    }

    /// A charged record will never reach the database.
    pub fn mark_incomplete(&self) {
        self.incomplete.store(true, Ordering::Relaxed);
    }

    fn unpersisted_since(&self, persisted_at_snapshot: u64) -> u64 {
        self.charged
            .load(Ordering::SeqCst)
            .saturating_sub(persisted_at_snapshot)
    }

    fn update_p95(&self) {
        let recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        if recent.is_empty() {
            return;
        }
        let mut v: Vec<u64> = recent.iter().copied().collect();
        v.sort_unstable();
        let i = (v.len() * 95).div_ceil(100).saturating_sub(1);
        self.p95.store(v[i.min(v.len() - 1)], Ordering::Relaxed);
    }
}

/// A completed request's charge, carried by its record to the writer.
#[derive(Clone, Debug)]
pub struct CapCharge {
    pub counters: Arc<CapCounters>,
    pub micros: u64,
}

impl CapCharge {
    pub fn persisted(&self) {
        self.counters.persisted(self.micros);
    }

    pub fn lost(&self) {
        self.counters.mark_incomplete();
    }
}

struct Entry {
    cap: CapId,
    month: Month,
    enforced: bool,
    granted: i128,
    escrowed: u64,
    local_db: u64,
    published: u64,
    persisted_at_snapshot: u64,
    counters: Arc<CapCounters>,
}

impl Entry {
    /// Rights left after escrow and spend, before in-flight reservations.
    fn avail(&self) -> i128 {
        let in_memory = self.counters.unpersisted_since(self.persisted_at_snapshot);
        let spend =
            u128::from(self.published).max(u128::from(self.local_db) + u128::from(in_memory));
        self.granted - i128::from(self.escrowed) - i128::try_from(spend).unwrap_or(i128::MAX)
    }

    fn threshold(&self) -> i128 {
        let p95 = self.counters.p95.load(Ordering::Relaxed);
        let t = (2 * u128::from(p95)).max(u128::from(NEAR_EXHAUSTION_FLOOR_MICROS));
        i128::try_from(t).unwrap_or(i128::MAX)
    }
}

struct Snapshot {
    built_at: Instant,
    generation: u64,
    inactive: Option<&'static str>,
    failing_open: bool,
    entries: Vec<Entry>,
    by_project: HashMap<String, usize>,
    pricing: BTreeMap<String, Vec<PricingRecord>>,
}

impl Snapshot {
    fn empty(reason: &'static str, failing_open: bool) -> Self {
        Self {
            built_at: Instant::now(),
            generation: 0,
            inactive: Some(reason),
            failing_open,
            entries: Vec::new(),
            by_project: HashMap::new(),
            pricing: BTreeMap::new(),
        }
    }
}

/// Why a request was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub cap: String,
    pub month: String,
    /// Rights remain, but requests already in flight hold them (near the
    /// cap one request runs at a time).
    pub serialized: bool,
}

/// The admission decision.
pub enum Admission {
    /// Forward. A ticket (for a capped project) charges the completed
    /// request; dropping it releases its reservation.
    Admit(Option<Ticket>),
    Refuse(Refusal),
}

/// One admitted request of a capped project.
pub struct Ticket {
    counters: Arc<CapCounters>,
    reserved: u64,
    counted: bool,
    snapshot: Arc<Snapshot>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if self.counted {
            self.counters
                .reserved
                .fetch_sub(self.reserved, Ordering::SeqCst);
            self.counters.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// The gate. One per gateway; cheap to share.
pub struct CapGate {
    db_path: PathBuf,
    snapshot: RwLock<Arc<Snapshot>>,
    registry: Mutex<HashMap<(CapId, Month), Arc<CapCounters>>>,
    generation: AtomicU64,
    last_written: Mutex<Option<GateStatus>>,
    stale_after: Duration,
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(0)
}

impl CapGate {
    pub fn new(db_path: &Path) -> Self {
        Self {
            db_path: db_path.to_path_buf(),
            snapshot: RwLock::new(Arc::new(Snapshot::empty(
                "the gate has not read the caps yet",
                false,
            ))),
            registry: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
            last_written: Mutex::new(None),
            stale_after: Duration::from_millis(SNAPSHOT_STALE_MS),
        }
    }

    /// A gate whose snapshot goes stale sooner (tests of the fail-open path).
    #[doc(hidden)]
    pub fn with_stale_after_for_test(mut self, d: Duration) -> Self {
        self.stale_after = d;
        self
    }

    fn current(&self) -> Arc<Snapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn counters(&self, cap: CapId, month: Month) -> Arc<CapCounters> {
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry((cap, month))
            .or_default()
            .clone()
    }

    /// **The hot path.** Decide on a request for local project
    /// `project_id`: no I/O, no lock the writer takes.
    pub fn admit(&self, project_id: Option<&str>) -> Admission {
        let snap = self.current();
        let Some(&i) = project_id.and_then(|p| snap.by_project.get(p)) else {
            return Admission::Admit(None);
        };
        let e = &snap.entries[i];
        let stale = snap.built_at.elapsed() > self.stale_after;
        let mut ticket = Ticket {
            counters: e.counters.clone(),
            reserved: 0,
            counted: false,
            snapshot: snap.clone(),
        };
        if !e.enforced || snap.inactive.is_some() || stale {
            return Admission::Admit(Some(ticket));
        }
        let refusal = |serialized| {
            e.counters.refused.fetch_add(1, Ordering::Relaxed);
            Admission::Refuse(Refusal {
                cap: e.cap.to_hex(),
                month: e.month.to_string(),
                serialized,
            })
        };
        let avail = e.avail();
        if avail <= 0 {
            return refusal(false);
        }
        // Reserve first (atomically), then decide on what is left. Alone in
        // flight, a request is admitted while any rights remain (the
        // one-request overshoot). Beside others, only while every
        // reservation still leaves the near-exhaustion margin.
        let reserve = e.counters.p95.load(Ordering::Relaxed);
        let others = e.counters.in_flight.fetch_add(1, Ordering::SeqCst);
        let held = e.counters.reserved.fetch_add(reserve, Ordering::SeqCst) + reserve;
        ticket.reserved = reserve;
        ticket.counted = true;
        if others > 0 && avail - i128::from(held) < e.threshold() {
            drop(ticket); // releases the reservation
            return refusal(true);
        }
        Admission::Admit(Some(ticket))
    }

    /// Charge a completed request: its estimated cost (billable input — the
    /// cached-read tokens are excluded, as the writer does — and output, at
    /// this snapshot's pricing) is added in memory at once and handed to the
    /// writer on the record. A response without usage is counted as
    /// unmetered and an unpriced model as unpriced; neither is charged.
    /// Dropping the ticket releases its reservation.
    pub fn charge(&self, ticket: Ticket, record: &mut ExchangeRecord) {
        let Some(usage) = record.usage.as_ref().filter(|u| u.available()) else {
            ticket.counters.unmetered.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match cost_of(&ticket.snapshot, &record.provider_id, &record.at, usage) {
            Some(micros) => {
                ticket.counters.charged.fetch_add(micros, Ordering::SeqCst);
                let mut recent = ticket
                    .counters
                    .recent
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if recent.len() == RECENT_COSTS {
                    recent.pop_front();
                }
                recent.push_back(micros);
                drop(recent);
                record.cap_charge = Some(CapCharge {
                    counters: ticket.counters.clone(),
                    micros,
                });
            }
            None => {
                ticket.counters.unpriced.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Rebuild the snapshot (the poller, every poll), acknowledge the escrow
    /// rows it counted, and persist the status when it changed. Never fails:
    /// an unreadable database installs a fail-open snapshot with its reason.
    pub fn refresh(&self, providers: &[String]) {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        // `persisted` BEFORE the database (see the module documentation).
        let before: HashMap<(CapId, Month), u64> = self
            .registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(k, c)| (*k, c.persisted.load(Ordering::SeqCst)))
            .collect();
        let conn = match db::open_at_current_version(&self.db_path) {
            Ok(c) => c,
            Err(_) => {
                // Nowhere to persist the status: `gateway status` reports it.
                self.install(Snapshot::empty(
                    "the database could not be opened at this gateway's schema version",
                    true,
                ));
                return;
            }
        };
        let read = gate::gate_snapshot(&conn, now_ms(), providers);
        let input = match read {
            Ok(GateRead::Ready(input)) => input,
            Ok(GateRead::NoMesh) => {
                self.install(Snapshot::empty("this device is not in a mesh", false));
                self.persist_status(&conn);
                return;
            }
            Err(_) => {
                self.install(Snapshot::empty(
                    "the spend-cap tables could not be read",
                    true,
                ));
                self.persist_status(&conn);
                return;
            }
        };
        let mut entries = Vec::new();
        let mut by_project = HashMap::new();
        for c in &input.caps {
            let counters = self.counters(c.cap_id, c.month);
            counters.update_p95();
            for l in &c.locals {
                by_project.insert(l.clone(), entries.len());
            }
            entries.push(Entry {
                cap: c.cap_id,
                month: c.month,
                enforced: c.enforced,
                granted: c.granted_micros,
                escrowed: c.escrowed_micros,
                local_db: c.local_spend_micros,
                published: c.published_used_micros,
                persisted_at_snapshot: before.get(&(c.cap_id, c.month)).copied().unwrap_or(0),
                counters,
            });
        }
        let inactive = (!entries.iter().any(|e| e.enforced))
            .then_some("no spend cap is enforced on this device");
        self.install(Snapshot {
            built_at: Instant::now(),
            generation,
            inactive,
            failing_open: false,
            entries,
            by_project,
            pricing: input.pricing,
        });
        // The installed snapshot deducts every pending row: acknowledge them,
        // so the node may publish the transfers (MESH-SI-10).
        let _ = gate::ack_counted(&conn, &input.pending_escrow, generation);
        self.persist_status(&conn);
    }

    fn install(&self, snap: Snapshot) {
        *self.snapshot.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(snap);
    }

    fn persist_status(&self, conn: &rusqlite::Connection) {
        let mut status = self.status();
        // Rewrite only when something other than the time changed.
        let mut last = self.last_written.lock().unwrap_or_else(|e| e.into_inner());
        let unchanged = last.as_ref().is_some_and(|l| {
            l.inactive_reason == status.inactive_reason
                && l.caps == status.caps
                && now_ms().saturating_sub(l.at_ms) < 30_000
        });
        if unchanged {
            return;
        }
        status.at_ms = now_ms();
        if gate::write_status(conn, &status).is_ok() {
            *last = Some(status);
        }
    }

    /// The gate's state for `gateway status` and the persisted status.
    pub fn status(&self) -> GateStatus {
        let snap = self.current();
        let stale = snap.built_at.elapsed() > self.stale_after;
        GateStatus {
            at_ms: now_ms(),
            generation: snap.generation,
            inactive_reason: if stale {
                Some("the spend-cap snapshot is stale (the poller has not run for a minute)".into())
            } else {
                snap.inactive.map(str::to_owned)
            },
            failing_open: stale || snap.failing_open,
            caps: snap
                .entries
                .iter()
                .map(|e| {
                    let avail = e.avail();
                    let held = e.counters.reserved.load(Ordering::SeqCst);
                    GateCapStatus {
                        cap_id: e.cap.to_hex(),
                        month: e.month.to_string(),
                        enforced: e.enforced,
                        avail_micros: i64::try_from(avail).unwrap_or(i64::MAX),
                        near_exhaustion: avail - i128::from(held) < e.threshold(),
                        accounting_incomplete: e.counters.incomplete.load(Ordering::Relaxed),
                        unpriced_requests: e.counters.unpriced.load(Ordering::Relaxed),
                        unmetered_requests: e.counters.unmetered.load(Ordering::Relaxed),
                        refused_requests: e.counters.refused.load(Ordering::Relaxed),
                    }
                })
                .collect(),
        }
    }
}

/// The estimate the writer would make (`writer::write_usage`): billable input
/// excludes cached reads; no price, no estimate.
fn cost_of(snap: &Snapshot, provider: &str, at: &str, usage: &UsageObservation) -> Option<u64> {
    let model = usage.model.as_deref()?;
    let candidates = snap.pricing.get(provider)?;
    let rec = pricing::choose_as_of(candidates, model, at)?;
    let input = usage
        .input_tokens
        .unwrap_or(0)
        .saturating_sub(usage.cached_input_tokens.unwrap_or(0));
    let clamp = |x: u64| i64::try_from(x).unwrap_or(i64::MAX);
    let est = pricing::estimate_token_cost_from(
        &rec,
        clamp(input),
        clamp(usage.output_tokens.unwrap_or(0)),
    )?;
    u64::try_from(est.micros).ok()
}
