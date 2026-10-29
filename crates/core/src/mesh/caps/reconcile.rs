//! The cap reconciler (the node's round hook after the usage publisher,
//! DESIGN §D13/§D15) and the two ends of a rights request.
//!
//! One run, each step its own transaction deciding from the state inside
//! it ([`SqliteStore::mint_with`]):
//! 1. **used** — publish `cap.used` for this device and month as its
//!    gateway's month spend for the cap's bound projects (Increment 06's
//!    single function); a decrease (local data deleted) bumps the epoch;
//! 2. **escrow** — publish acknowledged (or no longer fenced) transfers;
//!    cancel those whose month ended or that no longer fit;
//! 3. **mint** — on the owner: mint the current month if it has not been,
//!    and from day 20 mint next month in advance (its scheduled target);
//! 4. **distribute** — on the owner: make sure every active device has
//!    received its fair share of each minted month from it;
//! 5. **burn** — on every holder, after a lower: burn what it holds above
//!    its new share, never more than the pending decrease.
//!
//! Rebalancing runs during exchanges: [`rights_requests`] says what to ask a
//! peer for at the start of an exchange, and [`grant`] answers a peer's
//! request after the exchange committed (so the donor decides on the
//! freshest view). A grant reaches the requester in a later exchange.

use super::escrow::{self, EscrowState, Fence, GatewayProbe};
use super::period;
use super::policy;
use super::view::{self, CapInfo, Ledger, MonthFigures};
use crate::error::Result;
use crate::mesh::dot::{CapId, DeviceId};
use crate::mesh::error::MeshError;
use crate::mesh::item::SignedItem;
use crate::mesh::kinds::{CapRights, CapTarget, CapUsed, ItemKind, Month, Recipient};
use crate::mesh::sign::SigningKeyPair;
use crate::mesh::sqlite_store::SqliteStore;
use crate::mesh::store::{Draft, HlcPolicy, MeshStore};
use crate::mesh::views::State;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What one reconciler run did (also kept as `caps/last_run` in
/// `mesh_meta` for `tethra mesh status`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReconcileReport {
    pub at_ms: u64,
    /// `cap.used` items published.
    pub used_published: u64,
    /// Months the owner minted (current or in advance).
    pub months_minted: u64,
    pub distributed_micros: u64,
    pub burned_micros: u64,
    pub escrow_published: u64,
    pub escrow_cancelled: u64,
    /// Transfers waiting for the running gateway's ack longer than
    /// [`policy::ACK_WAIT_MS`].
    pub escrow_waiting: u64,
    /// Every item minted (the simulator hands them to its oracle).
    #[serde(skip)]
    pub items: Vec<SignedItem>,
}

/// One rights request (`DirectMsg::RightsRequest`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RightsAsk {
    pub cap: CapId,
    pub month: Month,
    pub want: u64,
    /// From the cap's owner: give rights back (a lower's remainder, or a
    /// manual reclaim).
    pub reclaim: bool,
}

fn clamp_u64(x: i128) -> u64 {
    u64::try_from(x.max(0)).unwrap_or(u64::MAX)
}

fn own_rights(state: &State, cap: &CapId, month: Month, from: &DeviceId, to: &Recipient) -> u64 {
    state
        .cap_counters
        .get(&(*cap, month))
        .map_or(0, |c| c.own_rights(from, to))
}

/// Gives and mints decided in one transaction: escrow rows go through the
/// transaction's connection; immediate gives become cumulative items.
pub(crate) struct Plan<'l, 'a> {
    l: &'l Ledger<'a>,
    at: String,
    rights: BTreeMap<(CapId, Month, Recipient), u64>,
    /// Given or published in this transaction, not in the state yet.
    spent: BTreeMap<(CapId, Month), u64>,
    others: Vec<Draft>,
}

impl<'l, 'a> Plan<'l, 'a> {
    pub(crate) fn new(l: &'l Ledger<'a>) -> Self {
        Self {
            l,
            at: period::rfc3339_of(l.now_ms),
            rights: BTreeMap::new(),
            spent: BTreeMap::new(),
            others: Vec::new(),
        }
    }

    /// What this device may still give or spend, net of this transaction.
    pub(crate) fn avail(&self, cap: &CapInfo, month: Month, f: &MonthFigures) -> Result<i128> {
        let spent = self.spent.get(&(cap.cap_id, month)).copied().unwrap_or(0);
        Ok(self.l.local_avail(cap, month, f)? - i128::from(spent))
    }

    fn add_rights(&mut self, cap: &CapId, month: Month, to: Recipient, amount: u64, spends: bool) {
        *self.rights.entry((*cap, month, to)).or_default() += amount;
        if spends {
            *self.spent.entry((*cap, month)).or_default() += amount;
        }
    }

    /// Give up to `amount` (never more than this device holds) to `to`
    /// through the escrow fence. Returns what was given or reserved.
    pub(crate) fn give(
        &mut self,
        fence: Fence,
        cap: &CapInfo,
        month: Month,
        f: &MonthFigures,
        to: Recipient,
        amount: u64,
    ) -> Result<u64> {
        if to == Recipient::Device(self.l.me) {
            return Ok(0);
        }
        let amount = amount.min(clamp_u64(self.avail(cap, month, f)?));
        if amount == 0 {
            return Ok(0);
        }
        match fence {
            Fence::Immediate => {
                escrow::insert(
                    self.l.conn,
                    &cap.cap_id,
                    month,
                    &to,
                    amount,
                    EscrowState::Published,
                    &self.at,
                )?;
                self.add_rights(&cap.cap_id, month, to, amount, true);
            }
            // The open row itself reserves the amount (`Ledger::local_avail`
            // reads it through this transaction).
            Fence::AwaitAck => {
                escrow::insert(
                    self.l.conn,
                    &cap.cap_id,
                    month,
                    &to,
                    amount,
                    EscrowState::Pending,
                    &self.at,
                )?;
            }
        }
        Ok(amount)
    }

    /// Mint `amount` more to this device itself: the owner's mint, or (on
    /// another device) a labelled local override.
    pub(crate) fn mint_self(&mut self, cap: &CapId, month: Month, amount: u64) {
        let me = Recipient::Device(self.l.me);
        self.add_rights(cap, month, me, amount, false);
    }

    pub(crate) fn push(&mut self, d: Draft) {
        self.others.push(d);
    }

    pub(crate) fn drafts(self) -> Result<Vec<Draft>> {
        let me = self.l.me;
        let mut out = self.others;
        for ((cap, month, to), delta) in self.rights {
            let cumulative = own_rights(self.l.state, &cap, month, &me, &to)
                .checked_add(delta)
                .ok_or(MeshError::InvalidOperation("cumulative amount overflows"))?;
            let is_override = to == Recipient::Device(me)
                && view::cap_in(self.l.state, &cap).is_some_and(|c| c.owner_device != me);
            out.push(Draft::of(
                &CapRights {
                    cap,
                    month,
                    to,
                    amount_micros: cumulative,
                    is_override,
                },
                HlcPolicy::Now,
            ));
        }
        Ok(out)
    }
}

fn core_err(e: crate::error::CoreError) -> MeshError {
    match e {
        crate::error::CoreError::Mesh(m) => m,
        _ => MeshError::Storage("reading local spend-cap figures"),
    }
}

/// Run `decide` inside one write transaction and mint what it returns.
pub(crate) fn decide(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    decide: impl FnOnce(&Ledger<'_>) -> Result<Vec<Draft>>,
) -> Result<Vec<SignedItem>> {
    let (me, now) = (store.self_id(), store.now_ms());
    Ok(store.mint_with(signing, |tx, state| {
        let l = Ledger {
            conn: tx,
            state,
            me,
            now_ms: now,
        };
        decide(&l).map_err(core_err)
    })?)
}

/// This device's own latest `cap.used` for `(cap, month)`: `(epoch, used)`.
fn own_used_entry(l: &Ledger<'_>, cap: &CapId, month: Month) -> Result<(u32, u64)> {
    let key = format!("{cap}/{month}");
    let bytes: Option<Vec<u8>> = l
        .conn
        .query_row(
            "SELECT bytes FROM mesh_items WHERE kind = ?1 AND item_key = ?2 AND origin = ?3
             ORDER BY seq DESC LIMIT 1",
            params![CapUsed::KIND, key, l.me.to_hex()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(bytes) = bytes else {
        return Ok((0, 0));
    };
    let body = SignedItem::from_wire(&bytes)?.decode_unverified()?;
    let u = CapUsed::try_from(&body)?;
    Ok((u.epoch, u.used_micros))
}

fn publish_used(store: &mut SqliteStore, signing: &SigningKeyPair) -> Result<Vec<SignedItem>> {
    decide(store, signing, |l| {
        let month = l.month();
        let mut out = Vec::new();
        for cap in l.caps() {
            if !l.bound(&cap)? {
                continue; // unbound: what was published stays
            }
            for m in [month.prev(), Some(month)].into_iter().flatten() {
                let local = l.local_spend(&cap, m)?;
                let (epoch, published) = own_used_entry(l, &cap.cap_id, m)?;
                if local == published {
                    continue;
                }
                // Local data was deleted: the decrease propagates (D8).
                let epoch = if local < published {
                    epoch.saturating_add(1)
                } else {
                    epoch
                };
                out.push(Draft::of(
                    &CapUsed {
                        cap: cap.cap_id,
                        month: m,
                        epoch,
                        used_micros: local,
                    },
                    HlcPolicy::Now,
                ));
            }
        }
        Ok(out)
    })
}

fn settle_escrow(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    probe: &dyn GatewayProbe,
    rep: &mut ReconcileReport,
) -> Result<Vec<SignedItem>> {
    if escrow::open_rows(store.connection())?.is_empty() {
        return Ok(Vec::new());
    }
    let fence = escrow::fence(store.connection(), probe)?;
    let (mut published, mut cancelled, mut waiting) = (0, 0, 0);
    let items = decide(store, signing, |l| {
        let mut plan = Plan::new(l);
        for r in escrow::open_rows(l.conn)? {
            let cap = view::cap_in(l.state, &r.cap_id);
            let (Some(cap), Some(to)) = (cap, r.recipient()) else {
                escrow::set_state(l.conn, &r.id, EscrowState::Cancelled, &plan.at)?;
                cancelled += 1;
                continue;
            };
            if period::has_ended(r.month, l.now_ms) {
                escrow::set_state(l.conn, &r.id, EscrowState::Cancelled, &plan.at)?;
                cancelled += 1;
                continue;
            }
            if r.state == EscrowState::Pending && fence == Fence::AwaitAck {
                let age = l
                    .now_ms
                    .saturating_sub(crate::mesh::peers::rfc3339_to_ms(&r.created_at));
                if age > policy::ACK_WAIT_MS {
                    waiting += 1;
                }
                continue;
            }
            // The row is still open, so `avail` already leaves it out: a
            // non-negative figure means the reservation is covered.
            let f = l.figures(&cap, r.month);
            if plan.avail(&cap, r.month, &f)? < 0 {
                escrow::set_state(l.conn, &r.id, EscrowState::Cancelled, &plan.at)?;
                cancelled += 1;
                continue;
            }
            escrow::set_state(l.conn, &r.id, EscrowState::Published, &plan.at)?;
            plan.add_rights(&cap.cap_id, r.month, to, r.amount_micros, true);
            published += 1;
        }
        plan.drafts()
    })?;
    rep.escrow_published += published;
    rep.escrow_cancelled += cancelled;
    rep.escrow_waiting += waiting;
    Ok(items)
}

/// The months the owner mints and distributes now: this one and, from day
/// 20, the next.
fn owner_months(l: &Ledger<'_>) -> Vec<Month> {
    let month = l.month();
    let mut out = vec![month];
    if policy::advance_due(period::day_of_month(l.now_ms)) {
        out.extend(month.next());
    }
    out
}

fn ensure_minted(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    rep: &mut ReconcileReport,
) -> Result<Vec<SignedItem>> {
    let mut minted = 0;
    let items = decide(store, signing, |l| {
        let roster = &l.state.roster;
        let mut plan = Plan::new(l);
        for cap in l.caps() {
            if !cap.is_live() || cap.owner_device != l.me {
                continue;
            }
            for m in owner_months(l) {
                let me = Recipient::Device(l.me);
                if own_rights(l.state, &cap.cap_id, m, &l.me, &me) > 0 {
                    continue;
                }
                let Some(target) = view::scheduled_target(l.state, &cap.cap_id, m) else {
                    continue;
                };
                let key = (cap.cap_id, m);
                if l.state.cap_targets.value(&key, roster).is_none() {
                    let winner = l
                        .state
                        .cap_targets
                        .register(&key)
                        .and_then(|r| r.winning_hlc(roster));
                    plan.push(Draft::of(
                        &CapTarget {
                            cap: cap.cap_id,
                            month: m,
                            target_micros: target,
                        },
                        HlcPolicy::After(winner),
                    ));
                }
                if target > 0 {
                    plan.mint_self(&cap.cap_id, m, target);
                    minted += 1;
                }
            }
        }
        plan.drafts()
    })?;
    rep.months_minted += minted;
    Ok(items)
}

/// On the owner: every active device has received at least its fair share
/// of each minted month from the owner (cumulative, so this is idempotent;
/// a device that becomes active later in the month gets its share then).
pub(crate) fn distribute(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    probe: &dyn GatewayProbe,
    rep: &mut ReconcileReport,
) -> Result<Vec<SignedItem>> {
    let fence = escrow::fence(store.connection(), probe)?;
    let mut given = 0;
    let items = decide(store, signing, |l| {
        let mut plan = Plan::new(l);
        let caps: Vec<CapInfo> = l
            .caps()
            .into_iter()
            .filter(|c| c.is_live() && c.owner_device == l.me)
            .collect();
        if caps.is_empty() {
            return Ok(Vec::new());
        }
        let active = l.active_devices()?;
        for cap in caps {
            for m in owner_months(l) {
                let f = l.figures(&cap, m);
                let (Some(target), true) = (f.target, f.owner_minted > 0) else {
                    continue;
                };
                let share = policy::fair_share(target, active.len());
                for d in active.iter().filter(|d| **d != l.me) {
                    if reclaiming(l.conn, &cap.cap_id, d, l.now_ms)? {
                        continue; // handing its rights back
                    }
                    let to = Recipient::Device(*d);
                    // Given so far: published, or reserved in escrow.
                    let so_far = own_rights(l.state, &cap.cap_id, m, &l.me, &to)
                        .saturating_add(escrow::open_amount_to(l.conn, &cap.cap_id, m, &to)?);
                    let need = share.saturating_sub(so_far);
                    if need > 0 {
                        given += plan.give(fence, &cap, m, &f, to, need)?;
                    }
                }
            }
        }
        plan.drafts()
    })?;
    rep.distributed_micros += given;
    Ok(items)
}

/// On every holder: after a lower, burn what this device holds above its
/// new share (DESIGN §D15).
pub(crate) fn burn_after_lower(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    probe: &dyn GatewayProbe,
    rep: &mut ReconcileReport,
) -> Result<Vec<SignedItem>> {
    let fence = escrow::fence(store.connection(), probe)?;
    let mut burned = 0;
    let items = decide(store, signing, |l| {
        let mut plan = Plan::new(l);
        let month = l.month();
        let mut active_n: Option<usize> = None;
        for cap in l.caps().into_iter().filter(CapInfo::in_force) {
            for m in [Some(month), month.next()].into_iter().flatten() {
                let f = l.figures(&cap, m);
                let (Some(target), Some(eff)) = (f.target, f.effective_target()) else {
                    continue;
                };
                let used = l.own_used(&cap, m, &f)?;
                let unpublished = u128::from(used).saturating_sub(f.device(&l.me).used);
                let pending =
                    policy::pending_decrease(f.supply(), eff, f.view.total_used + unpublished);
                if pending == 0 {
                    continue;
                }
                let n = match active_n {
                    Some(n) => n,
                    None => *active_n.insert(l.active_devices()?.len()),
                };
                let fair = policy::fair_share(target, n);
                let keep =
                    policy::keep_after_lower(fair, used, f.overrides_of(&l.me, &cap.owner_device));
                let burn = policy::burn_after_lower(plan.avail(&cap, m, &f)?, keep, pending);
                if burn > 0 {
                    burned += plan.give(fence, &cap, m, &f, Recipient::Burn, burn)?;
                }
            }
        }
        plan.drafts()
    })?;
    rep.burned_micros += burned;
    Ok(items)
}

/// One reconciler run (the node's round hook, `tethra mesh replicate`).
pub fn reconcile(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    probe: &dyn GatewayProbe,
) -> Result<ReconcileReport> {
    let mut rep = ReconcileReport {
        at_ms: store.now_ms(),
        ..Default::default()
    };
    let used = publish_used(store, signing)?;
    rep.used_published = used.len() as u64;
    rep.items.extend(used);
    let items = settle_escrow(store, signing, probe, &mut rep)?;
    rep.items.extend(items);
    let items = ensure_minted(store, signing, &mut rep)?;
    rep.items.extend(items);
    let items = distribute(store, signing, probe, &mut rep)?;
    rep.items.extend(items);
    let items = burn_after_lower(store, signing, probe, &mut rep)?;
    rep.items.extend(items);
    prune(store.connection(), period::month_of(rep.at_ms))?;
    let record = serde_json::to_string(&rep)?;
    store.connection().execute(
        "INSERT OR REPLACE INTO mesh_meta (key, value) VALUES ('caps/last_run', ?1)",
        [record],
    )?;
    Ok(rep)
}

/// Forget what ended months left behind: closed escrow rows and rate-limit
/// slots (local rows only; the items stay).
fn prune(conn: &Connection, month: Month) -> Result<()> {
    escrow::prune_before(conn, month)?;
    let mut st = conn.prepare(
        "SELECT key FROM mesh_meta WHERE key LIKE 'cap_rq_sent/%' OR key LIKE 'cap_rq_granted/%'",
    )?;
    let keys: Vec<String> = st
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    for k in keys {
        let ended = k
            .split('/')
            .nth(2)
            .and_then(Month::parse)
            .is_none_or(|m| m < month);
        if ended {
            conn.execute("DELETE FROM mesh_meta WHERE key = ?1", [k])?;
        }
    }
    Ok(())
}

/// The last reconciler run's report.
pub fn last_report(conn: &Connection) -> Result<Option<ReconcileReport>> {
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM mesh_meta WHERE key = 'caps/last_run'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(v.and_then(|v| serde_json::from_str(&v).ok()))
}

/// Take a rate-limit slot: `true` (and the slot is recorded) unless one was
/// taken within [`policy::REQUEST_INTERVAL_MS`]. Atomic, so two exchanges
/// with one peer at once cannot both take it.
fn take_slot(conn: &Connection, key: &str, now_ms: u64) -> Result<bool> {
    let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
    let floor = now.saturating_sub(policy::REQUEST_INTERVAL_MS as i64);
    Ok(conn.execute(
        "INSERT INTO mesh_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value
         WHERE typeof(mesh_meta.value) <> 'integer' OR mesh_meta.value <= ?3",
        params![key, now, floor],
    )? > 0)
}

fn slot_key(prefix: &str, cap: &CapId, month: Month, peer: &DeviceId) -> String {
    format!("{prefix}/{cap}/{month}/{peer}")
}

pub(crate) fn reclaim_key(cap: &CapId, device: &DeviceId) -> String {
    format!("cap_reclaim/{cap}/{device}")
}

/// Whether this device (the owner) is reclaiming `cap`'s rights from
/// `device` (`tethra mesh cap reclaim`, for [`policy::RECLAIM_WINDOW_MS`]).
fn reclaiming(conn: &Connection, cap: &CapId, device: &DeviceId, now_ms: u64) -> Result<bool> {
    let at: Option<i64> = conn
        .query_row(
            "SELECT value FROM mesh_meta WHERE key = ?1 AND typeof(value) = 'integer'",
            [reclaim_key(cap, device)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(at.is_some_and(|at| {
        now_ms.saturating_sub(u64::try_from(at).unwrap_or(0)) < policy::RECLAIM_WINDOW_MS
    }))
}

/// What to ask `peer` for at the start of an exchange. Rate-limited per
/// peer, cap and month; the slot is taken here, before the request goes out.
pub fn rights_requests(store: &SqliteStore, peer: &DeviceId) -> Result<Vec<RightsAsk>> {
    let l = Ledger::of(store);
    let roster = &l.state.roster;
    if *peer == l.me || !roster.is_active(peer) {
        return Ok(Vec::new());
    }
    let month = l.month();
    let mut out = Vec::new();
    let mut active_n: Option<usize> = None;
    for cap in l.caps().into_iter().filter(CapInfo::in_force) {
        let mut asks: Vec<(Month, u64, bool)> = Vec::new();
        if cap.owner_device == l.me && reclaiming(l.conn, &cap.cap_id, peer, l.now_ms)? {
            for m in [Some(month), month.next()].into_iter().flatten() {
                if l.figures(&cap, m).device(peer).avail > 0 {
                    asks.push((m, u64::MAX, true));
                }
            }
        } else {
            let f = l.figures(&cap, month);
            let Some(target) = f.target else {
                continue;
            };
            let n = match active_n {
                Some(n) => n,
                None => *active_n.insert(l.active_devices()?.len()),
            };
            let fair = policy::fair_share(target, n);
            let mine = l.local_avail(&cap, month, &f)?;
            let theirs = f.device(peer).avail;
            let pending = f.pending_decrease();
            let keep = policy::keep_after_lower(fair, l.own_used(&cap, month, &f)?, 0);
            if cap.owner_device == l.me && pending > 0 && mine <= i128::from(keep) && theirs > 0 {
                // The remainder of a lower: holders burned their excess; take
                // back what is still above the cap (the owner burns it).
                let want = u64::try_from(pending.min(theirs as u128)).unwrap_or(u64::MAX);
                asks.push((month, want, true));
            } else if pending > 0 {
                // The cap is coming down: no rebalancing until it has.
            } else if let Some(want) = policy::wants(mine, fair) {
                let overrides = f.overrides_of(peer, &cap.owner_device);
                if policy::donatable(theirs, fair, overrides) > 0 {
                    asks.push((month, want, false));
                }
            }
        }
        for (m, want, reclaim) in asks {
            if take_slot(
                l.conn,
                &slot_key("cap_rq_sent", &cap.cap_id, m, peer),
                l.now_ms,
            )? {
                out.push(RightsAsk {
                    cap: cap.cap_id,
                    month: m,
                    want,
                    reclaim,
                });
            }
        }
    }
    Ok(out)
}

/// Answer `peer`'s rights request after the exchange committed. Returns the
/// amount given (or reserved in escrow). A request this device cannot or
/// should not answer gives nothing; it is not an error.
pub fn grant(
    store: &mut SqliteStore,
    signing: &SigningKeyPair,
    probe: &dyn GatewayProbe,
    peer: &DeviceId,
    ask: RightsAsk,
) -> Result<u64> {
    let fence = escrow::fence(store.connection(), probe)?;
    let mut granted = 0;
    decide(store, signing, |l| {
        let mut plan = Plan::new(l);
        let Some(cap) = view::cap_in(l.state, &ask.cap) else {
            return Ok(Vec::new());
        };
        let month = l.month();
        let month_ok = ask.month == month || (ask.reclaim && Some(ask.month) == month.next());
        if !cap.in_force() || *peer == l.me || !l.state.roster.is_active(peer) || !month_ok {
            return Ok(Vec::new());
        }
        let f = l.figures(&cap, ask.month);
        let amount = if ask.reclaim {
            if *peer != cap.owner_device {
                return Ok(Vec::new());
            }
            ask.want
        } else {
            if cap.owner_device == l.me && reclaiming(l.conn, &cap.cap_id, peer, l.now_ms)? {
                return Ok(Vec::new());
            }
            let Some(target) = f.target else {
                return Ok(Vec::new());
            };
            if f.pending_decrease() > 0 {
                return Ok(Vec::new()); // the cap is coming down
            }
            let fair = policy::fair_share(target, l.active_devices()?.len());
            let overrides = f.overrides_of(&l.me, &cap.owner_device);
            policy::grant_amount(ask.want, plan.avail(&cap, ask.month, &f)?, fair, overrides)
        };
        if amount == 0
            || !take_slot(
                l.conn,
                &slot_key("cap_rq_granted", &cap.cap_id, ask.month, peer),
                l.now_ms,
            )?
        {
            return Ok(Vec::new());
        }
        let to = Recipient::Device(*peer);
        granted = plan.give(fence, &cap, ask.month, &f, to, amount)?;
        plan.drafts()
    })?;
    Ok(granted)
}
