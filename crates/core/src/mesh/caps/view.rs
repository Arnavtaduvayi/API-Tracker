//! What a spend cap looks like from this device (DESIGN §D15, PROTOCOL.md
//! §5.5): the caps it knows, each month's bounded-counter view, and this
//! device's own position, which also counts the spend its gateway recorded
//! but has not published yet and the transfers it has reserved in escrow.
//!
//! Figures are labelled the way usage is (Increment 06, MESH-SI-11): per
//! device, "as of" the last exchange with it, **stale** after 24 hours, and
//! a removed device is labelled.

use super::escrow;
use super::period;
use super::policy;
use crate::error::Result;
use crate::mesh::crdt::bounded::{BoundedView, DeviceRights};
use crate::mesh::dot::{CapId, DeviceId, MeshProjectId};
use crate::mesh::hlc::Hlc;
use crate::mesh::kinds::{Day, Month};
use crate::mesh::projects;
use crate::mesh::sqlite_store::SqliteStore;
use crate::mesh::store::MeshStore;
use crate::mesh::usage;
use crate::mesh::views::State;
use rusqlite::Connection;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// A cap this device knows: one admitted `cap.def` from one origin (a cap
/// id defined by two origins is conflicted and ignored, PROTOCOL.md §5.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapInfo {
    pub cap_id: CapId,
    pub mesh_project_id: MeshProjectId,
    /// The project its counters fold into (itself unless merged).
    pub root: MeshProjectId,
    pub owner_device: DeviceId,
    #[serde(skip)]
    pub created_hlc: Hlc,
    /// The owner device was removed (or forked): nobody mints for the cap
    /// again. The rights already handed out for the month stay usable.
    pub frozen: bool,
    /// Another cap is in force on the same project: one created first (two
    /// devices that could not see each other each created one), or the live
    /// cap that replaced this frozen one. This one is not minted,
    /// distributed, enforced or alerted on again.
    pub superseded_by: Option<CapId>,
}

impl CapInfo {
    /// Minted and distributed for (not frozen, not superseded).
    pub fn is_live(&self) -> bool {
        !self.frozen && self.superseded_by.is_none()
    }

    /// Counted by alerts, requests and burns (a frozen cap's month goes on).
    pub fn in_force(&self) -> bool {
        self.superseded_by.is_none()
    }
}

/// Every cap in `state`, oldest first.
pub fn caps_in(state: &State) -> Vec<CapInfo> {
    let roster = &state.roster;
    let mut out = Vec::new();
    for cap in state.cap_defs.keys() {
        let Some(reg) = state.cap_defs.register(cap) else {
            continue;
        };
        let admitted: Vec<_> = reg
            .entries()
            .filter(|(o, e)| roster.is_admitted(o, e.seq))
            .collect();
        let [(_, e)] = admitted.as_slice() else {
            continue; // none, or conflicted
        };
        let v = &e.value.value;
        let owner = v.owner_device;
        out.push(CapInfo {
            cap_id: *cap,
            mesh_project_id: v.mesh_project_id,
            root: projects::root_in(state, &v.mesh_project_id),
            owner_device: owner,
            created_hlc: v.created_hlc,
            frozen: roster.is_removed(&owner) || roster.fork_seq(&owner).is_some(),
            superseded_by: None,
        });
    }
    // One cap is in force per root project: the first-created live one; if
    // none is live, the newest frozen one (its month's rights stay usable).
    // A cap created to replace a frozen one supersedes it.
    let mut primary: BTreeMap<MeshProjectId, (bool, Hlc, CapId)> = BTreeMap::new();
    for c in &out {
        // Live sorts before frozen; among live the earliest, among frozen
        // the newest.
        let k = if c.frozen {
            (
                true,
                Hlc::from_raw(u64::MAX - c.created_hlc.raw()),
                c.cap_id,
            )
        } else {
            (false, c.created_hlc, c.cap_id)
        };
        primary
            .entry(c.root)
            .and_modify(|f| *f = (*f).min(k))
            .or_insert(k);
    }
    for c in out.iter_mut() {
        let (_, _, p) = primary[&c.root];
        if p != c.cap_id {
            c.superseded_by = Some(p);
        }
    }
    out.sort_by_key(|c| (c.created_hlc, c.cap_id));
    out
}

pub fn cap_in(state: &State, cap: &CapId) -> Option<CapInfo> {
    caps_in(state).into_iter().find(|c| c.cap_id == *cap)
}

/// One `(cap, month)`, as the bounded-counter view gives it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MonthFigures {
    /// The last-writer-wins target for the month, if one was written.
    pub target: Option<u64>,
    /// The owner's mint.
    pub owner_minted: u128,
    /// Self-mints by other devices: labelled local overrides.
    pub overrides: u128,
    pub view: BoundedView,
}

impl MonthFigures {
    pub fn supply(&self) -> i128 {
        self.view.supply()
    }

    /// The target plus every override: what the cap allows this month.
    pub fn effective_target(&self) -> Option<u128> {
        self.target.map(|t| u128::from(t) + self.overrides)
    }

    pub fn pending_decrease(&self) -> u128 {
        self.effective_target().map_or(0, |t| {
            policy::pending_decrease(self.supply(), t, self.view.total_used)
        })
    }

    pub fn device(&self, d: &DeviceId) -> DeviceRights {
        self.view.devices.get(d).cloned().unwrap_or_default()
    }

    /// `d`'s own local overrides this month (zero for the owner).
    pub fn overrides_of(&self, d: &DeviceId, owner: &DeviceId) -> u64 {
        if d == owner {
            return 0;
        }
        u64::try_from(self.device(d).minted).unwrap_or(u64::MAX)
    }
}

pub fn month_figures(state: &State, cap: &CapInfo, month: Month) -> MonthFigures {
    let roster = &state.roster;
    let target = state
        .cap_targets
        .value(&(cap.cap_id, month), roster)
        .copied();
    let view = state
        .cap_counters
        .get(&(cap.cap_id, month))
        .map(|c| c.view(roster))
        .unwrap_or_default();
    let mut f = MonthFigures {
        target,
        view,
        ..Default::default()
    };
    for (d, r) in &f.view.devices {
        if *d == cap.owner_device {
            f.owner_minted = r.minted;
        } else {
            f.overrides += r.minted;
        }
    }
    f
}

/// The target in force for `month`: its own, or the latest earlier month's
/// (a month nobody has minted yet takes the current target).
pub fn scheduled_target(state: &State, cap: &CapId, month: Month) -> Option<u64> {
    state
        .cap_targets
        .values(&state.roster)
        .filter(|((c, m), _)| c == cap && *m <= month)
        .max_by_key(|((_, m), _)| *m)
        .map(|(_, v)| *v)
}

/// This device's side of the counter: what it spent and what it reserved,
/// read through `conn` (inside a write transaction when deciding).
pub struct Ledger<'a> {
    pub conn: &'a Connection,
    pub state: &'a State,
    pub me: DeviceId,
    pub now_ms: u64,
}

impl<'a> Ledger<'a> {
    pub fn of(store: &'a SqliteStore) -> Self {
        Self {
            conn: store.connection(),
            state: store.state(),
            me: store.self_id(),
            now_ms: store.now_ms(),
        }
    }

    pub fn month(&self) -> Month {
        period::month_of(self.now_ms)
    }

    pub fn caps(&self) -> Vec<CapInfo> {
        caps_in(self.state)
    }

    pub fn figures(&self, cap: &CapInfo, month: Month) -> MonthFigures {
        month_figures(self.state, cap, month)
    }

    /// Whether a local project here is bound to the cap's project.
    pub fn bound(&self, cap: &CapInfo) -> Result<bool> {
        Ok(projects::bindings(self.conn)?
            .values()
            .any(|m| projects::root_in(self.state, m) == cap.root))
    }

    /// What this device's gateway recorded against the cap's project this
    /// month (Increment 06's single "local month spend").
    pub fn local_spend(&self, cap: &CapInfo, month: Month) -> Result<u64> {
        usage::local_month_spend_in(self.conn, self.state, &cap.mesh_project_id, month)
    }

    /// This device's spend against the cap: the larger of what it published
    /// and what its gateway recorded since.
    pub fn own_used(&self, cap: &CapInfo, month: Month, f: &MonthFigures) -> Result<u64> {
        let published = u64::try_from(f.device(&self.me).used).unwrap_or(u64::MAX);
        Ok(published.max(self.local_spend(cap, month)?))
    }

    /// What this device may still spend or give: its view position, with
    /// its gateway's unpublished spend and its open escrow taken off.
    pub fn local_avail(&self, cap: &CapInfo, month: Month, f: &MonthFigures) -> Result<i128> {
        let r = f.device(&self.me);
        let used = i128::from(self.own_used(cap, month, f)?);
        let reserved = i128::from(escrow::open_amount(self.conn, &cap.cap_id, month)?);
        Ok(r.avail + to_i128(r.used) - used - reserved)
    }

    /// The devices that get a share when the owner mints: this one, and
    /// every active member it exchanged with, or saw publish usage or cap
    /// figures, within [`policy::ACTIVE_WINDOW_MS`].
    pub fn active_devices(&self) -> Result<BTreeSet<DeviceId>> {
        let roster = &self.state.roster;
        let since = self.now_ms.saturating_sub(policy::ACTIVE_WINDOW_MS);
        let mut out = BTreeSet::from([self.me]);
        let mut st = self.conn.prepare(
            "SELECT peer_device, at FROM mesh_exchange_log
             WHERE result = 'ok' AND peer_device IS NOT NULL",
        )?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (p, at) = row?;
            if crate::mesh::peers::rfc3339_to_ms(&at) >= since {
                if let Ok(d) = DeviceId::parse(&p) {
                    out.insert(d);
                }
            }
        }
        let since_day = Day::from_unix_ms(since);
        for (k, o, e) in self.state.usage.iter() {
            if k.day >= since_day && roster.is_admitted(o, e.seq) {
                out.insert(*o);
            }
        }
        let floor = self.month().prev().unwrap_or(self.month());
        for ((_, m), c) in &self.state.cap_counters {
            if *m >= floor {
                out.extend(c.writers());
            }
        }
        out.retain(|d| *d == self.me || roster.is_active(d));
        Ok(out)
    }
}

fn to_i128(x: u128) -> i128 {
    i128::try_from(x).unwrap_or(i128::MAX)
}

/// One device's row in a cap month.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapDeviceRow {
    pub device_id: DeviceId,
    pub device_name: Option<String>,
    pub is_self: bool,
    pub is_owner: bool,
    pub removed: bool,
    /// The last successful exchange with it (RFC 3339); `None` for this
    /// device (current) or a device never exchanged with directly.
    pub as_of: Option<String>,
    pub stale: bool,
    /// The owner's mint, or (`is_override`) this device's local override.
    pub minted: u128,
    pub is_override: bool,
    pub received: u128,
    pub sent: u128,
    pub burned: u128,
    /// Outgoing amounts the view ignored: more than the device held.
    pub clamped: u128,
    pub used: u128,
    pub avail: i128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapMonthRow {
    pub month: Month,
    pub target: Option<u64>,
    /// The target plus every override.
    pub effective_target: Option<u128>,
    pub owner_minted: u128,
    pub overrides: u128,
    pub burned: u128,
    pub total_used: u128,
    /// Rights in existence: minted (overrides included) minus burned.
    pub supply: i128,
    /// Rights beyond what the cap now allows, until holders burn them.
    pub pending_decrease: u128,
    /// Total used as a percentage of the effective target.
    pub used_pct: Option<u64>,
    pub devices: Vec<CapDeviceRow>,
    /// This device's own figures, including spend its gateway recorded but
    /// has not published yet (none when no local project is bound here).
    pub local_spend: Option<u64>,
    pub local_avail: Option<i128>,
    /// This device's transfers waiting in escrow (MESH-SI-10).
    pub escrow_open: u64,
    pub total_label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapRow {
    /// This device's gateway enforces this cap (switched on here).
    pub enforced_here: bool,
    pub cap_id: CapId,
    pub mesh_project_id: MeshProjectId,
    pub project_name: Option<String>,
    pub owner_device: DeviceId,
    pub owner_name: Option<String>,
    pub owned_here: bool,
    pub bound_here: bool,
    pub frozen: bool,
    pub superseded_by: Option<CapId>,
    pub months: Vec<CapMonthRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapReport {
    pub month: Month,
    pub caps: Vec<CapRow>,
    /// The gateway's last report of its spend-cap gate (`caps::gate`), and
    /// whether it is recent enough to mean the gateway is running.
    pub gate: Option<super::gate::GateStatus>,
    pub gate_fresh: bool,
    pub notes: Vec<&'static str>,
}

/// A gate status this old means the gateway is not running (it rewrites
/// it at least every 30 s while it runs).
pub const GATE_STATUS_FRESH_MS: u64 = 45_000;

/// The fixed honesty notes every cap report carries.
pub const NOTES: &[&str] = &[
    "Spend caps count gateway-estimated cost (priced requests only), per device as of the last exchange with it; a device not heard from is unknown, not zero.",
    "A spend cap is a self-limit on traffic through Tethra's gateway, not a security boundary, and never a provider budget.",
    "This device's gateway refuses requests over a cap only where you switched enforcement on (`tethra mesh cap enforce`); otherwise a cap raises alerts.",
];

/// Percentage of `used` in `of`, rounded down (100 when `of` is zero and
/// something was spent).
pub fn used_pct(used: u128, of: u128) -> u64 {
    if of == 0 {
        return if used == 0 { 0 } else { 100 };
    }
    u64::try_from(used * 100 / of).unwrap_or(u64::MAX)
}

/// The caps report (`tethra mesh cap show` / `rights`): every cap, or one;
/// the given month (default the current one) and, for the current month,
/// next month too once it has figures.
pub fn report(store: &SqliteStore, only: Option<CapId>, month: Option<Month>) -> Result<CapReport> {
    let ledger = Ledger::of(store);
    let state = store.state();
    let roster = &state.roster;
    let now = ledger.now_ms;
    let current = ledger.month();
    let month = month.unwrap_or(current);
    let enforced = super::gate::enforced_caps(store.connection())?;
    let mut caps = Vec::new();
    for cap in ledger.caps() {
        if only.is_some_and(|c| c != cap.cap_id) {
            continue;
        }
        let bound = ledger.bound(&cap)?;
        let mut months = vec![month];
        if month == current {
            if let Some(next) = month.next() {
                let f = ledger.figures(&cap, next);
                if f.target.is_some() || !f.view.devices.is_empty() {
                    months.push(next);
                }
            }
        }
        let mut rows = Vec::new();
        for m in months {
            let f = ledger.figures(&cap, m);
            let mut devices = Vec::new();
            let mut stale_n = 0;
            for (d, r) in &f.view.devices {
                let is_self = *d == ledger.me;
                let as_of = if is_self {
                    None
                } else {
                    usage::last_exchange(store, d)?
                };
                let stale = !is_self
                    && as_of.as_deref().is_none_or(|a| {
                        now.saturating_sub(crate::mesh::peers::rfc3339_to_ms(a))
                            > usage::STALE_AFTER_MS
                    });
                stale_n += usize::from(stale);
                devices.push(CapDeviceRow {
                    device_id: *d,
                    device_name: usage::device_name(store, d),
                    is_self,
                    is_owner: *d == cap.owner_device,
                    removed: roster.is_removed(d),
                    as_of,
                    stale,
                    minted: r.minted,
                    is_override: *d != cap.owner_device && r.minted > 0,
                    received: r.received,
                    sent: r.sent,
                    burned: r.burned,
                    clamped: r.clamped,
                    used: r.used,
                    avail: r.avail,
                });
            }
            let (local_spend, local_avail) = if bound {
                (
                    Some(ledger.local_spend(&cap, m)?),
                    Some(ledger.local_avail(&cap, m, &f)?),
                )
            } else {
                (None, None)
            };
            let mine_unpublished = local_spend
                .map(|s| u128::from(s).saturating_sub(f.device(&ledger.me).used))
                .unwrap_or(0);
            let total_used = f.view.total_used + mine_unpublished;
            rows.push(CapMonthRow {
                month: m,
                target: f.target,
                effective_target: f.effective_target(),
                owner_minted: f.owner_minted,
                overrides: f.overrides,
                burned: f.view.total_burned,
                total_used,
                supply: f.supply(),
                pending_decrease: f.pending_decrease(),
                used_pct: f.effective_target().map(|t| used_pct(total_used, t)),
                total_label: format!(
                    "estimated, gateway-observed, across {} device(s); {} stale",
                    devices.len(),
                    stale_n
                ),
                devices,
                local_spend,
                local_avail,
                escrow_open: escrow::open_amount(store.connection(), &cap.cap_id, m)?,
            });
        }
        caps.push(CapRow {
            enforced_here: enforced.contains(&cap.cap_id),
            cap_id: cap.cap_id,
            mesh_project_id: cap.mesh_project_id,
            project_name: projects::get(store, &cap.mesh_project_id).map(|p| p.name),
            owner_device: cap.owner_device,
            owner_name: usage::device_name(store, &cap.owner_device),
            owned_here: cap.owner_device == ledger.me,
            bound_here: bound,
            frozen: cap.frozen,
            superseded_by: cap.superseded_by,
            months: rows,
        });
    }
    let gate = super::gate::read_status(store.connection())?;
    let gate_fresh = gate
        .as_ref()
        .is_some_and(|g| now.saturating_sub(g.at_ms) < GATE_STATUS_FRESH_MS);
    Ok(CapReport {
        month,
        caps,
        gate,
        gate_fresh,
        notes: NOTES.to_vec(),
    })
}
