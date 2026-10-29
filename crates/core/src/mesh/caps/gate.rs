//! What a gateway needs to enforce spend caps (Increment 08, DESIGN §D15,
//! ADR 0032): the snapshot input, the local enforcement switches, and the
//! gate's status as it persists it for `mesh status` and `mesh cap show`.
//!
//! The gateway links core only. It folds the cap, roster, fork and project
//! items of `mesh_items` itself (no mesh node, no keys), so it reads exactly
//! what the node publishes, and reads them **in one read transaction** with
//! the escrow rows and its own rollup: a transfer published between two
//! separate reads would be counted by neither.
//!
//! **Enforcement is local and opt-in (MESH-SI-9).** A cap is enforced on
//! this device only when the user switched it on here (`mesh_meta`
//! `cap_enforce/<cap>` = 1, set by a reauthenticated command); the global
//! `gateway_config.cap_enforcement` is on exactly while some cap is. Neither
//! replicates, so no peer can turn enforcement on or off.

use super::escrow::{self, EscrowState};
use super::period;
use super::view::{self, CapInfo};
use crate::error::Result;
use crate::mesh::dot::{CapId, DeviceId, MeshProjectId};
use crate::mesh::item::SignedItem;
use crate::mesh::kinds::{names, Month};
use crate::mesh::projects;
use crate::mesh::store::GenesisInfo;
use crate::mesh::usage;
use crate::mesh::views::{self as views_mod, State};
use crate::pricing::PricingRecord;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const ENFORCE_PREFIX: &str = "cap_enforce/";
const STATUS_KEY: &str = "gate/status";

/// After this long without a fresh snapshot the gate stops enforcing and
/// says why (a stuck poller must never block traffic).
pub const SNAPSHOT_STALE_MS: u64 = 60_000;
/// Near exhaustion the gate admits one request at a time per cap: when the
/// cap's available amount is below twice the 95th-percentile request cost
/// seen this month, or below this floor.
pub const NEAR_EXHAUSTION_FLOOR_MICROS: u64 = 500_000;

/// One cap as the gate sees it on this device for the current month.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateCapInput {
    pub cap_id: CapId,
    pub month: Month,
    pub mesh_project_id: MeshProjectId,
    /// Local projects bound to the cap's (root) project here.
    pub locals: Vec<String>,
    /// This device's rights: minted + received − sent − burned.
    pub granted_micros: i128,
    /// This device's gateway rollup's month spend for the cap's projects
    /// (`usage::local_month_spend_in`): where every persisted charge lands.
    pub local_spend_micros: u64,
    /// What this device published as `cap.used`: a floor on its spend (it
    /// stays when a project is unbound or local rows are gone). The gate
    /// takes `max(published, local + spend not yet persisted)`, so a charge
    /// moving from memory to the database never drops out of the count.
    pub published_used_micros: u64,
    /// Transfers reserved in escrow (pending + acked), not yet published.
    pub escrowed_micros: u64,
    /// Switched on here, and the cap is in force.
    pub enforced: bool,
    pub frozen: bool,
}

/// Everything one snapshot reads.
#[derive(Clone, Debug)]
pub struct GateInput {
    pub month: Month,
    pub caps: Vec<GateCapInput>,
    /// Escrow rows still `pending`: the gate acknowledges them once a
    /// snapshot that deducts them is installed (`escrow::ack`).
    pub pending_escrow: Vec<String>,
    /// Pricing candidates per provider, for costing completed requests in
    /// memory (`pricing::choose_as_of`).
    pub pricing: BTreeMap<String, Vec<PricingRecord>>,
}

/// The result of reading a snapshot.
#[derive(Clone, Debug)]
pub enum GateRead {
    /// This device is in no mesh: nothing to enforce.
    NoMesh,
    Ready(GateInput),
}

fn fold_caps(conn: &Connection, genesis: GenesisInfo) -> Result<State> {
    let mut state = State::new(genesis);
    let mut st = conn
        .prepare("SELECT bytes FROM mesh_items WHERE kind IN (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")?;
    let rows = st.query_map(
        params![
            names::ROSTER_ADD,
            names::ROSTER_REMOVE,
            names::FORK_REPORT,
            names::PROJECT_META,
            names::CAP_DEF,
            names::CAP_TARGET,
            names::CAP_RIGHTS,
            names::CAP_USED,
        ],
        |r| r.get::<_, Vec<u8>>(0),
    )?;
    for bytes in rows {
        // Stored items were verified when they were accepted.
        let item = SignedItem::from_wire(&bytes?)?;
        views_mod::apply_stored(&mut state, &item)?;
    }
    Ok(state)
}

/// Read one snapshot: every cap in force with this device's rights, spend
/// and escrow for the current month, the pending escrow rows, and pricing
/// for `providers`. One read transaction.
pub fn gate_snapshot(conn: &Connection, now_ms: u64, providers: &[String]) -> Result<GateRead> {
    let tx = conn.unchecked_transaction()?;
    let Some(me) = crate::mesh::identity::read_self(&tx)? else {
        return Ok(GateRead::NoMesh);
    };
    let genesis = GenesisInfo {
        mesh_id: me.info.mesh_id,
        genesis: me.info.genesis_device,
    };
    let self_id: DeviceId = me.info.device_id;
    let state = fold_caps(&tx, genesis)?;
    let month = period::month_of(now_ms);
    let enforced = enforced_caps(&tx)?;
    let global = escrow::enforcement_on(&tx)?;
    let bindings = projects::bindings(&tx)?;
    let all = view::caps_in(&state);
    // Switched on for a cap that was then superseded (or frozen and
    // replaced): the cap in force on that project carries the switch.
    let switched = |c: &CapInfo| {
        enforced.contains(&c.cap_id)
            || all
                .iter()
                .any(|o| o.superseded_by == Some(c.cap_id) && enforced.contains(&o.cap_id))
    };
    let mut caps = Vec::new();
    for c in all.iter().filter(|c| c.in_force()) {
        let f = view::month_figures(&state, c, month);
        let mine = f.device(&self_id);
        let granted = to_i128(mine.minted) + to_i128(mine.received)
            - to_i128(mine.sent)
            - to_i128(mine.burned);
        let local = usage::local_month_spend_in(&tx, &state, &c.mesh_project_id, month)?;
        let published = u64::try_from(mine.used).unwrap_or(u64::MAX);
        let locals = bindings
            .iter()
            .filter(|(_, m)| projects::root_in(&state, m) == c.root)
            .map(|(l, _)| l.clone())
            .collect();
        caps.push(GateCapInput {
            cap_id: c.cap_id,
            month,
            mesh_project_id: c.mesh_project_id,
            locals,
            granted_micros: granted,
            local_spend_micros: local,
            published_used_micros: published,
            escrowed_micros: escrow::open_amount(&tx, &c.cap_id, month)?,
            enforced: global && switched(c),
            frozen: c.frozen,
        });
    }
    let pending_escrow = escrow::open_rows(&tx)?
        .into_iter()
        .filter(|r| r.state == EscrowState::Pending)
        .map(|r| r.id)
        .collect();
    let mut pricing = BTreeMap::new();
    if !caps.is_empty() {
        for p in providers {
            pricing.insert(p.clone(), crate::pricing::candidates_for(&tx, p)?);
        }
    }
    tx.commit()?;
    Ok(GateRead::Ready(GateInput {
        month,
        caps,
        pending_escrow,
        pricing,
    }))
}

fn to_i128(x: u128) -> i128 {
    i128::try_from(x).unwrap_or(i128::MAX)
}

/// The caps switched on for enforcement on this device.
pub fn enforced_caps(conn: &Connection) -> Result<BTreeSet<CapId>> {
    let mut st =
        conn.prepare("SELECT key FROM mesh_meta WHERE key LIKE 'cap_enforce/%' AND value = 1")?;
    let keys: Vec<String> = st
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(keys
        .iter()
        .filter_map(|k| k.strip_prefix(ENFORCE_PREFIX))
        .filter_map(|c| CapId::parse(c).ok())
        .collect())
}

/// Switch every cap's enforcement off on this device (superseded and
/// forgotten caps included), and the global switch with it.
pub fn clear_enforced(conn: &Connection) -> Result<Vec<CapId>> {
    let all: Vec<CapId> = enforced_caps(conn)?.into_iter().collect();
    for c in &all {
        set_enforced(conn, c, false)?;
    }
    conn.execute(
        "UPDATE gateway_config SET cap_enforcement = 0 WHERE id = 'gateway'",
        [],
    )?;
    Ok(all)
}

/// Switch enforcement of `cap` on or off on this device, and keep the
/// global switch on exactly while some cap is enforced. Local only; the
/// reauthenticated caller is `UnlockedVault::mesh_cap_enforce`.
pub fn set_enforced(conn: &Connection, cap: &CapId, on: bool) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let key = format!("{ENFORCE_PREFIX}{cap}");
    if on {
        tx.execute(
            "INSERT OR REPLACE INTO mesh_meta (key, value) VALUES (?1, 1)",
            [key],
        )?;
    } else {
        tx.execute("DELETE FROM mesh_meta WHERE key = ?1", [key])?;
    }
    let any = !enforced_caps(&tx)?.is_empty();
    let now = crate::clock::now_rfc3339();
    tx.execute(
        "INSERT INTO gateway_config (id, enabled, cap_enforcement, created_at, updated_at)
         VALUES ('gateway', 0, ?1, ?2, ?2)
         ON CONFLICT(id) DO UPDATE SET cap_enforcement = excluded.cap_enforcement,
             updated_at = excluded.updated_at",
        params![i64::from(any), now],
    )?;
    tx.commit()?;
    Ok(())
}

/// One cap in the gate's status (control `Status` and `mesh_meta`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateCapStatus {
    pub cap_id: String,
    pub month: String,
    pub enforced: bool,
    /// What this device's gateway would still admit (rights − escrow −
    /// persisted spend − spend not yet persisted).
    pub avail_micros: i64,
    pub near_exhaustion: bool,
    /// A request the gate charged was dropped by the writer or failed to
    /// persist: after a restart that spend is not counted.
    pub accounting_incomplete: bool,
    /// Completed requests whose model has no price (admitted, not counted).
    pub unpriced_requests: u64,
    /// Completed requests whose response reported no usage (a stream without
    /// usage, a route without extraction): admitted, their cost unknown.
    #[serde(default)]
    pub unmetered_requests: u64,
    pub refused_requests: u64,
}

/// The gate as its poller last saw it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateStatus {
    pub at_ms: u64,
    pub generation: u64,
    /// Why the gate admits everything right now, if it does.
    pub inactive_reason: Option<String>,
    /// The reason is a failure (an unreadable or newer database, a stale
    /// snapshot), not "nothing to enforce": caps the user switched on are
    /// not holding.
    #[serde(default)]
    pub failing_open: bool,
    pub caps: Vec<GateCapStatus>,
}

/// Persist the gate's status (the gateway's poller, when it changed).
pub fn write_status(conn: &Connection, status: &GateStatus) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO mesh_meta (key, value) VALUES (?1, ?2)",
        params![STATUS_KEY, serde_json::to_string(status)?],
    )?;
    Ok(())
}

/// The gate's last persisted status, if a gateway ever wrote one.
pub fn read_status(conn: &Connection) -> Result<Option<GateStatus>> {
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM mesh_meta WHERE key = ?1 AND typeof(value) = 'text'",
            [STATUS_KEY],
            |r| r.get(0),
        )
        .optional()?;
    Ok(v.and_then(|v| serde_json::from_str(&v).ok()))
}

/// Acknowledge, as the gateway, the pending escrow rows a snapshot counted
/// (the fence's gateway half; see [`escrow::ack`]).
pub fn ack_counted(conn: &Connection, pending: &[String], generation: u64) -> Result<usize> {
    if pending.is_empty() {
        return Ok(0);
    }
    escrow::ack(conn, pending, i64::try_from(generation).unwrap_or(i64::MAX))
}
