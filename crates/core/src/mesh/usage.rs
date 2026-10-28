//! `tethra mesh usage`: honest cross-device usage (Increment 06, DESIGN §D14,
//! MESH-SI-11).
//!
//! Every figure is **per device**, labelled with that device's freshness: "as
//! of" the last successful exchange with it (this device's own figures are
//! current), and **stale** after 24 hours. A removed device is labelled. An
//! active device with no counters for a project is listed under "no data
//! from", which is unknown, never zero. A sum across devices is given only
//! with its label ("estimated, gateway-observed, across N devices; M stale").
//! Nothing here is ever added to provider-reported cost (gateway SI-19).
//!
//! The estimate covers priced requests only and was computed on the device
//! the usage came from, with its pricing. Unpriced, never-extracted and
//! split-unknown requests are counted beside it, never as $0.

use super::dot::{DeviceId, MeshProjectId};
use super::kinds::{Day, Month, UsageTotals};
use super::projects;
use super::publish;
use super::sqlite_store::SqliteStore;
use super::store::MeshStore;
use crate::error::Result;
use rusqlite::OptionalExtension;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// After this long without an exchange, a device's figures are stale.
pub const STALE_AFTER_MS: u64 = 24 * 3_600_000;

/// Which usage to report.
#[derive(Clone, Copy, Debug, Default)]
pub struct UsageFilter {
    pub project: Option<MeshProjectId>,
    /// One UTC day (wins over `month`).
    pub day: Option<Day>,
    /// One UTC month (default: the current one).
    pub month: Option<Month>,
}

/// One device's figures for one project.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceUsage {
    pub device_id: DeviceId,
    pub device_name: Option<String>,
    pub is_self: bool,
    /// The last successful exchange with it (RFC 3339); `None` for this
    /// device (current) or a device never exchanged with directly.
    pub as_of: Option<String>,
    pub stale: bool,
    pub removed: bool,
    pub totals: UsageTotals,
    /// Requests whose priced/unpriced split is unknown (traffic recorded
    /// before that device's upgrade to the split).
    pub split_unknown_requests: u64,
    /// The first day from which this device's figures carry the full split,
    /// when some earlier day in range does not.
    pub split_known_since: Option<Day>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectUsage {
    pub mesh_project_id: MeshProjectId,
    pub name: String,
    pub archived: bool,
    /// Projects merged into this one; their counters are folded in.
    pub merged: Vec<MeshProjectId>,
    pub devices: Vec<DeviceUsage>,
    /// Active devices with no figures for this project in range: unknown.
    pub no_data_from: Vec<(DeviceId, Option<String>)>,
    /// The sum over `devices`, valid only with `total_label`.
    pub total: UsageTotals,
    pub total_label: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageReport {
    /// `YYYY-MM` or `YYYY-MM-DD`.
    pub period: String,
    pub projects: Vec<ProjectUsage>,
    /// Days before this are past the retention horizon and not reported.
    pub horizon_start: Day,
    pub notes: Vec<&'static str>,
}

/// The fixed honesty notes every report carries.
pub const NOTES: &[&str] = &[
    "Estimated from gateway-observed traffic only; never summed with provider-reported cost.",
    "Each device priced its own usage with its own pricing table; cached-read tokens are not in the estimate.",
    "Unpriced, not-extracted and split-unknown requests are counted separately, not as $0.",
    "A device with no data is unknown, not zero.",
];

fn last_exchange(store: &SqliteStore, d: &DeviceId) -> Result<Option<String>> {
    Ok(store
        .connection()
        .query_row(
            "SELECT MAX(at) FROM mesh_exchange_log WHERE peer_device = ?1 AND result = 'ok'",
            [d.to_hex()],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten())
}

fn in_period(day: &Day, f: &UsageFilter, month: Month) -> bool {
    match f.day {
        Some(d) => *day == d,
        None => day.month() == f.month.unwrap_or(month),
    }
}

fn device_name(store: &SqliteStore, d: &DeviceId) -> Option<String> {
    let state = store.state();
    state
        .device_info
        .value(d, &state.roster)
        .map(|v| v.name.clone())
        .or_else(|| state.roster.added_name(d).map(str::to_owned))
}

/// Requests whose split is unknown in `t`.
pub fn split_unknown(t: &UsageTotals) -> u64 {
    t.requests
        .saturating_sub(t.priced_requests + t.unpriced_requests + t.unextracted_requests)
}

pub fn usage_report(store: &SqliteStore, f: &UsageFilter, now_ms: u64) -> Result<UsageReport> {
    let state = store.state();
    let roster = &state.roster;
    let me = store.self_id();
    let month = Day::from_unix_ms(now_ms).month();
    let horizon = publish::horizon_start(store, now_ms);
    let period = match f.day {
        Some(d) => d.to_string(),
        None => f.month.unwrap_or(month).to_string(),
    };
    // root project -> device -> (totals, days with an unknown split)
    let mut acc: BTreeMap<MeshProjectId, BTreeMap<DeviceId, (UsageTotals, BTreeSet<Day>)>> =
        BTreeMap::new();
    for (key, origin, entry) in state.usage.iter() {
        if key.day < horizon || !in_period(&key.day, f, month) {
            continue;
        }
        // Counters count where their latest entry is within the origin's
        // cutoff (removed devices keep their history up to it).
        if !roster.is_admitted(origin, entry.seq) {
            continue;
        }
        let root = projects::root_of(store, &key.project);
        if f.project
            .is_some_and(|p| projects::root_of(store, &p) != root)
        {
            continue;
        }
        let slot = acc.entry(root).or_default().entry(*origin).or_default();
        slot.0 = publish::add(&slot.0, &entry.value.totals);
        if split_unknown(&entry.value.totals) > 0 {
            slot.1.insert(key.day);
        }
    }
    let mut projects_out = Vec::new();
    let all = projects::list(store)?;
    for row in all.iter().filter(|r| r.root == r.mesh_project_id) {
        if f.project
            .is_some_and(|p| projects::root_of(store, &p) != row.mesh_project_id)
        {
            continue;
        }
        let per_device = acc.remove(&row.mesh_project_id).unwrap_or_default();
        let mut devices = Vec::new();
        let mut total = UsageTotals::default();
        let mut stale_n = 0;
        for (d, (t, unknown_days)) in per_device {
            let is_self = d == me;
            let as_of = if is_self {
                None
            } else {
                last_exchange(store, &d)?
            };
            let stale = !is_self
                && as_of.as_deref().is_none_or(|a| {
                    now_ms.saturating_sub(super::peers::rfc3339_to_ms(a)) > STALE_AFTER_MS
                });
            if stale {
                stale_n += 1;
            }
            total = publish::add(&total, &t);
            devices.push(DeviceUsage {
                device_id: d,
                device_name: device_name(store, &d),
                is_self,
                as_of,
                stale,
                removed: roster.is_removed(&d),
                split_unknown_requests: split_unknown(&t),
                split_known_since: unknown_days.iter().next_back().map(|d| d.next()),
                totals: t,
            });
        }
        let reporting: BTreeSet<DeviceId> = devices.iter().map(|d| d.device_id).collect();
        let no_data_from: Vec<(DeviceId, Option<String>)> = roster
            .members()
            .filter(|d| roster.is_active(d) && !reporting.contains(d))
            .map(|d| (*d, device_name(store, d)))
            .collect();
        let total_label = format!(
            "estimated, gateway-observed, across {} device(s); {} stale; {} with no data",
            devices.len(),
            stale_n,
            no_data_from.len()
        );
        projects_out.push(ProjectUsage {
            mesh_project_id: row.mesh_project_id,
            name: row.name.clone(),
            archived: row.archived,
            merged: all
                .iter()
                .filter(|r| r.root == row.mesh_project_id && r.mesh_project_id != row.root)
                .map(|r| r.mesh_project_id)
                .collect(),
            devices,
            no_data_from,
            total,
            total_label,
        });
    }
    Ok(UsageReport {
        period,
        projects: projects_out,
        horizon_start: horizon,
        notes: NOTES.to_vec(),
    })
}

/// This device's estimated spend this month for one mesh project, from its
/// own gateway rollup for the local projects bound to it: the single
/// function Increments 07 and 08 use for "local month spend".
pub fn local_month_spend_micros(
    store: &SqliteStore,
    mesh: &MeshProjectId,
    month: Month,
) -> Result<u64> {
    let root = projects::root_of(store, mesh);
    let locals: Vec<String> = projects::bindings(store.connection())?
        .into_iter()
        .filter(|(_, m)| projects::root_of(store, m) == root)
        .map(|(l, _)| l)
        .collect();
    let mut sum: u64 = 0;
    let prefix = format!("{month}-%");
    for l in locals {
        let v: i64 = store.connection().query_row(
            "SELECT COALESCE(SUM(estimated_cost_micros), 0) FROM gateway_usage_daily
             WHERE project_id = ?1 AND day LIKE ?2",
            rusqlite::params![l, prefix],
            |r| r.get(0),
        )?;
        sum = sum.saturating_add(v.max(0) as u64);
    }
    Ok(sum)
}
