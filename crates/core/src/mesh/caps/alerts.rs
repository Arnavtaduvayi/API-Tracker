//! Spend-cap alerts (Increment 07): raised by the monitor through the
//! existing alert system when this device's view of a cap's total spend
//! this month crosses 80% and 100% of the effective target (the target plus
//! any local overrides). Dedup keys `mesh_cap:<cap>:<YYYY-MM>:80` and
//! `:100`. The figure is cross-device, gateway-estimated and only as fresh
//! as the last exchange with each device; the alert says so. Budgets
//! (`crate::budget`) are not involved (SI-19).

use super::policy::ALERT_THRESHOLDS;
use super::view::{used_pct, Ledger};
use crate::alerts::{AlertKind, NewAlert, Severity};
use crate::error::Result;
use crate::mesh::projects;
use crate::mesh::sqlite_store::SqliteStore;
use crate::mesh::usage;
use crate::providers::Confidence;

/// The spend-cap alerts that hold now, for this device's view.
pub fn cap_alerts(store: &SqliteStore) -> Result<Vec<NewAlert>> {
    let l = Ledger::of(store);
    let month = l.month();
    let observed_at = crate::clock::now_rfc3339();
    let enforced = super::gate::enforced_caps(l.conn)?;
    let mut out = Vec::new();
    for cap in l.caps().into_iter().filter(|c| c.in_force()) {
        let f = l.figures(&cap, month);
        let Some(effective) = f.effective_target() else {
            continue;
        };
        let unpublished = if l.bound(&cap)? {
            u128::from(l.local_spend(&cap, month)?).saturating_sub(f.device(&l.me).used)
        } else {
            0
        };
        let used = f.view.total_used + unpublished;
        let pct = used_pct(used, effective);
        let mut stale = 0;
        for d in f.view.devices.keys().filter(|d| **d != l.me) {
            let fresh = usage::last_exchange(store, d)?.is_some_and(|a| {
                l.now_ms
                    .saturating_sub(crate::mesh::peers::rfc3339_to_ms(&a))
                    <= usage::STALE_AFTER_MS
            });
            stale += usize::from(!fresh);
        }
        let name = projects::get(store, &cap.mesh_project_id)
            .map_or_else(|| cap.mesh_project_id.to_hex()[..8].to_owned(), |p| p.name);
        for t in ALERT_THRESHOLDS.into_iter().filter(|t| pct >= *t) {
            out.push(NewAlert {
                kind: AlertKind::MeshSpendCap,
                severity: if t >= 100 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                dedup_key: format!("mesh_cap:{}:{month}:{t}", cap.cap_id),
                title: format!("Spend cap for {name} is at {pct}% for {month}"),
                detail: format!(
                    "Estimated gateway-observed spend across your devices is {} of a {} cap \
                     this month ({} device(s), {stale} not heard from in 24 hours). It is \
                     this device's view as of the last exchange with each device, priced by \
                     each device's own pricing table; a device not heard from may have spent \
                     more. {}",
                    crate::usage::format_micros(i64::try_from(used).unwrap_or(i64::MAX)),
                    crate::usage::format_micros(i64::try_from(effective).unwrap_or(i64::MAX)),
                    f.view.devices.len(),
                    if enforced.contains(&cap.cap_id) {
                        "This device's gateway enforces the cap: it refuses requests once this \
                         device's rights are used up."
                    } else {
                        "This device's gateway does not enforce it (alerts only); switch that \
                         on with `tethra mesh cap enforce`."
                    }
                ),
                evidence: format!(
                    "cap={} month={month} used_micros={used} cap_micros={effective} \
                     threshold={t}% devices={} stale={stale}",
                    cap.cap_id,
                    f.view.devices.len()
                ),
                confidence: Confidence::Medium,
                recommended_action: "Check the spend with `tethra mesh cap show` and \
                     `tethra mesh usage`; raise the cap with `tethra mesh cap raise` if the \
                     spend is expected."
                    .into(),
                project_id: None,
                credential_id: None,
                observed_at: observed_at.clone(),
            });
        }
    }
    Ok(out)
}
