//! Normalized local activity events and explainable suspicious-activity
//! rules.
//!
//! Activity events are a uniform record of things that happened locally
//! (usage syncs, process-injection sessions, validation results). The rules
//! turn evidence the vault already holds into alerts; every finding names its
//! exact rule, the measurements, the comparison period, the source, and a
//! confidence. Nothing is described as malicious — the rules describe
//! deviations, not intent.

use crate::alerts::{AlertKind, NewAlert, Severity};
use crate::clock;
use crate::error::Result;
use crate::providers::Confidence;
use crate::usage;
use rusqlite::{params, Connection, Row};
use serde::Serialize;
use time::Date;

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEvent {
    pub id: i64,
    pub at: String,
    pub source: String,
    pub kind: String,
    pub credential_id: Option<String>,
    pub project_id: Option<String>,
    pub detail: String,
    pub measurements: String,
}

pub fn record(
    conn: &Connection,
    source: &str,
    kind: &str,
    credential_id: Option<&str>,
    project_id: Option<&str>,
    detail: &str,
    measurements: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO activity_events (at, source, kind, credential_id, project_id, detail, measurements)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![clock::now_rfc3339(), source, kind, credential_id, project_id, detail, measurements],
    )?;
    Ok(())
}

pub fn list(
    conn: &Connection,
    limit: u32,
    credential_id: Option<&str>,
) -> Result<Vec<ActivityEvent>> {
    let row = |r: &Row<'_>| {
        Ok(ActivityEvent {
            id: r.get(0)?,
            at: r.get(1)?,
            source: r.get(2)?,
            kind: r.get(3)?,
            credential_id: r.get(4)?,
            project_id: r.get(5)?,
            detail: r.get(6)?,
            measurements: r.get(7)?,
        })
    };
    let cols = "id, at, source, kind, credential_id, project_id, detail, measurements";
    let mut out = Vec::new();
    match credential_id {
        Some(cid) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {cols} FROM activity_events WHERE credential_id = ?1 ORDER BY id DESC LIMIT ?2"
            ))?;
            for r in stmt.query_map(params![cid, limit], row)? {
                out.push(r?);
            }
        }
        None => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {cols} FROM activity_events ORDER BY id DESC LIMIT ?1"
            ))?;
            for r in stmt.query_map([limit], row)? {
                out.push(r?);
            }
        }
    }
    Ok(out)
}

/// Start of the previous calendar month, and the start of this one.
fn month_bounds(now: time::OffsetDateTime) -> (String, String) {
    let this = Date::from_calendar_date(now.year(), now.month(), 1).expect("valid");
    let prev = if now.month() == time::Month::January {
        Date::from_calendar_date(now.year() - 1, time::Month::December, 1)
    } else {
        Date::from_calendar_date(now.year(), now.month().previous(), 1)
    }
    .expect("valid");
    (
        clock::to_rfc3339(prev.with_time(time::Time::MIDNIGHT).assume_utc()),
        clock::to_rfc3339(this.with_time(time::Time::MIDNIGHT).assume_utc()),
    )
}

/// Cost-spike rule: this period's attributable cost against last period's.
/// Flags a large relative *and* absolute increase (to avoid noise on tiny
/// baselines). Returns an alert plus records an activity event.
pub fn cost_spike_alert(
    conn: &Connection,
    credential_id: &str,
    label: &str,
) -> Result<Option<NewAlert>> {
    let now = clock::now();
    let (prev_start, this_start) = month_bounds(now);
    let now_str = clock::now_rfc3339();
    let previous =
        usage::used_cost_between(conn, &prev_start, &this_start, Some(credential_id), None)?;
    let current = usage::used_cost_between(conn, &this_start, &now_str, Some(credential_id), None)?;

    // Require both a >=2x increase and at least $1.00 absolute growth.
    const ABS_FLOOR: i64 = 1_000_000;
    if previous > 0 && current >= previous.saturating_mul(2) && (current - previous) >= ABS_FLOOR {
        let ratio = current as f64 / previous as f64;
        Ok(Some(NewAlert {
            kind: AlertKind::CostSpike,
            severity: Severity::Medium,
            dedup_key: format!("cost_spike:{credential_id}"),
            title: format!("Cost for '{label}' jumped this period"),
            detail: format!(
                "this month's attributable cost is {} vs {} last month ({:.1}x)",
                usage::format_micros(current),
                usage::format_micros(previous),
                ratio
            ),
            evidence:
                "comparison period: last full month → this month; source: local usage snapshots"
                    .to_string(),
            confidence: Confidence::Medium,
            recommended_action:
                "confirm the increase is expected; check for a leaked or misused key".into(),
            project_id: None,
            credential_id: Some(credential_id.to_string()),
            observed_at: now_str,
        }))
    } else {
        Ok(None)
    }
}

/// The time a credential was last marked disabled, from the recorded
/// `credential_disabled` activity event (more precise than `updated_at`, which
/// any edit bumps). `None` when we have no recorded disable time.
pub fn last_disabled_at(conn: &Connection, credential_id: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT at FROM activity_events
             WHERE credential_id = ?1 AND kind = 'credential_disabled'
             ORDER BY id DESC LIMIT 1",
            [credential_id],
            |r| r.get::<_, String>(0),
        )
        .ok())
}

/// Usage-after-disabled rule: a credential marked disabled still has usage in
/// a window that starts on/after the recorded disable time. `disabled_since`
/// is the recorded disable time; if unknown (`None`), the rule is skipped
/// rather than guessing, to avoid false positives.
pub fn usage_after_disabled_alert(
    conn: &Connection,
    credential_id: &str,
    label: &str,
    disabled: bool,
    disabled_since: Option<&str>,
) -> Result<Option<NewAlert>> {
    if !disabled {
        return Ok(None);
    }
    let Some(disabled_since) = disabled_since else {
        return Ok(None);
    };
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM usage_snapshots WHERE credential_id = ?1 AND window_start >= ?2",
        params![credential_id, disabled_since],
        |r| r.get(0),
    )?;
    if count == 0 {
        return Ok(None);
    }
    Ok(Some(NewAlert {
        kind: AlertKind::UsageAfterDisabled,
        severity: Severity::High,
        dedup_key: format!("usage_after_disabled:{credential_id}"),
        title: format!("'{label}' shows usage after being disabled"),
        detail: format!("{count} usage snapshot(s) fall after this credential was marked disabled"),
        evidence: format!("comparison: usage window_start >= disabled time ({disabled_since})"),
        confidence: Confidence::High,
        recommended_action: "revoke the credential at the provider; it appears to still be in use"
            .into(),
        project_id: None,
        credential_id: Some(credential_id.to_string()),
        observed_at: clock::now_rfc3339(),
    }))
}

/// The activity-derived alert kinds this module manages, for auto-resolution.
pub fn managed_kinds() -> Vec<AlertKind> {
    vec![
        AlertKind::CostSpike,
        AlertKind::UsageAfterDisabled,
        AlertKind::OverBudget,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::usage::{Attribution, NewUsageSnapshot};

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        conn.pragma_update(None, "foreign_keys", 0).unwrap();
        conn
    }

    fn snap(conn: &Connection, cred: &str, start: &str, cost: i64) {
        let mut s = NewUsageSnapshot::new("openai", start, start);
        s.credential_id = Some(cred.into());
        s.reported_cost_micros = Some(cost);
        s.attribution = Attribution::ExactCredential;
        usage::record(conn, &s).unwrap();
    }

    #[test]
    fn records_and_lists_events() {
        let conn = mem();
        record(
            &conn,
            "process_session",
            "injection",
            Some("c1"),
            Some("p1"),
            "ran npm",
            "vars=1",
        )
        .unwrap();
        let events = list(&conn, 10, None).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "injection");
        assert!(!events[0].detail.is_empty());
    }

    #[test]
    fn usage_after_disabled_flags_only_when_disabled_and_present() {
        let conn = mem();
        snap(&conn, "c1", "2026-07-10T00:00:00Z", 5_000_000);
        // Disabled before the usage window: flagged.
        let a = usage_after_disabled_alert(
            &conn,
            "c1",
            "web/openai",
            true,
            Some("2026-07-01T00:00:00Z"),
        )
        .unwrap();
        assert!(a.is_some());
        // Not disabled: no alert.
        assert!(usage_after_disabled_alert(
            &conn,
            "c1",
            "web/openai",
            false,
            Some("2026-07-01T00:00:00Z")
        )
        .unwrap()
        .is_none());
        // Disabled after the usage: no alert.
        assert!(usage_after_disabled_alert(
            &conn,
            "c1",
            "web/openai",
            true,
            Some("2026-07-20T00:00:00Z")
        )
        .unwrap()
        .is_none());
        // Unknown disable time: skipped, not guessed.
        assert!(
            usage_after_disabled_alert(&conn, "c1", "web/openai", true, None)
                .unwrap()
                .is_none()
        );
    }
}
