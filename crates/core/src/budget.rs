//! Project- and credential-level budgets, current-period usage, and cost
//! projection.
//!
//! A budget is a monthly cost ceiling in micro-USD. Reports use the current
//! calendar month (UTC) as the period. "Used" cost prefers provider-reported
//! cost when present and falls back to the locally estimated cost, which is
//! always labeled estimated by callers. Only usage that is attributable to a
//! project or credential counts against its budget — account-level provider
//! usage does not, which is honest about attribution limits.

use crate::alerts::{AlertKind, NewAlert, Severity};
use crate::clock;
use crate::error::Result;
use crate::providers::Confidence;
use crate::usage;
use rusqlite::{params, Connection};
use serde::Serialize;
use time::{Date, OffsetDateTime, Time};

/// Start of the current calendar month, UTC, as an RFC 3339 string.
pub fn period_start(now: OffsetDateTime) -> String {
    let first =
        Date::from_calendar_date(now.year(), now.month(), 1).expect("day 1 is always valid");
    clock::to_rfc3339(first.with_time(Time::MIDNIGHT).assume_utc())
}

fn days_in_month(now: OffsetDateTime) -> i64 {
    let year = now.year();
    let month = now.month();
    let next = if month == time::Month::December {
        Date::from_calendar_date(year + 1, time::Month::January, 1)
    } else {
        Date::from_calendar_date(year, month.next(), 1)
    }
    .expect("valid");
    let this = Date::from_calendar_date(year, month, 1).expect("valid");
    (next - this).whole_days()
}

#[derive(Debug, Clone, Serialize)]
pub struct BudgetReport {
    pub scope: String,
    pub budget_micros: Option<i64>,
    pub period_start: String,
    pub reported_cost_micros: i64,
    pub estimated_cost_micros: i64,
    /// The figure used for budget comparison, chosen by `cost_source` —
    /// never the sum of both (cost rows and usage rows describe the same
    /// consumption, so adding them would double-count).
    pub used_micros: i64,
    pub used_is_estimated: bool,
    /// Which cost source this budget is configured to consume.
    pub cost_source: String,
    pub remaining_micros: Option<i64>,
    pub projected_period_end_micros: i64,
    pub over_budget: bool,
    pub attribution_note: Option<String>,
}

fn build_report(
    scope: String,
    budget: Option<i64>,
    totals: &usage::UsageTotals,
    now: OffsetDateTime,
    cost_source: usage::CostSource,
) -> BudgetReport {
    let reported = totals.reported_cost_micros;
    let estimated = totals.estimated_cost_micros;
    let (used, used_is_estimated) = usage::pick_used_cost(totals, cost_source);

    // Projection: scale used cost by (days in month / days elapsed).
    let day = now.day() as i64;
    let elapsed = day.max(1);
    let dim = days_in_month(now);
    let projected = if elapsed > 0 {
        used.saturating_mul(dim) / elapsed
    } else {
        used
    };

    let remaining = budget.map(|b| b - used);
    let over_budget = budget.map(|b| used > b).unwrap_or(false);

    BudgetReport {
        scope,
        budget_micros: budget,
        period_start: period_start(now),
        reported_cost_micros: reported,
        estimated_cost_micros: estimated,
        used_micros: used,
        used_is_estimated,
        cost_source: cost_source.as_str().to_string(),
        remaining_micros: remaining,
        projected_period_end_micros: projected,
        over_budget,
        attribution_note: totals
            .coarsest_attribution
            .clone()
            .map(|a| format!("based on usage attributed at: {}", a)),
    }
}

pub fn project_report(
    conn: &Connection,
    project_id: &str,
    cost_source: usage::CostSource,
) -> Result<BudgetReport> {
    let now = clock::now();
    let start = period_start(now);
    let budget: Option<i64> = conn.query_row(
        "SELECT monthly_budget_micros FROM projects WHERE id = ?1",
        [project_id],
        |r| r.get(0),
    )?;
    let name: String = conn.query_row(
        "SELECT name FROM projects WHERE id = ?1",
        [project_id],
        |r| r.get(0),
    )?;
    let totals = usage::totals_since(conn, &start, None, Some(project_id))?;
    Ok(build_report(
        format!("project:{name}"),
        budget,
        &totals,
        now,
        cost_source,
    ))
}

pub fn credential_report(
    conn: &Connection,
    credential_id: &str,
    label: &str,
    cost_source: usage::CostSource,
) -> Result<BudgetReport> {
    let now = clock::now();
    let start = period_start(now);
    let budget: Option<i64> = conn.query_row(
        "SELECT monthly_budget_micros FROM credentials WHERE id = ?1",
        [credential_id],
        |r| r.get(0),
    )?;
    let totals = usage::totals_since(conn, &start, Some(credential_id), None)?;
    Ok(build_report(
        format!("credential:{label}"),
        budget,
        &totals,
        now,
        cost_source,
    ))
}

pub fn set_project_budget(conn: &Connection, project_id: &str, micros: Option<i64>) -> Result<()> {
    conn.execute(
        "UPDATE projects SET monthly_budget_micros = ?1, updated_at = ?2 WHERE id = ?3",
        params![micros, clock::now_rfc3339(), project_id],
    )?;
    Ok(())
}

pub fn set_credential_budget(
    conn: &Connection,
    credential_id: &str,
    micros: Option<i64>,
) -> Result<()> {
    conn.execute(
        "UPDATE credentials SET monthly_budget_micros = ?1, updated_at = ?2 WHERE id = ?3",
        params![micros, clock::now_rfc3339(), credential_id],
    )?;
    Ok(())
}

/// Build an over-budget alert from a report, if it is over budget.
pub fn over_budget_alert(report: &BudgetReport, credential_id: Option<&str>) -> Option<NewAlert> {
    if !report.over_budget {
        return None;
    }
    let budget = report.budget_micros.unwrap_or(0);
    Some(NewAlert {
        kind: AlertKind::OverBudget,
        severity: Severity::High,
        dedup_key: format!("over_budget:{}", report.scope),
        title: format!("{} is over budget", report.scope),
        detail: format!(
            "used {} of a {} monthly budget ({} cost)",
            usage::format_micros(report.used_micros),
            usage::format_micros(budget),
            if report.used_is_estimated {
                "estimated"
            } else {
                "provider-reported"
            }
        ),
        evidence: format!(
            "projected month-end {} · {}",
            usage::format_micros(report.projected_period_end_micros),
            report.attribution_note.clone().unwrap_or_default()
        ),
        confidence: if report.used_is_estimated {
            Confidence::Medium
        } else {
            Confidence::High
        },
        recommended_action: "review usage, raise the budget, or rotate/limit the credential".into(),
        project_id: None,
        credential_id: credential_id.map(str::to_string),
        observed_at: clock::now_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage::UsageTotals;

    fn totals(reported: i64, estimated: i64) -> UsageTotals {
        UsageTotals {
            reported_cost_micros: reported,
            estimated_cost_micros: estimated,
            coarsest_attribution: Some("local_project".into()),
            ..Default::default()
        }
    }

    #[test]
    fn period_start_is_first_of_month() {
        let now = clock::parse_rfc3339("2026-07-18T12:00:00Z").unwrap();
        assert_eq!(period_start(now), "2026-07-01T00:00:00Z");
    }

    #[test]
    fn uses_reported_cost_when_present_else_estimated() {
        let now = clock::parse_rfc3339("2026-07-15T00:00:00Z").unwrap();
        let r = build_report(
            "project:x".into(),
            Some(10_000_000),
            &totals(4_000_000, 9_000_000),
            now,
            usage::CostSource::BestAvailable,
        );
        // Best-available picks reported OR estimated — never their sum.
        assert_eq!(r.used_micros, 4_000_000);
        assert!(!r.used_is_estimated);

        let r2 = build_report(
            "project:x".into(),
            Some(10_000_000),
            &totals(0, 9_000_000),
            now,
            usage::CostSource::BestAvailable,
        );
        assert_eq!(r2.used_micros, 9_000_000);
        assert!(r2.used_is_estimated);
    }

    #[test]
    fn explicit_cost_source_is_respected() {
        let now = clock::parse_rfc3339("2026-07-15T00:00:00Z").unwrap();
        let r = build_report(
            "project:x".into(),
            Some(10_000_000),
            &totals(4_000_000, 9_000_000),
            now,
            usage::CostSource::Estimated,
        );
        assert_eq!(r.used_micros, 9_000_000);
        assert!(r.used_is_estimated);
        assert_eq!(r.cost_source, "estimated");

        let r2 = build_report(
            "project:x".into(),
            Some(10_000_000),
            &totals(0, 9_000_000),
            now,
            usage::CostSource::ProviderReported,
        );
        // Explicit provider-reported never silently substitutes estimates.
        assert_eq!(r2.used_micros, 0);
    }

    #[test]
    fn over_budget_detected_and_projected() {
        // July has 31 days; on day 15 with $6 used, projected ≈ $12.40.
        let now = clock::parse_rfc3339("2026-07-15T00:00:00Z").unwrap();
        let r = build_report(
            "project:x".into(),
            Some(5_000_000),
            &totals(6_000_000, 0),
            now,
            usage::CostSource::BestAvailable,
        );
        assert!(r.over_budget);
        assert_eq!(r.remaining_micros, Some(-1_000_000));
        assert!(r.projected_period_end_micros > 12_000_000);
        let alert = over_budget_alert(&r, None).unwrap();
        assert_eq!(alert.kind, AlertKind::OverBudget);
        assert_eq!(alert.severity, Severity::High);
    }

    #[test]
    fn under_budget_has_no_alert() {
        let now = clock::parse_rfc3339("2026-07-15T00:00:00Z").unwrap();
        let r = build_report(
            "project:x".into(),
            Some(100_000_000),
            &totals(1_000_000, 0),
            now,
            usage::CostSource::BestAvailable,
        );
        assert!(!r.over_budget);
        assert!(over_budget_alert(&r, None).is_none());
    }
}
