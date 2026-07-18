//! Normalized local usage snapshots.
//!
//! A snapshot records what was consumed over a measurement window, plus the
//! precision at which it can be attributed. The attribution level is stored
//! and displayed honestly: account- or project-level data is never presented
//! as exact per-key usage. Monetary amounts are integer micro-USD.

use crate::clock;
use crate::error::{CoreError, Result};
use rusqlite::{params, Connection, Row};
use serde::Serialize;
use std::str::FromStr;
use uuid::Uuid;

/// One micro-USD is 1e-6 USD. All money is stored as integer micros.
pub const MICROS_PER_USD: i64 = 1_000_000;

/// Format an integer micro-USD amount as a dollar string.
pub fn format_micros(micros: i64) -> String {
    let cents = (micros as f64) / 10_000.0;
    format!("${:.2}", cents / 100.0)
}

/// Attribution precision for a usage measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    /// Attributed to the exact credential (best precision).
    ExactCredential,
    /// Provider-project granularity (several keys may share a project).
    ProviderProject,
    /// Whole provider account (org).
    ProviderAccount,
    /// Local API Tracker project only.
    LocalProject,
    /// A single local process-injection session.
    LocalProcess,
    Unknown,
}

impl Attribution {
    pub fn as_str(&self) -> &'static str {
        match self {
            Attribution::ExactCredential => "exact_credential",
            Attribution::ProviderProject => "provider_project",
            Attribution::ProviderAccount => "provider_account",
            Attribution::LocalProject => "local_project",
            Attribution::LocalProcess => "local_process",
            Attribution::Unknown => "unknown",
        }
    }

    /// A human label that never overstates precision.
    pub fn label(&self) -> &'static str {
        match self {
            Attribution::ExactCredential => "exact credential",
            Attribution::ProviderProject => "provider-project level (not per key)",
            Attribution::ProviderAccount => "provider-account level (not per key)",
            Attribution::LocalProject => "local project only",
            Attribution::LocalProcess => "local process session",
            Attribution::Unknown => "unknown precision",
        }
    }

    /// True when the measurement is precise enough to charge to one key.
    pub fn is_exact(&self) -> bool {
        matches!(self, Attribution::ExactCredential)
    }
}

impl FromStr for Attribution {
    type Err = CoreError;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "exact_credential" => Attribution::ExactCredential,
            "provider_project" => Attribution::ProviderProject,
            "provider_account" => Attribution::ProviderAccount,
            "local_project" => Attribution::LocalProject,
            "local_process" => Attribution::LocalProcess,
            _ => Attribution::Unknown,
        })
    }
}

/// Input to record a new snapshot.
#[derive(Debug, Clone)]
pub struct NewUsageSnapshot {
    pub credential_id: Option<String>,
    pub project_id: Option<String>,
    pub provider: String,
    pub model: Option<String>,
    pub window_start: String,
    pub window_end: String,
    pub request_count: Option<i64>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub total_tokens: Option<i64>,
    pub credits: Option<f64>,
    pub reported_cost_micros: Option<i64>,
    pub estimated_cost_micros: Option<i64>,
    pub currency: String,
    pub source: String,
    pub attribution: Attribution,
}

impl NewUsageSnapshot {
    pub fn new(provider: &str, window_start: &str, window_end: &str) -> Self {
        Self {
            credential_id: None,
            project_id: None,
            provider: provider.to_string(),
            model: None,
            window_start: window_start.to_string(),
            window_end: window_end.to_string(),
            request_count: None,
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            credits: None,
            reported_cost_micros: None,
            estimated_cost_micros: None,
            currency: "USD".to_string(),
            source: "provider_sync".to_string(),
            attribution: Attribution::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageSnapshot {
    pub id: String,
    pub credential_id: Option<String>,
    pub project_id: Option<String>,
    pub provider: String,
    pub model: Option<String>,
    pub window_start: String,
    pub window_end: String,
    pub request_count: Option<i64>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub total_tokens: Option<i64>,
    pub credits: Option<f64>,
    pub reported_cost_micros: Option<i64>,
    pub estimated_cost_micros: Option<i64>,
    pub currency: String,
    pub source: String,
    pub attribution: String,
    pub collected_at: String,
}

const COLUMNS: &str = "id, credential_id, project_id, provider, model, window_start, window_end, \
     request_count, input_tokens, output_tokens, total_tokens, credits, reported_cost_micros, \
     estimated_cost_micros, currency, source, attribution, collected_at";

fn row_to_snapshot(row: &Row<'_>) -> rusqlite::Result<UsageSnapshot> {
    Ok(UsageSnapshot {
        id: row.get(0)?,
        credential_id: row.get(1)?,
        project_id: row.get(2)?,
        provider: row.get(3)?,
        model: row.get(4)?,
        window_start: row.get(5)?,
        window_end: row.get(6)?,
        request_count: row.get(7)?,
        input_tokens: row.get(8)?,
        output_tokens: row.get(9)?,
        total_tokens: row.get(10)?,
        credits: row.get(11)?,
        reported_cost_micros: row.get(12)?,
        estimated_cost_micros: row.get(13)?,
        currency: row.get(14)?,
        source: row.get(15)?,
        attribution: row.get(16)?,
        collected_at: row.get(17)?,
    })
}

/// Record a snapshot. Returns its id.
pub fn record(conn: &Connection, snap: &NewUsageSnapshot) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        &format!(
            "INSERT INTO usage_snapshots ({COLUMNS}) VALUES \
             (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)"
        ),
        params![
            id,
            snap.credential_id,
            snap.project_id,
            snap.provider,
            snap.model,
            snap.window_start,
            snap.window_end,
            snap.request_count,
            snap.input_tokens,
            snap.output_tokens,
            snap.total_tokens,
            snap.credits,
            snap.reported_cost_micros,
            snap.estimated_cost_micros,
            snap.currency,
            snap.source,
            snap.attribution.as_str(),
            clock::now_rfc3339(),
        ],
    )?;
    Ok(id)
}

/// Aggregate totals over a set of snapshots.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UsageTotals {
    pub snapshots: i64,
    pub request_count: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub reported_cost_micros: i64,
    pub estimated_cost_micros: i64,
    /// True if any snapshot is not exact-credential attribution.
    pub has_inexact_attribution: bool,
    /// The coarsest attribution present, for honest labeling.
    pub coarsest_attribution: Option<String>,
}

fn window_filter(credential_id: Option<&str>, project_id: Option<&str>) -> (String, Vec<String>) {
    let mut clauses = vec!["window_start >= ?1".to_string()];
    let mut params = Vec::new();
    if let Some(c) = credential_id {
        clauses.push(format!("credential_id = ?{}", params.len() + 2));
        params.push(c.to_string());
    }
    if let Some(p) = project_id {
        clauses.push(format!("project_id = ?{}", params.len() + 2));
        params.push(p.to_string());
    }
    (clauses.join(" AND "), params)
}

/// Totals for snapshots on/after `since`, optionally filtered.
pub fn totals_since(
    conn: &Connection,
    since: &str,
    credential_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<UsageTotals> {
    let snaps = list_since(conn, since, credential_id, project_id)?;
    let mut totals = UsageTotals::default();
    // Attribution coarseness ranking (higher = coarser).
    let rank = |a: &str| match a {
        "exact_credential" => 0,
        "provider_project" => 1,
        "provider_account" => 2,
        "local_project" => 1,
        "local_process" => 0,
        _ => 3,
    };
    let mut worst = -1;
    for s in &snaps {
        totals.snapshots += 1;
        totals.request_count += s.request_count.unwrap_or(0);
        totals.input_tokens += s.input_tokens.unwrap_or(0);
        totals.output_tokens += s.output_tokens.unwrap_or(0);
        totals.total_tokens += s
            .total_tokens
            .unwrap_or(s.input_tokens.unwrap_or(0) + s.output_tokens.unwrap_or(0));
        totals.reported_cost_micros += s.reported_cost_micros.unwrap_or(0);
        totals.estimated_cost_micros += s.estimated_cost_micros.unwrap_or(0);
        if s.attribution != "exact_credential" {
            totals.has_inexact_attribution = true;
        }
        let r = rank(&s.attribution);
        if r > worst {
            worst = r;
            totals.coarsest_attribution = Some(s.attribution.clone());
        }
    }
    Ok(totals)
}

/// Total used cost (reported if present, else estimated) in a half-open
/// window [start, end), optionally filtered by credential/project.
pub fn used_cost_between(
    conn: &Connection,
    start: &str,
    end: &str,
    credential_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<i64> {
    let mut clauses = vec![
        "window_start >= ?1".to_string(),
        "window_start < ?2".to_string(),
    ];
    let mut binds: Vec<&dyn rusqlite::ToSql> = vec![&start, &end];
    let cred = credential_id;
    let proj = project_id;
    if let Some(c) = &cred {
        clauses.push(format!("credential_id = ?{}", binds.len() + 1));
        binds.push(c);
    }
    if let Some(p) = &proj {
        clauses.push(format!("project_id = ?{}", binds.len() + 1));
        binds.push(p);
    }
    let sql = format!(
        "SELECT COALESCE(SUM(CASE WHEN reported_cost_micros IS NOT NULL AND reported_cost_micros > 0 \
         THEN reported_cost_micros ELSE COALESCE(estimated_cost_micros, 0) END), 0) \
         FROM usage_snapshots WHERE {}",
        clauses.join(" AND ")
    );
    let total: i64 = conn.query_row(&sql, binds.as_slice(), |r| r.get(0))?;
    Ok(total)
}

/// Snapshots on/after `since`, optionally filtered, newest first.
pub fn list_since(
    conn: &Connection,
    since: &str,
    credential_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<Vec<UsageSnapshot>> {
    let (filter, extra) = window_filter(credential_id, project_id);
    let sql =
        format!("SELECT {COLUMNS} FROM usage_snapshots WHERE {filter} ORDER BY window_start DESC");
    let mut stmt = conn.prepare(&sql)?;
    let mut binds: Vec<&dyn rusqlite::ToSql> = vec![&since];
    for e in &extra {
        binds.push(e);
    }
    let rows = stmt.query_map(binds.as_slice(), row_to_snapshot)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        // This unit test exercises aggregation with synthetic ids, not
        // referential integrity, so relax the foreign keys here.
        conn.pragma_update(None, "foreign_keys", 0).unwrap();
        conn
    }

    #[test]
    fn record_and_aggregate() {
        let conn = mem();
        let mut a = NewUsageSnapshot::new("openai", "2026-07-01T00:00:00Z", "2026-07-02T00:00:00Z");
        a.credential_id = Some("cred-1".into());
        a.input_tokens = Some(1000);
        a.output_tokens = Some(500);
        a.estimated_cost_micros = Some(3_500);
        a.attribution = Attribution::ExactCredential;
        record(&conn, &a).unwrap();

        let mut b = a.clone();
        b.input_tokens = Some(2000);
        b.output_tokens = Some(1000);
        b.estimated_cost_micros = Some(7_000);
        b.attribution = Attribution::ProviderProject; // coarser
        record(&conn, &b).unwrap();

        let totals = totals_since(&conn, "2026-07-01T00:00:00Z", Some("cred-1"), None).unwrap();
        assert_eq!(totals.snapshots, 2);
        assert_eq!(totals.input_tokens, 3000);
        assert_eq!(totals.output_tokens, 1500);
        assert_eq!(totals.total_tokens, 4500);
        assert_eq!(totals.estimated_cost_micros, 10_500);
        assert!(totals.has_inexact_attribution);
        assert_eq!(
            totals.coarsest_attribution.as_deref(),
            Some("provider_project")
        );
    }

    #[test]
    fn attribution_labels_are_honest() {
        assert!(Attribution::ExactCredential.is_exact());
        assert!(!Attribution::ProviderAccount.is_exact());
        assert!(Attribution::ProviderAccount.label().contains("not per key"));
    }

    #[test]
    fn micros_format() {
        assert_eq!(format_micros(1_000_000), "$1.00");
        assert_eq!(format_micros(3_500), "$0.00");
        assert_eq!(format_micros(2_500_000), "$2.50");
    }
}
