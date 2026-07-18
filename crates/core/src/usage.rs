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

/// Convert a provider-reported decimal monetary amount into integer
/// micro-units, rejecting values that cannot be stored faithfully:
/// non-finite, negative, or large enough to overflow.
pub fn micros_from_decimal(value: f64) -> Result<i64> {
    if !value.is_finite() {
        return Err(CoreError::Provider(
            "provider reported a non-finite monetary amount".into(),
        ));
    }
    if value < 0.0 {
        return Err(CoreError::Provider(
            "provider reported a negative monetary amount".into(),
        ));
    }
    // Stay far below i64::MAX after scaling (≈ 9.2e12 dollars).
    const MAX_DOLLARS: f64 = 1.0e12;
    if value > MAX_DOLLARS {
        return Err(CoreError::Provider(
            "provider reported a monetary amount too large to store".into(),
        ));
    }
    Ok((value * MICROS_PER_USD as f64).round() as i64)
}

/// Attribution precision for a usage measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    /// Attributed to the exact local credential (best precision).
    ExactCredential,
    /// Grouped to an exact provider-side API-key id that is NOT (yet)
    /// linked to a local credential. Exact at the provider, unmapped here.
    ProviderKey,
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
            Attribution::ProviderKey => "provider_key",
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
            Attribution::ProviderKey => "exact provider key (not linked to a local credential)",
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
            "provider_key" => Attribution::ProviderKey,
            "provider_project" => Attribution::ProviderProject,
            "provider_account" => Attribution::ProviderAccount,
            "local_project" => Attribution::LocalProject,
            "local_process" => Attribution::LocalProcess,
            _ => Attribution::Unknown,
        })
    }
}

/// Input to record a new snapshot. Provider-side dimensions are `None` when
/// the provider did not report them — never invented locally.
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
    pub provider_account_id: Option<String>,
    pub provider_project_id: Option<String>,
    pub provider_api_key_id: Option<String>,
    pub line_item: Option<String>,
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
            provider_account_id: None,
            provider_project_id: None,
            provider_api_key_id: None,
            line_item: None,
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
    pub provider_account_id: Option<String>,
    pub provider_project_id: Option<String>,
    pub provider_api_key_id: Option<String>,
    pub line_item: Option<String>,
}

const COLUMNS: &str = "id, credential_id, project_id, provider, model, window_start, window_end, \
     request_count, input_tokens, output_tokens, total_tokens, credits, reported_cost_micros, \
     estimated_cost_micros, currency, source, attribution, collected_at, provider_account_id, \
     provider_project_id, provider_api_key_id, line_item";

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
        provider_account_id: row.get(18)?,
        provider_project_id: row.get(19)?,
        provider_api_key_id: row.get(20)?,
        line_item: row.get(21)?,
    })
}

/// Record a snapshot. Returns its id.
pub fn record(conn: &Connection, snap: &NewUsageSnapshot) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        &format!(
            "INSERT INTO usage_snapshots ({COLUMNS}) VALUES \
             (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, \
              ?19, ?20, ?21, ?22)"
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
            snap.provider_account_id,
            snap.provider_project_id,
            snap.provider_api_key_id,
            snap.line_item,
        ],
    )?;
    Ok(id)
}

/// Which snapshot sources a query includes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceFilter {
    #[default]
    All,
    /// Provider-synchronized rows only (anything not entered manually).
    Provider,
    /// Manually recorded rows only.
    Manual,
}

/// Filters for snapshot queries. `None` fields are unconstrained.
#[derive(Debug, Clone, Default)]
pub struct UsageFilter {
    pub since: Option<String>,
    pub until: Option<String>,
    pub credential_id: Option<String>,
    pub project_id: Option<String>,
    pub provider: Option<String>,
    pub source: SourceFilter,
}

fn filter_sql(filter: &UsageFilter) -> (String, Vec<String>) {
    let mut clauses = Vec::new();
    let mut params = Vec::new();
    let add = |clauses: &mut Vec<String>, params: &mut Vec<String>, col: &str, v: &str| {
        params.push(v.to_string());
        clauses.push(format!("{col} ?{}", params.len()));
    };
    if let Some(s) = &filter.since {
        add(&mut clauses, &mut params, "window_start >=", s);
    }
    if let Some(u) = &filter.until {
        add(&mut clauses, &mut params, "window_start <", u);
    }
    if let Some(c) = &filter.credential_id {
        add(&mut clauses, &mut params, "credential_id =", c);
    }
    if let Some(p) = &filter.project_id {
        add(&mut clauses, &mut params, "project_id =", p);
    }
    if let Some(p) = &filter.provider {
        add(&mut clauses, &mut params, "provider =", p);
    }
    match filter.source {
        SourceFilter::All => {}
        SourceFilter::Provider => clauses.push("source != 'manual'".into()),
        SourceFilter::Manual => clauses.push("source = 'manual'".into()),
    }
    if clauses.is_empty() {
        clauses.push("1=1".into());
    }
    (clauses.join(" AND "), params)
}

/// Aggregate totals over a set of snapshots. Reported and estimated costs
/// are summed separately (they come from different rows and must never be
/// added together — see `pick_used_cost`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct UsageTotals {
    pub snapshots: i64,
    pub request_count: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    /// Sum of provider-reported costs, USD rows only.
    pub reported_cost_micros: i64,
    /// Sum of locally estimated costs (always USD).
    pub estimated_cost_micros: i64,
    /// True if any snapshot is not exact-credential attribution.
    pub has_inexact_attribution: bool,
    /// The coarsest attribution present, for honest labeling.
    pub coarsest_attribution: Option<String>,
    /// Distinct currencies seen on provider-reported rows.
    pub reported_currencies: Vec<String>,
    /// True when non-USD reported rows exist; those are excluded from
    /// `reported_cost_micros` rather than silently mixed in.
    pub has_non_usd_reported: bool,
    /// Most recent collection time across the included snapshots.
    pub last_collected_at: Option<String>,
}

/// Totals for the snapshots matching `filter`.
pub fn totals(conn: &Connection, filter: &UsageFilter) -> Result<UsageTotals> {
    let snaps = list(conn, filter)?;
    let mut totals = UsageTotals::default();
    // Attribution coarseness ranking (higher = coarser).
    let rank = |a: &str| match a {
        "exact_credential" => 0,
        "local_process" => 0,
        "provider_key" => 1,
        "provider_project" => 2,
        "local_project" => 2,
        "provider_account" => 3,
        _ => 4,
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
        if let Some(rep) = s.reported_cost_micros {
            if s.currency.eq_ignore_ascii_case("USD") {
                totals.reported_cost_micros += rep;
            } else {
                totals.has_non_usd_reported = true;
            }
            if !totals
                .reported_currencies
                .iter()
                .any(|c| c.eq_ignore_ascii_case(&s.currency))
            {
                totals.reported_currencies.push(s.currency.to_uppercase());
            }
        }
        totals.estimated_cost_micros += s.estimated_cost_micros.unwrap_or(0);
        if s.attribution != "exact_credential" {
            totals.has_inexact_attribution = true;
        }
        let r = rank(&s.attribution);
        if r > worst {
            worst = r;
            totals.coarsest_attribution = Some(s.attribution.clone());
        }
        if totals
            .last_collected_at
            .as_deref()
            .map(|prev| s.collected_at.as_str() > prev)
            .unwrap_or(true)
        {
            totals.last_collected_at = Some(s.collected_at.clone());
        }
    }
    Ok(totals)
}

/// Totals for snapshots on/after `since`, optionally filtered.
pub fn totals_since(
    conn: &Connection,
    since: &str,
    credential_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<UsageTotals> {
    totals(
        conn,
        &UsageFilter {
            since: Some(since.to_string()),
            credential_id: credential_id.map(str::to_string),
            project_id: project_id.map(str::to_string),
            ..Default::default()
        },
    )
}

/// The cost source a budget consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CostSource {
    /// Provider-reported when any reported rows exist, else estimated.
    BestAvailable,
    ProviderReported,
    Estimated,
}

impl CostSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            CostSource::BestAvailable => "best_available",
            CostSource::ProviderReported => "provider_reported",
            CostSource::Estimated => "estimated",
        }
    }
}

impl FromStr for CostSource {
    type Err = CoreError;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "best_available" => Ok(CostSource::BestAvailable),
            "provider_reported" => Ok(CostSource::ProviderReported),
            "estimated" => Ok(CostSource::Estimated),
            other => Err(CoreError::InvalidInput(format!(
                "unknown cost source '{other}' (use best_available, provider_reported, or estimated)"
            ))),
        }
    }
}

/// Pick the used cost from totals for one configured source. Reported and
/// estimated sums come from *different rows* (cost rows vs. usage rows), so
/// exactly one of them is used — adding them would double-count the same
/// consumption.
pub fn pick_used_cost(totals: &UsageTotals, source: CostSource) -> (i64, bool) {
    match source {
        CostSource::ProviderReported => (totals.reported_cost_micros, false),
        CostSource::Estimated => (totals.estimated_cost_micros, true),
        CostSource::BestAvailable => {
            if totals.reported_cost_micros > 0 {
                (totals.reported_cost_micros, false)
            } else {
                (totals.estimated_cost_micros, true)
            }
        }
    }
}

/// Total used cost in a half-open window [start, end), optionally filtered
/// by credential/project, honoring the configured cost source.
pub fn used_cost_between(
    conn: &Connection,
    start: &str,
    end: &str,
    credential_id: Option<&str>,
    project_id: Option<&str>,
    source: CostSource,
) -> Result<i64> {
    let t = totals(
        conn,
        &UsageFilter {
            since: Some(start.to_string()),
            until: Some(end.to_string()),
            credential_id: credential_id.map(str::to_string),
            project_id: project_id.map(str::to_string),
            ..Default::default()
        },
    )?;
    Ok(pick_used_cost(&t, source).0)
}

/// Snapshots matching `filter`, newest first.
pub fn list(conn: &Connection, filter: &UsageFilter) -> Result<Vec<UsageSnapshot>> {
    let (clause, params) = filter_sql(filter);
    let sql =
        format!("SELECT {COLUMNS} FROM usage_snapshots WHERE {clause} ORDER BY window_start DESC");
    let mut stmt = conn.prepare(&sql)?;
    let binds: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
    let rows = stmt.query_map(binds.as_slice(), row_to_snapshot)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Snapshots on/after `since`, optionally filtered, newest first.
pub fn list_since(
    conn: &Connection,
    since: &str,
    credential_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<Vec<UsageSnapshot>> {
    list(
        conn,
        &UsageFilter {
            since: Some(since.to_string()),
            credential_id: credential_id.map(str::to_string),
            project_id: project_id.map(str::to_string),
            ..Default::default()
        },
    )
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
