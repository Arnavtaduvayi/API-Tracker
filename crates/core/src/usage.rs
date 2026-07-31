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
    /// Local Tethra project only.
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
    /// Non-token units, verbatim from the provider (requests, events,
    /// credits, bytes, operations, ...). Never coerced into tokens.
    pub quantity: Option<f64>,
    pub unit: Option<String>,
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
            quantity: None,
            unit: None,
        }
    }
}

/// Drop provider-fetched snapshots whose time window is unusable, returning
/// how many were dropped. Sync engines derive their replace-range DELETE
/// bounds from these provider-controlled strings, and the comparison is
/// lexicographic: a missing or blank `window_start` sorts below every real
/// timestamp, so one malformed bucket would otherwise delete the provider's
/// entire stored history (OBS-003). A window is usable only when both
/// bounds parse as RFC3339 and the range is not inverted.
pub fn retain_valid_windows(rows: &mut Vec<NewUsageSnapshot>) -> usize {
    let before = rows.len();
    rows.retain(|s| {
        matches!(
            (
                crate::clock::parse_rfc3339(&s.window_start),
                crate::clock::parse_rfc3339(&s.window_end),
            ),
            (Ok(start), Ok(end)) if start <= end
        )
    });
    before - rows.len()
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
    /// Non-token units, verbatim from the provider (requests, events,
    /// credits, bytes, operations, ...). Never coerced into tokens.
    pub quantity: Option<f64>,
    pub unit: Option<String>,
}

const COLUMNS: &str = "id, credential_id, project_id, provider, model, window_start, window_end, \
     request_count, input_tokens, output_tokens, total_tokens, credits, reported_cost_micros, \
     estimated_cost_micros, currency, source, attribution, collected_at, provider_account_id, \
     provider_project_id, provider_api_key_id, line_item, quantity, unit";

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
        quantity: row.get(22)?,
        unit: row.get(23)?,
    })
}

/// Record a snapshot. Returns its id.
pub fn record(conn: &Connection, snap: &NewUsageSnapshot) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        &format!(
            "INSERT INTO usage_snapshots ({COLUMNS}) VALUES \
             (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, \
              ?19, ?20, ?21, ?22, ?23, ?24)"
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
            snap.quantity,
            snap.unit,
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

/// Why a folded number is, or is not, showable (NEW-37).
///
/// This is the Rust half of the vocabulary in `apps/desktop/src/usage.ts`
/// (`UsageAvailability`). Every sum in [`UsageTotals`] folds `Option<i64>`
/// columns with `unwrap_or(0)`, so the sum alone cannot distinguish "no
/// record carried this number" from "the records carried numbers adding up
/// to zero". The residual counts recorded alongside each sum answer that
/// question, and this enum is the single predicate that turns a
/// covered/total pair into a decision.
///
/// The rule, stated once: a number may be presented as a TOTAL only when
/// every record in scope carried it. A sum over a mix of carrying and
/// non-carrying records is a FLOOR, never a total. A measured zero stays
/// expressible — hiding it would be a different lie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Availability {
    /// Every record in scope carried the number. The value — including 0 —
    /// is a measurement.
    Known { covered: i64, total: i64 },
    /// Some records carried it. The value is a lower bound over `covered`
    /// of `total` records.
    Partial { covered: i64, total: i64 },
    /// Nothing in scope carried the number. Absent is never zero.
    Unknown { total: i64 },
    /// The records in scope are metered in something other than this
    /// number, by design. It does not exist; it is not merely missing.
    Unsupported { detail: String },
}

/// The single predicate. `covered` records carried the number; `total` were
/// in scope. Nothing in scope, or nothing carrying it, is unknown — never
/// zero.
pub fn from_coverage(covered: i64, total: i64) -> Availability {
    if total <= 0 {
        return Availability::Unknown { total: 0 };
    }
    if covered <= 0 {
        return Availability::Unknown { total };
    }
    if covered < total {
        return Availability::Partial { covered, total };
    }
    Availability::Known { covered, total }
}

impl Availability {
    /// Whether a number may be shown at all. False means a sentence must
    /// replace it.
    pub fn has_value(&self) -> bool {
        matches!(
            self,
            Availability::Known { .. } | Availability::Partial { .. }
        )
    }

    /// Whether the number may be presented as a complete total. A partial
    /// sum is a floor and must never be compared as if it were the whole.
    pub fn is_complete(&self) -> bool {
        matches!(self, Availability::Known { .. })
    }

    /// How many records in scope carried the number.
    pub fn covered(&self) -> i64 {
        match self {
            Availability::Known { covered, .. } | Availability::Partial { covered, .. } => *covered,
            _ => 0,
        }
    }

    /// How many records were in scope.
    pub fn total(&self) -> i64 {
        match self {
            Availability::Known { total, .. }
            | Availability::Partial { total, .. }
            | Availability::Unknown { total } => *total,
            Availability::Unsupported { .. } => 0,
        }
    }

    /// A short machine-stable tag, for JSON consumers and tests.
    pub fn as_str(&self) -> &'static str {
        match self {
            Availability::Known { .. } => "known",
            Availability::Partial { .. } => "partial",
            Availability::Unknown { .. } => "unknown",
            Availability::Unsupported { .. } => "unsupported",
        }
    }

    /// The clause shown INSTEAD of a number, without the subject's name.
    /// Surfaces that already print a label ("Input tokens: …") use this so
    /// the name is not said twice. It never contains a figure that was not
    /// measured.
    pub fn sentence_body(&self, s: &UsageSubject) -> String {
        match self {
            Availability::Unsupported { detail } => {
                format!("not reported by this source — {detail}")
            }
            Availability::Unknown { total } => {
                let reason = if *total > 0 {
                    format!("none of the {total} {} carried {}", s.unit, s.carrier)
                } else {
                    format!("no {} in this window", s.unit)
                };
                match s.absent_detail {
                    Some(d) => format!("not reported — {reason} ({d})"),
                    None => format!("not reported — {reason}"),
                }
            }
            // Reached only when a value-bearing availability arrives with no
            // value — a contradiction between the count and the payload. A
            // missing number is never rendered as a zero.
            _ => "not reported — the value was missing where the source said it was known"
                .to_string(),
        }
    }

    /// The standalone sentence shown INSTEAD of a number, for surfaces that
    /// print no separate label.
    pub fn sentence(&self, s: &UsageSubject) -> String {
        format!("{} {}", s.name, self.sentence_body(s))
    }

    /// The clause qualifying a number that IS shown, or None when the
    /// number stands alone as a complete measurement.
    pub fn note(&self, s: &UsageSubject) -> Option<String> {
        match self {
            Availability::Partial { covered, total } => Some(format!(
                "{}: {covered} of {total} {} carried {}, and the rest are NOT counted as zero",
                s.partial_label, s.unit, s.carrier
            )),
            _ => None,
        }
    }
}

/// The wording for one measured quantity. Only phrasing lives here — the
/// predicate above is shared, so a new surface cannot pick up a new rule
/// along with its new label.
#[derive(Debug, Clone, Copy)]
pub struct UsageSubject {
    /// Sentence-leading noun phrase: "Input tokens", "Estimated cost".
    pub name: &'static str,
    /// Label for a sum that is a floor: "Partial token data".
    pub partial_label: &'static str,
    /// What a record must carry for the number to be known.
    pub carrier: &'static str,
    /// What is being counted: "usage record(s)".
    pub unit: &'static str,
    /// Why absence is normal, so "not reported" does not read as a fault.
    pub absent_detail: Option<&'static str>,
}

const RECORDS: &str = "usage record(s)";

pub const SUBJECT_REQUESTS: UsageSubject = UsageSubject {
    name: "Requests",
    partial_label: "Partial request data",
    carrier: "a request count",
    unit: RECORDS,
    absent_detail: Some("many providers report consumption without a request count"),
};

pub const SUBJECT_INPUT_TOKENS: UsageSubject = UsageSubject {
    name: "Input tokens",
    partial_label: "Partial token data",
    carrier: "an input token count",
    unit: RECORDS,
    absent_detail: Some("many providers meter products in units other than tokens"),
};

pub const SUBJECT_OUTPUT_TOKENS: UsageSubject = UsageSubject {
    name: "Output tokens",
    partial_label: "Partial token data",
    carrier: "an output token count",
    unit: RECORDS,
    absent_detail: Some("many providers meter products in units other than tokens"),
};

pub const SUBJECT_TOTAL_TOKENS: UsageSubject = UsageSubject {
    name: "Total tokens",
    partial_label: "Partial token data",
    carrier: "a token count",
    unit: RECORDS,
    absent_detail: Some("many providers meter products in units other than tokens"),
};

pub const SUBJECT_REPORTED_COST: UsageSubject = UsageSubject {
    name: "Reported cost",
    partial_label: "Partial cost data",
    carrier: "a USD provider-reported cost",
    unit: RECORDS,
    absent_detail: None,
};

pub const SUBJECT_ESTIMATED_COST: UsageSubject = UsageSubject {
    name: "Estimated cost",
    partial_label: "Partial cost data",
    carrier: "a local cost estimate",
    unit: RECORDS,
    absent_detail: Some("an estimate exists only where local pricing covers the model"),
};

/// Render a count with its qualifier, or the sentence that replaces it.
/// `render_count` can never print "0" for an absent number.
pub fn render_count(value: i64, a: &Availability, s: &UsageSubject) -> String {
    if !a.has_value() {
        return a.sentence_body(s);
    }
    match a.note(s) {
        Some(note) => format!("{value} — {note}"),
        None => value.to_string(),
    }
}

/// Micro-USD as dollars, or the sentence that replaces it. Returns a dollar
/// figure only for a measured or derived amount — an unknown cost never
/// acquires a dollar sign.
pub fn render_micros(micros: i64, a: &Availability, s: &UsageSubject) -> String {
    if !a.has_value() {
        return a.sentence_body(s);
    }
    let text = format_micros(micros);
    match a.note(s) {
        Some(note) => format!("{text} — {note}"),
        None => text,
    }
}

/// Aggregate totals over a set of snapshots. Reported and estimated costs
/// are summed separately (they come from different rows and must never be
/// added together — see `pick_used_cost`).
///
/// Every `*_micros` / token / request sum below folds `Option` columns with
/// `unwrap_or(0)`, so each is accompanied by the count of records that
/// actually carried it. The sums keep their original meaning (callers
/// depend on it); the counts are what let a caller ask "how many records
/// did this total actually fold?" and refuse to present a floor as a total.
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

    // --- residual coverage counts (NEW-37) ------------------------------
    // Additive: they do not change any sum above. `rows_without_*` is
    // always `snapshots - *_rows` and is materialised so that a JSON
    // consumer cannot forget to compute it.
    /// Records that carried a request count.
    pub request_rows: i64,
    /// Records in scope that carried no request count.
    pub rows_without_requests: i64,
    /// Records that carried an input token count.
    pub input_token_rows: i64,
    /// Records in scope that carried no input token count.
    pub rows_without_input_tokens: i64,
    /// Records that carried an output token count.
    pub output_token_rows: i64,
    /// Records in scope that carried no output token count.
    pub rows_without_output_tokens: i64,
    /// Records from which a token total could be derived: an explicit
    /// `total_tokens`, or at least one of input/output. These are exactly
    /// the records that contributed to `total_tokens`.
    pub token_rows: i64,
    /// Records in scope that carried no token count at all.
    pub rows_without_tokens: i64,
    /// Records that carried a USD provider-reported cost — exactly those
    /// folded into `reported_cost_micros`. Non-USD rows are excluded from
    /// the sum and so are excluded here.
    pub reported_cost_rows: i64,
    /// Records in scope that contributed nothing to `reported_cost_micros`.
    pub rows_without_reported_cost: i64,
    /// Records that carried a local cost estimate.
    pub estimated_cost_rows: i64,
    /// Records in scope that carried no local cost estimate.
    pub rows_without_estimated_cost: i64,
    /// Records metered in a non-token unit (a `quantity`/`unit` pair) that
    /// carried no token count. Their consumption is real but is not
    /// expressible in tokens, so it is reported as unsupported rather than
    /// as an absent token count.
    pub non_token_unit_rows: i64,
    /// The distinct non-token units seen, verbatim from the provider.
    pub non_token_units: Vec<String>,
}

impl UsageTotals {
    fn tokens_availability(&self, covered: i64) -> Availability {
        // Every record in scope is metered in some other unit: the token
        // count does not exist here, rather than merely being missing.
        if self.snapshots > 0 && self.token_rows == 0 && self.non_token_unit_rows == self.snapshots
        {
            return Availability::Unsupported {
                detail: format!(
                    "these {} record(s) are metered in {}, not tokens",
                    self.snapshots,
                    self.non_token_units.join(", ")
                ),
            };
        }
        from_coverage(covered, self.snapshots)
    }

    /// Availability of `request_count`.
    pub fn request_availability(&self) -> Availability {
        from_coverage(self.request_rows, self.snapshots)
    }

    /// Availability of `input_tokens`.
    pub fn input_token_availability(&self) -> Availability {
        self.tokens_availability(self.input_token_rows)
    }

    /// Availability of `output_tokens`.
    pub fn output_token_availability(&self) -> Availability {
        self.tokens_availability(self.output_token_rows)
    }

    /// Availability of `total_tokens`.
    pub fn total_token_availability(&self) -> Availability {
        self.tokens_availability(self.token_rows)
    }

    /// Availability of `reported_cost_micros`.
    pub fn reported_cost_availability(&self) -> Availability {
        from_coverage(self.reported_cost_rows, self.snapshots)
    }

    /// Availability of `estimated_cost_micros`.
    pub fn estimated_cost_availability(&self) -> Availability {
        from_coverage(self.estimated_cost_rows, self.snapshots)
    }
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
        // Residual coverage, counted from the SAME `Option`s the sums fold
        // above, so a sum and its count can never disagree about which rows
        // contributed.
        if s.request_count.is_some() {
            totals.request_rows += 1;
        }
        if s.input_tokens.is_some() {
            totals.input_token_rows += 1;
        }
        if s.output_tokens.is_some() {
            totals.output_token_rows += 1;
        }
        let carries_tokens =
            s.total_tokens.is_some() || s.input_tokens.is_some() || s.output_tokens.is_some();
        if carries_tokens {
            totals.token_rows += 1;
        }
        if !carries_tokens {
            if let Some(unit) = &s.unit {
                totals.non_token_unit_rows += 1;
                if !totals
                    .non_token_units
                    .iter()
                    .any(|u| u.eq_ignore_ascii_case(unit))
                {
                    totals.non_token_units.push(unit.clone());
                }
            }
        }
        if s.estimated_cost_micros.is_some() {
            totals.estimated_cost_rows += 1;
        }
        if let Some(rep) = s.reported_cost_micros {
            if s.currency.eq_ignore_ascii_case("USD") {
                totals.reported_cost_micros += rep;
                totals.reported_cost_rows += 1;
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
    totals.rows_without_requests = totals.snapshots - totals.request_rows;
    totals.rows_without_input_tokens = totals.snapshots - totals.input_token_rows;
    totals.rows_without_output_tokens = totals.snapshots - totals.output_token_rows;
    totals.rows_without_tokens = totals.snapshots - totals.token_rows;
    totals.rows_without_reported_cost = totals.snapshots - totals.reported_cost_rows;
    totals.rows_without_estimated_cost = totals.snapshots - totals.estimated_cost_rows;
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

/// The availability of the figure [`pick_used_cost`] returns, for the same
/// totals and source. It mirrors that function's branching exactly so the
/// number and its completeness can never come from different rows: a budget
/// compared against a floor it believes is a total is the correctness half
/// of NEW-37, not merely a display problem.
pub fn pick_used_cost_availability(totals: &UsageTotals, source: CostSource) -> Availability {
    match source {
        CostSource::ProviderReported => totals.reported_cost_availability(),
        CostSource::Estimated => totals.estimated_cost_availability(),
        CostSource::BestAvailable => {
            if totals.reported_cost_micros > 0 {
                totals.reported_cost_availability()
            } else {
                totals.estimated_cost_availability()
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
