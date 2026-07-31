//! Bounded, project-scoped reads over locally recorded observations, for the
//! live project activity surface (ADR 0029).
//!
//! Every query here is aggregated in SQL and bounded by a time window plus an
//! explicit row/bucket cap. Nothing transfers raw observation history to a
//! frontend, and nothing reads a request or response payload — there is no
//! column that holds one (`crates/gateway/src/record.rs`).
//!
//! ## Why the series reads raw events and not `runtime_metric_buckets`
//!
//! `aggregate::roll_up` only rolls up *complete* hours: it returns early when
//! `current_hour <= from_hour`. So the hour in progress is never in
//! `runtime_metric_buckets` — which is precisely the hour a live activity view
//! is about. A chart sourced from the rollup would show nothing for traffic
//! that just arrived and then appear to jump an hour later. These queries read
//! `runtime_request_events` directly, over `idx_rre_project` /
//! `idx_rre_project_source_at`, so "live" means live.
//!
//! ## Absent is not zero
//!
//! A bucket is emitted only when something was observed in it. Within a
//! bucket, request and error counts are measured, but token and cost figures
//! carry their own `*_known` flag: `SUM` over a column that is NULL for every
//! row yields NULL, and that means "nobody reported this", not "the total was
//! zero". Callers render the unknown case as unknown.

use std::collections::{BTreeMap, HashMap};

use rusqlite::{params, Connection, ToSql};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::pricing::{self, PricingRecord};
use crate::projectcost::ESTIMATE_CURRENCY;
use crate::runtime::inventory;

/// Most buckets one series will return. A 30-day daily series is 30 points and
/// a one-hour minute series is 60; the cap bounds a hostile or mis-specified
/// window rather than a normal one.
pub const MAX_BUCKETS: usize = 750;

/// Most rows the recent-activity table will return.
pub const MAX_RECENT_ROWS: usize = 200;

/// How wide each series bucket is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Granularity {
    Minute,
    Hour,
    Day,
}

impl Granularity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minute => "minute",
            Self::Hour => "hour",
            Self::Day => "day",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "minute" => Self::Minute,
            "day" => Self::Day,
            _ => Self::Hour,
        }
    }

    /// A SQL expression that floors an RFC 3339 `at` to this bucket, producing
    /// a value in the same RFC 3339 shape so the frontend parses one format.
    ///
    /// Prefix slicing is safe for either spelling of the timestamp: with or
    /// without a fractional part, the first 10/13/16 bytes are the date, the
    /// date-hour, and the date-hour-minute respectively.
    fn bucket_expr(self, column: &str) -> String {
        match self {
            Self::Minute => format!("substr({column}, 1, 16) || ':00Z'"),
            Self::Hour => format!("substr({column}, 1, 13) || ':00:00Z'"),
            Self::Day => format!("substr({column}, 1, 10) || 'T00:00:00Z'"),
        }
    }
}

/// One point in a project's activity series.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectSeriesPoint {
    pub bucket_start: String,
    /// Measured: the number of observations recorded in this bucket.
    pub requests: i64,
    /// Measured: 4xx + 5xx + transport + TLS failures.
    pub errors: i64,
    /// Mean latency over the observations in this bucket that HAD a latency.
    /// `None` when none did (for example a bucket of transport failures).
    pub avg_latency_ms: Option<i64>,
    /// `None` means no request in this bucket reported token usage.
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    /// Locally estimated cost for this bucket, in micro-units of
    /// [`ESTIMATE_CURRENCY`]. `None` when nothing in the bucket could be
    /// priced — never `Some(0)` standing in for "unknown".
    pub estimated_micros: Option<i64>,
    /// False when at least some usage in this bucket could not be priced, so
    /// `estimated_micros` is a floor for the bucket rather than its total.
    pub cost_complete: bool,
}

impl ProjectSeriesPoint {
    /// Input + output, or `None` when usage was not reported.
    pub fn total_tokens(&self) -> Option<i64> {
        match (self.input_tokens, self.output_tokens) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
        }
    }
}

/// Which observations a project surface is looking at.
///
/// Every field is an equality filter on a non-secret, already-recorded column.
/// `None` means "no constraint"; there is no free-text predicate and no
/// filter over anything the database does not already hold.
#[derive(Debug, Clone, Default)]
pub struct ActivityFilter<'a> {
    pub host: Option<&'a str>,
    pub provider: Option<&'a str>,
    pub credential_id: Option<&'a str>,
    /// Matches `runtime_request_events.status_class` ("2xx", "4xx", …).
    pub status_class: Option<&'a str>,
    pub endpoint: Option<&'a str>,
    /// Matches `runtime_request_events.observation_source`.
    pub observation_source: Option<&'a str>,
    /// Filters on the model reported for the request, via its usage row.
    pub model: Option<&'a str>,
}

/// Parameter slots every project-scoped read binds *before* its filter values:
/// `?1` = project id, `?2` = window start, `?3` = exclusive window end
/// (nullable).
///
/// [`ActivityFilter::clauses`] numbers its own placeholders from `?4`, so a
/// caller binding a different prefix would silently reuse `until` as a filter
/// value instead of failing. That is why no query in this crate writes its own
/// project/window predicate: every one of them is built by
/// [`ActivityFilter::event_scope`] or [`ActivityFilter::usage_scope`].
pub(crate) const BASE_PARAMS: usize = 3;

impl ActivityFilter<'_> {
    /// Render the filter as SQL conditions over `runtime_request_events e`,
    /// with bound parameters. Parameters are bound, never interpolated.
    fn clauses(&self) -> (String, Vec<&dyn ToSql>) {
        let mut sql = String::new();
        let mut binds: Vec<&dyn ToSql> = Vec::new();
        // The bound value is the `Option` itself, which rusqlite renders as its
        // inner value — a clause is only ever emitted when it is `Some`, so a
        // NULL bind (which `=` would never match) cannot reach the statement.
        let candidates: [(&str, bool, &dyn ToSql); 7] = [
            ("e.host = ?", self.host.is_some(), &self.host),
            (
                "e.credential_id = ?",
                self.credential_id.is_some(),
                &self.credential_id,
            ),
            (
                "e.status_class = ?",
                self.status_class.is_some(),
                &self.status_class,
            ),
            (
                "e.path_template = ?",
                self.endpoint.is_some(),
                &self.endpoint,
            ),
            (
                "e.observation_source = ?",
                self.observation_source.is_some(),
                &self.observation_source,
            ),
            (
                // A user-assigned provider counts as this service's provider,
                // so filtering by provider finds the traffic the user has told
                // Tethra belongs to it.
                "EXISTS (SELECT 1 FROM observed_api_services s \
                 WHERE s.id = e.service_id \
                 AND COALESCE(NULLIF(s.provider_id, ''), s.user_provider) = ?)",
                self.provider.is_some(),
                &self.provider,
            ),
            (
                "EXISTS (SELECT 1 FROM gateway_usage_events u \
                 WHERE u.event_id = e.id AND u.model = ?)",
                self.model.is_some(),
                &self.model,
            ),
        ];
        for (cond, present, v) in candidates {
            if !present {
                continue;
            }
            binds.push(v);
            let placeholder = format!("?{}", BASE_PARAMS + binds.len());
            sql.push_str(&format!(" AND {}", cond.replace('?', &placeholder)));
        }
        (sql, binds)
    }

    /// Whether this filter constrains anything.
    ///
    /// Load-bearing for the usage-side queries: with no filter, usage rows are
    /// read directly so that usage whose event row has already been pruned by
    /// retention still counts. With a filter, they must be restricted to events
    /// that match it — see [`ActivityFilter::usage_scope`].
    pub fn is_empty(&self) -> bool {
        self.host.is_none()
            && self.provider.is_none()
            && self.credential_id.is_none()
            && self.status_class.is_none()
            && self.endpoint.is_none()
            && self.observation_source.is_none()
            && self.model.is_none()
    }

    /// The complete `WHERE` predicate for a project-scoped, windowed, filtered
    /// read rooted at `runtime_request_events e`, with its bound parameters.
    ///
    /// This is the ONE place the project and window predicates are written.
    /// Before it existed, `project_series` and `recent_activity` threaded the
    /// filter while `project_metrics`, `project_cost_coverage` and
    /// `observed_integrations` each wrote their own project/window predicate and
    /// took no filter at all — so a page showed a filtered chart beside
    /// unfiltered totals (`AUD-01`). A shared builder makes "this query forgot
    /// the filter" impossible to express: there is no other way to scope a read.
    ///
    /// Callers bind `(project_id, since, until)` as `?1..?3` — see
    /// [`BASE_PARAMS`] — and then `params.extend(binds)`.
    pub(crate) fn event_scope(&self) -> (String, Vec<&dyn ToSql>) {
        let (extra, binds) = self.clauses();
        (
            format!("e.project_id = ?1 AND e.at >= ?2 AND (?3 IS NULL OR e.at < ?3){extra}"),
            binds,
        )
    }

    /// [`ActivityFilter::event_scope`] for a read rooted at
    /// `gateway_usage_events u` — the token and cost side.
    ///
    /// A usage row carries a provider, a model and token counts, but none of the
    /// request metadata the filter selects on (host, status class, endpoint,
    /// observation source, credential). So the filter reaches usage through the
    /// event that produced it.
    ///
    /// With NO filter the usage rows are read directly, so usage whose event row
    /// has already been pruned by retention still counts. With a filter they are
    /// restricted to matching events, which necessarily drops usage that has no
    /// event left to match: an unattributable row cannot be said to satisfy a
    /// filter, and counting it would put the wrong tokens back into a total the
    /// user narrowed.
    pub(crate) fn usage_scope(&self) -> (String, Vec<&dyn ToSql>) {
        let (extra, binds) = self.clauses();
        let base = "u.project_id = ?1 AND u.at >= ?2 AND (?3 IS NULL OR u.at < ?3)";
        if self.is_empty() {
            return (base.to_string(), binds);
        }
        (
            format!(
                "{base} AND EXISTS (SELECT 1 FROM runtime_request_events e \
                 WHERE e.id = u.event_id AND e.project_id = ?1{extra})"
            ),
            binds,
        )
    }
}

/// A project's activity series over `[since, until)`.
///
/// Buckets with no observation are omitted rather than emitted as zero: for
/// requests an absent bucket does mean none arrived, but for tokens and cost it
/// would be a fabricated figure, and one array cannot carry both meanings.
pub fn project_series(
    conn: &Connection,
    project_id: &str,
    since: &str,
    until: Option<&str>,
    granularity: Granularity,
    filter: &ActivityFilter<'_>,
) -> Result<Vec<ProjectSeriesPoint>> {
    let bucket = granularity.bucket_expr("e.at");
    let (scope, binds) = filter.event_scope();
    let sql = format!(
        "SELECT {bucket} AS b, COUNT(*),
                SUM(CASE WHEN e.status_class IN ('4xx','5xx')
                          OR e.transport_error <> 'none' THEN 1 ELSE 0 END),
                SUM(e.latency_ms), COUNT(e.latency_ms)
         FROM runtime_request_events e
         WHERE {scope}
         GROUP BY b ORDER BY b LIMIT {}",
        MAX_BUCKETS
    );
    let mut params: Vec<&dyn ToSql> = vec![&project_id, &since, &until];
    params.extend(binds);

    let mut points: BTreeMap<String, ProjectSeriesPoint> = BTreeMap::new();
    {
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params.as_slice(), |r| {
            let latency_sum: Option<i64> = r.get(3)?;
            let latency_n: i64 = r.get(4)?;
            Ok(ProjectSeriesPoint {
                bucket_start: r.get(0)?,
                requests: r.get(1)?,
                errors: r.get(2)?,
                avg_latency_ms: match (latency_sum, latency_n) {
                    (Some(s), n) if n > 0 => Some(s / n),
                    _ => None,
                },
                input_tokens: None,
                output_tokens: None,
                estimated_micros: None,
                cost_complete: true,
            })
        })?;
        for p in rows {
            let p = p?;
            points.insert(p.bucket_start.clone(), p);
        }
    }

    // Tokens and cost come from the usage table, bucketed the same way. Usage
    // rows are joined to the event they describe so the filter applies to both.
    //
    // The filter MUST reach this query too. Restricting only the request query
    // and then merging unfiltered usage into whichever buckets survived reports
    // one host's request count beside every host's tokens and cost — a wrong
    // number, not merely an imprecise one.
    let ubucket = granularity.bucket_expr("u.at");
    let (usage_scope, usage_binds) = filter.usage_scope();
    let usql = format!(
        "SELECT {ubucket} AS b, u.provider_id, u.model, substr(u.at, 1, 10),
                SUM(u.input_tokens), SUM(u.output_tokens), SUM(u.cached_input_tokens)
         FROM gateway_usage_events u
         WHERE {usage_scope}
         GROUP BY b, u.provider_id, u.model
         ORDER BY b LIMIT {}",
        MAX_BUCKETS * 8
    );
    // Same (project_id, since, until) prefix as the request query, so
    // `clauses()`'s placeholder numbering applies unchanged.
    let mut usage_params: Vec<&dyn ToSql> = vec![&project_id, &since, &until];
    usage_params.extend(usage_binds);

    let mut candidate_cache: HashMap<String, Vec<PricingRecord>> = HashMap::new();
    let mut stmt = conn.prepare(&usql)?;
    let groups = stmt
        .query_map(usage_params.as_slice(), |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, Option<i64>>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    for (b, provider, model, day, input, output, cached) in groups {
        // A usage bucket with no matching event bucket means the filter
        // excluded it, or retention pruned the event. Either way it is not
        // this series' data.
        let Some(point) = points.get_mut(&b) else {
            continue;
        };
        if let Some(v) = input {
            point.input_tokens = Some(point.input_tokens.unwrap_or(0) + v);
        }
        if let Some(v) = output {
            point.output_tokens = Some(point.output_tokens.unwrap_or(0) + v);
        }

        let (Some(model), Some(input), Some(output)) = (model.as_deref(), input, output) else {
            // Nothing priceable here, and that is a coverage gap for the
            // bucket, not a zero.
            point.cost_complete = false;
            continue;
        };
        if !candidate_cache.contains_key(&provider) {
            let loaded = pricing::candidates_for(conn, &provider)?;
            candidate_cache.insert(provider.clone(), loaded);
        }
        let candidates = &candidate_cache[&provider];
        let Some(rec) = pricing::choose_as_of(candidates, model, &day) else {
            point.cost_complete = false;
            continue;
        };
        if rec.currency != ESTIMATE_CURRENCY {
            point.cost_complete = false;
            continue;
        }
        let billable_input = input - cached.unwrap_or(0).clamp(0, input);
        match pricing::estimate_token_cost_from(&rec, billable_input, output) {
            Some(est) => {
                point.estimated_micros = Some(
                    point
                        .estimated_micros
                        .unwrap_or(0)
                        .saturating_add(est.micros),
                );
                if !est.complete {
                    point.cost_complete = false;
                }
            }
            None => point.cost_complete = false,
        }
    }

    Ok(points.into_values().collect())
}

/// One row of the recent-activity table.
///
/// Universal metadata only. Every field here is already recorded for every
/// observation regardless of whether the provider is known, which is what lets
/// an unknown API show requests, status, endpoint and latency.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityRow {
    pub id: String,
    pub at: String,
    pub host: String,
    /// The catalog provider for this host, when there is one. `None` is an
    /// unknown API — a state, not a missing value to be filled with a guess.
    pub provider: Option<String>,
    pub method: String,
    /// The templated endpoint. Path parameters are already replaced upstream;
    /// no raw URL or query string is stored.
    pub endpoint: String,
    pub status_code: Option<i64>,
    pub status_class: String,
    pub outcome: String,
    pub latency_ms: Option<i64>,
    pub ttfb_ms: Option<i64>,
    pub request_bytes: Option<i64>,
    pub response_bytes: Option<i64>,
    pub observation_source: String,
    pub model: Option<String>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub credential_id: Option<String>,
    pub attribution_confidence: Option<String>,
    /// Locally estimated cost for this row, `None` when it could not be priced.
    pub estimated_micros: Option<i64>,
    pub cost_complete: bool,
}

/// The most recent observations for a project, newest first.
///
/// `before` is an exclusive upper bound on `at`, for paging further back
/// without re-reading what the caller already has.
pub fn recent_activity(
    conn: &Connection,
    project_id: &str,
    since: &str,
    before: Option<&str>,
    filter: &ActivityFilter<'_>,
    limit: usize,
) -> Result<Vec<ActivityRow>> {
    let limit = limit.clamp(1, MAX_RECENT_ROWS);
    let (scope, binds) = filter.event_scope();
    let sql = format!(
        "SELECT e.id, e.at, e.host,
                COALESCE(NULLIF(s.provider_id, ''), s.user_provider),
                e.method, e.path_template, e.status_code,
                e.status_class, e.outcome, e.latency_ms, e.request_bytes, e.response_bytes,
                e.observation_source, e.credential_id, e.attribution_confidence,
                u.model, u.input_tokens, u.output_tokens, u.cached_input_tokens, u.provider_id
         FROM runtime_request_events e
         LEFT JOIN observed_api_services s ON s.id = e.service_id
         LEFT JOIN gateway_usage_events u ON u.event_id = e.id
         WHERE {scope}
         ORDER BY e.at DESC, e.rowid DESC LIMIT {limit}"
    );
    let mut params: Vec<&dyn ToSql> = vec![&project_id, &since, &before];
    params.extend(binds);

    let mut stmt = conn.prepare(&sql)?;
    let raw = stmt
        .query_map(params.as_slice(), |r| {
            Ok((
                ActivityRow {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    host: r.get(2)?,
                    provider: r.get::<_, Option<String>>(3)?.filter(|p| !p.is_empty()),
                    method: r.get(4)?,
                    endpoint: r.get(5)?,
                    status_code: r.get(6)?,
                    status_class: r.get(7)?,
                    outcome: r.get(8)?,
                    latency_ms: r.get(9)?,
                    // Time to first byte is recorded per exchange by the
                    // gateway only; the intercept path does not separate it.
                    ttfb_ms: None,
                    request_bytes: r.get(10)?,
                    response_bytes: r.get(11)?,
                    observation_source: r.get(12)?,
                    credential_id: r.get(13)?,
                    attribution_confidence: r.get(14)?,
                    model: r.get(15)?,
                    input_tokens: r.get(16)?,
                    output_tokens: r.get(17)?,
                    estimated_micros: None,
                    cost_complete: true,
                },
                r.get::<_, Option<i64>>(18)?,
                r.get::<_, Option<String>>(19)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut candidate_cache: HashMap<String, Vec<PricingRecord>> = HashMap::new();
    let mut out = Vec::with_capacity(raw.len());
    for (mut row, cached, usage_provider) in raw {
        let provider = usage_provider.or_else(|| row.provider.clone());
        match (
            provider,
            row.model.clone(),
            row.input_tokens,
            row.output_tokens,
        ) {
            (Some(provider), Some(model), Some(input), Some(output)) => {
                if !candidate_cache.contains_key(&provider) {
                    let loaded = pricing::candidates_for(conn, &provider)?;
                    candidate_cache.insert(provider.clone(), loaded);
                }
                let day = &row.at[..row.at.len().min(10)];
                match pricing::choose_as_of(&candidate_cache[&provider], &model, day) {
                    Some(rec) if rec.currency == ESTIMATE_CURRENCY => {
                        let billable = input - cached.unwrap_or(0).clamp(0, input);
                        match pricing::estimate_token_cost_from(&rec, billable, output) {
                            Some(est) => {
                                row.estimated_micros = Some(est.micros);
                                row.cost_complete = est.complete;
                            }
                            None => row.cost_complete = false,
                        }
                    }
                    _ => row.cost_complete = false,
                }
            }
            // No model or no tokens: there is no estimate for this row, and
            // that is reported as unavailable rather than as zero.
            _ => row.cost_complete = false,
        }
        out.push(row);
    }
    Ok(out)
}

/// One API a project has actually been observed talking to.
#[derive(Debug, Clone, Serialize)]
pub struct ObservedIntegration {
    pub host: String,
    /// The catalog provider for this host. `None` is an unknown API — a state,
    /// not a missing value to be filled with a guess.
    pub provider: Option<String>,
    /// A provider the USER assigned to this host, via
    /// `runtime::store::set_service_correction`. Kept separate from `provider`
    /// so a screen never presents the user's own answer as Tethra's detection.
    pub user_provider: Option<String>,
    /// A display name the user gave this host.
    pub user_api_name: Option<String>,
    pub requests: i64,
    pub errors: i64,
    pub avg_latency_ms: Option<i64>,
    pub first_at: String,
    pub last_at: String,
    /// True when the host looks like a private/internal address rather than a
    /// third-party API, so a surface can say so instead of calling it unknown.
    pub internal: bool,
}

impl ObservedIntegration {
    /// The provider to price and attribute against: the catalog's, or the one
    /// the user assigned when the catalog has none.
    pub fn effective_provider(&self) -> Option<&str> {
        self.provider.as_deref().or(self.user_provider.as_deref())
    }

    /// Whether cost can be estimated for this integration at all.
    ///
    /// A host with no provider has no pricing records, and a provider the user
    /// invented has none either — only a provider the catalog knows can select
    /// a record. Saying "unavailable" is the honest alternative to `$0.00`.
    pub fn cost_estimable(&self) -> bool {
        self.effective_provider()
            .and_then(crate::providers::find)
            .is_some()
    }

    /// What to call this integration on screen, and never a bare host when the
    /// user has given it a name.
    pub fn display_name(&self) -> String {
        if let Some(name) = self.user_api_name.as_deref() {
            return name.to_string();
        }
        match self.effective_provider() {
            Some(p) => p.to_string(),
            None => self.host.clone(),
        }
    }
}

/// Every host a project was observed talking to in the window, known or not.
///
/// An unknown provider is present with its universal metadata — requests,
/// errors, latency, first/last seen — because those are recorded for every
/// observation. It carries no cost and no credential attribution, and this
/// function does not invent either.
///
/// `filter` narrows this the same way it narrows the chart beside it. This is a
/// SUMMARY OF THE RESULT SET, not a picker: with a host filter active it lists
/// that host alone. The values a filter UI offers come from [`activity_facets`],
/// which is deliberately broader — see its own documentation.
pub fn observed_integrations(
    conn: &Connection,
    project_id: &str,
    since: &str,
    until: Option<&str>,
    filter: &ActivityFilter<'_>,
) -> Result<Vec<ObservedIntegration>> {
    let (scope, binds) = filter.event_scope();
    let sql = format!(
        "SELECT e.host, s.provider_id, s.user_provider, s.user_api_name, COUNT(*),
                SUM(CASE WHEN e.status_class IN ('4xx','5xx')
                          OR e.transport_error <> 'none' THEN 1 ELSE 0 END),
                SUM(e.latency_ms), COUNT(e.latency_ms), MIN(e.at), MAX(e.at)
         FROM runtime_request_events e
         LEFT JOIN observed_api_services s ON s.id = e.service_id
         WHERE {scope}
         GROUP BY e.host, s.provider_id, s.user_provider, s.user_api_name
         ORDER BY COUNT(*) DESC, e.host
         LIMIT 200"
    );
    let mut params: Vec<&dyn ToSql> = vec![&project_id, &since, &until];
    params.extend(binds);

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params.as_slice(), |r| {
        let host: String = r.get(0)?;
        let latency_sum: Option<i64> = r.get(6)?;
        let latency_n: i64 = r.get(7)?;
        Ok(ObservedIntegration {
            provider: r.get::<_, Option<String>>(1)?.filter(|p| !p.is_empty()),
            user_provider: r.get::<_, Option<String>>(2)?.filter(|p| !p.is_empty()),
            user_api_name: r.get::<_, Option<String>>(3)?.filter(|p| !p.is_empty()),
            requests: r.get(4)?,
            errors: r.get(5)?,
            avg_latency_ms: match (latency_sum, latency_n) {
                (Some(s), n) if n > 0 => Some(s / n),
                _ => None,
            },
            first_at: r.get(8)?,
            last_at: r.get(9)?,
            internal: inventory::looks_internal(&host),
            host,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The distinct values a project's activity can be filtered by, so a filter UI
/// offers only what actually exists rather than a guessed list.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ActivityFacets {
    pub hosts: Vec<String>,
    pub providers: Vec<String>,
    pub models: Vec<String>,
    pub status_classes: Vec<String>,
    pub endpoints: Vec<String>,
    pub observation_sources: Vec<String>,
}

/// Collect the filterable values present in the window. Each list is bounded.
///
/// # Why this one is NOT filtered
///
/// Every other project-activity read takes an [`ActivityFilter`] and describes
/// the filtered population, because a summary shown beside a filtered chart must
/// describe the same rows the chart does (`AUD-01`). Facets are the deliberate
/// exception: they populate the filter controls themselves.
///
/// Narrowing them by the current selection would make the controls one-way. Pick
/// host `api.openai.com` and a self-filtered host list contains only
/// `api.openai.com`, so there is no control left to pick a different host with
/// and no way back except "Clear filters". The same applies across dimensions:
/// choosing a host would empty the model list of every model that host did not
/// serve, and choosing that model would then be the only model offered.
///
/// So facets answer "what exists in this time window?", which is the question a
/// picker needs, while [`observed_integrations`] answers "what is in the result
/// you are looking at?", which is the question a summary needs. The two are
/// different questions and are deliberately allowed to disagree; the time window
/// is the one bound they share.
pub fn activity_facets(conn: &Connection, project_id: &str, since: &str) -> Result<ActivityFacets> {
    Ok(ActivityFacets {
        hosts: distinct(
            conn,
            "SELECT DISTINCT host FROM runtime_request_events
             WHERE project_id = ?1 AND at >= ?2 ORDER BY host LIMIT 100",
            project_id,
            since,
        )?,
        providers: distinct(
            conn,
            "SELECT DISTINCT COALESCE(NULLIF(s.provider_id, ''), s.user_provider) AS p
             FROM runtime_request_events e
             JOIN observed_api_services s ON s.id = e.service_id
             WHERE e.project_id = ?1 AND e.at >= ?2 AND p IS NOT NULL AND p <> ''
             ORDER BY p LIMIT 100",
            project_id,
            since,
        )?,
        models: distinct(
            conn,
            "SELECT DISTINCT model FROM gateway_usage_events
             WHERE project_id = ?1 AND at >= ?2 AND model IS NOT NULL
             ORDER BY model LIMIT 100",
            project_id,
            since,
        )?,
        status_classes: distinct(
            conn,
            "SELECT DISTINCT status_class FROM runtime_request_events
             WHERE project_id = ?1 AND at >= ?2 ORDER BY status_class LIMIT 10",
            project_id,
            since,
        )?,
        endpoints: distinct(
            conn,
            "SELECT DISTINCT path_template FROM runtime_request_events
             WHERE project_id = ?1 AND at >= ?2 ORDER BY path_template LIMIT 100",
            project_id,
            since,
        )?,
        observation_sources: distinct(
            conn,
            "SELECT DISTINCT observation_source FROM runtime_request_events
             WHERE project_id = ?1 AND at >= ?2 ORDER BY observation_source LIMIT 10",
            project_id,
            since,
        )?,
    })
}

fn distinct(conn: &Connection, sql: &str, project_id: &str, since: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![project_id, since], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::runtime::model::*;
    use crate::runtime::store::{self, testutil};

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        conn.pragma_update(None, "foreign_keys", 1).unwrap();
        testutil::seed_project(&conn, "p1", "web");
        conn
    }

    fn session(conn: &Connection) -> String {
        store::insert_session(
            conn,
            &store::NewSession {
                project_id: "p1",
                mode: ObservationMode::Metadata,
                source: "cli_run",
                command: "x",
                credential_names: &[],
            },
        )
        .unwrap()
    }

    fn req(host: &str, status: u16, latency: i64, path: &str) -> ObservedRequest {
        ObservedRequest {
            host: host.into(),
            port: 443,
            method: HttpMethod::Post,
            path_template: path.into(),
            template_confidence: crate::providers::Confidence::High,
            status_code: Some(status),
            req_content_kind: None,
            resp_content_kind: None,
            had_authorization: true,
            latency_ms: Some(latency),
            request_bytes: Some(100),
            response_bytes: Some(500),
            protocol: Protocol::Http11,
            observation_source: ObservationSource::Gateway,
            transport_error: TransportError::None,
        }
    }

    /// Record one observation, returning its event id.
    fn event(
        conn: &Connection,
        sid: &str,
        at: &str,
        host: &str,
        provider: Option<&str>,
        status: u16,
        latency: i64,
    ) -> String {
        let (svc, _) = store::upsert_service(conn, host, provider, false, at).unwrap();
        store::insert_request_event(
            conn,
            sid,
            "p1",
            &svc,
            None,
            at,
            &req(host, status, latency, "/v1/chat"),
            false,
        )
        .unwrap()
    }

    fn usage_for(
        conn: &Connection,
        event_id: &str,
        at: &str,
        provider: &str,
        model: Option<&str>,
        input: Option<i64>,
        output: Option<i64>,
    ) {
        let available = i64::from(input.is_some() || output.is_some());
        conn.execute(
            "INSERT INTO gateway_usage_events
                (id, event_id, at, route_prefix, provider_id, project_id, model,
                 input_tokens, output_tokens, usage_available, usage_state)
             VALUES (?1, ?2, ?3, ?4, ?4, 'p1', ?5, ?6, ?7, ?8, 'extracted')",
            params![
                uuid::Uuid::new_v4().to_string(),
                event_id,
                at,
                provider,
                model,
                input,
                output,
                available
            ],
        )
        .unwrap();
    }

    fn series(conn: &Connection, g: Granularity) -> Vec<ProjectSeriesPoint> {
        project_series(
            conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            g,
            &ActivityFilter::default(),
        )
        .unwrap()
    }

    #[test]
    fn an_empty_project_has_an_empty_series_not_a_zero_point() {
        let conn = mem();
        assert!(series(&conn, Granularity::Hour).is_empty());
    }

    #[test]
    fn a_single_observation_yields_a_single_point() {
        let conn = mem();
        let sid = session(&conn);
        event(
            &conn,
            &sid,
            "2026-07-24T10:15:00Z",
            "api.openai.com",
            Some("openai"),
            200,
            40,
        );
        let s = series(&conn, Granularity::Hour);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].bucket_start, "2026-07-24T10:00:00Z");
        assert_eq!(s[0].requests, 1);
        assert_eq!(s[0].errors, 0);
        assert_eq!(s[0].avg_latency_ms, Some(40));
        // No usage row: tokens are unknown, not zero.
        assert_eq!(s[0].input_tokens, None);
        assert_eq!(s[0].estimated_micros, None);
    }

    #[test]
    fn observations_group_into_their_buckets_at_each_granularity() {
        let conn = mem();
        let sid = session(&conn);
        for at in [
            "2026-07-24T10:15:00Z",
            "2026-07-24T10:15:30Z",
            "2026-07-24T10:40:00Z",
            "2026-07-25T09:00:00Z",
        ] {
            event(&conn, &sid, at, "api.openai.com", Some("openai"), 200, 10);
        }
        assert_eq!(series(&conn, Granularity::Day).len(), 2);
        // 10:15, 10:15:30 and 10:40 are all hour 10 on the 24th; 09:00 on the
        // 25th is the second hour bucket.
        assert_eq!(series(&conn, Granularity::Hour).len(), 2);
        // Two events share the 10:15 minute; 10:40 and the next day are their own.
        let minutes = series(&conn, Granularity::Minute);
        assert_eq!(minutes.len(), 3);
        assert_eq!(minutes[0].bucket_start, "2026-07-24T10:15:00Z");
        assert_eq!(minutes[0].requests, 2);
    }

    /// The whole point of reading raw events: traffic in the CURRENT hour must
    /// appear. `aggregate::roll_up` never rolls up an incomplete hour, so a
    /// rollup-sourced series would be empty here.
    #[test]
    fn traffic_in_an_unrolled_hour_is_visible() {
        let conn = mem();
        let sid = session(&conn);
        let now = crate::clock::now_rfc3339();
        event(&conn, &sid, &now, "api.openai.com", Some("openai"), 200, 25);

        // Confirm the rollup really has nothing for it, so this test cannot
        // pass by accident once buckets exist.
        crate::runtime::aggregate::roll_up(&conn, &now).unwrap();
        let rolled: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM runtime_metric_buckets WHERE bucket_start = ?1",
                params![format!("{}:00:00Z", &now[..13])],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rolled, 0, "the current hour is deliberately not rolled up");

        let s = series(&conn, Granularity::Hour);
        assert_eq!(s.len(), 1, "the live hour must still be in the series");
        assert_eq!(s[0].requests, 1);
    }

    #[test]
    fn errors_count_status_classes_and_transport_failures() {
        let conn = mem();
        let sid = session(&conn);
        let at = "2026-07-24T10:00:00Z";
        event(&conn, &sid, at, "api.openai.com", Some("openai"), 200, 10);
        event(&conn, &sid, at, "api.openai.com", Some("openai"), 404, 10);
        event(&conn, &sid, at, "api.openai.com", Some("openai"), 503, 10);
        let s = series(&conn, Granularity::Hour);
        assert_eq!(s[0].requests, 3);
        assert_eq!(s[0].errors, 2);
    }

    #[test]
    fn tokens_and_cost_ride_the_same_buckets_as_requests() {
        let conn = mem();
        let sid = session(&conn);
        let at = "2026-07-24T10:15:00Z";
        let e = event(&conn, &sid, at, "api.openai.com", Some("openai"), 200, 30);
        usage_for(
            &conn,
            &e,
            at,
            "openai",
            Some("gpt-4o"),
            Some(1_000_000),
            Some(0),
        );
        let s = series(&conn, Granularity::Hour);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].input_tokens, Some(1_000_000));
        assert_eq!(s[0].output_tokens, Some(0));
        assert_eq!(s[0].total_tokens(), Some(1_000_000));
        assert_eq!(s[0].estimated_micros, Some(2_500_000));
        assert!(s[0].cost_complete);
    }

    /// An unpriced model leaves the bucket's cost incomplete rather than
    /// contributing a zero.
    #[test]
    fn an_unpriced_model_makes_the_bucket_cost_incomplete() {
        let conn = mem();
        let sid = session(&conn);
        let at = "2026-07-24T10:15:00Z";
        let e = event(&conn, &sid, at, "api.openai.com", Some("openai"), 200, 30);
        usage_for(
            &conn,
            &e,
            at,
            "openai",
            Some("gpt-unpriced"),
            Some(500),
            Some(500),
        );
        let s = series(&conn, Granularity::Hour);
        assert_eq!(s[0].input_tokens, Some(500), "tokens are still known");
        assert_eq!(s[0].estimated_micros, None, "no estimate, not zero");
        assert!(!s[0].cost_complete);
    }

    /// Usage with no model reported: tokens known, cost unknown.
    #[test]
    fn usage_without_a_model_leaves_cost_unknown() {
        let conn = mem();
        let sid = session(&conn);
        let at = "2026-07-24T10:15:00Z";
        let e = event(&conn, &sid, at, "api.openai.com", Some("openai"), 200, 30);
        usage_for(&conn, &e, at, "openai", None, Some(500), Some(500));
        let s = series(&conn, Granularity::Hour);
        assert_eq!(s[0].total_tokens(), Some(1_000));
        assert_eq!(s[0].estimated_micros, None);
        assert!(!s[0].cost_complete);
    }

    /// An unknown host is a first-class integration with real universal
    /// metadata and no invented cost.
    #[test]
    fn an_unknown_host_keeps_its_universal_metadata() {
        let conn = mem();
        let sid = session(&conn);
        let at = "2026-07-24T10:00:00Z";
        for _ in 0..12 {
            event(&conn, &sid, at, "api.example.com", None, 200, 420);
        }
        let found = observed_integrations(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            &ActivityFilter::default(),
        )
        .unwrap();
        assert_eq!(found.len(), 1);
        let it = &found[0];
        assert_eq!(it.host, "api.example.com");
        assert_eq!(it.provider, None, "unknown is a state, not a guess");
        assert_eq!(it.requests, 12);
        assert_eq!(it.avg_latency_ms, Some(420));
        assert!(!it.cost_estimable(), "no provider means no pricing");
        assert_eq!(it.user_api_name, None);
        assert_eq!(it.display_name(), "api.example.com");
    }

    /// Naming an unknown host changes its display and nothing else. The name
    /// goes through the service-correction mechanism that shipped in v12, and is
    /// reported separately from Tethra's own detection.
    #[test]
    fn a_user_assigned_name_reaches_the_unknown_integration() {
        let conn = mem();
        let sid = session(&conn);
        event(
            &conn,
            &sid,
            "2026-07-24T10:00:00Z",
            "api.example.com",
            None,
            200,
            100,
        );
        let svc = store::get_service_by_host(&conn, "api.example.com")
            .unwrap()
            .unwrap();
        store::set_service_correction(&conn, &svc.id, None, Some("Acme"), None, None).unwrap();
        let found = observed_integrations(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            &ActivityFilter::default(),
        )
        .unwrap();
        assert_eq!(found[0].user_api_name.as_deref(), Some("Acme"));
        assert_eq!(found[0].provider, None, "a name is not a detected provider");
        assert_eq!(found[0].display_name(), "Acme");
        assert!(
            !found[0].cost_estimable(),
            "a name the user invented selects no pricing record"
        );
        // Naming created no route and approved no destination.
        let routes: i64 = conn
            .query_row("SELECT COUNT(*) FROM gateway_routes", [], |r| r.get(0))
            .unwrap();
        let approvals: i64 = conn
            .query_row("SELECT COUNT(*) FROM tracking_approved_origins", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!((routes, approvals), (0, 0));
    }

    #[test]
    fn recent_activity_returns_universal_metadata_newest_first() {
        let conn = mem();
        let sid = session(&conn);
        event(
            &conn,
            &sid,
            "2026-07-24T10:00:00Z",
            "api.openai.com",
            Some("openai"),
            200,
            10,
        );
        let e = event(
            &conn,
            &sid,
            "2026-07-24T11:00:00Z",
            "api.example.com",
            None,
            500,
            900,
        );
        usage_for(
            &conn,
            &e,
            "2026-07-24T11:00:00Z",
            "unknownprov",
            Some("mystery"),
            Some(10),
            Some(20),
        );
        let rows = recent_activity(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            &ActivityFilter::default(),
            50,
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].at, "2026-07-24T11:00:00Z");
        assert_eq!(rows[0].host, "api.example.com");
        assert_eq!(rows[0].provider, None);
        assert_eq!(rows[0].status_code, Some(500));
        assert_eq!(rows[0].latency_ms, Some(900));
        assert_eq!(rows[0].endpoint, "/v1/chat");
        assert_eq!(
            rows[0].estimated_micros, None,
            "unknown provider is unpriced"
        );
        assert!(!rows[0].cost_complete);
        assert_eq!(rows[1].provider.as_deref(), Some("openai"));
    }

    #[test]
    fn recent_activity_prices_a_known_row() {
        let conn = mem();
        let sid = session(&conn);
        let at = "2026-07-24T10:00:00Z";
        let e = event(&conn, &sid, at, "api.openai.com", Some("openai"), 200, 10);
        usage_for(
            &conn,
            &e,
            at,
            "openai",
            Some("gpt-4o"),
            Some(1_000_000),
            Some(0),
        );
        let rows = recent_activity(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            &ActivityFilter::default(),
            50,
        )
        .unwrap();
        assert_eq!(rows[0].estimated_micros, Some(2_500_000));
        assert!(rows[0].cost_complete);
        assert_eq!(rows[0].model.as_deref(), Some("gpt-4o"));
    }

    /// Each filter narrows, binds its value, and does not collide with the
    /// window parameters.
    #[test]
    fn filters_narrow_without_parameter_collision() {
        let conn = mem();
        let sid = session(&conn);
        let at = "2026-07-24T10:00:00Z";
        event(&conn, &sid, at, "api.openai.com", Some("openai"), 200, 10);
        event(&conn, &sid, at, "api.example.com", None, 404, 20);

        let by_host = project_series(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            Granularity::Hour,
            &ActivityFilter {
                host: Some("api.openai.com"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(by_host[0].requests, 1);

        let by_status = project_series(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            Granularity::Hour,
            &ActivityFilter {
                status_class: Some("4xx"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(by_status[0].requests, 1);
        assert_eq!(by_status[0].errors, 1);

        let by_provider = project_series(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            Granularity::Hour,
            &ActivityFilter {
                provider: Some("openai"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(by_provider[0].requests, 1);

        // Two filters at once, to prove the placeholder numbering advances.
        let both = project_series(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            Granularity::Hour,
            &ActivityFilter {
                host: Some("api.openai.com"),
                status_class: Some("2xx"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(both[0].requests, 1);

        // A filter that matches nothing returns nothing, not everything.
        let none = project_series(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            Granularity::Hour,
            &ActivityFilter {
                host: Some("nope.example"),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(none.is_empty());
    }

    /// A filter must reach the TOKEN and COST figures too. Restricting only the
    /// request query and merging unfiltered usage into the surviving buckets
    /// reports one host's request count beside every host's tokens — a wrong
    /// number, not an imprecise one.
    #[test]
    fn a_filter_applies_to_tokens_and_cost_not_only_to_requests() {
        let conn = mem();
        let sid = session(&conn);
        let at = "2026-07-24T10:00:00Z";

        let a = event(&conn, &sid, at, "api.openai.com", Some("openai"), 200, 10);
        usage_for(
            &conn,
            &a,
            at,
            "openai",
            Some("gpt-4o"),
            Some(1_000_000),
            Some(0),
        );
        let b = event(
            &conn,
            &sid,
            at,
            "api.anthropic.com",
            Some("anthropic"),
            200,
            10,
        );
        usage_for(
            &conn,
            &b,
            at,
            "anthropic",
            Some("claude-sonnet-4-5"),
            Some(4_000_000),
            Some(0),
        );

        // Unfiltered: both requests and both token counts.
        let all = series(&conn, Granularity::Hour);
        assert_eq!(all[0].requests, 2);
        assert_eq!(all[0].input_tokens, Some(5_000_000));

        // Filtered to one host: one request AND only that host's tokens/cost.
        let one = project_series(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            Granularity::Hour,
            &ActivityFilter {
                host: Some("api.openai.com"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(one[0].requests, 1);
        assert_eq!(
            one[0].input_tokens,
            Some(1_000_000),
            "the other host's tokens leaked into a filtered bucket"
        );
        assert_eq!(
            one[0].estimated_micros,
            Some(2_500_000),
            "cost must follow the same filter as the tokens it is derived from"
        );
    }

    #[test]
    fn the_window_excludes_traffic_outside_it() {
        let conn = mem();
        let sid = session(&conn);
        event(
            &conn,
            &sid,
            "2026-07-01T10:00:00Z",
            "api.openai.com",
            Some("openai"),
            200,
            10,
        );
        event(
            &conn,
            &sid,
            "2026-07-20T10:00:00Z",
            "api.openai.com",
            Some("openai"),
            200,
            10,
        );
        let s = project_series(
            &conn,
            "p1",
            "2026-07-15T00:00:00Z",
            Some("2026-07-25T00:00:00Z"),
            Granularity::Day,
            &ActivityFilter::default(),
        )
        .unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].bucket_start, "2026-07-20T00:00:00Z");
    }

    #[test]
    fn another_projects_traffic_is_excluded() {
        let conn = mem();
        testutil::seed_project(&conn, "p2", "other");
        let sid2 = store::insert_session(
            &conn,
            &store::NewSession {
                project_id: "p2",
                mode: ObservationMode::Metadata,
                source: "cli_run",
                command: "x",
                credential_names: &[],
            },
        )
        .unwrap();
        let (svc, _) = store::upsert_service(
            &conn,
            "api.openai.com",
            Some("openai"),
            false,
            "2026-07-24T10:00:00Z",
        )
        .unwrap();
        store::insert_request_event(
            &conn,
            &sid2,
            "p2",
            &svc,
            None,
            "2026-07-24T10:00:00Z",
            &req("api.openai.com", 200, 10, "/v1/chat"),
            false,
        )
        .unwrap();
        assert!(series(&conn, Granularity::Hour).is_empty());
    }

    #[test]
    fn facets_offer_only_values_that_exist() {
        let conn = mem();
        let sid = session(&conn);
        let at = "2026-07-24T10:00:00Z";
        let e = event(&conn, &sid, at, "api.openai.com", Some("openai"), 200, 10);
        usage_for(&conn, &e, at, "openai", Some("gpt-4o"), Some(1), Some(1));
        event(&conn, &sid, at, "api.example.com", None, 404, 10);
        let f = activity_facets(&conn, "p1", "2000-01-01T00:00:00Z").unwrap();
        assert_eq!(f.hosts, vec!["api.example.com", "api.openai.com"]);
        assert_eq!(f.providers, vec!["openai"], "unknown hosts add no provider");
        assert_eq!(f.models, vec!["gpt-4o"]);
        assert!(f.status_classes.contains(&"2xx".to_string()));
        assert!(f.status_classes.contains(&"4xx".to_string()));
        assert_eq!(f.endpoints, vec!["/v1/chat"]);
        assert_eq!(f.observation_sources, vec!["gateway"]);
    }

    /// A bounded dataset stays bounded: many buckets are capped, and the row
    /// limit is clamped rather than trusted.
    #[test]
    fn large_datasets_stay_bounded() {
        let conn = mem();
        let sid = session(&conn);
        for m in 0..70 {
            let at = format!("2026-07-24T10:{m:02}:00Z");
            if m < 60 {
                event(&conn, &sid, &at, "api.openai.com", Some("openai"), 200, 10);
            }
        }
        let minutes = series(&conn, Granularity::Minute);
        assert_eq!(minutes.len(), 60);
        assert!(minutes.len() <= MAX_BUCKETS);

        let rows = recent_activity(
            &conn,
            "p1",
            "2000-01-01T00:00:00Z",
            None,
            &ActivityFilter::default(),
            usize::MAX,
        )
        .unwrap();
        assert!(rows.len() <= MAX_RECENT_ROWS);
    }
}
