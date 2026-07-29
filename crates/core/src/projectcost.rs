//! Locally estimated cost for one project's observed usage, with honest
//! coverage (ADR 0029).
//!
//! The rule this module exists to enforce: **an amount is only ever reported
//! next to what it does not cover.** Three distinct things get conflated by a
//! naive `SUM(estimated_cost_micros)` and each is kept separate here:
//!
//! * usage that was priced — a real estimate;
//! * usage whose model is known but has no pricing record — visible, counted,
//!   and explicitly *not* zero;
//! * requests whose token usage was never extracted — a count, with tokens
//!   reported as unknown rather than as `0`.
//!
//! Why this does not read `gateway_usage_daily`: that rollup's
//! `estimated_cost_micros` is `INTEGER NOT NULL DEFAULT 0` and the writer
//! stores `cost.unwrap_or(0)` into it (`crates/gateway/src/writer.rs`), so an
//! unpriced request and a genuinely free one are the same integer in that
//! table — the distinction this module is built to preserve is already lost
//! there. `gateway_usage_events.estimated_cost_micros` is nullable, and
//! `usage_available` / `usage_state` record *why* a number is absent, so the
//! event table can still tell the three cases apart.
//!
//! Why it re-derives instead of summing the stored per-event estimate: the
//! stored value was computed at ingest and kept only `micros`, discarding
//! whether the estimate was complete. Re-deriving at read time also means a
//! pricing record added or corrected since the traffic arrived applies to it,
//! which is the documented point of effective-dated pricing.
//!
//! Provider-reported cost is deliberately absent from every total here. It
//! lives in `usage_snapshots` and is surfaced beside — never inside — the
//! local estimate (SI-19: locally observed data is never summed with
//! provider-reported data).

use std::collections::HashMap;

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::Result;
use crate::pricing::{self, PricingRecord};

/// The currency every local estimate is summed in. Records in any other
/// currency are reported as unpriced rather than converted or mixed, matching
/// how `usage.rs` excludes non-USD reported rows from its sums instead of
/// letting their absence read as a measured zero.
pub const ESTIMATE_CURRENCY: &str = "USD";

/// Most (provider, model, day) groups one call will price. A project with ~30
/// integrations over a 30-day window sits far below this; the cap exists so a
/// pathological history cannot make a refresh unbounded.
pub const MAX_GROUPS: usize = 2_000;

/// Why a slice of usage carries no estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnpricedReason {
    /// Tokens are known, the model is known, and no pricing record covers it.
    NoPricingRecord,
    /// The response did not name a model, so no record can be selected.
    ModelNotDetected,
    /// Usage extraction did not produce token counts for these requests, so
    /// their tokens are unknown — not zero.
    UsageNotExtracted,
    /// A record exists but prices something other than tokens.
    NonTokenUnit,
    /// A record exists in a currency this total is not denominated in.
    UnsupportedCurrency,
}

impl UnpricedReason {
    /// A sentence for a user, never a bare enum token on a screen.
    pub fn sentence(self) -> &'static str {
        match self {
            Self::NoPricingRecord => "no local pricing record covers this model",
            Self::ModelNotDetected => "the response did not report a model",
            Self::UsageNotExtracted => "token usage was not reported for these requests",
            Self::NonTokenUnit => "this model's pricing record is not token-based",
            Self::UnsupportedCurrency => "this model's pricing record is in another currency",
        }
    }
}

/// Usage that was priced, with the record that priced it.
#[derive(Debug, Clone, Serialize)]
pub struct PricedUsage {
    pub provider: String,
    /// The model id as the provider reported it.
    pub model: String,
    /// The record's model string that actually matched — a dated id resolves to
    /// its base entry, so this is what says which price was applied.
    pub matched_model: String,
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub micros: i64,
    pub currency: String,
    pub pricing_source: String,
    pub effective_from: String,
    pub last_verified: String,
    pub stale: bool,
    pub is_override: bool,
    pub note: String,
    /// False when the record priced only some of the dimensions that had
    /// usage; `micros` is then a floor for this group.
    pub complete: bool,
    pub unpriced_dimensions: Vec<String>,
}

/// Usage that carries no estimate, and why.
#[derive(Debug, Clone, Serialize)]
pub struct UnpricedUsage {
    pub provider: String,
    /// `None` when the provider never reported one.
    pub model: Option<String>,
    pub requests: i64,
    /// `None` means "not reported", which is not the same as `Some(0)`.
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub reason: UnpricedReason,
}

/// One project's locally estimated cost over a window, with what it misses.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectCostCoverage {
    /// Sum over priced groups. A LOWER BOUND whenever `complete` is false.
    pub estimated_micros: i64,
    pub currency: String,
    pub priced_requests: i64,
    /// Input tokens the estimate was computed over — BILLABLE input, i.e. after
    /// cache reads are excluded. Correct for cost, and deliberately not the
    /// figure to display as "input tokens": see `known_input_tokens`.
    pub priced_input_tokens: i64,
    pub priced_output_tokens: i64,
    /// Every input token any request REPORTED in this window, priced or not,
    /// including cache reads.
    ///
    /// Separate from `priced_input_tokens` because a token surface and a cost
    /// surface want different numbers: showing the priced figure as "input
    /// tokens" understates a project whose model has no local price, and also
    /// silently omits cache reads.
    pub known_input_tokens: i64,
    pub known_output_tokens: i64,
    /// Requests with known tokens that no record could price.
    pub unpriced_requests: i64,
    /// Tokens that are known but unpriced. Excludes anything unknown.
    pub unpriced_tokens: i64,
    /// Requests whose token usage was never reported. Their tokens are
    /// unknown, so they are counted here and appear in no token total.
    pub requests_with_unknown_usage: i64,
    /// Priced tokens as a fraction of *known* tokens. `None` when no tokens
    /// are known at all — there is no ratio to state, and `0.0` would read as
    /// "nothing was priced" rather than "there was nothing to price".
    pub token_coverage: Option<f64>,
    /// True only when everything observed in the window was priced and every
    /// priced group was itself complete.
    pub complete: bool,
    /// Any priced group used a record past its verification horizon.
    pub any_stale_pricing: bool,
    /// Groups were dropped at [`MAX_GROUPS`]; totals are partial by truncation
    /// as well as by coverage.
    pub truncated: bool,
    pub priced: Vec<PricedUsage>,
    pub unpriced: Vec<UnpricedUsage>,
}

impl ProjectCostCoverage {
    /// The amount, but only when it can stand as a complete total. Callers
    /// that must not present a floor as a total read this and render
    /// "unavailable" for `None` — never `$0.00`.
    pub fn micros_if_complete(&self) -> Option<i64> {
        self.complete.then_some(self.estimated_micros)
    }

    /// Whether anything at all was observed in the window.
    pub fn is_empty(&self) -> bool {
        self.priced_requests == 0
            && self.unpriced_requests == 0
            && self.requests_with_unknown_usage == 0
    }

    /// A short sentence naming what is missing, or `None` when nothing is.
    pub fn coverage_note(&self) -> Option<String> {
        if self.complete {
            return None;
        }
        let mut parts = Vec::new();
        let variants = self.unpriced_model_variants();
        if variants > 0 {
            parts.push(format!(
                "cost unavailable for {variants} model variant{}",
                if variants == 1 { "" } else { "s" }
            ));
        }
        if self.requests_with_unknown_usage > 0 {
            parts.push(format!(
                "{} request(s) reported no token usage",
                self.requests_with_unknown_usage
            ));
        }
        let partial = self.priced.iter().filter(|p| !p.complete).count();
        if partial > 0 {
            parts.push(format!(
                "{partial} priced group(s) are a floor, not a total"
            ));
        }
        if parts.is_empty() {
            // `complete` is false for some reason the branches above do not
            // name (truncation). Say that rather than nothing.
            parts.push("the window was truncated".to_string());
        }
        Some(parts.join("; "))
    }

    /// Distinct (provider, model) pairs that could not be priced. Requests
    /// with no reported model are one variant, not one per request.
    pub fn unpriced_model_variants(&self) -> usize {
        let mut seen = std::collections::BTreeSet::new();
        for u in &self.unpriced {
            seen.insert((u.provider.as_str(), u.model.as_deref()));
        }
        seen.len()
    }
}

/// One `GROUP BY (provider, model, day)` row out of `gateway_usage_events`.
struct UsageGroup {
    provider: String,
    model: Option<String>,
    day: String,
    requests: i64,
    /// `None` when no request in the group reported usage.
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cached_input_tokens: Option<i64>,
}

/// Estimate cost for `project_id` over `[since, until)`.
///
/// `since` / `until` are RFC 3339 timestamps compared as strings against
/// `gateway_usage_events.at`, which is what `idx_gue_project_at` (schema v20)
/// indexes. Pass `until = None` for "up to now".
pub fn project_cost_coverage(
    conn: &Connection,
    project_id: &str,
    since: &str,
    until: Option<&str>,
) -> Result<ProjectCostCoverage> {
    let groups = load_groups(conn, project_id, since, until)?;
    let truncated = groups.len() > MAX_GROUPS;
    let groups = &groups[..groups.len().min(MAX_GROUPS)];

    // One candidate load per provider rather than one per group: the set does
    // not change within a call, and a 30-integration project over 30 days is
    // hundreds of groups across a handful of providers.
    let mut candidate_cache: HashMap<String, Vec<PricingRecord>> = HashMap::new();

    let mut out = ProjectCostCoverage {
        estimated_micros: 0,
        currency: ESTIMATE_CURRENCY.to_string(),
        priced_requests: 0,
        priced_input_tokens: 0,
        priced_output_tokens: 0,
        known_input_tokens: 0,
        known_output_tokens: 0,
        unpriced_requests: 0,
        unpriced_tokens: 0,
        requests_with_unknown_usage: 0,
        token_coverage: None,
        complete: true,
        any_stale_pricing: false,
        truncated,
        priced: Vec::new(),
        unpriced: Vec::new(),
    };
    if truncated {
        out.complete = false;
    }

    // Accumulate per (provider, model) so the surface shows one row per model
    // rather than one per model per day, while pricing still happens per day
    // so effective dating is respected.
    let mut priced_acc: HashMap<(String, String), PricedUsage> = HashMap::new();
    let mut unpriced_acc: HashMap<(String, Option<String>, UnpricedReason), UnpricedUsage> =
        HashMap::new();

    for g in groups {
        // Tokens unknown is the blocker that outranks everything else: without
        // them there is nothing to price and nothing to put in a token total,
        // so these requests are counted and appear in neither token figure.
        let (Some(input), Some(output)) = (g.input_tokens, g.output_tokens) else {
            out.requests_with_unknown_usage += g.requests;
            out.complete = false;
            add_unpriced(
                &mut unpriced_acc,
                &g.provider,
                g.model.clone(),
                g.requests,
                None,
                None,
                UnpricedReason::UsageNotExtracted,
            );
            continue;
        };
        // Reported tokens are counted here, once, whatever happens to pricing
        // below. A token total must not depend on whether a price was found.
        out.known_input_tokens += input;
        out.known_output_tokens += output;

        // Tokens are known but no model was reported, so no record can be
        // selected. These tokens ARE known, so they count as unpriced tokens
        // rather than disappearing into "unknown usage".
        let Some(model) = g.model.as_deref() else {
            out.unpriced_requests += g.requests;
            out.unpriced_tokens += input + output;
            out.complete = false;
            add_unpriced(
                &mut unpriced_acc,
                &g.provider,
                None,
                g.requests,
                Some(input),
                Some(output),
                UnpricedReason::ModelNotDetected,
            );
            continue;
        };

        // `or_insert` would run the query on every group, cache hit or not,
        // because its argument is evaluated eagerly — the opposite of the
        // point. One query per distinct provider.
        if !candidate_cache.contains_key(&g.provider) {
            let loaded = pricing::candidates_for(conn, &g.provider)?;
            candidate_cache.insert(g.provider.clone(), loaded);
        }
        let candidates = &candidate_cache[&g.provider];

        let Some(rec) = pricing::choose_as_of(candidates, model, &g.day) else {
            out.unpriced_requests += g.requests;
            out.unpriced_tokens += input + output;
            out.complete = false;
            add_unpriced(
                &mut unpriced_acc,
                &g.provider,
                Some(model.to_string()),
                g.requests,
                Some(input),
                Some(output),
                UnpricedReason::NoPricingRecord,
            );
            continue;
        };
        if rec.currency != ESTIMATE_CURRENCY {
            out.unpriced_requests += g.requests;
            out.unpriced_tokens += input + output;
            out.complete = false;
            add_unpriced(
                &mut unpriced_acc,
                &g.provider,
                Some(model.to_string()),
                g.requests,
                Some(input),
                Some(output),
                UnpricedReason::UnsupportedCurrency,
            );
            continue;
        }

        // The gateway's own convention: cache-read tokens are excluded from
        // billable input, which makes the estimate a documented lower bound
        // rather than an over-count (docs/PRICING.md).
        let cached = g.cached_input_tokens.unwrap_or(0).clamp(0, input);
        let billable_input = input - cached;

        let Some(est) = pricing::estimate_token_cost_from(&rec, billable_input, output) else {
            out.unpriced_requests += g.requests;
            out.unpriced_tokens += input + output;
            out.complete = false;
            add_unpriced(
                &mut unpriced_acc,
                &g.provider,
                Some(model.to_string()),
                g.requests,
                Some(input),
                Some(output),
                UnpricedReason::NonTokenUnit,
            );
            continue;
        };

        out.estimated_micros = out.estimated_micros.saturating_add(est.micros);
        out.priced_requests += g.requests;
        out.priced_input_tokens += billable_input;
        out.priced_output_tokens += output;
        if !est.complete {
            out.complete = false;
            // The dimensions this record could not price are known tokens that
            // contributed nothing, so they belong in the unpriced token total.
            for dim in &est.unpriced_dimensions {
                match dim.as_str() {
                    "input tokens" => out.unpriced_tokens += billable_input,
                    "output tokens" => out.unpriced_tokens += output,
                    _ => {}
                }
            }
        }
        if est.stale {
            out.any_stale_pricing = true;
        }

        let key = (g.provider.clone(), model.to_string());
        let entry = priced_acc.entry(key).or_insert_with(|| PricedUsage {
            provider: g.provider.clone(),
            model: model.to_string(),
            matched_model: est.matched_model.clone(),
            requests: 0,
            input_tokens: 0,
            output_tokens: 0,
            micros: 0,
            currency: est.currency.clone(),
            pricing_source: est.pricing_source.clone(),
            effective_from: est.effective_from.clone(),
            last_verified: est.last_verified.clone(),
            stale: est.stale,
            is_override: est.is_override,
            note: est.note.clone(),
            complete: true,
            unpriced_dimensions: Vec::new(),
        });
        entry.requests += g.requests;
        entry.input_tokens += billable_input;
        entry.output_tokens += output;
        entry.micros = entry.micros.saturating_add(est.micros);
        entry.stale |= est.stale;
        if !est.complete {
            entry.complete = false;
            for dim in &est.unpriced_dimensions {
                if !entry.unpriced_dimensions.contains(dim) {
                    entry.unpriced_dimensions.push(dim.clone());
                }
            }
        }
    }

    let known_tokens = out.priced_input_tokens + out.priced_output_tokens + out.unpriced_tokens;
    out.token_coverage = (known_tokens > 0).then(|| {
        let priced = (out.priced_input_tokens + out.priced_output_tokens) as f64;
        priced / known_tokens as f64
    });

    out.priced = priced_acc.into_values().collect();
    out.priced
        .sort_by(|a, b| b.micros.cmp(&a.micros).then(a.model.cmp(&b.model)));
    out.unpriced = unpriced_acc.into_values().collect();
    out.unpriced.sort_by(|a, b| {
        b.requests
            .cmp(&a.requests)
            .then(a.provider.cmp(&b.provider))
            .then(a.model.cmp(&b.model))
    });
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn add_unpriced(
    acc: &mut HashMap<(String, Option<String>, UnpricedReason), UnpricedUsage>,
    provider: &str,
    model: Option<String>,
    requests: i64,
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    reason: UnpricedReason,
) {
    let key = (provider.to_string(), model.clone(), reason);
    let entry = acc.entry(key).or_insert_with(|| UnpricedUsage {
        provider: provider.to_string(),
        model,
        requests: 0,
        input_tokens: None,
        output_tokens: None,
        reason,
    });
    entry.requests += requests;
    // `None` is "not reported" and must survive being merged with a known
    // number: adding a known count to an unknown one does not make the total
    // known, so only accumulate when both sides are known.
    entry.input_tokens = merge_optional(entry.input_tokens, input_tokens);
    entry.output_tokens = merge_optional(entry.output_tokens, output_tokens);
}

/// Sum two possibly-unknown counts. Unknown + known stays known-so-far, which
/// would overstate coverage, so the result is unknown unless both are known or
/// the accumulator is still empty.
fn merge_optional(acc: Option<i64>, next: Option<i64>) -> Option<i64> {
    match (acc, next) {
        (None, v) => v,
        (Some(a), Some(b)) => Some(a + b),
        (Some(_), None) => None,
    }
}

fn load_groups(
    conn: &Connection,
    project_id: &str,
    since: &str,
    until: Option<&str>,
) -> Result<Vec<UsageGroup>> {
    // `SUM` over a column that is NULL for every row in the group yields NULL,
    // which is exactly the distinction that matters: it means "nobody reported
    // this", not "the total was zero". COALESCE(...,0) here would erase it.
    let mut stmt = conn.prepare(
        "SELECT provider_id, model, substr(at, 1, 10) AS day, COUNT(*),
                SUM(input_tokens), SUM(output_tokens), SUM(cached_input_tokens)
         FROM gateway_usage_events
         WHERE project_id = ?1 AND at >= ?2 AND (?3 IS NULL OR at < ?3)
         GROUP BY provider_id, model, day
         ORDER BY day, provider_id, model
         LIMIT ?4",
    )?;
    let rows = stmt.query_map(
        params![project_id, since, until, MAX_GROUPS as i64 + 1],
        |r| {
            Ok(UsageGroup {
                provider: r.get(0)?,
                model: r.get(1)?,
                day: r.get(2)?,
                requests: r.get(3)?,
                input_tokens: r.get(4)?,
                output_tokens: r.get(5)?,
                cached_input_tokens: r.get(6)?,
            })
        },
    )?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::runtime::store::testutil;

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        conn.pragma_update(None, "foreign_keys", 1).unwrap();
        testutil::seed_project(&conn, "p1", "web");
        conn
    }

    /// One usage event. `model = None` and `tokens = None` are the two distinct
    /// "absent" cases the module must keep apart.
    #[allow(clippy::too_many_arguments)]
    fn usage(
        conn: &Connection,
        at: &str,
        provider: &str,
        model: Option<&str>,
        input: Option<i64>,
        output: Option<i64>,
        cached: Option<i64>,
    ) {
        let available = i64::from(input.is_some() || output.is_some());
        let state = if available == 1 {
            "extracted"
        } else {
            "absent"
        };
        conn.execute(
            "INSERT INTO gateway_usage_events
                (id, at, route_prefix, provider_id, project_id, model,
                 input_tokens, output_tokens, cached_input_tokens,
                 usage_available, usage_state)
             VALUES (?1, ?2, ?3, ?4, 'p1', ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                uuid::Uuid::new_v4().to_string(),
                at,
                provider,
                provider,
                model,
                input,
                output,
                cached,
                available,
                state
            ],
        )
        .unwrap();
    }

    fn coverage(conn: &Connection) -> ProjectCostCoverage {
        project_cost_coverage(conn, "p1", "2000-01-01T00:00:00Z", None).unwrap()
    }

    #[test]
    fn known_openai_model_is_priced_and_complete() {
        let conn = mem();
        // gpt-4o bundled: input 2.50/M, output 10.00/M (2_500_000 / 10_000_000
        // micros per million). 1M in + 1M out = 12.50.
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-4o"),
            Some(1_000_000),
            Some(1_000_000),
            None,
        );
        let c = coverage(&conn);
        assert_eq!(c.estimated_micros, 12_500_000);
        assert_eq!(c.currency, "USD");
        assert!(c.complete);
        assert_eq!(c.micros_if_complete(), Some(12_500_000));
        assert_eq!(c.priced_requests, 1);
        assert_eq!(c.unpriced_requests, 0);
        assert_eq!(c.token_coverage, Some(1.0));
        assert!(c.coverage_note().is_none());
        assert_eq!(c.priced[0].matched_model, "gpt-4o");
    }

    #[test]
    fn known_anthropic_model_is_priced() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "anthropic",
            Some("claude-sonnet-4-5"),
            Some(1_000_000),
            Some(0),
            None,
        );
        let c = coverage(&conn);
        assert!(c.estimated_micros > 0);
        assert!(c.complete);
        assert_eq!(c.priced[0].provider, "anthropic");
    }

    /// A dated snapshot id resolves to its base record, and the estimate says
    /// which record priced it rather than echoing the id it was given.
    #[test]
    fn dated_snapshot_resolves_to_its_base_record() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-4o-2024-08-06"),
            Some(1_000_000),
            Some(1_000_000),
            None,
        );
        let c = coverage(&conn);
        assert_eq!(c.estimated_micros, 12_500_000);
        assert_eq!(c.priced[0].model, "gpt-4o-2024-08-06");
        assert_eq!(c.priced[0].matched_model, "gpt-4o");
        assert!(c.complete);
    }

    /// A provider-prefixed id still resolves, and the provider alias path does
    /// not silently find zero records.
    #[test]
    fn provider_prefixed_model_id_resolves() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("openai/gpt-4o"),
            Some(1_000_000),
            Some(0),
            None,
        );
        let c = coverage(&conn);
        assert_eq!(c.estimated_micros, 2_500_000);
        assert_eq!(c.priced[0].matched_model, "gpt-4o");
    }

    /// Input and output are priced at different rates, so swapping the two
    /// token counts must change the amount. A single blended rate would pass a
    /// same-total assertion, which is why this compares two directions.
    #[test]
    fn input_and_output_prices_are_not_interchangeable() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-4o"),
            Some(1_000_000),
            Some(0),
            None,
        );
        let input_only = coverage(&conn).estimated_micros;

        let conn2 = mem();
        usage(
            &conn2,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-4o"),
            Some(0),
            Some(1_000_000),
            None,
        );
        let output_only = coverage(&conn2).estimated_micros;

        assert_eq!(input_only, 2_500_000);
        assert_eq!(output_only, 10_000_000);
        assert_ne!(input_only, output_only);
    }

    /// Zero tokens against a known model is a real, complete $0.00 — and is
    /// distinguishable from an unpriced model, which is NOT zero.
    #[test]
    fn a_known_zero_is_complete_and_differs_from_unpriced() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-4o"),
            Some(0),
            Some(0),
            None,
        );
        let known_zero = coverage(&conn);
        assert_eq!(known_zero.estimated_micros, 0);
        assert!(known_zero.complete);
        assert_eq!(known_zero.micros_if_complete(), Some(0));

        let conn2 = mem();
        usage(
            &conn2,
            "2026-07-18T12:00:00Z",
            "mystery",
            Some("who-knows"),
            Some(1_000),
            Some(1_000),
            None,
        );
        let unpriced = coverage(&conn2);
        assert_eq!(unpriced.estimated_micros, 0);
        // Same integer, opposite meaning: this one may not be presented as a
        // total at all.
        assert!(!unpriced.complete);
        assert_eq!(unpriced.micros_if_complete(), None);
    }

    /// A token total must not depend on whether a price was found, and must not
    /// silently become the cache-excluded billable figure.
    #[test]
    fn known_tokens_are_counted_whether_or_not_they_could_be_priced() {
        let conn = mem();
        // Priced, with a cache read: billable input is lower than reported input.
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-4o"),
            Some(1_000),
            Some(500),
            Some(400),
        );
        // Unpriced, so it contributes nothing to the estimate.
        usage(
            &conn,
            "2026-07-18T12:05:00Z",
            "openai",
            Some("gpt-unpriced"),
            Some(70),
            Some(30),
            None,
        );
        let c = coverage(&conn);

        assert_eq!(c.known_input_tokens, 1_070, "every reported input token");
        assert_eq!(c.known_output_tokens, 530);
        assert_eq!(
            c.priced_input_tokens, 600,
            "the estimate is over billable input only (1000 - 400 cached)"
        );
        assert_eq!(c.priced_output_tokens, 500);
        assert!(!c.complete);
    }

    #[test]
    fn unknown_model_is_visible_counted_and_not_zero() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-nonexistent-9"),
            Some(4_000),
            Some(8_400),
            None,
        );
        let c = coverage(&conn);
        assert!(!c.complete);
        assert_eq!(c.micros_if_complete(), None);
        assert_eq!(c.unpriced_requests, 1);
        assert_eq!(c.unpriced_tokens, 12_400);
        assert_eq!(c.token_coverage, Some(0.0));
        assert_eq!(c.unpriced.len(), 1);
        assert_eq!(c.unpriced[0].reason, UnpricedReason::NoPricingRecord);
        assert_eq!(c.unpriced[0].input_tokens, Some(4_000));
        assert!(c.coverage_note().unwrap().contains("1 model variant"));
    }

    /// The spec's worked example: a known amount, a visible unpriced remainder,
    /// and a coverage fraction that is neither 0% nor 100%.
    #[test]
    fn mixed_known_and_unknown_reports_partial_coverage() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-4o"),
            Some(60_000),
            Some(16_000),
            None,
        );
        usage(
            &conn,
            "2026-07-18T12:05:00Z",
            "openai",
            Some("gpt-unpriced"),
            Some(8_000),
            Some(4_400),
            None,
        );
        let c = coverage(&conn);
        assert!(!c.complete);
        assert!(c.estimated_micros > 0, "the known half is still estimated");
        assert_eq!(c.priced_requests, 1);
        assert_eq!(c.unpriced_requests, 1);
        assert_eq!(c.unpriced_tokens, 12_400);
        let cov = c.token_coverage.unwrap();
        assert!(cov > 0.0 && cov < 1.0, "coverage was {cov}");
        // 76_000 priced of 88_400 known tokens.
        assert!((cov - (76_000.0 / 88_400.0)).abs() < 1e-9);
    }

    /// Requests that reported no usage at all are counted, and their tokens
    /// stay unknown: they must not land in either token total as zero.
    #[test]
    fn requests_without_reported_usage_are_unknown_not_zero() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-4o"),
            None,
            None,
            None,
        );
        let c = coverage(&conn);
        assert_eq!(c.requests_with_unknown_usage, 1);
        assert_eq!(c.priced_input_tokens, 0);
        assert_eq!(c.unpriced_tokens, 0);
        assert_eq!(c.token_coverage, None, "no known tokens means no ratio");
        assert!(!c.complete);
        assert_eq!(c.unpriced[0].reason, UnpricedReason::UsageNotExtracted);
        assert_eq!(c.unpriced[0].input_tokens, None);
    }

    /// Tokens known but no model reported: the tokens ARE known, so they count
    /// as unpriced tokens rather than vanishing into "unknown usage".
    #[test]
    fn known_tokens_without_a_model_are_unpriced_not_unknown() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            None,
            Some(500),
            Some(700),
            None,
        );
        let c = coverage(&conn);
        assert_eq!(c.requests_with_unknown_usage, 0);
        assert_eq!(c.unpriced_requests, 1);
        assert_eq!(c.unpriced_tokens, 1_200);
        assert_eq!(c.unpriced[0].reason, UnpricedReason::ModelNotDetected);
        assert_eq!(c.unpriced[0].model, None);
        assert!(!c.complete);
    }

    /// Merging an unknown token count into a known one must not yield a number
    /// that reads as known.
    #[test]
    fn merging_unknown_into_known_tokens_stays_unknown() {
        assert_eq!(merge_optional(None, Some(5)), Some(5));
        assert_eq!(merge_optional(Some(5), Some(5)), Some(10));
        assert_eq!(merge_optional(Some(5), None), None);
        assert_eq!(merge_optional(None, None), None);
    }

    /// Effective dating: the same model priced on two dates picks the two
    /// different records, and the later usage is not priced with the old rate.
    #[test]
    fn effective_date_selects_the_record_in_force_that_day() {
        let conn = mem();
        conn.execute(
            "INSERT INTO pricing_records
                (id, provider, model, unit, input_price_per_m_micros, output_price_per_m_micros,
                 currency, source, effective_from, last_verified, origin, version, note, created_at)
             VALUES ('r1','fakeprov','fm','tokens',1000000,0,'USD','test','2026-01-01',
                     '2026-07-18','imported',1,'','2026-01-01T00:00:00Z'),
                    ('r2','fakeprov','fm','tokens',2000000,0,'USD','test','2026-06-01',
                     '2026-07-18','imported',1,'','2026-06-01T00:00:00Z')",
            [],
        )
        .unwrap();
        usage(
            &conn,
            "2026-03-01T00:00:00Z",
            "fakeprov",
            Some("fm"),
            Some(1_000_000),
            Some(0),
            None,
        );
        usage(
            &conn,
            "2026-07-01T00:00:00Z",
            "fakeprov",
            Some("fm"),
            Some(1_000_000),
            Some(0),
            None,
        );
        let c = coverage(&conn);
        // 1.00 at the old rate + 2.00 at the new one, not 2 x either.
        assert_eq!(c.estimated_micros, 3_000_000);
        assert!(c.complete);
    }

    /// A record with an output price but no input price prices only half the
    /// usage. The amount is a floor, the group says so, and the unpriced
    /// dimension's tokens are counted as unpriced.
    #[test]
    fn partial_pricing_is_a_floor_not_a_total() {
        let conn = mem();
        conn.execute(
            "INSERT INTO pricing_records
                (id, provider, model, unit, input_price_per_m_micros, output_price_per_m_micros,
                 currency, source, effective_from, last_verified, origin, version, note, created_at)
             VALUES ('r1','fakeprov','half','tokens',NULL,10000000,'USD','test','2026-01-01',
                     '2026-07-18','imported',1,'','2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        usage(
            &conn,
            "2026-07-18T00:00:00Z",
            "fakeprov",
            Some("half"),
            Some(1_000_000),
            Some(1_000_000),
            None,
        );
        let c = coverage(&conn);
        assert_eq!(c.estimated_micros, 10_000_000, "output only");
        assert!(!c.complete);
        assert_eq!(c.micros_if_complete(), None);
        assert_eq!(c.unpriced_tokens, 1_000_000, "the unpriced input tokens");
        assert!(!c.priced[0].complete);
        assert!(c.priced[0]
            .unpriced_dimensions
            .contains(&"input tokens".to_string()));
        assert!(c.coverage_note().unwrap().contains("floor"));
    }

    /// A record past its verification horizon still prices, and says it is stale.
    #[test]
    fn a_stale_record_prices_and_is_flagged() {
        let conn = mem();
        conn.execute(
            "INSERT INTO pricing_records
                (id, provider, model, unit, input_price_per_m_micros, output_price_per_m_micros,
                 currency, source, effective_from, last_verified, origin, version, note, created_at)
             VALUES ('r1','fakeprov','oldm','tokens',1000000,0,'USD','test','2020-01-01',
                     '2020-01-01','imported',1,'','2020-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        usage(
            &conn,
            "2026-07-18T00:00:00Z",
            "fakeprov",
            Some("oldm"),
            Some(1_000_000),
            Some(0),
            None,
        );
        let c = coverage(&conn);
        assert_eq!(c.estimated_micros, 1_000_000);
        assert!(c.any_stale_pricing);
        assert!(c.priced[0].stale);
    }

    /// A record in another currency is reported as unpriced rather than summed
    /// into a USD total or converted.
    #[test]
    fn a_foreign_currency_record_does_not_enter_the_total() {
        let conn = mem();
        conn.execute(
            "INSERT INTO pricing_records
                (id, provider, model, unit, input_price_per_m_micros, output_price_per_m_micros,
                 currency, source, effective_from, last_verified, origin, version, note, created_at)
             VALUES ('r1','fakeprov','eurm','tokens',1000000,0,'EUR','test','2026-01-01',
                     '2026-07-18','imported',1,'','2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        usage(
            &conn,
            "2026-07-18T00:00:00Z",
            "fakeprov",
            Some("eurm"),
            Some(1_000_000),
            Some(0),
            None,
        );
        let c = coverage(&conn);
        assert_eq!(c.estimated_micros, 0);
        assert!(!c.complete);
        assert_eq!(c.unpriced[0].reason, UnpricedReason::UnsupportedCurrency);
    }

    /// Cache-read tokens are excluded from billable input, matching the
    /// gateway's own convention, so the estimate is a documented lower bound.
    #[test]
    fn cached_input_tokens_are_excluded_from_billable_input() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-4o"),
            Some(1_000_000),
            Some(0),
            Some(1_000_000),
        );
        let c = coverage(&conn);
        assert_eq!(c.estimated_micros, 0, "all input was a cache read");
        assert_eq!(c.priced_input_tokens, 0);
    }

    /// Nothing observed is not the same as nothing costing anything.
    #[test]
    fn an_empty_window_is_empty_not_free() {
        let conn = mem();
        let c = coverage(&conn);
        assert!(c.is_empty());
        assert_eq!(c.token_coverage, None);
        // With nothing to price, nothing is missing either.
        assert!(c.complete);
    }

    /// Provider-reported cost lives in `usage_snapshots` and must not reach the
    /// local estimate, in either direction (SI-19).
    #[test]
    fn provider_reported_cost_is_not_summed_into_the_local_estimate() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-18T12:00:00Z",
            "openai",
            Some("gpt-4o"),
            Some(1_000_000),
            Some(0),
            None,
        );
        conn.execute(
            "INSERT INTO usage_snapshots
                (id, provider, window_start, window_end, reported_cost_micros, currency,
                 source, attribution, collected_at)
             VALUES ('u1','openai','2026-07-18','2026-07-19',999_000_000,'USD','manual',
                     'account','2026-07-18T00:00:00Z')",
            [],
        )
        .unwrap();
        let c = coverage(&conn);
        assert_eq!(
            c.estimated_micros, 2_500_000,
            "the reported 999.00 must not appear in the local estimate"
        );
    }

    /// One row per (provider, model) on the surface, even when the traffic
    /// spans several days — while pricing still happened per day.
    #[test]
    fn groups_collapse_per_model_across_days() {
        let conn = mem();
        for day in ["2026-07-16", "2026-07-17", "2026-07-18"] {
            usage(
                &conn,
                &format!("{day}T12:00:00Z"),
                "openai",
                Some("gpt-4o"),
                Some(1_000_000),
                Some(0),
                None,
            );
        }
        let c = coverage(&conn);
        assert_eq!(c.priced.len(), 1);
        assert_eq!(c.priced[0].requests, 3);
        assert_eq!(c.estimated_micros, 7_500_000);
    }

    /// The window bounds are honoured, so a range change cannot silently
    /// include traffic from outside it.
    #[test]
    fn the_window_bounds_are_applied() {
        let conn = mem();
        usage(
            &conn,
            "2026-07-01T00:00:00Z",
            "openai",
            Some("gpt-4o"),
            Some(1_000_000),
            Some(0),
            None,
        );
        usage(
            &conn,
            "2026-07-20T00:00:00Z",
            "openai",
            Some("gpt-4o"),
            Some(1_000_000),
            Some(0),
            None,
        );
        let windowed = project_cost_coverage(
            &conn,
            "p1",
            "2026-07-15T00:00:00Z",
            Some("2026-07-25T00:00:00Z"),
        )
        .unwrap();
        assert_eq!(windowed.priced_requests, 1);
        assert_eq!(windowed.estimated_micros, 2_500_000);
    }

    /// Another project's traffic is not this project's cost.
    #[test]
    fn other_projects_are_excluded() {
        let conn = mem();
        testutil::seed_project(&conn, "p2", "other");
        conn.execute(
            "INSERT INTO gateway_usage_events
                (id, at, route_prefix, provider_id, project_id, model, input_tokens,
                 output_tokens, usage_available, usage_state)
             VALUES ('e9','2026-07-18T12:00:00Z','openai','openai','p2','gpt-4o',
                     1000000,0,1,'extracted')",
            [],
        )
        .unwrap();
        let c = coverage(&conn);
        assert!(c.is_empty());
        assert_eq!(c.estimated_micros, 0);
    }
}
