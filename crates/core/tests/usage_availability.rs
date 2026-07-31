//! NEW-37: absent usage data is a state, never a silent zero.
//!
//! Three shipped invariants govern this file — `PRODUCT_BEHAVIOR.md`
//! ("Absent usage data is a state, never a silent zero"),
//! `COVERAGE_LIMITATIONS.md` ("never a fabricated zero") and ADR 0019
//! ("never a fabricated 0") — and `CLAUDE.md` lists "Provider capabilities
//! must be represented honestly" among the requirements that may not be
//! silently changed.
//!
//! `UsageTotals` folds every `Option<i64>` column with `unwrap_or(0)`, so
//! the sums alone cannot tell "no record reported tokens" from "every
//! record reported zero tokens". These tests pin the residual counts that
//! make the difference visible, the three-valued budget verdict built on
//! them, and the completeness a partial pricing record now carries.

use api_tracker_core::budget::{self, BudgetStatus};
use api_tracker_core::pricing;
use api_tracker_core::usage::{
    self, Attribution, Availability, NewUsageSnapshot, UsageFilter, UsageTotals,
};
use rusqlite::Connection;

const START: &str = "2026-07-01T00:00:00Z";
const WINDOW_START: &str = "2026-07-05T00:00:00Z";
const WINDOW_END: &str = "2026-07-06T00:00:00Z";

fn mem() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    api_tracker_core::db::migrate(&mut conn).unwrap();
    // These tests exercise aggregation over synthetic ids, not referential
    // integrity.
    conn.pragma_update(None, "foreign_keys", 0).unwrap();
    conn
}

/// A snapshot that reports nothing at all: the shape produced by the five
/// routable providers whose manifests declare `usage_shape = ""`.
fn blank(provider: &str) -> NewUsageSnapshot {
    let mut s = NewUsageSnapshot::new(provider, WINDOW_START, WINDOW_END);
    s.attribution = Attribution::ProviderAccount;
    s
}

fn tokens(provider: &str, input: i64, output: i64) -> NewUsageSnapshot {
    let mut s = blank(provider);
    s.input_tokens = Some(input);
    s.output_tokens = Some(output);
    s.total_tokens = Some(input + output);
    s
}

fn totals_for(conn: &Connection, provider: &str) -> UsageTotals {
    usage::totals(
        conn,
        &UsageFilter {
            since: Some(START.into()),
            provider: Some(provider.into()),
            ..Default::default()
        },
    )
    .unwrap()
}

// --- token coverage ---------------------------------------------------

#[test]
fn all_records_known_reports_a_complete_total() {
    let conn = mem();
    usage::record(&conn, &tokens("openai", 1_000, 500)).unwrap();
    usage::record(&conn, &tokens("openai", 2_000, 1_000)).unwrap();

    let t = totals_for(&conn, "openai");
    // The sums keep their original meaning.
    assert_eq!(t.input_tokens, 3_000);
    assert_eq!(t.output_tokens, 1_500);
    assert_eq!(t.total_tokens, 4_500);
    // And now say how many records they folded.
    assert_eq!(t.token_rows, 2);
    assert_eq!(t.rows_without_tokens, 0);
    assert_eq!(
        t.total_token_availability(),
        Availability::Known {
            covered: 2,
            total: 2
        }
    );
    assert!(t.total_token_availability().is_complete());
}

#[test]
fn some_records_unknown_reports_a_floor_not_a_total() {
    let conn = mem();
    usage::record(&conn, &tokens("openai", 1_000, 500)).unwrap();
    usage::record(&conn, &blank("openai")).unwrap();
    usage::record(&conn, &blank("openai")).unwrap();

    let t = totals_for(&conn, "openai");
    assert_eq!(t.total_tokens, 1_500, "the sum itself must not change");
    assert_eq!(t.token_rows, 1);
    assert_eq!(t.rows_without_tokens, 2);
    let a = t.total_token_availability();
    assert_eq!(
        a,
        Availability::Partial {
            covered: 1,
            total: 3
        }
    );
    assert!(a.has_value(), "a floor is still worth showing");
    assert!(!a.is_complete(), "but it is not a total");
    // The qualifier names the shortfall and refuses the zero reading.
    let note = a.note(&usage::SUBJECT_TOTAL_TOKENS).unwrap();
    assert!(note.contains("1 of 3"), "note was: {note}");
    assert!(note.contains("NOT counted as zero"), "note was: {note}");
}

#[test]
fn all_records_unknown_is_unknown_and_never_renders_zero() {
    let conn = mem();
    usage::record(&conn, &blank("cohere")).unwrap();
    usage::record(&conn, &blank("cohere")).unwrap();

    let t = totals_for(&conn, "cohere");
    assert_eq!(t.total_tokens, 0, "the coalesced sum is still 0");
    assert_eq!(t.token_rows, 0);
    assert_eq!(t.rows_without_tokens, 2);
    let a = t.total_token_availability();
    assert_eq!(a, Availability::Unknown { total: 2 });
    assert!(!a.has_value());
    // This is the whole point: the renderer cannot emit "0" for it.
    let rendered = usage::render_count(t.total_tokens, &a, &usage::SUBJECT_TOTAL_TOKENS);
    assert!(!rendered.contains('0'), "rendered a zero: {rendered}");
    assert!(rendered.contains("not reported"), "rendered: {rendered}");
    assert!(
        rendered.contains("none of the 2 usage record(s)"),
        "rendered: {rendered}"
    );
}

#[test]
fn a_genuinely_measured_zero_is_still_shown_as_zero() {
    let conn = mem();
    // A real request that consumed nothing. Hiding this would be a
    // different lie: it is a measurement, not an absence.
    usage::record(&conn, &tokens("openai", 0, 0)).unwrap();

    let t = totals_for(&conn, "openai");
    let a = t.total_token_availability();
    assert_eq!(
        a,
        Availability::Known {
            covered: 1,
            total: 1
        }
    );
    assert_eq!(
        usage::render_count(t.total_tokens, &a, &usage::SUBJECT_TOTAL_TOKENS),
        "0"
    );
}

#[test]
fn a_provider_metered_in_other_units_is_unsupported_not_absent() {
    let conn = mem();
    for _ in 0..2 {
        let mut s = blank("supabase");
        s.quantity = Some(120.0);
        s.unit = Some("requests".into());
        usage::record(&conn, &s).unwrap();
    }

    let t = totals_for(&conn, "supabase");
    assert_eq!(t.token_rows, 0);
    assert_eq!(t.non_token_unit_rows, 2);
    assert_eq!(t.non_token_units, vec!["requests".to_string()]);
    let a = t.total_token_availability();
    assert!(
        matches!(a, Availability::Unsupported { .. }),
        "expected unsupported, got {a:?}"
    );
    let rendered = usage::render_count(t.total_tokens, &a, &usage::SUBJECT_TOTAL_TOKENS);
    assert!(
        rendered.contains("metered in requests, not tokens"),
        "rendered: {rendered}"
    );
    assert!(!rendered.contains('0'), "rendered a zero: {rendered}");
}

#[test]
fn partial_input_and_output_fields_are_tracked_independently() {
    let conn = mem();
    // A provider that reports prompt tokens but not completion tokens.
    let mut only_input = blank("google-gemini");
    only_input.input_tokens = Some(900);
    usage::record(&conn, &only_input).unwrap();
    usage::record(&conn, &tokens("google-gemini", 100, 50)).unwrap();

    let t = totals_for(&conn, "google-gemini");
    assert_eq!(t.input_token_rows, 2);
    assert_eq!(t.rows_without_input_tokens, 0);
    assert_eq!(t.output_token_rows, 1);
    assert_eq!(t.rows_without_output_tokens, 1);
    assert_eq!(t.token_rows, 2, "both records carried some token count");

    // Input is complete; output is a floor. One shared "tokens" verdict
    // would have flattened these into a single wrong answer.
    assert!(t.input_token_availability().is_complete());
    assert_eq!(
        t.output_token_availability(),
        Availability::Partial {
            covered: 1,
            total: 2
        }
    );
    let out = usage::render_count(
        t.output_tokens,
        &t.output_token_availability(),
        &usage::SUBJECT_OUTPUT_TOKENS,
    );
    assert!(
        out.starts_with("50 — Partial token data"),
        "rendered: {out}"
    );
}

#[test]
fn an_empty_window_is_unknown_rather_than_zero() {
    let conn = mem();
    let t = totals_for(&conn, "openai");
    assert_eq!(t.snapshots, 0);
    let a = t.total_token_availability();
    assert_eq!(a, Availability::Unknown { total: 0 });
    let rendered = usage::render_count(t.total_tokens, &a, &usage::SUBJECT_TOTAL_TOKENS);
    assert!(
        rendered.contains("no usage record(s) in this window"),
        "rendered: {rendered}"
    );
    assert!(!rendered.contains('0'), "rendered a zero: {rendered}");
}

// --- cost coverage ----------------------------------------------------

#[test]
fn reported_and_estimated_cost_coverage_are_separate_questions() {
    let conn = mem();
    // Reported-cost row with no estimate.
    let mut reported = tokens("anthropic", 10, 10);
    reported.reported_cost_micros = Some(2_000_000);
    usage::record(&conn, &reported).unwrap();
    // Estimated-only row.
    let mut estimated = tokens("anthropic", 10, 10);
    estimated.estimated_cost_micros = Some(500_000);
    usage::record(&conn, &estimated).unwrap();

    let t = totals_for(&conn, "anthropic");
    assert_eq!(t.reported_cost_micros, 2_000_000);
    assert_eq!(t.estimated_cost_micros, 500_000);
    assert_eq!(t.reported_cost_rows, 1);
    assert_eq!(t.rows_without_reported_cost, 1);
    assert_eq!(t.estimated_cost_rows, 1);
    assert_eq!(t.rows_without_estimated_cost, 1);
    assert!(!t.reported_cost_availability().is_complete());
    assert!(!t.estimated_cost_availability().is_complete());
}

#[test]
fn non_usd_reported_rows_are_excluded_from_the_count_as_well_as_the_sum() {
    let conn = mem();
    let mut eur = tokens("mistral", 10, 10);
    eur.reported_cost_micros = Some(9_000_000);
    eur.currency = "EUR".into();
    usage::record(&conn, &eur).unwrap();

    let t = totals_for(&conn, "mistral");
    assert_eq!(t.reported_cost_micros, 0, "non-USD stays out of the sum");
    assert_eq!(
        t.reported_cost_rows, 0,
        "and out of the count, so the $0.00 is never presented as measured"
    );
    let a = t.reported_cost_availability();
    assert_eq!(a, Availability::Unknown { total: 1 });
    let rendered = usage::render_micros(t.reported_cost_micros, &a, &usage::SUBJECT_REPORTED_COST);
    assert!(!rendered.contains("$0.00"), "rendered: {rendered}");
}

#[test]
fn mixed_sources_share_one_coverage_denominator() {
    let conn = mem();
    let mut manual = tokens("openai", 100, 100);
    manual.source = "manual".into();
    manual.estimated_cost_micros = Some(1_000);
    usage::record(&conn, &manual).unwrap();
    let mut synced = tokens("openai", 200, 200);
    synced.source = "provider_sync".into();
    usage::record(&conn, &synced).unwrap();

    let all = totals_for(&conn, "openai");
    assert_eq!(all.snapshots, 2);
    assert_eq!(
        all.estimated_cost_availability(),
        Availability::Partial {
            covered: 1,
            total: 2
        }
    );

    // Narrowing to the manual source narrows the denominator with it, so
    // the same estimate becomes a complete answer for that scope.
    let manual_only = usage::totals(
        &conn,
        &UsageFilter {
            since: Some(START.into()),
            provider: Some("openai".into()),
            source: usage::SourceFilter::Manual,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(manual_only.snapshots, 1);
    assert!(manual_only.estimated_cost_availability().is_complete());
}

#[test]
fn used_cost_availability_follows_the_same_branch_as_used_cost() {
    let conn = mem();
    let mut reported = tokens("openai", 10, 10);
    reported.reported_cost_micros = Some(4_000_000);
    usage::record(&conn, &reported).unwrap();
    let mut estimated = tokens("openai", 10, 10);
    estimated.estimated_cost_micros = Some(1_000_000);
    usage::record(&conn, &estimated).unwrap();

    let t = totals_for(&conn, "openai");
    for source in [
        usage::CostSource::BestAvailable,
        usage::CostSource::ProviderReported,
        usage::CostSource::Estimated,
    ] {
        let (used, _) = usage::pick_used_cost(&t, source);
        let a = usage::pick_used_cost_availability(&t, source);
        // Whatever figure was picked, its coverage describes THAT figure.
        let expected = if used == t.reported_cost_micros && source != usage::CostSource::Estimated {
            t.reported_cost_availability()
        } else {
            t.estimated_cost_availability()
        };
        assert_eq!(a, expected, "source {source:?} mismatched its coverage");
    }
}

// --- budget evaluation ------------------------------------------------

fn project_with_budget(conn: &Connection, id: &str, name: &str, budget_micros: i64) {
    conn.execute(
        "INSERT INTO projects (id, name, created_at, updated_at, wrapped_project_key, \
         key_wrap_mode, monthly_budget_micros) VALUES (?1, ?2, ?3, ?3, x'00', 'vault', ?4)",
        rusqlite::params![id, name, WINDOW_START, budget_micros],
    )
    .unwrap();
}

/// Snapshots attributed to `project_id` inside the CURRENT month, because
/// `project_report` always reports on the live calendar month.
fn record_for_project(conn: &Connection, project_id: &str, estimated: Option<i64>) {
    let now = api_tracker_core::clock::now_rfc3339();
    let mut s = NewUsageSnapshot::new("openai", &now, &now);
    s.project_id = Some(project_id.into());
    s.input_tokens = Some(1_000);
    s.output_tokens = Some(1_000);
    s.total_tokens = Some(2_000);
    s.estimated_cost_micros = estimated;
    s.attribution = Attribution::LocalProject;
    usage::record(conn, &s).unwrap();
}

#[test]
fn budget_over_complete_data_reports_under_budget() {
    let conn = mem();
    project_with_budget(&conn, "p-complete", "complete", 100_000_000);
    record_for_project(&conn, "p-complete", Some(1_000_000));
    record_for_project(&conn, "p-complete", Some(2_000_000));

    let r = budget::project_report(&conn, "p-complete", usage::CostSource::BestAvailable).unwrap();
    assert_eq!(r.used_micros, 3_000_000);
    assert_eq!(r.costed_rows, 2);
    assert_eq!(r.usage_rows, 2);
    assert!(r.used_is_complete);
    assert_eq!(r.status, BudgetStatus::Under);
    assert!(!r.over_budget);
    assert!(budget::over_budget_alert(&r, None).is_none());
}

/// The correctness half of NEW-37: an understated total must not be allowed
/// to answer "under budget" with confidence it does not have.
#[test]
fn budget_over_partial_data_cannot_be_evaluated() {
    let conn = mem();
    project_with_budget(&conn, "p-partial", "partial", 100_000_000);
    record_for_project(&conn, "p-partial", Some(1_000_000));
    // Three records whose cost never arrived. Their spend is unknown, and
    // an unknown is not a zero, so the $1.00 floor proves nothing.
    for _ in 0..3 {
        record_for_project(&conn, "p-partial", None);
    }

    let r = budget::project_report(&conn, "p-partial", usage::CostSource::BestAvailable).unwrap();
    assert_eq!(r.used_micros, 1_000_000, "the sum itself is unchanged");
    assert_eq!(r.costed_rows, 1);
    assert_eq!(r.usage_rows, 4);
    assert!(!r.used_is_complete);
    assert_eq!(
        r.status,
        BudgetStatus::Indeterminate,
        "a floor under the budget proves nothing"
    );
    assert!(!r.over_budget, "and it must not claim an overrun either");
    let note = r.completeness_note.expect("a shortfall must be named");
    assert!(note.contains("cannot evaluate"), "note was: {note}");
    assert!(note.contains("1 of 4"), "note was: {note}");
    assert!(note.contains("NOT counted as zero"), "note was: {note}");
}

/// MUTATION CONTROL for `budget.rs`: reverting the three-valued verdict to
/// the old `if !report.over_budget { return None }` makes this fail,
/// because partial data would go back to raising nothing at all.
#[test]
fn budget_incompleteness_raises_a_named_alert_instead_of_silence() {
    let conn = mem();
    project_with_budget(&conn, "p-alert", "alert", 100_000_000);
    record_for_project(&conn, "p-alert", Some(1_000_000));
    record_for_project(&conn, "p-alert", None);

    let r = budget::project_report(&conn, "p-alert", usage::CostSource::BestAvailable).unwrap();
    assert_eq!(r.status, BudgetStatus::Indeterminate);
    let alert = budget::over_budget_alert(&r, None)
        .expect("incomplete usage must surface, not silently read as under budget");
    assert_eq!(alert.dedup_key, "budget_incomplete:project:alert");
    assert!(
        alert.title.contains("cannot be evaluated"),
        "title was: {}",
        alert.title
    );
    assert!(
        !alert.title.contains("is over budget"),
        "must not fabricate an overrun from missing data: {}",
        alert.title
    );
    assert_eq!(alert.severity, api_tracker_core::alerts::Severity::Medium);
    assert_eq!(
        alert.confidence,
        api_tracker_core::providers::Confidence::Low
    );
    assert!(
        alert.evidence.contains("1 of 2 usage record(s)"),
        "evidence was: {}",
        alert.evidence
    );
}

#[test]
fn a_period_with_no_usage_at_all_does_not_alert() {
    let conn = mem();
    project_with_budget(&conn, "p-quiet", "quiet", 100_000_000);

    let r = budget::project_report(&conn, "p-quiet", usage::CostSource::BestAvailable).unwrap();
    // Nothing was observed, so nothing can be concluded — but a quiet
    // period is not a coverage gap and must not alert on every fresh
    // install that has set a budget.
    assert_eq!(r.status, BudgetStatus::Indeterminate);
    assert_eq!(r.usage_rows, 0);
    assert!(budget::over_budget_alert(&r, None).is_none());
}

#[test]
fn a_floor_above_the_budget_still_proves_an_overrun() {
    let conn = mem();
    project_with_budget(&conn, "p-over", "over", 5_000_000);
    record_for_project(&conn, "p-over", Some(9_000_000));
    record_for_project(&conn, "p-over", None); // uncosted, so partial

    let r = budget::project_report(&conn, "p-over", usage::CostSource::BestAvailable).unwrap();
    assert!(!r.used_is_complete);
    assert_eq!(
        r.status,
        BudgetStatus::Over,
        "more data could only raise the floor, so Over is sound"
    );
    let alert = budget::over_budget_alert(&r, None).unwrap();
    assert_eq!(alert.dedup_key, "over_budget:project:over");
    assert_eq!(alert.severity, api_tracker_core::alerts::Severity::High);
    assert!(
        alert.detail.contains("used at least $9.00"),
        "a lower bound must be labelled as one: {}",
        alert.detail
    );
}

#[test]
fn no_budget_configured_is_its_own_state() {
    let conn = mem();
    conn.execute(
        "INSERT INTO projects (id, name, created_at, updated_at, wrapped_project_key, \
         key_wrap_mode) VALUES ('p-none', 'none', ?1, ?1, x'00', 'vault')",
        [WINDOW_START],
    )
    .unwrap();
    record_for_project(&conn, "p-none", None);

    let r = budget::project_report(&conn, "p-none", usage::CostSource::BestAvailable).unwrap();
    assert_eq!(r.status, BudgetStatus::NoBudget);
    assert!(budget::over_budget_alert(&r, None).is_none());
}

// --- pricing completeness ---------------------------------------------

fn import(conn: &Connection, json: &str) {
    pricing::import_records(conn, json).unwrap();
}

#[test]
fn a_pricing_record_missing_the_output_price_yields_an_incomplete_estimate() {
    let conn = mem();
    import(
        &conn,
        r#"[{"provider":"fakeprov","model":"half-priced","unit":"tokens",
             "input_per_m":"1.000000","source":"test fixture",
             "effective_from":"2026-01-01","last_verified":"2026-07-01"}]"#,
    );

    let est = pricing::estimate_token_cost_as_of(
        &conn,
        "fakeprov",
        "half-priced",
        "2026-07-05",
        1_000_000,
        1_000_000,
    )
    .unwrap()
    .expect("the input price alone still produces a floor");

    // The old code returned exactly this number with nothing marking the
    // million unpriced output tokens, so it read downstream as the total.
    assert_eq!(est.micros, 1_000_000);
    assert!(!est.complete);
    assert_eq!(est.unpriced_dimensions, vec!["output tokens".to_string()]);
    assert_eq!(
        est.micros_if_complete(),
        None,
        "a floor must not be readable as a total"
    );
    let note = est.incompleteness_note().unwrap();
    assert!(note.contains("output tokens"), "note was: {note}");
    assert!(note.contains("floor, not a total"), "note was: {note}");
}

#[test]
fn a_fully_priced_record_yields_a_complete_estimate() {
    let conn = mem();
    import(
        &conn,
        r#"[{"provider":"fakeprov","model":"fully-priced","unit":"tokens",
             "input_per_m":"1.000000","output_per_m":"2.000000",
             "source":"test fixture","effective_from":"2026-01-01",
             "last_verified":"2026-07-01"}]"#,
    );

    let est = pricing::estimate_token_cost_as_of(
        &conn,
        "fakeprov",
        "fully-priced",
        "2026-07-05",
        1_000_000,
        1_000_000,
    )
    .unwrap()
    .unwrap();
    assert_eq!(est.micros, 3_000_000);
    assert!(est.complete);
    assert!(est.unpriced_dimensions.is_empty());
    assert_eq!(est.micros_if_complete(), Some(3_000_000));
    assert!(est.incompleteness_note().is_none());
}

#[test]
fn an_unpriced_dimension_with_no_usage_does_not_make_the_estimate_partial() {
    let conn = mem();
    import(
        &conn,
        r#"[{"provider":"fakeprov","model":"input-only","unit":"tokens",
             "input_per_m":"1.000000","source":"test fixture",
             "effective_from":"2026-01-01","last_verified":"2026-07-01"}]"#,
    );

    // No output tokens were used, so the missing output price costs nothing
    // and the estimate really is the whole amount.
    let est = pricing::estimate_token_cost_as_of(
        &conn,
        "fakeprov",
        "input-only",
        "2026-07-05",
        500_000,
        0,
    )
    .unwrap()
    .unwrap();
    assert_eq!(est.micros, 500_000);
    assert!(est.complete);
    assert_eq!(est.micros_if_complete(), Some(500_000));
}

#[test]
fn cost_estimation_is_unsupported_rather_than_zero_when_nothing_prices_it() {
    let conn = mem();
    // No pricing record at all.
    assert!(
        pricing::estimate_token_cost_as_of(&conn, "fakeprov", "unknown", "2026-07-05", 10, 10)
            .unwrap()
            .is_none(),
        "an unknown model must yield no estimate, never $0.00"
    );

    // A record that meters requests, not tokens.
    import(
        &conn,
        r#"[{"provider":"fakeprov","model":"per-call","unit":"requests",
             "per_request":"0.010000","source":"test fixture",
             "effective_from":"2026-01-01","last_verified":"2026-07-01"}]"#,
    );
    assert!(
        pricing::estimate_token_cost_as_of(&conn, "fakeprov", "per-call", "2026-07-05", 10, 10)
            .unwrap()
            .is_none(),
        "a request-metered model has no token price"
    );

    // Request pricing has a single dimension, and it is present.
    let est =
        pricing::estimate_request_cost_as_of(&conn, "fakeprov", "per-call", "2026-07-05", 100)
            .unwrap()
            .unwrap();
    assert_eq!(est.micros, 1_000_000);
    assert!(est.complete);
    assert_eq!(est.micros_if_complete(), Some(1_000_000));
}
