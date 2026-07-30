//! One filter, one population: every figure a project page shows together must
//! describe the same rows (`AUD-01`).
//!
//! # What went wrong
//!
//! `project::activity_only` threaded its `ActivityFilter` into
//! `projectactivity::project_series` and `projectactivity::recent_activity` and
//! into nothing else. `aggregate::project_metrics` and
//! `projectcost::project_cost_coverage` took no filter parameter at all, and
//! neither did `observed_integrations`. So with a filter active the page showed,
//! side by side:
//!
//! * a chart of the filtered population, and
//! * "Requests", "Input tokens", "Output tokens", "Error rate", "Average
//!   latency", "Estimated known cost", the whole cost-coverage box including its
//!   "% of token usage priced" sentence, and "Detected APIs" — all for the
//!   UNFILTERED window.
//!
//! Filtering to one model produced a dollar figure labelled "Estimated known
//! cost" that included every other model, and a coverage percentage computed
//! over traffic the user had filtered out. Nothing on screen said so.
//!
//! # How these tests are built
//!
//! Every fixture is deliberately asymmetric: the excluded rows carry different
//! token counts, different models with different prices, different statuses,
//! different latencies and different hosts, so a query that ignores the filter
//! CANNOT accidentally produce the filtered answer. `assert_consistent` then
//! checks all ten figures at once rather than spot-checking one, and
//! `assert_narrows` is the negative control: it fails if a filtered figure
//! equals its unfiltered counterpart.

mod common;

use api_tracker_core::projectactivity::ActivityFilter;
use api_tracker_core::runtime::model::*;
use api_tracker_core::runtime::store as rstore;
use api_tracker_tracking::project::{self, ProjectActivitySnapshot, TimeRange};
use common::*;
use rusqlite::{params, Connection};

// ---------------------------------------------------------------------------
// Fixture construction
// ---------------------------------------------------------------------------

/// One observation, with every dimension the filter can select on.
struct Obs<'a> {
    at: String,
    host: &'a str,
    /// The catalog provider recorded for the host, if any.
    provider: Option<&'a str>,
    status: u16,
    latency: i64,
    endpoint: &'a str,
    source: ObservationSource,
    credential: Option<&'a str>,
    /// The model on the usage row, and the tokens it reported. `None` model
    /// with `Some` tokens is the "known tokens, unpriceable" case.
    model: Option<&'a str>,
    usage_provider: &'a str,
    input: Option<i64>,
    output: Option<i64>,
    /// Emit no usage row at all — the "usage never reported" case.
    no_usage: bool,
}

impl<'a> Obs<'a> {
    fn new(at: &str, host: &'a str, provider: Option<&'a str>) -> Self {
        Self {
            at: at.to_string(),
            host,
            provider,
            status: 200,
            latency: 100,
            endpoint: "/v1/chat",
            source: ObservationSource::Gateway,
            credential: None,
            model: None,
            usage_provider: "openai",
            input: None,
            output: None,
            no_usage: true,
        }
    }
    fn status(mut self, s: u16) -> Self {
        self.status = s;
        self
    }
    fn latency(mut self, ms: i64) -> Self {
        self.latency = ms;
        self
    }
    fn endpoint(mut self, e: &'a str) -> Self {
        self.endpoint = e;
        self
    }
    fn source(mut self, s: ObservationSource) -> Self {
        self.source = s;
        self
    }
    fn credential(mut self, id: &'a str) -> Self {
        self.credential = Some(id);
        self
    }
    /// Attach a usage row with a model and token counts.
    fn usage(mut self, provider: &'a str, model: &'a str, input: i64, output: i64) -> Self {
        self.usage_provider = provider;
        self.model = Some(model);
        self.input = Some(input);
        self.output = Some(output);
        self.no_usage = false;
        self
    }
    /// A usage row that reported NO tokens: `requests_with_unknown_usage`.
    fn usage_without_tokens(mut self, provider: &'a str) -> Self {
        self.usage_provider = provider;
        self.model = None;
        self.input = None;
        self.output = None;
        self.no_usage = false;
        self
    }
}

/// Insert one observation and (optionally) its usage row.
fn record(conn: &Connection, project_id: &str, o: &Obs<'_>) -> String {
    let (service_id, _) = rstore::upsert_service(conn, o.host, o.provider, false, &o.at).unwrap();
    let session_id = rstore::insert_session(
        conn,
        &rstore::NewSession {
            project_id,
            mode: ObservationMode::Metadata,
            source: "gateway",
            command: "",
            credential_names: &[],
        },
    )
    .unwrap();
    let req = ObservedRequest {
        host: o.host.to_string(),
        port: 443,
        method: HttpMethod::Post,
        path_template: o.endpoint.to_string(),
        template_confidence: api_tracker_core::providers::Confidence::High,
        status_code: Some(o.status),
        req_content_kind: None,
        resp_content_kind: None,
        had_authorization: true,
        latency_ms: Some(o.latency),
        request_bytes: Some(100),
        response_bytes: Some(200),
        protocol: Protocol::Http11,
        observation_source: o.source,
        transport_error: TransportError::None,
    };
    let event_id = rstore::insert_request_event(
        conn,
        &session_id,
        project_id,
        &service_id,
        None,
        &o.at,
        &req,
        false,
    )
    .unwrap();
    if let Some(cred) = o.credential {
        conn.execute(
            "UPDATE runtime_request_events SET credential_id = ?2, attribution_confidence = 'exact'
             WHERE id = ?1",
            params![event_id, cred],
        )
        .unwrap();
    }
    if !o.no_usage {
        let available = i64::from(o.input.is_some() || o.output.is_some());
        conn.execute(
            "INSERT INTO gateway_usage_events
                (id, event_id, at, route_prefix, provider_id, project_id, model,
                 input_tokens, output_tokens, usage_available, usage_state)
             VALUES (?1, ?2, ?3, ?4, ?4, ?9, ?5, ?6, ?7, ?8, ?10)",
            params![
                uuid::Uuid::new_v4().to_string(),
                event_id,
                o.at,
                o.usage_provider,
                o.model,
                o.input,
                o.output,
                available,
                project_id,
                if available == 1 {
                    "extracted"
                } else {
                    "absent"
                },
            ],
        )
        .unwrap();
    }
    event_id
}

/// A credential row a `credential_id` filter can point at. The value column is
/// never touched — this exists so the foreign key resolves.
fn credential(conn: &Connection, project_id: &str, id: &str, name: &str) {
    conn.execute(
        "INSERT INTO credentials
            (id, project_id, provider, name, environment, credential_type, ciphertext,
             fingerprint, masked_value, created_at, updated_at)
         VALUES (?1, ?2, 'openai', ?3, 'development', 'api_key', X'00', X'00', 'sk-…FAKE',
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        params![id, project_id, name],
    )
    .unwrap();
}

/// Seconds ago, as RFC 3339, so every named `TimeRange` window contains it.
fn ago(secs: i64) -> String {
    api_tracker_core::clock::rfc3339_minus_seconds(&api_tracker_core::clock::now_rfc3339(), secs)
}

fn snapshot(conn: &Connection, filter: &ActivityFilter<'_>) -> ProjectActivitySnapshot {
    project::activity_only(conn, "p1", TimeRange::Last24Hours, filter, 50).unwrap()
}

fn snapshot_in(
    conn: &Connection,
    range: TimeRange,
    filter: &ActivityFilter<'_>,
) -> ProjectActivitySnapshot {
    project::activity_only(conn, "p1", range, filter, 50).unwrap()
}

// ---------------------------------------------------------------------------
// The ten figures, checked together
// ---------------------------------------------------------------------------

/// Every figure rendered on one screen, flattened so a test can compare them.
#[derive(Debug, PartialEq)]
struct Figures {
    request_total: i64,
    recent_rows: usize,
    series_requests: i64,
    series_input_tokens: i64,
    known_input_tokens: i64,
    known_output_tokens: i64,
    estimated_micros: i64,
    unpriced_requests: i64,
    unpriced_tokens: i64,
    requests_with_unknown_usage: i64,
    token_coverage: Option<String>,
    error_count: i64,
    series_errors: i64,
    latency_p50: Option<i64>,
    integration_hosts: Vec<String>,
    integration_requests: i64,
}

fn figures(s: &ProjectActivitySnapshot) -> Figures {
    let mut hosts: Vec<String> = s.integrations.iter().map(|i| i.host.clone()).collect();
    hosts.sort();
    Figures {
        request_total: s.metrics.total,
        recent_rows: s.recent.len(),
        series_requests: s.series.iter().map(|p| p.requests).sum(),
        series_input_tokens: s.series.iter().filter_map(|p| p.input_tokens).sum(),
        known_input_tokens: s.cost.known_input_tokens,
        known_output_tokens: s.cost.known_output_tokens,
        estimated_micros: s.cost.estimated_micros,
        unpriced_requests: s.cost.unpriced_requests,
        unpriced_tokens: s.cost.unpriced_tokens,
        requests_with_unknown_usage: s.cost.requests_with_unknown_usage,
        // Formatted, so a float comparison never decides a test.
        token_coverage: s.cost.token_coverage.map(|c| format!("{c:.6}")),
        error_count: s.metrics.errors,
        series_errors: s.series.iter().map(|p| p.errors).sum(),
        latency_p50: s.metrics.p50_ms,
        integration_hosts: hosts,
        integration_requests: s.integrations.iter().map(|i| i.requests).sum(),
    }
}

/// The consistency rule, stated once: the summary cards, the chart, the recent
/// table, the cost block and the integrations all describe the SAME rows.
///
/// `expected` is what the filtered population should be, computed by hand from
/// the fixture rather than from another query — a test that derived its
/// expectation from the code under test would pass whatever that code did.
#[track_caller]
fn assert_consistent(label: &str, s: &ProjectActivitySnapshot, expected: &Figures) {
    let got = figures(s);
    assert_eq!(&got, expected, "{label}: filtered figures disagree");

    // Cross-checks that must hold whatever the fixture is.
    assert_eq!(
        got.request_total, got.series_requests,
        "{label}: the Requests card and the chart must count the same rows"
    );
    assert_eq!(
        got.error_count, got.series_errors,
        "{label}: the error rate and the chart's errors must count the same rows"
    );
    assert_eq!(
        got.request_total, got.integration_requests,
        "{label}: Detected APIs must account for exactly the filtered requests"
    );
    assert_eq!(
        got.series_input_tokens, got.known_input_tokens,
        "{label}: the chart's tokens and the Input tokens card must agree"
    );
    // The coverage denominator is the filtered known-token total, so it can
    // never exceed it.
    let priced_and_unpriced = s.cost.priced_input_tokens
        + s.cost.priced_output_tokens
        + s.cost.unpriced_tokens
        + s.cost.requests_with_unknown_usage.min(0);
    assert!(
        priced_and_unpriced <= got.known_input_tokens + got.known_output_tokens,
        "{label}: coverage is computed over more tokens than the filter admits"
    );
}

/// The negative control. A filter that changes nothing is a filter that was
/// ignored, so every figure that CAN differ must differ.
#[track_caller]
fn assert_narrows(label: &str, all: &ProjectActivitySnapshot, filtered: &ProjectActivitySnapshot) {
    let (a, f) = (figures(all), figures(filtered));
    assert!(
        f.request_total < a.request_total,
        "{label}: request total did not narrow ({} vs {})",
        f.request_total,
        a.request_total
    );
    assert!(
        f.recent_rows < a.recent_rows,
        "{label}: recent rows did not narrow"
    );
    assert!(
        f.series_requests < a.series_requests,
        "{label}: the chart did not narrow"
    );
    assert!(
        f.known_input_tokens < a.known_input_tokens,
        "{label}: known input tokens did not narrow ({} vs {})",
        f.known_input_tokens,
        a.known_input_tokens
    );
    assert!(
        f.estimated_micros < a.estimated_micros,
        "{label}: estimated cost did not narrow ({} vs {})",
        f.estimated_micros,
        a.estimated_micros
    );
    assert!(
        f.integration_hosts.len() < a.integration_hosts.len()
            || f.integration_requests < a.integration_requests,
        "{label}: Detected APIs did not narrow"
    );
}

// ---------------------------------------------------------------------------
// The exact audit fixture
// ---------------------------------------------------------------------------

/// `AUD-01`, verbatim: two requests, one OpenAI and one other host, different
/// token and cost amounts. After filtering to OpenAI every result metric must
/// describe only the OpenAI observation.
///
/// This is the audit's own reproduction, kept as a permanent regression test.
/// Measured on the audited head: `metrics.total 2 → 2`, `known_input 5 000 000 →
/// 5 000 000`, `estimated_micros 14 500 000 → 14 500 000`, `integrations 2 → 2`,
/// while `series requests 2 → 1` and `recent rows 2 → 1`.
#[test]
fn aud_01_regression_a_host_filter_reaches_every_metric() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let at = ago(120);

    // openai: 1 request, 1_000_000 input tokens, priced (gpt-4o: $2.50/M in).
    record(
        &conn,
        "p1",
        &Obs::new(&at, "api.openai.com", Some("openai")).usage("openai", "gpt-4o", 1_000_000, 0),
    );
    // anthropic: 1 request, 4_000_000 input tokens, priced at a different rate.
    record(
        &conn,
        "p1",
        &Obs::new(&at, "api.anthropic.com", Some("anthropic")).usage(
            "anthropic",
            "claude-sonnet-4-5",
            4_000_000,
            0,
        ),
    );

    let all = snapshot(&conn, &ActivityFilter::default());
    let filtered = snapshot(
        &conn,
        &ActivityFilter {
            host: Some("api.openai.com"),
            ..Default::default()
        },
    );

    // The unfiltered totals the audit measured, so this test cannot pass by
    // the fixture having quietly changed.
    assert_eq!(all.metrics.total, 2);
    assert_eq!(all.cost.known_input_tokens, 5_000_000);
    assert_eq!(all.cost.estimated_micros, 14_500_000);
    assert_eq!(all.integrations.len(), 2);

    // Every one of the four figures the audit found unchanged.
    assert_eq!(
        filtered.metrics.total, 1,
        "AUD-01: the Requests card must count only the filtered population"
    );
    assert_eq!(
        filtered.cost.known_input_tokens, 1_000_000,
        "AUD-01: the Input tokens card must count only the filtered population"
    );
    assert_eq!(
        filtered.cost.estimated_micros, 2_500_000,
        "AUD-01: the Estimated known cost card must price only the filtered population"
    );
    assert_eq!(
        filtered.integrations.len(),
        1,
        "AUD-01: Detected APIs must list only the filtered population"
    );
    assert_eq!(filtered.integrations[0].host, "api.openai.com");

    // And the two that already worked, so the fix did not trade one for another.
    assert_eq!(filtered.series.iter().map(|p| p.requests).sum::<i64>(), 1);
    assert_eq!(filtered.recent.len(), 1);

    assert_narrows("aud-01 fixture", &all, &filtered);
}

// ---------------------------------------------------------------------------
// A fixture that differs on every dimension at once
// ---------------------------------------------------------------------------

/// Six observations, no two alike in any dimension the filter selects on.
///
/// Row 0 is the one every single-dimension filter below selects. Every other row
/// differs from it in host, provider, model, status, endpoint, source,
/// credential AND token count, so no filter can produce row 0's figures by
/// accident.
fn six_row_fixture(conn: &Connection) {
    insert_project(conn, "p1", "web");
    credential(conn, "p1", "cred-a", "openai-a");
    credential(conn, "p1", "cred-b", "openai-b");
    let now = ago(60);
    let older = ago(3 * 3_600); // outside the 1h window, inside 24h.

    // 0: the selected row. 1M input @ gpt-4o = 2_500_000 micros.
    record(
        conn,
        "p1",
        &Obs::new(&now, "api.openai.com", Some("openai"))
            .credential("cred-a")
            .endpoint("/v1/chat/completions")
            .latency(10)
            .usage("openai", "gpt-4o", 1_000_000, 0),
    );
    // 1: another host/provider/model, 4M input, a different price.
    record(
        conn,
        "p1",
        &Obs::new(&now, "api.anthropic.com", Some("anthropic"))
            .credential("cred-b")
            .endpoint("/v1/messages")
            .latency(1_000)
            .usage("anthropic", "claude-sonnet-4-5", 4_000_000, 0),
    );
    // 2: same host as row 0 but a 4xx, a different endpoint and model, and a
    //    different credential — so a status/endpoint/model/credential filter
    //    each excludes it while a host filter does not.
    record(
        conn,
        "p1",
        &Obs::new(&now, "api.openai.com", Some("openai"))
            .status(404)
            .credential("cred-b")
            .endpoint("/v1/embeddings")
            .latency(100)
            .usage("openai", "gpt-4o-mini", 2_000_000, 0),
    );
    // 3: observed by the intercept path rather than the gateway.
    record(
        conn,
        "p1",
        &Obs::new(&now, "api.example.com", None)
            .source(ObservationSource::Intercept)
            .endpoint("/v1/thing")
            .latency(500)
            .usage("mystery", "mystery-1", 500_000, 0),
    );
    // 4: known tokens, NO model — unpriced but counted.
    record(
        conn,
        "p1",
        &Obs::new(&now, "api.cohere.com", Some("cohere"))
            .endpoint("/v1/rerank")
            .latency(50)
            .usage_without_tokens("cohere"),
    );
    // 5: three hours ago, so the 1h window excludes it and the 24h window does
    //    not. Its own host and a PRICED model, so a time filter changes the
    //    integration list and the cost total, not just the request count.
    record(
        conn,
        "p1",
        &Obs::new(&older, "api.anthropic-eu.example", Some("anthropic"))
            .endpoint("/v1/old")
            .latency(25)
            .usage("anthropic", "claude-haiku-4-5", 3_000_000, 0),
    );
}

/// The figures row 0 alone produces. Computed by hand from the fixture.
fn row_zero_figures() -> Figures {
    Figures {
        request_total: 1,
        recent_rows: 1,
        series_requests: 1,
        series_input_tokens: 1_000_000,
        known_input_tokens: 1_000_000,
        known_output_tokens: 0,
        // gpt-4o: 2.50 per million input tokens => 2_500_000 micros.
        estimated_micros: 2_500_000,
        unpriced_requests: 0,
        unpriced_tokens: 0,
        requests_with_unknown_usage: 0,
        token_coverage: Some("1.000000".to_string()),
        error_count: 0,
        series_errors: 0,
        latency_p50: Some(10),
        integration_hosts: vec!["api.openai.com".to_string()],
        integration_requests: 1,
    }
}

/// Each filter dimension, one at a time, selecting exactly row 0.
///
/// Eight dimensions, eight assertions over ten figures each. A query that
/// ignored the filter would report six requests, 10.5M tokens and six hosts.
#[test]
fn every_filter_dimension_narrows_every_figure() {
    let (_tmp, conn) = test_conn();
    six_row_fixture(&conn);

    let all = snapshot(&conn, &ActivityFilter::default());
    assert_eq!(all.metrics.total, 6, "the fixture must have six rows");
    assert_eq!(
        all.integrations.len(),
        5,
        "and five distinct hosts across them"
    );

    let expected = row_zero_figures();
    let cases: Vec<(&str, ActivityFilter<'_>)> = vec![
        (
            "host",
            ActivityFilter {
                host: Some("api.openai.com"),
                status_class: Some("2xx"),
                ..Default::default()
            },
        ),
        (
            "provider",
            ActivityFilter {
                provider: Some("openai"),
                status_class: Some("2xx"),
                ..Default::default()
            },
        ),
        (
            "credential",
            ActivityFilter {
                credential_id: Some("cred-a"),
                ..Default::default()
            },
        ),
        (
            "model",
            ActivityFilter {
                model: Some("gpt-4o"),
                ..Default::default()
            },
        ),
        (
            "endpoint",
            ActivityFilter {
                endpoint: Some("/v1/chat/completions"),
                ..Default::default()
            },
        ),
        (
            // Two filters at once, which also proves the placeholder numbering
            // advances past the window parameters.
            "host + credential",
            ActivityFilter {
                host: Some("api.openai.com"),
                credential_id: Some("cred-a"),
                ..Default::default()
            },
        ),
        (
            "host + model + status + endpoint + source + provider + credential",
            ActivityFilter {
                host: Some("api.openai.com"),
                provider: Some("openai"),
                credential_id: Some("cred-a"),
                status_class: Some("2xx"),
                endpoint: Some("/v1/chat/completions"),
                observation_source: Some("gateway"),
                model: Some("gpt-4o"),
            },
        ),
    ];

    for (label, filter) in cases {
        let s = snapshot(&conn, &filter);
        assert_consistent(label, &s, &expected);
        assert_narrows(label, &all, &s);
    }
}

/// Status class and observation source select rows other than row 0, so they
/// get their own expectations.
#[test]
fn status_class_and_observation_source_narrow_every_figure() {
    let (_tmp, conn) = test_conn();
    six_row_fixture(&conn);
    let all = snapshot(&conn, &ActivityFilter::default());

    // Row 2 alone: a 4xx, 2M input tokens on text-embedding-3-small
    // ($0.02/M => 40_000 micros).
    let by_status = snapshot(
        &conn,
        &ActivityFilter {
            status_class: Some("4xx"),
            ..Default::default()
        },
    );
    assert_consistent(
        "status_class=4xx",
        &by_status,
        &Figures {
            request_total: 1,
            recent_rows: 1,
            series_requests: 1,
            series_input_tokens: 2_000_000,
            known_input_tokens: 2_000_000,
            known_output_tokens: 0,
            estimated_micros: 300_000,
            unpriced_requests: 0,
            unpriced_tokens: 0,
            requests_with_unknown_usage: 0,
            token_coverage: Some("1.000000".to_string()),
            error_count: 1,
            series_errors: 1,
            latency_p50: Some(100),
            integration_hosts: vec!["api.openai.com".to_string()],
            integration_requests: 1,
        },
    );
    assert!(
        by_status.metrics.errors == 1 && all.metrics.errors == 1,
        "the fixture has exactly one error, and the filter kept it"
    );

    // Row 3 alone: intercept-observed, unknown provider, so its tokens are
    // known but unpriceable.
    let by_source = snapshot(
        &conn,
        &ActivityFilter {
            observation_source: Some("intercept"),
            ..Default::default()
        },
    );
    assert_consistent(
        "observation_source=intercept",
        &by_source,
        &Figures {
            request_total: 1,
            recent_rows: 1,
            series_requests: 1,
            series_input_tokens: 500_000,
            known_input_tokens: 500_000,
            known_output_tokens: 0,
            estimated_micros: 0,
            unpriced_requests: 1,
            unpriced_tokens: 500_000,
            requests_with_unknown_usage: 0,
            // Nothing priced: the ratio is a measured zero, not "unknown".
            token_coverage: Some("0.000000".to_string()),
            error_count: 0,
            series_errors: 0,
            latency_p50: Some(500),
            integration_hosts: vec!["api.example.com".to_string()],
            integration_requests: 1,
        },
    );
    assert_narrows("observation_source", &all, &by_source);
}

/// The time range is part of the same scope, and every figure moves with it.
#[test]
fn the_time_range_narrows_every_figure_too() {
    let (_tmp, conn) = test_conn();
    six_row_fixture(&conn);

    let day = snapshot_in(&conn, TimeRange::Last24Hours, &ActivityFilter::default());
    let hour = snapshot_in(&conn, TimeRange::LastHour, &ActivityFilter::default());

    assert_eq!(day.metrics.total, 6);
    assert_eq!(hour.metrics.total, 5, "the three-hour-old row drops out");
    assert_eq!(day.integrations.len(), 5);
    assert_eq!(hour.integrations.len(), 4);
    assert!(!hour
        .integrations
        .iter()
        .any(|i| i.host == "api.anthropic-eu.example"));

    // Its 3M tokens and its cost leave with it.
    assert_eq!(day.cost.known_input_tokens, 10_500_000);
    assert_eq!(hour.cost.known_input_tokens, 7_500_000);
    assert!(hour.cost.estimated_micros < day.cost.estimated_micros);
    assert_eq!(
        hour.metrics.total,
        hour.series.iter().map(|p| p.requests).sum::<i64>(),
        "cards and chart share the window as well as the filter"
    );
    assert_eq!(
        hour.metrics.total,
        hour.integrations.iter().map(|i| i.requests).sum::<i64>()
    );
}

// ---------------------------------------------------------------------------
// Cost honesty under a filter
// ---------------------------------------------------------------------------

/// Filtered cost keeps every distinction the unfiltered call keeps: priced,
/// known-but-unpriced, never-reported, partial coverage — and the coverage
/// denominator is the FILTERED known-token total.
#[test]
fn filtered_cost_preserves_every_coverage_distinction() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let at = ago(120);

    // In scope (host = api.openai.com), three rows:
    //   priced:      1M input on gpt-4o          -> 2_500_000 micros
    //   unpriceable: 1M input on a model with no pricing record
    //   unknown:     a usage row that reported no tokens at all
    record(
        &conn,
        "p1",
        &Obs::new(&at, "api.openai.com", Some("openai")).usage("openai", "gpt-4o", 1_000_000, 0),
    );
    record(
        &conn,
        "p1",
        &Obs::new(&at, "api.openai.com", Some("openai")).usage(
            "openai",
            "gpt-not-a-real-priced-model",
            1_000_000,
            0,
        ),
    );
    record(
        &conn,
        "p1",
        &Obs::new(&at, "api.openai.com", Some("openai")).usage_without_tokens("openai"),
    );
    // Out of scope: a huge, fully priced Anthropic row that would swamp every
    // figure above if the filter did not reach the cost query.
    record(
        &conn,
        "p1",
        &Obs::new(&at, "api.anthropic.com", Some("anthropic")).usage(
            "anthropic",
            "claude-sonnet-4-5",
            40_000_000,
            0,
        ),
    );

    let all = snapshot(&conn, &ActivityFilter::default());
    let openai = snapshot(
        &conn,
        &ActivityFilter {
            host: Some("api.openai.com"),
            ..Default::default()
        },
    );

    // Unfiltered: the Anthropic row dominates.
    assert_eq!(all.cost.known_input_tokens, 42_000_000);

    let c = &openai.cost;
    assert_eq!(c.known_input_tokens, 2_000_000, "only the in-scope tokens");
    assert_eq!(c.estimated_micros, 2_500_000, "only the in-scope estimate");
    assert_eq!(c.priced_requests, 1);
    assert_eq!(c.unpriced_requests, 1, "the model with no pricing record");
    assert_eq!(c.unpriced_tokens, 1_000_000);
    assert_eq!(
        c.requests_with_unknown_usage, 1,
        "a request that reported no tokens is counted, never zeroed"
    );
    assert!(!c.complete, "a floor is not a total");
    assert_eq!(
        c.micros_if_complete(),
        None,
        "an incomplete filtered total must still refuse to stand as a total"
    );
    // The denominator is the FILTERED known tokens: 1M priced of 2M known.
    let coverage = c
        .token_coverage
        .expect("tokens are known, so there is a ratio");
    assert!(
        (coverage - 0.5).abs() < 1e-9,
        "coverage must use the filtered denominator, got {coverage}"
    );
    assert!(
        c.unpriced
            .iter()
            .any(|u| u.reason == api_tracker_core::projectcost::UnpricedReason::UsageNotExtracted),
        "the never-reported case survives filtering"
    );
    assert!(
        c.unpriced
            .iter()
            .any(|u| u.model.as_deref() == Some("gpt-not-a-real-priced-model")),
        "the unpriced model is still named"
    );
    assert!(
        !c.unpriced
            .iter()
            .any(|u| u.provider == "anthropic" || u.model.as_deref() == Some("claude-sonnet-4-5")),
        "an excluded observation must not appear in the coverage detail"
    );
    assert!(
        !c.priced.iter().any(|p| p.provider == "anthropic"),
        "an excluded observation must not appear in the priced detail"
    );
}

/// A known ZERO stays a measured zero under a filter, and is never turned into
/// "unknown".
#[test]
fn a_filtered_known_zero_is_still_a_measured_zero() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let at = ago(120);
    // A priced model with zero tokens reported: known, priced, and free.
    record(
        &conn,
        "p1",
        &Obs::new(&at, "api.openai.com", Some("openai")).usage("openai", "gpt-4o", 0, 0),
    );
    record(
        &conn,
        "p1",
        &Obs::new(&at, "api.anthropic.com", Some("anthropic")).usage(
            "anthropic",
            "claude-sonnet-4-5",
            9_000_000,
            0,
        ),
    );

    let openai = snapshot(
        &conn,
        &ActivityFilter {
            host: Some("api.openai.com"),
            ..Default::default()
        },
    );
    assert_eq!(openai.cost.known_input_tokens, 0);
    assert_eq!(openai.cost.estimated_micros, 0);
    assert_eq!(openai.cost.priced_requests, 1);
    assert_eq!(
        openai.cost.requests_with_unknown_usage, 0,
        "zero reported tokens is REPORTED, not missing"
    );
    assert!(
        openai.cost.complete,
        "everything in scope was priced, so the total stands as a total"
    );
    assert_eq!(openai.cost.micros_if_complete(), Some(0));
    assert_eq!(
        openai.cost.token_coverage, None,
        "no tokens known at all: there is no ratio to state, and 0.0 would read \
         as 'nothing was priced'"
    );
}

/// A filter that matches nothing yields nothing — everywhere, not just in the
/// chart.
#[test]
fn a_filter_that_matches_nothing_empties_every_figure() {
    let (_tmp, conn) = test_conn();
    six_row_fixture(&conn);
    let none = snapshot(
        &conn,
        &ActivityFilter {
            host: Some("nope.example"),
            ..Default::default()
        },
    );
    assert_eq!(none.metrics.total, 0);
    assert!(none.series.is_empty());
    assert!(none.recent.is_empty());
    assert!(none.integrations.is_empty());
    assert_eq!(none.cost.known_input_tokens, 0);
    assert_eq!(none.cost.estimated_micros, 0);
    assert!(none.cost.is_empty());
    assert!(
        none.no_observations,
        "a surface must be able to say 'nothing matches' rather than render zeroes"
    );
}

// ---------------------------------------------------------------------------
// Facets
// ---------------------------------------------------------------------------

/// Facets stay broad on purpose: they populate the controls, so narrowing them
/// by the current selection would make those controls one-way.
///
/// The integrations summary is the opposite and must match the result set. Both
/// halves are asserted here so the intent cannot be "fixed" in either direction
/// by accident.
#[test]
fn facets_stay_broad_while_the_integrations_summary_narrows() {
    let (_tmp, conn) = test_conn();
    six_row_fixture(&conn);

    let filtered = snapshot(
        &conn,
        &ActivityFilter {
            host: Some("api.openai.com"),
            ..Default::default()
        },
    );

    // The picker still offers every host in the window, so the user can change
    // their mind without clearing the filter first.
    assert_eq!(
        filtered.facets.hosts.len(),
        5,
        "facets must still offer every host in the window, got {:?}",
        filtered.facets.hosts
    );
    assert!(filtered
        .facets
        .hosts
        .contains(&"api.anthropic.com".to_string()));
    assert!(filtered
        .facets
        .models
        .contains(&"claude-sonnet-4-5".to_string()));
    assert!(filtered.facets.status_classes.contains(&"4xx".to_string()));
    assert!(filtered
        .facets
        .observation_sources
        .contains(&"intercept".to_string()));

    // The RESULT summary describes the filtered rows only.
    assert_eq!(
        filtered.integrations.len(),
        1,
        "two matching rows, one host: {:?}",
        filtered
            .integrations
            .iter()
            .map(|i| &i.host)
            .collect::<Vec<_>>()
    );
    assert_eq!(filtered.integrations[0].host, "api.openai.com");
    assert_eq!(
        filtered.integrations[0].requests, 2,
        "both openai rows, and only those"
    );

    // Facets remain bounded by the time window, which is the one scope they do
    // share with everything else.
    let hour = snapshot_in(&conn, TimeRange::LastHour, &ActivityFilter::default());
    assert!(
        !hour
            .facets
            .hosts
            .contains(&"api.anthropic-eu.example".to_string()),
        "a facet must not offer a value from outside the selected window"
    );
}

// ---------------------------------------------------------------------------
// Scope integrity
// ---------------------------------------------------------------------------

/// Another project's traffic is never in scope, filtered or not.
#[test]
fn another_projects_traffic_is_excluded_under_every_filter() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    insert_project(&conn, "p2", "other");
    let at = ago(120);

    record(
        &conn,
        "p1",
        &Obs::new(&at, "api.openai.com", Some("openai")).usage("openai", "gpt-4o", 1_000_000, 0),
    );
    // The same host, the same model, a much larger amount — on another project.
    record(
        &conn,
        "p2",
        &Obs::new(&at, "api.openai.com", Some("openai")).usage("openai", "gpt-4o", 90_000_000, 0),
    );

    for filter in [
        ActivityFilter::default(),
        ActivityFilter {
            host: Some("api.openai.com"),
            ..Default::default()
        },
        ActivityFilter {
            model: Some("gpt-4o"),
            ..Default::default()
        },
    ] {
        let s = snapshot(&conn, &filter);
        assert_eq!(s.metrics.total, 1);
        assert_eq!(s.cost.known_input_tokens, 1_000_000);
        assert_eq!(s.cost.estimated_micros, 2_500_000);
        assert_eq!(s.integrations.iter().map(|i| i.requests).sum::<i64>(), 1);
    }
}

/// Usage whose event row retention has already pruned still counts when there
/// is NO filter, and cannot be claimed by one when there is.
///
/// This is the documented asymmetry in `ActivityFilter::usage_scope`, asserted
/// so it stays a decision rather than an accident.
#[test]
fn orphaned_usage_counts_unfiltered_and_cannot_satisfy_a_filter() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let at = ago(120);
    let event = record(
        &conn,
        "p1",
        &Obs::new(&at, "api.openai.com", Some("openai")).usage("openai", "gpt-4o", 1_000_000, 0),
    );
    // Retention removes the event; the usage row survives it.
    conn.execute(
        "DELETE FROM runtime_request_events WHERE id = ?1",
        params![event],
    )
    .unwrap();

    let all = snapshot(&conn, &ActivityFilter::default());
    assert_eq!(
        all.cost.known_input_tokens, 1_000_000,
        "unfiltered totals still count usage whose event was pruned"
    );

    let filtered = snapshot(
        &conn,
        &ActivityFilter {
            host: Some("api.openai.com"),
            ..Default::default()
        },
    );
    assert_eq!(
        filtered.cost.known_input_tokens, 0,
        "a row with no event left cannot be said to satisfy a host filter"
    );
    assert_eq!(filtered.metrics.total, 0);
}
