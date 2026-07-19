//! OBS-003 regression: malformed Anthropic report buckets must never delete
//! previously stored usage history. The replace-range DELETE derives its
//! bounds from provider-controlled window strings; a missing/empty
//! `starting_at` sorts below every real timestamp and, at baseline
//! `7d81090`, wiped the provider's entire synced history. Invalid buckets
//! (missing, blank, malformed, or inverted ranges) must be skipped — with a
//! note — before any deletion happens, while valid buckets in the same
//! response still sync.

mod common;

use api_tracker_core::http::{HttpResponse, MockHttpClient};
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::UnlockedVault;
use common::new_vault;

const FAKE_ADMIN: &str = "sk-ant-admin01-FAKE-NOT-A-REAL-KEY-0000000001";

fn resp(body: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
    }
}

/// One usage bucket with the given time-range fields (verbatim JSON
/// fragments, e.g. `"\"2026-07-12T00:00:00Z\""` or omitted via `None`).
fn usage_page_with_range(starting_at: Option<&str>, ending_at: Option<&str>) -> HttpResponse {
    let mut fields = Vec::new();
    if let Some(s) = starting_at {
        fields.push(format!("\"starting_at\":{s}"));
    }
    if let Some(e) = ending_at {
        fields.push(format!("\"ending_at\":{e}"));
    }
    fields.push(
        r#""results":[{"api_key_id":"apikey_x","workspace_id":"wrkspc_1",
            "model":"claude-sonnet-4-5","uncached_input_tokens":7,
            "cache_read_input_tokens":0,"output_tokens":3}]"#
            .to_string(),
    );
    resp(&format!(
        r#"{{"data":[{{{}}}],"has_more":false}}"#,
        fields.join(",")
    ))
}

fn empty_costs() -> HttpResponse {
    resp(r#"{"data":[],"has_more":false}"#)
}

fn empty_list() -> HttpResponse {
    resp(r#"{"data":[],"first_id":null,"last_id":null,"has_more":false}"#)
}

fn valid_seed_mocks() -> MockHttpClient {
    MockHttpClient::new(vec![
        usage_page_with_range(
            Some("\"2026-07-10T00:00:00Z\""),
            Some("\"2026-07-11T00:00:00Z\""),
        ),
        resp(
            r#"{"data":[{"starting_at":"2026-07-10T00:00:00Z","ending_at":"2026-07-11T00:00:00Z",
            "results":[{"amount":"250.00","currency":"USD","description":"Claude usage",
                        "workspace_id":"wrkspc_1","cost_type":"tokens"}]}],"has_more":false}"#,
        ),
        empty_list(),
        empty_list(),
    ])
}

fn window(day_from: u8, day_to: u8) -> (time::OffsetDateTime, time::OffsetDateTime) {
    let d = |day| {
        time::OffsetDateTime::new_utc(
            time::Date::from_calendar_date(2026, time::Month::July, day).unwrap(),
            time::Time::MIDNIGHT,
        )
    };
    (d(day_from), d(day_to))
}

fn seeded_vault() -> (tempfile::TempDir, UnlockedVault) {
    let (dir, _paths, v) = new_vault();
    v.provider_admin_connect("anthropic", &SecretString::from(FAKE_ADMIN), None, None)
        .unwrap();
    let (from, to) = window(10, 11);
    let report = v
        .usage_sync_range("anthropic", &valid_seed_mocks(), from, to)
        .unwrap();
    assert_eq!(report.usage_rows, 1, "seed usage row stored");
    assert_eq!(report.cost_rows, 1, "seed cost row stored");
    (dir, v)
}

fn history_counts(v: &UnlockedVault) -> (i64, i64) {
    let usage: i64 = v
        .connection()
        .query_row(
            "SELECT count(*) FROM usage_snapshots
             WHERE provider='anthropic' AND source='anthropic_usage_api'
             AND window_start='2026-07-10T00:00:00Z'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let costs: i64 = v
        .connection()
        .query_row(
            "SELECT count(*) FROM usage_snapshots
             WHERE provider='anthropic' AND source='anthropic_costs_api'
             AND window_start='2026-07-10T00:00:00Z'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    (usage, costs)
}

/// Run a later sync whose usage page is `page`, with empty costs/metadata,
/// and assert the seeded 2026-07-10 history survives untouched.
fn assert_history_survives(case: &str, page: HttpResponse, expect_recorded: usize) {
    let (_dir, v) = seeded_vault();
    assert_eq!(history_counts(&v), (1, 1), "seed present before {case}");
    let mocks = MockHttpClient::new(vec![page, empty_costs(), empty_list(), empty_list()]);
    let (from, to) = window(12, 13);
    let report = v
        .usage_sync_range("anthropic", &mocks, from, to)
        .unwrap_or_else(|e| panic!("sync with {case} must skip safely, not fail the sync: {e:?}"));
    assert_eq!(
        report.usage_rows, expect_recorded,
        "{case}: only valid buckets are recorded"
    );
    if expect_recorded == 0 {
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("invalid time range")),
            "{case}: skipping must be reported honestly, notes: {:?}",
            report.notes
        );
    }
    let (usage, costs) = history_counts(&v);
    assert_eq!(
        (usage, costs),
        (1, 1),
        "OBS-003 regression ({case}): previously stored usage history was deleted \
         by a sync carrying an invalid provider time range"
    );
}

#[test]
fn empty_starting_at_does_not_wipe_history() {
    // The killer shape from the audit: empty start + real end makes the
    // replace range [\"\", end) — i.e. all history before `end`.
    assert_history_survives(
        "empty starting_at",
        usage_page_with_range(Some("\"\""), Some("\"2026-07-13T00:00:00Z\"")),
        0,
    );
}

#[test]
fn missing_starting_at_does_not_wipe_history() {
    assert_history_survives(
        "missing starting_at",
        usage_page_with_range(None, Some("\"2026-07-13T00:00:00Z\"")),
        0,
    );
}

#[test]
fn empty_or_missing_ending_at_is_skipped() {
    assert_history_survives(
        "empty ending_at",
        usage_page_with_range(Some("\"2026-07-12T00:00:00Z\""), Some("\"\"")),
        0,
    );
    assert_history_survives(
        "missing ending_at",
        usage_page_with_range(Some("\"2026-07-12T00:00:00Z\""), None),
        0,
    );
}

#[test]
fn malformed_timestamps_are_skipped() {
    assert_history_survives(
        "malformed starting_at",
        usage_page_with_range(
            Some("\"not-a-timestamp\""),
            Some("\"2026-07-13T00:00:00Z\""),
        ),
        0,
    );
    assert_history_survives(
        "malformed ending_at",
        usage_page_with_range(Some("\"2026-07-12T00:00:00Z\""), Some("\"07/13/2026\"")),
        0,
    );
}

#[test]
fn inverted_range_is_skipped() {
    assert_history_survives(
        "end before start",
        usage_page_with_range(
            Some("\"2026-07-13T00:00:00Z\""),
            Some("\"2026-07-12T00:00:00Z\""),
        ),
        0,
    );
}

#[test]
fn mixed_valid_and_invalid_buckets_record_only_the_valid_one() {
    let page = resp(
        r#"{"data":[
            {"starting_at":"","ending_at":"2026-07-13T00:00:00Z",
             "results":[{"api_key_id":"apikey_bad","workspace_id":"wrkspc_1",
                         "model":"claude-sonnet-4-5","uncached_input_tokens":1,
                         "cache_read_input_tokens":0,"output_tokens":1}]},
            {"starting_at":"2026-07-12T00:00:00Z","ending_at":"2026-07-13T00:00:00Z",
             "results":[{"api_key_id":"apikey_ok","workspace_id":"wrkspc_1",
                         "model":"claude-sonnet-4-5","uncached_input_tokens":9,
                         "cache_read_input_tokens":0,"output_tokens":4}]}
        ],"has_more":false}"#,
    );
    let (_dir, v) = seeded_vault();
    let mocks = MockHttpClient::new(vec![page, empty_costs(), empty_list(), empty_list()]);
    let (from, to) = window(12, 13);
    let report = v.usage_sync_range("anthropic", &mocks, from, to).unwrap();
    assert_eq!(report.usage_rows, 1, "the valid bucket is recorded");
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("invalid time range")),
        "the skipped bucket is reported, notes: {:?}",
        report.notes
    );
    // Seed history intact; the valid new bucket present.
    assert_eq!(
        history_counts(&v),
        (1, 1),
        "OBS-003 regression (mixed buckets): the invalid bucket's empty start \
         widened the replace range and deleted stored history"
    );
    let new_row: i64 = v
        .connection()
        .query_row(
            "SELECT count(*) FROM usage_snapshots
             WHERE provider='anthropic' AND provider_api_key_id='apikey_ok'
             AND window_start='2026-07-12T00:00:00Z'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(new_row, 1);
}

#[test]
fn invalid_cost_bucket_does_not_wipe_cost_history() {
    let (_dir, v) = seeded_vault();
    let cost_page = resp(
        r#"{"data":[{"starting_at":"","ending_at":"2026-07-13T00:00:00Z",
        "results":[{"amount":"100.00","currency":"USD","description":"Claude usage",
                    "workspace_id":"wrkspc_1","cost_type":"tokens"}]}],"has_more":false}"#,
    );
    let mocks = MockHttpClient::new(vec![
        usage_page_with_range(
            Some("\"2026-07-12T00:00:00Z\""),
            Some("\"2026-07-13T00:00:00Z\""),
        ),
        cost_page,
        empty_list(),
        empty_list(),
    ]);
    let (from, to) = window(12, 13);
    let report = v.usage_sync_range("anthropic", &mocks, from, to).unwrap();
    assert_eq!(
        report.cost_rows, 0,
        "the invalid cost bucket is not recorded"
    );
    assert_eq!(
        history_counts(&v),
        (1, 1),
        "OBS-003 regression (cost path): stored cost history was deleted by an \
         invalid provider time range"
    );
}
