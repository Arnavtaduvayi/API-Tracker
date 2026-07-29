//! `ZFT-006` literal regression: **a failed re-run must never report verified.**
//!
//! # The original defect
//!
//! v15 promoted a setup back to `traffic_observed` as soon as it found *any*
//! traffic, and nulled `attention_reason` while doing it. A developer whose
//! repair attempt had just failed was shown "tracking verified and active",
//! with no record of why it had failed, because the promotion was decided
//! from traffic that pre-dated the failure.
//!
//! # Why this file exists separately
//!
//! The fix has always been present and correct. What was missing was anything
//! that would notice if it stopped being: the independent re-audit
//! reintroduced the failure-drop and **every test in the crate still passed**
//! (`VER-02`). The clause was guarded by a second, unreachable copy of the
//! same question, and an unreachable guard is indistinguishable from a broken
//! one.
//!
//! So these tests are written against **observable product behaviour** — what
//! `track status` would show a user — rather than against the shape of the
//! code, and each one is paired with a note naming the mutation it kills.
//! `crates/tracking/tests/verification_concurrency.rs` covers the same
//! outcome reached through a race instead of through the clock.

mod common;

use api_tracker_core::clock;
use api_tracker_tracking::state::{
    self, CurrentHealth, GatewayLiveness, PlanSummary, TrackingSetup, TrackingState,
};
use common::*;
use rusqlite::Connection;
use std::path::Path;

const FAILURE: &str = "apply_failed:StartService";

fn summary() -> PlanSummary {
    PlanSummary {
        providers: vec!["openai".into()],
        links: vec!["openai".into()],
        port: 49152,
        ..Default::default()
    }
}

fn wire(conn: &Connection) {
    conn.execute(
        "INSERT OR REPLACE INTO gateway_routes
             (route_prefix, provider_id, enabled, created_at, updated_at)
         VALUES ('openai','openai',1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO gateway_project_links
             (link_slug, project_id, route_prefix, created_at)
         VALUES ('slug-openai','p1','openai','2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
}

fn ago(secs: i64) -> String {
    clock::rfc3339_minus_seconds(&clock::now_rfc3339(), secs)
}

/// Backdate the apply watermark so an observation recorded "a minute ago" is
/// still inside this session. Production reaches this state simply by the
/// passage of time; the test cannot wait, so it moves the watermark instead.
fn backdate_apply(conn: &Connection, id: &str, secs: i64) {
    conn.execute(
        "UPDATE tracking_setups SET applied_at = ?2 WHERE id = ?1",
        rusqlite::params![id, ago(secs)],
    )
    .unwrap();
}

/// Step 1 of the story: a project that is genuinely verified by current
/// traffic. Returns the setup as the product would then render it.
fn verified_project(conn: &Connection) -> TrackingSetup {
    insert_project(conn, "p1", "one");
    wire(conn);
    let s = state::upsert_setup(
        conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(conn, &s.id, &summary()).unwrap();
    backdate_apply(conn, &s.id, 3600);
    insert_gateway_event(conn, "p1", "api.openai.com", &ago(1800));

    let mut setup = state::get_setup(conn, &s.id).unwrap().unwrap();
    let report = state::refresh_with(conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(
        report.current,
        CurrentHealth::VerifiedAndActive,
        "precondition: the project must really be verified before the re-run"
    );
    assert!(
        report.history.first_verified_at.is_some(),
        "precondition: a first-verified watermark must have been recorded"
    );
    state::get_setup(conn, &s.id).unwrap().unwrap()
}

/// Steps 2-3: a repair attempt opens a new session, produces traffic, and
/// then fails. The traffic pre-dates the failure — which is the whole point,
/// and exactly the ordering v15 got wrong.
fn failed_repair(conn: &Connection, verified: &TrackingSetup) -> TrackingSetup {
    let reopened = state::upsert_setup(
        conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::Applying,
        "{}",
    )
    .unwrap();
    assert_eq!(reopened.id, verified.id, "same (project, folder) row");
    state::record_applied(conn, &reopened.id, &summary()).unwrap();
    backdate_apply(conn, &reopened.id, 600);

    // Traffic recorded during this attempt, BEFORE it failed.
    insert_gateway_event(conn, "p1", "api.openai.com", &ago(120));

    let current = state::get_setup(conn, &reopened.id).unwrap().unwrap();
    state::transition(conn, &current, TrackingState::NeedsAttention, Some(FAILURE)).unwrap();
    state::get_setup(conn, &reopened.id).unwrap().unwrap()
}

// ---------------------------------------------------------------------------

/// The whole `ZFT-006` story, asserted on what the user is shown.
///
/// **Kills:** forcing `failure_is_newer` to `false` in `refresh_with` (the
/// literal v15 clause — promote on any traffic), and dropping the preserved
/// reason in `write_derived`. Under either mutation the refresh promotes this
/// row to `traffic_observed` with a NULL reason and the assertions below fail.
#[test]
fn a_failed_re_run_is_never_reported_as_verified() {
    let (_d, conn) = test_conn();
    let verified = verified_project(&conn);
    let mut after_failure = failed_repair(&conn, &verified);

    let events: i64 = conn
        .query_row("SELECT COUNT(*) FROM runtime_request_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        events, 2,
        "historical traffic must remain in the database — the fix is not to delete evidence"
    );

    let report = state::refresh_with(&conn, &mut after_failure, GatewayLiveness::Verified).unwrap();

    // 5. Current status is the failure, not a success.
    assert!(
        matches!(report.current, CurrentHealth::NeedsAttention { .. }),
        "a failed re-run must not be reported as verified: {:?}",
        report.current
    );
    assert_ne!(report.current, CurrentHealth::VerifiedAndActive);

    // 7. And the reason is still there to act on.
    let row = state::get_setup(&conn, &after_failure.id).unwrap().unwrap();
    assert_eq!(
        row.attention_reason.as_deref(),
        Some(FAILURE),
        "the current failure reason must be preserved"
    );
    assert_eq!(row.state, TrackingState::NeedsAttention);

    // 6. Historical verification is still visible, separately.
    assert!(
        report.history.first_verified_at.is_some(),
        "history must survive: the project WAS verified once, and saying so is not \
         the same as claiming it is verified now"
    );
    // This session DID see traffic — and still is not healthy. That pairing
    // is the sharpest form of the claim: "some traffic was seen" is not
    // "tracking is working now", and v15 conflated exactly those two.
    assert!(
        report.history.session_first_observed_at.is_some(),
        "the session's own traffic watermark is recorded and shown as history"
    );
    assert!(
        report
            .freshness
            .iter()
            .any(|f| f.last_observed_at.is_some()),
        "the per-provider evidence is still surfaced, not hidden, while failed"
    );
}

/// Reading the row repeatedly must not wear the failure down. The v15 shape
/// nulled the reason on the first read, so the second read saw a clean,
/// verified row and had nothing left to report.
#[test]
fn repeated_reads_do_not_wear_the_failure_away() {
    let (_d, conn) = test_conn();
    let verified = verified_project(&conn);
    let mut setup = failed_repair(&conn, &verified);

    for pass in 1..=5 {
        let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
        assert!(
            matches!(report.current, CurrentHealth::NeedsAttention { .. }),
            "pass {pass}: the failure must survive re-reading, {:?}",
            report.current
        );
        assert_eq!(
            state::get_setup(&conn, &setup.id)
                .unwrap()
                .unwrap()
                .attention_reason
                .as_deref(),
            Some(FAILURE),
            "pass {pass}: and so must its reason"
        );
    }
}

/// The control in the other direction: when traffic genuinely POST-DATES the
/// failure, the product must clear it and report success. Without this, the
/// suite above could be satisfied by a build that never clears a failure at
/// all — which would strand users in a permanent error state.
#[test]
fn control_traffic_recorded_after_the_failure_does_clear_it() {
    let (_d, conn) = test_conn();
    let verified = verified_project(&conn);
    let mut setup = failed_repair(&conn, &verified);

    // New traffic, recorded now — after the failure was written.
    insert_gateway_event(&conn, "p1", "api.openai.com", &clock::now_rfc3339());

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(
        report.current,
        CurrentHealth::VerifiedAndActive,
        "evidence that post-dates the failure is the newer truth: {:?}",
        report.current
    );
    assert_eq!(
        state::get_setup(&conn, &setup.id)
            .unwrap()
            .unwrap()
            .attention_reason,
        None,
        "and a genuinely-resolved failure must be cleared, not kept forever"
    );
}

/// A row carried across the v15 → v16 upgrade may hold a failure reason while
/// its cached state still says "verified", and that failure must survive the
/// first refresh.
///
/// v15's `write_derived` nulled `attention_reason` only on the paths it
/// happened to take, so a v15 database can genuinely contain
/// `state = traffic_observed` **with** a reason recorded. Migration v16 then
/// stamps `attention_at = last_transition_at` for exactly those rows
/// (`crates/core/src/db.rs`, v16). This is the one shape in which a derived
/// write both moves the state AND must keep the failure, so it is the only
/// thing that exercises the preservation clause at all — every path a current
/// build writes leaves `state` already at `needs_attention`, where the write
/// is skipped entirely.
///
/// **Kills:** dropping the preserved reason in `write_derived` (the audit's
/// `VER-02` mutation). Without the clause the reason is nulled here and the
/// user upgrading from v15 silently loses the record of a live failure.
#[test]
fn an_upgraded_v15_row_does_not_lose_its_failure_on_the_first_refresh() {
    let (_d, conn) = test_conn();
    let verified = verified_project(&conn);

    // The upgraded row: cached state still claims observation, a failure is
    // recorded, and the failure is NEWER than the traffic that is on file.
    // Written as SQL because that is precisely what it is — a row this build
    // did not write, inherited from one that did.
    conn.execute(
        "UPDATE tracking_setups
         SET state = 'traffic_observed', attention_reason = ?2, attention_at = ?3
         WHERE id = ?1",
        rusqlite::params![verified.id, FAILURE, ago(60)],
    )
    .unwrap();

    let mut setup = state::get_setup(&conn, &verified.id).unwrap().unwrap();
    assert_eq!(setup.state, TrackingState::TrafficObserved);
    assert_eq!(setup.attention_reason.as_deref(), Some(FAILURE));

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();

    let row = state::get_setup(&conn, &verified.id).unwrap().unwrap();
    assert_eq!(
        row.state,
        TrackingState::NeedsAttention,
        "the newer failure must pull the cached 'verified' claim down"
    );
    assert_eq!(
        row.attention_reason.as_deref(),
        Some(FAILURE),
        "and the inherited failure reason must NOT be erased while doing it"
    );
    assert!(
        row.attention_at.is_some(),
        "nor its timestamp, which is what makes it outrank the traffic"
    );
    assert!(
        matches!(report.current, CurrentHealth::NeedsAttention { .. }),
        "the user is shown the failure, not the stale success: {:?}",
        report.current
    );
}

/// The failure must outrank traffic from the PREVIOUS session even when that
/// traffic is newer in wall-clock terms — the session boundary, not the
/// clock, is what binds evidence to an attempt.
#[test]
fn traffic_from_the_previous_session_cannot_verify_the_failed_one() {
    let (_d, conn) = test_conn();
    let verified = verified_project(&conn);

    let reopened = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::Applying,
        "{}",
    )
    .unwrap();
    state::record_applied(&conn, &reopened.id, &summary()).unwrap();
    backdate_apply(&conn, &reopened.id, 600);
    let current = state::get_setup(&conn, &reopened.id).unwrap().unwrap();
    state::transition(
        &conn,
        &current,
        TrackingState::NeedsAttention,
        Some(FAILURE),
    )
    .unwrap();

    // No traffic at all in the new session; only the old session's rows exist.
    let mut setup = state::get_setup(&conn, &reopened.id).unwrap().unwrap();
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();

    assert!(
        matches!(report.current, CurrentHealth::NeedsAttention { .. }),
        "the previous attempt's traffic is not evidence for this one: {:?}",
        report.current
    );
    assert_eq!(
        state::get_setup(&conn, &setup.id)
            .unwrap()
            .unwrap()
            .attention_reason
            .as_deref(),
        Some(FAILURE)
    );
    assert!(
        report.history.first_verified_at.is_some(),
        "and the historical success is still shown as history"
    );
    assert_ne!(
        verified.verification_session, setup.verification_session,
        "the sessions must actually differ, or this test proves nothing"
    );
}
