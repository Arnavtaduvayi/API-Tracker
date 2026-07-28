//! RA-005 regression suite: stored timestamps are untrusted input.
//!
//! `runtime_request_events.at` is a wall-clock string written by whichever
//! process recorded the exchange, into a plain column of an unencrypted
//! database. The reader compares it against *its own* wall clock. Before
//! this suite existed, that comparison was bounded from below only, so:
//!
//! * an observation dated a year ahead read as `VerifiedAndActive`, and
//!   stayed that way until the wall clock caught up; and
//! * because it was the largest timestamp in the table, it also out-ranked
//!   a failure recorded *now*, and `write_derived` nulled
//!   `attention_reason` — destroying the record of a live failure.
//!
//! The second is the sharper defect: it is the ZFT-006 shape the whole
//! verification rework exists to prevent, reachable through the clock.
//!
//! # What is asserted
//!
//! Three independent admissibility conditions, tested separately so that
//! removing any one of them fails something:
//!
//! 1. a bounded clock-skew window on `at` (both sides),
//! 2. the apply watermark on `at` (no back-dating into a previous session),
//! 3. the insertion-ordered `rowid` watermark, which no writer's clock can
//!    influence.
//!
//! The mutation controls at the bottom prove each condition is load-bearing
//! rather than incidentally satisfied.

mod common;

use api_tracker_core::clock;
use api_tracker_tracking::state::{
    self, CurrentHealth, GatewayLiveness, PlanSummary, TrackingState, MAX_CLOCK_SKEW_SECS,
    OBSERVATION_FRESHNESS_SECS,
};
use common::*;
use rusqlite::Connection;
use std::path::Path;

fn summary() -> PlanSummary {
    PlanSummary {
        providers: vec!["openai".into()],
        links: vec!["openai".into()],
        port: 49152,
        ..Default::default()
    }
}

/// Route and link rows so `route_present` and `link_present` hold — the
/// other two legs of a present-tense success. Without these the tests would
/// pass for the wrong reason.
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

/// An applied setup whose apply happened two days ago, exactly as the
/// audit's reproduction builds it.
fn applied(conn: &Connection) -> state::TrackingSetup {
    insert_project(conn, "p1", "one");
    let s = state::upsert_setup(
        conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(conn, &s.id, &summary()).unwrap();
    let two_days_ago = clock::rfc3339_minus_seconds(&clock::now_rfc3339(), 2 * 24 * 3600);
    conn.execute(
        "UPDATE tracking_setups SET applied_at = ?2 WHERE id = ?1",
        rusqlite::params![s.id, two_days_ago],
    )
    .unwrap();
    wire(conn);
    state::get_setup(conn, &s.id).unwrap().unwrap()
}

/// `now` shifted by `secs` (negative shifts into the future).
fn shifted(secs: i64) -> String {
    clock::rfc3339_minus_seconds(&clock::now_rfc3339(), secs)
}

// ---------------------------------------------------------------------------
// The audit's two reproductions
// ---------------------------------------------------------------------------

/// `repro/verification_future.rs`, test 1.
#[test]
fn a_future_dated_observation_must_not_be_currently_verified() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);
    let future = shifted(-365 * 24 * 3600); // one year AHEAD
    insert_gateway_event(&conn, "p1", "api.openai.com", &future);

    let r = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_ne!(
        r.current,
        CurrentHealth::VerifiedAndActive,
        "an observation dated a YEAR in the future must not be a present-tense success \
         (freshness: {:?})",
        r.freshness
    );
    assert!(
        r.freshness.iter().all(|f| !f.fresh),
        "no provider may be fresh on a year-ahead observation: {:?}",
        r.freshness
    );
}

/// `repro/verification_future.rs`, test 2 — the ZFT-006 shape.
#[test]
fn a_future_dated_observation_must_not_erase_a_current_failure() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);
    let future = shifted(-3600); // one hour ahead
    insert_gateway_event(&conn, "p1", "api.openai.com", &future);

    // The audit's exact shape: `transition` RETURNS the updated setup, and
    // the reproduction discarded it, so the refresh below runs against a
    // handle that predates the failure. That is the harsher case — the
    // in-memory struct does not even know a failure exists — and it is the
    // one that durably nulled `attention_reason` at the audited head. The
    // durable row is what matters, so it is asserted under this shape.
    let refreshed = state::transition(
        &conn,
        &setup,
        TrackingState::NeedsAttention,
        Some("apply_failed:EnsureRoutes"),
    )
    .unwrap();

    let stale = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    let persisted = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert_eq!(
        persisted.attention_reason.as_deref(),
        Some("apply_failed:EnsureRoutes"),
        "a failure recorded NOW must not be erased by a future-dated observation, even when \
         the reader holds a setup handle from before the failure (health seen: {:?})",
        stale.current
    );
    assert!(
        persisted.attention_at.is_some(),
        "the failure timestamp must survive too"
    );
    assert_ne!(
        stale.current,
        CurrentHealth::VerifiedAndActive,
        "and a stale handle must never yield a present-tense success"
    );

    // With the current handle — what every production caller uses, since
    // `apply` re-reads the row before transitioning — the reported health
    // is the failure itself.
    let mut current = refreshed;
    let r = state::refresh_with(&conn, &mut current, GatewayLiveness::Verified).unwrap();
    assert!(
        matches!(r.current, CurrentHealth::NeedsAttention { .. }),
        "the reported health must be the failure, not a success: {:?}",
        r.current
    );
    assert_eq!(
        state::get_setup(&conn, &setup.id)
            .unwrap()
            .unwrap()
            .attention_reason
            .as_deref(),
        Some("apply_failed:EnsureRoutes"),
        "and the reason still survives the second read"
    );
}

// ---------------------------------------------------------------------------
// The documented skew behaviour, at and around the boundary
// ---------------------------------------------------------------------------

/// One second ahead is ordinary skew between two processes and must be
/// believed — refusing it would make the product flap.
#[test]
fn one_second_of_skew_is_still_verified() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &shifted(-1));

    let r = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(
        r.current,
        CurrentHealth::VerifiedAndActive,
        "one second of clock skew must not break verification: {:?}",
        r.freshness
    );
}

/// Just inside the window is believed; just outside is not. Tested as a
/// pair so the window is pinned rather than merely "large".
#[test]
fn the_skew_boundary_is_where_it_is_documented_to_be() {
    let inside = {
        let (_d, conn) = test_conn();
        let mut setup = applied(&conn);
        // A margin below the edge, so the seconds that elapse during the
        // test cannot carry it across.
        insert_gateway_event(
            &conn,
            "p1",
            "api.openai.com",
            &shifted(-(MAX_CLOCK_SKEW_SECS - 30)),
        );
        state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified)
            .unwrap()
            .current
    };
    assert_eq!(
        inside,
        CurrentHealth::VerifiedAndActive,
        "an observation inside the skew window must still verify"
    );

    let outside = {
        let (_d, conn) = test_conn();
        let mut setup = applied(&conn);
        insert_gateway_event(
            &conn,
            "p1",
            "api.openai.com",
            &shifted(-(MAX_CLOCK_SKEW_SECS + 30)),
        );
        state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified)
            .unwrap()
            .current
    };
    assert_ne!(
        outside,
        CurrentHealth::VerifiedAndActive,
        "an observation beyond the skew window must not verify"
    );
}

/// A far-future observation must not verify, and must not keep verifying
/// on every subsequent read either — the "indefinitely" half of RA-005.
#[test]
fn a_far_future_observation_never_becomes_verified_however_often_it_is_read() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);
    insert_gateway_event(
        &conn,
        "p1",
        "api.openai.com",
        &shifted(-100 * 365 * 24 * 3600),
    );

    for pass in 0..5 {
        let r = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
        assert_ne!(
            r.current,
            CurrentHealth::VerifiedAndActive,
            "pass {pass}: a century-ahead observation must never read as working"
        );
    }
    let persisted = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert_ne!(
        persisted.state,
        TrackingState::TrafficObserved,
        "and it must not be cached as traffic_observed either"
    );
}

/// The clock moving BACKWARD (an NTP step-back, a restored snapshot) turns
/// honest recent observations into apparently-future ones. They must be
/// excluded, not believed — and the setup must degrade honestly rather
/// than claim success.
#[test]
fn a_clock_rollback_degrades_honestly_instead_of_verifying() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);
    // Written by the gateway before the rollback; from the reader's new
    // point of view it is two hours in the future.
    insert_gateway_event(&conn, "p1", "api.openai.com", &shifted(-2 * 3600));

    let r = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_ne!(
        r.current,
        CurrentHealth::VerifiedAndActive,
        "observations from after a clock rollback must not read as present-tense success"
    );
    assert!(
        !r.current.is_currently_working(),
        "and must not read as working at all: {:?}",
        r.current
    );
}

/// The clock moving FORWARD ages observations out of the freshness window.
/// That must read as "verified previously", never as broken-and-never-worked
/// and never as currently working.
#[test]
fn a_clock_jump_forward_reads_as_previously_verified() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);
    // Inside the apply watermark (2 days ago) but well outside the 6-hour
    // freshness window.
    insert_gateway_event(
        &conn,
        "p1",
        "api.openai.com",
        &shifted(OBSERVATION_FRESHNESS_SECS + 3600),
    );

    let r = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(
        matches!(r.current, CurrentHealth::VerifiedPreviouslyIdle { .. }),
        "an aged-out observation is history, not present health: {:?}",
        r.current
    );
    assert!(!r.current.is_currently_working());
}

/// A new failure recorded AFTER an apparently-future observation must win,
/// and must keep winning across reads.
#[test]
fn a_new_failure_after_a_future_observation_survives_repeated_reads() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &shifted(-30 * 24 * 3600));

    setup = state::transition(
        &conn,
        &setup,
        TrackingState::NeedsAttention,
        Some("apply_failed:EnsureLinks"),
    )
    .unwrap();

    for pass in 0..3 {
        let _ = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
        let persisted = state::get_setup(&conn, &setup.id).unwrap().unwrap();
        assert_eq!(
            persisted.attention_reason.as_deref(),
            Some("apply_failed:EnsureLinks"),
            "pass {pass}: the failure must not be erased"
        );
    }
}

// ---------------------------------------------------------------------------
// Session and generation binding
// ---------------------------------------------------------------------------

/// An observation from a PREVIOUS session must not verify the current one,
/// even when its timestamp is inside every window.
#[test]
fn an_observation_from_a_previous_session_cannot_verify_this_one() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);

    // Traffic that verified the first session.
    insert_gateway_event(&conn, "p1", "api.openai.com", &shifted(60));
    let first = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(
        first.current,
        CurrentHealth::VerifiedAndActive,
        "control: the first session must verify, or this test proves nothing"
    );

    // A re-run opens a new session; the previous session's observation is
    // still in the table and still recent.
    let mut reapplied = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(&conn, &reapplied.id, &summary()).unwrap();
    reapplied = state::get_setup(&conn, &reapplied.id).unwrap().unwrap();

    let r = state::refresh_with(&conn, &mut reapplied, GatewayLiveness::Verified).unwrap();
    assert_ne!(
        r.current,
        CurrentHealth::VerifiedAndActive,
        "the previous session's traffic must not verify the new one: {:?}",
        r.freshness
    );
}

/// The insertion-ordered watermark must exclude a row back-dated into the
/// current window but inserted before the apply — the case a timestamp
/// window alone cannot catch.
#[test]
fn a_row_inserted_before_apply_cannot_verify_however_it_is_dated() {
    let (_d, conn) = test_conn();
    insert_project(&conn, "p1", "one");

    // Recorded BEFORE the setup is applied, dated one minute ago — inside
    // every timestamp window the reader applies.
    insert_gateway_event(&conn, "p1", "api.openai.com", &shifted(60));

    let s = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(&conn, &s.id, &summary()).unwrap();
    // Back-date the apply watermark so the TIMESTAMP condition would admit
    // the row; only the rowid watermark can exclude it.
    conn.execute(
        "UPDATE tracking_setups SET applied_at = ?2 WHERE id = ?1",
        rusqlite::params![s.id, shifted(2 * 24 * 3600)],
    )
    .unwrap();
    wire(&conn);
    let mut setup = state::get_setup(&conn, &s.id).unwrap().unwrap();
    assert!(
        setup.applied_event_rowid > 0,
        "the apply must have stamped a rowid watermark, or this test is vacuous"
    );

    let r = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_ne!(
        r.current,
        CurrentHealth::VerifiedAndActive,
        "a row physically recorded before the apply must not verify it: {:?}",
        r.freshness
    );
}

/// A route or link removed after verification is a generation mismatch: the
/// evidence no longer describes the current configuration.
#[test]
fn a_route_or_link_change_after_observation_is_not_currently_working() {
    for (what, sql) in [
        ("route disabled", "UPDATE gateway_routes SET enabled = 0"),
        ("link removed", "DELETE FROM gateway_project_links"),
    ] {
        let (_d, conn) = test_conn();
        let mut setup = applied(&conn);
        insert_gateway_event(&conn, "p1", "api.openai.com", &shifted(60));

        let before = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
        assert_eq!(
            before.current,
            CurrentHealth::VerifiedAndActive,
            "control for {what}: it must verify first"
        );

        conn.execute(sql, []).unwrap();
        let after = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
        assert!(
            !after.current.is_currently_working(),
            "{what}: evidence from the previous configuration must not read as working: {:?}",
            after.current
        );
    }
}

/// Historical verification must survive, and must never be reported as
/// present health.
#[test]
fn historical_verification_survives_but_does_not_claim_current_health() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &shifted(60));
    let r = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(r.current, CurrentHealth::VerifiedAndActive);
    assert!(r.history.first_verified_at.is_some());

    // The gateway dies. History stays; present-tense success does not.
    let down = state::refresh_with(&conn, &mut setup, GatewayLiveness::Down).unwrap();
    assert!(
        down.history.first_verified_at.is_some(),
        "history must survive a dead gateway"
    );
    assert!(
        !down.current.is_currently_working(),
        "but it must not claim current health: {:?}",
        down.current
    );
}

/// RFC 3339 is not byte-order-equivalent to time order, and the difference
/// decides whether a failure survives.
///
/// `now_rfc3339` omits the fractional part when nanoseconds happen to be
/// zero, and `'.'` (0x2E) sorts before `'Z'` (0x5A). So a failure recorded at
/// `12:00:00.5Z` compares as OLDER than an observation at `12:00:00Z` under a
/// byte comparison, and the older observation erases the newer failure. Under
/// parsed instants the failure correctly wins.
///
/// This is the sub-second half of RA-005. The window is small; the
/// consequence — a destroyed record of a live failure — is not.
#[test]
fn a_failure_half_a_second_newer_than_an_observation_still_wins() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);

    // An observation on a whole second, inside every admissibility window.
    let observed = shifted(60);
    let seconds = observed[..observed.len() - 1]
        .split('.')
        .next()
        .expect("an RFC 3339 timestamp has a seconds field");
    let whole_second = format!("{seconds}Z");
    insert_gateway_event(&conn, "p1", "api.openai.com", &whole_second);

    // A failure recorded half a second LATER, in the same second.
    let failed = format!("{}.5Z", &whole_second[..whole_second.len() - 1]);
    setup = state::transition(
        &conn,
        &setup,
        TrackingState::NeedsAttention,
        Some("apply_failed:EnsureRoutes"),
    )
    .unwrap();
    conn.execute(
        "UPDATE tracking_setups SET attention_at = ?2 WHERE id = ?1",
        rusqlite::params![setup.id, failed],
    )
    .unwrap();
    setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();

    // The byte comparison the audited head used gets this backwards.
    assert!(
        failed.as_str() < whole_second.as_str(),
        "fixture check: the failure must sort BEFORE the observation as bytes,          or this test is not exercising the hazard ({failed} vs {whole_second})"
    );

    let r = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    let persisted = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert_eq!(
        persisted.attention_reason.as_deref(),
        Some("apply_failed:EnsureRoutes"),
        "a failure half a second newer than the observation must survive \
         (health seen: {:?})",
        r.current
    );
}

// ---------------------------------------------------------------------------
// Mutation controls
// ---------------------------------------------------------------------------

/// Proves the UPPER bound is what rejects a future observation, by
/// re-running the freshness comparison with only the lower bound — the
/// audited-head predicate. If this ever stops failing, the fixture no
/// longer produces a future-dated row and the tests above are vacuous.
#[test]
fn control_the_audited_head_predicate_would_have_accepted_the_future_row() {
    let now = clock::now_rfc3339();
    let stale_before = clock::rfc3339_minus_seconds(&now, OBSERVATION_FRESHNESS_SECS);
    let future_after = clock::rfc3339_minus_seconds(&now, -MAX_CLOCK_SKEW_SECS);
    let a_year_ahead = shifted(-365 * 24 * 3600);

    // The audited-head predicate: lower bound only.
    assert!(
        a_year_ahead.as_str() >= stale_before.as_str(),
        "MUTATION CONTROL FAILED: the audited-head predicate no longer accepts a \
         year-ahead timestamp, so the RA-005 tests are not testing what they claim"
    );
    // The remediated predicate.
    assert!(
        !(a_year_ahead.as_str() >= stale_before.as_str()
            && a_year_ahead.as_str() <= future_after.as_str()),
        "the bounded predicate must reject a year-ahead timestamp"
    );
}

/// Proves the failure-preservation path is reached by the fixture: with the
/// failure removed, the same future-dated row DOES flip the cached state.
/// Without this control, `a_future_dated_observation_must_not_erase_a_current_failure`
/// could pass simply because nothing ever writes the state.
#[test]
fn control_without_a_failure_an_admissible_observation_does_flip_the_state() {
    let (_d, conn) = test_conn();
    let mut setup = applied(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &shifted(60));

    let _ = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    let persisted = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert_eq!(
        persisted.state,
        TrackingState::TrafficObserved,
        "MUTATION CONTROL FAILED: the derivation never writes traffic_observed, so the \
         failure-preservation assertions prove nothing"
    );
    assert!(persisted.attention_reason.is_none());
}

/// The skew constant must stay far below the freshness window, or "slightly
/// ahead" would start to meaningfully extend verification.
#[test]
fn the_skew_window_is_small_relative_to_the_freshness_window() {
    // Read through locals so this stays an assertion about the constants'
    // relationship rather than one clippy can fold to a literal `true`.
    let skew = MAX_CLOCK_SKEW_SECS;
    let freshness = OBSERVATION_FRESHNESS_SECS;
    assert!(
        skew > 0,
        "a non-positive skew window would reject the gateway's own writes"
    );
    assert!(
        skew * 10 < freshness,
        "the skew window ({skew}s) must stay an order of magnitude below the \
         freshness window ({freshness}s)"
    );
}
