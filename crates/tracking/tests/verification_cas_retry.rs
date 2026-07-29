//! `NEW-05` regression suite: the compare-and-swap RETRY budget in
//! `refresh_with` must be falsifiable.
//!
//! # The gap this file closes
//!
//! `REFRESH_CAS_ATTEMPTS` was `3` and could be set to `1` with all 158
//! tracking tests still green. That is not a safety hole — exhaustion is
//! *report without writing*, so it degrades to a stale cached column and
//! never to an erased failure — but a constant no test can falsify is a
//! constant that will be "simplified" away, taking the convergence property
//! `VER-01` is built on with it.
//!
//! Nothing existing could fail, and the reason is structural:
//! `refresh_once` only writes when its conclusion DIFFERS from the stored
//! state. Every pre-existing concurrency test lands in a shape where the
//! re-read makes the retry a no-op — both racers derive the same thing, or
//! the re-read row already says what the retry would have written. The
//! observable difference between one attempt and three is therefore never
//! the returned report (which is honest either way, because the terminal
//! pass re-reads and re-derives) — it is **what ends up persisted**. Every
//! assertion below that kills the mutant is an assertion on the stored row.
//!
//! # Determinism
//!
//! No test here sleeps, and none depends on thread scheduling. Two
//! connections on one `vault.db` stand in for two processes, exactly as
//! `verification_concurrency.rs` does. Conflicts at a chosen ITERATION are
//! produced through `state::cas_test_hook`, a `#[doc(hidden)]` seam that
//! fires on the calling thread immediately before each attempt: the handle
//! `refresh_with` is about to decide from becomes stale at precisely the
//! attempts the test names, so "the second attempt is what persists the
//! correction" is an assertion rather than a race.
//!
//! # The mutation ladder these were built against
//!
//! ```text
//! REFRESH_CAS_ATTEMPTS = 1 -> 0 passed, 5 failed
//! REFRESH_CAS_ATTEMPTS = 2 -> 3 passed, 2 failed
//! REFRESH_CAS_ATTEMPTS = 3 -> 5 passed, 0 failed
//! ```

mod common;

use api_tracker_core::clock;
use api_tracker_tracking::state::{
    self, CurrentHealth, GatewayLiveness, PlanSummary, TrackingSetup, TrackingState,
};
use common::*;
use rusqlite::Connection;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn summary() -> PlanSummary {
    PlanSummary {
        providers: vec!["openai".into()],
        links: vec!["openai".into()],
        port: 49152,
        ..Default::default()
    }
}

/// Route + link rows, so `route_present` and `link_present` hold. Without
/// them no "still working" conclusion could be reached and these tests would
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

/// A setup applied two days ago, wired, still `awaiting_first_request`.
fn applied(conn: &Connection) -> TrackingSetup {
    insert_project(conn, "p1", "one");
    let mut s = state::upsert_setup(
        conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(conn, &mut s, &summary()).unwrap();
    let two_days_ago = clock::rfc3339_minus_seconds(&clock::now_rfc3339(), 2 * 24 * 3600);
    conn.execute(
        "UPDATE tracking_setups SET applied_at = ?2 WHERE id = ?1",
        rusqlite::params![s.id, two_days_ago],
    )
    .unwrap();
    wire(conn);
    state::get_setup(conn, &s.id).unwrap().unwrap()
}

fn ago(secs: i64) -> String {
    clock::rfc3339_minus_seconds(&clock::now_rfc3339(), secs)
}

/// An observation admissible for this session: gateway-sourced, inside the
/// freshness window, after the apply watermark and inserted after it. With
/// it present the derived answer is `traffic_observed`, which differs from
/// the stored `awaiting_first_request` — so a write is actually attempted.
fn admissible_observation(conn: &Connection) {
    insert_gateway_event(conn, "p1", "api.openai.com", &ago(60));
}

/// Move the row WITHOUT changing what the evidence implies: same state, no
/// failure. The only thing that moves is the compare-and-swap token, so the
/// retry re-derives the same conclusion and the test is measuring the retry
/// and nothing else.
///
/// `transition` to the same state is legal (the legality gate short-circuits
/// on `setup.state != next`) and bumps `row_version`, so this is a real
/// product operation rather than a hand-edit.
fn touch(conn: &Connection, id: &str) {
    let live = state::get_setup(conn, id).unwrap().unwrap();
    state::transition(conn, &live, live.state, None).unwrap();
}

// ---------------------------------------------------------------------------

/// One lost compare-and-swap, then a retry that commits.
///
/// Needs no hook at all: the caller's `&mut TrackingSetup` IS the read, so
/// moving the row once before the call guarantees attempt 0 loses.
/// Falsified by `REFRESH_CAS_ATTEMPTS = 1`.
#[test]
fn a_refresh_whose_first_compare_and_swap_loses_still_persists_its_correction() {
    let (_d, conn, path) = test_conn_at();
    let mut stale = applied(&conn);
    admissible_observation(&conn);
    let v0 = stale.row_version;

    let other = second_conn(&path);
    touch(&other, &stale.id);

    let report = state::refresh_with(&conn, &mut stale, GatewayLiveness::Verified).unwrap();
    // Deliberately holds at one attempt too: it documents that the REPORT is
    // honest either way, so a reader can see that the killing assertions are
    // the two on the persisted row below.
    assert_eq!(report.current, CurrentHealth::VerifiedAndActive);

    let row = state::get_setup(&conn, &stale.id).unwrap().unwrap();
    assert_eq!(
        row.state,
        TrackingState::TrafficObserved,
        "the RETRY is what persists the correction after the first compare-and-swap lost"
    );
    assert_eq!(
        row.row_version,
        v0 + 2,
        "one bump from the competing write, one from the retry that committed"
    );
}

/// Two consecutive conflicts: the third and last attempt must still commit.
/// Falsified by `REFRESH_CAS_ATTEMPTS = 2` and by `= 1`.
#[test]
fn a_refresh_persists_its_correction_after_two_consecutive_conflicts() {
    let (_d, conn, path) = test_conn_at();
    let mut handle = applied(&conn);
    admissible_observation(&conn);
    let v0 = handle.row_version;

    let bumper = second_conn(&path);
    let id = handle.id.clone();
    let guard = state::cas_test_hook::install(move |attempt| {
        if attempt < 2 {
            touch(&bumper, &id);
        }
    });

    state::refresh_with(&conn, &mut handle, GatewayLiveness::Verified).unwrap();
    drop(guard);

    let row = state::get_setup(&conn, &handle.id).unwrap().unwrap();
    assert_eq!(
        row.state,
        TrackingState::TrafficObserved,
        "the THIRD attempt is the last one allowed and must still commit"
    );
    assert_eq!(
        row.row_version,
        v0 + 3,
        "two bumps from the competing writer, one from the attempt that committed"
    );
}

/// Exhaustion. The whole documented terminal contract in one test: it
/// REPORTS, it does not error, it writes nothing, and the cached column is
/// left diverging from `current` — which is the residual this behaviour is
/// deliberately chosen to accept.
///
/// Also the direct pin on the constant's VALUE: the hook counts attempts.
#[test]
fn sustained_conflict_reports_the_truth_writes_nothing_and_makes_exactly_three_attempts() {
    let (_d, conn, path) = test_conn_at();
    let mut handle = applied(&conn);
    admissible_observation(&conn);
    let v0 = handle.row_version;

    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&attempts);
    let bumper = second_conn(&path);
    let id = handle.id.clone();
    let guard = state::cas_test_hook::install(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        touch(&bumper, &id);
    });

    let report = state::refresh_with(&conn, &mut handle, GatewayLiveness::Verified)
        .expect("exhaustion reports, it does not error");
    drop(guard);

    assert_eq!(
        attempts.load(Ordering::SeqCst),
        3,
        "REFRESH_CAS_ATTEMPTS is the number of write attempts actually made"
    );
    assert_eq!(
        report.current,
        CurrentHealth::VerifiedAndActive,
        "the derived answer stays honest under sustained contention — it is \
         re-derived from evidence on the terminal pass, not read from the row"
    );
    assert_eq!(
        report.state,
        TrackingState::AwaitingFirstRequest,
        "the CACHED column is the uncorrected one; a consumer keying on `.state` \
         instead of `.current` reads stale, which is the documented residual"
    );
    let row = state::get_setup(&conn, &handle.id).unwrap().unwrap();
    assert_eq!(
        row.state,
        TrackingState::AwaitingFirstRequest,
        "no correction is persisted once the budget is spent"
    );
    assert_eq!(
        row.row_version,
        v0 + 3,
        "only the competing writer moved the row; the refresh wrote nothing at all"
    );
}

/// A NEW failure arriving between retries must be written THROUGH, never
/// replaced by the success the first attempt had already concluded.
///
/// The competing writer moves to `traffic_observed` AND records the failure
/// in one step, because that is what makes the retry's write observable: had
/// it moved straight to `needs_attention`, the retry's conclusion would
/// already equal the stored state and nothing would be written — which is
/// precisely the shape that lets the existing suite survive one attempt.
/// The overclaiming intermediate is a state the product genuinely reaches
/// when a refresh and a failing repair interleave.
#[test]
fn a_failure_recorded_between_retries_is_written_through_and_never_erased() {
    let (_d, conn, path) = test_conn_at();
    let mut handle = applied(&conn);
    admissible_observation(&conn);

    let other = second_conn(&path);
    let id = handle.id.clone();
    let guard = state::cas_test_hook::install(move |attempt| {
        if attempt == 0 {
            let live = state::get_setup(&other, &id).unwrap().unwrap();
            state::transition(
                &other,
                &live,
                TrackingState::TrafficObserved,
                Some("apply_failed:EnsureRoutes"),
            )
            .unwrap();
        }
    });

    let report = state::refresh_with(&conn, &mut handle, GatewayLiveness::Verified).unwrap();
    drop(guard);

    assert!(
        matches!(report.current, CurrentHealth::NeedsAttention { .. }),
        "a failure newer than every observation outranks them: {:?}",
        report.current
    );
    let row = state::get_setup(&conn, &handle.id).unwrap().unwrap();
    assert_eq!(
        row.state,
        TrackingState::NeedsAttention,
        "the retry must CORRECT the overclaiming column, not leave it claiming traffic"
    );
    assert_eq!(
        row.attention_reason.as_deref(),
        Some("apply_failed:EnsureRoutes"),
        "and it must carry the failure through rather than erase it (ZFT-006)"
    );
}

/// A generation change between retries that leaves the cached column
/// overclaiming with no watermark: the retry is the only thing that can
/// downgrade it.
///
/// A *bare* re-apply is deliberately not the case under test — `upsert_setup`
/// leaves the row at `applying`, which is not overclaiming, so the retry
/// correctly writes nothing and the behaviour is identical at one attempt
/// and at three. That invariant is already covered by
/// `a_setup_generation_change_invalidates_an_in_flight_refresh`. The
/// interleaving below is the one where the retry is load-bearing: the new
/// session's cleared watermark lands while the cached column still claims
/// observation, which is the ZFT-008 shape.
#[test]
fn a_generation_change_between_retries_never_leaves_the_row_overclaiming() {
    let (_d, conn, path) = test_conn_at();
    let mut handle = applied(&conn);
    admissible_observation(&conn);
    let gen_before = handle.config_generation;

    let other = second_conn(&path);
    let id = handle.id.clone();
    let guard = state::cas_test_hook::install(move |attempt| {
        if attempt == 0 {
            other
                .execute(
                    "UPDATE tracking_setups
                     SET state = 'traffic_observed', applied_at = NULL,
                         config_generation = config_generation + 1,
                         row_version = row_version + 1
                     WHERE id = ?1",
                    [&id],
                )
                .unwrap();
        }
    });

    state::refresh_with(&conn, &mut handle, GatewayLiveness::Verified).unwrap();
    drop(guard);

    let row = state::get_setup(&conn, &handle.id).unwrap().unwrap();
    assert!(
        row.config_generation > gen_before,
        "the fixture must really have opened a new generation"
    );
    assert_eq!(
        row.state,
        TrackingState::NeedsAttention,
        "a row with no apply watermark may not stay traffic_observed once a retry \
         exists that can correct it — less evidence must never render as more"
    );
    assert!(
        row.attention_reason.is_some(),
        "and the downgrade has to say why: {:?}",
        row.attention_reason
    );
}
