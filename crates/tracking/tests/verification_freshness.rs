//! ZFT-005 / ZFT-006 / ZFT-008 regression suite: "tracking verified" must
//! describe the present, not the past.
//!
//! The audit reproduced three separate routes to a false "verified":
//!
//! 1. kill the gateway — status still read *"tracking verified — traffic
//!    observed"* while the user's application was pointed at a loopback
//!    port with nothing listening;
//! 2. re-run `track` and let it fail — the very next status promoted the
//!    row back to verified off the PREVIOUS run's traffic and nulled the
//!    failure reason;
//! 3. null one column in `vault.db` — re-derivation was skipped entirely,
//!    so a row rendered verified with zero events.
//!
//! Mutation testing found the boundary comparison and the
//! `observation_source` filter had zero coverage. Both are pinned here.
//!
//! Every test drives `refresh_with` directly with an explicit
//! [`GatewayLiveness`], so both sides of every branch are reachable without
//! a running service.

mod common;

use api_tracker_tracking::state::{
    self, CurrentHealth, GatewayLiveness, PlanSummary, TrackingState,
};
use common::*;
use rusqlite::Connection;
use std::path::Path;

fn summary(providers: &[&str]) -> PlanSummary {
    PlanSummary {
        providers: providers.iter().map(|s| s.to_string()).collect(),
        links: providers.iter().map(|s| s.to_string()).collect(),
        port: 49152,
        ..Default::default()
    }
}

/// A route + project link for `provider`, so the ground-truth checks in
/// `refresh_with` see a configuration that still exists.
fn wire_route_and_link(conn: &Connection, project_id: &str, provider: &str) {
    conn.execute(
        "INSERT OR REPLACE INTO gateway_routes
            (route_prefix, provider_id, enabled, created_at, updated_at)
         VALUES (?1, ?1, 1, '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z')",
        [provider],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO gateway_project_links
            (link_slug, project_id, route_prefix, created_at)
         VALUES (?1, ?2, ?3, '2099-01-01T00:00:00Z')",
        [&format!("slug-{provider}"), project_id, provider],
    )
    .unwrap();
}

/// An applied setup with one provider, its route and link present.
///
/// `applied_at` is backdated two days. Both bounds under test — "at or
/// after apply" and "inside the freshness window" — are then independently
/// reachable: a fresh event and a stale event can BOTH sit after the
/// watermark, which is what makes the freshness assertions mean anything.
fn applied_setup(conn: &Connection) -> state::TrackingSetup {
    insert_project(conn, "p1", "one");
    let setup = state::upsert_setup(
        conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(conn, &setup.id, &summary(&["openai"])).unwrap();
    let two_days_ago = api_tracker_core::clock::rfc3339_minus_seconds(
        &api_tracker_core::clock::now_rfc3339(),
        2 * 24 * 3600,
    );
    conn.execute(
        "UPDATE tracking_setups SET applied_at = ?2 WHERE id = ?1",
        rusqlite::params![setup.id, two_days_ago],
    )
    .unwrap();
    wire_route_and_link(conn, "p1", "openai");
    state::get_setup(conn, &setup.id).unwrap().unwrap()
}

/// A recent observation: `now` minus a minute, so it is inside the
/// freshness window whatever the wall clock says.
fn recent() -> String {
    api_tracker_core::clock::rfc3339_minus_seconds(&api_tracker_core::clock::now_rfc3339(), 60)
}

/// An observation old enough to be outside the freshness window.
fn stale() -> String {
    api_tracker_core::clock::rfc3339_minus_seconds(
        &api_tracker_core::clock::now_rfc3339(),
        state::OBSERVATION_FRESHNESS_SECS + 3600,
    )
}

// ---------------------------------------------------------------------------
// ZFT-005 — "verified" must not survive the gateway being dead
// ---------------------------------------------------------------------------

#[test]
fn a_dead_gateway_is_never_reported_as_currently_verified() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());

    // Gateway answering: this is the success case, and it must work — a
    // fix that reported failure unconditionally would pass every other
    // assertion in this file.
    let up = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(
        up.current,
        CurrentHealth::VerifiedAndActive,
        "a live gateway with fresh traffic must read as verified and active"
    );
    assert!(up.current.is_currently_working());

    // Same rows, gateway gone. The user's application is broken right now.
    let mut setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    let down = state::refresh_with(&conn, &mut setup, GatewayLiveness::Down).unwrap();
    assert_eq!(
        down.current,
        CurrentHealth::VerifiedPreviouslyGatewayDown,
        "killing the gateway must change the CURRENT answer"
    );
    assert!(
        !down.current.is_currently_working(),
        "a dead gateway is never a present-tense success"
    );
    // …and the historical fact survives, distinctly.
    assert!(
        down.history.first_verified_at.is_some(),
        "history must remain available even when current health is bad"
    );
}

#[test]
fn a_stale_observation_does_not_prove_current_health() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &stale());

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(
        matches!(report.current, CurrentHealth::VerifiedPreviouslyIdle { .. }),
        "an observation older than the freshness window is history, not health: {:?}",
        report.current
    );
    assert!(!report.current.is_currently_working());
    // The freshness flag is the load-bearing clause; pin it directly.
    assert!(
        report.freshness.iter().all(|f| !f.fresh),
        "the per-provider freshness flag must reflect the window"
    );
}

#[test]
fn removing_the_route_invalidates_current_tracking_health() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();

    conn.execute("DELETE FROM gateway_routes", []).unwrap();
    let mut setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(
        matches!(report.current, CurrentHealth::ConfigurationChanged { .. }),
        "a deleted route must not leave the setup reading as verified: {:?}",
        report.current
    );
    assert!(report.freshness.iter().all(|f| !f.route_present));
}

#[test]
fn removing_the_project_link_invalidates_current_tracking_health() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();

    conn.execute("DELETE FROM gateway_project_links", [])
        .unwrap();
    let mut setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(
        matches!(report.current, CurrentHealth::ConfigurationChanged { .. }),
        "a deleted project link must not leave the setup reading as verified: {:?}",
        report.current
    );
    assert!(report.freshness.iter().all(|f| !f.link_present));
}

// ---------------------------------------------------------------------------
// ZFT-006 — a failed re-run must not be verified by the previous run
// ---------------------------------------------------------------------------

#[test]
fn old_traffic_cannot_verify_a_new_setup_attempt() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    let first = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(first.current, CurrentHealth::VerifiedAndActive);
    let first_session = first.history.verification_session.clone();
    let first_generation = first.history.config_generation;

    // The user re-runs `track` on the same folder. A new session opens.
    let mut setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::Applying,
        "{}",
    )
    .unwrap();
    assert_ne!(
        setup.verification_session, first_session,
        "each attempt must get its own verification session"
    );
    assert!(
        setup.config_generation > first_generation,
        "each attempt must bump the configuration generation"
    );
    assert!(
        setup.applied_at.is_none() && setup.plan_summary_json.is_none(),
        "a new attempt must not inherit the previous attempt's apply artifacts"
    );

    // …and the attempt FAILS.
    let setup_ro = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    state::transition(
        &conn,
        &setup_ro,
        TrackingState::NeedsAttention,
        Some("apply_failed:EnsureService"),
    )
    .unwrap();
    setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(
        matches!(report.current, CurrentHealth::NeedsAttention { .. }),
        "a FAILED attempt must stay failed, whatever the previous attempt observed: {:?}",
        report.current
    );
    assert_eq!(
        setup.state,
        TrackingState::NeedsAttention,
        "the persisted row must not be promoted either"
    );
}

#[test]
fn a_current_failure_is_not_erased_by_older_success() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();

    // A failure recorded AFTER that observation.
    let setup_ro = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    state::transition(
        &conn,
        &setup_ro,
        TrackingState::NeedsAttention,
        Some("apply_failed:EnsureRoutes"),
    )
    .unwrap();
    let mut setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert!(
        setup.attention_at.is_some(),
        "a failure must be timestamped"
    );

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    match &report.current {
        CurrentHealth::NeedsAttention { reason } => {
            assert!(
                reason.contains("EnsureRoutes"),
                "the specific failure reason must survive re-derivation, got {reason:?}"
            );
        }
        other => panic!("a newer failure must outrank an older observation, got {other:?}"),
    }
    assert_eq!(
        setup.attention_reason.as_deref(),
        Some("apply_failed:EnsureRoutes"),
        "the persisted reason must not be nulled by a derived promotion"
    );
}

#[test]
fn an_observation_after_the_failure_does_clear_it() {
    // The converse control: the rule is "newer wins", not "failures are
    // permanent". Without this, the fix above could be a stuck flag.
    let (_db, conn) = test_conn();
    let setup = applied_setup(&conn);
    let setup_ro = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    state::transition(
        &conn,
        &setup_ro,
        TrackingState::NeedsAttention,
        Some("apply_failed:EnsureService"),
    )
    .unwrap();
    // Traffic arrives after the failure was recorded.
    let later = api_tracker_core::clock::now_rfc3339();
    insert_gateway_event(&conn, "p1", "api.openai.com", &later);

    let mut setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(
        report.current,
        CurrentHealth::VerifiedAndActive,
        "an observation that POST-dates the failure must clear it: {:?}",
        report.current
    );
}

// ---------------------------------------------------------------------------
// ZFT-008 — less evidence must never mean more
// ---------------------------------------------------------------------------

#[test]
fn a_missing_watermark_forces_a_downgrade_instead_of_skipping_derivation() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();

    // Exactly the audit's harness: null the watermark, as any process able
    // to write `vault.db` could.
    conn.execute(
        "UPDATE tracking_setups SET state = 'traffic_observed', applied_at = NULL WHERE id = ?1",
        [&setup.id],
    )
    .unwrap();
    let mut setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert_eq!(setup.state, TrackingState::TrafficObserved);

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_ne!(
        setup.state,
        TrackingState::TrafficObserved,
        "a nulled watermark must NOT leave the row rendering verified"
    );
    assert!(
        !report.current.is_currently_working(),
        "a nulled watermark must not read as working: {:?}",
        report.current
    );
    assert!(
        report.freshness.is_empty(),
        "no watermark means no qualifying observation can be attributed"
    );
}

#[test]
fn a_missing_plan_summary_forces_a_downgrade_too() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();

    conn.execute(
        "UPDATE tracking_setups
         SET state = 'traffic_observed', plan_summary_json = NULL WHERE id = ?1",
        [&setup.id],
    )
    .unwrap();
    let mut setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_ne!(setup.state, TrackingState::TrafficObserved);
    assert!(
        !report.current.is_currently_working(),
        "{:?}",
        report.current
    );
}

// ---------------------------------------------------------------------------
// The two clauses mutation testing found uncovered
// ---------------------------------------------------------------------------

#[test]
fn the_boundary_comparison_is_at_or_after_apply_not_strictly_after() {
    // `at >= applied_at`. A request that lands in the same instant as the
    // apply is a qualifying observation; one a microsecond earlier is not.
    // Mutating `>=` to `>` — or to `<=` — must fail this test.
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    let applied_at = setup.applied_at.clone().unwrap();
    // Both probe events below sit within the freshness window relative to
    // the backdated watermark, so this test isolates the >= comparison.

    // Strictly BEFORE: must not verify.
    let before = api_tracker_core::clock::rfc3339_minus_seconds(&applied_at, 1);
    insert_gateway_event(&conn, "p1", "api.openai.com", &before);
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(
        report
            .freshness
            .iter()
            .all(|f| f.last_observed_at.is_none()),
        "an event from before apply must never qualify"
    );

    // EXACTLY at the watermark: must verify.
    insert_gateway_event(&conn, "p1", "api.openai.com", &applied_at);
    let mut setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(
        report.freshness[0].last_observed_at.as_deref(),
        Some(applied_at.as_str()),
        "an event exactly at the watermark must qualify"
    );
}

#[test]
fn only_gateway_sourced_observations_verify() {
    // The `observation_source = 'gateway'` filter. A request recorded by
    // the `tethra run` wrapper or any other source proves nothing about
    // whether the gateway is on the app's path.
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    let at = recent();
    let id = insert_gateway_event(&conn, "p1", "api.openai.com", &at);
    conn.execute(
        "UPDATE runtime_request_events SET observation_source = 'run_wrapper' WHERE id = ?1",
        [&id],
    )
    .unwrap();

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(
        report
            .freshness
            .iter()
            .all(|f| f.last_observed_at.is_none()),
        "a non-gateway observation must never verify tracking"
    );
    assert!(!report.current.is_currently_working());

    // Control: flip it back and the same row DOES verify, so the assertion
    // above is about the filter and not about the fixture being broken.
    conn.execute(
        "UPDATE runtime_request_events SET observation_source = 'gateway' WHERE id = ?1",
        [&id],
    )
    .unwrap();
    let mut setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(report.current, CurrentHealth::VerifiedAndActive);
}

#[test]
fn unrelated_project_traffic_never_verifies_this_setup() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_project(&conn, "p2", "two");
    insert_gateway_event(&conn, "p2", "api.openai.com", &recent());

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(report
        .freshness
        .iter()
        .all(|f| f.last_observed_at.is_none()));
    assert!(!report.current.is_currently_working());
}

#[test]
fn unrelated_route_traffic_never_verifies_this_setup() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    // Right project, wrong host: nothing maps it to a configured provider.
    insert_gateway_event(&conn, "p1", "api.unrelated.example", &recent());

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(report
        .freshness
        .iter()
        .all(|f| f.last_observed_at.is_none()));
    assert!(!report.current.is_currently_working());
}

// ---------------------------------------------------------------------------
// History and current health are distinct
// ---------------------------------------------------------------------------

#[test]
fn history_survives_a_re_apply_while_session_evidence_does_not() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    let first = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    let first_verified = first
        .history
        .first_verified_at
        .clone()
        .expect("the first verification is recorded");

    // Re-apply: a new session, no inherited session evidence.
    let mut setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(&conn, &setup.id, &summary(&["openai"])).unwrap();
    setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(
        report.history.first_verified_at.as_deref(),
        Some(first_verified.as_str()),
        "the historical first verification must survive a re-apply"
    );
    assert!(
        !report.current.is_currently_working(),
        "…but it must not make the NEW attempt read as verified: {:?}",
        report.current
    );
}

#[test]
fn no_traffic_means_not_verified() {
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(report.current, CurrentHealth::WaitingForFirstRequest);
    assert!(report.history.first_verified_at.is_none());
}

#[test]
fn an_unknown_liveness_never_claims_present_tense_success() {
    // Bulk reads cannot afford a socket probe per row. They must degrade to
    // history, never to "working".
    let (_db, conn) = test_conn();
    let mut setup = applied_setup(&conn);
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Unknown).unwrap();
    assert!(
        !report.current.is_currently_working(),
        "an unprobed read must not assert present health: {:?}",
        report.current
    );
    assert!(matches!(
        report.current,
        CurrentHealth::VerifiedPreviouslyIdle { .. }
    ));
}
