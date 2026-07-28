//! State machine + re-derivation (TEST_PLAN §4): persisted state can
//! never overclaim, pre-existing traffic never verifies a new setup, and
//! partial observation is derived per provider.

mod common;

use api_tracker_tracking::state::{self, PlanSummary, TrackingState};
use api_tracker_tracking::verify::{self, WatchStatus};
use common::*;
use std::path::Path;

fn summary(providers: &[&str]) -> PlanSummary {
    PlanSummary {
        providers: providers.iter().map(|s| s.to_string()).collect(),
        links: providers.iter().map(|s| s.to_string()).collect(),
        port: 49152,
        ..Default::default()
    }
}

/// A timestamp a real gateway could have written: a moment after the apply
/// that just happened, and inside the clock-skew window verification allows.
///
/// These fixtures used to use `2099-01-01T00:00:00Z` as a stand-in for
/// "after applied_at". That is not a time any writer could produce, and
/// verification now refuses observations dated implausibly far ahead of this
/// machine's clock (RA-005), so the stand-in has to be a real one.
fn just_after_apply() -> String {
    api_tracker_core::clock::rfc3339_minus_seconds(&api_tracker_core::clock::now_rfc3339(), -2)
}

#[test]
fn every_documented_transition_is_legal_and_others_are_rejected() {
    use TrackingState::*;
    let legal = [
        (NotConfigured, Scanning),
        (Scanning, ReadyToConfigure),
        (ReadyToConfigure, Applying),
        (ReadyToConfigure, Unsupported),
        (Applying, AwaitingRestart),
        (Applying, AwaitingFirstRequest),
        (Applying, NeedsAttention),
        (AwaitingRestart, TrafficObserved),
        (AwaitingFirstRequest, TrafficObserved),
        (AwaitingFirstRequest, PartiallyObserved),
        (AwaitingFirstRequest, NeedsAttention),
        (NeedsAttention, TrafficObserved),
        (TrafficObserved, NeedsAttention),
        (PartiallyObserved, TrafficObserved),
    ];
    for (from, to) in legal {
        assert!(
            from.can_transition_to(to),
            "{from:?} -> {to:?} must be legal"
        );
    }
    // Undo is legal from anywhere.
    assert!(TrafficObserved.can_transition_to(NotConfigured));
    assert!(NeedsAttention.can_transition_to(NotConfigured));
    // Skipping the machine is not.
    let illegal = [
        (NotConfigured, TrafficObserved),
        (NotConfigured, Applying),
        (Scanning, TrafficObserved),
        (ReadyToConfigure, TrafficObserved),
        (Unsupported, TrafficObserved),
    ];
    for (from, to) in illegal {
        assert!(
            !from.can_transition_to(to),
            "{from:?} -> {to:?} must be illegal"
        );
    }
}

#[test]
fn illegal_transition_is_an_error_in_the_db_layer() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::NotConfigured,
        "{}",
    )
    .unwrap();
    let err = state::transition(&conn, &setup, TrackingState::TrafficObserved, None).unwrap_err();
    assert!(err.to_string().contains("illegal"), "{err}");
}

/// A hand-edited `traffic_observed` row with zero events downgrades on
/// read — the SI-19-alignment test, and the negative control proving
/// verification cannot pass without an observation.
#[test]
fn an_overclaiming_row_is_downgraded_on_refresh() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    let mut setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(&conn, &setup.id, &summary(&["openai"])).unwrap();
    // Forge the overclaim directly, as a corrupted/stale row would.
    conn.execute(
        "UPDATE tracking_setups SET state = 'traffic_observed' WHERE id = ?1",
        [&setup.id],
    )
    .unwrap();
    setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert_eq!(setup.state, TrackingState::TrafficObserved);

    let freshness = state::refresh(&conn, &mut setup).unwrap();
    assert_eq!(
        setup.state,
        TrackingState::AwaitingFirstRequest,
        "zero events must never support traffic_observed"
    );
    assert!(freshness.iter().all(|f| f.last_observed_at.is_none()));
}

#[test]
fn traffic_after_apply_verifies_and_watch_reports_it() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
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
    let applied_at = setup.applied_at.clone().unwrap();

    // No traffic → still waiting (negative control).
    match verify::check_traffic(&conn, &mut setup).unwrap() {
        WatchStatus::Waiting => {}
        other => panic!("expected Waiting, got {other:?}"),
    }

    // A qualifying event arrives (strictly after applied_at).
    let later = just_after_apply();
    assert!(later.as_str() > applied_at.as_str());
    insert_gateway_event(&conn, "p1", "api.openai.com", &later);

    match verify::check_traffic(&conn, &mut setup).unwrap() {
        WatchStatus::Observed {
            exchange,
            freshness,
        } => {
            assert_eq!(setup.state, TrackingState::TrafficObserved);
            assert_eq!(freshness.len(), 1);
            assert_eq!(freshness[0].provider_id, "openai");
            assert!(freshness[0].last_observed_at.is_some());
            let ex = exchange.expect("latest exchange");
            assert_eq!(ex.host, "api.openai.com");
            assert_eq!(ex.latency_ms, Some(201));
        }
        other => panic!("expected Observed, got {other:?}"),
    }
    assert_eq!(setup.first_traffic_at.as_deref(), Some(later.as_str()));
}

/// Clock honesty: traffic recorded BEFORE apply belongs to an earlier
/// setup and never verifies this one.
#[test]
fn pre_existing_traffic_never_verifies_a_new_setup() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    // Old traffic first.
    insert_gateway_event(&conn, "p1", "api.openai.com", "2000-01-01T00:00:00Z");
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

    state::refresh(&conn, &mut setup).unwrap();
    assert_eq!(
        setup.state,
        TrackingState::AwaitingFirstRequest,
        "an event before applied_at must not verify the setup"
    );
    assert!(setup.first_traffic_at.is_none());
}

#[test]
fn partial_observation_is_derived_per_provider() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    let mut setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(&conn, &setup.id, &summary(&["openai", "anthropic"])).unwrap();
    setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();

    insert_gateway_event(&conn, "p1", "api.openai.com", &just_after_apply());
    let freshness = state::refresh(&conn, &mut setup).unwrap();
    assert_eq!(setup.state, TrackingState::PartiallyObserved);
    let openai = freshness
        .iter()
        .find(|f| f.provider_id == "openai")
        .unwrap();
    let anthropic = freshness
        .iter()
        .find(|f| f.provider_id == "anthropic")
        .unwrap();
    assert!(openai.last_observed_at.is_some());
    assert!(anthropic.last_observed_at.is_none());

    // The second provider arrives → full observation.
    insert_gateway_event(&conn, "p1", "api.anthropic.com", &just_after_apply());
    state::refresh(&conn, &mut setup).unwrap();
    assert_eq!(setup.state, TrackingState::TrafficObserved);
}

#[test]
fn another_projects_traffic_never_verifies_this_setup() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    insert_project(&conn, "p2", "two");
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

    insert_gateway_event(&conn, "p2", "api.openai.com", &just_after_apply());
    state::refresh(&conn, &mut setup).unwrap();
    assert_eq!(setup.state, TrackingState::AwaitingFirstRequest);
}

#[test]
fn custom_origin_hosts_map_through_the_route_table() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    // A custom supabase route (row only; MAC content irrelevant here).
    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, custom_origin,
             custom_origin_port, custom_origin_mac, custom_origin_consent_at, created_at, updated_at)
         VALUES ('supabase', 'supabase', 1, 'xyzcompany.supabase.example', 443, X'00',
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    let mut setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(&conn, &setup.id, &summary(&["supabase"])).unwrap();
    setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();

    // The host is NOT in the compiled-in host table (".example"), so only
    // the custom-route mapping can attribute it.
    insert_gateway_event(
        &conn,
        "p1",
        "xyzcompany.supabase.example",
        &just_after_apply(),
    );
    state::refresh(&conn, &mut setup).unwrap();
    assert_eq!(setup.state, TrackingState::TrafficObserved);
}

#[test]
fn unknown_state_strings_render_as_needs_attention_never_observed() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::NotConfigured,
        "{}",
    )
    .unwrap();
    conn.execute(
        "UPDATE tracking_setups SET state = 'future_state_from_newer_build' WHERE id = ?1",
        [&setup.id],
    )
    .unwrap();
    let loaded = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert_eq!(loaded.state, TrackingState::NeedsAttention);
}
