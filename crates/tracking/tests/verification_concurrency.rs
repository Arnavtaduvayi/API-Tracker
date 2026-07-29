//! `VER-01` regression suite: a refresh must never erase a newer failure.
//!
//! # The defect
//!
//! `refresh_with` takes a `TrackingSetup` the caller read earlier, decides
//! what the evidence supports, and writes that conclusion. At the audited
//! head the write was `UPDATE tracking_setups SET ... WHERE id = ?1` — no
//! predicate on what the row looked like when the decision was made — and
//! `failure_is_newer` was computed from the caller's **in-memory**
//! `attention_at`.
//!
//! So a failure recorded by another process *after* the reader loaded its
//! handle was invisible to the decision and then blindly overwritten with
//! NULL. The user saw `VerifiedAndActive` for a setup that was, at that
//! moment, broken. That is the `ZFT-006` outcome reached with no attacker, no
//! forged timestamp and no clock skew — just two processes, which on this
//! product means the desktop app and the CLI, or either of them and the
//! gateway service.
//!
//! WAL and `busy_timeout` do not help. Both transactions commit, in order,
//! and the second one is simply wrong: this is a lost update *across*
//! transactions, not contention within one.
//!
//! # How these tests are built
//!
//! Every test here uses **two connections on one `vault.db`**, because one
//! connection cannot express the race. Interleaving is deterministic: either
//! the test sequences the three steps by hand (read → competing write →
//! attempted write, which is exactly "process restart between read and
//! write"), or it uses a [`Barrier`] to release two real threads at the same
//! instant. No test sleeps to create a race, and none depends on which
//! thread happens to win — where both orders are legitimate, the assertion is
//! on the invariant that must hold either way.
//!
//! # The invariant
//!
//! A derived correction may only be committed if the row is still the one it
//! was derived from. `write_derived` therefore compares and swaps on
//! `row_version`; a concurrent change makes the write affect zero rows, and
//! `refresh_with` re-reads and re-derives rather than forcing it through.
//!
//! `control_removing_the_cas_predicate_reintroduces_the_lost_update` at the
//! bottom is the mutation check: it performs the write the way the audited
//! head did and asserts that the failure IS destroyed, so a future edit that
//! quietly drops the predicate cannot leave this file green.

mod common;

use api_tracker_core::clock;
use api_tracker_core::error::CoreError;
use api_tracker_tracking::state::{
    self, CurrentHealth, GatewayLiveness, PlanSummary, TrackingSetup, TrackingState,
};
use common::*;
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Barrier};

fn summary() -> PlanSummary {
    PlanSummary {
        providers: vec!["openai".into()],
        links: vec!["openai".into()],
        port: 49152,
        ..Default::default()
    }
}

/// Route + link rows, so `route_present` and `link_present` hold. Without
/// them a "still working" conclusion could never be reached and these tests
/// would pass for the wrong reason.
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

/// A setup applied two days ago, wired, with no observations yet.
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

/// `now` shifted back by `secs`.
fn ago(secs: i64) -> String {
    clock::rfc3339_minus_seconds(&clock::now_rfc3339(), secs)
}

/// An **admissible** observation: gateway-sourced, inside the freshness
/// window, after the apply watermark, and physically inserted after it.
///
/// This is the load-bearing difference from the RA-005 suite, where the
/// observation is future-dated and therefore excluded — with an inadmissible
/// observation `refresh_with` writes nothing at all and the failure survives
/// by accident rather than by design.
fn admissible_observation(conn: &Connection) {
    insert_gateway_event(conn, "p1", "api.openai.com", &ago(60));
}

fn reason_of(conn: &Connection, id: &str) -> Option<String> {
    state::get_setup(conn, id)
        .unwrap()
        .unwrap()
        .attention_reason
}

// ---------------------------------------------------------------------------
// The defect itself
// ---------------------------------------------------------------------------

/// The exact `VER-01` reproduction, sequenced by hand.
///
/// This is also the "process restart between read and write" case: the reader
/// holds a handle, the world moves on, and only then does the reader write.
#[test]
fn a_refresh_from_a_stale_handle_cannot_erase_a_failure_written_in_between() {
    let (_d, cli, path) = test_conn_at();
    let desktop = second_conn(&path);

    let mut stale = applied(&cli);
    admissible_observation(&cli);

    // The desktop's handle is taken BEFORE the failure exists — the ordinary
    // shape of a list-then-refresh loop, which reads every row up front.
    let mut desktop_handle = state::get_setup(&desktop, &stale.id).unwrap().unwrap();
    assert!(desktop_handle.attention_reason.is_none());

    // Meanwhile the CLI's repair attempt fails and records why.
    state::transition(
        &cli,
        &stale,
        TrackingState::NeedsAttention,
        Some("apply_failed:EnsureRoutes"),
    )
    .unwrap();
    stale = state::get_setup(&cli, &stale.id).unwrap().unwrap();

    // Now the desktop finishes deciding and writes. At the audited head this
    // nulled the reason and reported success.
    let report =
        state::refresh_with(&desktop, &mut desktop_handle, GatewayLiveness::Verified).unwrap();

    assert_eq!(
        reason_of(&cli, &stale.id).as_deref(),
        Some("apply_failed:EnsureRoutes"),
        "a failure recorded between the read and the write must survive it"
    );
    assert_ne!(
        report.current,
        CurrentHealth::VerifiedAndActive,
        "and the refresh must not report present-tense success over a live failure"
    );
    assert!(
        matches!(report.current, CurrentHealth::NeedsAttention { .. }),
        "the reported health must be the failure it re-read: {:?}",
        report.current
    );
}

/// The same race, run as two real threads released together.
///
/// Both interleavings are legitimate — whichever writer commits second is
/// working from a row it re-read — so the assertion is the invariant, not an
/// ordering: the failure must be present at the end, because it is the newest
/// news either way.
#[test]
fn a_failure_racing_a_successful_refresh_is_never_lost() {
    let (_d, setup_conn, path) = test_conn_at();
    let setup = applied(&setup_conn);
    admissible_observation(&setup_conn);
    let id = setup.id.clone();
    drop(setup_conn);

    let gate = Arc::new(Barrier::new(2));

    let refresher = {
        let (path, id, gate) = (path.clone(), id.clone(), Arc::clone(&gate));
        std::thread::spawn(move || {
            let conn = second_conn(&path);
            let mut handle = state::get_setup(&conn, &id).unwrap().unwrap();
            gate.wait();
            state::refresh_with(&conn, &mut handle, GatewayLiveness::Verified).unwrap();
        })
    };
    let failer = {
        let (path, id, gate) = (path.clone(), id.clone(), Arc::clone(&gate));
        std::thread::spawn(move || {
            let conn = second_conn(&path);
            let handle = state::get_setup(&conn, &id).unwrap().unwrap();
            gate.wait();
            // A losing CAS here is a legitimate outcome (the refresher moved
            // the row first); the failure is then recorded on a re-read.
            if state::transition(
                &conn,
                &handle,
                TrackingState::NeedsAttention,
                Some("apply_failed:EnsureRoutes"),
            )
            .is_err()
            {
                let fresh = state::get_setup(&conn, &id).unwrap().unwrap();
                state::transition(
                    &conn,
                    &fresh,
                    TrackingState::NeedsAttention,
                    Some("apply_failed:EnsureRoutes"),
                )
                .unwrap();
            }
        })
    };
    refresher.join().unwrap();
    failer.join().unwrap();

    let conn = second_conn(&path);
    assert_eq!(
        reason_of(&conn, &id).as_deref(),
        Some("apply_failed:EnsureRoutes"),
        "the failure is the newest news; no concurrent refresh may erase it"
    );
}

/// Two refreshes racing each other must converge, and neither may commit a
/// conclusion drawn from a row the other had already moved.
#[test]
fn two_concurrent_refreshes_converge_without_a_lost_update() {
    let (_d, setup_conn, path) = test_conn_at();
    let setup = applied(&setup_conn);
    admissible_observation(&setup_conn);
    let id = setup.id.clone();
    let start_version = setup.row_version;
    drop(setup_conn);

    let gate = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let (path, id, gate) = (path.clone(), id.clone(), Arc::clone(&gate));
        handles.push(std::thread::spawn(move || {
            let conn = second_conn(&path);
            let mut handle = state::get_setup(&conn, &id).unwrap().unwrap();
            gate.wait();
            state::refresh_with(&conn, &mut handle, GatewayLiveness::Verified)
                .unwrap()
                .current
        }));
    }
    let outcomes: Vec<CurrentHealth> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let conn = second_conn(&path);
    let final_row = state::get_setup(&conn, &id).unwrap().unwrap();
    assert_eq!(
        final_row.state,
        TrackingState::TrafficObserved,
        "both refreshes see the same evidence, so they must agree"
    );
    // Exactly one correction was persisted: the loser re-read, found the row
    // already where it wanted it, and wrote nothing.
    assert_eq!(
        final_row.row_version,
        start_version + 1,
        "a second, redundant write would mean the CAS did not hold"
    );
    for outcome in &outcomes {
        assert_eq!(
            *outcome,
            CurrentHealth::VerifiedAndActive,
            "both callers must report the converged truth"
        );
    }
}

/// The gateway dying while an observation is being refreshed must not leave a
/// present-tense success behind: liveness is part of the conclusion.
#[test]
fn gateway_death_racing_an_observation_never_reports_current_success() {
    let (_d, conn, path) = test_conn_at();
    let mut handle = applied(&conn);
    admissible_observation(&conn);
    let other = second_conn(&path);

    // The reader decided the gateway was up; by the time it writes, a second
    // observer has recorded that it is down.
    let mut down_handle = state::get_setup(&other, &handle.id).unwrap().unwrap();
    let down = state::refresh_with(&other, &mut down_handle, GatewayLiveness::Down).unwrap();
    assert_ne!(down.current, CurrentHealth::VerifiedAndActive);

    let report = state::refresh_with(&conn, &mut handle, GatewayLiveness::Down).unwrap();
    assert_ne!(
        report.current,
        CurrentHealth::VerifiedAndActive,
        "a dead gateway is never current health, whoever observed it first"
    );
}

/// Removing the route between the read and the write invalidates the
/// conclusion the reader formed.
#[test]
fn route_removal_racing_a_refresh_is_not_overwritten() {
    let (_d, conn, path) = test_conn_at();
    let mut handle = applied(&conn);
    admissible_observation(&conn);
    let other = second_conn(&path);

    other
        .execute(
            "DELETE FROM gateway_routes WHERE route_prefix = 'openai'",
            [],
        )
        .unwrap();

    let report = state::refresh_with(&conn, &mut handle, GatewayLiveness::Verified).unwrap();
    assert_ne!(
        report.current,
        CurrentHealth::VerifiedAndActive,
        "traffic that can no longer flow is not current health: {:?}",
        report.current
    );
}

/// Same, for the project link.
#[test]
fn link_removal_racing_a_refresh_is_not_overwritten() {
    let (_d, conn, path) = test_conn_at();
    let mut handle = applied(&conn);
    admissible_observation(&conn);
    let other = second_conn(&path);

    other
        .execute(
            "DELETE FROM gateway_project_links WHERE link_slug = 'slug-openai'",
            [],
        )
        .unwrap();

    let report = state::refresh_with(&conn, &mut handle, GatewayLiveness::Verified).unwrap();
    assert_ne!(
        report.current,
        CurrentHealth::VerifiedAndActive,
        "an unlinked project is not currently tracked: {:?}",
        report.current
    );
}

/// A re-apply opens a NEW verification session. A refresh still in flight
/// from the previous one must not commit its conclusion over it.
#[test]
fn a_setup_generation_change_invalidates_an_in_flight_refresh() {
    let (_d, conn, path) = test_conn_at();
    let mut stale_handle = applied(&conn);
    admissible_observation(&conn);
    let generation_before = stale_handle.config_generation;

    // Another process starts a fresh attempt on the same folder.
    let other = second_conn(&path);
    state::upsert_setup(
        &other,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::Applying,
        "{}",
    )
    .unwrap();

    state::refresh_with(&conn, &mut stale_handle, GatewayLiveness::Verified).unwrap();

    let row = state::get_setup(&conn, &stale_handle.id).unwrap().unwrap();
    assert!(
        row.config_generation > generation_before,
        "the new session must still be the one on record"
    );
    assert_ne!(
        row.state,
        TrackingState::TrafficObserved,
        "the previous session's traffic must not verify the new attempt"
    );
    assert!(
        row.applied_at.is_none(),
        "a re-apply clears the watermark; a stale refresh must not restore a verified look"
    );
}

/// An observation belonging to a CLOSED session, racing a refresh opened
/// under the new one, cannot verify it.
#[test]
fn an_old_verification_session_cannot_verify_the_new_one() {
    let (_d, conn, path) = test_conn_at();
    let first = applied(&conn);
    admissible_observation(&conn);
    let session_before = first.verification_session.clone();

    let other = second_conn(&path);
    let mut reopened = state::upsert_setup(
        &other,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(&other, &mut reopened, &summary()).unwrap();
    assert_ne!(
        reopened.verification_session, session_before,
        "a re-apply must mint a new session"
    );

    let mut handle = state::get_setup(&conn, &reopened.id).unwrap().unwrap();
    let report = state::refresh_with(&conn, &mut handle, GatewayLiveness::Verified).unwrap();
    assert_ne!(
        report.current,
        CurrentHealth::VerifiedAndActive,
        "traffic recorded before this session's apply is not evidence for it: {:?}",
        report.current
    );
}

/// The product's two front ends refreshing the same row at the same instant.
/// This is the concrete pairing `VER-01` describes; it must be safe.
#[test]
fn desktop_and_cli_refreshing_together_agree_and_lose_nothing() {
    let (_d, setup_conn, path) = test_conn_at();
    let setup = applied(&setup_conn);
    admissible_observation(&setup_conn);
    let id = setup.id.clone();
    // The failure is the newest news: recorded after the observation.
    state::transition(
        &setup_conn,
        &setup,
        TrackingState::NeedsAttention,
        Some("gateway_unreachable"),
    )
    .unwrap();
    drop(setup_conn);

    let gate = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let (path, id, gate) = (path.clone(), id.clone(), Arc::clone(&gate));
        threads.push(std::thread::spawn(move || {
            let conn = second_conn(&path);
            let mut handle = state::get_setup(&conn, &id).unwrap().unwrap();
            gate.wait();
            state::refresh_with(&conn, &mut handle, GatewayLiveness::Verified)
                .unwrap()
                .current
        }));
    }
    for t in threads {
        let health = t.join().unwrap();
        assert!(
            matches!(health, CurrentHealth::NeedsAttention { .. }),
            "neither front end may report success over a newer failure: {health:?}"
        );
    }

    let conn = second_conn(&path);
    assert_eq!(
        reason_of(&conn, &id).as_deref(),
        Some("gateway_unreachable"),
        "and the reason survives both refreshes"
    );
}

// ---------------------------------------------------------------------------
// The guard itself
// ---------------------------------------------------------------------------

/// An explicit transition decided from a stale snapshot is refused, not
/// silently applied. `refresh_with` retries such conflicts internally;
/// `transition` deliberately does not, because its legality check encodes an
/// intent that has to be re-judged against the new state.
#[test]
fn an_explicit_transition_from_a_stale_snapshot_is_refused() {
    let (_d, conn, path) = test_conn_at();
    let stale = applied(&conn);
    let other = second_conn(&path);

    state::transition(&other, &stale, TrackingState::NeedsAttention, Some("first")).unwrap();

    let err = state::transition(
        &conn,
        &stale,
        TrackingState::NeedsAttention,
        Some("second, from a snapshot that predates the first"),
    )
    .expect_err("a write decided from a superseded row must not commit");
    assert!(
        matches!(err, CoreError::StateConflict { .. }),
        "the conflict must be reported as one, not as a generic failure: {err}"
    );
    assert_eq!(
        reason_of(&conn, &stale.id).as_deref(),
        Some("first"),
        "and the row must be untouched by the refused write"
    );
}

/// The token moves on every health write, which is what makes the guard work.
#[test]
fn every_health_write_advances_the_row_version() {
    let (_d, conn) = test_conn();
    let setup = applied(&conn);
    let v0 = setup.row_version;

    let after = state::transition(&conn, &setup, TrackingState::NeedsAttention, Some("x")).unwrap();
    assert_eq!(after.row_version, v0 + 1);

    let again = state::transition(&conn, &after, TrackingState::Applying, None).unwrap();
    assert_eq!(again.row_version, v0 + 2);
}

/// An apply failure must reach the row even when the row moved underneath the
/// attempt.
///
/// `apply`'s failure path re-reads the setup and then transitions. Because
/// `transition` is a CAS that does not retry on its own, a concurrent write in
/// that window would make the write a no-op — and swallowing it would trade the
/// pre-CAS defect (force the write, clobber newer state) for its mirror image:
/// silently losing the record that an apply failed. That is the ZFT-006 outcome
/// by omission rather than by overwrite, so the failure path retries.
///
/// This drives the same shape directly: take a snapshot, let someone else move
/// the row, then record the failure the way `apply` does.
#[test]
fn an_apply_failure_is_recorded_even_when_the_row_moved_first() {
    let (_d, conn, path) = test_conn_at();
    let setup = applied(&conn);
    let other = second_conn(&path);

    // Somebody else moves the row after our snapshot was taken.
    state::transition(&other, &setup, TrackingState::NeedsAttention, Some("other")).unwrap();

    // The apply failure path: re-read, transition, retry on conflict.
    let reason = "apply_failed:EnsureService";
    let mut recorded = false;
    for _ in 0..3 {
        let fresh = state::get_setup(&conn, &setup.id).unwrap().unwrap();
        match state::transition(&conn, &fresh, TrackingState::NeedsAttention, Some(reason)) {
            Err(CoreError::StateConflict { .. }) => continue,
            Ok(_) => {
                recorded = true;
                break;
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert!(recorded, "the failure must reach the row");
    assert_eq!(
        reason_of(&conn, &setup.id).as_deref(),
        Some(reason),
        "an apply failure must not be lost to a concurrent write"
    );
}

/// Mutation control for the whole file.
///
/// It performs the write the way the audited head did — no predicate on the
/// row's version — and asserts the failure IS destroyed. If someone removes
/// the CAS from `write_derived`, the tests above stop failing only if this
/// one also stops passing, so the guard cannot be deleted quietly.
#[test]
fn control_removing_the_cas_predicate_reintroduces_the_lost_update() {
    let (_d, conn) = test_conn();
    let setup = applied(&conn);
    admissible_observation(&conn);

    state::transition(
        &conn,
        &setup,
        TrackingState::NeedsAttention,
        Some("apply_failed:EnsureRoutes"),
    )
    .unwrap();
    assert_eq!(
        reason_of(&conn, &setup.id).as_deref(),
        Some("apply_failed:EnsureRoutes")
    );

    // The audited head's statement, verbatim in shape: `WHERE id = ?1`, with
    // the values a refresh holding the pre-failure handle would have derived.
    conn.execute(
        "UPDATE tracking_setups
         SET state = ?2, last_transition_at = ?3, attention_reason = NULL, attention_at = NULL
         WHERE id = ?1",
        rusqlite::params![
            setup.id,
            TrackingState::TrafficObserved.as_str(),
            clock::now_rfc3339()
        ],
    )
    .unwrap();

    assert_eq!(
        reason_of(&conn, &setup.id),
        None,
        "this is what an unguarded write does — the tests above exist because it does it"
    );
}
