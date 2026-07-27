//! ZFT-007 regression suite: `track undo` after a failed apply must not
//! report success while leaving the project pointed at the gateway.
//!
//! The audit's harness recorded:
//!
//! ```text
//! A: failed step = PathCheck
//! A: .env rewritten by failed apply = true
//! A: undo.complete = true, links_restored = 0, routes_removed = []
//! A: .env restored to original = false
//! A: leftover routes = 2, leftover links = 2
//! A: .env still points at gateway = true
//! ```
//!
//! The plan summary is written at the LAST apply step, so any earlier
//! failure left it NULL — and undo read it with `.unwrap_or_default()`,
//! turning "we do not know what was done" into "nothing was done". Both
//! loops iterated empty collections, `complete` stayed `true`, the row was
//! moved to `not_configured`, and the CLI printed "Tracking stopped."

mod common;

use api_tracker_tracking::state::{self, PlanSummary, TrackingState};
use api_tracker_tracking::undo;
use common::*;
use rusqlite::Connection;
use std::path::Path;

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
            (link_slug, project_id, route_prefix, env_path, prior_env_json, created_at)
         VALUES (?1, ?2, ?3, '/tmp/fixture/.env',
                 '{\"v\":1,\"port\":49152,\"files\":[]}', '2099-01-01T00:00:00Z')",
        [&format!("slug-{provider}"), project_id, provider],
    )
    .unwrap();
}

#[test]
fn undo_refuses_to_report_success_when_the_plan_was_never_recorded() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::Applying,
        "{}",
    )
    .unwrap();
    // Exactly the failed-apply shape: routes and links exist, the plan
    // summary was never written because apply died before step 10.
    wire_route_and_link(&conn, "p1", "openai");
    wire_route_and_link(&conn, "p1", "anthropic");
    let setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert!(setup.plan_summary_json.is_none());

    let report = undo::undo(&conn, &setup).unwrap();

    assert!(
        !report.complete,
        "undo must NOT claim completion when it cannot know what apply did"
    );
    assert!(
        !report.notes.is_empty(),
        "an incomplete undo must say why, in the user's own vocabulary"
    );
    assert!(
        report.notes.iter().any(|n| n.contains("routes")),
        "the note must tell the user what was left behind: {:?}",
        report.notes
    );

    // The row must land in a state that keeps asking for attention, not in
    // `not_configured` — which is what made the CLI print "Tracking stopped."
    let after = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert_eq!(after.state, TrackingState::NeedsAttention);
    assert_eq!(
        after.attention_reason.as_deref(),
        Some("undo_incomplete_plan_unknown")
    );
}

#[test]
fn undo_restores_links_it_finds_in_the_database_even_without_a_summary() {
    // Ground truth over bookkeeping: `gateway_project_links` rows carry the
    // recorded prior `.env` state, so the links a project holds are
    // authoritative regardless of what the summary says.
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::Applying,
        "{}",
    )
    .unwrap();
    wire_route_and_link(&conn, "p1", "openai");
    let setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();

    let report = undo::undo(&conn, &setup).unwrap();
    assert!(
        !report.links.is_empty(),
        "undo must attempt the links the database knows about, not the empty \
         set a missing summary defaults to"
    );
}

#[test]
fn a_complete_undo_still_reports_success_and_closes_the_session() {
    // The control: the fix must not turn every undo into a refusal.
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    // A properly recorded apply with nothing left to restore.
    state::record_applied(
        &conn,
        &setup.id,
        &PlanSummary {
            providers: vec!["openai".into()],
            port: 49152,
            ..Default::default()
        },
    )
    .unwrap();
    let setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();

    let report = undo::undo(&conn, &setup).unwrap();
    assert!(report.complete, "a fully recorded undo must complete");
    assert!(report.notes.is_empty());

    let after = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert_eq!(after.state, TrackingState::NotConfigured);
    assert!(
        after.applied_at.is_none() && after.plan_summary_json.is_none(),
        "a completed undo clears the apply artifacts"
    );
    assert!(
        after.verification_session.is_none(),
        "a completed undo closes the verification session, so nothing observed \
         under it can verify a later setup"
    );
}

#[test]
fn an_incomplete_undo_keeps_the_apply_watermark_so_status_stays_honest() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::Applying,
        "{}",
    )
    .unwrap();
    state::record_applied(
        &conn,
        &setup.id,
        &PlanSummary {
            providers: vec!["openai".into()],
            port: 49152,
            ..Default::default()
        },
    )
    .unwrap();
    // Then blank the summary, as a mid-apply crash would leave it, while
    // the links survive.
    conn.execute(
        "UPDATE tracking_setups SET plan_summary_json = NULL WHERE id = ?1",
        [&setup.id],
    )
    .unwrap();
    wire_route_and_link(&conn, "p1", "openai");
    let setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();

    let report = undo::undo(&conn, &setup).unwrap();
    assert!(!report.complete);
    let after = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert!(
        after.applied_at.is_some(),
        "an incomplete undo must NOT clear the watermark — status has to stay \
         able to tell the truth about a setup that is still partly in effect"
    );
}

/// ZFT-018 — a re-apply must not destroy route provenance.
///
/// On a second apply, `routes::add_manifest_route` returns AlreadyExists and
/// the run records the route as "reused", so `created_routes` came back
/// empty. A later undo then left the route in place with the false reason
/// "existed before this setup (only reused)" — a route this setup really
/// had created.
#[test]
fn a_re_apply_keeps_the_first_applys_route_provenance() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");

    // First apply: the setup CREATED the route.
    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(
        &conn,
        &setup.id,
        &PlanSummary {
            providers: vec!["openai".into()],
            created_routes: vec!["openai".into()],
            port: 49152,
            ..Default::default()
        },
    )
    .unwrap();

    // A second apply opens a new session, which clears the summary — so the
    // provenance has to be carried across explicitly.
    let prior = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    let carried = state::plan_summary_of(&prior).created_routes;
    assert_eq!(
        carried,
        vec!["openai".to_string()],
        "the previous apply's created_routes must be readable before the new \
         session clears them"
    );

    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::Applying,
        "{}",
    )
    .unwrap();
    // What apply now records: this run saw the route as pre-existing, but the
    // union keeps the true answer.
    let mut created: Vec<String> = Vec::new();
    for prefix in carried {
        if !created.contains(&prefix) {
            created.push(prefix);
        }
    }
    state::record_applied(
        &conn,
        &setup.id,
        &PlanSummary {
            providers: vec!["openai".into()],
            created_routes: created,
            reused_routes: Vec::new(),
            port: 49152,
            ..Default::default()
        },
    )
    .unwrap();

    let after = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    let summary = state::plan_summary_of(&after);
    assert_eq!(
        summary.created_routes,
        vec!["openai".to_string()],
        "a route this setup created on an earlier apply is still one it created"
    );
    assert!(
        summary.reused_routes.is_empty(),
        "and it must not ALSO be listed as merely reused: {:?}",
        summary.reused_routes
    );
}

/// ZFT-019 — undo must return a route it re-enabled to its prior disabled
/// state.
///
/// A user who deliberately disables a route and then runs `track` had that
/// route turned back on and left on: the apply loop recorded
/// `Ok("re-enabled")` through the same arm as "reused", so the summary
/// never said the flag had changed, and undo had nothing to restore.
#[test]
fn undo_returns_a_re_enabled_route_to_disabled() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    // The route exists but the user turned it OFF.
    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, created_at, updated_at)
         VALUES ('openai', 'openai', 0, '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z')",
        [],
    )
    .unwrap();

    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    // What apply records when it re-enables an existing, disabled route.
    state::record_applied(
        &conn,
        &setup.id,
        &PlanSummary {
            providers: vec!["openai".into()],
            re_enabled_routes: vec!["openai".into()],
            port: 49152,
            ..Default::default()
        },
    )
    .unwrap();
    conn.execute(
        "UPDATE gateway_routes SET enabled = 1 WHERE route_prefix = 'openai'",
        [],
    )
    .unwrap();
    let setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();

    let report = undo::undo(&conn, &setup).unwrap();
    assert!(report.complete);

    let enabled: i64 = conn
        .query_row(
            "SELECT enabled FROM gateway_routes WHERE route_prefix = 'openai'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        enabled, 0,
        "a route this setup re-enabled must go back to the state the user left it in"
    );
    assert!(
        report
            .kept_routes
            .iter()
            .any(|(p, why)| p == "openai" && why.contains("disabled")),
        "and the user must be told: {:?}",
        report.kept_routes
    );

    // The route ROW itself survives — undo restores the flag, it does not
    // delete a route that existed before this setup.
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM gateway_routes WHERE route_prefix = 'openai'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1);
}

/// The control: a route another project still links must NOT be disabled by
/// this project's undo, or one project's teardown breaks another's traffic.
#[test]
fn undo_does_not_disable_a_re_enabled_route_another_project_still_links() {
    let (_db, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    insert_project(&conn, "p2", "two");
    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, created_at, updated_at)
         VALUES ('openai', 'openai', 1, '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    // A DIFFERENT project links it.
    conn.execute(
        "INSERT INTO gateway_project_links (link_slug, project_id, route_prefix, created_at)
         VALUES ('slug-other', 'p2', 'openai', '2099-01-01T00:00:00Z')",
        [],
    )
    .unwrap();

    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(
        &conn,
        &setup.id,
        &PlanSummary {
            providers: vec!["openai".into()],
            re_enabled_routes: vec!["openai".into()],
            port: 49152,
            ..Default::default()
        },
    )
    .unwrap();
    let setup = state::get_setup(&conn, &setup.id).unwrap().unwrap();

    undo::undo(&conn, &setup).unwrap();
    let enabled: i64 = conn
        .query_row(
            "SELECT enabled FROM gateway_routes WHERE route_prefix = 'openai'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        enabled, 1,
        "another project still links this route; disabling it would break their traffic"
    );
}
