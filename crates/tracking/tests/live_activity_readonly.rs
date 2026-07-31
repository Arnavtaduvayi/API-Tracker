//! The five-second activity poll writes nothing (`AUD-03`), and the project
//! overview's status is the resolver's answer projected once (`AUD-05`).
//!
//! # AUD-03
//!
//! `project_activity` used to call `project::note_activity_refresh` after every
//! read, which compare-and-swapped `last_activity_refresh_at` on
//! `project_folder_links` and incremented `row_version` — twelve guarded writes
//! a minute per open project page, for a column nothing read. `row_version` is
//! the token that guards Disable tracking, Rescan and the applied-generation
//! record, so a poll landing between a caller's read and its write made that
//! caller fail with a raw `StateConflict` for no product reason.
//!
//! The tests below dump the durable configuration tables before and after a run
//! of polls and require the bytes to be identical.
//!
//! # AUD-05
//!
//! `project::overview` now projects the resolver's report into
//! `statusview::TrackingStatusView`. These tests drive the REAL resolver
//! (`state::refresh_with`) into each state and assert the projection, so the
//! chain "resolver → projection → what a screen renders" is covered end to end
//! rather than only at its ends.

mod common;

use std::path::Path;

use api_tracker_core::projectactivity::ActivityFilter;
use api_tracker_core::projectlink;
use api_tracker_tracking::project::{self, TimeRange};
use api_tracker_tracking::state::{
    self, CurrentHealth, GatewayLiveness, PlanSummary, TrackingState,
};
use api_tracker_tracking::statusview::{StatusContext, TrackingStatusView};
use common::*;
use rusqlite::Connection;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

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

/// An applied setup for `folder`, with its route and link present and its apply
/// backdated so a fresh observation can sit after the watermark.
fn applied_setup(conn: &Connection, folder: &Path) -> state::TrackingSetup {
    let mut setup = state::upsert_setup(
        conn,
        "p1",
        folder,
        TrackingState::AwaitingFirstRequest,
        "{}",
    )
    .unwrap();
    state::record_applied(conn, &mut setup, &summary(&["openai"])).unwrap();
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

fn recent() -> String {
    api_tracker_core::clock::rfc3339_minus_seconds(&api_tracker_core::clock::now_rfc3339(), 60)
}

/// Every row of a table, ordered, as one string. Byte-for-byte comparable.
fn dump(conn: &Connection, table: &str) -> String {
    let cols: Vec<String> = conn
        .prepare(&format!("SELECT * FROM {table} LIMIT 0"))
        .unwrap()
        .column_names()
        .into_iter()
        .map(str::to_string)
        .collect();
    let select = cols
        .iter()
        .map(|c| format!("COALESCE(CAST(\"{c}\" AS TEXT), '<null>')"))
        .collect::<Vec<_>>()
        .join(" || '|' || ");
    let mut stmt = conn
        .prepare(&format!("SELECT {select} AS row FROM {table} ORDER BY 1"))
        .unwrap();
    let rows: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    format!("{table}[{}]\n{}", cols.join(","), rows.join("\n"))
}

/// The tables that hold durable tracking configuration. A read must not move a
/// byte of any of them.
const DURABLE: [&str; 4] = [
    "project_folder_links",
    "tracking_setups",
    "gateway_routes",
    "gateway_project_links",
];

fn durable_state(conn: &Connection) -> String {
    DURABLE
        .iter()
        .map(|t| dump(conn, t))
        .collect::<Vec<_>>()
        .join("\n---\n")
}

// ---------------------------------------------------------------------------
// AUD-03 — polling is read-only
// ---------------------------------------------------------------------------

/// Fifty polls leave the durable tracking configuration byte-for-byte
/// unchanged, including `project_folder_links.row_version`.
///
/// Fifty is a little over four minutes of a page left open at the shipped
/// five-second cadence.
#[test]
fn repeated_polling_leaves_durable_tracking_configuration_unchanged() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = tempfile::TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let folder = dir.path().display().to_string();
    projectlink::upsert_link(&conn, "p1", &folder).unwrap();
    applied_setup(&conn, dir.path());
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());

    let before = durable_state(&conn);
    let link_before = projectlink::get_link(&conn, "p1").unwrap().unwrap();
    assert_eq!(link_before.row_version, 0);

    for _ in 0..50 {
        project::activity_only(
            &conn,
            "p1",
            TimeRange::Last24Hours,
            &ActivityFilter::default(),
            50,
        )
        .unwrap();
    }

    let after = durable_state(&conn);
    assert_eq!(
        before, after,
        "AUD-03: reading activity must not move a byte of the durable tracking \
         configuration"
    );
    let link_after = projectlink::get_link(&conn, "p1").unwrap().unwrap();
    assert_eq!(
        link_after.row_version, 0,
        "AUD-03: `row_version` is the compare-and-swap token that guards Disable \
         tracking and Rescan; a poll must not consume it"
    );
    assert_eq!(link_before, link_after);
    let _ = tmp;
}

/// A control action taken while the page is polling still succeeds.
///
/// This is the user-visible half of `AUD-03`: the reproduction held a link read
/// one tick earlier and got `StateConflict` from `set_tracking_enabled` because
/// the poll had bumped `row_version` underneath it.
#[test]
fn a_control_action_survives_a_page_that_is_polling() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = tempfile::TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let folder = dir.path().display().to_string();
    projectlink::upsert_link(&conn, "p1", &folder).unwrap();

    // What a UI holds: a link read before the user clicked anything.
    let mut held = projectlink::get_link(&conn, "p1").unwrap().unwrap();

    // Ten ticks land between that read and the click.
    for _ in 0..10 {
        project::activity_only(
            &conn,
            "p1",
            TimeRange::Last24Hours,
            &ActivityFilter::default(),
            50,
        )
        .unwrap();
    }

    projectlink::set_tracking_enabled(&conn, &mut held, false).expect(
        "AUD-03: a Disable that raced the activity poll used to fail with a raw \
         StateConflict",
    );
    assert!(
        !projectlink::get_link(&conn, "p1")
            .unwrap()
            .unwrap()
            .tracking_enabled
    );
    let _ = tmp;
}

/// The write really is gone from the code, not merely unobserved by the tests
/// above.
#[test]
fn nothing_stamps_the_activity_refresh_column_any_more() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let projectlink_rs = std::fs::read_to_string(root.join("core/src/projectlink.rs")).unwrap();
    assert!(
        !projectlink_rs.contains("pub fn record_activity_refresh"),
        "AUD-03: the stamping function must be gone, not just uncalled"
    );
    assert!(
        !projectlink_rs.contains("SET last_activity_refresh_at ="),
        "AUD-03: nothing may write `last_activity_refresh_at`"
    );
    let main_rs = std::fs::read_to_string(
        root.parent()
            .unwrap()
            .join("apps/desktop/src-tauri/src/main.rs"),
    )
    .unwrap();
    assert!(
        !main_rs.contains("note_activity_refresh"),
        "AUD-03: `project_activity` must be read-only"
    );
    // The COLUMN stays: existing vaults hold values for it, and dropping a
    // column to remove a write would break the data format for nothing.
    assert!(projectlink_rs.contains("pub last_activity_refresh_at: Option<String>"));
}

// ---------------------------------------------------------------------------
// AUD-05 — the real resolver, projected
// ---------------------------------------------------------------------------

/// The end-to-end chain for the headline state: a real applied setup, a real
/// fresh observation, a real `refresh_with` with the gateway answering, and the
/// projection a screen renders.
///
/// The audited page could not reach this outcome for any input.
#[test]
fn a_verified_and_active_setup_projects_to_tracking_is_on() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let mut setup = applied_setup(&conn, Path::new("/tmp/fixture"));
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(
        report.current,
        CurrentHealth::VerifiedAndActive,
        "precondition: the resolver must consider this healthy"
    );

    let view = TrackingStatusView::of(
        Some(&report),
        &StatusContext {
            linked: true,
            tracking_enabled: true,
            ..Default::default()
        },
    );
    assert_eq!(view.label, "Tracking is on");
    assert!(view.is_working);
    assert!(
        view.action.is_none(),
        "a healthy project is not asked to do anything"
    );
    assert!(
        view.last_observed_at.is_some(),
        "the observation is carried for display"
    );
}

/// The same setup with the gateway not answering: the projection changes, and
/// the observation recorded a minute ago does not keep it "on".
#[test]
fn the_same_setup_with_a_dead_gateway_projects_to_gateway_unavailable() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let mut setup = applied_setup(&conn, Path::new("/tmp/fixture"));
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    // Verify first, so `first_verified_at` is set and the history is real.
    state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();

    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Down).unwrap();
    let view = TrackingStatusView::of(
        Some(&report),
        &StatusContext {
            linked: true,
            tracking_enabled: true,
            ..Default::default()
        },
    );
    assert_eq!(view.label, "Gateway unavailable");
    assert!(!view.is_working);
    assert!(view.first_verified_at.is_some(), "history survives");
    assert!(
        view.last_observed_at.is_some(),
        "and so does the observation — which must not make it healthy"
    );
    assert!(view.action.is_some());
}

/// A route removed after verification projects to `Route unavailable`, not to a
/// generic configuration change and not to "tracking is on".
#[test]
fn a_removed_route_projects_to_route_unavailable() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let mut setup = applied_setup(&conn, Path::new("/tmp/fixture"));
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();

    // Disabled rather than deleted: deleting the route cascades to the project
    // link, which is the BOTH-gone case and a different state. A route the user
    // turned off is the one this test is about.
    conn.execute(
        "UPDATE gateway_routes SET enabled = 0 WHERE route_prefix = 'openai'",
        [],
    )
    .unwrap();
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(
        matches!(
            report.current,
            CurrentHealth::ConfigurationChanged {
                route_missing: true,
                link_missing: false,
                ..
            }
        ),
        "expected a route-only change, got {:?}",
        report.current
    );

    let view = TrackingStatusView::of(
        Some(&report),
        &StatusContext {
            linked: true,
            tracking_enabled: true,
            ..Default::default()
        },
    );
    assert_eq!(view.label, "Route unavailable");
    assert!(!view.is_working);
}

/// A project link removed after verification projects to `Project link
/// unavailable` — a different state with a different action.
#[test]
fn a_removed_project_link_projects_to_project_link_unavailable() {
    let (_tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let mut setup = applied_setup(&conn, Path::new("/tmp/fixture"));
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());
    state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();

    conn.execute(
        "DELETE FROM gateway_project_links WHERE route_prefix = 'openai'",
        [],
    )
    .unwrap();
    let report = state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert!(matches!(
        report.current,
        CurrentHealth::ConfigurationChanged {
            route_missing: false,
            link_missing: true,
            ..
        }
    ));

    let view = TrackingStatusView::of(
        Some(&report),
        &StatusContext {
            linked: true,
            tracking_enabled: true,
            ..Default::default()
        },
    );
    assert_eq!(view.label, "Project link unavailable");
}

// ---------------------------------------------------------------------------
// `project::overview` end to end
// ---------------------------------------------------------------------------

/// A project with no folder is a STATE, not a null.
#[test]
fn an_unlinked_project_overview_still_carries_a_tracking_state() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let o = project::overview(&conn, tmp.path(), "p1").unwrap();
    assert!(o.link.is_none());
    assert!(o.status.is_none());
    assert_eq!(o.tracking.label, "No folder selected");
    assert!(!o.tracking.is_working);
    assert!(o.tracking.action.is_some());
    assert!(
        o.folder_available,
        "there is no missing folder to report for a project that never chose one"
    );
}

/// A linked folder with no setup yet reads "Waiting for setup", not "needs
/// attention".
#[test]
fn a_linked_folder_with_no_setup_is_awaiting_setup() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = tempfile::TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    projectlink::upsert_link(&conn, "p1", &dir.path().display().to_string()).unwrap();

    let o = project::overview(&conn, tmp.path(), "p1").unwrap();
    assert!(o.status.is_none());
    assert_eq!(o.tracking.label, "Waiting for setup");
    assert!(o.folder_available);
    assert!(!o.scan_stale, "never scanned is not stale");
}

/// Tracking switched off is reported as off, and is not a fault.
#[test]
fn a_disabled_project_reads_as_tracking_off() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = tempfile::TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let mut link =
        projectlink::upsert_link(&conn, "p1", &dir.path().display().to_string()).unwrap();
    projectlink::set_tracking_enabled(&conn, &mut link, false).unwrap();

    let o = project::overview(&conn, tmp.path(), "p1").unwrap();
    assert_eq!(o.tracking.label, "Tracking is off");
    assert!(
        !o.tracking.state.is_fault(),
        "a project the user switched off is not a fault to style as one"
    );
}

/// A folder that is no longer there is reported as missing — and NOT as
/// "your files changed since the last scan", which is the sentence the audited
/// build produced and which offers a Rescan that fails.
#[test]
fn a_deleted_folder_reports_as_missing_not_as_edited() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = tempfile::TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let folder = dir.path().to_path_buf();
    let mut link = projectlink::upsert_link(&conn, "p1", &folder.display().to_string()).unwrap();
    let fingerprint = project::folder_fingerprint(&folder);
    projectlink::record_scan(&conn, &mut link, Some(&fingerprint)).unwrap();

    // Scanned and present: nothing to report.
    let before = project::overview(&conn, tmp.path(), "p1").unwrap();
    assert!(before.folder_available);
    assert!(!before.scan_stale);

    drop(dir);

    let after = project::overview(&conn, tmp.path(), "p1").unwrap();
    assert!(
        !after.folder_available,
        "the folder is gone and the overview must say so"
    );
    assert!(
        !after.scan_stale,
        "AUD-06: a folder that is not there did not have its files edited, and \
         offering a Rescan for it produces a raw filesystem error"
    );
    assert_eq!(after.tracking.label, "Folder missing");
    assert!(after
        .tracking
        .action
        .as_deref()
        .is_some_and(|a| a.contains("unlink") || a.contains("Choose the folder again")));
    assert!(
        after.link.is_some(),
        "the association is NOT lost — the folder is only unreadable"
    );
    assert_eq!(
        after.link.unwrap().folder_path,
        folder.display().to_string()
    );
}

/// A folder whose manifests really did change is still reported as stale.
///
/// The negative control for the test above: suppressing the stale notice for a
/// missing folder must not suppress it for a present one.
#[test]
fn an_edited_folder_is_still_reported_as_stale() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = tempfile::TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    let mut link =
        projectlink::upsert_link(&conn, "p1", &dir.path().display().to_string()).unwrap();
    projectlink::record_scan(&conn, &mut link, Some("a-fingerprint-from-before")).unwrap();

    let o = project::overview(&conn, tmp.path(), "p1").unwrap();
    assert!(o.folder_available);
    assert!(o.scan_stale, "the manifests differ from the recorded scan");
}

/// The overview re-resolves health rather than reading the cached row.
///
/// This is what makes a manual Refresh worth running (`AUD-08`): the cached
/// `tracking_setups.state` column survives the service being stopped, so a
/// surface that read it would report a project as tracking after the gateway
/// died.
#[test]
fn the_overview_re_resolves_health_instead_of_reading_the_cached_row() {
    let (tmp, conn) = test_conn();
    insert_project(&conn, "p1", "web");
    let dir = tempfile::TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    projectlink::upsert_link(&conn, "p1", &dir.path().display().to_string()).unwrap();
    let mut setup = applied_setup(&conn, dir.path());
    insert_gateway_event(&conn, "p1", "api.openai.com", &recent());

    // Drive the cached row to its most optimistic value with the gateway up.
    state::refresh_with(&conn, &mut setup, GatewayLiveness::Verified).unwrap();
    assert_eq!(
        state::get_setup(&conn, &setup.id).unwrap().unwrap().state,
        TrackingState::TrafficObserved
    );

    // `overview` probes liveness itself, and there is no gateway in a test, so
    // the honest answer is "not working" — despite the cached row.
    let o = project::overview(&conn, tmp.path(), "p1").unwrap();
    assert!(
        !o.tracking.is_working,
        "AUD-08/ZFT-005: the cached row says traffic was observed; nothing is \
         listening, so present-tense health must not"
    );
    assert!(
        o.tracking.first_verified_at.is_some(),
        "the history is still reported, beside the present-tense answer"
    );
    assert!(o.status.is_some(), "the raw report is still available");
}
