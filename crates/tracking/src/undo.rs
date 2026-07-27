//! Track-scoped teardown: restore exactly what `track` changed, keep
//! everything else. Recorded history is never touched (it's the user's
//! data), and routes another project still links stay in place.

use api_tracker_core::{audit, CoreError, Result};
use api_tracker_gateway::{envlink, routes};
use rusqlite::Connection;
use serde::Serialize;

use crate::state::{self, PlanSummary, TrackingSetup, TrackingState};

#[derive(Debug, Clone, Serialize)]
pub struct UndoReport {
    /// Per-link restore reports (envlink's exact-restore semantics:
    /// restored / left-your-edit / already-restored per variable).
    pub links: Vec<envlink::UnlinkReport>,
    pub removed_routes: Vec<String>,
    /// Routes kept, with the reason (another project links them, or this
    /// setup only reused them).
    pub kept_routes: Vec<(String, String)>,
    pub complete: bool,
    /// Why undo could not finish, in the user's own vocabulary. Non-empty
    /// exactly when `complete` is false for a reason the user must act on.
    pub notes: Vec<String>,
}

/// Undo this setup. Removes the links it made (restoring env files from
/// their recorded prior state), removes routes it CREATED that no other
/// project uses, and returns the setup to `not_configured`.
///
/// ## Why the plan summary is not trusted blindly
///
/// The summary is persisted at the LAST apply step, so any earlier failure
/// leaves it NULL. The previous code read it with
/// `.transpose()?.unwrap_or_default()`, which turned "we do not know what
/// was done" into "nothing was done": both loops iterated empty
/// collections, `complete` stayed `true`, the row was moved to
/// `not_configured`, and the CLI printed "Tracking stopped." — while the
/// user's `.env` still pointed at the gateway with routes and links intact
/// (ZFT-007).
///
/// Undo now derives its work from ground truth. `gateway_project_links`
/// rows carry the recorded prior `.env` state, so the links this project
/// holds are authoritative regardless of what the summary says. When the
/// summary is absent AND link rows exist, the route side cannot be
/// reconstructed (we cannot tell created from reused), so undo restores
/// what it can and REFUSES to report completion.
pub fn undo(conn: &Connection, setup: &TrackingSetup) -> Result<UndoReport> {
    let recorded: Option<PlanSummary> = setup
        .plan_summary_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?;

    // Ground truth: every route prefix this project is actually linked to.
    let live_links: Vec<String> = {
        let mut stmt =
            conn.prepare("SELECT route_prefix FROM gateway_project_links WHERE project_id = ?1")?;
        let rows = stmt.query_map([&setup.project_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        out
    };

    let summary_missing = recorded.is_none();
    let mut summary = recorded.unwrap_or_default();
    // Union: the summary's order matters (chained multi-provider plans over
    // one file must unwind last-to-first), so keep it and append anything
    // the database knows about that the summary does not.
    for prefix in &live_links {
        if !summary.links.contains(prefix) {
            summary.links.push(prefix.clone());
        }
    }

    let mut links = Vec::new();
    let mut complete = true;
    let mut notes: Vec<String> = Vec::new();
    if summary_missing && !live_links.is_empty() {
        complete = false;
        notes.push(
            "this setup failed before its plan was recorded, so Tethra cannot tell which routes \
             it created from which it reused. Environment files were restored from the recorded \
             link state; routes were left in place. Review them under Advanced → Gateway."
                .to_string(),
        );
    }
    // Reverse order: apply chained multi-provider plans over one file
    // (provider N planned over N−1's output), so restoring last-to-first
    // unwinds each layer onto exactly the prior state it recorded.
    for prefix in summary.links.iter().rev() {
        match envlink::unlink(conn, &setup.project_id, prefix) {
            Ok(report) => {
                complete &= report.complete;
                links.push(report);
            }
            // Already unlinked (e.g. a retried undo) — not a failure.
            Err(CoreError::NotFound { .. }) => {}
            Err(e) => return Err(e),
        }
    }

    let mut removed_routes = Vec::new();
    let mut kept_routes = Vec::new();
    for prefix in &summary.created_routes {
        let still_linked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM gateway_project_links WHERE route_prefix = ?1",
            [prefix],
            |r| r.get(0),
        )?;
        if still_linked > 0 {
            kept_routes.push((
                prefix.clone(),
                "another project still links this route".to_string(),
            ));
            continue;
        }
        if routes::remove_route(conn, prefix)? {
            removed_routes.push(prefix.clone());
        }
    }
    // A route this setup RE-ENABLED existed before, so it is not removed —
    // but its `enabled = false` was a deliberate choice by the user, and
    // undo restored the row while leaving the flag on (ZFT-019). Put it
    // back, under the same "is anyone still using it?" guard that protects
    // removal: a link whose restore FAILED still counts, so a half-undone
    // setup does not disable a route its own environment file still points
    // at.
    for prefix in &summary.re_enabled_routes {
        if removed_routes.contains(prefix) {
            continue;
        }
        let still_linked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM gateway_project_links WHERE route_prefix = ?1",
            [prefix],
            |r| r.get(0),
        )?;
        if still_linked > 0 {
            kept_routes.push((
                prefix.clone(),
                "was re-enabled by this setup, but another project still links it — left enabled"
                    .to_string(),
            ));
            continue;
        }
        routes::set_route_enabled(conn, prefix, false)?;
        kept_routes.push((
            prefix.clone(),
            "existed before this setup but was disabled; returned to disabled".to_string(),
        ));
    }
    for prefix in &summary.reused_routes {
        kept_routes.push((
            prefix.clone(),
            "existed before this setup (only reused)".to_string(),
        ));
    }

    if complete {
        // Return the row to not_configured (legal from any state) and
        // clear apply artifacts so a later setup starts clean. The session
        // is closed too: nothing observed under it may verify a later one.
        state::transition(conn, setup, TrackingState::NotConfigured, None)?;
        conn.execute(
            "UPDATE tracking_setups
             SET plan_summary_json = NULL, applied_at = NULL, first_traffic_at = NULL,
                 verification_session = NULL
             WHERE id = ?1",
            [&setup.id],
        )?;
    } else {
        // An incomplete undo must NOT clear the apply artifacts: leaving
        // `applied_at` in place is what keeps the next status read honest
        // about a setup that is still partly in effect.
        state::transition(
            conn,
            setup,
            TrackingState::NeedsAttention,
            Some(if summary_missing {
                "undo_incomplete_plan_unknown"
            } else {
                "undo_incomplete"
            }),
        )?;
    }
    audit::record(
        conn,
        "tracking_setup_undone",
        Some(&setup.project_id),
        None,
        &format!(
            "links_restored={} routes_removed={} complete={complete}",
            links.len(),
            removed_routes.len()
        ),
    )?;

    Ok(UndoReport {
        links,
        removed_routes,
        kept_routes,
        complete,
        notes,
    })
}
