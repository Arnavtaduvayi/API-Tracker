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
}

/// Undo this setup. Removes the links it made (restoring env files from
/// their recorded prior state), removes routes it CREATED that no other
/// project uses, and returns the setup to `not_configured`.
pub fn undo(conn: &Connection, setup: &TrackingSetup) -> Result<UndoReport> {
    let summary: PlanSummary = setup
        .plan_summary_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?
        .unwrap_or_default();

    let mut links = Vec::new();
    let mut complete = true;
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
    for prefix in &summary.reused_routes {
        kept_routes.push((
            prefix.clone(),
            "existed before this setup (only reused)".to_string(),
        ));
    }

    if complete {
        // Return the row to not_configured (legal from any state) and
        // clear apply artifacts so a later setup starts clean.
        state::transition(conn, setup, TrackingState::NotConfigured, None)?;
        conn.execute(
            "UPDATE tracking_setups
             SET plan_summary_json = NULL, applied_at = NULL, first_traffic_at = NULL
             WHERE id = ?1",
            [&setup.id],
        )?;
    } else {
        state::transition(
            conn,
            setup,
            TrackingState::NeedsAttention,
            Some("undo_incomplete"),
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
    })
}
