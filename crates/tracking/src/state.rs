//! The persisted tracking state machine (`tracking_setups`, migration v15).
//!
//! The row caches the product-level state; the source of truth for "is
//! traffic flowing" remains the observation tables. [`refresh`] re-derives
//! the observed states on every read, so a stale or hand-edited row can
//! never overclaim `traffic_observed` (SI-19 alignment).

use std::collections::BTreeMap;
use std::path::Path;

use api_tracker_core::runtime::inventory::provider_for_host;
use api_tracker_core::{clock, CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackingState {
    NotConfigured,
    Scanning,
    ReadyToConfigure,
    Applying,
    AwaitingRestart,
    AwaitingFirstRequest,
    TrafficObserved,
    PartiallyObserved,
    NeedsAttention,
    Unsupported,
}

impl TrackingState {
    pub fn as_str(self) -> &'static str {
        match self {
            TrackingState::NotConfigured => "not_configured",
            TrackingState::Scanning => "scanning",
            TrackingState::ReadyToConfigure => "ready_to_configure",
            TrackingState::Applying => "applying",
            TrackingState::AwaitingRestart => "awaiting_restart",
            TrackingState::AwaitingFirstRequest => "awaiting_first_request",
            TrackingState::TrafficObserved => "traffic_observed",
            TrackingState::PartiallyObserved => "partially_observed",
            TrackingState::NeedsAttention => "needs_attention",
            TrackingState::Unsupported => "unsupported",
        }
    }

    pub fn from_db(s: &str) -> Option<Self> {
        Some(match s {
            "not_configured" => TrackingState::NotConfigured,
            "scanning" => TrackingState::Scanning,
            "ready_to_configure" => TrackingState::ReadyToConfigure,
            "applying" => TrackingState::Applying,
            "awaiting_restart" => TrackingState::AwaitingRestart,
            "awaiting_first_request" => TrackingState::AwaitingFirstRequest,
            "traffic_observed" => TrackingState::TrafficObserved,
            "partially_observed" => TrackingState::PartiallyObserved,
            "needs_attention" => TrackingState::NeedsAttention,
            "unsupported" => TrackingState::Unsupported,
            _ => return None,
        })
    }

    /// Legal transitions (TARGET_USER_JOURNEYS §7). `undo` → NotConfigured
    /// is legal from anywhere and handled by the caller.
    pub fn can_transition_to(self, next: TrackingState) -> bool {
        use TrackingState::*;
        if next == NotConfigured {
            return true; // any --undo--> not_configured
        }
        matches!(
            (self, next),
            (NotConfigured, Scanning)
                | (Scanning, ReadyToConfigure)
                | (ReadyToConfigure, Applying)
                | (ReadyToConfigure, Unsupported)
                | (ReadyToConfigure, Scanning)
                | (Unsupported, Scanning)
                | (Applying, AwaitingRestart)
                | (Applying, AwaitingFirstRequest)
                | (Applying, NeedsAttention)
                | (AwaitingRestart, AwaitingFirstRequest)
                | (AwaitingRestart, TrafficObserved)
                | (AwaitingRestart, PartiallyObserved)
                | (AwaitingRestart, NeedsAttention)
                | (AwaitingFirstRequest, TrafficObserved)
                | (AwaitingFirstRequest, PartiallyObserved)
                | (AwaitingFirstRequest, NeedsAttention)
                | (NeedsAttention, AwaitingFirstRequest)
                | (NeedsAttention, TrafficObserved)
                | (NeedsAttention, PartiallyObserved)
                | (NeedsAttention, Applying)
                | (PartiallyObserved, TrafficObserved)
                | (PartiallyObserved, NeedsAttention)
                | (TrafficObserved, NeedsAttention)
                | (TrafficObserved, PartiallyObserved)
                | (Scanning, NotConfigured)
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TrackingSetup {
    pub id: String,
    pub project_id: String,
    pub folder_path: String,
    pub state: TrackingState,
    pub detection_json: String,
    pub plan_summary_json: Option<String>,
    pub applied_at: Option<String>,
    pub first_traffic_at: Option<String>,
    pub last_transition_at: String,
    pub attention_reason: Option<String>,
}

/// Per-provider observation freshness derived by [`refresh`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderFreshness {
    pub provider_id: String,
    pub last_observed_at: Option<String>,
}

/// The value-free plan summary persisted on the setup row. Everything undo
/// needs, nothing more: which routes/links/files this setup created or
/// reused, so `track undo` removes exactly what `track` did.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlanSummary {
    /// Configured providers (route prefixes double as provider ids).
    pub providers: Vec<String>,
    /// Route prefixes this setup CREATED (reused routes are absent).
    pub created_routes: Vec<String>,
    /// Route prefixes this setup reused.
    pub reused_routes: Vec<String>,
    /// Link route-prefixes this setup created or re-applied.
    pub links: Vec<String>,
    /// Files the approved link plans touched (paths only).
    pub files: Vec<String>,
    /// Whether attribution was enabled in this setup.
    pub attribution_enabled: bool,
    /// Whether the service install was performed by this setup.
    pub installed_service: bool,
    /// The port the plan was built against.
    pub port: u16,
}

const COLS: &str = "id, project_id, folder_path, state, detection_json, plan_summary_json, \
                    applied_at, first_traffic_at, last_transition_at, attention_reason";

fn row_to_setup(r: &rusqlite::Row<'_>) -> rusqlite::Result<TrackingSetup> {
    let state_raw: String = r.get(3)?;
    Ok(TrackingSetup {
        id: r.get(0)?,
        project_id: r.get(1)?,
        folder_path: r.get(2)?,
        // An unknown state string (from a newer build) renders honestly as
        // needs_attention instead of panicking or overclaiming.
        state: TrackingState::from_db(&state_raw).unwrap_or(TrackingState::NeedsAttention),
        detection_json: r.get(4)?,
        plan_summary_json: r.get(5)?,
        applied_at: r.get(6)?,
        first_traffic_at: r.get(7)?,
        last_transition_at: r.get(8)?,
        attention_reason: r.get(9)?,
    })
}

/// Create or replace the setup row for (project, folder). Folder must
/// already be canonicalized by the caller (detection canonicalizes).
pub fn upsert_setup(
    conn: &Connection,
    project_id: &str,
    folder: &Path,
    state: TrackingState,
    detection_json: &str,
) -> Result<TrackingSetup> {
    let now = clock::now_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO tracking_setups
             (id, project_id, folder_path, state, detection_json, last_transition_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(project_id, folder_path) DO UPDATE SET
             state = excluded.state,
             detection_json = excluded.detection_json,
             last_transition_at = excluded.last_transition_at,
             attention_reason = NULL",
        params![
            id,
            project_id,
            folder.display().to_string(),
            state.as_str(),
            detection_json,
            now
        ],
    )?;
    find_setup(conn, project_id, folder)?.ok_or(CoreError::NotFound {
        kind: "tracking setup",
        ident: folder.display().to_string(),
    })
}

pub fn get_setup(conn: &Connection, id: &str) -> Result<Option<TrackingSetup>> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLS} FROM tracking_setups WHERE id = ?1"),
            [id],
            row_to_setup,
        )
        .optional()?)
}

pub fn find_setup(
    conn: &Connection,
    project_id: &str,
    folder: &Path,
) -> Result<Option<TrackingSetup>> {
    Ok(conn
        .query_row(
            &format!(
                "SELECT {COLS} FROM tracking_setups
                 WHERE project_id = ?1 AND folder_path = ?2"
            ),
            params![project_id, folder.display().to_string()],
            row_to_setup,
        )
        .optional()?)
}

/// All setups, newest transition first.
pub fn list_setups(conn: &Connection) -> Result<Vec<TrackingSetup>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLS} FROM tracking_setups ORDER BY last_transition_at DESC"
    ))?;
    let rows = stmt.query_map([], row_to_setup)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Setups registered for a folder (any project), canonicalize-on-compare.
pub fn setups_for_folder(conn: &Connection, folder: &Path) -> Result<Vec<TrackingSetup>> {
    let wanted = folder
        .canonicalize()
        .unwrap_or_else(|_| folder.to_path_buf())
        .display()
        .to_string();
    Ok(list_setups(conn)?
        .into_iter()
        .filter(|s| s.folder_path == wanted)
        .collect())
}

/// Transition with legality enforcement. Illegal transitions are an error,
/// never a silent overwrite.
pub fn transition(
    conn: &Connection,
    setup: &TrackingSetup,
    next: TrackingState,
    attention_reason: Option<&str>,
) -> Result<TrackingSetup> {
    if setup.state != next && !setup.state.can_transition_to(next) {
        return Err(CoreError::InvalidInput(format!(
            "illegal tracking-state transition {} -> {}",
            setup.state.as_str(),
            next.as_str()
        )));
    }
    let now = clock::now_rfc3339();
    conn.execute(
        "UPDATE tracking_setups
         SET state = ?2, last_transition_at = ?3, attention_reason = ?4
         WHERE id = ?1",
        params![setup.id, next.as_str(), now, attention_reason],
    )?;
    get_setup(conn, &setup.id)?.ok_or(CoreError::NotFound {
        kind: "tracking setup",
        ident: setup.id.clone(),
    })
}

/// Record a completed apply: plan summary + applied_at timestamp.
pub fn record_applied(conn: &Connection, setup_id: &str, plan_summary: &PlanSummary) -> Result<()> {
    let now = clock::now_rfc3339();
    conn.execute(
        "UPDATE tracking_setups
         SET plan_summary_json = ?2, applied_at = ?3
         WHERE id = ?1",
        params![setup_id, serde_json::to_string(plan_summary)?, now],
    )?;
    Ok(())
}

/// Providers this setup configured, from the plan summary (fallback: none).
pub fn configured_providers(setup: &TrackingSetup) -> Vec<String> {
    setup
        .plan_summary_json
        .as_deref()
        .and_then(|json| serde_json::from_str::<PlanSummary>(json).ok())
        .map(|p| p.providers)
        .unwrap_or_default()
}

/// Map an observed host to a provider id: the compiled-in host table
/// first, then this vault's custom-origin routes (e.g. a confirmed
/// Supabase project origin).
fn provider_of_host(host: &str, custom_hosts: &BTreeMap<String, String>) -> Option<String> {
    if let Some(p) = provider_for_host(host) {
        return Some(p.to_string());
    }
    custom_hosts.get(&host.to_ascii_lowercase()).cloned()
}

/// Re-derive the observed states from the observation tables. Returns the
/// per-provider freshness list. The persisted row is corrected when it
/// disagrees with the evidence — in BOTH directions, but a downgrade never
/// invents an error state: an overclaiming `traffic_observed` row with no
/// qualifying events returns to `awaiting_first_request`.
pub fn refresh(conn: &Connection, setup: &mut TrackingSetup) -> Result<Vec<ProviderFreshness>> {
    let watchable = matches!(
        setup.state,
        TrackingState::AwaitingRestart
            | TrackingState::AwaitingFirstRequest
            | TrackingState::TrafficObserved
            | TrackingState::PartiallyObserved
            | TrackingState::NeedsAttention
    );
    let providers = configured_providers(setup);
    if !watchable || providers.is_empty() {
        return Ok(Vec::new());
    }
    let Some(applied_at) = setup.applied_at.clone() else {
        return Ok(Vec::new());
    };

    // Custom-origin host → provider map for hosts the compiled-in table
    // does not know.
    let mut custom_hosts = BTreeMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT custom_origin, provider_id FROM gateway_routes
             WHERE custom_origin IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (host, provider) = row?;
            custom_hosts.insert(host.to_ascii_lowercase(), provider);
        }
    }

    // Qualifying events: this project, gateway-observed, at/after apply.
    // Pre-existing traffic from an earlier setup can never verify this one.
    let mut per_provider: BTreeMap<String, Option<String>> =
        providers.iter().map(|p| (p.clone(), None)).collect();
    let mut earliest: Option<String> = None;
    {
        let mut stmt = conn.prepare(
            "SELECT host, MIN(at), MAX(at) FROM runtime_request_events
             WHERE project_id = ?1 AND observation_source = 'gateway' AND at >= ?2
             GROUP BY host",
        )?;
        let rows = stmt.query_map(params![setup.project_id, applied_at], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (host, first_at, last_at) = row?;
            let Some(provider) = provider_of_host(&host, &custom_hosts) else {
                continue;
            };
            if let Some(slot) = per_provider.get_mut(&provider) {
                let newer = match slot.as_deref() {
                    Some(cur) => last_at.as_str() > cur,
                    None => true,
                };
                if newer {
                    *slot = Some(last_at);
                }
                let older = match earliest.as_deref() {
                    Some(cur) => first_at.as_str() < cur,
                    None => true,
                };
                if older {
                    earliest = Some(first_at);
                }
            }
        }
    }

    let observed = per_provider.values().filter(|v| v.is_some()).count();
    let total = per_provider.len();
    let derived = if observed == 0 {
        match setup.state {
            // An observed claim with no supporting events is corrected.
            TrackingState::TrafficObserved | TrackingState::PartiallyObserved => {
                Some(TrackingState::AwaitingFirstRequest)
            }
            _ => None,
        }
    } else if observed == total {
        Some(TrackingState::TrafficObserved)
    } else {
        Some(TrackingState::PartiallyObserved)
    };

    if let Some(next) = derived {
        if next != setup.state {
            let now = clock::now_rfc3339();
            // Derived corrections bypass the legality table deliberately:
            // they move the row to what the evidence supports.
            conn.execute(
                "UPDATE tracking_setups
                 SET state = ?2, last_transition_at = ?3, attention_reason = NULL
                 WHERE id = ?1",
                params![setup.id, next.as_str(), now],
            )?;
            setup.state = next;
            setup.attention_reason = None;
            setup.last_transition_at = now;
        }
    }
    if observed > 0 && setup.first_traffic_at.is_none() {
        conn.execute(
            "UPDATE tracking_setups SET first_traffic_at = ?2 WHERE id = ?1",
            params![setup.id, earliest],
        )?;
        setup.first_traffic_at = earliest;
    }

    Ok(per_provider
        .into_iter()
        .map(|(provider_id, last_observed_at)| ProviderFreshness {
            provider_id,
            last_observed_at,
        })
        .collect())
}

/// Remove the setup row (undo). Recorded history is never touched.
pub fn delete_setup(conn: &Connection, setup_id: &str) -> Result<()> {
    conn.execute("DELETE FROM tracking_setups WHERE id = ?1", [setup_id])?;
    Ok(())
}
