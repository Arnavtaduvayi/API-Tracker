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
    /// First qualifying observation of the CURRENT verification session.
    pub first_traffic_at: Option<String>,
    pub last_transition_at: String,
    pub attention_reason: Option<String>,
    /// Non-secret id of the current setup/repair attempt. A new one is
    /// minted on every apply, so an observation recorded for a previous
    /// attempt can never verify this one (ZFT-006).
    pub verification_session: Option<String>,
    /// Bumped on every apply. Lets a reader tell "the configuration
    /// changed since this was verified" from "still the same setup".
    pub config_generation: i64,
    /// The first time this setup was EVER verified, across all sessions.
    /// Historical: it survives re-apply and is displayed as history, never
    /// as evidence of present health (ZFT-005).
    pub first_verified_at: Option<String>,
    /// When the current `attention_reason` was recorded. A failure that is
    /// newer than the newest observation must not be erased by that
    /// observation (ZFT-006).
    pub attention_at: Option<String>,
}

/// Per-provider observation freshness derived by [`refresh`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderFreshness {
    pub provider_id: String,
    pub last_observed_at: Option<String>,
    /// The route this provider's traffic must arrive through still exists
    /// and is enabled.
    pub route_present: bool,
    /// The project is still linked to that route.
    pub link_present: bool,
    /// `last_observed_at` is inside the freshness window.
    pub fresh: bool,
}

/// How long an observation counts as evidence that tracking is working
/// *now*. Older than this and the setup is "verified previously", never
/// "verified and active" (ZFT-005).
///
/// Chosen to be generous relative to how often a developer's app calls an
/// API — a project that is simply idle must not be reported as broken —
/// while still expiring long before the 7-to-90-day event retention that
/// let the old code claim success for months.
pub const OBSERVATION_FRESHNESS_SECS: i64 = 6 * 60 * 60;

/// Inputs `refresh` cannot read from the database: whether the gateway is
/// actually answering right now.
///
/// Passed in rather than probed inside so the derivation stays a pure
/// function of (rows, liveness) and can be tested in both directions
/// without a running service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayLiveness {
    /// A listener answered and proved it is this vault's gateway.
    Verified,
    /// Nothing is listening, or the listener did not verify.
    Down,
    /// Not probed on this read (e.g. a bulk list). Treated as "cannot
    /// confirm health": historical facts stay, present-tense claims do not.
    Unknown,
}

/// What is true about this setup RIGHT NOW, as distinct from what was ever
/// true. The persisted `TrackingState` is a cache; this is the answer the
/// user is shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CurrentHealth {
    /// Every configured provider observed within the freshness window, the
    /// routes and links still exist, and the gateway answered.
    VerifiedAndActive,
    /// Some providers observed and fresh, others not yet.
    PartiallyTracked {
        observed: usize,
        total: usize,
    },
    /// Verified at some point, but the gateway is not answering now — the
    /// user's application is pointed at a port with nothing behind it.
    VerifiedPreviouslyGatewayDown,
    /// Verified at some point, but nothing recent. Not an error: an idle
    /// project looks exactly like this.
    VerifiedPreviouslyIdle {
        last_observed_at: String,
    },
    /// Applied, gateway up, waiting for the first request of this session.
    WaitingForFirstRequest,
    /// Applied but the app has not been restarted yet.
    NeedsRestart,
    /// A route or link this setup configured has gone away.
    ConfigurationChanged {
        detail: String,
    },
    /// The gateway is not answering and this setup was never verified.
    GatewayUnavailable,
    /// The most recent setup or repair attempt failed, and no observation
    /// since then contradicts it.
    NeedsAttention {
        reason: String,
    },
    /// Attribution was enabled but the matching key is no longer resident.
    AttributionPaused,
    NotConfigured,
    Unsupported,
}

impl CurrentHealth {
    /// One short line for a status surface.
    pub fn describe(&self) -> String {
        match self {
            CurrentHealth::VerifiedAndActive => "tracking verified and active".into(),
            CurrentHealth::PartiallyTracked { observed, total } => {
                format!("partially tracked — {observed} of {total} providers observed")
            }
            CurrentHealth::VerifiedPreviouslyGatewayDown => {
                "verified previously — the local tracking service is not running, so requests are \
                 not reaching your APIs"
                    .into()
            }
            CurrentHealth::VerifiedPreviouslyIdle { last_observed_at } => {
                format!("verified previously — last observed {last_observed_at}")
            }
            CurrentHealth::WaitingForFirstRequest => "waiting for the first request".into(),
            CurrentHealth::NeedsRestart => "restart your project, then make one request".into(),
            CurrentHealth::ConfigurationChanged { detail } => {
                format!("configuration changed since verification — {detail}")
            }
            CurrentHealth::GatewayUnavailable => "the local tracking service is not running".into(),
            CurrentHealth::NeedsAttention { reason } => format!("needs attention — {reason}"),
            CurrentHealth::AttributionPaused => {
                "tracking active; credential attribution is paused (vault locked)".into()
            }
            CurrentHealth::NotConfigured => "not configured".into(),
            CurrentHealth::Unsupported => "no trackable APIs in this folder".into(),
        }
    }

    /// Whether this is a present-tense success. Deliberately narrow: only
    /// the two states that actually mean traffic is flowing right now.
    pub fn is_currently_working(&self) -> bool {
        matches!(
            self,
            CurrentHealth::VerifiedAndActive | CurrentHealth::PartiallyTracked { .. }
        )
    }
}

/// Facts that survive the current session, shown alongside — never instead
/// of — [`CurrentHealth`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct VerificationHistory {
    /// The first time this setup was ever verified, across all sessions.
    pub first_verified_at: Option<String>,
    /// The newest qualifying observation of the current session.
    pub last_observed_at: Option<String>,
    /// The current session's id, for support and diagnostics.
    pub verification_session: Option<String>,
    pub config_generation: i64,
}

/// The complete answer a status surface renders: what is true now, what was
/// true before, and the per-provider detail behind both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrackingStatusReport {
    pub current: CurrentHealth,
    pub history: VerificationHistory,
    pub freshness: Vec<ProviderFreshness>,
    /// The cached row value after re-derivation, for callers that still
    /// switch on it.
    pub state: TrackingState,
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
    /// Route prefixes that EXISTED but were disabled, and which this setup
    /// turned back on.
    ///
    /// Undo restored the route row but never its prior `enabled` state, so
    /// a route the user had deliberately disabled was left permanently
    /// re-enabled (ZFT-019). `serde(default)` so plan summaries written by
    /// earlier builds still deserialize.
    #[serde(default)]
    pub re_enabled_routes: Vec<String>,
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
                    applied_at, first_traffic_at, last_transition_at, attention_reason, \
                    verification_session, config_generation, first_verified_at, attention_at";

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
        verification_session: r.get(10)?,
        config_generation: r.get(11)?,
        first_verified_at: r.get(12)?,
        attention_at: r.get(13)?,
    })
}

/// Create or replace the setup row for (project, folder), opening a NEW
/// verification session. Folder must already be canonicalized by the
/// caller (detection canonicalizes).
///
/// The v15 conflict clause updated only four columns, so `applied_at`,
/// `plan_summary_json` and `first_traffic_at` survived a re-run. A setup
/// attempt that then FAILED was promoted straight back to verified by the
/// *previous* run's traffic, and the failure reason was nulled (ZFT-006).
///
/// Every re-run therefore now:
///
/// * mints a fresh `verification_session` and bumps `config_generation`,
///   so only observations recorded from this moment on can verify it;
/// * clears the apply artifacts of the previous attempt — an attempt that
///   has not completed has no plan summary and no applied watermark;
/// * clears the *session* traffic watermark while preserving
///   `first_verified_at`, so history survives and present-tense evidence
///   does not.
pub fn upsert_setup(
    conn: &Connection,
    project_id: &str,
    folder: &Path,
    state: TrackingState,
    detection_json: &str,
) -> Result<TrackingSetup> {
    let now = clock::now_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let session = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO tracking_setups
             (id, project_id, folder_path, state, detection_json, last_transition_at,
              verification_session, config_generation)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)
         ON CONFLICT(project_id, folder_path) DO UPDATE SET
             state = excluded.state,
             detection_json = excluded.detection_json,
             last_transition_at = excluded.last_transition_at,
             attention_reason = NULL,
             attention_at = NULL,
             verification_session = excluded.verification_session,
             config_generation = tracking_setups.config_generation + 1,
             plan_summary_json = NULL,
             applied_at = NULL,
             first_traffic_at = NULL",
        params![
            id,
            project_id,
            folder.display().to_string(),
            state.as_str(),
            detection_json,
            now,
            session
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
    // A failure carries its own timestamp so a LATER read can tell whether
    // an observation post-dates it. Without this, an older observation
    // silently outranked a newer failure (ZFT-006).
    let attention_at = attention_reason.map(|_| now.clone());
    conn.execute(
        "UPDATE tracking_setups
         SET state = ?2, last_transition_at = ?3, attention_reason = ?4, attention_at = ?5
         WHERE id = ?1",
        params![setup.id, next.as_str(), now, attention_reason, attention_at],
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

/// The setup's persisted plan summary, or an empty one when absent.
///
/// Callers that must distinguish "no plan" from "an empty plan" — undo
/// does — read `plan_summary_json` directly instead.
pub fn plan_summary_of(setup: &TrackingSetup) -> PlanSummary {
    setup
        .plan_summary_json
        .as_deref()
        .and_then(|json| serde_json::from_str::<PlanSummary>(json).ok())
        .unwrap_or_default()
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

/// Re-derive the current health of a setup from ground truth.
///
/// This is the function the audit broke three ways, so its contract is
/// stated explicitly:
///
/// * **Evidence, not cache.** The persisted `state` is corrected against
///   the observation tables on every read, in both directions.
/// * **Less evidence is never more.** The v15 code returned early when the
///   row was not watchable or the `applied_at` watermark was missing —
///   *before* any correction — so nulling one column left a row rendering
///   `traffic_observed` with zero events (ZFT-008). Both early exits now
///   happen after the downgrade decision: a missing watermark is strictly
///   less evidence than zero events and forces the row down.
/// * **Only this session counts.** An observation qualifies only if it was
///   recorded at or after the CURRENT session's `applied_at`. Traffic from
///   a previous, successful attempt cannot verify a new, failed one
///   (ZFT-006).
/// * **Old success is not present health.** An observation also has to be
///   inside [`OBSERVATION_FRESHNESS_SECS`], the route and link it arrived
///   through have to still exist, and the gateway has to answer. Killing
///   the service used to leave the product reporting success while the
///   user's application was broken (ZFT-005).
/// * **Newer bad news wins.** A derived promotion never clears an
///   `attention_reason` that is NEWER than the newest observation.
///
/// `liveness` is supplied by the caller because probing a socket is I/O:
/// keeping it a parameter makes every branch testable in both directions
/// without a running service.
pub fn refresh_with(
    conn: &Connection,
    setup: &mut TrackingSetup,
    liveness: GatewayLiveness,
) -> Result<TrackingStatusReport> {
    let watchable = matches!(
        setup.state,
        TrackingState::AwaitingRestart
            | TrackingState::AwaitingFirstRequest
            | TrackingState::TrafficObserved
            | TrackingState::PartiallyObserved
            | TrackingState::NeedsAttention
    );
    let providers = configured_providers(setup);

    // --- the two former early returns, now expressed as a downgrade ------
    // A row claiming observation with no providers, no watermark, or in a
    // non-watchable state has LESS supporting evidence than a row with
    // zero events, so it must fall at least as far.
    if !watchable || providers.is_empty() || setup.applied_at.is_none() {
        let overclaiming = matches!(
            setup.state,
            TrackingState::TrafficObserved | TrackingState::PartiallyObserved
        );
        if overclaiming {
            let reason = if setup.applied_at.is_none() {
                "the record of when this setup was applied is missing, so its verified state \
                 could not be confirmed"
            } else {
                "this setup has no recorded providers, so its verified state could not be \
                 confirmed"
            };
            write_derived(conn, setup, TrackingState::NeedsAttention, Some(reason))?;
        }
        return Ok(TrackingStatusReport {
            current: health_without_evidence(setup, liveness),
            history: history_of(setup),
            freshness: Vec::new(),
            state: setup.state,
        });
    }
    let applied_at = setup.applied_at.clone().expect("checked above");

    // --- ground truth: do the routes and links still exist? --------------
    let mut route_present: BTreeMap<String, bool> = BTreeMap::new();
    let mut link_present: BTreeMap<String, bool> = BTreeMap::new();
    let mut custom_hosts = BTreeMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT route_prefix, provider_id, custom_origin, enabled FROM gateway_routes",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (prefix, provider, custom_origin, enabled) = row?;
            if let Some(host) = custom_origin {
                custom_hosts.insert(host.to_ascii_lowercase(), provider.clone());
            }
            if enabled != 0 {
                route_present.insert(provider.clone(), true);
                route_present.insert(prefix, true);
            }
        }
    }
    {
        let mut stmt =
            conn.prepare("SELECT route_prefix FROM gateway_project_links WHERE project_id = ?1")?;
        let rows = stmt.query_map([&setup.project_id], |r| r.get::<_, String>(0))?;
        for row in rows {
            link_present.insert(row?, true);
        }
    }

    // --- qualifying observations of THIS session -------------------------
    let now = clock::now_rfc3339();
    let stale_before = clock::rfc3339_minus_seconds(&now, OBSERVATION_FRESHNESS_SECS);
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

    let freshness: Vec<ProviderFreshness> = per_provider
        .iter()
        .map(|(provider_id, last_observed_at)| ProviderFreshness {
            provider_id: provider_id.clone(),
            last_observed_at: last_observed_at.clone(),
            route_present: route_present.get(provider_id).copied().unwrap_or(false),
            link_present: link_present.contains_key(provider_id),
            fresh: last_observed_at
                .as_deref()
                .is_some_and(|at| at >= stale_before.as_str()),
        })
        .collect();

    let observed_ever = freshness
        .iter()
        .filter(|f| f.last_observed_at.is_some())
        .count();
    let total = freshness.len();
    // "Currently working" needs ALL of: a recent observation, the route it
    // came through still enabled, and the project still linked to it.
    let working_now = freshness
        .iter()
        .filter(|f| f.fresh && f.route_present && f.link_present)
        .count();
    let newest_observation = freshness
        .iter()
        .filter_map(|f| f.last_observed_at.clone())
        .max();

    // --- correct the cached row -----------------------------------------
    // A failure recorded AFTER the newest observation is the more recent
    // truth and must survive; only an observation that post-dates the
    // failure may clear it.
    let failure_is_newer = match (&setup.attention_at, &newest_observation) {
        (Some(failed), Some(seen)) => failed.as_str() > seen.as_str(),
        (Some(_), None) => true,
        _ => false,
    };
    let derived = if observed_ever == 0 {
        match setup.state {
            TrackingState::TrafficObserved | TrackingState::PartiallyObserved => {
                Some(TrackingState::AwaitingFirstRequest)
            }
            _ => None,
        }
    } else if failure_is_newer {
        // Evidence exists, but it all pre-dates the current failure.
        Some(TrackingState::NeedsAttention)
    } else if observed_ever == total {
        Some(TrackingState::TrafficObserved)
    } else {
        Some(TrackingState::PartiallyObserved)
    };
    if let Some(next) = derived {
        if next != setup.state {
            let keep_reason = if next == TrackingState::NeedsAttention {
                setup.attention_reason.clone()
            } else {
                None
            };
            write_derived(conn, setup, next, keep_reason.as_deref())?;
        }
    }

    // --- session and historical watermarks -------------------------------
    if observed_ever > 0 && setup.first_traffic_at.is_none() {
        conn.execute(
            "UPDATE tracking_setups SET first_traffic_at = ?2 WHERE id = ?1",
            params![setup.id, earliest],
        )?;
        setup.first_traffic_at = earliest.clone();
    }
    if observed_ever > 0 && setup.first_verified_at.is_none() {
        conn.execute(
            "UPDATE tracking_setups SET first_verified_at = ?2 WHERE id = ?1",
            params![setup.id, earliest],
        )?;
        setup.first_verified_at = earliest;
    }

    let current = derive_health(
        setup,
        liveness,
        &freshness,
        observed_ever,
        working_now,
        total,
        failure_is_newer,
        newest_observation.as_deref(),
    );

    Ok(TrackingStatusReport {
        current,
        history: history_of(setup),
        freshness,
        state: setup.state,
    })
}

/// [`refresh_with`] without a liveness probe. Kept for bulk reads (lists,
/// migrations) where probing a socket per row would be wrong; the health it
/// returns can never be a present-tense success claim.
pub fn refresh(conn: &Connection, setup: &mut TrackingSetup) -> Result<Vec<ProviderFreshness>> {
    Ok(refresh_with(conn, setup, GatewayLiveness::Unknown)?.freshness)
}

/// Write a derived correction. These deliberately bypass the legality
/// table: they move the row to what the evidence supports.
///
/// `attention_reason` is passed through rather than nulled. The v15 code
/// nulled it unconditionally, which deleted the record of why a setup had
/// failed the moment any older traffic was found (ZFT-006).
fn write_derived(
    conn: &Connection,
    setup: &mut TrackingSetup,
    next: TrackingState,
    attention_reason: Option<&str>,
) -> Result<()> {
    let now = clock::now_rfc3339();
    let attention_at = if attention_reason.is_some() {
        setup.attention_at.clone().or_else(|| Some(now.clone()))
    } else {
        None
    };
    conn.execute(
        "UPDATE tracking_setups
         SET state = ?2, last_transition_at = ?3, attention_reason = ?4, attention_at = ?5
         WHERE id = ?1",
        params![setup.id, next.as_str(), now, attention_reason, attention_at],
    )?;
    setup.state = next;
    setup.attention_reason = attention_reason.map(str::to_string);
    setup.attention_at = attention_at;
    setup.last_transition_at = now;
    Ok(())
}

fn history_of(setup: &TrackingSetup) -> VerificationHistory {
    VerificationHistory {
        first_verified_at: setup.first_verified_at.clone(),
        last_observed_at: setup.first_traffic_at.clone(),
        verification_session: setup.verification_session.clone(),
        config_generation: setup.config_generation,
    }
}

/// Health for a row we could not evaluate against observations at all.
fn health_without_evidence(setup: &TrackingSetup, liveness: GatewayLiveness) -> CurrentHealth {
    match setup.state {
        TrackingState::NotConfigured => CurrentHealth::NotConfigured,
        TrackingState::Unsupported => CurrentHealth::Unsupported,
        TrackingState::NeedsAttention => CurrentHealth::NeedsAttention {
            reason: setup
                .attention_reason
                .clone()
                .unwrap_or_else(|| "setup did not complete".to_string()),
        },
        TrackingState::AwaitingRestart => CurrentHealth::NeedsRestart,
        _ if liveness == GatewayLiveness::Down => CurrentHealth::GatewayUnavailable,
        _ => CurrentHealth::WaitingForFirstRequest,
    }
}

/// The present-tense answer, from the evidence gathered above.
///
/// Order matters: a current failure outranks stale success, a dead gateway
/// outranks any "active" claim, and a missing route or link is reported as
/// a configuration change rather than as traffic that simply stopped.
#[allow(clippy::too_many_arguments)]
fn derive_health(
    setup: &TrackingSetup,
    liveness: GatewayLiveness,
    freshness: &[ProviderFreshness],
    observed_ever: usize,
    working_now: usize,
    total: usize,
    failure_is_newer: bool,
    newest_observation: Option<&str>,
) -> CurrentHealth {
    if failure_is_newer {
        return CurrentHealth::NeedsAttention {
            reason: setup
                .attention_reason
                .clone()
                .unwrap_or_else(|| "the most recent setup attempt failed".to_string()),
        };
    }

    // A route or link this setup configured has gone away: the user's
    // `.env` still points at the gateway, but nothing will forward.
    let missing: Vec<&str> = freshness
        .iter()
        .filter(|f| !f.route_present || !f.link_present)
        .map(|f| f.provider_id.as_str())
        .collect();
    if !missing.is_empty() {
        // Name the providers rather than counting them: "the route for
        // supabase is gone" is actionable, "1 of 3 routes is gone" is not.
        let detail = format!(
            "the route or project link for {} is gone ({} of {} configured providers)",
            missing.join(", "),
            missing.len(),
            total
        );
        return CurrentHealth::ConfigurationChanged { detail };
    }

    match liveness {
        GatewayLiveness::Down => {
            // The decisive case the audit reproduced: the app's `.env`
            // points at a loopback port with nothing listening, so every
            // API call it makes is failing right now.
            if observed_ever > 0 || setup.first_verified_at.is_some() {
                CurrentHealth::VerifiedPreviouslyGatewayDown
            } else {
                CurrentHealth::GatewayUnavailable
            }
        }
        GatewayLiveness::Unknown => {
            // Cannot confirm present health; report history honestly
            // instead of asserting either success or failure.
            if let Some(at) = newest_observation {
                CurrentHealth::VerifiedPreviouslyIdle {
                    last_observed_at: at.to_string(),
                }
            } else if setup.state == TrackingState::AwaitingRestart {
                CurrentHealth::NeedsRestart
            } else {
                CurrentHealth::WaitingForFirstRequest
            }
        }
        GatewayLiveness::Verified => {
            if total > 0 && working_now == total {
                CurrentHealth::VerifiedAndActive
            } else if working_now > 0 {
                CurrentHealth::PartiallyTracked {
                    observed: working_now,
                    total,
                }
            } else if let Some(at) = newest_observation {
                // Observed, but not recently enough to call it active.
                CurrentHealth::VerifiedPreviouslyIdle {
                    last_observed_at: at.to_string(),
                }
            } else if setup.state == TrackingState::AwaitingRestart {
                CurrentHealth::NeedsRestart
            } else {
                CurrentHealth::WaitingForFirstRequest
            }
        }
    }
}

/// Remove the setup row (undo). Recorded history is never touched.
pub fn delete_setup(conn: &Connection, setup_id: &str) -> Result<()> {
    conn.execute("DELETE FROM tracking_setups WHERE id = ?1", [setup_id])?;
    Ok(())
}
