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
    /// The highest `runtime_request_events` rowid at the moment this setup
    /// was applied.
    ///
    /// SQLite assigns rowids monotonically on insert, so this is a
    /// clock-independent watermark: only observations *physically recorded
    /// after* the apply can verify it. That is what actually binds an
    /// observation to the current verification session, and it is what a
    /// forged or skewed `at` timestamp cannot forge (RA-005).
    pub applied_event_rowid: i64,
    /// Compare-and-swap token for this row's health columns (`VER-01`).
    ///
    /// Every write that decides *from* a value read into this struct requires
    /// the stored row to still be at this version, and bumps it. A concurrent
    /// change therefore makes the write affect zero rows — a signal the caller
    /// re-derives from, rather than a silent overwrite of somebody else's
    /// newer truth. This is the token, not the state: two writers that both
    /// read version 4 cannot both commit.
    pub row_version: i64,
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

/// How far ahead of this machine's clock a stored observation may be dated
/// and still be believed (RA-005).
///
/// # Why an upper bound exists at all
///
/// `at` is **untrusted stored input**. It is a wall-clock string written by
/// whichever process recorded the exchange, and the reader compares it
/// against its own wall clock. The two can disagree — an NTP step, a
/// suspended laptop, a restored VM snapshot, a gateway and desktop on
/// different clocks — and the row can also simply be edited. Before this
/// bound existed, `fresh` was `at >= now - 6h` with **no upper limit**, so a
/// single row dated a year ahead read as a present-tense success and stayed
/// one until the wall clock caught up. Worse, being the newest timestamp in
/// the table, it also out-ranked a failure recorded *now* and caused
/// `attention_reason` to be nulled — the exact ZFT-006 shape the freshness
/// work exists to prevent.
///
/// # Why five minutes
///
/// It has to absorb ordinary skew between two processes on one machine (a
/// few hundred milliseconds), and between a gateway service and a desktop
/// app that may have started at different times. It must stay far below
/// [`OBSERVATION_FRESHNESS_SECS`], so that "slightly ahead" can never
/// meaningfully extend the freshness window. Five minutes is the same order
/// as the default NTP correction step and is generous for both.
///
/// Observations outside this window are **excluded**, not clamped: a
/// timestamp we cannot believe is not evidence, and silently rewriting it
/// would make the stored row disagree with what the reader acted on.
pub const MAX_CLOCK_SKEW_SECS: i64 = 5 * 60;

/// Whether `a` is strictly later than `b`, comparing parsed instants.
///
/// Fails **closed**: if either side cannot be parsed, the answer is `true`.
/// Both call sites ask "is the recorded failure newer than the newest
/// observation?", so `true` preserves the failure. A timestamp we cannot
/// read is a reason to keep bad news, never to discard it.
fn instant_is_after(a: &str, b: &str) -> bool {
    match (clock::parse_rfc3339(a), clock::parse_rfc3339(b)) {
        (Ok(a), Ok(b)) => a > b,
        _ => true,
    }
}

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
    /// An apply STARTED and never reported an outcome (`NEW-35`).
    ///
    /// [`TrackingState::Applying`] is written by `apply` before its first
    /// side effect and replaced by every path that finishes — success,
    /// failure, or undo. A row still sitting in it is therefore either an
    /// apply running at this instant or one that was interrupted (a crash, a
    /// quit, a power loss), and in both cases nothing has been verified and
    /// no request will be observed yet.
    ///
    /// It has its own variant because `Applying` is not in `refresh_once`'s
    /// watchable set, so it falls through to [`health_without_evidence`],
    /// where it used to be answered by the catch-all "waiting for the first
    /// request" — advice that only makes sense for a setup that finished
    /// applying, and which sends the user off to make a request that nothing
    /// is configured to observe.
    ApplyIncomplete,
    /// Applied but the app has not been restarted yet.
    NeedsRestart,
    /// A route or link this setup configured has gone away.
    ConfigurationChanged {
        detail: String,
        /// A gateway route this setup configured is gone or disabled, so
        /// nothing will forward for that provider.
        ///
        /// Carried as its own flag rather than left for a reader to recover
        /// from `detail`: the two causes need different sentences ("the
        /// destination Tethra registered is gone" vs "this project is no
        /// longer attached to it"), and a surface that re-derived the
        /// distinction by parsing prose would be a second interpretation of
        /// health living outside this module.
        route_missing: bool,
        /// The project link binding this project's traffic to that route is
        /// gone. Both flags can be true at once.
        link_missing: bool,
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
            CurrentHealth::ApplyIncomplete => "setup has not finished applying — nothing is \
                                               verified yet and no request will be observed; if \
                                               no setup is running right now it was interrupted, \
                                               so start tracking for this folder again to finish \
                                               it"
            .into(),
            CurrentHealth::NeedsRestart => "restart your project, then make one request".into(),
            CurrentHealth::ConfigurationChanged { detail, .. } => {
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
    /// the two states that actually mean traffic is flowing right now — an
    /// apply that never finished ([`CurrentHealth::ApplyIncomplete`]) is not
    /// one of them, whatever the cached row still claims (`NEW-35`).
    pub fn is_currently_working(&self) -> bool {
        matches!(
            self,
            CurrentHealth::VerifiedAndActive | CurrentHealth::PartiallyTracked { .. }
        )
    }

    /// The stable machine tag for this variant — byte-for-byte the token
    /// `serde` writes into the `kind` field, because both come from the
    /// `#[serde(tag = "kind", rename_all = "snake_case")]` naming above.
    ///
    /// It exists as a function so there is ONE answer. The desktop's
    /// `TrackingStatusDto` used to carry a hand-written copy of this match in
    /// `main.rs`; a variant added here and forgotten there would have
    /// serialized under one name on one command and another name on the next.
    /// Every surface that needs the tag calls this.
    pub fn kind(&self) -> &'static str {
        match self {
            CurrentHealth::VerifiedAndActive => "verified_and_active",
            CurrentHealth::PartiallyTracked { .. } => "partially_tracked",
            CurrentHealth::VerifiedPreviouslyGatewayDown => "verified_previously_gateway_down",
            CurrentHealth::VerifiedPreviouslyIdle { .. } => "verified_previously_idle",
            CurrentHealth::WaitingForFirstRequest => "waiting_for_first_request",
            CurrentHealth::ApplyIncomplete => "apply_incomplete",
            CurrentHealth::NeedsRestart => "needs_restart",
            CurrentHealth::ConfigurationChanged { .. } => "configuration_changed",
            CurrentHealth::GatewayUnavailable => "gateway_unavailable",
            CurrentHealth::NeedsAttention { .. } => "needs_attention",
            CurrentHealth::AttributionPaused => "attribution_paused",
            CurrentHealth::NotConfigured => "not_configured",
            CurrentHealth::Unsupported => "unsupported",
        }
    }
}

/// Facts that survive the current session, shown alongside — never instead
/// of — [`CurrentHealth`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct VerificationHistory {
    /// The first time this setup was ever verified, across all sessions.
    pub first_verified_at: Option<String>,
    /// The FIRST qualifying observation of the current session. The
    /// newest one is per-provider, in `ProviderFreshness.last_observed_at`
    /// — there is no single "newest" across providers worth naming here.
    pub session_first_observed_at: Option<String>,
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
    /// Whether this summary describes an apply that RAN TO COMPLETION.
    ///
    /// Route provenance is now persisted the moment the routes exist
    /// ([`record_routes_created`], NEW-32) rather than at the last apply
    /// step, so "a summary is present" no longer means "the apply
    /// finished". Only [`record_applied`] sets this flag. `undo` keys its
    /// ZFT-007 refusal on it instead of on the presence of the column, so
    /// undo still refuses to claim success after a partial apply while
    /// finally being able to remove the routes that apply created.
    ///
    /// Defaults to **true** on deserialize, and only on deserialize: before
    /// this field existed, [`record_applied`] was the only writer of
    /// `plan_summary_json`, so every summary already on disk describes a
    /// completed apply. Defaulting to `false` would tell every existing
    /// user's undo that their finished setup was a partial one.
    #[serde(default = "summary_written_by_an_earlier_build")]
    pub apply_completed: bool,
}

/// See [`PlanSummary::apply_completed`]. `Default::default()` for the struct
/// still yields `false`, which is what a freshly-built partial summary wants.
fn summary_written_by_an_earlier_build() -> bool {
    true
}

const COLS: &str = "id, project_id, folder_path, state, detection_json, plan_summary_json, \
                    applied_at, first_traffic_at, last_transition_at, attention_reason, \
                    verification_session, config_generation, first_verified_at, attention_at, \
                    applied_event_rowid, row_version";

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
        applied_event_rowid: r.get(14)?,
        row_version: r.get(15)?,
    })
}

/// The highest observation rowid currently in the table.
///
/// Captured at apply time and stored as the setup's watermark. `COALESCE`
/// handles the empty table; the value is only ever compared with `>`, so
/// zero admits everything, which is exactly right for a setup applied
/// before any observation existed.
fn newest_event_rowid(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(rowid), 0) FROM runtime_request_events",
        [],
        |r| r.get(0),
    )?)
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
    // Move the insertion-ordered watermark forward as well. `applied_at` is
    // nulled here, so nothing is verifiable until the apply completes — but
    // carrying a STALE rowid across a re-run would leave the previous
    // attempt's observations admissible the moment it does.
    let rowid = newest_event_rowid(conn)?;
    conn.execute(
        "INSERT INTO tracking_setups
             (id, project_id, folder_path, state, detection_json, last_transition_at,
              verification_session, config_generation, applied_event_rowid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)
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
             first_traffic_at = NULL,
             applied_event_rowid = excluded.applied_event_rowid,
             -- A re-run opens a NEW verification session, which is the single
             -- biggest reason a refresh already in flight must not commit: its
             -- conclusion is about the previous attempt (`VER-01`).
             row_version = tracking_setups.row_version + 1",
        params![
            id,
            project_id,
            folder.display().to_string(),
            state.as_str(),
            detection_json,
            now,
            session,
            rowid
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
///
/// Guarded by the row version like every other health write (`VER-01`): the
/// legality check above was evaluated against `setup.state` as the CALLER
/// read it, so committing after someone else moved the row would enforce the
/// table against a state that is no longer there. A concurrent change is
/// [`CoreError::StateConflict`], which tells the caller to re-read — it is
/// deliberately NOT retried here, because an explicit transition encodes an
/// intent ("this apply failed") whose legality has to be re-judged against
/// the new state by whoever formed it.
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
    // A failure carries its own timestamp so a LATER read can tell whether
    // an observation post-dates it. Without this, an older observation
    // silently outranked a newer failure (ZFT-006).
    let attention_at = attention_reason.map(|_| clock::now_rfc3339());
    let mut working = setup.clone();
    cas_write_health(conn, &mut working, next, attention_reason, attention_at)?;
    get_setup(conn, &setup.id)?.ok_or(CoreError::NotFound {
        kind: "tracking setup",
        ident: setup.id.clone(),
    })
}

/// Persist route provenance the moment it becomes true, before the apply has
/// finished (`NEW-32`).
///
/// `created_routes` used to be written only by [`record_applied`], the LAST
/// apply step, and [`upsert_setup`] nulls the column on every re-run. An
/// apply that failed at any step between the two therefore erased the record
/// of the routes it had just created and wrote no replacement. The retry saw
/// `add_manifest_route` return `AlreadyExists`, classified those routes as
/// "reused", and `undo` then stranded them with the reason *"existed before
/// this setup (only reused)"* — the exact opposite of the truth, and ZFT-018
/// reappearing through the failure path.
///
/// The summary written here is deliberately partial: `apply_completed` stays
/// `false`, so undo can use the route provenance without reading it as
/// evidence that the apply finished (that is the ZFT-007 refusal, which must
/// keep refusing).
///
/// Guarded by the row version for the same reason [`record_applied`] is —
/// see below.
pub fn record_routes_created(
    conn: &Connection,
    setup: &mut TrackingSetup,
    created_routes: &[String],
    re_enabled_routes: &[String],
) -> Result<()> {
    let partial = PlanSummary {
        created_routes: created_routes.to_vec(),
        re_enabled_routes: re_enabled_routes.to_vec(),
        apply_completed: false,
        ..PlanSummary::default()
    };
    let json = serde_json::to_string(&partial)?;
    cas_write_summary(conn, setup, &json, None)
}

/// Record a completed apply: plan summary + applied_at timestamp.
pub fn record_applied(
    conn: &Connection,
    setup: &mut TrackingSetup,
    plan_summary: &PlanSummary,
) -> Result<()> {
    // Stamp the insertion-ordered watermark in the SAME statement as the
    // wall-clock one. Only observations recorded after this point can
    // verify this session, and that fact is now anchored to something the
    // writer's clock cannot influence (RA-005).
    let rowid = newest_event_rowid(conn)?;
    // Completion is decided here and nowhere else, whatever the caller
    // passed: this is the only writer that runs after every apply step.
    let completed = PlanSummary {
        apply_completed: true,
        ..plan_summary.clone()
    };
    let json = serde_json::to_string(&completed)?;
    cas_write_summary(conn, setup, &json, Some(rowid))
}

/// The ONE statement that writes a setup's apply artifacts, guarded like
/// every other write that decides from a row the caller read earlier
/// (`VER-01`, `NEW-31`).
///
/// This was the single health write with no `row_version` predicate. It
/// **bumped** the version — deliberately, so an in-flight refresh re-reads —
/// but bumping without comparing is last-writer-wins, and the three columns
/// it writes are exactly the ones that decide which observations are
/// admissible (`applied_at`, `applied_event_rowid`) and what undo will act on
/// (`plan_summary_json`). Two applies racing on one folder — the desktop and
/// the CLI — therefore left run A's plan summary describing run B's session,
/// after which undo removed or kept the wrong `created_routes`. A conflict is
/// now [`CoreError::StateConflict`], which the apply path reports as a failed
/// step rather than silently mis-recording.
///
/// `applied_rowid` is `Some` only for a completed apply: a partial provenance
/// write must not move the admissibility watermark, because no session has
/// been opened for verification yet.
fn cas_write_summary(
    conn: &Connection,
    setup: &mut TrackingSetup,
    summary_json: &str,
    applied_rowid: Option<i64>,
) -> Result<()> {
    let now = clock::now_rfc3339();
    let changed = match applied_rowid {
        Some(rowid) => conn.execute(
            "UPDATE tracking_setups
             SET plan_summary_json = ?2, applied_at = ?3, applied_event_rowid = ?4,
                 row_version = row_version + 1
             WHERE id = ?1 AND row_version = ?5",
            params![setup.id, summary_json, now, rowid, setup.row_version],
        )?,
        None => conn.execute(
            "UPDATE tracking_setups
             SET plan_summary_json = ?2, row_version = row_version + 1
             WHERE id = ?1 AND row_version = ?3",
            params![setup.id, summary_json, setup.row_version],
        )?,
    };
    if changed == 0 {
        return Err(CoreError::StateConflict {
            kind: "tracking setup",
            ident: setup.id.clone(),
        });
    }
    setup.plan_summary_json = Some(summary_json.to_string());
    if let Some(rowid) = applied_rowid {
        setup.applied_at = Some(now);
        setup.applied_event_rowid = rowid;
    }
    setup.row_version += 1;
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
    // Optimistic concurrency (`VER-01`). Every corrective write inside
    // `refresh_once` is guarded by the row version that `setup` was read at,
    // so a row somebody else moved in between yields `StateConflict` instead
    // of a lost update. The answer to a conflict is not to force the write —
    // it is to look again: re-read the row and re-derive, because the newer
    // row may well change the conclusion (that is the whole point when the
    // change was a freshly-recorded failure).
    for _attempt in 0..REFRESH_CAS_ATTEMPTS {
        // `_attempt` carries the underscore because the only reader is the
        // test seam below, which a release build does not compile.
        #[cfg(any(test, feature = "test-hooks"))]
        cas_test_hook::before_attempt(_attempt);
        match refresh_once(conn, setup, liveness, true) {
            Err(CoreError::StateConflict { .. }) => {
                let Some(fresh) = get_setup(conn, &setup.id)? else {
                    // The setup was deleted underneath us. That is a legitimate
                    // outcome (undo removes the row), not an error to retry.
                    return Err(CoreError::NotFound {
                        kind: "tracking setup",
                        ident: setup.id.clone(),
                    });
                };
                *setup = fresh;
            }
            other => return other,
        }
    }
    // Deterministic terminal behaviour: under sustained contention this
    // REPORTS but does not WRITE. Returning the truth currently stored is
    // always safe; forcing a write derived from a row that keeps moving is
    // the defect this guard exists to prevent, and a caller that never
    // converges is a caller whose cached correction does not matter.
    if let Some(fresh) = get_setup(conn, &setup.id)? {
        *setup = fresh;
    }
    refresh_once(conn, setup, liveness, false)
}

/// How many times [`refresh_with`] re-reads and re-derives before it gives up
/// on writing a correction. Three is enough for any realistic contention on a
/// single-user machine (the competing writers are the desktop, the CLI and
/// the gateway) and is bounded so a pathological writer cannot spin a reader.
///
/// Falsifiable: `crates/tracking/tests/verification_cas_retry.rs` fails, by
/// name, if this is lowered to 2 or to 1. It used to survive being set to 1
/// with all 158 tests green (`NEW-05`), because no test created enough
/// contention to need a second attempt.
const REFRESH_CAS_ATTEMPTS: usize = 3;

/// The seam that makes a compare-and-swap conflict DETERMINISTIC in a test.
///
/// # Why this exists
///
/// The retry budget above was unfalsifiable. Lowering it to one attempt left
/// every test green, because a conflict can only be *observed* through what
/// gets persisted, and no existing test could schedule a competing write into
/// the window between [`refresh_once`]'s read and its guarded write more than
/// once — [`refresh_with`] re-reads the row itself, so there is no second
/// window a test can reach from outside. One hook wide is exactly the gap.
///
/// # Why it is public rather than `#[cfg(test)]`
///
/// Every test in this crate is an integration test under `tests/`, which
/// links the crate as an ordinary dependency and therefore never sees
/// `cfg(test)`. The two ways out are a Cargo feature enabled through a
/// self-referencing dev-dependency, or a `#[doc(hidden)]` public item. This
/// is the latter, because the feature route requires editing
/// `crates/tracking/Cargo.toml`, and a feature that a workspace test build
/// unifies into `apps/cli` is not obviously better than an item that is
/// hidden from the docs, unreachable without an explicit `install` call, and
/// compiles to a single `thread_local` read on the retry path.
///
/// # Why thread-local
///
/// `cargo test` runs test functions on parallel threads inside one binary. A
/// global would leak one test's hook into another and make the suite
/// order-dependent; thread-local also means a hooked test cannot disturb the
/// existing `Barrier` tests running beside it.
/// Present only under `cfg(test)` or the `test-hooks` feature, so a release
/// build carries no settable callback inside the writer that decides whether
/// a tracking setup is healthy. Integration tests reach it through the
/// crate's self-dependency in `[dev-dependencies]`; nothing else can.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub mod cas_test_hook {
    use std::cell::RefCell;

    type Hook = Box<dyn FnMut(usize)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    /// Uninstalls the hook when dropped, so a test that panics mid-way
    /// cannot leave the seam armed for whatever runs next on this thread.
    pub struct Guard(());

    impl Drop for Guard {
        fn drop(&mut self) {
            HOOK.with(|h| *h.borrow_mut() = None);
        }
    }

    /// Run `f` with the zero-based attempt index immediately before each
    /// [`super::refresh_with`] attempt on THIS thread. A test installs a
    /// closure that moves the row from a second connection — as a second
    /// process would — at exactly the attempts it wants to lose.
    pub fn install(f: impl FnMut(usize) + 'static) -> Guard {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(f)));
        Guard(())
    }

    /// `try_borrow_mut`, not `borrow_mut`: a hook that re-entered
    /// `refresh_with` would otherwise panic inside production code. Skipping
    /// the call is the safe direction — the seam is allowed to do nothing,
    /// it is never allowed to break the caller.
    pub(super) fn before_attempt(attempt: usize) {
        HOOK.with(|h| {
            if let Ok(mut slot) = h.try_borrow_mut() {
                if let Some(f) = slot.as_mut() {
                    f(attempt);
                }
            }
        });
    }
}

/// One attempt at [`refresh_with`].
///
/// `may_write` is false on the terminal, post-contention pass: the report is
/// still derived from real evidence, but no correction is persisted.
fn refresh_once(
    conn: &Connection,
    setup: &mut TrackingSetup,
    liveness: GatewayLiveness,
    may_write: bool,
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
        if overclaiming && may_write {
            let reason = if setup.applied_at.is_none() {
                "the record of when this setup was applied is missing, so its verified state \
                 could not be confirmed"
            } else {
                "this setup has no recorded providers, so its verified state could not be \
                 confirmed"
            };
            // An existing failure reason is the more specific truth and is
            // kept; this generic one only fills a gap. Replacing a recorded
            // "apply_failed:EnsureRoutes" with "the record of when this setup
            // was applied is missing" would lose the actionable half.
            let recorded = setup
                .attention_reason
                .clone()
                .unwrap_or_else(|| reason.to_string());
            let attention_at = setup
                .attention_at
                .clone()
                .or_else(|| Some(clock::now_rfc3339()));
            cas_write_health(
                conn,
                setup,
                TrackingState::NeedsAttention,
                Some(&recorded),
                attention_at,
            )?;
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
    // The upper edge of belief. `rfc3339_minus_seconds` with a negative
    // count adds, and degrades to the year-9999 sentinel on unparseable
    // input — which here means "believe nothing later than the far future",
    // i.e. it fails OPEN on the upper bound only if our own `now` is
    // unparseable, which cannot happen because we just formatted it.
    let future_after = clock::rfc3339_minus_seconds(&now, -MAX_CLOCK_SKEW_SECS);
    let mut per_provider: BTreeMap<String, Option<String>> =
        providers.iter().map(|p| (p.clone(), None)).collect();
    let mut earliest: Option<String> = None;
    {
        // Three independent admissibility conditions, all of which must
        // hold (RA-005):
        //
        //   `rowid > ?2`  — the row was physically inserted after this
        //                   setup was applied. SQLite assigns rowids
        //                   monotonically, so this is an ordering signal
        //                   the writer's wall clock cannot influence, and
        //                   it is what actually binds an observation to the
        //                   CURRENT verification session.
        //   `at >= ?3`    — and it claims a time at or after the apply
        //                   watermark, so a row back-dated into a previous
        //                   session is excluded even if it was inserted now.
        //   `at <= ?4`    — and it does not claim a time this machine's
        //                   clock says has not happened yet.
        //
        // Belt and braces on purpose: the rowid alone would be defeated by
        // deleting the highest row (rowids are reused without AUTOINCREMENT),
        // and the timestamps alone are exactly what RA-005 forged.
        let mut stmt = conn.prepare(
            "SELECT host, MIN(at), MAX(at) FROM runtime_request_events
             WHERE project_id = ?1 AND observation_source = 'gateway'
               AND rowid > ?2 AND at >= ?3 AND at <= ?4
             GROUP BY host",
        )?;
        let rows = stmt.query_map(
            params![
                setup.project_id,
                setup.applied_event_rowid,
                applied_at,
                future_after
            ],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )?;
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
            // Bounded on BOTH sides. The upper bound is redundant with the
            // SQL above today, and deliberately kept: this predicate is the
            // one a reader reaches for when asking "is this fresh?", and it
            // must not be true for a timestamp we do not believe.
            fresh: last_observed_at
                .as_deref()
                .is_some_and(|at| at >= stale_before.as_str() && at <= future_after.as_str()),
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
    //
    // `newest_observation` is now drawn only from admissible rows, so a
    // forged future timestamp can no longer out-rank a real failure just by
    // being the largest string in the table (RA-005). The comparison itself
    // is done on parsed instants rather than bytes, because RFC 3339 is not
    // byte-order-equivalent to time order: `now_rfc3339` omits the
    // fractional part when nanoseconds are zero, and `'.'` (0x2E) sorts
    // before `'Z'` (0x5A), so `12:00:00.5Z` compares as OLDER than
    // `12:00:00Z`. On the sub-second boundary that is the difference
    // between preserving a failure and erasing it.
    let failure_is_newer = match (&setup.attention_at, &newest_observation) {
        (Some(failed), Some(seen)) => instant_is_after(failed, seen),
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
        if next != setup.state && may_write {
            // ONE decision, in one place: may this write clear the failure
            // record? Only if the evidence it is derived from post-dates that
            // failure. `failure_is_newer` is the same value the `derived`
            // ladder above used, deliberately — the previous shape asked the
            // question twice, once as `failure_is_newer` and once as
            // `next == NeedsAttention`, and the second copy was unreachable
            // because the first had already forced `next`. An unreachable
            // guard is indistinguishable from a guard that does not work
            // (`VER-02`), so there is now only the reachable one.
            write_derived(conn, setup, next, failure_is_newer)?;
        }
    }

    // --- session and historical watermarks -------------------------------
    // Both are write-once. The `IS NULL` predicate makes that a property of
    // the STATEMENT rather than of the in-memory row it was decided from: two
    // processes that both read a null watermark cannot both write, so the
    // first observation to be recorded wins and the second is a no-op. These
    // are deliberately outside the row-version CAS — they touch neither the
    // state nor the failure record, so racing them must not force a caller to
    // re-derive.
    if observed_ever > 0 && setup.first_traffic_at.is_none() && may_write {
        conn.execute(
            "UPDATE tracking_setups SET first_traffic_at = ?2
             WHERE id = ?1 AND first_traffic_at IS NULL",
            params![setup.id, earliest],
        )?;
        setup.first_traffic_at = earliest.clone();
    }
    if observed_ever > 0 && setup.first_verified_at.is_none() && may_write {
        conn.execute(
            "UPDATE tracking_setups SET first_verified_at = ?2
             WHERE id = ?1 AND first_verified_at IS NULL",
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

/// The ONE statement that writes a tracking setup's health columns.
///
/// Both writers reach the database through here — [`write_derived`] for
/// evidence-derived corrections and [`transition`] for explicit,
/// legality-checked moves — so the two cannot drift apart in what they
/// preserve or how they guard the write. They diverged once already: the
/// derived path learned to keep `attention_reason` (ZFT-006) while the
/// explicit path kept its own copy of the SQL.
///
/// # Compare-and-swap, not last-writer-wins (`VER-01`)
///
/// The caller decided `next` from a [`TrackingSetup`] it read earlier. If the
/// stored row changed in between — another process recorded a failure, a
/// re-apply opened a new session, the user removed a route — then that
/// decision was made against a row that no longer exists, and committing it
/// would erase whatever replaced it. The old `WHERE id = ?1` did exactly
/// that: a failure recorded between a refresh's read and its write was nulled
/// and the UI reported `VerifiedAndActive`, which is the ZFT-006 outcome
/// reached with no attacker, no forged timestamp and no clock skew.
///
/// `WHERE id = ?1 AND row_version = ?6` makes that a zero-row update instead,
/// and a zero-row update is [`CoreError::StateConflict`] — a signal the
/// caller re-derives from. Nothing is ever overwritten on this path;
/// `rotation::set_state` has guarded rotations this way since they existed.
fn cas_write_health(
    conn: &Connection,
    setup: &mut TrackingSetup,
    next: TrackingState,
    attention_reason: Option<&str>,
    attention_at: Option<String>,
) -> Result<()> {
    let now = clock::now_rfc3339();
    let changed = conn.execute(
        "UPDATE tracking_setups
         SET state = ?2, last_transition_at = ?3, attention_reason = ?4, attention_at = ?5,
             row_version = row_version + 1
         WHERE id = ?1 AND row_version = ?6",
        params![
            setup.id,
            next.as_str(),
            now,
            attention_reason,
            attention_at,
            setup.row_version
        ],
    )?;
    if changed == 0 {
        return Err(CoreError::StateConflict {
            kind: "tracking setup",
            ident: setup.id.clone(),
        });
    }
    setup.state = next;
    setup.attention_reason = attention_reason.map(str::to_string);
    setup.attention_at = attention_at;
    setup.last_transition_at = now;
    setup.row_version += 1;
    Ok(())
}

/// Write a derived correction. These deliberately bypass the legality
/// table: they move the row to what the evidence supports.
///
/// `attention_reason` is passed through rather than nulled. The v15 code
/// nulled it unconditionally, which deleted the record of why a setup had
/// failed the moment any older traffic was found (ZFT-006).
///
/// Guarded by the row version, so a correction derived from a stale read is
/// refused rather than applied (`VER-01`).
///
/// `preserve_failure` is the ZFT-006 clause and the only thing that decides
/// whether this write may drop the failure record. The v15 code had no such
/// clause: it nulled `attention_reason` unconditionally, so the moment ANY
/// older traffic was found, the record of why a setup had failed was deleted
/// and the row was promoted back to verified. Passing `false` here reproduces
/// exactly that.
fn write_derived(
    conn: &Connection,
    setup: &mut TrackingSetup,
    next: TrackingState,
    preserve_failure: bool,
) -> Result<()> {
    let attention_reason = if preserve_failure {
        setup.attention_reason.clone()
    } else {
        None
    };
    let attention_at = if attention_reason.is_some() {
        setup
            .attention_at
            .clone()
            .or_else(|| Some(clock::now_rfc3339()))
    } else {
        None
    };
    cas_write_health(conn, setup, next, attention_reason.as_deref(), attention_at)
}

fn history_of(setup: &TrackingSetup) -> VerificationHistory {
    VerificationHistory {
        first_verified_at: setup.first_verified_at.clone(),
        // `first_traffic_at` is the OLDEST qualifying observation of this
        // session and is written once. Surfacing it under a field named
        // `last_observed_at` made one card say "most recent observation:
        // <old>" directly above a per-provider "last seen: <newer>".
        // Renamed to what it is; the newest observation is already carried
        // per provider in `freshness`.
        session_first_observed_at: setup.first_traffic_at.clone(),
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
        // Ahead of the liveness arms on purpose (`NEW-35`): for a setup whose
        // apply never finished, "the local tracking service is not running"
        // describes a symptom of the unfinished apply and points the user at
        // the service, while the thing to do is to run the setup again.
        TrackingState::Applying => CurrentHealth::ApplyIncomplete,
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
        // WHICH of the two went missing is decided here, where the evidence
        // is, and carried on the variant. A surface needs it to say the right
        // sentence, and re-deriving it downstream would put a second reading
        // of health outside this function.
        let route_missing = freshness.iter().any(|f| !f.route_present);
        let link_missing = freshness.iter().any(|f| !f.link_present);
        // Name the providers rather than counting them: "the route for
        // supabase is gone" is actionable, "1 of 3 routes is gone" is not.
        let what = match (route_missing, link_missing) {
            (true, true) => "the route and the project link",
            (true, false) => "the route",
            _ => "the project link",
        };
        let detail = format!(
            "{what} for {} is gone ({} of {} configured providers)",
            missing.join(", "),
            missing.len(),
            total
        );
        return CurrentHealth::ConfigurationChanged {
            detail,
            route_missing,
            link_missing,
        };
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
