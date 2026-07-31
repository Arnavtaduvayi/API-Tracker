//! The ONE projection of tracking health into something a screen can render.
//!
//! # Why this module exists
//!
//! `project_tracking_overview` returned [`state::TrackingStatusReport`]
//! verbatim, whose `current` is the internally tagged [`state::CurrentHealth`]
//! enum. The desktop's project page read `status.health.currently_working` — a
//! path that payload cannot contain, because `health` belongs to a *different*
//! command's DTO. The expression was `undefined` for every setup, so the page
//! fell through to "needs attention" permanently, including for a verified and
//! actively tracked project (`AUD-05`).
//!
//! The fix is not a corrected TypeScript interface. A frontend that reads
//! `status.current.kind === "verified_and_active"` is a second implementation of
//! "is tracking working?" written in a language with no way to check it against
//! the enum, and it would drift again the next time a variant is added. So the
//! projection happens **here**, in Rust, once:
//!
//! * [`state::CurrentHealth::is_currently_working`] stays the only answer to
//!   "is it working right now?";
//! * [`state::CurrentHealth::describe`] stays the only sentence;
//! * this module adds the short label, the next action, and the product-level
//!   state token a surface switches on.
//!
//! Nothing here decides health. It is given a report produced by
//! [`crate::health`] and re-expresses it; there is no second derivation, no
//! reading of `tracking_setups.state`, and no inference from history.
//!
//! # Historical traffic is never present-tense health
//!
//! [`TrackingStatusView::last_observed_at`] is the newest per-provider
//! observation the resolver found. It is carried for display **beside** the
//! state and is never consulted to produce one: a project observed yesterday
//! with a dead gateway today is `gateway_unavailable`, not `tracking_on`
//! (`ZFT-005`). The state token comes from the [`state::CurrentHealth`] variant
//! and from nothing else.
//!
//! # Attribution is reported beside health, never as health
//!
//! A gateway that forwards without a matching key is still tracking: requests
//! are recorded, only the per-credential attribution degrades
//! (`SI-11`/`SI-12`/`SI-13`). So [`AttributionState::Paused`] rides alongside a
//! working state rather than replacing it, and a paused project whose universal
//! tracking is fine reads `tracking_on` + `attribution: paused`.

use serde::Serialize;

use crate::state::{self, CurrentHealth, TrackingStatusReport};

/// The product-level tracking state a surface switches on and styles by.
///
/// Deliberately its own vocabulary rather than [`state::CurrentHealth`]'s serde
/// tag. The enum is an internal derivation with variants that mean the same
/// thing to a user (`gateway_unavailable` and
/// `verified_previously_gateway_down` are one sentence: nothing is listening)
/// and one variant that hides two different user problems
/// (`configuration_changed` is either a missing route or a missing project
/// link). Mapping is [`TrackingStatusView::of`], and it is exhaustive over
/// `CurrentHealth`, so a new variant is a compile error here rather than a
/// silent fallback on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackingStateTag {
    /// No folder has been linked to this project yet.
    NotLinked,
    /// A folder is linked and the user turned tracking off. Not a fault.
    TrackingOff,
    /// The folder is linked but Tethra cannot find it on disk.
    FolderMissing,
    /// A folder is linked, tracking is on, and no setup exists for it yet.
    AwaitingSetup,
    /// Traffic is flowing through Tethra for every configured provider.
    TrackingOn,
    /// Some configured providers are observed and fresh, others are not.
    PartiallyTracked,
    /// Applied, gateway up, nothing observed for this configuration yet.
    WaitingForFirstRequest,
    /// Applied; the user's own project has to be restarted before its
    /// requests go through Tethra.
    RestartRequired,
    /// Nothing is listening on the port the project's `.env` points at.
    GatewayUnavailable,
    /// A gateway route this setup created is gone or disabled.
    RouteUnavailable,
    /// The link binding this project to its route is gone.
    ProjectLinkUnavailable,
    /// Verified before, nothing recent. An idle project looks exactly like
    /// this, so it is not an error state.
    Idle,
    /// The applied configuration is behind the setup's current generation, or
    /// the setup changed since it was verified.
    ConfigurationChanged,
    /// Tracking works; per-credential attribution does not.
    AttributionPaused,
    /// An apply started and never reported an outcome.
    SetupIncomplete,
    /// The most recent setup or repair attempt failed.
    NeedsAttention,
    /// Nothing in this folder is trackable.
    Unsupported,
}

impl TrackingStateTag {
    /// The short label a status row shows. Never a bare token (`ZFT-030`).
    pub fn label(self) -> &'static str {
        match self {
            Self::NotLinked => "No folder selected",
            Self::TrackingOff => "Tracking is off",
            Self::FolderMissing => "Folder missing",
            Self::AwaitingSetup => "Waiting for setup",
            Self::TrackingOn => "Tracking is on",
            Self::PartiallyTracked => "Partially tracked",
            Self::WaitingForFirstRequest => "Waiting for first request",
            Self::RestartRequired => "Restart required",
            Self::GatewayUnavailable => "Gateway unavailable",
            Self::RouteUnavailable => "Route unavailable",
            Self::ProjectLinkUnavailable => "Project link unavailable",
            Self::Idle => "No recent requests",
            Self::ConfigurationChanged => "Configuration changed",
            Self::AttributionPaused => "Attribution paused",
            Self::SetupIncomplete => "Setup did not finish",
            Self::NeedsAttention => "Tracking needs attention",
            Self::Unsupported => "Nothing to track",
        }
    }

    /// Whether this state is a fault the user should act on, for styling. A
    /// project that is simply off, idle or awaiting its first request is not.
    pub fn is_fault(self) -> bool {
        matches!(
            self,
            Self::FolderMissing
                | Self::GatewayUnavailable
                | Self::RouteUnavailable
                | Self::ProjectLinkUnavailable
                | Self::ConfigurationChanged
                | Self::SetupIncomplete
                | Self::NeedsAttention
        )
    }
}

/// Whether per-credential attribution is running, and why not when it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionState {
    /// This setup never asked for attribution. Not a degradation.
    NotEnabled,
    /// Enabled and the matching key is resident.
    Active,
    /// Enabled, but the gateway holds no usable matching key. Requests are
    /// still recorded; only the per-credential attribution is unavailable.
    Paused,
}

impl AttributionState {
    /// A sentence for a surface, or `None` when there is nothing to say.
    pub fn sentence(self) -> Option<&'static str> {
        match self {
            Self::NotEnabled => None,
            Self::Active => Some("Requests are attributed to the credential that made them."),
            Self::Paused => Some(
                "Requests are still being recorded, but credential attribution is paused \
                 until the vault is unlocked for it.",
            ),
        }
    }
}

/// The facts about a project that live outside [`state::TrackingStatusReport`]
/// but change what its status means to a user.
///
/// Passed in rather than probed here so this projection stays a pure function
/// and can be tested in every combination without a filesystem or a gateway.
#[derive(Debug, Clone, Copy)]
pub struct StatusContext {
    /// A folder is linked to this project.
    pub linked: bool,
    /// `project_folder_links.tracking_enabled`.
    pub tracking_enabled: bool,
    /// The linked folder is readable on disk right now.
    pub folder_available: bool,
    /// The setup's `config_generation` is ahead of the generation the last
    /// apply reached.
    pub configuration_behind: bool,
    /// `health::attribution_is_paused` for this machine.
    pub attribution_paused: bool,
    /// This setup asked for attribution when it was applied.
    pub attribution_requested: bool,
}

impl Default for StatusContext {
    fn default() -> Self {
        Self {
            linked: false,
            tracking_enabled: false,
            folder_available: true,
            configuration_behind: false,
            attribution_paused: false,
            attribution_requested: false,
        }
    }
}

/// Tracking status, projected for a surface.
///
/// This is what a project page renders. It carries no Rust enum a caller has to
/// destructure and no field whose absence changes the meaning of another: every
/// field is present for every state.
#[derive(Debug, Clone, Serialize)]
pub struct TrackingStatusView {
    /// The product state. Rendered via `label`, switched on for styling.
    pub state: TrackingStateTag,
    /// The short label for `state`, already resolved so no surface has to own
    /// a mapping from token to English.
    pub label: String,
    /// Whether `state` is something the user should act on, for styling.
    ///
    /// Resolved here so a surface does not have to sort the states itself. It is
    /// NOT `!is_working`: a project the user switched off, one that is idle, one
    /// waiting for its first request and one with nothing trackable are all "not
    /// working" and none of them is a fault, so keying a warning box off
    /// `is_working` puts an idle project in a warning box.
    pub is_fault: bool,
    /// Whether tracking is working RIGHT NOW.
    ///
    /// Straight from [`state::CurrentHealth::is_currently_working`] — the one
    /// authority — and `false` whenever there is no health report at all. A
    /// surface asks this and nothing else to decide "is it on?".
    pub is_working: bool,
    /// The full sentence for the current state. For a state that has a health
    /// report this is [`state::CurrentHealth::describe`] verbatim.
    pub sentence: String,
    /// What the user should do next, or `None` when there is nothing to do.
    pub action: Option<String>,
    /// The newest observation across configured providers.
    ///
    /// HISTORY. Displayed beside `state`, never used to derive it: traffic
    /// recorded before the gateway died does not make tracking healthy now.
    pub last_observed_at: Option<String>,
    /// The first time this setup was ever verified, across all sessions.
    pub first_verified_at: Option<String>,
    /// Per-credential attribution, reported beside health rather than folded
    /// into it.
    pub attribution: AttributionState,
    /// `true` when the setup exists but its `config_generation` is ahead of the
    /// last applied one — reported even while tracking works, because it is
    /// about what will happen next rather than what is happening now.
    pub configuration_behind: bool,
    /// The linked folder is readable on disk.
    pub folder_available: bool,
}

impl TrackingStatusView {
    /// Project a report (or its absence) plus the surrounding project facts
    /// into what a screen renders.
    ///
    /// # Precedence
    ///
    /// Structural facts that make every offered action wrong come first: an
    /// unlinked project, tracking the user switched off, a folder that is no
    /// longer there. Below those the [`state::CurrentHealth`] variant decides,
    /// exhaustively.
    ///
    /// `folder_available` outranks health because every control the page offers
    /// for a linked folder — Rescan, Change folder, Undo — acts on the folder,
    /// and each of them fails or misleads when it is gone. `is_working` is NOT
    /// overridden by it: whether traffic is flowing is still the resolver's
    /// answer, so a surface cannot be made to claim tracking stopped by a fact
    /// that did not stop it.
    pub fn of(report: Option<&TrackingStatusReport>, ctx: &StatusContext) -> Self {
        let is_working = report
            .map(|r| r.current.is_currently_working())
            .unwrap_or(false);
        let last_observed_at = report.and_then(newest_observation);
        let first_verified_at = report.and_then(|r| r.history.first_verified_at.clone());
        let attribution = match (ctx.attribution_requested, ctx.attribution_paused) {
            (false, _) => AttributionState::NotEnabled,
            (true, true) => AttributionState::Paused,
            (true, false) => AttributionState::Active,
        };

        let (state, sentence, action) = Self::resolve(report, ctx);

        Self {
            state,
            label: state.label().to_string(),
            is_fault: state.is_fault(),
            is_working,
            sentence,
            action,
            last_observed_at,
            first_verified_at,
            attribution,
            configuration_behind: ctx.configuration_behind,
            folder_available: ctx.folder_available,
        }
    }

    /// The state, its sentence and its action. Split out so the field
    /// assembly above stays readable and this stays exhaustive.
    fn resolve(
        report: Option<&TrackingStatusReport>,
        ctx: &StatusContext,
    ) -> (TrackingStateTag, String, Option<String>) {
        use TrackingStateTag as T;

        if !ctx.linked {
            return (
                T::NotLinked,
                "No folder is linked to this project yet, so there is nothing to track."
                    .to_string(),
                Some("Select this project's folder.".to_string()),
            );
        }
        if !ctx.tracking_enabled {
            return (
                T::TrackingOff,
                "Tracking is off for this project. The folder stays linked and everything \
                 already recorded is kept."
                    .to_string(),
                Some("Enable tracking to start observing again.".to_string()),
            );
        }
        if !ctx.folder_available {
            return (
                T::FolderMissing,
                "Tethra can no longer find this project's folder. Nothing already recorded is \
                 affected, and no file has been changed."
                    .to_string(),
                // Deliberately NOT "rescan": a rescan of a folder that is not
                // there fails with a raw filesystem error.
                Some(
                    "Choose the folder again if it moved, or unlink it if the project is gone."
                        .to_string(),
                ),
            );
        }
        let Some(report) = report else {
            return (
                T::AwaitingSetup,
                "This folder is linked, but tracking has not been set up for it yet.".to_string(),
                Some("Select the folder again to finish setting tracking up.".to_string()),
            );
        };

        // From here the health resolver decides. `describe()` is used verbatim
        // as the sentence so this module cannot state something the shared
        // resolver would not.
        let sentence = report.current.describe();
        let (tag, action) = match &report.current {
            CurrentHealth::VerifiedAndActive => {
                // The one state that is unambiguously fine. A configuration
                // that is behind is worth saying even here, because it changes
                // what the NEXT request will do.
                let action = ctx.configuration_behind.then(|| {
                    "This project's setup changed since it was last applied. Select the folder \
                     again to apply it."
                        .to_string()
                });
                (T::TrackingOn, action)
            }
            CurrentHealth::PartiallyTracked { .. } => (
                T::PartiallyTracked,
                Some(
                    "Make a request to the providers that have not been seen yet, or open \
                     advanced tracking diagnostics to see which ones."
                        .to_string(),
                ),
            ),
            CurrentHealth::WaitingForFirstRequest => (
                T::WaitingForFirstRequest,
                Some("Run your project and make one API request.".to_string()),
            ),
            CurrentHealth::NeedsRestart => (
                T::RestartRequired,
                Some("Restart your project, then make one request.".to_string()),
            ),
            // Both liveness failures are one problem for the user: the port
            // their application posts to has nothing behind it. The history
            // half of the difference is already carried in `first_verified_at`.
            CurrentHealth::GatewayUnavailable | CurrentHealth::VerifiedPreviouslyGatewayDown => (
                T::GatewayUnavailable,
                Some(
                    "Requests are failing right now. Open advanced tracking diagnostics to \
                     start the local helper."
                        .to_string(),
                ),
            ),
            CurrentHealth::ConfigurationChanged {
                route_missing,
                link_missing,
                ..
            } => match (route_missing, link_missing) {
                (true, false) => (
                    T::RouteUnavailable,
                    Some(
                        "The destination Tethra registered for this project is gone. Select \
                         the folder again to register it."
                            .to_string(),
                    ),
                ),
                (false, true) => (
                    T::ProjectLinkUnavailable,
                    Some(
                        "This project is no longer attached to the destination Tethra \
                         registered for it. Select the folder again to reattach it."
                            .to_string(),
                    ),
                ),
                // Both gone, or a future cause that sets neither: the generic
                // state, which is why it is in the vocabulary.
                _ => (
                    T::ConfigurationChanged,
                    Some("Select the folder again to re-apply this project's setup.".to_string()),
                ),
            },
            CurrentHealth::VerifiedPreviouslyIdle { .. } => (
                T::Idle,
                // Not an error and not an instruction: an idle project is a
                // normal project, and telling the user to fix it would be
                // wrong.
                None,
            ),
            CurrentHealth::ApplyIncomplete => (
                T::SetupIncomplete,
                Some("Select the folder again to finish setting tracking up.".to_string()),
            ),
            CurrentHealth::NeedsAttention { .. } => (
                T::NeedsAttention,
                Some(
                    "Open advanced tracking diagnostics to see what failed, then select the \
                     folder again."
                        .to_string(),
                ),
            ),
            CurrentHealth::AttributionPaused => (
                T::AttributionPaused,
                Some(
                    "Unlock the vault for attribution. Requests are being recorded either way."
                        .to_string(),
                ),
            ),
            CurrentHealth::NotConfigured => (
                T::AwaitingSetup,
                Some("Select the folder again to finish setting tracking up.".to_string()),
            ),
            CurrentHealth::Unsupported => (
                T::Unsupported,
                // Nothing to do: the folder has no API integration Tethra can
                // configure, which is a fact about the project, not a failure.
                None,
            ),
        };
        (tag, sentence, action)
    }
}

/// The newest per-provider observation in a report, or `None`.
///
/// Compared as RFC 3339 strings, which sort lexicographically in the one
/// spelling this codebase writes (`clock::now_rfc3339`). Purely for display.
fn newest_observation(report: &TrackingStatusReport) -> Option<String> {
    report
        .freshness
        .iter()
        .filter_map(|f| f.last_observed_at.as_deref())
        .max()
        .map(str::to_string)
}

/// Whether the setup this report came from asked for attribution.
///
/// Reads the persisted plan summary rather than guessing: a project that never
/// enabled attribution must not be told attribution is "paused", which is what
/// a bare `attribution_is_paused()` probe says for every project on a machine
/// whose gateway holds no key.
pub fn attribution_was_requested(setup: &state::TrackingSetup) -> bool {
    setup
        .plan_summary_json
        .as_deref()
        .and_then(|json| serde_json::from_str::<state::PlanSummary>(json).ok())
        .map(|s| s.attribution_enabled)
        .unwrap_or(false)
}
