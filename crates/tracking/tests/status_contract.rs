//! The tracking-status contract: one shape, agreed by Rust, the Tauri command
//! and the frontend (`AUD-05`).
//!
//! # What went wrong
//!
//! `project_tracking_overview` returns `project::ProjectOverview` verbatim, so
//! its `status` field is a serialized `state::TrackingStatusReport`:
//!
//! ```json
//! { "current": { "kind": "verified_and_active" }, "history": {…},
//!   "freshness": […], "state": "traffic_observed" }
//! ```
//!
//! The desktop declared that field as `TrackingStatus` — the DTO of a
//! *different* command — and read `status.health.currently_working`. There is no
//! `health` key in this payload and no `currently_working` boolean anywhere in
//! it, so the expression was `undefined` for every setup and the project page
//! rendered "needs attention" permanently, including for a verified and actively
//! tracked project. `ProjectTracking.test.tsx` passed `status: null` throughout,
//! so nothing exercised the branch.
//!
//! # What holds it closed
//!
//! Two things, and neither is a hand-written interface:
//!
//! * the projection is computed in Rust (`statusview::TrackingStatusView`), so a
//!   surface renders a finished answer instead of destructuring an enum;
//! * the exact serialized bytes of the real DTO are asserted here, and the same
//!   bytes are written to a fixture the frontend tests load — so a field renamed
//!   in Rust fails this suite and the frontend suite together, rather than
//!   silently becoming `undefined` on a screen.
//!
//! Everything below serializes REAL types. No test in this file constructs a
//! JSON literal and calls it a payload.

mod common;

use std::path::Path;

use api_tracker_core::projectlink::ProjectFolderLink;
use api_tracker_tracking::project::ProjectOverview;
use api_tracker_tracking::state::{
    CurrentHealth, ProviderFreshness, TrackingState, TrackingStatusReport, VerificationHistory,
};
use api_tracker_tracking::statusview::{AttributionState, StatusContext, TrackingStatusView};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Fixtures built from the real types
// ---------------------------------------------------------------------------

fn history() -> VerificationHistory {
    VerificationHistory {
        first_verified_at: Some("2026-07-29T10:01:00Z".to_string()),
        session_first_observed_at: Some("2026-07-29T10:02:00Z".to_string()),
        verification_session: Some("sess-1".to_string()),
        config_generation: 1,
    }
}

fn fresh(provider: &str, at: &str) -> ProviderFreshness {
    ProviderFreshness {
        provider_id: provider.to_string(),
        last_observed_at: Some(at.to_string()),
        route_present: true,
        link_present: true,
        fresh: true,
    }
}

fn report(current: CurrentHealth, state: TrackingState) -> TrackingStatusReport {
    TrackingStatusReport {
        current,
        history: history(),
        freshness: vec![
            fresh("openai", "2026-07-29T10:05:00Z"),
            fresh("anthropic", "2026-07-29T10:07:00Z"),
        ],
        state,
    }
}

fn link() -> ProjectFolderLink {
    ProjectFolderLink {
        project_id: "p1".to_string(),
        folder_path: "/work/app".to_string(),
        tracking_enabled: true,
        linked_at: "2026-07-29T10:00:00Z".to_string(),
        last_scan_at: Some("2026-07-29T10:00:00Z".to_string()),
        scan_fingerprint: Some("fp-1".to_string()),
        applied_generation: 1,
        last_activity_refresh_at: None,
        row_version: 2,
    }
}

fn linked_context() -> StatusContext {
    StatusContext {
        linked: true,
        tracking_enabled: true,
        folder_available: true,
        configuration_behind: false,
        attribution_paused: false,
        attribution_requested: false,
    }
}

/// A complete `ProjectOverview`, assembled from the real struct so that what is
/// serialized below is the payload the Tauri command actually returns.
fn overview_of(report: Option<TrackingStatusReport>, ctx: StatusContext) -> ProjectOverview {
    ProjectOverview {
        project_id: "p1".to_string(),
        link: ctx.linked.then(|| ProjectFolderLink {
            tracking_enabled: ctx.tracking_enabled,
            ..link()
        }),
        tracking: TrackingStatusView::of(report.as_ref(), &ctx),
        status: report,
        scan_stale: false,
        folder_available: ctx.folder_available,
        configuration_behind: ctx.configuration_behind,
        detected_credentials: Vec::new(),
        credentials_needing_details: 0,
        attribution_paused: ctx.attribution_paused,
    }
}

/// Every user-visible state, as `(fixture key, ProjectOverview)`.
///
/// Named by the fixture key rather than by the Rust variant because the point
/// is the state a user sees: `gateway_unavailable` covers two enum variants
/// that mean one thing to a person.
fn every_state() -> Vec<(&'static str, ProjectOverview)> {
    let idle_at = "2026-07-20T09:00:00Z".to_string();
    vec![
        (
            "tracking_on",
            overview_of(
                Some(report(
                    CurrentHealth::VerifiedAndActive,
                    TrackingState::TrafficObserved,
                )),
                linked_context(),
            ),
        ),
        (
            "partially_tracked",
            overview_of(
                Some(report(
                    CurrentHealth::PartiallyTracked {
                        observed: 1,
                        total: 2,
                    },
                    TrackingState::PartiallyObserved,
                )),
                linked_context(),
            ),
        ),
        (
            "waiting_for_first_request",
            overview_of(
                Some(report(
                    CurrentHealth::WaitingForFirstRequest,
                    TrackingState::AwaitingFirstRequest,
                )),
                linked_context(),
            ),
        ),
        (
            "restart_required",
            overview_of(
                Some(report(
                    CurrentHealth::NeedsRestart,
                    TrackingState::AwaitingRestart,
                )),
                linked_context(),
            ),
        ),
        (
            "gateway_unavailable",
            overview_of(
                Some(report(
                    CurrentHealth::GatewayUnavailable,
                    TrackingState::AwaitingFirstRequest,
                )),
                linked_context(),
            ),
        ),
        (
            // The other liveness variant. Same user-visible state, and its
            // history is what distinguishes it — not its headline.
            "gateway_unavailable_after_verification",
            overview_of(
                Some(report(
                    CurrentHealth::VerifiedPreviouslyGatewayDown,
                    TrackingState::TrafficObserved,
                )),
                linked_context(),
            ),
        ),
        (
            "route_unavailable",
            overview_of(
                Some(report(
                    CurrentHealth::ConfigurationChanged {
                        detail: "the route for openai is gone (1 of 2 configured providers)"
                            .to_string(),
                        route_missing: true,
                        link_missing: false,
                    },
                    TrackingState::NeedsAttention,
                )),
                linked_context(),
            ),
        ),
        (
            "project_link_unavailable",
            overview_of(
                Some(report(
                    CurrentHealth::ConfigurationChanged {
                        detail: "the project link for openai is gone (1 of 2 configured providers)"
                            .to_string(),
                        route_missing: false,
                        link_missing: true,
                    },
                    TrackingState::NeedsAttention,
                )),
                linked_context(),
            ),
        ),
        (
            "configuration_changed",
            overview_of(
                Some(report(
                    CurrentHealth::ConfigurationChanged {
                        detail: "the route and the project link for openai is gone (1 of 2 \
                                 configured providers)"
                            .to_string(),
                        route_missing: true,
                        link_missing: true,
                    },
                    TrackingState::NeedsAttention,
                )),
                linked_context(),
            ),
        ),
        (
            // Working universal tracking, attribution degraded. The state must
            // stay `tracking_on`: a paused matching key does not stop a single
            // request being recorded (SI-11/SI-12).
            "attribution_paused",
            overview_of(
                Some(report(
                    CurrentHealth::VerifiedAndActive,
                    TrackingState::TrafficObserved,
                )),
                StatusContext {
                    attribution_paused: true,
                    attribution_requested: true,
                    ..linked_context()
                },
            ),
        ),
        (
            // The `CurrentHealth::AttributionPaused` VARIANT, as distinct from
            // the scenario above. The current resolver never selects it, but it
            // is part of the enum and the projection is exhaustive over the
            // enum — an unhandled variant must be a compile error here, not a
            // blank label on a screen later.
            "health_attribution_paused",
            overview_of(
                Some(report(
                    CurrentHealth::AttributionPaused,
                    TrackingState::TrafficObserved,
                )),
                StatusContext {
                    attribution_paused: true,
                    attribution_requested: true,
                    ..linked_context()
                },
            ),
        ),
        (
            "needs_attention",
            overview_of(
                Some(report(
                    CurrentHealth::NeedsAttention {
                        reason: "the local helper could not be installed".to_string(),
                    },
                    TrackingState::NeedsAttention,
                )),
                linked_context(),
            ),
        ),
        (
            "setup_incomplete",
            overview_of(
                Some(report(
                    CurrentHealth::ApplyIncomplete,
                    TrackingState::Applying,
                )),
                linked_context(),
            ),
        ),
        (
            "idle",
            overview_of(
                Some(report(
                    CurrentHealth::VerifiedPreviouslyIdle {
                        last_observed_at: idle_at,
                    },
                    TrackingState::TrafficObserved,
                )),
                linked_context(),
            ),
        ),
        (
            "unsupported",
            overview_of(
                Some(report(
                    CurrentHealth::Unsupported,
                    TrackingState::Unsupported,
                )),
                linked_context(),
            ),
        ),
        (
            "folder_missing",
            overview_of(
                Some(report(
                    CurrentHealth::VerifiedAndActive,
                    TrackingState::TrafficObserved,
                )),
                StatusContext {
                    folder_available: false,
                    ..linked_context()
                },
            ),
        ),
        (
            "tracking_off",
            overview_of(
                Some(report(
                    CurrentHealth::VerifiedAndActive,
                    TrackingState::TrafficObserved,
                )),
                StatusContext {
                    tracking_enabled: false,
                    ..linked_context()
                },
            ),
        ),
        (
            "awaiting_setup",
            overview_of(None, StatusContext { ..linked_context() }),
        ),
        (
            "not_linked",
            overview_of(
                None,
                StatusContext {
                    linked: false,
                    tracking_enabled: false,
                    ..linked_context()
                },
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// The serialized shape
// ---------------------------------------------------------------------------

/// `status` serializes as a `TrackingStatusReport`, and `status.health` — the
/// exact path the project page used to read — does not exist.
///
/// This is `AUD-04`/`AUD-05` as an assertion: the payload the backend can emit,
/// checked against the payload a surface believed in.
#[test]
fn the_overview_status_is_a_tracking_status_report_with_no_health_key() {
    let overview = overview_of(
        Some(report(
            CurrentHealth::VerifiedAndActive,
            TrackingState::TrafficObserved,
        )),
        linked_context(),
    );
    let v = serde_json::to_value(&overview).unwrap();
    let status = &v["status"];

    // What the backend really emits.
    assert_eq!(status["current"]["kind"], "verified_and_active");
    assert!(status.get("history").is_some());
    assert!(status.get("freshness").is_some());
    assert_eq!(status["state"], "traffic_observed");

    // What the frontend used to read. Absent, both levels of it.
    assert!(
        status.get("health").is_none(),
        "`status.health` does not exist at the Tauri boundary and never did"
    );
    assert!(
        status
            .get("health")
            .and_then(|h| h.get("currently_working"))
            .is_none(),
        "`status.health.currently_working` — the exact path ProjectTracking.tsx \
         read — is unreachable"
    );
    // Proof it was the wrong DTO rather than a renamed field: `TrackingStatus`'s
    // own required fields are absent too.
    assert!(status.get("setup_id").is_none() && status.get("watch").is_none());
}

/// The projected view is present for EVERY state, including the ones with no
/// report at all, and carries every field the frontend type declares.
#[test]
fn the_projected_view_is_present_and_complete_for_every_state() {
    const FIELDS: [&str; 10] = [
        "state",
        "label",
        "is_working",
        "sentence",
        "action",
        "last_observed_at",
        "first_verified_at",
        "attribution",
        "configuration_behind",
        "folder_available",
    ];
    for (key, overview) in every_state() {
        let v = serde_json::to_value(&overview).unwrap();
        let tracking = v
            .get("tracking")
            .unwrap_or_else(|| panic!("{key}: no `tracking` field"));
        assert!(
            tracking.is_object(),
            "{key}: `tracking` must always be an object, never null — a surface \
             that tests for absence can read the wrong absence"
        );
        for field in FIELDS {
            assert!(
                tracking.get(field).is_some(),
                "{key}: `tracking.{field}` is missing"
            );
        }
        assert!(
            tracking["label"].as_str().is_some_and(|s| !s.is_empty()),
            "{key}: every state needs a rendered label, never a bare token"
        );
        assert!(
            tracking["sentence"].as_str().is_some_and(|s| !s.is_empty()),
            "{key}: every state needs a sentence"
        );
    }
}

/// The state token, the label and `is_working` for each user-visible state.
///
/// `is_working` comes from `CurrentHealth::is_currently_working` and from
/// nothing else, so this table is also the assertion that no state invented its
/// own idea of "working".
#[test]
fn every_user_visible_state_projects_to_its_label() {
    let expected: Vec<(&str, &str, &str, bool)> = vec![
        // fixture key, state token, label, is_working
        ("tracking_on", "tracking_on", "Tracking is on", true),
        (
            "partially_tracked",
            "partially_tracked",
            "Partially tracked",
            true,
        ),
        (
            "waiting_for_first_request",
            "waiting_for_first_request",
            "Waiting for first request",
            false,
        ),
        (
            "restart_required",
            "restart_required",
            "Restart required",
            false,
        ),
        (
            "gateway_unavailable",
            "gateway_unavailable",
            "Gateway unavailable",
            false,
        ),
        (
            "gateway_unavailable_after_verification",
            "gateway_unavailable",
            "Gateway unavailable",
            false,
        ),
        (
            "route_unavailable",
            "route_unavailable",
            "Route unavailable",
            false,
        ),
        (
            "project_link_unavailable",
            "project_link_unavailable",
            "Project link unavailable",
            false,
        ),
        (
            "configuration_changed",
            "configuration_changed",
            "Configuration changed",
            false,
        ),
        // Attribution paused rides BESIDE a working state. If this row ever
        // reads `false`, a vault lock has been turned into a tracking failure.
        ("attribution_paused", "tracking_on", "Tracking is on", true),
        // The enum variant itself. `is_currently_working` is false for it —
        // that is the shared resolver's own definition, not a second one — and
        // its sentence says tracking is active, so the state is not read as a
        // complete failure.
        (
            "health_attribution_paused",
            "attribution_paused",
            "Attribution paused",
            false,
        ),
        (
            "needs_attention",
            "needs_attention",
            "Tracking needs attention",
            false,
        ),
        (
            "setup_incomplete",
            "setup_incomplete",
            "Setup did not finish",
            false,
        ),
        ("idle", "idle", "No recent requests", false),
        ("unsupported", "unsupported", "Nothing to track", false),
        ("folder_missing", "folder_missing", "Folder missing", true),
        ("tracking_off", "tracking_off", "Tracking is off", true),
        (
            "awaiting_setup",
            "awaiting_setup",
            "Waiting for setup",
            false,
        ),
        ("not_linked", "not_linked", "No folder selected", false),
    ];
    let states = every_state();
    assert_eq!(
        states.len(),
        expected.len(),
        "every fixture must be asserted here"
    );

    for (key, state, label, is_working) in expected {
        let (_, overview) = states
            .iter()
            .find(|(k, _)| *k == key)
            .unwrap_or_else(|| panic!("no fixture named {key}"));
        let v = serde_json::to_value(overview).unwrap();
        assert_eq!(v["tracking"]["state"], state, "{key}: state token");
        assert_eq!(v["tracking"]["label"], label, "{key}: label");
        assert_eq!(
            v["tracking"]["is_working"], is_working,
            "{key}: `is_working` must be `CurrentHealth::is_currently_working` \
             and must not be overridden by a structural fact"
        );
    }
}

/// Attribution is reported beside health, and a setup that never asked for it
/// is not told it is "paused".
#[test]
fn attribution_is_beside_health_not_instead_of_it() {
    let working = report(
        CurrentHealth::VerifiedAndActive,
        TrackingState::TrafficObserved,
    );

    // Requested and paused: tracking still on, attribution paused.
    let paused = TrackingStatusView::of(
        Some(&working),
        &StatusContext {
            attribution_paused: true,
            attribution_requested: true,
            ..linked_context()
        },
    );
    assert!(paused.is_working, "a paused key does not stop tracking");
    assert_eq!(paused.attribution, AttributionState::Paused);

    // Never requested, on a machine whose gateway holds no key. A bare
    // `attribution_is_paused()` is true for every project on such a machine, so
    // reporting "paused" here would be a warning about a feature the user never
    // turned on.
    let never = TrackingStatusView::of(
        Some(&working),
        &StatusContext {
            attribution_paused: true,
            attribution_requested: false,
            ..linked_context()
        },
    );
    assert_eq!(never.attribution, AttributionState::NotEnabled);

    // Requested and resident.
    let active = TrackingStatusView::of(
        Some(&working),
        &StatusContext {
            attribution_paused: false,
            attribution_requested: true,
            ..linked_context()
        },
    );
    assert_eq!(active.attribution, AttributionState::Active);
}

/// Historical traffic never produces a present-tense success.
///
/// The freshness rows carry observations; the gateway is down. `ZFT-005` is
/// exactly the defect where the first fact was allowed to answer for the second.
#[test]
fn historical_traffic_cannot_create_present_tense_health() {
    let down = report(
        CurrentHealth::VerifiedPreviouslyGatewayDown,
        TrackingState::TrafficObserved,
    );
    let view = TrackingStatusView::of(Some(&down), &linked_context());

    assert!(
        view.last_observed_at.is_some(),
        "the fixture must carry observations, or this proves nothing"
    );
    assert!(view.first_verified_at.is_some());
    assert!(
        !view.is_working,
        "an observation recorded before the gateway died is history"
    );
    assert_eq!(view.state.label(), "Gateway unavailable");
    assert!(
        view.action.is_some(),
        "a state the user must act on names the action"
    );

    // And the idle case: observed, gateway up, nothing recent.
    let idle = report(
        CurrentHealth::VerifiedPreviouslyIdle {
            last_observed_at: "2026-07-20T09:00:00Z".to_string(),
        },
        TrackingState::TrafficObserved,
    );
    let idle_view = TrackingStatusView::of(Some(&idle), &linked_context());
    assert!(!idle_view.is_working);
    assert_eq!(idle_view.state.label(), "No recent requests");
    assert!(
        idle_view.action.is_none(),
        "an idle project is a normal project, not one to fix"
    );
}

/// `last_observed_at` is the NEWEST observation across providers, and is
/// carried for display only.
#[test]
fn last_observed_at_is_the_newest_observation_and_is_display_only() {
    let view = TrackingStatusView::of(
        Some(&report(
            CurrentHealth::VerifiedAndActive,
            TrackingState::TrafficObserved,
        )),
        &linked_context(),
    );
    assert_eq!(
        view.last_observed_at.as_deref(),
        Some("2026-07-29T10:07:00Z"),
        "the newest of the two providers, not the first"
    );
    // The same observations with a dead gateway do not make it working — see
    // `historical_traffic_cannot_create_present_tense_health`.
}

/// `CurrentHealth::kind` is byte-for-byte the tag serde writes, for every
/// variant. One answer, so a surface and the wire format cannot disagree.
#[test]
fn the_health_kind_helper_matches_what_serde_writes() {
    let variants = vec![
        CurrentHealth::VerifiedAndActive,
        CurrentHealth::PartiallyTracked {
            observed: 1,
            total: 2,
        },
        CurrentHealth::VerifiedPreviouslyGatewayDown,
        CurrentHealth::VerifiedPreviouslyIdle {
            last_observed_at: "2026-07-20T09:00:00Z".to_string(),
        },
        CurrentHealth::WaitingForFirstRequest,
        CurrentHealth::ApplyIncomplete,
        CurrentHealth::NeedsRestart,
        CurrentHealth::ConfigurationChanged {
            detail: "x".to_string(),
            route_missing: true,
            link_missing: false,
        },
        CurrentHealth::GatewayUnavailable,
        CurrentHealth::NeedsAttention {
            reason: "x".to_string(),
        },
        CurrentHealth::AttributionPaused,
        CurrentHealth::NotConfigured,
        CurrentHealth::Unsupported,
    ];
    for v in &variants {
        let serialized = serde_json::to_value(v).unwrap();
        assert_eq!(
            serialized["kind"].as_str().unwrap(),
            v.kind(),
            "`kind()` and serde disagree for {v:?}"
        );
        assert!(
            !v.describe().is_empty(),
            "every variant needs a sentence: {v:?}"
        );
    }
}

/// A route gone and a link gone are different problems with different fixes,
/// and the distinction is decided in the resolver rather than parsed back out
/// of prose.
#[test]
fn a_missing_route_and_a_missing_link_are_different_states() {
    let route = TrackingStatusView::of(
        Some(&report(
            CurrentHealth::ConfigurationChanged {
                detail: "d".to_string(),
                route_missing: true,
                link_missing: false,
            },
            TrackingState::NeedsAttention,
        )),
        &linked_context(),
    );
    let link_gone = TrackingStatusView::of(
        Some(&report(
            CurrentHealth::ConfigurationChanged {
                detail: "d".to_string(),
                route_missing: false,
                link_missing: true,
            },
            TrackingState::NeedsAttention,
        )),
        &linked_context(),
    );
    assert_eq!(route.label, "Route unavailable");
    assert_eq!(link_gone.label, "Project link unavailable");
    assert_ne!(route.action, link_gone.action);
}

// ---------------------------------------------------------------------------
// The Tauri boundary
// ---------------------------------------------------------------------------

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

/// `project_tracking_overview` returns THIS struct, not a re-shaped DTO.
///
/// The serialization assertions above are only about the payload the frontend
/// sees if the command returns `ProjectOverview`. A grep is a blunt instrument,
/// but a command quietly re-wrapped into another type is exactly the change no
/// serialization test can observe — and the original defect was a frontend
/// reading one command's DTO for another's.
#[test]
fn the_tauri_command_returns_the_project_overview_this_suite_asserts() {
    let main_rs = std::fs::read_to_string(repo_root().join("apps/desktop/src-tauri/src/main.rs"))
        .expect("the desktop entry point must exist");
    assert!(
        main_rs.contains("fn project_tracking_overview("),
        "the projects-first overview command must exist"
    );
    assert!(
        main_rs.contains("CmdResult<tracking_project::ProjectOverview>"),
        "`project_tracking_overview` must return `tracking_project::ProjectOverview` \
         verbatim — if it is re-wrapped, the shape asserted in this file is not the \
         shape the frontend receives"
    );
    assert!(
        main_rs.contains("tracking_project::overview(vault.connection(), &data_dir, &project.id)"),
        "the command must delegate to `project::overview`, which is where the \
         projection is built"
    );
    // The desktop must not carry its own copy of the health-tag mapping. It did,
    // and a variant added in the tracking crate would have serialized under one
    // name from one command and another from the next.
    assert!(
        !main_rs.contains("fn health_kind("),
        "the desktop must use `CurrentHealth::kind`, not a local copy of its match"
    );
}

// ---------------------------------------------------------------------------
// The fixture the frontend tests load
// ---------------------------------------------------------------------------

const FIXTURE_REL: &str = "apps/desktop/src/test/fixtures/project-overview.generated.json";

/// The frontend's fixtures ARE these bytes.
///
/// The audited defect survived because the frontend's fixture was a hand-written
/// object the backend could not emit (`status: null` throughout, and a
/// `TrackingStatus` shape nothing produces). A fixture written by Rust cannot be
/// wrong about the shape: if a field is renamed here, this test fails, and if it
/// is regenerated the frontend suite fails on the field it no longer finds.
///
/// Set `UPDATE_STATUS_FIXTURE=1` to rewrite it after an intended change.
#[test]
fn the_frontend_fixture_is_what_rust_serializes() {
    let mut map = serde_json::Map::new();
    map.insert(
        "_generated_by".to_string(),
        json!("crates/tracking/tests/status_contract.rs — do not edit by hand"),
    );
    for (key, overview) in every_state() {
        map.insert(key.to_string(), serde_json::to_value(&overview).unwrap());
    }
    let generated = format!(
        "{}\n",
        serde_json::to_string_pretty(&Value::Object(map)).unwrap()
    );

    let path = repo_root().join(FIXTURE_REL);
    if std::env::var("UPDATE_STATUS_FIXTURE").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "{FIXTURE_REL} is missing. Regenerate with \
             `UPDATE_STATUS_FIXTURE=1 cargo test -p api-tracker-tracking --test status_contract`"
        )
    });
    assert_eq!(
        committed, generated,
        "{FIXTURE_REL} is out of date with the Rust DTO. Regenerate with \
         `UPDATE_STATUS_FIXTURE=1 cargo test -p api-tracker-tracking --test status_contract` \
         and re-run the frontend suite."
    );
}
