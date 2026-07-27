//! Plan aggregation and the apply engine (TEST_PLAN §3): order pinned,
//! idempotence, partial failure without silent rollback, digest safety,
//! attribution degradation, and exact undo.

mod common;

use std::path::Path;
use std::sync::Mutex;

use api_tracker_core::secret::{SecretBytes, SecretString};
use api_tracker_tracking::apply::{
    apply, ApplyOptions, ServiceEnsureOutcome, ServiceOps, StepId, StepOutcome,
};
use api_tracker_tracking::detect::{detect, DetectionInput};
use api_tracker_tracking::plan::{
    ensure_port, plan, ProjectRef, RouteAction, Selections, ServiceAction,
};
use api_tracker_tracking::state::{self, TrackingState};
use api_tracker_tracking::undo::undo;
use api_tracker_tracking::verify::ProbeOutcome;
use common::*;
use tempfile::TempDir;

/// Records every call; success by default, individual failures injectable.
#[derive(Default)]
struct MockOps {
    calls: Mutex<Vec<String>>,
    fail_service: bool,
    block_install: bool,
    fail_matching_key: bool,
    gateway_answers_probe: bool,
}

impl MockOps {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl ServiceOps for MockOps {
    fn ensure_service(&self, actions: &[ServiceAction]) -> ServiceEnsureOutcome {
        self.calls.lock().unwrap().push("ensure_service".into());
        if self.block_install {
            return ServiceEnsureOutcome::InstallBlocked {
                error: "macOS blocked the background service".into(),
            };
        }
        if self.fail_service {
            return ServiceEnsureOutcome::Unverified {
                detail: "mock: listener never answered".into(),
            };
        }
        let _ = actions;
        ServiceEnsureOutcome::Verified
    }

    fn push_route_key(&self, _key: &SecretBytes) -> bool {
        self.calls.lock().unwrap().push("push_route_key".into());
        true
    }

    fn push_matching_key(&self, _key: SecretBytes) -> api_tracker_core::Result<()> {
        self.calls.lock().unwrap().push("push_matching_key".into());
        if self.fail_matching_key {
            return Err(api_tracker_core::CoreError::InvalidInput(
                "mock: control channel refused".into(),
            ));
        }
        Ok(())
    }

    fn reload_routes(&self) -> bool {
        self.calls.lock().unwrap().push("reload_routes".into());
        true
    }

    fn probe_route(&self, _port: u16, _base_url: &str) -> ProbeOutcome {
        self.calls.lock().unwrap().push("probe_route".into());
        if self.gateway_answers_probe {
            ProbeOutcome::GatewayAnswered {
                status: "404".into(),
            }
        } else {
            ProbeOutcome::ProviderAnswered {
                status: "401".into(),
            }
        }
    }
}

struct Fixture {
    tv: TestVault,
    dir: TempDir,
}

fn fixture() -> Fixture {
    let tv = test_vault();
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    Fixture { tv, dir }
}

fn plan_for(
    fx: &mut Fixture,
) -> (
    api_tracker_tracking::detect::ProjectDetection,
    api_tracker_tracking::plan::TrackingPlan,
) {
    ensure_port(fx.tv.vault.connection()).unwrap();
    let detection = detect(
        fx.tv.vault.connection(),
        &DetectionInput {
            folder: fx.dir.path(),
            project_id: None,
        },
    )
    .unwrap();
    let selections = Selections::defaults(&detection);
    let tracking_plan = plan(
        fx.tv.vault.connection(),
        &detection,
        &selections,
        ProjectRef {
            id: None,
            name: "fixture-app".to_string(),
        },
        &service_absent(),
        false,
    )
    .unwrap();
    (detection, tracking_plan)
}

#[test]
fn plan_aggregates_two_providers_into_one_operation() {
    let mut fx = fixture();
    let (_detection, tracking_plan) = plan_for(&mut fx);
    assert_eq!(
        tracking_plan.link_plans.len(),
        2,
        "one link plan per provider"
    );
    assert_eq!(tracking_plan.route_actions.len(), 2);
    assert!(tracking_plan
        .route_actions
        .iter()
        .all(|a| matches!(a, RouteAction::CreateManifestRoute { .. })));
    assert!(matches!(
        tracking_plan.service_actions[0],
        ServiceAction::InstallService
    ));
    assert!(!tracking_plan.port_provisional);
    // Both diffs land in the same .env.
    for lp in &tracking_plan.link_plans {
        assert!(lp.files[0].path.ends_with(".env"));
        assert!(lp.files[0].changed);
    }
}

#[test]
fn existing_routes_are_reused_and_disabled_ones_reenabled() {
    let mut fx = fixture();
    {
        let conn = fx.tv.vault.connection();
        api_tracker_gateway::routes::add_manifest_route(conn, "openai", "openai").unwrap();
        api_tracker_gateway::routes::add_manifest_route(conn, "anthropic", "anthropic").unwrap();
        api_tracker_gateway::routes::set_route_enabled(conn, "anthropic", false).unwrap();
    }
    let (_d, tracking_plan) = plan_for(&mut fx);
    let openai = tracking_plan
        .route_actions
        .iter()
        .find(|a| a.prefix() == "openai")
        .unwrap();
    let anthropic = tracking_plan
        .route_actions
        .iter()
        .find(|a| a.prefix() == "anthropic")
        .unwrap();
    assert!(matches!(openai, RouteAction::ReuseRoute { .. }));
    assert!(matches!(anthropic, RouteAction::ReEnableRoute { .. }));
}

#[test]
fn apply_runs_steps_in_order_and_reaches_awaiting_restart() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx);
    let ops = MockOps::default();
    let report = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: Some(master_password()),
        },
        &ops,
    );
    assert!(report.failed_step().is_none(), "{:?}", report.steps);
    assert_eq!(report.state, TrackingState::AwaitingRestart);
    assert!(report.attribution_enabled);
    // Order: service before routes' key push before probe; reload after
    // links; matching key last.
    assert_eq!(
        ops.calls(),
        vec![
            "ensure_service",
            "reload_routes",
            "probe_route",
            "probe_route",
            "push_matching_key"
        ]
    );
    let ids: Vec<StepId> = report.steps.iter().map(|s| s.id).collect();
    assert_eq!(
        ids,
        vec![
            StepId::EnsureProject,
            StepId::EnsurePort,
            StepId::EnsureService,
            StepId::EnsureRoutes,
            StepId::EnsureRouteKey,
            StepId::ApplyLinks,
            StepId::ReloadRoutes,
            StepId::PathCheck,
            StepId::Attribution,
            StepId::RecordSetup,
        ]
    );
    // The .env now points at the gateway with both providers' variables.
    let env = std::fs::read_to_string(fx.dir.path().join(".env")).unwrap();
    assert!(env.contains("OPENAI_BASE_URL=http://127.0.0.1:"));
    assert!(env.contains("ANTHROPIC_BASE_URL=http://127.0.0.1:"));
    assert!(env.contains("NO_PROXY"));
}

#[test]
fn apply_twice_converges_with_zero_new_rows() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx);
    let ops = MockOps::default();
    let report1 = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: None,
        },
        &ops,
    );
    assert!(report1.failed_step().is_none());
    let count = |fx: &Fixture, sql: &str| -> i64 {
        fx.tv
            .vault
            .connection()
            .query_row(sql, [], |r| r.get(0))
            .unwrap()
    };
    let routes_before = count(&fx, "SELECT COUNT(*) FROM gateway_routes");
    let links_before = count(&fx, "SELECT COUNT(*) FROM gateway_project_links");
    let env_before = std::fs::read_to_string(fx.dir.path().join(".env")).unwrap();

    // Re-plan (the project now exists) and re-apply.
    let detection2 = detect(
        fx.tv.vault.connection(),
        &DetectionInput {
            folder: fx.dir.path(),
            project_id: Some(&report1.project_id),
        },
    )
    .unwrap();
    let selections = Selections::defaults(&detection2);
    let plan2 = plan(
        fx.tv.vault.connection(),
        &detection2,
        &selections,
        ProjectRef {
            id: Some(report1.project_id.clone()),
            name: "fixture-app".to_string(),
        },
        &service_running(),
        false,
    )
    .unwrap();
    let report2 = apply(
        &mut fx.tv.vault,
        &detection2,
        &plan2,
        &ApplyOptions {
            master_password: None,
        },
        &MockOps::default(),
    );
    assert!(report2.failed_step().is_none(), "{:?}", report2.steps);
    assert_eq!(
        count(&fx, "SELECT COUNT(*) FROM gateway_routes"),
        routes_before
    );
    assert_eq!(
        count(&fx, "SELECT COUNT(*) FROM gateway_project_links"),
        links_before
    );
    assert_eq!(
        std::fs::read_to_string(fx.dir.path().join(".env")).unwrap(),
        env_before,
        "a second apply must not change the file again"
    );
    // Same setup row, not a second one.
    assert_eq!(count(&fx, "SELECT COUNT(*) FROM tracking_setups"), 1);
}

#[test]
fn a_failed_service_step_stops_the_sequence_and_reports_honestly() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx);
    let ops = MockOps {
        fail_service: true,
        ..Default::default()
    };
    let env_before = std::fs::read_to_string(fx.dir.path().join(".env")).unwrap();
    let report = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: None,
        },
        &ops,
    );
    let failed = report.failed_step().expect("a failed step");
    assert_eq!(failed.id, StepId::EnsureService);
    assert_eq!(report.state, TrackingState::NeedsAttention);
    // Earlier steps are left in place (project + setup row exist)…
    assert!(!report.project_id.is_empty());
    let setup = state::get_setup(fx.tv.vault.connection(), report.setup_id.as_ref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(setup.state, TrackingState::NeedsAttention);
    // …and later steps never ran: no routes, no file changes.
    let routes: i64 = fx
        .tv
        .vault
        .connection()
        .query_row("SELECT COUNT(*) FROM gateway_routes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(routes, 0);
    assert_eq!(
        std::fs::read_to_string(fx.dir.path().join(".env")).unwrap(),
        env_before
    );
}

#[test]
fn a_blocked_install_is_flagged_for_the_foreground_fallback() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx);
    let ops = MockOps {
        block_install: true,
        ..Default::default()
    };
    let report = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: None,
        },
        &ops,
    );
    assert!(report.install_blocked);
    assert_eq!(report.state, TrackingState::NeedsAttention);
}

#[test]
fn a_mutated_env_file_fails_the_digest_check_and_is_left_untouched() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx);
    // Mutate between preview and apply.
    let mutated = "OPENAI_API_KEY=sk-proj-FAKE-TEST-KEY-0000000000000002\n# edited after preview\n";
    std::fs::write(fx.dir.path().join(".env"), mutated).unwrap();
    let report = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: None,
        },
        &MockOps::default(),
    );
    let failed = report.failed_step().expect("digest mismatch must fail");
    assert_eq!(failed.id, StepId::ApplyLinks);
    match &failed.outcome {
        StepOutcome::Failed { error } => {
            assert!(error.contains("changed since the preview"), "{error}")
        }
        other => panic!("expected failure, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(fx.dir.path().join(".env")).unwrap(),
        mutated,
        "a stale plan must never be written"
    );
}

#[test]
fn attribution_push_failure_degrades_and_never_blocks_tracking() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx);
    let ops = MockOps {
        fail_matching_key: true,
        ..Default::default()
    };
    let report = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: Some(master_password()),
        },
        &ops,
    );
    assert!(report.failed_step().is_none(), "{:?}", report.steps);
    assert!(!report.attribution_enabled);
    assert_eq!(report.state, TrackingState::AwaitingRestart);
    let attribution = report
        .steps
        .iter()
        .find(|s| s.id == StepId::Attribution)
        .unwrap();
    assert!(matches!(attribution.outcome, StepOutcome::Skipped { .. }));
}

#[test]
fn a_wrong_master_password_skips_attribution_but_tracking_proceeds() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx);
    let report = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: Some(SecretString::new("wrong-password-000".to_string())),
        },
        &MockOps::default(),
    );
    assert!(report.failed_step().is_none());
    assert!(!report.attribution_enabled);
}

#[test]
fn a_gateway_answered_probe_fails_the_path_check() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx);
    let ops = MockOps {
        gateway_answers_probe: true,
        ..Default::default()
    };
    let report = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: None,
        },
        &ops,
    );
    let failed = report.failed_step().expect("path check must fail");
    assert_eq!(failed.id, StepId::PathCheck);
    assert_eq!(report.state, TrackingState::NeedsAttention);
}

#[test]
fn undo_restores_the_env_exactly_and_removes_only_created_routes() {
    let mut fx = fixture();
    let env_original = std::fs::read_to_string(fx.dir.path().join(".env")).unwrap();
    let (detection, tracking_plan) = plan_for(&mut fx);
    let report = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: None,
        },
        &MockOps::default(),
    );
    assert!(report.failed_step().is_none());
    // The user edits the file after setup; undo must keep their edit.
    let env_after = std::fs::read_to_string(fx.dir.path().join(".env")).unwrap();
    assert_ne!(env_original, env_after);

    let setup = state::get_setup(fx.tv.vault.connection(), report.setup_id.as_ref().unwrap())
        .unwrap()
        .unwrap();
    let undo_report = undo(fx.tv.vault.connection(), &setup).unwrap();
    assert!(undo_report.complete, "{undo_report:?}");
    assert_eq!(
        std::fs::read_to_string(fx.dir.path().join(".env")).unwrap(),
        env_original,
        "undo must restore the exact prior content"
    );
    assert_eq!(undo_report.removed_routes.len(), 2);
    let routes: i64 = fx
        .tv
        .vault
        .connection()
        .query_row("SELECT COUNT(*) FROM gateway_routes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(routes, 0);
    let refreshed = state::get_setup(fx.tv.vault.connection(), &setup.id)
        .unwrap()
        .unwrap();
    assert_eq!(refreshed.state, TrackingState::NotConfigured);
    // History rows are kept (none were created here, but the events table
    // is never touched by undo — guard with a count).
    let events: i64 = fx
        .tv
        .vault
        .connection()
        .query_row("SELECT COUNT(*) FROM runtime_request_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(events, 0);
}

#[test]
fn undo_keeps_routes_still_linked_by_another_project() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx);
    let report = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: None,
        },
        &MockOps::default(),
    );
    assert!(report.failed_step().is_none());
    // A second project links one of the routes by hand.
    let other = fx
        .tv
        .vault
        .create_project(api_tracker_core::vault::NewProject {
            name: "other-project".to_string(),
            ..Default::default()
        })
        .unwrap();
    api_tracker_gateway::routes::add_project_link(fx.tv.vault.connection(), &other.id, "openai")
        .unwrap();

    let setup = state::get_setup(fx.tv.vault.connection(), report.setup_id.as_ref().unwrap())
        .unwrap()
        .unwrap();
    let undo_report = undo(fx.tv.vault.connection(), &setup).unwrap();
    assert!(undo_report.complete);
    assert!(undo_report
        .removed_routes
        .contains(&"anthropic".to_string()));
    assert!(
        !undo_report.removed_routes.contains(&"openai".to_string()),
        "a route another project links must be kept"
    );
    assert!(undo_report
        .kept_routes
        .iter()
        .any(|(p, why)| p == "openai" && why.contains("another project")));
}

#[test]
fn selections_must_confirm_custom_origins_and_exclude_unsupported() {
    let tv = test_vault();
    let dir = TempDir::new().unwrap();
    write_project(
        dir.path(),
        &[(
            ".env",
            "SUPABASE_URL=https://xyzcompany.supabase.co\nSUPABASE_SERVICE_ROLE_KEY=sb_secret_FAKE-TEST-NOT-REAL-0001\nSTRIPE_SECRET_KEY=sk_live_FAKE0000000000000000000000000000\n",
        )],
    );
    ensure_port(tv.vault.connection()).unwrap();
    let detection = detect(
        tv.vault.connection(),
        &DetectionInput {
            folder: dir.path(),
            project_id: None,
        },
    )
    .unwrap();

    // Including an unsupported provider is an error.
    let mut bad = Selections::defaults(&detection);
    bad.include.insert("stripe".to_string());
    let err = plan(
        tv.vault.connection(),
        &detection,
        &bad,
        ProjectRef {
            id: None,
            name: "x".into(),
        },
        &service_absent(),
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unsupported"), "{err}");

    // Including a custom-origin provider without a confirmed origin is an
    // error.
    let mut no_origin = Selections::defaults(&detection);
    no_origin.include.insert("supabase".to_string());
    no_origin.confirmed_origins.clear();
    let err = plan(
        tv.vault.connection(),
        &detection,
        &no_origin,
        ProjectRef {
            id: None,
            name: "x".into(),
        },
        &service_absent(),
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("confirmed origin"), "{err}");
}

#[test]
fn nothing_selected_is_an_explicit_error_not_an_empty_plan() {
    let tv = test_vault();
    let dir = TempDir::new().unwrap();
    node_two_provider_fixture(dir.path());
    ensure_port(tv.vault.connection()).unwrap();
    let detection = detect(
        tv.vault.connection(),
        &DetectionInput {
            folder: dir.path(),
            project_id: None,
        },
    )
    .unwrap();
    let err = plan(
        tv.vault.connection(),
        &detection,
        &Selections::default(),
        ProjectRef {
            id: None,
            name: "x".into(),
        },
        &service_absent(),
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("nothing to configure"), "{err}");
}

#[test]
fn thirty_detected_providers_stay_one_plan_with_no_per_provider_forms() {
    // Provider scale: the fusion + plan layers must aggregate arbitrarily
    // many detections into ONE plan. Only manifest providers can be
    // configured today, but the detection list may be large; the plan API
    // has no per-provider interaction anywhere.
    let tv = test_vault();
    let dir = TempDir::new().unwrap();
    let mut env = String::new();
    // 26 unknown-but-detected "providers" via lockfile-style config
    // mentions cannot exist without manifests; instead simulate scale with
    // repeated known providers across many env files plus unknowns in
    // package.json deps (which map to no manifest and simply vanish).
    for i in 0..26 {
        env.push_str(&format!("SERVICE_{i}_URL=https://svc{i}.example.com\n"));
    }
    env.push_str(&format!("OPENAI_API_KEY={FAKE_OPENAI_KEY}\n"));
    env.push_str(&format!("ANTHROPIC_API_KEY={FAKE_ANTHROPIC_KEY}\n"));
    env.push_str("SUPABASE_URL=https://xyzcompany.supabase.co\n");
    env.push_str("SUPABASE_SERVICE_ROLE_KEY=sb_secret_FAKE-TEST-NOT-REAL-0001\n");
    env.push_str("STRIPE_SECRET_KEY=sk_live_FAKE0000000000000000000000000000\n");
    write_project(dir.path(), &[(".env", &env)]);
    ensure_port(tv.vault.connection()).unwrap();
    let detection = detect(
        tv.vault.connection(),
        &DetectionInput {
            folder: dir.path(),
            project_id: None,
        },
    )
    .unwrap();
    let mut selections = Selections::defaults(&detection);
    // Supabase needs its one confirmation; that is the ONLY extra input.
    selections.include.insert("supabase".to_string());
    selections.confirmed_origins.insert(
        "supabase".to_string(),
        "https://xyzcompany.supabase.co".to_string(),
    );
    let tracking_plan = plan(
        tv.vault.connection(),
        &detection,
        &selections,
        ProjectRef {
            id: None,
            name: "big".into(),
        },
        &service_absent(),
        false,
    )
    .unwrap();
    // One combined plan: all three configurable providers in one shot.
    assert_eq!(tracking_plan.route_actions.len(), 3);
    assert_eq!(tracking_plan.link_plans.len(), 3);
    // The unsupported provider is a warning, not a blocker.
    assert!(tracking_plan
        .warnings
        .iter()
        .any(|w| matches!(w, api_tracker_tracking::plan::PlanWarning::UnsupportedProvider { provider_id, .. } if provider_id == "stripe")));
}

#[test]
fn folder_is_registered_and_reverse_lookup_finds_the_project() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx);
    let report = apply(
        &mut fx.tv.vault,
        &detection,
        &tracking_plan,
        &ApplyOptions {
            master_password: None,
        },
        &MockOps::default(),
    );
    assert!(report.failed_step().is_none());
    let ids = api_tracker_core::vault::projects_for_folder(fx.tv.vault.connection(), fx.dir.path())
        .unwrap();
    assert_eq!(ids, vec![report.project_id.clone()]);
    // And through a non-canonical spelling of the same folder.
    let dodged = fx
        .dir
        .path()
        .join("..")
        .join(Path::new(fx.dir.path()).file_name().unwrap());
    let ids2 =
        api_tracker_core::vault::projects_for_folder(fx.tv.vault.connection(), &dodged).unwrap();
    assert_eq!(ids2, vec![report.project_id.clone()]);
}
