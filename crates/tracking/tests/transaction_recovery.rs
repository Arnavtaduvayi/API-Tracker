//! `NEW-31` / `NEW-32` / `NEW-33` / `NEW-34` regression suite: the four
//! places where a concurrent or partial run left the persisted record
//! disagreeing with what actually happened on the machine.
//!
//! Apply is not one transaction and deliberately is not — an honestly
//! reported partial apply is more recoverable than an automatic rollback
//! that can itself fail. The price of that choice is that every commit point
//! has to be individually correct about what it claims. These are the four
//! that were not:
//!
//! | Finding | The lie the user was told |
//! | --- | --- |
//! | `NEW-31` | run A's plan summary landed on run B's session, so undo acted on the wrong `created_routes` |
//! | `NEW-32` | routes this product created were reported as "existed before this setup (only reused)" and left behind |
//! | `NEW-33` | "this apply failed" silently reached no row at all, and a later status said "not configured" |
//! | `NEW-34` | a stale undo tore down a live setup and then returned a bare `state_conflict`, showing none of what it had destroyed |
//!
//! Two connections on one `vault.db` stand in for two processes, as in
//! `verification_concurrency.rs`. Nothing here sleeps and nothing depends on
//! scheduling: every interleaving is sequenced by hand or driven through the
//! `ServiceOps` seam the apply engine already exposes.

mod common;

use std::path::Path;
use std::sync::Mutex;

use api_tracker_core::secret::SecretBytes;
use api_tracker_core::CoreError;
use api_tracker_tracking::apply::{
    apply, ApplyOptions, ServiceEnsureOutcome, ServiceOps, StepId, StepOutcome,
};
use api_tracker_tracking::detect::{detect, DetectionInput, ProjectDetection};
use api_tracker_tracking::plan::{ensure_port, plan, ProjectRef, Selections, TrackingPlan};
use api_tracker_tracking::state::{self, PlanSummary, TrackingState};
use api_tracker_tracking::undo::undo;
use api_tracker_tracking::verify::ProbeOutcome;
use common::*;
use rusqlite::Connection;
use tempfile::TempDir;

/// A deterministic, unmistakably fake restore-record key.
fn restore_crypto() -> api_tracker_core::envrestore::RestoreCrypto {
    api_tracker_core::envrestore::RestoreCrypto::new(
        "vault-test-0001".to_string(),
        api_tracker_core::secret::SecretBytes::new(vec![0x2au8; 32]),
    )
}

// ---------------------------------------------------------------------------
// The apply harness
// ---------------------------------------------------------------------------

/// The same seam `plan_apply.rs` uses, plus one addition: `on_probe` runs
/// INSIDE the apply, at step 8, which is the only way to schedule a
/// competing writer into the middle of a real apply without sleeping.
struct HookedOps {
    /// `true` makes the gateway itself answer the path check, which fails
    /// step 8 — after routes and links, so everything earlier is genuinely
    /// on the machine when the failure lands.
    gateway_answers_probe: bool,
    on_probe: Mutex<Option<Box<dyn FnMut() + Send>>>,
}

impl HookedOps {
    fn succeeding() -> Self {
        Self {
            gateway_answers_probe: false,
            on_probe: Mutex::new(None),
        }
    }

    fn failing_at_path_check() -> Self {
        Self {
            gateway_answers_probe: true,
            on_probe: Mutex::new(None),
        }
    }

    fn with_hook(mut self, f: impl FnMut() + Send + 'static) -> Self {
        self.on_probe = Mutex::new(Some(Box::new(f)));
        self
    }
}

impl ServiceOps for HookedOps {
    fn ensure_service(
        &self,
        _actions: &[api_tracker_tracking::plan::ServiceAction],
    ) -> ServiceEnsureOutcome {
        ServiceEnsureOutcome::Verified
    }
    fn push_route_key(&self, _key: &SecretBytes) -> bool {
        true
    }
    fn push_matching_key(&self, _key: SecretBytes) -> api_tracker_core::Result<()> {
        Ok(())
    }
    fn reload_routes(&self) -> bool {
        true
    }
    fn probe_route(&self, _port: u16, _base_url: &str) -> ProbeOutcome {
        if let Some(hook) = self.on_probe.lock().unwrap().as_mut() {
            hook();
        }
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

/// A second connection on the fixture vault's own database file — a second
/// process, which on this product is the desktop app beside the CLI.
fn other_process(fx: &Fixture) -> Connection {
    second_conn(&fx.tv.data_dir.join("vault.db"))
}

fn plan_for(fx: &mut Fixture, project_id: Option<&str>) -> (ProjectDetection, TrackingPlan) {
    ensure_port(fx.tv.vault.connection()).unwrap();
    let detection = detect(
        fx.tv.vault.connection(),
        &DetectionInput {
            folder: fx.dir.path(),
            project_id,
        },
    )
    .unwrap();
    let selections = Selections::defaults(&detection);
    let tracking_plan = plan(
        fx.tv.vault.connection(),
        &detection,
        &selections,
        ProjectRef {
            id: project_id.map(str::to_string),
            name: "fixture-app".to_string(),
        },
        &service_absent(),
        false,
    )
    .unwrap();
    (detection, tracking_plan)
}

fn run(
    fx: &mut Fixture,
    d: &ProjectDetection,
    p: &TrackingPlan,
    ops: &dyn ServiceOps,
) -> api_tracker_tracking::apply::ApplyReport {
    apply(
        &mut fx.tv.vault,
        d,
        p,
        &ApplyOptions {
            master_password: None,
        },
        ops,
    )
}

// ---------------------------------------------------------------------------
// NEW-31 — record_applied is a compare-and-swap
// ---------------------------------------------------------------------------

fn summary_creating(prefix: &str) -> PlanSummary {
    PlanSummary {
        providers: vec![prefix.to_string()],
        created_routes: vec![prefix.to_string()],
        port: 49152,
        ..Default::default()
    }
}

/// `record_applied` was the ONE health write with no `row_version`
/// predicate. It bumped the version — so an in-flight refresh re-read, which
/// is `VER-01` working — but bumping without comparing is last-writer-wins,
/// and the columns it writes decide which observations are admissible and
/// what undo will act on.
#[test]
fn a_second_applys_plan_summary_cannot_overwrite_the_one_that_won() {
    let (_d, conn, path) = test_conn_at();
    insert_project(&conn, "p1", "one");
    let mut mine = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::Applying,
        "{}",
    )
    .unwrap();

    // A second process is applying the same folder and reads the row before
    // either of us has recorded anything.
    let other = other_conn_setup(&path, &mine.id);
    let mut theirs = other.1;
    state::record_applied(&other.0, &mut theirs, &summary_creating("anthropic")).unwrap();

    // My apply now finishes and records a summary decided from a row that no
    // longer exists.
    let err = state::record_applied(&conn, &mut mine, &summary_creating("openai"))
        .expect_err("the losing apply must be told, not silently believed");
    assert!(
        matches!(err, CoreError::StateConflict { .. }),
        "expected a state conflict, got {err}"
    );

    let stored = state::plan_summary_of(&state::get_setup(&conn, &mine.id).unwrap().unwrap());
    assert_eq!(
        stored.created_routes,
        vec!["anthropic".to_string()],
        "the winner's summary must survive; undo acting on the loser's \
         created_routes removes routes the live setup is still using"
    );
}

/// The control: the fix must not turn every apply into a conflict. Re-read
/// and the same write succeeds, which is exactly what the apply path does
/// when it carries its own handle forward.
#[test]
fn recording_an_apply_from_a_current_handle_still_succeeds() {
    let (_d, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    let mut setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::Applying,
        "{}",
    )
    .unwrap();
    let before = setup.row_version;
    state::record_applied(&conn, &mut setup, &summary_creating("openai")).unwrap();
    assert_eq!(
        setup.row_version,
        before + 1,
        "the handle must advance with the row, or the next guarded write \
         compares against a version that is already spent"
    );
    let row = state::get_setup(&conn, &setup.id).unwrap().unwrap();
    assert!(row.applied_at.is_some());
    assert_eq!(row.row_version, setup.row_version);
}

/// Read the same row through a second connection, returning both.
fn other_conn_setup(path: &Path, id: &str) -> (Connection, state::TrackingSetup) {
    let conn = second_conn(path);
    let setup = state::get_setup(&conn, id).unwrap().unwrap();
    (conn, setup)
}

// ---------------------------------------------------------------------------
// NEW-32 — a failed apply must not erase route provenance
// ---------------------------------------------------------------------------

/// The failing apply creates the routes at step 4 and dies at step 8. Under
/// the old ordering the summary was written only at step 10, and the
/// re-apply upsert had already nulled the previous run's — so nothing on
/// disk remembered that this product had created those routes.
#[test]
fn a_failed_apply_still_records_the_routes_it_created() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx, None);
    let report = run(
        &mut fx,
        &detection,
        &tracking_plan,
        &HookedOps::failing_at_path_check(),
    );
    assert_eq!(report.failed_step().unwrap().id, StepId::PathCheck);

    let setup = state::get_setup(fx.tv.vault.connection(), report.setup_id.as_ref().unwrap())
        .unwrap()
        .unwrap();
    let summary = state::plan_summary_of(&setup);
    let mut created = summary.created_routes.clone();
    created.sort();
    assert_eq!(
        created,
        vec!["anthropic".to_string(), "openai".to_string()],
        "the routes exist on the machine, so the record of who created them \
         has to exist too"
    );
    assert!(
        !summary.apply_completed,
        "and it must NOT read as a completed apply — that is the ZFT-007 \
         refusal, which has to keep refusing"
    );
}

/// The whole `NEW-32` chain end to end: fail, retry, undo. The retry sees
/// `AlreadyExists` for both routes and would classify them as "reused"; the
/// carried provenance is what stops undo telling the user those routes
/// "existed before this setup" and leaving them behind.
#[test]
fn a_retry_after_a_failed_apply_still_attributes_the_routes_to_this_setup() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx, None);
    let failed = run(
        &mut fx,
        &detection,
        &tracking_plan,
        &HookedOps::failing_at_path_check(),
    );
    assert!(failed.failed_step().is_some());

    // The retry: same folder, same project, routes now pre-existing.
    let (detection2, plan2) = plan_for(&mut fx, Some(&failed.project_id));
    let ok = run(&mut fx, &detection2, &plan2, &HookedOps::succeeding());
    assert!(ok.failed_step().is_none(), "{:?}", ok.steps);

    let setup = state::get_setup(fx.tv.vault.connection(), ok.setup_id.as_ref().unwrap())
        .unwrap()
        .unwrap();
    let summary = state::plan_summary_of(&setup);
    let mut created = summary.created_routes.clone();
    created.sort();
    assert_eq!(
        created,
        vec!["anthropic".to_string(), "openai".to_string()],
        "a route the FIRST attempt created is still one this setup created"
    );
    assert!(
        summary.reused_routes.is_empty(),
        "and it must not also be listed as merely reused: {:?}",
        summary.reused_routes
    );

    // And the consequence the user actually feels.
    let undone = undo(fx.tv.vault.connection(), Some(&restore_crypto()), &setup).unwrap();
    assert!(undone.complete, "{undone:?}");
    let mut removed = undone.removed_routes.clone();
    removed.sort();
    assert_eq!(
        removed,
        vec!["anthropic".to_string(), "openai".to_string()],
        "undo must remove what this setup created"
    );
    assert!(
        !undone
            .kept_routes
            .iter()
            .any(|(_, why)| why.contains("only reused")),
        "nothing may be stranded with the false reason 'existed before this \
         setup': {:?}",
        undone.kept_routes
    );
    let routes: i64 = fx
        .tv
        .vault
        .connection()
        .query_row("SELECT COUNT(*) FROM gateway_routes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(routes, 0, "and the machine must actually be clean");
}

/// Undo after a failed apply now knows which routes to remove — and still
/// refuses to call the teardown complete, because the rest of the plan was
/// never recorded. Both halves matter: the first is `NEW-32`, the second is
/// `ZFT-007`, and a fix for one that breaks the other is not a fix.
#[test]
fn undo_after_a_failed_apply_removes_its_routes_and_still_refuses_completion() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx, None);
    let failed = run(
        &mut fx,
        &detection,
        &tracking_plan,
        &HookedOps::failing_at_path_check(),
    );
    let setup = state::get_setup(fx.tv.vault.connection(), failed.setup_id.as_ref().unwrap())
        .unwrap()
        .unwrap();

    let undone = undo(fx.tv.vault.connection(), Some(&restore_crypto()), &setup).unwrap();
    let mut removed = undone.removed_routes.clone();
    removed.sort();
    assert_eq!(
        removed,
        vec!["anthropic".to_string(), "openai".to_string()],
        "the routes the failed apply created must be removed, not stranded"
    );
    assert!(
        !undone.complete,
        "the rest of the plan was never recorded, so this cannot be called complete"
    );
    assert!(
        !undone.notes.is_empty(),
        "and an incomplete teardown has to say why"
    );
    let after = state::get_setup(fx.tv.vault.connection(), &setup.id)
        .unwrap()
        .unwrap();
    assert_eq!(after.state, TrackingState::NeedsAttention);
}

// ---------------------------------------------------------------------------
// NEW-33 — an apply failure that cannot be recorded must not vanish
// ---------------------------------------------------------------------------

/// A concurrent `track undo` completes while this apply is at step 8. It
/// leaves the row at `not_configured`, from which `needs_attention` is an
/// ILLEGAL transition — so `state::transition` returns `InvalidInput`, which
/// the retry loop's catch-all used to treat exactly like success. The
/// failure record then reached no row at all and a later `track status` said
/// "not configured" rather than "the last attempt failed".
#[test]
fn a_failure_that_cannot_be_recorded_is_reported_instead_of_swallowed() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx, None);
    let other = other_process(&fx);
    let ops = HookedOps::failing_at_path_check().with_hook(move || {
        // Exactly what a `track undo` finishing mid-apply leaves behind.
        let live: Option<state::TrackingSetup> = other
            .query_row("SELECT id FROM tracking_setups LIMIT 1", [], |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .and_then(|id| state::get_setup(&other, &id).unwrap());
        if let Some(live) = live {
            if live.state != TrackingState::NotConfigured {
                state::transition(&other, &live, TrackingState::NotConfigured, None).unwrap();
            }
        }
    });

    let report = run(&mut fx, &detection, &tracking_plan, &ops);
    assert_eq!(report.failed_step().unwrap().id, StepId::PathCheck);

    let row = state::get_setup(fx.tv.vault.connection(), report.setup_id.as_ref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        row.state,
        TrackingState::NotConfigured,
        "the fixture must really have made the transition illegal"
    );
    assert!(
        row.attention_reason.is_none(),
        "and the failure genuinely could not be written to the row"
    );

    let told = report.steps.iter().any(|s| {
        matches!(&s.outcome, StepOutcome::Skipped { reason }
            if reason.contains("could not be recorded on the setup row"))
    });
    assert!(
        told,
        "so the report has to say so — losing bad news quietly is ZFT-006 by \
         omission: {:?}",
        report.steps
    );
}

/// The control: on the ordinary failure path nothing changed. The failure
/// still lands on the row, and no "could not be recorded" note is invented.
#[test]
fn an_ordinary_apply_failure_still_lands_on_the_row_with_no_extra_note() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx, None);
    let report = run(
        &mut fx,
        &detection,
        &tracking_plan,
        &HookedOps::failing_at_path_check(),
    );
    let row = state::get_setup(fx.tv.vault.connection(), report.setup_id.as_ref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(row.state, TrackingState::NeedsAttention);
    assert!(
        row.attention_reason
            .as_deref()
            .unwrap()
            .contains("path_check"),
        "{:?}",
        row.attention_reason
    );
    assert!(
        !report.steps.iter().any(|s| matches!(&s.outcome,
            StepOutcome::Skipped { reason } if reason.contains("could not be recorded"))),
        "{:?}",
        report.steps
    );
}

// ---------------------------------------------------------------------------
// NEW-34 — undo compares and swaps BEFORE it destroys anything
// ---------------------------------------------------------------------------

/// The stale-undo case. The caller read the setup, the row moved (a
/// re-apply, a refresh's correction, a failed repair recording a reason),
/// and undo then ran anyway: links restored, link rows deleted, routes
/// removed — and only afterwards did the compare-and-swap fail, returning a
/// bare `state_conflict` and discarding the report that said what had just
/// been dismantled.
#[test]
fn a_stale_undo_refuses_before_it_destroys_a_live_setup() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx, None);
    let report = run(
        &mut fx,
        &detection,
        &tracking_plan,
        &HookedOps::succeeding(),
    );
    assert!(report.failed_step().is_none());

    let stale = state::get_setup(fx.tv.vault.connection(), report.setup_id.as_ref().unwrap())
        .unwrap()
        .unwrap();
    let env_before = std::fs::read_to_string(fx.dir.path().join(".env")).unwrap();

    // The row moves under the caller's feet.
    {
        let other = other_process(&fx);
        let live = state::get_setup(&other, &stale.id).unwrap().unwrap();
        state::transition(
            &other,
            &live,
            TrackingState::NeedsAttention,
            Some("a repair failed a moment ago"),
        )
        .unwrap();
    }

    let err = undo(fx.tv.vault.connection(), Some(&restore_crypto()), &stale)
        .expect_err("a stale undo must refuse, not proceed and apologise");
    assert!(
        matches!(err, CoreError::StateConflict { .. }),
        "expected a state conflict, got {err}"
    );

    // Nothing was destroyed — which is the entire point of refusing first.
    assert_eq!(
        std::fs::read_to_string(fx.dir.path().join(".env")).unwrap(),
        env_before,
        "a refused undo must not have rewritten the user's environment file"
    );
    let counts = |sql: &str| -> i64 {
        fx.tv
            .vault
            .connection()
            .query_row(sql, [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(
        counts("SELECT COUNT(*) FROM gateway_routes"),
        2,
        "nor removed the live setup's routes"
    );
    assert_eq!(
        counts("SELECT COUNT(*) FROM gateway_project_links"),
        2,
        "nor deleted its link rows"
    );
}

/// The control: an undo from a current handle still tears the setup down and
/// still clears the apply artifacts through its own guarded write.
#[test]
fn an_undo_from_a_current_handle_completes_and_clears_the_artifacts() {
    let mut fx = fixture();
    let (detection, tracking_plan) = plan_for(&mut fx, None);
    let report = run(
        &mut fx,
        &detection,
        &tracking_plan,
        &HookedOps::succeeding(),
    );
    let setup = state::get_setup(fx.tv.vault.connection(), report.setup_id.as_ref().unwrap())
        .unwrap()
        .unwrap();
    let before = setup.row_version;

    let undone = undo(fx.tv.vault.connection(), Some(&restore_crypto()), &setup).unwrap();
    assert!(undone.complete, "{undone:?}");

    let after = state::get_setup(fx.tv.vault.connection(), &setup.id)
        .unwrap()
        .unwrap();
    assert_eq!(after.state, TrackingState::NotConfigured);
    assert!(after.plan_summary_json.is_none() && after.applied_at.is_none());
    assert!(after.verification_session.is_none());
    assert_eq!(
        after.row_version,
        before + 2,
        "one bump from the transition, one from the guarded artifact clear — \
         the clear used to carry no version predicate at all"
    );
}

/// The second half of `NEW-34`: a destructive operation that has already run
/// must report what it did, whatever the closing write says.
///
/// Reached here through the closing transition's OTHER failure mode — a row
/// already at `not_configured`, from which `needs_attention` is illegal.
/// That is the same `Err` arm a compare-and-swap conflict takes, and it used
/// to be a bare `?`: the CLI printed a raw error and none of the restored
/// files, removed routes or kept-route reasons.
#[test]
fn an_undo_whose_closing_write_fails_still_reports_everything_it_restored() {
    let (_d, conn) = test_conn();
    insert_project(&conn, "p1", "one");
    // A setup row already returned to `not_configured` — by an earlier undo
    // that got this far — while its link rows are still live.
    let setup = state::upsert_setup(
        &conn,
        "p1",
        Path::new("/tmp/fixture"),
        TrackingState::NotConfigured,
        "{}",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gateway_routes (route_prefix, provider_id, enabled, created_at, updated_at)
         VALUES ('openai','openai',1,'2099-01-01T00:00:00Z','2099-01-01T00:00:00Z')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gateway_project_links
            (link_slug, project_id, route_prefix, env_path, prior_env_json, created_at)
         VALUES ('slug-openai','p1','openai','/tmp/fixture/.env',
                 '{\"v\":1,\"port\":49152,\"files\":[]}','2099-01-01T00:00:00Z')",
        [],
    )
    .unwrap();

    let report = undo(&conn, Some(&restore_crypto()), &setup)
        .expect("the report must survive a closing write that cannot land");
    assert!(
        !report.links.is_empty(),
        "the links it restored have to be in the report the user is shown"
    );
    assert!(!report.complete);
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("could not be updated")),
        "and the user must be told the status write did not land: {:?}",
        report.notes
    );
}
