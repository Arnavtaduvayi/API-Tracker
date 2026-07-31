//! The apply engine: executes an approved `TrackingPlan` in the required
//! order with per-step honest reporting.
//!
//! Order (dictated by existing hard constraints — persisted port before
//! links, route rows before link rows, MAC key before custom routes
//! forward, reload nudge after links):
//!
//! 1. ensure project row (+ registered canonical folder)
//! 2. ensure port persisted (must match the approved plan's port)
//! 3. ensure service installed and running (bundled helper)
//! 4. ensure routes
//! 5. ensure route MAC key when any custom route exists
//! 6. apply links (digest-bound; never writes a stale plan)
//! 7. reload-routes nudge
//! 8. path check (keyless probe per route)
//! 9. attribution (only with the master password; failure degrades, never
//!    blocks)
//! 10. persist the setup row → awaiting_restart / awaiting_first_request
//!
//! Every step is idempotent (re-running converges). A step failure stops
//! the sequence, names the step, reports what was and wasn't changed, and
//! leaves earlier steps in place — an honestly-reported partial apply is
//! more recoverable than an automatic rollback that can itself fail.

use std::path::{Path, PathBuf};

use api_tracker_core::secret::{SecretBytes, SecretString};
use api_tracker_core::vault::{NewProject, UnlockedVault, UpdateProject, VaultPaths};
use api_tracker_core::{audit, CoreError, Result};
use api_tracker_gateway::lifecycle::provision;
use api_tracker_gateway::{control, envlink, lifecycle, routes, store};
use rusqlite::Connection;
use serde::Serialize;

use crate::detect::ProjectDetection;
use crate::plan::{AttributionPlan, RestartExpectation, RouteAction, ServiceAction, TrackingPlan};
use crate::state::{self, PlanSummary, TrackingState};
use crate::verify::{self, ProbeOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepId {
    EnsureProject,
    EnsurePort,
    EnsureService,
    EnsureRoutes,
    EnsureRouteKey,
    ApplyLinks,
    ReloadRoutes,
    PathCheck,
    Attribution,
    RecordSetup,
}

impl StepId {
    pub fn title(self) -> &'static str {
        match self {
            StepId::EnsureProject => "Project registered",
            StepId::EnsurePort => "Local port reserved",
            StepId::EnsureService => "Local service installed and running",
            StepId::EnsureRoutes => "Provider routes created",
            StepId::EnsureRouteKey => "Custom-route verification key installed",
            StepId::ApplyLinks => "Environment files updated",
            StepId::ReloadRoutes => "Service notified",
            StepId::PathCheck => "Path check",
            StepId::Attribution => "Credential attribution",
            StepId::RecordSetup => "Setup recorded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StepOutcome {
    Done { detail: String },
    Skipped { reason: String },
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct StepReport {
    pub id: StepId,
    pub title: &'static str,
    pub outcome: StepOutcome,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    pub steps: Vec<StepReport>,
    pub project_id: String,
    pub setup_id: Option<String>,
    pub state: TrackingState,
    /// Set when the service install was blocked by the OS (Gatekeeper on
    /// unsigned builds) — the UI offers the foreground fallback.
    pub install_blocked: bool,
    /// Attribution ended enabled.
    pub attribution_enabled: bool,
}

impl ApplyReport {
    pub fn failed_step(&self) -> Option<&StepReport> {
        self.steps
            .iter()
            .find(|s| matches!(s.outcome, StepOutcome::Failed { .. }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceEnsureOutcome {
    Verified,
    /// The OS refused to run the helper (exec probe / registration).
    InstallBlocked {
        error: String,
    },
    /// Actions ran but the listener did not verify in time.
    Unverified {
        detail: String,
    },
}

/// The seam between the orchestration logic and the host: tests supply a
/// mock; production talks to the real lifecycle and control channel.
pub trait ServiceOps {
    fn ensure_service(&self, actions: &[ServiceAction]) -> ServiceEnsureOutcome;
    fn push_route_key(&self, key: &SecretBytes) -> bool;
    /// Push the matching key over the authenticated control channel.
    fn push_matching_key(&self, key: SecretBytes) -> Result<()>;
    fn reload_routes(&self) -> bool;
    fn probe_route(&self, port: u16, base_url: &str) -> ProbeOutcome;
}

/// Production implementation over the real host.
pub struct HostServiceOps {
    pub data_dir: PathBuf,
    /// The helper binary to install — the bundled sidecar (desktop) or the
    /// current executable (CLI).
    pub helper_source: PathBuf,
    pub port: u16,
}

/// The install/repair half of step 3, expressed against injected seams.
///
/// # Why it is a free function (`NEW-02`)
///
/// The step pair here was already ordered correctly by hand — port persisted
/// in step 2, service started in step 3 — but ordering by hand is exactly
/// what [`provision`] exists to stop every caller having to do. Driving
/// `lc.install` / `lc.repair` directly also inherited the two gaps the
/// primitive closes: nothing proved the started service had actually bound
/// the port the plan was built against (an exit code is not evidence — D11),
/// and `repair` re-started a service that resolves its port from the database
/// without first guaranteeing that a port is there to resolve. `track` reaches
/// the repair path automatically, with no user decision behind it.
///
/// It takes the lifecycle, the connection and the host rather than reading
/// them from `self` so a test can drive the real ordered algorithm against a
/// mock `CommandRunner` and a fake [`provision::InstallHost`]: `cargo test`
/// must never write a service definition or install a real launchd job.
pub fn ensure_service_steps(
    lc: &lifecycle::Lifecycle,
    conn: &Connection,
    host: &dyn provision::InstallHost,
    helper_source: &Path,
    actions: &[ServiceAction],
) -> Result<()> {
    for action in actions {
        match action {
            ServiceAction::AlreadyRunning => {}
            ServiceAction::StartService => lc.start()?,
            ServiceAction::InstallService => {
                provision::install_gateway(
                    lc,
                    conn,
                    host,
                    &provision::InstallRequest::new(
                        helper_source,
                        false,
                        env!("CARGO_PKG_VERSION"),
                    ),
                )?;
            }
            ServiceAction::RepairService { .. } => {
                provision::repair_gateway(
                    lc,
                    conn,
                    host,
                    &provision::InstallRequest::new(
                        helper_source,
                        false,
                        env!("CARGO_PKG_VERSION"),
                    ),
                )?;
            }
        }
    }
    Ok(())
}

impl HostServiceOps {
    fn lifecycle(&self) -> Result<lifecycle::Lifecycle> {
        lifecycle::Lifecycle::for_host(&self.data_dir)
    }

    /// A second connection to the vault database, for the ordered install
    /// primitive.
    ///
    /// [`ServiceOps`] deliberately carries no connection — the apply engine
    /// holds the vault's own, and threading it through this trait would put
    /// a database handle in every mock. A separate handle is safe for what
    /// the primitive does: WAL with a five-second busy timeout, and each of
    /// its writes is one transaction. It is the same shape `tethra gateway
    /// repair` uses.
    fn connection(&self) -> Result<Connection> {
        api_tracker_core::db::open_at_current_version(
            &VaultPaths::new(self.data_dir.clone()).db_path(),
        )
    }

    fn wait_for_listener(&self) -> ServiceEnsureOutcome {
        // The existing install path polls 40 × 250 ms (≈10 s); D11: never
        // report healthy on the strength of an exit code alone.
        for _ in 0..40 {
            if let control::ListenerIdentity::Verified { .. } =
                control::verify_listener(&self.data_dir, self.port)
            {
                return ServiceEnsureOutcome::Verified;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        ServiceEnsureOutcome::Unverified {
            detail: format!(
                "the service did not answer on 127.0.0.1:{} within 10 s",
                self.port
            ),
        }
    }
}

impl ServiceOps for HostServiceOps {
    fn ensure_service(&self, actions: &[ServiceAction]) -> ServiceEnsureOutcome {
        let result = (|| -> Result<()> {
            let lc = self.lifecycle()?;
            let conn = self.connection()?;
            ensure_service_steps(
                &lc,
                &conn,
                &provision::HostEnvironment::quiet(),
                &self.helper_source,
                actions,
            )
        })();
        if let Err(e) = result {
            let text = e.to_string();
            // ONLY the exec-probe refusal is the Gatekeeper signature.
            // Every service-lifecycle error used to come back as
            // `InstallBlocked`, which both frontends render as "macOS
            // blocked the background service (this build is unsigned)"
            // — so a full disk, a missing HOME, a foreign definition in
            // our slot and a launchd failure all told the user the same
            // wrong thing (ZFT-039).
            if text.contains("execution probe") {
                return ServiceEnsureOutcome::InstallBlocked { error: text };
            }
            return ServiceEnsureOutcome::Unverified { detail: text };
        }
        // Kept even though the primitive verifies the listener itself: it
        // is the ONLY verification on the `StartService` and `AlreadyRunning`
        // paths, which do not go near the primitive, and on the install path
        // it costs one probe that has just succeeded.
        self.wait_for_listener()
    }

    fn push_route_key(&self, key: &SecretBytes) -> bool {
        control::push_route_key(&self.data_dir, key)
    }

    fn push_matching_key(&self, key: SecretBytes) -> Result<()> {
        let nonce = control::read_nonce(&self.data_dir)?;
        let key_hex = zeroize::Zeroizing::new(hex_lower(key.expose()));
        match control::send(
            &self.data_dir,
            &control::Request::PushKey {
                nonce: nonce.to_string(),
                key_hex: key_hex.to_string(),
            },
        )? {
            control::Response::Ok => Ok(()),
            control::Response::Error { code, message } => {
                Err(CoreError::InvalidInput(format!("{code}: {message}")))
            }
            other => Err(CoreError::InvalidInput(format!(
                "unexpected control response: {other:?}"
            ))),
        }
    }

    fn reload_routes(&self) -> bool {
        let Ok(nonce) = control::read_nonce(&self.data_dir) else {
            return false;
        };
        matches!(
            control::send(
                &self.data_dir,
                &control::Request::ReloadRoutes {
                    nonce: nonce.to_string(),
                },
            ),
            Ok(control::Response::Ok)
        )
    }

    fn probe_route(&self, port: u16, base_url: &str) -> ProbeOutcome {
        verify::probe_route(&self.data_dir, port, base_url)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct ApplyOptions {
    /// Enables credential attribution (ADR 0020 reauth). `None` skips
    /// attribution; tracking still proceeds.
    pub master_password: Option<SecretString>,
}

/// Execute the approved plan. See the module doc for order and failure
/// semantics.
pub fn apply(
    vault: &mut UnlockedVault,
    detection: &ProjectDetection,
    plan: &TrackingPlan,
    options: &ApplyOptions,
    ops: &dyn ServiceOps,
) -> ApplyReport {
    let mut steps: Vec<StepReport> = Vec::new();
    let mut install_blocked = false;
    let mut attribution_enabled = false;

    macro_rules! fail {
        ($id:expr, $err:expr, $project_id:expr, $setup_id:expr) => {{
            steps.push(StepReport {
                id: $id,
                title: $id.title(),
                outcome: StepOutcome::Failed { error: $err },
            });
            if let (Some(setup_id), true) = (&$setup_id, true) {
                let conn = vault.connection();
                let reason = format!(
                    "apply_failed:{}",
                    serde_json::to_string(&$id).unwrap_or_default()
                );
                // "This apply failed" is a fact that has to reach the row.
                //
                // `transition` is a compare-and-swap (`VER-01`) and deliberately
                // does not retry on its own, because its legality check encodes
                // an intent that generally has to be re-judged. Here the intent
                // is unconditional — the step DID fail — so a conflict means
                // only "re-read and say it again", never "reconsider".
                //
                // Retrying matters more than it looks. Before the CAS this write
                // was forced through and could clobber newer state; swallowing
                // the conflict without a retry would trade that for the opposite
                // defect, silently losing the failure record — which is the
                // ZFT-006 outcome by omission rather than by overwrite.
                //
                // Every arm below is spelled out because the catch-all used
                // to swallow `CoreError::InvalidInput` from the legality gate
                // (`state.rs`) as if it were a success (`NEW-33`). A
                // concurrent `track undo` that completes mid-apply leaves the
                // row at `not_configured`, from which `NeedsAttention` is an
                // illegal transition — so the failure record silently went
                // nowhere and a later `track status` said "not configured"
                // instead of "the last attempt failed". When it cannot be
                // written, the report has to say so.
                let mut unrecorded: Option<String> = None;
                for _ in 0..3 {
                    match state::get_setup(conn, setup_id) {
                        Ok(Some(setup)) => {
                            match state::transition(
                                conn,
                                &setup,
                                TrackingState::NeedsAttention,
                                Some(&reason),
                            ) {
                                Ok(_) => {
                                    unrecorded = None;
                                    break;
                                }
                                Err(api_tracker_core::CoreError::StateConflict { .. }) => {
                                    unrecorded = Some(
                                        "the setup row kept changing underneath this attempt"
                                            .to_string(),
                                    );
                                    continue;
                                }
                                Err(e) => {
                                    unrecorded = Some(e.to_string());
                                    break;
                                }
                            }
                        }
                        // The row is gone — undo removed it. There is nothing
                        // to record the failure against, and nothing wrong:
                        // the setup the failure would describe no longer
                        // exists.
                        Ok(None) => break,
                        // A database error is NOT the same thing, and must
                        // not be reported as though the row had been tidied
                        // away.
                        Err(e) => {
                            unrecorded = Some(e.to_string());
                            break;
                        }
                    }
                }
                if let Some(why) = unrecorded {
                    steps.push(StepReport {
                        id: StepId::RecordSetup,
                        title: StepId::RecordSetup.title(),
                        outcome: StepOutcome::Skipped {
                            reason: format!(
                                "this failure could not be recorded on the setup row ({why}), so \
                                 `tethra track status` may not mention it — re-run setup or run \
                                 `tethra track doctor`"
                            ),
                        },
                    });
                }
            }
            return ApplyReport {
                steps,
                project_id: $project_id,
                setup_id: $setup_id,
                state: TrackingState::NeedsAttention,
                install_blocked,
                attribution_enabled,
            };
        }};
    }

    // -- 1. ensure project ------------------------------------------------
    let folder = &detection.folder;
    let project_id = match ensure_project(vault, plan, folder) {
        Ok((id, detail)) => {
            steps.push(StepReport {
                id: StepId::EnsureProject,
                title: StepId::EnsureProject.title(),
                outcome: StepOutcome::Done { detail },
            });
            id
        }
        Err(e) => fail!(
            StepId::EnsureProject,
            e.to_string(),
            String::new(),
            None::<String>
        ),
    };

    // The setup row exists from here on, so every later failure has a
    // persisted, diagnosable home.
    // Route provenance has to be read BEFORE the new session clears the
    // previous summary. A re-apply sees `add_manifest_route` return
    // AlreadyExists and records the route as "reused", so `created_routes`
    // came back empty — and a later undo then stranded routes this setup
    // really had created, with the false reason "existed before this setup
    // (only reused)" (ZFT-018). The union below keeps the first apply's
    // answer, which is the true one.
    //
    // `re_enabled_routes` is carried across for the same reason and by the
    // same mechanism: on the second run the route is already enabled, so the
    // planner emits `ReuseRoute` and nothing records that this product turned
    // the flag on — which is how a deliberately-disabled route stayed
    // permanently enabled (ZFT-019).
    let (previously_created, previously_re_enabled): (Vec<String>, Vec<String>) = {
        let conn = vault.connection();
        state::find_setup(conn, &project_id, folder)
            .ok()
            .flatten()
            .map(|prior| {
                let summary = state::plan_summary_of(&prior);
                (summary.created_routes, summary.re_enabled_routes)
            })
            .unwrap_or_default()
    };

    // The row is carried, not just its id: every guarded write below updates
    // this handle in place, so the compare-and-swap on the last one compares
    // against the version THIS apply left the row at rather than against a
    // re-read of whatever a concurrent apply has since written (`NEW-31`).
    let mut setup_row = {
        let conn = vault.connection();
        let detection_json = serde_json::to_string(detection).unwrap_or_else(|_| "{}".to_string());
        match state::upsert_setup(
            conn,
            &project_id,
            folder,
            TrackingState::Applying,
            &detection_json,
        ) {
            Ok(setup) => setup,
            Err(e) => fail!(
                StepId::EnsureProject,
                e.to_string(),
                project_id,
                None::<String>
            ),
        }
    };
    let setup_id: Option<String> = Some(setup_row.id.clone());

    // -- 2. ensure port ---------------------------------------------------
    {
        let conn = vault.connection();
        match store::load_config(conn) {
            Ok(mut config) => match config.port {
                Some(p) if p != plan.port => fail!(
                    StepId::EnsurePort,
                    format!(
                        "the persisted gateway port ({p}) no longer matches this plan \
                         ({}); re-run setup to preview against the current port",
                        plan.port
                    ),
                    project_id,
                    setup_id
                ),
                Some(_) => steps.push(StepReport {
                    id: StepId::EnsurePort,
                    title: StepId::EnsurePort.title(),
                    outcome: StepOutcome::Skipped {
                        reason: format!("port {} already persisted", plan.port),
                    },
                }),
                None => {
                    config.port = Some(plan.port);
                    match store::save_config(conn, &config) {
                        Ok(()) => steps.push(StepReport {
                            id: StepId::EnsurePort,
                            title: StepId::EnsurePort.title(),
                            outcome: StepOutcome::Done {
                                detail: format!("port {}", plan.port),
                            },
                        }),
                        Err(e) => fail!(StepId::EnsurePort, e.to_string(), project_id, setup_id),
                    }
                }
            },
            Err(e) => fail!(StepId::EnsurePort, e.to_string(), project_id, setup_id),
        }
    }

    // -- 3. ensure service ------------------------------------------------
    let needs_service_work = plan
        .service_actions
        .iter()
        .any(|a| !matches!(a, ServiceAction::AlreadyRunning));
    match ops.ensure_service(&plan.service_actions) {
        ServiceEnsureOutcome::Verified => {
            let conn = vault.connection();
            if let Ok(mut config) = store::load_config(conn) {
                if !config.enabled || config.service_version.is_none() {
                    config.enabled = true;
                    config.service_version = Some(env!("CARGO_PKG_VERSION").to_string());
                    let _ = store::save_config(conn, &config);
                }
            }
            steps.push(StepReport {
                id: StepId::EnsureService,
                title: StepId::EnsureService.title(),
                outcome: if needs_service_work {
                    StepOutcome::Done {
                        detail: format!("listening on 127.0.0.1:{}", plan.port),
                    }
                } else {
                    StepOutcome::Skipped {
                        reason: "already running".to_string(),
                    }
                },
            });
        }
        ServiceEnsureOutcome::InstallBlocked { error } => {
            install_blocked = true;
            fail!(StepId::EnsureService, error, project_id, setup_id)
        }
        ServiceEnsureOutcome::Unverified { detail } => {
            fail!(StepId::EnsureService, detail, project_id, setup_id)
        }
    }

    // -- 4. ensure routes -------------------------------------------------
    let mut created_routes = Vec::new();
    let mut reused_routes = Vec::new();
    // Routes that existed but were DISABLED and which this run turned back
    // on. Without this, `Ok("re-enabled")` fell through the `Ok(_)` arm
    // into `reused_routes`, the summary never recorded that the flag had
    // changed, and undo left a deliberately-disabled route permanently
    // enabled (ZFT-019).
    let mut re_enabled_routes = Vec::new();
    let mut any_custom = false;
    for action in &plan.route_actions {
        let result: Result<&'static str> = (|| {
            match action {
                RouteAction::CreateManifestRoute {
                    prefix,
                    provider_id,
                } => {
                    let conn = vault.connection();
                    match routes::add_manifest_route(conn, prefix, provider_id) {
                        Ok(()) => Ok("created"),
                        // Converges on re-run: an existing row is a reuse.
                        Err(CoreError::AlreadyExists { .. }) => Ok("reused"),
                        Err(e) => Err(e),
                    }
                }
                RouteAction::CreateCustomRoute {
                    prefix,
                    provider_id,
                    origin,
                } => {
                    any_custom = true;
                    let mac_key = vault.gateway_route_mac_key()?;
                    let conn = vault.connection();
                    match routes::add_custom_route(conn, prefix, provider_id, origin, &mac_key) {
                        Ok(()) => Ok("created"),
                        Err(CoreError::AlreadyExists { .. }) => Ok("reused"),
                        Err(e) => Err(e),
                    }
                }
                RouteAction::ReEnableRoute { prefix, .. } => {
                    let conn = vault.connection();
                    routes::set_route_enabled(conn, prefix, true)?;
                    Ok("re-enabled")
                }
                RouteAction::ReuseRoute { .. } => Ok("reused"),
            }
        })();
        match result {
            Ok("created") => created_routes.push(action.prefix().to_string()),
            Ok("re-enabled") => re_enabled_routes.push(action.prefix().to_string()),
            Ok(_) => reused_routes.push(action.prefix().to_string()),
            Err(e) => fail!(
                StepId::EnsureRoutes,
                format!("route '{}': {e}", action.prefix()),
                project_id,
                setup_id
            ),
        }
    }
    steps.push(StepReport {
        id: StepId::EnsureRoutes,
        title: StepId::EnsureRoutes.title(),
        outcome: StepOutcome::Done {
            // What THIS run did, which is what the step line is about; the
            // union with earlier runs' provenance happens immediately below
            // and is a record for undo, not a claim about this run.
            detail: route_detail(&created_routes, &reused_routes),
        },
    });

    // A route this setup created on an EARLIER apply is still one it
    // created; the current run only sees it as pre-existing.
    for prefix in previously_created {
        if !created_routes.contains(&prefix) {
            created_routes.push(prefix);
        }
    }
    for prefix in previously_re_enabled {
        if !re_enabled_routes.contains(&prefix) && !created_routes.contains(&prefix) {
            re_enabled_routes.push(prefix);
        }
    }
    let reused_routes: Vec<String> = reused_routes
        .into_iter()
        .filter(|p| !created_routes.contains(p))
        .collect();

    // `NEW-32`: persist the provenance NOW, not at step 10.
    //
    // Everything above this line has already changed the machine — the
    // routes exist. Recording that only at the end meant an apply that
    // failed at any of steps 5-9 left `plan_summary_json` NULL (the re-apply
    // upsert had just cleared the previous run's), so the routes this
    // product had created became indistinguishable from routes the user had
    // always had. The retry classified them as "reused" and undo refused to
    // remove them, telling the user they "existed before this setup" —
    // which was false, and left the machine dirty with no way to find out.
    {
        let recorded = state::record_routes_created(
            vault.connection(),
            &mut setup_row,
            &created_routes,
            &re_enabled_routes,
        );
        if let Err(e) = recorded {
            fail!(
                StepId::EnsureRoutes,
                format!("could not record which routes this setup created: {e}"),
                project_id,
                setup_id
            );
        }
    }

    // Custom routes may also pre-exist (reused), so check the table, not
    // just this plan's created set.
    if !any_custom {
        let conn = vault.connection();
        any_custom = conn
            .query_row(
                "SELECT COUNT(*) FROM gateway_routes WHERE custom_origin IS NOT NULL",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false);
    }

    // -- 5. route MAC key -------------------------------------------------
    if any_custom {
        match vault.gateway_route_mac_key() {
            Ok(key) => {
                if ops.push_route_key(&key) {
                    steps.push(StepReport {
                        id: StepId::EnsureRouteKey,
                        title: StepId::EnsureRouteKey.title(),
                        outcome: StepOutcome::Done {
                            detail: "installed in the running service".to_string(),
                        },
                    });
                } else {
                    fail!(
                        StepId::EnsureRouteKey,
                        "the running service did not accept the route verification key; \
                         custom-origin routes cannot forward without it"
                            .to_string(),
                        project_id,
                        setup_id
                    );
                }
            }
            Err(e) => fail!(StepId::EnsureRouteKey, e.to_string(), project_id, setup_id),
        }
    } else {
        steps.push(StepReport {
            id: StepId::EnsureRouteKey,
            title: StepId::EnsureRouteKey.title(),
            outcome: StepOutcome::Skipped {
                reason: "no custom-origin routes".to_string(),
            },
        });
    }

    // -- 6. apply links ---------------------------------------------------
    // The handle that seals recorded prior `.env` values (RA-006). Derived
    // once, from the unlocked vault this apply already holds: a recorded
    // value is a credential, and it must never reach the database in the
    // clear. Failing to derive it fails the STEP — proceeding would either
    // store a credential in plaintext or silently lose the ability to undo,
    // and neither is a thing to do quietly.
    let restore_crypto = match vault.env_restore_crypto() {
        Ok(c) => c,
        Err(e) => fail!(
            StepId::ApplyLinks,
            format!("could not prepare the .env restore record key: {e}"),
            project_id,
            setup_id
        ),
    };
    let mut linked = Vec::new();
    let mut files_touched: Vec<String> = Vec::new();
    for link_plan in &plan.link_plans {
        let req = envlink::LinkRequest {
            project_id: project_id.clone(),
            project_name: plan.project.name.clone(),
            route_prefix: link_plan.route_prefix.clone(),
            project_dir: Some(folder.clone()),
            files: link_plan
                .files
                .iter()
                .map(|f| PathBuf::from(&f.path))
                .collect(),
            var_override: None,
        };
        let conn = vault.connection();
        match envlink::apply_link(conn, Some(&restore_crypto), &req, link_plan) {
            Ok(_prior) => {
                linked.push(link_plan.route_prefix.clone());
                for f in &link_plan.files {
                    if !files_touched.contains(&f.path) {
                        files_touched.push(f.path.clone());
                    }
                }
            }
            Err(e) => fail!(
                StepId::ApplyLinks,
                format!("{}: {e}", link_plan.route_prefix),
                project_id,
                setup_id
            ),
        }
    }
    steps.push(StepReport {
        id: StepId::ApplyLinks,
        title: StepId::ApplyLinks.title(),
        outcome: StepOutcome::Done {
            detail: format!("{} file(s)", files_touched.len()),
        },
    });

    // -- 7. reload nudge --------------------------------------------------
    let nudged = ops.reload_routes();
    steps.push(StepReport {
        id: StepId::ReloadRoutes,
        title: StepId::ReloadRoutes.title(),
        outcome: if nudged {
            StepOutcome::Done {
                detail: "routes reloaded".to_string(),
            }
        } else {
            // The service polls data_version every few seconds anyway.
            StepOutcome::Skipped {
                reason: "service will pick the change up on its own".to_string(),
            }
        },
    });

    // -- 8. path check ----------------------------------------------------
    let mut probe_details = Vec::new();
    for link_plan in &plan.link_plans {
        match ops.probe_route(plan.port, &link_plan.base_url) {
            ProbeOutcome::ProviderAnswered { status } => probe_details.push(format!(
                "{}: provider answered {status} to a keyless request — path verified",
                link_plan.provider_id
            )),
            ProbeOutcome::Forwarded { status } => probe_details.push(format!(
                "{}: provider answered {status}; the path through the gateway works",
                link_plan.provider_id
            )),
            ProbeOutcome::GatewayAnswered { status } => fail!(
                StepId::PathCheck,
                format!(
                    "{}: the gateway itself answered {status} — the route did not forward",
                    link_plan.provider_id
                ),
                project_id,
                setup_id
            ),
            ProbeOutcome::NoListener => fail!(
                StepId::PathCheck,
                "the service is not answering on its port".to_string(),
                project_id,
                setup_id
            ),
            ProbeOutcome::NotVerified { detail } => fail!(
                StepId::PathCheck,
                format!(
                    "the listener on the port did not verify as this vault's gateway: {detail}"
                ),
                project_id,
                setup_id
            ),
            ProbeOutcome::Unreachable { error } => fail!(
                StepId::PathCheck,
                format!("could not reach the gateway: {error}"),
                project_id,
                setup_id
            ),
        }
    }
    steps.push(StepReport {
        id: StepId::PathCheck,
        title: StepId::PathCheck.title(),
        outcome: StepOutcome::Done {
            detail: probe_details.join("; "),
        },
    });

    // -- 9. attribution (degrades, never blocks) --------------------------
    match (&plan.attribution, &options.master_password) {
        (AttributionPlan::Skip, _) | (_, None) => steps.push(StepReport {
            id: StepId::Attribution,
            title: StepId::Attribution.title(),
            outcome: StepOutcome::Skipped {
                reason: "not requested — you can enable it later from the dashboard".to_string(),
            },
        }),
        (AttributionPlan::Requested, Some(password)) => {
            let outcome = vault
                .gateway_matching_key(password)
                .and_then(|key| ops.push_matching_key(key));
            match outcome {
                Ok(()) => {
                    attribution_enabled = true;
                    steps.push(StepReport {
                        id: StepId::Attribution,
                        title: StepId::Attribution.title(),
                        outcome: StepOutcome::Done {
                            detail: "requests will be labeled with their credential".to_string(),
                        },
                    });
                }
                Err(e) => steps.push(StepReport {
                    id: StepId::Attribution,
                    title: StepId::Attribution.title(),
                    // Attribution failure is a warning: tracking works
                    // without it (Journey B).
                    outcome: StepOutcome::Skipped {
                        reason: format!(
                            "could not enable attribution ({e}); traffic is still recorded"
                        ),
                    },
                }),
            }
        }
    }

    // -- 10. record setup -------------------------------------------------
    let summary = PlanSummary {
        providers: plan
            .route_actions
            .iter()
            .map(|a| a.provider_id().to_string())
            .collect(),
        created_routes,
        reused_routes,
        re_enabled_routes,
        links: linked,
        files: files_touched,
        attribution_enabled,
        installed_service: plan
            .service_actions
            .iter()
            .any(|a| matches!(a, ServiceAction::InstallService)),
        port: plan.port,
        // `record_applied` owns this flag; see `PlanSummary::apply_completed`.
        apply_completed: false,
    };
    let end_state = match plan.restart_expectation {
        RestartExpectation::NotNeeded => TrackingState::AwaitingFirstRequest,
        RestartExpectation::RequiredLikely | RestartExpectation::Unknown => {
            TrackingState::AwaitingRestart
        }
    };
    {
        let conn = vault.connection();
        let recorded: Result<()> = (|| {
            // The in-memory row has been kept at the version every guarded
            // write left it at, so this is the caller's own snapshot rather
            // than a re-read — which is the whole point of the CAS: a
            // re-read here would compare the row against itself and guard
            // nothing (`NEW-31`).
            state::record_applied(conn, &mut setup_row, &summary)?;
            state::transition(conn, &setup_row, end_state, None)?;
            audit::record(
                conn,
                "tracking_setup_applied",
                Some(&project_id),
                None,
                &format!(
                    "providers={} files={} attribution={}",
                    summary.providers.join(","),
                    summary.files.len(),
                    attribution_enabled
                ),
            )?;
            Ok(())
        })();
        match recorded {
            Ok(()) => steps.push(StepReport {
                id: StepId::RecordSetup,
                title: StepId::RecordSetup.title(),
                outcome: StepOutcome::Done {
                    detail: end_state.as_str().to_string(),
                },
            }),
            Err(e) => fail!(StepId::RecordSetup, e.to_string(), project_id, setup_id),
        }
    }

    ApplyReport {
        steps,
        project_id,
        setup_id,
        state: end_state,
        install_blocked,
        attribution_enabled,
    }
}

fn route_detail(created: &[String], reused: &[String]) -> String {
    match (created.is_empty(), reused.is_empty()) {
        (false, true) => format!("created: {}", created.join(", ")),
        (true, false) => format!("reused: {}", reused.join(", ")),
        (false, false) => format!(
            "created: {}; reused: {}",
            created.join(", "),
            reused.join(", ")
        ),
        (true, true) => "none needed".to_string(),
    }
}

/// Ensure the project row exists and the canonical folder is registered.
fn ensure_project(
    vault: &mut UnlockedVault,
    plan: &TrackingPlan,
    folder: &Path,
) -> Result<(String, String)> {
    let folder_str = folder.display().to_string();
    match &plan.project.id {
        Some(id) => {
            let registered =
                api_tracker_core::vault::projects_for_folder(vault.connection(), folder)?
                    .contains(id);
            if !registered {
                vault.update_project(
                    id,
                    UpdateProject {
                        add_repo_paths: vec![folder_str.clone()],
                        ..Default::default()
                    },
                )?;
            }
            Ok((
                id.clone(),
                format!("existing project '{}'", plan.project.name),
            ))
        }
        None => {
            // Before creating anything, look for a project the user already
            // has under this name. A manually-configured user — one who set
            // up routes and links by hand, so their project carries no
            // registered repo path — otherwise got a DUPLICATE project, a
            // new link slug and a rewritten `.env`, which is exactly what
            // MIGRATION.md promises will not happen ("nothing is deleted,
            // duplicated, or re-created"). Adopting the existing row and
            // registering the folder on it is both what the user meant and
            // what the document says (ZFT-024).
            let wanted = plan.project.name.trim().to_lowercase();
            let existing = vault.list_projects(false).ok().and_then(|projects| {
                projects
                    .into_iter()
                    .find(|p| p.name.trim().to_lowercase() == wanted)
            });
            if let Some(project) = existing {
                vault.update_project(
                    &project.id,
                    UpdateProject {
                        add_repo_paths: vec![folder_str],
                        ..Default::default()
                    },
                )?;
                return Ok((
                    project.id,
                    format!(
                        "adopted the existing project '{}' and registered this folder on it",
                        project.name
                    ),
                ));
            }
            let project = vault.create_project(NewProject {
                name: plan.project.name.clone(),
                repo_paths: vec![folder_str],
                ..Default::default()
            })?;
            Ok((project.id, format!("created project '{}'", project.name)))
        }
    }
}
