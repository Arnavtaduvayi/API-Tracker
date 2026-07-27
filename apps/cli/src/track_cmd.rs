//! `tethra track` — the one-command tracking flow (ADR 0022 D7).
//!
//! `tethra track .` drives the shared orchestrator end to end: resolve or
//! create the project → bounded scan → one combined plan + diff → one
//! confirmation → apply → verify → live status. It prompts for the master
//! password itself when attribution is offered and NEVER prints shell
//! export choreography. The low-level `tethra gateway …` family remains
//! for experts and troubleshooting.
//!
//! Exit codes: 0 = configured and verified (or dry-run/status/undo OK),
//! 2 = configured but unverified (waiting window elapsed), 1 = error.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use api_tracker_core::secret::SecretString;
use api_tracker_core::vault::{self, UnlockedVault};
use api_tracker_tracking::apply::{self, ApplyOptions, HostServiceOps, StepOutcome};
use api_tracker_tracking::detect::{self, Configurability, DetectionInput};
use api_tracker_tracking::diagnose;
use api_tracker_tracking::plan::{
    self, ensure_port, AttributionPlan, PlanWarning, ProjectRef, RestartExpectation, Selections,
};
use api_tracker_tracking::state::{self, TrackingState};
use api_tracker_tracking::undo as track_undo;
use api_tracker_tracking::verify::{self, WatchStatus};
use clap::{Args, Subcommand};

use crate::ctx::Ctx;
use crate::render;

/// How long the post-apply wait watches for the first request before
/// reporting "needs attention" and exiting 2 (tracking stays on).
const WAIT_WINDOW_SECS: u64 = 120;
const POLL_INTERVAL_SECS: u64 = 5;

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct TrackArgs {
    #[command(subcommand)]
    cmd: Option<TrackSub>,

    /// Project folder to track (defaults to the current directory).
    path: Option<PathBuf>,

    /// Tethra project to attach this folder to (name or id). Without it,
    /// the folder's registered project is used, or a new one is created.
    #[arg(long)]
    project: Option<String>,

    /// Show the combined plan and diff, change nothing.
    #[arg(long)]
    dry_run: bool,

    /// Answer yes to the confirmation prompt (attribution is then enabled
    /// only when TETHRA_PASSWORD is set; it is never prompted for).
    #[arg(long)]
    yes: bool,
}

#[derive(Subcommand)]
enum TrackSub {
    /// Current tracking state, per-provider freshness, and diagnosis.
    Status {
        /// Folder to report on (defaults to the current directory).
        path: Option<PathBuf>,
    },
    /// Run the tracking diagnostics for a folder.
    Doctor {
        /// Folder to diagnose (defaults to the current directory).
        path: Option<PathBuf>,
    },
    /// Restore env files and remove the routes/links `track` created.
    Undo {
        /// Folder whose tracking to undo (defaults to the current directory).
        path: Option<PathBuf>,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

pub fn run(ctx: &Ctx, args: TrackArgs) -> Result<()> {
    match args.cmd {
        Some(TrackSub::Status { path }) => status(ctx, path),
        Some(TrackSub::Doctor { path }) => doctor(ctx, path),
        Some(TrackSub::Undo { path, yes }) => undo(ctx, path, yes),
        None => track(ctx, args.path, args.project, args.dry_run, args.yes),
    }
}

/// Unlock via session/TETHRA_PASSWORD, else prompt interactively — `track`
/// never tells the user to run a separate unlock command.
fn unlocked(ctx: &Ctx) -> Result<UnlockedVault> {
    if let Ok((vault, token)) = ctx.unlocked() {
        ctx.persist_session(&vault, &token)?;
        return Ok(vault);
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "the vault is locked. Set TETHRA_PASSWORD or run this command interactively \
             so it can ask for your master password."
        );
    }
    let password = crate::ctx::prompt_secret("Master password")?;
    let vault = vault::unlock_vault(&ctx.paths, &password)
        .context("unlocking the vault with that password")?;
    Ok(vault)
}

fn resolve_folder(path: Option<PathBuf>) -> Result<PathBuf> {
    let folder = match path {
        Some(p) => p,
        None => std::env::current_dir().context("reading the current directory")?,
    };
    folder
        .canonicalize()
        .with_context(|| format!("cannot access {}", folder.display()))
}

/// Resolve which project this folder belongs to. Exactly-one registered
/// match wins; ambiguity is an explicit error; no match → to-create.
fn resolve_project(
    vault: &UnlockedVault,
    folder: &Path,
    explicit: Option<&str>,
) -> Result<ProjectRef> {
    if let Some(ident) = explicit {
        let project = vault.get_project(ident)?;
        return Ok(ProjectRef {
            id: Some(project.id),
            name: project.name,
        });
    }
    let ids = vault::projects_for_folder(vault.connection(), folder)?;
    match ids.len() {
        0 => {
            let name = folder
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("tracked-project")
                .to_string();
            Ok(ProjectRef { id: None, name })
        }
        1 => {
            let project = vault.get_project(&ids[0])?;
            Ok(ProjectRef {
                id: Some(project.id),
                name: project.name,
            })
        }
        _ => {
            let names: Vec<String> = ids
                .iter()
                .filter_map(|id| vault.get_project(id).ok().map(|p| p.name))
                .collect();
            bail!(
                "this folder is registered to more than one project ({}); pick one with \
                 --project <name>",
                names.join(", ")
            );
        }
    }
}

fn track(
    ctx: &Ctx,
    path: Option<PathBuf>,
    project: Option<String>,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let folder = resolve_folder(path)?;
    let vault = unlocked(ctx)?;
    let mut vault = vault;

    println!("Tethra — track API activity\n");
    let project_ref = resolve_project(&vault, &folder, project.as_deref())?;
    match &project_ref.id {
        Some(_) => println!(
            "Project: {}  (matched this folder to the existing project '{}')",
            render::sanitize(&project_ref.name),
            render::sanitize(&project_ref.name)
        ),
        None => println!(
            "Project: {}  (will be created)",
            render::sanitize(&project_ref.name)
        ),
    }

    // ---- scan ----------------------------------------------------------
    let detection = detect::detect(
        vault.connection(),
        &DetectionInput {
            folder: &folder,
            project_id: project_ref.id.as_deref(),
        },
    )?;
    println!(
        "Scanned: {}  (this folder only; nothing executed or uploaded)\n",
        render::sanitize(&detection.folder.display().to_string())
    );

    if detection.providers.is_empty() {
        println!("No trackable APIs detected in this folder.");
        println!(
            "Tethra looked at .env files, package manifests, and lockfiles ({} file(s) \
             read, 6 levels deep).",
            detection.scanned_files
        );
        println!("• Using a provider Tethra doesn't support yet? See `tethra provider list`.");
        println!(
            "• Know the provider and its base URL? `tethra gateway route add` is the expert path."
        );
        std::process::exit(2);
    }

    println!("Detected:");
    for p in &detection.providers {
        let evidence: Vec<String> = p.evidence.iter().take(2).map(|e| e.describe()).collect();
        let label = match &p.configurability {
            Configurability::Unsupported { .. } => "unsupported".to_string(),
            _ => p.confidence.label().to_string(),
        };
        println!(
            "  {:<12}{:<12}{}",
            render::sanitize(&p.provider_id),
            label,
            render::sanitize(&evidence.join("; "))
        );
        for lim in &p.limitations {
            println!("              {}", render::sanitize(lim));
        }
    }
    println!();

    // ---- selections ----------------------------------------------------
    let selections = Selections::defaults(&detection);
    for p in &detection.providers {
        if let Configurability::NeedsOriginInput = p.configurability {
            println!(
                "{}: its project URL could not be inferred; after setup, add it under the \
                 expert path (`tethra gateway route add {} --origin https://…`).",
                render::sanitize(&p.provider_id),
                render::sanitize(&p.provider_id)
            );
        }
    }
    if selections.include.is_empty() {
        println!("Nothing detected is automatically configurable yet.");
        std::process::exit(2);
    }

    // ---- plan ----------------------------------------------------------
    if !dry_run {
        ensure_port(vault.connection())?;
    }
    let service_status = api_tracker_gateway::lifecycle::Lifecycle::for_host(&ctx.paths.data_dir)
        .map(|lc| lc.status())
        .unwrap_or_else(|e| {
            let mut s = fallback_service_status();
            s.notes.push(format!("service state unavailable: {e}"));
            s
        });
    let listener_live = matches!(
        api_tracker_gateway::control::verify_listener(
            &ctx.paths.data_dir,
            api_tracker_gateway::store::load_config(vault.connection())?
                .port
                .unwrap_or(0),
        ),
        api_tracker_gateway::control::ListenerIdentity::Verified { .. }
    );
    let tracking_plan = plan::plan(
        vault.connection(),
        &detection,
        &selections,
        project_ref.clone(),
        &service_status,
        listener_live,
    )?;

    println!("Will do:");
    let mut n = 1;
    for action in &tracking_plan.service_actions {
        use api_tracker_tracking::plan::ServiceAction::*;
        let text = match action {
            InstallService => {
                "install + start the local tracking service (per-user, loopback-only)".to_string()
            }
            StartService => "start the local tracking service".to_string(),
            RepairService { installed, current } => {
                format!("update the tracking service helper ({installed} → {current})")
            }
            AlreadyRunning => "local tracking service: already running".to_string(),
        };
        println!("  {n}. {text}");
        n += 1;
    }
    let route_list: Vec<String> = tracking_plan
        .route_actions
        .iter()
        .map(|a| match a {
            plan::RouteAction::CreateCustomRoute { prefix, origin, .. } => {
                format!("{prefix} → {origin}")
            }
            other => other.prefix().to_string(),
        })
        .collect();
    if !route_list.is_empty() {
        println!(
            "  {n}. create routes: {}",
            render::sanitize(&route_list.join(", "))
        );
        n += 1;
    }
    let file_count = tracking_plan
        .link_plans
        .iter()
        .flat_map(|lp| lp.files.iter())
        .filter(|f| f.changed)
        .count();
    println!(
        "  {n}. edit {file_count} environment file(s) (diff below), adding NO_PROXY for loopback"
    );
    n += 1;
    println!("  {n}. enable credential attribution (asks for your master password; Enter skips)");

    // ---- diff ----------------------------------------------------------
    for lp in &tracking_plan.link_plans {
        for file in &lp.files {
            if !file.changed {
                println!(
                    "\n{}: already linked (no change)",
                    render::sanitize(&file.path)
                );
                continue;
            }
            println!(
                "\n--- {} {}",
                render::sanitize(&file.path),
                if file.exists { "" } else { "(will be created)" }
            );
            // Line by line: whole-diff sanitizing would collapse newlines
            // and destroy the consent property the preview exists for.
            for line in file.diff.lines() {
                println!("{}", render::sanitize(line));
            }
        }
    }
    let mut warned = std::collections::BTreeSet::new();
    let warnings: Vec<&PlanWarning> = tracking_plan
        .warnings
        .iter()
        .filter(|w| warned.insert(w.describe()))
        .collect();
    if !warnings.is_empty() {
        println!("\nWarnings:");
        for w in warnings {
            println!("  ! {}", render::sanitize(&w.describe()));
        }
    }
    println!();

    if dry_run {
        println!("Dry run: nothing was changed.");
        if tracking_plan.port_provisional {
            println!("(The port shown is provisional until tracking actually starts.)");
        }
        return Ok(());
    }

    // ---- one confirmation ---------------------------------------------
    if !crate::ctx::confirm("Proceed?", yes)? {
        bail!("cancelled");
    }

    // ---- attribution password (O-22-3) ---------------------------------
    let password = attribution_password(yes)?;

    // ---- apply ---------------------------------------------------------
    let helper_source = std::env::current_exe().context("locating this binary")?;
    let ops = HostServiceOps {
        data_dir: ctx.paths.data_dir.clone(),
        helper_source,
        port: tracking_plan.port,
    };
    let mut plan_final = tracking_plan;
    if password.is_none() {
        plan_final.attribution = AttributionPlan::Skip;
    }
    let report = apply::apply(
        &mut vault,
        &detection,
        &plan_final,
        &ApplyOptions {
            master_password: password,
        },
        &ops,
    );

    for step in &report.steps {
        match &step.outcome {
            StepOutcome::Done { detail } => {
                println!("✓ {} — {}", step.title, render::sanitize(detail))
            }
            StepOutcome::Skipped { reason } => {
                println!("• {} — {}", step.title, render::sanitize(reason))
            }
            StepOutcome::Failed { error } => {
                println!("✗ {} — {}", step.title, render::sanitize(error))
            }
        }
    }

    if let Some(failed) = report.failed_step() {
        println!();
        if report.install_blocked {
            println!("The OS refused to run the background service (this build may be unsigned).");
            println!(
                "You can still track while a terminal is open: `tethra gateway serve` runs \
                 the same engine in the foreground."
            );
        }
        println!(
            "Setup stopped at '{}'. Completed steps are left in place; `tethra track undo` \
             restores everything, `tethra track doctor` diagnoses.",
            failed.title
        );
        std::process::exit(1);
    }

    // ---- verify --------------------------------------------------------
    println!();
    match plan_final.restart_expectation {
        RestartExpectation::NotNeeded => println!("Make one API request from your app."),
        _ => println!("Restart your app, then make one API request."),
    }
    println!(
        "Waiting for traffic (up to {WAIT_WINDOW_SECS} s; Ctrl-C stops waiting — tracking stays on)…"
    );
    let setup_id = report.setup_id.clone().unwrap_or_default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(WAIT_WINDOW_SECS);
    loop {
        let Some(mut setup) = state::get_setup(vault.connection(), &setup_id)? else {
            bail!("the tracking setup disappeared mid-verification");
        };
        match verify::check_traffic(vault.connection(), &mut setup)? {
            WatchStatus::Observed { exchange, .. } => {
                let detail = exchange
                    .map(|ex| {
                        let mut parts = vec![format!(
                            "{} request observed from {}",
                            ex.provider_id.unwrap_or_else(|| ex.host.clone()),
                            render::sanitize(&plan_final.project.name)
                        )];
                        if let Some(ms) = ex.latency_ms {
                            parts.push(format!("{ms} ms"));
                        }
                        if let Some(model) = ex.model {
                            parts.push(model);
                        }
                        parts.join(", ")
                    })
                    .unwrap_or_else(|| "traffic observed".to_string());
                println!("✓ Tracking verified — {}", render::sanitize(&detail));
                println!("\nDashboard: open the Tethra app, or run `tethra track status`.");
                return Ok(());
            }
            WatchStatus::PartiallyObserved { freshness, .. } => {
                let seen: Vec<String> = freshness
                    .iter()
                    .filter(|f| f.last_observed_at.is_some())
                    .map(|f| f.provider_id.clone())
                    .collect();
                let unseen: Vec<String> = freshness
                    .iter()
                    .filter(|f| f.last_observed_at.is_none())
                    .map(|f| f.provider_id.clone())
                    .collect();
                println!("✓ Tracking verified for {}.", seen.join(", "));
                println!(
                    "No {} traffic observed yet — this is normal if the app hasn't called \
                     it. Tethra keeps watching.",
                    unseen.join(", ")
                );
                return Ok(());
            }
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            println!("\nNo traffic observed yet. Tracking stays on; when a request arrives it");
            println!("will be recorded. Checked causes, in order:");
            let Some(setup) = state::get_setup(vault.connection(), &setup_id)? else {
                std::process::exit(2);
            };
            for d in diagnose::diagnose(vault.connection(), &ctx.paths.data_dir, &setup)? {
                println!("  - {}", render::sanitize(&d.message));
            }
            std::process::exit(2);
        }
        std::thread::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS));
    }
}

/// O-22-3: `--yes` never prompts and never fails over a missing password —
/// attribution is simply skipped with a note.
fn attribution_password(yes: bool) -> Result<Option<SecretString>> {
    if let Some(pw) = crate::ctx::master_password_from_env() {
        return Ok(Some(pw));
    }
    if yes || !std::io::stdin().is_terminal() {
        println!("(credential attribution skipped: no TETHRA_PASSWORD in a non-interactive run)");
        return Ok(None);
    }
    let pw = crate::ctx::prompt_secret("Master password (Enter to skip attribution)")?;
    if pw.expose().is_empty() {
        return Ok(None);
    }
    Ok(Some(pw))
}

fn fallback_service_status() -> api_tracker_gateway::lifecycle::ServiceStatus {
    api_tracker_gateway::lifecycle::ServiceStatus {
        platform: "unknown",
        installed: false,
        definition_path: String::new(),
        definition: None,
        matches_data_dir: false,
        binary_exists: false,
        binary_version: None,
        registered: false,
        running: false,
        pid: None,
        os_will_run: api_tracker_gateway::lifecycle::OsWillRun::Unknown {
            why: "service manager unavailable".to_string(),
        },
        owned_artifacts: Vec::new(),
        notes: Vec::new(),
    }
}

fn setup_for_folder(ctx: &Ctx, path: Option<PathBuf>) -> Result<Option<state::TrackingSetup>> {
    let folder = resolve_folder(path)?;
    let conn = api_tracker_core::db::open(&ctx.paths.db_path())?;
    let mut setups = state::setups_for_folder(&conn, &folder)?;
    Ok(setups.pop())
}

fn status(ctx: &Ctx, path: Option<PathBuf>) -> Result<()> {
    let folder = resolve_folder(path)?;
    let mut conn = api_tracker_core::db::open(&ctx.paths.db_path())?;
    api_tracker_core::db::migrate(&mut conn)?;
    let setups = state::setups_for_folder(&conn, &folder)?;
    let Some(mut setup) = setups.into_iter().next() else {
        println!("Tracking is not configured for {}.", folder.display());
        println!("Run `tethra track .` to set it up.");
        std::process::exit(2);
    };
    let freshness = state::refresh(&conn, &mut setup)?;
    #[derive(serde::Serialize)]
    struct StatusOut<'a> {
        state: &'a str,
        folder: &'a str,
        project_id: &'a str,
        applied_at: Option<&'a str>,
        first_traffic_at: Option<&'a str>,
        providers: &'a [state::ProviderFreshness],
        attention_reason: Option<&'a str>,
    }
    let out = StatusOut {
        state: setup.state.as_str(),
        folder: &setup.folder_path,
        project_id: &setup.project_id,
        applied_at: setup.applied_at.as_deref(),
        first_traffic_at: setup.first_traffic_at.as_deref(),
        providers: &freshness,
        attention_reason: setup.attention_reason.as_deref(),
    };
    render::emit(ctx.json, &out, || {
        println!("State: {}", state_label(setup.state));
        for f in &freshness {
            match &f.last_observed_at {
                Some(at) => println!("  {:<12}last observed {}", f.provider_id, at),
                None => println!("  {:<12}no traffic observed yet", f.provider_id),
            }
        }
        if setup.state == TrackingState::NeedsAttention {
            println!("\nRun `tethra track doctor` for the ranked diagnosis.");
        }
    });
    match setup.state {
        TrackingState::TrafficObserved | TrackingState::PartiallyObserved => Ok(()),
        _ => std::process::exit(2),
    }
}

fn state_label(s: TrackingState) -> &'static str {
    match s {
        TrackingState::NotConfigured => "not configured",
        TrackingState::Scanning => "scanning",
        TrackingState::ReadyToConfigure => "ready to configure",
        TrackingState::Applying => "applying",
        TrackingState::AwaitingRestart => "waiting — restart the project, then make one request",
        TrackingState::AwaitingFirstRequest => "waiting for the first request",
        TrackingState::TrafficObserved => "tracking verified — traffic observed",
        TrackingState::PartiallyObserved => "tracking verified — some providers not yet observed",
        TrackingState::NeedsAttention => "needs attention",
        TrackingState::Unsupported => "nothing trackable detected",
    }
}

fn doctor(ctx: &Ctx, path: Option<PathBuf>) -> Result<()> {
    let Some(setup) = setup_for_folder(ctx, path)? else {
        println!("Tracking is not configured for this folder. Run `tethra track .` first.");
        std::process::exit(2);
    };
    let mut conn = api_tracker_core::db::open(&ctx.paths.db_path())?;
    api_tracker_core::db::migrate(&mut conn)?;
    let diagnoses = diagnose::diagnose(&conn, &ctx.paths.data_dir, &setup)?;
    render::emit(ctx.json, &diagnoses, || {
        println!("Tracking diagnosis (most likely causes first):\n");
        for (i, d) in diagnoses.iter().enumerate() {
            println!("{}. {}", i + 1, render::sanitize(&d.message));
        }
    });
    Ok(())
}

fn undo(ctx: &Ctx, path: Option<PathBuf>, yes: bool) -> Result<()> {
    let Some(setup) = setup_for_folder(ctx, path)? else {
        println!("Tracking is not configured for this folder; nothing to undo.");
        return Ok(());
    };
    println!("Stop tracking this folder?");
    println!("• Restores env files to their recorded pre-tracking state (your later edits are kept and reported)");
    println!("• Removes this setup's routes if no other project uses them");
    println!("• Keeps all recorded history (it's your data)");
    if !crate::ctx::confirm("Stop tracking and restore?", yes)? {
        bail!("cancelled");
    }
    let vault = unlocked(ctx)?;
    let report = track_undo::undo(vault.connection(), &setup)?;
    for link in &report.links {
        for outcome in &link.outcomes {
            println!("  {}", render::sanitize(&format!("{outcome:?}")));
        }
    }
    if !report.removed_routes.is_empty() {
        println!("Routes removed: {}", report.removed_routes.join(", "));
    }
    for (route, why) in &report.kept_routes {
        println!("Route kept: {route} ({why})");
    }
    // Nudge the running service so restored links vanish immediately.
    let ops = HostServiceOps {
        data_dir: ctx.paths.data_dir.clone(),
        helper_source: std::env::current_exe()?,
        port: 0,
    };
    let _ = apply::ServiceOps::reload_routes(&ops);
    if report.complete {
        println!(
            "Tracking stopped. The background service keeps running if other projects use it;"
        );
        println!("turn it off with `tethra gateway disable` if you're done with it.");
        Ok(())
    } else {
        println!("Some files could not be fully restored (see above). The link was kept so you can retry.");
        std::process::exit(1);
    }
}
