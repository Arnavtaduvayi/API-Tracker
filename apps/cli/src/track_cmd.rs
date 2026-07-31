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
use api_tracker_tracking::health;
use api_tracker_tracking::origin;
use api_tracker_tracking::plan::{
    self, ensure_port, AttributionPlan, PlanWarning, ProjectRef, RestartExpectation, Selections,
};
use api_tracker_tracking::state;
use api_tracker_tracking::undo as track_undo;
use api_tracker_tracking::verify;
use clap::{Args, Subcommand};

use crate::ctx::Ctx;
use crate::render;

/// How long the post-apply wait watches for the first request before
/// reporting "needs attention" and exiting 2 (tracking stays on).
const WAIT_WINDOW_SECS: u64 = 120;

/// Test-only pacing overrides for the verify loop.
///
/// The loop's *decision* is never overridable — only how long it waits
/// between polls and before giving up. Without this a regression test for
/// `NEW-01` would have to sit through a two-minute window per failure case,
/// which is the reason the CLI had no test on this path at all. Read in the
/// CLI and nowhere else: no crate under `crates/` consults these, so the
/// derivation this loop depends on has no test seam of any kind.
fn secs_from_env(var: &str, default: u64) -> std::time::Duration {
    let secs = std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default);
    std::time::Duration::from_secs(secs)
}

fn wait_window() -> std::time::Duration {
    secs_from_env("TETHRA_TRACK_WAIT_SECS", WAIT_WINDOW_SECS)
}

fn poll_interval() -> std::time::Duration {
    secs_from_env("TETHRA_TRACK_POLL_SECS", POLL_INTERVAL_SECS)
}

/// How many unrecognised credentials to list before summarising the rest.
/// The COUNT is always exact; only the enumeration is bounded, so a
/// thirty-API project stays readable without hiding anything.
const UNRECOGNIZED_DISPLAY_LIMIT: usize = 12;
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
    ///
    /// Deliberately does NOT approve a destination read from the project's
    /// own files — that is a separate decision (see `--allow-origin`).
    #[arg(long)]
    yes: bool,

    /// Approve one exact destination read from this project's files, e.g.
    /// `--allow-origin https://abcdef.supabase.co`. Repeatable.
    ///
    /// This is the non-interactive equivalent of the approval prompt. It
    /// exists because a repository can choose where its configuration
    /// points, so "run the setup" and "send my API traffic to this host"
    /// must be two different answers (ADR 0024).
    #[arg(long = "allow-origin", value_name = "URL")]
    allow_origins: Vec<String>,
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
        None => track(
            ctx,
            args.path,
            args.project,
            args.dry_run,
            args.yes,
            &args.allow_origins,
        ),
    }
}

/// Unlock via session/TETHRA_PASSWORD, else prompt interactively — `track`
/// never tells the user to run a separate unlock command.
fn unlocked(ctx: &Ctx) -> Result<UnlockedVault> {
    if let Ok((vault, token)) = ctx.unlocked() {
        ctx.persist_session(&vault, &token)?;
        return Ok(vault);
    }
    // NEW-42: `ctx.unlocked()` fails identically for a MISSING vault and a
    // locked one, so a first-time user with TETHRA_PASSWORD already set was
    // told to set TETHRA_PASSWORD — advice that cannot work, for a problem
    // they do not have. Name the real one.
    if !ctx.paths.db_path().exists() {
        bail!(
            "no vault exists yet at {}. Run `tethra init` to create one, then `tethra track` \
             again.",
            ctx.paths.db_path().display()
        );
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "the vault is locked. Set TETHRA_PASSWORD or run this command interactively \
             so it can ask for your master password."
        );
    }
    let password = crate::ctx::prompt_secret("Master password")?;
    let mut vault = vault::unlock_vault(&ctx.paths, &password)
        .context("unlocking the vault with that password")?;
    // NEW-07: the interactive fallback unlocks directly rather than through
    // `Ctx::unlocked`, so it was the one successful unlock that never
    // re-sealed legacy rollback records (`ENC-01`).
    crate::ctx::upgrade_restore_records(&mut vault);
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

/// Whether the user pre-approved this exact destination on the command line.
///
/// Comparison is on the canonical origin, so `https://h`, `https://H` and
/// `https://h:443` all match — and nothing else does. In particular a
/// trailing slash does **not**: `origin::canonicalize` requires a bare
/// authority and rejects any path, query or fragment, because loosening that
/// is how a destination the user never approved starts matching an approval
/// they did give. This comment used to claim `https://H/` matched; it never
/// has, and [`validate_allow_origins`] now reports such a value instead of
/// letting it silently fail to match.
fn args_allows(allow_origins: &[String], origin: &str) -> bool {
    let Ok(wanted) = origin::canonicalize(origin) else {
        return false;
    };
    allow_origins
        .iter()
        .filter_map(|o| origin::canonicalize(o).ok())
        .any(|o| o == wanted)
}

/// Reject an unusable `--allow-origin` up front.
///
/// Without this, a value the canonicalizer cannot parse simply never matches
/// anything, and the user sees "NOT approved" for a destination they believe
/// they just approved — with nothing anywhere saying why. That is an
/// unactionable result on the one path whose entire job is to be an explicit,
/// deliberate approval, so a malformed value is an error before any scanning
/// happens rather than a silent no-op afterwards.
fn validate_allow_origins(allow_origins: &[String]) -> Result<()> {
    for raw in allow_origins {
        if let Err(e) = origin::canonicalize(raw) {
            bail!(
                "--allow-origin {}: {e}\n       \
                 Pass the destination exactly as Tethra displays it — scheme, host and \
                 optional :443, with no trailing slash and no path.",
                render::sanitize(raw)
            );
        }
    }
    Ok(())
}

fn track(
    ctx: &Ctx,
    path: Option<PathBuf>,
    project: Option<String>,
    dry_run: bool,
    yes: bool,
    allow_origins: &[String],
) -> Result<()> {
    validate_allow_origins(allow_origins)?;
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

    if detection.providers.is_empty() && detection.unrecognized.is_empty() {
        println!("No API integrations found in this folder.");
        println!(
            "Tethra looked at .env files, package manifests, and lockfiles ({} file(s) \
             read, 6 levels deep).",
            detection.scanned_files
        );
        if let Some(gaps) = detection.accounting.describe_gaps() {
            println!(
                "Not everything could be inspected: {}",
                render::sanitize(&gaps)
            );
        }
        println!(
            "If this is the wrong folder, point Tethra at the one containing your .env or \
             package manifest."
        );
        std::process::exit(2);
    }

    // The honest headline first: every integration the scan saw, in exactly
    // one bucket. The old screen listed only manifest-matched providers
    // under a heading reading `Detected:`, so unrecognised credentials were
    // invisible rather than merely unsupported (ZFT-010).
    for line in detection.coverage.lines() {
        println!("{}", render::sanitize(&line));
    }
    if let Some(gaps) = detection.accounting.describe_gaps() {
        println!(
            "Not everything could be inspected: {}",
            render::sanitize(&gaps)
        );
    }
    for warning in &detection.accounting.git_warnings {
        println!("! {}", render::sanitize(warning));
    }
    println!();

    if !detection.providers.is_empty() {
        println!("Recognised:");
        for p in &detection.providers {
            let evidence: Vec<String> = p.evidence.iter().take(2).map(|e| e.describe()).collect();
            // NEW-43: label the row with the bucket the HEADLINE counted it
            // in. This used to switch on configurability alone, with no
            // confidence guard, while the headline ranked confidence first —
            // so six rows could render under a headline that said three. One
            // precedence, in one place, for both.
            let label = p.bucket().label().to_string();
            println!(
                "  {:<12}{:<15}{}",
                render::sanitize(&p.provider_id),
                label,
                render::sanitize(&evidence.join("; "))
            );
            for lim in &p.limitations {
                println!("                             {}", render::sanitize(lim));
            }
        }
        println!();
    }

    if !detection.unrecognized.is_empty() {
        println!(
            "Not recognised ({}) — Tethra has no provider definition for these, so it cannot \
             track them yet. They are listed so this screen is not read as complete coverage:",
            detection.unrecognized.len()
        );
        for u in detection
            .unrecognized
            .iter()
            .take(UNRECOGNIZED_DISPLAY_LIMIT)
        {
            match &u.name_hint {
                Some(hint) => println!(
                    "  {:<28}{:<12}in {}",
                    render::sanitize(&u.var),
                    render::sanitize(hint),
                    render::sanitize(&u.file)
                ),
                None => println!(
                    "  {:<28}{:<12}in {}",
                    render::sanitize(&u.var),
                    "",
                    render::sanitize(&u.file)
                ),
            }
        }
        if detection.unrecognized.len() > UNRECOGNIZED_DISPLAY_LIMIT {
            println!(
                "  … and {} more (all counted above)",
                detection.unrecognized.len() - UNRECOGNIZED_DISPLAY_LIMIT
            );
        }
        println!();
    }

    // ---- selections ----------------------------------------------------
    // Defaults cover only providers whose destination comes from a
    // compiled-in Tethra manifest. Anything read out of this project's own
    // files is a separate, explicit decision below (ADR 0024).
    let mut selections = Selections::defaults(&detection);
    for p in &detection.providers {
        if let Configurability::NeedsOriginInput = p.configurability {
            println!(
                "{}: its project URL could not be inferred, so Tethra cannot track it \
                 automatically. Add the destination under Advanced, or re-run with \
                 --allow-origin https://… once you know it.",
                render::sanitize(&p.provider_id)
            );
        }
    }

    // ---- repository-discovered destinations ----------------------------
    let pending = Selections::pending_origin_approvals(&detection);
    let mut approvals_to_persist: Vec<(String, String)> = Vec::new();
    if !pending.is_empty() {
        let vault_id = api_tracker_gateway::routes::vault_id(vault.connection())?;
        let mac_key = vault.gateway_route_mac_key().ok();
        println!("Destinations read from this project (not from Tethra):");
        for (provider_id, inferred) in &pending {
            let display = detection
                .providers
                .iter()
                .find(|p| &p.provider_id == provider_id)
                .map(|p| p.display_name.clone())
                .unwrap_or_else(|| provider_id.clone());
            let source = detection
                .providers
                .iter()
                .find(|p| &p.provider_id == provider_id)
                .and_then(|p| {
                    p.evidence.iter().find_map(|e| match e {
                        detect::Evidence::BaseUrlVar { var, file } => {
                            Some((var.clone(), file.clone()))
                        }
                        _ => None,
                    })
                });
            let request = match origin::describe(
                provider_id,
                &display,
                inferred,
                source.as_ref().map(|(_, f)| f.as_str()),
                source.as_ref().map(|(v, _)| v.as_str()),
                true,
                origin::OriginTrust::RepositoryDiscovered,
            ) {
                Ok(r) => r,
                Err(e) => {
                    println!("  ! {} — {}", render::sanitize(provider_id), e);
                    continue;
                }
            };

            // Already approved, byte for byte, by this user in this vault?
            let already = mac_key.as_ref().and_then(|k| {
                origin::is_approved(vault.connection(), &vault_id, k, inferred, provider_id)
                    .ok()
                    .flatten()
            });
            if let Some(prior) = already {
                // NEW-15: route the decision through the shared predicate
                // rather than restating it. `OriginTrust`'s doc comment
                // called itself "the single place that decision is made"
                // while having no production caller at all — a false claim
                // about the code, in the code, on the consent path.
                let trust = origin::OriginTrust::PreviouslyApproved {
                    approved_at: prior.approved_at.clone(),
                };
                if trust.may_configure_without_asking() {
                    println!(
                        "  ✓ {} — you approved {} on {}",
                        render::sanitize(provider_id),
                        render::sanitize(&prior.origin),
                        render::sanitize(&prior.approved_at)
                    );
                    selections.approve_origin(provider_id, inferred);
                    continue;
                }
            }

            println!();
            println!("  {}", render::sanitize(&request.question()));
            for line in request.disclosure() {
                println!("    {}", render::sanitize(&line));
            }

            // Explicit pre-approval on the command line.
            if args_allows(allow_origins, inferred) {
                println!("    → approved by --allow-origin");
                // NEW-12: the approval is REMEMBERED for this vault, so a
                // later run — including one without `--allow-origin` — will
                // configure this destination without asking again. The
                // disclosure above never said so, which made a one-off flag
                // look like a one-off decision.
                println!(
                    "      (remembered for this vault: a later `tethra track` will configure \
                     {} without asking again)",
                    render::sanitize(inferred)
                );
                selections.approve_origin(provider_id, inferred);
                approvals_to_persist.push((provider_id.clone(), inferred.clone()));
                continue;
            }

            if dry_run {
                println!(
                    "    → NOT approved. This destination will not be configured. Re-run \
                     interactively, or pass --allow-origin {}",
                    render::sanitize(inferred)
                );
                continue;
            }

            // `--yes` answers "run the setup", never "send my traffic to a
            // host this repository chose" — the two are separate decisions.
            if yes {
                println!(
                    "    → NOT approved: --yes does not approve a project-chosen destination."
                );
                println!(
                    "      Re-run interactively, or pass --allow-origin {}",
                    render::sanitize(inferred)
                );
                continue;
            }
            if !std::io::stdin().is_terminal() {
                println!(
                    "    → NOT approved: no terminal to ask on. Pass --allow-origin {}",
                    render::sanitize(inferred)
                );
                continue;
            }
            // Default OFF: an empty answer declines.
            if crate::ctx::confirm_default_no("    Allow this destination?")? {
                selections.approve_origin(provider_id, inferred);
                approvals_to_persist.push((provider_id.clone(), inferred.clone()));
            } else {
                println!("    → declined; this destination will not be configured.");
            }
        }
        println!();
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
    // The ADR-0020 disclosure, identical in substance to the desktop flow
    // and the Advanced push-key dialog. Consenting to a memory oracle must
    // not be cheaper here than there just because this is the one-command
    // path (ZFT-013).
    println!("     This hands the local gateway a derived matching-only key so it can label");
    println!("     observed traffic with which vault credential was used. The key cannot decrypt");
    println!(
        "     anything, but while it is resident a process that can read the gateway's memory"
    );
    println!("     (or its database) gains an oracle for testing whether a value matches one of");
    println!("     your credentials. It covers credentials in every linked, non-password-locked");
    println!("     project in this vault — not only this one. The key is dropped when the service");
    println!("     stops, when you revoke it, and when the vault locks. Press Enter to skip:");
    println!("     tracking records traffic either way.");

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

    // Persist the destinations the user just approved, so the next run of
    // this project reuses them without asking again — but only after apply
    // actually succeeded, and only for the exact origin they were shown.
    if report.failed_step().is_none() && !approvals_to_persist.is_empty() {
        if let Ok(key) = vault.gateway_route_mac_key() {
            if let Ok(vault_id) = api_tracker_gateway::routes::vault_id(vault.connection()) {
                for (provider_id, o) in &approvals_to_persist {
                    let _ = origin::approve(vault.connection(), &vault_id, &key, o, provider_id);
                }
            }
        }
    }

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
        "Waiting for traffic (up to {} s; Ctrl-C stops waiting — tracking stays on)…",
        wait_window().as_secs()
    );
    let setup_id = report.setup_id.clone().unwrap_or_default();
    let deadline = std::time::Instant::now() + wait_window();
    loop {
        let Some(mut setup) = state::get_setup(vault.connection(), &setup_id)? else {
            bail!("the tracking setup disappeared mid-verification");
        };
        // NEW-01/VER-02: the ONE authoritative present-tense answer, shared
        // with `track status`, the desktop's tracking commands and the core
        // derivation. This loop used to gate its banner and its exit status
        // on `verify::check_traffic`, which switches on the cached `state`
        // column after a liveness-blind refresh — so "✓ Tracking verified"
        // and exit 0 survived stopping the gateway, removing the route and
        // deleting the link. A script that gates on `tethra track` must not
        // be told yes while the user's requests are failing.
        let health = health::resolve(vault.connection(), &ctx.paths.data_dir, &mut setup)?;
        if health.current.is_currently_working() {
            let exchange = verify::latest_observed_exchange(vault.connection(), &setup)?;
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
            if let state::CurrentHealth::PartiallyTracked { observed, total } = &health.current {
                let unseen: Vec<String> = health
                    .freshness
                    .iter()
                    .filter(|f| !f.fresh)
                    .map(|f| f.provider_id.clone())
                    .collect();
                println!("  {observed} of {total} configured providers are active right now.");
                if !unseen.is_empty() {
                    println!(
                        "  No recent {} traffic — this is normal if the app hasn't called \
                         it. Tethra keeps watching.",
                        render::sanitize(&unseen.join(", "))
                    );
                }
            }
            if health::attribution_is_paused(&ctx.paths.data_dir) {
                // Forwarding is healthy; only credential attribution is
                // degraded. Reported beside the success, never folded into
                // it (SI-11/SI-12).
                println!(
                    "  (credential attribution is paused — the vault is locked, so requests are \
                     tracked but not attributed to a stored credential)"
                );
            }
            println!("\nDashboard: open the Tethra app, or run `tethra track status`.");
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            // The present-tense answer first, then history, then the ranked
            // diagnosis. "Traffic was observed previously" is a fact worth
            // printing and is deliberately NOT a success: the exit status
            // below reflects the state now.
            println!("\nNot verified. Now: {}", health.current.describe());
            if let Some(at) = &health.history.first_verified_at {
                println!("History: first verified {}", render::sanitize(at));
            }
            if let Some(at) = &health.history.session_first_observed_at {
                println!(
                    "History: traffic was observed previously — first seen here {}",
                    render::sanitize(at)
                );
            }
            println!("Tracking stays on; when a request arrives it will be recorded.");
            println!("Checked causes, in order:");
            for d in diagnose::diagnose(vault.connection(), &ctx.paths.data_dir, &setup)? {
                println!("  - {}", render::sanitize(&d.message));
            }
            std::process::exit(2);
        }
        std::thread::sleep(poll_interval());
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
        // The lifecycle could not be built, so which installation this
        // would have controlled is genuinely unknown — reported as empty
        // rather than defaulted to something plausible.
        installation_id: String::new(),
        service_name: String::new(),
        installed: false,
        definition_path: String::new(),
        definition: None,
        matches_data_dir: false,
        binary_exists: false,
        binary_version: None,
        binary_version_measured: false,
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

/// The setup `undo` and `doctor` act on.
///
/// Two defects lived in these four lines. The connection was opened WITHOUT
/// running migrations, so the first `track undo` or `track doctor` after a
/// v14→v15 upgrade failed with "no such table: tracking_setups" (ZFT-036).
/// And `setups_for_folder` returns newest-transition-first, so `pop()` took
/// the OLDEST setup while `track status` reported the newest — `undo` and
/// `doctor` could act on a different setup than the one the user had just
/// been shown (ZFT-037).
/// One plain sentence per restore outcome.
///
/// `undo` used to print the Rust `Debug` form straight to the terminal —
/// `Restored { path: "…", key: "…" }` — which is a data structure, not an
/// answer to "what happened to my file?" (ZFT-034).
fn describe_restore(outcome: &api_tracker_gateway::envlink::RestoreOutcome) -> String {
    use api_tracker_gateway::envlink::RestoreOutcome as R;
    match outcome {
        R::Restored { path, key } => format!("restored {key} in {path}"),
        R::LeftUserEdit { path, key } => format!(
            "left {key} in {path} alone — you changed it after tracking started, so your value \
             was kept"
        ),
        R::AlreadyRestored { path, key } => {
            format!("{key} in {path} was already back to its original value")
        }
        R::FileMissing { path } => format!("{path} no longer exists; nothing to restore in it"),
        R::CreatedFileRemoved { path } => {
            format!("removed {path} — Tethra created it and nothing else was ever in it")
        }
        R::PriorNotRecorded { path, key } => format!(
            "left {key} in {path} in place: its original value was never recorded (it did not \
             look like non-secret configuration), so restoring it is a manual step"
        ),
        R::Failed { path, key, error } => {
            format!("could NOT restore {key} in {path}: {error}")
        }
    }
}

fn setup_for_folder(ctx: &Ctx, path: Option<PathBuf>) -> Result<Option<state::TrackingSetup>> {
    let folder = resolve_folder(path)?;
    let mut conn = api_tracker_core::db::open(&ctx.paths.db_path())?;
    api_tracker_core::db::migrate(&mut conn)?;
    // One-time privacy upgrade of link rows written by builds that stored
    // prior values in plaintext (ZFT-016, RA-006). These entry points hold
    // no unlocked vault, so the call is a deliberate no-op here and the work
    // happens on the next unlocked command — re-sealing needs a key, and
    // redacting without one would destroy the user's undo.
    let _ = api_tracker_gateway::envlink::scrub_stored_prior_env_once(&conn, None);
    let setups = state::setups_for_folder(&conn, &folder)?;
    Ok(setups.into_iter().next())
}

fn status(ctx: &Ctx, path: Option<PathBuf>) -> Result<()> {
    let folder = resolve_folder(path)?;
    let mut conn = api_tracker_core::db::open(&ctx.paths.db_path())?;
    api_tracker_core::db::migrate(&mut conn)?;
    // One-time privacy upgrade of link rows written by builds that stored
    // prior values in plaintext (ZFT-016, RA-006). These entry points hold
    // no unlocked vault, so the call is a deliberate no-op here and the work
    // happens on the next unlocked command — re-sealing needs a key, and
    // redacting without one would destroy the user's undo.
    let _ = api_tracker_gateway::envlink::scrub_stored_prior_env_once(&conn, None);
    let setups = state::setups_for_folder(&conn, &folder)?;
    let Some(mut setup) = setups.into_iter().next() else {
        println!("Tracking is not configured for {}.", folder.display());
        println!("Run `tethra track .` to set it up.");
        std::process::exit(2);
    };
    // Probe the gateway BEFORE deriving health. The audit's decisive
    // reproduction was killing the service and still reading "tracking
    // verified — traffic observed": the derivation consulted only
    // historical event rows, so it kept reporting success while the user's
    // application was pointed at a loopback port with nothing listening
    // (ZFT-005). Liveness is now an input, not an afterthought — and the
    // probe-then-derive pair lives in ONE place, shared with the verify
    // loop above and the desktop's tracking commands (NEW-01).
    let liveness = health::probe_liveness(&conn, &ctx.paths.data_dir);
    let report = health::resolve_with(&conn, &mut setup, liveness)?;
    let freshness = report.freshness.clone();
    #[derive(serde::Serialize)]
    struct StatusOut<'a> {
        /// The present-tense answer. This is what a caller should act on.
        current: &'a state::CurrentHealth,
        /// Facts that survive the current session. Shown alongside
        /// `current`, never instead of it.
        history: &'a state::VerificationHistory,
        /// Whether the gateway answered at the moment of this read.
        gateway_running: bool,
        state: &'a str,
        folder: &'a str,
        project_id: &'a str,
        applied_at: Option<&'a str>,
        providers: &'a [state::ProviderFreshness],
        attention_reason: Option<&'a str>,
    }
    let out = StatusOut {
        current: &report.current,
        history: &report.history,
        gateway_running: liveness == state::GatewayLiveness::Verified,
        state: setup.state.as_str(),
        folder: &setup.folder_path,
        project_id: &setup.project_id,
        applied_at: setup.applied_at.as_deref(),
        providers: &freshness,
        attention_reason: setup.attention_reason.as_deref(),
    };
    let currently_working = report.current.is_currently_working();
    render::emit(ctx.json, &out, || {
        println!("Now: {}", render::sanitize(&report.current.describe()));
        // History is printed under its own heading so "first verified" can
        // never be mistaken for "working right now".
        if report.history.first_verified_at.is_some()
            || report.history.session_first_observed_at.is_some()
        {
            println!("History:");
            if let Some(at) = &report.history.first_verified_at {
                println!("  first verified   {}", render::sanitize(at));
            }
            if let Some(at) = &report.history.session_first_observed_at {
                println!("  first seen here  {}", render::sanitize(at));
            }
        }
        if !freshness.is_empty() {
            println!("Providers:");
            for f in &freshness {
                let mut notes = Vec::new();
                if !f.route_present {
                    notes.push("route missing");
                }
                if !f.link_present {
                    notes.push("project link missing");
                }
                if f.last_observed_at.is_some() && !f.fresh {
                    notes.push("no recent traffic");
                }
                let suffix = if notes.is_empty() {
                    String::new()
                } else {
                    format!("  ({})", notes.join(", "))
                };
                match &f.last_observed_at {
                    Some(at) => println!(
                        "  {:<12}last observed {}{}",
                        render::sanitize(&f.provider_id),
                        render::sanitize(at),
                        suffix
                    ),
                    None => println!(
                        "  {:<12}no traffic observed in this session{}",
                        render::sanitize(&f.provider_id),
                        suffix
                    ),
                }
            }
        }
        if !currently_working {
            println!("\nRun `tethra track doctor` for the ranked diagnosis.");
        }
    });
    // Exit 0 only for a present-tense success. "Verified previously" is
    // deliberately a non-zero exit: a script that gates on tracking working
    // must not be told yes while the service is down.
    if currently_working {
        Ok(())
    } else {
        std::process::exit(2)
    }
}

fn doctor(ctx: &Ctx, path: Option<PathBuf>) -> Result<()> {
    let Some(setup) = setup_for_folder(ctx, path)? else {
        println!("Tracking is not configured for this folder. Run `tethra track .` first.");
        std::process::exit(2);
    };
    let mut conn = api_tracker_core::db::open(&ctx.paths.db_path())?;
    api_tracker_core::db::migrate(&mut conn)?;
    // One-time privacy upgrade of link rows written by builds that stored
    // prior values in plaintext (ZFT-016, RA-006). These entry points hold
    // no unlocked vault, so the call is a deliberate no-op here and the work
    // happens on the next unlocked command — re-sealing needs a key, and
    // redacting without one would destroy the user's undo.
    let _ = api_tracker_gateway::envlink::scrub_stored_prior_env_once(&conn, None);
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
    let mut vault = unlocked(ctx)?;
    let restore_crypto = vault.env_restore_crypto()?;
    let report = track_undo::undo(vault.connection(), Some(&restore_crypto), &setup)?;
    for link in &report.links {
        for outcome in &link.outcomes {
            println!("  {}", render::sanitize(&describe_restore(outcome)));
        }
    }
    for note in &report.notes {
        println!("! {}", render::sanitize(note));
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
        println!(
            "Tracking was NOT fully stopped (see above). Nothing was removed that could not be \
             restored, and the links were kept so you can retry."
        );
        std::process::exit(1);
    }
}
