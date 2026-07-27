//! `tethra gateway ...` — the Local Gateway command family.
//!
//! Productized surface (Phase 3): OS-service install/uninstall/start/stop/
//! restart/repair, doctor diagnostics, real `.env` link/unlink with
//! preview-diff-confirm, route enable/disable, and foreground `serve`
//! (aliased `run`, resolving HANDOFF_PHASE_2 D4 in favor of both names
//! meaning the same thing).
//!
//! Convention notes: status/doctor/start/stop/restart/repair never require
//! the vault (a locked desktop is never blind); install/disable/uninstall
//! and everything that rewrites project files or route rows go through the
//! unlocked vault; key handoff keeps its interactive-only reauth.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use api_tracker_gateway::{control, doctor, envlink, lifecycle, routes, service::Service, store};
use clap::Subcommand;

use crate::ctx::Ctx;
use crate::render;

#[derive(Subcommand)]
pub enum GatewayCmd {
    /// Install the gateway as a per-user login service and start it.
    #[command(alias = "enable")]
    Install {
        /// Replace a service that belongs to a different data directory.
        #[arg(long)]
        force: bool,
        /// Skip the consent prompt (you are still consenting).
        #[arg(long)]
        yes: bool,
    },
    /// Stop the service, unregister it, and restore linked .env files.
    /// Keeps installed binaries and all recorded history.
    Disable {
        /// Leave linked .env files pointing at the (stopped) gateway.
        #[arg(long)]
        keep_env: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Disable, then remove the gateway's binaries, logs, and runtime
    /// files. Recorded history stays in the vault database.
    Uninstall {
        /// Leave linked .env files untouched (they will point at nothing).
        #[arg(long)]
        keep_env: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Start the installed service.
    Start,
    /// Stop the running gateway (graceful drain when reachable).
    Stop,
    /// Restart the installed service.
    Restart,
    /// Re-align the installed service with this binary and data directory:
    /// re-copy, rewrite the definition, re-register, restart.
    Repair {
        #[arg(long)]
        yes: bool,
    },
    /// Full diagnosis with repair hints. Works with the vault locked.
    Doctor,
    /// Show what the gateway is doing. Works without unlocking the vault.
    Status,
    /// Run the gateway in the foreground until interrupted.
    #[command(alias = "run")]
    Serve {
        /// Bind port. Defaults to the persisted port, or a random high port
        /// chosen on first run.
        #[arg(long)]
        port: Option<u16>,
        /// Push the credential-matching key at startup so attribution works
        /// (requires an unlocked vault). Without it, attribution honestly
        /// reports `unavailable_no_key`.
        #[arg(long)]
        with_attribution: bool,
        /// Service mode (what the installed service runs): retry a held
        /// port instead of exiting, log to <data-dir>/logs/gateway.log,
        /// and exit cleanly if the data directory disappears.
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Manage provider routes.
    #[command(subcommand)]
    Route(RouteCmd),
    /// Link a project to a route: rewrite its .env (preview + confirm) so
    /// the project's SDK sends traffic through the gateway.
    Link {
        #[arg(long)]
        project: String,
        #[arg(long)]
        route: String,
        /// Environment file(s) to rewrite (repeatable). Defaults to the
        /// project directory's .env.
        #[arg(long = "env-file")]
        env_files: Vec<PathBuf>,
        /// The project directory (defaults to the project's single
        /// registered repository path, when there is exactly one).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Base-URL variable name override (required for providers that
        /// declare none).
        #[arg(long)]
        var: Option<String>,
        /// Show the diff and stop without writing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Unlink a project: restore the recorded prior .env state and remove
    /// the link.
    Unlink {
        #[arg(long)]
        project: String,
        #[arg(long)]
        route: String,
        #[arg(long)]
        yes: bool,
    },
    /// Push the credential-matching key to a running gateway.
    PushKey,
    /// Drop the matching key from a running gateway immediately.
    RevokeKey,
    /// Keep credential matching available while the vault is locked
    /// (consented, default OFF; retention after a lock is bounded by your
    /// auto-lock duration, capped at 8 hours — ADR 0020). Turning it off
    /// drops any resident key immediately.
    MatchWhileLocked {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Reload the route table in a running gateway.
    Reload,
    /// Pause or resume observation recording (forwarding is unaffected).
    Recording {
        #[arg(value_parser = ["pause", "resume"])]
        state: String,
    },
    /// Internal: prove this binary executes (service install probe).
    #[command(hide = true)]
    ServiceProbe,
}

#[derive(Subcommand)]
pub enum RouteCmd {
    /// List registered routes (including disabled ones).
    List,
    /// Register a provider route (origin comes from the provider manifest).
    Add {
        /// Provider id (e.g. `openai`, `anthropic`).
        provider: String,
        /// Route prefix; defaults to the provider id.
        #[arg(long)]
        prefix: Option<String>,
        /// Register a custom origin instead (e.g. a Supabase project URL).
        #[arg(long)]
        origin: Option<String>,
    },
    /// Remove a route.
    Remove { prefix: String },
    /// Enable a route without re-adding it.
    Enable { prefix: String },
    /// Disable a route without removing it (requests answer 404).
    Disable { prefix: String },
    /// Enable or disable a route (legacy spelling of enable/disable).
    #[command(hide = true)]
    Set {
        prefix: String,
        #[arg(value_parser = ["enabled", "disabled"])]
        state: String,
    },
}

pub fn run(ctx: &Ctx, cmd: GatewayCmd) -> Result<()> {
    match cmd {
        GatewayCmd::Install { force, yes } => install(ctx, force, yes),
        GatewayCmd::Disable { keep_env, yes } => disable(ctx, keep_env, yes),
        GatewayCmd::Uninstall { keep_env, yes } => uninstall(ctx, keep_env, yes),
        GatewayCmd::Start => start(ctx),
        GatewayCmd::Stop => stop(ctx),
        GatewayCmd::Restart => restart(ctx),
        GatewayCmd::Repair { yes } => repair(ctx, yes),
        GatewayCmd::Doctor => doctor_cmd(ctx),
        GatewayCmd::Status => status(ctx),
        GatewayCmd::Serve {
            port,
            with_attribution,
            service,
        } => {
            if service {
                serve_service_mode(ctx, port)
            } else {
                serve(ctx, port, with_attribution)
            }
        }
        GatewayCmd::Route(cmd) => route(ctx, cmd),
        GatewayCmd::Link {
            project,
            route,
            env_files,
            dir,
            var,
            dry_run,
            yes,
        } => link(ctx, &project, &route, env_files, dir, var, dry_run, yes),
        GatewayCmd::Unlink {
            project,
            route,
            yes,
        } => unlink(ctx, &project, &route, yes),
        GatewayCmd::PushKey => push_key(ctx),
        GatewayCmd::RevokeKey => simple(ctx, |nonce| control::Request::RevokeKey { nonce }),
        GatewayCmd::MatchWhileLocked { state } => match_while_locked(ctx, state == "on"),
        GatewayCmd::Reload => simple(ctx, |nonce| control::Request::ReloadRoutes { nonce }),
        GatewayCmd::Recording { state } => {
            let pause = state == "pause";
            simple(ctx, move |nonce| {
                if pause {
                    control::Request::PauseRecording { nonce }
                } else {
                    control::Request::ResumeRecording { nonce }
                }
            })
        }
        GatewayCmd::ServiceProbe => {
            // Consumed by lifecycle::prepare_binary. Deliberately touches
            // nothing: no database, no network, no files.
            println!(
                "{} {}",
                api_tracker_gateway::lifecycle::PROBE_MARKER,
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Service lifecycle
// ---------------------------------------------------------------------------

/// What the service definition currently in our slot points at, when that is
/// NOT this data directory. `None` means the slot is ours (or empty) and the
/// verb may proceed.
///
/// `installed` is only ever true with a definition the manager could parse,
/// so the `unwrap_or_else` below is unreachable today; it exists so that a
/// future status shape cannot turn a missing field into a silent pass.
fn foreign_owner(status: &lifecycle::ServiceStatus) -> Option<String> {
    if !status.installed || status.matches_data_dir {
        return None;
    }
    Some(
        status
            .definition
            .as_ref()
            .map(|d| d.data_dir.display().to_string())
            .unwrap_or_else(|| "an unreadable data directory".to_string()),
    )
}

/// Refuse a verb aimed at a service that belongs to a DIFFERENT data
/// directory (ZFT-014).
///
/// The lifecycle engine now proves ownership on every destructive verb, so a
/// foreign target already fails there — but it fails LATE and quietly: as a
/// `stop: ...` line buried in a report, and only after `uninstall` has
/// printed its consent wall, unlocked the vault, and started deleting. A
/// user running two Tethra environments cannot act on what they cannot see,
/// so every verb that reaches the OS service manager checks FIRST, names the
/// data directory that actually owns the job, and exits non-zero without
/// touching launchd/systemd/the registry at all.
fn refuse_if_foreign(status: &lifecycle::ServiceStatus, ctx: &Ctx, verb: &str) -> Result<()> {
    let Some(other) = foreign_owner(status) else {
        return Ok(());
    };
    bail!(
        "refusing to {verb}: the installed service '{name}' belongs to a different Tethra \
         data directory ({other}), not this one ({ours}). Acting on it would control \
         another environment's gateway.\n\
         To act on that installation, re-run with `--data-dir {other}`.\n\
         To take this machine's login slot over from here instead, run \
         `tethra gateway install --force`, which prints exactly what it replaces.",
        name = render::sanitize(&status.service_name),
        other = render::sanitize(&other),
        ours = render::sanitize(&ctx.paths.data_dir.display().to_string()),
    )
}

/// Print what `--force` is about to displace, and take a second, separate
/// confirmation for it.
///
/// `--force` is the one path that is ALLOWED to write over another
/// installation's definition, so "the user passed a flag" is not consent:
/// the flag is usually typed because the engine's refusal suggested it, long
/// before the user knows which other environment is involved. The
/// replacement is therefore disclosed concretely (definition file, service
/// name, both data directories) and confirmed on its own — `--yes` is what
/// says "I have seen this and still mean it".
fn confirm_forced_replacement(
    ctx: &Ctx,
    lc: &lifecycle::Lifecycle,
    status: &lifecycle::ServiceStatus,
    yes: bool,
) -> Result<()> {
    let Some(other) = foreign_owner(status) else {
        return Ok(());
    };
    println!("--force: this REPLACES an existing service definition.");
    println!(
        "  definition file  {}",
        render::sanitize(&lc.manager.definition_path().display().to_string())
    );
    println!(
        "  service name     {}",
        render::sanitize(&status.service_name)
    );
    println!("  it currently runs the gateway for data directory:");
    println!("      {}", render::sanitize(&other));
    println!("  this data directory is:");
    println!(
        "      {}",
        render::sanitize(&ctx.paths.data_dir.display().to_string())
    );
    println!("  After replacement, that installation's gateway will no longer start at");
    println!("  login through this service. Its vault, links, and recorded history are");
    println!("  not touched, and its .env files are left exactly as they are.");
    println!();
    if !crate::ctx::confirm("Replace that installation's service?", yes)? {
        bail!("cancelled");
    }
    println!();
    Ok(())
}

fn install(ctx: &Ctx, force: bool, yes: bool) -> Result<()> {
    let data_dir = &ctx.paths.data_dir;
    let lc = lifecycle::Lifecycle::for_host(data_dir)
        .context("preparing the service manager for this platform")?;

    // Ownership is settled before anything else: without `--force` this
    // install cannot succeed against a foreign slot, so failing here saves
    // the user the disclosure wall, the vault unlock, and a port binding
    // that would all be discarded by the engine's refusal.
    let status = lc.status();
    if !force {
        refuse_if_foreign(&status, ctx, "install over the existing service")?;
    }

    println!("Tethra can run a local background gateway at 127.0.0.1.");
    println!();
    println!("What this installs and starts:");
    println!("  - a per-user login service (no admin rights, no system service):");
    println!(
        "      {}",
        render::sanitize(&lc.manager.definition_path().display().to_string())
    );
    println!("  - a copy of this binary at:");
    println!(
        "      {}",
        render::sanitize(&lc.installed_binary_path().display().to_string())
    );
    println!(
        "  - logs at {}/",
        render::sanitize(&lifecycle::logs_dir(data_dir).display().to_string())
    );
    #[cfg(target_os = "macos")]
    println!("  - a Background item in System Settings → General → Login Items");
    println!();
    println!("What it does: projects you explicitly link can send API traffic through");
    println!("it to your registered providers. Tethra records metadata such as status");
    println!("and latency, but does not store API keys, authorization headers, query");
    println!("values, prompts, request bodies, or response bodies.");
    println!();
    println!("Be aware: any program on this machine can use the loopback port, and its");
    println!("credentials pass through the gateway's memory (never stored). The gateway");
    println!("is a standing local egress relay to your registered providers — a process");
    println!("blocked by a per-application firewall could still reach them through it.");
    println!("Routes can be disabled individually; one action removes everything and");
    println!("restores your .env files.");
    println!();
    // Order matters: what the feature IS, then what this particular run
    // destroys. Each is its own decision, so each gets its own prompt.
    if force {
        confirm_forced_replacement(ctx, &lc, &status, yes)?;
    }
    if !crate::ctx::confirm("Install and start the gateway service?", yes)? {
        bail!("cancelled");
    }

    let (vault, token) = ctx.unlocked()?;

    // The stable port is chosen at enable time (random high port, ADR O3)
    // so .env base URLs survive restarts.
    let mut config = store::load_config(vault.connection())?;
    if config.port.is_none() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .context("choosing a stable local port")?;
        config.port = Some(listener.local_addr()?.port());
        drop(listener);
    }
    let port = config.port.expect("just ensured");

    let source = std::env::current_exe().context("locating this binary")?;
    let report = lc.install(&source, force)?;
    // Before the up-to-ten-second wait, not after it: the notes are where
    // the engine records that it took over a legacy agent or replaced
    // another data directory's definition, and a user who is about to stare
    // at a progress spinner should already know that happened.
    print_install_report(&report);

    config.enabled = true;
    config.service_version = Some(env!("CARGO_PKG_VERSION").to_string());
    store::save_config(vault.connection(), &config)?;
    api_tracker_core::audit::record(
        vault.connection(),
        "gateway_service_installed",
        None,
        None,
        &format!("port={port} definition={}", report.definition),
    )?;
    ctx.persist_session(&vault, &token)?;

    // Verify the service actually came up, identity-checked (D11): never
    // report healthy on the strength of an exit code alone.
    print!("waiting for the gateway to come up");
    let mut verified = false;
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(250));
        if matches!(
            control::verify_listener(data_dir, port),
            control::ListenerIdentity::Verified { .. }
        ) {
            verified = true;
            break;
        }
        print!(".");
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
    println!();
    if verified {
        println!("gateway service installed and running on http://127.0.0.1:{port}");
        println!();
        println!("Next: link a project so its SDK uses the gateway:");
        println!("  tethra gateway route add openai");
        println!("  tethra gateway link --project <name> --route openai");
    } else {
        println!("The service was installed but did not answer its identity probe yet.");
        println!("Diagnose with: tethra gateway doctor");
    }
    Ok(())
}

/// Everything the install/repair engine reported, including the parts that
/// used to be dropped on the floor.
///
/// `notes` carries the events a user MUST be able to see after the fact:
/// legacy-agent migrations ("took over the pre-namespacing agent"), an
/// ownership refusal the engine tolerated rather than aborting on, and forced
/// replacements. `pruned_binaries` says which older helper copies were
/// deleted from `<data-dir>/bin`, and `started` says whether the engine
/// actually asked the OS to run it — all three are facts about this machine
/// that no other command reports.
///
/// Built as lines rather than printed inline so the formatting is testable
/// without installing a service (`report_lines_surface_*` below).
fn install_report_lines(report: &lifecycle::InstallReport) -> Vec<String> {
    let mut lines = Vec::new();
    for note in &report.notes {
        lines.push(format!("note: {}", render::sanitize(note)));
    }
    for pruned in &report.pruned_binaries {
        lines.push(format!(
            "removed older helper binary {}",
            render::sanitize(pruned)
        ));
    }
    if !report.started {
        lines.push(
            "note: the service manager did not report a successful start; \
             diagnose with `tethra gateway doctor`"
                .to_string(),
        );
    }
    lines
}

fn print_install_report(report: &lifecycle::InstallReport) {
    for line in install_report_lines(report) {
        println!("{line}");
    }
}

fn linked_projects_warning(vault: &api_tracker_core::vault::UnlockedVault) -> Result<Vec<String>> {
    let links = routes::list_project_links(vault.connection())?;
    Ok(links
        .iter()
        .filter(|l| l.prior_env_json.is_some())
        .map(|l| format!("{} → {}", l.project_id, l.route_prefix))
        .collect())
}

fn disable(ctx: &Ctx, keep_env: bool, yes: bool) -> Result<()> {
    // Ownership first, before the vault is unlocked and before a single
    // `.env` is described as "about to be restored": disable stops and
    // unregisters an OS job, and the job in the slot may not be ours.
    let lc = lifecycle::Lifecycle::for_host(&ctx.paths.data_dir)?;
    refuse_if_foreign(&lc.status(), ctx, "disable the gateway service")?;

    let (vault, token) = ctx.unlocked()?;
    let linked = linked_projects_warning(&vault)?;
    if !linked.is_empty() && !keep_env {
        println!("Disabling stops the gateway; these linked projects will have their");
        println!(".env files RESTORED to their pre-link values:");
        for l in &linked {
            println!("  {}", render::sanitize(l));
        }
    } else if !linked.is_empty() {
        println!("WARNING: --keep-env leaves these projects pointing at a gateway that");
        println!("will no longer be running (their SDK calls will get connection refused):");
        for l in &linked {
            println!("  {}", render::sanitize(l));
        }
    }
    if !crate::ctx::confirm("Disable the gateway service?", yes)? {
        bail!("cancelled");
    }
    let report = lc.disable(vault.connection(), keep_env)?;
    ctx.persist_session(&vault, &token)?;
    print_disable_report(&report);
    Ok(())
}

/// The disable/uninstall result, notes included.
///
/// `stopped: false` on its own is not an answer — the reason lives in
/// `notes`, which is where the engine now records an ownership refusal
/// ("stop: refusing to stop the service: … belongs to a different Tethra
/// data directory") and legacy-agent reclamation. Printing the booleans
/// without the notes is what made a refused teardown read as a mysterious
/// half-success.
fn disable_report_lines(report: &lifecycle::DisableReport) -> Vec<String> {
    let mut lines = vec![format!(
        "service stopped: {} / unregistered: {}",
        report.stopped, report.unregistered
    )];
    for restore in &report.env_restores {
        for outcome in &restore.outcomes {
            lines.push(format!("  {}", render::sanitize(&format!("{outcome:?}"))));
        }
    }
    if report.incomplete_restores > 0 {
        lines.push(format!(
            "WARNING: {} restore(s) could not complete; the link rows were kept so you \
             can retry with `tethra gateway unlink`",
            report.incomplete_restores
        ));
    }
    for note in &report.notes {
        lines.push(format!("note: {}", render::sanitize(note)));
    }
    lines
}

fn print_disable_report(report: &lifecycle::DisableReport) {
    for line in disable_report_lines(report) {
        println!("{line}");
    }
}

fn uninstall(ctx: &Ctx, keep_env: bool, yes: bool) -> Result<()> {
    // Uninstall is the sharpest case: it stops the job, unregisters it, and
    // removes the definition FILE. Against a foreign slot that last step
    // deletes another environment's service definition, so the check has to
    // come before the vault, the consent wall, and the engine.
    let lc = lifecycle::Lifecycle::for_host(&ctx.paths.data_dir)?;
    refuse_if_foreign(&lc.status(), ctx, "uninstall the gateway service")?;

    let (vault, token) = ctx.unlocked()?;
    let linked = linked_projects_warning(&vault)?;
    println!("Uninstall stops and removes the gateway service, its binaries, logs, and");
    println!("runtime files. Recorded history stays in your vault.");
    if !linked.is_empty() {
        if keep_env {
            println!();
            println!("WARNING: these projects stay pointed at a gateway that will no longer");
            println!("exist (connection refused) because of --keep-env:");
        } else {
            println!();
            println!("These linked projects will have their .env files restored first:");
        }
        for l in &linked {
            println!("  {}", render::sanitize(l));
        }
    }
    if !crate::ctx::confirm("Uninstall the gateway?", yes)? {
        bail!("cancelled");
    }
    let report = lc.uninstall(vault.connection(), keep_env)?;
    ctx.persist_session(&vault, &token)?;
    print_disable_report(&report.disable);
    for p in &report.removed_paths {
        println!("removed {}", render::sanitize(p));
    }
    for note in &report.notes {
        println!("note: {}", render::sanitize(note));
    }
    println!("uninstalled. Recorded gateway history remains in the vault database.");
    Ok(())
}

fn start(ctx: &Ctx) -> Result<()> {
    let lc = lifecycle::Lifecycle::for_host(&ctx.paths.data_dir)?;
    let s = lc.status();
    refuse_if_foreign(&s, ctx, "start the gateway service")?;
    if !s.installed {
        bail!(
            "no gateway service is installed. Install one with `tethra gateway install`, \
             or run in the foreground with `tethra gateway serve`."
        );
    }
    lc.start()?;
    println!("start requested");
    Ok(())
}

fn stop(ctx: &Ctx) -> Result<()> {
    let data_dir = &ctx.paths.data_dir;
    // Prefer the graceful control-plane drain: the process exits CLEANLY,
    // which KeepAlive={Crashed:true} / Restart=on-failure treat as
    // terminal, and the service stays registered for the next login.
    if control::instance_is_live(data_dir) {
        let nonce = control::read_nonce(data_dir).context("reading the gateway control nonce")?;
        match control::send(
            data_dir,
            &control::Request::Shutdown {
                nonce: nonce.to_string(),
            },
        )? {
            control::Response::Ok => {
                println!("stop requested (graceful drain)");
                return Ok(());
            }
            control::Response::Error { code, message } => {
                println!("control channel refused ({code}: {message}); falling back to the service manager");
            }
            other => bail!("unexpected control response: {other:?}"),
        }
    }
    // Only the service-manager fallback can reach a job that is not ours.
    // The graceful drain above is scoped to THIS data directory by
    // construction — it speaks to this directory's control socket and proves
    // the listener's identity against this directory's nonce — so the
    // ownership check belongs here, not at the top, or a foreign definition
    // sitting in the login slot would block a user from stopping their own
    // foreground gateway.
    let lc = lifecycle::Lifecycle::for_host(data_dir)?;
    let s = lc.status();
    refuse_if_foreign(&s, ctx, "stop the gateway service")?;
    if !s.installed {
        println!("nothing to stop: no service installed and no gateway reachable");
        return Ok(());
    }
    lc.stop()?;
    println!("service stopped");
    Ok(())
}

fn restart(ctx: &Ctx) -> Result<()> {
    let lc = lifecycle::Lifecycle::for_host(&ctx.paths.data_dir)?;
    let s = lc.status();
    refuse_if_foreign(&s, ctx, "restart the gateway service")?;
    if !s.installed {
        bail!("no gateway service is installed; use `tethra gateway serve` for foreground runs");
    }
    lc.restart()?;
    println!("restart requested");
    Ok(())
}

fn repair(ctx: &Ctx, yes: bool) -> Result<()> {
    let data_dir = &ctx.paths.data_dir;
    let lc = lifecycle::Lifecycle::for_host(data_dir)?;
    // `repair` is `install(force = false)` underneath, so a foreign slot can
    // only ever end in the engine's refusal — say so before asking for
    // consent to an operation that cannot succeed.
    refuse_if_foreign(&lc.status(), ctx, "repair the gateway service")?;
    println!("Repair re-copies this binary, rewrites the service definition for this");
    println!("data directory, re-registers it, and restarts the service.");
    if !crate::ctx::confirm("Repair the gateway service?", yes)? {
        bail!("cancelled");
    }
    let source = std::env::current_exe().context("locating this binary")?;
    let report = lc.repair(&source)?;
    // Keep the recorded version in step (plain config write, same trust
    // level as serve's port persistence).
    if let Ok(conn) = api_tracker_core::db::open_at_current_version(&ctx.paths.db_path()) {
        if let Ok(mut config) = store::load_config(&conn) {
            config.service_version = Some(env!("CARGO_PKG_VERSION").to_string());
            let _ = store::save_config(&conn, &config);
        }
    }
    println!(
        "repaired: binary {}, definition {}",
        report.binary, report.definition
    );
    print_install_report(&report);
    Ok(())
}

// ---------------------------------------------------------------------------
// Status / doctor
// ---------------------------------------------------------------------------

fn severity_tag(s: doctor::Severity) -> &'static str {
    match s {
        doctor::Severity::Ok => "ok",
        doctor::Severity::Info => "info",
        doctor::Severity::Warn => "WARN",
        doctor::Severity::Error => "ERROR",
    }
}

/// The two facts that tell a user WHICH service these numbers describe.
///
/// A developer with a work vault and a personal vault has two launchd labels
/// (or systemd units, or `Run` values) on one machine, and every lifecycle
/// verb silently addresses exactly one of them. Printing the resolved name
/// and the installation id is what makes `launchctl print gui/501/<label>`,
/// `systemctl --user status <unit>`, or a support request possible at all —
/// and it is the only place the mismatch between the slot and this data
/// directory is visible without reading a plist by hand.
fn print_service_identity(status: &lifecycle::ServiceStatus, ctx: &Ctx) {
    println!("  name      {}", render::sanitize(&status.service_name));
    println!("  id        {}", render::sanitize(&status.installation_id));
    println!(
        "  data dir  {}",
        render::sanitize(&ctx.paths.data_dir.display().to_string())
    );
    if let Some(other) = foreign_owner(status) {
        println!(
            "  WARNING   the installed definition ({}) names a DIFFERENT data",
            render::sanitize(&status.definition_path)
        );
        println!("            directory: {}", render::sanitize(&other));
        println!("            start/stop/restart/disable/uninstall refuse here; use");
        println!("            `--data-dir <that directory>`, or `install --force` to");
        println!("            take the slot over from this environment.");
    }
}

fn doctor_cmd(ctx: &Ctx) -> Result<()> {
    let report = doctor::diagnose(&ctx.paths.data_dir);
    render::emit(ctx.json, &report, || {
        println!("gateway doctor — overall: {}", severity_tag(report.overall));
        println!();
        println!("service identity (which OS job this vault controls):");
        print_service_identity(&report.service, ctx);
        println!(
            "  file      {}",
            render::sanitize(&report.service.definition_path)
        );
        println!();
        for f in &report.findings {
            println!(
                "[{}] {}",
                severity_tag(f.severity),
                render::sanitize(&f.title)
            );
            println!("      {}", render::sanitize(&f.detail));
            if let Some(repair) = &f.repair {
                println!("      fix: {}", render::sanitize(repair));
            }
        }
        if !report.links.is_empty() {
            println!();
            println!("linked projects:");
            for l in &report.links {
                println!(
                    "  {} → {} ({})",
                    render::sanitize(&l.project_id),
                    render::sanitize(&l.route_prefix),
                    if l.issues.is_empty() {
                        "ok".to_string()
                    } else {
                        render::sanitize(&l.issues.join("; "))
                    }
                );
            }
        }
    });
    Ok(())
}

fn status(ctx: &Ctx) -> Result<()> {
    let report = doctor::diagnose(&ctx.paths.data_dir);
    render::emit(ctx.json, &report, || {
        // Service line.
        let s = &report.service;
        if s.installed {
            println!(
                "service     installed ({}), {}",
                s.platform,
                if s.running {
                    format!(
                        "running (pid {})",
                        s.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into())
                    )
                } else {
                    "not running".to_string()
                }
            );
            print_service_identity(s, ctx);
            println!(
                "  at login  {}",
                match &s.os_will_run {
                    lifecycle::OsWillRun::Yes => "starts automatically".to_string(),
                    lifecycle::OsWillRun::OnlyWhileLoggedIn =>
                        "starts at login, stops at logout (linger off)".to_string(),
                    lifecycle::OsWillRun::RegisteredButNeverValidated =>
                        "registered (Windows: compile-validated only, never executed)".to_string(),
                    lifecycle::OsWillRun::No => "will not start".to_string(),
                    lifecycle::OsWillRun::Unknown { why } => format!("unknown ({why})"),
                }
            );
        } else {
            println!("service     not installed (install with `tethra gateway install`)");
            // The name is still worth printing: it is the slot this data
            // directory WOULD claim, which is what a second environment
            // needs to see to know the two will not collide.
            print_service_identity(s, ctx);
        }

        // Live gateway.
        match &report.gateway {
            Some(g) => {
                println!(
                    "gateway     running v{} on http://127.0.0.1:{}",
                    g.version, g.port
                );
                match &report.listener {
                    Some(control::ListenerIdentity::Verified { .. }) => {
                        println!("  identity  verified (answers this data directory's nonce)");
                    }
                    Some(other) => println!("  identity  NOT VERIFIED ({other:?})"),
                    None => {}
                }
                println!("  uptime    {}s", g.uptime_secs);
                println!(
                    "  routes    {} forwardable, {} unavailable, {} disabled",
                    g.routes, g.routes_unavailable, g.routes_disabled
                );
                for (prefix, why) in &g.routes_skipped {
                    println!(
                        "            skipped {}: {}",
                        render::sanitize(prefix),
                        render::sanitize(why)
                    );
                }
                println!("  in flight {}", g.connections_in_flight);
                println!(
                    "  recording {}",
                    if g.recording_paused {
                        "paused".to_string()
                    } else if g.recording_degraded {
                        format!("DEGRADED ({} persist failures)", g.persist_failures)
                    } else {
                        "on".to_string()
                    }
                );
                println!(
                    "  attribution {}",
                    if g.matching_key_present {
                        "on (matching key resident)"
                    } else {
                        "unavailable (no matching key; vault locked or not pushed)"
                    }
                );
                println!(
                    "  events    {} written, {} dropped, queue depth {}",
                    g.written_events, g.dropped_events, g.queue_depth
                );
                match &g.last_observation_at {
                    Some(at) => println!("  last event {at}"),
                    None => println!(
                        "  last event none yet (absence of recorded traffic is not evidence \
                         of absence of traffic)"
                    ),
                }
                if let Some(err) = &g.last_error {
                    println!("  last error {}", render::sanitize(err));
                }
            }
            None => {
                println!("gateway     not running");
                if let Some(port) = report.configured_port {
                    match &report.listener {
                        Some(control::ListenerIdentity::NotOurs) => println!(
                            "  WARNING   port {port} is held by a process that is NOT this \
                             vault's gateway"
                        ),
                        _ => println!("  port      {port} (persisted; nothing listening)"),
                    }
                }
            }
        }

        // Links.
        if report.links.is_empty() {
            println!("links       none");
        } else {
            for l in &report.links {
                println!(
                    "link        {} → {} {}",
                    render::sanitize(&l.project_id),
                    render::sanitize(&l.route_prefix),
                    if l.issues.is_empty() {
                        "(ok)".to_string()
                    } else {
                        format!("(! {})", render::sanitize(&l.issues.join("; ")))
                    }
                );
            }
        }

        // Anything actionable gets one summary line pointing at doctor.
        let actionable = report
            .findings
            .iter()
            .filter(|f| f.severity >= doctor::Severity::Warn)
            .count();
        if actionable > 0 {
            println!();
            println!("{actionable} issue(s) need attention — details: tethra gateway doctor");
        }
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Serve (foreground + service mode)
// ---------------------------------------------------------------------------

fn serve(ctx: &Ctx, port: Option<u16>, with_attribution: bool) -> Result<()> {
    let data_dir = ctx.paths.data_dir.clone();
    // The port is persisted so a linked `.env` keeps working across restarts;
    // a random high port is chosen once rather than a fixed pre-squattable
    // one (ADR 0019 O3).
    let chosen = match port {
        Some(p) => p,
        None => {
            let conn = api_tracker_core::db::open(&ctx.paths.db_path())
                .context("opening the vault database to read the gateway port")?;
            store::load_config(&conn)
                .ok()
                .and_then(|c| c.port)
                .unwrap_or(0)
        }
    };

    let service = Service::start(&data_dir, chosen)
        .context("starting the gateway (is one already running for this data directory?)")?;
    let bound = service.port();

    // Persist the port we actually got, so the next run reuses it and the
    // base URLs written into project .env files keep working. A failure here
    // is NOT cosmetic — the next run would bind a different random port and
    // every linked SDK would get connection-refused — so it is reported.
    if let Err(why) = persist_port(ctx, bound) {
        println!();
        println!("WARNING: could not persist port {bound} ({why}).");
        println!("The next `serve` may bind a different port, which would break any");
        println!(".env base URL pointing at this one. Pass --port {bound} to pin it.");
        println!();
    }

    if let Some(why) = service.control_unavailable() {
        println!();
        println!("WARNING: the local control channel is unavailable, so this gateway has");
        println!("no status, no credential attribution, and no graceful stop:");
        println!("  {why}");
        println!("Forwarding and observation recording are unaffected.");
        println!();
    }

    // Custom-origin routes need the verification key to be forwardable at
    // all (ADR 0021). A foreground `serve` started from an unlocked shell
    // session can install it with no prompt: it verifies route integrity
    // only and cannot decrypt or confirm anything about a credential.
    if service.control_unavailable().is_none() {
        match ctx.unlocked() {
            Ok((mut vault, token)) => {
                install_route_key(ctx, &mut vault, false);
                let _ = ctx.persist_session(&vault, &token);
            }
            Err(_) => {
                let custom_unavailable = service
                    .routes()
                    .table()
                    .iter_routes()
                    .any(|r| matches!(r.target, routes::RouteTarget::Unforwardable(_)));
                if custom_unavailable {
                    println!(
                        "custom-origin routes: unavailable (no unlocked vault session, so the \
                         route verification key could not be installed). Run `tethra unlock` \
                         in this shell and restart, or use the desktop app."
                    );
                }
            }
        }
    }

    if service.control_unavailable().is_some() {
        println!("credential attribution: unavailable (no control channel)");
    } else if with_attribution {
        match install_key(ctx, &data_dir) {
            Ok(()) => println!("credential attribution: enabled for this run"),
            Err(e) => println!(
                "credential attribution: unavailable ({e}); forwarding and recording continue"
            ),
        }
    } else {
        println!(
            "credential attribution: off (pass --with-attribution, or run \
             `tethra gateway push-key`, to enable it)"
        );
    }

    println!("tethra gateway listening on http://127.0.0.1:{bound}");
    println!("  loopback only; forwards only to registered provider routes");
    println!();
    println!("Stop it with Ctrl-C, or from another terminal:");
    println!("  tethra gateway stop");
    println!();
    println!("Coverage note: the gateway sees ONLY traffic whose base URL is");
    println!("repointed at it. Absence of recorded traffic is not evidence of");
    println!("absence of traffic.");

    // Ctrl-C uses the process default (terminate). A graceful drain is
    // available through the control channel (`tethra gateway stop`), which
    // stops accepting, finishes in-flight exchanges, and drains the writer.
    // No signal-handling dependency is added for this.
    service.run_until_stopped();
    println!("gateway stopped");
    Ok(())
}

/// Service mode (`--service`): what the installed service runs. Never exits
/// on a held port; exits cleanly when the install disappears; logs to
/// `<data-dir>/logs/gateway.log` as well as stdout (launchd redirects
/// stdout to the same file; on Windows nothing else captures it).
fn serve_service_mode(ctx: &Ctx, port: Option<u16>) -> Result<()> {
    let data_dir = ctx.paths.data_dir.clone();
    let configured = port.or_else(|| store::port_hint(&data_dir)).unwrap_or(0);
    let log_path = lifecycle::logs_dir(&data_dir).join("gateway.log");
    let _ = std::fs::create_dir_all(lifecycle::logs_dir(&data_dir));

    let write_log = move |line: &str| {
        let stamped = format!("{} {line}\n", api_tracker_core::clock::now_rfc3339());
        print!("{stamped}");
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = f.write_all(stamped.as_bytes());
        }
    };

    let exit = api_tracker_gateway::service::run_as_service(&data_dir, configured, write_log);
    // Both exits are CLEAN by design: KeepAlive={Crashed:true} and
    // Restart=on-failure must not respawn us.
    let _ = exit;
    Ok(())
}

fn persist_port(ctx: &Ctx, port: u16) -> Result<()> {
    let conn =
        api_tracker_core::db::open(&ctx.paths.db_path()).context("opening the vault database")?;
    let mut config = store::load_config(&conn).context("reading the gateway config")?;
    if config.port == Some(port) {
        return Ok(());
    }
    config.port = Some(port);
    store::save_config(&conn, &config).context("saving the gateway port")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Key handoff / one-shot control operations
// ---------------------------------------------------------------------------

fn install_key(ctx: &Ctx, data_dir: &std::path::Path) -> Result<()> {
    let (vault, token) = ctx.unlocked()?;
    // Reauth: handing the matching key to a long-lived process is a
    // consented, disclosed weakening (ADR 0019 D5), so it is gated exactly
    // like revealing a credential and is audited.
    let master = crate::ctx::prompt_secret("Master password")?;
    let key = vault
        .gateway_matching_key(&master)
        .context("reading the credential-matching key")?;
    ctx.persist_session(&vault, &token)?;
    let nonce = control::read_nonce(data_dir).context("reading the gateway control nonce")?;
    // The hex form of the key lives in a zeroizing buffer for the moments it
    // exists; serde still builds one plain String inside `send`, which is a
    // documented best-effort limit (SI-9).
    let hex = zeroize::Zeroizing::new(
        key.expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    let response = control::send(
        data_dir,
        &control::Request::PushKey {
            nonce: nonce.to_string(),
            key_hex: hex.to_string(),
        },
    )?;
    match response {
        control::Response::Ok => Ok(()),
        control::Response::Error { code, message } => bail!("{code}: {message}"),
        other => bail!("unexpected control response: {other:?}"),
    }
}

fn push_key(ctx: &Ctx) -> Result<()> {
    install_key(ctx, &ctx.paths.data_dir)?;
    println!("credential-matching key installed");
    Ok(())
}

/// Flip the consented keep-matching-while-locked toggle (ADR 0020).
/// Enabling grants a retained capability, so it is reauth-gated exactly like
/// the key push; disabling drops any resident key immediately (SI-9).
fn match_while_locked(ctx: &Ctx, enabled: bool) -> Result<()> {
    let (vault, token) = ctx.unlocked()?;
    if enabled {
        let master = crate::ctx::prompt_secret("Master password")?;
        vault
            .verify_master_password(&master)
            .context("enabling keep-while-locked requires the master password")?;
    }
    store::set_match_while_locked(vault.connection(), enabled)?;
    ctx.persist_session(&vault, &token)?;
    if enabled {
        println!(
            "keep-while-locked is ON: after the vault locks, a pushed matching key \
             stays resident for up to your auto-lock duration (8 h cap), then \
             attribution pauses until you push it again."
        );
    } else {
        let revoked = control::send_revoke_key(&ctx.paths.data_dir);
        println!(
            "keep-while-locked is OFF: locking the vault drops the matching key{}",
            if revoked {
                "; the resident key was dropped now"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn simple(ctx: &Ctx, build: impl FnOnce(String) -> control::Request) -> Result<()> {
    let nonce = control::read_nonce(&ctx.paths.data_dir)
        .context("reading the gateway control nonce (is the gateway running?)")?;
    match control::send(&ctx.paths.data_dir, &build(nonce.to_string()))? {
        control::Response::Ok => {
            println!("ok");
            Ok(())
        }
        control::Response::Error { code, message } => bail!("{code}: {message}"),
        other => bail!("unexpected control response: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

fn route(ctx: &Ctx, cmd: RouteCmd) -> Result<()> {
    match cmd {
        RouteCmd::List => {
            let conn = api_tracker_core::db::open(&ctx.paths.db_path())?;
            // Verify custom routes with the real key when a session exists.
            // Loading with `None` unconditionally — what shipped before —
            // always printed "unavailable" for a just-added custom origin,
            // even while a running gateway forwarded it correctly.
            let key = ctx
                .unlocked()
                .ok()
                .and_then(|(mut v, _)| v.gateway_route_mac_key().ok());
            let table = routes::load_route_table(&conn, key.as_ref())?;
            let verifiable = key.is_some();
            // Disabled rows are invisible in the snapshot by design; list
            // them from the table directly so the user sees what exists.
            let mut rows: Vec<Vec<String>> = table
                .iter_routes()
                .map(|r| {
                    vec![
                        r.prefix.clone(),
                        r.provider_id.clone(),
                        match &r.target {
                            routes::RouteTarget::Ready(o) => o.host.clone(),
                            routes::RouteTarget::Unforwardable(
                                routes::Unforwardable::MacKeyUnavailable,
                            ) if !verifiable => {
                                "unverifiable here (vault locked; a running gateway may \
                                 still forward it — see `tethra gateway status`)"
                                    .to_string()
                            }
                            routes::RouteTarget::Unforwardable(why) => {
                                format!("unavailable ({why:?})")
                            }
                        },
                        if r.custom { "custom" } else { "manifest" }.to_string(),
                        "enabled".to_string(),
                    ]
                })
                .collect();
            let mut stmt = conn.prepare(
                "SELECT route_prefix, provider_id FROM gateway_routes WHERE enabled = 0",
            )?;
            let disabled: Vec<(String, String)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<_, _>>()?;
            for (prefix, provider) in disabled {
                rows.push(vec![
                    prefix,
                    provider,
                    "-".into(),
                    "-".into(),
                    "DISABLED".into(),
                ]);
            }
            if rows.is_empty() {
                println!("no routes registered");
                println!("  add one with: tethra gateway route add openai");
            } else {
                render::table(&["PREFIX", "PROVIDER", "ORIGIN", "SOURCE", "STATE"], &rows);
            }
            for (prefix, why) in &table.skipped {
                println!("  skipped {prefix}: {why}");
            }
            Ok(())
        }
        RouteCmd::Add {
            provider,
            prefix,
            origin,
        } => {
            let prefix = prefix.unwrap_or_else(|| provider.clone());
            let (mut vault, token) = ctx.unlocked()?;
            let custom = origin.is_some();
            match origin {
                Some(origin) => {
                    // A custom origin is authenticated by a MAC under the
                    // vault-derived route key, so a later DB edit cannot
                    // redirect it (ADR 0019 D3).
                    let key = vault.gateway_route_mac_key()?;
                    routes::add_custom_route(
                        vault.connection(),
                        &prefix,
                        &provider,
                        &origin,
                        &key,
                    )?;
                }
                None => routes::add_manifest_route(vault.connection(), &prefix, &provider)?,
            }
            ctx.persist_session(&vault, &token)?;
            println!("route '{prefix}' added for provider '{provider}'");
            if custom {
                // Without this the route the user just created answers 503
                // until the next unlock — the defect the final audit found
                // (ADR 0021). Minting is correct here: adding a custom route
                // IS the moment the route key legitimately comes into being.
                install_route_key(ctx, &mut vault, true);
                if !control::instance_is_live(&ctx.paths.data_dir) {
                    println!(
                        "(no gateway is running; the route becomes forwardable when one starts \
                         and this vault is unlocked)"
                    );
                }
            }
            nudge_running_gateway(ctx);
            Ok(())
        }
        RouteCmd::Remove { prefix } => {
            let (vault, token) = ctx.unlocked()?;
            let removed = routes::remove_route(vault.connection(), &prefix)?;
            ctx.persist_session(&vault, &token)?;
            if removed {
                println!("route '{prefix}' removed");
                nudge_running_gateway(ctx);
            } else {
                println!("no route '{prefix}'");
            }
            Ok(())
        }
        RouteCmd::Enable { prefix } => set_route_state(ctx, &prefix, true),
        RouteCmd::Disable { prefix } => set_route_state(ctx, &prefix, false),
        RouteCmd::Set { prefix, state } => set_route_state(ctx, &prefix, state == "enabled"),
    }
}

fn set_route_state(ctx: &Ctx, prefix: &str, enabled: bool) -> Result<()> {
    let (mut vault, token) = ctx.unlocked()?;
    let changed = routes::set_route_enabled(vault.connection(), prefix, enabled)?;
    ctx.persist_session(&vault, &token)?;
    if enabled {
        install_route_key(ctx, &mut vault, false);
    }
    if changed {
        println!(
            "route '{prefix}' is now {}",
            if enabled {
                "enabled"
            } else {
                "disabled (requests answer 404)"
            }
        );
        nudge_running_gateway(ctx);
    } else {
        println!("no route '{prefix}'");
    }
    Ok(())
}

/// Ask a running gateway to re-read routes immediately (best-effort; the
/// 5-second poll would catch it anyway).
/// Install the custom-origin route verification key into a running gateway
/// (ADR 0021).
///
/// This is what makes a custom-origin route actually usable: without it the
/// gateway loads the row but cannot verify it, so every custom route answers
/// 503 forever. Called from every flow that both HAS an unlocked vault and
/// could plausibly precede a custom-route request — unlock, route add/enable,
/// link, status, and serve.
///
/// Silent and best-effort: no running gateway is the normal case, and a
/// vault that has never minted a route key (no custom route ever added) must
/// not have one minted as a side effect of an unrelated command — so this
/// only pushes a key that already exists, unless `mint` is set.
fn install_route_key(ctx: &Ctx, vault: &mut api_tracker_core::vault::UnlockedVault, mint: bool) {
    if !control::instance_is_live(&ctx.paths.data_dir) {
        return;
    }
    if !mint && !routes::route_key_exists(vault.connection()).unwrap_or(false) {
        return;
    }
    if let Ok(key) = vault.gateway_route_mac_key() {
        let _ = control::push_route_key(&ctx.paths.data_dir, &key);
    }
}

/// The unlock-path entry point: install the route key if one exists, never
/// minting a new one. Public so `vault unlock` can call it without
/// duplicating the "is a gateway even running" logic.
pub fn install_route_key_on_unlock(ctx: &Ctx, vault: &mut api_tracker_core::vault::UnlockedVault) {
    install_route_key(ctx, vault, false);
}

fn nudge_running_gateway(ctx: &Ctx) {
    let data_dir = &ctx.paths.data_dir;
    if !control::instance_is_live(data_dir) {
        return;
    }
    if let Ok(nonce) = control::read_nonce(data_dir) {
        let _ = control::send(
            data_dir,
            &control::Request::ReloadRoutes {
                nonce: nonce.to_string(),
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Link / unlink
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn link(
    ctx: &Ctx,
    project: &str,
    route: &str,
    env_files: Vec<PathBuf>,
    dir: Option<PathBuf>,
    var: Option<String>,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    let (vault, token) = ctx.unlocked()?;
    let proj = vault.get_project(project)?;

    // Default the project directory from the registered repo path when it
    // is unambiguous.
    let project_dir = dir.or_else(|| {
        if env_files.is_empty() && proj.repo_paths.len() == 1 {
            Some(PathBuf::from(&proj.repo_paths[0]))
        } else {
            None
        }
    });

    let req = envlink::LinkRequest {
        project_id: proj.id.clone(),
        project_name: proj.name.clone(),
        route_prefix: route.to_string(),
        project_dir,
        files: env_files,
        var_override: var,
    };
    let plan = envlink::plan_link(vault.connection(), &req)?;

    println!(
        "link plan: project '{}' → route '{}' (provider {})",
        render::sanitize(&plan.project_name),
        render::sanitize(&plan.route_prefix),
        render::sanitize(&plan.provider_id)
    );
    println!("base URL: {}", plan.base_url);
    println!();
    for warning in &plan.warnings {
        println!("WARNING: {}", render::sanitize(&format!("{warning:?}")));
    }
    let mut any_change = false;
    for file in &plan.files {
        if file.changed {
            any_change = true;
            println!();
            // Sanitize PER LINE: `render::sanitize` maps every control
            // character to a space, and '\n' is one — so sanitizing the whole
            // diff printed it as a single unreadable line, defeating the
            // consent property the preview exists for. Per-line keeps the
            // CR/ESC stripping that motivated the call.
            for line in file.diff.lines() {
                println!("{}", render::sanitize(line));
            }
        } else {
            println!(
                "{}: already linked (no change)",
                render::sanitize(&file.path)
            );
        }
    }
    // `--dry-run` writes NOTHING, including in the no-change case. The
    // no-change branch below is idempotent-by-design and still a DB write, an
    // audit row, and a nudge to the running gateway — all of which a dry run
    // promised not to do.
    if dry_run {
        if !any_change {
            println!("(dry run — files are already in the linked state; nothing to write)");
        } else {
            println!("(dry run — nothing written; run again without --dry-run to apply)");
        }
        return Ok(());
    }
    if !any_change {
        // Idempotent: make sure the DB row exists even when files are
        // already in the desired state.
        envlink::apply_link(vault.connection(), &req, &plan)?;
        ctx.persist_session(&vault, &token)?;
        // A running gateway must see the (possibly new) link slug NOW, not
        // after the 5s poll — otherwise the just-linked SDK gets a 404.
        nudge_running_gateway(ctx);
        println!("link is up to date");
        return Ok(());
    }
    if dry_run {
        println!();
        println!("(dry run — nothing written; run again without --dry-run to apply)");
        return Ok(());
    }
    println!();
    if !crate::ctx::confirm("Apply these .env changes?", yes)? {
        bail!("cancelled");
    }
    envlink::apply_link(vault.connection(), &req, &plan)?;
    ctx.persist_session(&vault, &token)?;
    // Push the new link slug into the running gateway's snapshot before the
    // probe below runs — the slug must resolve immediately.
    nudge_running_gateway(ctx);
    println!("linked. The gateway line(s) above are exactly what was written.");

    probe_after_link(ctx, &plan);
    Ok(())
}

/// The link-time keyless probe (D9/GW-13): one credential-free GET through
/// the gateway. A provider 401/403 PROVES the path end to end; a gateway
/// 404/503 or connection failure is reported honestly instead.
fn probe_after_link(ctx: &Ctx, plan: &envlink::LinkPlan) {
    use std::io::{Read, Write};
    let data_dir = &ctx.paths.data_dir;
    match control::verify_listener(data_dir, plan.port) {
        control::ListenerIdentity::Verified { .. } => {}
        control::ListenerIdentity::NoListener => {
            println!();
            println!("note: the gateway is not running, so the link was not probed.");
            println!("      Start it (`tethra gateway start` or `serve`) — until then the");
            println!(
                "      project's SDK will get connection refused on 127.0.0.1:{}.",
                plan.port
            );
            return;
        }
        other => {
            println!();
            println!(
                "WARNING: port {} did not verify as this vault's gateway ({other:?});",
                plan.port
            );
            println!("         skipping the probe. Run `tethra gateway doctor`.");
            return;
        }
    }
    let probe_path = if plan.base_url.ends_with("/v1") {
        format!("{}/models", plan.base_url)
    } else {
        format!("{}/v1/models", plan.base_url)
    };
    let path_only = probe_path
        .strip_prefix(&format!("http://127.0.0.1:{}", plan.port))
        .unwrap_or("/")
        .to_string();
    let result = (|| -> std::io::Result<String> {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", plan.port))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
        let req = format!(
            "GET {path_only} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            plan.port
        );
        stream.write_all(req.as_bytes())?;
        let mut buf = String::new();
        let mut limited = std::io::Read::take(&mut stream, 4096);
        let _ = limited.read_to_string(&mut buf);
        Ok(buf)
    })();
    println!();
    match result {
        Ok(response) => {
            let status = response
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("");
            let from_gateway = response.contains("tethra-gateway:");
            match (status, from_gateway) {
                ("401" | "403", _) => println!(
                    "probe: the provider answered {status} to a keyless request — the \
                     route works end to end. Requests with your key will flow."
                ),
                (_, false) if !status.is_empty() => println!(
                    "probe: the provider answered {status}; the path through the gateway \
                     works."
                ),
                (_, true) => println!(
                    "probe WARNING: the gateway itself answered {status} — the route did \
                     not forward. Run `tethra gateway doctor`."
                ),
                _ => println!("probe: no readable answer; run `tethra gateway doctor`."),
            }
        }
        Err(e) => println!("probe: could not reach the gateway ({e})"),
    }
    println!();
    println!("Note: until the project actually sends traffic, gateway activity for it");
    println!("will honestly read 'no traffic since link'. Only traffic whose base URL");
    println!("points at the gateway is ever seen.");
}

fn unlink(ctx: &Ctx, project: &str, route: &str, yes: bool) -> Result<()> {
    let (vault, token) = ctx.unlocked()?;
    let proj = vault.get_project(project)?;
    let link = routes::find_project_link(vault.connection(), &proj.id, route)?;
    let Some(link_row) = link else {
        bail!("no link between '{project}' and '{route}'");
    };
    if link_row.prior_env_json.is_some() {
        println!("Unlink restores the recorded pre-link .env state:");
        println!("  values that existed before come back;");
        println!("  lines Tethra created are removed;");
        println!("  anything you edited after linking is left alone and reported.");
    }
    if !crate::ctx::confirm("Unlink and restore?", yes)? {
        bail!("cancelled");
    }
    if link_row.prior_env_json.is_some() {
        let report = envlink::unlink(vault.connection(), &proj.id, route)?;
        for outcome in &report.outcomes {
            println!("  {}", render::sanitize(&format!("{outcome:?}")));
        }
        if !report.complete {
            ctx.persist_session(&vault, &token)?;
            bail!(
                "some files could not be restored; the link was KEPT so you can retry. \
                 Fix the reported problem and run unlink again."
            );
        }
    } else {
        routes::remove_project_link(vault.connection(), &proj.id, route)?;
    }
    ctx.persist_session(&vault, &token)?;
    // Drop the removed link slug from a running gateway's snapshot now.
    nudge_running_gateway(ctx);
    println!("unlinked project '{project}' from route '{route}'");
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests for the report/ownership formatting.
//
// These live here rather than in `tests/gateway_cli.rs` because the only way
// to make the lifecycle engine EMIT an install/disable report through the CLI
// is to install a real OS service, which no test may do. The report values
// are therefore built directly and the rendering asserted, so a note the
// engine records can never again be silently dropped on the way to the user.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn status_with_definition(data_dir: &str) -> lifecycle::ServiceStatus {
        lifecycle::ServiceStatus {
            installed: true,
            matches_data_dir: false,
            service_name: "dev.api-tracker.gateway.deadbeef1234".into(),
            installation_id: "deadbeef1234".into(),
            definition: Some(lifecycle::Definition {
                binary: PathBuf::from("/other/bin/tethra-gateway-0.1.0"),
                data_dir: PathBuf::from(data_dir),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn foreign_owner_names_the_other_data_directory() {
        let s = status_with_definition("/Users/someone/Library/Application Support/OtherTethra");
        assert_eq!(
            foreign_owner(&s).as_deref(),
            Some("/Users/someone/Library/Application Support/OtherTethra"),
            "a slot pointing elsewhere must be reported with the directory that owns it"
        );
    }

    #[test]
    fn foreign_owner_passes_our_own_and_absent_installations() {
        let mut ours = status_with_definition("/ours");
        ours.matches_data_dir = true;
        assert_eq!(
            foreign_owner(&ours),
            None,
            "our own installation must not be refused"
        );

        let mut absent = status_with_definition("/other");
        absent.installed = false;
        assert_eq!(
            foreign_owner(&absent),
            None,
            "no installation at all is not a foreign installation"
        );
    }

    #[test]
    fn install_report_lines_surface_notes_pruned_binaries_and_a_failed_start() {
        let report = lifecycle::InstallReport {
            binary: "/data/bin/tethra-gateway-0.1.0".into(),
            definition: "/home/u/Library/LaunchAgents/x.plist".into(),
            started: false,
            pruned_binaries: vec!["/data/bin/tethra-gateway-0.0.9".into()],
            notes: vec!["replaced a service that pointed at /other/data".into()],
        };
        let lines = install_report_lines(&report);
        assert!(
            lines
                .iter()
                .any(|l| l == "note: replaced a service that pointed at /other/data"),
            "the takeover note must reach the user: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("removed older helper binary /data/bin/tethra-gateway-0.0.9")),
            "pruned binaries must be reported: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("did not report a successful start")),
            "a service that was installed but not started must say so: {lines:?}"
        );
    }

    #[test]
    fn install_report_lines_stay_quiet_on_a_clean_start() {
        let report = lifecycle::InstallReport {
            binary: "/data/bin/tethra-gateway-0.1.0".into(),
            definition: "/home/u/Library/LaunchAgents/x.plist".into(),
            started: true,
            pruned_binaries: Vec::new(),
            notes: Vec::new(),
        };
        assert!(
            install_report_lines(&report).is_empty(),
            "a clean install must not invent warnings"
        );
    }

    #[test]
    fn install_report_notes_are_stripped_of_control_characters() {
        // Notes interpolate paths read off disk, so a crafted definition
        // must not be able to smuggle an escape sequence into the terminal.
        let report = lifecycle::InstallReport {
            binary: String::new(),
            definition: String::new(),
            started: true,
            pruned_binaries: vec!["/tmp/a\u{1b}[2Kb".into()],
            notes: vec!["replaced /tmp/x\u{1b}[31my".into()],
        };
        for line in install_report_lines(&report) {
            assert!(
                !line.contains('\u{1b}'),
                "escape sequences must be stripped: {line:?}"
            );
        }
    }

    #[test]
    fn disable_report_lines_surface_the_reason_a_teardown_did_not_happen() {
        let report = lifecycle::DisableReport {
            stopped: false,
            unregistered: false,
            env_restores: Vec::new(),
            incomplete_restores: 0,
            notes: vec!["stop: refusing to stop the service: the service \
                 dev.api-tracker.gateway.abc belongs to a different Tethra data directory \
                 (/other/data), not this one (/ours)."
                .into()],
        };
        let lines = disable_report_lines(&report);
        assert!(
            lines.iter().any(|l| l.contains("service stopped: false")),
            "the bare outcome is still reported: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("different Tethra data directory") && l.contains("/other/data")),
            "a false 'stopped' without its reason is unactionable: {lines:?}"
        );
    }
}
