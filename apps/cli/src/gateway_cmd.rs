//! `tethra gateway ...` — the Local Gateway command family.
//!
//! This session ships the CORE surfaces only: foreground operation, route
//! and link management, status, and the authenticated key handoff. Service
//! installation (`enable`/`disable`) and the desktop panels are deliberately
//! out of scope here (IMPLEMENTATION_PLAN Stages 5–6) and say so honestly
//! rather than pretending.

use anyhow::{bail, Context, Result};
use api_tracker_gateway::{control, routes, service::Service, store};
use clap::Subcommand;

use crate::ctx::Ctx;
use crate::render;

#[derive(Subcommand)]
pub enum GatewayCmd {
    /// Run the gateway in the foreground until interrupted.
    ///
    /// This is the supported way to run the gateway in this build: OS
    /// service installation is not implemented yet.
    Serve {
        /// Bind port. Defaults to the persisted port, or a random high port
        /// chosen on first run.
        #[arg(long)]
        port: Option<u16>,
        /// Push the credential-matching key at startup so attribution works
        /// (requires an unlocked vault). Without it, attribution honestly
        /// reports `unavailable_vault_locked`.
        #[arg(long)]
        with_attribution: bool,
    },
    /// Show what the gateway is doing. Works without unlocking the vault.
    Status,
    /// Manage provider routes.
    #[command(subcommand)]
    Route(RouteCmd),
    /// Link a project to a route (scopes traffic to that project).
    Link {
        #[arg(long)]
        project: String,
        #[arg(long)]
        route: String,
    },
    /// Remove a project link.
    Unlink {
        #[arg(long)]
        project: String,
        #[arg(long)]
        route: String,
    },
    /// Push the credential-matching key to a running gateway.
    PushKey,
    /// Drop the matching key from a running gateway immediately.
    RevokeKey,
    /// Ask a running gateway to stop.
    Stop,
    /// Reload the route table in a running gateway.
    Reload,
    /// Pause or resume observation recording (forwarding is unaffected).
    Recording {
        #[arg(value_parser = ["pause", "resume"])]
        state: String,
    },
    /// Report what is NOT implemented yet, honestly.
    Enable,
}

#[derive(Subcommand)]
pub enum RouteCmd {
    /// List registered routes.
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
    /// Enable or disable a route without removing it.
    Set {
        prefix: String,
        #[arg(value_parser = ["enabled", "disabled"])]
        state: String,
    },
}

pub fn run(ctx: &Ctx, cmd: GatewayCmd) -> Result<()> {
    match cmd {
        GatewayCmd::Serve {
            port,
            with_attribution,
        } => serve(ctx, port, with_attribution),
        GatewayCmd::Status => status(ctx),
        GatewayCmd::Route(cmd) => route(ctx, cmd),
        GatewayCmd::Link { project, route } => link(ctx, &project, &route),
        GatewayCmd::Unlink { project, route } => unlink(ctx, &project, &route),
        GatewayCmd::PushKey => push_key(ctx),
        GatewayCmd::RevokeKey => simple(ctx, |nonce| control::Request::RevokeKey { nonce }),
        GatewayCmd::Stop => simple(ctx, |nonce| control::Request::Shutdown { nonce }),
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
        GatewayCmd::Enable => {
            bail!(
                "installing the gateway as an OS service is not implemented in this build. \
                 Run it in the foreground with `tethra gateway serve`; see \
                 docs/gateway/HANDOFF_PHASE_2.md for what remains."
            )
        }
    }
}

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

fn status(ctx: &Ctx) -> Result<()> {
    let data_dir = &ctx.paths.data_dir;
    if !control::instance_is_live(data_dir) {
        if ctx.json {
            println!("{}", serde_json::json!({ "running": false }));
        } else {
            println!("gateway: not running");
            println!("  start it with: tethra gateway serve");
        }
        return Ok(());
    }
    let nonce = control::read_nonce(data_dir).context("reading the gateway control nonce")?;
    let status = match control::send(
        data_dir,
        &control::Request::Status {
            nonce: nonce.to_string(),
        },
    )? {
        control::Response::Status(s) => *s,
        control::Response::Error { code, message } => bail!("{code}: {message}"),
        other => bail!("unexpected control response: {other:?}"),
    };
    render::emit(ctx.json, &status, || {
        println!("gateway: running (v{})", status.version);
        println!("  listening   http://127.0.0.1:{}", status.port);
        println!("  uptime      {}s", status.uptime_secs);
        println!(
            "  routes      {} ({} unavailable)",
            status.routes, status.routes_unavailable
        );
        println!("  in flight   {}", status.connections_in_flight);
        println!(
            "  recording   {}",
            if status.recording_paused {
                "paused"
            } else if status.recording_degraded {
                "DEGRADED"
            } else {
                "on"
            }
        );
        println!(
            "  attribution {}",
            if status.matching_key_present {
                "on (matching key resident)"
            } else {
                "unavailable (no matching key; vault locked or not pushed)"
            }
        );
        println!(
            "  events      {} written, {} dropped, {} persist failures",
            status.written_events, status.dropped_events, status.persist_failures
        );
        if let Some(at) = &status.last_observation_at {
            println!("  last event  {at}");
        } else {
            println!("  last event  none yet (absence of traffic is not proof of absence)");
        }
        if status.routes_degraded {
            println!("  NOTE: route configuration could not be re-read; forwarding continues");
            println!("        on the last-known-good table.");
        }
        if let Some(err) = &status.last_error {
            println!("  last error  {err}");
        }
    });
    Ok(())
}

fn route(ctx: &Ctx, cmd: RouteCmd) -> Result<()> {
    match cmd {
        RouteCmd::List => {
            let conn = api_tracker_core::db::open(&ctx.paths.db_path())?;
            let table = routes::load_route_table(&conn, None)?;
            let rows: Vec<Vec<String>> = table
                .iter_routes()
                .map(|r| {
                    vec![
                        r.prefix.clone(),
                        r.provider_id.clone(),
                        match &r.target {
                            routes::RouteTarget::Ready(o) => o.host.clone(),
                            routes::RouteTarget::Unforwardable(why) => {
                                format!("unavailable ({why:?})")
                            }
                        },
                        if r.custom { "custom" } else { "manifest" }.to_string(),
                    ]
                })
                .collect();
            if rows.is_empty() {
                println!("no routes registered");
                println!("  add one with: tethra gateway route add openai");
            } else {
                render::table(&["PREFIX", "PROVIDER", "ORIGIN", "SOURCE"], &rows);
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
            Ok(())
        }
        RouteCmd::Remove { prefix } => {
            let (vault, token) = ctx.unlocked()?;
            let removed = routes::remove_route(vault.connection(), &prefix)?;
            ctx.persist_session(&vault, &token)?;
            if removed {
                println!("route '{prefix}' removed");
            } else {
                println!("no route '{prefix}'");
            }
            Ok(())
        }
        RouteCmd::Set { prefix, state } => {
            let (vault, token) = ctx.unlocked()?;
            let enabled = state == "enabled";
            let changed = routes::set_route_enabled(vault.connection(), &prefix, enabled)?;
            ctx.persist_session(&vault, &token)?;
            if changed {
                println!("route '{prefix}' is now {state}");
            } else {
                println!("no route '{prefix}'");
            }
            Ok(())
        }
    }
}

fn link(ctx: &Ctx, project: &str, route: &str) -> Result<()> {
    let (vault, token) = ctx.unlocked()?;
    let project_id = vault.get_project(project)?.id;
    let slug = routes::add_project_link(vault.connection(), &project_id, route)?;
    ctx.persist_session(&vault, &token)?;
    println!("linked project '{project}' to route '{route}'");
    println!();
    println!("Point the project's SDK at the gateway by setting, in its .env:");
    if let Some(manifest) = api_tracker_core::providers::find(route) {
        if let Some(gw) = &manifest.gateway {
            for var in &gw.env_vars {
                println!(
                    "  {var}=http://127.0.0.1:<port>/p/{slug}/{route}{}",
                    gw.base_path
                );
            }
        }
    } else {
        println!("  <PROVIDER>_BASE_URL=http://127.0.0.1:<port>/p/{slug}/{route}");
    }
    println!("  NO_PROXY=127.0.0.1,localhost,::1");
    println!();
    println!("(Automatic .env rewriting is not implemented in this build — see");
    println!(" docs/gateway/HANDOFF_PHASE_2.md. The gateway sees only traffic whose");
    println!(" base URL is repointed at it.)");
    Ok(())
}

fn unlink(ctx: &Ctx, project: &str, route: &str) -> Result<()> {
    let (vault, token) = ctx.unlocked()?;
    let project_id = vault.get_project(project)?.id;
    let removed = routes::remove_project_link(vault.connection(), &project_id, route)?;
    ctx.persist_session(&vault, &token)?;
    if removed {
        println!("unlinked project '{project}' from route '{route}'");
        println!("Remember to remove the base-URL line from the project's .env.");
    } else {
        println!("no link between '{project}' and '{route}'");
    }
    Ok(())
}
