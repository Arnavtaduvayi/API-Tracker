//! `mesh` subcommands: Tethra Mesh, peer-to-peer replication between your own
//! paired devices (ADR 0031): identity, pairing, devices, removal, leave, the
//! node (`serve`, `stop`, `replicate`, `peer`), and `status`/`doctor`
//! (`api-tracker-mesh`).
//!
//! Nothing printed here carries key material: not the private keys, not the
//! access key, not even public keys. Identifiers are random and not secret.
//! The one secret ever printed is an invite, once, by `mesh invite`.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Context, Result};
use api_tracker_core::mesh::clock::{Clock, SystemClock};
use api_tracker_core::mesh::doctor::Severity;
use api_tracker_core::mesh::identity::{MeshStatus, MeshStatusDetail};
use api_tracker_core::mesh::invite::format_invite;
use api_tracker_core::mesh::marker::MarkerStatus;
use api_tracker_core::mesh::peers::{self, DeviceChange, PeerLag, PeerRow};
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::mesh::{DeviceId, MeshId};
use api_tracker_mesh::discover::MdnsDiscovery;
use api_tracker_mesh::instance::{self, ExchangeSummary, NodeStatus, Response};
use api_tracker_mesh::replicate::replicate_once;
use api_tracker_mesh::runtime::{
    AnyOf, Deadline, NodeConfig, RunningNode, SessionAlive, StopCondition,
};
use api_tracker_mesh::serve::{bind_all, serve};
use api_tracker_mesh::{MeshNode, TransportLimits};
use clap::Subcommand;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// The shortest round interval `serve --interval` accepts. Each round dials
/// every peer once, and a node answers at most 10 handshakes a minute per
/// source address (DESIGN §D12).
const MIN_INTERVAL_SECS: u64 = 5;

#[derive(Subcommand)]
pub enum MeshCmd {
    /// Start a new mesh with this device as its only member.
    Init {
        /// The name other devices will see for this one (default: this
        /// machine's host name). It replicates to every paired device.
        #[arg(long)]
        name: Option<String>,
    },
    /// Show this device's mesh identity, roster and replication counters.
    Status,
    /// Create a one-time invite for another device (requires
    /// reauthentication). The invite is a password for its lifetime.
    Invite {
        /// Address(es) of this device the new device should dial
        /// (host:port; repeatable). With --wait, the addresses it listens on.
        #[arg(long = "addr", value_name = "HOST:PORT")]
        addrs: Vec<String>,
        /// Minutes the invite stays valid (default 10, at most 60).
        #[arg(long)]
        ttl: Option<u32>,
        /// Serve on --listen until the invite is used or expires.
        #[arg(long)]
        wait: bool,
        /// Where to listen with --wait (repeatable).
        #[arg(long, value_name = "ADDR:PORT")]
        listen: Vec<SocketAddr>,
    },
    /// Join a mesh with an invite from one of its devices (`-` reads it
    /// from standard input, so it stays out of your shell history).
    Join {
        invite: String,
        /// The name other devices will see for this one.
        #[arg(long)]
        name: Option<String>,
    },
    /// List the devices of this mesh.
    Devices,
    /// Rename this device (a device can only rename itself).
    Rename { name: String },
    /// Remove another device from the mesh and rotate the mesh access key
    /// (requires confirmation and reauthentication).
    Remove {
        /// The device id, or at least its first 8 characters.
        device: String,
        /// Skip the interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Leave the mesh: tell a peer if one is reachable, then delete this
    /// device's mesh identity and data (confirmation and reauthentication).
    Leave {
        /// A peer to deliver the departure to (repeatable).
        #[arg(long, value_name = "HOST:PORT")]
        peer: Vec<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Run this device's mesh node in the foreground: accept connections
    /// from paired devices and, every interval, exchange with each known
    /// peer. It stops when the vault session locks or expires, on `tethra
    /// mesh stop`, or on Ctrl-C. Nothing listens unless you give --listen.
    Serve {
        /// Address to listen on (repeatable); port 0 picks a free port.
        #[arg(long, required = true, value_name = "ADDR:PORT")]
        listen: Vec<SocketAddr>,
        /// Allow 0.0.0.0 or [::] (every network interface).
        #[arg(long)]
        all_interfaces: bool,
        /// Announce and find this mesh's devices on the local network
        /// (mDNS). Off unless given.
        #[arg(long)]
        discover: bool,
        /// The address other devices should dial (repeatable), when it is
        /// not the --listen address: a VPN name, say. Published to your
        /// devices only.
        #[arg(long, value_name = "HOST:PORT")]
        advertise: Vec<String>,
        /// Seconds between rounds (default 30, at least 5).
        #[arg(long, value_name = "SECONDS")]
        interval: Option<u64>,
        /// Stop after this many minutes. A vault session already stops the
        /// node when it locks; with TETHRA_PASSWORD it otherwise runs until
        /// stopped.
        #[arg(long, value_name = "MINUTES")]
        max_runtime: Option<u64>,
    },
    /// Stop the mesh node running for this data directory.
    Stop,
    /// Exchange with paired devices now: through the running node if there
    /// is one, otherwise directly from this command.
    Replicate {
        /// Only this address (default: every known peer).
        #[arg(long, value_name = "HOST:PORT")]
        peer: Option<String>,
    },
    /// The addresses this device's node dials.
    #[command(subcommand)]
    Peer(PeerCmd),
    /// Share local projects with your devices and bind them.
    #[command(subcommand)]
    Project(ProjectCmd),
    /// Gateway-observed usage across your devices, labelled per device.
    Usage {
        /// One mesh project (id, id prefix or name).
        #[arg(long)]
        project: Option<String>,
        /// A UTC month, YYYY-MM (default: this month).
        #[arg(long)]
        month: Option<String>,
        /// One UTC day, YYYY-MM-DD.
        #[arg(long)]
        day: Option<String>,
        /// Per-device rows only, without the labelled cross-device total.
        #[arg(long)]
        by_device: bool,
    },
    /// Mesh-wide settings (replicated to every device).
    #[command(subcommand)]
    Settings(SettingsCmd),
    /// Monthly spend caps on mesh projects, kept across your devices
    /// (alerts only in this version).
    #[command(subcommand)]
    Cap(crate::mesh_cap_cmd::CapCmd),
    /// Check this device's mesh: identity, keys, stored items, the node,
    /// its listeners and peers. Every finding comes with a fix.
    Doctor {
        /// Rewrite the item store's index columns from the item bytes and
        /// remove rows that are unreadable or unsigned (a peer returns them
        /// at the next exchange).
        #[arg(long)]
        rebuild: bool,
        /// Run a repair round now: one exchange with every peer, comparing
        /// what each side holds.
        #[arg(long)]
        repair: bool,
    },
}

#[derive(Subcommand)]
pub enum ProjectCmd {
    /// Share a local project: a new mesh project, bound to it here.
    Share {
        local: String,
    },
    /// Bind a local project to a mesh project another device shared.
    Bind {
        mesh: String,
        local: String,
    },
    /// Stop publishing a local project's usage (what was published stays).
    Unbind {
        local: String,
    },
    Rename {
        mesh: String,
        name: String,
    },
    Archive {
        mesh: String,
    },
    /// Merge two mesh projects that are the same real project.
    Merge {
        a: String,
        b: String,
    },
    List,
}

#[derive(Subcommand)]
pub enum SettingsCmd {
    List,
    Get { name: String },
    Set { name: String, value: String },
}

#[derive(Subcommand)]
pub enum PeerCmd {
    /// Add an address to dial: another device's listen address
    /// (`HOST:PORT`; an IP address, or a LAN or VPN host name).
    Add { addr: String },
    /// List the addresses, where each came from, and how dialling went.
    List,
    /// Forget an address. One that a device still publishes, or mDNS still
    /// finds, comes back at the next round.
    Remove { addr: String },
}

/// What `mesh init` reports. Deliberately no key, public or private.
#[derive(Serialize)]
struct InitReport {
    mesh_id: MeshId,
    device_id: DeviceId,
    device_name: String,
    access_key_epoch: u32,
    created_at: String,
}

pub fn run(ctx: &Ctx, cmd: MeshCmd) -> Result<()> {
    match cmd {
        MeshCmd::Init { name } => {
            let (vault, _token) = ctx.unlocked()?;
            let name = name.unwrap_or_else(default_device_name);
            let info = vault.mesh_init(&name)?;
            let report = InitReport {
                mesh_id: info.mesh_id,
                device_id: info.device_id,
                device_name: info.device_name,
                access_key_epoch: info.access_key_epoch,
                created_at: info.created_at,
            };
            render::emit(ctx.json, &report, || {
                println!("Started a new mesh with this device as its only member.");
                println!("  Mesh:    {}", short(&report.mesh_id.to_hex()));
                println!(
                    "  Device:  {} ({})",
                    render::sanitize(&report.device_name),
                    short(&report.device_id.to_hex())
                );
                println!(
                    "The device name is shown to every device you pair. Its keys are \
                     encrypted in this vault and never leave it."
                );
                println!(
                    "Pair another device with `tethra mesh invite`, then run a node with \
                     `tethra mesh serve`."
                );
            });
        }
        MeshCmd::Status => status(ctx)?,
        MeshCmd::Invite {
            addrs,
            ttl,
            wait,
            listen,
        } => invite(ctx, addrs, ttl, wait, listen)?,
        MeshCmd::Join { invite, name } => join(ctx, &invite, name)?,
        MeshCmd::Devices => {
            let (vault, _token) = ctx.unlocked()?;
            let devices = vault.mesh_devices()?;
            render::emit(ctx.json, &devices, || {
                let rows: Vec<Vec<String>> = devices
                    .iter()
                    .map(|d| {
                        let mut state = if d.removed {
                            "removed"
                        } else if d.fork_seq.is_some() {
                            "forked"
                        } else if d.active {
                            "active"
                        } else {
                            "not admitted"
                        }
                        .to_owned();
                        if d.is_self {
                            state.push_str(" (this device)");
                        }
                        vec![
                            render::sanitize(d.name.as_deref().unwrap_or("-")),
                            d.short_id.clone(),
                            state,
                            d.added_by
                                .map_or("-".into(), |a| short(&a.to_hex()).to_owned()),
                            d.last_exchange.clone().unwrap_or_else(|| "-".into()),
                        ]
                    })
                    .collect();
                render::table(
                    &["NAME", "DEVICE", "STATE", "ADDED BY", "LAST EXCHANGE"],
                    &rows,
                );
            });
        }
        MeshCmd::Rename { name } => {
            let (vault, _token) = ctx.unlocked()?;
            vault.mesh_device_rename(&name)?;
            let out = serde_json::json!({ "renamed": true, "name": name.trim() });
            render::emit(ctx.json, &out, || {
                println!(
                    "Renamed this device to {}. Other devices see it after their next exchange.",
                    render::sanitize(name.trim())
                );
            });
        }
        MeshCmd::Remove { device, yes } => {
            let (vault, _token) = ctx.unlocked()?;
            if !ctx::confirm(
                "Remove this device from the mesh? This device refuses it at once and the \
                 others as they hear of it; its records up to now stay. It cannot rejoin \
                 under the same identity.",
                yes,
            )? {
                bail!("aborted");
            }
            eprintln!("Reauthentication required to remove a device.");
            let master = ctx::master_password()?;
            let (removed, epoch) = vault.mesh_device_remove(&master, &device)?;
            let out = serde_json::json!({ "removed": removed, "access_key_epoch": epoch });
            render::emit(ctx.json, &out, || {
                println!("Removed device {}.", short(&removed.to_hex()));
                println!(
                    "The mesh access key rotated to epoch {epoch}; the other devices receive \
                     it in their next exchanges."
                );
            });
        }
        MeshCmd::Leave { peer, yes } => leave(ctx, peer, yes)?,
        MeshCmd::Serve {
            listen,
            all_interfaces,
            discover,
            advertise,
            interval,
            max_runtime,
        } => serve_node(
            ctx,
            ServeArgs {
                listen,
                all_interfaces,
                discover,
                advertise,
                interval,
                max_runtime,
            },
        )?,
        MeshCmd::Stop => stop_node(ctx)?,
        MeshCmd::Replicate { peer } => replicate(ctx, peer)?,
        MeshCmd::Peer(cmd) => peer_cmd(ctx, cmd)?,
        MeshCmd::Project(cmd) => project_cmd(ctx, cmd)?,
        MeshCmd::Usage {
            project,
            month,
            day,
            by_device,
        } => usage(ctx, project, month, day, by_device)?,
        MeshCmd::Settings(cmd) => settings_cmd(ctx, cmd)?,
        MeshCmd::Cap(cmd) => crate::mesh_cap_cmd::run(ctx, cmd)?,
        MeshCmd::Doctor { rebuild, repair } => doctor(ctx, rebuild, repair)?,
    }
    Ok(())
}

/// A line for the operator on stderr. A closed stderr is ignored: the node
/// keeps running (stdout and stderr may belong to a script that went away).
fn note(msg: &str) {
    let _ = writeln!(std::io::stderr(), "{msg}");
}

struct ServeArgs {
    listen: Vec<SocketAddr>,
    all_interfaces: bool,
    discover: bool,
    advertise: Vec<String>,
    interval: Option<u64>,
    max_runtime: Option<u64>,
}

/// The round interval: `--interval` (at least 5 s), or in debug builds only
/// `TETHRA_MESH_INTERVAL_MS` for tests.
fn round_interval(interval: Option<u64>) -> Result<Duration> {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var("TETHRA_MESH_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Ok(Duration::from_millis(ms.max(50)));
    }
    match interval {
        None => Ok(Duration::from_secs(30)),
        Some(s) if s < MIN_INTERVAL_SECS => {
            bail!("--interval must be at least {MIN_INTERVAL_SECS} seconds")
        }
        Some(s) => Ok(Duration::from_secs(s)),
    }
}

fn serve_node(ctx: &Ctx, args: ServeArgs) -> Result<()> {
    let interval = round_interval(args.interval)?;
    let (vault, token) = ctx.unlocked()?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let node = MeshNode::open(&vault, clock.clone(), TransportLimits::default())?;
    // The node holds the keys it needs (MESH-SI-7); nothing else here keeps
    // the vault open while it runs.
    drop(vault);
    let mut stops: Vec<Box<dyn StopCondition>> = Vec::new();
    if token.is_some() {
        stops.push(Box::new(SessionAlive::new(&ctx.paths.session_path())));
    }
    if let Some(m) = args.max_runtime {
        stops.push(Box::new(Deadline::after(
            clock.clone(),
            Duration::from_secs(m.saturating_mul(60)),
        )));
    }
    let mut cfg = NodeConfig::new(args.listen);
    cfg.all_interfaces = args.all_interfaces;
    cfg.advertise = args.advertise;
    cfg.interval = interval;
    if args.discover {
        cfg.discovery = Some(Arc::new(MdnsDiscovery::new()?));
    }
    cfg.log = Some(Arc::new(|m: &str| note(&format!("mesh: {m}"))));
    cfg.hooks = api_tracker_mesh::hooks::default_hooks();
    let running = RunningNode::start(node, &ctx.paths.data_dir, cfg, Box::new(AnyOf(stops)))?;
    for a in running.listen_addrs() {
        // Tests and scripts read the bound port from this line.
        println!("Listening on {a}");
    }
    std::io::stdout().flush()?;
    let st = running.status();
    note(&format!(
        "Mesh node running (pid {}): a round every {} s{}{}.",
        st.pid,
        interval.as_secs_f64(),
        if st.advertised.is_empty() {
            String::new()
        } else {
            format!("; publishing {}", st.advertised.join(", "))
        },
        if args.discover {
            "; mDNS discovery on"
        } else {
            ""
        }
    ));
    note(if token.is_some() {
        "It stops when this vault session locks or expires, on `tethra mesh stop`, or Ctrl-C."
    } else {
        "It stops on `tethra mesh stop`, Ctrl-C, or --max-runtime."
    });
    let report = running.wait();
    note(&format!(
        "Mesh node stopped: {}{}.",
        report.reason.describe(),
        if report.keys_dropped {
            "; its keys were dropped"
        } else {
            ""
        }
    ));
    Ok(())
}

fn stop_node(ctx: &Ctx) -> Result<()> {
    let dir = &ctx.paths.data_dir;
    let pid = instance::running_pid(dir);
    let stopped = match pid {
        Some(_) => instance::stop(dir)?,
        None => false,
    };
    if stopped {
        // The node finishes the exchanges it is in, then releases the data
        // directory.
        for _ in 0..200 {
            if instance::running_pid(dir).is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let out = serde_json::json!({ "stopped": stopped, "pid": pid });
    render::emit(ctx.json, &out, || match pid {
        Some(p) if stopped => println!("Stopped the mesh node (pid {p})."),
        _ => println!("No mesh node is running for this data directory."),
    });
    Ok(())
}

#[derive(Serialize)]
struct ReplicateOut {
    via_node: bool,
    exchanges: Vec<ExchangeSummary>,
}

fn replicate(ctx: &Ctx, peer: Option<String>) -> Result<()> {
    let dir = &ctx.paths.data_dir;
    let out = if instance::running_pid(dir).is_some() {
        match instance::request(
            dir,
            |nonce| instance::Request::ReplicateNow {
                nonce,
                peer: peer.clone(),
                repair: false,
            },
            instance::REPLICATE_WAIT,
        )? {
            Response::Replicated { exchanges, .. } => ReplicateOut {
                via_node: true,
                exchanges,
            },
            Response::Error { message, .. } => bail!("the mesh node refused: {message}"),
            _ => bail!("the mesh node gave an unexpected answer"),
        }
    } else {
        let (vault, _token) = ctx.unlocked()?;
        // Publish fresh usage and spend-cap figures first, so this exchange
        // carries them.
        if let Err(e) = vault.mesh_publish() {
            note(&format!("mesh: usage was not published: {e}"));
        }
        let probe = api_tracker_mesh::node::GatewaySocket(dir.clone());
        if let Err(e) = vault.mesh_cap_reconcile(&probe) {
            note(&format!("mesh: spend caps were not reconciled: {e}"));
        }
        let addrs = match &peer {
            Some(p) => vec![p.clone()],
            None => vault.mesh_peers()?.into_iter().map(|r| r.addr).collect(),
        };
        if addrs.is_empty() {
            bail!(
                "no peer is known: give --peer HOST:PORT, or add one with `tethra mesh peer add`"
            );
        }
        let node = MeshNode::open(&vault, Arc::new(SystemClock), TransportLimits::default())?;
        let exchanges = addrs
            .into_iter()
            .map(|addr| match replicate_once(&node, &addr) {
                Ok(r) => ExchangeSummary {
                    addr,
                    device: Some(r.peer),
                    items_in: r.items_in,
                    items_out: r.items_out,
                    duration_ms: r.duration_ms,
                    error: r.aborted.map(str::to_owned),
                },
                Err(e) => ExchangeSummary {
                    addr,
                    device: None,
                    items_in: 0,
                    items_out: 0,
                    duration_ms: 0,
                    error: Some(e.to_string()),
                },
            })
            .collect();
        ReplicateOut {
            via_node: false,
            exchanges,
        }
    };
    render::emit(ctx.json, &out, || {
        for e in &out.exchanges {
            match (&e.error, e.device) {
                (None, Some(d)) => println!(
                    "Exchanged with {} at {}: {} item(s) in, {} out, {} ms.",
                    short(&d.to_hex()),
                    e.addr,
                    e.items_in,
                    e.items_out,
                    e.duration_ms
                ),
                (Some(why), _) => println!("{}: {}", e.addr, render::sanitize(why)),
                (None, None) => println!("{}: no exchange", e.addr),
            }
        }
        if out.exchanges.is_empty() {
            println!("No peer was due or known.");
        }
    });
    if !out.exchanges.is_empty() && out.exchanges.iter().all(|e| e.error.is_some()) {
        bail!("no exchange completed");
    }
    Ok(())
}

fn project_cmd(ctx: &Ctx, cmd: ProjectCmd) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    match cmd {
        ProjectCmd::Share { local } => {
            let (id, name) = vault.mesh_project_share(&local)?;
            let out = serde_json::json!({ "mesh_project_id": id, "name": name, "bound": true });
            render::emit(ctx.json, &out, || {
                println!(
                    "Shared {} as mesh project {}. On each other device, bind a local \
                     project to it: tethra mesh project bind {} <local-project>",
                    render::sanitize(&name),
                    short(&id.to_hex()),
                    short(&id.to_hex())
                );
            });
        }
        ProjectCmd::Bind { mesh, local } => {
            let id = vault.mesh_project_bind(&mesh, &local)?;
            let out = serde_json::json!({ "mesh_project_id": id, "bound": true });
            render::emit(ctx.json, &out, || {
                println!(
                    "Bound {} to mesh project {}. Its gateway usage is published from the \
                     next run of the node (or `tethra mesh replicate`).",
                    render::sanitize(local.trim()),
                    short(&id.to_hex())
                );
            });
        }
        ProjectCmd::Unbind { local } => {
            let was = vault.mesh_project_unbind(&local)?;
            let out = serde_json::json!({ "unbound": was });
            render::emit(ctx.json, &out, || {
                if was {
                    println!("Unbound. Usage already published stays; nothing new is published.");
                } else {
                    println!("That project was not bound.");
                }
            });
        }
        ProjectCmd::Rename { mesh, name } => {
            let id = vault.mesh_project_rename(&mesh, &name)?;
            let out = serde_json::json!({ "mesh_project_id": id, "name": name.trim() });
            render::emit(ctx.json, &out, || {
                println!("Renamed mesh project {}.", short(&id.to_hex()))
            });
        }
        ProjectCmd::Archive { mesh } => {
            let id = vault.mesh_project_archive(&mesh)?;
            let out = serde_json::json!({ "mesh_project_id": id, "archived": true });
            render::emit(ctx.json, &out, || {
                println!("Archived mesh project {}.", short(&id.to_hex()))
            });
        }
        ProjectCmd::Merge { a, b } => {
            let (root, merged) = vault.mesh_project_merge(&a, &b)?;
            let out = serde_json::json!({ "root": root, "merged": merged });
            render::emit(ctx.json, &out, || {
                println!(
                    "Merged {} into {}: its usage now counts under {}.",
                    short(&merged.to_hex()),
                    short(&root.to_hex()),
                    short(&root.to_hex())
                )
            });
        }
        ProjectCmd::List => {
            let rows = vault.mesh_projects()?;
            render::emit(ctx.json, &rows, || {
                if rows.is_empty() {
                    println!(
                        "No mesh projects. Share one with `tethra mesh project share <local>`."
                    );
                    return;
                }
                let table: Vec<Vec<String>> = rows
                    .iter()
                    .map(|r| {
                        let mut state = Vec::new();
                        if r.archived {
                            state.push("archived".to_owned());
                        }
                        if let Some(m) = r.merged_into {
                            state.push(format!("merged into {}", short(&m.to_hex())));
                        }
                        vec![
                            render::sanitize(&r.name),
                            short(&r.mesh_project_id.to_hex()).to_owned(),
                            r.bound_local_project_name
                                .as_deref()
                                .map_or("-".to_owned(), render::sanitize),
                            r.publishing_devices.len().to_string(),
                            if state.is_empty() {
                                "active".to_owned()
                            } else {
                                state.join(", ")
                            },
                        ]
                    })
                    .collect();
                render::table(
                    &["NAME", "ID", "BOUND HERE TO", "DEVICES PUBLISHING", "STATE"],
                    &table,
                );
            });
        }
    }
    Ok(())
}

fn usd(micros: u64) -> String {
    format!("${}.{:04}", micros / 1_000_000, (micros % 1_000_000) / 100)
}

fn usage(
    ctx: &Ctx,
    project: Option<String>,
    month: Option<String>,
    day: Option<String>,
    by_device: bool,
) -> Result<()> {
    use api_tracker_core::mesh::kinds::{Day, Month};
    use api_tracker_core::mesh::usage::{split_unknown, UsageFilter};
    let (vault, _token) = ctx.unlocked()?;
    if let Err(e) = vault.mesh_publish() {
        note(&format!("mesh: this device's usage was not published: {e}"));
    }
    let mut filter = UsageFilter::default();
    if let Some(d) = day {
        filter.day = Some(Day::parse(d.trim()).context("--day must be YYYY-MM-DD")?);
    }
    if let Some(m) = month {
        filter.month = Some(Month::parse(m.trim()).context("--month must be YYYY-MM")?);
    }
    if let Some(p) = project {
        let store = vault.mesh_open_store()?;
        filter.project = Some(api_tracker_core::mesh::projects::resolve(&store, &p)?);
    }
    let report = vault.mesh_usage(&filter)?;
    render::emit(ctx.json, &report, || {
        println!(
            "Mesh usage for {} — estimated, gateway-observed, per device; never summed with \
             provider-reported cost.",
            report.period
        );
        for n in &report.notes[1..] {
            println!("  {n}");
        }
        if report.projects.is_empty() {
            println!("No shared projects. Share one with `tethra mesh project share <local>`.");
        }
        for p in &report.projects {
            println!();
            println!(
                "{} ({}){}",
                render::sanitize(&p.name),
                short(&p.mesh_project_id.to_hex()),
                if p.archived { ", archived" } else { "" }
            );
            let rows: Vec<Vec<String>> = p
                .devices
                .iter()
                .map(|d| {
                    let mut who = render::sanitize(d.device_name.as_deref().unwrap_or("-"));
                    if d.is_self {
                        who.push_str(" (this device)");
                    }
                    if d.removed {
                        who.push_str(" (removed)");
                    }
                    let as_of = if d.is_self {
                        "current".to_owned()
                    } else {
                        format!(
                            "{}{}",
                            d.as_of.as_deref().unwrap_or("never exchanged directly"),
                            if d.stale { " (stale)" } else { "" }
                        )
                    };
                    let t = &d.totals;
                    vec![
                        who,
                        as_of,
                        t.requests.to_string(),
                        t.priced_requests.to_string(),
                        t.unpriced_requests.to_string(),
                        t.unextracted_requests.to_string(),
                        split_unknown(t).to_string(),
                        t.input_tokens.to_string(),
                        t.output_tokens.to_string(),
                        usd(t.estimated_cost_micros),
                    ]
                })
                .collect();
            render::table(
                &[
                    "DEVICE",
                    "AS OF",
                    "REQUESTS",
                    "PRICED",
                    "UNPRICED",
                    "NOT EXTRACTED",
                    "SPLIT UNKNOWN",
                    "IN TOKENS",
                    "OUT TOKENS",
                    "EST. (PRICED ONLY)",
                ],
                &rows,
            );
            if !by_device && !p.devices.is_empty() {
                println!(
                    "  Total ({}): {} requests, {} estimated for priced requests only",
                    p.total_label,
                    p.total.requests,
                    usd(p.total.estimated_cost_micros)
                );
            }
            for (d, name) in &p.no_data_from {
                println!(
                    "  No data from {} ({}): unknown, not zero.",
                    render::sanitize(name.as_deref().unwrap_or("-")),
                    short(&d.to_hex())
                );
            }
            for d in p.devices.iter().filter(|d| d.split_unknown_requests > 0) {
                if let Some(since) = d.split_known_since {
                    println!(
                        "  {}: priced/unpriced split unknown before {since}.",
                        render::sanitize(d.device_name.as_deref().unwrap_or("-"))
                    );
                }
            }
        }
    });
    Ok(())
}

fn settings_cmd(ctx: &Ctx, cmd: SettingsCmd) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    match cmd {
        SettingsCmd::List | SettingsCmd::Get { .. } => {
            let want = match &cmd {
                SettingsCmd::Get { name } => Some(name.clone()),
                _ => None,
            };
            let rows: Vec<serde_json::Value> = vault
                .mesh_settings()?
                .into_iter()
                .filter(|(n, _, _)| want.as_ref().is_none_or(|w| w == n))
                .map(|(n, v, set)| serde_json::json!({ "name": n, "value": v, "default": !set }))
                .collect();
            if let Some(w) = &want {
                if rows.is_empty() {
                    bail!("unknown mesh setting '{w}'");
                }
            }
            render::emit(ctx.json, &rows, || {
                for r in &rows {
                    println!(
                        "{} = {}{}",
                        r["name"].as_str().unwrap_or_default(),
                        r["value"],
                        if r["default"] == true {
                            " (default)"
                        } else {
                            ""
                        }
                    );
                }
            });
        }
        SettingsCmd::Set { name, value } => {
            let v = vault.mesh_setting_set(name.trim(), &value)?;
            let out = serde_json::json!({ "name": name.trim(), "value": v });
            render::emit(ctx.json, &out, || {
                println!(
                    "Set {} = {v}. Every device applies it after its next exchange.",
                    name.trim()
                )
            });
        }
    }
    Ok(())
}

fn peer_cmd(ctx: &Ctx, cmd: PeerCmd) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    match cmd {
        PeerCmd::Add { addr } => {
            let (addr, changed) = vault.mesh_peer_add(&addr)?;
            let out = serde_json::json!({ "addr": addr, "added": changed });
            render::emit(ctx.json, &out, || {
                if changed {
                    println!("Added peer {addr}. A running node dials it at its next round.");
                } else {
                    println!("{addr} is already a peer.");
                }
            });
        }
        PeerCmd::Remove { addr } => {
            let removed = vault.mesh_peer_remove(&addr)?;
            let out = serde_json::json!({ "removed": removed.is_some(), "source": removed });
            render::emit(ctx.json, &out, || match removed {
                None => println!("{} was not a peer.", render::sanitize(addr.trim())),
                Some(peers::PeerSource::Manual) => println!("Removed peer {}.", addr.trim()),
                Some(_) => println!(
                    "Removed {}; a device still publishing it brings it back at the next round.",
                    addr.trim()
                ),
            });
        }
        PeerCmd::List => {
            let rows = peer_rows(&vault)?;
            render::emit(ctx.json, &rows, || print_peer_rows(&rows));
        }
    }
    Ok(())
}

/// One `mesh_peers` row with the name of the device behind it.
#[derive(Serialize)]
struct PeerOut {
    #[serde(flatten)]
    row: PeerRow,
    device_name: Option<String>,
}

fn device_names(
    vault: &api_tracker_core::vault::UnlockedVault,
) -> Result<BTreeMap<DeviceId, String>> {
    Ok(vault
        .mesh_devices()?
        .into_iter()
        .filter_map(|d| d.name.map(|n| (d.device_id, n)))
        .collect())
}

fn peer_rows(vault: &api_tracker_core::vault::UnlockedVault) -> Result<Vec<PeerOut>> {
    let names = device_names(vault)?;
    Ok(vault
        .mesh_peers()?
        .into_iter()
        .map(|row| PeerOut {
            device_name: row.device_id.and_then(|d| names.get(&d).cloned()),
            row,
        })
        .collect())
}

fn print_peer_rows(rows: &[PeerOut]) {
    if rows.is_empty() {
        println!(
            "No peer addresses. Add one with `tethra mesh peer add HOST:PORT`; a running node \
             also learns the addresses your other devices publish."
        );
        return;
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|p| {
            vec![
                p.row.addr.clone(),
                match (&p.device_name, p.row.device_id) {
                    (Some(n), Some(d)) => {
                        format!("{} ({})", render::sanitize(n), short(&d.to_hex()))
                    }
                    (None, Some(d)) => short(&d.to_hex()).to_owned(),
                    _ => "-".into(),
                },
                p.row.source.as_str().to_owned(),
                p.row
                    .last_success_at
                    .clone()
                    .unwrap_or_else(|| "never".into()),
                p.row.failures.to_string(),
                p.row
                    .unreachable_since
                    .clone()
                    .unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    render::table(
        &[
            "ADDRESS",
            "DEVICE",
            "SOURCE",
            "LAST SUCCESS",
            "FAILURES",
            "UNREACHABLE SINCE",
        ],
        &table,
    );
}

/// The lag record of one device (from its last `Hello`).
#[derive(Serialize)]
struct LagOut {
    device_id: DeviceId,
    device_name: Option<String>,
    #[serde(flatten)]
    lag: PeerLag,
}

/// The running node, as `status` reports it.
#[derive(Serialize)]
struct NodeOut {
    running: bool,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    status: Option<NodeStatus>,
}

#[derive(Serialize)]
struct StatusOut {
    #[serde(flatten)]
    status: MeshStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<NodeOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peers: Option<Vec<PeerOut>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lag: Option<Vec<LagOut>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_changes: Option<Vec<DeviceChange>>,
    /// The usage publisher's last run (Increment 06).
    #[serde(skip_serializing_if = "Option::is_none")]
    publish: Option<api_tracker_core::mesh::publish::PublishReport>,
    /// Spend caps known here and the reconciler's last run (Increment 07).
    #[serde(skip_serializing_if = "Option::is_none")]
    caps: Option<CapsStatus>,
}

#[derive(Serialize)]
struct CapsStatus {
    count: usize,
    frozen: usize,
    /// This device's transfers waiting for the gateway's acknowledgement.
    escrow_open: usize,
    last_run: Option<api_tracker_core::mesh::caps::ReconcileReport>,
}

fn status(ctx: &Ctx) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let status = vault.mesh_status()?;
    let mut out = StatusOut {
        status,
        node: None,
        peers: None,
        lag: None,
        address_changes: None,
        publish: None,
        caps: None,
    };
    if out.status.initialized {
        let node = instance::status(&ctx.paths.data_dir);
        out.node = Some(NodeOut {
            running: node.is_some(),
            status: node,
        });
        out.peers = Some(peer_rows(&vault)?);
        let names = device_names(&vault)?;
        let store = vault.mesh_open_store()?;
        let now = store.vv().clone();
        out.lag = Some(
            peers::hello_records(store.connection())?
                .into_iter()
                .map(|(d, rec)| LagOut {
                    device_id: d,
                    device_name: names.get(&d).cloned(),
                    lag: peers::lag(&rec, &now),
                })
                .collect(),
        );
        out.address_changes = Some(peers::device_changes(store.connection())?);
        out.publish = api_tracker_core::mesh::publish::last_report(store.connection())?;
        let caps = api_tracker_core::mesh::caps::view::caps_in(store.state());
        out.caps = Some(CapsStatus {
            count: caps.len(),
            frozen: caps.iter().filter(|c| c.frozen).count(),
            escrow_open: api_tracker_core::mesh::caps::escrow::open_rows(store.connection())?.len(),
            last_run: api_tracker_core::mesh::caps::reconcile::last_report(store.connection())?,
        });
    }
    render::emit(ctx.json, &out, || print_status(&out));
    Ok(())
}

fn doctor(ctx: &Ctx, rebuild: bool, repair: bool) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let report = api_tracker_mesh::doctor::run(
        &vault,
        &ctx.paths.data_dir,
        Arc::new(SystemClock),
        api_tracker_mesh::doctor::DoctorOptions { rebuild, repair },
    )?;
    #[derive(Serialize)]
    struct DoctorOut<'a> {
        worst: Severity,
        #[serde(flatten)]
        report: &'a api_tracker_mesh::doctor::DoctorReport,
    }
    let out = DoctorOut {
        worst: report.worst(),
        report: &report,
    };
    render::emit(ctx.json, &out, || {
        for f in &report.findings {
            println!(
                "[{:<7}] {}: {}",
                f.severity.as_str(),
                f.check,
                render::sanitize(&f.summary)
            );
            if f.severity != Severity::Ok {
                if let Some(fix) = &f.fix {
                    println!("          fix: {}", render::sanitize(fix));
                }
            }
        }
        if let Some(r) = &report.rebuild {
            println!(
                "Rebuild: {} row(s) rewritten from their bytes, {} removed.",
                r.rows_rewritten, r.rows_removed
            );
        }
        println!(
            "{}",
            match report.worst() {
                Severity::Ok | Severity::Info => "No problems found.",
                Severity::Warning => "Warnings found; see the fixes above.",
                Severity::Problem => "Problems found; see the fixes above.",
            }
        );
    });
    Ok(())
}

fn invite(
    ctx: &Ctx,
    addrs: Vec<String>,
    ttl: Option<u32>,
    wait: bool,
    listen: Vec<SocketAddr>,
) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    if wait && listen.is_empty() {
        bail!("--wait needs --listen ADDR:PORT to serve on");
    }
    let listeners = if wait {
        bind_all(&listen, false)?
    } else {
        Vec::new()
    };
    let mut addrs = addrs;
    if addrs.is_empty() {
        for l in &listeners {
            addrs.push(l.local_addr()?.to_string());
        }
    }
    if addrs.is_empty() {
        bail!("give the address other devices can reach this one at: --addr HOST:PORT");
    }
    eprintln!("Reauthentication required to create an invite.");
    let master = ctx::master_password()?;
    let inv = vault.mesh_invite_create(&master, ttl)?;
    let text = format_invite(&inv.token, &addrs)?;
    let out = serde_json::json!({
        "invite": text.expose(),
        "expires_at": inv.expires_at,
        "ttl_minutes": inv.ttl_minutes,
    });
    render::emit(ctx.json, &out, || println!("{}", text.expose()));
    std::io::stdout().flush()?;
    eprintln!(
        "Treat this invite like a password for the next {} minute(s): anyone who has it \
         can add a device to your mesh. Move it over a channel you trust; it is shown once.",
        inv.ttl_minutes
    );
    drop(out);
    drop(text);
    if wait {
        let node = Arc::new(MeshNode::open(
            &vault,
            Arc::new(SystemClock),
            TransportLimits::default(),
        )?);
        let hash = inv.token.hash();
        let conn = api_tracker_core::db::open(&ctx.paths.db_path())?;
        // Stop once the invite is used, expired or locked out (core's rule).
        let done = move || -> bool {
            !api_tracker_core::mesh::membership::invite_is_live(&conn, &hash).unwrap_or(false)
        };
        for l in &listeners {
            eprintln!("Waiting for the new device on {}", l.local_addr()?);
        }
        serve(node, listeners, &done)?;
        eprintln!("The invite was used or expired; stopped listening.");
    }
    Ok(())
}

fn join(ctx: &Ctx, invite: &str, name: Option<String>) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let invite = if invite == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_line(&mut s)
            .context("could not read the invite from standard input")?;
        zeroize::Zeroizing::new(s)
    } else {
        zeroize::Zeroizing::new(invite.to_owned())
    };
    let name = name.unwrap_or_else(default_device_name);
    let report = api_tracker_mesh::pair::join(
        &vault,
        invite.trim(),
        &name,
        Arc::new(SystemClock),
        TransportLimits::default(),
    )?;
    let out = serde_json::json!({
        "mesh_id": report.info.mesh_id,
        "device_id": report.info.device_id,
        "device_name": report.info.device_name,
        "items_in": report.exchange.items_in,
        "first_exchange_completed": report.exchange.aborted.is_none(),
        "inviter_verified": report.inviter_verified,
    });
    render::emit(ctx.json, &out, || {
        println!(
            "Joined mesh {} as {} ({}).",
            short(&report.info.mesh_id.to_hex()),
            render::sanitize(&report.info.device_name),
            short(&report.info.device_id.to_hex())
        );
        println!(
            "First exchange: {} item(s) received{}.",
            report.exchange.items_in,
            if report.exchange.aborted.is_some() {
                " (ended early; the next exchange continues)"
            } else {
                ""
            }
        );
    });
    if !report.inviter_verified && report.exchange.aborted.is_none() {
        eprintln!(
            "warning: the inviting device's key does not match its roster entry; \
             leave this mesh and pair again from a device you trust."
        );
    }
    Ok(())
}

fn leave(ctx: &Ctx, mut peers: Vec<String>, yes: bool) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    if !ctx::confirm(
        "Leave the mesh? This deletes this device's mesh identity, keys and records here; \
         to rejoin, pair again with a new invite.",
        yes,
    )? {
        bail!("aborted");
    }
    // Addresses the other devices published, after any given explicitly.
    {
        let store = vault.mesh_open_store()?;
        let state = store.state();
        for (d, _) in state.roster.known() {
            if *d == store.self_id() || !state.roster.is_active(d) {
                continue;
            }
            if let Some(info) = state.device_info.value(d, &state.roster) {
                peers.extend(info.listen_addrs.iter().cloned());
            }
        }
    }
    eprintln!("Reauthentication required to leave the mesh.");
    let master = ctx::master_password()?;
    let report = vault.mesh_leave(&master, &mut |_store| {
        let Ok(node) = MeshNode::open(&vault, Arc::new(SystemClock), TransportLimits::default())
        else {
            return false;
        };
        peers
            .iter()
            .any(|p| replicate_once(&node, p).is_ok_and(|r| r.aborted.is_none()))
    })?;
    render::emit(ctx.json, &report, || {
        if report.delivered {
            println!("Left the mesh; a peer received this device's departure.");
        } else {
            println!(
                "Left the mesh. No peer was reachable, so the other devices still list this \
                 one until someone removes it."
            );
        }
    });
    Ok(())
}

fn short(hex: &str) -> &str {
    &hex[..8.min(hex.len())]
}

fn print_status(out: &StatusOut) {
    let Some(d) = &out.status.detail else {
        println!("This device is not part of a mesh. Run `tethra mesh init` to start one.");
        return;
    };
    print_detail(d);
    match out.node.as_ref().and_then(|n| n.status.as_ref()) {
        Some(n) => {
            println!(
                "Node:         running (pid {}), listening on {}; a round every {} s, {} so far{}",
                n.pid,
                n.listen.join(", "),
                n.interval_ms as f64 / 1000.0,
                n.rounds,
                n.last_round_at
                    .as_deref()
                    .map(|t| format!(", last at {t}"))
                    .unwrap_or_default()
            );
            if !n.advertised.is_empty() {
                println!("              publishing {}", n.advertised.join(", "));
            }
            if let Some(e) = &n.last_publish_error {
                println!(
                    "              could not publish its addresses: {}",
                    render::sanitize(e)
                );
            }
        }
        None => println!(
            "Node:         not running (start one with `tethra mesh serve --listen ADDR:PORT`)"
        ),
    }
    if let Some(peers) = &out.peers {
        println!("Peers:");
        print_peer_rows(peers);
    }
    if let Some(lag) = out.lag.as_ref().filter(|l| !l.is_empty()) {
        println!("Lag at the last exchange with each device (items):");
        let rows: Vec<Vec<String>> = lag
            .iter()
            .map(|l| {
                vec![
                    render::sanitize(l.device_name.as_deref().unwrap_or("-")),
                    short(&l.device_id.to_hex()).to_owned(),
                    l.lag.at.clone(),
                    l.lag.peer_behind.to_string(),
                    l.lag.peer_ahead.to_string(),
                    l.lag.peer_behind_now.to_string(),
                    if l.lag.completed { "yes" } else { "no" }.to_owned(),
                ]
            })
            .collect();
        render::table(
            &[
                "NAME",
                "DEVICE",
                "LAST EXCHANGE",
                "IT LACKED",
                "WE LACKED",
                "IT LACKS NOW",
                "COMPLETED",
            ],
            &rows,
        );
    }
    if let Some(p) = &out.publish {
        println!(
            "Publishing:   last run {}: {} counter(s) published{}, {} collected (retention {} days)",
            peers::ms_rfc3339(p.at_ms),
            p.minted,
            if p.deferred > 0 {
                format!(", {} waiting for the next hour's budget", p.deferred)
            } else {
                String::new()
            },
            p.collected,
            p.retention_days
        );
    }
    if let Some(c) = out.caps.as_ref().filter(|c| c.count > 0) {
        println!(
            "Spend caps:   {} ({} frozen); `tethra mesh cap show` for spend and rights{}",
            c.count,
            c.frozen,
            if c.escrow_open > 0 {
                format!(
                    "; {} transfer(s) waiting for the gateway's acknowledgement",
                    c.escrow_open
                )
            } else {
                String::new()
            }
        );
    }
    for c in out.address_changes.iter().flatten() {
        println!(
            "Note: a different device ({}) now answers at {} (was {}).",
            short(&c.to.to_hex()),
            c.addr,
            short(&c.from.to_hex())
        );
    }
}

fn print_detail(d: &MeshStatusDetail) {
    let me = d.device_id;
    let origin = if d.genesis_device == me {
        "started on this device".to_owned()
    } else {
        format!("started on {}", short(&d.genesis_device.to_hex()))
    };
    println!("Mesh:         {} ({origin})", d.mesh_id_short);
    println!(
        "This device:  {} ({}), next item seq {}",
        render::sanitize(&d.device_name),
        short(&me.to_hex()),
        d.next_seq
    );
    match (d.marker, d.marker_problem) {
        (MarkerStatus::Ok, _) => println!("Identity:     marker ok"),
        (_, Some(problem)) => {
            println!("Identity:     NOT TRUSTED: {problem}.");
            println!(
                "              This device will not mint mesh items. Leave the mesh and \
                 pair it again."
            );
        }
        (status, None) => println!("Identity:     marker {}", status.as_str()),
    }
    if d.self_forked {
        println!(
            "              Another installation has used this identity (a fork was \
             reported). Leave the mesh and pair this device again."
        );
    }
    println!("Devices ({} member(s)):", d.roster_size);
    let rows: Vec<Vec<String>> = d
        .devices
        .iter()
        .map(|dev| {
            let mut state = if dev.removed {
                "removed".to_owned()
            } else if dev.fork_seq.is_some() {
                "forked".to_owned()
            } else if dev.active {
                "active".to_owned()
            } else {
                "not admitted".to_owned()
            };
            if dev.is_self {
                state.push_str(" (this device)");
            }
            vec![
                render::sanitize(dev.name.as_deref().unwrap_or("-")),
                short(&dev.device_id.to_hex()).to_owned(),
                state,
            ]
        })
        .collect();
    render::table(&["NAME", "DEVICE", "STATE"], &rows);
    let items: Vec<String> = d
        .items_by_kind
        .iter()
        .map(|(k, n)| format!("{} {n}", render::sanitize(k)))
        .collect();
    println!(
        "Items held:   {}",
        if items.is_empty() {
            "none".to_owned()
        } else {
            items.join(", ")
        }
    );
    println!(
        "Health:       {} rejected item(s), {} clock-skewed origin(s), {} fork report(s), \
         {} repair change(s)",
        d.rejected_items,
        d.clock_skew.len(),
        d.forked_devices,
        d.repairs_changed
    );
    for (dev, ms) in &d.clock_skew {
        println!(
            "              clock of {} ahead by {} s",
            short(&dev.to_hex()),
            ms / 1000
        );
    }
    if let Some(held) = d.rollback_hold {
        println!(
            "Rollback:     a peer holds this device's items up to seq {held}; nothing is \
             created here until they come back"
        );
    }
}

/// This machine's host name, first label only, or a placeholder. `hostname`
/// exists on macOS, Linux and Windows; Windows also sets `COMPUTERNAME`.
fn default_device_name() -> String {
    let raw = std::env::var("COMPUTERNAME").ok().or_else(|| {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    });
    let name: String = raw
        .unwrap_or_default()
        .trim()
        .split('.')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(api_tracker_core::mesh::identity::MAX_DEVICE_NAME_CHARS)
        .collect();
    if name.trim().is_empty() {
        "this-device".to_owned()
    } else {
        name
    }
}
