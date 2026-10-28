//! `mesh` subcommands: Tethra Mesh, peer-to-peer replication between your own
//! paired devices (ADR 0031): identity, pairing, devices, removal, leave, and
//! serving or replicating over the network (`api-tracker-mesh`).
//!
//! Nothing printed here carries key material: not the private keys, not the
//! access key, not even public keys. Identifiers are random and not secret.
//! The one secret ever printed is an invite, once, by `mesh invite`.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Context, Result};
use api_tracker_core::mesh::clock::SystemClock;
use api_tracker_core::mesh::identity::{MeshStatus, MeshStatusDetail};
use api_tracker_core::mesh::invite::format_invite;
use api_tracker_core::mesh::marker::MarkerStatus;
use api_tracker_core::mesh::store::MeshStore;
use api_tracker_core::mesh::{DeviceId, MeshId};
use api_tracker_mesh::replicate::replicate_once;
use api_tracker_mesh::serve::{bind_all, serve};
use api_tracker_mesh::{MeshNode, TransportLimits};
use clap::Subcommand;
use serde::Serialize;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

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
    /// Accept connections from paired devices until stopped (Ctrl-C).
    /// Nothing listens unless you give --listen.
    Serve {
        /// Address to listen on (repeatable); port 0 picks a free port.
        #[arg(long, required = true, value_name = "ADDR:PORT")]
        listen: Vec<SocketAddr>,
        /// Allow 0.0.0.0 or [::] (every network interface).
        #[arg(long)]
        all_interfaces: bool,
    },
    /// Run one exchange with a paired device now.
    Replicate {
        #[arg(long, value_name = "HOST:PORT")]
        peer: String,
    },
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
                println!("Pairing other devices is not available in this build yet.");
            });
        }
        MeshCmd::Status => {
            let (vault, _token) = ctx.unlocked()?;
            let status = vault.mesh_status()?;
            render::emit(ctx.json, &status, || print_status(&status));
        }
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
        } => {
            let (vault, _token) = ctx.unlocked()?;
            let node = Arc::new(MeshNode::open(
                &vault,
                Arc::new(SystemClock),
                TransportLimits::default(),
            )?);
            let listeners = bind_all(&listen, all_interfaces)?;
            for l in &listeners {
                // Tests and scripts read the bound port from this line.
                println!("Listening on {}", l.local_addr()?);
            }
            std::io::stdout().flush()?;
            serve(node, listeners, &|| false)?;
        }
        MeshCmd::Replicate { peer } => {
            let (vault, _token) = ctx.unlocked()?;
            let node = MeshNode::open(&vault, Arc::new(SystemClock), TransportLimits::default())?;
            let report = replicate_once(&node, &peer)?;
            render::emit(ctx.json, &report, || {
                println!(
                    "Exchanged with {}: {} item(s) in, {} out, {} ms.",
                    short(&report.peer.to_hex()),
                    report.items_in,
                    report.items_out,
                    report.duration_ms
                );
            });
            if let Some(why) = report.aborted {
                bail!("the exchange ended early: {why}");
            }
        }
    }
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

fn print_status(status: &MeshStatus) {
    let Some(d) = &status.detail else {
        println!("This device is not part of a mesh. Run `tethra mesh init` to start one.");
        return;
    };
    print_detail(d);
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
