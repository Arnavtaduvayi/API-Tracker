//! `mesh` subcommands: Tethra Mesh, peer-to-peer replication between your own
//! paired devices (ADR 0031). This build has `init` and `status`; pairing and
//! replication arrive in later increments (docs/mesh/increments/STATUS.md).
//!
//! Nothing printed here carries key material: not the private keys, not the
//! access key, not even public keys. Identifiers are random and not secret.

use crate::ctx::Ctx;
use crate::render;
use anyhow::Result;
use api_tracker_core::mesh::identity::{MeshStatus, MeshStatusDetail};
use api_tracker_core::mesh::marker::MarkerStatus;
use api_tracker_core::mesh::{DeviceId, MeshId};
use clap::Subcommand;
use serde::Serialize;

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
    }
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
