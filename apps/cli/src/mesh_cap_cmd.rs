//! `tethra mesh cap …`: replicated monthly spend caps on mesh projects
//! (Increment 07, ADR 0032). In this version caps raise alerts only; the
//! gateway enforces them from Increment 08.
//!
//! Amounts are given in US dollars and kept as micro-USD. Every figure is
//! gateway-estimated cost, labelled per device as of the last exchange with
//! it. A cap is a self-limit on traffic through Tethra's gateway, not a
//! security boundary, and never a budget (`tethra budget` is separate).

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::mesh::caps::view::{CapMonthRow, CapReport, CapRow};
use api_tracker_core::mesh::kinds::Month;
use api_tracker_mesh::node::GatewaySocket;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum CapCmd {
    /// Create a monthly spend cap on a mesh project. This device becomes the
    /// cap's owner: it mints each month's rights and shares them out.
    Create {
        /// The mesh project (id, id prefix or name).
        mesh: String,
        /// The cap per UTC calendar month, in US dollars.
        #[arg(long, value_name = "USD")]
        monthly: String,
    },
    /// Add <usd> to a cap this month. On a device that is not the cap's
    /// owner this is a local override for this device only (it asks first).
    Raise {
        /// The cap (id, id prefix, or its mesh project).
        cap: String,
        usd: String,
        /// Skip the confirmation an override asks for.
        #[arg(long)]
        yes: bool,
    },
    /// Lower a cap to <usd> a month (it asks first).
    Lower {
        cap: String,
        usd: String,
        #[arg(long)]
        yes: bool,
    },
    /// Show spend caps: this month's spend against each target.
    Show {
        cap: Option<String>,
        /// A UTC month, YYYY-MM (default: this month).
        #[arg(long)]
        month: Option<String>,
    },
    /// One cap's rights, per device.
    Rights {
        cap: String,
        #[arg(long)]
        month: Option<String>,
    },
    /// On the cap's owner: ask devices to hand their unspent rights back,
    /// before you remove a device. The requests travel in the node's next
    /// exchanges with them, for 24 hours.
    Reclaim {
        cap: String,
        /// Only this device (default: every device holding rights).
        #[arg(long, value_name = "DEVICE")]
        from: Option<String>,
    },
}

fn usd(micros: u128) -> String {
    format!(
        "${}.{:02}",
        micros / 1_000_000,
        (micros % 1_000_000) / 10_000
    )
}

fn usd_signed(micros: i128) -> String {
    if micros < 0 {
        format!("-{}", usd(micros.unsigned_abs()))
    } else {
        usd(micros as u128)
    }
}

fn micros(usd: &str) -> Result<u64> {
    let m = api_tracker_core::pricing::dollars_to_micros(usd)?;
    Ok(u64::try_from(m).unwrap_or(0))
}

fn month_arg(m: Option<String>) -> Result<Option<Month>> {
    match m {
        Some(s) => match Month::parse(s.trim()) {
            Some(m) => Ok(Some(m)),
            None => bail!("--month must be YYYY-MM"),
        },
        None => Ok(None),
    }
}

fn short(hex: &str) -> &str {
    &hex[..8.min(hex.len())]
}

pub fn run(ctx: &Ctx, cmd: CapCmd) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let probe = GatewaySocket(ctx.paths.data_dir.clone());
    match cmd {
        CapCmd::Create { mesh, monthly } => {
            let amount = micros(&monthly)?;
            let out = vault.mesh_cap_create(&mesh, amount, &probe)?;
            render::emit(ctx.json, &out, || {
                println!(
                    "Created spend cap {} on mesh project {}: {} for {}, then each month.",
                    short(&out.cap_id.to_hex()),
                    short(&out.mesh_project_id.to_hex()),
                    usd(u128::from(out.monthly_micros)),
                    out.month
                );
                println!(
                    "This device owns the cap: it mints each month's rights and shares them \
                     equally among your active devices ({} handed out now).",
                    usd(u128::from(out.distributed_micros))
                );
                println!(
                    "In this version the cap raises alerts only (at 80% and 100%); the gateway \
                     does not block requests yet."
                );
            });
        }
        CapCmd::Raise {
            cap,
            usd: amount,
            yes,
        } => {
            let amount = micros(&amount)?;
            let report = vault.mesh_caps(Some(&cap), None, &probe)?;
            let Some(row) = report.caps.first() else {
                bail!("no such spend cap");
            };
            if !row.owned_here
                && !ctx::confirm(
                    &format!(
                        "This device is not the cap's owner ({}), so this is a local \
                         override: it adds {} of rights for this device only, until the end \
                         of the month. Other devices see it labelled as an override, and the \
                         cap's target does not change. To raise the cap for every device, \
                         raise it on its owner. Continue?",
                        row.owner_name.as_deref().map_or_else(
                            || short(&row.owner_device.to_hex()).to_owned(),
                            render::sanitize
                        ),
                        usd(u128::from(amount))
                    ),
                    yes,
                )?
            {
                bail!("aborted");
            }
            let out = vault.mesh_cap_raise(&cap, amount, &probe)?;
            render::emit(ctx.json, &out, || {
                if out.is_override {
                    println!(
                        "Added a local override of {} to cap {} for this device, for {}.",
                        usd(u128::from(out.amount_micros)),
                        short(&out.cap_id.to_hex()),
                        out.months[0]
                    );
                } else {
                    let months: Vec<String> = out.months.iter().map(Month::to_string).collect();
                    println!(
                        "Raised cap {} by {} for {}; {} handed out to your devices now.",
                        short(&out.cap_id.to_hex()),
                        usd(u128::from(out.amount_micros)),
                        months.join(" and "),
                        usd(u128::from(out.distributed_micros))
                    );
                }
            });
        }
        CapCmd::Lower {
            cap,
            usd: amount,
            yes,
        } => {
            let target = micros(&amount)?;
            let report = vault.mesh_caps(Some(&cap), None, &probe)?;
            let Some(row) = report.caps.first() else {
                bail!("no such spend cap");
            };
            let now = row
                .months
                .first()
                .and_then(|m| m.target)
                .map_or_else(|| "its current target".to_owned(), |t| usd(u128::from(t)));
            if !ctx::confirm(
                &format!(
                    "Lower the spend cap on {} from {} to {} a month? Each device burns the \
                     rights it holds above its new share as it hears of this, and the owner \
                     takes back the rest. Spend already made stays counted; if it is already \
                     above {}, every device is capped for the rest of the month.",
                    row.project_name.as_deref().map_or_else(
                        || short(&row.mesh_project_id.to_hex()).to_owned(),
                        render::sanitize
                    ),
                    now,
                    usd(u128::from(target)),
                    usd(u128::from(target))
                ),
                yes,
            )? {
                bail!("aborted");
            }
            let out = vault.mesh_cap_lower(&cap, target, &probe)?;
            render::emit(ctx.json, &out, || {
                let months: Vec<String> = out.months.iter().map(Month::to_string).collect();
                println!(
                    "Lowered cap {} to {} for {}; this device burned {}. Other devices burn \
                     their excess as they hear of it.",
                    short(&out.cap_id.to_hex()),
                    usd(u128::from(out.amount_micros)),
                    months.join(" and "),
                    usd(u128::from(out.burned_micros))
                );
            });
        }
        CapCmd::Show { cap, month } => {
            let report = vault.mesh_caps(cap.as_deref(), month_arg(month)?, &probe)?;
            render::emit(ctx.json, &report, || print_show(&report));
        }
        CapCmd::Rights { cap, month } => {
            let report = vault.mesh_caps(Some(&cap), month_arg(month)?, &probe)?;
            render::emit(ctx.json, &report, || {
                for c in &report.caps {
                    print_header(c);
                    for m in &c.months {
                        print_month(m);
                        print_rights(m);
                    }
                }
            });
        }
        CapCmd::Reclaim { cap, from } => {
            let (id, devices) = vault.mesh_cap_reclaim(&cap, from.as_deref())?;
            let out = serde_json::json!({ "cap_id": id, "asked": devices });
            render::emit(ctx.json, &out, || {
                if devices.is_empty() {
                    println!(
                        "No other device holds rights for cap {}.",
                        short(&id.to_hex())
                    );
                } else {
                    println!(
                        "Asked {} device(s) to hand cap {}'s unspent rights back to this \
                         device. Each does at its next exchange with this device's node (for \
                         the next 24 hours); until then this device grants them none.",
                        devices.len(),
                        short(&id.to_hex())
                    );
                }
            });
        }
    }
    Ok(())
}

fn print_header(c: &CapRow) {
    let mut state = Vec::new();
    if c.frozen {
        state.push(
            "FROZEN: its owner device was removed; no new rights are minted (create a new cap \
             with `tethra mesh cap create`)"
                .to_owned(),
        );
    }
    if let Some(s) = c.superseded_by {
        state.push(format!(
            "superseded by cap {}, created first on the same project",
            short(&s.to_hex())
        ));
    }
    println!(
        "Cap {} on {} — owner {}{}",
        short(&c.cap_id.to_hex()),
        c.project_name.as_deref().map_or_else(
            || short(&c.mesh_project_id.to_hex()).to_owned(),
            render::sanitize
        ),
        c.owner_name.as_deref().map_or_else(
            || short(&c.owner_device.to_hex()).to_owned(),
            render::sanitize
        ),
        if c.owned_here { " (this device)" } else { "" }
    );
    for s in state {
        println!("  {s}");
    }
}

fn print_month(m: &CapMonthRow) {
    let Some(eff) = m.effective_target else {
        println!("  {}: no target set yet", m.month);
        return;
    };
    println!(
        "  {}: {} of {} ({}%) — {}",
        m.month,
        usd(m.total_used),
        usd(eff),
        m.used_pct.unwrap_or(0),
        m.total_label
    );
    let mut parts = vec![format!("target {}", usd(u128::from(m.target.unwrap_or(0))))];
    if m.overrides > 0 {
        parts.push(format!("local overrides {}", usd(m.overrides)));
    }
    if m.burned > 0 {
        parts.push(format!("burned {}", usd(m.burned)));
    }
    if m.pending_decrease > 0 {
        parts.push(format!("pending decrease {}", usd(m.pending_decrease)));
    }
    if let Some(a) = m.local_avail {
        parts.push(format!("this device can still spend {}", usd_signed(a)));
    }
    if m.escrow_open > 0 {
        parts.push(format!(
            "{} waiting for the gateway's acknowledgement",
            usd(u128::from(m.escrow_open))
        ));
    }
    println!("    {}", parts.join("; "));
}

fn print_rights(m: &CapMonthRow) {
    let rows: Vec<Vec<String>> = m
        .devices
        .iter()
        .map(|d| {
            let mut name = d
                .device_name
                .as_deref()
                .map_or_else(|| short(&d.device_id.to_hex()).to_owned(), render::sanitize);
            if d.is_self {
                name.push_str(" (this device)");
            }
            let mut role = Vec::new();
            if d.is_owner {
                role.push("owner");
            }
            if d.is_override {
                role.push("override");
            }
            if d.removed {
                role.push("removed");
            }
            if d.stale {
                role.push("stale");
            }
            vec![
                name,
                if role.is_empty() {
                    "-".into()
                } else {
                    role.join(", ")
                },
                usd(d.minted),
                usd(d.received),
                usd(d.sent),
                usd(d.burned),
                usd(d.used),
                usd_signed(d.avail),
                d.as_of
                    .clone()
                    .unwrap_or_else(|| if d.is_self { "now".into() } else { "-".into() }),
            ]
        })
        .collect();
    render::table(
        &[
            "DEVICE",
            "ROLE",
            "MINTED",
            "RECEIVED",
            "SENT",
            "BURNED",
            "USED",
            "AVAILABLE",
            "AS OF",
        ],
        &rows,
    );
    if m.devices.iter().any(|d| d.clamped > 0) {
        println!("    Some transfers were larger than the sender held; the excess is ignored.");
    }
}

fn print_show(report: &CapReport) {
    for n in &report.notes {
        println!("{n}");
    }
    if report.caps.is_empty() {
        println!(
            "No spend caps. Create one with `tethra mesh cap create <mesh-project> --monthly <usd>`."
        );
        return;
    }
    for c in &report.caps {
        println!();
        print_header(c);
        for m in &c.months {
            print_month(m);
        }
    }
}
