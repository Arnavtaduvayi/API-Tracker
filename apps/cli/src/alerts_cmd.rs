//! `alerts` and `monitor` subcommands.

use crate::ctx::Ctx;
use crate::render;
use anyhow::Result;
use api_tracker_core::alerts;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum AlertsCmd {
    /// List alerts (open by default).
    List {
        /// Include acknowledged and resolved alerts.
        #[arg(long)]
        all: bool,
    },
    /// Acknowledge an alert (by id or id prefix).
    Acknowledge { alert: String },
    /// Resolve an alert (by id or id prefix).
    Resolve { alert: String },
}

pub fn alerts(ctx: &Ctx, cmd: AlertsCmd) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    match cmd {
        AlertsCmd::List { all } => {
            let list = alerts::list(vault.connection(), all)?;
            render::emit(ctx.json, &list, || {
                if list.is_empty() {
                    println!("No alerts. Run `api-tracker monitor run` to check now.");
                } else {
                    let rows: Vec<Vec<String>> = list
                        .iter()
                        .map(|a| {
                            let state = if a.resolved_at.is_some() {
                                "resolved"
                            } else if a.acknowledged_at.is_some() {
                                "ack"
                            } else {
                                "open"
                            };
                            vec![
                                a.id.chars().take(8).collect::<String>(),
                                a.severity.clone(),
                                a.kind.clone(),
                                state.to_string(),
                                a.title.clone(),
                            ]
                        })
                        .collect();
                    render::table(&["ID", "SEVERITY", "KIND", "STATE", "TITLE"], &rows);
                }
            });
        }
        AlertsCmd::Acknowledge { alert } => {
            let a = alerts::acknowledge(vault.connection(), &alert)?;
            println!("Acknowledged: {}", a.title);
        }
        AlertsCmd::Resolve { alert } => {
            let a = alerts::resolve(vault.connection(), &alert)?;
            println!("Resolved: {}", a.title);
        }
    }
    Ok(())
}

pub fn monitor_run(ctx: &Ctx) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    let summary = vault.run_monitor()?;
    render::emit(ctx.json, &summary, || {
        println!(
            "Checked {} credential(s): {} new alert(s), {} resolved, {} open.",
            summary.checked, summary.alerts_created, summary.alerts_resolved, summary.open_alerts
        );
    });
    Ok(())
}
