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

pub fn monitor_run(ctx: &Ctx, offline: bool) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    let summary = vault.run_monitor()?;
    // Network phases are best-effort and offline-safe: due documentation
    // checks and webhook notification delivery. --offline skips them.
    let mut doc_checks = 0usize;
    let mut delivered = 0usize;
    if !offline {
        let fetcher = api_tracker_core::docwatch::HttpFetcher::new();
        if let Ok(results) = vault.check_due_doc_watches(&fetcher) {
            doc_checks = results.len();
        }
        let http = api_tracker_core::http::UreqClient::new();
        delivered = vault.deliver_notifications(&http).unwrap_or(0);
    }
    render::emit(ctx.json, &summary, || {
        println!(
            "Checked {} credential(s): {} new alert(s), {} resolved, {} open.",
            summary.checked, summary.alerts_created, summary.alerts_resolved, summary.open_alerts
        );
        if doc_checks > 0 {
            println!("Documentation checks performed: {doc_checks} (due per interval).");
        }
        if delivered > 0 {
            println!("Webhook notifications delivered: {delivered}.");
        }
    });
    Ok(())
}

#[derive(clap::Subcommand)]
pub enum NotifyCmd {
    /// Add a webhook channel (URL via stdin or hidden prompt; stored
    /// encrypted). Payloads carry alert metadata only, never secrets.
    Add(NotifyAddArgs),
    /// List channels.
    List,
    /// Remove a channel.
    Remove { channel: String },
    /// Enable or disable a channel.
    Enable {
        channel: String,
        #[arg(long)]
        off: bool,
    },
    /// Send a test notification through a channel.
    Test { channel: String },
}

#[derive(clap::Args)]
pub struct NotifyAddArgs {
    /// A name of your choice.
    #[arg(long)]
    pub name: String,
    /// Minimum severity delivered (info/low/medium/high/critical).
    #[arg(long, default_value = "high")]
    pub min_severity: String,
    /// Read the webhook URL from stdin (it may embed a token).
    #[arg(long)]
    pub url_stdin: bool,
}

pub fn notify(ctx: &Ctx, cmd: NotifyCmd) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    match cmd {
        NotifyCmd::Add(args) => {
            let url = if args.url_stdin {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                api_tracker_core::secret::SecretString::new(
                    buf.trim_end_matches(['\n', '\r']).to_owned(),
                )
            } else {
                crate::ctx::prompt_secret("Webhook URL (hidden)")?
            };
            let channel = vault.notification_channel_add(&args.name, &url, &args.min_severity)?;
            println!(
                "Channel '{}' added ({}; floor {}). Payloads contain alert metadata only.",
                channel.name, channel.url_masked, channel.min_severity
            );
        }
        NotifyCmd::List => {
            let channels = vault.notification_channels()?;
            render::emit(ctx.json, &channels, || {
                if channels.is_empty() {
                    println!("No channels. Add one with `notify add --name <n>`.");
                    return;
                }
                let rows: Vec<Vec<String>> = channels
                    .iter()
                    .map(|c| {
                        vec![
                            c.name.clone(),
                            c.url_masked.clone(),
                            c.min_severity.clone(),
                            if c.enabled { "on" } else { "off" }.into(),
                            c.last_delivery_at.clone().unwrap_or_else(|| "never".into()),
                            if c.last_error.is_empty() {
                                "-".into()
                            } else {
                                c.last_error.clone()
                            },
                        ]
                    })
                    .collect();
                render::table(
                    &[
                        "NAME",
                        "URL",
                        "FLOOR",
                        "STATE",
                        "LAST DELIVERY",
                        "LAST ERROR",
                    ],
                    &rows,
                );
            });
        }
        NotifyCmd::Remove { channel } => {
            vault.notification_channel_remove(&channel)?;
            println!("Channel removed.");
        }
        NotifyCmd::Enable { channel, off } => {
            vault.notification_channel_enable(&channel, !off)?;
            println!("Channel {}.", if off { "disabled" } else { "enabled" });
        }
        NotifyCmd::Test { channel } => {
            let ch = vault.notification_channels()?;
            let ch = ch
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case(&channel) || c.id == channel)
                .ok_or_else(|| anyhow::anyhow!("no channel named '{channel}'"))?;
            let http = api_tracker_core::http::UreqClient::new();
            match vault.notification_channel_test(&ch.id, &http) {
                Ok(detail) => println!("OK: {detail}"),
                Err(e) => println!("Delivery failed: {e}"),
            }
        }
    }
    Ok(())
}
