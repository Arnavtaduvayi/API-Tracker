//! `usage`, `budget`, `activity`, and `mapping` subcommands.

use crate::ctx::Ctx;
use crate::render;
use anyhow::Result;
use api_tracker_core::http::UreqClient;
use api_tracker_core::{budget, clock, usage};
use clap::Subcommand;

#[derive(Subcommand)]
pub enum UsageCmd {
    /// Sync usage from a provider using its connected admin credential.
    Sync {
        provider: String,
        /// Look back this many days.
        #[arg(long, default_value_t = 30)]
        days: u32,
    },
    /// Record a usage snapshot manually (attributed to a credential).
    Record {
        #[arg(long)]
        credential: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        input_tokens: i64,
        #[arg(long)]
        output_tokens: i64,
    },
    /// Show a usage + cost report for the current month.
    Report {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        credential: Option<String>,
    },
}

pub fn usage(ctx: &Ctx, cmd: UsageCmd) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    match cmd {
        UsageCmd::Sync { provider, days } => {
            let http = UreqClient::new();
            let n = vault.usage_sync(&provider, &http, days)?;
            let status = vault.provider_connection_status(&provider)?;
            println!("Synced {n} snapshot(s) for {provider}. {}", status.detail);
        }
        UsageCmd::Record {
            credential,
            model,
            input_tokens,
            output_tokens,
        } => {
            let now = clock::now_rfc3339();
            vault.usage_record_manual(
                &credential,
                model.as_deref(),
                input_tokens,
                output_tokens,
                &now,
                &now,
            )?;
            println!("Recorded a manual usage snapshot for '{credential}'.");
        }
        UsageCmd::Report {
            project,
            credential,
        } => {
            let start = budget::period_start(clock::now());
            let totals = vault.usage_totals(&start, credential.as_deref(), project.as_deref())?;
            render::emit(ctx.json, &totals, || print_usage_report(&totals, &start));
        }
    }
    Ok(())
}

fn print_usage_report(totals: &usage::UsageTotals, start: &str) {
    println!("Usage since {start} (current month):");
    println!("  Snapshots:     {}", totals.snapshots);
    println!("  Requests:      {}", totals.request_count);
    println!("  Input tokens:  {}", totals.input_tokens);
    println!("  Output tokens: {}", totals.output_tokens);
    println!("  Total tokens:  {}", totals.total_tokens);
    println!(
        "  Reported cost: {}",
        usage::format_micros(totals.reported_cost_micros)
    );
    println!(
        "  Estimated cost: {} (estimated — verify against the provider)",
        usage::format_micros(totals.estimated_cost_micros)
    );
    if let Some(attr) = &totals.coarsest_attribution {
        let a: usage::Attribution = attr.parse().unwrap_or(usage::Attribution::Unknown);
        println!("  Attribution:   {}", a.label());
    }
    if totals.has_inexact_attribution {
        println!("  NOTE: some usage is not exact per-key; it is not charged to one credential.");
    }
}

#[derive(Subcommand)]
pub enum BudgetCmd {
    /// Set (or clear) a monthly budget in dollars.
    Set {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        credential: Option<String>,
        /// Dollar amount, e.g. 25.00. Omit to clear.
        #[arg(long)]
        amount: Option<String>,
    },
    /// Show the budget report for the current month.
    Show {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        credential: Option<String>,
    },
}

pub fn budget(ctx: &Ctx, cmd: BudgetCmd) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    match cmd {
        BudgetCmd::Set {
            project,
            credential,
            amount,
        } => {
            if let Some(p) = &project {
                vault.set_project_budget_dollars(p, amount.as_deref())?;
                println!(
                    "Set project '{p}' budget to {}.",
                    amount.as_deref().unwrap_or("(none)")
                );
            } else if let Some(c) = &credential {
                vault.set_credential_budget_dollars(c, amount.as_deref())?;
                println!(
                    "Set credential '{c}' budget to {}.",
                    amount.as_deref().unwrap_or("(none)")
                );
            } else {
                anyhow::bail!("pass --project or --credential");
            }
        }
        BudgetCmd::Show {
            project,
            credential,
        } => {
            let report = if let Some(p) = &project {
                vault.project_budget_report(p)?
            } else if let Some(c) = &credential {
                vault.credential_budget_report(c)?
            } else {
                anyhow::bail!("pass --project or --credential");
            };
            render::emit(ctx.json, &report, || print_budget(&report));
        }
    }
    Ok(())
}

fn print_budget(r: &budget::BudgetReport) {
    println!("Budget report for {} (since {}):", r.scope, r.period_start);
    println!(
        "  Budget:        {}",
        r.budget_micros
            .map(usage::format_micros)
            .unwrap_or_else(|| "(none set)".into())
    );
    println!(
        "  Used:          {} ({})",
        usage::format_micros(r.used_micros),
        if r.used_is_estimated {
            "estimated"
        } else {
            "provider-reported"
        }
    );
    if let Some(rem) = r.remaining_micros {
        println!("  Remaining:     {}", usage::format_micros(rem));
    }
    println!(
        "  Projected end: {}",
        usage::format_micros(r.projected_period_end_micros)
    );
    if r.over_budget {
        println!("  STATUS: OVER BUDGET");
    }
    if let Some(note) = &r.attribution_note {
        println!("  {note}");
    }
}

#[derive(Subcommand)]
pub enum ActivityCmd {
    /// List recent local activity events.
    List {
        #[arg(long)]
        credential: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
}

pub fn activity(ctx: &Ctx, cmd: ActivityCmd) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    match cmd {
        ActivityCmd::List { credential, limit } => {
            let events = vault.activity_list(limit, credential.as_deref())?;
            render::emit(ctx.json, &events, || {
                if events.is_empty() {
                    println!("No activity recorded yet.");
                } else {
                    let rows: Vec<Vec<String>> = events
                        .iter()
                        .map(|e| {
                            vec![
                                e.at.clone(),
                                e.source.clone(),
                                e.kind.clone(),
                                e.detail.clone(),
                            ]
                        })
                        .collect();
                    render::table(&["WHEN", "SOURCE", "KIND", "DETAIL"], &rows);
                }
            });
        }
    }
    Ok(())
}

#[derive(Subcommand)]
pub enum MappingCmd {
    /// Map a credential to an environment-variable name for `run`.
    Set {
        #[arg(long)]
        project: String,
        #[arg(long)]
        credential: String,
        #[arg(long)]
        env: String,
    },
    /// Remove a mapping.
    Remove {
        #[arg(long)]
        project: String,
        #[arg(long)]
        env: String,
    },
    /// List a project's mappings.
    List {
        #[arg(long)]
        project: String,
    },
}

pub fn mapping(ctx: &Ctx, cmd: MappingCmd) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    match cmd {
        MappingCmd::Set {
            project,
            credential,
            env,
        } => {
            vault.set_env_mapping(&project, &credential, &env)?;
            println!("Mapped '{credential}' -> ${env} in project '{project}'.");
        }
        MappingCmd::Remove { project, env } => {
            if vault.remove_env_mapping(&project, &env)? {
                println!("Removed mapping for ${env}.");
            } else {
                println!("No mapping for ${env}.");
            }
        }
        MappingCmd::List { project } => {
            let maps = vault.list_env_mappings(&project)?;
            render::emit(ctx.json, &maps, || {
                if maps.is_empty() {
                    println!("No mappings configured.");
                } else {
                    let rows: Vec<Vec<String>> = maps
                        .iter()
                        .map(|m| vec![m.env_var.clone(), m.credential_name.clone()])
                        .collect();
                    render::table(&["ENV VAR", "CREDENTIAL"], &rows);
                }
            });
        }
    }
    Ok(())
}
