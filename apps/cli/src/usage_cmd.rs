//! `usage`, `budget`, `activity`, and `mapping` subcommands.

use crate::ctx::Ctx;
use crate::render;
use anyhow::Result;
use api_tracker_core::http::UreqClient;
use api_tracker_core::{budget, clock, usage};
use clap::Subcommand;

#[derive(Subcommand)]
pub enum UsageCmd {
    /// Sync usage from a provider using its administrative connection.
    Sync {
        provider: String,
        /// Look back this many days (default: incremental from checkpoint).
        #[arg(long)]
        days: Option<u32>,
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
        /// Only this provider's usage (also shows its sync freshness).
        #[arg(long)]
        provider: Option<String>,
        /// Which records to include: all, provider (synced), or manual.
        #[arg(long, default_value = "all")]
        source: String,
        /// How many individual records to list (0 hides the listing).
        #[arg(long, default_value_t = 15)]
        limit: usize,
    },
}

pub fn usage(ctx: &Ctx, cmd: UsageCmd) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    match cmd {
        UsageCmd::Sync { provider, days } => {
            let http = UreqClient::new();
            let report = match days {
                Some(days) => vault.usage_sync(&provider, &http, days)?,
                None => vault.usage_sync_default(&provider, &http)?,
            };
            println!(
                "Synced {} usage row(s) and {} provider-reported cost row(s) for {provider}.",
                report.usage_rows, report.cost_rows
            );
            for note in &report.notes {
                println!("NOTE: {note}");
            }
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
            provider,
            source,
            limit,
        } => {
            let source_filter = match source.as_str() {
                "all" => usage::SourceFilter::All,
                "provider" => usage::SourceFilter::Provider,
                "manual" => usage::SourceFilter::Manual,
                other => anyhow::bail!("unknown --source '{other}' (use all, provider, or manual)"),
            };
            let start = budget::period_start(clock::now());
            let (totals, rows) = vault.usage_report(
                &start,
                credential.as_deref(),
                project.as_deref(),
                provider.as_deref(),
                source_filter,
            )?;
            let connection = match provider.as_deref() {
                Some(p) => Some(vault.provider_connection_status(p)?),
                None => None,
            };
            if ctx.json {
                render::emit(
                    true,
                    &serde_json::json!({
                        "totals": totals,
                        "records": rows,
                        "connection": connection,
                    }),
                    || {},
                );
            } else {
                print_usage_report(&totals, &start, &rows, connection.as_ref(), limit);
            }
        }
    }
    Ok(())
}

fn print_usage_report(
    totals: &usage::UsageTotals,
    start: &str,
    rows: &[usage::UsageSnapshot],
    connection: Option<&api_tracker_core::vault::ProviderConnection>,
    limit: usize,
) {
    println!("Usage since {start} (current month):");
    println!("  Snapshots:      {}", totals.snapshots);
    println!("  Requests:       {}", totals.request_count);
    println!("  Input tokens:   {}", totals.input_tokens);
    println!("  Output tokens:  {}", totals.output_tokens);
    println!("  Total tokens:   {}", totals.total_tokens);
    println!(
        "  Reported cost:  {} (provider-reported)",
        usage::format_micros(totals.reported_cost_micros)
    );
    println!(
        "  Estimated cost: {} (estimated locally — may differ from the provider's bill)",
        usage::format_micros(totals.estimated_cost_micros)
    );
    if totals.has_non_usd_reported {
        println!(
            "  NOTE: non-USD provider costs exist ({}) and are excluded from the USD total.",
            totals.reported_currencies.join(", ")
        );
    }
    if let Some(attr) = &totals.coarsest_attribution {
        let a: usage::Attribution = attr.parse().unwrap_or(usage::Attribution::Unknown);
        println!("  Attribution:    coarsest level present: {}", a.label());
    }
    if totals.has_inexact_attribution {
        println!("  NOTE: some usage is not exact per-key; it is not charged to one credential.");
    }
    if let Some(c) = connection {
        println!(
            "  Last sync:      {} (status: {})",
            c.last_success_at.as_deref().unwrap_or("never"),
            c.last_status
        );
        if c.stale {
            println!(
                "  WARNING: synced data is STALE — run `tethra provider sync {}`.",
                c.provider
            );
        }
    }
    if limit == 0 || rows.is_empty() {
        return;
    }
    println!();
    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .take(limit)
        .map(|r| {
            let attribution: usage::Attribution =
                r.attribution.parse().unwrap_or(usage::Attribution::Unknown);
            vec![
                r.window_start
                    .get(..10)
                    .unwrap_or(&r.window_start)
                    .to_string(),
                r.model
                    .clone()
                    .or_else(|| r.line_item.clone())
                    .unwrap_or_default(),
                match (r.total_tokens, r.quantity, r.unit.as_deref()) {
                    // Non-token units are shown verbatim, never as tokens.
                    (_, Some(q), Some(unit)) => format!("{q} {unit}"),
                    (Some(t), _, _) => format!("{t} tokens"),
                    _ => String::new(),
                },
                r.reported_cost_micros
                    .map(usage::format_micros)
                    .unwrap_or_default(),
                r.estimated_cost_micros
                    .map(|m| format!("{} (est.)", usage::format_micros(m)))
                    .unwrap_or_default(),
                attribution.as_str().to_string(),
                r.provider_api_key_id
                    .clone()
                    .or_else(|| r.provider_project_id.clone())
                    .unwrap_or_default(),
                r.source.clone(),
            ]
        })
        .collect();
    render::table(
        &[
            "WINDOW",
            "MODEL/ITEM",
            "USAGE",
            "REPORTED",
            "ESTIMATED",
            "ATTRIBUTION",
            "PROVIDER KEY/PROJECT",
            "SOURCE",
        ],
        &table_rows,
    );
    if rows.len() > limit {
        println!(
            "… {} more record(s); raise --limit to see them.",
            rows.len() - limit
        );
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
    /// Show or set which cost source budgets consume:
    /// best_available (default), provider_reported, or estimated.
    Source {
        /// New value; omit to show the current one.
        value: Option<String>,
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
        BudgetCmd::Source { value } => match value {
            Some(v) => {
                let source: usage::CostSource = v.parse()?;
                vault.set_budget_cost_source(source)?;
                println!("Budgets now use the '{}' cost source.", source.as_str());
            }
            None => {
                let source = vault.budget_cost_source()?;
                println!("Budgets use the '{}' cost source.", source.as_str());
                println!(
                    "Options: best_available (provider-reported when present, else estimated), \
                     provider_reported, estimated."
                );
            }
        },
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
        "  Used:          {} ({}; source setting: {})",
        usage::format_micros(r.used_micros),
        if r.used_is_estimated {
            "estimated"
        } else {
            "provider-reported"
        },
        r.cost_source
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
