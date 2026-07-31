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
                // Additive only: `totals` and `records` keep their exact
                // shape and meaning (`totals` itself gained residual
                // `*_rows` counts, which are new keys, not repurposed
                // ones). `availability` is the pre-computed verdict for
                // each folded number so a JSON consumer does not have to
                // re-derive the rule and drift from the CLI and desktop.
                render::emit(
                    true,
                    &serde_json::json!({
                        "totals": totals,
                        "records": rows,
                        "connection": connection,
                        "availability": {
                            "requests": totals.request_availability(),
                            "input_tokens": totals.input_token_availability(),
                            "output_tokens": totals.output_token_availability(),
                            "total_tokens": totals.total_token_availability(),
                            "reported_cost": totals.reported_cost_availability(),
                            "estimated_cost": totals.estimated_cost_availability(),
                        },
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

/// What a per-record table cell says when the record did not carry that
/// measurement. Never blank and never a zero.
const NOT_REPORTED: &str = "not reported";

fn print_usage_report(
    totals: &usage::UsageTotals,
    start: &str,
    rows: &[usage::UsageSnapshot],
    connection: Option<&api_tracker_core::vault::ProviderConnection>,
    limit: usize,
) {
    println!("Usage since {start} (current month):");
    // `Snapshots` is a count of the rows in scope, so it is always known —
    // it is the denominator every other line's availability is measured
    // against. Everything below folds `Option` columns, and is printed only
    // when the records in scope actually carried the value: an absent token
    // count or cost is a state, never a silent 0 / $0.00 (NEW-37).
    println!("  Snapshots:      {}", totals.snapshots);
    println!(
        "  Requests:       {}",
        usage::render_count(
            totals.request_count,
            &totals.request_availability(),
            &usage::SUBJECT_REQUESTS
        )
    );
    println!(
        "  Input tokens:   {}",
        usage::render_count(
            totals.input_tokens,
            &totals.input_token_availability(),
            &usage::SUBJECT_INPUT_TOKENS
        )
    );
    println!(
        "  Output tokens:  {}",
        usage::render_count(
            totals.output_tokens,
            &totals.output_token_availability(),
            &usage::SUBJECT_OUTPUT_TOKENS
        )
    );
    println!(
        "  Total tokens:   {}",
        usage::render_count(
            totals.total_tokens,
            &totals.total_token_availability(),
            &usage::SUBJECT_TOTAL_TOKENS
        )
    );
    let reported = totals.reported_cost_availability();
    println!(
        "  Reported cost:  {}{}",
        usage::render_micros(
            totals.reported_cost_micros,
            &reported,
            &usage::SUBJECT_REPORTED_COST
        ),
        if reported.has_value() {
            " (provider-reported)"
        } else {
            ""
        }
    );
    let estimated = totals.estimated_cost_availability();
    println!(
        "  Estimated cost: {}{}",
        usage::render_micros(
            totals.estimated_cost_micros,
            &estimated,
            &usage::SUBJECT_ESTIMATED_COST
        ),
        if estimated.has_value() {
            " (estimated locally — may differ from the provider's bill)"
        } else {
            ""
        }
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
                // Per-record measurements: a column the record did not
                // carry says so. A blank cell reads as "nothing was used",
                // which is the same fabrication as a zero (NEW-37).
                match (r.total_tokens, r.quantity, r.unit.as_deref()) {
                    // Non-token units are shown verbatim, never as tokens.
                    (_, Some(q), Some(unit)) => format!("{q} {unit}"),
                    (Some(t), _, _) => format!("{t} tokens"),
                    _ => NOT_REPORTED.to_string(),
                },
                r.reported_cost_micros
                    .map(usage::format_micros)
                    .unwrap_or_else(|| NOT_REPORTED.to_string()),
                r.estimated_cost_micros
                    .map(|m| format!("{} (est.)", usage::format_micros(m)))
                    .unwrap_or_else(|| NOT_REPORTED.to_string()),
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
    // `used_micros` is a floor whenever some record in scope carried no
    // cost, so it is labelled "at least" rather than printed as if it were
    // the whole spend (NEW-37).
    println!(
        "  Used:          {}{} ({}; source setting: {}) — {} of {} usage record(s) costed",
        if r.used_is_complete { "" } else { "at least " },
        usage::format_micros(r.used_micros),
        if r.used_is_estimated {
            "estimated"
        } else {
            "provider-reported"
        },
        r.cost_source,
        r.costed_rows,
        r.usage_rows
    );
    if let Some(rem) = r.remaining_micros {
        println!(
            "  Remaining:     {}{}",
            usage::format_micros(rem),
            if r.used_is_complete {
                ""
            } else {
                " (at most — computed from a floor on spend)"
            }
        );
    }
    println!(
        "  Projected end: {}{}",
        usage::format_micros(r.projected_period_end_micros),
        if r.used_is_complete {
            ""
        } else {
            " (at least — projected from a floor on spend)"
        }
    );
    match r.status {
        budget::BudgetStatus::Over => println!("  STATUS: OVER BUDGET"),
        budget::BudgetStatus::Under => println!("  STATUS: under budget"),
        // Never printed as "under budget": the costed floor is below the
        // budget, but records that carried no cost are not zero, so the
        // true spend is unknown and may be over.
        budget::BudgetStatus::Indeterminate => {
            println!("  STATUS: CANNOT EVALUATE — usage data is incomplete");
            if let Some(note) = &r.completeness_note {
                println!("  {note}");
            }
        }
        budget::BudgetStatus::NoBudget => println!("  STATUS: no budget set"),
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
