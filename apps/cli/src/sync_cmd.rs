//! `api-tracker sync` — synchronization plans for credential value changes.
//!
//! Plans are dry runs by default: `sync plan` writes nothing anywhere.
//! `sync run` executes after explicit confirmation and master-password
//! reauthentication. Output shows masked values and version numbers only.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::syncplan::SyncPlan;
use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum SyncCmd {
    /// Generate a plan (dry run — nothing is written anywhere).
    Plan(PlanArgs),
    /// Show a plan.
    Show(ShowArgs),
    /// List plans.
    List(ListArgs),
    /// Execute a plan's pending/failed steps (reauth + confirmation).
    Run(RunArgs),
    /// Roll executed steps back to the previous retained version.
    Rollback(RollbackArgs),
}

#[derive(Args)]
pub struct PlanArgs {
    /// Credential selector (project/name or id).
    pub credential: String,
    /// A note describing why (e.g. "rotate after laptop loss").
    #[arg(long, default_value = "")]
    pub note: String,
}

#[derive(Args)]
pub struct ShowArgs {
    /// Plan id.
    pub plan: String,
}

#[derive(Args)]
pub struct ListArgs {
    /// Limit to one credential.
    #[arg(long)]
    pub credential: Option<String>,
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
}

#[derive(Args)]
pub struct RunArgs {
    /// Plan id.
    pub plan: String,
    /// Execute only this destination (name or id) — per-destination rollout.
    #[arg(long)]
    pub destination: Option<String>,
    /// Confirm non-interactively.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct RollbackArgs {
    /// Plan id.
    pub plan: String,
    /// Roll back only this destination.
    #[arg(long)]
    pub destination: Option<String>,
    /// Confirm non-interactively.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(ctx: &Ctx, cmd: SyncCmd) -> Result<()> {
    match cmd {
        SyncCmd::Plan(args) => plan(ctx, args),
        SyncCmd::Show(args) => show(ctx, args),
        SyncCmd::List(args) => list(ctx, args),
        SyncCmd::Run(args) => execute(ctx, args),
        SyncCmd::Rollback(args) => rollback(ctx, args),
    }
}

fn print_plan(plan: &SyncPlan) {
    println!("Plan:       {}", plan.id);
    let from_label = plan
        .from_version
        .map(|v| format!("v{v} {}", plan.from_masked.as_deref().unwrap_or("")))
        .unwrap_or_else(|| "no prior version".into());
    println!(
        "Credential: {}/{} ({from_label} → v{} {})",
        plan.project_name, plan.credential_name, plan.to_version, plan.to_masked,
    );
    println!("Status:     {}", plan.status);
    println!("Created:    {}", plan.created_at);
    if !plan.note.is_empty() {
        println!("Note:       {}", plan.note);
    }
    println!("Affected projects: {}", plan.affected_projects.join(", "));
    if plan.steps.is_empty() {
        println!("\nNo destinations are attached to this credential — nothing to synchronize.");
        println!("Attach one with `destination attach` or map variables with `mapping set`.");
        return;
    }
    println!();
    let rows: Vec<Vec<String>> = plan
        .steps
        .iter()
        .map(|s| {
            vec![
                s.destination_name.clone(),
                s.destination_kind.clone(),
                s.secret_name.clone(),
                s.action.clone(),
                s.status.clone(),
                if s.rollback_available { "yes" } else { "no" }.into(),
                s.validation.clone(),
            ]
        })
        .collect();
    render::table(
        &[
            "DESTINATION",
            "KIND",
            "SECRET",
            "ACTION",
            "STATUS",
            "ROLLBACK",
            "VALIDATION",
        ],
        &rows,
    );
    for step in &plan.steps {
        if !step.detail.is_empty() {
            println!("  {} — {}", step.destination_name, step.detail);
        }
    }
    if !plan.manual_steps.is_empty() {
        println!("\nManual steps you must perform yourself:");
        for manual in &plan.manual_steps {
            println!("  - {manual}");
        }
    }
    if plan.status == "stale" {
        println!(
            "\nThis plan is STALE: the credential changed after it was created. \
             Generate a new plan."
        );
    }
}

fn plan(ctx: &Ctx, args: PlanArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let plan = vault.sync_plan_create(&args.credential, &args.note)?;
    render::emit(ctx.json, &plan, || {
        print_plan(&plan);
        println!(
            "\nDry run — nothing was written. Execute with `sync run {}`.",
            plan.id
        );
    });
    Ok(())
}

fn show(ctx: &Ctx, args: ShowArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let plan = vault.sync_plan_get(&args.plan)?;
    render::emit(ctx.json, &plan, || print_plan(&plan));
    Ok(())
}

fn list(ctx: &Ctx, args: ListArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let plans = vault.sync_plans(args.credential.as_deref(), args.limit)?;
    render::emit(ctx.json, &plans, || {
        if plans.is_empty() {
            println!("No plans. Create one with `sync plan <credential>`.");
            return;
        }
        let rows: Vec<Vec<String>> = plans
            .iter()
            .map(|p| {
                vec![
                    p.id.clone(),
                    format!("{}/{}", p.project_name, p.credential_name),
                    format!(
                        "{} → v{}",
                        p.from_version
                            .map(|v| format!("v{v}"))
                            .unwrap_or_else(|| "-".into()),
                        p.to_version
                    ),
                    p.status.clone(),
                    p.created_at.clone(),
                ]
            })
            .collect();
        render::table(
            &["PLAN", "CREDENTIAL", "VERSIONS", "STATUS", "CREATED"],
            &rows,
        );
    });
    Ok(())
}

fn execute(ctx: &Ctx, args: RunArgs) -> Result<()> {
    let (mut vault, token) = ctx.unlocked()?;
    let plan = vault.sync_plan_get(&args.plan)?;
    print_plan(&plan);
    let pending: Vec<&api_tracker_core::syncplan::SyncStep> = plan
        .steps
        .iter()
        .filter(|s| matches!(s.status.as_str(), "planned" | "failed"))
        .filter(|s| s.action == "write" || s.action == "reexport" || s.action == "none")
        .collect();
    if pending.is_empty() {
        println!("\nNothing to execute (no pending or failed steps).");
        return Ok(());
    }
    println!();
    if !ctx::confirm(
        &format!(
            "Execute {} step(s){} now? Values are written directly from this machine.",
            pending.len(),
            args.destination
                .as_deref()
                .map(|d| format!(" for destination '{d}'"))
                .unwrap_or_default()
        ),
        args.yes,
    )? {
        bail!("cancelled — nothing was written");
    }
    let password = ctx::master_password()?;
    let http = api_tracker_core::http::UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    let executed = vault.sync_plan_execute(
        &args.plan,
        args.destination.as_deref(),
        &password,
        &http,
        &runner,
    )?;
    ctx.persist_session(&vault, &token)?;
    println!();
    print_plan(&executed);
    if executed.status == "partially_failed" {
        println!(
            "\nSome steps failed. Fix the cause and retry with \
             `sync run {}` (only pending/failed steps re-run), or roll back with \
             `sync rollback {}`.",
            executed.id, executed.id
        );
    }
    Ok(())
}

fn rollback(ctx: &Ctx, args: RollbackArgs) -> Result<()> {
    let (mut vault, token) = ctx.unlocked()?;
    let plan = vault.sync_plan_get(&args.plan)?;
    let Some(from_version) = plan.from_version else {
        bail!("this plan has no previous version to roll back to");
    };
    print_plan(&plan);
    println!();
    if !ctx::confirm(
        &format!(
            "Roll executed steps back to v{from_version} {}?",
            plan.from_masked.as_deref().unwrap_or("")
        ),
        args.yes,
    )? {
        bail!("cancelled — nothing was written");
    }
    let password = ctx::master_password()?;
    let http = api_tracker_core::http::UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    let rolled = vault.sync_plan_rollback(
        &args.plan,
        args.destination.as_deref(),
        &password,
        &http,
        &runner,
    )?;
    ctx.persist_session(&vault, &token)?;
    println!();
    print_plan(&rolled);
    println!(
        "\nNote: the VAULT still holds v{}. Rollback restored destinations only; \
         to change the vault value too, use `key update --new-value`.",
        plan.to_version
    );
    Ok(())
}
