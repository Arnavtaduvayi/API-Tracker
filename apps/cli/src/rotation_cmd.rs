//! `tethra rotation` — safe, durable credential rotation.
//!
//! `plan` is a dry run. `approve`, `advance`, `provide-key`, `rollback`,
//! `complete-manual`, and `cancel` are reauthentication-gated. Nothing here
//! ever prints a secret value; provider-side calls happen only inside
//! `advance`/`rollback` after explicit approval.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::vault::RotationView;
use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum RotationCmd {
    /// Build a rotation dry run (writes nothing anywhere).
    Plan(PlanArgs),
    /// Approve a planned rotation (reauthentication required).
    Approve {
        rotation: String,
        /// Confirm non-interactively.
        #[arg(long)]
        yes: bool,
    },
    /// Advance a rotation as far as it can go (reauthentication required).
    Advance(AdvanceArgs),
    /// Provide the manually created replacement key (stdin or hidden prompt).
    ProvideKey(ProvideKeyArgs),
    /// Show a rotation.
    Show { rotation: String },
    /// Show a rotation's full transition history.
    Events { rotation: String },
    /// List rotations.
    List(ListArgs),
    /// Roll a rotation back (destinations, vault value, provider state).
    Rollback(RollbackArgs),
    /// Confirm the remaining manual provider-side steps are done.
    CompleteManual(CompleteManualArgs),
    /// Cancel a rotation that has not changed anything yet.
    Cancel {
        rotation: String,
        /// Confirm non-interactively.
        #[arg(long)]
        yes: bool,
    },
    /// Manage rotation schedules (reminders — never automatic execution).
    #[command(subcommand)]
    Schedule(ScheduleCmd),
}

#[derive(Args)]
pub struct PlanArgs {
    /// Credential selector (project/name or id).
    pub credential: String,
    /// Overlap period between deploying the new key and disabling the old.
    #[arg(long, default_value_t = 60)]
    pub grace_minutes: i64,
    /// Provider-side project for API key creation (OpenAI project id /
    /// Supabase project ref). Derived from the linked key when omitted.
    #[arg(long)]
    pub provider_project: Option<String>,
    /// Provider-side id of the OLD key (see `provider keys`).
    #[arg(long)]
    pub old_key_id: Option<String>,
    #[arg(long, default_value = "")]
    pub note: String,
}

#[derive(Args)]
pub struct AdvanceArgs {
    pub rotation: String,
    /// Proceed although provider data shows activity on the old key.
    #[arg(long)]
    pub acknowledge_continued_use: bool,
}

#[derive(Args)]
pub struct ProvideKeyArgs {
    pub rotation: String,
    /// Read the replacement value from stdin (never from an argument).
    #[arg(long)]
    pub value_stdin: bool,
}

#[derive(Args)]
pub struct ListArgs {
    #[arg(long)]
    pub credential: Option<String>,
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
}

#[derive(Args)]
pub struct RollbackArgs {
    pub rotation: String,
    /// Also revoke the replacement key this rotation created.
    #[arg(long)]
    pub revoke_new: bool,
    /// Confirm non-interactively.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct CompleteManualArgs {
    pub rotation: String,
    /// What you did (recorded in the audit trail).
    #[arg(long, default_value = "manual provider-side steps done")]
    pub note: String,
    /// Confirm non-interactively.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Subcommand)]
pub enum ScheduleCmd {
    /// Enable a schedule (needs one completed rotation first).
    Set {
        credential: String,
        #[arg(long)]
        every_days: i64,
    },
    /// Remove a schedule.
    Remove { credential: String },
    /// List schedules.
    List,
}

pub fn run(ctx: &Ctx, cmd: RotationCmd) -> Result<()> {
    match cmd {
        RotationCmd::Plan(args) => plan(ctx, args),
        RotationCmd::Approve { rotation, yes } => approve(ctx, &rotation, yes),
        RotationCmd::Advance(args) => advance(ctx, args, None),
        RotationCmd::ProvideKey(args) => provide_key(ctx, args),
        RotationCmd::Show { rotation } => show(ctx, &rotation),
        RotationCmd::Events { rotation } => events(ctx, &rotation),
        RotationCmd::List(args) => list(ctx, args),
        RotationCmd::Rollback(args) => rollback(ctx, args),
        RotationCmd::CompleteManual(args) => complete_manual(ctx, args),
        RotationCmd::Cancel { rotation, yes } => cancel(ctx, &rotation, yes),
        RotationCmd::Schedule(cmd) => schedule(ctx, cmd),
    }
}

fn print_rotation(view: &RotationView) {
    let r = &view.rotation;
    println!("Rotation:   {}", r.id);
    println!(
        "Credential: {}/{} ({})",
        view.project_name, view.credential_name, r.provider
    );
    println!("State:      {}", r.state);
    println!(
        "Mode:       {}",
        if r.mode == "api_create" {
            "API creation (provider admin connection)"
        } else {
            "manual creation (provider dashboard)"
        }
    );
    if !r.note.is_empty() {
        println!("Note:       {}", r.note);
    }
    println!("Grace:      {} minute(s)", r.grace_minutes);
    if let Some(ends) = &r.grace_ends_at {
        println!("Grace ends: {ends}");
    }
    if let (Some(old), Some(new)) = (r.old_version, r.new_version) {
        println!("Versions:   v{old} → v{new}");
    }
    if let Some(id) = &r.old_provider_key_id {
        println!("Old key id: {id}");
    }
    if let Some(id) = &r.new_provider_key_id {
        println!("New key id: {id}");
    }
    println!(
        "New value validated: {}",
        if r.new_value_validated {
            "yes"
        } else {
            "not yet"
        }
    );
    if let Some(at) = &r.old_disabled_at {
        println!("Old disabled: {at}");
    }
    if let Some(at) = &r.old_revoked_at {
        println!("Old revoked:  {at}");
    }
    if !r.last_error.is_empty() {
        println!("\nLast error: {}", r.last_error);
    }
    if !r.manual_instructions.is_empty() {
        println!("\nManual steps:");
        for line in r.manual_instructions.lines() {
            println!("  - {line}");
        }
    }
    if let Some(waiting) = &view.waiting_on {
        println!("\nWaiting on: {waiting}");
    }
}

fn plan(ctx: &Ctx, args: PlanArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let view = vault.rotation_plan(
        &args.credential,
        args.grace_minutes,
        args.provider_project.as_deref(),
        args.old_key_id.as_deref(),
        &args.note,
    )?;
    render::emit(ctx.json, &view, || {
        print_rotation(&view);
        println!(
            "\nDry run — nothing was changed at any provider or destination (only this \
             plan record was saved). Review, then `rotation approve {}`.",
            view.rotation.id
        );
    });
    Ok(())
}

fn approve(ctx: &Ctx, rotation: &str, yes: bool) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let view = vault.rotation_get(rotation)?;
    print_rotation(&view);
    println!();
    if !ctx::confirm(
        "Approve this rotation? Subsequent steps will create a replacement, update \
         destinations, and eventually disable/revoke the OLD key.",
        yes,
    )? {
        bail!("not approved");
    }
    let password = ctx::master_password()?;
    let view = vault.rotation_approve(rotation, &password)?;
    println!(
        "Approved. Run `rotation advance {}` to start executing.",
        view.rotation.id
    );
    Ok(())
}

fn advance(
    ctx: &Ctx,
    args: AdvanceArgs,
    provide_value: Option<api_tracker_core::secret::SecretString>,
) -> Result<()> {
    let (mut vault, token) = ctx.unlocked()?;
    let password = ctx::master_password()?;
    let http = api_tracker_core::http::UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    let view = vault.rotation_advance(
        &args.rotation,
        &password,
        &http,
        &runner,
        provide_value,
        args.acknowledge_continued_use,
    )?;
    ctx.persist_session(&vault, &token)?;
    render::emit(ctx.json, &view, || {
        print_rotation(&view);
        match view.rotation.state.as_str() {
            "completed" => println!("\nRotation completed."),
            "manual_required" => println!("\nManual provider-side action is required (above)."),
            _ if view.waiting_on.is_some() => {
                println!("\nRun `rotation advance` again when ready.")
            }
            _ => {}
        }
    });
    Ok(())
}

fn provide_key(ctx: &Ctx, args: ProvideKeyArgs) -> Result<()> {
    let value = ctx::credential_value(args.value_stdin)?;
    advance(
        ctx,
        AdvanceArgs {
            rotation: args.rotation,
            acknowledge_continued_use: false,
        },
        Some(value),
    )
}

fn show(ctx: &Ctx, rotation: &str) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let view = vault.rotation_get(rotation)?;
    render::emit(ctx.json, &view, || print_rotation(&view));
    Ok(())
}

fn events(ctx: &Ctx, rotation: &str) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let events = vault.rotation_events(rotation)?;
    render::emit(ctx.json, &events, || {
        let rows: Vec<Vec<String>> = events
            .iter()
            .map(|e| {
                vec![
                    e.at.clone(),
                    if e.from_state.is_empty() {
                        e.to_state.clone()
                    } else if e.from_state == e.to_state {
                        format!("({})", e.to_state)
                    } else {
                        format!("{} → {}", e.from_state, e.to_state)
                    },
                    e.detail.clone(),
                ]
            })
            .collect();
        render::table(&["AT", "TRANSITION", "DETAIL"], &rows);
    });
    Ok(())
}

fn list(ctx: &Ctx, args: ListArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let rotations = vault.rotations(args.credential.as_deref(), args.limit)?;
    render::emit(ctx.json, &rotations, || {
        if rotations.is_empty() {
            println!("No rotations. Start one with `rotation plan <credential>`.");
            return;
        }
        let rows: Vec<Vec<String>> = rotations
            .iter()
            .map(|v| {
                vec![
                    v.rotation.id.clone(),
                    format!("{}/{}", v.project_name, v.credential_name),
                    v.rotation.state.clone(),
                    v.rotation.mode.clone(),
                    v.rotation.created_at.clone(),
                    v.waiting_on.clone().unwrap_or_else(|| "-".into()),
                ]
            })
            .collect();
        render::table(
            &[
                "ROTATION",
                "CREDENTIAL",
                "STATE",
                "MODE",
                "CREATED",
                "WAITING ON",
            ],
            &rows,
        );
    });
    Ok(())
}

fn rollback(ctx: &Ctx, args: RollbackArgs) -> Result<()> {
    let (mut vault, token) = ctx.unlocked()?;
    let view = vault.rotation_get(&args.rotation)?;
    print_rotation(&view);
    println!();
    if !ctx::confirm(
        &format!(
            "Roll this rotation back? Destinations and the vault value return to \
             v{}{}.",
            view.rotation.old_version.unwrap_or(0),
            if args.revoke_new {
                "; the replacement key will be REVOKED at the provider"
            } else {
                " (the replacement key stays valid — pass --revoke-new to revoke it)"
            }
        ),
        args.yes,
    )? {
        bail!("cancelled — nothing was changed");
    }
    let password = ctx::master_password()?;
    let http = api_tracker_core::http::UreqClient::new();
    let runner = api_tracker_core::destinations::SystemRunner;
    let view =
        vault.rotation_rollback(&args.rotation, &password, &http, &runner, args.revoke_new)?;
    ctx.persist_session(&vault, &token)?;
    print_rotation(&view);
    Ok(())
}

fn complete_manual(ctx: &Ctx, args: CompleteManualArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    if !ctx::confirm(
        "Confirm that you performed the manual provider-side steps (e.g. revoked the \
         old key in the dashboard)?",
        args.yes,
    )? {
        bail!("cancelled");
    }
    let password = ctx::master_password()?;
    let view = vault.rotation_complete_manual(&args.rotation, &password, &args.note)?;
    print_rotation(&view);
    Ok(())
}

fn cancel(ctx: &Ctx, rotation: &str, yes: bool) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    if !ctx::confirm("Cancel this rotation?", yes)? {
        bail!("kept");
    }
    let password = ctx::master_password()?;
    let view = vault.rotation_cancel(rotation, &password)?;
    println!("Cancelled (state: {}).", view.rotation.state);
    Ok(())
}

fn schedule(ctx: &Ctx, cmd: ScheduleCmd) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    match cmd {
        ScheduleCmd::Set {
            credential,
            every_days,
        } => {
            vault.rotation_schedule_set(&credential, every_days)?;
            println!(
                "Scheduled: a rotation of '{credential}' becomes DUE every {every_days} day(s).\n\
                 Nothing runs automatically — when due, the monitor raises an alert (and a \
                 desktop notification) and every destructive step still needs your approval \
                 and password."
            );
        }
        ScheduleCmd::Remove { credential } => {
            if vault.rotation_schedule_remove(&credential)? {
                println!("Schedule removed.");
            } else {
                println!("No schedule existed.");
            }
        }
        ScheduleCmd::List => {
            let schedules = vault.rotation_schedules()?;
            render::emit(ctx.json, &schedules, || {
                if schedules.is_empty() {
                    println!("No rotation schedules.");
                    return;
                }
                let rows: Vec<Vec<String>> = schedules
                    .iter()
                    .map(|s| {
                        vec![
                            s.credential_id.clone(),
                            format!("every {} day(s)", s.interval_days),
                            s.next_due_at.clone(),
                            if s.enabled {
                                "enabled".into()
                            } else {
                                format!("PAUSED: {}", s.paused_reason)
                            },
                        ]
                    })
                    .collect();
                render::table(&["CREDENTIAL", "INTERVAL", "NEXT DUE", "STATUS"], &rows);
            });
        }
    }
    Ok(())
}
