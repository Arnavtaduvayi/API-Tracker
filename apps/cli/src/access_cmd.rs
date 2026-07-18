//! `api-tracker access` — temporary LOCAL access grants for `run`.
//!
//! Grants bound what `run` will inject on this machine (time window, launch
//! count, per-process duration, credential subset). They are local controls:
//! ending a grant stops NEW launches and can terminate recorded processes,
//! but it does not revoke the provider credential and never claims to.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum AccessCmd {
    /// Create a grant.
    Grant(GrantArgs),
    /// List grants.
    List {
        /// Include expired/revoked/used-up grants.
        #[arg(long)]
        all: bool,
    },
    /// End a grant now (stops new launches; --kill terminates recorded
    /// running processes).
    End(EndArgs),
}

#[derive(Args)]
pub struct GrantArgs {
    /// Project whose credentials the grant may inject.
    #[arg(long)]
    pub project: String,
    /// Limit to specific credential(s); default: the project's mappings.
    #[arg(long = "credential", value_name = "CREDENTIAL")]
    pub credentials: Vec<String>,
    /// Grant lifetime in minutes.
    #[arg(long, default_value_t = 60)]
    pub ttl_minutes: u64,
    /// Maximum launches (0 = unlimited within the window).
    #[arg(long, default_value_t = 0)]
    pub max_launches: i64,
    /// Shorthand for --max-launches 1.
    #[arg(long)]
    pub one_time: bool,
    /// Kill each launched process after this many seconds.
    #[arg(long)]
    pub max_duration_secs: Option<i64>,
    /// Print an advisory warning when month-to-date recorded cost reaches
    /// this amount (e.g. 5.00). Advisory only — cannot cap provider spend.
    #[arg(long, value_name = "DOLLARS")]
    pub budget_warn: Option<String>,
    #[arg(long, default_value = "")]
    pub label: String,
}

#[derive(Args)]
pub struct EndArgs {
    pub grant: String,
    /// Send SIGTERM to recorded running processes of this grant.
    #[arg(long)]
    pub kill: bool,
    /// Confirm non-interactively.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(ctx: &Ctx, cmd: AccessCmd) -> Result<()> {
    match cmd {
        AccessCmd::Grant(args) => grant(ctx, args),
        AccessCmd::List { all } => list(ctx, all),
        AccessCmd::End(args) => end(ctx, args),
    }
}

fn grant(ctx: &Ctx, args: GrantArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let max_launches = if args.one_time { 1 } else { args.max_launches };
    let grant = vault.access_grant_create(
        &args.project,
        &args.label,
        &args.credentials,
        args.ttl_minutes,
        max_launches,
        args.max_duration_secs,
        args.budget_warn.as_deref(),
    )?;
    render::emit(ctx.json, &grant, || {
        println!("Grant {} created.", grant.id);
        println!("  Expires:  {}", grant.expires_at);
        println!(
            "  Launches: {}",
            if grant.max_launches == 0 {
                "unlimited within the window".to_string()
            } else {
                format!("{} max", grant.max_launches)
            }
        );
        if let Some(secs) = grant.max_duration_secs {
            println!("  Each process is terminated after {secs}s.");
        }
        println!(
            "\nRun with it:\n  api-tracker run --grant {} -- <command>",
            grant.id
        );
        println!(
            "\nThese are LOCAL controls: they bound what this machine injects. The \
             provider credential itself stays valid — local expiry is not revocation."
        );
    });
    Ok(())
}

fn list(ctx: &Ctx, all: bool) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let grants = vault.access_grants(all)?;
    let now = api_tracker_core::clock::now_rfc3339();
    render::emit(ctx.json, &grants, || {
        if grants.is_empty() {
            println!("No grants. Create one with `access grant --project <p>`.");
            return;
        }
        let rows: Vec<Vec<String>> = grants
            .iter()
            .map(|g| {
                vec![
                    g.id.clone(),
                    g.label.clone(),
                    g.status(&now).to_string(),
                    g.expires_at.clone(),
                    if g.max_launches == 0 {
                        format!("{}", g.launches_used)
                    } else {
                        format!("{}/{}", g.launches_used, g.max_launches)
                    },
                    g.max_duration_secs
                        .map(|s| format!("{s}s"))
                        .unwrap_or_else(|| "-".into()),
                ]
            })
            .collect();
        render::table(
            &[
                "GRANT", "LABEL", "STATUS", "EXPIRES", "LAUNCHES", "PROC TTL",
            ],
            &rows,
        );
    });
    Ok(())
}

fn end(ctx: &Ctx, args: EndArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    if !ctx::confirm(
        &format!(
            "End grant {}? New launches are refused immediately{}.",
            args.grant,
            if args.kill {
                "; recorded running processes receive SIGTERM"
            } else {
                " (running processes keep running — pass --kill to terminate them)"
            }
        ),
        args.yes,
    )? {
        bail!("kept");
    }
    let (grant, running) = vault.access_grant_end(&args.grant)?;
    println!("Grant {} ended.", grant.id);
    if running.is_empty() {
        println!("No recorded running processes.");
    } else {
        for (session, pid) in &running {
            if args.kill {
                let killed = std::process::Command::new("kill")
                    .arg(pid.to_string())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                println!(
                    "  session {session}: pid {pid} — {}",
                    if killed {
                        "SIGTERM sent"
                    } else {
                        "kill failed (already gone?)"
                    }
                );
            } else {
                println!("  session {session}: pid {pid} still running");
            }
        }
    }
    println!(
        "Reminder: values already injected into a process remain in its environment \
         until it exits, and the provider credential itself stays valid."
    );
    Ok(())
}
