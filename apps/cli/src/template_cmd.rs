//! `tethra template` — project templates and local stack detection.
//!
//! Detection is deterministic rules over static repository files plus a
//! locally stored confirm/dismiss history — not machine learning, and it is
//! described as such. Nothing is executed, nothing is uploaded, and no
//! suggestion is applied without explicit confirmation.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::stackdetect::DetectionReport;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum TemplateCmd {
    /// List available project templates.
    List,
    /// Show one template: variables, guidance, and the .env.example.
    Show(ShowArgs),
    /// Apply a template: create/annotate a project, optionally write
    /// .env.example, and print the exact follow-up commands.
    Apply(ApplyArgs),
    /// Detect the stack of a repository (or a project's repositories).
    Detect(DetectArgs),
    /// Confirm a suggestion for a repository (remembered locally).
    Confirm(DecisionArgs),
    /// Dismiss a suggestion for a repository (remembered locally).
    Dismiss(DecisionArgs),
    /// List or delete locally learned detection decisions.
    Prefs(PrefsArgs),
}

#[derive(Args)]
pub struct ShowArgs {
    pub id: String,
}

#[derive(Args)]
pub struct ApplyArgs {
    pub id: String,
    /// The project to create or apply to.
    #[arg(long)]
    pub project: String,
    /// Write a .env.example (names only) into this directory.
    #[arg(long, value_name = "DIR")]
    pub write_example: Option<PathBuf>,
}

#[derive(Args)]
pub struct DetectArgs {
    /// Detect over this repository directory.
    #[arg(long, value_name = "DIR", conflicts_with = "project")]
    pub repo: Option<PathBuf>,
    /// Detect over every repository registered on this project.
    #[arg(long)]
    pub project: Option<String>,
    /// Also show suggestions you previously dismissed.
    #[arg(long)]
    pub all: bool,
}

#[derive(Args)]
pub struct DecisionArgs {
    /// The template id being confirmed/dismissed.
    pub id: String,
    /// The repository directory the decision applies to.
    #[arg(long, value_name = "DIR")]
    pub repo: PathBuf,
}

#[derive(Args)]
pub struct PrefsArgs {
    /// Delete the learned decisions for one repository.
    #[arg(long, value_name = "DIR")]
    pub reset_repo: Option<PathBuf>,
    /// Delete ALL learned stack-detection data.
    #[arg(long)]
    pub clear_all: bool,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(ctx: &Ctx, cmd: TemplateCmd) -> Result<()> {
    match cmd {
        TemplateCmd::List => list(ctx),
        TemplateCmd::Show(a) => show(ctx, a),
        TemplateCmd::Apply(a) => apply(ctx, a),
        TemplateCmd::Detect(a) => detect(ctx, a),
        TemplateCmd::Confirm(a) => decide(ctx, a, "confirmed"),
        TemplateCmd::Dismiss(a) => decide(ctx, a, "dismissed"),
        TemplateCmd::Prefs(a) => prefs(ctx, a),
    }
}

fn list(ctx: &Ctx) -> Result<()> {
    let all = api_tracker_core::templates::catalog();
    render::emit(ctx.json, &all, || {
        let rows: Vec<Vec<String>> = all
            .iter()
            .map(|t| {
                vec![
                    t.id.clone(),
                    t.name.clone(),
                    t.providers.join(", "),
                    t.env_vars.iter().filter(|v| v.secret).count().to_string(),
                    t.description.clone(),
                ]
            })
            .collect();
        render::table(
            &["ID", "NAME", "PROVIDERS", "SECRETS", "DESCRIPTION"],
            &rows,
        );
        println!(
            "\nUse `template show <id>` for guidance and `template apply <id> --project <p>`."
        );
    });
    Ok(())
}

fn show(ctx: &Ctx, a: ShowArgs) -> Result<()> {
    let Some(t) = api_tracker_core::templates::find(&a.id) else {
        bail!("unknown template '{}' (see `template list`)", a.id);
    };
    render::emit(ctx.json, &t, || {
        println!("{} — {}", t.id, t.name);
        println!("{}\n", t.description);
        println!("providers:    {}", t.providers.join(", "));
        println!("environments: {}", t.environments.join(", "));
        if !t.destinations.is_empty() {
            println!("destinations: {}", t.destinations.join(", "));
        }
        println!("\nEnvironment variables:");
        for v in &t.env_vars {
            println!(
                "  {} {} — {}",
                v.name,
                if v.secret { "(secret)" } else { "(not secret)" },
                v.description
            );
        }
        if !t.credential_separation.is_empty() {
            println!(
                "\nCredential separation:\n{}",
                t.credential_separation.trim()
            );
        }
        if !t.permission_guidance.is_empty() {
            println!("\nPermissions:\n{}", t.permission_guidance.trim());
        }
        if !t.rotation_guidance.is_empty() {
            println!("\nRotation:\n{}", t.rotation_guidance.trim());
        }
        if !t.docs.is_empty() {
            println!("\nDocumentation:");
            for d in &t.docs {
                println!("  {d}");
            }
        }
    });
    Ok(())
}

fn apply(ctx: &Ctx, a: ApplyArgs) -> Result<()> {
    let (mut vault, _t) = ctx.unlocked()?;
    let outcome = vault.template_apply(&a.id, &a.project, a.write_example.as_deref())?;
    render::emit(ctx.json, &outcome, || {
        println!(
            "Applied template '{}' to project '{}'.",
            outcome.template.id, outcome.project.name
        );
        match &outcome.example_path {
            Some(p) => println!("Wrote {p} (variable names only — no values)."),
            None => println!("No .env.example written (pass --write-example <dir> to write one)."),
        }
        if !outcome.next_steps.is_empty() {
            println!(
                "\nNext steps — credentials are only added by these explicit commands\n\
                 (each prompts for its secret; values are never taken from arguments):"
            );
            for s in &outcome.next_steps {
                println!("  {s}");
            }
        }
        println!("\nGuidance: `template show {}`.", outcome.template.id);
    });
    Ok(())
}

fn print_report(report: &DetectionReport, show_all: bool) {
    println!("repository: {}", render::sanitize(&report.repo_path));
    if report.signals.is_empty() {
        println!("  no stack signals found");
        return;
    }
    println!("  evidence:");
    for s in &report.signals {
        println!(
            "    [{:?}] {}: {}",
            s.confidence,
            render::sanitize(&s.file),
            render::sanitize(&s.evidence)
        );
    }
    let visible: Vec<_> = report
        .suggestions
        .iter()
        .filter(|s| show_all || s.prior_decision.as_deref() != Some("dismissed"))
        .collect();
    if visible.is_empty() {
        println!("  no suggestions (dismissed ones hidden; --all shows them)");
        return;
    }
    println!("  suggestions (deterministic rules + your stored decisions — not ML):");
    for s in visible {
        println!(
            "    {} [{:?}]{}",
            s.template_id,
            s.confidence,
            match s.prior_decision.as_deref() {
                Some("confirmed") => " (you confirmed this earlier)",
                Some("dismissed") => " (you dismissed this earlier)",
                _ => "",
            }
        );
        for e in &s.evidence {
            println!("      - {}", render::sanitize(e));
        }
    }
    println!(
        "  confirm/dismiss with: template confirm|dismiss <id> --repo {}",
        render::sanitize(&report.repo_path)
    );
}

fn detect(ctx: &Ctx, a: DetectArgs) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    let reports: Vec<DetectionReport> = match (&a.repo, &a.project) {
        (Some(repo), None) => vec![vault.stack_detect_path(repo)?],
        (None, Some(project)) => vault.stack_detect_project(project)?,
        (None, None) => bail!("pass --repo <dir> or --project <name>"),
        (Some(_), Some(_)) => unreachable!("clap conflicts_with"),
    };
    render::emit(ctx.json, &reports, || {
        if reports.is_empty() {
            println!("no repositories to inspect (register one on the project first)");
        }
        for r in &reports {
            print_report(r, a.all);
            println!();
        }
        println!(
            "Detection reads dependency manifests, lockfiles, config files, and .env variable \
             NAMES only; nothing is executed or uploaded."
        );
    });
    Ok(())
}

fn decide(ctx: &Ctx, a: DecisionArgs, decision: &str) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    vault.stack_decide(&a.repo, &a.id, decision)?;
    println!(
        "{} '{}' for {} — remembered locally; `template prefs` lists and deletes decisions.",
        decision,
        a.id,
        a.repo.display()
    );
    if decision == "confirmed" {
        println!("Apply it with: template apply {} --project <name>", a.id);
    }
    Ok(())
}

fn prefs(ctx: &Ctx, a: PrefsArgs) -> Result<()> {
    let (vault, _t) = ctx.unlocked()?;
    if a.clear_all {
        if !ctx::confirm(
            "Delete ALL locally learned stack-detection decisions?",
            a.yes,
        )? {
            println!("cancelled");
            return Ok(());
        }
        let n = vault.stack_preferences_reset(None)?;
        println!("deleted {n} stored decision(s)");
        return Ok(());
    }
    if let Some(repo) = &a.reset_repo {
        let n = vault.stack_preferences_reset(Some(repo))?;
        println!("deleted {n} stored decision(s) for {}", repo.display());
        return Ok(());
    }
    let prefs = vault.stack_preferences()?;
    render::emit(ctx.json, &prefs, || {
        if prefs.is_empty() {
            println!("no stored decisions");
            return;
        }
        let rows: Vec<Vec<String>> = prefs
            .iter()
            .map(|p| {
                vec![
                    render::sanitize(&p.repo_path),
                    p.template_id.clone(),
                    p.decision.clone(),
                    p.decided_at.clone(),
                ]
            })
            .collect();
        render::table(&["REPOSITORY", "TEMPLATE", "DECISION", "AT"], &rows);
        println!(
            "\nDelete with --reset-repo <dir> or --clear-all. This is the entire learned \
             dataset — nothing else is stored."
        );
    });
    Ok(())
}
