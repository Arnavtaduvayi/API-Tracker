//! `scan`, `hooks`, and `suppress` subcommands.
//!
//! Scanning is useful even against a locked vault: pattern/entropy detection
//! and suppressions work without the master password (suppressions carry no
//! secret material). When the vault IS unlocked, findings are additionally
//! matched to stored credentials and matched credentials are marked possibly
//! exposed. The pre-commit hook uses the no-unlock path so it never prompts
//! during a commit.

use crate::ctx::Ctx;
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::providers::Confidence;
use api_tracker_core::scanner::{self, Finding, ScanOptions};
use api_tracker_core::{gitrepo, hooks};
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub struct ScanArgs {
    /// Path to scan (repository or directory). Defaults to the current dir.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Scan staged changes only.
    #[arg(long)]
    pub staged: bool,
    /// Scan Git history (last N commits; use --all-history for everything).
    #[arg(long, value_name = "N")]
    pub history: Option<usize>,
    /// Scan the entire Git history.
    #[arg(long)]
    pub all_history: bool,
    /// Internal: pre-commit hook mode (no unlock, blocks on high-confidence).
    #[arg(long, hide = true)]
    pub hook: bool,
    /// Do not mark matched vault credentials as possibly exposed.
    #[arg(long)]
    pub no_mark: bool,
}

#[derive(Subcommand)]
pub enum HooksCmd {
    /// Install the pre-commit secret-scanning hook.
    Install {
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Append to an existing hook instead of refusing.
        #[arg(long)]
        force: bool,
    },
    /// Remove the API Tracker pre-commit hook.
    Remove {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Show the pre-commit hook status.
    Status {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum SuppressCmd {
    /// Suppress a finding by its suppression key, with a required reason.
    Add {
        suppression_key: String,
        #[arg(long)]
        reason: String,
    },
    /// List local suppressions.
    List,
}

fn build_units(args: &ScanArgs) -> Result<Vec<gitrepo::ScanUnit>> {
    if args.staged || args.hook {
        let root = gitrepo::repo_root(&args.path)?;
        Ok(gitrepo::staged_units(&root)?)
    } else if args.all_history {
        let root = gitrepo::repo_root(&args.path)?;
        Ok(gitrepo::history_added_units(&root, None)?)
    } else if let Some(n) = args.history {
        let root = gitrepo::repo_root(&args.path)?;
        Ok(gitrepo::history_added_units(&root, Some(n))?)
    } else {
        Ok(gitrepo::working_tree_units(&args.path)?)
    }
}

pub fn scan(ctx: &Ctx, args: ScanArgs) -> Result<()> {
    // Hook mode: no unlock, detection + suppression only, block on high.
    if args.hook {
        let units = build_units(&args)?;
        let suppressed = ctx.suppression_keys();
        let findings = detect(&units, &suppressed);
        let high: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.confidence == Confidence::High)
            .collect();
        if high.is_empty() {
            return Ok(());
        }
        eprintln!(
            "api-tracker: blocking commit — {} high-confidence secret(s) found:",
            high.len()
        );
        for f in &high {
            eprintln!(
                "  {}:{}  [{}] {} ({})",
                f.file,
                f.line,
                f.confidence.label(),
                f.redacted,
                f.provider.as_deref().unwrap_or("unknown provider")
            );
        }
        eprintln!();
        eprintln!("Remove the secret(s), or suppress a false positive with a reason:");
        for f in &high {
            eprintln!(
                "  api-tracker suppress add {} --reason \"...\"",
                f.suppression_key
            );
        }
        eprintln!("To bypass once (not recommended): git commit --no-verify");
        bail!("commit blocked by api-tracker pre-commit hook");
    }

    // Rich path when unlocked: the vault scans, matches, and marks exposures.
    if let Some(mut vault) = ctx.try_unlocked() {
        let mut findings = if args.staged {
            vault.scan_staged(&args.path)?
        } else if args.all_history {
            vault.scan_history(&args.path, None)?
        } else if let Some(n) = args.history {
            vault.scan_history(&args.path, Some(n))?
        } else {
            vault.scan_working_tree(&args.path)?
        };
        let affected = if args.no_mark {
            Vec::new()
        } else {
            vault.mark_findings_exposed(&findings)?
        };
        findings.sort_by_key(|f| std::cmp::Reverse(f.confidence));
        report(ctx, &findings, affected.len());
    } else {
        let units = build_units(&args)?;
        let suppressed = ctx.suppression_keys();
        let findings = detect(&units, &suppressed);
        report(ctx, &findings, 0);
        if ctx.paths.vault_exists() {
            eprintln!(
                "(vault locked: findings were not matched against your stored credentials; \
                 unlock to enable matching)"
            );
        }
    }
    Ok(())
}

/// Detection-only scan (no vault), applying suppressions and per-file entropy.
fn detect(
    units: &[gitrepo::ScanUnit],
    suppressed: &std::collections::HashSet<String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for unit in units {
        let options = ScanOptions {
            entropy: !scanner::skip_entropy_for(&unit.label),
        };
        for f in scanner::scan_text(&unit.content, &unit.label, &options) {
            if !suppressed.contains(&f.suppression_key) {
                out.push(f);
            }
        }
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.confidence));
    out
}

fn report(ctx: &Ctx, findings: &[Finding], marked_exposed: usize) {
    render::emit(ctx.json, &findings, || {
        if findings.is_empty() {
            println!("No secrets found.");
            return;
        }
        println!("{} potential secret(s) found:\n", findings.len());
        for f in findings {
            println!(
                "{}:{}  [{}] {}",
                f.file,
                f.line,
                f.confidence.label(),
                f.provider.as_deref().unwrap_or("unknown")
            );
            println!("    value:   {}", f.redacted);
            println!("    reason:  {}", f.reason);
            if let Some(m) = &f.vault_match {
                print!(
                    "    IN VAULT: matches '{}/{}'",
                    m.project_name, m.credential_name
                );
                if !m.other_projects.is_empty() {
                    print!(" (also in: {})", m.other_projects.join(", "));
                }
                println!();
            }
            println!(
                "    suppress: api-tracker suppress add {} --reason \"...\"",
                f.suppression_key
            );
        }
        if marked_exposed > 0 {
            println!(
                "\n{marked_exposed} matched vault credential(s) were marked possibly exposed. \
                 Removing a secret from a file does not remove it from Git history — rotate it."
            );
        }
    });
}

pub fn hooks(ctx: &Ctx, cmd: HooksCmd) -> Result<()> {
    match cmd {
        HooksCmd::Install { path, force } => {
            let state = hooks::install(&path, force)?;
            render::emit(ctx.json, &hooks::status(&path)?, || {
                println!("Pre-commit hook installed ({state:?}).");
                println!("It runs `api-tracker scan --staged` and blocks high-confidence secrets.");
            });
        }
        HooksCmd::Remove { path } => {
            let state = hooks::remove(&path)?;
            println!("Pre-commit hook removed ({state:?}).");
        }
        HooksCmd::Status { path } => {
            let status = hooks::status(&path)?;
            render::emit(ctx.json, &status, || {
                println!("Repository: {}", status.repo);
                println!("Hook file:  {}", status.hook_path);
                println!("State:      {:?}", status.state);
            });
        }
    }
    Ok(())
}

pub fn suppress(ctx: &Ctx, cmd: SuppressCmd) -> Result<()> {
    match cmd {
        SuppressCmd::Add {
            suppression_key,
            reason,
        } => {
            let (vault, _t) = ctx.unlocked()?;
            vault.add_suppression(&suppression_key, "manual", "", &reason)?;
            println!("Suppression added.");
        }
        SuppressCmd::List => {
            let (vault, _t) = ctx.unlocked()?;
            let suppressions = vault.list_suppressions()?;
            render::emit(ctx.json, &suppressions, || {
                if suppressions.is_empty() {
                    println!("No suppressions.");
                } else {
                    let rows: Vec<Vec<String>> = suppressions
                        .iter()
                        .map(|s| {
                            vec![
                                s.suppression_key.chars().take(12).collect::<String>(),
                                s.path.clone(),
                                s.reason.clone(),
                            ]
                        })
                        .collect();
                    render::table(&["KEY", "PATH", "REASON"], &rows);
                }
            });
        }
    }
    Ok(())
}
