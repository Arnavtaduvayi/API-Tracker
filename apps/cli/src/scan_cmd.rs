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
    /// Re-verify: run a FULL history + working-tree scan and, only if it is
    /// clean, resolve this repository's outstanding exposure alerts. Exposure
    /// alerts never auto-resolve on their own; this is the qualifying clean
    /// re-scan that clears them.
    #[arg(long)]
    pub reverify: bool,
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
    /// Remove a suppression so future scans report the finding again.
    Remove { suppression_key: String },
}

/// Collected units plus coverage honesty (complete? + warnings).
fn build_units(args: &ScanArgs) -> Result<(Vec<gitrepo::ScanUnit>, bool, Vec<String>)> {
    if args.staged || args.hook {
        let root = gitrepo::repo_root(&args.path)?;
        Ok((gitrepo::staged_units(&root)?, true, Vec::new()))
    } else if args.all_history {
        let root = gitrepo::repo_root(&args.path)?;
        let scan = gitrepo::history_added_units(&root, None)?;
        Ok((scan.units, scan.complete, scan.warnings))
    } else if let Some(n) = args.history {
        let root = gitrepo::repo_root(&args.path)?;
        let scan = gitrepo::history_added_units(&root, Some(n))?;
        Ok((scan.units, scan.complete, scan.warnings))
    } else {
        Ok((gitrepo::working_tree_units(&args.path)?, true, Vec::new()))
    }
}

/// Print coverage warnings so an incomplete scan is never mistaken for a
/// clean full scan.
fn report_coverage(complete: bool, warnings: &[String]) {
    if complete {
        return;
    }
    eprintln!("WARNING: scan coverage is INCOMPLETE — this is not a clean full scan:");
    for w in warnings {
        eprintln!("  - {}", render::sanitize(w));
    }
}

pub fn scan(ctx: &Ctx, args: ScanArgs) -> Result<()> {
    // Re-verify: an explicit, unlock-gated full re-scan that resolves this
    // repo's exposure alerts only if nothing is found (history included).
    if args.reverify {
        let (vault, _token) = ctx.unlocked()?;
        let report = vault.reverify_repo_exposure(&args.path)?;
        report_coverage(report.coverage_complete, &report.coverage_warnings);
        if report.clean {
            println!(
                "Re-verification clean for {}: {} exposure alert(s) resolved.",
                report.repo_path, report.resolved_alerts
            );
        } else if !report.coverage_complete {
            println!(
                "Re-verification of {} was INCOMPLETE ({} finding(s) in the portion \
                 examined); exposure alert(s) kept open — incomplete coverage is not \
                 proof of remediation.",
                report.repo_path, report.findings
            );
        } else {
            println!(
                "Re-verification found {} likely secret(s) in {}; exposure alert(s) kept open. \
                 Remediate (rotate + scrub history), then re-verify again.",
                report.findings, report.repo_path
            );
        }
        return Ok(());
    }

    // Hook mode: no unlock, detection + suppression only, block on high.
    if args.hook {
        let (units, _complete, _warnings) = build_units(&args)?;
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
                render::sanitize(&f.file),
                f.line,
                f.confidence.label(),
                f.redacted,
                render::sanitize(f.provider.as_deref().unwrap_or("unknown provider"))
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
    if let Some(vault) = ctx.try_unlocked() {
        let (mut findings, complete, warnings) = if args.staged {
            (vault.scan_staged(&args.path)?, true, Vec::new())
        } else if args.all_history {
            let outcome = vault.scan_history(&args.path, None)?;
            (outcome.findings, outcome.complete, outcome.warnings)
        } else if let Some(n) = args.history {
            let outcome = vault.scan_history(&args.path, Some(n))?;
            (outcome.findings, outcome.complete, outcome.warnings)
        } else {
            (vault.scan_working_tree(&args.path)?, true, Vec::new())
        };
        let affected = if args.no_mark {
            Vec::new()
        } else {
            vault.mark_findings_exposed(&findings)?
        };
        findings.sort_by_key(|f| std::cmp::Reverse(f.confidence));
        report_coverage(complete, &warnings);
        report(ctx, &findings, affected.len());
    } else {
        let (units, complete, warnings) = build_units(&args)?;
        let suppressed = ctx.suppression_keys();
        let findings = detect(&units, &suppressed);
        report_coverage(complete, &warnings);
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
                render::sanitize(&f.file),
                f.line,
                f.confidence.label(),
                render::sanitize(f.provider.as_deref().unwrap_or("unknown"))
            );
            println!("    value:   {}", f.redacted);
            println!("    reason:  {}", render::sanitize(&f.reason));
            if let Some(m) = &f.vault_match {
                print!(
                    "    IN VAULT: matches '{}/{}'",
                    render::sanitize(&m.project_name),
                    render::sanitize(&m.credential_name)
                );
                if !m.other_projects.is_empty() {
                    print!(
                        " (also in: {})",
                        render::sanitize(&m.other_projects.join(", "))
                    );
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
            let status = hooks::status(&path)?;
            render::emit(ctx.json, &status, || {
                println!("Pre-commit hook installed ({state:?}).");
                println!("It runs `api-tracker scan --staged` and blocks high-confidence secrets.");
                println!(
                    "Active: {} — {}",
                    if status.active { "yes" } else { "NO" },
                    status.detail
                );
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
                if let Some(over) = &status.hooks_path_override {
                    println!("hooksPath:  {over} (git config core.hooksPath)");
                }
                println!("State:      {:?}", status.state);
                println!("Active:     {}", if status.active { "yes" } else { "NO" });
                println!("Detail:     {}", status.detail);
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
        SuppressCmd::Remove { suppression_key } => {
            let (vault, _t) = ctx.unlocked()?;
            vault.remove_suppression(&suppression_key)?;
            println!("Suppression removed; future scans report this finding again.");
        }
    }
    Ok(())
}
