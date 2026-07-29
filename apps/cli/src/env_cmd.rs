//! `tethra env` — .env governance: discover, preview, import, example
//! generation, drift detection, explicit export, and cleanup.
//!
//! No command here ever prints a secret value. Export requires master
//! password reauthentication and prints a plaintext warning.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::envgov;
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum EnvCmd {
    /// Find .env files in a project's repositories (or an explicit path).
    Discover(DiscoverArgs),
    /// Show a .env file's variables (masked) with classification.
    Preview(PreviewArgs),
    /// Import selected variables into the encrypted vault and map them.
    Import(ImportArgs),
    /// Generate or update .env.example (names only, never values).
    Example(ExampleArgs),
    /// Detect drift between .env files, the vault, and mappings.
    Drift(DriftArgs),
    /// Guided migration: import secrets, map them, and remove plaintext.
    Migrate(MigrateArgs),
    /// Explicitly export mapped credentials to a plaintext .env file.
    Export(ExportArgs),
    /// List recorded exports.
    Exports(ExportsArgs),
    /// Remove expired temporary exports (or all with --all).
    Cleanup(CleanupArgs),
}

#[derive(Args)]
pub struct DiscoverArgs {
    /// Project whose registered repositories are searched.
    #[arg(long)]
    pub project: Option<String>,
    /// Explicit directory to search instead of (or besides) the project.
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Args)]
pub struct PreviewArgs {
    /// Project context (mappings and vault matches are project-aware).
    #[arg(long)]
    pub project: String,
    /// The .env file to preview.
    pub file: PathBuf,
}

#[derive(Args)]
pub struct ImportArgs {
    /// Project to import into.
    #[arg(long)]
    pub project: String,
    /// The .env file to import from (the file itself is never modified).
    pub file: PathBuf,
    /// Variable name(s) to import; default: everything that looks secret.
    #[arg(long = "var", value_name = "NAME")]
    pub vars: Vec<String>,
    /// Override the environment (default: inferred from the file name).
    #[arg(long)]
    pub environment: Option<api_tracker_core::model::Environment>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct ExampleArgs {
    /// The values file to derive names from.
    pub file: PathBuf,
    /// Write the result (default: show the diff only).
    #[arg(long)]
    pub write: bool,
    /// Skip the confirmation prompt when writing.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct DriftArgs {
    /// Project to check.
    #[arg(long)]
    pub project: String,
}

#[derive(Args)]
pub struct MigrateArgs {
    /// Project to migrate.
    #[arg(long)]
    pub project: String,
    /// The .env file to migrate away from.
    pub file: PathBuf,
    /// Skip confirmation prompts (still requires reauth for verification).
    #[arg(long)]
    pub yes: bool,
    /// Keep the file untouched (import + map + verify only).
    #[arg(long)]
    pub keep_file: bool,
}

#[derive(Args)]
pub struct ExportArgs {
    /// Project whose mapped credentials are exported.
    #[arg(long)]
    pub project: String,
    /// Target file path.
    #[arg(long, value_name = "PATH")]
    pub to: PathBuf,
    /// Variable name(s) to export; default: every configured mapping.
    #[arg(long = "var", value_name = "NAME")]
    pub vars: Vec<String>,
    /// Replace the target file if it exists.
    #[arg(long)]
    pub overwrite: bool,
    /// Make the export temporary: remove it after N minutes (via cleanup).
    #[arg(long, value_name = "MINUTES")]
    pub ttl: Option<u64>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Args)]
pub struct ExportsArgs {
    /// Include exports that were already cleaned up.
    #[arg(long)]
    pub all: bool,
}

#[derive(Args)]
pub struct CleanupArgs {
    /// Remove every recorded export, not only expired temporary ones.
    #[arg(long)]
    pub all: bool,
    /// Also remove files whose content changed since export.
    #[arg(long)]
    pub force: bool,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(ctx: &Ctx, cmd: EnvCmd) -> Result<()> {
    match cmd {
        EnvCmd::Discover(args) => discover(ctx, args),
        EnvCmd::Preview(args) => preview(ctx, args),
        EnvCmd::Import(args) => import(ctx, args),
        EnvCmd::Example(args) => example(ctx, args),
        EnvCmd::Drift(args) => drift(ctx, args),
        EnvCmd::Migrate(args) => migrate(ctx, args),
        EnvCmd::Export(args) => export(ctx, args),
        EnvCmd::Exports(args) => exports(ctx, args),
        EnvCmd::Cleanup(args) => cleanup(ctx, args),
    }
}

fn discover(ctx: &Ctx, args: DiscoverArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    // `env discover` is an explicitly invoked command against a folder the
    // user named for this purpose, so it may pay for the hardened history
    // probe. Automatic scans (folder selection, tracking) never do — see
    // ADR 0023.
    let found = vault.env_discover_with(
        args.project.as_deref(),
        args.path.as_deref(),
        envgov::HistoryProbe::HardenedGit,
    )?;
    render::emit(ctx.json, &found, || {
        if found.is_empty() {
            println!("No .env files found.");
            return;
        }
        let rows: Vec<Vec<String>> = found
            .iter()
            .map(|f| {
                vec![
                    f.rel_path.clone(),
                    format!("{:?}", f.class).to_lowercase(),
                    f.environment
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "-".into()),
                    format!("{:?}", f.git_status).to_lowercase(),
                    match f.git_history {
                        envgov::GitHistory::Present => "yes",
                        envgov::GitHistory::Absent => "no",
                        envgov::GitHistory::NotChecked => "not checked",
                    }
                    .into(),
                    f.entry_count.to_string(),
                    f.problems.len().to_string(),
                ]
            })
            .collect();
        render::table(
            &[
                "FILE",
                "CLASS",
                "ENV",
                "GIT",
                "IN HISTORY",
                "VARS",
                "PROBLEMS",
            ],
            &rows,
        );
        for f in &found {
            if f.git_status == envgov::GitStatus::Tracked && f.class == envgov::EnvFileClass::Values
            {
                println!(
                    "\nWARNING: {} is committed to Git — its values are in the repository.",
                    f.rel_path
                );
            }
            if f.in_git_history() && f.class == envgov::EnvFileClass::Values {
                println!(
                    "NOTE: {} appears in Git history; deleting the file does not remove past commits.",
                    f.rel_path
                );
            }
        }
    });
    Ok(())
}

fn preview_rows(preview: &[envgov::VarPreview]) -> Vec<Vec<String>> {
    preview
        .iter()
        .map(|v| {
            vec![
                v.key.clone(),
                v.masked.clone(),
                v.provider.clone().unwrap_or_else(|| "-".into()),
                if v.looks_secret { "yes" } else { "-" }.into(),
                if v.is_placeholder { "yes" } else { "-" }.into(),
                v.vault_credential.clone().unwrap_or_else(|| "-".into()),
                v.mapped_credential.clone().unwrap_or_else(|| "-".into()),
            ]
        })
        .collect()
}

const PREVIEW_HEADERS: [&str; 7] = [
    "VARIABLE",
    "VALUE (MASKED)",
    "PROVIDER",
    "SECRET?",
    "PLACEHOLDER?",
    "IN VAULT",
    "MAPPED TO",
];

fn preview(ctx: &Ctx, args: PreviewArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let preview = vault.env_preview(&args.project, &args.file)?;
    render::emit(ctx.json, &preview, || {
        render::table(&PREVIEW_HEADERS, &preview_rows(&preview));
    });
    Ok(())
}

fn import(ctx: &Ctx, args: ImportArgs) -> Result<()> {
    let (mut vault, token) = ctx.unlocked()?;
    let preview = vault.env_preview(&args.project, &args.file)?;
    let select: Option<Vec<String>> = if args.vars.is_empty() {
        None
    } else {
        Some(args.vars.clone())
    };
    let candidates: Vec<&envgov::VarPreview> = match &select {
        Some(names) => preview.iter().filter(|v| names.contains(&v.key)).collect(),
        None => preview.iter().filter(|v| v.looks_secret).collect(),
    };
    if candidates.is_empty() {
        bail!("nothing to import; pass --var NAME to select variables explicitly");
    }
    if !ctx.json {
        println!("About to import into project '{}':", args.project);
        render::table(
            &PREVIEW_HEADERS,
            &preview_rows(&candidates.iter().map(|v| (*v).clone()).collect::<Vec<_>>()),
        );
        println!("The file itself is NOT modified.");
    }
    if !ctx::confirm(
        &format!("Import {} variable(s)?", candidates.len()),
        args.yes,
    )? {
        bail!("cancelled");
    }
    let outcomes = vault.env_import(
        &args.project,
        &args.file,
        select.as_deref(),
        args.environment,
    )?;
    ctx.persist_session(&vault, &token)?;
    render::emit(ctx.json, &outcomes, || {
        let rows: Vec<Vec<String>> = outcomes
            .iter()
            .map(|o| {
                vec![
                    o.key.clone(),
                    o.action.clone(),
                    o.credential.clone().unwrap_or_else(|| "-".into()),
                    o.note.clone(),
                ]
            })
            .collect();
        render::table(&["VARIABLE", "ACTION", "CREDENTIAL", "NOTE"], &rows);
    });
    Ok(())
}

/// Compute the example path, proposed content, and diff for a values file.
fn example_proposal(file: &Path) -> Result<(PathBuf, String, String, bool)> {
    let content = std::fs::read_to_string(file)?;
    let values = api_tracker_core::envfile::EnvDocument::parse(&content);
    let example_path = file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".env.example");
    let existing = match std::fs::read_to_string(&example_path) {
        Ok(text) => Some(api_tracker_core::envfile::EnvDocument::parse(&text)),
        Err(_) => None,
    };
    let old = existing.as_ref().map(|d| d.render()).unwrap_or_default();
    let proposed = envgov::generate_example(&values, existing.as_ref());
    let diff = envgov::render_diff(".env.example", &old, &proposed);
    let changed = old != proposed;
    Ok((example_path, proposed, diff, changed))
}

fn example(_ctx: &Ctx, args: ExampleArgs) -> Result<()> {
    let (example_path, proposed, diff, changed) = example_proposal(&args.file)?;
    if !changed {
        println!("{} is already up to date.", example_path.display());
        return Ok(());
    }
    println!("{diff}");
    if !args.write {
        println!("(dry run — pass --write to apply)");
        return Ok(());
    }
    if !ctx::confirm(&format!("Write {}?", example_path.display()), args.yes)? {
        bail!("cancelled");
    }
    envgov::atomic_write(&example_path, &proposed)?;
    println!("Wrote {}.", example_path.display());
    Ok(())
}

fn drift(ctx: &Ctx, args: DriftArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let findings = vault.env_drift(&args.project)?;
    render::emit(ctx.json, &findings, || {
        if findings.is_empty() {
            println!("No drift detected.");
            return;
        }
        for finding in &findings {
            println!(
                "[{}] {:?} — {}{}",
                finding.kind.severity(),
                finding.kind,
                finding.key,
                if finding.file.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", finding.file)
                }
            );
            println!("  {}", finding.detail);
            println!("  Recommendation: {}", finding.recommendation);
        }
        println!(
            "\nChoose the source of truth before synchronizing: re-import the file \
             (`env import`) or re-export the vault value (`env export`)."
        );
    });
    Ok(())
}

fn migrate(ctx: &Ctx, args: MigrateArgs) -> Result<()> {
    let (mut vault, token) = ctx.unlocked()?;
    // 1. Detect.
    let preview = vault.env_preview(&args.project, &args.file)?;
    let secretish: Vec<&envgov::VarPreview> = preview
        .iter()
        .filter(|v| v.looks_secret && !v.is_placeholder)
        .collect();
    if secretish.is_empty() {
        println!("No likely secrets found in {}.", args.file.display());
        return Ok(());
    }
    println!("Step 1/5 — secrets detected in {}:", args.file.display());
    render::table(
        &PREVIEW_HEADERS,
        &preview_rows(&secretish.iter().map(|v| (*v).clone()).collect::<Vec<_>>()),
    );
    // 2. Import + map.
    if !ctx::confirm(
        "Step 2/5 — import these into the vault and map them for injection?",
        args.yes,
    )? {
        bail!("cancelled");
    }
    let outcomes = vault.env_import(&args.project, &args.file, None, None)?;
    for outcome in &outcomes {
        println!("  {}: {} — {}", outcome.key, outcome.action, outcome.note);
    }
    // 3. Verify every secret variable now resolves from the vault.
    let mappings = vault.list_env_mappings(&args.project)?;
    let unresolved: Vec<&str> = secretish
        .iter()
        .filter(|v| !mappings.iter().any(|m| m.env_var == v.key))
        .map(|v| v.key.as_str())
        .collect();
    if !unresolved.is_empty() {
        bail!(
            "verification failed: no vault mapping for {} — resolve manually (values already \
             in another project need a reference: `key add --link-to`)",
            unresolved.join(", ")
        );
    }
    println!("Step 3/5 — verified: every detected secret resolves from the vault.");
    // 4. Show the proposed file change.
    let content = std::fs::read_to_string(&args.file)?;
    let mut doc = api_tracker_core::envfile::EnvDocument::parse(&content);
    for v in &secretish {
        doc.remove(&v.key);
    }
    let proposed = doc.render();
    let diff = envgov::render_diff(&args.file.to_string_lossy(), &content, &proposed);
    println!("Step 4/5 — proposed change to {}:", args.file.display());
    println!("{diff}");
    if args.keep_file {
        println!("--keep-file set: leaving the file unchanged. Migration data is in place.");
        ctx.persist_session(&vault, &token)?;
        return Ok(());
    }
    // 5. Apply after confirmation.
    if !ctx::confirm(
        "Step 5/5 — remove these plaintext values from the file? (Rollback: \
         `tethra env export` re-creates them from the vault.)",
        args.yes,
    )? {
        bail!("cancelled — nothing was changed");
    }
    envgov::atomic_write(&args.file, &proposed)?;
    ctx.persist_session(&vault, &token)?;
    println!(
        "Done. Run the project with:\n  tethra run --project {} -- <command>\n\
         The variables are injected at run time; no plaintext file is needed.",
        args.project
    );
    Ok(())
}

fn export(ctx: &Ctx, args: ExportArgs) -> Result<()> {
    let (mut vault, token) = ctx.unlocked()?;
    let mappings = vault.list_env_mappings(&args.project)?;
    let names: Vec<String> = if args.vars.is_empty() {
        mappings.iter().map(|m| m.env_var.clone()).collect()
    } else {
        args.vars.clone()
    };
    if names.is_empty() {
        bail!("no mapped variables to export; configure mappings first (`tethra mapping set`)");
    }
    println!("About to write a PLAINTEXT .env file:");
    println!("  Target:    {}", args.to.display());
    println!("  Variables: {}", names.join(", "));
    if let Some(minutes) = args.ttl {
        println!("  Temporary: removed by `env cleanup` after {minutes} minute(s)");
    } else {
        println!("  Temporary: no — the file persists until you delete it");
    }
    println!("Prefer `tethra run`, which injects credentials without a file.");
    if !ctx::confirm("Export?", args.yes)? {
        bail!("cancelled");
    }
    let password = ctx::master_password()?;
    let vars = if args.vars.is_empty() {
        None
    } else {
        Some(args.vars.as_slice())
    };
    let report = vault.env_export(
        &args.project,
        &args.to,
        vars,
        &password,
        args.overwrite,
        args.ttl,
    )?;
    ctx.persist_session(&vault, &token)?;
    render::emit(ctx.json, &report, || {
        println!(
            "Exported {} variable(s) to {}.",
            report.var_names.len(),
            report.path
        );
        for warning in &report.warnings {
            println!("WARNING: {warning}");
        }
        if let Some(expires) = &report.expires_at {
            println!("Expires: {expires} (run `tethra env cleanup` to enforce)");
        }
    });
    Ok(())
}

fn exports(ctx: &Ctx, args: ExportsArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    let exports = vault.env_exports(args.all)?;
    render::emit(ctx.json, &exports, || {
        if exports.is_empty() {
            println!("No recorded exports.");
            return;
        }
        let rows: Vec<Vec<String>> = exports
            .iter()
            .map(|e| {
                vec![
                    e.path.clone(),
                    e.var_names.clone(),
                    e.created_at.clone(),
                    e.expires_at.clone().unwrap_or_else(|| "-".into()),
                    e.cleaned_at.clone().unwrap_or_else(|| "live".into()),
                ]
            })
            .collect();
        render::table(
            &["PATH", "VARIABLES", "CREATED", "EXPIRES", "CLEANED"],
            &rows,
        );
    });
    Ok(())
}

fn cleanup(ctx: &Ctx, args: CleanupArgs) -> Result<()> {
    let (vault, _token) = ctx.unlocked()?;
    if args.all
        && !ctx::confirm(
            "Remove EVERY exported .env file recorded by Tethra?",
            args.yes,
        )?
    {
        bail!("cancelled");
    }
    let results = vault.env_cleanup(args.all, args.force)?;
    render::emit(ctx.json, &results, || {
        if results.is_empty() {
            println!("Nothing to clean up.");
            return;
        }
        for result in &results {
            println!("{}: {:?}", result.path, result.outcome);
            if result.outcome == envgov::CleanupOutcome::ModifiedSinceExport {
                println!("  (file changed since export; pass --force to remove anyway)");
            }
        }
    });
    Ok(())
}
