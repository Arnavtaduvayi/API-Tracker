//! api-tracker: local-first encrypted API credential manager (CLI).
//!
//! Uses the same vault, database, and business rules as the desktop app via
//! `api-tracker-core`. All output redacts credential values; the single
//! deliberate exception is `key reveal`, which requires reauthentication.

mod alerts_cmd;
mod backup_cmd;
mod ctx;
mod key_cmd;
mod project_cmd;
mod provider_cmd;
mod render;
mod run_cmd;
mod scan_cmd;
mod usage_cmd;
mod vault_cmd;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "api-tracker",
    version,
    about = "Local-first encrypted vault for organizing API credentials across projects",
    propagate_version = true
)]
struct Cli {
    /// Vault data directory (defaults to the platform data dir; the
    /// API_TRACKER_DIR environment variable also overrides it).
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// Emit machine-readable JSON instead of tables.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new encrypted vault and set the master password.
    Init,
    /// Unlock the vault and start a shell session.
    Unlock(vault_cmd::UnlockArgs),
    /// End the current session (lock the vault for the CLI).
    Lock,
    /// Check vault health: paths, schema, integrity, session state.
    Doctor,
    /// Show or change vault settings (auto-lock, status thresholds).
    #[command(subcommand)]
    Settings(vault_cmd::SettingsCmd),
    /// Provider catalog and documentation watches.
    #[command(subcommand)]
    Provider(provider_cmd::ProviderCmd),
    /// Manage projects (folders of credentials).
    #[command(subcommand)]
    Project(project_cmd::ProjectCmd),
    /// Manage credentials.
    #[command(subcommand)]
    Key(key_cmd::KeyCmd),
    /// Scan a repository or directory for committed secrets.
    Scan(scan_cmd::ScanArgs),
    /// Manage the Git pre-commit secret-scanning hook.
    #[command(subcommand)]
    Hooks(scan_cmd::HooksCmd),
    /// Manage local scan suppressions.
    #[command(subcommand)]
    Suppress(scan_cmd::SuppressCmd),
    /// Run local monitoring checks and generate alerts.
    Monitor,
    /// View and manage local alerts.
    #[command(subcommand)]
    Alerts(alerts_cmd::AlertsCmd),
    /// Usage synchronization and reports.
    #[command(subcommand)]
    Usage(usage_cmd::UsageCmd),
    /// Set and view budgets.
    #[command(subcommand)]
    Budget(usage_cmd::BudgetCmd),
    /// View local activity events.
    #[command(subcommand)]
    Activity(usage_cmd::ActivityCmd),
    /// Configure credential -> environment-variable mappings for `run`.
    #[command(subcommand)]
    Mapping(usage_cmd::MappingCmd),
    /// Run a command with credentials injected into its environment.
    Run(run_cmd::RunArgs),
    /// Encrypted vault backups.
    #[command(subcommand)]
    Backup(backup_cmd::BackupCmd),
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let ctx = ctx::Ctx::new(cli.data_dir, cli.json)?;
    match cli.command {
        Commands::Init => vault_cmd::init(&ctx),
        Commands::Unlock(args) => vault_cmd::unlock(&ctx, args),
        Commands::Lock => vault_cmd::lock(&ctx),
        Commands::Doctor => vault_cmd::doctor(&ctx),
        Commands::Settings(cmd) => vault_cmd::settings(&ctx, cmd),
        Commands::Provider(cmd) => provider_cmd::run(&ctx, cmd),
        Commands::Project(cmd) => project_cmd::run(&ctx, cmd),
        Commands::Key(cmd) => key_cmd::run(&ctx, cmd),
        Commands::Scan(args) => scan_cmd::scan(&ctx, args),
        Commands::Hooks(cmd) => scan_cmd::hooks(&ctx, cmd),
        Commands::Suppress(cmd) => scan_cmd::suppress(&ctx, cmd),
        Commands::Monitor => alerts_cmd::monitor_run(&ctx),
        Commands::Alerts(cmd) => alerts_cmd::alerts(&ctx, cmd),
        Commands::Usage(cmd) => usage_cmd::usage(&ctx, cmd),
        Commands::Budget(cmd) => usage_cmd::budget(&ctx, cmd),
        Commands::Activity(cmd) => usage_cmd::activity(&ctx, cmd),
        Commands::Mapping(cmd) => usage_cmd::mapping(&ctx, cmd),
        Commands::Run(args) => run_cmd::run(&ctx, args),
        Commands::Backup(cmd) => backup_cmd::run(&ctx, cmd),
    }
}
