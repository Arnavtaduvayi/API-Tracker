//! tethra: local-first encrypted API credential manager (CLI).
//!
//! The program lives here so both shipped entry points — the preferred
//! `tethra` binary (`src/main.rs`) and the legacy `api-tracker` compatibility
//! binary (`src/legacy_bin.rs`) — are one-line wrappers over the same
//! [`run_cli`] and cannot drift apart.
//!
//! Uses the same vault, database, and business rules as the desktop app via
//! `api-tracker-core`. All output redacts credential values; the single
//! deliberate exception is `key reveal`, which requires reauthentication.

mod access_cmd;
mod alerts_cmd;
mod backup_cmd;
mod ctx;
mod destination_cmd;
mod env_cmd;
mod key_cmd;
mod observe_cmd;
mod pricing_cmd;
mod project_cmd;
mod provider_cmd;
mod render;
mod rotation_cmd;
mod run_cmd;
mod scan_cmd;
mod sync_cmd;
mod template_cmd;
mod usage_cmd;
mod vault_cmd;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::path::PathBuf;

/// The two names this program ships under (`[[bin]]` targets in Cargo.toml).
const KNOWN_INVOCATIONS: &[&str] = &["tethra", "api-tracker"];

/// The command name to brand `--help` and `--version` with, derived from
/// argv[0] so the legacy `api-tracker` entry point keeps identifying itself
/// as `api-tracker` (scripts that parse `api-tracker --version` still match).
///
/// argv[0] is caller-controlled — a symlink or an `exec -a` can set it to
/// arbitrary bytes, including terminal escapes — so the derived name is
/// matched against a fixed allowlist and anything unrecognized falls back to
/// the preferred product name. No caller-supplied text ever reaches the
/// rendered help or version output.
fn invoked_name() -> &'static str {
    std::env::args_os()
        .next()
        .map(PathBuf::from)
        .as_deref()
        .and_then(std::path::Path::file_stem)
        .and_then(|stem| stem.to_str())
        .and_then(|stem| KNOWN_INVOCATIONS.iter().find(|known| **known == stem))
        .copied()
        .unwrap_or("tethra")
}

#[derive(Parser)]
#[command(
    name = "tethra",
    version,
    about = "Local-first encrypted vault for organizing API credentials across projects",
    propagate_version = true
)]
struct Cli {
    /// Vault data directory (defaults to the platform data dir; the
    /// TETHRA_DIR environment variable — or the legacy API_TRACKER_DIR —
    /// also overrides it).
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
    /// Change the master password (re-wraps the vault key; reauthenticated).
    ChangePassword,
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
    /// Project templates and local stack detection.
    #[command(subcommand)]
    Template(template_cmd::TemplateCmd),
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
    Monitor {
        /// Skip network phases (due doc checks, webhook delivery).
        #[arg(long)]
        offline: bool,
        /// Show when monitoring last ran and how it went, without running.
        #[arg(long)]
        status: bool,
    },
    /// View and manage local alerts.
    #[command(subcommand)]
    Alerts(alerts_cmd::AlertsCmd),
    /// Usage synchronization and reports.
    #[command(subcommand)]
    Usage(usage_cmd::UsageCmd),
    /// Set and view budgets.
    #[command(subcommand)]
    Budget(usage_cmd::BudgetCmd),
    /// Versioned pricing records for local cost estimates.
    #[command(subcommand)]
    Pricing(pricing_cmd::PricingCmd),
    /// View local activity events.
    #[command(subcommand)]
    Activity(usage_cmd::ActivityCmd),
    /// Configure credential -> environment-variable mappings for `run`.
    #[command(subcommand)]
    Mapping(usage_cmd::MappingCmd),
    /// Run a command with credentials injected into its environment.
    Run(run_cmd::RunArgs),
    /// Inspect and manage runtime API observability (metadata-only).
    #[command(subcommand)]
    Observe(observe_cmd::ObserveCmd),
    /// .env governance: discover, preview, import, drift, export, cleanup.
    #[command(subcommand)]
    Env(env_cmd::EnvCmd),
    /// Secret destinations (keychain, AWS, GitHub Actions, Vercel, ...).
    #[command(subcommand)]
    Destination(destination_cmd::DestinationCmd),
    /// Synchronization plans for credential value changes.
    #[command(subcommand)]
    Sync(sync_cmd::SyncCmd),
    /// Safe, durable credential rotation.
    #[command(subcommand)]
    Rotation(rotation_cmd::RotationCmd),
    /// Temporary local access grants for `run`.
    #[command(subcommand)]
    Access(access_cmd::AccessCmd),
    /// Encrypted vault backups.
    #[command(subcommand)]
    Backup(backup_cmd::BackupCmd),
    /// User-configured webhook notification channels.
    #[command(subcommand)]
    Notify(alerts_cmd::NotifyCmd),
}

/// The whole program. Both shipped entry points — the preferred `tethra`
/// binary and the legacy `api-tracker` one — are one-line wrappers around
/// this, so the two commands cannot drift apart.
pub fn run_cli() {
    // Brand help/version with the name the program was invoked as, so the
    // legacy entry point stays self-consistent (`api-tracker --version` →
    // `api-tracker 0.1.0`). clap already derives the usage line from argv[0];
    // `name` additionally drives the version line.
    let name = invoked_name();
    let matches = Cli::command().name(name).bin_name(name).get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(err) => err.exit(),
    };
    if let Err(err) = run(cli) {
        // Error text can embed attacker-influenced content (imported file
        // fields, provider responses, paths); strip control characters so a
        // crafted value cannot inject terminal escapes through an error.
        eprintln!("error: {}", render::sanitize(&format!("{err:#}")));
        std::process::exit(1);
    }
    // Returning (rather than exit(0)) lets the runtime flush stdout, exactly
    // as the pre-refactor `fn main` did.
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let ctx = ctx::Ctx::new(cli.data_dir, cli.json)?;
    match cli.command {
        Commands::Init => vault_cmd::init(&ctx),
        Commands::Unlock(args) => vault_cmd::unlock(&ctx, args),
        Commands::Lock => vault_cmd::lock(&ctx),
        Commands::ChangePassword => vault_cmd::change_password(&ctx),
        Commands::Doctor => vault_cmd::doctor(&ctx),
        Commands::Settings(cmd) => vault_cmd::settings(&ctx, cmd),
        Commands::Provider(cmd) => provider_cmd::run(&ctx, cmd),
        Commands::Project(cmd) => project_cmd::run(&ctx, cmd),
        Commands::Template(cmd) => template_cmd::run(&ctx, cmd),
        Commands::Key(cmd) => key_cmd::run(&ctx, cmd),
        Commands::Scan(args) => scan_cmd::scan(&ctx, args),
        Commands::Hooks(cmd) => scan_cmd::hooks(&ctx, cmd),
        Commands::Suppress(cmd) => scan_cmd::suppress(&ctx, cmd),
        Commands::Monitor { offline, status } => alerts_cmd::monitor_run(&ctx, offline, status),
        Commands::Alerts(cmd) => alerts_cmd::alerts(&ctx, cmd),
        Commands::Usage(cmd) => usage_cmd::usage(&ctx, cmd),
        Commands::Budget(cmd) => usage_cmd::budget(&ctx, cmd),
        Commands::Pricing(cmd) => pricing_cmd::run(&ctx, cmd),
        Commands::Activity(cmd) => usage_cmd::activity(&ctx, cmd),
        Commands::Mapping(cmd) => usage_cmd::mapping(&ctx, cmd),
        Commands::Run(args) => run_cmd::run(&ctx, args),
        Commands::Observe(cmd) => observe_cmd::run(&ctx, cmd),
        Commands::Env(cmd) => env_cmd::run(&ctx, cmd),
        Commands::Destination(cmd) => destination_cmd::run(&ctx, cmd),
        Commands::Sync(cmd) => sync_cmd::run(&ctx, cmd),
        Commands::Rotation(cmd) => rotation_cmd::run(&ctx, cmd),
        Commands::Access(cmd) => access_cmd::run(&ctx, cmd),
        Commands::Backup(cmd) => backup_cmd::run(&ctx, cmd),
        Commands::Notify(cmd) => alerts_cmd::notify(&ctx, cmd),
    }
}
