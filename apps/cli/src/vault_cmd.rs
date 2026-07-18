//! `init`, `unlock`, `lock`, `doctor`, `settings`, and `provider` commands.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::db;
use api_tracker_core::session::{self, SessionToken};
use api_tracker_core::settings::VaultSettings;
use api_tracker_core::vault::{self};
use clap::{Args, Subcommand};
use serde::Serialize;

pub fn init(ctx: &Ctx) -> Result<()> {
    if ctx.paths.vault_exists() {
        bail!(
            "a vault already exists at {} (an existing vault is never overwritten)",
            ctx.paths.db_path().display()
        );
    }
    eprintln!(
        "Creating a new encrypted vault at {}",
        ctx.paths.db_path().display()
    );
    eprintln!(
        "Choose a master password of at least {} characters. A long multi-word \
         passphrase is the strongest choice.",
        vault::MIN_PASSWORD_LEN
    );
    let password = ctx::new_password("master password", ctx::ENV_PASSWORD)?;
    let vault = vault::create_vault(&ctx.paths, &password)?;
    println!("Vault created at {}", ctx.paths.db_path().display());
    println!();
    println!("Important recovery information:");
    println!("  - The master password is NOT stored anywhere and cannot be recovered.");
    println!("  - If you lose it, the vault contents are unrecoverable by design.");
    println!("  - Create encrypted backups regularly: `api-tracker backup create <path>`.");
    drop(vault);
    Ok(())
}

#[derive(Args)]
pub struct UnlockArgs {
    /// Print only the `export API_TRACKER_SESSION=...` line (for eval).
    #[arg(long)]
    pub print_export: bool,
}

pub fn unlock(ctx: &Ctx, args: UnlockArgs) -> Result<()> {
    let password = ctx::master_password()?;
    let vault = vault::unlock_vault(&ctx.paths, &password)?;
    let token = SessionToken::generate();
    vault.save_session(&token)?;
    let auto_lock = vault.settings().auto_lock_minutes;
    if args.print_export {
        println!("export {}=\"{}\"", ctx::ENV_SESSION, token.encode());
    } else {
        eprintln!("Vault unlocked.");
        if auto_lock > 0 {
            eprintln!("The session expires after {auto_lock} minute(s) of inactivity.");
        } else {
            eprintln!("Auto-lock is disabled; the session will not expire on its own.");
        }
        eprintln!();
        eprintln!("Run this in your shell to use the session:");
        println!("export {}=\"{}\"", ctx::ENV_SESSION, token.encode());
    }
    Ok(())
}

pub fn lock(ctx: &Ctx) -> Result<()> {
    let existed = session::destroy(&ctx.paths)?;
    if existed {
        println!("Session ended; the vault is locked for the CLI.");
    } else {
        println!("No active session; the vault was already locked.");
    }
    println!(
        "(If you exported {}, unset it: `unset {}`.)",
        ctx::ENV_SESSION,
        ctx::ENV_SESSION
    );
    Ok(())
}

#[derive(Serialize)]
struct DoctorReport {
    data_dir: String,
    vault_exists: bool,
    schema_version: Option<i64>,
    expected_schema_version: i64,
    integrity: Option<String>,
    session: Option<session::SessionStatus>,
    project_count: Option<i64>,
    credential_count: Option<i64>,
    settings: Option<VaultSettings>,
    warnings: Vec<String>,
}

pub fn doctor(ctx: &Ctx) -> Result<()> {
    let mut report = DoctorReport {
        data_dir: ctx.paths.data_dir.display().to_string(),
        vault_exists: ctx.paths.vault_exists(),
        schema_version: None,
        expected_schema_version: db::current_schema_version(),
        integrity: None,
        session: None,
        project_count: None,
        credential_count: None,
        settings: None,
        warnings: Vec::new(),
    };
    if report.vault_exists {
        let conn = db::open(&ctx.paths.db_path())?;
        report.schema_version = Some(db::user_version(&conn)?);
        let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        report.integrity = Some(integrity.clone());
        if integrity != "ok" {
            report
                .warnings
                .push("SQLite integrity check FAILED".to_owned());
        }
        report.project_count =
            Some(conn.query_row("SELECT count(*) FROM projects", [], |r| r.get(0))?);
        report.credential_count =
            Some(conn.query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))?);
        report.settings = Some(VaultSettings::load(&conn)?);
        report.session = session::status(&ctx.paths)?;
        // Warn about registered repository paths that no longer exist.
        let mut stmt = conn.prepare(
            "SELECT p.name, r.path FROM project_repos r JOIN projects p ON p.id = r.project_id",
        )?;
        let repos: Vec<(String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        for (project, path) in repos {
            if !std::path::Path::new(&path).exists() {
                report.warnings.push(format!(
                    "project '{project}': repository path '{path}' does not exist"
                ));
            }
        }
    } else {
        report
            .warnings
            .push("no vault found; run `api-tracker init`".to_owned());
    }

    render::emit(ctx.json, &report, || {
        println!("Data directory:  {}", report.data_dir);
        println!(
            "Vault exists:    {}",
            if report.vault_exists { "yes" } else { "no" }
        );
        if let Some(v) = report.schema_version {
            println!(
                "Schema version:  {v} (this build expects {})",
                report.expected_schema_version
            );
        }
        if let Some(i) = &report.integrity {
            println!("DB integrity:    {i}");
        }
        if let (Some(p), Some(c)) = (report.project_count, report.credential_count) {
            println!("Projects:        {p}");
            println!("Credentials:     {c}");
        }
        if let Some(s) = &report.settings {
            println!(
                "Auto-lock:       {} minute(s) (0 = disabled)",
                s.auto_lock_minutes
            );
        }
        match &report.session {
            Some(s) => println!(
                "Session:         active since {} (expires {})",
                s.created_at,
                s.expires_at.as_deref().unwrap_or("never")
            ),
            None => println!("Session:         none (locked)"),
        }
        for warning in &report.warnings {
            println!("WARNING:         {warning}");
        }
    });
    Ok(())
}

#[derive(Subcommand)]
pub enum SettingsCmd {
    /// Show current settings.
    Show,
    /// Change a setting (requires an unlocked vault).
    Set {
        /// One of: auto_lock_minutes, expiring_soon_days, unused_days,
        /// stale_days, clipboard_clear_seconds.
        key: String,
        value: u32,
    },
}

pub fn settings(ctx: &Ctx, cmd: SettingsCmd) -> Result<()> {
    match cmd {
        SettingsCmd::Show => {
            if !ctx.paths.vault_exists() {
                bail!("no vault found at {}", ctx.paths.db_path().display());
            }
            let conn = db::open(&ctx.paths.db_path())?;
            let settings = VaultSettings::load(&conn)?;
            render::emit(ctx.json, &settings, || {
                for key in VaultSettings::known_keys() {
                    println!("{key} = {}", settings.get_field(key).expect("known key"));
                }
            });
        }
        SettingsCmd::Set { key, value } => {
            let (mut vault, token) = ctx.unlocked()?;
            let mut settings = vault.settings().clone();
            settings.set_field(&key, value)?;
            vault.update_settings(settings.clone())?;
            // Re-persist the session so a changed auto-lock takes effect on
            // the live session's TTL, not only on the next unlock.
            ctx.persist_session(&vault, &token)?;
            println!("{key} = {value}");
        }
    }
    Ok(())
}
