//! `init`, `unlock`, `lock`, `doctor`, `settings`, and `provider` commands.

use crate::ctx::{self, Ctx};
use crate::render;
use anyhow::{bail, Result};
use api_tracker_core::db;
use api_tracker_core::envcompat;
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
    println!("  - Create encrypted backups regularly: `tethra backup create <path>`.");
    drop(vault);
    Ok(())
}

#[derive(Args)]
pub struct UnlockArgs {
    /// Print only the session export lines (for eval). Both the preferred
    /// `TETHRA_SESSION` and the legacy `API_TRACKER_SESSION` line are
    /// printed — legacy first, so scripts that parse the legacy line keep
    /// working — and `eval` leaves both variables set to the same token.
    #[arg(long)]
    pub print_export: bool,
}

pub fn unlock(ctx: &Ctx, args: UnlockArgs) -> Result<()> {
    let password = ctx::master_password()?;
    let mut vault = vault::unlock_vault(&ctx.paths, &password)?;
    let token = SessionToken::generate();
    vault.save_session(&token)?;
    let auto_lock = vault.settings().auto_lock_minutes;
    // A re-authorized session cancels any pending keep-while-locked
    // matching-key retention deadline in a running gateway (ADR 0020), and
    // installs the custom-origin route verification key so routes the user
    // already consented to become forwardable again (ADR 0021). Neither
    // moves credential-bearing material; the matching key is NOT re-pushed
    // here — that stays reauth-gated and explicit.
    let _ = api_tracker_gateway::control::notify_vault_unlocked(&ctx.paths.data_dir);
    crate::gateway_cmd::install_route_key_on_unlock(ctx, &mut vault);
    if args.print_export {
        print_session_exports(&token);
    } else {
        eprintln!("Vault unlocked.");
        if auto_lock > 0 {
            eprintln!("The session expires after {auto_lock} minute(s) of inactivity.");
        } else {
            eprintln!("Auto-lock is disabled; the session will not expire on its own.");
        }
        eprintln!();
        eprintln!("Run this in your shell to use the session:");
        print_session_exports(&token);
    }
    Ok(())
}

/// The legacy line prints first so old scripts that parse
/// `export API_TRACKER_SESSION="..."` still find it; both variables carry
/// the same token, so precedence never matters after an `eval`.
fn print_session_exports(token: &SessionToken) {
    println!(
        "export {}=\"{}\"",
        envcompat::legacy_name(ctx::ENV_SESSION),
        token.encode()
    );
    println!(
        "export {}=\"{}\"",
        envcompat::preferred_name(ctx::ENV_SESSION),
        token.encode()
    );
}

pub fn lock(ctx: &Ctx) -> Result<()> {
    let existed = session::destroy(&ctx.paths)?;
    if existed {
        println!("Session ended; the vault is locked for the CLI.");
    } else {
        println!("No active session; the vault was already locked.");
    }
    // Any lock event drops the gateway's resident matching key (default;
    // ADR 0020 / SI-9) — including a CLI lock while the desktop still holds
    // a session, which errs toward revocation: the desktop can re-push. The
    // CLI cannot read auto_lock_minutes without a password, so it sends no
    // TTL; with keep-while-locked ON the service applies the 8-hour cap.
    if api_tracker_gateway::control::notify_vault_locked(&ctx.paths.data_dir, None) {
        println!(
            "A running gateway was notified; credential matching pauses unless \
             keep-while-locked is enabled."
        );
    }
    println!(
        "(If you exported {new} or {old}, unset them: `unset {new} {old}`.)",
        new = envcompat::preferred_name(ctx::ENV_SESSION),
        old = envcompat::legacy_name(ctx::ENV_SESSION)
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

pub fn change_password(ctx: &Ctx) -> Result<()> {
    let (mut vault, _token) = ctx.unlocked()?;
    eprintln!("Changing the master password re-wraps the vault key; no data is re-encrypted.");
    eprintln!("Note: backups made BEFORE the change still open with the OLD password.");
    eprintln!("Current master password:");
    let current = ctx::master_password()?;
    eprintln!(
        "Choose a new master password of at least {} characters.",
        vault::MIN_PASSWORD_LEN
    );
    let new = ctx::new_password("new master password", "NEW_PASSWORD")?;
    vault.change_master_password(&current, &new)?;
    println!("Master password changed.");
    println!("  - Existing CLI sessions keep working until they expire.");
    println!("  - Backups made before this change still need the OLD password to restore.");
    println!("  - Consider creating a fresh backup now: `tethra backup create <path>`.");
    Ok(())
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
            .push("no vault found; run `tethra init`".to_owned());
    }
    if !cfg!(unix) {
        report.warnings.push(
            "on this platform file permissions are OS-inherited (no owner-only mode is \
             applied); treat the data directory itself as sensitive material"
                .to_owned(),
        );
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
