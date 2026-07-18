//! Command context: data-directory resolution, session handling, and
//! password acquisition. All secret input goes through `SecretString` and is
//! never echoed or logged.

use anyhow::{bail, Context, Result};
use api_tracker_core::secret::SecretString;
use api_tracker_core::session::SessionToken;
use api_tracker_core::vault::{self, UnlockedVault, VaultPaths};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

pub const ENV_SESSION: &str = "API_TRACKER_SESSION";
pub const ENV_PASSWORD: &str = "API_TRACKER_PASSWORD";
pub const ENV_PROJECT_PASSWORD: &str = "API_TRACKER_PROJECT_PASSWORD";
pub const ENV_BACKUP_PASSWORD: &str = "API_TRACKER_BACKUP_PASSWORD";

pub struct Ctx {
    pub paths: VaultPaths,
    pub json: bool,
}

impl Ctx {
    pub fn new(data_dir: Option<PathBuf>, json: bool) -> Result<Self> {
        let dir = match data_dir {
            Some(dir) => dir,
            None => vault::default_data_dir()?,
        };
        Ok(Self {
            paths: VaultPaths::new(dir),
            json,
        })
    }

    /// Obtain an unlocked vault: from the session token if one is present,
    /// otherwise via `API_TRACKER_PASSWORD` (scripting), otherwise fail with
    /// instructions. Returns the token when a session was used, so mutations
    /// to session state (project unlock/lock) can be persisted.
    pub fn unlocked(&self) -> Result<(UnlockedVault, Option<SessionToken>)> {
        if let Ok(raw) = std::env::var(ENV_SESSION) {
            // An empty variable means "no session", not an invalid token.
            if !raw.trim().is_empty() {
                let token = SessionToken::decode(&raw)
                    .context("API_TRACKER_SESSION is not a valid session token")?;
                let vault = vault::resume_session(&self.paths, &token)?;
                return Ok((vault, Some(token)));
            }
        }
        if std::env::var_os(ENV_PASSWORD).is_some() {
            let password = env_secret(ENV_PASSWORD)?;
            let vault = vault::unlock_vault(&self.paths, &password)?;
            return Ok((vault, None));
        }
        bail!(
            "the vault is locked. Run `api-tracker unlock` and export {ENV_SESSION}, \
             or set {ENV_PASSWORD} for non-interactive use"
        );
    }

    /// Try to obtain an unlocked vault without ever prompting: only if a
    /// session token or password is already present in the environment.
    /// Used by scanning, which is useful even against a locked vault.
    pub fn try_unlocked(&self) -> Option<UnlockedVault> {
        let has_creds = std::env::var(ENV_SESSION)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
            || std::env::var_os(ENV_PASSWORD).is_some();
        if has_creds {
            self.unlocked().ok().map(|(v, _)| v)
        } else {
            None
        }
    }

    /// Read scan suppression keys from the local database without unlocking
    /// (they contain no secret material). Empty if no vault exists yet.
    pub fn suppression_keys(&self) -> std::collections::HashSet<String> {
        if !self.paths.vault_exists() {
            return Default::default();
        }
        match api_tracker_core::db::open(&self.paths.db_path()) {
            Ok(mut conn) => {
                let _ = api_tracker_core::db::migrate(&mut conn);
                api_tracker_core::vault::load_suppression_keys(&conn).unwrap_or_default()
            }
            Err(_) => Default::default(),
        }
    }

    /// Persist session-state changes (unlocked project keys) when running
    /// under a session token.
    pub fn persist_session(
        &self,
        vault: &UnlockedVault,
        token: &Option<SessionToken>,
    ) -> Result<()> {
        if let Some(token) = token {
            vault.save_session(token)?;
        }
        Ok(())
    }
}

fn env_secret(var: &str) -> Result<SecretString> {
    match std::env::var(var) {
        Ok(value) => Ok(SecretString::new(value)),
        Err(_) => bail!("{var} is not set or not valid UTF-8"),
    }
}

fn prompt_hidden(label: &str) -> Result<SecretString> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "cannot prompt for '{label}' without a terminal; \
             set the matching API_TRACKER_* environment variable"
        );
    }
    eprint!("{label}: ");
    std::io::stderr().flush()?;
    let value = rpassword::read_password().context("failed to read password input")?;
    Ok(SecretString::new(value))
}

/// The master password, for unlock and reauthentication.
pub fn master_password() -> Result<SecretString> {
    if std::env::var_os(ENV_PASSWORD).is_some() {
        return env_secret(ENV_PASSWORD);
    }
    prompt_hidden("Master password")
}

/// A newly chosen password, confirmed twice when prompted interactively.
pub fn new_password(what: &str, env_var: &str) -> Result<SecretString> {
    if std::env::var_os(env_var).is_some() {
        return env_secret(env_var);
    }
    let first = prompt_hidden(&format!("New {what}"))?;
    let second = prompt_hidden(&format!("Confirm {what}"))?;
    if !first.ct_eq(&second) {
        bail!("the passwords do not match");
    }
    Ok(first)
}

pub fn project_password() -> Result<SecretString> {
    if std::env::var_os(ENV_PROJECT_PASSWORD).is_some() {
        return env_secret(ENV_PROJECT_PASSWORD);
    }
    prompt_hidden("Project password")
}

pub fn backup_password(new: bool) -> Result<SecretString> {
    if std::env::var_os(ENV_BACKUP_PASSWORD).is_some() {
        return env_secret(ENV_BACKUP_PASSWORD);
    }
    if new {
        new_password("backup password", ENV_BACKUP_PASSWORD)
    } else {
        prompt_hidden("Backup password")
    }
}

/// A credential value: `--value-stdin` for scripts, hidden prompt otherwise.
/// Never accepted as a command-line argument (it would leak via `ps` and
/// shell history).
pub fn credential_value(value_stdin: bool) -> Result<SecretString> {
    if value_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read value from stdin")?;
        let value = SecretString::new(buf.trim_end_matches(['\n', '\r']).to_owned());
        if value.expose().trim().is_empty() {
            bail!("no credential value was provided on stdin");
        }
        return Ok(value);
    }
    prompt_hidden("Credential value (hidden)")
}

/// Interactive yes/no confirmation. Non-interactive runs must pass `--yes`.
pub fn confirm(question: &str, assume_yes: bool) -> Result<bool> {
    if assume_yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        bail!("refusing without confirmation; pass --yes to proceed non-interactively");
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
