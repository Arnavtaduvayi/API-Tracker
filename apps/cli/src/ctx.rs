//! Command context: data-directory resolution, session handling, and
//! password acquisition. All secret input goes through `SecretString` and is
//! never echoed or logged.
//!
//! Environment variables resolve through `envcompat`: the preferred
//! `TETHRA_*` name wins whenever present; the legacy `API_TRACKER_*` name
//! keeps working as a fallback (see docs/rebrand/TETHRA_COMPATIBILITY_MATRIX.md).

use anyhow::{bail, Context, Result};
use api_tracker_core::envcompat;
use api_tracker_core::secret::SecretString;
use api_tracker_core::session::SessionToken;
use api_tracker_core::vault::{self, UnlockedVault, VaultPaths};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

/// Variable-name suffixes; the full names are `TETHRA_<suffix>` and
/// `API_TRACKER_<suffix>`.
pub const ENV_SESSION: &str = "SESSION";
pub const ENV_PASSWORD: &str = "PASSWORD";
pub const ENV_PROJECT_PASSWORD: &str = "PROJECT_PASSWORD";
pub const ENV_BACKUP_PASSWORD: &str = "BACKUP_PASSWORD";
pub const ENV_PROVIDER_ADMIN_KEY: &str = "PROVIDER_ADMIN_KEY";

pub struct Ctx {
    pub paths: VaultPaths,
    pub json: bool,
}

impl Ctx {
    pub fn new(data_dir: Option<PathBuf>, json: bool) -> Result<Self> {
        // Absolutize ONCE, here, at the single point of entry. The resolved
        // path is baked into the service argv at install time, and launchd /
        // systemd / Task Scheduler start the service with a working directory
        // of `/` — so `--data-dir ./vault` would silently resolve to a
        // DIFFERENT vault in the service than in the CLI. It also breaks
        // install's foreign-data-dir guard, which compares raw path buffers.
        // Three documents plus the lifecycle module header already state that
        // this resolution happens; now it does.
        //
        // `std::path::absolute`, not `canonicalize`: the directory may not
        // exist yet (first run), and symlink resolution is not wanted — the
        // user's chosen path is what should be recorded.
        let dir = match data_dir {
            Some(dir) => dir,
            None => vault::default_data_dir()?,
        };
        let dir = std::path::absolute(&dir).unwrap_or(dir);
        Ok(Self {
            paths: VaultPaths::new(dir),
            json,
        })
    }

    /// Obtain an unlocked vault: from the session token if one is present,
    /// otherwise via `TETHRA_PASSWORD` / legacy `API_TRACKER_PASSWORD`
    /// (scripting), otherwise fail with instructions. Returns the token when
    /// a session was used, so mutations to session state (project
    /// unlock/lock) can be persisted.
    ///
    /// A session variable holding a stale or invalid token does NOT wedge
    /// scripting: if the session path fails and a password variable is set,
    /// the password is tried before giving up. (After the rename, an eval'd
    /// `unlock --print-export` sets BOTH session variables; an older script
    /// that unsets only `API_TRACKER_SESSION` after `lock` would otherwise
    /// strand a revoked token in `TETHRA_SESSION` and fail every following
    /// password-driven command.)
    pub fn unlocked(&self) -> Result<(UnlockedVault, Option<SessionToken>)> {
        let session_err = match self.session_unlocked() {
            Ok(Some(mut ok)) => {
                upgrade_restore_records(&mut ok.0);
                return Ok(ok);
            }
            Ok(None) => None,
            Err(err) => Some(err),
        };
        if envcompat::is_set(ENV_PASSWORD) {
            let password = env_secret(ENV_PASSWORD)?;
            let mut vault = vault::unlock_vault(&self.paths, &password)?;
            upgrade_restore_records(&mut vault);
            return Ok((vault, None));
        }
        if let Some(err) = session_err {
            return Err(err);
        }
        bail!(
            "the vault is locked. Run `tethra unlock` and export {}, \
             or set {} for non-interactive use",
            envcompat::preferred_name(ENV_SESSION),
            envcompat::hint(ENV_PASSWORD)
        );
    }

    /// The session path alone: `Ok(None)` when no session variable is set
    /// (or it is empty, which means "no session"), `Err` when one is set but
    /// does not produce a live session.
    fn session_unlocked(&self) -> Result<Option<(UnlockedVault, Option<SessionToken>)>> {
        let Some(Ok(raw)) = envcompat::var(ENV_SESSION) else {
            return Ok(None);
        };
        if raw.trim().is_empty() {
            return Ok(None);
        }
        let token = SessionToken::decode(&raw).with_context(|| {
            format!(
                "{} is not a valid session token",
                envcompat::active_name(ENV_SESSION)
                    .unwrap_or_else(|| envcompat::preferred_name(ENV_SESSION))
            )
        })?;
        let vault = vault::resume_session(&self.paths, &token)?;
        Ok(Some((vault, Some(token))))
    }

    /// Try to obtain an unlocked vault without ever prompting: only if a
    /// session token or password is already present in the environment.
    /// Used by scanning, which is useful even against a locked vault.
    pub fn try_unlocked(&self) -> Option<UnlockedVault> {
        let has_creds = envcompat::var(ENV_SESSION)
            .and_then(|v| v.ok())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
            || envcompat::is_set(ENV_PASSWORD);
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

fn env_secret(suffix: &str) -> Result<SecretString> {
    match envcompat::var(suffix) {
        Some(Ok(value)) => Ok(SecretString::new(value)),
        Some(Err(name)) => bail!("{name} is not valid UTF-8"),
        None => bail!("{} is not set", envcompat::hint(suffix)),
    }
}

fn prompt_hidden(label: &str) -> Result<SecretString> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "cannot prompt for '{label}' without a terminal; \
             set the matching TETHRA_* (or legacy API_TRACKER_*) environment variable"
        );
    }
    eprint!("{label}: ");
    std::io::stderr().flush()?;
    let value = rpassword::read_password().context("failed to read password input")?;
    Ok(SecretString::new(value))
}

/// A hidden one-off secret prompt (destination credentials etc.).
pub fn prompt_secret(label: &str) -> Result<SecretString> {
    prompt_hidden(label)
}

/// The master password, for unlock and reauthentication.
pub fn master_password() -> Result<SecretString> {
    if envcompat::is_set(ENV_PASSWORD) {
        return env_secret(ENV_PASSWORD);
    }
    prompt_hidden("Master password")
}

/// The master password from the environment only — `None` when unset.
/// `track --yes` uses this so a non-interactive run can include
/// attribution WITHOUT ever prompting or failing over its absence (O-22-3).
pub fn master_password_from_env() -> Option<SecretString> {
    if envcompat::is_set(ENV_PASSWORD) {
        env_secret(ENV_PASSWORD).ok()
    } else {
        None
    }
}

/// A newly chosen password, confirmed twice when prompted interactively.
/// `env_suffix` names the `TETHRA_*`/`API_TRACKER_*` pair consulted first.
pub fn new_password(what: &str, env_suffix: &str) -> Result<SecretString> {
    if envcompat::is_set(env_suffix) {
        return env_secret(env_suffix);
    }
    let first = prompt_hidden(&format!("New {what}"))?;
    let second = prompt_hidden(&format!("Confirm {what}"))?;
    if !first.ct_eq(&second) {
        bail!("the passwords do not match");
    }
    Ok(first)
}

pub fn project_password() -> Result<SecretString> {
    if envcompat::is_set(ENV_PROJECT_PASSWORD) {
        return env_secret(ENV_PROJECT_PASSWORD);
    }
    prompt_hidden("Project password")
}

pub fn backup_password(new: bool) -> Result<SecretString> {
    if envcompat::is_set(ENV_BACKUP_PASSWORD) {
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

/// A provider administrative key: `--key-stdin` for scripts, the
/// `TETHRA_PROVIDER_ADMIN_KEY` (or legacy `API_TRACKER_PROVIDER_ADMIN_KEY`)
/// variable, or a hidden prompt. Never accepted as a command-line argument
/// (it would leak via `ps` and shell history) and never echoed.
pub fn provider_admin_key(key_stdin: bool) -> Result<SecretString> {
    if key_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read the admin key from stdin")?;
        let value = SecretString::new(buf.trim_end_matches(['\n', '\r']).to_owned());
        if value.expose().trim().is_empty() {
            bail!("no administrative key was provided on stdin");
        }
        return Ok(value);
    }
    if envcompat::is_set(ENV_PROVIDER_ADMIN_KEY) {
        return env_secret(ENV_PROVIDER_ADMIN_KEY);
    }
    prompt_hidden("Administrative key (hidden)")
}

/// Interactive yes/no confirmation that CANNOT be pre-answered.
///
/// Deliberately takes no `assume_yes`: it is used for decisions that a
/// blanket "proceed" must not cover — approving a network destination the
/// project chose (ADR 0024). Default is no, and a non-terminal answers no
/// rather than erroring, so the caller can report which destinations were
/// left unconfigured and continue with the rest.
pub fn confirm_default_no(question: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        return Ok(false);
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

/// Re-seal any `.env` restore record an earlier build stored in plaintext
/// (RA-006).
///
/// Runs at unlock because that is the only moment a key is definitionally
/// available: the read-only entry points (`track status`, `track doctor`)
/// hold no vault, and redacting a legacy record without a key would destroy
/// the user's ability to undo the link. Best-effort and once per vault — it
/// must never stop the command the user actually asked for.
fn upgrade_restore_records(vault: &mut UnlockedVault) {
    // The migration itself lives in the gateway crate so the desktop runs the
    // SAME code (`ENC-01`): ADR 0028 claimed both front ends ran it, and only
    // this one did, which left a GUI-only user's plaintext in place forever.
    match api_tracker_gateway::envlink::upgrade_restore_records(vault) {
        Ok(_) => {}
        Err(e) => {
            // Actionable, and value-free: the user is told the upgrade did not
            // complete and that it will be retried, not what was in the row.
            eprintln!(
                "warning: could not re-seal legacy rollback records ({}); \
                 they remain readable in the vault database and Tethra will try \
                 again at the next unlock",
                e.code()
            );
        }
    }
}
