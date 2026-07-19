//! Configuration and bookkeeping for secure process injection.
//!
//! This module stores the project's credential→environment-variable mappings
//! and records process-injection sessions (variable NAMES only, never
//! values). Decryption of the selected credentials and spawning of the child
//! process happen in the vault and the CLI respectively — this module never
//! holds a plaintext secret.

use crate::clock;
use crate::error::{CoreError, Result};
use rusqlite::{params, Connection, Row};
use serde::Serialize;
use uuid::Uuid;

/// A configured credential→env-var mapping for a project.
#[derive(Debug, Clone, Serialize)]
pub struct EnvMapping {
    pub project_id: String,
    pub credential_id: String,
    pub credential_name: String,
    pub env_var: String,
}

/// The environment-variable prefix owned by API Tracker.
pub const ENV_PREFIX: &str = "API_TRACKER_";

/// The only `API_TRACKER_*` variables a spawned child may inherit. Every
/// other variable under the prefix is treated as authentication, password,
/// session, or internal control material and scrubbed by default, so a
/// variable added in the future is protected without anyone remembering to
/// enumerate it here.
///
/// - `API_TRACKER_DIR` — data-directory override: a plain path, required so
///   a child that itself invokes `api-tracker` talks to the same vault.
/// - `API_TRACKER_INSECURE_FAST_KDF` — debug-build-only KDF weakening used
///   by test harnesses; secretless, ignored by release builds.
///
/// Everything else currently in use is sensitive: `API_TRACKER_PASSWORD`,
/// `API_TRACKER_NEW_PASSWORD`, `API_TRACKER_PROJECT_PASSWORD`,
/// `API_TRACKER_BACKUP_PASSWORD` (password material),
/// `API_TRACKER_SESSION` (session material), and
/// `API_TRACKER_PROVIDER_ADMIN_KEY` / `API_TRACKER_DESTINATION_AUTH`
/// (authentication material).
pub const CHILD_SAFE_ENV: &[&str] = &["API_TRACKER_DIR", "API_TRACKER_INSECURE_FAST_KDF"];

/// ASCII case-insensitive byte-slice equality (non-ASCII bytes compared
/// verbatim). Used for the Windows scrub, where env names are matched
/// case-insensitively by the OS.
fn ascii_ci_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn ascii_ci_starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.len() >= prefix.len() && ascii_ci_eq(&bytes[..prefix.len()], prefix)
}

/// Whether an environment variable name must be scrubbed from an injected
/// child. `case_insensitive` selects the platform's env-name semantics:
/// Windows env lookups are case-insensitive, so ANY casing of the
/// `API_TRACKER_` prefix (e.g. `Api_Tracker_Password`) is an alias the app
/// could still read and must be scrubbed (RA-4); Unix env names are
/// case-sensitive, so only the exact-case prefix is API Tracker's and a
/// differently-cased name is an unrelated variable left untouched. The
/// child-safe allowlist is matched with the same case sensitivity.
pub fn env_name_is_scrubbed(name: &[u8], case_insensitive: bool) -> bool {
    let prefix = ENV_PREFIX.as_bytes();
    let prefix_match = if case_insensitive {
        ascii_ci_starts_with(name, prefix)
    } else {
        name.starts_with(prefix)
    };
    if !prefix_match {
        return false;
    }
    let child_safe = CHILD_SAFE_ENV.iter().any(|safe| {
        let safe = safe.as_bytes();
        if case_insensitive {
            ascii_ci_eq(safe, name)
        } else {
            safe == name
        }
    });
    !child_safe
}

/// Remove every API Tracker environment variable that is not explicitly
/// child-safe from a command about to be spawned. An injected child must
/// receive only the credentials mapped for it — never the master password,
/// session token, or other API Tracker authentication material that may sit
/// in the parent's environment for scripting (PI-01). Byte-level prefix
/// matching so a non-UTF-8 name cannot dodge the scrub. On Windows the match
/// is case-insensitive so an unusual-casing alias cannot leak (RA-4); on
/// Unix it stays case-sensitive, preserving normal env semantics.
pub fn scrub_own_env(cmd: &mut std::process::Command) {
    let case_insensitive = cfg!(windows);
    for (name, _) in std::env::vars_os() {
        if env_name_is_scrubbed(name.as_encoded_bytes(), case_insensitive) {
            cmd.env_remove(&name);
        }
    }
}

/// A POSIX-ish environment variable name: starts with a letter or `_`, then
/// letters/digits/`_`. Rejects shell metacharacters.
pub fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false)
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn set_mapping(
    conn: &Connection,
    project_id: &str,
    credential_id: &str,
    env_var: &str,
) -> Result<()> {
    if !valid_env_name(env_var) {
        return Err(CoreError::InvalidInput(format!(
            "'{env_var}' is not a valid environment-variable name"
        )));
    }
    conn.execute(
        "INSERT INTO credential_env_mappings (project_id, credential_id, env_var)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(project_id, env_var) DO UPDATE SET credential_id = excluded.credential_id",
        params![project_id, credential_id, env_var],
    )?;
    Ok(())
}

pub fn remove_mapping(conn: &Connection, project_id: &str, env_var: &str) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM credential_env_mappings WHERE project_id = ?1 AND env_var = ?2",
        params![project_id, env_var],
    )?;
    Ok(n > 0)
}

pub fn list_mappings(conn: &Connection, project_id: &str) -> Result<Vec<EnvMapping>> {
    let mut stmt = conn.prepare(
        "SELECT m.project_id, m.credential_id, c.name, m.env_var
         FROM credential_env_mappings m JOIN credentials c ON c.id = m.credential_id
         WHERE m.project_id = ?1 ORDER BY m.env_var",
    )?;
    let rows = stmt.query_map([project_id], |r: &Row<'_>| {
        Ok(EnvMapping {
            project_id: r.get(0)?,
            credential_id: r.get(1)?,
            credential_name: r.get(2)?,
            env_var: r.get(3)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSession {
    pub id: String,
    pub project_id: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub command: String,
    pub injected_vars: String,
    pub exit_code: Option<i64>,
    /// PID recorded at spawn time. A recorded PID proves what was launched,
    /// not that the process is still alive (rows are closed by the launching
    /// `run` process; if that process itself died, the row stays open).
    pub pid: Option<i64>,
    /// The access grant that authorized the launch, when there was one.
    pub grant_id: Option<String>,
    /// Platform-reported process identity (start time + executable name)
    /// captured at spawn while the child handle was still held, so the PID
    /// provably referred to our child at capture time. Termination re-probes
    /// and refuses on mismatch (PID reuse). `None` = capture unavailable;
    /// such sessions are refused termination.
    pub proc_identity: Option<String>,
}

/// Record the start of an injection session. `command` and `injected_vars`
/// must contain no secret values (names only).
pub fn start_session(
    conn: &Connection,
    project_id: &str,
    command: &str,
    injected_var_names: &[String],
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO process_sessions (id, project_id, started_at, command, injected_vars)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id,
            project_id,
            clock::now_rfc3339(),
            command,
            injected_var_names.join(",")
        ],
    )?;
    Ok(id)
}

/// Record the spawned child's PID (for temporary-access termination) and
/// the grant that authorized the launch. The child's platform identity
/// (start time + executable) is probed HERE, while the caller still holds
/// the unreaped child handle — the only moment the PID is guaranteed not to
/// have been recycled — and stored beside the PID. If the probe cannot
/// establish identity, `NULL` is stored and later termination of this
/// session is refused rather than signalling an unverified PID.
pub fn set_session_pid(
    conn: &Connection,
    session_id: &str,
    pid: u32,
    grant_id: Option<&str>,
) -> Result<()> {
    let identity = match probe_process_identity(i64::from(pid)) {
        IdentityProbe::Found(identity) => Some(identity),
        IdentityProbe::NotFound | IdentityProbe::Unverifiable => None,
    };
    conn.execute(
        "UPDATE process_sessions SET pid = ?1, grant_id = ?2, proc_identity = ?3 WHERE id = ?4",
        params![i64::from(pid), grant_id, identity, session_id],
    )?;
    Ok(())
}

/// Running sessions (not ended) launched under a grant, with their PIDs.
pub fn running_sessions_for_grant(conn: &Connection, grant_id: &str) -> Result<Vec<(String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT id, pid FROM process_sessions
         WHERE grant_id = ?1 AND ended_at IS NULL AND pid IS NOT NULL",
    )?;
    let rows = stmt.query_map([grant_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn end_session(conn: &Connection, session_id: &str, exit_code: Option<i32>) -> Result<()> {
    conn.execute(
        "UPDATE process_sessions SET ended_at = ?1, exit_code = ?2 WHERE id = ?3",
        params![clock::now_rfc3339(), exit_code.map(i64::from), session_id],
    )?;
    Ok(())
}

/// Close session rows whose recorded process no longer exists. A launcher
/// that crashed leaves its row "running" forever otherwise. Detection is a
/// `ps -p <pid>` liveness probe (POSIX; reports any user's process without
/// signal-permission ambiguity): only a definitive "not found" closes the
/// row. Unix only; on other platforms this is a no-op and rows close on
/// child exit as before. Returns how many rows were closed.
pub fn sweep_dead_sessions(conn: &Connection) -> Result<usize> {
    #[cfg(unix)]
    {
        let rows: Vec<(String, i64)> = conn
            .prepare(
                "SELECT id, pid FROM process_sessions
                 WHERE ended_at IS NULL AND pid IS NOT NULL",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut closed = 0usize;
        for (id, pid) in rows {
            if pid <= 0 {
                continue;
            }
            let probe = std::process::Command::new("ps")
                .args(["-p", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            // Only ps's definitive "no matching process" (exit code exactly
            // 1) closes the row. A ps that failed to spawn, was signal-
            // killed, or exited with any other code proves nothing and
            // changes nothing — a live session must never be closed by an
            // environmental ps failure.
            let gone = matches!(probe, Ok(status) if status.code() == Some(1));
            if gone {
                conn.execute(
                    "UPDATE process_sessions SET ended_at = ?1 WHERE id = ?2 AND ended_at IS NULL",
                    params![clock::now_rfc3339(), id],
                )?;
                closed += 1;
            }
        }
        Ok(closed)
    }
    #[cfg(not(unix))]
    {
        let _ = conn;
        Ok(0)
    }
}

pub fn list_sessions(
    conn: &Connection,
    limit: u32,
    active_only: bool,
) -> Result<Vec<ProcessSession>> {
    let filter = if active_only {
        "WHERE ended_at IS NULL"
    } else {
        ""
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT id, project_id, started_at, ended_at, command, injected_vars, exit_code,
                pid, grant_id, proc_identity
         FROM process_sessions {filter} ORDER BY started_at DESC LIMIT ?1",
    ))?;
    let rows = stmt.query_map([limit], |r: &Row<'_>| {
        Ok(ProcessSession {
            id: r.get(0)?,
            project_id: r.get(1)?,
            started_at: r.get(2)?,
            ended_at: r.get(3)?,
            command: r.get(4)?,
            injected_vars: r.get(5)?,
            exit_code: r.get(6)?,
            pid: r.get(7)?,
            grant_id: r.get(8)?,
            proc_identity: r.get(9)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Look one session up by id (or unambiguous id prefix).
pub fn get_session(conn: &Connection, ident: &str) -> Result<ProcessSession> {
    let all = list_sessions(conn, u32::MAX, false)?;
    let matches: Vec<_> = all
        .into_iter()
        .filter(|s| s.id == ident || s.id.starts_with(ident))
        .collect();
    match matches.len() {
        0 => Err(crate::error::CoreError::NotFound {
            kind: "process session",
            ident: ident.to_string(),
        }),
        1 => Ok(matches.into_iter().next().expect("len checked")),
        _ => Err(crate::error::CoreError::Ambiguous {
            kind: "process session",
            ident: ident.to_string(),
        }),
    }
}

/// Result of probing a PID's platform identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityProbe {
    /// The process exists and reported a stable identity string.
    Found(String),
    /// The platform definitively reports no such process.
    NotFound,
    /// Identity could not be established (probe tool missing/failed,
    /// non-positive PID, ambiguous output). Callers must treat this as
    /// "do not signal".
    Unverifiable,
}

/// Probe a process's platform identity: start time plus executable name,
/// prefixed with the platform family so an identity recorded on one OS never
/// compares equal on another.
///
/// - **Unix (macOS/Linux):** two `LC_ALL=C ps` probes (`lstart=`, `comm=`).
///   `ps` exiting 1 with empty output is the definitive "no such process"
///   (same convention as [`sweep_dead_sessions`]). If the two probes
///   disagree about existence (the process died between them) the result is
///   `Unverifiable` — never a guess.
/// - **Windows:** one PowerShell `Get-CimInstance Win32_Process` query for
///   `CreationDate` + `Name`. Behavioural coverage on Windows is manual
///   (CI compiles but does not execute this path); the structure mirrors
///   Unix and fails closed to `Unverifiable`.
///
/// PID start-time identity has second-level granularity; the executable name
/// is a second factor so a recycled PID with a coincidentally identical
/// start second still fails the match.
pub fn probe_process_identity(pid: i64) -> IdentityProbe {
    if pid <= 0 {
        return IdentityProbe::Unverifiable;
    }
    #[cfg(unix)]
    {
        fn ps_field(pid: i64, field: &str) -> std::result::Result<Option<String>, ()> {
            let out = std::process::Command::new("ps")
                .env("LC_ALL", "C")
                .args(["-p", &pid.to_string(), "-o", field])
                .output()
                .map_err(|_| ())?;
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if text.is_empty() {
                    return Err(()); // success but no value: proves nothing
                }
                return Ok(Some(text));
            }
            // Exit code exactly 1 is ps's definitive "no matching process".
            // Any other failure (spawn error, signal, other codes) proves
            // nothing and must not be read as "gone".
            if out.status.code() == Some(1) {
                return Ok(None);
            }
            Err(())
        }
        match (ps_field(pid, "lstart="), ps_field(pid, "comm=")) {
            (Ok(Some(lstart)), Ok(Some(comm))) => {
                IdentityProbe::Found(format!("unix:lstart={lstart};comm={comm}"))
            }
            (Ok(None), Ok(None)) => IdentityProbe::NotFound,
            // Disagreement or probe failure: the state changed mid-probe or
            // the tool is unusable — refuse rather than guess.
            _ => IdentityProbe::Unverifiable,
        }
    }
    #[cfg(not(unix))]
    {
        // `pid` is formatted from i64 — no untrusted text reaches the query.
        let script = format!(
            "$p = Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}'; \
             if ($p) {{ Write-Output (\"$($p.CreationDate.ToUniversalTime().ToString('yyyyMMddHHmmss.ffffff'))|$($p.Name)\") }} else {{ exit 1 }}"
        );
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output();
        match out {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if text.is_empty() {
                    IdentityProbe::Unverifiable
                } else {
                    IdentityProbe::Found(format!("win:{text}"))
                }
            }
            Ok(out) if out.status.code() == Some(1) => IdentityProbe::NotFound,
            _ => IdentityProbe::Unverifiable,
        }
    }
}

/// Outcome of a verified termination attempt. Serialized to the desktop
/// frontend; contains no secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminationOutcome {
    /// The signal was NOT sent, and why. Refusal is the fail-safe default:
    /// an unverified PID is never signalled.
    Refused { reason: String },
    /// The platform definitively reports the recorded process is gone.
    AlreadyExited,
    /// The identity matched and the termination signal was accepted.
    /// On Unix this means SIGTERM was delivered — the process may still
    /// choose to ignore it; delivery is not proof of exit.
    Signalled,
    /// The identity matched but the signal could not be delivered.
    SignalFailed,
}

impl TerminationOutcome {
    /// One-line human description (CLI/audit); never contains secrets.
    pub fn describe(&self) -> String {
        match self {
            TerminationOutcome::Refused { reason } => format!("refused: {reason}"),
            TerminationOutcome::AlreadyExited => "already exited".into(),
            TerminationOutcome::Signalled => {
                if cfg!(unix) {
                    "SIGTERM sent (delivery, not proof of exit)".into()
                } else {
                    "termination requested via taskkill".into()
                }
            }
            TerminationOutcome::SignalFailed => "signal could not be delivered".into(),
        }
    }
}

/// The single shared implementation behind every process-termination entry
/// point (CLI `access kill`, CLI `access end --kill`, desktop terminate
/// command — all via the vault). Verifies the recorded identity immediately
/// before signalling and refuses whenever confidence cannot be established:
///
/// 1. `pid <= 0` → refused (PI-06: `kill 0`/negative signals process groups).
/// 2. No recorded identity → refused (a bare PID cannot be verified; PI-02).
/// 3. Probe unverifiable → refused.
/// 4. Probe not-found → `AlreadyExited` (truthful, nothing signalled).
/// 5. Identity mismatch → refused (the PID was recycled to another process).
/// 6. Match → signal; a failed delivery re-probes and reports
///    `AlreadyExited` when the process disappeared in between.
///
/// Only the recorded process itself is signalled — never its descendants or
/// its process group (documented limitation; PI-03 remains open). The
/// verify→signal window is milliseconds; without OS process handles
/// (pidfd/Job objects) it cannot be zero. This is a LOCAL control: it cannot
/// claw back injected values and never touches the provider credential.
pub fn terminate_verified(pid: i64, recorded_identity: Option<&str>) -> TerminationOutcome {
    if pid <= 0 {
        return TerminationOutcome::Refused {
            reason: format!("recorded pid {pid} is not a valid child pid"),
        };
    }
    let recorded = match recorded_identity {
        Some(r) if !r.trim().is_empty() => r,
        _ => {
            return TerminationOutcome::Refused {
                reason: "no process identity was recorded at launch; \
                         cannot confirm the pid still refers to that process"
                    .into(),
            }
        }
    };
    match probe_process_identity(pid) {
        IdentityProbe::Unverifiable => TerminationOutcome::Refused {
            reason: "current process identity could not be established".into(),
        },
        IdentityProbe::NotFound => TerminationOutcome::AlreadyExited,
        IdentityProbe::Found(current) => {
            if current != recorded {
                return TerminationOutcome::Refused {
                    reason: "process identity does not match the recorded launch \
                             identity (pid likely reused by another process)"
                        .into(),
                };
            }
            if send_termination_signal(pid) {
                TerminationOutcome::Signalled
            } else if probe_process_identity(pid) == IdentityProbe::NotFound {
                TerminationOutcome::AlreadyExited
            } else {
                TerminationOutcome::SignalFailed
            }
        }
    }
}

/// Deliver the platform termination signal to an already-verified PID.
/// Callers must have validated `pid > 0` and, for recorded sessions,
/// matched the launch identity via [`terminate_verified`].
fn send_termination_signal(pid: i64) -> bool {
    if cfg!(unix) {
        std::process::Command::new("kill")
            .arg(pid.to_string())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        // Windows has no SIGTERM. A graceful taskkill (no /F) only reaches
        // processes with a message loop — console children (the normal
        // `run` case) reject it outright, which the Windows CI run proved.
        // Try graceful first for GUI children, then terminate forcefully:
        // this command exists to be a working kill switch for an injected
        // process, and a refusal would leave the credential-bearing child
        // running.
        let graceful = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if graceful {
            return true;
        }
        std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Terminate a recorded PID (best-effort): SIGTERM on Unix; on Windows a
/// graceful taskkill first, then a forceful one (console processes cannot
/// receive the graceful form). Returns whether termination was accepted.
/// This is a LOCAL control: it cannot claw back values the process already
/// received, and it never touches the provider.
///
/// NOTE: this legacy entry point guards `pid <= 0` but performs NO identity
/// verification. Recorded-session termination must go through
/// [`terminate_verified`]; this remains only for callers that hold a PID
/// they have just obtained from a live child handle.
pub fn terminate_pid(pid: i64) -> bool {
    // Refuse non-positive PIDs before any signal is sent. On Unix `kill 0`
    // signals the CALLER's entire process group and a negative PID signals a
    // process group, so a corrupted/edited/zero recorded PID could terminate
    // API Tracker itself or an unrelated group (PI-06). A real child PID is
    // always > 0. `taskkill` on Windows likewise must never receive 0/negative.
    if pid <= 0 {
        return false;
    }
    send_termination_signal(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_env_names() {
        assert!(valid_env_name("OPENAI_API_KEY"));
        assert!(valid_env_name("_X1"));
        assert!(!valid_env_name("1BAD"));
        assert!(!valid_env_name("has-dash"));
        assert!(!valid_env_name(""));
    }

    #[test]
    fn windows_scrub_is_case_insensitive_for_the_api_tracker_prefix() {
        // RA-4: on Windows env lookups are case-insensitive, so ANY casing of
        // the API_TRACKER_ prefix is an alias the app could still read and
        // must be scrubbed — the exact three casings the brief requires.
        let ci = true;
        for name in [
            "API_TRACKER_SESSION",
            "api_tracker_session",
            "Api_Tracker_New_Password",
            "API_TRACKER_PASSWORD",
            "api_tracker_new_password",
            "aPi_TrAcKeR_backup_password",
        ] {
            assert!(
                env_name_is_scrubbed(name.as_bytes(), ci),
                "Windows scrub must remove {name}"
            );
        }
        // The child-safe allowlist is honoured case-insensitively too.
        for safe in [
            "API_TRACKER_DIR",
            "api_tracker_dir",
            "Api_Tracker_Insecure_Fast_Kdf",
        ] {
            assert!(
                !env_name_is_scrubbed(safe.as_bytes(), ci),
                "child-safe var {safe} must survive on Windows"
            );
        }
        // Unrelated variables are never scrubbed.
        assert!(!env_name_is_scrubbed(b"PATH", ci));
        assert!(!env_name_is_scrubbed(b"APITRACKER_X", ci));
    }

    #[test]
    fn unix_scrub_preserves_case_sensitive_semantics() {
        // On Unix, env names are case-sensitive and the app reads exact-case
        // names, so only the exact-case prefix is API Tracker's. A
        // differently-cased name is an unrelated variable, left untouched.
        let ci = false;
        assert!(env_name_is_scrubbed(b"API_TRACKER_SESSION", ci));
        assert!(env_name_is_scrubbed(b"API_TRACKER_NEW_PASSWORD", ci));
        // Lowercase / mixed case are DIFFERENT variables on Unix — not ours.
        assert!(!env_name_is_scrubbed(b"api_tracker_session", ci));
        assert!(!env_name_is_scrubbed(b"Api_Tracker_New_Password", ci));
        // Exact-case child-safe survives; a differently-cased "dir" is
        // unrelated and simply not prefixed-matched anyway.
        assert!(!env_name_is_scrubbed(b"API_TRACKER_DIR", ci));
    }

    #[test]
    fn terminate_pid_refuses_non_positive_pids() {
        // PI-06: 0 and negative PIDs must be refused BEFORE any signal — on
        // Unix `kill 0` would signal API Tracker's own process group. These
        // return false without ever spawning `kill`/`taskkill`. (A positive
        // PID is not exercised here: it would send a real signal.)
        assert!(!terminate_pid(0));
        assert!(!terminate_pid(-1));
        assert!(!terminate_pid(-12345));
        assert!(!terminate_pid(i64::MIN));
    }
}
