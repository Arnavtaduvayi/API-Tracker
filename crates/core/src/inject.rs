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
/// the grant that authorized the launch.
pub fn set_session_pid(
    conn: &Connection,
    session_id: &str,
    pid: u32,
    grant_id: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE process_sessions SET pid = ?1, grant_id = ?2 WHERE id = ?3",
        params![i64::from(pid), grant_id, session_id],
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
            // Only a clean "ps ran and found nothing" closes the row; a
            // failure to run ps proves nothing and changes nothing.
            let gone = matches!(probe, Ok(status) if !status.success());
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
                pid, grant_id
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

/// Send SIGTERM to a recorded PID (best-effort, Unix only). Returns whether
/// the signal was accepted. This is a LOCAL control: it cannot claw back
/// values the process already received, and it never touches the provider.
pub fn terminate_pid(pid: i64) -> bool {
    if cfg!(unix) {
        std::process::Command::new("kill")
            .arg(pid.to_string())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        // Windows has no SIGTERM; taskkill without /F requests a graceful
        // close, matching the Unix semantics as closely as the OS allows.
        std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
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
}
