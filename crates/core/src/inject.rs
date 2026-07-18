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

pub fn list_sessions(conn: &Connection, limit: u32) -> Result<Vec<ProcessSession>> {
    let mut stmt = conn.prepare(
        "SELECT id, project_id, started_at, ended_at, command, injected_vars, exit_code
         FROM process_sessions ORDER BY started_at DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r: &Row<'_>| {
        Ok(ProcessSession {
            id: r.get(0)?,
            project_id: r.get(1)?,
            started_at: r.get(2)?,
            ended_at: r.get(3)?,
            command: r.get(4)?,
            injected_vars: r.get(5)?,
            exit_code: r.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
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
