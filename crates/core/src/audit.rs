//! Local audit trail for sensitive actions.
//!
//! Events record what happened and to which record, never secret values.
//! The table is local-only, like everything else in the vault.

use crate::clock;
use crate::error::Result;
use rusqlite::{params, Connection};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: i64,
    pub at: String,
    pub event: String,
    pub project_id: Option<String>,
    pub credential_id: Option<String>,
    pub detail: String,
}

/// Append an audit event. `detail` must contain only identifiers and names,
/// never secret material.
pub fn record(
    conn: &Connection,
    event: &str,
    project_id: Option<&str>,
    credential_id: Option<&str>,
    detail: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_events (at, event, project_id, credential_id, detail)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            clock::now_rfc3339(),
            event,
            project_id,
            credential_id,
            detail
        ],
    )?;
    Ok(())
}

pub fn list(conn: &Connection, limit: u32) -> Result<Vec<AuditEvent>> {
    let mut stmt = conn.prepare(
        "SELECT id, at, event, project_id, credential_id, detail
         FROM audit_events ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |row| {
        Ok(AuditEvent {
            id: row.get(0)?,
            at: row.get(1)?,
            event: row.get(2)?,
            project_id: row.get(3)?,
            credential_id: row.get(4)?,
            detail: row.get(5)?,
        })
    })?;
    let mut events = Vec::new();
    for event in rows {
        events.push(event?);
    }
    Ok(events)
}
