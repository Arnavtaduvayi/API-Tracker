//! Durable credential-rotation workflows: types, storage, and the state
//! model. Orchestration (provider calls, destination sync, verification)
//! lives in `vault.rs`; this module owns what must survive a restart.
//!
//! Rotation is NOT "change the value in a secret manager". A rotation is:
//! capability check → dry-run plan → reauthenticated approval → replacement
//! created (provider API or guided manual) → destinations updated and
//! verified → new value validated → grace/overlap period (with continued-use
//! detection where provider data exists) → previous credential disabled
//! where supported → revoked only after verification → completed. Every
//! transition is recorded; nothing here ever stores a secret value — only
//! version numbers, provider-side ids, and state.

use crate::error::{CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use uuid::Uuid;

// States. A rotation only ever moves forward through these, or into
// failed / rolling_back / rolled_back / manual_required.
pub const PLANNED: &str = "planned";
pub const APPROVED: &str = "approved";
pub const AWAITING_MANUAL_KEY: &str = "awaiting_manual_key";
pub const REPLACEMENT_STORED: &str = "replacement_stored";
pub const UPDATING_DESTINATIONS: &str = "updating_destinations";
pub const DESTINATIONS_VERIFIED: &str = "destinations_verified";
pub const GRACE_PERIOD: &str = "grace_period";
pub const OLD_DISABLED: &str = "old_disabled";
pub const COMPLETED: &str = "completed";
pub const FAILED: &str = "failed";
pub const ROLLING_BACK: &str = "rolling_back";
pub const ROLLED_BACK: &str = "rolled_back";
pub const MANUAL_REQUIRED: &str = "manual_required";

/// How the replacement value is obtained.
pub const MODE_API: &str = "api_create";
pub const MODE_MANUAL: &str = "manual_create";

/// States in which `advance` can still make progress by itself.
pub fn is_active(state: &str) -> bool {
    matches!(
        state,
        APPROVED
            | AWAITING_MANUAL_KEY
            | REPLACEMENT_STORED
            | UPDATING_DESTINATIONS
            | DESTINATIONS_VERIFIED
            | GRACE_PERIOD
            | OLD_DISABLED
    )
}

pub fn is_terminal(state: &str) -> bool {
    matches!(state, COMPLETED | ROLLED_BACK)
}

#[derive(Debug, Clone, Serialize)]
pub struct Rotation {
    pub id: String,
    pub credential_id: String,
    pub provider: String,
    pub state: String,
    pub mode: String,
    pub note: String,
    pub created_at: String,
    pub updated_at: String,
    pub approved_at: Option<String>,
    pub old_version: Option<i64>,
    pub new_version: Option<i64>,
    pub sync_plan_id: Option<String>,
    pub grace_minutes: i64,
    pub grace_ends_at: Option<String>,
    pub old_provider_key_id: Option<String>,
    pub new_provider_key_id: Option<String>,
    pub provider_project_id: Option<String>,
    pub new_value_validated: bool,
    pub old_disabled_at: Option<String>,
    pub old_revoked_at: Option<String>,
    pub last_error: String,
    pub manual_instructions: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotationEvent {
    pub at: String,
    pub from_state: String,
    pub to_state: String,
    pub detail: String,
}

const COLUMNS: &str = "id, credential_id, provider, state, mode, note, created_at, updated_at, \
     approved_at, old_version, new_version, sync_plan_id, grace_minutes, grace_ends_at, \
     old_provider_key_id, new_provider_key_id, provider_project_id, new_value_validated, \
     old_disabled_at, old_revoked_at, last_error, manual_instructions";

fn from_row(r: &Row<'_>) -> rusqlite::Result<Rotation> {
    Ok(Rotation {
        id: r.get(0)?,
        credential_id: r.get(1)?,
        provider: r.get(2)?,
        state: r.get(3)?,
        mode: r.get(4)?,
        note: r.get(5)?,
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
        approved_at: r.get(8)?,
        old_version: r.get(9)?,
        new_version: r.get(10)?,
        sync_plan_id: r.get(11)?,
        grace_minutes: r.get(12)?,
        grace_ends_at: r.get(13)?,
        old_provider_key_id: r.get(14)?,
        new_provider_key_id: r.get(15)?,
        provider_project_id: r.get(16)?,
        new_value_validated: r.get::<_, i64>(17)? != 0,
        old_disabled_at: r.get(18)?,
        old_revoked_at: r.get(19)?,
        last_error: r.get(20)?,
        manual_instructions: r.get(21)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn insert(
    conn: &Connection,
    credential_id: &str,
    provider: &str,
    mode: &str,
    note: &str,
    grace_minutes: i64,
    old_provider_key_id: Option<&str>,
    provider_project_id: Option<&str>,
    manual_instructions: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = crate::clock::now_rfc3339();
    conn.execute(
        "INSERT INTO rotations (id, credential_id, provider, state, mode, note, created_at,
             updated_at, grace_minutes, old_provider_key_id, provider_project_id,
             manual_instructions)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9, ?10, ?11)",
        params![
            id,
            credential_id,
            provider,
            PLANNED,
            mode,
            note,
            now,
            grace_minutes,
            old_provider_key_id,
            provider_project_id,
            manual_instructions,
        ],
    )?;
    record_event(conn, &id, "", PLANNED, "rotation planned (dry run)")?;
    Ok(id)
}

pub fn load(conn: &Connection, id: &str) -> Result<Rotation> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM rotations WHERE id = ?1"),
        [id],
        from_row,
    )
    .optional()?
    .ok_or_else(|| CoreError::NotFound {
        kind: "rotation",
        ident: id.to_string(),
    })
}

pub fn list(conn: &Connection, credential_id: Option<&str>, limit: u32) -> Result<Vec<Rotation>> {
    let mut out = Vec::new();
    match credential_id {
        Some(cred) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {COLUMNS} FROM rotations WHERE credential_id = ?1
                 ORDER BY created_at DESC LIMIT ?2"
            ))?;
            let rows = stmt.query_map(params![cred, limit], from_row)?;
            for r in rows {
                out.push(r?);
            }
        }
        None => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {COLUMNS} FROM rotations ORDER BY created_at DESC LIMIT ?1"
            ))?;
            let rows = stmt.query_map([limit], from_row)?;
            for r in rows {
                out.push(r?);
            }
        }
    }
    Ok(out)
}

/// Rotations that can still make progress (for restart recovery listings).
pub fn active(conn: &Connection) -> Result<Vec<Rotation>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM rotations
         WHERE state NOT IN (?1, ?2, ?3, ?4)
         ORDER BY created_at DESC"
    ))?;
    let rows = stmt.query_map(params![COMPLETED, ROLLED_BACK, FAILED, PLANNED], from_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Transition to a new state, recording the event. The `detail` must never
/// contain secret material.
pub fn set_state(conn: &Connection, id: &str, to_state: &str, detail: &str) -> Result<()> {
    let current = load(conn, id)?;
    conn.execute(
        "UPDATE rotations SET state = ?1, updated_at = ?2, last_error = '' WHERE id = ?3",
        params![to_state, crate::clock::now_rfc3339(), id],
    )?;
    record_event(conn, id, &current.state, to_state, detail)
}

/// Record a step failure WITHOUT changing state (the step stays retryable).
pub fn record_error(conn: &Connection, id: &str, error: &str) -> Result<()> {
    let current = load(conn, id)?;
    conn.execute(
        "UPDATE rotations SET last_error = ?1, updated_at = ?2 WHERE id = ?3",
        params![error, crate::clock::now_rfc3339(), id],
    )?;
    record_event(
        conn,
        id,
        &current.state,
        &current.state,
        &format!("step failed (retryable): {error}"),
    )
}

pub fn set_field(conn: &Connection, id: &str, field: &str, value: Option<&str>) -> Result<()> {
    // Guard against arbitrary SQL: only known columns may be set this way.
    const ALLOWED: [&str; 8] = [
        "approved_at",
        "sync_plan_id",
        "grace_ends_at",
        "old_provider_key_id",
        "new_provider_key_id",
        "provider_project_id",
        "old_disabled_at",
        "old_revoked_at",
    ];
    if !ALLOWED.contains(&field) {
        return Err(CoreError::InvalidInput(format!(
            "'{field}' is not a settable rotation field"
        )));
    }
    conn.execute(
        &format!("UPDATE rotations SET {field} = ?1, updated_at = ?2 WHERE id = ?3"),
        params![value, crate::clock::now_rfc3339(), id],
    )?;
    Ok(())
}

pub fn set_versions(conn: &Connection, id: &str, old: Option<i64>, new: i64) -> Result<()> {
    conn.execute(
        "UPDATE rotations SET old_version = ?1, new_version = ?2, updated_at = ?3 WHERE id = ?4",
        params![old, new, crate::clock::now_rfc3339(), id],
    )?;
    Ok(())
}

pub fn mark_new_value_validated(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE rotations SET new_value_validated = 1, updated_at = ?1 WHERE id = ?2",
        params![crate::clock::now_rfc3339(), id],
    )?;
    Ok(())
}

fn record_event(
    conn: &Connection,
    rotation_id: &str,
    from_state: &str,
    to_state: &str,
    detail: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO rotation_events (rotation_id, at, from_state, to_state, detail)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            rotation_id,
            crate::clock::now_rfc3339(),
            from_state,
            to_state,
            detail,
        ],
    )?;
    Ok(())
}

pub fn events(conn: &Connection, rotation_id: &str) -> Result<Vec<RotationEvent>> {
    let mut stmt = conn.prepare(
        "SELECT at, from_state, to_state, detail FROM rotation_events
         WHERE rotation_id = ?1 ORDER BY id",
    )?;
    let rows = stmt.query_map([rotation_id], |r| {
        Ok(RotationEvent {
            at: r.get(0)?,
            from_state: r.get(1)?,
            to_state: r.get(2)?,
            detail: r.get(3)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Scheduled rotation (intent + due dates; execution is never automatic)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct RotationSchedule {
    pub credential_id: String,
    pub interval_days: i64,
    pub next_due_at: String,
    pub enabled: bool,
    pub paused_reason: String,
    pub created_at: String,
    pub last_completed_rotation_id: Option<String>,
}

pub fn schedule_set(conn: &Connection, credential_id: &str, interval_days: i64) -> Result<()> {
    if !(1..=3650).contains(&interval_days) {
        return Err(CoreError::InvalidInput(
            "the rotation interval must be between 1 day and 10 years".into(),
        ));
    }
    let next = crate::clock::rfc3339_after(std::time::Duration::from_secs(
        (interval_days as u64) * 24 * 3600,
    ));
    conn.execute(
        "INSERT INTO rotation_schedules (credential_id, interval_days, next_due_at, enabled, created_at)
         VALUES (?1, ?2, ?3, 1, ?4)
         ON CONFLICT (credential_id) DO UPDATE SET
             interval_days = excluded.interval_days,
             next_due_at = excluded.next_due_at,
             enabled = 1,
             paused_reason = ''",
        params![credential_id, interval_days, next, crate::clock::now_rfc3339()],
    )?;
    Ok(())
}

pub fn schedule_remove(conn: &Connection, credential_id: &str) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM rotation_schedules WHERE credential_id = ?1",
        [credential_id],
    )?;
    Ok(n > 0)
}

pub fn schedule_pause(conn: &Connection, credential_id: &str, reason: &str) -> Result<()> {
    conn.execute(
        "UPDATE rotation_schedules SET enabled = 0, paused_reason = ?1 WHERE credential_id = ?2",
        params![reason, credential_id],
    )?;
    Ok(())
}

/// After a completed rotation: advance the schedule and clear any pause.
pub fn schedule_mark_completed(
    conn: &Connection,
    credential_id: &str,
    rotation_id: &str,
) -> Result<()> {
    let interval: Option<i64> = conn
        .query_row(
            "SELECT interval_days FROM rotation_schedules WHERE credential_id = ?1",
            [credential_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(days) = interval {
        let next =
            crate::clock::rfc3339_after(std::time::Duration::from_secs((days as u64) * 24 * 3600));
        conn.execute(
            "UPDATE rotation_schedules SET next_due_at = ?1, enabled = 1, paused_reason = '',
                 last_completed_rotation_id = ?2
             WHERE credential_id = ?3",
            params![next, rotation_id, credential_id],
        )?;
    }
    Ok(())
}

pub fn schedules(conn: &Connection) -> Result<Vec<RotationSchedule>> {
    let mut stmt = conn.prepare(
        "SELECT credential_id, interval_days, next_due_at, enabled, paused_reason, created_at,
                last_completed_rotation_id
         FROM rotation_schedules ORDER BY next_due_at",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(RotationSchedule {
            credential_id: r.get(0)?,
            interval_days: r.get(1)?,
            next_due_at: r.get(2)?,
            enabled: r.get::<_, i64>(3)? != 0,
            paused_reason: r.get(4)?,
            created_at: r.get(5)?,
            last_completed_rotation_id: r.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}
