//! Synchronization plans: reviewable, per-destination rollouts of a
//! credential value change.
//!
//! A plan is generated (dry run by default), shown to the user, and only
//! executed after explicit approval plus master-password reauthentication.
//! Plans store version NUMBERS, masked values, and destination names — never
//! plaintext. Execution, verification, retry, and rollback orchestration
//! live in `vault.rs`; this module owns the types and storage.

use crate::error::{CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use uuid::Uuid;

/// What a step will do (or did).
pub const ACTION_WRITE: &str = "write";
pub const ACTION_REEXPORT: &str = "reexport";
pub const ACTION_NONE: &str = "none";
pub const ACTION_MANUAL: &str = "manual";

/// Step lifecycle states.
pub const STEP_PLANNED: &str = "planned";
pub const STEP_EXECUTED: &str = "executed";
pub const STEP_FAILED: &str = "failed";
pub const STEP_SKIPPED: &str = "skipped";
pub const STEP_ROLLED_BACK: &str = "rolled_back";

/// Plan lifecycle states.
pub const PLAN_PLANNED: &str = "planned";
pub const PLAN_EXECUTED: &str = "executed";
pub const PLAN_PARTIAL: &str = "partially_failed";
pub const PLAN_ROLLED_BACK: &str = "rolled_back";
pub const PLAN_STALE: &str = "stale";

#[derive(Debug, Clone, Serialize)]
pub struct SyncStep {
    pub destination_id: String,
    pub destination_name: String,
    pub destination_kind: String,
    pub secret_name: String,
    pub environment: String,
    pub action: String,
    pub status: String,
    pub detail: String,
    /// How the step's outcome is (or would be) verified.
    pub validation: String,
    pub rollback_available: bool,
    pub executed_at: Option<String>,
    pub verified_at: Option<String>,
    pub rolled_back_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncPlan {
    pub id: String,
    pub credential_id: String,
    pub credential_name: String,
    pub project_name: String,
    /// The retained version a rollback would restore (None = no history).
    pub from_version: Option<i64>,
    pub from_masked: Option<String>,
    /// The current vault version this plan deploys.
    pub to_version: i64,
    pub to_masked: String,
    pub created_at: String,
    pub status: String,
    pub note: String,
    /// Projects that reference this credential (directly or via references).
    pub affected_projects: Vec<String>,
    /// Steps the user must perform by hand (unimplemented destinations …).
    pub manual_steps: Vec<String>,
    pub steps: Vec<SyncStep>,
}

pub fn insert_plan(
    conn: &Connection,
    credential_id: &str,
    from_version: Option<i64>,
    to_version: i64,
    note: &str,
    steps: &[SyncStep],
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = crate::clock::now_rfc3339();
    conn.execute(
        "INSERT INTO sync_plans (id, credential_id, from_version, to_version, created_at, status, note)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, credential_id, from_version, to_version, now, PLAN_PLANNED, note],
    )?;
    for step in steps {
        conn.execute(
            "INSERT INTO sync_plan_steps
                 (plan_id, destination_id, secret_name, environment, action, status, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                step.destination_id,
                step.secret_name,
                step.environment,
                step.action,
                step.status,
                step.detail,
            ],
        )?;
    }
    Ok(id)
}

/// Row-level data; display fields (names, validation) are recomputed by the
/// vault when loading, so renames stay correct.
#[derive(Debug, Clone)]
pub struct StoredStep {
    pub destination_id: String,
    pub secret_name: String,
    pub environment: String,
    pub action: String,
    pub status: String,
    pub detail: String,
    pub executed_at: Option<String>,
    pub verified_at: Option<String>,
    pub rolled_back_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredPlan {
    pub id: String,
    pub credential_id: String,
    pub from_version: Option<i64>,
    pub to_version: i64,
    pub created_at: String,
    pub status: String,
    pub note: String,
    pub steps: Vec<StoredStep>,
}

fn stored_plan_from_row(r: &Row<'_>) -> rusqlite::Result<StoredPlan> {
    Ok(StoredPlan {
        id: r.get(0)?,
        credential_id: r.get(1)?,
        from_version: r.get(2)?,
        to_version: r.get(3)?,
        created_at: r.get(4)?,
        status: r.get(5)?,
        note: r.get(6)?,
        steps: Vec::new(),
    })
}

pub fn load_plan(conn: &Connection, plan_id: &str) -> Result<StoredPlan> {
    let mut plan = conn
        .query_row(
            "SELECT id, credential_id, from_version, to_version, created_at, status, note
             FROM sync_plans WHERE id = ?1",
            [plan_id],
            stored_plan_from_row,
        )
        .optional()?
        .ok_or_else(|| CoreError::NotFound {
            kind: "sync plan",
            ident: plan_id.to_string(),
        })?;
    let mut stmt = conn.prepare(
        "SELECT destination_id, secret_name, environment, action, status, detail,
                executed_at, verified_at, rolled_back_at
         FROM sync_plan_steps WHERE plan_id = ?1 ORDER BY destination_id, secret_name",
    )?;
    let rows = stmt.query_map([plan_id], |r| {
        Ok(StoredStep {
            destination_id: r.get(0)?,
            secret_name: r.get(1)?,
            environment: r.get(2)?,
            action: r.get(3)?,
            status: r.get(4)?,
            detail: r.get(5)?,
            executed_at: r.get(6)?,
            verified_at: r.get(7)?,
            rolled_back_at: r.get(8)?,
        })
    })?;
    for r in rows {
        plan.steps.push(r?);
    }
    Ok(plan)
}

pub fn list_plans(
    conn: &Connection,
    credential_id: Option<&str>,
    limit: u32,
) -> Result<Vec<StoredPlan>> {
    let mut out = Vec::new();
    let mut collect =
        |stmt: &mut rusqlite::Statement<'_>, params: &[&dyn rusqlite::ToSql]| -> Result<()> {
            let rows = stmt.query_map(params, stored_plan_from_row)?;
            for r in rows {
                out.push(r?);
            }
            Ok(())
        };
    match credential_id {
        Some(cred) => {
            let mut stmt = conn.prepare(
                "SELECT id, credential_id, from_version, to_version, created_at, status, note
                 FROM sync_plans WHERE credential_id = ?1 ORDER BY created_at DESC LIMIT ?2",
            )?;
            collect(&mut stmt, &[&cred, &limit])?;
        }
        None => {
            let mut stmt = conn.prepare(
                "SELECT id, credential_id, from_version, to_version, created_at, status, note
                 FROM sync_plans ORDER BY created_at DESC LIMIT ?1",
            )?;
            collect(&mut stmt, &[&limit])?;
        }
    }
    Ok(out)
}

pub fn update_step(
    conn: &Connection,
    plan_id: &str,
    destination_id: &str,
    secret_name: &str,
    status: &str,
    detail: &str,
) -> Result<()> {
    let now = crate::clock::now_rfc3339();
    let (executed, verified, rolled_back): (Option<String>, Option<String>, Option<String>) =
        match status {
            STEP_EXECUTED => (Some(now.clone()), None, None),
            STEP_ROLLED_BACK => (None, None, Some(now.clone())),
            _ => (None, None, None),
        };
    conn.execute(
        "UPDATE sync_plan_steps SET status = ?1, detail = ?2,
             executed_at = COALESCE(?3, executed_at),
             verified_at = COALESCE(?4, verified_at),
             rolled_back_at = COALESCE(?5, rolled_back_at)
         WHERE plan_id = ?6 AND destination_id = ?7 AND secret_name = ?8",
        params![
            status,
            detail,
            executed,
            verified,
            rolled_back,
            plan_id,
            destination_id,
            secret_name
        ],
    )?;
    Ok(())
}

pub fn mark_step_verified(
    conn: &Connection,
    plan_id: &str,
    destination_id: &str,
    secret_name: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE sync_plan_steps SET verified_at = ?1
         WHERE plan_id = ?2 AND destination_id = ?3 AND secret_name = ?4",
        params![
            crate::clock::now_rfc3339(),
            plan_id,
            destination_id,
            secret_name
        ],
    )?;
    Ok(())
}

pub fn update_plan_status(conn: &Connection, plan_id: &str, status: &str) -> Result<()> {
    conn.execute(
        "UPDATE sync_plans SET status = ?1 WHERE id = ?2",
        params![status, plan_id],
    )?;
    Ok(())
}
