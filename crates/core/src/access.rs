//! Temporary LOCAL access grants for secure process injection.
//!
//! A grant bounds what `api-tracker run` will inject: which credentials,
//! until when, how many launches, and (optionally) how long each launched
//! process may live. These are **local controls enforced by Tethra on
//! this machine** — they never constrain the provider-side credential, and
//! nothing here claims otherwise. Local expiry is not provider revocation.

use crate::error::{CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct AccessGrant {
    pub id: String,
    pub project_id: String,
    pub label: String,
    /// Credential ids the grant is limited to; empty = the project's
    /// configured mappings.
    pub credential_ids: Vec<String>,
    pub expires_at: String,
    /// 0 = unlimited launches within the window.
    pub max_launches: i64,
    pub launches_used: i64,
    pub max_duration_secs: Option<i64>,
    pub budget_warn_micros: Option<i64>,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

impl AccessGrant {
    pub fn status(&self, now: &str) -> &'static str {
        if self.revoked_at.is_some() {
            "revoked"
        } else if self.expires_at.as_str() <= now {
            "expired"
        } else if self.max_launches > 0 && self.launches_used >= self.max_launches {
            "used_up"
        } else {
            "active"
        }
    }
}

const COLUMNS: &str = "id, project_id, label, credential_ids, expires_at, max_launches, \
     launches_used, max_duration_secs, budget_warn_micros, created_at, revoked_at";

fn from_row(r: &Row<'_>) -> rusqlite::Result<AccessGrant> {
    let ids: String = r.get(3)?;
    Ok(AccessGrant {
        id: r.get(0)?,
        project_id: r.get(1)?,
        label: r.get(2)?,
        credential_ids: if ids.is_empty() {
            Vec::new()
        } else {
            ids.split(',').map(str::to_string).collect()
        },
        expires_at: r.get(4)?,
        max_launches: r.get(5)?,
        launches_used: r.get(6)?,
        max_duration_secs: r.get(7)?,
        budget_warn_micros: r.get(8)?,
        created_at: r.get(9)?,
        revoked_at: r.get(10)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn insert(
    conn: &Connection,
    project_id: &str,
    label: &str,
    credential_ids: &[String],
    ttl_minutes: u64,
    max_launches: i64,
    max_duration_secs: Option<i64>,
    budget_warn_micros: Option<i64>,
) -> Result<String> {
    if ttl_minutes == 0 || ttl_minutes > 60 * 24 * 30 {
        return Err(CoreError::InvalidInput(
            "the grant lifetime must be between 1 minute and 30 days".into(),
        ));
    }
    if max_launches < 0 {
        return Err(CoreError::InvalidInput(
            "max launches must be 0 (unlimited) or positive".into(),
        ));
    }
    if let Some(secs) = max_duration_secs {
        if secs <= 0 {
            return Err(CoreError::InvalidInput(
                "the per-process duration must be positive".into(),
            ));
        }
    }
    let id = Uuid::new_v4().to_string();
    let expires = crate::clock::rfc3339_after(std::time::Duration::from_secs(ttl_minutes * 60));
    conn.execute(
        "INSERT INTO access_grants
             (id, project_id, label, credential_ids, expires_at, max_launches,
              max_duration_secs, budget_warn_micros, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id,
            project_id,
            label,
            credential_ids.join(","),
            expires,
            max_launches,
            max_duration_secs,
            budget_warn_micros,
            crate::clock::now_rfc3339(),
        ],
    )?;
    Ok(id)
}

pub fn get(conn: &Connection, id: &str) -> Result<AccessGrant> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM access_grants WHERE id = ?1"),
        [id],
        from_row,
    )
    .optional()?
    .ok_or_else(|| CoreError::NotFound {
        kind: "access grant",
        ident: id.to_string(),
    })
}

pub fn list(conn: &Connection, include_inactive: bool) -> Result<Vec<AccessGrant>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM access_grants ORDER BY created_at DESC"
    ))?;
    let rows = stmt.query_map([], from_row)?;
    let now = crate::clock::now_rfc3339();
    let mut out = Vec::new();
    for r in rows {
        let grant = r?;
        if include_inactive || grant.status(&now) == "active" {
            out.push(grant);
        }
    }
    Ok(out)
}

pub fn revoke(conn: &Connection, id: &str) -> Result<AccessGrant> {
    let grant = get(conn, id)?;
    if grant.revoked_at.is_none() {
        conn.execute(
            "UPDATE access_grants SET revoked_at = ?1 WHERE id = ?2",
            params![crate::clock::now_rfc3339(), id],
        )?;
    }
    get(conn, id)
}

/// Atomically consume one launch from an active grant. The UPDATE's WHERE
/// clause re-checks every condition, so two concurrent `run` invocations
/// cannot both consume the last launch of a one-time grant.
pub fn consume_launch(conn: &Connection, id: &str) -> Result<AccessGrant> {
    let now = crate::clock::now_rfc3339();
    let n = conn.execute(
        "UPDATE access_grants SET launches_used = launches_used + 1
         WHERE id = ?1 AND revoked_at IS NULL AND expires_at > ?2
           AND (max_launches = 0 OR launches_used < max_launches)",
        params![id, now],
    )?;
    if n == 0 {
        let grant = get(conn, id)?;
        return Err(CoreError::InvalidInput(format!(
            "access grant {id} is {} — it cannot authorize another launch",
            grant.status(&now)
        )));
    }
    get(conn, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let mut c = Connection::open_in_memory().unwrap();
        crate::db::migrate(&mut c).unwrap();
        c.execute(
            "INSERT INTO projects (id, name, created_at, updated_at, wrapped_project_key, key_wrap_mode)
             VALUES ('p1', 'test', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', x'00', 'vault')",
            [],
        )
        .unwrap();
        c
    }

    #[test]
    fn one_time_grants_cannot_be_consumed_twice() {
        let c = conn();
        let id = insert(&c, "p1", "one shot", &[], 60, 1, None, None).unwrap();
        assert_eq!(consume_launch(&c, &id).unwrap().launches_used, 1);
        let err = consume_launch(&c, &id).unwrap_err();
        assert!(err.to_string().contains("used_up"), "{err}");
    }

    #[test]
    fn revoked_and_expired_grants_refuse_launches() {
        let c = conn();
        let id = insert(&c, "p1", "revocable", &[], 60, 0, None, None).unwrap();
        revoke(&c, &id).unwrap();
        assert!(consume_launch(&c, &id).is_err());
        // Simulate expiry by rewriting the timestamp.
        let id2 = insert(&c, "p1", "expiring", &[], 60, 0, None, None).unwrap();
        c.execute(
            "UPDATE access_grants SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
            [&id2],
        )
        .unwrap();
        let err = consume_launch(&c, &id2).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn grant_lifetime_and_duration_are_validated() {
        let c = conn();
        assert!(insert(&c, "p1", "", &[], 0, 0, None, None).is_err());
        assert!(insert(&c, "p1", "", &[], 60 * 24 * 31, 0, None, None).is_err());
        assert!(insert(&c, "p1", "", &[], 60, -1, None, None).is_err());
        assert!(insert(&c, "p1", "", &[], 60, 0, Some(0), None).is_err());
    }
}
