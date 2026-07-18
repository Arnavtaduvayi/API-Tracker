//! Normalized permission/scope model.
//!
//! Raw provider scopes are preserved verbatim; a heuristic normalization sorts
//! them into read / write / admin / sensitive buckets with a human summary.
//! The normalization is best-effort and labeled with a confidence, so it never
//! overstates certainty. Permission *changes* are not performed here: no
//! initial provider supports a safe documented per-key scope change, so the
//! product surfaces the official management link instead (never pretending a
//! change happened).

use crate::clock;
use crate::error::Result;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedPermissions {
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub admin: Vec<String>,
    pub sensitive: Vec<String>,
    pub summary: String,
}

/// Heuristically classify GitHub OAuth scopes. Documented at
/// docs.github.com/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps.
pub fn normalize_github(raw: &[String]) -> NormalizedPermissions {
    let mut p = NormalizedPermissions::default();
    for scope in raw {
        let s = scope.trim();
        if s.is_empty() {
            continue;
        }
        let lower = s.to_ascii_lowercase();
        let is_admin = lower.starts_with("admin:")
            || lower == "delete_repo"
            || lower.starts_with("delete:")
            || lower == "site_admin";
        let is_write = lower == "repo"
            || lower == "workflow"
            || lower == "gist"
            || lower.starts_with("write:")
            || lower == "public_repo"
            || lower.starts_with("manage_")
            // `user` grants write to profile; `user:follow` follows/unfollows.
            || lower == "user"
            || lower == "user:follow";
        let is_read = lower.starts_with("read:")
            || lower == "user:email"
            || lower == "notifications"
            || lower == "read_org";

        if is_admin {
            p.admin.push(s.to_string());
            p.sensitive.push(s.to_string());
        } else if is_write {
            p.write.push(s.to_string());
            // `repo` (full control of private repositories) and `workflow`
            // are production-sensitive.
            if lower == "repo" || lower == "workflow" {
                p.sensitive.push(s.to_string());
            }
        } else if is_read {
            p.read.push(s.to_string());
        } else {
            // Unknown scope: surface it as write-ish to be cautious.
            p.write.push(s.to_string());
        }
    }
    p.summary = summarize(&p, raw.len());
    p
}

fn summarize(p: &NormalizedPermissions, total: usize) -> String {
    if total == 0 {
        return "no scopes are readable for this credential".to_string();
    }
    let mut parts = Vec::new();
    if !p.admin.is_empty() {
        parts.push(format!("{} administrative", p.admin.len()));
    }
    if !p.write.is_empty() {
        parts.push(format!("{} write", p.write.len()));
    }
    if !p.read.is_empty() {
        parts.push(format!("{} read", p.read.len()));
    }
    let mut summary = format!("{total} scope(s): {}", parts.join(", "));
    if !p.sensitive.is_empty() {
        summary.push_str(&format!("; {} production-sensitive", p.sensitive.len()));
    }
    summary
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredPermissions {
    pub credential_id: String,
    pub raw_scopes: Vec<String>,
    pub normalized: NormalizedPermissions,
    pub source: String,
    pub precision: String,
    pub confidence: String,
    pub synced_at: String,
}

pub fn store(
    conn: &Connection,
    credential_id: &str,
    raw_scopes: &[String],
    normalized: &NormalizedPermissions,
    source: &str,
    precision: &str,
    confidence: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO credential_permissions
         (credential_id, raw_scopes, normalized, source, precision, confidence, synced_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(credential_id) DO UPDATE SET
           raw_scopes = excluded.raw_scopes, normalized = excluded.normalized,
           source = excluded.source, precision = excluded.precision,
           confidence = excluded.confidence, synced_at = excluded.synced_at",
        params![
            credential_id,
            serde_json::to_string(raw_scopes)?,
            serde_json::to_string(normalized)?,
            source,
            precision,
            confidence,
            clock::now_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn load(conn: &Connection, credential_id: &str) -> Result<Option<StoredPermissions>> {
    let row = conn
        .query_row(
            "SELECT raw_scopes, normalized, source, precision, confidence, synced_at
             FROM credential_permissions WHERE credential_id = ?1",
            [credential_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((raw, norm, source, precision, confidence, synced_at)) = row else {
        return Ok(None);
    };
    Ok(Some(StoredPermissions {
        credential_id: credential_id.to_string(),
        raw_scopes: serde_json::from_str(&raw)?,
        normalized: serde_json::from_str(&norm)?,
        source,
        precision,
        confidence,
        synced_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_github_scopes() {
        let raw = vec![
            "repo".to_string(),
            "read:org".to_string(),
            "admin:org".to_string(),
            "workflow".to_string(),
            "gist".to_string(),
        ];
        let n = normalize_github(&raw);
        assert!(n.admin.contains(&"admin:org".to_string()));
        assert!(n.sensitive.contains(&"admin:org".to_string()));
        assert!(n.write.contains(&"repo".to_string()));
        assert!(n.sensitive.contains(&"repo".to_string()));
        assert!(n.read.contains(&"read:org".to_string()));
        assert!(n.summary.contains("production-sensitive"));
    }

    #[test]
    fn empty_scopes_summary_is_honest() {
        let n = normalize_github(&[]);
        assert!(n.summary.contains("no scopes are readable"));
    }
}
