//! User-configured notification channels (webhooks).
//!
//! Optional remote delivery for alerts the user explicitly configures — no
//! API-Tracker-hosted service is involved and none is ever required.
//! Payloads carry alert METADATA only (kind, severity, title, detail,
//! timestamps); alerts are secret-free by construction, and nothing else is
//! included. The webhook URL may embed a user-chosen token, so it is stored
//! encrypted under the vault key and masked everywhere.

use crate::error::{CoreError, Result};
use crate::http::{HttpClient, HttpRequest, Method};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct NotificationChannel {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub url_masked: String,
    /// Minimum severity delivered: info | low | medium | high | critical.
    pub min_severity: String,
    pub enabled: bool,
    pub created_at: String,
    pub last_delivery_at: Option<String>,
    pub last_error: String,
}

const COLUMNS: &str = "id, name, kind, url_masked, min_severity, enabled, created_at, \
     last_delivery_at, last_error";

fn from_row(r: &Row<'_>) -> rusqlite::Result<NotificationChannel> {
    Ok(NotificationChannel {
        id: r.get(0)?,
        name: r.get(1)?,
        kind: r.get(2)?,
        url_masked: r.get(3)?,
        min_severity: r.get(4)?,
        enabled: r.get::<_, i64>(5)? != 0,
        created_at: r.get(6)?,
        last_delivery_at: r.get(7)?,
        last_error: r.get(8)?,
    })
}

pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

pub fn insert(
    conn: &Connection,
    name: &str,
    url_ciphertext: &[u8],
    url_masked: &str,
    min_severity: &str,
) -> Result<String> {
    if severity_rank(min_severity) == 0 && min_severity != "info" {
        return Err(CoreError::InvalidInput(format!(
            "'{min_severity}' is not a severity (info/low/medium/high/critical)"
        )));
    }
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO notification_channels
             (id, name, kind, url_ciphertext, url_masked, min_severity, created_at)
         VALUES (?1, ?2, 'webhook', ?3, ?4, ?5, ?6)",
        params![
            id,
            name,
            url_ciphertext,
            url_masked,
            min_severity,
            crate::clock::now_rfc3339()
        ],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            CoreError::AlreadyExists {
                kind: "notification channel",
                ident: name.to_string(),
            }
        }
        other => other.into(),
    })?;
    Ok(id)
}

pub fn list(conn: &Connection) -> Result<Vec<NotificationChannel>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM notification_channels ORDER BY name"
    ))?;
    let rows = stmt.query_map([], from_row)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn get(conn: &Connection, ident: &str) -> Result<NotificationChannel> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM notification_channels WHERE id = ?1 OR name = ?1 COLLATE NOCASE"
    ))?;
    stmt.query_row([ident], from_row)
        .optional()?
        .ok_or_else(|| CoreError::NotFound {
            kind: "notification channel",
            ident: ident.to_string(),
        })
}

pub fn url_ciphertext(conn: &Connection, id: &str) -> Result<Vec<u8>> {
    Ok(conn.query_row(
        "SELECT url_ciphertext FROM notification_channels WHERE id = ?1",
        [id],
        |r| r.get(0),
    )?)
}

pub fn remove(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM notification_channels WHERE id = ?1", [id])?;
    Ok(())
}

pub fn set_enabled(conn: &Connection, id: &str, enabled: bool) -> Result<()> {
    conn.execute(
        "UPDATE notification_channels SET enabled = ?1 WHERE id = ?2",
        params![i64::from(enabled), id],
    )?;
    Ok(())
}

pub fn record_delivery(conn: &Connection, id: &str, error: Option<&str>) -> Result<()> {
    match error {
        None => conn.execute(
            "UPDATE notification_channels SET last_delivery_at = ?1, last_error = '' WHERE id = ?2",
            params![crate::clock::now_rfc3339(), id],
        )?,
        Some(e) => conn.execute(
            "UPDATE notification_channels SET last_error = ?1 WHERE id = ?2",
            params![e, id],
        )?,
    };
    Ok(())
}

/// The payload delivered to a webhook: alert metadata only. Alerts never
/// contain secret values, and nothing beyond the alert is included.
#[derive(Debug, Clone, Serialize)]
pub struct NotificationPayload<'a> {
    pub source: &'static str,
    pub kind: &'a str,
    pub severity: &'a str,
    pub title: &'a str,
    pub detail: &'a str,
    pub recommended_action: &'a str,
    pub observed_at: &'a str,
}

/// POST one alert to a webhook URL. Returns a short delivery note.
pub fn deliver_webhook(
    http: &dyn HttpClient,
    url: &str,
    payload: &NotificationPayload<'_>,
) -> Result<String> {
    if !url.starts_with("https://") && !url.starts_with("http://localhost") {
        return Err(CoreError::InvalidInput(
            "webhook URLs must be https (or http://localhost for testing)".into(),
        ));
    }
    let body = serde_json::to_vec(payload)?;
    let req = HttpRequest::with_method(Method::Post, url)
        .header("content-type", "application/json")
        .body(body);
    let resp = http.send(&req)?;
    if !resp.is_success() {
        return Err(CoreError::Provider(format!(
            "the webhook returned status {}",
            resp.status
        )));
    }
    Ok(format!("delivered (status {})", resp.status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttpClient;

    #[test]
    fn webhook_payload_is_metadata_only_and_https_enforced() {
        let payload = NotificationPayload {
            source: "api-tracker",
            kind: "expired",
            severity: "high",
            title: "credential expired: web/openai",
            detail: "the expiration date has passed",
            recommended_action: "rotate",
            observed_at: "2026-07-18T00:00:00Z",
        };
        let mock = MockHttpClient::json(r#"{"ok":true}"#);
        deliver_webhook(&mock, "https://example.com/hook", &payload).unwrap();
        let req = mock.last_request().unwrap();
        let body = String::from_utf8_lossy(req.body.as_ref().unwrap()).into_owned();
        assert!(body.contains("expired"));
        assert!(!body.contains("sk-"));

        let mock = MockHttpClient::json("{}");
        assert!(deliver_webhook(&mock, "http://example.com/hook", &payload).is_err());
    }

    #[test]
    fn severity_ranks_order() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("info"));
    }
}
