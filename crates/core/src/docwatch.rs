//! Local documentation-change watcher.
//!
//! Users watch selected official documentation URLs (from provider manifests
//! or chosen explicitly). A check performs a conditional HTTP GET (sending
//! `If-None-Modified`/`If-None-Match` when we have prior validators) directly
//! from the user's device, hashes the response body, and records only the
//! minimum state: ETag, Last-Modified, a content hash, and timestamps. The
//! full page content is never stored or redistributed.
//!
//! The HTTP transport is behind the [`DocFetcher`] trait so the change-
//! detection logic is fully testable offline with a mock; the real
//! implementation ([`HttpFetcher`]) uses a blocking client with a
//! conservative timeout. A page changing does not imply a breaking API
//! change — callers surface that caveat to the user.

use crate::clock;
use crate::error::{CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;

/// Validators we can send on a conditional request.
#[derive(Debug, Clone, Default)]
pub struct Conditional {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// The outcome of a fetch.
#[derive(Debug, Clone)]
pub enum FetchOutcome {
    /// 304 Not Modified — nothing changed.
    NotModified,
    /// 200 with a body; validators are echoed back when present.
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// Abstracts the HTTP transport so tests can inject a mock and no network is
/// required to exercise the change-detection logic.
pub trait DocFetcher {
    fn fetch(&self, url: &str, conditional: &Conditional) -> Result<FetchOutcome>;
}

/// The result of checking one watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    /// First successful capture (no prior hash to compare).
    FirstCapture,
    /// Content is unchanged (by 304 or identical hash).
    Unchanged,
    /// Content changed.
    Changed,
    /// The check failed (offline, error); prior state is preserved.
    Failed,
}

impl CheckResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckResult::FirstCapture => "first capture",
            CheckResult::Unchanged => "unchanged",
            CheckResult::Changed => "changed",
            CheckResult::Failed => "check failed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DocWatch {
    pub id: String,
    pub provider: String,
    pub url: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub content_hash: Option<String>,
    pub last_checked_at: Option<String>,
    pub last_changed_at: Option<String>,
    pub last_status: String,
    pub created_at: String,
}

const COLUMNS: &str = "id, provider, url, etag, last_modified, content_hash, \
     last_checked_at, last_changed_at, last_status, created_at";

fn row_to_watch(row: &Row<'_>) -> rusqlite::Result<DocWatch> {
    Ok(DocWatch {
        id: row.get(0)?,
        provider: row.get(1)?,
        url: row.get(2)?,
        etag: row.get(3)?,
        last_modified: row.get(4)?,
        content_hash: row.get(5)?,
        last_checked_at: row.get(6)?,
        last_changed_at: row.get(7)?,
        last_status: row.get(8)?,
        created_at: row.get(9)?,
    })
}

/// Only official documentation URLs from the manifests, or plain http(s)
/// URLs, may be watched — we never crawl arbitrary hosts.
fn validate_url(url: &str) -> Result<()> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(CoreError::InvalidInput("watch URLs must be http(s)".into()));
    }
    Ok(())
}

/// Register a watch for a URL (idempotent on URL).
pub fn add_watch(conn: &Connection, provider: &str, url: &str) -> Result<DocWatch> {
    validate_url(url)?;
    if let Some(existing) = get_by_url(conn, url)? {
        return Ok(existing);
    }
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO doc_watches (id, provider, url, last_status, created_at)
         VALUES (?1, ?2, ?3, 'never checked', ?4)",
        params![id, provider, url, clock::now_rfc3339()],
    )?;
    get(conn, &id)
}

pub fn remove_watch(conn: &Connection, url: &str) -> Result<bool> {
    let n = conn.execute("DELETE FROM doc_watches WHERE url = ?1", [url])?;
    Ok(n > 0)
}

pub fn list(conn: &Connection) -> Result<Vec<DocWatch>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM doc_watches ORDER BY provider, url"
    ))?;
    let rows = stmt.query_map([], row_to_watch)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn list_for_provider(conn: &Connection, provider: &str) -> Result<Vec<DocWatch>> {
    Ok(list(conn)?
        .into_iter()
        .filter(|w| w.provider.eq_ignore_ascii_case(provider))
        .collect())
}

fn get(conn: &Connection, id: &str) -> Result<DocWatch> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM doc_watches WHERE id = ?1"),
        [id],
        row_to_watch,
    )
    .optional()?
    .ok_or_else(|| CoreError::NotFound {
        kind: "doc watch",
        ident: id.to_owned(),
    })
}

fn get_by_url(conn: &Connection, url: &str) -> Result<Option<DocWatch>> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM doc_watches WHERE url = ?1"),
            [url],
            row_to_watch,
        )
        .optional()?)
}

fn content_hash(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

/// Record a check outcome in the local change history (validators and
/// outcomes only — never page content).
pub fn record_history(
    conn: &rusqlite::Connection,
    url: &str,
    provider: &str,
    outcome: &str,
    detail: &str,
) -> crate::error::Result<()> {
    conn.execute(
        "INSERT INTO doc_watch_history (url, provider, at, outcome, detail)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![url, provider, crate::clock::now_rfc3339(), outcome, detail],
    )?;
    Ok(())
}

/// One history entry (metadata only).
#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryEntry {
    pub url: String,
    pub provider: String,
    pub at: String,
    pub outcome: String,
    pub detail: String,
}

pub fn history(
    conn: &rusqlite::Connection,
    url: Option<&str>,
    limit: u32,
) -> crate::error::Result<Vec<HistoryEntry>> {
    let mut out = Vec::new();
    let mut push_rows = |stmt: &mut rusqlite::Statement<'_>,
                         params: &[&dyn rusqlite::ToSql]|
     -> crate::error::Result<()> {
        let rows = stmt.query_map(params, |r| {
            Ok(HistoryEntry {
                url: r.get(0)?,
                provider: r.get(1)?,
                at: r.get(2)?,
                outcome: r.get(3)?,
                detail: r.get(4)?,
            })
        })?;
        for r in rows {
            out.push(r?);
        }
        Ok(())
    };
    match url {
        Some(u) => {
            let mut stmt = conn.prepare(
                "SELECT url, provider, at, outcome, detail FROM doc_watch_history
                 WHERE url = ?1 ORDER BY id DESC LIMIT ?2",
            )?;
            push_rows(&mut stmt, &[&u, &limit])?;
        }
        None => {
            let mut stmt = conn.prepare(
                "SELECT url, provider, at, outcome, detail FROM doc_watch_history
                 ORDER BY id DESC LIMIT ?1",
            )?;
            push_rows(&mut stmt, &[&limit])?;
        }
    }
    Ok(out)
}

/// Watch URLs whose last check is older than `interval_hours` (or never
/// checked). Conservative scheduling input for the monitor.
pub fn due_watches(
    conn: &rusqlite::Connection,
    interval_hours: u32,
) -> crate::error::Result<Vec<String>> {
    if interval_hours == 0 {
        return Ok(Vec::new());
    }
    let cutoff = crate::clock::to_rfc3339(
        crate::clock::now() - time::Duration::hours(i64::from(interval_hours)),
    );
    let mut stmt = conn.prepare(
        "SELECT url FROM doc_watches
         WHERE last_checked_at IS NULL OR last_checked_at < ?1
         ORDER BY last_checked_at",
    )?;
    let rows = stmt.query_map([&cutoff], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Check one watched URL and persist the new state. Returns the outcome and
/// the refreshed watch. Failures preserve prior validators/hash.
pub fn check_watch(
    conn: &Connection,
    fetcher: &dyn DocFetcher,
    url: &str,
) -> Result<(CheckResult, DocWatch)> {
    let watch = get_by_url(conn, url)?.ok_or_else(|| CoreError::NotFound {
        kind: "doc watch",
        ident: url.to_owned(),
    })?;
    let conditional = Conditional {
        etag: watch.etag.clone(),
        last_modified: watch.last_modified.clone(),
    };
    let now = clock::now_rfc3339();

    let outcome = match fetcher.fetch(url, &conditional) {
        Ok(o) => o,
        Err(e) => {
            let status = format!("error: {e}");
            conn.execute(
                "UPDATE doc_watches SET last_checked_at = ?1, last_status = ?2 WHERE id = ?3",
                params![now, status, watch.id],
            )?;
            return Ok((CheckResult::Failed, get(conn, &watch.id)?));
        }
    };

    let (result, new_hash, new_etag, new_last_modified) = match outcome {
        FetchOutcome::NotModified => (
            CheckResult::Unchanged,
            watch.content_hash.clone(),
            watch.etag.clone(),
            watch.last_modified.clone(),
        ),
        FetchOutcome::Body {
            bytes,
            etag,
            last_modified,
        } => {
            let hash = content_hash(&bytes);
            let result = match &watch.content_hash {
                None => CheckResult::FirstCapture,
                Some(prev) if *prev == hash => CheckResult::Unchanged,
                Some(_) => CheckResult::Changed,
            };
            // Validators describe THIS body. If the response omits them, store
            // None (do not carry the previous body's ETag/Last-Modified) so the
            // next request is unconditional and a stale validator can never
            // make a future 304 mask a real change. Carrying them forward is
            // only safe when the content is unchanged.
            let (new_etag, new_last_modified) = if result == CheckResult::Unchanged {
                (
                    etag.or(watch.etag.clone()),
                    last_modified.or(watch.last_modified.clone()),
                )
            } else {
                (etag, last_modified)
            };
            (result, Some(hash), new_etag, new_last_modified)
        }
    };

    let changed_at = if result == CheckResult::Changed || result == CheckResult::FirstCapture {
        Some(now.clone())
    } else {
        watch.last_changed_at.clone()
    };

    conn.execute(
        "UPDATE doc_watches SET etag = ?1, last_modified = ?2, content_hash = ?3,
         last_checked_at = ?4, last_changed_at = ?5, last_status = ?6 WHERE id = ?7",
        params![
            new_etag,
            new_last_modified,
            new_hash,
            now,
            changed_at,
            result.as_str(),
            watch.id
        ],
    )?;
    Ok((result, get(conn, &watch.id)?))
}

/// A blocking HTTP fetcher used by the real application. Sends conditional
/// validators and a descriptive User-Agent; enforces a short timeout.
pub struct HttpFetcher {
    agent: ureq::Agent,
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpFetcher {
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(20)))
            // Do NOT follow redirects. A watched documentation page that
            // 30x-redirects could otherwise be pointed at an internal host
            // (e.g. a cloud metadata endpoint) or downgraded https→http; the
            // user chose the URL, so a redirect to a different origin is not
            // something we should silently follow. A redirect surfaces as a
            // non-success status (handled as a failed check), never as a
            // fetch of the redirect target.
            .max_redirects(0)
            .user_agent("api-tracker-docwatch/0.1 (+local, respects conditional requests)")
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl DocFetcher for HttpFetcher {
    fn fetch(&self, url: &str, conditional: &Conditional) -> Result<FetchOutcome> {
        let mut req = self.agent.get(url);
        if let Some(etag) = &conditional.etag {
            req = req.header("If-None-Match", etag);
        }
        if let Some(lm) = &conditional.last_modified {
            req = req.header("If-Modified-Since", lm);
        }
        match req.call() {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                if status == 304 {
                    return Ok(FetchOutcome::NotModified);
                }
                let etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let last_modified = resp
                    .headers()
                    .get("last-modified")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let bytes = resp
                    .body_mut()
                    .with_config()
                    .limit(8 * 1024 * 1024)
                    .read_to_vec()
                    .map_err(|e| {
                        CoreError::InvalidInput(format!("could not read response body: {e}"))
                    })?;
                Ok(FetchOutcome::Body {
                    bytes,
                    etag,
                    last_modified,
                })
            }
            // ureq surfaces 304 as an error in some versions; treat it as NotModified.
            Err(ureq::Error::StatusCode(304)) => Ok(FetchOutcome::NotModified),
            Err(e) => Err(CoreError::InvalidInput(format!(
                "documentation fetch failed: {e}"
            ))),
        }
    }
}

/// A scripted fetcher for tests: maps url → a queue of outcomes.
#[derive(Default)]
pub struct MockFetcher {
    pub responses: std::cell::RefCell<HashMap<String, Vec<FetchOutcome>>>,
    pub last_conditional: std::cell::RefCell<Option<Conditional>>,
}

impl MockFetcher {
    pub fn with(url: &str, outcomes: Vec<FetchOutcome>) -> Self {
        let mut map = HashMap::new();
        map.insert(url.to_string(), outcomes);
        Self {
            responses: std::cell::RefCell::new(map),
            last_conditional: Default::default(),
        }
    }
}

impl DocFetcher for MockFetcher {
    fn fetch(&self, url: &str, conditional: &Conditional) -> Result<FetchOutcome> {
        *self.last_conditional.borrow_mut() = Some(conditional.clone());
        let mut map = self.responses.borrow_mut();
        let queue = map
            .get_mut(url)
            .ok_or_else(|| CoreError::InvalidInput(format!("no mock response for {url}")))?;
        if queue.is_empty() {
            return Err(CoreError::InvalidInput("mock queue exhausted".into()));
        }
        Ok(queue.remove(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        conn
    }

    fn body(s: &str) -> FetchOutcome {
        FetchOutcome::Body {
            bytes: s.as_bytes().to_vec(),
            etag: None,
            last_modified: None,
        }
    }

    #[test]
    fn add_and_list_watch() {
        let conn = mem();
        let w = add_watch(&conn, "openai", "https://example.com/docs").unwrap();
        assert_eq!(w.provider, "openai");
        // Idempotent on URL.
        add_watch(&conn, "openai", "https://example.com/docs").unwrap();
        assert_eq!(list(&conn).unwrap().len(), 1);
        assert!(remove_watch(&conn, "https://example.com/docs").unwrap());
    }

    #[test]
    fn rejects_non_http_urls() {
        let conn = mem();
        assert!(add_watch(&conn, "openai", "ftp://x/y").is_err());
    }

    #[test]
    fn first_capture_then_unchanged_then_changed() {
        let conn = mem();
        let url = "https://example.com/docs";
        add_watch(&conn, "openai", url).unwrap();

        let fetcher = MockFetcher::with(
            url,
            vec![body("v1 content"), body("v1 content"), body("v2 content")],
        );

        let (r, w) = check_watch(&conn, &fetcher, url).unwrap();
        assert_eq!(r, CheckResult::FirstCapture);
        assert!(w.content_hash.is_some());
        assert!(w.last_changed_at.is_some());

        let (r, _) = check_watch(&conn, &fetcher, url).unwrap();
        assert_eq!(r, CheckResult::Unchanged);

        let (r, w) = check_watch(&conn, &fetcher, url).unwrap();
        assert_eq!(r, CheckResult::Changed);
        assert_eq!(w.last_status, "changed");
    }

    #[test]
    fn not_modified_is_unchanged_and_sends_validators() {
        let conn = mem();
        let url = "https://example.com/docs";
        add_watch(&conn, "openai", url).unwrap();
        // First: body with an ETag; then a 304.
        let fetcher = MockFetcher::with(
            url,
            vec![
                FetchOutcome::Body {
                    bytes: b"hello".to_vec(),
                    etag: Some("\"abc\"".into()),
                    last_modified: Some("Wed, 21 Oct 2026 07:28:00 GMT".into()),
                },
                FetchOutcome::NotModified,
            ],
        );
        check_watch(&conn, &fetcher, url).unwrap();
        let (r, _) = check_watch(&conn, &fetcher, url).unwrap();
        assert_eq!(r, CheckResult::Unchanged);
        // The second request carried the stored validators.
        let cond = fetcher.last_conditional.borrow();
        assert_eq!(cond.as_ref().unwrap().etag.as_deref(), Some("\"abc\""));
    }

    #[test]
    fn changed_body_without_validators_clears_stale_validator() {
        let conn = mem();
        let url = "https://example.com/docs";
        add_watch(&conn, "openai", url).unwrap();
        // First body carries an ETag; a later CHANGED body omits it.
        let fetcher = MockFetcher::with(
            url,
            vec![
                FetchOutcome::Body {
                    bytes: b"v1".to_vec(),
                    etag: Some("\"v1etag\"".into()),
                    last_modified: None,
                },
                FetchOutcome::Body {
                    bytes: b"v2".to_vec(),
                    etag: None,
                    last_modified: None,
                },
            ],
        );
        check_watch(&conn, &fetcher, url).unwrap();
        let (r, w) = check_watch(&conn, &fetcher, url).unwrap();
        assert_eq!(r, CheckResult::Changed);
        // The stale v1 ETag must not be carried onto the v2 body.
        assert_eq!(
            w.etag, None,
            "stale validator must be cleared on a changed body"
        );
    }

    #[test]
    fn failed_check_preserves_prior_state() {
        let conn = mem();
        let url = "https://example.com/docs";
        add_watch(&conn, "openai", url).unwrap();
        let fetcher = MockFetcher::with(url, vec![body("stable")]);
        check_watch(&conn, &fetcher, url).unwrap();
        let before = get_by_url(&conn, url).unwrap().unwrap();

        // Empty queue → fetch errors.
        let (r, after) = check_watch(&conn, &fetcher, url).unwrap();
        assert_eq!(r, CheckResult::Failed);
        assert_eq!(after.content_hash, before.content_hash);
        assert!(after.last_status.starts_with("error"));
    }
}
