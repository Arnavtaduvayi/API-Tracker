//! Projects-first folder linkage, detected-credential stubs, and user-supplied
//! names for unknown hosts (schema v20, ADR 0029).
//!
//! This module is deliberately *storage only*. It records the product-level
//! facts a projects-first surface needs — "this is the project's folder",
//! "tracking for it is on", "we saw `ANTHROPIC_API_KEY` and nobody has decided
//! what to do about it", "the user calls `api.example.com` Acme" — and it
//! orchestrates nothing. Detection, planning, applying, health and undo stay
//! in `api_tracker_tracking`, which is the one implementation of tracking
//! setup; a second one here is exactly what ADR 0029 refuses to build.
//!
//! Two invariants are structural rather than enforced by a predicate:
//!
//! * **No secret value can be stored.** [`DetectedCredential`] has no field,
//!   and `detected_credentials` no column, capable of holding one. The
//!   scanner already refuses to carry values out of a project; this layer
//!   could not persist one if a caller handed it over.
//!
//! Naming an unknown API is deliberately NOT here: `observed_api_services`
//! already carries `user_provider` / `user_api_name`, written through
//! `runtime::store::set_service_correction` and keyed by host. Adding a
//! per-project label table would be a second implementation of a feature that
//! shipped in schema v12.

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::clock;
use crate::error::{CoreError, Result};

// ---------------------------------------------------------------------------
// Project folder linkage
// ---------------------------------------------------------------------------

/// The one folder a project is linked to, and whether tracking for it is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectFolderLink {
    pub project_id: String,
    pub folder_path: String,
    pub tracking_enabled: bool,
    pub linked_at: String,
    pub last_scan_at: Option<String>,
    /// Digest over the dependency/env manifests the last scan looked at. A
    /// change HINT that gates offering a rescan — never an apply authorization.
    pub scan_fingerprint: Option<String>,
    /// `tracking_setups.config_generation` as of the last completed apply.
    pub applied_generation: i64,
    pub last_activity_refresh_at: Option<String>,
    /// Compare-and-swap token. Carry it into a write; a zero-row update means
    /// somebody else moved the row and the caller must re-read.
    pub row_version: i64,
}

const LINK_COLS: &str = "project_id, folder_path, tracking_enabled, linked_at, last_scan_at, \
                         scan_fingerprint, applied_generation, last_activity_refresh_at, \
                         row_version";

fn link_from_row(r: &Row<'_>) -> rusqlite::Result<ProjectFolderLink> {
    Ok(ProjectFolderLink {
        project_id: r.get(0)?,
        folder_path: r.get(1)?,
        tracking_enabled: r.get::<_, i64>(2)? != 0,
        linked_at: r.get(3)?,
        last_scan_at: r.get(4)?,
        scan_fingerprint: r.get(5)?,
        applied_generation: r.get(6)?,
        last_activity_refresh_at: r.get(7)?,
        row_version: r.get(8)?,
    })
}

/// The project's linked folder, or `None` when it has never selected one.
pub fn get_link(conn: &Connection, project_id: &str) -> Result<Option<ProjectFolderLink>> {
    let sql = format!("SELECT {LINK_COLS} FROM project_folder_links WHERE project_id = ?1");
    Ok(conn
        .query_row(&sql, params![project_id], link_from_row)
        .optional()?)
}

/// Every linked folder, oldest link first. Used on launch to restore what was
/// being observed without touching any of it.
pub fn list_links(conn: &Connection) -> Result<Vec<ProjectFolderLink>> {
    let sql =
        format!("SELECT {LINK_COLS} FROM project_folder_links ORDER BY linked_at, project_id");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], link_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Link `folder` to `project_id`, or move an existing link to a new folder.
///
/// Idempotent by construction: the row is keyed by `project_id` alone, so
/// selecting the same folder twice updates one row rather than accumulating
/// them. Re-selecting the SAME folder preserves `linked_at`, the scan
/// fingerprint and `applied_generation` — nothing about the folder changed, so
/// nothing that describes the folder is discarded. Choosing a DIFFERENT folder
/// clears the scan state, because a fingerprint and an applied generation
/// describe the old folder and would otherwise read as current for the new one.
///
/// `tracking_enabled` is preserved across a re-link so that re-selecting a
/// folder does not silently re-enable tracking the user turned off.
pub fn upsert_link(conn: &Connection, project_id: &str, folder: &str) -> Result<ProjectFolderLink> {
    let now = clock::now_rfc3339();
    let existing = get_link(conn, project_id)?;
    match existing {
        Some(prev) if prev.folder_path == folder => Ok(prev),
        Some(prev) => {
            let changed = conn.execute(
                "UPDATE project_folder_links
                 SET folder_path = ?2, last_scan_at = NULL, scan_fingerprint = NULL,
                     applied_generation = 0, last_activity_refresh_at = NULL,
                     row_version = row_version + 1
                 WHERE project_id = ?1 AND row_version = ?3",
                params![project_id, folder, prev.row_version],
            )?;
            if changed == 0 {
                return Err(CoreError::StateConflict {
                    kind: "project folder link",
                    ident: project_id.to_string(),
                });
            }
            Ok(ProjectFolderLink {
                folder_path: folder.to_string(),
                last_scan_at: None,
                scan_fingerprint: None,
                applied_generation: 0,
                last_activity_refresh_at: None,
                row_version: prev.row_version + 1,
                ..prev
            })
        }
        None => {
            conn.execute(
                "INSERT INTO project_folder_links
                    (project_id, folder_path, tracking_enabled, linked_at, applied_generation,
                     row_version)
                 VALUES (?1, ?2, 1, ?3, 0, 0)",
                params![project_id, folder, now],
            )?;
            Ok(ProjectFolderLink {
                project_id: project_id.to_string(),
                folder_path: folder.to_string(),
                tracking_enabled: true,
                linked_at: now,
                last_scan_at: None,
                scan_fingerprint: None,
                applied_generation: 0,
                last_activity_refresh_at: None,
                row_version: 0,
            })
        }
    }
}

/// Record that a scan completed: when, and the fingerprint it observed.
pub fn record_scan(
    conn: &Connection,
    link: &mut ProjectFolderLink,
    fingerprint: Option<&str>,
) -> Result<()> {
    let now = clock::now_rfc3339();
    let changed = conn.execute(
        "UPDATE project_folder_links
         SET last_scan_at = ?2, scan_fingerprint = ?3, row_version = row_version + 1
         WHERE project_id = ?1 AND row_version = ?4",
        params![link.project_id, now, fingerprint, link.row_version],
    )?;
    cas_check(changed, link)?;
    link.last_scan_at = Some(now);
    link.scan_fingerprint = fingerprint.map(str::to_string);
    link.row_version += 1;
    Ok(())
}

/// Record the `tracking_setups.config_generation` an apply actually reached.
///
/// This is the left-hand side of "is the applied configuration still the
/// current one?". v16 added the counter; until v20 nothing stored the value an
/// apply got to, so the comparison had nothing to compare against.
pub fn record_applied_generation(
    conn: &Connection,
    link: &mut ProjectFolderLink,
    generation: i64,
) -> Result<()> {
    let changed = conn.execute(
        "UPDATE project_folder_links
         SET applied_generation = ?2, row_version = row_version + 1
         WHERE project_id = ?1 AND row_version = ?3",
        params![link.project_id, generation, link.row_version],
    )?;
    cas_check(changed, link)?;
    link.applied_generation = generation;
    link.row_version += 1;
    Ok(())
}

// There is deliberately no `record_activity_refresh`. The five-second activity
// poll used to call one, compare-and-swapping `last_activity_refresh_at` and
// incrementing `row_version` twelve times a minute per open project page — and
// nothing read the column it wrote. The "Last updated" line comes from the
// client's own last successful fetch, which is the only place that knows whether
// the refresh the user is looking at actually landed.
//
// The cost was not the write. It was `row_version`: this row's compare-and-swap
// token is the guard for Disable tracking, Rescan and the applied-generation
// record, so a poll landing between a caller's read and its write made that
// caller fail with a raw StateConflict for no product reason (`AUD-03`).
// Reading activity now leaves the durable configuration byte-for-byte unchanged.
//
// The COLUMN stays in the schema and in this struct: existing vaults hold values
// for it, and dropping a column to remove a write would break the data format
// for nothing. It is read from the row and never written.

/// Turn tracking for this project's folder on or off without deleting the
/// project, the linkage, the credentials or the history.
pub fn set_tracking_enabled(
    conn: &Connection,
    link: &mut ProjectFolderLink,
    enabled: bool,
) -> Result<()> {
    let changed = conn.execute(
        "UPDATE project_folder_links
         SET tracking_enabled = ?2, row_version = row_version + 1
         WHERE project_id = ?1 AND row_version = ?3",
        params![link.project_id, enabled as i64, link.row_version],
    )?;
    cas_check(changed, link)?;
    link.tracking_enabled = enabled;
    link.row_version += 1;
    Ok(())
}

/// Remove the linkage row. The project, its credentials and its recorded
/// activity are untouched — and so is the user's folder on disk.
pub fn delete_link(conn: &Connection, project_id: &str) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM project_folder_links WHERE project_id = ?1",
        params![project_id],
    )?;
    Ok(n > 0)
}

/// Every write to a linkage row compare-and-swaps on `row_version`, matching
/// `tracking_setups` (schema v19). A blind UPDATE would let a refresh running
/// from a stale in-memory row overwrite a decision another window just made.
///
/// A zero-row update is a signal, not a no-op: the caller re-reads and
/// re-derives rather than forcing its conclusion over the newer row.
fn cas_check(changed: usize, link: &ProjectFolderLink) -> Result<()> {
    if changed == 0 {
        return Err(CoreError::StateConflict {
            kind: "project folder link",
            ident: link.project_id.clone(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Detected credentials (unfinished records)
// ---------------------------------------------------------------------------

/// What the user has decided about a detected credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedStatus {
    /// Tethra saw it; nobody has decided anything.
    Pending,
    /// The user supplied the value; it lives in the vault.
    Completed,
    /// The user does not want to be asked again.
    Ignored,
    /// Intentionally managed outside Tethra.
    External,
    /// Pointed at an existing credential.
    Merged,
}

impl DetectedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Ignored => "ignored",
            Self::External => "external",
            Self::Merged => "merged",
        }
    }

    /// Parse a stored value. The schema CHECK keeps anything else out of the
    /// table, so an unrecognized string is a corrupt row, not a new state.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "completed" => Ok(Self::Completed),
            "ignored" => Ok(Self::Ignored),
            "external" => Ok(Self::External),
            "merged" => Ok(Self::Merged),
            other => Err(CoreError::InvalidInput(format!(
                "unrecognized detected-credential status '{other}'"
            ))),
        }
    }

    /// Whether this row still wants the user's attention.
    pub fn needs_attention(self) -> bool {
        matches!(self, Self::Pending)
    }
}

/// Where the evidence for a detected credential came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedSource {
    /// A credential-shaped assignment in an `.env`-class file.
    EnvFile,
    /// A provider manifest matched the variable name.
    Manifest,
    /// An SDK dependency implied the integration.
    Dependency,
}

impl DetectedSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnvFile => "env_file",
            Self::Manifest => "manifest",
            Self::Dependency => "dependency",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "manifest" => Self::Manifest,
            "dependency" => Self::Dependency,
            // `env_file` is the default for an unrecognized value because it
            // is the least specific claim, not because it is most likely.
            _ => Self::EnvFile,
        }
    }
}

/// An integration Tethra can see the project uses but cannot safely complete.
///
/// Carries the variable NAME, the folder-relative file, and guesses. There is
/// no field for a value, by design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedCredential {
    pub id: String,
    pub project_id: String,
    /// An environment-variable name, e.g. `ANTHROPIC_API_KEY`.
    pub env_var: String,
    pub suggested_provider: Option<String>,
    pub suggested_name: Option<String>,
    /// `None` renders as "unknown", never as a guessed environment.
    pub suggested_environment: Option<String>,
    pub source_kind: DetectedSource,
    /// Folder-relative, never absolute.
    pub source_file: String,
    pub status: DetectedStatus,
    pub resolved_credential_id: Option<String>,
    pub first_detected_at: String,
    pub last_detected_at: String,
    pub row_version: i64,
}

impl DetectedCredential {
    /// The fixed, non-secret sentence about the value. There is nowhere for a
    /// value to live, so this is a property of the type, not of the row.
    pub fn value_status(&self) -> &'static str {
        match self.status {
            DetectedStatus::Completed => "Saved in Tethra",
            DetectedStatus::External => "Managed outside Tethra",
            _ => "Not saved in Tethra",
        }
    }

    /// Whether exact per-credential attribution can be expected for traffic
    /// this row describes.
    pub fn attribution_status(&self) -> &'static str {
        match self.status {
            DetectedStatus::Completed | DetectedStatus::Merged => "Exact key available",
            DetectedStatus::External => "Not attributed (external)",
            DetectedStatus::Ignored => "Not attributed (ignored)",
            DetectedStatus::Pending => "Pending exact key",
        }
    }
}

const DC_COLS: &str = "id, project_id, env_var, suggested_provider, suggested_name, \
                       suggested_environment, source_kind, source_file, status, \
                       resolved_credential_id, first_detected_at, last_detected_at, row_version";

fn dc_from_row(r: &Row<'_>) -> rusqlite::Result<DetectedCredential> {
    let status: String = r.get(8)?;
    Ok(DetectedCredential {
        id: r.get(0)?,
        project_id: r.get(1)?,
        env_var: r.get(2)?,
        suggested_provider: r.get(3)?,
        suggested_name: r.get(4)?,
        suggested_environment: r.get(5)?,
        source_kind: DetectedSource::parse(&r.get::<_, String>(6)?),
        source_file: r.get(7)?,
        // A row that fails to parse is a corrupt row; surface it as pending
        // (needs attention) rather than dropping the detection entirely.
        status: DetectedStatus::parse(&status).unwrap_or(DetectedStatus::Pending),
        resolved_credential_id: r.get(9)?,
        first_detected_at: r.get(10)?,
        last_detected_at: r.get(11)?,
        row_version: r.get(12)?,
    })
}

/// What a caller wants recorded about one detected integration.
#[derive(Debug, Clone)]
pub struct NewDetection<'a> {
    pub env_var: &'a str,
    pub suggested_provider: Option<&'a str>,
    pub suggested_name: Option<&'a str>,
    pub suggested_environment: Option<&'a str>,
    pub source_kind: DetectedSource,
    pub source_file: &'a str,
}

/// Record a detection, or refresh the `last_detected_at` of one already known.
///
/// Re-running detection must not resurrect a decision: a row the user set to
/// `ignored`, `external`, `completed` or `merged` keeps that status and only
/// its `last_detected_at` moves. Only the suggestion fields of a still-pending
/// row are refreshed, so an improved provider guess reaches the user without
/// re-asking a question they already answered.
pub fn upsert_detection(
    conn: &Connection,
    project_id: &str,
    new: &NewDetection<'_>,
) -> Result<DetectedCredential> {
    let now = clock::now_rfc3339();
    let existing = find_detection(conn, project_id, new.env_var, new.source_file)?;
    if let Some(mut row) = existing {
        if row.status.needs_attention() {
            conn.execute(
                "UPDATE detected_credentials
                 SET suggested_provider = ?2, suggested_name = ?3, suggested_environment = ?4,
                     source_kind = ?5, last_detected_at = ?6, row_version = row_version + 1
                 WHERE id = ?1",
                params![
                    row.id,
                    new.suggested_provider,
                    new.suggested_name,
                    new.suggested_environment,
                    new.source_kind.as_str(),
                    now
                ],
            )?;
            row.suggested_provider = new.suggested_provider.map(str::to_string);
            row.suggested_name = new.suggested_name.map(str::to_string);
            row.suggested_environment = new.suggested_environment.map(str::to_string);
            row.source_kind = new.source_kind;
            row.row_version += 1;
        } else {
            conn.execute(
                "UPDATE detected_credentials SET last_detected_at = ?2 WHERE id = ?1",
                params![row.id, now],
            )?;
        }
        row.last_detected_at = now;
        return Ok(row);
    }

    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO detected_credentials
            (id, project_id, env_var, suggested_provider, suggested_name, suggested_environment,
             source_kind, source_file, status, resolved_credential_id,
             first_detected_at, last_detected_at, row_version)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', NULL, ?9, ?9, 0)",
        params![
            id,
            project_id,
            new.env_var,
            new.suggested_provider,
            new.suggested_name,
            new.suggested_environment,
            new.source_kind.as_str(),
            new.source_file,
            now
        ],
    )?;
    Ok(DetectedCredential {
        id,
        project_id: project_id.to_string(),
        env_var: new.env_var.to_string(),
        suggested_provider: new.suggested_provider.map(str::to_string),
        suggested_name: new.suggested_name.map(str::to_string),
        suggested_environment: new.suggested_environment.map(str::to_string),
        source_kind: new.source_kind,
        source_file: new.source_file.to_string(),
        status: DetectedStatus::Pending,
        resolved_credential_id: None,
        first_detected_at: now.clone(),
        last_detected_at: now,
        row_version: 0,
    })
}

fn find_detection(
    conn: &Connection,
    project_id: &str,
    env_var: &str,
    source_file: &str,
) -> Result<Option<DetectedCredential>> {
    let sql = format!(
        "SELECT {DC_COLS} FROM detected_credentials
         WHERE project_id = ?1 AND env_var = ?2 AND source_file = ?3"
    );
    Ok(conn
        .query_row(&sql, params![project_id, env_var, source_file], dc_from_row)
        .optional()?)
}

/// Every detection for a project, most recently seen first.
pub fn list_detections(conn: &Connection, project_id: &str) -> Result<Vec<DetectedCredential>> {
    let sql = format!(
        "SELECT {DC_COLS} FROM detected_credentials WHERE project_id = ?1
         ORDER BY last_detected_at DESC, env_var"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![project_id], dc_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn get_detection(conn: &Connection, id: &str) -> Result<DetectedCredential> {
    let sql = format!("SELECT {DC_COLS} FROM detected_credentials WHERE id = ?1");
    conn.query_row(&sql, params![id], dc_from_row)
        .optional()?
        .ok_or_else(|| CoreError::NotFound {
            kind: "detected credential",
            ident: id.to_string(),
        })
}

/// Move a detection to a terminal status the user chose.
///
/// `Completed` and `Merged` both require the vault row they point at, which the
/// schema also enforces for `completed`. Passing a credential id for `Ignored`
/// or `External` is rejected rather than silently dropped: those states mean
/// "there is no Tethra record for this", and storing one would contradict the
/// sentence the user is shown.
pub fn resolve_detection(
    conn: &Connection,
    id: &str,
    status: DetectedStatus,
    credential_id: Option<&str>,
) -> Result<DetectedCredential> {
    let mut row = get_detection(conn, id)?;
    match (status, credential_id) {
        (DetectedStatus::Completed | DetectedStatus::Merged, None) => {
            return Err(CoreError::InvalidInput(format!(
                "marking a detection '{}' needs the credential it resolved to",
                status.as_str()
            )));
        }
        (DetectedStatus::Ignored | DetectedStatus::External | DetectedStatus::Pending, Some(_)) => {
            return Err(CoreError::InvalidInput(format!(
                "'{}' means there is no Tethra credential for this detection",
                status.as_str()
            )));
        }
        _ => {}
    }
    let changed = conn.execute(
        "UPDATE detected_credentials
         SET status = ?2, resolved_credential_id = ?3, row_version = row_version + 1
         WHERE id = ?1 AND row_version = ?4",
        params![id, status.as_str(), credential_id, row.row_version],
    )?;
    if changed == 0 {
        return Err(CoreError::StateConflict {
            kind: "detected credential",
            ident: id.to_string(),
        });
    }
    row.status = status;
    row.resolved_credential_id = credential_id.map(str::to_string);
    row.row_version += 1;
    Ok(row)
}

/// Rename the credential a detection suggests, without deciding anything else.
pub fn rename_detection(conn: &Connection, id: &str, name: &str) -> Result<DetectedCredential> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidInput(
            "a credential name cannot be empty".into(),
        ));
    }
    update_suggestion(conn, id, "suggested_name", trimmed)
}

/// Reassign the provider a detection suggests.
pub fn reassign_detection_provider(
    conn: &Connection,
    id: &str,
    provider: &str,
) -> Result<DetectedCredential> {
    let trimmed = provider.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidInput("a provider cannot be empty".into()));
    }
    update_suggestion(conn, id, "suggested_provider", trimmed)
}

/// Choose the environment a detection belongs to.
pub fn set_detection_environment(
    conn: &Connection,
    id: &str,
    environment: &str,
) -> Result<DetectedCredential> {
    let trimmed = environment.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidInput(
            "an environment cannot be empty".into(),
        ));
    }
    update_suggestion(conn, id, "suggested_environment", trimmed)
}

fn update_suggestion(
    conn: &Connection,
    id: &str,
    column: &'static str,
    value: &str,
) -> Result<DetectedCredential> {
    let mut row = get_detection(conn, id)?;
    // `column` is one of three compile-time constants chosen by the three
    // wrappers above; no caller-supplied string reaches this format.
    let sql = format!(
        "UPDATE detected_credentials SET {column} = ?2, row_version = row_version + 1
         WHERE id = ?1 AND row_version = ?3"
    );
    let changed = conn.execute(&sql, params![id, value, row.row_version])?;
    if changed == 0 {
        return Err(CoreError::StateConflict {
            kind: "detected credential",
            ident: id.to_string(),
        });
    }
    match column {
        "suggested_name" => row.suggested_name = Some(value.to_string()),
        "suggested_provider" => row.suggested_provider = Some(value.to_string()),
        _ => row.suggested_environment = Some(value.to_string()),
    }
    row.row_version += 1;
    Ok(row)
}
