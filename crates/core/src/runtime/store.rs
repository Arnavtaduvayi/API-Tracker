//! SQLite access for the runtime-observability tables.
//!
//! Every write goes through here, and nothing here accepts a raw path, header
//! map, or body — request events arrive as a sanitized [`ObservedRequest`]
//! ([`crate::runtime::model`]). The metadata-only guarantee is therefore
//! structural, not a filter applied at this layer.

use crate::clock;
use crate::error::Result;
use crate::providers::Confidence;
use crate::runtime::model::*;
use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

// --- Services (the automatic API inventory) --------------------------------

/// Find-or-create the service row for `host`. Returns `(service_id,
/// previously_known)` where `previously_known` is false only when this call
/// created the row (i.e. the host was first observed now).
pub fn upsert_service(
    conn: &Connection,
    host: &str,
    provider_id: Option<&str>,
    is_internal: bool,
    now: &str,
) -> Result<(String, bool)> {
    let host = host.trim().to_ascii_lowercase();
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM observed_api_services WHERE host = ?1",
            [&host],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        conn.execute(
            "UPDATE observed_api_services
             SET last_seen_at = ?1,
                 provider_id = COALESCE(provider_id, ?2)
             WHERE id = ?3",
            params![now, provider_id, id],
        )?;
        return Ok((id, true));
    }
    let id = new_id();
    let classification = if is_internal {
        ServiceClass::Internal
    } else {
        ServiceClass::External
    };
    conn.execute(
        "INSERT INTO observed_api_services
            (id, host, provider_id, source, classification, is_internal, first_seen_at, last_seen_at)
         VALUES (?1, ?2, ?3, 'locally_observed', ?4, ?5, ?6, ?6)
         ON CONFLICT(host) DO UPDATE SET last_seen_at = excluded.last_seen_at",
        params![id, host, provider_id, classification.as_str(), is_internal as i64, now],
    )?;
    // Re-resolve in case a concurrent writer won the race.
    let resolved: String = conn.query_row(
        "SELECT id FROM observed_api_services WHERE host = ?1",
        [&host],
        |r| r.get(0),
    )?;
    let created = resolved == id;
    Ok((resolved, !created))
}

fn row_to_service(r: &Row<'_>) -> rusqlite::Result<ObservedServiceRow> {
    Ok(ObservedServiceRow {
        id: r.get(0)?,
        host: r.get(1)?,
        provider_id: r.get(2)?,
        source: r.get(3)?,
        classification: r.get(4)?,
        is_internal: r.get::<_, i64>(5)? != 0,
        user_provider: r.get(6)?,
        user_api_name: r.get(7)?,
        user_notes: r.get(8)?,
        confirmed: r.get::<_, i64>(9)? != 0,
        first_seen_at: r.get(10)?,
        last_seen_at: r.get(11)?,
    })
}

const SERVICE_COLS: &str = "id, host, provider_id, source, classification, is_internal, \
     user_provider, user_api_name, user_notes, confirmed, first_seen_at, last_seen_at";

pub fn list_services(conn: &Connection) -> Result<Vec<ObservedServiceRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SERVICE_COLS} FROM observed_api_services ORDER BY last_seen_at DESC"
    ))?;
    let rows = stmt.query_map([], row_to_service)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn get_service(conn: &Connection, id: &str) -> Result<Option<ObservedServiceRow>> {
    Ok(conn
        .query_row(
            &format!("SELECT {SERVICE_COLS} FROM observed_api_services WHERE id = ?1"),
            [id],
            row_to_service,
        )
        .optional()?)
}

pub fn get_service_by_host(conn: &Connection, host: &str) -> Result<Option<ObservedServiceRow>> {
    Ok(conn
        .query_row(
            &format!("SELECT {SERVICE_COLS} FROM observed_api_services WHERE host = ?1"),
            [host.trim().to_ascii_lowercase()],
            row_to_service,
        )
        .optional()?)
}

/// Apply and PRESERVE a user correction to a service's identity/classification.
pub fn set_service_correction(
    conn: &Connection,
    id: &str,
    provider: Option<&str>,
    api_name: Option<&str>,
    notes: Option<&str>,
    classification: Option<ServiceClass>,
) -> Result<()> {
    conn.execute(
        "UPDATE observed_api_services SET
            user_provider = COALESCE(?2, user_provider),
            user_api_name = COALESCE(?3, user_api_name),
            user_notes = COALESCE(?4, user_notes),
            classification = COALESCE(?5, classification),
            is_internal = CASE WHEN ?5 IS NULL THEN is_internal ELSE (?5 = 'internal') END,
            confirmed = 1
         WHERE id = ?1",
        params![
            id,
            provider,
            api_name,
            notes,
            classification.map(|c| c.as_str())
        ],
    )?;
    Ok(())
}

// --- Endpoints -------------------------------------------------------------

/// Find-or-create the endpoint row. Returns `(endpoint_id, previously_known)`.
pub fn upsert_endpoint(
    conn: &Connection,
    service_id: &str,
    method: HttpMethod,
    path_template: &str,
    confidence: Confidence,
    now: &str,
) -> Result<(String, bool)> {
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM observed_endpoints
             WHERE service_id = ?1 AND method = ?2 AND path_template = ?3",
            params![service_id, method.as_str(), path_template],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        conn.execute(
            "UPDATE observed_endpoints SET last_seen_at = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        return Ok((id, true));
    }
    let id = new_id();
    conn.execute(
        "INSERT INTO observed_endpoints
            (id, service_id, method, path_template, template_confidence, first_seen_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(service_id, method, path_template)
            DO UPDATE SET last_seen_at = excluded.last_seen_at",
        params![id, service_id, method.as_str(), path_template, confidence.label(), now],
    )?;
    let resolved: String = conn.query_row(
        "SELECT id FROM observed_endpoints
         WHERE service_id = ?1 AND method = ?2 AND path_template = ?3",
        params![service_id, method.as_str(), path_template],
        |r| r.get(0),
    )?;
    let created = resolved == id;
    Ok((resolved, !created))
}

pub fn list_endpoints_for_service(
    conn: &Connection,
    service_id: &str,
) -> Result<Vec<ObservedEndpointRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, service_id, method, path_template, template_confidence, first_seen_at, last_seen_at
         FROM observed_endpoints WHERE service_id = ?1 ORDER BY last_seen_at DESC",
    )?;
    let rows = stmt.query_map([service_id], |r| {
        Ok(ObservedEndpointRow {
            id: r.get(0)?,
            service_id: r.get(1)?,
            method: r.get(2)?,
            path_template: r.get(3)?,
            template_confidence: r.get(4)?,
            first_seen_at: r.get(5)?,
            last_seen_at: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

// --- Request events (the hot write path) -----------------------------------

/// Insert one sanitized request event. `status_class` and `outcome` are
/// derived here from the metadata; the caller never supplies free-form text.
#[allow(clippy::too_many_arguments)]
pub fn insert_request_event(
    conn: &Connection,
    session_id: &str,
    project_id: &str,
    service_id: &str,
    endpoint_id: Option<&str>,
    at: &str,
    req: &ObservedRequest,
    previously_known: bool,
) -> Result<String> {
    let id = new_id();
    conn.execute(
        "INSERT INTO runtime_request_events (
            id, session_id, project_id, service_id, endpoint_id, at, host, port, method,
            path_template, template_confidence, status_code, status_class, outcome, latency_ms,
            request_bytes, response_bytes, req_content_kind, resp_content_kind, had_authorization,
            protocol, observation_source, transport_error, previously_known)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)",
        params![
            id,
            session_id,
            project_id,
            service_id,
            endpoint_id,
            at,
            req.host,
            i64::from(req.port),
            req.method.as_str(),
            req.path_template,
            req.template_confidence.label(),
            req.status_code.map(i64::from),
            req.status_class().as_str(),
            req.outcome().as_str(),
            req.latency_ms,
            req.request_bytes,
            req.response_bytes,
            req.req_content_kind.map(|k| k.as_str()),
            req.resp_content_kind.map(|k| k.as_str()),
            req.had_authorization as i64,
            req.protocol.as_str(),
            req.observation_source.as_str(),
            req.transport_error.as_str(),
            previously_known as i64,
        ],
    )?;
    Ok(id)
}

const EVENT_COLS: &str = "at, host, method, path_template, status_code, outcome, latency_ms, \
     request_bytes, response_bytes, protocol, observation_source, attribution_confidence";

fn row_to_event(r: &Row<'_>) -> rusqlite::Result<RuntimeEventRow> {
    Ok(RuntimeEventRow {
        at: r.get(0)?,
        host: r.get(1)?,
        method: r.get(2)?,
        path_template: r.get(3)?,
        status_code: r.get(4)?,
        outcome: r.get(5)?,
        latency_ms: r.get(6)?,
        request_bytes: r.get(7)?,
        response_bytes: r.get(8)?,
        protocol: r.get(9)?,
        observation_source: r.get(10)?,
        attribution_confidence: r.get(11)?,
    })
}

pub fn recent_events_for_service(
    conn: &Connection,
    service_id: &str,
    limit: u32,
) -> Result<Vec<RuntimeEventRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {EVENT_COLS} FROM runtime_request_events
         WHERE service_id = ?1 ORDER BY at DESC LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![service_id, limit], row_to_event)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn recent_events_for_session(
    conn: &Connection,
    session_id: &str,
    limit: u32,
) -> Result<Vec<RuntimeEventRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {EVENT_COLS} FROM runtime_request_events
         WHERE session_id = ?1 ORDER BY at DESC LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![session_id, limit], row_to_event)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

// --- Sessions --------------------------------------------------------------

pub struct NewSession<'a> {
    pub project_id: &'a str,
    pub mode: ObservationMode,
    pub source: &'a str,
    pub command: &'a str,
    pub credential_names: &'a [String],
}

pub fn insert_session(conn: &Connection, new: &NewSession<'_>) -> Result<String> {
    let id = new_id();
    conn.execute(
        "INSERT INTO observation_sessions
            (id, project_id, mode, source, status, command, credential_names, started_at)
         VALUES (?1, ?2, ?3, ?4, 'running', ?5, ?6, ?7)",
        params![
            id,
            new.project_id,
            new.mode.as_str(),
            new.source,
            new.command,
            new.credential_names.join(","),
            clock::now_rfc3339(),
        ],
    )?;
    Ok(id)
}

/// Record the launched child's identity and the proxy port for this session.
pub fn set_session_runtime(
    conn: &Connection,
    session_id: &str,
    pid: Option<u32>,
    proc_identity: Option<&str>,
    proxy_port: Option<u16>,
    runtime_detected: Option<&str>,
    trust_level: Option<TrustLevel>,
) -> Result<()> {
    conn.execute(
        "UPDATE observation_sessions SET
            pid = COALESCE(?2, pid),
            proc_identity = COALESCE(?3, proc_identity),
            proxy_port = COALESCE(?4, proxy_port),
            runtime_detected = COALESCE(?5, runtime_detected),
            trust_level = COALESCE(?6, trust_level)
         WHERE id = ?1",
        params![
            session_id,
            pid.map(i64::from),
            proc_identity,
            proxy_port.map(i64::from),
            runtime_detected,
            trust_level.map(|t| t.as_str()),
        ],
    )?;
    Ok(())
}

pub fn set_partial_coverage(conn: &Connection, session_id: &str, partial: bool) -> Result<()> {
    conn.execute(
        "UPDATE observation_sessions SET partial_coverage = ?2 WHERE id = ?1",
        params![session_id, partial as i64],
    )?;
    Ok(())
}

/// Mark a session completed with the child's exit code. Only affects a still-
/// running session (an interrupted session is never overwritten to completed).
pub fn finish_session(conn: &Connection, session_id: &str, exit_code: Option<i32>) -> Result<()> {
    conn.execute(
        "UPDATE observation_sessions SET status = 'completed', ended_at = ?2, exit_code = ?3
         WHERE id = ?1 AND status = 'running'",
        params![session_id, clock::now_rfc3339(), exit_code.map(i64::from)],
    )?;
    Ok(())
}

/// Honestly mark a session interrupted with a machine-readable reason.
pub fn interrupt_session(conn: &Connection, session_id: &str, reason: &str) -> Result<()> {
    conn.execute(
        "UPDATE observation_sessions
         SET status = 'interrupted', interrupt_reason = ?2, ended_at = COALESCE(ended_at, ?3)
         WHERE id = ?1 AND status = 'running'",
        params![session_id, reason, clock::now_rfc3339()],
    )?;
    Ok(())
}

const SESSION_COLS: &str = "id, project_id, mode, source, status, interrupt_reason, command, \
     credential_names, runtime_detected, trust_level, partial_coverage, proxy_port, pid, \
     started_at, ended_at, exit_code";

fn row_to_session(r: &Row<'_>) -> rusqlite::Result<ObservationSessionRow> {
    Ok(ObservationSessionRow {
        id: r.get(0)?,
        project_id: r.get(1)?,
        mode: r.get(2)?,
        source: r.get(3)?,
        status: r.get(4)?,
        interrupt_reason: r.get(5)?,
        command: r.get(6)?,
        credential_names: r.get(7)?,
        runtime_detected: r.get(8)?,
        trust_level: r.get(9)?,
        partial_coverage: r.get::<_, i64>(10)? != 0,
        proxy_port: r.get(11)?,
        pid: r.get(12)?,
        started_at: r.get(13)?,
        ended_at: r.get(14)?,
        exit_code: r.get(15)?,
        request_count: r.get(16)?,
        error_count: r.get(17)?,
    })
}

/// The correlated request/error counters appended to every session select.
const SESSION_COUNTS: &str = "(SELECT COUNT(*) FROM runtime_request_events e WHERE e.session_id = s.id), \
     (SELECT COUNT(*) FROM runtime_request_events e WHERE e.session_id = s.id \
        AND e.outcome != 'success')";

pub fn list_sessions(
    conn: &Connection,
    project_id: Option<&str>,
    limit: u32,
) -> Result<Vec<ObservationSessionRow>> {
    let base = format!(
        "SELECT {SESSION_COLS}, {SESSION_COUNTS} FROM observation_sessions s"
    );
    let mut out = Vec::new();
    match project_id {
        Some(pid) => {
            let mut stmt = conn.prepare(&format!(
                "{base} WHERE s.project_id = ?1 ORDER BY s.started_at DESC LIMIT ?2"
            ))?;
            for row in stmt.query_map(params![pid, limit], row_to_session)? {
                out.push(row?);
            }
        }
        None => {
            let mut stmt =
                conn.prepare(&format!("{base} ORDER BY s.started_at DESC LIMIT ?1"))?;
            for row in stmt.query_map([limit], row_to_session)? {
                out.push(row?);
            }
        }
    }
    Ok(out)
}

pub fn get_session(conn: &Connection, id: &str) -> Result<Option<ObservationSessionRow>> {
    Ok(conn
        .query_row(
            &format!("SELECT {SESSION_COLS}, {SESSION_COUNTS} FROM observation_sessions s WHERE s.id = ?1"),
            [id],
            row_to_session,
        )
        .optional()?)
}

/// Resolve a session by full id or unambiguous prefix.
pub fn resolve_session(conn: &Connection, ident: &str) -> Result<String> {
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM observation_sessions WHERE id = ?1",
            [ident],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        return Ok(id);
    }
    let mut stmt =
        conn.prepare("SELECT id FROM observation_sessions WHERE id LIKE ?1")?;
    let ids: Vec<String> = stmt
        .query_map([format!("{ident}%")], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<_>>()?;
    match ids.len() {
        0 => Err(crate::error::CoreError::NotFound {
            kind: "observation session",
            ident: ident.to_string(),
        }),
        1 => Ok(ids.into_iter().next().expect("len checked")),
        _ => Err(crate::error::CoreError::Ambiguous {
            kind: "observation session",
            ident: ident.to_string(),
        }),
    }
}

pub fn delete_session(conn: &Connection, session_id: &str) -> Result<()> {
    // Cascades to events, attributions, compatibility results via FK.
    conn.execute(
        "DELETE FROM observation_sessions WHERE id = ?1",
        [session_id],
    )?;
    Ok(())
}

/// Close any `running` session whose recording process is definitively gone,
/// marking it interrupted with `launcher_gone`. Reuses the POSIX `ps -p`
/// liveness convention (exit code exactly 1 = no such process). Unix only.
pub fn sweep_orphaned_sessions(conn: &Connection) -> Result<usize> {
    #[cfg(unix)]
    {
        let rows: Vec<(String, Option<i64>)> = conn
            .prepare("SELECT id, pid FROM observation_sessions WHERE status = 'running'")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut closed = 0;
        for (id, pid) in rows {
            let Some(pid) = pid else { continue };
            if pid <= 0 {
                continue;
            }
            let probe = std::process::Command::new("ps")
                .args(["-p", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if matches!(probe, Ok(s) if s.code() == Some(1)) {
                interrupt_session(conn, &id, "launcher_gone")?;
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

// --- Attribution rollup ----------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn upsert_attribution(
    conn: &Connection,
    session_id: &str,
    credential_id: &str,
    service_id: &str,
    request_count: i64,
    confidence: AttributionConfidence,
    evidence: &str,
    credential_version: Option<i64>,
    used_current_version: Option<bool>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO credential_traffic_attributions
            (session_id, credential_id, service_id, request_count, confidence, evidence,
             credential_version, used_current_version, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(session_id, credential_id, service_id) DO UPDATE SET
            request_count = excluded.request_count, confidence = excluded.confidence,
            evidence = excluded.evidence, credential_version = excluded.credential_version,
            used_current_version = excluded.used_current_version, updated_at = excluded.updated_at",
        params![
            session_id,
            credential_id,
            service_id,
            request_count,
            confidence.as_str(),
            evidence,
            credential_version,
            used_current_version.map(|b| b as i64),
            clock::now_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Backfill the credential attribution onto a session's events (so per-event
/// queries can show attribution) for one service.
pub fn set_event_attribution_for_session_service(
    conn: &Connection,
    session_id: &str,
    service_id: &str,
    credential_id: &str,
    confidence: AttributionConfidence,
    credential_version: Option<i64>,
    used_current_version: Option<bool>,
) -> Result<usize> {
    Ok(conn.execute(
        "UPDATE runtime_request_events
         SET credential_id = ?3, attribution_confidence = ?4,
             credential_version = ?5, used_current_version = ?6
         WHERE session_id = ?1 AND service_id = ?2",
        params![
            session_id,
            service_id,
            credential_id,
            confidence.as_str(),
            credential_version,
            used_current_version.map(|b| b as i64),
        ],
    )?)
}

fn row_to_attribution(r: &Row<'_>) -> rusqlite::Result<CredentialAttributionRow> {
    Ok(CredentialAttributionRow {
        session_id: r.get(0)?,
        credential_id: r.get(1)?,
        service_id: r.get(2)?,
        host: r.get(3)?,
        request_count: r.get(4)?,
        confidence: r.get(5)?,
        evidence: r.get(6)?,
        credential_version: r.get(7)?,
        used_current_version: r.get::<_, Option<i64>>(8)?.map(|v| v != 0),
    })
}

const ATTR_COLS: &str = "a.session_id, a.credential_id, a.service_id, s.host, a.request_count, \
     a.confidence, a.evidence, a.credential_version, a.used_current_version";

pub fn session_attributions(
    conn: &Connection,
    session_id: &str,
) -> Result<Vec<CredentialAttributionRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {ATTR_COLS} FROM credential_traffic_attributions a
         JOIN observed_api_services s ON s.id = a.service_id
         WHERE a.session_id = ?1 ORDER BY a.request_count DESC"
    ))?;
    let rows = stmt.query_map([session_id], row_to_attribution)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn credential_attributions(
    conn: &Connection,
    credential_id: &str,
    limit: u32,
) -> Result<Vec<CredentialAttributionRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {ATTR_COLS} FROM credential_traffic_attributions a
         JOIN observed_api_services s ON s.id = a.service_id
         WHERE a.credential_id = ?1 ORDER BY a.updated_at DESC LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![credential_id, limit], row_to_attribution)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

// --- Compatibility results -------------------------------------------------

pub fn record_compat(
    conn: &Connection,
    session_id: &str,
    check: &str,
    status: &str,
    detail: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO observation_compatibility_results (session_id, check_name, status, detail, at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(session_id, check_name) DO UPDATE SET
            status = excluded.status, detail = excluded.detail, at = excluded.at",
        params![session_id, check, status, detail, clock::now_rfc3339()],
    )?;
    Ok(())
}

pub fn session_compat(conn: &Connection, session_id: &str) -> Result<Vec<CompatibilityResultRow>> {
    let mut stmt = conn.prepare(
        "SELECT session_id, check_name, status, detail
         FROM observation_compatibility_results WHERE session_id = ?1 ORDER BY check_name",
    )?;
    let rows = stmt.query_map([session_id], |r| {
        Ok(CompatibilityResultRow {
            session_id: r.get(0)?,
            check: r.get(1)?,
            status: r.get(2)?,
            detail: r.get(3)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

// --- Certificate state (low-level row I/O; the vault owns the crypto) -------

/// The stored CA state, including the encrypted private key. NOT `Serialize`:
/// the ciphertext blob never crosses the IPC boundary. Use [`CertStatus`] for
/// display.
#[derive(Debug, Clone)]
pub struct CertStateRow {
    pub ca_cert_pem: String,
    pub key_ciphertext: Vec<u8>,
    pub fingerprint_sha256: String,
    pub serial: String,
    pub created_at: String,
    pub not_after: String,
    pub system_trust: String,
    pub system_trust_at: Option<String>,
}

/// Non-secret certificate status for the UI/CLI (no key material, no ciphertext).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertStatus {
    pub present: bool,
    pub fingerprint_sha256: Option<String>,
    pub serial: Option<String>,
    pub created_at: Option<String>,
    pub not_after: Option<String>,
    pub system_trust: String,
    pub system_trust_at: Option<String>,
}

pub fn cert_state_get(conn: &Connection) -> Result<Option<CertStateRow>> {
    Ok(conn
        .query_row(
            "SELECT ca_cert_pem, key_ciphertext, fingerprint_sha256, serial, created_at,
                    not_after, system_trust, system_trust_at
             FROM observe_certificate_state WHERE id = 'ca'",
            [],
            |r| {
                Ok(CertStateRow {
                    ca_cert_pem: r.get(0)?,
                    key_ciphertext: r.get(1)?,
                    fingerprint_sha256: r.get(2)?,
                    serial: r.get(3)?,
                    created_at: r.get(4)?,
                    not_after: r.get(5)?,
                    system_trust: r.get(6)?,
                    system_trust_at: r.get(7)?,
                })
            },
        )
        .optional()?)
}

pub fn cert_status(conn: &Connection) -> Result<CertStatus> {
    match cert_state_get(conn)? {
        Some(row) => Ok(CertStatus {
            present: true,
            fingerprint_sha256: Some(row.fingerprint_sha256),
            serial: Some(row.serial),
            created_at: Some(row.created_at),
            not_after: Some(row.not_after),
            system_trust: row.system_trust,
            system_trust_at: row.system_trust_at,
        }),
        None => Ok(CertStatus {
            present: false,
            fingerprint_sha256: None,
            serial: None,
            created_at: None,
            not_after: None,
            system_trust: "absent".to_string(),
            system_trust_at: None,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn cert_state_set(
    conn: &Connection,
    ca_cert_pem: &str,
    key_ciphertext: &[u8],
    fingerprint_sha256: &str,
    serial: &str,
    created_at: &str,
    not_after: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO observe_certificate_state
            (id, ca_cert_pem, key_ciphertext, fingerprint_sha256, serial, created_at, not_after,
             system_trust)
         VALUES ('ca', ?1, ?2, ?3, ?4, ?5, ?6, 'absent')
         ON CONFLICT(id) DO UPDATE SET
            ca_cert_pem = excluded.ca_cert_pem, key_ciphertext = excluded.key_ciphertext,
            fingerprint_sha256 = excluded.fingerprint_sha256, serial = excluded.serial,
            created_at = excluded.created_at, not_after = excluded.not_after",
        params![ca_cert_pem, key_ciphertext, fingerprint_sha256, serial, created_at, not_after],
    )?;
    Ok(())
}

pub fn cert_state_clear(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM observe_certificate_state WHERE id = 'ca'", [])?;
    Ok(())
}

pub fn cert_set_system_trust(conn: &Connection, status: &str, at: Option<&str>) -> Result<()> {
    conn.execute(
        "UPDATE observe_certificate_state SET system_trust = ?1, system_trust_at = ?2 WHERE id = 'ca'",
        params![status, at],
    )?;
    Ok(())
}

// --- Internal allowlist ----------------------------------------------------

pub fn allowlist_add(
    conn: &Connection,
    project_id: &str,
    host: &str,
    port: u16,
    note: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO observe_internal_allowlist (project_id, host, port, note, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(project_id, host, port) DO UPDATE SET note = excluded.note",
        params![project_id, host.trim().to_ascii_lowercase(), i64::from(port), note, clock::now_rfc3339()],
    )?;
    Ok(())
}

pub fn allowlist_remove(conn: &Connection, project_id: &str, host: &str, port: u16) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM observe_internal_allowlist WHERE project_id = ?1 AND host = ?2 AND port = ?3",
        params![project_id, host.trim().to_ascii_lowercase(), i64::from(port)],
    )?;
    Ok(n > 0)
}

/// `(host, port, note)` entries for a project.
pub fn allowlist_for_project(
    conn: &Connection,
    project_id: &str,
) -> Result<Vec<(String, u16, String)>> {
    let mut stmt = conn.prepare(
        "SELECT host, port, note FROM observe_internal_allowlist WHERE project_id = ?1 ORDER BY host, port",
    )?;
    let rows = stmt.query_map([project_id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u16, r.get::<_, String>(2)?))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

// --- Bulk deletion (reauthentication-gated at the vault layer) --------------

/// Delete all observability data for one project (sessions + their events/
/// attributions/compat cascade). Services are host-scoped and shared, so they
/// are left as inventory; use [`delete_all`] to remove everything.
pub fn delete_project_data(conn: &Connection, project_id: &str) -> Result<()> {
    conn.execute("DELETE FROM observation_sessions WHERE project_id = ?1", [project_id])?;
    conn.execute("DELETE FROM runtime_request_events WHERE project_id = ?1", [project_id])?;
    conn.execute("DELETE FROM runtime_metric_buckets WHERE project_id = ?1", [project_id])?;
    conn.execute("DELETE FROM observe_internal_allowlist WHERE project_id = ?1", [project_id])?;
    Ok(())
}

/// Delete ALL observability data (events, buckets, sessions, endpoints,
/// services, attributions, compat, baselines, allowlist). Does NOT touch the
/// certificate state — removing the CA is a separate, explicit action.
pub fn delete_all(conn: &Connection) -> Result<()> {
    for table in [
        "runtime_request_events",
        "runtime_metric_buckets",
        "credential_traffic_attributions",
        "observation_compatibility_results",
        "observation_sessions",
        "observed_endpoints",
        "observed_api_services",
        "observe_internal_allowlist",
        "runtime_alert_baselines",
    ] {
        conn.execute(&format!("DELETE FROM {table}"), [])?;
    }
    Ok(())
}

// --- vault_meta helpers scoped to observability ----------------------------

pub fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM vault_meta WHERE key = ?1", [key], |r| {
            r.get::<_, String>(0)
        })
        .optional()?)
}

pub fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod testutil {
    use rusqlite::{params, Connection};

    /// A minimal project row satisfying the FK + NOT NULL constraints, without
    /// going through the vault (tests only).
    pub fn seed_project(conn: &Connection, id: &str, name: &str) {
        conn.execute(
            "INSERT INTO projects (id, name, created_at, updated_at, wrapped_project_key, key_wrap_mode)
             VALUES (?1, ?2, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', X'00', 'vault')",
            params![id, name],
        )
        .unwrap();
    }

    /// A minimal credential row (FK target for attribution tests).
    pub fn seed_credential(conn: &Connection, id: &str, project_id: &str, provider: &str, name: &str) {
        conn.execute(
            "INSERT INTO credentials
                (id, project_id, provider, name, ciphertext, fingerprint, masked_value, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, X'00', X'00', '••••', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            params![id, project_id, provider, name],
        )
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        conn.pragma_update(None, "foreign_keys", 1).unwrap();
        conn
    }

    fn sample_request(host: &str, status: u16) -> ObservedRequest {
        ObservedRequest {
            host: host.to_string(),
            port: 443,
            method: HttpMethod::Get,
            path_template: "/v1/models".to_string(),
            template_confidence: Confidence::High,
            status_code: Some(status),
            req_content_kind: None,
            resp_content_kind: Some(ContentKind::Json),
            had_authorization: true,
            latency_ms: Some(42),
            request_bytes: Some(100),
            response_bytes: Some(2000),
            protocol: Protocol::Http11,
            observation_source: ObservationSource::Intercept,
            transport_error: TransportError::None,
        }
    }

    #[test]
    fn service_and_endpoint_upsert_track_previously_known() {
        let conn = mem();
        let now = clock::now_rfc3339();
        let (svc, known1) = upsert_service(&conn, "api.openai.com", Some("openai"), false, &now).unwrap();
        assert!(!known1, "first observation is not previously known");
        let (svc2, known2) = upsert_service(&conn, "API.OpenAI.com", None, false, &now).unwrap();
        assert_eq!(svc, svc2, "host match is case-insensitive");
        assert!(known2, "second observation is previously known");

        let (ep, ek1) = upsert_endpoint(&conn, &svc, HttpMethod::Get, "/v1/models", Confidence::High, &now).unwrap();
        assert!(!ek1);
        let (ep2, ek2) = upsert_endpoint(&conn, &svc, HttpMethod::Get, "/v1/models", Confidence::High, &now).unwrap();
        assert_eq!(ep, ep2);
        assert!(ek2);
    }

    #[test]
    fn full_session_write_and_query() {
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        let sid = insert_session(
            &conn,
            &NewSession {
                project_id: "p1",
                mode: ObservationMode::Metadata,
                source: "cli_run",
                command: "node server.js",
                credential_names: &["OPENAI_API_KEY".to_string()],
            },
        )
        .unwrap();

        let now = clock::now_rfc3339();
        let (svc, _) = upsert_service(&conn, "api.openai.com", Some("openai"), false, &now).unwrap();
        let (ep, known) = upsert_endpoint(&conn, &svc, HttpMethod::Get, "/v1/models", Confidence::High, &now).unwrap();
        insert_request_event(&conn, &sid, "p1", &svc, Some(&ep), &now, &sample_request("api.openai.com", 200), known).unwrap();
        insert_request_event(&conn, &sid, "p1", &svc, Some(&ep), &now, &sample_request("api.openai.com", 401), known).unwrap();

        let session = get_session(&conn, &sid).unwrap().unwrap();
        assert_eq!(session.request_count, 2);
        assert_eq!(session.error_count, 1, "the 401 is an error, the 200 is not");
        assert_eq!(session.status, "running");

        let events = recent_events_for_session(&conn, &sid, 10).unwrap();
        assert_eq!(events.len(), 2);
        // metadata only — the event row exposes no body/header/query field
        let json = serde_json::to_string(&events).unwrap();
        assert!(!json.contains("Authorization"));
        assert!(!json.contains("?"));

        finish_session(&conn, &sid, Some(0)).unwrap();
        assert_eq!(get_session(&conn, &sid).unwrap().unwrap().status, "completed");
    }

    #[test]
    fn interrupt_is_not_overwritten_by_finish() {
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        let sid = insert_session(&conn, &NewSession { project_id: "p1", mode: ObservationMode::Metadata, source: "cli_run", command: "x", credential_names: &[] }).unwrap();
        interrupt_session(&conn, &sid, "vault_locked").unwrap();
        finish_session(&conn, &sid, Some(0)).unwrap();
        let s = get_session(&conn, &sid).unwrap().unwrap();
        assert_eq!(s.status, "interrupted");
        assert_eq!(s.interrupt_reason.as_deref(), Some("vault_locked"));
    }

    #[test]
    fn attribution_rollup_and_backfill() {
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        testutil::seed_credential(&conn, "c1", "p1", "openai", "openai-main");
        let sid = insert_session(&conn, &NewSession { project_id: "p1", mode: ObservationMode::Metadata, source: "cli_run", command: "x", credential_names: &[] }).unwrap();
        let now = clock::now_rfc3339();
        let (svc, _) = upsert_service(&conn, "api.openai.com", Some("openai"), false, &now).unwrap();
        let (ep, k) = upsert_endpoint(&conn, &svc, HttpMethod::Get, "/v1/models", Confidence::High, &now).unwrap();
        insert_request_event(&conn, &sid, "p1", &svc, Some(&ep), &now, &sample_request("api.openai.com", 200), k).unwrap();

        upsert_attribution(&conn, &sid, "c1", &svc, 1, AttributionConfidence::Confirmed, "injected credential", Some(3), Some(true)).unwrap();
        let updated = set_event_attribution_for_session_service(&conn, &sid, &svc, "c1", AttributionConfidence::Confirmed, Some(3), Some(true)).unwrap();
        assert_eq!(updated, 1);

        let attrs = session_attributions(&conn, &sid).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].confidence, "confirmed");
        assert_eq!(attrs[0].credential_version, Some(3));
        assert_eq!(credential_attributions(&conn, "c1", 10).unwrap().len(), 1);
    }

    #[test]
    fn deleting_project_cascades_but_keeps_service_inventory() {
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        let sid = insert_session(&conn, &NewSession { project_id: "p1", mode: ObservationMode::Metadata, source: "cli_run", command: "x", credential_names: &[] }).unwrap();
        let now = clock::now_rfc3339();
        let (svc, _) = upsert_service(&conn, "api.openai.com", None, false, &now).unwrap();
        let (ep, k) = upsert_endpoint(&conn, &svc, HttpMethod::Get, "/v1/models", Confidence::High, &now).unwrap();
        insert_request_event(&conn, &sid, "p1", &svc, Some(&ep), &now, &sample_request("api.openai.com", 200), k).unwrap();

        delete_project_data(&conn, "p1").unwrap();
        assert!(list_sessions(&conn, Some("p1"), 10).unwrap().is_empty());
        let events: i64 = conn.query_row("SELECT COUNT(*) FROM runtime_request_events", [], |r| r.get(0)).unwrap();
        assert_eq!(events, 0);
        // inventory (the host) remains
        assert_eq!(list_services(&conn).unwrap().len(), 1);

        delete_all(&conn).unwrap();
        assert!(list_services(&conn).unwrap().is_empty());
    }

    #[test]
    fn allowlist_roundtrip() {
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        allowlist_add(&conn, "p1", "localhost", 3000, "local api").unwrap();
        allowlist_add(&conn, "p1", "10.0.0.5", 8080, "internal").unwrap();
        let list = allowlist_for_project(&conn, "p1").unwrap();
        assert_eq!(list.len(), 2);
        assert!(allowlist_remove(&conn, "p1", "localhost", 3000).unwrap());
        assert_eq!(allowlist_for_project(&conn, "p1").unwrap().len(), 1);
    }

    #[test]
    fn cert_state_roundtrip_no_ciphertext_in_status() {
        let conn = mem();
        cert_state_set(&conn, "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----", b"CIPHERTEXTBLOB", "ab:cd", "0011", "2026-01-01T00:00:00Z", "2029-01-01T00:00:00Z").unwrap();
        let status = cert_status(&conn).unwrap();
        assert!(status.present);
        assert_eq!(status.fingerprint_sha256.as_deref(), Some("ab:cd"));
        let json = serde_json::to_string(&status).unwrap();
        assert!(!json.contains("CIPHERTEXTBLOB"), "ciphertext must not be in the status DTO");
        cert_set_system_trust(&conn, "installed", Some("2026-07-24T00:00:00Z")).unwrap();
        assert_eq!(cert_status(&conn).unwrap().system_trust, "installed");
        cert_state_clear(&conn).unwrap();
        assert!(!cert_status(&conn).unwrap().present);
    }
}
