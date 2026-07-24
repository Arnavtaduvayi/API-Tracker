//! Observability alert rules over locally observed traffic.
//!
//! Every rule reads only stored `runtime_*` rows (no network), requires a
//! minimum sample size, and produces a [`crate::alerts::NewAlert`] fed through
//! the existing alert engine (dedup + lifecycle + delivery). No rule claims a
//! credential is compromised — they describe the observation and what to
//! check. Rules are wired into [`crate::vault::UnlockedVault::run_monitor`].

use crate::alerts::{AlertKind, NewAlert, Severity};
use crate::error::Result;
use crate::providers::Confidence;
use rusqlite::{params, Connection};

fn days_ago(now: time::OffsetDateTime, days: i64) -> String {
    crate::clock::to_rfc3339(now - time::Duration::days(days))
}
fn hours_ago(now: time::OffsetDateTime, hours: i64) -> String {
    crate::clock::to_rfc3339(now - time::Duration::hours(hours))
}

/// The alert kinds this module manages (for monitor auto-resolution).
pub fn managed_kinds() -> Vec<AlertKind> {
    vec![
        AlertKind::RuntimeAuthFailures,
        AlertKind::RuntimeForbidden,
        AlertKind::RuntimeRateLimited,
        AlertKind::RuntimeServerErrors,
        AlertKind::RuntimeTransportFailures,
        AlertKind::RuntimeTlsFailures,
        AlertKind::RuntimeApiInactive,
        AlertKind::RuntimeNewApi,
        AlertKind::RuntimeUnknownApi,
        AlertKind::RuntimeOldCredentialVersion,
        AlertKind::RuntimeRevokedCredentialInUse,
        AlertKind::RuntimeSharedCredential,
    ]
}

/// Evaluate every observability rule. `label_of` maps a credential id to its
/// display label (project/name).
pub fn alerts(
    conn: &Connection,
    now: time::OffsetDateTime,
    label_of: &dyn Fn(&str) -> String,
) -> Result<Vec<NewAlert>> {
    let observed = crate::clock::to_rfc3339(now);
    let mut out = Vec::new();

    status_spikes(conn, &observed, &hours_ago(now, 1), &mut out)?;
    new_and_unknown_apis(conn, &observed, &days_ago(now, 1), &mut out)?;
    inactive_apis(conn, &observed, &days_ago(now, 3), &days_ago(now, 7), &mut out)?;
    credential_rules(conn, &observed, label_of, &mut out)?;

    Ok(out)
}

fn status_spikes(
    conn: &Connection,
    observed: &str,
    since: &str,
    out: &mut Vec<NewAlert>,
) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT s.id, s.host, COUNT(*),
                SUM(e.outcome='auth_error'), SUM(e.status_code=403),
                SUM(e.outcome='rate_limited'), SUM(e.outcome='server_error'),
                SUM(e.outcome='transport_error'), SUM(e.outcome='tls_error')
         FROM runtime_request_events e JOIN observed_api_services s ON s.id = e.service_id
         WHERE e.at >= ?1 GROUP BY e.service_id",
    )?;
    let rows: Vec<(String, String, i64, i64, i64, i64, i64, i64, i64)> = stmt
        .query_map([since], |r| {
            Ok((
                r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;

    for (sid, host, total, auth, forbidden, rate, server5, transport, tls) in rows {
        let push = |out: &mut Vec<NewAlert>, kind: AlertKind, sev: Severity, key: &str, title: String, detail: String, action: &str, conf: Confidence| {
            out.push(NewAlert {
                kind, severity: sev,
                dedup_key: format!("{key}:{sid}"),
                title, detail,
                evidence: format!("service={host} window=last 1h total={total}"),
                confidence: conf,
                recommended_action: action.into(),
                project_id: None, credential_id: None,
                observed_at: observed.to_string(),
            });
        };
        // repeated 401 (>=5 and >=20% of >=10 reqs)
        if auth >= 5 && total >= 10 && auth * 5 >= total {
            push(out, AlertKind::RuntimeAuthFailures, Severity::High, "runtime_auth_failures",
                format!("repeated authentication failures calling {host}"),
                format!("{auth} of {total} requests to {host} in the last hour returned 401. The key may be revoked, rotated at the provider, or wrong."),
                "check the credential at the provider; update or rotate the stored value", Confidence::High);
        }
        if forbidden >= 5 {
            push(out, AlertKind::RuntimeForbidden, Severity::Medium, "runtime_forbidden",
                format!("repeated authorization failures (403) calling {host}"),
                format!("{forbidden} requests to {host} in the last hour returned 403 (forbidden). The credential may lack the required scope/permission."),
                "confirm the credential's permissions/scopes at the provider", Confidence::High);
        }
        if rate >= 3 {
            push(out, AlertKind::RuntimeRateLimited, Severity::Medium, "runtime_rate_limited",
                format!("{host} is rate-limiting your requests"),
                format!("{rate} requests to {host} in the last hour returned 429. Your application is being throttled."),
                "back off / add retry with jitter; check your plan's rate limits", Confidence::High);
        }
        if server5 >= 4 && total >= 20 && server5 * 5 >= total {
            push(out, AlertKind::RuntimeServerErrors, Severity::High, "runtime_server_errors",
                format!("{host} is returning server errors"),
                format!("{server5} of {total} requests to {host} in the last hour returned 5xx. This usually indicates a provider-side problem, not your code."),
                "check the provider's status page; retry idempotent calls", Confidence::High);
        }
        if transport >= 5 && total >= 10 && transport * 10 >= total * 3 {
            push(out, AlertKind::RuntimeTransportFailures, Severity::Medium, "runtime_transport_failures",
                format!("connection failures reaching {host}"),
                format!("{transport} of {total} attempts to {host} in the last hour failed at the transport level (DNS/connect/reset/timeout) — not an HTTP error."),
                "check network connectivity and DNS; the host may be unreachable", Confidence::High);
        }
        if tls >= 3 {
            push(out, AlertKind::RuntimeTlsFailures, Severity::High, "runtime_tls_failures",
                format!("TLS verification failures reaching {host}"),
                format!("{tls} attempts to {host} in the last hour failed upstream TLS verification. This can indicate a network interception or a misconfigured corporate proxy — it is NOT downgraded to a successful request."),
                "verify you are on a trusted network; add your corporate root if required (never disable TLS verification)", Confidence::Medium);
        }
    }
    Ok(())
}

fn new_and_unknown_apis(
    conn: &Connection,
    observed: &str,
    since: &str,
    out: &mut Vec<NewAlert>,
) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT id, host, provider_id FROM observed_api_services WHERE first_seen_at >= ?1",
    )?;
    let rows: Vec<(String, String, Option<String>)> = stmt
        .query_map([since], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (sid, host, provider) in rows {
        match provider {
            Some(p) => out.push(NewAlert {
                kind: AlertKind::RuntimeNewApi,
                severity: Severity::Info,
                dedup_key: format!("runtime_new_api:{sid}"),
                title: format!("new external API first observed: {host}"),
                detail: format!("your application started calling {host} ({p}) in the last 24 hours. New APIs are normal when you added them — this is a visibility notice."),
                evidence: format!("host={host} provider={p} first observed in the last 24h"),
                confidence: Confidence::High,
                recommended_action: "confirm you (or a teammate) introduced this dependency".into(),
                project_id: None, credential_id: None, observed_at: observed.to_string(),
            }),
            None => out.push(NewAlert {
                kind: AlertKind::RuntimeUnknownApi,
                severity: Severity::Medium,
                dedup_key: format!("runtime_unknown_api:{sid}"),
                title: format!("unknown API first observed: {host}"),
                detail: format!("your application started calling {host} — a host Tethra does not recognize as a known provider — in the last 24 hours."),
                evidence: format!("host={host} (unrecognized) first observed in the last 24h"),
                confidence: Confidence::High,
                recommended_action: "confirm this call is expected; classify or name the API in the Monitor view".into(),
                project_id: None, credential_id: None, observed_at: observed.to_string(),
            }),
        }
    }
    Ok(())
}

fn inactive_apis(
    conn: &Connection,
    observed: &str,
    quiet_since: &str,
    established_before: &str,
    out: &mut Vec<NewAlert>,
) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT id, host FROM observed_api_services
         WHERE last_seen_at < ?1 AND first_seen_at < ?2",
    )?;
    let rows: Vec<(String, String)> = stmt
        .query_map(params![quiet_since, established_before], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (sid, host) in rows {
        out.push(NewAlert {
            kind: AlertKind::RuntimeApiInactive,
            severity: Severity::Info,
            dedup_key: format!("runtime_api_inactive:{sid}"),
            title: format!("previously active API is now quiet: {host}"),
            detail: format!("{host} had recorded traffic but nothing in the last 3 days. This may be expected (a feature you stopped using) or a sign that something broke."),
            evidence: format!("host={host} no traffic in 3+ days"),
            confidence: Confidence::Medium,
            recommended_action: "confirm the integration is still meant to be active".into(),
            project_id: None, credential_id: None, observed_at: observed.to_string(),
        });
    }
    Ok(())
}

fn credential_rules(
    conn: &Connection,
    observed: &str,
    label_of: &dyn Fn(&str) -> String,
    out: &mut Vec<NewAlert>,
) -> Result<()> {
    // Old credential version still in use after rotation. Compared LIVE against
    // the credential's current value_version, so it fires when a rotation
    // (days later) advances the version past a still-running session's
    // launch-time version.
    let mut stmt = conn.prepare(
        "SELECT DISTINCT a.credential_id, s.host, a.credential_version
         FROM credential_traffic_attributions a
         JOIN credentials c ON c.id = a.credential_id
         JOIN observed_api_services s ON s.id = a.service_id
         WHERE a.credential_version IS NOT NULL AND a.credential_version < c.value_version
           AND a.confidence IN ('confirmed','high','possible')",
    )?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<i64>>(2)?)))? {
        let (cred, host, ver) = row?;
        let label = label_of(&cred);
        out.push(NewAlert {
            kind: AlertKind::RuntimeOldCredentialVersion,
            severity: Severity::High,
            dedup_key: format!("runtime_old_credential_version:{cred}"),
            title: format!("old credential version still in use: {label}"),
            detail: format!("traffic to {host} was launched with an older version (v{}) of '{label}' than the current stored value. A process started before a rotation is still using the previous key.", ver.unwrap_or(0)),
            evidence: format!("launch_version=v{} < current version; host={host}", ver.unwrap_or(0)),
            confidence: Confidence::High,
            recommended_action: "restart the process so it picks up the rotated value; revoke the old key once nothing uses it".into(),
            project_id: None, credential_id: Some(cred), observed_at: observed.to_string(),
        });
    }

    // Traffic attributed to a credential marked revoked.
    let mut stmt = conn.prepare(
        "SELECT DISTINCT a.credential_id, s.host FROM credential_traffic_attributions a
         JOIN credentials c ON c.id = a.credential_id
         JOIN observed_api_services s ON s.id = a.service_id
         WHERE c.revoked = 1 AND a.confidence IN ('confirmed','high','possible')",
    )?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (cred, host) = row?;
        let label = label_of(&cred);
        out.push(NewAlert {
            kind: AlertKind::RuntimeRevokedCredentialInUse,
            severity: Severity::High,
            dedup_key: format!("runtime_revoked_credential_in_use:{cred}"),
            title: format!("revoked credential still in use: {label}"),
            detail: format!("'{label}' is marked revoked in Tethra, but traffic to {host} was attributed to it. A process may still hold the old value."),
            evidence: format!("credential marked revoked; observed traffic to {host}"),
            confidence: Confidence::High,
            recommended_action: "restart the consuming process; confirm the key is actually revoked at the provider".into(),
            project_id: None, credential_id: Some(cred), observed_at: observed.to_string(),
        });
    }

    // Same credential's traffic across two or more projects.
    let mut stmt = conn.prepare(
        "SELECT a.credential_id, COUNT(DISTINCT sess.project_id)
         FROM credential_traffic_attributions a
         JOIN observation_sessions sess ON sess.id = a.session_id
         WHERE a.confidence IN ('confirmed','high','possible')
         GROUP BY a.credential_id HAVING COUNT(DISTINCT sess.project_id) >= 2",
    )?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
        let (cred, projects) = row?;
        let label = label_of(&cred);
        out.push(NewAlert {
            kind: AlertKind::RuntimeSharedCredential,
            severity: Severity::Medium,
            dedup_key: format!("runtime_shared_credential:{cred}"),
            title: format!("credential used across {projects} projects: {label}"),
            detail: format!("'{label}' has been observed serving traffic in {projects} different projects. Sharing one key across unrelated projects widens the blast radius if it leaks."),
            evidence: format!("distinct projects={projects}"),
            confidence: Confidence::Medium,
            recommended_action: "consider a separate credential per project".into(),
            project_id: None, credential_id: Some(cred), observed_at: observed.to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::runtime::model::*;
    use crate::runtime::store::{self, testutil};

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        conn.pragma_update(None, "foreign_keys", 1).unwrap();
        conn
    }

    fn ev(status: u16, outcome_transport: TransportError) -> ObservedRequest {
        ObservedRequest {
            host: "api.openai.com".into(), port: 443, method: HttpMethod::Post,
            path_template: "/v1/chat".into(), template_confidence: crate::providers::Confidence::High,
            status_code: if outcome_transport.is_failure() { None } else { Some(status) },
            req_content_kind: None, resp_content_kind: None, had_authorization: true,
            latency_ms: Some(20), request_bytes: Some(1), response_bytes: Some(1),
            protocol: Protocol::Http11, observation_source: ObservationSource::Intercept, transport_error: outcome_transport,
        }
    }

    #[test]
    fn repeated_auth_failures_raise_a_high_alert() {
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        let sid = store::insert_session(&conn, &store::NewSession { project_id: "p1", mode: ObservationMode::Metadata, source: "cli_run", command: "x", credential_names: &[] }).unwrap();
        let now_ts = crate::clock::now_rfc3339();
        let (svc, _) = store::upsert_service(&conn, "api.openai.com", Some("openai"), false, &now_ts).unwrap();
        // 8x 401, 4x 200 = 12 total, 8/12 = 66% auth failures
        for _ in 0..8 { store::insert_request_event(&conn, &sid, "p1", &svc, None, &now_ts, &ev(401, TransportError::None), true).unwrap(); }
        for _ in 0..4 { store::insert_request_event(&conn, &sid, "p1", &svc, None, &now_ts, &ev(200, TransportError::None), true).unwrap(); }

        let alerts = alerts(&conn, crate::clock::now(), &|_| "web/openai-main".to_string()).unwrap();
        let auth = alerts.iter().find(|a| a.kind == AlertKind::RuntimeAuthFailures).expect("auth failure alert");
        assert_eq!(auth.severity, Severity::High);
        assert!(auth.detail.contains("401"));
    }

    #[test]
    fn unknown_api_first_seen_raises_alert() {
        let conn = mem();
        let now_ts = crate::clock::now_rfc3339();
        store::upsert_service(&conn, "api.mystery.example", None, false, &now_ts).unwrap();
        let alerts = alerts(&conn, crate::clock::now(), &|_| String::new()).unwrap();
        assert!(alerts.iter().any(|a| a.kind == AlertKind::RuntimeUnknownApi));
    }

    #[test]
    fn old_credential_version_raises_alert() {
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        testutil::seed_credential(&conn, "c1", "p1", "openai", "openai-main");
        let sid = store::insert_session(&conn, &store::NewSession { project_id: "p1", mode: ObservationMode::Metadata, source: "cli_run", command: "x", credential_names: &[] }).unwrap();
        let now_ts = crate::clock::now_rfc3339();
        let (svc, _) = store::upsert_service(&conn, "api.openai.com", Some("openai"), false, &now_ts).unwrap();
        // launched at v1; the credential has since rotated to v3.
        store::upsert_attribution(&conn, &sid, "c1", &svc, 5, AttributionConfidence::Confirmed, "e", Some(1), Some(true)).unwrap();
        conn.execute("UPDATE credentials SET value_version = 3 WHERE id = 'c1'", []).unwrap();
        let alerts = alerts(&conn, crate::clock::now(), &|_| "web/openai-main".to_string()).unwrap();
        assert!(alerts.iter().any(|a| a.kind == AlertKind::RuntimeOldCredentialVersion));
    }
}
