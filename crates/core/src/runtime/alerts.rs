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
    inactive_apis(
        conn,
        &observed,
        &days_ago(now, 3),
        &days_ago(now, 7),
        &mut out,
    )?;
    credential_rules(conn, &observed, now, label_of, &mut out)?;

    Ok(out)
}

/// One service's outcome counts over the recent window.
struct SpikeRow {
    sid: String,
    host: String,
    total: i64,
    auth: i64,
    forbidden: i64,
    rate: i64,
    server5: i64,
    transport: i64,
    tls: i64,
}

fn status_spikes(
    conn: &Connection,
    observed: &str,
    since: &str,
    out: &mut Vec<NewAlert>,
) -> Result<()> {
    let mut stmt = conn.prepare(
        // COALESCE every SUM to 0: SUM over an all-NULL group returns NULL, and
        // SUM(status_code=403) is NULL for a host whose last-hour events are all
        // transport failures / opaque tunnels (status_code NULL). Reading that
        // NULL as i64 errored (InvalidColumnType) and aborted the ENTIRE monitor
        // cycle before auto-resolution ran. The transport-failure count also
        // excludes SUCCESSFUL opaque CONNECT tunnels: those record outcome=
        // 'transport_error' with transport_error='none' (a model quirk), so
        // without the `transport_error <> 'none'` guard a normal h2-only session
        // produced a false 'connection failures' alert.
        "SELECT s.id, s.host, COUNT(*),
                COALESCE(SUM(e.outcome='auth_error'),0), COALESCE(SUM(e.status_code=403),0),
                COALESCE(SUM(e.outcome='rate_limited'),0), COALESCE(SUM(e.outcome='server_error'),0),
                COALESCE(SUM(e.outcome='transport_error' AND e.transport_error <> 'none'),0),
                COALESCE(SUM(e.outcome='tls_error'),0)
         FROM runtime_request_events e JOIN observed_api_services s ON s.id = e.service_id
         WHERE e.at >= ?1 GROUP BY e.service_id",
    )?;
    let rows: Vec<SpikeRow> = stmt
        .query_map([since], |r| {
            Ok(SpikeRow {
                sid: r.get(0)?,
                host: r.get(1)?,
                total: r.get(2)?,
                auth: r.get(3)?,
                forbidden: r.get(4)?,
                rate: r.get(5)?,
                server5: r.get(6)?,
                transport: r.get(7)?,
                tls: r.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;

    for SpikeRow {
        sid,
        host,
        total,
        auth,
        forbidden,
        rate,
        server5,
        transport,
        tls,
    } in rows
    {
        let push = |out: &mut Vec<NewAlert>,
                    kind: AlertKind,
                    sev: Severity,
                    key: &str,
                    title: String,
                    detail: String,
                    action: &str,
                    conf: Confidence| {
            out.push(NewAlert {
                kind,
                severity: sev,
                dedup_key: format!("{key}:{sid}"),
                title,
                detail,
                evidence: format!("service={host} window=last 1h total={total}"),
                confidence: conf,
                recommended_action: action.into(),
                project_id: None,
                credential_id: None,
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
    struct SvcRow {
        sid: String,
        host: String,
        provider: Option<String>,
        confirmed: bool,
        user_provider: Option<String>,
    }
    let mut stmt = conn.prepare(
        "SELECT id, host, provider_id, confirmed, user_provider
         FROM observed_api_services WHERE first_seen_at >= ?1",
    )?;
    let rows: Vec<SvcRow> = stmt
        .query_map([since], |r| {
            Ok(SvcRow {
                sid: r.get(0)?,
                host: r.get(1)?,
                provider: r.get(2)?,
                confirmed: r.get::<_, i64>(3)? != 0,
                user_provider: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    for SvcRow {
        sid,
        host,
        provider,
        confirmed,
        user_provider,
    } in rows
    {
        // A service the user has already classified/named is no longer
        // "unknown"; following the alert's own remediation (classify it in the
        // Monitor view) sets user_provider/confirmed but not provider_id, so
        // keying only on provider_id re-emitted the alert every cycle. Suppress
        // once the user has acted.
        if provider.is_none() && (confirmed || user_provider.is_some()) {
            continue;
        }
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
    // Only declare individual hosts inactive if observation was actually
    // running during the quiet window: if NO traffic to ANY host was recorded in
    // the window, the user simply was not running `api-tracker run --observe`,
    // and flagging every established host as "now quiet" is noise, not signal.
    let observed_recently: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_request_events WHERE at >= ?1)",
        [quiet_since],
        |r| r.get(0),
    )?;
    if !observed_recently {
        return Ok(());
    }
    let mut stmt = conn.prepare(
        "SELECT id, host FROM observed_api_services
         WHERE last_seen_at < ?1 AND first_seen_at < ?2",
    )?;
    let rows: Vec<(String, String)> = stmt
        .query_map(params![quiet_since, established_before], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
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

/// How recent a session's activity must be for the shared-credential rule to
/// still consider its cross-project use "current".
const SHARED_CREDENTIAL_WINDOW_DAYS: i64 = 7;

fn credential_rules(
    conn: &Connection,
    observed: &str,
    now: time::OffsetDateTime,
    label_of: &dyn Fn(&str) -> String,
    out: &mut Vec<NewAlert>,
) -> Result<()> {
    // Old credential version still in use after rotation. Compared LIVE against
    // the credential's current value_version, so it fires when a rotation
    // (days later) advances the version past a still-running session's
    // launch-time version. It is bound to sessions that are STILL RUNNING: once
    // the process exits the row no longer matches and the alert auto-resolves.
    // Without that bound it fired forever from long-ended sessions (attributions
    // are never pruned) and could never be cleared. Restricted to
    // confirmed/high attributions so a heuristic 'possible' guess cannot raise a
    // High-severity claim about a specific credential.
    let mut stmt = conn.prepare(
        "SELECT DISTINCT a.credential_id, s.host, a.credential_version
         FROM credential_traffic_attributions a
         JOIN credentials c ON c.id = a.credential_id
         JOIN observed_api_services s ON s.id = a.service_id
         JOIN observation_sessions sess ON sess.id = a.session_id
         WHERE a.credential_version IS NOT NULL AND a.credential_version < c.value_version
           AND a.confidence IN ('confirmed','high')
           AND sess.status = 'running'",
    )?;
    for row in stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<i64>>(2)?,
        ))
    })? {
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

    // Traffic attributed to a credential marked revoked, bound to STILL-RUNNING
    // sessions: "still in use" means a live process is currently using it. Once
    // the session ends the process is gone and the alert auto-resolves. Without
    // the bound, historical (pre-revocation) traffic matched forever and the
    // alert could never clear. Restricted to confirmed/high attributions.
    let mut stmt = conn.prepare(
        "SELECT DISTINCT a.credential_id, s.host FROM credential_traffic_attributions a
         JOIN credentials c ON c.id = a.credential_id
         JOIN observed_api_services s ON s.id = a.service_id
         JOIN observation_sessions sess ON sess.id = a.session_id
         WHERE c.revoked = 1 AND a.confidence IN ('confirmed','high')
           AND sess.status = 'running'",
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

    // Same credential's traffic across two or more projects, bounded to RECENT
    // cross-project use (a session that is running or started within the recency
    // window). Without the bound, a single historical cross-project use matched
    // forever — the alert could never clear after the user remediated by using a
    // per-project credential.
    let recent_cutoff = days_ago(now, SHARED_CREDENTIAL_WINDOW_DAYS);
    let mut stmt = conn.prepare(
        "SELECT a.credential_id, COUNT(DISTINCT sess.project_id)
         FROM credential_traffic_attributions a
         JOIN observation_sessions sess ON sess.id = a.session_id
         WHERE a.confidence IN ('confirmed','high','possible')
           AND (sess.status = 'running' OR sess.started_at >= ?1)
         GROUP BY a.credential_id HAVING COUNT(DISTINCT sess.project_id) >= 2",
    )?;
    for row in stmt.query_map([recent_cutoff], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })? {
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
            host: "api.openai.com".into(),
            port: 443,
            method: HttpMethod::Post,
            path_template: "/v1/chat".into(),
            template_confidence: crate::providers::Confidence::High,
            status_code: if outcome_transport.is_failure() {
                None
            } else {
                Some(status)
            },
            req_content_kind: None,
            resp_content_kind: None,
            had_authorization: true,
            latency_ms: Some(20),
            request_bytes: Some(1),
            response_bytes: Some(1),
            protocol: Protocol::Http11,
            observation_source: ObservationSource::Intercept,
            transport_error: outcome_transport,
        }
    }

    #[test]
    fn repeated_auth_failures_raise_a_high_alert() {
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        let sid = store::insert_session(
            &conn,
            &store::NewSession {
                project_id: "p1",
                mode: ObservationMode::Metadata,
                source: "cli_run",
                command: "x",
                credential_names: &[],
            },
        )
        .unwrap();
        let now_ts = crate::clock::now_rfc3339();
        let (svc, _) =
            store::upsert_service(&conn, "api.openai.com", Some("openai"), false, &now_ts).unwrap();
        // 8x 401, 4x 200 = 12 total, 8/12 = 66% auth failures
        for _ in 0..8 {
            store::insert_request_event(
                &conn,
                &sid,
                "p1",
                &svc,
                None,
                &now_ts,
                &ev(401, TransportError::None),
                true,
            )
            .unwrap();
        }
        for _ in 0..4 {
            store::insert_request_event(
                &conn,
                &sid,
                "p1",
                &svc,
                None,
                &now_ts,
                &ev(200, TransportError::None),
                true,
            )
            .unwrap();
        }

        let alerts = alerts(&conn, crate::clock::now(), &|_| {
            "web/openai-main".to_string()
        })
        .unwrap();
        let auth = alerts
            .iter()
            .find(|a| a.kind == AlertKind::RuntimeAuthFailures)
            .expect("auth failure alert");
        assert_eq!(auth.severity, Severity::High);
        assert!(auth.detail.contains("401"));
    }

    #[test]
    fn unknown_api_first_seen_raises_alert() {
        let conn = mem();
        let now_ts = crate::clock::now_rfc3339();
        store::upsert_service(&conn, "api.mystery.example", None, false, &now_ts).unwrap();
        let alerts = alerts(&conn, crate::clock::now(), &|_| String::new()).unwrap();
        assert!(alerts
            .iter()
            .any(|a| a.kind == AlertKind::RuntimeUnknownApi));
    }

    #[test]
    fn old_credential_version_raises_alert() {
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        testutil::seed_credential(&conn, "c1", "p1", "openai", "openai-main");
        let sid = store::insert_session(
            &conn,
            &store::NewSession {
                project_id: "p1",
                mode: ObservationMode::Metadata,
                source: "cli_run",
                command: "x",
                credential_names: &[],
            },
        )
        .unwrap();
        let now_ts = crate::clock::now_rfc3339();
        let (svc, _) =
            store::upsert_service(&conn, "api.openai.com", Some("openai"), false, &now_ts).unwrap();
        // launched at v1; the credential has since rotated to v3.
        store::upsert_attribution(
            &conn,
            &sid,
            "c1",
            &svc,
            5,
            AttributionConfidence::Confirmed,
            "e",
            Some(1),
            Some(true),
        )
        .unwrap();
        conn.execute(
            "UPDATE credentials SET value_version = 3 WHERE id = 'c1'",
            [],
        )
        .unwrap();
        let alerts = alerts(&conn, crate::clock::now(), &|_| {
            "web/openai-main".to_string()
        })
        .unwrap();
        assert!(alerts
            .iter()
            .any(|a| a.kind == AlertKind::RuntimeOldCredentialVersion));
    }

    #[test]
    fn old_version_does_not_fire_for_an_ended_session() {
        // Regression: the rule matched attributions from ANY session forever,
        // so every rotation produced a permanent false High alert. Bound to
        // running sessions: an ended session must not alert.
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        testutil::seed_credential(&conn, "c1", "p1", "openai", "openai-main");
        let sid = store::insert_session(
            &conn,
            &store::NewSession {
                project_id: "p1",
                mode: ObservationMode::Metadata,
                source: "cli_run",
                command: "x",
                credential_names: &[],
            },
        )
        .unwrap();
        let now_ts = crate::clock::now_rfc3339();
        let (svc, _) =
            store::upsert_service(&conn, "api.openai.com", Some("openai"), false, &now_ts).unwrap();
        store::upsert_attribution(
            &conn,
            &sid,
            "c1",
            &svc,
            5,
            AttributionConfidence::Confirmed,
            "e",
            Some(1),
            Some(true),
        )
        .unwrap();
        conn.execute(
            "UPDATE credentials SET value_version = 3 WHERE id = 'c1'",
            [],
        )
        .unwrap();
        // The session has ended.
        conn.execute(
            "UPDATE observation_sessions SET status = 'completed', ended_at = ?1 WHERE id = ?2",
            params![now_ts, sid],
        )
        .unwrap();
        let alerts = alerts(&conn, crate::clock::now(), &|_| {
            "web/openai-main".to_string()
        })
        .unwrap();
        assert!(
            !alerts
                .iter()
                .any(|a| a.kind == AlertKind::RuntimeOldCredentialVersion),
            "an ended session must not raise old-credential-version"
        );
    }

    #[test]
    fn opaque_tunnel_success_is_not_a_transport_failure_and_never_crashes() {
        // Regression: (1) SUM(status_code=403) over an all-NULL-status group
        // returned NULL and crashed the whole monitor cycle; (2) successful
        // opaque CONNECT tunnels (status None, transport 'none') were counted as
        // transport failures, producing a false 'connection failures' alert.
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        let sid = store::insert_session(
            &conn,
            &store::NewSession {
                project_id: "p1",
                mode: ObservationMode::Connection,
                source: "cli_run",
                command: "x",
                credential_names: &[],
            },
        )
        .unwrap();
        let now_ts = crate::clock::now_rfc3339();
        let (svc, _) =
            store::upsert_service(&conn, "api.stream.example", None, false, &now_ts).unwrap();
        let opaque = ObservedRequest {
            host: "api.stream.example".into(),
            port: 443,
            method: HttpMethod::Connect,
            path_template: "/:connect".into(),
            template_confidence: crate::providers::Confidence::Low,
            status_code: None,
            req_content_kind: None,
            resp_content_kind: None,
            had_authorization: false,
            latency_ms: Some(5),
            request_bytes: Some(1),
            response_bytes: Some(1),
            protocol: Protocol::ConnectTunnel,
            observation_source: ObservationSource::ConnectionOnly,
            transport_error: TransportError::None,
        };
        for _ in 0..20 {
            store::insert_request_event(&conn, &sid, "p1", &svc, None, &now_ts, &opaque, false)
                .unwrap();
        }
        // Must not crash, and must not raise a transport-failure alert.
        let alerts = alerts(&conn, crate::clock::now(), &|_| String::new()).unwrap();
        assert!(
            !alerts
                .iter()
                .any(|a| a.kind == AlertKind::RuntimeTransportFailures),
            "successful opaque tunnels must not be flagged as connection failures"
        );
    }

    #[test]
    fn unknown_api_suppressed_after_user_classification() {
        // Regression: classifying an unknown API (sets user_provider/confirmed,
        // not provider_id) did not stop the alert re-emitting.
        let conn = mem();
        let now_ts = crate::clock::now_rfc3339();
        let (svc, _) =
            store::upsert_service(&conn, "api.mystery.example", None, false, &now_ts).unwrap();
        // Before classification: the alert fires.
        let before = alerts(&conn, crate::clock::now(), &|_| String::new()).unwrap();
        assert!(before
            .iter()
            .any(|a| a.kind == AlertKind::RuntimeUnknownApi));
        // The user classifies it.
        store::set_service_correction(&conn, &svc, Some("acme"), Some("Acme API"), None, None)
            .unwrap();
        let after = alerts(&conn, crate::clock::now(), &|_| String::new()).unwrap();
        assert!(
            !after.iter().any(|a| a.kind == AlertKind::RuntimeUnknownApi),
            "classifying the API must stop the unknown-API alert"
        );
    }

    #[test]
    fn inactive_api_suppressed_when_observation_was_not_running() {
        // Regression: with no recent traffic to ANY host, every established host
        // was flagged inactive — but that just means observation was off.
        let conn = mem();
        // A service established and last seen long ago, and no recent events.
        store::upsert_service(
            &conn,
            "api.old.example",
            Some("acme"),
            false,
            "2020-01-01T00:00:00Z",
        )
        .unwrap();
        let alerts = alerts(&conn, crate::clock::now(), &|_| String::new()).unwrap();
        assert!(
            !alerts
                .iter()
                .any(|a| a.kind == AlertKind::RuntimeApiInactive),
            "no observation coverage means no inactive-API alerts"
        );
    }
}
