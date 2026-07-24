//! Credential attribution for a completed observation session.
//!
//! Attribution is derived ONLY from what Tethra controls — the credentials it
//! injected into the monitored process and their `value_version` captured at
//! launch — never from reading an `Authorization` value. Because the launch
//! version is known, "an old credential version is still in use after
//! rotation" is provable: if a session's injected version is below the
//! credential's current version, the traffic used the old value.

use crate::error::Result;
use crate::runtime::inventory;
use crate::runtime::model::AttributionConfidence;
use crate::runtime::store;
use rusqlite::{params, Connection};

/// A credential Tethra injected into the monitored process, with the version
/// active at launch and the credential's current version (to detect old-version
/// use after a rotation).
#[derive(Debug, Clone)]
pub struct InjectedCredential {
    pub credential_id: String,
    pub provider: String,
    pub environment: String,
    pub launch_version: i64,
    pub current_version: i64,
}

/// Attribute a completed session's traffic and write the attribution rollup +
/// per-event backfill. Returns the number of (service, credential) attributions
/// written.
pub fn attribute_session(
    conn: &Connection,
    session_id: &str,
    injected: &[InjectedCredential],
) -> Result<usize> {
    // Services this session actually touched, with the resolved provider id and
    // a request count.
    let mut stmt = conn.prepare(
        "SELECT e.service_id, s.host, s.provider_id, COUNT(*)
         FROM runtime_request_events e
         JOIN observed_api_services s ON s.id = e.service_id
         WHERE e.session_id = ?1
         GROUP BY e.service_id",
    )?;
    let rows: Vec<(String, String, Option<String>, i64)> = stmt
        .query_map([session_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;

    let mut written = 0usize;
    for (service_id, host, provider_id, count) in rows {
        // Prefer the stored provider; fall back to a host→provider lookup.
        let provider = provider_id
            .or_else(|| inventory::provider_for_host(&host).map(|p| p.to_string()));

        let candidates: Vec<&InjectedCredential> = match &provider {
            Some(p) => injected.iter().filter(|c| &c.provider == p).collect(),
            None => Vec::new(),
        };

        let (chosen, confidence, evidence): (Option<&InjectedCredential>, AttributionConfidence, String) =
            match candidates.len() {
                1 => (
                    Some(candidates[0]),
                    AttributionConfidence::Confirmed,
                    "single injected credential of the matching provider".into(),
                ),
                n if n > 1 => {
                    // Ambiguous: record each candidate, choose none.
                    for c in &candidates {
                        store::upsert_attribution(
                            conn,
                            session_id,
                            &c.credential_id,
                            &service_id,
                            count,
                            AttributionConfidence::Ambiguous,
                            "multiple injected credentials of this provider could explain the traffic",
                            Some(c.launch_version),
                            Some(c.launch_version >= c.current_version),
                        )?;
                        written += 1;
                    }
                    continue;
                }
                _ => {
                    // No provider match. If exactly one credential was injected
                    // at all, it is a *possible* explanation (weak).
                    if provider.is_none() && injected.len() == 1 {
                        (
                            Some(&injected[0]),
                            AttributionConfidence::Possible,
                            "one credential was injected; the API's provider is unknown".into(),
                        )
                    } else {
                        (None, AttributionConfidence::Unattributed, String::new())
                    }
                }
            };

        match chosen {
            Some(c) => {
                let used_current = c.launch_version >= c.current_version;
                store::upsert_attribution(
                    conn,
                    session_id,
                    &c.credential_id,
                    &service_id,
                    count,
                    confidence,
                    &evidence,
                    Some(c.launch_version),
                    Some(used_current),
                )?;
                // Backfill events only for confident (non-ambiguous) attributions.
                store::set_event_attribution_for_session_service(
                    conn,
                    session_id,
                    &service_id,
                    &c.credential_id,
                    confidence,
                    Some(c.launch_version),
                    Some(used_current),
                )?;
                written += 1;
            }
            None => { /* Unattributed: no row, event credential stays NULL */ }
        }
    }

    // Update credentials.last_used_at from observed traffic (so the existing
    // "unused credential" rule benefits), for any credential we attributed.
    conn.execute(
        "UPDATE credentials SET last_used_at = ?2
         WHERE id IN (SELECT DISTINCT credential_id FROM credential_traffic_attributions
                      WHERE session_id = ?1 AND confidence IN ('confirmed','high','possible'))",
        params![session_id, crate::clock::now_rfc3339()],
    )?;

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::runtime::model::*;
    use crate::runtime::store::testutil;

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        conn.pragma_update(None, "foreign_keys", 1).unwrap();
        conn
    }

    fn req(host: &str) -> ObservedRequest {
        ObservedRequest {
            host: host.into(),
            port: 443,
            method: HttpMethod::Get,
            path_template: "/v1/models".into(),
            template_confidence: crate::providers::Confidence::High,
            status_code: Some(200),
            req_content_kind: None,
            resp_content_kind: None,
            had_authorization: true,
            latency_ms: Some(10),
            request_bytes: Some(10),
            response_bytes: Some(10),
            protocol: Protocol::Http11,
            observation_source: ObservationSource::Intercept,
            transport_error: TransportError::None,
        }
    }

    fn setup(conn: &Connection) -> String {
        testutil::seed_project(conn, "p1", "web");
        testutil::seed_credential(conn, "c-openai", "p1", "openai", "openai-main");
        let sid = store::insert_session(
            conn,
            &store::NewSession { project_id: "p1", mode: ObservationMode::Metadata, source: "cli_run", command: "x", credential_names: &[] },
        )
        .unwrap();
        let now = crate::clock::now_rfc3339();
        let (svc, _) = store::upsert_service(conn, "api.openai.com", Some("openai"), false, &now).unwrap();
        let (ep, k) = store::upsert_endpoint(conn, &svc, HttpMethod::Get, "/v1/models", crate::providers::Confidence::High, &now).unwrap();
        store::insert_request_event(conn, &sid, "p1", &svc, Some(&ep), &now, &req("api.openai.com"), k).unwrap();
        sid
    }

    #[test]
    fn single_injected_match_is_confirmed() {
        let conn = mem();
        let sid = setup(&conn);
        let n = attribute_session(&conn, &sid, &[InjectedCredential {
            credential_id: "c-openai".into(),
            provider: "openai".into(),
            environment: "production".into(),
            launch_version: 2,
            current_version: 2,
        }]).unwrap();
        assert_eq!(n, 1);
        let attrs = store::session_attributions(&conn, &sid).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].confidence, "confirmed");
        assert_eq!(attrs[0].credential_version, Some(2));
        assert_eq!(attrs[0].used_current_version, Some(true));
    }

    #[test]
    fn old_version_after_rotation_is_detectable() {
        let conn = mem();
        let sid = setup(&conn);
        attribute_session(&conn, &sid, &[InjectedCredential {
            credential_id: "c-openai".into(),
            provider: "openai".into(),
            environment: "production".into(),
            launch_version: 1,      // launched at v1
            current_version: 3,     // rotated to v3 since
        }]).unwrap();
        let attrs = store::session_attributions(&conn, &sid).unwrap();
        assert_eq!(attrs[0].used_current_version, Some(false), "old version in use");
        assert_eq!(attrs[0].credential_version, Some(1));
    }

    #[test]
    fn multiple_matching_credentials_are_ambiguous() {
        let conn = mem();
        let sid = setup(&conn);
        testutil::seed_credential(&conn, "c-openai-2", "p1", "openai", "openai-alt");
        let n = attribute_session(&conn, &sid, &[
            InjectedCredential { credential_id: "c-openai".into(), provider: "openai".into(), environment: "production".into(), launch_version: 1, current_version: 1 },
            InjectedCredential { credential_id: "c-openai-2".into(), provider: "openai".into(), environment: "production".into(), launch_version: 1, current_version: 1 },
        ]).unwrap();
        assert_eq!(n, 2);
        let attrs = store::session_attributions(&conn, &sid).unwrap();
        assert!(attrs.iter().all(|a| a.confidence == "ambiguous"));
    }
}
