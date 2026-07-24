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
    // Services this session actually touched, with the resolved provider id, a
    // request count, and how many of those requests carried a recognized auth
    // header (presence only — the value is never read). Attribution keys off
    // that presence so unauthenticated traffic is not asserted as credential use.
    struct SvcTraffic {
        service_id: String,
        host: String,
        provider_id: Option<String>,
        count: i64,
        auth_count: i64,
    }
    let mut stmt = conn.prepare(
        "SELECT e.service_id, s.host, s.provider_id, COUNT(*), COALESCE(SUM(e.had_authorization),0)
         FROM runtime_request_events e
         JOIN observed_api_services s ON s.id = e.service_id
         WHERE e.session_id = ?1
         GROUP BY e.service_id",
    )?;
    let rows: Vec<SvcTraffic> = stmt
        .query_map([session_id], |r| {
            Ok(SvcTraffic {
                service_id: r.get(0)?,
                host: r.get(1)?,
                provider_id: r.get(2)?,
                count: r.get(3)?,
                auth_count: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;

    let mut written = 0usize;
    for SvcTraffic {
        service_id,
        host,
        provider_id,
        count,
        auth_count,
    } in rows
    {
        let has_auth = auth_count > 0;
        // Prefer the stored provider; fall back to a host→provider lookup.
        let provider =
            provider_id.or_else(|| inventory::provider_for_host(&host).map(|p| p.to_string()));

        let candidates: Vec<&InjectedCredential> = match &provider {
            Some(p) => injected.iter().filter(|c| &c.provider == p).collect(),
            None => Vec::new(),
        };

        let (chosen, confidence, evidence): (
            Option<&InjectedCredential>,
            AttributionConfidence,
            String,
        ) = match candidates.len() {
            1 if has_auth => (
                Some(candidates[0]),
                AttributionConfidence::Confirmed,
                "single injected credential of the matching provider; an authorization header was observed".into(),
            ),
            1 => (
                // Provider host matched, but NO request to it carried an auth
                // header (e.g. an unauthenticated fetch, or a robots.txt call):
                // do not assert the credential was used — downgrade to Possible.
                Some(candidates[0]),
                AttributionConfidence::Possible,
                "single injected credential of the matching provider, but no authorization header was observed".into(),
            ),
            n if n > 1 => {
                // Ambiguous: record each candidate, choose none.
                for c in &candidates {
                    let current = current_value_version(conn, &c.credential_id)
                        .unwrap_or(c.current_version);
                    store::upsert_attribution(
                        conn,
                        session_id,
                        &c.credential_id,
                        &service_id,
                        count,
                        AttributionConfidence::Ambiguous,
                        "multiple injected credentials of this provider could explain the traffic",
                        Some(c.launch_version),
                        Some(c.launch_version >= current),
                    )?;
                    written += 1;
                }
                continue;
            }
            _ => {
                // No provider match. Attribute to the sole injected credential as
                // a *possible* explanation ONLY if some request actually carried
                // an auth header — otherwise (package registries, telemetry, an
                // allowlisted internal host) it is Unattributed, so a key is
                // never credited with traffic it demonstrably did not send.
                if provider.is_none() && injected.len() == 1 && has_auth {
                    (
                        Some(&injected[0]),
                        AttributionConfidence::Possible,
                        "one credential was injected and an authorization header was observed; the API's provider is unknown".into(),
                    )
                } else {
                    (None, AttributionConfidence::Unattributed, String::new())
                }
            }
        };

        if let Some(c) = chosen {
            // Re-read the root credential's LIVE value_version at session end:
            // a rotation during the run advances it, so comparing against the
            // launch-time placeholder (which equalled launch_version) always
            // reported "used current version = true".
            let current =
                current_value_version(conn, &c.credential_id).unwrap_or(c.current_version);
            let used_current = c.launch_version >= current;
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
            // Backfill the per-event credential for any chosen attribution
            // (Confirmed or Possible); ambiguous/unattributed leave events NULL.
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
    }

    // Bump credentials.last_used_at ONLY for confirmed/high attributions — never
    // for a weak 'possible' guess, so the "unused credential" rule is not
    // silenced by traffic the key may not have sent.
    conn.execute(
        "UPDATE credentials SET last_used_at = ?2
         WHERE id IN (SELECT DISTINCT credential_id FROM credential_traffic_attributions
                      WHERE session_id = ?1 AND confidence IN ('confirmed','high'))",
        params![session_id, crate::clock::now_rfc3339()],
    )?;

    Ok(written)
}

/// The root credential's current `value_version` (its id is already resolved to
/// the value-bearing root by `observe_injected`).
fn current_value_version(conn: &Connection, credential_id: &str) -> Option<i64> {
    conn.query_row(
        "SELECT value_version FROM credentials WHERE id = ?1",
        [credential_id],
        |r| r.get(0),
    )
    .ok()
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
            &store::NewSession {
                project_id: "p1",
                mode: ObservationMode::Metadata,
                source: "cli_run",
                command: "x",
                credential_names: &[],
            },
        )
        .unwrap();
        let now = crate::clock::now_rfc3339();
        let (svc, _) =
            store::upsert_service(conn, "api.openai.com", Some("openai"), false, &now).unwrap();
        let (ep, k) = store::upsert_endpoint(
            conn,
            &svc,
            HttpMethod::Get,
            "/v1/models",
            crate::providers::Confidence::High,
            &now,
        )
        .unwrap();
        store::insert_request_event(
            conn,
            &sid,
            "p1",
            &svc,
            Some(&ep),
            &now,
            &req("api.openai.com"),
            k,
        )
        .unwrap();
        sid
    }

    #[test]
    fn single_injected_match_is_confirmed() {
        let conn = mem();
        let sid = setup(&conn);
        let n = attribute_session(
            &conn,
            &sid,
            &[InjectedCredential {
                credential_id: "c-openai".into(),
                provider: "openai".into(),
                environment: "production".into(),
                launch_version: 2,
                current_version: 2,
            }],
        )
        .unwrap();
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
        // Rotate the stored credential to v3 (as a real rotation would), so the
        // current version is re-read live at attribution time rather than taken
        // from a launch-time constant that was always equal to launch_version.
        conn.execute(
            "UPDATE credentials SET value_version = 3 WHERE id = 'c-openai'",
            [],
        )
        .unwrap();
        attribute_session(
            &conn,
            &sid,
            &[InjectedCredential {
                credential_id: "c-openai".into(),
                provider: "openai".into(),
                environment: "production".into(),
                launch_version: 1,  // launched at v1
                current_version: 1, // launch-time placeholder (ignored; re-read)
            }],
        )
        .unwrap();
        let attrs = store::session_attributions(&conn, &sid).unwrap();
        assert_eq!(
            attrs[0].used_current_version,
            Some(false),
            "old version in use"
        );
        assert_eq!(attrs[0].credential_version, Some(1));
    }

    #[test]
    fn unauthenticated_provider_traffic_is_not_confirmed_and_does_not_bump_last_used() {
        // Regression: a provider-host match alone yielded Confirmed and bumped
        // last_used_at even with zero authorization evidence.
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        testutil::seed_credential(&conn, "c-openai", "p1", "openai", "openai-main");
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
        let now = crate::clock::now_rfc3339();
        let (svc, _) =
            store::upsert_service(&conn, "api.openai.com", Some("openai"), false, &now).unwrap();
        // An UNAUTHENTICATED request to the provider host.
        let mut e = req("api.openai.com");
        e.had_authorization = false;
        store::insert_request_event(&conn, &sid, "p1", &svc, None, &now, &e, false).unwrap();

        attribute_session(
            &conn,
            &sid,
            &[InjectedCredential {
                credential_id: "c-openai".into(),
                provider: "openai".into(),
                environment: "production".into(),
                launch_version: 1,
                current_version: 1,
            }],
        )
        .unwrap();
        let attrs = store::session_attributions(&conn, &sid).unwrap();
        assert_eq!(
            attrs[0].confidence, "possible",
            "no auth header => not confirmed"
        );
        let last_used: Option<String> = conn
            .query_row(
                "SELECT last_used_at FROM credentials WHERE id='c-openai'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            last_used.is_none(),
            "possible attribution must not bump last_used_at"
        );
    }

    #[test]
    fn unknown_host_without_auth_is_unattributed() {
        // Regression: every unknown-provider host was attributed 'possible' to
        // the sole injected credential — even package registries with no auth.
        let conn = mem();
        testutil::seed_project(&conn, "p1", "web");
        testutil::seed_credential(&conn, "c-openai", "p1", "openai", "openai-main");
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
        let now = crate::clock::now_rfc3339();
        // An unknown provider host (a package registry), no auth header.
        let (svc, _) =
            store::upsert_service(&conn, "registry.npmjs.org", None, false, &now).unwrap();
        let mut e = req("registry.npmjs.org");
        e.had_authorization = false;
        store::insert_request_event(&conn, &sid, "p1", &svc, None, &now, &e, false).unwrap();

        let n = attribute_session(
            &conn,
            &sid,
            &[InjectedCredential {
                credential_id: "c-openai".into(),
                provider: "openai".into(),
                environment: "production".into(),
                launch_version: 1,
                current_version: 1,
            }],
        )
        .unwrap();
        assert_eq!(
            n, 0,
            "unauthenticated unknown-host traffic must be unattributed"
        );
        assert!(store::session_attributions(&conn, &sid).unwrap().is_empty());
    }

    #[test]
    fn multiple_matching_credentials_are_ambiguous() {
        let conn = mem();
        let sid = setup(&conn);
        testutil::seed_credential(&conn, "c-openai-2", "p1", "openai", "openai-alt");
        let n = attribute_session(
            &conn,
            &sid,
            &[
                InjectedCredential {
                    credential_id: "c-openai".into(),
                    provider: "openai".into(),
                    environment: "production".into(),
                    launch_version: 1,
                    current_version: 1,
                },
                InjectedCredential {
                    credential_id: "c-openai-2".into(),
                    provider: "openai".into(),
                    environment: "production".into(),
                    launch_version: 1,
                    current_version: 1,
                },
            ],
        )
        .unwrap();
        assert_eq!(n, 2);
        let attrs = store::session_attributions(&conn, &sid).unwrap();
        assert!(attrs.iter().all(|a| a.confidence == "ambiguous"));
    }
}
