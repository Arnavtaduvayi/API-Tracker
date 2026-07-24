//! Retention sweep: bounded database growth for observability data.
//!
//! Event rows have a short life (default 7 days) — they exist for recent
//! debugging. Aggregate buckets live longer (default 90 days) for trends.
//! `secure_delete` (on for the whole DB) overwrites the freed pages.

use crate::error::Result;
use crate::{clock, runtime::settings::ObservabilitySettings};
use rusqlite::{params, Connection};
use time::{Duration, OffsetDateTime};

/// Delete events older than `event_days` and buckets older than `agg_days`.
/// Returns `(events_deleted, buckets_deleted)`.
pub fn sweep_with(
    conn: &Connection,
    event_days: u32,
    agg_days: u32,
    now: OffsetDateTime,
) -> Result<(usize, usize)> {
    let event_cutoff = clock::to_rfc3339(now - Duration::days(i64::from(event_days)));
    let agg_cutoff = clock::to_rfc3339(now - Duration::days(i64::from(agg_days)));
    let events = conn.execute(
        "DELETE FROM runtime_request_events WHERE at < ?1",
        params![event_cutoff],
    )?;
    let buckets = conn.execute(
        "DELETE FROM runtime_metric_buckets WHERE bucket_start < ?1",
        params![agg_cutoff],
    )?;
    Ok((events, buckets))
}

/// Sweep using the vault's configured retention settings and the current time.
pub fn sweep(conn: &Connection) -> Result<(usize, usize)> {
    let s = ObservabilitySettings::load(conn)?;
    sweep_with(conn, s.event_retention_days, s.aggregate_retention_days, clock::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::runtime::model::*;
    use crate::runtime::store::{self, testutil};

    #[test]
    fn sweep_prunes_old_events_but_keeps_recent() {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        conn.pragma_update(None, "foreign_keys", 1).unwrap();
        testutil::seed_project(&conn, "p1", "web");
        let sid = store::insert_session(&conn, &store::NewSession { project_id: "p1", mode: ObservationMode::Metadata, source: "cli_run", command: "x", credential_names: &[] }).unwrap();
        let (svc, _) = store::upsert_service(&conn, "api.openai.com", None, false, "2026-01-01T00:00:00Z").unwrap();

        let req = |at: &str| {
            let e = ObservedRequest {
                host: "api.openai.com".into(), port: 443, method: HttpMethod::Get,
                path_template: "/v1/models".into(), template_confidence: crate::providers::Confidence::High,
                status_code: Some(200), req_content_kind: None, resp_content_kind: None,
                had_authorization: false, latency_ms: Some(10), request_bytes: Some(1), response_bytes: Some(1),
                protocol: Protocol::Http11, observation_source: ObservationSource::Intercept, transport_error: TransportError::None,
            };
            store::insert_request_event(&conn, &sid, "p1", &svc, None, at, &e, false).unwrap();
        };
        // one old (30 days ago) and one recent event, relative to a fixed "now"
        let now = time::macros::datetime!(2026-07-24 12:00:00 UTC);
        req(&clock::to_rfc3339(now - Duration::days(30)));
        req(&clock::to_rfc3339(now - Duration::hours(1)));

        let (events, _buckets) = sweep_with(&conn, 7, 90, now).unwrap();
        assert_eq!(events, 1, "only the 30-day-old event is pruned");
        let remaining: i64 = conn.query_row("SELECT COUNT(*) FROM runtime_request_events", [], |r| r.get(0)).unwrap();
        assert_eq!(remaining, 1);
    }
}
