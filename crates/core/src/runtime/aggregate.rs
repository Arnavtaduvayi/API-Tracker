//! Bounded-memory metrics and idempotent aggregation.
//!
//! Dashboard metrics are computed with a fixed 14-bin latency histogram (never
//! by storing per-request samples), so memory is O(bins) not O(requests).
//! p50/p95/p99 are linearly interpolated within the containing bin and are
//! labelled *approximate* in the UI.
//!
//! [`roll_up`] fills `runtime_metric_buckets` idempotently: each complete hour
//! is recomputed from its events and REPLACED (so an interrupted run simply
//! redoes the last hour), and day buckets are recomputed from the hour buckets
//! (which persist beyond the short event retention). A watermark in
//! `vault_meta` records the last processed hour.

use crate::error::Result;
use crate::runtime::store;
use rusqlite::{params, Connection, Row};
use serde::Serialize;

const WATERMARK: &str = "runtime_aggregate_watermark";

/// Latency histogram upper bounds in milliseconds; the 14th bin is `> 10000`.
const LAT_UPPERS: [i64; 13] = [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

/// The 27 counter/histogram columns, shared by the bucket table and the
/// events aggregate (same names, same order).
const COUNTER_COLS: &str = "total, c2xx, c3xx, c4xx, c5xx, auth_errors, forbidden, rate_limited, \
     server_errors, transport_errors, tls_errors, request_bytes, response_bytes, \
     lat_le_1, lat_le_2, lat_le_5, lat_le_10, lat_le_25, lat_le_50, lat_le_100, lat_le_250, \
     lat_le_500, lat_le_1000, lat_le_2500, lat_le_5000, lat_le_10000, lat_gt_10000";

/// The aggregate expressions over `runtime_request_events`, in COUNTER_COLS order.
const EVENT_AGG: &str = "COUNT(*), \
     SUM(status_class='2xx'), SUM(status_class='3xx'), SUM(status_class='4xx'), SUM(status_class='5xx'), \
     SUM(outcome='auth_error'), SUM(status_code=403), SUM(outcome='rate_limited'), \
     SUM(outcome='server_error'), SUM(outcome='transport_error'), SUM(outcome='tls_error'), \
     COALESCE(SUM(request_bytes),0), COALESCE(SUM(response_bytes),0), \
     SUM(latency_ms<=1), SUM(latency_ms>1 AND latency_ms<=2), SUM(latency_ms>2 AND latency_ms<=5), \
     SUM(latency_ms>5 AND latency_ms<=10), SUM(latency_ms>10 AND latency_ms<=25), \
     SUM(latency_ms>25 AND latency_ms<=50), SUM(latency_ms>50 AND latency_ms<=100), \
     SUM(latency_ms>100 AND latency_ms<=250), SUM(latency_ms>250 AND latency_ms<=500), \
     SUM(latency_ms>500 AND latency_ms<=1000), SUM(latency_ms>1000 AND latency_ms<=2500), \
     SUM(latency_ms>2500 AND latency_ms<=5000), SUM(latency_ms>5000 AND latency_ms<=10000), \
     SUM(latency_ms>10000)";

/// Aggregated metrics for a scope + window. `success` = 2xx/3xx, everything
/// else counted as an error subclass; the two are never conflated.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Metrics {
    pub total: i64,
    pub success: i64,
    pub c2xx: i64,
    pub c3xx: i64,
    pub c4xx: i64,
    pub c5xx: i64,
    pub auth_errors: i64,
    pub forbidden: i64,
    pub rate_limited: i64,
    pub server_errors: i64,
    pub transport_errors: i64,
    pub tls_errors: i64,
    pub errors: i64,
    pub error_rate: f64,
    pub request_bytes: i64,
    pub response_bytes: i64,
    pub p50_ms: Option<i64>,
    pub p95_ms: Option<i64>,
    pub p99_ms: Option<i64>,
    /// True — percentiles come from a histogram and are approximate.
    pub latency_approximate: bool,
}

fn metrics_from_row(r: &Row<'_>) -> rusqlite::Result<Metrics> {
    let total: i64 = r.get(0)?;
    let c2xx: i64 = r.get(1)?;
    let c3xx: i64 = r.get(2)?;
    let mut bins = [0i64; 14];
    for (i, b) in bins.iter_mut().enumerate() {
        *b = r.get(13 + i)?;
    }
    let success = c2xx + c3xx;
    let errors = total - success;
    Ok(Metrics {
        total,
        success,
        c2xx,
        c3xx,
        c4xx: r.get(3)?,
        c5xx: r.get(4)?,
        auth_errors: r.get(5)?,
        forbidden: r.get(6)?,
        rate_limited: r.get(7)?,
        server_errors: r.get(8)?,
        transport_errors: r.get(9)?,
        tls_errors: r.get(10)?,
        errors,
        error_rate: if total > 0 {
            errors as f64 / total as f64
        } else {
            0.0
        },
        request_bytes: r.get(11)?,
        response_bytes: r.get(12)?,
        p50_ms: percentile(&bins, 0.50),
        p95_ms: percentile(&bins, 0.95),
        p99_ms: percentile(&bins, 0.99),
        latency_approximate: true,
    })
}

/// Interpolate a percentile from the fixed histogram. Returns `None` if there
/// are no latency samples.
fn percentile(bins: &[i64; 14], p: f64) -> Option<i64> {
    let total: i64 = bins.iter().sum();
    if total == 0 {
        return None;
    }
    let target = (p * total as f64).ceil().max(1.0) as i64;
    let mut cum = 0i64;
    for i in 0..14 {
        cum += bins[i];
        if cum >= target {
            let lower = if i == 0 { 0 } else { LAT_UPPERS[i - 1] };
            if i >= LAT_UPPERS.len() {
                // open-ended top bin: report its lower bound
                return Some(lower);
            }
            let upper = LAT_UPPERS[i];
            let bin_count = bins[i].max(1);
            let rank_in_bin = target - (cum - bins[i]);
            let frac = rank_in_bin as f64 / bin_count as f64;
            return Some((lower as f64 + frac * (upper - lower) as f64).round() as i64);
        }
    }
    Some(LAT_UPPERS[LAT_UPPERS.len() - 1])
}

fn scope_metrics(conn: &Connection, cond: &str, ident: &str, since: &str) -> Result<Metrics> {
    let sql = format!("SELECT {EVENT_AGG} FROM runtime_request_events WHERE {cond} AND at >= ?2");
    let m = conn.query_row(&sql, params![ident, since], metrics_from_row)?;
    Ok(m)
}

pub fn service_metrics(
    conn: &Connection,
    service_id: &str,
    since: Option<&str>,
) -> Result<Metrics> {
    scope_metrics(conn, "service_id = ?1", service_id, since.unwrap_or(""))
}

pub fn session_metrics(conn: &Connection, session_id: &str) -> Result<Metrics> {
    scope_metrics(conn, "session_id = ?1", session_id, "")
}

pub fn project_metrics(
    conn: &Connection,
    project_id: &str,
    since: Option<&str>,
) -> Result<Metrics> {
    scope_metrics(conn, "project_id = ?1", project_id, since.unwrap_or(""))
}

/// Overview metrics across all services since `since`.
pub fn overview_metrics(conn: &Connection, since: Option<&str>) -> Result<Metrics> {
    let sql = format!("SELECT {EVENT_AGG} FROM runtime_request_events WHERE at >= ?1");
    Ok(conn.query_row(&sql, params![since.unwrap_or("")], metrics_from_row)?)
}

fn hour_floor(ts: &str) -> String {
    // "YYYY-MM-DDTHH:..." -> "YYYY-MM-DDTHH:00:00Z"
    if ts.len() >= 13 {
        format!("{}:00:00Z", &ts[..13])
    } else {
        "1970-01-01T00:00:00Z".to_string()
    }
}

/// Idempotently roll up complete hours (and days) up to `now`.
pub fn roll_up(conn: &Connection, now: &str) -> Result<usize> {
    let watermark =
        store::meta_get(conn, WATERMARK)?.unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
    let from_hour = hour_floor(&watermark);
    let current_hour = hour_floor(now);
    if current_hour <= from_hour {
        return Ok(0);
    }

    let insert_cols = format!(
        "id, granularity, bucket_start, project_id, service_id, endpoint_id, credential_id, first_at, last_at, {COUNTER_COLS}"
    );

    // Recompute the affected hour buckets: delete then insert (idempotent).
    conn.execute(
        "DELETE FROM runtime_metric_buckets
         WHERE granularity = 'hour' AND bucket_start >= ?1 AND bucket_start < ?2",
        params![from_hour, current_hour],
    )?;
    // all-credential hour buckets
    conn.execute(
        &format!(
            "INSERT INTO runtime_metric_buckets ({insert_cols})
             SELECT lower(hex(randomblob(16))), 'hour',
                    strftime('%Y-%m-%dT%H:00:00Z', at), project_id, service_id, '', '',
                    MIN(at), MAX(at), {EVENT_AGG}
             FROM runtime_request_events
             WHERE at >= ?1 AND at < ?2
             GROUP BY strftime('%Y-%m-%dT%H:00:00Z', at), project_id, service_id"
        ),
        params![from_hour, current_hour],
    )?;
    // per-credential hour buckets
    conn.execute(
        &format!(
            "INSERT INTO runtime_metric_buckets ({insert_cols})
             SELECT lower(hex(randomblob(16))), 'hour',
                    strftime('%Y-%m-%dT%H:00:00Z', at), project_id, service_id, '', credential_id,
                    MIN(at), MAX(at), {EVENT_AGG}
             FROM runtime_request_events
             WHERE at >= ?1 AND at < ?2 AND credential_id IS NOT NULL
             GROUP BY strftime('%Y-%m-%dT%H:00:00Z', at), project_id, service_id, credential_id"
        ),
        params![from_hour, current_hour],
    )?;

    // Recompute day buckets from the hour buckets (which persist beyond event
    // retention), for the affected days.
    let from_day = format!("{}T00:00:00Z", &from_hour[..10]);
    conn.execute(
        "DELETE FROM runtime_metric_buckets WHERE granularity = 'day' AND bucket_start >= ?1",
        params![from_day],
    )?;
    let sum_cols = COUNTER_COLS
        .split(',')
        .map(|c| format!("SUM({})", c.trim()))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute(
        &format!(
            "INSERT INTO runtime_metric_buckets ({insert_cols})
             SELECT lower(hex(randomblob(16))), 'day',
                    strftime('%Y-%m-%dT00:00:00Z', bucket_start), project_id, service_id, '', credential_id,
                    MIN(first_at), MAX(last_at), {sum_cols}
             FROM runtime_metric_buckets
             WHERE granularity = 'hour' AND bucket_start >= ?1
             GROUP BY strftime('%Y-%m-%dT00:00:00Z', bucket_start), project_id, service_id, credential_id"
        ),
        params![from_hour],
    )?;

    store::meta_set(conn, WATERMARK, &current_hour)?;
    Ok(1)
}

/// A point in a time series (for the requests-over-time chart).
#[derive(Debug, Clone, Serialize)]
pub struct SeriesPoint {
    pub bucket_start: String,
    pub total: i64,
    pub errors: i64,
}

/// Requests-over-time for a service at a granularity, since `since`.
pub fn series(
    conn: &Connection,
    service_id: &str,
    granularity: &str,
    since: &str,
) -> Result<Vec<SeriesPoint>> {
    let mut stmt = conn.prepare(
        "SELECT bucket_start, SUM(total), SUM(c4xx + c5xx + transport_errors + tls_errors)
         FROM runtime_metric_buckets
         WHERE service_id = ?1 AND granularity = ?2 AND credential_id = '' AND bucket_start >= ?3
         GROUP BY bucket_start ORDER BY bucket_start",
    )?;
    let rows = stmt.query_map(params![service_id, granularity, since], |r| {
        Ok(SeriesPoint {
            bucket_start: r.get(0)?,
            total: r.get(1)?,
            errors: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
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

    fn ev(status: u16, latency: i64, transport: TransportError) -> ObservedRequest {
        ObservedRequest {
            host: "api.openai.com".into(),
            port: 443,
            method: HttpMethod::Get,
            path_template: "/v1/models".into(),
            template_confidence: crate::providers::Confidence::High,
            status_code: if transport.is_failure() {
                None
            } else {
                Some(status)
            },
            req_content_kind: None,
            resp_content_kind: None,
            had_authorization: true,
            latency_ms: if transport.is_failure() {
                None
            } else {
                Some(latency)
            },
            request_bytes: Some(100),
            response_bytes: Some(500),
            protocol: Protocol::Http11,
            observation_source: ObservationSource::Intercept,
            transport_error: transport,
        }
    }

    fn seed(conn: &Connection) -> (String, String) {
        testutil::seed_project(conn, "p1", "web");
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
        let now = "2026-07-24T10:15:00Z";
        let (svc, _) =
            store::upsert_service(conn, "api.openai.com", Some("openai"), false, now).unwrap();
        // 8x 200 (varied latency), 1x 401, 1x 500, 1x transport error
        for lat in [5, 8, 12, 20, 40, 60, 90, 300] {
            store::insert_request_event(
                conn,
                &sid,
                "p1",
                &svc,
                None,
                now,
                &ev(200, lat, TransportError::None),
                false,
            )
            .unwrap();
        }
        store::insert_request_event(
            conn,
            &sid,
            "p1",
            &svc,
            None,
            now,
            &ev(401, 10, TransportError::None),
            false,
        )
        .unwrap();
        store::insert_request_event(
            conn,
            &sid,
            "p1",
            &svc,
            None,
            now,
            &ev(500, 15, TransportError::None),
            false,
        )
        .unwrap();
        store::insert_request_event(
            conn,
            &sid,
            "p1",
            &svc,
            None,
            now,
            &ev(0, 0, TransportError::Refused),
            false,
        )
        .unwrap();
        (sid, svc)
    }

    #[test]
    fn metrics_separate_classes_and_never_conflate() {
        let conn = mem();
        let (_sid, svc) = seed(&conn);
        let m = service_metrics(&conn, &svc, None).unwrap();
        assert_eq!(m.total, 11);
        assert_eq!(m.success, 8, "only 2xx/3xx are success");
        assert_eq!(m.auth_errors, 1);
        assert_eq!(m.server_errors, 1);
        assert_eq!(
            m.transport_errors, 1,
            "transport failure counted separately"
        );
        // the transport failure is NOT an HTTP status class
        assert_eq!(m.c5xx, 1);
        assert!(m.p95_ms.is_some());
        assert!(m.latency_approximate);
        assert!((m.error_rate - (3.0 / 11.0)).abs() < 1e-9);
    }

    #[test]
    fn rollup_is_idempotent() {
        let conn = mem();
        let (_sid, _svc) = seed(&conn);
        let after = "2026-07-24T12:00:00Z";
        roll_up(&conn, after).unwrap();
        let count1: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM runtime_metric_buckets WHERE granularity='hour'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        roll_up(&conn, after).unwrap();
        let count2: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM runtime_metric_buckets WHERE granularity='hour'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count1, count2,
            "running roll_up twice must not duplicate buckets"
        );
        // the hour bucket totals match the events
        let total: i64 = conn.query_row("SELECT SUM(total) FROM runtime_metric_buckets WHERE granularity='hour' AND credential_id=''", [], |r| r.get(0)).unwrap();
        assert_eq!(total, 11);
    }
}
