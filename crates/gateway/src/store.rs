//! Gateway configuration and counter storage (migration v13 tables).
//!
//! Everything in these tables is non-secret operational metadata. WRITES are
//! performed only by the CLI/desktop flows (unlocked vault + re-auth,
//! audited); the running service only READS, and every service-side open goes
//! through `db::open_at_current_version` so a schema from a different build
//! degrades recording instead of corrupting it (KNOWN_CONFLICTS C15).

use api_tracker_core::clock;
use api_tracker_core::error::Result;
use rusqlite::{params, Connection, OptionalExtension};

/// The singleton `gateway_config` row. The bind address is deliberately not
/// configurable (SI-1: loopback only, hard-coded). The derived default is
/// the honest disabled state: not enabled, no port chosen, and the
/// match-while-locked toggle OFF (OPEN_DECISIONS O2).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct GatewayConfig {
    pub enabled: bool,
    /// Random persisted high port chosen at enable time (ADR 0019 O3);
    /// `None` until the gateway has been enabled or run once.
    pub port: Option<u16>,
    /// The consented, default-OFF "keep matching credentials while the vault
    /// is locked" toggle (ADR 0019 D5, OPEN_DECISIONS O2).
    pub match_while_locked: bool,
    pub service_version: Option<String>,
    pub usage_event_retention_days: Option<u32>,
    pub usage_daily_retention_days: Option<u32>,
}

/// Default retention when no override is set: raw usage events ride the short
/// window, the daily rollup keeps the displayed spend series
/// (PRIVACY_MODEL gateway §6, KNOWN_CONFLICTS C16).
pub const DEFAULT_USAGE_EVENT_RETENTION_DAYS: u32 = 7;
pub const DEFAULT_USAGE_DAILY_RETENTION_DAYS: u32 = 90;

/// The persisted gateway port, read without a vault through the
/// schema-checked open. `None` when the database, schema, or config row is
/// unavailable — callers treat that as "no stable port exists yet".
pub fn port_hint(data_dir: &std::path::Path) -> Option<u16> {
    let conn = api_tracker_core::db::open_at_current_version(&data_dir.join("vault.db")).ok()?;
    load_config(&conn).ok().and_then(|c| c.port)
}

pub fn load_config(conn: &Connection) -> Result<GatewayConfig> {
    let row = conn
        .query_row(
            "SELECT enabled, port, match_while_locked, service_version,
                    usage_event_retention_days, usage_daily_retention_days
             FROM gateway_config WHERE id = 'gateway'",
            [],
            |r| {
                Ok(GatewayConfig {
                    enabled: r.get::<_, i64>(0)? != 0,
                    port: r
                        .get::<_, Option<i64>>(1)?
                        .and_then(|p| u16::try_from(p).ok()),
                    match_while_locked: r.get::<_, i64>(2)? != 0,
                    service_version: r.get(3)?,
                    usage_event_retention_days: r
                        .get::<_, Option<i64>>(4)?
                        .and_then(|d| u32::try_from(d).ok()),
                    usage_daily_retention_days: r
                        .get::<_, Option<i64>>(5)?
                        .and_then(|d| u32::try_from(d).ok()),
                })
            },
        )
        .optional()?;
    Ok(row.unwrap_or_default())
}

pub fn save_config(conn: &Connection, config: &GatewayConfig) -> Result<()> {
    let now = clock::now_rfc3339();
    conn.execute(
        "INSERT INTO gateway_config
            (id, enabled, port, match_while_locked, service_version,
             usage_event_retention_days, usage_daily_retention_days,
             created_at, updated_at)
         VALUES ('gateway', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
         ON CONFLICT(id) DO UPDATE SET
            enabled = excluded.enabled,
            port = excluded.port,
            match_while_locked = excluded.match_while_locked,
            service_version = excluded.service_version,
            usage_event_retention_days = excluded.usage_event_retention_days,
            usage_daily_retention_days = excluded.usage_daily_retention_days,
            updated_at = excluded.updated_at",
        params![
            config.enabled as i64,
            config.port.map(|p| p as i64),
            config.match_while_locked as i64,
            config.service_version,
            config.usage_event_retention_days.map(|d| d as i64),
            config.usage_daily_retention_days.map(|d| d as i64),
            now,
        ],
    )?;
    Ok(())
}

/// Route-level daily counters. `route_prefix = ""` holds gateway-global
/// counters (e.g. `rejected_browser_origin`, which by design has no route —
/// THREAT_MODEL GW-2). `day` is `YYYY-MM-DD` UTC.
pub fn bump_counter(
    conn: &Connection,
    route_prefix: &str,
    day: &str,
    counter: &str,
    by: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO gateway_route_counters (route_prefix, day, counter, count)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(route_prefix, day, counter)
         DO UPDATE SET count = count + excluded.count",
        params![route_prefix, day, counter, by],
    )?;
    Ok(())
}

pub fn counter_total(conn: &Connection, route_prefix: &str, counter: &str) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COALESCE(SUM(count), 0) FROM gateway_route_counters
         WHERE route_prefix = ?1 AND counter = ?2",
        params![route_prefix, counter],
        |r| r.get(0),
    )?)
}

/// The UTC `YYYY-MM-DD` day for counter rows, derived from an RFC 3339
/// timestamp string (prefix — all persisted timestamps are UTC).
pub fn day_of(at_rfc3339: &str) -> &str {
    at_rfc3339.get(..10).unwrap_or(at_rfc3339)
}

/// Gateway-only activity, aggregated from runtime events where
/// `observation_source = 'gateway'` plus the gateway usage rollup.
///
/// Everything here is LOCALLY OBSERVED: only traffic whose base URL pointed
/// at the gateway, never summed with provider-reported usage (SI-19), and
/// an empty summary is never evidence of zero provider usage. Double
/// counting against the interception proxy is prevented upstream by
/// construction: linked `.env` files carry `NO_PROXY=127.0.0.1,...`, so
/// loopback gateway traffic never also transits the proxy — each exchange
/// is recorded under exactly one `observation_source`.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct GatewayActivitySummary {
    pub since: Option<String>,
    pub total_requests: i64,
    /// 2xx/3xx statuses.
    pub success_count: i64,
    /// 4xx/5xx statuses (transport failures count separately).
    pub error_count: i64,
    pub transport_error_count: i64,
    pub p50_latency_ms: Option<i64>,
    pub p95_latency_ms: Option<i64>,
    pub p99_latency_ms: Option<i64>,
    pub request_bytes: i64,
    pub response_bytes: i64,
    /// (path_template, count) — sanitized templates only, top 8.
    pub top_endpoints: Vec<(String, i64)>,
    /// (attribution state, count) — the six honest states.
    pub attribution: Vec<(String, i64)>,
    /// From the gateway usage rollup (bounded extraction; absent ≠ zero).
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub usage_event_count: i64,
    /// (model, request_count) from the rollup, top 8.
    pub top_models: Vec<(String, i64)>,
    /// Estimated (lower-bound) cost in micro-USD from local pricing tables.
    pub estimated_cost_micros: i64,
    pub first_event_at: Option<String>,
    pub last_event_at: Option<String>,
}

/// Percentile from a sorted slice (nearest-rank).
fn percentile(sorted: &[i64], p: f64) -> Option<i64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}

pub fn gateway_activity_summary(
    conn: &Connection,
    since: Option<&str>,
) -> Result<GatewayActivitySummary> {
    let since_clause = since.unwrap_or("");
    let mut summary = GatewayActivitySummary {
        since: since.map(|s| s.to_string()),
        ..Default::default()
    };

    conn.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(CASE WHEN status_code BETWEEN 200 AND 399 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN transport_error != 'none' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(COALESCE(request_bytes, 0)), 0),
                COALESCE(SUM(COALESCE(response_bytes, 0)), 0),
                MIN(at), MAX(at)
         FROM runtime_request_events
         WHERE observation_source = 'gateway' AND at >= ?1",
        params![since_clause],
        |r| {
            summary.total_requests = r.get(0)?;
            summary.success_count = r.get(1)?;
            summary.error_count = r.get(2)?;
            summary.transport_error_count = r.get(3)?;
            summary.request_bytes = r.get(4)?;
            summary.response_bytes = r.get(5)?;
            summary.first_event_at = r.get(6)?;
            summary.last_event_at = r.get(7)?;
            Ok(())
        },
    )?;

    let mut stmt = conn.prepare(
        "SELECT latency_ms FROM runtime_request_events
         WHERE observation_source = 'gateway' AND latency_ms IS NOT NULL AND at >= ?1
         ORDER BY latency_ms",
    )?;
    let latencies: Vec<i64> = stmt
        .query_map(params![since_clause], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    summary.p50_latency_ms = percentile(&latencies, 50.0);
    summary.p95_latency_ms = percentile(&latencies, 95.0);
    summary.p99_latency_ms = percentile(&latencies, 99.0);

    let mut stmt = conn.prepare(
        "SELECT path_template, COUNT(*) AS n FROM runtime_request_events
         WHERE observation_source = 'gateway' AND at >= ?1
         GROUP BY path_template ORDER BY n DESC LIMIT 8",
    )?;
    summary.top_endpoints = stmt
        .query_map(params![since_clause], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut stmt = conn.prepare(
        "SELECT COALESCE(attribution_confidence, 'unavailable'), COUNT(*)
         FROM runtime_request_events
         WHERE observation_source = 'gateway' AND at >= ?1
         GROUP BY 1 ORDER BY 2 DESC",
    )?;
    summary.attribution = stmt
        .query_map(params![since_clause], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    conn.query_row(
        "SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0),
                COALESCE(SUM(usage_event_count), 0), COALESCE(SUM(estimated_cost_micros), 0)
         FROM gateway_usage_daily WHERE day >= ?1",
        params![since_clause.get(..10).unwrap_or("")],
        |r| {
            summary.input_tokens = r.get(0)?;
            summary.output_tokens = r.get(1)?;
            summary.usage_event_count = r.get(2)?;
            summary.estimated_cost_micros = r.get(3)?;
            Ok(())
        },
    )?;

    let mut stmt = conn.prepare(
        "SELECT model, SUM(request_count) AS n FROM gateway_usage_daily
         WHERE day >= ?1 AND model != '' GROUP BY model ORDER BY n DESC LIMIT 8",
    )?;
    summary.top_models = stmt
        .query_map(params![since_clause.get(..10).unwrap_or("")], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().expect("open in-memory db");
        api_tracker_core::db::migrate(&mut conn).expect("migrate");
        conn
    }

    #[test]
    fn config_defaults_when_absent_and_round_trips() {
        let conn = mem();
        let loaded = load_config(&conn).unwrap();
        assert_eq!(loaded, GatewayConfig::default());
        assert!(!loaded.enabled);
        assert!(!loaded.match_while_locked, "toggle must default OFF (O2)");

        let config = GatewayConfig {
            enabled: true,
            port: Some(49723),
            match_while_locked: false,
            service_version: Some("0.1.0".into()),
            usage_event_retention_days: Some(7),
            usage_daily_retention_days: Some(90),
        };
        save_config(&conn, &config).unwrap();
        assert_eq!(load_config(&conn).unwrap(), config);

        // Upsert, not duplicate.
        save_config(&conn, &config).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM gateway_config", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn counters_accumulate_per_route_and_day() {
        let conn = mem();
        bump_counter(&conn, "openai", "2026-07-26", "unlinked_requests", 1).unwrap();
        bump_counter(&conn, "openai", "2026-07-26", "unlinked_requests", 2).unwrap();
        bump_counter(&conn, "", "2026-07-26", "rejected_browser_origin", 1).unwrap();
        assert_eq!(
            counter_total(&conn, "openai", "unlinked_requests").unwrap(),
            3
        );
        assert_eq!(
            counter_total(&conn, "", "rejected_browser_origin").unwrap(),
            1
        );
        assert_eq!(
            counter_total(&conn, "openai", "rejected_browser_origin").unwrap(),
            0
        );
    }

    #[test]
    fn day_of_extracts_utc_date() {
        assert_eq!(day_of("2026-07-26T12:34:56Z"), "2026-07-26");
        assert_eq!(day_of("short"), "short");
    }
}

#[cfg(test)]
mod activity_tests {
    use super::*;

    #[test]
    fn gateway_activity_summary_counts_only_gateway_sourced_events() {
        let mut conn = Connection::open_in_memory().unwrap();
        api_tracker_core::db::migrate(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO projects (id, name, description, notes, environments, archived,
                 created_at, updated_at, wrapped_project_key, key_wrap_mode)
             VALUES ('p1', 'app', '', '', '[]', 0, '2026-01-01T00:00:00Z',
                 '2026-01-01T00:00:00Z', x'00', 'vault');
             INSERT INTO observed_api_services (id, host, provider_id, first_seen_at,
                 last_seen_at)
             VALUES ('svc1', 'api.openai.com', 'openai',
                 '2026-07-01T00:00:00Z', '2026-07-01T00:00:00Z');
             INSERT INTO observation_sessions (id, project_id, mode, source, command, started_at)
             VALUES ('sess1', 'p1', 'intercept', 'gateway', 'gw boot', '2026-07-01T00:00:00Z');",
        )
        .unwrap();
        // Two gateway events (one error), one proxy event that must NOT count.
        for (id, source, status, latency) in [
            ("e1", "gateway", 200, 100),
            ("e2", "gateway", 500, 300),
            ("e3", "intercept", 200, 50),
        ] {
            conn.execute(
                "INSERT INTO runtime_request_events
                    (id, session_id, project_id, service_id, at, host, port, method,
                     path_template, outcome, status_code, latency_ms, request_bytes,
                     response_bytes, protocol, observation_source)
                 VALUES (?1, 'sess1', 'p1', 'svc1', '2026-07-02T00:00:00Z',
                     'api.openai.com', 443, 'POST', '/v1/chat/completions', 'completed',
                     ?3, ?4, 10, 20, 'http1', ?2)",
                params![id, source, status, latency],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO gateway_usage_daily (day, provider_id, project_id, model,
                 request_count, usage_event_count, input_tokens, output_tokens,
                 cached_input_tokens, estimated_cost_micros, updated_at)
             VALUES ('2026-07-02', 'openai', '', 'gpt-test', 2, 2, 120, 40, 0, 990,
                 '2026-07-02T01:00:00Z')",
            [],
        )
        .unwrap();

        let s = gateway_activity_summary(&conn, None).unwrap();
        assert_eq!(s.total_requests, 2, "proxy events are a different source");
        assert_eq!(s.success_count, 1);
        assert_eq!(s.error_count, 1);
        assert_eq!(s.p50_latency_ms, Some(100));
        assert_eq!(s.p99_latency_ms, Some(300));
        assert_eq!(s.request_bytes, 20);
        assert_eq!(s.top_endpoints[0].0, "/v1/chat/completions");
        assert_eq!(s.input_tokens, 120);
        assert_eq!(s.top_models[0], ("gpt-test".to_string(), 2));
        assert_eq!(s.estimated_cost_micros, 990);

        // A window after the events is honestly empty.
        let empty = gateway_activity_summary(&conn, Some("2026-07-03T00:00:00Z")).unwrap();
        assert_eq!(empty.total_requests, 0);
        assert!(empty.last_event_at.is_none());
    }
}
