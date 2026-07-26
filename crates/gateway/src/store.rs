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
