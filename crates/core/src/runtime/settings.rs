//! Observability settings, stored as rows in `vault_meta` (mirroring the
//! [`crate::settings::VaultSettings`] pattern, but kept separate so the
//! all-`u32` `VaultSettings` contract is undisturbed and the default mode can
//! be a string).

use crate::error::Result;
use crate::runtime::model::ObservationMode;
use crate::runtime::store;
use rusqlite::Connection;
use serde::Serialize;

const KEY_MODE: &str = "observe_default_mode";
const KEY_EVENT_RET: &str = "observe_event_retention_days";
const KEY_AGG_RET: &str = "observe_aggregate_retention_days";

/// Configurable retention bounds (justified in the privacy model §7).
pub const EVENT_RETENTION_MIN: u32 = 1;
pub const EVENT_RETENTION_MAX: u32 = 90;
pub const AGG_RETENTION_MIN: u32 = 7;
pub const AGG_RETENTION_MAX: u32 = 730;

#[derive(Debug, Clone, Serialize)]
pub struct ObservabilitySettings {
    /// Default observation mode for Tethra-launched runs. `Off` by default —
    /// monitoring is never automatic.
    pub default_mode: ObservationMode,
    /// Days to keep event-level rows (default 7).
    pub event_retention_days: u32,
    /// Days to keep aggregate buckets (default 90).
    pub aggregate_retention_days: u32,
}

impl Default for ObservabilitySettings {
    fn default() -> Self {
        Self {
            default_mode: ObservationMode::Off,
            event_retention_days: 7,
            aggregate_retention_days: 90,
        }
    }
}

impl ObservabilitySettings {
    pub fn load(conn: &Connection) -> Result<Self> {
        let mut s = Self::default();
        if let Some(m) = store::meta_get(conn, KEY_MODE)? {
            if let Some(mode) = ObservationMode::from_db(&m) {
                s.default_mode = mode;
            }
        }
        if let Some(v) = store::meta_get(conn, KEY_EVENT_RET)? {
            if let Ok(n) = v.parse::<u32>() {
                s.event_retention_days = n.clamp(EVENT_RETENTION_MIN, EVENT_RETENTION_MAX);
            }
        }
        if let Some(v) = store::meta_get(conn, KEY_AGG_RET)? {
            if let Ok(n) = v.parse::<u32>() {
                s.aggregate_retention_days = n.clamp(AGG_RETENTION_MIN, AGG_RETENTION_MAX);
            }
        }
        Ok(s)
    }

    pub fn save(&self, conn: &Connection) -> Result<()> {
        let ev = self
            .event_retention_days
            .clamp(EVENT_RETENTION_MIN, EVENT_RETENTION_MAX);
        let ag = self
            .aggregate_retention_days
            .clamp(AGG_RETENTION_MIN, AGG_RETENTION_MAX);
        store::meta_set(conn, KEY_MODE, self.default_mode.as_str())?;
        store::meta_set(conn, KEY_EVENT_RET, &ev.to_string())?;
        store::meta_set(conn, KEY_AGG_RET, &ag.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn mem() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        db::migrate(&mut conn).unwrap();
        conn
    }

    #[test]
    fn defaults_are_off_7_90() {
        let conn = mem();
        let s = ObservabilitySettings::load(&conn).unwrap();
        assert_eq!(s.default_mode, ObservationMode::Off);
        assert_eq!(s.event_retention_days, 7);
        assert_eq!(s.aggregate_retention_days, 90);
    }

    #[test]
    fn roundtrips_and_clamps() {
        let conn = mem();
        let s = ObservabilitySettings {
            default_mode: ObservationMode::Metadata,
            event_retention_days: 9999, // clamped to 90
            aggregate_retention_days: 1, // clamped to 7
        };
        s.save(&conn).unwrap();
        let loaded = ObservabilitySettings::load(&conn).unwrap();
        assert_eq!(loaded.default_mode, ObservationMode::Metadata);
        assert_eq!(loaded.event_retention_days, 90);
        assert_eq!(loaded.aggregate_retention_days, 7);
    }
}
