//! Vault-level settings, stored as rows in `vault_meta`.

use crate::error::{CoreError, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSettings {
    /// Inactivity period after which the vault locks itself (desktop) or the
    /// CLI session expires. 0 disables auto-lock.
    pub auto_lock_minutes: u32,
    /// Days before a user-entered expiration date at which a credential is
    /// classified as expiring soon.
    pub expiring_soon_days: u32,
    /// Days after creation without any recorded use before a credential is
    /// classified as unused.
    pub unused_days: u32,
    /// Days since the last recorded use/validation before a credential is
    /// classified as stale.
    pub stale_days: u32,
    /// Best-effort clipboard clear delay after copying a secret. 0 disables.
    pub clipboard_clear_seconds: u32,
    /// Days after the last successful provider sync before synchronized
    /// data is flagged stale (connected providers only). 0 disables.
    pub provider_stale_days: u32,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 15,
            expiring_soon_days: 14,
            unused_days: 30,
            stale_days: 90,
            clipboard_clear_seconds: 30,
            provider_stale_days: 3,
        }
    }
}

const KEYS: [&str; 6] = [
    "auto_lock_minutes",
    "expiring_soon_days",
    "unused_days",
    "stale_days",
    "clipboard_clear_seconds",
    "provider_stale_days",
];

impl VaultSettings {
    pub fn load(conn: &Connection) -> Result<Self> {
        let mut settings = VaultSettings::default();
        let mut stmt = conn.prepare("SELECT value FROM vault_meta WHERE key = ?1")?;
        for key in KEYS {
            let value: Option<String> =
                stmt.query_row([key], |row| row.get(0))
                    .map(Some)
                    .or_else(|e| match e {
                        rusqlite::Error::QueryReturnedNoRows => Ok(None),
                        other => Err(other),
                    })?;
            if let Some(v) = value {
                let parsed: u32 = v.parse().map_err(|_| {
                    CoreError::InvalidInput(format!("stored setting '{key}' is not a number"))
                })?;
                settings.set_field(key, parsed)?;
            }
        }
        Ok(settings)
    }

    pub fn save(&self, conn: &Connection) -> Result<()> {
        for key in KEYS {
            conn.execute(
                "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![key, self.get_field(key)?.to_string()],
            )?;
        }
        Ok(())
    }

    pub fn get_field(&self, key: &str) -> Result<u32> {
        match key {
            "auto_lock_minutes" => Ok(self.auto_lock_minutes),
            "expiring_soon_days" => Ok(self.expiring_soon_days),
            "unused_days" => Ok(self.unused_days),
            "stale_days" => Ok(self.stale_days),
            "clipboard_clear_seconds" => Ok(self.clipboard_clear_seconds),
            "provider_stale_days" => Ok(self.provider_stale_days),
            other => Err(CoreError::InvalidInput(format!(
                "unknown setting '{other}'"
            ))),
        }
    }

    pub fn set_field(&mut self, key: &str, value: u32) -> Result<()> {
        match key {
            "auto_lock_minutes" => self.auto_lock_minutes = value,
            "expiring_soon_days" => self.expiring_soon_days = value,
            "unused_days" => self.unused_days = value,
            "stale_days" => self.stale_days = value,
            "clipboard_clear_seconds" => self.clipboard_clear_seconds = value,
            "provider_stale_days" => self.provider_stale_days = value,
            other => {
                return Err(CoreError::InvalidInput(format!(
                    "unknown setting '{other}'"
                )));
            }
        }
        Ok(())
    }

    pub fn known_keys() -> &'static [&'static str] {
        &KEYS
    }
}

/// Shared auto-lock rule used by the desktop app (in-memory lock) and the CLI
/// (session file expiry).
pub fn should_auto_lock(
    last_activity: OffsetDateTime,
    now: OffsetDateTime,
    auto_lock_minutes: u32,
) -> bool {
    if auto_lock_minutes == 0 {
        return false;
    }
    now - last_activity >= time::Duration::minutes(i64::from(auto_lock_minutes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::now;

    #[test]
    fn auto_lock_threshold() {
        let t0 = now();
        assert!(!should_auto_lock(t0, t0 + time::Duration::minutes(14), 15));
        assert!(should_auto_lock(t0, t0 + time::Duration::minutes(15), 15));
        assert!(should_auto_lock(t0, t0 + time::Duration::hours(2), 15));
    }

    #[test]
    fn auto_lock_disabled_with_zero() {
        let t0 = now();
        assert!(!should_auto_lock(t0, t0 + time::Duration::days(365), 0));
    }
}
