//! SQLite storage with versioned migrations.
//!
//! The schema version is tracked in SQLite's `user_version` pragma. Each
//! migration runs inside a transaction; the version is only bumped when the
//! whole migration succeeds. Migrations are append-only: existing entries
//! must never be edited once released.

use crate::error::Result;
use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial schema",
        sql: r#"
CREATE TABLE vault_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE projects (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL COLLATE NOCASE UNIQUE,
    description         TEXT NOT NULL DEFAULT '',
    notes               TEXT NOT NULL DEFAULT '',
    environments        TEXT NOT NULL DEFAULT '[]',
    archived            INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    wrapped_project_key BLOB NOT NULL,
    key_wrap_mode       TEXT NOT NULL CHECK (key_wrap_mode IN ('vault', 'vault+password')),
    project_kdf_params  TEXT,
    project_salt        BLOB
) STRICT;

CREATE TABLE project_repos (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    path       TEXT NOT NULL,
    PRIMARY KEY (project_id, path)
) STRICT;

CREATE TABLE credentials (
    id                   TEXT PRIMARY KEY,
    project_id           TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    provider             TEXT NOT NULL,
    name                 TEXT NOT NULL COLLATE NOCASE,
    environment          TEXT NOT NULL DEFAULT 'development',
    credential_type      TEXT NOT NULL DEFAULT 'api_key',
    ciphertext           BLOB,
    linked_credential_id TEXT REFERENCES credentials(id),
    fingerprint          BLOB NOT NULL,
    masked_value         TEXT NOT NULL,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL,
    key_created_at       TEXT,
    expires_at           TEXT,
    last_validated_at    TEXT,
    last_used_at         TEXT,
    docs_url             TEXT NOT NULL DEFAULT '',
    notes                TEXT NOT NULL DEFAULT '',
    manually_disabled    INTEGER NOT NULL DEFAULT 0,
    revoked              INTEGER NOT NULL DEFAULT 0,
    marked_invalid       INTEGER NOT NULL DEFAULT 0,
    possibly_exposed     INTEGER NOT NULL DEFAULT 0,
    exposure_note        TEXT NOT NULL DEFAULT '',
    UNIQUE (project_id, name),
    CHECK ((ciphertext IS NULL) != (linked_credential_id IS NULL))
) STRICT;

CREATE INDEX idx_credentials_fingerprint ON credentials(fingerprint);
CREATE INDEX idx_credentials_project ON credentials(project_id);

CREATE TABLE audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    at            TEXT NOT NULL,
    event         TEXT NOT NULL,
    project_id    TEXT,
    credential_id TEXT,
    detail        TEXT NOT NULL DEFAULT ''
) STRICT;
"#,
    },
    Migration {
        version: 2,
        name: "scanning, alerts, and documentation watches",
        sql: r#"
-- Local scan suppressions. suppression_key is a non-secret hash of
-- (rule|path|redacted-preview); no credential value is stored here.
CREATE TABLE scan_suppressions (
    id              TEXT PRIMARY KEY,
    suppression_key TEXT NOT NULL UNIQUE,
    rule            TEXT NOT NULL,
    path            TEXT NOT NULL,
    reason          TEXT NOT NULL,
    created_at      TEXT NOT NULL
) STRICT;

-- Local alerts with lifecycle. dedup_key keeps one open alert per condition.
CREATE TABLE alerts (
    id                 TEXT PRIMARY KEY,
    kind               TEXT NOT NULL,
    severity           TEXT NOT NULL,
    dedup_key          TEXT NOT NULL,
    title              TEXT NOT NULL,
    detail             TEXT NOT NULL,
    evidence           TEXT NOT NULL DEFAULT '',
    confidence         TEXT NOT NULL,
    recommended_action TEXT NOT NULL DEFAULT '',
    project_id         TEXT,
    credential_id      TEXT,
    created_at         TEXT NOT NULL,
    observed_at        TEXT NOT NULL,
    acknowledged_at    TEXT,
    resolved_at        TEXT
) STRICT;

CREATE UNIQUE INDEX idx_alerts_open_dedup ON alerts(dedup_key) WHERE resolved_at IS NULL;
CREATE INDEX idx_alerts_open ON alerts(resolved_at);

-- Watched official documentation URLs and their conditional-request state.
CREATE TABLE doc_watches (
    id              TEXT PRIMARY KEY,
    provider        TEXT NOT NULL,
    url             TEXT NOT NULL UNIQUE,
    etag            TEXT,
    last_modified   TEXT,
    content_hash    TEXT,
    last_checked_at TEXT,
    last_changed_at TEXT,
    last_status     TEXT NOT NULL DEFAULT 'never checked',
    created_at      TEXT NOT NULL
) STRICT;
"#,
    },
    Migration {
        version: 3,
        name: "provider integrations: usage, pricing, permissions, activity, injection",
        sql: r#"
-- Monetary amounts are integer micro-USD (1 USD = 1_000_000) to avoid float
-- rounding. Budgets are user-facing dollars stored the same way.
ALTER TABLE projects ADD COLUMN monthly_budget_micros INTEGER;
ALTER TABLE credentials ADD COLUMN monthly_budget_micros INTEGER;

-- Provider connection state: which vault credential (if any) is the admin key
-- used for usage sync, and the last sync result.
CREATE TABLE provider_connections (
    provider            TEXT PRIMARY KEY,
    admin_credential_id TEXT REFERENCES credentials(id) ON DELETE SET NULL,
    last_synced_at      TEXT,
    last_status         TEXT NOT NULL DEFAULT 'never',
    detail              TEXT NOT NULL DEFAULT ''
) STRICT;

-- Normalized usage snapshots. attribution records the precision honestly.
CREATE TABLE usage_snapshots (
    id                   TEXT PRIMARY KEY,
    credential_id        TEXT REFERENCES credentials(id) ON DELETE CASCADE,
    project_id           TEXT REFERENCES projects(id) ON DELETE CASCADE,
    provider             TEXT NOT NULL,
    model                TEXT,
    window_start         TEXT NOT NULL,
    window_end           TEXT NOT NULL,
    request_count        INTEGER,
    input_tokens         INTEGER,
    output_tokens        INTEGER,
    total_tokens         INTEGER,
    credits              REAL,
    reported_cost_micros INTEGER,
    estimated_cost_micros INTEGER,
    currency             TEXT NOT NULL DEFAULT 'USD',
    source               TEXT NOT NULL,
    attribution          TEXT NOT NULL,
    collected_at         TEXT NOT NULL
) STRICT;
CREATE INDEX idx_usage_credential ON usage_snapshots(credential_id);
CREATE INDEX idx_usage_project ON usage_snapshots(project_id);
CREATE INDEX idx_usage_window ON usage_snapshots(window_start);

-- Manual pricing overrides (bundled prices live in code with source + dates).
CREATE TABLE pricing_overrides (
    id                          TEXT PRIMARY KEY,
    provider                    TEXT NOT NULL,
    model                       TEXT NOT NULL,
    unit                        TEXT NOT NULL,
    input_price_per_m_micros    INTEGER,
    output_price_per_m_micros   INTEGER,
    currency                    TEXT NOT NULL DEFAULT 'USD',
    note                        TEXT NOT NULL DEFAULT '',
    created_at                  TEXT NOT NULL,
    UNIQUE (provider, model)
) STRICT;

-- Normalized permissions with raw scopes preserved.
CREATE TABLE credential_permissions (
    credential_id TEXT PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
    raw_scopes    TEXT NOT NULL,
    normalized    TEXT NOT NULL,
    source        TEXT NOT NULL,
    precision     TEXT NOT NULL,
    confidence    TEXT NOT NULL,
    synced_at     TEXT NOT NULL
) STRICT;

-- Normalized local activity events feeding suspicious-activity rules.
CREATE TABLE activity_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    at            TEXT NOT NULL,
    source        TEXT NOT NULL,
    kind          TEXT NOT NULL,
    credential_id TEXT,
    project_id    TEXT,
    detail        TEXT NOT NULL DEFAULT '',
    measurements  TEXT NOT NULL DEFAULT ''
) STRICT;

-- Project credential -> environment-variable injection mappings.
CREATE TABLE credential_env_mappings (
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    env_var       TEXT NOT NULL,
    PRIMARY KEY (project_id, env_var)
) STRICT;

-- Local record of process-injection sessions (names only, never values).
CREATE TABLE process_sessions (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    ended_at      TEXT,
    command       TEXT NOT NULL,
    injected_vars TEXT NOT NULL,
    exit_code     INTEGER
) STRICT;
"#,
    },
];

/// Open (or create) the database file with hardened pragmas.
pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    configure(&conn)?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<()> {
    // WAL for safe concurrent access from the desktop app and CLI.
    conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
    conn.pragma_update(None, "foreign_keys", 1)?;
    // Overwrite deleted rows so removed (encrypted) data does not linger.
    conn.pragma_update(None, "secure_delete", 1)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(())
}

pub fn user_version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

pub fn migrate(conn: &mut Connection) -> Result<()> {
    migrate_with(conn, MIGRATIONS)
}

pub fn migrate_with(conn: &mut Connection, migrations: &[Migration]) -> Result<()> {
    for migration in migrations {
        let current = user_version(conn)?;
        if migration.version <= current {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(migration.sql)?;
        tx.pragma_update(None, "user_version", migration.version)?;
        tx.commit()?;
    }
    Ok(())
}

/// The schema version this build reads and writes.
pub fn current_schema_version() -> i64 {
    MIGRATIONS.last().map(|m| m.version).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        configure(&conn).unwrap();
        conn
    }

    #[test]
    fn migrations_apply_and_record_version() {
        let mut conn = mem();
        migrate(&mut conn).unwrap();
        assert_eq!(user_version(&conn).unwrap(), current_schema_version());
        for table in [
            "vault_meta",
            "projects",
            "project_repos",
            "credentials",
            "audit_events",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing table {table}");
        }
    }

    #[test]
    fn migrations_are_idempotent() {
        let mut conn = mem();
        migrate(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(user_version(&conn).unwrap(), current_schema_version());
    }

    #[test]
    fn migrations_apply_incrementally() {
        let mut conn = mem();
        let steps = [
            Migration {
                version: 1,
                name: "one",
                sql: "CREATE TABLE a (x INTEGER);",
            },
            Migration {
                version: 2,
                name: "two",
                sql: "CREATE TABLE b (y INTEGER);",
            },
        ];
        migrate_with(&mut conn, &steps[..1]).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 1);
        migrate_with(&mut conn, &steps).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 2);
        conn.execute("INSERT INTO a (x) VALUES (1)", []).unwrap();
        conn.execute("INSERT INTO b (y) VALUES (1)", []).unwrap();
    }

    #[test]
    fn failed_migration_rolls_back() {
        let mut conn = mem();
        let steps = [Migration {
            version: 1,
            name: "broken",
            sql: "CREATE TABLE ok_table (x INTEGER); CREATE TABLE bad syntax error;",
        }];
        assert!(migrate_with(&mut conn, &steps).is_err());
        assert_eq!(user_version(&conn).unwrap(), 0);
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='ok_table'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "partial migration must roll back");
    }
}
