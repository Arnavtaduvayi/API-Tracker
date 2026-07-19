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
    Migration {
        version: 4,
        name: "openai admin connection, sync checkpoints, provider key mapping",
        sql: r#"
-- A dedicated, vault-encrypted administrative provider connection. The admin
-- key is encrypted under the vault key (AAD binds vault + provider); it is
-- vault-level state, deliberately separate from ordinary project credentials.
-- admin_credential_id (v3) remains as a legacy fallback.
ALTER TABLE provider_connections ADD COLUMN admin_key_ciphertext BLOB;
ALTER TABLE provider_connections ADD COLUMN admin_key_masked TEXT;
ALTER TABLE provider_connections ADD COLUMN org_label TEXT;
ALTER TABLE provider_connections ADD COLUMN connected_at TEXT;
ALTER TABLE provider_connections ADD COLUMN last_success_at TEXT;
ALTER TABLE provider_connections ADD COLUMN last_failure_at TEXT;
ALTER TABLE provider_connections ADD COLUMN last_error TEXT NOT NULL DEFAULT '';

-- Provider-side dimensions on usage snapshots. NULL means the provider did
-- not report that dimension — values are never invented locally.
ALTER TABLE usage_snapshots ADD COLUMN provider_account_id TEXT;
ALTER TABLE usage_snapshots ADD COLUMN provider_project_id TEXT;
ALTER TABLE usage_snapshots ADD COLUMN provider_api_key_id TEXT;
ALTER TABLE usage_snapshots ADD COLUMN line_item TEXT;
CREATE INDEX idx_usage_provider_key ON usage_snapshots(provider_api_key_id);

-- Confirmed association between a provider-side API-key id and a vault
-- credential. source records the evidence ('user_confirmed'); suggestions
-- (e.g. redacted-value matches) are computed live and never stored as links.
CREATE TABLE provider_key_links (
    provider            TEXT NOT NULL,
    provider_api_key_id TEXT NOT NULL,
    credential_id       TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    source              TEXT NOT NULL,
    evidence            TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL,
    PRIMARY KEY (provider, provider_api_key_id)
) STRICT;

-- Cached provider-side metadata (non-secret): organization projects and the
-- API keys the provider lists for them (redacted values only).
CREATE TABLE provider_side_projects (
    provider    TEXT NOT NULL,
    project_id  TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',
    synced_at   TEXT NOT NULL,
    PRIMARY KEY (provider, project_id)
) STRICT;

CREATE TABLE provider_side_keys (
    provider            TEXT NOT NULL,
    api_key_id          TEXT NOT NULL,
    provider_project_id TEXT,
    name                TEXT NOT NULL DEFAULT '',
    redacted_value      TEXT NOT NULL DEFAULT '',
    created_at          TEXT,
    last_used_at        TEXT,
    synced_at           TEXT NOT NULL,
    PRIMARY KEY (provider, api_key_id)
) STRICT;

-- Synchronization checkpoints: the last successfully synced window per
-- provider + endpoint kind ('usage' / 'costs').
CREATE TABLE provider_sync_state (
    provider     TEXT NOT NULL,
    kind         TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end   TEXT NOT NULL,
    synced_at    TEXT NOT NULL,
    PRIMARY KEY (provider, kind)
) STRICT;
"#,
    },
    Migration {
        version: 5,
        name: "env governance, credential versions, destinations, sync plans",
        sql: r#"
-- Prior credential values, retained encrypted (same project key; AAD binds
-- vault, project, credential, and version number) so synchronization plans
-- can roll a destination back. Purged when the credential is deleted.
CREATE TABLE credential_versions (
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    version       INTEGER NOT NULL,
    ciphertext    BLOB NOT NULL,
    masked_value  TEXT NOT NULL,
    fingerprint   BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    reason        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (credential_id, version)
) STRICT;

-- The current version number of each credential's value. Starts at 1.
ALTER TABLE credentials ADD COLUMN value_version INTEGER NOT NULL DEFAULT 1;

-- Exported .env files (explicit, reauthentication-gated). Values are never
-- stored here — only where an export went, which variable NAMES it holds,
-- a content hash for safe cleanup, and an optional expiry for temporary
-- exports.
CREATE TABLE env_exports (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    path         TEXT NOT NULL,
    var_names    TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    cleaned_at   TEXT
) STRICT;

-- Configured secret destinations (where credential values are deployed).
-- kind is the adapter id (aws_secrets_manager, github_actions, vercel,
-- macos_keychain, ...). auth_ciphertext holds the destination's own
-- administrative credential encrypted under the vault key (AAD binds vault
-- and destination id); it is write-only, like provider admin keys.
CREATE TABLE destinations (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    name            TEXT NOT NULL COLLATE NOCASE UNIQUE,
    config          TEXT NOT NULL DEFAULT '{}',
    auth_ciphertext BLOB,
    auth_masked     TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    last_verified_at TEXT,
    last_error      TEXT NOT NULL DEFAULT ''
) STRICT;

-- Which credential is deployed to which destination, under what name.
CREATE TABLE credential_destinations (
    credential_id       TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    destination_id      TEXT NOT NULL REFERENCES destinations(id) ON DELETE CASCADE,
    secret_name         TEXT NOT NULL,
    environment         TEXT NOT NULL DEFAULT '',
    last_synced_version INTEGER,
    last_synced_at      TEXT,
    last_verified_at    TEXT,
    drift               TEXT NOT NULL DEFAULT 'unknown',
    PRIMARY KEY (credential_id, destination_id, secret_name)
) STRICT;

-- Synchronization plans: a reviewable, per-destination rollout of a
-- credential value change. Plans store version NUMBERS and masked values
-- only, never plaintext.
CREATE TABLE sync_plans (
    id            TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    from_version  INTEGER,
    to_version    INTEGER NOT NULL,
    created_at    TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'planned',
    note          TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE TABLE sync_plan_steps (
    plan_id        TEXT NOT NULL REFERENCES sync_plans(id) ON DELETE CASCADE,
    destination_id TEXT NOT NULL,
    secret_name    TEXT NOT NULL,
    environment    TEXT NOT NULL DEFAULT '',
    action         TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'planned',
    detail         TEXT NOT NULL DEFAULT '',
    executed_at    TEXT,
    verified_at    TEXT,
    rolled_back_at TEXT,
    PRIMARY KEY (plan_id, destination_id, secret_name)
) STRICT;
"#,
    },
    Migration {
        version: 6,
        name: "rotation workflows, access grants, provider expiry, schedules",
        sql: r#"
-- Expiration reported by the PROVIDER (e.g. GitHub's token-expiration
-- header), distinct from the user-entered expires_at.
ALTER TABLE credentials ADD COLUMN provider_expires_at TEXT;

-- Durable credential-rotation workflows. Values never appear here — only
-- version NUMBERS, provider-side ids, and state. Survives restarts; every
-- transition is recorded in rotation_events.
CREATE TABLE rotations (
    id                  TEXT PRIMARY KEY,
    credential_id       TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    state               TEXT NOT NULL,
    mode                TEXT NOT NULL,
    note                TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    approved_at         TEXT,
    old_version         INTEGER,
    new_version         INTEGER,
    sync_plan_id        TEXT,
    grace_minutes       INTEGER NOT NULL DEFAULT 0,
    grace_ends_at       TEXT,
    old_provider_key_id TEXT,
    new_provider_key_id TEXT,
    provider_project_id TEXT,
    new_value_validated INTEGER NOT NULL DEFAULT 0,
    old_disabled_at     TEXT,
    old_revoked_at      TEXT,
    last_error          TEXT NOT NULL DEFAULT '',
    manual_instructions TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX idx_rotations_credential ON rotations(credential_id);

CREATE TABLE rotation_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rotation_id TEXT NOT NULL REFERENCES rotations(id) ON DELETE CASCADE,
    at          TEXT NOT NULL,
    from_state  TEXT NOT NULL,
    to_state    TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT ''
) STRICT;

-- Scheduled rotation: recorded intent + due dates. Execution is NEVER
-- automatic — due schedules raise an alert/notification and every
-- destructive step still requires reauthentication and confirmation.
CREATE TABLE rotation_schedules (
    credential_id TEXT PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
    interval_days INTEGER NOT NULL,
    next_due_at   TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    paused_reason TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    last_completed_rotation_id TEXT
) STRICT;

-- Child PID and grant linkage for injection sessions, so a temporary
-- access session can be terminated and audited. Names/ids only.
ALTER TABLE process_sessions ADD COLUMN pid INTEGER;
ALTER TABLE process_sessions ADD COLUMN grant_id TEXT;

-- Temporary LOCAL access grants for secure process injection. These bound
-- what `api-tracker run` will inject and for how long; they do not (and
-- never claim to) constrain the provider-side credential.
CREATE TABLE access_grants (
    id                 TEXT PRIMARY KEY,
    project_id         TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    label              TEXT NOT NULL DEFAULT '',
    credential_ids     TEXT NOT NULL DEFAULT '',
    expires_at         TEXT NOT NULL,
    max_launches       INTEGER NOT NULL DEFAULT 0,
    launches_used      INTEGER NOT NULL DEFAULT 0,
    max_duration_secs  INTEGER,
    budget_warn_micros INTEGER,
    created_at         TEXT NOT NULL,
    revoked_at         TEXT
) STRICT;
"#,
    },
    Migration {
        version: 7,
        name: "observability: units, first-seen, doc history, repo state, channels",
        sql: r#"
-- Non-token usage units (requests, credits, bytes, transactions, ...).
-- quantity/unit carry what the provider reported, verbatim; the token and
-- request columns remain for providers that use them.
ALTER TABLE usage_snapshots ADD COLUMN quantity REAL;
ALTER TABLE usage_snapshots ADD COLUMN unit TEXT;

-- When a provider-side entity was FIRST seen locally (synced_at moves on
-- every sync; first_seen_at does not). Pre-existing rows are backfilled
-- with the epoch — "existed before tracking began" — so the upgrade does
-- not flood users with false "new key appeared" alerts.
ALTER TABLE provider_side_keys ADD COLUMN first_seen_at TEXT;
ALTER TABLE provider_side_projects ADD COLUMN first_seen_at TEXT;
UPDATE provider_side_keys SET first_seen_at = '1970-01-01T00:00:00Z' WHERE first_seen_at IS NULL;
UPDATE provider_side_projects SET first_seen_at = '1970-01-01T00:00:00Z' WHERE first_seen_at IS NULL;

-- Documentation-watch change history (validators/hashes only, no content).
CREATE TABLE doc_watch_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT NOT NULL,
    provider   TEXT NOT NULL DEFAULT '',
    at         TEXT NOT NULL,
    outcome    TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX idx_doc_history_url ON doc_watch_history(url);

-- Incremental repository scanning: the last commit each registered repo
-- was scanned at, so background checks only look at NEW commits.
CREATE TABLE repo_scan_state (
    repo_path         TEXT PRIMARY KEY,
    last_scanned_commit TEXT NOT NULL,
    last_scan_at      TEXT NOT NULL,
    last_findings     INTEGER NOT NULL DEFAULT 0
) STRICT;

-- User-configured notification channels (webhooks). The URL may embed a
-- user-chosen token, so it is encrypted under the vault key and masked for
-- display. Payloads carry alert metadata only — alerts are secret-free by
-- construction.
CREATE TABLE notification_channels (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL COLLATE NOCASE UNIQUE,
    kind            TEXT NOT NULL DEFAULT 'webhook',
    url_ciphertext  BLOB NOT NULL,
    url_masked      TEXT NOT NULL,
    min_severity    TEXT NOT NULL DEFAULT 'high',
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    last_delivery_at TEXT,
    last_error      TEXT NOT NULL DEFAULT ''
) STRICT;

-- One row per (channel, alert): what was last delivered, so open alerts
-- are not re-posted on every monitor run. Re-delivery happens only when
-- the alert's severity escalates.
CREATE TABLE notification_deliveries (
    channel_id         TEXT NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    alert_id           TEXT NOT NULL,
    delivered_severity TEXT NOT NULL,
    delivered_at       TEXT NOT NULL,
    PRIMARY KEY (channel_id, alert_id)
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
    // A database from a NEWER build must not be opened read/write: this
    // build does not know the newer schema's invariants, and writing could
    // silently corrupt data the newer build depends on.
    let found = user_version(conn)?;
    let supported = migrations.last().map(|m| m.version).unwrap_or(0);
    if found > supported {
        return Err(crate::error::CoreError::SchemaTooNew { found, supported });
    }
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
