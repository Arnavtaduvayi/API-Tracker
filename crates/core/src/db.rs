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
    Migration {
        version: 8,
        name: "versioned pricing records",
        sql: r#"
-- Effective-dated pricing records (imported files and manual overrides;
-- the bundled table lives in code with the same shape). History is
-- append-only by design: estimation resolves the record effective at the
-- usage date, so new prices never silently reprice older usage.
CREATE TABLE pricing_records (
    id        TEXT PRIMARY KEY,
    provider  TEXT NOT NULL,
    model     TEXT NOT NULL,
    unit      TEXT NOT NULL DEFAULT 'tokens',
    input_price_per_m_micros        INTEGER,
    cached_input_price_per_m_micros INTEGER,
    output_price_per_m_micros       INTEGER,
    batch_input_price_per_m_micros  INTEGER,
    batch_output_price_per_m_micros INTEGER,
    per_request_micros INTEGER,
    currency  TEXT NOT NULL DEFAULT 'USD',
    source    TEXT NOT NULL DEFAULT '',
    effective_from TEXT NOT NULL,
    last_verified  TEXT NOT NULL,
    origin    TEXT NOT NULL,
    version   INTEGER NOT NULL DEFAULT 1,
    note      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(provider, model, origin, effective_from)
) STRICT;

-- Preserve legacy manual overrides. They predate effective dating, so they
-- keep their historical semantics: applying to all usage dates.
INSERT INTO pricing_records (id, provider, model, unit, input_price_per_m_micros,
    output_price_per_m_micros, currency, source, effective_from, last_verified,
    origin, version, note, created_at)
SELECT id, provider, model, unit, input_price_per_m_micros, output_price_per_m_micros,
    currency, 'manual override (' || note || ')', '1970-01-01', substr(created_at, 1, 10),
    'override', 1, note, created_at
FROM pricing_overrides;
DROP TABLE pricing_overrides;
"#,
    },
    Migration {
        version: 9,
        name: "project templates and local stack-detection preferences",
        sql: r#"
-- Which templates were applied to which projects (informational).
CREATE TABLE project_templates (
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    template_id TEXT NOT NULL,
    applied_at  TEXT NOT NULL,
    PRIMARY KEY (project_id, template_id)
) STRICT;

-- Locally learned stack-detection decisions: the user's explicit
-- confirm/dismiss history per repository and template. Deterministic
-- rules + this table are the entire "learning" mechanism (no ML), and the
-- table can be reset or cleared entirely at any time.
CREATE TABLE stack_preferences (
    repo_path   TEXT NOT NULL,
    template_id TEXT NOT NULL,
    decision    TEXT NOT NULL,
    decided_at  TEXT NOT NULL,
    PRIMARY KEY (repo_path, template_id)
) STRICT;
"#,
    },
    Migration {
        version: 10,
        name: "provider-account metadata (official endpoints only)",
        sql: r#"
-- Account identity reported by official provider endpoints (GitHub /user,
-- Stripe /v1/account, Supabase /v1/organizations, Anthropic
-- /v1/organizations/me). Only provider-reported values are stored, with
-- their source and sync time; nothing is derived from credential
-- appearance, and no login/password material exists anywhere.
ALTER TABLE provider_connections ADD COLUMN account_id TEXT;
ALTER TABLE provider_connections ADD COLUMN account_email TEXT;
ALTER TABLE provider_connections ADD COLUMN account_name TEXT;
ALTER TABLE provider_connections ADD COLUMN account_plan TEXT;
ALTER TABLE provider_connections ADD COLUMN account_source TEXT;
ALTER TABLE provider_connections ADD COLUMN account_synced_at TEXT;
"#,
    },
    Migration {
        version: 11,
        name: "process start identity for safe termination",
        sql: r#"
-- Platform-reported identity of the spawned process (start time + executable
-- name), captured at launch while the child handle is still held. Termination
-- re-probes this identity and refuses to signal when it does not match, so a
-- PID recycled to an unrelated process is never killed (PI-02). NULL means
-- identity could not be captured; such sessions are refused termination.
ALTER TABLE process_sessions ADD COLUMN proc_identity TEXT;
"#,
    },
    Migration {
        version: 12,
        name: "runtime api observability (metadata-only)",
        sql: r#"
-- Runtime API observability. These tables store ONLY sanitized operational
-- metadata about traffic observed by the local observation proxy: never
-- request/response bodies, header values, cookies, authorization values,
-- query strings, or raw URLs (see
-- docs/observability/RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md). They are kept
-- deliberately separate from usage_snapshots so locally observed request
-- counts are never summed with provider-reported usage.

-- One monitored run. `command`/`credential_names` are labels/names only.
-- `status` is running|completed|interrupted; an interrupted session is a
-- distinct, honestly-recorded state (vault locked, launcher gone, proxy
-- error) — a session is never silently marked completed.
CREATE TABLE observation_sessions (
    id                TEXT PRIMARY KEY,
    project_id        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    mode              TEXT NOT NULL,
    source            TEXT NOT NULL DEFAULT 'cli_run',
    status            TEXT NOT NULL DEFAULT 'running',
    interrupt_reason  TEXT,
    command           TEXT NOT NULL DEFAULT '',
    credential_names  TEXT NOT NULL DEFAULT '',
    runtime_detected  TEXT,
    trust_level       TEXT,
    partial_coverage  INTEGER NOT NULL DEFAULT 0,
    proxy_port        INTEGER,
    pid               INTEGER,
    proc_identity     TEXT,
    started_at        TEXT NOT NULL,
    ended_at          TEXT,
    exit_code         INTEGER
) STRICT;
CREATE INDEX idx_obs_sessions_project ON observation_sessions(project_id);
CREATE INDEX idx_obs_sessions_status ON observation_sessions(status);

-- One row per observed host (the automatic API inventory). provider_id is the
-- resolved manifest id when known; source labels how the row was learned;
-- user_* hold explicit user corrections that must be preserved.
CREATE TABLE observed_api_services (
    id             TEXT PRIMARY KEY,
    host           TEXT NOT NULL UNIQUE,
    provider_id    TEXT,
    source         TEXT NOT NULL DEFAULT 'locally_observed',
    classification TEXT NOT NULL DEFAULT 'external',
    is_internal    INTEGER NOT NULL DEFAULT 0,
    user_provider  TEXT,
    user_api_name  TEXT,
    user_notes     TEXT,
    confirmed      INTEGER NOT NULL DEFAULT 0,
    first_seen_at  TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL
) STRICT;

-- One row per (service, method, sanitized path template).
CREATE TABLE observed_endpoints (
    id                  TEXT PRIMARY KEY,
    service_id          TEXT NOT NULL REFERENCES observed_api_services(id) ON DELETE CASCADE,
    method              TEXT NOT NULL,
    path_template       TEXT NOT NULL,
    template_confidence TEXT NOT NULL DEFAULT 'high',
    first_seen_at       TEXT NOT NULL,
    last_seen_at        TEXT NOT NULL,
    UNIQUE (service_id, method, path_template)
) STRICT;

-- One sanitized request event. Short retention (default 7 days). Every column
-- here is on the privacy-model allowlist; there is deliberately no column able
-- to hold a body, header value, cookie, query string, or raw URL.
CREATE TABLE runtime_request_events (
    id                     TEXT PRIMARY KEY,
    session_id             TEXT NOT NULL REFERENCES observation_sessions(id) ON DELETE CASCADE,
    project_id             TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    service_id             TEXT NOT NULL REFERENCES observed_api_services(id) ON DELETE CASCADE,
    endpoint_id            TEXT REFERENCES observed_endpoints(id) ON DELETE CASCADE,
    at                     TEXT NOT NULL,
    host                   TEXT NOT NULL,
    port                   INTEGER NOT NULL,
    method                 TEXT NOT NULL,
    path_template          TEXT NOT NULL,
    template_confidence    TEXT NOT NULL DEFAULT 'high',
    status_code            INTEGER,
    status_class           TEXT NOT NULL DEFAULT 'none',
    outcome                TEXT NOT NULL,
    latency_ms             INTEGER,
    request_bytes          INTEGER,
    response_bytes         INTEGER,
    req_content_kind       TEXT,
    resp_content_kind      TEXT,
    had_authorization      INTEGER NOT NULL DEFAULT 0,
    protocol               TEXT NOT NULL,
    observation_source     TEXT NOT NULL,
    transport_error        TEXT NOT NULL DEFAULT 'none',
    previously_known       INTEGER NOT NULL DEFAULT 0,
    credential_id          TEXT REFERENCES credentials(id) ON DELETE SET NULL,
    attribution_confidence TEXT,
    credential_version     INTEGER,
    used_current_version   INTEGER
) STRICT;
CREATE INDEX idx_rre_session ON runtime_request_events(session_id);
CREATE INDEX idx_rre_service_at ON runtime_request_events(service_id, at);
CREATE INDEX idx_rre_at ON runtime_request_events(at);
CREATE INDEX idx_rre_project ON runtime_request_events(project_id);
CREATE INDEX idx_rre_credential ON runtime_request_events(credential_id);

-- Pre-aggregated hourly/daily counters + a fixed 14-bin latency histogram.
-- Longer retention (default 90 days). endpoint_id/credential_id use '' as the
-- "all" sentinel so the UNIQUE key works (SQLite treats NULLs as distinct).
CREATE TABLE runtime_metric_buckets (
    id                 TEXT PRIMARY KEY,
    granularity        TEXT NOT NULL,
    bucket_start       TEXT NOT NULL,
    project_id         TEXT NOT NULL,
    service_id         TEXT NOT NULL,
    endpoint_id        TEXT NOT NULL DEFAULT '',
    credential_id      TEXT NOT NULL DEFAULT '',
    credential_version INTEGER,
    total              INTEGER NOT NULL DEFAULT 0,
    c2xx               INTEGER NOT NULL DEFAULT 0,
    c3xx               INTEGER NOT NULL DEFAULT 0,
    c4xx               INTEGER NOT NULL DEFAULT 0,
    c5xx               INTEGER NOT NULL DEFAULT 0,
    auth_errors        INTEGER NOT NULL DEFAULT 0,
    forbidden          INTEGER NOT NULL DEFAULT 0,
    rate_limited       INTEGER NOT NULL DEFAULT 0,
    server_errors      INTEGER NOT NULL DEFAULT 0,
    transport_errors   INTEGER NOT NULL DEFAULT 0,
    tls_errors         INTEGER NOT NULL DEFAULT 0,
    request_bytes      INTEGER NOT NULL DEFAULT 0,
    response_bytes     INTEGER NOT NULL DEFAULT 0,
    lat_le_1           INTEGER NOT NULL DEFAULT 0,
    lat_le_2           INTEGER NOT NULL DEFAULT 0,
    lat_le_5           INTEGER NOT NULL DEFAULT 0,
    lat_le_10          INTEGER NOT NULL DEFAULT 0,
    lat_le_25          INTEGER NOT NULL DEFAULT 0,
    lat_le_50          INTEGER NOT NULL DEFAULT 0,
    lat_le_100         INTEGER NOT NULL DEFAULT 0,
    lat_le_250         INTEGER NOT NULL DEFAULT 0,
    lat_le_500         INTEGER NOT NULL DEFAULT 0,
    lat_le_1000        INTEGER NOT NULL DEFAULT 0,
    lat_le_2500        INTEGER NOT NULL DEFAULT 0,
    lat_le_5000        INTEGER NOT NULL DEFAULT 0,
    lat_le_10000       INTEGER NOT NULL DEFAULT 0,
    lat_gt_10000       INTEGER NOT NULL DEFAULT 0,
    first_at           TEXT,
    last_at            TEXT,
    UNIQUE (granularity, bucket_start, project_id, service_id, endpoint_id, credential_id)
) STRICT;
CREATE INDEX idx_rmb_lookup ON runtime_metric_buckets(service_id, granularity, bucket_start);
CREATE INDEX idx_rmb_project ON runtime_metric_buckets(project_id);

-- Per-session credential attribution rollup, with confidence + evidence and
-- the launch-time version (so "old version after rotation" is provable).
CREATE TABLE credential_traffic_attributions (
    session_id           TEXT NOT NULL REFERENCES observation_sessions(id) ON DELETE CASCADE,
    credential_id        TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    service_id           TEXT NOT NULL REFERENCES observed_api_services(id) ON DELETE CASCADE,
    request_count        INTEGER NOT NULL DEFAULT 0,
    confidence           TEXT NOT NULL,
    evidence             TEXT NOT NULL DEFAULT '',
    credential_version   INTEGER,
    used_current_version INTEGER,
    updated_at           TEXT NOT NULL,
    PRIMARY KEY (session_id, credential_id, service_id)
) STRICT;

-- Honest per-session compatibility diagnosis (trust support, proxy conflict,
-- pinning/bypass symptoms, cleanup). `check_name` avoids the SQL keyword.
CREATE TABLE observation_compatibility_results (
    session_id TEXT NOT NULL REFERENCES observation_sessions(id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    status     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    at         TEXT NOT NULL,
    PRIMARY KEY (session_id, check_name)
) STRICT;

-- Singleton local-CA state. The CA PRIVATE KEY is stored ONLY as vault-key
-- ciphertext (key_ciphertext); the certificate (ca_cert_pem) is public. The
-- CHECK enforces a single row.
CREATE TABLE observe_certificate_state (
    id                 TEXT PRIMARY KEY CHECK (id = 'ca'),
    ca_cert_pem        TEXT NOT NULL,
    key_ciphertext     BLOB NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    serial             TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    not_after          TEXT NOT NULL,
    system_trust       TEXT NOT NULL DEFAULT 'absent',
    system_trust_at    TEXT
) STRICT;

-- Explicit per-project internal-destination allowlist (bypasses the private-
-- range denial for exactly these host:port pairs; surfaced with a warning).
CREATE TABLE observe_internal_allowlist (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, host, port)
) STRICT;

-- Rolling baselines for warm-up / regression alert rules (latency, volume).
CREATE TABLE runtime_alert_baselines (
    rule_key     TEXT NOT NULL,
    metric       TEXT NOT NULL,
    value        REAL NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    window_start TEXT,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (rule_key, metric)
) STRICT;
"#,
    },
];

/// Open (or create) the database file with hardened pragmas.
pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    configure(&conn)?;
    restrict_db_permissions(path);
    Ok(conn)
}

/// Owner-only permissions on the database and its WAL/SHM sidecars
/// (defense in depth on top of the 0700 data directory). Best-effort;
/// a no-op on non-Unix, where OS-inherited ACLs govern (documented).
fn restrict_db_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for candidate in [
            path.to_path_buf(),
            path.with_extension("db-wal"),
            path.with_extension("db-shm"),
        ] {
            if candidate.exists() {
                let _ =
                    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Checkpoint and truncate the WAL so committed frames (which may hold
/// pages from before a key rotation or secure delete) do not linger in the
/// sidecar file. Best-effort by design: with a concurrent reader the
/// checkpoint degrades gracefully instead of failing the caller.
pub fn checkpoint_truncate(conn: &Connection) {
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
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
