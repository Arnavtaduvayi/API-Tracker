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
"#,
    },
    Migration {
        version: 13,
        name: "local gateway (loopback reverse gateway, metadata-only)",
        sql: r#"
-- Local Gateway (ADR 0019). These tables store ONLY non-secret routing
-- configuration and sanitized usage metadata. Like the runtime observability
-- tables, no column can hold a body, header value, cookie, query string,
-- credential value, or raw URL. Gateway usage is kept out of usage_snapshots
-- so locally observed consumption is never summed with provider-reported
-- usage (double-count guard, KNOWN_CONFLICTS C8).

-- Singleton gateway configuration. The bind address is deliberately NOT a
-- column: the listener is hard-coded to loopback (SECURITY_INVARIANTS SI-1;
-- a host-configuration surface would be an invariant violation, so the
-- ARCHITECTURE.md sketch's `bind` field was dropped). `port` is a random
-- persisted high port chosen at enable time (ADR 0019 D8/O3), NULL until
-- then. `match_while_locked` is the consented, default-OFF fingerprint-key
-- retention toggle (ADR 0019 D5, OPEN_DECISIONS O2).
CREATE TABLE gateway_config (
    id                         TEXT PRIMARY KEY CHECK (id = 'gateway'),
    enabled                    INTEGER NOT NULL DEFAULT 0,
    port                       INTEGER,
    match_while_locked         INTEGER NOT NULL DEFAULT 0,
    service_version            TEXT,
    usage_event_retention_days INTEGER,
    usage_daily_retention_days INTEGER,
    created_at                 TEXT NOT NULL,
    updated_at                 TEXT NOT NULL
) STRICT;

-- Registered routes, keyed by the first path segment. Manifest routes store
-- NO origin at all — the upstream is resolved from the compiled-in provider
-- manifest at forward time, so no attacker-chosen destination can be written
-- into this same-uid-writable table (ADR 0019 D3, the route-row-tampering
-- blocker). Custom-origin routes store the origin string ONLY next to a MAC
-- over (vault_id, route_prefix, provider_id, origin, port, consent_ts)
-- computed under a vault-derived key at consent time; the gateway verifies
-- the MAC before forwarding and never obeys the bare DB value, so an edited
-- stored origin STOPS the route instead of redirecting it.
--
-- Scope limit (SEC-01 / NEW-49): provider_id IS stored here, is not covered
-- by any MAC for a manifest row, and selects which compiled-in origin a
-- built-in route resolves to. The three CHECK constraints below also let all
-- four custom columns go NULL together, which downgrades a MAC'd custom row
-- to the unauthenticated manifest path. Both need local write access to
-- vault.db and are an accepted, documented exclusion, not a defence — see
-- docs/gateway/SECURITY.md and docs/gateway/THREAT_MODEL.md GW-3.
CREATE TABLE gateway_routes (
    route_prefix             TEXT PRIMARY KEY,
    provider_id              TEXT NOT NULL,
    enabled                  INTEGER NOT NULL DEFAULT 1,
    custom_origin            TEXT,
    custom_origin_port       INTEGER,
    custom_origin_mac        BLOB,
    custom_origin_consent_at TEXT,
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL,
    CHECK ((custom_origin IS NULL) = (custom_origin_mac IS NULL)),
    CHECK ((custom_origin IS NULL) = (custom_origin_port IS NULL)),
    CHECK ((custom_origin IS NULL) = (custom_origin_consent_at IS NULL))
) STRICT;

-- Project links. `link_slug` is a >=128-bit CSPRNG value (never name-derived,
-- SI-4) that scopes /p/<slug>/<route> traffic to a project. `env_path` and
-- `prior_env_json` record what the .env onboarding rewrote so disable/unlink
-- can restore the exact prior state (ADR 0019 D9).
CREATE TABLE gateway_project_links (
    link_slug      TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    route_prefix   TEXT NOT NULL REFERENCES gateway_routes(route_prefix) ON DELETE CASCADE,
    env_path       TEXT,
    prior_env_json TEXT,
    created_at     TEXT NOT NULL,
    UNIQUE (project_id, route_prefix)
) STRICT;
CREATE INDEX idx_gpl_project ON gateway_project_links(project_id);

-- Best-effort usage extracted in flight from provider responses (bounded
-- extractor, PRIVACY_MODEL gateway §3). Raw events ride the short retention
-- window; gateway_usage_daily keeps the long series. `usage_state` records
-- WHY usage may be absent (absent | extracted | unsupported_shape |
-- oversized_dropped | malformed) so a missing number is never a silent zero.
-- `model` is length-capped and charset-filtered before insert; a hostile
-- model value stores NULL plus a model_rejected counter, never a truncated
-- attacker string.
CREATE TABLE gateway_usage_events (
    id                    TEXT PRIMARY KEY,
    event_id              TEXT REFERENCES runtime_request_events(id) ON DELETE SET NULL,
    at                    TEXT NOT NULL,
    route_prefix          TEXT NOT NULL,
    provider_id           TEXT NOT NULL,
    project_id            TEXT REFERENCES projects(id) ON DELETE CASCADE,
    model                 TEXT,
    input_tokens          INTEGER,
    output_tokens         INTEGER,
    total_tokens          INTEGER,
    cached_input_tokens   INTEGER,
    usage_available       INTEGER NOT NULL DEFAULT 0,
    usage_state           TEXT NOT NULL DEFAULT 'absent',
    estimated_cost_micros INTEGER,
    was_streamed          INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX idx_gue_at ON gateway_usage_events(at);
CREATE INDEX idx_gue_project ON gateway_usage_events(project_id);

-- ~90-day daily rollup of gateway usage (raw events expire sooner). '' is
-- the "all" sentinel for project_id/model, mirroring runtime_metric_buckets.
CREATE TABLE gateway_usage_daily (
    day                   TEXT NOT NULL,
    provider_id           TEXT NOT NULL,
    project_id            TEXT NOT NULL DEFAULT '',
    model                 TEXT NOT NULL DEFAULT '',
    request_count         INTEGER NOT NULL DEFAULT 0,
    usage_event_count     INTEGER NOT NULL DEFAULT 0,
    input_tokens          INTEGER NOT NULL DEFAULT 0,
    output_tokens         INTEGER NOT NULL DEFAULT 0,
    cached_input_tokens   INTEGER NOT NULL DEFAULT 0,
    estimated_cost_micros INTEGER NOT NULL DEFAULT 0,
    updated_at            TEXT NOT NULL,
    PRIMARY KEY (day, provider_id, project_id, model)
) STRICT;

-- Route-level daily counters: unlinked traffic, rejected browser writes
-- (the ONLY record a rejected request produces, THREAT_MODEL GW-2), dropped
-- observation events, and extraction/attribution accounting. route_prefix ''
-- holds gateway-global counters that have no route.
CREATE TABLE gateway_route_counters (
    route_prefix TEXT NOT NULL DEFAULT '',
    day          TEXT NOT NULL,
    counter      TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (route_prefix, day, counter)
) STRICT;

-- Distinguishes value-derived attribution (gateway keyed-fingerprint match,
-- 'observed_fingerprint') from injection-derived attribution ('injected'),
-- preserving the truth of attribution.rs's "never reads an Authorization
-- value" for the injection path (ADR 0019 D5). NULL on pre-v13 rows.
ALTER TABLE runtime_request_events ADD COLUMN attribution_method TEXT;
"#,
    },
    Migration {
        version: 14,
        name: "index gateway_usage_events.event_id (FK-scan cost)",
        sql: r#"
-- `gateway_usage_events.event_id` REFERENCES runtime_request_events(id) with
-- ON DELETE SET NULL, and foreign keys are enforced on every connection — so
-- with no index on the child key, SQLite full-scans gateway_usage_events once
-- PER deleted parent row. That fires on the hot path: the gateway's own
-- writer runs `retention::sweep` every 5 minutes, deleting a whole cohort of
-- expired runtime events at a time.
CREATE INDEX IF NOT EXISTS idx_gue_event ON gateway_usage_events(event_id);
"#,
    },
    Migration {
        version: 15,
        name: "tracking_setups (zero-friction tracking state machine)",
        sql: r#"
-- One row per (project, folder) tracking setup — the persisted product-level
-- state behind "Track API activity" / `tethra track` (ADR 0022 D8). The row
-- caches the state machine value; readers re-derive it against the
-- observation tables on every load, so a stale row can never overclaim
-- `traffic_observed` (SI-19). Contents carry NO SECRET VALUES: provider ids,
-- confidence labels, evidence kinds, and file paths — never a credential,
-- a header, a body, or wire data.
--
-- One NON-SECRET value is carried, deliberately: a repository-discovered
-- origin the user explicitly approved (`NeedsOriginConfirm.inferred_origin`,
-- read from a manifest-declared base-URL variable such as `SUPABASE_URL`).
-- It is a host name the user was shown verbatim at the approval point, and
-- undo needs it. This comment previously said "value-free", which the
-- crate's own test contradicts by asserting the host IS present
-- (audit finding `ZFT-047`).
CREATE TABLE tracking_setups (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    folder_path TEXT NOT NULL,            -- canonicalized at insert
    state TEXT NOT NULL,
    detection_json TEXT NOT NULL,
    plan_summary_json TEXT,
    applied_at TEXT,
    first_traffic_at TEXT,
    last_transition_at TEXT NOT NULL,
    attention_reason TEXT,
    UNIQUE(project_id, folder_path)
) STRICT;
CREATE INDEX IF NOT EXISTS idx_tracking_setups_project
    ON tracking_setups(project_id);
"#,
    },
    Migration {
        version: 16,
        name: "tracking verification sessions (current health vs historical verification)",
        sql: r#"
-- v15 collapsed several distinct facts into one durable `state` value plus a
-- `first_traffic_at` watermark, and the audit showed what that costs: a
-- setup stayed "tracking verified" after the gateway was killed, a FAILED
-- re-run was promoted back to verified by the PREVIOUS run's traffic, and
-- nulling one column skipped re-derivation entirely (ZFT-005, ZFT-006,
-- ZFT-008).
--
-- The fix separates them. Each apply or repair attempt opens a new
-- verification SESSION with its own non-secret id and its own generation
-- number; only observations recorded during the CURRENT session can verify
-- the CURRENT setup. Historical success keeps its own column so it can still
-- be displayed without implying present health, and a failure carries its own
-- timestamp so newer bad news is never erased by older good news.
--
-- All values remain non-secret: opaque ids, integers and RFC 3339 timestamps.
ALTER TABLE tracking_setups ADD COLUMN verification_session TEXT;
ALTER TABLE tracking_setups ADD COLUMN config_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tracking_setups ADD COLUMN first_verified_at TEXT;
ALTER TABLE tracking_setups ADD COLUMN attention_at TEXT;

-- Existing rows: carry the historical watermark across so an already-verified
-- user keeps their "first verified" date, and open a generation so the next
-- read re-derives against the new rules instead of trusting the cached value.
UPDATE tracking_setups SET first_verified_at = first_traffic_at
    WHERE first_traffic_at IS NOT NULL;
UPDATE tracking_setups SET attention_at = last_transition_at
    WHERE attention_reason IS NOT NULL;

-- The re-derivation query filters observations by project, source, session
-- window and freshness; this is the index that keeps it cheap.
CREATE INDEX IF NOT EXISTS idx_rre_project_source_at
    ON runtime_request_events(project_id, observation_source, at);
"#,
    },
    Migration {
        version: 17,
        name: "approved route origins (repository content is not authorization)",
        sql: r#"
-- Destinations a user has explicitly approved for API traffic (ADR 0024).
--
-- The audit showed a repository with no secrets in it — just a committed
-- `package.json` and a committed `SUPABASE_URL` — driving the creation of a
-- MAC'd, enabled route to an attacker-chosen host (ZFT-004). Project content
-- may suggest that an API exists; it may never authorize a destination.
-- Origins that come from a compiled-in Tethra manifest stay automatic;
-- origins read from project files need a row here first.
--
-- `mac` is a keyed BLAKE3 over (vault id, origin, provider id, approved_at)
-- using the vault's route MAC key, in the same length-prefixed shape as
-- `gateway_routes`. A hand-edited row fails verification and is treated as
-- ABSENT, so tampering downgrades to "ask the user again" rather than to
-- "silently trusted".
--
-- Contents are non-secret: a host name the user was shown verbatim at the
-- moment they approved it, a provider id, and a timestamp.
CREATE TABLE tracking_approved_origins (
    origin TEXT NOT NULL,             -- canonical https://<host>:<port>
    provider_id TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    mac TEXT NOT NULL,
    PRIMARY KEY (origin, provider_id)
) STRICT;
"#,
    },
    Migration {
        version: 18,
        name: "insertion-ordered verification watermark (timestamps are untrusted input)",
        sql: r#"
-- v16 bound an observation to the current verification session by comparing
-- its `at` timestamp against the setup's `applied_at`. The re-audit showed
-- what that costs: `at` is a wall-clock string written by another process
-- and stored in a plain column, and it was only ever bounded from BELOW. A
-- row dated a year ahead therefore read as a present-tense success and
-- stayed one until the clock caught up, and — being the largest timestamp in
-- the table — it also out-ranked a failure recorded now and caused the
-- failure reason to be nulled (RA-005).
--
-- The bound from above is a clock-skew window, but a window is still a
-- judgement about two clocks. This column adds a signal that does not depend
-- on any clock at all: the highest observation rowid at the moment the setup
-- was applied. SQLite assigns rowids monotonically on insert, so
-- `rowid > applied_event_rowid` means "physically recorded after this setup
-- was applied" regardless of what time the writer claims it was.
--
-- Existing rows get 0, which admits every row exactly as before, so an
-- already-applied setup is not retroactively un-verified by the upgrade; its
-- timestamp bounds still apply, and its next apply stamps a real watermark.
ALTER TABLE tracking_setups ADD COLUMN applied_event_rowid INTEGER NOT NULL DEFAULT 0;
"#,
    },
    Migration {
        version: 19,
        name: "tracking setup row version (compare-and-swap, not last-writer-wins)",
        sql: r#"
-- Every write to a tracking setup's health columns used to be
-- `UPDATE tracking_setups SET ... WHERE id = ?1` — a blind write. The state
-- the write was DECIDED from was read into memory earlier, so any change
-- another process made in between was overwritten without anyone noticing.
--
-- That is a lost update, and it reproduces `ZFT-006` with no attacker and no
-- clock skew: the desktop lists setups, refreshes each one, and while it is
-- deciding, the CLI (or the gateway, or a second window) records a failure.
-- The refresh then writes the conclusion it reached from the PRE-failure row,
-- nulling `attention_reason`/`attention_at` and reporting `VerifiedAndActive`
-- for a setup that is, right now, broken (`VER-01`). WAL and `busy_timeout`
-- do not help — both transactions commit, in order, and the second one is
-- simply wrong.
--
-- This column is the compare-and-swap token. A reader carries the version it
-- read; the writer requires the row to still be at that version and bumps it.
-- A concurrent change makes the UPDATE affect zero rows, which is a signal
-- rather than a silent overwrite: the caller re-reads and re-derives against
-- what is actually there. `crates/core/src/rotation.rs` has used this shape
-- since rotations existed; this brings tracking to the same standard.
--
-- Existing rows start at 0, which is exactly right: the first CAS write
-- against an un-upgraded row reads 0, requires 0, and moves it to 1.
ALTER TABLE tracking_setups ADD COLUMN row_version INTEGER NOT NULL DEFAULT 0;
"#,
    },
    Migration {
        version: 20,
        name: "projects-first folder linkage, detected credential stubs, unknown API labels",
        sql: r#"
-- ONE primary folder per project, so "select project folder" is a thing the
-- user does once and Tethra remembers (ADR 0029).
--
-- This is deliberately NOT a second tracking state machine. `tracking_setups`
-- keeps owning apply/health/verification per (project, folder); this table
-- records the product-level fact "THIS is the project's folder, and tracking
-- for it is on/off", which `tracking_setups` cannot express because its key
-- admits many folders per project and its row is destroyed and re-minted by
-- `upsert_setup` on every apply.
--
-- `project_id` is the PRIMARY KEY, not part of a composite: a project has at
-- most one primary folder. Re-selecting a folder UPDATEs this row rather than
-- accumulating rows, which is what makes repeated selection idempotent.
--
-- `scan_fingerprint` is a non-secret digest over the (relative path, byte
-- length, mtime) of the dependency/env manifests the scan looked at. It exists
-- so a relaunch can answer "did anything change?" WITHOUT re-running the
-- 20-second bounded scan and without rewriting the user's files. It is a
-- change HINT that gates offering a rescan; it never authorizes an apply.
--
-- `applied_generation` snapshots `tracking_setups.config_generation` at the
-- moment an apply for this folder completed. v16 added that counter but
-- nothing ever compared it to a desired value, so "is the applied
-- configuration still the current one?" had no answer. Storing the generation
-- an apply actually reached gives the comparison a left-hand side.
--
-- `tracking_enabled = 0` is "disable tracking without deleting the project":
-- the linkage and the history stay, future automatic configuration stops.
--
-- Contents are non-secret: a folder path the user chose in a native picker,
-- RFC 3339 timestamps, a digest of file sizes, and integers.
CREATE TABLE project_folder_links (
    project_id               TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    folder_path              TEXT NOT NULL,
    tracking_enabled         INTEGER NOT NULL DEFAULT 1,
    linked_at                TEXT NOT NULL,
    last_scan_at             TEXT,
    scan_fingerprint         TEXT,
    applied_generation       INTEGER NOT NULL DEFAULT 0,
    last_activity_refresh_at TEXT,
    row_version              INTEGER NOT NULL DEFAULT 0
) STRICT;

-- An integration Tethra can see the project uses, but whose vault record it
-- cannot safely or confidently complete on its own.
--
-- THERE IS NO COLUMN CAPABLE OF HOLDING A SECRET VALUE, and that is the
-- point: the guarantee "a discovered plaintext value is never persisted
-- merely because it was found in a project file" is enforced by the shape of
-- this table, not by a predicate that a future edit could loosen. The scanner
-- already refuses to carry values out of a project
-- (`UnrecognizedCredential` "carries the variable NAME and the file, never
-- the value", crates/tracking/src/detect.rs:206-217); this table cannot
-- store one even if a caller had it.
--
-- `env_var` is an environment-variable NAME (`ANTHROPIC_API_KEY`).
-- `source_file` is a FOLDER-RELATIVE path (`.env`), never absolute, so the
-- row does not leak where on disk the user keeps their work.
-- `suggested_provider` / `suggested_name` are presentation-only guesses; they
-- never select a provider, create a route, or raise detection confidence.
--
-- `status` is the user's decision about the row, and every value except
-- 'pending' is one the user chose:
--   pending   — Tethra detected it; nobody has decided anything
--   completed — the user supplied the value; `resolved_credential_id` points
--               at the real vault record
--   ignored   — the user does not want to be asked again
--   external  — intentionally managed outside Tethra
--   merged    — the user pointed it at an existing credential
-- The CHECK keeps an unrecognized status out of the table rather than letting
-- it reach a screen as a bare enum token.
CREATE TABLE detected_credentials (
    id                     TEXT PRIMARY KEY,
    project_id             TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    env_var                TEXT NOT NULL,
    suggested_provider     TEXT,
    suggested_name         TEXT,
    suggested_environment  TEXT,
    source_kind            TEXT NOT NULL,
    source_file            TEXT NOT NULL DEFAULT '',
    status                 TEXT NOT NULL DEFAULT 'pending',
    resolved_credential_id TEXT REFERENCES credentials(id) ON DELETE SET NULL,
    first_detected_at      TEXT NOT NULL,
    last_detected_at       TEXT NOT NULL,
    row_version            INTEGER NOT NULL DEFAULT 0,
    UNIQUE (project_id, env_var, source_file),
    CHECK (status IN ('pending', 'completed', 'ignored', 'external', 'merged')),
    -- 'completed' means "the user supplied the value and it lives in the
    -- vault", so it is unrepresentable without the vault row it points at.
    CHECK (status <> 'completed' OR resolved_credential_id IS NOT NULL)
) STRICT;
CREATE INDEX idx_detcred_project ON detected_credentials(project_id);
-- FK child-key index. `foreign_keys = 1` is on for every connection, so
-- without this SQLite full-scans this table once per DELETED credential row —
-- the exact cost migration v14 exists to fix for gateway_usage_events.
CREATE INDEX idx_detcred_resolved ON detected_credentials(resolved_credential_id);

-- NOTE: naming an unknown API deliberately adds NO table here. v12 already
-- gave `observed_api_services` the `user_provider` / `user_api_name` columns
-- and `runtime::store::set_service_correction` to write them, keyed by host —
-- which is the right key, since a host is a host regardless of which project
-- reached it. A second per-project label table would be a second
-- implementation of an existing feature, and the two would disagree the first
-- time one was written without the other.

-- The project activity surface windows usage by (project, time). v13 gave
-- gateway_usage_events only the single-column idx_gue_at and idx_gue_project,
-- so a per-project time window scanned every row that project ever produced.
CREATE INDEX IF NOT EXISTS idx_gue_project_at
    ON gateway_usage_events(project_id, at);
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

/// Open the database ONLY if its schema is exactly this build's version.
///
/// `open()` performs no schema check at all, and `migrate()` mutates the
/// schema — neither is safe for a long-lived background process (the gateway
/// service) that may outlive an app upgrade in either direction
/// (KNOWN_CONFLICTS C15). A newer schema returns `SchemaTooNew`; an older
/// (not-yet-migrated) schema returns `SchemaNotCurrent` — migration v13+ is
/// applied only by the enable/unlock flow, never by a background service.
/// Callers treat both as "persistence degraded, keep forwarding".
pub fn open_at_current_version(path: &Path) -> Result<Connection> {
    if !path.exists() {
        return Err(crate::error::CoreError::VaultNotFound(path.to_path_buf()));
    }
    let conn = open(path)?;
    let found = user_version(&conn)?;
    let supported = current_schema_version();
    if found > supported {
        return Err(crate::error::CoreError::SchemaTooNew { found, supported });
    }
    if found < supported {
        return Err(crate::error::CoreError::SchemaNotCurrent { found, supported });
    }
    Ok(conn)
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
