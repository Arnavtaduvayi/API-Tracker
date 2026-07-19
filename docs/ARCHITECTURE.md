# Architecture Overview

Current state: milestones 1–5 — encrypted vault, project/credential
management, reuse detection, backups, provider catalog + connectors,
scanning + hooks, monitoring + doc watching, OpenAI usage/cost sync,
`.env` governance, destinations, and synchronization plans. CLI + desktop
parity throughout.

## Workspace

```text
┌─────────────────────────┐   ┌──────────────────────────────┐
│ apps/cli                │   │ apps/desktop                 │
│ binary: api-tracker     │   │ src/        React + TS UI    │
│ clap commands, prompts, │   │ src-tauri/  Tauri v2 backend │
│ session handling        │   │ (commands, auto-lock state,  │
│                         │   │  clipboard)                  │
└───────────┬─────────────┘   └───────────────┬──────────────┘
            │            both depend only on  │
            ▼                                 ▼
┌──────────────────────────────────────────────────────────────┐
│ crates/core  (api-tracker-core)                              │
│  secret    SecretString/SecretBytes (redact + zeroize)       │
│  crypto    Argon2id KDF, XChaCha20-Poly1305 envelopes, AAD   │
│  vault     key hierarchy, projects, credentials, reveal      │
│  db        SQLite + versioned migrations (user_version)      │
│  status    explainable status engine                         │
│  reuse     keyed fingerprints + reuse classification         │
│  backup    encrypted backup create/verify/restore            │
│  session   split-token CLI sessions                          │
│  settings  auto-lock + thresholds                            │
│  audit     local audit trail                                 │
│  providers manifest catalog + capability matrix              │
│  scanner/gitrepo/hooks   local secret scanning + pre-commit  │
│  alerts/monitor/docwatch alert lifecycle + doc watching      │
│  connectors/http/openai  provider adapters (mockable HTTP)   │
│  usage/pricing/budget    snapshots, estimates, budgets       │
│  permissions/activity    scopes + suspicious-activity rules  │
│  inject    credential→env mappings, process sessions         │
│  envfile/envgov          lossless .env parsing + governance  │
│  destinations            deployment adapters (keychain, AWS, │
│                          GitHub Actions, Vercel) + catalog   │
│  syncplan  reviewable value-change rollout plans             │
│  templates/stackdetect  stack templates + local detection    │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
        one SQLite database: <data-dir>/vault.db
        (shared by CLI and desktop; WAL mode)
```

Both frontends resolve the same data directory (`API_TRACKER_DIR` override,
platform default otherwise), so they operate on the same vault concurrently
(SQLite WAL + busy timeout).

## Data model (schema v5)

- `vault_meta` — key/value: vault id, crypto version, KDF params, master
  salt, wrapped vault key, wrapped fingerprint key, settings.
- `projects` — metadata + wrapped per-project key (`key_wrap_mode` is
  `vault` or `vault+password`, with per-project KDF params/salt for the
  password wrap).
- `project_repos` — registered local repository paths per project.
- `credentials` — metadata, masked value, keyed fingerprint, and either an
  encrypted value (`ciphertext`) or a reference to another credential
  (`linked_credential_id`); a CHECK constraint enforces exactly one of the
  two.
- `audit_events` — local sensitive-action log (no secret values).
- v2: `scan_suppressions`, `alerts`, `doc_watches`.
- v3: usage snapshots, pricing overrides, permissions, activity events,
  env mappings, process sessions, budgets.
- v4: encrypted provider admin connections, provider-side key/project
  caches, key links, sync checkpoints.
- v5: `credential_versions` (retained encrypted prior values),
  `env_exports`, `destinations` (encrypted write-only auth),
  `credential_destinations`, `sync_plans`, `sync_plan_steps`.
- v6: rotations, rotation schedules, access grants, PID columns.
- v7: usage units, first-seen tracking, doc history, repo scan state,
  notification channels.
- v8: `pricing_records` (effective-dated; legacy overrides migrated).
- v9: `project_templates`, `stack_preferences` (local decision history).
- v10: provider-account identity columns on `provider_connections`.

Timestamps are RFC 3339 UTC strings. Schema changes are append-only
migrations tracked via SQLite `user_version`.

## Key flows

**Unlock**: master password → Argon2id (stored params) → unwrap vault key →
unwrap fingerprint key (also validates the vault key). Wrong password =
AEAD failure.

**Reveal**: reauth (full KDF + unwrap) → resolve references to the
value-bearing record → project key (fails if a password-locked project is
locked) → decrypt with AAD binding → `SecretString` out; audit event
recorded.

**Add credential**: fingerprint the value → collect same-fingerprint
matches → classify (duplicate in project / prod-with-dev / cross-project /
intentional reference) → caller shows warnings and lets the user store a
copy, store a reference, or abort → encrypt under the project key.

**Status**: pure function over local evidence (user-entered dates, manual
marks, reuse analysis) → primary status + findings, each with reason,
source, observation time, confidence, and recommended action.

**CLI sessions**: `unlock` writes the vault key (and unlocked project keys)
encrypted under a fresh random token to `session.json`; the token goes to
the user's shell only. Sliding expiry = auto-lock setting. Desktop keeps the
`UnlockedVault` in memory behind a mutex with the same inactivity rule.

## Where future milestones attach

- Background scheduling: `run_monitor`, doc checks, and destination drift
  checks are on-demand functions today; a desktop timer + interval settings
  make them autonomous (FEATURE_MATRIX #10/#17).
- Rotation workflows: provider admin actions (create/revoke) + the existing
  sync plans compose into create → deploy → verify → revoke.
- More destinations/providers: both catalogs are additive (one reviewed
  file/adapter each) with honest capability matrices.

Decision records live in `docs/decisions/`; the audited feature status
lives in `docs/FEATURE_MATRIX.md`.
