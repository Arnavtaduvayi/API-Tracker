# Architecture Overview

Current state: the "local foundation" milestone — encrypted vault, project
and credential management, reuse detection, backups, CLI + desktop parity.

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
│  providers static informational catalog                      │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
        one SQLite database: <data-dir>/vault.db
        (shared by CLI and desktop; WAL mode)
```

Both frontends resolve the same data directory (`API_TRACKER_DIR` override,
platform default otherwise), so they operate on the same vault concurrently
(SQLite WAL + busy timeout).

## Data model (schema v1)

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

- Provider connectors: a `providers` capability matrix + adapters crate;
  credentials already store a provider id (ADR 0007).
- Repo scanning: a scanner module/crate reading `project_repos`; findings
  feed `possibly_exposed` status which already exists.
- Alerts/usage/doc-watching: new tables + evidence sources for the status
  engine; the finding structure already carries source/confidence fields.

Decision records live in `docs/decisions/`.
