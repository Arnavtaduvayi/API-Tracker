# Changelog

All notable changes to API Tracker are documented here. The project is in
**public alpha**; expect breaking changes before 1.0. Dates are UTC.

## [Unreleased]

### Added — real OpenAI usage & cost synchronization
- **Administrative OpenAI connection**: `provider connect openai` stores an
  OpenAI Admin API key encrypted under the vault key (validated before
  storage; replace/remove only — never displayed; reauthentication required
  to replace, remove, or live-test). `connection-status` reports last
  successful/failed sync, errors, and staleness. One organization per vault
  (documented limitation).
- **Usage sync** from the official organization Usage API: daily buckets
  grouped by provider project × API-key id × model, with cursor pagination,
  bounded retries honoring `Retry-After`, and typed auth/rate-limit/network
  errors. **Provider-reported costs** from the Costs API (project × key ×
  line item), preserved exactly as reported (value + currency; money-safety
  guards against negative/non-finite/overflowing amounts; non-USD rows are
  never silently mixed into USD totals).
- **Honest attribution + key linking**: new `provider_key` attribution
  level; provider-side key ids count against a local credential only after
  an explicit `provider link` confirmation (redacted-value matches are
  suggestions only). `provider keys` / `provider projects` show unmatched
  keys and unmapped projects; new alerts `provider_connection_invalid`,
  `provider_sync_failed`, `provider_data_stale`, `unmatched_provider_key`,
  and `unmapped_provider_project`.
- **Safe re-sync**: fetch-all-then-replace transactional writes; repeated
  and overlapping windows reconcile instead of double-counting; manual
  usage entries are never touched; checkpoints drive incremental default
  syncs (first sync 30 days, later syncs overlap 2 days). Offline failures
  change nothing and previously synced data stays viewable.
- **Budget cost source** (`budget source`, desktop selector):
  `best_available` (default) / `provider_reported` / `estimated` — budgets
  consume exactly one source, never the sum of reported + estimated.
- **CLI**: `provider connect/disconnect/test/keys/link/unlink/projects`,
  `provider sync [--days|--from/--to]`, `usage report
  --provider/--source/--limit` with per-record attribution and stale-data
  warnings. **Desktop**: administrative connection panel (connect/replace/
  disconnect/test/sync with period selection), provider key linking with
  suggestions, per-record usage listing, non-USD and stale warnings.
- `scripts/live_verify_openai.sh`: optional, self-cleaning live check with a
  throwaway vault (normal builds/tests remain fully mocked); six new smoke
  checks for the connection lifecycle (53 total). Schema migration v4.

### Added — demo, smoke test
- `scripts/demo.sh [--keep]` builds a fully isolated demonstration vault
  (fake generated credentials only, never a network call): a development
  project plus a password-locked production project; active / expired /
  expiring-soon / unused credentials; a cross-project reuse warning;
  synthetic usage with an over-budget alert; an encrypted, verified backup;
  and secure process injection. See `docs/DEMO.md`.
- `scripts/smoke.sh` runs an automated end-to-end smoke test of the release
  binary under production Argon2id (47 checks: vault lifecycle, password
  policy, sessions, project locks, encryption at rest, redaction, expiration,
  duplicate detection, usage/cost, budget alerts, backup verify/restore,
  desktop/CLI shared core, injection hygiene, and `.gitignore` protection).

### Changed — security
- The minimum length for newly chosen master, project, and backup passwords
  is now **12 characters** (was 8), with passphrase guidance in the desktop
  setup screen and CLI `init`. Existing vaults, locked projects, and backups
  created under the old policy still unlock and restore unchanged
  (ADR 0010).

### Added — provider integrations, usage, cost, and secure injection
- **Provider connectors** for OpenAI, Anthropic, GitHub, Stripe, and Supabase
  behind a mockable HTTP client. Implemented: credential **validation** (all
  five), GitHub **metadata** + **permissions** (via `X-OAuth-Scopes`),
  OpenAI/Anthropic **usage** sync (admin key, organization level), Stripe /
  Supabase **metadata**. Unimplemented capabilities report the official
  management link instead of faking behavior.
- **Usage snapshots** with honest attribution precision (account-level provider
  data is never shown as exact per-key).
- **Cost estimation** from a versioned local pricing table (source + retrieval
  date + staleness) with manual overrides; costs are labeled estimated vs
  provider-reported.
- **Budgets** (project + credential) with current-period usage, month-end
  projection, and over-budget alerts.
- **Permission model**: raw scopes + normalized read/write/admin/sensitive with
  a human summary; read-only GitHub sync.
- **Suspicious-activity rules**: over-budget, cost-spike, and
  usage-after-disabled, integrated with the alert lifecycle.
- **Secure process injection** — `api-tracker run --project P [--credential C
  --env VAR] -- cmd` injects only the named project's credentials into the child
  environment, never writes/prints values, propagates the exit code, and records
  a process session (variable names only). Project credential→env mappings.
- CLI: `provider connect/sync/connection-status`, `key
  validate/metadata/permissions`, `usage sync/record/report`, `budget set/show`,
  `activity list`, `mapping`, `run`.
- Desktop: Usage & cost screen (usage, budget, activity) and credential
  Validate / Fetch metadata / Sync permissions actions.
- **Release workflow** building CLI + desktop artifacts for macOS/Windows/Linux
  with SHA-256 checksums, attaching a draft GitHub Release on `v*` tags. Builds
  are **unsigned** (alpha).
- Docs: install, first-run, provider-support matrix, connector guide,
  troubleshooting, backup/recovery, packaging/signing.
- Database migration v3 (usage, pricing overrides, permissions, activity,
  env mappings, process sessions, provider connections, budgets).

### Previously (foundation + scanning/monitoring milestones)
- Encrypted local vault (Argon2id + XChaCha20-Poly1305), projects, credentials,
  reuse detection, encrypted backups, CLI + desktop.
- Provider catalog, local repository secret scanning, pre-commit hooks, local
  alerts/monitoring, and an official-documentation change watcher.

[Unreleased]: https://github.com/Arnavtaduvayi/API-Tracker/compare/main...HEAD
