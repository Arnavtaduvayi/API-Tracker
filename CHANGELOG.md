# Changelog

All notable changes to API Tracker are documented here. The project is in
**public alpha**; expect breaking changes before 1.0. Dates are UTC.

## [Unreleased]

### Added — product gap closure (migrations v8–v10)
- **Versioned pricing**: effective-dated records (bundled current
  OpenAI/Anthropic prices with per-entry source + verification date,
  validated JSON imports, manual overrides; cached/batch/per-request
  fields). Usage is priced as of its own date — updates never silently
  reprice history; unknown models never get invented estimates; stale
  records (45+ days) are flagged and raise a `pricing_stale` alert.
  CLI `pricing` group (list/show/set-override/remove-override/import/
  export/propose) + desktop Pricing screen.
- **Project templates & local stack detection**: nine embedded templates
  (no values, ever — enforced by test); names-only `.env.example`
  generation; deterministic detection over static repository signals with
  per-suggestion evidence/confidence, explicit confirm/dismiss, and a
  listable, resettable, fully deletable local decision history (labeled
  rules + stored decisions, not ML). CLI `template` group + desktop
  Templates screen.
- **Provider-account identity** from official endpoints only (GitHub
  /user, Stripe /v1/account, Supabase /v1/organizations, Anthropic
  /v1/organizations/me), stored with source + sync time; OpenAI reported
  honestly as having no such endpoint. Console-login and billing-portal
  URLs in every manifest. `provider account [--sync]`.
- **Destination completion**: AWS Secrets Manager delete (30-day recovery
  window, never forced), Linux Secret Service (secret-tool, stdin),
  Windows Credential Manager (keyring crate; compiled + tested on real
  Windows in CI), reauthenticated `destination delete-secret` (CLI +
  desktop), and per-kind declarations of verification method, required
  plan, possible charges, and testing status. Doppler/1Password/HashiCorp
  Vault evaluated and deferred (ADR 0016).
- **Opt-in destination live-verification scripts** for AWS, GitHub
  Actions, and Vercel: throwaway vault, hidden prompts, one disposable
  FAKE-value secret, typed confirmation before any write, strongest
  supported verification, loud cleanup. Never in CI.
- Smoke suite grown to **126 checks** (pricing, templates/detection,
  extended destination honesty, master-password change).

### Security — residual hardening
- **Master-password change** (CLI `change-password`, desktop Settings).
- **Project-key rotation** whenever a project password is set, changed,
  or removed: fresh key, full re-encryption of values and retained
  versions — wraps predating the password become worthless.
- WAL checkpoint-truncate on lock and after password operations; 0600
  permissions on `vault.db` and sidecars (Unix); `doctor` warns where
  permissions are OS-inherited (Windows).
- `.env` export refuses symlink targets; expired temporary exports are
  swept on session resume too; orphaned atomic-write temp files are
  removed (bounded, age-gated); the monitor closes injection-session rows
  whose recorded process died with its launcher.

### Added — alpha hardening & completion
- **Live-verification scripts** for Anthropic, GitHub, and Stripe
  (`scripts/live_verify_{anthropic,github,stripe}.sh`), matching the OpenAI
  pattern: throwaway vault, hidden prompt, read-only by default, no secret in
  argv or plaintext on disk, self-cleaning, never run in CI.
- **Desktop/CLI parity**: secret-scan suppression list + removal (CLI
  `suppress remove`, desktop list/remove); user-chosen Git history depth incl.
  full history in the desktop scan (was fixed at 50); injection-session
  listing incl. non-grant runs and per-session SIGTERM termination
  (`access sessions`/`access kill`, desktop Sessions table); `monitor
  --status` and a desktop last-run/success/failure surface; webhook
  delivery/failure history (`notify history`, desktop table); doc-watch
  last-changed column; in-flight-rotation "needs attention" flag.
- **Complete encrypted backups (format v2)**: the payload now captures every
  table generically, so provider connections, usage/cost history, alerts,
  destinations, sync plans, rotations, access grants, env mappings,
  credential versions, and notification channels are preserved on restore
  (they were silently dropped before). Older-schema backups restore and
  migrate forward; newer-schema backups and newer-schema live vaults are
  refused loudly. Backup files are written owner-only (0600). ADR 0015.
- **Migration & data-safety test suite**: populated v1/v5/v6 upgrades (direct
  and stepwise), v7 backfill, interrupted-migration resume, corrupted-input
  rollback, future-schema refusal via the real unlock path, and full
  backup/restore completeness.

### Fixed — security (adversarial review)
- Webhook delivery enforces once-per-alert dedup (alerts no longer re-post on
  every monitor run within their first hour) and retries after a failure.
- AWS region validated before it reaches the request authority (off-host
  exfiltration guard); documentation watcher no longer follows redirects
  (SSRF/downgrade guard); rotation provider-key creation serialized via
  compare-and-swap (no duplicate live keys under concurrent advance); desktop
  file-writing IPC commands gated behind an unlocked vault; opener capability
  scoped to http/https/mailto; CLI direct-print paths sanitize
  attacker-influenced strings (terminal-escape guard); Git scan bounds staged
  blobs and caps diff reconstruction; backup restore --force never clobbers a
  prior aside.

### Added — cross-provider observability
- **Anthropic per-key sync engine**: daily usage grouped by API-key id ×
  workspace × model via the Admin API (officially supported grouping),
  cents-denominated cost report converted with guards at workspace level,
  workspace/key metadata with provider-reported expirations flowing onto
  linked credentials, dedicated admin connections for Anthropic.
- **GitHub billing usage** (fine-grained token, account level, units
  verbatim) and **Stripe Events activity** (daily event families, 30-day
  retention) — non-token units (`quantity`/`unit`) are first-class and
  never coerced into tokens. Supabase's undocumented analytics units are
  honestly declined.
- **16 explainable suspicious-activity rules** (new: request spikes,
  dormant-credential activation, repeated auth failures, new provider
  project/key, first model use, unusual local session hour, destination
  drift, rotation attention, expired grants) with evidence, windows,
  attribution notes, and confidence.
- **Incremental repository monitoring**: registered repos baselined, only
  new commits scanned on monitor runs, findings through the standard
  suppression/vault-match/exposure path.
- **Notifications**: desktop background monitor timer
  (`monitor_interval_minutes`), medium+ native notifications, and
  user-configured **webhook channels** (encrypted https URLs, severity
  floors, metadata-only payloads, per-channel failure records; `notify`
  command group). No hosted relay.
- **Documentation monitoring**: check intervals, change history
  (`provider docs-history`), changelog/pricing/permission URLs in every
  manifest.
- Database migration v7.

### Added — rotation, permission management, and temporary credentials
- **Durable rotation workflows** (`rotation` command group, desktop
  Rotation screen): dry-run plan → reauthenticated approval → replacement
  (OpenAI/Supabase via official APIs; Anthropic/GitHub/Stripe guided
  manual) → destination sync + verification → live validation of the new
  value → grace/overlap with continued-use detection from per-key provider
  usage → disable where supported (Anthropic) → revoke ONLY after
  verification (OpenAI/Supabase delete; Anthropic archive, labeled soft) →
  completed. Restart-recoverable, idempotent retries, stuck detection,
  rollback (destinations + vault value + Anthropic re-enable + optional
  new-key revocation), honest manual fallbacks.
- **Scheduled rotation as intent**: enabled only after a completed manual
  rotation; due schedules raise high-severity alerts (desktop
  notification) after preflight; preflight failure pauses the schedule;
  nothing ever executes unattended.
- **Temporary local access grants**: `access grant/list/end` +
  `run --grant` with expiry windows, one-time/max-launch atomic limits,
  per-process kill timers, PID-tracked termination, advisory budget
  warnings — explicitly local controls, never presented as provider-side.
- **Provider-reported expiration**: GitHub's token-expiration header is
  recorded and drives expiry status with its own source label.
- **Provider-created test keys**: `key test-create` (OpenAI service
  accounts / Supabase secret keys) with PROVIDER-ENFORCED vs NOT-enforced
  vs ADVISORY labeling; `key provider-revoke` for confirmed provider-side
  revocation.
- **Permissions**: Supabase privilege read from the documented key format
  (incl. legacy JWT role claim); `key permissions-diff` before/after view;
  permission snapshots in the audit trail; changes routed through
  dashboards or rotation — never faked.
- **Lifecycle**: `key history` merged timeline (audit + activity +
  versions + rotation events); rollback window setting (default 30 days)
  pruning retained versions with secure_delete.
- Database migration v6.

### Added — `.env` governance, destinations, and synchronization plans
- **`.env` governance**: `env discover` (variants + Git
  tracked/ignored/untracked/in-history status), lossless non-executing
  parsing (comments/order/quoting/line endings preserved; malformed and
  duplicate detection), `env preview` (masked classification against
  provider manifests, the scanner, the vault, and mappings), selective
  `env import` into the encrypted vault with automatic injection mappings
  (duplicates mapped or referenced, never copied), `env example`
  generation (names only, diff-previewed), `env drift` (diverged values,
  unmapped secrets, production-in-dev files, copied values, template gaps),
  and a guided `env migrate` that removes plaintext only after verifying
  every secret resolves from the vault.
- **Explicit `.env` export**: reauthentication-gated, atomic 0600 writes,
  never overwrites without a flag, refuses Git-tracked targets, verifies
  `.gitignore`, warns inside the file, records a redacted audit event, and
  supports temporary exports (`--ttl`) with hash-checked `env cleanup`.
- **Credential version history**: replacing a value retains prior versions
  encrypted (AAD-bound to the version number; bounded; purged on delete);
  `key versions` lists them masked after reauthentication.
- **Destinations** (separate from provider connectors) with an explicit
  per-kind capability matrix (read/write/delete/versioning/rollback/
  validation): macOS Keychain (secret via stdin, never argv), AWS Secrets
  Manager (SigV4 verified against the official test vector), GitHub Actions
  repository secrets (libsodium sealed box), Vercel environment variables,
  plus the built-in vault/mapping/export kinds. Destination admin
  credentials are stored encrypted and write-only; `destination
  kinds/add/remove/test/attach/detach/attachments/drift`.
- **Synchronization plans**: `sync plan` (dry run by default) shows old/new
  versions (masked), every destination, planned action, validation method,
  rollback availability, and affected projects; `sync run` executes after
  confirmation + reauthentication with per-destination rollout,
  verification (fingerprint read-back or existence), partial-failure
  handling, and retry; `sync rollback` restores the retained previous
  version; stale plans refuse to run. Nothing is ever written or revoked
  automatically.
- Desktop: Env files, Destinations, and Sync plans screens; CLI/desktop
  share all logic through the core crate. Smoke test grew to 68 checks.
- Database migration v5; PUT/DELETE support in the HTTP layer.

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
