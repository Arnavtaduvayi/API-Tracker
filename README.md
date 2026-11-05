# Tethra

A local-first desktop app and CLI for individual developers to organize,
secure, and track the API credentials scattered across their projects.

Think of it as a folder system for API keys: a **project** is a folder, each
**credential** is an encrypted record inside it, and the app tells you what
state each key is in — expired, expiring soon, unused, stale, reused across
projects — with the reason and evidence for every claim.

The vault stays on your computer. There is **no account**, hosted vault, or
Tethra credential server. Measurement analytics uses a U.S. regional default
with opt-out and remains opt-in elsewhere; its small event allowlist excludes
credentials, vault records, project/provider names, paths, URLs, and request content. Other
network traffic goes directly from your machine to providers, destinations,
webhooks, or documentation pages you configure. See [Analytics](docs/ANALYTICS.md)
and the [Privacy Policy](landing/privacy.html).

> **Public alpha.** Tethra is usable and well-tested, but it is alpha
> software: evaluate it carefully before storing highly sensitive production
> credentials. Local-first reduces exposure but does **not** eliminate
> local-device risks (malware, an unlocked machine, memory inspection) — see
> [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md). Provider
> capability and usage-attribution precision **vary by provider** — see the
> [provider support matrix](docs/PROVIDER_SUPPORT.md).
>
> Guides: [Install](docs/INSTALL.md) · [Provider support](docs/PROVIDER_SUPPORT.md)
> · [Destination support](docs/DESTINATION_SUPPORT.md) · [Pricing](docs/PRICING.md)
> · [Templates & stack detection](docs/TEMPLATES.md)
> · [Troubleshooting](docs/TROUBLESHOOTING.md) · [Backup & recovery](docs/BACKUP_RECOVERY.md)
> · [Packaging/signing](docs/PACKAGING.md) · [Changelog](CHANGELOG.md)

## Status: working alpha

Implemented and tested today:

- **Encrypted local vault** — Argon2id master-password key derivation,
  XChaCha20-Poly1305 authenticated encryption, random per-project keys,
  versioned encryption metadata, tamper detection (see
  `docs/decisions/0002-cryptography.md`).
- **Projects** — create/list/show/edit/archive/restore, environment
  classifications, local repository paths, notes, and optional per-project
  **password locks** (a second password on top of the vault).
- **Credentials** — add/edit/replace/delete with provider tag, environment,
  creation/expiration dates, docs links, notes, manual usage/validation
  tracking; values are always shown masked and revealed or copied only after
  re-entering the master password.
- **Explainable status engine** — `unknown`, `active`, `invalid`, `expired`,
  `expiring_soon`, `unused`, `stale`, `shared_across_projects`,
  `possibly_exposed`, `manually_disabled`, `revoked`; every finding carries a
  reason, evidence source, observation time, confidence, and recommended
  action.
- **Reuse detection** — vault-specific keyed fingerprints detect the same
  secret stored in multiple places, classify the reuse (worst case:
  production key shared with development), and offer storing a *reference*
  to one encrypted value instead of a duplicate copy.
- **Encrypted backups** — create/verify/restore a single password-protected
  backup file; restore never silently overwrites a vault.
- **Provider catalog + connectors** — version-controlled TOML manifests for
  OpenAI, Anthropic, GitHub, Stripe, and Supabase with an **honest capability
  matrix**. Implemented: credential **validation** (all five), GitHub
  **metadata + permissions**, Anthropic org-level usage sync, Stripe/Supabase
  metadata. Unimplemented capabilities link to the official page instead of
  faking it. See the [provider support matrix](docs/PROVIDER_SUPPORT.md).
- **OpenAI usage & cost synchronization** — connect an OpenAI **Admin API
  key** (stored encrypted in the vault, replace/remove only, never
  displayed) and sync daily token usage grouped by provider project ×
  API-key id × model, plus **provider-reported costs** (value + currency
  preserved) grouped by project × key × line item. Repeated and overlapping
  syncs reconcile instead of double-counting; previously synced data stays
  viewable offline. See the [OpenAI sync guide](docs/OPENAI_SYNC.md).
- **Honest attribution + key linking** — every usage record carries its
  attribution level (exact credential / provider key / provider project /
  provider account); a provider-side key id counts against a local
  credential **only after you confirm the link** (redacted-value matches are
  shown as suggestions, never auto-applied). Unmatched keys and unmapped
  provider projects stay visible and raise alerts instead of being divided
  among local keys.
- **Usage, cost & budgets** — normalized usage snapshots; provider-reported
  cost and locally estimated cost are kept strictly separate; budgets pick
  one configurable source (best-available, provider-reported, or estimated)
  and never sum both; month-end projection and over-budget alerts.
- **Versioned pricing** — effective-dated records for current OpenAI and
  Anthropic models (source URL + verification date per entry), manual
  overrides, validated import/export, and a reviewable propose → review →
  import update loop. Usage is priced as of its own date, so price updates
  never silently reprice history; unknown models get no invented estimate;
  stale records (45+ days unverified) are flagged and alerted. See
  [docs/PRICING.md](docs/PRICING.md).
- **Project templates & stack detection** — nine stack templates
  (variables, environments, separation/permission/rotation guidance;
  never any values) and deterministic local stack detection with
  per-suggestion evidence, explicit confirmation, and a fully deletable
  local decision history — not ML, and labeled as such. See
  [docs/TEMPLATES.md](docs/TEMPLATES.md).
- **Provider-account identity** — provider-reported org/account id, name,
  email, and plan from official endpoints only (GitHub, Stripe, Supabase,
  Anthropic), each stored with its source and sync time; OpenAI has no such
  endpoint and the app says so. No provider passwords, MFA material, or
  browser sessions — ever.
- **Permissions** — raw scopes plus a normalized read/write/admin/sensitive
  view; read-only GitHub scope sync.
- **Suspicious-activity rules** — over-budget, cost-spike, and
  usage-after-disabled, each with evidence and a comparison period.
- **Secure process injection** — `tethra run --project P [--credential C
  --env VAR] -- cmd` injects only that project's chosen credentials into the
  child's environment; it never writes a `.env` or prints values, refuses
  unrelated credentials, and records a process session (names only).
- **Local repository scanning** — working-tree, staged, and Git-history scans
  detect secrets via provider key patterns, known secret env-var names, and
  calibrated entropy. Findings are redacted, show file/line/provider/
  confidence, are matched against your vault (marking matches possibly
  exposed), and can be suppressed with a required reason. Nothing leaves the
  machine.
- **`.env` governance** — discover `.env` files across a project's
  repositories (with Git tracked/ignored/untracked/in-history status), parse
  them losslessly without executing anything, preview variables masked,
  **selectively import** secrets into the encrypted vault (auto-creating
  injection mappings), generate `.env.example` (names only), detect drift
  (diverged values, unmapped secrets, production keys in dev files, values
  copied between files), and run a guided **migration** that removes
  plaintext only after verifying every secret resolves from the vault.
  Explicit, reauthentication-gated **export** exists for tools that truly
  need a file: atomic 0600 writes, `.gitignore` verification, refusal to
  write into Git-tracked files, and temporary exports with automatic
  cleanup.
- **Destinations & sync plans** — a destination-adapter system (separate
  from provider connectors) with an honest per-kind capability matrix:
  macOS Keychain, **Linux Secret Service**, **Windows Credential Manager**,
  AWS Secrets Manager (SigV4, verified against the official test vector;
  delete uses the official 30-day recovery window), GitHub Actions
  repository secrets (sealed-box), and Vercel environment variables, plus
  the local vault/mappings/exports. Destination admin credentials are
  stored encrypted and write-only. Changing a credential value generates a
  reviewable **synchronization plan** (dry run by default) with
  per-destination execution, verification, partial-failure handling,
  retry, and **rollback** to retained previous versions — never an
  automatic write, never an automatic revoke. Deleting a secret AT a
  destination is a confirmed, reauthenticated action, and opt-in
  live-verification scripts exist for AWS/GitHub Actions/Vercel.
- **Credential version history** — replacing a value retains the previous
  versions encrypted (bounded by count and a configurable rollback window,
  purged with the credential) so destination rollback restores real
  material; `key versions` lists them masked after reauthentication and
  `key history` shows the full merged lifecycle timeline.
- **Safe credential rotation** — a durable, restart-recoverable workflow:
  dry-run plan, reauthenticated approval, replacement via official provider
  APIs (OpenAI service-account keys, Supabase secret keys) or a guided
  manual path (Anthropic/GitHub/Stripe), destination sync + verification,
  live validation, a grace period with continued-use detection from per-key
  usage data, disable where supported, and revocation only after
  verification. Rollback where safe; honest "irreversible" errors where
  not. Schedules raise due alerts — nothing destructive ever runs
  unattended.
- **Temporary access** — local grants bound what `run` injects (expiry,
  one-time/max launches, per-process kill timers, SIGTERM termination),
  clearly labeled as local controls; provider-reported expirations (GitHub
  header) recorded and driving status; provider-created test keys with
  explicit provider-enforced vs local vs advisory labeling.
- **Pre-commit hook** — `hooks install` blocks commits containing
  high-confidence secrets; it runs without unlocking the vault and preserves
  any existing hook.
- **Local monitoring + alerts** — `monitor` evaluates expiry, staleness,
  unused, reuse, production-in-development, and exposure conditions into an
  acknowledge/resolve alert lifecycle, with native desktop notifications.
- **Documentation watcher** — watch official provider docs URLs; conditional
  HTTP (ETag/Last-Modified) + content hashing detect changes and raise an
  alert. Requests go directly from your device; only validators, a hash, and
  timestamps are stored — never the page content.
- **Runtime API observability (opt-in, metadata only)** — `tethra run
  --observe -- <command>` monitors one launched process through a
  loopback-only, token-authenticated proxy and records **sanitized metadata
  only**: host, templated path, method, status, latency, and byte counts.
  Request/response bodies, header values, cookies, authorization values, and
  query strings are never stored. `tethra observe` shows the automatic API
  inventory, per-session detail, and credential attribution; the desktop
  **API activity** screen inspects the same data. Locking the vault stops an
  active run. See
  [docs/RUNTIME_OBSERVABILITY.md](docs/RUNTIME_OBSERVABILITY.md).
- **Desktop app and CLI share one vault** — both are thin frontends over the
  same Rust core crate and the same SQLite database.
- **Auto-lock** — configurable inactivity lock for the desktop app and CLI
  sessions.
- **Master-password change & project-key rotation** — `change-password`
  re-wraps the vault key; setting/changing/removing a project password
  rotates the project key and re-encrypts its values, and the WAL is
  checkpointed so old material does not linger.
- **Tethra Mesh: your own devices, peer to peer (opt-in)** — pair your
  devices with a one-time invite and they replicate directly over your LAN or
  a VPN you run, with no Tethra server, relay or cloud
  ([ADR 0031](docs/decisions/0031-device-mesh.md)). Share a project and see
  its gateway-observed usage per device; hold a monthly **spend cap** across
  devices that raises alerts everywhere and, where you switch it on, is
  enforced by that device's gateway with a non-retried 403
  ([ADR 0032](docs/decisions/0032-spend-caps.md)); share **one credential at
  a time** with chosen devices, sealed to each device's key and imported only
  on request with the master password
  ([ADR 0033](docs/decisions/0033-credential-sharing.md)). `tethra mesh …` and
  the desktop app's **Devices** view and project/credential pages. Every
  connection is encrypted and authenticated, but every paired device can read
  what replicates (only a shared credential's value is sealed); a cap is a
  self-limit whose overshoot is limited, not zero; there is no NAT traversal
  and no background service (the node runs while `tethra mesh serve` or the
  unlocked desktop app does). An independent four-auditor review found 48
  issues, 41 fixed with failing-first tests and 7 accepted as documented
  limits ([audit](docs/mesh/audit/2026-11-03/FINDINGS_INDEX.md),
  [limitations](docs/mesh/KNOWN_LIMITATIONS.md),
  [user guide](docs/mesh/USER_GUIDE.md)).

Not implemented yet (planned, see `docs/PRODUCT_SPEC.md`): programmatic
permission *changes* (no provider offers a safe documented per-key method
today — the app links to the official page or routes through rotation);
OpenAI token detail beyond the completions endpoint (embeddings/images/audio
usage endpoints — total *spend* is still complete via the costs API); more
than one OpenAI organization per vault; live-account exercise of the
AWS/GitHub Actions/Vercel destination paths (fixture-tested; opt-in scripts
provided); and **signed/notarized** installers (the alpha artifacts are
unsigned except for the manually signed and notarized macOS DMG served from
the Tethra landing site — see [docs/PACKAGING.md](docs/PACKAGING.md)).

## Security in one paragraph

Credential values are encrypted with XChaCha20-Poly1305 under random
per-project keys, wrapped by a vault key, wrapped by an Argon2id-stretched
master password; every ciphertext is bound to the record it belongs to, so
database tampering and ciphertext swaps are detected. Values are redacted
everywhere by default, revealing/copying/exporting requires re-entering the
master password, and nothing is sent to any Tethra server. If you turn on
Tethra Mesh, a fixed set of data replicates to the devices you paired, and a
credential's value only when you share it, sealed to the devices you chose. Read
[SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md) — including
what this does **not** protect against (malware running as you, an unlocked
machine, memory inspection). **If you lose your master password, your vault
cannot be recovered.** Make encrypted backups.

## Development

```bash
# Rust: format, lint, test (weak KDF profile keeps Argon2id fast in tests;
# it only works in debug builds)
cargo fmt --all
cargo clippy --workspace --all-targets
TETHRA_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core -p api-tracker-cli

# Frontend
cd apps/desktop
npm run lint && npm run typecheck && npm test && npm run build
```

Tests use obviously fake credentials (`FAKE-TEST-NOT-A-REAL-KEY-…`) and
temporary vaults; they never touch your real data directory. See
[CONTRIBUTING.md](CONTRIBUTING.md) and `docs/ARCHITECTURE.md`; significant
choices are recorded in `docs/decisions/`.

## License

Apache-2.0 (see [LICENSE](LICENSE)).
