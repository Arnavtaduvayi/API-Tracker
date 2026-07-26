# Tethra

A local-first desktop app and CLI for individual developers to organize,
secure, and track the API credentials scattered across their projects.

Think of it as a folder system for API keys: a **project** is a folder, each
**credential** is an encrypted record inside it, and the app tells you what
state each key is in — expired, expiring soon, unused, stale, reused across
projects — with the reason and evidence for every claim.

Everything stays on your computer. There is **no account**, no cloud service, no
telemetry, and no Tethra server. The only network traffic Tethra ever
produces is direct traffic between your machine and API providers (or
documentation pages) you explicitly configure — your secrets are never uploaded
to a Tethra server.

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

Not implemented yet (planned, see `docs/PRODUCT_SPEC.md`): programmatic
permission *changes* (no provider offers a safe documented per-key method
today — the app links to the official page or routes through rotation);
OpenAI token detail beyond the completions endpoint (embeddings/images/audio
usage endpoints — total *spend* is still complete via the costs API); more
than one OpenAI organization per vault; live-account exercise of the
AWS/GitHub Actions/Vercel destination paths (fixture-tested; opt-in scripts
provided); and **signed/notarized** installers (the alpha artifacts are
unsigned — see [docs/PACKAGING.md](docs/PACKAGING.md)).

## Install and build

Prerequisites:

- Rust (stable, 1.85+) — <https://rustup.rs>
- Node.js 20+ and npm (for the desktop UI)
- Platform build tools: Xcode Command Line Tools on macOS; on Linux the
  [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/)
  (webkit2gtk 4.1 etc.); on Windows the MSVC build tools + WebView2.

```bash
git clone https://github.com/Arnavtaduvayi/API-Tracker
cd API-Tracker

# CLI
cargo build --release -p api-tracker-cli
# binary at target/release/tethra

# Desktop app
cd apps/desktop
npm install
npx tauri build          # bundles the app (unsigned)
npx tauri dev            # or run it in development mode
```

## Try it in two minutes (no real keys needed)

```bash
bash scripts/demo.sh --keep   # isolated demo vault, fake credentials only
bash scripts/smoke.sh         # automated end-to-end smoke test
```

The demo builds a throwaway vault with a development project, a
password-locked production project, credentials in every interesting state
(active, expired, expiring soon, unused, reused across projects), synthetic
usage with an over-budget alert, an encrypted verified backup, and a secure
process-injection run — then prints the exact commands to explore it from
the CLI and desktop app. Your real vault is never touched. See
[docs/DEMO.md](docs/DEMO.md).

## CLI quick start

> The legacy `api-tracker` command remains available as a compatibility alias
> for `tethra` (same program), and the legacy `API_TRACKER_*` environment
> variable names still work — see
> [docs/rebrand/TETHRA_MIGRATION_GUIDE.md](docs/rebrand/TETHRA_MIGRATION_GUIDE.md).

```bash
tethra init                     # create the encrypted vault
tethra unlock                   # prints an export TETHRA_SESSION=... line
export TETHRA_SESSION="..."     # paste it (or: eval "$(tethra unlock --print-export)")

tethra project create my-app --env development --env production \
    --repo ~/code/my-app
tethra key add --project my-app --name openai-main --provider openai \
    --environment production --expires 2027-01-01
# (the secret is prompted, hidden; it is never a command-line argument)

tethra key list                 # masked values only
tethra key status my-app/openai-main   # explainable status report
tethra key reveal my-app/openai-main   # asks for the master password again

tethra backup create ~/tethra-backup.json
tethra backup verify ~/tethra-backup.json

# Provider catalog
tethra provider list
tethra provider capabilities openai       # honest support matrix
tethra provider docs anthropic

# Scan a repository and install the pre-commit hook
tethra scan --staged ~/code/my-app        # or --history N, or a dir
tethra hooks install ~/code/my-app        # blocks high-confidence secrets
tethra suppress add <suppression-key> --reason "test fixture"

# Monitoring, alerts, and documentation watches
tethra monitor                            # evaluate and raise alerts
tethra alerts list
tethra alerts acknowledge <id> && tethra alerts resolve <id>
tethra provider watch-docs openai         # watch official docs pages
tethra provider check-docs openai         # conditional request, direct

# Validate, sync usage, budget, and inspect permissions
tethra key validate my-app/openai-main    # direct provider request
tethra key permissions my-app/gh --sync   # e.g. GitHub scopes
tethra provider connect openai            # prompts for an Admin key
tethra provider connection-status openai  # status, freshness, last error
tethra provider sync openai               # usage + provider-reported costs
tethra provider sync openai --from 2026-07-01 --to 2026-07-15
tethra provider keys openai               # provider-side keys + link state
tethra provider link openai key_abc123 --credential my-app/openai-main
tethra usage report --provider openai --source provider
tethra usage report --project my-app      # usage + estimated cost
tethra budget set --project my-app --amount 50.00
tethra budget source provider_reported    # which cost source budgets use
tethra provider disconnect openai         # remove local admin access
tethra activity list

# Govern .env files: discover, import into the vault, migrate off plaintext
tethra env discover --project my-app
tethra env import --project my-app .env          # preview + confirm
tethra env migrate --project my-app .env         # guided plaintext removal
tethra env drift --project my-app
tethra env export --project my-app --to .env --ttl 60   # reauth-gated escape hatch

# Deploy destinations and synchronization plans
tethra destination kinds
tethra destination add github_actions --name ci --owner me --repo app --auth-stdin
tethra destination attach my-app/openai-main ci --secret-name OPENAI_API_KEY
tethra sync plan my-app/openai-main              # dry run
tethra sync run <plan-id>                        # confirm + reauth
tethra key versions my-app/openai-main

# Rotate a credential safely (dry run first, everything confirmed + reauthed)
tethra rotation plan my-app/openai-main --grace-minutes 60
tethra rotation approve <rotation-id>
tethra rotation advance <rotation-id>      # repeat until completed
tethra rotation schedule set my-app/openai-main --every-days 90

# Pricing, templates, and stack detection
tethra pricing list                       # versioned, effective-dated records
tethra pricing propose openai --out p.json   # review against the official page
tethra pricing import p.json              # validated; history preserved
tethra template list
tethra template apply openai-app --project my-app --write-example ~/code/my-app
tethra template detect --repo ~/code/my-app   # evidence + confidence; local only
tethra provider account github --sync     # provider-reported identity only

# Temporary local access (bounds what THIS machine injects; not provider-side)
tethra access grant --project my-app --one-time --ttl-minutes 30
tethra run --grant <grant-id> -- npm test
tethra access end <grant-id> --kill

# Lifecycle, permissions, test keys
tethra key history my-app/openai-main
tethra key permissions-diff my-app/gh-token
tethra key test-create --project my-app --provider openai     --provider-project proj_abc --name probe --ttl-minutes 240

# Run a command with exactly one credential injected (never written to disk)
tethra run --project my-app --credential my-app/openai-main \
    --env OPENAI_API_KEY -- npm run dev

tethra lock
```

Useful details:

- The vault lives in the platform data directory (macOS:
  `~/Library/Application Support/api-tracker` — the directory keeps its
  historical name so existing vaults are found); `--data-dir` or
  `TETHRA_DIR` override it. The desktop app uses the same location, so
  both frontends see the same data.
- For scripts/CI, `TETHRA_PASSWORD`, `TETHRA_PROJECT_PASSWORD`,
  and `TETHRA_BACKUP_PASSWORD` replace interactive prompts, and
  `--value-stdin` feeds secrets on stdin. Prefer sessions interactively:
  environment variables are visible to other processes you run.
- `--json` makes the inspection commands (`doctor`, `settings show`,
  `provider list`, `project list`/`show`, `key list`/`show`/`status`, and the
  `key add`/`project create` results) emit machine-readable output. Purely
  action commands (`lock`, `archive`, `remove`, …) print a plain status line.
- `tethra doctor` checks vault health without unlocking anything (it
  reads only unencrypted metadata: counts, schema version, integrity).

## Security in one paragraph

Credential values are encrypted with XChaCha20-Poly1305 under random
per-project keys, wrapped by a vault key, wrapped by an Argon2id-stretched
master password; every ciphertext is bound to the record it belongs to, so
database tampering and ciphertext swaps are detected. Values are redacted
everywhere by default, revealing/copying/exporting requires re-entering the
master password, and nothing is ever sent anywhere. Read
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
