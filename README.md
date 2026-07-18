# API Tracker

A local-first desktop app and CLI for individual developers to organize,
secure, and track the API credentials scattered across their projects.

Think of it as a folder system for API keys: a **project** is a folder, each
**credential** is an encrypted record inside it, and the app tells you what
state each key is in — expired, expiring soon, unused, stale, reused across
projects — with the reason and evidence for every claim.

Everything stays on your computer. There is no account, no cloud service, no
telemetry, and no API Tracker server. The only network traffic the finished
product will ever produce is direct traffic between your machine and API
providers you explicitly configure (not implemented yet — see status below).

## Status: early, working foundation

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
- **Desktop app and CLI share one vault** — both are thin frontends over the
  same Rust core crate and the same SQLite database.
- **Auto-lock** — configurable inactivity lock for the desktop app and CLI
  sessions.

Not implemented yet (planned, see `docs/PRODUCT_SPEC.md`): provider API
integrations (validation, usage, cost, permissions), repository secret
scanning and Git hooks, documentation-change watching, alerts/notifications,
usage dashboards, packaged installers/signing. The provider catalog in this
version is informational only and makes no capability claims.

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
# binary at target/release/api-tracker

# Desktop app
cd apps/desktop
npm install
npx tauri build          # bundles the app (unsigned)
npx tauri dev            # or run it in development mode
```

## CLI quick start

```bash
api-tracker init                     # create the encrypted vault
api-tracker unlock                   # prints an export API_TRACKER_SESSION=... line
export API_TRACKER_SESSION="..."     # paste it (or: eval "$(api-tracker unlock --print-export)")

api-tracker project create my-app --env development --env production \
    --repo ~/code/my-app
api-tracker key add --project my-app --name openai-main --provider openai \
    --environment production --expires 2027-01-01
# (the secret is prompted, hidden; it is never a command-line argument)

api-tracker key list                 # masked values only
api-tracker key status my-app/openai-main   # explainable status report
api-tracker key reveal my-app/openai-main   # asks for the master password again

api-tracker backup create ~/api-tracker-backup.json
api-tracker backup verify ~/api-tracker-backup.json
api-tracker lock
```

Useful details:

- The vault lives in the platform data directory (macOS:
  `~/Library/Application Support/api-tracker`); `--data-dir` or
  `API_TRACKER_DIR` override it. The desktop app uses the same location, so
  both frontends see the same data.
- For scripts/CI, `API_TRACKER_PASSWORD`, `API_TRACKER_PROJECT_PASSWORD`,
  and `API_TRACKER_BACKUP_PASSWORD` replace interactive prompts, and
  `--value-stdin` feeds secrets on stdin. Prefer sessions interactively:
  environment variables are visible to other processes you run.
- `--json` on any command emits machine-readable output.
- `api-tracker doctor` checks vault health without unlocking anything.

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
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core -p api-tracker-cli

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
