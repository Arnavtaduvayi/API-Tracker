# Contributing to API Tracker

Thanks for helping build a trustworthy local-first credential manager.

## Ground rules

- **Security first.** Never log, print, serialize, or commit credential
  values. All secrets go through `SecretString`/`SecretBytes` (they redact
  and zeroize). Any new code path that touches secrets needs a test proving
  it does not leak them.
- **Local-first.** No telemetry, no analytics, no calls to any
  API-Tracker-operated service — the current core performs no network I/O
  at all. Future provider calls go directly from the user's device.
- **Shared core.** Business logic lives in `crates/core` only. The CLI and
  desktop app are thin frontends; do not duplicate logic in TypeScript.
- **Honesty about capabilities.** Never present a provider feature, status,
  or automation as working when it is not.
- **Test credentials must be obvious fakes**, e.g.
  `FAKE-TEST-NOT-A-REAL-KEY-000001`. Never anything resembling a real key.
- Tests must not touch the developer's real vault: always use temp dirs
  (`API_TRACKER_DIR`).

## Repository layout

```text
crates/core/          shared Rust core (vault, crypto, db, models, services)
apps/cli/             api-tracker CLI
apps/desktop/         React/TS UI + src-tauri (Tauri v2 backend)
docs/                 product spec, architecture, ADRs (docs/decisions/)
```

Read `docs/ARCHITECTURE.md` and the ADRs in `docs/decisions/` before
changing architecture-level behavior; add a new ADR for significant
decisions.

## Development setup

Prerequisites: Rust stable (1.85+), Node 20+, plus the
[Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your
platform.

```bash
# Rust checks (run all of these before pushing)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core -p api-tracker-cli

# Frontend checks
cd apps/desktop
npm install
npm run lint && npm run typecheck && npm test && npm run format:check
npm run build

# Run the desktop app against your code
npx tauri dev
```

`API_TRACKER_INSECURE_FAST_KDF=1` weakens Argon2id **in debug builds only**
so tests are fast; release builds ignore it.

To experiment without touching your real vault:

```bash
API_TRACKER_DIR=/tmp/at-dev target/debug/api-tracker init
```

## Adding a provider or detection pattern

Providers are TOML manifests under `provider-manifests/` (embedded and
validated at build time — see `crates/core/src/providers.rs`). To add one,
copy an existing file and:

- Fill the official links, `credential_types`, and expiration behavior.
- List only **secret-bearing** environment variables in `env_vars` (never
  URLs, org ids, or publishable keys — they cause scanner false positives).
- Add `[[detection]]` patterns using **public** key prefixes/shapes only
  (never a real secret); every regex must compile (a test enforces this).
- Fill the `[capabilities]` matrix **honestly**, verified against the
  provider's official documentation. Nothing is `implemented` until a real
  connector exists; use `supported_not_implemented`, `unsupported`,
  `manual_only`, plus `requires_admin_credential` and `attribution` as
  applicable. Never present account/project-level usage as exact per-key.

Then add the file to `MANIFEST_SOURCES` and run `cargo test -p api-tracker-core
providers::` — the validation test will reject malformed manifests.

## Database migrations

Migrations live in `crates/core/src/db.rs` and are append-only: never edit a
released migration; add a new numbered one. Restoring backups requires
matching schema versions, so bumping the schema also means teaching restore
about the old version (see ADR 0006).

## Commit style

Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`), present
tense, scoped to one logical change. Make sure the checks above pass before
committing; do not commit broken checkpoints, vault databases, backups, or
`.env` files (the `.gitignore` blocks the usual suspects).

## Reporting security issues

See [SECURITY.md](SECURITY.md) — privately, via GitHub Security Advisories.
