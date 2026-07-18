# ADR 0001: Cargo workspace with a single shared core crate

Status: accepted (2026-07-17)

## Decision

Use one Cargo workspace with three members:

- `crates/core` (`api-tracker-core`) — all security-sensitive and business
  logic: crypto, vault, SQLite storage and migrations, models, status engine,
  reuse detection, backups, CLI sessions, audit trail.
- `apps/cli` (`api-tracker-cli`, binary `api-tracker`) — a thin command-line
  frontend over the core.
- `apps/desktop/src-tauri` (`api-tracker-desktop`) — a thin Tauri command
  layer over the core, with a React/TypeScript UI in `apps/desktop/src`.

The product specification sketched many small crates (`vault`, `database`,
`providers`, `scanner`, `usage`, `alerts`, `docs-watcher`). We start with one
core crate and split later when a boundary earns its keep.

## Why

- The vault, database, models, and services are tightly coupled; separate
  crates at this stage would mean churn in cross-crate interfaces without any
  consumer benefiting. Both frontends need exactly one dependency.
- A single crate makes the "desktop and CLI share all business logic" rule
  structurally trivial to enforce: neither frontend depends on anything but
  `api-tracker-core`.
- Future subsystems with genuinely separate concerns (repository scanner,
  provider connectors, docs watcher) can become sibling crates without
  breaking this layout.

## Alternatives considered

- Many small crates (as sketched in the spec): rejected for now — premature
  boundaries, slower builds, no second consumer for any of them.
- Separate `vault`/`database` crates: rejected — the vault *is* the database
  plus the key hierarchy; splitting them invites accidental use of the
  database without the vault's invariants.

## Security implications

Positive: one place to audit; frontends cannot bypass core invariants because
the crate only exposes safe operations (e.g., there is no public API that
returns a decrypted value without reauthentication).

## Future limitations

If the core grows past roughly the scanner milestone, compile times and
review scope will justify extracting `scanner`/`providers` crates. The
workspace layout already anticipates that.
