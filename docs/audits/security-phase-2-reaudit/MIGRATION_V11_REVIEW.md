# Migration v11 — Dedicated Line-by-Line Review

**Verdict: SAFE.** Migration v11 is a single additive, nullable, forward-only column with no data-loss, no downgrade claim, and correct backward-compatibility for the PI-02 fix. It does not block PR #10.

## What v11 is

`crates/core/src/db.rs`, migration entry `version: 11, name: "process start identity for safe termination"`:

```sql
ALTER TABLE process_sessions ADD COLUMN proc_identity TEXT;
```

That is the entire schema change. `proc_identity` is nullable (`TEXT`, no `NOT NULL`, no `DEFAULT`).

## Framework review (`migrate_with`, unchanged by Phase 2)

The diff only *appends* an entry to `MIGRATIONS`; it does not touch `migrate_with`. The framework:

1. `let found = user_version(conn)?; let supported = migrations.last().version;` — **schema-too-new refusal:** `if found > supported { return Err(SchemaTooNew) }`. With v11, `supported == 11`; a DB stamped 12+ is refused, never opened read/write. Reproduced: a DB stamped 99 returned `SchemaTooNew { found: 99, supported: 11 }`.
2. Per migration: `if migration.version <= current { continue }` — **forward-only + idempotent.** Re-running is a no-op.
3. Each migration runs in its own `conn.transaction()`; `execute_batch(sql)` and the `user_version` bump **commit together**. An interrupted/failed migration rolls back atomically and `user_version` does not advance (covered by the existing `failed_migration_rolls_back` unit test, which I read).

## Table lineage (verified by reading every `process_sessions` reference in `MIGRATIONS`)

- v3 (line ~233) `CREATE TABLE process_sessions (...) STRICT` — no FK.
- v6 (lines ~472–473) `ADD COLUMN pid INTEGER; ADD COLUMN grant_id TEXT`.
- v11 (line ~654) `ADD COLUMN proc_identity TEXT`.

Versions are contiguous 1..11. No migration between v3 and v11 already declares `proc_identity`, so the ALTER never collides on a duplicate column for a fresh (1→11) run or any incremental (k→11) run.

## Independent reproduction on a REAL pre-v11 fixture

`evidence/mig_v11_repro.rs` links the **actual** `crates/core` and:

1. Builds a genuine v10 database via `db::migrate_with(&MIGRATIONS[..10])`; asserts `user_version == 10` and that `process_sessions` has `pid`+`grant_id` but **no** `proc_identity`.
2. Inserts a realistic legacy running-session row (`pid=4242`, `grant_id='grant-1'`, no identity column).
3. Runs `db::migrate()` to v11.

Assertions that passed (`evidence/mig_v11_repro.out.txt`):

- `user_version == 11 == current_schema_version()`.
- `proc_identity` column now present.
- **No data loss:** the legacy row's `pid`, `grant_id`, `command`, `injected_vars` are intact and `proc_identity IS NULL`.
- **PI-02 compat invariant:** a migrated pre-v11 row (NULL identity) is **refused** termination — `terminate_verified(4242, None)` returns `Refused{..}`. A pre-v11 record can therefore never be signalled blind after upgrade.
- **Idempotency:** re-running `migrate()` at v11 is a clean no-op.
- **Restart survival:** reopening the DB file and re-migrating is a no-op; the row survives.
- **Schema-too-new:** a DB stamped 99 is refused.

## Brief checklist

| Requirement | Finding |
|---|---|
| Clean migration from every supported prior version (1..10) | PASS — ordered, version-gated; v11 only alters a table that exists by v3 |
| Idempotency | PASS — `version <= current` skip; reproduced |
| Interrupted-migration recovery | PASS — per-migration transaction; `failed_migration_rolls_back` |
| Concurrent first-open | See "Residual" — inherits pre-existing CONC-10; **not worsened** by v11 |
| Null / backward-compatible handling | PASS — nullable column; NULL identity → termination refused (safe) |
| Existing process-session rows | PASS — preserved verbatim; reproduced |
| No data loss | PASS — additive ALTER; reproduced |
| Schema-too-new refusal | PASS — `SchemaTooNew{found:99,supported:11}` reproduced |
| Backup/restore compatibility | PASS — backups are schema-generic (they snapshot the DB); restore migrates forward; `backup_restore` authz test green. `proc_identity` is a normal column carried by any DB-level backup |
| Demo/test vault compatibility | PASS — every `new_vault()` in the workspace migrates to 11; 505/0 |
| Windows/Linux/macOS behaviour | PASS — pure SQLite DDL, platform-independent; the *identity string* is platform-prefixed (`unix:`/`win:`) so a cross-platform vault never matches (tested in `pi02`) |
| No unsupportable downgrade claim | PASS — no downgrade path exists or is claimed; older builds refuse a v11 DB via SchemaTooNew |

## Residual (pre-existing, NOT introduced by v11)

**CONC-10 (concurrent first-open race), Low, deferred.** `user_version` is read *outside* the per-migration transaction, so if two processes open a v10 DB simultaneously, the loser's `ALTER TABLE ADD COLUMN proc_identity` runs after the winner committed and fails with a duplicate-column error (surfaced as a `CoreError`, not corruption). v11 is subject to this exactly as every prior migration is; the migration framework is unchanged by Phase 2, so v11 does not worsen it. No data loss occurs (the winner's migration committed atomically; the loser's rolled back; a retry succeeds). This remains a documented deferred item, not a Phase 2 regression.
