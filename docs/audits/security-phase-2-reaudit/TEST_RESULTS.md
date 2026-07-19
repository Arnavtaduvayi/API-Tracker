# Phase 2 Re-Audit — Test Results

**Model:** Claude Fable 5 (`claude-fable-5`), max effort, extended thinking. No fallback.
**Worktree:** `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-security-phase-2-reaudit`
**Branch:** `audit/security-phase-2-reaudit` · **HEAD under review:** `260e47e`
**Baseline (merged PR #9):** `033f747` (confirmed `git merge-base HEAD 033f747 == 033f747`, a proper ancestor).
**Toolchain:** rustc/cargo 1.96.1 (default) + cargo 1.97.0 (clippy, per CI parity); node v24.13.0; npm 11.6.2; git 2.50.1. `cargo-tauri` is NOT installed locally (no `.app`/`.dmg` bundle — see limitations).
**Date:** 2026-07-19.

All runs used synthetic credentials and disposable temp directories only. No provider, destination, or network host was contacted (all provider/destination traffic is `MockHttpClient`; all git-misbehaviour is stub `git` binaries; all repos are `tempfile` dirs). No production source was modified.

---

## Required commands

| Command | Result | Duration |
|---|---|---|
| `cargo test --workspace --all-targets` | **505 passed, 0 failed, 0 ignored** | 110 s |
| `cargo +1.97.0 clippy --workspace --all-targets -- -D warnings` | **0 warnings (exit 0)** | 36 s |
| `cargo fmt --all --check` | **clean (exit 0)** | <1 s |
| `bash scripts/smoke.sh` | **126 passed, 0 failed (exit 0)** | 76 s |

`smoke.sh` builds and exercises the **release** binary (production Argon2id KDF). The RA-2 broken-pipe panic fired on piped stdout during the run (as it did in the PR #9 re-audit) but did not fail any assertion (126/0) — see NEW_FINDINGS RA-2.

## PR #10 GitHub CI status (inspected via `gh`, head `260e47e`) — RED

**A required check fails on the PR head — this is the merge blocker (RA2-6).** My local workspace run passed 505/0, but the Linux CI runner did not:

| CI check | Result |
|---|---|
| **Rust (core + CLI)** | **FAILURE** — `pid_reused_by_a_different_process_is_refused` (`got Signalled`) |
| Rust core (Windows) | success |
| Desktop frontend | success |
| Desktop backend (macOS) | success |

**Local vs CI discrepancy explained:** the failing test is flaky/timing-dependent (relies on `ps lstart` 1-second granularity to separate a recycled PID's start-time). It passed **15/15** on a repeated local macOS run but failed on the Linux runner, where `ps lstart` rounding let the new decoy's start-second collide with the recorded identity — hitting the documented same-second-recycle residual. Production PI-02 code is correct; the test over-asserts. See NEW_FINDINGS `RA2-6`; evidence `evidence/ci_pi02_flake_failure.log.txt`. **PR #10 was NOT merged.**

## Each Phase 2 regression suite, run individually

| Suite | Tests | Result |
|---|---|---|
| `crates/core` `pi02_process_identity` (PI-02/CONC-11/CLI-03/RA-1) | 10 | ok |
| `crates/core` `gscan_hooks` (GScan-01/02) | 12 | ok |
| `crates/core` `gitbound_scanning` (CONC-06/GScan-03/CONC-05) | 10 | ok |
| `crates/core` `dest_truthfulness` (DEST-01/03/04) | 5 | ok |
| `crates/core` `obs004_expiration_isolation` (OBS-004) | 5 | ok |
| `crates/core` `tauri_command_authz` (Tauri authz harness) | 18 | ok |
| `apps/cli` `access_end_kill_guard` (RA-1) | 1 | ok |
| `crates/core` `destinations::tests` (DEST-01/02 unit, inside lib) | 11 new | ok (part of workspace run) |

Baseline-failure evidence in `docs/remediation-phase-2/evidence/` was cross-read and is consistent with the fixes: `pi02` (1 stale-PID test killed the decoy at baseline), `gscan` (9/10 property tests failed), `conc06` (hung git blocked >5 s), `dest` (12 tests failed: missing-on-error / key-only / verified-on-failure), `obs004` (one malformed expiry failed the whole listing). I did not re-run the baseline harnesses at `033f747` (audit worktree kept clean at `260e47e`); baseline reproduction was done by independent construction at HEAD (migration harness, source proof) rather than checkout.

## Frontend CI (exact CI commands, `apps/desktop`)

`npm ci` used a scratchpad cache (`~/.npm` is root-owned in this environment); no lockfile change.

| Step | Result |
|---|---|
| `npm ci` | exit 0 |
| `npm run format:check` (prettier) | exit 0 |
| `npm run lint` (eslint) | exit 0 |
| `npm run typecheck` (`tsc --noEmit`) | exit 0 |
| `npm test` (vitest) | **32 passed (32)**, 7 files |
| `npm run build` (`tsc --noEmit && vite build`) | exit 0, 59 modules, built in ~0.45 s |

Vitest breakdown: `utils.test.ts` 8, `safeUrl.test.ts` 3, `api.security.test.ts` 8, `ReauthDialog.test.tsx` 4, `RotationView.security.test.tsx` 1, `App.security.test.tsx` 2, `CredentialDetail.security.test.tsx` 6.

## Independent reproductions built for this re-audit

- **Migration v11 on a real pre-v11 fixture** — a disposable harness (`evidence/mig_v11_repro.rs`) that path-depends on the *actual* `crates/core` and drives `db::migrate_with(&MIGRATIONS[..10])` → insert a legacy `process_sessions` row → `db::migrate()` to v11. All assertions passed (`evidence/mig_v11_repro.out.txt`), including `SchemaTooNew { found: 99, supported: 11 }`. See `MIGRATION_V11_REVIEW.md`.
- **GitHub Actions pinning** — programmatic verification of all 23 `uses:` refs as 40-hex SHAs + permission-scope analysis (delegated, cross-checked). See `FIX_VERIFICATION_MATRIX.md` §M-6.
- **Tauri command inventory reconciliation** — `#[tauri::command]` fns (137) = `generate_handler!` entries (137) = inventory JSON entries (137), identical sets.

## Builds

- **Desktop backend (`api-tracker-desktop` bin)** compiles clean — it is part of `cargo test --workspace --all-targets` (0 unit tests, `unittests src/main.rs ... ok`) and of the clippy `--all-targets` run. Confirmed the Tauri command layer type-checks against the core API.
- **Vite production build** succeeded (frontend `npm run build`).
- **Packaged `.app`/`.dmg`: NOT produced** — `cargo-tauri` is not installed in this environment. Runtime CSP/allowlist/opener verification remains a manual gap (same limitation the Phase 2 report records).

## Platform limitations (unchanged from Phase 2, confirmed honest)

- The Unix-only suites (`#![cfg(unix)]`: pi02, gscan_hooks, gitbound_scanning, obs004, dest) do not execute on Windows. The Windows process-identity probe (`Get-CimInstance`), `taskkill`, git-hooks-via-`sh`, and the case-insensitive env scrub compile in CI but are not behaviourally executed here; the env-scrub case-insensitive mode is exercised directly via the `env_name_is_scrubbed(_, true)` helper tests.
- No `#[ignore]`, `todo!()`, `unimplemented!()`, or `dbg!()` was introduced anywhere in the diff. 0 tests ignored across the workspace run.
