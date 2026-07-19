# Continuation — Everything Still Open After the Phase 2 Re-Audit

**Audit branch:** `audit/security-phase-2-reaudit`. **Reviewed:** `033f747..260e47e` (PR #10). **Verdict:** **PASS WITH REQUIRED CHANGES** — production fixes are correct, but a flaky PI-02 test fails the required CI check (RA2-6). **PR #10 was NOT merged.**

## Required before PR #10 can merge (blocking)

1. **De-flake `pid_reused_by_a_different_process_is_refused`** (`crates/core/tests/pi02_process_identity.rs`) so the required "Rust (core + CLI)" CI check is green on Linux. The 1-second wall-clock wait cannot reliably produce a distinct `ps lstart` second (1-second resolution + rounding slop); wait ≥2 s, or assert the freshly-probed `lstart` actually differs from the recorded one before asserting `Refused` (treat a collision as the documented same-second-recycle residual, not a test failure). Test-only change; the production PI-02 code is correct. Re-run CI, confirm green, then merge with a merge commit (no squash).

## Verified fixed by Phase 2 (this re-audit)

PI-02/CONC-11/CLI-03/RA-1, migration v11, GScan-01/02, CONC-06/GScan-03/CONC-05, DEST-01/02/03/04, OBS-004, M-6, the Tauri direct-authorization harness (+ `provider_admin_disconnect` core reauth), the React security-test foundations (+ IPC-05 `safeExternalUrl`), and RA-4. All FIXED; see `FIX_VERIFICATION_MATRIX.md`.

Still closed from PR #9 (re-confirmed green at `260e47e`): CRYPTO-01, OBS-001, OBS-003, PI-01, IPC-01, IPC-02, CONC-04, ROT-001, PI-06.

## New this re-audit (non-blocking; see `NEW_FINDINGS.md`)

- **RA2-1** Vercel env resolution reads only one page (no pagination) — Low, pre-existing, fails safe.
- **RA2-2** `terminate_pid` is dead production code (misleading doc) — Info.
- **RA2-3** `git_available()` uses an unbounded `git --version` — Info (cannot hang on repo/mount).
- **RA2-4** tampered `proc_identity` matching a live victim would signal it — Info (requires DB write = full compromise).
- **RA2-5** React "32 tests" inflated; holes: reveal auto-hide timer, `EnvView` error path, replace-value dialog clearing; delete test lacks a pre-reauth ordering assert — Low (coverage).

## Confirmed still-open, correctly out of Phase 2 scope

- **RA-2 / NF-1 — CLI broken-pipe panic.** Reproduced live during `smoke.sh` (panic on piped stdout; no secret; 126/0). Fix: reset `SIGPIPE` / handle `ErrorKind::BrokenPipe` in the CLI entry point.
- **RA-3 / NF-2 — unconfined `env_preview` / `env_import` reads.** Read-only, scanner-redacted previews. Fix: confine to registered repositories (mirror `env_example_write`).
- **RA-P2-1** — `backup_create` / `provider_admin_connect` / `provider_admin_test` enforce reauth in the wrapper, not core. Fix: move into core + extend `tauri_command_authz.rs`.
- **RA-P2-2 / RA-P2-3** — 97 low-relevance commands untested; `ProviderDetail` `openUrl` without FE `safeExternalUrl`.
- **CONC-01 / CONC-02** — desktop mutex breadth; auto-lock across suspend. Phase 3 removed git-time from CONC-01 for scans (collect-outside-lock) but not the coarse mutex model.
- **PI-03** — descendant / process-group termination (now tested as documented behavior).
- **PI-05** — wall-clock grant/session expiry rollback (desktop auto-lock uses monotonic time).
- **ROT-002..008, ROT-011** — rotation state-machine races/correctness. **Untouched by Phase 2** and the highest-value remaining follow-up. Independent re-verification of these races is the top next-audit item.
- **Remaining Low/Info from the deep audit** — DEST-05..13, OBS-002/005..012, FS-01..08, CONC-07..10/12, CLI-02/04/05/06, CRYPTO-03/04/05, NET-01..04, GScan-04/05, INFO-01/02.

## Manual / out-of-automated-scope verification still required

- **Windows behavioural runner** — process-identity probe (`Get-CimInstance`), `taskkill` graceful→forceful, git hooks via `sh`, and the case-insensitive env scrub. CI compiles these paths; none is executed here.
- **Live-provider verification** (real credentials) — destination read-back / `exists` semantics per provider (GitHub Actions, AWS, Vercel), and the full rotation lifecycle.
- **Packaged Tauri app** — `cargo-tauri` is not installed locally; no `.app`/`.dmg` bundle or runtime CSP/allowlist/opener check was produced. Build the bundle and verify the opener capability restricts schemes (closes RA-P2-3's backend half).
- **CI action SHA↔upstream-tag correspondence** — verify each pinned SHA belongs to its claimed release tag (offline check not possible here; SHA/version pairs tabulated in `FIX_VERIFICATION_MATRIX.md` §M-6).
- **Manual UI plan** — add hook `active`/`Overridden` status, destination not-checked drift rows, invalid-expiration display, and the `docs_url` inert-rendering to the UI test plan.

## Release-gate status after this re-audit

- **Public alpha:** blocker set already closed by PR #9; unaffected.
- **Production / GA:** Phase 2 closes the remaining audit-named GA-gate findings (GScan-01/02, DEST-01/02/03, OBS-004, CONC-06, PI-02, M-6, the Tauri/frontend automated-test gaps). Before a GA claim: the deferred items above (notably PI-05, CONC-01/02, the ROT-* races, RA-2/RA-3), the manual Windows/live-provider/packaged-app verification, and closing the RA2-5 React coverage holes.

## How to re-run this re-audit

```bash
git -C <worktree> switch audit/security-phase-2-reaudit && git rev-parse HEAD   # expect 260e47e (+ audit doc commit)
cargo test --workspace --all-targets
cargo +1.97.0 clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
bash scripts/smoke.sh
( cd apps/desktop && npm ci && npm run format:check && npm run lint && npm run typecheck && npm test && npm run build )
# Migration v11 fixture harness: docs/audits/security-phase-2-reaudit/evidence/mig_v11_repro.rs
```
