# Independent Adversarial Re-Audit — API Tracker Security Remediation Phase 2 (PR #10)

- **Model / provenance:** Claude Fable 5 (`claude-fable-5`), max effort, extended thinking enabled. **No model fallback occurred.**
- **Worktree:** `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-security-phase-2-reaudit`, branch `audit/security-phase-2-reaudit`, started **clean**.
- **Range under review:** Phase 2 baseline `033f747` (merged PR #9) → `260e47e` (12 commits; `git merge-base HEAD 033f747 == 033f747` confirms the baseline is a proper ancestor). Diff: **59 files, +8545 / −454**.
- **Scope:** audit-only. No production source, no Phase 2 test, and no PR was modified. All new material is under `docs/audits/security-phase-2-reaudit/`. Reproductions ran in disposable scratch dirs outside the repo. No provider/destination/network host was contacted; synthetic credentials only.

## Overall verdict

> **PASS WITH REQUIRED CHANGES — the Phase 2 fixes are substantially correct, but one specified change is required before merge: de-flake the timing-dependent PI-02 test that fails the required CI check.**

Every claimed Phase 2 *production* fix is **FIXED** at `260e47e`, verified by attacking the code rather than trusting the Phase 2 report — no fix is ineffective and no Phase 2 change introduces a production regression. **However, PR #10 must NOT be merged as-is:** the required "Rust (core + CLI)" GitHub CI check is **RED** on the PR head `260e47e`. A new Phase 2 test, `pid_reused_by_a_different_process_is_refused` (`crates/core/tests/pi02_process_identity.rs:183`), is **flaky/timing-dependent** — it passes 15/15 locally on macOS but failed on the Linux CI runner with *"a recycled PID must fail the identity match, got Signalled"* (finding **RA2-6**). This is a merge-blocker under the closeout gate ("every required CI check must be green"). The remaining new/residual items (`RA2-1..5`, `RA-P2-1..3`, the deferred backlog) are Low/Informational and non-blocking.

**Even once CI is green, this remains scoped to PR #10's Phase 2 merge-readiness — NOT a statement that API Tracker is GA-ready.** Deferred blockers remain (PI-05, CONC-01/02, ROT-002..008/011, the manual Windows/live-provider/packaged-app verification) — see `CONTINUATION.md`.

### Required change before merge (single, specified)

De-flake `pid_reused_by_a_different_process_is_refused`. The test constructs a "recycled PID with a different start time" and asserts termination is `Refused`, but its 1-second wall-clock wait cannot reliably produce distinct `ps lstart` values: `ps lstart` has 1-second resolution with jiffies→wall-clock rounding slop, so on the Linux runner the new decoy's displayed start-second collided with the recorded (dead) identity's — and the production code **correctly** matched two now-identical `lstart`+`comm` identities and signalled, hitting the *documented* same-second-same-executable recycle residual the PI-02 design explicitly cannot distinguish. The fix is a **test** fix (not production): either wait ≥2 s, or assert the recorded vs freshly-probed `lstart` strings actually differ before asserting `Refused`, or skip when they collide. Re-run the required CI checks and confirm green. Per audit scope I did not modify the test.

## How this was verified

Every changed production line in `033f747..260e47e` was read (25 production files across `crates/core`, `apps/cli`, `apps/desktop`, `.github/workflows`). Each fix was attacked from the code:

1. **Source-level invariant checks beyond the diff** — inventoried every process-termination entry point and proved they all route through the single guarded `terminate_verified` (and that legacy `terminate_pid` has zero production callers); inventoried every git subprocess and proved all repository/network calls are bounded; traced the destination `exists`/`delete`/`record_verify`/`execute_step` state machine; confirmed `reverify_repo_exposure_collected` resolves alerts only on `count == 0 && coverage_complete`; confirmed `credential_model` isolates malformed expirations without fabrication; confirmed `provider_admin_disconnect` verifies the master password in core.
2. **Independent reproductions** — a migration-v11 harness linking the *actual* `crates/core` (real pre-v11 fixture → forward-migrate → NULL-identity row refused termination → `SchemaTooNew` refusal); a full third-party-action SHA/permission audit of both workflows; a Tauri-command inventory reconciliation (137 = 137 = 137, identical sets).
3. **Full test execution** — workspace **505/0**; each Phase 2 suite individually (pi02 10, gscan_hooks 12, gitbound 10, dest_truthfulness 5, obs004 5, tauri_command_authz 18, access_end_kill_guard 1); `clippy -D warnings` 0; `fmt --check` clean; the exact frontend CI (prettier/eslint/tsc/**vitest 32**/vite build); `smoke.sh` **126/0** on the release binary with production KDF.
4. **Adversarial sub-reviews** — the React suite was read line-by-line against its production components for over-mocking/fake-timer/tautology hazards (verdict: real tests, correct seam, three documented coverage holes).

Per-finding detail is in `FIX_VERIFICATION_MATRIX.md`; migration v11 in `MIGRATION_V11_REVIEW.md`; run output in `TEST_RESULTS.md`; new/deferred items in `NEW_FINDINGS.md`; residual scope in `CONTINUATION.md`.

## Findings summary

| Finding(s) | Verdict | Blocks PR #10 |
|---|---|---|
| PI-02 / CONC-11 / CLI-03 / RA-1 — process identity before termination | FIXED | No |
| Migration v11 — `proc_identity` additive column | FIXED | No |
| GScan-01 / GScan-02 — git hook truthfulness & scan-first chaining | FIXED | No |
| CONC-06 / GScan-03 / CONC-05 — bounded git execution & streaming | FIXED | No |
| DEST-01 / DEST-02 / DEST-03 / DEST-04 — destination truthfulness | FIXED | No |
| OBS-004 — malformed expiration isolation | FIXED | No |
| M-6 — CI action SHA pinning & least privilege | FIXED | No |
| Tauri authz harness (+ `provider_admin_disconnect` core reauth) | FIXED (5 documented gaps) | No |
| React security tests (+ IPC-05 `safeExternalUrl`) | FIXED (IPC-05 solid; RA2-5 coverage gaps) | No |
| RA-4 — Windows env-casing scrub | FIXED | No |

**Merge-blocking (required change):** **RA2-6** — the new PI-02 test `pid_reused_by_a_different_process_is_refused` is flaky/timing-dependent and **fails the required "Rust (core + CLI)" CI check** on the Linux runner (passes 15/15 locally on macOS). Production code is correct; the test over-asserts against the documented same-second-recycle residual. PR #10 must not merge until this is de-flaked and CI is green.

New (non-blocking): **RA2-1** Vercel no pagination (Low, pre-existing); **RA2-2** `terminate_pid` dead code (Info); **RA2-3** unbounded `git --version` (Info); **RA2-4** tampered-identity threat boundary (Info); **RA2-5** React test count inflated + 3 coverage holes (Low). **RA-P2-1/2/3** confirmed valid and non-blocking. Deferred backlog (RA-2 broken-pipe reproduced, RA-3, PI-03/05, CONC-01/02, ROT-002..008/011) correctly out of scope.

### CI status of PR #10 head `260e47e` (inspected via `gh`)

| Check | Result |
|---|---|
| Rust (core + CLI) | **FAILURE** — `pid_reused_by_a_different_process_is_refused` (RA2-6) |
| Rust core (Windows) | success |
| Desktop frontend | success |
| Desktop backend (macOS) | success |

`gh pr view 10`: OPEN, **draft**, base `main`, head `fix/security-phase-2` @ `260e47e` (== audited), `mergeable: MERGEABLE` (no conflicts), `mergeStateStatus: UNSTABLE` (checks not all green). Evidence: `evidence/ci_pi02_flake_failure.log.txt`.

## What was checked most aggressively

- **Every termination entry point routes through the shared guarded path.** `terminate_pid` (no identity check) has **zero production callers**; the three recorded-session paths and the desktop command all reach `terminate_verified` via `vault.terminate_process_session`; the duration-limit auto-kill uses the live `Child` handle (a stronger primitive). The residual check-to-signal TOCTOU is **honestly documented, not claimed eliminated** — exactly as the brief requires.
- **Incomplete scans can never read as clean.** `complete = complete && warnings.is_empty()`; alerts resolve only on `count == 0 && coverage_complete`; the incremental monitor raises a persistent, non-auto-resolving `RepoScanCoverageGap`. Proven with hang/flood/slow `git` stubs that also assert the child PID was reaped.
- **Destination identity is key + exact targets + custom-env context**, and no error path advances `last_verified_at` or presents stale drift as fresh — proven with mocked HTTP including an *empty* response queue so a reauth/identity bypass would fail differently.
- **Migration v11 is additive and preserves the PI-02 invariant** — a real pre-v11 row migrates to a NULL `proc_identity` that is refused termination (independently reproduced against the real core).
