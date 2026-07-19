# Independent Remediation Re-Audit — PR #9 (release-blocker remediation)

- **Model / provenance:** Claude Fable 5 (`claude-fable-5`), highest available effort, extended
  thinking enabled. No model fallback occurred.
- **Worktree:** `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-remediation-reaudit`,
  branch `audit/remediation-reaudit`, started clean.
- **Range under review:** vulnerable baseline `7d81090a1068476291546963e68ca8c7de1a7145` →
  remediation `1ec4073` (9 commits, `git merge-base` confirms baseline is an ancestor of HEAD).
- **Scope:** audit-only. No production source, remediation test, or PR was modified. All new
  material is under `docs/audits/remediation-reaudit/`. A disposable git worktree at the
  baseline was used for independent reproduction; the audit worktree was never altered to
  simulate the baseline.

## Overall verdict

> **PASS — PR #9 fixes the reviewed release-blocker set with no new merge-blocking finding.**

All nine remediation areas (13 finding IDs: CRYPTO-01/CONC-03, CONC-04, OBS-003, PI-01/CLI-01,
IPC-01/FS-09, OBS-001, ROT-001/ROT-010, PI-06, IPC-02) are verified **FIXED** at `1ec4073`,
with two precise qualifications that do **not** block merge: PI-06's guard covers the audited
`terminate_pid` but not a second CLI kill path (RA-1), and the PI-01 scrub has a theoretical
Windows-casing edge (RA-4). Four non-blocking follow-ups are recorded in `NEW_FINDINGS.md`.

**This PASS is scoped to PR #9's merge readiness for the reviewed blocker-remediation set. It
is NOT a statement that API Tracker is ready for public alpha or GA.** The audit's own
Production/GA blocker list (GScan-01/02, DEST-01/02/03, OBS-004, CONC-06, PI-02, M-6, and the
Tauri/frontend automated-test gaps) is outside this PR and remains open.

## How this was verified

Every changed production line in the `7d81090..1ec4073` diff was read (16 production files,
~860 changed lines across `crates/core`, `apps/cli`, `apps/desktop`), and each fix was attacked
from the code rather than accepted from the remediation report. Verification combined:

1. **Source-level invariant checks** beyond the diff — confirming the DB opens WAL +
   busy_timeout 5s + foreign_keys=1 (the substrate CRYPTO-01/CONC-04 depend on); enumerating
   every project-key ciphertext writer to prove none escapes `write_txn`; confirming
   `auto_resolve_stale` structurally excludes the new alert kinds; tracing the rotation
   state-machine CAS and every ROT-001 crash/lost-response branch; confirming
   `scan_history(None)` = `git log --all` (full history).
2. **Independent reproduction** of the flagship CRYPTO-01 against the real baseline (the
   unmodified regression test orphans 3/3), plus a 5×-repeated deterministic race stress at HEAD
   (~80 armed races, zero orphans).
3. **Full test execution:** workspace 413/0; each focused regression suite individually; clippy
   `-D warnings` (0); `fmt --check`; the exact frontend CI commands (prettier/eslint/tsc/vitest
   8/8/vite build); and `smoke.sh` (126/0) on the release binary with production KDF.
4. **Baseline-evidence validation:** confirmed each remediation baseline-fail log faithfully
   represents `7d81090` (real runs for CRYPTO-01/PI-01/OBS-003/ROT-001; faithful
   signature-adapting or deterministic-seam shims for IPC-01/IPC-02/CONC-04/OBS-001 that
   preserve the property under test).

Detail per finding is in `FIX_VERIFICATION_MATRIX.md`; full run output in `TEST_RESULTS.md`;
new/deferred issues in `NEW_FINDINGS.md`; residual scope and re-run instructions in
`CONTINUATION.md`.

## Findings summary

| Finding | Verdict | Blocks PR #9 |
|---|---|---|
| CRYPTO-01 (+CONC-03) — concurrent-rotation ciphertext orphan | FIXED | No |
| CONC-04 — non-transactional backup snapshot | FIXED | No |
| OBS-003 — malformed sync range wipes usage history | FIXED | No |
| PI-01 (+CLI-01) — master password leaks to child env | FIXED (Windows-casing caveat RA-4) | No |
| IPC-01 (+FS-09) — arbitrary file overwrite via IPC | FIXED (FS-race TOCTOU out of threat model) | No |
| OBS-001 — exposure alerts self-resolve | FIXED | No |
| ROT-001 (+ROT-010) — ambiguous revoke wedge / unsafe rollback | FIXED | No |
| PI-06 — `terminate_pid` accepts pid ≤ 0 | FIXED (terminate_pid); PARTIAL at class level → RA-1 | No |
| IPC-02 — credential deletion without core reauth | FIXED | No |

New (non-blocking, pre-existing): **RA-1** `access grant end --kill` bypasses the pid-guard;
**RA-2** CLI broken-pipe panic (= NF-1); **RA-3** unconfined `env_preview`/`env_import` reads
(= NF-2); **RA-4** Windows env-casing scrub edge. **PI-02** (PID reuse) correctly remains open —
the fix does not claim to solve it.

## Highlights of what was checked most aggressively

- **CRYPTO-01 / CONC-03 (transaction boundary):** the entire read-wrap → encrypt → write span
  now runs under one `BEGIN IMMEDIATE` transaction with the project row read *after* the lock is
  taken, in all four writers; `remove_project_password` hoists its Argon2id unwrap outside the
  lock then compare-and-swaps the wrap. Rotation re-encrypts both `credentials` and
  `credential_versions`. No ciphertext-writing path reads a project key outside a transaction
  and writes inside a later one. Independently reproduced the baseline orphan and stress-tested
  the fix.
- **ROT-001 / ROT-010 (the under-reported production change):** production code *was* changed.
  The state machine now reaches a truthful terminal or explicit manual-recovery state for every
  crash / lost-response / first-404 / wrong-key / retry / rollback scenario, without false
  success, duplicate revocation, unsafe rollback of a permanently-deleted key, or a permanent
  wedge. The `OLD_DISABLED → MANUAL_REQUIRED` test change is backed by the real CAS transition,
  not a loosened assertion.
- **Direct-IPC bypass (IPC-01, IPC-02):** authorization for both `env_example_write` and
  `credential_delete` is enforced in core via `verify_master_password`, so a hostile webview
  issuing a raw `invoke` cannot bypass reauth or path confinement; the React dialogs are UX
  only.
- **OBS-001 resolution honesty:** `--reverify` resolves an exposure alert only after a clean
  **full-history** (`git log --all`) + working-tree scan, so a secret that left the working tree
  but remains in history keeps the alert open — the specific failure the brief flags.
