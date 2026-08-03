# Release-Blocker Remediation

**Model:** Fable 5 (`claude-fable-5`), effort `max`. **Worktree:**
`API-Tracker-remediation`, branch `fix/security-release-blockers`.
**Starting production baseline:** `7d81090a1068476291546963e68ca8c7de1a7145`.
**Audit source (read-only):** `../API-Tracker-deep-audit` @ `fba2b72`
(`audit/deep-pressure-test`).

This phase fixes the confirmed release blockers from the deep audit while
preserving Tethra's local-first architecture and existing product
behavior. Every fix ships with a regression test that fails at baseline (each
demonstrated by running the test against the vulnerable behavior — via a
temporary in-place shim where a live baseline run is unsafe — and captured
under `docs/remediation/evidence/`), and the corrected implementation is
verified green. No schema migration was added. No production data format
changed. Only synthetic credentials and disposable temp directories were used.

One finding — **PI-06** — is verified by code inspection and a fixed-behavior
test only: running its baseline is inherently unsafe (`kill 0` / `kill -1`
would signal the test runner's own process group or every process the user can
signal — that *is* the vulnerability). The audit's `MATERIAL_LEADS_VERIFICATION`
records the baseline absence of the guard.

---

## CRYPTO-01 (+CONC-03) — Concurrent project-key rotation orphaned ciphertext

- **Root cause:** `add_credential` and `replace_credential_value` read the
  project-key wrap, derived the key, encrypted, and wrote in *separate*
  autocommit statements. A project-key rotation (`set_project_password` /
  `remove_project_password`) committing inside that window destroyed the old
  wrap; the racing write then persisted ciphertext under a key with no wrap
  anywhere — silent, permanent loss of that credential value, which also
  wedged every future rotation of the project (the orphan can never be
  re-encrypted).
- **Final design:** both writers now run their whole read-wrap → derive →
  encrypt → write span inside one `BEGIN IMMEDIATE` transaction
  (`UnlockedVault::write_txn`), reading the project row only *after* the write
  lock is held, so the existing BLAKE3 wrap-hash freshness check is evaluated
  against the authoritative row. The rotation writers take the same write lock
  before their own row read, so the race serialises cleanly in both
  directions. `remove_project_password` hoists its memory-hard unwrap outside
  the lock and then compare-and-swaps the wrap it derived from. A losing
  operation fails with the typed `ProjectLocked` / `Busy` errors, never a
  partial write. Chose the transaction approach over a `key_generation` CAS
  column because it needs no schema change and reuses the freshness check
  already in place.
- **Files changed:** `crates/core/src/vault.rs`, `crates/core/src/error.rs`
  (new `CoreError::Busy` → code `vault_busy`), `crates/core/Cargo.toml`
  (dev-dep `rusqlite` for the lock probe).
- **Security invariant:** a credential add or value replacement racing a
  project-key rotation either commits under the currently persisted project
  key or fails with a typed error; committed ciphertext is always decryptable
  under the persisted key, and rotation never wedges.
- **Regression test:** `crates/core/tests/crypto01_rotation_race.rs` —
  in-process and **multi-process** (spawned child) variants, made
  deterministic by a write-lock probe rather than timing; asserts no orphaned
  ciphertext, the sentinel value survives, and a follow-up rotation succeeds
  (which re-encrypts every row, proving nothing is orphaned). Runs repeatedly.
- **Baseline evidence:** `evidence/crypto01_baseline_fail.log.txt` — 3/3 race
  tests orphan at baseline; corroborated by the audit's 25/25 reproduction.
- **Corrected result:** all four tests pass; every armed race refuses with
  `project_locked`. Established over ≥5 consecutive full runs.
- **Deviation from audit recommendation:** none material (audit proposed
  `IMMEDIATE` transaction or a `key_generation` CAS; implemented the former).
- **Residual risk:** a busy timeout under sustained contention surfaces as a
  typed `Busy`/`ProjectLocked` the caller must retry; no data risk.
- **Manual tests still required:** none specific beyond the checked-in suite.

## CONC-04 — Non-transactional backup snapshot

- **Root cause:** `collect_payload_v2` read each table with a separate
  autocommit `SELECT`. A writer committing between two tables' reads (worst
  case, a project-key rotation between `credentials` and `projects`) produced
  a backup pairing old ciphertext with the new wrap — internally
  inconsistent, undetectable by `verify`, unrestorable.
- **Final design:** payload collection runs inside one deferred read
  transaction, so every table comes from the same WAL snapshot; concurrent
  writers proceed unblocked and simply do not appear in the snapshot. A
  post-collection consistency tripwire asserts every credential's project row
  is present in the same payload.
- **Files changed:** `crates/core/src/backup.rs`.
- **Security invariant:** every table in one backup reflects the same logical
  snapshot; a concurrent writer cannot produce a cross-table-inconsistent
  backup.
- **Regression test:** `backup::tests::backup_snapshot_is_consistent_under_concurrent_rotation`
  commits a rotation from a second session mid-collection (via a
  payload-collection seam) and asserts the backup restores to a decryptable
  credential and a working rotation.
- **Baseline evidence:** `evidence/conc04_baseline_fail.log.txt` — restores to
  an undecryptable credential at baseline.
- **Corrected result:** passes; backup restores and rotates cleanly.
- **Deviation:** none (matches the audit's single-read-transaction design).
- **Residual risk:** none identified. **Manual tests still required:** none.

## OBS-003 — Malformed provider sync ranges wiped usage history

- **Root cause:** the sync engines derive their replace-range `DELETE` bounds
  from provider-controlled window strings compared *lexicographically*. An
  Anthropic bucket missing `starting_at` yielded `window_start = ""`, which
  sorts below every real timestamp, so one malformed bucket deleted the
  provider's entire stored usage history. Inverted/unparseable ranges
  corrupted the range the same way.
- **Final design:** `usage::retain_valid_windows` drops snapshots whose bounds
  do not both parse as RFC3339 or whose range is inverted, before any deletion
  range is computed, in all three engines (openai, anthropic, legacy
  connector). Invalid buckets are skipped and reported in the sync notes;
  valid buckets in the same response still sync. `anthropic.rs` no longer
  invents `ending_at = starting_at`, so a bucket missing its end is visibly
  invalid rather than silently zero-width.
- **Files changed:** `crates/core/src/usage.rs`, `crates/core/src/anthropic.rs`,
  `crates/core/src/vault.rs`.
- **Security invariant:** missing, blank, malformed, inverted, or otherwise
  invalid provider time ranges fail or skip safely *before* any replace-range
  deletion; previously stored history is preserved.
- **Regression test:** `crates/core/tests/obs003_sync_range_guard.rs` — empty
  and missing `starting_at`/`ending_at`, malformed timestamps, end-before-start,
  mixed valid+invalid buckets, and the cost-report path; each asserts stored
  history survives.
- **Baseline evidence:** `evidence/obs003_baseline_fail.log.txt` — the
  empty-`starting_at` fixture deletes the stored history row at baseline.
- **Corrected result:** 7/7 pass. **Deviation:** none. **Residual risk:** none.
  **Manual tests still required:** live-provider attribution (out of automated
  scope; unchanged by this fix).

## PI-01 (+CLI-01) — Master password leaked to injected child processes

- **Root cause:** `api-tracker run` scrubbed an *enumerated* list of API
  Tracker variables from the injected child, and the list missed
  `API_TRACKER_NEW_PASSWORD` — leaking a master password from a scripted
  password change into any launched process. Any future variable would have
  leaked the same way.
- **Final design:** scrubbing moved into core (`inject::scrub_own_env`) as
  **deny-by-default** over the whole `API_TRACKER_` prefix (byte-level match),
  keeping only an explicit child-safe allowlist (`API_TRACKER_DIR`,
  `API_TRACKER_INSECURE_FAST_KDF`). Classification of every `API_TRACKER_*`
  variable is documented at `CHILD_SAFE_ENV`: password material
  (`_PASSWORD`, `_NEW_PASSWORD`, `_PROJECT_PASSWORD`, `_BACKUP_PASSWORD`),
  session material (`_SESSION`), and authentication material
  (`_PROVIDER_ADMIN_KEY`, `_DESTINATION_AUTH`) are all removed; only the two
  secretless metadata vars survive.
- **Files changed:** `crates/core/src/inject.rs`, `apps/cli/src/run_cmd.rs`.
- **Security invariant:** no Tethra authentication/password/session/
  internal-control variable reaches an injected child; explicitly mapped
  credential variables still arrive.
- **Regression test:** `apps/cli/tests/run_env_scrub.rs` — spawns the real
  binary with a live session token plus sentinel values for every sensitive
  variable (never on the command line), has the child print its environment,
  and proves the mapped credential arrives while no sensitive variable does.
- **Baseline evidence:** `evidence/pi01_baseline_fail.log.txt` —
  `API_TRACKER_NEW_PASSWORD` present in the child at baseline.
- **Corrected result:** passes. **Deviation:** strengthened the audit's
  "strip the known auth vars" to deny-by-default so future vars are safe.
  **Residual risk:** the child still inherits the non-Tethra parent
  environment by design. **Manual tests still required:** none.

## IPC-01 (+FS-09) — Arbitrary file overwrite via `env_example_write`

- **Root cause:** the desktop `env_example_write` command forwarded a
  frontend-controlled path and content straight to an atomic file write, gated
  only by an unlocked vault — an arbitrary-file-overwrite primitive over IPC
  with no reauthentication and no path constraint.
- **Final design:** authorization and confinement moved into core
  (`UnlockedVault::env_example_write`): re-verifies the master password; the
  target must be named `.env.example`; its parent is canonicalised (resolving
  `..` and symlinked directories) and must lie inside one of the project's
  registered repositories; symlinked targets are refused; a project with no
  registered repo cannot be a target. The Tauri command passes the project and
  a reauth password through; the React confirm dialog is UX only.
- **Files changed:** `crates/core/src/vault.rs`,
  `apps/desktop/src-tauri/src/main.rs`, `apps/desktop/src/api.ts`,
  `apps/desktop/src/components/EnvView.tsx`.
- **Security invariant:** the write is reauthenticated and confined to a
  `.env.example` inside the intended registered project/repository; out-of-tree
  paths, `..` traversal, symlinks, a path switched after preview, and
  missing/incorrect reauth are all refused.
- **Regression test:** `crates/core/tests/ipc01_env_example_confinement.rs` —
  backend-level (bypasses the UI): valid in-project write, unrelated absolute
  path, `..` traversal, symlink destination, symlinked parent, non-example
  file name, path-switched-after-preview, and missing/incorrect reauth.
- **Baseline evidence:** `evidence/ipc01_baseline_fail.log.txt` — every escape
  and the reauth-less write succeed at baseline.
- **Corrected result:** 9/9 pass. **Deviation:** the target is derived as the
  `.env.example` of a confined directory rather than trusting the
  frontend-supplied path, which also closes "path switched after preview".
  **Residual risk:** a `.env.example` inside a registered repo can still be
  overwritten with names-only content (the intended operation; reauth-gated).
  **Manual tests still required:** desktop UI reauth flow (manual UI suite).

## OBS-001 — Exposure alerts silently self-resolved

- **Root cause:** repository-scan exposure alerts were raised as
  `AlertKind::PossibleExposure` with a head-commit-keyed dedup key and left in
  the monitor's auto-resolve managed set. The incremental scan skips
  unchanged/unavailable/failed repos, so the finding was not re-emitted and
  `auto_resolve_stale` silently resolved the still-valid exposure on the next
  cycle. The rebaseline coverage-gap warning was worse: its key was never
  added to `active_keys`, so it auto-resolved in the same run it was raised.
- **Final design:** repository exposure and coverage-gap alerts now use
  dedicated kinds (`RepoSecretExposure`, `RepoScanCoverageGap`) excluded from
  every auto-resolve managed set, so they never clear because a finding was
  not re-emitted. The exposure dedup key is repo-scoped
  (`repo_scan_exposure:{repo}`), so a persistent secret keeps one stable alert
  as HEAD advances. Resolution is evidence-based: explicit user resolution, or
  `reverify_repo_exposure()` — a FULL history + working-tree scan that clears
  the alerts only if nothing is found (a secret still in history keeps them
  open). Exposed via `scan --reverify` and the desktop `scan_reverify` command.
- **Files changed:** `crates/core/src/alerts.rs`, `crates/core/src/vault.rs`,
  `apps/cli/src/scan_cmd.rs`, `apps/desktop/src-tauri/src/main.rs`,
  `apps/desktop/src/api.ts`, `apps/desktop/src/types.ts`.
- **Security invariant:** a possible-secret-exposure alert stays open until an
  explicit remediation or a sufficiently strong re-verification; it does not
  resolve because the head is unchanged, the repo is unreachable, the scan
  fails/skips, only an incremental range was checked, the secret left the
  working tree but remains in history, or the commit-specific dedup key
  changed. Honest "coverage gap / not re-verified" status is preserved.
- **Regression test:** `crates/core/tests/obs001_exposure_alert_lifecycle.rs`
  — real-git `run_monitor` scenarios: survives unchanged/unavailable/failed
  runs and a working-tree-only scrub; clears on explicit resolution and on a
  clean full re-scan; rebaseline coverage gap persists.
- **Baseline evidence:** `evidence/obs001_baseline_fail.log.txt` — six of the
  seven fail with the auto-resolve symptom at baseline. (Helpers key on the
  stable alert *title* so the same test demonstrates baseline and verifies the
  fix.)
- **Corrected result:** 7/7 pass. **Deviation:** split the alert kinds (audit
  recommendation #1) *and* implemented the repo-scoped key (#3) and clean-rescan
  resolution (#2). **Residual risk:** resolution needs an explicit full
  re-scan or user action — intentional (a security signal must not clear
  itself). **Manual tests still required:** desktop reverify affordance.

## ROT-001 (+ROT-010) — Ambiguous revoke wedged / restored a deleted key

- **Root cause:** the revoke crash-recovery marker was checked only against
  the *last* event; a lost/failed response records an outcome event after the
  marker, burying it, so a retried 404 was refused as "wrong key id" and the
  rotation looped in `OLD_DISABLED` forever. There was no idempotency guard
  (a crash after `old_revoked_at` re-called revoke on restart → 404 → wedge),
  no exit from `OLD_DISABLED`, and the only escape — rollback — restored a
  permanently-deleted key (OpenAI/Supabase) and reported a clean `ROLLED_BACK`.
- **Final design (in `rotation_revoke_old` / `rotation_rollback` /
  `rotation_complete_manual`):** (1) idempotent short-circuit to completion
  when `old_revoked_at` is already set; (2) a key-specific attempt marker
  matched across the *whole* event log, so a buried marker is recovered while
  an unrelated 404 is never converted to success (ROT-010); (3) a first 404
  with no prior attempt routes to `MANUAL_REQUIRED` with explicit
  verify-and-complete guidance, and `complete_manual` now accepts
  `OLD_DISABLED`, so the rotation always has a truthful terminal path;
  (4) rollback refuses to restore the old key when a revoke was *attempted*
  against a permanent-delete provider (reversibility centralised in
  `revoke_is_reversible`, Anthropic soft-archive only, used by both the
  refusal guard and the re-enable branch). A pre-revoke rollback still works.
- **Files changed:** `crates/core/src/vault.rs`,
  `crates/core/tests/rotation_access.rs` (the existing `revoke_404` test now
  asserts the new manual-required exit rather than the old wedge).
- **Security invariant:** an ambiguous revoke outcome converges to a truthful
  terminal or manual-recovery state without falsely restoring a deleted key,
  falsely claiming revocation, or permanently wedging the credential.
- **Regression test:** `crates/core/tests/rot001_revoke_recovery.rs` — mocked
  providers, a scripted HTTP client placing a lost response exactly on the
  revoke send: lost-response-then-404 → completed; crash-after-`old_revoked_at`
  → idempotent completion on restart without re-calling revoke; first-404 →
  manual-required then completes; rollback after a revoke attempt on a
  permanent-delete provider → refused; pre-revoke rollback → still works.
- **Baseline evidence:** `evidence/rot001_baseline_fail.log.txt` — all four
  ambiguity tests fail at baseline (including the rollback restoring the
  deleted key); corroborates the audit's `ROT-001_RESOLUTION.md` control-flow
  proof.
- **Corrected result:** 5/5 new + 23/23 existing rotation tests pass.
  **Deviation:** none material (implements all four audit recommendations).
  **Residual risk:** a first-404 that was actually a wrong-key config error
  routes to manual-required; the honest forward-fix is `complete-manual` on
  the validated new key. **Manual tests still required:** live provider
  revoke/disable lifecycle (out of automated scope).

## PI-06 — `terminate_pid` had no `pid <= 0` guard

- **Root cause:** `inject::terminate_pid` spawned `kill`/`taskkill` on any
  `i64`. On Unix `kill 0` signals the caller's whole process group and a
  negative PID signals a process group, so a corrupted/edited/zero recorded
  PID could terminate Tethra itself or an unrelated group.
- **Final design:** refuse any `pid <= 0` before spawning anything. A real
  child PID is always > 0.
- **Files changed:** `crates/core/src/inject.rs`.
- **Security invariant:** no signal is ever sent to PID ≤ 0.
- **Regression test:** `inject::tests::terminate_pid_refuses_non_positive_pids`
  — asserts `0`, `-1`, `-12345`, `i64::MIN` all return false without spawning.
- **Baseline evidence:** code inspection + the audit's
  `MATERIAL_LEADS_VERIFICATION` (baseline has no guard). A live baseline run is
  deliberately **not** performed — it would signal the test runner's own
  process group / every user process, which is exactly the hazard.
- **Corrected result:** passes. **Deviation:** none. **Residual risk:** none.

## IPC-02 — Credential deletion had no core reauthentication

- **Root cause:** the desktop `credential_delete` command deleted the local
  record (cascading versions) on a direct IPC invoke, gated only by a React
  confirm dialog; core `delete_credential` performed no reauth.
- **Final design:** `delete_credential` re-verifies the master password in
  core, matching reveal/replace/destination-removal. The Tauri command and CLI
  `key remove` pass the master password through; the confirm dialog is UX only.
- **Files changed:** `crates/core/src/vault.rs`,
  `apps/desktop/src-tauri/src/main.rs`, `apps/desktop/src/api.ts`,
  `apps/desktop/src/components/CredentialDetail.tsx`, `apps/cli/src/key_cmd.rs`,
  and the three affected core test files.
- **Security invariant:** deleting a credential requires master-password
  reauthentication enforced in core.
- **Regression test:** the credential-lifecycle test asserts a wrong-password
  delete is refused (`WrongPassword`) and the credential survives, then the
  correct password deletes.
- **Baseline evidence:** `evidence/ipc02_baseline_fail.log.txt` — a
  wrong-password delete succeeds at baseline.
- **Corrected result:** passes. **Deviation:** none. **Residual risk:** none.
  **Manual tests still required:** desktop delete reauth flow (manual UI suite).

---

## Cross-cutting note

CRYPTO-01, CONC-04, and OBS-003 share one root class — multi-step DB
reads/writes that were not wrapped in a single transaction or snapshot. The
same principle (a read-modify-write or a multi-table read that must be
consistent runs in one transaction/snapshot) closes all three.
