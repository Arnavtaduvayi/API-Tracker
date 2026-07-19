# Fix Verification Matrix — PR #9 release-blocker remediation

Model: Fable 5 (`claude-fable-5`), highest effort. Baseline `7d81090` → remediation `1ec4073`.
Method: independent code review of every changed production line, independent reproduction
where safe, and per-suite test execution. The remediation report's conclusions were **not**
accepted as proof; each fix was attacked from the changed code.

Legend for verdicts: FIXED / PARTIALLY FIXED / NOT FIXED / REGRESSION / INCONCLUSIVE.

---

## CRYPTO-01 (+CONC-03) — concurrent rotation orphans ciphertext

- **Baseline behavior:** `add_credential` / `replace_credential_value` read the project-key
  wrap, derived the key, encrypted, then wrote in a *separate autocommit* step. A
  `set_project_password` / `remove_project_password` committing in that window destroyed the
  old wrap, orphaning the just-written ciphertext (silent, permanent loss) and wedging future
  rotations. BLAKE3 wrap-hash freshness only caught the coarse/sequential case.
- **Changed files/symbols:** `vault.rs` — new `write_txn()` (BEGIN IMMEDIATE, maps
  BUSY/LOCKED → typed `CoreError::Busy`); `add_credential`, `replace_credential_value`,
  `set_project_password`, `remove_project_password` now read the project row **after** taking
  the write lock; `remove_project_password` hoists its Argon2id unwrap outside the lock then
  compare-and-swaps the wrap it derived from. `error.rs` — `CoreError::Busy`/`vault_busy`.
  `Cargo.toml` — `rusqlite` dev-dep for the lock probe.
- **Invariant:** a credential add/replace racing any project-key rotation either commits under
  the persisted current key or returns a typed failure; no ciphertext under a destroyed key.
- **Independent verification:**
  - Enumerated every project-key ciphertext writer. Only `add_credential` (vault.rs:1287),
    `replace_credential_value` (1736), and the rotation re-encrypt loop `rotate_project_key`
    (921/939) write credential-value/version ciphertext under a project key — **all now
    transactional**. `retain_credential_version` (4452) has exactly one caller (1745, inside
    `replace`'s `write_txn`). The other `project_key_for_row` callers (1540/2460/4554/4584) are
    decrypt-only (reveal/decrypt_value/version). `provider_admin_connect`/`notification_channel_add`/
    `destination_add` encrypt under the **vault key**, not a project key. No uncovered writer.
  - Confirmed the DB opens **WAL + busy_timeout 5s + foreign_keys=1** (db.rs:689-693), so the
    IMMEDIATE lock + snapshot semantics the fix relies on hold at `1ec4073`.
  - `rotate_project_key` re-encrypts **both** `credentials` and `credential_versions` under the
    new key inside the rotation tx — so a follow-up rotation cannot leave versions orphaned.
- **Test fails at baseline?** YES — independently reproduced: the unmodified
  `crypto01_rotation_race.rs` compiled against real `7d81090` orphans 3/3 race tests
  (`armed=true`, "does not decrypt under the persisted project key"). Evidence:
  `evidence/crypto01_independent_baseline_repro.log.txt`.
- **Test passes at 1ec4073?** YES — 4/4, and 5/5 stress runs (~80 armed races), zero orphans.
- **Edge cases:** rotation-wins-first (racer blocks then sees new wrap or gets Busy),
  writer-wins-first (rotation re-encrypts the new row), refusal path leaves no partial row,
  sentinel still decrypts, follow-up rotation succeeds (proves nothing orphaned). Multi-process
  variant drives the racer from a spawned child (real desktop+CLI shared-vault model).
- **New failure modes:** under sustained contention a loser gets typed `Busy`/`ProjectLocked`
  (retryable, no data risk). Rotation holds the write lock across its re-encrypt loop — an
  availability trade-off proportional to credential count, not a data-loss risk.
- **Verdict: FIXED.** **Blocks PR #9: No.**

---

## CONC-04 — non-transactional backup → unrestorable

- **Baseline behavior:** `collect_payload_v2` read each table in a separate autocommit SELECT;
  a rotation committing between the `credentials` and `projects` reads paired pre-rotation
  ciphertext with the post-rotation wrap → restored credential undecryptable; AEAD verify
  cannot detect it.
- **Changed files/symbols:** `backup.rs` — `collect_payload_v2_with` wraps all table reads in
  one `conn.unchecked_transaction()` (deferred read snapshot); `after_table` seam for the test;
  `assert_payload_consistent` tripwire (every credential's project row present in the payload).
- **Invariant:** every table in one backup comes from a single logical snapshot.
- **Independent verification:** in WAL mode a deferred read transaction fixes the snapshot at
  first read; concurrent writers commit to the WAL and are simply absent from the snapshot, so
  the backup is internally consistent. The test rotates from a second session at the
  `after_table("credentials")` seam and asserts the restored backup decrypts AND the restored
  vault re-rotates. Note: `assert_payload_consistent` only checks project-row *presence*, not
  wrap/ciphertext key-match — it is a secondary tripwire, not the primary guarantee (which is
  the snapshot itself); this is defense-in-depth, not a gap.
- **Test fails at baseline?** YES (shim-assisted, faithful): `conc04_baseline_fail.log.txt`
  shows the restored credential does not decrypt. The shim adds the deterministic `after_table`
  seam but preserves baseline's per-table autocommit reads — the property under test is
  unchanged.
- **Test passes at 1ec4073?** YES — 1/1 (26.7s; exercises the real production KDF).
- **Verdict: FIXED.** **Blocks PR #9: No.**

---

## OBS-003 — malformed provider range wipes usage history

- **Baseline behavior:** a bucket with empty/missing `starting_at` produced `window_start=""`,
  which sorts below every real timestamp; the replace-range DELETE then removed the provider's
  entire stored history. `anthropic.rs` also fabricated `ending_at = starting_at`.
- **Changed files/symbols:** `usage.rs` — `retain_valid_windows` drops rows unless both bounds
  parse as RFC3339 and `start <= end`, returning the dropped count. `vault.rs` — called in all
  three sync engines before the DELETE; `note_skipped_invalid_windows` reports skips honestly.
  `anthropic.rs` — `ending_at` no longer defaults to `starting_at` (missing end → dropped).
- **Invariant:** invalid provider ranges never reach a replace-range deletion; stored history
  preserved.
- **Independent verification:** the DELETE bound comes from `snapshots.iter().map(window_start).min()`;
  filtering invalid rows first means `.min()` only sees valid timestamps, and an all-invalid
  response yields an empty set → no DELETE → history preserved. Guard placement confirmed
  before each DELETE in the two detail engines and the simple `sync_usage` path.
- **Test fails at baseline?** YES (real baseline run): `obs003_baseline_fail.log.txt` — the
  empty/missing `starting_at` cases delete the stored history row `(0,1)` vs expected `(1,1)`;
  invalid buckets are recorded.
- **Test passes at 1ec4073?** YES — 7/7. Covers empty/missing start, empty/missing end,
  malformed timestamps, inverted range, mixed valid+invalid, and the cost path.
- **Verdict: FIXED.** **Blocks PR #9: No.**

---

## PI-01 (+CLI-01) — master password leaks into injected child env

- **Baseline behavior:** `run` scrubbed an *enumerated* list of secret env vars that omitted
  `API_TRACKER_NEW_PASSWORD` → a master password leaked to launched children.
- **Changed files/symbols:** `inject.rs` — `scrub_own_env` deny-by-default over the whole
  `API_TRACKER_` prefix (byte-level match), allowlisting only `API_TRACKER_DIR` and
  `API_TRACKER_INSECURE_FAST_KDF`; `run_cmd.rs` calls it before injecting mapped credentials.
- **Invariant:** no API Tracker auth/password/session/control var reaches a child; mapped
  credentials still arrive.
- **Independent verification:** deny-by-default is strictly stronger than the audit's "strip
  known vars" and future-proof. Injection runs *after* the scrub, so mapped credentials survive.
  Caveat: the byte-level prefix match is case-sensitive; on Windows (case-insensitive env
  lookup) a variable stored with non-standard casing (e.g. `Api_Tracker_Password`) would not be
  scrubbed yet could still be read by the app — a theoretical, low-severity edge that requires
  the user to deliberately set the var with unusual casing (recorded as RA-4).
- **Test fails at baseline?** YES (real baseline run of the CLI binary): `pi01_baseline_fail.log.txt`
  — "API_TRACKER_NEW_PASSWORD reached the injected child's environment."
- **Test passes at 1ec4073?** YES — 1/1 (`run_env_scrub.rs`): the mapped credential arrives, no
  sensitive `API_TRACKER_*` var does.
- **Verdict: FIXED** (with RA-4 Windows-casing caveat). **Blocks PR #9: No.**

---

## IPC-01 (+FS-09) — arbitrary file overwrite via `env_example_write`

- **Baseline behavior:** the IPC command forwarded a frontend-controlled path + content to
  `envgov::atomic_write` with only an unlocked-vault gate — an arbitrary-file-overwrite
  primitive reachable from a hostile webview, no reauth, no path constraint.
- **Changed files/symbols:** `vault.rs` — new `env_example_write` enforces, in core: master
  password reauth; final component must be `.env.example`; parent canonicalized (resolves `..`
  and symlinked dirs) and must be inside a registered repo of the named project; symlinked
  target refused; target derived as `canon_parent/.env.example`. Desktop command + `api.ts` +
  `EnvView.tsx` pass `project` + reauth password through a `ReauthDialog` (UX only).
- **Invariant:** the command can write only the intended `.env.example` inside the correctly
  registered repository after backend-enforced reauth.
- **Independent verification (webview treated as hostile):** authorization is in core, not
  React — a direct `invoke` cannot bypass it; a missing `password` fails deserialization; a
  wrong password fails `verify_master_password`. `Path::starts_with` is component-wise (no
  `/repo` vs `/repofoo` prefix confusion). Deriving the target from the canonical parent closes
  "path switched after preview." Residual: a filesystem-race TOCTOU between parent
  canonicalization and the atomic write requires a *separate local FS attacker*, which is
  outside the webview threat model this fix targets (noted, not blocking).
- **Test fails at baseline?** YES (signature-adapting shim, faithful): `ipc01_baseline_fail.log.txt`
  — every escape and the reauth-less write succeed at baseline.
- **Test passes at 1ec4073?** YES — 9/9: valid write; unrelated absolute path; `..` traversal;
  symlink destination; symlinked parent escaping the repo; non-`.env.example` name; path
  switched after preview; wrong/missing reauth; project with no registered repo.
- **Related deferred:** `env_preview`/`env_import` reads remain unconfined (RA-3 / NF-2) — a
  read-only surface, out of this fix's scope.
- **Verdict: FIXED.** **Blocks PR #9: No.**

---

## OBS-001 — exposure alerts self-resolve

- **Baseline behavior:** repo-scan findings raised `PossibleExposure` with a head-commit-keyed
  dedup; `PossibleExposure` is in the monitor's managed auto-resolve set, so the next
  incremental run (unchanged/unavailable/failed/skipped repo, or secret only in history)
  auto-resolved the still-valid alert. The rebaseline coverage-gap alert auto-resolved in the
  same run (its key was never added to `active_keys`).
- **Changed files/symbols:** `alerts.rs` — new kinds `RepoSecretExposure`,
  `RepoScanCoverageGap` (both excluded from the managed set); `resolve_by_dedup`. `vault.rs` —
  incremental monitor emits `RepoSecretExposure` with a repo-scoped key
  `repo_scan_exposure:{repo}`; rebaseline emits `RepoScanCoverageGap`
  `repo_scan_coverage_gap:{repo}`; new `reverify_repo_exposure` (full-history + working-tree
  scan; resolves only if clean). CLI `scan --reverify`, desktop `scan_reverify`, `types.ts`.
- **Invariant:** an exposure alert stays open until explicit remediation or a sufficiently
  strong re-verification; never resolves because a finding was not re-emitted.
- **Independent verification:** `auto_resolve_stale` selects only `kind IN
  (managed_credential_kinds)`; the two new kinds are **not** in that list, so re-emission-driven
  resolution can never touch them. `reverify_repo_exposure` runs
  `scan_history(repo, None)` = `git log -p --all` (full history across all refs) plus the
  working tree, and resolves only when the finding count is 0 — so a secret still in history
  keeps the alert open. Reverify matches the registered repo-path spelling by canonical path,
  so its dedup keys line up with the monitor's; the passing `clean_full_rescan` test proves the
  round-trip. Repo-scoped dedup means one stable alert per repo (no duplicate growth). Reverify
  needs an unlocked vault but no reauth — acceptable, since it can only *clear* an alert when
  the repo is genuinely clean and it is keyed to the specific repo being verified (cannot clear
  a dirty repo's alert).
- **Test fails at baseline?** YES (shim-assisted, faithful for the vulnerability tests):
  `obs001_baseline_fail.log.txt` — 6/7 fail with the auto-resolve symptom (unchanged run,
  unavailable repo, scan failure, secret-in-history, rebaseline coverage gap). The 7th
  (clean-rescan resolution) exercises new-only functionality.
- **Test passes at 1ec4073?** YES — 7/7.
- **Verdict: FIXED.** **Blocks PR #9: No.**

---

## ROT-001 (+ROT-010) — ambiguous revoke wedges / restores a deleted key

- **Baseline behavior:** a lost/failed revoke response buried the attempt marker (only
  `.last()` was inspected), so a retried 404 was refused as "wrong key" and the rotation looped
  in `OLD_DISABLED` forever; `complete_manual`/`cancel` refused the state; the only exit,
  `rollback`, restored a permanently-deleted key (OpenAI/Supabase) and reported a clean
  rollback. (ROT-010: opposite direction — a 404 after a recorded attempt marked a
  never-revoked key revoked.)
- **Changed files/symbols:** `vault.rs` — `revoke_attempt_marker` (key-specific),
  `revoke_was_attempted` (scans the whole event log), `rotation_revoke_old` (idempotent
  short-circuit when `old_revoked_at` set; first-404 → `set_state(OLD_DISABLED →
  MANUAL_REQUIRED)`; 404-after-attempt sets `old_revoked_at` truthfully),
  `rotation_complete_manual` accepts `OLD_DISABLED`, `rotation_rollback` refuses when a revoke
  was attempted against a permanent-delete provider, `revoke_is_reversible` (Anthropic only).
  `rotation_access.rs` — `revoke_404` test now asserts `manual_required` then completion.
- **Invariant:** an ambiguous revoke converges to a truthful terminal or manual-recovery state
  without false success, unsafe rollback, duplicate revocation, or a permanent wedge.
- **Independent verification (full state-machine trace):** `set_state` is a real CAS
  (`WHERE ... AND state = from_state`; 0 rows → loud `InvalidInput`), so the first-404
  transition only fires from the actual `OLD_DISABLED` state and **concurrent `advance` is
  safe** (one wins, the other errors). `record_error` appends a "step failed (retryable)" event
  without changing state — exactly the marker-burying that whole-log `revoke_was_attempted` now
  defeats. Traced all mandated scenarios: response-delivered → COMPLETED; lost-then-404 →
  completed retry (`old_revoked_at` set); first/wrong-key 404 → MANUAL_REQUIRED (no false
  success, no `old_revoked_at`); crash-after-`old_revoked_at` → idempotent completion without
  re-calling revoke; buried marker → still found; manual providers → MANUAL_REQUIRED with
  instructions; rollback after attempt on permanent-delete provider → refused; pre-revoke
  rollback → still allowed; repeated `complete_manual` → rejected once COMPLETED. Changing the
  test expectation from `OLD_DISABLED` to `MANUAL_REQUIRED` is backed by the real transition,
  not a loosened assertion.
- **Test fails at baseline?** YES: `rot001_baseline_fail.log.txt` — 4 ambiguity tests fail
  (state stuck at `old_disabled`, mock exhausted by the re-call loop, rollback returns Ok where
  the fix refuses).
- **Test passes at 1ec4073?** YES — 5/5 new + the changed `revoke_404` existing test + 22
  existing rotation tests.
- **Verdict: FIXED.** **Blocks PR #9: No.** (This is the finding the session report under-listed;
  production code *was* changed, and the state machine is now safe.)

---

## PI-06 — `terminate_pid` accepts pid ≤ 0

- **Baseline behavior:** `terminate_pid(pid)` sent `kill`/`taskkill` with no guard; a
  corrupted/edited pid of 0 → `kill 0` signals API Tracker's own process group; negative →
  a process group.
- **Changed files/symbols:** `inject.rs` — `if pid <= 0 { return false }` before any signal;
  unit test `terminate_pid_refuses_non_positive_pids`.
- **Independent verification:** the guard is correct and precedes both the Unix and Windows
  branches. **However**, `apps/cli/src/access_cmd.rs:259` (`access grant end --kill`) spawns
  `kill` **directly** with a DB-sourced pid, bypassing `terminate_pid` and its new guard — a
  second process-termination entry point that is still unguarded (see NEW_FINDINGS RA-1). PI-02
  (PID reuse) is correctly **not** claimed fixed — no spawn-identity check was added.
- **Test fails at baseline?** N/A by design (running `kill 0`/`kill -1` is the hazard);
  inspection + fixed-behavior unit test only.
- **Test passes at 1ec4073?** YES — 1/1.
- **Verdict: FIXED for the audited entry point (`terminate_pid`); PARTIALLY FIXED at the
  entry-point-class level** (access_cmd path still unguarded). **Blocks PR #9: No** (RA-1 is
  Info, pre-existing, requires DB tampering, self-signal impact).

---

## IPC-02 — credential deletion without core reauth

- **Baseline behavior:** desktop `credential_delete` deleted with no reauth; confirmation was
  UI-only, so a direct `invoke` deleted (cascading versions).
- **Changed files/symbols:** `vault.rs` — `delete_credential(selector, master_password)` calls
  `verify_master_password` first; desktop command + `api.ts` + `CredentialDetail.tsx` pass the
  password through (removing the client-side `api.reauth`); CLI `key remove` prompts and passes
  it.
- **Invariant:** deleting a credential requires master-password reauth enforced in core.
- **Independent verification:** authorization is in core — a direct `invoke` without the
  `password` arg fails deserialization; a wrong password fails `verify_master_password`; the
  existing active-rotation / linked-reference refusals still run after reauth. React sequencing
  is not the gate.
- **Test fails at baseline?** YES (signature-adapting shim, faithful): `ipc02_baseline_fail.log.txt`
  — a wrong-password delete succeeds at baseline.
- **Test passes at 1ec4073?** YES — `credentials::credential_lifecycle_with_metadata` now
  asserts wrong-password delete → `WrongPassword`, credential survives, then correct-password
  delete succeeds (a security property, not a happy path).
- **Verdict: FIXED.** **Blocks PR #9: No.**

---

## Summary

| Finding | Verdict | Blocks PR #9 |
|---|---|---|
| CRYPTO-01 (+CONC-03) | FIXED | No |
| CONC-04 | FIXED | No |
| OBS-003 | FIXED | No |
| PI-01 (+CLI-01) | FIXED (Windows-casing caveat RA-4) | No |
| IPC-01 (+FS-09) | FIXED (FS-race TOCTOU residual, out of threat model) | No |
| OBS-001 | FIXED | No |
| ROT-001 (+ROT-010) | FIXED | No |
| PI-06 | FIXED (terminate_pid); PARTIAL at class level → RA-1 | No |
| IPC-02 | FIXED | No |
| PI-02 (PID reuse) | NOT in scope; correctly **not** claimed fixed — remains open | No |
