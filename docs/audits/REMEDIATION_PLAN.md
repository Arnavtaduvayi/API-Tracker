# Remediation Plan (Phase 9)

**Baseline audited:** `7d81090`. **Model:** Fable 5. **No fixes are implemented in this session** — this is design + sequencing only.

## Release-blocker summary
| Gate | Blockers |
|---|---|
| **Local development** | none — usable now |
| **Private alpha** | CRYPTO-01 acknowledged in docs; OBS-001 acknowledged; PI-06 quick guard |
| **Public alpha** | CRYPTO-01, OBS-001, ROT-001, PI-01, IPC-01, CONC-04 |
| **Production / GA** | all of the above **fixed & regression-tested**, plus GScan-01/02, DEST-01/02/03, OBS-003/004, CONC-06, PI-02, M-6, and the Tauri/FE test gap |

**Hard release blockers (must fix before any "production" claim):** CRYPTO-01 (silent permanent data loss), OBS-001 (security signal self-resolves), PI-01 (master-password env leak), IPC-01 (arbitrary file write, no reauth), CONC-04 (inconsistent backup → unrestorable), OBS-003 (usage-history wipe).

## Priority order & designs

### P1 — Critical/High + data-loss (release-blocking)

**R1 · CRYPTO-01 (+CONC-03) — concurrent rotation orphans ciphertext.** `CV-Loss, High.`
- Root cause: `add_credential` (vault.rs:1204-1275) and `replace_credential_value` (1652-1714) read the project row, derive the key, then INSERT/UPDATE in a **separate autocommit** step; a rotation committing in that window persists ciphertext under a destroyed key.
- Design: wrap read-of-wrap → encrypt → write in **one `BEGIN IMMEDIATE` transaction**; re-read `projects.wrapped_project_key` inside it and re-check the BLAKE3 wrap-hash immediately before the write (holding the write lock prevents a rotation from interleaving; a rotation that already committed is caught → clean `ProjectLocked`). Alternative: a `projects.key_generation` CAS carried in the write's `WHERE`.
- Modules: vault.rs (both writers, `project_key_for_row`, rotation writers). Migration: optional `key_generation` column (append-only, back-compat). Regression test: the `evidence/crypto01` harness as a checked-in concurrency test. Independently fixable: **yes.** Release-blocking: **yes.**

**R2 · OBS-001 — exposure alerts self-resolve.** `CV-Corr, Med (High impact).`
- Design: remove `PossibleExposure` from `auto_resolve_stale`'s managed set, OR gate its resolution on a recorded remediation (rotation/revocation) or a fresh clean full-history re-scan of the same secret fingerprint. Make the exposure dedup_key **fingerprint-based** (not head-commit-based) so a persistent secret keeps one stable alert. Never drop standing exposure alerts when a repo is skipped/unavailable — mark "coverage gap: not re-verified". Audit/notify on any security-alert auto-resolve.
- Modules: alerts.rs (`auto_resolve_stale`), vault.rs (`run_monitor`, `scan_repos_incremental`). Regression test: double-monitor-run keeps the alert open. Independently fixable: **yes.** Release-blocking: **yes.**

**R3 · OBS-003 — Anthropic sync wipes usage history.** `CV-Loss, Med.`
- Design: refuse/skip a bucket with empty `starting_at` instead of computing `window_start=""` and issuing a replace-range DELETE over the whole history. Modules: anthropic.rs (226-279), vault.rs (3310-3331). Test: malformed-bucket fixture asserts history preserved. Release-blocking: **yes.**

**R4 · CONC-04 — non-transactional backup snapshot.** `CV-Loss, Med.`
- Design: wrap `collect_payload_v2` in a single deferred read transaction so all table SELECTs share one snapshot; add a cross-table consistency assertion (every credential's project-key wrap present). Modules: backup.rs (135-168). Test: concurrent-writer-during-backup → restorable. Release-blocking: **yes.**

**R5 · PI-01 (+CLI-01) — master password leaks to child env.** `CV-Priv, Med.`
- Design: strip `API_TRACKER_NEW_PASSWORD` (and any `API_TRACKER_*` auth vars) from the spawned child's environment in `run`. Modules: run_cmd.rs (88-101), inject.rs. Test: assert absent in child env. Release-blocking: **yes.**

**R6 · IPC-01 (+FS-09) — arbitrary file write over IPC.** `CV-Sec, Med.`
- Design: require reauth for `env_example_write`; confine `example_path` to a previewed/registered repo path (canonicalize, refuse symlink, refuse writing outside the project). Modules: desktop main.rs (1409-1418), envgov.rs. Test: reject out-of-tree path; require reauth. Release-blocking: **yes (public alpha).**

### P2 — Auth/authz, wrong-key & destructive-operation risks

**R7 · ROT-001 (+ROT-010) — revoke crash-marker fragility / stuck OLD_DISABLED.** `CV-Rel+Corr, Med.`
- Design: allow `complete_manual` from `OLD_DISABLED` (with explicit "old key verified gone" confirmation); promote OLD_DISABLED→MANUAL_REQUIRED after a recorded revoke attempt returns 404; make the attempt marker a per-round id (not strictly-last-event) so a graceful lost-response is recoverable without converting an unrelated 404 to success; have `rollback` refuse/warn for permanent-delete providers. Modules: vault.rs (7057-7312, complete_manual/cancel/rollback guards). Test: mock revoke→transport-error→404 reaches a correct terminal state.

**R8 · IPC-02 — desktop delete without reauth.** `CV-Sec, Low.` Require confirm-token/reauth in `credential_delete` matching the CLI. main.rs (742-748).

**R9 · PI-02/PI-06/CONC-11 — PID termination safety.** `CV-Rel, Med/Info.` Add `if pid<=0 { return false }`; record spawn start-time/cmd and verify before signalling (defeat PID reuse); escalate SIGTERM→SIGKILL on Unix. inject.rs (271-300).

**R10 · PI-05 — clock-rollback re-activates grants/sessions.** `CV-Sec, Low.` Anchor grant/session expiry to a monotonic-ish or store-and-compare basis; at minimum document. access.rs/session.rs.

**R11 · GScan-01/02 — hooks silently inert.** `CV-Corr, Med.` Detect `core.hooksPath`; refuse to report "Installed" when the hook won't run; prepend (not append) the scan block in force-chain. hooks.rs.

**R12 · DEST-01/02/03 — false drift / wrong-var operations.** `CV-Corr, Med.` Distinguish transport/auth errors from "absent" in `exists()`; match Vercel env vars by key+target; surface skipped adapters instead of re-presenting stale drift. destinations.rs, vault.rs drift paths.

### P3 — Reliability / DoS

**R13 · CONC-06 — no git subprocess timeout.** Add a timeout to every git spawn. gitrepo.rs.
**R14 · GScan-03 (+CONC-05) — history-scan memory.** Stream `git log -p` line-by-line; cap total bytes; skip oversized blobs in history like the staged path. gitrepo.rs.
**R15 · OBS-004 — one unparseable `expires_at` breaks all listings.** Parse defensively per-row; isolate failures. vault.rs.
**R16 · CONC-01/02, IPC-04, INFO-01 — desktop mutex/auto-lock/suspend/poison.** Release the mutex across network I/O; make auto-lock advance across suspend (wall-clock cross-check); avoid `.expect` panics under the lock.

### P4 — Low correctness & concurrency
ROT-002..008/011, CONC-07..12, SYNC-001, OBS-002/005..012, FS-01..08, DEST-04..13, CLI-02/03/04, CRYPTO-03, NET-01, IPC-05. Batch by subsystem; each independently fixable.

### P5 — Documentation, test, supply-chain
- **M-6:** pin GitHub Actions to commit SHAs (esp. release.yml with `contents:write`); avoid `@stable` branch ref.
- **Docs (Doc verdicts):** DEST-08, GScan-05, OBS-009/012/013, FS-07 — correct capability/coverage claims to match behavior.
- **Tests:** see TEST_COVERAGE_GAPS.md (Tauri command layer, FE, concurrency, Windows/Linux, live-provider, fault injection).

## Cross-cutting theme
CRYPTO-01, CONC-04 (and OBS-003's replace-range) share one root class: **multi-step DB reads/writes that are not wrapped in a single transaction/snapshot.** A single design principle — *every read-modify-write or multi-table read that must be consistent runs in one transaction* — closes R1, R4, and hardens R3. Prioritize this pattern fix; it is the highest-leverage change in the codebase.
