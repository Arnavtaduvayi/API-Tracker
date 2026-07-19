# Test Coverage Gaps (Phase 9)

**Baseline:** `7d81090`. **Model:** Fable 5. The core has a solid integration suite (`crates/core/tests/*`, 17 files) and many in-file unit tests; `test-baseline.log.txt` records a passing run. Gaps below are ordered by risk.

## Missing concurrency tests (highest risk)
- **CRYPTO-01:** no test exercises `add_credential`/`replace_credential_value` racing `set_project_password`. The audit's `evidence/crypto01` harness should be adopted as a checked-in concurrency test asserting the raced write is refused-or-recoverable, never orphaned, and rotation never wedges.
- **CONC-04:** no test writes to the vault during `collect_payload_v2` to prove backup consistency.
- **CONC-12 / ROT-002/003 / CONC-10:** no tests for `rotation_approve` single-flight under two processes, CREATING_IN_PROGRESS replay, or first-open migration race.
- **CONC-09:** no test for concurrent `session.json` rewrite (torn read / lost keys).

## Missing fault-injection tests
- **ROT-001/010:** no mock-`HttpClient` test driving revoke → transport-error → retried-404 to assert a correct terminal state (currently the marker-burying wedge is unverified by any test).
- **OBS-003:** no malformed-Anthropic-bucket fixture (empty `starting_at`) asserting usage history is preserved.
- **OBS-004:** no unparseable-`expires_at` fixture asserting listings still work.
- **DEST-01/03:** no test that transport/auth errors are not reported as `missing` drift.
- **CRYPTO-03:** no crafted-backup-header test asserting KDF params are capped before allocation.

## Missing property/fuzz tests
- No fuzzing of: the `.env` parser (`envfile.rs`), git-diff parsing (`gitrepo.rs` `range_added_units`), backup payload deserialization (`backup.rs`), secret scanner (`scanner.rs`), URL validators (`notify.rs`/`docwatch.rs` — esp. IPv4-mapped IPv6, decimal/hex IP, DNS-rebinding).
- No property test for money/usage arithmetic overflow (NET-03/OBS-015) — release profile lacks overflow-checks.

## Missing tests for verified findings (regression)
Every P1–P2 remediation in REMEDIATION_PLAN.md needs a regression test: CRYPTO-01 (concurrency), OBS-001 (double-monitor-run keeps alert open), PI-01 (child env scrubbed), IPC-01 (path-confined + reauth), IPC-02 (reauth on delete), PI-06 (`pid<=0` guarded), GScan-01/02 (`core.hooksPath` detection, force-chain ordering).

## Untested layers (structural)
- **Tauri command layer (136 commands):** **no Rust tests.** Direct-IPC authorization (reauth-in-core vs UI-only) is only spot-verified by reading; needs a harness invoking each destructive command without the UI sequence.
- **React frontend (31 files):** **no tests.** Confirm/reauth dialogs, secret display/clearing, `docs_url` anchor rendering (IPC-05) are unverified by automated tests.
- **Migrations:** `migration_safety.rs` exists; verify it covers every one of the 10 migrations forward, plus the concurrent-first-open race (CONC-10) and SchemaTooNew refusal.

## Missing platform tests
- **Windows:** the CI Windows job is a compile gate (memory: `forbid-unsafe-and-platform-code`). No behavioral tests for: `taskkill` graceful→forceful (inject.rs), Windows credential manager (keyring), file-permission/ACL on exports (FS-07), auto-lock across suspend (CONC-02).
- **Linux:** no behavioral tests for process-group signalling, `Instant` across suspend (CONC-02), or 0600 semantics.
- **macOS-only assumptions:** clock/suspend behavior (CONC-02, PI-05) tested only on macOS; do not generalize.

## Missing packaged-app tests
- No test of the bundled Tauri app (cargo-tauri not installed locally per `BASELINE.md`); CSP/allowlist/opener config (`tauri.conf.json`, `capabilities/default.json`) unverified at runtime.

## Missing live-provider / destination tests (out of automated scope — require real creds)
- `scripts/live_verify_*.sh` exist for OpenAI/Anthropic/AWS/GitHub/GitHub-Actions/Stripe/Vercel but are **not run** in this audit (no real credentials; forbidden by scope). Live verification still required for: create/revoke/disable lifecycle per provider (ROT paths), destination read-back/exists semantics (DEST-01/02/09), and usage/pricing attribution accuracy.

## Tests that pass without proving the claimed property (audit caution)
- Verify that `execute_step`/drift tests actually assert on `missing`/`unknown` outcomes (DEST-04 shows the code marks verified regardless) rather than only on the happy path.
- Verify rotation tests assert the *value_version re-check* before destructive steps (ROT-004), not just state transitions.
