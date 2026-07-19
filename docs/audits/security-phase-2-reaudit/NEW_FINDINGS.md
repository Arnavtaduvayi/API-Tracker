# Phase 2 Re-Audit — New Findings & Deferred-Item Reassessment

IDs local to this re-audit (`RA2-n`). **None is merge-blocking for PR #10.** Each is pre-existing (not introduced by Phase 2) or an honestly-documented residual. Recorded for a follow-up pass.

---

## New observations from this re-audit

### RA2-6 — Flaky/timing-dependent PI-02 test fails the required CI check (MERGE-BLOCKING)
- **Severity:** Medium (release-process / merge-gate). **Blocks PR #10: YES.** **Blocks GA: yes (until de-flaked).**
- **Where:** `crates/core/tests/pi02_process_identity.rs` — `pid_reused_by_a_different_process_is_refused` (assert at line 183). A **new** Phase 2 test.
- **Symptom:** the required GitHub CI job **"Rust (core + CLI)" FAILED** on PR #10's head `260e47e` with `a recycled PID must fail the identity match, got Signalled` (`evidence/ci_pi02_flake_failure.log.txt`). It passes **15/15** locally on macOS; it failed on the Linux CI runner. The other three CI jobs (Windows Rust, frontend, macOS backend) pass.
- **Root cause (test, not production):** the test records a dead process's identity (`unix:lstart=…;comm=sleep`), waits **one** wall-clock second so a new decoy will have a *different* start-time, then asserts termination is `Refused`. But `ps lstart` has **1-second resolution** with jiffies→wall-clock **rounding slop** (±1 s), so a new process spawned ~1 s later can display the **same** `lstart` second. When it does, the new decoy's `(lstart, comm)` equals the recorded dead identity, and `terminate_verified` **correctly** matches them and returns `Signalled` — hitting the *documented* same-second-same-executable recycle residual (which the Phase 2 report itself states "this identity scheme cannot distinguish"). So the production PI-02 code is behaving exactly as designed and disclosed; the test's precondition (distinct start-seconds) is not reliably established by a 1-second wait.
- **Why it matters:** (1) it makes the required CI check red, blocking a clean merge; (2) it is precisely a "flaky, timing-dependent test" — the class this re-audit was asked to hunt; (3) it incidentally demonstrates that the PI-02 same-second-recycle residual is **real, not merely theoretical** — it manifested on CI. The residual disclosure is honest, but the test over-asserts a property the design cannot guarantee.
- **Not higher severity because:** no production defect — the identity check still fails *closed* for genuinely-distinct identities; the only impact is CI flakiness and an over-strong test assertion.
- **Required fix (test-only; NOT applied here per audit scope):** make the separation robust — wait ≥2 s, or (better) assert the freshly-probed `lstart` **actually differs** from the recorded one before asserting `Refused` (and treat a collision as the documented residual, not a failure). Then re-run CI and confirm the "Rust (core + CLI)" check is green.

### RA2-1 — Vercel env-var resolution reads only one page (no pagination)
- **Severity:** Low (correctness). **Blocks PR #10: No. Blocks GA: consider.**
- **Where:** `crates/core/src/destinations.rs` — `VercelDestination::resolve_env_identity` issues one `GET /v9/projects/{id}/env` and matches within the returned `envs` array. Vercel's env endpoint can paginate; a project with more variables than one page returns could place the destination's variable on a later page.
- **Impact:** a false `Ok(None)` (absent) for `exists`, and an idempotent no-op for `delete`, on projects with very large env-var sets. It cannot cause a wrong-variable delete (identity is still key+targets), so it fails *safe*, not dangerous.
- **Pre-existing:** the baseline matched key-only on the same single response; Phase 2 tightened matching but did not add pagination. Not a Phase 2 regression.
- **Fix (follow-up):** follow Vercel pagination (`pagination.next`) until the identity is found or the list is exhausted.

### RA2-2 — `terminate_pid` is dead production code with a slightly misleading doc comment
- **Severity:** Informational (hygiene). **Blocks PR #10: No.**
- **Where:** `crates/core/src/inject.rs` — `pub fn terminate_pid` has **zero production callers** (only its own unit test). Its doc says it "remains only for callers that hold a PID they have just obtained from a live child handle," but no such caller exists; the duration-limit auto-kill uses `Child::kill()` directly.
- **Impact:** none today. Risk is that a *future* caller could reach for `terminate_pid` (which does no identity check) instead of `terminate_verified`. It still guards `pid <= 0`.
- **Fix (follow-up):** remove it, or `#[doc(hidden)]`/`#[deprecated]` it pointing at `terminate_verified`.

### RA2-3 — `git_available()` uses an unbounded `git --version`
- **Severity:** Informational. **Blocks PR #10: No.**
- **Where:** `crates/core/src/gitrepo.rs` — `git_available` (and `git_program`'s `--version` check) call `Command::new(git).arg("--version").output()` without the bounded runner. Every *repository/network-touching* git call is bounded; this one is not.
- **Impact:** negligible — `git --version` performs no repo/network I/O and cannot hang on a dead mount or wedged lock (the CONC-06 threat). A hung `git --version` implies a broken git binary, not a repository problem.
- **Fix (optional):** route it through `run_git_bounded` for uniformity.

### RA2-4 — Tampered `proc_identity` matching a live victim's real identity would signal it
- **Severity:** Informational (threat-model boundary). **Blocks PR #10: No.**
- **Where:** `inject::terminate_verified` compares the *re-probed* identity to the recorded one. The identity check defeats accidental PID reuse. An attacker who can **write** an arbitrary `proc_identity` into the DB *and* crafts it to equal a currently-running victim's real `lstart`+`comm` could get that victim signalled.
- **Impact:** requires local DB write access, which already implies full local compromise (the attacker could kill the victim directly). The check's purpose — preventing accidental recycled-PID kills — holds. Documented as a limitation, not a defended-against threat.

---

### RA2-5 — React "32 security tests" headline is inflated; three coverage holes
- **Severity:** Low (test coverage). **Blocks PR #10: No.**
- **Finding:** an adversarial read of all 32 React tests + their production components confirms the **mocking seam is correct** (real components rendered; only the `../api`/`invoke` boundary mocked), **no fake timers**, no missing awaits, and the *genuine* security properties (reauth clear-on-success / retain-on-failure, reveal→hide DOM clearing, locked-vault gating of the authenticated tree, the rotation two-stage confirm→reauth **with a real pre-reauth `not.toHaveBeenCalled()` ordering assert**, honest backend-error propagation, and `safeExternalUrl` scheme neutralization at both unit and component layers) are established by driving real components against user-visible DOM. Under mutation reasoning each fails if its property breaks.
- **But:** of 32 tests, ~8 are ordinary util tests (date/severity) and ~5 are IPC arg-shape "contract pins" (mock `invoke`, assert its args) — useful regression pins but not user-visible security. ~16–19 carry the security weight. Three real coverage holes leave a security behavior able to regress with the suite green: (1) the 30-second reveal **auto-hide timer** (`CredentialDetail.tsx:116–120`) has zero coverage (would need fake timers); (2) **`EnvView`** is never rendered — the `.env.example` write error path is covered only *by composition* through the shared `ReauthDialog` catch, not an EnvView-specific test; (3) the **replace-value dialog** (holds a new secret + password in state, clears both on success/cancel) is untested. The delete test also lacks the pre-reauth ordering assert the rotation test has.
- **Not higher severity because:** all three untested behaviors *exist and are correct in production*; the IPC-05 fix (the only production change in Phase 8) is solidly tested; nothing is over-mocked or tautological in a way that hides a broken property. This is a coverage/label-accuracy gap, not a defective fix.
- **Fix (follow-up):** add a fake-timer test for the reveal auto-hide, one rendered-`EnvView` failure-path test, and a replace-value-dialog clear test; add the pre-reauth ordering assert to the delete test; and describe the count honestly (security vs contract-pin vs util).

## RA-P2-* (Phase 2's self-reported new findings) — confirmed dispositions

All three are **valid, correctly severity-rated, and non-blocking.** The Tauri inventory reconciliation confirmed they are the *only* wrapper-enforced security commands and are honestly marked `not_covered_*`.

| ID | Summary | My disposition |
|---|---|---|
| RA-P2-1 | `backup_create`, `provider_admin_connect`, `provider_admin_test` enforce reauth in the Tauri **wrapper**, not core | **Confirmed, Low.** All three *do* verify reauth today; the gap is enforcement *location* (a future core caller could miss it), matching the IPC-01/02 pattern. The destructive `provider_admin_disconnect` was correctly moved into core this phase. Does not block PR #10. |
| RA-P2-2 | 97 low-relevance commands have no direct authz test | **Confirmed, Informational.** They are `with_vault`-gated read/metadata commands. The harness deliberately scopes to the destructive/secret-bearing set. Does not block. |
| RA-P2-3 | `ProviderDetail` passes manifest URLs to `openUrl` without FE scheme validation | **Confirmed, Info/Low.** Distinct from the fixed IPC-05 `docs_url` anchor: `openUrl` routes through the Tauri opener allowlist (backend gate), not an `href`. Manifest URLs are shipped/vault data. Does not block; validate with `safeExternalUrl` as a follow-up. |

Two additional security-relevant commands surfaced by the inventory reconciliation as `not_covered` (structural-unlock-gated, reauth not required by design): `template_apply` (destructive: creates a project + writes `.env.example`, never overwrites) and `env_import` (secret-bearing: imports from a `.env`; the RA-3 unconfined-read concern applies). Neither requires reauth by design; both are honestly inventoried. Non-blocking.

---

## Deferred items — reassessed (correctly out of Phase 2 scope)

| Item | Status at `260e47e` | Blocks PR #10 | Blocks public alpha | Blocks GA |
|---|---|---|---|---|
| **RA-2 / NF-1** CLI broken-pipe panic | **Still present** — reproduced live during `smoke.sh` (panic on piped stdout); no secret, 126/0 | No | No | Yes (fix before GA polish) |
| **RA-3 / NF-2** unconfined `env_preview`/`env_import` reads | Still open; read-only, scanner-redacted previews | No | No | Yes |
| **PI-03** descendant/process-group termination | Open; now *tested* as documented behavior (grandchild survives) | No | No | Recommended |
| **PI-05** wall-clock grant/session expiry rollback | Open (desktop auto-lock uses monotonic time) | No | No | Yes |
| **CONC-01 / CONC-02** desktop mutex breadth / auto-lock across suspend | Open; Phase 3 removed git-time from CONC-01 for scans (scans collect outside the lock) but the coarse mutex model remains | No | No | Yes |
| **ROT-002..008, ROT-011** rotation state-machine races/correctness | Open; **untouched** by Phase 2 (the only rotation-adjacent change, `execute_step` verify-honesty, does not alter the ROT state machine) | No | No | Yes — highest-value remaining follow-up |

**CRYPTO-01, OBS-001, OBS-003, PI-01, IPC-01, IPC-02, CONC-04, ROT-001, PI-06** were closed by PR #9 (verified PASS in the prior re-audit) and remain closed at `260e47e` (their regression tests are green in the 505/0 run).

## Regression review — new failure modes introduced by Phase 2

**None found.** Specifically checked and cleared: no new deadlocks (git moved *outside* the vault lock — a net improvement); no transaction/lock held across a subprocess; process-identity fails **closed** (a probe failure refuses rather than signals — the safe direction); migration additive/compatible; no resource or child-process leaks (`ChildGuard` reaps on every path — verified by `assert_stub_reaped`; `SystemRunner` uses `wait_with_output`; the duration-kill uses `child.kill()`+`child.wait()`); git-hook edits are block-scoped (foreign content preserved); no misleading clean-scan (`complete = complete && warnings.is_empty()`, alerts resolve only on clean+complete); no stale verification timestamps (`record_verify` skips `last_verified_at` on `unknown`); no secret-bearing error messages (asserted in `tauri_command_authz` and destination tests); FE/BE types consistent (`tsc` green; `TerminationOutcome` tagged enum matches); serialization compatible (`Credential` is `Serialize`-only, new bool fields derived not stored); platform assumptions documented honestly; no `#[ignore]`/`todo!`/`unimplemented!` introduced; two existing tests **strengthened** (`observability`, `scanning`), all other existing-test edits legitimate adaptations (new arg signatures, coverage-gap alert kind, realistic Vercel mock, OBS-004 fixture fields).
