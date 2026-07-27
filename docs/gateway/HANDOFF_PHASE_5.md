# Local Gateway — Phase 5 handoff (final-audit remediation)

**Status: remediation complete; merge readiness NOT claimed.** PR #15 is open
and unmerged and requires a fresh independent re-audit before any merge
decision. See `audit/RE_AUDIT_HANDOFF.md`.

Nothing below is claimed unless a shipped test, a recorded measurement, or a
validation run in this document demonstrates it. Where this phase found an
earlier document claiming something the code did not do, the correction is
recorded rather than the original quietly rewritten.

## What this phase was

Remediation of the final independent audit of `feat/local-gateway`
(branch `audit/lg-final-independent-20260726`, base `ae66ca7`, verdict
`LOCAL GATEWAY READY TO MERGE: NO`). The audit reported 1 blocker, 6 high,
21 medium, and 26 low findings, plus 5 lows it could not verify.

**Every finding was reproduced against `ae66ca7` before any code changed. None
failed to reproduce.** The complete matrix — claim, reproduction, root cause,
disposition, code, test, docs, residual risk, commit — is in
`audit/REMEDIATION.md`.

## Commits

| Commit | What |
|---|---|
| `f202193` | Matching-key lock lifecycle + TTL (ADR 0020); `Debug` redaction; control-channel doc corrections |
| `7ec7289` | Custom-route verification key lifecycle (ADR 0021); MAC v2 binds the route prefix; load-time port re-validation |
| `b348084` | High-severity: prior-value disclosure and plaintext storage, restore-record destruction, macOS service swap, gateway-table deletion, plus duplicate-key/created-file/version-check/dry-run/FK-index |
| `45390f0` | Medium and low: systemd escaping, self-exit debounce, nonce race, token clamping, queue depth, DB error classification, orphan-sweep retry, bounded writer join, Windows session sweep, traversal hardening, trailer filtering, `Expect: 100-continue`, label honesty, stale-status banner; deleted the vacuous skeptic test and the spike |
| `d78f740` | Validation-evidence integrity: non-vacuous macOS script with negative controls, real-persistence privacy canary, adopted 16-category black-box battery |
| (this commit) | Documentation corrections, remediation matrix, re-audit handoff |

## Architecture decisions recorded

Two new ADRs. Both amend ADR 0019 rather than replacing it, and ADR 0019 now
carries an amendments section marking its superseded statements instead of
being rewritten.

- **ADR 0020 — matching-key lifecycle.** Drop on lock by default; the
  consented `match_while_locked` opt-out buys retention bounded by the locking
  session's `auto_lock_minutes`, capped at 8 hours. Contains the TTL decision
  ADR 0019 deferred, the rejected alternatives, the full lifecycle table,
  persistence and restart rules, and what termination does NOT clear.
- **ADR 0021 — custom-route verification key lifecycle.** Derivation, domain
  separation, install and clear points, why lock does NOT clear it (the
  deliberate opposite of the matching key), why symmetric and what that costs,
  MAC v2, and status honesty.

## The blocker

The vault-derived matching key was never dropped when the vault locked, though
SI-9, ADR 0019 D5, THREAT_MODEL GW-6 and the push-key consent dialog all
promised it was. `gateway_config.match_while_locked` was a stored column with
no consumer anywhere in the tree. No TTL existed. In a KeepAlive login service
the key — a guess-confirmation oracle over every in-scope fingerprint — stayed
resident for weeks after a lock.

Fixed with the policy in the service rather than in the callers: frontends send
a `VaultLocked` signal, `service::lock_disposition` decides, and
`ControlTarget::vault_locked` is a required trait method so a target that
ignores a lock does not compile. Every lock path signals — explicit lock, both
desktop auto-lock paths, backup restore, app exit, and `tethra vault lock`.

Mutation-checked: deleting the revoke fails
`locking_the_vault_revokes_the_resident_matching_key_by_default` and
`forwarding_continues_after_the_lock_revokes_the_key`.

## The functional blocker

`RouteState::set_mac_key` had no callers anywhere in the tree, so every
custom-origin route was permanently 503 — and the 503 text told the user to
unlock their vault, which installed nothing. The feature could not be used.

Fixed by a `PushRouteKey` control operation installed from every flow that has
an unlocked vault and could precede a custom-route request. Thirteen
end-to-end tests, including one that drives the real control channel against a
real service and then sends real HTTP through the listener to a synthetic
upstream.

## False security claims

Four documented mitigations did not exist. Each was decided individually
rather than uniformly implemented or uniformly deleted:

| Claim | Outcome | Why |
|---|---|---|
| SIGTERM handler clears the key | **Claim corrected** | No signal handler exists and adding one needs a dependency ADR 0019 rules out. GW-6 now distinguishes graceful stop (clears) from SIGTERM/SIGINT/SIGKILL/crash/OS shutdown/power loss (does not). |
| Unused routes are auto-disabled | **Claim removed, exposure disclosed** | Does not exist; `gateway_routes` has no last-used column. Deliberately not added: "unused" is not reliably observable — absence of recorded traffic is never evidence of absence of traffic, the rule this whole feature rests on — and silently disabling a route would break a project that runs monthly. An enabled route is now described as a standing exposure. |
| `SO_PEERCRED` peer-euid enforcement | **Claim corrected** | `peer_cred` is unstable; the alternatives need `unsafe` (forbidden) or a new dependency. The gate is filesystem permissions re-checked on every accept — same-uid-exact one layer down. The non-existent "peer-cred tests" citation is gone. |
| Per-tool link coverage note | **Claim narrowed** | Never implemented. The shipped heuristic is Node-only; COVERAGE_LIMITATIONS now lists the runtimes that are NOT detected. |

## Validation evidence

The audit found the flagship macOS evidence contained unconditional passes and
a "distinct fingerprint" result no assertion ever produced.

`scripts/gateway_validate_macos.sh` now asserts semantic outcomes against the
vault database and the status JSON, treats an empty response as failure,
scans for privacy canaries (failing if it scanned nothing), exercises its own
helpers against conditions they must reject, and fails the run if too few
checks executed.

`PACKAGED_MACOS_RESULTS.md` is marked **SUPERSEDED**: its numbers describe a
script that no longer exists, and it has not been re-executed. It was not
edited to look successful — the specific vacuous rows are marked as such.

The vacuous privacy canary is replaced by one that drives the real persistence
path and asserts the row count rose before it scans. Mutation-checked: storing
the raw request target instead of the sanitized path template fails it by
canary name and file.

## Tests

Counts from the final commit, executed locally:

| Suite | Result |
|---|---|
| `cargo test --workspace` | **936 passed, 0 failed, 0 ignored** |
| of which `crates/gateway` | **263 passed, 0 failed** |
| `bash scripts/smoke.sh` | **126 passed, 0 failed** |
| `vitest run` (desktop) | **41 passed, 9 files** |

Gateway suite breakdown at this head (`cargo test -p api-tracker-gateway`):

| Suite | Passed |
|---|---|
| unit (`src/`) | 75 |
| `adversarial_blackbox` | 17 |
| `control` | 24 |
| `custom_routes` | 13 |
| `doctor` | 5 |
| `envlink` | 22 |
| `forwarding` | 44 |
| `lifecycle` | 15 |
| `no_insecure_verifier` | 6 |
| `privacy_canaries` | 9 |
| `routes` | 11 |
| `schema` | 5 |
| `writer` | 17 |
| `perf` | 0 passed, 8 ignored (script-run; `PERFORMANCE_RESULTS.md`) |
| **Total** | **263 passed, 0 failed, 8 ignored** |

New this phase: 11 matching-key lifecycle tests (`tests/control.rs`), 5
control-plane unit tests, 13 custom-route tests (`tests/custom_routes.rs`), 17
black-box attack tests (`tests/adversarial_blackbox.rs`, adopted from the audit
branch), 3 lifecycle tests, 6 envlink tests, 2 core deletion tests, 2 envgov
masking tests, 3 forwarding tests, 2 privacy-canary tests (one a
`#[should_panic]` control on the canary machinery itself), and 4 frontend
tests.

Removed: `zz_skeptic_overflow_repro.rs` (asserted nothing; both tests ended in
a captured `eprintln!`) and `experiments/gateway-spike` (superseded; its
committed lockfile pinned 17 crates at versions differing from the root).

## Full validation run

```
cargo fmt --all --check                                  clean
cargo clippy --workspace --all-targets -- -D warnings    clean
cargo test --workspace                                   936 passed, 0 failed
cargo build --workspace --release                        ok (1m 12s)
bash scripts/smoke.sh                                    126 passed, 0 failed
npm ci                                                   ok (locked lockfile)
npx prettier --check "src/**/*.{ts,tsx}"                 clean
npx eslint src                                           clean
npx tsc --noEmit                                         clean
npx vitest run                                           41 passed (9 files)
npx vite build                                           ok
```

## Authoritative CI

All four required checks passed on the commits carrying this remediation's
code and prose:

| Commit | Rust (core + CLI) | Rust core (Windows) | Desktop backend (macOS) | Desktop frontend |
|---|---|---|---|---|
| `fc55d9c` — every code change plus the documentation corrections | pass | pass | pass | pass |
| `17b314a` — the last two peer-credential doc corrections | pass | pass | pass | pass |

`fc55d9c` is the important row: it contains **100% of the code** in this
phase, including the `cfg(not(unix))` Windows session sweep and the Windows
control-channel stub, both exercised on a real `windows-latest` runner.

A caveat stated rather than papered over: every push starts a new run, so the
commit that RECORDS a CI result is by construction not the commit that result
came from. This table names the commits actually verified. If the branch head
is later than `17b314a`, the delta is documentation only — check
`git diff 17b314a..HEAD` before treating that as a gap, and re-run CI yourself
against whatever head you audit.

## Platform validation — what was and was NOT executed

| Platform | Executed |
|---|---|
| macOS | Unit, integration, smoke, release build, frontend suite — locally. **Packaged service lifecycle: NOT re-executed since the validation script was corrected.** |
| Linux | **Compiled and tested in CI only.** No packaged lifecycle validation has ever been performed. |
| Windows | **Compiled and tested in CI only.** The HKCU `Run` autostart path has never executed on a real Windows login session; status reports `RegisteredButNeverValidated` by design. |

"Compiled and tested in CI" and "packaged lifecycle validated" are different
claims and are kept distinct here and in `COVERAGE_LIMITATIONS.md`.

## Known accepted risks

Six findings were dispositioned ACCEPTED RISK with reasoning, listed together
in `audit/REMEDIATION.md` under "What is NOT fixed, and why": the activity
summary's mixed window granularities, carryover bytes transiting plain
allocations, `tethra run --observe` over a gateway-linked project producing
silent zero coverage, the audit event recorded at key-release rather than
push-success time, the consent file list sitting behind "Learn more", and
non-modal confirmation dialogs (repo-wide, not gateway-specific).

None is a false security claim: each is described accurately in the document a
reader would consult.

## Provenance correction

`HANDOFF_PHASE_3.md` claimed 17 Phase 3 commits. The real count, verified with
`git rev-list --count 0e76eed..HEAD`, is 28 at this head — and was already
wrong when a commit whose own message read "correct the handoff commit range"
landed. That table is now generated from `git log` rather than maintained by
hand.

Commit `4814a3b` was reviewed: `test: drop a vacuous assertion newer clippy
rejects (overly_complex_bool_expr)`, a one-line deletion in
`crates/core/tests/rotation_access.rs` with no production code touched — a
legitimate CI-hygiene prerequisite. Its parent is `927cadf`, so it sits inside
the Phase 2 range where `HANDOFF_PHASE_2.md` lists it; plain `git log
--oneline` prints it below `927cadf` because their commit dates are equal,
which is what makes it look out of range.

## Next step

A fresh independent re-audit, in a fresh session and a fresh worktree, by a
reviewer who did not perform this remediation. `audit/RE_AUDIT_HANDOFF.md`
names the decisions that need independent judgement, the files deserving
attention, and the specific things to try to break.

**PR #15 remains open and unmerged. This phase makes no merge recommendation.**
