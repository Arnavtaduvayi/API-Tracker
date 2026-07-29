# Handoff to the next independent auditor

You are auditing `feat/zero-friction-api-tracking` after the remediation of
`audit/opus-fresh-final-20260728`. This file exists to make your job harder,
not easier: it names what was fixed, what was **not**, and where a
plausible-looking fix could still be hollow.

Do not treat anything below as verified because it is written down. Every
claim here is falsifiable and most of them tell you exactly how.

```text
Previous audit:  docs/activity-onboarding/audit/opus-fresh-final-20260728/
                 (unchanged — 9 merge blockers, 28 findings)
Audited head:    cac469e3497e5ba905c9e26d31d43c4b989594c5
This head:       see `git rev-parse HEAD`
PR:              #16 — OPEN, unmerged
```

## The defect class this codebase keeps producing

Three consecutive audits have found the same thing wearing different clothes:

> a check that has never executed anywhere is indistinguishable, from the
> outside, from a check that always passes.

Instances found so far: a gate reading its expectations from the artifact it
validated; a `sed` that never matched a byte; two checks that could not fail;
two negative controls that did not call the primitives they certified; a
preservation clause guarded by an unreachable copy of its own condition; and a
refusal branch with no test that executed it.

**Hunt this class first.** The remediation added mutation checks for each fix,
and those are recorded — but a mutation check written by the person doing the
fixing is exactly the thing you should distrust.

## What is NOT fixed, in priority order

### 1. `VAL-05` — the gateway gate binds a COUNT, not IDENTITIES

The floor is gone. `scripts/gateway_validate_macos.sh` now enforces an
**equality** on its required set: the three machine-dependent sites the audit
named (`node` presence, the repair staging block, the port re-check) route
through `opt_ok`/`opt_bad` and are excluded, and everything else must total
exactly `REQUIRED_CHECKS=50`.

**What is still missing.** That equality binds how MANY required checks ran,
not WHICH. This script still has:

* no check register,
* no per-check IDs,
* no required-vs-optional declaration per check (only per call site),
* no machine-readable results,
* no duplicate/missing/skip rejection,
* no external result validation,
* **no mutation suite** — there is no counterpart to
  `scripts/validation_harness_mutants.sh`.

So a required check **swapped for a different one** keeps the count and passes.
That is strictly weaker than `tracking_validate_macos.sh`, which has a declared
group table, a fail-closed enumerator that reads the script itself, a per-group
equality gate, and a register with named checks.

**What to check:** whether `REQUIRED_CHECKS=50` is itself defensible. It was
derived from one measured CI run (57 total on `141152d`, minus 1 node, 5 repair,
1 port), not from an enumerator that reads the source. Count the call sites
yourself and see whether you get 50. If you get a different number, the constant
is wrong and the gate has been passing for the wrong reason — or failing for
one.

### 2. `VAL-04` was fixed but never executed

The negative controls now call the real primitives via `probe_primitive`, but
`gateway_validate_macos.sh` has **no mutation suite** — there is no counterpart
to `scripts/validation_harness_mutants.sh`. The fix is argued from source. The
first CI run on this head is its first execution.

**What to check:** neuter `assert_db` and `assert_status` in a copy and confirm
the controls fail. If they do not, `VAL-04` is not fixed.

### 3. `VAL-03`'s two rewritten checks have never run

Same reason. `--mode service` runs only in CI. Their failure modes are argued
from source.

**What to check:** that `la_digest()` actually differs when a namespaced plist
is installed, and that the label assertion fails when the product reports a
non-namespaced label.

### 4. `VER-02` is pinned at the core layer only

`crates/tracking/tests/zft006_regression.rs` asserts observable behaviour of
`TrackingStatusReport`. The CLI status renderer, the Tauri command boundary and
the UI state mapping are **not** separately pinned. They render from the same
report, so a divergence would be in the rendering.

**What to check:** whether a mutation in `apps/cli/src/track_cmd.rs`'s status
rendering, or in the frontend's state mapping, can make a failed setup read as
verified while the crate stays green.

### 5. `ENC-02` — the highest-value remaining non-blocker

Dropping the `sealed` field from `prior_env_json` silently empties the user's
`.env` while reporting `complete:true`. There is no structural `had_prior` flag
and no MAC, so "a value was recorded" and "no value existed" are
indistinguishable. The gateway compartment opens `vault.db` read-write with the
key withheld: it cannot read restore values but can destroy them.
`gateway_routes` and `tracking_approved_origins` are MAC'd against this same
adversary; `prior_env_json` is not. **Not addressed in this pass.**

### 6. Fourteen further deferred findings

`ENC-03` `ENC-04` `VAL-06` `VAL-07` `VAL-08` `VAL-09` `VAL-10` `VAL-11`
`ORG-02` `VER-04` `GIT-01` `CON-01` `CON-02` `CON-03`. Each has a disposition
and reasoning in `POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md`. None was fixed.

### 7. `REPO-01` is blocked on repository administration

`main` has no branch protection and no rulesets. This is a GitHub setting, not
a code change, and cannot be done from a branch. Until it is, "required check"
is a convention — which compounds `VAL-01`: a correct gate that nothing
enforces is still not a gate.

## Where to attack the fixes that ARE claimed

### `VAL-01` — the trusted manifest

The manifest identifies required checks by **static label prefix**, not by a
stable per-check ID. So:

* a check renamed *and* the manifest updated in the same commit passes the
  gate — review is the only control;
* a label whose static prefix is not actually static (an interpolation moved
  earlier) would silently stop matching.

Try: change a SERVICE label's leading words and update the manifest to match.
Nothing fails. Is that acceptable? Argue it either way, but notice that this is
one rung short of the "unique stable check IDs" the remediation brief asked
for, and the matrix says so.

Also try: `scripts/validation_asserter_tests.sh` builds its "genuine" result
**from the manifest**. That is a parser test, not a harness test — the harness
and the validator are only tied together by
`scripts/validation_manifest_check.sh`. Is that tie strong enough?

### `VER-01` — the CAS

`refresh_with` retries three times and then **reports without writing**. Ask
whether a caller can be starved into that path in practice, and whether the
resulting stale cached row is observable to a user.

Also: `transition` does not retry, by design. All four production callers were
checked — three propagate with `?`; `apply.rs`'s failure path swallowed the
result with `let _ =` and now retries, because a swallowed conflict there loses
the record that an apply failed. Confirm that retry is bounded and that no
caller surfaces `StateConflict` as a raw driver string to a user.

### `ENC-01` — the desktop call site

`both_front_ends_call_the_shared_migration` asserts the call site by **reading
the source file**. That is a real guard against the exact defect (a missing
call site is what no unit test can observe), but it does not prove the command
runs the migration at runtime. The Tauri command was not driven.

Try: does `vault_unlock` reach `upgrade_restore_records` on every path, or only
some? What happens if `with_vault` fails?

### `ORG-01` — the CLI refusal

Every fixture declares **only** repository-chosen destinations, so the run exits
at "nothing configurable" before apply step 1. The mixed built-in/custom case
is driven through apply only in CI. "Changed previously approved origin" is
covered at the library layer, not the CLI.

Try: a repository with a built-in provider *and* a custom origin, run
`track --yes` through a complete apply on a disposable machine, and confirm the
custom route is absent from `gateway_routes` afterwards.

## Environment constraints this remediation worked under

Stated so you can judge what was and was not observed:

* **The development machine carries a live production gateway**
  (`dev.api-tracker.gateway`, loaded in `gui/<uid>`). Every service-lifecycle
  path — `gateway_validate_macos.sh`, `--scope full`, `--require-service`,
  `service_cleanup_safety.sh`, every `launchctl` write verb — was therefore
  **not executed**. Redirecting `$HOME` does not isolate this;
  `launchctl` addresses `gui/<uid>`.
* Verified after every run in this pass: the production plist is byte-identical
  and still loaded, and no stray agent was created.
* The desktop GUI was not click-driven. Backend validation of the same
  orchestration was executed; UI claims are source-reviewed only.
* `scripts/validation_ownership_tests.sh` exercises the ownership primitives
  against a **fake `$HOME`** through a new library mode
  (`TETHRA_VALIDATE_LIB_ONLY=1`). That seam is new; check it does not weaken
  the script's own preflight ordering.

## What would make the next verdict clean

1. Port the register, per-check IDs and machine-readable results to
   `gateway_validate_macos.sh`, proved on a disposable runner. The equality
   gate exists now but binds a count, not identities (`VAL-05`).
2. Give that script a mutation suite (`VAL-04`).
3. Bind `prior_env_json` with a `had_prior` flag or a MAC (`ENC-02`).
4. Per-check IDs for the trusted manifest, replacing label prefixes
   (`VAL-01` residue).
5. Pin `ZFT-006` at the CLI and UI boundaries (`VER-02` residue).
6. Branch protection on `main` (`REPO-01`) — needs a repository admin.

## Do not

* Merge PR #16. It stays open and unmerged; the merge decision is yours, not
  the remediation's.
* Treat the mutation checks recorded in the matrix as independent verification.
  Re-run them. Better: invent your own.
* Run service-lifecycle validation on a machine with a live gateway.
