# Post-final-re-audit remediation evidence

What was actually run, and what it produced. Dispositions and reasoning live in
`POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md`; this file is the measurements.

Where a thing was **not** executed, it says so and why. That distinction is the
whole point of the audit this remediation answers.

```text
Audited head:   cac469e3497e5ba905c9e26d31d43c4b989594c5
Base:           0e6764ba3bcc7a2e3d14afaa91041d4bfcd3b75b
Branch:         feat/zero-friction-api-tracking
Audit branch:   audit/pr16-fresh-final-reaudit @ baa0239   (never modified)
PR:             #16 — OPEN, unmerged, base main
```

---

## 1. The blockers, reproduced BEFORE any production change

Each was reproduced on the audited head, in this order, before the
corresponding fix was written.

### VAL-01 — reproduced

```text
$ python3 scripts/ci_assert_service_results.py \
    <audit>/repro/repro_asserter_accepts_zero_checks.json
  OK    executed_total = 0 (declared 0)
  OK    group SERVICE      0/0 executed, 0 failed
  OK    register: 0 named checks, 0 not passed
=== SERVICE SCOPE COMPLETED: 0/0 checks passed in full:service ===
EXIT=0
```

A twelve-line document declaring zero checks certified the entire service
scope.

### VAL-02 — reproduced

```text
$ printf '{\n  "definition_path": "/Users/x/…/dev.api-tracker.gateway.abc123.plist"\n}' \
    | sed -n 's/.*"definition_path":"\([^"]*\)".*/\1/p' | wc -l
0
```

`apps/cli/src/render.rs:15` renders with `serde_json::to_string_pretty`, which
emits `"definition_path": "…"` — with a space. The expression required none, so
it matched nothing on every run that has ever executed, and every run fell
through to the filename glob.

### VAL-03 — reproduced by source

`scripts/tracking_validate_macos.sh` (audited head):

* `[ ! -f "$PLIST" ]` — `$PLIST` is `$LA_DIR/dev.api-tracker.gateway.plist`, the
  pre-namespacing path. Preflight has already proved it absent, and ADR 0026
  means the product writes `…gateway.<installation-id>.plist` instead. The
  assertion cannot fail and does not observe the file it purports to exclude.
* `[ "$INSTALLED_LABEL" != "$LEGACY_LABEL" ]` — `$INSTALLED_LABEL` is `basename`
  of a glob that **mandates** a suffix, so it can never equal the bare label.
  The `none` fallback also passes.

### VAL-04 / VAL-05 — reproduced by source

`scripts/gateway_validate_macos.sh:716` calls `db` and compares inline;
`:731` re-implements `assert_status`'s python inline. Neither calls the
primitive it names. `MIN_CHECKS=32` at `:772`, against `56` quoted as a fixed
property in three documents.

### VER-01 — reproduced by construction

`refresh_with` computes `failure_is_newer` from the caller's in-memory
`setup.attention_at`; `write_derived` commits `UPDATE … WHERE id = ?1`. With
two connections on one database, a failure recorded between the read and the
write is nulled and the report is `VerifiedAndActive`.

### VER-02 — reproduced

```text
$ # replace keep_reason with None, then:
$ cargo test -p api-tracker-tracking
… 15 binaries, 152 tests, test result: ok. 0 failed
```

The literal ZFT-006 failure-drop broke nothing in the crate.

### ENC-01 — reproduced

```text
$ grep -rn 'scrub' apps/desktop/ --include='*.rs' --include='*.ts' --include='*.tsx'
(no output)
```

### ORG-01 — reproduced

```text
$ grep -rn 'allow-origin\|allow_origin\|does not approve' apps/cli/tests/
(no output)
```

---

## 2. The same reproductions, after the fixes

### VAL-01 — refused

```text
$ python3 scripts/ci_assert_service_results.py <the same forgery> --commit any
  FAIL  executed_total = 0 (manifest requires 63)
  FAIL  group SERVICE      0/9 executed, 0 failed
  FAIL  group APPLY        DID NOT RUN
  … 9 more groups …
  FAIL  required SERVICE  'launchd loaded the namespaced service gui/'
  … 8 more required checks …
  FAIL  fact service_created_by_this_run = None
=== SERVICE SCOPE ASSERTION FAILED ===
  (33 distinct failures)
EXIT=1
```

### VAL-02 — the extractor works and the glob is gone

```text
$ bash scripts/validation_ownership_tests.sh
  PASS  control: the audited head's sed extracts NOTHING from pretty-printed JSON
  PASS  while exact JSON parsing extracts the path the product actually reported
  PASS  the harness contains NO $LEGACY_LABEL.*.plist glob
  PASS  and no regex that assumes the product renders JSON without a space
=== OWNERSHIP TEST RESULT: 29 passed, 0 failed ===
```

### VER-02 — the regression is caught

```text
$ # failure_is_newer -> false (the literal v15 clause)
$ cargo test -p api-tracker-tracking
    a_failed_re_run_is_never_reported_as_verified … FAILED

$ # keep_reason -> None (the audit's exact mutation)
$ cargo test -p api-tracker-tracking
    an_upgraded_v15_row_does_not_lose_its_failure_on_the_first_refresh … FAILED
```

Both mutations survived the entire suite at the audited head.

### ORG-01 — the refusal is pinned

```text
$ # replace the --yes refusal with selections.approve_origin(...)
$ cargo test -p api-tracker-cli --test track_origin_refusal
test result: FAILED. 5 passed; 6 failed
    a_yes_run_refuses_a_repository_chosen_origin
    a_yes_run_refuses_several_repository_chosen_origins
    a_repository_cannot_disguise_a_custom_origin_as_a_builtin_provider
    a_refused_run_creates_no_approval_record_for_a_later_run_to_inherit
    a_near_miss_allow_origin_does_not_approve_the_repositorys_choice
    no_credential_value_appears_on_the_refusal_path
```

### ENC-01 — the call site is pinned

```text
$ # delete the desktop call site
$ cargo test -p api-tracker-gateway --test legacy_rollback_migration
    both_front_ends_call_the_shared_migration … FAILED
```

---

## 3. Validation-integrity: the ten required scenarios

`scripts/validation_asserter_tests.sh`, wired into `ci.yml`. One genuine result
is built **from the trusted manifest** and accepted; every mutation of it is
refused.

| # | Scenario | Result |
|---|---|---|
| 1 | Known-good output | **accepted** |
| 2 | Forged-success output (the audit's own 0/0 artifact, verbatim) | refused |
| 3 | One required check removed (count preserved by a filler) | refused |
| 4 | One check duplicated | refused |
| 5 | One required check marked skipped | refused |
| 6 | Scope changed | refused |
| 7 | Commit changed | refused |
| 8 | Namespace changed (production label / empty id / foreign label / absent) | refused ×4 |
| 9 | Offline result substituted — as-is, and relabelled `full:service` | refused ×2 |
| 10 | File truncated (also: empty, non-JSON, JSON array, missing) | refused ×5 |

Plus: mode changed; a false expected count; a shrunk SERVICE group; an
informational result substituted; a nonzero skipped count; an unknown check
name; an undeclared group; a pre-existing service; missing provenance; an
unknown schema; and an undeclared scope.

**33 assertions, 0 failed.**

Separate suites, as required:

* **Harness behaviour** — `scripts/validation_harness_mutants.sh` (8 mutants,
  8 killed) and `scripts/tracking_validate_macos.sh --scope selfcheck`.
* **Result parser** — `scripts/validation_asserter_tests.sh`.
* **Trusted manifest** — `scripts/validation_manifest_check.sh` (37 assertions).
* **Workflow wiring** — `.github/workflows/ci.yml` and
  `packaged-service-macos.yml`; the latter passes `--scope`, `--mode` and
  `--commit` from the workflow, never from the artifact.

### The trust-boundary mutation

Required by the brief: restore the self-reported-count behaviour and prove the
tests fail.

```text
$ # expected = r.get("expected_total"); group sizes from the results file
$ bash scripts/validation_asserter_tests.sh
  FAIL  a SELF-CONSISTENT result containing only the SERVICE group is REFUSED
=== ASSERTER FORGERY RESULT: 32 passed, 1 failed ===
```

That forgery is internally perfect — every count agrees with every other, all
nine required SERVICE checks are present under their real labels and passing,
provenance is true, the label is namespaced, the commit matches. Its only
defect is that it contains 9 checks where the scope is 63. Nothing inside the
file can detect that; the manifest is the only thing that does.

**Note on defence in depth.** The first version of this suite did **not** kill
that mutation: the by-name and provenance guards independently caught every
other forgery, masking the count boundary. That is the same defect class the
audit is about — a guard that could be removed with nothing noticing — so the
suite was extended until the boundary had a test of its own. Recorded because
it is exactly the kind of near-miss that should not be silent.

---

## 4. Concurrency

`crates/tracking/tests/verification_concurrency.rs` — 12 tests, two
`rusqlite::Connection`s on one `vault.db`, because one connection cannot
express a lost update. Interleaving is deterministic: either hand-sequenced
(read → competing write → attempted write, which is the "process restart
between read and write" case) or two threads released by a `std::sync::Barrier`.
**No test sleeps to create a race.**

| Required case | Test |
|---|---|
| Two refreshes racing | `two_concurrent_refreshes_converge_without_a_lost_update` |
| Failure racing with success | `a_failure_racing_a_successful_refresh_is_never_lost` |
| Gateway death racing an observation | `gateway_death_racing_an_observation_never_reports_current_success` |
| Route removal racing refresh | `route_removal_racing_a_refresh_is_not_overwritten` |
| Link removal racing refresh | `link_removal_racing_a_refresh_is_not_overwritten` |
| Setup generation change | `a_setup_generation_change_invalidates_an_in_flight_refresh` |
| Old verification session vs new | `an_old_verification_session_cannot_verify_the_new_one` |
| Desktop and CLI concurrently | `desktop_and_cli_refreshing_together_agree_and_lose_nothing` |
| Process restart between read and write | `a_refresh_from_a_stale_handle_cannot_erase_a_failure_written_in_between` |

Mutation: removing the CAS predicate fails 5 of the 12.

**Not covered:** apply-vs-apply, apply-vs-undo and legacy-scrub-vs-undo are not
separately tested. **That gap was real and `NEW-31` found what was hiding in
it: `record_applied` advanced the row version without predicating on it, so
apply-vs-apply was last-writer-wins.** Fixed and covered in the latest-audit
remediation (`crates/tracking/tests/transaction_recovery.rs`). The original
argument below is preserved as written:

`record_applied`, the undo artifact clear and the re-apply
upsert all advance the row version, so a refresh in flight across any of them
re-reads; the *pairwise* races between those writers themselves are argued from
that, not measured. Named in the handoff.

---

## 5. Local validation on this head

```text
cargo fmt --all --check                              PASS
cargo clippy --workspace --all-targets -- -D warnings PASS (0 warnings)
cargo test --workspace --all-targets                 see §6
cargo build --workspace --release                    PASS
bash scripts/tracking_validate_macos.sh --scope selfcheck   5/5 checks, PASS
bash scripts/validation_harness_mutants.sh           8 killed, 0 survived
bash scripts/validation_ownership_tests.sh           29 passed, 0 failed
bash scripts/validation_manifest_check.sh            37 passed, 0 failed
bash scripts/validation_asserter_tests.sh            33 passed, 0 failed
```

### NOT executed here, and why

* `scripts/gateway_validate_macos.sh`, `--scope full`, `--require-service`,
  `scripts/service_cleanup_safety.sh`, and every `launchctl` write verb.
  **This machine carries a live production gateway**
  (`dev.api-tracker.gateway`, loaded in `gui/<uid>`), and `launchctl` addresses
  `gui/<uid>` regardless of `$HOME` — a redirected `$HOME` does **not** isolate
  a service install. Real service-lifecycle validation stays on the disposable
  macOS CI runner.
* The desktop GUI was not click-driven. Backend validation of the same
  orchestration ran; UI claims are source-reviewed.

### Isolation invariant, checked after every run in this pass

```text
$ ls -la ~/Library/LaunchAgents/dev.api-tracker.gateway.plist
-rw-------  1 … 996 Jul 27 09:15 …/dev.api-tracker.gateway.plist
$ launchctl print gui/$(id -u)/dev.api-tracker.gateway >/dev/null && echo LOADED
LOADED
$ ls ~/Library/LaunchAgents | grep -i tethra
(no stray agents)
```

The production plist is byte-identical to how this session found it, still
loaded, and nothing this work did created an agent.

---

## 6. Test counts on the final head

```text
cargo fmt --all --check                                PASS
cargo +stable clippy --workspace --all-targets -D warnings   PASS — 0 warnings
cargo test --workspace --all-targets                   40 binaries, 552 passed,
                                                       0 failed, 9 ignored
cargo build --workspace --release                      PASS
bash scripts/smoke.sh                                  140 passed, 0 failed

apps/desktop:
  npm ci                                               PASS (lockfile)
  prettier --check src                                 PASS
  eslint src                                           PASS — 0 problems
  tsc --noEmit                                         PASS
  vitest                                               11 files, 102 passed, 0 failed
  vite build                                           PASS
```

Validation scripts (all wired into `ci.yml`):

```text
tracking_validate_macos.sh --scope selfcheck    5/5 checks, 0 failed
validation_harness_mutants.sh                   8 mutants, 8 killed, 0 survived
validation_ownership_tests.sh                  29 passed, 0 failed
validation_manifest_check.sh                   37 passed, 0 failed
validation_asserter_tests.sh                   33 passed, 0 failed
```

Not run locally, for the reason in §5: `gateway_validate_macos.sh`,
`--scope full`, `--require-service`, and the packaged macOS service lifecycle.
Those run only on the disposable CI runner.

* New test files added by this remediation:
  * `crates/tracking/tests/verification_concurrency.rs` — 12
  * `crates/tracking/tests/zft006_regression.rs` — 5
  * `crates/gateway/tests/legacy_rollback_migration.rs` — 9
  * `apps/cli/tests/track_origin_refusal.rs` — 11
  * `crates/gateway/src/stream.rs` (unit) — 2
  * `scripts/validation_ownership_tests.sh` — 29 assertions
  * `scripts/validation_manifest_check.sh` — 37 assertions
  * `scripts/validation_asserter_tests.sh` — 33 assertions
* Migration added: `db.rs` v19 (`tracking_setups.row_version`).

---

## 7. Mutation and negative-control ledger

Every fix below was mutated and the named test observed to fail. Each mutation
was reverted immediately and the suite re-run green.

| Finding | Mutation applied | Killed by |
|---|---|---|
| `VAL-01` | expectations read from the results file again | `a SELF-CONSISTENT result containing only the SERVICE group is REFUSED` |
| `VAL-02` | dead sed + glob fallback restored as code | 4 assertions in the ownership suite + its count floor |
| `VER-01` | CAS predicate removed (`WHERE id = ?1`) | 5 tests in `verification_concurrency.rs` |
| `VER-02` a | `failure_is_newer` forced false (literal v15) | `a_failed_re_run_is_never_reported_as_verified` |
| `VER-02` b | preserved reason dropped (`write_derived(..., false)`) | `an_upgraded_v15_row_does_not_lose_its_failure_on_the_first_refresh` |
| `ENC-01` | desktop call site deleted | `both_front_ends_call_the_shared_migration` |
| `ORG-01` | refusal replaced with an approval | 6 of 11 tests |
| `SEC-02` | (control) a reader that refuses everything | `control_a_reader_inside_its_deadline_relays_normally` — **insufficient, see `NEW-48`/`NEW-51`**: this exercises the reader, not the connection loop around it, so deleting the whole wiring left it green. The real controls are in `crates/gateway/tests/connection_limits.rs`. |

### `VAL-04`, mutation-checked after CI proved it necessary

`probe_primitive` was verified against a stand-in harness: a false assertion
yields `fail`, a true one `pass`, the outer tally is untouched, and — the point
— a **neutered** primitive (`assert_db(){ ok "$2"; }`) makes the false case read
`pass`, which is what the control tests for.

That verification was written *because CI failed*. The first version ran each
primitive inside `v="$(probe_primitive …)"`, and command substitution is a
subshell whose `pass`/`fail` increments never reach the parent — so every probe
read `+0p/+0f` and all three controls failed:

```text
FAIL  assert_db did not behave as required (false-query:malformed(+0p/+0f) …)
FAIL  assert_status did not reject a stopped gateway (observed: malformed …)
=== PACKAGED MACOS RESULT: 54 passed, 3 failed ===
```

Worth recording plainly: the fix for *a control that never called its
primitive* was itself, briefly, *a control that never observed one*. It was
caught on first execution because the controls are now load-bearing — at the
audited head this same defect would have reported PASS.

That run also measured the real total: **57** (the audited 56, plus the control
this adds). The new floor of 45 sits comfortably below it; the previous 32 did
not.

**No mutation check for `VAL-03`.** It is in `--mode service`, which cannot be
executed on this machine. Its fix is argued from source and is first executed
by CI. This is a gap, stated rather than left for the next auditor to find.


---

## 8. What the packaged macOS runner actually proved

`VAL-01` … `VAL-05` are the findings whose fixes cannot be executed on a
developer machine. Here is what CI executed, per head.

```text
cac469e  (audited head)            packaged: success
4140168  first remediation head    packaged: FAILURE  — probe_primitive subshell
141152d  commit-identity fix       packaged: FAILURE  — same
9117e83  evidence counts           packaged: FAILURE  — same
54455ee  flaky-probe fix           packaged: FAILURE  — same
1af8edf  probe_primitive fixed     packaged: success
e4c5264  docs                      packaged: success
4ee7494  VAL-05 equality gate      packaged: success
9844c49  docs only, on 4ee7494     packaged: FAILURE  — partial gateway link
db2707a  apply-failure retry       packaged: (pending)
```

### `VAL-01`, `VAL-02`, `VAL-03` — executed and passing (`e4c5264`, `4ee7494`)

```text
=== PACKAGED TRACKING VALIDATION (scope=full, mode=service): 63 passed, 0 failed (63/63 checks) ===
  OK    executed_total = 63 (manifest requires 63)
  OK    required SERVICE  'the dry run left ~/Library/LaunchAgents byte-identical'
  OK    required SERVICE  'the apply installed a real LaunchAgent the product can name'
  OK    required SERVICE  'the installed LaunchAgent declares the label the product reports'
  OK    required SERVICE  'the label is namespaced per data directory, not the global one'
  OK    required SERVICE  "the LaunchAgent runs the helper the product installed in this run's data directory"
  OK    required SERVICE  'the installed helper is byte-identical to the in-bundle helper'
  OK    required SERVICE  'launchd loaded the namespaced service gui/'
  OK    required SERVICE  'the running service (pid '
  OK    required SERVICE  'the service exposes its control endpoint at $TETHRA_DIR/gateway.sock, mode 0600'
  OK    fact service_created_by_this_run = True
=== SERVICE SCOPE COMPLETED: 63/63 required checks passed in full:service ===
```

The count came from the manifest (`manifest requires 63`), the nine SERVICE
checks matched **by name**, and the provenance fact held. `VAL-02`'s
product-derived ownership and `VAL-03`'s two rewritten checks are inside that
63 and passed.

### `VAL-04` — executed and passing

```text
  PASS  assert_db itself rejects false, empty and erroring queries, and accepts a true one
  PASS  assert_status itself rejects a stopped gateway (an empty response is a failure)
  PASS  assert_status rejects a property that evaluates false
```

Its own first execution **failed** (four consecutive heads), because the first
version ran each primitive inside a command substitution. That failure is the
evidence the controls are load-bearing: at the audited head the same defect
reported PASS.

### `VAL-05` — the constant was right

```text
=== PACKAGED MACOS RESULT: 55 passed, 2 failed ===
  required 50/50   optional 7   total 57
```

`50` was derived from a measured run (57 total − node 1 − repair 5 − port 1) and
the gate confirms it exactly. `4ee7494`, the first head carrying the gate,
passed the whole job.

---

## 9. New finding: the packaged link check is nondeterministic

`9844c49` differs from `4ee7494` by **documentation only** — verified with
`git diff --name-only`, which lists five `.md` files and nothing else. `4ee7494`
passed; `9844c49` failed:

```text
== 6. Link the project (real .env rewrite, preview+confirm) ==
  FAIL  base url not written
  FAIL  alias not written
  PASS  NO_PROXY written
  PASS  marker comment written
  PASS  existing OPENAI_API_KEY preserved
```

So the link **partially** applied: the marker, `NO_PROXY` and the preserved key
landed; the two base-URL variables did not. The run then continued and curl,
Python and Node all reached the provider through the gateway.

Ruled out:

* **A port mismatch between the two assertions.** Both runs report the same
  value in `gateway is listening (port N)` and in `link base: …:N/p/…`.
* **A code regression.** No product file differs between the passing and
  failing heads.
* **Nondeterminism in the product's link path.** Driven locally five times
  against a persisted port with no service installed, `gateway link` wrote both
  variables every time.

Not ruled out: a divergence between the port persisted in `gateway_config` and
the port the service is actually listening on, which would make the harness's
`grep "…:$PORT/p/"` fail while the link itself succeeded against the stored
value. That is a real hypothesis and it is **unconfirmed** — it needs the `.env`
from a failing run.

Which is why the step now prints, on failure, the link log (fake key redacted)
and the `.env` reduced to variable names plus whether each points at this run's
gateway. No values. **A check that fails leaving nothing to diagnose with is the
defect class this entire audit chain is about, applied to the harness's own
failure path.**

Severity: this is a HARNESS reliability defect, not a product defect, on the
evidence available. It is recorded rather than dismissed because "it passed the
second time" is exactly the reasoning that should not be accepted here.
