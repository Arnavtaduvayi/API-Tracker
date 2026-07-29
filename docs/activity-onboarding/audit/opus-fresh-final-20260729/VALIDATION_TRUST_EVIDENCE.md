# Validation trust — independent evidence

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b` (PR #16, OPEN, unmerged).
Everything below was executed by this audit unless marked *(source only)*.

## 1. What actually gates a packaged run

There are **two** harnesses, and the remediation's headline numbers come from
different ones. Deriving them myself:

| Script | Scope | Total | Gate | Externally validated? |
| --- | --- | --- | --- | --- |
| `scripts/tracking_validate_macos.sh` | `full:service` | **63** | per-group equality + register | **Yes** — `ci_assert_service_results.py` vs `validation_manifest.json` |
| `scripts/gateway_validate_macos.sh` | service lifecycle | **57** (50 required + 7 optional) | `REQUIRED_CHECKS=50` equality | **No** — self-certifying, exit code only |

Counted directly from the exact-head CI artifact
(run `30413771190`, job `90455634358`):

```
gateway-lifecycle.log:  PASS lines = 57   FAIL lines = 0
service-lifecycle.log:  PASS lines = 63   FAIL lines = 0
results.json:           executed_total = 63, failed = 0, checks[] length = 63
```

The remediation's "Service scope 63/63" is the tracking harness; "Packaged
macOS 57/57" is the gateway harness. Both numbers are real; the labelling
collides and is easy to misread.

### Commit identity of the evidence

`results.json` stamps `commit = 3e28380f2caac8fb0f463c3c50eb40c0ec08aecc`,
which is **not** the PR head. It is `refs/pull/16/merge`. Verified:

```
$ git log -1 --format='%H parents: %P' refs/pull/16/merge
3e28380f…  parents: 0e6764ba…(main)  0c3b7d6f…(PR head)

$ git diff --stat refs/pull/16/merge 0c3b7d6f…
(empty — the merge tree is byte-identical to the PR head tree)
```

So the evidence *is* about the exact audited code. The workflow deliberately
passes `github.sha` (the merge commit) rather than the PR head, and
`packaged-service-macos.yml:170-177` documents why. **This is correct, not a
defect** — REM (`141152d`) fixed it in the right direction.

## 2. Forgery resistance — my own suite

I wrote an independent suite (`repro/forge_results_json.py`) using the **real
exact-head CI artifact** as the base document, then mutated it 30 ways. Every
mutation must be rejected.

```
OK    CONTROL genuine artifact is accepted                                rc=0  ACCEPTED
OK    1  correct count but every check ID is wrong                        rc=1  rejected
OK    2  one required SERVICE check replaced by an unrelated passing one  rc=1  rejected
LEAK  2b one APPLY check replaced by an unrelated passing one             rc=0  ACCEPTED
OK    3  duplicate check IDs (one row cloned over another)                rc=1  rejected
OK    4  unknown check ID appended                                        rc=1  rejected
OK    5  a required SERVICE check removed entirely                        rc=1  rejected
OK    6  a required check marked skipped                                  rc=1  rejected
OK    7  a required check downgraded to informational                     rc=1  rejected
OK    8  offline-scope result filed as full:service                       rc=1  rejected
OK    9  foreground-mode result filed as service                          rc=1  rejected
OK    10 results from a different commit                                  rc=1  rejected
OK    11 the run installed the PRODUCTION service label                   rc=1  rejected
OK    11b service label is not a gateway label at all                     rc=1  rejected
OK    11c service label has an empty installation id                      rc=1  rejected
OK    12 a genuine but STALE artifact from an earlier commit              rc=1  rejected
OK    13 a real offline:none result substituted wholesale                 rc=1  rejected
OK    14 empty results file                                               rc=1  rejected
OK    14b whitespace-only results file                                    rc=1  rejected
OK    15 truncated JSON (process killed mid-write)                        rc=1  rejected
OK    16 twelve-line forgery declaring its own zero criteria              rc=1  rejected
OK    16b forged all-green with a plausible self-declared total           rc=1  rejected
OK    17 the service was NOT created by this run                          rc=1  rejected
OK    17b the required fact is absent entirely                            rc=1  rejected
OK    18 a group borrows rows from another (totals still 63)              rc=1  rejected
OK    19 verdict PASS while a check failed                                rc=1  rejected
OK    19b failed count non-zero                                           rc=1  rejected
OK    20 wrong schema version                                             rc=1  rejected
OK    20b results file is a JSON array, not an object                     rc=1  rejected
OK    20c whole group missing from the breakdown                          rc=1  rejected

FORGERY SUITE FAILED: 1 case(s) behaved wrongly
```

**29 of 30 vectors rejected.** The VAL-01 rewrite is genuine: a results file
can no longer define its own acceptance criteria, and every one of the
brief's enumerated forgery classes is refused — *except one*.

### The one leak: `VAL-05-R` (identity binding stops at the SERVICE group)

`validation_manifest.json` binds check **identities** only for the `SERVICE`
group (9 prefixes, one-to-one, leftovers rejected — `ci_assert_service_results.py:276-297`).
The other ten groups — `HARNESS 5, BUNDLE 5, FIXTURE 3, DRYRUN 6, APPLY 9,
NEGATIVE 8, TRAFFIC 5, PRIVACY 5, IDEMPOTENCE 4, UNDO 4` = **54 of 63
checks** — are bound by **count only** (`required_checks: {}` for every other
scope, too: `full:foreground` binds 0 of 57, `offline:none` 0 of 20).

Case 2b renamed one `APPLY` check and the validator emitted:

```
  OK    group APPLY        9/9 executed, 0 failed
  OK    register: 63 named checks, 0 not passed
=== SERVICE SCOPE COMPLETED: 63/63 required checks passed in full:service ===
```

**What still protects those 54 checks** (this is not nothing):

* `enumerate_checks()` (`tracking_validate_macos.sh:235+`) reads the script's
  own source, attributes every call site to its group, resolves `$SCOPE`/`$MODE`
  guards, requires sibling branches to emit equal counts, and is fail-closed.
  A check that *stops running* is caught.
* The register rejects duplicates, skips, and `informational` substitution.
* `validation_manifest_check.sh` re-derives the manifest counts from the
  harness and additionally proves all nine SERVICE prefixes are real call
  sites (**37 passed, 0 failed** — executed).

**What is not protected:** a required check *swapped* for a different one
inside the same group. That needs a one-file edit to the harness; the manifest
does not change; every gate stays green. Code review is the only control.

Approval criterion 1 ("exact check identities, not only counts") is therefore
**met for 9 of 63 checks in the service scope and 0 of 57 in the packaged
scope**. The remediation discloses this honestly in
`NEXT_INDEPENDENT_REAUDIT_HANDOFF.md:38-68`; I confirm it empirically.

## 3. `REQUIRED_CHECKS=50` — the handoff's dare

The gateway harness has no enumerator; `50` was derived from one measured run.
I checked the decomposition against the source (`repro/enumerate_gateway_checks.py`)
and against the exact-head CI log.

All `opt_ok`/`opt_bad` sites — the only environment-dependent ones — are:

* `gateway_validate_macos.sh:517` — `node` presence → **1** check
* `:683-702` — the repair staging block → **5** checks when taken, **1** when
  there is no installed helper to damage
* `:725` — the port re-check → **1** check

CI measured `optional 7` = 1 + 5 + 1. `57 − 7 = 50`. **The constant is
consistent with the source and with the measured run.**

Caveat I could not close: a full static re-derivation needs a parser of the
enumerator's calibre, which this script does not have. If a required check
were added or removed, the gate fails *closed* (annoying, safe). The dangerous
shape — a runtime conditional whose two branches emit *different* checks with
the same count — is not detectable here, and unlike the tracking harness there
is no enumerator to forbid it. That is `VAL-05`'s residue restated for the
second script, plus `VAL-04`'s: **`gateway_validate_macos.sh` has no mutation
suite and no machine-readable result.**

## 4. VAL-04 — negative controls actually call the primitives

The handoff dares: *"neuter `assert_db` and `assert_status` in a copy and
confirm the controls fail. If they do not, VAL-04 is not fixed."*

I extracted the **genuine** primitive definitions verbatim from the audited
script (not a re-implementation) and drove the real control block
(`repro/probe_primitive_mutation.sh`). No service, no launchd, throwaway
sqlite only.

```
=== M0: GENUINE primitives (controls must report PASS) ===
CONTROL_RESULT=PASS
STATUS_CONTROL_RESULT=PASS

=== M1: assert_db neutered to always ok() ===
CONTROL_RESULT=FAIL ( false-query:pass empty-query:pass erroring-query:pass)

=== M2: assert_db accepts ANY result ===
CONTROL_RESULT=FAIL ( false-query:pass empty-query:pass erroring-query:pass)

=== M3: assert_status neutered to always ok() ===
STATUS_CONTROL_RESULT=FAIL (observed: pass)

=== M4: probe_primitive runs the fn in a SUBSHELL (the corrected defect) ===
CONTROL_RESULT=FAIL ( false-query:malformed(+0p/+0f) … )
STATUS_CONTROL_RESULT=FAIL (observed: malformed(+0p/+0f))
```

**VAL-04 is genuinely fixed.** M4 is the important one: it reintroduces
REM-002 (the control that ran in a subshell and therefore observed nothing)
and the probe reports the exact `malformed(+0p/+0f)` signature that would have
caught it. The regression is structurally covered, not merely argued.

The exact-head CI log also shows these three controls executing for real:

```
== 30. Negative controls: prove the assertions can FAIL ==
  PASS  assert_db itself rejects false, empty and erroring queries, and accepts a true one
  PASS  assert_status itself rejects a stopped gateway (an empty response is a failure)
  PASS  assert_status rejects a property that evaluates false
```

The handoff's "the fix is argued from source; the first CI run on this head is
its first execution" is now superseded — it executed.

## 5. Harness mutation suite (executed)

```
$ bash scripts/validation_harness_mutants.sh
  KILLED  MA — bad() prints PASS and counts a pass
  KILLED  MB — bad() is a silent no-op
  KILLED  MC — check() always calls ok()
  KILLED  MD — assert_db() always passes
  KILLED  ME — assert_same_bytes() always passes
  KILLED  MF — assert_same_bytes() reverts to string equality
  KILLED  MG — the self-check group is deleted outright
  KILLED  MH — selfcheck() is replaced by a bare ok()
=== HARNESS MUTATION RESULT: 8 killed, 0 survived ===
```

`MG` directly answers "can a required check disappear while the suite stays
green?" for the tracking harness: **no** — the count-equality gate catches it.

## 6. Counts derived by this audit (not copied)

| Suite | Claimed | **Derived here** | Result |
| --- | --- | --- | --- |
| Asserter forgery tests | 33 | **33** | 0 failed |
| Manifest consistency | 37 | **37** | 0 failed |
| Harness mutants | 8 | **8** | 0 survived |
| Ownership tests | 29 | **29** | 0 failed (shimmed `launchctl` — see `SERVICE_LIFECYCLE_EVIDENCE.md`) |
| Tracking selfcheck scope | 5 | **5** | 0 failed |
| Gateway lifecycle (CI) | 57 | **57** | 0 failed |
| Tracking `full:service` (CI) | 63 | **63** | 0 failed |
| My independent forgery suite | — | **30** | 29 rejected, **1 leak** |

## 7. Verdict for this area

* Forged, truncated, empty, stale, wrong-scope, wrong-mode, wrong-commit,
  wrong-namespace, offline-substituted and self-defining results are **all
  refused**. The VAL-01 class is closed.
* Every required check I could test **executes, can fail, and tests the
  property it names**; the primitives behind them are mutation-proved.
* A required check **cannot silently disappear** (count equality + enumerator).
* A required check **can be replaced by another** in 54 of 63 service-scope
  checks and in every check of the other scopes. `VAL-05` is real and
  unfixed, exactly as the remediation states.
