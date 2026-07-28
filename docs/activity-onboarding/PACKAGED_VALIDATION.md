# Packaged validation

What is executed against the real `Tethra.app`, where it is executed, and —
stated at least as prominently — what is **not**.

The audit's `ZFT-VAL-1`, `ZFT-VAL-4`, `ZFT-VAL-7`, `ZFT-VAL-8` and
`ZFT-VAL-9` were all one failure: a headline number that did not correspond
to executed assertions. This page is written so that every number on it can
be re-derived by running the command beside it.

Harness: `scripts/tracking_validate_macos.sh`. Its own anti-tautology tests:
`scripts/validation_harness_mutants.sh`.

---

## The scopes, and their exact counts

The totals **differ by construction**, and the script enforces
`total == expected` — per group as well as in total — for the scope it ran. A
foreground run therefore cannot be mistaken for, or quoted as, a service run
— which is precisely what `ZFT-VAL-4` described, where both modes reported 42.

| Scope | Checks | Groups | Runs in CI? |
|---|---|---|---|
| `--scope selfcheck` | **5** | HARNESS 5 | **yes** |
| `--scope offline` | **20** | HARNESS 5 · BUNDLE 5 · FIXTURE 3 · DRYRUN 6 · OFFLINE 1 | **yes** |
| `--scope full --foreground` | **57** | + APPLY 9 · NEGATIVE 8 · TRAFFIC 5 · PRIVACY 5 · IDEMPOTENCE 4 · UNDO 4 · FOREGROUND 3 | no |
| `--scope full --require-service` | **59** | as above, minus FOREGROUND 3, plus SERVICE 5 | no |

> **`--scope full --require-service` has never been observed passing.** The
> structural defect (`RA-003`) is fixed — the run now reaches the count gate and
> reports `59/59` instead of INCONCLUSIVE — but a clean pass needs a machine
> with **no installed Tethra gateway**, which is this mode's own documented
> precondition. Do not quote it as passing until someone runs it somewhere
> clean.
>
> Running it on a machine that *does* have one is how `REM-001` was found: the
> interlock globbed `$HOME/Library/LaunchAgents`, but `launchctl` addresses
> `gui/<uid>`, which `$HOME` does not isolate — so redirecting `HOME` walked
> past the interlock while every `launchctl` call still landed on the live
> service, and it stopped a real production gateway. The interlock now asks
> launchd as well as the filesystem. **Shim `launchctl` anyway if you are
> experimenting with this mode.**

None of those four totals is written down in the script. Each is **summed**
from one number per group, and the group table is **proved against the
script's own source** by `--scope selfcheck` before any check runs: an
enumerator walks the `$SCOPE`/`$MODE` conditionals and reports what each of
the four combinations can actually execute, and a disagreement aborts the run.

That exists because the hand-maintained version of this table was wrong.
`full:service` was declared to run **60** checks while the groups it runs sum
to **59** (`57 − FOREGROUND 3 + SERVICE 5`), so the strongest mode was
unpassable by construction: all 59 of its assertions could pass and the gate
would still print `INCONCLUSIVE` and exit 1. The entry that drifted was the
one nobody can run on a machine that already has Tethra installed, which is
why the check is now mechanical and runs in CI on every PR rather than
depending on a human recounting 59 call sites.

### Measured on this machine (macOS 25.5.0, aarch64)

```text
$ bash scripts/tracking_validate_macos.sh --scope selfcheck
  check inventory (summed from the group table, proved against this file):
    selfcheck:none    5 checks
    offline:none     20 checks
    full:foreground  57 checks
    full:service     59 checks
=== PACKAGED TRACKING VALIDATION (scope=selfcheck, mode=none): 5 passed, 0 failed (5/5 checks) ===

$ bash scripts/tracking_validate_macos.sh --scope offline
    HARNESS        5 checks  (5 passed, 0 failed)
    BUNDLE         5 checks  (5 passed, 0 failed)
    FIXTURE        3 checks  (3 passed, 0 failed)
    DRYRUN         6 checks  (6 passed, 0 failed)
    OFFLINE        1 checks  (1 passed, 0 failed)
    TOTAL         20 checks  (20 passed, 0 failed)

$ bash scripts/validation_harness_mutants.sh
=== HARNESS MUTATION RESULT: 8 killed, 0 survived ===

$ bash scripts/tracking_validate_macos.sh --scope full --foreground
=== PACKAGED TRACKING VALIDATION: ABORTED (a precondition failed) ===
$ echo $?
1
```

The `--scope selfcheck` and mutation lines were re-measured after the
`RA-002` / `RA-003` / `RA-015` repairs below. The `--scope offline` breakdown
is the run recorded earlier on this machine: those five group counts are
unchanged by the repairs, and the enumerator now derives the same 20 from the
script's source on every `--scope selfcheck`, but the offline scope needs a
built `.app` and has not been re-run since.

The abort is the correct outcome **on this machine** and is explained below.
It exits **non-zero**, so a CI job cannot mistake "we refused to run" for a
pass.

---

## Why `--scope full` did not run here

This machine has a Tethra gateway installed and running
(`~/Library/LaunchAgents/dev.api-tracker.gateway.plist`, pid 65270). The
script refuses `--scope full` when **any** Tethra LaunchAgent is present.

Service names are namespaced per data directory now (ADR 0026) and every
destructive verb proves ownership first, so a current helper would hard-stop
rather than damage anything. The interlock exists anyway, for three reasons:

* a **pre-namespacing** helper under test would boot that gateway out of its
  slot — which is exactly what happened during the audit, to this machine;
* a legacy agent pointing at the same data directory would be silently
  migrated by the takeover path;
* a run that succeeds only because the machine happened to be clean is not
  evidence. Awarding a pass for that is the shape `ZFT-VAL-7` objected to,
  so the interlock **aborts** rather than being tallied as a check.

`--scope full` therefore needs a machine with no installed Tethra gateway.
That has not been run for this branch, and nothing on this page claims it
has.

---

## What CI executes

`.github/workflows/ci.yml`, job **`packaged-macos`** (`macos-latest`), on
every PR:

1. `tracking_validate_macos.sh --scope selfcheck` — before anything it
   certifies, prove the harness reports a deliberately-broken control as a
   **failure**, and prove the check inventory still describes the script:
   the four scope+mode totals are enumerated from the source and must match
   the declared group table, for the combinations CI cannot run as well as
   the one it can;
2. `validation_harness_mutants.sh` — and prove that gate is not itself
   decorative: eight mutants that weaken the harness into "always ok",
   including the literal `ZFT-VAL-7` and `ZFT-VAL-10` defects, must each be
   killed;
3. `npm ci`, `scripts/bundle_cli.sh`, `tauri build --bundles app` — a **real
   `.app`**, which is what the validation then inspects;
4. `tracking_validate_macos.sh --scope offline` — 20 required checks;
5. `scripts/smoke.sh`.

Every one of those fails the build.

### What a green CI build does NOT claim

* **LaunchAgent registration.** A hosted runner has no login session to
  register into, and `launchctl bootstrap gui/<uid>` behaves differently
  under Actions than on a desktop, so a green result there would not be
  evidence about the path a real user gets. `--scope offline` starts no
  gateway at all.
* **Traffic observation, verification, privacy-at-rest, undo.** These need a
  running gateway and a real request. They live in `--scope full`, and in
  the in-process suites the `rust` job already runs
  (`crates/tracking/tests/verification_freshness.rs`,
  `crates/gateway/tests/privacy_canaries.rs`,
  `crates/tracking/tests/undo_ground_truth.rs`).
* **Windows and Linux packaging.** Not covered by this harness at all.

The script prints its own `NOT RUN HERE` block for whichever scope it ran,
so the CI log states the boundary rather than relying on this page.

---

## The specific things the audit found unverified

| Finding | What was wrong | What it does now |
|---|---|---|
| `ZFT-VAL-3` | "version-matched helper" was `[ -n "$APP_VER" ]` | the helper is **run** and its `--version` compared to the bundle's `Info.plist` |
| `ZFT-VAL-5` | a variable named `CANARY` was planted, advertised, and never searched for | searched for across the DB, WAL, SHM, logs and desktop storage |
| `ZFT-VAL-7` | 4 of 42 checks were unconditional passes | every unconditional pass removed or replaced; the count-equality gate and the harness mutation suite are the guards |
| `ZFT-VAL-8` | the advertised forged-old-event negative control did not exist | implemented, and its SQL verified against the real schema |
| `ZFT-VAL-9` | the group table summed to 40, not 42 | the table above is printed by the script and the script enforces the sum |
| `ZFT-VAL-10` | "byte for byte" used `[ "$(cat a)" = "$b" ]`, stripping trailing newlines | `cmp(1)` on the real files; a mutant that reverts it is killed |

### What the follow-up audit found in the harness itself

All three were found by running the harness, not by reading it — the first
`--scope full` run that reached the end.

| Finding | What was wrong | What it does now |
|---|---|---|
| `RA-002` | the forged-event control ended by asserting `COUNT(*) FROM runtime_request_events WHERE at < applied_at = 0` — a premise the product's own apply contradicts, because the apply's keyless path check records a **real** gateway observation ~0.3s before `applied_at` is stamped. The forged row was deleted correctly; the assertion failed anyway | the pre-apply population is counted **before** the forgery, and the assertion is the delta: every planted row is gone by id and by session, and the observations the product recorded itself are still there. Verified both ways against a fixture reproducing the measured state |
| `RA-003` | `full:service` was defined to run 60 checks while its groups sum to 59, so the mode could not pass with every assertion green | no per-mode total exists; totals are summed from one number per group, and `--scope selfcheck` enumerates the script and aborts unless the table matches the source. The group counts are enforced individually at the end of a run, so two drifts that cancel out no longer hide in the sum |
| `RA-015` | `--help` printed a fixed `1,89p` slice of a header that had grown to 94 lines, so it dropped the isolation/cleanup disclosure, and its stated totals were stale | the cut point is computed (print until the first non-comment line), and every total it states is one of the four the script enforces |

### The defect found while fixing them

The first version of the anti-tautology guard **did not work**. `ok()` and
`bad()` began with an early return for the self-check mode, so the guard
exercised a code path the real checks never take. Mutating `bad()` into an
unconditional pass — the literal `ZFT-VAL-7` defect — left the harness
reporting *5 passed, 0 failed, exit 0*.

`ok()`/`bad()` are now unconditional, the self-check runs its controls
through the **unmodified** reporting path and reads back both the printed
verdict and the counter deltas, and a mismatch **aborts** rather than being
reported through `bad()` — a weakened `bad()` cannot be trusted to report
its own weakening. `validation_harness_mutants.sh` makes that repeatable:
8 mutants, 8 killed.
