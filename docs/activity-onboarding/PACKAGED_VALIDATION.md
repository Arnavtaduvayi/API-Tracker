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
| `--scope full --require-service` | **63** | as above, minus FOREGROUND 3, plus SERVICE 9 | **yes** |

> **`--scope full --require-service` now passes, on a clean hosted macOS
> runner, and runs on every PR.**
>
> ```text
> Workflow  Packaged macOS service lifecycle   run 30325704492
> Runner    macos-26-arm64, macOS 26.4 (25E246), arm64, session Aqua
> Result    63 passed, 0 failed (63/63) — verdict PASS, 0 skipped
> Label     dev.api-tracker.gateway.39d11f8db375  (namespaced, per data dir)
> Cleanup   verified from outside the script: no residue
> ```
>
> Full record: `audit/SERVICE_VALIDATION_EVIDENCE.md`.
>
> **The history matters and is not rewritten.** Until run `30325704492` this
> scope had never been observed passing anywhere. The structural defect
> (`RA-003`) was fixed first — the run reached the count gate and reported
> `59/59` instead of INCONCLUSIVE — but a clean pass needs a machine with **no
> installed Tethra gateway**, which no developer machine here satisfies. When
> that first real run finally happened it failed 2 of 59: `REM-003` and
> `REM-004`, both checks that had never executed anywhere and one of which
> asserted something the product does not do. SERVICE is 9 checks, not 5,
> because of what fixing them made provable.
>
> Running it on a machine that *does* have a gateway is how `REM-001` was
> found: the interlock globbed `$HOME/Library/LaunchAgents`, but `launchctl`
> addresses `gui/<uid>`, which `$HOME` does not isolate — so redirecting `HOME`
> walked past the interlock while every `launchctl` call still landed on the
> live service, and it stopped a real production gateway. The interlock now
> asks launchd as well as the filesystem, and it runs **before** any cleanup
> trap is armed. **Shim `launchctl` anyway if you are experimenting with this
> mode** — `scripts/service_cleanup_safety.sh` does exactly that, and is the
> executable proof that a refusal is inert.

None of those four totals is written down in the script. Each is **summed**
from one number per group, and the group table is **proved against the
script's own source** by `--scope selfcheck` before any check runs: an
enumerator walks the `$SCOPE`/`$MODE` conditionals and reports what each of
the four combinations can actually execute, and a disagreement aborts the run.

That exists because the hand-maintained version of this table was wrong.
`full:service` was declared to run **60** checks while the groups it ran summed
to **59** (`57 − FOREGROUND 3 + SERVICE 5`), so the strongest mode was
unpassable by construction: all 59 of its assertions could pass and the gate
would still print `INCONCLUSIVE` and exit 1. The entry that drifted was the
one nobody could run on a machine that already has Tethra installed, which is
why the check is now mechanical and runs in CI on every PR rather than
depending on a human recounting call sites.

That mechanism was then exercised for real. `SERVICE` went 5 → 9 when the
first clean-runner execution exposed `REM-003` and `REM-004`, and the total
moved 59 → 63 **without anyone editing a total**: `group_size(SERVICE)`
changed, `expected_total()` re-summed, and the enumerator independently
re-derived 63 by reading the script's own conditionals. A stale expected total
is the failure this design exists to prevent, and the change that would have
produced one is the change that proved it does not.

### Measured on this machine (macOS 25.5.0, aarch64)

```text
$ bash scripts/tracking_validate_macos.sh --scope selfcheck
  check inventory (summed from the group table, proved against this file):
    selfcheck:none    5 checks
    offline:none     20 checks
    full:foreground  57 checks
    full:service     63 checks
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
**It now has one: a fresh hosted macOS runner**, which is disposable, has
never had Tethra on it, and is destroyed after the job. That is the job
`.github/workflows/packaged-service-macos.yml` runs on every PR, and its
results are in `audit/SERVICE_VALIDATION_EVIDENCE.md`.

Nothing on this page claims the scope was ever run on THIS machine. It was
not, it must not be, and the refusal above is the correct outcome here.

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

`.github/workflows/packaged-service-macos.yml`, job **`Packaged macOS service
lifecycle`** (`macos-latest`), also on every PR — this is the one that runs
the **real service**:

1. `ci_service_preconditions.sh` — assert a clean room, read-only, and
   **refuse rather than remediate**. It runs before any toolchain, any build
   and any cleanup registration;
2. `tracking_validate_macos.sh --scope selfcheck` — the anti-tautology gate,
   before a bundle exists, so a broken harness fails in seconds;
3. `bundle_cli.sh`, then `gateway_validate_macos.sh` — **50 required checks,
   enforced as an equality**, plus up to 7 environment-dependent ones (node
   presence, the repair staging block, the port re-check), which are tallied
   separately through `opt_ok`/`opt_bad` and excluded from that equality
   (`VAL-05`) — driving
   install → stop → restart → uninstall against a **real per-user
   LaunchAgent**, before the ten-minute bundle build so a lifecycle failure
   surfaces early;
4. `ci_service_preconditions.sh` again — the clean room must be a clean room
   again between the two real-service runs;
5. `tauri build --bundles app`, then the `.app` is **copied outside the
   repository**, so nothing it needs may resolve relative to the source tree;
6. `tracking_validate_macos.sh --scope full --require-service` — **63
   required checks**;
7. `ci_assert_service_results.sh` — assert the machine-readable result names
   the exact scope and mode, per-group counts, zero failed, zero skipped,
   zero duplicate names, every register row `pass`, and a **namespaced**
   service label. Not `grep "0 failed"`, which a silent downgrade satisfies;
8. `ci_service_cleanup_check.sh` — verify teardown from outside the script,
   after its `EXIT` trap has run;
9. logs and `results.json` uploaded as an artifact.

### What a green CI build does NOT claim

* **The desktop GUI.** Nothing click-drives the React surface.
* **Windows and Linux packaging.** Not covered by this harness at all.
* **Provider acceptance.** Routes point at real origins with fake keys, so a
  `401` proves DNS → gateway → TLS → provider and nothing about a real
  credential.
* **Code signing.** No signing identity exists on a hosted runner; the alpha
  ships unsigned (`docs/PACKAGING.md`).

This list used to begin with "**LaunchAgent registration.** A hosted runner
has no login session to register into…". That was asserted and never
measured, and it is **false** — `launchctl managername` reports `Aqua` on
`macos-26-arm64`, `gui/501` is created by `loginwindow`, bootstrap returns 0
and the agent runs (probe run `30323981718`). The claim retired the strongest
available scope on a premise nobody had checked. It is recorded here rather
than quietly deleted, because a wrong reason for not testing survives longer
than a gap somebody can see.

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

### What the first REAL service run found

`RA-002`, `RA-003` and `RA-015` were found by running the harness at
`--scope full --foreground`. The four below needed something no developer
machine here can provide: a clean room in which `--require-service` can
actually execute. They were found by the first three runs of
`.github/workflows/packaged-service-macos.yml`.

| Finding | What was wrong | What it does now |
|---|---|---|
| `REM-003` | `the installed LaunchAgent runs the bundled helper` grepped the plist for the path inside the `.app`. The plist never contains it: `gateway install` deliberately copies the running CLI to `<data-dir>/bin/tethra-gateway-<version>` so the login item survives the `.app` moving. The check was written blind against a scope nobody could run, and had therefore never executed anywhere | two assertions, each stronger than the one they replace: the plist runs the copy installed inside **this run's** data directory, and that copy is **byte-identical** to the in-bundle helper. Provenance proven, not inferred from a path |
| `REM-004` | the privacy header sweep matched `authorization:` / `Bearer ` inside the installed helper **binary** — a compiled forwarding proxy carries those as its own string constants. In service mode that binary lands inside `$TETHRA_DIR`; foreground mode never produces it | excluded from the header sweep only, and sound *because of* `REM-003`'s fix: the binary is proven byte-identical to the shipped one, so it cannot hold anything captured at runtime. The two per-run needles still sweep that directory |
| `REM-005` | `gateway_validate_macos.sh` gated its attribution assertions on `--json gateway status \| grep '"matching_key_present":true'`. That command emits the **doctor** document, which has never carried that field (it lives on the control-channel status), and is pretty-printed besides. The gate was false on every run for the whole life of the check, so the else-branch reported a permanent COVERAGE GAP and blamed a TTY — while the transcript read `credential-matching key installed` every time. A gate that is always false does not protect an assertion, it deletes it: the `ZFT-VAL-7` shape inverted | the gate is removed. The two assertions are unconditional and are themselves the ground truth about whether the key is resident. push-key's own success line is asserted separately, so a real breakage fails three checks with a readable cause instead of being skipped |
| `REM-006` | the `RA-004` evidence quoted sha256 pairs, a `launchctl` invocation log and a four-row mutation table produced by a harness that **was never committed** — the strongest safety claim in the remediation rested on output nobody could regenerate | `scripts/service_cleanup_safety.sh`, committed. 11 assertions across both validation scripts, and it reports honestly that defeating the trap ordering alone does **not** kill while defeating both layers destroys the decoy plist |

Note what `REM-003` and `REM-005` have in common with `ZFT-VAL-8`, and why
that pattern is worth naming: an assertion that never runs is
indistinguishable, from the outside, from an assertion that always passes.
The count-equality gate catches a check that stops executing; it cannot catch
a check that has never executed anywhere, because the count is consistent
either way. Only running the scope catches that — which is the argument for
this CI job, stated as the thing it actually found.


## The trusted manifest (2026-07-28, `VAL-01`)

The gate that certifies the packaged service scope used to read its own
expectations out of the artifact it was validating. `expected_total`, every
`groups[].expected` and every check name came from the results file, so it
proved internal self-consistency and nothing else — and a twelve-line forgery
declaring zero checks printed
`SERVICE SCOPE COMPLETED: 0/0 checks passed in full:service` and exited 0.

The rule now:

> A result may **report** what it observed. It may not **define** what is
> acceptable.

### Where acceptance comes from

| Source | Carries | Trusted because |
|---|---|---|
| `scripts/validation_manifest.json` | required total, per-group counts, the nine SERVICE checks by name, required provenance facts | committed and reviewed; not produced by the run |
| Workflow arguments | `--scope`, `--mode`, `--commit` | set by `.github/workflows/packaged-service-macos.yml`, not read from the artifact |

The results file additionally carries `commit` and
`service_created_by_this_run`. The second is true only when the run recorded
creating the LaunchAgent in its own ownership ledger — so "a service existed
and was observed" and "this run installed, exercised and removed one" stop
being the same document.

### The number lives in three places, and none can move alone

1. `group_size()` / `scope_groups()` in `tracking_validate_macos.sh` — the
   harness's own declaration.
2. `enumerate_checks()` in the same file — a fail-closed awk enumerator that
   re-reads the script and counts the call sites a scope+mode can actually
   execute. The harness proves (1) against (2) before any check runs.
3. `validation_manifest.json` — what CI enforces.

`scripts/validation_manifest_check.sh` proves (3) against (1), and proves every
check the manifest names by string exists as a real call site.

### The scripts, and what each is for

| Script | Proves | Runs in |
|---|---|---|
| `tracking_validate_macos.sh --scope selfcheck` | the harness reports a deliberately-broken control as a failure | `ci.yml` |
| `validation_harness_mutants.sh` | 8 mutants that weaken the harness into "always ok" are each killed | `ci.yml` |
| `validation_ownership_tests.sh` | cleanup authority comes from the ledger, never a filename pattern (`VAL-02`) | `ci.yml` |
| `validation_manifest_check.sh` | the manifest describes the harness that exists | `ci.yml` |
| `validation_asserter_tests.sh` | the gate accepts exactly one genuine result out of 33 documents | `ci.yml` |
| `ci_assert_service_results.sh` | the service scope completed, against the manifest | `packaged-service-macos.yml` |

### Library mode

`tracking_validate_macos.sh` sourced with `TETHRA_VALIDATE_LIB_ONLY=1` defines
its primitives and returns without acting. That seam exists because the
ownership path — the one bounding a `launchctl bootout` and an `rm -f` — could
otherwise only be reached from `--scope full --mode service`, which cannot run
on a machine carrying a live gateway. A dead field extractor survived there for
months precisely because nothing could reach it locally.

### What is NOT covered

`gateway_validate_macos.sh` has **none** of this apparatus: no inventory, no
register, no per-check IDs, no machine-readable output, no equality gate. Its
enforcement is a floor (45), not a count, and its total is machine-dependent.
See `VAL-05` in
`audit/POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md` — it is recorded as partially
remediated, not as done.
