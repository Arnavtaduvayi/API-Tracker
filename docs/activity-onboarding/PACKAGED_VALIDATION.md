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
`total == expected` for the scope it ran. A foreground run therefore cannot
be mistaken for, or quoted as, a service run — which is precisely what
`ZFT-VAL-4` described, where both modes reported 42.

| Scope | Checks | Groups | Runs in CI? |
|---|---|---|---|
| `--scope selfcheck` | **5** | HARNESS 5 | **yes** |
| `--scope offline` | **20** | HARNESS 5 · BUNDLE 5 · FIXTURE 3 · DRYRUN 6 · OFFLINE 1 | **yes** |
| `--scope full --foreground` | **57** | + APPLY 9 · NEGATIVE 8 · TRAFFIC 5 · PRIVACY 5 · IDEMPOTENCE 4 · UNDO 4 · FOREGROUND 3 | no |
| `--scope full --require-service` | **60** | as above, minus FOREGROUND 3, plus SERVICE 5 | no |

### Measured on this machine (macOS 25.5.0, aarch64)

```text
$ bash scripts/tracking_validate_macos.sh --scope selfcheck
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
   **failure**;
2. `validation_harness_mutants.sh` — and prove that gate is not itself
   decorative: seven mutants that weaken the harness into "always ok",
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
