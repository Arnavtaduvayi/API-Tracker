# Handoff to the next independent auditor

You are being asked to break this, not to confirm it. This page exists to make
that cheap: every claim below names the file, the command, and the control that
would expose it if the claim were false.

```text
Remediated branch: feat/zero-friction-api-tracking
PR:                #16 (OPEN, unmerged, base main)
Previous audit:    docs/activity-onboarding/audit/fable-final-reaudit-20260727/
                   (audited head 4a89ced; branch audit/fable-zft-final-20260727 @ 083d885)
```

**A fresh independent audit is still required.** Nothing in this remediation was
independently verified. The previous auditor's artifacts were not modified.

---

## Read this first: where I think I am weakest

Ordered by how likely I think you are to find something.

1. **The sealed Git directory is a new, security-critical component that
   nobody has attacked yet.** `crates/core/src/gitseal.rs` decides what of a
   repository to reproduce and what to refuse. I chose an allowlist of
   `extensions.*` keys and a set of bounds. If you can make sealing produce a
   directory that Git treats as the *repository's own* — or make it read a file
   outside the repository, or make a refusal fall back to an unsealed read —
   that is a real finding. Start at `read_format`, `write_alternates` and
   `copy_tree_bounded`.
2. **`config_get` still reads the real configuration** (`gitrepo.rs`). It is the
   one documented exception. I argue `git config --get` runs no hook, filter,
   driver or verifier. If that is wrong on any Git version, RA-001 is back on a
   narrower path.
3. **The RA-004 mutation control still does not kill on the single mutation
   the brief asked for**, and I have not made it. Moving `trap cleanup EXIT`
   back above the guard, alone, still passes, because the ledger-bounded
   `cleanup` finds nothing to do. Reverting **both** layers destroys the decoy
   plist. That negative result is unchanged; what changed is that it is now
   **re-runnable** — the harness it came from was never committed (`REM-006`),
   which meant the strongest safety claim in the previous remediation rested
   on output nobody could regenerate. Run
   `bash scripts/service_cleanup_safety.sh` and judge the design for yourself:
   two independently sufficient layers, or a test that should be able to see
   each one.
4. **The RA-002 assertion is now a floor, not an equality.** I chose that
   deliberately over flakiness (the gateway writer commits per batch on a 250 ms
   timeout, so a legitimate observation can land during the control). A floor is
   weaker. Check whether a real regression can hide under it.
5. **`--scope full --foreground` results below were produced on one machine,
   by me.** Treat a single passing run with the suspicion it deserves.
6. **`--scope full --require-service` now passes — for the first time
   anywhere — but only three runs of it have ever existed.** It runs on a
   disposable hosted macOS runner on every PR and reports 63/63
   (run `30325704492`; `SERVICE_VALIDATION_EVIDENCE.md`). Every one of its
   first three executions found a harness defect (`REM-003`, `REM-004`,
   `REM-005`), which is the correct prior for how much a newly-exercised path
   should be trusted. Assume there is a fourth.

   The defect class those three share is worth attacking directly: **a check
   that has never executed anywhere is indistinguishable, from the outside,
   from a check that always passes.** The count-equality gate catches a check
   that *stops* running; it cannot catch one that never ran, because the count
   is consistent either way. Look for others — any assertion whose first real
   execution has not happened yet.

**And read `REM-001` in `FINAL_REMEDIATION_EVIDENCE.md` §4b before you run
anything in service mode.** I stopped this machine's live production gateway by
running `--require-service` with `HOME` redirected — the technique the previous
audit used and documented as *stronger* isolation. It is stronger for the
filesystem and provides none at all for launchd, which `launchctl` addresses as
`gui/<uid>` regardless of `$HOME`. The interlock now covers both. Shim
`launchctl` anyway.

---

## 1. Git signature-verifier execution (`RA-001`, CRITICAL)

**Reproduce the original defect first**, so you know your fixture is real:

```bash
git worktree add /tmp/at-4a89ced 4a89ced
bash docs/activity-onboarding/audit/fable-final-reaudit-20260727/repro/repro_git_config_rce.sh
```

Expect `*** EXECUTED ***` on `log -p --all` and `log -p -n 5`. If you do not see
it, your Git build does not honour the vector and nothing below proves anything.

**Then attack the remediation:**

```bash
cargo test -p api-tracker-core --test git_isolation_canaries -- --nocapture
cargo test -p api-tracker-core --test git_execution_canaries
```

What to attack specifically:

* `sealing_alone_closes_every_vector` runs the product's argv against a sealed
  directory with **no `-c` overrides**. If you can make a vector fire there, the
  structural claim is false and the enumeration is doing the work.
* `every_reachable_vector_is_armed` must fail if a canary goes inert. Try
  breaking a fixture and confirm the suite notices.
* Five vectors are declared *unreachable* with measured reasons
  (`diff.external`, named diff-driver `command`, hooks, filters, pager, editor,
  credential helper). I measured `diff.external` as firing only for a bare
  working-tree `git diff`, which the product never runs. Verify that on your Git.
* Try a repository shape I did not: reftable, sha256, a linked worktree, a
  submodule, `clone --shared`, a shallow clone, 20 000 loose refs, a symlinked
  `HEAD`/`config`/ref, `extensions.partialClone`.

**The end-to-end chain** (the one that decided the previous verdict) is
`the_background_monitor_path_is_clean_after_head_advances`: baseline scan, the
attacker pushes a signature-shaped commit, `HEAD` advances, the incremental
range scan runs. The audit's own `repro/scanner_rce.rs` drives the same chain
through `vault.create_project` + `vault.scan_repos_incremental`; port it and run
it.

## 2. Background monitoring execution (`RA-001`, the automatic path)

The chain is `App.tsx` timer → `monitor_run_full` → `vault.run_monitor_cycle` →
`vault.scan_repos_incremental` → `gitrepo::head_commit` and
`gitrepo::range_added_units`. Both now seal. Confirm there is no *other* Git
spawn: two `Command::new` sites exist for `git` in the whole workspace
(`gitrepo.rs`), and `crates/tracking/**` spawns nothing except service verbs.

```bash
grep -rn "Command::new" crates apps --include=*.rs | grep -v tests
```

## 3. Full packaged validation (`RA-002`, `RA-003`)

```bash
bash scripts/tracking_validate_macos.sh --scope selfcheck
bash scripts/tracking_validate_macos.sh --help
bash scripts/validation_harness_mutants.sh
bash scripts/tracking_validate_macos.sh --scope offline  <app>
bash scripts/tracking_validate_macos.sh --scope full     <app>
bash scripts/tracking_validate_macos.sh --scope full --require-service <app>
```

Counts are no longer typed anywhere: `group_size()` declares one number per
group and `expected_total()` sums them. `enumerate_checks()` re-derives the same
totals from the source and `verify_check_inventory()` compares them, inside the
HARNESS group, so CI's `--scope selfcheck` gates on it.

Attack the enumerator. It is fail-closed by design (a check inside a loop, a
runtime branch emitting different counts, an unknown invocation shape are errors
rather than guesses). Find a shape that makes it **miscount** rather than refuse
and you have a finding.

## 4. Cleanup isolation (`RA-004`)

**Do not run `scripts/gateway_validate_macos.sh` against your real `$HOME`
until you have satisfied yourself about this.** The pre-fix file deletes a
production LaunchAgent and boots the live gateway out of launchd on its own
refusal path — and `bootout` addresses the live `gui/<uid>` domain regardless of
`$HOME`, so a fake HOME alone does not protect you. Shim `launchctl`.

The refusal is now the first thing that runs, before any trap. Verify by
snapshotting a production-like plist's sha256, size, mtime and mode either side
of a refusal, and by asserting `launchctl` was never invoked. Then check the
ownership ledger: cleanup should touch only what this run created, verify process
identity before signalling, never delete a pre-existing file, and be idempotent.

## 5. Future-dated verification (`RA-005`)

```bash
cargo test -p api-tracker-tracking --test verification_clock
```

Port the audit's `repro/verification_future.rs` unchanged — it is reproduced as
the first two tests. Admissibility is three conditions (insertion-ordered
`rowid` watermark, `at >= applied_at`, `at <= now + 300s`). Try to defeat each
in isolation:

* delete the highest observation row so a rowid is reused, then insert;
* back-date a row inserted after the apply;
* sit exactly on the skew boundary;
* make the gateway and the reader disagree by 4 minutes 59 seconds.

`control_the_audited_head_predicate_would_have_accepted_the_future_row` is the
anti-vacuity gate: it asserts the *old* predicate still accepts a year-ahead
timestamp, so the fixture cannot quietly stop producing one.

## 6. Plaintext rollback-secret persistence (`RA-006`)

```bash
cargo test -p api-tracker-gateway --test restore_record_privacy
cargo test -p api-tracker-gateway --test envlink
cargo test -p api-tracker-core --lib envrestore
```

The suite sweeps **raw bytes** of `vault.db`, `-wal` and `-shm` for ten secret
shapes, and `control_the_disk_sweep_can_find_a_planted_needle` proves the sweep
works. Extend it: add your own shape, and add surfaces I did not sweep — a
backup file, the gateway log, a temp file mid-write, a diagnostics bundle.

Then attack the crypto: transplant a ciphertext between variables, files and
links (must fail to open); check the key never crosses the gateway control
socket; check what happens when the vault is locked mid-unlink; check that a v1
plaintext record still restores after upgrade and is re-sealed rather than
deleted.

## 7. All 15 original blockers

`FINAL_REMEDIATION_MATRIX.md` carries the table. Two were reopened by the
previous audit (`ZFT-001` via `RA-001`, `ZFT-006` via `RA-005`) and both routes
are now closed. Re-run the original reproductions rather than trusting the
table — the previous auditor found `ZFT-001` reopened *by a new route*, which is
exactly what a table of "resolved" would have hidden.

---

## 8. The clean-room service lifecycle (`REM-002` … `REM-006`)

**Reproduce this on a machine with NO Tethra installation.** Not a machine you
cleaned — one that never had it. A hosted macOS runner is the cheapest such
machine, and the workflow is committed:
`.github/workflows/packaged-service-macos.yml`.

```bash
bash scripts/ci_service_preconditions.sh     # must pass, or stop. read-only.
bash scripts/bundle_cli.sh
bash scripts/gateway_validate_macos.sh                       # 51 checks
cd apps/desktop && npm ci && npm run tauri build -- --bundles app && cd -
cp -R target/release/bundle/macos/Tethra.app /tmp/packaged/
TETHRA_VALIDATION_RESULTS_JSON=/tmp/results.json \
  bash scripts/tracking_validate_macos.sh --scope full --require-service \
    /tmp/packaged/Tethra.app                                 # 63 checks
bash scripts/ci_assert_service_results.sh /tmp/results.json
bash scripts/ci_service_cleanup_check.sh
```

What to attack specifically:

* **The preconditions are read-only.** Verify that. A precondition script that
  quietly remediates to make itself runnable is `REM-001` in a new costume.
  Give it a machine that fails one precondition and confirm nothing changed.
* **The namespace.** The label is derived by the product, not by the harness.
  Try to make an isolated run produce `dev.api-tracker.gateway` — through a
  symlinked data directory, a path with `..`, a directory that canonicalises
  onto the shared one, `TETHRA_DIR` unset mid-run.
* **The asserter is not a grep for "0 failed".** Point
  `ci_assert_service_results.py` at a `--scope offline` or `--scope selfcheck`
  result and confirm it refuses. Then try to construct a `results.json` it
  accepts for a run that did not install a service.
* **Cleanup.** Kill the script mid-run (`SIGKILL`, not `SIGTERM`, so the trap
  never fires) and see what survives. Then run it again and confirm the stale
  namespace precondition refuses rather than adopting.
* **REM-005's class.** Grep both validation scripts for every conditional that
  gates an assertion on a command's output, and check that the field it greps
  for is one that command actually emits. That is the defect I found; assume
  I did not find all of them.

## 9. Trap ordering and the ownership ledger (`REM-002`)

```bash
bash scripts/service_cleanup_safety.sh
```

11 assertions across both validation scripts, under a fake `$HOME` with a
decoy production plist and a shimmed `launchctl` that records intent and
performs nothing. Shim it yourself too — `bootout` addresses the live
`gui/<uid>` domain regardless of `$HOME`, which is the whole `REM-001` lesson.

Expect: a refusal changes nothing and issues no destructive verb; an owned run
cleans up completely; defeating the ordering layer alone does **not** kill;
defeating both destroys the decoy. If the last one stops killing, the harness
has gone blind and every other line of its output is worthless — check that
first.

## 10. `NetworkClass::Restricted` (`RA-011` follow-up)

```bash
cargo test -p api-tracker-tracking --test origin_trust
```

Resolved as a **reserved** classification with no present-tense product claim:
no code path produces it, `describe` refuses restricted destinations instead
of describing them, and the reservation is pinned by two tests rather than by
a comment. Judge whether keeping the variant is right. The argument for
keeping it is that a single-variant enum makes `Public` unconditional, so
relaxing the destination policy would silently produce a false classification
instead of a compile error — which is exactly `RA-011`. The argument against
is that dead code is dead code. I did not add any cross-crate dependency to
keep it.

---

## What a fresh reviewer must reproduce independently

Use a **fresh session**, a **fresh worktree**, the **exact remote head**, an
**isolated service namespace**, and a machine with **no production Tethra
installation**. Reproduce, in this order:

1. the clean-runner service lifecycle (§8) — end to end, on a clean machine;
2. the launchd-versus-`$HOME` isolation defect (`REM-001`) — confirm a
   `$HOME`-keyed interlock does not protect `gui/<uid>`, with `launchctl`
   shimmed;
3. trap ordering (§9, `P1`) — a refusal must write nothing at all;
4. ownership-ledger cleanup (§9, `P2`/`P5`) — and confirm `P3` still kills, or
   nothing else in that file counts;
5. sealed-Git signature-verifier protection (§1, §2) — including the
   background-monitor path after `HEAD` advances;
6. encrypted rollback values (§6) — with your own canary shapes and surfaces I
   did not sweep;
7. future-observation handling (§5) — attack each of the three admissibility
   conditions in isolation;
8. custom-origin approval (§7 / `origin_trust`) — including `--yes` refusing
   an unapproved custom origin;
9. **all 15 original merge blockers**, by re-running the original
   reproductions rather than trusting `FINAL_REMEDIATION_MATRIX.md`. The
   previous auditor found `ZFT-001` reopened by a *new route*, which a table
   of "resolved" would have hidden;
10. every new remediation finding: `REM-001` … `REM-006`, plus `RA-001` …
    `RA-015`.

A fresh independent audit is still required. Nothing in this remediation was
independently verified, and the previous auditors' artifacts were not
modified.

## Full local validation, as run

Recorded in `FINAL_REMEDIATION_EVIDENCE.md` with exact commands, exact counts,
and anything that did not pass.

## What I did not do

* I did not merge PR #16, and did not mark it ready.
* I did not modify the previous audit's artifacts.
* I did not redesign the zero-friction workflow.
* I did not run `scripts/gateway_validate_macos.sh` against the real `$HOME`.
  It now runs in CI, on a clean disposable runner, which is where it belongs —
  and where the previous handoff's identically-worded gap is finally closed.
* I did not merge PR #16 and I make no claim about merge readiness. That
  decision is the fresh independent audit's.
* I did not independently re-audit my own work. That is your job, and the reason
  this page leads with where I think I am weakest rather than with a summary of
  what passed.
