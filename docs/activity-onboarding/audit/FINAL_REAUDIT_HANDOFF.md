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
3. **The RA-004 mutation control does not kill on the single mutation the brief
   asked for.** Moving `trap cleanup EXIT` back above the guard, alone, still
   passes, because the ledger-bounded `cleanup` finds nothing to do. I report
   this as a negative result rather than dressing it up. Reverting **both**
   layers fails, and so does the real pre-fix file. Judge whether two
   independent layers each of which is individually sufficient is the right
   design, or whether the test should be able to see each one.
4. **The RA-002 assertion is now a floor, not an equality.** I chose that
   deliberately over flakiness (the gateway writer commits per batch on a 250 ms
   timeout, so a legitimate observation can land during the control). A floor is
   weaker. Check whether a real regression can hide under it.
5. **`--scope full` results below were produced on one machine, by me**, and
   that scope had never completed anywhere before this work. Treat a single
   passing run with the suspicion it deserves.
6. **`--scope full --require-service` has never been observed passing, here or
   anywhere.** `RA-003`'s structural defect is fixed (it reaches the count gate
   and reports `59/59`), but the scope's own precondition — a machine with no
   installed Tethra gateway — is not met on this one. Running it here is how I
   found `REM-001`, below. If your machine is clean, this is the single most
   valuable thing you can run that I could not.

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

## Full local validation, as run

Recorded in `FINAL_REMEDIATION_EVIDENCE.md` with exact commands, exact counts,
and anything that did not pass.

## What I did not do

* I did not merge PR #16, and did not mark it ready.
* I did not modify the previous audit's artifacts.
* I did not redesign the zero-friction workflow.
* I did not run `scripts/gateway_validate_macos.sh` against the real `$HOME`.
* I did not independently re-audit my own work. That is your job, and the reason
  this page leads with where I think I am weakest rather than with a summary of
  what passed.
