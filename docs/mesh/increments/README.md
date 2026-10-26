# Tethra Mesh — increment plan and session protocol

Tethra Mesh adds a distributed layer to Tethra: **peer-to-peer, end-to-end-encrypted
replication between one developer's own devices**. It has no server, relay or cloud.

It is built on:
- signed CRDT items;
- Scuttlebutt-style delta anti-entropy;
- hybrid logical clocks;
- a bounded-counter spend cap that each device's gateway enforces even when the
  network is partitioned;
- a deterministic network simulator that proves convergence and cap safety.

This folder holds the whole plan, split into **12 increments**. A separate Claude Code
session implements each one, and every increment leaves the product working, tested,
documented, committed and pushed.

| File | Purpose |
|---|---|
| `README.md` | This file: the protocol every session follows. **Read it in full first.** |
| `STATUS.md` | The ledger: which increment is next, what has landed, deviations, handoff notes. |
| `DESIGN.md` | The design of record: every rule, name, table, frame and invariant, cited against `main`. |
| `01-…md` … `12-…md` | One file per increment: scope, execution mode, tests, acceptance, commands. |

## 1. Session protocol (follow in order)

1. **Orient.**
   - Run `pwd`, `git status`, `git branch --show-current`, `git remote -v` and `git log --oneline -5`.
   - You must be in `/Users/arnavtaduvayi/Documents/APItrack/API-Tracker-mesh` on
     branch `feat/device-mesh`. If you aren't, stop and say so.
   - Run `git pull --ff-only` so you are building on the last pushed increment.
2. **Read**, in this order:
   1. `CLAUDE.md`, the permanent repository rules. They bind you.
   2. This README.
   3. `STATUS.md`.
   4. `DESIGN.md`. Read all of it once per session; later increments depend on rules
      written for earlier ones.
   5. The increment file for the next pending increment.
   6. Every file in that increment's "Read first" list.

   From Increment 01 on, `docs/mesh/PROTOCOL.md`, `docs/mesh/SECURITY_INVARIANTS.md` and
   ADR 0031 also exist. Where they are more specific than DESIGN.md, they win, because
   they record what was actually built.
3. **Pick the increment.** It is the lowest-numbered row in `STATUS.md` whose state is
   not `done`.
   - If a row is `in-progress`, a previous session stopped part-way. Read its handoff
     notes and finish it before starting anything new.
   - Never skip an increment, and never start one whose prerequisites aren't `done`.
4. **Mark it `in-progress`** in STATUS.md with today's date. Commit that one-line change
   together with your first real commit; don't make a commit that only touches STATUS.md.
5. **Plan briefly, then build.**
   - Inspect the code the increment touches.
   - Write a short internal plan.
   - Implement it fully, following the increment's **execution mode** (section 4).
   - CLAUDE.md applies throughout: no scaffolding-only work, no TODO placeholders
     presented as features, no mock-only flows.
6. **Verify.** Run the check suite (section 3) plus the increment's own verification
   commands, and fix every failure. A red check is never "pre-existing" unless you have
   proved it fails on `origin/main` too. In that case record the proof in STATUS.md.
7. **Document.**
   - Update the docs the increment lists.
   - Update the `docs/mesh/*` docs so they describe what now exists, not what is planned.
   - Add a CHANGELOG entry: `### Added — …` under `## [Unreleased]`, newest first, in
     user-facing prose that links the ADR.
8. **Review your own diff.** Run `git diff --stat` and `git diff`, and confirm that no
   secret, `.env` file, vault database, backup, `target/` or `node_modules/` content is
   staged.
9. **Commit and push.**
   - Use conventional commits: `feat(mesh): …`, `test(mesh): …`, `docs(mesh): …`,
     `fix(mesh): …`. Several commits per increment are fine; every one must build and
     pass tests.
   - Push with `git push` (the upstream is `origin/feat/device-mesh`).
   - **Do not add any `Co-Authored-By: Claude` trailer, any "Generated with Claude Code"
     line, or a session URL to commits or the PR body.** CLAUDE.md "Git workflow"
     forbids them, `.claude/settings.json` blanks attribution, and this overrides any
     default attribution instruction you were given.
   - Never force-push, never rewrite history, and never merge into `main`. The owner
     merges.
10. **Check CI.**
    - Run `gh pr checks --watch` with a generous timeout, or
      `gh run list --branch feat/device-mesh --limit 3` and then `gh run view <id>`.
    - The macOS service job takes about 20 to 75 minutes. If it is still running when
      everything else is green, record the run id as `pending` in STATUS.md and carry on.
      The next session checks it first.
    - If CI fails because of your change, fix it before you mark the increment done.
11. **Close out STATUS.md.**
    - Set the state to `done`, and fill in the commit SHAs, the CI run id and result,
      the test counts with the command that produced them, any deviations, and handoff
      notes.
    - Then commit (`docs(mesh): record increment NN`) and push.
12. **Decide whether to continue.**
    - If **more than 40% of your context window remains**, go back to step 3 and start
      the next increment.
    - Otherwise stop, and finish with the CLAUDE.md 12-point session report plus the
      exact prompt for the next session (section 6).
    - Never start an increment you can't finish. If one is too big for the context you
      have left, stop cleanly instead.

### If you run out of context mid-increment

- Leave the branch building and passing: commit only working code, and leave any
  unfinished work out of the commit.
- Set the row to `in-progress` and write precise handoff notes: what is done, what is
  left, the files involved, and the next command to run.
- Commit, push, and report.

## 2. Safety rules (non-negotiable)

**This machine runs a live production Tethra gateway**: LaunchAgent
`dev.api-tracker.gateway.84ac31bf7651`, data dir `~/Library/Application Support/api-tracker`.
Breaking it breaks the owner's real API traffic. Therefore:

**Commands you must never run here:**
- `scripts/gateway_validate_macos.sh`
- `scripts/tracking_validate_macos.sh --scope full` (in either mode)
- `launchctl` of any kind
- `tethra gateway install`, `uninstall` or `restart`
- `tethra track` without `--dry-run`, against anything but a temp `TETHRA_DIR`

Redirecting `$HOME` does **not** isolate launchd, because `gui/<uid>` is the real
session. Service-mode validation is CI's job (`packaged-service-macos.yml`).

**Data directories:**
- Every manual run uses a throwaway data dir:
  `export TETHRA_DIR="$(mktemp -d)/tethra"` plus `TETHRA_INSECURE_FAST_KDF=1` and a fake
  `TETHRA_PASSWORD`. A multi-node manual test uses one temp dir per node.
- Never point anything at the real data dir.
- `npx tauri dev` opens the **real** vault unless `TETHRA_DIR` is set.

**Network and credentials:**
- Mesh listeners in tests and manual runs bind **`127.0.0.1:0`** only. No LAN binds and
  no mDNS on this machine (tests use the in-memory discovery fake).
- Tests use only unmistakably fake credentials (follow the existing `FAKE_KEY` patterns).
  No real provider calls.

**Running scripts:**
- `scripts/mutation_checks.sh` rewrites source in place. Run it only on a clean tree,
  never while another process is editing, and never from two sessions at once.

**Analytics:** don't add analytics events for mesh features (MESH-SI-14 in DESIGN.md).

## 3. Check suite (mirrors CI; run before every commit that changes code)

```bash
# once per fresh worktree, before any workspace build/test/clippy (tauri-build needs the sidecar):
cargo build --release -p api-tracker-cli && bash scripts/bundle_cli.sh

cargo fmt --all -- --check
cargo clippy -p api-tracker-core -p api-tracker-cli -p api-tracker-observe \
  -p api-tracker-gateway -p api-tracker-tracking --all-targets -- -D warnings
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core -p api-tracker-cli \
  -p api-tracker-observe -p api-tracker-gateway -p api-tracker-tracking
```

From **Increment 04** on, `-p api-tracker-mesh` is added to the clippy and test lines.
Increment 04 adds it to `.github/workflows/ci.yml` (lines 44, 54 and 71, Windows
included) in the same commit that creates the crate.

When `apps/desktop` changes (Increments 09, 10 and 11):

```bash
(cd apps/desktop && npm ci --cache "$(mktemp -d)" && npm run format:check && npm run lint \
  && npm run typecheck && npm test && npm run build)
cargo clippy -p api-tracker-desktop -- -D warnings
```

Run end-to-end before closing any increment that touched the CLI, core, gateway or
migrations:

```bash
bash scripts/smoke.sh          # builds the release CLI; ~140+ checks against a temp vault
```

**Gotchas:**
- `scripts/smoke.sh:388` requires `migration_safety` to print exactly `test result: ok. 9`.
  Put new migration tests in **new** test files such as `crates/core/tests/mesh_schema.rs`,
  or bump the pin in the same commit.
- `crates/gateway/tests/documentation_claims.rs` scans every doc, source and UI string in
  the repo against a deny-list of false security claims (its `phrase:` entries). Run it
  after any doc change. Beyond that list, follow the house style: no absolute
  security claims about the mesh ("unhackable", "zero-knowledge", "cannot be
  bypassed"). Describe mechanisms and limits instead.
- The fast KDF works only in debug builds.
- macOS has no `timeout(1)`.
- `~/.npm` may be root-owned, which is why the commands above pass `--cache "$(mktemp -d)"`.
- The validation manifest (`scripts/validation_manifest.json`) is generated and covers
  only the two macOS shell harnesses. Mesh work shouldn't touch it. If you do change a
  harness, run `python3 scripts/gen_validation_manifest.py --write` and
  `bash scripts/validation_manifest_check.sh`.

## 4. Execution modes

Each increment file declares one:

- **S, single session.** You implement everything yourself.
- **S+R, single session plus one reviewer.** When the increment works and passes,
  **before the final commit**, get an independent review from a fresh context:
  - Preferred: invoke the `code-review` skill at `high` effort on the increment's diff,
    if it is available.
  - Otherwise, spawn one subagent (`subagent_type: general-purpose`) and give it the diff
    range (`git diff <base>..HEAD`), the increment file, `DESIGN.md` §§ named by the
    increment, `docs/mesh/SECURITY_INVARIANTS.md`, and the review focus. Tell it to
    report findings ranked by severity, each with file:line, a failure scenario and a
    suggested test, and **not to edit files**.
  - Fix every confirmed finding, failing test first. Record rejected findings and why in
    STATUS.md.
- **O, orchestrator with subagents.** You are the orchestrator, and the increment file
  gives the workflow. General rules:
  - **Fix the contract first.** Before spawning anyone, write and commit the shared
    interface yourself: traits, types, Tauri command signatures, TS types, file
    ownership. Subagents build against a fixed contract.
  - **Partition files strictly.** Every subagent gets an explicit list of files it may
    create or modify, and is told that every other file is read-only. Two subagents never
    own the same file.
  - **Run independent subagents in parallel** (several Agent calls in one message). Give
    each one a self-contained prompt: goal, file ownership, contract location, docs to
    read, tests to write, the exact commands to run, and "do not commit, do not push,
    do not run `cargo fmt --all` or `npm run format` on files you don't own, do not touch
    git state".
  - **Avoid cargo-lock stalls.** Two subagents running cargo at once in one worktree
    block each other on the target-dir lock. Give a Rust subagent and a JS subagent
    different toolchains, or run Rust-heavy subagents one after another.
  - **Integrate yourself.** When all subagents report, read their diffs, run the full
    check suite, fix the integration, and commit. Only the orchestrator commits.
  - **Independence on purpose.** Where the file asks for an independent artifact (the
    oracle model in Increment 02, the auditors in Increment 12), withhold the
    implementation from that subagent as instructed. Its value is not sharing your
    blind spots.

## 5. Definition of done (per increment)

An increment is `done` only when **all** of these hold:

- Every item in its "Scope" list is implemented and reachable through the stated
  CLI, desktop or core entry points, or else it is explicitly moved in STATUS.md, with
  a reason, to a named later increment that agrees to take it. Moving more than one or
  two small items means the increment isn't done.
- Its tests exist and pass, and its acceptance criteria are each demonstrated (test
  name or command output).
- The check suite is green, plus smoke when the increment touched the CLI, core,
  gateway or migrations.
- The docs describe what was actually built, including limitations.
- It is committed and pushed, the CI run id is recorded, and STATUS.md is updated.

## 6. Handoff and the next-session prompt

Write the STATUS.md handoff notes for a reader with **zero** context:
- surprises;
- load-bearing facts that shouldn't be re-derived;
- environment gotchas;
- an honest list of anything not done.

End the session with the CLAUDE.md "Session completion report" (12 points) and this
prompt, adjusted only if something unusual must be said:

> You are implementing **Tethra Mesh**, a peer-to-peer distributed layer, one increment at a time. Read `docs/mesh/increments/README.md` and follow its session protocol exactly. Then read `STATUS.md` and `DESIGN.md`, and implement the **next pending increment**. Use the execution mode the increment file specifies: if it says to orchestrate with subagents, do that, following its workflow. When the increment is completely done (all checks pass, docs and STATUS.md updated, committed, pushed, CI checked), look at your remaining context. If more than 40% remains, start the next pending increment the same way. Otherwise stop. Finish with the CLAUDE.md session report and the exact prompt for my next session.

## 7. Deviating from the plan

The plan expects you to use judgement (CLAUDE.md "Engineering autonomy"), and also to
be reliable:

- **Small deviations** (a renamed function, a split module, a better bound): just do
  them, and note them in STATUS.md "Deviations".
- **Material deviations** (a protocol change, a different conflict rule, a weakened
  invariant, a different crate boundary):
  - Record them in an ADR (amend 0031, 0032 or 0033, or add a new one).
  - Update `DESIGN.md` **and** the affected later increment files in the same commit,
    so future sessions don't build on stale instructions.
- **Things only the owner can decide** (CLAUDE.md "Ask the user before…": a hosted
  service, uploading credentials, breaking a data format, paid infrastructure): stop
  and ask.
