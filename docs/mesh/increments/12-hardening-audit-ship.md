# Increment 12: Hardening, independent audit and ship

**Mode:** O (orchestrator with parallel auditor subagents, then remediation, then a verification subagent) · **Size:** L · **Prerequisites:** 11 done

## Goal

Make Tethra Mesh ready for the owner to merge:
- stress it (a long soak, adversarial and chaos tests, mutation testing of the critical
  invariants);
- get an **independent multi-agent audit** whose findings are fixed failing-test-first;
- verify the fixes with a fresh agent;
- consolidate the documentation;
- mark the PR ready for review.

This mirrors how previous Tethra milestones were closed: see `docs/activity-onboarding/audit/`
and `docs/remediation*/`.

## Read first

- All of `docs/mesh/*`, ADRs 0031, 0032 and 0033, and STATUS.md, all of it, including
  everything deferred to 12.
- `scripts/mutation_checks.sh` (how mutants are declared, anchors, restore trap, SKIPPED
  counting as a failure) and `scripts/mesh_soak.sh`.
- One previous audit folder for format: `docs/activity-onboarding/audit/` (`FINDINGS_INDEX`, `FINAL_VERDICT`, `findings.json`) and `docs/remediation/` (`evidence/<id>_baseline_fail.log.txt`).

## Execution workflow (O)

### Phase A: hardening (you)

1. **Clear the deferrals.** Finish anything STATUS.md moved to 12, for example the
   desktop credential sharing.
2. **Soak.**
   - `bash scripts/mesh_soak.sh --minutes 30` (all scenarios, release).
   - `bash scripts/mesh_soak.sh --scenario caps --minutes 20`.
   - Record the seeds run and the results. Any failing seed becomes a permanent
     regression test.
3. **Adversarial and chaos additions.** Add whatever isn't already covered, in
   `crates/mesh/tests/adversarial.rs` and the simulator:
   - fuzz-style randomized frames and items (seeded, at least 100k cases) against the
     parsers: no panic, bounded allocation;
   - handshake floods across many source ports;
   - a peer that sends a valid Hello and then stalls;
   - a Commit with an `upto` beyond the items sent (must not advance past what was
     stored);
   - clock-skew poisoning at ±1 year;
   - a removed device reconnecting with old and new access keys;
   - a forked clone racing the original;
   - a restore while a node is running (the node must detect it and stop);
   - SQLite busy storms while the gateway writer is active.
4. **Mutants.** Add these to `scripts/mutation_checks.sh`, each with its anchor and the
   test that must kill it:
   - the VV advanced before commit;
   - signature verification skipped;
   - the drift clamp removed;
   - the removal cutoff ignored;
   - view clamping removed;
   - the escrow fence skipped;
   - the one-in-flight flag never set;
   - the 403 changed to 429;
   - share binding verification skipped;
   - the restore wipe skipped.

   Run them on a clean tree. **All must be KILLED, none SKIPPED.** Record the output.
5. Commit: `test(mesh): soak, adversarial, and mutation hardening`.

### Phase B: independent audit (parallel subagents)

Spawn **four** auditor subagents **in one message** (`subagent_type: general-purpose`).
Each prompt is self-contained:
- the scope below;
- the branch and the base commit `5ec8198`, so `git diff 5ec8198..HEAD -- <paths>`
  works;
- `docs/mesh/SECURITY_INVARIANTS.md`, the relevant ADRs and `DESIGN.md`;
- the instruction: **read-only**. Do not edit, commit or run `mutation_checks.sh`. Tests
  may be run. Never run service-mode scripts or launchctl, because a production gateway
  is live on this machine.
- the report format: findings ranked by severity (critical, high, medium, low), each with
  an id prefix, file:line, the claim, a concrete failure scenario, a proposed failing
  test, and confidence. Plus a list of invariants it checked and found to hold, with
  evidence.

Tell each auditor that it is one of several, and that it must **not** assume another
auditor covers anything in its scope.

| Auditor | Prefix | Scope |
|---|---|---|
| A1 Protocol and crypto | `MP-` | `core::mesh::{item,sign,codec,hlc,crdt,proto,views}`, `crates/mesh::{noise,frame,session,pair,directs}`. The D9 safety argument, pre-auth parsing, psk/prologue/pattern use, rotation, removal, fork handling. |
| A2 Persistence and identity | `MI-` | `sqlite_store`, `identity`, the mesh migrations (v21, v22, and v23 if one was added), the backup/restore hook, marker file, `leave`, durability (`synchronous`), chunked commit correctness, Windows cfg paths. |
| A3 Caps and gateway | `MC-` | `core::mesh::caps`, `crates/gateway/src/capgate.rs` and its integration, the escrow fence, in-memory vs persisted accounting, the one-in-flight logic, fail-open, the 403 path, perf claims. |
| A4 Claims, UX and leakage | `MD-` | Every doc in `docs/mesh/`, ADRs 0031-0033, README/CHANGELOG/SECURITY/THREAT_MODEL edits, CLI and desktop copy versus actual behaviour (honesty labels, SI-19), every place a secret could leak (logs, errors, JSON, UI), and analytics (MESH-SI-14: no mesh analytics events). |

### Phase C: triage and remediation (you)

1. Write `docs/mesh/audit/<YYYY-MM-DD>/findings.json` (all findings, deduplicated across
   auditors) and `FINDINGS_INDEX.md`. Each finding gets a verdict: `confirmed`,
   `rejected` (with the reason and evidence) or `duplicate-of`.
2. For each confirmed finding:
   1. Write the failing test **first**.
   2. Capture its failing output to
      `docs/mesh/audit/<date>/evidence/<id>_baseline_fail.log.txt`.
   3. Fix it.
   4. Confirm the test passes.

   Commit one finding (or a tight cluster) at a time: `fix(mesh): <id> — …`.
3. Re-run the full check suite, the soak (10 minutes) and the mutants after
   remediation.

### Phase D: verification (fresh subagent)

Spawn one fresh `general-purpose` subagent. It must not have seen the auditors' reasoning
beyond `findings.json`. It:
- re-checks every confirmed finding's fix and test, and checks the rejected ones'
  rationale;
- runs the full suite;
- spot-checks 5 invariants from scratch;
- writes its verdict back to you.

Write `docs/mesh/audit/<date>/FINAL_VERDICT.md` from it. Remediate anything it reopens,
and repeat Phase D once if needed.

### Phase E: ship (you)

1. **Docs:**
   - README: move the mesh from "in development" to the feature list, with an honest
     summary and limitations.
   - `docs/mesh/USER_GUIDE.md`: a final pass.
   - `CHANGELOG.md`: consolidate the mesh entries into one coherent `### Added — Tethra
     Mesh …` section, plus `### Security` notes.
   - Root `SECURITY.md` and `THREAT_MODEL.md` final.
   - `PRODUCT_SPEC.md` "Device mesh" section current.
   - `docs/mesh/SECURITY_INVARIANTS.md`: every MESH-SI implemented with tests.
   - `docs/mesh/TEST_PLAN.md`: final counts, each with its command.
2. **`docs/mesh/REVIEW_HANDOFF.md`**, following `docs/projects-first/REVIEW_HANDOFF.md`:
   - a measured command → result table;
   - what was not executed here, and why (service-mode validation runs only in CI);
   - the CI run ids for the final head.
3. **Wait for CI to be green on the final head**, all jobs including
   `packaged-service-macos`. That job also validates that mesh didn't break the packaged
   service lifecycle.
4. `gh pr ready <PR>`. Update the PR body with the summary, the review handoff link, the
   audit verdict link, and a test plan checklist, **with no attribution lines**.
5. **Do not merge.** The owner merges.

## Acceptance criteria

- [ ] The soak and adversarial suites ran and every failing seed was converted into a regression test. The mutants are all KILLED, with the output recorded.
- [ ] The audit folder is complete: findings.json, FINDINGS_INDEX, evidence logs for every confirmed finding, FINAL_VERDICT.
- [ ] Every confirmed finding is fixed with a test, and the verification subagent concurs.
- [ ] Documentation is consolidated and accurate. `documentation_claims` passes.
- [ ] CI is green on the final head (all jobs), and the PR is marked ready, not merged.
- [ ] STATUS.md shows all 12 increments `done`, with final test counts.

## Verification commands

```bash
bash scripts/mesh_soak.sh --minutes 30
bash scripts/mutation_checks.sh mesh_vv_before_commit mesh_skip_sig_verify   # …all mesh mutants by name
# the full README §3 suite, the desktop checks, and:
bash scripts/smoke.sh
gh pr checks <PR> --watch
```

## Docs to update

Everything listed in Phase E, plus `docs/mesh/audit/<date>/*` and `REVIEW_HANDOFF.md`.

## Handoff checklist (final)

- [ ] STATUS.md is complete, with the final test counts and the CI run ids.
- [ ] The CLAUDE.md 12-point session report includes a section addressed to the owner:
      what to review first, the residual risks, and the recommended next milestone
      (candidates: a background node service consistent with ADR 0020, multi-user
      meshes, or mobile read-only).
