# Audit Recovery & Re-Audit Plan

Recovery performed on branch `audit/deep-pressure-test`, model **Fable 5 (`claude-fable-5`)**, effort `max`, extended thinking. No product code was modified during recovery.

> **Note on the "interruption":** the prior deep audit ran in *this* project's session. It hit the **monthly Fable 5 spend limit** during the parallel verification workflow — 49 of the workflow's sub-agents aborted. The main reasoning loop survived and completed `DEEP_TECHNICAL_AUDIT.md`. So the two written reports are **intact**, but the *audit itself* is **incomplete** (4 verifier categories never ran; 3 of 5 planned reports were never written). Both facts are reflected below.

## 1. Normal repository path
`/Users/arnavtaduvayi/Documents/GitHub/API-Tracker` — branch `main`, commit `7d81090a1068476291546963e68ca8c7de1a7145`, working tree **clean**. This is the immutable product baseline and matches the expected `7d81090`.

## 2. Every discovered worktree
`git worktree list` (all share the same repo and all sit at commit `7d81090a1068476291546963e68ca8c7de1a7145`):

| Path | Branch | Commit | Clean? | Notes |
|---|---|---|---|---|
| `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker` | `main` | `7d81090` | clean | product baseline |
| `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-deep-audit` | `audit/deep-pressure-test` | `7d81090` | dirty: `?? docs/audits/` (this recovery) | **interrupted audit worktree** |
| `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-fable-reaudit` | `audit/fable-independent-reaudit` | `7d81090` | **clean** | **pristine unbiased re-audit worktree (already exists)** |
| `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-ui-map` | `audit/ui-map` | `7d81090` | dirty: `?? docs/{UI_MAP,MANUAL_UI_TEST_PLAN,MANUAL_TEST_DATA}.md` | separate UI-audit effort; left untouched |

No detached or orphaned API-Tracker worktrees were found. No worktree was removed.

## 3. Interrupted audit worktree path
`/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-deep-audit` (branch `audit/deep-pressure-test`).

## 4. Files found
In `API-Tracker-deep-audit/docs/audits/` (were **untracked** until this recovery commit):
- `DEEP_TECHNICAL_AUDIT.md` — 179 lines, 24,150 bytes — **complete** (7 H2 sections, ends at `## Git status`).
- `MANUAL_SECURITY_TESTS.md` — 141 lines, 9,211 bytes — **complete**.

Preserved into `docs/audits/evidence/` from the session scratchpad (would otherwise be lost with the temp dir):
- `BASELINE.md`, `ARCH_TRUST.md`, `MY_FINDINGS.md` (orchestrator's own analysis + trust-boundary map + independent candidate findings)
- `all_findings.tsv` (96 findings: severity/id/verdict/title/location), `findings_raw.tsv` (full finding bodies), `verdicts.tsv` (48 verifier verdicts)
- `test-baseline.log` (398 tests pass, 0 fail/ignored/warn)

Raw workflow evidence (durable in the session project dir, **not** copied into git to avoid a 677 KB blob):
- Journal: `~/.claude/projects/-Users-…-deep-audit/2018f276-…/subagents/workflows/wf_0974ed1d-c1c/journal.jsonl` (167 lines) + 108 `agent-*.jsonl` transcripts.
- Full workflow result: `…/tasks/wcvydxitq.output` (677,101 bytes).

## 5. Files missing (never created — spend limit)
- `THREAT_MODEL_DELTA.md` — **missing**
- `TEST_COVERAGE_GAPS.md` — **missing**
- `REMEDIATION_PLAN.md` — **missing**
- `FINDINGS_INDEX.md`, `SOURCE_REVIEW_LEDGER.md`, `CONTINUATION.md` — never planned under those names (a review ledger exists as a *section* of `DEEP_TECHNICAL_AUDIT.md`, not a standalone file).

## 6. Files recovered from Git
**None required.** All discovered audit files were present in the working directory (untracked), so no reflog/stash/`fsck`/unreachable-object recovery was needed. `git status` confirmed the only dirty path was `docs/audits/`.

## 7. Files that appear truncated
**None.** Both written reports end cleanly at their intended final sections. The tool-reported "Wrote 179 lines" was independently confirmed by `wc -l`, first/last-line inspection, and section-count checks. (The *audit* is incomplete, but no *file* is truncated.)

## 8. Audit-document completeness
- `DEEP_TECHNICAL_AUDIT.md`: complete as a document; cites file:line evidence; **explicitly labels** which findings are CONFIRMED vs `unverified` (verifier aborted) vs trace-confirmed; includes a review ledger and an "areas not conclusively verified" section. It is an honest *interim* report, not a final one.
- `MANUAL_SECURITY_TESTS.md`: complete; concrete synthetic-only procedures.
- Overall audit deliverable set: **3 of 5 reports missing** (see §5).

## 9. Prior audit model provenance
- Entire audit ran on **Fable 5 (`claude-fable-5`)**, effort `max`, extended thinking — no silent fallback.
- **Provenance gap:** the verification pass was *mixed* — 46 findings CONFIRMED by a second Fable agent, 2 REFUTED, and **the remaining ~48 findings were never independently verified** because the rotation, concurrency-dos, business-docs, and fs-envfile verifier agents aborted on the spend limit (49 aborts total). The `db-migration` *reviewer* also aborted (covered instead by the orchestrator's own full read of `db.rs`).

## 10. Findings evidence recovered
96 candidate findings recovered and organized: **2 High, 25 Medium, 42 Low, 27 Informational** (raw review counts); **46 CONFIRMED, 2 REFUTED, ~48 unverified**. Headline confirmed/High leads: `CRYPTO-01`/`CONC-03` (concurrent rotation data-loss, CONFIRMED), `ROT-001` (revoke-response wedge, trace-only), `OBS-001` (exposure alerts auto-resolve, trace-only), `DEST-01/02` (destination exists()/target confusion, CONFIRMED), `IPC-01` (arbitrary-file-write over IPC, CONFIRMED), `PI-01/02` (master-password-to-child env; PID-reuse termination, CONFIRMED), `NET-01` (doc-watch SSRF, CONFIRMED). Full table: `docs/audits/evidence/all_findings.tsv`. These are **leads pending independent re-verification**, not accepted facts.

## 11. Whether production code was modified
**No.** Recovery touched only `docs/audits/**`. `git status` in every worktree shows zero changes to any file under `crates/`, `apps/`, `provider-manifests/`, `templates/`, `scripts/`, or any manifest.

## 12. Whether evidence was committed
**Yes** — see the audit-only commit on `audit/deep-pressure-test` recorded in the completion report. Only `docs/audits/**` was committed; no secrets, vaults, `*.db`, backups, logs, or provider responses.

## 13. Whether a full Fable-only redo is required — **YES**
The interrupted audit fails the Phase-7 completion gate on multiple counts:

| Gate | Met? | Evidence |
|---|---|---|
| Every production file reviewed | Partial | `db-migration` reviewer aborted (db.rs covered only by orchestrator); ledger is area-level, not per-file line-by-line |
| Complete source-review ledger | **No** | ledger is a section, not an exhaustive per-file table |
| Every migration reviewed | Yes | orchestrator read all 10 migrations |
| Every CLI / Tauri command inventoried | Partial | 136 Tauri cmds listed; per-command reauth only spot-checked |
| Every provider / destination / rotation reviewed | Yes | dedicated mandates |
| **All High findings independently verified** | **No** | ROT-001, OBS-001 verifiers never ran |
| **All data-loss claims reproduced/proved** | **No** | CRYPTO-01 trace-confirmed, not reproduced; OBS-003 unverified |
| Secret-exposure claims reproduced | Partial | PI-01 reviewer-only |
| **Threat-model delta / coverage-gap / remediation reports** | **No** | all three missing |
| No unfinished verifier categories | **No** | 4 categories aborted |
| No model-provenance gaps | **No** | ~48 findings single-agent only |
| No truncated reports | Yes (files) | but 3 reports absent |

**Decision:** a full **independent Fable-only re-audit** is warranted — redoing the **audit**, not the product. The existing 96 leads must be re-verified from code, not accepted.

## 14. Clean re-audit worktree path
`/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-fable-reaudit` — **already exists, verified clean and unbiased** (no `docs/audits`, tracked tree byte-identical to `main`). Rather than create a redundant near-duplicate of the "preferred" `../API-Tracker-fable-full-reaudit`, this existing pristine worktree is designated the re-audit worktree (it satisfies every Phase-8 criterion). If the exact preferred name is desired, rename with `git branch -m audit/fable-independent-reaudit audit/fable-full-reaudit` — no new worktree needed.

## 15. Clean re-audit branch
`audit/fable-independent-reaudit` (checked out in the worktree above), at `7d81090`. Serves the role of the preferred `audit/fable-full-reaudit`.

## 16. Exact immutable commit
`7d81090a1068476291546963e68ca8c7de1a7145`.

## 17. Commands needed to open the re-audit worktree
```bash
# The worktree already exists — just enter it:
cd /Users/arnavtaduvayi/Documents/GitHub/API-Tracker-fable-reaudit
git rev-parse HEAD        # must print 7d81090a1068476291546963e68ca8c7de1a7145
git status --porcelain    # must be empty (pristine, unbiased)

# If it did NOT exist, it would be created with:
# git -C /Users/arnavtaduvayi/Documents/GitHub/API-Tracker worktree add \
#     ../API-Tracker-fable-full-reaudit -b audit/fable-full-reaudit 7d81090a1068476291546963e68ca8c7de1a7145
```
Run the re-audit using the prompt at `docs/audits/FABLE_FULL_REAUDIT_PROMPT.md` (this branch), keeping that prompt **out** of the re-audit worktree until the blind pass is complete.

## 18. Unresolved recovery issues
1. **Spend limit** — a full re-audit needs substantially more Fable 5 budget than remains this cycle; do not start it until capacity is restored (the prompt mandates durable checkpoints for exactly this reason).
2. **Branch-name mismatch** — the pre-existing re-audit branch is `audit/fable-independent-reaudit`, not the preferred `audit/fable-full-reaudit`; documented above, not auto-renamed to avoid surprising an existing worktree.
3. **Provenance of the existing re-audit worktree** — it was created (mtime today 08:58) outside the recorded prior session; it is clean and unbiased, so it is safe to use, but its origin was not otherwise established.
4. Raw 677 KB workflow output lives in the session project dir, not in git; it is durable there for now but is not branch-preserved.
