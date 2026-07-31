# Targeted verification handoff

For a reviewer confirming the remediation of the two merge blockers in
`audit/pr17-projects-first-bounded`. Narrow by design: this is a verification
handoff, not a request for another audit.

The audit branch and its artifacts are untouched. Everything below runs against
the PR branch `feat/projects-first-live-activity`.

---

## 1. The two blockers, reproduced then fixed

### AUD-05

Before (audited head `f0ff1a1`):

```text
$ npx vitest run src/components/AuditPr17Repro.test.tsx
AUD-05 rendered tracking label = "needs attention"
AssertionError: expected 'needs attention' to be 'on'
```

After:

```bash
cargo test -p api-tracker-tracking --test status_contract
cargo test -p api-tracker-tracking --test live_activity_readonly
cd apps/desktop && npx vitest run src/components/ProjectTrackingStatus.test.tsx
```

The headline assertion is
`ProjectTrackingStatus.test.tsx > renders 'Tracking is on' for a verified and
active setup`, against a fixture Rust generated. Its end-to-end counterpart is
`live_activity_readonly.rs ::
a_verified_and_active_setup_projects_to_tracking_is_on`, which drives the real
resolver.

### AUD-01

Before:

```text
AUD-01 metrics.total    unfiltered=2        filtered=2
AUD-01 known_input      unfiltered=5000000  filtered=5000000
AUD-01 estimated_micros unfiltered=14500000 filtered=14500000
AUD-01 integrations     unfiltered=2        filtered=2
```

After:

```bash
cargo test -p api-tracker-tracking --test activity_filter_consistency
```

`aud_01_regression_a_host_filter_reaches_every_metric` uses the audit's exact
fixture and asserts both the unfiltered totals above and the filtered
`1 / 1 000 000 / 2 500 000 / 1`.

---

## 2. Running the audit's own reproductions against the fixed head

Measured, not asserted. Copy `audit/repro/audit_pr17_repro.rs` from the audit
branch into `crates/tracking/tests/` and run it.

**It does not compile as-is**, at exactly two lines:

```text
error[E0425]: cannot find function `note_activity_refresh` in module `project`
  --> crates/tracking/tests/audit_pr17_repro.rs:269:18
  --> crates/tracking/tests/audit_pr17_repro.rs:285:14
```

Those are inside `aud_03_the_activity_poll_writes_a_row_and_bumps_row_version_every_tick`,
which calls the function AUD-03's preferred remediation deletes. With that one
test removed and every other byte unchanged:

| Test | Audited head | Fixed head | Why |
|---|---|---|---|
| `aud_01_a_filter_does_not_reach_the_summary_cards_or_the_cost_block` | **FAILED** | **ok** | the blocker is fixed |
| `aud_04_the_overview_status_has_no_health_key_the_ui_reads` | ok | ok | the payload shape it documents is unchanged; what changed is that nothing reads the impossible path |
| `aud_02_a_custom_origin_only_project_has_no_in_flow_approval_path` | ok | ok | not fixed, still true |
| `aud_07_two_projects_can_link_the_same_folder` | ok | ok | not fixed, still true |
| `aud_v1_no_project_file_value_reaches_any_persisted_or_serialized_artifact` | ok | **ok** | privacy canaries unregressed |
| `aud_v2_reads_do_not_disturb_tracking_state` | ok | **ok** | reads still write nothing |
| `aud_j1_the_projects_first_journey_end_to_end` | ok | **ok** | the full journey unregressed |
| `aud_06_a_deleted_folder_reports_as_edited_not_as_missing` | ok | **FAILED** | it asserts `scan_stale == true` for a missing folder, which is the defect AUD-06 describes and this work fixes |
| `aud_03_…` | ok | *does not compile* | it asserts `row_version == 10` after ten polls, which is the defect AUD-03 describes |

So two audit assertions no longer hold, and both are assertions **of the defect**
rather than of correct behaviour. No verification test regressed.

The frontend reproduction cannot be run verbatim at all:

```text
$ npx vitest run src/components/AuditPr17Repro.test.tsx   # audit copy, fixed head
AssertionError: expected 'unknown' to be 'needs attention'
```

Its fixture predates `ProjectOverview.tracking`, a field the fixed backend always
emits, so it is now an impossible shape — the exact category the remediation brief
forbids in new fixtures. Its *intent* is carried by
`ProjectTrackingStatus.test.tsx`, against bytes Rust generated.

---

## 3. Full local validation, as run

```bash
cargo fmt --all --check                              # clean
cargo +1.97.0 clippy --workspace --all-targets -- -D warnings   # clean
cargo test --workspace --all-targets                 # 1486 passed, 0 failed
cargo build --workspace --release                    # ok
bash scripts/smoke.sh                                # 140 passed, 0 failed

cd apps/desktop
npm ci                                               # locked install
npx prettier --check src                             # clean
npx eslint src                                       # clean
npx tsc --noEmit                                     # clean
npx vitest run                                       # 257 passed, 0 failed
npm run build                                        # vite build ok
cargo build --release -p api-tracker-desktop         # tauri backend ok
```

`scripts/smoke.sh` runs against a throwaway vault in a temp dir and touches no
launchd job, so it is safe beside the live production gateway on this machine. No
service-mode validation harness was run locally, unchanged from the PR's existing
position.

---

## 4. What to check by hand

The projected DTO is the whole of the AUD-05 fix, so the thing worth a human
reading is whether its states say the right thing:

1. `crates/tracking/src/statusview.rs` — the precedence in
   `TrackingStatusView::resolve`, and the sentence/action for each state.
   Particularly: `folder_missing` outranks health for the *state* but does not
   override `is_working`; `attribution` rides beside health; `idle` and
   `unsupported` deliberately have no action.
2. `apps/desktop/src/test/fixtures/project-overview.generated.json` — the actual
   bytes. Regenerate with
   `UPDATE_STATUS_FIXTURE=1 cargo test -p api-tracker-tracking --test status_contract`
   and confirm the diff is empty.
3. `ActivityFilter::event_scope` / `usage_scope` in
   `crates/core/src/projectactivity.rs` — that no project-activity query builds
   its own project/window predicate any more. `grep -n "project_id = ?1"
   crates/core/src/` should show only those two builders for the activity path.
4. `activity_facets`'s doc comment — that the "facets stay broad" decision is
   stated where the code is, not only in the docs.

## 5. Repository state

```text
PR:                #17, OPEN and unmerged
Branch:            feat/projects-first-live-activity
Audit branch:      audit/pr17-projects-first-bounded @ 971ee46 — untouched
Worktree:          clean
```

## 6. Out of scope

AUD-02, AUD-07 and AUD-09 are open and recorded in `KNOWN_LIMITATIONS.md` and in
`TARGETED_REMEDIATION.md`. They were not merge blockers and were not adjacent to
either fix. No further broad audit is requested.
