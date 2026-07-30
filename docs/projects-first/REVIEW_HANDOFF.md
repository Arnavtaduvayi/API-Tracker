# Review handoff

Branch: `feat/projects-first-live-activity`
Base: `main` @ `b6f6692` (PR #16 merge commit, verified from git)

## What changed

| Area | Files |
|---|---|
| Schema v20 | `crates/core/src/db.rs` |
| Linkage + detections | `crates/core/src/projectlink.rs` (new) |
| Bounded project reads | `crates/core/src/projectactivity.rs` (new) |
| Cost with coverage | `crates/core/src/projectcost.rs` (new) |
| Pricing metadata + batch lookup | `crates/core/src/pricing.rs` |
| Projects-first facade | `crates/tracking/src/project.rs` (new) |
| Tracking-status projection | `crates/tracking/src/statusview.rs` (new) |
| 11 commands | `apps/desktop/src-tauri/src/main.rs` |
| Project page | `ProjectTracking.tsx`, `ProjectActivity.tsx`, `ActivityChart.tsx` (new) |
| Shared refresh | `apps/desktop/src/useLiveRefresh.ts` (new) |
| Availability helpers | `apps/desktop/src/usage.ts` |
| Navigation | `apps/desktop/src/App.tsx` |

## Targeted remediation of the bounded audit

`audit/pr17-projects-first-bounded` (`971ee46`) raised two merge blockers against
head `f0ff1a1`. Both are fixed, with two adjacent follow-ups:

| ID | What | Where it is written up |
|---|---|---|
| AUD-05 | The project page read `status.health.currently_working`, a path the backend cannot emit, so a healthy project rendered "needs attention" forever | `audit/TARGETED_REMEDIATION.md` |
| AUD-01 | A filter reached the chart and the recent table but not the summary cards, the cost-coverage block or Detected APIs | `audit/TARGETED_REMEDIATION.md` |
| AUD-08 | Manual Refresh did not re-resolve health, contrary to ADR 0029 | `LIVE_ACTIVITY.md` |
| AUD-03 | The five-second poll wrote a row nothing read and consumed a compare-and-swap token other writers need | `LIVE_ACTIVITY.md` |
| AUD-06 | A deleted folder reported as an edited one, and offered a Rescan that fails | `audit/TARGETED_REMEDIATION.md` |

`audit/TARGETED_VERIFICATION_HANDOFF.md` records what the audit's own
reproductions now do against the fixed head, including the two that no longer hold
because they assert the defects.

AUD-02, AUD-07 and AUD-09 remain open; none was a merge blocker. They are in
`KNOWN_LIMITATIONS.md`.

## Local validation — measured, on this branch's head

```text
cargo fmt --all --check                                    PASS (exit 0)
cargo +1.97.0 clippy --workspace --all-targets -D warnings PASS (exit 0)
cargo test --workspace --all-targets                       PASS 1486 passed / 0 failed
cargo build --workspace --release                           PASS (exit 0)
bash scripts/smoke.sh                                       PASS 140 passed / 0 failed

npm ci                    (locked install)                  PASS
npm run format:check                                        PASS
npm run lint                                                PASS
npm run typecheck                                           PASS
npm test                                                    PASS 259 passed / 22 files
npm run build             (tsc --noEmit && vite build)      PASS
cargo build --release -p api-tracker-desktop (Tauri backend) PASS
```

Two prerequisites, both documented rather than worked around:

* `cargo build --release -p api-tracker-cli && bash scripts/bundle_cli.sh` must
  run first, or `tauri-build` refuses before anything compiles (CONTRIBUTING,
  `NEW-22`/`ZFT-045`).
* `target/` held artifacts from a previous checkout path
  (`~/Documents/GitHub/API-Tracker`), which made `tauri-build` read plugin
  permissions from a directory that no longer exists. Cleared with
  `cargo clean -p tauri -p api-tracker-desktop …` for both profiles. A local
  cache artifact, not a source problem.

## Not executed here, and why

**The packaged pressure test.** It installs a login-scoped helper, and a live
production gateway (`dev.api-tracker.gateway`) occupies that slot on this machine.
`NEXT_FRESH_AUDIT_HANDOFF.md` forbids running either validation harness in
service mode on a developer machine. No shell-harness check was added or changed,
so the validation manifest, its mutation suites and the three exact-assertion-count
gates are untouched — deliberately, since adding a check requires regenerating
the manifest and satisfying four separate shape constraints.

**Live provider traffic end to end.** Same reason. Every activity path is covered
by tests that seed observations directly.

## Focused review: what it found, and what changed

A review across the eight named dimensions was run, with each finding
independently refuted before being accepted. 13 findings survived refutation.
Every one was real; all 13 are fixed on this branch, each with a test that fails
against the previous code.

The two most serious were both false-reporting bugs in the area this iteration
exists to get right, and both had passed the original tests:

1. **Priced-request overstatement (high).** The gateway writes a usage row for
   every request, whether or not usage could be extracted — so a normal streamed
   workload produces `(provider, model, day)` groups where one row has tokens and
   ninety-nine do not. `COUNT(*)` credited all hundred as priced, leaving
   `requests_with_unknown_usage` at 0 and `complete` at true. The query now counts
   usage-bearing rows separately and splits the group.
2. **A partially-failed apply reported "Tracking is on" (high).** The UI tested
   `step.outcome === "failed"` against `apply::ApplyReport`, whose `StepOutcome`
   is a nested Rust enum — so the comparison could never match. Worse, the test
   written to prove partial applies are reported honestly used a hand-authored
   fixture in a shape the backend cannot emit, so it passed against a UI that
   could not detect failure at all: a false validation PASS. `LinkOutcome` now
   carries an `ApplyReportView` whose `failed_step` is computed by the
   orchestrator's own `failed_step()`, and the fixture is the real shape.

The rest:

| Finding | Fix |
|---|---|
| The series' token/cost query ignored the activity filter, so a filtered bucket showed one host's requests beside every host's tokens | the filter now reaches both queries, via one shared clause builder |
| The token cards showed *priced* tokens — excluding unpriced models and cache reads | added `known_input_tokens` / `known_output_tokens` |
| Partial pricing counted the same tokens as both priced and unpriced | a dimension is counted in exactly one total |
| `projectCostAvailability` ignored `complete`, rendering a floor as an unqualified figure | it now degrades to `partial` |
| A fetcher change mid-flight locked the poll loop onto the OLD fetcher (the shared `inFlight` guard also dropped the new one) | a generation counter; stale closures no-op |
| "Change folder" was a dead button — an effect discarded any preview whose path differed from the linked one, which is exactly that case | the effect is gone; the preview is cleared where it is finished with |
| A clean setup immediately reported "your files changed", because the stored fingerprint predated the apply that rewrote `.env` | recomputed after apply |
| A failed overview read rendered the "Select project folder" call to action for a project that may be linked | the last known overview is kept and the failure is stated |
| A disabled surface stayed on "Loading…" forever | `loading` cleared on the disabled path |
| The canary sweep serialized only the credential sub-list, not the whole preview | sweeps the preview, the detection as written to `detection_json`, and the disclosure |
| Stale *pricing* used the wording for a stale provider *sync* | no longer marked stale; the pricing sentence carries it |
| No `(project_id, at)` index on `runtime_request_events` — v16's composite has `observation_source` between the two columns a range needs | added |
| `project_name_unknown_api` set `confirmed = 1` for an empty correction, permanently suppressing that host's alert | an empty correction is refused |

Findings raised and **refuted** (recorded so they are not re-raised): that the
sequence/`applied` guard is unreachable because the overlap guard prevents
concurrency — true of the same generation, which is why the generation check was
added rather than the sequence check removed.

## Please look hardest at

0. **The tracking-status projection.** `crates/tracking/src/statusview.rs` is the
   whole of the AUD-05 fix, and it is the file where a wrong sentence would now
   live. Specifically: the precedence in `TrackingStatusView::resolve` (an
   unlinked project, then tracking switched off, then a missing folder, then the
   resolver's verdict); that `folder_missing` names the state without overriding
   `is_working`; that `attribution` rides beside health rather than replacing it;
   and that `idle` and `unsupported` deliberately carry no action. Nothing there
   decides health — `is_working` and `sentence` come from
   `CurrentHealth::is_currently_working` and `CurrentHealth::describe` — and the
   match is exhaustive over the enum so a new variant is a compile error rather
   than a blank label.
1. **The consent gate.** `crates/tracking/src/project.rs` `link_digest` and
   `confirm_link`. The digest binds the decisions, not the envlink plan digest,
   because the latter embeds a per-link CSPRNG slug and would reject every
   confirmation. Question worth asking: is there an apply-relevant decision the
   digest does not cover? It currently covers port, service actions, route
   prefixes + provider ids + creates-flag, and per-file (path, exists, changed).
2. **`derive_detections`.** `credential_candidates` means "credentials the project
   already holds", which I initially read as "variables found in the project". A
   test caught it. Worth confirming the corrected reading against `detect.rs`.
3. **Cost coverage arithmetic** in `projectcost.rs`: which bucket a group lands in
   when tokens are known but the model is not, versus usage never reported. The
   two are different and are counted differently.
4. **The refresh loop's stale-response guard.** `useLiveRefresh.ts` uses a
   monotonic `applied` sequence. The test drives out-of-order settlement, but it
   cannot easily force a genuinely superseded response to land, because the
   overlap guard prevents two concurrent fetches. That is a real gap in the test,
   not in the code — the guard is what makes the race hard to stage.
5. **Whether `overview` is on any hot path.** It resolves health, which
   compare-and-swaps. It is called on page open, after a change, and from
   `ProjectDetail`'s effect. If a future caller puts it on a timer, that is a
   write storm.

## Security reconciliation

| Invariant | Status |
|---|---|
| Sealed, non-executing project scanning | unchanged; fingerprint walk is stat-only and refuses symlinks |
| Loopback-only gateway | unchanged |
| Registered upstream origins | unchanged |
| Explicit custom-origin approval | unchanged; a repo-discovered destination yields no plan and no approval |
| No open relay | unchanged |
| No payload persistence | unchanged; no new column can hold one |
| No authorization/header/query persistence | unchanged |
| Encrypted rollback data | unchanged |
| Current-health verification | unchanged; one resolver, never read from the cached column |
| Service namespace and ownership | unchanged; no lifecycle code touched |
| Exact validation check identity | unchanged; no harness check added |
| Safe install ordering | unchanged; apply step order untouched |
| Connection resource bounds | unchanged; new reads are bounded and capped |
| No production gateway interaction from tests | preserved; mocked ops throughout |
| No whole-computer scanning | unchanged; root/home/`/Users` still refused |
| No arbitrary project code execution | unchanged |
| SI-19 local vs provider-reported never summed | preserved and newly pinned by a test |

New secret-handling surface: `detected_credentials`, which has no column capable
of holding a value, swept by a canary test over every column of every row.

## Follow-ups (not blocking)

* **AUD-02** — add an in-flow "Approve this destination" affordance to the preview
  panel, or at minimum render the `Advanced tracking diagnostics` button there so
  the screen the disclosure names is one click away on the first-time path. Top
  remaining follow-up from the bounded audit.
* **AUD-07** — detect an existing claim on a folder in `prepare_link` and surface
  it, or refuse with an actionable message.
* **AUD-09** — dedupe `PlanSummaryView::files_to_edit` and render it
  folder-relative, as its own doc comment says.
* Scope destination approvals per project — changes the MAC message, ADR-level.
* Surface provider-reported cost beside the local estimate on the project page,
  clearly separated.
* Populate `ttfb_ms` for the intercept path.
* Support several folders per project for monorepos.
* A reviewed, explicit secure-import path for a detected credential's value, if
  one can be built without this layer reading a value.
* Consider whether the first backoff step should exceed the normal interval; it
  currently equals it, so one transient failure does not slow anything down.
