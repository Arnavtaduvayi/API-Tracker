# Targeted remediation of the bounded PR #17 audit

Scope: the two merge blockers from `audit/pr17-projects-first-bounded` (commit
`971ee46`, audited head `f0ff1a1`), plus the two adjacent follow-ups that were
small enough to fix alongside them. Nothing else was redesigned.

This document records what was reproduced, what changed and what is pinned. It
does not restate or revise the audit's own artifacts, which stay on the audit
branch untouched.

| ID | Severity | Merge blocking | Status |
|---|---|---|---|
| AUD-05 | High | **YES** | Fixed |
| AUD-01 | High | **YES** | Fixed |
| AUD-08 | Medium | No | Fixed (adjacent) |
| AUD-03 | Low | No | Fixed (adjacent) |
| AUD-06 | Low | No | Fixed (fell out of AUD-05's required states) |
| AUD-02 | Medium | No | **Open** — see `KNOWN_LIMITATIONS.md` |
| AUD-07 | Low | No | **Open** — see `KNOWN_LIMITATIONS.md` |
| AUD-09 | Cosmetic | No | **Open** |

---

## AUD-05 — the project page could not report healthy tracking

### Reproduced

Run on the audited head, before any change:

```text
$ npx vitest run src/components/AuditPr17Repro.test.tsx
AUD-05 rendered tracking label = "needs attention"
AssertionError: expected 'needs attention' to be 'on'
```

```text
$ cargo test -p api-tracker-tracking --test audit_pr17_repro
aud_04_the_overview_status_has_no_health_key_the_ui_reads ... ok
```

### Root cause

`project_tracking_overview` returns `tracking_project::ProjectOverview` verbatim,
so its `status` is a serialized `state::TrackingStatusReport`:

```json
{ "current": { "kind": "verified_and_active" }, "history": {…},
  "freshness": […], "state": "traffic_observed" }
```

`ProjectTracking.tsx:163` read `overview?.status?.health?.currently_working`.
There is no `health` key in that payload and no `currently_working` boolean
anywhere in it, so the expression was `undefined` for every setup and the page
fell through to "needs attention" — permanently, including when
`CurrentHealth::VerifiedAndActive.is_currently_working()` was true.

`types.ts` declared the same field as `TrackingStatus`, which is the DTO of a
*different* command (`tracking_status` → `TrackingStatusDto`), so the compiler
could not see the mismatch either. `ProjectTracking.test.tsx` passed
`status: null` throughout, so nothing exercised the branch.

### Fixed

**The frontend no longer interprets a Rust enum.** A corrected TypeScript
interface would have left the frontend deciding health from a tagged union with
nothing to check it against — it would drift again the next time a variant is
added. So the projection moved into Rust:

`crates/tracking/src/statusview.rs` — `TrackingStatusView::of(report, ctx)`. It
decides nothing: `is_working` is `CurrentHealth::is_currently_working` and
`sentence` is `CurrentHealth::describe`, both from the shared resolver. What it
adds is the product-level state tag, a short label, and the next action.

```text
state             tracking_on | route_unavailable | folder_missing | …
label             "Tracking is on"
is_working        CurrentHealth::is_currently_working — the ONE answer
sentence          CurrentHealth::describe, verbatim
action            what to do next, or null
last_observed_at  HISTORY. Beside `state`, never used to derive it
first_verified_at HISTORY.
attribution       not_enabled | active | paused
configuration_behind, folder_available
```

`ProjectOverview` gained `tracking: TrackingStatusView` (never null — an unlinked
project or one with no setup is a *state*, not a missing field) and
`folder_available: bool`. `status` is retained for diagnostics with an exact,
contract-tested TypeScript type.

Supporting changes, all in service of "one authority":

* `CurrentHealth::kind()` in `state.rs` is now the single source of the machine
  tag. `main.rs` had its own copy (`fn health_kind`); it is gone, and
  `the_health_kind_helper_matches_what_serde_writes` checks the remaining one
  against serde's own output for all 13 variants.
* `CurrentHealth::ConfigurationChanged` gained `route_missing` / `link_missing`,
  decided in `derive_health` where the evidence is. "Route unavailable" and
  "Project link unavailable" are different problems with different fixes, and
  recovering the distinction downstream by parsing `detail` would have been a
  second reading of health outside the resolver.
* `overview()` resolves folder availability before fingerprinting, so a folder
  that is not there is no longer reported as one whose files changed (AUD-06).

### The states, and what a user sees

| State | Label | `is_working` | Source |
|---|---|---|---|
| `tracking_on` | Tracking is on | true | `VerifiedAndActive` |
| `partially_tracked` | Partially tracked | true | `PartiallyTracked` |
| `waiting_for_first_request` | Waiting for first request | false | `WaitingForFirstRequest` |
| `restart_required` | Restart required | false | `NeedsRestart` |
| `gateway_unavailable` | Gateway unavailable | false | `GatewayUnavailable`, `VerifiedPreviouslyGatewayDown` |
| `route_unavailable` | Route unavailable | false | `ConfigurationChanged { route_missing: true, link_missing: false }` |
| `project_link_unavailable` | Project link unavailable | false | `ConfigurationChanged { route_missing: false, link_missing: true }` |
| `configuration_changed` | Configuration changed | false | `ConfigurationChanged` (both, or neither) |
| `attribution_paused` | Attribution paused | false | `AttributionPaused` |
| `idle` | No recent requests | false | `VerifiedPreviouslyIdle` |
| `setup_incomplete` | Setup did not finish | false | `ApplyIncomplete` |
| `needs_attention` | Tracking needs attention | false | `NeedsAttention` |
| `unsupported` | Nothing to track | false | `Unsupported` |
| `folder_missing` | Folder missing | resolver's answer | the linked folder is unreadable |
| `tracking_off` | Tracking is off | resolver's answer | `tracking_enabled = false` |
| `awaiting_setup` | Waiting for setup | false | linked, no setup row |
| `not_linked` | No folder selected | false | no link |

Two rules the table encodes:

* **Historical traffic never implies current health.** `last_observed_at` and
  `first_verified_at` are carried for display and are read by nothing that
  produces a state. A project observed a minute ago with a dead gateway is
  `gateway_unavailable`.
* **Attribution paused is not a tracking failure.** A gateway forwarding without
  a matching key still records every request, so `attribution: paused` rides
  beside `tracking_on` rather than replacing it, and a project that never enabled
  attribution reads `not_enabled` rather than being warned about a feature it
  never turned on. `attribution_was_requested` reads the persisted plan summary
  rather than guessing.
* **`folder_missing` does not override `is_working`.** The state names the most
  decisive thing to act on — every control the page offers for a linked folder
  acts on that folder — while whether traffic is flowing stays the resolver's
  answer. A structural fact cannot make a surface claim tracking stopped when it
  did not.

### Contract tests

`crates/tracking/tests/status_contract.rs` (10 tests). Every fixture is the real
`ProjectOverview` serialized by serde; no test writes a JSON literal and calls it
a payload.

* `the_overview_status_is_a_tracking_status_report_with_no_health_key` — the
  negative test: `status.health` and `status.health.currently_working` are
  absent, and so are `TrackingStatus`'s own `setup_id` and `watch`, proving it
  was the wrong DTO rather than a renamed field.
* `the_tauri_command_returns_the_project_overview_this_suite_asserts` — the Tauri
  boundary: `project_tracking_overview` returns
  `CmdResult<tracking_project::ProjectOverview>` verbatim and delegates to
  `project::overview`; the desktop carries no local `health_kind`.
* `the_frontend_fixture_is_what_rust_serializes` — writes every state to
  `apps/desktop/src/test/fixtures/project-overview.generated.json` and fails if
  the committed file differs. Regenerate with `UPDATE_STATUS_FIXTURE=1`.
* plus per-state, attribution, history and route/link tests.

`crates/tracking/tests/live_activity_readonly.rs` closes the loop end to end: a
real applied setup, a real fresh observation, a real
`state::refresh_with(GatewayLiveness::Verified)`, and the projection —
`a_verified_and_active_setup_projects_to_tracking_is_on`.

`apps/desktop/src/components/ProjectTrackingStatus.test.tsx` (15 tests) loads the
generated fixture. It asserts "Tracking is on" for the verified-and-active
payload, and contains the negative control the audit asked for: deleting `status`
entirely, and injecting the old impossible `{health:{currently_working:false}}`
shape, both leave the label unchanged, because nothing reads that path.

`ProjectTracking.test.tsx`'s own `overview()` / `linked()` helpers now start from
the generated fixture. Hand-written fixtures are how a full suite passed while the
page could not report a healthy project.

---

## AUD-01 — a filter reached the chart but not the numbers beside it

### Reproduced

Run on the audited head, before any change:

```text
$ cargo test -p api-tracker-tracking --test audit_pr17_repro
AUD-01 metrics.total    unfiltered=2        filtered=2
AUD-01 known_input      unfiltered=5000000  filtered=5000000
AUD-01 estimated_micros unfiltered=14500000 filtered=14500000
AUD-01 integrations     unfiltered=2        filtered=2
assertion failed: AUD-01: the Requests card must count only the filtered population
  left: 2, right: 1
```

while `series requests` went 2 → 1 and `recent rows` 2 → 1.

### Root cause

`project::activity_only` threaded its `ActivityFilter` into
`projectactivity::project_series` and `projectactivity::recent_activity` only.
`aggregate::project_metrics(conn, project_id, since)` and
`projectcost::project_cost_coverage(conn, project_id, since, until)` took no
filter parameter, and neither did `observed_integrations`. So with a filter active
the page rendered, side by side, a chart of the filtered population and —
unfiltered — "Requests", "Input tokens", "Output tokens", "Error rate", "Average
latency", "Estimated known cost", the whole cost-coverage box including its "% of
token usage priced" sentence, and "Detected APIs".

### Fixed

**One filter, one window, resolved once.** `activity_only` computes `since` a
single time (calling `range.since()` per query gives each a slightly later
boundary) and hands both to every query.

**One scope builder.** There is now no way to write a project-activity query that
forgets the filter, because there is no way to scope one by hand:

| Builder | Root | Used by |
|---|---|---|
| `ActivityFilter::event_scope` | `runtime_request_events e` | `project_series`, `recent_activity`, `observed_integrations`, `aggregate::project_metrics` |
| `ActivityFilter::usage_scope` | `gateway_usage_events u` | the series' token/cost query, `projectcost::load_groups` |

Both emit the project predicate, the half-open window and every active filter, and
both bind `(project_id, since, until)` as `?1..?3` with filter values from `?4` —
the off-by-one that would silently reuse `until` as a filter value is now
expressible in one place instead of six. `project_series` had built the usage-side
EXISTS clause inline; that duplication is gone.

Signatures changed:

```text
aggregate::project_metrics(conn, project_id, since, until, filter)
projectcost::project_cost_coverage(conn, project_id, since, until, filter)
projectactivity::observed_integrations(conn, project_id, since, until, filter)
```

Covered dimensions: time range, provider (catalog or user-assigned), host,
credential, model, status class, endpoint, observation source, project.

### Cost behaviour

Filtered cost is cost, not a share of cost. The estimate, the priced and known
token totals, the unpriced counts, the unknown-usage count and therefore
`token_coverage` are computed from the filtered rows alone; nothing is scaled or
apportioned from an unfiltered figure. Every distinction survives filtering:

* known estimated cost;
* provider-reported cost — still absent from this surface entirely (SI-19),
  unchanged;
* unpriced usage, with the model still named;
* partial pricing coverage, with `micros_if_complete()` still returning `None` so
  a floor is never presented as a total;
* unknown cost (`requests_with_unknown_usage`), still counted and still in no
  token total;
* a known zero, still a measured zero rather than "unknown".

The coverage denominator is the filtered known-token total.
`filtered_cost_preserves_every_coverage_distinction` builds 1M priced + 1M
unpriced + 1 unknown-usage request in scope and a 40M fully-priced row out of
scope, and asserts coverage is exactly 0.5.

### Integration behaviour

`observed_integrations` reflects the filtered result set. `activity_facets`
deliberately does not — see the next section.

### Facet behaviour, stated

`activity_facets` takes no filter and is scoped by the time window only.

Narrowing facets by the current selection makes the controls one-way: pick host
`api.openai.com` and a self-filtered host list contains only `api.openai.com`, so
there is no control left to pick a different host with and no way back except
"Clear filters". Across dimensions it is worse — choosing a host would empty the
model list of every model that host did not serve, and choosing that model would
then be the only model offered.

So facets answer *"what exists in this time window?"*, which is what a picker
needs, and `observed_integrations` answers *"what is in the result you are looking
at?"*, which is what a summary needs. They are allowed to disagree; the time
window is the one bound they share, and a facet never offers a value from outside
the selected window.

`facets_stay_broad_while_the_integrations_summary_narrows` asserts both halves in
one test, so the intent cannot be "fixed" in either direction by accident.

### Filter-consistency tests

`crates/tracking/tests/activity_filter_consistency.rs` (10 tests). Every fixture
is deliberately asymmetric — excluded rows carry different token counts, models
with different prices, different statuses, latencies and hosts — so a query that
ignores the filter cannot accidentally produce the filtered answer.

`assert_consistent` checks all of these at once for each case: request total,
recent rows, series requests, series tokens, known input and output tokens,
estimated cost, unpriced requests and tokens, unknown-usage requests, coverage
percentage, error count, series errors, latency, observed integration hosts and
their request sum. It also cross-checks that the cards and the chart count the
same rows, that Detected APIs accounts for exactly the filtered requests, and that
coverage is never computed over more tokens than the filter admits.

`assert_narrows` is the negative control: it fails if any figure that can differ
equals its unfiltered counterpart.

The regression test uses the audit's exact fixture, and asserts the unfiltered
totals the audit measured (2 / 5 000 000 / 14 500 000 / 2 integrations) so it
cannot pass by the fixture having quietly changed.

---

## Adjacent follow-ups fixed

### AUD-03 — the poll wrote a row nothing read

`project_activity` called `project::note_activity_refresh`, which
compare-and-swapped `last_activity_refresh_at` on `project_folder_links` and
incremented `row_version` — twelve guarded writes a minute per open project page,
for a column read by nothing ("Last updated" comes from the client's own last
successful fetch).

The write was not the cost; `row_version` was. It is the compare-and-swap token
guarding Disable tracking, Rescan and the applied-generation record, so a poll
landing between a caller's read and its write made that caller fail with a raw
`StateConflict`.

**Removed** — the audit's preferred remediation. `record_activity_refresh` and
`note_activity_refresh` are gone; reads are read-only. The **column** stays in the
schema and in `ProjectFolderLink`: existing vaults hold values for it, and
dropping a column to remove a write would break the data format for nothing.

Pinned by `repeated_polling_leaves_durable_tracking_configuration_unchanged`
(fifty polls; `project_folder_links`, `tracking_setups`, `gateway_routes` and
`gateway_project_links` dumped and compared byte-for-byte),
`a_control_action_survives_a_page_that_is_polling`, and
`nothing_stamps_the_activity_refresh_column_any_more`.

### AUD-08 — manual Refresh did not re-resolve health

ADR 0029 says Refresh resolves health; it re-read observations only, so a gateway
that died with the page open went unreported until the user navigated away and
back.

`ProjectActivity` takes an `onRefreshHealth` prop, wired by `ProjectDetail` to
`reloadOverview`. Refresh now reloads local observations, recalculates aggregates
and re-resolves gateway and tracking health. It does not re-run detection, rewrite
a project file, reinstall the service or re-apply configuration —
`project_tracking_overview` does none of those, which is why it is the only extra
call, and the five-second timer still calls neither.

Pinned by `manual Refresh re-resolves health as well as re-reading observations`,
`the five-second timer refreshes observations only, never health`, and
`the_overview_re_resolves_health_instead_of_reading_the_cached_row`.

### AUD-06 — a missing folder reported as an edited one

Not on the follow-up list, but "Folder missing" is one of the user-visible states
AUD-05's remediation is required to represent, and the fix is one field.

`folder_fingerprint` returns a stable sentinel for an unreadable folder, so
`scan_stale` tripped and the page said "This project's dependency or environment
files changed since the last scan" — the wrong sentence — and offered a Rescan
that fails with a raw filesystem error.

`ProjectOverview.folder_available` is resolved before fingerprinting; `scan_stale`
is suppressed when the folder is gone; the state becomes `folder_missing` with the
action "Choose the folder again if it moved, or unlink it"; and the Rescan button
is disabled. The association is **not** lost — the link row and its path survive,
which is what the audit found already correct.

Pinned by `a_deleted_folder_reports_as_missing_not_as_edited` and its negative
control `an_edited_folder_is_still_reported_as_stale`.

---

## Behaviour deliberately unchanged

Re-run and still green: the projects-only workflow, persistent folder linkage,
zero-terminal setup, safe unfinished credential records, automatic built-in
provider setup, explicit custom-origin approval, the five-second visible refresh,
auto-lock, honest partial pricing, null chart gaps, byte-for-byte undo, sealed
project scanning, gateway security, exact validation manifests and
production-service isolation. No test was weakened; two audit assertions that
asserted the defects now fail, which is recorded in
`TARGETED_VERIFICATION_HANDOFF.md`.

## Remaining non-blocking follow-ups

* **AUD-02** — a custom-origin-only project has no in-flow approval and, on the
  first-time path, no navigation control to the advanced screen it names. Not
  silent: the panel lists each pending origin, explains the policy and names the
  screen. Top remaining follow-up.
* **AUD-07** — two projects can link the same folder with no state saying so.
  `envlink::apply_link`'s own digest prevents silent corruption.
* **AUD-09** — the disclosure lists the same `.env` twice when two providers' link
  plans name it, and renders absolute paths where `PlanSummaryView::files_to_edit`
  documents folder-relative ones.
