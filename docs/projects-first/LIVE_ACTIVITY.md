# Live activity

## One refresh mechanism

`apps/desktop/src/useLiveRefresh.ts`. One timer per surface, shared by every
card, the chart and the table. Not one per component: N components would mean N
concurrent backend calls per tick, N independent backoffs, and N chances to leave
one running after unmount.

| Behaviour | Value |
|---|---|
| Refresh on open | immediate |
| Visible interval | 5 s |
| Hidden interval | 60 s |
| On focus | immediate |
| Backoff | 5 s doubling to a 60 s ceiling |
| Manual refresh | immediate, and re-arms the interval |
| Unmount | timer cleared, in-flight results discarded |

### Overlap

A tick that arrives while a fetch is in flight is **dropped**, not queued.
Queuing would turn a slow backend into an unbounded backlog that keeps firing
after the user has left, and the in-flight fetch is already going to deliver
fresher data than the dropped tick could.

### Stale responses

Every fetch carries a sequence number, and a result is discarded if a newer fetch
has already been applied. Without this a slow response can land after a fast one
and roll the display backwards — which on a live view is indistinguishable from
real data arriving.

### Failure

The error is recorded and the last good data is **left on screen**, with "The
figures below are from the last successful refresh." A failed refresh must not
blank a display that still holds a valid answer. Consecutive failures back off;
one success resets.

## Why the timer does not resolve health

`health::resolve*` compare-and-swaps up to `REFRESH_CAS_ATTEMPTS` times per
setup. A 5-second timer over it is a guarded-write storm contending with the
gateway's own writer. So:

* `project_tracking_overview` resolves health — page open, **manual refresh**,
  after a change.
* `project_activity` reads observations and touches no tracking state.

### Manual Refresh resolves health (AUD-08)

The **Refresh** button on the activity panel calls both the snapshot command and
`project_tracking_overview`. It previously called only the first, so the health
line beside the figures stayed as it was until the user navigated away and back —
a gateway that died with the page open went unreported indefinitely, contrary to
what ADR 0029 said Refresh did.

`ProjectActivity` takes an `onRefreshHealth` prop, wired by `ProjectDetail` to
`reloadOverview`. Refresh therefore re-reads local observations, recalculates
aggregates, and re-resolves gateway and tracking health. It does **not** re-run
detection, rewrite a project file, reinstall the service or re-apply
configuration — `project_tracking_overview` does none of those, which is why it
is the only extra call.

`manual Refresh re-resolves health as well as re-reading observations` and
`the five-second timer refreshes observations only, never health` pin both
halves.

## Reads do not write (AUD-03)

`project_activity` is read-only. It used to call `project::note_activity_refresh`
after every read, which compare-and-swapped `last_activity_refresh_at` on
`project_folder_links` and incremented `row_version` — twelve guarded writes a
minute per open project page, for a column nothing read ("Last updated" comes
from the client's own last successful fetch).

The write was not the cost; `row_version` was. That column is the compare-and-swap
token guarding Disable tracking, Rescan and the applied-generation record, so a
poll landing between a caller's read and its write made that caller fail with a
raw `StateConflict` for no product reason.

`projectlink::record_activity_refresh` and `project::note_activity_refresh` are
gone. The **column** stays in the schema and in `ProjectFolderLink`: existing
vaults hold values for it, and dropping a column to remove a write would break the
data format for nothing. It is read from the row and never written.

Pinned by `repeated_polling_leaves_durable_tracking_configuration_unchanged`
(fifty polls, four tables dumped and compared byte-for-byte) and
`a_control_action_survives_a_page_that_is_polling`.

## Why polling does not defeat auto-lock

`project_activity` uses `with_vault_background`, which does not refresh the
inactivity clock. `tracking_status` and `tracking_list` — the two commands a live
page would otherwise poll — use `with_vault`, so polling either would mean an
open project page never auto-locks. Verified by
`the_activity_snapshot_writes_no_tracking_state`, which polls ten times and
asserts the setup's `row_version` and `config_generation` are unchanged.

## Bounded reads

| Query | Bound |
|---|---|
| Series | `MAX_BUCKETS = 750`, aggregated in SQL |
| Recent activity | clamped to `MAX_RECENT_ROWS = 200` |
| Integrations | `LIMIT 200` |
| Facets | 10–100 per list |
| Cost groups | `MAX_GROUPS = 2 000`, with `truncated` reported |

Everything is aggregated in SQL or Rust; no raw observation history crosses IPC.
Windows are indexed: `idx_rre_project_source_at` (v16) and `idx_gue_project_at`
(v20).

## Why the series reads raw events

`aggregate::roll_up` returns early when the current hour is incomplete, so
`runtime_metric_buckets` never contains the hour a live view is about. A
rollup-sourced chart would show nothing for traffic that just arrived, then jump
an hour later. `project_series` reads `runtime_request_events` directly.

`traffic_in_an_unrolled_hour_is_visible` proves this rather than assuming it: it
runs `roll_up`, asserts the current hour has **no** bucket, then asserts the
series contains it anyway.

## Absent is not zero

A bucket is emitted only when something was observed in it. Within a bucket,
requests and errors are measured, but token and cost figures carry their own
known/unknown state — `SUM` over an all-NULL column yields NULL, and that means
"nobody reported this", not "the total was zero".

In the chart, a `null` breaks the line. Only requests and errors treat an absent
bucket as a real zero, because only those are counted from the observation rows
themselves.

## Chart

Inline SVG, no new dependency. Metrics: requests, input tokens, output tokens,
total tokens, average latency, errors, estimated known cost. Ranges: last hour
(minute buckets), 24 hours (hour), 7 days and 30 days (day).

Accessibility: `role="img"` with `aria-labelledby` pointing at a `<title>` and a
`<desc>` that states the metric, how many buckets had data, and the peak; the
same series is duplicated as a visually-hidden table. Per-point `<title>`
tooltips. A partially priced bucket is drawn hollow and its tooltip says
"partial — a floor, not a total".

Wide content scrolls inside its own container, so the page body never scrolls
sideways.

## Filtering

Provider (catalog or user-assigned), host, model, status class, endpoint,
observation source, credential. Values are offered from facets computed over the
window, so the UI only offers filters that exist. Every filter is an equality
predicate on a column the database already holds, bound as a parameter — there is
no free-text predicate.

`filters_narrow_without_parameter_collision` covers the placeholder numbering
specifically: the first filter parameter is `?4` because the window binds `?1..?3`,
and an off-by-one there would silently reuse `until` as a filter value instead of
failing.

### One filter, one population (AUD-01)

`project::activity_only` resolves the window and the filter **once** and hands
both to every query. Previously it threaded the filter into `project_series` and
`recent_activity` only — `aggregate::project_metrics`,
`projectcost::project_cost_coverage` and `observed_integrations` took no filter
parameter at all — so a filtered chart sat beside unfiltered summary cards, an
unfiltered "Estimated known cost", an unfiltered coverage percentage and an
unfiltered "Detected APIs".

There is now no way to write a project-activity query that forgets the filter,
because there is no way to scope one by hand:

| Builder | Root | Used by |
|---|---|---|
| `ActivityFilter::event_scope` | `runtime_request_events e` | `project_series`, `recent_activity`, `observed_integrations`, `aggregate::project_metrics` |
| `ActivityFilter::usage_scope` | `gateway_usage_events u` | the series' token/cost query, `projectcost::load_groups` |

Both emit the project predicate, the half-open window and every active filter, and
bind `(project_id, since, until)` as `?1..?3` with filter values from `?4`.

`usage_scope` reaches usage through the event that produced it, because a usage
row carries a provider, a model and token counts but none of the request metadata
the filter selects on. With **no** filter it reads usage rows directly, so usage
whose event row retention has already pruned still counts; with a filter it
restricts to matching events, which drops that orphaned usage — a row with no
event left cannot be said to satisfy a host filter, and counting it would put the
wrong tokens back into a total the user narrowed. Both directions are asserted by
`orphaned_usage_counts_unfiltered_and_cannot_satisfy_a_filter`.

### Filtered cost

Filtered cost is cost, not a share of cost. The estimate, the priced and known
token totals, the unpriced counts, the unknown-usage count and therefore
`token_coverage` are all computed from the filtered rows alone. Nothing is scaled
or apportioned from an unfiltered figure: a coverage percentage computed over
traffic the user filtered out is a wrong number, not an approximate one.

Every distinction the unfiltered call preserves survives filtering — priced,
known-but-unpriced, never-reported, partial coverage, a floor never presented as a
total (`micros_if_complete` still returns `None`), and a known zero still a
measured zero rather than "unknown".

### Facets are deliberately broader

`activity_facets` takes no filter. It populates the filter controls, and a
self-filtered control is one-way: pick host `api.openai.com` and a self-filtered
host list contains only `api.openai.com`, so there is no control left to pick a
different host with and no way back except "Clear filters". Choosing a host would
likewise empty the model list of every model that host did not serve.

So facets answer **"what exists in this time window?"**, which is what a picker
needs, and `observed_integrations` answers **"what is in the result you are
looking at?"**, which is what a summary needs. The two are different questions and
are allowed to disagree; the time window is the one bound they share — a facet
never offers a value from outside the selected window.

`facets_stay_broad_while_the_integrations_summary_narrows` asserts both halves, so
the intent cannot be "fixed" in either direction by accident.

## What is not polled

Provider APIs. This loop reads local observations Tethra already recorded.
Provider-side usage synchronisation keeps its own cadence and rate limits,
untouched by this work.
