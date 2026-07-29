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

* `project_tracking_overview` resolves health — page open, manual refresh, after
  a change.
* `project_activity` reads observations and touches no tracking state.

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

## What is not polled

Provider APIs. This loop reads local observations Tethra already recorded.
Provider-side usage synchronisation keeps its own cadence and rate limits,
untouched by this work.
