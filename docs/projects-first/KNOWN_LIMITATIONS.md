# Known limitations

Stated because they are true, not because they are comfortable.

## Coverage of traffic

**Only traffic that reaches the local helper is recorded.** A project that has not
been reconfigured, or whose process was not restarted after its `.env` changed,
produces nothing. The page says "Waiting for the first request" — which is
accurate, and does not distinguish "not started yet" from "misconfigured". The
existing advanced diagnostics do.

**An unknown host is only visible if something observed it.** A route cannot exist
outside the compiled-in catalog, an unrouted prefix produces a 404 and a counter
with no event row, and even routed traffic produces no row unless it arrived
through the project link. So a genuinely unknown API appears on the activity
surface only via the interception path. Detected-but-never-observed integrations
appear as detections, not as activity — those are different claims and are not
merged.

**`.env` drift is not a health input.** If something external rewrites the project
`.env` after setup, the route, link and helper all survive, so health still reads
as working while requests no longer pass through. This is a pre-existing
limitation and is not fixed here.

## Filtering

**Facets are broader than the result they filter.** `activity_facets` is scoped by
the time window only, deliberately: it populates the filter controls, and a
self-filtered control cannot be changed without clearing it first. So the Host
dropdown may offer a host the current result set contains none of. The summary
shown as a *result* — Detected APIs — always matches the active filter. The two
answer different questions, and `LIVE_ACTIVITY.md` says which is which.

**Filtered cost drops usage whose event row has been pruned.** With no filter,
`gateway_usage_events` rows are read directly, so usage that outlived its request
event still counts. With a filter active they are restricted to events that match,
which necessarily excludes those orphans: a row with no event left cannot be said
to satisfy a host or status filter. A filtered total over a window older than the
raw-event retention can therefore be lower than the unfiltered one by more than
the filter alone would explain.

**The cards and the cost block bound different columns.**
`runtime_request_events.at` and `gateway_usage_events.at` are written by the same
exchange but are not guaranteed to be the same instant, so a request landing
within milliseconds of a window boundary can be inside one figure and outside the
other. Pre-existing, unchanged by the filter work, and far below the resolution of
anything the surface displays.

## Cost

**Only bundled and imported pricing records.** OpenAI and Anthropic, 29 bundled
entries, one verification date. Everything else is visible and unpriced.

**Cache reads are excluded from billable input**, so an estimate is a lower bound
for cache-heavy usage. Note the admin-sync path prices all input at the base
rate — two conventions, both documented, and this surface uses the gateway's.

**The whole bundled table goes stale on a fixed horizon** after its single
verification date. Stale records still price, and say they are stale.

**Truncation is possible.** Above 2 000 (provider, model, day) groups in one
window, totals are partial by truncation as well as by coverage, and the surface
says so.

**Provider-reported cost is not shown on this surface at all.** It is not summed
with the estimate, and rather than place two differently-derived numbers side by
side here, this iteration shows only the local estimate. Provider-reported figures
remain on the usage surface.

## Activity data

**Time to first byte is always `null`.** The gateway records it per exchange; the
interception path does not separate it. The column exists in the DTO and is
honestly empty rather than filled with total latency.

**Latency percentiles are histogram-derived and approximate**, and labelled so.
The chart's per-bucket latency is a mean over the observations in that bucket that
had a latency at all.

**Retention bounds history.** Raw events have a short retention (default 7 days)
and the daily rollup a longer one, so a 30-day window may cover fewer raw events
than a 30-day range implies. The series reads raw events, so it is subject to that
retention.

**A bucket exists only if something was observed in it.** For requests and errors
an absent bucket means none arrived. For tokens, latency and cost it means
unknown, and the chart leaves a gap.

## Tracking status

**`CurrentHealth::AttributionPaused` is unreachable from the current resolver.**
The variant exists, the projection handles it and both suites cover it, but
`derive_health` never selects it — attribution is reported through
`ProjectOverview.attribution_paused` and `TrackingStatusView.attribution` instead.
It is kept because the projection is exhaustive over the enum, so an unhandled
variant is a compile error rather than a blank label.

**`folder_available` is a point-in-time answer.** It is resolved on page open,
manual refresh and after a change, like the rest of `overview` — not watched. A
folder deleted while a project page is open reads as present until the next
overview read.

**Two projects can still link the same folder** (AUD-06's sibling, AUD-07).
`project_folder_links.project_id` is the primary key with no uniqueness on
`folder_path`, and no field reports the other claim. `envlink::apply_link` binds
the file bytes with its own digest and refuses when they no longer match, so the
second apply cannot silently corrupt the first's work.

## Scope of this iteration

**One folder per project.** A monorepo with several independently-configured
subdirectories is not expressible through this surface; the advanced flow still
handles multiple folders per project.

**Destination approvals are vault-wide.** `tracking_approved_origins` is keyed by
`(origin, provider_id)` with no project column, so the project page words them as
pending rather than as this project's. Scoping them per project would change the
MAC message and is an ADR-level decision, not made here.

**`unlink` does not undo managed file changes.** Restoring them stays the explicit
undo action, so unlinking never edits a project file unasked. The confirmation
says this.

**No secure value import from `.env`.** Completing a detected credential means
adding the credential through the normal form. An import action would require this
layer to read a value, which is precisely what its design prevents.

**Attribution requires a project link.** The gateway's matcher only considers
credentials of projects with a live link row, excluding password-locked projects.
A project registered but not linked records `unmatched` for every credential.
Deliberate, and surfaced rather than widened.

**The layout is temporary.** Plain cards, one chart, one table, expected to be
replaced by a later visual redesign.

## Not verified in this iteration

**The packaged pressure test was not executed on this machine.** It requires
installing a login-scoped helper, and a live production gateway occupies that slot
here. The repository's own handoff forbids running either validation harness in
service mode on a developer machine. The workflow that covers it in CI is
unchanged by this work; the manual sequence is written down in
`../activity-onboarding/PACKAGED_VALIDATION.md` and remains unexecuted here.

**No live provider traffic was observed end to end locally** for the same reason.
Every activity path is covered by tests that seed observations directly.
