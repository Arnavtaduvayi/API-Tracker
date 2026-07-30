# Test plan

All mocks and fixtures. No test reaches the network, installs a service, touches
launchd, or opens a socket. There is a live production gateway on the machine
this was developed on; nothing here can reach it, by four independent layers
(injected `CommandRunner`, foreground-only CLI fixtures, the shell harness's
launchd check, and no service-mode harness run locally).

Every timing test uses controllable timers.

## Rust — `crates/core/src/projectcost.rs` (21)

| Test | Holds |
|---|---|
| `known_openai_model_is_priced_and_complete` | 1M in + 1M out gpt-4o = $12.50, complete |
| `known_anthropic_model_is_priced` | a bundled Anthropic model prices |
| `dated_snapshot_resolves_to_its_base_record` | `gpt-4o-2024-08-06` → `gpt-4o`, and reports which |
| `provider_prefixed_model_id_resolves` | `openai/gpt-4o` resolves |
| `input_and_output_prices_are_not_interchangeable` | swapping the counts changes the amount |
| `a_known_zero_is_complete_and_differs_from_unpriced` | same integer, opposite `complete` |
| `unknown_model_is_visible_counted_and_not_zero` | counted, tokens reported, not $0 |
| `mixed_known_and_unknown_reports_partial_coverage` | 0 < coverage < 1 |
| `requests_without_reported_usage_are_unknown_not_zero` | no ratio at all |
| `known_tokens_without_a_model_are_unpriced_not_unknown` | known tokens stay known |
| `merging_unknown_into_known_tokens_stays_unknown` | unknown + known is unknown |
| `effective_date_selects_the_record_in_force_that_day` | two dates, two rates |
| `partial_pricing_is_a_floor_not_a_total` | `micros_if_complete()` is None |
| `a_stale_record_prices_and_is_flagged` | prices, and says stale |
| `a_foreign_currency_record_does_not_enter_the_total` | reported unpriced |
| `cached_input_tokens_are_excluded_from_billable_input` | documented lower bound |
| `an_empty_window_is_empty_not_free` | empty, not free |
| `provider_reported_cost_is_not_summed_into_the_local_estimate` | SI-19 |
| `groups_collapse_per_model_across_days` | one row per model, priced per day |
| `the_window_bounds_are_applied` | range change excludes outside traffic |
| `other_projects_are_excluded` | project isolation |

## Rust — `crates/core/src/projectactivity.rs` (21)

Empty series; one point; bucketing at minute/hour/day; **traffic in an unrolled
hour visible** (asserts the rollup has no bucket for it first); error counting
across status classes and transport failures; tokens and cost riding the same
buckets; an unpriced model leaving the bucket incomplete with tokens still known;
usage with no model; an unknown host keeping its universal metadata; a
user-assigned name reaching the surface while creating no route and no approval;
recent activity newest-first with an unknown provider unpriced; a known row
priced; every filter narrowing without parameter collision, including two at once
and one that matches nothing; window bounds; project isolation; facets offering
only values that exist; and large datasets staying bounded.

## Rust — `crates/tracking/tests/projects_first.rs` (31)

**Workflow** — a project with no folder; preview producing a disclosure and a
digest; the disclosure naming every file the plan edits; a repository-discovered
destination producing no plan, an empty digest and no approval row; a wrong
digest refused with nothing changed; a matching digest linking and recording;
idempotent re-selection; a folder change clearing the previous folder's scan
state; disable/re-enable preserving linkage, detections and history; re-linking
not re-enabling disabled tracking; unlink preserving project and history and
being idempotent; project delete cascading.

**Credentials** — the canary sweep over every column; a provider with an existing
credential not being unfinished; rename / reassign / environment / ignore, with
the two contradictory status+credential combinations refused; decisions surviving
a rescan; duplicate detection collapsing while the same variable in another file
does not; ~30 detections all surviving.

**Reads that do not write** — five overview reads not moving
`config_generation` or `verification_session`; ten activity polls not moving
`row_version`; an empty snapshot saying so rather than showing zeroes; a
populated one reporting its traffic; each range picking a sensible granularity.

**Relaunch** — restore neither rescanning nor re-applying; a disabled project not
resumed.

**Fingerprint** — stable across calls; unmoved by a source edit; moved by a
manifest change; a missing folder not panicking; symlinks not followed out of the
folder (unix); a stale fingerprint offering a rescan without reconfiguring; a
rescan refreshing it.

**Concurrency** — a stale linkage write refused as `StateConflict` rather than
losing the update, driven through two connections on one database file.

## Frontend — `src/useLiveRefresh.test.tsx` (18)

Immediate open refresh; the 5 s interval firing and not firing early; a tick
during an in-flight fetch dropped; a late response unable to overwrite newer
data; backoff with the doubling starting at the second failure; the cap still
recovering; a failed refresh keeping the last good data; hidden slowdown and
show-again refresh; focus refresh; manual refresh re-arming; unmount stopping the
timer; a post-unmount result setting no state; disabled not polling; a changed
fetcher refetching. Plus `relativeTime` unit coverage.

## Frontend — `src/components/ActivityChart.test.tsx` (15)

Empty; one point; many points; absent-as-zero only for requests/errors and
absent-as-**gap** for tokens (two path segments, no marker); a never-reported
metric replaced by a sentence; a caller-supplied note; a partially priced bucket
rendered hollow with a floor tooltip; metric change; granularity change;
`aria-labelledby` resolving to real elements plus the hidden table; an unknown
value as "not reported" and never `0`; 720 points bounded to ≤10 axis labels; an
all-zero series not collapsing.

## Frontend — `ProjectActivity.test.tsx` (19) / `ProjectTracking.test.tsx` (16)

Waiting-for-first-request instead of zeroes; summary cards; **an unpriced cost
never rendering a dollar amount**; the coverage percentage; unknown-usage
requests as "unknown — not zero"; the unpriced-model drill-down; the complete
case; an unknown API keeping its metadata with cost unavailable; naming it sending
only a display name; an unavailable per-row estimate; a per-row floor labelled;
range and filter changes refetching; a failed refresh keeping figures; disabled
not fetching; **manual Refresh re-resolving health** while the five-second timer
never does, and the panel still working with no health hook (AUD-08).

`ProjectTracking.test.tsx`'s two overview helpers are no longer hand-written:
they start from the Rust-generated fixture. Hand-written fixtures with
`status: null` throughout are precisely why a full suite passed while the page
could not report a healthy project.

Scope stated before the picker; the backend's own disclosure rendered; the digest
echoed on confirm; a cancelled picker configuring nothing; a refused digest
re-previewing; a no-plan preview offering no confirmation; a
repository-discovered destination presented as needing approval; no value
rendered; credentials needing details not blocking tracking; ignore / managed
elsewhere; the rescan offer wording; rescan calling rescan and not a re-link;
disable wording; unlink confirmation listing every consequence; the ADR-0020
oracle disclosure wherever the matching key is minted; a partial apply reported
as stopped.

## Rust — `crates/tracking/tests/status_contract.rs` (10) — AUD-05

The tracking-status contract, asserted against the **real** `ProjectOverview`
serialized by serde. No test in this file writes a JSON literal and calls it a
payload.

| Test | Holds |
|---|---|
| `the_overview_status_is_a_tracking_status_report_with_no_health_key` | `status.current.kind` exists; `status.health`, `status.health.currently_working`, `setup_id` and `watch` do not |
| `the_projected_view_is_present_and_complete_for_every_state` | `tracking` is an object with all ten fields for all 19 fixtures, never null |
| `every_user_visible_state_projects_to_its_label` | the state token, label and `is_working` for every user-visible state |
| `attribution_is_beside_health_not_instead_of_it` | paused/active/not-enabled; a paused key never makes `is_working` false |
| `historical_traffic_cannot_create_present_tense_health` | observations present, gateway down ⇒ not working; idle ⇒ no action |
| `last_observed_at_is_the_newest_observation_and_is_display_only` | the newest of two providers, not the first |
| `the_health_kind_helper_matches_what_serde_writes` | `CurrentHealth::kind()` == serde's tag, all 13 variants |
| `a_missing_route_and_a_missing_link_are_different_states` | different labels, different actions |
| `the_tauri_command_returns_the_project_overview_this_suite_asserts` | `project_tracking_overview` returns the struct verbatim; the desktop has no local `health_kind` |
| `the_frontend_fixture_is_what_rust_serializes` | the committed frontend fixture equals the bytes Rust emits |

## Rust — `crates/tracking/tests/activity_filter_consistency.rs` (10) — AUD-01

Every fixture is deliberately asymmetric: excluded rows carry different token
counts, models with different prices, different statuses, latencies and hosts, so
a query that ignores the filter cannot accidentally produce the filtered answer.
`assert_consistent` checks ten figures at once — request total, recent rows,
series requests, series tokens, known input/output tokens, estimated cost,
unpriced requests/tokens, unknown-usage requests, coverage percentage, error
count, series errors, latency and observed integrations — and `assert_narrows` is
the negative control that fails if any of them equals its unfiltered counterpart.

| Test | Holds |
|---|---|
| `aud_01_regression_a_host_filter_reaches_every_metric` | the audit's exact fixture: 2 requests, 1 OpenAI, 1 other host, different tokens and cost. Unfiltered 2 / 5 000 000 / 14 500 000 / 2 integrations; filtered 1 / 1 000 000 / 2 500 000 / 1 |
| `every_filter_dimension_narrows_every_figure` | host, provider, credential, model, endpoint, two-at-once and all-seven-at-once, each selecting one row of six |
| `status_class_and_observation_source_narrow_every_figure` | the 4xx row and the intercept row, with their own hand-computed expectations |
| `the_time_range_narrows_every_figure_too` | 1h vs 24h moves requests, tokens, cost and the integration list together |
| `filtered_cost_preserves_every_coverage_distinction` | priced / unpriced / never-reported all survive; coverage denominator is the filtered known-token total (1M of 2M = 0.5); an excluded observation appears in neither the priced nor the unpriced detail |
| `a_filtered_known_zero_is_still_a_measured_zero` | 0 tokens priced is complete, `micros_if_complete() == Some(0)`, coverage `None` |
| `a_filter_that_matches_nothing_empties_every_figure` | cards, chart, table, integrations and cost all empty; `no_observations` true |
| `facets_stay_broad_while_the_integrations_summary_narrows` | both halves of the intended facet behaviour, in one test |
| `another_projects_traffic_is_excluded_under_every_filter` | same host, same model, 90× the tokens, another project |
| `orphaned_usage_counts_unfiltered_and_cannot_satisfy_a_filter` | the documented usage-scope asymmetry |

## Rust — `crates/tracking/tests/live_activity_readonly.rs` (13) — AUD-03/05/06/08

| Test | Holds |
|---|---|
| `repeated_polling_leaves_durable_tracking_configuration_unchanged` | 50 polls; `project_folder_links`, `tracking_setups`, `gateway_routes`, `gateway_project_links` dumped and compared byte-for-byte; `row_version` still 0 |
| `a_control_action_survives_a_page_that_is_polling` | a Disable holding a link read from before ten ticks still commits |
| `nothing_stamps_the_activity_refresh_column_any_more` | the function is gone, nothing writes the column, the column itself stays |
| `a_verified_and_active_setup_projects_to_tracking_is_on` | real `refresh_with` ⇒ `VerifiedAndActive` ⇒ "Tracking is on", `is_working`, no action |
| `the_same_setup_with_a_dead_gateway_projects_to_gateway_unavailable` | same rows, gateway down; history kept, `is_working` false |
| `a_removed_route_projects_to_route_unavailable` | a disabled route, link intact |
| `a_removed_project_link_projects_to_project_link_unavailable` | the other half, with a different action |
| `an_unlinked_project_overview_still_carries_a_tracking_state` | no folder is a state, not a null |
| `a_linked_folder_with_no_setup_is_awaiting_setup` | never-scanned is not stale |
| `a_disabled_project_reads_as_tracking_off` | and is not styled as a fault |
| `a_deleted_folder_reports_as_missing_not_as_edited` | `folder_available` false, `scan_stale` false, the link survives |
| `an_edited_folder_is_still_reported_as_stale` | the negative control for the row above |
| `the_overview_re_resolves_health_instead_of_reading_the_cached_row` | the cached row says `traffic_observed`; nothing is listening; health says so |

## Frontend — `ProjectTrackingStatus.test.tsx` (15) — AUD-05

Every fixture is bytes Rust wrote (`src/test/fixtures/project-overview.generated.json`,
generated and verified by `status_contract.rs`). Covers: the projected object
present for all 19 fixtures; only declared state tokens emitted **and** no
declared token without a fixture; `status` carrying no `health` key; **"Tracking
is on" for a verified and active setup**; the negative control (deleting `status`
entirely, and injecting the old impossible `{health:{currently_working:false}}`
shape, both leave the label unchanged); every fixture's label with no bare token
rendered; the call-to-action for an unlinked project; sentence + action for the
six states a user must act on; an idle project asked to do nothing; historical
traffic not creating present-tense success; attribution paused shown beside
"Tracking is on"; the `AttributionPaused` health variant still saying tracking is
active; a project that never enabled attribution not warned about it; a missing
folder reported as missing with Rescan disabled; a present folder with changed
files still offering Rescan.

## Regression suites re-run unchanged

Git isolation, origin trust, verification health and freshness, verification CAS
retry and concurrency, rollback encryption, service ownership, validator
identities, gateway security, privacy canaries, documentation claims, migration
safety, scan bounds, detect coverage, plan/apply, undo ground truth, and the 45
TrackFlow tests for the advanced flow.

## Counts

```text
crates/core     new: 42        (21 cost + 21 activity)
crates/tracking new: 31
frontend        new: 64        (18 + 15 + 15 + 16)
                     ----
                     137

targeted remediation (AUD-05 / AUD-01 / AUD-03 / AUD-06 / AUD-08)
crates/tracking new: 33        (10 status_contract + 10 filter consistency
                                + 13 live_activity_readonly)
frontend        new: 19        (15 ProjectTrackingStatus + 4 ProjectActivity)
                     ----
                     52

                total new: 189
```

Whole-suite totals on the remediated head: **1 486** Rust tests and **257**
frontend tests, 0 failures.
