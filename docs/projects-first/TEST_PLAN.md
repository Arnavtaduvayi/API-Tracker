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

## Frontend — `ProjectActivity.test.tsx` (15) / `ProjectTracking.test.tsx` (16)

Waiting-for-first-request instead of zeroes; summary cards; **an unpriced cost
never rendering a dollar amount**; the coverage percentage; unknown-usage
requests as "unknown — not zero"; the unpriced-model drill-down; the complete
case; an unknown API keeping its metadata with cost unavailable; naming it sending
only a display name; an unavailable per-row estimate; a per-row floor labelled;
range and filter changes refetching; a failed refresh keeping figures; disabled
not fetching.

Scope stated before the picker; the backend's own disclosure rendered; the digest
echoed on confirm; a cancelled picker configuring nothing; a refused digest
re-previewing; a no-plan preview offering no confirmation; a
repository-discovered destination presented as needing approval; no value
rendered; credentials needing details not blocking tracking; ignore / managed
elsewhere; the rescan offer wording; rescan calling rescan and not a re-link;
disable wording; unlink confirmation listing every consequence; the ADR-0020
oracle disclosure wherever the matching key is minted; a partial apply reported
as stopped.

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
                total new: 137
```
