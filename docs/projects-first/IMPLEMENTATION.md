# Implementation

## Layers

```text
apps/desktop/src/                       the project page
  components/ProjectTracking.tsx        folder selection, disclosure, lifecycle
  components/ProjectActivity.tsx        cards, chart, cost, integrations, table
  components/ActivityChart.tsx          inline SVG chart
  useLiveRefresh.ts                     the ONE refresh loop
  usage.ts                              +projectCost/TokenAvailability

apps/desktop/src-tauri/src/main.rs      11 project_* commands

crates/tracking/src/project.rs          the projects-first facade
crates/core/src/projectlink.rs          v20 storage: linkage + detections
crates/core/src/projectactivity.rs      bounded project-scoped reads
crates/core/src/projectcost.rs          cost with coverage
crates/core/src/pricing.rs              +matched_model/currency, batch lookup
crates/core/src/db.rs                   migration v20
```

## Reused, not rebuilt

| Concern | Owner |
|---|---|
| Folder detection | `crates/tracking/src/detect.rs` |
| Planning | `crates/tracking/src/plan.rs` |
| Applying | `crates/tracking/src/apply.rs` |
| Present-tense health | `crates/tracking/src/health.rs` |
| Undo | `crates/tracking/src/undo.rs` |
| Destination approval | `crates/tracking/src/origin.rs` |
| Observation storage | `crates/core/src/runtime/` |
| Request metrics | `runtime::aggregate::project_metrics` |
| Pricing records | `crates/core/src/pricing.rs` |
| Naming an unknown host | `runtime::store::set_service_correction` |

`project.rs` is a facade. It sequences these and adds the product-level linkage
and the consent artifact; it re-implements none of them.

## Schema v20

Three additions, appended (migrations are append-only):

* `project_folder_links` — `project_id` PRIMARY KEY (one folder per project),
  `folder_path`, `tracking_enabled`, `linked_at`, `last_scan_at`,
  `scan_fingerprint`, `applied_generation`, `last_activity_refresh_at`,
  `row_version`.
* `detected_credentials` — `env_var`, suggestions, `source_kind`, `source_file`
  (folder-relative), `status` with a CHECK, `resolved_credential_id`,
  timestamps, `row_version`. Plus two FK child indexes.
  **No column can hold a value.**
* `idx_gue_project_at` on `gateway_usage_events(project_id, at)`.

Every table is `STRICT`, matching the rest of the schema. Every write to either
new table compare-and-swaps on `row_version`.

Migration tests live in a new file rather than in `migration_safety.rs`, because
`scripts/smoke.sh` greps that suite for `test result: ok. 9` and adding a test
there would break it.

## The facade

```text
prepare_link(project, folder)   -> FolderLinkPreview { detection, summary,
                                     digest, disclosure, pending_origins,
                                     detected_credentials, fingerprint }
confirm_link(.., digest)        -> LinkOutcome  (refuses a mismatched digest)
overview(project)              -> ProjectOverview   (resolves health)
activity_only(project, range)  -> ProjectActivitySnapshot  (reads only)
rescan(project)                -> Vec<DetectedCredential>  (no apply)
set_tracking_enabled(project, bool)
unlink(project)                -> bool
restore_on_launch()            -> per-project status
folder_fingerprint(folder)     -> String
```

`prepare_link` writes exactly one thing: `plan::ensure_port`, which persists a
free loopback port so the previewed base URL is the one that will be used. It
starts nothing.

## Cost derivation

Group `gateway_usage_events` by (provider, model, day) in SQL, then per group:
resolve a pricing record for that day and price it. Candidate records are loaded
once per provider rather than once per group, so a 30-integration project over 30
days costs a handful of queries instead of hundreds.

Three outcomes are kept apart, and `SUM` over an all-NULL column is left as NULL
rather than coalesced to 0, because that NULL is the distinction:

* priced;
* tokens known, no usable price → counted in `unpriced_requests` /
  `unpriced_tokens`;
* usage never reported → counted in `requests_with_unknown_usage`, contributing
  to no token total.

Cache-read tokens are excluded from billable input, matching the gateway's own
convention, which makes the estimate a documented lower bound.

## Read/write split

| Path | Writes? | Cadence |
|---|---|---|
| `overview` | yes (health CAS) | page open, manual refresh, after a change |
| `activity_only` | no | every ~5s while visible |
| `rescan` | linkage row only | explicit user action |
| `confirm_link` | yes (full apply) | explicit user action |

`project_activity` and `project_restore_tracking` are `with_vault_background`
commands, so polling does not refresh the inactivity clock.

## Deliberate deviations from the brief

* **A confirmation was added.** The brief says selecting the folder is the
  tracking action and asks for one disclosure before the first
  configuration-changing action. Those are satisfied by one disclosure plus one
  confirm; zero gates would have meant a login service and `.env` rewrites with
  no user knowledge. ADR 0029 D4.
* **`unknown_api_labels` was designed, then dropped.** `observed_api_services`
  already had `user_provider`/`user_api_name` since v12. ADR 0029 D8.
* **The raw plan is not sent over IPC.** A purpose-built `PlanSummaryView`
  carries what the screen renders.
