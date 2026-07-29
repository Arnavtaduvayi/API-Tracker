# Tracking Orchestrator — Architecture

The engine behind "Track API activity" and `tethra track .`. It composes
proven components; it does not reimplement them.

## 1. Responsibilities

One module owns the sequence scan → detect → plan → consent → apply →
verify → diagnose → undo, with a persisted state machine shared by desktop
and CLI. Everything below it already exists and is called as-is:

| Concern | Existing component (unchanged) |
|---|---|
| Env-file inventory | `envgov::discover` |
| Provider signals | `stackdetect::detect`, manifests, `provider_for_host` |
| Service lifecycle | `gateway::lifecycle::Lifecycle` (install / start / status / repair) |
| Routes | `gateway::routes::{add_manifest_route, add_custom_route, …}` |
| Env edits | `gateway::envlink::{plan_link, apply_link, unlink}` (digest-bound) |
| Path proof | keyless probe (today inline in `gateway_cmd.rs:1273` — extracted, see §6) |
| Matching key | `UnlockedVault::gateway_matching_key` + `control::Request::PushKey` |
| Route MAC key | `UnlockedVault::gateway_route_mac_key` + `control::push_route_key` |
| Diagnostics | `gateway::doctor::diagnose` + `LinkWarning` + new checks (§7) |
| Activity | `store::gateway_activity_summary`, `runtime` store |

## 2. Placement: a new `crates/tracking` crate

`api-tracker-tracking`, workspace member, depends on `api-tracker-core` +
`api-tracker-gateway`. Both apps already depend on the gateway crate, so
adding the tracking crate to `apps/cli` and `apps/desktop/src-tauri` is a
one-line dependency each.

Why not inside `crates/gateway`: the gateway crate is the security-audited
forwarding engine (`#![forbid(unsafe_code)]`, 14 adversarial test suites);
keeping product orchestration out of it preserves that audit boundary and
review economics. Why not `crates/core`: the orchestrator must call gateway
APIs, and core must not depend on gateway (dependency direction).
Why not per-app: CLAUDE.md requires desktop and CLI to share business
logic; two orchestrators would drift.

Modules:

```text
crates/tracking/src/
  lib.rs        — public API, TrackingError
  detect.rs     — signal fusion (AUTOMATIC_PROVIDER_DETECTION.md)
  plan.rs       — TrackingPlan assembly from a ProjectDetection
  apply.rs      — step executor with per-step reporting
  verify.rs     — probe + first-request watch
  diagnose.rs   — ranked no-traffic diagnosis
  state.rs      — TrackingState machine + persistence (migration v15)
  undo.rs       — track-scoped teardown
```

## 3. Public API (consumed by Tauri commands and `track_cmd.rs`)

```rust
pub fn scan(conn, folder: &Path, project: Option<&str>) -> Result<ProjectDetection>;

pub fn plan(conn, detection: &ProjectDetection, selections: &Selections)
    -> Result<TrackingPlan>;

pub struct TrackingPlan {
    pub project: ProjectRef,               // existing or to-create
    pub service_actions: Vec<ServiceAction>,   // InstallService | StartService | None
    pub route_actions: Vec<RouteAction>,       // CreateManifestRoute | CreateCustomRoute{origin} | ReuseRoute
    pub link_plans: Vec<envlink::LinkPlan>,    // one per provider, digest-bound
    pub attribution: AttributionPlan,          // WithPassword | Skip
    pub warnings: Vec<PlanWarning>,            // aggregated LinkWarnings + service warnings
    pub restart_expectation: RestartExpectation, // RequiredLikely | Unknown | NotNeeded
}

pub fn apply(ctx: &mut ApplyCtx, plan: &TrackingPlan) -> ApplyReport;
    // ApplyReport: per-step Outcome { Done, Skipped(reason), Failed(error) },
    // stops at first failure, never rolls back silently, offers undo.

pub fn watch_first_request(conn, setup_id, deadline) -> WatchOutcome;
    // Observed { provider, project, latency_ms, model } | PartiallyObserved | TimedOut

pub fn diagnose(conn, setup_id) -> Vec<Diagnosis>;   // ranked, evidence-based
pub fn status(conn, setup_id | folder) -> TrackingStatus;
pub fn undo(conn, setup_id) -> UndoReport;
```

All functions are synchronous and DB-transactional where they write;
watching is a polling call the UI/CLI drives, so no background thread owns
UI state.

## 4. The apply sequence (exact order and failure semantics)

Order is dictated by the existing hard constraints
(`envlink::plan_link` requires a persisted port; routes must exist before
links; MAC key before custom routes are forwardable):

```text
 1. ensure project row (create if planned; register canonicalized folder
    in project_repos)
 2. ensure service:
      installed & running        → no-op
      installed, stopped         → Lifecycle::start
      not installed              → Lifecycle::install(bundled helper, force=false)
      install blocked (probe)    → offer foreground fallback (PACKAGING_PLAN §5)
    then control::verify_listener until Verified (bounded retries — the
    existing install path already polls 40×)
 3. ensure routes (per selected provider):
      add_manifest_route | add_custom_route(confirmed origin)
      existing row → reuse; disabled row → set_route_enabled(true)
 4. ensure route MAC key when any custom route exists:
      vault.gateway_route_mac_key() → control::push_route_key
 5. apply links (per provider): envlink::apply_link(approved plan)
      digest mismatch → abort step, re-plan, re-present (never write stale)
 6. control::ReloadRoutes (existing nudge)
 7. path check: keyless probe per route (§6)
 8. attribution (if password provided):
      vault.gateway_matching_key(master) → control::PushKey
 9. persist TrackingSetup row → state = awaiting_restart or
    awaiting_first_request (per restart_expectation)
```

Every step is idempotent (re-running `track` converges); every failure
names the step, what was and wasn't changed, and the next action. A step
failure leaves earlier steps in place — `applying → needs_attention` with
the partial report and an undo offer, because a half-configured setup that
is honestly reported is more recoverable than an automatic rollback that
can itself fail.

## 5. State and data model (migration v15)

```sql
CREATE TABLE tracking_setups (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    folder_path TEXT NOT NULL,            -- canonicalized
    state TEXT NOT NULL,                  -- the state machine value
    detection_json TEXT NOT NULL,         -- value-free detection summary
    plan_summary_json TEXT,               -- providers/routes/files configured
    applied_at TEXT,
    first_traffic_at TEXT,
    last_transition_at TEXT NOT NULL,
    attention_reason TEXT,                -- machine-readable Diagnosis id
    UNIQUE(project_id, folder_path)
) STRICT;
```

States: `not_configured, scanning, ready_to_configure, applying,
awaiting_restart, awaiting_first_request, traffic_observed,
partially_observed, needs_attention, unsupported` (transitions in
`TARGET_USER_JOURNEYS.md` §7). `scanning`/`ready_to_configure` are
normally transient and only persisted by the CLI's `--dry-run`-less
interrupted runs; the source of truth for "is traffic flowing" remains the
observation tables — `tracking_setups` caches the product-level state and
is re-derived (`state.rs::refresh`) on every read, so a stale row can
never claim `traffic_observed` falsely.

Existing-table touches (no breaking changes):

* `project_repos.path` — new paths are canonicalized at insert; existing
  rows are matched by canonicalize-on-compare (no destructive rewrite).
  A reverse lookup `project_for_folder(conn, &Path)` is added in core.
* No change to `gateway_*` tables; links created by `track` are ordinary
  `gateway_project_links` rows. `track undo` only removes what its setup
  row's plan summary attributes to `track`.

## 6. Verification

Two distinct proofs, deliberately separated:

1. **Path proof (synthetic)** — the existing keyless probe: one
   credential-free GET through the gateway per route; provider 401/403
   proves DNS→gateway→TLS→provider. Extracted from `gateway_cmd.rs:1273`
   into `tracking::verify::probe_route` so desktop, CLI, and diagnosis
   share it. Proves Tethra's side; says nothing about the user's app.
2. **Traffic proof (real)** — `traffic_observed` requires at least one
   `runtime_request_events` row with `observation_source='gateway'` for
   this setup's link slugs at/after `applied_at`. Watch implementation:
   poll `store::gateway_activity_summary` / a targeted
   `runtime_request_events` query keyed by the link's project and
   `applied_at` (2 s UI, 5 s CLI). `control::Status.last_observation_at`
   is a cheap pre-filter but never the proof (it is gateway-global).

Per-provider freshness feeds `partially_observed`: providers with routes
but no post-apply events are listed as unobserved, with the explicit note
that this is expected until the app calls them.

## 7. Diagnosis engine

`diagnose.rs` runs ordered checks, each returning evidence or passing;
output is the ranked list in `TARGET_USER_JOURNEYS.md` §A7. Sources:

| Diagnosis | Evidence source |
|---|---|
| Process not restarted | `applied_at` recent + zero events + no contrary signal (default first hint) |
| Docker / Compose project | existing `LinkWarning::DockerComposePresent` re-checked live |
| No dotenv loader | existing `LinkWarning::NoDotenvLoaderDetected` |
| Variable overridden elsewhere | re-scan env files: same var set in a later-loaded file (framework load-order table, versioned in `detect.rs`) |
| Env file drifted since apply | `doctor::LinkHealth` (env_points_at_gateway, port drift, NO_PROXY missing) |
| Gateway unavailable | `doctor::diagnose` findings (`not_installed`, `installed_but_stopped`, `port_collision`, `listener_unverifiable`, …) |
| Traffic bypassing gateway | route counters zero while provider-reported usage grows (when synced) — labeled as inference, never certainty |
| Provider unsupported | detection `Configurability::Unsupported` |
| Remote / devcontainer execution | `.devcontainer/`, `Dockerfile` CMD evidence — labeled "possible" |
| Nothing wrong found | explicit "everything checks out on Tethra's side" |

Diagnoses carry stable ids (mirroring `doctor::Finding.id` convention) so
tests can pin them and the UI can deep-link help.

## 8. Desktop and CLI wiring

* **Tauri**: new commands `tracking_scan`, `tracking_plan`,
  `tracking_apply`, `tracking_status`, `tracking_watch` (single poll),
  `tracking_diagnose`, `tracking_undo` — thin wrappers like the existing
  186; the vault handle comes from `AppState` (desktop stays in-process
  for vault operations; only the long-running service is the helper
  binary). Folder picking via `@tauri-apps/plugin-dialog` (new, vetted
  plugin dependency; capability entry added).
* **CLI**: `apps/cli/src/track_cmd.rs` implementing
  `tethra track [PATH] [--project N] [--dry-run] [--yes]`,
  `tethra track status`, `tethra track undo`, reusing `ctx::confirm`,
  the global `--json` convention, and interactive password prompts. The
  low-level `tethra gateway …` family is untouched.

## 9. What is explicitly out of scope for the orchestrator

* It never opens a listening socket, parses HTTP, or touches TLS — that
  stays in the gateway crate.
* It never reads credential values; attribution key material passes
  through the existing reauth-gated vault call and control channel only.
* It never edits files outside the approved `envlink` plans.
* It never deletes recorded history.
* It performs no network calls other than the keyless probe through the
  local gateway.
