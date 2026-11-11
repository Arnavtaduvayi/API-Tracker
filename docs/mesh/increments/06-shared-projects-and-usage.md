# Increment 06: Shared projects and cross-device usage

**Mode:** S · **Size:** M · **Prerequisites:** 05 done

## Goal

The first real product value. You share a project from one device and bind it on the
others. Gateway-observed API usage from every device then replicates as compact,
deletion-aware counters. `tethra mesh usage` shows honest cross-device totals:
- labelled per device;
- with freshness;
- with the priced, unpriced and unextracted split;
- never summed with provider-reported cost.

## Read first

- DESIGN §D11, §D14, §D17 (the usage-split columns; **v23**, since Increment 04 took v22 for the pairing psk), §D19 (MESH-SI-11/13) and the "What replicates" table in §D1.
- `crates/gateway/src/writer.rs`: 723-817 (attribution, `write_usage`, the daily upsert, line 812 `cost.unwrap_or(0)`) and 886-913 (retention sweep).
- `crates/core/src/projectcost.rs` (14-21, the honesty split).
- `crates/core/src/runtime/store.rs:1149-1200` (`delete_project_data`, `delete_all`).
- `docs/gateway/SECURITY_INVARIANTS.md` SI-19 (167-171) and `docs/gateway/PRIVACY.md` (the deletion promises).
- `crates/core/src/db.rs:970-983` (`gateway_usage_daily`).
- The STATUS.md handoff notes for 05, which describe the round-hook API.

## Scope (build all of this)

### 1. Migration v23, the honest usage split

(Renumbered by Increment 04, which added v22 `mesh_invites.wrapped_psk`; DESIGN §D14/§D17 say v22 for this one.)

- Add `unpriced_requests INTEGER NOT NULL DEFAULT 0` and
  `unextracted_requests INTEGER NOT NULL DEFAULT 0` to `gateway_usage_daily`.
- Store a cut-over marker: `mesh_meta('usage_split_since', <first day the writer populated them>)`,
  or a `gateway_config` column if that fits better. Document which you chose.
- Change the gateway writer so the daily upsert increments the two new columns, using
  **the same classification** `projectcost.rs` uses (priced / unpriced / unextracted).
  Don't create a second classifier; share a function in core if you need to.
- Gateway tests (`crates/gateway/tests/writer.rs` or a new file) cover each class
  landing in the right column.
- Keep `migration_safety` at 9 tests. Put the v23 schema test in `mesh_schema.rs`.

### 2. Projects (`core::mesh::projects`, plus `UnlockedVault` methods)

- `share(local_project_id)` mints `project.meta` and binds the project. It refuses if
  the project is already bound.
- `bind(mesh_project_id, local_project_id)`:
  - the target must exist in the views and not be archived;
  - the local project must not already be bound;
  - nothing is ever automatic (MESH-SI-13).
- `unbind(local_project_id)`, `rename(mesh_project_id, name)` (LWW, D7 local-write
  timestamp) and `archive(mesh_project_id)` (LWW).
- `merge(a, b)` follows D11: the root is the smaller id, and it refuses when both
  projects have caps. Caps arrive in 07; add the check now against the empty cap views.
- `list()` returns mesh projects with: bound locally (which local project), bound on
  which other devices (from the publisher's counters: a device with counters for it is
  "publishing"), archived, merged_into.

### 3. Publisher (`core::mesh::publish`)

- Follows D14 exactly: the cursor table `mesh_publish_cursor`, deltas going to the
  currently bound mesh project, the epoch bump on decrease, and skipping `''` sentinel
  rows.
- Runs as a **node round hook** (05), and also at the start of `mesh replicate` and
  `mesh usage` (so a one-shot run publishes fresh data).
- It's idempotent: running twice with no new traffic mints nothing.
- **Batching:** one `usage.counter` item per changed `(mesh_project, day, provider,
  model)` per run, inside the per-origin rate cap (D12). If the cap would be exceeded,
  publish the oldest changes first and continue next round. Record this in status.
- **Retention horizon:**
  - The `mesh.setting` `retention.usage_days` defaults to 90 and is LWW, settable by
    `tethra mesh settings set retention.usage_days <n>`. The `mesh settings` subcommand
    is a small addition here: `get`/`set`/`list`, for retention only.
  - Counters for days older than the horizon are never published, and are
    garbage-collected from views and `mesh_items` on every device.
  - Received items below the horizon are dropped at ingest without being counted as
    rejected.

### 4. Views (`core::mesh::views::usage`)

`usage_report(filter) -> UsageReport`. Per mesh project (merged children folded into the
root), per day or month, and per device, it gives:
- the totals, in the D14 fields;
- `as_of` = that device's last successful exchange time (from `mesh_exchange_log`), or
  "this device" for self;
- `stale` = more than 24 h since `as_of`;
- `removed` = whether the device has been removed;
- `split_known_since`, the per-device cut-over marker. Publish it in `device.info` or as
  a counter field; pick one and document it.

The report also lists the **devices that are bound but have never published** ("no data
from X"). Totals are reported **per device and summed across devices only with an
explicit label**: "estimated, gateway-observed, across N devices; M stale".

### 5. CLI

- `mesh project share|bind|unbind|rename|archive|merge|list`.
- `mesh usage [--project] [--month] [--day] [--by-device] [--json]`.
- `mesh settings get|set|list`.
- **Human output** puts the honesty labels first. Unpriced and unextracted counts are
  always shown when nonzero.
- `tethra usage` (the existing command) is **unchanged**. SI-19 keeps provider-reported
  usage separate; add a one-line hint pointing to `tethra mesh usage` when the mesh is
  initialized.

### 6. SI-19 amendment

Edit `docs/gateway/SECURITY_INVARIANTS.md` SI-19 per D14: coverage may now include
paired devices, labelled per device with freshness; a missing device is unknown, not
zero; and the figures are never summed with provider-reported cost. Then make sure
`crates/gateway/tests/documentation_claims.rs` still passes.

### 7. Smoke

Two nodes, where each data dir uses its own isolated gateway test database.
1. A shares project P and binds it.
2. Seed `gateway_usage_daily` rows on A with a direct `sqlite3` insert into A's
   temp `vault.db`. Smoke runs on macOS in CI, where `/usr/bin/sqlite3` exists. Smoke
   uses neither `sqlite3` nor `gateway serve` today (checked at planning time), and a
   hidden seeding command in release builds is **not** acceptable. Add a comment saying
   the full path (real gateway writer → publisher → replication) is covered by the
   Rust integration test in `mesh_usage.rs`, which drives the gateway writer's own
   persistence function.
3. Replicate.
4. B binds P.
5. `mesh usage --json` on B shows A's numbers labelled with A's device and an `as_of`.

## Out of scope

Caps (07), desktop (10), replicating request-level events (never).

## Tests to write

- **`crates/core/tests/mesh_usage.rs`** (or `crates/gateway/tests/mesh_publish_e2e.rs`
  if the writer's persistence function is only reachable from the gateway crate):
  - **End to end:** exchanges persisted through the gateway writer's own persistence
    path, then the publisher, then `SqliteStore` replication to a second store, then
    `usage_report` on the second store showing the first device's labelled totals.
  - **Publisher deltas:** traffic, then publish, then more traffic, then publish, gives
    correct cumulative totals.
  - **Rebinding mid-day:** pre-rebind traffic stays with M and post-rebind traffic goes
    to N.
  - **Deletion:** `delete_project_data` then publish gives an epoch bump, and after
    replication the peer shows the reduced totals.
  - The retention sweep bumps the epoch the same way.
  - Sentinel rows are skipped.
  - Running the publisher twice is idempotent.
  - The rate cap defers the remainder to the next round.
  - **Bindings:** never automatic (sharing on A creates no binding on B until `bind`);
    deleting a local project cascades its binding; a second bind of the same project is
    refused.
  - **Merge:** counters fold into the root; merge is refused when both have caps (use
    fixture cap views).
  - **Views:** per-device labels, a stale device after 24 h (injected clock), a removed
    device labelled, "no data from X", and the split cut-over.
  - **Privacy:** for every item kind published here, the payload contains **no**
    path, endpoint, host, request id, credential reference or digest. Make it a
    structural assertion over the payload keys.
- **Simulator:** extend the 02 workload with the publisher's epoch semantics so that
  epoch-bump convergence is covered under faults.
- **Gateway:** the writer populates the split columns.
- **CLI:** the `mesh project` and `mesh usage` flows across two temp dirs.

## Acceptance criteria

- [ ] Usage generated on device A appears on device B, labelled and fresh, end to end through real nodes.
- [ ] A deletion on A propagates to B.
- [ ] Unpriced and unextracted traffic are never shown as $0; they are counted separately.
- [ ] MESH-SI-11 and MESH-SI-13 have named tests.
- [ ] The SI-19 amendment is in place and `documentation_claims` passes.
- [ ] Smoke passes, and the check suite is green.

## Verification commands

```bash
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --test mesh_usage --test mesh_schema
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-gateway
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --features mesh-sim --test mesh_sim
bash scripts/smoke.sh
```

## Docs to update

- `docs/mesh/USER_GUIDE.md`: sharing and binding, reading `mesh usage`, retention.
- `docs/mesh/ARCHITECTURE.md`: the publisher.
- `docs/mesh/KNOWN_LIMITATIONS.md`: origin-side pricing, cached-token undercount, and the
  pre-v23 split being unknown.
- `docs/gateway/SECURITY_INVARIANTS.md` (SI-19).
- `docs/gateway/PRIVACY.md`: the deletion tools also propagate to paired devices through
  the epoch.
- `CHANGELOG.md`.

## Handoff checklist

- [ ] STATUS.md row 06 `done`.
- [ ] Handoff notes:
  - how "local month spend for a bound project" is computed; 07 and 08 reuse it, so
    there must be a single function;
  - the round-hook ordering.
