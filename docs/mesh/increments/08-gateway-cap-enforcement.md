# Increment 08: Gateway cap enforcement

**Mode:** S+R, single session plus a hot-path reviewer before the final commit · **Size:** M · **Prerequisites:** 07 done

> **Amended by Increment 07 (2026-10-28).** What 07 built for this
> increment (STATUS.md, 07 handoff, has the details):
> - **The ack contract** is `core::mesh::caps::escrow::ack(conn, ids,
>   generation)`: it moves `pending` rows to `acked` with the snapshot's
>   generation. Open rows are `pending` + `acked`
>   (`escrow::open_amount`); read them in the **same read transaction** as the
>   cap items. The node publishes acked rows at its next round, not within the
>   round.
> - **`gate_snapshot` is not built yet**: build it from
>   `caps::view::{caps_in, month_figures}` (enforce only caps that are
>   `in_force()`: a *superseded* cap is never enforced; a *frozen* cap keeps
>   its current rights), `caps::escrow::open_amount` and
>   `usage::local_month_spend_in`. `caps::view::Ledger::local_avail` is the
>   node-side figure the gate's `avail` must agree with (it already counts
>   unpublished spend and open escrow); `caps::try_spend` is the strict check.
> - **Liveness probe:** the node uses `crates/mesh::node::GatewaySocket`
>   (Unix: the control socket; Windows: always "running", so transfers wait
>   for the ack). Add the Windows listener-identity probe here.
> - Enforcement is consulted through `caps::escrow::enforcement_on(conn)`
>   (`gateway_config.cap_enforcement`); keep the per-cap opt-in consistent
>   with it.

## Goal

Let a user opt in, per cap and per device, to having the local gateway **refuse**
requests once this device's rights are exhausted. Rules:
- The forward path never waits on the database or the network.
- Overshoot is bounded to one in-flight request's cost.
- Refusals are non-retryable 403s that SDKs surface clearly.
- Rights are never double-spent across the escrow fence.
- Failure modes are fail-open, and they are reported loudly.

## Read first

- DESIGN §D15 (Enforcement and Escrow fence) and §D19 (MESH-SI-9/10).
- ADR 0032.
- `crates/gateway/src/routes.rs:784-900` (`RouteState`: the snapshot plus `data_version` poller pattern to copy) and `crates/gateway/src/service.rs` (23, 301-401: the poller thread and boot).
- `crates/gateway/src/forward.rs`:
  - 325-342 `local_response` (text/plain only);
  - 683+ `handle_request` ordering;
  - 836-913 record scaffold and `forward_exchange`.
- `crates/gateway/src/usage.rs` (where response usage is extracted at completion), `crates/gateway/src/record.rs` and `crates/gateway/src/control.rs` (`Status` op, `instance_is_live` at 1023, Windows at 1028).
- `docs/gateway/SECURITY_INVARIANTS.md` SI-11 to SI-14 and SI-19, and `docs/decisions/0019-local-gateway.md`.
- `crates/gateway/tests/common/mod.rs` (`RunningGateway`, `MockUpstream`), `crates/gateway/tests/perf.rs` and `scripts/gateway_perf.sh`.
- The STATUS.md handoff notes for 07.

## Scope (build all of this)

### 1. `crates/gateway/src/capgate.rs`, `CapGate`

- **Snapshot.** `Arc<CapSnapshot>` behind the same swap pattern as `RouteState`. It is
  rebuilt by the **existing poller thread** when `data_version` changes, plus at least
  every 5 s. It holds, per enforced cap for the current month:
  - `granted` (minted to self, plus received, minus given; from the mesh views via
    `core::mesh::caps::gate_snapshot(conn, now)`);
  - `persisted_spend` (the single 06/07 month-spend function);
  - `escrowed` (pending plus acked, not yet published);
  - the route prefixes and project ids that map to the cap;
  - a `generation`.

  **The gateway links only `api-tracker-core`.** The `no_mesh_dependency` test from 04
  must still pass.
- **Fence acks.** After building a snapshot that includes pending escrow rows, the
  poller writes `acked_generation = generation` for them in a short transaction. This is
  the gateway half of MESH-SI-10.
- **In-memory spend.** On response completion, at the point where the usage tap has
  final token counts and the cost estimate is computable, add the exchange's estimated
  cost to `AtomicU64 spend_since_snapshot[cap]`.
  - This is independent of the writer queue, which may drop records (SI-12).
  - When a new snapshot's `persisted_spend` absorbs those records, reset the delta by
    generation. Design this so a record is never counted twice and never missed: tag
    in-memory increments with the snapshot generation they arrived under, and subtract
    what persistence has caught up on (the writer exposes a monotone `persisted_cost`
    counter per cap). Document the reasoning and test it.
  - If the writer has dropped records for a capped project, set `accounting_incomplete`.
- **Admission decision** (hot path; reads only the `Arc` and atomics):
  `avail = granted − escrowed − persisted_spend − spend_since_snapshot`.
  - `avail ≤ 0` → refuse.
  - **Near exhaustion** (avail < max(2 × the p95 request cost observed this month on this
    device, 500 000 micros)) → admit **at most one in flight** for that cap through an
    atomic flag. A concurrent request while one is in flight is refused with the same
    403 and `reason=cap_near_exhaustion_serialized`, so the user sees why.
  - Cost unknown at admission time (no pricing for the model) → admit, count it as
    unpriced, and show it in status. Never block on unknown.
- **Opt-in.** Only caps with local enforcement on are enforced. Read the flag from
  the local-only `mesh_meta` key `cap_enforce/<cap_id>` = `1`. That needs no new
  migration, and `mesh_meta` never replicates, so peers can't change it (MESH-SI-9).
  - The global switch is `gateway_config.cap_enforcement` (v21).
  - The core method `UnlockedVault::mesh_cap_enforce(master_password, cap | All, on)`
    requires reauth and writes an audit event.
- **Response.** A new `local_response_json(client, 403, body, extra_headers)` alongside
  `local_response`:
  - a provider-shaped body for OpenAI-style and Anthropic-style routes (D15);
  - `x-tethra-cap: exceeded; cap=<id>; month=<YYYY-MM>`;
  - `content-type: application/json`.

  It is sent **before any upstream connect**: admission sits in `handle_request` after
  route resolution, before `forward_exchange`.
- **Never 429** (the SDKs retry it). Add a test asserting the status code.
- **Fail open.** When the cap tables are unreadable, the schema is mismatched (the
  gateway's `open_at_current_version` path), the mesh isn't initialized, or the snapshot
  is older than 60 s (a stuck poller), the gate admits everything and sets
  `inactive_reason`.

### 2. Status surfaces

- **`gateway status`** (control `Status`) gains `caps: [{cap, enforced, avail_micros,
  near_exhaustion, accounting_incomplete, inactive_reason}]`.
- **`mesh status`** and **`mesh cap show`** read and display it from the gateway's
  control socket (Unix) or the snapshot fields persisted in `mesh_meta` by the poller,
  which also works on Windows. Choose one and document it; the second is simpler and
  cross-platform.

### 3. CLI

`mesh cap enforce <cap|--all> on|off`, with the reauth prompt and a clear explanation:
- requests over the cap are refused locally;
- other devices enforce only if they opt in themselves;
- anything that bypasses the gateway bypasses the cap.

### 4. Escrow (node side)

The node side from 07 now waits for real acks when enforcement is on **and** the gateway
is live:
- Unix: `instance_is_live`.
- Windows: the `verify_listener` probe, because `instance_is_live` is always false there.

### 5. Security invariants

Add **SI-22 "Cap gate"** to `docs/gateway/SECURITY_INVARIANTS.md`: the hot path is
read-only, the 403 is sent pre-upstream, it fails open, and enforcement is opt-in and
local. Update MESH-SI-9/10 to "implemented", with tests.

## Execution workflow (S+R)

Implement and test it all, run `bash scripts/gateway_perf.sh`, and compare against
`docs/gateway/PERFORMANCE_RESULTS.md`. A regression above 5% p50 or 10% p99 on the
admission path must be fixed or justified.

Then, **before the final commit**, run the README §4 review. The focus is:
- the hot path doing any I/O or taking a lock that the writer also holds;
- double counting or undercounting between in-memory and persisted spend;
- fence races (gateway boot during a transfer; a snapshot built between the escrow
  insert and the ack);
- the one-in-flight logic under concurrency (lost wakeups, a flag stuck after a client
  disconnect or an upstream error — **the flag must clear on every exit path**);
- 403 body shape and headers;
- fail-open coverage;
- leakage of credentials or authorization in the 403 body.

## Out of scope

The desktop toggle (10), and blocking anything the gateway doesn't see (impossible;
document it).

## Tests to write

- **`crates/gateway/tests/cap_enforcement.rs`** (`RunningGateway` + `MockUpstream`,
  fixture mesh views written through core):
  - Under the cap, requests forward.
  - At exhaustion, the gateway returns 403 with the exact JSON and headers, and the
    `MockUpstream` saw **zero** connections for the refused request.
  - Near exhaustion with 8 concurrent requests: exactly one forwards and the rest get the
    serialized 403. After completion the flag clears, including when the upstream errors,
    the client disconnects mid-stream, or a timeout fires.
  - Only opted-in caps are enforced. A peer-replicated item can't enable enforcement:
    simulate a forged `mesh.setting` and assert it is ignored.
  - Fail-open for each `inactive_reason`.
  - In-memory plus persisted accounting under a writer that drops records (use the
    existing writer test hooks): never double counted, `accounting_incomplete` set.
  - **Fence.** Insert a pending escrow; the poller acks it within one poll; avail drops
    *before* the transfer is published, and never rises again when the transfer
    publishes (no double-subtract either).
  - **Restart.** A gateway that starts while escrow is pending counts it.
  - Status JSON fields.
- **`crates/gateway/tests/perf.rs`:** an `#[ignore]` admission-path benchmark, run by
  `gateway_perf.sh`.
- **Privacy canaries:** the 403 body never contains authorization or credential bytes.
  Use the `FAKE_KEY` pattern.
- **End to end (CLI):** two nodes with a cap. Exhaust A's rights through a foreground
  `gateway serve` on A in a temp dir against the mock upstream. A gets the 403. B grants
  rights. Through the fence, A's next request succeeds. **Foreground gateway only; never
  install a service.**

## Acceptance criteria

- [ ] All of the tests above pass. MESH-SI-9/10 and SI-22 are documented with test names.
- [ ] Perf is within budget, and the numbers are recorded in `docs/gateway/PERFORMANCE_RESULTS.md`.
- [ ] The review was run, with findings resolved or rejected with reasons.
- [ ] The CLI flow works end to end with a foreground gateway in a temp dir.
- [ ] The check suite and smoke are green.

## Verification commands

```bash
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-gateway --test cap_enforcement --test no_mesh_dependency
bash scripts/gateway_perf.sh
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-cli --test mesh_cli
bash scripts/smoke.sh
# NEVER: scripts/gateway_validate_macos.sh, tracking --scope full, launchctl, gateway install
```

## Docs to update

- `docs/gateway/SECURITY_INVARIANTS.md` (SI-22) and `docs/gateway/PERFORMANCE_RESULTS.md`.
- `docs/gateway/USER_GUIDE.md`: the cap refusal and what SDK users will see.
- `docs/mesh/USER_GUIDE.md` and `docs/mesh/KNOWN_LIMITATIONS.md`: bounded overshoot,
  bypassing the gateway, unpriced models never blocked.
- ADR 0032: the enforcement section, now implemented.
- `CHANGELOG.md`.

## Handoff checklist

- [ ] STATUS.md row 08 `done`, with the perf numbers and the review summary.
- [ ] Handoff notes: the Tauri-facing core APIs that 10 will call for caps and the
      enforcement toggle.
