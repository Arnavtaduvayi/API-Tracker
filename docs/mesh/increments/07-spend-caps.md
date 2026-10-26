# Increment 07: Spend caps (bounded counter; alerts only)

**Mode:** S · **Size:** L · **Prerequisites:** 06 done

## Goal

Add replicated monthly **spend caps** on mesh projects. The global invariant "total
gateway-estimated spend across all devices ≤ cap" is maintained **without
coordination** by a bounded-counter CRDT.

Each device holds *rights* and spends only its own. Rights flow between devices through
owner-signed transfers, with hysteresis-based rebalancing. A partitioned device stays
capped, choosing safety over liveness. A month's rights are minted in advance so
devices that are offline across the month boundary aren't stranded.

This increment raises **alerts only**. Gateway blocking comes in 08, but the escrow
fence table and the node side are built now.

## Read first

- DESIGN §D8 (bounded), §D15 (all of it) and §D19 (MESH-SI-10).
- ADR 0031.
- Balegas et al. 2015, "Extending eventually consistent cloud databases for enforcing numeric invariants" (SRDS). Cite it in ADR 0032. Summarize it from your knowledge; don't fetch paywalled PDFs.
- `crates/core/src/budget.rs` (20-25 `period_start`; understand it, **do not use or modify** budgets).
- `crates/core/src/alerts.rs` (rule kinds, dedup keys) and `crates/core/src/monitor.rs` or `run_monitor` (`vault.rs` around 2193-2260), which is how alerts are raised.
- The STATUS.md handoff notes for 06, which point to the single "local month spend" function.

## Scope (build all of this)

### 1. `core::mesh::caps` (policy; the pure parts are unit-testable)

- **`create(mesh_project_id, monthly_micros)`**, on this device, which becomes the
  immutable owner. It mints `cap.def` and the current month's `cap.rights`
  (owner→owner = monthly), plus `cap.target` for the month.
  - One cap per mesh project. A second is refused.
  - Merged projects follow D11.
- **Month instances** key off UTC `YYYY-MM`, with the same semantics as
  `budget::period_start`. **Write a new helper; don't call `budget`** (SI-19
  separation), and test that the two agree on boundaries.
- **Advance minting** (owner node round hook): from day 20 of month m, the owner mints
  month m+1 (the current target, or an LWW-scheduled change) and pre-distributes equal
  shares to devices active in the last 30 days (D15).
- **Distribution and rebalancing** (round hook plus a `Direct RightsRequest` handler on
  the node):
  - The fair share is `target / active_devices`.
  - A device asks when its available amount is below 20% of its share. A donor grants
    `min(want, avail − 50% share)`.
  - All thresholds are constants with docs, and tested.
  - Rate limit: at most 1 request per peer per cap per 5 minutes.
- **`raise(cap, x)`.** On the owner, it mints `+x` and raises the target by x. On a
  non-owner, it is a **local override** (D15): a self-mint with `override = true`, after
  an explicit confirmation that explains what an override means.
- **`lower(cap, x)`** sets the LWW target. Every holder burns unspent rights above its
  new fair share in the cap reconciler hook. The owner reclaims any remainder with
  `RightsRequest`s. Views show `pending_decrease` until the effective total is ≤ the
  target.
- **`reclaim(cap)`** (owner) is a manual "pull rights back to me" for a device that is
  being decommissioned.
- **Freeze:** if the owner device is removed, the cap is frozen. Views say so and no
  minting happens; the next month has no rights unless the user creates a new cap (the
  CLI suggests how).
- **`used` publishing:** a round hook publishes `cap.used` for this device and month as
  the authoritative local month spend for the cap's bound projects, using **the single
  function from 06**. It is monotone within a month; an epoch bump on decrease follows
  D8.
- **Escrow fence (MESH-SI-10).** Every transfer, burn or reclaim grant goes through
  `mesh_cap_escrow` first (D15):
  - When `gateway_config.cap_enforcement` is **off** (always true in this increment) or
    the gateway is provably not running, publish immediately and mark the row
    `published` in the same transaction.
  - Otherwise wait for `acked_generation`. The gateway ack arrives in 08; write and test
    the waiting state machine now with a fake acker.
- **Views (`views::caps`)** give, per cap and month:
  - target;
  - minted, burned and overrides;
  - per device: rights in, rights out, used, available (clamped, D8);
  - pending_decrease;
  - frozen;
  - freshness per device (as in 06).

### 2. Alerts

Add a new alert rule kind in the existing alert system, with dedup keys
`mesh_cap:<cap>:<YYYY-MM>:80` and `:100`, triggered from the views when **this device's
view** of total used versus target crosses each threshold. The alert text makes clear
the figure is cross-device, estimated, and as of the last exchange. Alerts are local
and raised when the vault is unlocked, in the same lifecycle as other alerts. Never
touch `budget.rs`.

### 3. CLI

- `mesh cap create <mesh-project> --monthly <usd>`
- `mesh cap raise <cap> <usd>`, with the confirmation text for overrides on non-owners
- `mesh cap lower <cap> <usd>`, with confirmation
- `mesh cap show [<cap>]`
- `mesh cap rights <cap>`, a per-device table
- `mesh cap reclaim <cap>`

Amounts are given in USD and stored as micros. Reuse the existing money parsing and
formatting helpers if there are any (search `pricing`/`budget` for them).

### 4. Simulation on SQLite

A new simulator scenario family (feature `mesh-sim`, SQLite-backed with fewer seeds) has
3-5 devices with a cap. Spend is driven by a workload that calls the **real**
`caps::try_spend` (local avail check). Inject:
- partitions of every shape;
- an owner offline across the month boundary (advance minting must cover it);
- concurrent `lower`s;
- an override on a partitioned non-owner;
- an owner removal (freeze).

Invariants:
- `Σ used ≤ minted − burned + overrides` per (cap, month), on every node and in the
  oracle;
- no device's available amount is ever negative in its own view;
- rights conservation for transfers;
- the clamped view ignores forged over-transfers;
- liveness: after heal, a device below its threshold receives rights within K rounds if
  any donor has surplus.

### 5. ADR 0032: spend caps

Cover the bounded counter, minting and month rules, raise vs lower, overrides, freeze,
the escrow fence, why caps aren't budgets (SI-19), "a self-limit, not a security
boundary", and the bounded overshoot that 08 implements.

## Out of scope

Gateway enforcement and acks (08), desktop UI (10).

## Tests to write

- **`crates/core/tests/mesh_caps.rs`:**
  - creating a cap (one per project);
  - month boundary helpers versus `budget::period_start`, at the year boundary and in
    leap Februaries;
  - advance minting from day 20 (injected clock);
  - distribution and rebalancing thresholds and the request rate limit;
  - raise on the owner versus an override on a non-owner;
  - lower: burn, reclaim, pending_decrease and convergence;
  - reclaim;
  - freeze on owner removal;
  - `used` publishing from the 06 function;
  - escrow state machine paths (enforcement off publishes immediately; enforcement on
    waits for the ack; the ack lets it publish; a timeout carries it to the next round)
    using a fake acker;
  - alerts at 80% and 100% with dedup and no `budget.rs` involvement (assert that no
    budget alert fires).
- **The simulator scenarios above.** Make sure a failure prints its seed.
- **CLI:** cap flows across two temp dirs with real nodes, so a rights request and grant
  happen over a real `Direct` frame.

## Acceptance criteria

- [ ] The cap-safety invariant holds over the full scenario family on SQLite (CI seeds, plus a 10-minute release soak recorded in STATUS).
- [ ] Advance minting covers an owner that is offline across the month boundary.
- [ ] Lower and override semantics behave as documented, and the CLI explains them.
- [ ] Alerts fire through the existing alert system with the correct labels.
- [ ] ADR 0032 is written. MESH-SI-10's node half has tests.
- [ ] The check suite and smoke (add `cap create`/`show` checks) are green.

## Verification commands

```bash
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --test mesh_caps
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --features mesh-sim --test mesh_sim caps
bash scripts/mesh_soak.sh --scenario caps --minutes 10
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-cli --test mesh_cli
bash scripts/smoke.sh
```

## Docs to update

- ADR 0032.
- `docs/mesh/PROTOCOL.md`: the caps section, now implemented.
- `docs/mesh/USER_GUIDE.md`: caps explained without jargon, covering why a disconnected
  device can hit its cap early and what an override does.
- `docs/mesh/KNOWN_LIMITATIONS.md`.
- `CHANGELOG.md`.

## Handoff checklist

- [ ] STATUS.md row 07 `done`, with the soak results.
- [ ] Handoff notes:
  - the exact `gate_snapshot` inputs 08 needs (which views, the escrow states, the
    single month-spend function);
  - the escrow ack contract (columns, generation semantics).
