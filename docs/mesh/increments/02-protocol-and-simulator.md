# Increment 02: Sans-IO protocol and deterministic simulator

**Mode:** O (orchestrator plus one isolated oracle subagent) · **Size:** L · **Prerequisites:** 01 done

## Goal

1. Build the replication protocol as a pure state machine, with an in-memory store and
   the materialized views.
2. Prove the protocol correct under adversarial network conditions with a seeded,
   replayable simulator, checking it against an **independently written oracle**.

This is the distributed-systems heart of the project. The simulator is the tool every
later increment uses to show it hasn't broken convergence or cap safety.

## Read first

- DESIGN §D5 (fork and rollback), §D6-D10, §D12, §D15 (bounded-counter use in simulation) and §D21.
- `docs/mesh/PROTOCOL.md` and `docs/mesh/SECURITY_INVARIANTS.md` (from 01).
- `crates/core/src/mesh/**`, all of it (from 01).
- The STATUS.md handoff notes for 01.

## Scope (build all of this)

### `core::mesh::store`

`pub trait MeshStore`, with the operations the protocol and views need. **Minimum:**

| Group | Operations |
|---|---|
| Self | self identity read |
| Version vector | `vv()` |
| Reads | `items_after(origin, seq_exclusive, limit)`; latest item by `(kind, key, origin)`; max seq held per origin |
| Atomic commit | `commit(staged_items, upto_vv) -> CommitOutcome`: store the items idempotently, detect forks (same dot, different hash, so record `ForkEvidence`), garbage-collect superseded same-origin rows, update views and advance the VV, **all atomically** |
| Mint | `mint(body) -> SignedItem`: allocate the seq, sign, commit locally (for local writes) |
| Repair | bucket digests and items by bucket |
| Counters | rejected items, clock-skew flags, fork evidence list |
| Views | the `views::State` read |

`memstore::MemStore` implements it, with commit atomicity simulated: copy on write,
then swap.

### `core::mesh::views`

- `State` holds the roster, the device info and settings, `project.meta` maps, usage
  counters, caps (def, targets, rights, used) and shares.
- It is computed **incrementally** on commit, and `views::rebuild(items) -> State` exists
  as a pure function.
- An invariant check asserts that incremental equals rebuild.
- The admission rules come from `crdt::roster` (D8/D10). View clamping comes from
  `crdt::bounded`.

### `core::mesh::proto`

- Frame types (D9), serde-tagged with `t`, plus `Session`:
  `Session::new(role, local_snapshot, clock, limits)`, `start() -> Vec<Action>` and
  `on_frame(Frame) -> Result<Vec<Action>, ProtoError>`.
- `Action` is one of: `Send(Frame)`, `Commit { items, upto }`, `Direct(DirectMsg)`
  (surfaced to the caller: `AccessKeyUpdate`, `RightsRequest` and `RollbackNotice`
  are handled by higher layers), or `Close(reason)`.
- **Rules:**
  - Hello negotiation: mesh_id and version range.
  - Compute the peer's missing ranges from its VV and stream batches, ≤ 512 items or
    1 MiB each.
  - **Stage and verify** every inbound item (D6 checks, using the roster as known so far,
    plus items staged earlier in the *same* session, so a `roster.add` and the new
    member's items can arrive together).
  - **Commit only at `Commit`.**
  - `own_next_seq` rollback detection produces `RollbackNotice`.
  - Repair flow when the VVs match but `digest_root` differs, or when `force_repair`.
  - Bounds: staged count, bytes, and the per-origin rate cap.
  - **Pure:** no I/O, no wall clock (time comes through the `Clock` trait), no randomness
    except an injected RNG.

### `core::mesh::sim` (feature `mesh-sim`)

Enable it in core tests through a self dev-dependency, following the
`crates/tracking/Cargo.toml:37-43` pattern.

- **Deterministic world:**
  - virtual time;
  - `SplitMix64`-driven scheduling;
  - N nodes, each a `MemStore`, an identity, and a `ManualClock` with a per-node skew of
    up to ±10 min, some above `MAX_DRIFT`;
  - links with probabilities for drop, duplicate, reorder and delay.
- **Fault events:** partition and heal (arbitrary groups); crash, which loses in-flight
  sessions and staged items; restart from the store; slow nodes.
- **Workload generator** (weighted random), covering every kind:
  - `project.meta` LWW writes from any node;
  - `usage.counter` updates, including epoch bumps;
  - roster add (a new node joins through an existing one) and remove (with cutoff);
  - `cap.def`, mint, transfer, burn and `used` updates driven by a local "spend" that
    always checks `avail` first.
- **Adversarial injections:**
  - **forged origin**: a member signs an item claiming another origin;
  - **replay of an old item**;
  - **fork**: clone a node's identity and store into a second node and let both mint;
  - **mid-session crash** of the sender after some batches;
  - **huge-seq forgery**;
  - **far-future HLC**.
- **Invariants**, checked after every step (cheap ones) or at quiescence (expensive ones):
  1. **Commit-only VV.** For every node and origin, every seq ≤ `vv[o]` is either stored
     or superseded by a stored same-origin, same-key item. Garbage-collected roster and
     cap.def items are never missing.
  2. **Convergence to the global join.** After heal, plus K quiescent rounds of all-pairs
     exchange, every node's `views::State` is equal, **and** equal to the oracle's state
     computed from all valid items ever minted.
  3. **Incremental views = rebuild** on every node.
  4. **Removal exclusion.** Nothing above a removed origin's cutoff contributes to shared
     LWW values on any node at quiescence.
  5. **Fork detection.** At quiescence every node holds `ForkEvidence` for a forked
     origin and accepts no new items from it.
  6. **No forgery accepted.** No item with a forged origin is ever stored, and a
     huge-seq forgery never advances any VV.
  7. **Cap safety.** For every `(cap, month)`: `Σ U ≤ Σ minted − Σ burned`, on every
     node's view and in the oracle. (Spend in the simulator checks `avail`, so overshoot
     is 0 here; 08 handles real overshoot.)
  8. **Bounds.** Staging never exceeds its limits.
  9. **Clock safety.** No observation moves a node's HLC past its own
     `now + MAX_DRIFT` (`last ≤ max(previous last, now + MAX_DRIFT)`). Amended in 01:
     after a node's physical clock steps back, `last` may already sit above the new
     bound and must not climb further; `local_write_ts` lifts single writes without
     moving `last` (PROTOCOL.md §4).
- **Replay:** `MESH_SIM_SEED=<u64>` and `MESH_SIM_STEPS=<n>` run exactly one seed. Every
  failure message prints `MESH_SIM_SEED=… MESH_SIM_STEPS=…` and the minimized event
  index. Also add a shrinking helper that retries with fewer steps until the shortest
  failing prefix is found.
- **Tests in `crates/core/tests/mesh_sim.rs`:**
  - CI: 200 seeds × ~2 000 steps, 3-6 nodes, in under 60 s in debug.
  - One `#[ignore]` soak test reading `MESH_SIM_SEEDS`.
  - Add `scripts/mesh_soak.sh`: runs the ignored soak in `--release` for a given number
    of seeds or minutes, and prints any failing seed.

## Execution workflow (O)

1. **Contract (you, the orchestrator). Commit it before spawning.**
   - Update `docs/mesh/PROTOCOL.md` so it fully specifies the frames, session, commit and
     repair (D9) and the view semantics for every kind. Fix any ambiguity now.
     Increment 01 left two items explicitly for this step (STATUS.md handoff notes):
     how fork evidence reaches every node (PROTOCOL.md §7 — with latest-only storage a VV
     comparison cannot see a fork), and per-kind view rules beyond the CRDTs (which
     `cap.def` wins if two origins publish one cap id; how `share.sealed` and
     `share.revoke` order).
   - Write `crates/core/src/mesh/sim/oracle_api.rs`:
     - `pub trait OracleModel { fn new(genesis: &GenesisInfo) -> Self; fn observe_minted(&mut self, item: &SignedItem); fn expected(&self) -> ExpectedState; }`
     - `ExpectedState`: plain structs mirroring `views::State`'s comparable content,
       with the conversion `impl From<&views::State> for ExpectedState`.
   - Commit: `docs(mesh): specify protocol v1 sessions and oracle contract`.
2. **Spawn the oracle subagent** (`subagent_type: general-purpose`) **in parallel with
   your own work.** Its prompt must include:
   - **Goal:** implement `crates/core/src/mesh/sim/oracle.rs`, a deliberately naive,
     obviously-correct model. It keeps every valid item ever minted (it is told about
     every mint, including forged and forked ones). `expected()` recomputes the state
     **from scratch** by brute force, straight from PROTOCOL.md's definitions: per-origin
     latest **by seq** (PROTOCOL.md §5.1; the epoch-lexicographic lattice is the
     honest-writer rule, not the per-origin join), LWW max over admitted origins, the
     roster with its stratified resolution, cutoffs and genesis (§6), bounded-counter
     one-hop clamped views (§5.5), fork handling (an origin with
     two hashes at one dot is forked; it excludes items after the fork point exactly as
     PROTOCOL.md says), and forged-origin rejection by signature check.
   - **Allowed reading:** `docs/mesh/PROTOCOL.md`, `docs/mesh/increments/DESIGN.md`
     (§D6-D10, §D15), `crates/core/src/mesh/sim/oracle_api.rs`, and the public types in
     `mesh/item.rs`, `mesh/codec.rs`, `mesh/sign.rs`, `mesh/dot.rs` and `mesh/hlc.rs`
     (decode and verify only).
   - **Forbidden:** `mesh/crdt/**`, `mesh/views.rs`, `mesh/proto.rs`, `mesh/memstore.rs`
     and `mesh/sim/world.rs` (or whatever you name the simulator). It must not import
     `crate::mesh::crdt` or `views`. Its independence is the point. If PROTOCOL.md is
     ambiguous, it should say so in its report and choose the most literal reading;
     it must not peek.
   - **Owned files:** only `crates/core/src/mesh/sim/oracle.rs`, and the oracle's own
     unit tests inside it.
   - **Tests:** unit tests built from every worked example in PROTOCOL.md.
   - **Commands:** `API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --features mesh-sim oracle`.
   - **Rules:** do not commit, do not touch git, do not edit other files, and do not run
     `cargo fmt --all`. Run `rustfmt` on its own file only.
   - **Report:** a list of spec ambiguities found and how it resolved each one.
3. **Meanwhile, you implement** `store.rs`, `memstore.rs`, `views.rs`, `proto.rs` and the
   simulator world. These files are disjoint from the oracle's.
4. **Integrate.**
   - Wire `OracleModel` into invariant 2 and run the seeds.
   - **Every disagreement is investigated**: is it an implementation bug, an oracle bug,
     or a spec ambiguity? Fix the spec first when it is ambiguous, then the code. Record
     each disagreement and its resolution in STATUS.md "Handoff notes". That record is
     the evidence the oracle earned its keep.
5. Commit and push. Only you commit.

## Out of scope

SQLite (03), networking (04), the real publisher and caps policy (06/07). The simulator
drives cap operations directly.

## Acceptance criteria

- [ ] `proto` and `views` are pure: no `std::net`, `std::fs`, `SystemTime` or `thread`
      usage. Check with `grep` and record the command.
- [ ] Every one of the 9 invariants is implemented and exercised. Each adversarial
      injection has a test that **fails when the corresponding defence is disabled**.
      Demonstrate this by temporarily commenting it out and recording the failing seed in
      STATUS.md; don't commit the mutation.
- [ ] The oracle was written by the isolated subagent. Its ambiguity report and every
      oracle/implementation disagreement are recorded in STATUS.md.
- [ ] The CI simulator test runs 200 seeds in < 60 s. Replay via `MESH_SIM_SEED`
      reproduces a failure deterministically: same event trace hash.
- [ ] `scripts/mesh_soak.sh` works. Run it for 10 minutes in release and record the
      result.
- [ ] The check suite is green.

## Verification commands

```bash
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --features mesh-sim --test mesh_sim
MESH_SIM_SEED=12345 MESH_SIM_STEPS=5000 cargo test -p api-tracker-core --features mesh-sim --test mesh_sim replay
bash scripts/mesh_soak.sh --minutes 10
# plus the full README §3 suite
```

## Docs to update

- `docs/mesh/PROTOCOL.md`: mark it as implemented (02).
- `docs/mesh/TEST_PLAN.md`: the simulator section, the invariants list, and replay
  instructions.
- `docs/mesh/SECURITY_INVARIANTS.md`: list the tests for MESH-SI-3, 4 and 8.
- `CHANGELOG.md`.

## Handoff checklist

- [ ] STATUS.md row 02 is `done`, with the oracle disagreement log and the soak result.
- [ ] Handoff notes describe the `MeshStore` trait surface 03 must implement, and the
      seed corpus of any interesting failing seeds, kept as regression tests.
