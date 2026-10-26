# Tethra Mesh — Test Plan

How Tethra Mesh is tested, layer by layer ([ADR 0031](../decisions/0031-device-mesh.md)).
Every MESH-SI invariant names at least one test here or in
`SECURITY_INVARIANTS.md`. Tests use only unmistakably fake keys and never touch
the network beyond `127.0.0.1:0`.

## Layers

| Layer | Where | What | Status |
|---|---|---|---|
| Algebraic laws | `crates/core/src/mesh/crdt/*` unit tests | Commutativity, associativity, idempotence and monotonicity of every join (LWW map, owner-counter map and its epoch lattice, roster, bounded counter, version vectors), 10 000 seeded `SplitMix64` cases each; roster resolution and LWW values independent of join order | **implemented (01)** |
| CRDT specifics | same | LWW: max over admitted origins, removal fallback, origin tie-break, seq-over-HLC within an origin. Owner counter: epoch bump, field-wise max, honest latest = lattice join (10k), regression flag. Roster: genesis, non-member adds, chains, cutoffs, removed-is-forever, max cutoff, mutual removal, removed adder, genesis removal, fork reports, known-set monotonicity. Bounded: avail arithmetic, spend/transfer/burn refusal, conservation, burn, forged over-transfer, clamp order, overshoot stays with the overspender, cycles, admission, cap safety over 10 000 honest multi-replica sequences | **implemented (01)** |
| Worked examples | `protocol_md_worked_example(s)` in `lww_map`, `roster`, `bounded` | Every worked example in PROTOCOL.md §5-6, asserted | **implemented (01)** |
| HLC | `mesh::hlc` unit tests | Monotonic under a stalled and a backward clock, logical overflow, drift clamp and skew report, `local_write_ts` beats a far-future winner without moving the clock, `restore` never goes backwards, restart from high water, 20 000-step randomized walk | **implemented (01)** |
| Codec and signing | `mesh::codec`, `mesh::sign`, `mesh::item`, `mesh::kinds` unit tests; `tests/mesh_foundations.rs` | Exact bytes, round trip, determinism over 10 000 random bodies (including reversed map insertion order), escaping, non-canonical forms, duplicates, floats and `-0`, depth and size limits, newer format, unknown envelope field, every kind round-trips, origin bindings, weak keys, opaque unknown kinds, exhaustive byte-flip tamper detection (3 masks × every byte), wrong mesh, wrong key, forged origin | **implemented (01)** |
| Leakage | `sign::tests`, `kinds::tests`, `tests/mesh_foundations.rs` | `Debug`/`Display` of signing keys, signed items and sealed shares, and every verification error (also via `CoreError`), never contain secret key bytes, signature bytes or sealed bytes | **implemented (01)**; canaries extend in 04 and 11 |
| Protocol and simulator | `crates/core/tests/mesh_sim.rs` (feature `mesh-sim`) | N nodes with seeded drop, duplicate, reorder, delay, partition and heal, crash mid-session, restart, clock skew, removal, fork; invariants: convergence to the oracle, commit-only VV, removal exclusion, fork detection, cap safety, no forged origin. 200 seeds in < 60 s; replay with `MESH_SIM_SEED` | specified, lands in 02 |
| Independent oracle | `sim/oracle.rs` | A naive model written from PROTOCOL.md alone by an isolated subagent | specified, lands in 02 |
| Store conformance | `crates/core/tests/mesh_store_conformance.rs` | The simulator suite against `SqliteStore`, plus crash between commit chunks | specified, lands in 03 |
| Schema | `crates/core/tests/mesh_schema.rs` | Migrations v21/v22, STRICT, restore wipe, the `migration_safety` exemption | specified, lands in 03/06 |
| Transport | `crates/mesh/tests/*` | Pair, replicate, remove, rotate, bounds, malformed frames, handshake floods, wrong psk, removed key, bind guard | specified, lands in 04-05 |
| CLI | `apps/cli/tests/mesh_cli.rs` | init/invite/join/replicate/usage/cap across temp `TETHRA_DIR`s | specified, lands in 03+ |
| Gateway | `crates/gateway/tests/cap_enforcement.rs` | 403 shape, before upstream bytes, one in flight near exhaustion, fail-open, fence acks, no DB on the hot path | specified, lands in 08 |
| Desktop | vitest + `tauri_command_authz.rs` | Views, reauth enforcement, error redaction | specified, lands in 09-11 |
| Mutation | `scripts/mutation_checks.sh` | Mutants: VV before commit, signature check skipped, drift clamp removed, escrow fence skipped, view clamp removed, cutoff ignored | specified, lands in 12 |

## Running

```bash
# All mesh unit tests (law tests included); < 2 s in debug.
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core mesh
# Cross-module foundations.
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --test mesh_foundations
```

Randomized tests print `MESH_SIM_SEED=<seed> case <n>` on failure. The seeds are
fixed in the source, so a failure reproduces exactly on rerun.
