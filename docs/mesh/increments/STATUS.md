# Tethra Mesh: increment ledger

Every session reads this file first and updates it at the end (README §1).

**States:** `pending`, `in-progress`, `done`, `blocked` (give the reason).

| Branch | Base | Draft PR |
|---|---|---|
| `feat/device-mesh` | `origin/main` @ `5ec8198` (2026-10-26) | [#19](https://github.com/Arnavtaduvayi/API-Tracker/pull/19) (draft) |

| # | Increment | Mode | Size | State | Started | Finished | Commits | CI run (result) |
|---|---|---|---|---|---|---|---|---|
| 01 | [Foundations & decision](01-foundations-and-decision.md) | S | L | done | 2026-10-26 | 2026-10-26 | `e746a01`, `df3d8ec`, `f888eb1` | CI `40397253597` (success); macOS service `40397253640` (success) |
| 02 | [Sans-IO protocol & simulator](02-protocol-and-simulator.md) | O | L | in-progress | 2026-10-26 | | | |
| 03 | [Persistence & identity](03-persistence-and-identity.md) | S | L | pending | | | | |
| 04 | [Transport & pairing](04-transport-and-pairing.md) | S+R | L | pending | | | | |
| 05 | [Node runtime](05-node-runtime.md) | S | M | pending | | | | |
| 06 | [Shared projects & cross-device usage](06-shared-projects-and-usage.md) | S | M | pending | | | | |
| 07 | [Spend caps (alerts only)](07-spend-caps.md) | S | L | pending | | | | |
| 08 | [Gateway cap enforcement](08-gateway-cap-enforcement.md) | S+R | M | pending | | | | |
| 09 | [Desktop: devices & node](09-desktop-devices-and-node.md) | O | M | pending | | | | |
| 10 | [Desktop: projects, usage & caps](10-desktop-projects-usage-caps.md) | O | M | pending | | | | |
| 11 | [Opt-in credential sharing](11-credential-sharing.md) | S+R | L | pending | | | | |
| 12 | [Hardening, audit & ship](12-hardening-audit-ship.md) | O | L | pending | | | | |

Sizes are rough context cost for a 1M-token session:
- **M** is about 15-25% of the session.
- **L** is about 25-45%.

A session that finishes an M with plenty left should usually continue; check the 40%
rule (README §1 step 12).

## Test counts (update every increment; always print the command next to the number)

| After | Rust tests (command) | Frontend tests | Smoke |
|---|---|---|---|
| base 5ec8198 | ~1,486 (projects-first handoff) | ~261 | 140 |
| 01 `df3d8ec` | **1,591 passed, 0 failed, 9 ignored** (`API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core -p api-tracker-cli -p api-tracker-observe -p api-tracker-gateway -p api-tracker-tracking`); of these, 100 mesh unit tests (`cargo test -p api-tracker-core --lib mesh`, 1.7 s) and 5 in `--test mesh_foundations` | unchanged (not touched) | **140 passed** (`bash scripts/smoke.sh`) |

## Deviations from DESIGN.md

_(Increment, what changed, why, where it's recorded: ADR or doc. Material deviations
also update DESIGN.md and the affected increment files; README §7.)_

| Inc. | What changed | Why | Recorded |
|---|---|---|---|
| 01 | **R1** An origin's order is its `seq` for every kind; D8's per-origin HLC join and epoch-lex counter join become honest-writer rules (a regression is flagged). | The store keeps one item per `(kind, key, origin)` and latest-only relaying needs seq supersession; any other per-origin order lets a misbehaving origin split devices, incremental views and rebuilds. | ADR 0031 R1, PROTOCOL §5.1, DESIGN D8 [Amended 01] |
| 01 | **R2** A removed origin's items above its cutoff keep relaying (and are never garbage-collected); views exclude them. | D10's "never relayed again" leaves devices holding different latest entries for the removed origin forever. | ADR 0031 R2, PROTOCOL §8.3-8.4, DESIGN D9/D10 |
| 01 | **R3** Bounded clamp: one hop, budget `minted + raw_in` (not minus used), burn first then ascending device id. | D8's rule was recursive; a transitive fixpoint is unbounded under hostile values; subtracting used claws rights back from innocent recipients after an honest overshoot. | ADR 0031 R3, PROTOCOL §5.5, DESIGN D8 |
| 01 | **R4** A non-owner self-mint (`R[i][i]`) counts, labelled override. | Reconciles D8 "only the owner may mint" with D15's local override. | ADR 0031 R4, DESIGN D8 |
| 01 | **R5** Roster resolution stratified (reach → conflicts → known → cutoffs → members); conflicting re-adds lock a device out. | Adds/removes/cutoffs were mutually recursive; prevents identity hijack by a re-add. | ADR 0031 R5, PROTOCOL §6.3, DESIGN D8 |
| 01 | **R6** Genesis device id is a mesh parameter carried in `PairAccept`. | A self-add proves nothing alone. | ADR 0031 R6, PROTOCOL §9, DESIGN D10, increment 04 |
| 01 | **R7** `local_write_ts` lifts the write but not the clock; simulator invariant 9 reworded. | Keeps a device's clock within `now + MAX_DRIFT` of observations. | ADR 0031 R7, PROTOCOL §4, increment 02 |
| 01 | Small: payload structs live in `mesh/kinds.rs` (not `item.rs`); `encode_body` returns `Result` (floats/oversize/invalid fields are errors); `SignedItem::verify` plus `verify_with`/`decode_unverified`; `DeviceId::MIN/MAX`; extra id types (`MeshProjectId`, `CapId`, `ShareId`, `CredentialRef`). | Smaller modules; an infallible encoder would have to accept invalid bodies. | this table |
| 02 | **R8** Device ids are derived from the three public keys (BLAKE3 derive-key, 16 bytes). | Random ids allowed key-conflict re-adds whose resolution (banning) cannot converge: whether a banned device's own adds were stored depends on timing. | ADR 0031 R8, PROTOCOL §6.1, DESIGN D5 |
| 02 | **R9** Fork detection uses per-origin dot logs and hash chains compared at `Hello`, bisected with `ChainQuery`/`ChainReply`. Forks are recorded as replicated `fork.report` items (new kind), and a forked origin is repaired in full. | Latest-only storage makes dot-collision detection incomplete. | ADR 0031 R9, PROTOCOL §7, DESIGN D5/D6/D17 (`mesh_dots`) |
| 02 | **R10** A known kind with an invalid payload is rejected at ingest; the valid prefix is kept. | Storing it unmaterialized lets it supersede valid entries on some devices only. | ADR R10, PROTOCOL §2.4/§3.3 |
| 02 | **R11** Repair compares per-origin digests in `Hello`. `Want`, `RepairDigest` and `RepairWant` are unused. | Simpler; per-origin granularity is what fork repair needs. | ADR R11, PROTOCOL §8.5 |
| 02 | **R12** Frames carry a per-direction sequence number `n`. | Reordered, duplicated or dropped frames end the session. | ADR R12, PROTOCOL §8.1 |
| 02 | **R13** A suspected-forked origin is never streamed on the main path (simulator finding). | A session that died mid-bisection left mixed logs. | ADR R13, PROTOCOL §7.2 |
| 02 | **R14** The dense-prefix validity rule applies only below an origin's fork point (oracle finding). | Repair delivers a forked device's items without a dot log. | ADR R14, PROTOCOL §5.6 |
| 02 | **R15** A commit compares every overlapping hash, items and dots, with the dot log, and never extends a disagreeing log (soak finding). | Two concurrent sessions appended two branches. | ADR R15, PROTOCOL §7.2 |
| 02 | Small deviations, in this table only: `GenesisInfo` lives in `mesh::store` (re-exported by `oracle_api`). The oracle contract gained `observe_unreached`. `Session::new(limits, expected_peer)` takes the store per call (`start(&store)`, `on_frame(frame, &store)`) instead of a snapshot. The store owns the HLC. `HlcClock: Clone`. The genesis is always a member once its self-add exists (PROTOCOL §6.3 clarified). The workspace dev profile optimises only the crypto crates. | Simpler or required by what was built. | — |

## Handoff notes (newest first)

_(Per increment: surprises, load-bearing facts, environment gotchas, anything not done,
pending CI runs to check first.)_

### Increment 02 — Sans-IO protocol & simulator (2026-10-26/27)

**What landed** (all in `crates/core/src/mesh/`, still pure and sans-IO):
- `chain` (dot chains and origin digests).
- `store` (the `MeshStore` trait, `GenesisInfo`, `CommitBatch`, `ForkEvidence`, `Draft`,
  `HlcPolicy`, `Stats`).
- `memstore` (the reference store).
- `views` (the CRDT containers, `rebuild`, `State::expected`).
- `proto` (the session).
- `sim::{world, oracle, oracle_api}`.
- `crates/core/tests/mesh_sim.rs` and `scripts/mesh_soak.sh`.
- The contract changes: key-derived ids, `fork.report`, and the roster without
  conflicts.

**`MeshStore` surface that 03's `SqliteStore` must implement:**
- `genesis()`, `self_id()`, `vv()`, `state() -> &views::State` (keep an in-memory
  `State`, rebuilt at open), `stats()`;
- `dot_hash(o, s)`, `chain_at(o, s)` (seq 0 = zero), `origin_digest(o)`;
- `held_items(o, from_excl, to_incl)` (seq order; forks can hold two per dot);
- `ingest_rate_used(o)`, `now_ms()`, `hlc_last()`;
- `commit(CommitBatch) -> CommitOutcome`, `mint(&SigningKeyPair, Draft)`,
  `record_rejected(n)`.

`MemStore` is the reference. Copy its validate-then-apply commit, including the R15
overlap comparison, exactly; the 03 file now spells this out.

**The oracle** (`sim/oracle.rs`, 1 860 lines, 32 tests):
- **Isolation.** It was written by an isolated subagent from PROTOCOL.md alone. Its
  imports show it never used `crdt`, `views`, `proto`, `memstore` or `world`.
- **Tooling quirk.** The agent's worktree was created from `main` (5ec8198), not this
  branch. The agent therefore built from a read-only `git archive` export of `a9fddeb`
  in the session scratchpad, and the file was copied in by the orchestrator.
- **Ambiguity report** (13 items) and how each was resolved:
  - 1, 4-8, 11 and 12: the oracle's literal reading equals the implementation's; no
    change.
  - 2: moot under the amended rule 4.
  - 3 (genesis membership when its self-add is cut off): the spec was clarified to the
    implementation's reading (the genesis is always a member once its self-add
    exists), and the oracle was changed to match.
  - 9: definitions of `clamped` and the totals were added to §5.5.
  - 10: the collusion caveat was added to §5.5.
  - 13: the stale `kinds.rs` doc comment was fixed.
  - Its `oracle_api` note: the `Mutex` for its cache is fine.

**Oracle/implementation disagreement log** (the evidence the oracle earned its keep):
1. **29/200 seeds, harness bug.** The simulator's "lost item" filter dropped items
   superseded before sending whose dot hashes did travel, so the oracle saw gaps.
   *Fix:* an item is lost only if neither it nor its dot hash reached a device in
   contact.
2. **Seed 163, spec bug (R14).** A forked device's own `fork.report` arrives by repair,
   and the dense-prefix rule discarded it in the oracle. *Fix:* rule 4 applies only
   below the fork point; the oracle was changed, and a test was added
   (`above_its_fork_point_a_forked_origin_needs_no_dense_prefix`).
3. **5 soak seeds, contract gap.** The forked device's superseded items never reached
   contact even as dots, so the oracle saw a gap below a report that devices held.
   *Fix:* the contract gained `observe_unreached` (the item fills its dot for rule 4
   and nothing else); the oracle implements it; PROTOCOL §5.6 "What converges" says
   so.

**Simulator-found bugs without the oracle:**
- **Harness bugs:** the partition table was indexed by later joiners; the fork
  "truth" was taken from lost items; the fork invariant wrongly owed detection for
  out-of-contact devices.
- **Protocol bugs:**
  - **R13** (seeds 1000, 1004, 1178): a mid-bisection abort mixed logs.
  - **R15** (soak seeds 1008759, 1011053, 1018365 and others): concurrent sessions
    appended two branches.

**The final fork invariant** is a range: true divergence ≤ recorded ≤ divergence
visible among devices in contact. It is never early, never later than can be seen,
and allows a valid earlier report from a device that has since been cut off. The
increment file had "exactly the divergence"; the range is the provable property.

**Regression seeds** (`mesh_sim::regression_seeds`):
- 4, 15, 34, 163, 1000, 1004 and 1178 at 2 000 steps;
- 1008114, 1008759, 1011053, 1012130, 1015682, 1016234, 1017206, 1017426, 1018365,
  1019427 and 1021656 at 3 000 steps.

**Each defence disabled → the simulator fails** (seeds 0-199 × 2 000 steps, first
failure; not committed):
| Mutation | First failure |
|---|---|
| M1: signature check in `proto::check` removed | `MESH_SIM_SEED=0`, invariant 6 (node committed a forged item) |
| M2: supersession check in `MemStore::apply_entry` removed | `MESH_SIM_SEED=1`, the replay check (replaying an accepted item changed the store) |
| M3: `Hello` chain comparison off | no failure in 200 seeds: the commit-time overlap check (R15) catches forks too |
| M3b: chain comparison, commit overlap check and repair collision check all off | `MESH_SIM_SEED=4`, invariant 1 (a forked origin's item is held outside the log) |
| M4: gap check, session completeness and store completeness off | `MESH_SIM_SEED=2`, invariant 8 (a session staged 50 001) |
| M5: drift clamp in `HlcClock::observe` removed | `MESH_SIM_SEED=0`, invariant 9 (clock beyond now + drift) |

The mid-session-crash defence (Commit-only application) is shown by
`proto::tests::a_dead_sender_leaves_nothing_half_applied` and by crashes in every seed.

**Purity** (acceptance):
`grep -nE "std::net|std::fs|SystemTime|std::thread|thread::|Instant|TcpStream|File::"`
over `proto.rs`, `views.rs`, `store.rs`, `memstore.rs`, `chain.rs` and `crdt/*.rs`
gives no matches (exit 1).

**Replay determinism.** `MESH_SIM_SEED=12345 MESH_SIM_STEPS=2000` gives trace hash
`48ed5b75e81cb919…`, identical over two runs (the `replay` test asserts it).

**Soaks** (`scripts/mesh_soak.sh`, release):
1. 22 000 seeds × 3 000 steps from 1 000 000 in 1 403 s: 11 failing seeds, all fixed
   (R15, the fork-invariant range and the `observe_unreached` contract) and now
   regression tests.
2. After the fixes, 10 minutes from 2 000 000: **58 000 seeds × 3 000 steps in 606 s, 0 failing** (`bash scripts/mesh_soak.sh --minutes 10 --start 2000000 --batch 2000`).

**Environment notes.**
- `ci_200_seeds` takes about 10 s on 10 cores; expect 25-40 s on CI's 4 cores.
- The oracle's `expected()` takes about 8 ms over 2 000 items.
- Debug sign/verify costs about 51/77 µs with the crypto-only `opt-level = 3` override
  in the workspace `Cargo.toml`, against 205/315 µs without it.

**Left for later increments:**
- 03: the SQLite store, the clone marker, the restore wipe, "a forked node refuses to
  run".
- 04: transport, session concurrency and timeouts.
- 07: cap-policy views (owner labels and overrides; who may mint).

The `cap.def` conflict rule and the `share.*` ordering are specified and implemented
(§5.6), not deferred.

### Increment 01 — Foundations & decision (2026-10-26)

**What landed.** ADR 0031; `docs/mesh/{ARCHITECTURE,PROTOCOL,SECURITY_INVARIANTS,THREAT_MODEL,KNOWN_LIMITATIONS,TEST_PLAN}.md`;
the DESIGN §D2 amendments (CLAUDE.md, PRODUCT_SPEC, root THREAT_MODEL) plus a README
pointer and a CHANGELOG entry; and `crates/core/src/mesh/` (pure, sans-IO) with its tests.
There are no user-visible commands yet.

**Public API of `core::mesh` that 02 builds on** (one line each):
- `clock`: `Clock` (`now_ms`), `SystemClock`, `ManualClock::{new,set,advance}`. `Clock` is
  implemented for `&C` and `Arc<C>`, so the simulator shares one `Arc<ManualClock>` per node.
- `hlc`: `Hlc(u64)`, which is 48-bit ms plus a 16-bit logical counter
  (`new/from_raw/raw/physical/logical/successor`, `ZERO`, `MAX`). `HlcClock<C>` provides
  `now`, `observe -> Observation{clamped, skew_ms}`, `local_write_ts(Option<Hlc>)`,
  `restore(high_water)`, `last` and `drift_bound`. `MAX_DRIFT_MS = 60_000`.
- `dot`: `DeviceId`, `MeshId`, `MeshProjectId`, `CapId`, `ShareId`, `CredentialRef`. Each is
  a 16-byte id with `random/parse/to_hex/from_bytes/as_bytes` and strict lowercase-hex
  serde, plus `MIN`/`MAX` consts. `Dot{origin, seq}`.
- `vv`: `VersionVector` with `get`, `contains(dot)`, `advance_to`, `join`, `dominates`,
  `missing_from(&peer) -> Vec<(origin, from_excl, to_incl)>` and `iter`. Zero entries are
  never stored.
- `codec`: `ItemBody{v,mesh,origin,seq,hlc,kind,key,payload: Value}`, `ItemBody::new`,
  `encode_body -> Result<Vec<u8>>` and `decode_body -> Result<ItemBody>`. Decoding
  re-encodes and requires byte equality. Constants: `MAX_ITEM_BYTES` (65 536),
  `MAX_BODY_BYTES`, `SIGNATURE_LEN`, `MAX_KIND_BYTES`, `MAX_KEY_BYTES`, `MAX_PAYLOAD_DEPTH`.
- `sign`: `SigningKeyPair::{generate, from_secret_bytes, expose_secret_bytes, verifying_key,
  public_key}`, which redacts in Debug/Display and zeroizes on drop. Also
  `PublicKeyBytes::{parse,to_hex,to_verifying_key}` (rejects weak keys),
  `verify_body_signature` and `ITEM_SIGNATURE_DOMAIN`.
- `item`: `SignedItem::{sign, from_parts, from_wire, to_wire, body_bytes, sig, hash, wire_len,
  decode_unverified, verify(body,sig,key,mesh), verify_with}`. The wire form is
  `body || sig`. `ItemHash` = BLAKE3(wire).
- `kinds`: the `ItemKind` trait (`KIND`, `item_key`, `payload`, `parse`, `to_body`) and one
  typed struct per v1 kind, each with `TryFrom<&ItemBody>`. Also `TypedItem::parse`
  (`Unknown` for unknown kinds), `UsageKey`, `UsageTotals`, `Day`, `Month`, `names::*` and
  `KNOWN_KINDS`.
- `crdt`: `SwEntry<T>{seq, hash, value}` (the higher `(seq, hash)` wins), the `Admit` trait
  (implemented for closures and for `Roster`) and `AdmitAll`. Plus:
  - `lww_map::{LwwRegister, LwwMap, LwwValue}` (`winner/value/winning_hlc`);
  - `owner_counter::{OwnerCounterMap, CounterValue (lattice_join/lattice_le), Totals,
    InsertOutcome{changed, regression}}`;
  - `roster::{Roster (apply_add/apply_remove/record_fork/join; is_known/keys/is_member/
    is_removed/cutoff/fork_seq/is_conflicted/is_active/is_admitted), DeviceKeys, AddRecord}`;
  - `bounded::{BoundedCounter (apply_rights/apply_used/join/view/avail/can_spend/
    prepare_{spend,transfer,burn,mint}), BoundedView, DeviceRights, Recipient}`.
- `sim::rng::SplitMix64` sits behind `cfg(any(test, feature = "mesh-sim"))`. Core has a self
  dev-dependency with `mesh-sim` on, so `tests/` can use it.
- Errors: `MeshError`, surfaced as `CoreError::Mesh` with `code()` values of the form `mesh_*`.

**PROTOCOL.md ambiguities resolved** (ADR 0031 R1-R7; DESIGN marks them [Amended 01]):
- **R1.** An origin's order is its `seq`, for every kind. HLC and the epoch lattice are
  honest-writer properties.
- **R2.** A removed origin's items keep relaying, and views exclude them. Under the old
  rule (never relay items above the cutoff), devices never converge. Garbage collection
  must not delete them (PROTOCOL §8.4).
- **R3.** The bounded clamp is one hop, from a budget of `minted + raw_in`. Burns come
  first, then recipients by ascending id, and spend is not in the budget. A transitive
  fixpoint would let hostile values force about 2^60 iterations.
- **R4.** A non-owner self-mint counts, as a labelled override.
- **R5.** Roster resolution is stratified: reach → conflicts → known → cutoffs → members.
- **R6.** The genesis is a mesh parameter, and `PairAccept` carries it.
- **R7.** `local_write_ts` does not move the clock.
- Also settled:
  - payload decoders ignore unknown payload fields, but the envelope is strict;
  - a known kind with an invalid payload is stored and relayed but not materialized;
  - ingest check 4 must re-check items whose roster.add arrives later in the same session;
  - verification is `verify_strict`;
  - item bytes inside frames are base64.

**Left open for 02 (on purpose, flagged in PROTOCOL.md §7 and in the 02 file):**
- **How fork evidence reaches every node.** With latest-only storage, two nodes can hold
  different branches with no dot in common, so a VV comparison cannot see the fork. The
  candidates are repair plus forwarding the self-certifying evidence.
- **Two origins publishing a `cap.def` with the same id.** A suggestion: treat the cap as
  conflicted and exclude it.
- **How `share.sealed` and `share.revoke` order for one key.**
- **The simulator's invariant 9** is reworded in the 02 file: "no observation moves the HLC
  past now + MAX_DRIFT".

**Dependency.** `ed25519-dalek` 2.2.0 (`fast`, `std`, `zeroize`). It reuses
`curve25519-dalek` 4.1.3, `sha2`, `subtle` and `zeroize`, and compiles only `ed25519` 2.2.3
and `signature` 2.2.0 as new crates. `pkcs8`/`der`/`spki`/`const-oid` appear in
`Cargo.lock` as inactive optional dependencies and are not built.
`cargo tree -d -p api-tracker-core` shows no new duplicate.

**Environment notes.**
- The mesh unit suite takes about 1.7 s in debug.
- The exhaustive tamper test runs about 720 verifications in under 0.1 s, but most of them
  fail at decode. For the 02 simulator, measure debug sign and verify cost before choosing
  seeds and steps. If they are slow, add `[profile.dev.package.curve25519-dalek] opt-level = 3`
  (plus `ed25519-dalek`, `sha2`) to the workspace `Cargo.toml`.
- The PRNG reference test checks the published SplitMix64 constants (seed 1234567).

**CI.**
- The first run, `40394393640`, **failed** in "Rust (core + CLI)" and "Desktop backend
  (macOS)" because of a toolchain gap:
  - CI's `stable` is **rustc 1.99.1**, while this machine's default `stable` is 1.96.1.
  - 1.99 deprecates `AtomicU64::fetch_update`, and its replacement `try_update` is newer
    than the 1.85 MSRV.
  - `f888eb1` fixes it with a CAS loop.
- The first run's packaged macOS service lifecycle job, `40394393614`, **passed**.
- After the fix: CI `40397253597` — **success** (Rust core+CLI, Rust core Windows, Desktop
  frontend, Desktop backend macOS, Packaged app + validation macOS). macOS service
  `40397253640` — **success**. Nothing is pending.

**Toolchain gotcha (load-bearing).**
- Toolchain 1.99.1 is now installed alongside the default (`rustup toolchain install 1.99.1
  --profile minimal -c clippy -c rustfmt`). The default `stable` is unchanged. Before
  pushing, run CI's clippy with it, using a separate target dir so the main `target/`
  isn't rebuilt:
  `CARGO_TARGET_DIR=<scratch>/target199 cargo +1.99.1 clippy -p api-tracker-core -p api-tracker-cli -p api-tracker-observe -p api-tracker-gateway -p api-tracker-tracking --all-targets -- -D warnings`
  Add `cargo +1.99.1 clippy -p api-tracker-desktop -- -D warnings` too.
- Recheck `gh run view <id> --log | grep -m1 "rustc "` when CI's stable moves.

**Not done / honest list.** Nothing in 01's scope was moved. The DESIGN §D21 mutation
tests are Increment 12's. The `TEST_PLAN` "Leakage" layer covers keys, signatures, sealed
bytes and errors; CLI/`--json` canaries arrive with the CLI (03+).


## Planning record

- **2026-10-26.** Plan created in a planning session.
  - The owner chose a P2P CRDT mesh; usage, metadata and caps first and credentials
    last (opt-in); own devices only; 12 increments maximum.
  - The design was reviewed by an independent planning agent before this was written.
    Its P0 fixes are already folded into DESIGN.md: signed items, accept-and-flag HLC,
    Commit-only VV, per-origin LWW maps, removal cutoffs, fork detection, the
    bounded-counter month rules, the escrow fence, 403 instead of 429, and delta/epoch
    publishing.
