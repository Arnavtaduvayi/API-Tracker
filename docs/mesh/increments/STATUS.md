# Tethra Mesh: increment ledger

Every session reads this file first and updates it at the end (README §1).

**States:** `pending`, `in-progress`, `done`, `blocked` (give the reason).

| Branch | Base | Draft PR |
|---|---|---|
| `feat/device-mesh` | `origin/main` @ `5ec8198` (2026-10-26) | [#19](https://github.com/Arnavtaduvayi/API-Tracker/pull/19) (draft) |

| # | Increment | Mode | Size | State | Started | Finished | Commits | CI run (result) |
|---|---|---|---|---|---|---|---|---|
| 01 | [Foundations & decision](01-foundations-and-decision.md) | S | L | done | 2026-10-26 | 2026-10-26 | `e746a01`, `df3d8ec`, `f888eb1` | CI `40397253597` (success); macOS service `40397253640` (success) |
| 02 | [Sans-IO protocol & simulator](02-protocol-and-simulator.md) | O | L | done | 2026-10-26 | 2026-10-27 | `bb651d0`, `a9fddeb`, `fed0b34`, `db52154` | CI `40541779107` (success: Rust core+CLI, Windows, frontend, desktop backend, packaged app); macOS service `40541779109` (success); contract commit: CI `40418521889` (success), service `40418521735` (success) |
| 03 | [Persistence & identity](03-persistence-and-identity.md) | S | L | done | 2026-10-27 | 2026-10-27 | `1b4c8a2`, `6a8213f` | CI `40554008854` (success: Rust core+CLI, Windows, frontend, desktop backend, packaged app); macOS service `40554008811` (success) |
| 04 | [Transport & pairing](04-transport-and-pairing.md) | S+R | L | done | 2026-10-27 | 2026-10-28 | `bd6d89e`, `40bd38a` | CI `40630951922` (success: Rust core+CLI+mesh on Linux, Rust core+mesh on Windows, frontend, desktop backend, packaged app on macOS); macOS service `40630951920` (success). 03 record commit `21b4c70`: CI `40588124547`, service `40588124805` (both success) |
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
| 02 `db52154` | **1,643 passed, 0 failed, 10 ignored** (`API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core -p api-tracker-cli -p api-tracker-observe -p api-tracker-gateway -p api-tracker-tracking`); includes `--test mesh_sim` (200 seeds in ~10 s, replay, per-adversary, 18 regression seeds; soak ignored), 10 `proto` session tests, 32 oracle tests | unchanged (not touched) | **140 passed** (`bash scripts/smoke.sh`) |

| 03 `6a8213f` | **1,682 passed, 0 failed, 11 ignored** (12 ignored after the `commit_timing` addition in the record commit) (`API_TRACKER_INSECURE_FAST_KDF=1 cargo test --no-fail-fast -p api-tracker-core -p api-tracker-cli -p api-tracker-observe -p api-tracker-gateway -p api-tracker-tracking`; one run had 1 failure in the unrelated `git_execution_canaries::each_canary_is_armed_against_unhardened_git`, which passed 5/5 on rerun, see handoff). Of these: 171 mesh unit tests (`cargo test -p api-tracker-core --lib mesh`), `--test mesh_store_conformance` 5 (+2 ignored: `soak`, `commit_timing`), `--test mesh_schema` 7, `--test migration_safety` still 9, `-p api-tracker-cli --test mesh_cli` 4 | unchanged (not touched) | **151 passed** (`bash scripts/smoke.sh`; 11 new mesh checks) |

| 04 `40bd38a` | **1,724 passed, 0 failed, 12 ignored** (`API_TRACKER_INSECURE_FAST_KDF=1 cargo test --no-fail-fast -p api-tracker-core -p api-tracker-cli -p api-tracker-observe -p api-tracker-gateway -p api-tracker-tracking -p api-tracker-mesh`). New: `-p api-tracker-mesh` 30 (`wire` unit 2, `bind_guard` 2, `bounds` 9, `noise_spike` 3, `pairing` 8, `replication` 6); `--test mesh_membership` 5; `mesh_schema` 8; `gateway --test no_mesh_dependency` 1; `cli --test mesh_cli` 5 | unchanged (not touched) | **158 passed** (`bash scripts/smoke.sh`; 7 two-node checks) |

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
| 03 | **R16** `seq` ≤ 2^63 − 1 in the codec. | Every accepted seq must fit and sort as SQLite's signed INTEGER; repair skips the gap check, so a member could otherwise sign a seq that makes every SQLite commit fail. | ADR 0031 R16, PROTOCOL §2.1, DESIGN header |
| 03 | **R17** No SQL view tables: the views are the in-memory `State`, rebuilt from `mesh_items` at open. | Every view value depends on the roster (cutoffs, forks); SQL copies would need full recomputation on each removal or fork, or would duplicate `mesh_items`. Readers fold rows by the `(kind, item_key)` index with `State::apply`. | ADR 0031 R17, PROTOCOL §8.6, DESIGN §D15/§D17 [Amended 03] |
| 03 | **R18** `MeshStore::{dot_hash, dot_hashes, chain_at, held_items}` return `Result`; a failed read ends the session with `Bye(Unavailable)` (new `ByeReason`). | The dot log is unbounded and lives on disk; an empty read in place of a failed one would stream dots without items. | ADR 0031 R18, PROTOCOL §8.1/§8.6 |
| 03 | Schema details: `mesh_items` PK `(origin, seq, hash)`, no `hlc` column, `received_at` integer ms, no separate `(kind, item_key)` index (the UNIQUE index serves it); `mesh_self` without `next_seq` (= `vv[self]+1`) and with `genesis_device`; access keys in `mesh_access_keys(epoch, …)`; `mesh_meta.value` is `ANY`; `mesh_publish_cursor` has no FK (06 decides deletion semantics). | Forks hold two items per dot; one source of truth for the next seq; rotation (04) without a migration. | ADR 0031 "Smaller storage decisions", DESIGN §D17 [Amended 03] |
| 03 | Commits chunk by **whole origins** (never split one origin's range); one origin's range is one transaction. | A split range could log a superseded dot before the item that supersedes it. Measured: 2 000 / 10 000 items of one origin commit in ~12 / ~60 ms (release, FULL + F_FULLFSYNC); the 50 000 maximum extrapolates to ~0.3 s. | ADR 0031, PROTOCOL §8.6, DESIGN §D12 [Amended 03] |
| 03 | Marker rule made precise: rolled back ⇔ `seq_high_water > vv[self] + 64`; a store not `ok` refuses to mint and does not trust the old mark. | `next_seq` below the mark is the normal state with block allocation. | ADR 0031, PROTOCOL §7.5, DESIGN §D5 [Amended 03] |
| 03 | AAD binds vault **and** device id (`mesh_*_key(vault_id, device_id)`) / mesh id and epoch (`mesh_access_key(vault_id, mesh_id, epoch)`). | Stronger than vault-only binding: a leftover blob of an earlier identity never opens. | ADR 0031 |
| 03 | Small, this table only: `identity::init` (not `init_mesh`) behind `UnlockedVault::mesh_init`; `UnlockedVault::mesh_keys` added for 04/05; `MeshError::{Storage, NotInitialized, AlreadyInMesh, IdentityMismatch, InvalidDeviceName, Forked}`; `CoreError::Mesh` is `#[error(transparent)]` (it printed twice in CLI chains); new audit event `mesh_identity_wiped` on restore; `BackupInfo.mesh_wipe` (restore only); `projects_first_schema.rs` no longer pins v20 as current; PROTOCOL §8.4 clarified: rule (a) supersession applies to every kind, the never-deleted list is about rule (b). | Required by what was built or a bug fix. | — |
| 04 | **R19** The pairing psk is stored encrypted under the vault key (`mesh_invites.wrapped_psk`, **migration v22**); the usage split of 06 becomes **v23**. | PROTOCOL §9 stored only `blake3(token)`, from which the inviter cannot derive the psk the handshake needs. | ADR 0031 R19, PROTOCOL §9.2, DESIGN §D10/§D14/§D17 [Amended 04], 06 file |
| 04 | **R20** A 16-byte preamble picks the handshake; pairing carries the invite hint (`blake3(token)[..8]`); the inviter answers only a live invite's hint. | The responder must choose the handshake and the invite's psk before message 1. | ADR 0031 R20, PROTOCOL §9.1-9.3 |
| 04 | **R21** `AccessKeyUpdate` in every session; applied after the exchange's commit, bounded by `1 + removals`, equal epochs resolved by the larger BLAKE3 hash; re-removal refused. | The review found epoch poisoning (`u32::MAX`), a split on concurrent rotations, and a key travelling ahead of its removal. | ADR 0031 R21, PROTOCOL §9.5 |
| 04 | Small, this table only: the inviter's side is `membership::accept_pairing(store, …)` (not an `UnlockedVault` method; the serving thread holds the node); `mesh_device_rename(name)` renames self only; `remove`/`leave` confirm via `--yes` in non-interactive runs (the `backup restore` pattern) rather than `confirm_default_no`; `invite --addr HOST:PORT` (plus `--wait --listen`) supplies the invite's addresses (05 publishes listen addresses); `join -` reads the invite from stdin; two checksum characters, not one; `SqliteStore::refresh` added. | Required by what was built, or stronger. | — |
| 02 | Small deviations, in this table only: `GenesisInfo` lives in `mesh::store` (re-exported by `oracle_api`). The oracle contract gained `observe_unreached`. `Session::new(limits, expected_peer)` takes the store per call (`start(&store)`, `on_frame(frame, &store)`) instead of a snapshot. The store owns the HLC. `HlcClock: Clone`. The genesis is always a member once its self-add exists (PROTOCOL §6.3 clarified). The workspace dev profile optimises only the crypto crates. | Simpler or required by what was built. | — |

## Handoff notes (newest first)

_(Per increment: surprises, load-bearing facts, environment gotchas, anything not done,
pending CI runs to check first.)_

### Increment 04 — Transport & pairing (2026-10-27)

**What landed.**
- `crates/mesh` (`api-tracker-mesh`, `#![forbid(unsafe_code)]`, std threads,
  `snow` 0.10.0). Modules: `bind` (the only bind), `noise`, `wire` (preamble,
  `u16` Noise messages, 1 MiB `u32` frames), `handshake`, `session` (one
  exchange, with a writer thread), `pair`, `serve`, `replicate`, `directs`
  and `node` (`MeshNode`, `TransportLimits`).
- Core: `mesh::invite` (token, invite string with a 2-character checksum,
  `PairRequest`/`PairAccept`, the redacting `AccessKey`) and `mesh::membership`
  (`PendingIdentity`, `MeshVault`, `accept_pairing`, `devices`, `rename`,
  `remove` with rotation, `mint_self_remove`, `log_exchange`,
  `invite_is_live`, `max_access_epoch`).
- Core API: `UnlockedVault::{mesh_vault, mesh_open_store, mesh_invite_create,
  mesh_join, mesh_devices, mesh_device_rename, mesh_device_remove, mesh_leave}`
  and `SqliteStore::refresh`. `Roster::added_by`. `DirectMsg::AccessKeyUpdate`
  and `Session::direct`.
- Migration v22 (`mesh_invites.wrapped_psk`).
- CLI: `mesh invite|join|devices|rename|remove|leave|serve|replicate`.
- CI lists include `-p api-tracker-mesh` (clippy, tests, Windows tests).
- Tests: `crates/mesh/tests/{noise_spike,pairing,replication,bounds,bind_guard}.rs`,
  `crates/gateway/tests/no_mesh_dependency.rs`,
  `crates/core/tests/mesh_membership.rs`, `mesh_schema` (v22), and the
  three-device CLI test.
- Smoke: a two-node block on 127.0.0.1.

**For 05 (load-bearing).**
- **Where the outbound loop plugs in.** `serve::serve(node: Arc<MeshNode>,
  listeners, stop)` is the inbound loop. The outbound loop should share the
  same `Arc<MeshNode>` and call `replicate::replicate_once(&node, addr)` (it
  logs to `mesh_exchange_log`, tries every resolved address and the previous
  access key). Session concurrency lives only in `serve`'s
  `active`/`max_sessions` counter today; the node should count outbound
  sessions against the same 8.
- **Building the node.** `MeshNode::open(&vault, clock, limits)` runs
  `identity::preflight` (marker and fork) and holds `MeshKeys` + `MeshVault`.
  `node.store()` locks *and refreshes* the store.
- **`RollbackNotice`** is ignored in `directs::handle` (one-shot exchanges);
  05 must make the node stop minting until `vv[self] ≥ held_seq`.
- **`serve` prints `Listening on <addr>`** on stdout per listener (tests and
  smoke parse it). It stops only when killed; graceful stop is the `stop`
  closure (05: control socket `Stop`).

**For 07.**
- The `Direct` dispatch point is `crates/mesh/src/directs.rs::handle`. It
  returns `Some(msg)` for messages to apply after the exchange's commit (as
  `AccessKeyUpdate` is), or handles them in place. Add `RightsRequest` there
  and to `proto::DirectMsg`.

**Review (S+R).** `code-review` skill at `high` on the uncommitted increment
diff. All 10 findings were confirmed and fixed with tests; none were rejected:
1. Access-key epoch poisoning (`u32::MAX` blocks every later rotation) →
   bound `epoch ≤ 1 + removals` (`mesh_membership::an_access_key_epoch_must_be_justified_by_removals`).
2. Concurrent rotations split the mesh → equal epochs resolve to the larger
   BLAKE3 hash (`two_keys_for_one_epoch_converge_on_the_larger_hash`).
3. A key applied before the removal that justifies it, then handed to the
   removed device → keys are held until after the exchange's commit
   (`session.rs`, `directs::apply_access_key`) and bounded as in 1.
4. The smoke check "the invite cannot be used again" was vacuous (the joiner
   was already in a mesh) → a third, fresh vault whose join fails and leaves
   it in no mesh. (A used invite no longer matches at the inviter, which closes
   without replying; "already used" appears only when two joiners race while
   the invite is live.)
5. `invite --wait` re-implemented liveness in CLI SQL without the attempt
   limit → `membership::invite_is_live` in core.
6. Only the first resolved address was dialed (`localhost` → `::1`) → every
   address (`replication::a_name_that_resolves_to_several_addresses_reaches_the_ipv4_listener`).
7. `join` gave up after the first failing invite address → the next address on
   transport errors (`pairing::an_invite_whose_first_address_is_dead_still_pairs_through_the_next`).
8. Removing an already-removed device rotated again → `AlreadyRemoved`
   (`replication::a_removed_device_is_refused…`).
9. No previous key after skipping epochs → the newest stored epoch below the
   current one (`the_previous_key_is_the_newest_below_the_current_even_after_a_skip`).
10. A removed or forked device could still invite or accept pairings →
    `NotActive` (`a_device_that_left_its_roster_cannot_invite…`).

**Surprises.**
- PROTOCOL §9's "store `blake3(token)`" could not work with a token-derived
  psk (R19).
- A serving node's mirror only reloaded on its own writes, so a removal made
  by a CLI command was invisible to the handshake check. Fixed with
  `SqliteStore::refresh` in `MeshNode::store()`.
- `snow` does not zeroize its internal key copies (KNOWN_LIMITATIONS).

**Gotchas.**
- Every test connects from 127.0.0.1, so tests set
  `handshakes_per_ip_per_minute: 1_000` (`tests/common::test_limits`). Only the
  flood test uses a low limit.
- Vaults are `Send` but not `Sync`: move a vault into a thread rather than
  sharing a reference to it.

### Increment 03 — Persistence & identity (2026-10-27)

**What landed.**
- Migration v21 (`db.rs`): 14 tables — `mesh_meta`, `mesh_self`, `mesh_access_keys`,
  `mesh_items`, `mesh_vv`, `mesh_dots`, `mesh_fork_evidence`, `mesh_peers` (05),
  `mesh_invites` (04), `mesh_project_bindings` (06), `mesh_publish_cursor` (06),
  `mesh_cap_escrow` (07/08), `mesh_exchange_log` (04/05), `mesh_share_imports` (11) —
  plus `gateway_config.cap_enforcement`. All STRICT with CHECKs.
- `core::mesh::sqlite_store::SqliteStore`, `core::mesh::marker`, `core::mesh::identity`,
  `core::mesh::sim::sqlite` (the conformance factory).
- `UnlockedVault::{mesh_init, mesh_status, mesh_keys}`; the restore hook in
  `backup::restore_backup`.
- CLI `tethra mesh init [--name]` and `tethra mesh status` (both `--json`).
- Tests: `tests/mesh_schema.rs`, `tests/mesh_store_conformance.rs`,
  `apps/cli/tests/mesh_cli.rs`, and unit tests in `sqlite_store`, `identity`,
  `marker` and `proto`.
- Smoke has a `-- mesh --` block (11 checks).

**How 04 gets what it needs (load-bearing).**
- **Keys.** Call `vault.mesh_keys()?`, which returns `identity::MeshKeys`:
  - `signing_key()` gives the item-signing `&SigningKeyPair`;
  - `expose_noise_secret()` gives the X25519 static secret, already clamped, and
    `noise_pub()` its public key;
  - `expose_access_key()` and `access_epoch()` give the psk0 key and its epoch;
  - `device_id()`, `mesh_id()` and `genesis_device()` give the ids.

  There is no reauth (D5: the node runs only while unlocked), and the sealing key is
  never in it. The public keys are derived with `crypto_box`'s X25519
  (`identity::x25519_public`). **04 should assert that snow's public key for
  `expose_noise_secret()` equals `noise_pub()`.**
- **Noise public keys of the roster.** Use
  `store.state().roster.keys(&device)` → `DeviceKeys { sign_pub, noise_pub, seal_pub }`.
  They come from `roster.add` items, and `is_active(&d)` is the MESH-SI-2 check. This
  device's own `noise_pub` is in `mesh_self.noise_pub` / `MeshSelfInfo.noise_pub`.
- **Opening the store.** Call
  `identity::open_store(&db_path, &data_dir, clock) -> Option<SqliteStore>`. It opens
  its own connection via `open_at_current_version`. Run `identity::preflight(&store)`
  before starting a node: it fails on a bad marker (`IdentityMismatch`) or a fork
  report naming this device (`Forked`).
- **The session must handle `ByeReason::Unavailable`** (R18). `proto` already does:
  `Action::Close(CloseReason::Aborted("local storage error"))`.
- **Joining** needs a new identity path inside an existing mesh: the keys like
  `identity::init`, but with the received `mesh_id`/`genesis`/access key and **no**
  genesis items.
  - Write the marker (mark 0 is fine) **before** the joiner's first mint; without a
    marker the store refuses to mint (`Missing`).
  - Reuse the private helpers in `identity.rs`. They are `x25519_generate`, `random_key`,
    `delete_mesh_rows` and the `mesh_self` insert, so factor them rather than copying.
- **`mesh leave`.** `identity::leave_local_wipe(conn, data_dir)` does the local half.
  The `AlreadyInMesh`, `IdentityMismatch` and `Forked` error texts already tell users to
  run `tethra mesh leave`, **which 04 must add**.

**Surprises and bugs found (all fixed):**
1. **Marker trust at open (real bug).** `SqliteStore::open` cached the marker's mark
   whenever the marker *named* this identity. A rolled-back database still names it,
   so it would have minted seqs below the cached mark without re-checking — reusing
   seqs. Now the mark is trusted only when the classification is `ok`. The rollback
   test exercises the real path (`copies_and_rollbacks_are_detected_and_refuse_to_mint`).
2. **Harness bug.** A simulated commit crash during the fault-free quiescence phase
   left a device down for the rest of the run (seed 22 shrank to 457 steps). Now
   `SimStore::calm()` turns store faults off before the calm rounds, after two
   explicit crash-prone catch-up rounds (`CRASHY_CATCH_UP_ROUNDS`). Those two rounds
   are where the large multi-origin commits happen; during the step phase, most
   sessions abort under network faults.
3. **`CoreError::Mesh` printed twice** in CLI error chains (`{0}` + `#[from]`); it is now
   `#[error(transparent)]`.

**Conformance facts.**
- `SqliteFactory` defaults: chunk size 1 (every origin is its own transaction) and
  250‰ of splittable commits crash.
- With crashes off, a SQLite run has **the same trace hash** as a `MemStore` run
  (`without_crashes_sqlite_runs_are_identical_to_memstore_runs`). The 02 replay hash
  and the regression seeds are untouched, because the world's RNG stream is unchanged.
- Release soak: **600 seeds × 2 000 steps with crashes, 0 failing, 172 s**
  (`MESH_SIM_START=10000 MESH_SIM_COUNT=600 MESH_SIM_STEPS=2000 cargo test --release -p api-tracker-core --test mesh_store_conformance soak -- --ignored`).
- `thirty_seeds_with_crashes_between_chunks` takes about 13 s locally. Windows CI ran
  the whole suite green.

**Measured (release, this Mac, `synchronous=FULL` + F_FULLFSYNC):**
- Committing 500 / 2 000 / 10 000 items of one origin in one transaction takes
  7.4 ms / 11.9 ms / 60 ms (`mesh_store_conformance::commit_timing`, ignored).
- Extrapolated, the 50 000-row session maximum is about 0.3 s, a little over D12's
  ~250 ms. That is the documented cost of never splitting one origin.
- Each **mint** is its own fsynced transaction: about 5.5 ms each (12 500 mints in
  about 69 s while setting up that test). If a later increment mints many items at
  once (the 06 publisher), give it a batch-mint path that uses one `write`.

**Environment gotchas.**
- `scripts/smoke.sh` now runs 151 checks, and the `migration_safety` pin (`ok. 9`) holds.
- **Flaky, unrelated test.** `git_execution_canaries::each_canary_is_armed_against_unhardened_git`
  failed once ("clean/smudge filters" did not fire against unhardened git), then passed
  5/5 on rerun. It drives real `git`, so it looks like a racy-git stat timing issue. It is
  not mesh code; rerun it before treating it as a regression.
- Python heredocs used to edit Rust swallow `\`-newline string continuations. Check
  any multi-line Rust string after editing it that way.
- A Bash call containing `rm -rf "$(…)"` is refused whole by the harness's safety
  check, including any edits earlier in the same call. Remove temp dirs by literal path.
- The CI-toolchain clippy target dir for this session was
  `<scratchpad>/target199` (rebuilds from scratch in about 3 min).

**Not done / honest list.**
- Nothing in 03's scope was moved.
- `mesh doctor` and `--rebuild` belong to 05. The building blocks exist:
  `SqliteStore::{rebuild_views, verify_against_disk, rematerialize}` and
  `identity::preflight`.
- "A forked node refuses to run" exists as `preflight`. The node that calls it is 05.
- The device name defaults to the `hostname` command (or `COMPUTERNAME`) and falls back
  to `this-device`. 04 may want a prompt.

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
