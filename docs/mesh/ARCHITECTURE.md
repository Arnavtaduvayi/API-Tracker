# Tethra Mesh — Architecture

Tethra Mesh replicates a small, fixed set of data **peer-to-peer and end-to-end
encrypted between one developer's own paired devices**, with no server, relay or
cloud of any kind. Decision record: [ADR 0031](../decisions/0031-device-mesh.md).
Normative protocol: [PROTOCOL.md](PROTOCOL.md).

> **Status.** In development on `feat/device-mesh`, built in twelve increments
> (`increments/STATUS.md`). As of Increment 03, `crates/core/src/mesh/` holds the
> pure foundations (01) and the replication protocol as a sans-IO state machine
> (02). That protocol is proven by a deterministic simulator against an
> independently written oracle, over in-memory stores and, since 03, over the
> SQLite store. A device has a real identity (keys encrypted in the vault, a
> clone/rollback marker). Since 04, `crates/mesh` carries the protocol over Noise
> on TCP. Devices pair with a one-time invite, serve, replicate on demand, relay
> through one another, remove a device (with access-key rotation) and leave,
> all from `tethra mesh …`. The automatic node loop arrives in 05. Each section
> below says what is implemented and what is specified.

## Vocabulary

**Status: implemented (01)**

| Term | Meaning |
|---|---|
| **mesh** | The set of paired devices. Each mesh has a random `mesh_id`. |
| **device** | One Tethra installation (one data dir) holding a mesh identity. Two data dirs on one machine are two devices. |
| **origin** | The device that created and signed an item. |
| **item** | A signed, immutable record — the only thing that replicates. |
| **dot** | `(origin, seq)`: an item's position in its origin's log. |
| **VV** | Version vector, `origin → max seq known`. |
| **replicate / exchange** | One anti-entropy session between two devices. Never "sync": `tethra sync` is sync plans. |
| **bind / binding** | A *local-only* mapping from a local project to a mesh project. Never "link": that word belongs to `gateway_project_links`, `project_folder_links` and `projectlink.rs`. |
| **spend cap** | A replicated monthly ceiling on *gateway-estimated* cost. Never "budget": `budget.rs` is the provider/manual-usage alert feature. |
| **rights** | Bounded-counter allowance, in micro-USD, one device may spend against a cap in one month. |

## What replicates

**Status: implemented (01) as the closed set of item kinds (`mesh::kinds`).**
Nothing outside this table ever replicates.

| Data | Replicates? | Notes |
|---|---|---|
| Device roster: id, name, public keys, listen addresses, removals | yes | `roster.add`, `roster.remove`, `device.info` |
| Mesh projects: id, name, archived, merged_into | yes | Only projects you explicitly share (`project.meta`) |
| Usage counters per (origin device, mesh project, UTC day, provider, model) | yes | Counts, tokens and an estimated-cost split; **no** request-level data (`usage.counter`) |
| Spend caps, rights, used totals | yes | `cap.def`, `cap.target`, `cap.rights`, `cap.used` |
| Mesh settings (retention horizon) | yes | `mesh.setting` |
| Credential shares (Increment 11) | yes | Sealed per recipient device; opt-in per credential (`share.sealed`, `share.revoke`) |
| Local project ids, bindings, peers, invites, keys, cursors, enforcement switch | **no** | Device-local only |
| Gateway request events, routes, paths, endpoints, scan findings, alerts, audit rows, provider admin keys, destinations | **no** | Never |

## Layering

```text
 apps/desktop (Tauri)          apps/cli (tethra mesh …)
        │                              │
        └──────────────┬───────────────┘
                       ▼
        crates/mesh  (api-tracker-mesh, from Increment 04)
        noise · wire · handshake · pair · session · serve ·
        replicate · node · runtime · peers · discover ·
        instance · doctor · bind  — the ONLY network code
                       │ drives
                       ▼
        crates/core::mesh   (pure, sans-IO)          ◄── crates/gateway reads
        clock · hlc · dot · vv · codec · sign ·          cap state only
        item · kinds · crdt::{lww_map,                   (core::mesh::caps,
        owner_counter, roster, bounded} ·                 Increment 08); never
        proto · store · views · publish · caps ·          depends on crates/mesh
        share · identity · sim (feature mesh-sim)
```

| Module | Status | Role |
|---|---|---|
| `mesh::clock` | implemented (01) | `Clock` trait; `SystemClock`, `ManualClock` |
| `mesh::hlc` | implemented (01) | 48/16-bit hybrid logical clock, accept-and-flag |
| `mesh::dot`, `mesh::vv` | implemented (01) | 16-byte ids, dots, version vectors |
| `mesh::codec` | implemented (01) | canonical JSON item bodies |
| `mesh::sign`, `mesh::item` | implemented (01) | Ed25519 keys, signed items, `BLAKE3` item hashes |
| `mesh::kinds` | implemented (01) | typed payloads for every v1 kind |
| `mesh::crdt` | implemented (01) | LWW map, owner counter, roster, bounded counter |
| `mesh::sim::rng` | implemented (01) | seeded `SplitMix64` for tests and the simulator |
| `mesh::proto` | implemented (02) | the anti-entropy session as a pure state machine (frames, staging, prefix commits, dot hashes, repair, fork bisection, rollback notice) |
| `mesh::store`, `mesh::memstore` | implemented (02) | the `MeshStore` trait and its in-memory implementation (dot logs, chains, atomic commit, mint) |
| `mesh::chain` | implemented (02) | dot chains and per-origin digests |
| `mesh::views` | implemented (02) | the CRDT containers every stored item feeds, `rebuild`, and the comparable state |
| `mesh::sim::world`, `oracle`, `oracle_api` | implemented (02) | the deterministic simulator and the independent oracle (feature `mesh-sim`) |
| `mesh::sqlite_store` | implemented (03) | the SQLite `MeshStore`: item store, VV and dot log on disk; views, counters and digests mirrored in memory; chunked crash-safe commits; durable mints |
| `mesh::identity` | implemented (03) | `mesh init`, keys wrapped under the vault key, `MeshKeys` for the node, `status`, the restore/leave wipe, `preflight` |
| `mesh::marker` | implemented (03) | the clone/rollback marker file and its classification |
| `mesh::sim::sqlite` | implemented (03) | SQLite devices for the simulator (store conformance) |
| `mesh::invite`, `mesh::membership` | implemented (04) | invite tokens and strings, pairing messages, `MeshVault`, the inviter's single-use claim, devices, rename, removal with rotation, leave, the exchange log |
| `crates/mesh` (`api-tracker-mesh`) | implemented (04) | `bind` (the only bind), `noise`, `wire` (preamble, framing), `handshake` (roster check), `session` (one exchange), `pair`, `serve` (accept loop, limits), `replicate`, `directs`, `node` |
| `mesh::peers`, `mesh::doctor` | implemented (05) | the peer table (`mesh_peers`), lag and repair records; the store-side checks of `mesh doctor` and `--rebuild` |
| `mesh::projects`, `mesh::publish`, `mesh::usage` | implemented (06) | shared projects and local bindings; the usage publisher (cursor, deltas, epoch bumps, hourly budget, retention); the per-device usage report and `local_month_spend_micros` |
| `crates/mesh` `runtime`, `peers`, `instance`, `discover`, `doctor` | implemented (05) | the node loop (rounds, hooks, stop conditions), backoff and targets, one node per data directory with its control socket, opt-in mDNS and its in-memory fake, `mesh doctor` |
| `mesh::caps` | implemented (07) | spend caps: month helpers, the policy thresholds, the read model and this device's `Ledger` (unpublished spend, open escrow), the escrow fence and the gateway's ack contract, create/raise/lower/reclaim/`try_spend`, the reconciler and rights requests/grants, alerts |
| `mesh::sim::caps` | implemented (07) | the spend-cap scenario family on SQLite |
| `share` | specified, lands in 11 | credential shares |

**Rules.** Core performs no network I/O (`crates/core/src/lib.rs`), and
`core::mesh` keeps it that way: it reads time only through `Clock` and draws
randomness only from the OS RNG for keys and ids (or an injected seeded RNG in
the simulator). The CLI and the desktop app share this one implementation.
Reauth-gated operations are methods on `UnlockedVault` in core (from 03), so
neither front end re-implements a check.

## Storage

**Status: implemented (03)** — migration v21 in `crates/core/src/db.rs`;
`mesh::sqlite_store`, `mesh::identity`, `mesh::marker`. The mesh lives in the
vault's own `vault.db`, beside everything else, with no separate database.

| Table | Replicated? | Holds |
|---|---|---|
| `mesh_items` | **yes** (the only one) | The exact bytes of the latest item per `(kind, key, origin)`, unknown kinds included. Primary key `(origin, seq, hash)`: a fork can put two items at one dot |
| `mesh_vv`, `mesh_dots` | proof of what was received | The VV, and the hash and chain at every dot up to it (PROTOCOL §7.1) |
| `mesh_self`, `mesh_access_keys` | local | This device's identity: ids, name, public keys, and the signing, Noise and sealing private keys and access keys, all encrypted under the vault key |
| `mesh_meta`, `mesh_fork_evidence` | local | HLC high-water mark, write generation, counters (rejected, skew, regressions, repairs, ingest rate), fork evidence |
| `mesh_peers` (05), `mesh_invites` (04), `mesh_project_bindings` (06), `mesh_publish_cursor` (06), `mesh_cap_escrow` (07-08), `mesh_exchange_log` (04-05), `mesh_share_imports` (11) | local | Created by v21, filled by the increment named |
| `gateway_config.cap_enforcement` | local | The opt-in enforcement switch (08); a peer can never change it |

**Views are not tables.** The roster, projects, usage, caps and shares views
are a `views::State` built in memory from `mesh_items` when the store opens,
and kept equal to a rebuild after every commit (ADR 0031 R17). A reader that
needs only some kinds can load those rows by the `(kind, item_key)` index and
fold them with the same `State::apply`.

**What is in memory.** The VV, the views, the counters, the HLC and the
per-origin digests mirror the database. The dot log and the held items stay on
disk, because the dot log grows with every item any device ever minted. A failed
disk read ends the session; it never counts as an empty read (R18).

**Writes.** A mint is one `BEGIN IMMEDIATE` transaction with `synchronous=FULL`.
It allocates the seq (`vv[self] + 1`), advances the marker one block ahead if
needed (written and fsynced first), signs, stores the item, appends the dot,
advances the VV and records the HLC high-water mark. A commit runs in chunks of
whole origins: a crash between chunks leaves only whole origins (PROTOCOL
§8.6). Every write first checks `mesh_meta.write_gen` and reloads the mirror if
another process wrote, so a CLI command and a running node never reuse a seq.

**Identity** (DESIGN §D5). `UnlockedVault::mesh_init` generates the mesh id,
the access key (epoch 1) and three key pairs. The device id is derived from
the three public keys. The private keys are encrypted under the vault key with
AAD naming the vault and the device. The genesis `roster.add` and `device.info`
are minted in the same transaction that stores the identity.
`UnlockedVault::mesh_keys` gives a node the signing key, the Noise key and the
current access key, checking each against its public key. It never returns the
sealing key (MESH-SI-7).

**Copies and rollbacks.** `<data-dir>/mesh/identity.marker` ties the database to
its directory (PROTOCOL §7.5). A missing or foreign marker, or a database more
than one block behind it, refuses to mint. Restoring a backup wipes every mesh
row and the matching marker (MESH-SI-5): a restored vault is a copy and must
pair again.

## Runtime

**Status: implemented (05)** — `crates/mesh::{runtime, peers, instance,
discover, doctor}`; the user-facing view is [USER_GUIDE.md](USER_GUIDE.md).

A **node** is `RunningNode::start(MeshNode, data_dir, NodeConfig,
StopCondition)`. `tethra mesh serve` runs one in the foreground; the desktop
app runs one on a thread from Increment 09. In order, it:

1. claims the data directory (`instance::claim`): binding
   `<data-dir>/mesh/node.sock` (0600, in the 0700 `mesh/` directory) is the
   single-instance lock, and a fresh per-boot nonce goes to `node.nonce`
   (0600). On Windows the control channel is a loopback TCP listener whose port
   is in the nonce file (compiled and unit-tested, runtime untested);
2. binds its listeners (`bind::bind_listener` only, MESH-SI-1);
3. starts three threads:

| Thread | Holds the keys? | Does |
|---|---|---|
| serve | yes (`Arc<MeshNode>`) | the accept loop: authenticated exchanges and pairing |
| control | **no** (status only) | one JSON line per request: `health`, `status`, `replicate_now`, `stop`; all but `health` need the nonce |
| main | yes | the outbound loop below, and the stop conditions |

**A round** (every `interval`, 30 s ± 20% jitter by default, and on
`replicate_now`):

```text
round hooks (06: usage publisher; 07: cap reconciler)
  → publish listen addresses in device.info if they changed
  → refresh learned peers: gossip (active devices' device.info addresses),
    mDNS sightings whose daily tag matches this mesh
  → targets: one per known device (its addresses, last success first), one
    per address of a device not seen yet; skip removed/forked devices and
    peers in backoff (5 s doubling to 15 min, ±20%)
  → ≤ 4 exchanges at once, inside the node's 8 session slots (in + out)
  → record each dial in mesh_peers and each peer's Hello (lag) in mesh_meta
  → once a day: record it as a repair round (node/last_repair)
```

Every exchange already compares per-origin digests and repairs differences
(PROTOCOL.md §8.5), so the daily repair round is a record of whether repair
changed anything, not a separate protocol.

**Stopping and keys (MESH-SI-7).** The keys live in the `MeshNode`; only the
serve and main threads, and the exchanges they run, hold it. The node stops on
its `StopCondition` (`SessionAlive`: the CLI session file deleted, expired or
replaced; `Deadline`: an opted-in maximum runtime; `StopFlag`: the desktop's
lock signal), on `stop`, or by itself when this device left the mesh, was
removed, or forked (`identity::preflight`). It then closes the listeners, lets
running exchanges finish, joins every thread, and the last reference to the
`MeshNode` drops, which zeroizes `MeshKeys` and `MeshVault`.
`StopReport::keys_dropped` states it. Ctrl-C ends the process without this
sequence (no signal handler, like the gateway); stored state is safe because
every write is one transaction and an interrupted exchange commits nothing.

**Rollback hold (PROTOCOL.md §7.4).** A peer's `RollbackNotice` is stored per
reporting device in `mesh_meta` (`rollback_hold/<device>`), so every process
minting on this database — the node, its round hooks, a CLI command — refuses
until `vv[self]` reaches the reported seq (ADR 0031 R22).

## Usage publishing

**Status: implemented (06)** — `core::mesh::{projects, publish, usage}`,
migration v23, the gateway writer's split, the node's `UsagePublisher` hook.

- **Split at the source.** The gateway writer classifies each request with
  `projectcost::UsageClass` (the same rule `projectcost` reports by) and adds it
  to `gateway_usage_daily.unpriced_requests` / `unextracted_requests`; rows it
  creates carry `split_known = 1`. Rows from before v23 keep 0: they publish
  `unextracted` (always derivable) and leave priced/unpriced at 0, so views show
  the remainder as "split unknown".
- **Cursor and deltas.** `mesh_publish_cursor` (rebuilt by v23 with
  `mesh_project_id` in its key) records what each local row contributed to each
  mesh project's counter. A run adds new traffic to the project bound **now**;
  a shrunk or deleted row is taken back from every counter it fed, with an
  epoch bump. Counters and cursor commit in one transaction
  (`SqliteStore::mint_batch`), and a `publish/gen` check makes two publishers on
  one database (node and CLI) safe.
- **Bounds and retention.** ≤ 5 000 counters an hour, oldest days first;
  `retention.usage_days` (LWW, default 90): older days are not published, and
  past the horizon plus two days every store drops them at ingest and
  collects them (`SqliteStore::{set_usage_floor, gc_usage}`), which PROTOCOL
  §8.4 (b) allows because the exclusion does not depend on seq.
- **Views.** `usage_report` folds merged projects into their root and reports
  per device with `as_of`, `stale`, `removed`, the split-unknown remainder, "no
  data from" the active devices without figures, and a labelled sum.
- **Local month spend.** `usage::local_month_spend_micros(store, project,
  month)` sums this device's own rollup for the local projects bound to a mesh
  project: the one function Increments 07 and 08 use.

## Spend caps

**Status: implemented (07), alerts only; gateway enforcement in 08**
([ADR 0032](../decisions/0032-spend-caps.md)).

- **Owner and months.** `caps::create` makes this device the owner and mints
  the month (UTC, `caps::period`). From day 20 the owner mints next month in
  advance. One `(cap, month)` is one bounded counter (PROTOCOL.md §5.5).
- **The reconciler** (`caps::reconcile`, the round hook after the usage
  publisher; `mesh replicate` and `mesh cap show` run it too): publish
  `cap.used` from `usage::local_month_spend_micros`; settle escrow; mint;
  distribute equal shares to devices active in the last 30 days; burn after a
  lower. Each step decides inside its write transaction
  (`SqliteStore::mint_with`), so a node and a CLI command never act on one
  snapshot; an idle step rolls back.
- **Rebalancing.** `caps::rights_requests` adds `Direct RightsRequest`s at the
  start of an exchange (`crates/mesh::session`); `caps::grant` answers the
  peer's after the exchange committed (`crates/mesh::directs`). Thresholds are
  in `caps::policy`.
- **This device's figure.** `caps::view::Ledger::local_avail`: the view's
  available amount, minus the gateway's spend not yet published and the open
  escrow. `try_spend` is the strict check on it (Increment 08's gate makes the
  same one in memory).
- **The escrow fence.** `caps::escrow`: every give is a `mesh_cap_escrow` row;
  `Fence::Immediate` (enforcement off, or no gateway running — the node probes
  the gateway's control socket, `crates/mesh::node::GatewaySocket`) publishes
  in the same transaction; `Fence::AwaitAck` reserves until the gateway's
  `escrow::ack`.
- **Alerts.** `caps::alerts::cap_alerts`, called by `run_monitor`: kind
  `mesh_spend_cap`, dedup `mesh_cap:<cap>:<month>:{80,100}`.
- **Views.** `caps::report` gives each cap and month per device, labelled with
  freshness like usage; frozen and superseded caps are labelled.

## Data flow

**Status: implemented (06-07)** up to the views; the gateway reads caps in 08. Text
diagram of one usage figure's path:

```text
 device A                                            device B
 ────────                                            ────────
 gateway forwards a request
   │ writer upserts gateway_usage_daily
   ▼
 publisher (06): delta since cursor for each
 bound local project → new cumulative totals
   │ mints usage.counter (signed, seq n, hlc)
   ▼
 mesh_items (+ views) ── exchange (Noise, 04) ──► stage → verify → Commit
                                                    │ one transaction:
                                                    │ items + views + VV
                                                    ▼
                                                  views render "A: $3.20,
                                                  as of 2 min ago" next to
                                                  B's own figure
```

Spend caps follow the same path (`cap.*` items, minted by the reconciler);
each device's gateway will read its own cap view from its local database
(Increment 08).

## Item lifecycle

**Status: implemented** — minting and verifying (01), the session (02), durable
storage (03).

1. **Mint.** The origin builds an `ItemBody` (`kinds::ItemKind::to_body`), with
   its next `seq` and an HLC timestamp, encodes it canonically
   (`codec::encode_body`), and signs `"tethra-mesh/v1/item\0" || body`
   (`item::SignedItem::sign`). Wire form: `body || sig`; hash:
   `BLAKE3(wire)`.
2. **Ingest.** A receiver runs the ordered checks of PROTOCOL §3.3 (size, parse,
   mesh, origin known, signature, rate, kind) and stores the exact bytes.
3. **Combine.** Each item is one origin's entry for one `(kind, key)`; the CRDTs
   combine entries across origins (PROTOCOL §5-6). Admission (roster cutoffs
   and forks) decides which entries count.
4. **Relay.** Items are relayed byte-for-byte — including a removed device's
   items, which views exclude (PROTOCOL §8.3).

## Related documents

- [USER_GUIDE.md](USER_GUIDE.md) — setup, the node, `status` and `doctor`.
- [PROTOCOL.md](PROTOCOL.md) — the normative spec, with worked examples.
- [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) — MESH-SI-1 to MESH-SI-15.
- [THREAT_MODEL.md](THREAT_MODEL.md) — the device-mesh trust boundary.
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) — what the mesh does not do.
- [TEST_PLAN.md](TEST_PLAN.md) — the test layers and their status.
- [increments/](increments/README.md) — the build plan and ledger.
