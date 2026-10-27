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
> clone/rollback marker), and two commands exist: `tethra mesh init` and
> `tethra mesh status`. A single device is a working one-device mesh; pairing
> and the network transport arrive in 04. Each section below says what is
> implemented and what is specified.

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
        noise · frame · pair · session · node · peers ·
        discover · instance · bind  — the ONLY network code
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
| `crates/mesh` | specified, lands in 04-05 | Noise transport, pairing, node runtime |
| `mesh::publish`, `caps`, `share` | specified, lands in 06, 07-08, 11 | usage publisher, spend caps, credential shares |

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

## Data flow

**Status: specified; lands in 02-06.** Text diagram of one usage figure's path:

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

Spend caps follow the same path (`cap.*` items), and each device's gateway
reads its own cap view from its local database (Increment 08).

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

- [PROTOCOL.md](PROTOCOL.md) — the normative spec, with worked examples.
- [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md) — MESH-SI-1 to MESH-SI-15.
- [THREAT_MODEL.md](THREAT_MODEL.md) — the device-mesh trust boundary.
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) — what the mesh does not do.
- [TEST_PLAN.md](TEST_PLAN.md) — the test layers and their status.
- [increments/](increments/README.md) — the build plan and ledger.
