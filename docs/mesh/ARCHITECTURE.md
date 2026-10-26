# Tethra Mesh — Architecture

Tethra Mesh replicates a small, fixed set of data **peer-to-peer and end-to-end
encrypted between one developer's own paired devices**, with no server, relay or
cloud of any kind. Decision record: [ADR 0031](../decisions/0031-device-mesh.md).
Normative protocol: [PROTOCOL.md](PROTOCOL.md).

> **Status.** In development on `feat/device-mesh`, built in twelve increments
> (`increments/STATUS.md`). As of Increment 01 the pure foundations exist in
> `crates/core/src/mesh/` — identifiers, version vectors, the hybrid logical
> clock, the canonical item codec, Ed25519 item signing, typed payloads and the
> four CRDTs — with no user-visible commands yet. Each section below says what
> is implemented and what is specified.

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
| `mesh::proto`, `store`, `memstore`, `views`, `sim` world + oracle | specified, lands in 02 | anti-entropy state machine, in-memory store, views, simulator |
| `mesh::sqlite_store`, `identity` | specified, lands in 03 | SQLite store (migration v21), keys wrapped under the vault key |
| `crates/mesh` | specified, lands in 04-05 | Noise transport, pairing, node runtime |
| `mesh::publish`, `caps`, `share` | specified, lands in 06, 07-08, 11 | usage publisher, spend caps, credential shares |

**Rules.** Core performs no network I/O (`crates/core/src/lib.rs`), and
`core::mesh` keeps it that way: it reads time only through `Clock` and draws
randomness only from the OS RNG for keys and ids (or an injected seeded RNG in
the simulator). The CLI and the desktop app share this one implementation.
Reauth-gated operations are methods on `UnlockedVault` in core (from 03), so
neither front end re-implements a check.

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

**Status: implemented (01)** for minting and verifying; storage lands in 02-03.

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
