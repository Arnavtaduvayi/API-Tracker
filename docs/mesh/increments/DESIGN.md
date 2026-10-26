# Tethra Mesh: design of record

This is the design brief the increments are built from. Increment 01 turns it into
ADR 0031 and `docs/mesh/*`. From then on those documents describe what was actually
built and take precedence wherever they are more specific. The deviation rule in
README §7 governs any change.

The repository owner approved the product direction, the scope rules in §1 and the
amendment text in §2 when they approved the plan on 2026-10-26.

Section ids (D1 to D21) are stable. Increment files cite them as "DESIGN §Dn".

> **Amended by Increment 01 (2026-10-26).** Writing the normative protocol exposed
> ambiguities and two non-convergent rules. They are resolved in ADR 0031
> ("Decisions resolved while specifying", R1-R7) and `docs/mesh/PROTOCOL.md` §13, and
> the affected passages below are marked **[Amended 01, Rn]**. PROTOCOL.md is now the
> more specific source and wins.

---

## D1. Goals, non-goals, scope rules

**Goal.** One developer's own devices (laptop, desktop, home server) form a *mesh*:
- They replicate project sharing, cross-device API usage, and spend caps peer-to-peer,
  directly or over the user's LAN or VPN.
- There is no server of any kind.
- Every device keeps working fully offline. Devices converge when they reconnect.
- A monthly **spend cap** can be enforced by every device's local gateway at once,
  safely, even while the devices can't reach each other.

**Owner decisions (fixed):**
1. Peer-to-peer CRDT mesh, not consensus. Raft would need a majority online, and a
   lone offline laptop could not commit. That breaks local-first.
2. Usage, metadata and spend caps replicate from the start. **Encrypted credential
   values replicate only in Increment 11, opt-in, per credential, behind reauth.**
3. Peers are only the user's own devices. There is no multi-user and no teams, but
   nothing in the design blocks adding them later.
4. At most 12 increments.

**Non-goals:**
- Any Tethra-hosted server, relay, rendezvous or STUN/TURN service.
- NAT traversal. The mesh works on a LAN or a user-run VPN such as Tailscale or
  WireGuard, and says so.
- Mobile.
- Replicating gateway request events, routes, paths, endpoints, scan findings,
  alerts, audit rows, provider admin keys or destinations.
- Any change to `tethra sync` (sync plans) or provider usage sync.
- Analytics for the mesh.

**What replicates (data minimization).** Nothing else ever replicates.

| Data | Replicates? | Notes |
|---|---|---|
| Device roster: id, name, public keys, listen addresses, removals | yes | |
| Mesh projects: id, name, archived, merged_into | yes | Only projects you explicitly share |
| Usage counters per (origin device, mesh project, UTC day, provider, model) | yes | Counts, tokens, estimated cost split; **no** request-level data |
| Spend caps, rights, used totals | yes | |
| Mesh settings (retention horizon) | yes | |
| Credential shares (Increment 11) | yes | Sealed per recipient device; opt-in per credential |
| Local project ids, bindings, peers, invites, keys, cursors, enforcement switch | **no** | Device-local only |

## D2. Product-rule amendments (Increment 01 applies them verbatim)

1. **`CLAUDE.md`, "Local-first requirements".** Add this paragraph directly after the
   "Sensitive user information must remain on the user's computer" list (it currently
   ends near line 287):

   > **Exception — the user's own paired devices (ADR 0031).** Tethra Mesh may replicate
   > the data listed in `docs/mesh/ARCHITECTURE.md` "What replicates" between devices the
   > user has explicitly paired, peer-to-peer and end-to-end encrypted, with no Tethra
   > server, relay, or rendezvous involved. Credential values replicate only when the user
   > explicitly shares a specific credential, after reauthentication, sealed to specific
   > recipient devices. This is not cloud synchronization: no third party ever holds or
   > forwards the data.

2. **`CLAUDE.md`, "Do not add".** Change "Cloud synchronization" (line 295) to
   "Cloud synchronization (peer-to-peer replication between the user's own paired
   devices is governed by ADR 0031 and is not cloud synchronization)".
3. **`CLAUDE.md`, "Do not introduce".** Leave it unchanged. The mesh adds no
   microservice, hosted infrastructure, mandatory proxy or hosted database.
4. **`docs/PRODUCT_SPEC.md` §4 "Non-goals"** (lines 106-122). Keep "Team collaboration"
   and "Shared cloud vaults". Add a new section after §4, "Device mesh (ADR 0031)", with
   a 5-8 line summary of D1, including the explicit statement that this is
   single-user and serverless.
5. **`THREAT_MODEL.md`.** Add a "Device mesh" trust boundary and adversaries (D18), and
   point to `docs/mesh/THREAT_MODEL.md`.

## D3. Vocabulary (use these words everywhere)

| Term | Meaning |
|---|---|
| **mesh** | The set of paired devices. Each mesh has a random `mesh_id`. |
| **device** | One Tethra installation (one data dir) holding a mesh identity. It is *not* a machine: two data dirs on one machine are two devices. |
| **origin** | The device that created and signed an item. |
| **item** | A signed, immutable record. It is the only thing that replicates. |
| **dot** | `(origin, seq)`: the item's unique position in its origin's log. |
| **VV** | Version vector, `origin → max seq known`. |
| **replicate / exchange** | One anti-entropy session between two devices. **Never say "sync".** `tethra sync` is sync plans. |
| **bind / binding** | A *local-only* mapping from a local project to a mesh project. **Never say "link".** That word is taken by `gateway_project_links`, `project_folder_links` and `projectlink.rs`. |
| **spend cap** | A replicated monthly ceiling on *gateway-estimated* cost. **Never say "budget".** `budget.rs` is the existing provider/manual-usage alert feature, and SI-19 keeps the two apart. |
| **rights** | Bounded-counter allowance, in micro-USD, that one device may spend against a cap in one month. |

## D4. Layering and crates

- **`crates/core/src/mesh/`** holds all pure and storage logic. Register it with
  `pub mod mesh;` in `crates/core/src/lib.rs`, alphabetically between `inject` and
  `model` (lines 47-48).
  - It is **sans-IO**. Core "performs no network I/O" (`lib.rs:20`), and that stays true.
  - Both the CLI and the desktop app use it.
  - Modules:
    - `clock`: a mesh-local `Clock` trait with `SystemClock` and `ManualClock`. Core's
      `clock.rs` has only free functions (`clock.rs:9-25`); don't retrofit it.
    - `hlc`, `dot`, `vv`, `codec`, `item`, `sign`
    - `crdt::{lww_map, owner_counter, roster, bounded}`
    - `proto`: the anti-entropy state machine; frames as values, no sockets.
    - `store`: the `MeshStore` trait. `memstore` implements it in memory and
      `sqlite_store` implements it in SQLite.
    - `identity`, `publish`, `caps`, `share`, `views` (materialized reads for the CLI and
      desktop), `error` (`MeshError`, surfaced as `CoreError::Mesh`).
    - `sim`: the deterministic simulator and oracle, behind the core feature `mesh-sim`,
      which the core tests enable through a self dev-dependency. That is the pattern
      `crates/tracking/Cargo.toml:37-43` uses for `test-hooks`.
  - **Reauth-gated operations are methods on `UnlockedVault` in core**: create an invite,
    remove a device, leave, set cap enforcement, share and import a credential. They take
    `master_password: &SecretString` and call `verify_master_password`. Neither the CLI,
    the Tauri wrapper nor React re-implements that check
    (`crates/core/tests/tauri_command_authz.rs:1-23`).
- **`crates/mesh` (`api-tracker-mesh`, created in Increment 04)** holds the network code
  only. It depends on core, uses `#![forbid(unsafe_code)]` and std threads (no tokio,
  matching the gateway), and contains:
  - `noise` (snow), `frame`, `pair`, `session` (drives `core::mesh::proto` over a framed
    Noise stream), `node` (the runtime loop), `peers`, `discover` (`Discovery` trait;
    the mDNS impl plus an in-memory fake), `instance` (single-instance lock and control
    socket), `bind` (the only function in the crate allowed to bind a socket).
- **`crates/gateway` depends only on core** and reads cap state from core
  (`core::mesh::caps::gate_snapshot`). Increment 04 adds a test asserting
  `api-tracker-gateway` never depends on `api-tracker-mesh`, using
  `cargo metadata` or a `Cargo.toml` grep.
- **Dependencies** are new and minimal, and each is recorded in ADR 0031 with its
  version and the reason.
  - Core gets `ed25519-dalek`. Prefer the 2.x line so it reuses the `curve25519-dalek`
    4.1.3 already in `Cargo.lock`; check with `cargo tree -d`.
  - `crates/mesh` gets `snow` 0.10.x and `mdns-sd` 0.21.x (no async runtime).
  - Nothing else unless an increment justifies it.
  - `crypto_box` 0.9.1, `blake3`, `chacha20poly1305`, `uuid`, `serde_json`, `time`,
    `zeroize` and `subtle` are already present; reuse them.
- **MSRV is 1.85** (`Cargo.toml:17`). `std::fs::File::try_lock` (1.89+) is not
  available, so don't use it. The single-instance lock is in D13.

## D5. Identity and keys

- **`mesh init`** on the first device creates:
  - a random `mesh_id` (16 random bytes, hex);
  - a random 32-byte **access key** at epoch 1;
  - this device's identity.

  `mesh join` on every other device creates its identity *inside* the existing mesh_id.
- **Device identity** (row `mesh_self`, local-only):
  - `device_id`: 16 bytes, hex. **[Amended 02, R8]** Derived from the device's three
    public keys: `BLAKE3-derive_key("tethra-mesh v1 device id", sign_pub || noise_pub ||
    seal_pub)[..16]` (PROTOCOL.md §6.1). Random-looking, never derived from anything
    identifying; a re-add with other keys is invalid instead of a conflict.
  - `device_name`: user-chosen, defaulting to the hostname. It is shown to other devices;
    warn the user that it replicates.
  - Ed25519 **signing key**, for items.
  - X25519 **Noise static key**, for transport.
  - A *separate* X25519 **sealing key**, for credential shares (`crypto_box`).
  - The three private keys and the access key are stored with
    `crypto::encrypt(vault_key, …)` under new AAD constructors in `crypto::aad`,
    following the `api-tracker:v1:<kind>:<vault_id>:...` pattern in
    `crypto.rs:165-264`: `mesh_sign_key`, `mesh_noise_key`, `mesh_seal_key` and
    `mesh_access_key(epoch)`. The `vault_id` binding means a copied key blob can't be
    opened in another vault.
- **Key lifetime follows ADR 0020** (drop on lock):
  - The **node** unwraps the signing key, the Noise key and the access key when it
    starts, holds them in `Zeroizing` buffers, and **stops** when the vault locks
    (desktop) or when the CLI session it started from expires or disappears
    (`tethra mesh serve`).
  - There is no "keep while locked" option in v1.
  - The **sealing private key is never held by the node**. Only the reauth-gated import
    (Increment 11) unwraps it, uses it, and drops it.
- **Never reuse an identity on another installation** (a device id reused across
  installations breaks the single-writer property dots depend on):
  - **Backup restore.** `backup::restore_backup` calls `mesh::identity::on_restore(&conn)`
    right after `restore_v2`, before `session::destroy` and the audit record at
    `backup.rs:583-584`. It deletes every `mesh_*` row (identity, items, VV, views,
    peers, invites, bindings, cursors, escrow) and sets the mesh state to "not
    initialized". The user must re-pair. `crates/core/tests/migration_safety.rs` asserts
    that every table's row count survives a restore (around lines 272-273 and 395-415),
    so add a `mesh_` prefix exemption there with a comment citing this rule. Because
    `smoke.sh:388` pins that file at 9 tests, change existing assertions; don't add tests.
  - **Copied vault.db** (Migration Assistant, Time Machine, a copied `TETHRA_DIR`). A
    **marker file** `<data-dir>/mesh/identity.marker` (0600 file, 0700 dir) holds
    `device_id`, a random `marker_nonce` that is also stored in `mesh_self`, and the
    **seq high-water mark**.
    - It is rewritten atomically (temp file, then fsync, then rename) *before* any seq
      above the recorded mark is used. Allocate in blocks of 64 so the fsync cost is
      amortized.
    - When the node starts: a missing marker, a mismatched `device_id`/`marker_nonce`,
      or `mesh_self.next_seq` below the marker's mark means a clone or local rollback.
      The node refuses to run and `mesh doctor` explains how to recover
      (`mesh leave` and re-pair).
  - **Fork detection on the wire.** This covers the cases the marker can't, such as a
    clone together with its marker. **[Amended 02, R9]** Detection uses per-origin dot
    logs and hash chains compared at `Hello` and bisected with `ChainQuery`/`ChainReply`;
    the detector mints a replicated `fork.report` item; the forked origin's items keep
    relaying and are repaired in full (PROTOCOL.md §7). The bullets below are the
    original brief.
    - Hello carries the sender's own `next_seq`. A peer that holds items from that
      origin *above* it tells the sender, and the sender enters `rollback-recovery`: it
      fetches its own items first and sets `next_seq` above them before minting.
    - Two items with the same `(origin, seq)` and different hashes mean the origin has
      **forked**. Every device that sees this stores a `ForkEvidence` record, stops
      accepting new items from that origin, and surfaces it.
    - The forked device must `mesh leave` and re-pair under a new id. A member can then
      remove the old id, with the cutoff at the last agreed seq.

## D6. Items, signing and codec

- **Envelope.** `body` is canonical-by-construction JSON, produced only by
  `codec::encode_body`: a fixed struct field order, integers only, no floats, no maps
  with nondeterministic order. Its fields are:
  - `v`: format version, 1;
  - `mesh`: mesh_id;
  - `origin`: device_id;
  - `seq`: u64, ≥ 1, dense per origin;
  - `hlc`: u64 (D7);
  - `kind`: a short string, for example `roster.add`;
  - `key`: string, the CRDT key within the kind;
  - `payload`: a kind-specific object.
- **Signature.** `sig = Ed25519(sign_key, "tethra-mesh/v1/item\0" || body_bytes)`.
- **Hash.** `hash = BLAKE3(body_bytes || sig)`.
- **Store and relay the exact received bytes.** Never re-serialize a received item;
  verification always runs over the stored bytes. That removes canonical-encoding risk
  from relaying.
- **Ingest checks, in order.** Any failure rejects the item, counts it in
  `mesh_meta.rejected_items`, and does not advance the VV past it.
  1. Size ≤ 64 KiB.
  2. Parses.
  3. `mesh` matches.
  4. `origin` is in the roster add-set. For `roster.add` items, the *added* key is
     checked against the signer differently; see D10.
  5. Signature verifies with the origin's signing key.
  6. Seq is not above the per-origin rate cap (D12).
  7. Kind is known, *or* unknown. Unknown kinds are **stored opaquely and relayed**,
     but not materialized. **[Amended 02, R10]** A known kind whose payload fails
     validation is rejected; the receiver keeps that origin's valid prefix.
- **Unknown kinds** keep a newer Tethra's data intact while it passes through an older
  one. After an upgrade, `views::rematerialize` runs over the stored items of the
  newly understood kinds.
- **Item kinds in v1:**

  | Kind | Key | Payload |
  |---|---|---|
  | `roster.add` | `device_id` | name, `sign_pub`, `noise_pub`, `seal_pub`, `added_by` |
  | `roster.remove` | `device_id` | `cutoff_seq` |
  | `device.info` | `device_id` | name, listen_addrs (LWW, origin = the device itself) |
  | `mesh.setting` | setting name | value |
  | `project.meta` | `mesh_project_id` | name, archived, merged_into |
  | `usage.counter` | `mesh_project_id/day/provider/model` | epoch, totals |
  | `cap.def` | `cap_id` | `mesh_project_id`, `owner_device`, created_hlc; immutable, owner only |
  | `cap.target` | `cap_id/month` | target_micros (LWW) |
  | `cap.rights` | `cap_id/month/to_device` | cumulative amount from origin to `to_device`; origin == to_device means minted (owner only) |
  | `cap.used` | `cap_id/month` | cumulative used_micros by origin |
  | `share.sealed` | `credential_ref/recipient` | Increment 11 |
  | `share.revoke` | `credential_ref/recipient` | Increment 11 |
  | `fork.report` | forked `device_id` | seq, hash_a, hash_b **[Added 02, R9]** |

## D7. Hybrid logical clock

- **Encoding:** a 64-bit `u64` = 48 bits of physical milliseconds since the Unix epoch
  plus a 16-bit logical counter. It is compared as an integer, and tie-breaks always add
  `origin` (lexicographic device_id).
- **`now()`** = `max(last.physical, clock.now_ms())`. The logical counter increments when
  the physical part didn't advance. Overflow of the logical counter bumps the physical
  part by 1 ms.
- **Receive:**
  - `last = max(last, min(remote, clock.now_ms() + MAX_DRIFT_MS))`, with `MAX_DRIFT_MS`
    set to 60 000.
  - **Every validly signed item is accepted, whatever its timestamp.** Rejecting it
    makes convergence depend on each node's own clock, and quarantining it behind an
    advanced VV loses it.
  - A remote hlc above `now + MAX_DRIFT` is **flagged**: the origin and amount are
    recorded in `mesh_meta.clock_skew/<origin>` and shown by `status`/`doctor`. It never
    drags the local clock forward by more than the drift.
- **Local LWW writes** use `ts = max(hlc.now(), current_winner_ts + 1)`. A user's edit
  always beats the value they were looking at, even if a skewed device wrote that value.
  **[Amended 01, R7]** This lifts only that write: it does not move the clock's `last`,
  so no observation or write drags a device's clock past `now + MAX_DRIFT`.
- **Persistence:** `mesh_meta.hlc_high_water` is written in the same transaction as every
  minted item, and `now()` never returns below it after a restart.
- **The HLC orders only LWW registers.** Counters, rights and used totals never use it:
  their bucket (day, month) comes from the origin's own record timestamps, and they join
  by max or epoch.

## D8. CRDTs (`core::mesh::crdt`)

Every CRDT below has a `join` that is commutative, associative and idempotent.
Increment 01 proves this with law tests over a seeded PRNG, at least 10 000 cases per
law.

- **[Amended 01, R1] Per-origin order is `seq` for every kind.** Each item is one
  origin's entry for one `(kind, key)`; an origin's higher `seq` supersedes its lower one
  (ties at one dot, a fork, break by hash). This is what the store keeps and what makes
  latest-only relaying safe. The HLC orders only *across* origins.
- **`lww_map`.** A register is `map<origin, (seq, hash, hlc, value)>`.
  - **Join:** per origin, keep the higher `(seq, hash)` **[Amended 01, R1]** (for an
    honest origin that is also the higher hlc).
  - **Value:** the entry with the maximum `(hlc, origin)` over *admitted* origins. An
    origin is admitted if it is in the add-set and the entry's seq is within its removal
    cutoff (D10).
  - Keeping one entry per origin (the latest from each) means removing a device needs no
    history: its entries are simply dropped from the max.
- **`owner_counter`.** One map entry per `(origin, key)`, written only by that origin.
  - The value is `(epoch: u32, totals: struct of u64)`.
  - **Join** **[Amended 01, R1]:** per `(origin, key)`, the higher `seq`. The
    lexicographic lattice — a higher epoch wins outright; with equal epochs, each field
    takes its max — is the **honest-writer rule**: every new entry is ≥ its predecessor
    in that order, so for an honest origin the latest entry equals the lattice join of
    all its entries. A successor that breaks the rule is kept (seq decides) and counted
    as a regression against the origin.
  - The origin bumps the epoch when its own totals legitimately *decrease*, for example
    when the user deletes local gateway data. A deletion then propagates; it doesn't get
    "resurrected" by max.
  - Used for usage counters and cap `used`.
- **`roster`, a 2P-set with cutoffs.**
  - **Add-set:** device_id mapped to its keys.
  - **Remove-set:** device_id mapped to `cutoff_seq`.
  - **Join:** union, and the *max* cutoff for concurrent removals.
  - **Removed is forever.** A device id that has been removed can never be added again;
    re-pairing mints a new id.
  - If two devices each remove the other at the same time, both are removed, and the
    docs say so.
  - **[Amended 01, R5/R6] Resolution is stratified** (PROTOCOL.md §6.3), so adds,
    removes and cutoffs are not mutually recursive: reach from the **genesis** (a mesh
    parameter every member holds; its keys come only from its self-add) → targets added
    with conflicting keys are excluded (a re-add cannot hijack an identity) → *known*
    devices (ingest check 4; includes removed devices, whose items keep relaying) →
    cutoffs from removes whose origin is known (max) → *members*, honouring cutoffs.
    Forks cut an origin off at the lowest known fork seq.
- **`bounded`, a bounded counter** (Balegas et al., SRDS 2015, "Extending eventually
  consistent cloud databases for enforcing numeric invariants"). One instance per
  `(cap_id, month)`.
  - **State:**
    - `R[from][to]`: cumulative rights. `R[o][o]` is minted by the cap owner.
      **[Amended 01, R4]** `R[i][i]` for a non-owner is the labelled local override of
      D15: it counts like a mint and views label it. `R[i][j]` with `i ≠ j` is a
      transfer, written only by `i`.
    - `U[i]`: cumulative used, written only by `i`.
    - Both are owner-written monotone entries, so they join by max.
  - **Available** to device `i`:
    `avail(i) = R[i][i] + Σ_j R[j][i] − Σ_j R[i][j] − U[i]`.
  - **Local operations:**
    - `spend(i, x)` requires `x ≤ avail(i)`. The gateway applies it, with the overshoot
      rule in D15.
    - `transfer(i, j, x)` requires `x ≤ avail(i)`.
    - `mint(owner, x)`.
    - `burn(i, x)` is a transfer to the reserved sink `"burn"`.
  - **Views clamp** each device's outgoing transfers to what it has. A buggy or
    malicious row then can't create rights out of nothing in *other* devices' views.
    **[Amended 01, R3]** Precisely: outgoing amounts are honoured from a budget of
    `minted + raw received` (not minus used), burn first, then recipients by ascending
    device id; the rest is clamped. One hop, so it is a closed form (a transitive clamp
    is a fixpoint hostile values can make run ~2^60 rounds); spend not in the budget, so
    an overshooting device goes negative itself instead of clawing rights back from
    devices it paid. Honest devices are never clamped.
  - **Invariant**, proved by the simulator: `Σ_i U[i] ≤ Σ minted − Σ burned + overshoot`,
    where overshoot is bounded per D15.

## D9. Replication protocol (`core::mesh::proto`, sans-IO)

`proto` is a pure state machine: it takes inbound frames and returns outbound frames
plus store operations. `crates/mesh::session` runs it over Noise. The simulator runs it
over a simulated network.

**Frames** (JSON inside Noise transport messages; each ≤ 1 MiB; field `t` is the tag).
**[Amended 02, R9/R11/R12]** PROTOCOL.md §8 is now authoritative: every frame carries a
per-direction `n`; `Hello` adds `chains` and per-origin `digests` (replacing
`digest_root`); `Items` adds `dots` (hashes of superseded dots) and `repair`;
`ChainQuery`/`ChainReply` are added; `Want`, `RepairDigest` and `RepairWant` are not
used. The list below is the original brief:
- `Hello { proto_min, proto_max, mesh_id, device_id, kinds: [..], vv, own_next_seq, digest_root }`
- `Want { since: vv }`
  - Normally the Hello VV is enough. `Want` is used after repair narrows the range.
- `Items { batch: [item_bytes], more: bool }`
  - At most 512 items or 1 MiB per batch.
- `Commit { upto: vv, count, batch_hash }`
  - `upto` is the sender's VV for exactly the origins it served.
- `RepairDigest { scope, buckets: [(bucket_id, hash)] }`
- `RepairWant { buckets }`
- `Direct { kind, payload }`
  - Point-to-point, never relayed or stored as items. Used for `AccessKeyUpdate`,
    `RightsRequest` and `RollbackNotice`.
- `Bye { reason }`

**Session (push-pull, symmetric):**
1. Both sides send Hello.
2. A mismatched `mesh_id`, or no overlapping protocol version, ends the session with
   `Bye`.
3. Each side computes what the other lacks: for each origin `o`, the items it holds with
   `seq > peer.vv[o]`, in seq order.
4. It streams `Items` batches, then `Commit`.
5. The receiver **stages** batches in memory, bounded by D12, verifying each item on
   arrival.
6. On `Commit` the receiver applies everything in **one SQLite transaction**:
   - insert the items (idempotent; `INSERT OR IGNORE` on `(origin, seq)` with a hash
     check, which detects forks);
   - update the materialized views;
   - set `vv[o] = max(vv[o], upto[o])`.
7. **The VV never advances without that Commit.** A sender that dies mid-stream leaves
   nothing half-applied, and the next session resends.
8. **Rollback check:** if the peer's `own_next_seq` is at or below the max seq we hold
   for that peer as origin, send `Direct RollbackNotice` (D5).

**Why relaying only the latest item per (kind, key, origin) is safe:**
- An item is superseded only by a *later* item of the **same origin** and key (higher
  seq). So when a sender's `vv[o] = n`, it holds, for every key, either `o`'s item or a
  later `o` item with seq ≤ n that dominates it.
- Sending all held `o` items with seq in `(peer.vv[o], n]` therefore transfers
  everything needed.
- Superseded rows may be garbage-collected after commit.
- Exception: `roster.*` and `cap.def` items are never garbage-collected.
- **[Amended 01, R2]** Otherwise an item may be deleted only when every item of its
  `(kind, key, origin)` is permanently excluded for a reason that does not depend on
  seq (a share to a removed recipient, a day beyond the retention horizon). A removed
  origin's items above its cutoff must be kept and relayed (PROTOCOL.md §8.3-8.4).

**Repair (a safety net, not the main path):**
- Each side keeps a BLAKE3 digest per bucket: `(kind, scope)`, where scope is
  `mesh_project_id/month` for usage and caps and `-` for everything else. Each bucket's
  hash is over its sorted `hash`es.
- `digest_root` in Hello is the hash of all bucket hashes.
- Repair runs when the VVs match but the roots differ, and also every 24 h:
  1. The sides exchange `RepairDigest`.
  2. They request the differing buckets with `RepairWant`.
  3. They send every item in those buckets.
  4. They commit as above, joining the items. The VV doesn't change.
- A repair that changes state on a node is a **bug signal**. Count it and surface it in
  `doctor`.

**Versioning:**
- Protocol version 1. The Noise prologue is `"tethra-mesh/v1\0" || mesh_id`.
- Peers negotiate the highest common version in `[proto_min, proto_max]`.
- Item format `v` and kinds evolve independently: unknown kinds are stored opaquely.
- A device whose database schema is newer than its binary refuses to run the node
  (`db::open_at_current_version`, `db.rs:1401-1418`).

## D10. Membership: pairing, sessions, removal

**Invite (on an existing member):**
- `UnlockedVault::mesh_invite_create(master_password, ttl)` requires reauth.
- It generates a 20-byte random **token** (160 bits) and stores `blake3(token)` in
  `mesh_invites` with `expires_at` (default 10 minutes, maximum 60), `attempts = 0`, and
  `used_at = NULL`.
- It prints an invite string: `tethra-mesh-invite:v1:<base32 token>@<host:port>[,<host:port>…]`.
  The addresses are this node's configured listen addresses.
- **The token is a bearer secret** valid for 10 minutes. Tell the user to move it by a
  channel they trust (typing it, or their own password manager), never a public channel.

**Join (on the new device):**
- `mesh join <invite>` requires an unlocked vault and refuses if this device already has
  a mesh.
- It creates its identity, connects to the listed addresses in order, and runs
  **`Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`** with:
  - `psk = blake3::derive_key("tethra-mesh v1 pairing psk", token)`;
  - prologue `"tethra-mesh/v1-pair\0"`.
- The inviter checks that the token hash is unused and unexpired, that `attempts < 5`
  (every failed attempt increments it), and that the token was not already used. It
  marks the token used **before** replying.
- **Inside the Noise channel:**
  - The joiner sends its public keys and name in a `PairRequest`.
  - The inviter mints a signed `roster.add` for the joiner, then sends a `PairAccept`
    with mesh_id, **the genesis device_id [Amended 01, R6]**, the access key and its
    epoch, and the inviter's device_id.
  - After that, a normal anti-entropy session runs on the same connection.
- **`roster.add` rule:** an add is admitted if its origin is an admitted member when the
  add's seq was minted (i.e. within the origin's cutoff), or if it is the genesis self-add
  of the device that ran `mesh init`. A mesh therefore has exactly one genesis. A
  `roster.add` signed by a non-member is rejected.

**Normal sessions:**
- Use **`Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s`** with `psk = access key` (current
  epoch) and prologue `"tethra-mesh/v1\0" || mesh_id`.
  - With psk0, a LAN prober who lacks the access key fails at message 1, so it never
    learns a device's static key. That stops devices being tracked by their key.
- After the handshake, the remote static key **must** equal the `noise_pub` of a roster
  member that has not been removed. Otherwise the session closes (MESH-SI-2).
- The responder tries the current access-key epoch first, then the previous one if it is
  younger than 30 days.
- If `snow` does not support `XXpsk0`, use `Noise_XX` and document the static-key
  exposure as a known limitation in ADR 0031. Increment 04 checks this first.

**Access-key rotation:**
- On a removal, the remover generates epoch + 1 and delivers it with
  `Direct AccessKeyUpdate` inside authenticated sessions.
- Every member that receives it re-wraps it under its vault key and forwards it to the
  peers it talks to.
- A device that misses the update for 30 days has to re-pair. The docs say so.

**Removal:**
- `UnlockedVault::mesh_device_remove(master_password, device_id)` requires reauth and the
  CLI/UI asks for confirmation.
- It mints `roster.remove { cutoff_seq = local vv[target] }`.
- Effects, everywhere the item arrives:
  - **Transport:** sessions with the removed key are refused immediately.
  - **Items the removed device owns** (its `usage.counter`, `cap.used` and `cap.rights`
    rows) are **kept** up to the cutoff, so totals stay honest. Views label them
    "removed device".
  - **Its contributions to shared state** (`lww_map` entries, `roster.add`, `cap.target`,
    `share.*`) with seq above the cutoff are excluded from views. **[Amended 01, R2]**
    Items above the cutoff are still stored and relayed (and never garbage-collected);
    withholding them breaks convergence, because only the latest item per
    `(kind, key, origin)` is kept. Its own counters and rights count only where their
    latest entry is within the cutoff.
- **Self-removal** (`mesh leave`) requires confirmation and reauth. It mints a self-remove
  if any peer is reachable, then wipes local mesh state the same way restore does.
- **Removal is eventually consistent:** a removed device can keep exchanging with devices
  that haven't heard yet. A compromised member can remove every other device; recovery is
  re-pairing. Both are documented.

## D11. Shared projects and bindings

- **`mesh project share <local-project>`** mints `project.meta` with a new random
  `mesh_project_id`, the name and `archived = false`, and binds the local project to it.
- **`mesh project bind <mesh-project> <local-project>`** creates a binding on this device
  only. **Binding is never automatic:** not by name, and not by local project id (a
  restored backup clones local project UUIDs).
- **`unbind`**: the binding table has `ON DELETE CASCADE` from `projects`, so deleting a
  local project unbinds it automatically.
- **`rename` and `archive`** are LWW. **Mesh projects are never hard-deleted.**
- **Concurrent shares** of the same real project create duplicates. **`merge <a> <b>`**
  sets an LWW `merged_into` on the non-root, where the **root is the lexicographically
  smaller id**. Views fold counters into the root. Merging two projects that both have
  caps is refused (UX: lower one cap to 0 and archive it first).
- Usage on a local project that has no binding is never published and never capped.

## D12. Bounds and rate limits (MESH-SI-8; mirrors SI-14)

| Bound | Value |
|---|---|
| Frame size | ≤ 1 MiB |
| Item | ≤ 64 KiB |
| Batch | ≤ 512 items |
| Staged items per session | ≤ 50 000, else `Bye(too_large)` and resume next session |
| Concurrent sessions | ≤ 8 (inbound + outbound) |
| Handshake timeout | 5 s |
| Idle timeout | 30 s |
| Session wall time | ≤ 10 min |
| Handshakes per source IP | ≤ 10/min (token bucket) |
| Pairing attempts per token | ≤ 5 |
| Items minted per origin | ≤ 10 000 per hour, enforced on **ingest** per origin |
| Write transactions | one Commit per transaction, chunked to stay under ~250 ms, so the gateway writer (busy_timeout 5 s) is never starved |

- **Durability:** the transaction that allocates seqs and mints items runs with
  `PRAGMA synchronous=FULL` on the node's own connection. `db::configure` sets no
  `synchronous` pragma (`db.rs:1347-1355`).

## D13. Network guard, discovery and node runtime

- **Bind discipline (MESH-SI-1).** `crates/mesh/src/bind.rs` is the only place that
  binds a socket.
  - It takes an explicit `SocketAddr`.
  - It refuses unspecified addresses (`0.0.0.0`, `::`) unless `allow_all_interfaces` is
    set, which only the `--all-interfaces` flag sets.
  - A grep test, like `crates/gateway/tests/no_insecure_verifier.rs:86-104`, fails the
    build if any other file in `crates/mesh/src` calls `bind` or `TcpListener::bind`, or
    contains a wildcard literal.
  - Nothing listens by default: `mesh serve` requires `--listen`.
  - The gateway's SI-1 is untouched.
- **No NAT traversal, relay or rendezvous.** Reachability is the user's network: a LAN,
  or Tailscale/WireGuard addresses passed to `--listen` and `peer add`.
- **Address gossip:** each device publishes its configured listen addresses in its
  `device.info` item. Peers try the gossiped addresses as well as manual ones.
- **mDNS** is opt-in (`--discover`), `mdns-sd`, behind the `Discovery` trait. CI and
  tests use the in-memory fake, so they never multicast.
  - Service `_tethra-mesh._tcp.local.`.
  - The instance name is random per boot.
  - The TXT record holds only `v=1` and `m=` plus the first 16 hex characters of
    `HMAC-BLAKE3(access_key, "mdns" || utc_day)`. Members recognise their mesh; outsiders
    learn nothing linkable across days.
  - No device, user or host names. The port is the listen port.
- **Node loop** (`crates/mesh::node`):
  - Every 30 s ± 20% jitter, plus on demand: for each known peer address that is not in
    backoff, run one exchange.
  - Backoff is exponential, from 5 s up to 15 min.
  - Peer status tracks `last_success_at`, `failures` and `unreachable_since`. (The
    phi-accrual failure detector was considered and is unnecessary for ≤ 10 devices.)
  - Before each round, run the usage publisher (D14) and the cap reconciler (D15).
  - Run repair every 24 h.
- **Single instance:**
  - The node owns `<data-dir>/mesh/node.sock`, a 0600 Unix socket in a 0700 dir,
    following the gateway's pattern (`crates/gateway/src/control.rs:42-48, 661-727`).
    Binding it is the lock. It also serves `status`, `replicate-now` and `stop` to the
    CLI and desktop, using a per-boot nonce file the same way the gateway does.
  - On Windows, use an exclusive loopback TCP listener plus a nonce file, compile it,
    run it in Windows CI unit tests, and document it as "runtime untested on Windows",
    which is how the gateway is treated (ADR 0019 D8).
- **Who runs the node:**
  - `tethra mesh serve` runs in the foreground (CLI), from `TETHRA_SESSION` or
    `TETHRA_PASSWORD`. It stops when that session expires.
  - The desktop app runs it **in-process on a thread** while the app is open and
    unlocked, if the local setting "Run mesh while Tethra is open" is on.
    - This **deliberately differs** from `foreground_gateway`, which is a child process
      (`apps/desktop/src-tauri/src/main.rs:4276-4297`). Running in-process avoids handing
      keys to a child through env vars or a session file.
    - It stops on lock, on exit (the same hook points as `stop_foreground_gateway`,
      `main.rs:4366-4381, 4992-5006`), and when the setting is turned off.
  - There is no LaunchAgent for the mesh in v1. It would have to hold keys while locked,
    which ADR 0020 forbids, and on this development machine it would be unsafe to
    validate. This is a known limitation.

## D14. Usage publishing (`core::mesh::publish`)

- **Source:** `gateway_usage_daily` (`db.rs:970-983`), keyed by
  `(day, provider_id, project_id, model)`.
  - Its additive upsert is at `crates/gateway/src/writer.rs:790-815`, and line 812 stores
    `cost.unwrap_or(0)`, so unpriced usage looks free.
  - **Migration v22** therefore adds `unpriced_requests INTEGER NOT NULL DEFAULT 0` and
    `unextracted_requests INTEGER NOT NULL DEFAULT 0`. The writer increments them where
    `projectcost.rs:14-21` already classifies an exchange as priced, unpriced or
    unextracted.
  - Rows dated before v22 are labelled "split unknown before <date>".
- **Publishing deltas through a cursor:**
  - `mesh_publish_cursor(local_project_id, day, provider_id, model, published_totals…)`
    records what has been attributed so far.
  - Each run computes `delta = daily_now − published` for every bound local project and
    adds it to the counter of the **currently bound** mesh project
    (`usage.counter` totals = previous totals + delta).
  - Rebinding mid-day therefore moves only *future* traffic.
  - If `daily_now < published`, local data was deleted (`runtime::store::delete_project_data`
    and `delete_all`, `crates/core/src/runtime/store.rs:1149-1200`, or the retention sweep
    at `writer.rs:886-913`). The publisher then **bumps the epoch** of the affected
    counters and republishes the corrected totals. Deletion propagates, which keeps the
    promise in `docs/gateway/PRIVACY.md` that the deletion tools cover gateway data.
  - Skip sentinel rows whose model or provider is `''`.
- **Totals per counter:**
  - `requests`, `priced_requests`, `unpriced_requests`, `unextracted_requests`;
  - `input_tokens`, `output_tokens`, `cached_input_tokens`;
  - `estimated_cost_micros`, covering priced requests only.
- **Cost is computed on the device the usage came from**, with its own pricing table, at
  ingest time. Views say so. Cached-read tokens are excluded from estimates
  (`writer.rs:734-743`), so caps undercount cached-heavy traffic. Document it.
- **Views (`mesh usage`)** give, per mesh project, per month or day, and per device:
  - **Every number is labelled by device**, with "as of <last exchange with that
    device>".
  - A device not heard from in > 24 h is shown as **stale**, never as zero.
  - Removed devices are labelled.
  - The **SI-19 amendment** (`docs/gateway/SECURITY_INVARIANTS.md:167-171`): coverage may
    now include other paired devices, labelled per device with freshness. A missing
    device is unknown, not zero, and the totals are never summed with provider-reported
    cost.

## D15. Spend caps and enforcement (ADR 0032)

- **Cap.** `cap.def { cap_id, mesh_project_id, owner_device }` is immutable, and the
  owner is the device that created the cap.
  - The period is the UTC calendar month, the same semantics as
    `budget::period_start` (`crates/core/src/budget.rs:20-25`).
  - **Unused rights expire with the month.**
  - If the owner device is removed, the cap is **frozen**: no new minting. The user
    creates a new cap. This is honest and simple.
- **Minting (owner only):**
  - The owner mints the current month's target when the cap is created.
  - From day 20 of month m onwards, it **mints month m+1 in advance** and pre-distributes
    it. Without that, every device that is offline on the 1st would sit at zero.
- **Distribution policy:**
  - When it mints, the owner gives each device that was active (an exchange or a
    published counter) in the last 30 days an equal share, and keeps the remainder.
  - **Rebalancing** runs during exchanges. A device below 20% of its fair share sends
    `Direct RightsRequest { cap, month, want }`. A peer above 50% of its fair share
    grants `min(want, avail − 50% fair share)` by minting `cap.rights` to the requester.
    These thresholds (hysteresis) stop rights ping-ponging.
- **Raise vs lower:**
  - **Raise** adds: the owner mints `+x`. "Set to X" is never used, because two
    partitioned devices both setting it would double-mint.
  - A **raise on a non-owner device** is an explicit, labelled **local override**: it
    mints to itself under its own origin, as `cap.rights` with `from == to` and a
    payload flag `override = true`. Views show it as an override that raised the
    effective cap.
  - **Lower** sets the LWW `cap.target`. Any device can do this, but only through the
    UI/CLI with confirmation.
    - Every holder that learns of a lower target burns its unspent rights above its new
      fair share.
    - The owner reconciles any remainder by issuing `RightsRequest` reclaims.
    - Views show "pending decrease: X" until the total is ≤ the target.
    - Lowering below what has already been spent caps every device immediately.
- **Escrow fence (MESH-SI-10).** It stops the node giving away rights that the running
  gateway's snapshot, which can be up to 5 s old, still counts as available.
  1. Before publishing a transfer or burn, the node inserts
     `mesh_cap_escrow(id, cap_id, month, amount, state='pending')`.
  2. The gateway's poller (`crates/gateway/src/service.rs:374-401`, every 5 s,
     `ROUTE_POLL_INTERVAL` at `:23`) deducts every pending or acked escrow amount from
     its snapshot and writes `acked_generation = <snapshot generation>`.
  3. Only after it sees an ack does the node publish the `cap.rights` item, marking the
     escrow row `published` in the same transaction.
  4. If the gateway is **provably not running** (`gateway::control::instance_is_live`,
     `control.rs:1023`, on Unix; on Windows, where `instance_is_live` is always false
     (`control.rs:1028`), use the TCP listener identity probe `verify_listener`), the
     node publishes immediately: a gateway that starts later reads the published
     transfers anyway.
  5. If it is running and hasn't acked within 15 s, the transfer waits for the next
     round.
  - The control socket is *not* used for this, because Windows has no control channel
    (`control.rs:943-1004`).
  - Before Increment 08 the gateway doesn't enforce, so the node treats the fence as
    satisfied only when `gateway_config.cap_enforcement` is off. Increment 08 adds the
    ack path.
- **Enforcement (Increment 08; opt-in, local).**
  - The switch is `gateway_config.cap_enforcement` (local-only; a peer can't flip it),
    set through a reauth-gated core method.
  - The **`CapGate`** follows the `RouteState` pattern
    (`crates/gateway/src/routes.rs:784-900`): an `Arc` snapshot rebuilt by the poller
    from:
    - `mesh_cap_*` views;
    - authoritative local spend for the month, from `gateway_usage_daily` for the bound
      local projects;
    - pending escrow.
  - **The hot path never touches the database** (SI-12/SI-13 stay true).
  - **Spend is counted in memory when a response completes**: the cost estimate for that
    exchange is added to an atomic per cap. This doesn't depend on the writer, which
    drops records under load (SI-12). If the writer has dropped records for a capped
    project, the gate reports its accounting as "incomplete" in `status`.
  - **Near exhaustion** (avail < 2× the 95th-percentile request cost seen this month, or
    < $0.50), the gate admits **at most one in-flight request per cap**, so overshoot
    is at most one request's cost (MESH-SI-9). The docs state the bounded-overshoot rule
    honestly: cost is known only after the response.
  - **Exhausted:** a **non-retryable `403`** with a provider-shaped JSON error body. For
    OpenAI-style routes:
    `{"error":{"message":"…","type":"tethra_spend_cap","code":"spend_cap_exceeded"}}`.
    Anthropic routes use the equivalent shape. The response also carries headers
    `x-tethra-cap: exceeded; cap=<id>` and `content-type: application/json`, and is sent
    **before any upstream byte**.
    - **Never 429**: the OpenAI and Anthropic SDKs retry 429 automatically.
    - `local_response` (`crates/gateway/src/forward.rs:329`) emits text/plain only, so
      add a JSON variant.
  - **Fail open, and report it:**
    - schema mismatch in the gateway (`open_at_current_version` rejects);
    - cap tables unreadable;
    - mesh not initialized.

    In each case the gate admits requests and reports "cap enforcement inactive: <reason>"
    in `gateway status`, `mesh status` and the desktop.
  - **Caps are a self-limit, not a security boundary.** Anything that bypasses the
    gateway bypasses the cap. The docs say so.
- **Alerts (Increment 07).** These are local alerts through the existing alert system,
  with a new rule kind and dedup keys `mesh_cap:<cap>:<month>:{80,100}`. Never use
  `budget.rs`.

## D16. Credential sharing (Increment 11, ADR 0033)

- **Opt-in, one credential at a time:**
  `UnlockedVault::mesh_credential_share(master_password, credential_id, recipients)`.
  - The default recipients are all current non-removed devices. The credential's project
    must be bound to a mesh project.
  - Password-locked projects (`key_wrap_mode = 'vault+password'`) also need that project
    unlocked.
- **Envelope.** For each recipient there is one `share.sealed` item, signed by the
  sharer like every item:
  - payload: `{ share_id, mesh_project_id, credential_name, provider, value_version, recipient, sealed }`;
  - `sealed = crypto_box::seal(recipient.seal_pub, plaintext)`;
  - `plaintext` is JSON
    `{ mesh_id, share_id, credential_name, provider, value_version, recipient, sharer, value }`.
- **Sealed boxes are anonymous**, so the recipient checks after opening that every bound
  field matches the signed outer payload and the signer. Without that check, a member
  could plant a credential in another device's vault.
- **Import:** `UnlockedVault::mesh_credential_import(master_password, share_id, local_project_id)`.
  - It requires reauth, unwraps the sealing key only for the duration of the call, opens
    the box, verifies the bindings, and stores the value through the **existing
    add/update credential path**, re-encrypted under the local project key.
  - **Nothing is imported automatically.**
- **Lifecycle:**
  - `cap`-style LWW per `(credential_ref, recipient)`: only the latest share is kept.
  - `share.revoke` is a tombstone.
  - Shares addressed to removed devices are purged from views and storage.
  - **Reseal:** when the sharer is unlocked and sees a new roster member that the user
    included ("all my devices" was chosen at share time), it offers to reseal, which
    needs reauth.
- **Honest limits:**
  - No forward secrecy (static sealing keys).
  - A recipient keeps whatever it imported.
  - Revoking a share does **not** revoke the credential at the provider. The UI links to
    the existing rotation flow.
- **Canaries:** a test captures every byte written to the mesh socket during a share and
  asserts the fake credential never appears in plaintext. It also asserts the credential
  never appears in logs, errors, `--json` output, the item store's plaintext columns, or
  `doctor` output.

## D17. Storage schema

- **Migration v21** (mesh) and **v22** (the usage-split columns) are appended to `MIGRATIONS` in
  `crates/core/src/db.rs`. v20, at line 1178, is the latest today. The tables are
  STRICT, and migrations are append-only (SI-17). Exact columns are finalized in
  Increment 03 (v21) and Increment 06 (v22).
- **Local-only tables** (never replicated; all wiped by `on_restore` and `leave`):
  - `mesh_meta(key PK, value)`: settings, `hlc_high_water`, counters, `clock_skew/*`,
    `rejected_items`, repair stats.
  - `mesh_self(singleton)`: mesh_id, device_id, device_name, the three public keys, the
    four encrypted private blobs plus the access-key epoch, `next_seq`, `marker_nonce`,
    `state ∈ {active, rollback_recovery, forked, left}`, `created_at`.
  - `mesh_peers(addr PK, device_id NULL, source ∈ {manual,gossip,mdns}, last_attempt_at, last_success_at, failures, unreachable_since, last_error)`.
  - `mesh_invites(token_hash PK, created_at, expires_at, attempts, used_at, used_by)`.
  - `mesh_project_bindings(local_project_id PK REFERENCES projects ON DELETE CASCADE, mesh_project_id, bound_at)`.
  - `mesh_publish_cursor(local_project_id, day, provider_id, model, published totals…, PK(...))`.
  - `mesh_cap_escrow(id PK, cap_id, month, to_device, amount_micros, state ∈ {pending,acked,published,cancelled}, acked_generation, created_at, updated_at)`.
  - `mesh_exchange_log(id INTEGER PK, peer_device, at, direction, items_in, items_out, result, error)`: bounded to the last 1 000 rows; drives "last exchanged".
  - `mesh_fork_evidence(origin, seq, hash_a, hash_b, seen_at, PK(origin, seq))`.
  - **[Added 02, R9]** `mesh_dots(origin, seq, hash, chain, PK(origin, seq))`: the dot
    log and chain (PROTOCOL.md §7.1). One row per accepted dot, written in the same
    transaction as the commit or mint that covers it; never pruned below the VV.
  - `mesh_share_imports(share_id PK, credential_id REFERENCES credentials ON DELETE CASCADE, imported_at)`.
    Created in v21 and populated from Increment 11, which records which shares this
    device imported.
- **Replicated store:**
  - `mesh_items(origin, seq, kind, item_key, hlc, hash, bytes BLOB, received_at, PK(origin, seq))`
    with `UNIQUE(kind, item_key, origin)` (the latest per origin) and an index on
    `(kind, item_key)`.
  - `mesh_vv(origin PK, max_seq)`.
- **Materialized views:** these are plain tables, *derived* only from `mesh_items` and
  rebuildable by `mesh doctor --rebuild`. Their consistency with `mesh_items` is itself
  a test invariant.
  - `mesh_devices`, `mesh_projects`, `mesh_usage_counters`, `mesh_caps`,
    `mesh_cap_targets`, `mesh_cap_rights`, `mesh_cap_used`, `mesh_shares`.
- **Local-only enforcement switch:** `gateway_config.cap_enforcement INTEGER NOT NULL DEFAULT 0`,
  added in v21. `gateway_config` is defined at `db.rs:881`.

## D18. Threat model delta

**New trust boundary:** the LAN or VPN between paired devices.

**Adversaries and responses:**

| Adversary | Response |
|---|---|
| Passive LAN observer | Noise encryption; mDNS reveals only a daily-rotating HMAC |
| Active LAN prober | psk0, so it cannot learn static keys; rate limits; bounded parsing before auth (only the handshake is parsed pre-auth) |
| Stolen invite token | 10-minute single use plus attempt lockout; residual risk documented |
| Removed or stolen device | Removal and rotation; eventual consistency documented; credentials it already imported stay compromised, so rotate them (link to the rotation flow) |
| Malicious member | It is the user's own device, so it is trusted. Signatures stop it impersonating *other* origins. View clamping stops it creating rights out of nothing in others' views. Bound checks stop credential planting. It can still remove devices, publish false usage about itself, and DoS within the rate limits. Documented. |
| Cloned or rolled-back installation | Marker file, fork evidence, and wipe on restore (D5) |
| Clock-skewed device | Accept and flag, with the drift bound (D7) |

**Unchanged:** malware running as the user, and memory inspection, remain out of scope
(`THREAT_MODEL.md:165`). Mesh metadata at rest is plaintext like other usage data
(ADR 0018); private keys are encrypted.

## D19. Security invariants (`docs/mesh/SECURITY_INVARIANTS.md`, MESH-SI-n)

Each invariant must have at least one test named in TEST_PLAN.

1. **Bind discipline.** No mesh listener binds an unspecified address without
   `--all-interfaces`; nothing listens unless `--listen` was given; the gateway stays
   loopback-only.
2. **No mesh data before authentication.** No mesh data is accepted or sent before a
   Noise handshake completes with a non-removed roster member's static key, or with a
   valid pairing token.
3. **Signed items.** Every item is Ed25519-signed by its origin and verified before it is
   stored, and stored bytes are exactly the received bytes.
4. **Commit-only VV.** A VV entry advances only in the transaction that stores every item
   it covers.
5. **No identity reuse.** Restore wipes identity; a marker mismatch or fork stops the node.
6. **Credential values.** They leave a device only as a sealed box to a specific roster
   member, after reauth. They never appear in plaintext in frames, logs, errors, JSON
   output or plaintext columns.
7. **Key lifetime.** Mesh private keys are in memory only while the vault is unlocked (or
   the CLI session is live). The sealing key is used only inside a reauth-gated import.
8. **Bounds.** Every frame, batch, stage, session, rate and transaction is bounded (D12).
9. **Enforcement.** Cap enforcement is local and opt-in, and peers can't toggle it. The
   forward path never waits on the database or the network for a cap decision.
   Overshoot is ≤ one in-flight request's cost per cap per device.
10. **No double spending.** Rights are never spent twice; transfers are fenced against the
    running gateway's snapshot.
11. **Honest cross-device figures.** They are labelled per device with freshness. A
    missing device is unknown, never zero. They are never summed with provider-reported
    cost.
12. **No third parties.** No Tethra server, relay, rendezvous or third-party NAT service.
13. **Nothing automatic.** No auto-binding, auto-import or auto-enforcement.
14. **No analytics.** The mesh emits no analytics events; the `docs/ANALYTICS.md`
    allowlists are unchanged.
15. **No unsafe code.** `#![forbid(unsafe_code)]` in `crates/mesh`, and core stays the same.

## D20. CLI command tree (`apps/cli/src/mesh_cmd.rs`)

Add `#[command(subcommand)] Mesh(mesh_cmd::MeshCmd)` to `Commands` in
`apps/cli/src/lib.rs`. Model it on `backup_cmd.rs` (enum at lines 10-32, run at 34-102)
and use the reauth helper pattern from `backup_cmd.rs:37-40`. Every command supports
`--json`.

```text
tethra mesh init [--name <device-name>]                       (03)
tethra mesh status                                            (03, extended 05/06/07/08)
tethra mesh invite [--ttl <minutes>] [--wait]                 (04, reauth)
tethra mesh join <invite> [--name <device-name>]              (04)
tethra mesh devices | rename <device> <name>                  (04)
tethra mesh remove <device>                                   (04, confirm + reauth)
tethra mesh leave                                             (04, confirm + reauth)
tethra mesh serve --listen <addr:port> [--listen …] [--all-interfaces] [--discover]   (04 minimal, 05 full)
tethra mesh replicate [--peer <addr:port>]                    (04 one-shot, 05 via node)
tethra mesh peer add <addr:port> | list | remove <addr:port>  (05)
tethra mesh doctor [--rebuild]                                (05)
tethra mesh project share <local> | bind <mesh> <local> | unbind <local>
                    | rename <mesh> <name> | archive <mesh> | merge <a> <b> | list   (06)
tethra mesh usage [--project <mesh>] [--month YYYY-MM] [--day YYYY-MM-DD] [--by-device]   (06)
tethra mesh cap create <mesh-project> --monthly <usd> | raise <cap> <usd> | lower <cap> <usd>
                | show [<cap>] | rights <cap> | reclaim <cap>                         (07)
tethra mesh cap enforce <cap|--all> on|off                    (08, reauth)
tethra mesh credential share <credential> [--to <device>…] | list
                       | import <share> --project <local> | revoke <share>            (11, reauth)
```

**Errors:** `CoreError::Mesh(MeshError)`, with variants such as `NotInitialized`,
`AlreadyInMesh`, `InviteExpired`, `InviteUsed`, `NotAMember`, `Removed`, `Forked`,
`IdentityMismatch`, `ProtocolMismatch`, `Bound(…)`, `CapFrozen`, `MergeRefused` and
`ShareBindingMismatch`.

**Messages:** never include key material, tokens (after printing an invite once), or
credential values. Tests assert this.

**Local audit events** (`audit::record`): `mesh_initialized`, `mesh_invite_created`,
`mesh_device_joined`, `mesh_device_removed`, `mesh_left`, `mesh_cap_created`,
`mesh_cap_changed`, `mesh_cap_enforcement_changed`, `mesh_credential_shared`,
`mesh_credential_imported` and `mesh_share_revoked`. They stay local.

## D21. Test strategy (`docs/mesh/TEST_PLAN.md`)

| Layer | Where | What |
|---|---|---|
| Algebraic laws | `crates/core/src/mesh/crdt/*` unit tests | commutativity, associativity, idempotence, monotonicity; ≥ 10k cases per law from the seeded `sim::rng::SplitMix64` (zero deps) |
| HLC | `hlc` unit tests | monotonicity, drift bound, persistence across restart, logical overflow |
| Codec and signing | `item`/`sign` unit tests | round trip, tamper (each byte flipped → reject), wrong mesh, wrong origin key, oversize |
| Protocol and simulator | `crates/core/tests/mesh_sim.rs` (feature `mesh-sim`) | N nodes; seeded faults: drop, duplicate, reorder, delay, partition and heal, crash mid-session, restart from store, clock skew, removal, fork. Invariants: **convergence to the global join** (oracle), Commit-only VV, removal exclusion, fork detection, **cap safety**, no forged-origin acceptance. CI runs 200 seeds in under 60 s; `scripts/mesh_soak.sh` runs ignored long soaks. Failures print `MESH_SIM_SEED=<n>` for replay. |
| Independent oracle | `sim/oracle.rs` | a naive model written from PROTOCOL.md alone, by an isolated subagent (Increment 02) |
| Store conformance | `crates/core/tests/mesh_store_conformance.rs` | the same simulator suite against `SqliteStore` on temp files, plus crash between batches |
| Schema | `crates/core/tests/mesh_schema.rs` | migrations v21/v22, STRICT, the restore wipe, the `migration_safety` exemption |
| Transport | `crates/mesh/tests/*` | multi-node on 127.0.0.1:0 with temp data dirs: pair, replicate, remove, rotate key, bounds, malformed frames, handshake floods, wrong psk, removed key, bind guard (grep) |
| CLI | `apps/cli/tests/mesh_cli.rs` | init/invite/join/replicate/usage/cap across 2-3 temp `TETHRA_DIR`s, using the `apps/cli/tests/common/mod.rs:50-69` env-clearing pattern |
| Gateway | `crates/gateway/tests/cap_enforcement.rs` + `perf.rs` addition | 403 shape, before-upstream-byte, one-in-flight near exhaustion, fail-open, fence acks, no DB on hot path |
| Desktop | vitest + `tauri_command_authz.rs` | views, reauth enforcement, error redaction |
| Leakage canaries | across layers | the fake credential and tokens never appear on the wire, in logs, errors or JSON |
| Mutation | `scripts/mutation_checks.sh` (Increment 12) | mutants for: VV advanced before commit, signature check skipped, the drift clamp removed, the escrow fence skipped, view clamping removed, the cutoff ignored |

## Appendix: facts from `main` at 5ec8198 that the increments rely on

- `crates/core/src/lib.rs:20`: core performs no network I/O. Lines 47-48: insert
  `pub mod mesh;` there.
- `crates/core/src/db.rs`:
  - line 1178: v20 is the latest migration;
  - lines 1347-1355: `configure` sets WAL, `foreign_keys`, `secure_delete` and
    `busy_timeout` 5 s, with no `synchronous` pragma;
  - lines 1365-1385: `migrate_with`, one transaction per migration;
  - lines 1401-1418: `open_at_current_version`, used by background processes;
  - line 881: `gateway_config`;
  - lines 970-983: `gateway_usage_daily`.
- `crates/core/src/backup.rs`:
  - lines 150-153: the backup copies every `sqlite_master` table;
  - lines 508-586: `restore_backup`;
  - lines 583-584: `session::destroy` and the audit record;
  - line 590: `restore_v2`.
- `crates/core/tests/migration_safety.rs`: row-count equality across restore.
  `scripts/smoke.sh:388`: the 9-test pin.
- `crates/core/src/budget.rs:20-25`: `period_start`, the UTC calendar month. Budgets
  only raise alerts.
- `crates/core/src/crypto.rs:165-264`: AAD constructors bound to `vault_id`.
  `crypto_box` 0.9.1 is already a core dependency (`destinations.rs:1546-1557`).
- `crates/core/src/vault.rs`:
  - `UnlockedVault` (around line 479);
  - `verify_master_password` (the reauth pattern);
  - `create_vault` (lines 165-215);
  - `default_data_dir` and `TETHRA_DIR` handling (lines 82-111).
- `crates/gateway/src/routes.rs:784-900`: the `RouteState` `Arc` snapshot with
  `data_version` polling.
- `crates/gateway/src/service.rs:23`: `ROUTE_POLL_INTERVAL` = 5 s. Lines 374-401: the
  poller thread.
- `crates/gateway/src/writer.rs`:
  - lines 734-762: cached-read tokens excluded, plus the cost estimate;
  - lines 790-815: the daily upsert (line 812 stores `unwrap_or(0)`);
  - lines 886-913: the retention sweep.
- `crates/gateway/src/forward.rs:329`: `local_response`, text/plain only.
- `crates/gateway/src/control.rs`:
  - lines 42-48 and 661-727: the Unix control socket and single-instance lock;
  - lines 943-1004: the Windows stubs;
  - line 1023: `instance_is_live` (line 1028: always false on non-Unix).
- `crates/gateway/tests/no_insecure_verifier.rs:86-104`: the SI-1 grep guard pattern.
- `docs/gateway/SECURITY_INVARIANTS.md`: SI-1 at line 11, SI-12 to SI-14 at 132-147,
  SI-19 at 167.
- `crates/core/src/projectcost.rs:14-21`: the priced/unpriced/unextracted honesty
  split. `crates/core/src/runtime/store.rs:1149-1200`: the deletion tools.
- `apps/cli/src/lib.rs`: the clap `Commands` enum (lines 83-177) and dispatch (204-239).
  `apps/cli/src/ctx.rs:68-92`: `unlocked()`. `apps/cli/src/backup_cmd.rs`: the template.
- `apps/cli/tests/common/mod.rs:50-69`: the hermetic CLI test environment.
- `apps/desktop/src-tauri/src/main.rs`:
  - lines 91-100: `AppState`;
  - lines 154-199: `with_vault*`;
  - lines 4276-4297: the `foreground_gateway` spawn;
  - lines 4366-4381: stop;
  - lines 4992-5006: exit.
  - 212 commands are registered at 4751+.
- `crates/core/tests/tauri_command_authz.rs:1-23` and
  `docs/remediation-phase-2/tauri_command_inventory.json`: the authz pattern and
  inventory. The inventory is stale at 137 commands; update the mesh rows only.
- `.github/workflows/ci.yml`: lines 44, 54 and 71 hold the explicit `-p` lists.
- `Cargo.toml:17`: MSRV 1.85. `crates/tracking/Cargo.toml:37-43`: the self-dev-dependency
  feature pattern.
- `docs/decisions/`: 0001-0030 exist, and 0028 is used twice. **The next ADR numbers are
  0031 (mesh), 0032 (spend caps) and 0033 (credential sharing).**
