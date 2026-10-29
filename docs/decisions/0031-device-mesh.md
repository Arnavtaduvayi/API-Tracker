# ADR 0031 — Tethra Mesh: peer-to-peer replication between your own devices

Status: accepted (in development on `feat/device-mesh`; see
`docs/mesh/increments/STATUS.md` for what has landed)
Date: 2026-10-26
Amends: `CLAUDE.md` ("Local-first requirements", "Do not add"),
`docs/PRODUCT_SPEC.md` §4, root `THREAT_MODEL.md`, and — taking effect in
Increment 06 — gateway SI-19 (`docs/gateway/SECURITY_INVARIANTS.md`)
Preserves: gateway SI-1 (loopback-only gateway), ADR 0018 (runtime
observability storage), ADR 0019 (local gateway), ADR 0020 (matching-key
lifecycle: drop on lock)

## Context

Tethra is local-first and single-user, and a developer increasingly has more
than one machine: a laptop, a desktop, a home server running agents. Each
installation tracks its own gateway traffic, so "how much has project X spent
this month?" has only per-machine answers, and a spend limit enforced on one
machine says nothing about the others. Users who want one picture today copy
`vault.db` through a cloud drive — which the root `THREAT_MODEL.md` already
lists as a risk, corrupts SQLite under concurrent writers, and clones device
identities.

Three properties have to hold together:

1. **No server.** CLAUDE.md forbids a Tethra-hosted backend, relay or cloud
   sync, and the owner rejected any third party holding or forwarding data.
2. **Offline-first.** A laptop on a plane must keep working fully — including
   enforcing a spend cap — and converge when it reconnects.
3. **Honest numbers.** Cross-device figures must say which device each number
   came from and how fresh it is; a device not heard from is unknown, not zero.

The owner decided (2026-10-26): a peer-to-peer CRDT mesh, not consensus; usage,
project metadata and spend caps replicate first, encrypted credential values
only later and opt-in per credential; peers are only the user's own devices;
at most 12 increments.

## Decision

**D1 — A mesh of the user's own devices, replicating signed items.** A *mesh*
is a set of paired devices (a *device* is one data directory, not a machine).
The only thing that replicates is an **item**: a canonical-JSON body signed with
the origin device's Ed25519 key. What replicates is fixed and small: the device
roster, explicitly shared projects, per-device daily usage counters, spend caps
and their rights, mesh settings, and — from Increment 11, opt-in — credential
shares sealed to specific devices. Local project ids, bindings, keys, gateway
request events, routes, findings, alerts and audit rows never replicate
(`docs/mesh/ARCHITECTURE.md` "What replicates").

**D2 — State-based CRDTs over single-writer entries.** Every item is one
origin's entry for one `(kind, key)`; an origin's higher `seq` supersedes its
lower one. Four CRDTs combine entries across origins: last-writer-wins maps
(HLC-ordered), owner-written counters (labelled per device), a two-phase roster
with removal cutoffs and a single genesis, and a Balegas-style bounded counter
for spend-cap rights with clamped views. Every join is commutative, associative
and idempotent, proved by seeded law tests (≥ 10 000 cases per law).

**D3 — Hybrid logical clocks, accept-and-flag.** 48-bit physical milliseconds
plus a 16-bit logical counter. Every validly signed item is accepted whatever
its timestamp; one beyond `now + 60 s` is flagged and never drags the local
clock further. A user's edit is lifted above the value they were looking at
even if a skewed device wrote it.

**D4 — Delta anti-entropy with commit-only version vectors.** Two devices
exchange Hello (version vectors), stream what the other lacks, and the receiver
applies everything in one transaction at `Commit`. A version vector entry never
advances without the items it covers (MESH-SI-4). A digest-based repair is a
safety net whose firing is surfaced as a bug signal.

**D5 — Membership by invitation; identity never reused.** A short-lived,
single-use invite token admits a device over `Noise_XXpsk3`; normal sessions use
`Noise_XXpsk0` keyed by a mesh access key, and the remote static key must belong
to an active roster device. Removal mints a cutoff and rotates the access key.
A restored backup wipes mesh identity, a marker file catches cloned or
rolled-back data directories, and two items at one dot are fork evidence.

**D6 — Layering.** `core::mesh` is pure and sans-IO (core still performs no
network I/O). A new `crates/mesh` (Increment 04) holds the only network code,
with `#![forbid(unsafe_code)]`, std threads (no async runtime) and a single
`bind` function. The gateway depends on core only and reads cap state from it.

**D7 — Nothing listens by default; no third parties.** `mesh serve` requires
`--listen`; unspecified addresses need `--all-interfaces`; mDNS is opt-in and
publishes only a daily-rotating HMAC. Reachability is the user's LAN or VPN
(Tailscale, WireGuard). There is no NAT traversal, relay, rendezvous or STUN.

**D8 — Bounds everywhere.** Items ≤ 64 KiB, frames ≤ 1 MiB, batches ≤ 512,
≤ 50 000 staged items per session, ≤ 8 sessions, handshake/idle/session
timeouts, ≤ 10 handshakes per IP per minute, ≤ 5 attempts per invite, ≤ 10 000
items per origin per hour, write transactions chunked to ~250 ms (MESH-SI-8).

**D9 — Node runtime tied to the unlocked vault.** The node holds the signing,
Noise and access keys only while the vault is unlocked (desktop, in-process) or
the CLI session lives (`tethra mesh serve`), per ADR 0020's drop-on-lock rule.
There is no LaunchAgent for the mesh in v1. The sealing key is never held by the
node.

Spend-cap policy and enforcement are ADR 0032 (Increments 07-08); credential
sharing is ADR 0033 (Increment 11).

### Decisions resolved while specifying (Increment 01)

Writing the normative protocol (`docs/mesh/PROTOCOL.md`) and its law tests
exposed places where the design brief was ambiguous or, read literally, would
not converge. Each is resolved below and in `docs/mesh/increments/DESIGN.md`.

* **R1 — An origin's order is its `seq`, for every kind.** The brief joined an
  origin's LWW entries by HLC and its counters epoch-lexicographically. The
  store keeps one item per `(kind, key, origin)` and relaying latest-only is safe
  only if a higher seq supersedes; under any other per-origin order, a
  misbehaving origin makes devices, incremental views and rebuilt views
  disagree. The HLC still orders *across* origins, and the `(epoch, totals)`
  lattice is now the rule an honest writer follows (a successor that breaks it
  is counted as a regression). For honest devices nothing changes.
* **R2 — Removed origins' items keep relaying.** The brief stopped relaying items
  above a removal cutoff. Then a device holding a removed origin's older,
  admitted entry never learns it was superseded, while another shows nothing
  for that origin — divergence forever. Items now relay regardless; admission
  excludes them. Garbage collection must not delete them (PROTOCOL §8.4).
* **R3 — The bounded-counter clamp is one hop, transfers before spend.** "Clamp
  outgoing transfers to minted plus received minus used" is recursive (received
  depends on others' clamps) and, taken transitively, a fixpoint whose iteration
  count hostile values control (two forged rows of 2^60 cycle for ~2^60 rounds).
  Outgoing amounts are honoured from `minted + raw received`, burn first then
  ascending device id; spend is not part of the budget, so an overshooting
  device goes negative itself instead of clawing rights back from devices it
  paid. Honest devices are never clamped; a single device cannot create rights
  in others' views.
* **R4 — Non-owner self-mints are labelled overrides.** The brief's "only the
  owner may mint" (D8) and "a non-owner raise is a labelled local override"
  (D15) are reconciled: `R[i][i]` counts for any `i`, and views label it an
  override when `i` is not the cap owner.
* **R5 — Roster resolution is stratified.** Adds, removes and cutoffs were
  mutually recursive. Resolution now runs in a fixed order (reach from the
  genesis → key conflicts → known → cutoffs from known removers → members with
  cutoffs). Amended by R8/R9 in Increment 02: key conflicts are gone (ids are
  derived from keys), and fork reports by known devices feed the cutoffs. Consequences: two devices removing each other are both removed (as
  the brief wanted); a removed device's later adds admit no one; a member that
  re-adds an existing id with other keys locks it out rather than hijacking it.
* **R6 — The genesis is a mesh parameter.** A self-add proves nothing by itself
  (anyone can sign one), so every member holds the genesis `device_id`, learned
  in `PairAccept` (Increment 04 adds the field).
* **R7 — `local_write_ts` does not move the clock.** Lifting one write above a
  skewed value must not pull the device's clock into the future.

### Decisions resolved while specifying sessions (Increment 02)

* **R8 — Device ids are derived from the device's keys** (first 16 bytes of a
  BLAKE3 derive-key over the three public keys). With random ids, a member could
  re-add an existing id with other keys; resolving such "key conflicts" by
  banning the id cannot converge, because whether a conflicted device's own adds
  were stored depends on timing. With derived ids, such an add is simply
  invalid. Ids stay random-looking and carry nothing identifying.
* **R9 — Forks are detected with per-origin dot logs and hash chains, and
  recorded as `fork.report` items.** Every device keeps the hash it accepted at
  every dot (commits now carry the hashes of superseded dots), and `Hello`
  carries each origin's chain head. Two devices whose logs diverge find the
  first differing seq by bisection; the brief's dot-collision-only detection
  misses forks whose items were superseded before they met. Reports make the
  fork part of the replicated roster, so every device converges on it; a forked
  origin's items keep relaying and are repaired in full so every device ends
  with the same entries (PROTOCOL §7).
* **R10 — A known kind with an invalid payload is rejected at ingest**, keeping
  the valid prefix of that origin's batch. Storing it but leaving it out of views
  would let it supersede a valid entry on some devices and not others.
* **R11 — Repair compares per-origin digests carried in `Hello`** instead of
  `(kind, scope)` buckets in `RepairDigest`/`RepairWant`; `Want` is unused.
  With ≤ 10 devices the digests are a few hundred bytes, and per-origin
  granularity is exactly what fork repair needs.
* **R12 — Frames carry a per-direction sequence number**, so any reordered,
  duplicated or dropped frame ends the session instead of being misapplied.

### Decisions forced by the simulator and the oracle (Increment 02)

* **R13 — Never stream an origin whose chains disagree.** The simulator found
  seeds where a session died after the peer committed a second branch's items
  but before the fork bisection finished, leaving a log that mixed both
  branches and no report; later comparisons then found the fork late or never.
  A suspected-forked origin now travels by repair only, which never touches a
  dot log, so the detection guarantee holds.
* **R14 — The dense-prefix validity rule applies only below an origin's fork
  point.** The independent oracle disagreed with every device about a forked
  device's own `fork.report`: devices held it (repair needs no dot log), while
  the rule, applied to every seq, discarded it. The spec now matches what can
  be implemented: at or above the fork point items need only be signed and
  well-formed.
* **R15 — A commit compares every hash it carries for an already-logged dot
  with the dot log, and never extends a log that disagrees.** The release soak
  (22 000 seeds) found the race: two concurrent sessions at one device each
  passed the `Hello` chain comparison against the same prefix, and the second
  commit appended its branch on top of the first. Superseded items travel as
  dot hashes, so the comparison must cover dots, not only items. The 11 seeds
  are now regression tests.

### Decisions made while building storage (Increment 03)

* **R16 — An item's `seq` is at most 2^63 − 1.** The codec now refuses larger
  values. Every accepted seq then fits SQLite's signed 64-bit `INTEGER` and
  sorts correctly there, so range reads of the dot log and the item store
  work for every item a device can hold. Without the bound, a member could
  sign a repair item at seq 2^64 − 1 (repair skips the gap check) and make
  every SQLite commit containing it fail. No honest origin reaches 2^63
  items.
* **R17 — The views are the in-memory `State`, rebuilt from `mesh_items` when
  the store opens; migration v21 has no SQL view tables.** DESIGN §D17 listed
  eight materialized tables (`mesh_devices` … `mesh_shares`). Every value in
  them depends on the roster (cutoffs, forks and admission), so they would
  need a full recomputation on every removal or fork report. A raw per-origin
  projection would also duplicate `mesh_items`, which already holds exactly
  the latest entry per `(kind, key, origin)`. `State` is the code the
  simulator and the independent oracle check, and the SQLite store keeps it
  identical to a rebuild (conformance invariant 3, plus a fresh-load
  comparison after every run). A reader that needs only some kinds — the
  gateway's cap snapshot in Increment 08, say — loads those rows by the
  `(kind, item_key)` index and folds them with the same `State::apply`. If a
  later increment needs an SQL-side projection for performance, it adds one
  in a new migration, together with its reader.
* **R18 — Store reads that go to disk are fallible, and a failed read ends the
  session.** The dot log grows with every item any device ever minted, so the
  SQLite store reads it, and the held items, from disk on demand.
  `MeshStore::{dot_hash, dot_hashes, chain_at, held_items}` return `Result`.
  A session whose store read fails ends with `Bye { reason: "Unavailable" }`
  and sends nothing built from the failed read. Treating a failed read as an
  empty one could stream dot hashes without their items and let a peer commit
  a range it does not hold. The VV, views, counters and per-origin digests stay
  in memory, so `vv()`, `state()` and `origin_digest()` cannot fail.

Smaller storage decisions (Increment 03; DESIGN §D17 is amended to match):

- `mesh_items` has primary key `(origin, seq, hash)`, not `(origin, seq)`: a
  forked origin can put two different items at one dot. `UNIQUE(kind,
  item_key, origin)` keeps one item per key; its index also serves lookups by
  `(kind, item_key)`, so there is no separate index. There is no `hlc` column
  (it is in the stored bytes), and `received_at` is integer milliseconds from
  the store's clock.
- `mesh_self` has no `next_seq`; it is `mesh_vv[self] + 1`, so it cannot
  disagree with the dot log. It does have `genesis_device` (R6). Access keys
  live in `mesh_access_keys`, one row per epoch, so the rotation in Increment
  04 needs no migration.
- AAD for wrapped mesh keys binds the vault **and** the device id
  (`mesh_*_key(vault_id, device_id)`), or the mesh id and epoch
  (`mesh_access_key(vault_id, mesh_id, epoch)`). A leftover blob from an
  earlier identity in the same vault then never opens.
- **Chunked commits keep whole origins together.** A chunk holds every item,
  dot and VV entry of some origins, so a crash between chunks leaves the state
  a smaller valid commit would have produced. Splitting one origin's range is
  unsafe: a superseded dot would be logged before the item that supersedes
  it. One origin's range — at most the session's 50 000 staged rows — is one
  transaction (KNOWN_LIMITATIONS).
- **The marker's rollback rule.** A store writes the marker one block (64 seqs)
  ahead before it uses the block's first seq. A database is "rolled back" when
  the marker's mark exceeds `vv[self] + 64`. A rollback inside the current
  block cannot be seen by the marker; the wire's fork detection covers it.
- The store reloads its in-memory mirror when another process has written
  (`mesh_meta.write_gen`), inside the write transaction. A CLI command and a
  running node can therefore both mint without reusing a seq.

### Decisions made while building the transport (Increment 04)

* **R19 — The pairing psk is stored, encrypted under the vault key.** PROTOCOL
  §9 derives the psk from the invite *token* and stores only the token's hash,
  so the inviter could never run the handshake. Migration v22 adds
  `mesh_invites.wrapped_psk`: the psk encrypted under the vault key, with AAD
  naming the vault and the token hash. The invite row is still keyed by the
  hash. A running node reads the psk through `MeshVault`, a capability limited
  to mesh access keys and invite psks. A copy of the database alone cannot
  pair. The alternative, storing the psk in the clear, would make database
  read access during an invite's lifetime enough to join. Increment 06's
  usage-split migration becomes v23.
* **R20 — A 16-byte preamble picks the handshake, and pairing sends the invite
  hint.** The responder must know which handshake to run (and, for pairing,
  which invite's psk) before it reads message 1. The hint is the first 8 bytes
  of the token's hash. The inviter answers only a hint that matches a live
  invite, so its static key (sent in `XXpsk3`'s message 2, before the psk is
  mixed in) reaches only a client holding the invite's hint.
* **R21 — Each side sends its current access key in every authenticated
  session** (`Direct AccessKeyUpdate`), so a rotation spreads with no per-peer
  queue, and a device that was offline catches up in its next session within
  the 30-day grace period. Three rules, added after the Increment 04 review,
  make this safe:
  - A received key is applied only after the exchange's commit, and only if
    its epoch is at most `1 + removals in the local roster`. Without the bound,
    any member could push epoch `u32::MAX` and block every later removal's
    rotation. Without the ordering, a device could take a key before it learns
    of the removal behind it and pass it to the removed device.
  - Two keys for one epoch (concurrent removals) resolve to the larger BLAKE3
    hash, so the mesh cannot split.
  - Removing an already-removed device is refused.

  The roster check at the handshake stays the real gate. The access key keeps
  probers from learning static keys and cuts removed devices off at message 1
  once every member has moved on.

Smaller transport decisions (Increment 04):

- `snow` supports both `XXpsk0` and `XXpsk3`, so the D10 fallback to plain
  `Noise_XX` was not needed: a wrong access key fails at message 1, and the
  responder sends nothing (`bounds::a_wrong_access_key_fails_at_message_one_and_reveals_no_static_key`).
- An exchange uses a writer thread beside the reading thread, sharing `snow`'s
  stateless transport (explicit nonces per direction). Two peers streaming at
  once could otherwise block on full socket buffers.
- A running node refreshes its store from disk (`SqliteStore::refresh`, one
  read of the write generation) before each use, so a removal made by a CLI
  command applies at the node's next handshake.
- The inviter's side of pairing is `membership::accept_pairing(store, …)`, called
  by the network crate with the node's keys, instead of an `UnlockedVault`
  method: the serving thread holds the node, not the vault. The reauth-gated
  step is creating the invite.
- `mesh remove` and `mesh leave` confirm with `--yes` in non-interactive runs
  (the `backup restore` pattern), then reauthenticate.

### Decisions made while building the node (Increment 05)

* **R22 — A rollback hold is stored per reporting device, applies to every
  minter, and ends with the report.** PROTOCOL §7.4 says a device told it is
  behind its own history "MUST NOT mint again until `vv[self] ≥ held_seq`", but
  not where that state lives or what ends it. As built:
  - the notice is stored in `mesh_meta` as `rollback_hold/<reporter>`, so the
    node, its round hooks and every CLI command on the same database refuse to
    mint (`MeshError::RollbackHold`), not just the session that heard it;
  - a hold counts only while its reporter is an **active** device, and while
    the reported seq is above `vv[self]`;
  - a completed exchange with the reporter in which it did **not** report
    again clears its hold (it no longer holds anything past this device's
    log); a repeated report stays, because one exchange carries at most
    50 000 items and a large rollback takes several;
  - `mesh remove` clears the target's own report before it mints the removal.
    Otherwise a member that falsely reports a rollback would block its own
    removal (a removal is a mint).
  The alternatives were an in-memory flag in the node (other processes could
  then mint into a seq a peer holds, forking the device) and a hold with no
  release but satisfaction (a lying member could stop this device's writes for
  good, with no way to remove it).

Smaller node decisions (Increment 05):

- The loop lives in `crates/mesh::runtime` (`RunningNode`); `node.rs` keeps the
  shared `MeshNode`. The peer table and lag/repair records are in
  `core::mesh::peers` (shared with the desktop); backoff and target selection
  are `crates/mesh::peers`.
- **Repair cadence.** Every exchange compares per-origin digests and repairs
  (R11), so DESIGN §D9's "repair every 24 h" is a record, not a mechanism: once
  a day the node marks a round as a repair round (`node/last_repair` in
  `mesh_meta`: when, exchanges, and whether `repairs_changed` moved).
  `doctor --repair` runs one on demand.
- **Lag** is the peer's `Hello` VV next to this device's at that moment
  (`node/peer/<device>` in `mesh_meta`), plus the origins whose digests
  differed at equal VVs. No migration: `mesh_meta.value` is `ANY`, and the
  store's loader skips non-integer values.
- **`doctor --rebuild` rebuilds the item store, not view tables** (there are
  none, R17): it rewrites each row's index columns from its bytes and removes
  rows that are unreadable or unsigned. The VV and dot log stay, so repair
  re-fetches removed items from a peer.
- **The control channel** is the gateway's pattern: a Unix socket bound in
  `bind.rs` (the single-instance lock), a per-boot nonce compared in constant
  time, one JSON line ≤ 8 KiB, and a target that holds status only, never the
  keys. On Windows it is a loopback TCP listener whose port is in the nonce
  file (runtime untested).
- **Ctrl-C** ends `mesh serve` without a signal handler, like `tethra gateway
  serve` (no new dependency); `tethra mesh stop` is the graceful path that runs
  the key-drop sequence.
- **`--interval`** (default 30 s, at least 5 s) is a documented option, so a
  release binary (and `scripts/smoke.sh`) can run short rounds; the
  millisecond `TETHRA_MESH_INTERVAL_MS` override exists in debug builds only.
- **Interface addresses** for `--all-interfaces` come from `if-addrs`, already
  in the tree through `mdns-sd`; link-local and loopback addresses are not
  published.
- `record_attempt` updates only addresses already in `mesh_peers`: an ad-hoc
  `replicate --peer` does not add a peer. `mesh join` does record the invite
  address that answered (source `manual`: the user entered it with the
  invite), so a new device always has one address to dial even if no device
  has published one yet. CI found that race: a device that joined before its
  inviter's node published an address had no one to dial.

### Decisions made while building usage publishing (Increment 06)

* **R23 — Retention drops usage counters at ingest and from storage, two days
  after the horizon.** DESIGN §D14 said counters older than the horizon are
  "garbage-collected from views and `mesh_items` on every device" and "dropped
  at ingest". As built, each store has a usage floor (`horizon + 2 days`, set
  by the publisher from the LWW `retention.usage_days` and the device's clock):
  below it an arriving counter is not stored (its dot is logged; it is not a
  rejection), and held ones are deleted (`SqliteStore::gc_usage`). This is rule
  (b) of PROTOCOL §8.4: the exclusion does not depend on seq. Views stop at the
  horizon itself. The two days keep devices whose clocks or settings differ
  slightly from dropping different sets for long; in that window repair resends
  what the other side drops. The simulator does not set a floor, so its
  convergence checks are unaffected.

Smaller usage decisions (Increment 06):

- **Unknown model, not "sentinel".** The writer stores `model = ''` for a
  response that named no model; it is real, unpriced traffic, not an "all"
  sentinel (nothing writes aggregate rows to `gateway_usage_daily`). It is
  published under the model label `(not reported)` instead of being skipped as
  DESIGN §D14 said. Rows with `project_id = ''` (unattributed) are never
  published; they cannot be bound.
- **The split cut-over is per row, not per device.** Migration v23 adds
  `split_known` to `gateway_usage_daily` (1 on rows the writer creates from v23
  on; a row that already existed stays 0 as it grows). A row with 0 publishes
  `unextracted = request_count − usage_event_count` (always known) and leaves
  priced and unpriced at 0, so views show the remainder as "split unknown" and
  derive each device's `split_known_since` from its counters. No new item field
  was needed. The alternatives — a marker row written by the migration (a
  restore inserts every backed-up row into a freshly migrated database, so a
  migration-inserted row collides) or a `gateway_config` column (its row may not
  exist) — were rejected.
- **The publish cursor is keyed by mesh project too** (v23 rebuilds
  `mesh_publish_cursor`; v21 created it and nothing wrote it). After a rebind, a
  deletion is taken back from each counter its traffic went to.
- **Publishing is atomic and safe to race.** Counters and cursor commit in one
  transaction (`SqliteStore::mint_batch`), and a `publish/gen` check inside it
  makes a node and a CLI command on one database unable to attribute one delta
  twice (the loser re-reads and retries).
- **The hourly budget is the publisher's own** (5 000 counters an hour, oldest
  days first): own mints are not counted against the per-origin ingest rate
  that peers enforce (10 000 an hour).
- **LWW writes that carry unchanged fields are built inside the write
  transaction** (`SqliteStore::mint_from`). A rename keeps the listen
  addresses and an address publish keeps the name; built from a snapshot read
  before the transaction, a node publishing its addresses could undo a rename a
  CLI command made a moment earlier (Windows CI caught it in
  `node::three_nodes_converge…`). `device.info` and `project.meta` edits use it.
- **`local_month_spend_micros`** (`core::mesh::usage`) is the single function
  for "this device's spend this month on a mesh project", for 07 and 08.

### Dependencies

| Crate | Version | Increment | Why |
|---|---|---|---|
| `ed25519-dalek` | 2.2.0 (features `fast`, `std`, `zeroize`; no `rand_core`) | 01 | Item signatures. Reviewed dalek implementation; `verify_strict`. |
| `snow` | 0.10.0 (no default features; `std`, `default-resolver`, `use-chacha20poly1305`, `use-blake2`, `use-curve25519`, `use-getrandom`) | 04 | Noise XXpsk0 / XXpsk3 transport, in `crates/mesh` only. MSRV 1.85. |
| `mdns-sd` | 0.21.6 (no default features: no `async`, no `log`) | 05 | Opt-in LAN discovery (`serve --discover`) without an async runtime, in `crates/mesh` only. Never constructed in tests. |
| `if-addrs` | 0.15.0 (already a dependency of `mdns-sd`) | 05 | This machine's interface addresses, published for a node bound with `--all-interfaces`. |

`ed25519-dalek` 2.2.0 reuses the `curve25519-dalek` 4.1.3, `sha2` 0.10,
`subtle` and `zeroize` already in the lockfile for `crypto_box`
(`cargo tree -d -p api-tracker-core` shows no new duplicate). It compiles two
small new crates, `ed25519` 2.2.3 and `signature` 2.2.0; `pkcs8`, `der`, `spki`
and `const-oid` appear in `Cargo.lock` only as inactive optional dependencies
and are not built. Keys are generated from 32 bytes of the operating-system RNG
(`getrandom`), like every other key in core. BLAKE3, `crypto_box`,
ChaCha20-Poly1305, `serde_json`, `time`, `uuid`, `zeroize` and `subtle` are
reused.

`snow` 0.10.0 reuses `curve25519-dalek` 4.1.3, `blake2` 0.10, `subtle` and
`getrandom` 0.3 from the lockfile. It adds three crates: `snow` itself, plus
`chacha20poly1305` 0.10.1 and `chacha20` 0.9.1. Those two are older lines that
sit beside core's `chacha20poly1305` 0.11 (duplicate versions, shown by
`cargo tree -d -p api-tracker-mesh`), because `snow` 0.10 pins 0.10. `snow` does
not zeroize its internal copies of keys (KNOWN_LIMITATIONS).

`mdns-sd` 0.21.6 reuses `socket2` 0.6, `mio` 1.2 and `fastrand` 2 from the
lockfile and adds `flume` 0.12 (its event channels, with only the `spin`
backend), `if-addrs` 0.15, `socket-pktinfo` 0.4 and `spin` 0.9. Its
`socket-pktinfo` needs `libc` ≥ 0.2.191, so `libc` moved from 0.2.186 to
0.2.191 for the workspace (a patch release). It runs its own thread and
multicast sockets only when a user passes `--discover`.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Raft or other consensus | Needs a majority online: a lone offline laptop could not commit a single write, which breaks local-first. |
| A hosted relay or sync server | Forbidden by CLAUDE.md; a third party would hold or forward the data. |
| Users syncing `vault.db` through a cloud drive | SQLite corruption under concurrent writers, no merge, and identity cloning. The root threat model already lists it as a risk. |
| Cloning the vault onto each device instead of federating | Forces one master password and one key hierarchy everywhere, and couples secret replication to metadata replication. |
| libp2p or iroh | Large dependency trees, an async runtime, and relay/hole-punching defaults that contact third parties. |
| Automerge, yrs or the `crdts` crate | General-purpose document CRDTs and their dependency weight for four small, auditable state shapes. |
| mTLS with raw public keys instead of Noise | rustls custom certificate verifiers collide with the existing `no_insecure_verifier` guards; Noise gives pinned-key mutual authentication natively. |
| Rejecting or quarantining far-future HLC items | Rejection makes convergence depend on each receiver's own clock; quarantine behind an advanced VV loses the item. Accept-and-flag with a drift bound converges and still surfaces the skew. |
| Phi-accrual failure detection | Unnecessary for ≤ 10 devices; exponential backoff with `last_success_at` is enough and easier to explain. |
| A transitive (fixpoint) clamp for spend-cap rights | Unbounded iteration under hostile values; the one-hop clamp gives the same honest-device behaviour (R3). |
| Per-origin LWW by HLC / counters by epoch-lex max | Diverges from latest-only storage when an origin misbehaves (R1). |

## Security implications

* **New trust boundary: the LAN or VPN between paired devices.** Passive
  observers see Noise ciphertext; active probers without the access key fail at
  the first handshake message and never learn a device's static key (psk0).
  Only the handshake is parsed before authentication. See
  `docs/mesh/THREAT_MODEL.md`.
* **Every item is signed and verified before storage** (MESH-SI-3), with strict
  Ed25519 verification and a domain-separated message. Stored bytes are the
  received bytes. Signature checks stop a member impersonating another origin
  (as long as that origin's signing key stays secret).
* **Private keys stay encrypted at rest** under the vault key, with AAD bound
  to the vault and the device (Increment 03), and are in memory only while the
  vault is unlocked (MESH-SI-7). `UnlockedVault::mesh_keys` returns the
  signing, Noise and access keys and never the sealing key. Each key is checked
  against its stored public key when it is loaded. Key types never print their
  secret halves; tests assert it.
* **A restored or copied vault does not keep acting as the device it came
  from** (MESH-SI-5). Restore wipes every mesh row and the matching marker. A
  database whose marker is missing, belongs to another identity, or records
  seqs the database lacks refuses to mint. A database copied together with its
  marker is caught on the wire as a fork.
* **Credential values do not replicate** until Increment 11, and then only as
  sealed boxes to specific devices after reauthentication (MESH-SI-6).
* **A malicious member is still the user's own device.** Signatures stop it
  impersonating others and view clamping stops it creating spend-cap rights in
  others' views, but it can remove devices, report false usage about itself,
  raise its own cap with a labelled override, and consume rate-limited
  resources. Recovery is re-pairing. This is documented, not hidden.
* **Spend caps are a self-limit, not a security boundary**: anything that
  bypasses the gateway bypasses the cap.
* **No analytics** (MESH-SI-14): the `docs/ANALYTICS.md` allowlists are
  unchanged.
* Mesh metadata at rest is plaintext like other usage data (ADR 0018).

## Future limitations

* No NAT traversal: devices must reach each other over a LAN or a user-run VPN.
* Removal and access-key rotation are eventually consistent; a device that
  misses a rotation for 30 days must re-pair.
* A device's earlier value for a key is not restored when its later entry is
  excluded by a removal cutoff (R1/R2): only its latest entry per key is kept.
* No mesh LaunchAgent in v1: the node runs only while the desktop app is open
  and unlocked, or while `tethra mesh serve` runs.
* Cost is computed on the device the usage came from, with that device's
  pricing table; cached-read tokens are excluded from estimates, so caps
  undercount cached-heavy traffic.
* Windows runtime is compiled and unit-tested but not behaviourally validated,
  as for the gateway (ADR 0019 D8).
* Credential shares (Increment 11) have no forward secrecy (static sealing keys).
* Fork-evidence propagation is finalized in Increment 02 (PROTOCOL §7).
* The identity marker sees a rollback only when it spans more than one block of
  64 seqs; a smaller rollback, or a copy of the whole data directory, is caught
  only when the diverging histories meet on the wire (Increment 03, R17).
