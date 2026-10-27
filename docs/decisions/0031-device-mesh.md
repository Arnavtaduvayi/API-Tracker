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

### Dependencies

| Crate | Version | Increment | Why |
|---|---|---|---|
| `ed25519-dalek` | 2.2.0 (features `fast`, `std`, `zeroize`; no `rand_core`) | 01 | Item signatures. Reviewed dalek implementation; `verify_strict`. |
| `snow` | 0.10.x (planned) | 04 | Noise XXpsk0 / XXpsk3 transport. |
| `mdns-sd` | 0.21.x (planned) | 05 | Opt-in LAN discovery without an async runtime. |

`ed25519-dalek` 2.2.0 reuses the `curve25519-dalek` 4.1.3, `sha2` 0.10,
`subtle` and `zeroize` already in the lockfile for `crypto_box`
(`cargo tree -d -p api-tracker-core` shows no new duplicate). It compiles two
small new crates, `ed25519` 2.2.3 and `signature` 2.2.0; `pkcs8`, `der`, `spki`
and `const-oid` appear in `Cargo.lock` only as inactive optional dependencies
and are not built. Keys are generated from 32 bytes of the operating-system RNG
(`getrandom`), like every other key in core. BLAKE3, `crypto_box`,
ChaCha20-Poly1305, `serde_json`, `time`, `uuid`, `zeroize` and `subtle` are
reused.

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
* **Private keys stay encrypted at rest** under the vault key with
  vault-bound AAD (Increment 03), and in memory only while unlocked
  (MESH-SI-7). Key types never print their secret halves; tests assert it.
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
