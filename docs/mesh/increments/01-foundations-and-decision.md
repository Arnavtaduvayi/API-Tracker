# Increment 01: Foundations and decision

**Mode:** S (single session) · **Size:** L · **Prerequisites:** none (first increment)

## Goal

1. Record the architectural decision and apply the approved product-rule amendments.
2. Write the normative protocol spec.
3. Ship the pure, fully tested foundation of `core::mesh`: clocks, dots, version vectors,
   the canonical item codec with Ed25519 signing, and the four CRDTs.

Everything later builds on these types, so get them exactly right and prove their
algebra.

## Read first

- `CLAUDE.md`, the whole file. Note lines 276-296 ("Local-first requirements") and 365-371 ("Do not introduce").
- `docs/PRODUCT_SPEC.md` §1 and §4 (lines 1-30, 104-122).
- `THREAT_MODEL.md` (headings, plus lines 156-230).
- `docs/decisions/0029-projects-first-live-activity.md` as the ADR format template, plus `0001`, `0002`, `0018`, `0019` and `0020`.
- `crates/core/src/lib.rs`, `crates/core/src/error.rs`, `crates/core/src/crypto.rs` (the AAD pattern at 165-264) and `crates/core/src/clock.rs`.
- `crates/core/Cargo.toml` and `crates/tracking/Cargo.toml:37-43` (the feature pattern).
- DESIGN §D1-D10, §D19 and §D21.

## Scope (build all of this)

### 1. Draft PR

Do this first, once the first commit is pushed. Open it with no attribution lines:

```bash
gh pr create --draft --base main --head feat/device-mesh \
  --title "feat: Tethra Mesh — peer-to-peer replication between your own devices" \
  --body-file <scratch file>
```

- The body is a short summary that links to `docs/mesh/increments/README.md` and
  `STATUS.md`, plus the increment checklist 01-12.
- Record the PR number in STATUS.md.

### 2. ADR 0031: `docs/decisions/0031-device-mesh.md`

Use the 0029 format: Status, Date, Amends, Preserves, Context, Decision, Alternatives
considered, Security implications, Future limitations.

**Decision** summarizes D1, D3-D10 and D12-D13. **Amends** lists `CLAUDE.md`,
`PRODUCT_SPEC.md` §4, and gateway SI-19 (the SI-19 change takes effect in 06; note it
as forthcoming). **Preserves** SI-1 and ADRs 0018, 0019 and 0020.

Alternatives must cover at least these:

| Alternative | Why rejected |
|---|---|
| Raft or other consensus | majority availability breaks offline-first |
| Hosted relay or sync server | forbidden by CLAUDE.md; a third party holds data |
| Users syncing `vault.db` through a cloud drive | SQLite corruption, no merge, identity clone; THREAT_MODEL already lists it as a risk |
| Cloning the vault per device instead of federating | forces one password and one key hierarchy, couples secrets to metadata replication |
| libp2p / iroh | large dependency trees, async runtime, relay defaults |
| Automerge / yrs / the `crdts` crate | heavy general-purpose document CRDTs vs four small, auditable state shapes |
| mTLS with raw public keys vs Noise | rustls custom verifiers collide with the existing `no_insecure_verifier` guards; Noise gives pinned-key mutual auth natively |
| HLC reject or quarantine vs accept-and-flag | — |
| Phi-accrual failure detection vs simple backoff | — |

Record the chosen dependency versions after you add them:
- `ed25519-dalek`: the version, and whether it reuses `curve25519-dalek` 4.1.3 (check
  with `cargo tree -d -p api-tracker-core`);
- `snow` and `mdns-sd`: planned for 04 and 05. Name them; they are added later.

### 3. Product-rule amendments

Apply them exactly as written in DESIGN §D2, items 1-5. Then add a one-line pointer to
the mesh docs in README.md's "Not implemented yet" (or nearest equivalent) section,
stating that the mesh is in development on this branch. Don't advertise it as a feature
yet.

### 4. `docs/mesh/`

Mirror `docs/gateway/`. Every document **marks what is implemented vs specified**, with
each section saying "Status: implemented (01)" or "Status: specified, lands in NN".

- **`ARCHITECTURE.md`**: layering (D4), the "What replicates" table (D1), the data flow
  as text diagrams (the gateway writes daily usage, the publisher writes items, items
  replicate, views render), and the vocabulary (D3).
- **`PROTOCOL.md`**: the normative spec. Use MUST/SHOULD language, with byte-level
  detail for the codec and signature domain separation. It covers:
  - items, kinds, ingest checks (D6);
  - the HLC (D7);
  - every CRDT's state, join, value and admission rules (D8);
  - frames and the session (D9);
  - pairing, sessions, rotation and removal (D10);
  - bounds (D12).

  Include **worked examples** for each CRDT join, with small concrete states and the
  expected result. Increment 02's independent oracle is written from this file alone, so
  it must be complete and unambiguous.
- **`SECURITY_INVARIANTS.md`**: MESH-SI-1 to MESH-SI-15 (D19). Each entry has its
  status and the test(s) that prove it. "none yet" is allowed for later increments.
- **`THREAT_MODEL.md`**: D18.
- **`KNOWN_LIMITATIONS.md`**: no NAT traversal, eventual revocation, compromised-member
  powers, no LaunchAgent node, origin-side pricing, cached-token undercount, caps as a
  self-limit, Windows runtime untested, and no forward secrecy for shares (11).
- **`TEST_PLAN.md`**: D21 as a table, with a column for status and the test file.

### 5. Code in `crates/core/src/mesh/`

Register it with `pub mod mesh;` between `inject` and `model` in `lib.rs`.

- **`mod.rs`**: module docs stating that this layer is sans-IO and pointing to PROTOCOL.md.
- **`error.rs`**: a `MeshError` (thiserror), wired in as `CoreError::Mesh(#[from] MeshError)`
  in `crates/core/src/error.rs`. Messages never contain key material.
- **`clock.rs`**: `pub trait Clock: Send + Sync { fn now_ms(&self) -> u64; }`, plus
  `SystemClock` and `ManualClock` (an `AtomicU64` that tests can set or advance).
- **`hlc.rs`**: `Hlc(u64)` (48/16 split), and `HlcClock { last, max_drift_ms }` with
  `now()`, `observe(remote) -> Observation { clamped: bool, skew_ms }` and
  `local_write_ts(current_winner: Option<Hlc>)`. Behaviour is exactly as in D7.
  Persistence of the high-water mark is a store concern (03); expose `restore(high_water)`.
- **`dot.rs` / `vv.rs`**: `DeviceId` (16 bytes, displayed as hex), `Dot { origin, seq }`,
  and `VersionVector` (a `BTreeMap<DeviceId, u64>`) with `join`, `dominates`,
  `missing_from(&other) -> Vec<(DeviceId, u64 /*from_exclusive*/, u64 /*to_inclusive*/)>`,
  and `advance_to`.
- **`codec.rs`**: `ItemBody` (D6 field order) and
  `encode_body(&ItemBody) -> Vec<u8>`. It is deterministic: JSON with a fixed field
  order and integers only. Write it by hand or with serde on a struct that has no maps,
  but **prove determinism with a test**: 10k random bodies, each encoded twice, compare
  bytes. `decode_body(&[u8]) -> Result<ItemBody>` enforces the 64 KiB limit and
  `deny_unknown_fields` at the envelope level. Payloads stay `serde_json::Value` until
  kind-specific parsing.
- **`sign.rs` / `item.rs`**:
  - `SigningKeyPair` wraps `ed25519_dalek::SigningKey` and zeroizes it.
  - `SignedItem { body_bytes, sig: [u8;64], hash: [u8;32] }`, built by
    `SignedItem::sign(&body, &key)`.
  - `SignedItem::verify(bytes, sig, &VerifyingKey, expected_mesh) -> Result<ItemBody>`
    applies the domain prefix `b"tethra-mesh/v1/item\0"` and computes
    `hash = blake3(body_bytes || sig)`.
  - Kind-specific payload structs for every v1 kind in the D6 table, as typed structs
    with `TryFrom<&ItemBody>`. The `share.*` kinds can be typed now and used in 11.
- **`crdt/lww_map.rs`, `crdt/owner_counter.rs`, `crdt/roster.rs`, `crdt/bounded.rs`**:
  exactly D8, generic enough for 02's views.
  - `bounded.rs` exposes `avail(device)`, `can_spend`, `transfer`, `mint` and `burn`, and
    computes the clamped view.
  - `roster.rs` exposes `is_admitted(origin, seq)` with removal cutoffs and the genesis
    rule.
- **`sim/rng.rs`**: `SplitMix64` (no dependencies), usable from unit tests now. Gate it
  `#[cfg(any(test, feature = "mesh-sim"))]`, and add the `mesh-sim` feature to
  `crates/core/Cargo.toml` (empty for now; Increment 02 fills it) so the gate compiles.

**Dependency:** add `ed25519-dalek` to `crates/core/Cargo.toml` (D4: prefer the version
that reuses the `curve25519-dalek` already locked). Use only the `rand_core`/`zeroize`
features you need, and generate keys from `getrandom`-backed randomness the way
`crypto.rs` does.

## Out of scope

Protocol and sessions (02), SQLite and migrations (03), any network or `crates/mesh`
crate (04), and the CLI (03+). Don't create an empty `crates/mesh`.

## Tests to write

All are unit tests in the modules, plus `crates/core/tests/mesh_foundations.rs` for the
cross-module ones.

- **CRDT laws.** Each runs ≥ 10 000 cases from the seeded `SplitMix64`, and failures print
  the seed:
  - commutativity, associativity and idempotence of `join` for all four CRDTs;
  - monotonicity, i.e. `join(a, b) ≥ a` under each CRDT's order.
- **LWW specifics:**
  - the max over admitted origins;
  - excluding a removed origin above its cutoff changes the value to the next winner;
  - the tie-break by origin.
- **Owner counter:**
  - an epoch bump overrides a higher-valued old epoch;
  - equal epochs take the field-wise max.
- **Roster:**
  - removed is forever;
  - concurrent removals take the max cutoff;
  - the genesis rule;
  - an add signed by a non-member is not admitted.
- **Bounded counter:**
  - `avail` arithmetic;
  - spend beyond `avail` is refused;
  - a transfer conserves the total;
  - a burn reduces the total;
  - the clamped view ignores a forged over-transfer;
  - the randomized invariant `Σ U ≤ Σ minted − Σ burned` for honest operation sequences
    (10k sequences).
- **HLC:**
  - monotonic under a stalled or backward physical clock;
  - logical-counter overflow;
  - `observe` clamps at `now + MAX_DRIFT` and reports the skew;
  - `local_write_ts` beats a far-future winner;
  - `restore(high_water)` never goes backwards.
- **Codec and signing:**
  - round trip;
  - determinism (10k bodies);
  - flipping each byte of the body or signature makes verification fail (exhaustively,
    for a small item);
  - wrong mesh → error;
  - wrong key → error;
  - oversize → error;
  - unknown envelope field → error;
  - an unknown *kind* decodes as opaque.
- **Leakage:** `Debug` and `Display` of the key types never print key bytes. Assert with
  a known fake key pattern.

## Acceptance criteria

- [ ] ADR 0031 exists and covers every heading CLAUDE.md requires (decision, why, alternatives, security implications, future limitations).
- [ ] The amendments from DESIGN §D2 are applied verbatim, and `git diff` of CLAUDE.md shows only those additions.
- [ ] All six `docs/mesh/*.md` exist with status markers. PROTOCOL.md has worked examples for every join.
- [ ] `core::mesh` modules exist as specified, with no `todo!()` and no `unimplemented!()`.
- [ ] Every test listed above exists and passes. The law tests run ≥ 10k cases each, and the whole mesh unit suite takes < 30 s in debug.
- [ ] The check suite is green (README §3) and `scripts/smoke.sh` still passes.
- [ ] `crates/gateway/tests/documentation_claims.rs` still passes against the new docs.
- [ ] The draft PR is open and CI is green (or the run id is recorded as pending, per README §1.10).

## Verification commands

```bash
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core mesh
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --test mesh_foundations
cargo tree -d -p api-tracker-core | head -50     # record duplicate-crate impact in ADR 0031
# plus the full README §3 suite and: bash scripts/smoke.sh
```

## Docs to update

- ADR 0031.
- `docs/mesh/*`.
- `CLAUDE.md` and `docs/PRODUCT_SPEC.md` (the amendments only).
- `THREAT_MODEL.md` (pointer section).
- `README.md` (the in-development pointer).
- `CHANGELOG.md`: `### Added — Tethra Mesh foundations (in development)`.

## Handoff checklist

- [ ] STATUS.md row 01: set to `done`, with commits, the CI run, test counts with their
      command, any deviations, and the PR number in the header.
- [ ] Handoff notes:
  - the exact public API of `core::mesh` that 02 builds on (type names, plus one line
    each);
  - any PROTOCOL.md ambiguity you resolved;
  - the `ed25519-dalek` version and its duplicate-crate impact.
