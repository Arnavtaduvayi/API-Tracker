# Tethra Mesh — Security Invariants

The properties that must hold in every build of Tethra Mesh
([ADR 0031](../decisions/0031-device-mesh.md)), enforced by construction and
proved by named tests (`TEST_PLAN.md`). Nothing here may be weakened without an
ADR amendment. "none yet" means the invariant is specified and the code that
must uphold it lands in a later increment.

Status per invariant: **implemented (NN)** when the mechanism exists and its
test passes; **partial (NN)** when part of it exists; **specified (lands in
NN)** otherwise.

## Network

- **MESH-SI-1 Bind discipline.** No mesh listener binds an unspecified address
  (`0.0.0.0`, `::`) unless `--all-interfaces` was given; nothing listens unless
  `--listen` was given; the gateway stays loopback-only (gateway SI-1 untouched).
  *Enforced by:* one `bind` function in `crates/mesh/src/bind.rs`.
  *Status:* specified (lands in 04). *Tests:* none yet (a grep guard modelled on
  `crates/gateway/tests/no_insecure_verifier.rs`).
- **MESH-SI-2 No mesh data before authentication.** No mesh data is accepted or
  sent before a Noise handshake completes with an **active** roster device's
  static key (PROTOCOL §6.4), or with a valid pairing token.
  *Status:* partial (01): the roster's `is_active` rule exists. Transport lands
  in 04. *Tests:* `crdt::roster::tests::removal_cuts_off_later_items_but_keeps_earlier_ones`
  and `a_fork_cuts_the_forked_origin_off_at_the_fork_point` (a removed or forked
  device is not active); transport tests in 04.
- **MESH-SI-12 No third parties.** No Tethra server, relay, rendezvous or
  third-party NAT service. *Enforced by:* there is no such code; reachability is
  the user's LAN or VPN. *Status:* implemented (01) as a design rule.
  *Tests:* none yet (04/05 assert the node dials only roster-gossiped or
  user-entered addresses).

## Items and replication

- **MESH-SI-3 Signed items.** Every item is Ed25519-signed by its origin over a
  domain-separated message and verified (strictly) before it is stored; the
  stored bytes are exactly the received bytes; a body has one canonical
  encoding. *Status:* implemented (01) for signing, verification and the codec;
  storage lands in 02/03. *Tests:*
  `mesh_foundations::flipping_any_byte_of_body_or_signature_fails_verification`,
  `mesh_foundations::roster_built_from_signed_items_drives_verification_and_admission`
  (forged origin refused), `mesh_foundations::wrong_mesh_wrong_key_oversize_and_unknown_field_are_refused`,
  `item::tests::wrong_mesh_and_wrong_key_are_refused`,
  `sign::tests::signatures_are_domain_separated`,
  `codec::tests::non_canonical_encodings_are_refused`,
  `codec::tests::encoding_is_deterministic_over_10k_random_bodies`.
- **MESH-SI-4 Commit-only VV.** A version-vector entry advances only in the
  transaction that stores every item it covers. *Status:* specified (lands in
  02, SQLite in 03). *Tests:* none yet (simulator invariant 1; store
  conformance).
- **MESH-SI-5 No identity reuse.** A restored backup wipes mesh identity; a
  clone/rollback marker mismatch or a fork stops the node. *Status:* partial
  (01): fork cutoffs exist in the roster. Marker and restore wipe land in 03,
  fork detection in 02. *Tests:*
  `crdt::roster::tests::a_fork_cuts_the_forked_origin_off_at_the_fork_point`.
- **MESH-SI-8 Bounds.** Every frame, batch, stage, session, rate and transaction
  is bounded (PROTOCOL §11). *Status:* partial (01): items ≤ 64 KiB, bodies,
  payload depth, `kind` and `key` lengths. *Tests:*
  `codec::tests::oversize_is_refused_both_ways`, `codec::tests::depth_limit`,
  `codec::tests::envelope_field_validation`,
  `item::tests::short_and_oversize_wire_items_are_refused`.

## Keys and secrets

- **MESH-SI-6 Credential values.** They leave a device only as a sealed box to a
  specific roster device, after reauthentication, and never appear in plaintext
  in frames, logs, errors, JSON output or plaintext columns. *Status:* specified
  (lands in 11); until then no item kind carries a credential value.
  *Tests:* `kinds::tests::share_debug_never_prints_the_sealed_bytes`; canaries
  in 11.
- **MESH-SI-7 Key lifetime.** Mesh private keys are in memory only while the
  vault is unlocked or the CLI session lives; the sealing key is used only
  inside a reauth-gated import. Key types never print secret material.
  *Status:* partial (01): `SigningKeyPair` wipes on drop (dalek `zeroize`) and
  redacts in `Debug`/`Display`. Wrapping and lifetime land in 03-05. *Tests:*
  `sign::tests::debug_and_display_never_print_the_secret`,
  `mesh_foundations::no_key_signature_or_sealed_bytes_leak_through_debug_display_or_errors`.

## Spend caps

- **MESH-SI-9 Enforcement.** Cap enforcement is local and opt-in, peers cannot
  toggle it, the forward path never waits on the database or network for a cap
  decision, and overshoot is ≤ one in-flight request's cost per cap per device.
  *Status:* specified (lands in 08). *Tests:* none yet.
- **MESH-SI-10 No double spending.** Rights are never spent twice; transfers are
  fenced against the running gateway's snapshot (escrow). *Status:* partial
  (01): the bounded counter refuses spends and transfers beyond `avail`, and its
  view clamps a device's outgoing rows to what it held. The escrow fence lands in
  07/08. *Tests:* `crdt::bounded::tests::spend_beyond_avail_is_refused`,
  `the_clamped_view_ignores_a_forged_over_transfer`, `cycles_create_nothing`,
  `cap_safety_holds_for_10k_honest_operation_sequences`.

## Honesty and scope

- **MESH-SI-11 Honest cross-device figures.** Labelled per device with
  freshness; a missing device is unknown, never zero; never summed with
  provider-reported cost. *Status:* partial (01): owner counters expose values
  per origin only (`OwnerCounterMap::admitted`). Views land in 06. *Tests:*
  `crdt::owner_counter::tests::admitted_values_are_per_origin`.
- **MESH-SI-13 Nothing automatic.** No auto-binding, auto-import or
  auto-enforcement. *Status:* specified (lands in 06/08/11). *Tests:* none yet.
- **MESH-SI-14 No analytics.** The mesh emits no analytics events; the
  `docs/ANALYTICS.md` allowlists are unchanged. *Status:* implemented (01): no
  mesh code references the analytics module. *Tests:* none yet (12 adds a grep
  guard).
- **MESH-SI-15 No unsafe code.** `#![forbid(unsafe_code)]` in `crates/mesh`, and
  core keeps its crate-level `#![forbid(unsafe_code)]`. *Status:* implemented
  (01) for core (`core::mesh` is inside core). *Tests:* the compiler.
