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
  *Status:* partial (02): the roster's `is_active` rule, the session's check
  that the `Hello` names the authenticated peer, and the simulator's rule that
  devices only exchange with peers they consider active. The Noise transport
  lands in 04. *Tests:* `crdt::roster::tests::removal_cuts_off_later_items_but_keeps_earlier_ones`,
  `a_fork_report_cuts_the_forked_origin_off_at_the_fork_point`,
  `proto::tests::a_different_mesh_or_peer_is_refused_with_bye`; transport
  tests in 04.
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
  (02) for ingest: every received item passes the ordered checks of PROTOCOL
  §3.3 before it is staged. *Tests:* `mesh_sim::ci_200_seeds` and
  `each_adversary_alone_is_exercised_and_defended` (simulator invariant 6:
  forged-origin and huge-seq injections are never stored or committed),
  `mesh_foundations::flipping_any_byte_of_body_or_signature_fails_verification`,
  `mesh_foundations::roster_built_from_signed_items_drives_verification_and_admission`
  (forged origin refused), `mesh_foundations::wrong_mesh_wrong_key_oversize_and_unknown_field_are_refused`,
  `item::tests::wrong_mesh_and_wrong_key_are_refused`,
  `sign::tests::signatures_are_domain_separated`,
  `codec::tests::non_canonical_encodings_are_refused`,
  `codec::tests::encoding_is_deterministic_over_10k_random_bodies`.
- **MESH-SI-4 Commit-only VV.** A version-vector entry advances only in the
  transaction that stores every item it covers. *Status:* implemented (02) in
  `MemStore::commit` (validate everything, then apply) and the session (one
  commit per session, only after a `Commit` whose count and batch hash match);
  SQLite in 03. *Tests:* `proto::tests::a_dead_sender_leaves_nothing_half_applied`,
  `a_commit_that_does_not_match_the_items_aborts_and_applies_nothing`,
  `mesh_sim::ci_200_seeds` (invariant 1, under crashes and dropped frames).
- **MESH-SI-5 No identity reuse.** A restored backup wipes mesh identity; a
  clone/rollback marker mismatch or a fork stops the node. *Status:* partial
  (02): forks are detected by dot-log chains and reported at their true
  divergence point; rollbacks get a `RollbackNotice`. Marker, restore wipe and
  "a forked node refuses to run" land in 03/05. *Tests:*
  `mesh_sim::ci_200_seeds` (invariant 5 with cloned data directories),
  `proto::tests::a_device_behind_its_own_history_gets_a_rollback_notice`.
- **MESH-SI-8 Bounds.** Every frame, batch, stage, session, rate and transaction
  is bounded (PROTOCOL §11). *Status:* partial (02): items, bodies, payload
  depth, `kind`/`key` (01); per session ≤ 50 000 staged items and dots,
  batches ≤ 512 items, frames ≤ 1 MiB, a 50 000-seq gap bound, 10 000 items per
  origin per hour, `ChainQuery` ≤ 64 seqs (02, `proto::Limits`). Concurrency and
  timeouts land in 04-05. *Tests:* `mesh_sim::ci_200_seeds` (invariant 8),
  `proto::tests::frames_have_the_documented_json_shape`,
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
