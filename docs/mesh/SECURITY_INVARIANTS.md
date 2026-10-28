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
  *Enforced by:* one `bind_listener` function in `crates/mesh/src/bind.rs`;
  `tethra mesh serve` requires `--listen`. The node's local control socket
  (05) is bound in `bind.rs` too (`bind_control_socket`, a Unix socket in the
  0700 `mesh/` directory; on Windows a loopback listener through
  `bind_listener`). With `--all-interfaces` the node publishes concrete
  interface addresses, never a wildcard. mDNS (`--discover`, off by default) is
  the `mdns-sd` crate's own multicast sockets.
  *Status:* implemented (04, 05). *Tests:*
  `bind_guard::only_bind_rs_binds_and_no_file_names_a_wildcard_address` (no
  other file binds, `UnixListener` included; no wildcard literal anywhere),
  `runtime::tests::an_every_interface_bind_publishes_concrete_non_loopback_addresses`,
  `bind_guard::unspecified_addresses_are_refused_without_the_flag`,
  `no_mesh_dependency::the_gateway_does_not_depend_on_api_tracker_mesh`
  (the gateway's listener stays its own, loopback-only).
- **MESH-SI-2 No mesh data before authentication.** No mesh data is accepted or
  sent before a Noise handshake completes with an **active** roster device's
  static key (PROTOCOL §6.4), or with a valid pairing token.
  *Status:* implemented (04).
  - The roster's `is_active` rule, and the session's check that `Hello` names
    the authenticated peer (02).
  - Over TCP (04), only a 16-byte preamble and handshake messages of at most
    1 KiB are read before authentication. A wrong access key fails at message 1
    with nothing sent back.
  - Each side checks the other's static key against the active roster — the
    initiator before message 3, the responder after it — before any frame
    moves.
  - Pairing answers only a live invite's hint, and the joiner's key is bound to
    the handshake.

  *Tests:* `crdt::roster::tests::removal_cuts_off_later_items_but_keeps_earlier_ones`,
  `a_fork_report_cuts_the_forked_origin_off_at_the_fork_point`,
  `proto::tests::a_different_mesh_or_peer_is_refused_with_bye`,
  `bounds::{garbage_before_the_handshake_gets_nothing_back,
  a_malformed_handshake_message_gets_nothing_back,
  a_wrong_access_key_fails_at_message_one_and_reveals_no_static_key}`,
  `replication::a_removed_device_is_refused_and_its_later_writes_stop_counting`,
  `replication::a_device_that_missed_a_rotation_for_over_30_days_is_refused`,
  `pairing::{five_wrong_attempts_lock_the_invite_out,
  a_token_is_single_use_even_for_two_concurrent_joiners,
  a_typo_fails_before_any_connection_and_a_wrong_mesh_cannot_talk}`,
  `noise_spike::a_wrong_access_key_fails_at_message_one`.
- **MESH-SI-12 No third parties.** No Tethra server, relay, rendezvous or
  third-party NAT service. *Enforced by:* there is no such code; reachability is
  the user's LAN or VPN. *Status:* implemented (01) as a design rule.
  *Status:* implemented (04, 05): `replicate --peer`, `leave --peer` and `join`
  dial only addresses the user typed or the invite carries; the node (05) dials
  only `mesh_peers` rows, which come from `peer add`, from the `device.info`
  of **active** roster devices (gossip), or from mDNS sightings carrying this
  mesh's daily tag. There is no rendezvous, relay or NAT service. *Tests:*
  `node::three_nodes_converge_on_their_own_and_gossip_lets_c_find_a`,
  `discover::a_node_finds_a_peer_through_discovery_alone_and_ignores_strangers`.

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
  `codec::tests::encoding_is_deterministic_over_10k_random_bodies`,
  `codec::tests::envelope_field_validation` (03: `seq` ≤ 2^63 − 1, so stored
  seqs keep their order on disk, ADR 0031 R16).
- **MESH-SI-4 Commit-only VV.** A version-vector entry advances only in the
  transaction that stores every item it covers. *Status:* implemented (02) in
  `MemStore::commit` (validate everything, then apply) and the session (one
  commit per session, only after a `Commit` whose count and batch hash match);
  implemented (03) in `SqliteStore::commit`. That commit validates the whole
  batch before writing, then writes in transactions of **whole origins**: each
  origin's items, dots and VV entry commit together, so a crash between
  transactions leaves no item outside its VV. A failed transaction rolls back
  and reloads the in-memory mirror. A failed disk read ends the session instead
  of serving an empty range (R18). *Tests:*
  `proto::tests::a_dead_sender_leaves_nothing_half_applied`,
  `a_commit_that_does_not_match_the_items_aborts_and_applies_nothing`,
  `mesh_sim::ci_200_seeds` (invariant 1, under crashes and dropped frames),
  `proto::tests::a_failed_store_read_ends_the_session_and_sends_nothing_built_from_it`,
  `sqlite_store::tests::a_failure_between_the_item_insert_and_the_vv_update_leaves_nothing`,
  `sqlite_store::tests::a_crash_between_chunks_keeps_whole_origins_only`,
  `mesh_store_conformance::thirty_seeds_with_crashes_between_chunks` (invariant
  1 on SQLite devices that crash between commit chunks and reopen from disk),
  `mesh_store_conformance::crashes_between_chunks_happen_and_are_survived`.
- **MESH-SI-5 No identity reuse.** A restored backup wipes mesh identity; a
  clone/rollback marker mismatch or a fork stops the node. *Status:* implemented
  (03, 05). The node (05) refuses to open on a bad marker or a fork naming this
  device, and stops itself if one appears while it runs; a peer's
  `RollbackNotice` holds every mint on this database until the device's own
  items are back (ADR 0031 R22):
  - Forks are detected by dot-log chains and reported at their true divergence
    point (02); rollbacks get a `RollbackNotice` (02).
  - Restore deletes every `mesh_*` row and the marker that names the wiped
    identity (`identity::on_restore`, called by `backup::restore_backup`).
  - A store whose marker is missing, foreign or more than one block ahead of
    its log refuses to mint, and does not trust the old mark.
  - Two stores on one database never reuse a seq.
  - `identity::preflight` fails on a bad marker or a fork report naming this
    device. The node (05) runs it before starting.

  *Tests:* `mesh_sim::ci_200_seeds` (invariant 5 with cloned data
  directories), `proto::tests::a_device_behind_its_own_history_gets_a_rollback_notice`,
  `mesh_schema::backup_then_restore_wipes_mesh_state_and_mints_nothing`,
  `mesh_schema::restore_removes_the_marker_only_when_it_names_the_wiped_identity`,
  `backup::tests::a_v1_backup_restore_is_a_mesh_no_op`,
  `migration_safety::backup_captures_every_table_and_restore_preserves_all_rows`
  (`mesh_` tables come back empty),
  `sqlite_store::tests::copies_and_rollbacks_are_detected_and_refuse_to_mint`,
  `sqlite_store::tests::the_marker_is_advanced_one_block_ahead_and_durably_before_its_first_seq`,
  `sqlite_store::tests::two_stores_on_one_database_never_reuse_a_seq`,
  `sqlite_store::tests::a_device_reported_forked_does_not_pass_preflight`,
  `marker::tests::classification_covers_every_case`,
  `mesh_cli::a_restored_backup_leaves_the_mesh_and_can_start_a_new_one`,
  `sqlite_store::tests::a_rollback_hold_refuses_every_mint_until_the_own_log_is_back`,
  `replication::a_rolled_back_device_recovers_its_own_items_before_minting_again`,
  `doctor::a_marker_mismatch_is_found_and_the_node_refuses_to_start`.
- **MESH-SI-8 Bounds.** Every frame, batch, stage, session, rate and transaction
  is bounded (PROTOCOL §11). *Status:* partial (02): items, bodies, payload
  depth, `kind`/`key` (01); per session ≤ 50 000 staged items and dots,
  batches ≤ 512 items, frames ≤ 1 MiB, a 50 000-seq gap bound, 10 000 items per
  origin per hour, `ChainQuery` ≤ 64 seqs (02, `proto::Limits`); write
  transactions chunked by whole origins (03, `SqliteStore`, ~2 000 rows a
  chunk; one origin's range is one transaction). Concurrency and timeouts land
  in 04-05. Transport (04): frames ≤ 1 MiB, handshake messages ≤ 1 KiB, a
  5 s handshake, 30 s idle and 10 min exchange timeout, ≤ 8 connections at once,
  ≤ 10 new connections per source IP per minute, ≤ 5 pairing attempts per
  invite. The node (05): the 8 session slots are shared by inbound and
  outbound exchanges, at most 4 outbound at once, a round interval of at least
  5 s outside tests, control requests ≤ 8 KiB and ≤ 4 control connections at
  once, at most 16 published addresses and 64 mDNS addresses kept per round.
  *Tests:* `bounds::*` (oversize frame, slowloris, idle session, session
  limit, per-IP flood, the defaults),
  `instance::tests::an_unparseable_or_oversize_request_gets_an_error_not_a_panic`, `mesh_sim::ci_200_seeds` (invariant 8),
  `proto::tests::frames_have_the_documented_json_shape`,
  `mesh_store_conformance::commits_wait_for_a_busy_writer_and_stay_consistent`,
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
  *Status:* implemented (01, 03, 05); the reauth-gated import that uses the
  sealing key is 11. `SigningKeyPair` wipes on drop (dalek `zeroize`) and
  redacts in `Debug`/`Display` (01). The four private keys are encrypted under
  the vault key with AAD naming the vault and the device (or mesh and epoch)
  (03). `UnlockedVault::mesh_keys` returns only the signing key, the Noise key
  and the current access key, in zeroizing buffers, each checked against its
  stored public key. It never returns the sealing key. The CLI prints no key,
  public or private. *Implemented (05):* the node holds its keys in one
  `MeshNode` that only its serve and main threads hold (the control channel
  holds status only). It stops when its CLI session is deleted, expires or is
  replaced, on an opted-in maximum runtime, on a lock signal, or on `stop`; it
  then joins every thread so the last reference drops and `MeshKeys` and
  `MeshVault` zeroize, which `StopReport::keys_dropped` reports. `mesh serve`
  drops its `UnlockedVault` once the node is built. `doctor` unwraps the node's
  keys only to compare them with their public keys, and never the sealing key.
  *Tests:*
  `node::a_node_stops_within_an_interval_when_its_session_expires_or_ends_and_drops_its_keys`,
  `node::a_lock_signal_stops_the_node_and_a_new_session_does_too`,
  `node::the_control_channel_answers_status_replicate_now_and_stop_and_refuses_a_wrong_nonce`,
  `runtime::tests::a_session_file_that_disappears_expires_or_changes_stops_the_node`,
  `doctor::a_healthy_device_has_no_problem_and_a_device_outside_a_mesh_has_little_to_check`
  (no key in a doctor report),
  `sign::tests::debug_and_display_never_print_the_secret`,
  `mesh_foundations::no_key_signature_or_sealed_bytes_leak_through_debug_display_or_errors`,
  `identity::tests::keys_round_trip_and_never_include_the_sealing_key`,
  `identity::tests::key_blobs_are_bound_to_their_vault_and_corruption_is_typed`,
  `identity::tests::a_swapped_public_key_is_caught_when_the_keys_load`,
  `mesh_cli::init_then_status_in_human_and_json_form_without_any_key_material`.

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
  provider-reported cost. *Status:* implemented (01, 06): owner counters expose
  values per origin only (`OwnerCounterMap::admitted`); `usage_report` gives
  every figure a device, an `as_of` and `stale`, lists active devices without
  figures under `no_data_from`, labels any sum, and reads nothing
  provider-reported; `tethra usage` only points to it (gateway SI-19, amended).
  *Tests:* `crdt::owner_counter::tests::admitted_values_are_per_origin`,
  `mesh_usage::usage_on_a_reaches_b_labelled_per_device_with_freshness`,
  `mesh_usage::views_label_stale_and_removed_devices_and_devices_with_no_data`,
  `mesh_usage::rows_from_before_the_split_publish_an_honest_unknown_remainder`,
  `mesh_publish_e2e::gateway_usage_reaches_a_paired_device_split_and_labelled`,
  `mesh_cli::share_bind_and_read_usage_across_two_devices_from_the_cli`.
- **MESH-SI-13 Nothing automatic.** No auto-binding, auto-import or
  auto-enforcement. *Status:* implemented (06) for binding: sharing binds only
  the sharer's own project; every other device binds by an explicit command,
  never by name or local id; caps (08) and imports (11) follow. *Tests:*
  `mesh_usage::binding_is_never_automatic_cascades_on_delete_and_is_refused_twice`,
  `mesh_usage::usage_on_a_reaches_b_labelled_per_device_with_freshness`.
- **MESH-SI-14 No analytics.** The mesh emits no analytics events; the
  `docs/ANALYTICS.md` allowlists are unchanged. *Status:* implemented (01, 05):
  no mesh code, the node included, references the analytics module. *Tests:* none yet (12 adds a grep
  guard).
- **MESH-SI-15 No unsafe code.** `#![forbid(unsafe_code)]` in `crates/mesh`, and
  core keeps its crate-level `#![forbid(unsafe_code)]`. *Status:* implemented
  (01) for core (`core::mesh` is inside core), (04) for `crates/mesh`. The
  control channel's same-user check is filesystem permissions, not a peer
  credential call, which would need `unsafe` or a new dependency (as for the
  gateway). *Tests:* the compiler.
