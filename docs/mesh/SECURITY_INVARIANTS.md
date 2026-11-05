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
  *Implemented (09), the desktop:* the app's node listens only on the
  addresses in its local node settings (`core::mesh::node_settings`; empty by
  default, so nothing listens until the user adds one), and an unspecified
  address is refused unless "all interfaces" is on. Widening the LAN surface
  — turning on all interfaces or mDNS discovery, or adding a listen address
  that is not loopback — needs the master password, checked in core
  (`UnlockedVault::mesh_node_settings_set`; no password →
  `mesh_reauth_required`, a wrong one → `wrong_password`) and recorded in the
  audit log (`mesh_node_exposure_widened`); the UI warns before it asks.
  *Tests:* `tauri_command_authz::mesh::mesh_node_settings_widening_the_lan_surface_requires_reauth`,
  `node_settings::tests::{validation_normalizes_and_refuses_what_the_node_would_refuse,
  only_widening_the_lan_surface_needs_the_password}`.
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
  *Audit (12):* a removed device's own remove cannot raise its cutoff (MP-1,
  `roster::tests::a_removed_devices_own_remove_cannot_raise_its_cutoff`, the
  oracle's twin); small-order Noise and sealing keys are invalid (MP-5,
  `kinds::tests::roster_add_refuses_small_order_noise_and_seal_keys`,
  `mesh_audit_protocol::a_small_order_seal_key_is_refused_so_no_share_can_be_sealed_to_it`);
  a copied Noise key cannot shadow a device (MP-7,
  `proto::tests::a_shared_noise_key_resolves_by_the_hellos_device_id`,
  `adversarial::a_ghost_device_with_a_copied_noise_key_does_not_shadow_the_real_one`);
  pairing counts only authenticated failures and enforces the inviter check
  (MP-11, MP-12, `pairing::{a_dropped_connection_does_not_count_as_a_wrong_attempt,
  join_fails_when_the_inviter_key_does_not_match_its_roster_entry}`).
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
  - Backups carry no `mesh_*` row (only the device id); restore never inserts
    one (an older backup's are skipped), deletes any, and removes the marker
    that names the backup's identity (`identity::on_restore_after_skipping`,
    called by `backup::restore_backup`; audit MI-3, MI-4).
  - A store whose marker is missing, foreign or unreadable, or whose log is
    below the marker's committed floor, refuses to mint and does not trust the
    old mark (marker v2, audit MI-1: a failed multi-block batch no longer
    looks like a rollback).
  - `mesh leave` always wipes, minting no self-removal when the identity is
    untrusted or held (audit MI-2); a rollback notice above the reporter's own
    `Hello` is ignored (audit MP-9).
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
  `doctor::a_marker_mismatch_is_found_and_the_node_refuses_to_start`,
  `mesh_audit_identity::{a_failed_mint_batch_spanning_blocks_keeps_the_identity_ok,
  a_failed_mint_batch_in_another_store_never_stops_this_one,
  a_rollback_past_a_committed_multi_block_batch_is_still_detected,
  leave_succeeds_on_a_missing_mismatched_or_rolled_back_marker,
  leave_succeeds_under_a_rollback_hold, backup_payload_carries_no_mesh_rows,
  restore_never_imports_mesh_rows_from_an_older_backup,
  a_failed_rotation_after_removal_is_completed_by_a_retry,
  every_mesh_writing_connection_uses_fullfsync}`,
  `marker::tests::{the_floor_not_the_mark_decides_a_rollback,
  version_1_markers_still_read_with_the_rule_they_had}`,
  `proto::tests::{a_rollback_notice_above_the_reporters_hello_is_ignored,
  a_rollback_notice_is_sent_from_the_reporters_own_hello}`.
- **MESH-SI-8 Bounds.** Every frame, batch, stage, session, rate and transaction
  is bounded (PROTOCOL §11). *Status:* implemented (01-05): items, bodies, payload
  depth, `kind`/`key` (01); per session ≤ 50 000 staged items and dots,
  batches ≤ 512 items, frames ≤ 1 MiB, a 50 000-seq gap bound, 10 000 items per
  origin per hour, `ChainQuery` ≤ 64 seqs (02, `proto::Limits`); write
  transactions chunked by whole origins (03, `SqliteStore`, ~2 000 rows a
  chunk; one origin's range is one transaction). Transport (04): frames ≤ 1 MiB, handshake messages ≤ 1 KiB, a
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
  *Audit (12):* one deadline covers the preamble and the whole handshake
  (MP-4, `bounds::a_trickled_handshake_is_closed_at_the_handshake_deadline`);
  repair fits in the staging bound after the main path (MP-3,
  `proto::tests::repair_fits_in_what_the_main_path_leaves_of_max_staged`);
  `ChainReply` entries outside the queried range are ignored (MP-2,
  `proto::tests::{a_chain_reply_outside_the_queried_range_is_ignored,
  a_peers_chain_claim_never_reports_this_device_forked}`); the adversarial
  suite (`crates/mesh/tests/adversarial.rs`, Phase A).

## Keys and secrets

- **MESH-SI-6 Credential values.** They leave a device only as a sealed box to a
  specific roster device, after reauthentication, and never appear in plaintext
  in frames, logs, errors, JSON output or plaintext columns. *Status:*
  implemented (11, ADR 0033). A share is one `share.sealed` per chosen active
  device, sealed (`crypto_box`) to that device's sealing key inside
  `share::share`, from a zeroizing buffer that never reallocates; the sharer
  reauthenticates first, and the credential's project must be bound (a
  password-locked one unlocked). The importer verifies every sealed field
  against the signed envelope and its signer before anything is stored, so a
  member cannot plant a value under another device's name. Errors on these
  paths are static (a JSON parse error, which could quote its input, becomes
  `ShareBindingMismatch("contents")`); receipts, lists and import results
  carry names, devices, share ids and the masked value only; audit details
  carry ids only. *Tests:*
  `share_wire::a_shared_credential_never_crosses_the_wire_in_plaintext` (every
  byte of a real Noise session through a TCP shim: raw, hex, base64 at each
  alignment, JSON-escaped),
  `mesh_share::share_then_import_round_trip_re_encrypts_under_the_target_project`
  (every session frame; every column of every table on three devices, the item
  store's sealed bytes and audit rows included; doctor, status and list
  output; the value decrypts only through the normal reveal path),
  `mesh_share::a_member_cannot_plant_a_credential_in_the_name_of_another_device`,
  `mesh_share::each_bound_field_that_disagrees_with_the_envelope_is_refused`,
  `mesh_share::the_share_items_carry_names_but_never_the_value`,
  `mesh_share::a_wrong_password_on_share_or_import_changes_nothing`,
  `mesh_share::a_share_from_a_since_removed_device_cannot_be_imported`,
  `mesh_share::replace_refuses_a_same_named_credential_of_another_provider`,
  `mesh_share::a_share_whose_audit_row_fails_mints_nothing`,
  `share::tests::sealed_bindings_round_trip_and_each_field_is_checked`,
  `share::tests::a_box_for_another_key_or_garbage_is_unreadable_without_echoing_it`,
  `mesh_cli::share_a_credential_and_import_it_on_another_device_over_a_real_node`
  (CLI stdout and stderr, human and `--json`), smoke's sharing block,
  `kinds::tests::share_debug_never_prints_the_sealed_bytes`,
  `MeshCredentialSharePanel.test.tsx`, `MeshIncomingShares.test.tsx`.
  *Audit (12):* only the sharer or the recipient can revoke a share (MP-10,
  `views::tests::{a_revoke_by_neither_sharer_nor_recipient_ends_nothing,
  copying_a_share_id_does_not_make_a_member_its_sharer}`, the oracle's twin);
  no share can be sealed to a small-order key (MP-5); a credential with live
  outgoing shares cannot be deleted until they are revoked (MI-8,
  `mesh_audit_identity::deleting_a_credential_with_live_shares_is_refused_until_they_are_revoked`).
- **MESH-SI-7 Key lifetime.** Mesh private keys are in memory only while the
  vault is unlocked or the CLI session lives; the sealing key is used only
  inside a reauth-gated import. Key types never print secret material.
  *Status:* implemented (01, 03, 05, 11). *Implemented (11):* the sealing key
  is unwrapped only by `identity::load_seal_key`, called only by
  `UnlockedVault::mesh_credential_import` after its reauthentication; it is
  checked against its public key, used through `crypto_box::SecretKey`
  (zeroized on drop) to open one box, and dropped before the value is stored.
  A running node never holds it, so no share is ever opened unattended
  (`mesh_share::a_wrong_password_on_share_or_import_changes_nothing`,
  `tauri_command_authz::mesh::mesh_credential_share_import_and_reseal_require_correct_reauth`). `SigningKeyPair` wipes on drop (dalek `zeroize`) and
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
  *Implemented (09), the desktop:* the app runs its node in-process
  (`api_tracker_mesh::supervisor`), never as a child process, so keys never
  travel through an environment variable or a session file. Every lock path
  (explicit lock, both auto-lock checks, backup restore) raises the node's
  lock flag; a reaper joins the node so its keys drop; exit waits up to 5 s for
  the same; a backup restore and `leave` stop the node and wait before they
  touch the data directory. The node is started only from an unlocked vault,
  while the app holds it. *Tests:*
  `supervisor::a_real_node_starts_from_the_settings_and_a_lock_stops_it_and_drops_its_keys`,
  `supervisor::a_lock_raises_the_flag_reaps_the_node_and_nothing_restarts`,
  `supervisor::shutdown_on_exit_releases_the_data_directory_and_a_second_node_is_a_recorded_error`,
  `supervisor::sync_runs_nothing_outside_a_mesh_or_with_the_setting_off_and_stops_a_running_node`.

## Spend caps

- **MESH-SI-9 Enforcement.** Cap enforcement is local and opt-in, peers cannot
  toggle it, the forward path never waits on the database or network for a cap
  decision, and overshoot is bounded only as far as costs are known: near
  exhaustion, and while no request cost is known (after a gateway restart or
  at the start of a month), requests run one at a time per cap; beside other
  in-flight requests a request is admitted only while every in-flight
  request's reserved typical (p95) cost still leaves the margin, so several
  requests that each cost far more than typical can together go over by more
  than one request; and spend the gateway has not saved yet can be forgotten
  by a restart (KNOWN_LIMITATIONS "Spend caps").
  *Status:* implemented (08): `crates/gateway::capgate` decides from an `Arc`
  snapshot and atomics only, serializes per cap as above, refuses with a
  pre-upstream 403, fails open with a reason; the
  switch is `mesh_meta` `cap_enforce/<cap>` (local, set only by the
  reauthenticated `UnlockedVault::mesh_cap_enforce`), never a replicated item
  (gateway SI-22). *Tests:* `cap_enforcement::at_exhaustion_a_non_retryable_403_is_sent_before_any_upstream_byte`,
  `near_exhaustion_one_request_at_a_time_and_the_slot_clears_on_every_exit`,
  `only_caps_switched_on_here_are_enforced_and_a_peer_cannot_switch_one_on`,
  `the_gate_fails_open_and_says_why`, `perf::perf_cap_admission_overhead`.
  *Implemented (10), the desktop:* the cap panel's **Enforce on this device**
  goes through the same reauthenticated core method (`mesh_cap_enforce`); the
  dialog explains the 403, when and how far spend can go over the cap, and the
  self-limit before it asks; the panel says when enforcement is inactive and why. *Tests:*
  `tauri_command_authz::mesh::mesh_cap_enforce_requires_correct_reauth`,
  `desktop_flow::a_project_shared_in_the_app_shows_the_cli_devices_usage_and_its_cap`
  (a switch on one device stays off on the other), `CapsPanel.test.tsx`.
- **MESH-SI-10 No double spending.** Rights a device gives away are fenced
  against its running gateway's snapshot (escrow), so the same rights are not
  both spent here and given away, within two limits (KNOWN_LIMITATIONS "Spend
  caps"): a transfer can slip past spend the gateway's writer has not saved
  yet, and a gateway restart can forget recent spend. *Status:* implemented
  (07 node half, 08 gateway half: each snapshot deducts every open escrow row,
  then acknowledges the pending ones it counted, `caps::gate::ack_counted`;
  spend is `persisted + (charged − persisted at the snapshot)`, so while the
  gateway runs a request is neither missed nor counted twice across the
  writer). The bounded
  counter refuses spends and transfers beyond `avail`, and its view clamps a
  device's outgoing rows to what it held (01). Every transfer, burn and grant
  is decided inside the write transaction that publishes it, against this
  device's own spendable figure (its view, minus its gateway's unpublished
  spend and its open escrow), so two processes cannot both give the same
  rights. Every give is a `mesh_cap_escrow` row first: published in the same
  transaction when enforcement is off or no gateway runs; otherwise reserved
  (`pending`) until the gateway acknowledges it (`caps::escrow::ack`), and
  only then published. *Tests:* `crdt::bounded::tests::spend_beyond_avail_is_refused`,
  `the_clamped_view_ignores_a_forged_over_transfer`, `cycles_create_nothing`,
  `cap_safety_holds_for_10k_honest_operation_sequences`,
  `mesh_caps::caps_escrow_publishes_at_once_unfenced_and_waits_for_the_gateway_ack_when_fenced`,
  `mesh_caps::caps_rebalancing_asks_below_20_percent_grants_above_half_and_is_rate_limited`,
  `mesh_caps::caps_advance_minting_covers_an_owner_offline_across_the_month_boundary`
  (unpublished spend counts at once), `mesh_sim::caps_ci_seeds` (cap safety,
  own avail ≥ 0, conservation and the clamp at every step on SQLite, the
  oracle at quiescence),
  `cap_enforcement::the_fence_reserves_before_a_transfer_publishes_and_never_subtracts_twice`,
  `cap_enforcement::under_the_cap_requests_forward_and_spend_is_counted_once_across_the_writer`,
  `cap_enforcement::a_charge_the_writer_never_persists_stays_counted_and_marks_accounting_incomplete`.
  *Audit (12):* a burn waiting for the gateway's ack counts against the
  pending decrease, so it is not burned twice (MC-2,
  `mesh_caps::caps_a_burn_awaiting_the_ack_is_not_burned_twice`); `cap.used`
  never decreases within a month, so deleting local usage returns no spent
  rights (MC-3, `mesh_caps::{caps_deleting_local_usage_never_returns_spent_rights,
  caps_used_is_published_from_the_local_month_spend_and_never_decreases_within_a_month}`);
  a reclaim never takes a local override (MC-6,
  `mesh_caps::caps_a_reclaim_never_takes_a_local_override`); the caps
  simulator checks "not over-burned" at quiescence (MC-4, `mesh_sim::caps_ci_seeds`).
  The gate (MESH-SI-9): a cold gate serializes until it knows a cost (MC-1,
  `cap_enforcement::a_cold_gate_serializes_until_it_knows_a_request_cost`),
  reads rights after reserving (MC-5,
  `capgate::tests::a_completion_racing_an_admission_is_seen_by_it`), flags a
  charge for a vanished project (MC-7,
  `cap_enforcement::a_charge_for_a_vanished_project_stays_counted_and_marks_accounting_incomplete`),
  keeps enforcing through one failed refresh (MC-8,
  `cap_enforcement::one_failing_refresh_between_two_good_ones_keeps_enforcing`),
  and alerts say what it does (MC-10,
  `mesh_caps::caps_alert_text_says_what_the_gate_does_with_the_cap_in_force`).

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
  *Implemented (10), the desktop:* the usage card shows core's report as is
  (per device, "as of", stale/removed, "No data from …: unknown, not zero",
  core's `total_label` and notes) in its own card on the project page and on
  Usage, apart from the provider-reported figures and never added to them.
  *Tests:* `desktop_flow::a_project_shared_in_the_app_shows_the_cli_devices_usage_and_its_cap`,
  `MeshUsageCard.test.tsx`.
- **MESH-SI-13 Nothing automatic.** No auto-binding, auto-import or
  auto-enforcement. *Status:* implemented (06) for binding: sharing binds only
  the sharer's own project; every other device binds by an explicit command,
  never by name or local id; spend caps (07) are created and changed only by
  explicit commands; nothing is enforced until the user switches enforcement
  on, per cap, on that device, with reauthentication (08). Credential shares
  (11) are made, imported and resealed only by explicit, reauthenticated
  commands: a share waits until the user imports it, and a device paired
  later, or a changed value, only raises a reseal *offer* (the node never
  reseals: it would need the value in memory unattended). The desktop (10, 11)
  shares, binds and imports only on an explicit click (rendering the project
  panel, "Available from your devices", the credential's share panel or
  "Credentials shared with this device" calls none of them). *Tests:*
  `mesh_usage::binding_is_never_automatic_cascades_on_delete_and_is_refused_twice`,
  `MeshProjectPanel.test.tsx`, `MeshAvailableProjects.test.tsx`,
  `mesh_usage::usage_on_a_reaches_b_labelled_per_device_with_freshness`,
  `mesh_share::a_new_device_gets_a_reseal_offer_that_does_nothing_without_reauth`,
  `MeshIncomingShares.test.tsx`, `MeshCredentialSharePanel.test.tsx`.
- **MESH-SI-14 No analytics.** The mesh emits no analytics events; the
  `docs/ANALYTICS.md` allowlists are unchanged. *Status:* implemented (01, 05,
  09): no mesh code, the node included, references the analytics module; the
  desktop's Devices view maps to no analytics screen, so opening it sends no
  `screen_view`, and its `mesh_*` commands produce no product event. *Tests:*
  `MeshAppNav.test.tsx` (the Devices view tracks nothing with consent
  granted); `MeshNoAnalytics.test.tsx` (12): binding to a new project from
  Devices (only `invoke` mocked, consent granted, the App's listener mounted)
  sends no event, with a positive control for the ordinary create; and a
  source guard that no mesh component imports the analytics module, calls
  `trackAnalytics`/`gtag` or an `api` method that sends a product signal, and
  that no `mesh_*` command maps to one.
- **MESH-SI-15 No unsafe code.** `#![forbid(unsafe_code)]` in `crates/mesh`, and
  core keeps its crate-level `#![forbid(unsafe_code)]`. *Status:* implemented
  (01) for core (`core::mesh` is inside core), (04) for `crates/mesh`. The
  control channel's same-user check is filesystem permissions, not a peer
  credential call, which would need `unsafe` or a new dependency (as for the
  gateway). *Tests:* the compiler.
