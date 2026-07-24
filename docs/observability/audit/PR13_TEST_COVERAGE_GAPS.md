# PR #13 — Test Coverage: Added & Remaining Gaps

## Regression tests added during remediation

Rust unit/integration (all passing):

- `proxy_integration.rs::plain_http_round_trips_body_and_records_origin_path` —
  proves the plain-HTTP relay direction, header forwarding, connect-host
  recording, and origin-form path (would hang/fail under the original bugs).
- `wire.rs::deadline_read_*` — absolute head-read deadline tolerates
  would-block reads and fires on a Slowloris.
- `proxy.rs::rewrite_uses_origin_form_drops_proxy_headers_and_preserves_the_rest`,
  `request_head_debug_redacts_query_and_proxy_token`,
  `classify_upstream_error_only_certs_are_cert_invalid`.
- `policy.rs::trailing_dot_does_not_bypass_*`,
  `ipv6_transition_prefixes_decode_embedded_ipv4`,
  `ietf_protocol_assignments_block_denied`.
- `sanitize.rs::opaque_tokens_are_never_kept_verbatim` (non-circular),
  `property_no_sensitive_runs_survive` (independent Shannon oracle),
  `redact_command_strips_secrets_from_argv`.
- `aggregate.rs::rollup_survives_an_hour_of_only_transport_errors`,
  `day_bucket_includes_all_hours_not_just_since_watermark`,
  `empty_scope_metrics_return_zeros_not_error`,
  `reroll_hours_backfills_per_credential_buckets_after_attribution`.
- `retention.rs::sweep_never_deletes_events_not_yet_aggregated`.
- `store.rs::oversized_or_empty_host_folds_into_overflow_service`.
- `alerts.rs::old_version_does_not_fire_for_an_ended_session`,
  `opaque_tunnel_success_is_not_a_transport_failure_and_never_crashes`,
  `unknown_api_suppressed_after_user_classification`,
  `inactive_api_suppressed_when_observation_was_not_running`.
- `attribution.rs::unauthenticated_provider_traffic_is_not_confirmed…`,
  `unknown_host_without_auth_is_unattributed`; updated
  `old_version_after_rotation_is_detectable` to rotate the DB credential.
- `observability.rs::observe_injected_resolves_reference_to_the_root…`,
  `run_monitor_sweeps_orphaned_observation_sessions` (unix),
  `tampered_ca_certificate_fails_closed_and_cannot_be_materialized`.
- `no_insecure_verifier.rs` — source-level TLS-bypass + forbidden-env-var guard
  (the test the docs referenced but which did not exist).
- `trust.rs::detects_common_runtimes` (extended: .cmd/.bat/py),
  `merge_no_proxy_unions_both_casings`.

## Remaining gaps (honestly tracked — NOT claimed as covered)

1. **Per-language runtime interception** (Node/Python/curl/Go through the real
   scoped-trust env) has no automated integration test — detection is unit-
   tested, interception is manual. Needs a fixture that launches a real child.
2. **Negative upstream-TLS test** (M10): a self-signed / wrong-host provider
   with `upstream_config: None` must be rejected. Traced correct; needs a
   self-signed provider harness. The `no_insecure_verifier.rs` guard covers the
   source-level invariant in the meantime.
3. **Canary over raw byte streams** (M31): the canary asserts over emitted
   `ObservedRequest` metadata; extending it to scan the SQLite file/WAL,
   captured stderr, and temp files end-to-end is follow-up.
4. **Vault-lock interruption** (H12): no test because the behavior is not
   implemented; a `vault_lock.rs` accompanies the required lock-hook follow-up.
5. **WebSocket / SSE / redirect / compression / chunked-streaming** integration
   coverage: the WS bidirectional relay and framing are implemented and unit-
   level tested (relay.rs), but no end-to-end protocol integration tests exist.
6. **Windows/Alpine platform paths**: verified by the authoritative CI runners
   for compile + the Windows core test job; runtime behavior of `.cmd` spawning
   and BusyBox `ps` is documented, not automated.
7. **Inventory/connection-cap limits** (MAX_SERVICES=5000, cap=64): the fold-to-
   overflow logic is unit-tested for host length; the numeric caps are not
   load-tested.

None of these gaps hides an active vulnerability; they bound how much of the
"works & tested" claim is automated. The compatibility matrix has been rewritten
to mark exactly these as "implemented, not automated-tested".
