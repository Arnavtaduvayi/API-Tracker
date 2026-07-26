# PR #13 — Adversarial Audit Findings Index

Master index of every finding from the 13-agent adversarial audit of the
runtime API observability change set, each independently verified against the
code before remediation. Disposition legend:

- **FIXED** — root cause fixed in code + regression test where feasible.
- **FIXED (docs)** — the claim was false; corrected to match reality (an
  honesty fix, per the "never claim capability you can't prove" rule).
- **RESIDUAL** — accepted for this draft with rationale; tracked as follow-up.
  (PR #13 stays draft/experimental; none are exploitable in the default
  posture.)

Severity is the auditor's rating. "Verified" = I reproduced/confirmed the
finding against the actual code (I did not take agents at face value; several
claims were downgraded on inspection — noted inline).

---

## HIGH / CRITICAL

| # | Area | Finding | Verified | Disposition | Where |
|---|---|---|---|---|---|
| H1 | proxy | plain-HTTP response relay src/dst reversed (client starves, body written upstream) | yes | FIXED | proxy.rs handle_plain; test `plain_http_round_trips_body_and_records_origin_path` |
| H2 | sanitizer | opaque tokens (≤2 classes / no digit) kept verbatim; circular P6 test | yes | FIXED | sanitize.rs is_high_entropy + vowel heuristic; non-circular oracle + opaque-token test |
| H3 | db | roll_up bricks on transport-error-only hour (NULL SUM → NOT NULL); then sweep destroys events | yes | FIXED | aggregate.rs COALESCE; test `rollup_survives_an_hour_of_only_transport_errors` |
| H4 | db | day-bucket undercount (from_hour vs from_day) | yes | FIXED | aggregate.rs from_day; test `day_bucket_includes_all_hours_not_just_since_watermark` |
| H5 | alerts | NULL SUM(status_code=403) crashes alerts(), aborts whole monitor cycle | yes | FIXED | alerts.rs COALESCE + isolate pass; test `opaque_tunnel_success_is_not_a_transport_failure_and_never_crashes` |
| H6 | alerts | old-version-after-rotation fires forever from ended sessions | yes | FIXED | alerts.rs session-liveness bound; test `old_version_does_not_fire_for_an_ended_session` |
| H7 | alerts | revoked-in-use counts pre-revocation traffic, stuck | yes | FIXED | alerts.rs session-liveness bound |
| H8 | attribution | used_current_version always true (current_version never re-read) | yes | FIXED | attribution.rs re-query; test `old_version_after_rotation_is_detectable` (now rotates DB) |
| H9 | attribution | reference credentials break version attribution (read reference row, always v1) | yes | FIXED | vault.rs observe_injected resolves root; test `observe_injected_resolves_reference_to_the_root_credentials_version` |
| H10 | attribution | possible-fallback attributes ALL unknown-host traffic to sole credential | yes | FIXED | attribution.rs gate on had_authorization; test `unknown_host_without_auth_is_unattributed` |
| H11 | process | sweep_orphaned_sessions dead code (never called) → phantom running sessions | yes | FIXED | vault.rs run_monitor wiring + /proc liveness; test `run_monitor_sweeps_orphaned_observation_sessions` |
| H12 | vault-lock | lock/auto-lock does NOT stop an active observation session (CA key stays live) | yes | FIXED (docs) + RESIDUAL | corrected ADR/arch/threat-model/dev-guide honestly; lock-hook = required follow-up |
| C1 | honesty | compat matrix cites ~20 nonexistent test files/functions | yes | FIXED (docs) | RUNTIME_COMPATIBILITY_MATRIX.md rewritten |
| H13 | honesty | unsupported-runtime partial-coverage not implemented; bypassed sessions show "full" | yes | FIXED | session.rs partial-coverage flags + Go downgrade |
| H14 | honesty | corporate proxy chaining + `--proxy-conflict` documented, unimplemented; false diagnostics | yes | FIXED (docs) + code | diagnostics text (Wave 7) + docs corrected; chaining = documented not-implemented |
| H15 | honesty | Go "falls back to connection-only" false | yes | FIXED | session.rs downgrades ConnectionOnlyFallback → Connection + partial flag |
| H16 | honesty | `observe cert repair` / `observe export` don't exist | yes | FIXED (docs) | removed from 4 docs |

## MEDIUM

| # | Area | Finding | Verified | Disposition |
|---|---|---|---|---|
| M1 | proxy | client Host header stored unvalidated as service host (+IPv6 `[` bug) | yes | FIXED — record_http uses connect_host |
| M2 | proxy | plain-HTTP strips all headers incl Authorization | yes | FIXED — forward verbatim except Proxy-*/Connection |
| M3 | proxy | WebSocket/101 tunnels dropped after upgrade | yes | FIXED — real bidirectional relay + mark_partial |
| M4 | proxy | session shutdown stalled by unauth Slowloris | yes | FIXED — client-socket registry + shutdown(Both) + head deadline |
| M5 | proxy | unauth process exhausts connection cap | yes | FIXED (mitigated) — pre-auth deadline + 503-at-cap |
| M6 | sanitizer | 16–19 char tokens pass length floor | yes | FIXED — floor lowered to 16 |
| M7 | ssrf | trailing dot bypasses metadata blocklist | yes | FIXED — normalize host once |
| M8 | ssrf | trailing dot flips single-label internal to Allow | yes | FIXED — same normalization |
| M9 | tls | no_insecure_verifier.rs guard test missing | yes | FIXED — test created |
| M10 | tls | no negative test for untrusted upstream cert | yes | RESIDUAL — traced correct; test noted in coverage-gaps (needs a self-signed provider harness) |
| M11 | tls | plain-HTTP path strips Authorization (dup of M2) | yes | FIXED (M2) |
| M12 | ca | ca_cert_pem not integrity-bound to key → Mode C laundering | yes | FIXED — AAD binds cert PEM hash; test `tampered_ca_certificate_fails_closed…` |
| M13 | db | metrics error on empty scope (InvalidColumnType Null) | yes | FIXED — COALESCE; test `empty_scope_metrics_return_zeros_not_error` |
| M14 | db | roll_up not transactional + sweep un-aggregated events | yes | FIXED — IMMEDIATE txn + watermark-gated sweep; test `sweep_never_deletes_events_not_yet_aggregated` |
| M15 | db | per-credential buckets lose hours before backfill | yes | FIXED — aggregate::reroll_hours at finalize; test `reroll_hours_backfills…` |
| M16 | db | unbounded inventory cardinality/host length | yes | FIXED — host + service + endpoint caps; test `oversized_or_empty_host_folds_into_overflow_service` |
| M17 | alerts | opaque tunnel success counted as transport failure | yes | FIXED — exclude transport_error='none' |
| M18 | alerts | RuntimeUnknownApi ignores user classification | yes | FIXED — suppress on confirmed/user_provider; test `unknown_api_suppressed_after_user_classification` |
| M19 | alerts | shared-credential alert can't clear | yes | FIXED — recency/running bound |
| M20 | attribution | Confirmed with zero auth evidence | yes | FIXED — require had_authorization; wire.rs detects x-api-key etc.; test `unauthenticated_provider_traffic…` |
| M21 | attribution | ambient env-credential misattribution | yes | FIXED (docs) — documented in ADR 0017 limitations |
| M22 | process | parent lowercase no_proxy clobbered on Unix | yes | FIXED — merge both casings; test `merge_no_proxy_unions_both_casings` |
| M23 | process | full command line stored verbatim (secrets in argv) | yes | FIXED — sanitize::redact_command; test `redact_command_strips_secrets_from_argv` |
| M24 | process | Node .cmd/.bat not spawnable/detected on Windows | partial | FIXED (detect) — detect_runtime handles .cmd/.bat/py; spawning .cmd documented |
| M25 | process | BusyBox `ps` breaks liveness (suspected) | code-read | FIXED for new sweep (/proc on Linux); pre-existing inject.rs = RESIDUAL (not in this branch) |
| M26 | process | Windows identity probe conflates WMI failure w/ not-found (suspected) | code-read | RESIDUAL — inject.rs pre-existing, not in this branch |
| M27 | process | diagnostics claim upstream proxy chaining | yes | FIXED — honest text |
| M28 | session | unbounded mpsc writer channel | yes | FIXED — sync_channel(4096) |
| M29 | honesty | pinning detection not emitted | yes | FIXED (docs) — documented limitation |
| M30 | honesty | QUIC/bypass detection not emitted | yes | FIXED (docs) — documented limitation |
| M31 | honesty | canary scope overstated (DB/logs/exports) | yes | FIXED (docs) — narrowed to what the test asserts; extension noted |
| M32 | honesty | dead default-mode setting | yes | FIXED (docs/UI) — disclosed as not-yet-consumed |
| M33 | honesty | upstream TLS bypass guard test missing (dup of M9) | yes | FIXED (M9) |
| M34 | honesty | Mode C shown for Linux/Windows (macOS-only) | yes | FIXED (docs) — matrix marks not-automated |
| M35 | proxy | worker JoinHandle vec grows unbounded | yes | FIXED — reap finished on accept |

## LOW / INFO (dispositions)

| # | Finding | Disposition |
|---|---|---|
| L1 | plain-HTTP path always `/:redacted` | FIXED (sanitize origin-form) |
| L2 | sanitizer: percent-encoded secrets not decoded | FIXED (redact encoded-control; documented printable-% residual) |
| L3 | ssrf NAT64/6to4 embedded-IPv4 not decoded | FIXED (decode + reclassify) |
| L4 | ssrf 192.0.0.0/24 not classified | FIXED (deny Reserved) |
| L5 | all upstream errors recorded as UpstreamCertInvalid | FIXED (classify_upstream_handshake_error) |
| L6 | upstream_config ungated public field | RESIDUAL — internal crate; no-insecure-verifier guard covers the real risk (permissive verifier); noted |
| L7 | leaf cache never re-checks expiry (>24h sessions) | RESIDUAL — availability only, fail-closed; noted in coverage-gaps |
| L8 | rotation wipes system-trust tracking (orphan) | FIXED (docs) — status honesty; `uninstall` guidance |
| L9 | worker handles accumulate (dup M35) | FIXED |
| L10 | proxy token in plain String not SecretString | RESIDUAL — no current leak; RequestHead Debug now redacts; noted |
| L11 | token via child env inheritance / port rebind | RESIDUAL — inherent to env proxying; documented |
| L12 | credential delete leaves per-cred buckets | FIXED (delete buckets on credential delete) |
| L13 | inactive-api fires when observation not running | FIXED (coverage gate); test `inactive_api_suppressed_when_observation_was_not_running` |
| L14 | cred alerts High-confidence w/ 'possible' | FIXED (restricted to confirmed/high) |
| L15 | resolve_validated single-address (no dual-stack fallback) | FIXED (connect_any over all validated addrs) |
| L16 | Windows session sweeping absent | RESIDUAL — Unix-only sweep; documented (inject.rs pre-existing) |
| L17 | systemtrust detect / Orphaned dead code | FIXED (docs) — status honesty; detect() remains for macOS |
| L18 | hour_floor byte-slice panic | FIXED (get(..13)) |
| I1 | RequestHead derives Debug w/ token+query | FIXED (manual redacting Debug) |
| I2 | rcgen KeyPair not zeroized | FIXED (zeroize feature + generate_ca wipe); leaf-key zeroize = RESIDUAL |
| I3 | CertStateRow Debug exposes ciphertext | FIXED (manual Debug elides) |
| I4 | concurrent first-run CA race | RESIDUAL — INSERT-only hardening deferred; consistency-only, not exploitable |
| I5 | runtime_alert_baselines dead schema | FIXED (dropped from migration + docs) |
| I6 | Proxy-* headers forwarded in intercept path | RESIDUAL — token→verified provider only; plain path strips; noted |
| I7 | 192.0.0.0/24 (see L4) | FIXED |
| I8 | 1xx classified as transport error (suspected) | RESIDUAL — not reproduced; 101 handled explicitly in intercept |

See `PR13_REMEDIATION_PLAN.md` for the commit-by-commit remediation,
`PR13_SOURCE_REVIEW_LEDGER.md` for per-finding verification notes,
`PR13_TEST_COVERAGE_GAPS.md` for remaining gaps, and
`PR13_THREAT_MODEL_DELTA.md` for the security-posture change.

---

## Addendum — 2026-07-24: H12 vault-lock now code-fixed (supersedes its earlier "FIXED (docs) + RESIDUAL" disposition)

H12 ("vault lock does not stop an active observation session") was originally
dispositioned as a documented residual (docs corrected honestly; a lock hook
tracked as follow-up). It is now **implemented** and regression-tested. See
`PR13_VAULT_LOCK_COMPLETION.md` (design), `PR13_VAULT_LOCK_REAUDIT.md`
(independent re-audit), and `PR13_VAULT_LOCK_FINAL_VERDICT.md` (verdict). In
brief: `run_monitored` now watches the vault lock state on a bounded poll loop
and, on a manual lock (session-file deleted → `vault_locked`) or auto-lock
(session-file expiry / inline-password TTL → `auto_lock`), shuts the proxy down
first (stopping all decryption + invalidating the token), terminates the child
via the verified-identity path, drops the CA + temp trust files, and marks the
session interrupted. Coverage: `crates/observe/tests/lock_lifecycle.rs`,
`core::session::peek_state` and `LockPolicy` unit tests, and the observe test
suite is now run in CI (Linux job).
