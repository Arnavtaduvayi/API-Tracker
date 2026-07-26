# Runtime API Observability — Implementation Plan

Base: `main` @ `4f8c8cb1bd3217231c6f8b298534ce64c8ce78cf`.
Branch: `feat/runtime-api-observability`, worktree `API-Tracker-observability`.

This plan is the build order and the justification for the non-obvious
choices. It is a gate document, not a substitute for the code; each item is
implemented and tested, not stubbed.

---

## 1. Naming decisions (locked, to avoid collisions found in the sweep)

| Concept | Name | Why |
|---|---|---|
| New crate | `api-tracker-observe` (`crates/observe`) | separate trust surface: sockets + TLS + CA. `forbid(unsafe_code)`. |
| Core module tree | `crate::runtime::*` | `crate::observe` (alert rules) already exists — must not clash |
| CLI verb | `observe` + `run --observe=<mode>` | matches the brief's flag; distinct from existing `monitor` |
| Tauri commands | `observe_*` | matches domain-prefix convention |
| Desktop nav label | **API activity** | "Monitor" is already the alert/doc/webhook cycle |
| Persisted identifiers, env vars, AAD, events | `api-tracker` / `API_TRACKER_` | data-format compatibility; the Tethra rebrand explicitly preserves these |
| New user-facing copy | neutral wording; product name avoided | no new hardcoded "API Tracker"; compatible with the separate rebrand |

## 2. Dependency change

`crates/observe/Cargo.toml` adds, and only adds:
`rustls`, `rustls-pki-types`, `webpki-roots`, `httparse`, `socket2` (already in
the lockfile via `ureq`/`hyper`), and `rcgen` (default-features off; `pem`,
`ring`, `zeroize`) — the single genuinely new crate, on the already-vendored
`ring` backend. `Cargo.lock` is updated with `--locked`-preserving intent (no
unrelated version bumps).

## 3. Data model — migration 12

`db.rs` current head is **v11**; this adds **v12** "runtime api observability".
Tables (all `STRICT`, ASCII identifiers, no `sqlite_` prefix, none named
`projects`/`credentials`):

- `observation_sessions` — one monitored run: id, project_id, mode, source
  (`cli_run`/`desktop_run`), status (`running`/`completed`/`interrupted`),
  interrupt_reason, command, started_at, ended_at, exit_code, pid,
  proc_identity, proxy_port, partial_coverage, runtime_detected,
  trust_level, credential_ids (comma-joined names, no values).
- `observed_api_services` — one host per vault: id, host, provider_id (nullable,
  resolved via manifest api_hosts), source (`locally_observed`/…), is_internal,
  first_seen_at, last_seen_at, user_provider (user correction), user_api_name,
  user_notes, classification (`external`/`internal`), confirmed.
- `observed_endpoints` — (service_id, method, path_template) with
  template_confidence, first_seen_at, last_seen_at.
- `runtime_request_events` — the §1 privacy-model allowlist columns; 7-day
  default retention. Indexed on (session_id), (service_id, at), (at).
- `runtime_metric_buckets` — (granularity, bucket_start, project_id, service_id,
  endpoint_id?, credential_id?) → counters (total, 2xx, 3xx, 4xx, 5xx, auth,
  forbidden, rate_limited, server_error, transport_error, tls_error,
  req_bytes, resp_bytes) + 14 latency histogram bins + credential_version.
  90-day default retention.
- `credential_traffic_attributions` — (session_id, credential_id, service_id)
  → request_count, confidence, evidence, credential_version, used_current.
- `observation_compatibility_results` — (session_id, check) → status, detail.
- `observe_certificate_state` — singleton row: ca_cert_pem, key_ciphertext
  (vault-key AEAD), fingerprint_sha256, created_at, not_after, serial,
  system_trust (`absent`/`installed`/`orphaned`), system_trust_at.
- `observe_internal_allowlist` — (project_id, host, port) user-approved
  internal destinations.

(A `runtime_alert_baselines` table for rolling warm-up/regression baselines was
planned but is **not implemented**: it was dropped from migration 12 and the
shipped alert rules use fixed thresholds with sample floors, not stored
baselines. Adding warm-up baselines is future work.)

Observability settings live in `vault_meta` via `runtime::settings`
(`observe_default_mode`, `observe_event_retention_days`,
`observe_aggregate_retention_days`) — mirroring the `VaultSettings` pattern
without disturbing its all-`u32`, 9-key contract.

**Retention defaults & justification.** Event rows: **7 days** — event
granularity serves recent debugging ("what changed an hour ago"), decays fast,
and is the fastest-growing table; 7 days bounds growth while covering a work
week. Aggregate buckets: **90 days** — trend rules (latency regression, volume
baselines) need weeks; buckets are tiny and coarse. Both configurable
(events 1–90, aggregates 7–730). Sweep runs each monitor cycle (hooking the
existing `prune_observability_state()` call site) and on session end;
`secure_delete=ON` overwrites freed pages.

**Backup/restore.** v2 backup dumps every table dynamically → new tables ride
along automatically. Migration 12 is registered in `db::MIGRATIONS` so
restore_v2 can rebuild at v12. Migration tests go in a **new**
`crates/core/tests/runtime_migration.rs` — **not** `migration_safety.rs`
(smoke greps `test result: ok. 8` there) and **not** in the fixed 4-binary
mocked-suite invocation.

## 4. Module inventory & build order

Each step compiles and its tests pass before the next.

1. Scaffold: workspace member, `rcgen` dep, empty `runtime` tree, migration 12.
2. `runtime::sanitize` + property tests (privacy heart).
3. `runtime::model` + `runtime::store` + `runtime_migration.rs`.
4. `observe::policy` (SSRF/private-range) + tests.
5. `observe::ca` (rcgen CA+leaf) + `observe::keystore` (vault-AEAD) + tests.
6. `observe::clienthello`, `observe::wire`, `observe::relay`, `observe::tls`
   (webpki-roots upstream verifier) + unit tests.
7. `observe::proxy` (listener/auth/CONNECT/plain), `observe::trust`
   (runtime detection + env adapters), `observe::session`,
   `observe::diagnostics` + integration tests against a local rustls "provider".
8. `runtime::attribution`, `runtime::aggregate` (histogram + idempotent rollup),
   `runtime::inventory`, `runtime::retention` + tests.
9. `runtime::alerts` (new rules) + `AlertKind` additions + monitor wiring.
10. Vault methods (session lifecycle, cert lifecycle, queries, delete-by-*).
11. CLI: `run --observe`, `observe_cmd` group + CLI tests.
12. Desktop: `observe_*` Tauri commands + registration; React types, api
    methods, `ApiActivityView`, project/credential activity, cert + settings
    UI, nav wiring; vitest tests.
13. `observe::systemtrust` (Mode C, per-OS) + isolated `#[ignore]` tests.
14. Docs, benchmarks, manual plan, matrix/threat/feature updates, ADR 0017.
15. Validation, hardening, final report, draft PR.

## 5. Alert rules, thresholds, warm-up (conservative by design)

Every rule reads only stored `runtime_*` rows (offline; no network in
`run_monitor`). Minimum sample sizes and baselines prevent noise. All produce
`alerts::NewAlert` fed through the existing engine. New `AlertKind`s carry a
`runtime_` dedup namespace.

| AlertKind | Fires when | Min sample / warm-up | Severity |
|---|---|---|---|
| `RuntimeAuthFailures` | ≥5 `401` to one service in 1h, ≥20% of its reqs | ≥10 reqs | High |
| `RuntimeForbidden` | ≥5 `403` to one service in 1h | ≥10 reqs | Medium |
| `RuntimeRateLimited` | ≥3 `429` to one service in 1h | ≥10 reqs | Medium |
| `RuntimeServerErrors` | 5xx rate ≥20% over ≥20 reqs in 1h | ≥20 reqs | High |
| `RuntimeTransportFailures` | transport-error rate ≥30% over ≥10 conns | ≥10 conns | Medium |
| `RuntimeTlsFailures` | ≥3 upstream TLS failures to one service | ≥3 | High |
| `RuntimeLatencyRegression` | p95 ≥2× the 7-day baseline **and** ≥250ms abs | baseline ≥3 days, ≥50 reqs | Medium |
| `RuntimeVolumeSpike` | day's volume ≥3× 7-day median | baseline ≥7 days | Low |
| `RuntimeApiInactive` | a service with ≥7-day history had 0 reqs for 3× its median gap | history ≥7 days | Info |
| `RuntimeNewApi` | a *known-provider* host first observed in 24h | — | Info |
| `RuntimeUnknownApi` | an *unknown* host first observed in 24h | — | Medium |
| `RuntimeOldCredentialVersion` | a session's injected credential_version < credential's current value_version, after a rotation | rotation exists | High |
| `RuntimeRevokedCredentialInUse` | observed traffic attributed to a credential marked `revoked` | attribution ≥ High | High |
| `RuntimeProdCredInDev` | a `production` credential observed in a session whose project env is `development` | attribution ≥ High | Medium |
| `RuntimeSharedCredential` | one credential's traffic observed across ≥2 unrelated projects | attribution ≥ High | Medium |

"Credential unused for a period" reuses the existing `Unused` kind — observed
traffic updates `credentials.last_used_at`, so the existing rule improves for
free (no new kind). Each alert carries: what, when it began, project, API,
endpoint, credential + confidence, supporting metrics, likely explanations,
recommended next action. **No rule ever says "compromised"** — they describe
deviations and what to check.

## 6. Attribution (no header inspection)

Because `run --observe` injects a known credential set at a known
`value_version`, attribution is derived entirely from state Tethra controls:

- session ↔ injected credential mappings (`credential_env_mappings` + the
  session's injected var names),
- the credential's provider vs. the observed host's resolved provider,
- project association,
- `value_version` captured at launch.

Confidence: **Confirmed** (exactly one injected credential matches the host's
provider) · **High** (one match via inferred host→provider) · **Possible**
(project's sole credential for that provider) · **Ambiguous** (multiple
candidates — all listed, none chosen) · **Unattributed**. Authorization header
values are **never read**, even transiently — old-version-after-rotation is
proven from the launch-time version capture, not from the wire.

## 7. Metrics definitions (explicit)

- **success** = response received with status `2xx` or `3xx`.
- **error** = `4xx`/`5xx` (subclassified) OR a transport/TLS failure.
- Subclasses kept separate and never conflated: auth (`401`), authorization
  (`403`), rate-limited (`429`), client (other `4xx`), server (`5xx`),
  network (transport), TLS.
- A `4xx` is **not** a provider outage; a transport failure is **not** an HTTP
  error rate; a TCP success is **not** a request success. (All three asserted.)
- Latency: fixed 14-bin histogram → interpolated p50/p95/p99, labelled
  *approximate*. Bounded memory, never per-sample storage.

## 8. Test plan → requirement mapping

> **Status note (honest):** the file names below were the PLANNED test layout.
> The shipped tests are consolidated, not one file per row. Authoritative
> mapping of what actually exists vs. what is manual/untested is the
> `RUNTIME_COMPATIBILITY_MATRIX.md` and `audit/PR13_TEST_COVERAGE_GAPS.md`. In
> particular the real Rust integration tests are
> `crates/observe/tests/proxy_integration.rs` (intercept, plain-HTTP, SSRF,
> proxy-auth) and `crates/observe/tests/no_insecure_verifier.rs` (TLS-bypass
> guard); the no-leak canary lives inside `proxy_integration.rs`; migration/
> retention/aggregation/alerts/attribution are covered by in-module unit tests
> and `crates/core/tests/observability.rs`. The `tls_*.rs`, `ssrf.rs`,
> `scope_*.rs`, `proxy_auth.rs`, `privacy_no_leak.rs`, `systemtrust_*.rs`, and
> per-`runtime_*.rs` files named below were NOT created as separate files.

| Brief §22 category | Where |
|---|---|
| Unit | co-located `#[cfg(test)]` in every module |
| Migration | `crates/core/tests/runtime_migration.rs` |
| Property-based sanitizer | `runtime::sanitize` tests (hand-rolled fuzz, no new dep) |
| Proxy integration | `crates/observe/tests/proxy_*.rs` |
| TLS | `crates/observe/tests/tls_*.rs`, `no_insecure_verifier.rs` |
| Process scope | `crates/observe/tests/scope_*.rs` |
| Auth (proxy token) | `crates/observe/tests/proxy_auth.rs` |
| SSRF | `crates/observe/tests/ssrf.rs` |
| Retention | `crates/core/tests/runtime_retention.rs` |
| Aggregation | `runtime::aggregate` tests + `runtime_aggregate.rs` |
| Alerts | `runtime::alerts` tests + `runtime_alerts.rs` |
| CLI | `apps/cli/tests/observe_cli.rs` |
| Tauri authorization | `apps/desktop/src-tauri` command tests |
| React component | `apps/desktop/src/components/*.test.tsx` |
| macOS cert lifecycle | `crates/observe/tests/systemtrust_*.rs` (`#[ignore]`) |
| Backup/restore | `runtime_migration.rs::backup_roundtrip_includes_runtime_tables` |
| Existing-run regression | existing `run_env_scrub.rs` + a new no-observe assertion |
| Privacy no-leak | `crates/observe/tests/privacy_no_leak.rs` (the canary proof) |

## 9. Performance

Benchmarks (`crates/observe/benches/` or a `--bench`-style integration harness
against the local provider): proxy p50/p95/p99 latency overhead, throughput,
concurrency, streaming, event insertion, aggregation, dashboard queries,
retention sweep — measured for baseline / Mode A / Mode B, reported honestly in
the final report. No benchmark massaging.

## 10. Release classification framework

Public distribution stays **blocked** unless every one of these is proven:
upstream cert validation · CA key protection · proxy auth · SSRF prevention ·
payload non-retention · trust cleanup · process scoping · vault-lock behaviour ·
DB migration · existing-run regression · packaged-app behaviour.

The final report classifies against this list with evidence, and is honest
about anything not fully validated in this session (expected: full desktop
end-to-end and packaged-app runs, and the breadth of the runtime matrix beyond
Node/requests/curl). Realistic target for a first pass: **Experimental /
Internal-alpha**, **public-blocked**, with a precise remaining-work list.
