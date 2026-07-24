# Runtime Observability — Developer Guide

Internals guide for contributors working on the runtime API observability
subsystem: the `api-tracker-observe` crate (`crates/observe`) and the
`crate::runtime` module tree in `api-tracker-core` (`crates/core/src/runtime`).

Read the gate documents first; this guide explains *how the code implements
them* and must never contradict them:

- `RUNTIME_OBSERVABILITY_ARCHITECTURE.md` — system design
- `RUNTIME_OBSERVABILITY_THREAT_MODEL.md` — threats `RO-1` … `RO-20`
- `RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md` — the persistence allowlist and sanitizer spec
- `RUNTIME_COMPATIBILITY_MATRIX.md` — what genuinely works, per runtime and protocol
- `IMPLEMENTATION_PLAN.md` — build order, naming, data model, alert rules

Scope reminder, because everything below depends on it: this feature is a
**local, explicitly-launched, metadata-only** observation proxy. There is no
code path capable of recording request bodies, response bodies, header values,
cookies, authorization values, query strings, or full URLs. If a change you
are making would create one, the change is wrong.

Naming rules (locked in `IMPLEMENTATION_PLAN.md` §1): the CLI verb is
`observe` plus `run --observe=off|connection|metadata`; the three modes are
A (`connection`), B (`metadata`, the default when `--observe` is given), and
C (system trust, opt-in, not a run mode); the desktop nav label is
**API activity**. Persisted identifiers, env vars, AAD strings, and event
names use `api-tracker` / `API_TRACKER_` for data-format compatibility. New
user-facing copy uses neutral wording and avoids hardcoding a product name.

---

## Proxy architecture (`observe::proxy`, `observe::relay`, `observe::session`)

The proxy is **blocking, thread-per-connection, with a bounded pool**. There
is no async runtime, no `tokio`, no `hyper`.

Why not async:

- **Backpressure is the whole streaming requirement.** A blocking
  `read()`/`write()` copy loop over a fixed 16 KiB stack buffer *is*
  backpressure. It cannot buffer a body even by accident — there is nowhere to
  put one. This property is load-bearing for the privacy model, not just a
  performance choice.
- `rustls` has a first-class blocking API (`StreamOwned`), so blocking TLS is
  idiomatic, not a workaround.
- The realistic concurrency is one developer's dev server. Adding an executor
  to a security-sensitive local daemon for that workload is unjustified
  complexity and a larger audit surface.
- Bounded resources come from a counting semaphore over a hard connection cap
  (default 64 concurrent, configurable), not from executor fairness. Excess
  connections are `accept`ed and immediately closed with `503`.

Connection lifecycle (architecture §6):

1. The listener binds `127.0.0.1:<ephemeral>` — loopback only, never
   `0.0.0.0`. The child is pointed at it via `HTTPS_PROXY`/`HTTP_PROXY`.
2. Every request must carry `Proxy-Authorization: Basic
   base64("tethra:<32-byte token>")`. The token is per-session `getrandom`
   entropy, compared with `subtle::ConstantTimeEq`, and is never logged, never
   in an error message, never in the DB (RO-2, RO-3). Auth failure is a bare
   `407` with no detail.
3. Request head read is bounded: ≤ 32 KiB total, ≤ 100 headers, ≤ 8 KiB per
   header line, 10 s deadline.
4. `CONNECT host:port` → HTTPS path; absolute-form `http://` → plain path.
5. On the HTTPS path, `observe::clienthello` **peeks** (never consumes) the
   child's TLS ClientHello to read SNI and ALPN without decrypting anything:
   - ALPN offers `http/1.1` (or is absent) → intercept (Mode B).
   - ALPN offers **only** `h2` → opaque tunnel with connection-only metadata.
     We do not pretend to understand HTTP/2.
   - Mode A always takes the opaque path regardless of ALPN.

Timeouts use `SO_RCVTIMEO`/`SO_SNDTIMEO` (`socket2`) plus an overall
connection deadline checked between relay iterations. All bounds are in the
threat model's RO-11 table (Slowloris, oversized heads, idle, lifetime); if
you change one, update that table.

`observe::wire` parses **only heads** — request and response — and determines
framing (`Content-Length`, `Transfer-Encoding: chunked`, `Connection: close`,
status-implied-empty). Bodies are relayed by `observe::relay`, never parsed,
never accumulated; byte counts come from the relay counter. Compression is
passed through undecoded (sizes are wire sizes). `101 Switching Protocols`
records the handshake's metadata, then the connection becomes an opaque relay
(`observation_source = "upgrade_then_opaque"`, `protocol = "websocket"`).
Redirects are not followed by the proxy — each client hop is its own event.

Panic containment (RO-12): a panicking connection thread is caught at the
thread boundary; the listener thread never runs user-influenced parsing
itself. A panic records a compatibility result, marks the session
`partial_coverage`, and closes the socket on unwind so the child never sees a
half-open connection that appears verified.

`observe::session::run_monitored` orchestrates lifecycle: ensure CA → open
session → start proxy + writer → launch child → **interruptible wait loop**
(poll `child.try_wait()` + `LockPolicy::lock_signal` each ~250 ms) → teardown
(proxy shutdown FIRST → verified child termination on a lock → join the writer,
drop + zeroize the CA, delete temp trust files) → attribute/aggregate/finalize.
The vault-lock interrupt is the poll loop, not an `on_lock()` callback (RO-13).
A completed run finalizes `completed`; a lock finalizes `interrupted`
(`vault_locked` / `auto_lock`); a pre-launch failure or a crashed
launcher yields `interrupted` with a machine-readable reason
(`trust_setup_failed` / `child_spawn_failed` / `launcher_gone`), never a silent
`completed`.

## TLS architecture (`observe::tls`, `observe::clienthello`)

Two independent TLS relationships exist on an intercepted connection, and
they must never be conflated:

- **Server side (toward the child):** a `rustls` server using a leaf
  certificate minted by the local CA for the requested SNI. ALPN advertised is
  `["http/1.1"]` only — this is the deliberate HTTP/2 downgrade (see
  "Adding protocol support" below and compatibility matrix §4).
- **Client side (toward the real provider):** a `rustls` client whose config
  is built exactly once, in `tls::upstream_config()`, from
  `webpki_roots::TLS_SERVER_ROOTS`, with **full default verification** and
  correct SNI/hostname checking.

Non-negotiable rules (RO-6):

- There is **no** `dangerous()` call anywhere in the crate, no custom
  permissive `ServerCertVerifier`, ever. Not behind a feature flag, not in a
  test helper, not "temporarily".
- `tests/no_insecure_verifier.rs` is a **source-level guard**: it reads every
  `.rs` file in `crates/observe/src` and fails if it finds `dangerous`,
  `NoCertificateVerification`, `set_certificate_verifier`,
  `danger_accept_invalid`, or `ServerCertVerifier` outside a comment. It
  exists to catch a future contributor adding a bypass. Do not weaken or
  special-case this test to make a change compile — restructure the change.
- Upstream verification failure is surfaced to the child as a TLS alert
  **and** recorded as `transport_error = "upstream_certificate_invalid"`. It
  is never downgraded to a successful request.
- Never set, and never suggest setting, verification-disabling variables
  (`NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONHTTPSVERIFY`, `GIT_SSL_NO_VERIFY`,
  etc.). `trust.rs` tests assert their absence from the child environment.
  When a corporate MITM proxy makes upstream verification fail, the correct
  answer is chaining plus adding the corporate root via `SSL_CERT_FILE`-style
  configuration (RO-18) — never disabling verification.

Dependency posture: `rustls` 0.23, `rustls-pki-types`, `webpki-roots`,
`httparse`, `socket2` are all already in the lockfile; `rcgen`
(`default-features = false, features = ["pem", "ring", "zeroize"]`) is the
single genuinely new crate, on the already-vendored `ring` backend. No
`openssl`, no `native-tls`. The crate is `forbid(unsafe_code)`.

## Certificate lifecycle (`observe::ca`, `observe::keystore`, `observe::systemtrust`)

**CA generation.** One CA per vault: ECDSA P-256, `getrandom` OS entropy via
`ring`, `basicConstraints: CA:TRUE, pathlen:0`, `keyUsage: keyCertSign,
cRLSign`, 36-month validity, random 20-byte serial, CN
`Tethra Local Observation CA (<vault-id-prefix>)`. Generation writes the
`observe_certificate_state` row in one transaction; a crash mid-generation
leaves no row and the next start regenerates (RO-15).

**Key storage.** The private key exists as PKCS#8 DER, encrypted via
`crypto::encrypt` under the **vault key** with AAD
`api-tracker:v1:observe-ca-key:{vault_id}`, stored in
`observe_certificate_state.key_ciphertext`. It is never written to disk in
plaintext, never printed, never crosses the Tauri IPC boundary (no DTO carries
`key_ciphertext`), and is not in any backup's plaintext sections. In memory it
lives in `SecretBytes` (zeroize-on-drop) and is materialised only inside the
proxy thread pool.

**CA certificate (public half).** Written to a `0600` temp file for
`NODE_EXTRA_CA_CERTS`-style trust and deleted on session end. It contains no
private key.

**Leaf minting.** Per-SNI leaves (falling back to the CONNECT authority):
24 h validity, `serverAuth` EKU only, SAN = exactly the requested name.
Cached in a bounded LRU of 256 entries; leaf keys are zeroized on eviction and
on lock/shutdown.

**Vault lock (RO-13).** Implemented via an in-process lock watch rather than a
cross-process hook (the CLI `run` process owns the live proxy + CA, so it
enforces the lock itself). `run_monitored` polls `LockPolicy::lock_signal` while
waiting on the child: a deleted session file → `vault_locked`; an expired
session file or the inline-password auto-lock TTL → `auto_lock`. On a signal it
shuts the proxy FIRST (stops decryption, invalidates the token), terminates the
child via `inject::terminate_verified`, drops the CA + temp files, and marks the
session interrupted. Portable state check lives in `core::session::peek_state`
(unit-tested on Linux+Windows CI); the end-to-end lifecycle is
`crates/observe/tests/lock_lifecycle.rs` (Unix; wired into the Linux CI job).
There is no `session::on_lock()` symbol — the mechanism is the poll loop, not a
callback.

**Rotation, removal, orphans.** `observe cert status` reports
present/absent, fingerprint, dates, and the system-trust state THIS VAULT
recorded (`absent`/`installed`). `observe cert rotate` mints a new CA
(required after any suspected exposure, RO-1). `observe cert uninstall` removes
a Mode C entry from the OS store. There is no `observe cert repair`, and status
does not scan the OS store, so it cannot report `orphaned`; a stale OS-store
entry (e.g. after a vault was deleted and recreated) must be removed manually
with `observe cert uninstall` — app uninstall does **not** remove a
system-trust entry, so this path matters.

**Mode C constraints (RO-20).** Installation targets the **user** trust store
only (macOS login keychain via `security add-trusted-cert` without `-d`,
Linux user NSS DB, Windows `certutil -addstore -user Root`), requires all five
gates (explanation screen, explicit choice, master-password reauth, the OS's
own prompt, confirmation text), and never suppresses, imitates, or works
around the OS prompt. Mode C code must never run implicitly from a monitored
launch.

## Data model (migration 12, `runtime::model`, `runtime::store`, `runtime::retention`)

Migration **12** ("runtime api observability") in `crates/core/src/db.rs`.
All tables are `STRICT`. Grains and retention:

| Table | Grain | Retention |
|---|---|---|
| `observation_sessions` | one monitored run | with project |
| `observed_api_services` | one host per vault | permanent inventory |
| `observed_endpoints` | (service, method, path template) | permanent inventory |
| `runtime_request_events` | one request | **7 days** default (configurable 1–90) |
| `runtime_metric_buckets` | (granularity, bucket, project, service, endpoint?, credential?) | **90 days** default (configurable 7–730) |
| `credential_traffic_attributions` | (session, credential, service) rollup | with session |
| `observation_compatibility_results` | (session, check) | with session |
| `observe_certificate_state` | singleton | until rotated/removed |
| `observe_internal_allowlist` | (project, host, port) | user-managed |

Key rules:

- `runtime_request_events` columns are exactly the privacy model §1 allowlist
  — adding a column requires updating that document first and demonstrating
  the new column cannot carry payload-derived text.
- `runtime_metric_buckets`, `observed_api_services`, `observed_endpoints`,
  and `credential_traffic_attributions` are aggregates or references; they
  introduce **no new payload-derived string**.
- Locally observed data and provider-reported `usage_snapshots` are **never
  merged** — there is deliberately no query that sums across the two.
- Settings live in `vault_meta` via `runtime::settings`
  (`observe_default_mode`, `observe_event_retention_days`,
  `observe_aggregate_retention_days`), mirroring the `VaultSettings` pattern
  without disturbing its existing key contract.
- Rows live in the vault DB under the same at-rest protections as every other
  operational table (`0700` dir, `0600` DB/WAL/SHM, `secure_delete=ON`, WAL
  truncation on lock). They are deliberately **not** column-encrypted — see
  the architecture §12 rationale and `docs/decisions/0018-runtime-observability-storage.md`.
  No secret material is stored by this feature at all.
- `retention::sweep` runs each monitor cycle and on session end;
  `secure_delete=ON` overwrites freed pages. Deletion surfaces: by project,
  by session, and delete-all (reauthentication-gated); none touch credentials.
- Migration tests go in `crates/core/tests/runtime_migration.rs` — **not**
  `migration_safety.rs` (its smoke test greps a fixed result count) and not
  the fixed mocked-suite invocation. v2 backup dumps tables dynamically, so
  the new tables ride along; `backup_roundtrip_includes_runtime_tables`
  proves it.

## Sanitization (`runtime::sanitize`)

This is the privacy heart. It is pure, deterministic, has no DB or network
access, and is **the only code permitted to turn a wire-derived string into a
stored string**. The single rule: no unsanitized string derived from the wire
ever reaches a `store::` function.

Pipeline (privacy model §3):

1. **Query/fragment removal, first and unconditional.** The raw target is cut
   at the first `?` or `#`; the remainder is dropped immediately and never
   assigned to anything that outlives the function.
2. **Bounds.** ≤ 512 bytes, ≤ 20 segments; overflow appends `/:truncated`
   and drops confidence to `low`. Empty or non-`/`-leading targets become
   `/:redacted` at confidence `low`.
3. **Per-segment classification**, first matching rule wins: UUID → `:uuid`,
   JWT-shaped → `:jwt`, email → `:email`, credential-shaped prefixes
   (`sk-`, `ghp_`, `AKIA…`, …) → `:token`, long hex (≥16) → `:hash`,
   base64/high-entropy → `:token`, digit runs (≥2) → `:id`, filenames with
   sensitive embedded runs → `:file`, oversized/non-printable → `:redacted`
   (confidence `low`), otherwise **keep verbatim**. Low-entropy dictionary-ish
   segments (`v1`, `users`, `octocat`) are intentionally kept — over-templating
   destroys the endpoint table's usefulness; the guarantee is that
   identifier-shaped segments are always replaced.
4. **Content-Type → category.** Parameters (everything after `;`, including
   multipart boundaries) are severed before mapping to the closed
   `ContentKind` enum. The raw header value is never stored.
5. **Authorization presence.** `had_authorization` is a boolean recording only
   that an `Authorization` header existed. The value is never read, copied,
   decoded, or parsed for a scheme. The proxy strips `Authorization`,
   `Proxy-Authorization`, `Cookie`, and `Set-Cookie` from its own view
   immediately after using the framing-relevant headers.

**Type-level enforcement** (privacy model §4): the sanitizer returns
`ObservedRequest`, which has no field capable of holding a query string, a
header value, a cookie, or a body. `store::insert_request_event` accepts only
`&ObservedRequest` plus numeric/enum measurements. There is no function
anywhere that accepts a raw path, raw header map, or body and writes to the
database. A reviewer verifies the guarantee by reading the struct definition,
not by auditing a filter.

**Property invariants P1–P9**, asserted by hand-rolled deterministic fuzz in
`sanitize.rs` tests (no new dev-dependency):

- **P1** no `?`/`#` in output, and nothing that appeared only after them in
  the input
- **P2** no digit run ≥ 5
- **P3** no hex run ≥ 16
- **P4** no UUID
- **P5** no `@`
- **P6** every segment below a fixed Shannon-entropy ceiling, or a
  `:placeholder`
- **P7** idempotent: `sanitize(sanitize(x)) == sanitize(x)`
- **P8** bounded: ≤ 512 bytes, ≤ 21 segments
- **P9** stable structure: a fixture list of real REST path shapes maps to
  expected templates (guards against over-templating regressions)

Any change to the classification rules must keep all nine passing and update
the worked-example table in the privacy model.

## Attribution (`runtime::attribution`)

Attribution **never inspects an `Authorization` header** — not even
transiently. It is derived only from state the product already controls:

- session ↔ injected credential mappings (which credentials
  `run --observe` injected, under which env var names),
- the credential's provider vs. the observed host's resolved provider
  (`runtime::inventory` + manifest `api_hosts`),
- project association,
- the credential's `value_version` **captured at process launch**.

Confidence states, in order:

| State | Meaning |
|---|---|
| **Confirmed** | exactly one injected credential matches the host's provider |
| **High** | one injected match, but host→provider mapping is inferred rather than manifest-declared |
| **Possible** | no injection match, but the project has exactly one credential for that provider |
| **Ambiguous** | multiple candidates — all listed, none chosen |
| **Unattributed** | unknown host, no provider mapping |

`credential_id` is persisted only at ≥ Possible. The launch-time
`value_version` capture is what makes "old credential still in use after
rotation" (`RuntimeOldCredentialVersion`) **provable rather than guessed** —
we compare the version injected at launch against the credential's current
version; nothing is inferred from wire content. `used_current_version` is set
only when provable.

## Aggregation (`runtime::aggregate`)

`aggregate::roll_up(conn, through)` is **idempotent by construction**:

1. Read the watermark from `vault_meta` (`runtime_aggregate_watermark`).
2. Recompute every **complete** hour bucket from `watermark − 1h` through
   `through` — an interrupted run always redoes the last partial hour.
3. `INSERT … ON CONFLICT(granularity, bucket_start, project_id, service_id,
   endpoint_id, credential_id) DO UPDATE` with **full replacement, never
   increment**. Running it twice produces identical rows.
4. Advance the watermark in the same transaction.

Latency is a **fixed 14-boundary histogram** (1, 2, 5, 10, 25, 50, 100, 250,
500, 1000, 2500, 5000, 10000, +inf ms), stored as 14 integer counters per
bucket. p50/p95/p99 are linearly interpolated within the containing bin.
Memory is O(buckets), never O(samples); quantiles are labelled *approximate*
in the UI because they are.

Metric definitions are fixed in `IMPLEMENTATION_PLAN.md` §7 and enforced by
test: a transport failure is never counted in the HTTP error rate
(`transport_never_counts_as_http_error`), and a TCP connect success is never
a request success (`tcp_success_is_not_request_success`). A `4xx` is not a
provider outage. Keep the subclasses (401 / 403 / 429 / other-4xx / 5xx /
transport / TLS) separate everywhere.

## Alert rules (`runtime::alerts`)

Rules read only stored `runtime_*` rows — they run offline inside the
existing `run_monitor` cycle, with no network access. Each rule produces
`alerts::NewAlert` values fed through the **existing** `alerts::upsert` /
`auto_resolve_stale` engine, inheriting dedup, lifecycle, notification
channels, and UI for free. New `AlertKind` variants use a `runtime_` dedup
namespace.

The full rule table — thresholds, minimum sample sizes, warm-up, severity —
is normative in `IMPLEMENTATION_PLAN.md` §5. Highlights for implementers:

- Rolling-baseline volume/latency rules (`RuntimeLatencyRegression`,
  `RuntimeVolumeSpike`) and the `runtime_alert_baselines` table are **NOT
  implemented** in this version and the table was dropped from migration 12.
  The shipped spike rules use fixed thresholds with sample floors, not stored
  baselines. Adding warm-up baselines is future work.
- Credential rules (`RuntimeOldCredentialVersion`,
  `RuntimeRevokedCredentialInUse`, `RuntimeSharedCredential`) require
  attribution confidence ∈ {confirmed, high} and bind old-version/revoked
  detection to still-running sessions (so they auto-resolve).
- "Credential unused" reuses the existing `Unused` kind: observed traffic
  updates `credentials.last_used_at`, so the existing rule improves with no
  new kind.
- **No rule ever says "compromised."** Alerts describe deviations, supporting
  metrics, likely explanations, and what to check.

## Test fixtures and the privacy proof

- **Local rustls "provider" server.** The proxy integration test
  (`crates/observe/tests/proxy_integration.rs`) runs against a local TLS server
  acting as the upstream provider — no real provider, no real credentials, no
  network. It covers TLS intercept, plain-HTTP round-trip, SSRF blocking, and
  proxy-auth 407. The upstream-verification guard is
  `crates/observe/tests/no_insecure_verifier.rs`. (There are no separate
  `tls_*.rs`/`ssrf.rs`/`proxy_auth.rs`/`scope_*.rs` files; those cases live in
  `proxy_integration.rs` and the in-module unit tests.)
- **Canary markers.** Test traffic stuffs every dangerous location — URL path,
  query string, `Authorization: Bearer <marker>`, `Cookie`, request body,
  response body — with distinct high-entropy markers (fake keys like
  `sk-proj-LEAKCANARY…`, `canary@leak.test`, a JWT, a UUID,
  `AI-PROMPT-CANARY`, source code, multipart forms). All test credentials are
  unmistakably fake.
- **The end-to-end canary
  (`proxy_integration.rs::intercept_captures_sanitized_metadata_and_leaks_no_payload`).**
  Drives a real monitored HTTPS request through the proxy and asserts every
  marker is absent from the metadata the proxy emits — the in-memory
  `ObservedRequest` values (and their `Debug`/serde forms) collected by a test
  sink, which are the ONLY thing that reaches the store — while confirming the
  provider *received* the streamed body and the client got the response. The
  guarantee is structural (`ObservedRequest` cannot hold payload). Scope note:
  the canary asserts over the emitted metadata, not the raw SQLite file/WAL,
  captured stderr, or temp files; extending it to scan those byte streams is
  tracked follow-up. If your change makes this test fail, the change is leaking;
  fix the change, never the test.
- **Source-grep guards.** `no_insecure_verifier.rs` (TLS, above) and the
  privacy model §2 grep (`record.?body|capture.?body|full.?payload|
  store.?body` must match nothing outside absence-asserting tests).
- **Mode C tests** (`systemtrust_*.rs`) are `#[ignore]` and run only under
  `TETHRA_TEST_SYSTEM_TRUST=1` in an isolated environment — CI never touches
  a real trust store. `mode_b_never_installs` proves scoped mode makes no
  system change.
- Logging discipline (RO-16): the observe crate has no logging framework and
  no `println!`/`eprintln!` of wire-derived data. Errors carry
  `&'static str` context, never formatted wire data. Keep it that way — a
  debug log is the most likely leak vector in a metadata-only design.

## Adding a runtime adapter

A "runtime adapter" is how `observe::trust` gives a specific runtime scoped
trust in Mode B. To add one:

1. **Detection.** Extend the classifier in `trust.rs` (argv0 / interpreter
   inspection) to recognize the runtime, and pick the honest support level:
   `FullySupported`, `ProbablySupported`, `ConnectionOnlyFallback`,
   `Unsupported`, plus the diagnostic states `PinningSuspected` /
   `ProxyBypassSuspected`. Verify against **current official documentation**
   which trust env var the runtime actually honours, per platform — do not
   assume (Go honours `SSL_CERT_FILE` on Linux but not macOS/Windows; Java
   reads neither the proxy env vars nor a CA env var).
2. **Environment.** Add the variable to the child environment via
   `std::process::Command::env` only — never `setenv` in the parent. If the
   variable has **replace semantics** (like `SSL_CERT_FILE`), point it at the
   combined bundle (platform roots ++ local CA) that `trust.rs` builds;
   pointing it at our CA alone would shrink the child's trust set and break
   unrelated TLS. Append-semantics variables (like `NODE_EXTRA_CA_CERTS`) may
   reference the CA file directly.
3. **Never** add any verification-disabling variable. The existing test
   asserting the absence of `NODE_TLS_REJECT_UNAUTHORIZED`,
   `PYTHONHTTPSVERIFY`, `GIT_SSL_NO_VERIFY`, etc. must keep passing; extend
   it with any new runtime's equivalent.
4. **Fallback honesty.** If the runtime cannot be given scoped trust, report
   `ConnectionOnlyFallback` or `Unsupported` so the session is recorded
   `partial_coverage` with a reason and the UI shows the badge. Never let a
   new adapter claim `FullySupported` without a passing `trust_<runtime>.rs`
   integration test proving the monitored process both proxies **and**
   verifies against the session CA.
5. **Documentation.** Add a row to `RUNTIME_COMPATIBILITY_MATRIX.md` §2 with
   the honest status and the test name (or "documented" / "manual").

## Adding protocol support

**HTTP/2 is the top candidate.** Today Mode B advertises only `http/1.1` in
the intercepted connection's ALPN, so dual-stack clients downgrade for the
monitored run (an observable behaviour change, documented and shown in the
UI), and h2-only clients (gRPC) get an opaque tunnel with connection-only
metadata. This was a deliberate decision (compatibility matrix §4): a
half-correct h2 decoder is worse than none, because it would mis-frame and
could mis-attribute.

What true HTTP/2 support would require:

- **HPACK.** Stateful header compression with per-connection dynamic tables
  in both directions. Getting the table state wrong corrupts every subsequent
  header on the connection — and because attribution and metadata come from
  headers' *structural* fields (method, path, status), HPACK correctness is a
  privacy-adjacent requirement, not a nicety. The privacy discipline carries
  over unchanged: decoded header *values* would still be dropped at the
  sanitizer boundary; only the same allowlisted metadata may survive.
- **Stream multiplexing.** Many concurrent streams per connection, each an
  independent request event; per-stream state machines; correct association
  of HEADERS/DATA/RST_STREAM frames to events.
- **Flow control.** Connection- and stream-level windows in both directions —
  this replaces the "blocking copy loop is backpressure" property, so the
  no-buffering guarantee has to be re-established explicitly and re-proven by
  `privacy_no_leak.rs` and the streaming tests.
- **CONTINUATION handling** and the associated header-bomb bounds, mapped
  onto the existing RO-11 limits.
- ALPN would then advertise `h2` where appropriate, and `protocol` would
  record `h2` honestly instead of `h2_opaque`.

For any protocol addition: extend the `protocol` and `observation_source`
enums, keep transport/HTTP outcome separation intact, add a `proxy_*.rs`
integration test, update the compatibility matrix row from ⛔/🟡 with the
test name, and never claim coverage the code cannot prove.

**Explicitly out of reach without a redesign:** HTTP/3/QUIC (UDP — bypasses
an HTTP proxy entirely; documented as a known bypass but NOT auto-detected in
this version — there is no `possible_quic_or_bypass` diagnostic yet — never
blocked or hidden), browser traffic, and machine-wide capture. These
are product non-goals, not backlog items.

## Security invariants — reviewer checklist

Run down this list for any change touching `crates/observe` or
`crates/core/src/runtime`. Each line names its enforcement.

- [ ] **Loopback-only listener.** The proxy binds `127.0.0.1` on an ephemeral
  port, never `0.0.0.0`, never a configurable interface. (RO-19)
- [ ] **Proxy token never logged.** Per-session 32-byte token; constant-time
  compare; absent from logs, errors, compatibility results, DTOs, and the DB.
  Bare `407` on failure. (`proxy_auth.rs`, `privacy_no_leak.rs`; RO-2/RO-3)
- [ ] **SSRF pre- and post-DNS.** `policy::check_host` runs on the literal
  authority **and** on every resolved address; the connection dials the
  validated `SocketAddr`, never re-resolving — no rebinding window.
  Loopback/private/link-local/CGN/metadata/multicast/reserved denied;
  IPv4-mapped IPv6 unwrapped before checking; only ports 80/443 unless
  explicitly allowlisted per `(project, host, port)` with a persistent UI
  warning and a compatibility-result record.
  (`proxy_integration.rs::ssrf_targets_are_blocked`, `policy.rs` unit tests;
  RO-4/RO-5)
- [ ] **Upstream verification intact.** One `ClientConfig` from
  `webpki-roots`, full verification, no `dangerous()`, source-grep guard
  passing; upstream cert failure surfaces as a TLS alert to the child and
  `upstream_certificate_invalid` in the record, never as success.
  (`no_insecure_verifier.rs`, `tls.rs` unit tests; RO-6)
- [ ] **Metadata-only type boundary.** Every stored wire-derived string
  passes through `runtime::sanitize`; `ObservedRequest` still has no field
  able to hold a query string, header value, cookie, or body; no new
  `store::` function accepts raw wire data; P1–P9 pass; the
  `proxy_integration.rs` canary passes. (privacy model §§3–6)
- [ ] **No verification-disabling env vars** set on the child, ever, enforced
  by `no_insecure_verifier.rs`, and the absence test covers any new variable
  the change introduces. (§10 of the architecture)
- [ ] **Vault-lock teardown (implemented).** On a manual lock / auto-lock the
  proxy is shut down (listener stops, token invalidated, connections closed, CA
  key + leaf cache cleared), the monitored child is terminated (verified), and
  the session is `interrupted / vault_locked` (or `auto_lock`). Covered by
  `crates/observe/tests/lock_lifecycle.rs` and the `core::session::peek_state` /
  `LockPolicy` unit tests. (RO-13)
- [ ] **CA key containment.** Key exists only as vault-key AEAD ciphertext
  (AAD `api-tracker:v1:observe-ca-key:{vault_id}`) at rest and `SecretBytes`
  in memory; not in any DTO, IPC payload, CLI output, or backup plaintext.
  (RO-1)
- [ ] **Mode C gating untouched.** Any Mode C change preserves all five
  gates, user-store scoping, and the ban on suppressing or imitating the OS
  prompt. (RO-20)
- [ ] **Honest coverage.** Anything short of `FullySupported` marks the
  session `partial_coverage` with a machine-readable reason; no dashboard
  path presents partial data without the badge; TCP success ≠ request
  success; transport errors ≠ HTTP errors. (RO-8, matrix §3)
- [ ] **Bounded resources.** Any new buffer, cache, queue, or loop has an
  explicit bound consistent with the RO-11 table, and the table is updated if
  a bound changes.
- [ ] **No new logging of wire data.** No logging framework, no
  `println!`/format of wire-derived strings; errors carry `&'static str`
  context. (RO-16)
