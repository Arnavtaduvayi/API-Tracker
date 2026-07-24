# Runtime API Observability — Architecture

Status: implemented (this branch, `feat/runtime-api-observability`)
Base commit: `4f8c8cb1bd3217231c6f8b298534ce64c8ce78cf` (`main`)
Scope: **metadata-only**. No request/response body capture capability exists in
this design or in the code that implements it.

---

## 1. Problem

The product today answers "what credentials do I have, and what do providers
say about them". It cannot answer "what is my application actually doing right
now". Provider-reported usage (`usage_snapshots`, synced from OpenAI/Anthropic
admin APIs) is daily-granular, account- or project-attributed, covers only the
five catalog providers, and arrives hours late.

Runtime observability answers a different set of questions from a different
evidence source: a local, explicitly-launched, per-process HTTP proxy.

These two sources are **never merged**. Provider-reported numbers stay in
`usage_snapshots`; locally observed numbers stay in `runtime_*` tables. The UI
labels them separately (§16 of the brief; enforced by having no query that
sums across the two).

## 2. Non-goals

- Machine-wide traffic capture.
- Browser traffic.
- Any capability to record request or response bodies.
- Decoding protocols we cannot decode correctly (HTTP/2 framing, QUIC).
- Claiming coverage we cannot prove.

## 3. Crate layout

Core stays free of listening sockets and TLS termination. The proxy is a new,
separately auditable crate.

```
crates/core                    (api-tracker-core)      existing
  src/runtime/mod.rs           module root, public types
  src/runtime/sanitize.rs      path templating + header allowlist  ← privacy boundary
  src/runtime/model.rs         Rust types for the runtime_* tables
  src/runtime/store.rs         all SQL for runtime_* tables
  src/runtime/attribution.rs   credential attribution + confidence
  src/runtime/aggregate.rs     idempotent hourly/daily rollups, histograms
  src/runtime/alerts.rs        observability alert rules
  src/runtime/retention.rs     retention sweep
  src/runtime/inventory.rs     observed API identity, provider host mapping
  src/runtime/settings.rs      observation settings + internal allowlist
  src/db.rs                    migration 12

crates/observe                 (api-tracker-observe)   NEW
  src/lib.rs                   forbid(unsafe_code)
  src/ca.rs                    CA + leaf certificate lifecycle
  src/keystore.rs              vault-encrypted CA key handling
  src/policy.rs                destination policy (SSRF/private-range denial)
  src/clienthello.rs           TLS ClientHello sniffer (SNI + ALPN, no decrypt)
  src/wire.rs                  bounded HTTP/1.1 head parsing + framing
  src/relay.rs                 streaming copy with backpressure, no buffering
  src/proxy.rs                 listener, auth, connection lifecycle
  src/trust.rs                 per-runtime scoped-trust environment adapters
  src/systemtrust.rs           Mode C: OS trust store (macOS/Linux/Windows)
  src/diagnostics.rs           compatibility self-check
  src/session.rs               ObservationSession orchestration

apps/cli/src/observe_cmd.rs    NEW   `observe` subcommands
apps/cli/src/run_cmd.rs        EXTENDED  `run --observe=<mode>`
apps/desktop/src-tauri         EXTENDED  observe_* Tauri commands
apps/desktop/src/components/MonitorView.tsx etc.  NEW
```

Rationale for a separate crate: `api-tracker-core`'s module doc promises no
network I/O beyond the outbound provider clients. A listening socket, a TLS
terminator and a certificate authority are a materially different trust
surface and deserve their own review boundary, their own dependency set, and
their own `forbid(unsafe_code)`.

`api-tracker-observe` depends on `api-tracker-core` (for the sanitizer, the
store, `SecretBytes`, and the vault). Core does **not** depend on it, so the
CLI's non-observed paths and every existing test link exactly as before.

## 4. Dependencies added

| Crate | Version | Already in lockfile? | Why |
|---|---|---|---|
| `rustls` | 0.23 | **yes** (via `ureq`) | TLS server + client |
| `rustls-pki-types` | 1 | **yes** | cert/key types |
| `webpki-roots` | 1.0 | **yes** | upstream verification root store |
| `httparse` | 1.10 | **yes** (via `hyper`) | bounded HTTP/1.1 head parsing |
| `rcgen` | 0.14 | no — **only new crate** | X.509 CA + leaf generation |

`rcgen` is configured `default-features = false, features = ["pem", "ring",
"zeroize"]`, so it uses the `ring` backend already vendored for `rustls`. No
`tokio`, no `hyper`, no `openssl`, no `native-tls` is introduced.

## 5. Concurrency model — threads, not async

The proxy is **blocking, thread-per-connection, with a bounded pool**. There is
no async runtime.

Justification:

- Backpressure is the entire streaming requirement, and a blocking
  `read()`/`write()` copy loop over a fixed 16 KiB stack buffer *is*
  backpressure. It cannot buffer a body even by accident: there is nowhere to
  put one.
- `rustls` has a first-class blocking API (`StreamOwned`).
- Adding `tokio` to a security-sensitive local daemon for a workload whose
  realistic concurrency is "one developer's dev server" is unjustified
  complexity.
- Bounded resources come from a counting semaphore over a hard connection cap
  (default 64 concurrent, configurable), not from an executor's fairness.

Timeouts are enforced with `SO_RCVTIMEO`/`SO_SNDTIMEO` (`socket2`) plus an
overall connection deadline checked between relay iterations.

## 6. Connection lifecycle

```
 child process
   │  HTTPS_PROXY=http://127.0.0.1:<ephemeral>
   │  Proxy-Authorization: Basic base64("tethra:<32-byte token>")
   ▼
 Listener 127.0.0.1:<ephemeral>            ← loopback only, never 0.0.0.0
   │  accept()  (refused past MAX_CONNS)
   ▼
 read request head, ≤ 32 KiB, ≤ 100 headers, 10 s deadline
   │
   ├─ Proxy-Authorization missing/wrong ──► 407, log NOTHING about the token
   │
   ├─ CONNECT host:port ──► §6.1
   └─ absolute-form http:// ──► §6.2
```

### 6.1 CONNECT (HTTPS)

1. **Policy check on the literal authority** (`policy::check_host`): reject
   loopback/private/link-local/multicast/broadcast literals, `.local`,
   cloud-metadata names, non-`443`/`80`/allowlisted ports, invalid hostnames.
2. **Resolve**, then **re-check every resolved address**. Both pre- and
   post-resolution checks run, which is what closes DNS rebinding: the address
   we actually `connect()` to is the address that passed the check, because we
   connect to the resolved `SocketAddr` directly rather than re-resolving.
3. Reply `200 Connection Established`.
4. **Peek** (do not consume) the client's TLS ClientHello (`clienthello.rs`):
   extract SNI and ALPN.
   - ALPN offers `http/1.1` (or is absent) → **intercept** (§6.1a).
   - ALPN offers **only** `h2` (gRPC, h2-only clients) → **opaque tunnel**
     (§6.1b). We do not pretend to understand HTTP/2.
5. Mode A (`connection`) always takes the opaque path regardless of ALPN.

#### 6.1a Intercept path (Mode B)

- Generate/lease a leaf certificate for the SNI (falling back to the CONNECT
  authority), signed by the Tethra CA. 24 h validity, `serverAuth` EKU only,
  SAN = exactly the requested name. Cached, bounded LRU (256), cleared on lock
  and shutdown.
- `rustls` server accept, ALPN advertised = `["http/1.1"]` only.
- `rustls` client connect **upstream** with a verifier built from
  `webpki-roots`. Full chain + hostname verification. There is no code path in
  this crate that constructs a permissive verifier — see
  `tests/no_insecure_verifier.rs`, which greps the crate source for
  `dangerous`, `NoCertificateVerification`, `set_certificate_verifier`,
  `danger_accept_invalid`.
- Then HTTP/1.1 request/response cycles (§7) until close.

#### 6.1b Opaque tunnel path

Bidirectional byte relay. Recorded: host, port, connect outcome, connect
latency, total duration, bytes each way, and `observation_source =
"connection_only"`. **No** status code, method, or path is recorded or
inferred. The session is marked `partial_coverage = 1` with a reason.

### 6.2 Plain HTTP

Absolute-form request line (`GET http://host/path HTTP/1.1`). Same policy
checks, same metadata extraction, no TLS. The `Proxy-Authorization` and
`Proxy-Connection` headers are stripped before forwarding upstream.

## 7. HTTP/1.1 handling

`wire.rs` parses **only heads**, never bodies:

- Request head: ≤ 32 KiB, ≤ 100 headers, ≤ 8 KiB single header line.
- Response head: same bounds.
- Framing determined from `Content-Length` / `Transfer-Encoding: chunked` /
  `Connection: close` / status-implied-empty (1xx, 204, 304, HEAD response).
- Bodies are **relayed**, never parsed and never accumulated. Byte counts come
  from the relay counter, so "request size" and "response size" are measured
  without buffering (§4 of the brief).
- `101 Switching Protocols` (WebSocket): the handshake's metadata is recorded
  (method, sanitized path, status 101), then the connection becomes an opaque
  relay and the event is flagged `protocol = "websocket"` with
  `observation_source = "upgrade_then_opaque"`.
- Compression: `Content-Encoding` is passed through untouched and never
  decoded. Response size is the **wire** size; this is stated in the UI.
- Redirects: each hop is its own event. Tethra does not follow redirects; the
  client does, and we observe each request it makes.

### HTTP/2 — explicit, honest position

Tethra **does not decode HTTP/2** in this release. Concretely:

- On intercepted connections it advertises only `http/1.1` in ALPN. A client
  that supports both (Node `undici`, Python `requests`, `curl`) transparently
  uses HTTP/1.1 for the monitored run. **This is an observable behaviour
  change** for that process and is documented in the compatibility matrix and
  shown in the UI.
- A client that offers only `h2` gets an opaque tunnel and connection-only
  metadata.
- `protocol` on every event records what was actually negotiated, so the UI
  never implies HTTP/2 visibility.

## 8. Metadata extraction and the persistence boundary

The single rule: **no unsanitized string derived from the wire ever reaches a
`store::` function.**

```
wire head  ──►  runtime::sanitize::sanitize_request(...)  ──►  ObservedRequest
                        │                                        (host, method,
                        │                                         path_template,
                        │                                         confidence)
                        └── everything else is DROPPED here,
                            not "kept but hidden"
```

`ObservedRequest` has no field capable of holding a query string, a header
value, a cookie, or a body. The type system is the enforcement mechanism, not
a filter applied later. `store::insert_request_event` accepts only
`ObservedRequest` + numeric/enum measurements.

Sanitization detail is in `RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md` §3.

## 9. Certificate authority

See `RUNTIME_OBSERVABILITY_THREAT_MODEL.md` §T1 for the threat analysis.

- One CA per vault. ECDSA P-256, `getrandom` OS entropy via `ring`.
- `basicConstraints: CA:TRUE, pathlen:0`, `keyUsage: keyCertSign, cRLSign`,
  36-month validity, random 20-byte serial, CN `Tethra Local Observation CA
  (<vault-id-prefix>)`.
- Private key: PKCS#8 DER → `crypto::encrypt` under the **vault key**, AAD
  `api-tracker:v1:observe-ca-key:{vault_id}` → `observe_certificate_state.
  key_ciphertext`. It is never written to disk in plaintext, never leaves the
  process, never crosses the Tauri IPC boundary, and is not included in
  backups' plaintext sections.
- In memory it lives in `SecretBytes` (zeroize-on-drop). The signing key is
  materialised only inside the proxy thread pool and dropped on shutdown.
- The CA **certificate** (public) is written to a `0600` temp file for
  `NODE_EXTRA_CA_CERTS`-style trust and deleted on session end. That file
  contains no private key.
- Leaf keys are generated per hostname, live only in the bounded cache, and
  are zeroized when evicted or on lock/shutdown.

Vault lock during an active run: **not implemented in this version.** There is
no `session::on_lock()` hook. A `run --observe` process holds its own copy of
the vault key and the reconstituted CA signing key in memory and keeps
minting leaves / decrypting the child's TLS until the child exits; only then
are the CA dropped, the leaf cache cleared, and keys zeroized. Locking the vault
from another process does not interrupt that run. A lock/auto-lock hook that
shuts the proxy down and interrupts the session (`reason = vault_locked`) is
required follow-up before public release (see THREAT_MODEL RO-13).

## 10. Scoped trust (Mode B) — no system changes

Environment applied **only to the spawned child**, via
`std::process::Command::env`, never `setenv` in the parent:

| Variable | Runtime | Notes |
|---|---|---|
| `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` | generic | both cases set |
| `NO_PROXY`, `no_proxy` | generic | preserved/merged, `localhost,127.0.0.1,::1` always added |
| `NODE_EXTRA_CA_CERTS` | Node.js | appends our CA to Node's bundle |
| `REQUESTS_CA_BUNDLE` | Python `requests` | |
| `SSL_CERT_FILE` | OpenSSL / Python `ssl` | set to a **concatenation** of the platform bundle + our CA, never our CA alone |
| `CURL_CA_BUNDLE` | curl | |
| `AWS_CA_BUNDLE` | AWS SDKs | same concatenated bundle |
| `GIT_SSL_CAINFO` | git | |

`SSL_CERT_FILE` replacing rather than appending would *shrink* the child's
trust set and break unrelated TLS. `trust.rs` therefore builds a combined
bundle file (platform roots ++ Tethra CA) and points the replace-semantics
variables at that.

**Never set**, and asserted absent by test:
`NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONHTTPSVERIFY`, `CURL_INSECURE`,
`REQUESTS_CA_BUNDLE=""`, `SSL_VERIFY=0`, `GIT_SSL_NO_VERIFY`.

## 11. Existing-proxy compatibility

`trust::inspect_existing_proxy()` reads the parent env before launch:

- No existing proxy → proceed.
- Existing `HTTP(S)_PROXY` → the child's proxy variables are **overridden** to
  point at the local observation proxy; upstream connections go **direct** to
  the providers. Upstream CONNECT chaining is **not implemented** in this
  version, and there is no `--proxy-conflict` flag. A monitored run therefore
  requires direct egress; `observe diagnostics` warns when a proxy variable is
  present.
- The parent shell's environment is never modified, so there is nothing to
  restore.

## 12. Data model

Migration **12**, `runtime api observability`. Full DDL in `crates/core/src/db.rs`.

| Table | Grain | Retention |
|---|---|---|
| `observation_sessions` | one monitored run | with project |
| `observed_api_services` | one host (per vault) | permanent inventory |
| `observed_endpoints` | (service, method, path template) | permanent inventory |
| `runtime_request_events` | one request | **7 days** default |
| `runtime_metric_buckets` | (granularity, bucket, project, service, endpoint?, credential?) | **90 days** default |
| `credential_traffic_attributions` | (session, credential, service) rollup | with session |
| `observation_compatibility_results` | (session, check) | with session |
| `observe_certificate_state` | singleton | until rotated/removed |
| `observe_internal_allowlist` | (project, host, port) | user-managed |

Retention defaults are justified in `IMPLEMENTATION_PLAN.md` §7 and are
configurable in Settings.

### Encryption-at-rest position (explicit)

Runtime observability rows are stored in the **same vault database**, under the
**same at-rest protections** as every other operational table in this product:
`0700` data directory, `0600` database + WAL + SHM, `secure_delete=ON`, WAL
truncation on lock.

They are **not** additionally column-encrypted, and that is a deliberate
decision, recorded in `docs/decisions/0018-runtime-observability-storage.md`:

- The product's existing encryption model encrypts **credential material**
  (values, version history, provider admin keys, destination auth, webhook
  URLs). It does not encrypt operational metadata — `process_sessions.command`,
  `usage_snapshots.provider`, `activity_events.detail`, `project_repos.path`
  and `env_exports.path` are all plaintext columns today and reveal
  comparable information about what a developer runs and calls.
- Column-encrypting `host` and `path_template` would defeat `GROUP BY`,
  making every dashboard a full-table decrypt, while leaving equivalent
  information legible in the adjacent tables. That is a real performance and
  complexity cost for no real adversary reduction.
- **No secret material is stored by this feature at all**, so there is nothing
  here for column encryption to protect.

If whole-database encryption (SQLCipher) is adopted later it covers these
tables automatically, which is the correct place to solve this.

## 13. Attribution

Attribution never inspects an `Authorization` header. It is derived only from
state Tethra already owns:

| Evidence | Result |
|---|---|
| Exactly one credential of the matching provider was injected by Tethra into this session | **Confirmed** |
| One matching credential injected, host→provider mapping is inferred rather than manifest-declared | **High** |
| No injection match, but exactly one project credential has that provider | **Possible** |
| Several credentials could explain it | **Ambiguous** (all candidates listed, none chosen) |
| Unknown host, no provider mapping | **Unattributed** |

`credential_version` is the credential's `value_version` **captured at process
launch**, which is what makes "old credential still in use after rotation"
provable rather than guessed.

## 14. Aggregation

`aggregate::roll_up(conn, through)` is idempotent:

1. Read the watermark from `vault_meta` (`runtime_aggregate_watermark`).
2. Recompute every **complete** hour bucket from `watermark - 1h` through
   `through`, so an interrupted run always redoes the last partial hour.
3. `INSERT … ON CONFLICT(granularity, bucket_start, project_id, service_id,
   endpoint_id, credential_id) DO UPDATE` — full replacement, never increment.
   Running it twice produces identical rows.
4. Advance the watermark in the same transaction.

Latency uses a **fixed 14-boundary histogram** (1, 2, 5, 10, 25, 50, 100, 250,
500, 1000, 2500, 5000, 10000, +inf ms) stored as 14 integer counters per
bucket. p50/p95/p99 are linearly interpolated within the containing bucket.
Memory is O(buckets), never O(samples). Quantiles are labelled *approximate*
in the UI because they are.

## 15. Alerting

Alert rules live in `runtime::alerts` and produce `alerts::NewAlert` values fed
through the **existing** `alerts::upsert` / `auto_resolve_stale` engine — the
same dedup, lifecycle, notification-channel delivery and UI as every other
alert. Eleven new `AlertKind` variants. Rules, thresholds, warm-up and minimum
sample sizes are tabulated in `IMPLEMENTATION_PLAN.md` §8.

## 16. Failure semantics

| Event | Behaviour |
|---|---|
| Child exits | session `completed`, aggregates flushed, token invalidated, temp files removed, CA key zeroized |
| Child crashes | identical — exit code recorded |
| Proxy thread panics | connection dropped; listener survives; a `proxy_internal_error` compatibility result is recorded; the session is marked `partial_coverage` |
| Listener dies | session marked `interrupted`, child keeps running (it loses connectivity through the proxy and will error honestly rather than silently bypassing) |
| Vault locks | §9 |
| App quits | `Drop` on the session stops the listener, joins threads with a 2 s deadline, zeroizes, marks `interrupted` |
| Token reused after shutdown | listener is closed; there is nothing to authenticate against |

Sessions are never silently marked `completed`. `interrupted` is a distinct
state shown in the UI with its reason.
