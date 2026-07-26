# Local Gateway — Architecture

How the gateway is built. Authority for guarantees is `SECURITY_INVARIANTS.md`
and `PRIVACY_MODEL.md`; authority for "why this and not that" is ADR 0019.
This document is descriptive of the intended production shape; the
architecture phase validated it with the spike in `experiments/gateway-spike`
(9 passing tests) but did NOT build the production crate.

## Placement in the workspace

A new crate `crates/gateway` (package `api-tracker-gateway`), peer to
`crates/observe`. It depends on `api-tracker-core` (store, types,
SecretString, db, runtime funnel, providers, envfile/envgov) and on
`api-tracker-observe` for the already-audited wire/relay/policy/upstream-TLS
primitives. Core depends on neither. The crate carries its own
`#![forbid(unsafe_code)]` and its own review boundary, exactly as observe does
for the "opens listening sockets / handles trust material" surface.

The service is a small binary `tethra-gateway` (a `[[bin]]`); the CLI verb
family `tethra gateway ...` lives in `apps/cli`; desktop panels live in
`apps/desktop`. All request/route/attribution/usage logic lives in the crate
(shared by CLI and desktop), never in the frontends.

## Reused, unchanged

- `observe::wire` — bounded httparse head parsing, `BodyFraming`, Slowloris
  deadline read, secret-redacting `Debug`. The gateway adds head-rewrite and
  stricter framing validation on top; it does not fork wire.
- `observe::relay` — streaming, backpressured body relay
  (Content-Length/chunked/until-close) with carryover. This is the exact
  primitive path-prefix forwarding and SSE need; the spike used it verbatim.
- `observe::policy` — SSRF/private-range/metadata denial for route origins
  and connect-time IP checks.
- `observe::tls` (upstream side) — rustls client, webpki-roots, ALPN
  http/1.1. NOT the server-side/CA modules (`ca`, `clienthello`, `trust`,
  `systemtrust`) — the gateway terminates no TLS toward clients.
- `core::runtime::sanitize`, the `ObservedRequest` funnel
  (`upsert_service`/`upsert_endpoint`/`insert_request_event`, which already
  takes an explicit `at` timestamp), `aggregate`, `retention`,
  `store::sweep_orphaned_sessions`.
- `core::reuse::fingerprint`, `core::secret`, `core::crypto::aad` (for any
  new vault-wrapped state), `core::envfile`/`envgov`.

## Request lifecycle

```
client (plain HTTP/1.1, loopback)
  → accept (cap-gated; 503 over cap; reject non-loopback peer)
  → read + validate request head (bounded; Host exact-match gate;
     framing validation: reject TE+CL, dup/≠1*DIGIT CL, non-final TE,
     bare CR/LF; reject browser writes via Sec-Fetch-*/Origin/Referer)
  → match first path segment → route (in-memory table)
     · no match → 404 (identical for unknown prefix and unknown slug), close
  → rebuild head from PARSED fields (canonical CRLF): strip /{route} or
     /p/{slug}/{route}; drop request hop-by-hop; strip Cookie; rewrite Host;
     regenerate framing headers from the validated value
  → resolve upstream origin (manifest lookup, or MAC-verified custom origin)
  → dial (or reuse per-(connection,route)) upstream TLS to the validated
     SocketAddr — AFTER head parse, never at accept; two-phase SSRF
  → [Expect: 100-continue? read interim (seedable reader), relay, then body]
  → relay request body (streaming, bounded)
  → read response head (seedable, carryover threaded); relay 1xx interims;
     sanitize response head (strip response hop-by-hop, Set-Cookie,
     Access-Control-*; regenerate Connection); then to client
  → relay response body (streaming) THROUGH a bounded usage tap
  → enqueue ObservedRequest + auth digest via try_send (never blocks)
  → [writer thread] persist; resolve fingerprint match; rollup
  → connection-terminal? (UntilClose / truncation / mid-chunk EOF / upstream
     close) → force Connection: close, close both. else keep-alive: loop
```

Concurrency is thread-per-connection with a hard cap (128), matching observe.
Routing is PER REQUEST (first path segment), so the upstream connection is
keyed by (client connection, resolved route) and dialed only after the head is
parsed — a kept-alive client that switches providers gets a separate upstream
socket, so a credential for provider B is never written into provider A's TLS
session. Client and upstream connection lifetimes are decoupled: an upstream
close never tears down a kept-alive client. Three timeout budgets apply (client
head deadline; client body idle; long upstream response idle, reset per byte),
not observe's single 90 s.

## Route table and configuration

New v13 append-only migration adds plaintext (non-secret) tables in the
shared vault.db:

- `gateway_config` — singleton: enabled, port (random persisted, not fixed),
  bind, matching-key toggle (default OFF), enabled service version,
  retention overrides.
- `gateway_routes` — (route_prefix, provider_id, custom_origin_mac?,
  enabled). **The upstream origin is NOT stored here** — manifest routes
  resolve it from the on-disk manifest; custom origins store a MAC over
  `(vault_id, provider_id, origin, port, consent_ts)` verified before use.
- `gateway_project_links` — (link_slug≥128-bit CSPRNG, project_id,
  route_prefix, prior env value + no_proxy state for restore).
- `gateway_usage_events` — extracted usage (model, token counts,
  usage_available, estimated_cost_micros); raw, 7-day. NEVER `usage_snapshots`.
- `gateway_usage_daily` — ~90-day usage rollup (raw events expire sooner).
- `gateway_route_counters` — route-level counters for unlinked traffic and a
  `rejected_browser_origin` counter.

The running service holds an in-memory, validated route table and detects
changes by polling SQLite `PRAGMA data_version` (cheap, no vault). Route/config
WRITES require an unlocked vault + re-auth via the CLI/desktop and are audited;
the service only READS. Because origins are never obeyed from the DB (manifest
lookup or MAC-verified), a same-user `UPDATE gateway_routes` cannot redirect a
live pass-through credential. Every upstream connection runs the observe
two-phase SSRF check (`check_authority` at load AND `resolve_validated` at
connect — resolve once, filter each resolved address, dial the validated
`SocketAddr`, never re-resolve). Custom-origin routes whose MAC cannot be
verified (vault locked since boot) return 503; manifest routes keep forwarding.
Every DB touch uses `db::open_at_current_version` (open + assert
`user_version == current_schema_version`) — plain `db::open` does NOT check the
schema; on busy / missing / `SchemaTooNew` the service keeps forwarding on the
last-known-good table and flags recording degraded. Migration v13 is applied
only by the enable/unlock flow, never by the background service.

## Control channel (fingerprint-key handoff)

Separate from the forwarding listener: a Unix-domain socket at
`<data-dir>/gateway.sock` (0600 inside the 0700 dir) with a peer-euid check
(`SO_PEERCRED`/`LOCAL_PEERCRED` == our uid), write-only (key push + revoke, no
read-back), with a gateway-written nonce the pusher echoes so the pusher also
authenticates the server. The fingerprint key NEVER crosses the TCP listener,
argv, or an environment variable (source-grep guarded). Windows uses a
per-user-DACL named pipe or refuses key push in v1 (attribution unavailable,
labeled). Each push is reauth-gated and audited.

## Observation writer

One dedicated writer thread, bounded `sync_channel`. Unlike observe's blocking
sink, the gateway sink uses `try_send` and DROPS-with-counter on a full queue
— because "forwarding must continue when persistence fails" is immutable and
must beat "capture every event". Dropped counts surface partial-coverage
style. The writer opens short-lived connections through `db::open`
(schema-checked) per flush so it does not hold vault.db open across the
desktop's `wal_checkpoint(TRUNCATE)` on lock. Because a monitored run may
never happen, the writer also drives `aggregate::roll_up` and
`retention::sweep` on a timer.

## Sessions and attribution

One `observation_sessions` row per (service boot × linked project), source
`gateway` (new `ObservationSource::Gateway` variant; `from_db` call sites
audited — the enum has zero external call sites today so the additive variant
is safe), pid recorded so a crash is closed honestly. The writer calls
`sweep_orphaned_sessions` at boot. Events flow through the funnel with the
captured `at` timestamp; after each flush the writer re-rolls the batch's hour
range (`reroll_hours`) so the shared roll-up watermark cannot permanently
exclude a late-flushed event. Attribution uses the scoped, matching-only
fingerprint key (PRIVACY_MODEL §4): the digest is computed on the forwarding
path and the table lookup (`subtle::ConstantTimeEq`) runs on the writer thread,
so no forwarding-path timing depends on a match. A new `attribution_method`
column separates value-derived (`observed_fingerprint`) from injection-derived
(`injected`) rows. Non-attributable requests increment `gateway_route_counters`
only.

## Usage extraction

A `TeeWriter` on the response relay feeds a bounded, provider-scoped extractor
(SSE incremental parser; JSON tail-window) emitting only allowlisted
numeric/enum fields — model string (128-byte-capped, charset-filtered) and
token counts. No full-body accumulation exists. Per-provider accumulation
(never overwrite a populated field with null): OpenAI streaming yields usage
only with `stream_options.include_usage` (not injected; absent → `usage_available
=false`, surfaced, never a fabricated 0); Anthropic sums `message_start`
input + cache_read + cache_creation and takes `message_delta` output. gzip
defeats a tail scan, so with extraction on the request `Accept-Encoding` is set
to `identity` (documented wire change) or compressed responses are counted
`unsupported_shape`; the relay never decompresses. Extraction failure never
touches the relay.

## Service lifecycle

Per-user, consent-first. `enable` installs the binary into
`<data-dir>/bin/tethra-gateway-<version>` by a FRESH byte-write (not
`fs::copy`, which propagates `com.apple.quarantine`) + `xattr -d` + an exec
probe before registering; on a Gatekeeper kill it fails honestly to foreground
mode. The service argv carries `--data-dir <resolved-at-enable-time>` (service
managers inherit no shell env, so `TETHRA_DIR` would otherwise drift the
vault). It never exits on bind failure (retries with backoff, reports degraded
via status) — KeepAlive respawn of a fast-exiting process is a crash loop
(macOS) or a permanent fail (systemd rate limit). macOS: LaunchAgent
`KeepAlive={Crashed:true}`, `bootout`/`kickstart`, never `disable`. Linux:
systemd user unit, honest linger reporting. Windows: foreground
`tethra gateway run` only in v1 (`enable` says "not yet supported"). Upgrade: a
version handshake re-copies + rewrites the service + kickstarts + prunes old
copies. Disable/uninstall is one ordered action: stop → remove service
artifacts → **restore every linked `.env`** → delete `<data-dir>/bin` + logs →
keep DB rows. `status` reports whether the OS will actually run it. See ADR
0019 D8, IMPLEMENTATION_PLAN §6, and KNOWN_CONFLICTS C12/C13.

## Data directory

Resolved via the existing `VaultPaths` (`TETHRA_DIR`/`API_TRACKER_DIR` else
platform default) — importantly WITHOUT depending on shell environment, since
launchd/systemd/Task Scheduler do not inherit a shell. The service resolves
the data dir from the same core logic the app uses.

## Dependencies

Target: ZERO net-new third-party crates. Everything needed (rustls +
ring/webpki-roots, httparse, socket2, rusqlite bundled, base64, time, serde,
zeroize, blake3 via core) is already in the workspace lockfile through core
and observe. If any platform service-registration helper is unavoidable it
must be justified in ADR 0019 against the "no unnecessary dependency growth"
rule; the current design uses only `std::process`/plist/unit-file text
generation and needs none.
```
