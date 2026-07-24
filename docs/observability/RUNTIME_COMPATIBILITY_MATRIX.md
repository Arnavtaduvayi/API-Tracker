# Runtime API Observability — Compatibility Matrix

Honest capability reporting per the product's "never claim support you can't
prove" rule. Status is what the **first version** on
`feat/runtime-api-observability` genuinely does.

**Test honesty:** only tests that actually exist in the repository are cited.
The automated suite for this crate is `crates/observe/tests/proxy_integration.rs`
and `crates/observe/tests/no_insecure_verifier.rs`, plus in-module unit tests
(`trust.rs`, `wire.rs`, `policy.rs`, `clienthello.rs`, `relay.rs`, `ca.rs`,
`tls.rs`) and the core `runtime::*` unit tests (`sanitize.rs`, `aggregate.rs`,
`alerts.rs`, `attribution.rs`, `store.rs`). Anything not covered by one of those
is marked **🧪 implemented, not automated-tested** and was checked by manual
run / code inspection — it is NOT claimed as verified.

Legend: ✅ works & automated-tested · 🧪 implemented, manual/inspection only ·
🟡 works, partial/known caveat · ⛔ not covered (honestly reported, never
silently) · N/A not applicable.

---

## 1. Observation modes

| | Mode A `connection` | Mode B `metadata` (default) | Mode C system-trust |
|---|---|---|---|
| Decrypts HTTPS | No | Yes, for the launched child only | Yes (widens *which* clients trust the CA) |
| Custom CA trust | None | Scoped env vars, child only | OS trust store (opt-in, reauth + OS prompt) |
| Records host/port/bytes/latency | ✅ | ✅ | ✅ |
| Records method/path/status | ⛔ (honestly null) | ✅ | ✅ |
| System changes | None | None | One OS-trust entry, reversible |
| Default | fallback | **on when `--observe` given** | **off**, never automatic |

Mode C is not a run mode — it is a one-time trust decision that makes Mode B
work for runtimes that ignore scoped env vars. A monitored run is always
Mode A or Mode B.

## 2. Runtime × scoped trust (Mode B)

"Trust var honoured" = the runtime reads the environment variable we set and
therefore accepts the Tethra CA for the monitored process without any system
change. Detection is by argv0 / interpreter inspection in `trust.rs`.

Runtime DETECTION (name → runtime/trust level) is unit-tested
(`trust.rs::detects_common_runtimes`). The actual per-language INTERCEPTION was
verified by manual run and is not yet an automated integration test.

| Runtime | Proxy var | CA trust var | Status | Reported as |
|---|---|---|---|---|
| Node.js (https, undici, axios, node-fetch) | `HTTPS_PROXY` | `NODE_EXTRA_CA_CERTS` | 🧪 | FullySupported |
| Python `requests` | `HTTPS_PROXY` | `REQUESTS_CA_BUNDLE` | 🧪 | FullySupported |
| Python `httpx`/`aiohttp`/stdlib `ssl` | `HTTPS_PROXY` | `SSL_CERT_FILE` | 🟡 | ProbablySupported |
| curl | `HTTPS_PROXY` | `CURL_CA_BUNDLE` | 🧪 | FullySupported |
| OpenSSL CLI / generic libcrypto | `HTTPS_PROXY` | `SSL_CERT_FILE` | 🟡 | ProbablySupported |
| AWS SDKs (JS/Python/CLI) | `HTTPS_PROXY` | `AWS_CA_BUNDLE` (+ lang bundle) | 🟡 | ProbablySupported |
| git (https remotes) | `HTTPS_PROXY` | `GIT_SSL_CAINFO` | 🟡 | ProbablySupported |
| Ruby (net/http, `SSL_CERT_FILE`) | `HTTPS_PROXY` | `SSL_CERT_FILE` | 🟡 | ProbablySupported |
| PHP (curl ext) | `HTTPS_PROXY` | `CURL_CA_BUNDLE` | 🟡 | ProbablySupported |
| Go (`net/http`) | `HTTPS_PROXY` | **none honoured** on macOS/Windows¹ | 🟡 | ConnectionOnlyFallback |
| Java / JVM | `HTTPS_PROXY`² | own `cacerts` keystore | ⛔ | Unsupported (Mode B) → Mode C |
| .NET | `HTTPS_PROXY` | OS store | ⛔ | Unsupported (Mode B) → Mode C |
| Rust `reqwest` (rustls) | `HTTPS_PROXY` | `SSL_CERT_FILE`³ | 🟡 | ProbablySupported |
| Rust `reqwest` (native-tls) | `HTTPS_PROXY` | OS store | ⛔ | Unsupported (Mode B) → Mode C |
| Browsers (Chrome/Firefox/Safari) | N/A | own store | ⛔ | out of scope (§20 no-browser) |

¹ Go reads `SSL_CERT_FILE` on Linux but not on macOS/Windows. On a detected Go
runtime in metadata mode we now **downgrade the run to connection-only
observation** (opaque tunnels) rather than let interception fail, and flag the
session partial with reason `runtime_connection_only`
(`session.rs::run_monitored`). ² Java needs `-Dhttps.proxyHost`, not the env
var. ³ rustls-based clients honour `SSL_CERT_FILE` only if they build roots
from it; many pin `webpki-roots` and ignore it.

**The rule (implemented):** when the detected runtime cannot be given scoped
trust — `ConnectionOnlyFallback` (Go) or `Unsupported` (Java/.NET) — in metadata
mode, `run_monitored` marks the session `partial_coverage` with a machine-
readable reason (`runtime_connection_only` / `runtime_unsupported`) and records
a compat note. Client-side handshake failures inside the tunnel are not yet
individually recorded (see §Known gaps).

## 3. Protocol × support

| Protocol | Behaviour | Status | Test (if automated) |
|---|---|---|---|
| Plain HTTP/1.0, HTTP/1.1 | full metadata; headers forwarded verbatim | ✅ | `proxy_integration.rs::plain_http_round_trips_body_and_records_origin_path` |
| HTTPS via CONNECT | full metadata (Mode B), payload-free | ✅ | `proxy_integration.rs::intercept_captures_sanitized_metadata_and_leaks_no_payload` |
| Chunked transfer | framed, relayed, sizes measured | ✅ | `relay.rs` unit tests |
| Streaming response (long-lived) | relayed with backpressure, sizes measured | 🧪 | — |
| Large streaming body | streamed, never buffered | 🧪 | — |
| Redirects (3xx) | each hop is its own event; we don't follow | 🧪 | — |
| Compression (gzip/br/zstd) | passed through, **not decoded**; size is wire size | 🧪 | — |
| Server-Sent Events | request + 200 recorded, body relayed opaque | 🧪 | — |
| WebSocket (`Upgrade`) | 101 recorded, then real bidirectional opaque relay; flagged partial (`websocket_opaque`) | 🧪 | — |
| gRPC (HTTP/2 only) | opaque tunnel, connection-only metadata | 🧪 | — |
| HTTP/2 (general) | **not decoded**; ALPN advertises http/1.1 so most clients downgrade for the monitored run; h2-only clients get opaque tunnel | 🟡 | `tls.rs::server_config_advertises_only_http11`, `clienthello.rs` |
| HTTP/3 / QUIC | **UDP — bypasses the proxy entirely**; documented limitation, NOT auto-detected (see §Known gaps) | ⛔ | — |

**Honesty invariant (tested):** a transport/TLS failure is never counted as an
HTTP error class, and a bare TCP/tunnel success is never reported as a
successful HTTP request —
`aggregate.rs::metrics_separate_classes_and_never_conflate`.

## 4. HTTP/2 decision (why we downgrade instead of decoding)

Correctly decoding HTTP/2 requires HPACK state, stream multiplexing, flow
control, and CONTINUATION handling — a large, security-sensitive surface. A
half-correct h2 decoder is worse than none: it would mis-frame and could
mis-attribute. So Mode B advertises only `http/1.1` in the intercepted
connection's ALPN. Every mainstream client that offers h2 also offers http/1.1
and transparently uses it for the monitored process. This is an **observable
behaviour change for that process only**, documented in the UI and here. A
client that offers *only* h2 gets an opaque tunnel and connection-only
metadata, flagged partial (`h2_only_client`).

## 5. OS trust store (Mode C)

Mode C is **implemented on macOS only** in this version. Linux and Windows
return a documented error from `systemtrust::install`/`remove` and are NOT
automated; there is no bundled certutil/certstore flow yet.

| OS | Install mechanism | Automated? | Status |
|---|---|---|---|
| macOS | `security add-trusted-cert` (login keychain), native OS prompt | Yes (`systemtrust.rs`) | 🟡 opt-in, isolated |
| Linux | manual (`certutil`/`update-ca-certificates`) | No | ⛔ not automated (documented) |
| Windows | manual (`certutil -addstore -user Root`) | No | ⛔ not automated (documented) |

Mode B never touches the system store (it only sets child-scoped env vars);
`systemtrust::install` is called exclusively from the explicit, reauthenticated
`observe cert install` path.

## 6. Environment / machine compatibility

| Situation | Behaviour |
|---|---|
| Existing `HTTP(S)_PROXY` (corporate) | the child's proxy vars are OVERRIDDEN to the local observation proxy; upstream connections go **direct** (no chaining), so a monitored run needs direct egress. `observe diagnostics` warns when a proxy var is present. Parent env never modified. |
| `NO_PROXY` / `no_proxy` set | both casings preserved and merged; `localhost,127.0.0.1,::1` always added |
| Managed / MDM machine | Mode C typically blocked by policy; failure reported plainly, never escalated |
| Multi-user machine | loopback-only listener; token in child env readable only by same user |
| Certificate-pinned client | the client rejects the minted leaf and its HTTPS calls fail; this is NOT yet auto-detected/flagged as "pinning suspected" (see §Known gaps). Use Mode A (`--observe=connection`) for pinned clients. |
| Internal / localhost API | blocked by default; explicit per-project allowlist with warning |

## Known gaps (documented, not detected)

These are real limitations of the first version. They are described honestly
here rather than claimed as automatic detections:

- **Certificate pinning** is not auto-detected. A pinned client's requests fail;
  the session simply shows no successful requests for that host.
- **QUIC / HTTP/3** bypasses the proxy over UDP. There is no
  connections-without-requests heuristic yet; a session that shows connections
  but no requests may indicate QUIC or a bypass.
- **Client-side handshake failures** inside a CONNECT tunnel (a runtime that
  rejects the minted leaf) currently end the connection without an individual
  `tls_error` event. Partial coverage IS flagged for detected
  ConnectionOnlyFallback/Unsupported runtimes, but not derived per-connection.
- **Corporate upstream-proxy chaining** is not implemented; monitored children
  require direct egress.

## 7. Overall first-version classification

Honestly usable **today** for the common developer case: Node /
Python-requests / curl calling public HTTPS APIs over HTTP/1.1. It is explicit
and partial-flagged for detected unsupported runtimes. Public distribution
stays blocked pending the automated integration coverage this matrix is careful
NOT to claim already exists. See `IMPLEMENTATION_PLAN.md` §10 for the release
classification and remaining blockers.
