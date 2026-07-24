# Runtime API Observability — Compatibility Matrix

Honest capability reporting per the product's "never claim support you can't
prove" rule. Status is what the **first version** on
`feat/runtime-api-observability` genuinely does, verified by the named tests.

Legend: ✅ works & tested · 🟡 works, partial/known caveat · ⛔ not covered
(honestly reported, never silently) · N/A not applicable.

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

| Runtime | Proxy var | CA trust var | Status | Reported as | Test |
|---|---|---|---|---|---|
| Node.js (https, undici, axios, node-fetch) | `HTTPS_PROXY` | `NODE_EXTRA_CA_CERTS` | ✅ | FullySupported | `trust_node.rs` |
| Python `requests` | `HTTPS_PROXY` | `REQUESTS_CA_BUNDLE` | ✅ | FullySupported | `trust_python_requests.rs` |
| Python `httpx`/`aiohttp`/stdlib `ssl` | `HTTPS_PROXY` | `SSL_CERT_FILE` | 🟡 | ProbablySupported | `trust_python_ssl.rs` |
| curl | `HTTPS_PROXY` | `CURL_CA_BUNDLE` | ✅ | FullySupported | `trust_curl.rs` |
| OpenSSL CLI / generic libcrypto | `HTTPS_PROXY` | `SSL_CERT_FILE` | 🟡 | ProbablySupported | `trust_openssl.rs` |
| AWS SDKs (JS/Python/CLI) | `HTTPS_PROXY` | `AWS_CA_BUNDLE` (+ lang bundle) | 🟡 | ProbablySupported | manual |
| git (https remotes) | `HTTPS_PROXY` | `GIT_SSL_CAINFO` | 🟡 | ProbablySupported | manual |
| Ruby (net/http, `SSL_CERT_FILE`) | `HTTPS_PROXY` | `SSL_CERT_FILE` | 🟡 | ProbablySupported | — |
| PHP (curl ext) | `HTTPS_PROXY` | `CURL_CA_BUNDLE` | 🟡 | ProbablySupported | — |
| Go (`net/http`) | `HTTPS_PROXY` | **none honoured** on macOS/Windows¹ | ⛔ | ConnectionOnlyFallback | `trust_go.rs` (asserts fallback) |
| Java / JVM | `HTTPS_PROXY`² | own `cacerts` keystore | ⛔ | Unsupported (Mode B) → Mode C | documented |
| .NET | `HTTPS_PROXY` | OS store | ⛔ | Unsupported (Mode B) → Mode C | documented |
| Rust `reqwest` (rustls) | `HTTPS_PROXY` | `SSL_CERT_FILE`³ | 🟡 | ProbablySupported | — |
| Rust `reqwest` (native-tls) | `HTTPS_PROXY` | OS store | ⛔ | Unsupported (Mode B) → Mode C | documented |
| Browsers (Chrome/Firefox/Safari) | N/A | own store | ⛔ | out of scope (§20 no-browser) | — |

¹ Go reads `SSL_CERT_FILE` on Linux but not on macOS/Windows; on those we
report ConnectionOnlyFallback rather than pretend. ² Java needs
`-Dhttps.proxyHost`, not the env var. ³ rustls-based clients honour
`SSL_CERT_FILE` only if they build roots from it; many pin `webpki-roots` and
ignore it → detected as failing and reported.

**The rule:** when the runtime cannot be given scoped trust, the session is
recorded `partial_coverage` with the reason, and the UI shows a **partial
coverage** badge. We never silently show a green dashboard for a runtime whose
requests bypassed decryption.

## 3. Protocol × support

| Protocol | Behaviour | Status | Test |
|---|---|---|---|
| Plain HTTP/1.0, HTTP/1.1 | full metadata | ✅ | `proxy_http1.rs` |
| HTTPS via CONNECT | full metadata (Mode B) | ✅ | `proxy_connect.rs` |
| Chunked transfer | framed, relayed, sizes measured | ✅ | `proxy_chunked.rs` |
| Streaming response (long-lived) | relayed with backpressure, sizes measured | ✅ | `proxy_streaming.rs` |
| Large streaming body | streamed, never buffered | ✅ | `proxy_large_body.rs` |
| Redirects (3xx) | each hop is its own event; we don't follow | ✅ | `proxy_redirect.rs` |
| Compression (gzip/br/zstd) | passed through, **not decoded**; size is wire size | 🟡 | `proxy_compressed.rs` |
| Server-Sent Events | request + 200 recorded, body relayed opaque | 🟡 | `proxy_sse.rs` |
| WebSocket (`Upgrade`) | handshake recorded (101), then opaque relay | 🟡 | `proxy_websocket.rs` |
| gRPC (HTTP/2 only) | opaque tunnel, connection-only metadata | 🟡 | `proxy_h2_opaque.rs` |
| HTTP/2 (general) | **not decoded**; ALPN advertises http/1.1 so most clients downgrade for the monitored run; h2-only clients get opaque tunnel | 🟡 | `proxy_alpn.rs` |
| HTTP/3 / QUIC | **UDP — bypasses the proxy entirely**; detected & reported, never blocked or hidden | ⛔ | `diagnostics_quic.rs` |

**Two honesty invariants (tested):**
- A transport failure is **never** counted as an HTTP error rate
  (`metrics.rs::transport_never_counts_as_http_error`).
- A successful TCP connection is **never** reported as a successful request
  (`metrics.rs::tcp_success_is_not_request_success`).

## 4. HTTP/2 decision (why we downgrade instead of decoding)

Correctly decoding HTTP/2 requires HPACK state, stream multiplexing, flow
control, and CONTINUATION handling — a large, security-sensitive surface. A
half-correct h2 decoder is worse than none: it would mis-frame and could
mis-attribute. So Mode B advertises only `http/1.1` in the intercepted
connection's ALPN. Every mainstream client that offers h2 also offers http/1.1
and transparently uses it for the monitored process. This is an **observable
behaviour change for that process only**, documented in the UI and here. A
client that offers *only* h2 gets an opaque tunnel and connection-only
metadata, flagged partial. Adding true h2 decoding is the top item in the
"adding protocol support" developer guide.

## 5. OS trust store (Mode C)

| OS | Install mechanism | User store (no admin)? | OS prompt | Status | Test |
|---|---|---|---|---|---|
| macOS | `security add-trusted-cert` (login keychain) | Yes | Yes (native) | 🟡 opt-in, isolated | `systemtrust_macos.rs` (`#[ignore]`) |
| Linux (NSS: Chrome/Firefox profile) | `certutil -d sql:~/.pki/nssdb -A` | Yes | policy-dependent | 🟡 | `systemtrust_linux.rs` (`#[ignore]`) |
| Linux (system CA dir) | copy to `/usr/local/share/ca-certificates` + `update-ca-certificates` | No (needs root) | sudo | ⛔ not automated | documented |
| Windows | `certutil -addstore -user Root` | Yes (CurrentUser) | Yes (native) | 🟡 | `systemtrust_windows.rs` (`#[ignore]`) |

Mode C tests are `#[ignore]` by default and run only under
`TETHRA_TEST_SYSTEM_TRUST=1` in an isolated environment — CI never touches the
real trust store. Scoped Mode B is proven to **not** touch the system store by
`systemtrust_macos.rs::mode_b_never_installs`.

## 6. Environment / machine compatibility

| Situation | Behaviour |
|---|---|
| Existing `HTTP(S)_PROXY` (corporate) | chained upstream if reachable; else explicit error; per-child override available. Parent env never modified. |
| `NO_PROXY` set | preserved and merged; `localhost,127.0.0.1,::1` always added |
| Managed / MDM machine | Mode C typically blocked by policy; failure reported plainly, never escalated |
| Multi-user machine | loopback-only listener; token in child env readable only by same user |
| Certificate-pinned client | handshake fails; detected as `pinning_suspected`; UI recommends Mode A, never "disable pinning" |
| Internal / localhost API | blocked by default; explicit per-project allowlist with warning |

## 7. Overall first-version classification

The feature is honestly usable **today** for the common developer case:
Node / Python-requests / curl calling public HTTPS APIs over HTTP/1.1, which
is the majority of "what API is my dev server calling" questions. It is
explicit and partial-flagged everywhere else. See
`IMPLEMENTATION_PLAN.md` §10 for the release classification and remaining
blockers.
