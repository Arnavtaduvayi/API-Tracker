# Runtime API Observability (User Guide)

Runtime API observability lets you watch **what your application actually
does on the network while it runs** — which APIs it calls, how often, how
fast, with what outcomes — without ever recording what it sends or receives.

It is a **local, metadata-only HTTPS observation proxy**. It runs entirely on
your machine, observes only the process you explicitly launch, and stores
nothing but sanitized metadata. There is no cloud component, no telemetry,
and no capability — anywhere in the design — to record request or response
bodies, headers, query strings, or credential values.

---

## Quickstart

From the CLI, launch your program through the observer:

```sh
api-tracker run --observe=metadata -- npm run dev
```

- `--observe=metadata` (Mode B) is the default when `--observe` is given; you
  can also use `--observe=connection` (Mode A) or `--observe=off`.
- Everything after `--` runs as your child process, with observation scoped
  to it and its descendants only.
- When the process exits, the session is finalized automatically: the
  temporary trust files are removed, the proxy shuts down, and nothing about
  your system is left changed.

In the desktop app, open the **API activity** screen in the navigation to see
recorded observation: services, endpoints, error rates, latency, credential
attribution, and per-session coverage status. (The view fetches on open/tab
switch; it does not auto-refresh live during a run — reopen it to see new data.)

Certificate and session management is under the `observe` CLI verb (for
example `observe cert status`, `observe cert rotate`, `observe cert remove`,
`observe cert install`, `observe cert uninstall`). Data deletion is
`observe delete-session`, `observe delete-project`, and `observe delete-all`.

---

## What runtime observation does

Provider dashboards tell you what your *account* did, usually a day late and
only for providers that report usage at all. Runtime observation answers a
different question from a different evidence source: a local, per-process
proxy that sees your application's outbound HTTP(S) traffic **as it
happens**.

Questions it answers:

- What APIs is my dev server actually calling right now?
- Why did my deploy start throwing 401s an hour ago?
- Is that endpoint slower this week than last week?
- Am I still sending traffic with a credential I rotated yesterday?
- Is a production credential being used from a development project?
- Which third-party hosts does this dependency talk to that I did not know
  about?
- Am I getting rate-limited, and by which service?

Locally observed numbers and provider-reported numbers are **never merged**.
They come from different evidence sources with different meanings, and the UI
labels them separately.

## What it can see vs. what it never stores

| Sees (and stores, sanitized) | Never stores (and cannot, by construction) |
|---|---|
| Hostname and port of each API call | Request bodies |
| HTTP method (GET, POST, …) | Response bodies |
| **Templated** path — identifiers replaced (`/v1/users/:id`) | Raw paths, raw full URLs |
| Status code and outcome class (success / auth error / rate limited / …) | Query strings and URL fragments |
| Latency, request/response **byte counts** (wire size) | Header values of any kind |
| Content-Type **category** only (json, form, multipart, …) | Authorization values, cookies, session tokens |
| Whether an `Authorization` header was **present** (a boolean) | API keys, raw credentials |
| Negotiated protocol (HTTP/1.1, opaque h2 tunnel, WebSocket upgrade, …) | AI prompts and responses, GraphQL documents |
| Timing, session, project, and credential-attribution metadata | Form data, multipart uploads, uploaded files, source code |
| Transport/TLS failure classification | TLS private keys (the local CA key exists only as vault-encrypted ciphertext) |

This is not a filter applied at display time. The internal type that reaches
storage **has no field capable of holding** a body, a header value, a cookie,
a query string, or a full URL. Query strings are severed before any value is
even constructed. Path identifiers (UUIDs, numeric IDs, emails, tokens, hex
blobs, high-entropy strings) are replaced with placeholders like `:id`,
`:uuid`, `:email`, `:token` before persistence. Property tests and an
end-to-end "canary" test enforce this on every build: the canary drives a
real monitored HTTPS request whose path/query/headers/body carry distinctive
fake secrets and asserts every one is absent from the observed metadata the
proxy emits (the in-memory `ObservedRequest` values collected by a test sink,
which are the *only* thing that reaches the database) while proving the
provider still received the streamed body and the client got the response. The
guarantee is structural — `ObservedRequest` cannot hold a body, header value,
cookie, query string, or raw URL — so no reconstruction from stored rows is
possible. (The canary asserts over the emitted metadata, not the raw SQLite
file bytes; extending it to scan the DB file and captured stderr is tracked as
follow-up.)

There is **no** hidden or experimental full-payload option. It does not exist
in the settings, the CLI, or the code.

## Why HTTPS trust is required

Modern API traffic is TLS-encrypted. To see anything beyond "a connection to
`api.example.com:443` happened", the observer must terminate TLS locally: it
presents your monitored process a certificate for the requested host, signed
by a **local certificate authority (CA) generated on your machine**, then
opens its own fully verified TLS connection to the real server.

Key facts about this CA:

- It is generated locally, per vault. The private key is stored only as
  ciphertext encrypted under your vault key (the ciphertext is
  cryptographically bound to the CA certificate, so a tampered certificate
  fails to decrypt), is never written to disk in plaintext, and is dropped and
  zeroized from memory when the monitored **session** ends. Note: while a
  `run --observe` is active the reconstituted signing key stays in that run
  process's memory for the child's lifetime; locking the vault does not end an
  already-running session.
- Upstream server certificates are **always fully verified** against the
  standard public root store, with hostname checking. A failed upstream
  verification is surfaced as an error to your application — never silently
  accepted. A source-level guard test
  (`crates/observe/tests/no_insecure_verifier.rs`) fails the build if anyone
  adds a verification bypass (`.dangerous(`, a custom `ServerCertVerifier`,
  `danger_accept_invalid`, …) to the crate.
- TLS verification in your application is **never disabled**. The observer
  never sets variables like `NODE_TLS_REJECT_UNAUTHORIZED` and you should
  never set them yourself — not for this tool, not for anything.

Being open source and local reduces some risks (you can audit exactly what is
recorded), but it does **not** eliminate the inherent seriousness of TLS
interception. That is why the default trust model is as narrow as possible,
described next.

## Scoped trust (Mode B) vs. system trust (Mode C)

There are three observation levels:

| | Mode A `connection` | Mode B `metadata` (default) | Mode C system trust |
|---|---|---|---|
| Decrypts HTTPS | No | Yes, for the launched child only | Yes (widens *which* clients trust the CA) |
| How the CA is trusted | Not used | Environment variables set on the child process only | One entry in your OS user trust store (opt-in) |
| Records host / port / bytes / latency | Yes | Yes | Yes |
| Records method / path / status | No (honestly shown as unavailable) | Yes | Yes |
| Changes to your system | None | None | One reversible OS-trust entry |
| Default | fallback | on when `--observe` is given | **off — never automatic** |

**Mode A (`connection`)** never decrypts anything. It records only connection
metadata: host, port, connect outcome and latency, duration, bytes each way.
Use it for pinned clients or whenever you do not want interception at all.

**Mode B (`metadata`, the default)** grants trust through environment
variables applied **only to the spawned child process** — `HTTPS_PROXY`,
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` (as a
*concatenated* bundle of the platform roots plus the local CA, never the CA
alone), `CURL_CA_BUNDLE`, `AWS_CA_BUNDLE`, `GIT_SSL_CAINFO`. Your shell, your
browser, and every other process on the machine are untouched, and there is
nothing to clean up afterwards: when the session ends, the temporary trust
files are deleted.

**Mode C (system trust)** is not a run mode — it is a one-time, opt-in trust
decision that installs the local CA certificate into your **user-level** OS
trust store, so that runtimes which ignore trust environment variables (Java,
.NET, Go on macOS/Windows, native-TLS Rust clients) can still be observed in
Mode B. Understand the trade-off plainly: **every application that uses that
trust store — browsers, mail clients, package managers — will then trust
certificates signed by this local CA.** Because of that blast radius, Mode C
requires all of the following, every time:

1. A dedicated explanation screen in plain language.
2. Your explicit choice — never a default, never pre-ticked.
3. Master-password reauthentication.
4. The **operating system's own** authorization prompt.
5. Confirmation of how removal works.

Choosing between them:

- **Start with Mode B.** It covers the most common developer stacks (Node,
  Python `requests`, curl) with zero system changes.
- If your runtime is listed as unsupported for scoped trust (see below) and
  you genuinely need method/path/status detail, consider Mode C — or accept
  Mode A's connection-level view, which is often enough.
- On a corporate or managed machine, prefer Mode B; Mode C is typically
  blocked by policy anyway (see below).

## Supported runtimes

Full details, caveats, and test references are in the
[compatibility matrix](observability/RUNTIME_COMPATIBILITY_MATRIX.md). The
summary for Mode B (scoped trust):

**Fully supported (works and tested):**

- Node.js (`https`, `undici`, `axios`, `node-fetch`)
- Python `requests`
- curl

**Partially supported (works, known caveats):**

- Python `httpx` / `aiohttp` / stdlib `ssl`
- OpenSSL CLI and generic libcrypto consumers
- AWS SDKs (JS/Python/CLI)
- git (HTTPS remotes)
- Ruby (`net/http`), PHP (curl extension)
- Rust `reqwest` with rustls (only if it builds roots from `SSL_CERT_FILE`;
  clients that pin their own root set are detected as failing and reported)

**Not covered by scoped trust (reported honestly, never silently):**

- Go (`net/http`) on macOS and Windows — Go ignores `SSL_CERT_FILE` there. A
  detected Go runtime in metadata mode is automatically downgraded to
  connection-only observation (opaque tunnels) so it keeps working, and the
  session is flagged partial coverage (`runtime_connection_only`).
- Java / JVM — uses its own `cacerts` keystore (and needs
  `-Dhttps.proxyHost`-style flags rather than the proxy env var). Mode C or
  Mode A.
- .NET and Rust `reqwest` with native-tls — use the OS store. Mode C or
  Mode A.
- Browsers — out of scope entirely. This feature does not observe browser
  traffic.

The rule for DETECTED runtimes: when the detected runtime cannot be given
scoped trust — Go (`ConnectionOnlyFallback`) or Java/.NET (`Unsupported`) — a
metadata-mode run is recorded as **partial coverage** with a machine-readable
reason (`runtime_connection_only` / `runtime_unsupported`), and the UI shows a
partial-coverage badge. Go runs are additionally downgraded to connection-only
observation automatically so they keep working.

Limitation: a client that fails the TLS handshake *inside* the tunnel for
another reason (certificate pinning) is not yet auto-detected — its requests
simply do not appear. Do not read an empty "full" dashboard as proof of no
traffic; see the pinning and QUIC notes below.

## Certificate pinning

Some applications pin their expected server certificate and will refuse any
locally signed certificate. That is the pinning working as designed — it is a
compatibility limit, not a bug in either tool.

What happens: the pinned client's TLS handshake to the observer fails and its
HTTPS calls error, while the observer can reach the same host upstream. This
version does **not** yet auto-detect this as "pinning suspected" — the session
simply shows no successful requests for that host. If a client's calls fail
only under observation, suspect pinning and use **Mode A (`--observe=connection`,
connection-level observation)** for that host.

**Never disable pinning, and never disable TLS verification, to make
observation work.** Connection-level metadata is the honest maximum for a
pinned client.

## Corporate and managed machines

**Existing proxy:** if your environment already sets `HTTP_PROXY` /
`HTTPS_PROXY` (a corporate proxy), the observer **overrides** those variables
for the monitored child so its traffic goes to the local observation proxy.
Upstream connections then go **directly** to the providers — they are **not
chained** through your corporate proxy. A monitored run therefore requires
direct egress; if egress is only permitted via the corporate proxy, monitored
requests will fail. `observe doctor` warns when a proxy variable is present.
Your parent shell's environment is never modified. (Upstream CONNECT chaining
is not implemented in this version.)

**TLS-intercepting corporate proxy:** if your corporate proxy itself
intercepts TLS, the observer's upstream verification against the public root
store will fail — which is correct behavior. The fix is to add your corporate
root certificate to the upstream trust configuration (the
`SSL_CERT_FILE`-style bundle), **not** to disable verification.

**Managed (MDM) machines:** Mode C installation is typically blocked by
device policy. The failure is detected and reported plainly; the app never
retries, escalates, or attempts to work around the OS or MDM. Mode B needs no
system change and usually works fine on managed machines.

## Monitoring internal and localhost APIs

By default the proxy **refuses** connections to loopback, private (RFC 1918),
link-local, carrier-grade NAT, and cloud-metadata addresses, and to ports
other than 80/443. This is a deliberate security posture: an open local proxy
must not be usable to reach your database, your LAN, or cloud metadata
endpoints.

If you want to observe your own internal or localhost API, add an explicit
**per-project allowlist entry** for that exact `(host, port)`. Allowlisted
internal destinations are:

- surfaced with a **persistent warning** in the UI, and
- recorded in the session's compatibility results, so anyone reading the data
  later knows the destination policy was relaxed for that session.

Note that `localhost`, `127.0.0.1`, and `::1` are always kept in the child's
`NO_PROXY` for ordinary (non-allowlisted) operation.

## Privacy and retention

All observation data lives in your local vault database, under the same
at-rest protections as the rest of your data. Nothing is uploaded anywhere.

- **Per-request events:** kept **7 days** by default. Event-level detail
  exists for recent debugging ("what changed an hour ago") and decays in
  value quickly. Configurable from 1 to 90 days.
- **Aggregate metric buckets** (hourly/daily counters and latency
  histograms): kept **90 days** by default, to support trend detection like
  latency regressions and volume baselines. Configurable from 7 to 730 days.
- Expired rows are swept automatically, and the database's secure-delete mode
  overwrites the freed pages.

Deletion is available at three scopes, none of which touch credentials or any
other vault data:

- delete observation data **by project** (`observe delete-project <project>`),
- delete **by session** (`observe delete-session <session>`),
- **delete all observability data** (`observe delete-all`, reauthentication
  required).

Exports and backups of the vault include these tables, and they are safe to
include for the same reason the feature is safe at all: they contain no
secrets and no payloads by construction. (There is no dedicated `observe
export` command in this version; share the vault backup or query the aggregate
tables directly.)

## Removing the certificate

- **Mode B leaves nothing behind.** The CA certificate file used for scoped
  trust is a temporary file deleted when the session ends. There is nothing
  to remove.
- **Mode C (system trust)** installed one entry in your user trust store. To
  remove it, use `observe cert uninstall`, which deletes the entry through the
  platform's own tooling. `observe cert status` shows the system-trust state
  this vault recorded (installed / absent). Note: `status` reflects installs
  performed *by this vault*; it does not currently scan the OS store, so after
  deleting and recreating a vault an old entry may remain and should be removed
  with `observe cert uninstall`.
- **Rotation:** `observe cert rotate` generates a fresh CA. Rotate after any
  suspected exposure of your machine. If the previous CA was installed via
  Mode C, uninstall it from the OS store separately — rotation does not remove
  the old system-trust entry.

## Troubleshooting

**No data captured at all**

- Confirm you launched through `run --observe=…` — only the launched process
  and its descendants are observed. Nothing machine-wide is ever captured.
- Check whether your client uses **HTTP/3 (QUIC)**. QUIC is UDP and bypasses
  an HTTP proxy entirely. This version does **not** auto-detect this — a
  session that shows connections but no requests may indicate QUIC or another
  bypass (this is a documented limitation, not a diagnostic flag). Most
  clients have a flag to disable HTTP/3 for a run; the observer never sets
  such flags silently, and it cannot and does not block UDP.
- Some programs ignore proxy environment variables by design, and a child
  process that explicitly clears its environment escapes observation. This
  is a stated limit — enforcing it would require machine-wide capture, which
  this product deliberately does not do.

**Partial coverage badge on a session**

- The runtime was classified as less than fully supported (see the
  compatibility matrix), a connection fell back to an opaque tunnel (for
  example an HTTP/2-only client such as gRPC), or a proxy-internal error
  occurred. The session record carries the specific reason. Error rates from
  partial sessions are always shown with the badge — never as if coverage
  had been complete.

**Repeated TLS failures from one host**

- Likely certificate pinning (the client rejects the locally minted leaf).
  This is not auto-flagged in this version — the host simply shows no
  successful requests. Use Mode A (`--observe=connection`) for that host. Do
  not disable pinning or TLS verification.
- If the failure is on the **upstream** side
  (`upstream_certificate_invalid`), the real server's certificate failed
  verification — possibly a corporate TLS-intercepting proxy (add its root
  to the trust bundle) or a genuine certificate problem. This is never
  downgraded to a success.

**My client suddenly speaks HTTP/1.1**

- Expected in Mode B: the observer negotiates HTTP/1.1 with clients that
  support it (see "Protocol limitations"). It affects only the monitored
  process, only for the monitored run.

**Session shows "interrupted"**

- Interruption is a distinct, honestly reported state with a reason:
  `trust_setup_failed` (scoped trust could not be prepared),
  `child_spawn_failed` (the command could not be launched), or `launcher_gone`
  (the launching process disappeared and the orphaned session was later swept
  by the monitor). Interrupted sessions are never silently relabeled as
  completed.

**Locking the vault during a run**

- Important: locking the vault (or auto-lock) does **not** stop an already-
  running `run --observe`. That run holds its own copy of the vault key and the
  CA signing key in memory for the lifetime of the monitored child, and keeps
  observing until the child exits. If you need the CA-key exposure window to
  end, stop the monitored process. (Cross-process lock interruption of a live
  run is not implemented in this version — see the threat model.)

## Uninstalling: cleanup checklist

Deleting the application does **not** remove a Mode C system-trust
certificate — OS trust stores are not cleaned up by file deletion. If you
ever enabled Mode C, run `observe cert uninstall` (or remove the entry named
with the `Tethra Local Observation CA` prefix through your OS's certificate
manager) **before** uninstalling. Mode B users have nothing to do: scoped
trust never touched the system and its temp files are already gone.

## Protocol limitations (read this — it is honest, not fine print)

- **HTTP/2 is not decoded.** On intercepted connections the observer
  advertises only HTTP/1.1, so clients that support both (Node, Python
  `requests`, curl) transparently use HTTP/1.1 for the monitored run. This
  is an observable behavior change for that process and is shown in the UI.
  A client that offers *only* HTTP/2 (gRPC, some h2-only clients) gets an
  opaque tunnel: host, port, timing, and byte counts, but no method, path,
  or status — and the session is flagged partial. The recorded protocol
  field always states what was actually negotiated, so the UI never implies
  HTTP/2 visibility it does not have.
- **HTTP/3 / QUIC bypasses the proxy entirely.** It is UDP; proxy
  environment variables do not apply. This is a known, documented,
  detected-when-possible bypass — never hidden, never blocked.
- **WebSockets:** the upgrade handshake is recorded (method, templated path,
  status 101), then the connection becomes an opaque relay. Message contents
  are never observed.
- **Server-Sent Events / streaming:** the request and response status are
  recorded; the stream itself is relayed untouched with backpressure, never
  buffered.
- **Compression:** response bodies are passed through undecoded; recorded
  sizes are **wire** sizes, and the UI says so.
- **Redirects:** each hop your client follows is its own event; the observer
  itself never follows redirects.
- **Quantiles are approximate:** latency percentiles are interpolated from a
  fixed histogram and labeled approximate in the UI.
- Two invariants are enforced by tests: a transport failure is never counted
  in an HTTP error rate, and a successful TCP connection is never reported
  as a successful request.

## Unknown APIs still give value

You do not need a provider integration for an observed host to be useful.
Every hostname your application calls becomes part of a persistent **observed
API inventory**: first seen, last seen, endpoints (method + templated path),
volumes, error rates, and latency. Hosts that map to a known provider are
labeled as such; unknown hosts are kept as first-class entries you can name,
annotate, and classify as external or internal yourself. A newly observed
unknown host raises an informational alert — often the fastest way to
discover that a dependency phones an API you did not know about.

## Credential attribution and confidence

When you launch with `run --observe`, the credentials injected into that run
are known — which credential, for which provider, at which version. Traffic
attribution is derived **entirely from that launch-time state**, never from
the wire:

| Confidence | Meaning |
|---|---|
| **Confirmed** | Exactly one injected credential matches the observed host's provider (manifest-declared mapping) |
| **High** | One injected match, but the host→provider mapping is inferred rather than declared |
| **Possible** | No injection match, but exactly one project credential has that provider |
| **Ambiguous** | Several credentials could explain the traffic — all candidates are listed, none is chosen |
| **Unattributed** | Unknown host with no provider mapping |

**Authorization header values are never read** — not parsed, not decoded,
not even glanced at to determine a scheme. The only thing recorded about
authorization is a boolean: whether an `Authorization` header was present,
which is genuinely useful (a 401 without an auth header is a different
diagnosis than a 401 with one) and reveals nothing about the credential.

Because the credential's version is captured at process launch, "this run is
still using the pre-rotation credential" is **provable**, not guessed — the
basis for the old-credential-after-rotation alert.

---

*For the full technical specifications this guide summarizes, see the
[architecture](observability/RUNTIME_OBSERVABILITY_ARCHITECTURE.md),
[threat model](observability/RUNTIME_OBSERVABILITY_THREAT_MODEL.md),
[privacy model](observability/RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md), and
[compatibility matrix](observability/RUNTIME_COMPATIBILITY_MATRIX.md).*
