# ADR 0017: Runtime API observability — a local, opt-in, metadata-only HTTPS observation proxy

Status: accepted (2026-07-24)

Introduces the runtime observation subsystem: the `observe` CLI verb,
`run --observe=off|connection|metadata`, the `api-tracker-observe` crate, a
per-vault certificate authority, and migration v12 (`runtime_*` and
`observe_*` tables). Gate documents:
`docs/observability/RUNTIME_OBSERVABILITY_ARCHITECTURE.md`,
`RUNTIME_OBSERVABILITY_THREAT_MODEL.md`,
`RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md`, `RUNTIME_COMPATIBILITY_MATRIX.md`,
and `IMPLEMENTATION_PLAN.md`. This ADR records why the design is what it is;
the gate documents record what it is in full.

## The problem this fixes

The product can answer "what credentials do I have, and what do providers
say about them" — provider-reported usage lands in `usage_snapshots`, is
daily-granular, account- or provider-project-attributed, covers only the
catalog providers, and arrives hours late. It cannot answer "what is my
application actually doing right now": which hosts a dev server calls,
which endpoints started returning 401 an hour ago, whether a rotated-away
credential version is still in use.

ADR 0014 considered a local request-proxy/gateway for exactly this and
rejected it "for now": substantial machinery, a risk of becoming de-facto
mandatory, and provider aggregates plus injection-session records covered
the questions then being asked. It explicitly left the door open: "the
decision stands until a concrete use case demands an OPTIONAL gateway."
That condition is now met — the runtime questions above are asked routinely
and cannot be answered from provider data at any granularity or freshness.
This ADR **refines, and for this specific mechanism supersedes, the ADR 0014
stance**: an optional local observation proxy is now built. The parts of
0014 that motivated the refusal remain binding constraints on the design:
the proxy is opt-in per run, never ambient, never required by any other
feature, and adds no mandatory moving part to the product.

## Decisions

1. **A MITM proxy, because it is the only honest local vantage point.**
   Per-request runtime visibility requires sitting on the connection. Of
   the realistic mechanisms (SDK instrumentation, machine-wide capture, an
   explicit proxy — see Alternatives), only an explicitly launched,
   loopback-only, per-process HTTP proxy matches the product's scope rules:
   it observes exactly the child process the user launched with
   `run --observe`, nothing else, and disappears when the run ends. HTTPS
   interception uses a per-vault CA; the child is given scoped trust in it.
   The proxy verifies upstream certificates fully against `webpki-roots` —
   there is no permissive-verifier code path in the crate, and a
   source-level guard test (`no_insecure_verifier.rs`) fails the build if
   one is ever added. TLS verification is never disabled or weakened, in
   the proxy or in the child.

2. **Metadata only, enforced by the type system rather than by filtering.**
   The proxy parses HTTP/1.1 heads only; bodies are relayed through a fixed
   16 KiB buffer and never accumulated. The single persistence rule: no
   unsanitized wire-derived string reaches a `store::` function. The
   sanitizer output type, `ObservedRequest`, has no field capable of
   holding a query string, a header value, a cookie, an authorization
   value, or a body — the review burden is "confirm the struct has no such
   field", not "trust that a filter is comprehensive". Query strings and
   fragments are severed before templating begins; path segments that look
   like identifiers (UUIDs, JWTs, emails, credential-shaped prefixes, long
   hex, high-entropy strings, digit runs) are replaced with placeholders,
   property-tested. There is no full-payload flag, hidden or otherwise, and
   an end-to-end canary test proves distinctive markers placed in URLs,
   headers, and bodies are byte-for-byte absent from the database, logs,
   DTOs, exports, and temp files after a real monitored request.

3. **A separate crate (`api-tracker-observe`).** `api-tracker-core`
   promises no network I/O beyond outbound provider clients. A listening
   socket, a TLS terminator, and a certificate authority are a materially
   different trust surface and get their own review boundary, dependency
   set, and `forbid(unsafe_code)`. The observe crate depends on core (for
   the sanitizer, store, `SecretBytes`, vault); core does not depend on it,
   so every non-observed path links exactly as before. The only genuinely
   new dependency is `rcgen` (default-features off, on the already-vendored
   `ring` backend); no tokio, hyper, openssl, or native-tls is introduced.

4. **Blocking threads, not async.** The proxy is thread-per-connection with
   a bounded pool (64 connections via semaphore) and no async runtime. A
   blocking read/write copy loop over a fixed stack buffer *is* the
   backpressure requirement — it cannot buffer a body even by accident
   because there is nowhere to put one. `rustls` has a first-class blocking
   API, the realistic workload is one developer's dev server, and adding an
   executor to a security-sensitive local daemon for that workload is
   unjustified complexity. Timeouts come from socket timeouts plus a
   per-connection deadline.

5. **Scoped trust by default; system trust as a separate, gated opt-in.**
   Mode B (`metadata`, the default when `--observe` is given) applies proxy
   and CA-trust environment variables **only to the spawned child** via
   `Command::env` — never `setenv` in the parent, never a system change.
   Replace-semantics variables (`SSL_CERT_FILE` and friends) point at a
   concatenation of the platform bundle plus our CA, never our CA alone, so
   the child's trust set is widened by exactly one certificate and never
   shrunk. Verification-disabling variables
   (`NODE_TLS_REJECT_UNAUTHORIZED`, `GIT_SSL_NO_VERIFY`, etc.) are never
   set, asserted by test. Mode C (system trust) exists only because some
   runtimes (Java, .NET, Go on macOS/Windows, native-tls) ignore scoped
   trust variables; it is a one-time trust decision, off by default, and
   gated on five independent controls: a plain-language warning screen, an
   explicit non-default choice, master-password reauthentication, the
   operating system's own authorization prompt (never suppressed or
   imitated), and confirmation text covering removal. Mode A
   (`connection`) records connection-level metadata only, with no
   decryption at all.

6. **The CA private key is a high-value asset and is treated like one.**
   One CA per vault, ECDSA P-256. The private key exists at rest only as
   XChaCha20-Poly1305 ciphertext under the vault key with AAD
   `api-tracker:v1:observe-ca-key:{vault_id}`; in memory only as
   `SecretBytes` inside the proxy thread pool. It is never written to a
   plaintext file, never printed, never crosses the Tauri IPC boundary,
   and is absent from every DTO (only the fingerprint and dates are
   exposed). Vault lock zeroizes the key and the leaf cache and tears down
   active sessions — decryption cannot continue past a lock. Rotation and
   removal commands exist (`observe cert rotate` / `remove` / `repair`),
   and destructive observability operations (delete-all, Mode C install)
   are reauthentication-gated, consistent with the vault's existing
   reauth-before-sensitive-action rule.

7. **Observed data and provider-reported data are never merged.**
   Provider-reported numbers stay in `usage_snapshots`; locally observed
   numbers stay in the `runtime_*` tables. There is no query that sums
   across the two, and the UI labels the sources separately. This
   preserves ADR 0014's honesty discipline: an account-level daily number
   from a provider and a locally observed per-request count answer
   different questions from different evidence, and blending them would
   fabricate precision neither source has. Attribution of observed traffic
   to credentials never inspects an `Authorization` header — it derives
   entirely from state the vault already owns (which credentials were
   injected into the session, at which `value_version`), with an explicit
   confidence ladder that lists candidates rather than guessing when
   ambiguous. (Storage/encryption-at-rest posture for the new tables is a
   separate decision, ADR 0018.)

## Alternatives considered

- **SDK instrumentation / client-library shims** — rejected. Requires
  users to modify application code per language and per HTTP library,
  drifts as libraries change, silently misses anything not wrapped, and
  puts observation code inside the process that holds live credentials.
  ADR 0014's "mandatory-feeling moving part" objection applies with full
  force: a shim invites coupling application code to this product.
- **Machine-wide capture (eBPF, packet capture, OS network extension)** —
  rejected. Violates the explicit non-goal of machine-wide traffic
  capture, requires elevated privileges, observes processes the user never
  asked to observe (including browsers, also an explicit non-goal), and
  turns a per-run developer tool into resident privileged software. It is
  also the only mechanism that could close the QUIC and env-clearing-
  descendant gaps — the design accepts those gaps and states them instead.
- **Full-payload capture (bodies/headers, even behind a flag)** —
  rejected. Payloads contain the exact material this product exists to
  protect: API keys, tokens, prompts, source code, personal data. A
  disabled-by-default body recorder would still be a body recorder — a
  capability whose mere existence changes the threat model of the vault
  database and every backup. The metadata-only guarantee is only credible
  because the capability is structurally absent, not policy-disabled.
- **Decoding HTTP/2** — deferred, not half-done. Correct h2 decoding needs
  HPACK state, stream multiplexing, and flow control; a half-correct
  decoder would mis-frame and mis-attribute, which is worse than honestly
  declining. Intercepted connections advertise only `http/1.1` in ALPN
  (most clients transparently downgrade for the monitored run — a
  documented, per-process behaviour change); h2-only clients get an opaque
  tunnel with connection-only metadata, flagged partial.
- **Doing nothing (the ADR 0014 status quo)** — rejected now. The runtime
  questions are concrete and recurring, and no provider API answers them
  at any freshness or granularity.

## Security implications

- **New attack surface.** A loopback listener, a TLS terminator, and a CA
  now exist in the product. Mitigations, all tested: loopback-only bind;
  per-session 32-byte proxy token compared in constant time and never
  logged; destination policy denying loopback/private/link-local/metadata
  ranges and non-web ports on both the literal authority and every
  resolved address (connecting to the validated `SocketAddr`, closing DNS
  rebinding); bounded heads, bounded connections, bounded lifetimes
  (Slowloris-bounded); no `unsafe`; no permissive upstream verifier, with
  a source-grep guard test.
- **The CA key is the highest-value new asset.** In Mode B its blast
  radius is the monitored children of one run; in Mode C it is every
  application on the machine, which is precisely why Mode C is off by
  default and multi-gated. Residual risk, stated honestly: an attacker who
  can read process memory while the vault is unlocked gets the key — the
  same residual that applies to every vault secret and cannot be
  eliminated by local software.
- **Open source does not eliminate TLS-interception risk.** The design's
  safety rests on scoped trust, full upstream verification, key
  protection, and metadata-only persistence — properties that are tested,
  not merely inspectable. Interception is inherently sensitive and the
  documentation says so.
- **Accepted residual risks** (threat-model summary): same-user processes
  can read the child's environment and reuse the session token (bounded to
  one user account); QUIC/HTTP-3 bypasses the proxy entirely (detected and
  reported, never hidden or blocked); descendants that clear their
  environment are invisible (enforcement would require machine-wide
  capture); Mode C's blast radius (off by default, five gates, fully
  reversible).
- **What is *not* stored:** no bodies, no header values, no query strings,
  no authorization material, no full URLs. The metadata that *is* stored
  (hosts, sanitized path templates, timing) discloses which APIs a
  developer calls; it lives in the vault database under the same at-rest
  protections as the rest of the operational schema (see ADR 0018).
- Failure semantics fail closed: if the listener dies the child loses
  connectivity through the proxy and errors honestly rather than silently
  bypassing; sessions interrupted by lock, crash, or quit are marked
  `interrupted` with a reason, never silently `completed`.

## Future limitations

- **HTTP/2 is not decoded.** Clients are downgraded to HTTP/1.1 for the
  monitored run where they allow it; h2-only clients (gRPC) yield
  connection-only metadata. True h2 decoding is the top item in the
  protocol-support roadmap.
- **HTTP/3 / QUIC bypasses the proxy entirely** (UDP; proxy variables do
  not apply). It is detected heuristically and reported as a possible
  bypass; it cannot be observed or blocked without a network extension,
  which is out of scope.
- **Runtimes that ignore trust environment variables** (Java, .NET, Go on
  macOS/Windows, native-tls Rust clients) get connection-only fallback or
  require the Mode C opt-in; sessions record `partial_coverage` with a
  machine-readable reason and the UI badges them. Certificate-pinned
  clients cannot be intercepted; the recommendation is Mode A for that
  host, never disabling pinning.
- **Coverage is per-process-tree via environment inheritance.** A
  descendant that clears its environment, or a program that ignores proxy
  variables by design, is not covered, and no process-tree enforcement is
  claimed.
- **Browsers and machine-wide traffic remain out of scope** by product
  rule; this ADR does not reopen them.
- The first release is classified experimental/internal-alpha and
  public-blocked until every item on the release-classification list in
  `IMPLEMENTATION_PLAN.md` §10 is proven; latency quantiles are
  histogram-interpolated and labelled approximate; response sizes are wire
  (possibly compressed) sizes and labelled as such.
