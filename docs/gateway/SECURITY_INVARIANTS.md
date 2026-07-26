# Local Gateway — Security Invariants

The properties that must hold in every build, enforced by construction and by
named tests (TEST_PLAN.md). Each invariant traces to an immutable requirement
or a challenge finding. "Enforced by" names the mechanism; "Verified by"
names the test class. Nothing here may be weakened without stopping and
reporting a blocker.

## Binding and reachability

- **SI-1 Loopback only.** The listener binds `127.0.0.1` (and optionally
  `::1`), never `0.0.0.0`, never a routable or configurable external
  interface. *Enforced by:* a single hard-coded bind address, no
  host-configuration surface. *Verified by:* a unit test asserting the bind
  address and a source-grep guard rejecting `0.0.0.0`/`INADDR_ANY`.
- **SI-2 Not an open relay.** Requests are forwarded ONLY to explicitly
  registered upstream origins selected by the first path segment. No
  CONNECT, no absolute-form targets, no client-supplied upstream. Unknown
  prefix → 404, no DNS, nothing forwarded. *Verified by:* §2/§3 routing and
  smuggling tests.
- **SI-3 Registered origins only, re-validated.** Every route origin is
  https, port 443, and passes the SSRF policy (deny loopback, RFC1918,
  link-local, CGNAT, cloud-metadata names) at registration AND the resolved
  IP is policy-checked at connect time, connecting to the validated
  `SocketAddr` (DNS-rebinding closed, mirroring observe RO-5). *Enforced by:*
  reuse of `observe::policy`. *Verified by:* §3 tests incl. re-resolution.
- **SI-4 Host-header gate + browser-write rejection.** Requests whose `Host`
  is not the gateway's own loopback authority (case-insensitive EXACT match
  against `{127.0.0.1:port, localhost:port, [::1]:port}`) are rejected. The
  gateway generates no CORS headers and strips relayed `Access-Control-*`.
  Browser writes are rejected: any request bearing `Origin`, `Referer`,
  `Sec-Fetch-Mode: no-cors`, or `Sec-Fetch-Site` ≠ absent, or a
  CORS-safelisted Content-Type with no credential header, is refused and
  produces NO observation row/counter/alert (only a `rejected_browser_origin`
  counter). Non-loopback peers are rejected at accept. Link slugs are
  ≥128-bit CSPRNG; unknown prefix and unknown slug return an identical 404.
  *(A `text/plain` no-cors POST IS a CORS-simple request and fires with no
  preflight — the review's `simple-request-write-primitive` finding; these
  checks, not a preflight assumption, are the defence.)* *Verified by:* §2.
- **SI-4a No cookie relay.** `Cookie` (client→upstream) and `Set-Cookie`
  (upstream→client) are stripped — cookies ignore port and the gateway shares
  127.0.0.1's cookie jar with every local dev server. *Verified by:* §1.

## TLS and upstream

- **SI-5 Upstream TLS is always fully verified.** rustls against
  webpki-roots, ALPN http/1.1, no permissive-verifier code path anywhere in
  the crate. *Enforced by:* `forbid(unsafe_code)` + a
  `no_insecure_verifier` source-grep guard scoped to `crates/gateway/src`.
  *Verified by:* the guard test (§11).
- **SI-6 No inbound certificate impersonation.** The gateway terminates NO
  TLS toward clients (plain loopback HTTP) and holds no certificate-authority
  key. There is no MITM surface. *Enforced by:* the crate never links the CA
  modules (`ca`, server-side `tls`, `clienthello`, `trust`, `systemtrust`).

## Credentials and secrets

- **SI-7 Credential values are never persisted or logged.** Forwarded
  credential values exist only inside `Zeroizing` buffers for the duration of
  one exchange (a gateway-local head reader, since observe's `wire` buffers
  are plain unzeroized `Vec`s); the record type has no field capable of
  holding a value. This is BEST-EFFORT in-process hygiene — defeated by swap
  and core dumps, which are documented out of scope. No `Debug`/diagnostic/
  panic path may emit a header value or the raw head (only a byte count).
  *Verified by:* §6 raw-file canaries and a `security_residuals`-style test
  asserting a fake key produces no substring in Debug, compat strings, or a
  forced panic.
- **SI-8 Authorization values are never persisted or logged.** Only
  attribution STATE (five labels) and, on a match, a credential id are stored
  — never the header value. `attribution_method` distinguishes value-derived
  from injection-derived rows. *Verified by:* §5/§6.
- **SI-9 The fingerprint matching key cannot decrypt anything, and the
  matcher table is never vault-wide.** The key is the ADR 0005 keyed-hash key
  (matching only), lives only in `Zeroizing` memory, never at rest outside
  vault wrapping, is dropped on stop/disable/lock/toggle-off, and (when the
  "match while locked" toggle is ON) is TTL-bounded by the pushing session's
  auto-lock. The table contains only credentials of linked, non-password-
  locked projects, with references resolved to their root. *Verified by:* §5
  key-lifecycle and table-scoping tests.
- **SI-21 The matching key arrives only over the authenticated control
  channel.** It is accepted only over the `<data-dir>/gateway.sock` Unix
  socket with a peer-euid == our-uid check, never over the TCP listener,
  never via argv or an environment variable. The channel is write-only (no
  key read-back). Each push is reauth-gated and audited. *(Windows v1 refuses
  key push rather than fall back to TCP.)* *Verified by:* a source-grep guard
  ("the key never crosses TCP/argv/env") + §5 peer-cred tests.
- **SI-10 No cookies, query values, request bodies, response bodies,
  prompts, or generated responses are ever persisted or logged.** Query and
  fragment are severed before any stored string is constructed;
  `sanitize_path` is the only wire-to-stored-string transformation.
  *Verified by:* §6 canaries + sanitize property tests.

## Availability and independence

- **SI-11 Forwarding continues while the vault is locked.** The forward path
  depends on no vault-decrypted material. *Verified by:* §4 locked-vault
  end-to-end test.
- **SI-12 Forwarding continues when observation persistence fails.** The
  observation hand-off is `try_send` with drop-and-count; a full queue, a
  busy DB, a missing DB, or a too-new schema never blocks or fails a forward.
  *Enforced by:* the writer never shares the forward path's critical section.
  *Verified by:* §4 degradation tests, timing-asserted.
- **SI-13 The vault is never required to complete an upstream request.** No
  forward path calls unlock, decrypt, or any vault-key operation. *Verified
  by:* §4 no-database forwarding test.

## Bounds

- **SI-14 Every queue and buffer is bounded.** Head size (32 KiB), header
  count (100), chunk-header line, relay buffer (16 KiB fixed), SSE
  event/line caps, JSON tail window, writer queue (bounded, drop-on-full),
  connection cap (503 over the cap), Slowloris absolute head deadline.
  *Verified by:* §1/§2 bound tests + §7 pathological-input test.
- **SI-15 Request smuggling is rejected, not normalized-and-forwarded.**
  TE+CL together, conflicting duplicate CL, and malformed framing are hard
  errors. *Verified by:* §2.

## Filesystem and privilege

- **SI-16 No Full Disk Access; no unrelated files inspected.** The gateway
  reads only its own binary, the vault data directory (config/routes/DB
  under the existing `0700`/`0600` regime), and the project `.env` files the
  user explicitly links. *Enforced by:* no filesystem traversal code.
- **SI-17 Existing migrations are immutable; schema changes are append-only.**
  The v13 migration adds tables only; v1–v12 are untouched. *Verified by:*
  §8 append-only test.
- **SI-18 The gateway supplements, never deletes, the interception proxy.**
  `crates/observe` and `tethra run` remain fully functional and unmodified in
  behavior. *Enforced by:* additive-only changes to shared code.

## Honesty

- **SI-19 Product claims match coverage.** Gateway-observed data is labeled
  locally-observed, never summed with provider-reported usage; coverage
  limitations (local machine only, base-URL-repointed traffic only, no
  remote/production) are stated wherever coverage is shown. Absence of
  recorded traffic is never presented as absence of traffic.
- **SI-20 No unsafe code in Tethra-owned Rust.** `#![forbid(unsafe_code)]`
  at the crate root.
