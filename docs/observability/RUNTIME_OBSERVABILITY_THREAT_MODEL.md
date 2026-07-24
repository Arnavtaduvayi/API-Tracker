# Runtime API Observability — Threat Model

Companion to the repository-wide `THREAT_MODEL.md`. Covers only the runtime
observation subsystem (local CA, loopback proxy, scoped trust, Mode C system
trust). Identifiers `RO-xx` are referenced from code comments and tests.

**Assets introduced by this feature**

| Asset | Where it lives | Worst case if lost |
|---|---|---|
| Local CA private key | `observe_certificate_state.key_ciphertext`, encrypted under the vault key | Attacker can mint certificates trusted by any process configured to trust the Tethra CA (Mode B: only monitored children; Mode C: **everything on the machine**) |
| Per-session proxy token | process memory only | Local process can route traffic through the proxy |
| Sanitized traffic metadata | `runtime_*` tables | Discloses which APIs a developer calls and when |
| Trust configuration of the child | child environment only | Misconfiguration could downgrade the child's TLS verification |

**Explicit non-asset:** payload content. It is never held beyond a 16 KiB
relay buffer and never persisted, so it is not in scope as an asset to
protect at rest — only as a leakage risk in logs (RO-16).

---

## RO-1 — Local CA private-key theft

**Threat.** Malware or another local user reads the CA key and mints trusted
certificates.

**Mitigations.**
- Key stored only as XChaCha20-Poly1305 ciphertext under the vault key, AAD
  `api-tracker:v1:observe-ca-key:{vault_id}`. Unavailable while the vault is
  locked.
- Never written to a plaintext file, never printed, never serialized to the
  Tauri IPC layer or CLI output. `SecretBytes` (zeroize on drop) in memory.
- `observe_certificate_state` exposes `fingerprint_sha256`, `created_at`,
  `not_after` to the UI; `key_ciphertext` is not in any DTO.
- Rotation (`observe cert rotate`) is available and required after any
  suspected exposure.

**Residual risk — stated honestly.** An attacker who has already compromised
the user account and can read memory while the vault is unlocked gets the key.
This is the same residual risk that applies to every credential in the vault
and cannot be eliminated by local software. In **Mode C** the blast radius is
larger than any single credential, which is exactly why Mode C is off by
default, gated on reauthentication + an OS prompt, and carries an explicit
warning screen.

## RO-2 — Unauthorized local processes connecting to the proxy

**Threat.** Any local process can reach `127.0.0.1:<port>` and use Tethra as an
egress proxy or pollute another project's metrics.

**Mitigations.**
- 32 bytes of `getrandom` entropy per session, presented as
  `Proxy-Authorization: Basic base64("tethra:<token>")`.
- Compared with `subtle::ConstantTimeEq`. **Never logged, never in an error
  message, never in a compatibility result, never in the DB.**
- Token dies with the session; the listener socket is closed, so a replayed
  token has nothing to talk to.
- Failures return a bare `407` with `Proxy-Authenticate: Basic realm="tethra"`
  and no detail.

**Residual risk.** A local process running as the same user can read the
child's `/proc/<pid>/environ` (Linux) or be a descendant that inherited it. On
macOS `ps -E` requires the same user. This is unavoidable: the token must reach
the child through its environment. It bounds damage to *the same user account*,
not to *any local process*.

## RO-3 — Proxy credential leakage into recorded metadata

**Threat.** The `Proxy-Authorization` value ends up in an event, log or error.

**Mitigations.** `wire.rs` strips `Proxy-Authorization` and `Proxy-Connection`
before forwarding, and `ObservedRequest` has no header field at all — there is
no container for it. `tests/privacy_no_leak.rs` asserts the token string is
absent from the DB file bytes, every log line, every error string, every DTO,
and every export.

## RO-4 — Malicious CONNECT destinations / SSRF (RO-4, RO-5, RO-6, RO-7)

**Threat.** The proxy is an unauthenticated-to-the-network SSRF primitive:
`CONNECT 169.254.169.254:80` reaches cloud metadata; `CONNECT 127.0.0.1:5432`
reaches the developer's database; `CONNECT 10.0.0.5:22` reaches the corporate
LAN.

**Mitigations (`policy.rs`), applied to the literal authority *and* to every
resolved address:**

| Denied | Examples |
|---|---|
| Loopback | `127.0.0.0/8`, `::1`, `localhost` |
| Private / RFC1918 | `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` |
| Link-local | `169.254/16`, `fe80::/10` |
| Cloud metadata | `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, `metadata.goog`, `100.100.100.200` |
| Carrier-grade NAT | `100.64/10` |
| Multicast / broadcast | `224/4`, `255.255.255.255`, `ff00::/8` |
| Unspecified / reserved | `0.0.0.0/8`, `240/4`, `::` |
| IPv4-mapped IPv6 wrappers | `::ffff:127.0.0.1` is unwrapped **before** the check |
| Non-web ports | anything outside `{80, 443}` unless explicitly allowlisted |
| Unix sockets, non-HTTP CONNECT | rejected — the authority grammar only accepts host:port |
| Malformed hostnames | empty labels, `..`, >253 bytes, >63-byte labels, NUL, whitespace |

Per-project internal allowlisting exists (`observe_internal_allowlist`) for
teams monitoring their own localhost APIs. It requires an explicit entry per
`(project, host, port)`, is surfaced with a persistent warning in the UI, and
is recorded in the session's compatibility results so a reader of the data
knows the policy was relaxed.

## RO-5 — DNS rebinding

**Threat.** A hostname resolves public at check time and private at connect
time (TOCTOU).

**Mitigation.** We resolve **once**, validate **the resolved
`SocketAddr` set**, and then `TcpStream::connect(addr)` to a **validated
address**, not to the hostname. There is no second resolution, so there is no
window. Any address failing validation removes that address from the candidate
set; if none survive, the CONNECT is refused with `403`.

`tests/ssrf.rs::rebinding_uses_validated_address_only` exercises a resolver
stub that returns a public address first and a private one second, and asserts
the connection goes to the first and the second is never dialled.

## RO-6 — Upstream TLS verification weakening

**Threat.** The classic MITM-proxy bug: the proxy verifies nothing upstream, so
a network attacker between the developer and the provider is invisible, and the
developer's own client — which now trusts our CA — sees a green padlock.

**Mitigations.**
- The upstream `rustls::ClientConfig` is built exactly once, in
  `tls::upstream_config()`, from `webpki_roots::TLS_SERVER_ROOTS`, with default
  (full) verification and correct SNI/hostname checking.
- There is **no** `dangerous()` call anywhere in the crate.
- `tests/no_insecure_verifier.rs` is a source-level guard: it reads every
  `.rs` file in `crates/observe/src` and fails if it finds `dangerous`,
  `NoCertificateVerification`, `set_certificate_verifier`,
  `danger_accept_invalid`, or `ServerCertVerifier` outside a comment. This
  catches a future contributor adding a "temporary" bypass.
- Upstream verification failure is surfaced to the child as a TLS alert **and**
  recorded as `transport_error = "upstream_certificate_invalid"`. It is never
  downgraded to a successful request.

## RO-7 — Certificate pinning in the monitored application

**Threat.** A pinned client fails to connect and the developer blames Tethra,
or worse, disables pinning.

**Mitigation.** Not a vulnerability — a compatibility limit. Detected
heuristically: repeated TLS handshake failures from the client to us on a host
that we can reach successfully upstream ⇒ `pinning_suspected`. The UI says so
explicitly and recommends Mode A for that host, **never** disabling pinning.

## RO-8 — Unsupported trust stores / silent bypass

**Threat.** A runtime ignores `NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE` (Go's
`crypto/x509` on macOS, Java's cacerts, .NET, Rust `native-tls`) and either
fails or silently bypasses, while the UI implies full coverage.

**Mitigations.**
- `trust.rs` classifies the launched runtime: `FullySupported`,
  `ProbablySupported`, `ConnectionOnlyFallback`, `Unsupported`,
  `PinningSuspected`, `ProxyBypassSuspected`.
- A session records `partial_coverage` plus a machine-readable reason whenever
  anything short of `FullySupported` occurs.
- The dashboard shows a **partial coverage** badge; the API detail view shows
  which sessions were partial. §11 of the brief is satisfied by never
  presenting an error rate computed across a partial session without the badge.

## RO-9 — HTTP/3 and QUIC bypass

**Threat.** QUIC is UDP; an HTTP proxy environment variable does not apply. A
client with HTTP/3 enabled bypasses Tethra entirely and the developer sees
*zero* traffic and concludes there was none.

**Mitigations.**
- Documented as a **known bypass** in the compatibility matrix, the UI setup
  screen, and the user documentation.
- Detection: if a session records TCP connections to a host but the process
  ran for a meaningful duration with no requests, `diagnostics` reports
  `possible_quic_or_bypass`. We do not block UDP (we cannot, without a network
  extension) and we do not claim we do.
- Mitigation available to the user: most clients honour
  `--disable-http3`-style flags; the docs list the common ones. We never set
  them silently.

## RO-10 — Process escape / descendants

**Threat.** The child spawns grandchildren; some inherit the environment
(covered) and some deliberately clear it (not covered).

**Position.** Environment inheritance is transitive by default, so
`npm run dev` → `node server.js` → `python worker.py` are all covered.
A descendant that explicitly resets its environment, or a program that ignores
proxy variables by design, is **not** covered. We say so rather than implying
process-tree enforcement we do not have. Enforcing it would require a network
extension / eBPF, which is out of scope and would violate "no machine-wide
capture".

## RO-11 — Resource exhaustion, oversized headers, Slowloris

| Vector | Bound |
|---|---|
| Concurrent connections | 64 (semaphore; excess `accept`ed then immediately closed with `503`) |
| Request/response head | 32 KiB total |
| Single header line | 8 KiB |
| Header count | 100 |
| Handshake deadline | 10 s |
| Head read deadline | 10 s |
| Idle (between requests) | 90 s |
| Total connection lifetime | 30 min (configurable) |
| Relay buffer | 16 KiB fixed, per direction |
| Leaf cert cache | 256 entries LRU |
| Internal queues | none — the relay is synchronous, so there is no queue to grow |

Slowloris is bounded by the head deadline plus the connection cap: 64 slow
connections is the maximum, and each dies after 10 s.

## RO-12 — Proxy crash behaviour

A panicking connection thread is caught at the thread boundary; the listener
thread never runs user-influenced parsing itself. A panic records a
compatibility result and marks the session partial. It cannot leave the child
with a half-open TLS connection that appears verified, because the socket is
closed on unwind.

## RO-13 — Vault lock during an active session

Covered in the architecture §9. The invariant asserted by
`tests/vault_lock.rs`: after a lock, (a) the listener refuses new connections,
(b) the CA key material is zeroized, (c) the session row's `status` is
`interrupted` with `reason = vault_locked`, (d) no event rows are written with
`at` after the lock time.

## RO-14 — Stale sessions, port reuse, PID reuse

- Sessions carry the ephemeral port **and** the launch-time process identity
  (reusing the existing hardened `inject::probe_process_identity`).
- A session row is only attached to by the launching process, in memory. There
  is no "attach to session by port" API, so a recycled port cannot be attached
  to.
- On startup, `store::sweep_orphaned_sessions` marks any `running` session
  whose recording process is gone as `interrupted / launcher_gone`, reusing the
  existing `sweep_dead_sessions` liveness convention (`ps -p`, exit code
  exactly 1 = definitively gone).

## RO-15 — CA removal, interrupted creation, orphaned certificates

- Generation writes the row in one transaction; a crash mid-generation leaves
  no row and the next start regenerates.
- `observe cert status` reports: present/absent, fingerprint, dates,
  system-trust installed/absent/**orphaned** (present in the OS store but not
  in the vault — e.g. the vault was deleted and recreated).
- `observe cert repair` re-installs when the vault has a CA the OS store lacks;
  `observe cert remove` removes from the OS store; orphan detection scans the
  OS store for certificates with our CN prefix and offers removal.
- Uninstall guidance is in the user docs, because deleting the app does **not**
  remove a system-trust entry.

## RO-16 — Logging and diagnostic leakage

The most likely way a metadata-only design leaks payloads is a debug log.

**Mitigations.**
- The observe crate has no logging framework and no `println!`/`eprintln!` of
  wire-derived data. Diagnostics emit fixed enum variants plus numbers.
- `CoreError` and the crate's own error type carry `&'static str` context, not
  formatted wire data — the same discipline already used across this codebase.
- `tests/privacy_no_leak.rs` drives a full monitored request whose URL, headers
  and bodies are stuffed with distinctive markers, then asserts every marker is
  absent from: the DB file bytes, WAL, stdout, stderr, every `Debug`/`Display`
  of every public type, every serialized DTO, every export, every temp file
  left behind, and the audit + activity tables.

## RO-17 — Path and query leakage

Query strings are removed **before** the value is constructed
(`sanitize::sanitize_path` splits on `?` and `#` and discards the remainder),
not filtered at display time. Fragments never reach the server anyway but are
stripped defensively. Path templating is property-tested (§3 of the privacy
model).

## RO-18 — Corporate proxy chaining

Chaining means Tethra's upstream connection goes through the corporate proxy,
so the corporate proxy sees exactly what it saw before (a `CONNECT` to the
provider). We do not send the corporate proxy anything additional, and we do
not send it our credentials. If the corporate proxy is itself MITM-ing, our
upstream verification will fail against `webpki-roots` — which is **correct
behaviour**; the user is told to add their corporate root, and we point at
`SSL_CERT_FILE`-style configuration rather than disabling verification.

## RO-19 — Multi-user and managed machines

- The listener is loopback-only, so a different machine cannot reach it.
- A different local user cannot read the token (the child's environment is
  readable only by the same user and root).
- On a managed machine, Mode C will typically be blocked by MDM policy. We
  detect the failure and report it plainly rather than retrying or escalating.
- We never request or use elevated privileges except through the OS's own
  authorization prompt in Mode C.

## RO-20 — Mode C blast radius (the one that matters most)

Installing a CA into the **system** trust store means *every* application on
the machine will trust certificates minted by that key — browsers, email
clients, package managers.

**Controls, all of which must pass:**
1. A dedicated explanation screen stating this in plain language.
2. Explicit user choice (not a default, not a checkbox pre-ticked).
3. Master-password reauthentication.
4. The **operating system's own** authorization prompt (macOS `security
   add-trusted-cert`, which prompts; Linux writes to the user's NSS/ca-
   certificates with the distribution's own tooling; Windows `certutil
   -addstore -user`).
5. Confirmation text covering: key stays local, payloads are not retained,
   removal is possible and how.

**Prohibited and not implemented:** any attempt to suppress, pre-authorize,
imitate, or work around the OS prompt; writing directly to keychain files;
using `sudo` with a cached credential; instructing the user to disable SIP or
Gatekeeper.

Mode C is scoped to the **user's** trust store where the platform offers one
(`certutil -addstore -user` on Windows, user NSS DB on Linux). On macOS
`security add-trusted-cert` without `-d` targets the login keychain, which is
per-user; the admin/system variant is not used.

---

## Summary of accepted residual risks

| ID | Residual risk | Accepted because |
|---|---|---|
| RO-1 | Memory-resident CA key readable by same-user malware while unlocked | Identical to every other vault secret; unfixable in local software |
| RO-2 | Same-user process can read the child's env and reuse the token | Token must reach the child somehow; bounded to one user account |
| RO-9 | QUIC/HTTP-3 bypasses the proxy entirely | Fixing needs a network extension; documented, detected, never hidden |
| RO-10 | Env-clearing descendants are invisible | Enforcing would need machine-wide capture, which is a product non-goal |
| RO-20 | Mode C is genuinely dangerous | Off by default, five independent gates, fully reversible, clearly explained |
