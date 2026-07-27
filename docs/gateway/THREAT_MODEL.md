# Local Gateway — Threat Model

Adversaries, assets, and the boundary of what this feature defends. Uses the
repository's existing conventions (`THREAT_MODEL.md` top-level; the observe
`RUNTIME_OBSERVABILITY_THREAT_MODEL.md` RO-N style). Threats are numbered
GW-N. "Accepted residual" means a real exposure the design does not close and
documents honestly rather than papering over.

## Assets

- API credential values passing through loopback (in memory, in flight).
- The vault fingerprint key, IF the matching toggle is on (in memory).
- Route/config integrity (which upstreams the gateway will reach).
- Observation metadata and extracted usage (in the vault DB).
- The user's outbound-egress posture (the gateway must not become a bypass).

## Adversaries (aligned with the repo's top-level table)

- **A1 Remote network attacker** — cannot reach a loopback-only listener.
- **A2 Malicious web page in the user's browser** — can issue cross-origin
  requests to `127.0.0.1:8787` (simple requests fire without preflight).
- **A3 Another local process, same user** — can connect to the port, read the
  DB (0600, same uid), and (when the service is down) attempt to bind the
  port.
- **A4 Malware running as the user** — explicitly OUT of scope in the
  repo-wide model (a process running as the user can already read the vault
  when unlocked, keylog, etc.). Recorded here only where the gateway would
  MEANINGFULLY WIDEN A4's reach beyond what it already has.
- **A5 Local file-access attacker (stolen disk / backup)** — reads the DB at
  rest.
- **A6 Another LOCAL USER on a shared machine** — a distinct uid on the same
  host; can reach `127.0.0.1:<port>` and race for the port when the service is
  down, but cannot read the 0600 DB or the 0600 control socket. This adversary
  is NEW to this feature (the repo-wide model had no shared-host row) and is
  the one D11's port-squat residual actually concerns.

## Threats

### GW-1 Open relay / SSRF (A2, A3) — DEFENDED
Forwards only to registered origins via first-path-segment match; no CONNECT,
no absolute-form, no client-chosen upstream; origins are https/443 and pass
the SSRF policy at registration and at connect time (validated `SocketAddr`,
DNS-rebinding closed). Unknown prefix → 404, no DNS. *Residual:* none beyond
reaching the SAME public provider origins the caller could already reach
directly.

### GW-2 Browser drive-by via loopback (A2) — DEFENDED (corrected)
A `text/plain` no-cors POST IS a CORS-simple request and fires with no
preflight, and `127.0.0.1:<port>` is a valid Host — so "JSON/Authorization
preflight" is NOT the defence (an earlier draft claimed it; the review's
`simple-request-write-primitive` finding corrected this). The actual defences:
(a) reject any request bearing `Origin`/`Referer`, `Sec-Fetch-Mode: no-cors`,
or `Sec-Fetch-Site` ≠ absent (Sec-Fetch-* are forbidden headers a page cannot
forge; no SDK sends them); (b) reject a CORS-safelisted Content-Type carrying
no credential header; (c) rejected requests write NO observation row, counter,
or alert (only a `rejected_browser_origin` counter) — so a page cannot
manufacture auth-failure alerts, inventory entries, or fingerprint which
providers/projects are configured (unknown prefix and unknown slug return an
identical 404); (d) no CORS headers emitted and relayed `Access-Control-*`
stripped, so responses stay opaque; (e) exact Host match. *Residual:* a page
can still cause credential-less requests to a provider (rejected as
unauthenticated); low impact, noted.

### GW-3 Route-table tampering (A3, A4) — DEFENDED (origins not obeyed from DB)
`gateway_routes` stores provider_id + link slug ONLY; the upstream origin is
NOT stored there. Manifest routes resolve the origin from the on-disk manifest
(install tree, not the same-uid DB); custom origins carry a MAC over
`(vault_id, provider_id, origin, port, consent_ts)` under a vault-derived key,
verified before forwarding, and are not forwarded while the vault has been
locked since boot. So a same-uid `UPDATE gateway_routes SET ...` cannot
redirect a live pass-through credential to an attacker origin — the earlier
free-form-origin design (the review's `route-row-tamper-credential-theft`
blocker) is removed. The two-phase SSRF check runs at load AND connect
(`resolve_validated`, dialing the validated `SocketAddr`), closing split-
horizon/rebinding origins that `check_authority` alone would pass. *Accepted
residual:* A4 (malware as the user, out of scope repo-wide) can still tamper
with the on-disk manifest or unlocked-session state, but A4 can already
intercept the user's clients directly; the gateway adds no capability A4 lacks.
Route writes through Tethra require an unlocked vault + re-auth and are audited.

### GW-4 Port squatting when the service is down (A3, A4) — MITIGATED, residual
A fixed port (8787) can be bound by another same-uid process while the service
is down, then receive cleartext requests carrying the caller's credential.
Mitigations: KeepAlive restart shrinks the window; `status` and the desktop
verify the listener's identity (same-uid PID + expected binary path) before
telling the user the gateway is healthy or writing `.env`; the port binds
`127.0.0.1` only. *Accepted residual:* a brief squat window exists; a
same-uid attacker who can squat the port can also already read the unlocked
vault and the clients' traffic. Multi-user machines: documented limitation.
(Randomized-stable-port is OPEN_DECISIONS O3 if the residual proves material.)

### GW-5 Credential capture from persistence (A5) — DEFENDED
No credential value, header value, body, prompt, query, or cookie is ever
persisted (structural: the record type has no field for them; sanitize severs
query/fragment). Raw-file canary tests prove absence on disk. *Residual:*
none for persisted data; the metadata that IS stored (hosts, path templates)
is the same class the repo already accepts (ADR 0018).

### GW-6 Fingerprint-key abuse (A3, A4, A5, A6) — MITIGATED, disclosed residual
The matching key, when resident, is a guess-confirmation oracle. Two attack
shapes, both now bounded: (1) ONLINE — any local caller replays guessed values
as `Authorization:` through the gateway and reads `matched` from the plaintext
attribution rows. Bounded by SCOPING the matcher table to linked,
non-password-locked projects (never vault-wide), so password-locked and
unlinked credentials are not oracles, plus an `unmatched`-rate counter
surfaced in status. (2) OFFLINE — key in memory + a DB/backup copy confirms
guesses for every in-scope fingerprint. Bounded by defaulting the "match while
locked" toggle OFF (attribution degrades to `unavailable_no_key`), and,
when ON, TTL-bounding the key to the pushing session's auto-lock so it never
outlives the vault key. The earlier "strictly weaker than reading live
headers" claim is RETRACTED (false on lifetime, scope, and capability — the
review's `fingerprint-key-in-locked-daemon` finding). *Accepted, disclosed
residual:* with the toggle ON and the key resident, a memory+DB attacker gains
an oracle over in-scope fingerprints; named on the consent screen. SIGKILL
leaves the key resident until page reuse (a SIGTERM handler clears it first);
core dumps/swap are out of scope, stated honestly.

### GW-7 Egress-control bypass (A4, sandboxed processes) — PARTIALLY WIDENED (corrected)
The earlier "equivalent to direct provider access; no privilege gained" claim
is FALSE wherever PER-APPLICATION egress control exists (Little Snitch/LuLu,
Windows Firewall per-program rules, uid/cgroup nftables) — the standard local
egress control. A process denied outbound 443 can still open loopback and have
`tethra-gateway` (which has an allow rule) perform the connection, DNS, and TLS
for it; same for a sandbox given host-loopback but no outbound policy. The
gateway does NOT tunnel arbitrary destinations (only registered public
origins). *Mitigation:* routes are individually enable/disable-able and a route
unused within a configurable window is auto-disabled, so a forgotten link does
not leave a permanent relay. *Accepted, disclosed residual:* the gateway is a
standing local egress relay to its registered origins and therefore bypasses
per-application (not per-user) egress controls — stated in the consent screen
and the ADR, not hidden behind a false equivalence.

### GW-8 Control-channel abuse (A3, A4, A6) — DEFENDED
The fingerprint-key handoff is a Unix-domain socket at
`<data-dir>/gateway.sock` (0600 in the 0700 dir) with a peer-euid == our-uid
check, write-only (no key read-back), plus a server nonce the pusher echoes. It
is NOT the TCP forwarding listener, and the key never crosses TCP, argv, or an
environment variable. So a local process (even same-uid, and certainly A6)
cannot push a chosen key (attribution poisoning) or read the key back over the
forwarding port. Re-push after a service restart requires an explicit
unlocked-session action, never an automatic retry against whatever is
listening. Windows v1 refuses key push rather than ship a TCP fallback.
*Residual:* A4 as the user is out of scope per the repo model.

### GW-9 Request smuggling / desync (A2, A3) — DEFENDED
TE+CL together, conflicting duplicate CL, and malformed framing are rejected,
not normalized-and-forwarded; 1:1 connection mapping removes cross-request
desync; bounds prevent Slowloris. *Residual:* none known; the CL+TE handling
is a hardening delta over observe's wire layer, tested (§2).

### GW-10 Availability / DoS (A2, A3) — BOUNDED
Connection cap + 503, bounded queues with drop-and-count, fixed relay buffer,
Slowloris deadline. A flood degrades recording (dropped, counted) but never
OOMs and never blocks forwarding. *Residual:* a local flood can still consume
CPU/sockets; loopback-only bounds the blast radius to the same user.

### GW-11 Dishonest coverage (product integrity) — DEFENDED
Gateway data is labeled locally-observed, never summed with provider sync;
coverage limits (local machine, repointed traffic only) are stated where data
is shown; "no traffic recorded" is never "no traffic". *Residual:* users may
still misread; mitigated by explicit UI copy and a "no traffic since link"
state (GW-13).

### GW-12 Cleartext-loopback credential capture (A2 via proxy, A4) — MITIGATED
Repointing to `http://127.0.0.1:...` makes the SDK speak plaintext, and some
clients (e.g. Python `requests`) route `http://` through an ambient
`HTTP_PROXY` without exempting loopback — sending the real key in cleartext to
a corporate/third-party proxy. *Mitigation:* the `.env` write also adds/extends
`NO_PROXY`/`no_proxy` to cover loopback (mirroring `observe::trust`), and the
link flow warns when `HTTP_PROXY` is set. *Accepted residual:* the credential
crosses a loopback socket in cleartext (capturable by anything sharing the host
network namespace); documented.

### GW-13 Silent no-coverage (product integrity) — MITIGATED
A base-URL line is inert for runtimes that never load `.env` (plain
Python/Node without dotenv, Go, shell) — traffic goes direct, dashboards stay
empty, the user believes monitoring is on. *Mitigation:* the link flow runs a
keyless end-to-end probe (an unauthenticated request through the route → a
provider 401 proves the path with no secret), records a persistent "no traffic
since link (N days)" state, and warns when the project has no dotenv loader or
a `docker-compose.yml` (containers reach their own loopback, a documented v1
non-goal).

## Out of scope (inherited from the repo-wide model)

Malware running as the user (A4) beyond the specific widenings analyzed above;
a compromised OS; physical access to an unlocked machine; supply-chain
compromise of dependencies (mitigated by the near-zero-new-dep policy and
lockfile pinning; no cargo-deny gate exists yet — PACKAGING future work).
