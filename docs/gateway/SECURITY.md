# Local Gateway — Security

The security properties a user or reviewer should know, in plain terms.
The binding engineering statements are `SECURITY_INVARIANTS.md` (SI-1..SI-21,
each enforced by construction and tests) and `THREAT_MODEL.md`
(GW-1..GW-13); ADR 0019 records why each decision was made.

## The listener

- **Loopback only, always.** The gateway binds `127.0.0.1` — never
  `0.0.0.0`, never a configurable interface. There is no setting to change
  this; the configuration surface was deliberately removed, and a
  source-guard test fails the build if a wildcard bind ever appears.
- **Not a proxy.** Only origin-form requests to registered route prefixes
  are forwarded. `CONNECT` is refused, absolute-form targets are refused,
  protocol upgrades (WebSocket, h2c) are refused, and an unknown prefix or
  link slug gets an identical 404 so nothing about your configuration can
  be enumerated.
- **Browser-shaped requests are refused** (`Origin`/`Referer`/`Sec-Fetch-*`
  markers, and the no-preflight `text/plain` write primitive), and a
  rejected browser request produces **no** observation row — a web page
  cannot manufacture inventory entries or fingerprint your providers.
- Request smuggling shapes (TE+CL, duplicate CL, bare-LF chunk framing) are
  **rejected, never normalized and forwarded**.

## Where traffic can go

- Upstreams are **https on port 443 only**, and only origins that came from
  the compiled-in provider manifest or a user-consented custom origin.
- Every origin passes the SSRF policy twice: by name at registration and
  load, and **by resolved IP address at connect time** — a public DNS name
  that resolves into loopback/private/link-local/metadata space is refused
  at the socket, connecting only to the validated address.
- Upstream TLS is **fully verified** (system roots, real hostname
  verification); there is no permissive-verifier code path anywhere in the
  crate, enforced by a source-level guard test.
- The gateway terminates **no TLS toward clients** and holds no CA key —
  unlike the interception proxy, it has no man-in-the-middle surface.

## What database tampering can and cannot do to your routes

This section used to claim that editing `vault.db` could not redirect your
credentials. That claim was wrong, and correcting it is finding **NEW-49**
(the underlying behaviour is **SEC-01**). What follows is the measured
behaviour.

**What the route table cannot do.** No free-form destination can be injected
into it. `gateway_routes` holds no origin that is obeyed as typed: a built-in
route resolves its upstream from the compiled-in provider manifest in the
install tree, and a custom origin is stored next to a MAC computed under a
vault-derived key over the route's full identity (vault id, route prefix,
provider id, origin host, port, consent timestamp). The gateway verifies that
MAC before forwarding and never obeys the bare row, so **editing a stored
custom origin stops the route rather than redirecting it** — the route reports
`MacMismatch` and forwards nowhere. An attacker cannot write
`custom_origin = 'attacker.example.com'` and have traffic follow it, and
cannot invent a provider that does not ship with Tethra (an unrecognized
`provider_id` fails closed and the route is skipped).

**What it can do.** A built-in route selects its destination by `provider_id`,
and `provider_id` is read straight from the row without any authenticated
binding. So software that can already write your `vault.db` can:

- **reassign a built-in route to a different shipped provider.**
  `UPDATE gateway_routes SET provider_id='anthropic' WHERE route_prefix='openai'`
  makes `/openai/...` forward to `api.anthropic.com` — with your OpenAI
  credential still attached, because the gateway is a pass-through and relays
  the credential your client sent. The reachable destinations are the eleven
  forwardable origins compiled into the shipped provider manifests, not an
  attacker-chosen host; but a credential arriving at the wrong trusted provider
  is still a credential disclosure.
- **downgrade a custom route to that same unauthenticated path.** The MAC is
  selected by the *shape* of the row, not by a recorded route kind: nulling
  `custom_origin`, `custom_origin_port`, `custom_origin_mac` and
  `custom_origin_consent_at` together (which the schema's CHECK constraints
  permit) moves the row onto the built-in path, where the MAC is never
  consulted. The attacker does not forge the MAC; they delete it. So "the
  custom origin is integrity-protected" holds **only for as long as the row is
  still a custom row**.

These are genuinely different capabilities and this document keeps them
distinct: arbitrary custom-destination injection is prevented; reassignment
among origins Tethra already trusts is not.

**Disposition: accepted risk, not a defence.** Every path above requires local
write access to `vault.db`. An attacker who has that can equally replace the
Tethra binary, rewrite the LaunchAgent definition, edit the compiled-in
manifests in the install tree, or read the running process's memory — the
credential is reachable by simpler means than a `provider_id` swap. That
adversary is out of scope for this product, not defended against by it:
`THREAT_MODEL.md` records that metadata edits are **not** cryptographically
detected, and `provider_id` is metadata. The full statement is
`docs/activity-onboarding/SECURITY_AND_PRIVACY.md`, section *"Correction
(2026-07-28, post-final-re-audit): the local-database attacker"*.

**Tethra does not claim to detect or resist tampering with its own database by
software already running as you.**

*Follow-up, deliberately not bundled here:* an additive `route_kind` column
would let a stripped custom row fail closed instead of silently downgrading.
It would close the accident and raise the bar by one step; it would **not**
move the threat boundary, because `route_kind` is itself unauthenticated. It
is tracked separately so that a partial mitigation is never again described as
protection — that is how the claim this section replaces came to be written.

## The control channel

Privileged operations (status, key push/revoke, route reload, pause, stop)
arrive only over a Unix-domain socket, mode 0600 inside the 0700 data
directory, re-verified on every accept. Callers must echo a per-boot nonce
from a 0600 file — which also authenticates the *gateway* to the caller, so
a socket squatter cannot harvest a pushed key. The key channel is
**write-only**: the protocol has no message capable of returning key
material. On Windows there is no control channel, and the gateway **refuses
key push** rather than falling back to an unauthenticated TCP port.

## Listener identity

Status, doctor, and every `.env` write verify the listener's identity with
a challenge–response probe: the listener must answer with a proof derived
from the per-boot nonce, which never crosses the TCP socket. A process
squatting on the gateway's persisted port is therefore detected as
`port_collision` instead of being trusted — a PID or binary-path check was
rejected in design as unimplementable without races.

## The service

- Per-user only: a macOS LaunchAgent (never a root LaunchDaemon), a systemd
  *user* unit (never a system service), an HKCU Run value (no elevation).
- No secrets in service definitions, argv, environment blocks, or the
  registry — the definition carries only the binary path and `--data-dir`.
- Definitions are written 0600; the installed binary is a fresh byte-write
  (never `fs::copy`, which would propagate macOS quarantine into a launchd
  crash loop) and is execution-probed **before** any definition points at
  it.
- The service reads configuration through a schema-checked open and never
  applies migrations; a database from a different build degrades recording
  instead of being written.

## Honest residual risks

- **Same-user malware.** Anything running as your user can read your files
  and memory; the gateway does not change that and does not claim to. It can
  also rewrite `gateway_routes` to point a built-in prefix at a different
  shipped provider, or strip a custom route's authenticated columns — see
  *What database tampering can and cannot do to your routes* above (SEC-01).
- **The memory oracle while attribution is on.** Documented in
  `PRIVACY.md`; default off, revocable, dropped on lock.
- **A standing local egress relay.** Any local program can use the loopback
  port, and a process blocked by a per-application firewall could still
  reach your registered providers through the gateway. This is disclosed at
  consent time; routes can be disabled individually and the whole feature
  removes with one action.
- **Unsigned alpha builds on macOS.** Gatekeeper may block the service
  binary; the install fails honestly toward foreground mode rather than
  leaving a crash-looping agent.
- **In-process hygiene is best-effort.** Zeroized buffers do not defeat
  swap or core dumps.
