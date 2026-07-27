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

## Why database tampering cannot redirect your credentials

Manifest routes store **no origin in the database at all** — the upstream
is resolved from the compiled-in manifest at forward time. Custom origins
are stored only next to a MAC computed under a vault-derived key over the
origin's full identity; the gateway verifies the MAC before forwarding and
never obeys the bare row. A same-user process editing SQLite cannot make
`/openai/...` (with your key attached) go anywhere else.

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
  and memory; the gateway does not change that and does not claim to.
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
