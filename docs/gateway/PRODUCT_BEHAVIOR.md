# Local Gateway — Product Behavior

What the user experiences, exactly, and what the product does and does not
claim. Companion documents: `ARCHITECTURE.md` (how), `SECURITY_INVARIANTS.md`
and `PRIVACY_MODEL.md` (guarantees), `THREAT_MODEL.md` (adversaries),
`IMPLEMENTATION_PLAN.md` (stages), ADR 0019 (why).

## The problem

Tethra can observe a single explicitly-launched process (`tethra run`,
ADR 0017) and can sync provider-reported usage where an admin credential
exists (ADR 0011). Neither covers the common case: a developer runs their
project from an IDE, a terminal, a task runner, or a launcher, wants Tethra to
know which APIs it calls and roughly what it spends — without launching
through a wrapper, installing an SDK, trusting a local root certificate, or
keeping a terminal open.

## The user flow

1. **Save a credential** in Tethra (unchanged, existing flow).
2. **Enable Local Gateway** — one explicit action in the desktop app or
   `tethra gateway enable`. A consent screen states, before anything is
   installed: a background service will run at login; what it does (forwards a
   loopback port to the providers you register, records metadata and token
   counts, never bodies or credentials); that any program on this machine can
   use the port and that its credentials pass through the gateway's memory
   (never stored); that the gateway is a standing local egress relay to your
   registered providers (so it can reach them on behalf of a process a
   per-application firewall blocked); exactly which files are created (and, on
   macOS, that the OS will show a Login-Items entry); the optional "keep
   matching credentials while the vault is locked" toggle (OFF by default,
   with its exact consequence shown at the moment it is switched on); and how
   to remove all of it — restoring your `.env` files — with one action. The
   enable dialog offers to link the first project immediately, so it never
   ends with an enabled service and zero routes.
3. **Link a project to a provider route** — pick a project, pick a provider
   (or a custom origin, e.g. a Supabase project URL). Tethra shows the exact
   `.env` change — the gateway line shown UNMASKED so the port and slug are
   verifiable — and applies it on confirmation. The base path is
   provider-correct (the `/v1` placement differs per provider because SDKs
   join URLs differently):

   ```
   # tethra-gateway route: openai (project: my-web-app) — remove this line if
   # 127.0.0.1 refuses connections, or run: tethra gateway status
   OPENAI_BASE_URL=http://127.0.0.1:<port>/p/<slug>/openai/v1
   NO_PROXY=127.0.0.1,localhost,::1
   ```

   (Anthropic's SDK sends `/v1/messages` itself, so `ANTHROPIC_BASE_URL` ends
   at `.../anthropic` with no `/v1`. Tethra writes the correct form and any
   known aliases, e.g. `OPENAI_API_BASE` for litellm/aider.)

4. **Run the project normally.** Any client honoring the provider's base-URL
   variable sends ordinary HTTP to loopback; the gateway forwards it to the
   real provider over certificate-verified HTTPS with the caller's own
   credential passed through untouched. Streaming (SSE) works; provider
   errors arrive verbatim. At link time Tethra runs a keyless probe through
   the route to confirm the path actually reaches the provider, and flags a
   NODE project whose `package.json` never mentions a dotenv loader. Python,
   Go, and shell projects are NOT detected — the heuristic is Node-only, and a
   project in those languages that never loads `.env` will silently produce no
   gateway traffic. Those need the variable set another way, or the gateway
   sees nothing.
5. **See it in Tethra.** The activity screens show gateway-observed services,
   endpoints (sanitized templates), statuses, latency, and — for supported
   response shapes — model and token counts with estimated (never asserted)
   cost, labeled as locally observed.

The user does NOT need to: install an SDK, launch through a wrapper, keep a
terminal open, install a root certificate, grant Tethra access to unrelated
files, grant provider write permissions, or send anything to a hosted Tethra
service (none exists).

## What each piece does when things are off

| Situation | Behavior |
|---|---|
| Vault locked | Forwarding continues unchanged. Metadata still recorded. Credential attribution degrades honestly to `unavailable_no_key` (the "match while locked" key toggle is OFF by default). A compact status strip on the lock screen — driven only by lock-free commands — shows running / recording / degraded, so the state is never silent even though the main UI requires unlock. Custom-origin (non-manifest) routes return 503 while the vault has been locked since boot (their origin MAC cannot be verified); manifest routes forward normally. |
| Vault database missing/busy/newer schema | Forwarding continues on the last-known-good route table; recording pauses/drops with visible counters; status shows "recording degraded", never silently. |
| Gateway service stopped or crashed | The OS service manager restarts it (KeepAlive). While it is down, linked projects' API calls fail fast with connection-refused — Tethra surfaces this state in status and offers unlink/repair. This failure mode is the honest cost of the design and is disclosed at link time. |
| Route's provider unreachable | The provider error / transport failure is relayed to the client exactly as a direct connection would produce. |
| Unlinked traffic hits a bare route prefix | Forwarded normally; counted at route level; shown as "unlinked traffic" (no project attribution invented). |
| Request for an unregistered prefix | `404` from the gateway; nothing forwarded (never an open relay). |
| WebSocket / HTTP upgrade requested | `501` with a clear body; documented limitation (v1). |

## Honest coverage statement

The gateway sees ONLY traffic whose base URL was repointed at it, from
processes on this machine that load the variable into their environment. It
does not see: production or remote-machine traffic, tools that ignore the
provider's base-URL variable or construct their own URLs, hardcoded endpoints,
**containerized runs** (inside a container `127.0.0.1` is the container's own
loopback — a documented v1 non-goal), or providers without a linked route.
Absence of recorded traffic is never evidence of absence of traffic.
Provider-side usage sync (where an admin credential exists) remains the only
source for account-level truth and remote coverage; the two sources are
labeled distinctly and never summed.

The compatibility target is the mainstream SDKs that honor a base-URL variable
(OpenAI Python/JS `OPENAI_BASE_URL` / `OPENAI_API_BASE`, Anthropic
`ANTHROPIC_BASE_URL`, plus explicit client `base_url` parameters). **Shipped scope, corrected:** the link screen shows the generic coverage
caveat plus two heuristic warnings — a Node project whose `package.json` never
mentions `dotenv`, and a `docker-compose.yml` next to the project. It does NOT
name individual tools. A per-tool note naming the Vercel AI SDK, `curl`
scripts, and hardcoded clients was specified here but never implemented;
`COVERAGE_LIMITATIONS.md` carries the accurate list and is the document to
read for what the gateway can and cannot see.

## Uninstall / disable

One ordered action, so disabling the OPTIONAL feature never bricks a linked
app: stop/bootout/unregister the service → remove the service registration
(plist / systemd unit + wants-symlink + daemon-reload / task) → **restore
every `.env` line the gateway rewrote** (original values and `no_proxy` state
recorded at link time; `--keep-env` to leave them) → delete the copied
binaries (all versions) and service logs → keep DB rows (user data). If any
`.env` restore fails (file moved, drifted), it is reported per-project, never
silently skipped. `tethra gateway status` lists every artifact the feature
owns. Deleting the app without disabling first is detected: the service
self-unloads when its data directory / vault.db disappears.

## Explicit non-goals (v1)

- Not a credential injector: clients keep using their own keys; the vault is
  never required to complete a request (a possible future opt-in
  "key-brokering" mode is ADR 0019 future work, unlocked-vault-only).
- Not a general proxy: no CONNECT, no absolute-form targets, no
  user-configurable non-provider upstreams beyond validated custom origins.
- Not a replacement for the interception proxy (`tethra run`): that remains
  the tool for observing a process that cannot be repointed; the gateway
  supplements it and neither deletes nor disables it.
- No HTTP/2 or gRPC client-side; no WebSockets (documented limitations).
