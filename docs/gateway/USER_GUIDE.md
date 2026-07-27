# Local Gateway — User Guide

> **Most people should not need this document.** The Local Gateway is the
> infrastructure underneath **Track API activity** (desktop) and
> `tethra track .` (terminal), both of which install the service, create
> routes, edit environment files, and enable credential attribution for
> you — no route prefixes, no linking step, no separate attribution
> command. Start with
> `docs/activity-onboarding/USER_GUIDE.md`.
>
> This document is the **advanced / expert** surface: the low-level
> commands and the Gateway internals panel, for diagnostics,
> troubleshooting, and configurations the automatic flow does not cover.
> Everything here still works and is fully supported — the automatic flow
> writes through these same APIs, so hand-made and automatic
> configuration stay interoperable.

How to enable, use, inspect, and remove the Local Gateway, as it actually
works in this build. Companion documents: `TROUBLESHOOTING.md` (when
something is wrong), `PRIVACY.md` and `SECURITY.md` (what is recorded and
how it is protected), `COVERAGE_LIMITATIONS.md` (what the gateway does NOT
see or claim).

## What it is

The Local Gateway is an **optional** background process that listens only on
`127.0.0.1` and forwards API traffic from projects you explicitly link to
the providers you register (OpenAI, Anthropic, or a custom origin such as
your own Supabase project host). While forwarding, it records **metadata
only** — status codes, latency, sizes, sanitized path templates, and bounded
token counts when a provider response carries them. It never stores API
keys, authorization headers, query values, prompts, request bodies, or
response bodies.

It is off until you enable it, sees only traffic whose base URL points at
it, and one action removes it and restores your `.env` files.

## Enabling from the desktop

Open the **Gateway** panel. If the gateway is not installed you will see the
consent card. Read it — it names every file that will be created, the macOS
Login Items entry, and the honest cautions (any local program can use the
loopback port; the gateway is a standing local egress relay to your
registered providers). Then:

- **Enable Local Gateway** — installs the per-user login service and starts
  it after one confirmation.
- **Not now** — nothing is installed; the card stays available.
- **Learn more** — expands the full file list and cautions.

Honest requirement: the desktop app does not bundle the CLI binary, and the
gateway service *is* the CLI binary. If no runnable `tethra` CLI is found on
this machine, enabling stops with a clear message and installs nothing —
install the Tethra CLI archive first (see `docs/INSTALL.md`), then enable
again.

Enabling creates exactly:

- a service definition (macOS: `~/Library/LaunchAgents/dev.api-tracker.gateway.plist`;
  Linux: `~/.config/systemd/user/tethra-gateway.service`; Windows: an HKCU
  `Run` registry value),
- a copy of the CLI binary at `<data-dir>/bin/tethra-gateway-<version>`,
- a log file directory at `<data-dir>/logs/`.

On macOS the service also appears under **System Settings → General →
Login Items** as a background item — that entry is this gateway.

## Enabling from the CLI

```
tethra gateway install        # `enable` is an alias
```

The command prints the same consent summary, asks for confirmation (pass
`--yes` in scripts), chooses a stable random port on first enable, installs
and starts the service, and then verifies the gateway actually answers its
identity probe before claiming success.

## Adding routes

A route maps the first path segment of a gateway URL to one provider
origin. Nothing forwards without a route.

```
tethra gateway route add openai           # manifest route: origin comes from
tethra gateway route add anthropic        # the compiled-in provider manifest
tethra gateway route add supabase --origin https://xyzcompany.supabase.co
tethra gateway route list
tethra gateway route disable openai       # requests answer 404 until enabled
tethra gateway route enable openai
tethra gateway route remove openai
```

Providers with a fixed API origin (OpenAI, Anthropic) need no origin
argument. Providers whose origin is per-project (Supabase) must be given
their exact origin; it is validated (https, port 443, public address) and
integrity-protected so a later database edit cannot redirect your traffic.

The desktop **Routes** tab does the same with a form, and explains when a
provider requires a custom origin.

## Linking a project

Linking rewrites the project's `.env` so its SDK sends traffic through the
gateway. You always see the exact change before anything is written.

```
tethra gateway link --project my-app --route openai --env-file /path/to/my-app/.env
```

(`--dir /path/to/my-app` uses/creates that directory's `.env`; when the
project has exactly one registered repository path, it is the default.
`--dry-run` shows the diff and stops. `--env-file` may repeat for multiple
files.)

What gets written, per provider:

- OpenAI: `OPENAI_BASE_URL` and the `OPENAI_API_BASE` alias, both set to
  `http://127.0.0.1:<port>/p/<slug>/openai/v1` (OpenAI SDKs join the base
  with `/chat/completions`, so the base must end in `/v1`).
- Anthropic: `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>/p/<slug>/anthropic`
  — no `/v1`, because the Anthropic SDK sends `/v1/messages` itself.
- Providers that declare no base-URL variable: pass `--var NAME` explicitly.
- `NO_PROXY=127.0.0.1,localhost,::1` is added (or your existing
  `no_proxy`/`NO_PROXY` is extended in place) so loopback traffic never
  detours through a corporate proxy.

Every line the writer owns sits under a marker comment:

```
# tethra-gateway route: openai (project: my-app) — remove this line if 127.0.0.1 refuses connections, or run: tethra gateway status
```

Everything else in the file — comments, ordering, quoting, blank lines,
CRLF endings, even duplicate keys — is preserved byte-for-byte. The diff
shows the gateway lines unmasked (you are approving that exact URL) while
other values stay masked. `.env.example` generation skips gateway-marked
lines: the port and slug are machine-local wiring, not something
collaborators should copy.

After a link is applied, Tethra runs a **keyless probe**: one
credential-free GET through the gateway. A provider `401` proves the path
works end to end without ever using your key. If the gateway is not
running, the link still applies but the probe is skipped and you are told
the SDK will get connection-refused until the gateway starts.

Until the project actually sends traffic, activity for it honestly reads
**no traffic since link** — the gateway only ever sees traffic whose base
URL points at it.

## Reading activity

- Desktop → Gateway → **Activity**: requests, success/error rates,
  p50/p95/p99 through-gateway latency, bytes, top (sanitized) endpoints,
  attribution states, and tokens/models/estimated cost where responses
  carried usage. Every figure is labeled **locally observed**; an empty view
  is never evidence of zero provider usage.
- Credential detail → **Activity**: last activity split by source — locally
  observed by gateway, locally observed by proxy, provider-reported
  (synced), manually marked, last validated — plus the most recent of those
  with its source named.

Local numbers are never summed with provider-reported usage, and gateway
spend estimates are lower bounds (see `COVERAGE_LIMITATIONS.md`).

## Credential attribution (optional)

By default the gateway records exchanges without knowing which vault
credential was used (`unavailable_no_key`). To label traffic:

```
tethra gateway push-key        # or desktop → Gateway → "Enable attribution…"
```

This is reauthenticated (master password) because it hands the gateway a
derived **matching-only** key. The key cannot decrypt anything, but while it
is resident a process that can read the gateway's memory gains an oracle for
testing whether a value matches one of your credentials — that is why it is
off by default, why pushing it is an explicit act, and why it is dropped on
stop, revoke, or vault lock (the keep-while-locked toggle also defaults
OFF). Revoke any time:

```
tethra gateway revoke-key
```

## Day-2 operations

```
tethra gateway status     # summary: service, process, identity, routes, links
tethra gateway doctor     # full diagnosis with repair hints
tethra gateway start
tethra gateway stop       # graceful drain when reachable
tethra gateway restart
tethra gateway repair     # re-copy binary, rewrite definition, re-register, restart
tethra gateway recording pause|resume
```

`status` and `doctor` never need the vault password, and the desktop lock
screen shows a one-line gateway strip — forwarding continues while the
vault is locked, and the UI says so.

Foreground mode (no service at all):

```
tethra gateway serve      # `run` is an alias; Ctrl-C or `tethra gateway stop` ends it
```

## Unlinking

```
tethra gateway unlink --project my-app --route openai
```

Restore is exact and conservative in your favor:

- a variable that existed before linking gets its old value back;
- a line Tethra created is removed (marker comment included);
- a value **you changed after linking** is left alone and reported;
- if a file cannot be rewritten, the link is kept so you can retry — a
  failed restore is never silently skipped.

## Disable vs uninstall

```
tethra gateway disable     # stop + unregister; restores linked .env files
tethra gateway uninstall   # disable + remove binaries, logs, runtime files
```

- **Disable** is "off": the service stops and is unregistered, linked `.env`
  files are restored (pass `--keep-env` to skip, with a warning that linked
  SDKs will then get connection-refused), binaries and all recorded history
  stay.
- **Uninstall** additionally removes `<data-dir>/bin/` (all versions),
  `<data-dir>/logs/`, and stale runtime files. Recorded history stays in
  your vault database — it is your data. `tethra gateway status` lists every
  artifact the feature owns, so you can verify nothing is left behind.

Both warn about linked projects first and offer the `.env` restore before
anything stops.

## Platform notes

- **macOS** — a per-user LaunchAgent (never a root daemon). On unsigned
  alpha builds, Gatekeeper may kill the installed binary; the install runs
  an execution probe *before* registering anything, and if the probe is
  blocked it fails honestly and points you at foreground mode
  (`tethra gateway serve`) or System Settings → Privacy & Security to allow
  the binary.
- **Linux** — a systemd *user* unit (`WantedBy=default.target`). It starts
  at login and, unless lingering is enabled for your user, stops at logout.
  Tethra reports this state but never changes it; `loginctl enable-linger`
  is your call.
- **Windows** — the lifecycle code (HKCU `Run` value, per-user, no admin)
  compiles and is unit-tested in CI, but has **never been executed on a real
  Windows machine**. Every status surface says so. The supported mode on
  Windows is foreground `tethra gateway serve`; credential attribution is
  unavailable there by design (no control socket, and the gateway refuses to
  fall back to an unauthenticated TCP channel).
