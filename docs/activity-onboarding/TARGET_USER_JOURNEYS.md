# Target User Journeys — Screens, States, and Exact Language

Concrete UI and CLI behavior for the redesigned tracking flow. Strings in
this document are the intended shipping strings; implementation may adjust
layout, never honesty.

## 1. Desktop information architecture

The flat 17-entry top bar becomes three groups (final shell layout to be
coordinated with PR #14's sidebar redesign — see `OPEN_DECISIONS.md`
O-22-8):

```text
ACTIVITY  (default view)
  Dashboard            ← the product's home
  [Track API activity] ← the primary action, always visible

VAULT
  Projects · Credentials · Providers · Env files · Templates · Backup

SECURITY
  Scan · Rotation · Temporary access · Destinations · Sync plans ·
  Alerts · Notifications

ADVANCED
  Gateway internals (today's Gateway view, unchanged) ·
  Observation runs (today's API activity view) ·
  Pricing · Usage records · Settings · Diagnostics
```

Nothing is deleted. "Usage" (provider-reported) merges into the Dashboard
as a clearly labeled, never-summed section; its management screens move to
Advanced.

## 2. Journey A — first-time tracking, existing Tethra project

### A1. Dashboard, empty state (no tracking configured)

```text
No API activity yet.

Tethra can watch a project's API traffic locally and show requests,
errors, latency, tokens, and estimated cost — metadata only, never
prompts, keys, or bodies.

[Track API activity]
```

### A2. Folder selection

Native folder picker (`@tauri-apps/plugin-dialog`), title:
"Select the project folder to track". If the folder matches a registered
project repo path (canonicalized comparison), that project is preselected;
otherwise:

```text
This folder isn't part of a Tethra project yet.
Create one?   Project name: [<folder basename>]        [Create and continue]
```

### A3. Scanning (transient state: `scanning`)

```text
Scanning <folder>…
Only this folder is read. Nothing is uploaded or executed.
```

Scan is bounded (depth 6, 256 KiB/file caps) and typically sub-second;
the state exists so failures have a home. Scan errors render inline with
[Retry] — never a silent empty result.

### A4. Review screen (state: `ready_to_configure`)

One screen. Header:

```text
Tethra detected 8 APIs in <folder>:
6 can be configured automatically
1 needs confirmation
1 is not currently supported
```

Provider list (each row: provider icon-less name, confidence, evidence in
plain words, checkbox where applicable):

```text
✓ OpenAI        — will be tracked
    Found OPENAI_API_KEY in .env and the openai package in package.json
✓ Anthropic     — will be tracked
    Found ANTHROPIC_API_KEY in .env
☑ Supabase      — likely; confirm its project URL
    Found SUPABASE_URL=https://xyzcompany.supabase.co in .env
    Traffic will be forwarded only to this exact address.
☐ <possible provider row, unchecked by default>
✗ Stripe        — detected, not currently supported
    The Stripe SDK does not read a base-URL environment variable, so
    Tethra cannot observe it this way yet. Everything else still works.
```

Environment changes section — the exact `envlink` diff, gateway lines
unmasked, all other values masked, per file, with the existing warning
strip (git-tracked file, Docker Compose present, no dotenv loader
detected → each warning rendered as a sentence with its consequence).

What-will-happen section (the disclosure from `PRODUCT_BEHAVIOR.md`,
primary card, file list included — not behind "Learn more"):

```text
Starting tracking will:
• run a local background service on 127.0.0.1 (starts at login;
  on macOS it appears in System Settings → Login Items)
• create: ~/Library/LaunchAgents/dev.api-tracker.gateway.plist,
  a helper binary copy and logs under Tethra's data folder
• apply the file changes shown above
• record request metadata: provider, endpoint template, status, latency,
  sizes, token counts and models when responses carry them
It will never record API keys, authorization headers, cookies, query
values, prompts, request bodies, or response bodies.
Note: any local program can send traffic to the loopback port; the
service is a standing local relay to the providers listed above.
```

Attribution field:

```text
Label traffic with which stored credential was used (recommended)
Master password: [________]   (leave empty to skip — you can enable this later)
```

Buttons: `[Start tracking]` `[Cancel]`
Validation: nothing to configure → the button is disabled and the header
explains why (see Journey D).

### A5. Applying (state: `applying`)

Progress list, each step rendered with ✓ / spinner / ✗ and honest failure
text; failures stop the sequence, completed steps are reported, and
[Undo what was done] is offered:

```text
✓ Local service installed and running
✓ Provider routes created (openai, anthropic, supabase)
✓ .env updated (2 files)
✓ Path check passed — the gateway can reach api.openai.com
⠿ Enabling credential attribution…
```

The "path check" is the existing keyless probe, run per configured route.

### A6. Waiting for restart / first request (states: `awaiting_restart`, `awaiting_first_request`)

If the scan found evidence the project loads `.env` at startup (dotenv
loader, framework default), and no traffic arrives within 10 s:

```text
Almost done — one step left, in your project:

Restart your app, then make one API request.
Waiting for traffic…                                [Run diagnostics]
```

The screen polls the orchestrator (2 s interval). On the first observed
exchange:

```text
✓ Tracking verified
  Anthropic request observed from <project> (201 ms, claude-fable-5)

[Open dashboard]
```

`partially_observed` variant (some providers seen, others not, after the
waiting window):

```text
Tracking verified for OpenAI and Anthropic.
No Supabase traffic observed yet — this is normal if the app hasn't
called it. Tethra keeps watching.
```

### A7. Diagnosis (state: `needs_attention`)

Entered when the user clicks [Run diagnostics] or nothing arrives in 120 s.
Renders ranked, evidence-based findings (each maps to an orchestrator
check, `TRACKING_ORCHESTRATOR.md` §Verification):

```text
No traffic has reached Tethra yet. Most likely causes, checked in order:

1. The project hasn't been restarted — a running process keeps its old
   configuration. Restart it, then make one request.
2. This project runs with Docker Compose (docker-compose.yml found).
   Containers don't see this machine's .env change or 127.0.0.1.
   [How to track a Docker project]
3. The variable OPENAI_BASE_URL is also set in `.env.production`, which
   may override the file Tethra edited.
4. No dotenv loader was detected in package.json — if the app doesn't
   read .env files, export the variable in the environment that runs it.
5. The gateway itself is healthy (path check passed 2 minutes ago).
   [Re-run path check]
```

Never a blank screen; if every check passes, say so:

```text
Everything on Tethra's side checks out. The gateway is running, routes
are live, and the path check succeeded — no request has arrived yet.
```

## 3. Journey B — attribution degrades later

Vault locks → matching key drops (ADR 0020). Dashboard banner:

```text
Credential attribution paused — traffic is still recorded.
Unlock the vault to resume labeling requests with their credential.
```

After unlock, if reauthorization is genuinely required:

```text
[Resume attribution]  → master password dialog (existing ReauthDialog)
```

Forwarding and metadata recording continue throughout; no shell
instructions anywhere in this path.

## 4. Journey C — stop / undo

Dashboard → project card → `Stop tracking…`:

```text
Stop tracking <project>?
• Restores .env to its recorded pre-tracking state (your later edits
  are kept and reported)
• Removes this project's routes if no other project uses them
• Keeps all recorded history (it's your data)
The background service keeps running if other projects use it;
otherwise you can turn it off under Advanced → Gateway internals.

[Stop tracking]  [Cancel]
```

CLI: `tethra track undo` — same semantics, same report format as
`envlink::UnlinkReport` (restored / left-your-edit / already-restored per
variable).

## 5. Journey D — nothing detected

```text
No trackable APIs detected in this folder.

Tethra looked at .env files, package manifests, and lockfiles in
<folder> (6 levels deep, nothing executed or uploaded).

• Using a provider Tethra doesn't support yet? [See supported providers]
• Expected a detection? [Review what was scanned]
• Know the provider and its base URL? [Configure manually]
```

[Configure manually] opens the Advanced route/link forms — the expert path,
one click away but never in the way.

## 6. CLI journey — `tethra track .`

```text
$ tethra track .
Tethra — track API activity

Project: my-app  (matched this folder to the existing project 'my-app')
Scanned: /Users/dev/my-app  (folder only; nothing executed or uploaded)

Detected:
  openai      confirmed   OPENAI_API_KEY in .env; openai in package.json
  anthropic   confirmed   ANTHROPIC_API_KEY in .env
  supabase    likely      SUPABASE_URL=https://xyzcompany.supabase.co
  stripe      unsupported no configurable base URL in the Stripe SDK

Will do:
  1. install + start the local tracking service (per-user, loopback-only)
  2. create routes: openai, anthropic, supabase → https://xyzcompany.supabase.co
  3. edit .env (diff below), adding NO_PROXY for loopback
  4. enable credential attribution (asks for your master password)

--- .env ------------------------------------------------------------
+ OPENAI_BASE_URL=http://127.0.0.1:49152/p/9f2c…/openai/v1   # tethra-gateway …
  <full envlink diff, gateway lines unmasked, other values masked>
---------------------------------------------------------------------
Warnings:
  ! docker-compose.yml present — containers will not see this change.

Proceed? [y/N] y
Master password (Enter to skip attribution): ********

✓ service installed and running (port 49152)
✓ routes created: openai, anthropic, supabase
✓ .env updated (1 file)
✓ path check: provider reachable through the gateway
✓ credential attribution enabled

Restart your app, then make one API request.
Waiting for traffic (Ctrl-C to stop waiting; tracking stays on)…
✓ Tracking verified — openai request observed from my-app (312 ms)

Dashboard: open the Tethra app, or run `tethra track status`.
```

Behavior notes:

* No session/export choreography: `track` prompts for the master password
  itself when needed (existing `ctx` prompt machinery); it never prints
  `eval "$(tethra unlock --print-export)"`.
* `--dry-run` prints everything through the diff and warnings, changes
  nothing (including no project creation), exit 0.
* `--yes` answers the proceed prompt; attribution is then included only if
  `TETHRA_PASSWORD` is set, otherwise skipped with a note.
* `tethra track status` prints the state machine value, per-provider
  observation freshness, and the current diagnosis list (same engine as
  the desktop).
* `tethra track undo` = Journey C.
* Exit codes: 0 configured-and-verified (or dry-run), 2 configured but
  unverified (waiting window elapsed), 1 error.

## 7. State transitions (authoritative)

```text
not_configured --scan--> scanning --ok--> ready_to_configure
scanning --error--> not_configured (error shown)
ready_to_configure --none-detected--> unsupported (Journey D)
ready_to_configure --start--> applying
applying --all-steps-ok--> awaiting_restart | awaiting_first_request
applying --step-failed--> needs_attention (partial-apply report + undo)
awaiting_restart --traffic--> traffic_observed
awaiting_first_request --traffic--> traffic_observed
awaiting_first_request --some-providers--> partially_observed
awaiting_first_request --timeout--> needs_attention
needs_attention --fixed+traffic--> traffic_observed
traffic_observed --coverage-loss (gateway stopped, link drifted)--> needs_attention
any --undo--> not_configured
```

Attribution state is orthogonal (on / paused / off) and never gates the
main states.

## 8. Error-state inventory (no silent failures)

Every orchestrator step has a rendered failure with the same three parts —
what happened, what was and wasn't changed, one next action:

* Service install fails (Gatekeeper kills exec probe) → offer
  "Track while the app is open" foreground fallback (`PACKAGING_PLAN.md`
  §5) with its honest limitation, plus the System Settings allow path.
* Route creation fails → named route, others proceed, listed in report.
* Env apply digest mismatch (file changed since preview) → re-plan and
  re-show the diff; never write a stale plan (existing `envlink` behavior).
* Probe fails → forwarding-path diagnosis before waiting for traffic.
* Attribution push fails → tracking continues, banner from Journey B.
* Status/activity fetch fails on the dashboard → inline error + [Retry],
  never an empty chart presented as "no data".
