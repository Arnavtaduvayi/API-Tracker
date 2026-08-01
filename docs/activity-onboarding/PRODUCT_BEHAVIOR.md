# Zero-Friction API Tracking — Product Behavior

Status: design phase (no implementation yet). Base: `main` @ `0e6764b`
(PR #15, Local Gateway Phase 3, merged 2026-07-27).

This document defines what the redesigned tracking experience does, from the
user's point of view. It is the product contract the implementation phases
must satisfy. Companion documents in this directory: `CURRENT_UX_AUDIT.md`
(what exists today and why it fails), `TARGET_USER_JOURNEYS.md` (exact
screens and transitions), `TRACKING_ORCHESTRATOR.md` (the engine),
`AUTOMATIC_PROVIDER_DETECTION.md`, `PACKAGING_PLAN.md`,
`SECURITY_AND_PRIVACY.md`, `IMPLEMENTATION_PLAN.md`, `TEST_PLAN.md`,
`OPEN_DECISIONS.md`. Decision record: `docs/decisions/0022-zero-friction-api-tracking.md`.

## The product promise

> One central place to see your APIs in action: request volume, providers,
> endpoints, success and failure rates, latency, tokens, models, estimated
> cost, recent activity, and which projects are generating traffic.

The Local Gateway, routes, links, matching keys, control tokens, and service
lifecycle are **implementation infrastructure**. They continue to exist —
unchanged in their security properties — but they disappear from the normal
setup path. A normal user interacts with exactly three concepts:

1. **A project folder** (the thing they select).
2. **Tracking** (the thing they turn on).
3. **Activity** (the thing they look at).

## Vocabulary a normal user never sees

These terms remain in code, in Advanced/Diagnostics surfaces, and in
`docs/gateway/`, but never appear in the primary workflow:

gateway authorization · matching keys · route signing keys · routes · route
prefixes · origins · linking · service installation · LaunchAgents · control
tokens · provider manifests · fingerprints · vault exports · shell
environment exports · which Tethra binary is on PATH.

## One primary action

The desktop app's primary action is:

```text
Track API activity
```

The CLI equivalent is one command:

```bash
tethra track .
```

Both drive the same orchestrator (`TRACKING_ORCHESTRATOR.md`) and produce
the same state, visible in both surfaces.

## The standard authorization model

Enabling tracking is one decision, made once, with one honest disclosure.
The disclosure states — in the primary card, not behind "Learn more":

* Tethra will run a local background service (loopback-only) and route the
  selected project's API traffic through it to the providers it detected.
* What is recorded: request metadata — time, provider, project, sanitized
  endpoint template, status, latency, sizes, and bounded token counts /
  model names when responses carry them.
* What is never recorded: API keys, authorization headers, cookies, query
  values, prompts, request bodies, response bodies.
* What is created on disk: the per-user service definition, a copy of the
  helper binary in Tethra's data directory, a log directory, and the
  previewed edits to the project's environment file(s).
* The honest cautions carried over from the gateway consent card: any local
  program can use the loopback port; the service is a standing local egress
  relay to the registered providers.

Accepting that disclosure authorizes, in one step:

* starting the local gateway,
* installing the per-user background component,
* supplying the gateway with the credential-matching capability
  (credential attribution). This is **not narrowly scoped**, and the
  earlier wording here said it was: the key pushed to the gateway is the
  vault-wide fingerprint key, and the matcher covers every
  gateway-linked project, not just the one being set up. It is a real
  capability with a real residual risk (GW-6), disclosed at the point of
  consent and dropped when the vault locks (audit finding `ZFT-020`),
* creating the required provider routes,
* recording sanitized request metadata,
* associating observed traffic with locally stored credentials when
  possible.

There are no further per-subcomponent consent prompts. Two flows keep an
extra interaction for security reasons, and only these two:

1. **The environment-file diff.** File edits are always shown before they
   are written (existing `envlink` plan → approve → apply, digest-bound).
   In the desktop flow this is the single review screen; in the CLI it is
   the combined diff before the confirmation prompt.
2. **One master-password confirmation** covering credential attribution.
   ADR 0020 requires reauthentication before the matching-only key is
   released to the gateway process. The Start-tracking confirmation
   includes one password field for this, labeled honestly. Declining it
   (leaving it empty) still starts tracking — attribution simply reads
   "Credential attribution off" until enabled from the dashboard.

Locking behavior and the matching-key lifecycle (ADR 0020) are unchanged:
the key drops on vault lock by default; keep-while-locked remains an
explicit, off-by-default, capped opt-in under Advanced.

## Automatic provider discovery

The user selects a project folder. Tethra scans **only that folder**
(bounded depth, bounded file sizes, no symlink following, no execution, no
upload — see `AUTOMATIC_PROVIDER_DETECTION.md`) and reports detected
providers at four confidence levels:

* **Confirmed** — configured automatically, no interaction.
* **Likely** — shown pre-selected in the review screen.
* **Possible** — shown unselected in the review screen.
* **Unsupported / unknown** — listed honestly with the reason
  ("Stripe was detected, but its SDK does not read a base-URL environment
  variable, so Tethra cannot observe it this way yet").

Unknown or unsupported providers never block the supported ones.

## The workflow (desktop)

1. User clicks **Track API activity**.
2. User selects the local project folder (native folder picker).
3. Tethra scans only that folder.
4. Tethra detects providers, environment files, credentials, and SDKs.
5. Tethra shows **one** review screen: detected providers with confidence,
   the exact environment-file diff, what will be installed, and the
   disclosure above.
6. User clicks **Start tracking** (optionally entering the master password
   to include attribution).
7. Tethra installs/starts the service, creates all routes, applies all
   file edits, pushes the matching key — in one orchestrated sequence with
   per-step progress and per-step honest failure.
8. Tethra tells the user to restart their project **only when necessary**
   (a running process does not re-read `.env`).
9. Tethra waits for and verifies the first observed request.
10. The user lands on the activity dashboard with live data.

No step requires the terminal. No step requires a separately installed CLI
(see `PACKAGING_PLAN.md` — the helper is bundled).

## The workflow (CLI)

```bash
tethra track .
```

orchestrates the identical sequence: resolve/create the project → scan →
detect → show one combined plan (providers, routes, env diff, service
actions) → one confirmation → apply → verify → live status. Variants:

```bash
tethra track . --project <name>   # explicit project
tethra track . --dry-run          # plan and diff only, change nothing
tethra track status               # current tracking state + verification
tethra track undo                 # restore env files, remove routes/links made by track
```

Existing low-level commands (`tethra gateway …`) remain for diagnostics and
expert workflows, unchanged.

## Tracking and attribution are one feature

There is no separate "Enable attribution" step in the primary flow. When
attribution degrades at runtime (vault locked, keep-while-locked window
expired, key revoked), the dashboard shows:

```text
Credential attribution paused — traffic is still recorded.
```

with a single in-app **Resume attribution** action (master password prompt)
when reauthorization is genuinely required. Forwarding and general metadata
recording continue; the UI never implies tracking stopped, and never tells
the user to run shell commands.

## Verification is mandatory

Configuration success is not tracking success. The orchestrator's state
model (persisted, shared by CLI and desktop):

```text
not_configured → scanning → ready_to_configure → applying →
awaiting_restart → awaiting_first_request → traffic_observed
                                     ↘ partially_observed
                                     ↘ needs_attention
                          ready_to_configure ↘ unsupported
```

"Tracking active" (`traffic_observed`) is claimed only after a real request
from the project reached the gateway and was recorded. Until then the UI
says exactly where things stand:

```text
Restart your app, then make one API request.
Waiting for traffic…
```

and on success:

```text
Tracking verified
Anthropic request observed from <project>
```

If nothing arrives within the waiting window, Tethra diagnoses instead of
showing a blank screen (see `TARGET_USER_JOURNEYS.md` §Diagnosis): process
not restarted, `.env` not loaded by this run mode, variable overridden,
SDK ignores the base-URL variable, Docker/remote execution, provider
without a configurable base URL, wrong folder selected, gateway
unavailable, traffic bypassing the gateway, or simply no request made yet.

`partially_observed` is the honest state when some detected providers have
observed traffic and others have none.

## Empty states are actionable

Every empty state names the situation and the next action. The canonical
set (exact strings in `TARGET_USER_JOURNEYS.md`):

```text
No trackable APIs detected in this folder.
[Review detected configuration]
```

```text
No traffic observed yet.
Restart the project and make one API request.
[Run diagnostics]
```

```text
Tethra detected 8 APIs:
6 can be configured automatically
1 needs confirmation
1 is not currently supported
```

No unexplained "Choose…" dropdowns. No silently swallowed loading errors:
every fetch failure renders the error and a retry action.

## What the dashboard prioritizes

Primary surface (the Activity home):

live request count · requests over time · active providers · active
projects · success and error rate · latency (p50/p95/p99) · endpoint
templates · tokens and models where detectable · estimated cost where
supportable (labeled as a lower bound) · recent activity · last observed
usage · coverage and freshness · alerts for abnormal volume, errors, or
spending.

Moved out of the primary navigation (retained under grouped secondary
navigation / Advanced — nothing is deleted):

temporary credential access · rotation flows · deep credential lifecycle
tools · service management · internal gateway configuration (routes,
recording, control state) · manual usage records · destinations and sync
plans · pricing table management.

## Honesty rules carried forward unchanged

* Locally observed traffic is never summed with provider-reported usage.
* An empty view is never presented as evidence of zero provider usage.
* Cost estimates are labeled lower bounds (cache-read tokens excluded).
* Absent usage data is a state, never a silent zero.
* Windows service mode remains labeled compile-validated-only; the
  supported Windows mode is foreground.
* Coverage limitations (`docs/gateway/COVERAGE_LIMITATIONS.md`) apply
  verbatim: only traffic whose base URL points at the gateway is seen.

## Non-goals of this redesign

* No weakening of any invariant in `docs/gateway/SECURITY_INVARIANTS.md`
  (see `SECURITY_AND_PRIVACY.md` for the reconciliation).
* No whole-computer scanning; detection reads only the selected folder.
* No cloud dependency or hosted credential service. Optional product analytics
  remains off until explicit consent and cannot receive scan or project data.
* No removal of existing security or lifecycle features — they move, they
  do not disappear.
* No rewrite of the forwarding engine, vault, or observation pipelines.
