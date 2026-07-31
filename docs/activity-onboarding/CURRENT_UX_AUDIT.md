# Current UX Audit — API Tracking Setup as Shipped at `main` @ `0e6764b`

Audited 2026-07-27 against the live repository (PR #15 merged), the packaged
`Tethra.app` on this machine, and the actual code paths — not the docs alone.
File references are to real lines at this commit.

## 1. Summary verdict

Tracking works end to end **for an expert who already knows the internal
model**. For the product's actual promise — "see your APIs in action" — the
current experience fails in five structural ways:

1. **The packaged app cannot start tracking at all.** `Tethra.app` contains
   only `Contents/MacOS/api-tracker-desktop` (verified on the installed
   bundle). The gateway service *is* the CLI binary, which is not bundled
   (`tauri.conf.json` has no `externalBin`; `docs/gateway/OPEN_DECISIONS.md`
   O10 defers it until signing exists). Enabling stops honestly:
   `apps/desktop/src-tauri/src/main.rs:2521-2527` — "the Tethra CLI is not
   installed (or not executable) on this machine…". The referenced fix is a
   manual terminal install (`docs/INSTALL.md:34-42`: `tar -xzf`,
   `sudo mv tethra /usr/local/bin/`) — and `docs/INSTALL.md` itself contains
   zero gateway content, a documented dead end.
2. **Setup is ~12 deliberate steps across 4 sub-tabs**, each using internal
   vocabulary (routes, prefixes, origins, links, matching keys).
3. **Verification does not exist as a concept.** Nothing distinguishes
   "configured" from "observed traffic"; no state model spans the flow.
4. **The activity surfaces are split three ways** (Gateway → Activity,
   API activity, Usage) with no cross-links and mutually exclusive empty
   states.
5. **The desktop routinely hands users terminal commands** as the way
   forward, including in diagnostics "Fix:" hints and primary empty states.

## 2. The current journey, reproduced step by step

Persona: a developer with the packaged desktop app who wants to see their
project's OpenAI + Anthropic traffic. Steps follow real code paths.

### 2.0 Install the app

`Tethra.app` is unsigned (`docs/PACKAGING.md:37-40`); Gatekeeper refuses it
by default; the documented workaround is right-click → Open or
`xattr -dr com.apple.quarantine` (release notes). Already a terminal step
for many users, before Tethra even runs.

### 2.1 First run

`VaultSetup.tsx` — master password, "Create encrypted vault". That is the
entire first-run experience; the user lands on Projects with "No projects
yet." There is no onboarding, no checklist, no pointer toward tracking
(grep for onboarding/wizard/welcome across `apps/desktop/src` matches only
a code comment in `GatewayView.tsx:163`).

### 2.2 Create a project and add a credential

Projects → New project (`ProjectForm.tsx`). The repository path is a
**hand-typed text field** (`/path/to/repository` placeholder) — there is no
native folder picker anywhere in the app (`@tauri-apps/plugin-dialog` is
not a dependency; `package.json:17-23`). Add credential via
`CredentialForm.tsx` (works well; reuse detection is good).

### 2.3 Enable the gateway

Gateway tab (position 13 of 17 in a flat, ungrouped top bar;
`App.tsx:198-253`) → consent card ("Enable the Local Gateway?"). On this
packaged app, the flow ends here with the CLI-missing blocker (§1.1). With
the CLI separately installed: confirm dialog → LaunchAgent install → the
success notice hands off with *"Next: add a route and link your first
project."* and switches to the Projects sub-tab.

Observed local evidence of how developers actually get past the CLI gap
today: `~/.local/bin/tethra` on this machine is a **symlink into a Git
worktree's `target/release`** — exactly the anti-pattern the redesign must
eliminate.

### 2.4 Add routes

Gateway → Routes sub-tab. Empty state: *"No routes yet. A route maps a path
prefix (http://127.0.0.1:&lt;port&gt;/openai/…) to one provider origin."* The
user must operate a three-field form (Provider "Choose…" dropdown, optional
route prefix with a regex pattern, custom origin field) **once per
provider**, and must understand that Supabase requires a typed origin URL.
All of this is derivable: the provider is known from the manifest, the
prefix defaults to the provider id, and the origin is compiled in.

### 2.5 Link the project

Gateway → Projects sub-tab. A five-control form: project dropdown, route
dropdown (one link per route — a two-provider project means doing this
twice), a **hand-typed** absolute `.env` path or project directory, and a
variable-override field. Preview diff → "Apply exactly this". The diff and
prior-state recording underneath (`envlink.rs`) are excellent engineering —
but the user had to assemble the request from internal parts.

### 2.6 Enable attribution

Back on Gateway → Status: a separate "Enable attribution…" button opens a
reauth dialog explaining matching-only keys and memory-oracle residual
risk. A user who never finds this button gets every exchange labeled
`unavailable_no_key` with no prompt to fix it at setup time.

### 2.7 Restart the project and generate a request

Nothing in the UI tells the user a running process will not re-read `.env`.
The post-link notice says only *"Traffic will appear once the project
actually sends requests."* The link warnings machinery already detects
`NoDotenvLoaderDetected` and `DockerComposePresent`
(`crates/gateway/src/envlink.rs:153-190`) but nothing turns them into a
restart instruction.

### 2.8 Find the activity

Three unlinked destinations claim to answer "what happened":

* **Gateway → Activity** (`GatewayView.tsx:1136-1253`): gateway-observed
  metrics only; a `<dl>` of numbers, no chart; empty tables are hidden
  entirely rather than explained.
* **API activity** (`ApiActivityView.tsx`): proxy + gateway events, but its
  primary empty state instructs a terminal command:
  *"No API traffic observed yet (from the proxy or the local gateway).
  Launch a monitored run: `tethra run --observe -- <command>`"* — wrong
  advice for a gateway-linked project (`docs/gateway/audit/REMEDIATION.md`
  accepted-risk #3: running `--observe` over a gateway-linked project
  silently produces zero observe coverage).
* **Usage** (`UsageView.tsx`): provider-reported + manual usage; gateway
  numbers deliberately never appear here.

A first-time user cannot know which of the three to open, and each shows
"empty" while another may have data.

### 2.9 Understand an empty activity view

The Gateway Activity header explains coverage honestly, but when nothing
has arrived the user gets metric rows with dashes and *"no events in this
window"* — no diagnosis, no "restart your app" instruction, no probe
result. The keyless post-link probe (`gateway_cmd.rs:1273`) already proves
path-correctness, but its result is shown once at link time and never
again.

### 2.10 Undo

Undo exists and is well-built: per-link unlink with exact restore
(`envlink::unlink`, `RestoreOutcome`), disable/uninstall with bulk `.env`
restore. But it is scattered (Gateway → Projects per link, Status for the
service) and there is no single "stop tracking this project" action.

## 3. Step count, measured

Minimum happy path today, packaged app, two providers (OpenAI + Anthropic),
one project, attribution on:

| # | Action | Surface |
|---|--------|---------|
| 1 | Install CLI archive (terminal, sudo) | Terminal |
| 2 | Create vault | App |
| 3 | Create project (type repo path by hand) | App |
| 4 | Add credential(s) | App |
| 5 | Gateway → Enable → confirm | App |
| 6 | Routes → add `openai` | App |
| 7 | Routes → add `anthropic` | App |
| 8 | Projects → link project→openai (type `.env` path) → preview → apply | App |
| 9 | Projects → link project→anthropic → preview → apply | App |
| 10 | Status → Enable attribution → master password | App |
| 11 | Restart project (uninstructed) | User's own inference |
| 12 | Find the right activity tab | App |

The CLI path additionally requires `tethra init`,
`eval "$(tethra unlock --print-export)"` (a shell export the desktop never
needs), `project create --repo`, `gateway install`, two `route add`s, two
`link`s, `push-key` — with hard ordering constraints that fail informatively
but only one step at a time (`envlink.rs:312-319` port-first;
`gateway_cmd.rs:445-450` install-first).

## 4. What already works and must be preserved

The audit is not all negative. These components are production-quality and
are the foundation the orchestrator composes (details in
`TRACKING_ORCHESTRATOR.md` §Reuse):

* `envlink` plan → digest-bound apply → exact restore, with the best
  warning model in the codebase (`LinkWarning`, `RestoreOutcome`).
* `doctor::diagnose` — lock-free, stable finding ids, repair hints, shared
  by CLI/desktop/JSON.
* `lifecycle` — mockable service engine for LaunchAgent/systemd-user/HKCU
  Run, quarantine-aware binary install with exec probe.
* Route model with manifest-as-trust-root and MAC'd custom origins.
* The consent card's honesty (content is right; placement and repetition
  are the problem).
* The keyless post-link probe.
* `stackdetect` + `envgov::discover` + scanner (unused for this purpose so
  far — see `AUTOMATIC_PROVIDER_DETECTION.md`).
* The `control::Status` DTO and per-exchange honesty enums.

## 5. Specific defects to fix regardless of the redesign

1. **Wrong command in a user-facing string**: `gateway_cmd.rs:779-783`
   says "Run `tethra vault unlock`…" — there is no `vault` subcommand; the
   command is `tethra unlock`.
2. **Flaky CI test**: `a_304_response_carries_no_body_and_keeps_the_
   connection_usable` (`crates/gateway/tests/forwarding.rs:1437`) failed on
   the PR #15 merge commit's CI run on `main` and passes locally 5/5
   (~20 s per run — it contains a generous timing window that loaded CI
   runners can exceed). `main` is healthy; the test needs a deterministic
   rework.
3. **Stale UI docs**: `docs/UI_MAP.md` and `docs/MANUAL_UI_TEST_PLAN.md`
   contain zero gateway coverage (16-button pre-gateway baseline).
4. **Stale handoff status**: `docs/gateway/HANDOFF_PHASE_5.md`,
   `docs/gateway/audit/RE_AUDIT_HANDOFF.md`, and
   `docs/gateway/audit/REMEDIATION.md` all state PR #15 is open/unmerged
   and must not merge without a fresh independent re-audit; GitHub shows it
   merged 2026-07-27 with no recorded re-audit. The docs need a dated
   status correction; the governance gap itself is recorded in
   `OPEN_DECISIONS.md` (O-22-9).
5. **Dead setting**: the observability "default mode" preference is stored
   but consumed by nothing, and the UI says so in prose
   (`ApiActivityView.tsx:519-524`).
6. **Diagnostics render CLI commands as fixes** in the desktop
   (`GatewayView.tsx:641-645` renders `doctor.rs` repair strings like
   `tethra gateway repair`) even where an equivalent button exists on the
   same screen.
7. **`project_repos.path` is stored uncanonicalized** with no reverse
   lookup (folder → project), which folder-first flows need
   (`crates/core/src/vault.rs:694` ff.; contrast `stack_repo_key`, which
   canonicalizes).

## 6. Navigation inventory (for the IA change)

17 flat top-bar entries (`App.tsx:200-252`): Projects · Providers · Scan ·
Env files · Destinations · Sync plans · Rotation · Temporary access ·
Alerts · Notifications · Usage · API activity · Gateway · Pricing ·
Templates · Backup · Settings. The two tracking entries sit at positions
12–13. Gateway itself contains six sub-tabs; API activity another six.
Open PR #14 (`eesh-ui`, collapsible sidebar shell redesign) touches this
same surface — coordination is required (see `OPEN_DECISIONS.md` O-22-8).
