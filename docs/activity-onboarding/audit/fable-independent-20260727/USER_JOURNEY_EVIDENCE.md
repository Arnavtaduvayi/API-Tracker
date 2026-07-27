# User-Journey Evidence — Independent Audit of PR #16

Audited commit: `24acc470538ca8f198a06456ef84f04c2f891918` (`feat/zero-friction-api-tracking`)
Base: `0e6764ba3bcc7a2e3d14afaa91041d4bfcd3b75b` (`main`)
Auditor: independent session, fresh worktree `audit/fable-zft-independent-20260727`.
Date: 2026-07-27.

Nothing in this document is taken from the implementation handoff. Every result
below was produced by executing the **packaged** application's helper on this
machine and is reproducible with the commands shown.

---

## 1. Clean-state construction

The principal onboarding test used the **packaged app**, not a development
binary.

```
# Built in the audit worktree, following the documented build order:
bash scripts/bundle_cli.sh                       # stages the sidecar
cd apps/desktop && npm ci && npm run tauri build -- --bundles app
# → target/release/bundle/macos/Tethra.app
```

The app was then **copied out of the repository** to simulate an installed app:

```
cp -R target/release/bundle/macos/Tethra.app <scratch>/clean-install/Tethra.app
```

Clean-state invariants established for every run:

| Requirement | How it was enforced | Verified |
|---|---|---|
| No Tethra CLI on PATH | `env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin` | yes — `which tethra` empty inside the run |
| No development binary reachable | app copied outside the repo; helper invoked by absolute path inside the bundle | yes |
| No existing LaunchAgent | `HOME` redirected to a fresh dir, so `~/Library/LaunchAgents` was empty | yes (see §7 for the caveat that matters) |
| No existing routes / links / setups | fresh `TETHRA_DIR` with a newly `init`-ed vault | yes |
| No matching authorization | fresh vault | yes |
| No cached setup session | fresh `TETHRA_DIR` | yes |
| No prior observations | fresh vault; `runtime_request_events` empty | yes |

**Packaged helper answers in the clean environment** (`J-00`):

```
$ env -i HOME=<clean> TETHRA_DIR=<clean>/data PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    <clean-install>/Tethra.app/Contents/MacOS/tethra --version
tethra 0.1.0                                    # exit 0
```

The bundled helper is byte-identical to the CLI:

```
cc15a1e9…510b  Tethra.app/Contents/MacOS/tethra
cc15a1e9…510b  target/release/tethra
cc15a1e9…510b  apps/desktop/src-tauri/binaries/tethra-aarch64-apple-darwin
```

---

## 2. Journey 1 — Standard Anthropic project — **PASS with defects**

Fixture: `.env` with `ANTHROPIC_API_KEY`, `package.json` depending on
`@anthropic-ai/sdk`, one JS source file.

```
$ tethra track <fixture> --project anthropic-app --dry-run
Detected:
  anthropic   confirmed   Found ANTHROPIC_API_KEY in .env (value not read);
                          Found the @anthropic-ai/sdk package in package.json
Will do:
  1. install + start the local tracking service (per-user, loopback-only)
  2. create routes: anthropic
  3. edit 1 environment file(s) (diff below), adding NO_PROXY for loopback
  4. enable credential attribution (asks for your master password; Enter skips)
```

Observed, in the product's favour:

* Detection required **no manual provider selection**. Confidence was
  `confirmed`, derived from two independent signals.
* One **combined** plan for the whole project, with the exact file diff.
* The credential value is **redacted in the diff** (`ANTHROPIC_API_KEY=sk-a…al`).
* `--dry-run` changed nothing; byte-compared before/after.
* Warnings are honest and specific (provisional port; no dotenv loader found).

Apply, against a live gateway (`J-01`):

```
✓ Project registered — existing project 'anthropic-app'
• Local port reserved — port 55102 already persisted
• Local service installed and running — already running
✓ Provider routes created — created: anthropic
• Custom-route verification key installed — no custom-origin routes
✓ Environment files updated — 1 file(s)
✓ Service notified — routes reloaded
✓ Path check — anthropic: provider answered 401 to a keyless request — path verified
✓ Credential attribution — requests will be labeled with their credential
✓ Setup recorded — awaiting_restart

Restart your app, then make one API request.
Waiting for traffic (up to 120 s; Ctrl-C stops waiting — tracking stays on)…
```

Per-step reporting is honest, attribution was configured **without a separate
authorization step**, and no shell-export choreography was printed.

### Defects found in this journey

**`ZF-D1` — the marker comment written into the user's `.env` instructs them to
run a terminal command they do not have.** Every rewritten variable is preceded
by:

```
# tethra-gateway route: anthropic (project: anthropic-app) — remove this line
# if 127.0.0.1 refuses connections, or run: tethra gateway status
```

For the target user — desktop-only, zero terminal — `tethra` is **not on PATH**;
it lives inside `Tethra.app/Contents/MacOS/`. The recovery instruction embedded
in their own source tree is unexecutable, and it names two internal concepts
("gateway route", "gateway status"). This is written into a file the user
commits and reads.

**`ZF-D2` — the marker comment is emitted twice per file**, once before the base
URL and once before `NO_PROXY`, doubling the noise in the user's file.

**`ZF-D3` — the diff header prints a stray bare path line.** Every file block
renders three header lines:

```
--- /path/.env
--- /path/.env (current)
+++ /path/.env (proposed)
```

The first is a formatting bug.

---

## 3. Journey 2 — Standard OpenAI project — **PASS**

Fixture: Python project, `.env` with `OPENAI_API_KEY`, `requirements.txt` with
`openai`, source using the OpenAI SDK. Detected `openai confirmed` from two
signals; plan wrote both `OPENAI_BASE_URL` and `OPENAI_API_BASE` (correct — the
SDK honours either). Same defects `ZF-D1`–`ZF-D3` apply.

---

## 4. Journey 3 — Multi-provider project — **PASS (bulk workflow confirmed)**

Fixture `.env` with OpenAI, Anthropic, Stripe and Groq keys plus matching
`package.json` dependencies.

```
Detected:
  anthropic   confirmed   …
  openai      confirmed   …
  stripe      unsupported …
              The Stripe SDK does not read a base-URL environment variable, so
              Tethra cannot observe it this way yet. Everything else still works.
Will do:
  2. create routes: anthropic, openai
```

* **One review screen, one confirmation, N providers.** No per-provider form,
  no repeated prompt. This requirement is genuinely met.
* The unsupported item receives a **specific, accurate** explanation rather than
  a generic failure.
* Groq was **not detected at all** — see §5.

---

## 5. Journey 4 — Large project (~30 APIs) — **FAIL (silent under-reporting)**

Fixture: 14 MB monorepo, 8 `.env*` files across root and two workspaces,
30 distinct API credentials, a 3 MB binary, a 12 MB text file, a `.gitignore`,
a `node_modules/openai/.env` decoy, custom origins declared in
`config/services.json`, and a Ruby file using an unsupported runtime pattern.

**Bounds behaved well.** Full scan completed in **287 ms**; `node_modules` was
correctly excluded (the decoy key never appeared); the UI stayed comprehensible
and demanded no provider-by-provider route setup.

**But of ~30 planted APIs, exactly 4 were named and 2 were configured:**

```
Detected:
  anthropic   confirmed
  openai      confirmed
  stripe      unsupported
  github      unsupported
```

Everything else — `GROQ_API_KEY`, `MISTRAL_API_KEY`, `COHERE_API_KEY`,
`SENDGRID_API_KEY`, `TWILIO_AUTH_TOKEN`, `SLACK_BOT_TOKEN`, `DEEPSEEK_API_KEY`,
`TOGETHER_API_KEY`, `PERPLEXITY_API_KEY`, `FIREWORKS_API_KEY`,
`HUGGINGFACE_API_KEY`, `AZURE_OPENAI_API_KEY`, `GOOGLE_API_KEY`,
`ELEVENLABS_API_KEY`, `ASSEMBLYAI_API_KEY`, `PINECONE_API_KEY`,
`LANGSMITH_API_KEY`, `REPLICATE_API_TOKEN`, `RESEND_API_KEY`, and the three
custom origins — **was not mentioned anywhere in the output**. Not as detected,
not as unsupported, not as unknown, not as a count.

**`ZF-D4` (HIGH, product) — unknown API credentials are silently dropped.**
The screen is headed `Detected:` and lists four rows. A user reading it
reasonably concludes their project uses four APIs. It uses thirty. There is no
"unknown"/"unrecognised" section and no residual count, so the omission is
invisible. The audit brief's requirement that "uncertain detections are reviewed
without blocking confirmed detections" is not met because uncertain detections
are not surfaced at all.

I confirmed the cause is provider-coverage, not file skipping. A filename probe
showed `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.test`,
`.env.staging`, `.env.qa`, `.env.prod` are **all** scanned (`env` and
`.environment` are not). `.env.staging` was read; its contents simply matched no
known provider.

**Related monorepo limitation (`ZF-D5`, MEDIUM):** the same route id and base URL
were written into `.env`, `.env.local` and `packages/worker/.env`. Traffic from
the `web` and `worker` packages is therefore indistinguishable — one route per
provider per project, not per workspace.

---

## 6. Journey 5 — Unsupported project — **FAIL (dead end violates the brief)**

Fixture: only unrecognised providers (Groq, Mistral, Cohere, DeepSeek, Together,
Perplexity, plus a custom internal key) with matching SDK dependencies.

```
No trackable APIs detected in this folder.
Tethra looked at .env files, package manifests, and lockfiles (2 file(s) read, 6 levels deep).
• Using a provider Tethra doesn't support yet? See `tethra provider list`.
• Know the provider and its base URL? `tethra gateway route add` is the expert path.
                                                                     exit code 2
```

**`ZF-D6` (HIGH, product) — the unsupported-project dead end routes the user to a
terminal command and to manual route creation.** Against the acceptance target:

| Acceptance target | Result on this path |
|---|---|
| Terminal commands: 0 | **violated** — `tethra provider list` |
| Manual route creation: 0 | **violated** — `tethra gateway route add` |
| Internal gateway concepts required: 0 | **violated** — "route", "gateway" |

And for the desktop-only user the commands are unexecutable (no CLI on PATH).
The desktop equivalent is slightly better but not compliant: `TrackFlow.tsx`
points the user at "Advanced → Gateway internals has the manual route form" —
still manual route creation and still internal gateway concepts.

### Root cause: the product supports five providers, three of them trackable

```
$ tethra provider list
openai · anthropic · github · stripe · supabase        (5 manifests on disk)
```

`provider-manifests/` contains exactly five `.toml` files. Only `openai`,
`anthropic` and `supabase` declare a base-URL environment variable, so only
those three can be tracked. `github` and `stripe` are detected and honestly
labelled unsupported.

**`ZF-D7` (HIGH, product) — coverage is three providers.** "Zero-friction API
activity tracking" delivers its promise only for OpenAI, Anthropic and Supabase.
Every other API in a user's project — including OpenAI-compatible services such
as Groq, Together, DeepSeek, Fireworks, Perplexity and Mistral, which would need
little more than a manifest entry — falls off the automatic path onto the expert
path. `KNOWN_LIMITATIONS.md` does not state the provider count.

---

## 7. Journey 6 — Existing manually-configured user / migration — **PASS on env, FAIL on service isolation**

Fixture: `.env` already containing a custom `OPENAI_BASE_URL`
(`https://my-corporate-proxy.internal.example/v1`).

The plan **noticed and disclosed it**:

```
- OPENAI_BASE_URL=https://my-corporate-proxy.internal.example/v1
+ OPENAI_BASE_URL=http://127.0.0.1:54280/p/…/openai/v1
Warnings:
  ! OPENAI_BASE_URL in …/.env already had a value; it was recorded and will be
    restored on undo.
```

That is correct and honest behaviour.

**`ZF-D8` (HIGH, safety) — the tracking flow silently takes over any existing
gateway service, because the LaunchAgent label is a fixed global constant.**

`crates/gateway/src/lifecycle/macos.rs:26` — `pub const LABEL: &str =
"dev.api-tracker.gateway"`. Install does `launchctl bootstrap gui/<uid>`, and on
"already bootstrapped" it performs **`bootout` then `bootstrap`**
(`macos.rs:204-221`). The plist path is derived from `$HOME`, but the launchd
*domain target* is the real `gui/<uid>` regardless.

This is not theoretical. **During this audit a subagent ran a real
`tethra track --yes` against an isolated data directory, and it booted out this
machine's live gateway service** (`dev.api-tracker.gateway`, pid 43853), which
had been serving the user's real vault at
`~/Library/Application Support/api-tracker`. I detected the loss and restored it
with `launchctl bootstrap gui/501 ~/Library/LaunchAgents/dev.api-tracker.gateway.plist`
(now running as pid 50655, pointing at the original data directory). No user
data was lost, and the plist was never rewritten — but the service was down
until I restored it.

Consequences: two vaults/data directories cannot coexist; a second tracked
environment silently disables the first; and the shipped validation script's
"switch to foreground mode when a LaunchAgent already exists" is a workaround for
this defect rather than a test mode (see `VALIDATION_INTEGRITY.md`).

---

## 8. Journey 7 — Docker / remote runtime — **PASS (no false claim)**

No string in the CLI or UI claims coverage of remote or containerised traffic.
The opposite is stated plainly, in several places:

* apply output: *"the gateway sees ONLY traffic whose base URL is repointed at
  it. Absence of recorded traffic is not evidence of absence of traffic."*
* `TrackFlow.tsx:410-411`: *"local or remote traffic that bypasses Tethra is not
  observed"*.
* `DashboardView.tsx:309-313`: *"Only traffic whose base URL points at Tethra is
  observed; some traffic may bypass Tethra."*
* Empty state reads *"No activity **observed yet**"*, never "no API usage".
* `diagnose.rs` explicitly ranks Docker Compose and devcontainer causes.

This requirement is met well.

---

## 9. Journey 8 — Undo — **PASS**

```
$ tethra track undo <proj> --yes
  Restored { path: "/private/tmp/tza/proj/.env", key: "ANTHROPIC_BASE_URL" }
  Restored { path: "/private/tmp/tza/proj/.env", key: "NO_PROXY" }
Routes removed: anthropic
$ cmp <proj>/.env <snapshot-before>
UNDO: RESTORED BYTE-FOR-BYTE ✓
```

Undo restored the file byte-for-byte, removed the route, and correctly **kept**
recorded history. It also correctly declines to stop a service other projects
may use.

**`ZF-D9` (LOW, UX) — raw Rust `Debug` output leaks into user-facing CLI text.**
`Restored { path: "…", key: "…" }` is a struct debug-print, not a sentence.

---

## 10. Verification integrity — **FAIL**

Detail and root causes are in `SECURITY_EVIDENCE.md`; the journey-level results
are summarised here. All were executed black-box against the packaged helper.

| Attack | Result |
|---|---|
| Do not restart the project; make no request | **Correctly refuses.** `State: waiting — restart the project, then make one request` |
| Unrelated local traffic (`/_tethra/health`, closed port) | **Correctly refuses** — 404/000, still "no traffic observed yet" |
| Traffic to the wrong route (bad slug, wrong prefix) | **Correctly refuses** — 404, still unverified |
| One genuine request through the correct route | **Correctly verifies** — `State: tracking verified — traffic observed`, with an accurate first-observed timestamp |
| **Stop the gateway, then ask status** | **FAILS** — still reports `tracking verified — traffic observed` with the gateway process dead and the port closed |
| **Re-run `track` and let it fail** | **FAILS** — apply stopped at `✗ Local service installed and running — the service did not answer on 127.0.0.1:55102 within 10 s`, and the immediately following `track status` reported `tracking verified — traffic observed`, hiding the failure |

The last two are the serious ones. In both, the user's application is
**broken** — its `.env` points at a 127.0.0.1 port with nothing listening, so
every API call fails — while Tethra reports tracking as verified.

---

## 11. Acceptance-target scorecard

Measured on the supported path (OpenAI / Anthropic / Supabase, desktop app):

| Target | Result |
|---|---|
| Terminal commands: 0 | **Met** on the supported path; **violated** on the unsupported-project dead end (`ZF-D6`) and by the `.env` marker comment (`ZF-D1`) |
| External CLI installation: 0 | **Met** — the app ships and uses its own helper |
| PATH changes: 0 | **Met** |
| Manual symlinks: 0 | **Met** |
| Manual route creation: 0 | **Met** on the supported path; **violated** for every unsupported provider (`ZF-D6`) |
| Separate gateway authorization: 0 | **Met** |
| Separate attribution authorization: 0 | **Met** — one optional password field, forwarding continues without it |
| Manual provider selection for confident detections: 0 | **Met** |
| Internal gateway concepts required: 0 | **Violated** — `ZF-D1`, `ZF-D6`; "routes" also appears in the primary flow copy |

The fallback is genuinely `tethra track .` — a single command, not a chain of
low-level commands. That part of the brief is satisfied.
