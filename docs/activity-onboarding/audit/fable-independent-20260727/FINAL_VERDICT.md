# Final Verdict — Independent Audit of PR #16

**Audited:** `24acc470538ca8f198a06456ef84f04c2f891918` on
`feat/zero-friction-api-tracking`, against base `0e6764ba` (`main`).
**Date:** 2026-07-27. **PR was not merged and the implementation branch was not
modified.**

## Runtime disclosure

* **Model:** Claude Fable 5 (`claude-fable-5`)
* **Execution mode:** interactive Claude Code CLI session, autonomous, with
  independent subagents across product, security, packaging, UX, detection,
  validation, privacy, platform behaviour and authorization
* **Effort level:** max (the highest available in this session)
* **Fallback:** none configured
* **Whether fallback occurred:** no

---

## Answer to the primary audit question

> *Can a normal new user genuinely obtain the core value of Tethra without
> understanding or manually configuring gateway internals?*

**For an OpenAI, Anthropic or Supabase project: yes — and the flow is good.**
For anything else: **no.**

The supported journey works exactly as specified. From a clean state, using the
packaged app with no CLI on PATH, I went from a fresh vault to verified activity
in four in-app steps. Detection required no manual provider selection; three
providers were configured in one bulk review with an exact file diff; no route
was created by hand; attribution was granted with no separate authorization step;
the restart instruction was prominent; and one real API request genuinely flipped
the state to verified. The fallback is `tethra track .` — a single command, not a
chain of low-level ones. Zero terminal commands, zero CLI installation, zero PATH
changes, zero symlinks.

That is a real achievement, and the packaging claim underpinning it is true: the
`.app` ships a byte-identical helper inside `Contents/MacOS/`, prefers it over
anything on PATH, contains no dependence on `target/release/tethra`, and works
with the source repository deleted.

But the promise holds for **three providers**. `provider-manifests/` contains
five entries, and only OpenAI, Anthropic and Supabase declare the base-URL
variable that tracking requires. A project using Groq, Mistral, Cohere, DeepSeek,
Together, Perplexity, Fireworks, Azure OpenAI, Replicate or any of a dozen
others gets "No trackable APIs detected in this folder" and is pointed at
`tethra provider list` and `tethra gateway route add` — a terminal command and
manual route creation, the two things the acceptance target sets to zero, and
both unexecutable for the desktop-only user this feature is built for. Worse, in
a 30-API project the twenty-six unrecognised credentials are not merely
unsupported: they are **invisible**, under a heading that reads `Detected:`.

---

## Verdict against the approval criteria

| Criterion | Result |
|---|---|
| Clean packaged desktop setup succeeds with zero terminal commands | **Met** on the supported path |
| The packaged app supplies its own compatible helper | **Met** — verified byte-identical, probe-gated, repo-independent |
| Provider detection works without manual selection for confident detections | **Met** — but confidence is inflatable (`ZFT-012`, `ZFT-025`, `ZFT-026`, `ZFT-027`) |
| Multiple APIs configured in bulk | **Met** — one screen, one confirmation, N providers |
| Tracking authorization and attribution are automatic | **Met** mechanically; **failed** on disclosure (`ZFT-013`) |
| No manual route creation required | **Met** for three providers; **failed** for everything else (`ZFT-009`) |
| First-request verification is genuine | **Failed** — `ZFT-005`, `ZFT-006`, `ZFT-008` |
| Empty states are actionable | **Met** for supported projects; **failed** for unsupported ones |
| The dashboard delivers the central API-activity value | **Partially** — 8 of 11 questions answered; per-project attribution is unanswerable (`ZFT-029`) |
| Existing gateway security remains intact | **Met** — 269/269 pass, all 19 named threats covered, `routes.rs` changed by one doc comment |
| Privacy canaries pass | **Failed** — `ZFT-016`, one canary recovered from `vault.db` |
| Complete local validation passes | **Passed**, but the evidence does not stand (`ZFT-VAL-1`, `ZFT-VAL-4`) |
| Required authoritative CI passes | **Met** — all four checks green on the audited head |
| No merge-blocking product or security defect remains | **Failed** — 15 remain |

---

## The three findings that decide this

**1. Scanning a folder executes arbitrary code (`ZFT-001`, CRITICAL).**
A folder containing a git repository with a hostile `core.fsmonitor` runs
attacker code the moment it is scanned — four times, during `--dry-run`, on a
screen that prints *"nothing executed or uploaded"*. In the desktop app the scan
fires the instant a folder is picked, so the trigger is *clicking a folder*,
before any confirmation. The product's central call to action invites users to
point it at project folders, which developers routinely clone from the internet.
Three tests appear to cover this and none do. I reproduced it directly against
the packaged app.

**2. Route destinations come from repository content (`ZFT-004`, HIGH).**
A repository containing no secrets at all — just a committed `package.json` and a
committed `SUPABASE_URL` — causes a MAC'd, enabled route from the user's local
gateway to an attacker-chosen host, with the app's `.env` rewritten to send its
credential through it. The PR's own security document promises this "requires an
explicit checkbox (never part of Confirmed auto-config)". There is no checkbox in
the CLI, and the desktop ships it pre-checked with the origin pre-filled. The
gateway's transport defenses are intact and did their job; what regressed is the
provenance of the one input they cannot judge.

**3. "Tracking verified" can be false (`ZFT-005`, `ZFT-006`, `ZFT-008`, HIGH).**
The audit brief's core requirement is that the system must never show "Tracking
verified" without a qualifying new observation. It does, by three routes I
confirmed:

* Kill the gateway. Status still reads *"tracking verified — traffic observed"* —
  while the user's application is broken, because its `.env` points at a loopback
  port with nothing listening.
* Re-run `track` and let it fail. The failure is reported honestly on screen, and
  then the very next `track status` reports verified, having promoted the row off
  the *previous* run's traffic and nulled the failure reason.
* Null one column in `vault.db` and re-derivation is skipped entirely — the
  documented "a stale row can never overclaim" invariant is defeated by removing
  the input it depends on.

Mutation testing found the boundary comparison and the `observation_source`
filter — two of the mechanism's load-bearing clauses — have **zero** test
coverage.

---

## On the quality of the work

This is a strong implementation with a specific and correctable class of
failures, and the audit should not be read as a wholesale rejection.

The engineering that is right is right for good reasons: shell-free command
construction throughout, per-step honest apply reporting, real idempotence,
lossless `.env` editing with byte-for-byte undo, a genuine digest binding, a real
negative control in the UI test suite, and coverage honesty that is better than
most shipping products — no claim of remote or Docker coverage, cost labelled a
lower bound, empty state that says "observed yet" rather than "no API usage",
and specific per-provider explanations for what cannot be tracked.

The PR's arithmetic is also unusually trustworthy. Every number I re-derived
matched: 54 tracking tests, 269 gateway tests, 1005 workspace tests, 65 vitest
cases, 138 smoke checks, 20/20 deterministic runs of the rewritten 304 test, and
the app-bundle byte sizes to the byte. The branch also caught and disclosed a
real Windows security defect of its own during development.

Where the self-reporting fails is narrative rather than numeric: the
"30-provider-scale test" is a four-provider test with a thirty-variable `.env`;
"eight commits, each independently green" sits atop a seven-item list on a branch
whose first five pushed heads failed CI; "value-free" is contradicted by the
crate's own test. And the headline "42 checks" is a single developer-machine run
that CI never executes, in a self-weakening foreground mode that leaves the
packaged **service** path — the one every real user gets — validated by nothing.

---

## Required before re-review

Blocking, in priority order:

1. `ZFT-001` — stop spawning git during detection.
2. `ZFT-002`, `ZFT-003` — one reader with the containment and byte-cap checks;
   cap inside `envgov::discover`.
3. `ZFT-004` — remove `NeedsOriginConfirm` from `Selections::defaults`; make
   `--yes` refuse an inferred origin; ship the checkbox unchecked.
4. `ZFT-005`, `ZFT-006`, `ZFT-008` — gate `Observed` on live route/link existence
   and bounded freshness; clear the watermark on re-apply; move the early returns
   after the downgrade. Add tests for the two surviving mutants.
5. `ZFT-007` — undo must derive from ground truth or refuse loudly.
6. `ZFT-009`, `ZFT-010`, `ZFT-011` — an in-app path for unrecognised APIs, a
   visible "not recognised" group, and an honest statement of provider scope.
7. `ZFT-012` — a customised base URL must downgrade to `NeedsOriginConfirm`.
8. `ZFT-013` — restore the ADR-0020 disclosure to the primary consent surface.
9. `ZFT-014` — the LaunchAgent label must not be a global constant.
10. `ZFT-015` — re-arm or honestly retire the waiting screen's poll.

Also strongly recommended before shipping: `ZFT-016` (query-string persistence),
`ZFT-017` (mask bypass), and a macOS CI job that builds the bundle and runs the
packaged validation, so `ZFT-VAL-1` and `ZFT-VAL-4` stop being true.

An important operational note for whoever fixes `ZFT-014`: during this audit a
real apply against an isolated data directory booted out this machine's live
gateway service. I detected it and restored it (`launchctl bootstrap gui/501
~/Library/LaunchAgents/dev.api-tracker.gateway.plist`; running as pid 50655
against the original data directory). No user data was lost and the plist was
never rewritten — but that is exactly what will happen to a user with two Tethra
environments, silently.

---

FINAL AUDIT COMPLETE: REMEDIATION REQUIRED
