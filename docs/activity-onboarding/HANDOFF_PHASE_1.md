# Handoff — Activity Onboarding Phase 1 (Architecture)

Date: 2026-07-27. Branch: `feat/zero-friction-api-tracking`
(worktree `API-Tracker-zero-friction`), based on `main` @ `0e6764b`.
Scope of this phase: repository-grounded product and architecture plan.
**No implementation was performed.**

## Repository state as verified live (do not trust older handoffs)

* **PR #15 (Local Gateway Phase 3) is MERGED** into `main`
  (merge commit `0e6764b`, 2026-07-27T13:02Z). Every pre-existing gateway
  handoff/audit doc claimed it was open and must not merge without a fresh
  independent re-audit; those docs now carry dated status corrections, and
  the governance question is recorded as O-22-9 in
  `docs/activity-onboarding/OPEN_DECISIONS.md`.
* **CI on the merge commit failed** — one test:
  `a_304_response_carries_no_body_and_keeps_the_connection_usable`
  (`crates/gateway/tests/forwarding.rs:1437`). All five CI runs on the PR
  head passed; the test passes locally 5/5 (~20 s each — a timing window
  loaded CI runners can exceed). Verdict: flaky test, `main` healthy;
  deterministic rewrite scheduled as Phase 0.
* **Open PRs**: only #14 (`eesh-ui`, sidebar shell redesign) — collision
  surface for Phase 4 UI work (O-22-8). Not modified, not merged.
* **Packaged reality on this machine**: `/Applications/Tethra.app`
  contains only the desktop binary; `~/.local/bin/tethra` is a symlink
  into a Git worktree's `target/release`; the LaunchAgent runs a copied
  binary from Application Support. This is the packaging failure the plan
  fixes.

## Branching decision (required by the phase brief)

**Begin from current `main`.** Rationale from live evidence: PR #15 is
merged, so "build on PR #15", "wait for PR #15", and "add to PR #15" all
collapse into `main`; its head branch is historical. No PR was modified or
merged. The dedicated branch/worktree follows the repo's established
sibling-worktree convention.

## What this phase produced

```text
docs/activity-onboarding/PRODUCT_BEHAVIOR.md      — the product contract
docs/activity-onboarding/CURRENT_UX_AUDIT.md      — reproduced current journey, defects, step count
docs/activity-onboarding/TARGET_USER_JOURNEYS.md  — screens, states, exact strings, CLI transcript
docs/activity-onboarding/AUTOMATIC_PROVIDER_DETECTION.md
docs/activity-onboarding/TRACKING_ORCHESTRATOR.md — crates/tracking design, apply order, v15 schema
docs/activity-onboarding/PACKAGING_PLAN.md        — sidecar bundling, closes O10
docs/activity-onboarding/SECURITY_AND_PRIVACY.md  — SI-1..21 reconciliation, new surface
docs/activity-onboarding/IMPLEMENTATION_PLAN.md   — phases 0–5
docs/activity-onboarding/TEST_PLAN.md
docs/activity-onboarding/OPEN_DECISIONS.md        — O-22-1..10
docs/decisions/0022-zero-friction-api-tracking.md — the ADR (D1–D10)
```

Plus dated status-correction notes on `docs/gateway/HANDOFF_PHASE_5.md`,
`docs/gateway/audit/RE_AUDIT_HANDOFF.md`, `docs/gateway/audit/REMEDIATION.md`.

## Load-bearing facts the next phase should not re-derive

* No `track` command exists; `Commands` in `apps/cli/src/lib.rs:83-174`
  is the clean insertion point.
* Hard apply-order constraints: persisted port before `plan_link`
  (`envlink.rs:312-319`); route row before link; MAC key before custom
  routes forward; `ReloadRoutes` nudge after link.
* All orchestrator building blocks are already public APIs (inventory in
  `TRACKING_ORCHESTRATOR.md` §1; gateway public surface list in that
  audit).
* Detection primitives: `stackdetect::detect`, `envgov::discover`,
  scanner name/value rules, manifests (`[gateway]` sections only for
  openai/anthropic/supabase), `provider_for_host`,
  unused `ServiceSource::RepositoryDetected`.
* `project_repos.path` is uncanonicalized, no reverse lookup — core
  addition required (Phase 1).
* Desktop has no folder picker (`plugin-dialog` absent), no state
  management library, 186 Tauri commands in one file, and a deliberate
  plain-CSS convention (visual polish is priority 7 — keep it plain).
* Known string bug: `gateway_cmd.rs:779-783` references nonexistent
  `tethra vault unlock` (Phase 0 fix).
* Session-environment gotchas (from earlier handoffs, still true): Rust
  tests want `API_TRACKER_INSECURE_FAST_KDF=1`; CI clippy pins
  `+1.97.0`; npm cache may be root-owned (use a scratch cache dir).

## What is NOT done (honest ledger)

* No code, no migration, no UI, no packaging change exists yet.
* The corrected macOS packaged-validation script has still never been
  re-executed (Phase 3 discharges this).
* Windows/Linux packaged validation: unchanged, not run.
* The stale UI docs (`UI_MAP.md`, `MANUAL_UI_TEST_PLAN.md`) still lack
  gateway coverage until Phase 5.
* PR #15's demanded independent re-audit remains uncommissioned (owner
  decision, O-22-9).

## External actions required from the owner (none block Phase 0–2)

1. Code-signing credentials (Apple Developer ID; Windows Authenticode)
   before any public build — `docs/PACKAGING.md` lists the exact secrets.
2. Decision on commissioning the post-merge independent re-audit of the
   gateway (O-22-9).
3. Optional: PR #14 sequencing preference before Phase 4 (O-22-8).

## Suggested next session

Phase 0 + Phase 1 of `IMPLEMENTATION_PLAN.md`: flake fix, string fix,
`crates/tracking` with detection + plan + migration v15, all library-side
with tests — no UI risk, immediately verifiable.
