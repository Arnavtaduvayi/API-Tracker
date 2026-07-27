# Handoff — Activity Onboarding Phase 2 (Implementation)

Branch `feat/zero-friction-api-tracking` (worktree
`API-Tracker-zero-friction`), based on `main` @ `0e6764b`.
Phase 1 produced the architecture; **this phase implemented it**.

Companion records: `IMPLEMENTATION_STATUS.md` (what works, with counts),
`PACKAGED_VALIDATION.md` (executed packaged evidence),
`KNOWN_LIMITATIONS.md`, `MIGRATION.md`, `DETECTION_COVERAGE.md`,
`USER_GUIDE.md`, `TROUBLESHOOTING.md`, `audit/REVIEW_HANDOFF.md`.

## Record

```text
Base commit    0e6764b  (main, PR #15 merge)
Final head     see PR #16 head
Branch         feat/zero-friction-api-tracking
PR             #16 (open, NOT merged)
Commits behind base  0 (branch is a fast-forward of main @ 0e6764b)
```

A note on history: the first push was rejected by GitHub push protection,
which matched a synthetic Stripe fixture value in the new tests. The
fixture was changed to the convention already used elsewhere in this
repository and the (never-pushed) local commits were rewritten to remove
the pattern. No shared history was rewritten — the rejected push never
landed.

## Repository state as verified live

* PR #15 (Local Gateway) is merged; `main` @ `0e6764b` is the base. The
  only other open PR is #14 (`eesh-ui`, sidebar shell) — not modified,
  not merged. The navigation regrouping here landed in the current top
  bar so #14 can restyle it (O-22-8's documented default).
* The flaky `a_304_response_carries_no_body_and_keeps_the_connection_
  usable` test that failed CI on the merge commit is **fixed
  deterministically**, not retried: it no longer waits out a 20 s client
  read timeout. 20/20 consecutive local runs, 0.02 s each.
* A second latent flake was found and fixed while running the baseline:
  `hook_falls_back_to_the_legacy_binary_name` prepended its stub dir to
  the real `PATH`, so on any machine with a real `tethra` installed the
  hook preferred it and the legacy fallback was never exercised. It now
  builds a hermetic PATH.

## What was built

Eight commits, each independently green:

1. `fix:` Phase 0 hygiene — the two test fixes above plus the
   user-facing `tethra vault unlock` string (no such subcommand; it is
   `tethra unlock`).
2. `feat(core,gateway):` migration v15 (`tracking_setups`),
   `projects_for_folder` reverse lookup with canonicalized inserts, and
   two read-only `envlink` planning entry points — including
   `plan_link_as_provider_projected`, which is what lets several
   providers share one `.env` in a single coherent diff whose digests
   still bind apply to exactly what was previewed.
3. `feat(tracking):` the `api-tracker-tracking` crate — detect, plan,
   apply, verify, diagnose, state, undo.
4. `feat(cli):` `tethra track` (+ `status`, `doctor`, `undo`).
5. `feat(packaging):` the bundled sidecar, closing gateway O10.
6. `feat(desktop):` the Track flow and the Activity dashboard.
7. `test(packaging):` the packaged macOS validation script.

## Load-bearing facts the next phase should not re-derive

* **The orchestrator is the only place setup logic lives.** Desktop and
  CLI are both thin callers, so they cannot drift. `ServiceOps` is the
  single seam between orchestration and the host — tests supply a mock,
  production supplies `HostServiceOps`.
* **Apply order is load-bearing and pinned by a test**: project → port →
  service → routes → route MAC key → links → reload → probe →
  attribution → record. It follows existing hard constraints (persisted
  port before `plan_link`, route rows before link rows, MAC key before
  custom routes forward).
* **Multi-provider plans are chained, and undo unwinds in reverse.**
  Provider N plans over provider N−1's projected file content; undo
  restores last-to-first so each layer lands on the state it recorded.
  Getting this backwards silently corrupts a shared `.env`.
* **Verification is derived, not stored.** `state::refresh` recomputes
  observed states from `runtime_request_events` on every read and
  downgrades a row that claims more than the evidence supports. Do not
  add a code path that writes `traffic_observed` without an observation.
* **Detection's value-read exception is exactly one rule** — a
  manifest-declared non-secret base-URL var of a custom-origin provider,
  validated and confirmed. Widening it is a security change.
* `plan()` takes `listener_live` because a foreground `gateway serve`
  counts as running; without it, setup would try to install a service
  over a working one.

## Environment gotchas (still true)

* Rust tests want `API_TRACKER_INSECURE_FAST_KDF=1`.
* CI clippy pins `+1.97.0`.
* `~/.npm` may be root-owned — use `npm ci --cache <scratch>/npm-cache`.
* `timeout(1)` does not exist on macOS.
* `scripts/bundle_cli.sh` must run before any `tauri build`, or the
  bundler fails on the missing `externalBin`.

## Honest ledger — what is NOT done

* **Linux and Windows packaged runs were not performed** and nothing
  about them is claimed. Windows attribution remains structurally
  unavailable.
* **The desktop GUI click-through was not automated** (no display access
  in this environment). Every operation behind it was executed through
  the same commands the UI calls; a human click-through is still worth
  doing before release.
* **The LaunchAgent install path was not exercised in the packaged run** —
  an existing user agent was preserved rather than clobbered. Covered by
  the mock-runner lifecycle suite and `gateway_validate_macos.sh`.
* Code signing is unresolved and remains the one external dependency.
* Stripe/GitHub manifest expansion, source-import detection, nested
  manifests, and `observed_api_services` seeding are deliberately out of
  scope (O-22-1, O-22-6, O-22-10).
* PR #15's demanded independent re-audit is still uncommissioned
  (O-22-9) — an owner decision, unchanged by this work.

## External actions required from the owner

1. **Code-signing credentials** (Apple Developer ID; Windows
   Authenticode) before any public build. `docs/PACKAGING.md` lists the
   exact secrets. Until then, unsigned builds may need the foreground
   fallback on first run.
2. **A decision on O-22-9** (the post-merge independent gateway
   re-audit).
3. **PR #14 sequencing** — this branch regrouped the existing top bar
   rather than touching #14's shell.

## Suggested next milestone

Provider-manifest expansion (O-22-1), starting by verifying against
official documentation which Stripe and GitHub SDK versions actually
honor a base-URL environment variable — the detection and plan layers
already absorb new manifest entries without an API change.
