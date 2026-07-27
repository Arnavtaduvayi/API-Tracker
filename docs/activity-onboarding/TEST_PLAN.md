# Test Plan — Zero-Friction API Tracking

What must be proven, per layer. Conventions follow the repo: mocks and
fixtures only, no real credentials, unmistakably fake values, tests never
touch the developer's own vault or unrelated repositories, `cargo test`
never installs a real service (mock `CommandRunner`).

## 1. Detection (`crates/tracking/tests/detect.rs`)

* Fixture folders (committed, tiny) per scenario: node+openai,
  python+anthropic, mixed 3-provider, supabase-with-origin,
  supabase-two-conflicting-origins, stripe-only (unsupported),
  lockfile-only (possible), empty folder, placeholder-values-only.
* Confidence table pinned: each fusion rule from
  `AUTOMATIC_PROVIDER_DETECTION.md` §3 has a fixture proving it, including
  the two-signal requirement for Confirmed and the stack-preferences
  up/down adjustment.
* Evidence never contains a value: serialize every `ProjectDetection` from
  every fixture and assert no fixture secret marker appears (canary
  pattern, mirroring `privacy_canaries.rs`).
* Unsupported providers never suppress supported ones.

## 2. Detection bounds (the security-critical suite)

* Refuses `/`, home directory, and a path that canonicalizes to either.
* Symlink escape: fixture with a symlink pointing outside the folder —
  assert the target is never opened (instrumented via a canary file whose
  read would fail the test).
* Depth cap honored; oversized files counted in `skipped_oversized`, not
  silently ignored.
* No execution: fixture `.env` with `$(touch pwned)` and backticks —
  parse-only assertion (file must not exist after detection; value stays
  literal).
* No network: detection runs with a panicking mock resolver/HTTP seam.
* Origin inference: only manifest-declared non-secret base-URL vars are
  value-read; a secret-classified var with a URL value is never surfaced;
  inferred origins failing `validate_origin`/SSRF policy (http://, :8080,
  loopback, RFC1918, metadata IPs) are rejected with the finding, never
  auto-confirmed.

## 3. Plan and apply (`crates/tracking/tests/{plan,apply}.rs`)

* Plan aggregation: two-provider fixture yields two `LinkPlan`s, one
  service action, correct route actions; existing route → `ReuseRoute`;
  disabled route → re-enable action; existing link → slug reuse
  (`plan_link_with_slug`), never a second link row.
* Apply order pinned: service before routes before links before probe
  before attribution (mock step recorder asserts sequence).
* Idempotence: apply twice → second run is all no-ops, zero new rows.
* Partial failure: route step forced to fail → earlier steps intact,
  report names the step, state = `needs_attention`, undo offer present;
  no silent rollback.
* Digest mismatch mid-apply (file mutated between plan and apply) →
  abort with re-plan signal, file untouched (delegates to existing
  `envlink` behavior — regression-pinned here at the orchestrator level).
* Undo: restores env exactly (reuses `envlink` restore semantics),
  removes only plan-attributed routes/links, keeps shared routes used by
  another project, keeps history rows.
* Attribution skipped (no password) → tracking proceeds, state records
  attribution off; push failure → apply completes with warning, not
  failure.

## 4. State machine (`crates/tracking/tests/state.rs`)

* Every transition in `TARGET_USER_JOURNEYS.md` §7 exercised; illegal
  transitions rejected.
* `refresh` re-derivation: a hand-edited `traffic_observed` row with zero
  events downgrades on read — persisted state can never overclaim
  (SI-19-alignment test).
* `partially_observed`: 2 providers, events for 1 → correct state and
  per-provider freshness.
* Clock honesty: `first_traffic_at` only set from an event at/after
  `applied_at`; pre-existing traffic from an earlier setup never verifies
  a new one.

## 5. Verification and diagnosis (`crates/tracking/tests/{verify,diagnose}.rs`)

* Probe extraction: provider-401 through a `MockUpstream` gateway →
  path-proof success; gateway-answered response (`tethra-gateway:`
  marker) → honest not-forwarded failure (reuses the existing test
  harness from `crates/gateway/tests/common`).
* Watch: event inserted for the setup's slug → `Observed` with provider
  and latency; unrelated slug → still waiting; deadline → `TimedOut`.
* Each diagnosis id has a positive and negative fixture (compose file
  present/absent; override var in later-loaded file; drifted link via
  doctored `LinkHealth`; gateway stopped via mock status; all-clear →
  the explicit "everything checks out" result).
* Ranking stable and pinned (ids in order).

## 6. CLI (`apps/cli/tests/track.rs`)

* `--dry-run` writes nothing (filesystem + DB snapshot compare), exit 0.
* Full run against mock-runner lifecycle + `MockUpstream`: reaches
  `awaiting_first_request`, exit 2 without traffic, exit 0 after a
  simulated request; `track status` output matches state; `track undo`
  restores; `--json` shapes stable.
* No secret in any output (canary sweep over stdout/stderr).
* Never prints `--print-export` or any shell-export instruction.

## 7. Desktop (vitest + manual plan)

* Vitest: `TrackFlow` state rendering per state (strings from
  `TARGET_USER_JOURNEYS.md` asserted verbatim for the load-bearing ones:
  disclosure card, waiting, verified, attribution-paused banner, Journey D
  empty state); fetch-failure paths render error + retry (no silent
  empties); review screen disables Start-tracking when nothing
  configurable.
* Manual UI test plan additions (currently zero gateway/tracking cases):
  scripted cases for Journeys A–D, the foreground fallback, stop/undo, and
  the Advanced escape hatches, in the existing 129-case template format.

## 8. Packaged end-to-end (macOS, scripted)

Extend `scripts/gateway_validate_macos.sh` (or a sibling
`tracking_validate_macos.sh` sharing its assert library — keep the
anti-vacuity floor pattern: minimum check count, `assert_db`,
`assert_status`):

* Precondition: no `tethra` on PATH, clean `TETHRA_DIR` → proves the
  bundled-helper path.
* `Tethra.app`-driven flow up to service running (scriptable via the CLI
  sidecar path for the service part), then `tethra track .` on a fixture
  project with fake keys against real provider origins (401 = proof),
  restart-simulation, verification reaching `traffic_observed`,
  `track undo`, uninstall, artifact sweep, privacy canaries.
* This run also discharges the outstanding "corrected macOS validation
  script has never been re-executed" debt from
  `docs/gateway/PACKAGED_MACOS_RESULTS.md`.

## 9. Regression guards inherited

* Full existing suites stay green: workspace (~936 at last recorded run),
  gateway crate suites, smoke.sh 126, desktop vitest.
* Phase 0's deterministic rewrite of the flaky 304 keep-alive test
  verified by 20 consecutive local runs and one CI cycle.

## 10. Explicitly not claimed by tests

Windows execution (labeled), Linux packaged run unless Phase 5 does one,
live-provider streaming, Docker-project tracking (diagnosed, not
supported), and any provider not in `provider-manifests/`.
