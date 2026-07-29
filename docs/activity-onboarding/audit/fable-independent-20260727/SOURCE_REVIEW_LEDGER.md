# Source Review Ledger — Independent Audit of PR #16

Audited commit `24acc470`; base `0e6764ba`. 81 files changed, +12,583 / −56.

This ledger records what was actually read, by whom, to what depth, and what came
out of it. "Read fully" means the whole file was read top to bottom, not grepped.

---

## Coverage of the diff

| Area | Files | Lines changed | Review depth |
|---|---|---|---|
| `crates/tracking/` (new crate) | 8 src + 6 test | +5,082 | **Read fully**, 3 independent reviewers |
| `apps/cli/src/track_cmd.rs` + tests | 2 | +913 | Read fully, 2 reviewers |
| `apps/desktop/src-tauri/src/main.rs` | 1 | +676 | Read fully (tracking commands + surrounding state) |
| `apps/desktop/src/` (TrackFlow, Dashboard, App, api, types, tests) | 9 | +1,614 | Read fully |
| `crates/gateway/` (envlink, lifecycle, routes, tests) | 5 | +222 | Read fully + full base-diff |
| `crates/core/` (db, vault, tests) | 3 | +124 | Read fully + full base-diff |
| Packaging (`bundle_cli.sh`, `tauri.conf.json`, capabilities, CI, release) | 6 | +82 | Read fully |
| Validation scripts (`tracking_validate_macos.sh`, `smoke.sh`) | 2 | +322 | **Line-by-line assertion classification** |
| Docs (`docs/activity-onboarding/*`, ADR 0022, README, INSTALL, UI_MAP) | 25 | +2,850 | Read, then cross-checked against code |

Every file in the diff was reviewed by at least one reviewer. The
security-critical files were reviewed by two or three independently, without
sharing intermediate conclusions.

---

## Reviewer assignments (independent, no shared context)

| # | Scope | Primary artifacts | Outcome |
|---|---|---|---|
| R1 | Detection subsystem | `detect.rs` (697 L), `stackdetect.rs`, `tests/detect.rs`, `tests/bounds.rs`, provider manifests | 13 defects incl. **ZFT-001** (RCE), **ZFT-002** (symlink escape), **ZFT-003** (unbounded read), **ZFT-012** |
| R2 | Verification & persisted state | `verify.rs`, `state.rs`, `diagnose.rs`, `db.rs` v15, gateway write path | 8 defects incl. **ZFT-006**, **ZFT-008**; mutation testing (below) |
| R3 | Plan / apply / undo | `plan.rs`, `apply.rs`, `undo.rs`, `envlink.rs`, `plan_apply.rs` | 14 defects incl. **ZFT-007**, **ZFT-018**, **ZFT-022**, **ZFT-023**, **ZFT-024** |
| R4 | Packaging & platform | `bundle_cli.sh`, `tauri.conf.json`, `lifecycle/*`, `helper_discovery.rs`, CI + release workflows | 9 findings; core packaging claim **verified true** |
| R5 | Desktop UX honesty | `TrackFlow.tsx`, `DashboardView.tsx`, `App.tsx`, `api.ts`, `types.ts`, vitest suites | 8 findings incl. **ZFT-015**; premature-verified hunt came back **clean** |
| R6 | Validation integrity | `tracking_validate_macos.sh`, `smoke.sh`, `track.rs`, `ci.yml` | 13 findings; every assertion classified REAL / WEAK / VACUOUS |
| R7 | Gateway security regression | full gateway suite, `routes.rs` + `envlink.rs` base-diff, auto-route path | **ZFT-004**; enforcement plane confirmed **not regressed** |
| R8 | Privacy persistence | every write path repo-wide + dynamic canary run | **ZFT-016**, **ZFT-017**; all other categories clean |
| R9 | IPC, authorization, lifecycle | ten `tracking_*` commands, `capabilities/default.json`, `vault.rs`, ADR 0020 policy | **ZFT-013**, **ZFT-020**, **ZFT-021**; vault change confirmed benign |
| Lead | Packaged end-to-end journeys, reproduction of all CRITICAL/HIGH claims | packaged `Tethra.app` in clean state | 10 findings reproduced first-hand |

---

## Executed test results (measured, not quoted from the PR)

| Command | Result |
|---|---|
| `cargo test -p api-tracker-tracking` | **54 passed, 0 failed** (bounds 10, detect 12, diagnose 7, plan_apply 16, state 9) |
| `cargo test -p api-tracker-gateway` | **269 passed, 0 failed, 8 ignored** (perf only) |
| `cargo test -p api-tracker-gateway --test helper_discovery` | 6 passed |
| `npm test` (desktop) | **65 passed, 0 failed**, 11 files (`TrackFlow.test.tsx` 14, `DashboardView.test.tsx` 10) |
| `npm run typecheck` | clean |
| `npm run lint` | clean |
| `gh pr checks 16` | **all 4 green** on `24acc470` |
| `cargo build --release --workspace` (clean checkout) | **FAILS** until `scripts/bundle_cli.sh` runs — `ZFT-045` |
| `bash scripts/bundle_cli.sh` | OK; sidecar staged; probe OK |
| `npm run tauri build -- --bundles app` | OK; `Tethra.app` produced with helper inside |

The PR's claimed counts ("53 tests", "24 new vitest cases", "6-test suite") are
accurate or slightly conservative against what I measured (54 / 24 / 6).

---

## Mutation testing

Performed by R2 against a throwaway copy (`cp -Rc`; worktree verified
byte-identical afterwards). Target: the single clause defining "a new
observation" — `AND at >= ?2` in `state::refresh` (`state.rs:359`).

| Mutation | Caught? |
|---|---|
| `at >= ?2` → `(at >= ?2 OR 1=1)` (watermark neutralized) | **CAUGHT** — `pre_existing_traffic_never_verifies_a_new_setup` |
| `at >= ?2` → `at > ?2` (boundary flip) | **SURVIVES** — 0 tests fail |
| `observation_source = 'gateway'` → `(… OR 1=1)` | **SURVIVES** — 0 tests fail |
| `project_id = ?1` → `(… OR 1=1)` | **CAUGHT** — `another_projects_traffic_never_verifies_this_setup` |
| downgrade arm → `None` | **CAUGHT** — `an_overclaiming_row_is_downgraded_on_refresh` |

Three guard tests, each killed by exactly one mutant; **two load-bearing clauses
with zero coverage**. The surviving `observation_source` mutant matters: that
filter is the only thing preventing `observe`/`run` proxy sessions — which write
to the same table, for the same project and hosts — from satisfying gateway
verification.

---

## Test-vacuity findings

Tests that pass while the defect they appear to cover is live:

| Test | Verdict |
|---|---|
| `bounds.rs:238 detection_source_makes_no_network_calls` | **Effectively vacuous** — `include_str!("../src/detect.rs")` + `contains("TcpStream")`. A textual grep of one file that cannot see the call graph. Passes while detection spawns git subprocesses (`ZFT-001`). |
| `bounds.rs:172 env_files_are_parsed_never_executed` | Real negative control, but scoped to the env *parser*. Passes while `.git/config` achieves code execution. |
| `bounds.rs:159 oversized_files_are_counted_not_silently_ignored` | Asserts `skipped_oversized >= 1` with no assertion the bytes were not read — fully compatible with `ZFT-003`. |
| `bounds.rs:117 a_symlink_out_of_the_folder_is_never_followed` | Covers only a symlinked `.env` + directory; certifies a bound broader than it tests (`ZFT-002`). |
| `bounds.rs:211 invalid_origins_are_rejected_never_auto_confirmed` | Assertions inside `if let Some(...)`; empty detection passes silently. |
| `detect.rs:78 placeholder_values_do_not_count_as_keys` | Assertions inside `for p in &providers`; empty vector passes. |
| `plan_apply.rs:657 thirty_detected_providers_stay_one_plan…` | **Semi-vacuous** — the 26 synthetic entries match no manifest and produce zero detections, so no scale property is exercised. Degenerates to a 3-provider plan. |
| `plan_apply.rs:472 undo_restores_the_env_exactly…` | Comment describes a user edit that never happens; history guard asserts `0 == 0` on a table empty before undo — a history-deleting undo would pass. |
| `track.rs:219 track_json_status_shape_is_stable` | Asserts only exit code 2. **No JSON is asserted anywhere.** Name overclaims. |
| `detect.rs:315 serialized_detection_never_contains_a_value` | **Solid** — canary negative control plus a positive control so it cannot pass by producing nothing. |
| `bounds.rs:76 the_home_refusal_covers_this_platforms_home_variable` | **Solid** — `assert!(checked > 0)` is exactly the anti-vacuity guard the others lack. |
| `TrackFlow.test.tsx:230 negative control` | **Solid** — mocks `watch:"waiting"`, asserts `queryByText("Tracking verified")).not.toBeInTheDocument()`, and the paired positive test proves the query can find it. |

**Systemic gap:** apart from `empty_folder_detects_nothing`, there is **no
false-positive negative control** anywhere in the detection suite — nothing
asserts that an unrelated dependency, a vendored copy, a test fixture, or a
name-prefix collision does *not* produce a detection. That is the gap `ZFT-025`,
`ZFT-026` and `ZFT-027` live in.

Missing coverage behind confirmed defects: undo-after-failed-apply (`ZFT-007`),
undo-after-re-apply (`ZFT-018`), re-enable-then-undo (`ZFT-019`),
stale-plan/second-slug apply (`ZFT-022`), value-only mutation past the digest
(`ZFT-023`), multi-setup folder selection (`ZFT-037`).

---

## Base-diff regression assessment (pre-existing code)

Changes to already-shipped code carry more risk than the new crate. Assessed
line by line:

* **`routes.rs` (+2 / −2)** — a doc-comment typo fix only (`tethra vault unlock`
  → `tethra unlock`). `validate_origin`, `route_mac` v2, `add_custom_route` and
  the load-time re-validation are byte-identical. **No relaxation.**
* **`envlink.rs` (+73)** — adds `plan_link_as_provider` /
  `plan_link_as_provider_projected`. `plan_link` now delegates with
  `projected = &BTreeMap::new()`, which reduces to the old behaviour. Digest
  check and `apply_link` write path unchanged. Two latent issues surfaced by the
  new caller: `ZFT-022`, `ZFT-023`. One latent signature hazard: the new entry
  point takes `provider_id` free-form rather than resolving it from
  `gateway_routes`; every current caller passes `pid` for both, so binding is
  1:1 today, but the signature no longer enforces it.
* **`lifecycle/mod.rs` (+31)** — bundled-helper discovery behind the same exec
  probe; 6 new passing tests.
* **`core/src/vault.rs` (+56)** — three hunks: canonicalized `project_repos`
  writes, remove-both-spellings, and the `projects_for_folder` reverse lookup.
  **No change** to KDF parameters, lock/auto-lock, zeroization, the
  reauthentication requirement, or decrypted-value lifetime. Confirmed benign.
* **`core/src/db.rs` (+28)** — migration v15 adds one STRICT table, additive.
  `migration_safety` 9/9 pass.
* **`forwarding.rs` test edit** — replaces a blocking `read_response` with
  `read_head` on the 304 test. This **strengthens** the assertion (a wrongly
  relayed body byte now corrupts the next parse). Not a weakened test.

---

## What could not be reviewed

* **Windows and Linux packaged behaviour.** CI compiles and unit-tests on both;
  neither builds nor exercises a packaged app. Not reviewable on this machine.
* **Signed-build behaviour.** All builds are unsigned; Gatekeeper-blocked install
  paths could not be exercised naturally.
* **Real LaunchAgent service mode.** Blocked by `ZFT-014` — the fixed label meant
  exercising it would disable the user's live service. Tested in foreground mode
  instead, with the limitation recorded rather than papered over.
* **Multi-day freshness decay.** `ZFT-005` was demonstrated at the mechanism
  level (no staleness bound exists in code) rather than by waiting out the 7-day
  retention window.
