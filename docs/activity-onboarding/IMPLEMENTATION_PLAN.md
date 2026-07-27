# Implementation Plan — Zero-Friction API Tracking

Phased so every phase lands as a working, tested, honestly-documented
increment (CLAUDE.md definition of done). Base: `main` @ `0e6764b`.
Branch: `feat/zero-friction-api-tracking`.

## Reuse map (from the audits — what we do NOT build)

Reused unchanged: forwarding engine, control plane, lifecycle engine,
route model + MAC keys, `envlink` plan/apply/undo, `doctor`, keyless
probe logic, `stackdetect`, `envgov`, scanner, provider manifests,
pricing/usage extraction, both observation pipelines, vault/session
machinery, ReauthDialog/ConfirmDialog components, `--json` + `render::emit`
conventions.

Removed from the primary UI (kept under Advanced): route forms, link
forms, service action rows, matching-key vocabulary, `Fix: <shell
command>` strings for actions that have buttons.

Made automatic: CLI/helper availability (bundled), service install/start,
route creation, env-file selection + linking, NO_PROXY, attribution push,
restart guidance, first-request verification.

Genuinely new: `crates/tracking` (detection fusion, plan/apply/verify/
diagnose/undo, state machine), migration v15, `Track API activity` UI
flow, `tethra track` command family, folder picker plugin, sidecar
bundling, dashboard IA regrouping.

## Phase 0 — hygiene (small, immediate)

* Fix the flaky `a_304_response_carries_no_body_and_keeps_the_connection_
  usable` test (deterministic handshake instead of a 20 s timing window)
  — it failed CI on the merge commit and passes locally 5/5.
* Fix the wrong `tethra vault unlock` string (`gateway_cmd.rs:779-783`).
* Dated status correction on the three stale gateway handoff/audit docs
  (PR #15 is merged; the demanded re-audit is unrecorded) — see O-22-9.

Exit: CI green on the branch.

## Phase 1 — `crates/tracking`: detection + plan (library only)

* New crate (`#![forbid(unsafe_code)]`), workspace member.
* `detect.rs` per `AUTOMATIC_PROVIDER_DETECTION.md` (fusion over
  stackdetect/envgov/scanner/manifests/vault signals; bounds pinned by
  tests).
* `plan.rs`: `TrackingPlan` assembly, aggregating `envlink::plan_link`
  per provider, service/route actions, warnings, restart expectation.
* Core additions: `project_for_folder` reverse lookup (canonicalize-on-
  compare), canonicalize new `project_repos` inserts.
* Migration v15 (`tracking_setups`) + `state.rs` with re-derivation
  (`refresh`) so persisted state can never overclaim.

Exit: `cargo test -p api-tracker-tracking` green incl. bounds tests;
no UI change yet.

## Phase 2 — apply + verify + diagnose (library) and `tethra track` (CLI)

* `apply.rs` (ordered idempotent steps, per-step report), `verify.rs`
  (probe extraction from `gateway_cmd.rs:1273` + first-request watch),
  `diagnose.rs` (ranked checks), `undo.rs` (track-scoped teardown over
  `envlink::unlink` + route/link rows from the plan summary).
* `apps/cli/src/track_cmd.rs`: `track [PATH]`, `--project`, `--dry-run`,
  `--yes`, `track status`, `track undo`; interactive master-password
  prompt; exit codes 0/2/1 per `TARGET_USER_JOURNEYS.md` §6.
* CLI is the first consumer on purpose: it exercises the whole engine
  end-to-end before any UI work, and gives scriptable test surface.

Exit: on a real sample project, `tethra track . && <restart+request>`
reaches `traffic_observed`; `track undo` restores exactly; smoke-test
extension in `scripts/smoke.sh`.

## Phase 3 — packaging: bundled helper

* `scripts/bundle_cli.sh`, `externalBin` config, release-workflow wiring,
  `locate_cli` bundle-first ordering, version-drift repair step in apply.
* Re-run the corrected `scripts/gateway_validate_macos.sh` against a
  packaged build (it has not been executed since its anti-vacuity fixes —
  this closes that gap too), extended with a "no separately installed CLI
  present" precondition.

Exit: fresh-machine simulation (clean `TETHRA_DIR`, no `tethra` on PATH)
enables tracking from the packaged app with zero terminal use.

## Phase 4 — desktop flow + dashboard IA

* Tauri commands (`tracking_*`), `@tauri-apps/plugin-dialog` (folder
  picker) + capability entry.
* `TrackFlow.tsx`: picker → scanning → review (detection + diff +
  disclosure + password field) → applying → waiting → verified/diagnosis,
  exactly per `TARGET_USER_JOURNEYS.md` (strings are normative).
* Dashboard home (Activity): merge of gateway activity + observe overview
  + labeled provider-reported section; per-project cards with tracking
  state; attribution-paused banner; every empty state actionable.
* Navigation regrouping (ACTIVITY / VAULT / SECURITY / ADVANCED) —
  coordinate with PR #14's sidebar shell (O-22-8): if #14 merges first,
  build groups into its sidebar; otherwise land groups in the current top
  bar and let #14 restyle.
* Desktop diagnostics stop rendering shell commands where a button exists
  (doctor repair strings get an action mapping table in the frontend).

Exit: desktop journeys A–D work end-to-end on macOS; vitest suites for
the flow's state rendering; manual UI test plan extended (`TEST_PLAN.md`
§7).

## Phase 5 — docs, migration of user expectations, release prep

* Update `README.md`, `docs/INSTALL.md` (gateway/tracking section — fixes
  the documented dead end), `docs/TROUBLESHOOTING.md` (tracking section),
  `docs/UI_MAP.md`, `docs/MANUAL_UI_TEST_PLAN.md` (gateway + tracking
  cases — both currently have zero gateway coverage), `docs/gateway/USER_GUIDE.md`
  (points normal users at `track`, keeps expert paths),
  `docs/PRODUCT_SPEC.md` observability positioning note.
* `CHANGELOG.md`; release-notes draft; Linux packaged validation twin if
  Linux claims are made (else keep labels).

Exit: docs describe actual behavior; full workspace checks + smoke green.

## Migration notes (user data)

* Existing gateway users (routes/links made by hand): `track` detects
  existing routes/links and reuses them (`ReuseRoute`, existing-link slug
  reuse via `plan_link_with_slug`) — no duplicate rows, no re-linking, no
  breakage. Their Advanced screens are unchanged.
* No schema rewrites; v15 is additive. Uninstall/backup paths inherit the
  new table automatically (backup v2 captures tables generically).
* `project_repos` rows stay as stored; comparisons canonicalize.

## Effort shape (indicative, not a promise)

Phases 1–2 are the bulk (library + CLI). Phase 3 is small but
validation-heavy. Phase 4 is UI-wide but composes existing components.
Each phase is independently shippable behind the existing UI (nothing
user-visible until Phase 4 except the `track` command).

## Risks

* PR #14 collision on the desktop shell (O-22-8) — mitigated by phase
  ordering (UI last) and group-vs-shell separation.
* Framework env-loading heuristics (restart expectation, override
  detection) will have false negatives — always fail toward showing the
  restart instruction; keep the load-order table versioned and tested.
* Windows remains labeled-not-validated; `track` on Windows configures
  foreground-only and says so.
