# Source review ledger

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`
Audit worktree: `audit/pr16-fresh-final-20260729` (fresh, created from that commit)
Diff reviewed: `main@0e6764ba…0c3b7d6f` — +51,544 / −665

Legend — **X** = read in full · **P** = read the relevant regions ·
**E** = executed / driven · **M** = mutated to test falsifiability

## Validation harnesses

| Path | Depth | Notes |
| --- | --- | --- |
| `scripts/validation_manifest.json` | X | 4 scopes; identity binding for `SERVICE` only |
| `scripts/ci_assert_service_results.py` | X, E, M | 30 forgery vectors run against it; 1 leak |
| `scripts/validation_manifest_check.sh` | P, E | 37 passed, 0 failed |
| `scripts/validation_asserter_tests.sh` | P, E | 33 passed, 0 failed |
| `scripts/validation_harness_mutants.sh` | X, E | 8 killed, 0 survived |
| `scripts/validation_ownership_tests.sh` | X, E* | 29 passed; *`launchctl` shimmed |
| `scripts/gateway_validate_macos.sh` | X, M | primitives extracted and mutated; **not** executed (production gateway) |
| `scripts/tracking_validate_macos.sh` | P, E | `--scope selfcheck` 5/5; `enumerate_checks()` read in full |
| `scripts/ci_service_preconditions.sh` | X | glob covers `/tmp/tethra-track-val-*` only |
| `scripts/ci_service_cleanup_check.sh` | P | |
| `scripts/service_cleanup_safety.sh` | P | read only, never executed |
| `scripts/smoke.sh` | E | 140 passed, 0 failed |
| `scripts/bundle_cli.sh` | X, E | sidecar staging — a build prerequisite, see `NEW-22` |
| `.github/workflows/ci.yml` | P | |
| `.github/workflows/packaged-service-macos.yml` | X | the job that matters |

## Tracking crate (the new orchestrator)

| Path | Depth | Notes |
| --- | --- | --- |
| `crates/tracking/src/state.rs` | X, M | CAS, `derived` ladder, `refresh_with`; M2/M3 killed, M4 survived |
| `crates/tracking/src/verify.rs` | X | `check_traffic` is liveness-blind — origin of `NEW-01` |
| `crates/tracking/src/apply.rs` | P | step ordering, `fail!` retry, `EnsurePort` before `EnsureService` |
| `crates/tracking/src/undo.rs` | P | `transition` callers propagate |
| `crates/tracking/src/plan.rs` | P | `Selections`, `approve_origin`, hard error on unconfirmed |
| `crates/tracking/src/origin.rs` | X | `approval_mac`, `is_approved`, dead `OriginTrust`, unused `list`/`revoke` |
| `crates/tracking/src/detect.rs` | P | manifest-anchored built-in matching |
| `crates/tracking/src/diagnose.rs` | P | |
| `crates/tracking/tests/zft006_regression.rs` | X, E | 5 tests incl. an anti-vacuity control |
| `crates/tracking/tests/verification_concurrency.rs` | P, E | 13 tests |
| `crates/tracking/tests/verification_freshness.rs` | P, E | 16 tests |
| `crates/tracking/tests/origin_trust.rs` | P, E | |

## Gateway crate

| Path | Depth | Notes |
| --- | --- | --- |
| `crates/gateway/src/envlink.rs` | X | `open_prior_file`, `restore_file`, `scrub_stored_prior_env`, `upgrade_restore_records` — ENC-01/ENC-02 |
| `crates/gateway/src/routes.rs` | P | `route_mac`, `validate_origin`, `add_manifest_route` |
| `crates/gateway/src/store.rs` | P | `port_hint` swallows every failure — root of `NEW-02` |
| `crates/gateway/src/lifecycle/mod.rs` | P | `installation_id`, `ensure_ours` |
| `crates/gateway/src/lifecycle/macos.rs` | P | label derivation, `reclaim_legacy` |
| `crates/gateway/src/service.rs` | P | `run_as_service` never falls back to port 0 |
| `crates/gateway/src/writer.rs` | P | opens `vault.db` read-write |
| `crates/gateway/src/doctor.rs` | P | no `config.port` vs live-port comparison |
| `crates/gateway/tests/legacy_rollback_migration.rs` | X, E | incl. the source-text call-site guard |

## Core crate

| Path | Depth | Notes |
| --- | --- | --- |
| `crates/core/src/db.rs` | P | schema for `gateway_project_links`, `gateway_routes`, `tracking_approved_origins`; migration v19 `row_version`; `checkpoint_truncate` |
| `crates/core/src/envrestore.rs` | X | module doc reviewed against ENC-02 |
| `crates/core/src/vault.rs` | P | `env_restore_key`, per-vault id and MAC keys |
| `crates/core/src/error.rs` | P | `StateConflict` is typed and SQL-free |
| `crates/core/src/providers.rs` | P | manifests are `include_str!`-compiled |

## CLI

| Path | Depth | Notes |
| --- | --- | --- |
| `apps/cli/src/track_cmd.rs` | X | verify loop (`NEW-01`) vs `status()` — the same file states both rules |
| `apps/cli/src/gateway_cmd.rs` | P | install ordering (`NEW-02`), `serve_service_mode` |
| `apps/cli/src/ctx.rs` | P | `confirm_default_no` takes no `assume_yes` |
| `apps/cli/tests/track.rs` | X | 10 tests, all on the unconfigured path |
| `apps/cli/tests/track_origin_refusal.rs` | X, E, M | 11 tests; mutation kills 6 |

## Desktop

| Path | Depth | Notes |
| --- | --- | --- |
| `apps/desktop/src-tauri/src/main.rs` | P | `vault_unlock` migration call site, `health_kind` 12-arm map, gateway enable ordering |
| `apps/desktop/src/components/TrackFlow.tsx` | P | headline gated on `currently_working`; the ZFT-005 comment |
| `apps/desktop/src/components/DashboardView.tsx` | P | "Right now" vs "Previously" split |
| `apps/desktop/src/components/TrackFlow.test.tsx` | P, E | the gateway-down regression test |
| `apps/desktop/src/components/DashboardView.test.tsx` | P, E | |

## Documentation reviewed against behaviour

`THREAT_MODEL.md` · `docs/activity-onboarding/KNOWN_LIMITATIONS.md` ·
`docs/activity-onboarding/SECURITY_AND_PRIVACY.md` ·
`docs/decisions/0019-local-gateway.md` · `docs/decisions/0028-encrypted-env-restore-records.md` ·
`docs/gateway/OPEN_DECISIONS.md` · and the eleven files under
`docs/activity-onboarding/audit/`.

## Not reviewed / not executed, and why

| Area | Reason |
| --- | --- |
| Live service-lifecycle scopes on this machine | Production gateway present; forbidden by the brief |
| Desktop GUI click-through | No GUI automation available; UI claims are source-reviewed plus vitest only |
| `crates/observe` beyond `policy.rs` | Outside this PR's diff except where tracking calls it |
| Windows-specific lifecycle | CI-only; the Windows check passed on the audited head |
