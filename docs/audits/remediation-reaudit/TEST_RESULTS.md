# Test Results — remediation re-audit

Environment: macOS (Darwin 25.5.0), rustc/cargo **1.97.0** (CI toolchain, used for all Rust
commands to avoid clippy drift), node v24.13.0 / npm 11.6.2. HEAD under test: `1ec4073`.
Raw evidence: `evidence/tooling_and_test_results.txt`,
`evidence/crypto01_independent_baseline_repro.log.txt`.

## Rust — full workspace
`cargo +1.97.0 test --workspace --all-targets` → **413 passed, 0 failed** (27 test binaries
with tests), exit 0.

## Rust — focused regression suites (individual, with exact names/counts/durations)

| Suite / test | Finding | Result | Duration |
|---|---|---|---|
| `crypto01_rotation_race` (4 fns: add-race, replace-race, multiprocess-add-race, child-worker) | CRYPTO-01/CONC-03 | 4 passed / 0 failed | 3.27s |
| `obs001_exposure_alert_lifecycle` (7 fns) | OBS-001 | 7 passed / 0 failed | 0.79s |
| `obs003_sync_range_guard` (7 fns) | OBS-003 | 7 passed / 0 failed | 0.33s |
| `rot001_revoke_recovery` (5 fns) | ROT-001/ROT-010 | 5 passed / 0 failed | 0.71s |
| `ipc01_env_example_confinement` (9 fns) | IPC-01/FS-09 | 9 passed / 0 failed | 0.35s |
| `run_env_scrub::injected_child_sees_mapped_credentials_but_no_api_tracker_auth_vars` | PI-01/CLI-01 | 1 passed / 0 failed | 0.94s |
| `credentials::credential_lifecycle_with_metadata` | IPC-02 | 1 passed / 0 failed | 0.04s |
| `rotation_access::revoke_404_is_an_error_not_success_on_first_attempt` | ROT-001 | 1 passed / 0 failed | 0.05s |
| `inject::tests::terminate_pid_refuses_non_positive_pids` | PI-06 | 1 passed / 0 failed | 0.00s |
| `backup::tests::backup_snapshot_is_consistent_under_concurrent_rotation` | CONC-04 | 1 passed / 0 failed | 26.70s* |

*Uses the real production Argon2id KDF (no test escape hatch), hence the runtime.

## CRYPTO-01 — deterministic race stress (HEAD)
5 consecutive full runs of `crypto01_rotation_race`, each ~16 armed races (`armed=true`
verified per iteration): **5/5 runs clean, 0 orphans** (~80 races total). Durations
3.44–3.82s.

## CRYPTO-01 — independent baseline reproduction (`7d81090`, disposable worktree)
The unmodified checked-in `crypto01_rotation_race.rs` compiled against real baseline production
code (only the `rusqlite` dev-dep added for the lock probe) → **3/3 race tests FAILED
(orphaned)**, `armed=true`, "does not decrypt under the persisted project key." Confirms the
regression test genuinely fails at baseline and passes at `1ec4073` — not a green test that
never exercised the vulnerability.

## Baseline-fail evidence validation (remediation's own `docs/remediation/evidence/`)
| Finding | Baseline evidence | Nature | Faithful? |
|---|---|---|---|
| CRYPTO-01 | `crypto01_baseline_fail.log.txt` | **Real** baseline run (re-reproduced independently) | Yes |
| PI-01 | `pi01_baseline_fail.log.txt` | **Real** (black-box CLI binary) | Yes |
| OBS-003 | `obs003_baseline_fail.log.txt` | **Real** (end-to-end sync; history wiped) | Yes |
| ROT-001 | `rot001_baseline_fail.log.txt` | **Real** (public rotation API; state wedged) | Yes |
| IPC-02 | `ipc02_baseline_fail.log.txt` | Signature-adapting shim | Faithful (baseline deletes w/o reauth) |
| IPC-01 | `ipc01_baseline_fail.log.txt` | Signature-adapting shim | Faithful (baseline writes anywhere, no reauth) |
| CONC-04 | `conc04_baseline_fail.log.txt` | Deterministic-seam shim | Faithful (baseline non-transactional read → undecryptable restore) |
| OBS-001 | `obs001_baseline_fail.log.txt` | Shim-assisted | Faithful for the 6 vulnerability tests (auto-resolution) |
| PI-06 | (none, by design) | Inspection + fixed-behavior test | Baseline run is itself the hazard |

No shim changes the property under test in a way that invalidates the demonstration; each
adapts a signature or adds a deterministic interleave point while preserving the vulnerable
behavior.

## Lint / format / build
- `cargo +1.97.0 clippy --workspace --all-targets -- -D warnings` → **0 warnings**, exit 0.
- `cargo +1.97.0 fmt --all --check` → clean, exit 0.
- `cargo +1.97.0 build --release -p api-tracker-cli` → exit 0.
- Desktop Tauri backend (`api-tracker-desktop`) compiles (via clippy `--all-targets` and the
  workspace test build). `cargo-tauri` is not installed locally, so no bundle/packaged-app
  build was produced.

## Frontend (apps/desktop — exact CI commands)
- `npm ci` → ok (0 vulnerabilities).
- `npm run format:check` (prettier) → clean.
- `npm run lint` (eslint) → clean.
- `npm run typecheck` (tsc --noEmit) → clean.
- `npm test` (vitest run) → **8 passed / 0 failed** (1 file: `src/utils.test.ts`).
- `npm run build` (tsc --noEmit && vite build) → built in 601ms, 59 modules.

## Smoke
`bash scripts/smoke.sh` (release binary, production Argon2id, throwaway vault, fake creds) →
**126 passed, 0 failed**, exit 0. The NF-1/RA-2 broken-pipe panic was observed on stdout during
`head`/`grep`-piped sections; it did not affect any assertion (suite still 126/0).
