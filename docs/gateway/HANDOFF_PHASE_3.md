# Local Gateway — Phase 3 (Productization) Handoff

What Phase 3 turned the tested core into: a product a desktop user can
enable, configure, diagnose, use, disable, and uninstall without keeping a
terminal open. Nothing here is claimed unless a shipped test, a recorded
measurement, or a validation run in this document demonstrates it.

## Commits

- **Starting commit:** `0e76eed` (end of Phase 2 — "CORE LOCAL GATEWAY
  READY FOR PRODUCTIZATION: YES").
- **Ending commit:** the `feat/local-gateway` tip. Phase 3 range is
  `0e76eed..HEAD`, 17 commits (15 feature/doc + 2 CI-hygiene: the
  link/unlink reload fix and the removal of a stray Phase-2 debug probe
  plus Unix-gating of the control-channel tests).
- **PR #13 dependency:** merged into `origin/main` (`5efec9b`) before
  Phase 1; `git merge-base HEAD origin/main == origin/main`, so no rebase
  was required and none was performed. No force-push, no history rewrite.

| Commit | What |
|---|---|
| `4916826` | core: `.env` gateway ownership markers (`set_with_comment`, skip in `generate_example`) |
| `3ee1f6a` | gateway: `/_tethra/probe` listener identity, disabled-route count, richer status |
| `b57c1fd` | gateway: `.env` link engine (`envlink.rs`) |
| `d94d2e3` | gateway: per-user service lifecycle (macOS/Linux/Windows) |
| `3970280` | gateway: the doctor diagnosis engine |
| `9b2be37` | cli: the complete `tethra gateway` family |
| `a262f1f` | ci: compile-validate the full CLI on Windows |
| `45964d3` | desktop: Tauri gateway commands |
| `d4787d2` | desktop: the Gateway panel + consent onboarding + lock strip |
| `199c33a` | source-labeled activity + gateway metrics |
| `532a372` | perf: measurement suite, results, the accept-latency fix |
| `3da8b88` | docs: user guide / troubleshooting / privacy / security / coverage |
| `c7b9052` | style: prettier |
| `0439dc5` | docs: Stage-7 honesty amendments, implementation status, ADR deviations, platform records |
| `c75f574` | fix: reload snapshot on link/unlink; packaged macOS validation (42/42) |

## What was built

Everything in the Phase 3 scope. The authoritative implemented-vs-not
ledger is `IMPLEMENTATION_STATUS.md`; in brief:

- **CLI** (`apps/cli/src/gateway_cmd.rs`): `install` (alias `enable`),
  `uninstall`, `start`, `stop`, `restart`, `repair`, `doctor`, `status`,
  `serve` (alias `run`, plus hidden `--service`), `route add/list/remove/
  enable/disable`, `link`, `unlink`, `push-key`, `revoke-key`, `reload`,
  `recording`, hidden `service-probe`. Follows every existing convention
  (clap derive, anyhow, 0/1 exit, `--json`, per-command `--yes`,
  `prompt_secret` reauth, `render::emit`/`sanitize`).
- **`.env` link/unlink** (`crates/gateway/src/envlink.rs`): lossless
  rewrite through `EnvDocument`, provider-declared variables + `NO_PROXY`,
  marker comments, unmasked-gateway-line diff, digest-bound preview→apply,
  recorded prior state in `gateway_project_links.prior_env_json`, exact
  restore honoring post-link user edits, idempotent re-link, the full
  warning set (git-tracked / template / CI / outside-project / read-only /
  proxy vars / duplicates / malformed / compose / dotenv heuristic),
  symlink refusal, multi-file.
- **Service lifecycle** (`crates/gateway/src/lifecycle/`): macOS
  LaunchAgent, Linux systemd-user, Windows HKCU Run-key — one engine over
  a mockable `CommandRunner`, so `cargo test` never installs a real
  service. `serve --service` retries a held port and self-exits on a
  vanished data dir.
- **Diagnostics** (`crates/gateway/src/doctor.rs`): one lock-free engine
  behind CLI `doctor`/`status`, the desktop Diagnostics tab, and the
  failure banners. Distinguishes all the required states (not installed /
  running / stopped / running-manually / port collision / control-auth /
  version mismatch / invalid snapshot / disabled routes / forwarding /
  recording paused|degraded / vault-locked / buffering / overflow /
  coverage gap / unhealthy / stale path / linked-projects-at-risk).
- **Desktop** (`apps/desktop`): the gateway crate is now a desktop
  dependency (which is what brings the gateway into macOS CI via the
  desktop clippy job); Tauri commands (lock-free status/doctor/route-list/
  start/stop/restart, vault-gated install/disable/uninstall/route-mutate/
  link/unlink/push-key); `GatewayView.tsx` with consent-first onboarding,
  a truthful status panel, routes, projects (preview→apply link), an
  Activity tab, Diagnostics, and Privacy; a lock-screen status strip.
- **Activity honesty**: `credential_activity_sources` (per-source
  last-used) and `gateway_activity_summary` (gateway-only metrics),
  surfaced with source/freshness/coverage labels; the ambiguous "Last
  used" row is gone.

## Deviations from the approved design (all in ADR 0019 "Phase 3 amendments")

1. **D4 resolved** — shipped verb is `serve`; `run` is a full alias.
2. **D11 as challenge-response** — `GET /_tethra/probe?c=<hex>` answered
   with `keyed_hash(derive_key(nonce), challenge)`; the nonce never
   crosses the TCP socket.
3. **No `.env.bak`** — restore comes from the recorded prior state, not a
   sibling copy of a secrets file (leak-primitive rationale).
4. **O5 Windows** — the Run-key lifecycle CODE ships (no new deps) but the
   platform is unvalidated and labeled `RegisteredButNeverValidated`
   everywhere; foreground `serve` is the supported Windows mode.
5. **`ACCEPT_POLL` 50 ms → 5 ms** — a measured fix; perf caught +47 ms per
   fresh connection from the 50 ms accept-poll wake.
6. **Custom-only `[gateway]` manifests (C11)** — `supabase.toml` declares
   `origins = []` + env metadata; `add_manifest_route` refuses such
   providers toward the custom-origin flow.
7. **Foreign-install `--force`** — `install` refuses to steal the login
   slot from a service pointing at a different data directory.

No immutable product/security/privacy requirement was weakened. The
Stage-7 honesty amendments (`THREAT_MODEL.md`, `docs/RUNTIME_OBSERVABILITY.md`,
`docs/FEATURE_MATRIX.md`) correct the claims this feature makes false.

## Validation performed

- **`cargo fmt --all --check`**: clean.
- **`cargo +1.97.0 clippy --workspace --all-targets -- -D warnings`**: clean.
- **`cargo test --workspace --all-targets`** (`API_TRACKER_INSECURE_FAST_KDF=1`):
  **874 passed, 0 failed, 9 ignored** on unix (the 8 perf measurements + 1
  pre-existing bench). Gateway crate: 205 (was 171 in Phase 2). Windows CI
  runs 3 fewer gateway tests — the control-channel is Unix-only (SI-21), so
  the live-gateway doctor tests and the graceful-stop lifecycle test are
  `#[cfg(unix)]`; Windows keeps their injected-state and clean-exit siblings.
- **`cargo build --workspace --release`**: succeeds.
- **`bash scripts/smoke.sh`**: 126 passed, 0 failed (production Argon2id).
- **Desktop CI-equivalent** (`apps/desktop`): `npm ci`, `format:check`,
  `lint`, `typecheck`, `vitest` (**37 passed**, +3 for GatewayView),
  `vite build` — all green.
- **Performance** (`scripts/gateway_perf.sh`, release): 8/8; results in
  `PERFORMANCE_RESULTS.md` (added p50 +69 µs small-JSON, SSE +5.6 ms
  first-byte with 200/200 events, 13.5k req/s concurrent, forwarding
  unaffected by a locked DB).
- **Packaged macOS** (`scripts/gateway_validate_macos.sh`): the full
  28-step lifecycle against a REAL LaunchAgent — **42 checks, 0 failed** —
  plus a privacy canary (no plaintext key in vault.db/WAL/logs). Full
  record in `PACKAGED_MACOS_RESULTS.md`.

## Platform readiness

| Platform | Status |
|---|---|
| macOS | Implemented and **validated end to end** on macOS 26.5 arm64 (packaged, real LaunchAgent). Builds are unsigned — an exec probe gates install and fails honestly toward foreground on a Gatekeeper kill. |
| Linux | Implemented; **unit-tested via the mock runner and compiled+tested in CI**; no packaged end-to-end run this phase (`PACKAGED_LINUX_RESULTS.md`). |
| Windows | Mechanism implemented; **compile-validated in CI only, NEVER executed on Windows** — labeled as such everywhere. Foreground `serve` is the supported mode (`PACKAGED_WINDOWS_RESULTS.md`). |

## Known limitations carried into any Phase 4

Recorded in full in `IMPLEMENTATION_STATUS.md` and `COVERAGE_LIMITATIONS.md`:
no SIGTERM handler (control-channel stop is the graceful path); control
socket unavailable when the data-dir path exceeds ~104 bytes (detected +
warned); `ControlServer` stale-socket replacement is TOCTOU under two
concurrent starts; cost estimates exclude cache-read tokens (lower bound);
no HTTP/2 or WebSockets; no live-provider streaming evidence without a real
key (by policy); macOS builds unsigned; the desktop bundles no CLI
(externalBin deferred until signing — O10, install locates the CLI on
PATH/known dirs and reports honestly when absent).

## Remaining required work (none blocking this PR)

- Real packaged validation on Linux and Windows desktops (the harness and
  honest placeholders exist; the runs do not).
- Code-signing/notarization for macOS so a downloaded build's exec probe
  is not Gatekeeper-blocked.
- Wiring the cached token rate through `estimate_token_cost_as_of` so cost
  is not a lower bound for prompt-cached workloads (a core change).
- A live-provider run with a real key (outside automated CI) to confirm
  streaming/attribution against a provider-accepted `200`.

## Files most important for the final audit

1. `crates/gateway/src/envlink.rs` — the `.env` write/restore engine; read
   the prior-state and user-edit-preservation logic.
2. `crates/gateway/src/lifecycle/{mod,macos,linux,windows}.rs` — the
   service engine and the D8 install order (byte-write → probe → define →
   register → start).
3. `crates/gateway/src/doctor.rs` — the single diagnosis engine every
   surface renders.
4. `crates/gateway/src/forward.rs` — the `/_tethra/probe` handler and the
   unchanged request gate (the security-relevant order).
5. `apps/cli/src/gateway_cmd.rs` and `apps/desktop/src-tauri/src/main.rs`
   (gateway section) — the two frontends; note the lock-free vs vault-gated
   split and the link/unlink reload nudge.
6. `docs/gateway/PACKAGED_MACOS_RESULTS.md` and `PERFORMANCE_RESULTS.md` —
   the evidence, including the honest synthetic-upstream reconciliation.
7. `docs/gateway/SECURITY.md`, `PRIVACY.md`, `COVERAGE_LIMITATIONS.md` —
   the user-facing honesty surface.
8. `docs/decisions/0019-local-gateway.md` — the "Phase 3 amendments"
   section records every deviation with rationale.

LOCAL GATEWAY PRODUCTIZATION COMPLETE: YES
