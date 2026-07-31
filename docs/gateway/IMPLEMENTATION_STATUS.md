# Local Gateway — implementation status

The authoritative implemented-versus-not ledger for the gateway feature
after Phase 3 (productization) and the Phase 5 audit remediation, 2026-07-26.
Anything not listed as implemented here should be assumed absent. Details live in the referenced
documents; nothing below is claimed without a shipped test or a recorded
measurement.

## Phase 5 — audit remediation (shipped)

Remediating the final independent audit (`audit/lg-final-independent-20260726`
against base `ae66ca7`). Full matrix: `docs/gateway/audit/REMEDIATION.md`.

| Piece | State |
|---|---|
| Matching-key lock lifecycle (ADR 0020) | Implemented: `VaultLocked`/`VaultUnlocked` control ops, policy in the service (`lock_disposition`, fails toward revoking), bounded keep-while-locked retention on dual clocks, enforcement in the poller. Every lock path in both frontends signals. 11 tests, one mutation-checked. |
| Keep-while-locked toggle | Implemented and ENFORCED (it was a stored column with no consumer): reauth-gated to enable, immediate key drop on disable, CLI + desktop surfaces, live countdown in status. |
| Matching-key TTL | Implemented: locking session's `auto_lock_minutes`, hard cap 8 h. Decision and reasoning in ADR 0020. |
| Custom-route verification key (ADR 0021) | Implemented: `PushRouteKey`/`RevokeRouteKey`, installed on route add, unlock, route enable, and foreground `serve`. Before this, `set_mac_key` had no callers and every custom route was permanently 503. 13 end-to-end tests. |
| Route MAC v2 | Implemented: binds `route_prefix`, so a MAC'd row cannot be transplanted onto another prefix. Fails closed for v1 MACs. |
| Gateway-table deletion | Implemented: `observe delete-all` reaches all three gateway tables; per-project deletion reaches the two project-scoped ones. Previously none had any deletion path. |
| Migration v14 | Implemented: index on `gateway_usage_events(event_id)`. |
| Black-box attack battery | Adopted from the audit branch: 17 tests over 16 attack categories (`adversarial_blackbox.rs`). |
| Validation-script integrity | Corrected: no unconditional passes, semantic assertions, privacy canaries, negative controls, minimum-check floor. `PACKAGED_MACOS_RESULTS.md` is marked superseded pending a fresh run. |

**NOT implemented, and no longer claimed anywhere** (each previously appeared
as a present-tense mitigation):

| Claim | Reality |
|---|---|
| SIGTERM handler clears the key | No signal handler exists. Graceful stop clears it; SIGTERM/SIGINT/SIGKILL/crash/power-loss do not. THREAT_MODEL GW-6 now says so. |
| Automatic disabling of unused routes | Does not exist and is deliberately not being added (no last-used column; "unused" is not reliably observable; silent disabling would break periodic projects). An enabled route is a disclosed standing exposure. THREAT_MODEL GW-7. |
| `SO_PEERCRED` peer-euid enforcement | Not implemented; `peer_cred` is unstable and the alternatives need `unsafe` or a new dependency. The gate is filesystem permissions re-checked per accept. SI-21. |
| Per-tool link coverage note | Not implemented. The shipped heuristics are Node `package.json` dotenv detection and a compose-file warning. PRODUCT_BEHAVIOR corrected. |

## Core (Phase 2 — shipped)

| Piece | State |
|---|---|
| Forwarding engine (`forward.rs`, `head.rs`, `stream.rs`) | Implemented: canonical head regeneration, strict chunked relay (smuggling rejected, not normalized), streamed bodies both directions, per-(connection,route) upstreams, three timeout budgets |
| Secure route table (`routes.rs`) | Implemented: manifest origins as the trust root, MAC'd custom origins, last-known-good snapshots, SSRF two-phase validation. Scope limit (SEC-01): the built-in route's `provider_id` selector is unauthenticated — see `SECURITY.md` and `THREAT_MODEL.md` GW-3 |
| Attribution (`attribution.rs`) | Implemented: keyed-fingerprint matching, six honest states, scoped matcher table, `attribution_method` provenance |
| Usage extraction (`usage.rs`) | Implemented: bounded OpenAI/Anthropic shapes, absent-is-a-state, cache-token semantics per provider |
| Observation writer (`writer.rs`) | Implemented: dedicated thread, bounded queue with drop-and-count, transactional persist, retention/rollup |
| Control channel (`control.rs`) | Implemented: authenticated Unix socket (0600/0700, per-boot nonce, constant-time compare), write-only key channel; Windows stub REFUSES rather than TCP fallback |
| Migration v13 | Implemented: append-only, STRICT, `gateway_*` tables + `attribution_method` column |

Phase 2 ended at 826 workspace tests, 171 in the gateway crate
(`HANDOFF_PHASE_2.md`).

## Productization (Phase 3 — shipped)

| Piece | State |
|---|---|
| CLI family (`gateway_cmd.rs`) | Implemented: `install` (alias `enable`, consent summary + confirm + port choice + verified startup), `disable`, `uninstall`, `start`, `stop` (graceful control drain first), `restart`, `repair`, `doctor`, `status`, `serve` (alias `run`, plus hidden `--service` mode), `route add/list/remove/enable/disable`, `link`/`unlink`, `push-key`/`revoke-key`, `reload`, `recording`, hidden `service-probe` |
| `.env` link engine (`envlink.rs`) | Implemented: lossless rewrite via `EnvDocument`, per-provider variables + `NO_PROXY`, marker comments, unmasked-gateway-line diff, digest-bound preview→apply, recorded prior state, exact restore honoring user edits, idempotent re-link, warnings (git-tracked / template / CI path / outside-project / read-only / proxy vars / duplicates / malformed / compose / dotenv heuristic), symlink refusal, multi-file |
| macOS lifecycle (`lifecycle/macos.rs`) | Implemented: LaunchAgent (never a daemon), fresh byte-write install + `xattr -d` + exec probe BEFORE the plist, `KeepAlive={Crashed:true}`, bootstrap/bootout/`kickstart -k`, 0600 plist, `--data-dir` in argv, foreign-data-dir refusal, prune-on-upgrade |
| Linux lifecycle (`lifecycle/linux.rs`) | Implemented: systemd USER unit, `WantedBy=default.target`, `Restart=on-failure`, honest linger reporting (never auto-enabled) |
| Windows lifecycle (`lifecycle/windows.rs`) | Implemented as CODE, **compile-validated only**: HKCU `Run` value via `reg.exe`, probe-verified stop, `RegisteredButNeverValidated` everywhere; foreground `serve` is the supported Windows mode |
| Service run mode (`service::run_as_service`) | Implemented: held-port retry with capped backoff (never exits), clean self-exit when the data dir / vault.db disappears, service log file |
| Listener identity (`/_tethra/probe`) | Implemented: challenge–response derived from the per-boot nonce; used by status, doctor, install verification, link probes, and Windows stop |
| Doctor engine (`doctor.rs`) | Implemented: one lock-free diagnosis distinguishing not-installed / running / stopped / running-manually / port collision / control auth failure / version mismatch / invalid snapshot / disabled routes / recording states / buffering / overflow / coverage gap / vault-locked attribution / unhealthy process / stale paths / linger / Windows honesty / linked-projects-at-risk / env drift |
| Desktop backend | Implemented: 21 gateway commands; status/control lock-free (lock screen stays informed), mutations vault-gated, digest-bound link plan/apply, core-enforced reauth for the key push |
| Desktop UI (`GatewayView.tsx`) | Implemented: consent-first onboarding (no silent install; honest CLI-absence message), status panel with findings + repair actions, routes tab, projects link/unlink with preview diff, Activity tab (gateway-only, labeled), Diagnostics, Privacy, lock-screen status strip |
| Activity source labels | Implemented: per-credential last-activity by source (gateway / proxy / provider-reported / manually marked / validated + most-recent-with-source), gateway-only metrics summary, `Marked used` project column |
| Performance measurement | Implemented: `tests/perf.rs` + `scripts/gateway_perf.sh`; measured results in `PERFORMANCE_RESULTS.md`, including the measured `ACCEPT_POLL` 50 ms → 5 ms fix |
| CI | Gateway compiled+tested on Linux and Windows; full CLI now compile-validated on Windows; gateway reaches macOS CI through the desktop crate's new dependency |

## Not implemented / known limitations

- **No SIGTERM handler** (a signal-handling dependency is ruled out by the
  ADR): Ctrl-C terminates without drain; `tethra gateway stop` /
  control-channel shutdown is the graceful path. launchd/systemd stops via
  the CLI use the control drain first.
- **Control socket path limit:** a data-directory path past ~104 bytes
  makes the Unix control socket unavailable (detected, warned; forwarding
  and recording continue).
- **`ControlServer::start` stale-socket replacement is TOCTOU** under two
  concurrent starts against one data directory (small window, documented).
- **Cost estimates exclude cache-read tokens** — a LOWER bound for
  prompt-cached workloads (`estimate_token_cost_as_of` has no cached-rate
  path; carrying it through remains a core follow-up).
- **HTTP/1.1 only:** no HTTP/2, no WebSockets/upgrades (501).
- **Windows has never executed a gateway.** Compile + unit tests on CI
  only. Never claimed otherwise. The Unix service-manager behavioral tests
  (LaunchAgent/systemd file formats, the graceful control-plane stop, the
  live-gateway doctor diagnoses) and the "vault DB deleted underneath a
  running gateway" scenario are `#[cfg(unix)]` — the control channel is
  Unix-only (SI-21) and Windows cannot delete an open file. One writer
  stress test (`dropped_events_are_reported_not_hidden`) asserts strict
  counter conservation only on Unix: replaying 1024 increments to a single
  row across the writer's rapid per-batch WAL connection cycle can lose
  committed increments on Windows (a SQLite-on-Windows durability quirk of
  connection cycling, not an accounting gap — no bump errors, and the
  queue-drop accounting that SI-12 actually protects is asserted on every
  platform). Production bumps one counter per exchange over time, never in
  that burst.
- **No live-provider streaming evidence:** SSE correctness/timing evidence
  comes from the synthetic-upstream suite; a keyless request to a real
  provider proves the forwarding path (401), but streaming a real response
  requires a real key, which validation never uses.
- **macOS builds are unsigned:** Gatekeeper may kill the exec probe on a
  quarantined install; install then fails honestly toward foreground mode
  (the consent copy says so).
- **The desktop bundles no CLI** (`externalBin` deferred until signing —
  OPEN_DECISIONS O10): desktop enable requires the separately installed
  CLI and reports its absence honestly.
- **Container traffic is out of scope** (127.0.0.1 inside a container is
  the container's own loopback) — documented v1 non-goal.

## Validation evidence, per platform

| Platform | Evidence |
|---|---|
| macOS | Full workspace test suites locally (arm64); measured performance (`PERFORMANCE_RESULTS.md`); packaged end-to-end run recorded in `PACKAGED_MACOS_RESULTS.md` |
| Linux | Lifecycle unit-tested against the mock runner + temp dirs; gateway crate compiled and tested in Linux CI on every push; no real systemd session was driven (`PACKAGED_LINUX_RESULTS.md`) |
| Windows | Compile + unit tests in Windows CI only; no gateway has ever executed on Windows (`PACKAGED_WINDOWS_RESULTS.md`) |

## Where to read more

- User-facing: `USER_GUIDE.md`, `TROUBLESHOOTING.md`, `PRIVACY.md`,
  `SECURITY.md`, `COVERAGE_LIMITATIONS.md`
- Engineering: `ARCHITECTURE.md`, `SECURITY_INVARIANTS.md`,
  `PRIVACY_MODEL.md`, `THREAT_MODEL.md`, `TEST_PLAN.md`
- Decisions: `docs/decisions/0019-local-gateway.md` (including the Phase 3
  amendments), `OPEN_DECISIONS.md`, `KNOWN_CONFLICTS.md`
- History: `HANDOFF_PHASE_1.md`, `HANDOFF_PHASE_2.md`, `HANDOFF_PHASE_3.md`
