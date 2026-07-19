# Continuation — Everything Still Open After Phase 2

**Branch:** `fix/security-phase-2`. **Baseline:** `033f747` (merged PR #9).
This lists what remains after Phase 2's nine fixes, so a follow-up pass (or an
independent re-audit) can pick up without re-deriving scope.

## Fixed in Phase 2 (for reference)

PI-02/CONC-11 (+CLI-03/RA-1), GScan-01/02, CONC-06, GScan-03/CONC-05, DEST-01/
02/03 (+DEST-04 verify honesty), OBS-004, M-6, the Tauri direct-authorization
harness + command inventory, the React security-workflow test foundations
(incl. the IPC-05 `docs_url` fix), and RA-4 (Windows env-casing scrub).

## Deferred by the Phase 2 brief (explicitly out of scope)

- **RA-2 / NF-1 — CLI broken-pipe panic.** Piping CLI stdout into
  `head`/`grep -q` panics on a closed stdout. Cosmetic; no secret. Fix: reset
  `SIGPIPE` or handle `ErrorKind::BrokenPipe` in the CLI entry point.
- **RA-3 / NF-2 — unconfined `env_preview` / `env_import` reads.** Read-only
  arbitrary-path reads (`crates/core/src/vault.rs`), adjacent to the now-fixed
  IPC-01 write. Values are scanner-redacted in previews. Fix: confine to the
  project's registered repositories, mirroring `env_example_write`.
- **CONC-01 / CONC-02 — desktop mutex breadth and auto-lock across suspend.**
  Phase 3 removed git-time from CONC-01 for scans but not the coarse mutex
  model or the `Instant`-based auto-lock's suspend behavior.
- **PI-03 — descendant / process-group termination.** Only the recorded
  process is signalled; grandchildren survive (now tested as documented
  behavior).
- **PI-05 — wall-clock grant/session expiry rollback.** A backward clock can
  re-activate an expired CLI grant/session (desktop auto-lock uses monotonic
  time).
- **ROT-002..008, ROT-011 — remaining rotation state-machine races and
  correctness items.** ROT-001/010 were fixed in PR #9; the rest remain.
- **Remaining Low / Informational findings** from the deep audit's
  `FINDINGS_INDEX.md` not listed above (DEST-05..13, OBS-002/005..012,
  FS-01..08, CONC-07..10/12, CLI-02/04/05/06, CRYPTO-03/04/05, NET-01..04,
  GScan-04/05, INFO-01/02, IPC-04/05-adjacent).

## New this phase (see NEW_FINDINGS.md)

- **RA-P2-1** — `backup_create` / `provider_admin_connect` /
  `provider_admin_test` enforce reauth in the Tauri wrapper, not core (Low).
- **RA-P2-2** — 97 low-relevance Tauri commands have no direct authorization
  test (Informational).
- **RA-P2-3** — ProviderDetail opens backend-manifest URLs via `openUrl`
  without FE scheme validation (Info/Low).

## Manual / out-of-automated-scope verification still required

- **Windows behavioural runner** for: the process-identity probe
  (`Get-CimInstance`), `taskkill` graceful→forceful, git hook execution via
  `sh`, and the case-insensitive env scrub. CI compiles these paths but does
  not execute them.
- **Live-provider verification** (real credentials): destination read-back /
  exists semantics per provider; the full rotation lifecycle per provider.
- **Packaged Tauri app**: `cargo-tauri` is not installed locally, so no
  `.app`/`.dmg` bundle or runtime CSP/allowlist/opener verification was
  produced this phase.
- **Manual UI plan updates**: hook `active`/`Overridden` status,
  destination not-checked drift rows, invalid-expiration display, docs_url
  inert-rendering (see PHASE_2_REMEDIATION.md "Manual tests still required").

## Release-gate status after Phase 2

- **Public alpha:** the public-alpha blocker set was already closed by PR #9
  (CRYPTO-01, OBS-001, PI-01, IPC-01, CONC-04, OBS-003, ROT-001, PI-06, IPC-02).
- **Production / GA:** Phase 2 closes the remaining audit-named GA-gate
  findings (GScan-01/02, DEST-01/02/03, OBS-004, CONC-06, PI-02, M-6, and the
  Tauri/frontend automated-test gaps). Remaining before a GA claim: the
  deferred items above (notably PI-05, CONC-01/02, the ROT-* races), the manual
  Windows/live-provider/packaged-app verification, and an independent
  adversarial re-audit of this branch.
