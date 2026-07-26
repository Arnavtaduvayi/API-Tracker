# Tethra macOS Private Alpha — Release-Readiness Inventory

> **Naming note:** API Tracker was renamed **Tethra** on the
> `release/tethra-macos-private-alpha` branch. Every audit, remediation, and
> test document referenced below predates the rename and uses the historical
> name; those documents are accurate for the baselines they describe and are
> deliberately not rewritten. See `docs/rebrand/TETHRA_REBRAND_PLAN.md`.
>
> **Scope update (2026-07-25):** this inventory was compiled before the
> branch integrated `main` (PR #13, runtime API observability). That feature
> is now part of the branch and is NOT covered by the readiness evidence
> below; it carries its own audit trail in `docs/observability/audit/`.
> Re-package and re-verify before releasing.

- **Date:** 2026-07-24
- **Branch:** `release/tethra-macos-private-alpha`
- **Branch point (verified):** `4f8c8cb1bd3217231c6f8b298534ce64c8ce78cf`
  (main = merge of PR #11, manual-UI-testing docs). Phase 2 security merge
  `0ab6636eefda46a99125c2f4bd3c801700626ffa` (PR #10) verified as an ancestor
  via `git merge-base --is-ancestor`.
- **Packaged source commit:** the exact commit that produces the shipped
  artifacts is recorded in `docs/release/TETHRA_MACOS_PACKAGING_RESULTS.md`
  (this branch's HEAD at build time; the rebrand commits sit between the
  branch point and that HEAD).
- **Application version:** 0.1.0 (consistent across the Cargo workspace,
  `apps/desktop/package.json`, and `tauri.conf.json`).
- **Target classification for this release: PRIVATE ALPHA (internal testing
  only).** The artifacts are unsigned and unnotarized (see §"Blocks public
  alpha"); this build must not be represented as publicly deployment-ready.

## How this inventory was produced

Every item below was checked against the *current* state of the release
branch rather than copied forward from historical reports:

- Remediation ledgers: `docs/remediation/RELEASE_BLOCKER_REMEDIATION.md`
  (PR #9, baseline `7d81090`), `docs/remediation-phase-2/PHASE_2_REMEDIATION.md`
  and `CONTINUATION.md` (PR #10, baseline `033f747`), and both `NEW_FINDINGS.md`
  files.
- Independent re-audits (sibling audit worktrees, none of whose report sets
  exist on main): the deep audit (`audit/deep-pressure-test` @ `fba2b72`,
  baseline `7d81090`), the PR #9 remediation re-audit
  (`audit/remediation-reaudit` @ `7ec6973`, verdict **PASS**), and the Phase 2
  re-audit (`audit/security-phase-2-reaudit` @ `17de499`, verdict **PASS WITH
  REQUIRED CHANGES** — the single required change, flaky test RA2-6, was fixed
  on PR #10 by `095494a` "test: make recycled pid identity test deterministic"
  before the merge to main; the fixed test is in current main and passes).
- Latest manual test execution report:
  `docs/manual-test-runs/LOCAL_MANUAL_TEST_2026-07-19.md` on branch
  `test/manual-local-smoke` @ `65b3b25` — 113 PASS / 0 FAIL / 12 NOT RUN /
  4 deferred numbered IDs + 7 live scripts, **executed against pre-remediation
  baseline `7d81090`, not current main**.
- The full workspace test suite was run green on the branch point before any
  rebrand change (exit 0, `cargo test --workspace --all-targets` with
  `API_TRACKER_INSECURE_FAST_KDF=1`); exact post-rebrand counts are in the
  packaging report.

## Classification legend

- **[PA]** Blocks private alpha
- **[PUB]** Blocks public alpha
- **[GA]** Blocks GA
- **[DOC]** Documentation limitation
- **[MAN]** Manual-verification requirement
- **[PLAT]** Platform-specific limitation
- **[DEF]** Deferred non-release work

## 1. Blocks private alpha — **none open**

No known unresolved issue blocks a *controlled, internal* private alpha,
provided the artifacts are distributed only to known testers with the
"unsigned and unnotarized — internal testing only" label and Gatekeeper
bypass instructions. The public-alpha blocker set (CRYPTO-01, OBS-001,
PI-01, IPC-01, CONC-04, OBS-003, ROT-001, PI-06, IPC-02) was closed by PR #9
and independently verified PASS by the remediation re-audit; the audit-named
GA-gate set (PI-02, GScan-01/02, CONC-06/GScan-03/CONC-05, DEST-01/02/03,
OBS-004, M-6, wrapper reauth for `provider_admin_disconnect`, IPC-05, RA-4)
was closed by PR #10 and verified by the Phase 2 re-audit.

## 2. Blocks public alpha

| Item | Status | Detail |
|---|---|---|
| **[PUB] Signing & notarization** | **BLOCKED — missing credentials** | This machine has **zero** codesigning identities (`security find-identity -v -p codesigning` → "0 valid identities found"), no Developer ID Application certificate, no notarytool keychain profile, and no `APPLE_*`/`TAURI_SIGNING_*` environment variables. The DMG produced by this release is unsigned and unnotarized, labeled "internal testing only". Public macOS distribution is blocked until the user provisions an Apple Developer ID Application certificate + notarization credentials (see `docs/PACKAGING.md` §Signing). |
| **[PUB][MAN] Full manual UI pass on current main** | OPEN | The only full manual execution (129 IDs) ran against pre-remediation `7d81090`. Phase 2 changed user-visible behavior (hook status states, invalid-expiration display, destination drift rows, inert unsafe URLs). The targeted packaged-app checks for this release (see packaging report) cover the security-critical subset only; a full re-execution of `docs/MANUAL_UI_TEST_PLAN.md` against the packaged release candidate has not been done. |
| **[PUB] Independent re-audit of merged main** | OPEN | Both re-audits verified *branches* (PR #9 head `1ec4073`, PR #10 head `260e47e`). No independent audit has run against merged main (`0ab6636`/`4f8c8cb`) or this release branch. The planned full Fable independent re-audit of the 96-finding deep-audit set was prepared (two pristine worktrees) but **never executed** — no deliverables exist. |

## 3. Blocks GA (per the Phase 2 CONTINUATION release-gate statement and re-audit ledger)

All verified open at the branch point; none is claimed fixed by this release.

- **[GA] Rotation state-machine races — ROT-002..008, ROT-011.** Untouched by
  Phase 2; the Phase 2 re-audit calls these "the highest-value remaining
  follow-up". Includes rotation interruption/race-condition work.
- **[GA] Process & concurrency edge cases — CONC-01 (coarse desktop mutex),
  CONC-02 (auto-lock across suspend), CONC-07..10, CONC-12, PI-03 (descendant
  processes survive termination; tested as documented behavior), PI-05
  (wall-clock rollback re-activates expired CLI grants/sessions).**
- **[GA] CLI broken-pipe panic — NF-1 / RA-2.** Verified still present at the
  branch point (no `BrokenPipe`/`SIGPIPE` handling exists in `apps/cli` or
  core; grep confirms). Cosmetic (no secret exposure), reproduced by both
  re-audits when piping CLI stdout into `head`/`grep -q`.
- **[GA] Environment-file read confinement — NF-2 / RA-3.** `env_preview` /
  `env_import` still read arbitrary filesystem paths (read-only; values
  scanner-redacted). The *write* path (`env_example_write`, IPC-01) is fixed
  and confined; the read paths are not.
- **[GA] Wrapper-only reauthentication — RA-P2-1.** `backup_create`,
  `provider_admin_connect`, `provider_admin_test` enforce reauth in the Tauri
  wrapper, not core (defense-in-depth gap, not an active bypass).
- **[GA] Frontend/authz coverage gaps — RA-P2-2, RA2-5.** 97 of 137 Tauri
  commands have no direct authorization test; React security coverage has
  three named holes (reveal auto-hide timer, EnvView error path,
  replace-value dialog clearing).
- **[GA] Provider pagination limitation — RA2-1.** Vercel env resolution does
  not paginate; very large env sets can produce a false "absent" (fails safe
  — no destructive action taken on "absent"). OpenAI sync paginates with a
  bounded page cap.
- **[GA] RA-P2-3.** ProviderDetail passes backend-manifest URLs to `openUrl`
  without frontend scheme validation (backend/opener allowlist remains the
  gate).
- **[GA] Remaining deep-audit Low/Informational ledger.** DEST-05..13,
  OBS-002/005..012, FS-01..08, CLI-02/04/05/06, CRYPTO-03/04/05, NET-01..04,
  GScan-04 (medium-confidence secrets pass the pre-commit block), GScan-05
  (documented evasion gaps), INFO-01/02, RA2-2..RA2-4.
- **[GA][MAN] Upstream verification of pinned CI actions.** M-6 pinned all 23
  actions to full commit SHAs (verified), but the SHA↔upstream-release-tag
  correspondence has never been verified against upstream (offline-unverifiable
  at audit time; still unverified).

## 4. Documentation limitations

- **[DOC] `docs/UI_MAP.md` and `docs/MANUAL_UI_TEST_PLAN.md` describe the
  pre-remediation baseline `7d81090`** (their stated stamp). They pre-date
  both Phase 2 behavior changes and the Tethra rename. They carry a
  historical-baseline banner (added this release) rather than a rewrite;
  Phase 2's CONTINUATION lists the specific manual-plan additions still
  needed (hook `active`/`Overridden` status, destination not-checked drift
  rows, invalid-expiration display, docs_url inert rendering).
- **[DOC] LICENSE copyright appendix** retains the stock Apache-2.0
  placeholder (`Copyright [yyyy] [name of copyright owner]`); no NOTICE file.
  Not filled in this release — registrant/legal identity must come from the
  user, not be invented.
- **[DOC] `docs/PACKAGING.md`** documents no DMG naming convention or bundle
  output paths; the packaging report for this release records the actual
  paths produced.
- **[DOC] Historical reports** (remediation ledgers, audit evidence, manual
  test run, FABLE_HANDOFF) intentionally keep "API Tracker" naming.

## 5. Manual-verification requirements

- **[MAN] Packaged-app behavior on current main** — performed for this
  release on the built bundle (results in the packaging report): fresh
  first-launch vault, lock/unlock, wrong password, masked secrets,
  reauth-gated reveal/delete, legacy-vault compatibility, backup/restore,
  no plaintext secrets on disk, CSP/external-link behavior, Tethra branding
  in window title/notifications/Finder.
- **[MAN] Keychain-assisted destination cases** — 12 NOT-RUN manual IDs
  (DST-02/03/05/06/07/08, SYN-01/02/04/05, VLT-10-offline, CON-03) need a
  human to click macOS Keychain "Allow" dialogs / toggle Wi-Fi; still
  outstanding since the 2026-07-19 run.
- **[MAN] Two open low defects from the last manual run** — MANUAL-001
  (doc-watch records an HTTP 301 as successful `first_capture`; the redirect
  is correctly not followed) and MANUAL-002 (cancelling a planned rotation
  stores terminal state "failed" and prints "Cancelled (state: failed)").
  Neither was claimed fixed by Phase 2; both are assumed still present on
  current main pending re-test.
- **[MAN] Live provider verification** — `scripts/live_verify_*.sh` (7
  scripts) have never been run; destination read-back/exists semantics and
  the full rotation lifecycle are unverified against real provider accounts.
  Deliberately out of scope for this release (no real credentials permitted).
- **[MAN] Live destination verification** — AWS / GitHub Actions / Vercel
  destinations are fixture-tested only; GitHub/Vercel can never be
  value-verified by read-back (write-only APIs), labeled
  `present_unverifiable`.

## 6. Platform-specific limitations

- **[PLAT] Windows behavioral testing** — the process-identity probe
  (`Get-CimInstance`), `taskkill` graceful→forceful, git hook execution via
  `sh`, and the case-insensitive env scrub compile in CI but have never been
  *executed* on Windows.
- **[PLAT] Local build is Apple Silicon (arm64) only** — this machine is
  aarch64; x86_64 macOS, Windows, and Linux artifacts come only from CI and
  are untested locally.
- **[PLAT] Notifications require the app open and unlocked** — no OS
  background service (by design, documented).
- **[PLAT] Packaged .app launched via Finder/`open` does not inherit shell
  env vars** — `TETHRA_DIR`/`API_TRACKER_DIR` overrides only apply when
  launching the inner binary from a shell (known quirk, documented in the
  manual test plan).

## 7. Deferred non-release work

- **[DEF]** Doppler / 1Password / HashiCorp Vault destinations (ADR 0016).
- **[DEF]** Cached-token discount modeling in cost estimates.
- **[DEF]** Per-request activity logging (no official provider API; ADR 0014).
- **[DEF]** Reproducible builds, SLSA provenance, SBOM (PACKAGING.md future
  work).
- **[DEF]** Crate renames (`api-tracker-core`/`-cli`/`-desktop`), GitHub
  repository rename, and the data-directory rename — see the rebrand plan's
  deferred-identifier table; all are compatibility-preserving deferrals, not
  regressions.
- **[DEF]** Webhook payload `source: "api-tracker"` and rotation-created
  provider key prefix `api-tracker-rotation-*` — preserved verbatim so
  existing user webhook filters and provider-side artifacts keep working.

## 8. Release classification decision

**Private alpha (internal testing only).** The build is expected to be
functionally complete and green across the full automated suite, but it is
unsigned/unnotarized, the current-main manual pass and merged-main re-audit
are outstanding, and the GA ledger above is open. It must not be published,
tagged, or represented as publicly deployment-ready.
