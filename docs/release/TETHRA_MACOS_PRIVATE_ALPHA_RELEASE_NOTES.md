# Tethra 0.1.0 — macOS Private Alpha Release Notes

- **Release classification: PRIVATE ALPHA — internal testing only.**
- **Artifacts: UNSIGNED AND UNNOTARIZED — internal testing only.** Do not
  distribute publicly. Gatekeeper will (correctly) refuse the app by
  default; testers must right-click → Open, or clear quarantine:
  `xattr -dr com.apple.quarantine Tethra.app`.
- Platform: macOS, Apple Silicon (arm64) only in this build.
- Exact source commit, checksums, and verification results:
  `docs/release/TETHRA_MACOS_PACKAGING_RESULTS.md`.

## What this release is

The first release candidate under the product's new name, **Tethra**
(formerly API Tracker), containing:

- The complete rebrand with full backward compatibility — existing vaults,
  backups, sessions, git hooks, keychain entries, scripts, and CI keep
  working unchanged. See `docs/rebrand/TETHRA_MIGRATION_GUIDE.md`.
- The new preferred CLI command `tethra` (the `api-tracker` command remains
  installed as a byte-identical compatibility binary).
- New preferred `TETHRA_*` environment variables with the legacy
  `API_TRACKER_*` names still honored; both prefixes are scrubbed from
  injected child processes.
- All Phase 1 (PR #9) and Phase 2 (PR #10) security remediation, previously
  verified by independent re-audits (PASS; the Phase 2 re-audit's single
  merge-blocker — a flaky test — was fixed before merge).

## What this release is NOT

- Not signed and not notarized (no Developer ID certificate or notarization
  credentials exist on the build machine). **Public macOS distribution is
  blocked.**
- Not a GA or public-alpha claim: the full 129-case manual UI plan has not
  been re-executed against this exact build (the last full pass was against
  pre-remediation `7d81090`), no independent audit has run against merged
  main, and the open GA-gate ledger in
  `docs/release/TETHRA_MACOS_PRIVATE_ALPHA_READINESS.md` stands.
- Not tested on Intel macOS, Windows, or Linux in this release.

## Known open issues carried into this release

- MANUAL-001 (low): doc-watch records an HTTP 301 redirect as a successful
  first capture (the redirect is correctly not followed).
- MANUAL-002 (low): cancelling a planned rotation reports state "failed".
- CLI panics on a closed output pipe (NF-1/RA-2, cosmetic).
- `env preview`/`env import` read paths are not confined to registered
  repositories (NF-2/RA-3; read-only, values redacted).
- Full list with classifications:
  `docs/release/TETHRA_KNOWN_RELEASE_LIMITATIONS.md`.

## Verification summary (details in the packaging report)

- Rust workspace: full suite green (exact counts in the packaging report).
- Frontend: prettier, ESLint, tsc, vitest (32 tests), production build — green.
- Smoke suite: 126/126 green, driven through the new `tethra` binary with
  legacy environment variables (the rebrand-compatibility path).
- Packaged app: launches from `Tethra.app`, from the mounted DMG, and from
  a copied install; opens a vault created by a genuine pre-rename build;
  window titled "Tethra"; bundle id preserved; no plaintext secrets in the
  bundle; the user's real vault is never touched by any test.
