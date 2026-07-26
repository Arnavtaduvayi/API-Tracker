# Tethra macOS Private Alpha — Known Release Limitations

Companion to `TETHRA_MACOS_PRIVATE_ALPHA_READINESS.md` (full classification)
and `TETHRA_MACOS_PACKAGING_RESULTS.md` (verification evidence). This file
lists what a private-alpha tester and the release owner must know.

## Distribution

- **Unsigned and unnotarized — internal testing only.** No Developer ID
  Application certificate or notarization credentials exist on the build
  machine; Gatekeeper refuses the app by default (verified: `spctl` reject).
  Public macOS distribution is **blocked** until the user provisions an
  Apple Developer ID certificate and notarization credentials
  (`docs/PACKAGING.md` §Signing lists the exact inputs).
- Apple Silicon (arm64) only; Intel macOS, Windows, and Linux artifacts
  exist only via CI and are untested locally.
- Launching the `.app` via Finder/`open` does not inherit shell environment
  variables, so `TETHRA_DIR` overrides require launching the inner binary
  from a shell (documented quirk).

## Functional (open defects, all Low)

- **MANUAL-001** — doc-watch records an HTTP 301 as successful
  `first_capture`; the redirect is correctly not followed.
- **MANUAL-002** — cancelling a planned rotation stores terminal state
  "failed" and prints "Cancelled (state: failed)".
- **NF-1 / RA-2** — the CLI panics on a closed stdout pipe
  (`… | head` / `grep -q`); cosmetic, no secret exposure.
- **NF-2 / RA-3** — `env preview` / `env import` read arbitrary local paths
  (read-only, values redacted); write path is confined, read paths are not.

## Security posture (open, non-blocking for private alpha)

- Rotation state-machine races ROT-002..008/011 (top remaining follow-up).
- CONC-01/02 (desktop mutex breadth; auto-lock across suspend), PI-03
  (descendant processes survive termination), PI-05 (wall-clock rollback
  can re-activate expired CLI grants/sessions).
- RA-P2-1 (three commands enforce reauth in the Tauri wrapper, not core),
  RA-P2-2/RA2-5 (authorization/frontend test-coverage gaps), RA-P2-3
  (frontend scheme validation relies on the backend/opener allowlist),
  RA2-1 (Vercel env resolution unpaginated; fails safe), plus the deep
  audit's Low/Informational ledger (see readiness inventory §3).

## Verification debt

- The 129-case manual UI plan has not been re-executed against this build
  (last full pass: pre-remediation `7d81090`, 113 PASS / 0 FAIL / 12 NOT
  RUN). This session re-verified the packaged-app subset listed in the
  packaging report only.
- 12 manual cases require a human (macOS Keychain "Allow" dialogs, Wi-Fi
  off), unchanged since 2026-07-19.
- No independent audit has run against merged main; the planned full
  Fable re-audit of the 96-finding set was prepared but never executed.
- Windows behavioral paths (identity probe, taskkill, `sh` hooks,
  case-insensitive scrub) compile in CI but have never been executed on
  Windows.
- Live provider/destination verification (`scripts/live_verify_*.sh`) has
  never been run; network destinations are fixture-tested only.
- Pinned CI action SHAs have not been diffed against their upstream tags.

## Rebrand-specific limitations

- The vault data directory intentionally keeps its historical `api-tracker`
  name; the macOS bundle identifier remains `dev.api-tracker.desktop`; the
  inner bundle executable remains `api-tracker-desktop`. All deliberate —
  see `docs/rebrand/TETHRA_COMPATIBILITY_MATRIX.md`.
- The webhook payload `source` field still reads `api-tracker` (preserved
  for receiver compatibility).
- Crate names and the GitHub repository name are unchanged (deferred).
- No Tethra-specific icon exists; the existing approved icon set is used.
- The UseTethra.com domain was NOT purchased (blocked; see
  `DOMAIN_PURCHASE_RECORD.md`) — no docs reference the domain.
