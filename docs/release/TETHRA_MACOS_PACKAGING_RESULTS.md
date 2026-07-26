# Tethra macOS Packaging Results — Private Alpha

> **Superseded build (2026-07-25):** these results record commit
> `0972f20`. The branch has since integrated `main` (PR #13, runtime API
> observability) and extended the rebrand over it, so the artifacts, sizes,
> and SHA-256 values below no longer correspond to the branch head. They
> remain the accurate record of what was built and verified on `0972f20`;
> **regenerate the package and re-run this verification before releasing.**

## Build provenance

- **Source commit (packaged):** `0972f20cc76d9682c3473538c23e875564830ffb`
- **Branch:** `release/tethra-macos-private-alpha` (branched from main
  `4f8c8cb`; Phase 2 merge `0ab6636` verified in ancestry)
- **Build date:** 2026-07-24 (local, Apple Silicon macOS 26.5 / build 25F71)
- **Toolchains:** rustc/cargo 1.96.1 stable (build), clippy run under the
  pinned 1.97.0 toolchain, Node v24.13.0, npm 11.6.2, tauri-cli 2.11.4,
  Tauri crate 2.11.5, Xcode 26.3 (17C529)
- **Application version:** 0.1.0 (workspace, package.json, tauri.conf all
  consistent)
- **Bundle identifier:** `dev.api-tracker.desktop` (preserved on purpose —
  see rebrand plan §7.7)
- **Bundle metadata:** CFBundleName/DisplayName `Tethra`, executable
  `api-tracker-desktop` (internal name preserved), LSMinimumSystemVersion
  10.13
- **Build command:** `npx tauri build` from `apps/desktop` (lockfile-
  preserving `npm ci` used for dependencies; note: `npm ci` requires an
  alternate cache dir on this machine because `~/.npm` is root-owned —
  a pre-existing, documented environment quirk)

## Artifacts

Staged in
`/Users/arnavtaduvayi/Documents/APItrack/API-Tracker-artifacts/tethra-macos-private-alpha/`
(none committed to git):

| Artifact | Size | SHA-256 |
|---|---|---|
| `Tethra.dmg` (= `Tethra_0.1.0_aarch64.dmg`) | 6,093,279 B | `133504fa9ad4859d11802b8581805bd456cc6d892350ebe0d3ab8c16b64ee115` |
| `Tethra.app.zip` (ditto-archived bundle) | 6,089,417 B | `6537d3595ffb6902ae96fd58916add329f20503b425b0f5cc269be71822d68ed` |
| `tethra` (CLI, release) | 9,475,936 B | `e8d6c8e986a278f779523264de229067b1f7bb39d6107e666f53b0561abc213f` |
| `api-tracker` (CLI compat, release) | 9,475,952 B | `3a31f6313dc9bd6e9e52318d5d02d486eddc99fa883d516ec2d9411c833c087c` |

Build-tree originals: `target/release/bundle/macos/Tethra.app`,
`target/release/bundle/dmg/Tethra_0.1.0_aarch64.dmg`. Architecture:
**arm64 only** (thin Mach-O). Both artifacts were produced by the final
build of commit `0972f20` (rebuilt after a strings-sweep of the first
build found and removed two residual old-brand literals).

## Signing / notarization / Gatekeeper — UNSIGNED

**Unsigned and unnotarized — internal testing only.**

- `security find-identity -v -p codesigning` → **0 valid identities**; no
  Developer ID Application certificate, no notarytool keychain profile, no
  `APPLE_*`/`TAURI_SIGNING_*` environment variables. No credentials were
  invented; no Apple account was created.
- `codesign -dv` → `Signature=adhoc`, `flags=0x20002(adhoc,linker-signed)`,
  `TeamIdentifier=not set`
- `codesign --verify --deep --strict` → FAILS: "code has no resources but
  signature indicates they must be present" (expected for a linker-signed,
  unsigned bundle)
- `spctl --assess --type execute` → REJECTS with the same message
  (Gatekeeper refuses the app — expected)
- `xcrun stapler validate` → no ticket on `.app` or `.dmg` (never notarized)
- **Public macOS distribution: BLOCKED.** To unblock, the user must
  provision: an Apple Developer Program membership, a Developer ID
  Application certificate (+ `APPLE_SIGNING_IDENTITY`/cert env vars for
  tauri-action), and notarization credentials (`APPLE_ID`,
  `APPLE_PASSWORD` app-specific password or an App Store Connect API key,
  `APPLE_TEAM_ID`), then re-run signing + notarization + stapling per
  `docs/PACKAGING.md`.

## Automated validation on the packaged commit (exact counts)

| Suite | Command | Result |
|---|---|---|
| Rust workspace (all targets) | `API_TRACKER_INSECURE_FAST_KDF=1 cargo test --workspace --all-targets` | **525 passed / 0 failed / 0 ignored** across 39 suite binaries (includes migration-safety, security-regression, authorization (`tauri_command_authz`, 18), reauthentication, process-identity (`pi02`, 10 + kill-guard), git-scanner (`scanning`, `gitbound_scanning`, `gscan_hooks` 14), env-file confinement (`ipc01`, 9), backup/restore, rebrand compat (`tethra_compat`, 13), env precedence, CLI alias tests) |
| Rust format | `cargo fmt --all -- --check` | clean |
| Clippy (pinned toolchain) | `cargo +1.97.0 clippy --workspace --all-targets -- -D warnings` | clean |
| Frontend format | `npm run format:check` (prettier) | clean |
| Frontend lint | `npm run lint` (eslint) | clean |
| Frontend types | `npm run typecheck` (tsc) | clean |
| Frontend tests | `npm test` (vitest) | **32 passed / 0 failed** (7 files) |
| Frontend build | `npm run build` (tsc + vite) | success |
| Smoke suite | `bash scripts/smoke.sh` | **126 passed / 0 failed** — run through the `tethra` binary driven entirely by legacy `API_TRACKER_*` variables (the rebrand-compatibility path) |

Baseline note: the same workspace suite was green at the branch point
before any rebrand change (exit 0). During rebrand validation the smoke
suite initially failed 72 checks and exposed a real compatibility bug
(stale `TETHRA_SESSION` after a legacy-only `unset`); fixed in `776b759`
with a password fallback + regression tests, after which smoke returned to
126/0.

## Packaged-application verification (synthetic data only)

Isolated workspace `~/at-tethra-release-test/`; the user's real vault
(`~/Library/Application Support/api-tracker/vault.db`) was stat-snapshotted
before testing and verified byte-identical (same mtime/size) after — **no
test ever touched it**. Every launch used the inner bundle binary with
`TETHRA_DIR` pointed at an isolated directory (the packaged app ignores
shell env when launched via `open` — documented quirk).

| Check | Result |
|---|---|
| Direct launch of `Tethra.app` (fresh isolated dir) | PASS — process stable, window titled **"Tethra"** |
| Fresh first launch creates no silent vault | PASS — isolated dir stays empty until the UI creates a vault |
| Legacy-vault compatibility | PASS — a vault created by the **genuine pre-rename binary** (built from main `4f8c8cb`) opens in the packaged Tethra app; `vault.db` byte-identical after; still unlocks via CLI |
| Mount `Tethra.dmg` | PASS — volume mounts as **"Tethra"**, contains `Tethra.app` + Applications symlink; `hdiutil verify` checksum VALID |
| Launch from mounted image | PASS — window "Tethra" |
| Copy to disposable Applications-style dir + launch | PASS — window "Tethra" (no existing installed app was touched) |
| Close and reopen (repeated instance kills across tests) | PASS — vault state persisted, reopened cleanly each time |
| Wrong password | PASS — rejected (verified through the shared core via CLI against the same vault; UI dialog covered by React tests) |
| Backup before rebrand → restore after rebrand | PASS — backup created by the pre-rename binary restores through `tethra` into a fresh dir with contents intact |
| `tethra` and `api-tracker` on the same vault | PASS — both directions (vault created by either opens in both) |
| Env-var precedence / DIR-conflict warning / dual-prefix child scrub | PASS — `tethra_compat` suite (13 tests) |
| No plaintext secret in vault dir or app bundle | PASS — grep for all synthetic markers: none |
| No fallback to the normal user vault | PASS — isolated dirs honored; real vault untouched |
| Runtime CSP config embedded | PASS — exact configured CSP string present in the binary (frontend assets are embedded compressed) |
| External-link surface | Config verified: opener capability allowlists `https://*`, `http://*`, `mailto:*` only; unsafe-scheme inertness covered by `safeUrl` unit tests (3) and React security tests |
| Native notification branding | Source verified (`title: "Tethra"` in `App.tsx`/`AlertsView.tsx`, embedded in the compressed bundle); a live OS banner was not triggered in this run — listed as manual follow-up |
| Finder application name | PASS — bundle is `Tethra.app`, CFBundleName/DisplayName "Tethra" |
| Reveal/delete reauthentication in the packaged UI | Not re-driven interactively this session (UI keystroke automation was deliberately avoided with another instance of the app running); enforced in core (`cargo` authz/reauth suites) and React dialog tests, and passed the 113-case manual run on the pre-remediation baseline — listed as manual follow-up |

Residual-branding sweep of the final binary: **0** occurrences of the old
title-case product name (the first build had 2, fixed in `0972f20`).

## Manual checks still open

Full 129-ID manual plan re-execution on this build; the 12 human-assisted
Keychain/Wi-Fi cases; live notification banner; packaged reveal/delete
reauth walk-through. See `TETHRA_KNOWN_RELEASE_LIMITATIONS.md`.

## Final release classification

**Private alpha (internal testing only)** — functionally green across all
automated suites and packaged checks above, blocked from public
distribution by missing signing/notarization and the open manual/audit
debt recorded in the readiness inventory.
