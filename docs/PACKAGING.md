# Packaging & Release

Tethra ships a CLI binary and a Tauri desktop app for macOS, Windows, and
Linux. The `.github/workflows/release.yml` workflow builds and attaches
artifacts to a **draft** GitHub Release when a `v*` tag is pushed.

## Artifacts

| Platform | Desktop | CLI |
| --- | --- | --- |
| macOS (arm64) | `.dmg`, `.app` | `tethra-<target>.tar.gz` |
| macOS (x64) | **not built** — the release matrix produces arm64 desktop artifacts only | `tethra-x86_64-apple-darwin.tar.gz` |
| Windows (x64) | `.msi` / `.exe` (NSIS) | `tethra-x86_64-pc-windows-msvc.zip` |
| Linux (x64) | `.AppImage`, `.deb` | `tethra-x86_64-unknown-linux-gnu.tar.gz` |

Each CLI archive contains both the `tethra` binary and the legacy
`api-tracker` compatibility alias (the same program); see
`docs/rebrand/TETHRA_MIGRATION_GUIDE.md`.

Every artifact is accompanied by a SHA-256 checksum; the CLI job also produces
a combined `SHA256SUMS.txt`. Users should verify checksums before running (see
`docs/INSTALL.md`).

## Local build verification status

At alpha-completion the **macOS arm64** artifacts were built and inspected
locally: the release CLI (`cargo build --release -p api-tracker-cli`) and the
Tauri desktop bundle (`npx tauri build` → `Tethra.app` + a `.dmg`). The
bundle was swept for leaked dev vaults, `.env` files, backups, logs,
machine-specific paths, test-fixture secrets, and Claude attribution — clean.

The **Windows and Linux** artifacts, and the macOS **x64 CLI**, are produced
by `release.yml` in CI and were **not** built on the alpha-completion machine
(only the host `aarch64-apple-darwin` toolchain is installed here). Their
build configuration is verified by review; download and smoke-test each
platform artifact from the draft release before publishing.

There is **no macOS x64 desktop artifact**: `release.yml`'s desktop matrix
builds `aarch64-apple-darwin` only. This table previously listed
"macOS (arm64 + x64)" for the desktop, which the matrix never produced
(audit finding `ZFT-043`).

## Signing & notarization

Automated release-workflow builds are currently unsigned. Do not represent
those CI artifacts as signed or notarized. The Apple Silicon DMG served from
`usetethra.com` is a separately prepared artifact signed with Developer ID
Application `Eesh Majithia (ZT56M637KS)`, notarized by Apple, and stapled.

To sign for a real release, configure the following and add the corresponding
steps/secrets to `release.yml`:

### macOS (Apple Developer ID + notarization)
- An **Apple Developer ID Application** certificate (paid Apple Developer
  account) imported into the CI keychain.
- Environment for `tauri-action`: `APPLE_CERTIFICATE`,
  `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
  `APPLE_PASSWORD` (app-specific password), `APPLE_TEAM_ID`.
- Tauri then codesigns and submits to Apple's notary service; staple the
  ticket. Without this, Gatekeeper shows "cannot be opened because the
  developer cannot be verified".

### Windows (Authenticode)
- An **EV or OV code-signing certificate** (from a CA) or Azure Trusted
  Signing.
- Configure `signCommand`/`certificate` in the Tauri Windows bundle config (or
  sign the `.msi`/`.exe` in a CI step). Without this, SmartScreen warns of an
  "unrecognized app".

### Linux
- `.deb`/`.AppImage` are typically distributed unsigned; provide the
  `SHA256SUMS.txt` (and optionally a detached GPG signature) so users can
  verify integrity. AppImage can be signed with `--sign` given a GPG key.

## Later hardening (documented as future work)
- Reproducible builds (pin toolchains, vendor deps, record build metadata).
- Release artifact transparency (attestations / SLSA provenance).
- SBOM generation.

## Release checklist

1. All checks green: `cargo fmt --all --check`, `cargo clippy --workspace
   --all-targets -- -D warnings`, `cargo test`, and the frontend checks.
2. Update `CHANGELOG.md` with the new version and date.
3. Bump versions: `Cargo.toml` workspace `version`, `apps/desktop/package.json`,
   and `apps/desktop/src-tauri/tauri.conf.json`.
4. Verify the README, install guide, and provider-support matrix are current.
5. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
6. The workflow produces a **draft** release. Download the artifacts, verify
   checksums, and smoke-test each platform you can.
7. State the signing/notarization status of each published artifact precisely.
8. Publish the release.
