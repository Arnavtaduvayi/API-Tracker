#!/bin/sh
# Build, Developer ID sign, notarize, staple, verify, and stage the exact
# current macOS application for the landing site.
set -eu

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
IDENTITY=${APPLE_SIGNING_IDENTITY:-"Developer ID Application: Eesh Majithia (ZT56M637KS)"}
NOTARY_PROFILE=${NOTARY_KEYCHAIN_PROFILE:-TethraNotary}
RELEASE_REPOSITORY=${GITHUB_RELEASE_REPOSITORY:-Arnavtaduvayi/API-Tracker}
RELEASE_TAG=${GITHUB_RELEASE_TAG:-v0.1.0-alpha-ui.3}
VERSION=$(jq -r '.version' "$REPO_ROOT/apps/desktop/src-tauri/tauri.conf.json")
DMG="$REPO_ROOT/target/release/bundle/dmg/Tethra_${VERSION}_aarch64.dmg"
LANDING_DMG="$REPO_ROOT/landing/downloads/Tethra.dmg"
cd "$REPO_ROOT"

if [ -n "$(git status --porcelain -- Cargo.toml Cargo.lock crates apps/cli apps/desktop scripts/bundle_cli.sh)" ]; then
  echo "error: application source is dirty; commit every app update before releasing" >&2
  git status --short -- Cargo.toml Cargo.lock crates apps/cli apps/desktop scripts/bundle_cli.sh >&2
  exit 1
fi

SOURCE_COMMIT=$(git log -1 --format=%H -- Cargo.toml Cargo.lock crates apps/cli apps/desktop scripts/bundle_cli.sh)
[ -n "$SOURCE_COMMIT" ] || { echo "error: could not resolve application source commit" >&2; exit 1; }

./scripts/bundle_cli.sh aarch64-apple-darwin
(
  cd apps/desktop
  APPLE_SIGNING_IDENTITY="$IDENTITY" npx tauri build --bundles dmg
)

[ -f "$DMG" ] || { echo "error: expected DMG was not built: $DMG" >&2; exit 1; }
codesign --verify --strict --verbose=2 "$DMG"

xcrun notarytool submit "$DMG" \
  --keychain-profile "$NOTARY_PROFILE" \
  --wait \
  --timeout 30m
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
spctl --assess --type open --context context:primary-signature --verbose=4 "$DMG"

MOUNT_DIR=$(mktemp -d /private/tmp/tethra-release-check.XXXXXX)
cleanup() {
  hdiutil detach "$MOUNT_DIR" >/dev/null 2>&1 || true
  rmdir "$MOUNT_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

hdiutil attach -readonly -nobrowse -mountpoint "$MOUNT_DIR" "$DMG" >/dev/null
codesign --verify --deep --strict --verbose=2 "$MOUNT_DIR/Tethra.app"
spctl --assess --type execute --verbose=4 "$MOUNT_DIR/Tethra.app"

cp "$DMG" "$LANDING_DMG"
DMG_SHA=$(shasum -a 256 "$LANDING_DMG" | awk '{print $1}')
printf '%s\n' "$SOURCE_COMMIT" > "$REPO_ROOT/landing/downloads/MACOS_SOURCE_COMMIT.txt"

CHECKSUM_TMP=$(mktemp /private/tmp/tethra-checksums.XXXXXX)
printf '%s  Tethra.dmg\n' "$DMG_SHA" > "$CHECKSUM_TMP"
if [ -f "$REPO_ROOT/landing/downloads/WINDOWS_SHA256.txt" ]; then
  sed -n '1p' "$REPO_ROOT/landing/downloads/WINDOWS_SHA256.txt" >> "$CHECKSUM_TMP"
fi
mv "$CHECKSUM_TMP" "$REPO_ROOT/landing/downloads/SHA256SUMS.txt"

command -v gh >/dev/null 2>&1 || { echo "error: gh is required to publish the direct DMG" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "error: gh is not authenticated" >&2; exit 1; }
gh release upload "$RELEASE_TAG" "$DMG" \
  --repo "$RELEASE_REPOSITORY" \
  --clobber

echo "macOS release staged from source commit $SOURCE_COMMIT"
echo "DMG SHA-256: $DMG_SHA"
echo "Direct DMG published to GitHub release $RELEASE_TAG"
