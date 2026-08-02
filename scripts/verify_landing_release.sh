#!/bin/sh
# Refuse a Hosting deploy when the macOS installer is missing, stale, or not
# the direct notarized DMG referenced by the landing page.
set -eu

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
DMG="$REPO_ROOT/landing/downloads/Tethra.dmg"
SOURCE_RECORD="$REPO_ROOT/landing/downloads/MACOS_SOURCE_COMMIT.txt"
WINDOWS_SOURCE_RECORD="$REPO_ROOT/landing/downloads/WINDOWS_SOURCE_COMMIT.txt"
WINDOWS_CHECKSUM="$REPO_ROOT/landing/downloads/WINDOWS_SHA256.txt"
CHECKSUMS="$REPO_ROOT/landing/downloads/SHA256SUMS.txt"
MACOS_RELEASE_URL=${MACOS_RELEASE_URL:-https://github.com/Arnavtaduvayi/API-Tracker/releases/download/v0.1.0-alpha-ui.3/Tethra_0.1.0_aarch64.dmg}
WINDOWS_RELEASE_URL=${WINDOWS_RELEASE_URL:-https://github.com/Arnavtaduvayi/API-Tracker/releases/download/v0.1.0-alpha-ui.3/Tethra_0.1.0_x64-setup.exe}
cd "$REPO_ROOT"

[ -f "$DMG" ] || { echo "error: direct macOS artifact is missing: $DMG" >&2; exit 1; }
[ -f "$SOURCE_RECORD" ] || { echo "error: macOS source record is missing" >&2; exit 1; }
[ -f "$WINDOWS_SOURCE_RECORD" ] || { echo "error: Windows source record is missing" >&2; exit 1; }
[ -f "$WINDOWS_CHECKSUM" ] || { echo "error: Windows checksum is missing" >&2; exit 1; }

if [ -n "$(git status --porcelain -- Cargo.toml Cargo.lock crates apps/cli apps/desktop scripts/bundle_cli.sh)" ]; then
  echo "error: application source changed after the DMG was built" >&2
  git status --short -- Cargo.toml Cargo.lock crates apps/cli apps/desktop scripts/bundle_cli.sh >&2
  exit 1
fi

BUILT_COMMIT=$(sed -n '1p' "$SOURCE_RECORD")
WINDOWS_BUILT_COMMIT=$(sed -n '1p' "$WINDOWS_SOURCE_RECORD")
CURRENT_COMMIT=$(git log -1 --format=%H -- Cargo.toml Cargo.lock crates apps/cli apps/desktop scripts/bundle_cli.sh)
[ "$BUILT_COMMIT" = "$CURRENT_COMMIT" ] || {
  echo "error: DMG source $BUILT_COMMIT does not match current app source $CURRENT_COMMIT" >&2
  exit 1
}
[ "$WINDOWS_BUILT_COMMIT" = "$CURRENT_COMMIT" ] || {
  echo "error: Windows installer source $WINDOWS_BUILT_COMMIT does not match current app source $CURRENT_COMMIT" >&2
  exit 1
}

EXPECTED_SHA=$(awk '$2 == "Tethra.dmg" { print $1 }' "$CHECKSUMS")
ACTUAL_SHA=$(shasum -a 256 "$DMG" | awk '{print $1}')
[ -n "$EXPECTED_SHA" ] && [ "$EXPECTED_SHA" = "$ACTUAL_SHA" ] || {
  echo "error: direct DMG checksum does not match SHA256SUMS.txt" >&2
  exit 1
}

rg -Fq "href=\"$MACOS_RELEASE_URL\"" landing/index.html || {
  echo "error: landing page does not link directly to the published DMG" >&2
  exit 1
}
rg -Fq "href=\"$WINDOWS_RELEASE_URL\"" landing/index.html || {
  echo "error: landing page does not link directly to the current Windows installer" >&2
  exit 1
}
if rg -q 'href="\./downloads/Tethra\.dmg"' landing; then
  echo "error: landing page still points at Firebase for the forbidden DMG" >&2
  exit 1
fi
if rg -q 'Tethra\.dmg\.zip' landing firebase.json; then
  echo "error: obsolete DMG ZIP reference remains in hosting content" >&2
  exit 1
fi

REMOTE_DMG=$(mktemp /private/tmp/tethra-remote-dmg.XXXXXX)
REMOTE_WINDOWS=$(mktemp /private/tmp/tethra-remote-windows.XXXXXX)
cleanup() {
  rm -f "$REMOTE_DMG" "$REMOTE_WINDOWS"
}
trap cleanup EXIT HUP INT TERM
curl -fsSL "$MACOS_RELEASE_URL" -o "$REMOTE_DMG"
REMOTE_SHA=$(shasum -a 256 "$REMOTE_DMG" | awk '{print $1}')
[ "$REMOTE_SHA" = "$ACTUAL_SHA" ] || {
  echo "error: public DMG $REMOTE_SHA does not match current app DMG $ACTUAL_SHA" >&2
  exit 1
}

EXPECTED_WINDOWS_SHA=$(awk 'NR == 1 { print $1 }' "$WINDOWS_CHECKSUM")
[ -n "$EXPECTED_WINDOWS_SHA" ] || {
  echo "error: Windows checksum file is empty" >&2
  exit 1
}
curl -fsSL "$WINDOWS_RELEASE_URL" -o "$REMOTE_WINDOWS"
REMOTE_WINDOWS_SHA=$(shasum -a 256 "$REMOTE_WINDOWS" | awk '{print $1}')
[ "$REMOTE_WINDOWS_SHA" = "$EXPECTED_WINDOWS_SHA" ] || {
  echo "error: public Windows installer $REMOTE_WINDOWS_SHA does not match expected $EXPECTED_WINDOWS_SHA" >&2
  exit 1
}

if [ "$(uname -s)" = "Darwin" ]; then
  xcrun stapler validate "$DMG"
  spctl --assess --type open --context context:primary-signature --verbose=4 "$DMG"
fi

echo "Landing release verified: app source $CURRENT_COMMIT, macOS $ACTUAL_SHA, Windows $EXPECTED_WINDOWS_SHA"
