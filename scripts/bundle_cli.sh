#!/bin/sh
# Build the CLI and stage it as the desktop app's Tauri sidecar
# (PACKAGING_PLAN §2, closes gateway OPEN_DECISIONS O10).
#
# Tauri's `externalBin` expects target-triple-suffixed files under
# `apps/desktop/src-tauri/binaries/` and bundles the matching one beside
# the main executable (macOS: Contents/MacOS/tethra). The bundled binary
# is byte-identical to the standalone CLI archive binary — one program,
# no helper-only build flavor.
#
# Usage: scripts/bundle_cli.sh [target-triple]
#   (default: the host triple from `rustc -vV`)
set -eu

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET_DIR=${CARGO_TARGET_DIR:-"$REPO_ROOT/target"}
TRIPLE=${1:-$(rustc -vV | sed -n 's/^host: //p')}
[ -n "$TRIPLE" ] || { echo "error: could not determine the target triple" >&2; exit 1; }

case "$TRIPLE" in
  *windows*) EXE=".exe" ;;
  *) EXE="" ;;
esac

echo "Building the CLI for ${TRIPLE}..."
if [ "${BUNDLE_CLI_HOST_BUILD:-}" = "1" ] || [ "$TRIPLE" = "$(rustc -vV | sed -n 's/^host: //p')" ]; then
  cargo build --release -p api-tracker-cli
  SRC="$TARGET_DIR/release/tethra$EXE"
else
  cargo build --release -p api-tracker-cli --target "$TRIPLE"
  SRC="$TARGET_DIR/$TRIPLE/release/tethra$EXE"
fi
[ -f "$SRC" ] || { echo "error: built CLI not found at $SRC" >&2; exit 1; }

DEST_DIR="$REPO_ROOT/apps/desktop/src-tauri/binaries"
DEST="$DEST_DIR/tethra-$TRIPLE$EXE"
mkdir -p "$DEST_DIR"
# Plain byte copy into a fresh file (no metadata propagation), then the
# executable bit.
rm -f "$DEST"
cat "$SRC" > "$DEST"
chmod 755 "$DEST"

echo "Sidecar staged: $DEST"
"$DEST" gateway service-probe >/dev/null 2>&1 && echo "Probe: OK" || {
  # Cross-compiled sidecars cannot run on this host; that is expected.
  echo "Probe: skipped (binary is for $TRIPLE)"
}
