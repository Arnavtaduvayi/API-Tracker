#!/usr/bin/env bash
# Clean-room preconditions for the packaged macOS service-lifecycle job.
#
#   scripts/ci_service_preconditions.sh
#
# The service scope is only evidence if it ran somewhere with no pre-existing
# Tethra installation. This asserts that and FAILS SAFELY if it does not hold.
#
# THIS SCRIPT IS READ-ONLY BY CONSTRUCTION. It inspects and reports; it never
# removes, boots out, stops, repairs, or otherwise remediates anything — not
# even to "make the test runnable". Deleting unknown pre-existing state to
# force a run to continue is precisely the REM-001 mistake in a new costume:
# the previous remediation stopped a live production gateway that way. If a
# precondition fails, the correct outcome is a failed job on a machine that is
# not a clean room, not a clean room manufactured by destruction.
#
# It runs BEFORE any cleanup action is registered anywhere and before any
# service command is issued, which is the ordering the whole design depends
# on: a refusal must be reachable without ever having armed a destructive
# path.
set -uo pipefail

UID_NUM="$(id -u)"
DATA_DIR="$HOME/Library/Application Support/api-tracker"
LA_DIR="$HOME/Library/LaunchAgents"
LEGACY_LABEL="dev.api-tracker.gateway"

fails=0
note() { printf '  %-6s %s\n' "$1" "$2"; }
ok()   { note "OK" "$1"; }
bad()  { note "FAIL" "$1"; fails=$((fails + 1)); }

echo "=== clean-runner preconditions (read-only; nothing is remediated) ==="
echo "    host:     $(hostname)"
echo "    user:     $(whoami) (uid $UID_NUM)"
echo "    HOME:     $HOME"
echo "    macOS:    $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
echo "    arch:     $(uname -m)"
echo "    session:  $(launchctl managername 2>/dev/null || echo '<unknown>')"
echo

# 1. No Tethra LaunchAgent registered in the LIVE launchd session.
#
# This asks launchd, not the filesystem. `launchctl` addresses `gui/<uid>`,
# which no $HOME redirection isolates — the REM-001 lesson, applied to the
# precondition rather than only to the cleanup.
REGISTERED="$(launchctl list 2>/dev/null \
  | awk -v l="$LEGACY_LABEL" '$3 == l || index($3, l ".") == 1 { print "      " $3 }')"
if [ -z "$REGISTERED" ]; then
  ok "no gateway job is registered in launchd (gui/$UID_NUM)"
else
  bad "a gateway job is ALREADY registered in launchd:"
  printf '%s\n' "$REGISTERED"
fi

# 2. No matching plist on disk — legacy or namespaced.
EXISTING_PLISTS=""
for candidate in "$LA_DIR/$LEGACY_LABEL.plist" "$LA_DIR/$LEGACY_LABEL".*.plist; do
  [ -f "$candidate" ] && EXISTING_PLISTS="$EXISTING_PLISTS
      $candidate"
done
if [ -z "$EXISTING_PLISTS" ]; then
  ok "no gateway LaunchAgent plist exists under $LA_DIR"
else
  bad "a gateway LaunchAgent plist ALREADY exists:$EXISTING_PLISTS"
fi

# 3. No gateway process. Matched on the product's own installed-helper name
# rather than a broad pattern: `pkill -f tethra` on a developer machine is a
# footgun, and a precondition that over-matches is one that fails for the
# wrong reason.
GATEWAY_PROCS="$(pgrep -f 'tethra-gateway-[0-9]' 2>/dev/null | while read -r p; do
  printf '      pid %s: %s\n' "$p" "$(ps -o command= -p "$p" 2>/dev/null)"
done)"
if [ -z "$GATEWAY_PROCS" ]; then
  ok "no gateway process is running"
else
  bad "a gateway process is ALREADY running:"
  printf '%s\n' "$GATEWAY_PROCS"
fi

# 4. No installed helper. `gateway install` copies the running CLI to
# <data-dir>/bin/tethra-gateway-<version>; its presence means a prior install.
if [ -d "$DATA_DIR/bin" ]; then
  HELPERS="$(find "$DATA_DIR/bin" -maxdepth 1 -name 'tethra-gateway-*' 2>/dev/null | sed 's/^/      /')"
  if [ -z "$HELPERS" ]; then
    ok "no installed gateway helper under $DATA_DIR/bin"
  else
    bad "an installed gateway helper ALREADY exists:"
    printf '%s\n' "$HELPERS"
  fi
else
  ok "no installed gateway helper (no $DATA_DIR/bin)"
fi

# 5. No shared Tethra data directory from a prior run.
if [ ! -e "$DATA_DIR" ]; then
  ok "no shared data directory at $DATA_DIR"
else
  bad "a shared data directory ALREADY exists at $DATA_DIR:"
  ls -la "$DATA_DIR" 2>/dev/null | sed 's/^/      /'
fi

# 6. No control endpoint. The gateway's control channel is a Unix socket at
# <data-dir>/gateway.sock; a live socket means a live gateway.
if [ ! -e "$DATA_DIR/gateway.sock" ]; then
  ok "no control endpoint at $DATA_DIR/gateway.sock"
else
  bad "a control endpoint ALREADY exists at $DATA_DIR/gateway.sock"
fi

# 7. No route state. The routes live in the vault database; its presence is
# the observable form of "this machine already has a configured gateway".
if [ ! -e "$DATA_DIR/vault.db" ]; then
  ok "no vault database (and therefore no route state) at $DATA_DIR/vault.db"
else
  bad "a vault database ALREADY exists at $DATA_DIR/vault.db"
fi

# 8. No stale temporary test namespace. The harness works under
# /tmp/tethra-track-val-<pid>; a survivor means a previous run died without
# cleaning up, and reusing the namespace would make this run's ownership
# claims false.
STALE="$(ls -d /tmp/tethra-track-val-* 2>/dev/null | sed 's/^/      /')"
if [ -z "$STALE" ]; then
  ok "no stale /tmp/tethra-track-val-* namespace"
else
  bad "a stale test namespace ALREADY exists:"
  printf '%s\n' "$STALE"
fi

# 9. No Tethra CLI on PATH. The run must be driven by the in-bundle helper
# only; a developer CLI here would make "the app ships its helper" unfalsifiable.
if command -v tethra >/dev/null 2>&1; then
  bad "a tethra CLI is already on PATH at $(command -v tethra)"
else
  ok "no tethra CLI on PATH"
fi

# 10. The launchd domain the product will actually register into must exist.
# This is not a cleanliness check but a capability one: without an Aqua login
# session there is no gui/<uid> to bootstrap into, and the run would be
# testing a fallback rather than the path a user gets.
if launchctl print "gui/$UID_NUM" >/dev/null 2>&1; then
  ok "the gui/$UID_NUM launchd domain exists (session: $(launchctl managername 2>/dev/null))"
else
  bad "no gui/$UID_NUM launchd domain — a per-user LaunchAgent cannot be registered here,
      so a run on this machine would not exercise the path a user gets"
fi

echo
if [ "$fails" -ne 0 ]; then
  echo "=== PRECONDITIONS FAILED ($fails) — refusing to run the service scope ==="
  echo
  echo "Nothing was modified. This machine is not a clean room, and the correct"
  echo "response is to fail rather than to delete unknown state to continue."
  echo "The service scope is only evidence when it starts from nothing."
  exit 1
fi
echo "=== PRECONDITIONS PASSED — this is a clean room ==="
