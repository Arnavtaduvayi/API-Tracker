#!/usr/bin/env bash
# OPTIONAL live verification of the OpenAI usage/cost connector.
#
#   bash scripts/live_verify_openai.sh
#
# What this does — read before running:
#   * Creates a THROWAWAY vault in a private temp directory (your real vault
#     is never touched) and deletes it when the script exits.
#   * Prompts for an OpenAI ADMIN API key (organization settings → Admin
#     keys). This key has organization-wide READ access to usage, costs,
#     projects, and key metadata. The script performs read-only requests:
#     it lists projects/keys and fetches usage + costs for the last 7 days.
#   * OpenAI does not charge for these administration endpoints, but the key
#     itself is powerful — delete it from the OpenAI dashboard afterwards if
#     it was created only for this test.
#   * The key is read without echo, lives only in this process's memory and
#     the throwaway encrypted vault, and is never printed or written in
#     plaintext. Raw provider responses are not saved.
#
# This script is NOT part of any automated test suite and never runs in CI.
# Normal builds and tests use mocked fixtures only.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$REPO_ROOT/$TARGET_DIR" ;; esac
BIN="$TARGET_DIR/release/api-tracker"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/api-tracker-live-openai.XXXXXX")" \
  || { echo "failed to create a temp dir" >&2; exit 1; }
cleanup() {
  unset API_TRACKER_PROVIDER_ADMIN_KEY 2>/dev/null || true
  rm -rf "$WORK"
  echo "Cleaned up the throwaway vault."
}
trap cleanup EXIT

echo "Building the release CLI..."
(cd "$REPO_ROOT" && cargo build --release --quiet -p api-tracker-cli) || exit 1

export API_TRACKER_DIR="$WORK/vault"
# Throwaway master password for a throwaway vault (deleted on exit).
export API_TRACKER_PASSWORD="live-verify-throwaway-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')"

"$BIN" init >/dev/null || exit 1
echo "Throwaway vault created at $API_TRACKER_DIR (deleted on exit)."
echo

echo "Paste your OpenAI ADMIN key (input is hidden; the key is never echoed"
echo "or stored outside the throwaway encrypted vault):"
read -r -s ADMIN_KEY
[ -n "$ADMIN_KEY" ] || { echo "no key provided; aborting."; exit 1; }

# The key reaches the CLI via the environment of this one invocation only.
API_TRACKER_PROVIDER_ADMIN_KEY="$ADMIN_KEY" \
  "$BIN" provider connect openai --org live-verify || exit 1
unset ADMIN_KEY

echo
echo "Synchronizing the last 7 days of usage and costs..."
"$BIN" provider sync openai --days 7 || exit 1

echo
"$BIN" provider connection-status openai
echo
"$BIN" provider keys openai
echo
"$BIN" provider projects openai
echo
"$BIN" usage report --provider openai --source provider

echo
echo "Live verification finished. The throwaway vault (and the stored admin"
echo "key) will now be deleted. If you created the admin key only for this"
echo "test, revoke it at https://platform.openai.com/settings/organization/admin-keys"
