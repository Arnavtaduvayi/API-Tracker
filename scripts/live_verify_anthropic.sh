#!/usr/bin/env bash
# OPTIONAL live verification of the Anthropic usage/cost connector.
#
#   bash scripts/live_verify_anthropic.sh
#
# What this does — read before running:
#   * Creates a THROWAWAY vault in a private temp directory (your real vault
#     is never touched) and deletes it when the script exits.
#   * Prompts for an Anthropic ADMIN API key (sk-ant-admin..., created in the
#     console under Settings → Organization). This key has organization-wide
#     READ access to usage, costs, workspaces, and API-key metadata — and it
#     can also disable/archive keys, which this script NEVER does.
#   * Every request this script performs is READ-ONLY:
#       - GET /v1/organizations/me            (validates the admin key)
#       - usage report (last 7 days)          (per-key × workspace × model)
#       - cost report (last 7 days)           (workspace level, in cents)
#       - workspace and API-key metadata      (ids, names, expirations)
#     Nothing is created, changed, disabled, archived, or deleted.
#   * Anthropic does not charge for these administration endpoints, and no
#     model tokens are consumed — this run cannot incur provider charges.
#   * The key is read without echo, lives only in this process's memory and
#     the throwaway encrypted vault, and is never printed or written in
#     plaintext. Raw provider responses are not saved.
#
# Requirements: an Anthropic organization admin key. If you create one just
# for this test, revoke it in the console afterwards.
#
# This script is NOT part of any automated test suite and never runs in CI.
# Normal builds and tests use mocked fixtures only.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$REPO_ROOT/$TARGET_DIR" ;; esac
BIN="$TARGET_DIR/release/api-tracker"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/api-tracker-live-anthropic.XXXXXX")" \
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

echo "Paste your Anthropic ADMIN key (input is hidden; the key is never echoed"
echo "or stored outside the throwaway encrypted vault):"
read -r -s ADMIN_KEY
[ -n "$ADMIN_KEY" ] || { echo "no key provided; aborting."; exit 1; }

# The key reaches the CLI via the environment of this one invocation only —
# never as a command-line argument.
API_TRACKER_PROVIDER_ADMIN_KEY="$ADMIN_KEY" \
  "$BIN" provider connect anthropic --org live-verify || exit 1
unset ADMIN_KEY

echo
echo "Synchronizing the last 7 days of usage and costs (read-only)..."
"$BIN" provider sync anthropic --days 7 || exit 1

echo
"$BIN" provider connection-status anthropic
echo
echo "Provider-side API keys (metadata only — note any provider-reported"
echo "expirations; linking suggestions are never auto-applied):"
"$BIN" provider keys anthropic
echo
"$BIN" provider projects anthropic
echo
"$BIN" usage report --provider anthropic --source provider

echo
echo "Live verification finished. No write action was performed against your"
echo "Anthropic organization. The throwaway vault (and the stored admin key)"
echo "will now be deleted. If you created the admin key only for this test,"
echo "revoke it in the Anthropic console (Settings → Organization)."
