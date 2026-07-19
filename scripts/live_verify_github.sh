#!/usr/bin/env bash
# OPTIONAL live verification of the GitHub connector.
#
#   bash scripts/live_verify_github.sh
#
# What this does — read before running:
#   * Creates a THROWAWAY vault in a private temp directory (your real vault
#     is never touched) and deletes it when the script exits.
#   * Prompts for a GitHub personal access token. Recommended: a
#     FINE-GRAINED token with only "Plan" (read-only) account permission —
#     that is the one permission the billing-usage endpoint documents.
#     A CLASSIC token also works for the scope/metadata/expiration checks
#     (its scopes are read from the X-OAuth-Scopes header), but the billing
#     endpoint is not documented for classic tokens and will be reported
#     honestly as rejected if GitHub declines it.
#   * Every request this script performs is READ-ONLY:
#       - GET /user                       (validates the token; records the
#                                          provider-reported expiration header)
#       - GET /                            (X-OAuth-Scopes metadata)
#       - Enhanced Billing usage report    (account-level quantities/units)
#     NO repository, organization, or account setting is read beyond the
#     endpoints above, and nothing is created, changed, or deleted.
#   * These endpoints are free of charge — this run cannot incur charges.
#   * The token is read without echo, lives only in this process's memory and
#     the throwaway encrypted vault, and is never printed, never passed as a
#     command-line argument, and never written in plaintext. Raw provider
#     responses are not saved.
#
# This script is NOT part of any automated test suite and never runs in CI.
# Normal builds and tests use mocked fixtures only.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$REPO_ROOT/$TARGET_DIR" ;; esac
BIN="$TARGET_DIR/release/api-tracker"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/api-tracker-live-github.XXXXXX")" \
  || { echo "failed to create a temp dir" >&2; exit 1; }
cleanup() {
  unset GH_LIVE_TOKEN 2>/dev/null || true
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
"$BIN" project create live-verify --env development >/dev/null || exit 1
echo "Throwaway vault created at $API_TRACKER_DIR (deleted on exit)."
echo

echo "Paste your GitHub token (input is hidden; fine-grained with Plan:read"
echo "recommended — see the header of this script):"
read -r -s GH_LIVE_TOKEN
[ -n "$GH_LIVE_TOKEN" ] || { echo "no token provided; aborting."; exit 1; }

# The token reaches the CLI on stdin only — never as an argument.
printf '%s' "$GH_LIVE_TOKEN" | "$BIN" key add --project live-verify \
  --name github-token --provider github --environment development \
  --value-stdin >/dev/null || exit 1
unset GH_LIVE_TOKEN

echo
echo "Validating the token (GET /user; read-only). If GitHub reports a token"
echo "expiration header, it is recorded as provider-reported:"
"$BIN" key validate live-verify/github-token || exit 1

echo
echo "Provider-reported expiration and status:"
"$BIN" key status live-verify/github-token

echo
echo "Scope sync (classic tokens: exact scopes from X-OAuth-Scopes;"
echo "fine-grained tokens: honestly reported as not enumerable):"
"$BIN" key permissions live-verify/github-token --sync

echo
echo "Connecting the credential for billing-usage sync and syncing 7 days"
echo "(account-level quantities and unit types, read-only; requires a"
echo "fine-grained token with Plan:read — anything else is reported, not faked):"
"$BIN" provider connect github --credential live-verify/github-token || exit 1
if "$BIN" provider sync github --days 7; then
  echo
  "$BIN" usage report --provider github --source provider
else
  echo
  echo "Billing sync was rejected — expected for classic tokens or tokens"
  echo "without Plan:read. The scope/expiration checks above still verified"
  echo "the metadata paths."
fi

echo
echo "Live verification finished. No repository or organization setting was"
echo "read or changed; every request was read-only. The throwaway vault (and"
echo "the stored token) will now be deleted. If you created the token only"
echo "for this test, revoke it at https://github.com/settings/tokens"
