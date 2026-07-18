#!/usr/bin/env bash
# OPTIONAL live verification of the Stripe connector.
#
#   bash scripts/live_verify_stripe.sh
#
# What this does — read before running:
#   * Creates a THROWAWAY vault in a private temp directory (your real vault
#     is never touched) and deletes it when the script exits.
#   * Prompts for a Stripe API key. Recommended: a RESTRICTED key with
#     read-only permissions (Balance: read, Events: read), or a TEST-mode
#     secret key (sk_test_...). A live secret key also works — this script
#     still performs only reads — but a least-privilege key is always the
#     better choice.
#   * Every request this script performs is READ-ONLY:
#       - GET /v1/balance   (validates the key; reports live/test mode)
#       - GET /v1/events    (recent account activity, aggregated locally
#                            into daily event counts; 30-day retention)
#     NO charge is created, NO customer or payment object is created,
#     modified, or deleted, and NO account setting is touched.
#   * Reading balance and events is free of charge — this run cannot incur
#     Stripe fees and cannot move money.
#   * The key is read without echo, lives only in this process's memory and
#     the throwaway encrypted vault, and is never printed, never passed as a
#     command-line argument, and never written in plaintext. Raw provider
#     responses (which can reference customer activity) are aggregated into
#     counts and are not saved.
#
# This script is NOT part of any automated test suite and never runs in CI.
# Normal builds and tests use mocked fixtures only.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$REPO_ROOT/$TARGET_DIR" ;; esac
BIN="$TARGET_DIR/release/api-tracker"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/api-tracker-live-stripe.XXXXXX")" \
  || { echo "failed to create a temp dir" >&2; exit 1; }
cleanup() {
  unset STRIPE_LIVE_KEY 2>/dev/null || true
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

echo "Paste your Stripe key (input is hidden; a read-only restricted key or"
echo "a test-mode key is recommended — see the header of this script):"
read -r -s STRIPE_LIVE_KEY
[ -n "$STRIPE_LIVE_KEY" ] || { echo "no key provided; aborting."; exit 1; }

# The key reaches the CLI on stdin only — never as an argument.
printf '%s' "$STRIPE_LIVE_KEY" | "$BIN" key add --project live-verify \
  --name stripe-key --provider stripe --environment development \
  --value-stdin >/dev/null || exit 1
unset STRIPE_LIVE_KEY

echo
echo "Validating the key (GET /v1/balance; read-only, reports live/test mode):"
"$BIN" key validate live-verify/stripe-key || exit 1

echo
echo "Key metadata (live/test mode, balance currencies):"
"$BIN" key metadata live-verify/stripe-key

echo
echo "Connecting the credential for Events activity sync and syncing 7 days"
echo "(daily event counts by family, account level, read-only):"
"$BIN" provider connect stripe --credential live-verify/stripe-key || exit 1
"$BIN" provider sync stripe --days 7 || exit 1

echo
"$BIN" provider connection-status stripe
echo
"$BIN" usage report --provider stripe --source provider

echo
echo "Live verification finished. No charge was created, no customer or"
echo "payment data was modified, and no account setting was touched — every"
echo "request was read-only. The throwaway vault (and the stored key) will"
echo "now be deleted. If you created the key only for this test, revoke it"
echo "at https://dashboard.stripe.com/apikeys"
