#!/usr/bin/env bash
# OPTIONAL live verification of the Vercel environment-variables
# destination.
#
#   bash scripts/live_verify_vercel.sh
#
# What this does — read before running:
#   * Creates a THROWAWAY vault in a private temp directory (your real vault
#     is never touched) and deletes it when the script exits.
#   * Asks for a Vercel project id (use a THROWAWAY/test project, never a
#     production one) and prompts (hidden) for a Vercel access token.
#     Prefer a token scoped to the team that owns the test project.
#   * After showing you the exact actions and asking for confirmation, it:
#       1. reads the project (read-only auth test),
#       2. upserts ONE disposable encrypted environment variable named
#          API_TRACKER_LIVE_VERIFY_<random> holding a RANDOM FAKE value
#          (no real secret is ever sent) for the development target only,
#       3. verifies it by existence (encrypted variables are write-only),
#       4. deletes it.
#   * Cost: none — the Vercel API is free for this. Required plan: any.
#     NOTE: a variable change affects the project's next deployment; using
#     a throwaway project keeps this consequence-free.
#   * The token is read without echo, lives only in this process and the
#     throwaway encrypted vault, and is never printed. Revoke it afterwards
#     if created only for this test.
#
# This script is NOT part of any automated test suite and never runs in CI.
# Normal builds and tests use mocked fixtures only.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$REPO_ROOT/$TARGET_DIR" ;; esac
BIN="$TARGET_DIR/release/api-tracker"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/api-tracker-live-vercel.XXXXXX")" \
  || { echo "failed to create a temp dir" >&2; exit 1; }
CLEANED_REMOTE=0
SECRET_NAME=""
cleanup() {
  rm -rf "$WORK"
  echo "Cleaned up the throwaway vault."
  if [ "$CLEANED_REMOTE" -ne 1 ] && [ -n "$SECRET_NAME" ]; then
    echo "WARNING: the disposable variable '$SECRET_NAME' may still exist in"
    echo "the Vercel project — delete it under Project Settings → Environment Variables."
  fi
}
trap cleanup EXIT

echo "Building the release CLI..."
(cd "$REPO_ROOT" && cargo build --release --quiet -p api-tracker-cli) || exit 1

export API_TRACKER_DIR="$WORK/vault"
export API_TRACKER_PASSWORD="live-verify-throwaway-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')"

"$BIN" init >/dev/null || exit 1
echo "Throwaway vault created at $API_TRACKER_DIR (deleted on exit)."
echo

printf "Vercel project id (a TEST project, e.g. prj_...): "
read -r VC_PROJECT
[ -n "$VC_PROJECT" ] || { echo "missing project id; aborting."; exit 1; }
printf "Team id (empty for a personal account): "
read -r VC_TEAM
echo "Paste the Vercel access token (hidden):"
read -r -s VC_TOKEN
[ -n "$VC_TOKEN" ] || { echo "no token provided; aborting."; exit 1; }

RAND="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')"
SECRET_NAME="API_TRACKER_LIVE_VERIFY_$RAND"
FAKE_VALUE="api-tracker-live-verify-FAKE-$RAND"

echo
echo "The following LIVE actions will be performed against Vercel project $VC_PROJECT:"
echo "  1. GET the project (read-only auth test)"
echo "  2. POST env var '$SECRET_NAME' (encrypted type, development target"
echo "     only) with a random FAKE value"
echo "  3. GET the env list (existence verification — encrypted variables"
echo "     are write-only)"
echo "  4. DELETE the variable"
echo "Cost: none. The change affects only the project's next deployment."
printf "Type 'yes' to proceed: "
read -r CONFIRM
[ "$CONFIRM" = "yes" ] || { echo "aborted; nothing was sent to Vercel."; SECRET_NAME=""; exit 1; }

ADD_ARGS=(destination add vercel --name live-verify-vercel --project-id "$VC_PROJECT" --targets development --auth-stdin --no-verify)
if [ -n "$VC_TEAM" ]; then
  ADD_ARGS+=(--team-id "$VC_TEAM")
fi
printf '%s' "$VC_TOKEN" | "$BIN" "${ADD_ARGS[@]}" || exit 1
unset VC_TOKEN

echo "Testing authentication (project fetch)..."
"$BIN" destination test live-verify-vercel || exit 1

"$BIN" project create live-verify --env development >/dev/null || exit 1
printf '%s' "$FAKE_VALUE" | "$BIN" key add --project live-verify \
  --name vercel-probe --provider other --environment development --value-stdin >/dev/null || exit 1
"$BIN" destination attach live-verify/vercel-probe live-verify-vercel \
  --secret-name "$SECRET_NAME" --environment development || exit 1

echo
echo "Creating the sync plan (dry run first)..."
PLAN_ID="$("$BIN" --json sync plan live-verify/vercel-probe | sed -n 's/^ *"id": *"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$PLAN_ID" ] || { echo "could not determine the plan id"; exit 1; }
"$BIN" sync show "$PLAN_ID"

echo
echo "Executing the plan (upsert + existence verification)..."
"$BIN" sync run "$PLAN_ID" --yes || exit 1

echo
echo "Drift check (existence verification — Vercel is write-only):"
"$BIN" destination drift || exit 1

echo
echo "Cleaning up: deleting '$SECRET_NAME' from the project..."
if "$BIN" destination delete-secret live-verify-vercel "$SECRET_NAME" --yes; then
  CLEANED_REMOTE=1
else
  echo "CLEANUP FAILED — delete the variable manually (see the warning below)."
fi

echo
echo "Live verification finished. The throwaway vault (and the stored token)"
echo "will now be deleted. If the token was created only for this test,"
echo "revoke it at https://vercel.com/account/tokens"
