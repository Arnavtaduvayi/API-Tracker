#!/usr/bin/env bash
# OPTIONAL live verification of the GitHub Actions repository-secrets
# destination.
#
#   bash scripts/live_verify_github_actions.sh
#
# What this does — read before running:
#   * Creates a THROWAWAY vault in a private temp directory (your real vault
#     is never touched) and deletes it when the script exits.
#   * Asks for a repository (use a THROWAWAY/test repository you own, never
#     a production one) and prompts (hidden) for a token with secrets
#     access to that repository only (fine-grained PAT with
#     "Secrets: read and write" on that single repo is the minimal scope).
#   * After showing you the exact actions and asking for confirmation, it:
#       1. reads the repository public key (read-only),
#       2. creates ONE disposable Actions secret named
#          API_TRACKER_LIVE_VERIFY_<random> holding a RANDOM FAKE value
#          (no real secret is ever sent; GitHub encrypts it client-side
#          with a libsodium sealed box),
#       3. verifies it by existence (GitHub never returns secret values),
#       4. deletes it.
#   * Cost: none — the GitHub API is free for this. Required plan: any
#     (the token needs admin/secrets access to the repository).
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

WORK="$(mktemp -d "${TMPDIR:-/tmp}/api-tracker-live-gha.XXXXXX")" \
  || { echo "failed to create a temp dir" >&2; exit 1; }
CLEANED_REMOTE=0
SECRET_NAME=""
GH_OWNER=""
GH_REPO=""
cleanup() {
  rm -rf "$WORK"
  echo "Cleaned up the throwaway vault."
  if [ "$CLEANED_REMOTE" -ne 1 ] && [ -n "$SECRET_NAME" ]; then
    echo "WARNING: the disposable secret '$SECRET_NAME' may still exist in"
    echo "$GH_OWNER/$GH_REPO — delete it under Settings → Secrets → Actions."
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

printf "Repository owner (a TEST repository you own): "
read -r GH_OWNER
printf "Repository name: "
read -r GH_REPO
[ -n "$GH_OWNER" ] && [ -n "$GH_REPO" ] || { echo "missing repository; aborting."; exit 1; }
echo "Paste the GitHub token (hidden; scope it to this repository's secrets only):"
read -r -s GH_TOKEN
[ -n "$GH_TOKEN" ] || { echo "no token provided; aborting."; exit 1; }

RAND="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')"
SECRET_NAME="API_TRACKER_LIVE_VERIFY_$RAND"
FAKE_VALUE="api-tracker-live-verify-FAKE-$RAND"

echo
echo "The following LIVE actions will be performed against $GH_OWNER/$GH_REPO:"
echo "  1. GET the repository Actions public key (read-only auth test)"
echo "  2. PUT Actions secret '$SECRET_NAME' with a random FAKE value"
echo "  3. GET the secret's metadata (existence verification — GitHub never"
echo "     returns values)"
echo "  4. DELETE the secret"
echo "Cost: none."
printf "Type 'yes' to proceed: "
read -r CONFIRM
[ "$CONFIRM" = "yes" ] || { echo "aborted; nothing was sent to GitHub."; SECRET_NAME=""; exit 1; }

printf '%s' "$GH_TOKEN" | "$BIN" destination add github_actions \
  --name live-verify-gha --owner "$GH_OWNER" --repo "$GH_REPO" --auth-stdin --no-verify || exit 1
unset GH_TOKEN

echo "Testing authentication (public-key fetch)..."
"$BIN" destination test live-verify-gha || exit 1

"$BIN" project create live-verify --env development >/dev/null || exit 1
printf '%s' "$FAKE_VALUE" | "$BIN" key add --project live-verify \
  --name gha-probe --provider other --environment development --value-stdin >/dev/null || exit 1
"$BIN" destination attach live-verify/gha-probe live-verify-gha \
  --secret-name "$SECRET_NAME" --environment development || exit 1

echo
echo "Creating the sync plan (dry run first)..."
PLAN_ID="$("$BIN" --json sync plan live-verify/gha-probe | sed -n 's/^ *"id": *"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$PLAN_ID" ] || { echo "could not determine the plan id"; exit 1; }
"$BIN" sync show "$PLAN_ID"

echo
echo "Executing the plan (sealed-box write + existence verification)..."
"$BIN" sync run "$PLAN_ID" --yes || exit 1

echo
echo "Drift check (existence verification — GitHub is write-only):"
"$BIN" destination drift || exit 1

echo
echo "Cleaning up: deleting '$SECRET_NAME' from the repository..."
if "$BIN" destination delete-secret live-verify-gha "$SECRET_NAME" --yes; then
  CLEANED_REMOTE=1
else
  echo "CLEANUP FAILED — delete the secret manually (see the warning below)."
fi

echo
echo "Live verification finished. The throwaway vault (and the stored token)"
echo "will now be deleted. If the token was created only for this test,"
echo "revoke it at https://github.com/settings/tokens"
