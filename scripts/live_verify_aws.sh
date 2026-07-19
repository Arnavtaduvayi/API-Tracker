#!/usr/bin/env bash
# OPTIONAL live verification of the AWS Secrets Manager destination.
#
#   bash scripts/live_verify_aws.sh
#
# What this does — read before running:
#   * Creates a THROWAWAY vault in a private temp directory (your real vault
#     is never touched) and deletes it when the script exits.
#   * Prompts (hidden) for an IAM access key id + secret access key
#     (+ optional session token). Scope it minimally: it needs only
#     secretsmanager CreateSecret/PutSecretValue/GetSecretValue/
#     DescribeSecret/DeleteSecret/ListSecrets, ideally restricted to the
#     name prefix api-tracker-live-verify-*. NEVER use production
#     credentials.
#   * After showing you the exact actions and asking for confirmation, it:
#       1. creates ONE disposable secret named api-tracker-live-verify-<random>
#          holding a RANDOM FAKE value (no real secret is ever sent),
#       2. reads it back to verify the write (GetSecretValue + fingerprint),
#       3. schedules its deletion (DeleteSecret, 30-day recovery window —
#          the standard, cancellable AWS deletion; the entry stays visible
#          as "scheduled for deletion" until the window ends).
#   * Expected cost: AWS Secrets Manager bills ~$0.40/secret/month prorated
#     and $0.05 per 10,000 API calls; secrets scheduled for deletion are not
#     billed. MAXIMUM EXPECTED COST: well under $0.05.
#   * Required plan: any AWS account. Avoid production accounts/regions.
#   * The IAM credentials are read without echo, live only in this process
#     and the throwaway encrypted vault, and are never printed or written in
#     plaintext. Revoke them afterwards if created only for this test.
#
# This script is NOT part of any automated test suite and never runs in CI.
# Normal builds and tests use mocked fixtures only.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$REPO_ROOT/$TARGET_DIR" ;; esac
BIN="$TARGET_DIR/release/api-tracker"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/api-tracker-live-aws.XXXXXX")" \
  || { echo "failed to create a temp dir" >&2; exit 1; }
CLEANED_REMOTE=0
SECRET_NAME=""
cleanup() {
  rm -rf "$WORK"
  echo "Cleaned up the throwaway vault."
  if [ "$CLEANED_REMOTE" -ne 1 ] && [ -n "$SECRET_NAME" ]; then
    echo "WARNING: the disposable AWS secret '$SECRET_NAME' may still exist."
    echo "Delete it manually:  aws secretsmanager delete-secret --secret-id $SECRET_NAME"
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

printf "AWS region for the test (e.g. us-east-1): "
read -r AWS_REGION
[ -n "$AWS_REGION" ] || { echo "no region provided; aborting."; exit 1; }
printf "IAM access key id (hidden): "
read -r -s AWS_KEY_ID; echo
printf "IAM secret access key (hidden): "
read -r -s AWS_SECRET; echo
printf "Session token (hidden; empty if none): "
read -r -s AWS_TOKEN; echo
[ -n "$AWS_KEY_ID" ] && [ -n "$AWS_SECRET" ] || { echo "missing credentials; aborting."; exit 1; }
# Real IAM material never contains quotes or backslashes; refuse anything
# that would break the JSON we build below rather than mangling it.
case "$AWS_KEY_ID$AWS_SECRET$AWS_TOKEN" in
  *'"'*|*'\'*) echo "credentials contain characters that are not valid IAM material; aborting."; exit 1 ;;
esac

RAND="$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SECRET_NAME="api-tracker-live-verify-$RAND"
FAKE_VALUE="api-tracker-live-verify-FAKE-$RAND"

echo
echo "The following LIVE actions will be performed against AWS ($AWS_REGION):"
echo "  1. ListSecrets            (auth test, read-only)"
echo "  2. CreateSecret           '$SECRET_NAME' with a random FAKE value"
echo "  3. GetSecretValue         (verify the write by value read-back)"
echo "  4. DeleteSecret           '$SECRET_NAME' (30-day recovery window)"
echo "Maximum expected cost: under \$0.05."
printf "Type 'yes' to proceed: "
read -r CONFIRM
[ "$CONFIRM" = "yes" ] || { echo "aborted; nothing was sent to AWS."; SECRET_NAME=""; exit 1; }

if [ -n "$AWS_TOKEN" ]; then
  AUTH_JSON="{\"access_key_id\":\"$AWS_KEY_ID\",\"secret_access_key\":\"$AWS_SECRET\",\"session_token\":\"$AWS_TOKEN\"}"
else
  AUTH_JSON="{\"access_key_id\":\"$AWS_KEY_ID\",\"secret_access_key\":\"$AWS_SECRET\"}"
fi
unset AWS_SECRET AWS_TOKEN

printf '%s' "$AUTH_JSON" | "$BIN" destination add aws_secrets_manager \
  --name live-verify-aws --region "$AWS_REGION" --auth-stdin --no-verify || exit 1
unset AUTH_JSON

echo "Testing authentication (ListSecrets)..."
"$BIN" destination test live-verify-aws || exit 1

"$BIN" project create live-verify --env development >/dev/null || exit 1
printf '%s' "$FAKE_VALUE" | "$BIN" key add --project live-verify \
  --name aws-probe --provider other --environment development --value-stdin >/dev/null || exit 1
"$BIN" destination attach live-verify/aws-probe live-verify-aws \
  --secret-name "$SECRET_NAME" --environment development || exit 1

echo
echo "Creating the sync plan (dry run first)..."
PLAN_ID="$("$BIN" --json sync plan live-verify/aws-probe | sed -n 's/^ *"id": *"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$PLAN_ID" ] || { echo "could not determine the plan id"; exit 1; }
"$BIN" sync show "$PLAN_ID"

echo
echo "Executing the plan (writes the FAKE value to AWS and verifies by read-back)..."
"$BIN" sync run "$PLAN_ID" --yes || exit 1

echo
echo "Drift check (value read-back verification):"
"$BIN" destination drift || exit 1

echo
echo "Cleaning up: scheduling deletion of '$SECRET_NAME'..."
if "$BIN" destination delete-secret live-verify-aws "$SECRET_NAME" --yes; then
  CLEANED_REMOTE=1
else
  echo "CLEANUP FAILED — delete the secret manually (see the warning below)."
fi

echo
echo "Live verification finished. The throwaway vault (and the stored IAM"
echo "credentials) will now be deleted. If the IAM key was created only for"
echo "this test, deactivate/delete it in the AWS IAM console."
