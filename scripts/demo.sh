#!/usr/bin/env bash
# Tethra demo: builds a fully isolated demonstration vault with fake
# credentials, then shows how to explore it from the CLI and the desktop app.
#
#   bash scripts/demo.sh          # build, tour, then delete the demo vault
#   bash scripts/demo.sh --keep   # retain the demo vault for manual inspection
#   bash scripts/demo.sh --fresh  # replace an existing kept demo without asking
#
# Safety properties:
#   - Everything lives under an isolated temporary directory (a fresh mktemp
#     dir by default; set API_TRACKER_DEMO_DIR for a fixed location); your
#     real vault (default platform data dir) is never touched.
#   - Every credential value is generated at runtime, unmistakably fake, and
#     never sent to any provider. No network request is made.
#   - No real API key of any kind is required or used.
#
# The demo passwords are intentionally public documentation (docs/DEMO.md):
#   master password:  demo-master-password-12345
#   project password: demo-prod-project-password
#   backup password:  demo-backup-password-12345
# NEVER reuse them for a real vault.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$REPO_ROOT/$TARGET_DIR" ;; esac
BIN="$TARGET_DIR/release/api-tracker"

KEEP=0
FRESH=0
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --fresh) FRESH=1 ;;
    *) echo "unknown option: $arg (supported: --keep, --fresh)"; exit 2 ;;
  esac
done

MASTER_PASSWORD='demo-master-password-12345'
PROJECT_PASSWORD='demo-prod-project-password'
BACKUP_PASSWORD='demo-backup-password-12345'

# Runtime-generated fake values: obviously fake by construction, and the
# random tail guarantees the exact strings never exist in the repository or
# its Git history.
rand() { head -c "${1:-6}" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
FAKE_OPENAI="sk-proj-DEMO-FAKE-$(rand)-NOT-A-REAL-KEY"
FAKE_GITHUB="ghp_DEMOFAKE$(rand)0000000000"
FAKE_STRIPE="sk_test_DEMOFAKE$(rand)0000"
FAKE_ANTHROPIC="sk-ant-DEMO-FAKE-$(rand)-NOT-A-REAL-KEY"
FAKE_SHARED="sk-proj-DEMO-FAKE-SHARED-$(rand)-NOT-A-REAL-KEY"

# Expiration dates: one in the past, one within the 14-day warning window.
EXPIRED_DATE="2025-12-31"
if EXPIRING_DATE=$(date -v+7d +%Y-%m-%d 2>/dev/null); then
  :
else
  EXPIRING_DATE=$(date -d "+7 days" +%Y-%m-%d)
fi

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
run()  { echo "\$ api-tracker $*"; "$BIN" "$@"; }

if [ ! -x "$BIN" ]; then
  echo "Building the CLI (first run only)..."
  (cd "$REPO_ROOT" && cargo build --release -p api-tracker-cli)
  [ -x "$BIN" ] || { echo "error: built binary not found at $BIN" >&2; exit 1; }
fi

# Fresh, isolated data directory. The default is an unpredictable mktemp dir
# owned by the current user (nothing can pre-plant it). A fixed location via
# API_TRACKER_DEMO_DIR is reused only if it carries our marker file, and an
# existing kept demo is never deleted without --fresh or a confirmation.
if [ -n "${API_TRACKER_DEMO_DIR:-}" ]; then
  DEMO_DIR="$API_TRACKER_DEMO_DIR"
  MARKER="$DEMO_DIR/.api-tracker-demo"
  if [ -e "$DEMO_DIR" ]; then
    if [ ! -f "$MARKER" ]; then
      echo "error: $DEMO_DIR exists but was not created by this demo; refusing to delete it." >&2
      echo "Set API_TRACKER_DEMO_DIR to an unused path and re-run." >&2
      exit 1
    elif [ "$FRESH" -eq 1 ]; then
      rm -rf "$DEMO_DIR"
    elif [ -t 0 ]; then
      printf 'A previous demo vault exists at %s. Delete it and start fresh? [y/N] ' "$DEMO_DIR"
      read -r reply
      case "$reply" in
        y|Y|yes|YES) rm -rf "$DEMO_DIR" ;;
        *) echo "Keeping the existing demo. Re-run with --fresh to replace it."; exit 1 ;;
      esac
    else
      echo "error: a previous demo vault exists at $DEMO_DIR; re-run with --fresh to replace it." >&2
      exit 1
    fi
  fi
  mkdir -p "$DEMO_DIR/vault"
else
  DEMO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/api-tracker-demo.XXXXXX")" \
    || { echo "error: failed to create a temp dir under ${TMPDIR:-/tmp}" >&2; exit 1; }
  MARKER="$DEMO_DIR/.api-tracker-demo"
  mkdir -p "$DEMO_DIR/vault"
fi
touch "$MARKER"

# Isolate completely: only the demo vault, only demo secrets.
export API_TRACKER_DIR="$DEMO_DIR/vault"
export API_TRACKER_PASSWORD="$MASTER_PASSWORD"
export API_TRACKER_BACKUP_PASSWORD="$BACKUP_PASSWORD"
unset API_TRACKER_SESSION 2>/dev/null || true

echo "Demo vault directory: $API_TRACKER_DIR"
echo "(your real vault is untouched)"

say "Create the encrypted demo vault"
run init
# Surface never-used credentials immediately instead of after 30 days, so the
# demo can show the 'unused' classification honestly.
run settings set unused_days 0 >/dev/null

say "Create a development project and a production project"
run project create demo-dev  --env development --description "Demo development project"
run project create demo-prod --env production  --description "Demo production project (will be password-locked)"

say "Add demo credentials (all values are generated fakes)"
echo "$FAKE_OPENAI"    | run key add --project demo-dev --name openai-main            --provider openai    --environment development --value-stdin
"$BIN" key update demo-dev/openai-main --mark-valid >/dev/null    # -> active
echo "$FAKE_GITHUB"    | run key add --project demo-dev --name github-deploy          --provider github    --environment development --value-stdin --expires "$EXPIRED_DATE"
echo "$FAKE_STRIPE"    | run key add --project demo-dev --name stripe-webhook         --provider stripe    --environment development --value-stdin --expires "$EXPIRING_DATE"
echo "$FAKE_ANTHROPIC" | run key add --project demo-dev --name anthropic-experiments  --provider anthropic --environment development --value-stdin
echo "$FAKE_SHARED"    | run key add --project demo-dev --name payments-legacy        --provider openai    --environment development --value-stdin

say "Reuse the same fake credential in production (cross-project reuse)"
echo "The vault detects the duplicate and refuses unless you opt in:"
if echo "$FAKE_SHARED" | run key add --project demo-prod --name payments-live --provider openai --environment production --value-stdin; then
  echo "error: the duplicate was NOT refused — reuse detection regressed" >&2
  exit 1
fi
echo "(that refusal is the reuse warning — now storing it anyway with --allow-duplicate)"
echo "$FAKE_SHARED" | run key add --project demo-prod --name payments-live --provider openai --environment production --value-stdin --allow-duplicate

say "Password-lock the production project"
API_TRACKER_PROJECT_PASSWORD="$PROJECT_PASSWORD" run project lock demo-prod

say "Credential list (values are always redacted)"
run key list

say "Reuse warning on the shared credential"
run key status demo-dev/payments-legacy

say "Record synthetic token usage and set a small budget"
run usage record --credential demo-dev/openai-main --model gpt-4o --input-tokens 1000000 --output-tokens 1000000
run budget set --project demo-dev --amount 5.00
run usage report --project demo-dev
run budget show --project demo-dev

say "Run monitoring: expiration, reuse, and budget alerts"
run monitor
run alerts list

say "Create and verify an encrypted backup"
run backup create "$DEMO_DIR/demo-vault.backup"
run backup verify "$DEMO_DIR/demo-vault.backup"

say "Secure process injection (no .env file, value never printed)"
run mapping set --project demo-dev --credential demo-dev/openai-main --env OPENAI_API_KEY
echo "\$ api-tracker run --project demo-dev -- sh -c '...check env...'"
"$BIN" run --project demo-dev -- sh -c '
  if [ -n "${OPENAI_API_KEY:-}" ]; then echo "  child process: OPENAI_API_KEY is present (value hidden)"; fi
  if [ -z "${API_TRACKER_PASSWORD:-}" ]; then echo "  child process: API_TRACKER_PASSWORD is absent (master password not inherited)"; fi
'

say "Demo vault ready"
cat <<EOF
Projects:
  demo-dev   (development)          5 credentials: active, expired, expiring
                                    soon, unused, and one shared with prod
  demo-prod  (production, LOCKED)   1 credential: payments-live (same value
                                    as demo-dev/payments-legacy)

Demo passwords (fake, documented in docs/DEMO.md — never reuse them):
  master password:  $MASTER_PASSWORD
  project password: $PROJECT_PASSWORD
  backup password:  $BACKUP_PASSWORD

Explore from the CLI:
  export API_TRACKER_DIR="$DEMO_DIR/vault"
  export API_TRACKER_PASSWORD='$MASTER_PASSWORD'   # or: api-tracker unlock
  $BIN key list
  $BIN alerts list
  $BIN key reveal demo-dev/openai-main
  API_TRACKER_PROJECT_PASSWORD='$PROJECT_PASSWORD' \\
    $BIN project unlock demo-prod

Open in the desktop app (uses the same vault through the same core):
  cd "$REPO_ROOT/apps/desktop"
  API_TRACKER_DIR="$DEMO_DIR/vault" npm run tauri dev
  # then unlock with the master password above

Delete the demo when finished:
  rm -rf "$DEMO_DIR"
EOF

if [ "$KEEP" -eq 1 ]; then
  echo
  echo "--keep: the demo vault is retained at $DEMO_DIR"
else
  rm -rf "$DEMO_DIR"
  echo
  echo "Demo vault deleted (re-run with --keep to retain it and use the commands above)."
fi
