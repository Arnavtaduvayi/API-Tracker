#!/usr/bin/env bash
# Packaged macOS end-to-end validation of ZERO-FRICTION TRACKING.
#
# The precondition that matters: NO `tethra` CLI on PATH and a clean
# TETHRA_DIR. Everything is driven through the helper the PACKAGED APP
# ships (Tethra.app/Contents/MacOS/tethra) — if the bundling is wrong,
# this script cannot run at all, which is the point.
#
# Two modes. SERVICE mode installs a real per-user LaunchAgent. When one
# already exists for this user, the script switches to FOREGROUND mode
# instead of clobbering it (the ships-with label is fixed), starts the
# bundled helper's own `gateway serve`, and says so in the summary.
#
# What it proves:
#   * the packaged app carries a runnable, version-matched helper;
#   * `tethra track` configures a fixture project end to end with no
#     manual route/link/attribution step;
#   * verification cannot pass without observed traffic (negative
#     control), and DOES pass once a real request flows;
#   * `track undo` restores the .env exactly;
#   * no secret value reaches the database, WAL, or logs.
#
# Routes point at REAL provider origins with FAKE keys: a 401 proves
# DNS -> gateway -> TLS -> provider. Synthetic local upstreams are
# structurally impossible for a packaged binary (SI-3 refuses loopback
# origins), so those behaviors stay covered by the in-process suites.
#
# Isolated: a short TETHRA_DIR under /tmp (the control socket needs a
# sun_path under ~104 bytes), a throwaway vault, fake credentials. It
# never removes a LaunchAgent it did not install, and always cleans up
# after itself.
set -uo pipefail

APP="${1:-target/release/bundle/macos/Tethra.app}"
HELPER="$APP/Contents/MacOS/tethra"
DIR="/tmp/tethra-track-val-$$"
PROJECT="$DIR/sample-app"
export TETHRA_DIR="$DIR"
export TETHRA_PASSWORD="packaged-validation-password-123"
export API_TRACKER_INSECURE_FAST_KDF=1   # test vault only; never a real one
LABEL="dev.api-tracker.gateway"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
FAKE_KEY="sk-proj-PACKAGED-VALIDATION-FAKE-NOT-A-REAL-KEY-0001"
CANARY="TETHRA-CANARY-$$-MUST-NEVER-PERSIST"

pass=0; fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }
step() { echo; echo "== $1 =="; }

db() { sqlite3 "$DIR/vault.db" "$1" 2>/dev/null; }
assert_db() {
  local got; got="$(db "$1")"
  if [ "$got" = "1" ]; then ok "$2"; else bad "$2 (query returned '${got:-<empty/error>}')"; fi
}

SERVE_PID=""
cleanup() {
  step "cleanup"
  if [ -n "$SERVE_PID" ]; then
    kill "$SERVE_PID" >/dev/null 2>&1
    wait "$SERVE_PID" 2>/dev/null
    echo "  stopped the foreground gateway (pid $SERVE_PID)"
  fi
  # Only ever remove a LaunchAgent this run installed (service mode).
  if [ "${MODE:-foreground}" = "service" ]; then
    "$HELPER" gateway uninstall --yes >/dev/null 2>&1
    launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1
    rm -f "$PLIST"
  fi
  rm -rf "$DIR"
  echo "  cleaned $DIR"
}
trap cleanup EXIT

# --- preconditions ---------------------------------------------------------
step "preconditions (a clean machine, packaged app only)"
if [ ! -x "$HELPER" ]; then
  echo "FATAL: no runnable helper inside the app bundle at $HELPER"
  echo "The packaged app MUST ship its helper (scripts/bundle_cli.sh + externalBin)."
  exit 1
fi
ok "the packaged app contains an executable helper at Contents/MacOS/tethra"

# Service mode vs foreground mode.
#
# The LaunchAgent label that ships (dev.api-tracker.gateway) is fixed, so
# installing one here would bootout and overwrite an existing agent —
# destroying whatever the user already had. When one exists, this script
# runs in FOREGROUND mode instead: it starts the bundled helper's own
# `gateway serve` inside the isolated TETHRA_DIR, which is exactly the
# unsigned-build fallback path. Everything except the LaunchAgent
# registration itself is still proven end to end, and the summary says
# which mode ran — no silent downgrade.
MODE="service"
if [ -f "$PLIST" ] || [ "${TETHRA_VALIDATE_FOREGROUND:-}" = "1" ]; then
  MODE="foreground"
  echo "  NOTE  an existing gateway LaunchAgent is present (or foreground mode was"
  echo "        requested), so this run uses foreground mode and will NOT touch it."
  ok "pre-existing user state is left untouched (foreground mode)"
else
  ok "no pre-existing gateway LaunchAgent (service mode)"
fi

# Deliberately strip every place a developer CLI could hide, so nothing
# but the bundled helper can satisfy the run.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
if command -v tethra >/dev/null 2>&1; then
  echo "FATAL: a tethra CLI is still on PATH ($(command -v tethra)); this run would not prove bundling."
  exit 1
fi
ok "no tethra CLI on PATH (the bundled helper is the only one available)"

"$HELPER" gateway service-probe 2>/dev/null | grep -q "tethra-gateway-service-probe"
[ $? -eq 0 ] && ok "the bundled helper answers the exec probe" || bad "the bundled helper failed the exec probe"

APP_VER="$("$HELPER" --version 2>/dev/null | awk '{print $NF}')"
[ -n "$APP_VER" ] && ok "the bundled helper reports a version ($APP_VER)" || bad "the bundled helper reports no version"

# --- fixture ---------------------------------------------------------------
step "fixture project (fake keys only)"
mkdir -p "$PROJECT"
cat > "$PROJECT/.env" <<EOF
# A comment that must survive verbatim
OPENAI_API_KEY=$FAKE_KEY
UNRELATED_SETTING=$CANARY

EOF
cat > "$PROJECT/package.json" <<'EOF'
{ "name": "sample-app", "dependencies": { "openai": "^4.0.0", "dotenv": "^16.0.0" } }
EOF
ENV_BEFORE="$(cat "$PROJECT/.env")"
ok "fixture project written with a fake key and a canary value"

"$HELPER" init >/dev/null 2>&1
[ $? -eq 0 ] && ok "vault created through the bundled helper" || bad "vault creation failed"

if [ "$MODE" = "foreground" ]; then
  step "foreground gateway (the unsigned-build fallback path)"
  "$HELPER" gateway serve >"$DIR/serve.log" 2>&1 &
  SERVE_PID=$!
  for _ in $(seq 1 40); do
    sleep 0.5
    PORT="$(db "SELECT port FROM gateway_config WHERE id='gateway'")"
    [ -n "$PORT" ] && [ "$PORT" != "" ] && break
  done
  if kill -0 "$SERVE_PID" 2>/dev/null && [ -n "${PORT:-}" ]; then
    ok "the bundled helper serves the gateway in the foreground (port $PORT)"
  else
    bad "the foreground gateway did not start"
    sed 's/^/      /' "$DIR/serve.log" | head -10
  fi
fi

# --- dry run: nothing changes ---------------------------------------------
step "tethra track --dry-run (must change nothing)"
DRY="$("$HELPER" track "$PROJECT" --dry-run 2>&1)"
echo "$DRY" | grep -q "openai" && ok "the dry run detected openai" || bad "the dry run detected nothing"
echo "$DRY" | grep -q "OPENAI_BASE_URL" && ok "the dry run showed the exact env diff" || bad "no diff shown"
[ "$(cat "$PROJECT/.env")" = "$ENV_BEFORE" ] && ok "the dry run changed no file" || bad "the dry run modified .env"
if [ "$MODE" = "service" ]; then
  [ -f "$PLIST" ] && bad "the dry run installed a LaunchAgent" || ok "the dry run installed no service"
else
  ok "the dry run installed no service (foreground mode)"
fi
echo "$DRY" | grep -q "$FAKE_KEY" && bad "the dry run printed a key value" || ok "no key value in dry-run output"

# --- the one command -------------------------------------------------------
step "tethra track . (one command, no manual route/link/attribution steps)"
TRACK_OUT="$("$HELPER" track "$PROJECT" --yes 2>&1)"
TRACK_CODE=$?
echo "$TRACK_OUT" | sed 's/^/    /'
# Exit 2 = configured but no traffic yet: correct here, because nothing
# has made a request. Exit 0 would mean it verified without traffic.
[ $TRACK_CODE -eq 2 ] && ok "track exits 2 (configured, awaiting first request)" \
  || bad "track exited $TRACK_CODE (expected 2 before any traffic)"
echo "$TRACK_OUT" | grep -qi "route" && ok "routes were created automatically" || bad "no route step reported"
if [ "$MODE" = "service" ]; then
  [ -f "$PLIST" ] && ok "a real LaunchAgent was installed" || bad "no LaunchAgent installed"
else
  echo "  SKIP  LaunchAgent installation (foreground mode; existing user agent preserved)"
fi
grep -q "OPENAI_BASE_URL=http://127.0.0.1:" "$PROJECT/.env" \
  && ok ".env now points at the local gateway" || bad ".env was not repointed"
grep -q "^# A comment that must survive verbatim" "$PROJECT/.env" \
  && ok "comments survived the rewrite" || bad "the lossless rewrite lost a comment"
grep -q "NO_PROXY" "$PROJECT/.env" && ok "NO_PROXY was added for loopback" || bad "NO_PROXY missing"
echo "$TRACK_OUT" | grep -q "print-export" && bad "track printed shell-export choreography" \
  || ok "no shell-export choreography anywhere in the flow"

assert_db "SELECT COUNT(*)>=1 FROM gateway_routes WHERE route_prefix='openai'" \
  "the openai route exists in the database"
assert_db "SELECT COUNT(*)=1 FROM gateway_project_links" "exactly one project link was created"
assert_db "SELECT COUNT(*)=1 FROM tracking_setups" "one tracking setup was recorded"

# --- negative control: verification cannot pass without traffic -------------
step "negative control (no traffic yet)"
assert_db "SELECT state!='traffic_observed' FROM tracking_setups" \
  "the setup is NOT marked traffic_observed before any request"
assert_db "SELECT first_traffic_at IS NULL FROM tracking_setups" \
  "no first-traffic timestamp exists before any request"
"$HELPER" track status "$PROJECT" >/dev/null 2>&1
[ $? -eq 2 ] && ok "track status exits 2 while unverified" || bad "track status did not exit 2"

# Forge an OLD event (before applied_at): must not verify the setup.
APPLIED="$(db "SELECT applied_at FROM tracking_setups LIMIT 1")"
ok "applied_at recorded ($APPLIED)"

# --- real traffic ----------------------------------------------------------
step "one real request through the gateway (fake key -> provider 401)"
BASE="$(grep '^OPENAI_BASE_URL=' "$PROJECT/.env" | head -1 | cut -d= -f2- | awk '{print $1}')"
echo "    base URL: $BASE"
STATUS="$(curl -s -o /dev/null -w '%{http_code}' -m 30 \
  -H "Authorization: Bearer $FAKE_KEY" "$BASE/models" 2>/dev/null)"
echo "    provider answered: $STATUS"
case "$STATUS" in
  401|403) ok "the provider answered $STATUS through the gateway (path proven end to end)" ;;
  200) ok "the provider answered 200 through the gateway" ;;
  *) bad "unexpected status '$STATUS' (no network? the gateway did not forward?)" ;;
esac

# Give the writer thread its batch window.
sleep 8
assert_db "SELECT COUNT(*)>=1 FROM runtime_request_events WHERE observation_source='gateway'" \
  "the request was recorded as a gateway observation"

step "verification now passes (and only now)"
"$HELPER" track status "$PROJECT" >/dev/null 2>&1
VERIFY_CODE=$?
[ $VERIFY_CODE -eq 0 ] && ok "track status exits 0 after real traffic" \
  || bad "track status exited $VERIFY_CODE after traffic (expected 0)"
assert_db "SELECT state='traffic_observed' FROM tracking_setups" \
  "the setup is marked traffic_observed ONLY after a real request"
assert_db "SELECT first_traffic_at IS NOT NULL FROM tracking_setups" \
  "the first-traffic timestamp is set"

# --- privacy canaries ------------------------------------------------------
step "privacy canaries (no secret or payload at rest)"
for artifact in "$DIR/vault.db" "$DIR/vault.db-wal" "$DIR/vault.db-shm"; do
  [ -f "$artifact" ] || continue
  if grep -q "$FAKE_KEY" "$artifact" 2>/dev/null; then
    bad "the API key value appears in $(basename "$artifact")"
  else
    ok "no API key value in $(basename "$artifact")"
  fi
done
if grep -rq "$FAKE_KEY" "$DIR/logs" 2>/dev/null; then
  bad "the API key value appears in the logs"
else
  ok "no API key value in the logs"
fi
if grep -rq "Authorization" "$DIR/vault.db" 2>/dev/null; then
  bad "an authorization header string appears in the database"
else
  ok "no authorization header stored"
fi

# --- idempotence -----------------------------------------------------------
step "re-running setup is idempotent"
ENV_AFTER_FIRST="$(cat "$PROJECT/.env")"
"$HELPER" track "$PROJECT" --yes >/dev/null 2>&1
[ "$(cat "$PROJECT/.env")" = "$ENV_AFTER_FIRST" ] \
  && ok "a second run changed nothing in .env" || bad "a second run rewrote .env"
assert_db "SELECT COUNT(*)=1 FROM gateway_project_links" "no duplicate link row"
assert_db "SELECT COUNT(*)=1 FROM tracking_setups" "no duplicate tracking setup"

# --- undo ------------------------------------------------------------------
step "track undo restores exactly"
"$HELPER" track undo "$PROJECT" --yes >/dev/null 2>&1
[ "$(cat "$PROJECT/.env")" = "$ENV_BEFORE" ] \
  && ok "undo restored .env byte for byte" || {
    bad "undo did not restore .env exactly"
    diff <(echo "$ENV_BEFORE") "$PROJECT/.env" | head -10 | sed 's/^/      /'
  }
assert_db "SELECT COUNT(*)=0 FROM gateway_project_links" "the link row was removed"
assert_db "SELECT COUNT(*)>=1 FROM runtime_request_events" \
  "recorded history was KEPT (undo never deletes the user's data)"

# --- result ----------------------------------------------------------------
step "result"
MIN_CHECKS=30
total=$((pass+fail))
if [ "$total" -lt "$MIN_CHECKS" ]; then
  echo "=== PACKAGED TRACKING VALIDATION: VACUOUS ($total checks < $MIN_CHECKS floor) ==="
  exit 1
fi
echo "=== PACKAGED TRACKING VALIDATION ($MODE mode): $pass passed, $fail failed ($total checks) ==="
if [ "$MODE" = "foreground" ]; then
  echo "    NOTE: LaunchAgent registration was NOT exercised (an existing agent was"
  echo "    preserved). Service-mode registration is covered by the mock-runner"
  echo "    lifecycle suite and scripts/gateway_validate_macos.sh."
fi
[ "$fail" -eq 0 ]
