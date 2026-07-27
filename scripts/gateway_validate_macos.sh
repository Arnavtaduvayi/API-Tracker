#!/usr/bin/env bash
# Packaged macOS end-to-end validation of the Local Gateway.
#
# Drives the RELEASE tethra CLI (the exact binary the desktop "Enable"
# flow copies and the LaunchAgent runs) through the full 28-step
# lifecycle against a REAL per-user LaunchAgent. No real API keys: routes
# point at REAL provider origins and fake keys produce 401s — enough to
# prove forwarding, TLS verification, metadata recording, and
# fingerprint attribution (which is value-based and independent of
# provider acceptance). Synthetic LOCAL upstreams are structurally
# impossible for the packaged binary (SI-3 refuses loopback origins), so
# those behaviors are covered by the in-process test suite instead; this
# script says so where it applies.
#
# Isolated: a short TETHRA_DIR under /tmp (the control socket needs a
# sun_path under ~104 bytes), a throwaway fake vault, fake credentials,
# and a LaunchAgent label unique to this run is NOT used — the real label
# dev.api-tracker.gateway is used because that is what ships, but the
# script refuses to run if a gateway is already installed for the user,
# and always cleans up.
set -uo pipefail

CLI="$(pwd)/target/release/tethra"
DIR="/tmp/tethra-gw-val-$$"
export TETHRA_DIR="$DIR"
export TETHRA_PASSWORD="packaged-validation-password-123"
export API_TRACKER_INSECURE_FAST_KDF=1   # test vault only; never a real one
LABEL="dev.api-tracker.gateway"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
UID_N="$(id -u)"

pass=0; fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }
step() { echo; echo "== $1 =="; }

# Assert a SEMANTIC property of the vault database, not merely that some
# command exited 0. `$1` is a SQL query that must return exactly `1`; `$2` is
# the label. A query that errors, returns nothing, or returns anything else
# FAILS — so a check cannot pass because the gateway returned nothing.
db() { sqlite3 "$DIR/vault.db" "$1" 2>/dev/null; }
assert_db() {
  local got
  got="$(db "$1")"
  if [ "$got" = "1" ]; then ok "$2"; else bad "$2 (query returned '${got:-<empty/error>}')"; fi
}

# Assert a property of `gateway status` JSON. `$1` is a python expression over
# the parsed `gateway` object `g`; it must evaluate truthy.
assert_status() {
  local expr="$1" label="$2"
  if "$CLI" --json gateway status 2>/dev/null | python3 -c '
import sys, json
raw = sys.stdin.read()
if not raw.strip():
    sys.exit(1)                      # no output is a FAILURE, never a pass
d = json.loads(raw)
g = d.get("gateway")
if not g:
    sys.exit(1)                      # gateway absent is a FAILURE
sys.exit(0 if bool(eval(sys.argv[1], {}, {"g": g})) else 1)
' "$expr"; then ok "$label"; else bad "$label"; fi
}

cleanup() {
  "$CLI" gateway uninstall --keep-env --yes >/dev/null 2>&1 || true
  launchctl bootout "gui/$UID_N/$LABEL" >/dev/null 2>&1 || true
  rm -f "$PLIST" 2>/dev/null || true
  rm -rf "$DIR" 2>/dev/null || true
}
trap cleanup EXIT

if [ -e "$PLIST" ]; then
  echo "REFUSING: a gateway LaunchAgent already exists at $PLIST"; exit 2
fi
mkdir -p "$DIR"; chmod 700 "$DIR"

echo "CLI: $("$CLI" --version)"
echo "TETHRA_DIR: $DIR"

# --- vault + fake data ---
"$CLI" init >/dev/null 2>&1 && ok "init a fresh isolated vault" || bad "init"
"$CLI" project create app >/dev/null 2>&1 && ok "create project 'app'" || bad "project create"
# Two FAKE OpenAI-shaped keys: one we will link into the vault, one unknown.
KNOWN_KEY="sk-proj-FAKEvalidation0000000000000000000000000000known"
printf '%s' "$KNOWN_KEY" | "$CLI" key add --project app --provider openai --name prod --environment production --value-stdin >/dev/null 2>&1 \
  && ok "add a KNOWN fake credential to the vault" || bad "key add"

PROJDIR="$DIR/project"; mkdir -p "$PROJDIR"
printf 'OPENAI_API_KEY=%s\n' "$KNOWN_KEY" > "$PROJDIR/.env"

# =====================================================================
step "1-3. Enable gateway (desktop-equivalent), approve, confirm LaunchAgent"
# The desktop "Enable" action calls exactly this install path (byte-write
# + de-quarantine + exec probe + plist + bootstrap + kickstart). --yes is
# the programmatic consent; the desktop shows the consent card first.
"$CLI" gateway install --yes > "$DIR/install.log" 2>&1
if [ $? -eq 0 ]; then ok "gateway install succeeded"; else bad "gateway install (see install.log)"; cat "$DIR/install.log"; fi
[ -f "$PLIST" ] && ok "LaunchAgent plist written at $PLIST" || bad "no plist"
grep -q "KeepAlive" "$PLIST" && grep -q "Crashed" "$PLIST" && ok "plist has KeepAlive={Crashed:true}" || bad "plist KeepAlive"
grep -q -- "--data-dir" "$PLIST" && grep -q "$DIR" "$PLIST" && ok "plist bakes --data-dir into argv" || bad "plist data-dir"
launchctl print "gui/$UID_N/$LABEL" >/dev/null 2>&1 && ok "launchctl knows the service (bootstrapped)" || bad "not bootstrapped"

# Give the service a moment to bind and answer its identity probe.
PORT=""
for i in $(seq 1 40); do
  PORT="$("$CLI" --json gateway status 2>/dev/null | python3 -c 'import sys,json;d=json.load(sys.stdin);print((d.get("gateway") or {}).get("port") or "")' 2>/dev/null)"
  [ -n "$PORT" ] && break
  sleep 0.25
done
[ -n "$PORT" ] && ok "gateway is listening (port $PORT), identity-verified via status" || bad "gateway never came up"

step "4. Service survives the enabling process exiting"
# The CLI that ran `install` has already exited; the service is a
# separate launchd-owned process. Prove it is still up.
sleep 1
"$CLI" gateway status >/dev/null 2>&1 && ok "service still running after installer exited" || bad "service died with installer"
SVC_PID="$(launchctl print "gui/$UID_N/$LABEL" 2>/dev/null | awk '/pid =/{print $3; exit}')"
[ -n "$SVC_PID" ] && ok "launchd owns the service process (pid $SVC_PID)" || bad "no service pid"

step "5. Add a route (real provider origin; fake keys → 401)"
"$CLI" gateway route add openai >/dev/null 2>&1 && ok "route 'openai' added" || bad "route add"
"$CLI" gateway route list 2>/dev/null | grep -q "api.openai.com" && ok "route resolves to api.openai.com" || bad "route origin"

step "6. Link the project (real .env rewrite, preview+confirm)"
"$CLI" gateway link --project app --route openai --env-file "$PROJDIR/.env" --yes > "$DIR/link.log" 2>&1
grep -q "OPENAI_BASE_URL=http://127.0.0.1:$PORT/p/" "$PROJDIR/.env" && ok "OPENAI_BASE_URL rewritten to the gateway" || bad "base url not written"
grep -q "OPENAI_API_BASE=http://127.0.0.1:$PORT/p/" "$PROJDIR/.env" && ok "OPENAI_API_BASE alias written" || bad "alias not written"
grep -q "NO_PROXY=127.0.0.1,localhost,::1" "$PROJDIR/.env" && ok "NO_PROXY written" || bad "NO_PROXY missing"
grep -q "tethra-gateway route: openai" "$PROJDIR/.env" && ok "marker comment written" || bad "marker missing"
grep -q "OPENAI_API_KEY=$KNOWN_KEY" "$PROJDIR/.env" && ok "existing OPENAI_API_KEY preserved" || bad "user key clobbered"

# The base URL the SDKs will use.
BASE="http://127.0.0.1:$PORT/p/$(grep -oE '/p/[0-9a-f]+/openai' "$PROJDIR/.env" | head -1 | sed 's#/p/##;s#/openai##')/openai"
echo "  (link base: http://127.0.0.1:$PORT/p/<slug>/openai)"

step "7. curl through the gateway (fake key → provider 401 proves the path)"
CURL_STATUS="$(curl -s -o "$DIR/curl.out" -w '%{http_code}' --max-time 20 \
  -H "Authorization: Bearer $KNOWN_KEY" "$BASE/v1/models")"
if [ "$CURL_STATUS" = "401" ] || [ "$CURL_STATUS" = "403" ]; then
  ok "curl reached OpenAI through the gateway (provider $CURL_STATUS on a fake key)"
elif grep -q "tethra-gateway:" "$DIR/curl.out" 2>/dev/null; then
  bad "gateway answered locally ($CURL_STATUS) instead of forwarding: $(cat "$DIR/curl.out")"
else
  bad "unexpected curl result: $CURL_STATUS ($(head -c120 "$DIR/curl.out"))"
fi

step "8. Python Requests through the gateway"
if command -v python3 >/dev/null; then
  PY_STATUS="$(OPENAI_BASE="$BASE" KEY="$KNOWN_KEY" python3 - <<'PY' 2>/dev/null
import os, urllib.request
req = urllib.request.Request(os.environ["OPENAI_BASE"] + "/v1/models",
    headers={"Authorization": "Bearer " + os.environ["KEY"]})
try:
    urllib.request.urlopen(req, timeout=20)
    print(200)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print("ERR", e)
PY
)"
  [ "$PY_STATUS" = "401" ] || [ "$PY_STATUS" = "403" ] && ok "Python reached OpenAI through the gateway ($PY_STATUS)" || bad "python result: $PY_STATUS"
else
  echo "  SKIP python3 not present"
fi

step "9. Node through the gateway"
if command -v node >/dev/null; then
  NODE_STATUS="$(OPENAI_BASE="$BASE" KEY="$KNOWN_KEY" node -e '
const http=require("http");
const u=new URL(process.env.OPENAI_BASE+"/v1/models");
const req=http.request(u,{headers:{Authorization:"Bearer "+process.env.KEY}},res=>{console.log(res.statusCode);res.resume();});
req.on("error",e=>console.log("ERR",e.message));req.end();
' 2>/dev/null)"
  [ "$NODE_STATUS" = "401" ] || [ "$NODE_STATUS" = "403" ] && ok "Node reached OpenAI through the gateway ($NODE_STATUS)" || bad "node result: $NODE_STATUS"
else
  echo "  SKIP node not present"
fi

step "10. Verify metadata was recorded"
sleep 1
assert_status 'g.get("written_events", 0) >= 1' \
  "metadata events recorded (status/latency/path — no bodies)"
# ...and prove it landed in the DATABASE, not merely in a counter.
assert_db "SELECT CASE WHEN COUNT(*) >= 1 THEN 1 ELSE 0 END
           FROM runtime_request_events WHERE observation_source='gateway'" \
  "the recorded events are actually persisted"
# Negative control: the forbidden columns must not exist at all, so a future
# schema that adds one is caught here rather than by a reviewer.
assert_db "SELECT CASE WHEN COUNT(*) = 0 THEN 1 ELSE 0 END
           FROM pragma_table_info('runtime_request_events')
           WHERE name IN ('body','request_body','response_body','headers','url','query')" \
  "no body/header/url/query column exists on the event table"

step "11-12. Attribution: KNOWN vs UNKNOWN fake credential"
# Attribution is fingerprint-based, so it works on a 401. Push the key.
"$CLI" gateway push-key >/dev/null 2>&1 <<< "$TETHRA_PASSWORD" || true
# push-key uses prompt_secret (interactive); drive it with expect.
if command -v expect >/dev/null; then
  expect -c "
    set timeout 15
    spawn $CLI gateway push-key
    expect -re {[Pp]assword}
    send \"$TETHRA_PASSWORD\r\"
    expect eof
  " >/dev/null 2>&1 && ok "matching key pushed (attribution enabled)" || echo "  NOTE push-key needs a TTY; attribution stays off (honest state)"
fi
BEFORE_EVENTS="$(db "SELECT COUNT(*) FROM runtime_request_events WHERE observation_source='gateway'")"
# Known key traffic:
curl -s -o /dev/null --max-time 20 -H "Authorization: Bearer $KNOWN_KEY" "$BASE/v1/models"
# Unknown key traffic:
UNKNOWN_KEY="sk-proj-FAKEvalidation1111111111111111111111111unknown"
curl -s -o /dev/null --max-time 20 -H "Authorization: Bearer $UNKNOWN_KEY" "$BASE/v1/models"
sleep 2

# ASSERTED, not narrated. Both exchanges must have produced gateway events.
assert_db "SELECT CASE WHEN COUNT(*) >= ${BEFORE_EVENTS:-0} + 2 THEN 1 ELSE 0 END
           FROM runtime_request_events WHERE observation_source='gateway'" \
  "both known- and unknown-key exchanges were recorded"

# The two exchanges must be attributed DIFFERENTLY. This is the check whose
# absence the audit found: the previous script printed a 'distinct
# fingerprint' claim that no assertion ever produced. With the matching key
# resident, the known key resolves to a credential and the unknown one does
# not; without the key, both are unavailable and the check is skipped with a
# recorded reason rather than silently passing.
if "$CLI" --json gateway status 2>/dev/null | grep -q '"matching_key_present":true'; then
  assert_db "SELECT CASE WHEN COUNT(DISTINCT COALESCE(credential_id,'<none>')) >= 2
                         THEN 1 ELSE 0 END
             FROM (SELECT credential_id FROM runtime_request_events
                   WHERE observation_source='gateway'
                   ORDER BY at DESC LIMIT 2)" \
    "the known and unknown credentials attribute DISTINCTLY"
  assert_db "SELECT CASE WHEN COUNT(*) >= 1 THEN 1 ELSE 0 END
             FROM runtime_request_events
             WHERE observation_source='gateway' AND credential_id IS NOT NULL" \
    "the known fake credential was matched to a vault credential"
else
  echo "  SKIP attribution distinctness: no matching key resident (push-key"
  echo "       needs a TTY). This is a COVERAGE GAP in this run, not a pass."
  bad "attribution distinctness NOT verified (no matching key)"
fi

step "13. SSE begins promptly — NOT VERIFIED HERE"
echo "  A 401 does not stream, and a synthetic local upstream is structurally"
echo "  impossible for the packaged binary (SI-3 refuses loopback origins), so"
echo "  this property is measured in the in-process suite instead"
echo "  (PERFORMANCE_RESULTS.md: +5.6ms first-byte, 200/200 events)."
echo "  Deliberately NOT counted as a check: pointing at other evidence is not"
echo "  evidence, and counting it inflated this run's total by one."

step "14-16. Lock the vault during traffic; forwarding continues"
# The service holds no vault key material; forwarding is vault-independent.
# There is no live vault session in the service to 'lock' — prove instead
# that the service keeps forwarding with NO unlocked vault anywhere.
curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H "Authorization: Bearer $KNOWN_KEY" "$BASE/v1/models" | grep -qE '401|403' \
  && ok "forwarding continues with no unlocked vault (SI-11)" || bad "forwarding stopped without a vault"
"$CLI" gateway status >/dev/null 2>&1 && ok "status works with the vault locked (SI: lock-free)" || bad "status needs the vault"

step "17-18. Unlock, verify flush and honest gap reporting"
# The previous form piped status into a python that only PRINTED, so it
# exited 0 — and reported PASS — even against an empty response.
assert_status '"dropped_events" in g and "queue_depth" in g and "written_events" in g' \
  "queue/drop counters exposed for honest gap reporting"
assert_status 'g["written_events"] >= 1' \
  "the run recorded at least one event (an empty status is a failure, not a pass)"

step "19-20. Stop the gateway; verify diagnostics"
"$CLI" gateway stop >/dev/null 2>&1 && ok "gateway stop requested (graceful)" || bad "stop failed"
sleep 1
"$CLI" --json gateway doctor 2>/dev/null | python3 -c '
import sys,json; d=json.load(sys.stdin)
ids=[f["id"] for f in d["findings"]]
print("  doctor findings:", ", ".join(ids))
# After a graceful stop the service (KeepAlive=Crashed) stays down.
sys.exit(0 if ("installed_but_stopped" in ids or "running" in ids or "running_manually" in ids) else 1)
' && ok "doctor diagnoses the stopped/running state" || bad "doctor unclear"

step "21-22. Restart; verify recovery"
"$CLI" gateway restart >/dev/null 2>&1 && ok "restart requested" || bad "restart failed"
RECOVERED=""
for i in $(seq 1 40); do
  RECOVERED="$("$CLI" --json gateway status 2>/dev/null | python3 -c 'import sys,json;d=json.load(sys.stdin);print("y" if d.get("gateway") else "")' 2>/dev/null)"
  [ -n "$RECOVERED" ] && break
  sleep 0.25
done
[ -n "$RECOVERED" ] && ok "gateway recovered after restart" || bad "no recovery"

step "23. Unlink the project (restore prior .env)"
"$CLI" gateway unlink --project app --route openai --yes >/dev/null 2>&1 && ok "unlink succeeded" || bad "unlink failed"
if grep -q "OPENAI_API_KEY=$KNOWN_KEY" "$PROJDIR/.env" && ! grep -q "127.0.0.1" "$PROJDIR/.env"; then
  ok "unlink restored .env exactly (key kept, gateway lines gone)"
else
  bad "unlink restore imperfect: $(cat "$PROJDIR/.env")"
fi

step "24-25. Disable then uninstall"
"$CLI" gateway uninstall --yes >/dev/null 2>&1 && ok "uninstall succeeded" || bad "uninstall failed"

step "26-27. Verify LaunchAgent + listener + tokens + files all gone"
sleep 1
[ ! -f "$PLIST" ] && ok "LaunchAgent plist removed" || bad "plist remains"
launchctl print "gui/$UID_N/$LABEL" >/dev/null 2>&1 && bad "launchd still knows the service" || ok "service unregistered from launchd"
[ ! -e "$DIR/gateway.sock" ] && ok "control socket removed" || bad "socket remains"
[ ! -e "$DIR/gateway.nonce" ] && ok "control nonce removed" || bad "nonce remains"
[ ! -d "$DIR/bin" ] && ok "service binaries removed" || bad "bin/ remains"
if [ -n "$PORT" ]; then
  sleep 1
  curl -s -o /dev/null --max-time 5 "http://127.0.0.1:$PORT/openai/v1/models" 2>/dev/null && bad "something still listens on $PORT" || ok "no listener on the old port"
fi

step "28. Ordinary networking is unaffected"
curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://api.openai.com/v1/models -H "Authorization: Bearer $KNOWN_KEY" | grep -qE '401|403' \
  && ok "direct provider networking still works (401 on the fake key)" || bad "direct networking broken"

step "29. Privacy canaries: forbidden values must appear NOWHERE on disk"
# The known fake key and the distinctive path/query canaries must not be in
# the database, its WAL/SHM sidecars, the service log, or any runtime file.
# Scanned AFTER uninstall so the check covers what is left behind.
CANARY_FOUND=0
for f in "$DIR/vault.db" "$DIR/vault.db-wal" "$DIR/vault.db-shm" \
         "$DIR/logs/gateway.log" "$DIR/gateway.nonce" "$DIR/gateway.pid"; do
  [ -e "$f" ] || continue
  for needle in "$KNOWN_KEY" "$UNKNOWN_KEY" "CANARYQUERY"; do
    if LC_ALL=C grep -qa -- "$needle" "$f" 2>/dev/null; then
      bad "canary '${needle:0:12}...' found in $f"
      CANARY_FOUND=1
    fi
  done
done
# The scan must actually have had something to scan; an all-missing file set
# would otherwise report a clean pass having read nothing.
SCANNED=0
for f in "$DIR/vault.db" "$DIR/vault.db-wal" "$DIR/vault.db-shm" "$DIR/logs/gateway.log"; do
  [ -e "$f" ] && SCANNED=$((SCANNED+1))
done
if [ "$SCANNED" -lt 1 ]; then
  bad "privacy canary scanned NO files (vacuous); expected at least vault.db"
elif [ "$CANARY_FOUND" -eq 0 ]; then
  ok "no credential or query canary in any on-disk artifact ($SCANNED file(s) scanned)"
fi

step "30. Negative controls: prove the assertions can FAIL"
# A validation script that cannot fail proves nothing. These exercise the
# helpers against conditions that MUST be rejected.
if db "SELECT 0" >/dev/null 2>&1; then
  NEG_OK=1
  # assert_db must reject a query returning 0.
  got="$(db "SELECT 0")"; [ "$got" = "1" ] && NEG_OK=0
  # ...and one returning nothing.
  got="$(db "SELECT 1 WHERE 0")"; [ "$got" = "1" ] && NEG_OK=0
  # ...and a syntactically invalid one.
  got="$(db "SELECT FROM nowhere")"; [ "$got" = "1" ] && NEG_OK=0
  [ "$NEG_OK" -eq 1 ] \
    && ok "assert_db rejects false, empty, and erroring queries" \
    || bad "assert_db would pass a query it must reject"
else
  bad "negative control could not run (no readable database)"
fi
# assert_status must reject an absent gateway: nothing is running now.
if "$CLI" --json gateway status 2>/dev/null | python3 -c '
import sys, json
raw = sys.stdin.read()
if not raw.strip():
    sys.exit(1)
g = json.loads(raw).get("gateway")
sys.exit(0 if g else 1)
'; then
  bad "a stopped gateway still reported a live status object"
else
  ok "assert_status rejects a stopped gateway (an empty response is a failure)"
fi

echo
echo "=== PACKAGED MACOS RESULT: $pass passed, $fail failed ==="
# A run that asserted almost nothing must not read as success. This floor is
# the structural guard against the vacuity the final audit found: if steps are
# skipped or helpers silently stop asserting, the count drops below it and the
# script fails even with zero recorded failures.
MIN_CHECKS=30
if [ "$pass" -lt "$MIN_CHECKS" ]; then
  echo "FAIL: only $pass checks ran; at least $MIN_CHECKS are expected."
  echo "      A low count means checks were SKIPPED, not that all is well."
  exit 1
fi
[ "$fail" -eq 0 ]
