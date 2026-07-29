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
# ISOLATED, and isolated the way the product is (RA-004). Every identifier
# this script touches belongs to THIS run: a short data directory under
# /private/tmp (the control socket needs a sun_path under ~104 bytes), a
# throwaway fake vault, fake credentials, and the PER-INSTALLATION
# LaunchAgent label the product derives from that data directory
# (lifecycle::installation_id → macos::label_for). The production label
# dev.api-tracker.gateway is never installed, never bootstrapped, never
# booted out and never deleted here.
#
# The revision this replaces hardcoded the production label and plist path
# and armed an `rm -f "$PLIST"` EXIT trap BEFORE its own safety guard ran,
# so on a machine that already had a gateway the guard's `exit 2` fired the
# trap and permanently deleted the user's live LaunchAgent — the refusal
# path was the destructive one. Two independent properties now prevent
# that: every refusal happens before any trap exists (so a refusal writes
# nothing at all), and teardown removes only what an explicit ownership
# ledger records this run creating, re-proving each record before acting.
# This mirrors lifecycle::ServiceManager::ensure_ours, which refuses to
# touch any definition it cannot prove points at its own data directory;
# read the two together.
set -uo pipefail

# --- identity: everything below names THIS run, and only this run ----------

# The PRODUCTION label. Named here once so every refusal below can compare
# against it by name; nothing in this script ever installs, starts, stops or
# removes it. Matches lifecycle::macos::LEGACY_LABEL.
LEGACY_LABEL="dev.api-tracker.gateway"

CLI="$(pwd)/target/release/tethra"
UID_N="$(id -u)"

# /private/tmp, not /tmp. `installation_id` CANONICALIZES the data directory,
# so a path reached through the /tmp symlink hashes to one label while the
# directory is absent and a different one once it exists — deriving our label
# from an already-canonical path keeps it stable, which is what lets every
# refusal below run before anything is created. The assertion after mkdir
# proves the derivation did not move rather than assuming it.
TMPBASE="$(cd /tmp 2>/dev/null && pwd -P)" || TMPBASE="/tmp"
RUN_ID="$$-$(od -An -N4 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
DIR="$TMPBASE/tethra-gw-val-$RUN_ID"
LEDGER="$TMPBASE/tethra-gw-val-$RUN_ID.ledger"
export TETHRA_DIR="$DIR"
export TETHRA_PASSWORD="packaged-validation-password-123"
export API_TRACKER_INSECURE_FAST_KDF=1   # test vault only; never a real one

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

# =====================================================================
# Ownership ledger
# =====================================================================
# What the old teardown got wrong was not WHICH paths it deleted but that it
# ASSUMED it owned them: it deleted a hardcoded plist whether or not this run
# had ever written one. Nothing is assumed here. An artifact is recorded the
# moment this run is observed to have created it, together with the evidence
# teardown needs to re-prove ownership later:
#
#   dir    <path>                    a directory we created (preflight proved
#                                    it absent, so its existence is ours)
#   plist  <path>   <label>          a definition we created; removed only
#                                    while it still names <label> AND bakes
#                                    --data-dir $DIR into its argv
#   label  <label>                   a launchd job we bootstrapped
#   pid    <pid>    <binary-prefix>  a process we started; signalled only if
#                                    that pid still runs that binary
#
# A file rather than shell variables: every record then survives subshells and
# pipelines, so a record written inside one cannot silently fail to reach
# teardown. Anything the ledger does not name is, by construction, something
# this run found already on the machine — and is never a removal candidate.
ledger_add() { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$LEDGER"; }
ledger_values() {
  [ -f "$LEDGER" ] || return 0
  awk -F'\t' -v k="$1" '$1 == k { print $2 "\t" $3 }' "$LEDGER"
}

# Does the definition at $1 still prove it is the one we wrote under label $2?
# Both facts are required: the label alone is just a string anyone can put in
# a file, while --data-dir names a directory that did not exist before this
# run started. Our paths contain no XML metacharacters, so the plist's
# escaping (macos::xml_escape) cannot change how they appear here.
plist_is_ours() {
  local p="$1" lbl="$2"
  [ -L "$p" ] && return 1          # a symlink is not the file we wrote
  [ -f "$p" ] || return 1
  grep -q "<string>$lbl</string>" "$p" 2>/dev/null || return 1
  grep -q "<string>$DIR</string>" "$p" 2>/dev/null || return 1
  return 0
}

# Is pid $1 still the process we started from $2? IDENTITY, never a pattern.
# `pkill -f tethra` or `killall` would have matched the user's production
# gateway — a live service holding their real vault — which is the same class
# of mistake as deleting their plist. `ps -o comm=` reports the executable
# PATH on macOS, and ours lives under a directory unique to this run.
proc_is_ours() {
  local pid="$1" prefix="$2" cmd
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  kill -0 "$pid" 2>/dev/null || return 1
  cmd="$(ps -p "$pid" -o comm= 2>/dev/null)" || return 1
  case "$cmd" in "$prefix"*) return 0 ;; *) return 1 ;; esac
}

# Teardown. Ledger-driven, ownership-checked, and idempotent: every action is
# guarded by "does this still exist and is it still ours", so a second run
# finds nothing left to prove and does nothing. It is armed only after every
# refusal below has passed.
cleanup() {
  local value extra

  # 1. Let the PRODUCT tear down its own installation first — the same path a
  #    user runs, and one that applies ensure_ours against $TETHRA_DIR, so it
  #    can only act on this run's service. Skipped entirely when we never got
  #    as far as registering one.
  if [ -n "$(ledger_values label)" ]; then
    "$CLI" gateway uninstall --keep-env --yes >/dev/null 2>&1 || true
  fi

  # 2. Stop only processes this run started, proven by pid AND binary.
  while IFS=$'\t' read -r value extra; do
    if proc_is_ours "$value" "$extra"; then
      kill -TERM "$value" 2>/dev/null || true
    fi
  done < <(ledger_values pid)

  # 3. Unload only labels this run bootstrapped. `bootout` addresses the LIVE
  #    gui/<uid> domain no matter which $HOME the plist came from (ZFT-014),
  #    so it gets the strictest guard: never the production label, and — while
  #    the definition is still on disk — only when that definition proves ours.
  #    Once step 1 has removed the plist there is nothing left to re-read; the
  #    record itself is then the proof, because the label is derived from a
  #    data directory that did not exist until this run created it.
  while IFS=$'\t' read -r value extra; do
    [ -n "$value" ] || continue
    [ "$value" = "$LEGACY_LABEL" ] && continue
    if [ -e "$LA_DIR/$value.plist" ] && ! plist_is_ours "$LA_DIR/$value.plist" "$value"; then
      echo "  cleanup: leaving $LA_DIR/$value.plist alone (it no longer proves it is ours)" >&2
      continue
    fi
    launchctl bootout "gui/$UID_N/$value" >/dev/null 2>&1 || true
  done < <(ledger_values label)

  # 4. Remove only definitions this run created, and only while they still
  #    prove it. A recorded plist whose contents stopped matching is LEFT IN
  #    PLACE and reported: a visible stray file under a label nothing else
  #    uses is a far smaller harm than deleting a file we can no longer prove
  #    we wrote, which is precisely the harm being fixed here.
  while IFS=$'\t' read -r value extra; do
    [ -n "$value" ] || continue
    [ "$value" = "$PROD_PLIST" ] && continue
    if [ -e "$value" ] && ! plist_is_ours "$value" "$extra"; then
      echo "  cleanup: NOT removing $value (it no longer proves it is ours)" >&2
      continue
    fi
    rm -f "$value" 2>/dev/null || true
  done < <(ledger_values plist)

  # 5. Our scratch directory. The prefix test is belt-and-braces: a truncated
  #    or corrupted ledger must not be able to widen an `rm -rf`.
  while IFS=$'\t' read -r value extra; do
    case "$value" in
      "$TMPBASE"/tethra-gw-val-*) rm -rf "$value" 2>/dev/null || true ;;
      *) [ -n "$value" ] && echo "  cleanup: refusing to remove unexpected directory $value" >&2 ;;
    esac
  done < <(ledger_values dir)

  rm -f "$LEDGER" 2>/dev/null || true
}

# =====================================================================
# Preflight
# =====================================================================
# EVERY refusal lives here, above the `trap` line, and writes nothing: no
# directory, no ledger, no trap. A refusal therefore leaves the machine
# byte-identical to how it was found — which is the property the old script
# advertised and inverted.
refuse() { echo "REFUSING: $*" >&2; exit 2; }

if [ ! -x "$CLI" ]; then
  refuse "no release CLI at $CLI (build it first: cargo build --release)"
fi
if ! command -v python3 >/dev/null 2>&1; then
  refuse "python3 is required to read the CLI's JSON service identity"
fi
if [ -z "${HOME:-}" ]; then
  refuse "HOME is not set; cannot locate ~/Library/LaunchAgents"
fi
# $DIR and $LEDGER are built from $TMPBASE and teardown's prefix guard trusts
# it, so a scratch base that did not resolve must stop the run rather than
# quietly relocate both to /.
if [ -z "$TMPBASE" ] || [ ! -d "$TMPBASE" ]; then
  refuse "could not resolve a scratch base directory (got '${TMPBASE}')"
fi
LA_DIR="$HOME/Library/LaunchAgents"
PROD_PLIST="$LA_DIR/$LEGACY_LABEL.plist"

if [ -e "$DIR" ]; then
  refuse "scratch data directory $DIR already exists; this run will not adopt a directory it did not create"
fi
if [ -e "$LEDGER" ]; then
  refuse "ownership ledger $LEDGER already exists"
fi

# This script drives install → bootstrap → stop → restart → uninstall. It will
# not do that beside a live production gateway: `gateway install` also runs
# the legacy-agent reclaim (lifecycle::reclaim_legacy), and a validation
# harness has no business standing next to the user's real service to find out
# whether the product's ownership proof holds. Read-only checks — a stat, a
# glob and a `launchctl print` — and the plist named here is NEVER removed by
# this script under any exit path.
if [ -e "$PROD_PLIST" ]; then
  refuse "a production gateway LaunchAgent already exists at $PROD_PLIST. This run will not proceed beside it, and will never delete it. Uninstall it yourself first (\`tethra gateway uninstall\`) if you want this validation."
fi
for existing in "$LA_DIR/$LEGACY_LABEL".*.plist; do
  [ -e "$existing" ] || continue
  refuse "a Tethra gateway LaunchAgent already exists at $existing. This run will not proceed beside it, and will never delete it."
done
if launchctl print "gui/$UID_N/$LEGACY_LABEL" >/dev/null 2>&1; then
  refuse "launchd already runs the production job gui/$UID_N/$LEGACY_LABEL"
fi

# The label is the PRODUCT's to decide, not ours to invent: ask the CLI which
# service this data directory owns. Re-deriving blake3 over a canonicalized
# path in shell would be a second implementation, free to drift from the one
# that actually writes the plist — and drift here means acting on a job that
# is not the one we installed.
svc_field() {
  "$CLI" --json gateway status 2>/dev/null | python3 -c '
import sys, json
raw = sys.stdin.read()
if not raw.strip():
    sys.exit(1)
s = (json.loads(raw) or {}).get("service") or {}
v = s.get(sys.argv[1])
if not v:
    sys.exit(1)
print(v)
' "$1"
}
LABEL="$(svc_field service_name)" || refuse "could not read the LaunchAgent label the CLI derives for $DIR"
PLIST="$(svc_field definition_path)" || refuse "could not read the plist path the CLI derives for $DIR"

# Refuse the production identifiers outright. Whatever else drifts — the
# derivation, the CLI, this script — the run must be unable to NAME the user's
# live service, so the checks are on the resolved strings rather than on the
# reasoning that produced them.
if [ "$LABEL" = "$LEGACY_LABEL" ]; then
  refuse "the CLI resolved the PRODUCTION label $LEGACY_LABEL for $DIR; this run installs only per-installation labels"
fi
case "$LABEL" in
  "$LEGACY_LABEL".*) ;;
  *) refuse "resolved label '$LABEL' is outside the $LEGACY_LABEL.* family" ;;
esac
if ! printf '%s' "${LABEL#"$LEGACY_LABEL".}" | grep -qE '^[0-9a-f]{12}$'; then
  refuse "resolved label '$LABEL' is not a per-installation label (expected $LEGACY_LABEL.<12 hex>)"
fi
if [ "$PLIST" = "$PROD_PLIST" ]; then
  refuse "the CLI resolved the PRODUCTION plist path $PROD_PLIST for $DIR"
fi
if [ "$PLIST" != "$LA_DIR/$LABEL.plist" ]; then
  refuse "resolved plist $PLIST does not sit at $LA_DIR/$LABEL.plist; refusing to act on an unexpected path"
fi
if [ -e "$PLIST" ]; then
  refuse "$PLIST already exists — this run neither adopts nor deletes a file it did not create"
fi
if launchctl print "gui/$UID_N/$LABEL" >/dev/null 2>&1; then
  refuse "launchd already knows gui/$UID_N/$LABEL; refusing to take over a job this run did not create"
fi

# Read-only snapshot of the production definition, for the invariant asserted
# at the end. The refusal above means this is normally `absent`; the assertion
# then fails if this run ever CREATES, moves or replaces that file — which is
# the check that would have caught RA-004 from inside the script.
prod_sig() {
  if [ -e "$PROD_PLIST" ]; then
    stat -f '%z-bytes mtime=%m mode=%Lp' "$PROD_PLIST" 2>/dev/null || echo "present-unreadable"
  else
    echo absent
  fi
}
PROD_SIG_BEFORE="$(prod_sig)"

# =====================================================================
# Create the isolated namespace. Only now does a teardown trap exist.
# =====================================================================
if ! : > "$LEDGER"; then
  refuse "could not create the ownership ledger at $LEDGER"
fi
if ! mkdir "$DIR"; then          # plain mkdir: a second guard against adoption
  rm -f "$LEDGER"
  refuse "could not create the scratch data directory $DIR"
fi
chmod 700 "$DIR"
ledger_add dir "$DIR"
trap cleanup EXIT

# `installation_id` canonicalizes, so creating the directory could in
# principle move the label the preflight checks just vetted (it does for a
# /tmp-symlinked path — the reason $TMPBASE is resolved with `pwd -P`). Prove
# it did not, before anything is installed under either name.
LABEL_AFTER="$(svc_field service_name)" || LABEL_AFTER=""
if [ "$LABEL_AFTER" != "$LABEL" ]; then
  echo "ABORT: the service label moved when $DIR was created ($LABEL -> ${LABEL_AFTER:-<unreadable>})." >&2
  echo "       Refusing to install under a label no preflight check vetted." >&2
  exit 2
fi

echo "CLI: $("$CLI" --version)"
echo "TETHRA_DIR: $DIR"
echo "LaunchAgent: $LABEL"
echo "  plist:     $PLIST"

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
# Record BEFORE asserting anything about the contents: preflight proved this
# path absent, so a file here now is this run's doing, and a plist that is
# present but malformed must still be cleaned up rather than leaked. What the
# record permits is bounded separately, by plist_is_ours at teardown.
if [ -e "$PLIST" ]; then
  ledger_add plist "$PLIST" "$LABEL"
  ledger_add label "$LABEL"
  ok "LaunchAgent plist written at $PLIST"
else
  bad "no plist"
fi
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
if [ -n "$SVC_PID" ]; then
  # Recorded with the binary it must still be running: teardown signals this
  # pid only after re-proving both facts, so a pid that has since been reused
  # by an unrelated process is left alone.
  ledger_add pid "$SVC_PID" "$DIR/bin/"
  ok "launchd owns the service process (pid $SVC_PID)"
else
  bad "no service pid"
fi

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
# push-key is DELIBERATELY interactive: it is a reauthentication, so it uses
# prompt_secret() rather than master_password() and does not read
# $TETHRA_PASSWORD from the environment the way `unlock` does. That is a
# security property, not an oversight, and this script drives the prompt with
# a pty rather than asking for it to be relaxed.
#
# The stdin attempt below cannot work for the same reason (prompt_hidden reads
# the terminal, not stdin). It is kept only so the expect path is not the only
# thing that has ever been tried, and its result is ignored.
"$CLI" gateway push-key >/dev/null 2>&1 <<< "$TETHRA_PASSWORD" || true
if ! command -v expect >/dev/null; then
  bad "expect(1) is unavailable, so the interactive push-key path cannot be driven here"
else
  # The transcript stays in a shell variable and is REDACTED before it is
  # printed. It must never reach the disk: a pty transcript of a password
  # prompt can echo the password, $DIR is swept for canaries at step 29, and
  # "the harness wrote the secret to the directory it then searches" is a
  # self-inflicted version of the exact defect that sweep exists to catch.
  PUSH_KEY_LOG="$(expect -c "
    set timeout 15
    spawn $CLI gateway push-key
    expect -re {[Pp]assword}
    send \"$TETHRA_PASSWORD\r\"
    expect eof
  " 2>&1 | sed "s/$TETHRA_PASSWORD/<redacted>/g")"
  # GROUND TRUTH, not inference.
  #
  # This used to be `expect ... && ok "matching key pushed"`, which asserts
  # that EXPECT ran to eof — a statement about the harness, not about the
  # product. Expect exits 0 whether or not the key landed.
  if printf '%s\n' "$PUSH_KEY_LOG" | grep -q "credential-matching key installed"; then
    ok "push-key installed the credential-matching key (the product said so)"
  else
    bad "push-key did not install a credential-matching key"
    echo "      push-key transcript (password redacted):"
    printf '%s\n' "$PUSH_KEY_LOG" | head -20 | sed 's/^/        /'
  fi
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
# fingerprint' claim that no assertion ever produced.
#
# REM-005: it then spent its whole life un-runnable, behind
#
#     if "$CLI" --json gateway status | grep -q '"matching_key_present":true'
#
# `--json gateway status` emits the DOCTOR document — `overall`, `findings[]`,
# and a `service` object — and has never carried a `matching_key_present`
# field at all; the field lives on the control-channel status
# (gateway/src/control.rs). The grep could not match for two independent
# reasons (the field is absent, and the document is pretty-printed while the
# pattern has no space), so the else-branch fired on every run and reported a
# COVERAGE GAP blamed on a missing TTY.
#
# The first clean-runner CI execution showed the blame was wrong: the
# transcript reads "credential-matching key installed" every time. A gate that
# is always false does not protect an assertion, it deletes it — the same
# shape as the counted check that could never fail (ZFT-VAL-7), inverted.
#
# So there is no gate. These two assertions ARE the property, and they are the
# ground truth about whether the key is resident: with it, the known key
# resolves to a credential and the unknown one does not. If push-key ever
# breaks, the check above fails AND these fail, which is both correct and
# more informative than a skip.
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

step "22b. Repair: damage an OWNED resource and re-align the installation"
# `gateway repair` is `install(force=false)` underneath: re-copy this binary,
# rewrite the definition for this data directory, re-register, restart. It was
# the one supported lifecycle verb this script never exercised — doctor was
# called, but the repair it hints at was not.
#
# The damage is deliberately to a resource THIS RUN OWNS and created: the
# installed helper under $DIR/bin, which the ownership ledger already covers.
# Nothing outside the run's own namespace is touched.
INSTALLED_HELPER="$(find "$DIR/bin" -maxdepth 1 -name 'tethra-gateway-*' 2>/dev/null | head -1)"
if [ -z "$INSTALLED_HELPER" ]; then
  bad "no installed helper found under $DIR/bin to exercise repair against"
else
  rm -f "$INSTALLED_HELPER"
  [ ! -e "$INSTALLED_HELPER" ] && ok "the installed helper was removed (damage staged: $(basename "$INSTALLED_HELPER"))" \
    || bad "could not stage the damage"
  "$CLI" gateway repair --yes >/dev/null 2>&1 && ok "gateway repair completed" || bad "gateway repair failed"
  [ -x "$INSTALLED_HELPER" ] && ok "repair restored the installed helper binary" \
    || bad "repair did not restore the installed helper"
  # And the service must actually be serving again, not merely present.
  REPAIRED=""
  for i in $(seq 1 40); do
    REPAIRED="$("$CLI" --json gateway status 2>/dev/null | python3 -c 'import sys,json;d=json.load(sys.stdin);print("y" if d.get("gateway") else "")' 2>/dev/null)"
    [ -n "$REPAIRED" ] && break
    sleep 0.25
  done
  [ -n "$REPAIRED" ] && ok "the gateway is serving again after repair" || bad "no gateway after repair"
  # Repair must not have escaped this run's namespace.
  launchctl print "gui/$UID_N/$LEGACY_LABEL" >/dev/null 2>&1 \
    && bad "repair registered the PRODUCTION label" \
    || ok "repair did not touch the production label"
fi

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
# A validation script that cannot fail proves nothing.
#
# VAL-04: these controls used to RE-IMPLEMENT the comparison inline — they
# called `db`/`python3` directly and never `assert_db`/`assert_status`. So a
# neutered primitive (`assert_db(){ ok "$2"; }`) flipped every real assertion
# from FAIL to PASS while the control still reported PASS, and 8 of the checks
# in this file flow through those two primitives.
#
# A control that does not call the thing it certifies is certifying nothing.
# These now invoke the REAL primitives and capture what they actually did.

# Run a primitive with the tally detached, and record only whether it counted
# a pass. This is the whole trick: the primitive executes exactly as it does in
# production — same function, same body — but its verdict is OBSERVED instead
# of counted.
#
# The result is left in $PROBE_VERDICT rather than printed, and the primitive's
# own output is redirected to a file rather than captured. Both are deliberate:
# `v="$(probe_primitive …)"` would run the whole thing in a SUBSHELL, and a
# subshell's increments to `pass`/`fail` do not reach the parent — so every
# probe would read as `+0p/+0f` and every control would fail. (It did, on the
# first CI run that executed this: the fix for a control that never called its
# primitive must not itself be a control that never observes one.)
PROBE_VERDICT=""
PROBE_LOG="${TMPDIR:-/tmp}/tethra-gw-probe-$$.log"
probe_primitive() {   # probe_primitive <fn> <args...>  -> sets PROBE_VERDICT
  local before_pass=$pass before_fail=$fail
  "$@" >>"$PROBE_LOG" 2>&1
  local gained_pass=$((pass - before_pass)) gained_fail=$((fail - before_fail))
  pass=$before_pass
  fail=$before_fail
  if [ "$gained_pass" -eq 1 ] && [ "$gained_fail" -eq 0 ]; then
    PROBE_VERDICT="pass"
  elif [ "$gained_fail" -eq 1 ] && [ "$gained_pass" -eq 0 ]; then
    PROBE_VERDICT="fail"
  else
    PROBE_VERDICT="malformed(+${gained_pass}p/+${gained_fail}f)"
  fi
}

if db "SELECT 0" >/dev/null 2>&1; then
  NEG_DETAIL=""
  # assert_db must REJECT a query returning 0, one returning nothing, and one
  # that errors — and must ACCEPT a true one. All four through assert_db
  # itself, so neutering it breaks this control.
  probe_primitive assert_db "SELECT 0" "control: false query"
  [ "$PROBE_VERDICT" = "fail" ] || NEG_DETAIL="$NEG_DETAIL false-query:$PROBE_VERDICT"
  probe_primitive assert_db "SELECT 1 WHERE 0" "control: empty query"
  [ "$PROBE_VERDICT" = "fail" ] || NEG_DETAIL="$NEG_DETAIL empty-query:$PROBE_VERDICT"
  probe_primitive assert_db "SELECT FROM nowhere" "control: erroring query"
  [ "$PROBE_VERDICT" = "fail" ] || NEG_DETAIL="$NEG_DETAIL erroring-query:$PROBE_VERDICT"
  probe_primitive assert_db "SELECT 1" "control: true query"
  [ "$PROBE_VERDICT" = "pass" ] || NEG_DETAIL="$NEG_DETAIL true-query:$PROBE_VERDICT"
  if [ -z "$NEG_DETAIL" ]; then
    ok "assert_db itself rejects false, empty and erroring queries, and accepts a true one"
  else
    bad "assert_db did not behave as required ($NEG_DETAIL)"
  fi
else
  bad "negative control could not run (no readable database)"
fi

# assert_status must reject an absent gateway. Nothing is running at this
# point, so the REAL primitive must record a failure — and it is called here,
# rather than its python re-implemented inline as before.
probe_primitive assert_status 'True' "control: any status property, gateway stopped"
if [ "$PROBE_VERDICT" = "fail" ]; then
  ok "assert_status itself rejects a stopped gateway (an empty response is a failure)"
else
  bad "assert_status did not reject a stopped gateway (observed: $PROBE_VERDICT)"
fi
# ...and it must reject a FALSE property even when a gateway IS answering,
# which is the other half of "this primitive consults its argument".
probe_primitive assert_status 'False' "control: a property that is never true"
if [ "$PROBE_VERDICT" = "fail" ]; then
  ok "assert_status rejects a property that evaluates false"
else
  bad "assert_status accepted a property that is never true (observed: $PROBE_VERDICT)"
fi

step "31. Isolation invariant: the user's production service was never touched"
# RA-004 was a teardown that deleted the PRODUCTION LaunchAgent
# ($HOME/Library/LaunchAgents/dev.api-tracker.gateway.plist) — a live service
# holding the user's real vault — from the REFUSAL path. Preflight refuses to
# run at all when that agent is present, so both signatures below are normally
# the absent state; these assertions fail if this run created, replaced or
# registered the production identifiers at any point.
PROD_SIG_AFTER="$(prod_sig)"
if [ "$PROD_SIG_AFTER" = "$PROD_SIG_BEFORE" ]; then
  ok "the production plist is exactly as this run found it ($PROD_SIG_AFTER)"
else
  bad "the production plist CHANGED during this run ($PROD_SIG_BEFORE -> $PROD_SIG_AFTER)"
fi
if launchctl print "gui/$UID_N/$LEGACY_LABEL" >/dev/null 2>&1; then
  bad "gui/$UID_N/$LEGACY_LABEL is loaded; preflight refused to run beside one, so this run registered the production label"
else
  ok "the production label was never registered in gui/$UID_N by this run"
fi

echo
echo "=== PACKAGED MACOS RESULT: $pass passed, $fail failed ==="
# A run that asserted almost nothing must not read as success.
#
# VAL-05, AND WHAT IS AND IS NOT FIXED HERE
# -----------------------------------------
# This is a FLOOR, not an equality gate, and that distinction was being
# papered over: the floor was 32 while `SECURITY_AND_PRIVACY.md`,
# `KNOWN_LIMITATIONS.md` and `FINAL_REAUDIT_HANDOFF.md` all quoted "56 checks"
# as though it were a fixed property of this script. It is not. The count is
# machine-dependent by construction:
#
#   * step 9 emits one check or none, on `command -v node`;
#   * step 22b emits five or one, depending on whether an installed helper is
#     found to damage;
#   * the port re-check in step 26-27 is guarded by `[ -n "$PORT" ]` with no
#     else branch.
#
# So 24 checks could vanish with zero recorded failures and this script would
# still exit 0 — the exact weakness its sibling `tracking_validate_macos.sh`
# documents as fixed, using a declared group table, a fail-closed enumerator
# that reads the script itself, and a per-group equality gate.
#
# That apparatus has NOT been ported here yet. Porting it needs an enumerator
# proved against a real `--scope full` run, and this script cannot be executed
# on a developer machine (it installs a LaunchAgent, and `launchctl` addresses
# `gui/<uid>` regardless of `$HOME`). Landing an unverified equality gate would
# turn a soft weakness into a broken required job.
#
# What HAS changed: the floor is raised to a value that no longer admits a
# nearly-empty run, and every document that quoted 56 as fixed now states the
# real structure instead. The remaining work is recorded as VAL-05 in
# docs/activity-onboarding/audit/POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md and
# is explicitly handed to the next auditor rather than claimed as done.
MIN_CHECKS=45
if [ "$pass" -lt "$MIN_CHECKS" ]; then
  echo "FAIL: only $pass checks ran; at least $MIN_CHECKS are expected."
  echo "      A low count means checks were SKIPPED, not that all is well."
  exit 1
fi
echo "NOTE: this is a floor, not an equality gate. The total is machine-dependent"
echo "      (node present, repair staging, port re-check). Do not quote it as a"
echo "      fixed property of this script — see VAL-05."
[ "$fail" -eq 0 ]
