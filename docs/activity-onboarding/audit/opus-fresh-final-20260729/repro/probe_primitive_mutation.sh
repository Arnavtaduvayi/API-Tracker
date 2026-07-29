#!/bin/bash
# VAL-04 mutation test, written independently for the fresh final audit.
#
# The handoff dares: "neuter assert_db and assert_status in a copy and confirm
# the controls fail. If they do not, VAL-04 is not fixed."
#
# This extracts the REAL primitive definitions from the real script (rather
# than re-implementing them) and drives the real negative-control block, first
# genuine, then with each primitive neutered.
#
# Touches no service, no launchd, no production gateway. Uses a throwaway
# sqlite database under /private/tmp only.
set -u
SRC=/Users/arnavtaduvayi/Documents/APItrack/audit-pr16-fresh-20260729/scripts/gateway_validate_macos.sh
WORK=$(mktemp -d "${TMPDIR:-/tmp}/gw-probe-mut.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

DIR="$WORK/data"
mkdir -p "$DIR"
sqlite3 "$DIR/vault.db" "CREATE TABLE t(x); INSERT INTO t VALUES(1);" || exit 1

# Extract the genuine primitive definitions verbatim from the audited script.
{
  sed -n '62,64p'   "$SRC"     # ok, bad, step
  sed -n '83,84p'   "$SRC"     # opt_ok, opt_bad
  sed -n '90,112p'  "$SRC"     # db, assert_db, assert_status
  sed -n '783,798p' "$SRC"     # PROBE_VERDICT, PROBE_LOG, probe_primitive
} > "$WORK/primitives.sh"

echo "extracted $(wc -l < "$WORK/primitives.sh") lines of genuine primitives"
echo ""

# The negative-control block, transcribed from steps 30 of the audited script.
cat > "$WORK/controls.sh" <<'CONTROLS'
NEG_DETAIL=""
probe_primitive assert_db "SELECT 0"             "control: false query"
[ "$PROBE_VERDICT" = "fail" ] || NEG_DETAIL="$NEG_DETAIL false-query:$PROBE_VERDICT"
probe_primitive assert_db "SELECT 1 WHERE 0"     "control: empty query"
[ "$PROBE_VERDICT" = "fail" ] || NEG_DETAIL="$NEG_DETAIL empty-query:$PROBE_VERDICT"
probe_primitive assert_db "SELECT FROM nowhere"  "control: erroring query"
[ "$PROBE_VERDICT" = "fail" ] || NEG_DETAIL="$NEG_DETAIL erroring-query:$PROBE_VERDICT"
probe_primitive assert_db "SELECT 1"             "control: true query"
[ "$PROBE_VERDICT" = "pass" ] || NEG_DETAIL="$NEG_DETAIL true-query:$PROBE_VERDICT"
if [ -z "$NEG_DETAIL" ]; then
  echo "CONTROL_RESULT=PASS"
else
  echo "CONTROL_RESULT=FAIL ($NEG_DETAIL)"
fi

# assert_status against a gateway that is not running (CLI absent here, which
# is exactly the "no output" case the primitive must treat as a failure).
probe_primitive assert_status 'True' "control: any status property, gateway stopped"
if [ "$PROBE_VERDICT" = "fail" ]; then
  echo "STATUS_CONTROL_RESULT=PASS"
else
  echo "STATUS_CONTROL_RESULT=FAIL (observed: $PROBE_VERDICT)"
fi
CONTROLS

driver() {  # driver <mutation-sed-expr-or-empty> <label>
  local mut="$1" label="$2"
  local p="$WORK/prim_$label.sh"
  cp "$WORK/primitives.sh" "$p"
  [ -n "$mut" ] && sed -i '' "$mut" "$p"
  {
    echo 'pass=0; fail=0; optional=0'
    echo "DIR='$DIR'"
    echo "CLI=/nonexistent/tethra"
    cat "$p"
    cat "$WORK/controls.sh"
  } > "$WORK/run_$label.sh"
  echo "--- $label ---"
  bash "$WORK/run_$label.sh" 2>&1 | grep -E 'CONTROL_RESULT|STATUS_CONTROL_RESULT'
  echo ""
}

echo "=== M0: GENUINE primitives (controls must report PASS) ==="
driver "" genuine

echo "=== M1: assert_db neutered to always ok()  (controls MUST report FAIL) ==="
driver 's|^assert_db() {|assert_db() { ok "$2"; return 0; }\nunused_assert_db() {|' m1

echo "=== M2: assert_db accepts ANY non-empty result (controls MUST report FAIL) ==="
driver 's|if \[ "\$got" = "1" \]|if [ -n "$got" ] \|\| [ -z "$got" ]|' m2

echo "=== M3: assert_status neutered to always ok() (status control MUST report FAIL) ==="
driver 's|^assert_status() {|assert_status() { ok "$2"; return 0; }\nunused_assert_status() {|' m3

echo "=== M4: probe_primitive runs the fn in a SUBSHELL (the corrected defect) ==="
driver 's|^  "\$@" >>"\$PROBE_LOG" 2>&1|  ( "$@" ) >>"$PROBE_LOG" 2>\&1|' m4
