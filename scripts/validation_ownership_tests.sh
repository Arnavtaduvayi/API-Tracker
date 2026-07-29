#!/usr/bin/env bash
# Ownership tests for scripts/tracking_validate_macos.sh (`VAL-02`).
#
# The harness's teardown does two irreversible things — `launchctl bootout` on
# a label and `rm -f` on a plist — and BOTH are bounded entirely by the
# ownership ledger. Getting that boundary wrong is not a reporting bug; it is
# `RA-004`, where a refusal path deleted the user's live production
# LaunchAgent.
#
# At the audited head the boundary was derived from a filename glob. The
# expression that was supposed to ask the PRODUCT what it had installed —
#
#     sed -n 's/.*"definition_path":"\([^"]*\)".*/\1/p'
#
# — required no space after the colon, while the product renders with
# `to_string_pretty`, which emits one. It had therefore never matched a byte
# on any run, and every run silently fell through to
# `ls "$LA_DIR/dev.api-tracker.gateway".*.plist` — which matches a SECOND
# environment's live agent exactly as well as it matches this run's.
#
# Nothing tested any of this. Two comments in the harness cited
# `crates/tracking/tests/validation_script_safety.rs` and
# `tests/service_namespace_scripts.rs` as the coverage; neither file has ever
# existed in this repository. The only scope that exercises the ownership path
# end-to-end is `--scope full --mode service`, which cannot be run on a
# developer machine beside a live production gateway — so the logic was
# reachable only from the one path nobody can run locally.
#
# These tests drive the real primitives through the harness's library mode
# (TETHRA_VALIDATE_LIB_ONLY=1), against a fake $HOME.
#
# NO REAL launchctl IS EVER INVOKED (`NEW-17`). The previous version of this
# header claimed that outright and was wrong: section 4 reached
# `launchctl bootout gui/<uid>/dev.api-tracker.gateway.ours00000000` against
# the operator's LIVE session, and was inert only because that label happened
# not to exist. Two independent mechanisms make the claim true now:
#
#   1. both harnesses route every launchd interaction through `$LAUNCHCTL`,
#      and this file exports it — before sourcing, because the harness binds it
#      at load — to `$WORLD/bin/fake-launchctl`, a stub that RECORDS what it
#      was asked to do and performs nothing. `print` answers out of a fixture
#      directory of `.spec` files this file writes, so every launchd state can
#      be simulated;
#   2. a shell FUNCTION named `launchctl` is defined below as a breach
#      detector. A bash function beats a PATH lookup for an unqualified
#      command, so any call site that escaped the `$LAUNCHCTL` seam is caught,
#      logged and turned into a hard failure instead of a real invocation.
#      `$BREACH_LOG` being empty is itself an assertion.
#
# Section 6 is `NEW-03`: the bootout guard was `$HOME`-keyed while `bootout`
# addresses `gui/<uid>`, which no HOME redirection isolates, so when the plist
# was absent the guard was skipped entirely and an unproven job was booted out.
# Because `gateway uninstall` deletes the plist in cleanup step 2, absent was
# the NORMAL state: the proof had never once evaluated on a real run.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="$HERE/tracking_validate_macos.sh"
pass=0
fail=0

ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }
chk() { if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; fi; }

echo "=== ownership tests for tracking_validate_macos.sh ==="
echo

# A throwaway world: fake HOME, fake data dir, fake LaunchAgents.
WORLD="$(mktemp -d "${TMPDIR:-/tmp}/tethra-ownership-tests.XXXXXX")"
export HOME="$WORLD/home"
mkdir -p "$HOME/Library/LaunchAgents"

# The harness derives everything from these; set them the way a real run does.
export TETHRA_DIR="/tmp/tethra-track-val-$$"
mkdir -p "$TETHRA_DIR"

# `NEW-19`: the EXIT trap used to remove only $WORLD, so every run of these
# "safe" tests left a /tmp/tethra-track-val-$$ directory behind — and
# ci_service_preconditions.sh FAILS on exactly that glob, so running this file
# locally poisoned the precondition for the real service scope. Ten such
# leftovers were found on the audited machine. Both are removed now.
trap 'rm -rf "$WORLD" "$TETHRA_DIR"' EXIT

# --- the launchctl seam (`NEW-17`) ------------------------------------------
# Exported BEFORE sourcing, because the harness binds LAUNCHCTL at load time.
export LAUNCHCTL_LOG="$WORLD/launchctl.log"
export BREACH_LOG="$WORLD/breach.log"
export FAKE_DOMAIN="$WORLD/domain"
mkdir -p "$WORLD/bin" "$FAKE_DOMAIN"
: > "$LAUNCHCTL_LOG"
: > "$BREACH_LOG"
cat > "$WORLD/bin/fake-launchctl" <<'STUB'
#!/bin/sh
# Records intent; performs nothing. `print` answers out of a fixture domain so
# the ownership proof under test has a launchd record to read — which is the
# whole point of NEW-03: the proof must come from the domain the action
# addresses, not from $HOME.
printf '%s\n' "$*" >> "$LAUNCHCTL_LOG"
case "$1" in
  print)
    spec="$FAKE_DOMAIN/${2##*/}.spec"
    [ -f "$spec" ] || exit 1          # launchd's "Could not find service"
    cat "$spec"; exit 0 ;;
  list) exit 0 ;;
  *)    exit 0 ;;                     # bootout/bootstrap/…: logged only
esac
STUB
chmod +x "$WORLD/bin/fake-launchctl"
export LAUNCHCTL="$WORLD/bin/fake-launchctl"

# The breach detector. Any call site that still names `launchctl` directly
# lands here instead of on the operator's live session.
launchctl() { printf 'REAL launchctl reached: %s\n' "$*" >> "$BREACH_LOG"; return 1; }

# Load the primitives without running anything.
# shellcheck disable=SC1090
TETHRA_VALIDATE_LIB_ONLY=1 . "$HARNESS" --scope selfcheck >/dev/null 2>&1

if ! command -v plist_is_ours >/dev/null 2>&1 && ! type plist_is_ours >/dev/null 2>&1; then
  echo "FATAL: the harness did not expose its ownership primitives in library mode."
  exit 1
fi

LA="$HOME/Library/LaunchAgents"
LEDGER="$WORLD/ledger.tsv"
: > "$LEDGER"

# A plist that proves it is ours: it declares our label AND points at $DIR.
write_plist() {   # write_plist <path> <label> <datadir>
  cat > "$1" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>$2</string>
  <key>ProgramArguments</key><array><string>$3/bin/tethra</string></array>
  <key>EnvironmentVariables</key><dict><key>TETHRA_DIR</key><string>$3</string></dict>
</dict></plist>
PLIST
}

OURS_LABEL="dev.api-tracker.gateway.ours00000000"
THEIRS_LABEL="dev.api-tracker.gateway.theirs000000"
OURS="$LA/$OURS_LABEL.plist"
THEIRS="$LA/$THEIRS_LABEL.plist"

write_plist "$OURS"   "$OURS_LABEL"   "$DIR"
write_plist "$THEIRS" "$THEIRS_LABEL" "/tmp/tethra-track-val-SOMEONE-ELSE"
THEIRS_SUM_BEFORE="$(shasum -a 256 "$THEIRS" | awk '{print $1}')"

# ---------------------------------------------------------------------------
echo "== 1. the proof term, not the name =="

plist_is_ours "$OURS" "$OURS_LABEL"
chk $? "a plist declaring our label and our data directory proves ours"

plist_is_ours "$THEIRS" "$THEIRS_LABEL"
[ $? -ne 0 ]
chk $? "a NAME-IDENTICAL plist from another environment does NOT prove ours"

plist_is_ours "$OURS" "$THEIRS_LABEL"
[ $? -ne 0 ]
chk $? "our own file does not prove ownership of a label we did not record"

plist_is_ours "$LA/does-not-exist.plist" "$OURS_LABEL"
[ $? -ne 0 ]
chk $? "a missing definition never proves ownership"

# ---------------------------------------------------------------------------
echo
echo "== 2. the ledger is the only source of authority =="

ledger_add plist "$OURS" "$OURS_LABEL"
ledger_add label "$OURS_LABEL"

[ "$(ledger_values label | tr -d '\t')" = "$OURS_LABEL" ]
chk $? "a recorded label reads back exactly"

ledger_values plist | grep -qF "$THEIRS"
[ $? -ne 0 ]
chk $? "the other environment's plist is NOT in this run's ledger"

# The defect itself: the glob would have adopted BOTH files.
GLOBBED="$(ls -1 "$LA/dev.api-tracker.gateway".*.plist 2>/dev/null | wc -l | tr -d ' ')"
[ "$GLOBBED" = "2" ]
chk $? "control: the filename glob the audited head fell back to matches BOTH ($GLOBBED files)"

LEDGERED="$(ledger_values plist | grep -c . | tr -d ' ')"
[ "$LEDGERED" = "1" ]
chk $? "while the ledger holds exactly the one resource this run created"

# ---------------------------------------------------------------------------
echo
echo "== 3. the dead extractor is caught =="

# The exact expression from the audited head, against the exact shape the
# product emits. This is the one-character class of defect the audit named,
# pinned so it cannot come back unnoticed.
PRETTY='{
  "service_name": "dev.api-tracker.gateway.abc123",
  "definition_path": "/Users/x/Library/LaunchAgents/dev.api-tracker.gateway.abc123.plist"
}'
OLD_SED="$(printf '%s' "$PRETTY" | sed -n 's/.*"definition_path":"\([^"]*\)".*/\1/p')"
[ -z "$OLD_SED" ]
chk $? "control: the audited head's sed extracts NOTHING from pretty-printed JSON"

NEW_PARSE="$(printf '%s' "$PRETTY" | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
sys.stdout.write(d.get("definition_path", ""))
')"
[ "$NEW_PARSE" = "/Users/x/Library/LaunchAgents/dev.api-tracker.gateway.abc123.plist" ]
chk $? "while exact JSON parsing extracts the path the product actually reported"

# And it must not be fooled by a value that merely mentions the key.
TRICKY='{"notes": "definition_path: /tmp/decoy.plist", "definition_path": "/real/path.plist"}'
TRICKY_OUT="$(printf '%s' "$TRICKY" | python3 -c '
import sys, json
sys.stdout.write(json.loads(sys.stdin.read()).get("definition_path",""))
')"
[ "$TRICKY_OUT" = "/real/path.plist" ]
chk $? "a decoy inside another field cannot displace the real value"

# ---------------------------------------------------------------------------
echo
echo "== 3b. the harness asks the product, and has no name-pattern fallback =="

# Drive `product_status_field` against a stub product that renders exactly the
# way the real one does. This is the function whose predecessor never matched.
STUB="$WORLD/stub-helper"
cat > "$STUB" <<'STUBEOF'
#!/usr/bin/env bash
cat <<'JSON'
{
  "service_name": "dev.api-tracker.gateway.stub00000000",
  "definition_path": "/tmp/stub/dev.api-tracker.gateway.stub00000000.plist",
  "installed": true
}
JSON
STUBEOF
chmod +x "$STUB"
HELPER="$STUB"

[ "$(product_status_field definition_path)" = "/tmp/stub/dev.api-tracker.gateway.stub00000000.plist" ]
chk $? "product_status_field reads definition_path from PRETTY-PRINTED product output"

[ "$(product_status_field service_name)" = "dev.api-tracker.gateway.stub00000000" ]
chk $? "…and service_name, which is the label cleanup proves against"

# Absent / unparseable / empty output must FAIL, never yield a guess.
HELPER="/usr/bin/false"
product_status_field definition_path >/dev/null 2>&1
[ $? -ne 0 ]
chk $? "a product that cannot answer yields a failure, never a fallback value"

cat > "$STUB" <<'STUBEOF'
#!/usr/bin/env bash
echo "not json at all"
STUBEOF
HELPER="$STUB"
product_status_field definition_path >/dev/null 2>&1
[ $? -ne 0 ]
chk $? "unparseable output yields a failure, never a fallback value"

cat > "$STUB" <<'STUBEOF'
#!/usr/bin/env bash
echo '{"service_name": "x", "definition_path": ""}'
STUBEOF
HELPER="$STUB"
product_status_field definition_path >/dev/null 2>&1
[ $? -ne 0 ]
chk $? "an EMPTY field is an absent answer, not a usable one"

# Structural: the ownership path must contain no filename-pattern fallback at
# all. This is what makes reintroducing the glob a test failure rather than an
# invisible regression — the resolution path itself cannot be exercised
# without a real service install, which no developer machine may perform.
#
# Comment lines are stripped first, deliberately: the harness *documents* both
# defects verbatim so a reader can see what changed, and the point here is
# that neither survives as executable code.
harness_code() { grep -vE '^[[:space:]]*#' "$HARNESS"; }

harness_code | grep -qE 'ls .*LEGACY_LABEL"?\.\*\.plist'
[ $? -ne 0 ]
chk $? "the harness contains NO \$LEGACY_LABEL.*.plist glob (ownership is never a name pattern)"

harness_code | grep -qE 'definition_path\\?":\\?\\?"'
[ $? -ne 0 ]
chk $? "and no regex that assumes the product renders JSON without a space"

grep -q 'product_status_field definition_path' "$HARNESS"
chk $? "the service path resolves its plist by asking the product"

grep -q 'product_status_field service_name' "$HARNESS"
chk $? "and resolves its label the same way"

# ---------------------------------------------------------------------------
echo
echo "== 4. cleanup acts only on what it can prove =="

# Cleanup needs these; they are set by a real run's preflight.
SERVE_PID=""
MODE="foreground"          # keeps `gateway uninstall` out of a unit test
PROD_SIG_BEFORE="$(prod_sig)"

cleanup >/dev/null 2>&1

[ ! -e "$OURS" ]
chk $? "the resource this run recorded is removed"

[ -e "$THEIRS" ]
chk $? "the name-identical resource this run did NOT record still exists"

[ "$(shasum -a 256 "$THEIRS" 2>/dev/null | awk '{print $1}')" = "$THEIRS_SUM_BEFORE" ]
chk $? "and it is byte-identical to how cleanup found it"

# ---------------------------------------------------------------------------
echo
echo "== 5. a ledger that cannot be trusted removes nothing =="

restore_world() {
  write_plist "$OURS"   "$OURS_LABEL"   "$DIR"
  write_plist "$THEIRS" "$THEIRS_LABEL" "/tmp/tethra-track-val-SOMEONE-ELSE"
}

# 5a. EMPTY ledger: must not fall back to a glob and sweep the directory.
restore_world
: > "$LEDGER"
cleanup >/dev/null 2>&1
[ -e "$OURS" ] && [ -e "$THEIRS" ]
chk $? "an empty ledger removes NOTHING — it can never widen into a glob"

# 5b. MISSING ledger file: the parser must fail closed, not error into a sweep.
restore_world
rm -f "$LEDGER"
cleanup >/dev/null 2>&1
[ -e "$OURS" ] && [ -e "$THEIRS" ]
chk $? "a missing ledger removes NOTHING (the parser fails closed)"
: > "$LEDGER"

# 5c. CORRUPT ledger: truncated rows, no tabs, binary noise.
restore_world
printf 'plist\nlabel\n\x00\x01garbage\nplist\t\n' > "$LEDGER"
cleanup >/dev/null 2>&1
[ -e "$OURS" ] && [ -e "$THEIRS" ]
chk $? "a corrupt ledger removes NOTHING"

# 5d. FORGED ledger aimed at the production resources.
restore_world
PROD_LABEL="dev.api-tracker.gateway"
PROD_TARGET="$LA/$PROD_LABEL.plist"
write_plist "$PROD_TARGET" "$PROD_LABEL" "$DIR"   # even made to LOOK like ours
PROD_SUM="$(shasum -a 256 "$PROD_TARGET" | awk '{print $1}')"
{
  printf 'plist\t%s\t%s\n' "$PROD_TARGET" "$PROD_LABEL"
  printf 'label\t%s\t\n'   "$PROD_LABEL"
  printf 'dir\t%s\t\n'     "$HOME"
  printf 'dir\t%s\t\n'     "/"
} > "$LEDGER"
cleanup >/dev/null 2>&1

[ -e "$PROD_TARGET" ] && [ "$(shasum -a 256 "$PROD_TARGET" | awk '{print $1}')" = "$PROD_SUM" ]
chk $? "a forged ledger cannot make cleanup delete the PRODUCTION definition"

[ -d "$HOME" ]
chk $? "a forged ledger cannot make cleanup remove \$HOME"

[ -d "/" ]
chk $? "a forged ledger cannot make cleanup remove /"

# ---------------------------------------------------------------------------
echo
echo "== 6. a launchd job is booted out only when ownership is PROVEN (NEW-03) =="
#
# The audited guard was
#
#     if [ -e "$LA_DIR/$value.plist" ] && ! plist_is_ours ...; then continue; fi
#     launchctl bootout "gui/$UID_N/$value"
#
# `$LA_DIR` is `$HOME`-keyed. `bootout` addresses `gui/<uid>`, which no HOME
# redirection isolates. So when the plist was absent the `&&` short-circuited
# the ENTIRE proof — including plist_is_ours — while the action still landed on
# the operator's real session. And absent is the normal state: cleanup step 2
# runs `gateway uninstall`, which deletes the plist before step 3 reads it.
#
# Every case below asserts on what the harness WOULD have invoked, never on a
# real domain. The stub's log is the evidence.

OURS12="dev.api-tracker.gateway.0123456789ab"
THEIRS12="dev.api-tracker.gateway.aaaaaaaaaaaa"

# A launchd job spec in the shape `launchctl print` emits.
write_spec() {   # write_spec <label> <data-dir>
  cat > "$FAKE_DOMAIN/$1.spec" <<SPEC
gui/$UID_N/$1 = {
	active count = 1
	path = $LA/$1.plist
	type = LaunchAgent
	state = running

	program = $2/bin/tethra-gateway-0.1.0
	arguments = {
		$2/bin/tethra-gateway-0.1.0
		gateway
		serve
		--service
		--data-dir
		$2
	}

	domain = gui/$UID_N
}
SPEC
}

# Run cleanup with a freshly-written ledger and a fresh launchctl log.
run_cleanup() {   # run_cleanup <ledger-contents-writer>
  : > "$LAUNCHCTL_LOG"
  CLEANUP_REFUSALS=0
  cleanup >"$WORLD/cleanup.out" 2>&1
}
verbs()    { cut -d' ' -f1 "$LAUNCHCTL_LOG" | sort | uniq -c | tr -s ' ' | tr '\n' ';'; }
bootouts() { grep -c '^bootout ' "$LAUNCHCTL_LOG" 2>/dev/null | tr -d ' '; }

SERVE_PID=""
MODE="foreground"          # keeps `gateway uninstall` out of a unit test

# --- T1: owned loaded job, plist PRESENT -----------------------------------
rm -f "$FAKE_DOMAIN"/*.spec
write_plist "$LA/$OURS12.plist" "$OURS12" "$DIR"
write_spec "$OURS12" "$DIR"
printf 'label\t%s\t%s\n' "$OURS12" "$DIR" > "$LEDGER"
run_cleanup
[ "$(bootouts)" = "1" ] && grep -q "^bootout gui/$UID_N/$OURS12$" "$LAUNCHCTL_LOG"
chk $? "T1 an owned, loaded job with its plist PRESENT is booted out (exactly once)"

# --- T2: owned loaded job, plist REMOVED (the real post-uninstall state) ----
rm -f "$LA/$OURS12.plist"
write_spec "$OURS12" "$DIR"
printf 'label\t%s\t%s\n' "$OURS12" "$DIR" > "$LEDGER"
run_cleanup
[ "$(bootouts)" = "1" ] && grep -q "^bootout gui/$UID_N/$OURS12$" "$LAUNCHCTL_LOG"
chk $? "T2 …and STILL booted out when the plist is gone — the legitimate path survives"

grep -q 'REFUSING' "$WORLD/cleanup.out"
[ $? -ne 0 ]
chk $? "T2b …with no refusal reported for a job it could prove"

# --- T3: FOREIGN loaded job with a matching-LOOKING label ------------------
# This is the finding. dev.api-tracker.gateway.aaaaaaaaaaaa is well-formed, is
# in the namespaced family, and has no plist under this $HOME — precisely the
# state of the six orphaned jobs the audit found live in gui/501.
rm -f "$FAKE_DOMAIN"/*.spec "$LA/$OURS12.plist"
write_spec "$THEIRS12" "/tmp/tethra-track-val-SOMEONE-ELSE"
SPEC_SUM_BEFORE="$(shasum -a 256 "$FAKE_DOMAIN/$THEIRS12.spec" | awk '{print $1}')"
printf 'label\t%s\t%s\n' "$THEIRS12" "$DIR" > "$LEDGER"
run_cleanup
[ "$(bootouts)" = "0" ]
chk $? "T3 a FOREIGN loaded job with a matching-looking label is NOT booted out"

grep -q "REFUSING to boot out gui/$UID_N/$THEIRS12" "$WORLD/cleanup.out"
chk $? "T3b …and the refusal names the label and says the job is left registered"

[ "$CLEANUP_REFUSALS" -eq 1 ]
chk $? "T3c …and is counted, so the run cannot report a clean teardown"

# --- T3d: the ledger's own proof term is load-bearing on its own ------------
# Spec says $DIR (so launchd's record would agree) but the ledger row carries
# no data directory — the OLD ledger shape, where a `label` row recorded only
# that a label was seen.
rm -f "$FAKE_DOMAIN"/*.spec
write_spec "$THEIRS12" "$DIR"
printf 'label\t%s\t\n' "$THEIRS12" > "$LEDGER"
run_cleanup
[ "$(bootouts)" = "0" ]
chk $? "T3d a ledger row with no recorded data directory cannot authorise a bootout"

# --- T3e: launchd's own record is load-bearing on its own ------------------
# Ledger row forged to claim $DIR; launchd says otherwise.
rm -f "$FAKE_DOMAIN"/*.spec
write_spec "$THEIRS12" "/tmp/tethra-track-val-SOMEONE-ELSE"
printf 'label\t%s\t%s\n' "$THEIRS12" "$DIR" > "$LEDGER"
run_cleanup
[ "$(bootouts)" = "0" ]
chk $? "T3e a forged ledger row cannot outvote launchd's own record of the job"

# --- T3f: a mangled `launchctl print` must fail CLOSED ---------------------
rm -f "$FAKE_DOMAIN"/*.spec
printf 'gui/%s/%s = {\n  some unversioned future format\n}\n' "$UID_N" "$OURS12" \
  > "$FAKE_DOMAIN/$OURS12.spec"
printf 'label\t%s\t%s\n' "$OURS12" "$DIR" > "$LEDGER"
run_cleanup
[ "$(bootouts)" = "0" ]
chk $? "T3f print output this parser cannot read refuses, it does not fall through"

# --- T4: STALE ledger — the job is no longer registered --------------------
rm -f "$FAKE_DOMAIN"/*.spec
printf 'label\t%s\t%s\n' "$OURS12" "$DIR" > "$LEDGER"
run_cleanup
[ "$(bootouts)" = "0" ]
chk $? "T4 a stale ledger naming an unregistered job issues no bootout"

grep -q "is not registered; nothing to boot out" "$WORLD/cleanup.out"
chk $? "T4b …and says so, rather than claiming to have booted something out"

[ "$CLEANUP_REFUSALS" -eq 0 ]
chk $? "T4c …and is NOT counted as a refusal — a no-op is not a failure"

# --- T5: CORRUPT ledger ----------------------------------------------------
printf 'label\n\x00\x01garbage\nlabel\t\n' > "$LEDGER"
run_cleanup
[ ! -s "$LAUNCHCTL_LOG" ]
chk $? "T5 a corrupt ledger produces NO launchctl invocation of any kind"

# --- T6: missing plist AND missing ledger ----------------------------------
rm -f "$LEDGER" "$LA"/*.plist "$FAKE_DOMAIN"/*.spec
: > "$LAUNCHCTL_LOG"
CLEANUP_REFUSALS=0
cleanup >"$WORLD/cleanup.out" 2>&1
CLEANUP_RC=$?
[ ! -s "$LAUNCHCTL_LOG" ] && [ "$CLEANUP_RC" -eq 0 ]
chk $? "T6 no plist and no ledger: no launchctl invocation, and cleanup exits cleanly"
: > "$LEDGER"

# --- T7: PID REUSE ---------------------------------------------------------
# The pid is recorded but now runs something else. proc_is_ours re-proves the
# EXECUTABLE, so nothing is signalled.
sleep 60 &
REUSED_PID=$!
printf 'pid\t%s\t/definitely/not/our/prefix\n' "$REUSED_PID" > "$LEDGER"
SERVE_PID="$REUSED_PID"
run_cleanup
SERVE_PID=""
kill -0 "$REUSED_PID" 2>/dev/null
chk $? "T7 a reused pid running a different executable is not signalled"
kill "$REUSED_PID" 2>/dev/null
wait "$REUSED_PID" 2>/dev/null

# --- T8: cleanup after a PARTIAL installation ------------------------------
# A label row exists but nothing was ever registered and no plist row was
# written — the state after `gateway install` failed halfway.
rm -f "$FAKE_DOMAIN"/*.spec
printf 'label\t%s\t%s\n' "$OURS12" "$DIR" > "$LEDGER"
run_cleanup
[ "$(bootouts)" = "0" ] && [ "$CLEANUP_REFUSALS" -eq 0 ]
chk $? "T8 cleanup after a partial installation issues no bootout and no spurious refusal"

# --- T9: the refusal path is SIDE-EFFECT-FREE ------------------------------
rm -f "$FAKE_DOMAIN"/*.spec
write_spec "$THEIRS12" "/tmp/tethra-track-val-SOMEONE-ELSE"
write_plist "$LA/$THEIRS12.plist" "$THEIRS12" "/tmp/tethra-track-val-SOMEONE-ELSE"
BEFORE_TREE="$(find "$LA" "$FAKE_DOMAIN" -type f 2>/dev/null | sort | xargs shasum -a 256 2>/dev/null)"
printf 'label\t%s\t%s\n' "$THEIRS12" "$DIR" > "$LEDGER"
run_cleanup
AFTER_TREE="$(find "$LA" "$FAKE_DOMAIN" -type f 2>/dev/null | sort | xargs shasum -a 256 2>/dev/null)"
[ "$BEFORE_TREE" = "$AFTER_TREE" ]
chk $? "T9 the refusal path changes not one byte on disk"

! grep -qE '^(bootout|bootstrap|kickstart|enable|disable|load|unload|remove|kill|stop|start) ' "$LAUNCHCTL_LOG"
chk $? "T9b …and issues only read-only launchctl verbs"

[ "$(shasum -a 256 "$FAKE_DOMAIN/$THEIRS12.spec" | awk '{print $1}')" = "$SPEC_SUM_BEFORE" ]
chk $? "T9c …and the foreign job's own record is byte-identical"
rm -f "$LA/$THEIRS12.plist"

# --- T10: the PRODUCTION label is exempt, against a spec built to pass ------
# Every other term is engineered to succeed: the spec claims --data-dir $DIR
# and the ledger row agrees. Only the name skip stands between this and a
# bootout of the operator's live gateway.
rm -f "$FAKE_DOMAIN"/*.spec
write_spec "dev.api-tracker.gateway" "$DIR"
printf 'label\t%s\t%s\n' "dev.api-tracker.gateway" "$DIR" > "$LEDGER"
run_cleanup
[ ! -s "$LAUNCHCTL_LOG" ]
chk $? "T10 the PRODUCTION label is skipped before any launchctl call is made at all"

# --- structural: nothing may escape the $LAUNCHCTL seam --------------------
# Without this, a future call site would silently stop being covered by the
# stub and these tests would become vacuous — this repository's signature
# failure mode.
seam_escapes() {   # seam_escapes <file>
  grep -vE '^[[:space:]]*#' "$1" | grep -v 'LAUNCHCTL="\${LAUNCHCTL:-launchctl}"' \
    | grep -nE '(^|[^A-Za-z_$"/-])launchctl[[:space:]]'
}
seam_escapes "$HARNESS" >/dev/null 2>&1
[ $? -ne 0 ]
chk $? "no bare 'launchctl' call survives in tracking_validate_macos.sh"

seam_escapes "$HERE/gateway_validate_macos.sh" >/dev/null 2>&1
[ $? -ne 0 ]
chk $? "no bare 'launchctl' call survives in gateway_validate_macos.sh"

[ ! -s "$BREACH_LOG" ]
chk $? "and the breach detector was never reached: no REAL launchctl ran in this suite"

# --- MUTATION CONTROL ------------------------------------------------------
echo
echo "== 6b. mutation control: the ownership proof must be what refuses T3 =="
# Every PASS above is worth nothing unless REVERTING the fix flips a NAMED one.
# The guard is put back to the audited-head shape in a COPY of the harness and
# T3 is replayed against it; the mutant MUST issue the bootout.
MUTANT="$WORLD/mutant-new03.sh"
sed 's|    if ! job_is_ours "$value" "$extra"; then|    if [ -e "$LA_DIR/$value.plist" ] \&\& ! plist_is_ours "$LA_DIR/$value.plist" "$value"; then|' \
  "$HARNESS" > "$MUTANT"

if cmp -s "$MUTANT" "$HARNESS"; then
  bad "the NEW-03 mutation did not apply — the sed expression no longer matches the harness"
  echo "        Update it in the same commit that changed the guard; a mutation that does"
  echo "        not apply reports a green control for a test that was never run."
else
  MUT_LOG="$WORLD/mutant-launchctl.log"
  rm -f "$FAKE_DOMAIN"/*.spec
  write_spec "$THEIRS12" "/tmp/tethra-track-val-SOMEONE-ELSE"
  printf 'label\t%s\t%s\n' "$THEIRS12" "$DIR" > "$WORLD/mutant-ledger.tsv"
  : > "$MUT_LOG"
  env -u TETHRA_VALIDATE_LIB_ONLY \
      HOME="$HOME" TETHRA_DIR="$TETHRA_DIR" LAUNCHCTL="$LAUNCHCTL" \
      LAUNCHCTL_LOG="$MUT_LOG" FAKE_DOMAIN="$FAKE_DOMAIN" \
      bash -c '
        TETHRA_VALIDATE_LIB_ONLY=1 . "$1" --scope selfcheck >/dev/null 2>&1
        LEDGER="$2"
        SERVE_PID=""
        MODE="foreground"
        PROD_SIG_BEFORE="$(prod_sig)"
        cleanup >/dev/null 2>&1
      ' _ "$MUTANT" "$WORLD/mutant-ledger.tsv"

  if grep -q "^bootout gui/$UID_N/$THEIRS12$" "$MUT_LOG"; then
    ok "the audited-head guard DOES boot out the foreign job — T3 is not vacuous"
  else
    bad "the audited-head guard did NOT boot out the foreign job, so T3 proves nothing"
    echo "        The whole of section 6's evidence is void until this control passes."
    echo "        mutant launchctl log:"
    sed 's/^/          /' "$MUT_LOG"
  fi
fi

# Restore a quiet world for anything that runs after this section.
rm -f "$FAKE_DOMAIN"/*.spec
: > "$LEDGER"
: > "$LAUNCHCTL_LOG"

# ---------------------------------------------------------------------------
echo
echo "=== OWNERSHIP TEST RESULT: $pass passed, $fail failed ==="
# `NEW-18`: this was `MIN=29` against a run that produced exactly 29 — zero
# headroom, so an added assertion silently raised the true count above a floor
# nobody updated, and a REMOVED one could be masked by an added one. It is an
# equality against a declared inventory now: a different count means assertions
# were added or skipped, and both are things a reader of this number needs to
# know.
DECLARED_ASSERTIONS=53
if [ "$pass" -ne "$DECLARED_ASSERTIONS" ] && [ "$fail" -eq 0 ]; then
  echo "FAIL: $pass assertions ran; exactly $DECLARED_ASSERTIONS are declared."
  echo "      A DIFFERENT count means assertions were added or SKIPPED, not that all"
  echo "      is well. Update DECLARED_ASSERTIONS in the same commit that changes them."
  exit 1
fi
[ "$fail" -eq 0 ]
