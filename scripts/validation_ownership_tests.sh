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
# (TETHRA_VALIDATE_LIB_ONLY=1), against a fake $HOME. Nothing here starts a
# gateway, installs a service, or calls launchctl.

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
trap 'rm -rf "$WORLD"' EXIT
export HOME="$WORLD/home"
mkdir -p "$HOME/Library/LaunchAgents"

# The harness derives everything from these; set them the way a real run does.
export TETHRA_DIR="/tmp/tethra-track-val-$$"
mkdir -p "$TETHRA_DIR"

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
echo "=== OWNERSHIP TEST RESULT: $pass passed, $fail failed ==="
MIN=29
if [ "$pass" -lt "$MIN" ]; then
  echo "FAIL: only $pass assertions ran; at least $MIN are expected."
  echo "      A low count means assertions were SKIPPED, not that all is well."
  exit 1
fi
[ "$fail" -eq 0 ]
