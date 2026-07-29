#!/usr/bin/env bash
# The trusted manifest must describe the harness that actually exists.
#
# `scripts/validation_manifest.json` is what `ci_assert_service_results.py`
# believes a run must contain, and it is deliberately NOT read from the results
# file (that was `VAL-01`). But a manifest that has drifted away from the
# harness is its own hazard: it would either demand checks nobody runs, or —
# worse — bless a smaller suite than the one the harness declares.
#
# So the number lives in three independent places and all three must agree:
#
#   1. `group_size()` / `scope_groups()` in tracking_validate_macos.sh — the
#      harness's own declaration;
#   2. `enumerate_checks()` in the same file, which re-reads the script and
#      counts the call sites a scope+mode can actually execute (the harness
#      proves 1 against 2 itself, before any check runs); and
#   3. this manifest, which is what CI enforces.
#
# This script proves 3 against 1. A single edit cannot move all three quietly.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="$HERE/tracking_validate_macos.sh"
MANIFEST="$HERE/validation_manifest.json"
pass=0
fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }

echo "=== the trusted manifest must match the harness's own group table ==="
echo

# Load the harness's declarations without running it.
export TETHRA_VALIDATE_LIB_ONLY=1
export TETHRA_DIR="${TETHRA_DIR:-/tmp/tethra-manifest-check-$$}"
# shellcheck disable=SC1090
. "$HARNESS" --scope selfcheck >/dev/null 2>&1
unset TETHRA_VALIDATE_LIB_ONLY

for tuple in "full:service" "full:foreground" "offline:none" "selfcheck:none"; do
  harness_groups="$(scope_groups "$tuple")"
  harness_total="$(expected_total "$tuple")"

  manifest_total="$(python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
s = (m.get("scopes") or {}).get(sys.argv[2])
sys.stdout.write(str(s["expected_total"]) if s else "MISSING")
' "$MANIFEST" "$tuple")"

  if [ "$harness_total" = "$manifest_total" ]; then
    ok "$tuple: manifest total $manifest_total matches the harness ($harness_total)"
  else
    bad "$tuple: manifest says $manifest_total, the harness sums to $harness_total"
  fi

  # Group-by-group, both directions.
  manifest_groups="$(python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
s = (m.get("scopes") or {}).get(sys.argv[2]) or {}
sys.stdout.write(" ".join(sorted((s.get("groups") or {}).keys())))
' "$MANIFEST" "$tuple")"
  sorted_harness="$(printf '%s\n' $harness_groups | sort | tr '\n' ' ' | sed 's/ $//')"
  sorted_manifest="$(printf '%s\n' $manifest_groups | tr '\n' ' ' | sed 's/ $//')"
  if [ "$sorted_harness" = "$sorted_manifest" ]; then
    ok "$tuple: the same groups are declared on both sides"
  else
    bad "$tuple: groups differ — harness [$sorted_harness] vs manifest [$sorted_manifest]"
  fi

  for g in $harness_groups; do
    hs="$(group_size "$g")"
    ms="$(python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
s = (m.get("scopes") or {}).get(sys.argv[2]) or {}
sys.stdout.write(str((s.get("groups") or {}).get(sys.argv[3], "MISSING")))
' "$MANIFEST" "$tuple" "$g")"
    if [ "$hs" = "$ms" ]; then
      ok "$tuple/$g: $hs"
    else
      bad "$tuple/$g: manifest says $ms, the harness declares $hs"
    fi
  done
done

# The named SERVICE checks must exist as real call sites in the harness.
echo
echo "== every required check named in the manifest exists in the harness =="
python3 - "$MANIFEST" "$HARNESS" <<'PY'
import json, sys
manifest, harness = sys.argv[1], sys.argv[2]
m = json.load(open(manifest))
# The manifest holds the label as it appears AT RUNTIME. The source holds it as
# a bash double-quoted string, where a literal `$` is written `\$`. Dropping
# backslashes is the smallest normalisation that lets the two be compared
# without teaching this script to parse shell quoting.
src = open(harness).read().replace("\\$", "$")
bad = 0
for tuple_name, spec in (m.get("scopes") or {}).items():
    for group, prefixes in (spec.get("required_checks") or {}).items():
        if group.startswith("_"):
            continue
        for p in prefixes:
            # The manifest holds the STATIC prefix of a label whose tail may
            # interpolate. Requiring the prefix to appear verbatim in the
            # script is what ties the two together.
            if p in src:
                print("  PASS  %s/%s: %r is a real call site" % (tuple_name, group, p))
            else:
                print("  FAIL  %s/%s: %r appears nowhere in the harness" % (tuple_name, group, p))
                bad += 1
sys.exit(1 if bad else 0)
PY
if [ $? -eq 0 ]; then
  pass=$((pass+1))
else
  bad "a required check named in the manifest does not exist in the harness"
fi

echo
echo "=== MANIFEST CHECK RESULT: $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
