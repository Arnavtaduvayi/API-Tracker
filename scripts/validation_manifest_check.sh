#!/usr/bin/env bash
# The trusted manifest must describe the harnesses that actually exist.
#
# `scripts/validation_manifest.json` is what `ci_assert_service_results.py`
# believes a run must contain, and it is deliberately NOT read from the results
# file (that was `VAL-01`). But a manifest that has drifted away from the
# harness is its own hazard: it would either demand checks nobody runs, or —
# worse — bless a smaller suite than the one the harness declares.
#
# So the numbers live in three independent places and all three must agree:
#
#   1. `group_size()` / `scope_groups()` in tracking_validate_macos.sh — the
#      harness's own declaration;
#   2. `enumerate_checks()` in the same file, which re-reads the script and
#      counts the call sites a scope+mode can actually execute (the harness
#      proves 1 against 2 itself, before any check runs); and
#   3. this manifest, which is what CI enforces.
#
# This script proves 3 against 1. A single edit cannot move all three quietly.
#
# `VAL-05-R` added a fourth statement, and it is about IDENTITY rather than
# arithmetic: the manifest now carries the EXACT SET of checks each scope runs,
# named by the static prefix of each label, and `gen_validation_manifest.py`
# re-derives that set from the harness SOURCES. The first section below runs it
# in `--check` mode, which is the assertion that makes drift impossible rather
# than merely detectable: a check added, removed, renamed or re-grouped without
# regenerating the manifest fails here, naming the exact check.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HARNESS="$HERE/tracking_validate_macos.sh"
GATEWAY="$HERE/gateway_validate_macos.sh"
MANIFEST="$HERE/validation_manifest.json"
GENERATOR="$HERE/gen_validation_manifest.py"
pass=0
fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }

echo "=== the trusted manifest must match the harnesses it describes ==="
echo

echo "== 0. the manifest is EXACTLY what the generator produces from the sources =="
GEN_OUT="$(python3 "$GENERATOR" --check 2>&1)"
if [ $? -eq 0 ]; then
  ok "validation_manifest.json is in sync with the harness sources"
else
  bad "validation_manifest.json has DRIFTED from the harness sources"
  printf '%s\n' "$GEN_OUT" | sed 's/^/        /'
fi

# …and the generator must be capable of reporting drift at all. A --check that
# cannot fail is the same class of defect as a harness that cannot fail: it is
# reported here as a measured property rather than assumed. The mutation is a
# label edit in a COPY of the harness; nothing in the repository is touched.
DRIFT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tethra-manifest-drift.XXXXXX")"
cp "$MANIFEST" "$DRIFT_DIR/validation_manifest.json"
python3 - "$DRIFT_DIR/validation_manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
spec = m["scopes"]["full:service"]
spec["required_checks"][0]["label_prefixes"] = ["a check nobody ever wrote"]
json.dump(m, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
PY
if python3 - "$GENERATOR" "$DRIFT_DIR/validation_manifest.json" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("gen", sys.argv[1])
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)
gen.MANIFEST = sys.argv[2]
sys.exit(gen.main(["--check"]))
PY
then
  bad "the generator ACCEPTED a manifest whose first required check was renamed — --check cannot detect drift"
else
  ok "control: the generator REFUSES a manifest whose first required check was renamed"
fi
rm -rf "$DRIFT_DIR"

echo
echo "== 1. the manifest's counts match the harness's own group table =="

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

echo
echo "== 2. every required check is a real, reachable CALL SITE in its own scope =="
# The check this replaces was a whole-file substring test: it proved a prefix
# appeared SOMEWHERE in the harness — a prefix that existed only inside a
# comment satisfied it — and said nothing about the group or the scope. Each
# prefix is now matched against the enumerated call sites for that exact
# scope+mode, in that exact group, which is a far stronger statement and the
# one the validator actually relies on.
python3 - "$MANIFEST" "$HARNESS" "$GATEWAY" <<'PY'
import json, subprocess, sys

manifest, harness, gateway = sys.argv[1], sys.argv[2], sys.argv[3]
m = json.load(open(manifest))
flags = {"full:service": ["--require-service"], "full:foreground": ["--foreground"],
         "offline:none": [], "selfcheck:none": []}
bad = 0
checked = 0

for tuple_name in sorted(flags):
    spec = m["scopes"][tuple_name]
    scope = tuple_name.split(":")[0]
    out = subprocess.check_output(
        ["bash", harness, "--scope", scope] + flags[tuple_name] + ["--emit-check-sites"]
    ).decode("utf-8", "replace")
    sites = {}
    for row in out.split("\n"):
        if not row.strip():
            continue
        seq, group, raw = row.split("\t", 2)
        sites.setdefault(group, []).append(raw)
    for entry in spec["required_checks"]:
        checked += 1
        group = entry["group"]
        hit = False
        for raw in sites.get(group, []):
            for prefix in entry["label_prefixes"]:
                # The source writes a literal `$` as `\$`; the runtime label
                # contains the bare character. This is the smallest
                # normalisation that lets the two be compared.
                if prefix in raw.replace("\\$", "$"):
                    hit = True
        if not hit:
            print("  FAIL  %s/%s: %r is not a call site reachable in this scope"
                  % (tuple_name, group, entry["label_prefixes"][0]))
            bad += 1

# The gateway harness's required and optional sets must be disjoint, and its
# in-script REQUIRED_CHECKS constant must equal the manifest's expected_total.
gw = m["scopes"]["gateway:lifecycle"]
req = set()
for e in gw["required_checks"]:
    for p in e["label_prefixes"]:
        req.add(p)
opt = set()
for e in gw["optional_checks"]:
    for p in e["label_prefixes"]:
        opt.add(p)
checked += 1
if req & opt:
    print("  FAIL  gateway: a label is declared both required and optional: %r" % sorted(req & opt))
    bad += 1

declared = None
for line in open(gateway):
    if line.startswith("REQUIRED_CHECKS="):
        declared = int(line.split("=", 1)[1].strip())
checked += 1
if declared != gw["expected_total"]:
    print("  FAIL  gateway: REQUIRED_CHECKS=%r but the manifest declares %d"
          % (declared, gw["expected_total"]))
    bad += 1

print("  (%d manifest entries checked against the enumerated call sites)" % checked)
sys.exit(1 if bad else 0)
PY
if [ $? -eq 0 ]; then
  ok "every required check named in the manifest is a reachable call site in its own scope"
else
  bad "a required check named in the manifest is not a reachable call site in its scope"
fi

echo
echo "== 3. no scope may be bound by counts alone (VAL-05-R) =="
# The defect itself, as a structural assertion: `required_checks: {}` for three
# of four scopes is what let a renamed check through. A scope that declares a
# group must name that group's checks.
python3 - "$MANIFEST" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
bad = 0
for name in sorted(m["scopes"]):
    spec = m["scopes"][name]
    entries = spec.get("required_checks")
    if not isinstance(entries, list) or not entries:
        print("  FAIL  %s declares no required-check set" % name)
        bad += 1
        continue
    if len(entries) != spec["expected_total"]:
        print("  FAIL  %s names %d checks but declares expected_total %d"
              % (name, len(entries), spec["expected_total"]))
        bad += 1
    named = {}
    for e in entries:
        named[e["group"]] = named.get(e["group"], 0) + 1
    for g, n in sorted((spec.get("groups") or {}).items()):
        if named.get(g) != n:
            print("  FAIL  %s/%s: %d checks named, %d declared" % (name, g, named.get(g, 0), n))
            bad += 1
    seen = set()
    for e in entries + (spec.get("optional_checks") or []):
        for p in e["label_prefixes"]:
            if len(p) < m["min_label_prefix"]:
                print("  FAIL  %s: label prefix %r is shorter than the declared minimum %d"
                      % (name, p, m["min_label_prefix"]))
                bad += 1
            if p in seen:
                print("  FAIL  %s: label prefix %r is declared twice" % (name, p))
                bad += 1
            seen.add(p)
sys.exit(1 if bad else 0)
PY
if [ $? -eq 0 ]; then
  ok "every scope names its full check set, per group, with no duplicate or degenerate prefix"
else
  bad "a scope is bound by counts alone, or carries a duplicate/degenerate label prefix"
fi

echo
echo "=== MANIFEST CHECK RESULT: $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
