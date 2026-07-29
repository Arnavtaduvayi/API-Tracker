#!/usr/bin/env bash
# Forgery tests for scripts/ci_assert_service_results.py (`VAL-01`).
#
# The gate whose stated purpose is "a green script exit is not the same
# statement as 'the service scope completed'" accepted a twelve-line results
# document declaring ZERO checks and printed
#
#     === SERVICE SCOPE COMPLETED: 0/0 checks passed in full:service ===
#
# with exit 0. It read `expected_total`, every `groups[].expected` and every
# check name FROM THE FILE IT WAS VALIDATING, so it proved only internal
# self-consistency — never that anything had run.
#
# The validator now takes its expectations from `validation_manifest.json` and
# from arguments the CALLER supplies. This file proves that: it builds ONE
# known-good result and then mutates it, one property at a time, and requires
# the validator to accept exactly the genuine one.
#
# The audit's own artifact is replayed verbatim as test 0, so the exact
# document that defeated the audited head can never quietly start passing
# again.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ASSERT="$HERE/ci_assert_service_results.py"
MANIFEST="$HERE/validation_manifest.json"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tethra-asserter-tests.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

COMMIT="0123456789abcdef0123456789abcdef01234567"
pass=0
fail=0

# Accepts / refuses, stated as the property under test.
accepts() {   # accepts <file> <label> [extra args...]
  local f="$1" label="$2"; shift 2
  if python3 "$ASSERT" "$f" --commit "$COMMIT" "$@" >/dev/null 2>&1; then
    echo "  PASS  $label"; pass=$((pass+1))
  else
    echo "  FAIL  $label (the validator REFUSED a genuine result)"; fail=$((fail+1))
  fi
}
refuses() {   # refuses <file> <label> [extra args...]
  local f="$1" label="$2"; shift 2
  if python3 "$ASSERT" "$f" --commit "$COMMIT" "$@" >/dev/null 2>&1; then
    echo "  FAIL  $label (the validator ACCEPTED it)"; fail=$((fail+1))
  else
    echo "  PASS  $label"; pass=$((pass+1))
  fi
}

# Build a genuine full:service result FROM THE MANIFEST — the same shape the
# harness emits, with every declared group at its declared size and every
# required SERVICE check present under its real label.
build_good() {   # build_good <outfile>
  python3 - "$MANIFEST" "$1" "$COMMIT" <<'PY'
import json, sys
manifest, out, commit = sys.argv[1], sys.argv[2], sys.argv[3]
m = json.load(open(manifest))
spec = m["scopes"]["full:service"]
required = {k: v for k, v in (spec.get("required_checks") or {}).items() if not k.startswith("_")}
checks, groups = [], []
for name, size in spec["groups"].items():
    named = list(required.get(name, []))
    for i in range(size):
        if i < len(named):
            # Real labels interpolate; the suffix stands in for that tail.
            label = named[i] + " (measured)"
        else:
            label = "%s check %d" % (name, i + 1)
        checks.append({"group": name, "name": label, "result": "pass"})
    groups.append({"name": name, "expected": size, "executed": size, "passed": size, "failed": 0})
total = spec["expected_total"]
assert len(checks) == total, (len(checks), total)
json.dump({
    "schema": m["results_schema"],
    "scope": "full", "mode": "service", "verdict": "PASS",
    "expected_total": total, "executed_total": total,
    "passed": total, "failed": 0, "skipped": 0, "duplicate_names": 0,
    "app": "/tmp/x/Tethra.app", "data_dir": "/tmp/tethra-track-val-1",
    "service_plist": "/Users/x/Library/LaunchAgents/dev.api-tracker.gateway.abc123.plist",
    "service_label": "dev.api-tracker.gateway.abc123",
    "commit": commit,
    "service_created_by_this_run": True,
    "groups": groups, "checks": checks,
}, open(out, "w"), indent=2)
PY
}

# Copy the good file and apply one python mutation to it.
mutate() {   # mutate <name> <python-body-operating-on-`d`>
  local out="$WORK/$1.json"
  cp "$WORK/good.json" "$out"
  python3 - "$out" <<PY
import json, sys
p = sys.argv[1]
d = json.load(open(p))
$2
json.dump(d, open(p, "w"), indent=2)
PY
  printf '%s' "$out"
}

echo "=== forgery tests for ci_assert_service_results.py ==="
echo

build_good "$WORK/good.json"

echo "== 1. the genuine article is accepted =="
accepts "$WORK/good.json" "a complete, honest full:service result is ACCEPTED"

echo
echo "== 2. the audit's own forgery =="
cat > "$WORK/audit_forgery.json" <<'JSON'
{
  "schema": "tethra.validation.results/1",
  "scope": "full",
  "mode": "service",
  "verdict": "PASS",
  "passed": 0,
  "failed": 0,
  "skipped": 0,
  "executed_total": 0,
  "expected_total": 0,
  "service_label": "dev.api-tracker.gateway.deadbeef1234",
  "groups": [
    { "name": "SERVICE", "expected": 0, "executed": 0, "failed": 0 }
  ],
  "checks": [],
  "duplicate_names": 0
}
JSON
refuses "$WORK/audit_forgery.json" "the audit's 0/0 forgery is REFUSED (VAL-01 itself)"

echo
echo "== 3. the result file cannot define its own acceptance criteria =="
refuses "$(mutate false_count 'd["expected_total"] = d["executed_total"] = 1
d["passed"] = 1
d["checks"] = d["checks"][:1]
d["groups"] = [{"name": "SERVICE", "expected": 1, "executed": 1, "passed": 1, "failed": 0}]')" \
  "a one-check run that declares itself complete is REFUSED"

refuses "$(mutate inflated 'd["expected_total"] = 999')" \
  "a false expected count is REFUSED even when execution matches the manifest"

refuses "$(mutate shrunk_group 'd["groups"] = [g for g in d["groups"] if g["name"] != "SERVICE"] + [
    {"name": "SERVICE", "expected": 7, "executed": 7, "passed": 7, "failed": 0}]
d["checks"] = [c for c in d["checks"] if c["group"] != "SERVICE"][:56] + [
    c for c in d["checks"] if c["group"] == "SERVICE"][:7]
d["executed_total"] = d["expected_total"] = len(d["checks"])
d["passed"] = len(d["checks"])')" \
  "redefining the SERVICE group as smaller is REFUSED"

# THE SHARPEST ONE, and the reason the manifest exists at all.
#
# This document is entirely self-consistent: every count agrees with every
# other count, all nine required SERVICE checks are present under their real
# labels and passing, the provenance fact is true, the label is namespaced,
# the commit matches. The ONLY thing wrong with it is that it contains just
# the SERVICE group — 9 checks presented as the whole of full:service.
#
# Nothing inside the file can detect that. It is caught solely because the
# manifest says full:service is 63 checks across eleven groups. Restoring the
# audited head's trust boundary — reading `expected_total` and the group sizes
# from the results file — makes this forgery pass, which is what makes this
# test the mutation check for that boundary.
python3 - "$MANIFEST" "$WORK/service_only.json" "$COMMIT" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
spec = m["scopes"]["full:service"]
named = [k for k in (spec.get("required_checks") or {}) if not k.startswith("_")]
prefixes = spec["required_checks"]["SERVICE"]
checks = [{"group": "SERVICE", "name": p + " (measured)", "result": "pass"} for p in prefixes]
n = len(checks)
json.dump({
    "schema": m["results_schema"], "scope": "full", "mode": "service", "verdict": "PASS",
    "expected_total": n, "executed_total": n, "passed": n, "failed": 0,
    "skipped": 0, "duplicate_names": 0,
    "service_label": "dev.api-tracker.gateway.abc123",
    "commit": sys.argv[3], "service_created_by_this_run": True,
    "groups": [{"name": "SERVICE", "expected": n, "executed": n, "passed": n, "failed": 0}],
    "checks": checks,
}, open(sys.argv[2], "w"), indent=2)
PY
refuses "$WORK/service_only.json" \
  "a SELF-CONSISTENT result containing only the SERVICE group is REFUSED (the trust boundary)"

echo
echo "== 4. structural forgeries =="
refuses "$(mutate zero_checks 'd["checks"] = []')" \
  "an empty register is REFUSED"

refuses "$(mutate missing_required 'd["checks"] = [c for c in d["checks"]
    if not c["name"].startswith("launchd loaded the namespaced service gui/")]
d["checks"].append({"group": "SERVICE", "name": "SERVICE filler", "result": "pass"})')" \
  "removing one required check is REFUSED (count preserved)"

refuses "$(mutate duplicate 'svc = [c for c in d["checks"] if c["group"] == "SERVICE"]
d["checks"].remove(svc[-1])
d["checks"].append(dict(svc[0]))')" \
  "duplicating a check is REFUSED"

refuses "$(mutate skipped 'd["checks"][0]["result"] = "skip"')" \
  "marking a required check skipped is REFUSED"

refuses "$(mutate informational 'd["checks"][0]["result"] = "info"')" \
  "substituting an informational result for a required check is REFUSED"

refuses "$(mutate skipped_count 'd["skipped"] = 1')" \
  "a nonzero skipped count is REFUSED"

refuses "$(mutate unknown_name 'svc = [c for c in d["checks"] if c["group"] == "SERVICE"]
svc[0]["name"] = "an unrelated check nobody declared"')" \
  "an unknown check name in a required group is REFUSED"

refuses "$(mutate unknown_group 'd["groups"].append(
    {"name": "INVENTED", "expected": 1, "executed": 1, "passed": 1, "failed": 0})')" \
  "a group the manifest does not declare is REFUSED"

echo
echo "== 5. identity forgeries =="
refuses "$(mutate wrong_scope 'd["scope"] = "offline"')" \
  "a mismatched scope is REFUSED"

refuses "$(mutate wrong_mode 'd["mode"] = "foreground"')" \
  "a mismatched mode is REFUSED"

refuses "$(mutate wrong_commit 'd["commit"] = "ffffffffffffffffffffffffffffffffffffffff"')" \
  "evidence about a different commit is REFUSED"

refuses "$(mutate prod_label 'd["service_label"] = "dev.api-tracker.gateway"')" \
  "the PRODUCTION service label is REFUSED"

refuses "$(mutate empty_id 'd["service_label"] = "dev.api-tracker.gateway."')" \
  "a namespaced label with an empty installation id is REFUSED"

refuses "$(mutate no_label 'd["service_label"] = ""')" \
  "a service scope with no resolved label is REFUSED"

refuses "$(mutate foreign_label 'd["service_label"] = "com.example.something"')" \
  "a label outside the gateway namespace is REFUSED"

refuses "$(mutate wrong_schema 'd["schema"] = "tethra.validation.results/999"')" \
  "an unknown schema is REFUSED"

echo
echo "== 6. provenance =="
refuses "$(mutate preexisting 'd["service_created_by_this_run"] = False')" \
  "a run that did not create the service it observed is REFUSED"

refuses "$(mutate no_provenance 'del d["service_created_by_this_run"]')" \
  "a result that omits the provenance fact entirely is REFUSED"

echo
echo "== 7. an offline run cannot be filed as service evidence =="
python3 - "$MANIFEST" "$WORK/offline.json" "$COMMIT" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
spec = m["scopes"]["offline:none"]
checks, groups = [], []
for name, size in spec["groups"].items():
    for i in range(size):
        checks.append({"group": name, "name": "%s check %d" % (name, i + 1), "result": "pass"})
    groups.append({"name": name, "expected": size, "executed": size, "passed": size, "failed": 0})
t = spec["expected_total"]
json.dump({
    "schema": m["results_schema"], "scope": "offline", "mode": "none", "verdict": "PASS",
    "expected_total": t, "executed_total": t, "passed": t, "failed": 0,
    "skipped": 0, "duplicate_names": 0, "service_label": "", "commit": sys.argv[3],
    "service_created_by_this_run": False, "groups": groups, "checks": checks,
}, open(sys.argv[2], "w"), indent=2)
PY
accepts "$WORK/offline.json" "a genuine offline result is accepted AS AN OFFLINE RESULT" \
  --scope offline --mode none
refuses "$WORK/offline.json" "…and REFUSED when submitted as full:service"

# The same document relabelled — the "silent downgrade" this gate exists for.
cp "$WORK/offline.json" "$WORK/relabelled.json"
python3 - "$WORK/relabelled.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["scope"], d["mode"] = "full", "service"
d["service_label"] = "dev.api-tracker.gateway.abc123"
json.dump(d, open(sys.argv[1], "w"), indent=2)
PY
refuses "$WORK/relabelled.json" "an offline result RELABELLED as full:service is REFUSED"

echo
echo "== 8. malformed artifacts are failures, not absences =="
: > "$WORK/empty.json"
refuses "$WORK/empty.json" "an empty file is REFUSED"

head -c 120 "$WORK/good.json" > "$WORK/truncated.json"
refuses "$WORK/truncated.json" "a truncated file is REFUSED"

printf 'not json at all\n' > "$WORK/garbage.json"
refuses "$WORK/garbage.json" "a non-JSON file is REFUSED"

printf '[]\n' > "$WORK/array.json"
refuses "$WORK/array.json" "a JSON array instead of an object is REFUSED"

refuses "$WORK/does-not-exist.json" "a missing file is REFUSED"

echo
echo "== 9. the scope must be one the manifest knows =="
cp "$WORK/good.json" "$WORK/unknown_scope.json"
if python3 "$ASSERT" "$WORK/unknown_scope.json" --scope invented --mode nonsense \
     --commit "$COMMIT" >/dev/null 2>&1; then
  echo "  FAIL  a scope the manifest never declared was CERTIFIED"; fail=$((fail+1))
else
  echo "  PASS  a scope the manifest never declared cannot be certified"; pass=$((pass+1))
fi

echo
echo "=== ASSERTER FORGERY RESULT: $pass passed, $fail failed ==="
MIN=33
if [ "$pass" -lt "$MIN" ]; then
  echo "FAIL: only $pass assertions ran; at least $MIN are expected."
  echo "      A low count means assertions were SKIPPED, not that all is well."
  exit 1
fi
[ "$fail" -eq 0 ]
