#!/usr/bin/env bash
# Forgery tests for scripts/ci_assert_service_results.py (`VAL-01`, `VAL-05-R`).
#
# The gate whose stated purpose is "a green script exit is not the same
# statement as 'the service scope completed'" accepted a twelve-line results
# document declaring ZERO checks and printed
#
#     === SERVICE SCOPE COMPLETED: 0/0 checks passed in full:service ===
#
# with exit 0. It read `expected_total`, every `groups[].expected` and every
# check name FROM THE FILE IT WAS VALIDATING, so it proved only internal
# self-consistency — never that anything had run. That is `VAL-01`.
#
# `VAL-05-R` is the sequel, and the reason section 10 below exists. Once the
# manifest supplied the counts, only 9 of the 63 checks in `full:service` were
# bound by IDENTITY: the SERVICE group. The other 54 were bound by count alone,
# as were all 57 of `full:foreground`, all 20 of `offline:none`, and all 57 of
# the gateway harness — which had no register at all. So the auditor's case 2b,
# which renames ONE required APPLY check and touches no number, was ACCEPTED.
# A correct count is not evidence that the correct checks ran.
#
# This file builds a GENUINE document for every scope the manifest declares and
# then mutates it one property at a time, requiring the validator to accept
# exactly the genuine ones. The acceptance controls are as load-bearing as the
# refusals: a suite that refuses everything passes for the wrong reason.

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
    python3 "$ASSERT" "$f" --commit "$COMMIT" "$@" 2>&1 | tail -8 | sed 's/^/          /'
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

# Build a genuine result FROM THE MANIFEST for any scope it declares — the same
# shape the harness emits, with every declared check present under a label that
# begins with its recorded static prefix. The " (measured)" suffix stands in for
# the runtime tail a real label interpolates.
build_scope() {   # build_scope <outfile> <scope> <mode> [n-optional]
  python3 - "$MANIFEST" "$1" "$2" "$3" "$COMMIT" "${4:-0}" <<'PY'
import json, sys
manifest, out, scope, mode, commit, n_opt = sys.argv[1:7]
m = json.load(open(manifest))
spec = m["scopes"][scope + ":" + mode]
checks = []
for e in spec["required_checks"]:
    checks.append({"group": e["group"], "result": "pass",
                   "name": e["label_prefixes"][0] + " (measured)"})
required_n = len(checks)
for e in (spec.get("optional_checks") or [])[: int(n_opt)]:
    checks.append({"group": e["group"], "result": "pass", "optional": True,
                   "name": e["label_prefixes"][0] + " (measured)"})
groups = {}
for c in checks:
    if not c.get("optional"):
        groups[c["group"]] = groups.get(c["group"], 0) + 1
assert required_n == spec["expected_total"], (required_n, spec["expected_total"])
json.dump({
    "schema": m["results_schema"], "scope": scope, "mode": mode, "verdict": "PASS",
    "expected_total": required_n, "executed_total": required_n,
    "passed": len(checks), "failed": 0, "skipped": 0, "duplicate_names": 0,
    "app": "/tmp/x/Tethra.app", "data_dir": "/tmp/tethra-track-val-1",
    "service_plist": "/Users/x/Library/LaunchAgents/dev.api-tracker.gateway.abc123def456.plist",
    "service_label": "dev.api-tracker.gateway.abc123def456" if spec["requires_service"] else "",
    "commit": commit,
    "service_created_by_this_run": bool(spec["requires_service"]),
    "groups": [{"name": g, "expected": n, "executed": n, "passed": n, "failed": 0}
               for g, n in sorted(groups.items())],
    "checks": checks,
}, open(out, "w"), indent=2)
PY
}

# Copy a document and apply one python mutation to it.
mutate_from() {   # mutate_from <source> <name> <python-body-operating-on-`d`>
  local src="$1" out="$WORK/$2.json"
  cp "$src" "$out"
  python3 - "$out" <<PY
import json, sys
p = sys.argv[1]
d = json.load(open(p))
$3
json.dump(d, open(p, "w"), indent=2)
PY
  printf '%s' "$out"
}
mutate() {   # mutate <name> <python-body>  — against the full:service document
  mutate_from "$WORK/good.json" "$1" "$2"
}

echo "=== forgery tests for ci_assert_service_results.py ==="
echo

build_scope "$WORK/good.json" full service
build_scope "$WORK/foreground.json" full foreground
build_scope "$WORK/offline.json" offline none
build_scope "$WORK/selfcheck.json" selfcheck none
build_scope "$WORK/gateway0.json" gateway lifecycle 0
build_scope "$WORK/gateway7.json" gateway lifecycle 7

echo "== 1. the genuine article is accepted, for EVERY scope the manifest declares =="
# These are the anti-vacuity controls. Without them a validator that refused
# every document would pass this entire suite.
accepts "$WORK/good.json"       "a complete, honest full:service result is ACCEPTED"
accepts "$WORK/foreground.json" "a complete, honest full:foreground result is ACCEPTED" \
  --scope full --mode foreground
accepts "$WORK/offline.json"    "a complete, honest offline:none result is ACCEPTED" \
  --scope offline --mode none
accepts "$WORK/selfcheck.json"  "a complete, honest selfcheck:none result is ACCEPTED" \
  --scope selfcheck --mode none
accepts "$WORK/gateway0.json"   "a gateway result with 0 optional checks executed is ACCEPTED" \
  --scope gateway --mode lifecycle
accepts "$WORK/gateway7.json"   "a gateway result with 7 optional checks executed is ACCEPTED" \
  --scope gateway --mode lifecycle

echo
echo "== 2. the audit's own forgery =="
cat > "$WORK/audit_forgery.json" <<'JSON'
{
  "schema": "tethra.validation.results/2",
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
svc = [c for c in d["checks"] if c["group"] == "SERVICE"][:7]
d["checks"] = [c for c in d["checks"] if c["group"] != "SERVICE"] + svc
d["executed_total"] = d["expected_total"] = len(d["checks"])
d["passed"] = len(d["checks"])')" \
  "redefining the SERVICE group as smaller is REFUSED"

# THE SHARPEST COUNT ONE, and the reason the manifest exists at all.
#
# This document is entirely self-consistent: every count agrees with every
# other count, every SERVICE check is present under its real label and passing,
# the provenance fact is true, the label is namespaced, the commit matches. The
# ONLY thing wrong with it is that it contains just the SERVICE group presented
# as the whole of full:service. Nothing inside the file can detect that.
python3 - "$MANIFEST" "$WORK/service_only.json" "$COMMIT" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
spec = m["scopes"]["full:service"]
checks = [{"group": "SERVICE", "name": e["label_prefixes"][0] + " (measured)", "result": "pass"}
          for e in spec["required_checks"] if e["group"] == "SERVICE"]
n = len(checks)
json.dump({
    "schema": m["results_schema"], "scope": "full", "mode": "service", "verdict": "PASS",
    "expected_total": n, "executed_total": n, "passed": n, "failed": 0,
    "skipped": 0, "duplicate_names": 0,
    "service_label": "dev.api-tracker.gateway.abc123def456",
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

refuses "$(mutate old_schema 'd["schema"] = "tethra.validation.results/1"')" \
  "an artifact in the PREVIOUS results schema is REFUSED (no pre-remediation evidence)"

echo
echo "== 6. provenance =="
refuses "$(mutate preexisting 'd["service_created_by_this_run"] = False')" \
  "a run that did not create the service it observed is REFUSED"

refuses "$(mutate no_provenance 'del d["service_created_by_this_run"]')" \
  "a result that omits the provenance fact entirely is REFUSED"

echo
echo "== 7. an offline run cannot be filed as service evidence =="
accepts "$WORK/offline.json" "a genuine offline result is accepted AS AN OFFLINE RESULT" \
  --scope offline --mode none
refuses "$WORK/offline.json" "…and REFUSED when submitted as full:service"

# The same document relabelled — the "silent downgrade" this gate exists for.
cp "$WORK/offline.json" "$WORK/relabelled.json"
python3 - "$WORK/relabelled.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["scope"], d["mode"] = "full", "service"
d["service_label"] = "dev.api-tracker.gateway.abc123def456"
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

# ---------------------------------------------------------------------------
echo
echo "== 10. IDENTITY, not count (VAL-05-R) =="
# Every case below leaves EVERY number in the document untouched. At the
# audited head all of them were accepted.

# 10a. THE AUDITOR'S CASE 2b, replayed verbatim.
refuses "$(mutate case_2b 'for c in d["checks"]:
    if c["group"] == "APPLY" and c["name"].startswith("the openai route exists"):
        c["name"] = "a completely different apply assertion"
        break')" \
  "case 2b: ONE required APPLY check renamed, every count intact, is REFUSED"

# 10b. Substitution: a required check replaced by another VALID-LOOKING one —
# a real label, from a real check, in the same group. Both the substituted
# check's absence and the duplicate land.
refuses "$(mutate substituted 'apply = [c for c in d["checks"] if c["group"] == "APPLY"]
apply[0]["name"] = apply[1]["name"]')" \
  "a required check replaced by another valid-looking check is REFUSED"

# 10c. Correct total, wrong identity set: every APPLY label replaced by a
# plausible-sounding fabrication. 64 rows, 9 APPLY rows, nothing else moves.
refuses "$(mutate wrong_set 'n = 0
for c in d["checks"]:
    if c["group"] == "APPLY":
        n += 1
        c["name"] = "the apply step completed assertion number %d" % n')" \
  "a correct total with a WRONG IDENTITY SET is REFUSED"

# 10d. A duplicate plus a missing check, chosen so the total is unchanged.
refuses "$(mutate dup_plus_missing 'apply = [c for c in d["checks"] if c["group"] == "APPLY"]
apply[0]["name"] = apply[1]["name"]
' )" "a duplicate plus a missing check with the SAME total is REFUSED"

# 10e. An unknown id replacing a required one, in the group with no history of
# identity binding at all.
refuses "$(mutate unknown_id 'for c in d["checks"]:
    if c["group"] == "TRAFFIC":
        c["name"] = "TRAFFIC.some_check_id_nobody_declared"
        break')" \
  "an unknown identity replacing a required TRAFFIC check is REFUSED"

# 10f. Group borrowing: identity kept, group moved. The count per group also
# moves, but the identity binding catches it first and names the check.
refuses "$(mutate moved_group 'for c in d["checks"]:
    if c["group"] == "UNDO":
        c["group"] = "APPLY"
        break')" \
  "a check moved to another group, identity kept, is REFUSED"

# 10g. FOREGROUND manifest mismatch — 0 of 57 were bound at the audited head.
refuses "$(mutate_from "$WORK/foreground.json" fg_garbled 'for c in d["checks"]:
    c["name"] = "fabricated " + c["group"] + " assertion"')" \
  "a full:foreground result with every label fabricated is REFUSED" \
  --scope full --mode foreground

refuses "$(mutate_from "$WORK/foreground.json" fg_one_renamed 'for c in d["checks"]:
    if c["group"] == "FOREGROUND":
        c["name"] = "the foreground gateway did something else entirely"
        break')" \
  "a full:foreground result with ONE label renamed is REFUSED" \
  --scope full --mode foreground

# 10h. SERVICE manifest mismatch, stated separately from case 2b: the group
# that WAS bound must stay bound.
refuses "$(mutate svc_renamed 'for c in d["checks"]:
    if c["name"].startswith("launchd loaded the namespaced service gui/"):
        c["name"] = "some other service thing that passed"
        break')" \
  "a full:service result with one SERVICE check renamed is REFUSED"

# 10i. offline:none — 0 of 20 were bound at the audited head.
refuses "$(mutate_from "$WORK/offline.json" offline_garbled 'for c in d["checks"]:
    c["name"] = "fabricated " + c["group"] + " assertion"')" \
  "an offline:none result with every label fabricated is REFUSED" \
  --scope offline --mode none

# 10j. selfcheck:none — 0 of 5 were bound at the audited head.
refuses "$(mutate_from "$WORK/selfcheck.json" sc_garbled 'd["checks"][0]["name"] = "the harness said something"')" \
  "a selfcheck:none result with one control renamed is REFUSED" \
  --scope selfcheck --mode none

# 10k. GATEWAY packaged manifest mismatch — the harness had NO register at all
# at the audited head, so every one of these is new ground.
refuses "$(mutate_from "$WORK/gateway0.json" gw_renamed 'for c in d["checks"]:
    if c["group"] == "UNINSTALL":
        c["name"] = "the uninstall did something unrelated"
        break')" \
  "a gateway:lifecycle result with one required check renamed is REFUSED" \
  --scope gateway --mode lifecycle

refuses "$(mutate_from "$WORK/gateway7.json" gw_opt_as_required 'for c in d["checks"]:
    if c.get("optional"):
        c["optional"] = False
        break')" \
  "a gateway OPTIONAL check presented as REQUIRED is REFUSED" \
  --scope gateway --mode lifecycle

refuses "$(mutate_from "$WORK/gateway7.json" gw_required_as_opt 'for c in d["checks"]:
    if not c.get("optional"):
        c["optional"] = True
        break')" \
  "a gateway REQUIRED check presented as OPTIONAL is REFUSED" \
  --scope gateway --mode lifecycle

refuses "$(mutate_from "$WORK/gateway0.json" gw_unknown 'd["checks"].append(
    {"group": "UNINSTALL", "result": "pass", "name": "an assertion nobody declared"})')" \
  "a gateway result carrying an id the manifest never declared is REFUSED" \
  --scope gateway --mode lifecycle

refuses "$(mutate_from "$WORK/gateway0.json" gw_missing_plus_opt 'req = [c for c in d["checks"] if not c.get("optional")]
d["checks"].remove(req[0])
d["checks"].append({"group": req[0]["group"], "result": "pass", "optional": True,
                    "name": "no listener on the old port (measured)"})')" \
  "a gateway result with one required check missing and an extra optional one is REFUSED" \
  --scope gateway --mode lifecycle

# 10l. A scope whose manifest entry names no checks must be a HARD failure, not
# a quiet pass. This is the defect itself, expressed as a manifest: it is how
# VAL-05-R would return.
python3 - "$MANIFEST" "$WORK/empty_manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["scopes"]["full:service"]["required_checks"] = []
json.dump(m, open(sys.argv[2], "w"), indent=2)
PY
refuses "$WORK/good.json" \
  "a manifest that names NO checks for a scope is REFUSED (the defect cannot recur by omission)" \
  --manifest "$WORK/empty_manifest.json"

python3 - "$MANIFEST" "$WORK/half_manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
spec = m["scopes"]["full:service"]
spec["required_checks"] = [e for e in spec["required_checks"] if e["group"] != "APPLY"]
json.dump(m, open(sys.argv[2], "w"), indent=2)
PY
refuses "$WORK/good.json" \
  "a manifest declaring a group but naming none of its checks is REFUSED" \
  --manifest "$WORK/half_manifest.json"

# ---------------------------------------------------------------------------
echo
echo "== 11. MUTATION CONTROL: the identity comparison must be load-bearing =="
# The tests in section 10 are only worth their PASS lines if REMOVING the
# comparison makes a NAMED one of them fail. This is that proof, committed
# rather than performed by hand: the exact-set-equality block is deleted from a
# COPY of the validator with `sed`, and the copy is then required to ACCEPT the
# case-2b document. If it still refuses, the comparison was not what did the
# work and every PASS above is void.
MUTANT="$WORK/mutant_no_set_equality.py"
awk '
  /^    # --- THE EXACT REQUIRED CHECK SET \(VAL-05-R\)/ { skip = 1 }
  /^    # --- required facts/                            { skip = 0 }
  !skip
' "$ASSERT" > "$MUTANT"

if cmp -s "$MUTANT" "$ASSERT"; then
  echo "  FAIL  the mutation did not apply — the set-equality block could not be located."
  echo "        Update this awk range in the same commit that moved it; a mutation that"
  echo "        does not apply reports a green control for a test that was never run."
  fail=$((fail+1))
elif ! python3 "$MUTANT" "$WORK/good.json" --manifest "$MANIFEST" --commit "$COMMIT" >/dev/null 2>&1; then
  echo "  FAIL  the mutant refuses even a GENUINE document, so it proves nothing about"
  echo "        case 2b. The awk range removed more than the identity comparison."
  fail=$((fail+1))
elif python3 "$MUTANT" "$WORK/case_2b.json" --manifest "$MANIFEST" --commit "$COMMIT" >/dev/null 2>&1; then
  echo "  PASS  removing the exact-set-equality block makes case 2b PASS again —"
  echo "        so the case-2b test above is not vacuous, and the comparison is what"
  echo "        refuses it."
  pass=$((pass+1))
else
  echo "  FAIL  case 2b is refused EVEN WITHOUT the identity comparison, so the test in"
  echo "        section 10a proves nothing about it. Find what is really refusing it."
  fail=$((fail+1))
fi

# The same control for the gateway scope, which had no identity binding of any
# kind before this change.
if python3 "$MUTANT" "$WORK/gw_renamed.json" --scope gateway --mode lifecycle \
     --manifest "$MANIFEST" --commit "$COMMIT" >/dev/null 2>&1; then
  echo "  PASS  …and a renamed gateway check passes the mutant too, so the gateway"
  echo "        identity tests are not vacuous either"
  pass=$((pass+1))
else
  echo "  FAIL  a renamed gateway check is refused without the identity comparison"
  fail=$((fail+1))
fi

echo
echo "=== ASSERTER FORGERY RESULT: $pass passed, $fail failed ==="
# The floor is an EQUALITY, not a minimum: a floor with no headroom cannot tell
# "an assertion was added" from "an assertion was skipped", and both are things
# a reader of this number needs to know.
EXPECTED_ASSERTIONS=59
if [ "$pass" -ne "$EXPECTED_ASSERTIONS" ] && [ "$fail" -eq 0 ]; then
  echo "FAIL: $pass assertions ran; exactly $EXPECTED_ASSERTIONS are declared."
  echo "      A DIFFERENT count means assertions were added or SKIPPED, not that all"
  echo "      is well. Update EXPECTED_ASSERTIONS in the same commit that changes them."
  exit 1
fi
[ "$fail" -eq 0 ]
