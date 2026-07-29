#!/usr/bin/env bash
# Mutation test OF the identity binding itself (`VAL-05-R`).
#
#   bash scripts/validation_manifest_mutants.sh
#
# `scripts/validation_manifest.json` is the TRUSTED statement of which checks
# each scope must run, and `scripts/gen_validation_manifest.py --check` is what
# stops it drifting away from the harnesses. That arrangement is worth exactly
# as much as the generator's ability to NOTICE. A `--check` that cannot fail is
# the same class of defect as a harness that cannot fail — and this repository
# has shipped both: `ZFT-VAL-7` (four counted checks that were unconditional
# passes) and `VAL-05-R` itself (a manifest that named 9 of 63 checks and let a
# renamed one through).
#
# So each mutant below changes ONE thing about a check's IDENTITY in a COPY of
# a harness and requires `--check` to refuse. A mutant that survives means the
# manifest would not have noticed that change, and no set-equality claim made
# against it is trustworthy until it does.
#
# Nothing in the repository is modified: every mutant is a copy under a mktemp
# directory removed by the EXIT trap. No harness is EXECUTED beyond
# `--emit-check-sites`, which reads its own source, starts nothing, writes
# nothing and needs no app bundle — so this is safe to run on a machine with a
# live Tethra gateway installed.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$ROOT/scripts"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tethra-manifest-mutants.XXXXXX")" \
  || { echo "failed to create a temporary directory" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT

for f in tracking_validate_macos.sh gateway_validate_macos.sh validation_manifest.json \
         gen_validation_manifest.py; do
  [ -f "$SCRIPTS/$f" ] || { echo "missing $SCRIPTS/$f" >&2; exit 1; }
done

KILLED=0
SURVIVED=0
SURVIVORS=""

# Runs gen_validation_manifest.py --check with its inputs pointed at $1, a
# directory holding a (possibly mutated) copy of both harnesses and the
# COMMITTED manifest. Exit 0 means "the manifest still describes these sources".
run_check() {   # run_check <dir>
  python3 - "$SCRIPTS/gen_validation_manifest.py" "$1" <<'PY' >/dev/null 2>&1
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("gen", sys.argv[1])
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)
d = sys.argv[2]
gen.TRACKING = os.path.join(d, "tracking_validate_macos.sh")
gen.GATEWAY = os.path.join(d, "gateway_validate_macos.sh")
gen.MANIFEST = os.path.join(d, "validation_manifest.json")
sys.exit(gen.main(["--check"]))
PY
}

# mutate <name> <harness-file> <sed-expression> <why-this-matters>
mutate() {
  local name="$1" target="$2" expr="$3" why="$4"
  local dir="$WORK/$RANDOM$RANDOM"
  mkdir -p "$dir"
  cp "$SCRIPTS/tracking_validate_macos.sh" "$SCRIPTS/gateway_validate_macos.sh" \
     "$SCRIPTS/validation_manifest.json" "$dir/"
  sed "$expr" "$SCRIPTS/$target" > "$dir/$target"

  # A mutation that did not apply would "pass" for the wrong reason — the same
  # class of vacuity this whole script exists to reject. Treat a no-op edit as
  # a hard ERROR, not as a killed mutant.
  if cmp -s "$dir/$target" "$SCRIPTS/$target"; then
    echo "  ERROR   $name"
    echo "          the mutation did not apply — the sed expression no longer matches"
    echo "          $target. Update it in the same commit that changed the label."
    SURVIVED=$((SURVIVED + 1))
    SURVIVORS="$SURVIVORS
    $name (mutation did not apply)"
    return
  fi

  if run_check "$dir"; then
    echo "  SURVIVED  $name"
    echo "          $why"
    SURVIVED=$((SURVIVED + 1))
    SURVIVORS="$SURVIVORS
    $name"
  else
    echo "  KILLED  $name"
    echo "          $why"
    KILLED=$((KILLED + 1))
  fi
}

echo "=== mutation test of the trusted check-identity binding ==="
echo "    each mutant must be KILLED by gen_validation_manifest.py --check"
echo

# --- control -----------------------------------------------------------------
# Before any mutant: the UNMUTATED sources must still agree with the committed
# manifest. Without this, every "KILLED" below could be a copy that never
# agreed in the first place.
CONTROL="$WORK/control"
mkdir -p "$CONTROL"
cp "$SCRIPTS/tracking_validate_macos.sh" "$SCRIPTS/gateway_validate_macos.sh" \
   "$SCRIPTS/validation_manifest.json" "$CONTROL/"
if run_check "$CONTROL"; then
  echo "  CONTROL   the unmutated sources agree with the committed manifest"
else
  echo "  CONTROL FAILED — the committed manifest already disagrees with the harnesses."
  echo "  Every mutant below would be 'killed' for the wrong reason. Run"
  echo "  python3 scripts/gen_validation_manifest.py --write first."
  exit 1
fi
echo

# --- MI: a CHANGED CHECK IDENTITY -------------------------------------------
mutate "MI — a check's identity is changed (APPLY route row)" \
  tracking_validate_macos.sh \
  's|"the openai route exists in the database"|"the openai route is present in the database"|' \
  "the auditor's case 2b at the source: one required check renamed, no count moved."

mutate "MI2 — a check's identity is changed in the GATEWAY harness" \
  gateway_validate_macos.sh \
  's|ok "gateway install succeeded"|ok "gateway install completed"|' \
  "the harness that had no register at all before this change."

# --- MJ: TWO SITES SHARING ONE IDENTITY -------------------------------------
# The generator must refuse this outright rather than emit a manifest in which
# two entries can claim the same register row — that ambiguity is what made the
# audited validator's first-match assignment order-dependent.
mutate "MJ — two APPLY checks are given the SAME identity" \
  tracking_validate_macos.sh \
  's|"exactly one project link was created"|"the openai route exists in the database"|' \
  "two call sites sharing one label make 'which check did not run?' unanswerable."

mutate "MK — one identity is made a strict PREFIX of another" \
  tracking_validate_macos.sh \
  's|"one tracking setup was recorded"|"the openai route exists"|' \
  "prefix shadowing: the shorter entry would consume the longer one's row."

# --- ML: a LABEL-ONLY CHANGE -------------------------------------------------
# The analogue, under this design, of deleting an `#@id` annotation: a label
# whose first characters are interpolated has no static identity at all, so
# nothing can pin the check. It must be refused at generation time.
mutate "ML — a label is changed so it begins with an interpolation" \
  tracking_validate_macos.sh \
  's|"the fixture .env really contains the fake key|"$PROJECT really contains the fake key|' \
  "a check whose label starts with a runtime value cannot be identified at all."

mutate "ML2 — a label's static text is edited, nothing else" \
  tracking_validate_macos.sh \
  's|"undo restored the .env byte for byte|"undo restored the .env byte-for-byte|' \
  "a prose edit and a substituted check are indistinguishable unless both are diffs."

# --- MM / MN: the two gateway shapes the audit found ------------------------
mutate "MM — NEW-27 restored: a conditional arm that emits nothing" \
  gateway_validate_macos.sh \
  's|^  bad "python3 is a preflight requirement of this script but is not on PATH, so the Python-through-the-gateway check could not run"$|  echo "  SKIP python3 not present"|' \
  "a required check behind a conditional whose other arm emits nothing vanishes silently."

mutate "MN — NEW-26 restored: a counted check inside a nested loop" \
  gateway_validate_macos.sh \
  's|      CANARY_HITS="$CANARY_HITS ${needle:0:12}...@$f"|      bad "canary found in $f"|' \
  "a check emitted per data hit makes the required total depend on the data."

echo
echo "=== MANIFEST MUTATION RESULT: $KILLED killed, $SURVIVED survived ==="
if [ "$SURVIVED" -ne 0 ]; then
  echo "    surviving mutants:$SURVIVORS"
  echo "    The manifest would NOT have noticed these identity changes, so no"
  echo "    set-equality claim made against it is trustworthy. Do not quote"
  echo "    'the exact required check set was enforced' until every mutant is killed."
  exit 1
fi
