#!/usr/bin/env bash
# Mutation test OF scripts/tracking_validate_macos.sh.
#
#   bash scripts/validation_harness_mutants.sh
#
# The packaged validation harness certifies the product. Nothing certified
# the harness: the 2026-07-27 audit found 4 of its 42 counted checks were
# unconditional passes (ZFT-VAL-7) and its anti-vacuity floor counted
# `pass+fail`, so it detected truncation but never tautology. The harness now
# carries its own self-check group — and this script is what proves that
# group is not itself decorative.
#
# For each mutant it:
#
#   1. copies the harness to a temporary directory,
#   2. rewrites one primitive so the harness can no longer report a failure
#      (or, for MF, so it reverts to the exact defect ZFT-VAL-10 named),
#   3. runs `--scope selfcheck`, which needs no app bundle, no vault, no
#      gateway and no network,
#   4. requires the mutant to be KILLED — a non-zero exit.
#
# A mutant that exits 0 is reported as SURVIVING and this script exits
# non-zero: the harness's self-check would not have caught that weakening,
# and no total the harness prints is trustworthy until it does.
#
# Nothing in the repository is modified: every mutant is a copy under a
# mktemp directory removed by the EXIT trap. `--scope selfcheck` starts no
# service, writes only inside its own isolated TETHRA_DIR, and makes no
# network request, so this is safe to run anywhere — including on a machine
# with a live Tethra gateway installed.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HARNESS="$ROOT/scripts/tracking_validate_macos.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tethra-harness-mutants.XXXXXX")" \
  || { echo "failed to create a temporary directory" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT

[ -f "$HARNESS" ] || { echo "harness not found at $HARNESS" >&2; exit 1; }

KILLED=0
SURVIVED=0
SURVIVORS=""

# mutate <name> <sed-expression> <why-this-matters>
mutate() {
  local name="$1" expr="$2" why="$3"
  local file="$WORK/mutant.sh"
  sed "$expr" "$HARNESS" > "$file"

  # A mutation that did not apply would "pass" for the wrong reason — the
  # same class of vacuity this whole script exists to reject. Treat a no-op
  # edit as a hard error, not as a killed mutant.
  if cmp -s "$file" "$HARNESS"; then
    echo "  ERROR   $name"
    echo "          the mutation did not apply — the sed expression no longer"
    echo "          matches the harness. Update it in the same commit that"
    echo "          changed the primitive."
    SURVIVED=$((SURVIVED + 1))
    SURVIVORS="$SURVIVORS
    $name (mutation did not apply)"
    return
  fi

  local out
  out="$(bash "$file" --scope selfcheck 2>&1)"
  if [ $? -ne 0 ]; then
    echo "  KILLED  $name"
    echo "          $why"
    KILLED=$((KILLED + 1))
  else
    echo "  SURVIVED  $name"
    echo "          $why"
    printf '%s\n' "$out" | sed 's/^/          /'
    SURVIVED=$((SURVIVED + 1))
    SURVIVORS="$SURVIVORS
    $name"
  fi
}

echo "=== mutation test of scripts/tracking_validate_macos.sh ==="
echo "    each mutant must be KILLED by the harness's own self-check"
echo

mutate "MA — bad() prints PASS and counts a pass" \
  's|^bad() { echo "  FAIL  \$1"; fail=\$((fail+1)); bump fail; record_check fail "\$1"; }|bad() { echo "  PASS  $1"; pass=$((pass+1)); bump pass; record_check pass "$1"; }|' \
  "the literal ZFT-VAL-7 defect: a harness that can only say ok."

mutate "MB — bad() is a silent no-op" \
  's|^bad() { echo "  FAIL  \$1"; fail=\$((fail+1)); bump fail; record_check fail "\$1"; }|bad() { return 0; }|' \
  "failures vanish entirely; the total shrinks and every check appears green."

mutate "MC — check() always calls ok()" \
  's|^check() { if \[ "\$1" -eq 0 \]; then ok "\$2"; else bad "\$2"; fi; }|check() { ok "$2"; }|' \
  "the funnel 30 of the checks flow through stops consulting its argument."

mutate "MD — assert_db() always passes" \
  's|^  if \[ "\$got" = "1" \]; then ok "\$2"; else bad "\$2 (query returned .*$|  ok "$2"|' \
  "the database primitive behind the state, link, route and event assertions."

mutate "ME — assert_same_bytes() always passes" \
  's|^  if cmp -s "\$1" "\$2"; then|  if true; then|' \
  "the primitive behind every unchanged/restored/byte-identical claim."

mutate "MF — assert_same_bytes() reverts to string equality" \
  's|^  if cmp -s "\$1" "\$2"; then|  if [ "$(cat "$1")" = "$(cat "$2")" ]; then|' \
  "the literal ZFT-VAL-10 defect: trailing-newline drift becomes invisible."

mutate "MG — the self-check group is deleted outright" \
  '/^selfcheck fail /d; /^selfcheck pass /d; /^  selfcheck fail /d; /^  selfcheck pass /d' \
  "removing the guard must not be a quiet way to pass; the count-equality gate catches it."

# MH is the mutation an adversarial reviewer found and this suite did not:
# gut the GATE rather than the primitives it guards. The count is preserved,
# so the count-equality gate cannot see it, and the first guard written
# against it was itself vacuous (it required counter movement that BOTH the
# real gate and the bypass produce). What discriminates is that the real
# gate RUNS its control and REJECTS a mismatched expectation.
mutate "MH — selfcheck() is replaced by a bare ok()" \
  '/^selfcheck() {   # selfcheck/,/^}$/c\
selfcheck() { ok "$2"; }' \
  "the gate that certifies every other check, disabled by one line, with the count preserved."

echo
echo "=== HARNESS MUTATION RESULT: $KILLED killed, $SURVIVED survived ==="
if [ "$SURVIVED" -ne 0 ]; then
  echo "    surviving mutants:$SURVIVORS"
  echo "    The harness would NOT have caught these weakenings. Do not quote a"
  echo "    check total from it until every mutant is killed."
  exit 1
fi
