#!/usr/bin/env bash
# Executable proof that a validation script's REFUSAL path is inert, and that
# its teardown can only remove what it created.
#
#   scripts/service_cleanup_safety.sh [--script tracking|gateway|both]
#
# WHY THIS FILE EXISTS
# --------------------
# `FINAL_REMEDIATION_EVIDENCE.md` §RA-004 quotes sha256 pairs, a launchctl
# invocation log and a four-row mutation table. None of it was reproducible:
# the harness that produced those numbers was never committed, so the strongest
# safety claim in the remediation rested on output nobody else could regenerate.
# That is the same defect class as an uncounted check — a claim whose control
# cannot be re-run is a claim, not evidence. This is that harness, committed.
#
# WHAT IT PROVES, as five separate properties (the brief's RA-004 list):
#
#   P1  the refusal guard runs BEFORE any destructive cleanup is registered
#   P2  the ownership ledger independently prevents deleting a pre-existing
#       resource, even when the ordering layer is defeated
#   P3  removing BOTH protections reproduces the original dangerous behaviour
#   P4  a refusal path performs no service and no filesystem mutation
#   P5  an owned-resource cleanup completes: everything the run created is gone
#
# P1 and P2 are deliberately reported SEPARATELY. The previous remediation
# found that reverting the trap ordering alone did not fail, because the
# ledger independently prevented damage, and reported that as a negative
# result rather than dressing it up. That honesty is preserved here and made
# mechanical: each layer is defeated on its own and the outcome is printed as
# measured, so "two independent sufficient layers" is a finding a reader can
# check rather than a claim they must accept.
#
# METHOD
#   * a fake $HOME containing a DECOY production plist
#     ($HOME/Library/LaunchAgents/dev.api-tracker.gateway.plist);
#   * a shimmed `launchctl` first on PATH that RECORDS every invocation and
#     performs none — so the harness measures intent, not merely effect. A
#     read-only `list` is permitted; any destructive verb is a failure.
#     Shimming matters: `bootout` addresses the live gui/<uid> domain
#     regardless of $HOME, so a fake HOME alone would not protect a real
#     gateway. That is REM-001, and it is why this harness never runs
#     unshimmed.
#   * the decoy's sha256, size, mtime and mode are compared either side.
#
# It never touches the real ~/Library/LaunchAgents and never calls the real
# launchctl.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WHICH="both"
while [ $# -gt 0 ]; do
  case "$1" in
    --script) WHICH="${2:-both}"; shift 2 ;;
    --script=*) WHICH="${1#--script=}"; shift ;;
    -h|--help) awk '!/^#/ { exit } { print }' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; fail=$((fail + 1)); }
step() { echo; echo "== $1 =="; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/tethra-cleanup-safety-XXXXXX")" || exit 2
cleanup_harness() { rm -rf "$WORK"; }
trap cleanup_harness EXIT

# --- the launchctl shim ----------------------------------------------------
SHIM="$WORK/bin"
mkdir -p "$SHIM"
cat > "$SHIM/launchctl" <<'SHIMEOF'
#!/bin/sh
# Records intent; performs nothing. `list` answers empty so a caller's
# read-only interlock sees a clean machine and proceeds to the part under test.
printf '%s\n' "$*" >> "$LAUNCHCTL_LOG"
case "$1" in
  list)  exit 0 ;;
  print) exit 1 ;;   # "no such job"
  *)     exit 0 ;;
esac
SHIMEOF
chmod +x "$SHIM/launchctl"

DECOY_BODY='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.api-tracker.gateway</string>
  <key>ProgramArguments</key><array><string>/decoy/tethra-gateway-0.1.0</string></array>
</dict></plist>'

sig() {   # sha256 + size + mtime + mode, or the word absent
  if [ -e "$1" ]; then
    printf '%s %s\n' \
      "$(shasum -a 256 "$1" 2>/dev/null | awk '{print $1}')" \
      "$(stat -f 'size=%z mtime=%m mode=%Lp' "$1" 2>/dev/null)"
  else
    echo absent
  fi
}

# Build a fake HOME with a decoy production LaunchAgent. Returns the HOME path.
make_fake_home() {
  local h="$1"
  mkdir -p "$h/Library/LaunchAgents"
  printf '%s\n' "$DECOY_BODY" > "$h/Library/LaunchAgents/dev.api-tracker.gateway.plist"
  chmod 600 "$h/Library/LaunchAgents/dev.api-tracker.gateway.plist"
}

# Run a script under the fake HOME and the shim, and report what it did to the
# decoy and to launchctl.
#
#   run_case <case-name> <script-path> <args...>
# Sets: RC, DECOY_BEFORE, DECOY_AFTER, LAUNCHCTL_CALLS, DESTRUCTIVE_CALLS
run_case() {
  local name="$1" script="$2"; shift 2
  local home="$WORK/home-$name"
  local plist
  rm -rf "$home"
  make_fake_home "$home"
  plist="$home/Library/LaunchAgents/dev.api-tracker.gateway.plist"
  LAUNCHCTL_LOG="$WORK/launchctl-$name.log"
  : > "$LAUNCHCTL_LOG"
  DECOY_BEFORE="$(sig "$plist")"

  # The scripts under test build their scratch path from a LITERAL /tmp, not
  # from $TMPDIR, so redirecting TMPDIR would produce a stray check that can
  # never fire — a vacuous control, which is the exact defect this repository
  # keeps finding in its own harnesses. Snapshot the real /tmp instead and
  # compare sets: anything present after and not before was created by the run.
  ls -d /tmp/tethra-track-val-* /tmp/tethra-gw-val-* 2>/dev/null | sort > "$WORK/tmp-before-$name"

  ( export HOME="$home" \
           LAUNCHCTL_LOG="$LAUNCHCTL_LOG" \
           PATH="$SHIM:/usr/bin:/bin:/usr/sbin:/sbin"
    "$script" "$@" ) >"$WORK/out-$name.log" 2>&1
  RC=$?

  ls -d /tmp/tethra-track-val-* /tmp/tethra-gw-val-* 2>/dev/null | sort > "$WORK/tmp-after-$name"
  NEW_SCRATCH="$(comm -13 "$WORK/tmp-before-$name" "$WORK/tmp-after-$name")"

  DECOY_AFTER="$(sig "$plist")"
  LAUNCHCTL_CALLS="$(cat "$LAUNCHCTL_LOG" 2>/dev/null)"
  DESTRUCTIVE_CALLS="$(grep -E '^(bootout|bootstrap|kickstart|load|unload|remove|stop|start|enable|disable)' \
    "$LAUNCHCTL_LOG" 2>/dev/null)"
  CASE_HOME="$home"
}

report_case() {   # report_case <label>
  echo "    exit code:          $RC"
  echo "    decoy before:       $DECOY_BEFORE"
  echo "    decoy after:        $DECOY_AFTER"
  if [ -n "$LAUNCHCTL_CALLS" ]; then
    echo "    launchctl calls:    $(printf '%s' "$LAUNCHCTL_CALLS" | tr '\n' ';')"
  else
    echo "    launchctl calls:    (none)"
  fi
}

# ===========================================================================
# The tracking harness
# ===========================================================================
check_tracking() {
  local script="$REPO_ROOT/scripts/tracking_validate_macos.sh"

  step "tracking_validate_macos.sh — P1/P4: a refusal is inert"
  # --scope full --require-service against a HOME that already has a gateway
  # agent MUST refuse. Nothing may be created, and nothing destructive may
  # reach launchctl.
  run_case "track-refuse" "$script" --scope full --require-service
  report_case

  [ "$RC" -ne 0 ]
  if [ "$RC" -ne 0 ]; then
    ok "P1: the run REFUSED (exit $RC) rather than proceeding beside an existing agent"
  else
    bad "P1: the run did NOT refuse beside an existing gateway LaunchAgent"
  fi

  if [ "$DECOY_AFTER" = "$DECOY_BEFORE" ] && [ "$DECOY_AFTER" != absent ]; then
    ok "P4: the pre-existing production plist is byte-identical after the refusal"
  else
    bad "P4: the refusal changed the pre-existing production plist"
  fi

  if [ -z "$DESTRUCTIVE_CALLS" ]; then
    ok "P4: no destructive launchctl verb was attempted on the refusal path"
  else
    bad "P4: the refusal path attempted: $(printf '%s' "$DESTRUCTIVE_CALLS" | tr '\n' ';')"
  fi

  # The refusal must also not have created the run's own scratch state — that
  # is what "the guards run before any trap is registered" buys, and it is
  # observable rather than merely argued.
  if [ -z "$NEW_SCRATCH" ]; then
    ok "P1: the refusal created no isolated data directory (no trap was ever armed)"
  else
    bad "P1: the refusal created scratch state: $(printf '%s' "$NEW_SCRATCH" | tr '\n' ' ')"
  fi

  step "tracking_validate_macos.sh — P5: an owned cleanup completes"
  # --scope selfcheck creates the isolated directories, the ledger and the
  # register, runs its checks and tears everything down. Nothing may survive.
  run_case "track-owned" "$script" --scope selfcheck
  echo "    exit code:          $RC"
  if [ "$RC" -eq 0 ]; then
    ok "P5: the owned run completed (exit 0)"
  else
    bad "P5: the owned run did not complete (exit $RC)"
    sed 's/^/        /' "$WORK/out-track-owned.log" | tail -20
  fi
  if [ -z "$NEW_SCRATCH" ]; then
    ok "P5: every directory the owned run created was removed"
  else
    bad "P5: the owned run left: $(printf '%s' "$NEW_SCRATCH" | tr '\n' ' ')"
  fi

  step "tracking_validate_macos.sh — P2/P3: defeating the layers, one at a time"
  # Layer A: ordering. Move `trap cleanup EXIT` above the preflight, so a
  # refusal fires the teardown.
  local mut_a="$WORK/mutant-ordering.sh"
  awk '
    /^trap cleanup EXIT$/ { next }                      # remove the correct site
    /^# PREFLIGHT — every refusal lives here/ && !done {
      print "trap cleanup EXIT"; done = 1               # arm it BEFORE the guards
    }
    { print }
  ' "$script" > "$mut_a"
  chmod +x "$mut_a"
  if ! grep -q '^trap cleanup EXIT$' "$mut_a"; then
    bad "P2: the ordering mutation did not apply (the trap line moved or changed)"
  else
    run_case "mut-ordering" "$mut_a" --scope full --require-service
    report_case
    if [ "$DECOY_AFTER" = "$DECOY_BEFORE" ]; then
      ok "P2: with the ORDERING layer defeated, the ledger alone still protected the plist"
      echo "        (reported as measured: this mutation does NOT kill, because the"
      echo "         two layers are independently sufficient. See P3.)"
    else
      bad "P2: with the ordering layer defeated, the plist changed — the ledger did not hold"
    fi
  fi

  # Layer B: ownership. Replace the ledger-bounded teardown with the
  # pattern-based one the model exists to forbid — the shape that infers
  # ownership from a filename glob.
  local mut_b="$WORK/mutant-both.sh"
  awk '
    /^trap cleanup EXIT$/ { next }
    /^# PREFLIGHT — every refusal lives here/ && !done {
      print "trap cleanup EXIT"; done = 1
    }
    # Widen teardown to a glob over the LaunchAgents directory: ownership by
    # filename pattern, which matches a production agent as well as ours.
    /^  # 5\. Our scratch directories\./ && !widened {
      print "  rm -f \"$LA_DIR/$LEGACY_LABEL\"*.plist 2>/dev/null"
      widened = 1
    }
    { print }
  ' "$script" > "$mut_b"
  chmod +x "$mut_b"
  if ! grep -q 'rm -f "\$LA_DIR/\$LEGACY_LABEL"\*\.plist' "$mut_b"; then
    bad "P3: the combined mutation did not apply"
  else
    run_case "mut-both" "$mut_b" --scope full --require-service
    report_case
    if [ "$DECOY_AFTER" = absent ] || [ "$DECOY_AFTER" != "$DECOY_BEFORE" ]; then
      ok "P3: with BOTH layers defeated, the pre-existing plist was destroyed — the harness sees danger"
    else
      bad "P3: with both layers defeated the plist survived, so this harness cannot
        detect the very defect it exists to detect. Every PASS above is void."
    fi
  fi
}

# ===========================================================================
# The gateway harness — same model, the script that grew it first
# ===========================================================================
check_gateway() {
  local script="$REPO_ROOT/scripts/gateway_validate_macos.sh"

  step "gateway_validate_macos.sh — P1/P4: a refusal is inert"
  run_case "gw-refuse" "$script"
  report_case
  if [ "$RC" -ne 0 ]; then
    ok "P1: the run REFUSED (exit $RC) beside a pre-existing production agent"
  else
    bad "P1: the run did NOT refuse"
  fi
  if [ "$DECOY_AFTER" = "$DECOY_BEFORE" ] && [ "$DECOY_AFTER" != absent ]; then
    ok "P4: the pre-existing production plist is byte-identical after the refusal"
  else
    bad "P4: the refusal changed the pre-existing production plist"
  fi
  if [ -z "$DESTRUCTIVE_CALLS" ]; then
    ok "P4: no destructive launchctl verb was attempted on the refusal path"
  else
    bad "P4: the refusal path attempted: $(printf '%s' "$DESTRUCTIVE_CALLS" | tr '\n' ';')"
  fi
}

echo "=== service cleanup safety: refusal inertness and ledger-bounded teardown ==="
echo "    repo:  $REPO_ROOT"
echo "    work:  $WORK"
echo "    NOTE:  a shimmed launchctl records intent and performs nothing; the"
echo "           real ~/Library/LaunchAgents is never touched."

case "$WHICH" in
  tracking) check_tracking ;;
  gateway)  check_gateway ;;
  both)     check_tracking; check_gateway ;;
  *) echo "unknown --script '$WHICH' (expected tracking, gateway or both)" >&2; exit 2 ;;
esac

echo
echo "=== SERVICE CLEANUP SAFETY: $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
