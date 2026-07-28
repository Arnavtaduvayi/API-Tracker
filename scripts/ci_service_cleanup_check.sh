#!/usr/bin/env bash
# Post-run cleanup verification for the packaged macOS service-lifecycle job.
#
#   scripts/ci_service_cleanup_check.sh
#
# The validation script cleans up after itself and says so. That is a claim the
# run makes about its own behaviour, and a claim made by the thing under test is
# the weakest kind of evidence. This verifies it from OUTSIDE, after the
# script's EXIT trap has already run.
#
# The assertion is deliberately the strongest available one and also the
# simplest to state: THE MACHINE IS AS CLEAN AFTER AS IT WAS BEFORE. The
# preconditions script already defines "clean" — no registered job, no plist,
# no process, no installed helper, no data directory, no control endpoint, no
# route state, no stale namespace — so cleanup is verified by requiring that
# every one of those still holds. A residue of any kind flips exactly the
# check that was green before the run.
#
# Read-only, for the same reason the preconditions are: a cleanup verifier that
# cleans up is not a verifier.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

echo "=== post-run cleanup verification ==="
echo "    The run claims it removed everything it created. That claim is not"
echo "    taken on trust: the clean-room preconditions are re-asserted below,"
echo "    from outside the script, after its EXIT trap has run. If any resource"
echo "    survived — a registered job, a plist, a process, an installed helper,"
echo "    a data directory, a control endpoint, route state, or a temporary"
echo "    namespace — the corresponding check flips from OK to FAIL."
echo

if bash "$HERE/ci_service_preconditions.sh"; then
  echo
  echo "=== CLEANUP VERIFIED: the machine is as clean after the run as before ==="
  exit 0
fi

echo
echo "=== CLEANUP INCOMPLETE — the run left resources behind ==="
echo
echo "Whatever is reported above as FAIL survived the run's own cleanup. Note"
echo "which: a surviving LaunchAgent or process is a service-lifecycle defect,"
echo "a surviving data directory is an isolation defect (the run escaped its"
echo "TETHRA_DIR), and a surviving temporary namespace is a cleanup defect."
exit 1
