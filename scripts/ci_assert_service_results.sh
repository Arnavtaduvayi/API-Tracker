#!/usr/bin/env bash
# Assert that the SERVICE SCOPE completed — not merely that a script exited.
#
#   scripts/ci_assert_service_results.sh <results.json>
#
# WHY THIS IS NOT `grep "0 failed"`
# --------------------------------
# "the script exited 0" and "the full service scope ran and passed" are
# different statements, and this project has already been bitten by both
# directions of the gap:
#
#   * RA-003: `full:service` declared 60 expected checks while its groups sum
#     to 59, so the mode exited NON-ZERO with all 59 of its assertions green.
#     A job asserting "exit 0" would have called that a product failure.
#   * The mirror image is worse: a run that quietly downgraded to
#     `--foreground`, or ran `--scope offline`, exits 0 with a confident
#     total. A job asserting "0 failed" would call that a service-lifecycle
#     pass. That downgrade is ZFT-VAL-4, and it is the reason the modes are
#     built to produce DIFFERENT totals.
#
# So this asserts the machine-readable result names the exact scope and mode
# that were meant to run, that every required group executed its required
# number of checks, that nothing was skipped or duplicated, and that the
# service label the run installed was namespaced rather than the production
# one. Any of those failing fails the job.
#
# WHERE "REQUIRED" COMES FROM (`VAL-01`)
# --------------------------------------
# Not from the results file. The previous revision read `expected_total`,
# every `groups[].expected` and every check name out of the artifact it was
# validating, so a twelve-line forgery declaring zero checks printed
# "SERVICE SCOPE COMPLETED: 0/0" and exited 0. Expectations now come from
# `scripts/validation_manifest.json` — committed, reviewed, and proved against
# the harness's own group table by `scripts/validation_manifest_check.sh` —
# and the scope, mode and commit come from THIS script's arguments, which in
# CI are set by the workflow. A result may report what it observed; it may not
# define what is acceptable.
#
#   scripts/ci_assert_service_results.sh <results.json> [--scope S] [--mode M] [--commit SHA]
set -uo pipefail

JSON="${1:-}"
if [ -z "$JSON" ]; then
  echo "usage: $0 <results.json> [--scope S] [--mode M] [--commit SHA]" >&2
  exit 2
fi
shift
if [ ! -f "$JSON" ]; then
  echo "FATAL: no machine-readable results at $JSON" >&2
  echo "The validation script writes this when TETHRA_VALIDATION_RESULTS_JSON is set." >&2
  echo "Its absence means the run died before the result stage — read the log." >&2
  exit 1
fi

echo "=== asserting the service scope completed (source: $JSON) ==="
python3 "$(dirname "$0")/ci_assert_service_results.py" "$JSON" "$@"
