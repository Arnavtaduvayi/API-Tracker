#!/usr/bin/env bash
# Mutation checks for the load-bearing security properties.
#
# A passing test proves nothing on its own: it may be asserting something
# that is true for reasons unrelated to the protection it claims to cover.
# The audit found exactly that — three tests appeared to prove "nothing is
# executed during a scan" while a hostile `core.fsmonitor` executed four
# times, and mutation testing found two load-bearing clauses of the
# verification mechanism with ZERO effective coverage.
#
# This script closes that loop mechanically. For each protection it:
#
#   1. rewrites the production source to REMOVE the protection,
#   2. runs the test that is supposed to catch it,
#   3. requires that test to FAIL,
#   4. restores the original source byte for byte.
#
# A mutation that leaves the suite green is reported as a SURVIVING MUTANT
# and the script exits non-zero: that test is not pinning what it says it
# pins. Restoration runs from an EXIT trap, so an interrupted run does not
# leave a mutated tree behind.
#
# Usage:  bash scripts/mutation_checks.sh [name ...]
#   With no arguments, runs every check.

set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
WORK="$(mktemp -d)"
PASSED=0
SURVIVED=0
SKIPPED=0
declare -a SURVIVORS=()
declare -a BACKED_UP=()

restore_all() {
  local f
  for f in "${BACKED_UP[@]:-}"; do
    [ -n "$f" ] || continue
    if [ -f "$WORK/$(echo "$f" | tr / _)" ]; then
      cp "$WORK/$(echo "$f" | tr / _)" "$ROOT/$f"
    fi
  done
  BACKED_UP=()
}
trap 'restore_all; rm -rf "$WORK"' EXIT

backup() {
  local f="$1"
  cp "$ROOT/$f" "$WORK/$(echo "$f" | tr / _)"
  BACKED_UP+=("$f")
}

# mutate <name> <file> <python-replacement-script> <cargo-test-args...>
#
# The replacement is a Python snippet operating on the variable `s` (the
# file contents). Using Python rather than sed keeps multi-line, indentation-
# sensitive replacements exact.
mutate() {
  local name="$1"; shift
  local file="$1"; shift
  local pyrepl="$1"; shift

  if [ "$#" -eq 0 ]; then
    echo "internal error: no test command for $name" >&2
    exit 2
  fi

  if [ -n "${FILTER:-}" ] && [[ " $FILTER " != *" $name "* ]]; then
    return 0
  fi

  echo
  echo "── mutation: $name"
  echo "   file:     $file"
  echo "   test:     cargo test $*"

  backup "$file"
  if ! FILE="$file" python3 - "$pyrepl" <<'PY'
import os, sys
path = os.environ["FILE"]
repl = sys.argv[1]
s = open(path).read()
before = s
ns = {"s": s}
exec(repl, ns)
s = ns["s"]
if s == before:
    sys.stderr.write("MUTATION DID NOT APPLY: the anchor text was not found\n")
    sys.exit(3)
open(path, "w").write(s)
PY
  then
    echo "   RESULT:   SKIPPED — the mutation anchor no longer matches this source."
    echo "             The code moved; update this check rather than ignoring it."
    SKIPPED=$((SKIPPED + 1))
    restore_all
    return 0
  fi

  # The mutated tree must still COMPILE — a mutation that only breaks the
  # build proves nothing about the test.
  if ! cargo test "$@" --no-run >/dev/null 2>&1; then
    echo "   RESULT:   SKIPPED — the mutated tree does not compile."
    echo "             A compile error is not evidence that the test catches the defect."
    SKIPPED=$((SKIPPED + 1))
    restore_all
    return 0
  fi

  if cargo test "$@" >/dev/null 2>&1; then
    echo "   RESULT:   *** SURVIVING MUTANT *** the test still passes without the protection."
    SURVIVED=$((SURVIVED + 1))
    SURVIVORS+=("$name")
  else
    echo "   RESULT:   killed — the test fails without the protection, as it must."
    PASSED=$((PASSED + 1))
  fi
  restore_all
}

FILTER="${*:-}"

echo "Mutation checks for the load-bearing security properties"
echo "========================================================"

# ---------------------------------------------------------------------------
# BLOCKER 1 — no repository-controlled execution during a scan
# ---------------------------------------------------------------------------

# Put the git subprocess back into the automatic scan path: `discover` again
# asks git whether each file is tracked, which is what let a hostile
# `core.fsmonitor` run (ZFT-001).
mutate "scan-uses-gitsafe-not-git" \
  "crates/core/src/envgov.rs" \
  's = s.replace(
      "    let repo = crate::gitsafe::RepoView::open(&root);",
      "    let _ = std::process::Command::new(\"git\").current_dir(std::env::temp_dir()).arg(\"-C\").arg(&root).args([\"ls-files\", \"--error-unmatch\", \"--\", \".env\"]).output();\n    let repo = crate::gitsafe::RepoView::open(&root);")' \
  -p api-tracker-core --test git_execution_canaries scanning_never_executes

# Point Git back at the REAL repository instead of the sealed directory
# (ADR 0027). This is the whole of RA-001 in one line: the repository's own
# `.git/config` becomes part of the repository Git is reading, and
# `log.showSignature` + `gpg.program` execute its chosen binary.
#
# This mutant replaced "hardened-git-disables-fsmonitor", which removed
# `-c core.fsmonitor=false` from the enumeration. That mutant now SURVIVES,
# and correctly so: the enumeration is no longer the control. Deleting it
# without replacement would have quietly reduced this suite's coverage of
# the very defect the re-audit found, so it is repointed at the protection
# that actually holds the property today.
# Both layers are removed together, deliberately. Removing either ALONE
# leaves the other holding, which is the point of defence in depth and is
# not something to mutate away one at a time; a single-layer mutant would
# survive and read as "unpinned" when the property is in fact intact.
# `sealing_alone_closes_every_vector` is what proves layer 1 carries its own
# weight, with no `-c` override in play.
mutate "sealed-gitdir-isolates-repository-config" \
  "crates/core/src/gitrepo.rs" \
  's = s.replace(
      "    cmd.args(hardened_leading_args());\n    cmd.arg(\"--git-dir\").arg(sealed.git_dir());",
      "    cmd.arg(\"--no-pager\");\n    cmd.arg(\"-C\").arg(sealed.work_tree());")' \
  -p api-tracker-core --test git_isolation_canaries no_product_path_executes

# Remove the symlink refusal from the manifest reader (ZFT-002).
mutate "stackdetect-refuses-symlinks" \
  "crates/core/src/stackdetect.rs" \
  's = s.replace(
      "    if meta.file_type().is_symlink() {\n        counters.skipped_outside_folder += 1;\n        return None;\n    }\n",
      "")' \
  -p api-tracker-tracking --test scan_bounds

# Remove the size check that happens BEFORE the file is opened (ZFT-003).
mutate "env-size-cap-precedes-the-read" \
  "crates/core/src/envgov.rs" \
  's = s.replace(
      "if size > limits.max_file_bytes {",
      "if false && size > limits.max_file_bytes {")' \
  -p api-tracker-tracking --test scan_bounds

# ---------------------------------------------------------------------------
# BLOCKER 2 — repository content is not authorization
# ---------------------------------------------------------------------------

# Put the pre-filled origin back into the defaults: exactly the ZFT-004
# construction, where the confirmation is satisfied by the code that should
# be asking for it.
mutate "defaults-exclude-repository-origins" \
  "crates/tracking/src/plan.rs" \
  's = s.replace(
      "            if matches!(p.configurability, Configurability::Automatic)\n                && p.confidence >= DetectionConfidence::Likely\n            {\n                sel.include.insert(p.provider_id.clone());\n            }",
      "            if p.confidence >= DetectionConfidence::Likely {\n                sel.include.insert(p.provider_id.clone());\n                if let Configurability::NeedsOriginConfirm { inferred_origin } = &p.configurability {\n                    sel.confirmed_origins.insert(p.provider_id.clone(), inferred_origin.clone());\n                }\n            }")' \
  -p api-tracker-tracking --test origin_trust

# Accept a tampered approval row.
mutate "approval-mac-is-verified" \
  "crates/tracking/src/origin.rs" \
  's = s.replace(
      "    if expected.as_bytes().ct_eq(stored_mac.as_bytes()).unwrap_u8() != 1 {\n        return Ok(None);\n    }",
      "")' \
  -p api-tracker-tracking --test origin_trust tampered

# ---------------------------------------------------------------------------
# BLOCKER 3 — current health is not historical verification
# ---------------------------------------------------------------------------

# Ignore gateway liveness: the ZFT-005 defect exactly.
mutate "liveness-gates-verified-and-active" \
  "crates/tracking/src/state.rs" \
  's = s.replace(
      "    match liveness {\n        GatewayLiveness::Down => {",
      "    match GatewayLiveness::Verified {\n        GatewayLiveness::Down => {")' \
  -p api-tracker-tracking --test verification_freshness

# Drop the freshness bounds entirely: any observation, however old and
# however implausibly dated, proves health.
mutate "observation-freshness-window" \
  "crates/tracking/src/state.rs" \
  's = s.replace(
      "            fresh: last_observed_at\n                .as_deref()\n                .is_some_and(|at| at >= stale_before.as_str() && at <= future_after.as_str()),",
      "            fresh: last_observed_at.is_some(),")' \
  -p api-tracker-tracking --test verification_freshness

# Drop ONLY the upper bound, leaving the lower one: exactly the audited-head
# predicate, which read a year-ahead observation as a present-tense success
# and let it erase a failure recorded now (RA-005).
# Both upper bounds go together, for the same reason as the sealed-gitdir
# mutant above: the SQL bound and the `fresh` predicate are independent
# layers, and removing one alone leaves the other holding.
mutate "observation-freshness-upper-bound" \
  "crates/tracking/src/state.rs" \
  's = s.replace(
      "                .is_some_and(|at| at >= stale_before.as_str() && at <= future_after.as_str()),",
      "                .is_some_and(|at| at >= stale_before.as_str()),")
s = s.replace(
      "               AND rowid > ?2 AND at >= ?3 AND at <= ?4",
      "               AND rowid > ?2 AND at >= ?3 AND ?4 IS NOT NULL")' \
  -p api-tracker-tracking --test verification_clock

# Drop the insertion-ordered watermark from the admissibility query, leaving
# only the wall-clock conditions (RA-005). A row recorded BEFORE the apply
# then verifies it, however it is dated.
mutate "observation-insertion-watermark" \
  "crates/tracking/src/state.rs" \
  's = s.replace(
      "               AND rowid > ?2 AND at >= ?3 AND at <= ?4",
      "               AND rowid > -1 AND at >= ?3 AND at <= ?4")' \
  -p api-tracker-tracking --test verification_clock

# Compare failure and observation timestamps as BYTES again rather than as
# parsed instants (RA-005): `12:00:00.5Z` sorts before `12:00:00Z`.
mutate "failure-ordering-uses-parsed-instants" \
  "crates/tracking/src/state.rs" \
  's = s.replace(
      "        (Some(failed), Some(seen)) => instant_is_after(failed, seen),",
      "        (Some(failed), Some(seen)) => failed.as_str() > seen.as_str(),")' \
  -p api-tracker-tracking --test verification_clock

# Stop clearing the previous attempt'"'"'s apply artifacts on re-run (ZFT-006).
mutate "re-apply-clears-previous-session" \
  "crates/tracking/src/state.rs" \
  's = s.replace(
      "             plan_summary_json = NULL,\n             applied_at = NULL,\n             first_traffic_at = NULL",
      "             plan_summary_json = tracking_setups.plan_summary_json,\n             applied_at = tracking_setups.applied_at,\n             first_traffic_at = tracking_setups.first_traffic_at")' \
  -p api-tracker-tracking --test verification_freshness

# Let an older observation outrank a newer failure (ZFT-006).
mutate "newer-failure-outranks-older-success" \
  "crates/tracking/src/state.rs" \
  's = s.replace(
      "    let failure_is_newer = match (&setup.attention_at, &newest_observation) {",
      "    let failure_is_newer = false; #[allow(unreachable_code)] let _unused = match (&setup.attention_at, &newest_observation) {")' \
  -p api-tracker-tracking --test verification_freshness

# Restore the early return that skipped derivation entirely (ZFT-008).
mutate "missing-watermark-forces-downgrade" \
  "crates/tracking/src/state.rs" \
  's = s.replace(
      "    if !watchable || providers.is_empty() || setup.applied_at.is_none() {\n        let overclaiming = matches!(",
      "    if !watchable || providers.is_empty() || setup.applied_at.is_none() {\n        let overclaiming = false && matches!(")' \
  -p api-tracker-tracking --test verification_freshness

# Ignore route/link disappearance.
mutate "route-and-link-existence-gate-health" \
  "crates/tracking/src/state.rs" \
  's = s.replace(
      "    if !missing.is_empty() {",
      "    if false && !missing.is_empty() {")' \
  -p api-tracker-tracking --test verification_freshness

# Put back the undo default that reported success after doing nothing.
mutate "undo-refuses-when-the-plan-is-unknown" \
  "crates/tracking/src/undo.rs" \
  's = s.replace(
      "    if plan_incomplete && !live_links.is_empty() {\n        complete = false;",
      "    if false && plan_incomplete && !live_links.is_empty() {\n        complete = false;")' \
  -p api-tracker-tracking --test undo_ground_truth

# ---------------------------------------------------------------------------
# Privacy — nothing secret reaches plaintext storage or stdout
# ---------------------------------------------------------------------------

# Stop sealing recorded prior values (ADR 0028): they go into
# `prior_env_json` — a plaintext column of an unencrypted database — exactly
# as RA-006 found them.
#
# This mutant replaced "prior-env-refuses-query-material", which neutered
# `prior_value_is_recordable`. That mutant now SURVIVES, and correctly so:
# the predicate no longer gates storage, because deciding secrecy from a
# value's shape is what RA-006 proved unsound. Repointed rather than
# deleted, so the privacy property stays pinned by something.
mutate "prior-env-values-are-sealed" \
  "crates/gateway/src/envlink.rs" \
  's = s.replace(
      "            let plaintext = var.prior.take();",
      "            let plaintext = var.prior.clone();")' \
  -p api-tracker-gateway --test restore_record_privacy no_recorded_prior_value

# Put the placeholder exemption back into the masker: the ZFT-017 defect,
# where a host containing "example" printed the whole line.
# Put the ZFT-017 defect back at its source: `is_placeholder_value` becomes
# a bare substring test again, so a host containing "example" satisfies it.
mutate "placeholder-test-is-not-a-bare-substring-match" \
  "crates/core/src/scanner.rs" \
  's = s.replace(
      "    if looks_like_key_material(v) {\n        return false;\n    }",
      "")' \
  -p api-tracker-core --test scanning

# And the regression an adversarial reviewer caught in the FIRST fix: a
# length-based denylist that printed short credentials the original code
# masked.
mutate "diff-masking-is-not-a-length-denylist" \
  "crates/core/src/envgov.rs" \
  's = s.replace(
      "    if name_suggests_a_credential(name) {",
      "    if value.chars().count() <= 16 && !crate::scanner::looks_like_key_material(value) {\n        return line.to_string();\n    }\n    if name_suggests_a_credential(name) {")' \
  -p api-tracker-core --test scanning

# ---------------------------------------------------------------------------
# BLOCKER 4 — one environment cannot control another
# ---------------------------------------------------------------------------

# The ownership proof is the half that actually blocks the destructive
# verbs; the id alone only makes the slots distinct.
mutate "destructive-verbs-prove-ownership" \
  "crates/gateway/src/lifecycle/macos.rs" \
  's = s.replace(
      "        self.ensure_ours(\"unregister the service\")?;\n",
      "")' \
  -p api-tracker-gateway --test service_namespace

mutate "repair-does-not-force-past-the-ownership-refusal" \
  "crates/gateway/src/lifecycle/mod.rs" \
  's = s.replace(
      "        self.install(source_binary, false)",
      "        self.install(source_binary, true)")' \
  -p api-tracker-gateway --test service_namespace repair_

mutate "planner-stops-on-a-foreign-service-slot" \
  "crates/tracking/src/plan.rs" \
  's = s.replace(
      "    if service.installed && !service.matches_data_dir {",
      "    if false && service.installed && !service.matches_data_dir {")' \
  -p api-tracker-tracking --test origin_trust planning_refuses

mutate "service-identity-is-namespaced" \
  "crates/gateway/src/lifecycle/mod.rs" \
  's = s.replace(
      "pub fn installation_id(data_dir: &Path) -> String {",
      "pub fn installation_id(_ignored: &Path) -> String { return \"fixedglobal00\".to_string(); }\n#[allow(dead_code)]\nfn installation_id_real(data_dir: &Path) -> String {")' \
  -p api-tracker-gateway --test service_namespace

# ---------------------------------------------------------------------------
# Honest coverage — unknown APIs must stay visible
# ---------------------------------------------------------------------------

mutate "unknown-credentials-stay-visible" \
  "crates/tracking/src/detect.rs" \
  's = s.replace(
      "    let unrecognized: Vec<UnrecognizedCredential> = unattributed.into_values().collect();",
      "    let unrecognized: Vec<UnrecognizedCredential> = Vec::new(); let _ = unattributed;")' \
  -p api-tracker-tracking --test detect_coverage

# ---------------------------------------------------------------------------
# The latest fresh audit (2026-07-29). Every one of these protections had a
# test that could not fail: the constant nothing contended for, the one health
# write with no predicate, the provenance a failed apply never recorded, the
# swallowed transition error, the CAS that ran after the destruction it was
# meant to guard, and the row label that used a different precedence from the
# headline that counted it.
# ---------------------------------------------------------------------------

# NEW-05: three attempts and one attempt were indistinguishable, because no
# test created enough contention to need a second.
mutate "refresh-retries-a-lost-compare-and-swap" \
  "crates/tracking/src/state.rs" \
  's = s.replace(
      "const REFRESH_CAS_ATTEMPTS: usize = 3;",
      "const REFRESH_CAS_ATTEMPTS: usize = 1;")' \
  -p api-tracker-tracking --test verification_cas_retry

# NEW-31: `record_applied` advanced the row version without predicating on it,
# so two concurrent applies were last-writer-wins and undo then acted on the
# wrong created_routes.
mutate "record-applied-predicates-on-the-row-it-read" \
  "crates/tracking/src/state.rs" \
  's = s.replace("AND row_version = ?5", "")' \
  -p api-tracker-tracking --test transaction_recovery

# NEW-32: a failed apply wrote no plan summary, so the retry's undo reported
# "existed before this setup (only reused)" for routes it had created itself.
mutate "a-failed-apply-still-records-what-it-created" \
  "crates/tracking/src/apply.rs" \
  's = s.replace(
      "state::record_routes_created(",
      "(|_: &_, _: &mut _, _: &_, _: &_| -> api_tracker_core::Result<()> { Ok(()) })(")' \
  -p api-tracker-tracking --test transaction_recovery

# NEW-34: undo destroyed the setup before its compare-and-swap, so a stale
# undo tore down a live one.
mutate "undo-checks-the-row-version-before-it-destroys" \
  "crates/tracking/src/undo.rs" \
  's = s.replace("    if live.row_version != setup.row_version {",
                 "    if false && live.row_version != setup.row_version {")' \
  -p api-tracker-tracking --test transaction_recovery

# NEW-43: the headline ranked confidence first while the row labels did not,
# so six rows could render under a headline that said three.
mutate "row-labels-use-the-headline-precedence" \
  "crates/tracking/src/detect.rs" \
  's = s.replace(
      "        if self.confidence < DetectionConfidence::Likely {",
      "        if false && self.confidence < DetectionConfidence::Likely {")' \
  -p api-tracker-tracking --test detect_coverage

echo
echo "========================================================"
echo "killed (protection is genuinely pinned): $PASSED"
echo "skipped (anchor moved or build broke):   $SKIPPED"
echo "SURVIVING MUTANTS:                       $SURVIVED"
if [ "$SURVIVED" -gt 0 ]; then
  echo
  echo "These protections are NOT pinned by the tests that claim to cover them:"
  for s in "${SURVIVORS[@]}"; do echo "  - $s"; done
  exit 1
fi
if [ "$SKIPPED" -gt 0 ]; then
  echo
  echo "Skipped checks are a failure of THIS script, not of the product, but they"
  echo "mean the listed protections went unverified on this run."
  exit 1
fi
echo "All mutation checks killed."
