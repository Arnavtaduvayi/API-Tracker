#!/usr/bin/env bash
# Packaged macOS end-to-end validation of ZERO-FRICTION TRACKING.
#
#   scripts/tracking_validate_macos.sh [--scope full|offline|selfcheck]
#                                      [--foreground|--require-service]
#                                      [path/to/Tethra.app]
#
# ---------------------------------------------------------------------------
# WHAT THIS SCRIPT PROVES, AND WHAT IT DOES NOT (read before quoting a total)
# ---------------------------------------------------------------------------
# The 2026-07-27 independent audit (ZFT-VAL-*) found that this harness could
# report a large, confident-looking total while several of the counted checks
# were incapable of failing, and while the weaker of its two execution modes
# produced the SAME total as the stronger one. Everything below is structured
# to make both of those impossible rather than merely discouraged.
#
# PROVES (when the run reports scope=full):
#   * the packaged app carries a runnable helper whose MEASURED version and
#     MEASURED bytes match the sidecar built from this source tree — the
#     version is compared, never stamped;
#   * `tethra track` configures a fixture project end to end with no manual
#     route / link / attribution step, driven only by the in-bundle helper
#     with every developer CLI stripped off PATH;
#   * verification cannot pass without observed traffic. This is pinned by a
#     real forged-event negative control: an otherwise-valid gateway
#     observation for the right provider host is INSERTED with a timestamp
#     before `applied_at` and must not verify anything. Its matching positive
#     is the genuine request later in the run — same host, same source, newer
#     timestamp — which does verify;
#   * `track undo` restores the .env byte for byte, compared with cmp(1) on
#     the real files, so trailing-newline drift is caught;
#   * neither the credential value nor an unrelated env value (the canary)
#     reaches the database, its WAL/SHM, the gateway log, anything else in
#     the isolated data directory, or the shared desktop/CLI data directory.
#     Both greps are proven falsifiable first, by finding the same needles in
#     the fixture that legitimately contains them.
#
# DOES NOT PROVE:
#   * `--scope offline` runs NO gateway and makes NO network request. It
#     proves packaging, helper execution, PATH isolation and dry-run
#     inertness only. Everything else is listed as NOT RUN HERE.
#   * `--foreground` never registers a LaunchAgent. It asserts that the
#     LaunchAgents directory is byte-identical before and after, which is a
#     real statement about not damaging user state — and is emphatically NOT
#     a statement that login registration works. Only `--require-service`
#     exercises that, and it refuses to run rather than quietly downgrade.
#     Service names are now namespaced per data directory (ADR 0026), so a
#     second Tethra environment no longer collides with a first. That is a
#     product fix, not a licence for this script to install a login agent on
#     a developer's machine: `--scope full` refuses to start — in EITHER
#     mode — when ANY Tethra LaunchAgent is already present, because a
#     machine that already runs Tethra is not a clean room, a pre-namespacing
#     legacy agent would trigger the takeover migration, and a run that
#     succeeds only because the machine happened to be clean is not evidence.
#     Use `--scope offline` there.
#   * the totals for the modes DIFFER BY CONSTRUCTION (foreground 57,
#     service 59, offline 20, selfcheck 5). A foreground run therefore can
#     never be mistaken for, or quoted as, a service run. Those four numbers
#     are SUMMED from the group table below, never typed in: `full:service`
#     was once typed as 60 while its groups sum to 59, which made the mode
#     unpassable with every one of its assertions green (RA-003).
#   * this is a macOS harness. Windows and Linux packaging are not covered.
#
# ANTI-VACUITY MECHANICS:
#   * `set -uo pipefail`, deliberately no `set -e` (failures are counted, not
#     aborted). No `|| true`, no `set +e`, no trailing `exit 0`.
#   * every check goes through ok()/bad(); nothing is ever awarded for
#     entering a mode, writing a fixture, or reaching a line.
#   * the HARNESS group is a mutation test OF THIS SCRIPT: it feeds
#     deliberately false controls through the very same primitives the real
#     checks use — unmodified, nothing diverted — and requires the harness to
#     report them as FAILURES (and deliberately true ones as PASSES). A
#     mismatch ABORTS rather than being tallied, because a weakened bad()
#     cannot be trusted to report its own weakening. A harness that always
#     says "ok" — the exact defect ZFT-VAL-7 found — dies in its own first
#     group. `--scope selfcheck` runs that group alone and needs no app
#     bundle, so CI gates on it in seconds.
#     Verified by mutation, each of these killed by the HARNESS group:
#       bad() prints PASS and counts a pass | bad() is a silent no-op |
#       check() always calls ok() | assert_db() always passes |
#       assert_same_bytes() always passes | assert_same_bytes() reverts to
#       `[ "$(cat a)" = "$(cat b)" ]` (the literal ZFT-VAL-10 defect).
#     Deleting the group itself is killed by the count-equality gate below.
#   * the final gate asserts that the executed check count EQUALS the count
#     this scope+mode is defined to run, PER GROUP as well as in total. A
#     floor catches only truncation; equality also catches a check
#     disappearing into a conditional, which is how a mode downgrade used to
#     keep the same total (ZFT-VAL-4), and the per-group form also catches
#     two drifts that cancel out in the sum.
#   * the count a run is measured against is not a number a human maintains.
#     `--scope selfcheck` ENUMERATES this file — it walks the scope/mode
#     conditionals and counts the checks each of the four scope+mode
#     combinations can actually execute — and aborts unless the group table
#     matches the source. That runs in CI, so the drift that made
#     `full:service` unpassable (RA-003) is now caught mechanically on every
#     PR instead of by a human recounting a comment.
#
# Routes point at REAL provider origins with FAKE keys: a 401 proves
# DNS -> gateway -> TLS -> provider. Synthetic local upstreams are
# structurally impossible for a packaged binary (SI-3 refuses loopback
# origins), so those behaviors stay covered by the in-process suites.
#
# Isolated: a short TETHRA_DIR under /tmp (the control socket needs a
# sun_path under ~104 bytes), a throwaway vault, fake credentials. It never
# removes a LaunchAgent it did not install, and always cleans up after
# itself.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Resolved before PATH is stripped, because rustc lives in ~/.cargo/bin.
TRIPLE="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
if [ -z "$TRIPLE" ]; then
  case "$(uname -m)" in
    arm64|aarch64) TRIPLE="aarch64-apple-darwin" ;;
    *)             TRIPLE="x86_64-apple-darwin" ;;
  esac
fi

# --- arguments -------------------------------------------------------------
SCOPE="full"
# The mode is never inferred from machine state. The old script silently
# switched to foreground when a LaunchAgent already existed and still
# reported the same total, so "42/42" was numerically identical in the strong
# and the weak configuration (ZFT-VAL-4).
MODE="foreground"
APP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --scope)           SCOPE="${2:-}"; shift 2 ;;
    --scope=*)         SCOPE="${1#--scope=}"; shift ;;
    --foreground)      MODE="foreground"; shift ;;
    --require-service) MODE="service"; shift ;;
    --self-check|--selfcheck) SCOPE="selfcheck"; shift ;;
    # The whole header — the mode/scope table and the proves/does-not-prove
    # list ARE the help — up to (not including) the first line of code. The
    # cut point is COMPUTED rather than written down: `sed -n '1,89p'` kept
    # printing 89 lines after the header grew past 89, so it silently dropped
    # the isolation/cleanup disclosure (RA-015). A help text that truncates
    # itself stops disclosing exactly what a reader opened it for.
    -h|--help)         awk '!/^#/ { exit } { print }' "$0"; exit 0 ;;
    -*)                echo "unknown option: $1" >&2; exit 2 ;;
    *)                 APP="$1"; shift ;;
  esac
done
[ -n "$APP" ] || APP="$REPO_ROOT/target/release/bundle/macos/Tethra.app"
case "$SCOPE" in
  full|offline|selfcheck) ;;
  *) echo "unknown --scope '$SCOPE' (expected full, offline or selfcheck)" >&2; exit 2 ;;
esac
# offline and selfcheck start no gateway at all, so neither mode word applies.
[ "$SCOPE" = "full" ] || MODE="none"

# --- the check inventory ---------------------------------------------------
# How many checks each scope+mode is DEFINED to execute. The summary refuses
# to report a quotable result unless the measured count matches, so a check
# that quietly stops running is a hard failure rather than a smaller number
# nobody notices.
#
# ONE number per group lives here, and every total is SUMMED from it. No
# per-mode total is written down any more: `full:service` was written down as
# 60 while the groups it runs sum to 59, so that mode was unpassable BY
# CONSTRUCTION — all 59 of its assertions could pass and the gate would still
# print INCONCLUSIVE and exit 1 (RA-003). The mode that drifted is precisely
# the mode that cannot be run on a machine that already has Tethra installed,
# which is why a hand-maintained total is the wrong instrument: the arithmetic
# is done below, and verify_check_inventory() proves this table against the
# conditionals in this file before any check runs.
#
# Two former BUNDLE "checks" are uncounted PRECONDITIONS (a `check` followed
# by `die` on the failing branch can never be reported as a failure), which is
# why BUNDLE is 5 and offline is 20 rather than 22.
group_size() {   # group_size <GROUP> -> the number of checks that group runs
  case "$1" in
    HARNESS)     echo 5 ;;
    BUNDLE)      echo 5 ;;
    FIXTURE)     echo 3 ;;
    DRYRUN)      echo 6 ;;
    OFFLINE)     echo 1 ;;
    FOREGROUND)  echo 3 ;;
    SERVICE)     echo 5 ;;
    APPLY)       echo 9 ;;
    NEGATIVE)    echo 8 ;;
    TRAFFIC)     echo 5 ;;
    PRIVACY)     echo 5 ;;
    IDEMPOTENCE) echo 4 ;;
    UNDO)        echo 4 ;;
    *) echo "internal error: no declared size for group '$1'" >&2; return 2 ;;
  esac
}
# Which groups each scope+mode is defined to run. This is the OTHER half of
# the arithmetic, and it is verified the same way — enumerate_checks() decides
# which groups a scope+mode reaches by reading the conditionals, not this
# list, so a wrong entry here is a mismatch rather than a silent redefinition.
scope_groups() {   # scope_groups <scope>:<mode> -> group names, space separated
  case "$1" in
    selfcheck:*)     echo "HARNESS" ;;
    offline:*)       echo "HARNESS BUNDLE FIXTURE DRYRUN OFFLINE" ;;
    full:foreground) echo "HARNESS BUNDLE FIXTURE DRYRUN FOREGROUND APPLY NEGATIVE TRAFFIC PRIVACY IDEMPOTENCE UNDO" ;;
    full:service)    echo "HARNESS BUNDLE FIXTURE DRYRUN SERVICE APPLY NEGATIVE TRAFFIC PRIVACY IDEMPOTENCE UNDO" ;;
  esac
}
expected_total() {   # expected_total <scope>:<mode> -> the enforced check count
  local g n t=0 groups
  groups="$(scope_groups "$1")"
  [ -n "$groups" ] || { echo "internal error: no group list for $1" >&2; return 2; }
  for g in $groups; do
    n="$(group_size "$g")" || return 2
    t=$(( t + n ))
  done
  echo "$t"
}
in_list() {   # in_list <word> <space-separated list>
  case " $2 " in *" $1 "*) return 0 ;; esac
  return 1
}

# THE SELF-TEST. Reads THIS file and counts the checks a given scope+mode can
# actually execute: it attributes every counted call site to the group in
# effect at that line, resolves each `if [ "$SCOPE" ... ]` / `if [ "$MODE"
# ... ]` guard for the combination being enumerated, and collapses the
# branches of a runtime conditional (which emits one check whichever branch
# runs) into one.
#
# It is deliberately fail-closed. A check inside a loop, a runtime if/else
# whose branches emit DIFFERENT numbers of checks, a check invoked in a shape
# it does not recognise, or unbalanced nesting are reported as errors rather
# than guessed at, because each of those would make the enforced total depend
# on machine state — the property this whole file exists to deny. A call site
# that must not be counted carries `#@uncounted` and says why.
enumerate_checks() {   # enumerate_checks <scope> <mode> -> "GROUP=N" lines
  awk -v want_scope="$1" -v want_mode="$2" '
    function fail(msg) { printf "ERROR (line %d): %s\n", NR, msg; errs++ }

    # Quote-aware, so a multi-line SQL string or a multi-line die() message is
    # read as the single logical line it is.
    function nquotes(str,   n, i, c, prev) {
      n = 0; prev = ""
      for (i = 1; i <= length(str); i++) {
        c = substr(str, i, 1)
        if (c == "\"" && prev != "\\") n++
        prev = c
      }
      return n
    }
    # Blank out every double-quoted string before matching, so prose in a
    # label or a die() message can never look like a check or a keyword.
    function blanked(str,   out) { out = str; gsub(/"[^"]*"/, "\"\"", out); return out }

    function all_active(   i) {
      for (i = 1; i <= depth; i++) if (!act[i]) return 0
      return 1
    }
    function push(type, a) {
      depth++
      ftype[depth] = type; act[depth] = a; taken[depth] = a
      nbr[depth] = 0; cnt[depth] = 0; first[depth] = 0; closed[depth] = 0
      if (type == "loop") loops++
    }
    function pop() {
      if (depth == 0) { fail("a closing keyword with nothing open"); return }
      if (ftype[depth] == "loop") loops--
      depth--
    }
    # A branch of a runtime conditional must emit the same number of checks as
    # its siblings, because exactly one of them runs and the enforced total
    # may not depend on which.
    function close_branch(   d) {
      d = depth
      if (d == 0) { fail("a branch keyword outside any conditional"); return }
      if (ftype[d] != "guard") {
        if (nbr[d] == 0) first[d] = cnt[d]
        else if (cnt[d] != first[d])
          fail("the branches of a runtime conditional emit different numbers of checks (" first[d] " vs " cnt[d] "), so the total would depend on machine state")
        act[d] = 0
      }
      nbr[d]++; cnt[d] = 0; closed[d] = 1
    }
    function close_if(   d) {
      d = depth
      if (d == 0) { fail("fi with nothing open"); return }
      close_branch()
      if (ftype[d] == "runtime" && nbr[d] == 1 && first[d] > 0)
        fail("a runtime conditional with no else emits " first[d] " check(s) conditionally")
      pop()
    }
    function close_case(   d) {
      d = depth
      if (d == 0) { fail("esac with nothing open"); return }
      if (!closed[d]) close_branch()
      if (nbr[d] == 1 && first[d] > 0)
        fail("a case with a single arm emits " first[d] " check(s) conditionally")
      pop()
    }
    # Only a bare `[ "$SCOPE" op "value" ]` / `[ "$MODE" op "value" ]` test is
    # decidable here. Anything else is treated as a runtime condition, which
    # is the fail-closed direction: runtime branches must then agree on their
    # check counts.
    function classify(str,   n, f, var, op, val, want) {
      n = split(str, f, /[ \t]+/)
      if (n != 7 || f[2] != "[" || f[6] != "];" || f[7] != "then") return "?"
      var = f[3]; gsub(/"/, "", var); sub(/^\$/, "", var)
      op  = f[4]
      val = f[5]; gsub(/"/, "", val)
      if (var == "SCOPE") want = want_scope
      else if (var == "MODE") want = want_mode
      else return "?"
      if (op == "=")  return (val == want) ? "1" : "0"
      if (op == "!=") return (val != want) ? "1" : "0"
      return "?"
    }
    function site(q, s,   i) {
      if (s ~ /#@uncounted/) return
      if (q ~ ("^" PRIM "[ \t]") || q ~ ("(&&|\\|\\|)[ \t]*" PRIM "[ \t]")) {
        if (loops > 0) fail("a counted check inside a loop makes the total depend on runtime state")
        if (cur == "") fail("a counted check appears before any group statement")
        for (i = 1; i <= depth; i++) cnt[i]++
        if (all_active()) count[cur]++
        return
      }
      if (q ~ ("(;|then|else|do|\\()[ \t]+" PRIM "[ \t]"))
        fail("a check is invoked in a shape this enumerator cannot count; give it its own line, or mark the line #@uncounted and say why")
    }

    function handle(s,   q, lead, v) {
      # Everything above the first `group` statement is definitions and setup;
      # no check can run there, and every function in this file is defined
      # there (asserted just below).
      if (!scanning) {
        if (s !~ /^group [A-Z_]+$/) return
        scanning = 1
      }
      if (s ~ /^[A-Za-z_][A-Za-z0-9_]*\(\)/) {
        fail("a function is defined below the first group statement, where this enumerator assumes only checks live")
        return
      }
      q = blanked(s)
      if (q ~ /^group [A-Z_]+$/) { cur = substr(q, 7); return }

      if (depth > 0 && ftype[depth] == "case" && q ~ /^[^ ()]*\)/) {
        sub(/^[^ ()]*\)[ \t]*/, "", q)
        closed[depth] = 0
      }
      lead = q; sub(/[ \t].*$/, "", lead)

      if (lead == "then") return
      if (lead == "fi")   { close_if();   return }
      if (lead == "esac") { close_case(); return }
      if (lead == "done") { pop();        return }
      if (lead == "elif") {
        close_branch()
        v = classify(s)
        if (ftype[depth] == "guard" && v != "?") {
          act[depth] = (v + 0 && !taken[depth]) ? 1 : 0
          if (act[depth]) taken[depth] = 1
        } else if (ftype[depth] == "guard" || v != "?") {
          fail("an if chain mixes scope/mode guards with runtime conditions")
        }
        return
      }
      if (lead == "else") {
        close_branch()
        if (ftype[depth] == "guard") act[depth] = taken[depth] ? 0 : 1
        sub(/^else[ \t]*/, "", q)
        if (q == "") return
        lead = q; sub(/[ \t].*$/, "", lead)
      }

      if (lead == "if") {
        v = classify(s)
        if (v == "?") push("runtime", 1); else push("guard", v + 0)
      } else if (q ~ /^case[ \t].*[ \t]in$/) {
        push("case", 1)
      } else if (q ~ /^(for|while|until)[ \t].*;[ \t]*do$/) {
        push("loop", 1)
      }

      site(q, s)

      if (q ~ /;;[ \t]*$/)  close_branch()
      if (q ~ /;[ \t]*fi$/) close_if()
    }

    # SQ is a single quote. This program is itself inside single quotes, so it
    # cannot contain one literally.
    BEGIN {
      PRIM = "(ok|bad|check|assert_db|assert_same_bytes|selfcheck)"
      SQ = sprintf("%c", 39)
    }
    {
      if (cont) { buf = buf " " $0 }
      else {
        t = $0; sub(/^[ \t]+/, "", t)
        if (t ~ /^#/ || t == "") next
        buf = $0
      }
      if (buf ~ /\\[ \t]*$/) { sub(/\\[ \t]*$/, " ", buf); cont = 1; next }
      # An unbalanced double quote continues the line as well, which is how a
      # multi-line SQL string stays attached to the assert_db that owns it.
      # Only when no single quote is in play, though: a double quote inside a
      # single-quoted sed script is not a string delimiter, and counting it
      # swallows the rest of the file. The lines that fall out of a string
      # this way are inert fragments (SELECT clauses, prose) — and if one ever
      # is not, it lands as unbalanced nesting or an uncountable check shape,
      # which is an error here rather than a wrong number.
      if (index(buf, SQ) == 0 && nquotes(buf) % 2 == 1) { cont = 1; next }
      cont = 0
      t = buf; buf = ""
      sub(/^[ \t]+/, "", t); sub(/[ \t]+$/, "", t)
      handle(t)
    }
    END {
      if (cont)       fail("a logical line is still open at end of file")
      if (depth != 0) fail("unbalanced if/case/loop nesting at end of file (depth " depth ")")
      if (errs) exit 1
      for (g in count) if (count[g] > 0) printf "%s=%d\n", g, count[g]
    }
  ' "$0"
}

# Compares the table above with what this file can actually execute, for
# EVERY scope+mode — including the ones this run is not executing, because the
# entry that drifted is the one nobody can run on a developer machine.
verify_check_inventory() {
  local tuple scope mode g declared derived rc=0
  for tuple in selfcheck:none offline:none full:foreground full:service; do
    scope="${tuple%%:*}"; mode="${tuple##*:}"
    declared=""
    for g in $(scope_groups "$tuple"); do
      declared="$declared $g=$(group_size "$g")"
    done
    declared="$(printf '%s\n' $declared | sort | tr '\n' ' ')"
    derived="$(enumerate_checks "$scope" "$mode")"
    if [ $? -ne 0 ]; then
      echo "  $tuple — this file could not be enumerated:"
      printf '%s\n' "$derived" | sed 's/^/      /'
      rc=1
      continue
    fi
    derived="$(printf '%s\n' $derived | sort | tr '\n' ' ')"
    if [ "$declared" != "$derived" ]; then
      echo "  $tuple"
      echo "      declared here:   $declared"
      echo "      found in source: $derived"
      rc=1
    fi
  done
  return "$rc"
}

EXPECTED="$(expected_total "$SCOPE:$MODE")" || exit 2

HELPER="$APP/Contents/MacOS/tethra"
INFO_PLIST="$APP/Contents/Info.plist"
SIDECAR="$REPO_ROOT/apps/desktop/src-tauri/binaries/tethra-$TRIPLE"
DIR="/tmp/tethra-track-val-$$"
PROJECT="$DIR/sample-app"
# The byte-exact .env snapshots live OUTSIDE the isolated data directory on
# purpose: they legitimately contain both privacy needles, and the privacy
# search below sweeps everything under $DIR that is not the fixture project.
# Keeping them here means that sweep never has to special-case a harness file
# — the only exclusion is the fixture the product is allowed to read.
COPIES="/tmp/tethra-track-val-copies-$$"
export TETHRA_DIR="$DIR"
export TETHRA_PASSWORD="packaged-validation-password-123"
export API_TRACKER_INSECURE_FAST_KDF=1   # test vault only; never a real one
# The pre-namespacing label. Service names are `dev.api-tracker.gateway.<id>`
# now (ADR 0026), so the interlock below globs for BOTH: checking only the
# legacy name would let a run proceed on a machine whose gateway is already
# namespaced — precisely the machine most likely to be a developer's.
LEGACY_LABEL="dev.api-tracker.gateway"
LA_DIR="$HOME/Library/LaunchAgents"
PLIST="$LA_DIR/$LEGACY_LABEL.plist"

# Every gateway job REGISTERED IN THE LIVE LAUNCHD SESSION, whatever `$HOME`
# says.
#
# The plist globs below are keyed on `$HOME`. `launchctl` is not: it addresses
# `gui/<uid>`, which no `HOME` redirection isolates. The previous audit ran
# `--scope full` with `HOME` pointed at a temp directory — a documented and
# otherwise sensible technique — and that is exactly the shape that walks past
# a `$HOME`-keyed interlock while the damage still lands on the user's real
# service. It was reproduced during this remediation: the run booted the
# machine's live `dev.api-tracker.gateway` out of launchd.
#
# So the interlock asks launchd as well as the filesystem.
registered_gateway_jobs() {
  launchctl list 2>/dev/null \
    | awk -v l="$LEGACY_LABEL" '$3 == l || index($3, l ".") == 1 { print "  " $3 }'
}
FAKE_KEY="sk-proj-PACKAGED-VALIDATION-FAKE-NOT-A-REAL-KEY-0001"
CANARY="TETHRA-CANARY-$$-MUST-NEVER-PERSIST"
# The shared data directory the desktop app and CLI use when TETHRA_DIR is
# unset. An isolated run must leave no trace of itself here.
SHARED_DIR="$HOME/Library/Application Support/api-tracker"

# --- counting --------------------------------------------------------------
# Bash 3.2 (the /bin/bash every macOS ships) has no associative arrays, so the
# per-group counters live in generated variable names. Group names are
# therefore restricted to [A-Z_].
pass=0; fail=0
GROUP="HARNESS"
GROUPS_SEEN=""
# Only suppresses the extra diagnostics a failing assertion prints. It must
# NEVER alter what ok()/bad() report or count: an earlier revision of this
# script short-circuited both at the top when SELFCHECK=1, which meant the
# self-check exercised a code path the real checks never take — and a mutant
# that rewrote bad() into "print PASS, count a pass" survived all five
# harness controls. The controls now run through the unmodified reporting
# path and the verdict is OBSERVED (see selfcheck() below).
SELFCHECK=0

group() {
  GROUP="$1"
  case " $GROUPS_SEEN " in
    *" $1 "*) ;;
    *) GROUPS_SEEN="$GROUPS_SEEN $1" ;;
  esac
}
bump() { eval "G_${GROUP}_$1=\$(( \${G_${GROUP}_$1:-0} + 1 ))"; }

# --- the check register ----------------------------------------------------
# Every counted check records itself here, as it executes, under the group in
# effect. Three things come out of it that a running tally cannot give:
#
#   * a machine-readable result (CI asserts the SCOPE completed, rather than
#     asserting the script exited 0 — those are different statements, and the
#     RA-003 defect was precisely a script that exited on a count gate with
#     every assertion green);
#   * every check has a NAME, and two checks may not share one. A duplicate
#     name makes "which check did not run?" unanswerable, which is the
#     question the per-group equality gate exists to answer;
#   * the register is the evidence that a required check EXECUTED rather than
#     being reported. A check that never ran leaves no row, and the row count
#     is reconciled against the declared inventory below.
#
# RECORD is 0 only inside the harness self-check's own subshells, where a
# control's verdict is captured for inspection rather than counted. Those
# controls must not appear in the register for the same reason they must not
# appear in the tally: they are deliberately-false assertions about nothing.
RESULTS_TSV=""
RECORD=1
record_check() {   # record_check <pass|fail> <label>
  [ -n "$RESULTS_TSV" ] || return 0
  [ "${RECORD:-1}" -eq 1 ] || return 0
  [ "$SELFCHECK" -eq 0 ] || return 0
  printf '%s\t%s\t%s\n' "$GROUP" "$1" "$2" >> "$RESULTS_TSV"
}

ok()  { echo "  PASS  $1"; pass=$((pass+1)); bump pass; record_check pass "$1"; }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); bump fail; record_check fail "$1"; }
# The single funnel every shell-condition check uses.
check() { if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; fi; }
step()  { echo; echo "== $1 =="; }

# `.timeout` rather than `PRAGMA busy_timeout=`: the pragma form ECHOES its
# value on stdout and would prefix every query result. (The harness
# self-check below caught exactly that when this was first written.) The
# timeout matters because the foreground gateway holds the same database.
db()       { sqlite3 -cmd ".timeout 15000" "$DIR/vault.db" "$1" 2>/dev/null; }
db_write() { sqlite3 -cmd ".timeout 15000" "$DIR/vault.db" "$1" >/dev/null 2>&1; }
assert_db() {
  local got; got="$(db "$1")"
  if [ "$got" = "1" ]; then ok "$2"; else bad "$2 (query returned '${got:-<empty/error>}')"; fi
}

# The byte-comparison primitive. `[ "$(cat a)" = "$b" ]` strips trailing
# newlines and so is blind to exactly the drift a "restores byte for byte"
# claim is about (ZFT-VAL-10). cmp(1) on the real files is not.
assert_same_bytes() {
  if cmp -s "$1" "$2"; then
    ok "$3"
  else
    bad "$3"
    if [ "$SELFCHECK" -eq 0 ]; then
      diff "$1" "$2" 2>/dev/null | head -10 | sed 's/^/      /'
      echo "      sizes: $(wc -c < "$1" 2>/dev/null) vs $(wc -c < "$2" 2>/dev/null) bytes"
    fi
  fi
}

# Recursive fixed-string search. Returns 0 when the needle IS present, so the
# same primitive serves both the positive controls (the needle must be found
# where it genuinely is) and the negatives (it must be found nowhere else).
found_in() { grep -rqF -- "$2" "$1" 2>/dev/null; }

# Everything under the isolated data directory except the fixture project,
# which legitimately holds both needles.
isolated_files() { find "$DIR" -type f 2>/dev/null | grep -v "^$PROJECT/"; }

# A content digest of ~/Library/LaunchAgents. Read-only: no launchctl, no
# writes, not even plist parsing — just names and hashes, so "this run
# installed and modified nothing" becomes an assertion instead of a promise.
la_digest() {
  if [ -d "$LA_DIR" ]; then
    find "$LA_DIR" -maxdepth 1 -type f -print 2>/dev/null | sort | while read -r f; do
      shasum -a 256 "$f" 2>/dev/null
    done | shasum -a 256 | awk '{print $1}'
  else
    echo "no-launchagents-directory"
  fi
}

SERVE_PID=""
cleanup() {
  step "cleanup"
  if [ -n "$SERVE_PID" ]; then
    kill "$SERVE_PID" >/dev/null 2>&1
    wait "$SERVE_PID" 2>/dev/null
    echo "  stopped the foreground gateway (pid $SERVE_PID)"
  fi
  # Only ever remove a LaunchAgent this run actually installed.
  # SERVICE_INSTALLED holds the resolved path of the plist THIS run
  # installed, so cleanup removes exactly that and nothing else. It used to
  # boot out `$LABEL` — a variable that no longer exists — and delete the
  # LEGACY path, so a real namespaced agent would have been orphaned.
  if [ "$MODE" = "service" ] && [ -n "${SERVICE_INSTALLED:-}" ]; then
    "$HELPER" gateway uninstall --yes >/dev/null 2>&1
    launchctl bootout "gui/$(id -u)/$(basename "$SERVICE_INSTALLED" .plist)" >/dev/null 2>&1
    rm -f "$SERVICE_INSTALLED"
    echo "  removed the LaunchAgent this run installed: $SERVICE_INSTALLED"
  fi
  rm -rf "$DIR" "$COPIES"
  echo "  cleaned $DIR"
}
trap cleanup EXIT

die() {
  echo
  echo "FATAL: $1"
  echo "=== PACKAGED TRACKING VALIDATION: ABORTED (a precondition failed) ==="
  exit 1
}

echo "=== packaged tracking validation — scope=$SCOPE mode=$MODE ==="
echo "    app:      $APP"
echo "    data dir: $DIR (isolated; removed on exit)"
case "$MODE" in
  foreground)
    echo "    MODE MEANING: the bundled helper's own 'gateway serve' runs as a"
    echo "                  foreground child. LaunchAgent registration is NOT"
    echo "                  exercised and must not be claimed from this run." ;;
  service)
    echo "    MODE MEANING: a REAL per-user LaunchAgent is installed and removed."
    echo "                  --require-service aborts rather than downgrading." ;;
  *)
    echo "    MODE MEANING: no gateway is started and no network request is made." ;;
esac

# ---------------------------------------------------------------------------
# 1. HARNESS — prove this harness is capable of reporting a failure
# ---------------------------------------------------------------------------
# A mutation test of the script itself. Each control is an assertion whose
# truth value is KNOWN, run through the completely unmodified reporting path
# — the same ok()/bad()/check()/assert_db()/assert_same_bytes() every real
# check uses, with nothing diverted and nothing stubbed. The control runs in
# a subshell so its verdict is captured instead of counted; the driver then
# reads back both the printed verdict line and the counter deltas the control
# caused, and demands exactly the pair a working harness must produce.
#
# Two properties make this catch the ZFT-VAL-7 defect rather than merely
# describe it:
#
#   1. Nothing about the control's execution differs from a real check.
#      (An earlier revision short-circuited ok()/bad() when SELFCHECK=1. A
#      mutant that rewrote the *reporting* branch of bad() into "print PASS,
#      count a pass" then survived all five controls, because the self-check
#      never reached that branch. Verified by mutation: it now dies.)
#   2. A mismatch ABORTS the run — it is not reported through bad(). A
#      harness whose bad() has been weakened cannot be trusted to report its
#      own weakening, so the finding must not travel through it. Nothing
#      from an aborted run is quotable.
selfcheck() {   # selfcheck <fail|pass> <label> <command...>
  local want="$1" label="$2"; shift 2
  local p0="$pass" f0="$fail" out verdict got_pass got_fail
  # SELFCHECK=1 silences only the extra diagnostics a failing assertion
  # prints (a diff and a byte count); it does not touch the verdict.
  out="$( SELFCHECK=1; "$@"; printf 'SC-TALLY %d %d\n' "$pass" "$fail" )"
  verdict="$(printf '%s\n' "$out" | awk '/^  (PASS|FAIL)  /{print $1; exit}')"
  got_pass=$(( $(printf '%s\n' "$out" | awk '/^SC-TALLY/{print $2; exit}') - p0 ))
  got_fail=$(( $(printf '%s\n' "$out" | awk '/^SC-TALLY/{print $3; exit}') - f0 ))

  local want_verdict="FAIL" want_pass=0 want_fail=1
  if [ "$want" = "pass" ]; then want_verdict="PASS"; want_pass=1; want_fail=0; fi

  if [ "$verdict" = "$want_verdict" ] && [ "$got_pass" -eq "$want_pass" ] \
     && [ "$got_fail" -eq "$want_fail" ]; then
    ok "$label"
  else
    echo "  BROKEN HARNESS  $label"
    echo "      a control that is KNOWN-$(echo "$want" | tr '[:lower:]' '[:upper:]')ING was reported as:"
    echo "        verdict line   = ${verdict:-<none printed>}   (expected $want_verdict)"
    echo "        pass counter   += $got_pass                   (expected $want_pass)"
    echo "        fail counter   += $got_fail                   (expected $want_fail)"
    printf '%s\n' "$out" | grep -v '^SC-TALLY' | sed 's/^/        /'
    die "the harness does not report verdicts correctly, so it cannot certify
anything about the product. This is deliberately NOT counted as a failed
check: a weakened bad() cannot be trusted to report its own weakening. No
number from this run is quotable."
  fi
}
# Each control writes a sentinel first, so the gate above can prove it was
# actually invoked rather than merely reported on.
sc_false_condition() { : > "$DIR/.gate-ran"; [ 1 -eq 2 ]; check $? "control: 1 equals 2"; }
sc_true_condition()  { [ 1 -eq 1 ]; check $? "control: 1 equals 1"; }
sc_newline_drift()   { assert_same_bytes "$DIR/.sc-a" "$DIR/.sc-b" "control: trailing-newline drift"; }
sc_false_db()        { assert_db "SELECT 1=0" "control: a query returning 0"; }
sc_true_db()         { assert_db "SELECT 1=1" "control: a query returning 1"; }

group HARNESS
step "harness self-check (a harness that cannot fail is caught here)"
mkdir -p "$DIR"
# The register opens here, before the first counted check, so that every check
# this run executes lands in it.
#
# It lives under $COPIES rather than under $DIR, for the same reason the
# byte-exact .env snapshots do: the privacy sweep greps everything under $DIR
# that is not the fixture, and a check LABEL is prose that can legitimately
# contain a needle shape. "no authorization header line and no bearer token is
# stored" matches the sweep's own case-insensitive `Bearer [A-Za-z0-9_-]`
# pattern — so a register inside $DIR would make the privacy check fail on the
# text of the privacy check. Keeping it outside means the sweep needs no new
# exclusion, and the only excluded path stays the fixture the product may read.
mkdir -p "$COPIES"
RESULTS_TSV="$COPIES/checks.tsv"
: > "$RESULTS_TSV"

# THE COUNT'S OWN GUARD.
#
# The count-equality gate at the end of this run is only as good as the table
# it compares against, and that table has already been wrong: `full:service`
# was defined to run 60 checks while the groups it runs sum to 59, so the
# strongest mode could not report a pass with every one of its assertions
# green (RA-003). Nobody noticed, because verifying it by hand means
# recounting 59 call sites on a machine that is allowed to run them.
#
# So nothing here is recounted by hand. The enumerator reads the conditionals
# in this file and reports what each scope+mode can actually execute, for all
# four combinations — not just the one being run — and a disagreement aborts.
# It runs in every scope, so `--scope selfcheck` in CI gates on it in seconds
# without an app bundle. A table that does not describe this file makes every
# total the script could print wrong, which is the same reason the harness
# gate below dies rather than tallying: no number from the run is quotable.
CHECK_INVENTORY_DIFF="$(verify_check_inventory)" || die \
  "the declared check inventory does not describe this file:
$CHECK_INVENTORY_DIFF

Every enforced total is summed from that table, so no number from this run is
quotable until the table and the source agree. Fix whichever one is wrong."
echo "  check inventory (summed from the group table, proved against this file):"
for tuple in selfcheck:none offline:none full:foreground full:service; do
  printf '    %-16s %2d checks\n' "$tuple" "$(expected_total "$tuple")"
done

# THE GUARD'S OWN GUARD.
#
# An adversarial reviewer replaced `selfcheck()` with `selfcheck() { ok "$2"; }`
# and the script still reported "5 passed, 0 failed (5/5 checks), exit 0" —
# the count-equality gate cannot see it, because the count is preserved. So
# the gate that certifies every other check could be disabled by one line,
# which is the same class of defect it exists to catch.
#
# The FIRST attempt at this guard was itself vacuous: it required the
# counters to move by +1 pass / +0 fail, which is exactly what BOTH the real
# `selfcheck` and the `ok "$2"` bypass produce (the real one runs its control
# in a subshell, so the control's own tally never reaches the parent). It is
# recorded here because it is the same mistake twice, and the lesson is that
# a guard must be tested against the mutation it claims to catch.
#
# Two properties actually discriminate:
#
#   1. the gate must RUN the control — a bypass never invokes it at all;
#   2. the gate must REJECT a mismatch — asked to certify a KNOWN-FAILING
#      control as passing, it must abort. A bypass reports success.
#
# The second runs in a subshell so its deliberate abort cannot end this run.
# `#@uncounted` tells the enumerator what the subshell already tells bash: the
# probe's tally never reaches this shell, so it is not one of the 5 HARNESS
# checks. Without the marker the enumerator would refuse to guess and abort.
__probe="$DIR/.gate-ran"
rm -f "$__probe"
if ( RECORD=0; selfcheck pass "gate probe (must not be reported)" sc_false_condition ) >/dev/null 2>&1  #@uncounted
then
  die "the harness self-check gate ACCEPTED a known-failing control as a pass.
That means the gate is not evaluating verdicts at all — a selfcheck()
replaced by a bare ok() produces exactly this, and the count-equality gate
cannot see it because the count is preserved.
No number from this run is quotable."
fi
if [ ! -f "$__probe" ]; then
  die "the harness self-check gate did not RUN its control (the sentinel
$__probe was never created). A gate that does not execute what it certifies
certifies nothing.
No number from this run is quotable."
fi
rm -f "$__probe"
unset __probe

selfcheck fail "a known-false shell condition is reported as a FAILURE" sc_false_condition
selfcheck pass "a known-true shell condition is reported as a PASS"     sc_true_condition

# The trailing-newline mutation: the concrete defect ZFT-VAL-10 named.
# `[ "$(cat a)" = "$(cat b)" ]` scores these two files as identical.
printf 'x\n'   > "$DIR/.sc-a"
printf 'x\n\n' > "$DIR/.sc-b"
selfcheck fail "two files differing only by a trailing newline are reported DIFFERENT" sc_newline_drift
rm -f "$DIR/.sc-a" "$DIR/.sc-b"

if [ "$SCOPE" = "selfcheck" ]; then
  # The database primitive needs only a readable SQLite file, so this mode
  # runs without an app bundle and without a vault — it is a fast CI gate on
  # the harness itself, nothing more.
  sqlite3 "$DIR/vault.db" "CREATE TABLE harness_selfcheck(x INTEGER);" >/dev/null 2>&1
  selfcheck fail "a known-false database assertion is reported as a FAILURE" sc_false_db
  selfcheck pass "a known-true database assertion is reported as a PASS"     sc_true_db
fi

if [ "$SCOPE" != "selfcheck" ]; then

# ---------------------------------------------------------------------------
# 2. BUNDLE — packaging, helper execution, PATH isolation
# ---------------------------------------------------------------------------
group BUNDLE
step "preconditions (a clean machine, packaged app only)"

# PRECONDITION, not a check. This used to `check` and then `die` on the
# failing branch, so it was a pass with probability 1 in any run that got as
# far as printing a total — a counted check that could never be reported as
# a failure is the ZFT-VAL-7 shape wearing a label. It aborts instead, and
# is not tallied.
[ -x "$HELPER" ] || die "no runnable helper inside the app bundle at $HELPER.
The packaged app MUST ship its helper (scripts/bundle_cli.sh + externalBin)."

FILE_OUT="$(file -b "$HELPER" 2>/dev/null)"
ARCH="$(uname -m)"
case "$FILE_OUT" in
  *Mach-O*"$ARCH"*) ok "the helper is a native Mach-O executable for $ARCH" ;;
  *) bad "the helper is not a native Mach-O executable for $ARCH (file said: ${FILE_OUT:-<none>})" ;;
esac

BUNDLE_VER="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$INFO_PLIST" 2>/dev/null)"
[ -n "$BUNDLE_VER" ]
check $? "the app bundle declares a version in Info.plist (${BUNDLE_VER:-<none>})"

# ZFT-VAL-3: "version-matched helper" used to mean `[ -n "$APP_VER" ]`. The
# helper's version is now MEASURED by running the binary, and compared with
# the version the bundle independently declares. Two producers, one value.
APP_VER="$("$HELPER" --version 2>/dev/null | awk '{print $NF}')"
[ -n "$APP_VER" ] && [ "$APP_VER" = "$BUNDLE_VER" ]
check $? "the helper's MEASURED version (${APP_VER:-<none>}) equals the bundle's declared version (${BUNDLE_VER:-<none>})"

# The other half of "version-matched": the same program, not merely the same
# number. bundle_cli.sh stages a byte copy of the release CLI as the Tauri
# sidecar, and Tauri copies that into Contents/MacOS.
assert_same_bytes "$SIDECAR" "$HELPER" \
  "the in-bundle helper is byte-identical to the sidecar staged from this source tree"

# Deliberately strip every place a developer CLI could hide, so nothing but
# the bundled helper can satisfy the run.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
# PRECONDITION, not a check — same reason as the helper check above.
command -v tethra >/dev/null 2>&1 && \
  die "a tethra CLI is still on PATH ($(command -v tethra)); this run would not prove bundling."

"$HELPER" gateway service-probe 2>/dev/null | grep -q "tethra-gateway-service-probe"
check $? "the bundled helper answers the exec probe"

# ---------------------------------------------------------------------------
# 3. FIXTURE
# ---------------------------------------------------------------------------
group FIXTURE
step "fixture project (fake keys only)"
mkdir -p "$PROJECT"
cat > "$PROJECT/.env" <<EOF
# A comment that must survive verbatim
OPENAI_API_KEY=$FAKE_KEY
UNRELATED_SETTING=$CANARY

EOF
cat > "$PROJECT/package.json" <<'EOF'
{ "name": "sample-app", "dependencies": { "openai": "^4.0.0", "dotenv": "^16.0.0" } }
EOF
# A byte-exact copy, not a shell string: every later "unchanged"/"restored"
# claim compares the real files with cmp(1).
mkdir -p "$COPIES"
ENV_BEFORE="$COPIES/env.before"
cp "$PROJECT/.env" "$ENV_BEFORE"

# ZFT-VAL-7 replaced an unconditional "fixture project written ..." pass here.
# These two verify the write AND double as the falsifiability proof for the
# privacy greps far below: the same primitive must find both needles where
# they genuinely are, or its later "found nowhere" verdicts mean nothing.
found_in "$PROJECT/.env" "$FAKE_KEY"
check $? "the fixture .env really contains the fake key (the key search can find a present key)"
found_in "$PROJECT/.env" "$CANARY"
check $? "the fixture .env really contains the canary (the canary search can find a present canary)"

"$HELPER" init >/dev/null 2>&1
INIT_CODE=$?
[ $INIT_CODE -eq 0 ] && [ -f "$DIR/vault.db" ]
check $? "a vault was created through the bundled helper (exit $INIT_CODE)"

# The database half of the harness mutation test, now that a real vault
# exists — assert_db is the primitive behind the database assertions below.
group HARNESS
selfcheck fail "a known-false database assertion is reported as a FAILURE" sc_false_db
selfcheck pass "a known-true database assertion is reported as a PASS"     sc_true_db

# ---------------------------------------------------------------------------
# 4. the gateway, per mode
# ---------------------------------------------------------------------------
LA_BEFORE="$(la_digest)"
if [ "$MODE" = "service" ]; then
  group SERVICE
  step "service mode (a REAL LaunchAgent; --require-service never downgrades)"
  # ZFT-VAL-4: the old script silently switched to foreground here and kept
  # the same total, so the evidence could be quieter than its label. This
  # aborts instead.
  #
  # The interlock is a PRECONDITION, not a check: awarding a counted pass
  # for "the machine happened to be clean" is the shape ZFT-VAL-7 objected
  # to, and this branch used to do exactly that ten lines from the
  # foreground branch that refuses to. It globs for the namespaced names as
  # well as the legacy one — the product writes
  # `dev.api-tracker.gateway.<installation-id>.plist` now (ADR 0026), so
  # checking only the legacy path would wave through the machine most
  # likely to have one.
  EXISTING_AGENTS=""
  for candidate in "$PLIST" "$LA_DIR/$LEGACY_LABEL".*.plist; do
    [ -f "$candidate" ] && EXISTING_AGENTS="$EXISTING_AGENTS
  $candidate"
  done
  REGISTERED="$(registered_gateway_jobs)"
  [ -z "$REGISTERED" ] || EXISTING_AGENTS="$EXISTING_AGENTS
  (registered in launchd, regardless of \$HOME):
$REGISTERED"
  [ -z "$EXISTING_AGENTS" ] || die "a gateway LaunchAgent already exists:$EXISTING_AGENTS

--require-service will not overwrite it and will not downgrade to foreground.
Run this on a machine with no installed Tethra gateway. Passing --foreground
is NOT a workaround: --scope full applies a real configuration whose service
step reaches the same login slot, so it refuses there too.
Use --scope offline (20 checks) instead."
elif [ "$MODE" = "foreground" ]; then
  group FOREGROUND
  step "foreground gateway (the unsigned-build fallback path)"
  # Safety interlock, deliberately NOT a counted check.
  #
  # "Foreground" describes how THIS script starts the gateway; it does not
  # stop `track --yes` further down from reaching the service-lifecycle step.
  # Service names are namespaced per data directory now (ADR 0026), and every
  # destructive verb proves ownership before it runs — so a post-fix helper
  # would hard-stop rather than damage anything. But a PRE-namespacing helper
  # would still boot the user's live gateway out of its slot (ZFT-014, which
  # is exactly what happened during the audit), and a legacy agent pointing at
  # this data directory would be silently migrated. Neither outcome is
  # evidence, and one of them is damage — so refuse before anything is
  # applied, regardless of which helper is under test.
  #
  # A precondition is not a product property: awarding a pass for "the
  # machine happened to be clean" is the shape ZFT-VAL-7 objected to. It
  # aborts loudly instead of being tallied.
  # Glob for the namespaced names as well as the legacy one: a machine whose
  # gateway is ALREADY namespaced is the most likely developer machine, and
  # checking only `$PLIST` would wave it through.
  EXISTING_AGENTS=""
  for candidate in "$PLIST" "$LA_DIR/$LEGACY_LABEL".*.plist; do
    [ -f "$candidate" ] && EXISTING_AGENTS="$EXISTING_AGENTS
  $candidate"
  done
  if [ -n "$EXISTING_AGENTS" ]; then
    die "a gateway LaunchAgent already exists on this machine:$EXISTING_AGENTS

--scope full applies a real configuration and reaches the service-lifecycle
step. Service names are namespaced per data directory now (ADR 0026) and
every destructive verb proves ownership first, so a current helper would
hard-stop rather than damage anything — but a pre-namespacing helper under
test would boot that gateway out of its slot (ZFT-014), and a legacy agent
pointing at this data directory would be migrated. A run that succeeds only
because the machine happened to be clean is not evidence either.
Run '--scope offline' on this machine (20 checks: packaging, helper
execution, PATH isolation and dry-run inertness), or run '--scope full' on a
machine with no installed Tethra gateway."
  fi
  "$HELPER" gateway serve >"$DIR/serve.log" 2>&1 &
  SERVE_PID=$!
  PORT=""
  for _ in $(seq 1 40); do
    sleep 0.5
    PORT="$(db "SELECT port FROM gateway_config WHERE id='gateway'")"
    [ -n "$PORT" ] && break
  done
  if kill -0 "$SERVE_PID" 2>/dev/null && [ -n "$PORT" ]; then
    ok "the bundled helper serves the gateway in the foreground (port $PORT)"
  else
    bad "the foreground gateway did not start"
    sed 's/^/      /' "$DIR/serve.log" 2>/dev/null | head -10
  fi
fi

# ---------------------------------------------------------------------------
# 5. dry run — nothing changes
# ---------------------------------------------------------------------------
group DRYRUN
step "tethra track --dry-run (must change nothing)"
DRY="$("$HELPER" track "$PROJECT" --dry-run 2>&1)"
DRY_CODE=$?
[ $DRY_CODE -eq 0 ]
check $? "the dry run exits 0 (got $DRY_CODE)"
echo "$DRY" | grep -q "openai"
check $? "the dry run detected openai"
echo "$DRY" | grep -q "OPENAI_BASE_URL"
check $? "the dry run showed the exact env diff"
assert_same_bytes "$ENV_BEFORE" "$PROJECT/.env" "the dry run changed the .env not one byte"
echo "$DRY" | grep -qF "$FAKE_KEY" && bad "the dry run printed the key value" \
  || ok "no key value appears in dry-run output"
echo "$DRY" | grep -qF "$CANARY" && bad "the dry run printed the unrelated env value" \
  || ok "no unrelated env value appears in dry-run output"

# The dry run must not have touched the login-item surface either. This
# replaced the old unconditional "the dry run installed no service
# (foreground mode)" free pass (ZFT-VAL-7, line 164 of the audited version).
if [ "$MODE" = "foreground" ]; then
  group FOREGROUND
  [ "$(la_digest)" = "$LA_BEFORE" ]
  check $? "the dry run left ~/Library/LaunchAgents byte-identical"
elif [ "$MODE" = "service" ]; then
  group SERVICE
  [ ! -f "$PLIST" ]
  check $? "the dry run installed no LaunchAgent"
fi

if [ "$SCOPE" = "offline" ]; then
  group OFFLINE
  step "offline scope boundary"
  [ "$(la_digest)" = "$LA_BEFORE" ]
  check $? "no LaunchAgent was installed or modified anywhere in this run"
fi
fi   # end: not selfcheck

# ---------------------------------------------------------------------------
# everything below needs a running gateway and network egress
# ---------------------------------------------------------------------------
if [ "$SCOPE" = "full" ]; then

# --- 6. the one command ----------------------------------------------------
group APPLY
step "tethra track . (one command, no manual route/link/attribution steps)"
TRACK_OUT="$("$HELPER" track "$PROJECT" --yes 2>&1)"
TRACK_CODE=$?
echo "$TRACK_OUT" | sed 's/^/    /'
# Exit 2 = configured but no traffic yet: correct here, because nothing has
# made a request. Exit 0 would mean it verified without traffic.
[ $TRACK_CODE -eq 2 ]
check $? "track exits 2 (configured, awaiting first request) — got $TRACK_CODE"
# ZFT-VAL-7: `grep -qi route` passed on any occurrence, including one inside
# an error message. The route step must be reported AND the run must not have
# emitted an error line.
echo "$TRACK_OUT" | grep -Eq "routes?:? *openai|routes?: .*openai" && \
  ! echo "$TRACK_OUT" | grep -Eqi "^[[:space:]]*(error|failed|could not)"
check $? "the automatic route step is reported and no error line was printed"
grep -q "OPENAI_BASE_URL=http://127.0.0.1:" "$PROJECT/.env"
check $? "the .env now points at the local gateway"
grep -q "^# A comment that must survive verbatim" "$PROJECT/.env"
check $? "the comment survived the rewrite verbatim"
grep -q "NO_PROXY" "$PROJECT/.env"
check $? "NO_PROXY was added for loopback"
echo "$TRACK_OUT" | grep -q "print-export" && bad "track printed shell-export choreography" \
  || ok "no shell-export choreography anywhere in the flow"
assert_db "SELECT COUNT(*)>=1 FROM gateway_routes WHERE route_prefix='openai'" \
  "the openai route exists in the database"
assert_db "SELECT COUNT(*)=1 FROM gateway_project_links" "exactly one project link was created"
assert_db "SELECT COUNT(*)=1 FROM tracking_setups" "one tracking setup was recorded"

if [ "$MODE" = "foreground" ]; then
  group FOREGROUND
  [ "$(la_digest)" = "$LA_BEFORE" ]
  check $? "the apply left ~/Library/LaunchAgents byte-identical (no login item was touched)"
elif [ "$MODE" = "service" ]; then
  group SERVICE
  # Service names are namespaced per data directory (ADR 0026), so the
  # installed file is `dev.api-tracker.gateway.<installation-id>.plist` and
  # its exact name is not knowable here. Resolve it by asking the product —
  # `gateway status --json` reports `service_name` and `definition_path` —
  # and fall back to a glob. Hard-coding the legacy path made this assertion
  # unable to fire AND left cleanup unable to remove what the run installed.
  INSTALLED_PLIST="$("$HELPER" gateway status --json 2>/dev/null \
    | sed -n 's/.*"definition_path":"\([^"]*\)".*/\1/p' | head -1)"
  if [ -z "$INSTALLED_PLIST" ] || [ ! -f "$INSTALLED_PLIST" ]; then
    INSTALLED_PLIST="$(ls -1 "$LA_DIR/$LEGACY_LABEL".*.plist 2>/dev/null | head -1)"
  fi
  [ -n "$INSTALLED_PLIST" ] && [ -f "$INSTALLED_PLIST" ] && SERVICE_INSTALLED="$INSTALLED_PLIST"
  [ -n "${SERVICE_INSTALLED:-}" ]
  check $? "the apply installed a real LaunchAgent (resolved: ${SERVICE_INSTALLED:-none})"
  INSTALLED_LABEL="$(basename "${SERVICE_INSTALLED:-none}" .plist)"
  grep -q "$INSTALLED_LABEL" "${SERVICE_INSTALLED:-/dev/null}" 2>/dev/null
  check $? "the installed LaunchAgent declares its own namespaced label"
  # ADR 0026: the label must be namespaced, not the pre-namespacing global.
  [ "$INSTALLED_LABEL" != "$LEGACY_LABEL" ]
  check $? "the label is namespaced per data directory, not the global one"
  grep -qF "$HELPER" "${SERVICE_INSTALLED:-/dev/null}" 2>/dev/null
  check $? "the installed LaunchAgent runs the bundled helper, not a developer CLI"
fi

# --- 7. negative controls --------------------------------------------------
group NEGATIVE
step "negative control (verification must be impossible without traffic)"
assert_db "SELECT state!='traffic_observed' FROM tracking_setups" \
  "the setup is NOT marked traffic_observed before any request"
assert_db "SELECT first_traffic_at IS NULL FROM tracking_setups" \
  "no first-traffic timestamp exists before any request"
"$HELPER" track status "$PROJECT" >/dev/null 2>&1
[ $? -eq 2 ]
check $? "track status exits 2 while unverified"

# ZFT-VAL-8: this control was advertised in a comment and never implemented —
# the line beneath it was an unconditional `ok`. It is real now.
#
# The forged row is a fully valid gateway observation for the provider host
# that DOES verify this setup (api.openai.com -> openai, source 'gateway',
# this project id), differing from the genuine one later in the run in
# exactly one respect: its timestamp predates applied_at. Delete the
# `at >= applied_at` clause from state::refresh_with and these three
# assertions fail — which is the property "traffic from a previous attempt
# cannot verify a new one" (SI-19 / ZFT-006), tested rather than asserted.
PROJECT_ID="$(db "SELECT project_id FROM tracking_setups LIMIT 1")"
APPLIED="$(db "SELECT applied_at FROM tracking_setups LIMIT 1")"
# Counted BEFORE anything is forged, because the cleanup assertion below has
# to tell this control's residue apart from the product's own history. The
# apply runs a keyless path check THROUGH the gateway, so a real gateway
# observation for this host is normally already recorded a fraction of a
# second BEFORE applied_at is stamped (measured: applied_at
# 2026-07-27T23:04:47.074134Z, observation at 2026-07-27T23:04:46.7567Z).
PRE_APPLY_ROWS="$(db "SELECT COUNT(*) FROM runtime_request_events WHERE at<'$APPLIED'")"
OLD_AT="1999-01-01T00:00:00Z"
FORGE_SESSION="forged-session-$$"
FORGE_EVENT="forged-event-$$"
FORGE_SERVICE="forged-service-$$"
echo "    applied_at = $APPLIED"
echo "    forged event at = $OLD_AT (strictly older, same host, same source)"
echo "    pre-apply observations the product itself recorded = $PRE_APPLY_ROWS"
db_write "INSERT OR IGNORE INTO observed_api_services
            (id, host, provider_id, first_seen_at, last_seen_at)
          VALUES ('$FORGE_SERVICE','api.openai.com','openai','$OLD_AT','$OLD_AT');"
SERVICE_ID="$(db "SELECT id FROM observed_api_services WHERE host='api.openai.com' LIMIT 1")"
db_write "INSERT INTO observation_sessions
            (id, project_id, mode, source, status, started_at)
          VALUES ('$FORGE_SESSION','$PROJECT_ID','proxy','forged_control','ended','$OLD_AT');"
db_write "INSERT INTO runtime_request_events
            (id, session_id, project_id, service_id, at, host, port, method,
             path_template, outcome, protocol, observation_source)
          VALUES ('$FORGE_EVENT','$FORGE_SESSION','$PROJECT_ID','$SERVICE_ID','$OLD_AT',
                  'api.openai.com',443,'GET','/v1/models','completed','https','gateway');"
assert_db "SELECT COUNT(*)=1 FROM runtime_request_events
           WHERE id='$FORGE_EVENT' AND at<'$APPLIED' AND observation_source='gateway'" \
  "the forged pre-apply gateway observation was really inserted (the control is armed)"
"$HELPER" track status "$PROJECT" >/dev/null 2>&1
[ $? -eq 2 ]
check $? "track status STILL exits 2 with a forged pre-apply observation present"
assert_db "SELECT state!='traffic_observed' FROM tracking_setups" \
  "a forged pre-apply observation does not flip the setup to traffic_observed"
assert_db "SELECT first_traffic_at IS NULL FROM tracking_setups" \
  "a forged pre-apply observation does not set the first-traffic timestamp"
db_write "DELETE FROM runtime_request_events WHERE id='$FORGE_EVENT';
          DELETE FROM observation_sessions WHERE id='$FORGE_SESSION';
          DELETE FROM observed_api_services WHERE id='$FORGE_SERVICE';"
# The control must leave behind nothing of its own and everything of the
# product's, so that no assertion below can be satisfied by planted evidence
# and none of the product's real history was destroyed proving it.
#
# RA-002: the second clause of this assertion used to be
# `COUNT(*) FROM runtime_request_events WHERE at<applied_at = 0`, a premise
# the product's own apply contradicts — the keyless path check writes a
# genuine gateway observation ~0.3s before applied_at is stamped, so the
# assertion could not pass on the first `--scope full` run that ever reached
# it, while the forged row it was actually about had been deleted correctly.
# An absolute absence was never the property; the delta against
# $PRE_APPLY_ROWS, captured before the forgery, is.
#
# The first three clauses name the planted rows by id and by session, so a
# survivor cannot hide behind a count. The fourth is a floor rather than an
# equality on purpose: the gateway's writer thread commits in batches (which
# is why the traffic step below waits for its window), so a legitimate
# observation recorded during the apply may still land in the table while
# this control runs. An equality would turn that into a flaky failure; a
# floor still catches the failure mode that matters here — a cleanup DELETE
# wide enough to take the product's own history with it (widen it to
# `WHERE at<applied_at` and this clause fails).
assert_db "SELECT (SELECT COUNT(*) FROM runtime_request_events
                     WHERE id='$FORGE_EVENT' OR session_id='$FORGE_SESSION')=0
              AND (SELECT COUNT(*) FROM observation_sessions WHERE id='$FORGE_SESSION')=0
              AND (SELECT COUNT(*) FROM observed_api_services WHERE id='$FORGE_SERVICE')=0
              AND (SELECT COUNT(*) FROM runtime_request_events WHERE at<'$APPLIED')>=$PRE_APPLY_ROWS" \
  "the control removed exactly what it planted: no forged row survives, and the $PRE_APPLY_ROWS pre-apply observation(s) the product recorded itself are intact"

# --- 8. real traffic -------------------------------------------------------
group TRAFFIC
step "one real request through the gateway (fake key -> provider 401)"
BASE="$(grep '^OPENAI_BASE_URL=' "$PROJECT/.env" | head -1 | cut -d= -f2- | awk '{print $1}')"
echo "    base URL: $BASE"
# Counted BEFORE the request so the assertion below is a delta. "at least one
# row exists" would also be satisfied by the apply's own keyless path check;
# "one more row than a moment ago" can only be satisfied by this request.
EVENTS_BEFORE="$(db "SELECT COUNT(*) FROM runtime_request_events
                     WHERE observation_source='gateway' AND at>='$APPLIED'")"
STATUS="$(curl -s -o /dev/null -w '%{http_code}' -m 30 \
  -H "Authorization: Bearer $FAKE_KEY" "$BASE/models" 2>/dev/null)"
echo "    provider answered: $STATUS"
case "$STATUS" in
  401|403) ok "the provider answered $STATUS through the gateway (path proven end to end)" ;;
  200)     ok "the provider answered 200 through the gateway" ;;
  *)       bad "unexpected status '$STATUS' (no network? the gateway did not forward?)" ;;
esac

# Give the writer thread its batch window.
sleep 8
assert_db "SELECT (SELECT COUNT(*) FROM runtime_request_events
                   WHERE observation_source='gateway' AND at>='$APPLIED') > $EVENTS_BEFORE" \
  "this request added a NEW gateway observation post-dating applied_at (was $EVENTS_BEFORE)"

"$HELPER" track status "$PROJECT" >/dev/null 2>&1
VERIFY_CODE=$?
[ $VERIFY_CODE -eq 0 ]
check $? "track status exits 0 after real traffic (got $VERIFY_CODE)"
assert_db "SELECT state='traffic_observed' FROM tracking_setups" \
  "the setup is marked traffic_observed ONLY after a real request"
assert_db "SELECT first_traffic_at IS NOT NULL FROM tracking_setups" \
  "the first-traffic timestamp is set"

# --- 9. privacy canaries ---------------------------------------------------
group PRIVACY
step "privacy canaries (no secret and no unrelated env value at rest)"
# ZFT-VAL-5 / ZFT-VAL-7: the old loop skipped WAL and SHM silently when they
# were absent, `grep -rq ... "$DIR/logs"` passed identically when that
# directory did not exist, and the canary was advertised but never searched
# for at all. The search is now recursive over the WHOLE isolated data
# directory — database, WAL, SHM, control socket dir, gateway log, everything
# — for BOTH needles, and the inventory is printed so a reader can see
# exactly what was searched.
echo "    searched recursively under $DIR (fixture project excluded):"
isolated_files | sed "s|^$DIR|      .|" | sort
for artifact in vault.db vault.db-wal vault.db-shm serve.log logs; do
  if [ -e "$DIR/$artifact" ]; then echo "      [present] $artifact"
  else                             echo "      [absent ] $artifact"; fi
done

INVENTORY="$(isolated_files)"
[ -n "$INVENTORY" ] && printf '%s\n' "$INVENTORY" | grep -q "/vault.db$"
check $? "the searched inventory is non-empty and includes the vault database"

HITS_KEY="$(grep -rlF -- "$FAKE_KEY" "$DIR" 2>/dev/null | grep -v "^$PROJECT/")"
[ -z "$HITS_KEY" ]
check $? "the API key value appears in no file under the isolated data directory${HITS_KEY:+ — hits: $HITS_KEY}"

HITS_CANARY="$(grep -rlF -- "$CANARY" "$DIR" 2>/dev/null | grep -v "^$PROJECT/")"
[ -z "$HITS_CANARY" ]
check $? "the unrelated env value (canary) appears in no file under the isolated data directory${HITS_CANARY:+ — hits: $HITS_CANARY}"

# ZFT-VAL-7: the old check was a case-sensitive literal "Authorization", so
# lowercase storage would false-pass — while a naive case-insensitive search
# would false-FAIL on the `had_authorization` column name carried in the
# schema text. Match the header LINE form and the bearer prefix instead;
# neither of those appears in a schema.
HITS_HDR="$(grep -rlEi 'authorization[[:space:]]*:|Bearer [A-Za-z0-9_-]' "$DIR" 2>/dev/null | grep -v "^$PROJECT/")"
[ -z "$HITS_HDR" ]
check $? "no authorization header line and no bearer token is stored${HITS_HDR:+ — hits: $HITS_HDR}"

# The isolated run must also leave nothing behind in the shared desktop/CLI
# data directory. Both needles are unique to this PID, so a hit here means a
# TETHRA_DIR escape.
# The absent-directory branch used to award a counted `ok`. That is a
# property of the MACHINE, not of the product — the exact shape this script
# declares out of bounds a few hundred lines up ("awarding a pass for 'the
# machine happened to be clean' is the shape ZFT-VAL-7 objected to"). It was
# the last unconditional pass in the file, and it was found by an
# adversarial reviewer, not by the anti-vacuity gate.
#
# The assertion is now the same either way: the needles are absent from the
# shared directory. An absent directory trivially satisfies that, and the
# label says which case held, so the check is real in both branches.
if [ -d "$SHARED_DIR" ]; then
  ! found_in "$SHARED_DIR" "$FAKE_KEY" && ! found_in "$SHARED_DIR" "$CANARY"
  check $? "neither needle reached the shared desktop/CLI data directory"
else
  [ ! -e "$SHARED_DIR" ]
  check $? "neither needle reached the shared desktop/CLI data directory (it does not exist)"
fi

# --- 10. idempotence -------------------------------------------------------
group IDEMPOTENCE
step "re-running setup is idempotent"
ENV_AFTER_FIRST="$COPIES/env.after-first"
cp "$PROJECT/.env" "$ENV_AFTER_FIRST"
"$HELPER" track "$PROJECT" --yes >/dev/null 2>&1
RERUN_CODE=$?
# ZFT-VAL-7: the second run's exit code was never checked, so a re-run that
# crashed instantly also "changed nothing" and passed all three idempotence
# assertions.
#
# The expected code is 2, not 0, and that is measured behavior rather than a
# convenient one: re-applying opens a NEW verification session, and traffic
# recorded against the previous session must not verify it (ZFT-006 /
# SI-19). So the honest answer for a fresh session with no traffic yet is
# "configured, awaiting first request". A crash would be 1 or 101; a false
# verification would be 0. Both are caught.
[ $RERUN_CODE -eq 2 ]
check $? "the second run exits 2 — a new verification session, not a crash and not a stale pass (got $RERUN_CODE)"
assert_same_bytes "$ENV_AFTER_FIRST" "$PROJECT/.env" "a second run changed the .env not one byte"
assert_db "SELECT COUNT(*)=1 FROM gateway_project_links" "no duplicate link row"
assert_db "SELECT COUNT(*)=1 FROM tracking_setups" "no duplicate tracking setup"

# --- 11. undo --------------------------------------------------------------
group UNDO
step "track undo restores exactly"
"$HELPER" track undo "$PROJECT" --yes >/dev/null 2>&1
UNDO_CODE=$?
[ $UNDO_CODE -eq 0 ]
check $? "track undo exits 0 (got $UNDO_CODE)"
assert_same_bytes "$ENV_BEFORE" "$PROJECT/.env" "undo restored the .env byte for byte (cmp, not string equality)"
assert_db "SELECT COUNT(*)=0 FROM gateway_project_links" "the link row was removed"
assert_db "SELECT COUNT(*)>=1 FROM runtime_request_events" \
  "recorded history was KEPT (undo never deletes the user's data)"

fi   # end: scope=full

# ---------------------------------------------------------------------------
# result
# ---------------------------------------------------------------------------
step "result"
total=$((pass+fail))

echo "  group breakdown (scope=$SCOPE, mode=$MODE):"
for g in $GROUPS_SEEN; do
  eval "gp=\${G_${g}_pass:-0}"
  eval "gf=\${G_${g}_fail:-0}"
  printf '    %-12s %3d checks  (%d passed, %d failed)\n' "$g" "$((gp+gf))" "$gp" "$gf"
done
printf '    %-12s %3d checks  (%d passed, %d failed)\n' "TOTAL" "$total" "$pass" "$fail"

echo
echo "  NOT RUN HERE — do not quote these from this run:"
case "$SCOPE:$MODE" in
  selfcheck:*)
    echo "    - everything except the harness mutation test. This mode proves only"
    echo "      that the harness reports a deliberately-broken control as a failure." ;;
  offline:*)
    echo "    - no gateway was started, no request was made, nothing was verified."
    echo "    - LaunchAgent registration, traffic observation, privacy-at-rest and"
    echo "      undo are NOT covered by this scope. Use --scope full for those." ;;
  full:foreground)
    echo "    - LaunchAgent registration at login is NOT exercised: the gateway ran"
    echo "      as a foreground child process. Service-mode registration is covered"
    echo "      only by --require-service on a machine with no installed agent, plus"
    echo "      the mock-runner lifecycle suite and scripts/gateway_validate_macos.sh."
    echo "    - the desktop GUI is not click-driven; Windows and Linux packaging are"
    echo "      not covered by this macOS harness." ;;
  *)
    echo "    - the desktop GUI is not click-driven; Windows and Linux packaging are"
    echo "      not covered by this macOS harness." ;;
esac

echo
# Equality, not a floor. The old MIN_CHECKS=30 floor detected truncation only;
# equality also detects a check that quietly stopped executing, which is how a
# mode downgrade used to keep the same total (ZFT-VAL-4, ZFT-VAL-7).
#
# Per GROUP as well as in total, and both sides come from the inventory that
# was proved against this file before the first check ran. A total alone
# cannot say WHICH check stopped running, and two drifts that cancel out
# (one group short, another long) leave it unmoved.
# --- the register: duplicate names, and a machine-readable result -----------
# Two checks may not share a name. The per-group equality gate answers "did
# every declared check run?"; a duplicate name makes the follow-up question —
# WHICH one stopped running — unanswerable, because two rows are
# indistinguishable. It is a hard failure rather than a warning for the same
# reason the count gate is: a result nobody can attribute is not quotable.
DUPLICATES=""
if [ -n "$RESULTS_TSV" ] && [ -f "$RESULTS_TSV" ]; then
  DUPLICATES="$(awk -F'\t' '{ key = $1 "\t" $3; n[key]++ }
    END { for (k in n) if (n[k] > 1) printf "      %d x %s\n", n[k], k }' "$RESULTS_TSV")"
fi

# The machine-readable result. CI asserts against THIS rather than against the
# script's exit status, because those are different statements: RA-003 was a
# script that exited non-zero on a count gate with all 59 of its assertions
# green, and the mirror-image failure — exiting 0 having run the wrong scope —
# is exactly what a job that greps for "0 failed" would wave through. The file
# names the scope, the mode, the declared and executed totals, and every check
# by name and verdict, so a caller can require the exact combination it meant
# to run.
if [ -n "${TETHRA_VALIDATION_RESULTS_JSON:-}" ]; then
  RESULTS_VERDICT="PASS"
  [ "$fail" -eq 0 ] || RESULTS_VERDICT="FAIL"
  [ "$total" -eq "$EXPECTED" ] || RESULTS_VERDICT="INCONCLUSIVE"
  [ -z "$DUPLICATES" ] || RESULTS_VERDICT="INCONCLUSIVE"
  {
    echo "{"
    echo "  \"schema\": \"tethra.validation.results/1\","
    echo "  \"scope\": \"$SCOPE\","
    echo "  \"mode\": \"$MODE\","
    echo "  \"verdict\": \"$RESULTS_VERDICT\","
    echo "  \"expected_total\": $EXPECTED,"
    echo "  \"executed_total\": $total,"
    echo "  \"passed\": $pass,"
    echo "  \"failed\": $fail,"
    # Nothing in this harness is ever "skipped": a check either executes and is
    # counted, or the run is INCONCLUSIVE. The field is emitted as a constant 0
    # so a caller can assert on it without having to know that.
    echo "  \"skipped\": 0,"
    echo "  \"duplicate_names\": $(printf '%s' "$DUPLICATES" | grep -c . || true),"
    echo "  \"app\": \"$(printf '%s' "$APP" | sed 's/\\/\\\\/g; s/"/\\"/g')\","
    echo "  \"data_dir\": \"$(printf '%s' "$DIR" | sed 's/\\/\\\\/g; s/"/\\"/g')\","
    echo "  \"service_plist\": \"$(printf '%s' "${SERVICE_INSTALLED:-}" | sed 's/\\/\\\\/g; s/"/\\"/g')\","
    echo "  \"service_label\": \"$(basename "${SERVICE_INSTALLED:-}" .plist 2>/dev/null | sed 's/\\/\\\\/g; s/"/\\"/g')\","
    echo "  \"groups\": ["
    RESULTS_SEP=""
    for g in $(scope_groups "$SCOPE:$MODE"); do
      eval "gp=\${G_${g}_pass:-0}"
      eval "gf=\${G_${g}_fail:-0}"
      printf '%s    {"name": "%s", "expected": %s, "executed": %s, "passed": %s, "failed": %s}' \
        "$RESULTS_SEP" "$g" "$(group_size "$g")" "$((gp + gf))" "$gp" "$gf"
      RESULTS_SEP=",
"
    done
    echo
    echo "  ],"
    echo "  \"checks\": ["
    if [ -f "$RESULTS_TSV" ]; then
      awk -F'\t' '{
        name = $3
        gsub(/\\/, "\\\\", name); gsub(/"/, "\\\"", name)
        printf "%s    {\"group\": \"%s\", \"result\": \"%s\", \"name\": \"%s\"}", sep, $1, $2, name
        sep = ",\n"
      } END { if (NR) printf "\n" }' "$RESULTS_TSV"
    fi
    echo "  ]"
    echo "}"
  } > "$TETHRA_VALIDATION_RESULTS_JSON"
  echo "  machine-readable results written to $TETHRA_VALIDATION_RESULTS_JSON"
fi

GROUP_DIFF=""
if [ -n "$DUPLICATES" ]; then
  GROUP_DIFF="$GROUP_DIFF
      two or more checks share a name, so a missing one cannot be identified:
$DUPLICATES"
fi
for g in $(scope_groups "$SCOPE:$MODE"); do
  eval "gp=\${G_${g}_pass:-0}"
  eval "gf=\${G_${g}_fail:-0}"
  want="$(group_size "$g")"
  [ "$((gp+gf))" -eq "$want" ] || GROUP_DIFF="$GROUP_DIFF
      $g ran $((gp+gf)) checks, defined to run $want"
done
# GROUPS_SEEN records a group the moment its `group` statement runs, so this
# catches a group that reached this scope+mode at all — not only one that
# reported checks.
for g in $GROUPS_SEEN; do
  in_list "$g" "$(scope_groups "$SCOPE:$MODE")" || GROUP_DIFF="$GROUP_DIFF
      $g ran, but $SCOPE:$MODE is not defined to run it"
done
if [ "$total" -ne "$EXPECTED" ] || [ -n "$GROUP_DIFF" ]; then
  echo "=== PACKAGED TRACKING VALIDATION: INCONCLUSIVE ==="
  echo "    scope=$SCOPE mode=$MODE ran $total checks; it is defined to run $EXPECTED."
  [ -n "$GROUP_DIFF" ] && echo "    groups that disagree with the declared inventory:$GROUP_DIFF"
  echo "    A differing count means checks were skipped, added, or made conditional;"
  echo "    the tally ($pass passed, $fail failed) is not quotable until they agree."
  exit 1
fi
echo "=== PACKAGED TRACKING VALIDATION (scope=$SCOPE, mode=$MODE): $pass passed, $fail failed ($total/$EXPECTED checks) ==="
[ "$fail" -eq 0 ]
