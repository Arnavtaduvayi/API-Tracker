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
#   * the totals for the modes DIFFER BY CONSTRUCTION (foreground 59,
#     service 61, offline 22, selfcheck 5). A foreground run therefore can
#     never be mistaken for, or quoted as, a service run.
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
#     this scope+mode is defined to run. A floor catches only truncation;
#     equality also catches a check disappearing into a conditional, which is
#     how a mode downgrade used to keep the same total (ZFT-VAL-4).
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
    # The whole header, up to (not including) `set -uo pipefail` on line 90 —
    # the mode/scope table and the proves/does-not-prove list are the help.
    -h|--help)         sed -n '1,89p' "$0"; exit 0 ;;
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

# How many checks this exact scope+mode is DEFINED to execute. The summary
# refuses to report a quotable result unless the measured count matches, so a
# check that quietly stops running is a hard failure rather than a smaller
# number nobody notices. Update this table in the same commit that adds or
# removes a check.
#
#   HARNESS 5 + BUNDLE 7 + FIXTURE 3 + DRYRUN 6 = 21 (+ OFFLINE 1 = 22)
#   ... + APPLY 9 + NEGATIVE 8 + TRAFFIC 5 + PRIVACY 5
#       + IDEMPOTENCE 4 + UNDO 4                        = 56 common to scope=full
#   ... + FOREGROUND 3 = 59      |      ... + SERVICE 5 = 61
case "$SCOPE:$MODE" in
  selfcheck:*)     EXPECTED=5  ;;
  offline:*)       EXPECTED=22 ;;
  full:foreground) EXPECTED=59 ;;
  full:service)    EXPECTED=61 ;;
  *) echo "internal error: no expected count for $SCOPE:$MODE" >&2; exit 2 ;;
esac

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

ok()  { echo "  PASS  $1"; pass=$((pass+1)); bump pass; }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); bump fail; }
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
  if [ "$MODE" = "service" ] && [ -n "${SERVICE_INSTALLED:-}" ]; then
    "$HELPER" gateway uninstall --yes >/dev/null 2>&1
    launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1
    rm -f "$PLIST"
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
# — the same ok()/bad()/check()/assert_db()/assert_same_bytes() the 54 real
# checks use, with nothing diverted and nothing stubbed. The control runs in
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
sc_false_condition() { [ 1 -eq 2 ]; check $? "control: 1 equals 2"; }
sc_true_condition()  { [ 1 -eq 1 ]; check $? "control: 1 equals 1"; }
sc_newline_drift()   { assert_same_bytes "$DIR/.sc-a" "$DIR/.sc-b" "control: trailing-newline drift"; }
sc_false_db()        { assert_db "SELECT 1=0" "control: a query returning 0"; }
sc_true_db()         { assert_db "SELECT 1=1" "control: a query returning 1"; }

group HARNESS
step "harness self-check (a harness that cannot fail is caught here)"
mkdir -p "$DIR"
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

[ -x "$HELPER" ]
check $? "the packaged app contains an executable helper at Contents/MacOS/tethra"
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
! command -v tethra >/dev/null 2>&1
check $? "no tethra CLI is reachable on the stripped PATH"
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
# exists — assert_db is the primitive behind 17 of the checks below.
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
  [ ! -f "$PLIST" ]
  check $? "no pre-existing gateway LaunchAgent for $LABEL"
  [ -f "$PLIST" ] && die "a gateway LaunchAgent already exists at $PLIST.
--require-service will not overwrite it and will not downgrade to foreground.
Run this on a machine with no installed Tethra gateway. Passing --foreground
is NOT a workaround here: --scope full applies a real configuration whose
service step targets the same global label, so it refuses on this machine
too. Use --scope offline (22 checks) instead."
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
Run '--scope offline' on this machine (22 checks: packaging, helper
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
  [ -f "$PLIST" ] && SERVICE_INSTALLED=1
  [ -f "$PLIST" ]
  check $? "the apply installed a real LaunchAgent at $PLIST"
  grep -q "$LABEL" "$PLIST" 2>/dev/null
  check $? "the installed LaunchAgent declares the expected label"
  grep -qF "$HELPER" "$PLIST" 2>/dev/null
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
OLD_AT="1999-01-01T00:00:00Z"
FORGE_SESSION="forged-session-$$"
FORGE_EVENT="forged-event-$$"
FORGE_SERVICE="forged-service-$$"
echo "    applied_at = $APPLIED"
echo "    forged event at = $OLD_AT (strictly older, same host, same source)"
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
# Not `COUNT(*)=0` over the whole table: the apply's own keyless path check
# legitimately leaves observations behind. The property that matters is that
# the forgery is gone and nothing predating the apply survives, so no
# assertion below can be satisfied by planted evidence.
assert_db "SELECT (SELECT COUNT(*) FROM runtime_request_events WHERE id='$FORGE_EVENT')=0
              AND (SELECT COUNT(*) FROM runtime_request_events WHERE at<'$APPLIED')=0" \
  "the forged rows are gone and no pre-apply observation survives"

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
if [ -d "$SHARED_DIR" ]; then
  ! found_in "$SHARED_DIR" "$FAKE_KEY" && ! found_in "$SHARED_DIR" "$CANARY"
  check $? "neither needle reached the shared desktop/CLI data directory"
else
  ok "the shared desktop/CLI data directory does not exist, so nothing was written to it"
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
if [ "$total" -ne "$EXPECTED" ]; then
  echo "=== PACKAGED TRACKING VALIDATION: INCONCLUSIVE ==="
  echo "    scope=$SCOPE mode=$MODE ran $total checks but is defined to run $EXPECTED."
  echo "    A differing count means checks were skipped, added, or made conditional;"
  echo "    the tally ($pass passed, $fail failed) is not quotable until they agree."
  exit 1
fi
echo "=== PACKAGED TRACKING VALIDATION (scope=$SCOPE, mode=$MODE): $pass passed, $fail failed ($total/$EXPECTED checks) ==="
[ "$fail" -eq 0 ]
