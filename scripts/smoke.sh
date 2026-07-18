#!/usr/bin/env bash
# API Tracker automated smoke test.
#
#   bash scripts/smoke.sh
#
# Exercises the real release binary (production Argon2id, no test escape
# hatches) against a throwaway vault in a temporary directory, and verifies
# the security-critical end-to-end behavior listed in docs/DEMO.md. Uses only
# unmistakably fake credentials, never makes a network request, and never
# touches a real user vault. Exits non-zero if any check fails.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$REPO_ROOT/$TARGET_DIR" ;; esac
BIN="$TARGET_DIR/release/api-tracker"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/api-tracker-smoke.XXXXXX")" \
  || { echo "smoke: failed to create a temp dir under ${TMPDIR:-/tmp}" >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT
# Run from inside the workspace so any accidental cwd-relative write (e.g. a
# stray ./.env) lands where the final artifact sweep will catch it.
cd "$WORK" || exit 1

MASTER='smoke-master-password-0001'
PROJECT_PW='smoke-project-password-01'
BACKUP_PW='smoke-backup-password-001'
FAKE_KEY="sk-proj-SMOKE-FAKE-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')-NOT-A-REAL-KEY"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  PASS  $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
check(){ if [ "$1" -eq 0 ]; then ok "$2"; else bad "$2"; fi; }

echo "Building the release CLI (ensures the binary matches the sources)..."
(cd "$REPO_ROOT" && cargo build --release --quiet -p api-tracker-cli) || { echo "build failed"; exit 1; }
[ -x "$BIN" ] || { echo "error: built binary not found at $BIN" >&2; exit 1; }

export API_TRACKER_DIR="$WORK/vault"
export API_TRACKER_PASSWORD="$MASTER"
unset API_TRACKER_SESSION 2>/dev/null || true

echo "Smoke vault: $API_TRACKER_DIR"
echo

echo "-- vault creation and password policy --"
OUT=$(API_TRACKER_PASSWORD='elevenchars' "$BIN" --data-dir "$WORK/short" init 2>&1 < /dev/null); RC=$?
[ $RC -ne 0 ] && echo "$OUT" | grep -q "12 characters"; check $? "passwords shorter than 12 characters are rejected"
API_TRACKER_PASSWORD='exactly12chr' "$BIN" --data-dir "$WORK/twelve" init >/dev/null 2>&1
check $? "a 12-character password is accepted"
"$BIN" init >/dev/null 2>&1
check $? "vault creation succeeds"
"$BIN" init >/dev/null 2>&1; [ $? -ne 0 ]
check $? "an existing vault is never overwritten"

echo "-- unlock behavior --"
"$BIN" project list >/dev/null 2>&1
check $? "correct master password unlocks the vault"
OUT=$(API_TRACKER_PASSWORD='wrong-password-for-smoke' "$BIN" project list 2>&1); RC=$?
[ $RC -ne 0 ] && echo "$OUT" | grep -qi "incorrect password"; check $? "wrong master password is rejected"
echo "$OUT" | grep -q "wrong-password-for-smoke" && bad "error output echoes the attempted password" || ok "error output does not echo the attempted password"

echo "-- sessions: locking and unlocking --"
EXPORT_LINE=$("$BIN" unlock --print-export 2>/dev/null)
echo "$EXPORT_LINE" | grep -q "export API_TRACKER_SESSION="; check $? "unlock issues a session"
eval "$EXPORT_LINE"
env -u API_TRACKER_PASSWORD API_TRACKER_SESSION="${API_TRACKER_SESSION:-}" "$BIN" project list >/dev/null 2>&1
check $? "session works without the master password"
"$BIN" lock >/dev/null 2>&1; check $? "lock succeeds"
env -u API_TRACKER_PASSWORD API_TRACKER_SESSION="${API_TRACKER_SESSION:-}" "$BIN" project list >/dev/null 2>&1; [ $? -ne 0 ]
check $? "the revoked session is rejected after lock"
unset API_TRACKER_SESSION

echo "-- projects and credentials --"
"$BIN" project create smoke-dev  --env development >/dev/null 2>&1; check $? "project creation (development)"
"$BIN" project create smoke-prod --env production  >/dev/null 2>&1; check $? "project creation (production)"
printf '%s' "$FAKE_KEY" | "$BIN" key add --project smoke-dev --name main-key --provider openai --environment development --value-stdin >/dev/null 2>&1
check $? "credential added"
printf '%s' "$FAKE_KEY" | "$BIN" key add --project smoke-prod --name prod-copy --provider openai --environment production --value-stdin >/dev/null 2>&1
[ $? -ne 0 ]; check $? "duplicate value across projects is detected and refused"
printf '%s' "$FAKE_KEY" | "$BIN" key add --project smoke-prod --name prod-copy --provider openai --environment production --value-stdin --allow-duplicate >/dev/null 2>&1
check $? "explicit duplicate stored with --allow-duplicate"
"$BIN" key status smoke-dev/main-key 2>/dev/null | grep -qi "shared across projects\|stored separately in project"
check $? "cross-project reuse warning is reported"

echo "-- expiration classification --"
printf 'ghp_SMOKEFAKE0000000000000000' | "$BIN" key add --project smoke-dev --name expired-key --provider github --value-stdin --expires 2025-01-01 >/dev/null 2>&1
"$BIN" key status smoke-dev/expired-key 2>/dev/null | grep -q "Primary status: expired"
check $? "past expiration classifies as expired"
if SOON=$(date -v+5d +%Y-%m-%d 2>/dev/null); then :; else SOON=$(date -d "+5 days" +%Y-%m-%d); fi
printf 'sk_test_SMOKEFAKE00000000000' | "$BIN" key add --project smoke-dev --name expiring-key --provider stripe --value-stdin --expires "$SOON" >/dev/null 2>&1
"$BIN" key status smoke-dev/expiring-key 2>/dev/null | grep -q "Primary status: expiring soon"
check $? "near-future expiration classifies as expiring soon"

echo "-- redaction and encryption at rest --"
LISTOUT=$("$BIN" key list 2>&1 && "$BIN" key show smoke-dev/main-key 2>&1 && "$BIN" --json key list 2>&1)
LIST_RC=$?
[ $LIST_RC -eq 0 ] && echo "$LISTOUT" | grep -qF "main-key"
check $? "key list/show/json succeed and include the stored credential"
if [ $LIST_RC -ne 0 ]; then
  bad "cannot judge redaction: list/show failed"
else
  echo "$LISTOUT" | grep -qF "$FAKE_KEY" && bad "credential value appears in list/show output" || ok "list/show/json output is redacted"
fi
"$BIN" key reveal smoke-dev/main-key 2>/dev/null | grep -qF "$FAKE_KEY"
check $? "reveal (with reauthentication) returns the value"
grep -rqF "$FAKE_KEY" "$API_TRACKER_DIR" && bad "plaintext value found in the data directory" || ok "credential is encrypted at rest (no plaintext in data dir)"
ERROUT=$( (API_TRACKER_PASSWORD='another-wrong-password-1' "$BIN" key reveal smoke-dev/main-key) 2>&1; "$BIN" --json key show smoke-dev/does-not-exist 2>&1 )
echo "$ERROUT" | grep -qF "$FAKE_KEY" && bad "secret leaked into an error message" || ok "errors and serialized errors contain no secret"

echo "-- project password locking --"
API_TRACKER_PROJECT_PASSWORD="$PROJECT_PW" "$BIN" project lock smoke-prod >/dev/null 2>&1
check $? "project password set (project locked)"
"$BIN" key reveal smoke-prod/prod-copy >/dev/null 2>&1; [ $? -ne 0 ]
check $? "locked project blocks reveal without its password"
EXPORT_LINE=$("$BIN" unlock --print-export 2>/dev/null); eval "$EXPORT_LINE"
API_TRACKER_PROJECT_PASSWORD="$PROJECT_PW" "$BIN" project unlock smoke-prod >/dev/null 2>&1
check $? "project unlocks with its password"
"$BIN" key reveal smoke-prod/prod-copy 2>/dev/null | grep -qF "$FAKE_KEY"
check $? "unlocked project reveals with master reauthentication"
API_TRACKER_PROJECT_PASSWORD="wrong-project-password-x" "$BIN" project unlock smoke-prod >/dev/null 2>&1; [ $? -ne 0 ]
check $? "wrong project password is rejected"
"$BIN" lock >/dev/null 2>&1; unset API_TRACKER_SESSION

echo "-- usage, cost, and budget alerts --"
"$BIN" usage record --credential smoke-dev/main-key --model gpt-4o --input-tokens 1000000 --output-tokens 1000000 >/dev/null 2>&1
check $? "synthetic usage recorded"
USAGE=$("$BIN" usage report --project smoke-dev 2>&1)
echo "$USAGE" | grep -q "12.50" && echo "$USAGE" | grep -qi "estimat"
check $? "estimated cost is \$12.50 for 1M+1M gpt-4o tokens and labeled estimated"
"$BIN" budget set --project smoke-dev --amount 5.00 >/dev/null 2>&1
"$BIN" monitor >/dev/null 2>&1
"$BIN" alerts list 2>/dev/null | grep -qi "over.budget"
check $? "over-budget alert raised"

echo "-- backup, verify, restore --"
export API_TRACKER_BACKUP_PASSWORD="$BACKUP_PW"
"$BIN" backup create "$WORK/smoke.backup" >/dev/null 2>&1; check $? "backup created"
"$BIN" backup verify "$WORK/smoke.backup" >/dev/null 2>&1; check $? "backup verifies"
API_TRACKER_BACKUP_PASSWORD='wrong-backup-password-01' "$BIN" backup verify "$WORK/smoke.backup" >/dev/null 2>&1; [ $? -ne 0 ]
check $? "backup rejects a wrong backup password"
grep -qF "$FAKE_KEY" "$WORK/smoke.backup" && bad "backup contains plaintext secret" || ok "backup contains no plaintext secret"
API_TRACKER_DIR="$WORK/restored" "$BIN" backup restore "$WORK/smoke.backup" --yes >/dev/null 2>&1
check $? "backup restores into a fresh directory"
API_TRACKER_DIR="$WORK/restored" "$BIN" key reveal smoke-dev/main-key 2>/dev/null | grep -qF "$FAKE_KEY"
check $? "restored vault decrypts the credential"

echo "-- desktop/CLI shared core --"
# Grep for the test's success marker so this cannot pass vacuously (the test
# no-ops without the env vars; the marker proves the gated body really ran).
CORE_OUT=$(cd "$REPO_ROOT" && API_TRACKER_SMOKE_DIR="$API_TRACKER_DIR" \
    API_TRACKER_SMOKE_PASSWORD="$MASTER" \
    API_TRACKER_SMOKE_PROJECT="smoke-dev" \
    cargo test --release --quiet -p api-tracker-core --test shared_vault_smoke -- --nocapture 2>&1)
CORE_RC=$?
[ $CORE_RC -eq 0 ] && echo "$CORE_OUT" | grep -q "shared-vault-smoke: verified"
check $? "the desktop's core (api-tracker-core) opens the CLI-created vault"

echo "-- secure process injection --"
"$BIN" mapping set --project smoke-dev --credential smoke-dev/main-key --env SMOKE_INJECTED_KEY >/dev/null 2>&1
# Put a LIVE token/password of every kind into the parent environment first,
# so each "absent from the child" assertion below is falsifiable: if the CLI
# ever stopped scrubbing one of these, the child would inherit it and the
# matching check would fail.
EXPORT_LINE=$("$BIN" unlock --print-export 2>/dev/null); eval "$EXPORT_LINE"
export API_TRACKER_PROJECT_PASSWORD="$PROJECT_PW"
CHILD_ENV=$("$BIN" run --project smoke-dev -- /usr/bin/env 2>/dev/null)
echo "$CHILD_ENV" | grep -qF "SMOKE_INJECTED_KEY=$FAKE_KEY"
check $? "child process receives the injected credential"
echo "$CHILD_ENV" | grep -q "API_TRACKER_PASSWORD" && bad "master password leaked into the child environment" || ok "master password is absent from the child environment"
echo "$CHILD_ENV" | grep -q "API_TRACKER_SESSION" && bad "session token leaked into the child environment" || ok "session token (live in the parent) is absent from the child environment"
echo "$CHILD_ENV" | grep -q "API_TRACKER_PROJECT_PASSWORD" && bad "project password leaked into the child environment" || ok "project password is absent from the child environment"
echo "$CHILD_ENV" | grep -q "API_TRACKER_BACKUP_PASSWORD" && bad "backup password leaked into the child environment" || ok "backup password is absent from the child environment"
"$BIN" lock >/dev/null 2>&1
unset API_TRACKER_SESSION API_TRACKER_PROJECT_PASSWORD
FOUND_ENV=$(find "$WORK" -name "*.env" -o -name ".env" 2>/dev/null)
[ -z "$FOUND_ENV" ]; check $? "no plaintext .env file is ever created"

echo "-- OpenAI administrative connection (offline; no network request) --"
FAKE_ADMIN="sk-admin-SMOKE-FAKE-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')-NOT-A-REAL-KEY"
API_TRACKER_PROVIDER_ADMIN_KEY="$FAKE_ADMIN" \
  "$BIN" provider connect openai --no-verify --org smoke-org >/dev/null 2>&1
check $? "admin connection stored (--no-verify, key via environment)"
STATUS_OUT=$("$BIN" provider connection-status openai 2>&1)
echo "$STATUS_OUT" | grep -q "administrative" && ! echo "$STATUS_OUT" | grep -qF "$FAKE_ADMIN"
check $? "connection status is labeled administrative and never shows the key"
grep -rqF "$FAKE_ADMIN" "$API_TRACKER_DIR" && bad "admin key stored in plaintext" || ok "admin key exists nowhere in plaintext on disk"
"$BIN" usage report --provider openai >/dev/null 2>&1
check $? "usage report works offline with a provider filter"
"$BIN" provider disconnect openai --yes >/dev/null 2>&1
check $? "disconnect removes the administrative connection (reauth via env)"
"$BIN" provider connection-status openai 2>/dev/null | grep -q "(not connected)"
check $? "status reports not connected after disconnect"

echo "-- .env governance (offline) --"
ENV_WORK=$(mktemp -d)
printf '# app config\nSMOKE_ENV_KEY=%s\nAPP_NAME=demo\n' "$FAKE_KEY" > "$ENV_WORK/.env"
PREVIEW_OUT=$("$BIN" env preview --project smoke-dev "$ENV_WORK/.env" 2>&1)
echo "$PREVIEW_OUT" | grep -q "SMOKE_ENV_KEY" && ! echo "$PREVIEW_OUT" | grep -qF "$FAKE_KEY"
check $? "env preview lists variables without exposing values"
"$BIN" env import --project smoke-dev --var SMOKE_ENV_KEY --yes "$ENV_WORK/.env" >/dev/null 2>&1
check $? "env import stores a selected variable"
"$BIN" mapping list --project smoke-dev 2>/dev/null | grep -q "SMOKE_ENV_KEY"
check $? "env import creates the injection mapping"
grep -qF "$FAKE_KEY" "$ENV_WORK/.env"
check $? "env import never modifies the source file"
"$BIN" env example --write --yes "$ENV_WORK/.env" >/dev/null 2>&1
check $? "env example generates .env.example"
grep -q "SMOKE_ENV_KEY=" "$ENV_WORK/.env.example" && ! grep -qF "$FAKE_KEY" "$ENV_WORK/.env.example"
check $? ".env.example carries names only, never values"
"$BIN" env export --project smoke-dev --var SMOKE_ENV_KEY --ttl 0 --yes --to "$ENV_WORK/exported.env" >/dev/null 2>&1
check $? "env export writes after reauthentication (password via env)"
if [ "$(uname)" = "Darwin" ]; then
  EXPORT_MODE=$(stat -f "%Lp" "$ENV_WORK/exported.env" 2>/dev/null)
else
  EXPORT_MODE=$(stat -c "%a" "$ENV_WORK/exported.env" 2>/dev/null)
fi
[ "$EXPORT_MODE" = "600" ]; check $? "exported file has owner-only (0600) permissions"
"$BIN" env cleanup >/dev/null 2>&1 && [ ! -f "$ENV_WORK/exported.env" ]
check $? "expired temporary export is cleaned up"
rm -rf "$ENV_WORK"

echo "-- destinations (offline; no network request) --"
DEST_OUT=$("$BIN" destination kinds 2>&1)
echo "$DEST_OUT" | grep -q "aws_secrets_manager" && echo "$DEST_OUT" | grep -q "vercel"
check $? "destination kinds reports the capability catalog"
FAKE_GH_TOKEN="ghp_SMOKEFAKE0000000000000000000000000000"
printf '%s' "$FAKE_GH_TOKEN" | "$BIN" destination add github_actions --name smoke-ci \
  --owner smoke --repo demo --auth-stdin --no-verify >/dev/null 2>&1
check $? "destination add stores an encrypted admin credential"
grep -rqF "$FAKE_GH_TOKEN" "$API_TRACKER_DIR" && bad "destination token stored in plaintext" || ok "destination token exists nowhere in plaintext on disk"
"$BIN" destination attach smoke-dev/main-key smoke-ci --secret-name SMOKE_KEY >/dev/null 2>&1
check $? "credential attaches to the destination"
PLAN_OUT=$("$BIN" sync plan smoke-dev/main-key 2>&1)
echo "$PLAN_OUT" | grep -q "Dry run" && ! echo "$PLAN_OUT" | grep -qF "$FAKE_KEY"
check $? "sync plan is a dry run and never shows values"
"$BIN" destination remove smoke-ci --yes >/dev/null 2>&1
check $? "destination remove works with reauthentication via env"

echo "-- rotation and temporary access (offline) --"
ROT_OUT=$("$BIN" rotation plan smoke-dev/main-key --grace-minutes 5 2>&1)
echo "$ROT_OUT" | grep -q "Dry run" && ! echo "$ROT_OUT" | grep -qF "$FAKE_KEY"
check $? "rotation plan is a dry run and never shows values"
ROT_ID=$("$BIN" rotation plan smoke-dev/main-key --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
"$BIN" rotation cancel "$ROT_ID" --yes >/dev/null 2>&1
check $? "an untouched rotation can be cancelled (reauth via env)"
"$BIN" rotation schedule set smoke-dev/main-key --every-days 30 >/dev/null 2>&1 && bad "schedule allowed without a completed rotation" || ok "scheduling is refused before a completed manual rotation"
GRANT_ID=$("$BIN" access grant --project smoke-dev --one-time --ttl-minutes 5 --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
[ -n "$GRANT_ID" ]; check $? "a one-time access grant is created"
GRANT_CHILD=$("$BIN" run --grant "$GRANT_ID" -- /usr/bin/env 2>/dev/null)
echo "$GRANT_CHILD" | grep -qF "SMOKE_INJECTED_KEY=$FAKE_KEY"
check $? "run --grant injects under the grant"
"$BIN" run --grant "$GRANT_ID" -- /usr/bin/true >/dev/null 2>&1 && bad "one-time grant allowed a second launch" || ok "a one-time grant refuses a second launch"
"$BIN" access end "$GRANT_ID" --yes 2>/dev/null | grep -q "stays valid"
check $? "ending a grant states the provider credential stays valid"
HIST_OUT=$("$BIN" key history smoke-dev/main-key 2>&1)
echo "$HIST_OUT" | grep -q "credential_created" && ! echo "$HIST_OUT" | grep -qF "$FAKE_KEY"
check $? "key history shows the lifecycle without values"

echo "-- repository git-ignore protection --"
GITIGNORE_OK=0
for p in vault.db data/vault.db-wal x.sqlite3 secrets.vault y.backup z.bak .env .env.local app.log demo/vault.db; do
  git -C "$REPO_ROOT" check-ignore -q "$p" || { GITIGNORE_OK=1; echo "        not ignored: $p"; }
done
check $GITIGNORE_OK "databases, vaults, backups, .env files, and logs are git-ignored"
git -C "$REPO_ROOT" check-ignore -q ".env.example"; [ $? -ne 0 ]
check $? ".env.example remains committable (negation works)"

echo
echo "=== SMOKE RESULT: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ]
