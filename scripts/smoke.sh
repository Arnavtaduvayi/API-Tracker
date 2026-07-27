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
# The preferred `tethra` binary is exercised; the legacy API_TRACKER_* env
# vars below stay on purpose — the smoke suite doubles as the rebrand
# compatibility check (new binary + legacy variables).
BIN="$TARGET_DIR/release/tethra"
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
# eval of --print-export sets BOTH session variable generations; clear both.
unset API_TRACKER_SESSION TETHRA_SESSION

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

echo "-- observability (offline) --"
"$BIN" monitor --offline >/dev/null 2>&1
check $? "monitor runs fully offline with --offline"
FAKE_HOOK_TOKEN="FAKE-webhook-token-000001"
printf 'https://hooks.example.invalid/T0/%s' "$FAKE_HOOK_TOKEN" | "$BIN" notify add --name smoke-hook --url-stdin >/dev/null 2>&1
check $? "a webhook notification channel is created (URL via stdin)"
NOTIFY_LIST=$("$BIN" notify list 2>&1)
echo "$NOTIFY_LIST" | grep -q "smoke-hook" && ! echo "$NOTIFY_LIST" | grep -qF "$FAKE_HOOK_TOKEN"
check $? "channel listings mask the webhook URL"
grep -rqF "$FAKE_HOOK_TOKEN" "$API_TRACKER_DIR" && bad "webhook URL stored in plaintext" || ok "webhook URL exists nowhere in plaintext on disk"
printf 'http://insecure.example.invalid/hook' | "$BIN" notify add --name smoke-bad --url-stdin >/dev/null 2>&1 && bad "an http webhook URL was accepted" || ok "non-https webhook URLs are refused"
"$BIN" notify remove smoke-hook >/dev/null 2>&1
check $? "a channel can be removed"
"$BIN" provider docs-history >/dev/null 2>&1
check $? "documentation change history is queryable"

echo "-- credential version history --"
printf 'sk-proj-SMOKE-FAKE-REPLACEMENT-0002-NOT-A-REAL-KEY' | \
  "$BIN" key update smoke-dev/main-key --new-value --value-stdin >/dev/null 2>&1
check $? "credential value replaced (reauthentication via env)"
VERS_OUT=$("$BIN" key versions smoke-dev/main-key 2>/dev/null)
echo "$VERS_OUT" | grep -q "v1"
check $? "version history lists the retained previous version"
{ echo "$VERS_OUT" | grep -qF "$FAKE_KEY" || echo "$VERS_OUT" | grep -qF "REPLACEMENT-0002"; } \
  && bad "version listing exposes a value" || ok "version listing is masked"

echo "-- git scanning end to end (staged, history, full history, hook) --"
SCAN_REPO=$(mktemp -d)
git -C "$SCAN_REPO" init -q
git -C "$SCAN_REPO" config user.email smoke@example.invalid
git -C "$SCAN_REPO" config user.name smoke
echo "just a readme" > "$SCAN_REPO/README.md"
git -C "$SCAN_REPO" add . && git -C "$SCAN_REPO" commit -qm init
GIT_FAKE="sk-proj-SMOKEGIT-FAKE-00000000000000000000-NOT-REAL"
printf 'OPENAI_API_KEY=%s\n' "$GIT_FAKE" > "$SCAN_REPO/config.env"
git -C "$SCAN_REPO" add .
STAGED_OUT=$("$BIN" --json scan --staged "$SCAN_REPO" 2>/dev/null)
echo "$STAGED_OUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if len(d)>=1 else 1)' 2>/dev/null
check $? "staged scan detects the planted secret"
echo "$STAGED_OUT" | grep -qF "$GIT_FAKE" && bad "scan output contains the raw secret" || ok "scan findings are redacted"
"$BIN" hooks install "$SCAN_REPO" >/dev/null 2>&1
check $? "pre-commit hook installs"
( cd "$SCAN_REPO" && PATH="$(dirname "$BIN"):$PATH" git commit -qm leak ) >/dev/null 2>&1 \
  && bad "the hook allowed a commit containing a high-confidence secret" \
  || ok "the pre-commit hook blocks the secret-bearing commit"
( cd "$SCAN_REPO" && git commit -qm leak --no-verify ) >/dev/null 2>&1
check $? "--no-verify bypass works (documented Git behavior)"
"$BIN" --json scan --history 5 "$SCAN_REPO" 2>/dev/null | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if len(d)>=1 else 1)' 2>/dev/null
check $? "recent-history scan finds the committed secret"
"$BIN" --json scan --all-history "$SCAN_REPO" 2>/dev/null | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if len(d)>=1 else 1)' 2>/dev/null
check $? "full-history scan finds the committed secret"
SUPP_KEY=$(echo "$STAGED_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["suppression_key"])' 2>/dev/null)
"$BIN" suppress add "$SUPP_KEY" --reason "smoke fixture" >/dev/null 2>&1 && \
  "$BIN" suppress list 2>/dev/null | grep -q "smoke fixture" && \
  "$BIN" suppress remove "$SUPP_KEY" >/dev/null 2>&1
check $? "suppressions can be added, listed, and removed"

echo "-- .env discovery on a registered repository --"
"$BIN" project edit smoke-dev --add-repo "$SCAN_REPO" >/dev/null 2>&1
printf 'SMOKE_DISCOVER_KEY=sk-proj-SMOKE-DISCOVER-FAKE-0000-NOT-REAL\n' > "$SCAN_REPO/.env"
"$BIN" env discover --project smoke-dev 2>/dev/null | grep -q ".env"
check $? "env discover finds the .env file in the registered repository"
rm -rf "$SCAN_REPO"

echo "-- provider catalog and documentation-watch surfaces (offline) --"
"$BIN" provider list 2>/dev/null | grep -qi "openai" && \
  "$BIN" provider list 2>/dev/null | grep -qi "anthropic"
check $? "provider catalog lists the built-in providers"
CAP_OUT=$("$BIN" provider capabilities supabase 2>/dev/null)
echo "$CAP_OUT" | grep -qi "not impl\|unsupported\|manual"
check $? "capability matrix reports honest non-implemented states"
"$BIN" provider docs stripe 2>/dev/null | grep -q "https://"
check $? "provider docs prints official links"
"$BIN" provider docs-status >/dev/null 2>&1
check $? "documentation-watch status is queryable offline"

echo "-- monitor status and injection-session listing --"
"$BIN" monitor --status 2>/dev/null | grep -q "Last success"
check $? "monitor --status reports the last successful run"
"$BIN" access sessions --all 2>/dev/null | grep -q "SESSION\|No .*sessions"
check $? "injection sessions are listable (names and PIDs only)"

echo "-- webhook delivery to a local test server --"
HOOK_LOG="$WORK/webhook_bodies.log"
: > "$HOOK_LOG"
python3 - "$HOOK_LOG" "$WORK/webhook_port" <<'WEBEOF' &
import http.server, socketserver, sys
log, portfile = sys.argv[1], sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        with open(log, 'ab') as f:
            f.write(self.rfile.read(n) + b"\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b'{}')
    def log_message(self, *a): pass
with socketserver.TCPServer(("127.0.0.1", 0), H) as srv:
    with open(portfile, 'w') as f:
        f.write(str(srv.server_address[1]))
    srv.timeout = 2
    for _ in range(20):
        srv.handle_request()
WEBEOF
WEBHOOK_SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$WORK/webhook_port" ] && break; sleep 0.2; done
HOOK_PORT=$(cat "$WORK/webhook_port" 2>/dev/null)
printf 'http://127.0.0.1:%s/hook' "$HOOK_PORT" | \
  "$BIN" notify add --name smoke-local --min-severity high --url-stdin >/dev/null 2>&1
check $? "a localhost webhook channel is accepted (http allowed for 127.0.0.1)"
"$BIN" monitor >/dev/null 2>&1
check $? "monitor runs its network phase against the local server only"
sleep 0.5
grep -q '"severity"' "$HOOK_LOG" 2>/dev/null
check $? "the local server received alert metadata"
{ grep -qF "$FAKE_KEY" "$HOOK_LOG" || grep -qF "REPLACEMENT-0002" "$HOOK_LOG"; } 2>/dev/null \
  && bad "webhook payload contained a secret value" \
  || ok "webhook payloads carry metadata only (no secret values)"
"$BIN" notify history 2>/dev/null | grep -q "delivered"
check $? "notify history records the delivery"
"$BIN" notify remove smoke-local >/dev/null 2>&1
{ kill "$WEBHOOK_SERVER_PID" && wait "$WEBHOOK_SERVER_PID"; } >/dev/null 2>&1

echo "-- migration/data-safety and mocked provider-sync suites --"
(cd "$REPO_ROOT" && cargo test --release --quiet -p api-tracker-core --test migration_safety 2>&1 | grep -q "test result: ok. 9")
check $? "migration + backup-completeness suite passes against the release core"
(cd "$REPO_ROOT" && API_TRACKER_INSECURE_FAST_KDF=1 cargo test --quiet -p api-tracker-core \
    --test openai_sync --test anthropic_sync --test env_destinations --test rotation_access 2>&1 | \
    grep -c "test result: ok" | grep -q "4")
check $? "mocked provider sync, destination, and rotation suites pass"

echo "-- versioned pricing --"
"$BIN" pricing list --provider anthropic | grep -q "claude-sonnet-5"
check $? "pricing list shows effective-dated bundled records"
"$BIN" pricing show anthropic claude-sonnet-5 --as-of 2026-09-02 | grep -q '\$3\.00'
check $? "effective dating resolves the documented September price change"
"$BIN" pricing set-override other smoke-model --input 1.00 --output 2.00 --note smoke >/dev/null
check $? "a manual pricing override can be stored"
"$BIN" pricing show other smoke-model | grep -q "override"
check $? "the override is labeled as an override"
"$BIN" pricing propose openai --out "$WORK/pricing-prop.json" >/dev/null && \
  "$BIN" pricing import "$WORK/pricing-prop.json" | grep -q "Imported"
check $? "pricing propose -> review -> import round-trips"
"$BIN" pricing show openai no-such-model 2>&1 | grep -q "UNAVAILABLE"
check $? "unknown models yield no estimate (never invented)"

echo "-- templates and stack detection --"
"$BIN" template list | grep -q "fullstack-saas"
check $? "template catalog lists the stack templates"
mkdir -p "$WORK/stackrepo"
printf '{"dependencies":{"openai":"^4","next":"^15"}}' > "$WORK/stackrepo/package.json"
"$BIN" template apply openai-app --project smoke-tpl --write-example "$WORK/stackrepo" >/dev/null
check $? "template apply creates the project and writes .env.example"
grep -q "OPENAI_API_KEY=" "$WORK/stackrepo/.env.example" && \
  ! grep -Eq "OPENAI_API_KEY=.+" "$WORK/stackrepo/.env.example"
check $? ".env.example carries names only, never values"
"$BIN" template detect --repo "$WORK/stackrepo" | grep -q 'dependency "openai"'
check $? "stack detection shows its evidence"
"$BIN" template confirm openai-app --repo "$WORK/stackrepo" >/dev/null && \
  "$BIN" template prefs | grep -q confirmed
check $? "detection decisions are remembered locally"
"$BIN" template prefs --clear-all --yes | grep -q "deleted"
check $? "all learned stack data can be deleted"

echo "-- destination capability honesty (extended matrix) --"
"$BIN" destination kinds | grep -q "windows_credential_manager"
check $? "the OS credential-store kinds are cataloged"
"$BIN" destination kinds | grep -qi "recovery window"
check $? "AWS delete declares its recovery-window semantics"
"$BIN" destination kinds | grep -q "Charges:"
check $? "each kind declares possible charges and testing status"

echo "-- master password change --"
API_TRACKER_NEW_PASSWORD="$MASTER-changed01" "$BIN" change-password >/dev/null 2>&1
check $? "the master password can be changed"
API_TRACKER_PASSWORD="$MASTER" "$BIN" key list >/dev/null 2>&1; [ $? -ne 0 ]
check $? "the old master password stops working"
export API_TRACKER_PASSWORD="$MASTER-changed01"
"$BIN" key list >/dev/null 2>&1
check $? "the new master password unlocks the vault"

echo "-- zero-friction tracking (offline: dry-run, status, undo honesty) --"
TRACKAPP="$WORK/trackapp"
mkdir -p "$TRACKAPP"
printf 'OPENAI_API_KEY=sk-proj-SMOKE-FAKE-TRACK-NOT-A-REAL-KEY-01\n' > "$TRACKAPP/.env"
printf '{ "dependencies": { "openai": "^4.0.0", "dotenv": "^16.0.0" } }\n' > "$TRACKAPP/package.json"
# A real byte snapshot, not a shell string. `[ "$(cat a)" = "$b" ]` strips
# trailing newlines from BOTH sides, so it cannot see a dry run that added or
# removed one — the same defect the audit found in the packaged harness
# (ZFT-VAL-10). The `.snapshot` suffix keeps it out of the earlier
# "no plaintext .env file is ever created" sweep, which matches *.env/.env.
ENV_BEFORE="$WORK/trackapp-env-before.snapshot"
cp "$TRACKAPP/.env" "$ENV_BEFORE"
TRACK_OUT=$("$BIN" track "$TRACKAPP" --dry-run 2>&1)
check $? "track --dry-run succeeds on a detectable project"
echo "$TRACK_OUT" | grep -q "openai" && echo "$TRACK_OUT" | grep -q "OPENAI_BASE_URL"
check $? "the dry run shows the detection and the exact env diff"
echo "$TRACK_OUT" | grep -q "Dry run: nothing was changed."
check $? "the dry run says it changed nothing"
cmp -s "$ENV_BEFORE" "$TRACKAPP/.env"
check $? "the dry run really changed nothing on disk (cmp, not string equality)"
echo "$TRACK_OUT" | grep -q "sk-proj-SMOKE-FAKE-TRACK" && bad "track output leaked a key value" || ok "no key value appears in track output"
echo "$TRACK_OUT" | grep -q "print-export" && bad "track printed shell-export choreography" || ok "track never prints shell-export choreography"
"$BIN" project list 2>/dev/null | grep -q "trackapp" && bad "dry-run created a project" || ok "the dry run created no project"
"$BIN" track status "$TRACKAPP" >/dev/null 2>&1; [ $? -eq 2 ]
check $? "track status exits 2 while tracking is not configured"
"$BIN" track status "$TRACKAPP" 2>&1 | grep -q "not configured"
check $? "track status names the unconfigured state honestly"
"$BIN" track undo "$TRACKAPP" --yes 2>&1 | grep -q "nothing to undo"
check $? "track undo is honest when there is nothing to undo"
EMPTYAPP="$WORK/emptyapp"; mkdir -p "$EMPTYAPP"
"$BIN" track "$EMPTYAPP" >/dev/null 2>&1; [ $? -eq 2 ]
check $? "an empty folder exits 2 (no trackable APIs), not an error"
EMPTY_OUT="$("$BIN" track "$EMPTYAPP" 2>&1 || true)"
printf '%s' "$EMPTY_OUT" | grep -q "No API integrations found"
check $? "the empty-folder message names the outcome plainly"
printf '%s' "$EMPTY_OUT" | grep -q "wrong folder"
check $? "the empty-folder message says what the user can do about it"
# ZFT-009: the desktop-only user has no `tethra` on PATH — the CLI lives
# inside Tethra.app/Contents/MacOS. An empty state that sends them to a
# terminal command is a dead end, not guidance.
! printf '%s' "$EMPTY_OUT" | grep -qE "tethra provider list|tethra gateway route add"
check $? "the empty-folder message points at no unexecutable CLI command"

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
