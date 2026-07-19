# Manual UI Test Data

Synthetic data for [docs/MANUAL_UI_TEST_PLAN.md](MANUAL_UI_TEST_PLAN.md).
Every value below is **fake and non-functional by construction** (note the
`MANUAL`/`FAKE`/`NOT-A-REAL-KEY` markers and the all-zero bodies). None of
these strings can authenticate to any real service. Never replace them with
real credentials, and never reuse the passwords for a real vault.

Values marked *(detector fixture)* reuse the repository's own scanner test
fixture (`apps/cli/tests/fixtures/leaky-repo/config.env`), so the secret
scanner is guaranteed to detect them exactly as the automated tests prove.

## 1. Workspace layout

All manual-test artifacts live under **one throwaway directory** so cleanup
is a single delete (see the test plan for the exact setup commands):

```text
~/at-manual-test/
├── vault/          # isolated test vault (API_TRACKER_DIR points here)
├── alpha-repo/     # scratch Git repository for scanning and .env tests
├── docroot/        # local documentation-watch test page
├── backup-1.json   # encrypted backup created during the plan
└── webhook_sink.py # local webhook receiver
```

## 2. Passwords (normal local storage)

| Purpose | Value | Notes |
| --- | --- | --- |
| Master password (test vault) | `manual-master-passphrase-01` | 28 chars, ≥ 12 minimum |
| New master password (change test) | `manual-master-passphrase-02` | for the change-password test |
| Project password (`beta-service`) | `manual-beta-project-pw-01` | second lock on one project |
| Backup password | `manual-backup-passphrase-01` | protects `backup-1.json` |

### Negative-path passwords

| Purpose | Value | Expected behavior |
| --- | --- | --- |
| One character below the minimum | `elevenchars` | exactly 11 chars → rejected with a "must be at least 12 characters" error |
| Wrong master password | `wrong-master-passphrase-00` | valid length, wrong → "incorrect password" |
| Wrong project password | `wrong-beta-project-pw-00` | rejected; project stays locked |
| Wrong backup password | `wrong-backup-passphrase-00` | backup verify/restore fails; nothing changes |

## 3. Projects and environments

| Project | Environments | Purpose |
| --- | --- | --- |
| `alpha-app` | development, production | primary project; registered repo `~/at-manual-test/alpha-repo` |
| `beta-service` | development | duplicate-detection target; later gets the project password |

Environment classification values are fixed by the product:
`development`, `test`, `staging`, `production`.

## 4. Credentials (normal local storage)

All are stored via the app's own add-credential flow (the value field is a
hidden input; the CLI equivalent uses `--value-stdin`).

| # | Project/Name | Provider | Environment | Value | Purpose |
| --- | --- | --- | --- | --- | --- |
| C1 | `alpha-app/generic-token` | Custom… → `internal` | development | `MANUAL-TEST-NOT-A-REAL-KEY-000001` | plain generic storage, reveal/copy |
| C2 | `alpha-app/openai-main` | OpenAI | development | `sk-proj-MANUAL-FAKE-000000000000-NOT-A-REAL-KEY` | provider-shaped **invalid** key: live validation must fail with a provider rejection |
| C3 | `alpha-app/github-ci` | GitHub | development | `ghp_MANUALFAKE0000000000000000000000000000` | **expired**: set "Expires on" = `2025-12-31` |
| C4 | `alpha-app/stripe-webhook` | Stripe | test | `sk_test_MANUALFAKE00000000000000000000` | **expiring soon**: set "Expires on" = today + 7 days (inside the 14-day default) |
| C5 | `alpha-app/shared-payments` | OpenAI | production | `sk-proj-MANUAL-FAKE-SHARED-0000000000-NOT-A-REAL-KEY` | duplicate source (production side) |
| C6 | `beta-service/payments-copy` | OpenAI | development | same value as C5 | duplicate copy → triggers the highest-risk "production shared with development" reuse warning |

### Replacement values (versions / sync plans / rotation)

| Purpose | Value |
| --- | --- |
| First replacement of C2 (version history, sync plan) | `sk-proj-MANUAL-FAKE-ROTATED-000000000-NOT-A-REAL-KEY` |
| Second replacement of C2 (stale-plan test) | `sk-proj-MANUAL-FAKE-STALE-00000000000-NOT-A-REAL-KEY` |
| Manually "created in the dashboard" rotation key (rotation mock) | `sk-proj-MANUAL-FAKE-ROTNEW-0000000000-NOT-A-REAL-KEY` |
| Anthropic-shaped extra credential (optional catalog variety) | `sk-ant-MANUAL-FAKE-000000000000-NOT-A-REAL-KEY` |

## 5. Git-scanning fixtures *(detector fixtures)*

Committed into `~/at-manual-test/alpha-repo` per the plan. The first three
values are byte-identical to the repository's automated-test fixture and are
proven to match the manifest detection regexes (`sk-proj-[A-Za-z0-9_-]{20,}`,
`gh[posru]_[A-Za-z0-9]{36,}`, `sk_live_[A-Za-z0-9]{24,}`):

`leaky.env` (working-tree/staged/history scans — must be detected):

```text
# Fixture data — every value is an obviously FAKE, non-functional credential.
OPENAI_API_KEY=sk-proj-FAKE0000000000000000000000000000FAKE
GITHUB_TOKEN=ghp_FAKE0000000000000000000000000000000000
STRIPE_SECRET_KEY=sk_live_FAKE0000000000000000000000000000

# Placeholders below must NOT be flagged:
EXAMPLE_KEY=your-key-here
ANOTHER=<REPLACE_ME>
PUBLIC_KEY=pk_live_notasecretnotasecret000000
```

Additional scan-test values:

| Purpose | Value |
| --- | --- |
| Staged-secret (pre-commit hook block) | `sk-proj-FAKE1111111111111111111111111111FAKE` in `staged-secret.txt` |
| History-only secret (committed then deleted) | `ghp_FAKE1111111111111111111111111111111111` in `old-secret.txt` |
| Vault-match scan (marks C5 possibly exposed) | the C5 value in `oops-committed.txt` |
| Binary file (must not crash / not flag) | 1 KiB from `/dev/urandom` in `blob.bin` |
| Large text file (bounded scan) | ~2 MiB of `x` lines in `big.txt` |

## 6. `.env` governance test files

`~/at-manual-test/alpha-repo/.env` — discovery, preview, import, example,
drift (comments, `export` prefix, quotes, a placeholder, a non-secret):

```text
# Manual test data — every value is fake (docs/MANUAL_TEST_DATA.md)
export OPENAI_API_KEY="sk-proj-MANUAL-FAKE-ENVFILE00000000-NOT-A-REAL-KEY"
GITHUB_TOKEN=ghp_MANUALFAKE1111111111111111111111111111
APP_DEBUG=true
EXAMPLE_KEY=your-key-here
```

Expected classification: `OPENAI_API_KEY` and `GITHUB_TOKEN` are secrets
(import-checked by default), `APP_DEBUG` is not a secret, `EXAMPLE_KEY` is a
placeholder (never import-checked by default).

`~/at-manual-test/alpha-repo/.env.local` — malformed line, duplicate
variable, quoted value with inline comment:

```text
GITHUB_TOKEN=ghp_MANUALFAKE1111111111111111111111111111
GITHUB_TOKEN=ghp_MANUALFAKE2222222222222222222222222222
THIS LINE IS MALFORMED
STRIPE_SECRET_KEY='sk_live_MANUALFAKE11111111111111111111' # quoted + comment
```

Drift-test edit (after importing `OPENAI_API_KEY`, change the `.env` line
to this to create a file-vs-vault divergence):

```text
export OPENAI_API_KEY="sk-proj-MANUAL-FAKE-DRIFTED-0000000-NOT-A-REAL-KEY"
```

Temporary-export settings: target `~/at-manual-test/alpha-repo/.env.tmp`,
lifetime `1` minute.

## 7. Injection, mappings, grants

| Item | Value |
| --- | --- |
| Mapping (CLI `run` + export tests) | credential `alpha-app/openai-main` → env var `OPENAI_API_KEY` |
| Test child command (sees the variable) | `sh -c 'test -n "$OPENAI_API_KEY" && echo INJECTED'` |
| Long-running child (kill-timer / terminate tests) | `sleep 300` |
| Grant lifetime (expiry test) | `2` minutes |
| One-time grant | "One-time grant" checked (exactly one launch) |
| Max-launches grant | `2` launches |
| Per-process kill timer | `5` seconds (child `sleep 300` → killed, exit 124) |
| Grant budget warning (advisory) | `5.00` |

## 8. Usage, budgets, pricing

| Item | Value | Expected |
| --- | --- | --- |
| Manual usage record (CLI) | credential `alpha-app/openai-main`, model `gpt-4o`, input tokens `1000000`, output tokens `1000000` | estimated cost **$12.50** (bundled gpt-4o pricing: $2.50/1M input + $10.00/1M output), labeled *estimated* |
| Over-budget budget | `5.00` | used $12.50 > $5.00 → `over_budget` alert |
| Budget exactly at spend | `12.50` | **not** over budget (over = used strictly greater than budget) |
| Budget one cent under spend | `12.49` | over budget |
| Pricing override | provider `openai`, model `manual-test-model`, unit tokens, input $/1M `2.50`, output $/1M `10`, note `manual test override` | origin `override` row appears; removable |
| Unknown model (no invented estimate) | manual usage with model `made-up-model-xyz` | record stores tokens; estimated cost is absent/"—" (never invented) |

## 9. Documentation-watch test content (local, deterministic)

Serve `~/at-manual-test/docroot` locally so a "changed page" can be forced
without touching real provider pages (the watcher accepts `http://` URLs and
never follows redirects):

```bash
mkdir -p ~/at-manual-test/docroot
echo '<html><body>manual docs v1</body></html>' > ~/at-manual-test/docroot/docs.html
python3 -m http.server 8090 --bind 127.0.0.1 --directory ~/at-manual-test/docroot
```

| Item | Value |
| --- | --- |
| Watched URL (unchanged/changed tests) | `http://127.0.0.1:8090/docs.html` |
| "Changed" edit | overwrite `docs.html` with `<html><body>manual docs v2</body></html>` |
| Watch provider tag | `openai` (any catalog provider works; the tag only groups the watch) |

Redirect-blocked test (optional): run this tiny redirecting server on port
8091 and watch `http://127.0.0.1:8091/docs.html` — every check must fail
(the watcher sends requests with redirects disabled) rather than follow it:

```python
# redirect_server.py
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header("Location", "http://127.0.0.1:8090/docs.html")
        self.end_headers()
HTTPServer(("127.0.0.1", 8091), H).serve_forever()
```

## 10. Webhook notification test addresses (local)

Webhook URLs must be `https://…`, or `http://` strictly to
localhost/127.0.0.1/[::1] for testing.

| Purpose | Value | Expected |
| --- | --- | --- |
| Working local receiver | `http://127.0.0.1:8085/hook` | test delivery succeeds (the sink below answers 200) |
| Invalid destination (validation) | `http://example.com/hook` | **rejected at add time**: webhook URLs must be https (http only to localhost) |
| Failing destination (failure + retry) | `http://127.0.0.1:8086/hook` (nothing listens) | delivery fails; per-channel last-error recorded; retried on a later monitor run |
| Severity floor | `high` (default) and `info` (deliver-everything channel) | |

`~/at-manual-test/webhook_sink.py` — local receiver that prints each
delivery and answers 200:

```python
# webhook_sink.py — local manual-test webhook receiver
from http.server import BaseHTTPRequestHandler, HTTPServer

class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        print(self.rfile.read(length).decode("utf-8", "replace"))
        self.send_response(200)
        self.end_headers()

HTTPServer(("127.0.0.1", 8085), Hook).serve_forever()
```

Run with: `python3 ~/at-manual-test/webhook_sink.py`

## 11. Destinations (rotation/sync-plan mocks — no external account)

| Item | Value |
| --- | --- |
| Local destination (real end-to-end, macOS only) | kind **macOS Keychain**, name `manual-keychain`, account left empty (defaults to `api-tracker`) |
| Secret name at the destination | `API_TRACKER_MANUAL_TEST_SECRET` |
| Deliberately failing network destination | kind **GitHub Actions repository secrets**, name `manual-broken-gha`, owner `manual-test-owner`, repo `manual-test-repo`, token `ghp_MANUALFAKE3333333333333333333333333333` — every test/execute against it must fail with a provider rejection (the token is fake) and must never be reported as success |

The macOS Keychain destination writes only the fake values above into your
login keychain under the secret name shown, and the plan deletes it again
("delete at destination"). macOS may show a keychain permission prompt.

## 12. Live verification (instructions only — never paste credentials here)

The optional live scripts each prompt for their credential **hidden, at run
time**. Do **not** put a real credential in any file, chat, command-line
argument, or environment variable ahead of time; the scripts refuse
argument-passed secrets by design. What each needs is documented in the test
plan's live-verification section (§L) and in
[PROVIDER_SUPPORT.md](PROVIDER_SUPPORT.md):

- `scripts/live_verify_openai.sh` — an OpenAI **Admin** key you create for
  the test and revoke afterwards.
- `scripts/live_verify_anthropic.sh` — an Anthropic **Admin** key
  (`sk-ant-admin…`), likewise.
- `scripts/live_verify_github.sh` — a fine-grained PAT with only
  **Plan: read**.
- `scripts/live_verify_stripe.sh` — a **test-mode** or read-only restricted
  Stripe key.
- `scripts/live_verify_aws.sh` — a minimally scoped IAM key
  (`secretsmanager` on `api-tracker-live-verify-*` only). Max cost < $0.05.
- `scripts/live_verify_github_actions.sh` — a PAT with Secrets read/write on
  a **throwaway** repository only.
- `scripts/live_verify_vercel.sh` — an access token and a **throwaway**
  Vercel project.

## 13. Value-purpose index

| Category | Values |
| --- | --- |
| Normal local storage | C1–C6, replacement values (§4) |
| Invalid-provider validation | C2 (OpenAI-shaped), C3 (GitHub-shaped), C4 (Stripe test-mode-shaped) — all fail live validation with a provider rejection |
| Duplicate detection | C5 + C6 shared value |
| Git scanning | §5 fixtures (`FAKE`-marked, detector-proven) + placeholders that must stay unflagged |
| `.env` import | §6 files (secrets, non-secret, placeholder, malformed, duplicate) |
| Rotation mocks | §4 replacement values + §11 destinations |
| Live verification | §12 — instructions only, no values by design |
