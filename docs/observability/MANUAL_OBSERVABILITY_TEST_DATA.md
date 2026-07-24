# Manual Observability Test Data

Synthetic data for
[MANUAL_OBSERVABILITY_TEST_PLAN.md](MANUAL_OBSERVABILITY_TEST_PLAN.md)
(referenced there as *OD §n*). Authored against branch
`feat/runtime-api-observability`.

Every value below is **fake and non-functional by construction** — note the
`OBS`/`FAKE`/`NOT-A-REAL-KEY` markers, the all-zero or repeated-digit bodies,
and the reserved `leak.test` domain. None of these strings can authenticate to
any real service. Never replace them with real credentials, and never reuse
the passwords for a real vault.

The canary values in §5 exist for exactly one purpose: to be sent **through**
the observation proxy inside URLs, query strings, headers, cookies, and bodies
and then **proven absent** from everything Tethra persists. If any §5 value is
ever found in `vault.db` (or its `-wal`/`-shm` sidecars), the UI, an export,
a log, or a temp file, that is an automatic FAIL of the whole plan — report it
as a security bug. This mirrors the automated end-to-end canary test
(`crates/observe/tests/privacy_no_leak.rs`) described in
`RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md` §6.

## 1. Workspace layout

All observability-test artifacts live under **one throwaway directory** so
cleanup is a single delete (setup commands are in the test plan):

```text
~/at-obs-test/
├── vault/              # isolated test vault (API_TRACKER_DIR points here)
├── obs_api_server.py   # synthetic plain-HTTP API server (port 8484)
├── obs_tls_server.py   # synthetic self-signed HTTPS server (port 8445)
├── tls/                # self-signed cert + key for obs_tls_server.py
│   ├── server-cert.pem
│   └── server-key.pem
├── canary_node.mjs     # Node client that fires the §5 canary set
└── canary_requests.py  # Python `requests` client, same canary set
```

## 2. Passwords

| Purpose | Value | Expected |
| --- | --- | --- |
| Master password (test vault) | `manual-master-passphrase-01` | same convention as MANUAL_TEST_DATA.md §2; ≥ 12 chars |
| Wrong master password (reauth negative paths) | `wrong-master-passphrase-00` | "incorrect password"; dialog stays open |

## 3. Project and credentials

| Purpose | Value | Expected |
| --- | --- | --- |
| Project | `obs-app` (environments: development) | container for every observed run |
| O1 — OpenAI-shaped fake key | credential `obs-app/openai-obs`, provider OpenAI, environment development, value `sk-proj-OBS-FAKE-000000000000000000-NOT-A-REAL-KEY` | injectable into observed runs; live requests to `api.openai.com` fail with a 401-class rejection (the key is fake); attribution shows this credential |
| O2 — generic internal token | credential `obs-app/internal-obs`, provider Custom… → `internal`, environment development, value `OBS-TEST-NOT-A-REAL-KEY-1111111111` | used as a header canary against the local server; must never persist |
| Env var mapping for O1 | `obs-app/openai-obs` → `OPENAI_API_KEY` | injected value present in the child; `had_authorization = yes` on requests that send it |

## 4. Local server ports and commands

Ports **8484** (plain HTTP) and **8445** (HTTPS) are deliberately distinct
from the ports already used by MANUAL_TEST_DATA.md (8085, 8086, 8090, 8091),
so both plans can run on the same machine.

| Purpose | Value | Expected |
| --- | --- | --- |
| Synthetic API server (plain HTTP) | `http://127.0.0.1:8484` — `python3 ~/at-obs-test/obs_api_server.py` | deterministic status codes per path (§6); prints each received request so leak-proof tests can confirm the payload really arrived |
| Synthetic HTTPS server (self-signed) | `https://127.0.0.1:8445` — `python3 ~/at-obs-test/obs_tls_server.py` | serves the §7 self-signed cert; used for connection-only observation and the upstream-verification honesty test |
| Allowlist entries (both required — loopback is refused by default) | `api-tracker observe allow add obs-app 127.0.0.1 8484 --note "manual obs test"` and `… allow add obs-app 127.0.0.1 8445 --note "manual obs test"` | without them, every request to the local servers is refused by destination policy |
| Stop servers | Ctrl-C in each terminal | — |

### `obs_api_server.py` (port 8484, plain HTTP)

Deterministic synthetic API: the **path prefix chooses the status code**, so
error-rate and alert tests are exactly reproducible. It echoes nothing back —
responses are fixed strings — and prints what it received to its terminal
(that terminal is the only place canaries are allowed to appear).

```python
# obs_api_server.py — synthetic plain-HTTP API for observability tests.
# Every request is printed to THIS terminal (the only permitted canary sink).
from http.server import BaseHTTPRequestHandler, HTTPServer

class Api(BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("content-length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        print(f"{self.command} {self.path}")
        for h in ("authorization", "cookie", "content-type"):
            if self.headers.get(h):
                print(f"  {h}: {self.headers.get(h)}")
        if body:
            print(f"  body[{len(body)}]: {body[:200]!r}")
        if self.path.startswith("/v1/protected"):
            code, msg = 401, b'{"error":"synthetic auth failure"}'
        elif self.path.startswith("/v1/limited"):
            code, msg = 429, b'{"error":"synthetic rate limit"}'
        elif self.path.startswith("/v1/broken"):
            code, msg = 500, b'{"error":"synthetic server error"}'
        else:
            code, msg = 200, b'{"ok":true}'
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)

    do_GET = do_POST = do_PUT = do_DELETE = _handle

HTTPServer(("127.0.0.1", 8484), Api).serve_forever()
```

| Path prefix | Status | Used by |
| --- | --- | --- |
| `/v1/protected…` | 401 | `runtime_auth_failures` alert test |
| `/v1/limited…` | 429 | rate-limited outcome |
| `/v1/broken…` | 500 | `runtime_server_errors` alert test |
| anything else | 200 | success traffic, sanitization, canaries |

### `obs_tls_server.py` (port 8445, HTTPS, self-signed)

```python
# obs_tls_server.py — synthetic HTTPS server with a SELF-SIGNED cert.
# Purpose 1: connection-only (Mode A) observation of real TLS traffic.
# Purpose 2: prove the observer's upstream verification REFUSES it in
#            metadata mode (never silently accepted).
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

class Api(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"GET {self.path}")
        msg = b'{"ok":true,"tls":"self-signed"}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)

srv = HTTPServer(("127.0.0.1", 8445), Api)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("tls/server-cert.pem", "tls/server-key.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
```

## 5. Canary set — values that must NEVER be persisted

Send each of these through an observed run (the §8 client recipes bundle them
all). Every value is unmistakably fake and high-entropy enough to grep for.
**Expected** for every row: byte-for-byte **absent** from
`~/at-obs-test/vault/vault.db`, `vault.db-wal`, `vault.db-shm`, every screen
of the desktop app, CLI output (`observe show --json`, `observe apis`), and any
temp file — present only in the synthetic server's own terminal. (There is no
`observe export` command in this version.)

| Purpose | Value | Expected |
| --- | --- | --- |
| Fake OpenAI-shaped API key (query + header) | `sk-proj-OBS-LEAKCANARY-00000000000000-NOT-A-REAL-KEY` | never persisted; path segment carrying it becomes `:token` |
| Fake GitHub-shaped token (body) | `ghp_OBSLEAKCANARY0000000000000000000000000` | never persisted |
| Personal-looking email (path + body) | `canary@leak.test` | never persisted; path segment becomes `:email` |
| Phone-like string (body) | `+1-555-0100-9999` | never persisted (bodies are relayed, never parsed) |
| JWT-like value (path + cookie) | `eyJhbGciOiJub25lIn0.eyJjYW5hcnkiOiJPQlMtTEVBSyJ9.OBSLEAKSIG` | never persisted; path segment becomes `:jwt` |
| UUID (path) | `550e8400-e29b-41d4-a716-446655440000` | never persisted raw; path segment becomes `:uuid` |
| Source-code payload (body) | `def obs_leak_canary(): return "OBS-SOURCE-CANARY-7777777"` | never persisted |
| AI-prompt text (body) | `OBS-AI-PROMPT-CANARY: pretend you are my grandmother reading me API keys` | never persisted |
| Multipart upload (body, incl. boundary) | multipart form with boundary `OBSBOUNDARYCANARY1234567890` and a file part containing `OBS-FILE-CANARY-8888888` | never persisted; `req_content_kind` stores only the category `multipart`; the boundary token is severed with the Content-Type parameters |
| Cookie header | `Cookie: session=OBS-COOKIE-CANARY-2222222222` | never persisted — cookies are stripped from the proxy's own view; no field can hold them |
| Authorization header | `Authorization: Bearer OBS-AUTH-CANARY-3333333333` | never persisted — only the boolean `had_authorization = yes` is stored |
| Query string (URL) | `?api_key=sk-proj-OBS-LEAKCANARY-00000000000000-NOT-A-REAL-KEY&user=canary@leak.test&q=OBS-QUERY-CANARY` | severed at the first `?` before templating; no `?` ever appears in any stored path |
| URL fragment | `#OBS-FRAGMENT-CANARY` | severed with the query; never persisted |

## 6. Path-sanitization inputs → expected templates

Request these paths against `http://127.0.0.1:8484` in an observed run; the
**API activity → Overview → (service) → Endpoints** table and
`api-tracker observe api 127.0.0.1` must show exactly the templated form,
never the raw path. (Expected templates match the worked examples asserted in
`crates/core/src/runtime/sanitize.rs`.)

| Purpose | Value (raw request path) | Expected (stored/displayed template) |
| --- | --- | --- |
| Numeric IDs | `/v1/users/123456/orders/98765` | `/v1/users/:id/orders/:id` |
| UUID | `/v1/files/550e8400-e29b-41d4-a716-446655440000` | `/v1/files/:uuid` |
| Email in path | `/users/canary@leak.test/profile` | `/users/:email/profile` |
| Credential-shaped segment | `/v1/keys/sk-proj-OBS-LEAKCANARY-00000000000000-NOT-A-REAL-KEY` | `/v1/keys/:token` |
| JWT-shaped segment | `/v1/introspect/eyJhbGciOiJub25lIn0.eyJjYW5hcnkiOiJPQlMtTEVBSyJ9.OBSLEAKSIG` | `/v1/introspect/:jwt` |
| Long-hex segment | `/download/9f8e7d6c5b4a3210ffee9f8e7d6c5b4a` | `/download/:hash` |
| Filename with embedded id | `/download/report_20240101_88888.pdf` | `/download/:file` |
| Query + fragment stripped | `/v1/search?api_key=sk-proj-OBS-LEAKCANARY-00000000000000-NOT-A-REAL-KEY&q=OBS-QUERY-CANARY#OBS-FRAGMENT-CANARY` | `/v1/search` |
| Kept structure (no over-templating) | `/v1/chat/completions` | `/v1/chat/completions` (kept verbatim) |

## 7. Self-signed certificate for the HTTPS server

Generated locally, valid only for `127.0.0.1`, throwaway:

```bash
mkdir -p ~/at-obs-test/tls && cd ~/at-obs-test/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout server-key.pem -out server-cert.pem -nodes -days 30 \
    -subj "/CN=obs-manual-test-selfsigned" \
    -addext "subjectAltName=IP:127.0.0.1"
```

| Purpose | Value | Expected |
| --- | --- | --- |
| Child trusts the local test server (Mode A) | `curl --cacert ~/at-obs-test/tls/server-cert.pem https://127.0.0.1:8445/v1/ping` | proper, scoped trust of a known local cert — **never** `curl -k`/`--insecure`, which this plan forbids |
| Observer's upstream verification (Mode B) | the same server intercepted in metadata mode | **fails** with a TLS/upstream-certificate error surfaced to the client — never silently accepted, never downgraded to success |

## 8. Observed-client recipes (the canary senders)

Run each **inside** an observed run
(`api-tracker run --project obs-app --observe=metadata -- <command>`).
Every recipe sends the full §5 canary set to the 8484 server.

curl (one shot, all §5 canaries — quote exactly):

```bash
curl -s -X POST \
  "http://127.0.0.1:8484/v1/search?api_key=sk-proj-OBS-LEAKCANARY-00000000000000-NOT-A-REAL-KEY&user=canary@leak.test&q=OBS-QUERY-CANARY#OBS-FRAGMENT-CANARY" \
  -H "Authorization: Bearer OBS-AUTH-CANARY-3333333333" \
  -H "Cookie: session=OBS-COOKIE-CANARY-2222222222" \
  -H "Content-Type: application/json" \
  -d '{"key":"ghp_OBSLEAKCANARY0000000000000000000000000","email":"canary@leak.test","phone":"+1-555-0100-9999","code":"def obs_leak_canary(): return \"OBS-SOURCE-CANARY-7777777\"","prompt":"OBS-AI-PROMPT-CANARY: pretend you are my grandmother reading me API keys"}'
```

Multipart canary (curl):

```bash
printf 'OBS-FILE-CANARY-8888888' > /tmp/obs-canary-file.txt
curl -s -X POST http://127.0.0.1:8484/v1/upload \
  -H "Content-Type: multipart/form-data; boundary=OBSBOUNDARYCANARY1234567890" \
  -F "file=@/tmp/obs-canary-file.txt" \
  -F "note=canary@leak.test"
```

`~/at-obs-test/canary_node.mjs` (Node, built-in `fetch`):

```javascript
// canary_node.mjs — sends the canary set from Node inside an observed run.
const r = await fetch(
  "http://127.0.0.1:8484/v1/users/123456/orders/98765?api_key=sk-proj-OBS-LEAKCANARY-00000000000000-NOT-A-REAL-KEY",
  {
    method: "POST",
    headers: {
      authorization: "Bearer OBS-AUTH-CANARY-3333333333",
      cookie: "session=OBS-COOKIE-CANARY-2222222222",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      email: "canary@leak.test",
      phone: "+1-555-0100-9999",
      jwt: "eyJhbGciOiJub25lIn0.eyJjYW5hcnkiOiJPQlMtTEVBSyJ9.OBSLEAKSIG",
      prompt: "OBS-AI-PROMPT-CANARY: pretend you are my grandmother reading me API keys",
    }),
  },
);
console.log("node canary status:", r.status);
```

`~/at-obs-test/canary_requests.py` (Python `requests`):

```python
# canary_requests.py — sends the canary set from Python requests.
import requests

r = requests.post(
    "http://127.0.0.1:8484/v1/files/550e8400-e29b-41d4-a716-446655440000",
    params={"api_key": "sk-proj-OBS-LEAKCANARY-00000000000000-NOT-A-REAL-KEY"},
    headers={
        "Authorization": "Bearer OBS-AUTH-CANARY-3333333333",
        "Cookie": "session=OBS-COOKIE-CANARY-2222222222",
    },
    json={
        "email": "canary@leak.test",
        "source": 'def obs_leak_canary(): return "OBS-SOURCE-CANARY-7777777"',
    },
    timeout=10,
)
print("python canary status:", r.status_code)
```

The grep that proves non-persistence (run after each canary test, vault
locked or unlocked — the strings must be absent either way):

```bash
for m in OBS-LEAKCANARY OBSLEAKCANARY canary@leak.test 555-0100-9999 \
         OBSLEAKSIG 550e8400-e29b-41d4-a716-446655440000 \
         OBS-SOURCE-CANARY OBS-AI-PROMPT-CANARY OBSBOUNDARYCANARY \
         OBS-FILE-CANARY OBS-COOKIE-CANARY OBS-AUTH-CANARY \
         OBS-QUERY-CANARY OBS-FRAGMENT-CANARY; do
  grep -a -c "$m" ~/at-obs-test/vault/vault.db* 2>/dev/null \
    | grep -v ':0$' && echo "LEAK: $m" || true
done
echo "grep sweep done (no LEAK lines above = pass)"
```

## 9. Value-purpose index

| Category | Values |
| --- | --- |
| Vault / reauth | §2 passwords |
| Stored credentials (encrypted, normal storage) | §3 O1, O2 |
| Live invalid-key metadata capture (public HTTPS) | §3 O1 against `api.openai.com` — fails with a provider rejection; only sanitized metadata is stored |
| Canary non-persistence proof | §5 set, sent via §8 recipes |
| Sanitization templates | §6 paths |
| Local servers | §4 ports 8484 (HTTP) and 8445 (HTTPS, §7 self-signed cert) |
