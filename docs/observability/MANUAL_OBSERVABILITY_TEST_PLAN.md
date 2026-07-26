# Manual Observability Test Plan

A button-by-button manual test plan for **runtime API observability** — the
local, opt-in, metadata-only HTTPS observation proxy — written for a tester
who has never seen the code. Authored against branch
`feat/runtime-api-observability` (commit `4f70adc`); this feature does not
exist on `main`.

Companions:

- [MANUAL_OBSERVABILITY_TEST_DATA.md](MANUAL_OBSERVABILITY_TEST_DATA.md) —
  every synthetic value, canary, server script, and client recipe used below
  (referenced as *OD §n*). **Never use real credentials.**
- [../MANUAL_UI_TEST_PLAN.md](../MANUAL_UI_TEST_PLAN.md) — the base app plan;
  this plan reuses its template, its vault conventions, and its Part 1 build
  instructions.
- The gate documents this plan verifies against:
  [RUNTIME_OBSERVABILITY_ARCHITECTURE.md](RUNTIME_OBSERVABILITY_ARCHITECTURE.md),
  [RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md](RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md),
  [RUNTIME_OBSERVABILITY_THREAT_MODEL.md](RUNTIME_OBSERVABILITY_THREAT_MODEL.md),
  [RUNTIME_COMPATIBILITY_MATRIX.md](RUNTIME_COMPATIBILITY_MATRIX.md).

## How to read a test case

Every test uses the repository's standard template:

```text
Test ID / title
Mode:                       Manual UI | Manual UI + CLI | CLI | Mocked provider |
                            Optional live provider | Platform-specific (macOS)
Requirement:                what product requirement this verifies
Starting state:             what must already be true
Prerequisites:              data/tools needed
Exact navigation:           screen path from the top bar
Exact buttons to click:     verbatim labels, in order
Exact fields to fill:       verbatim labels
Exact test values:          from MANUAL_OBSERVABILITY_TEST_DATA.md
Expected visible result:    exact on-screen outcome
Expected persisted result:  what survives a reload/restart, and where
Expected audit/alert result:alerts raised, or audit-trail visibility
Expected security behavior: redaction/reauth/confirmation guarantees
Cleanup:                    what to undo (— if nothing)
Screenshot checkpoint:      take one here (— if not needed)
Pass/fail:                  ☐
```

Notes that apply everywhere:

- **Metadata only is the whole point.** If you ever see a request body,
  response body, header value, cookie, query string, full raw URL, or any
  OD §5 canary value anywhere in the app, CLI output, database, export, or
  temp file, that is an automatic FAIL of the whole plan — report it as a
  security bug. The only permitted canary sink is the synthetic server's own
  terminal.
- **Honesty rules.** The product never claims visibility it lacks: HTTP/2 is
  not decoded (clients are downgraded to HTTP/1.1 for the monitored run, or
  tunneled opaquely), HTTP/3/QUIC bypasses the proxy entirely, pinned clients
  fail closed, and runtimes that ignore trust variables fall back to
  connection-only with a **partial coverage** badge. A test that finds a
  green, complete-looking dashboard for a run whose traffic bypassed
  observation is a FAIL.
- **Never disable TLS verification.** No test in this plan uses
  `curl -k`/`--insecure`, `NODE_TLS_REJECT_UNAUTHORIZED`, or any equivalent.
  If a step seems to need one, the step is wrong.
- **Reauthentication dialog** means the shared dialog with the text "Confirm
  your master password to continue.", a **Master password** field, and
  **Cancel** — same semantics as the base plan (wrong password shows
  `incorrect password`, Cancel always aborts with no effect).
- The desktop screen under test is the top-bar destination **API activity**
  with tabs **Overview · Sessions · Certificate · Settings · Diagnostics ·
  Privacy**. The CLI verb under test is `tethra observe …` plus
  `tethra run --observe=off|connection|metadata`.
- Run this entire plan against the isolated vault
  (`API_TRACKER_DIR=~/at-obs-test/vault`). Never run it against a real vault,
  and never install system trust (OBS-10) on a machine you do not own.

---

## Part 1 — One-time setup (verified command shapes)

Build the CLI and desktop app exactly as in the base plan's Part 1
(`cargo build --release -p api-tracker-cli`; `cd apps/desktop && npm install`),
from this branch.

### 1.1 Isolated workspace and vault

```bash
mkdir -p ~/at-obs-test/vault
export API_TRACKER_DIR=~/at-obs-test/vault
export PATH="$PWD/target/release:$PATH"

# Desktop app against the same vault:
cd apps/desktop
API_TRACKER_DIR=~/at-obs-test/vault npm run tauri dev
```

Create the vault on first launch with the master password from OD §2
(`manual-master-passphrase-01`), then for CLI convenience:

```bash
export API_TRACKER_PASSWORD='manual-master-passphrase-01'
```

### 1.2 Local synthetic servers (Python; ports 8484 and 8445)

The scripts are printed in full in OD §4 and OD §7. Ports 8484/8445 are new —
deliberately not the base plan's 8085/8086/8090/8091, so both plans can run
side by side.

```bash
# One-time: self-signed cert for the HTTPS server (OD §7)
mkdir -p ~/at-obs-test/tls && cd ~/at-obs-test/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout server-key.pem -out server-cert.pem -nodes -days 30 \
    -subj "/CN=obs-manual-test-selfsigned" \
    -addext "subjectAltName=IP:127.0.0.1"

# Terminal A — synthetic plain-HTTP API (deterministic status codes, OD §4):
cd ~/at-obs-test && python3 obs_api_server.py        # 127.0.0.1:8484

# Terminal B — synthetic self-signed HTTPS server (OD §7):
cd ~/at-obs-test && python3 obs_tls_server.py        # 127.0.0.1:8445
```

### 1.3 Resetting only test data — safely

> ⚠️ **Deletion warning.** Check each path before pressing Enter; never point
> these at a real vault directory.

```bash
rm -rf ~/at-obs-test
rm -f /tmp/obs-canary-file.txt
```

If OBS-10 installed system trust and you skipped OBS-18, remove it before
deleting anything: `tethra observe cert uninstall` (macOS: verify with
`security find-certificate -c "Tethra Local Observation CA"` → not found).

---

## Part 2 — Test cases

Run in the order printed; later tests reuse earlier data and state.

### Setup and baseline

#### OBS-01 — project, credentials, allowlist

```text
Mode: Manual UI + CLI
Requirement: fixtures exist; loopback destinations require an explicit
  per-project allowlist (secure default)
Starting state: vault created (Part 1.1), app unlocked
Prerequisites: OD §3, §4
Exact navigation: Projects → New project; then obs-app → Add credential (twice)
Exact buttons to click: New project; Create project; Add credential
Exact fields to fill: Name; Provider; Environment; Secret value
Exact test values: project obs-app (environment development); credentials O1
  and O2 exactly as OD §3; then CLI:
    tethra observe allow add obs-app 127.0.0.1 8484 --note "manual obs test"
    tethra observe allow add obs-app 127.0.0.1 8445 --note "manual obs test"
    tethra observe allow list obs-app
Expected visible result: obs-app shows 2 credentials (values masked); allow
  list prints both (host, port, note) entries
Expected persisted result: entries survive relaunch (observe_internal_allowlist)
Expected audit/alert result: —
Expected security behavior: before the allow-add, an observed request to
  127.0.0.1:8484 is REFUSED by destination policy (verified implicitly in
  OBS-05 preamble); credential values masked everywhere
Cleanup: —
Screenshot checkpoint: —
Pass/fail: ☐
```

#### OBS-02 — start the local servers

```text
Mode: CLI
Requirement: deterministic local observation targets (OD §4, §7)
Starting state: Part 1.2 cert generated
Prerequisites: python3, openssl
Exact navigation: —
Exact buttons to click: —
Exact fields to fill: —
Exact test values: python3 ~/at-obs-test/obs_api_server.py   (terminal A, :8484)
  python3 ~/at-obs-test/obs_tls_server.py                     (terminal B, :8445)
Expected visible result: both servers idle, printing requests as they arrive
Expected persisted result: —
Expected audit/alert result: —
Expected security behavior: servers bind 127.0.0.1 only
Cleanup: Ctrl-C both at the end of the plan
Screenshot checkpoint: —
Pass/fail: ☐
```

#### OBS-03 — existing non-observed runs are unchanged

```text
Mode: CLI
Requirement: without --observe, `run` behaves exactly as before this branch:
  no proxy, no trust variables, no observation rows
Starting state: OBS-01, OBS-02
Prerequisites: —
Exact navigation: —
Exact buttons to click: —
Exact fields to fill: —
Exact test values:
  tethra run --project obs-app -- sh -c \
    'env | grep -iE "proxy|ca_bundle|extra_ca|ssl_cert" ; \
     curl -s http://127.0.0.1:8484/v1/plain ; echo'
Expected visible result: the env grep prints NOTHING (no HTTP(S)_PROXY, no
  NODE_EXTRA_CA_CERTS/REQUESTS_CA_BUNDLE/SSL_CERT_FILE/CURL_CA_BUNDLE added);
  curl reaches the server DIRECTLY ({"ok":true}); server terminal shows the
  request (it did not pass through any proxy)
Expected persisted result: `tethra observe sessions --project obs-app`
  lists NO session for this run; API activity → Sessions is empty
Expected audit/alert result: no runtime_* alert
Expected security behavior: observation is strictly opt-in per run; nothing
  machine-wide, nothing by default
Cleanup: —
Screenshot checkpoint: —
Pass/fail: ☐
```

### Observation modes

#### OBS-04 — Mode A (connection) needs no certificate trust

```text
Mode: Manual UI + CLI
Requirement: connection-only observation records host/port/bytes/latency
  without decrypting HTTPS and without any CA trust anywhere
Starting state: OBS-01..02; no local CA exists yet (fresh vault)
Prerequisites: OD §7 cert (for the CHILD to trust the local test server —
  proper scoped trust of a known test cert, not a bypass)
Exact navigation: API activity → Sessions (after the run); API activity →
  Certificate
Exact buttons to click: —
Exact fields to fill: —
Exact test values:
  tethra run --project obs-app --observe=connection -- \
    curl -s --cacert ~/at-obs-test/tls/server-cert.pem \
    https://127.0.0.1:8445/v1/ping
Expected visible result: curl prints {"ok":true,"tls":"self-signed"}; the run
  summary names the session; API activity → Sessions shows it with mode
  "connection"; opening it shows host 127.0.0.1, port 8445, bytes each way,
  connect latency/duration — and method/path/status shown as unavailable
  ("—"), never invented; Certificate tab still says "No local CA yet …"
Expected persisted result: `observe show <session>` reports
  observation_source connection_only; no endpoint row gains a method/path
Expected audit/alert result: —
Expected security behavior: no CA was generated, no trust variable was set
  for interception (child env has proxy vars but no Tethra CA bundle); the
  proxy never decrypted the TLS stream — the metadata columns that would
  prove decryption (method/path/status) are honestly NULL
Cleanup: —
Screenshot checkpoint: the connection-only session detail with "—" columns
Pass/fail: ☐
```

#### OBS-05 — Mode B (metadata) works for curl

```text
Mode: Manual UI + CLI + network (no account needed — the key is fake)
Requirement: scoped metadata observation intercepts HTTPS for the launched
  child only; curl honours CURL_CA_BUNDLE (FullySupported in the matrix)
Starting state: OBS-01..02
Prerequisites: internet available (api.openai.com); O1 value from OD §3
Exact navigation: API activity → Overview; API activity → Sessions
Exact buttons to click: (Overview) the api.openai.com service row
Exact fields to fill: —
Exact test values:
  tethra run --project obs-app --credential obs-app/openai-obs \
    --observe=metadata -- \
    sh -c 'curl -s https://api.openai.com/v1/models \
             -H "Authorization: Bearer $OPENAI_API_KEY" >/dev/null; echo done'
Expected visible result: the child completes ("done"; the provider rejects
  the fake key — a 401-class response, which is the point); first metadata
  run generates the local CA (Certificate tab now shows Fingerprint
  (SHA-256), Created, Expires, System trust "absent"); Overview lists
  api.openai.com with 1+ requests; the event shows method GET, path template
  /v1/models, status 401, outcome auth_error, protocol http1.1,
  authorization-present = yes; attribution names obs-app/openai-obs
Expected persisted result: `observe api api.openai.com` shows the same
  sanitized event; `observe sessions` lists the session as completed
Expected audit/alert result: repeated 401s may raise runtime_auth_failures
  later (OBS-14 forces it deterministically)
Expected security behavior: the fake key appears ONLY inside the relayed
  request — never on screen, never in the DB (OD §8 grep sweep passes); the
  Authorization header VALUE is never stored, only its presence as a boolean
Cleanup: —
Screenshot checkpoint: Overview with api.openai.com and the 401 event
Pass/fail: ☐
```

#### OBS-06 — Mode B works for Node.js

```text
Mode: Manual UI + CLI
Requirement: Node honours NODE_EXTRA_CA_CERTS + HTTPS_PROXY (FullySupported)
Starting state: OBS-05 done (CA exists)
Prerequisites: Node 20+; OD §8 canary_node.mjs; server :8484 running
Exact navigation: API activity → Overview → 127.0.0.1 (the :8484 service)
Exact buttons to click: —
Exact fields to fill: —
Exact test values:
  tethra run --project obs-app --observe=metadata -- \
    node ~/at-obs-test/canary_node.mjs
Expected visible result: script prints "node canary status: 200"; server
  terminal A shows the raw canary request (proof it arrived intact); the
  Overview service 127.0.0.1 gains endpoint
  POST /v1/users/:id/orders/:id — raw IDs 123456/98765 nowhere visible
Expected persisted result: the event row persists with the templated path;
  the OD §8 grep sweep finds NO canary marker in vault.db/-wal/-shm
Expected audit/alert result: —
Expected security behavior: interception applied ONLY to the child (a curl
  run from a separate normal terminal to :8484 does not pass through any
  proxy and creates no event)
Cleanup: —
Screenshot checkpoint: —
Pass/fail: ☐
```

#### OBS-07 — Mode B works for Python `requests`

```text
Mode: Manual UI + CLI
Requirement: Python requests honours REQUESTS_CA_BUNDLE + HTTPS_PROXY
  (FullySupported)
Starting state: OBS-06
Prerequisites: python3 with `requests` installed; OD §8 canary_requests.py
Exact navigation: API activity → Overview → 127.0.0.1
Exact buttons to click: —
Exact fields to fill: —
Exact test values:
  tethra run --project obs-app --observe=metadata -- \
    python3 ~/at-obs-test/canary_requests.py
Expected visible result: script prints "python canary status: 200"; the
  service gains endpoint POST /v1/files/:uuid; the raw UUID
  550e8400-e29b-41d4-a716-446655440000 appears nowhere in the UI
Expected persisted result: grep sweep (OD §8) still clean
Expected audit/alert result: —
Expected security behavior: as OBS-06
Cleanup: —
Screenshot checkpoint: —
Pass/fail: ☐
```

### Trust boundaries

#### OBS-08 — scoped mode does NOT install a system certificate

```text
Mode: Platform-specific (macOS) + CLI
Requirement: Mode B never touches the OS trust store (mirror of the
  automated `mode_b_never_installs` check)
Starting state: several Mode B runs completed (OBS-05..07)
Prerequisites: macOS `security` CLI
Exact navigation: API activity → Certificate
Exact buttons to click: —
Exact fields to fill: —
Exact test values:
  security find-certificate -c "Tethra Local Observation CA"
  tethra observe cert status
Expected visible result: `security find-certificate` FAILS (no such
  certificate in any keychain); `observe cert status` shows the CA present
  in the vault with system trust "absent"; Certificate tab System trust row
  reads "absent"
Expected persisted result: still absent after further Mode B runs
Expected audit/alert result: —
Expected security behavior: scoped trust lives only in per-child environment
  variables and temp bundle files; the system store is untouched without the
  explicit Mode C flow (OBS-10)
Cleanup: —
Screenshot checkpoint: Certificate tab with System trust "absent"
Pass/fail: ☐
```

#### OBS-09 — Mode C never auto-enables

```text
Mode: Manual UI + CLI
Requirement: system trust is opt-in only — never a default, never pre-ticked,
  never a side effect of any run mode or setting
Starting state: OBS-08 (system trust absent)
Prerequisites: —
Exact navigation: API activity → Settings; API activity → Certificate
Exact buttons to click: (Settings) open the "Default observation mode for
  Tethra-launched runs" select — inspect only; Save settings NOT clicked
Exact fields to fill: —
Exact test values: run one more metadata run (repeat OBS-06's command);
  then: tethra observe cert status ; tethra observe settings show
Expected visible result: the mode select offers only off / connection /
  metadata — there is NO "system trust" run mode and no pre-ticked install
  option anywhere; the default is "off (recommended — monitoring is opt-in
  per run)"; after the extra run, cert status still reports system trust
  "absent"; the only route to Mode C is the explicit "Install in system
  trust (Mode C)" button (OBS-10) or `observe cert install`, both
  reauthentication-gated
Expected persisted result: settings default_mode remains off
Expected audit/alert result: —
Expected security behavior: no code path enables system trust implicitly;
  the CLI install refuses without confirmation (`observe cert install`
  prompts "Proceed with system-trust installation?" and aborts on anything
  but yes)
Cleanup: —
Screenshot checkpoint: —
Pass/fail: ☐
```

#### OBS-10 — the OS prompt appears only after explicit install

```text
Mode: Platform-specific (macOS), Manual UI
Requirement: Mode C requires plain-language explanation + explicit choice +
  master-password reauthentication + the OS's own prompt, in that order
Starting state: OBS-09; system trust absent; you are on a personal test
  machine (never run this on a machine you do not own)
Prerequisites: macOS admin/user keychain access
Exact navigation: API activity → Certificate
Exact buttons to click: Install in system trust (Mode C); in the dialog
  titled "Install the CA in your system trust store": first Cancel (negative
  path), then repeat and Install
Exact fields to fill: Master password
Exact test values: manual-master-passphrase-01
Expected visible result: the warnbox on the tab states plainly that Mode C
  makes EVERY application trust this CA, is off by default, and that deleting
  the app does NOT remove it; Cancel path: dialog closes, no OS prompt ever
  appeared, system trust still "absent"; Install path: reauth first, THEN
  macOS shows its own authorization prompt; after approving, notice
  "Installed in the system trust store." and System trust row "installed"
Expected persisted result: `security find-certificate -c "Tethra Local
  Observation CA"` now finds the certificate;
  `observe cert status` reports system trust installed
Expected audit/alert result: —
Expected security behavior: at no earlier point in this plan (OBS-01..09)
  did any OS trust prompt appear — the prompt is reachable ONLY through this
  explicit, reauthenticated flow; wrong master password
  (wrong-master-passphrase-00) keeps the dialog open and never reaches the
  OS prompt
Cleanup: system trust is REMOVED again in OBS-18 — do not skip it
Screenshot checkpoint: the macOS trust prompt
Pass/fail: ☐
```

### Privacy proofs

#### OBS-11 — payloads, headers, cookies, and query strings never persist

```text
Mode: Manual UI + CLI
Requirement: metadata only, structurally enforced — no canary from OD §5 may
  survive into any store or surface
Starting state: OBS-06/07 canary runs done; also run the curl canary and the
  multipart canary from OD §8 inside one more metadata run
Prerequisites: OD §5 canary table, OD §8 recipes + grep sweep
Exact navigation: API activity → Overview → 127.0.0.1 → each endpoint and
  recent event; API activity → Sessions → the canary sessions
Exact buttons to click: —
Exact fields to fill: —
Exact test values: the OD §8 grep sweep, run twice — once with the vault
  unlocked, once after Lock vault; plus (there is no `observe export` command
  in this version — inspect the CLI/JSON surfaces directly instead):
    tethra observe api 127.0.0.1
    tethra observe show <session-id> --json > ~/at-obs-test/show.json
    grep -c "OBS-.*CANARY\|canary@leak.test" ~/at-obs-test/show.json
Expected visible result: every UI surface shows templated paths with NO query
  string (no "?" anywhere), no header values, no cookie, no body fragment;
  content type shown only as a category (json / multipart); the multipart
  boundary string appears nowhere
Expected persisted result: the grep sweep prints no LEAK lines; the
  `observe show --json` grep finds 0 matches; the canaries exist only in the
  synthetic server's terminal
Expected audit/alert result: audit/activity tables also contain no canary
  (covered by the sweep against the whole vault.db)
Expected security behavior: this is the manual mirror of the automated canary
  test (intercept_captures_sanitized_metadata_and_leaks_no_payload in
  proxy_integration.rs); a single hit anywhere fails the entire plan
Cleanup: rm ~/at-obs-test/show.json
Screenshot checkpoint: an event detail showing sanitized path + boolean
  authorization-present
Pass/fail: ☐
```

#### OBS-12 — path sanitization matches the specification

```text
Mode: Manual UI + CLI
Requirement: identifier-shaped segments are replaced (:id/:uuid/:email/
  :token/:jwt/:hash/:file); stable structure is kept (no over-templating)
Starting state: servers running; OBS-01 allowlist in place
Prerequisites: OD §6 table
Exact navigation: API activity → Overview → 127.0.0.1 → Endpoints
Exact buttons to click: —
Exact fields to fill: —
Exact test values: one metadata run requesting every OD §6 path:
  tethra run --project obs-app --observe=metadata -- sh -c '
    for p in "/v1/users/123456/orders/98765" \
             "/v1/files/550e8400-e29b-41d4-a716-446655440000" \
             "/users/canary@leak.test/profile" \
             "/v1/keys/sk-proj-OBS-LEAKCANARY-00000000000000-NOT-A-REAL-KEY" \
             "/download/9f8e7d6c5b4a3210ffee9f8e7d6c5b4a" \
             "/download/report_20240101_88888.pdf" \
             "/v1/chat/completions"; do
      curl -s "http://127.0.0.1:8484$p" >/dev/null; done'
Expected visible result: the Endpoints table shows EXACTLY the templates in
  OD §6 (e.g. /v1/users/:id/orders/:id, /v1/files/:uuid,
  /users/:email/profile, /v1/keys/:token, /download/:hash, /download/:file)
  and keeps /v1/chat/completions verbatim; no raw identifier visible
Expected persisted result: `observe api 127.0.0.1` prints the same templates
Expected audit/alert result: —
Expected security behavior: no output contains a ≥5-digit run, a UUID, an
  "@", or a long hex blob (the sanitizer property guarantees)
Cleanup: —
Screenshot checkpoint: the Endpoints table
Pass/fail: ☐
```

### Inventory, metrics, alerts

#### OBS-13 — unknown APIs still get metrics and inventory

```text
Mode: Manual UI + CLI
Requirement: hosts with no provider integration are first-class: inventory
  row, volumes, error rate, latency, and a new-API notification
Starting state: OBS-12 traffic exists (127.0.0.1:8484 maps to no provider)
Prerequisites: —
Exact navigation: API activity → Overview; Alerts → Run checks now
Exact buttons to click: Run checks now (on the Alerts screen)
Exact fields to fill: —
Exact test values: tethra observe apis ; tethra observe overview
Expected visible result: the 127.0.0.1 service row shows request volume,
  error rate, and latency (percentiles labeled approximate) even though it is
  an unknown/unmapped host; `observe apis` lists it with first/last seen;
  after Run checks now, an informational runtime_new_api /
  runtime_unknown_api alert names the newly observed host
Expected persisted result: the inventory row survives relaunch
  (observed_api_services / observed_endpoints are permanent inventory)
Expected audit/alert result: the alert above, informational severity
Expected security behavior: locally observed numbers are never merged with
  provider-reported usage (the Usage screen's provider-reported totals are
  unchanged by any of this traffic)
Cleanup: acknowledge/resolve the informational alert
Screenshot checkpoint: Overview with metrics for the unknown host
Pass/fail: ☐
```

#### OBS-14 — runtime alerts show cause and recommended action

```text
Mode: Manual UI + CLI
Requirement: runtime_* alerts are explainable — severity, evidence (what was
  observed), and a recommended action; delivered through the existing alert
  engine with dedup
Starting state: servers running; allowlist in place
Prerequisites: OD §4 deterministic status paths
Exact navigation: Alerts → Run checks now
Exact buttons to click: Run checks now; acknowledge; resolve
Exact fields to fill: —
Exact test values: force deterministic failures, then check:
  tethra run --project obs-app --observe=metadata -- sh -c \
    'for i in 1 2 3 4 5 6 7 8 9 10; do
       curl -s http://127.0.0.1:8484/v1/protected >/dev/null; done'
  tethra run --project obs-app --observe=metadata -- sh -c \
    'for i in 1 2 3 4 5 6 7 8 9 10; do
       curl -s http://127.0.0.1:8484/v1/broken >/dev/null; done'
  tethra alerts list
Expected visible result: after Run checks now, the Alerts screen shows a
  high-severity runtime_auth_failures alert and a high-severity
  runtime_server_errors alert for the 127.0.0.1 service; each card carries a
  severity badge, a title naming the service, an "Evidence: …" line with the
  observed counts/window, and a "Recommended: …" action; running checks again
  without new traffic raises no duplicate (dedup, one open alert per
  condition)
Expected persisted result: `tethra alerts list` shows the same kinds;
  acknowledge/resolve lifecycle behaves as in the base plan (ALR-02)
Expected audit/alert result: this IS the alert check
Expected security behavior: alert text contains templated paths and counts
  only — never a canary, header value, or credential
Cleanup: resolve both alerts
Screenshot checkpoint: a runtime alert card with Evidence + Recommended
Pass/fail: ☐
```

#### OBS-15 — upstream verification is never weakened (self-signed refused)

```text
Mode: Manual UI + CLI
Requirement: in metadata mode the proxy fully verifies the UPSTREAM server
  against the public root store; a self-signed server fails closed and is
  reported honestly, never downgraded to success
Starting state: OBS-02 (:8445 running); allowlist covers 127.0.0.1:8445
Prerequisites: OD §7
Exact navigation: API activity → Sessions → the failing session
Exact buttons to click: —
Exact fields to fill: —
Exact test values:
  tethra run --project obs-app --observe=metadata -- \
    curl -s --cacert ~/at-obs-test/tls/server-cert.pem \
    https://127.0.0.1:8445/v1/ping ; echo "curl exit: $?"
Expected visible result: the request FAILS (curl exits non-zero — the proxy
  could not verify the self-signed upstream and surfaced the error to the
  client); the session's event shows a transport/TLS failure classification
  (upstream certificate invalid), NOT a 200 and NOT a success outcome
Expected persisted result: `observe show <session>` records the tls_error /
  upstream_cert_invalid classification
Expected audit/alert result: repeated occurrences feed runtime_tls_failures
Expected security behavior: no setting, flag, or prompt anywhere offers to
  "accept invalid certificates" or disable verification — if you find one,
  FAIL the plan; a transport failure is never counted as an HTTP error rate,
  and a TCP success is never shown as a request success
Cleanup: —
Screenshot checkpoint: the honest failure classification in the session
Pass/fail: ☐
```

### Lifecycle and teardown

#### OBS-16 — locking the vault STOPS an already-running observed run

> NOTE: observed runs are CLI-only (the desktop app does not launch them), so a
> manual lock is exercised with `tethra lock` in a second terminal. The
> run must inherit the lock behavior of the session it was started under, so
> start it under a session token (`tethra unlock` → export
> `API_TRACKER_SESSION`). `tethra lock` deletes the session file, which the
> run detects and tears itself down.

```text
Mode: Manual CLI
Requirement: a manual lock during an active observed run tears interception
  down (proxy stops, token invalidated, CA/leaf cache cleared, child
  terminated) and marks the session interrupted with reason vault_locked;
  decryption does not continue past the lock.
Starting state: vault unlocked via `tethra unlock`, API_TRACKER_SESSION
  exported; a local synthetic HTTPS server running
Prerequisites: two terminals sharing API_TRACKER_SESSION
Exact test values: in terminal 1 start a long observed loop:
  tethra run --project obs-app --observe=metadata -- sh -c \
    'while true; do curl -s --max-time 5 https://127.0.0.1:8443/v1/tick \
       >/dev/null; sleep 1; done'
  confirm metadata appears (`tethra observe sessions`), then in terminal 2:
  tethra lock
Expected visible result: within ~1 second of `tethra lock`, terminal 1
  prints "Monitored session <id> INTERRUPTED — the vault was locked: the
  observation proxy was shut down and the monitored process was terminated" and
  exits non-zero (125). The curl loop stops (its proxy is gone / it was killed).
Expected persisted result: `tethra observe show <id>` shows status
  "interrupted", reason "vault_locked"; events recorded before the lock remain;
  the session is NOT relabeled "completed".
Expected audit/alert result: —
Expected security behavior: after the lock, no new request is decrypted or
  recorded (compare `observe show` request count before vs after). Unlock and
  confirm the OLD run does not resume and a fresh `run --observe` works
  normally. (Auto-lock variant: instead of `tethra lock`, wait out the
  vault's auto-lock interval; the run interrupts with reason "auto_lock".)
Cleanup: unset API_TRACKER_SESSION; unlock as needed
Screenshot checkpoint: the interrupted session with reason vault_locked
Pass/fail: ☐
```

#### OBS-17 — ending a session / closing the app cleans up

```text
Mode: Manual UI + CLI
Requirement: session end removes every temporary artifact: trust bundle temp
  files deleted, listener closed, proxy token dead, nothing left running
Starting state: OBS-16 recovered (unlocked)
Prerequisites: lsof
Exact navigation: API activity → Sessions
Exact buttons to click: —
Exact fields to fill: —
Exact test values: during an observed run, from a second terminal capture the
  child's proxy address and the temp CA files:
    tethra run --project obs-app --observe=metadata -- sh -c \
      'echo "PROXY=$HTTPS_PROXY"; echo "CA=$NODE_EXTRA_CA_CERTS"; sleep 15'
  while it sleeps: ls -l the CA= path (mode 0600, contains only a PUBLIC
  certificate — "BEGIN CERTIFICATE", never "PRIVATE KEY");
  lsof -iTCP -sTCP:LISTEN | grep <proxy port>  → listener present.
  After the child exits (and again after quitting the desktop app mid-run in
  a second pass): repeat both checks, and:
    curl -s -x "$PROXY" http://127.0.0.1:8484/v1/late || echo "proxy gone"
Expected visible result: after exit, the temp CA file is DELETED, the
  listener port is gone from lsof, and the post-exit curl prints "proxy
  gone" (nothing to authenticate against — the token cannot be reused);
  quitting the app mid-run marks that session "interrupted", never completed
Expected persisted result: sessions recorded with honest final states;
  no stray temp files under the temp directory afterwards
Expected audit/alert result: —
Expected security behavior: the temp file never contains private key
  material; the parent shell environment was never modified (echo
  $HTTPS_PROXY in your own shell is still empty)
Cleanup: —
Screenshot checkpoint: —
Pass/fail: ☐
```

#### OBS-18 — removing the certificate works (system trust and local CA)

```text
Mode: Platform-specific (macOS), Manual UI + CLI
Requirement: Mode C is fully reversible from inside the product; the local
  CA can be rotated and removed (both reauthentication-gated)
Starting state: OBS-10 left system trust "installed"
Prerequisites: macOS `security` CLI
Exact navigation: API activity → Certificate
Exact buttons to click: Remove from system trust; then Rotate CA (dialog
  "Rotate the local CA" → Rotate); then Remove CA (dialog "Remove the local
  CA" → Remove)
Exact fields to fill: Master password (Rotate and Remove dialogs)
Exact test values: manual-master-passphrase-01; verification commands:
  security find-certificate -c "Tethra Local Observation CA"
  tethra observe cert status
Expected visible result: after Remove from system trust: notice "Removed
  from the system trust store (if present)."; find-certificate FAILS again;
  System trust row "absent". After Rotate CA: notice "CA rotated." and a NEW
  fingerprint (record the old one first and compare). After Remove CA: notice
  "CA removed."; the tab returns to "No local CA yet …"; a subsequent
  metadata run regenerates a fresh CA automatically
Expected persisted result: `observe cert status` matches each state
Expected audit/alert result: —
Expected security behavior: Rotate and Remove both require the master
  password; wrong-master-passphrase-00 is rejected in-dialog; the rotate
  dialog warns to remove/reinstall any system-trust copy of the OLD CA
Cleanup: —
Screenshot checkpoint: Certificate tab back to "No local CA yet"
Pass/fail: ☐
```

#### OBS-19 — delete observability data, then tear down

```text
Mode: Manual UI + CLI
Requirement: observability data is deletable at all three scopes without
  touching credentials; the workspace resets cleanly
Starting state: all previous cases done
Prerequisites: —
Exact navigation: API activity → Sessions (per-session delete via CLI);
  API activity → Settings
Exact buttons to click: Delete all observability data; in the dialog
  "Delete ALL observability data": Delete everything
Exact fields to fill: Master password
Exact test values: manual-master-passphrase-01; first delete one session:
  tethra observe delete-session <session-id> --yes
Expected visible result: the single session disappears from Sessions; after
  Delete everything: notice "All observability data deleted."; Overview and
  Sessions are empty; obs-app's credentials O1/O2 still exist untouched,
  values still masked and revealable
Expected persisted result: empty observation tables survive relaunch;
  credentials and projects intact
Expected audit/alert result: open runtime_* alerts no longer re-raise (their
  evidence is gone)
Expected security behavior: delete-all is reauthentication-gated; it never
  touches credentials, the vault, or the certificate state
Cleanup: Ctrl-C both servers; Part 1.3 (`rm -rf ~/at-obs-test`,
  rm -f /tmp/obs-canary-file.txt); confirm OBS-18 removed system trust
  BEFORE deleting the workspace
Screenshot checkpoint: —
Pass/fail: ☐
```

---

## Order checklist

OBS-01 → OBS-02 → OBS-03 → OBS-04 → OBS-05 → OBS-06 → OBS-07 → OBS-08 →
OBS-09 → OBS-10 → OBS-11 → OBS-12 → OBS-13 → OBS-14 → OBS-15 → OBS-16 →
OBS-17 → OBS-18 → OBS-19.

OBS-10 and OBS-18 are a pair: never finish a session with system trust still
installed. Everything else is safe to re-run in isolation after OBS-01/02.

## What this plan deliberately does not claim

Consistent with the compatibility matrix, this plan does not test — because
the product honestly does not provide — HTTP/2 decoding (clients downgrade to
HTTP/1.1 or are tunneled opaquely with a partial-coverage badge), HTTP/3/QUIC
visibility (UDP bypasses the proxy; detected and reported, never blocked),
observation of certificate-pinned clients beyond connection-level metadata,
runtimes that ignore trust variables (Go on macOS/Windows, JVM, .NET —
connection-only fallback or explicit Mode C), or browser traffic (out of
scope entirely).
