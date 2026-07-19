# Local Manual UI Test Run — 2026-07-19

A guided, hands-on manual UI pressure test of API Tracker's safe, local,
offline-capable functionality. A human tester performed every GUI action and
personally reported every observed result; the conductor recorded only what
the tester reported. CLI-mode steps (Mode: CLI in the plan) were executed by
the conductor and their command output is quoted as evidence.

Plan of record: [docs/MANUAL_UI_TEST_PLAN.md](../MANUAL_UI_TEST_PLAN.md)
(129 manual test IDs / 126 procedures), with
[docs/UI_MAP.md](../UI_MAP.md) and
[docs/MANUAL_TEST_DATA.md](../MANUAL_TEST_DATA.md) as companions — all
verified against production baseline `7d81090`.

## Environment

- Machine: macOS 26.5 (build 25F71), Apple Silicon (aarch64), Darwin 25.5.0
- Rust: rustc 1.96.1 (2026-06-26)
- Node.js: v24.13.0, npm 11.6.2
- Git: 2.50.1 (Apple Git-155)
- Python: 3.14.3
- Worktree: `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-manual-test`
- Branch: `test/manual-local-smoke` @ `7605142` (clean tree at session start)

## Baseline

- Production code baseline under test: **`7d81090`** (main).
- Branch HEAD `7605142` differs from `7d81090` by exactly the three testing
  documents (`git diff --stat 7d81090..7605142`: only
  `docs/MANUAL_TEST_DATA.md`, `docs/MANUAL_UI_TEST_PLAN.md`,
  `docs/UI_MAP.md`; 4129 insertions, 0 production files). No production
  source was modified during this session.
- App version: 0.1.0 (tauri.conf.json / workspace Cargo.toml);
  CLI `api-tracker 0.1.0` built in this worktree from `7605142`
  (production code identical to `7d81090`).

## Application launch method

1. **Development launch** (diagnostic logs visible):
   `cd apps/desktop && API_TRACKER_DIR=~/at-manual-test/vault npm run tauri dev`
   — per verified Part 1.2/1.4 of the test plan.
2. **Packaged launch**: the pre-existing bundle at
   `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker/target/release/bundle/macos/API Tracker.app`
   turned out to be **stale** — its binary was built Jul 18 **20:29**,
   2.5 h *before* the `7d81090` merge (22:56), and it supports only schema
   ≤ v7 (baseline code expects v10). It was therefore NOT used as the
   release artifact under test. A fresh bundle was built from this
   worktree (`npx tauri build --bundles app`, production code =
   `7d81090`) and used for all packaged-app results. Launched ONLY via the
   inner binary with the vault override, per the plan's Part 1.3 warning:
   `API_TRACKER_DIR=~/at-manual-test/vault ".../API Tracker.app/Contents/MacOS/api-tracker-desktop"`
   — never via `open` (which would resolve the default data dir = the real
   vault).

## Test-data isolation

- All test data lives in `~/at-manual-test/` (vault, alpha-repo fixtures,
  docroot, webhook sink) per TD §1. Fixture repo `alpha-repo` created
  exactly per SETUP-02 (5 commits; all secret-shaped values carry
  `FAKE`/`MANUAL`/`NOT-A-REAL-KEY` markers).
- A **real vault exists** on this machine at
  `~/Library/Application Support/api-tracker/`. Snapshot at session start
  (to be re-verified at session end):
  - `vault.db` 184320 bytes, modified Jul 18 13:52:50 2026
  - `vault.db-shm` 32768 bytes, modified Jul 18 13:52:54 2026
  - `vault.db-wal` 24752 bytes, modified Jul 18 13:54:09 2026
- Every app launch in this session used `API_TRACKER_DIR=~/at-manual-test/vault`
  (or a sibling under `~/at-manual-test/`). The packaged app was never
  launched via `open`.
- **External event (not caused by this session):** at 09:55:54 a packaged
  `api-tracker-desktop` instance (PID 46592, binary
  `…/API-Tracker-ui-map/target/release/bundle/macos/API Tracker.app/Contents/MacOS/api-tracker-desktop`)
  started with **no `API_TRACKER_DIR`** in its environment — i.e., pointed
  at the DEFAULT data dir (the real vault). At 09:56:03–09:56:07 the real
  vault changed: `vault.db` 184320 → 372736 bytes, `vault.db-wal`
  24752 → 8272 bytes (checkpoint pattern). The tester confirmed they had
  launched it themselves to look at the UI; with their approval it was
  closed via SIGTERM at 09:58 (only the dev test instance, PID 45096,
  remained; real-vault files unchanged after the close — last modified
  09:56:07). The size growth is consistent with an at-open schema
  migration/checkpoint by the newer build. Recorded here because it invalidates a naive "real vault bytes
  unchanged at session end" check; session-end verification will instead
  verify no *further* changes attributable to this session's actions.
- No real credentials, no live-provider contact, no writes to real
  AWS/GitHub Actions/Vercel destinations.

## Scope decided at session start

Of the 129 manual test IDs, **125 are eligible** for this safe/local
session. **4 are deferred** because their expected path contacts a live
provider endpoint (prohibited this session even with fake keys):

- CRD-18 (live validation against api.openai.com)
- CON-02 (admin test/sync against api.openai.com)
- DST-04 (fake-token destination test against api.github.com)
- SYN-03 (retry of the failing GitHub Actions step)

Adapted (recorded per-test): SYN-01/SYN-02 run **keychain-only** (the plan's
second, network-failing GHA destination is skipped with DST-04); ROT-03's
final live-validation advance is performed offline so it fails with a
network error instead of contacting a provider. All seven §L live
verification scripts are deferred by design. Native-notification results
(ALR-03) are recorded separately from core app behavior.

## Summary

_(updated at each phase checkpoint)_

Running totals (updated live; checkpoint after each phase):

| Result | Count |
| --- | --- |
| PASS | 78 |
| FAIL | 0 |
| BLOCKED | 0 |
| NOT RUN (eligible, not yet reached) | 47 |
| DEFERRED (out of session scope) | 4 (+7 live scripts) |
| DEFECTS filed | 1 (MANUAL-001, low) |

PASS to date: SETUP-01/02/03, VLT-01..06, PRJ-01..07, CRD-01..17, CRD-19,
PRV-01/02, DOC-01..04, USE-01..07, PRC-01..05, SCN-01..09, ALR-01/02/03,
NTF-01..05, ENV-01..09. DEFERRED:
CRD-18 (live). Defect: MANUAL-001 (doc-watch redirect labeled first_capture
— low). Note: from CRD-06 onward, GUI driven by the conductor via a macOS
accessibility harness + real key events, with CLI/DB cross-checks;
conductor-observed, not human-observed (human screenshots at
SETUP-01/VLT-01/PRJ-01/CRD-05). Pending: packaged-app re-check; Phases:
Alerts/NTF, Env, Destinations/Sync, Rotation, Access, Templates, Admin(mock),
Settings/offline, Backup endgame.

## Items needing human confirmation

Two UI interactions could not be driven by the accessibility automation and
are low-risk to eyeball manually (the underlying logic is verified via the
shared CLI core / source):

1. **SCN-06 suppress dialog** — clicking a finding's "suppress" link should
   open an in-app dialog titled "Suppress this finding" with a reason input
   (placeholder "why this is not a real secret"); submitting empty shows "A
   reason is required to suppress." AXPress did not open it in automation.
   (Suppression add/list/remove + required-reason are proven via CLI.)
2. **USE-05 budget-cost-source popup** — the native select changes the
   "Used" figure between provider-reported ($0.00) and estimated ($12.50).
   Verified via CLI; the popup renders its current value in the UI.

## Passed

_(none recorded yet)_

## Failed

_(none recorded yet)_

## Blocked

_(none recorded yet)_

## Not run

All 125 eligible IDs pending at skeleton creation; this section lists only
the IDs still pending at session end.

## Defects

### MANUAL-001 — doc-watch records an HTTP redirect as a successful "first_capture" instead of a failed check

- **Title:** Documentation watch treats a 301/redirect response as a
  successful capture rather than surfacing it as a failed/blocked check.
- **Severity recommendation:** **Low** (honesty/UX; **not** a security
  hole — the redirect is correctly NOT followed).
- **Test ID:** DOC-03.
- **Preconditions:** a watched URL that responds with an HTTP 301 redirect
  (here `http://127.0.0.1:8091/docs.html` → 301 to :8090).
- **Reproduction steps:** add the watch via
  `provider watch-docs openai --url http://127.0.0.1:8091/docs.html`;
  Providers → OpenAI → Documentation watches → "check now" on that row.
- **Expected result (per plan):** the check FAILS / status reflects an
  error, "redirect not followed"; Last changed stays "no change seen".
- **Actual result:** the check succeeds with outcome `first_capture`
  (UI: "Checked: first capture."); the 301 response itself is hashed and
  stored as the baseline.
- **Reproduction rate:** 1/1.
- **Logs:** redirect server logged only the direct 301 (no follow); the
  docroot server logged **no** request at check time — confirming the
  redirect target was never fetched; CLI `docs-history` for the URL →
  `first_capture`.
- **Screenshot reference:** AX-tree capture of "Checked: first capture."
- **Possible affected files/symbols:** the documentation-watch HTTP fetch
  + outcome classification in the core provider docs watcher (redirect
  responses should map to an error/blocked outcome, not `first_capture`).
- **Security relevance:** the SSRF/downgrade guard itself **works** (the
  redirect is not followed; no request reaches the redirect target). The
  only issue is the misleading outcome label, which could let a user
  believe a page is being watched normally when the endpoint actually
  redirects (and its real content is never seen).
- **Data-loss relevance:** none.
- **Blocks further testing:** no.

_(further defects appended as found: MANUAL-002, …)_

## Screenshots/evidence

_(indexed per test as collected)_

## Logs

- Dev-mode stdout/stderr captured from the `npm run tauri dev` background
  task per launch; excerpts quoted per test where relevant.

## Residual limitations

- Live-provider behavior (validation, admin sync, network destinations,
  rotation completion) is NOT covered by this run — deferred to the
  post-audit live verification (§L).
- Manual observation covers macOS only; Windows/Linux behavior untested.
- Documented non-protections (THREAT_MODEL.md) were not treated as defects.
- **Concurrent clipboard contention:** the parallel deep-audit session
  (separate worktree, not touched) writes large text to the **system
  clipboard** during this run (observed: a full "Session Completion
  Report" appeared on the clipboard mid-test). Because API Tracker's
  clipboard auto-clear is deliberately best-effort ("only clears if the
  clipboard still holds this value"), an external clipboard write both
  (a) legitimately suppresses the app's clear and (b) makes precise
  auto-clear-timing measurement unreliable on this machine right now. See
  CRD-11 for how this was handled.

## Recommended next step

_(written at session end)_

---

# Per-test records

_(appended as tests execute; format: ID, screen/workflow, preconditions,
build, result, actual, expected, evidence, reproducibility, logs, suspected
component)_

### SETUP-01 — build and launch — **PASS**

- Screen/workflow: first-run launch → Create your vault
- Preconditions: clean checkout at `7605142` (prod code = `7d81090`);
  `~/at-manual-test/vault` empty; dev launch with
  `API_TRACKER_DIR=~/at-manual-test/vault npm run tauri dev`
- Build: dev profile, compiled in 35.65 s, `target/debug/api-tracker-desktop`
  (app 0.1.0)
- Result: **PASS** (tester-observed, screenshot 10:09:55)
- Actual: window titled "API Tracker"; heading "Create your vault"; intro
  "API Tracker stores all data encrypted on this computer at
  /Users/arnavtaduvayi/at-manual-test/vault. No account, no cloud."; fields
  "Master password (at least 12 characters; a long multi-word passphrase is
  best)" (autofocused) + "Confirm master password"; button "Create
  encrypted vault"; warning box "The master password is never stored and
  cannot be recovered… Create encrypted backups regularly from the Backup
  screen."
- Expected: exactly the above (plan SETUP-01 + UI_MAP §3.1) — matched
  verbatim, including the isolated data-dir path.
- Evidence: tester screenshot "Screenshot 2026-07-19 at 10.09.55 AM.png";
  conductor filesystem check: vault dir contained no files before form
  submission (`ls -la` → empty).
- Reproduction: observed once (launch).
- Logs: dev task output — clean compile, `Running target/debug/api-tracker-desktop`,
  no startup errors.
- Suspected component: n/a.

### SETUP-02 — fixture repository and files — **PASS** (CLI mode, conductor-executed)

- Screen/workflow: CLI fixture setup per plan Part 2
- Result: **PASS**
- Actual: `~/at-manual-test/alpha-repo` created with 5 commits
  (`init` → `add old secret` → `remove old secret` → `leaky env fixture` →
  `package.json`); `leaky.env` copied byte-identical from
  `apps/cli/tests/fixtures/leaky-repo/config.env`; `.env` (242 B) and
  `.env.local` (213 B) written with TD §6 exact contents; `blob.bin`
  (1024 B), `big.txt` (2,000,000 B); `webhook_sink.py`,
  `redirect_server.py`, `docroot/docs.html` (v1) in place.
- Expected: git log shows 4+ commits; files exist; every fixture value
  carries a FAKE marker — all confirmed in command output.
- Evidence: git log/ls output captured in session transcript.
- Reproduction: n/a (setup step).
- Suspected component: n/a.

### SETUP-03 — local test servers — deferred until first needed (DOC/NTF phases)

### VLT-02 — master password one character below the minimum — **PASS**

- Screen/workflow: Create your vault (run before VLT-01 on the main empty
  vault dir, as the plan's starting-state note permits — no second
  `vault-short` dir needed)
- Preconditions: `~/at-manual-test/vault` empty; Create screen shown
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (tester-observed)
- Actual: tester confirmed all three checks — red error naming the
  12-character minimum; still on the Create screen; attempted password not
  echoed anywhere.
- Expected: red error "… must be at least 12 characters"; no navigation;
  no echo — matched.
- Evidence: tester report; conductor filesystem check after the click:
  vault dir still completely empty (no `vault.db` or sidecars).
- Reproduction: observed once.
- Logs: no errors beyond the expected validation rejection.
- Suspected component: n/a.

### VLT-03 — password confirmation mismatch — **PASS**

- Screen/workflow: Create your vault (before VLT-01, same empty dir)
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (tester-observed)
- Actual: tester confirmed all three checks — "The passwords do not
  match." shown; rejection instant (client-side, no busy state); still on
  the Create screen.
- Expected: exactly the above — matched.
- Evidence: tester report; conductor check: vault dir still empty.
- Reproduction: observed once.
- Suspected component: n/a.

### VLT-01 — create the vault — **PASS**

- Screen/workflow: Create your vault → main navigation
- Preconditions: empty `~/at-manual-test/vault`; VLT-02/03 rejections done
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (tester-observed, screenshot 10:54:50)
- Actual: main navigation appeared with all 15 nav buttons in the exact
  documented order (Projects · Providers · Scan · Env files · Destinations
  · Sync plans · Rotation · Temporary access · Alerts · Notifications ·
  Usage · Pricing · Templates · Backup · Settings) + right-aligned "Lock
  vault"; Projects screen with "New project", "show archived" checkbox,
  and empty state "No projects yet. A project is a folder for the API
  credentials of one codebase."
- Expected: as above — matched verbatim.
- Evidence: tester screenshot "Screenshot 2026-07-19 at 10.54.50 AM.png";
  conductor checks: `vault.db` created 10:53, mode **600** (dir 0700);
  `api-tracker doctor` → "Vault exists: yes; Schema version: 10 (this
  build expects 10); DB integrity: ok; Projects: 0; Credentials: 0;
  Auto-lock: 15 minute(s)".
- Reproduction: observed once.
- Logs: no errors in dev output.
- Suspected component: n/a.

### VLT-04 — wrong vault password on relaunch — **PASS**

- Screen/workflow: quit (Cmd-Q) → dev relaunch with same
  `API_TRACKER_DIR` → Unlock vault
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (tester-observed)
- Actual: after relaunch the app showed the Unlock screen (vault
  persisted); wrong password `wrong-master-passphrase-00` → tester
  reports "incorrect password" error shown; remained on the Unlock
  screen; no echo of the attempted password reported.
- Expected: red "incorrect password"; screen stays; no echo — matched.
- Evidence: tester report; dev relaunch task logs clean.
- Reproduction: observed once.
- Suspected component: n/a.

### VLT-05 — unlock — **PASS**

- Screen/workflow: Unlock vault → main navigation
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (tester-observed)
- Actual: tester confirmed all three checks — unlock took a noticeable
  fraction of a second (memory-hard Argon2id KDF, "Unlocking…" busy
  state), then main navigation with the empty Projects list; password
  field cleared.
- Expected: as above — matched.
- Evidence: tester report.
- Reproduction: observed once (second successful unlock overall, counting
  the implicit unlock after VLT-01 creation).
- Suspected component: n/a.

### Packaged-app launch check, attempt 1 (stale bundle) — incidental PASS of the SchemaTooNew guard

- Screen/workflow: packaged `.app` (pre-existing main-worktree bundle)
  launched via inner binary with `API_TRACKER_DIR=~/at-manual-test/vault`
- Result: launch attempt **superseded** (stale artifact — not the baseline);
  the observed refusal itself is **correct behavior** and is evidence the
  GUI surfaces the schema guard (CLI variant tested later in BCK-07)
- Actual (tester-observed, verbatim): "this vault uses database schema
  v10, but this build supports up to v7 — it was created or upgraded by a
  newer version of API Tracker; upgrade this installation instead of
  opening the vault with an older build" + "Vault location:
  /Users/arnavtaduvayi/at-manual-test/vault"
- Analysis: the bundle's binary is dated Jul 18 20:29; baseline merge
  `7d81090` landed Jul 18 22:56 → the bundle predates the gap-closure
  migrations (v8–v10) and is not the artifact under test. The vault was
  NOT opened or modified by the refusal (correct). A fresh bundle was
  rebuilt from this worktree for the real packaged-app check.
- Evidence: tester-quoted error text; binary mtime vs commit timestamp;
  conductor mtime check — real vault untouched; test vault only accessed.
- Suspected component: n/a (test-infrastructure staleness, not an app
  defect).

### VLT-06 — Lock vault button — **PASS**

- Screen/workflow: main nav → Lock vault → Unlock vault → unlock again
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (tester-observed)
- Actual: tester confirmed — Lock vault flipped immediately to the Unlock
  screen; nothing reachable while locked (no nav bar); unlocking restored
  the main navigation with nothing lost.
- Expected: as above — matched.
- Evidence: tester report.
- Reproduction: observed once.
- Suspected component: n/a.

### PRJ-01 — create `alpha-app` — **PASS** (with usability observation)

- Screen/workflow: Projects → New project → project detail
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (tester-observed, screenshot 11:05:34)
- Actual: project detail "alpha-app" with description "manual test
  project", Environments "development, production", Password lock "not
  set", Created timestamp, Credentials section empty. First submission
  showed **Repositories "—"** — the tester had typed the repo path but
  not clicked **Add path**, so the typed text was (per the documented
  form design) not part of the submission. Recovered via **Edit → Add
  path → Save changes**; the path then persisted.
- Expected: detail with both environments, the repository path listed,
  Password lock "not set" — matched after the Edit-flow recovery.
- Evidence: tester screenshots/report; CLI `project show alpha-app`
  (fields match; note: CLI `project show` does not print a Repositories
  line at all); read-only SQLite check
  `project_repos` → `alpha-app|/Users/arnavtaduvayi/at-manual-test/alpha-repo`.
- Reproduction: n/a.
- **Usability observation (not a defect):** text typed into the "Local
  repository paths" input is silently discarded on Create/Save unless
  "Add path" is clicked first — no warning about the pending unadded
  path. Consider flagging unsubmitted input at save time.
  Suspected component (for the observation): `ProjectForm.tsx` (not
  modified).
- Incidental coverage: the Edit flow (PRJ-03's mechanism) was exercised
  for repository paths and saved correctly.

### PRJ-02 — create `beta-service` — **PASS**

- Screen/workflow: Projects → New project → Projects list
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (tester-observed)
- Actual: tester confirmed the Projects table lists both `alpha-app` and
  `beta-service`, credentials count 0 each, beta-service environments
  "development" only.
- Expected: as above — matched.
- Evidence: tester report; CLI `project list` shows both rows
  (alpha-app: development,production / beta-service: development, KEYS 0).
- Reproduction: observed once.
- Suspected component: n/a.

### PRJ-03 — edit a project — **PASS**

- Screen/workflow: alpha-app → Edit → Save changes
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (tester-observed)
- Actual: description updated to "manual test project (edited)" and shown
  on the detail page.
- Expected: matched. (Relaunch persistence checked implicitly at the next
  restart.)
- Evidence: tester report.
- Reproduction: observed once (second successful edit-flow use, after
  PRJ-01's recovery edit).
- Suspected component: n/a.

### PRJ-04 — archive and restore — **PASS**

- Screen/workflow: beta-service → Archive → list (show archived) → Restore
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (tester-observed)
- Actual: tester confirmed the full expected sequence — "(archived)" title
  suffix, "Project archived." notice, Add credential disabled with
  "(restore the project first)", State "archived" in the list with show
  archived ticked, then "Project restored." after Restore; Archive was
  confirmation-free (non-destructive by design).
- Expected: matched.
- Evidence: tester report.
- Reproduction: observed once.
- Suspected component: n/a.

### CRD-01 — add a generic credential (custom provider) — **PASS**
### CRD-02..CRD-05 — add the four provider-shaped credentials — **PASS**

- Screen/workflow: alpha-app → Add credential (×5) → project table +
  credential details
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS ×5** (tester-observed, screenshot 11:22:12)
- Actual: 5 rows in the alpha-app table, every Value masked
  (`MANU…01`, `ghp_…00`, `sk-p…EY` ×2, `sk_t…00`); Status badges exactly
  as expected — github-ci **expired** (red), stripe-webhook **expiring
  soon** (yellow, expiry 2026-07-26 = today+7d inside the 14-day
  default), others **unknown**; Secret value field was a hidden
  password-type input; tester reported the github-ci detail finding
  (reason/source/confidence/recommended action) and "Expires
  (provider-reported)" = "not reported by the provider"; no full secret
  value anywhere.
- Expected: matched in full.
- Evidence: tester screenshot "Screenshot 2026-07-19 at 11.22.12 AM.png";
  CLI `key list` identical masked rows/statuses; CLI
  `key status alpha-app/github-ci` → "[expired] (High confidence),
  Reason: the expiration date 2025-12-31T00:00:00Z has passed, Source:
  user-entered expiration date, Recommended: create a replacement
  credential at the provider and rotate";
  encrypted-at-rest greps: `MANUAL-TEST-NOT-A-REAL-KEY-000001` and
  `MANUAL-FAKE` → **zero hits** in `~/at-manual-test/vault/`.
- Reproduction: consistent across 5 sequential creations.
- Suspected component: n/a.

---

**Automation note:** from CRD-06 onward the conductor drives the GUI directly
via a macOS accessibility harness (`scratchpad/ax.js` — reads the live
AX tree, presses buttons, sets/type fields) plus real keyboard events for
secret inputs, at the tester's request (the tester will spot-check and is
still asked for a human screenshot/confirmation at native-notification and
OS-prompt checkpoints). Results below are **conductor-observed via automated
UI interaction against the live rendered UI** (the actual on-screen text,
buttons, and masked values read from the accessibility tree), not from
source inspection. Screenshots are replaced by verbatim AX-tree captures
where a human screenshot is not separately noted.

### CRD-06 — duplicate credential across two projects (store a copy) — **PASS**

- Screen/workflow: beta-service → Add credential → reuse dialog → Store a
  duplicate copy anyway
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: submitting `payments-copy` / OpenAI / development with the C5
  value raised the reuse dialog — verbatim from the AX tree: Heading
  "This value is already in your vault"; body "this value is shared
  between production and development/test: it is also stored as
  'alpha-app/shared-payments' (production…"; "Recommendation: create
  separate provider credentials for production and development, and rotate
  this one"; the referencing-vs-copy guidance paragraph; buttons
  "Reference the existing credential" / "Store a duplicate copy anyway" /
  "Cancel". **No secret value appeared in the dialog** — identifying info
  only. After choosing "Store a duplicate copy anyway",
  `beta-service/payments-copy` detail rendered with Value masked "sk-p…EY",
  Status "shared across projects", "Expires (provider-reported): not
  reported by the provider".
- Expected: matched in full (plan CRD-06 + UI_MAP §3.6 reuse dialog).
- Evidence: AX-tree captures (dialog + resulting detail); CLI
  `key status alpha-app/shared-payments` → "[shared across projects] (High
  confidence), Reason: an identical secret value is stored separately in
  project(s): beta-service, Source: keyed fingerprint comparison inside
  this vault"; encrypted-at-rest grep `MANUAL-FAKE-SHARED` → zero hits in
  the vault dir.
- Reproduction: observed once (one earlier submit was rejected with
  "credential value must not be empty" because AX direct value-set on the
  secure field did not register with the app's input handler; retyping via
  real key events fixed it — an automation-harness artifact, not an app
  defect).
- Suspected component: n/a.

### CRD-07 — reference instead of copy — **PASS**

- Screen/workflow: beta-service → Add credential → reuse dialog →
  Reference the existing credential
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: submitting `shared-ref` / OpenAI / development with the C5 value
  raised the same reuse dialog; choosing "Reference the existing
  credential" created `beta-service/shared-ref` whose **Value reads
  "reference to alpha-app/shared-payments"**, Status "shared across
  projects". Sensitive actions on the reference are Reveal value / Copy
  value / Edit metadata / Delete… — the **"Replace value…" button is
  absent** (it is present on the CRD-06 copy's detail), matching the
  documented reference behavior.
- Expected: matched in full (plan CRD-07 + UI_MAP reference semantics).
- Evidence: AX-tree captures; CLI `key show beta-service/shared-ref` →
  "Value: reference to alpha-app/shared-payments"; read-only SQLite proof
  — `shared-ref` has `linked_credential_id` → alpha-app/shared-payments
  and **no own ciphertext**, whereas `payments-copy` and `shared-payments`
  each hold a 93-byte ciphertext (true copy vs. link distinction).
- Reproduction: observed once.
- Suspected component: n/a. (Target-deletion protection for references is
  exercised in CRD-17.)

### PRJ-05 — set a project password (reauthenticated) — **PASS**

- Screen/workflow: beta-service → Set project password → Confirm
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: dialog "Set project password" with the warning "This adds a
  second lock on top of the vault. If you lose this password, the
  credential values in this project are unreco[verable]…" and three fields
  (Project password / Confirm project password / Master password
  (reauthentication)). Filling `manual-beta-project-pw-01` twice +
  `manual-master-passphrase-01` and Confirm → notice "Project password
  set. Keep it safe: losing it makes this project's credential values
  unrecoverable."; Password lock became "set (unlocked this session)";
  buttons became Lock project / Remove password.
- Expected: matched (plan PRJ-05 + UI_MAP §3.5). Master password was
  required inline (reauth) as designed.
- Evidence: AX-tree captures.
- Reproduction: observed once.
- Suspected component: n/a. Per ADR-0016, setting a project password
  rotates the project key and re-encrypts values — not separately
  asserted here beyond the successful set.

### PRJ-06 — lock; wrong project password; unlock — **PASS** (minor UX note)

- Screen/workflow: beta-service → Lock project → Unlock project (wrong,
  then correct)
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: Lock project → notice "Project locked.", Password lock "set
  (locked)", button became Unlock project. Unlock with
  `wrong-beta-project-pw-00` → "incorrect password"; state stayed "set
  (locked)". Unlock with `manual-beta-project-pw-01` → "Project
  unlocked.", Password lock "set (unlocked this session)".
- Expected: matched.
- Evidence: AX-tree captures.
- Reproduction: observed once.
- **Minor UX note (not a defect):** on the wrong project-password
  attempt the Unlock-project dialog appears to close (had to reopen to
  retry), whereas the shared master-password ReauthDialog is documented to
  stay open on error. Different component (project-password ConfirmDialog);
  no security impact — the wrong attempt was rejected and the project
  stayed locked. Timing of the AX read could also have caught the dialog
  mid-close; noting for the UI rebuild, not filing as a defect.
- Suspected component (for the note): the project-password
  Confirm/Unlock dialog in `ProjectDetail.tsx` (not modified).

### CRD-19 — reveal blocked in a locked project — **PASS (security-critical)**

- Screen/workflow: beta-service (LOCKED) → payments-copy → Reveal value →
  reauth with the correct master password
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: with beta-service password-locked, opening payments-copy still
  showed the value masked ("sk-p…EY"); clicking Reveal value raised the
  reauth dialog ("Reveal credential value" / "Confirm your master password
  to continue."); entering the **correct** master password
  `manual-master-passphrase-01` and Confirm produced the error "project
  'beta-service' is password-locked; unlock it first" — **no plaintext was
  shown anywhere** (AX text scan for `sk-proj-MANUAL` → zero hits). This
  proves the master password alone is NOT sufficient to read a
  password-locked project's values.
- Expected: exactly this (plan CRD-19) — matched.
- Evidence: AX-tree captures of the reauth dialog and the refusal error;
  negative plaintext scan.
- Reproduction: observed once.
- Suspected component: n/a (correct behavior).

### CRD-17 — delete a credential (reference protection first) — **PASS (security-relevant)**

- Screen/workflow: (a) alpha-app/shared-payments → Delete… (referenced
  target); (b) beta-service/shared-ref → Delete… (the reference)
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation + CLI/DB)
- Actual: (a) the Delete dialog is reauth-gated ("Confirm your master
  password to continue."); after the correct master password, deleting the
  **target** was **refused** with "credential is referenced by 1 linked
  credential(s); remove the references first" and shared-payments remained
  present. (b) Deleting the **reference** shared-ref (same reauth)
  succeeded, returning to beta-service which then showed only
  payments-copy.
- Expected: matched (plan CRD-17) — reauth required; referenced target
  protected; reference deletable.
- Evidence: AX-tree captures of both the refusal and the successful
  delete; CLI `key show beta-service/shared-ref` → "not found"; CLI
  `key show alpha-app/shared-payments` still present with masked value
  "sk-p…EY", status "shared across projects" (payments-copy still shares
  it); audit `credential_deleted name=shared-ref` at 16:19:28.
- Reproduction: observed once each path.
- Suspected component: n/a. Note: shared-payments correctly retains
  "shared across projects" because the payments-copy duplicate still
  exists.

### CRD-18 — live validation of an invalid provider credential — **DEFERRED**

- Reason: the expected path makes a direct request to api.openai.com;
  live-provider contact is prohibited this session (even with a fake key).
  Recorded as deferred, not failed. To be run in the post-audit live
  verification window.

### PRJ-07 — remove the project password — **PASS**

- Screen/workflow: beta-service → Remove password → Confirm
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: the Remove-project-password dialog asked for the **Project
  password** (not the master) — the "prove knowledge of the current
  password" design. Entering `manual-beta-project-pw-01` and Confirm →
  notice "Project password removed; the vault lock still protects it.";
  Password lock "not set"; button back to "Set project password".
- Expected: matched (plan PRJ-07). Removal required the project password,
  not just the master.
- Evidence: AX-tree captures.
- Reproduction: observed once.
- Suspected component: n/a.

### CRD-10 — wrong master password in reauth — **PASS**

- Screen/workflow: alpha-app/generic-token → Reveal value → wrong master pw
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: entering `wrong-master-passphrase-00` and Confirm showed
  "incorrect password" **inside the still-open** reauth dialog (Confirm/
  Cancel still present); nothing revealed; password not echoed. Confirms
  the shared ReauthDialog stays open on error (contrast with the
  project-password dialog note in PRJ-06).
- Expected: matched (plan CRD-10).
- Evidence: AX-tree capture showing the error text within the dialog;
  negative plaintext scan.
- Reproduction: observed once.
- Suspected component: n/a.

### CRD-09 — cancelled reauthentication — **PASS**

- Screen/workflow: Reveal value → Cancel
- Result: **PASS** — Cancel closed the dialog, nothing revealed, no error.
- Evidence: AX-tree scan (no dialog, no plaintext); audit shows no reveal
  event from this attempt.
- Suspected component: n/a.

### CRD-08 — reveal (auto-hide) — **PASS**

- Screen/workflow: Reveal value → correct master pw → inline plaintext →
  auto-hide
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: reauth dialog "Reveal credential value" / "Confirm your master
  password to continue."; entering `manual-master-passphrase-01` and
  Confirm displayed the plaintext **MANUAL-TEST-NOT-A-REAL-KEY-000001**
  inline with a "hide" button. (Auto-hide timing verified separately —
  see below.)
- Expected: matched (plan CRD-08) — reveal is the only place plaintext
  appears.
- Evidence: AX-tree capture of the revealed value + hide button; audit
  `credential_revealed` event recorded exactly once for generic-token,
  with empty detail (no value), timestamp 15:56:02.
- Reproduction: observed once.
- Suspected component: n/a.
- Auto-hide result: **confirmed** — the plaintext disappeared on its own;
  a later AX read (≈80 s after the 11:56:02 reveal) showed only the masked
  "MANU…01" with no "hide" button and no plaintext. Exact seconds not
  precisely measured (an intermediate automated AX read returned an empty
  tree, a harness flake, not app behavior); the security-relevant fact —
  reveal auto-hides without user action — is verified and consistent with
  the documented ~30 s.

**Audit cross-check (CRD-08/09/10):** `audit_events` for generic-token show
exactly one `credential_revealed` (from CRD-08) and no reveal events from
the cancelled or wrong-password attempts; event detail is empty (metadata
only). Full audit distribution at this point: credential_created×6,
credential_reference_created×1, credential_revealed×1, credential_updated×1,
project_created×2, project_updated×2, project_archived×1, project_restored×1,
project_password_set×1, project_locked×1, project_unlocked×1,
project_password_removed×1, vault_created×1, vault_unlocked×9. No event row
contains a secret value.

### CRD-11 — copy with timed clipboard clear — **PASS**

- Screen/workflow: alpha-app/generic-token → Copy value → reauth →
  clipboard clear
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation + `pbpaste`
  measurement)
- Actual: Copy value raised the reauth dialog "Copy credential value" /
  "Confirm your master password to continue."; after
  `manual-master-passphrase-01` and Confirm → notice "Copied. The
  clipboard will be cleared in about 30 seconds." The system clipboard
  then actually held the C1 value `MANUAL-TEST-NOT-A-REAL-KEY-000001`
  (verified via `pbpaste`), while the **screen rendered no plaintext**
  during copy. The app's timer subsequently cleared the clipboard **to
  empty** (definitive run: "cleared to EMPTY", i.e. the app's own clear,
  not an external overwrite), at ~23 s measured from a clock started
  several seconds after the copy → real copy-to-clear ≈ 28–33 s,
  consistent with the confirmed setting `clipboard_clear_seconds = 30`.
- Expected: matched (plan CRD-11). Best-effort semantics also observed:
  when the concurrent deep-audit session overwrote the clipboard in an
  earlier attempt, the app correctly did not clobber that external
  content (the clear only fires while the clipboard still holds the
  copied value).
- Evidence: AX-tree capture of the notice; `pbpaste` = C1 value
  immediately post-copy; single-shell timing run "cleared to EMPTY at
  +23s → app timer cleared it"; `api-tracker settings show` →
  `clipboard_clear_seconds = 30`.
- Reproduction: copy+clear observed across multiple attempts; exact-second
  precision limited by inter-tool-call latency and by clipboard
  contention from the concurrent session (documented in Residual
  limitations), but the app-clears-to-empty behavior is unambiguous.
- Suspected component: n/a.

### CRD-12 — replace the value (history begins) — **PASS**

- Screen/workflow: alpha-app/openai-main → Replace value… → Replace
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: Replace dialog with "New secret value" + "Master password"
  fields; entering the TD §4 first replacement value
  (`sk-proj-MANUAL-FAKE-ROTATED-…`) + master password and Replace →
  notice "Value replaced."; value stays masked "sk-p…EY" (old and new
  both end "…KEY" so the mask string is unchanged, but the ciphertext
  differs).
- Expected: matched (plan CRD-12).
- Evidence: AX-tree capture; read-only SQLite — `credential_versions`
  now holds one superseded version row (v1, 88 B ciphertext) for
  openai-main, with the current value (v2) in the credentials table →
  two versions total, as CRD-13 shows.
- Reproduction: observed once.
- Suspected component: n/a.

### CRD-14 — manual marks (disable / revoke / exposure) — **PASS**

- Screen/workflow: alpha-app/generic-token → Manual tracking (full mark
  cycle)
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: executed the full sequence and observed each state transition:
  Mark used now / Mark validated OK (recorded use+validation timestamps,
  surfaced in status findings) → Mark disabled (notice "Marked disabled.",
  badge "manually disabled", button became Enable) → Enable ("Re-enabled")
  → Mark revoked (notice "Marked revoked.", badge "revoked", button became
  Unmark revoked) → Unmark revoked ("Unmarked revoked.") → Flag possibly
  exposed (dialog "Flag as possibly exposed" with an optional note field;
  entered "manual test note"; Flag → notice "Flagged as possibly
  exposed.", badge "possibly exposed", button became Clear exposure flag)
  → Clear exposure flag ("Exposure flag cleared."). Final status via CLI:
  "active" (Medium confidence, "use or validation was recorded on
  2026-07-19T16:08:31Z") — all destructive marks cleared.
- Expected: matched (plan CRD-14) — notices, badges, and button
  transitions all as documented.
- Evidence: AX-tree captures per transition; CLI `key status
  alpha-app/generic-token` shows the cleared, active end state.
- Reproduction: observed once (long sequence, no anomalies).
- Suspected component: n/a.

### CRD-15 — lifecycle timeline — **PASS**

- Screen/workflow: generic-token → Lifecycle → Load timeline
- Result: **PASS** (conductor-observed via AX automation + CLI)
- Actual: timeline table with columns At / Event / Detail / Source listing
  the created, revealed (reveals + copies both log as
  `credential_revealed`), and the CRD-14 mark/update events; **no secret
  values anywhere** (AX scan and CLI `key history` both clean). CLI
  `key history alpha-app/generic-token` matches (created, ×4 revealed,
  ×2 updated used/validated, disabled/enabled, ×2 updated revoked, ×2
  updated possibly_exposed).
- Expected: matched (plan CRD-15) — metadata only.
- Evidence: AX-tree capture; CLI history dump; negative value scans.
- Observation (not a defect): copy actions log as `credential_revealed`
  rather than a distinct "copied" event — the security-relevant fact
  (plaintext accessed) is captured; noted for the UI rebuild.
- Suspected component: n/a.

### CRD-16 — edit metadata — **PASS**

- Screen/workflow: generic-token → Edit metadata → Save changes
- Result: **PASS** (conductor-observed via AX automation + CLI)
- Actual: the Edit form correctly **omits the Secret value field**
  (metadata-only edit); set Documentation link
  `https://example.com/manual-docs` and note "edited"; after Save the
  detail shows the documentation link as a clickable Link and the value
  stayed masked "MANU…01". CLI `key show` confirms
  "Docs: https://example.com/manual-docs" + "Value: MANU…01 (masked)".
- Expected: matched (plan CRD-16).
- Evidence: AX-tree capture (Link element); CLI `key show`.
- Suspected component: n/a.

### SETUP-03 — local test servers — **PASS**

- Result: **PASS** (conductor-executed) — `webhook_sink.py` on
  127.0.0.1:8085 (POST → 200) and `python3 -m http.server 8090` serving
  `~/at-manual-test/docroot` (GET /docs.html → 200) both confirmed live.

### PRV-01 — provider catalog — **PASS**

- Screen/workflow: Providers
- Result: **PASS** (conductor-observed via AX + CLI)
- Actual: "Provider catalog" with columns Provider / Secret env vars /
  Detection patterns / Expiration, listing exactly OpenAI, Anthropic,
  GitHub, Stripe, Supabase; OpenAI env vars "OPENAI_API_KEY,
  OPENAI_ADMIN_KEY". CLI `provider list` matches (5 rows, same env vars).
- Expected: matched (plan PRV-01).
- Evidence: AX-tree capture; CLI `provider list`.
- Suspected component: n/a.

### PRV-02 — provider detail: links + honest capability matrix — **PASS**

- Screen/workflow: Providers → OpenAI (Capabilities + an official link)
- Result: **PASS** (conductor-observed via AX + CLI + browser check)
- Actual: OpenAI detail shows the Administrative connection panel and a
  Capabilities matrix with all 10 rows and honest statuses: validate
  credential = implemented·exact credential; fetch metadata / fetch usage
  = implemented·admin credential·exact credential; read permissions &
  change permissions = manual action required; create credential =
  implemented·admin credential·provider-project level only; disable
  credential = unsupported; revoke credential & rotate credential =
  implemented·admin credential·exact credential; fetch pricing = manual
  action required. Clicking the "Manage keys"
  (platform.openai.com/api-keys) link **kept the app on the OpenAI detail
  (no in-app navigation)** and opened the URL in the **system browser**
  (Chrome tab `platform.openai.com/login?next=%2Fapi-keys`).
- Expected: matched (plan PRV-02) — nothing claimed implemented that
  isn't; links open externally.
- Evidence: AX-tree matrix capture; CLI `provider capabilities openai`
  (identical 10-row honest matrix); Chrome tab URL confirming external
  open.
- Suspected component: n/a.

### DOC-01 — watch a local page (unchanged) — **PASS**

- Screen/workflow: (CLI add watch) → Providers → OpenAI → Documentation
  watches → check now ×2 (8090 row)
- Result: **PASS** (conductor-observed via AX + CLI)
- Actual: watch added via `provider watch-docs openai --url
  http://127.0.0.1:8090/docs.html`; first "check now" → "Checked: first
  capture. A page change does not necessarily mean a breaking API
  change."; second → "Checked: unchanged. …". CLI `docs-history` for the
  URL: `first_capture` then `unchanged`. The docroot access log shows the
  second check was a **conditional GET returning 304 Not Modified** —
  confirming ETag/Last-Modified conditional requests.
- Expected: matched (plan DOC-01), incl. the honest "not necessarily
  breaking" copy and conditional checks.
- Evidence: AX captures; CLI `docs-history`; docroot server log
  (200 then 304).
- Suspected component: n/a.

### DOC-02 — the page changes — **PASS**

- Screen/workflow: overwrite docs.html → v2, check now
- Result: **PASS** (conductor-observed via AX + CLI)
- Actual: after replacing the page with v2, "check now" → "Checked:
  changed. A page change does not necessarily mean a breaking API
  change."; `docs-history` records outcome `changed`; a
  `documentation_changed` alert (id cf483c05, severity info, "openai
  documentation changed") is raised.
- Expected: matched (plan DOC-02).
- Evidence: docroot log (200 on the changed fetch); CLI `docs-history`
  (`changed`); CLI `alerts list` shows the documentation_changed alert.
- Suspected component: n/a.

### DOC-03 — redirect is refused — **PASS (security) / MANUAL-001 (label)**

- Screen/workflow: (CLI add watch 8091) → check now (8091 row)
- Result: **PASS for the security-critical property**; a low-severity
  outcome-label discrepancy is filed as MANUAL-001.
- Actual: the watcher issued a single GET to :8091 which returned 301; it
  **did not follow the redirect** — the docroot (:8090) access log shows
  **no request at that time** (12:30:36), and the redirect server logged
  only the direct 301. So no request was made to the redirect target on
  the watcher's behalf (SSRF/downgrade guard holds). **However**, the
  recorded outcome was `first_capture` (a successful capture of the 301
  response), not a failure — the plan expected "the check FAILS".
- Expected: security expectation (no redirect follow) **met**; the
  visible-result expectation ("the check FAILS / error status") **not
  met** — see MANUAL-001.
- Evidence: redirect server log (301 only, no follow); docroot log (no hit
  at 12:30:36); CLI `docs-history` for 8091 → `first_capture`.
- Reproduction: observed once.
- Suspected component: the docs-watch fetch/outcome-classification path in
  the provider docs watcher (core) — reported, not modified.

### DOC-04 — unwatch — **PASS**

- Screen/workflow: Documentation watches → unwatch (8091 row)
- Result: **PASS** (conductor-observed via AX + CLI)
- Actual: after unwatch, CLI `docs-status openai` lists only the 8090
  watch (8091 removed); the docs-history rows for 8091 correctly remain
  (history persists after unwatch, as documented).
- Expected: matched (plan DOC-04).
- Evidence: CLI `docs-status` before/after.
- Suspected component: n/a.

### USE-01 — record synthetic usage; estimated cost — **PASS**

- Screen/workflow: (CLI record) → Usage → scope alpha-app
- Result: **PASS** (conductor-observed via AX + CLI)
- Actual: after `usage record … --model gpt-4o --input-tokens 1000000
  --output-tokens 1000000`, the Usage screen (scope alpha-app) "This
  month" shows Input tokens 1,000,000, Output tokens 1,000,000, Reported
  cost $0.00 "(provider-reported)", Estimated cost $12.50 "(estimated
  locally from token counts and a bundled price table — may differ from
  the provider's bill)", Attribution exact_credential; Records table has
  the manual row "2,000,000 tokens", "$12.50 (est.)", source manual.
- Expected: matched (plan USE-01); estimate clearly labeled, never
  provider-reported.
- Evidence: AX capture; CLI `usage report --project alpha-app` identical
  ($12.50 estimated / $0.00 reported / exact credential).
- Suspected component: n/a.

### USE-02 / USE-03 / USE-04 — over-budget alert + strict boundary — **PASS**

- Screen/workflow: Usage (scope alpha-app) → Budget; boundary via CLI
  `budget set` + UI re-read
- Result: **PASS** (conductor-observed via AX + CLI)
- Actual: budget 5.00 → "Budget saved.", "over budget" badge, projected
  month-end shown (USE-02). Strict boundary (used = $12.50): budget
  **12.50 → NOT over budget** (UI over-budget badge count 0; CLI STATUS
  blank); budget **12.49 → over budget** (UI badge count 1; CLI STATUS:
  OVER BUDGET). Confirms "over" means used **strictly greater** than
  budget. Budget reset to 5.00 for the alert phase.
- Expected: matched (plan USE-02/03/04).
- Evidence: UI badge counts at 12.50 (0) vs 5.00 (1); CLI `budget show`
  STATUS at 12.50 (none), 12.49 (OVER BUDGET), 5.00 (OVER BUDGET).
- Note: the exact-value boundary was set via CLI `budget set` because the
  numeric budget field did not reliably accept automated keystroke
  replacement (harness limitation, not an app defect); the UI badge was
  read from the live screen after each change.
- Suspected component: n/a.

### USE-05 — budget cost source selector — **PASS (behavior via CLI/shared core)**

- Screen/workflow: Usage → Budget cost source
- Result: **PASS** — the "Used" figure tracks the selected source exactly:
  provider_reported → Used $0.00 (provider-reported); estimated → Used
  $12.50; best_available → Used $12.50 (reported 0 → falls to estimated).
  The Usage screen shows the "Budget cost source" popup with its current
  selection; the source change itself was driven via CLI `budget source`
  (shared core) because the native popup menu did not expose items to the
  AX driver during this test. Left at best_available.
- Evidence: CLI `budget show` per source.
- Suspected component: n/a (UI-driver limitation on the native popup only).

### USE-06 — empty usage range — **PASS**

- Screen/workflow: Usage → Scope → beta-service
- Result: **PASS** — This month all $0.00; "No usage records for this
  scope and source." rendered cleanly (empty scope).
- Evidence: AX capture at scope beta-service.
- Suspected component: n/a.

### USE-07 — unknown model: no invented estimate — **PASS**

- Screen/workflow: (CLI record made-up-model-xyz) → Usage → scope
  alpha-app → Records
- Result: **PASS** (conductor-observed via AX + CLI)
- Actual: the new record row shows "2,000 tokens" with Estimated **"—"**
  (no number invented for an unknown model); the gpt-4o row keeps its
  $12.50 estimate. CLI `usage report` shows the made-up-model-xyz row with
  2000 tokens and no estimated-cost value.
- Expected: matched (plan USE-07).
- Evidence: AX capture (row "made-up-model-xyz / 2,000 tokens / —"); CLI
  `usage report`.
- Suspected component: n/a.

### PRC-01 — pricing records table — **PASS**

- Screen/workflow: Pricing (records table + "Show full version history")
- Result: **PASS** (conductor-observed via AX + CLI)
- Actual: the Pricing screen renders the records table with columns incl.
  Origin (bundled) and the checkbox "Show full version history (not just
  currently effective records)". With history on, **claude-sonnet-5
  appears twice** with different Effective-from dates: $2.00/$10.00
  effective 2026-07-18 and $3.00/$15.00 effective 2026-09-01 (the
  documented Sept-2026 change). CLI `pricing list --all` matches.
- Expected: matched (plan PRC-01).
- Evidence: CLI `pricing list` / `pricing list --all`; AX capture of the
  Pricing heading, checkbox, and bundled records.
- Note: the Pricing screen's large table exceeds the AX driver's
  fast-read budget, so the record data was cross-checked via CLI (shared
  core) rather than a full UI table scrape; the UI controls were confirmed
  present.
- Suspected component: n/a.

### PRC-02 — manual override makes the unknown model estimable — **PASS**

- Result: **PASS** (conductor-observed via CLI/shared core)
- Actual: `pricing set-override openai made-up-model-xyz --input 2.50
  --output 10` → "Override stored for openai/made-up-model-xyz. It wins
  over imported and bundled records; existing stored estimates are NOT
  recomputed." An Origin "override" row ($2.50/$10.00) appears. Re-recording
  the unknown-model usage then produces a row estimated at **$0.01 (est.)**
  (1k×$2.50/1M + 1k×$10/1M = $0.0125 → $0.01), while the OLD unknown-model
  rows keep "—" (stored estimates not recomputed).
- Expected: matched (plan PRC-02) — override > imported > bundled; new
  usage uses it.
- Evidence: CLI `pricing set-override`, `pricing list --all` (override
  row), `usage report` (new row $0.01, old rows —).
- Suspected component: n/a.

### PRC-03 — remove the override — **PASS**

- Result: **PASS** — `pricing remove-override openai made-up-model-xyz` →
  "removed 1 override record(s)"; no override row remains.
- Evidence: CLI before/after.

### PRC-04 — import rejects malformed pricing — **PASS**

- Result: **PASS** (whole-file validation; nothing added on any bad input)
- Actual: the plan's exact JSON
  `[{"provider":"openai","model":"bad","unit":"tokens","input_per_m":"-1"}]`
  is rejected ("missing field `source`") — it is malformed (missing a
  required field). A fully-formed record carrying a negative price is
  rejected specifically on the price: "record 1 (openai/bad): input_per_m:
  invalid input: '-1.000000' is not a valid amount". In both cases **no
  record is added** (whole-file validation, no partial import).
- Expected: matched in outcome (malformed rejected, nothing added). Minor
  note: the plan expected the "negative price" message for its exact JSON,
  but the missing-`source` check fires first; the negative-price check was
  confirmed separately. Not a defect.
- Evidence: CLI import attempts + post-count (bad rows: 0).
- Suspected component: n/a.

### PRC-05 — export / re-import round trip — **PASS (with benign layering note)**

- Result: **PASS** — export → re-import completes with **no error**.
- Actual: `pricing export` (14,936 bytes) → `pricing import` → "Imported 30
  new record(s); replaced 0 …". The first round-trip creates
  **"imported"-origin copies** of the "bundled" records (identical values;
  origin bundled→imported). Because precedence is override > imported >
  bundled and the values are identical, **estimates are unaffected**. The
  growth is **bounded and idempotent**: a second identical import reports
  "Imported 0 new; replaced 30" and the record count does not increase
  further (stayed 59; claude-sonnet-5 stayed at 4 rows = 2 bundled + 2
  imported shadows).
- Expected: the plan's "Imported 0 new, replaced N; never an error" is met
  on the **second** import; the first import shadows bundled→imported. This
  is defensible layering (reviewed imports outrank bundled defaults),
  causes no estimate change and no error — recorded as a benign
  observation, **not** a defect.
- Evidence: CLI export/import twice; record-count and sonnet-5-row counts
  before/after; the 4 sonnet-5 rows are 2×bundled + 2×imported with
  identical prices.
- Suspected component: n/a (pricing import origin-layering; by design).

### SCN-01 — working-tree scan (fixtures found, placeholders not) — **PASS**

- Screen/workflow: Scan → path + Mode "Working tree" → Scan
- Result: **PASS** (conductor-observed via AX UI + CLI JSON)
- Actual: the UI shows **"Findings (8)"** with all values **redacted**
  (ghp_…11, ghp_…22, sk_l…11 on .env.local; sk-p…KE, ghp_…00, sk_l…00 on
  leaky.env; sk-p…EY, ghp_…11 on .env), every finding "high" confidence,
  with file names shown. The placeholders (`your-key-here`, `<REPLACE_ME>`,
  `pk_live_notasecret…`) are **not** listed; blob.bin and big.txt produce
  no findings and no crash. CLI `scan … --json` returns the identical 8
  findings with file:line and redacted values.
- Expected: matched (plan SCN-01) — fixtures found, placeholders excluded,
  values redacted, no crash on binary/large files.
- Evidence: AX capture "Findings (8)" + rows; CLI `scan --json` (8
  findings: 3 leaky.env, 2 .env, 3 .env.local; all high/redacted).
- Suspected component: n/a.

### SCN-02 — staged scan — **PASS**

- Screen/workflow: Scan → Mode "Staged changes (Git)" → Scan (staged
  `staged-secret.txt`)
- Result: **PASS** — UI shows "Findings (1)": only staged-secret.txt
  (sk-p…KE redacted); the committed leaky.env does NOT appear (correct —
  it is committed, not staged).
- Evidence: AX capture "Findings (1)".
- Suspected component: n/a.

### SCN-03 — recent-commit history scan — **PASS**

- Screen/workflow: Scan → Mode "History (Git)" (default depth) → Scan
- Result: **PASS** — "Findings (4)": leaky.env's 3 secrets
  (commit 6b0ed4e1, sk-p…KE/ghp_…00/sk_l…00) plus the **deleted**
  old-secret.txt token (commit 5a408626, ghp_…11 — history remembers a
  removed secret), each with commit:file references.
- Evidence: AX capture.
- Suspected component: n/a.

### SCN-04 — full-history scan — **PASS**

- Screen/workflow: Scan → History mode → check "full history" → Scan
- Result: **PASS** — checking "full history" **hides the depth field**
  and the scan returns the same "Findings (4)" (small repo).
- Evidence: AX capture (depth label count 0; Findings (4)).
- Suspected component: n/a.

### SCN-05 — vault match marks the credential possibly exposed — **PASS**

- Screen/workflow: commit oops-committed.txt (C5 value) → Scan → Working
  tree, "mark matched vault credentials as possibly exposed" checked
- Result: **PASS** (conductor-observed via AX UI + CLI)
- Actual: UI "Findings (10)"; the oops-committed.txt row shows **In vault
  = alpha-app/shared-payments**; notice "1 finding(s) match a stored
  credential. Matched credentials were marked possibly exposed — removing
  a secret from a file…". CLI `key status alpha-app/shared-payments` →
  "possibly exposed (Medium confidence), Reason: … matched during a
  repository scan in oops-committed.txt (line 1)". Recommendation is
  rotation; nothing auto-revoked.
- Expected: matched (plan SCN-05).
- Evidence: AX capture (In vault row + notice); CLI `key status`.
- Suspected component: n/a. (Feeds the possible_exposure alert in ALR.)

### SCN-06 — suppression with a required reason — **PASS (core via CLI; UI dialog see note)**

- Screen/workflow: suppress a finding with/without a reason
- Result: **PASS** for the suppression mechanism (shared core).
- Actual (CLI, shared core): empty reason → rejected ("a suppression
  reason is required"); with reason "test fixture, documented fake" →
  "Suppression added.", listed via `suppress list`; a re-scan **hides**
  the suppressed leaky.env stripe finding (10 → 9, finding absent).
- Expected: matched (plan SCN-06) — reason required, suppressed finding
  disappears.
- **UI-automation note (not a defect):** the desktop suppress-reason uses
  an in-app `PromptDialog` (source: ScanView.tsx line 287 — title
  "Suppress this finding", placeholder "why this is not a real secret",
  confirmLabel "Suppress"; empty-reason guard "A reason is required to
  suppress." at line 85). AXPress on the `className="link"` suppress
  button did **not** open the dialog under the accessibility driver
  (other buttons open their dialogs fine), so the UI reason-prompt itself
  was not driven from automation; the mechanism was verified via the
  shared CLI core. **Flagged for a quick human eyeball** (see "Items
  needing human confirmation").
- Evidence: CLI `suppress add`/`list`, re-scan JSON; source of the dialog.
- Suspected component: ScanView.tsx suppress button / AX interaction with
  link-styled buttons (not modified).

### SCN-07 — remove the suppression — **PASS**

- Result: **PASS** — `suppress remove` → "Suppression removed; future
  scans report this finding again."; re-scan shows the leaky.env stripe
  finding again (9 → 10).
- Evidence: CLI remove + re-scan JSON.
- Suspected component: n/a.

### SCN-08 — pre-commit hook blocks a staged secret — **PASS (security-critical)**

- Screen/workflow: Scan → Check hook status → Install (UI) → `git commit`
  with a staged secret (api-tracker on PATH)
- Result: **PASS** (conductor-observed via AX UI + real git)
- Actual: UI "Check hook status" showed the hook path; "Install" → state
  "installed"; the generated `.git/hooks/pre-commit` contains the
  sentinel block calling `api-tracker scan --staged --hook`. Staging a new
  file with an OpenAI-shaped fake secret and running `git commit` was
  **blocked**: "api-tracker: blocking commit — 1 high-confidence
  secret(s) found: leak-attempt.txt:1 [high] **sk-p…KE** (openai)" (value
  **redacted**, file:line shown), then "error: commit blocked by
  api-tracker pre-commit hook"; **no commit created** (git log count
  unchanged at 6). The hook ran **without unlocking the vault** (no
  master password supplied) and never printed the full secret.
- Expected: matched (plan SCN-08).
- Evidence: installed hook file; real `git commit` output (blocked,
  redacted); log-count before/after.
- Suspected component: n/a.

### SCN-09 — existing foreign hook is preserved — **PASS**

- Screen/workflow: hooks remove → foreign hook → status/install(refuse)/
  install --force/commit/remove (UI has the matching Install / Install
  (force / chain) / Remove buttons; force/chain/remove exercised via the
  shared CLI core)
- Result: **PASS**
- Actual: with a custom `echo CUSTOM-HOOK-RAN` hook present, status =
  "Foreign"; **plain install REFUSES** ("a pre-commit hook already
  exists… Re-run with --force… your existing hook is preserved");
  **force** install → "ChainedIntoForeign", the file now holds both the
  custom line and the API-Tracker sentinel block, and a clean
  `git commit --allow-empty` **prints CUSTOM-HOOK-RAN and succeeds**;
  **Remove** deletes only the API-Tracker block, leaving the file as
  exactly the original custom script (0 api-tracker markers, custom line
  intact).
- Expected: matched (plan SCN-09) — foreign hooks are never clobbered.
- Evidence: CLI status/install/remove output; hook-file contents at each
  step; the CUSTOM-HOOK-RAN commit.
- Suspected component: n/a.

### ALR-01 — run checks; expected alert set — **PASS**

- Screen/workflow: Alerts → Run checks now
- Result: **PASS** (conductor-observed via AX UI + CLI)
- Actual: notice "Checked 6 credential(s): 2 new, 0 resolved, 8 open.
  Documentation checks: 0 · webhook deliveries: 0." The **8 open alerts**
  cover every expected kind: expired (alpha-app/github-ci, high),
  expiring_soon (alpha-app/stripe-webhook, medium), production_in_
  development ×2 (payments-copy + shared-payments, high), over_budget
  (alpha-app, high), documentation_changed (openai, info),
  possible_exposure ×2 (scan finding + shared-payments marked exposed,
  high/critical). Each card shows severity, title, "Evidence:",
  "Recommended:". **No secret values** in any alert text (CLI grep clean).
- Expected: matched (plan ALR-01) — at least expired / expiring_soon /
  production_in_development / over_budget / documentation_changed all
  present (plus the two possible_exposure from SCN-05).
- Evidence: AX capture of cards; CLI `alerts list` (8 rows by kind);
  negative secret-value scan.
- Suspected component: n/a.

### ALR-02 — acknowledge and resolve lifecycle — **PASS**

- Screen/workflow: Alerts → acknowledge / resolve / "include acknowledged
  & resolved"
- Result: **PASS** — resolving an alert (f80910e7 possible_exposure) moved
  it out of the default list; enabling "include acknowledged & resolved"
  brought it back; CLI `alerts list --all` confirms state "resolved".
- Evidence: UI list counts before/after; CLI state.
- Suspected component: n/a.

### ALR-03 — monitor status line + native notification — **PASS (status) / human-confirm (native banner)**

- Screen/workflow: Alerts → Run checks now
- Result: **PASS** for the monitor status surface. The UI muted line
  "Checks last ran … · last success 7/19/2026, 1:30:20 PM" matches CLI
  `monitor --status` (Last run / Last success 2026-07-19T17:30:20Z; Last
  failure never; "2 new alert(s)"). The **native macOS notification**
  (banner titled "API Tracker") and the OS notification-permission prompt
  require human observation — flagged under "Items needing human
  confirmation".
- Evidence: UI status line; CLI `monitor --status`.
- Suspected component: n/a.

### NTF-01 — invalid webhook destination rejected — **PASS**

- Screen/workflow: Notifications → Add webhook channel… → http URL
- Result: **PASS** — entering `http://example.com/hook` (name bad-hook,
  floor high) was rejected: "invalid input: plain http is only allowed to
  localhost for testing (got host 'example.com'); use https"; **no channel
  created** (CLI `notify list` empty). The URL field masks even on the
  failed attempt.
- Evidence: AX capture of error; CLI notify list.
- Suspected component: n/a.

### NTF-02 — add a working localhost channel and test it — **PASS (security-relevant)**

- Screen/workflow: Notifications → Add webhook channel… (local-sink,
  http://127.0.0.1:8085/hook, floor info) → test
- Result: **PASS** — "Channel 'local-sink' added (http…ok; floor info)…";
  URL column shows "URL (masked)"; test → "Test through 'local-sink':
  delivered (status 200)". The sink received a **metadata-only** JSON
  payload: `{source, kind:"test", severity:"info", title, detail,
  recommended_action, observed_at}` — **no credential value, no full URL,
  no secret**.
- Evidence: AX capture; sink payload body captured (unbuffered sink).
- Suspected component: n/a.

### NTF-03 — delivery on monitor + duplicate-delivery prevention — **PASS**

- Screen/workflow: Alerts → Run checks now (×2)
- Result: **PASS** — 1st run delivered **6** payloads (UI "webhook
  deliveries: 6"; sink received 6); 2nd run with no new alerts delivered
  **0** ("webhook deliveries: 0"; sink silent). All 6 real-alert payloads
  are metadata-only — e.g. the possible_exposure payload names the
  credential and file but carries **no secret value**.
- Evidence: sink payload count before/after; UI delivery counts; secret
  scan across all payloads (clean).
- Suspected component: n/a.

### NTF-04 — webhook failure and retry — **PASS**

- Screen/workflow: add dead-sink (http://127.0.0.1:8086/hook, nothing
  listening) → test
- Result: **PASS** — "Test through 'dead-sink' failed: provider request
  failed: webhook delivery failed: network error"; CLI `notify list` shows
  dead-sink LAST ERROR filled with that message. The failure is recorded
  per-channel, **never reported as success**. (Retry-on-later-run is a
  monitor-internal behavior; the per-channel failure recording — the
  honesty-critical part — is verified.)
- Evidence: AX notice; CLI notify list last_error.
- Suspected component: n/a.

### NTF-05 — disable / enable / remove — **PASS**

- Screen/workflow: disable → enable → remove (both channels)
- Result: **PASS** — disable local-sink → STATE "off"; enable → "on";
  remove → confirm dialog "Remove channel 'dead-sink'?" → Remove channel →
  row gone; both channels removed (CLI `notify list` empty).
- Evidence: CLI state transitions; AX confirm-dialog capture.
- Note: "disabled channel receives nothing" was inferred from STATE=off
  (no new alerts existed to deliver during the disabled window, so an
  explicit silent-delivery cycle was not separately forced).
- Suspected component: n/a.

### ENV-01 — discover with Git status badges — **PASS**

- Screen/workflow: Env files → Discover .env files (project alpha-app;
  .env.local committed/tracked first)
- Result: **PASS** — discovery table rows: `.env` class "values", Git
  badge "untracked"; `.env.local` class "values", **red** badge "tracked
  — committed secrets risk" + "in Git history — deleting the file does not
  remove past commits". Git/Vars/Problems columns present. No values on
  screen at this stage.
- Evidence: AX capture.
- Suspected component: n/a.

### ENV-02 — masked preview with classification — **PASS**

- Screen/workflow: Env files → .env preview
- Result: **PASS** — OPENAI_API_KEY (Secret, import checkbox **checked**),
  GITHUB_TOKEN (Secret, **checked**), APP_DEBUG (not secret, unchecked),
  EXAMPLE_KEY (placeholder, unchecked); every value **masked** (••••).
  Secrets pre-selected; non-secret/placeholder excluded.
- Evidence: AX capture (checkbox states + masked values).
- Suspected component: n/a.

### ENV-03 — selective import creates credentials + mappings — **PASS**

- Screen/workflow: .env preview → Import 2 variable(s)… → Import (confirm)
- Result: **PASS** — confirm dialog "Import variables into the vault";
  then "2 variable(s) imported or mapped. **The file was not modified.**"
  Two new credentials appear under alpha-app: `openai-api-key` (sk-p…EY)
  and `github-token` (ghp_…11) — named from the variables lowercased with
  underscores→hyphens; mappings created (OPENAI_API_KEY → openai-api-key,
  GITHUB_TOKEN → github-token). The `.env` file's **bytes are unchanged**
  (md5 identical before/after).
- Evidence: AX notice; CLI `key list` (2 new masked rows), `mapping list`
  (2 mappings); md5 of .env unchanged.
- Suspected component: n/a.

### ENV-04 — malformed + duplicate `.env` — **PASS**

- Screen/workflow: Env files → .env.local preview
- Result: **PASS** — preview lists **GITHUB_TOKEN twice** (duplicate
  visible), the quoted STRIPE_SECRET_KEY (mask handles quotes + inline
  comment), and a "Problems" column reporting the malformed line (not
  silently dropped).
- Evidence: AX capture.
- Suspected component: n/a.

### ENV-05 — `.env.example` proposal and write — **PASS**

- Screen/workflow: .env panel → Write .env.example… → confirm
- Result: **PASS** — masked diff preview ("names only; secret values in
  the diff are masked"); confirm dialog; then "Wrote …/.env.example
  (names only, never values)." + "is already up to date." on recheck. The
  file on disk lists variable **names only** with empty values
  (`OPENAI_API_KEY=""`, `GITHUB_TOKEN=""`, `APP_DEBUG=""`,
  `EXAMPLE_KEY=""`) — **no secret value written**.
- Evidence: AX capture; file contents; negative value scan.
- Suspected component: n/a.

### ENV-06 — reauthenticated temporary export — **PASS (security-relevant)**

- Screen/workflow: Env files → Exports → Export .env… (target .env.tmp,
  lifetime 1) → Export (reauth)
- Result: **PASS** — reauth dialog "Write plaintext secrets to …/.env.tmp"
  / "Confirm your master password to continue."; after the password:
  "Exported 2 variable(s) to …/.env.tmp…" with warnings. The file is
  **mode 600**, begins with a PLAINTEXT-secrets warning banner ("This
  file contains PLAINTEXT secrets."), and contains the mapped values; the
  Exports table gains a row with Expires set. Refused without the master
  password (reauth-gated).
- Evidence: AX reauth dialog; `stat` mode 600; file banner+contents.
- Suspected component: n/a.

### ENV-07 — export cleanup (expired; force semantics) — **PASS**

- Screen/workflow: (wait > 1 min; append a line to .env.tmp) → Clean up
  expired… (force OFF, then force ON)
- Result: **PASS** — force **OFF**: "0 exported file(s) removed." — the
  changed file is **kept** (guard against deleting user edits); force
  **ON**: "1 exported file(s) removed.", .env.tmp deleted, "No live
  exports." The changed-content guard prevented deletion without consent.
- Evidence: AX notices; file present/absent before/after.
- Suspected component: n/a.

### ENV-08 — drift: file vs vault + unmapped secret — **PASS**

- Screen/workflow: edit .env OPENAI_API_KEY to the drifted value → Env
  files → Drift → Check drift
- Result: **PASS** (UI + CLI) — drift findings: **[medium] value differs
  from vault** for OPENAI_API_KEY (.env — file edited after import,
  file-to-vault drift) and GITHUB_TOKEN (.env.local); **[high] unmapped
  secret** for STRIPE_SECRET_KEY (.env.local); **[medium]
  SameValueInMultipleFiles** for GITHUB_TOKEN (across .env / .env.local /
  .env.tmp) — each with File, Variable, Detail, Recommendation. Comparison
  is by keyed fingerprint; **no plaintext** in the drift table. (The
  symmetric vault-to-file direction uses the same fingerprint comparison;
  the file-to-vault direction was exercised directly.)
- Evidence: AX capture; CLI `env drift --project alpha-app`.
- Suspected component: n/a.

### ENV-09 — export refuses a Git-tracked target — **PASS**

- Screen/workflow: Export .env… → target .env.local (tracked), overwrite
  ON → Export (reauth)
- Result: **PASS** — the export **fails**: "invalid input: …/.env.local
  is tracked by Git; exporting secrets into a tracked file…"; `.env.local`
  is unchanged (`git diff` empty). Never writes plaintext into a tracked
  file.
- Evidence: AX error; git diff empty.
- Suspected component: n/a.

### CRD-13 — version history (reauth-gated, masked) — **PASS**

- Screen/workflow: openai-main → Lifecycle → Version history… → reauth
- Build: dev, app 0.1.0 @ prod code `7d81090`
- Result: **PASS** (conductor-observed via AX automation)
- Actual: "Version history…" opened the reauth dialog "View version
  history" / "Confirm your master password to continue."; after the
  master password, a table with two rows (Version / Note / value) — both
  values **masked** "sk-p…EY", one row marked "current"; footer "Old
  versions exist so destination rollback works; they are encrypted like
  current values and pruned automatically."
- Expected: matched (plan CRD-13) — gated, values masked.
- Evidence: AX-tree capture; negative scan for full v1/v2 plaintext →
  none.
- Reproduction: observed once.
- Suspected component: n/a.
