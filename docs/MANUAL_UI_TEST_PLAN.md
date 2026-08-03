# Manual UI Test Plan

> **Naming note (2026-07-24):** API Tracker was renamed **Tethra** after this
> plan's baseline (`7d81090`) was verified. When executing against a
> post-rename build: the window/bundle is **Tethra** / `Tethra.app` /
> `Tethra.dmg` (inner binary path under `Tethra.app/Contents/MacOS/`), macOS
> notifications are titled "Tethra", `tethra` is the preferred CLI command
> (legacy `api-tracker` still works), and `TETHRA_*` env vars are preferred
> (legacy `API_TRACKER_*` still honored — every procedure below works
> unchanged). The vault data directory is intentionally still named
> `api-tracker`. Baseline steps below are intentionally unchanged; see
> docs/rebrand/TETHRA_MIGRATION_GUIDE.md.

A button-by-button manual test plan for the API Tracker desktop app (with
the CLI used where a workflow is CLI-only), written for a tester who has
never seen the code. Verified against `main` commit `7d81090`.

Companions:

- [UI_MAP.md](UI_MAP.md) — every screen, button, field, and state, with
  source files (read it side by side with this plan).
- [MANUAL_TEST_DATA.md](MANUAL_TEST_DATA.md) — every synthetic value used
  below (referenced as *TD §n*). **Never use real credentials.**

## How to read a test case

Every test uses this exact template:

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
Exact test values:          from MANUAL_TEST_DATA.md
Expected visible result:    exact on-screen outcome
Expected persisted result:  what survives a reload/restart, and where
Expected audit/alert result:alerts raised, or audit-trail visibility
Expected security behavior: redaction/reauth/confirmation guarantees
Cleanup:                    what to undo (— if nothing)
Screenshot checkpoint:      take one here (— if not needed)
Pass/fail:                  ☐
```

Notes that apply everywhere:

- **Reauthentication dialog** means the shared dialog titled per action
  with the text "Confirm your master password to continue.", a **Master
  password** field, and **Cancel**. A wrong password shows `incorrect
  password` inside the dialog and the dialog stays open; **Cancel always
  aborts with no effect** (spot-verified in VLT-04, CRD-09; assumed
  elsewhere).
- **Audit trail:** sensitive actions are recorded in the local
  `audit_events` table. The desktop has no dedicated audit screen; audit
  entries for a credential are visible in its **Lifecycle → Load timeline**
  (CLI: `api-tracker key history <c>`). Where a test says "audit: timeline
  shows …", check there.
- The app never shows a secret value except during an explicit **Reveal
  value**. If you ever see a plaintext secret anywhere else (list, error,
  alert, notification, export listing), that is an automatic FAIL of the
  whole plan — report it as a security bug.
- Timestamps display in local time; stored values are UTC RFC 3339.

Do not re-verify what the automated suites already prove exhaustively
unless a visible UI workflow depends on it — see §A (automated-coverage
map) before extending this plan.

---

## Part 1 — Launch, data locations, and reset (verified commands)

All commands below were run and verified on macOS against this repository.
Run them from the repository root unless stated otherwise.

### 1.1 Install dependencies

Prerequisites: Rust stable 1.85+ (`rustup`), Node.js 20+ with npm, Xcode
Command Line Tools.

```bash
# CLI + core (release binary at target/release/api-tracker)
cargo build --release -p api-tracker-cli

# Desktop UI dependencies
cd apps/desktop
npm install
```

> If `npm install` fails with an EACCES error on `~/.npm`, use
> `npm install --cache /tmp/npm-cache` (a root-owned npm cache is a known
> machine-specific issue, not an app bug).

### 1.2 Run the desktop app (development mode)

```bash
cd apps/desktop
npm run tauri dev          # equivalently: npx tauri dev
```

First compile of the Rust backend takes a few minutes; the window titled
**API Tracker** opens when ready.

### 1.3 Build and run the packaged macOS app

```bash
cd apps/desktop
npx tauri build            # bundles target/release/bundle/macos/API Tracker.app + .dmg
open "../../target/release/bundle/macos/API Tracker.app"
```

The alpha bundle is **unsigned**: on a fresh download macOS Gatekeeper will
warn; right-click → *Open* → *Open* (locally built bundles usually launch
without the warning). **Note:** the packaged app resolves the vault
directory from its own environment — launching via `open` uses the default
data directory (1.5), not your shell's `API_TRACKER_DIR`. Use
`API_TRACKER_DIR=… "…/API Tracker.app/Contents/MacOS/api-tracker-desktop"`
to run a packaged build against an isolated vault.

### 1.4 Start with a completely clean, isolated test vault

The vault directory is chosen by `API_TRACKER_DIR`. Point it at an empty
directory and the app starts on the **Create your vault** screen without
touching your real data:

```bash
mkdir -p ~/at-manual-test/vault
cd apps/desktop
API_TRACKER_DIR=~/at-manual-test/vault npm run tauri dev
```

### 1.5 Where data lives / preserving an existing vault

Without `API_TRACKER_DIR`, both the desktop app and the CLI use the
platform data directory — macOS: `~/Library/Application Support/api-tracker/`
(`vault.db` + WAL/SHM sidecars + `session.json`). **Every test in this plan
runs with `API_TRACKER_DIR=~/at-manual-test/vault`**, so an existing real
vault is preserved untouched. Never run the plan without the override if
this machine has a real vault.

### 1.6 Run the demo seed and open it in the desktop app

The demo builds a *separate* throwaway vault with fake credentials in every
interesting state (see docs/DEMO.md; passwords are documented there and in
the script header):

```bash
export API_TRACKER_DEMO_DIR="${TMPDIR:-/tmp}/api-tracker-demo"
bash scripts/demo.sh --keep            # --fresh replaces a previous kept demo

cd apps/desktop
API_TRACKER_DIR="$API_TRACKER_DEMO_DIR/vault" npm run tauri dev
# unlock with: demo-master-password-12345
```

CLI against the same demo vault:

```bash
export API_TRACKER_DIR="$API_TRACKER_DEMO_DIR/vault"
export API_TRACKER_PASSWORD='demo-master-password-12345'
./target/release/api-tracker key list
./target/release/api-tracker alerts list
```

### 1.7 Resetting only test data — safely

> ⚠️ **Deletion warning.** The commands below permanently delete the named
> directories. Check each path before pressing Enter, and never point them
> at `~/Library/Application Support/api-tracker` unless you truly intend to
> delete your real vault.

```bash
rm -rf ~/at-manual-test                      # the manual-test workspace (vault + fixtures)
rm -rf "${TMPDIR:-/tmp}/api-tracker-demo"    # the kept demo vault, if created
```

Also remove the disposable macOS Keychain item if DST/SYN tests wrote one
and you skipped DST-08:
`security delete-generic-password -s API_TRACKER_MANUAL_TEST_SECRET` (it is
a fake value either way).

### 1.8 Run the CLI against the same vault as the desktop app

The two frontends share one vault when they resolve the same directory:

```bash
export API_TRACKER_DIR=~/at-manual-test/vault
export PATH="$PWD/target/release:$PATH"      # puts `api-tracker` on PATH
api-tracker doctor                           # health info, no unlock needed
api-tracker unlock                           # prints an export API_TRACKER_SESSION=... line
# or non-interactively for this plan:
export API_TRACKER_PASSWORD='manual-master-passphrase-01'
api-tracker key list
```

Two useful smoke commands (both verified green on this commit):
`bash scripts/smoke.sh` (126 automated end-to-end checks) and
`bash scripts/demo.sh` (self-deleting tour).

---

## Part 2 — One-time test-session setup

### SETUP-01 — build and launch

```text
Mode: Manual UI + CLI
Requirement: the app installs, builds, and launches from a clean checkout
Starting state: repository checked out at main (7d81090)
Prerequisites: Rust 1.85+, Node 20+, Xcode CLT
Exact navigation: —
Exact buttons to click: —
Exact fields to fill: —
Exact test values: commands from Part 1.1, 1.2, 1.4
Expected visible result: a window titled "API Tracker" showing the
  "Create your vault" screen with the data dir ~/at-manual-test/vault
Expected persisted result: —
Expected audit/alert result: —
Expected security behavior: no vault files created before the form submits
Cleanup: —
Screenshot checkpoint: the Create your vault screen
Pass/fail: ☐
```

### SETUP-02 — create the fixture repository and files

```text
Mode: CLI
Requirement: scanning/.env/detection fixtures exist (TD §1, §5, §6)
Starting state: ~/at-manual-test exists
Prerequisites: git on PATH
Exact test values / commands (run exactly; values from TD §5, §6):
    cd ~/at-manual-test
    git init alpha-repo && cd alpha-repo
    git commit --allow-empty -m init
    # history-only secret (committed then deleted):
    printf 'token=ghp_FAKE1111111111111111111111111111111111\n' > old-secret.txt
    git add old-secret.txt && git commit -m "add old secret"
    git rm -q old-secret.txt && git commit -m "remove old secret"
    # working-tree fixture (TD §5 leaky.env content) + committed vault match:
    cp <repo>/apps/cli/tests/fixtures/leaky-repo/config.env leaky.env
    git add leaky.env && git commit -m "leaky env fixture"
    # .env files (TD §6, exact contents):
    #   .env        (4 lines incl. export/quotes/placeholder)
    #   .env.local  (duplicate var, malformed line, quoted+comment)
    # detection fixture:
    printf '{"dependencies":{"openai":"^4.0.0"}}\n' > package.json
    git add package.json && git commit -m "package.json"
    # binary + large file (working tree only):
    head -c 1024 /dev/urandom > blob.bin
    yes xxxxxxxxxxxxxxxx | head -c 2000000 > big.txt
Expected visible result: git log shows 4+ commits; files exist
Expected persisted result: fixture repo at ~/at-manual-test/alpha-repo
Expected audit/alert result: —
Expected security behavior: every fixture value carries a FAKE marker
Cleanup: Part 1.7 at the end of the plan
Screenshot checkpoint: —
Pass/fail: ☐
```

### SETUP-03 — start the local test servers (when needed)

```text
Mode: CLI
Requirement: deterministic webhook + documentation-watch targets (TD §9, §10)
Starting state: —
Prerequisites: python3
Exact test values:
    python3 ~/at-manual-test/webhook_sink.py             # terminal A (port 8085)
    python3 -m http.server 8090 --bind 127.0.0.1 \
        --directory ~/at-manual-test/docroot             # terminal B
Expected visible result: both servers idle, printing requests as they come
Cleanup: Ctrl-C both when done
Pass/fail: ☐
```

---

## Part 3 — Test cases

Run in the order printed; later tests reuse earlier data. §Order at the end
condenses this into a checklist.

### Vault gate

#### VLT-01 — create the vault

```text
Mode: Manual UI
Requirement: vault creation with a master password (encrypted at rest)
Starting state: app launched per SETUP-01, "Create your vault" shown
Prerequisites: —
Exact navigation: (first-run screen)
Exact buttons to click: Create encrypted vault
Exact fields to fill: "Master password (at least 12 characters; a long
  multi-word passphrase is best)"; "Confirm master password"
Exact test values: manual-master-passphrase-01 (both fields)
Expected visible result: main navigation appears (top bar Projects …
  Settings, Lock vault); Projects screen shows "No projects yet. A project
  is a folder for the API credentials of one codebase."
Expected persisted result: ~/at-manual-test/vault/vault.db exists;
  `api-tracker doctor` reports "Vault exists: yes", schema version 10
Expected audit/alert result: —
Expected security behavior: password typed into password-type inputs only;
  `ls -l` shows vault.db mode 0600 (`stat -f "%Lp" vault.db` → 600)
Cleanup: —
Screenshot checkpoint: main navigation, first unlock
Pass/fail: ☐
```

#### VLT-02 — master password one character below the minimum

```text
Mode: Manual UI
Requirement: 12-character minimum for newly chosen passwords
Starting state: fresh app pointed at an EMPTY second dir
  (API_TRACKER_DIR=~/at-manual-test/vault-short) — or delete and redo
  before VLT-01
Prerequisites: —
Exact navigation: Create your vault
Exact buttons to click: Create encrypted vault
Exact fields to fill: both password fields
Exact test values: elevenchars (exactly 11 characters)
Expected visible result: red error naming the 12-character minimum
  ("… must be at least 12 characters"); still on the create screen
Expected persisted result: no vault.db created in that directory
Expected audit/alert result: —
Expected security behavior: the attempted password is not echoed anywhere
Cleanup: rm -rf ~/at-manual-test/vault-short; relaunch against the main
  test vault
Screenshot checkpoint: —
Pass/fail: ☐
```

#### VLT-03 — password confirmation mismatch

```text
Mode: Manual UI
Requirement: client-side confirmation on vault creation
Starting state: as VLT-02 (empty dir, create screen)
Exact buttons to click: Create encrypted vault
Exact test values: manual-master-passphrase-01 / wrong-master-passphrase-00
Expected visible result: "The passwords do not match."; nothing created
Expected persisted result: no vault.db
Expected security behavior: no backend call made (instant client error)
Cleanup: as VLT-02
Pass/fail: ☐
```

#### VLT-04 — wrong vault password, then cancel-free retry

```text
Mode: Manual UI
Requirement: wrong master password is rejected without leaking anything
Starting state: main test vault exists; app relaunched (Unlock vault shown)
Exact navigation: Unlock vault
Exact buttons to click: Unlock
Exact fields to fill: Master password
Exact test values: wrong-master-passphrase-00
Expected visible result: red error "incorrect password"; screen stays
Expected persisted result: vault remains locked
Expected audit/alert result: —
Expected security behavior: the error does not echo the attempted password
Cleanup: —
Pass/fail: ☐
```

#### VLT-05 — unlock

```text
Mode: Manual UI
Requirement: correct master password unlocks
Starting state: VLT-04
Exact buttons to click: Unlock
Exact test values: manual-master-passphrase-01
Expected visible result: main navigation, Projects list
Expected persisted result: —
Expected security behavior: Argon2id unlock takes a noticeable fraction of
  a second (memory-hard KDF), then the field clears
Cleanup: —
Pass/fail: ☐
```

#### VLT-06 — Lock vault button

```text
Mode: Manual UI
Requirement: manual locking
Starting state: unlocked
Exact navigation: top bar
Exact buttons to click: Lock vault
Expected visible result: immediately back on "Unlock vault"
Expected persisted result: relaunching still shows Unlock (nothing lost)
Expected security behavior: no further screen is reachable without the
  password
Cleanup: unlock again (VLT-05)
Pass/fail: ☐
```

### Projects

#### PRJ-01 — create `alpha-app`

```text
Mode: Manual UI
Requirement: project creation with environments and a repository path
Starting state: unlocked, Projects list
Exact navigation: Projects → New project
Exact buttons to click: New project; Add path; Create project
Exact fields to fill: Name; Description; Environment classifications
  (checkboxes development + production); Local repository paths (input with
  placeholder /path/to/repository); Notes (never encrypted; do not put
  secrets here)
Exact test values: Name alpha-app; Description "manual test project";
  repo path /Users/<you>/at-manual-test/alpha-repo (absolute); Notes empty
Expected visible result: Project detail for alpha-app: Environments
  "development, production", the repository path listed, Password lock
  "not set"
Expected persisted result: CLI `api-tracker project show alpha-app` shows
  the same fields
Expected audit/alert result: —
Expected security behavior: —
Cleanup: —
Screenshot checkpoint: project detail
Pass/fail: ☐
```

#### PRJ-02 — create `beta-service`

```text
Mode: Manual UI
Requirement: multiple projects
Starting state: PRJ-01 done
Exact navigation: Projects → New project
Exact buttons to click: New project; Create project
Exact test values: Name beta-service; environment development only
Expected visible result: Projects table lists alpha-app and beta-service
  (Credentials counts 0)
Expected persisted result: `project list` shows both
Cleanup: —
Pass/fail: ☐
```

#### PRJ-03 — edit a project

```text
Mode: Manual UI
Requirement: project editing
Starting state: alpha-app exists
Exact navigation: Projects → alpha-app → Edit
Exact buttons to click: Edit; Save changes
Exact fields to fill: Description
Exact test values: "manual test project (edited)"
Expected visible result: detail shows the new description
Expected persisted result: survives relaunch
Cleanup: —
Pass/fail: ☐
```

#### PRJ-04 — archive and restore

```text
Mode: Manual UI
Requirement: archive is reversible and blocks new credentials
Starting state: beta-service open
Exact navigation: Projects → beta-service
Exact buttons to click: Archive (red); then Restore
Expected visible result: after Archive: title suffix "(archived)", notice
  "Project archived.", the Add credential button disabled with
  "(restore the project first)"; list State column "archived" (with
  "show archived" checked). After Restore: notice "Project restored."
Expected persisted result: archived flag round-trips
Expected audit/alert result: —
Expected security behavior: archive is confirmation-free (non-destructive:
  data retained)
Cleanup: leave restored
Pass/fail: ☐
```

### Credentials — creation and duplicates

#### CRD-01 — add a generic credential (custom provider)

```text
Mode: Manual UI
Requirement: credential storage, masked display, custom provider names
Starting state: alpha-app detail
Exact navigation: alpha-app → Add credential
Exact buttons to click: Add credential (page button); Add credential (form)
Exact fields to fill: Name (unique within the project); Provider (select
  Custom…); Custom provider name; Environment; Secret value (encrypted at
  rest; shown masked afterwards)
Exact test values: TD §4 C1 — name generic-token, custom provider
  internal, environment development, value
  MANUAL-TEST-NOT-A-REAL-KEY-000001
Expected visible result: credential detail page alpha-app/generic-token;
  Value shows a masked form (first/last characters + …), never the full
  value; Status badge "unknown"
Expected persisted result: `api-tracker key list` shows the row masked
Expected audit/alert result: audit: timeline (Load timeline) has a
  created event
Expected security behavior: `grep -r "MANUAL-TEST-NOT-A-REAL-KEY-000001"
  ~/at-manual-test/vault/` finds nothing (encrypted at rest)
Cleanup: —
Screenshot checkpoint: credential detail, masked value
Pass/fail: ☐
```

#### CRD-02..CRD-05 — add the four provider-shaped credentials

```text
Mode: Manual UI
Requirement: provider tagging, user-entered expiration dates
Starting state: alpha-app detail
Exact navigation: alpha-app → Add credential (four times)
Exact buttons to click: Add credential
Exact fields to fill: Name / Provider / Environment / Secret value /
  Expires on (optional)
Exact test values (TD §4):
  CRD-02: openai-main   / OpenAI / development / C2 value / no expiry
  CRD-03: github-ci     / GitHub / development / C3 value / Expires on 2025-12-31
  CRD-04: stripe-webhook/ Stripe / test        / C4 value / Expires on <today+7d>
  CRD-05: shared-payments / OpenAI / production / C5 value / no expiry
Expected visible result: project credential table shows 5 rows; Status
  badges: github-ci "expired" (red), stripe-webhook "expiring soon"
  (yellow), others "unknown"; credential detail for github-ci shows a
  status finding with reason, source, confidence, recommended action;
  "Expires (provider-reported)" reads "not reported by the provider"
Expected persisted result: `key status alpha-app/github-ci` reports
  expired with the same evidence
Expected audit/alert result: alerts appear later via ALR-01
Expected security behavior: all values masked everywhere
Cleanup: —
Screenshot checkpoint: project table with the mixed status badges
Pass/fail: ☐
```

#### CRD-06 — duplicate credential across two projects (store a copy)

```text
Mode: Manual UI
Requirement: keyed-fingerprint duplicate detection + explicit override
Starting state: CRD-05 done; beta-service exists (unlocked, no password yet)
Exact navigation: Projects → beta-service → Add credential
Exact buttons to click: Add credential; then in the dialog:
  Store a duplicate copy anyway
Exact fields to fill: Name payments-copy; Provider OpenAI; Environment
  development; Secret value
Exact test values: the C5 shared value (TD §4)
Expected visible result: dialog "This value is already in your vault" with
  a warning naming alpha-app/shared-payments, the highest-risk
  classification (production value shared with development), a
  "Recommendation: …" line, and the guidance paragraph; after choosing
  Store a duplicate copy anyway, beta-service/payments-copy exists; both
  credentials now show status "shared across projects"
Expected persisted result: `key status alpha-app/shared-payments` lists
  the reuse finding naming beta-service/payments-copy
Expected audit/alert result: monitor later raises
  production_in_development / reuse alerts (ALR-01)
Expected security behavior: the dialog shows identifying info only, never
  the value
Cleanup: —
Screenshot checkpoint: the reuse dialog
Pass/fail: ☐
```

#### CRD-07 — reference instead of copy

```text
Mode: Manual UI
Requirement: intentional sharing stores a reference, not a second ciphertext
Starting state: CRD-06 done
Exact navigation: beta-service → Add credential
Exact buttons to click: Add credential; Reference the existing credential
Exact fields to fill: Name shared-ref; Provider OpenAI; Environment
  development; Secret value = the C5 shared value again
Expected visible result: reuse dialog appears; after Reference the existing
  credential, beta-service/shared-ref exists and its Value column shows
  "→ alpha-app/shared-payments" (detail: "reference to …"); the
  "Replace value…" button is absent on the reference's detail page
Expected persisted result: `key show beta-service/shared-ref` reports a
  reference
Expected security behavior: deleting the TARGET is refused/protected while
  references exist (verify in CRD-17 note)
Cleanup: keep (deleted in CRD-17)
Pass/fail: ☐
```

### Project password locks

#### PRJ-05 — set a project password (reauthenticated)

```text
Mode: Manual UI
Requirement: second password layer on one project; key rotation on set
Starting state: beta-service has credentials (CRD-06/07)
Exact navigation: Projects → beta-service → Set project password
Exact buttons to click: Set project password; Confirm
Exact fields to fill: Project password; Confirm project password; Master
  password (reauthentication)
Exact test values: manual-beta-project-pw-01 (twice);
  manual-master-passphrase-01
Expected visible result: warning box about the second lock and
  unrecoverability; notice "Project password set. Keep it safe: losing it
  makes this project's credential values unrecoverable."; detail shows
  Password lock "set (unlocked this session)"; buttons now Lock project /
  Remove password
Expected persisted result: Projects list State column "password set
  (unlocked)"
Expected audit/alert result: —
Expected security behavior: requires the master password (reauth); wrong
  master aborts with "incorrect password"
Cleanup: —
Pass/fail: ☐
```

#### PRJ-06 — lock; wrong project password; unlock

```text
Mode: Manual UI
Requirement: project locking blocks values; wrong project password rejected
Starting state: PRJ-05
Exact navigation: beta-service → Lock project; then Unlock project
Exact buttons to click: Lock project; Unlock project; Confirm (twice)
Exact fields to fill: Project password
Exact test values: first wrong-beta-project-pw-00, then
  manual-beta-project-pw-01
Expected visible result: after Lock: notice "Project locked.", Password
  lock "set (locked)"; wrong password → red "incorrect password", still
  locked; correct → "Project unlocked."
Expected persisted result: lock state survives Lock vault/unlock (session
  scoped: after a full vault relock the project is locked again)
Expected audit/alert result: audit records the unlock (timeline of a
  credential in the project shows project events via key history)
Expected security behavior: see CRD-19 — reveal is blocked while locked
Cleanup: leave UNLOCKED for later tests
Pass/fail: ☐
```

#### CRD-19 — reveal blocked in a locked project

```text
Mode: Manual UI
Requirement: locked project ⇒ values unreadable even with the master password
Starting state: beta-service LOCKED (run before the final unlock of
  PRJ-06, or Lock project again)
Exact navigation: beta-service → payments-copy → Reveal value
Exact buttons to click: Reveal value; Confirm (reauth with the master
  password)
Exact test values: manual-master-passphrase-01
Expected visible result: error "project 'beta-service' is password-locked;
  unlock it first" — no value shown
Expected persisted result: —
Expected audit/alert result: no reveal audit event added
Expected security behavior: master password alone is NOT sufficient for a
  password-locked project's values
Cleanup: unlock the project again
Pass/fail: ☐
```

#### PRJ-07 — remove the project password

```text
Mode: Manual UI
Requirement: password removal proves knowledge of the current password
Starting state: beta-service unlocked (password set)
Exact navigation: beta-service → Remove password
Exact buttons to click: Remove password; Confirm
Exact fields to fill: Project password
Exact test values: manual-beta-project-pw-01
Expected visible result: notice "Project password removed; the vault lock
  still protects it."; Password lock "not set"
Expected persisted result: reveal works again with only master reauth
Expected security behavior: removal required the project password (not
  just the master)
Cleanup: —
Pass/fail: ☐
```

### Credentials — sensitive actions

#### CRD-08 — reveal (auto-hide)

```text
Mode: Manual UI
Requirement: reveal requires reauthentication; plaintext auto-hides
Starting state: alpha-app/generic-token detail
Exact navigation: alpha-app → generic-token → Reveal value
Exact buttons to click: Reveal value; Confirm
Exact fields to fill: Master password
Exact test values: manual-master-passphrase-01
Expected visible result: reauth dialog "Reveal credential value"; then the
  plaintext MANUAL-TEST-NOT-A-REAL-KEY-000001 appears inline in a warning
  box with a "hide" link; it disappears by itself after ~30 seconds
Expected persisted result: —
Expected audit/alert result: audit: timeline gains a viewed/revealed event
Expected security behavior: reveal is the ONLY place plaintext appears
Cleanup: click hide (or wait)
Screenshot checkpoint: revealed value with the hide link
Pass/fail: ☐
```

#### CRD-09 — cancelled reauthentication

```text
Mode: Manual UI
Requirement: cancelling reauth aborts with no effect
Starting state: generic-token detail
Exact navigation: Reveal value → Cancel
Exact buttons to click: Reveal value; Cancel
Expected visible result: dialog closes; nothing revealed; no error
Expected audit/alert result: no reveal event recorded
Expected security behavior: as stated
Cleanup: —
Pass/fail: ☐
```

#### CRD-10 — wrong master password in reauth

```text
Mode: Manual UI
Requirement: reauth rejects a wrong password and stays open
Starting state: generic-token detail
Exact buttons to click: Reveal value; Confirm
Exact test values: wrong-master-passphrase-00
Expected visible result: "incorrect password" INSIDE the dialog; dialog
  stays open; Cancel then closes it
Expected security behavior: no value revealed; password not echoed
Cleanup: Cancel
Pass/fail: ☐
```

#### CRD-11 — copy with timed clipboard clear

```text
Mode: Manual UI
Requirement: copy is reauthenticated; clipboard clears after the delay
Starting state: generic-token detail; Settings clipboard delay default 30
Exact buttons to click: Copy value; Confirm
Exact test values: manual-master-passphrase-01
Expected visible result: notice "Copied. The clipboard will be cleared in
  about 30 seconds."
Expected persisted result: paste into a text editor within 30 s → the C1
  value; paste after ~35 s → empty (clipboard cleared; best-effort — only
  cleared if still holding this value)
Expected audit/alert result: audit copy event on the timeline
Expected security behavior: plaintext never rendered on screen during copy
Cleanup: clear the editor scratch text
Pass/fail: ☐
```

#### CRD-12 — replace the value (history begins)

```text
Mode: Manual UI
Requirement: credential replacement retains the prior version encrypted
Starting state: alpha-app/openai-main detail
Exact navigation: openai-main → Replace value…
Exact buttons to click: Replace value…; Replace
Exact fields to fill: New secret value; Master password
Exact test values: TD §4 first replacement value
  (sk-proj-MANUAL-FAKE-ROTATED-…); manual-master-passphrase-01
Expected visible result: notice "Value replaced."; the masked Value
  changes
Expected persisted result: CRD-13 shows v1 + v2
Expected audit/alert result: changed event on the timeline
Expected security behavior: dialog states it re-encrypts and updates the
  reuse fingerprint; requires the master password
Cleanup: —
Pass/fail: ☐
```

#### CRD-13 — version history (reauth-gated, masked)

```text
Mode: Manual UI
Requirement: credential version history
Starting state: CRD-12 done
Exact navigation: openai-main → Lifecycle → Version history…
Exact buttons to click: Version history…; Confirm
Exact test values: manual-master-passphrase-01
Expected visible result: reauth "View version history"; table with v1
  (Note = replacement reason) and v2 (Note "current"), both values MASKED;
  footer explains versions exist for destination rollback and are pruned
Expected persisted result: `api-tracker key versions alpha-app/openai-main`
  (reauth) lists the same
Expected security behavior: gated because it reveals rotation cadence;
  values stay masked
Cleanup: —
Pass/fail: ☐
```

#### CRD-14 — manual marks (disable / revoke / exposure)

```text
Mode: Manual UI
Requirement: manual status marks incl. revoked and possibly-exposed
Starting state: alpha-app/generic-token detail
Exact navigation: Manual tracking row
Exact buttons to click: Mark used now; Mark validated OK; Mark disabled;
  Enable; Mark revoked; Unmark revoked; Flag possibly exposed (dialog →
  Flag); Clear exposure flag
Exact test values: exposure note "manual test note"
Expected visible result: notices in order: "Recorded a use just now." /
  "Recorded: validation OK." / "Marked disabled." (status badge "manually
  disabled") / "Re-enabled." / "Marked revoked." (badge "revoked", red) /
  "Unmarked revoked." / "Flagged as possibly exposed." (badge "possibly
  exposed") / "Exposure flag cleared."; Last used and Last validated
  timestamps update
Expected persisted result: `key status` mirrors each state
Expected audit/alert result: revoked/exposed states raise alerts on the
  next monitor run if left set (we clear them)
Expected security behavior: —
Cleanup: end with all marks cleared (status back to active/unknown)
Pass/fail: ☐
```

#### CRD-15 — lifecycle timeline

```text
Mode: Manual UI
Requirement: merged lifecycle timeline (metadata only)
Starting state: after CRD-08..14
Exact navigation: generic-token → Lifecycle → Load timeline
Exact buttons to click: Load timeline
Expected visible result: table At / Event / Detail / Source listing the
  created, revealed/copied, marks, and update events — no values anywhere
Expected persisted result: `key history alpha-app/generic-token` matches
Expected security behavior: metadata only
Cleanup: —
Pass/fail: ☐
```

#### CRD-16 — edit metadata

```text
Mode: Manual UI
Requirement: metadata editing without touching the secret
Starting state: generic-token detail
Exact navigation: Edit metadata
Exact buttons to click: Edit metadata; Save changes
Exact fields to fill: Documentation link (optional); Notes
Exact test values: https://example.com/manual-docs ; note "edited"
Expected visible result: detail shows the documentation link (opens in the
  default browser) and note
Expected persisted result: survives relaunch; masked value unchanged
Cleanup: —
Pass/fail: ☐
```

#### CRD-17 — delete a credential (reference protection first)

```text
Mode: Manual UI
Requirement: deletion is reauthenticated; reference targets are protected
Starting state: beta-service/shared-ref (reference) and its target exist
Exact navigation: (a) alpha-app → shared-payments → Delete…;
  (b) beta-service → shared-ref → Delete…
Exact buttons to click: Delete…; Delete permanently
Exact test values: manual-master-passphrase-01
Expected visible result: (a) deleting the TARGET fails with "credential is
  referenced by 1 linked credential(s); remove the references first";
  (b) deleting the REFERENCE succeeds and returns to beta-service
Expected persisted result: shared-ref gone from every list; target intact
Expected audit/alert result: deleted event in audit (target's timeline)
Expected security behavior: reauth required (the dialog performs a real
  password check before the delete)
Cleanup: — (payments-copy stays for scanning/alerts)
Pass/fail: ☐
```

#### CRD-18 — live validation of an invalid provider credential

```text
Mode: Manual UI + network (no account needed — the key is fake)
Requirement: validation makes a direct provider request and records failure
Starting state: internet available; alpha-app/openai-main detail
Exact navigation: Provider row → Validate
Exact buttons to click: Validate
Expected visible result: notice "Invalid: …" (provider rejected the fake
  key, HTTP 401-class detail); Last validated timestamp updates; Status
  gains an "invalid" finding
Expected persisted result: `key status` shows the failed validation
Expected audit/alert result: 3+ repeats within 24 h raise a
  repeated_auth_failure alert on the next monitor run (optional to verify)
Expected security behavior: request goes directly to api.openai.com; the
  key appears only in the request header, never on screen
Cleanup: Manual tracking → Mark validated OK to clear the invalid state
  (keeps later status tests clean)
Pass/fail: ☐
```

### Providers, catalog, documentation watches

#### PRV-01 — provider catalog

```text
Mode: Manual UI
Requirement: provider/API catalog (5 providers, honest data)
Starting state: unlocked
Exact navigation: Providers
Expected visible result: title "Provider catalog"; table with exactly
  OpenAI, Anthropic, GitHub, Stripe, Supabase; columns Provider / Secret
  env vars / Detection patterns / Expiration (OpenAI env vars:
  OPENAI_API_KEY, OPENAI_ADMIN_KEY)
Expected persisted result: `api-tracker provider list` matches
Cleanup: —
Pass/fail: ☐
```

#### PRV-02 — provider detail: links + honest capability matrix

```text
Mode: Manual UI
Requirement: capability honesty; official links open externally
Starting state: Providers
Exact navigation: Providers → OpenAI
Exact buttons to click: one official link (e.g. Manage keys); scroll to
  Capabilities
Expected visible result: the link opens in the SYSTEM browser (not inside
  the app window); Capabilities table lists exactly: validate credential /
  fetch metadata / fetch usage / read permissions / change permissions /
  create credential / disable credential / revoke credential / rotate
  credential / fetch pricing — with OpenAI statuses: validate implemented;
  read & change permissions "manual action required"; disable credential
  "unsupported"; usage/create/revoke/rotate "implemented · admin
  credential …" with explanatory notes
Expected persisted result: `provider capabilities openai` matches
Expected security behavior: nothing is claimed implemented that is not
Cleanup: close the browser tab
Screenshot checkpoint: capability matrix
Pass/fail: ☐
```

#### DOC-01 — watch a local page (unchanged)

```text
Mode: Manual UI + CLI
Requirement: documentation watch with conditional checks (no change)
Starting state: SETUP-03 server on :8090 running; docs.html = v1
Prerequisites: custom URLs are added via CLI (the desktop button watches
  the manifest's official pages)
Exact test values (CLI):
  api-tracker provider watch-docs openai --url http://127.0.0.1:8090/docs.html
Exact navigation: Providers → OpenAI → Documentation watches
Exact buttons to click: check now (on the 127.0.0.1 row) — twice
Expected visible result: the watch row appears with the URL; first check
  notice "Checked: … A page change does not necessarily mean a breaking
  API change."; Last checked set; Last changed "no change seen" after the
  second check (content unchanged); Docs change history table gains rows
  with outcome unchanged/not modified
Expected persisted result: `provider docs-history openai` lists the checks
Expected audit/alert result: no documentation_changed alert
Expected security behavior: only validators/hash/timestamps stored — never
  page content
Cleanup: —
Pass/fail: ☐
```

#### DOC-02 — the page changes

```text
Mode: Manual UI + CLI
Requirement: change detection raises an alert
Starting state: DOC-01 done
Exact test values: overwrite docs.html with the v2 content (TD §9)
Exact navigation: Providers → OpenAI → Documentation watches → check now
Expected visible result: Last changed now set; history row outcome
  "changed"
Expected audit/alert result: Alerts screen shows a documentation_changed
  alert for the URL (with the honest "not necessarily breaking" copy)
Cleanup: resolve the alert later in ALR-02
Pass/fail: ☐
```

#### DOC-03 — redirect is refused

```text
Mode: Manual UI + CLI
Requirement: the watcher never follows redirects (SSRF/downgrade guard)
Starting state: redirect_server.py on :8091 running (TD §9)
Exact test values (CLI):
  api-tracker provider watch-docs openai --url http://127.0.0.1:8091/docs.html
Exact navigation: Providers → OpenAI → Documentation watches → check now
  (8091 row)
Expected visible result: the check FAILS (status reflects an error /
  redirect not followed); Last changed stays "no change seen"
Expected security behavior: no request to the redirect target is made on
  the watcher's behalf (server B logs only the direct check on :8091)
Cleanup: unwatch the :8091 row (DOC-04)
Pass/fail: ☐
```

#### DOC-04 — unwatch

```text
Mode: Manual UI
Requirement: watch removal
Starting state: DOC-03
Exact navigation: Providers → OpenAI → Documentation watches
Exact buttons to click: unwatch (red, on the :8091 row)
Expected visible result: row disappears; history entries remain
Cleanup: also unwatch the :8090 row after DOC-02 if you prefer a quiet
  monitor
Pass/fail: ☐
```

### Usage, budgets, pricing

#### USE-01 — record synthetic usage; estimated cost

```text
Mode: Manual UI + CLI
Requirement: usage snapshots + local cost estimation (labeled)
Starting state: alpha-app/openai-main exists
Exact test values (CLI — manual recording is CLI-only):
  api-tracker usage record --credential alpha-app/openai-main \
      --model gpt-4o --input-tokens 1000000 --output-tokens 1000000
Exact navigation: Usage → Scope select → Projects → alpha-app
Expected visible result: "This month": Input tokens 1,000,000; Output
  tokens 1,000,000; Estimated cost $12.50 with the "(estimated locally
  from token counts and a bundled price table — may differ from the
  provider's bill)" label; Reported cost $0.00 "(provider-reported)";
  Attribution "exact_credential"; Records table has one manual row
  ("2,000,000 tokens", "(est.)" $12.50, source manual)
Expected persisted result: `usage report --project alpha-app` matches
Expected audit/alert result: —
Expected security behavior: estimate clearly labeled, never presented as
  provider-reported
Cleanup: —
Screenshot checkpoint: Usage screen with the labeled estimate
Pass/fail: ☐
```

#### USE-02 — over-budget alert

```text
Mode: Manual UI
Requirement: budgets + over_budget alert
Starting state: USE-01
Exact navigation: Usage (scope alpha-app) → Budget
Exact buttons to click: Save budget; then Alerts → Run checks now
Exact fields to fill: Monthly budget (USD)
Exact test values: 5.00
Expected visible result: "Budget saved."; status line "Used $12.50
  (estimated) · projected month-end $…" with the red badge "over budget";
  after Run checks now, Alerts lists a high-severity over_budget alert
  ("project:alpha-app is over budget"-style title) with evidence and a
  recommended action
Expected persisted result: `budget show --project alpha-app` matches
Expected audit/alert result: over_budget alert open
Expected security behavior: —
Cleanup: keep (used by NTF tests), adjusted in USE-03
Pass/fail: ☐
```

#### USE-03 — budget exactly at the spend (boundary)

```text
Mode: Manual UI
Requirement: over-budget means STRICTLY more than the budget
Starting state: USE-02 ($12.50 used)
Exact fields to fill: Monthly budget (USD)
Exact test values: 12.50
Expected visible result: after Save budget: NO "over budget" badge (used
  equals the budget); Alerts → Run checks now auto-resolves the previous
  over_budget alert (it disappears from the open list; visible with
  "include acknowledged & resolved")
Expected persisted result: budget 12.50 stored
Pass/fail: ☐
```

#### USE-04 — budget one cent under the spend

```text
Mode: Manual UI
Requirement: the boundary flips at one cent
Starting state: USE-03
Exact test values: 12.49
Expected visible result: "over budget" badge returns; Run checks now
  re-raises the over_budget alert
Cleanup: set the budget back to 5.00 (keeps a live alert for NTF tests)
Pass/fail: ☐
```

#### USE-05 — budget cost source selector

```text
Mode: Manual UI
Requirement: budgets consume exactly one configurable source
Starting state: only estimated data exists (no provider-reported rows)
Exact navigation: Usage → Budget cost source
Exact buttons to click: (select) provider-reported only; then estimated
  only; then best available (reported, else estimated)
Expected visible result: notice "Budgets now use the '…' cost source." per
  change; with provider-reported only: Used $0.00 (provider-reported), no
  over-budget badge; with estimated/best available: Used $12.50
Expected persisted result: `budget source` prints the current choice
Cleanup: leave best available
Pass/fail: ☐
```

#### USE-06 — empty usage range

```text
Mode: Manual UI
Requirement: empty scopes render cleanly
Starting state: beta-service has no usage
Exact navigation: Usage → Scope → beta-service
Expected visible result: This month all zeros ($0.00, labeled); Records:
  "No usage records for this scope and source."; Recent activity: "No
  activity recorded for this scope."
Pass/fail: ☐
```

#### USE-07 — unknown model: no invented estimate

```text
Mode: Manual UI + CLI
Requirement: unknown models never get an invented estimate
Exact test values (CLI):
  api-tracker usage record --credential alpha-app/openai-main \
      --model made-up-model-xyz --input-tokens 1000 --output-tokens 1000
Exact navigation: Usage → scope alpha-app → Records
Expected visible result: the new row shows "2,000 tokens" with Estimated
  "—" (no number invented for an unknown model)
Expected persisted result: totals unchanged except tokens
Pass/fail: ☐
```

#### PRC-01 — pricing records table

```text
Mode: Manual UI
Requirement: versioned effective-dated pricing visible
Exact navigation: Pricing
Exact buttons to click: checkbox "Show full version history (not just
  currently effective records)" on and off
Expected visible result: bundled OpenAI + Anthropic records with columns
  Provider/Model/Unit/Input /1M/Cached /1M/Output /1M/Per request/
  Effective from/Last verified/Origin (origin "bundled"); with history on,
  Claude Sonnet 5 appears twice with different Effective from dates (the
  documented September 2026 price change)
Expected persisted result: `pricing list --all` matches
Pass/fail: ☐
```

#### PRC-02 — manual override makes the unknown model estimable

```text
Mode: Manual UI
Requirement: override > imported > bundled; new usage uses it
Starting state: USE-07 done
Exact navigation: Pricing → Manual override
Exact buttons to click: Save override
Exact fields to fill: Provider; Model / service; Unit; Input $/1M;
  Output $/1M; Note
Exact test values: openai / made-up-model-xyz / tokens / 2.50 / 10 /
  "manual test override"
Expected visible result: "Override stored for openai/made-up-model-xyz.";
  a row with Origin "override" and a Remove button appears
Expected persisted result: re-record USE-07's command → the NEW row now
  shows an estimate of $0.01 (1k×$2.50/1M + 1k×$10/1M = $0.0125 → shown
  rounded); the OLD row keeps "—" ("Stored estimates are not recomputed.")
Pass/fail: ☐
```

#### PRC-03 — remove the override

```text
Mode: Manual UI
Exact buttons to click: Remove (on the override row)
Expected visible result: "Removed override for openai/made-up-model-xyz.";
  row gone (with history off)
Pass/fail: ☐
```

#### PRC-04 — import rejects malformed pricing

```text
Mode: Manual UI
Requirement: whole-file validation on import
Exact navigation: Pricing → Import reviewed pricing
Exact buttons to click: Validate and import
Exact test values: paste exactly:
  [{"provider":"openai","model":"bad","unit":"tokens","input_per_m":"-1"}]
Expected visible result: a red validation error (negative price rejected);
  no record added anywhere
Expected persisted result: records table unchanged
Pass/fail: ☐
```

#### PRC-05 — export / re-import round trip

```text
Mode: Manual UI
Exact buttons to click: Export all records; then copy the exported JSON
  into the import box; Validate and import
Expected visible result: export fills the read-only textarea; the import
  reports "Imported 0 new record(s), replaced N." (same records) or
  replaced-counts — never an error
Pass/fail: ☐
```

### Alerts and notifications

#### ALR-01 — run checks; expected alert set

```text
Mode: Manual UI
Requirement: local monitoring generates explainable alerts
Starting state: CRD-02..06 + USE-04 data present (budget 5.00)
Exact navigation: Alerts
Exact buttons to click: Run checks now
Expected visible result: notice "Checked N credential(s): … new, …
  resolved, … open. Documentation checks: … · webhook deliveries: …"; open
  alerts include at least, by kind:
    expired            (alpha-app/github-ci)
    expiring_soon      (alpha-app/stripe-webhook)
    production_in_development (the shared C5/C6 value)
    over_budget        (alpha-app)
    documentation_changed (from DOC-02, if run)
  each card shows severity badge, title, detail, "Evidence: …",
  "Recommended: …"
Expected persisted result: `api-tracker alerts list` shows the same kinds
Expected audit/alert result: this IS the alert check
Expected security behavior: alert text never contains secret values
Cleanup: —
Screenshot checkpoint: alerts list
Pass/fail: ☐
```

#### ALR-02 — acknowledge and resolve lifecycle

```text
Mode: Manual UI
Starting state: ALR-01 alerts open
Exact buttons to click: acknowledge (on one alert); resolve (on the same);
  checkbox "include acknowledged & resolved"
Expected visible result: after acknowledge: "(acknowledged)" suffix and
  the acknowledge link disappears; after resolve: the card leaves the
  default list; with the checkbox on it reappears marked "(resolved)"
Expected persisted result: state survives relaunch; a still-true condition
  (e.g. expired) re-raises on the next Run checks now (dedup: one open
  alert per condition)
Pass/fail: ☐
```

#### ALR-03 — monitor status line + native notification

```text
Mode: Manual UI (desktop notifications)
Requirement: monitor status surface + medium+ native notification
Starting state: at least one open medium+ alert condition still true
Exact navigation: Alerts
Exact buttons to click: Run checks now (grant the OS notification
  permission when asked)
Expected visible result: the muted line "Checks last ran … · last success
  …" updates; if NEW alerts were created this run, a macOS notification
  titled "API Tracker" appears ("… new high-priority alert(s)" from this
  screen; the background timer's variant reads "N new alert(s) — top
  severity: …")
Expected persisted result: `api-tracker monitor --status` shows the same
  last-run data
Screenshot checkpoint: the native notification
Pass/fail: ☐
```

#### NTF-01 — invalid webhook destination rejected

```text
Mode: Manual UI
Requirement: https-only webhook validation (http only to localhost)
Exact navigation: Notifications → Add webhook channel…
Exact buttons to click: Add webhook channel…; Add channel
Exact fields to fill: Name; Webhook URL (https; stored encrypted, shown
  masked afterwards); Minimum severity delivered
Exact test values: name bad-hook; URL http://example.com/hook; floor high
Expected visible result: red error "webhook URLs must be https (or http to
  localhost for testing)"; no channel created
Pass/fail: ☐
```

#### NTF-02 — add a working localhost channel and test it

```text
Mode: Manual UI
Requirement: webhook channels deliver metadata-only payloads
Starting state: webhook sink running on :8085 (SETUP-03)
Exact test values: name local-sink; URL http://127.0.0.1:8085/hook;
  Minimum severity delivered = info
Exact buttons to click: Add channel; then test (row link)
Expected visible result: "Channel 'local-sink' added (http://…{masked};
  floor info). Use \"test\" to verify delivery."; URL column shows a MASKED
  form; test notice "Test through 'local-sink': …"; the sink terminal
  prints a JSON payload containing alert metadata fields only — verify NO
  credential value and no full URL appear in it
Expected persisted result: Last delivery column set
Expected security behavior: URL stored encrypted; masked everywhere
Cleanup: —
Pass/fail: ☐
```

#### NTF-03 — delivery on monitor + duplicate-delivery prevention

```text
Mode: Manual UI
Requirement: open alerts deliver once per alert (no re-post every run)
Starting state: NTF-02; open alerts from ALR-01
Exact navigation: Alerts → Run checks now (twice, a minute apart)
Expected visible result: first run: sink prints deliveries and the run
  notice counts "webhook deliveries: N>0"; second run with no NEW alerts:
  sink prints NOTHING new ("webhook deliveries: 0")
Expected persisted result: Notifications → Delivery history (Show history)
  lists each attempt once with outcomes
Pass/fail: ☐
```

#### NTF-04 — webhook failure and retry

```text
Mode: Manual UI
Requirement: failures recorded per channel; retried on a later run
Exact test values: add channel dead-sink → http://127.0.0.1:8086/hook
  (nothing listens), floor info
Exact buttons to click: Add channel; test; then Alerts → Run checks now
Expected visible result: test fails ("Test through 'dead-sink' failed: …");
  the channel's Last error column fills; monitor runs record failed
  delivery attempts in Delivery history (retry attempts appear on later
  runs rather than being dropped)
Expected persisted result: last_error persists until a success
Cleanup: remove dead-sink (confirm dialog "Remove channel 'dead-sink'?" →
  Remove channel)
Pass/fail: ☐
```

#### NTF-05 — disable / enable / remove

```text
Mode: Manual UI
Starting state: local-sink exists
Exact buttons to click: disable; (Run checks now); enable; remove →
  Remove channel
Expected visible result: disabled channel receives nothing while disabled
  (sink silent); State column toggles; remove asks "Remove channel
  'local-sink'?" with "…cannot be undone." and deletes the row
Cleanup: sink can be stopped after this
Pass/fail: ☐
```

### Repository scanning and hooks

#### SCN-01 — working-tree scan (fixtures found, placeholders not)

```text
Mode: Manual UI
Requirement: local secret scanning with redaction and confidence
Starting state: SETUP-02 fixtures in ~/at-manual-test/alpha-repo
Exact navigation: Scan
Exact buttons to click: Scan
Exact fields to fill: Repository or directory path; Mode
Exact test values: /Users/<you>/at-manual-test/alpha-repo; Mode "Working
  tree"
Expected visible result: "Findings (N)" with rows for the three leaky.env
  fixtures (openai high, github high, stripe high) and the .env/.env.local
  secrets; every Value cell REDACTED (prefix…suffix); the placeholder rows
  (your-key-here, <REPLACE_ME>, pk_live_notasecret…) are NOT listed;
  blob.bin and big.txt produce no findings and no crash
Expected persisted result: none (scans do not persist findings)
Expected audit/alert result: audit records the scan (scan completed)
Expected security behavior: full values never shown; nothing leaves the
  machine (offline works — see OFF-01)
Cleanup: —
Screenshot checkpoint: findings table
Pass/fail: ☐
```

#### SCN-02 — staged scan

```text
Mode: Manual UI + CLI
Starting state: stage a new secret:
  cd ~/at-manual-test/alpha-repo
  printf 'key=sk-proj-FAKE1111111111111111111111111111FAKE\n' > staged-secret.txt
  git add staged-secret.txt
Exact test values: same path; Mode "Staged changes (Git)"
Exact buttons to click: Scan
Expected visible result: exactly the staged finding(s) (leaky.env is
  already committed, not staged — it must NOT appear here)
Cleanup: keep staged for SCN-08
Pass/fail: ☐
```

#### SCN-03 — recent-commit history scan

```text
Mode: Manual UI
Requirement: history scanning with a chosen depth and real line numbers
Exact test values: Mode "History (Git)"; Most recent commits = 50
Exact buttons to click: Scan
Expected visible result: findings include the DELETED old-secret.txt
  github token (history remembers) and the committed leaky.env values,
  each with file:line
Pass/fail: ☐
```

#### SCN-04 — full-history scan

```text
Mode: Manual UI
Exact test values: Mode "History (Git)"; checkbox "full history (every
  commit; can be slow on large repositories)" checked
Expected visible result: same findings as SCN-03 (the repo is small); the
  depth field hides while full history is checked
Pass/fail: ☐
```

#### SCN-05 — vault match marks the credential possibly exposed

```text
Mode: Manual UI + CLI
Requirement: scan findings are matched against the vault
Starting state: commit the C5 shared value:
  printf 'OOPS=sk-proj-MANUAL-FAKE-SHARED-0000000000-NOT-A-REAL-KEY\n' > oops-committed.txt
  git add oops-committed.txt && git commit -m oops
Exact test values: Mode "Working tree"; checkbox "mark matched vault
  credentials as possibly exposed" CHECKED (default)
Exact buttons to click: Scan
Expected visible result: the oops row shows In vault =
  alpha-app/shared-payments; notice "1 finding(s) match a stored
  credential. Matched credentials were marked possibly exposed — removing
  a secret from a file does not remove it from Git history; rotate it."
Expected persisted result: alpha-app/shared-payments status badge becomes
  "possibly exposed" (red); the finding card names the file
Expected audit/alert result: next Run checks now raises a
  possible_exposure alert
Expected security behavior: recommendation is rotation — nothing is
  auto-revoked
Cleanup: after ALR re-check, clear via Manual tracking → Clear exposure
  flag; git rm -q oops-committed.txt && git commit -m "remove oops"
Pass/fail: ☐
```

#### SCN-06 — suppression with a required reason

```text
Mode: Manual UI
Requirement: suppressions need a reason; suppressed findings disappear
Starting state: SCN-01 findings on screen
Exact buttons to click: suppress (on the leaky.env stripe row); Suppress
Exact fields to fill: the reason prompt (placeholder "why this is not a
  real secret") — FIRST submit it EMPTY, then with a reason
Exact test values: reason "test fixture, documented fake"
Expected visible result: empty reason → "A reason is required to
  suppress."; with a reason → "Suppressed. Re-run the scan to confirm it
  is hidden."; re-running Scan omits that finding; Show suppressions lists
  it with Key prefix / Path / Reason / Since
Expected persisted result: `api-tracker suppress list` shows it
Cleanup: SCN-07 removes it
Pass/fail: ☐
```

#### SCN-07 — remove the suppression

```text
Mode: Manual UI
Exact buttons to click: Show suppressions; remove (row link)
Expected visible result: "Suppression removed; future scans report this
  finding again."; re-scan shows the stripe finding again
Pass/fail: ☐
```

#### SCN-08 — pre-commit hook blocks a staged secret

```text
Mode: Manual UI + CLI
Requirement: hook install + a real blocked commit
Starting state: SCN-02 staged secret still staged; `api-tracker` on PATH
  for the git process (Part 1.8 export)
Exact navigation: Scan → Check hook status → Install
Exact buttons to click: Check hook status; Install
Exact test values (CLI): cd ~/at-manual-test/alpha-repo && git commit -m "try to leak"
Expected visible result: hook state shows installed (sentinel block in
  .git/hooks/pre-commit); the commit FAILS, printing the finding
  (file:line, redacted value) and no commit is created (`git log` count
  unchanged)
Expected persisted result: hook file persists; suppressions would bypass
  only that specific finding
Expected audit/alert result: —
Expected security behavior: the hook runs WITHOUT unlocking the vault and
  never prints the full secret
Cleanup: git restore --staged staged-secret.txt && rm staged-secret.txt
Pass/fail: ☐
```

#### SCN-09 — existing foreign hook is preserved

```text
Mode: Manual UI + CLI
Requirement: never clobber a user's pre-commit hook
Starting state: remove our hook first (Scan → Remove); then:
  printf '#!/bin/sh\necho CUSTOM-HOOK-RAN\n' > .git/hooks/pre-commit
  chmod +x .git/hooks/pre-commit
Exact navigation: Scan → Check hook status
Exact buttons to click: Check hook status; Install; Install (force /
  chain); Remove
Expected visible result: state reports a foreign hook; plain Install
  REFUSES to overwrite it; Install (force / chain) appends the API Tracker
  block while keeping the custom hook (a clean `git commit --allow-empty
  -m t` prints CUSTOM-HOOK-RAN and succeeds); Remove deletes only the API
  Tracker block — the custom hook file remains and still prints
Expected persisted result: .git/hooks/pre-commit contains only the custom
  script afterwards
Cleanup: rm .git/hooks/pre-commit; undo the empty commit if you care
  (optional)
Pass/fail: ☐
```

### `.env` governance

#### ENV-01 — discover with Git status badges

```text
Mode: Manual UI
Requirement: .env discovery incl. tracked/untracked/history status
Starting state: TD §6 files exist; commit .env.local first so one values
  file is TRACKED:
  cd ~/at-manual-test/alpha-repo && git add .env.local && git commit -m "track env.local"
Exact navigation: Env files
Exact buttons to click: Discover .env files
Exact fields to fill: Project (its registered repositories are searched;
  also the import target) = alpha-app
Expected visible result: rows for .env (class values, Git badge yellow
  "untracked") and .env.local (class values, RED badge "tracked —
  committed secrets risk"); Problems column counts .env.local's malformed
  line; Vars counts per file
Expected persisted result: —
Expected audit/alert result: —
Expected security behavior: no values on screen at this stage
Cleanup: —
Screenshot checkpoint: discovery table with the red tracked badge
Pass/fail: ☐
```

#### ENV-02 — masked preview with classification

```text
Mode: Manual UI
Requirement: preview shows masked values, secrets pre-selected,
  placeholders excluded
Starting state: ENV-01 table shown
Exact buttons to click: the .env file link
Expected visible result: preview table: OPENAI_API_KEY (Secret? yes,
  checkbox CHECKED), GITHUB_TOKEN (yes, CHECKED), APP_DEBUG (Secret? —,
  unchecked), EXAMPLE_KEY (Placeholder? yes, unchecked); Value column
  masked for every row (quotes/export prefix handled)
Expected security behavior: full values never rendered
Pass/fail: ☐
```

#### ENV-03 — selective import creates credentials + mappings

```text
Mode: Manual UI
Requirement: import stores encrypted values and auto-creates injection
  mappings; the file is not modified
Starting state: ENV-02 preview
Exact buttons to click: Import 2 variable(s)…; Import (confirm dialog)
Expected visible result: confirm dialog "Import variables into the vault"
  quoting the count and project; then "2 variable(s) imported or mapped.
  The file was not modified."; Import outcome table rows (action
  imported / mapped_existing) with credential names; re-opened preview
  shows In vault + Mapped to filled
Expected persisted result: two new credentials appear under alpha-app,
  named from the variables lowercased with underscores→hyphens
  (openai-api-key, github-token); `api-tracker mapping list --project
  alpha-app` includes OPENAI_API_KEY → the imported credential; the file's
  bytes are unchanged (`git diff` empty for tracked, mtime aside)
Expected audit/alert result: created events in audit
Expected security behavior: values encrypted; file untouched
Cleanup: —
Pass/fail: ☐
```

#### ENV-04 — malformed + duplicate `.env`

```text
Mode: Manual UI
Requirement: malformed lines reported, duplicates flagged, nothing dropped
Starting state: ENV-01 table
Exact buttons to click: the .env.local file link
Expected visible result: preview lists GITHUB_TOKEN twice (duplicate
  visible) and the quoted STRIPE_SECRET_KEY (mask handles quotes + inline
  comment); the malformed line is reported as a problem (count in the
  discovery table), not silently dropped
Pass/fail: ☐
```

#### ENV-05 — `.env.example` proposal and write

```text
Mode: Manual UI
Requirement: names-only example generation, never overwriting silently
Starting state: .env panel open (ENV-02)
Exact buttons to click: Write .env.example… ; Write .env.example (confirm)
Expected visible result: a masked diff preview under ".env.example"; after
  writing: "Wrote …/.env.example (names only, never values)."; reopening
  the file panel shows "….env.example is already up to date."; the file on
  disk lists variable NAMES only
Expected persisted result: .env.example exists; re-discovery classifies it
  class "template" with "…nothing to import."
Expected security behavior: no value ever written to the example
Cleanup: —
Pass/fail: ☐
```

#### ENV-06 — reauthenticated temporary export

```text
Mode: Manual UI
Requirement: plaintext export is loud, gated, 0600, gitignore-checked
Starting state: ENV-03 mappings exist
Exact navigation: Env files → Exports → Export .env…
Exact buttons to click: Export .env…; Export…; Export (reauth)
Exact fields to fill: Target path; Variables (comma-separated; empty =
  every configured mapping); Temporary lifetime in minutes (empty =
  persists until you delete it); checkbox overwrite the file if it already
  exists (leave OFF)
Exact test values: /Users/<you>/at-manual-test/alpha-repo/.env.tmp ;
  variables empty; lifetime 1
Expected visible result: reauth dialog titled "Write plaintext secrets to
  …/.env.tmp"; after Export: "Exported N variable(s) to … .env.tmp."
  plus warnings — including a .gitignore warning (the repo has none, so
  the file is not ignored); Exports table gains the row with Expires set
Expected persisted result: file exists with mode 600
  (stat -f "%Lp" → 600), starts with a plaintext warning banner, contains
  the mapped values
Expected audit/alert result: redacted export audit event
Expected security behavior: refused without the master password; the
  export list shows variable NAMES only
Cleanup: ENV-07 cleans it
Pass/fail: ☐
```

#### ENV-07 — export cleanup (expired; force semantics)

```text
Mode: Manual UI
Requirement: TTL cleanup; changed files kept unless forced
Starting state: ENV-06 done; wait ≥ 1 minute; then APPEND a line to
  .env.tmp (echo '# my edit' >> .env.tmp)
Exact buttons to click: Clean up expired… → Clean up expired (confirm,
  force checkbox OFF); then check "force: also delete files whose content
  changed since export…", Clean up expired… again → Clean up expired
Expected visible result: first pass: "0 exported file(s) removed." with a
  per-file outcome noting the changed content was kept; with force on the
  file is deleted ("1 exported file(s) removed.") and the row leaves the
  table
Expected persisted result: .env.tmp gone
Expected security behavior: the changed-file guard prevented deleting
  possible user edits without consent
Pass/fail: ☐
```

#### ENV-08 — drift: file vs vault (both directions) + unmapped secret

```text
Mode: Manual UI
Requirement: drift kinds with severity, fingerprint comparison only
Starting state: ENV-03 imported; now edit .env's OPENAI_API_KEY line to
  the DRIFTED value (TD §6)
Exact navigation: Env files → Drift → Check drift
Expected visible result: findings table including:
  "value differs from vault" (medium) for OPENAI_API_KEY — the file was
  edited after import (file-to-vault drift);
  "unmapped secret" (high) for .env.local's STRIPE_SECRET_KEY / duplicate
  GITHUB_TOKEN values (secrets on disk with no vault mapping)
  — each with File, Variable, Detail, Recommendation
Then: revert the .env edit; instead REPLACE the imported OPENAI_API_KEY
  credential's value in its detail page (Replace value…, any new fake) and
  Check drift again → "value differs from vault" appears again (vault-to-
  file drift: the vault moved, the file did not)
Expected persisted result: none (drift is computed on demand)
Expected security behavior: comparison is by keyed fingerprint; no
  plaintext in the drift table
Cleanup: optional — re-export or re-import to converge
Pass/fail: ☐
```

#### ENV-09 — export refuses a Git-tracked target

```text
Mode: Manual UI
Requirement: never write plaintext into a tracked file
Starting state: .env.local is tracked (ENV-01)
Exact navigation: Env files → Export .env…
Exact test values: Target path …/alpha-repo/.env.local ; overwrite ON
Exact buttons to click: Export…; Export (reauth)
Expected visible result: the export FAILS with an error stating the target
  is tracked by Git; the file is unchanged (`git diff` empty)
Pass/fail: ☐
```

### Destinations and sync plans (local Keychain + a deliberately broken remote)

#### DST-01 — catalog honesty and platform gating

```text
Mode: Manual UI (macOS)
Requirement: per-kind capability chips, platform availability, testing
  status
Exact navigation: Destinations
Expected visible result: Catalog lists 9 kinds; macOS Keychain row: write/
  read/delete/validation "implemented", platform macOS; Linux Secret
  Service and Windows Credential Manager show "unavailable on this
  platform" chips on macOS; GitHub Actions & Vercel show read:
  "unsupported" (write-only APIs); every row shows "verify: … · plan: … ·
  charges: …" and "testing: …" lines
Pass/fail: ☐
```

#### DST-02 — add + test the macOS Keychain destination

```text
Mode: Manual UI (macOS, local — no account)
Requirement: destination add/test with no admin credential
Exact navigation: Destinations → Add destination…
Exact buttons to click: Add destination… ; Add destination; then test
Exact fields to fill: Kind; Name (your label for this destination);
  Keychain account (optional; default "api-tracker") — leave empty
Exact test values: kind macOS Keychain; name manual-keychain
Expected visible result: "Added destination 'manual-keychain'. Use Test to
  verify it."; test notice "Test 'manual-keychain': …" success; Auth
  column "none"
Expected persisted result: `api-tracker destination list` shows it
Expected security behavior: no credential stored for OS-store kinds
Cleanup: removed in DST-08
Pass/fail: ☐
```

#### DST-03 — attach a credential

```text
Mode: Manual UI
Requirement: attachments record where a value is deployed
Exact navigation: Destinations → Attach a credential
Exact buttons to click: Attach
Exact fields to fill: Credential; Destination; Secret name at the
  destination; Environment
Exact test values: alpha-app/openai-main; manual-keychain;
  API_TRACKER_MANUAL_TEST_SECRET; development
Expected visible result: "Attached. Generate a sync plan to deploy the
  value."; Attachments row with Last synced "never", Drift "never checked"
Pass/fail: ☐
```

#### DST-04 — deliberately failing network destination

```text
Mode: Manual UI + network (Mocked provider — fake token, real endpoint)
Requirement: failures are reported, never faked as success
Exact test values (TD §11): kind GitHub Actions repository secrets; name
  manual-broken-gha; Repository owner manual-test-owner; Repository name
  manual-test-repo; Access token ghp_MANUALFAKE3333333333333333333333333333
Exact buttons to click: Add destination…; Add destination; test
Expected visible result: destination added with Auth (masked); test FAILS
  ("Test 'manual-broken-gha': …" error or red Last error column — GitHub
  rejects the fake token); never a success
Expected persisted result: last_error recorded on the row
Expected security behavior: the token is masked in the table and
  write-only (no reveal anywhere)
Cleanup: removed in DST-08
Pass/fail: ☐
```

#### SYN-01 — generate a dry-run plan

```text
Mode: Manual UI (macOS)
Requirement: sync plans are dry-run by default
Starting state: DST-03 attachment; also attach openai-main to
  manual-broken-gha (secret name API_TRACKER_MANUAL_TEST_SECRET) to get a
  two-step plan
Exact navigation: Sync plans
Exact buttons to click: Generate plan (dry run)
Exact fields to fill: Credential; Note (why this rollout is happening,
  optional)
Exact test values: alpha-app/openai-main; note "manual test rollout"
Expected visible result: "Plan generated (dry run). Nothing has been
  written — review the steps, then execute."; plan detail: Change v1→v2
  masked (from CRD-12's replacement), steps for BOTH destinations with
  action write, Validation (value read-back for keychain,
  existence for GitHub), Rollback? yes, Status "planned"
Expected persisted result: nothing written yet — `security
  find-generic-password -s API_TRACKER_MANUAL_TEST_SECRET` still fails
Expected security behavior: masked versions only
Cleanup: —
Screenshot checkpoint: plan detail before execution
Pass/fail: ☐
```

#### SYN-02 — execute: partial failure (keychain OK, GHA fails)

```text
Mode: Manual UI (macOS + network)
Requirement: reauthenticated execution, per-step verification,
  partial-failure honesty
Starting state: SYN-01 plan open
Exact buttons to click: Execute plan (2 step(s))… ; Continue to password;
  Execute (reauth)
Exact test values: manual-master-passphrase-01
Expected visible result: confirm dialog lists the exact writes ("Write
  version v2 (…) of alpha-app/openai-main to: '…' at manual-keychain
  (macos_keychain); '…' at manual-broken-gha (github_actions). Requests go
  directly from this machine to each destination."); after execution the
  keychain step is "executed" (verified timestamp — value read-back) and
  the GHA step "failed" (red detail); plan badge "partially failed" with
  the warning box "Some steps failed while others were executed:
  destinations are currently inconsistent. Retry the failed steps, or roll
  back the executed ones."; error banner "1 step(s) failed — the plan is
  partially failed. …" (macOS may prompt to allow keychain access — allow)
Expected persisted result: `security find-generic-password -s
  API_TRACKER_MANUAL_TEST_SECRET -w` prints the CURRENT fake value;
  Destinations → Attachments: keychain row Last synced v2, Drift
  "in sync" after Check drift now; GHA row unchanged
Expected audit/alert result: redacted sync audit events; a
  destination_drift alert may appear for the failed/never-synced GHA row
  on later monitor runs
Expected security behavior: execution required confirm + master password
Cleanup: —
Pass/fail: ☐
```

#### SYN-03 — retry the failed step (still failing, honestly)

```text
Mode: Manual UI + network
Exact buttons to click: Retry failed steps… ; Continue to password;
  Execute
Expected visible result: only the GHA step re-runs and fails again with a
  provider-rejection detail; the executed keychain step is NOT re-written
Pass/fail: ☐
```

#### SYN-04 — rollback to the previous version

```text
Mode: Manual UI (macOS)
Requirement: rollback restores destinations from retained versions
Starting state: SYN-02 executed keychain step
Exact buttons to click: Roll back to v1… ; Continue; Roll back (reauth)
Expected visible result: red confirm "Roll alpha-app/openai-main back to
  retained version v1 (…) by re-writing: '…' at manual-keychain …";
  after: "Rollback complete."; step status "rolled back"; plan badge
  "rolled back"
Expected persisted result: the keychain item now holds the v1 (original
  C2) value (`security … -w` shows it); the VAULT still holds v2 — the
  UI/CLI state rollback restores destinations, not the vault value
Expected security behavior: reauthenticated; masked throughout
Cleanup: —
Pass/fail: ☐
```

#### SYN-05 — stale plan refuses to run

```text
Mode: Manual UI
Requirement: a plan never deploys a value the user did not review
Starting state: generate a fresh plan for openai-main (dry run); then
  Replace value… on openai-main with TD's second replacement value
  (sk-proj-MANUAL-FAKE-STALE-…)
Exact buttons to click: (back on Sync plans) open the pre-replacement
  plan; Execute plan …
Expected visible result: the plan shows the warning "The credential's
  value changed after this plan was created. It can no longer be executed
  — generate a new plan." and the Execute button is disabled / execution
  refused; plan badge "stale"
Expected persisted result: nothing written
Cleanup: —
Pass/fail: ☐
```

#### DST-05 — drift check states

```text
Mode: Manual UI (macOS)
Starting state: after SYN-04 (keychain holds v1, vault holds v3 by now)
Exact navigation: Destinations
Exact buttons to click: Check drift now
Expected visible result: "Drift check complete. Write-only destinations
  can only be verified for existence."; keychain attachment shows
  "drifted" or "rolled back" (red/yellow badge — the keychain value no
  longer matches the current vault version); the GHA attachment shows
  "missing"/"never checked"
Pass/fail: ☐
```

#### DST-06 — delete the secret AT the destination

```text
Mode: Manual UI (macOS)
Requirement: destination-side deletion is confirmed + reauthenticated and
  never touches the vault
Exact navigation: Destinations → Attachments → delete at destination
  (keychain row)
Exact buttons to click: delete at destination; Delete secret at
  destination (reauth)
Expected visible result: reauth dialog titled "Delete
  'API_TRACKER_MANUAL_TEST_SECRET' AT 'manual-keychain'" with the body
  noting AWS's 30-day recovery window vs immediate deletion elsewhere and
  "The value in the local vault is NOT touched."; success notice
Expected persisted result: `security find-generic-password -s
  API_TRACKER_MANUAL_TEST_SECRET` now FAILS (item gone); the credential's
  vault value is intact (masked detail unchanged)
Pass/fail: ☐
```

#### DST-07 — detach

```text
Mode: Manual UI
Exact buttons to click: detach (each attachment row); Detach (confirm)
Expected visible result: confirm "Detach credential from destination" with
  "…The secret stored at the destination is not deleted."; rows disappear
Pass/fail: ☐
```

#### DST-08 — remove the destinations (reauth)

```text
Mode: Manual UI
Exact buttons to click: remove (manual-keychain row); Remove destination
  (reauth); repeat for manual-broken-gha
Expected visible result: "Removed 'manual-keychain'. Secrets already
  stored at the destination are NOT deleted." (ours was already deleted in
  DST-06); rows gone
Expected security behavior: removal reauthenticated (destinations may hold
  admin credentials)
Pass/fail: ☐
```

### Rotation (manual-mode, no provider account)

#### ROT-01 — plan a rotation (dry run)

```text
Mode: Manual UI
Requirement: rotation planning creates nothing anywhere
Starting state: alpha-app/openai-main exists (no admin connection ⇒
  manual-create mode); re-attach it to manual-keychain first if you want a
  destination step (optional; DST-02/03 can be redone)
Exact navigation: Rotation
Exact buttons to click: Plan rotation (dry run)
Exact fields to fill: Credential; Grace/overlap minutes; Note (optional)
Exact test values: alpha-app/openai-main; grace 60; note "manual test"
Expected visible result: "Dry run — nothing was created, written, or
  revoked. Review the plan below, then approve it."; detail shows state
  badge "planned", Mode "manual creation (provider dashboard)", the
  planned notice, and New value validated "not yet"
Expected persisted result: rotation listed; `api-tracker rotation list`
  matches
Expected security behavior: nothing contacted the provider
Cleanup: —
Screenshot checkpoint: planned rotation detail
Pass/fail: ☐
```

#### ROT-02 — cancel before anything changed

```text
Mode: Manual UI
Requirement: rotation cancelled before creation
Starting state: ROT-01's rotation open (state planned)
Exact buttons to click: Cancel rotation…; Continue to password; Cancel
  rotation (reauth)
Expected visible result: confirm "Cancel this rotation of
  alpha-app/openai-main? Only rotations that have not changed anything yet
  can be cancelled."; then notice "Cancelled (state: cancelled)."
Expected persisted result: list shows the cancelled rotation; credential
  untouched
Pass/fail: ☐
```

#### ROT-03 — approve, advance to the manual-key step, provide the key

```text
Mode: Manual UI
Requirement: guided manual rotation path with reauth at every step
Starting state: plan a NEW rotation (repeat ROT-01)
Exact buttons to click: Approve… → Continue to password → Approve;
  Advance… → Advance (reauth); (state becomes awaiting_manual_key);
  fill "Replacement key value (created by you in the provider dashboard;
  stored encrypted, never displayed)"; Advance… → Advance
Exact test values: replacement value TD §4
  sk-proj-MANUAL-FAKE-ROTNEW-0000000000-NOT-A-REAL-KEY;
  manual-master-passphrase-01 at each reauth
Expected visible result: after approve: "Approved. Use Advance to start
  executing."; the events table records each transition; after providing
  the key the rotation stores it as a new version and proceeds to
  destination updates (keychain step verified if attached) and then live
  validation of the new value — which FAILS with the fake key: "Last error
  (the step stays retryable): …" and the state stays advanceable. This is
  the honest stopping point without a real provider account.
Expected persisted result: `key versions` shows the rotation's new version;
  rotation events list persisted transitions
Expected audit/alert result: rotation_stuck alert only after 24 h idle
  (not expected today); "needs attention" badge appears after 24 h
Expected security behavior: every step needed the master password; the
  provided key is never displayed
Cleanup: ROT-05 rolls back
Pass/fail: ☐
```

#### ROT-04 — restart recovery mid-rotation

```text
Mode: Manual UI
Requirement: rotations are durable and resume after a restart
Starting state: ROT-03 in flight (mid state)
Exact test values: quit the app entirely (Cmd-Q), relaunch with the same
  API_TRACKER_DIR, unlock
Exact navigation: Rotation
Expected visible result: the in-flight rotation is still listed in the
  same state with its events; Advance… continues from exactly where it
  stopped (idempotent — the stored replacement is not created twice)
Expected persisted result: state machine lives in SQLite
Pass/fail: ☐
```

#### ROT-05 — rollback the rotation

```text
Mode: Manual UI
Requirement: rollback restores the vault value and destinations; honest
  irreversibility rules
Starting state: ROT-03 stuck at validation (old key never revoked)
Exact buttons to click: (optionally check "On rollback, also revoke the
  new key this rotation created." — leave UNCHECKED here); Roll back… ;
  Continue to password; Roll back
Expected visible result: confirm body "Roll this rotation back?
  Destinations and the vault value return to v{n} (the replacement key
  stays valid — tick \"also revoke the new key\" to revoke it)."; after:
  "Rollback finished — review the state details below."; state
  "rolled_back"
Expected persisted result: the credential's masked value equals the
  pre-rotation one; a new version row records the restore (audit-visible,
  not history rewriting)
Expected security behavior: reauthenticated; nothing destructive happened
  provider-side (mode was manual; no admin connection exists)
Cleanup: —
Pass/fail: ☐
```

#### ROT-06 — scheduling requires one completed rotation

```text
Mode: Manual UI
Requirement: schedules are gated on a proven, completed rotation
Exact navigation: Rotation → Schedules
Exact buttons to click: Set schedule (re-enables a paused one)
Exact fields to fill: Credential; Interval (days)
Exact test values: alpha-app/openai-main; 90
Expected visible result: the attempt FAILS with an error explaining a
  successfully completed rotation is required first (no schedule row
  appears) — completing one synthetically is impossible (validation needs
  a real provider), which is the honest design
Expected persisted result: "No rotation schedules."
Pass/fail: ☐
```

### Temporary access grants and injection sessions

#### ACC-01 — create a one-time grant

```text
Mode: Manual UI
Requirement: local grants bound what `run` injects
Starting state: mapping exists from ENV-03 (or create one:
  api-tracker mapping set --project alpha-app --credential
  alpha-app/openai-main --env OPENAI_API_KEY)
Exact navigation: Temporary access → Create a grant
Exact buttons to click: Create grant
Exact fields to fill: Project (whose credentials the grant may inject);
  Lifetime (minutes); One-time grant (exactly one launch); Label
  (optional)
Exact test values: alpha-app; 60; one-time CHECKED; label "manual one
  time"
Expected visible result: notice "Grant {id} created — expires …, 1
  launch(es) max. Run with it: api-tracker run --grant {id} -- <command>";
  Grants table row status badge "active", Launches "0/1"
Expected persisted result: `api-tracker access list` shows it
Expected security behavior: the notice explicitly gives the CLI command —
  grants only bound LOCAL injection
Cleanup: consumed next
Pass/fail: ☐
```

#### ACC-02 — run under the grant; one-time used twice

```text
Mode: CLI (+ Manual UI verification)
Requirement: one-time grant consumed atomically; second use refused
Exact test values (CLI, with API_TRACKER_DIR/PASSWORD exported per 1.8):
  api-tracker run --grant <id> -- sh -c 'test -n "$OPENAI_API_KEY" && echo INJECTED'
  api-tracker run --grant <id> -- sh -c 'echo SHOULD-NOT-RUN'
Expected visible result: first run prints INJECTED (value itself never
  printed); SECOND run is REFUSED (grant used up) and prints an error —
  SHOULD-NOT-RUN never appears
Expected persisted result: Temporary access → Grants (Include expired,
  used-up, and revoked grants) shows status "used up", Launches 1/1;
  Injection sessions (Show sessions, include ended) records the session
  with command + PID, no values
Expected security behavior: the child received only the mapped variable;
  API Tracker's own env vars are scrubbed from the child
Cleanup: —
Pass/fail: ☐
```

#### ACC-03 — max launch count

```text
Mode: Manual UI + CLI
Requirement: launch counting
Exact test values: create a grant, one-time UNCHECKED, Maximum launches 2,
  lifetime 60; run the INJECTED command three times with --grant
Expected visible result: runs 1–2 succeed; run 3 refused; Grants row
  Launches 2/2, status "used up"
Pass/fail: ☐
```

#### ACC-04 — grant expiry

```text
Mode: Manual UI + CLI
Requirement: expiry window enforcement
Exact test values: grant with Lifetime (minutes) = 2, no launch limits;
  wait > 2 minutes; run with --grant
Expected visible result: run refused (expired); Grants (include inactive)
  shows status "expired"
Pass/fail: ☐
```

#### ACC-05 — per-process kill timer

```text
Mode: Manual UI + CLI
Requirement: launched processes can be time-boxed (exit 124)
Exact test values: grant with "Terminate each launched process after this
  many seconds (optional)" = 5; then:
  api-tracker run --grant <id> -- sleep 300 ; echo "exit=$?"
Expected visible result: the child is terminated after ~5 s; shell prints
  exit=124
Expected persisted result: session recorded as ended
Pass/fail: ☐
```

#### ACC-06 — active-session listing and termination

```text
Mode: Manual UI + CLI
Requirement: session listing incl. non-grant runs; SIGTERM termination
Starting state: start a long run WITHOUT a grant:
  api-tracker run --project alpha-app -- sleep 300   (leave it running)
Exact navigation: Temporary access → Injection sessions
Exact buttons to click: Show sessions; terminate (the running row);
  Send SIGTERM (confirm)
Expected visible result: the running session row (status "running", PID,
  Command "sleep 300", Grant "—"); confirm dialog "Terminate session
  process" — "Send SIGTERM to session … (pid …)? This is a local control:
  values already in the process's environment cannot be clawed back, and
  the provider credential stays valid."; then notice "SIGTERM sent to pid
  …. The provider credential stays valid."; the CLI `run` in the other
  terminal exits; Refresh sessions shows it ended
Expected security behavior: the dialog and notice both repeat the
  local-control honesty
Cleanup: —
Screenshot checkpoint: sessions table with the running row
Pass/fail: ☐
```

#### ACC-07 — end a grant with a running process

```text
Mode: Manual UI + CLI
Requirement: ending a grant refuses new launches; running processes
  surfaced, not silently killed
Starting state: new grant (no kill timer); start
  api-tracker run --grant <id> -- sleep 300
Exact buttons to click: end (grant row); End grant (confirm)
Expected visible result: warning box "Grant {id} ended." listing "session
  …: pid … still running", pointing at the Sessions list and the CLI
  `access end <id> --kill`; the sleep keeps running until terminated via
  ACC-06's flow (or exits naturally)
Expected persisted result: grant status "revoked"; new launches refused
Cleanup: terminate the session
Pass/fail: ☐
```

### Templates and stack detection

#### TPL-01 — template catalog and details (no values anywhere)

```text
Mode: Manual UI
Requirement: 9 templates with guidance, never values
Exact navigation: Templates
Exact buttons to click: Details / apply (on openai-app); Close
Expected visible result: table lists 9 templates (openai-app,
  anthropic-app, supabase-web, stripe-app, github-automation, nextjs-app,
  node-backend, python-backend, fullstack-saas); the detail box lists env
  variable NAMES with (secret)/(not secret) labels, credential-separation
  / permissions / rotation guidance — no credential value anywhere
Pass/fail: ☐
```

#### TPL-02 — apply a template (+ names-only .env.example)

```text
Mode: Manual UI
Requirement: applying creates/annotates a project and never credentials
Exact navigation: Templates → openai-app → Details / apply
Exact buttons to click: Apply template
Exact fields to fill: Project name (created if missing); Write
  .env.example into directory (optional; names only)
Exact test values: tpl-demo ; /Users/<you>/at-manual-test/tpl-demo-dir
  (mkdir it first)
Expected visible result: "Applied 'openai-app' to project 'tpl-demo'.";
  "Wrote …/.env.example."; "Next steps — credentials are only added by
  these explicit commands (each prompts for its secret):" with `key add` /
  `mapping set` commands printed
Expected persisted result: project tpl-demo exists with the template's
  environments; the .env.example on disk holds names only; NO credential
  was created (tpl-demo credential count 0)
Expected security behavior: templates cannot introduce values (test-
  enforced upstream)
Cleanup: —
Pass/fail: ☐
```

#### TPL-03 — apply never overwrites an existing example

```text
Mode: Manual UI
Exact test values: apply openai-app again to tpl-demo with the same
  directory
Expected visible result: the apply succeeds but reports the example was
  NOT overwritten (write_new semantics) — the file's mtime/content are
  unchanged
Pass/fail: ☐
```

#### TPL-04 — deterministic stack detection with evidence

```text
Mode: Manual UI
Requirement: detection = rules + stored decisions, not ML; evidence shown
Starting state: SETUP-02 wrote package.json with an "openai" dependency
Exact navigation: Templates → Detect stack
Exact buttons to click: Detect
Exact fields to fill: Or a repository directory
Exact test values: /Users/<you>/at-manual-test/alpha-repo
Expected visible result: a report box for the repo path with "Evidence:"
  lines including `[…] package.json: …openai…` and "Suggestions
  (deterministic rules + your stored decisions — not ML):" listing
  openai-app with its evidence and Confirm / Dismiss buttons
Expected persisted result: nothing stored until a decision is made
Expected security behavior: .env values never appear in evidence (names
  only); nothing executed
Pass/fail: ☐
```

#### TPL-05 — confirm/dismiss decisions are remembered

```text
Mode: Manual UI
Exact buttons to click: Confirm (openai-app suggestion); Detect again;
  Dismiss it; Detect again; checkbox Show dismissed suggestions
Expected visible result: after Confirm: notice "Confirmed 'openai-app' —
  remembered locally; manage under Learned decisions." and the suggestion
  shows "— you confirmed this earlier" (high confidence); after Dismiss it
  disappears from the default list and reappears with the checkbox marked
  "— you dismissed this earlier"; Learned decisions table lists the
  repo/template/decision rows
Pass/fail: ☐
```

#### TPL-06 — delete learned data (repo, then all)

```text
Mode: Manual UI
Requirement: the learned store is fully deletable
Exact buttons to click: Delete repo decisions (row); Delete ALL learned
  stack data
Expected visible result: "Deleted decisions for …"; then "Deleted all N
  stored decision(s)."; "No stored decisions."
Pass/fail: ☐
```

### Provider administrative connection (mocked; live variants in §L)

#### CON-01 — offline admin connect (CLI) renders in the desktop panel

```text
Mode: Mocked provider (CLI-assisted; no network, fake key)
Requirement: admin connection storage, masking, honest labels
Exact test values (CLI — `--no-verify` skips live validation):
  printf 'sk-admin-MANUAL-FAKE-000000-NOT-A-REAL-KEY' | \
    api-tracker provider connect openai --org manual-org --key-stdin --no-verify
Exact navigation: Providers → OpenAI → Administrative connection
Expected visible result: Admin key row shows a MASKED value with
  "(administrative; encrypted at rest)"; Organization "manual-org
  (user-entered label, not provider-verified)"; Last successful sync
  "never"; buttons Replace admin key… / Sync period / Sync now / Sync
  account identity / Test connection / Disconnect appear
Expected persisted result: `provider connection-status openai` matches
Expected security behavior: the key is never displayed after storage;
  grep of the vault directory finds no plaintext key
Cleanup: CON-04 disconnects
Pass/fail: ☐
```

#### CON-02 — live test / sync with the fake key fails honestly

```text
Mode: Mocked provider + network (fake key, real endpoint)
Requirement: rejected admin keys mark the connection invalid; alerts raise
Starting state: CON-01; internet available
Exact buttons to click: Test connection → Test connection (reauth); then
  Sync now
Exact test values: manual-master-passphrase-01
Expected visible result: the test reports a provider rejection; Sync now
  fails with a rejection error; Status row shows the failure and Last
  failed sync is set; Last error filled
Expected persisted result: Alerts → Run checks now raises
  provider_connection_invalid (and/or provider_sync_failed); nothing was
  stored (no usage rows appear)
Expected security behavior: error text carries status only — never the key
Cleanup: resolve alerts after CON-04
Pass/fail: ☐
```

#### CON-03 — offline sync attempt changes nothing

```text
Mode: Mocked provider (offline)
Requirement: offline syncs fail safely
Starting state: CON-01; NOW TURN OFF Wi-Fi
Exact buttons to click: Sync now
Expected visible result: a network-unavailability error; no partial data
Expected persisted result: usage records unchanged; previously stored data
  still viewable (Usage screen renders)
Cleanup: Wi-Fi back on
Pass/fail: ☐
```

#### CON-04 — disconnect (reauth)

```text
Mode: Manual UI
Requirement: disconnecting deletes the encrypted key; synced data remains
Exact buttons to click: Disconnect; Disconnect (reauth)
Exact test values: manual-master-passphrase-01
Expected visible result: reauth dialog "Remove the administrative
  connection"; notice "Disconnected. Previously synced data remains
  viewable offline."; panel returns to "Not connected."
Expected persisted result: `provider connection-status openai` reports not
  connected
Expected security behavior: removal reauthenticated; ciphertext deleted
Pass/fail: ☐
```

### Settings, auto-lock, restart, offline

#### SET-01 — settings persist and drive behavior

```text
Mode: Manual UI
Requirement: settings save + clipboard-delay behavior
Exact navigation: Settings
Exact buttons to click: Save settings
Exact fields to fill: Clear the clipboard after copying (seconds, 0
  disables)
Exact test values: 5
Expected visible result: "Settings saved."
Expected persisted result: `api-tracker settings show` prints
  clipboard_clear_seconds = 5; re-run CRD-11 → notice now says "about 5
  seconds" and the clipboard clears in ~5 s
Cleanup: set back to 30 and Save settings
Pass/fail: ☐
```

#### VLT-07 — auto-lock after inactivity

```text
Mode: Manual UI
Requirement: inactivity auto-lock (desktop) — same setting expires CLI
  sessions
Exact navigation: Settings
Exact test values: Auto-lock after inactivity (minutes, 0 disables) = 1;
  Save settings; do NOTHING for ~90 seconds
Expected visible result: the app flips to "Unlock vault" by itself (within
  the poll interval after the minute elapses); any in-flight action would
  fail with the vault-locked error
Expected persisted result: relock is clean; unlocking restores everything
Expected security behavior: background monitor timer does NOT keep the
  vault awake (it never counts as activity)
Cleanup: unlock; set auto-lock back to 15; Save settings
Pass/fail: ☐
```

#### VLT-10 — restart + offline reopening of stored data

```text
Mode: Manual UI
Requirement: application restart; offline reopening of stored data
Exact test values: quit the app (Cmd-Q); TURN OFF Wi-Fi; relaunch with the
  same API_TRACKER_DIR; unlock
Expected visible result: everything stored renders offline: projects,
  credentials (masked, statuses), alerts, usage totals, pricing records,
  scan suppressions, rotation history, grants, exports table
Expected persisted result: no data loss across restart
Expected audit/alert result: —
Expected security behavior: no network is needed to read local data
Cleanup: Wi-Fi back on
Pass/fail: ☐
```

### Backups, master-password change, and the restore endgame

Run these LAST — the restore replaces the live vault.

#### BCK-01 — create an encrypted backup

```text
Mode: Manual UI
Requirement: backup creation (reauthenticated; separate backup password)
Exact navigation: Backup → Create
Exact buttons to click: Create; Create encrypted backup
Exact fields to fill: Backup file path; Master password
  (reauthentication); Backup password (protects this file; can differ from
  the master password); Confirm backup password; checkbox Overwrite the
  file if it exists (leave OFF)
Exact test values: /Users/<you>/at-manual-test/backup-1.json;
  manual-master-passphrase-01; manual-backup-passphrase-01 (twice)
Expected visible result: "Backup created. Restoring will require BOTH this
  backup password and the master password in use when the backup was
  made."; info line "{n} project(s), {m} credential(s), created {t}"
Expected persisted result: backup-1.json exists, mode 600; `grep -c
  MANUAL-TEST backup-1.json` finds no plaintext values (encrypted payload)
Expected security behavior: reauthenticated; the permanent-loss warning
  box is visible on the screen
Cleanup: —
Pass/fail: ☐
```

#### BCK-02 — verify

```text
Mode: Manual UI
Exact navigation: Backup → Verify
Exact test values: same path; manual-backup-passphrase-01
Expected visible result: "The backup decrypts and validates correctly." +
  the counts line
Pass/fail: ☐
```

#### BCK-03 — wrong backup password

```text
Mode: Manual UI
Requirement: backup wrong password
Exact test values: same path; wrong-backup-passphrase-00
Expected visible result: verification fails with an auth error ("incorrect
  password"-class); nothing changes
Pass/fail: ☐
```

#### BCK-04 — tampered backup detected

```text
Mode: Manual UI + CLI
Requirement: AEAD tamper detection
Starting state: make a corrupted COPY:
  python3 - <<'EOF'
  import pathlib
  p = pathlib.Path.home()/ 'at-manual-test/backup-1.json'
  t = pathlib.Path.home()/ 'at-manual-test/backup-tampered.json'
  data = bytearray(p.read_bytes())
  data[len(data)//2] ^= 0x01     # flip one bit mid-payload
  t.write_bytes(bytes(data))
  EOF
Exact navigation: Backup → Verify
Exact test values: …/backup-tampered.json; manual-backup-passphrase-01
Expected visible result: verification FAILS (authentication/corruption
  error); never a success on tampered input
Cleanup: rm ~/at-manual-test/backup-tampered.json
Pass/fail: ☐
```

#### BCK-08 — create refuses to overwrite silently

```text
Mode: Manual UI
Exact navigation: Backup → Create (same path as BCK-01, overwrite OFF)
Expected visible result: error (file exists); with "Overwrite the file if
  it exists" CHECKED, the create succeeds
Pass/fail: ☐
```

#### VLT-08 — change the master password

```text
Mode: Manual UI
Requirement: master-password change re-wraps the vault key
Exact navigation: Settings → Change master password
Exact buttons to click: Change master password
Exact fields to fill: Current master password; New master password (12+
  characters; a long passphrase is strongest); Confirm new master password
Exact test values: manual-master-passphrase-01;
  manual-master-passphrase-02 (twice)
Expected visible result: "Master password changed. Create a fresh backup
  when convenient." (screen also explains earlier backups still open with
  the OLD password)
Expected persisted result: Lock vault → unlocking with -01 FAILS
  ("incorrect password"); -02 unlocks; reauth dialogs now require -02
Expected security behavior: no data re-encryption (fast); old password
  dead for the live vault
Cleanup: — (restored by BCK-06)
Pass/fail: ☐
```

#### VLT-09 — change with a wrong current password

```text
Mode: Manual UI
Exact test values: current wrong-master-passphrase-00; new
  manual-master-passphrase-01 (twice)
Expected visible result: "incorrect password" error; nothing changes (-02
  still unlocks)
Pass/fail: ☐
```

#### BCK-05 — restore collision (unforced restore refused)

```text
Mode: Manual UI
Requirement: restore never silently overwrites a vault
Exact navigation: Backup → Restore
Exact test values: …/backup-1.json; manual-backup-passphrase-01; checkbox
  "Replace the existing vault (it is renamed aside, not deleted)"
  UNCHECKED
Exact buttons to click: Restore backup
Expected visible result: an error that a vault already exists; the current
  vault (with password -02) is untouched
Pass/fail: ☐
```

#### BCK-06 — forced restore; backup-time password applies

```text
Mode: Manual UI
Requirement: restore replaces the vault after explicit confirmation; the
  restored vault uses the master password from BACKUP time
Exact navigation: Backup → Restore
Exact test values: …/backup-1.json; manual-backup-passphrase-01; checkbox
  CHECKED
Exact buttons to click: Restore backup; Replace and restore (confirm)
Expected visible result: confirm dialog "Replace the current vault?" —
  "The existing database is renamed aside (not deleted), and the vault
  will lock. You will unlock the restored vault with the master password
  from when the backup was created."; then "Backup restored. The vault is
  now locked; unlock it…" and the app returns to Unlock vault
Expected persisted result: unlocking needs manual-master-passphrase-01
  (the -02 change happened AFTER the backup — this proves the semantics);
  all data from backup time is present (projects, credentials, versions,
  alerts, suppressions, grants, rotations); `ls ~/at-manual-test/vault/`
  shows a vault.db.replaced-<timestamp> aside file
Expected audit/alert result: —
Expected security behavior: two explicit gates (checkbox + confirm) before
  replacement; the old database is renamed, not deleted
Cleanup: —
Screenshot checkpoint: the Replace the current vault? dialog
Pass/fail: ☐
```

#### BCK-07 — future database schema rejected

```text
Mode: CLI (guards the shared core; desktop shows the same error at unlock)
Requirement: newer-schema vaults are refused loudly
Exact test values:
  cp -R ~/at-manual-test/vault ~/at-manual-test/vault-future
  sqlite3 ~/at-manual-test/vault-future/vault.db 'PRAGMA user_version=99;'
  api-tracker --data-dir ~/at-manual-test/vault-future project list
Expected visible result: a clear "schema … newer than this build" error
  (SchemaTooNew) — the vault is NOT opened read/write
Expected persisted result: the copy is unchanged; the real vault untouched
Cleanup: rm -rf ~/at-manual-test/vault-future
Pass/fail: ☐
```

#### CLEAN-01 — final cleanup

```text
Mode: CLI
Requirement: reset only test data (Part 1.7)
Exact test values: the two rm -rf commands from Part 1.7 (⚠️ read the
  deletion warning there first) + the keychain check
Expected visible result: workspace gone; your real vault untouched (verify
  ~/Library/Application Support/api-tracker unchanged if it exists)
Pass/fail: ☐
```

---

## §A — Covered by automated tests (do not re-test manually)

These behaviors are exhaustively proven by the automated suites on this
commit (`API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core -p
api-tracker-cli`, frontend `npm test`, and `bash scripts/smoke.sh` — 126
checks, verified green). Re-test manually only if a UI change touches
them:

| Behavior | Where proven |
| --- | --- |
| Rate-limit responses (429 + Retry-After, bounded retries) | `crates/core/tests/openai_sync.rs` fixtures |
| Overlapping provider sync reconciliation (no double-count) | `openai_sync.rs`, `anthropic_sync.rs` |
| Unknown/mixed currency handling (non-USD excluded from USD totals, note shown) | `openai_sync.rs` money tests |
| Unmatched provider key / unmapped provider project alerts | `openai_sync.rs` / `observe` tests (live variant: §L) |
| Provider-data-stale flagging (3-day threshold) | core tests; needs wall-clock days manually |
| Reported-vs-estimated cost separation with real provider rows | sync fixtures (live variant: §L) |
| Ciphertext corruption, wrong AAD, swapped rows | `vault_lifecycle.rs`, `credentials.rs` |
| Backup format v1 restore + forward migration; future-format/schema backup refusal | `migration_safety.rs`, `backup_session.rs` |
| Injection env hygiene (API_TRACKER_* scrubbed from children) | smoke checks + `cli.rs` |
| Secret-leak regressions (logs, errors, JSON, DB plaintext) | `security_residuals.rs`, smoke |
| Password policy boundaries (11 vs 12 chars) at the CLI | smoke (manually covered in VLT-02 for the UI) |
| Windows Credential Manager / Linux Secret Service adapters | windows-latest CI job; `CommandRunner` fixtures |
| WAL truncation, 0600 file modes, orphan sweeps | `security_residuals.rs`, smoke |
| Terminal-escape sanitization of provider-influenced CLI output | CLI tests |

## §L — Optional live verification (real accounts; opt-in)

Each script builds its own throwaway vault, prompts for the credential
hidden (never as an argument, never stored outside the throwaway vault),
prints exactly what it will do, and cleans up after itself. **Never paste a
credential into a file, prompt, chat, or command line.** Build the release
CLI first (`cargo build --release -p api-tracker-cli`) — each script also
does this itself. None of these run in CI.

After a live run, inspect the results in the desktop app by pointing it at
the throwaway vault *before the script exits* — or simpler, re-run the
equivalent flows via the Administrative connection panel with your real
key in your isolated manual-test vault, then Disconnect and revoke the key
at the provider.

### L-01 `bash scripts/live_verify_openai.sh`

- Credential: an OpenAI **Admin API key** (console → Settings →
  Organization → Admin keys). Privileges: organization-wide **read**.
- Reads performed: `provider connect` validation
  (GET /v1/organization/projects), 7-day usage + costs sync, project/key
  metadata, `usage report`. **Writes: none. Charges: none** (admin
  endpoints are free).
- Cleanup: unsets the key variable and deletes the throwaway vault on
  exit; the printed reminder tells you to revoke the key at
  platform.openai.com/settings/organization/admin-keys if it was created
  for the test.
- Expected output: connection status (connected, last success set),
  provider keys table with redacted values and link suggestions, provider
  projects with month-to-date reported cost, a usage report labeled with
  attribution levels.
- Desktop inspection: Providers → OpenAI → Administrative connection
  (status/keys/projects tables), Usage screen records with source
  provider, attribution `provider_key`/`provider_project` until you
  confirm a link.
- Expected local records: usage + cost rows for the last 7 days in the
  throwaway vault only.

### L-02 `bash scripts/live_verify_anthropic.sh`

- Credential: an Anthropic **Admin key** (`sk-ant-admin…`). Read-only run;
  the script never disables/archives anything.
- Reads: GET /v1/organizations/me, 7-day usage (per key × workspace ×
  model) and cost (workspace level, cents) reports, workspace/key
  metadata incl. provider-reported expirations. **Writes: none. Charges:
  none.**
- Cleanup/output/inspection: as L-01 (Anthropic panel; expirations appear
  on linked credentials as "Expires (provider-reported)").

### L-03 `bash scripts/live_verify_github.sh`

- Credential: a **fine-grained PAT with only Plan: read** (classic PATs
  work for scopes/expiration; billing is then honestly reported as
  rejected).
- Reads: GET /user validation (records the token-expiration header),
  X-OAuth-Scopes metadata, Enhanced Billing 7-day usage. **Writes: none.
  Charges: none.**
- Expected: `key validate` valid; `key status` shows provider-reported
  expiration when the token has one; `key permissions --sync` exact scopes
  (classic) or the honest not-enumerable message (fine-grained); billing
  sync account-level quantities/units.
- Desktop inspection: the credential's detail (Validate / Sync
  permissions / provider-reported expiry) after adding the token to a
  test project yourself; Usage records show units verbatim (e.g.
  minutes).

### L-04 `bash scripts/live_verify_stripe.sh`

- Credential: a **test-mode secret key** or read-only restricted key
  (Balance: read, Events: read).
- Reads: GET /v1/balance validation (reports live/test mode), metadata,
  7-day Events sync aggregated to daily counts. **Writes: none. Charges:
  none — no payment object is ever created.**
- Expected: validation valid; usage report rows with unit `events`,
  account-level attribution.

### L-05 `bash scripts/live_verify_aws.sh` (the only one that can cost money)

- Credential: an IAM key scoped to `secretsmanager`
  Create/Put/Get/Describe/Delete/List on `api-tracker-live-verify-*`.
- Actions (shown first; requires typing `yes`): ListSecrets (read),
  CreateSecret `api-tracker-live-verify-<random>` with a RANDOM FAKE
  value, GetSecretValue read-back verification, DeleteSecret with the
  standard **30-day recovery window** (never
  ForceDeleteWithoutRecovery). **Max expected cost: under $0.05.**
- Cleanup: schedules deletion itself; on failure it prints the exact
  `aws secretsmanager delete-secret` command — run it.
- Expected: destination test OK, sync plan executes with value read-back
  verification, drift check in sync, delete-secret confirmation.

### L-06 `bash scripts/live_verify_github_actions.sh`

- Credential: PAT with **Secrets read/write on ONE throwaway repo**.
- Actions (typed `yes` gate): read the repo public key, PUT one Actions
  secret `API_TRACKER_LIVE_VERIFY_<random>` (sealed-box, FAKE value),
  existence verification (GitHub never returns values), DELETE it.
  **Charges: none.**
- Cleanup warning printed if deletion fails (delete under repo Settings →
  Secrets → Actions).

### L-07 `bash scripts/live_verify_vercel.sh`

- Credential: access token; a **throwaway Vercel project** (a variable
  change affects its next deployment).
- Actions (typed `yes` gate): GET the project, POST one encrypted env var
  `API_TRACKER_LIVE_VERIFY_<random>` (FAKE value, development target
  only), existence verification, DELETE it. **Charges: none.**

Live-only manual follow-ups (need a real admin connection in YOUR test
vault, not the script's throwaway): provider key **confirm link /
unlink** attribution changes (Providers panel), Sync account identity,
rotation completion via `api_create` (OpenAI/Supabase), test-key creation
and provider-side revocation (Credential detail), unmatched-key /
unmapped-project alerts, provider-data-stale after 3 quiet days.

## §Order — recommended execution order and condensed checklist

One isolated vault, destructive steps last. Keep the two local servers
(SETUP-03) running from NTF/DOC onwards.

1. **Setup:** SETUP-01, SETUP-02, SETUP-03
2. **Vault gate:** VLT-01, VLT-02, VLT-03, VLT-04, VLT-05, VLT-06
3. **Projects & credentials:** PRJ-01, PRJ-02, PRJ-03, PRJ-04,
   CRD-01, CRD-02, CRD-03, CRD-04, CRD-05, CRD-06, CRD-07
4. **Project locks:** PRJ-05, PRJ-06, CRD-19, PRJ-07
5. **Sensitive actions:** CRD-08, CRD-09, CRD-10, CRD-11, CRD-12, CRD-13,
   CRD-14, CRD-15, CRD-16, CRD-17, CRD-18
6. **Catalog & doc watches:** PRV-01, PRV-02, DOC-01, DOC-02, DOC-03,
   DOC-04
7. **Usage & pricing:** USE-01, USE-02, USE-03, USE-04, USE-05, USE-06,
   USE-07, PRC-01, PRC-02, PRC-03, PRC-04, PRC-05
8. **Alerts & webhooks:** ALR-01, ALR-02, ALR-03, NTF-01, NTF-02, NTF-03,
   NTF-04, NTF-05
9. **Scanning & hooks:** SCN-01, SCN-02, SCN-03, SCN-04, SCN-05, SCN-06,
   SCN-07, SCN-08, SCN-09
10. **.env governance:** ENV-01, ENV-02, ENV-03, ENV-04, ENV-05, ENV-06,
    ENV-07, ENV-08, ENV-09
11. **Destinations & sync plans:** DST-01, DST-02, DST-03, DST-04, SYN-01,
    SYN-02, SYN-03, SYN-04, SYN-05, DST-05, DST-06, DST-07, DST-08
12. **Rotation:** ROT-01, ROT-02, ROT-03, ROT-04, ROT-05, ROT-06
13. **Temporary access:** ACC-01, ACC-02, ACC-03, ACC-04, ACC-05, ACC-06,
    ACC-07
14. **Templates:** TPL-01, TPL-02, TPL-03, TPL-04, TPL-05, TPL-06
15. **Admin connection (mocked):** CON-01, CON-02, CON-03, CON-04
16. **Settings/restart/offline:** SET-01, VLT-07, VLT-10
17. **Endgame (destructive last):** BCK-01, BCK-02, BCK-03, BCK-04,
    BCK-08, VLT-08, VLT-09, BCK-05, BCK-06, BCK-07, CLEAN-01
18. **Optional live:** L-01 … L-07 (any time, separate vaults)

**Checklist (129 manual test IDs across 126 procedures, + 7 live-verification scripts):**

SETUP-01 ☐ SETUP-02 ☐ SETUP-03 ☐ ·
VLT-01 ☐ VLT-02 ☐ VLT-03 ☐ VLT-04 ☐ VLT-05 ☐ VLT-06 ☐ VLT-07 ☐ VLT-08 ☐
VLT-09 ☐ VLT-10 ☐ ·
PRJ-01 ☐ PRJ-02 ☐ PRJ-03 ☐ PRJ-04 ☐ PRJ-05 ☐ PRJ-06 ☐ PRJ-07 ☐ ·
CRD-01 ☐ CRD-02 ☐ CRD-03 ☐ CRD-04 ☐ CRD-05 ☐ CRD-06 ☐ CRD-07 ☐ CRD-08 ☐
CRD-09 ☐ CRD-10 ☐ CRD-11 ☐ CRD-12 ☐ CRD-13 ☐ CRD-14 ☐ CRD-15 ☐ CRD-16 ☐
CRD-17 ☐ CRD-18 ☐ CRD-19 ☐ ·
PRV-01 ☐ PRV-02 ☐ DOC-01 ☐ DOC-02 ☐ DOC-03 ☐ DOC-04 ☐ ·
USE-01 ☐ USE-02 ☐ USE-03 ☐ USE-04 ☐ USE-05 ☐ USE-06 ☐ USE-07 ☐ ·
PRC-01 ☐ PRC-02 ☐ PRC-03 ☐ PRC-04 ☐ PRC-05 ☐ ·
ALR-01 ☐ ALR-02 ☐ ALR-03 ☐ NTF-01 ☐ NTF-02 ☐ NTF-03 ☐ NTF-04 ☐ NTF-05 ☐ ·
SCN-01 ☐ SCN-02 ☐ SCN-03 ☐ SCN-04 ☐ SCN-05 ☐ SCN-06 ☐ SCN-07 ☐ SCN-08 ☐
SCN-09 ☐ ·
ENV-01 ☐ ENV-02 ☐ ENV-03 ☐ ENV-04 ☐ ENV-05 ☐ ENV-06 ☐ ENV-07 ☐ ENV-08 ☐
ENV-09 ☐ ·
DST-01 ☐ DST-02 ☐ DST-03 ☐ DST-04 ☐ DST-05 ☐ DST-06 ☐ DST-07 ☐ DST-08 ☐ ·
SYN-01 ☐ SYN-02 ☐ SYN-03 ☐ SYN-04 ☐ SYN-05 ☐ ·
ROT-01 ☐ ROT-02 ☐ ROT-03 ☐ ROT-04 ☐ ROT-05 ☐ ROT-06 ☐ ·
ACC-01 ☐ ACC-02 ☐ ACC-03 ☐ ACC-04 ☐ ACC-05 ☐ ACC-06 ☐ ACC-07 ☐ ·
TPL-01 ☐ TPL-02 ☐ TPL-03 ☐ TPL-04 ☐ TPL-05 ☐ TPL-06 ☐ ·
CON-01 ☐ CON-02 ☐ CON-03 ☐ CON-04 ☐ ·
SET-01 ☐ ·
BCK-01 ☐ BCK-02 ☐ BCK-03 ☐ BCK-04 ☐ BCK-05 ☐ BCK-06 ☐ BCK-07 ☐ BCK-08 ☐ ·
CLEAN-01 ☐ ·
L-01 ☐ L-02 ☐ L-03 ☐ L-04 ☐ L-05 ☐ L-06 ☐ L-07 ☐

## Tracking cases (ADR 0022)

Previously this plan had zero gateway or tracking coverage. These cases
cover the primary workflow. Use fake credentials only.

| # | Case | Steps | Expected |
|---|---|---|---|
| T1 | First-time tracking, one provider | Fresh vault → Activity → Track API activity → pick a folder with `OPENAI_API_KEY` in `.env` and `openai` in `package.json` → Start tracking | One review screen lists OpenAI as confirmed with its evidence, shows the exact `.env` diff, and states what is never recorded. Apply reports each step. Then "Restart your app, then make one API request." |
| T2 | Verification requires real traffic | From T1, do nothing | Stays on "Waiting for traffic…". **Never** shows "Tracking verified". |
| T3 | Verification succeeds | From T2, restart the sample app and make one request | Flips to "Tracking verified" naming the provider, latency, and model when present. |
| T4 | Multiple providers in one pass | Folder with OpenAI + Anthropic keys and SDKs | Both appear pre-selected; ONE review screen; one Start tracking; both routes created. No per-provider form. |
| T5 | Unsupported provider is honest | Add `STRIPE_SECRET_KEY` and the stripe SDK | Stripe is listed as "detected, not currently supported" with the reason, its checkbox disabled, and Start tracking still enabled for the others. |
| T6 | Custom origin needs confirmation | Folder with `SUPABASE_URL` | Supabase shows a pre-filled, editable origin field and the "forwarded only to this exact address" wording. |
| T7 | Nothing detected | Empty folder | "No trackable APIs detected in this folder." plus what was scanned and how deep. Not a blank screen. |
| T8 | Refused scan root | Pick your home directory | Inline error naming the refusal, with Try again. |
| T9 | Deselect everything | Uncheck every provider | Start tracking disabled AND the reason shown. |
| T10 | Diagnosis on demand | On the waiting screen, click Run diagnostics | Ranked list; restart hint first when the gateway is healthy. |
| T11 | Docker project | Add `docker-compose.yml`, run diagnostics | Compose cause listed explicitly. |
| T12 | Attribution paused | Lock the vault, return to Activity | Banner: "Credential attribution paused — traffic is still recorded." with Resume attribution. |
| T13 | Resume attribution | Click Resume attribution, enter master password | Banner clears. |
| T14 | Stop tracking | Project card → Stop tracking… | `.env` restored to pre-tracking content; routes removed unless shared; history retained. |
| T15 | Re-run is idempotent | Run T1 again on the same folder | "already tracked" note; no duplicate rows; no second file change. |
| T16 | Load failure is visible | Simulate a backend failure for the activity fetch | Error text plus Retry — never an empty chart presented as no data. |
| T17 | Advanced still reachable | Advanced → Gateway internals | The previous Gateway view, unchanged. |

---

## U — Card-based interface and first run (ADR 0030)

Supersedes earlier cases wherever labels differ. Run against a scratch vault
(`TETHRA_DATA_DIR` pointed somewhere disposable), never a real one.

### U1 — First run, from nothing

| # | Step | Expected |
|---|---|---|
| U1.1 | Delete the scratch vault, launch Tethra | "Create encrypted vault" gate |
| U1.2 | Create the vault | Lands on **Welcome**, not an empty dashboard |
| U1.3 | Read before clicking | The scope paragraph — reads variable *names*, never values, never runs your code, nothing uploaded — is on screen **before** the picker opens (ZFT-009) |
| U1.4 | Click **Choose a project folder**, pick a repo with an `OPENAI_API_KEY` in `.env` | Native picker; then "Here is what is in `<folder>`" with a card per detected provider |
| U1.5 | Check the disclosure | **What Tethra will change** is expanded already, and its lines are the backend's, not a summary |
| U1.6 | Click **Start tracking** | Lands on the project page with the folder linked and live activity mounted |
| U1.7 | Count it | ≤5 clicks from vault creation, zero terminal commands, no separate "create project" step |

### U2 — First run, declining

| # | Step | Expected |
|---|---|---|
| U2.1 | On Welcome, click **I'll do this later** | Dashboard, with an empty state offering **Choose a project folder** |
| U2.2 | Reach the review screen, then click **Not now** | The project that was created is kept and opened; its page offers the same picker. Nothing is orphaned |
| U2.3 | Relaunch with at least one project | Opens on Activity, not Welcome |

### U3 — Dashboard

| # | Step | Expected |
|---|---|---|
| U3.1 | With traffic recorded, open Activity | Four tiles: Requests, Tracked projects, Open alerts, Observed cost — each with its sub-line |
| U3.2 | Check the chart | Request volume renders; hovering a point shows its bucket and value |
| U3.3 | Stop the gateway, force an activity failure | Error text plus Retry. Never an empty chart presented as no data |
| U3.4 | Run traffic through a provider with no usage shape (Cohere, Gemini, LangSmith, Replicate, Supabase) | Cost tile says "locally observed only" and shows **no** `$0.0000`; the "lower bound" caveat is absent |
| U3.5 | Leave a gap in traffic, then resume | The line breaks across the gap for token/latency/cost metrics on the project page; requests may legitimately show zero |
| U3.6 | Lock the vault so alerts cannot be read | Open alerts tile says "could not be read", not `0` |
| U3.7 | Click a project card | Opens that project |
| U3.8 | Check the feed | Attribution rows read as sentences; no raw token (`matched_fingerprint`, `unavailable`) appears anywhere |

### U4 — Card grids

| # | Step | Expected |
|---|---|---|
| U4.1 | Projects | One card per project with sparkline, credential count, requests, errors, last request as relative time — not a raw ISO timestamp |
| U4.2 | A project with no traffic | Card reads "No traffic observed in this window"; its dot is **not** coloured as a fault |
| U4.3 | A password-locked project | "Password-locked", amber dot |
| U4.4 | Providers | All 21 manifests as cards with brand-coloured marks |
| U4.5 | Search "STRIPE_SECRET" | Filters to Stripe; the "N of M providers" count updates |
| U4.6 | A provider with no documented expiry | Says so explicitly; no card implies a capability its manifest does not declare |
| U4.7 | Project → Credentials | Cards with provider mark, status badge, masked value. **No unmasked secret anywhere** |

### U5 — Detected credentials are not a dead end

| # | Step | Expected |
|---|---|---|
| U5.1 | On a linked project, find a pending detected credential | Row offers **Store this key** · Ignore · Managed elsewhere |
| U5.2 | Click **Store this key** | Credential form opens with provider, name and environment pre-filled and the value field **empty** |
| U5.3 | Paste a fake value and save | Credential stored; the detection row becomes "completed" without a second manual step |

### U6 — Accessibility and layout

| # | Step | Expected |
|---|---|---|
| U6.1 | Tab through a card grid | Every card is reachable and shows a visible focus ring |
| U6.2 | VoiceOver on the dashboard chart | Announces the metric, the bucket count and the peak; the visually-hidden data table is readable |
| U6.3 | VoiceOver on a project sparkline | Announces range, total and peak |
| U6.4 | System → Reduce motion on | No card lift, no button transform, no chart animation |
| U6.5 | Resize the window to ~700px, then ~560px | Grids collapse; the content pane never scrolls sideways |
| U6.6 | Check every status dot | Each sits beside a word — colour never carries the meaning alone |
