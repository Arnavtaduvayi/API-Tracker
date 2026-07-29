# Desktop UI Map

> **Naming note (2026-07-24):** API Tracker was renamed **Tethra** after this
> report was produced. This map remains the verified record of the
> **pre-rename baseline `7d81090`**: the window/app title is now "Tethra",
> native notifications are titled "Tethra", the preferred CLI command is
> `tethra` (legacy `api-tracker` still works), and preferred env vars are
> `TETHRA_*` (legacy `API_TRACKER_*` still honored). Baseline content below
> is intentionally unchanged; see docs/rebrand/TETHRA_REBRAND_PLAN.md.

An exact, button-by-button inventory of the API Tracker desktop application,
verified against the source on `main` (commit `7d81090`, 2026-07-18; this is
the current `main`, six commits ahead of the `v0.3.0-alpha-rc1` tag — the
gap-closure merge added the Pricing and Templates screens and three
destination live-verify scripts).

Companion documents:

- [MANUAL_UI_TEST_PLAN.md](MANUAL_UI_TEST_PLAN.md) — launch instructions and
  the numbered test cases (start there to run the app).
- [MANUAL_TEST_DATA.md](MANUAL_TEST_DATA.md) — all synthetic test values.

Every label in this document is quoted verbatim from the component source
files listed per screen. The desktop app is a Tauri v2 shell
(`apps/desktop/src-tauri/src/main.rs`, window title **"API Tracker"**,
1050×760) over a React UI (`apps/desktop/src/`); every command is a thin
wrapper over the same `api-tracker-core` crate the CLI uses, against the
same SQLite vault in the same data directory.

## 1. Sitemap

There is no URL router; navigation is a view enum in `App.tsx`. Top-level
destinations are the 16 nav buttons plus the two vault gate screens.

```text
API Tracker (window)
├── Create your vault            (first run only — no vault exists yet)
├── Unlock vault                 (vault exists, locked; also after auto-lock)
└── Main navigation (vault unlocked) — top bar, left to right:
    ├── Projects
    │   ├── Projects (list)
    │   ├── New project / Edit project (form)
    │   ├── Project detail
    │   │   └── password dialogs: Set / Unlock / Remove project password
    │   ├── Add credential / Edit credential (form)
    │   │   └── reuse dialog: "This value is already in your vault"
    │   └── Credential detail
    │       ├── Sensitive actions (reveal / copy / replace / delete)
    │       ├── Provider actions (validate / metadata / permissions / diff)
    │       ├── Lifecycle (timeline, version history)
    │       ├── Provider-side lifecycle (test key, revoke at provider)
    │       ├── Manual tracking marks
    │       └── Status findings
    ├── Providers
    │   ├── Provider catalog (list)
    │   └── Provider detail
    │       ├── official links (system browser)
    │       ├── Administrative connection (OpenAI & Anthropic only)
    │       │   ├── connect / replace / sync / account / test / disconnect
    │       │   ├── Provider-side API keys (link / unlink)
    │       │   └── Provider-side projects
    │       ├── Capabilities (honest matrix)
    │       ├── Documentation watches
    │       └── Docs change history
    ├── Scan            (repository scan, pre-commit hook, suppressions)
    ├── Env files       (discover, preview/import, .env.example, drift, exports)
    ├── Destinations    (catalog, configured, attachments, delete-at-destination)
    ├── Sync plans      (generate dry run, review, execute, rollback)
    ├── Rotation        (plan, approve, advance, rollback, schedules)
    ├── Temporary access(grants, injection sessions, terminate)
    ├── Alerts          (run checks, acknowledge, resolve)
    ├── Notifications   (webhook channels, delivery history)
    ├── Usage           (usage & cost, records, budget, activity)
    ├── API activity    (runtime observability: sessions, services, certificate, diagnostics — metadata only)
    ├── Pricing         (records, overrides, import/export)
    ├── Templates       (catalog, apply, stack detection, learned decisions)
    ├── Backup          (create, verify, restore)
    ├── Settings        (thresholds, timers, change master password)
    └── Lock vault      (right-aligned button, locks immediately)
```

Screen count: **18 top-level screens** (16 nav destinations + the 2 vault
gate screens); **25 distinct screens/views** counting the nested
project/credential/provider forms and detail pages.

## 2. Global behavior (App.tsx)

- **Source:** `apps/desktop/src/App.tsx`, `apps/desktop/src/api.ts`,
  errors from `apps/desktop/src-tauri/src/main.rs` (`ErrDto {code,message}`).
- **Vault state machine:** no vault → *Create your vault*; locked →
  *Unlock vault*; unlocked → main navigation. State polls every 30 s.
- **Top bar** (only while unlocked): brand text **API Tracker**, then
  link-style buttons, exact labels: **Projects · Providers · Scan ·
  Env files · Destinations · Sync plans · Rotation · Temporary access ·
  Alerts · Notifications · Usage · API activity · Pricing · Templates ·
  Backup · Settings**, and right-aligned **Lock vault**.
- **Auto-lock:** enforced by the backend on every command after
  `auto_lock_minutes` (default 15) of inactivity. Any command then fails
  with code `vault_locked`, which flips the UI to *Unlock vault*
  (view resets to Projects). The 30 s status poll also locks the UI
  visibly. `0` disables.
- **Background monitor:** while unlocked and
  `monitor_interval_minutes` > 0 (default 30), a timer runs the full
  monitor cycle (local rules + due documentation checks + webhook
  delivery). It does **not** count as activity (auto-lock still fires).
  New alerts of medium+ severity raise one native notification: title
  **"API Tracker"**, body `N new alert(s) — top severity: {sev}. Open
  Alerts for details.` (asks for OS notification permission on first use).
- **Startup failure:** `Startup error: {message}` under an `API Tracker`
  heading.
- **Dialogs:** native `window.confirm`/`prompt` do not work under the macOS
  WKWebView, so every confirmation is an in-app `<dialog>`
  (`ConfirmDialog.tsx`); every reauthentication is the shared
  **ReauthDialog** (`ReauthDialog.tsx`): text "Confirm your master password
  to continue.", field **Master password**, buttons *{action}* / **Cancel**;
  a wrong password shows the error inside the dialog and keeps it open.
- **Offline behavior:** local screens are unaffected. Network buttons
  (Validate, Sync now, check now, destination test, webhook test, sync-plan
  execute against network kinds) surface a connectivity error and change
  nothing; previously synced data stays viewable.

---

## 3. Screens

### 3.1 Create your vault (first run)

| | |
| --- | --- |
| Reached by | launching the app with no vault in the data directory |
| Page title | `Create your vault` |
| Component | `components/VaultSetup.tsx` |
| Purpose | create the encrypted vault and set the master password |
| Prerequisites | none (this *is* first run) |
| CLI equivalent | `api-tracker init` |

- Intro text: "API Tracker stores all data encrypted on this computer at
  `{data dir}`. No account, no cloud."
- Fields: **Master password (at least 12 characters; a long multi-word
  passphrase is best)** — password input, required, autofocus;
  **Confirm master password** — password, required. No placeholders.
- Validation: mismatch → "The passwords do not match." (client); < 12
  chars → backend error naming the 12-character minimum.
- Button: **Create encrypted vault** (busy label "Creating…").
- Warning box: "The master password is never stored and cannot be
  recovered. If you lose it, the vault contents are unrecoverable by
  design. Create encrypted backups regularly from the Backup screen."
- Success: switches to the main navigation (vault created and unlocked).

### 3.2 Unlock vault

| | |
| --- | --- |
| Reached by | launching with an existing vault; after Lock vault; after auto-lock; after a restore |
| Page title | `Unlock vault` |
| Component | `components/VaultUnlock.tsx` |
| Purpose | unlock with the master password |
| CLI equivalent | `api-tracker unlock` (session) or `API_TRACKER_PASSWORD` |

- Muted line: "Vault location: `{data dir}`".
- Field: **Master password** (password, required, autofocus).
- Button: **Unlock** (busy "Unlocking…").
- Error state: wrong password → "incorrect password" style error from the
  backend, shown in red; the field stays for retry.

### 3.3 Projects (list) — nav **Projects**

| | |
| --- | --- |
| Page title | `Projects` |
| Component | `components/ProjectList.tsx` |
| Purpose | list projects; entry point to everything project-scoped |
| CLI | `api-tracker project list [--archived]` |

- Buttons: **New project**. Filter: checkbox **show archived** (default
  off).
- Empty state: "No projects yet. A project is a folder for the API
  credentials of one codebase."
- Table columns: **Name** (link opens Project detail) · **Environments** ·
  **Credentials** (count) · **State** · **Description**.
- State cell values: `archived` · `password set (unlocked)` ·
  `password-locked` · `—`.

### 3.4 New project / Edit project — via **New project** / **Edit**

| | |
| --- | --- |
| Page title | `New project` / `Edit project` |
| Component | `components/ProjectForm.tsx` |
| CLI | `api-tracker project create <NAME> [--env …] [--repo …]`, `project edit` |

- Fields: **Name** (text, required, autofocus) · **Description** (text) ·
  fieldset **Environment classifications** with checkboxes `development`,
  `test`, `staging`, `production` · fieldset **Local repository paths**
  (each row: mono path + red link **remove**; add row: text input,
  placeholder `/path/to/repository`, button **Add path**) ·
  **Notes (never encrypted; do not put secrets here)** (textarea).
- Buttons: **Create project** / **Save changes** (busy "Saving…"),
  **Cancel**. Loading state (edit): "Loading…".
- Validation: name required (HTML5); duplicate names rejected by backend.

### 3.5 Project detail

| | |
| --- | --- |
| Reached by | clicking a project name |
| Page title | project name (+ " (archived)") |
| Component | `components/ProjectDetail.tsx` |
| CLI | `project show/lock/unlock/archive/restore`, `key list --project` |

- Back link: **← All projects**.
- Facts grid: **Environments · Repositories · Password lock · Created ·
  Notes**. Password lock values: `not set` / `set (unlocked this session)`
  / `set (locked)`.
- Action buttons (contextual): **Edit**; **Set project password** (only
  when no password); **Lock project** + **Remove password** (password set
  and unlocked); **Unlock project** (password set, locked); **Archive**
  (red) / **Restore**.
- Password dialog (one dialog, three titles): **Set project password** /
  **Unlock project** / **Remove project password**. Set mode shows warning
  box "This adds a second lock on top of the vault. If you lose this
  password, the credential values in this project are unrecoverable." and
  fields **Project password**, **Confirm project password**,
  **Master password (reauthentication)**; unlock/remove show only
  **Project password**. Buttons **Confirm** / **Cancel**. Mismatch → "The
  passwords do not match."
- Success notices: "Project locked." · "Project unlocked." · "Project
  archived." · "Project restored." · "Project password set. Keep it safe:
  losing it makes this project's credential values unrecoverable." ·
  "Project password removed; the vault lock still protects it."
- **Credentials** section: button **Add credential** (disabled when
  archived, with "(restore the project first)"); empty state "No
  credentials in this project yet."; table **Name** (link) · **Provider** ·
  **Environment** · **Value** (masked; references show `→ target`) ·
  **Status** (colored badge; labels from `utils.ts`: `unknown / active /
  invalid / expired / expiring soon / unused / stale / shared across
  projects / possibly exposed / manually disabled / revoked`) ·
  **Last used**.

### 3.6 Add credential / Edit credential

| | |
| --- | --- |
| Page title | `Add credential` / `Edit credential` |
| Component | `components/CredentialForm.tsx` |
| CLI | `key add --project P --name N --provider … --value-stdin`, `key update` |

- Fields: **Name (unique within the project)** (required, autofocus) ·
  **Provider** (select of the five catalog providers + **Custom…**; picking
  Custom reveals **Custom provider name**, required) · **Environment**
  (select, default `development`) · *(add mode only)* **Secret value
  (encrypted at rest; shown masked afterwards)** (password input, required,
  autocomplete off) · **Key created on (optional)** (date) ·
  **Expires on (optional)** (date) · **Documentation link (optional)**
  (url) · **Notes (never encrypted; do not put secrets here)** (textarea).
- Buttons: **Add credential** / **Save changes** (busy "Saving…"),
  **Cancel**.
- **Reuse dialog** (add mode; appears when the value already exists in the
  vault): title "This value is already in your vault"; one warning box per
  match with the classification message and "Recommendation: …"; guidance
  paragraph "Referencing the existing credential keeps one encrypted source
  of truth instead of a second copy. Creating separate provider credentials
  per project is safer still."; buttons **Reference the existing
  credential** · **Store a duplicate copy anyway** · **Cancel**.

### 3.7 Credential detail

| | |
| --- | --- |
| Page title | `{project}/{name}` |
| Component | `components/CredentialDetail.tsx` |
| CLI | `key show/status/reveal/update/remove/validate/metadata/permissions/permissions-diff/history/versions/test-create/provider-revoke` |

- Back link: **← {project name}**.
- Facts grid: **Provider · Environment · Value** (masked; references show
  "reference to {target}") **· Status** (badge) **· Key created · Expires**
  (+ "(entered by you — a local reminder)") **· Expires
  (provider-reported)** (or "not reported by the provider") **· Last
  validated · Last used · Documentation** (external link) **· Notes ·
  Added**.
- **Sensitive actions** ("Each of these asks for your master password
  again."): **Reveal value** · **Copy value** · **Replace value…**
  (non-reference only) · **Edit metadata** · **Delete…** (red).
  - Reveal: reauth dialog "Reveal credential value" → plaintext appears
    inline in a warning box with a **hide** link; auto-hides after 30 s.
  - Copy: reauth "Copy credential value" → notice "Copied. The clipboard
    will be cleared in about {N} seconds." (or "Copied to the clipboard."
    when clearing is disabled). Plaintext never enters the UI.
  - Replace dialog: title "Replace value", text "Replacing re-encrypts the
    new value and updates the reuse fingerprint. Requires your master
    password.", fields **New secret value** + **Master password**, buttons
    **Replace** / **Cancel**. Notices: "Value replaced." or "Value
    replaced. Note: the new value also exists elsewhere in the vault."
  - Delete: reauth "Delete credential" with action label **Delete
    permanently** (the reauth *is* the confirmation); returns to the
    project on success. Destructive.
- **Provider** ("These make a direct request to the provider from this
  device."): **Validate** (notice `Valid: {detail}` / `Invalid: {detail}`)
  · **Fetch metadata** (notice `Metadata ({source}): k=v, …`) ·
  **Sync permissions** (notice "Permissions synced." / "No permissions
  available.") · **Permissions diff**.
  - Permissions panel: "Permissions ({source}, {confidence} confidence)",
    normalized summary, `scopes: …`, `production-sensitive: …`.
  - Diff panel: "(fresh from {source}, {confidence} confidence — NOT
    stored)", Before (stored) / After (fresh), `+`/`−` scope lines or "No
    scope changes.", and the honest guidance: store via "Sync permissions";
    to CHANGE permissions no current provider supports a per-key API edit —
    use the provider dashboard or rotate (Rotation view).
- **Lifecycle**: **Load timeline** (table **At · Event · Detail · Source**;
  empty "No recorded lifecycle events.") · **Version history…** (reauth
  "View version history" — it reveals rotation cadence; table **Version ·
  Value (masked) · At · Note**, current row marked `current`; footer "Old
  versions exist so destination rollback works; they are encrypted like
  current values and pruned automatically.").
- **Provider-side lifecycle** (non-reference only; buttons only where the
  manifest declares the capability `implemented` — honest gating):
  - **Create test key…** (OpenAI/Supabase) or the text "This provider has
    no API key creation — create keys in its dashboard ({manage url})."
    Dialog "Create a test key": text "This creates a REAL key at
    {provider}… The expiry below is a LOCAL reminder only — the provider
    key stays valid until you revoke it."; fields **Provider-side project
    (OpenAI project id / Supabase project ref — optional)** · **Key name**
    (required) · **Local reminder lifetime (minutes — not enforced by the
    provider)** (default 60); button **Continue to password** → reauth
    "Create a real provider-side key" / action **Create real key**.
    Afterwards a warning box "What is actually enforced:" lists the
    PROVIDER-ENFORCED vs local vs advisory notes verbatim.
  - **Revoke at provider…** (red; OpenAI/Anthropic/Supabase) or "This
    provider has no API revocation — revoke keys in its dashboard…".
    Confirm dialog "Revoke at the provider": "REVOKE '{proj}/{name}' at
    {provider}? This is usually irreversible and anything still using the
    key will break." (Anthropic adds "(Anthropic has no hard delete — this
    archives the key, a soft revoke.)"); **Continue to password** → reauth,
    action **Revoke at provider**. Success notice: "Revoked at the
    provider: {detail}. The vault record is marked revoked (kept for
    history)." Destructive (provider-side).
- **Manual tracking** buttons: **Mark used now** · **Mark validated OK** ·
  **Mark validation failed** · **Mark disabled**/**Enable** ·
  **Mark revoked**/**Unmark revoked** · **Flag possibly exposed**/**Clear
  exposure flag**. The exposure flag opens a prompt dialog "Flag as
  possibly exposed" (placeholder "optional note", button **Flag**).
- **Status findings**: one card per finding — status label, "({confidence}
  confidence)", reason, "Source: …", "Recommended: …".

### 3.8 Provider catalog — nav **Providers**

| | |
| --- | --- |
| Page title | `Provider catalog` |
| Component | `components/ProviderCatalog.tsx` |
| CLI | `provider list`, `provider show <id>` |

- Intro: "Catalog with an honest capability matrix. …"
- Table: **Provider** (link) · **Secret env vars** · **Detection patterns**
  (count) · **Expiration**. Always five rows (OpenAI, Anthropic, GitHub,
  Stripe, Supabase — embedded manifests).

### 3.9 Provider detail

| | |
| --- | --- |
| Page title | provider display name |
| Component | `components/ProviderDetail.tsx` (+ `ProviderConnectionPanel.tsx`) |
| CLI | `provider show/capabilities/docs`, `provider watch-docs/check-docs/unwatch-docs/docs-history` |

- Back link **← Provider catalog**. Facts grid of official links (each a
  link-button that opens the **system browser**): **Website · API docs ·
  Manage keys · Changelog · Pricing docs · Permissions docs · Console
  login · Billing portal**, plus **Secret env vars · Key types ·
  Expiration**.
- **Administrative connection** section — OpenAI and Anthropic pages only
  (see 3.9a).
- **Capabilities**: table **Capability · Status · Note** for exactly:
  `validate credential, fetch metadata, fetch usage, read permissions,
  change permissions, create credential, disable credential, revoke
  credential, rotate credential, fetch pricing`. Status text is the honest
  support level — `implemented` / `supported, not implemented` /
  `unsupported` / `manual action required` — plus `admin credential` and
  the attribution level when applicable.
- **Documentation watches**: button **Watch official pages** (adds every
  manifest watch URL; notice "Now watching the official documentation
  pages."); empty state "No pages watched yet."; table **URL** (opens
  browser) · **Status** · **Last checked** (`never`) · **Last changed**
  (`no change seen`) · actions **check now** / **unwatch** (red). Check
  notice: "Checked: {status}. A page change does not necessarily mean a
  breaking API change." Custom URLs can be added via the CLI
  (`provider watch-docs <id> --url <URL>`) and then appear/are managed
  here.
- **Docs change history**: "…validators and outcomes only — page content is
  never stored…"; empty "No checks recorded yet."; table **When · URL ·
  Outcome · Detail**.

### 3.9a Administrative connection panel (inside OpenAI/Anthropic detail)

| | |
| --- | --- |
| Component | `components/ProviderConnectionPanel.tsx` |
| CLI | `provider connect/disconnect/test/sync/connection-status/account/keys/projects/link/unlink` |

- Heading **Administrative connection** with the elevated-key explanation
  ("…never displayed once stored…").
- Disconnected state: "Not connected." + button **Connect…**.
- Connected facts: **Admin key** (masked, "(administrative; encrypted at
  rest)") · **Organization** ("(user-entered label, not
  provider-verified)") · **Account (provider-reported)** (name/email/id/
  plan + "via {endpoint} at {time}"; only after an account sync) ·
  **Connected at** · **Last successful sync** (`never`) · **Last failed
  sync** (`never`) · **Status** (+ red badge **stale data** when older than
  `provider_stale_days`, default 3) · **Last error**.
- Buttons: **Connect…**/**Replace admin key…** · **Sync period** select
  (`since last sync (default)` / `last 7 days` / `last 30 days` /
  `last 90 days`) · **Sync now** · **Sync account identity** ·
  **Test connection** · **Disconnect** (red).
- Connect form: **Admin API key (never displayed after saving)** (password,
  required) · **Organization label (optional, for your reference)** ·
  *(replace only)* **Master password (required to replace the stored
  key)**; note "The key is validated against the provider before it is
  stored, then encrypted under your vault key."; buttons **Save
  connection** / **Cancel**.
- Reauth dialogs: **Remove the administrative connection** (action
  **Disconnect**; notice "Disconnected. Previously synced data remains
  viewable offline.") and **Run a live connection test** (action **Test
  connection**; notice "Connection test: {detail}").
- Notices: "Connected: {detail}" · "Synced {n} usage row(s) and {m}
  provider-reported cost row(s)." (+ per-sync notes list) · "Account
  identity synced from {endpoint}."
- **Provider-side API keys** table (after a sync finds keys): **Key id ·
  Name** (+ redacted value) **· Project · Records · Linked credential ·**
  actions. Unlinked rows: select "choose credential…" (pre-selects the
  suggestion when the provider's redacted value matches) + **confirm
  link**; linked rows: **unlink** (red). Notices: "Linked {id}: {n}
  record(s) re-attributed as exact-credential." / "Unlinked {id}; its
  records honestly show provider-key attribution again."
- **Provider-side projects** table: **Project · Reported cost (month) ·
  Linked usage** (`yes` / `none`) — cost is never divided among local keys.

### 3.10 Scan — nav **Scan**

| | |
| --- | --- |
| Page title | `Repository scan` |
| Component | `components/ScanView.tsx` |
| CLI | `scan [--staged|--history N] <PATH>`, `hooks install/remove/status`, `suppress add/list/remove` |

- Intro: "Scanning happens entirely on this machine. No source code or
  findings ever leave your computer."
- Fields: **Repository or directory path** (mono, placeholder
  `/path/to/repo`) · **Mode** select — `Staged changes (Git)` (default) /
  `Working tree` / `History (Git)` · *(history only)* checkbox **full
  history (every commit; can be slow on large repositories)** and **Most
  recent commits** (number, default 50) · checkbox **mark matched vault
  credentials as possibly exposed** (default checked).
- Buttons: **Scan** (busy "Scanning…") · **Check hook status** ·
  **Show suppressions**.
- Client validation: "Enter a repository or directory path." / "History
  depth must be a positive number of commits."
- Vault-match notice: "{n} finding(s) match a stored credential. Matched
  credentials were marked possibly exposed — removing a secret from a file
  does not remove it from Git history; rotate it."
- **Pre-commit hook** section (after Check hook status): "State:
  **{state}** ({hook path})"; buttons **Install** · **Install (force /
  chain)** · **Remove**. A foreign hook is preserved (chained), never
  clobbered.
- **Findings ({n})**: empty "No secrets found."; table **Confidence**
  (badge; high = red) · **Location** (`file:line`) · **Provider**
  (`unknown` for generic) · **Value** (redacted) · **In vault**
  (project/credential or —) · **suppress** link.
- Suppress prompt dialog: "Suppress this finding" — "{file}:{line} — a
  reason is required and stored locally.", placeholder "why this is not a
  real secret", button **Suppress**; empty reason → "A reason is required
  to suppress." Success: "Suppressed. Re-run the scan to confirm it is
  hidden."
- **Suppressions ({n})**: empty "No suppressions stored."; table **Key**
  (prefix) · **Path** · **Reason** · **Since** · **remove** link (notice
  "Suppression removed; future scans report this finding again.").

### 3.11 Env files — nav **Env files**

| | |
| --- | --- |
| Page title | `Env files` |
| Component | `components/EnvView.tsx` |
| CLI | `env discover/preview/import/example/drift/export/exports/cleanup/migrate` |

- Intro: "Everything here runs locally. Previews and diffs show masked
  values only; plaintext is written to disk only through the explicit,
  password-confirmed export below."
- **Discover**: **Project (its registered repositories are searched; also
  the import target)** select (defaults to the first project; "— none —"
  option) · **Extra directory to search (optional)** (placeholder
  `/path/to/repo`) · button **Discover .env files**. Error when neither is
  set: "Choose a project or enter a directory path to search."
- Files table: **File** (link, opens the per-file panel) · **Class**
  (`values`/`template`) · **Environment** · **Git** (badges: red
  `tracked — committed secrets risk` for a tracked values file; `tracked`
  / `ignored` green; `untracked` yellow; "not in a repo"; plus the note
  "in Git history — deleting the file does not remove past commits") ·
  **Vars** · **Problems**. Empty: "No .env files found."
- Per-file panel: template files → "Template file (variable names only, by
  convention) — there is nothing to import."; values files → preview table
  **Import** (checkbox, pre-checked for secret non-placeholder rows) ·
  **Variable · Value (masked) · Provider · Secret? · Placeholder? ·
  In vault · Mapped to**; buttons **Select all secrets** and
  **Import {n} variable(s)…**.
  - Import confirm dialog: "Import variables into the vault" — `Import {n}
    variable(s) into project "{name}"? Values are stored encrypted and
    mapped for injection. The file itself is not modified.` → **Import**.
    Notice: "{n} variable(s) imported or mapped. The file was not
    modified." Outcome table: **Variable · Action · Credential · Note**
    (actions such as `imported`, `mapped_existing`, skipped-placeholder).
  - **.env.example** block: proposed masked diff + button **Write
    .env.example…** (confirm dialog "Write .env.example" — "…names only —
    never values — and preserves existing entries."), or "{path} is already
    up to date." Notice: "Wrote {path} (names only, never values)."
- **Drift**: button **Check drift** (needs a project). "No drift detected."
  or table **Severity** (badge) · **Kind** · **File** · **Variable** ·
  **Credential** · **Detail** · **Recommendation**. Kinds/severities:
  `production value in dev file`, `unmapped secret` (high); `value differs
  from vault`, `same value in multiple files` (medium); `missing expected
  variable` (low); `mapping not in files` (info).
- **Exports**: "Plaintext .env files previously written by API Tracker…";
  empty "No live exports."; table **Path · Variables · Created · Expires**
  (`never (persistent)`). Buttons: **Clean up expired…** · **Clean up
  all…** (red) · checkbox **force: also delete files whose content changed
  since export (otherwise they are kept, since edits may be yours)** ·
  **Export .env…**. Cleanup confirm dialogs: "Clean up expired exports" /
  "Remove every recorded export" (both red-confirm, wording includes the
  force behavior). Notice: "{n} exported file(s) removed." + per-file
  outcomes.
- Export form: "Export mapped credentials to a plaintext .env file" — "The
  file will contain PLAINTEXT secrets. It is written atomically with
  owner-only permissions and refused when the target is tracked by Git.";
  fields **Target path** (required, placeholder `/path/to/repo/.env`) ·
  **Variables (comma-separated; empty = every configured mapping)** ·
  **Temporary lifetime in minutes (empty = persists until you delete
  it)** · checkbox **overwrite the file if it already exists**; button
  **Export…** → reauth dialog titled **"Write plaintext secrets to
  {path}"**, action **Export**. Notice: "Exported {n} variable(s) to
  {path}. {warnings}".
- Guided **migration** (`env migrate`) is CLI-only; the desktop screen
  covers discover/preview/import/example/drift/export/cleanup.

### 3.12 Destinations — nav **Destinations**

| | |
| --- | --- |
| Page title | `Destinations` |
| Component | `components/DestinationsView.tsx` |
| CLI | `destination kinds/add/list/test/remove/attach/detach/attachments/drift/delete-secret` |

- **Catalog** table (all 9 kinds): **Destination** (name + description) ·
  **Kind** · **Platforms** · **Status** · **Capabilities** — six chips
  (`read/write/delete/versioning/rollback/validation`) each labeled
  `implemented` / `not implemented yet` / `unsupported` / `unavailable on
  this platform`, plus "verify: … · plan: … · charges: …" and
  "testing: …".
- **Configured destinations**: empty "No destinations configured."; table
  **Name · Kind · Auth (masked)** (`none` for OS stores) **· Last
  verified** (`never`) **· Last error** · actions **test** / **remove**
  (red; reauth dialog "Remove destination '{name}'", action **Remove
  destination**; notice "Removed '{name}'. Secrets already stored at the
  destination are NOT deleted.").
- **Add destination…** form: **Kind** select (catalog minus the built-in
  vault/mapping/export kinds; default AWS Secrets Manager) · **Name (your
  label for this destination)** (required) · kind-specific fields:
  - AWS Secrets Manager: **Region** (required, placeholder `us-east-1`) ·
    **IAM access key id** (required) · **IAM secret access key (stored
    encrypted; write-only after saving)** (password, required).
  - GitHub Actions: **Repository owner** · **Repository name** · **Access
    token with repository secrets permission (stored encrypted; write-only
    after saving)** (password) — all required.
  - Vercel: **Project id** (required) · **Team id (optional)** · **Targets
    (comma-separated; default production,preview,development)** · **Vercel
    access token (stored encrypted; write-only after saving)** (password,
    required).
  - macOS Keychain: **Keychain account (optional; default "api-tracker")**.
  - Buttons **Add destination** / **Cancel**. Notice: "Added destination
    '{name}'. Its credential is stored encrypted and is write-only. Use
    Test to verify it." Test notice: "Test '{name}': {detail}".
- **Attachments**: "An attachment records that a credential is deployed to
  a destination under a secret name. Deploying or updating the value always
  goes through a reviewed sync plan."; empty "No attachments."; table
  **Credential · Destination · Secret name · Environment · Last synced**
  (`v{n} ({time})` / `never`) **· Drift** (badges: `in sync` / `drifted` /
  `missing` / `present (value unverifiable)` / `rolled back` / "never
  checked") · actions **detach** / **delete at destination** (both red).
  - Detach confirm: "Detach credential from destination" — "…The secret
    stored at the destination is not deleted." → **Detach**.
  - Delete-at-destination reauth: title "Delete '{secret}' AT '{dest}'",
    body "This deletes the secret at the destination itself (AWS schedules
    a 30-day recovery window; other destinations delete immediately). The
    value in the local vault is NOT touched.", action **Delete secret at
    destination**. Destructive (destination-side).
- Button **Check drift now** — notice "Drift check complete. Write-only
  destinations can only be verified for existence."
- **Attach a credential** form: **Credential** select · **Destination**
  select · **Secret name at the destination** (required, placeholder
  `OPENAI_API_KEY`) · **Environment** select (default production) →
  **Attach**. Notice: "Attached. Generate a sync plan to deploy the value."

### 3.13 Sync plans — nav **Sync plans**

| | |
| --- | --- |
| Page title | `Sync plans` |
| Component | `components/SyncView.tsx` |
| CLI | `sync plan/show/list/run/rollback` |

- Intro: "…Generating a plan writes nothing; execution requires your master
  password and explicit confirmation. Values are shown masked only."
- Form: **Credential (empty shows plans for every credential)** select ·
  **Note (why this rollout is happening, optional)** · button **Generate
  plan (dry run)**. Notice: "Plan generated (dry run). Nothing has been
  written — review the steps, then execute."
- **Plans** table: **Created** (link opens the plan) · **Credential** ·
  **Change** (`v1 → v2`) · **Status** badge (`draft`/`executed`/`partially
  failed`/`rolled back`/`stale`) · **Note**. Empty: "No plans yet."
- Plan detail: facts **Change** (masked from/to versions) · **Created** ·
  **Note** · **Affected projects**. Warning boxes: stale ("The credential's
  value changed after this plan was created. It can no longer be executed —
  generate a new plan."), partially failed ("…destinations are currently
  inconsistent. Retry the failed steps, or roll back the executed ones."),
  and **Manual steps required** list.
- Steps table: **Destination · Kind · Secret · Action**
  (`write`/`reexport`/`none`/`manual`) **· Validation · Rollback? ·
  Status** (badge + executed/verified/rolled-back timestamps) **· Detail**
  · per-step **execute**/**retry** link.
- Buttons: **Execute plan ({n} step(s))…** (or **Retry failed steps…**) ·
  **Roll back to v{n}…** (red; only when a previous version is retained) ·
  **Refresh**.
- Execute flow: confirm "Execute synchronization plan" (exact write list +
  "Requests go directly from this machine to each destination.") →
  **Continue to password** → reauth "Confirm execution with your master
  password", action **Execute**. Success "Plan executed."; failures: "{n}
  step(s) failed — the plan is {status}. Fix the cause and retry the failed
  steps, or roll back executed ones."
- Rollback flow: confirm "Roll back synchronization plan" (red) → reauth
  "Confirm rollback with your master password", action **Roll back** →
  "Rollback complete." (Rollback restores destinations, not the vault
  value.)

### 3.14 Rotation — nav **Rotation**

| | |
| --- | --- |
| Page title | `Rotation` |
| Component | `components/RotationView.tsx` |
| CLI | `rotation plan/approve/advance/rollback/complete-manual/cancel/show/list/events/provide-key`, `rotation schedule set/remove/list` |

- Intro: "…Every step needs your master password; nothing runs
  automatically."
- **Plan a rotation (dry run)**: **Credential** select · **Grace/overlap
  minutes (between deploying the new key and disabling the old)** (default
  60) · **Provider-side project (…optional, derived from the linked key
  when empty)** · **Provider-side id of the OLD key (optional, derived from
  a confirmed link when empty)** · button **List provider keys** (admin
  connection; table with **use as old key** link) · **Note (optional)** ·
  button **Plan rotation (dry run)**. Notice: "Dry run — nothing was
  created, written, or revoked. Review the plan below, then approve it."
- **Rotations** list: filter **Filter by credential**; table **Rotation**
  (id link) · **Credential** · **State** badge (planned/approved/…/
  completed/failed/manual required, + yellow **needs attention** badge when
  in-flight and idle > 24 h) · **Mode** · **Created** · **Waiting on**.
  Empty: "No rotations yet. Plan one above."
- Rotation detail: facts **Rotation id · Provider · Mode** ("API creation
  (provider admin connection)" / "manual creation (provider dashboard)")
  **· Note · Grace · Versions · Old/New key id · New value validated ·
  Old disabled · Old revoked · Created**; warning boxes for **Last error
  (the step stays retryable)** and **Manual steps**; "Waiting on: …".
- Contextual inputs: **Replacement key value (created by you in the
  provider dashboard; stored encrypted, never displayed)** (password;
  `awaiting_manual_key` only) · checkbox **Acknowledge continued use — I
  verified every consumer moved off the OLD key and want to proceed
  anyway.** (grace period with detected old-key use) · checkbox **On
  rollback, also revoke the new key this rotation created.** ·
  **Complete-manual note (what you did; recorded in the audit trail)**.
- Action buttons by state: **Approve…** (planned) · **Advance…** (any
  active state; goes straight to reauth) · **Complete manual…**
  (manual_required/grace_period) · **Roll back…** (red) · **Cancel
  rotation…** (red; planned/approved/awaiting_manual_key only — "Only
  rotations that have not changed anything yet can be cancelled.") ·
  **Refresh**. Every action confirms and then reauthenticates ("Continue to
  password" → e.g. "Confirm approval with your master password").
- Post-action notices: "Approved. Use Advance to start executing." ·
  "Rotation completed." · "Manual provider-side action is required (see the
  manual steps below)." · "Advance again when ready." · "Rollback finished
  — review the state details below." · "Rotation completed after your
  confirmed manual provider-side action." · "Cancelled (state: …)."
- **Events** table: **At · Transition · Detail**.
- **Schedules**: "A schedule is a reminder, never automation… Scheduling
  needs one manually approved, successfully completed rotation for the
  credential first."; table **Credential · Interval · Next due · Status**
  (`enabled` / `PAUSED: {reason}`) · **remove** link (confirm "Remove
  rotation schedule"); form **Credential** select + **Interval (days)**
  (default 90) + button **Set schedule (re-enables a paused one)**.

### 3.15 Temporary access — nav **Temporary access**

| | |
| --- | --- |
| Page title | `Temporary access` |
| Component | `components/AccessView.tsx` |
| CLI | `access grant/list/end/sessions/kill`, `run --grant` |

- Intro: grants bound what `api-tracker run` injects on this machine —
  "LOCAL controls… local expiry is not provider revocation."
- **Create a grant**: **Project (whose credentials the grant may inject)**
  select · per-project checkbox list **Limit to specific credentials (none
  selected = the project's configured mappings)** · **Lifetime (minutes)**
  (default 60) · checkbox **One-time grant (exactly one launch)** ·
  **Maximum launches (0 = unlimited within the window)** (hidden when
  one-time; default 0) · **Terminate each launched process after this many
  seconds (optional)** · **Budget warning threshold in dollars (optional;
  advisory only — it observes recorded usage and cannot cap provider-side
  spend)** (placeholder `e.g. 5.00`) · **Label (optional)** · button
  **Create grant**. Success notice includes the exact run command:
  `Run with it: api-tracker run --grant {id} -- <command>`.
- **Grants**: checkbox **Include expired, used-up, and revoked grants**;
  table **Grant · Project · Label · Status** (badge active/expired/
  used_up/revoked) **· Expires · Launches** (`used` or `used/max`) **·
  Proc TTL · Budget warn** · **end** link (active only). End confirm
  dialog "End access grant": "…New launches are refused immediately.
  Running processes keep running — terminate them individually from the
  Sessions list below if needed — … Ending a grant never revokes the
  provider credential." → **End grant**. After ending, a warning box lists
  recorded running PIDs and the CLI kill command.
- **Injection sessions**: "Every `run` launch is recorded (command,
  variable names, PID — never values)…"; buttons **Show sessions** /
  **Refresh sessions**, checkbox **include ended sessions**; table
  **Session · Project · Started · Status** (`running`/`ended`) **· PID ·
  Grant · Command** · **terminate** link (running rows). Terminate confirm:
  "Terminate session process" — "Send SIGTERM to session {id} (pid {p})?
  This is a local control: values already in the process's environment
  cannot be clawed back, and the provider credential stays valid." →
  **Send SIGTERM**. Notices: "SIGTERM sent to pid {p}. The provider
  credential stays valid." / "kill failed for pid {p} (already gone?)."
- Note: launching processes (`run`) is CLI-only; the desktop lists and
  terminates.

### 3.16 Alerts — nav **Alerts**

| | |
| --- | --- |
| Page title | `Alerts` |
| Component | `components/AlertsView.tsx` |
| CLI | `monitor [--offline|--status]`, `alerts list/acknowledge/resolve` |

- Buttons: **Run checks now**; filter checkbox **include acknowledged &
  resolved**.
- Monitor status line: "Checks last ran {t} · last success {t} · last
  failure {t} ({error}) — {detail}".
- Run notice: "Checked {n} credential(s): {a} new, {b} resolved, {c} open.
  Documentation checks: {d} · webhook deliveries: {e}."
- Empty state: "No alerts. Run the checks to evaluate your credentials."
- Alert cards: severity badge (critical/high red, medium yellow, low/info
  green) + title + `(acknowledged)`/`(resolved)`; detail line; "Evidence:
  …"; "Recommended: …"; links **acknowledge** and **resolve**.
- Native notification from this screen: "{n} new high-priority alert(s)".

### 3.17 Notifications — nav **Notifications**

| | |
| --- | --- |
| Page title | `Notifications` |
| Component | `components/NotifyView.tsx` |
| CLI | `notify add/list/enable/test/remove/history` |

- Intro: webhooks receive alert **metadata only**; the URL is stored
  encrypted and shown masked.
- Button **Add webhook channel…** → form: **Name** (required) · **Webhook
  URL (https; stored encrypted, shown masked afterwards)** (password-type
  input, placeholder `https://…`) · **Minimum severity delivered** select
  (`info/low/medium/high/critical`, default high) · **Add channel**.
  Validation: https required (http allowed only to
  localhost/127.0.0.1/[::1]). Notice: "Channel '{name}' added ({masked};
  floor {sev}). Use \"test\" to verify delivery."
- Channels table: **Name · URL (masked) · Floor · State**
  (`enabled`/`disabled`) **· Last delivery** (`never`) **· Last error** ·
  actions **disable**/**enable** · **test** · **remove** (red; confirm
  "Remove channel '{name}'?" — "The stored (encrypted) webhook URL is
  deleted and deliveries stop. This cannot be undone." → **Remove
  channel**). Empty: "No channels configured. Notifications are entirely
  optional."
- Test notice: "Test through '{name}': {detail}" (failures show the error
  and update the channel's last-error column).
- **Delivery history**: button **Show history**/**Refresh history**; table
  **At · Outcome** (failures highlighted); "Every delivery attempt is
  recorded — successes and failures — … URLs and secret values are never
  recorded."

### 3.18 Usage — nav **Usage**

| | |
| --- | --- |
| Page title | `Usage & cost` |
| Component | `components/UsageView.tsx` |
| CLI | `usage report/record`, `budget set/show/source`, `activity list` |

- **Scope** select with optgroups **Projects** / **Credentials** (defaults
  to the first project).
- Stale warnings: "{provider} data is stale — the last successful sync was
  {t}. Open the provider page to sync." (red, per connected provider).
- **This month** grid: **Requests · Input tokens · Output tokens ·
  Reported cost** ("(provider-reported)") **· Estimated cost** ("(estimated
  locally from token counts and a bundled price table — may differ from the
  provider's bill)") **· Attribution** (coarsest level in the data). Notes:
  "Non-USD provider costs exist ({currencies}) and are excluded from the
  USD total above." · "Some usage is not exact per-key and is not charged
  to a single credential."
- **Records**: **Source** filter (`all` / `provider-synced` / `manual`);
  table (30 most recent) **Window · Model / line item · Amount** (non-token
  units verbatim, e.g. `14 events`; else `N tokens`) **· Reported ·
  Estimated** ("(est.)") **· Attribution · Provider key/project · Source**.
  Empty: "No usage records for this scope and source."
- **Budget**: **Monthly budget (USD)** (placeholder `e.g. 25.00`; empty
  clears) + **Save budget**; **Budget cost source** select — `best
  available (reported, else estimated)` / `provider-reported only` /
  `estimated only` (notice "Budgets now use the '{v}' cost source.");
  status line "Used {$} ({estimated|provider-reported}) · projected
  month-end {$}" + red badge **over budget** when exceeded (strictly
  greater than the budget).
- **Recent activity** table: **When · Source · Kind · Detail** (25 rows).
- Manual usage recording is CLI-only: `api-tracker usage record
  --credential C --model M --input-tokens N --output-tokens N`.

### 3.19 Pricing — nav **Pricing**

| | |
| --- | --- |
| Page title | `Pricing` |
| Component | `components/PricingView.tsx` |
| CLI | `pricing list/show/set-override/remove-override/import/export/propose` |

- Intro: estimates only, never invented for unknown models,
  effective-dated.
- Filter checkbox: **Show full version history (not just currently
  effective records)**.
- Stale warning box: "{n} record(s) were last verified more than 45 days
  ago and are flagged stale. …"
- Records table: **Provider · Model · Unit · Input /1M · Cached /1M ·
  Output /1M · Per request · Effective from · Last verified · Origin**
  (`bundled`/`imported`/`override`) · trailing cell with **STALE** badge
  and, for overrides, a **Remove** button (notice "Removed override for
  {p}/{m}.").
- **Manual override** form: **Provider · Model / service · Unit**
  (`tokens`/`requests`) · tokens: **Input $/1M** (placeholder `2.50`),
  **Output $/1M** (placeholder `10`), **Cached input $/1M (optional)**;
  requests: **$ per request** (placeholder `0.01`) · **Note** (placeholder
  `negotiated rate`) · button **Save override** ("Override stored for
  {p}/{m}."). "An override wins over imported and bundled records. Stored
  estimates are not recomputed."
- **Import reviewed pricing**: paste-textarea (placeholder shows the JSON
  shape) + buttons **Validate and import** ("Imported {n} new record(s),
  replaced {m}.") and **Export all records** (fills a read-only textarea).
  Malformed/negative prices reject the whole file. `pricing propose` is
  CLI-only (writes a reviewable JSON file).

### 3.20 Templates — nav **Templates**

| | |
| --- | --- |
| Page title | `Templates` |
| Component | `components/TemplatesView.tsx` |
| CLI | `template list/show/apply/detect/confirm/dismiss/prefs` |

- Intro: "Templates seed a project… They never contain values, and applying
  one never creates credentials — the follow-up commands do, explicitly."
- Catalog table (9 templates): **Template · Providers · Secret vars ·
  Description ·** button **Details / apply** (toggles **Close**).
- Detail box: env-variable list (`(secret)`/`(not secret)`), **Credential
  separation / Permissions / Rotation** guidance; apply form **Project name
  (created if missing)** + **Write .env.example into directory (optional;
  names only)** + button **Apply template**. Notice "Applied '{id}' to
  project '{name}'."; outcome shows "Wrote {path}." and "Next steps —
  credentials are only added by these explicit commands (each prompts for
  its secret):" with the exact CLI commands.
- **Detect stack**: **Project (its registered repositories)** select or
  **Or a repository directory** input; button **Detect**; checkbox **Show
  dismissed suggestions**. Per-repo report: **Evidence:** lines
  (`[confidence] file: evidence`), **Suggestions (deterministic rules +
  your stored decisions — not ML):** each with evidence sublist and buttons
  **Confirm** / **Dismiss** ("Confirmed '{id}' — remembered locally; manage
  under Learned decisions."). "No stack signals found." / "No repositories
  to inspect." states.
- **Learned decisions**: "The complete locally stored detection history —
  nothing else is learned or kept."; table **Repository · Template ·
  Decision · At ·** button **Delete repo decisions**; bottom button
  **Delete ALL learned stack data** ("Deleted all {n} stored
  decision(s)."). Empty: "No stored decisions."

### 3.21 Backup — nav **Backup**

| | |
| --- | --- |
| Page title | `Backup and restore` |
| Component | `components/BackupView.tsx` |
| CLI | `backup create/verify/restore [--force]` |

- Mode buttons: **Create** · **Verify** · **Restore** (active one
  disabled).
- Shared field: **Backup file path** (required, placeholder
  `/path/to/api-tracker-backup.json`).
- Create: **Master password (reauthentication)** · **Backup password
  (protects this file; can differ from the master password)** · **Confirm
  backup password** · checkbox **Overwrite the file if it exists** →
  button **Create encrypted backup**. Mismatch: "The backup passwords do
  not match." Success: "Backup created. Restoring will require BOTH this
  backup password and the master password in use when the backup was
  made."
- Verify: **Backup password** → **Verify backup** → "The backup decrypts
  and validates correctly."
- Restore: **Backup password** + checkbox **Replace the existing vault (it
  is renamed aside, not deleted)** → **Restore backup**. With the checkbox
  a confirm dialog appears: "Replace the current vault?" — "The existing
  database is renamed aside (not deleted), and the vault will lock. You
  will unlock the restored vault with the master password from when the
  backup was created." → **Replace and restore** (red). Success: "Backup
  restored. The vault is now locked; unlock it with the master password
  from when the backup was created." — the app immediately returns to the
  Unlock screen.
- Info line after any success: "{n} project(s), {m} credential(s), created
  {t}". Warning box: "Losing both the backup password and the master
  password makes a backup permanently unreadable. There is no recovery
  bypass."

### 3.22 Settings — nav **Settings**

| | |
| --- | --- |
| Page title | `Settings` |
| Component | `components/SettingsView.tsx` |
| CLI | `settings show`, `settings set <KEY> <VALUE>`, `change-password` |

- "Vault location: {data dir}. All data stays on this computer."
- Numeric fields (all min 0), exact labels and hints:
  1. **Auto-lock after inactivity (minutes, 0 disables)** — "Locks the
     desktop app and expires CLI sessions." (default 15)
  2. **Warn this many days before expiration** — "Controls the 'expiring
     soon' status." (default 14)
  3. **Days before a never-used credential counts as unused** (default 30)
  4. **Days without use/validation before a credential counts as stale**
     (default 90)
  5. **Clear the clipboard after copying (seconds, 0 disables)** —
     "Best-effort: other apps may have read the clipboard meanwhile."
     (default 30)
  6. **Background monitor interval (minutes, 0 disables)** — "Runs the
     alert checks, due documentation checks, and webhook delivery while the
     vault is unlocked." (default 30)
  7. **Documentation check interval (hours, 0 disables)** — "How often
     watched documentation pages are re-checked when monitoring runs with
     network access." (default 24)
- Button **Save settings** → "Settings saved." (re-arms the monitor timer).
- Two settings exist only in the CLI: `provider_stale_days` (default 3) and
  `rollback_window_days` (default 30) via `settings set`.
- **Change master password**: "Re-wraps the vault key under the new
  password; no data is re-encrypted. Backups made before the change still
  open with the old password — consider creating a fresh backup
  afterwards." Fields: **Current master password** · **New master password
  (12+ characters; a long passphrase is strongest)** · **Confirm new master
  password** → button **Change master password**. Mismatch: "The new
  passwords do not match." Success: "Master password changed. Create a
  fresh backup when convenient."

### 3.23 API activity — nav **API activity** (feat/runtime-api-observability)

*Appended as 3.23 to preserve the existing numbering; in the top bar the
button sits between **Usage** and **Pricing**.*

| | |
| --- | --- |
| Page title | `API activity` |
| Component | `components/ApiActivityView.tsx` |
| Purpose | inspect metadata-only runtime API observability (observed services, endpoints, sessions, certificate state); observation runs are launched from the CLI, the desktop inspects |
| CLI equivalent | `api-tracker observe …` (and `api-tracker run --observe=off\|connection\|metadata`) |

- Intro (muted): "Metadata only — endpoint paths are sanitized;
  request/response bodies, header values, cookies, and query strings are
  never stored, and your traffic never leaves this device."
- Tab bar, exact labels: **Overview · Sessions · Certificate · Settings ·
  Diagnostics · Privacy**.
  - **Overview** — observed API services and their sanitized endpoints
    with request/error/latency aggregates; drill-down per service.
  - **Sessions** — recorded observation sessions (most recent 50) with
    their per-session request events.
  - **Certificate** — per-vault observation CA state (create / export /
    remove); certificate and delete actions reauthenticate through the
    shared **ReauthDialog**.
  - **Settings** — observation retention and mode preferences.
  - **Diagnostics** — compatibility results and honest visibility notes
    (e.g. QUIC/HTTP-3 bypass, certificate pinning, runtimes that ignore
    trust variables).
  - **Privacy** — the metadata-only guarantees, including "The certificate
    can be removed at any time from the Certificate tab."
- Honesty guarantee: the screen never renders request/response bodies,
  header values, query strings, or secret values — metadata only, matching
  the privacy model in `docs/observability/PRIVACY_MODEL.md`.
- Launching observation is CLI-only (`api-tracker observe`, `run
  --observe`); the desktop screen inspects and manages what was recorded.

---

## 4. Requirement → UI mapping

Columns: **Where** (screen / navigation), **Start** (the button that begins
the workflow), **Data** (see [MANUAL_TEST_DATA.md](MANUAL_TEST_DATA.md)),
**Scope** (Desktop / CLI / Shared core), **Net** (needs internet),
**Acct** (needs a real provider/destination account), **Synth** (fully
testable with synthetic data). Success/failure appearances are detailed in
the per-screen sections above and asserted per test in the test plan.

| Requirement | Where / navigation | Start | Scope | Net | Acct | Synth |
| --- | --- | --- | --- | --- | --- | --- |
| Vault creation | first-run screen | **Create encrypted vault** | shared | no | no | yes |
| Vault locking/unlocking, auto-lock | top bar / Unlock screen / Settings | **Lock vault** / **Unlock** | shared | no | no | yes |
| Master-password change | Settings | **Change master password** | shared | no | no | yes |
| Projects (create/edit/archive) | Projects → form/detail | **New project** | shared | no | no | yes |
| Project locks (second password) | Project detail | **Set project password** | shared | no | no | yes |
| Credentials (add/edit/delete) | Project detail → forms | **Add credential** | shared | no | no | yes |
| Credential reveal / copy | Credential detail | **Reveal value** / **Copy value** | desktop UI (CLI: `key reveal`) | no | no | yes |
| Credential replacement | Credential detail | **Replace value…** | shared | no | no | yes |
| Credential version history | Credential detail → Lifecycle | **Version history…** | shared | no | no | yes |
| Duplicate-key detection | Add credential (reuse dialog) | **Add credential** | shared | no | no | yes |
| Expiry states (expired/expiring soon) | credential status badges + findings | *(set Expires on)* | shared | no | no | yes |
| Provider connections (admin) | Providers → OpenAI/Anthropic → Administrative connection | **Connect…** | shared | yes (validate) | Admin key (or `--no-verify` offline via CLI) | partially |
| OpenAI usage sync | same panel | **Sync now** | shared | yes | OpenAI Admin key | no (fixtures in automated tests; live opt-in) |
| Anthropic usage sync | same panel (Anthropic) | **Sync now** | shared | yes | Anthropic Admin key | no (same) |
| GitHub billing & metadata | Credential detail (**Validate/Fetch metadata/Sync permissions**) + CLI `provider connect github --credential` | **Validate** | shared | yes | GitHub PAT | no (live opt-in) |
| Stripe Events | CLI `provider connect stripe --credential` + sync; Usage screen shows `events` units | **Sync now**/CLI | shared | yes | Stripe key (test mode) | no (live opt-in) |
| Cost estimation | Usage ("Estimated cost"), Pricing records | *(record usage)* | shared | no | no | yes |
| Provider-reported costs | Usage ("Reported cost"), records table | **Sync now** | shared | yes | Admin key | no |
| Attribution levels | Usage records "Attribution" column; provider keys table | — | shared | mixed | mixed | partially (manual rows are exact-credential) |
| Budgets | Usage → Budget | **Save budget** | shared | no | no | yes |
| Suspicious-activity alerts | Alerts (rules incl. over_budget, cost_spike, usage_after_disabled) | **Run checks now** | shared | no (local rules) | no | yes (over_budget deterministic) |
| Permission visibility | Credential detail → **Sync permissions** | **Sync permissions** | shared | yes | GitHub classic PAT (exact) / Supabase key (local format read) | no |
| Permission-change plans | Credential detail → **Permissions diff** guidance; capability matrix `manual action required` | **Permissions diff** | shared | yes (fresh read) | as above | partially (guidance text offline) |
| `.env` discovery | Env files | **Discover .env files** | shared | no | no | yes |
| `.env` import | Env files → file panel | **Import {n} variable(s)…** | shared | no | no | yes |
| `.env.example` | Env files → file panel | **Write .env.example…** | shared | no | no | yes |
| Drift detection (.env) | Env files → Drift | **Check drift** | shared | no | no | yes |
| Temporary `.env` export | Env files → Exports | **Export .env…** | shared | no | no | yes |
| Runtime injection (`run`) | **CLI only** (`api-tracker run`); sessions appear in Temporary access | CLI | CLI | no | no | yes |
| Destination adapters | Destinations | **Add destination…** | shared | network kinds: yes; macOS Keychain: no | network kinds: yes; Keychain: no | Keychain yes; network kinds fixture/live |
| Synchronization plans | Sync plans | **Generate plan (dry run)** | shared | only for network steps | only for network kinds | yes (Keychain/dry-run/stale paths) |
| Rotation | Rotation | **Plan rotation (dry run)** | shared | api_create + validation phases: yes | for API-driven modes | partially (plan/approve/cancel/manual paths offline) |
| Rotation recovery (restart) | Rotation (state persists; **Advance…** resumes) | **Advance…** | shared | as above | as above | yes (restart mid-flow) |
| Temporary access grants | Temporary access | **Create grant** | shared (run is CLI) | no | no | yes |
| Active-session listing | Temporary access → Injection sessions | **Show sessions** | shared | no | no | yes |
| Session termination | same table | **terminate** | shared | no | no | yes |
| Git working-tree scanning | Scan (Mode `Working tree`) | **Scan** | shared | no | no | yes |
| Staged scanning | Scan (Mode `Staged changes (Git)`) | **Scan** | shared | no | no | yes |
| Recent-commit scanning | Scan (Mode `History (Git)`, depth N) | **Scan** | shared | no | no | yes |
| Full-history scanning | Scan (History + **full history** checkbox) | **Scan** | shared | no | no | yes |
| Suppressions | Scan (suppress link; Show suppressions) | **suppress** | shared | no | no | yes |
| Pre-commit hook | Scan → Pre-commit hook | **Install** | shared | no | no | yes |
| Provider catalog | Providers | *(navigate)* | shared | no | no | yes |
| Documentation watches | Provider detail → Documentation watches | **Watch official pages** / CLI `--url` | shared | yes (checks; local server works) | no | yes (local server) |
| Native notifications | background monitor + Alerts | **Run checks now** | desktop | no | no | yes |
| Webhook notifications | Notifications | **Add webhook channel…** | shared | localhost works | no | yes |
| Background monitoring | App timer (Settings: monitor interval); Alerts status line | *(automatic)* | desktop (CLI: `monitor`) | optional | no | yes |
| Backups | Backup | **Create encrypted backup** | shared | no | no | yes |
| Restores | Backup → Restore | **Restore backup** | shared | no | no | yes |
| Offline operation | everything local; failed syncs change nothing | — | shared | — | no | yes |
| Templates & stack detection | Templates | **Details / apply**, **Detect** | shared | no | no | yes |
| Versioned pricing | Pricing | **Save override** / **Validate and import** | shared | no | no | yes |
| Runtime API observability (inspect) | API activity → Overview/Sessions/Diagnostics | *(navigate; runs start via CLI `api-tracker observe` / `run --observe`)* | shared (launch is CLI) | no | no | yes |
| Observation CA management | API activity → Certificate | **Certificate** tab actions (ReauthDialog for cert/delete) | shared | no | no | yes |
| Provider-account identity | Provider detail → **Sync account identity** | **Sync account identity** | shared | yes | admin/credential connection | no (OpenAI: honestly unsupported) |
| Provider-created test keys | Credential detail → **Create test key…** | **Create test key…** | shared | yes | OpenAI/Supabase admin | no |
| Provider-side revocation | Credential detail → **Revoke at provider…** | **Revoke at provider…** | shared | yes | admin connection | no |

**Features with no desktop UI** (CLI-only): `api-tracker run` (process
injection) and `mapping set/list/remove`; `env migrate` (guided plaintext
removal); `usage record` (manual usage entry); `pricing propose` (review
file); `doctor`; `suppress`-by-key without a prior scan listing; custom
doc-watch URLs (`provider watch-docs --url`); credential-reference
provider connections (`provider connect <p> --credential <c>`) for
GitHub/Stripe/Supabase sync; `key metadata`; project budget via
`budget set`'s `--credential` form is in both, but `budget show --project`
detail text is CLI; `rotation provide-key` exists in CLI (the desktop uses
the inline replacement-value field); `access end --kill` (desktop ends
grants without signalling; per-session terminate covers the kill path).

**Provider-limited by design** (the UI says so): per-key usage only where
official (OpenAI/Anthropic); GitHub/Stripe account-level; Supabase usage
declined (undocumented units); no per-key permission *changes* anywhere
(dashboard or rotation); no API-issued short-lived credentials; OpenAI has
no account-identity endpoint; Anthropic revoke is a soft archive;
GitHub/Vercel destinations verify by existence only (write-only APIs).

---

## Addendum: verification baseline

The verbatim-label baseline of this document was verified against commit
`7605142`. The **API activity** additions (sitemap entry, top-bar label,
section 3.23, and the runtime-observability mapping rows) reflect the
`feat/runtime-api-observability` branch; see the gate documents under
`docs/observability/` for the authoritative architecture, threat model,
and privacy model.

## Activity dashboard and Track API activity (ADR 0022)

Added by the zero-friction tracking milestone. The app's default view is
now **Activity**; navigation is grouped ACTIVITY / VAULT / SECURITY /
ADVANCED, with the previous Gateway view under **Advanced → Gateway
internals** and the previous API activity view as **Observation runs**.
Nothing was deleted.

### Activity (`DashboardView.tsx`) — default view

| Control | Behavior |
|---|---|
| Today / 7 days / 30 days | time-range selector for the observed-traffic panel |
| Track API activity | opens the Track flow |
| Retry (activity) | re-fetches after a visible load failure |
| Retry (tracked projects) | independent of the activity panel |
| Resume attribution | master-password dialog; appears only when attribution is paused |
| Run tracking check | ranked diagnosis for that project |
| Stop tracking… | undo: restores files, removes routes it created, keeps history |

Panels: observed-locally metrics (requests, success rate, errors,
latency p50/p95/p99, tokens, estimated cost labeled a lower bound, first
and last observed), endpoints, models, attribution states, tracked-project
cards, and a coverage-honesty footer. Every panel distinguishes loading,
empty, and error.

### Track API activity (`TrackFlow.tsx`)

| Screen | Controls |
|---|---|
| idle | Select project folder · Cancel (Try again after an error) |
| scanning | none (transient; errors render inline) |
| review | per-provider checkboxes · per-provider origin field (custom-origin providers only) · master-password field (optional) · Start tracking · Cancel |
| applying | none |
| waiting | Run diagnostics · Open dashboard |
| verified | Open dashboard |
| needs attention | Track while the app is open (only when the OS blocked the service) · Try again · Back to dashboard |

Start tracking is disabled — with the reason stated — when nothing is
selected or the diff could not be prepared.
