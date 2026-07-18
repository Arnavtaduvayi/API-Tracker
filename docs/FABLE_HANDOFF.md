# Fable Session Handoff

This document hands the repository off to a fresh session. It records exactly
what is verified working, what is planned, and what must not be repeated. It is
written to be precise: **"verified"** means exercised by a passing test or a
manual end-to-end run this session; **"planned"** means designed/labeled but not
yet implemented.

_Last updated for the milestone-3 (provider integrations) wrap-up._

---

## 1. Current branch and latest commit

- **Branch:** `feat/provider-integrations` (pushed, up to date with `origin`).
- **Latest commit:** `bb602b4` — `fix: resolve milestone-3 adversarial-review findings`.
- **Working tree:** clean (`git status` reports nothing to commit).
- **Base commits for this milestone (already on the branch):**
  - `13d9549` feat(core): provider connectors, usage, pricing, budgets, permissions, activity, injection
  - `28e834b` feat(cli): provider connect/sync, key validate/metadata/permissions, usage/budget/activity/mapping, run
  - `79205e4` feat(desktop): validate/metadata/permissions, usage/cost/budget, activity screens
  - `c625f72` ci+docs: release workflow, packaging, and public-alpha documentation
  - `bb602b4` fix: resolve milestone-3 adversarial-review findings (this session)
- **Not yet merged to `main`.** Opening the PR is a human decision (see §17).

---

## 2. Current architecture

Local-first desktop app + CLI sharing one Rust core. No hosted backend; the only
network calls are direct to selected API providers or official docs sites.

```
API-Tracker/
├── crates/core/          # api-tracker-core — ALL security-sensitive logic
│   ├── src/              # vault, crypto, db, connectors, usage, pricing, …
│   └── tests/            # integration tests (mocks + fixtures only)
├── apps/cli/             # api-tracker — Rust CLI (thin wrapper over core)
│   ├── src/*_cmd.rs      # one module per command group
│   └── tests/            # assert_cmd end-to-end CLI tests
├── apps/desktop/         # Tauri v2 desktop app
│   ├── src/              # React + TypeScript UI (minimal, no design system)
│   └── src-tauri/        # Rust Tauri commands, thin over core
├── provider-manifests/   # TOML capability manifests, embedded via include_str!
├── docs/                 # product spec, ADRs, install/packaging/support guides
└── .github/workflows/    # release CI (build matrix + checksums)
```

**Core principle:** the CLI and desktop must never duplicate business logic. Both
call into `api-tracker-core`. The desktop's `src-tauri` and the CLI's `*_cmd.rs`
are thin adapters. This is enforced by convention and ADR-0001.

---

## 3. Important file and module locations

`crates/core/src/`:
- `vault.rs` — `UnlockedVault`, the primary API surface (add/list/reveal
  credentials, provider connect/sync, usage, budgets, permissions, injection).
- `crypto.rs` — Argon2id KDF + XChaCha20-Poly1305 AEAD (via `chacha20poly1305`,
  `argon2`). No hand-rolled crypto.
- `secret.rs` — `SecretString`/`SecretBytes` (redact on Debug/Display, zeroize on
  drop).
- `db.rs` — SQLite schema + versioned migrations (`user_version` pragma).
  **Current schema version: 3.**
- `model.rs` — Project, Credential, Environment data types.
- `connectors.rs` — `Connector` trait + `for_provider()` registry. Implemented:
  GitHub, OpenAI, Anthropic, Stripe, Supabase.
- `http.rs` — `HttpClient` trait; `UreqClient` (real, ureq 3.x) + `MockHttpClient`
  (offline fixtures for tests).
- `usage.rs` — usage snapshots, attribution precision enum, cost windows.
- `pricing.rs` — bundled pricing table (micro-USD, per-million-token), overrides,
  longest-prefix model matching.
- `budget.rs` — monthly budget reports + over-budget alert.
- `permissions.rs` — normalized read/write/admin/sensitive scope model
  (GitHub scopes implemented).
- `activity.rs` — activity events + suspicious-activity rules (cost spike,
  usage-after-disabled).
- `inject.rs` — env-mapping config + process-session records (names only).
- `alerts.rs`, `monitor.rs`, `scanner.rs`, `gitrepo.rs`, `hooks.rs`,
  `docwatch.rs`, `reuse.rs`, `status.rs`, `backup.rs`, `session.rs`,
  `settings.rs`, `audit.rs`, `clock.rs`, `providers.rs`, `error.rs` — milestone
  1–2 subsystems (stable).

`apps/cli/src/`: `main.rs` (clap command tree), `ctx.rs` (env/session/unlock),
and `*_cmd.rs` per group. `run_cmd.rs` is the secure-injection command.

`apps/desktop/src/components/`: React views (see §6 for status).
`apps/desktop/src-tauri/src/main.rs`: registered Tauri commands.

`provider-manifests/*.toml`: honest capability matrices, one per provider.

---

## 4. Database and encryption design

- **Storage:** SQLite at `$API_TRACKER_DIR/vault.db` (default under the OS data
  dir). `STRICT` tables. Migrations are forward-only, tracked in `user_version`;
  `db::migrate` runs them idempotently on unlock. **Current version: 3.**
- **Milestone-3 tables (v3):** `provider_connections`, `usage_snapshots`,
  `pricing_overrides`, `credential_permissions`, `activity_events`,
  `credential_env_mappings`, `process_sessions`; plus `monthly_budget_micros`
  columns on `projects` and `credentials`.
- **Money:** integer **micro-USD** (`MICROS_PER_USD = 1_000_000`) everywhere — no
  floats at rest. Pricing is per-million-tokens in micros.
- **Encryption:** master password → **Argon2id** (memory-hard) → master key.
  Per-project data keys wrapped under the master key (key hierarchy in
  ADR-0003). Credential values encrypted with **XChaCha20-Poly1305** (AEAD);
  additional authenticated data binds ciphertext to its record. Decrypted values
  live in `SecretString` and are zeroized on drop.
- **Secret handling:** values are redacted by default in all output; reveal/copy/
  export/change require reauthentication; nothing secret is logged, printed, or
  written to disk in plaintext (verified by tests, see §9).
- **Test speed:** set `API_TRACKER_INSECURE_FAST_KDF=1` to use weak Argon2id
  params **in tests only**. Never use in production; it is an intentional test
  escape hatch, not a config option.

---

## 5. Features completed and verified

Verified this session by a full 13-step end-to-end run with the release binary
under **production Argon2id** (no fast-KDF), plus automated tests:

- **Encrypted vault** create/unlock/lock; project + credential CRUD; values
  stored encrypted and shown redacted (`sk-p…PT`).
- **Provider validation** (`key validate`) — live authenticated check via each
  connector, exercised offline with `MockHttpClient` fixtures.
- **Metadata fetch** (`key metadata`) where the provider supports it.
- **Permission visibility** (`key permissions`) — GitHub scopes normalized into
  read/write/admin/sensitive with an honest confidence label. `user` and
  `user:follow` classified as write; `user:email` as read.
- **Usage + cost** — manual usage record (`usage record`) and `usage report`
  produce an **estimated cost of $12.50** for 1M+1M gpt-4o tokens, explicitly
  labeled *"estimated — verify against the provider"*, with attribution
  *"exact credential"*.
- **Provider usage sync** (`provider sync`) — records account-level snapshots,
  honestly attributed `provider_account`, **de-duplicated on re-sync** (no
  double-counting).
- **Budgets** (`budget set` / `budget show`) — over-budget detection; `monitor`
  raises an `over_budget` alert.
- **Suspicious-activity rules** — cost-spike and usage-after-disabled (the latter
  compares against a recorded `credential_disabled` event, not `updated_at`).
- **Secure process injection** (`run`) — verified end to end: the child received
  the injected key; **API Tracker's own master password was `<absent>`** in the
  child; no `.env` was written; no plaintext secret was found at rest; the
  activity log recorded var names/command only, never the value.
- **Honest capability reporting** — `provider capabilities <p>` prints per-
  capability support levels and attribution (e.g. OpenAI usage is
  *"account level only… never as exact per-key"*).
- **Milestone 1–2 features remain verified:** vault lifecycle, backup/restore,
  local secret scanning, git hooks, alerts, doc-change watching.

---

## 6. Features partially implemented

- **Desktop UI** compiles (`cargo check -p api-tracker-desktop` passes) and was
  previously bundled to a `.dmg`. Milestone-3 screens (`UsageView`,
  `CredentialDetail` usage/permissions sections) are wired to Tauri commands.
  The React views were **not** re-exercised in a running desktop window this
  session — verification this session was via the CLI and automated tests. Treat
  desktop milestone-3 flows as **implemented but manually unverified in-app**.
- **Usage sync attribution** is deliberately `provider_account` (org-level) for
  OpenAI/Anthropic because provider key-ids are not yet mapped to vault
  credentials. This is honest and by design, not a stub — but per-key precision
  is a future upgrade.

---

## 7. Features represented only by interfaces, mocks, or placeholders

Everything below is **honestly labeled in the provider manifests** as
`supported_not_implemented`, `manual_only`, or `unsupported` — none are presented
as working:

- **Live usage sync** for providers marked `supported_not_implemented` (e.g.
  Supabase project usage).
- **Credential create / revoke / rotate** via provider APIs — designed and
  labeled per provider, not implemented. Rotation guidance is manual.
- **Permission *changes*** — intentionally not implemented for any provider; no
  initial provider offers a safe documented per-key scope change, so the product
  shows the official management link instead. It never claims a change happened.
- **Pricing API fetch** — none of the initial providers expose an official
  pricing API; pricing is a bundled, dated table with manual overrides.

`MockHttpClient` exists **only** for tests; no production path uses it.

---

## 8. Commands

Prerequisites: Rust (stable, edition 2021), Node 18+, and — for the desktop app —
the Tauri v2 system prerequisites (WebView runtime, platform toolchain).

### Run the CLI
```bash
# from repo root
cargo run -p api-tracker-cli -- <command>        # e.g. -- init
# or the built binary
cargo build --release -p api-tracker-cli
./target/release/api-tracker <command>           # binary name: api-tracker
```
Key env vars: `API_TRACKER_DIR` (data dir), `API_TRACKER_PASSWORD` (master
password, for non-interactive use). Top-level commands: `init`, `unlock`, `lock`,
`settings`, `provider`, `project`, `key`, `scan`, `hooks`, `suppress`, `monitor`,
`alerts`, `usage`, `budget`, `activity`, `mapping`, `run`, `backup`.

### Run the desktop app
```bash
cd apps/desktop
npm install                       # first time only (see §16 re: npm cache)
npm run tauri dev                 # dev window
npm run tauri build               # produce a platform bundle (.dmg/.msi/.deb/AppImage)
```

### Format / lint / typecheck / test / build
```bash
# Rust (from repo root)
cargo fmt --all                                   # format
cargo fmt --all --check                           # verify formatting
cargo clippy --workspace --all-targets -- -D warnings
API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core -p api-tracker-cli
cargo build --release -p api-tracker-cli

# Frontend (from apps/desktop)
npm run typecheck                                 # tsc --noEmit
npm run lint                                      # eslint src
npm test                                          # vitest run
npm run build                                     # tsc + vite build
```
> Run the Rust test suite with `API_TRACKER_INSECURE_FAST_KDF=1`, otherwise
> production Argon2id makes tests slow. Do not commit that variable into any
> non-test code path.

---

## 9. Tests currently passing

All green as of this handoff (0 failing, 0 ignored):

- **Rust: 185 tests.**
  - `api-tracker-core`: 156 — lib unit 108, `backup_session` 10, `credentials`
    12, `integrations` 7, `scanning` 9, `vault_lifecycle` 10.
  - `api-tracker-cli`: 29 — `cli` 15, `integrations_cli` 8, `scanning_cli` 6.
- **Frontend: 5** vitest tests (`src/utils.test.ts`).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cargo fmt --all --check`, `tsc --noEmit`, `eslint src`: clean.

Security-relevant regression tests added this session: child does not inherit the
vault master password; usage sync does not double-count on re-sync; Anthropic
usage sends an RFC-3339 `starting_at`; Supabase reports `Unsupported` (not
invalid) for non-PAT keys; usage-after-disabled is skipped when the disable time
is unknown.

## 10. Tests currently failing

None.

---

## 11. Known bugs

None known that are caused by the current changes. Honest limitations (not bugs):
- Usage sync is org/account-level for OpenAI/Anthropic (labeled as such).
- Cost figures are estimates from a bundled pricing table (labeled "estimated");
  they can drift if provider prices change before the table is updated.
- Model-price matching is substring/longest-prefix; a brand-new model id with no
  matching prefix yields no estimate (correct, but means "no cost shown").

---

## 12. Security concerns / unfinished security work

- **Bundled pricing staleness:** the pricing table has retrieval dates but no
  automatic freshness enforcement beyond labeling. Consider a staleness warning
  threshold in a future pass.
- **Process injection** relies on the OS process boundary; a compromised host,
  malware, or a child that re-exports the value is out of scope (documented in
  `THREAT_MODEL.md`). The child intentionally inherits the parent environment
  minus API Tracker's own secrets.
- **Clipboard/memory exposure** for reveal/copy is inherent to local software and
  documented as a limitation, not solved.
- **No signing/notarization** is claimed in the release workflow unless signing
  credentials are configured (per the packaging requirement). Do not claim it
  until certificates exist.
- General local-first risks (malware, unlocked device, memory inspection) are
  documented honestly in `THREAT_MODEL.md` / `SECURITY.md`; they are not
  eliminated.

---

## 13. Architecture decisions made this session

Recorded in `docs/decisions/0009-provider-integrations.md` (created earlier in
the milestone). Decisions refined during the review-fix pass:
- **Usage-sync dedup keyed off returned buckets:** on re-sync, non-manual
  snapshots for the provider whose `window_start >= min(fetched window_start)`
  are deleted before inserting the fresh set — clock-independent, and manual
  snapshots are never touched.
- **Disable time from a recorded event:** `usage_after_disabled` compares against
  a `credential_disabled` activity event rather than `updated_at` (which any edit
  bumps). If no disable time is recorded, the rule is skipped rather than
  guessing.
- **Attribution honesty over precision:** provider usage is attributed at the
  coarsest truthful level (`provider_account`) and never upgraded to per-key
  without a real key-id→credential mapping.
- **Pricing longest-match:** dated/variant model ids resolve to the most specific
  bundled entry (`gpt-4o-mini-2024-07-18` → `gpt-4o-mini`, not `gpt-4o`).

---

## 14. Deviations from PRODUCT_SPEC.md

No core deviations from the spec's local-first / security requirements. Honest
narrowing:
- Provider usage attribution is account-level where the provider does not expose
  per-key attribution (the spec permits reporting the most precise supported
  level; we do exactly that and label it).
- Permission *editing* is not implemented (spec allows manual workflow when no
  safe official API exists); we surface the official link instead.
- Only 5 providers have connectors so far (GitHub, OpenAI, Anthropic, Stripe,
  Supabase). The catalog lists more; unimplemented capabilities are labeled.

---

## 15. Exact recommended next task

**Implement one real provider usage-sync connector end to end behind the optional
live-verification path — OpenAI organization usage is the best-documented
starting point.** Specifically:
1. Wire `OpenAI::fetch_usage` to the org usage endpoint with real pagination and
   the RFC-3339 `starting_at` already in place.
2. Keep attribution honestly `provider_account` unless/until a key-id→credential
   mapping is added.
3. Add fixture-based tests for pagination and empty windows; keep live
   verification optional (never required for normal builds/tests).
4. Then tackle the officially-supported **create/revoke** actions (e.g. OpenAI
   Admin API service-account keys), upgrading those manifest entries from
   `supported_not_implemented` to `implemented` only when verified.

Do **not** start this in the current session — it is the next milestone.

---

## 16. Setup the next session must not repeat

- **Do not re-run milestone-3 scaffolding** — connectors, usage, pricing,
  budgets, permissions, activity, injection, CLI/desktop wiring, CI, and docs are
  all committed on `feat/provider-integrations`.
- **Do not re-derive** the 13-step acceptance workflow; it passed this session.
- **npm cache:** `~/.npm` is root-owned on this machine. If `npm install` fails
  with EACCES, use `npm install --cache <scratchpad>/npm-cache`.
- **Test KDF:** always run Rust tests with `API_TRACKER_INSECURE_FAST_KDF=1`;
  production Argon2id is intentionally slow.
- **Branch:** continue on `feat/provider-integrations` (or branch from it); it is
  pushed. Do not force-push or rewrite history.

---

## 17. Generated / local files that must not be committed

Already covered by `.gitignore` (verified: none are tracked):
- Vault DBs and WAL/SHM: `*.db`, `*.db-wal`, `*.db-shm`, `*.sqlite*`, `*.vault`.
- Backups: `*.backup`, `*.bak`.
- Secrets/keys: `.env`, `.env.*` (except `.env.example`), `*.pem`, `*.key`,
  `*.p12`, `*.pfx`.
- Build output: `target/`, `node_modules/`, `dist/`, `*.dmg`/`*.msi`/`*.deb`/
  `*.AppImage`/`*.app`.
- Logs: `*.log`.
- The scratchpad E2E run this session lives under the session scratchpad
  directory, **outside** the repo — nothing to clean in-tree.

**Intentional exception:** `apps/cli/tests/fixtures/leaky-repo/config.env` is a
committed scanner test fixture. It is safe: **every value is an obviously FAKE,
non-functional credential** (verified). Do not delete it — tests depend on it.

---

## 18. Repository status at handoff

- Branch `feat/provider-integrations`, HEAD `bb602b4`, pushed and up to date with
  `origin`.
- `git status`: clean working tree, nothing to commit.
- No credentials, vaults, backups, `.env`, logs, or build artifacts are staged or
  tracked (except the intentional fake-credential test fixture noted above).
- PR into `main` is **not** open — that is a human decision for the next session
  or the maintainer.
