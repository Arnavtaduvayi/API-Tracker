# Fable Session Handoff

This document hands the repository off to a fresh session. It records exactly
what is verified working, what is planned, and what must not be repeated.
**"Verified"** means exercised by a passing test or a manual end-to-end run
this session; **"planned"** means designed/labeled but not yet implemented.

_Last updated for the OpenAI usage-synchronization milestone wrap-up._

---

## 1. Current branch and latest commit

- **Branch:** `feat/openai-usage-sync` (branched from `main` at `74bab59`).
- **Commits on this branch:**
  - `60ef202` feat(core): OpenAI usage/cost sync with encrypted admin
    connection and honest key attribution
  - `2518662` feat(cli): OpenAI connection, sync windows, key linking, and
    usage report filters
  - `71614c1` feat(desktop): OpenAI connection panel, usage records, and
    budget cost source
  - (a docs/scripts commit follows; see `git log`)
- **`main`** contains milestones 1–3 plus the demo/smoke/password-policy PRs
  (all merged).

---

## 2. What this milestone added (all mocked-verified)

### Encrypted administrative connection (ADR 0011)
- `provider_connections` gained v4 columns: the OpenAI **Admin API key** is
  stored encrypted under the **vault key** (AAD
  `api-tracker:v1:provider-admin:{vault_id}:{provider}`), masked for
  display, validated against `GET /v1/organization/projects` before storage
  (`--no-verify` opt-out stores unvalidated and says so).
- Write-only: replace/remove/test require master-password reauthentication;
  there is deliberately **no reveal** for the admin key.
- Legacy path (`provider connect <p> --credential <c>`, a vault-credential
  reference) still works and is the only option for non-OpenAI providers.
- One OpenAI org per vault (PK is `provider`) — documented limitation.

### Real OpenAI sync engine (`crates/core/src/openai.rs`)
- Usage: `GET /v1/organization/usage/completions`, daily buckets, grouped
  `project_id × api_key_id × model`, `limit=31`, cursor pagination
  (`has_more`/`next_page`), 200-page cap.
- Costs: `GET /v1/organization/costs`, grouped
  `project_id × api_key_id × line_item`, `limit=180`. Amounts preserved
  exactly (micros conversion guards negative/non-finite/overflow; currency
  kept verbatim; non-USD excluded from USD totals with a flag, never mixed).
- Metadata: org projects + per-project API keys (id/name/`redacted_value`),
  cached in `provider_side_projects` / `provider_side_keys`; failures are
  per-sync *notes*, never sync failures.
- Transport: bounded retries (2 extra attempts) on network/5xx/429 honoring
  `Retry-After` (cap 30s); 401/403 → `CoreError::ProviderAuth`; persistent
  429 → `ProviderRateLimited`; transport failures → `CoreError::Network`
  (http.rs now uses this typed variant).
- **Fetch-all-then-replace:** every page is fetched before any write; then
  one transaction deletes previously synced rows covering the returned
  buckets and inserts fresh ones. Usage-kind deletes exclude
  `manual` + `openai_costs_api` sources (so legacy org-level rows are also
  replaced); cost deletes target `openai_costs_api` only. Manual rows are
  never touched. Cost-fetch failure while usage succeeded = partial success
  with a note; the costs checkpoint is left untouched for retry.
- Checkpoints (`provider_sync_state`): `usage_sync_default` continues from
  the last window end minus a 2-day overlap; first sync = 30 days;
  `usage_sync(days)` and `usage_sync_range(from,to)` are explicit.

### Attribution and key linking
- New `Attribution::ProviderKey` = exact provider-side key id, **not**
  linked locally. Rows are attributed from the dimensions the provider
  actually returned; `provider_account_id` is only ever the user-entered org
  label (the APIs don't return an org id — nothing is invented).
- `provider_key_links` stores **user-confirmed** links only
  (`provider link/unlink`); linking retroactively upgrades synced rows to
  `exact_credential` + local project (and sync applies links to new rows);
  unlinking downgrades them back. Same-provider credential enforced.
- Redacted-value matching (`sk-proj...1234` vs decryptable vault values) is
  computed on demand in `provider_keys_overview` as a **suggestion**
  (ambiguity → no suggestion; locked projects noted); it never auto-links.
- Monitor rules (auto-resolving): `provider_data_stale` (last success older
  than `provider_stale_days`, default 3, new vault setting),
  `unmatched_provider_key` (unlinked key with rows),
  `unmapped_provider_project` (no linked usage and ≥ $1.00 month-to-date
  reported cost). Sync-path alerts (not monitor-managed):
  `provider_connection_invalid` (auth) / `provider_sync_failed` (other),
  both resolved by the next successful sync.

### Costs vs. estimates, budgets
- Usage rows carry tokens + optional local estimate; cost rows carry the
  reported amount only. They are never joined or summed together.
- `usage::CostSource` (`best_available` default / `provider_reported` /
  `estimated`) is stored in `vault_meta.budget_cost_source`; budgets and
  `used_cost_between` (cost-spike rule) pick exactly one source.
  `BudgetReport` now includes `cost_source`.

### CLI / desktop
- CLI: `provider connect [--credential|--org|--key-stdin|--no-verify]`,
  `disconnect --yes` (confirm+reauth), `test` (reauth), `sync
  [--days|--from/--to]`, `connection-status` (freshness/stale/last error),
  `keys`, `link`, `unlink`, `projects`; `usage report
  --provider/--source/--limit` with per-record table; `budget source`.
  Admin key input via hidden prompt, stdin, or
  `API_TRACKER_PROVIDER_ADMIN_KEY` (stripped from `run` children).
- Desktop: `ProviderConnectionPanel` (connect/replace with validation,
  reauth dialogs for disconnect/test, sync period selector, status/stale
  badges, notes, keys table with confirm-link/unlink + suggestions,
  projects table), UsageView records table with source filter + non-USD +
  stale warnings, budget cost-source selector. New Tauri commands mirror
  the vault API; `provider_sync` now returns a `SyncReport`.

---

## 3. Test/verification status at handoff

- **Rust: 220 tests, 0 failed** (`API_TRACKER_INSECURE_FAST_KDF=1 cargo
  test -p api-tracker-core -p api-tracker-cli`): core lib 123 (incl. 13
  openai.rs engine unit tests), openai_sync integration 13, integrations 7,
  plus all milestone 1–3 suites; CLI 33 (incl. 4 new connection tests).
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`: clean. Frontend: `tsc --noEmit`, `eslint src`, 5 vitest tests,
  `vite build`: clean/passing.
- **Smoke test: 53/53** (`bash scripts/smoke.sh`) — 6 new checks cover the
  offline admin-connection lifecycle incl. no-plaintext-on-disk.
- **Desktop UI flows were NOT manually exercised in a running window** this
  session (no display interaction available); the desktop backend compiles
  and its logic is the same core verified by tests. Treat the new React
  panel as implemented but manually unverified in-app.
- **No live OpenAI verification was run** (no real credential; by design).
  `scripts/live_verify_openai.sh` is the safe manual path.

## 4. Known limitations (honest, documented)

- Token detail = completions endpoint only (embeddings/images/audio usage
  endpoints not yet synced); total spend is complete via the costs API.
- One OpenAI organization per vault.
- `provider_account_id` on rows is the user-entered org label or NULL.
- Estimates don't model cached/batch/service-tier discounts (documented in
  OPENAI_SYNC.md); reported vs estimated may differ.
- Anthropic still uses the legacy single-request org-level sync path.

## 5. API facts confirmed from primary sources (ADR 0011)

Confirmed against `github.com/openai/openai-openapi` (spec 2.3.0,
2026-07-18): AdminApiKeyAuth on all org endpoints; usage `bucket_width`
1m/1h/1d with limit max 31 at 1d; usage `group_by` includes `api_key_id`;
costs `bucket_width` 1d only, limit ≤ 180, `group_by`
project_id/line_item/api_key_id; `amount.value` number + lowercase ISO-4217
currency; list endpoints use `limit`/`after` + `has_more`/`last_id`;
ProjectApiKey exposes `redacted_value`. Docs now live at
developers.openai.com (platform.openai.com blocks plain fetches).

## 6. Setup the next session must not repeat

- npm cache: `~/.npm` is root-owned → `npm install --cache <scratchpad>/npm-cache`.
- Rust tests: always `API_TRACKER_INSECURE_FAST_KDF=1`.
- CI clippy may use a newer toolchain than local stable; if
  `cargo +1.97.0` is available, run it before pushing.
- Do not re-research the OpenAI API surface (see §5 / ADR 0011); do not
  re-derive the sync/dedup design.

## 7. Recommended next milestone

Either of (in preference order):
1. **`.env` governance** or **rotation workflows** per the product spec, or
2. **OpenAI admin actions** (service-account key create/revoke via the
   Admin API) upgrading `create_credential`/`revoke_credential` from
   `supported_not_implemented` — with explicit confirmation + reauth, never
   automatic; or extend token detail to the remaining usage endpoints
   (embeddings first — same parser shape).

Do not merge the PR without the maintainer's review unless instructed.
