# Fable Session Handoff

This document hands the repository off to a fresh session. **"Verified"**
means exercised by a passing test or a manual end-to-end run this session;
**"planned"** means designed/labeled but not yet implemented.

_Last updated for the cross-provider observability milestone wrap-up._

---

## 1. Where things stand

- **`main`** contains milestones 1–5 (vault, catalog/scanning/monitoring,
  provider integrations, OpenAI usage/cost sync, `.env` governance +
  destinations + sync plans), tagged `v0.1.0-alpha-core` and
  `v0.2.0-alpha-openai`.
- **This milestone's branch:** `feat/cross-provider-observability`
  (migration v7) — Anthropic per-key sync engine (usage grouped by
  api_key_id × workspace × model; CENTS-denominated cost report; key
  expirations onto linked credentials; admin connections for Anthropic),
  GitHub billing usage (fine-grained tokens, account level), Stripe Events
  activity, non-token units first-class, 16 explainable rules, incremental
  repo monitoring, webhook notification channels (encrypted, https-only,
  once-per-alert delivery), doc-watch intervals + history, desktop
  background monitor timer. Read
  `docs/decisions/0014-cross-provider-observability.md` FIRST.
- The prior rotation milestone (migration v6, ADR 0013) is merged in
  `main`. This milestone's adversarial review produced 2 medium / 6 low /
  4 info findings (webhook re-delivery flapping, migration alert flood,
  localhost URL bypass, redirect header forwarding, silent re-baselines) —
  ALL fixed with regression tests.
- Research note: Anthropic docs moved to platform.claude.com; Supabase's
  `usage.api` endpoint is GONE from the Management API (analytics
  endpoints are untyped — deliberately not stored); GitHub billing usage
  documents fine-grained tokens only.

## 2. What this milestone added

Read `docs/decisions/0012-env-governance-and-destinations.md` first — it
records the design and its reasoning. Summary:

- **`envfile.rs`** — lossless, non-executing `.env` parser (comments,
  ordering, quoting, `export` prefixes, CRLF preserved; malformed/duplicate
  detection; raw lines + values in `SecretString`).
- **`envgov.rs`** — discovery (variants, Git status incl. history),
  environment inference, `.env.example` generation, masked diffs, atomic
  0600 writes, export records with hash-checked cleanup, drift types.
- **vault.rs** — `env_discover/preview/import/drift/export/cleanup/exports`,
  credential **version history** (retained encrypted, AAD-bound to version
  number, bounded, purged on delete, reauth-gated masked listing),
  destination CRUD with vault-encrypted write-only auth, sync-plan
  create/get/list/execute/rollback + `destination_drift_check`.
- **`destinations.rs`** — adapter trait + honest per-kind capability
  catalog. Implemented: macOS Keychain (`security -i`, secret via stdin,
  never argv; platform-gated), AWS Secrets Manager (own SigV4 —
  **verified against the official AWS test vector**), GitHub Actions
  repository secrets (`crypto_box` sealed box), Vercel env vars. Local
  kinds (vault / env_mapping / env_export) are catalog entries handled by
  the vault. AWS delete is `supported_not_implemented` (recovery-window
  semantics deferred).
- **`syncplan.rs`** + vault orchestration — dry-run plans, reauth-gated
  execution, per-destination rollout, verification (fingerprint read-back
  or existence), partial failures, retry (re-runs only pending/failed),
  rollback to retained versions, stale-plan refusal, redacted audit events.
- **CLI** — `env`, `destination`, `sync` command groups + `key versions`;
  `run` also strips `API_TRACKER_DESTINATION_AUTH` from children.
- **Desktop** — Env files / Destinations / Sync plans screens over new
  Tauri commands (thin wrappers, same core).
- **DB migration v5**: `credential_versions`, `env_exports`, `destinations`,
  `credential_destinations`, `sync_plans`, `sync_plan_steps`,
  `credentials.value_version`.
- **docs/FEATURE_MATRIX.md** — the definitive audited feature matrix (18
  product requirements classified with acceptance criteria and owning
  milestones). Keep it accurate.

## 3. Test/verification status at handoff

- Core: 160 lib unit tests + integration suites incl. 22 `rotation_access`
  tests (restart recovery, idempotency, 404-ambiguity, external
  replacement, orphaned keys, prune exemptions, rollback refusals) and 20
  `env_destinations` tests; CLI: 46 tests incl. 6 `rotation_access_cli`
  end-to-end tests. All green with `API_TRACKER_INSECURE_FAST_KDF=1`.
- `cargo fmt --check`, `cargo +1.97.0 clippy --workspace --all-targets -- -D warnings`: clean.
- Frontend: `tsc --noEmit`, eslint, vitest, `vite build`, prettier: clean.
- **Smoke test: 83 checks** (`bash scripts/smoke.sh`) — 15 new checks cover
  env preview/import/example/export permissions/cleanup and destination
  add/attach/plan (offline, encrypted-at-rest asserted).
- An adversarial security review ran over the milestone diff; findings were
  fixed or explicitly accepted (see the PR discussion / commit messages).
- **Not live-verified:** AWS/GitHub/Vercel destination writes follow the
  documented API shapes with fixture tests only — no real accounts were
  used. The catalog and docs say so. Desktop screens compile and typecheck;
  in-window manual exercise remains for a session with a display.

## 4. Honest limitations

- Destination delete for AWS; HashiCorp Vault/Doppler/1Password kinds;
  Windows Credential Manager / libsecret — not implemented, labeled.
- Drift checks and doc watches run on demand; no background scheduler yet
  (the scheduling/notifications milestone owns this — FEATURE_MATRIX #10,
  #17).
- One `.env.example` per directory convention; monorepo tuning is future
  work.
- Rollback restores destinations, not the vault value (stated in CLI
  output).

## 5. Setup the next session must not repeat

- npm cache: `~/.npm` is root-owned → `npm install --cache <scratchpad>/npm-cache`.
- Rust tests: always `API_TRACKER_INSECURE_FAST_KDF=1`.
- CI clippy: run `cargo +1.97.0 clippy` before pushing.
- Do not re-derive: the SigV4 implementation is pinned by the official test
  vector; the `.env` parser round-trip contract is pinned by tests; the
  sync-plan semantics are in ADR 0012.

## 6. Recommended next milestone

In preference order:
1. **Background scheduling + notifications** (FEATURE_MATRIX #10/#17): a
   battery-friendly monitor timer in the desktop app, doc-watch intervals,
   OS notifications without a manual click; monitor-driven destination
   drift checks.
2. **OpenAI admin actions** (create/revoke service-account keys) building
   on ADR 0011, which combined with sync plans gives a full rotation
   workflow (create new → plan → deploy → verify → manually revoke old).
3. Live verification passes for AWS/GitHub/Vercel destinations behind an
   optional script like `scripts/live_verify_openai.sh`.
