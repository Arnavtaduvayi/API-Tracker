# Fable Session Handoff

This document hands the repository off to a fresh session. **"Verified"**
means exercised by a passing test or a manual end-to-end run this session;
**"planned"** means designed/labeled but not yet implemented.

_Last updated for the `.env`-governance + destinations milestone wrap-up._

---

## 1. Where things stand

- **`main`** contains milestones 1–4 (vault, catalog/scanning/monitoring,
  provider integrations, OpenAI usage/cost sync), tagged
  `v0.1.0-alpha-core` and `v0.2.0-alpha-openai`.
- **This milestone's branch:** `feat/env-destinations` — `.env` governance,
  credential version history, destination adapters, synchronization plans,
  across core + CLI + desktop, with docs and tests. See §2–§4 and the PR.
- A prettier regression from PR #3 was fixed directly on `main`
  (`e7c1edf`); `main` CI is green.

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

- Core: 152 lib unit tests + integration suites incl. 17 new
  `env_destinations` tests; CLI: 40 tests incl. 7 new end-to-end
  `env_destinations_cli` tests. All green with
  `API_TRACKER_INSECURE_FAST_KDF=1`.
- `cargo fmt --check`, `cargo +1.97.0 clippy --workspace --all-targets -- -D warnings`: clean.
- Frontend: `tsc --noEmit`, eslint, vitest, `vite build`, prettier: clean.
- **Smoke test: 68 checks** (`bash scripts/smoke.sh`) — 15 new checks cover
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
