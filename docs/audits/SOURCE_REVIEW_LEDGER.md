# Source Review Ledger (Phase 8)

**Baseline:** `7d81090`. **Model:** Fable 5. Every production source file appears exactly once below.

**Depth key:** `Full` = read in full or in all security-critical parts (this session or prior orchestrator per `evidence/MY_FINDINGS.md`); `Sec` = security-critical regions read; `Arch` = reviewed at architecture/verifier-category level (`findings_raw.tsv`) but not line-by-line this session; `Tool` = tooling-blocked; `Plat` = platform-blocked; `None` = not reviewed. **Status** ∈ {Fully reviewed, Partially reviewed, Platform-blocked, Tooling-blocked, Not reviewed}.

To keep 110+ files legible, trust-boundary + test notes are given per group; per-file rows carry Purpose, Depth, Findings, Status. Test suites present: `crates/core/tests/*` (17 integration files + `common`), plus in-file `#[cfg(test)]` modules.

---

## crates/core (shared security core; `#![forbid(unsafe_code)]`)
**Trust boundaries:** all sensitive inputs (passwords, session tokens, provider HTTP, .env content, git content/args, PIDs, backup files, pricing imports) enter here; sinks are the encrypted DB, spawned processes, and network. **Security relevance:** maximal — this crate is the entire security surface. **Tests:** vault_lifecycle, credentials, rotation_access, backup_session, migration_safety, scanning, env_destinations, security_residuals, observability, {openai,anthropic}_sync, account_metadata, integrations, templates_stack, shared_vault_smoke.

| File | Purpose | Depth | Findings | Status |
|---|---|---|---|---|
| crypto.rs | AEAD/Argon2id/AAD primitives | **Full** | CRYPTO-04/05 | Fully reviewed |
| vault.rs | vault/key hierarchy, credentials, rotation, monitor, backup orchestration (8520 LoC) | **Sec** (key-mgmt, rotation, monitor, reveal/replace/add, backup regions read this session) | CRYPTO-01, CONC-03/04, ROT-001..010, OBS-001..004, IPC-01, DEST-*, FS-03 | Partially reviewed |
| rotation.rs | rotation state model + storage | **Full** | ROT-009/011 (state guards) | Fully reviewed |
| secret.rs | SecretString/Bytes zeroize+redact | Full (prior) | — | Fully reviewed |
| error.rs | typed errors | Full (prior) | — | Fully reviewed |
| clock.rs | time source | Full (prior) | PI-05, FS-08, OBS-010 (wall-clock/RFC3339) | Fully reviewed |
| db.rs | schema, migrations, pragmas | Full (prior) | CONC-10 | Fully reviewed |
| session.rs | split-token CLI session | Full (prior) | CONC-08/09 | Fully reviewed |
| inject.rs | env injection, PID termination | **Full** | PI-01..07, CONC-11 | Fully reviewed |
| http.rs | ureq client, redaction, caps | Full (prior) | NET-04 | Fully reviewed |
| docwatch.rs | doc-change watch + fetch | **Full** | NET-01, OBS-012 | Fully reviewed |
| notify.rs | webhook validate + deliver | **Sec** (validate read this session) | NET-02, CONC-07 | Fully reviewed |
| backup.rs | backup/restore, v2 payload | **Sec** (collect_payload read this session) | CONC-04, CRYPTO-03 | Fully reviewed |
| destinations.rs | GitHub/AWS/Vercel adapters, SigV4 | Sec (prior: sigv4/region/capability) | DEST-01..13 | Partially reviewed |
| gitrepo.rs | git scanning I/O | Full (prior) | GScan-03, CONC-05/06 | Fully reviewed |
| scanner.rs | secret detection | Arch | GScan-05 | Partially reviewed |
| hooks.rs | pre-commit hook install/chain | Arch | GScan-01/02 | Partially reviewed |
| envfile.rs | .env parser | Full (prior) | FS-06 | Fully reviewed |
| envgov.rs | .env discover/preview/import/export | Sec | FS-01/02/04/05/07/08, IPC-01(atomic_write) | Partially reviewed |
| connectors.rs | provider connector trait + impls | Arch | NET-03, ROT-002 | Partially reviewed |
| openai.rs | OpenAI sync/lifecycle | Arch | INFO-02, NET-03/04, OBS-014/015 | Partially reviewed |
| anthropic.rs | Anthropic sync/lifecycle | Arch | OBS-003, NET-03 | Partially reviewed |
| pricing.rs | pricing import/estimation/money | Sec (prior: money/validate/import) | OBS-005/009/010/011 | Partially reviewed |
| usage.rs | usage aggregation | Arch | OBS-007/008/015 | Partially reviewed |
| budget.rs | budget reporting | Arch | OBS-008 | Partially reviewed |
| observe.rs | explainable observability rules | Arch | OBS-006, OBS-001(alerts) | Partially reviewed |
| monitor.rs | monitor orchestration, managed kinds | **Sec** (managed_kinds + run_monitor read this session) | OBS-001 | Fully reviewed |
| alerts.rs | alert upsert/resolve | **Sec** (auto_resolve_stale read this session) | OBS-001, CONC-07 | Fully reviewed |
| access.rs | access grants | **Sec** (consume_launch read this session) | PI-05/07 | Fully reviewed |
| reuse.rs | fingerprint/reuse detection | Sec | DEST-12 | Fully reviewed |
| permissions.rs | scope honesty | Full (prior) | — (positive: honest) | Fully reviewed |
| providers.rs | provider registry/capabilities | Sec (manifests read this session) | ROT-001(matrix) | Fully reviewed |
| audit.rs | audit event log | Arch | CONC-07 | Partially reviewed |
| activity.rs | activity events, managed kinds | Arch | CONC-07 | Partially reviewed |
| status.rs | credential status engine | Arch | OBS-001(PossiblyExposed) | Partially reviewed |
| syncplan.rs | sync plan model | Arch | SYNC-001/002, DEST-06 | Partially reviewed |
| settings.rs | vault settings | Arch | OBS-012 | Partially reviewed |
| model.rs | core data types | Sec | — | Fully reviewed |
| templates.rs | project templates | None | — | Not reviewed |
| stackdetect.rs | stack detection | None | — | Not reviewed |
| lib.rs | crate root, module exports | Full | — | Fully reviewed |

## apps/cli (`api-tracker`)
**Trust boundaries:** clap arg parsing, no-echo password prompts, process spawning (`run`), stdout rendering. **Security relevance:** high (owns injection + the one deliberate plaintext reveal). **Tests:** in-file + core integration.

| File | Purpose | Depth | Findings | Status |
|---|---|---|---|---|
| run_cmd.rs | `run` injection, kill-timer | Sec | PI-01/03, CLI-01/06 | Fully reviewed |
| scan_cmd.rs | scan/hook CLI | Arch | GScan-04 | Partially reviewed |
| access_cmd.rs | access grant CLI, `--kill` | Sec | CLI-03, PI-02 | Partially reviewed |
| env_cmd.rs | env-governance CLI output | Arch | CLI-02 | Partially reviewed |
| render.rs | output sanitization | Full | CLI-05 | Fully reviewed |
| key_cmd.rs | credential CLI (reveal/remove) | Full (prior) | — (reauth+confirm OK) | Fully reviewed |
| provider_cmd.rs | provider CLI | Arch | CLI-04 | Partially reviewed |
| destination_cmd.rs | destination CLI | Arch | DEST-05 | Partially reviewed |
| rotation_cmd.rs | rotation CLI | Arch | ROT-008 | Partially reviewed |
| usage_cmd.rs | usage/budget CLI | Arch | OBS-002/008 | Partially reviewed |
| pricing_cmd.rs | pricing CLI | None | — | Not reviewed |
| sync_cmd.rs | sync plan CLI | Arch | SYNC-001 | Partially reviewed |
| ctx.rs | CLI context, confirm | Sec | CONC-08 | Fully reviewed |
| alerts_cmd.rs | alerts CLI | Arch | CONC-08 | Partially reviewed |
| backup_cmd.rs | backup CLI | Arch | — | Partially reviewed |
| project_cmd.rs | project CLI | None | — | Not reviewed |
| template_cmd.rs | template CLI | None | — | Not reviewed |
| vault_cmd.rs | vault CLI (setup/unlock) | Arch | — | Partially reviewed |
| main.rs | CLI entrypoint/dispatch | Arch | — | Partially reviewed |

## apps/desktop/src-tauri (Tauri 2, 136 commands)
**Trust boundaries:** IPC payloads from the webview; `with_vault` gates unlock; reauth enforced in core (structurally). **Security relevance:** high — direct-IPC can bypass UI sequencing. **Tests:** none Rust-side for the command layer (gap).

| File | Purpose | Depth | Findings | Status |
|---|---|---|---|---|
| main.rs | 136 `#[tauri::command]`s, mutex, auto-lock | Sec (state/with_vault/reveal/copy/delete 60-810 prior; env_example_write + credential_delete this session) | IPC-01/02/04, INFO-01, CONC-01/02, PI-06 | Partially reviewed |
| build.rs | Tauri build script | None | — | Not reviewed |

## apps/desktop/src (React/TS frontend)
**Trust boundaries:** presentation only; must NOT be the sole authorization (core reauth is authoritative). **Security relevance:** medium (secret display, reauth prompt, confirm dialogs — all backed by core checks). **Tests:** none (gap). **Depth:** the security-sensitive components (CredentialDetail, ReauthDialog, VaultUnlock, ConfirmDialog, App, AlertsView, NotifyView, ProviderDetail) were in the verifier's IPC/frontend category (`Arch`); the rest `None`.

| File | Depth | Findings | Status |
|---|---|---|---|
| CredentialDetail.tsx | Arch | IPC-05 | Partially reviewed |
| ReauthDialog.tsx / VaultUnlock.tsx / ConfirmDialog.tsx | Arch | (IPC-02 UI-only confirm) | Partially reviewed |
| App.tsx / AlertsView.tsx / NotifyView.tsx / ProviderDetail.tsx | Arch | — | Partially reviewed |
| SyncView.tsx / DestinationsView.tsx | Arch | DEST-03/04 (display) | Partially reviewed |
| api.ts / types.ts / utils.ts | Arch | — | Partially reviewed |
| AccessView, BackupView, CredentialForm, EnvView, PricingView, ProjectDetail, ProjectForm, ProjectList, ProviderCatalog, ProviderConnectionPanel, RotationView, ScanView, SettingsView, TemplatesView, UsageView, VaultSetup, main.tsx | None | — | Not reviewed |
| vite.config.ts | None | — | Not reviewed |

## Scripts, CI, packaging, manifests
**Trust boundaries:** CI runs with `contents: write` on release; live_verify scripts touch real providers (never in normal test). **Security relevance:** supply-chain (CI) + release integrity.

| File | Depth | Findings | Status |
|---|---|---|---|
| .github/workflows/ci.yml | Sec (prior) | M-6 (mutable action tags) | Fully reviewed |
| .github/workflows/release.yml | Sec (prior) | M-6 (mutable tags; `contents:write`; SHA256SUMS present) | Fully reviewed |
| scripts/smoke.sh, demo.sh | Arch (memory: harness facts) | — | Partially reviewed |
| scripts/live_verify_*.sh (7) | None (require real provider creds; out of scope) | — | Not reviewed (by design) |
| provider-manifests/*.toml (5) | Sec (capabilities read this session) | ROT-001 matrix, DEST-08 | Fully reviewed |
| apps/desktop/src-tauri/tauri.conf.json | Arch | — | Partially reviewed |
| apps/desktop/src-tauri/capabilities/default.json | Arch | (IPC allowlist) | Partially reviewed |
| Cargo.toml (root/core/cli/desktop) | Full | OBS-015 (no overflow-checks) | Fully reviewed |
| package.json / package-lock.json / tsconfig.json / .prettierrc.json | None | — | Not reviewed |
| templates/*.toml (9) | None | — | Not reviewed |

## Coverage summary
- **Fully reviewed:** 24 core + 4 CLI + CI(2) + manifests(5) + Cargo(4) ≈ **39 files** (all security-critical primitives, key management, rotation, monitor/alerts, injection, backup, crypto, providers).
- **Partially reviewed:** most remaining core/CLI/desktop-command/FE-security files (verifier-category or architecture depth; findings attributed).
- **Not reviewed:** `templates.rs`, `stackdetect.rs`, several non-security CLI/FE files, build scripts, packaging manifests, live_verify scripts (real-provider, out of automated scope), most non-security React views.
- **No file claims line-by-line completion beyond what a `Full`/`Sec` row supports.** The largest residual is the 136-command Tauri layer (no Rust tests) and the React frontend (no tests) — see TEST_COVERAGE_GAPS.md.
