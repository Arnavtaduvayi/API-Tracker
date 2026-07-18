# Feature Matrix

A definitive audit of product requirements against the **actual code**, not
prior session reports. Every claim below was verified by inspecting the
modules and tests named. Last audited: 2026-07-18, at `main` commit `e7c1edf`
(post-`v0.2.0-alpha-openai`), updated during the `.env`-governance milestone.

Classifications:

- **Fully implemented** — the workflow works end to end, with tests.
- **Partially implemented** — a real subset works; gaps are listed.
- **Provider-limited** — bounded by what providers officially expose; API
  Tracker implements the most precise supported level and labels it.
- **Local-only** — implemented with local data; no provider round-trip.
- **Mocked only** — exercised only through test mocks; no production path.
- **Not implemented** — absent from the codebase.
- **Intentionally excluded** — deliberately not built; reasoning recorded.

| # | Requirement | Status |
| --- | --- | --- |
| 1 | Per-key metadata and usage attribution | Partially implemented / provider-limited |
| 2 | Secret-manager synchronization | Partially implemented (this milestone) |
| 3 | Offline access | Fully implemented |
| 4 | Token-based cost estimation | Partially implemented |
| 5 | Permission visibility and changes | Provider-limited (visibility); changes manual by design |
| 6 | Request/activity tracking + suspicious-activity alerts | Partially implemented |
| 7 | Duplicate credentials across projects | Fully implemented |
| 8 | `.env` governance | Fully implemented (this milestone) |
| 9 | Provider/API catalog | Fully implemented |
| 10 | Documentation-change notifications | Partially implemented |
| 11 | Git hooks and history scanning | Fully implemented (desktop partial) |
| 12 | Temporary local access | Partially implemented |
| 13 | Provider-issued temporary credentials | Not implemented |
| 14 | Credential version history | Fully implemented (this milestone) |
| 15 | Provider-account metadata | Partially implemented (OpenAI-first) |
| 16 | Provider-account password handling | Intentionally excluded (metadata only) |
| 17 | Local desktop notifications | Partially implemented |
| 18 | Remote push notifications | Intentionally excluded |
| 19 | Project templates and local stack learning | Not implemented |

---

## 1. Per-key metadata and usage attribution — Partially implemented / provider-limited

**What works.** A seven-level `Attribution` model (`exact_credential`,
`provider_key`, `provider_project`, `provider_account`, `local_project`,
`local_process`, `unknown`) is threaded through every usage row
(`crates/core/src/usage.rs`); aggregation tracks the coarsest attribution so
coarse data is never presented as exact. OpenAI usage/costs are synced per
provider project × API-key id × model/line item (`crates/core/src/openai.rs`),
with provider-side projects/keys cached (`provider_side_projects`,
`provider_side_keys`). Rows become `exact_credential` **only** through a
user-confirmed link (`provider_key_links`; `provider link/unlink`), which
retroactively upgrades/downgrades rows. Redacted-value matches are surfaced
as suggestions and never auto-link.

**What is missing.** Exact per-key attribution exists only for OpenAI.
Anthropic sync is org-level (`provider_account`) via the legacy connector
path; GitHub/Stripe/Supabase have no usage sync (validate/metadata only).
Token detail covers the completions endpoint only (spend is complete via the
costs API).

**Files.** `crates/core/src/{openai,usage,connectors,vault}.rs`;
`apps/cli/src/{provider_cmd,usage_cmd}.rs`;
`apps/desktop/src/components/{ProviderConnectionPanel,UsageView}.tsx`.

**Tests.** `crates/core/tests/openai_sync.rs` (13 integration tests incl.
link/unlink attribution upgrades, dedup on re-sync); openai.rs unit tests
(pagination, grouping, redacted matching).

**Acceptance criteria for completion.** Per-key sync for every provider whose
official API supports it (Anthropic exposes org-level only today — that ceiling
is provider-limited and already honest); token detail from the remaining OpenAI
usage endpoints (embeddings, images, audio); linking UX for suggested matches
in the CLI.

**Owning milestone.** Provider-depth milestone (after rotation workflows).

## 2. Secret-manager synchronization — Partially implemented (this milestone)

**What works (after this milestone).** A destination-adapter architecture
(`crates/core/src/destinations.rs`) separate from provider connectors, with
explicit per-destination capability reporting (read/write/delete/versioning/
rollback/validation, auth requirements, platform support, implementation
status). Implemented destinations: local vault (source of truth), local env
mappings, temporary `.env` export, macOS Keychain (via `security(1)`,
platform-gated), Vercel project environment variables and GitHub Actions
repository secrets (official REST APIs, mock-tested), AWS Secrets Manager
(SigV4-signed official API, mock-tested against published test vectors).
Destination admin credentials are stored encrypted in the vault. Credential
changes generate reviewable synchronization plans (`crates/core/src/syncplan.rs`)
with dry-run, reauthentication, per-destination execution, verification,
partial-failure handling, retry, and rollback where supported.

**What is missing.** Live verification against real AWS/GitHub/Vercel accounts
(mock-tested only; the network paths follow the documented API shapes).
No HashiCorp Vault / Doppler / 1Password destinations. Windows Credential
Manager / libsecret equivalents of the Keychain destination.

**Files.** `crates/core/src/{destinations,syncplan}.rs`,
`apps/cli/src/{destination_cmd,sync_cmd}.rs`, desktop `DestinationsView`.

**Tests.** Mock-based destination write/verify/rollback tests, capability
honesty tests, SigV4 test vectors, partial-failure and retry tests.

**Acceptance criteria for completion.** Live verification path exercised
against at least one real account per destination; additional managers by
user demand; drift checks run from the monitor.

**Owning milestone.** This milestone (architecture + first destinations);
live verification in the next provider-depth milestone.

## 3. Offline access — Fully implemented

Vault unlock and all CRUD are pure local SQLite + crypto; no network client is
even constructible in those paths (network entry points require an explicit
`HttpClient` argument). Transport failures map to typed `CoreError::Network`;
sync failures preserve previously synced data and raise `provider_sync_failed`
alerts that auto-resolve on the next success. Verified by
`crates/core/tests/openai_sync.rs::offline_sync_fails_safely_and_previous_data_stays_viewable`.

## 4. Token-based cost estimation — Partially implemented

**What works.** Versioned bundled pricing table (micro-USD per million
tokens, source URL + retrieval date), manual overrides, longest-prefix model
matching, integer money math, estimates labeled "estimated" and kept in a
separate column from provider-reported cost, staleness flag after 45 days,
`CostSource` selection for budgets (never summing reported + estimated).

**What is missing.** Bundled prices cover only 5 models across 2 providers.
`Unit::Requests`/`Credits` exist in the type system but have no estimation
path (tokens only). No alert kind for stale pricing. No desktop editor for
pricing overrides (CLI only).

**Files.** `crates/core/src/{pricing,usage,budget}.rs`.
**Tests.** pricing.rs unit tests (prefix match, override precedence,
staleness); `openai_sync.rs::budgets_choose_reported_or_estimated_without_double_counting`.

**Acceptance criteria.** Broader bundled table with a documented update
process; request/credit-unit estimation; stale-pricing alert; desktop
override editor.

**Owning milestone.** Usage-depth milestone.

## 5. Permission visibility and changes — Provider-limited

**What works.** GitHub classic-PAT scopes read exactly per credential from
the `X-OAuth-Scopes` header, normalized into read/write/admin/sensitive with
confidence labels (`crates/core/src/permissions.rs`); fine-grained tokens
honestly report "not API-readable". Both CLI (`key permissions [--sync]`) and
desktop (CredentialDetail) expose it.

**Changes are manual everywhere by design.** No initial provider offers a
safe, documented per-key scope change; every manifest marks
`change_permissions` as `manual_only` or `unsupported`, and the product
surfaces the official management link instead of pretending. This is the
honest ceiling, not a gap.

**Missing.** Only GitHub has a permission *reader*; Supabase's
`read_permissions` is `supported_not_implemented`.

**Owning milestone.** Provider-depth milestone (Supabase permission read).

## 6. Request/activity tracking + suspicious-activity alerts — Partially implemented

**What works.** Normalized `activity_events` (credential disable/enable,
usage syncs, injection sessions) plus aggregate `request_count` on usage
snapshots. Explainable rules, each with evidence/confidence/recommended
action: `cost_spike` (≥2× and ≥$1.00 month-over-month), `usage_after_disabled`
(against a recorded disable event; skipped when unknown), `over_budget`,
`expired`, `expiring_soon`, `stale`, `unused`, `possible_exposure`,
`production_in_development`, `reused_across_projects`, `provider_data_stale`,
`unmatched_provider_key`, `unmapped_provider_project`,
`provider_connection_invalid`, `provider_sync_failed`,
`documentation_changed`. Alert lifecycle with dedup and auto-resolve.

**What is missing.** No per-request log (provider aggregates only — that part
is provider-limited). `AlertKind::CredentialActivated` is declared but has no
producer (dead variant). No direct unit test for `cost_spike`. Monitoring
runs on demand (CLI `monitor`, desktop button) — no background scheduler.

**Files.** `crates/core/src/{activity,monitor,alerts,budget}.rs`.

**Acceptance criteria.** Background monitor scheduling (see #17), a producer
or removal for `CredentialActivated`, direct cost-spike test, local
instrumentation source (future proxy/SDK events).

**Owning milestone.** Scheduling/notifications milestone.

## 7. Duplicate credentials across projects — Fully implemented

Keyed BLAKE3 fingerprints (per-vault wrapped key), classification
(duplicate-in-project, across-projects, production↔development, intentional
reference), reference records sharing one ciphertext, deletion protection,
reuse alerts, CLI `--allow-duplicate`/`--link-to`, desktop reuse-warning
dialog with reference option. Extensive tests in
`crates/core/tests/credentials.rs`, `reuse.rs` unit tests, CLI tests.
The fingerprint's equality-leak across the project-password boundary is
documented in ADR 0005 and THREAT_MODEL.md.

## 8. `.env` governance — Fully implemented (this milestone)

**What works (after this milestone).** Lossless, non-executing `.env` parsing
preserving comments/order/quoting/line endings (`crates/core/src/envfile.rs`);
discovery of `.env` variants across registered repositories with Git
tracked/ignored/untracked/in-history status (`crates/core/src/envgov.rs`);
malformed/duplicate detection; variable classification against provider
manifests, the scanner, and vault fingerprints; previewed selective import
into the encrypted vault with automatic env-mappings; `.env.example`
generation with diff preview; drift detection (value differs, missing var,
unmapped secret, unused mapping, production-in-dev file, same value in
multiple files); guided migration with confirmation and injection-based
verification; reauthentication-gated atomic export (0600, temp-file rename)
with `.gitignore` verification, redacted audit events, and temporary exports
with automatic cleanup. CLI `env` command group and desktop Env view.

**Tests.** envfile round-trip/quoting/duplicates; discovery/git-status;
import/redaction; example generation; drift; atomic writes; permissions;
export/cleanup including failure paths.

**Remaining.** Monorepo-scale discovery tuning; watching env files for
changes from the background monitor.

## 9. Provider/API catalog — Fully implemented

Compile-time-embedded TOML manifests (5 providers) with validated detection
regexes and a 10-capability honesty matrix; CLI `provider
list/show/docs/capabilities`; desktop catalog + detail screens.
(Stale UI copy claiming "connectors not implemented yet" was corrected this
milestone.) Tests: manifest validation, catalog CLI tests.

## 10. Documentation-change notifications — Partially implemented

**What works.** Conditional GETs (ETag/If-Modified-Since), BLAKE3 content
hashing, validator-clearing on change, offline-safe failure handling, change
alerts with honest "not necessarily breaking" copy; CLI
`watch-docs/check-docs/docs-status`; desktop watch/check UI.

**What is missing.** No watch-frequency configuration and no scheduler —
checks are strictly on-demand; `run_monitor` does not include doc checks.
One CLI help string overstates ("respects conservative intervals") — there is
no interval logic.

**Acceptance criteria.** A `docwatch_interval` setting; monitor-driven
checks; per-watch frequency; corrected CLI copy.

**Owning milestone.** Scheduling/notifications milestone.

## 11. Git hooks and history scanning — Fully implemented (desktop partial)

Pre-commit hook with sentinel block, foreign-hook chaining, no-unlock staged
scanning, suppressions with reasons; working-tree/staged/history scanning
(`git log -p` parsing with real line numbers); vault matching and
possibly-exposed marking. Desktop gaps: history scan fixed at 50 commits; no
suppression-list view (CLI has both). Extensive tests across core and CLI.

**Acceptance criteria for desktop parity.** History-depth control and a
suppression list in the desktop UI.
**Owning milestone.** Desktop-parity milestone.

## 12. Temporary local access — Partially implemented

**What works.** `api-tracker run` injects selected project credentials into a
child process (no `.env`, no printing, cross-project refusal, API Tracker's
own secrets stripped from the child, zeroized buffers, names-only session
records); configured mappings; desktop clipboard auto-clear on copy.
This milestone adds temporary `.env` exports with TTL and automatic cleanup.

**What is missing.** Desktop has no run/mapping/session UI. Process-session
records are written but `list_process_sessions` has no CLI/desktop surface.
No timed reveal grant (deliberate: reveal is one-shot + reauth).

**Acceptance criteria.** A `sessions` listing surface; desktop mapping/run
parity (or a documented decision that `run` stays CLI-only).
**Owning milestone.** Desktop-parity milestone.

## 13. Provider-issued temporary credentials — Not implemented

Only user-entered expiration dates exist (labeled as such in the status
engine). No acquisition/refresh/renewal of short-lived provider tokens
(STS-style), no TTL field on provider-side key metadata, no
temporary-vs-static credential type distinction.

**Acceptance criteria.** A credential type for provider-issued short-lived
tokens with provider-reported expiry, refresh workflows where officially
supported (e.g. AWS STS), and honest labeling where not.
**Owning milestone.** Provider-depth milestone.

## 14. Credential version history — Fully implemented (this milestone)

**Before this milestone:** none — `replace_credential_value` overwrote
ciphertext in place (with `secure_delete`); audit events recorded that a
change happened but old values were unrecoverable.

**After this milestone.** `credential_versions` retains prior values
encrypted under the same project key (AAD-bound to the version row), with
version numbers, timestamps, and reasons; value replacement records the
outgoing version; sync-plan rollback uses retained versions;
reauthentication-gated version listing (masked) via the CLI. Version
retention is bounded and prunable; deleting a credential purges its history.

**Tests.** Version recording on replace, rollback material integrity,
reauth gating, purge on delete.

## 15. Provider-account metadata — Partially implemented

**What works.** Per-provider connection rows (masked admin key, user-entered
organization label, connect/sync/success/failure timestamps, last error);
OpenAI admin connection encrypted under the vault key (write-only, reauth to
replace/remove/test); provider-side project/key metadata cached with
redacted values; staleness computation.

**What is missing.** Dedicated admin connections are OpenAI-only (others use
the legacy credential-reference path). Org label is user-entered, not
provider-verified (OpenAI's APIs do not return an org id — nothing is
invented). No account email field (see #16).

**Owning milestone.** Provider-depth milestone (Anthropic admin connection
next).

## 16. Provider-account password handling — Intentionally excluded (metadata only)

**Audited conclusion: no provider account-password storage exists anywhere in
the codebase** — every `password` reference is the vault's own master,
project, or backup password. This is deliberate and remains so: API Tracker
is a credential manager for API keys, not a general password manager.
Storing provider *login* passwords would expand the threat model (a vault
compromise would yield console access, password-reuse risk, and 2FA-reset
surface) for little benefit over the user's real password manager.

What API Tracker does preserve: organization label on provider connections,
official login/management URLs in every manifest (`manage_url`), and
free-form notes on credentials for non-secret account metadata (e.g. the
account email). If dedicated account-email/org fields are wanted later, they
are non-secret metadata — an additive migration, not password storage.

## 17. Local desktop notifications — Partially implemented

**What works.** The Tauri notification plugin is wired with permission
handling; new high/critical alerts raise a native OS notification.

**What is missing.** Notifications fire only when the user manually clicks
"Run checks now" — there is no background monitor timer, so nothing notifies
autonomously. The only desktop timer polls lock status.

**Acceptance criteria.** A configurable background monitor interval in the
desktop app (battery-friendly), notifying on new high-severity alerts, plus
doc-watch checks (#10).
**Owning milestone.** Scheduling/notifications milestone.

## 18. Remote push notifications — Intentionally excluded

Push to a phone or another machine requires a relay server (APNs/FCM or an
API-Tracker-operated service), which contradicts the core requirements: no
hosted backend, no credential or alert metadata leaving the machine, no
ongoing paid infrastructure. Excluded unless the product's local-first
posture is deliberately revisited. Local OS notifications (#17) are the
supported channel.

## 19. Project templates and local stack learning — Not implemented

No template system; no dependency-manifest parsing to infer a project's
stack or suggest providers. (Lockfile awareness exists only to *skip*
lockfiles during entropy scanning.)

**Acceptance criteria.** Local detection of common dependency files
(package.json, Cargo.toml, requirements.txt, …) suggesting providers and
env-var mappings from the manifests; opt-in, fully local, never sending
project contents anywhere.
**Owning milestone.** Usability milestone after scheduling/notifications.
