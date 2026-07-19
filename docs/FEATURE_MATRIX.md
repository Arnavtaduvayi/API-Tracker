# Feature Matrix

A definitive audit of product requirements against the **actual code**, not
prior session reports. Every claim below was verified by inspecting the
modules and tests named. Last audited: **2026-07-18, alpha-completion
branch** (post-observability, migrations v1–v7, backup format v2).

Classifications:

- **Fully implemented** — the workflow works end to end, with tests.
- **Provider-limited** — bounded by what providers officially expose; API
  Tracker implements the most precise supported level and labels it.
- **Local-only by design** — implemented with local data; no provider
  round-trip is possible or claimed.
- **Advisory-only** — informs and warns but cannot enforce; labeled as such
  in every surface.
- **Partially implemented** — a real subset works; gaps are listed.
- **Intentionally excluded** — deliberately not built; reasoning recorded.
- **Not implemented** — absent from the codebase.

| # | Requirement | Status |
| --- | --- | --- |
| 1 | Per-key metadata and usage attribution | Provider-limited (per-key OpenAI + Anthropic; account-level GitHub/Stripe; Supabase honestly declined) |
| 2 | Secret-manager synchronization | Partially implemented (4 destination kinds; mock-tested network paths) |
| 3 | Offline access | Fully implemented |
| 4 | Token-based cost estimation | Partially implemented (5 bundled models; tokens only) |
| 5 | Permission visibility and changes | Provider-limited (visibility complete where possible; changes route through rotation/dashboard by design) |
| 6 | Request/activity tracking + suspicious-activity alerts | Provider-limited (official aggregates + local sessions; 20 explainable rules) |
| 7 | Duplicate credentials across projects | Fully implemented |
| 8 | `.env` governance | Fully implemented |
| 9 | Provider/API catalog | Fully implemented |
| 10 | Documentation-change notifications | Fully implemented (intervals, history, monitor-driven) |
| 11 | Git hooks and history scanning | Fully implemented (desktop parity closed this session) |
| 12 | Temporary local access | Fully implemented (session listing/termination added this session) |
| 13 | Provider-issued temporary credentials | Provider-limited (expiry recorded where reported; none issuable via API) |
| 14 | Credential version history | Fully implemented |
| 15 | Provider-account metadata | Partially implemented (OpenAI + Anthropic admin connections) |
| 16 | Provider-account password handling | Intentionally excluded (metadata only) |
| 17 | Local desktop notifications | Fully implemented (in-app background monitor timer; not an OS service) |
| 18 | Remote push notifications | Intentionally excluded (user-configured webhooks offered instead) |
| 19 | Project templates and local stack learning | Not implemented |

Cross-cutting, added at alpha completion: **complete encrypted backups**
(format v2 captures every table; older backups restore and migrate forward —
ADR 0015), **newer-schema refusal** on live vaults and backups, and a
**108-check end-to-end smoke suite** including real localhost webhook
delivery and hook-blocked commits.

---

## 1. Per-key metadata and usage attribution — Provider-limited

**What works.** A seven-level `Attribution` model threads through every
usage row (`crates/core/src/usage.rs`); aggregation tracks the coarsest
attribution so coarse data is never presented as exact. **OpenAI**: usage
per provider project × API-key id × model and reported costs per project ×
key × line item (`openai.rs`, ADR 0011). **Anthropic**: usage per API-key
id × workspace × model (officially supported grouping) and cents-denominated
costs at workspace level — never divided per key (`anthropic.rs`, ADR 0014);
provider-reported key expirations flow onto linked credentials. **GitHub**:
Enhanced Billing quantities/units at account level (fine-grained token with
Plan:read; `connectors.rs:349-419`). **Stripe**: Events API daily counts by
family, unit `events`, account level (`connectors.rs:959-1051`). Rows become
`exact_credential` **only** through a user-confirmed link
(`provider link/unlink`); redacted-value matches are suggestions only.
**Supabase**: analytics endpoints return undocumented units — honestly
declined (manifest says so).

**The honest ceiling.** GitHub/Stripe per-token/per-key usage does not exist
in any official API. OpenAI token detail covers the completions endpoint
(spend is complete via the costs API).

**Tests.** `openai_sync.rs` (13), `anthropic_sync.rs`, connector unit tests
(fixtures); attribution up/downgrade covered.
**Live verification.** Opt-in scripts: `scripts/live_verify_{openai,anthropic,github,stripe}.sh` (read-only).

## 2. Secret-manager synchronization — Partially implemented

Destination adapters (`destinations.rs`) with per-kind capability honesty:
macOS Keychain (secret via stdin), AWS Secrets Manager (SigV4 verified
against the official test vector), GitHub Actions repository secrets
(sealed box), Vercel env vars, plus local vault/mapping/export kinds.
Reviewable sync plans (`syncplan.rs`): dry-run default, reauth-gated
execution, per-destination verification, partial-failure handling, retry,
rollback to retained versions, stale-plan refusal. Desktop + CLI surfaces
incl. drift checks (monitor rule `destination_drift`).

**Missing.** Live verification against real AWS/GitHub/Vercel accounts
(fixture-tested network paths); AWS delete; HashiCorp Vault/Doppler/
1Password kinds; Windows Credential Manager/libsecret.

## 3. Offline access — Fully implemented

All vault operations are pure local SQLite + crypto; network entry points
require an explicit `HttpClient`. Failed syncs change nothing and prior data
stays viewable (`openai_sync.rs::offline_sync_fails_safely_...`). `monitor
--offline` skips network phases. Smoke: the offline usage report check.

## 4. Token-based cost estimation — Partially implemented

Versioned bundled pricing (5 models, 2 providers; source URL + retrieval
date), overrides, longest-prefix matching, integer micro-USD math,
"estimated" labeling strictly separate from provider-reported cost,
staleness flag at 45 days, budget `CostSource` selection (never summing
sources). **Missing:** request/credit-unit estimation (types exist, no
estimation path), stale-pricing alert kind, desktop pricing-override editor,
broader table.

## 5. Permission visibility and changes — Provider-limited

GitHub classic-PAT scopes from `X-OAuth-Scopes` (exact); Supabase privilege
from the documented key format (local read); normalized
read/write/admin/sensitive with confidence; `key permissions-diff`
before/after against a fresh read; snapshots in the audit trail. **Changes
are replacement-shaped by design** — no provider offers a documented per-key
scope edit; the product links the dashboard or routes through rotation.
Anthropic has no per-key permission concept (`unsupported`); fine-grained
GitHub token permissions are not enumerable (stated, not guessed).

## 6. Request/activity tracking + suspicious-activity alerts — Provider-limited

Official aggregates where they exist (OpenAI/Anthropic per-key daily usage,
GitHub billing quantities, Stripe Events) + local injection-session records.
**20 explainable rules** (each with evidence, window, attribution note,
confidence, recommended action): expired, expiring_soon, stale, unused,
possible_exposure, production_in_development, reused_across_projects
(`monitor.rs`); request_spike, credential_activated (dormant→active),
repeated_auth_failure, new_provider_project, new_provider_key,
unusual_model, unusual_time_pattern (local sessions, UTC-labeled, low
confidence), destination_drift, rotation_attention, access_grant_expired
(`observe.rs`); cost_spike, usage_after_disabled (`activity.rs`, both
directly unit-tested); over_budget (`budget.rs`). Plus connection-health
alerts (provider_data_stale, unmatched_provider_key,
unmapped_provider_project, provider_connection_invalid,
provider_sync_failed, documentation_changed, rotation_due, rotation_stuck).
Alert lifecycle with dedup and auto-resolve. Incremental repo monitoring
scans only new commits (`scan_repos_incremental`).

**The honest ceiling.** No per-request log exists in any official API; no
local gateway/SDK shim is built (deliberate — ADR 0014).

## 7. Duplicate credentials across projects — Fully implemented

Keyed BLAKE3 fingerprints (per-vault wrapped key), four-way classification,
reference records sharing one ciphertext, deletion protection, reuse alerts,
CLI `--allow-duplicate`/`--link-to`, desktop reuse dialog. The
equality-leak across the project-password boundary is documented (ADR 0005,
THREAT_MODEL). Extensive tests + smoke checks.

## 8. `.env` governance — Fully implemented

Lossless non-executing parser (`envfile.rs`); discovery with Git status
incl. history (`envgov.rs`); masked previews; selective import with
automatic injection mappings; `.env.example` generation; drift detection;
guided migration (plaintext removed only after vault verification);
reauth-gated atomic 0600 export with `.gitignore` verification, Git-tracked
refusal, TTL cleanup. CLI `env` group + desktop Env view. Smoke: discovery,
preview redaction, import, example, export permissions, cleanup.

## 9. Provider/API catalog — Fully implemented

Compile-time-embedded TOML manifests (5 providers) with validated detection
regexes, a 10-capability honesty matrix, and changelog/pricing/permission
URLs. CLI `provider list/show/docs/capabilities`; desktop catalog/detail.
Manifest validation tests; smoke checks assert honest non-implemented
labels.

## 10. Documentation-change notifications — Fully implemented

Conditional GETs (ETag/If-Modified-Since), BLAKE3 hashing, per-watch
intervals (`docwatch_interval_hours`, default 24), due-watch checks in every
networked monitor cycle (CLI `monitor`, desktop timer), change history
(validators/outcomes only; `provider docs-history`, desktop table incl.
last-changed), offline-safe failures, honest "not necessarily breaking"
copy. Page content is never stored or redistributed.

## 11. Git hooks and history scanning — Fully implemented

Pre-commit hook with sentinel block, foreign-hook chaining, no-unlock staged
scanning; working-tree/staged/history scanning with real line numbers;
vault matching and possibly-exposed marking; suppressions with required
reasons — add/list/**remove** in both CLI (`suppress`) and desktop
(ScanView). Desktop history depth is now user-chosen including full history
(closed this session). Smoke proves the hook blocks a real commit.

## 12. Temporary local access — Fully implemented

Access grants (`access grant/list/end`, `run --grant`): expiry windows,
atomic one-time/max-launch consumption, per-process kill timers (exit 124),
PID-tracked termination, advisory budget warnings — all labeled LOCAL
controls. This session added: injection-session listing incl. non-grant
runs (`access sessions`, desktop table) and per-session SIGTERM termination
(`access kill`, desktop confirm dialog), with the PID-liveness caveat
stated. Ending anything local never claims provider revocation.

## 13. Provider-issued temporary credentials — Provider-limited

Provider-REPORTED expiration recorded in its own column from GitHub's
official header (and Anthropic key listings), driving status with a
"provider-reported" source label. Provider-CREATED test keys
(`key test-create`: OpenAI service accounts, Supabase secret keys) with
three-way enforcement labeling (PROVIDER-ENFORCED / NOT provider-enforced /
ADVISORY-ONLY) and confirmed reauthenticated `key provider-revoke`. **No
current provider can ISSUE short-lived credentials via API — stated, never
simulated.**

## 14. Credential version history — Fully implemented

`credential_versions` retains prior values encrypted (AAD-bound to version
number), bounded (count cap + `rollback_window_days`), purged on delete;
powers sync-plan rollback with real material; reauth-gated masked listing
(`key versions`, smoke-checked); `key history` merged timeline. Versions
survive backup/restore (migration_safety completeness test).

## 15. Provider-account metadata — Partially implemented

Dedicated encrypted admin connections for **OpenAI and Anthropic**
(validated before storage, write-only, reauth to replace/remove/test — the
live test now covers both). Provider-side project/workspace/key metadata
cached with redacted values; staleness computation; last success/failure
timestamps surfaced in CLI + desktop. **Missing:** dedicated admin
connections for the remaining providers (credential-reference path works),
provider-verified org identity (nothing is invented), account email field
(see #16).

## 16. Provider-account password handling — Intentionally excluded

No provider account-password storage exists anywhere in the codebase (every
`password` reference is the vault's own master/project/backup password).
API Tracker is a credential manager for API keys, not a general password
manager; storing console login passwords would expand the threat model
(console takeover, password-reuse, 2FA-reset surface) for little benefit
over a real password manager. Preserved instead: org labels, official
`manage_url` links in every manifest, free-form notes for non-secret
account metadata.

## 17. Local desktop notifications — Fully implemented (scope stated)

Native OS notifications for new medium+ alerts, driven by an in-app
background monitor timer (`monitor_interval_minutes`, default 30, 0
disables) that runs the full shared cycle (local rules + due doc checks +
webhook delivery). Honest scope: the timer runs while the app is open and
unlocked — it is **not** an OS background service, and the UI/docs say so.
Monitor status (last run/success/failure) is persisted and shown in both
frontends (added this session).

## 18. Remote push notifications — Intentionally excluded

Push to a phone requires a relay (APNs/FCM or a hosted service),
contradicting local-first. Offered instead: **user-configured webhook
channels** — https-only (http allowed only for 127.0.0.1/::1 testing),
URL encrypted at rest and masked everywhere, severity floors, metadata-only
payloads, once-per-alert dedup with escalation re-delivery (regression
fixed + tested this session), failure retry, per-channel last-error, and a
delivery/failure history (`notify history`, desktop table).

## 19. Project templates and local stack learning — Not implemented

No template system; no dependency-manifest parsing to infer a stack.
(Lockfile awareness exists only to skip lockfiles during entropy scanning.)
Acceptance criteria and scope unchanged; owning milestone: post-alpha
usability milestone.
