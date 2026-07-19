# Feature Matrix

A definitive audit of product requirements against the **actual code**, not
prior session reports. Every claim below was verified by inspecting the
modules and tests named. Last audited: **2026-07-19, gap-closure branch**
(migrations v1–v10, backup format v2).

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
| 2 | Secret-manager synchronization | Destination-limited product-complete (9 kinds incl. OS stores; network paths fixture-tested, opt-in live-verification scripts provided) |
| 3 | Offline access | Fully implemented |
| 4 | Token-based cost estimation | Fully implemented (versioned effective-dated pricing; unknown models never estimated) |
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
| 15 | Provider-account metadata | Provider-limited (complete where official identity endpoints exist; OpenAI has none and says so) |
| 16 | Provider-account password handling | Intentionally excluded (metadata only) |
| 17 | Local desktop notifications | Fully implemented (in-app background monitor timer; not an OS service) |
| 18 | Remote push notifications | Intentionally excluded (user-configured webhooks offered instead) |
| 19 | Project templates and local stack learning | Fully implemented (9 templates; deterministic detection + local decision history — not ML) |

Cross-cutting, added at alpha completion: **complete encrypted backups**
(format v2 captures every table; older backups restore and migrate forward —
ADR 0015), **newer-schema refusal** on live vaults and backups. Added at
gap closure (ADR 0016): **master-password change** (CLI + desktop),
**project-key rotation** on every project-password set/change/remove
(fresh key, full re-encryption — old wraps become worthless), WAL
checkpoint-truncate on lock and password operations, 0600 database
permissions on Unix, symlink-refusing exports, orphaned temp-file and
dead-injection-session sweeps, and a **126-check end-to-end smoke suite**.

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

## 2. Secret-manager synchronization — Destination-limited product-complete

Destination adapters (`destinations.rs`) with per-kind capability honesty:
macOS Keychain (secret via stdin), **Linux Secret Service** (secret-tool,
value via stdin, locked-keyring failures never misreported as absent),
**Windows Credential Manager** (keyring crate; a windows-latest CI job
compiles and tests the core crate), AWS Secrets Manager (SigV4 verified against the official
test vector; **delete implemented** with the 30-day recovery window and
never ForceDeleteWithoutRecovery), GitHub Actions repository secrets
(sealed box), Vercel env vars, plus local vault/mapping/export kinds.
Reviewable sync plans (`syncplan.rs`): dry-run default, reauth-gated
execution, per-destination verification, partial-failure handling, retry,
rollback to retained versions, stale-plan refusal. Reauthenticated
`destination delete-secret` (CLI + desktop). The catalog now declares per
kind: verification method, required plan, possible charges, and testing
status. Opt-in live-verification scripts exist for AWS/GitHub
Actions/Vercel (`scripts/live_verify_{aws,github_actions,vercel}.sh`).

**The honest ceiling.** Network destinations are fixture-tested; they are
NOT marked live-verified until someone runs the opt-in scripts against
real accounts (the catalog says so per kind). Doppler/1Password/HashiCorp
Vault were evaluated and deferred (ADR 0016). GitHub/Vercel can never be
verified by value read-back — their APIs are write-only (existence checks,
labeled).

## 3. Offline access — Fully implemented

All vault operations are pure local SQLite + crypto; network entry points
require an explicit `HttpClient`. Failed syncs change nothing and prior data
stays viewable (`openai_sync.rs::offline_sync_fails_safely_...`). `monitor
--offline` skips network phases. Smoke: the offline usage report check.

## 4. Token-based cost estimation — Fully implemented

Versioned, **effective-dated** pricing (`pricing.rs`, migration v8):
bundled records for current OpenAI/Anthropic models (per-entry source URL
+ verification date, incl. cached/batch rates and the documented Sonnet 5
September price change as two dated records), validated JSON
import/export, manual overrides (override > imported > bundled), and
request-unit estimation. Estimation resolves the record effective at the
usage window's own date, so re-syncs never silently reprice history;
unknown models yield NO estimate; a `pricing_stale` alert flags records
unverified for 45+ days with recent estimated usage. Reviewable updates:
`pricing propose` → user verifies against the published page → `pricing
import` (nothing scraped, nothing silent). CLI `pricing` group + desktop
Pricing screen (records, stale flags, override editor, import/export).
Cached-token discounts are not applied to estimates (cached counts are not
broken out in usage rows) — documented; provider-reported cost stays
authoritative and strictly separate.

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
scans only new commits (`scan_repos_incremental`). **Repository-scan
exposure alerts (`repo_secret_exposure`) and coverage-gap alerts
(`repo_scan_coverage_gap`) are deliberately excluded from auto-resolve**: a
possible-secret-exposure signal never clears just because a later
incremental scan stopped re-emitting it (unchanged / unavailable / failed /
skipped repo, or the secret left the working tree but remains in history).
It stays open until an explicit resolution or a qualifying clean full
re-scan — `api-tracker scan <repo> --reverify` (or the desktop
`scan_reverify` command), which resolves the alerts only when a full
history + working-tree scan finds nothing.

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

## 15. Provider-account metadata — Provider-limited

Dedicated encrypted admin connections for **OpenAI and Anthropic**
(validated before storage, write-only, reauth to replace/remove/test);
credential-reference connections for the rest. **Provider-reported account
identity** (`provider account [--sync]`, desktop panel; migration v10):
GitHub `/user` (login, id, email, plan), Stripe `/v1/account` (account id,
email, business name), Supabase `/v1/organizations` (multiple orgs report
a count, never a guess), Anthropic `/v1/organizations/me` (org id/name) —
every field stored with its source endpoint and sync time. Manifests carry
official console-login and billing-portal URLs. **The honest ceiling:**
OpenAI's Admin API has no documented account-identity endpoint — reported
unsupported, and the user-entered org label is labeled "user-entered, not
provider-verified" everywhere. Nothing is ever derived from a credential's
appearance. Tests: `account_metadata.rs` (6).

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

## 19. Project templates and local stack learning — Fully implemented

Nine embedded templates (`templates.rs`, `templates/*.toml`): suggested
providers, environments, env-variable names with secret labeling,
credential-separation/permission/rotation guidance, docs links, suggested
destinations. Templates never contain values (a test proves no template
text matches any detection pattern); applying one creates/annotates a
project and optionally writes a names-only `.env.example` (never
overwriting) — credentials are only added by the explicit printed
commands. Stack detection (`stackdetect.rs`, migration v9) is
**deterministic rules + a locally stored confirm/dismiss history — not
ML**, and every surface says so: bounded reads of dependency manifests,
lockfiles, framework config, workflows, and `.env` variable NAMES (values
never leave the redacting parser); per-suggestion evidence + confidence;
confirmation required before anything is applied; learned data is
listable, per-repo resettable, and fully deletable. CLI `template` group +
desktop Templates screen. Tests: `templates_stack.rs` (4) + module tests.
