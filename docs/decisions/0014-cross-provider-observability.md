# ADR 0014: Cross-provider observability

Status: accepted (2026-07-18)

Migration v7 adds usage units (`quantity`/`unit`), first-seen tracking for
provider-side entities, documentation-watch history, incremental
repository-scan state, and encrypted webhook notification channels.

## Provider audit outcomes (primary sources, 2026-07-18)

- **Anthropic** — the Admin API officially supports per-key usage grouping
  (`group_by[]=api_key_id`, alongside workspace and model), cursor
  pagination, and a cost report whose amounts are **decimal strings in
  CENTS** ("123.45" = $1.23, documented). Cost grouping is workspace-level
  only — no per-key cost exists and none is fabricated. Key listings carry
  provider-reported `expires_at`. Result: a full sync engine
  (`anthropic.rs`) replacing the org-total legacy path, with linked keys
  reaching exact-credential attribution and provider expirations flowing
  onto linked credentials. Admin connections now accept Anthropic
  (validated via `GET /v1/organizations/me`).
- **GitHub** — the Enhanced Billing usage endpoint reports metered usage
  (quantity + unitType + net amounts) at ACCOUNT level and is documented
  for **fine-grained tokens with "Plan" (read) only**; classic-PAT support
  is undocumented and the connector's errors say so. Org audit logs are
  Enterprise Cloud only (not implemented — we hold user tokens).
- **Stripe** — there is **no API for per-key request logs** (dashboard
  only, confirmed). The official Events API (secret key, 30-day retention)
  is the honest activity source: synced as daily event counts by family,
  account-level, in EVENTS. The page cap errors instead of silently
  truncating.
- **Supabase** — `usage.api` is gone from the Management API; the current
  analytics endpoints return loosely-typed rows with undocumented units at
  120 req/min. We refuse to store data whose units we cannot preserve —
  the manifest says exactly that. No audit-log API exists (Team/Enterprise
  dashboard only).
- **OpenAI** — unchanged (ADR 0011); it remains the deepest integration.

Non-token units are first-class: `usage_snapshots` gained
`quantity`/`unit`, and every surface renders them verbatim ("120 minutes",
"14 events") instead of forcing a token model.

## Request/activity tracking decision

Where official request/audit APIs exist we use them (Stripe Events; GitHub
billing quantities; OpenAI/Anthropic per-key daily usage). For the gaps,
the existing process-injection session records already provide local
request-context (who launched what, when, under which grant) — a local
gateway or SDK shim would add a mandatory-feeling moving part for marginal
data, so none was built. The decision stands until a concrete use case
demands an OPTIONAL gateway.

## Expanded rules

Ten new explainable rules (observe.rs), each emitting rule + evidence +
comparison window + attribution note + confidence + recommended response:
request spike (3x month-over-month, min 50 baseline), dormant credential
active (quiet 90→14 days ago, active since, requires older history),
repeated auth failures (3+ failed validations/24h), new provider
project/key (first-seen within 7 days — visibility notices, not
accusations), first use of a new model against an older baseline, unusual
LOCAL session hour (UTC-labeled, low confidence, needs a 10-session
baseline; provider buckets are daily and carry no time signal — stated),
destination drift, rotations needing manual attention, and expired access
grants. Nothing claims malice; wording sticks to observations.

## Incremental repository monitoring

Registered repos are baselined at first sight (HEAD recorded, history NOT
silently scanned — on-demand `scan --history` exists for that) and later
monitor runs scan only `last..HEAD` added lines (one `git rev-parse` when
idle). Findings run through the same suppression/vault-match/exposure path
as on-demand scans. History rewrites re-baseline rather than failing the
monitor. This makes background repo monitoring effectively free and
transparent (audit events record findings).

## Notifications

Local-first stays intact: native notifications remain the desktop's
channel, now driven by a background monitor timer
(`monitor_interval_minutes`, default 30, 0 disables). For optional remote
delivery the user can configure **webhook channels**: https-only URLs
(may embed a user-chosen token → encrypted under the vault key, masked
everywhere), per-channel severity floors, delivery of alert METADATA only
(alerts are secret-free by construction), per-channel failure recording,
and a stop-on-first-failure rule per run so a dead endpoint is not
hammered. No API-Tracker-hosted relay exists or is required. Webhooks are
outbound requests made on the user's explicit configuration — the same
egress posture as provider syncs.

## Documentation monitoring

Watches gained an interval (`docwatch_interval_hours`, default 24; the
monitor checks due watches when run with network access, offline-safe), a
change history (validators/outcomes only — content is never stored or
redistributed), and manifest-level changelog/pricing/permission URLs for
every provider.

## Alternatives considered

- A local request-proxy/gateway for per-request visibility — rejected for
  now (see above): substantial machinery, risks becoming de-facto
  mandatory, and provider aggregates + session records cover the stated
  questions.
- Storing Supabase analytics rows as-is — rejected: undocumented units
  would poison the "exact units preserved" guarantee.
- Hour-of-day anomaly detection on provider data — impossible honestly
  (daily buckets); implemented only for local sessions, labeled low
  confidence.

## Security implications

- Webhook URLs are the new semi-secret: encrypted at rest, masked in every
  listing, never in audit details. Delivery errors record status codes,
  not URLs.
- The monitor now touches the network (doc checks, webhooks) — every
  network phase is best-effort, offline-safe, and skippable (`--offline`).
- Repo monitoring reads only local git data; nothing leaves the machine.
