# ADR 0011: Real OpenAI usage/cost synchronization and honest key attribution

Status: accepted (2026-07-18)

This milestone replaces the placeholder org-total OpenAI usage sync (ADR 0009)
with a real connector for the official OpenAI Admin ("platform") APIs: usage,
costs, and project/key metadata — plus a dedicated, vault-encrypted
administrative connection and a provider-key→local-credential mapping model.

## Confirmed official API behavior (primary sources)

Verified against the official OpenAPI specification
(`github.com/openai/openai-openapi`, spec version 2.3.0, retrieved 2026-07-18)
and the official API reference (`developers.openai.com/api/reference`):

- **Authentication:** all endpoints below use an **Admin API key**
  (`AdminApiKeyAuth`, `Authorization: Bearer <key>`), created in the
  organization console. It has organization-wide read access — it is *not* an
  ordinary workload API key and is treated as elevated.
- **Usage:** `GET /v1/organization/usage/completions` (embeddings, images,
  audio, moderations, vector stores etc. have parallel endpoints).
  `start_time` (Unix s, inclusive, required), `end_time` (exclusive),
  `bucket_width` `1m`/`1h`/`1d` (default `1d`; **limit max 31 buckets at
  `1d`**), `group_by` any combination of `project_id`, `user_id`,
  `api_key_id`, `model`, `batch`, `service_tier`; cursor pagination via
  `has_more`/`next_page` → `page`. Results carry `input_tokens` (includes
  cached), `input_cached_tokens`, `output_tokens`, `num_model_requests`, and
  the grouped dimensions (null unless grouped).
- **Costs:** `GET /v1/organization/costs`. `bucket_width` only `1d`
  (limit 1–180 buckets), `group_by` any combination of `project_id`,
  `line_item`, `api_key_id`. Results carry
  `amount: { value: number, currency: lowercase ISO-4217 }`, plus grouped
  dimensions. Cost data covers **all** products (line items), not only
  completions.
- **Metadata:** `GET /v1/organization/projects` (id, name, status) and
  `GET /v1/organization/projects/{id}/api_keys` (id, name, `redacted_value`,
  created/last-used). These are the official provider-side credential
  metadata endpoints.
- **Rate limits / errors:** standard HTTP semantics (401/403/429 with
  optional `Retry-After`); no separately documented quota for these
  endpoints.

## Decisions

1. **Per-key grouping is now used — with honest attribution.** ADR 0009
   deferred `group_by=api_key_id` because provider key ids were unmapped.
   This milestone adds the mapping model, so usage is synced grouped by
   `project_id × api_key_id × model` and costs by
   `project_id × api_key_id × line_item`. A row's *data* granularity
   (provider key / provider project / organization) is recorded separately
   from its *local* mapping:
   - `exact_credential` — only when the provider key id is linked to a vault
     credential by a **user-confirmed** association.
   - `provider_key` (new) — grouped to an exact provider-side key id that is
     **not** linked locally. Never presented as a local credential's usage.
   - `provider_project` / `provider_account` — coarser rows (missing group
     dimensions are stored as NULL, never invented).
   Redacted-value matches (provider `redacted_value` prefix/suffix vs. the
   vault value) are surfaced only as *suggestions*; they never auto-link.
2. **The administrative connection is vault-level, not a project
   credential.** New columns on `provider_connections` hold the admin key
   encrypted under the **vault key** with AAD
   `api-tracker:v1:provider-admin:{vault_id}:{provider}` — same primitives,
   no new cryptography. It is labeled administrative everywhere, is never
   revealable (replace or remove only), and disconnecting deletes the
   ciphertext (`secure_delete` is on). The legacy
   `admin_credential_id`-reference path still works as a fallback.
   One connection per provider for now; multiple organizations per provider
   would require a schema key change and is documented as a limitation.
3. **Usage rows and cost rows stay separate.** The usage API returns tokens
   (no money); the costs API returns money (no tokens) at different
   dimensions. We do not join them. Usage rows may carry a *locally
   estimated* cost (bundled pricing table); cost rows carry the
   *provider-reported* amount, its currency, and line item, exactly as
   reported. Budgets choose their source via the `budget_cost_source`
   setting (`best_available` default, `provider_reported`, `estimated`) —
   never summing both, which would double-count.
4. **Sync is fetch-all-then-replace.** All pages for the window are fetched
   into memory first; only then, in one transaction, previously synced rows
   of the same kind covering the returned buckets are deleted and fresh rows
   inserted. A mid-pagination failure changes nothing (safe retry). Manual
   rows are never touched. Checkpoints (`provider_sync_state`) record the
   last successful window; the default sync re-fetches a 2-day overlap to
   reconcile late-arriving provider data.
5. **Completions + costs first.** Token detail is synced from the
   completions usage endpoint (the dominant token workload); the parallel
   usage endpoints (embeddings, images, audio, …) are not yet synced and are
   documented as such. Total *spend* is still complete because the costs
   endpoint covers all products.
6. **Money safety.** Reported amounts are converted to integer micro-units
   with guards: non-finite, negative, or overflowing values are rejected
   (the sync fails loudly rather than storing garbage). Currency is
   preserved uppercase; non-USD rows are kept but excluded from USD totals
   with an explicit mixed-currency note.

## Alternatives considered

- **Splitting org usage across local keys proportionally** — rejected:
  fabricated attribution (spec forbids it).
- **Auto-linking on redacted-value match** — rejected: prefix+suffix match
  is strong but not proof; a wrong auto-link would silently misattribute
  spend. Suggestions + one-click user confirmation instead.
- **Storing the admin key as a regular project credential (status quo)** —
  kept only as a fallback: it forces an artificial project, mislabels an
  elevated org credential as a workload key, and couples connection life to
  project life.
- **Grouping costs by `line_item` only** — rejected: per-key reported cost
  is officially supported and is the strongest honest attribution.

## Security implications

- The admin key grants organization-wide read access; its blast radius is
  documented in THREAT_MODEL.md. It is encrypted at rest, never logged,
  never in CLI/desktop output, never in errors, and requires master-password
  reauthentication to replace, remove, or live-test.
- Provider metadata cached locally (project names, key names,
  `redacted_value`) is non-secret by the provider's own definition but is
  still local-only data.

## Future limitations

- One OpenAI organization per vault (see decision 2).
- Token detail beyond completions (embeddings/images/audio usage endpoints)
  is not yet synced.
- `user_id`-level grouping is not synced (individual-developer product; can
  be added if a use case appears).
