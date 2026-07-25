# OpenAI usage & cost synchronization

Tethra can connect an OpenAI **administrative** account and synchronize
real usage and cost data into the local vault. Everything is local-first: the
admin key is encrypted inside your vault, every request goes directly from
your device to `api.openai.com`, and all synchronized data stays on your
computer.

## The credential: an Admin API key (not a normal API key)

The OpenAI usage, cost, and organization endpoints require an **Admin API
key**, created in the OpenAI console under
*Settings → Organization → Admin keys*
(<https://platform.openai.com/settings/organization/admin-keys>).

This is **not** an ordinary workload API key:

- it has organization-wide read access to usage, costs, projects, and API-key
  metadata;
- Tethra stores it separately from project credentials, labels it
  administrative everywhere, and encrypts it under the vault key;
- once stored it can be **replaced or removed but never displayed**;
- replacing, removing, or live-testing it requires re-entering your master
  password.

Disconnecting (`api-tracker provider disconnect openai`) deletes the
encrypted key from the vault (SQLite `secure_delete` overwrites the row).
Previously synchronized usage remains viewable offline. To fully revoke
access, also delete the admin key in the OpenAI dashboard.

## Connecting

```bash
api-tracker provider connect openai            # hidden prompt for the key
api-tracker provider connect openai --org "my-org"     # optional label
api-tracker provider connect openai --no-verify        # offline: store unvalidated
api-tracker provider connection-status openai
api-tracker provider test openai               # live test (reauthentication)
```

The key is validated against `GET /v1/organization/projects` before it is
stored (unless `--no-verify`). For scripts, the key can be supplied via the
`API_TRACKER_PROVIDER_ADMIN_KEY` environment variable or `--key-stdin` — it
is never accepted as a command-line argument.

One OpenAI organization can be connected per vault. Supporting several
organizations at once would require a schema change and is a known
limitation of the alpha.

## What is synchronized

| Data | Endpoint | Grouping | Buckets |
| --- | --- | --- | --- |
| Token usage (completions) | `GET /v1/organization/usage/completions` | provider project × API-key id × model | daily |
| Provider-reported costs | `GET /v1/organization/costs` | provider project × API-key id × line item | daily |
| Provider projects | `GET /v1/organization/projects` | — | — |
| Project API keys (metadata) | `GET /v1/organization/projects/{id}/api_keys` | — | — |

All endpoints are official and documented; pagination cursors are followed;
rate limits are respected (bounded retries honoring `Retry-After`). Metadata
(names, ids, redacted values) contains no secrets.

Currently the **token detail** covers the completions usage endpoint (chat/
completions/responses workloads). The parallel usage endpoints (embeddings,
images, audio, moderations, …) are not yet synchronized — but total **spend**
is still complete, because the costs endpoint covers every product as line
items.

```bash
api-tracker provider sync openai                 # incremental (default)
api-tracker provider sync openai --days 90       # explicit look-back
api-tracker provider sync openai --from 2026-06-01 --to 2026-07-01
```

The first sync covers a conservative 30 days. Later default syncs continue
from the last successful checkpoint, re-fetching a two-day overlap so
late-arriving provider data is reconciled. Re-syncing an overlapping window
**replaces** the previously synced rows for that window — repeated syncs
never double-count. Manually recorded usage is never touched by sync.

## Attribution: honest by design

Every synchronized record stores the dimensions the provider actually
reported and displays one of these attribution levels:

| Level | Meaning |
| --- | --- |
| `exact_credential` | The provider-side API-key id is **linked by you** to a vault credential. |
| `provider_key` | Grouped to an exact provider-side key id that is not linked locally. |
| `provider_project` | Only the provider project is known. |
| `provider_account` | Organization-level; no finer dimension was reported. |

Rules Tethra never breaks:

- Usage is **never divided among local keys** as though it were measured
  per key.
- A provider key id counts against a local credential **only after you
  confirm the association** (`provider link`). Tethra suggests a match
  when the provider's redacted value (`sk-proj...1234`) is consistent with a
  vault credential — but a suggestion is evidence, not proof, and is never
  applied automatically.
- Unlinking downgrades the affected rows back to `provider_key` attribution.
- Unmatched keys and unmapped provider projects stay visible
  (`provider keys openai`, `provider projects openai`) and raise alerts
  (`unmatched_provider_key`, `unmapped_provider_project` for projects with
  ≥ $1.00 month-to-date reported cost).

## Reported cost vs. estimated cost

These are different numbers from different sources, and Tethra keeps
them strictly separate:

- **Provider-reported cost** comes from the OpenAI costs endpoint, exactly
  as reported: amount, currency (kept verbatim; non-USD rows are excluded
  from USD totals with a note rather than silently converted), reporting
  window, and line item.
- **Estimated cost** is computed locally from synced token counts and the
  versioned, effective-dated pricing dataset (bundled + imported + manual
  overrides — see [PRICING.md](PRICING.md); price changes are modeled by
  effective date). Estimates can still differ from the bill: cached-token
  discounts, batch pricing, service tiers, and non-completions products are
  not fully modeled. Estimates are always labeled.

Budgets consume **one** configurable source — never the sum of both, which
would double-count the same consumption:

```bash
api-tracker budget source                       # show (default best_available)
api-tracker budget source provider_reported    # or: estimated / best_available
```

`best_available` uses provider-reported cost when any exists for the period,
otherwise the estimate.

## Freshness, offline behavior, and alerts

- `provider connection-status openai` shows the last successful and last
  failed synchronization; data older than `provider_stale_days` (default 3,
  configurable in settings) is flagged **stale** in the CLI, the desktop
  app, and a `provider_data_stale` alert.
- Offline or failing syncs change nothing: all pages are fetched before
  anything is written, so a failed sync can simply be retried. Previously
  synced data remains viewable offline.
- A rejected admin key marks the connection `invalid` and raises a
  `provider_connection_invalid` alert; other failures raise
  `provider_sync_failed`. Both resolve automatically on the next successful
  sync. Network failures are reported as connectivity problems — never
  mislabeled as attacks.

## Optional live verification

Normal development and the automated test suite use only mocked fixtures —
no real credential is ever required. To verify the connector against the
real API once, run:

```bash
bash scripts/live_verify_openai.sh
```

The script creates a throwaway vault in a temp directory, prompts for an
admin key without echoing it, performs read-only requests (7-day usage +
costs + metadata), prints the summaries, and deletes the throwaway vault on
exit. It never prints or saves the key or raw responses. The administration
endpoints are free of charge, but the admin key is powerful — revoke it in
the OpenAI dashboard afterwards if it was created just for the test.

## Security notes

- The admin key is encrypted with XChaCha20-Poly1305 under the vault key,
  with associated data binding it to this vault and provider.
- It is never logged, never printed, never included in errors or alerts, and
  is stripped from the environment of processes started via
  `api-tracker run`.
- Threats that local encryption cannot defend against (malware running as
  you, memory inspection) apply to the admin key exactly as to other vault
  secrets — see `THREAT_MODEL.md`.
