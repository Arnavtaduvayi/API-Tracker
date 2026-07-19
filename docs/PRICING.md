# Pricing and Cost Estimation

API Tracker computes **local estimates** from token counts and a versioned
pricing dataset. Estimates are always labeled, kept strictly separate from
provider-reported cost (which is authoritative wherever it is synced), and
**never invented**: an unknown model yields "estimate unavailable", not a
number.

## The dataset

Three origins, in precedence order (at equal model-match specificity):

1. **Manual overrides** (`pricing set-override`) — always win; by default
   they apply to all usage dates.
2. **Imported records** (`pricing import`) — reviewed JSON files.
3. **Bundled records** — compiled into the binary, one entry per model per
   effective date, each with its official source URL and the date it was
   last verified. Current OpenAI and Anthropic models are covered,
   including cached-input and batch rates where published.

Every record is **effective-dated**. Estimation prices usage *as of the
usage window's own date*: importing a new price never silently reprices
older usage, and re-syncs re-derive the same estimate a window originally
got. A documented future change (e.g. Claude Sonnet 5's standard pricing
from 2026-09-01) is simply two dated records. Usage older than every known
record is priced with the earliest record and the estimate's note says so.

```bash
api-tracker pricing list                      # currently effective records
api-tracker pricing list --all                # full version history
api-tracker pricing show anthropic claude-sonnet-5 --as-of 2026-09-02
```

## Updating prices (reviewable by design)

Nothing is scraped and nothing changes silently:

```bash
api-tracker pricing propose openai --out openai-pricing.json
# 1. open the provider's published pricing page (provider docs → pricing)
# 2. review/edit the JSON (prices are human-readable dollar strings)
api-tracker pricing import openai-pricing.json
```

Imports are validated strictly — negative, non-finite, overflowing, or
malformed prices and dates reject the whole file — and preserve history: a
record is replaced only when provider, model, and effective date all
match. `pricing export` writes the complete dataset for review or moving
between machines. You can also watch a provider's pricing page for changes
(`provider watch-docs`); a change raises a documentation alert, after
which the propose → review → import loop applies it.

A `pricing_stale` alert flags records last verified more than 45 days ago
for models with recent estimated usage; stale records keep estimating
(labeled stale) — staleness is made loud, never silently "fixed".

## Honest limitations

- Estimates price all input tokens at the base input rate: usage snapshots
  do not break out cached tokens, so cached-token discounts (and batch
  pricing, service tiers) are not modeled. The bill can be lower than the
  estimate. Cached/batch rates are still carried on records for display
  and imports.
- Budgets consume exactly one configurable cost source
  (`api-tracker budget source`): provider-reported, estimated, or
  best-available — never the sum of both.
- Request-unit pricing is supported (per-request records via override or
  import); no bundled per-request entries exist because none of the
  integrated providers publishes one that maps onto synced usage rows.
