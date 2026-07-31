# Cost estimation

## Rule

An amount is only ever reported next to what it does not cover.

## Source

`gateway_usage_events`, not `gateway_usage_daily`. The rollup's
`estimated_cost_micros` is `INTEGER NOT NULL DEFAULT 0` and the writer stores
`cost.unwrap_or(0)` into it, so an unpriced request and a genuinely free one are
the same integer there — the distinction this module exists to preserve is
already lost. The event table's column is nullable and `usage_available` /
`usage_state` record *why* a number is absent.

## Re-derived at read time

The stored per-event estimate is computed at ingest and keeps only `micros`,
discarding whether the estimate was complete. Re-deriving:

* recovers completeness;
* applies a pricing record added or corrected since the traffic arrived, which is
  the documented point of effective-dated pricing.

## Model resolution

Unchanged, and better than it first appears. `lookup_as_of` matches
case-insensitively on exact-or-substring with **longest match wins**, so:

| Reported model | Resolves to |
|---|---|
| `gpt-4o` | `gpt-4o` |
| `gpt-4o-2024-08-06` | `gpt-4o` (dated snapshot) |
| `openai/gpt-4o` | `gpt-4o` (provider prefix) |
| `gpt-4o-mini` | `gpt-4o-mini`, not `gpt-4o` (longest match) |
| `claude-sonnet-4-9` | `claude-sonnet` family fallback, **labelled** |
| `gpt-nonexistent-9` | nothing — unpriced |

Family fallbacks exist for exactly two entries (`claude-sonnet`,
`claude-haiku`) and carry the note "family-level fallback rate for model ids
without a specific entry". A coarser rate is applied only where it is labelled as
one.

One fix: `lookup_as_of` resolved the provider with bare `to_lowercase`, which
found zero records for any provider string needing alias resolution. It now uses
`providers::normalize`, which maps a known provider to its stable manifest id and
leaves an unknown one as trimmed lowercase — strictly wider, and identical for
already-canonical ids.

## Estimate metadata

Every estimate retains: amount, currency, pricing source, effective-from, last
verified, provider, **matched model**, input and output token quantities,
completeness, staleness, override flag, and the note.

`matched_model` is the record's model string that actually priced it, not the id
the caller passed in — reporting the caller's id would hide which price was
applied.

## Coverage

```text
priced_requests               priced, with an amount
priced_input_tokens / output  the tokens that amount covers
unpriced_requests             tokens known, no usable price
unpriced_tokens               those tokens
requests_with_unknown_usage   usage never reported; tokens UNKNOWN
token_coverage                priced / known tokens, or None
complete                      everything priced AND every group complete
any_stale_pricing             a record past its verification horizon
truncated                     more groups than one refresh prices
```

`token_coverage` is `None`, not `0.0`, when no tokens are known at all. `0.0`
would read as "nothing was priced" rather than "there was nothing to price".

Requests with no reported usage widen the denominator of the *cost* availability
and appear in **no** token total — adding them as zero would overstate coverage.

## Partial pricing

A record that prices output but not input produces an amount that is a **floor**.
`micros_if_complete()` returns `None` for it, and the UI renders the sentence
rather than the figure. The unpriced dimension's tokens are counted as unpriced.

## Never

* An unknown cost is never `$0.00`. `formatCostMicros` renders a sentence for a
  `null`; an unknown cost never acquires a dollar sign.
* A partial estimate is never labelled complete, and never stored as fully priced.
* A price is never invented, and a "similar" model's price is never applied
  unlabelled.
* Provider-reported cost is never summed with a local estimate (SI-19). Pinned by
  `provider_reported_cost_is_not_summed_into_the_local_estimate`, which puts a
  reported $999 in `usage_snapshots` and asserts the local estimate stays $2.50.
* Records in another currency are reported as unpriced rather than converted,
  matching how `usage.rs` already excludes non-USD reported rows.

## A real zero

Zero tokens against a known model is a real, complete `$0.0000`.
`a_known_zero_is_complete_and_differs_from_unpriced` asserts the two produce the
same integer and opposite `complete`, so only one may be shown as a total.

## Cache reads

Cache-read tokens are excluded from billable input, matching the gateway's
convention. The estimate is a documented lower bound.

## Pricing records

Only Tethra's existing bundled and imported records, through the existing
reviewable versioned process. 30 bundled entries — 17 Anthropic, 13 OpenAI —
each carrying the verification date of the source page it was checked against
(the two providers are dated independently, so re-reading one provider's pricing
cannot reset the other's staleness clock). Nothing is scraped at display time.
Unknown models stay visible and unpriced.

A model with no bundled entry resolves to no record at all rather than to a
near-neighbour: `choose_as_of` matches on equality or substring, and only
`claude-sonnet` and `claude-haiku` have family-level fallback rows. So a new
Opus or GPT id is reported unpriced until it gets its own entry — visible and
honest, never silently priced at a sibling's rate.
