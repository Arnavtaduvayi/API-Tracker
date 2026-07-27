# ADR 0025: Current tracking health is not historical verification

Status: accepted (2026-07-27) — remediation of ADR 0022 following the
independent audit of PR #16 (`ZFT-005`, `ZFT-006`, `ZFT-007`, `ZFT-008`,
`ZFT-018`).

Amends ADR 0022 D8 (the persisted tracking state machine, migration v15).

## Context

ADR 0022 D8 gave every setup one durable `state` value plus a
`first_traffic_at` watermark, with the claim — repeated in `state.rs:4-6`,
`verify.rs:10-12`, `lib.rs:12` and the v15 migration comment — that "a
stale or hand-edited row can never overclaim `traffic_observed`".

The audit reproduced three separate routes to a false "verified":

1. **Kill the gateway.** Status still read *"tracking verified — traffic
   observed"*. At that moment the user's application is **broken**: its
   `.env` points at a loopback port with nothing listening, so every API
   call fails. `state::refresh` consulted only historical event rows. It
   never checked whether the route still existed, whether the link still
   existed, whether the service was running, or how old the newest
   observation was. `ProviderFreshness.last_observed_at` was computed and
   displayed and never compared to `now`, anywhere in Rust or TypeScript.
   Event retention defaults to 7 days and is user-settable to 90, so the
   false claim persisted that long.
2. **Re-run `track` and let it fail.** The failure was reported honestly on
   screen, and the very next `track status` reported verified — having
   promoted the row off the *previous* run's traffic and nulled
   `attention_reason`, deleting the record of why setup failed.
   `upsert_setup`'s `ON CONFLICT` updated four columns, so `applied_at`,
   `plan_summary_json` and `first_traffic_at` survived a re-run.
3. **Null one column.** With `applied_at` NULL, re-derivation was skipped
   entirely: two early returns fired *before* any correction, so a row
   rendered `traffic_observed` with zero events. One nulled column defeated
   the mechanism the invariant was named for.

Mutation testing found the boundary comparison and the `observation_source`
filter — two of the mechanism's load-bearing clauses — with **zero** test
coverage.

## Decision

### D1. Separate the facts v15 collapsed

Migration v16 adds four columns and the code adds two types. The facts are
now distinct:

| Fact | Where it lives |
|---|---|
| Configuration applied | `applied_at` (per session) |
| First request ever verified | `first_verified_at` (survives re-apply) |
| Gateway currently healthy | `GatewayLiveness`, an **input** to derivation |
| Project currently observable | route + link existence, read per refresh |
| Last successful observation | `ProviderFreshness.last_observed_at` |
| Latest setup attempt | `verification_session`, `config_generation` |
| Current failure | `attention_reason` + `attention_at` |

`CurrentHealth` (what is true now) and `VerificationHistory` (what was ever
true) are separate types, returned together in `TrackingStatusReport`, and
rendered under separate headings. `CurrentHealth::is_currently_working()`
is deliberately narrow: only `VerifiedAndActive` and `PartiallyTracked`.

### D2. A verification session per attempt

Every apply or repair mints a non-secret `verification_session` id and
bumps `config_generation`. The `ON CONFLICT` branch clears the previous
attempt's `applied_at`, `plan_summary_json` and `first_traffic_at` —
an attempt that has not completed has no plan summary and no watermark.

`first_verified_at` is deliberately **not** cleared: history survives a
re-apply so "first verified: July 27" can still be shown, while
present-tense evidence does not carry over.

A completed undo clears the session, so nothing observed under it can
verify a later setup.

### D3. Present-tense success requires all of four things

`refresh_with` reports `VerifiedAndActive` only when, for every configured
provider:

1. a qualifying observation exists — this project, `observation_source =
   'gateway'`, at or after the **current session's** `applied_at`;
2. that observation is inside `OBSERVATION_FRESHNESS_SECS` (6 hours);
3. the route it arrived through still exists and is enabled;
4. the gateway answered a listener-identity probe **at the moment of this
   read**.

Liveness is a parameter rather than something `refresh` probes, so the
derivation stays a pure function of (rows, liveness) and both sides of
every branch are testable without a running service. Bulk reads pass
`Unknown`, which can never produce a present-tense success claim.

Failing (2) is not an error: an idle project reads *"verified previously —
last observed …"*. Failing (3) reads *"configuration changed since
verification"* naming the provider. Failing (4) reads *"verified
previously — the local tracking service is not running, so requests are not
reaching your APIs"*.

### D4. Less evidence is never more

Both early returns move **after** the downgrade decision. A row claiming
observation with no providers, no watermark, or in a non-watchable state
has *less* supporting evidence than a row with zero events, so it falls at
least as far — to `needs_attention` with a stated reason.

### D5. Newer bad news outranks older good news

A failure carries `attention_at`. A derived promotion never clears an
`attention_reason` that is newer than the newest observation. The converse
holds too — an observation that post-dates the failure does clear it — so
this is "newer wins", not a stuck flag.

### D6. Undo derives from ground truth, or refuses

The plan summary is persisted at the last apply step, so any earlier
failure leaves it NULL. Reading it with `.unwrap_or_default()` turned "we
do not know what apply did" into "nothing was done": both loops iterated
empty collections, `complete` stayed `true`, the row moved to
`not_configured`, and the CLI printed "Tracking stopped." while the user's
`.env` still pointed at the gateway with routes and links intact.

Undo now derives its links from `gateway_project_links`, which carry the
recorded prior `.env` state and are authoritative. When the summary is
absent **and** link rows exist, the route side cannot be reconstructed —
created and reused are indistinguishable — so undo restores what it can and
**refuses to report completion**, with a note naming what was left. An
incomplete undo keeps `applied_at`, so the next status read stays honest
about a setup that is still partly in effect.

Route provenance also survives re-apply: a second apply sees
`add_manifest_route` return `AlreadyExists` and would record the route as
merely reused, so apply reads the previous summary's `created_routes`
before the new session clears them and unions them (`ZFT-018`).

## Consequences

* A user whose project is genuinely idle for more than six hours sees
  "verified previously" rather than "verified and active". This is honest
  and is the direction that under-claims.
* `track status` exits non-zero for "verified previously": a script gating
  on tracking working must not be told yes while the service is down.
* One extra listener probe per interactive status read (~1 ms, loopback).
* `refresh` (no liveness) is kept for bulk reads and can never claim
  present-tense success; callers that need the real answer call
  `refresh_with`.

Every clause above is pinned by `crates/tracking/tests/verification_freshness.rs`
and by a mutant in `scripts/mutation_checks.sh` that removes it and requires
the test to fail. The two clauses mutation testing found uncovered — the
`at >= applied_at` boundary and the `observation_source` filter — have
dedicated tests asserting both directions.

## Alternatives considered

* **Keep one boolean and add a freshness check.** Rejected: it does not
  separate "was ever verified" from "is working now", so the historical
  fact would be lost every time the service restarted.
* **Probe liveness inside `refresh`.** Rejected: it makes the derivation
  untestable in the failing direction without a running service, which is
  exactly how the original defect survived review.
* **Expire the row after N days.** Rejected: it discards the user's
  history to fix a display problem.
