# Local Gateway — Privacy

What the gateway records, what it cannot record, where the data lives, and
how to make it go away. This is the user-facing statement; the engineering
source of truth (field-by-field allowlist, canary proof style, attribution
state machine) is `PRIVACY_MODEL.md`.

## What is persisted

For each forwarded exchange, the gateway stores **metadata only**:

- when it happened, which route and provider, and (for link-scoped traffic)
  which project;
- method class, a **sanitized path template** (`/v1/chat/completions`, with
  variable segments templated — never the raw URL), status code and class,
  outcome, latency, time-to-first-byte, and request/response sizes;
- bounded usage when the provider's response carried it: the model name
  (length-capped, charset-filtered) and token counts, plus an estimated
  cost computed from your local pricing tables;
- an **attribution state** (one of six honest labels) and, only on a match,
  the id of the matching vault credential — never the credential value and
  never the header that carried it;
- operational counters: dropped events, rejected browser-shaped requests,
  queue behavior, unlinked-traffic counts.

## What is never persisted or logged — structurally

The record type the gateway hands to its writer has **no field capable of
holding** a request body, response body, prompt, generated text, header
value, cookie, query value, credential value, or raw URL. There is nothing
to redact because there is nowhere to put the data. This is not a filter
that could regress silently: privacy canary tests drive real traffic
through a live gateway with planted marker strings in bodies, headers,
queries, and credentials, then scan every artifact on disk — the database,
its WAL, logs — for the markers.

Credential values pass through gateway memory only for the moments one
exchange needs them, in zeroizing buffers (best-effort in-process hygiene,
honestly stated: swap files and core dumps are outside its control).

## Where data lives

Everything is in your local vault database (`vault.db` in your data
directory). There is no telemetry, no analytics, no Tethra server, and the
gateway makes no network connection except to the provider origins you
registered. The service's log file (`<data-dir>/logs/gateway.log`) contains
lifecycle events only — never traffic contents or secrets.

## Retention

- Raw gateway usage events: 7 days by default.
- The daily rollup (the spend/usage series you see): ~90 days by default.
- Operational counters are swept on the same schedule.

Both windows are configuration, and the sweep runs in the gateway itself
without needing your vault password.

## What linking writes into your project files

Linking a project edits the `.env` file you chose — with a preview you
confirm — and writes only non-secret configuration: the loopback base URL
(with a random link slug), a `NO_PROXY` entry, and a marker comment naming
the route and project. The pre-link value of every touched variable is
recorded in your local database so unlink can restore the file exactly.
Base URLs and proxy lists are treated as non-secret configuration; nothing
read from your `.env` beyond those touched variables is stored, and the
file is never executed or interpolated.

## The matching key, plainly

Credential attribution is **off by default**. Turning it on hands the
gateway a derived, matching-only key: it can label observed traffic with
which of your credentials was used, and it **cannot decrypt anything**.

The disclosed trade-off: while the key is resident in gateway memory, local
software able to read that memory (or to time the database) gains an oracle
for testing whether a guessed value matches one of your credentials. That
is why pushing the key is reauthenticated, why it is dropped when the
gateway stops, when you revoke it, and when the vault locks, and why the
"keep matching while locked" toggle defaults OFF and states this exact
consequence when you flip it.

The matcher table is scoped: only credentials in projects you linked, and
never credentials in password-locked projects (traffic using those reports
`unmatched`/`unavailable` until the project is unlocked — the honest
degradation).

## Deletion

- **Unlink** restores the project's `.env` to its recorded pre-link state.
- **Disable/uninstall** stop and remove the service (uninstall also removes
  binaries, logs, and runtime files) but deliberately keep recorded history
  — it is your data.
- To purge observed history: the runtime observability deletion tools
  (`tethra observe delete-all`, or per-session deletion) cover gateway
  events too, since gateway records flow through the same runtime tables;
  retention windows bound everything else.
