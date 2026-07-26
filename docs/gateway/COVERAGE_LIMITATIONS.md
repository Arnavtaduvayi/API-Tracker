# Local Gateway — Coverage Limitations

What the gateway does **not** see, and what its numbers do **not** mean.
Every activity surface links back to these limits; none of them is a bug.
The one-line rule: **absence of recorded traffic is never evidence of
absence of traffic.**

## The gateway sees only traffic that is pointed at it

The gateway observes a request only when the client actually sends it to
`http://127.0.0.1:<port>/...`. It never intercepts anything. Traffic it
does NOT see:

- SDKs that do not read `.env` at runtime (no dotenv loader — the link
  warns heuristically when a Node project's `package.json` never mentions
  `dotenv`); the variable must reach the process's environment somehow.
- Code with a **hardcoded base URL**, or code that overrides the
  environment.
- Processes that started **before** the link and still hold the old
  environment.
- Containers/compose services with their own environment blocks
  (docker-compose does not read your linked `.env` unless wired to — the
  link warns when a compose file is present).
- Any other machine, CI, or teammate: the loopback URL is meaningless off
  this machine (which is why `.env.example` generation skips gateway
  lines).
- Anything sent to a provider you never routed, or over a disabled route
  (disabled routes answer 404).

## Protocol limits (v1)

- HTTP/1.1 only. No HTTP/2, no WebSockets, no protocol upgrades — upgrade
  requests are refused with 501, visibly, rather than half-supported.
- HTTP/1.0 clients are refused (505).

## Usage extraction limits

- **Compressed responses are never decompressed** (a zip-bomb surface), so
  they yield no token counts: the exchange is still counted, with usage
  state `unsupported_shape`.
- Providers include usage only on some responses. When it is absent, Tethra
  records **absent** — never a fabricated zero.
- For OpenAI **streaming**, usage appears only when the *caller* sets
  `stream_options.include_usage`. The gateway never injects it: request
  bodies stream through unmodified.
- Extraction is bounded (fixed window sizes); pathological responses drop
  extraction (`oversized_dropped`/`malformed`), never the forward.
- Only OpenAI- and Anthropic-shaped responses are parsed at all; other
  providers get request counts, not tokens.

## Cost estimates are lower bounds

Estimated cost uses your local pricing tables over extracted tokens.
Cache-read tokens are currently **excluded** (the estimator does not
consult cached rates), so prompt-cached workloads cost more than shown —
the estimate is deliberately a lower bound because overstating spend is the
worse failure for a budgeting tool. Estimates are never presented as
provider-billed truth.

## Attribution limits

- Attribution is **off** until the matching key is pushed; until then every
  exchange honestly records `unavailable_vault_locked`.
- Only credentials in **linked** projects are matchable, and never
  credentials in **password-locked** projects (their traffic reports
  `unmatched` until the project is unlocked).
- The state machine is honest: `matched`, `matched_old_version`,
  `unmatched`, `ambiguous_duplicate`, `no_credential_present`,
  `unavailable_vault_locked` — six states, never conflated, and a
  locked-window state is never rewritten after the fact.

## Recording gaps are explicit

Forwarding never waits on recording. The consequences are labeled, not
hidden:

- paused recording → a coverage gap for the whole window;
- a full observation queue → dropped events (counted) and a permanent gap;
- a failing database → persist failures (counted); forwarding unaffected.

Doctor surfaces all three (`coverage_gap`), and the activity views carry
the caveat inline.

## No cross-source arithmetic

- Gateway-observed usage is **never summed** with provider-reported usage
  (separate tables, separate labels, SI-19), and it does not feed budget
  alerts.
- Versus the interception proxy: every exchange is recorded under exactly
  **one** `observation_source` (`gateway` or the proxy's), so per-source
  views cannot double count. In practice a request cannot transit both: the
  link writes `NO_PROXY=127.0.0.1,...` precisely so loopback gateway
  traffic never also detours through the proxy.
- An **empty gateway view is not zero usage** — it means zero *observed*
  traffic. Provider-side truth requires the provider-usage sync (where the
  provider supports it), which remains labeled separately.
