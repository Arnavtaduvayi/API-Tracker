# Local Gateway — Privacy Model

What the gateway sees, what it may derive, what it may persist, and the
mechanisms that make violations structurally hard. This is the gateway
counterpart of `docs/observability/RUNTIME_OBSERVABILITY_PRIVACY_MODEL.md`;
where the two differ, the differences are called out explicitly (this feature
deliberately does two things the observation proxy never does — §3 and §4).

## 1. What the gateway sees in flight (unavoidably)

The gateway is the terminating server for `http://127.0.0.1:8787`. Every
byte of every routed request and response passes through its memory: URLs
with query strings, all header values including `Authorization`/`x-api-key`,
cookies, request bodies (prompts), response bodies (generated content).
Seeing is not retaining: everything below is about what may be DERIVED and
PERSISTED from that stream.

## 2. The persistence allowlist

Persisted per request (same funnel and sanitizer as the observation proxy —
`sanitize_path` is the only wire-string-to-stored-string transformation):

| Field | Source | Notes |
|---|---|---|
| route id / provider id | gateway's own route table | never derived from client-sent Host |
| host, port | route table origin | not from the wire |
| method | request line | enum |
| path template | `sanitize_path(route-stripped path)` | query/fragment severed unconditionally first; identifiers templated |
| status code / class / outcome | response line | numeric/enum |
| latency ms, request/response byte counts | measured | numeric |
| content kinds | coarse mapping of Content-Type | enum, not the raw value |
| auth header presence | boolean | the value is handled ONLY per §4 |
| protocol, transport error | connection facts | enums |
| observation source | constant `gateway` | |
| event timestamp | captured at observation time | passed into the insert, not persist-time |
| project link / session id | gateway's own link table | never inferred from traffic content |
| usage fields | §3 extraction only | model string + token counts |
| attribution state + credential id | §4 matching only | one of five honest states |

Never persisted, never logged, structurally impossible to persist (the
record type has no field capable of holding them — same enforcement pattern
as `ObservedRequest`): request bodies, response bodies, prompts, generated
text, header VALUES, cookies, query values, raw URLs, credential values,
client-sent Host values.

Raw-file canaries: the test plan (TEST_PLAN §6) includes scans of vault.db,
its WAL/SHM sidecars, and gateway logs proving that a known fake credential
value, a known prompt string, and a known query value routed through a live
gateway appear nowhere on disk.

## 3. Bounded usage extraction (NEW capability — the delta from observe)

The observation proxy never reads body bytes. The gateway DOES inspect
response bytes in flight, under these rules:

- **Fixed allowlist out:** model identifier string, prompt/input tokens,
  completion/output tokens, total tokens, cached-token counts. Nothing else
  is ever extracted, whatever else the body contains.
- **Bounded state:** SSE responses go through an incremental event parser
  holding at most one capped event (128 KiB) plus one capped line buffer;
  oversized events are discarded wholesale and counted, never partially
  parsed (spike-proven under a 10 MiB pathological event). Non-streamed JSON
  uses a capped tail window (OPEN_DECISIONS O4). No full-body accumulation
  exists in any code path; the relay streams independently of extraction.
- **Provider-scoped and accumulating:** extractors run only for response
  shapes the route's provider declares; unknown shapes → no parsing, counts
  only. Per-provider accumulation never overwrites a populated field with
  null (OpenAI streaming yields usage only with `stream_options.include_usage`,
  which the gateway does NOT inject → `usage_available=false`, surfaced, never
  a fabricated 0; Anthropic sums `message_start` input+cache and
  `message_delta` output). Compressed responses defeat a byte scan, so
  extraction either sets the request `Accept-Encoding: identity` (documented
  wire change) or counts the exchange `unsupported_shape`; the relay never
  decompresses.
- **Model strings are constrained on write:** length-capped and
  charset-filtered before persistence (a model field echoing user input would
  otherwise be a body-content smuggling path into the DB).
- **Failure is silent-to-traffic:** extraction errors never affect the relay.

Honesty labels: extracted counts are provider-reported-in-band numbers read
from the response the provider sent, but they are recorded as LOCALLY
OBSERVED usage, never merged with admin-sync `usage_snapshots`, and cost is
always `estimated_cost_micros` via the pricing tables, never asserted.

## 4. Credential attribution and the fingerprint key

The observation proxy records only auth-header PRESENCE. The gateway adds
value-based matching, bounded as follows:

- **Mechanism:** `blake3::keyed_hash(fingerprint_key, credential_value)`
  compared against the plaintext `credentials.fingerprint` column — the exact
  ADR 0005 construction (`core::reuse::fingerprint`; spike-proven
  byte-identical). The fingerprint key CANNOT decrypt anything; it supports
  matching only. The stored fingerprint is over the SAVED value (`sk-...`),
  not the header value, so the gateway strips one leading scheme token
  (`Bearer`/`Token`, case-insensitive + OWS) and hashes the remainder, AND
  hashes the whole trimmed value (covers `x-api-key`/`api-key`/
  `x-goog-api-key`). `Basic` and any query- or cookie-borne credential are out
  of scope v1 and record `no_credential_present`. *(Without the scheme strip,
  every `Authorization: Bearer` request would falsely report `unmatched` —
  spike-proven fixed.)*
- **Scoped table, authenticated channel:** the matcher table contains only
  credentials of linked, non-password-locked projects, references resolved to
  their root; it is never vault-wide (that would be an online guess-
  confirmation oracle). The key arrives only over the `<data-dir>/gateway.sock`
  Unix socket with a peer-uid check, never over TCP/argv/env (SI-21).
- **Transient handling:** the presented value is parsed into a
  secret-wrapped buffer, hashed, and zeroized within the request scope. It
  is never stored, never logged, never placed in any queue or DTO.
- **Key custody:** the fingerprint key reaches the gateway only from an
  unlocked-vault process over the local control channel, lives only in
  `Zeroizing` memory, is dropped on gateway stop, monitoring-disable, or
  toggle-off, and never exists at rest outside its vault-key wrapping.
- **Honest states, never conflated:** `matched` (exactly one fingerprint
  row), `matched_old_version` (a still-deployed pre-rotation credential
  version), `unmatched` (no row), `ambiguous_duplicate` (the same value under
  multiple INDEPENDENT credentials — references are collapsed to their root
  first, so the vault's recommended sharing model does not force permanent
  ambiguity), `no_credential_present` (no recognized auth header),
  `unavailable_vault_locked` (no key in memory — recorded as such, NEVER as
  `unmatched`, and not retroactively rewritten: values are not retained, so
  post-unlock re-attribution of past events is impossible by design). A
  `matched` never invents provenance: the `attribution_method` column marks
  it `observed_fingerprint`, distinct from injection-derived `injected`.
- **Disclosed weakening:** while the key is resident, an attacker who can
  read gateway memory AND the database gains an offline value-confirmation
  oracle against ALL vault fingerprints — broader than the live-traffic
  exposure gateway memory already implies. This is why key retention is a
  visible, revocable setting (default per OPEN_DECISIONS O2) and why the
  consent screen names it.

## 5. Data the gateway writes about itself

Status, drop counters, degraded-recording flags, service install/uninstall
audit events: operational, content-free. Error text follows the repo rule
that no wire-derived string reaches logs without sanitization; gateway logs
contain no URLs-with-query, no header values, no body fragments.

## 6. Retention and deletion

Gateway request events ride the existing runtime retention window (7-day
events / 90-day buckets). Because the existing `retention::sweep` touches only
`runtime_request_events` and `runtime_metric_buckets`, retention is EXTENDED
(new function or params) to cover the new tables: raw `gateway_usage_events`
on the 7-day window, `gateway_usage_daily` on ~90 days (so the displayed spend
series keeps history), `gateway_route_counters` swept with the same logic. The
gateway drives `aggregate::roll_up` + the extended `retention::sweep` on a
timer (DB connection only, no vault). Uninstall ENUMERATES and deletes every
gateway table; the same deletion scopes (session/project/all, reauth-gated for
all) apply.
