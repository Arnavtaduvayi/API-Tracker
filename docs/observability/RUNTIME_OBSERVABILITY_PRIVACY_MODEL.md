# Runtime API Observability — Privacy Model

This document is the authoritative specification of **what may be persisted**,
**what must never be persisted**, and **the exact sanitization algorithm** that
sits at the persistence boundary. The implementation (`crates/core/src/runtime/
sanitize.rs`) and its property tests are written to this document.

The governing principle: **metadata only**. There is no code path in this
feature capable of recording a request body, a response body, a header value,
a cookie, an authorization value, a query string, or a full URL. This is
enforced by the type system, not by a runtime filter — see §4.

---

## 1. Persisted fields (the entire allowlist)

A runtime request event stores exactly these columns and nothing else:

| Field | Type | Source | Notes |
|---|---|---|---|
| `at` | RFC3339 string | proxy clock | request start |
| `session_id` | uuid | session | |
| `project_id` | uuid | session | |
| `service_id` | uuid | inventory | one per host |
| `endpoint_id` | uuid | inventory | (service, method, path template) |
| `host` | string | CONNECT authority / SNI | hostname only, never with port-in-name or userinfo |
| `port` | int | CONNECT authority | |
| `method` | enum string | request line | GET/POST/… (fixed set; unknown → `OTHER`) |
| `path_template` | string | **sanitizer** | never a raw path — see §3 |
| `template_confidence` | enum | sanitizer | high / medium / low |
| `status_code` | int? | response status line | NULL if no response (transport error) |
| `status_class` | enum | derived | 1xx/2xx/3xx/4xx/5xx/none |
| `outcome` | enum | derived | success / client_error / auth_error / rate_limited / server_error / transport_error / tls_error |
| `latency_ms` | int? | proxy clock | request-line-sent → first-response-byte |
| `request_bytes` | int? | relay counter | measured on the wire, never from buffering |
| `response_bytes` | int? | relay counter | measured on the wire, never from buffering |
| `req_content_kind` | enum? | Content-Type **category** | parameter-stripped, closed set — see §3.4 |
| `resp_content_kind` | enum? | Content-Type **category** | " |
| `had_authorization` | bool | header **presence** | the value is never read, copied, parsed, or stored — see §3.5 |
| `protocol` | enum | negotiation | http1.0 / http1.1 / h2_opaque / websocket / connect_tunnel / plain_http |
| `observation_source` | enum | proxy | intercept / connection_only / upgrade_then_opaque |
| `transport_error` | enum? | proxy | none / dns / refused / reset / timeout / upstream_cert_invalid / proxy_error |
| `previously_known` | bool | inventory | was this endpoint seen before this event |
| `credential_id` | uuid? | attribution | only when attribution ≥ Possible |
| `attribution_confidence` | enum? | attribution | confirmed / high / possible / ambiguous / unattributed |
| `credential_version` | int? | attribution | credential `value_version` captured at launch |
| `used_current_version` | bool? | attribution | only set when provable |
| `partial_coverage` | bool | session/proxy | true when coverage was incomplete |

That is the **complete** list. `runtime_metric_buckets`,
`observed_api_services`, `observed_endpoints`, and
`credential_traffic_attributions` are all **aggregates or references** built
from the above — they introduce no new payload-derived string.

## 2. Never persisted (and cannot be, by construction)

Request bodies · response bodies · streaming chunks · Authorization values ·
Proxy-Authorization values · Cookie / Set-Cookie · raw API keys · session
tokens · raw query strings · URL fragments · form data · multipart uploads ·
GraphQL documents · AI prompts or responses · source-code payloads · uploaded
files · raw full URLs · unredacted identifiers from paths · TLS private keys ·
the local CA private key (except as vault ciphertext).

There is **no** hidden or experimental full-payload flag. There is **no**
disabled-in-UI body recorder. `grep -rniE 'record.?body|capture.?body|
full.?payload|store.?body' crates/observe crates/core/src/runtime` returns
nothing but this sentence's echoes in tests that assert their absence.

## 3. The sanitizer

`runtime::sanitize` is pure, deterministic, and has **no** database or network
access. It is the only thing permitted to turn a wire-derived string into a
stored string, and it runs **before** the value is placed into an
`ObservedRequest`.

### 3.1 Query and fragment removal (first, unconditional)

```
raw = "/v1/users/42?token=SECRET#frag"
cut at first '?' or '#'   →  "/v1/users/42"
```

The remainder after `?`/`#` is dropped **immediately** and is never assigned to
any variable that outlives the function. Query strings and fragments cannot
reach persistence because they are severed before templating even begins.

### 3.2 Bounds

- Path truncated to 512 bytes and 20 segments; overflow becomes a trailing
  `/:truncated` marker and drops `template_confidence` to `low`.
- Empty or non-`/`-leading targets → `path_template = "/:redacted"`, confidence
  `low` (e.g. `CONNECT`-only or malformed).

### 3.3 Per-segment classification

Split on `/`. For each non-empty segment, the **first** matching rule wins. A
rule that fires on a "sensitive" class replaces the whole segment with its
placeholder:

| Rule (in order) | Placeholder | Example → |
|---|---|---|
| UUID (8-4-4-4-12 hex, any case) | `:uuid` | `550e8400-e29b-41d4-a716-446655440000` → `:uuid` |
| JWT-like (`eyJ…\.…\.…`, 3 dot-parts) | `:jwt` | `eyJhbGci….sig` → `:jwt` |
| Email (`x@y.z`) | `:email` | `alice@example.com` → `:email` |
| Credential-shaped prefix (`sk-`,`sk-proj-`,`ghp_`,`gho_`,`github_pat_`,`xox[baprs]-`,`AKIA…`,`AIza…`,`glpat-`,`shpat_`,`Bearer…`) | `:token` | `sk-proj-abc123…` → `:token` |
| Long hex (≥ 16 hex chars) | `:hash` | `9f8e7d6c5b4a3210ff` → `:hash` |
| Base64/high-entropy (len ≥ 20, ≥ 3 char classes, or base64url charset len ≥ 24) | `:token` | `dGhpcyBpcyBhIHRlc3Q…` → `:token` |
| Pure digits, len ≥ 2 | `:id` | `123456` → `:id`, `98765` → `:id` |
| Filename with a sensitive embedded run (has an extension **and** contains a uuid/long-hex/≥5-digit run) | `:file` | `invoice_20240101_8842.pdf` → `:file` |
| Segment > 40 bytes, or contains non-printable/reserved chars | `:redacted` (→ confidence `low`) | |
| Otherwise **keep verbatim** | (segment) | `v1`, `users`, `chat`, `completions`, `models` kept |

Worked examples (asserted in `sanitize.rs` tests):

```
/v1/users/123456/orders/98765            → /v1/users/:id/orders/:id
/v1/files/550e8400-…-446655440000        → /v1/files/:uuid
/repos/octocat/hello/issues/42/comments  → /repos/octocat/hello/issues/:id/comments
/users/alice@example.com/profile         → /users/:email/profile
/download/report_9f8e7d6c5b4a.csv        → /download/:file
/                                        → /
(garbage / no leading slash)             → /:redacted   (confidence low)
```

Note `octocat` and `hello` are **kept** — they are low-entropy, dictionary-ish
collection/owner names, not identifiers. This is intentional: over-templating
destroys the usefulness of the endpoint table. The privacy guarantee is that
**high-entropy / identifier-shaped** segments are always replaced; stable path
structure is preserved. The property tests (§5) pin exactly this.

### 3.4 Content-Type → category

The raw `Content-Type` is **never stored**. It is mapped, parameters stripped
(everything after `;` — charset, multipart boundary — is discarded before the
map), lowercased, to a closed enum: `json`, `form`, `multipart`, `xml`, `text`,
`html`, `grpc`, `event_stream` (SSE), `octet_stream`, `graphql` (only from
`application/graphql`), `other`, or `none`. The boundary token of a multipart
upload is severed with the rest of the parameters and never seen again.

### 3.5 Authorization presence

`had_authorization` records only whether an `Authorization` request header was
**present**. The header's value is never read, copied, decoded, parsed for a
scheme, or stored. The proxy strips `Authorization`, `Proxy-Authorization`,
`Cookie`, and `Set-Cookie` from its own view immediately after using the
framing-relevant headers; only the boolean survives. This boolean is genuinely
useful (a 401 with no auth header is a different diagnosis from a 401 with one)
and leaks nothing about the credential.

## 4. Enforcement is structural, not procedural

The type returned by the sanitizer:

```rust
pub struct ObservedRequest {
    pub host: String,          // hostname only
    pub port: u16,
    pub method: HttpMethod,    // enum
    pub path_template: String, // sanitized, from sanitize_path()
    pub template_confidence: Confidence,
    pub req_content_kind: Option<ContentKind>,   // enum
    pub had_authorization: bool,
    // ... only enums / numbers / the sanitized template below here ...
}
```

`store::insert_request_event` accepts `&ObservedRequest` plus numeric/enum
measurements. **There is no function anywhere that accepts a raw path, a raw
header map, or a body and writes to the database.** A reviewer does not have to
trust that a filter is comprehensive; they only have to confirm `ObservedRequest`
has no field able to hold payload text, which is a five-line check.

## 5. Property tests (the privacy proof for sanitization)

`crates/core/src/runtime/sanitize.rs` `#[cfg(test)]` (and a dedicated
`proptest`-free deterministic generator, to avoid a new dev-dependency —
hand-rolled fuzz over thousands of composed segments) asserts:

- **P1 no-query:** for any input, the output contains no `?` and no `#`, and
  never contains any character sequence that appeared only after the first
  `?`/`#` in the input.
- **P2 no-long-digit-run:** the output contains no run of ≥ 5 digits.
- **P3 no-hex-blob:** the output contains no run of ≥ 16 hex chars.
- **P4 no-uuid:** the output matches no UUID regex.
- **P5 no-email:** the output contains no `@`.
- **P6 no-high-entropy:** every output segment has Shannon entropy below a
  fixed ceiling for its length, or is a `:placeholder`.
- **P7 idempotent:** `sanitize(sanitize(x)) == sanitize(x)`.
- **P8 bounded:** output ≤ 512 bytes, ≤ 21 segments.
- **P9 stable-structure:** known-good REST paths (a fixture list of real public
  API shapes with identifiers substituted) map to their expected templates —
  guards against over-templating regressions.

## 6. The end-to-end leakage proof

`crates/observe/tests/privacy_no_leak.rs` runs a **real** monitored HTTPS
request through the proxy where the URL path, query string, request headers
(including `Authorization: Bearer <marker>` and `Cookie: <marker>`), request
body, and response body are each stuffed with a **distinct** high-entropy
marker (fake API keys `sk-proj-LEAKCANARY…`, an email `canary@leak.test`, a
JWT, a UUID, `AI-PROMPT-CANARY`, source code, a multipart form, a phone
number). After the session ends the test asserts **every** marker is byte-for-
byte absent from:

- the SQLite database file (raw bytes) and its `-wal` / `-shm` sidecars,
- process stdout and stderr,
- the `Debug` and `Display` rendering of every public type,
- every serialized DTO / export JSON,
- the `audit_events` and `activity_events` tables,
- every temp file the session created (enumerated before/after),
- the diagnostics report.

The only place a marker legitimately appears is inside the **live relayed
bytes**, which are never captured — the test observes the provider *received*
the body (proving streaming worked) while Tethra *stored* none of it.

## 7. Retention and deletion

- Event-level rows: default **7 days** (`observability_event_retention_days`).
  Rationale: event granularity exists for recent debugging ("why did my
  deploy start throwing 401s an hour ago"); its value decays fast and its row
  count is the fastest-growing table. 7 days balances usefulness against
  unbounded growth. Configurable 1–90.
- Aggregate buckets: default **90 days** (`observability_aggregate_retention_days`).
  Rationale: trends (latency regression, volume baselines) need weeks of
  history; buckets are small and bounded (fixed histogram, coarse grain).
  Configurable 7–730.
- `retention::sweep` runs in the monitor cycle and on session end, deletes
  expired rows, and `secure_delete=ON` overwrites the freed pages.
- Deletion surfaces: by project, by session, and **delete-all-observability-
  data** (reauthentication-gated). None of these touch credentials or other
  vault data.

## 8. Export

The existing backup/export path carries these tables because they live in the
vault DB. They contain **no secrets and no payloads by construction**, so a
backup is safe by the same argument as the rest of the schema. (There is no
dedicated `observe export` command in this version; the safety argument is
structural — the schema has no column that can hold payload — not a claim about
a specific export tool.)
