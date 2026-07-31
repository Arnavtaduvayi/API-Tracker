# Privacy Evidence — Independent Audit of PR #16

Method: full static trace of every write path in the repository (SQL, file
writes, logging macros, IPC DTOs, frontend storage), followed by a dynamic canary
run in an isolated `HOME` + `TETHRA_DIR` sandbox. Isolation was verified before
and after; the user's real vault was never written and contains no canaries.

**Result: one forbidden category is persisted** (`ZFT-016`). Everything else is
clean, verified both statically and by canary.

---

## 1. Canary results

Distinctive canaries planted in a fixture `.env`, then exercised through
`init`, `track --dry-run`, `track status`, `track doctor`, `project create`,
`gateway route add` and `gateway link --yes`:

| File searched | Size | Result |
|---|---|---|
| `vault.db` | 598,016 B | **HIT** — `sk-QUERYCANARY-p3z6t8-DO-NOT-PERSIST` at byte offset **527979**, and `canaryorigin-3fq9x2` at 527936, inside `gateway_project_links.prior_env_json`. **All API-key canaries: 0 hits.** |
| `vault.db-wal` | 0 B | no hits (checkpointed; `secure_delete=1`, WAL truncate on lock) |
| `vault.db-shm` | 32,768 B | no hits |
| `tracking_setups` after dry-run | 0 rows | dry-run persists nothing |
| `logs/gateway.log` | — | no hits (lifecycle lines only) |
| captured stdout (`track --dry-run`) | 6,220 B | **HIT (terminal only)** — full `DATABASE_URL` including `canarypass-v5n8q2` printed unmasked; API-key lines correctly masked as `sk-C…ST` |
| all other command stdout/stderr | 43–2,001 B | no key canaries |
| real data dir `~/Library/Application Support/api-tracker` | — | **no canaries; isolation held** |

Searches used `grep -rIa`, raw `grep -a`, and offset scans over the SQLite files
so binary storage could not hide a hit.

---

## 2. `ZFT-016` — raw URLs including query strings are persisted (MEDIUM)

**Affected user:** anyone whose linked base-URL variable previously held a URL
carrying a secret in its query string — Helicone-style `?…-api-key=…`, signed
URLs, `?api_key=…`.

**Reproduction:** set `OPENAI_BASE_URL=https://host/v1?api_key=sk-…` in `.env`,
run the tracking flow (or `tethra gateway link`), then
`SELECT prior_env_json FROM gateway_project_links` — the full URL is returned in
plaintext. Confirmed by canary at `vault.db` offset 527979.

**Expected:** the forbidden-persistence list covers "query-string values" and
"raw URLs containing queries". `envlink`'s own doc comment says only values "safe
there" are recorded.

**Actual:** `prior_value_is_recordable` (`envlink.rs:97-130`) accepts any
`http(s)` URL whose **authority** lacks `@`. It splits on `['/', '?', '#']` and
then ignores everything after — path, query and fragment are recorded verbatim.
The value also flows into `PriorVar`, which derives `Debug` + `Serialize`.

**Remediation:** record scheme + authority only (truncate at the first `/`, `?`
or `#`), or set `prior_withheld` for any value containing `?` or `#` or a
non-trivial path. Migrate existing rows by re-filtering stored priors.

---

## 3. `ZFT-017` — masking bypass prints full credentials (MEDIUM, disclosure not persistence)

`envgov::mask_assignment` (`envgov.rs:353-370`) leaves a line **untouched** when
`scanner::is_placeholder_value` matches — and that check (`scanner.rs:122-147`)
is a **substring** test for needles like `example`, `sample`, `your`, `todo`,
`xxxx`.

A real credential whose value contains any needle prints **fully unmasked**. In
the canary run, a `DATABASE_URL` containing `db.example.com` — with the password
`canarypass-v5n8q2` in its userinfo — was printed in full by
`tethra track --dry-run`, and the same string crosses the Tauri IPC boundary in
`TrackingFileDto.diff`.

This violates the repository rule *"never print full credentials in CLI output"*.
Tethra does not write it to disk, but terminal scrollback and CI log capture are
outside Tethra's control.

**Remediation:** treat the placeholder check as a display-skip only when the
*whole* value equals or starts with a placeholder pattern, or drop the exemption
entirely for context and removed lines.

---

## 4. What is persisted, column by column

The PR claims `tracking_setups` contents are "value-free". Verified field by
field:

| Store / field | Content | Class |
|---|---|---|
| `tracking_setups.{id, project_id, folder_path, state, applied_at, first_traffic_at, last_transition_at}` | UUIDs, canonical path, state enum, timestamps | SAFE |
| `tracking_setups.detection_json` | provider ids, confidence, evidence (variable **names** + relative paths), credential names, env-file paths/class/git flag, counters — **plus `NeedsOriginConfirm.inferred_origin`** | **SAFE except one value** — see `ZFT-047` below |
| `tracking_setups.plan_summary_json` | provider ids, route prefixes, file paths, booleans, port | SAFE |
| `tracking_setups.attention_reason` | only `"apply_failed:<step-id>"` / `"undo_incomplete"` — never error text | SAFE |
| `gateway_routes.{custom_origin, custom_origin_port, custom_origin_mac, …}` | validated bare host, port 443, 32-byte derived MAC | SAFE |
| `gateway_project_links.{link_slug, env_path}` | 128-bit CSPRNG routing slug (by design also in `.env`), path | SAFE (design) |
| `gateway_project_links.prior_env_json` | prior values of linked vars | **DANGEROUS** — `ZFT-016` |
| `runtime_request_events.*` | host (from the route table, never the client Host), port, method, `path_template` with query/fragment **severed before sanitization**, status, latency, byte counts, content kinds, `had_authorization` boolean | SAFE — the schema comment ("no column able to hold a body, header value, cookie, query string, or raw URL") is accurate |
| `gateway_usage_events` / `_daily` / `route_counters` | token counts, constrained model string, cost, counters | SAFE |
| `audit_events.detail` | `providers=…, files=<count>`, `prefix=…`, `custom_origin=<host>` | SAFE |
| `gateway.nonce` / `gateway.pid` | 16 random bytes hex, 0600, per boot | SAFE (local control capability, by design) |
| `logs/gateway.log` | lifecycle lines only; the gateway crate contains **zero** logging macros | SAFE |
| LaunchAgent plist / helper copy | paths, XML-escaped | SAFE |
| `session.json` | ciphertext only | SAFE |
| Desktop frontend | **no** `localStorage`, `sessionStorage` or `indexedDB` anywhere in `apps/desktop/src` or the built bundle; no window-state plugin. `LinkPlan` (file contents) is deliberately kept off the IPC boundary — DTOs carry masked diff + paths only | SAFE |
| Route snapshots / diagnostics | `RouteTable` is in-memory only; `diagnose` emits fixed strings, variable names and paths | SAFE |

### `ZFT-047` (LOW-MEDIUM) — "value-free" is literally false

`db.rs:1016` says *"never env values"*; ADR 0022 D10 says contents are
*"value-free"*. But `apply.rs:309` persists the full serialized
`ProjectDetection` as `detection_json`, which includes
`NeedsOriginConfirm { inferred_origin }` — the value read from `SUPABASE_URL`.

The crate's own test asserts this: `tests/detect.rs:339` requires
`serialized.contains("xyzcompany.supabase.co")`.

It is a manifest-declared **non-secret** value and the read is disclosed in
`DETECTION_COVERAGE`'s "one value-read exception" — so this is a wording defect,
not a secret leak. **Remediation:** amend the schema comment and D10 to
*"never secret values; may contain the confirmed non-secret origin URL"*, and
cross-reference the exception.

---

## 5. The value-read exception — verified genuinely bounded

`detect.rs:401-431`: for custom-origin providers **only**, the value of a
manifest-declared *non-secret* base-URL variable is read via `expose()`,
immediately passed through `routes::validate_origin` (https-only, bare authority,
port 443, SSRF policy), reduced to `https://host:port`, and shown for
confirmation. Rejected values increment a counter and are discarded.

The gate is `gw.origins.is_empty()` — Supabase only — and Supabase's
`env_vars = ["SUPABASE_URL"]` is disjoint from its secret variables. Only the
reconstructed `host:port` ever persists. This control is solid.

The other `expose()` call (`detect.rs:391`, the placeholder check) inspects and
discards.

---

## 6. Debug / Serialize hazards (LOW, latent)

`envlink::FilePlan.new_content` / `old_content` are plain `String`s holding the
**complete** `.env` — all secrets — and `FilePlan`, `LinkPlan` and
`tracking::plan::TrackingPlan` all `#[derive(Debug)]` with no redaction.
Serialization is protected (`#[serde(skip)]`) and a repo-wide grep shows **no
current `{:?}` call site** on them — but any future log or error wrap leaks
everything. `PriorVar.prior` likewise.

By contrast `SecretString`, `SecretBytes`, `EnvEntry.raw` and `CredentialDigest`
all have proper redacting implementations. **Remediation:** hold file contents in
`SecretString`, or write manual `Debug` impls.

Also LOW: the raw `String` at `detect.rs:270` and `envgov.rs:182` holds full
plaintext secrets and is dropped without zeroing.

---

## 7. Categories confirmed clean

Verified statically and by canary — **none of these is persisted anywhere**:
API keys, Authorization headers, cookies, request bodies, response bodies,
prompts, generated responses, raw sensitive headers, matching-key material,
route-signing material, and scanned source contents.

* Observation rows structurally cannot hold them; the query string is severed at
  `sanitize.rs:31-32` before any lasting binding.
* Attribution stores a keyed digest resolved off the forwarding path; the
  matching key and route-MAC key exist on disk only vault-wrapped.
* Errors in the new code interpolate paths, prefixes, ports and step ids — never
  values.
* Diagnostics read `.env` content only for substring presence checks and emit
  fixed strings, variable names and paths.
* Dry-run persists nothing at all.
