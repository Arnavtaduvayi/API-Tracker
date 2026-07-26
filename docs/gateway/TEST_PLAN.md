# Local Gateway — Test Plan

Only tests that exist may ever be cited in coverage claims
(`RUNTIME_COMPATIBILITY_MATRIX.md` discipline). This plan enumerates the
tests the implementation must ship, grouped by what they prove. Mock
upstreams are loopback listeners; NO test uses a real credential or makes a
live provider call. The spike tests in `experiments/gateway-spike/` are the
templates for §1–§3 and are superseded (and deleted) once their production
equivalents land in `crates/gateway`.

## 1. HTTP correctness (unit + loopback integration)

- Content-Length request/response relay, exact byte counts, carryover reuse
  on keep-alive (both sides), connection-close framing.
- Chunked request and response relay: framing echoed verbatim, trailers
  relayed, terminal-chunk detection, carryover after terminal chunk.
- SSE end-to-end: events arrive incrementally (timing-asserted, as in the
  spike), byte-identical, through BOTH close-delimited and chunked framing
  (the chunked path exercises the decoded tap).
- **Cross-route safety:** a keep-alive client sending `/openai/...` then
  `/anthropic/...` on one connection reaches TWO distinct upstreams; the
  second request's credential NEVER lands in the first upstream's connection
  (the per-(connection,route) mapping). This is the highest-severity test.
- **Coalesced `100 Continue` + final response in one segment** does not hang
  (seedable response-head reader — spike-proven in
  `coalesced_100_continue_does_not_hang`).
- `Expect: 100-continue`: interim relayed before body; upstream that sends a
  final response instead (417) — body skipped AND the client connection marked
  non-reusable; upstream that sends neither → response-side deadline reader
  proceeds with the body (no deadlock), timeout restored to the long budget.
- Response-side hop-by-hop + `Set-Cookie` + `Access-Control-*` stripped;
  `Cookie` stripped client→upstream; client-facing `Connection` regenerated.
- Upstream teardown mismatch: upstream `Connection: close` / idle-close does
  not tear down a kept-alive client; a dead cached upstream is redialed; an
  upstream close before any response byte yields a synthesized 502, never a
  silent drop.
- `UntilClose` response / truncated Content-Length / mid-chunk EOF are
  connection-terminal (forced `Connection: close`, both sockets closed, counted
  errored, never reused, never auto-retried).
- 1xx interim loop; HEAD/204/304 zero-body framing.
- Slow client with fast upstream and vice versa (backpressure, no
  accumulation — bounded RSS assertion under a multi-MB stream).
- Client disconnect mid-request and mid-response: upstream socket torn down,
  event recorded with honest transport outcome.
- Provider error statuses (401/403/429/500) relayed verbatim with headers.
- Redirects (301/302/307) relayed, never followed.
- Upgrade/WebSocket request → 501; CONNECT → 405/501; absolute-form target →
  rejected.

## 2. Request-smuggling and robustness defenses

- Reject (400 + close): Transfer-Encoding + Content-Length both present;
  duplicate/`≠1*DIGIT`/`"5, 5"`/`"+5"`/`"0x10"` Content-Length; multiple or
  non-final Transfer-Encoding codings; **bare-LF/bare-CR line endings**
  (httparse tolerates bare LF — the head is rebuilt from parsed fields with
  canonical CRLF, and header names/values containing CR/LF are rejected);
  oversized head (32 KiB) and >100 headers; chunk-size line over limit;
  malformed chunk terminator. Framing headers are REGENERATED from the
  validated value, not copied. (Spike-proven in
  `framing_validator_rejects_smuggling_shapes`.)
- LF-only chunk framing rejected in the client→upstream direction.
- Slowloris: partial head past the absolute deadline → connection dropped.
- Concurrency cap: connections over the cap receive 503 without unbounded
  queueing; cap release verified after close.
- **Browser-write rejection:** a `text/plain` no-cors POST, and any request
  bearing `Origin`/`Referer`/`Sec-Fetch-Mode: no-cors`/`Sec-Fetch-Site`≠absent
  or a CORS-safelisted Content-Type without a credential header, is refused
  and writes NO observation row/counter/alert (only `rejected_browser_origin`).
- Route prefix confusion: `/openai2/x` does not match route `openai`;
  `/openai/../anthropic/x` and percent-encoded traversal do not escape the
  route (path is normalized/validated before prefix strip); empty path,
  bare `/openai`, and query-only tails behave per spec; unknown prefix and
  unknown slug return an IDENTICAL 404.
- Host-header gate: absent, foreign (`evil.com`), `localhost.evil.com`,
  duplicate, and bare-hostname-without-port Host values are rejected;
  exact `127.0.0.1:<port>` / `localhost:<port>` / `[::1]:<port>` accepted;
  non-loopback peer rejected at accept.

## 3. Route table and SSRF

- Origin validation: https-only, port-443-only, bare-authority-only; deny
  loopback/private/link-local/CGNAT/metadata for HOSTNAMES too — feed a stub
  resolver names resolving to private/loopback/link-local addresses (not just
  IP literals, the gap the spike's IP-only test left) and assert the two-phase
  check (`check_authority` + `resolve_validated`, dial validated `SocketAddr`,
  no re-resolution) refuses them.
- **Origins are not obeyed from the DB:** a direct `UPDATE gateway_routes`
  cannot change where a manifest route forwards (origin comes from the on-disk
  manifest); a custom-origin route with an invalid/absent MAC returns 503 and
  forwards nowhere.
- Unregistered prefix → 404, nothing forwarded, no DNS performed.
- Route updates picked up via data-version polling; deleted route stops
  matching within the poll interval; last-known-good table survives DB
  unavailability.
- Custom-origin registration requires the consent path + a valid vault-derived
  MAC; manifest-origin routes match the manifest exactly.
- **Control channel:** the fingerprint key is accepted ONLY over the
  `<data-dir>/gateway.sock` Unix socket with a peer-uid check, never over the
  TCP listener (a POST to any `_tethra`-style path on the forwarding port 404s);
  a source-grep guard asserts the key never crosses TCP/argv/env; each push is
  audited.

## 4. Vault-independence and persistence degradation

- Forwarding with NO database file present (fresh boot, DB deleted).
- Forwarding with the DB held by a competing writer past busy_timeout
  (SQLITE_BUSY): events drop with counters, forwarding unaffected
  (timing-asserted: persistence stall must not add latency to the relay).
- Forwarding with `user_version` ahead of the binary (SchemaTooNew): recording
  disabled, status degraded, forwarding unaffected.
- Vault locked end-to-end: forward + record + attribution state
  `unavailable_vault_locked` (toggle off) or `matched` (toggle on, key
  resident); after `clear_key`, state degrades immediately.
- Writer queue: try_send drop-counting under flood (never blocks the relay —
  spike-proven pattern), drained on shutdown, drops surfaced.

## 5. Attribution (unit, against a real migrated in-memory DB)

- All states, including trim semantics identical to `core::reuse::fingerprint`
  (cross-checked byte-for-byte, as in the spike).
- **A full `Authorization: Bearer FAKE-TEST-...` header line matches** a
  fingerprint stored over the bare value (scheme stripped) — end-to-end, not
  just a bare value (spike-proven). `x-api-key` hashes the whole value.
- **Table scoping:** a locked/unlinked/password-locked project's fingerprints
  are ABSENT from a pushed table (asserted); references collapse to their root
  so the recommended sharing model does not force `ambiguous_duplicate`; a
  retained pre-rotation version yields `matched_old_version`, not `unmatched`.
- `ambiguous_duplicate` lists ALL genuinely-independent candidates, chooses
  none, bumps no `last_used_at`; `matched` bumps it per the confirmed-only rule
  (and the decision to let a fingerprint match bump `last_used_at` is
  documented as "some process on this machine presented this value").
- `attribution_method` = `observed_fingerprint` on value-derived rows,
  `injected` on injection-derived rows.
- Key lifecycle: handoff over the peer-checked Unix socket; zeroize-on-drop;
  SIGTERM handler clears the key before drain; no key → attribution is
  `unavailable_vault_locked` and fingerprint computation is impossible.
- Timing: the digest is computed on the forwarding path and the table lookup
  (`subtle::ConstantTimeEq`) runs on the writer thread, so no forwarding-path
  timing depends on a match (provable by construction).

## 6. Privacy canaries (raw-file scans, the repo's proof style)

Route a request with: a known fake credential (`FAKE-TEST-...`), a known
prompt marker in the request body, a known response marker, a known query
value, and a cookie. Then scan vault.db + WAL (BEFORE forcing a checkpoint AND
the main DB after) + SHM + any gateway log files + the diagnostics output +
`audit_events`/`activity_events` byte-wise and assert NONE appear. **Scan the
32-byte fingerprint key as its own canary** across the whole data dir, the
plist/unit/task files, gateway logs, and a captured snapshot of the process's
argv and environ — proving it never reaches disk or `ps`. Assert the persisted
path template contains no query material and passes the sanitize property tests
(P1–P8). Assert the persisted model string is length-capped/charset-filtered
even when the mock provider returns a hostile "model" value (never a truncated
attacker string). Assert the persisted fingerprint is the KEYED hash, never an
unkeyed `blake3::hash(value)` (pins that no plain-hash fallback exists). With
attribution disabled, assert NO `credential_id`/`attribution_method` is
written for gateway events.

## 7. Usage extraction (fixtures only)

- OpenAI SSE final-usage chunk (with `stream_options.include_usage`), no
  usage chunk (absent → `usage_available=false`, NOT a fabricated 0), oversized
  event (dropped + counted, spike-proven), `[DONE]` only.
- OpenAI non-stream JSON; Anthropic REAL SSE shape: `message_start` nested
  `message.usage` (input + cache_read + cache_creation) accumulated with
  `message_delta` output — never overwriting a populated field with null (the
  spike's fabricated flat-`usage` payload is replaced with the real shape).
- gzip/deflate response: either `Accept-Encoding: identity` was set (extraction
  works) or the exchange is counted `unsupported_shape` — never silently zero.
- Unknown provider shape → counts only, no usage row.
- Extraction never mutates relayed bytes (byte-identical relay asserted with
  extraction enabled).
- Double-count guard: a route with BOTH gateway traffic and admin sync active
  does not sum the same consumption (gateway rows never enter
  `usage_snapshots`).

## 8. Migration and store (v13)

- Fresh migrate to head; upgrade from a v12 fixture; migration is
  append-only (existing entries untouched). The v12→v13 populated-upgrade
  test goes IN `crates/core/tests/migration_safety.rs` following the existing
  `populated_v5_and_v6_tables_survive_the_upgrade` pattern — that file
  iterates `MIGRATIONS` dynamically and has NO fixed-count assertion, so
  appending v13 extends its coverage automatically (corrected after a direct
  read of the test; the earlier "greps a fixed count" claim was wrong).
  STRICT tables; backup v2 round-trip rebuilds gateway tables (backup.rs
  enumerates sqlite_master, so this is generic).
- Session lifecycle: one session per (boot × linked project), source
  `gateway`; crash → `sweep_orphaned_sessions` closes honestly; clean stop →
  `finish_session`; never silently completed.
- Roll-up/retention driven by the gateway's own timer with no vault.

## 9. Service lifecycle (per-platform, staged)

- Install/uninstall idempotence; foreign-artifact refusal without `--force`;
  `status` truthfully reports OS-will-run state (hooks.rs contract).
- **`--data-dir` argv** is baked at enable time and used by the service
  (no reliance on `TETHRA_DIR` in the service env); a `TETHRA_DIR`-isolated
  install resolves the SAME data dir from service and CLI.
- **Bind failure does not exit:** simulate a held port → the process stays up,
  retries with backoff, and `status` shows "degraded: port held" (never a
  crash loop).
- macOS: packaged-app validation that the FRESH-byte-written, de-quarantined
  copy executes under launchd on a quarantined install (KNOWN_CONFLICTS C12
  gate) — if it cannot, `enable` fails to foreground mode honestly; plist
  golden test asserts `KeepAlive={Crashed:true}`.
- Linux: unit golden test (`WantedBy=default.target`); enable/disable
  round-trip where systemd is present (skipped, not faked, elsewhere); linger
  state reported by `status`.
- Windows: v1 asserts `enable` prints "not supported" and foreground
  `run` works; a later scheduled-task impl adds golden task XML +
  `SO_EXCLUSIVEADDRUSE` on the listener.
- Upgrade: version handshake detects a stale service binary; refresh replaces
  + rewrites + kickstarts + prunes old copies; uninstall removes every artifact
  `status` lists AND restores linked `.env` files.
- **Disable restores linked `.env`s:** after `disable`, every linked project's
  base-URL line is restored to its recorded prior value (or the line removed if
  none), with per-project failure reporting.

## 10. `.env` onboarding

- Lossless rewrite via EnvDocument (quoting/comments preserved), gateway line
  shown UNMASKED in the diff, duplicates all updated, marker comment written
  (needs the additive `set_with_comment` API); the correct per-provider
  base path (`/openai/v1`, `/anthropic`) and known aliases
  (`OPENAI_API_BASE`); `NO_PROXY`/`no_proxy` extended to cover loopback;
  unlink restores the recorded prior value including the no-prior-value case
  (line removed) and the prior `no_proxy` state; files with CRLF/mixed endings.
- `generate_example` SKIPS gateway-marked lines (no empty `OPENAI_BASE_URL`
  in a committed `.env.example`).
- Per-SDK URL-join: openai-python (httpx join), openai-node (string concat),
  anthropic (both) against the two-segment `/p/<slug>/<provider>` prefix
  produce the correct upstream path.
- Link-flow keyless probe reaches the provider (401) and records a
  "no traffic since link" state; warns on a missing dotenv loader or a
  `docker-compose.yml`.
- `HTTP_PROXY` present in the environment/`.env` → link flow warns before
  writing.
- Composition with `tethra run`: monitored child reaches the loopback
  gateway directly (NO_PROXY covers loopback) — integration-asserted, not
  assumed (KNOWN_CONFLICTS C10); the observe session records the linked-to-
  gateway note so an empty observe feed next to a full gateway feed is
  explained.

## 11. Security guards (source-level)

- `forbid(unsafe_code)` at crate root.
- A `no_insecure_verifier` grep guard scoped to `crates/gateway/src`.
- A grep guard asserting no `Debug` impl in the crate prints a target with
  query material (wire.rs redaction pattern).
- CI: crate present in clippy/test `-p` lists (meta-test or checklist gate).
