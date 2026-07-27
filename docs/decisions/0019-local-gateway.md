# ADR 0019: Local Gateway — an optional, loopback, path-prefix reverse gateway for local API observation

Status: accepted (2026-07-26) — architecture phase only; production implementation is gated (see "Reversal and migration" and `docs/gateway/IMPLEMENTATION_PLAN.md`).

Introduces the Local Gateway: a new crate `crates/gateway` (`api-tracker-gateway`), a `tethra-gateway` service binary, a `tethra gateway ...` CLI family, desktop panels, and migration v13 (`gateway_*` tables). Gate documents live under `docs/gateway/`: `PRODUCT_BEHAVIOR.md`, `ARCHITECTURE.md`, `SECURITY_INVARIANTS.md`, `PRIVACY_MODEL.md`, `THREAT_MODEL.md`, `TEST_PLAN.md`, `KNOWN_CONFLICTS.md`, `OPEN_DECISIONS.md`, `IMPLEMENTATION_PLAN.md`, `HANDOFF_PHASE_1.md`. This ADR records why the design is what it is; the gate documents record what it is in full. The design was validated by an isolated feasibility spike (`experiments/gateway-spike`, 11 passing tests) and hardened against a six-perspective independent adversarial review whose findings are incorporated below and enumerated in `HANDOFF_PHASE_1.md`.

## The problem this fixes

Tethra can observe a process launched through `tethra run` (ADR 0017) and can sync provider-reported usage where an admin credential exists (ADR 0011). Neither answers the common case: a developer runs their project from an IDE, terminal, or task runner and wants Tethra to know which APIs it calls and roughly what it spends — without a per-project SDK, a wrapper command, a trusted local root certificate, or an open terminal.

ADR 0014 considered a local request gateway and rejected it "until a concrete use case demands an OPTIONAL gateway"; ADR 0017 reaffirmed the binding constraints (opt-in, never ambient, never required) while superseding 0014 for the observation-proxy mechanism only. **This ADR invokes ADR 0014's escape clause for a second, distinct mechanism and supersedes its gateway stance accordingly, re-binding the same constraints:** the gateway is optional, never installed without an explicit action, and no other feature depends on it. Tethra remains fully functional with the gateway absent.

## Decisions

### D1. Path-prefix reverse gateway, blocking Rust, reusing the observe primitives

A loopback-only HTTP/1.1 server where the first path segment selects a registered provider route: `http://127.0.0.1:<port>/openai/v1/chat/completions` → `https://api.openai.com/v1/chat/completions` over certificate-verified rustls (webpki-roots, ALPN http/1.1). Credentials are PASS-THROUGH — the client sends its own key; the gateway injects nothing and needs no vault material to forward. Thread-per-connection, connection cap with 503, Slowloris head deadline. It reuses `observe::wire` (bounded head parsing), `observe::relay` (streaming backpressured body relay), `observe::policy` (SSRF), and the `observe::tls` upstream client. It does NOT link the CA/TLS-server modules — the gateway terminates no TLS toward clients and holds no certificate-authority key.

Chosen over the alternatives (see "Alternatives considered") because it is a single port, a single `.env` edit per provider per project, needs no CA and no runtime cooperation, and — unlike the interception proxy — depends on no vault-decrypted material, so it can forward while the vault is locked.

**Blocking, not Tokio/Hyper:** the reused relay's blocking copy loop IS the backpressure (a slow reader throttles a fast writer with nowhere to accumulate), which is load-bearing for the "bounded buffers" and "no body accumulation" invariants; the whole observe stack is already blocking HTTP/1.1 with these deps in the lockfile. The review confirmed the protocol-correct implementation does not become materially more dangerous in blocking form provided the framing hardening in D2 is done; it does not, so Tokio/Hyper are not adopted.

### D2. HTTP correctness is hardened well beyond the observe wire layer

The adversarial review proved that reusing observe verbatim is wrong for a reverse gateway. The production crate MUST:

- **Route per request, dial per (connection, route).** Path-prefix routing is per-request, so the upstream connection is keyed by (client connection, resolved route), never 1:1 with the client connection. The upstream is dialed AFTER the head is parsed, never at accept time. A request whose route differs from the current upstream on a kept-alive client connection gets its own upstream socket. *(Fixes the cross-route credential-leak blocker: without this, a keep-alive client sending `/openai/...` then `/anthropic/...` would ship the Anthropic key into the OpenAI TLS session.)*
- **Seed the response-head reader.** A seedable response-head reader (added to `wire`) threads bytes read past an interim (1xx) head into the next parse. *(Fixes the hang blocker: a coalesced `100 Continue` + final response in one segment otherwise loses the final head. Proven fixed in the spike's `coalesced_100_continue_does_not_hang`.)*
- **Validate framing, then regenerate framing headers.** Reject (400 + close) any head with Transfer-Encoding + Content-Length together, duplicate/`≠1*DIGIT` Content-Length, multiple or non-final Transfer-Encoding codings, or any bare-CR/bare-LF (httparse tolerates bare LF; the rewriter must not). Rebuild the forwarded head from parsed fields with canonical CRLF rather than string-splitting the raw bytes; regenerate Content-Length/Transfer-Encoding from the validated value so gateway and upstream provably agree. *(Proven in the spike's `framing_validator_rejects_smuggling_shapes`.)*
- **Sanitize the response head too.** Strip response-side hop-by-hop headers (Connection + named tokens, Keep-Alive, Proxy-*, Upgrade), regenerate the client-facing Connection header from the gateway's own reuse decision, and strip `Access-Control-*` from responses so a custom origin's CORS headers cannot make the loopback endpoint browser-readable.
- **Strip cookies both directions.** Remove `Cookie` (client→upstream) and `Set-Cookie` (upstream→client) — an explicit, documented deviation from observe's byte-for-byte rule, required because cookies ignore port and the gateway shares 127.0.0.1's cookie jar with every local dev server. No API SDK depends on cookies.
- **Handle teardown mismatch and terminal framing.** Never propagate an upstream close to a kept-alive client; probe a cached upstream for EOF before reuse and redial a dead one; treat `UntilClose` response framing, truncated Content-Length bodies, and mid-chunk EOF as connection-terminal (force `Connection: close`, close both sockets, count as errored, never auto-retry a non-idempotent streamed request); a synthesized 502 for an upstream that closes before any response byte.
- **Three timeout budgets, not one.** Short client head deadline; short-ish client body idle timeout; long upstream response idle timeout (reset per received byte) so reasoning-model latencies are not killed; the interim-read timeout is temporary and restored to the long budget before the final read.
- **Reject what it is not.** WebSocket/Upgrade → 501; CONNECT and absolute-form targets → rejected (not an open proxy); HTTP/1.0 client → 505 (cannot frame a chunked response); Host header must case-insensitively exactly equal the gateway's own loopback authority (`127.0.0.1:<port>` / `localhost:<port>` / `[::1]:<port>`), else reject.
- **Reject browser writes.** Reject any request bearing `Origin`/`Referer`, `Sec-Fetch-Mode: no-cors`, or a `Sec-Fetch-Site` other than absent (Sec-Fetch-* are forbidden headers a page cannot forge and no SDK sends), and any request with a CORS-safelisted Content-Type (text/plain, form types) that carries no credential header. Rejected requests write NO observation row, counter, or alert — only a single `rejected_browser_origin` counter. Link slugs are ≥128-bit CSPRNG, never name-derived; unknown route prefix and unknown slug return an identical 404.

### D3. Routes live in the vault DB, but upstream ORIGINS do not — the trust path excludes free-form DB rows

New v13 append-only plaintext tables (`gateway_config`, `gateway_routes`, `gateway_project_links`, `gateway_usage_events`, `gateway_usage_daily`, `gateway_route_counters`). Crucially, **`gateway_routes` stores a provider id + link slug ONLY; it does NOT store the upstream origin.** The origin is resolved at forward time from the on-disk provider manifest (`[gateway]` origins, D10), which lives in the install tree, not in the same-user-writable vault DB. User-registered custom origins (Supabase per-project refs) carry a MAC over `(vault_id, provider_id, origin, port, consent_ts)` computed under a vault-derived key at consent time; the gateway verifies the MAC before forwarding, and a custom-origin route whose MAC cannot be verified (vault locked since boot, no verification key present) is NOT forwarded (503 "custom routes unavailable while locked") — manifest routes keep forwarding. *(Fixes the route-row-tampering credential-theft blocker: a bare `UPDATE gateway_routes SET origin=...` can no longer redirect a live pass-through credential, because origins are not obeyed from the DB.)*

The SSRF check is the observe TWO-phase check on every upstream connection, not just at registration: syntax check at load AND `resolve_validated` at connect time (resolve once, filter every resolved address through `check_resolved`, dial the validated `SocketAddr`, never re-resolve). *(Fixes the post-DNS-SSRF blocker: `check_authority` alone does not classify DNS names, so a split-horizon internal FQDN with a public cert would otherwise reach the private network.)* Config/route WRITES require an unlocked vault + re-auth and are audited; the service only READS. On DB busy/missing/`SchemaTooNew`, the service keeps forwarding on the last-known-good in-memory table and flags recording degraded. A `db::open_at_current_version` helper is used for every writer flush and route load (plain `db::open` performs NO schema check); migration v13 is applied only by the enable/unlock flow, never by the background service.

### D4. Forward-while-locked is safe because the gateway holds no vault key material

This inverts observe's stop-on-lock (RO-13). Observe tears down on lock because it holds the CA signing key and decrypts TLS; the gateway holds neither, terminates no TLS toward clients, and reads no credential from the vault. A lock therefore removes nothing the forward path depends on. The one piece of vault-derived material the gateway may hold — the matching-only fingerprint key (D5) — is dropped on lock, degrading attribution honestly rather than stopping forwarding.

### D5. Attribution: matching-only fingerprint key, scoped, over an authenticated channel, default-OFF while locked

Attribution uses `blake3::keyed_hash(fingerprint_key, credential_value)` compared against the plaintext `credentials.fingerprint` column — the exact ADR 0005 construction. Five honest states: matched, unmatched, ambiguous_duplicate, no_credential_present, unavailable_vault_locked (plus a sixth, matched_old_version, for a still-deployed pre-rotation credential version). The review forced five corrections:

- **The header value is not the credential value.** The stored fingerprint is over the saved value (`sk-...`), so the gateway strips one leading scheme token (`Bearer`/`Token`, case-insensitive + OWS) and hashes the remainder, and also hashes the whole trimmed value, so both storage conventions match. `x-api-key`/`api-key`/`x-goog-api-key` hash the whole value; `Basic` and any query- or cookie-borne credential are out of scope v1 and record `no_credential_present`. *(Without this, every `Authorization: Bearer` request would be a false "shadow credential" `unmatched`. Proven fixed in the spike's Bearer-stripping assertions.)*
- **The matcher table is never vault-wide.** It contains only credentials of projects with a live `gateway_project_links` row, excluding password-locked projects unless explicitly unlocked in the pushing session, with references resolved to their root credential (so the vault's own recommended sharing model does not force permanent `ambiguous_duplicate`) and retained-version fingerprints included. *(Fixes the online-oracle blocker: a vault-wide resident table would let any local process confirm guessed values against every credential — including password-locked projects — while the vault is locked.)*
- **The key arrives over an authenticated, non-TCP channel.** A Unix-domain socket at `<data-dir>/gateway.sock` (0600 in the 0700 dir) with a peer-euid == our-uid check (LOCAL_PEERCRED/SO_PEERCRED), write-only (push/revoke, no read-back), plus a gateway-written nonce the pusher echoes so the pusher authenticates the server; Windows uses a per-user-DACL named pipe or refuses key push in v1 (attribution unavailable, labeled). The key never crosses a TCP socket, argv, or an environment variable (source-grep guarded). Each push is reauth-gated and writes an `audit_events` row. *(Fixes the key-exfiltration blocker: pushing the key to the unauthenticated forwarding port would let a port-squatter harvest it.)*
- **Default OFF while locked.** The "keep matching while locked" toggle defaults OFF (aligning the whole design with `OPEN_DECISIONS` O2 and ADR 0005). The prior "strictly weaker than reading live headers" justification is retracted: it is false on lifetime (a header is in memory for microseconds; the key persists for the KeepAlive process's weeks, outliving the vault's own auto-lock), scope (the key confirms ANY value against ALL in-scope fingerprints, not just observed ones), and capability (it converts a stolen DB into an oracle). When ON, the key's residency is TTL-bounded by the pushing session's `auto_lock_minutes`, and the consent copy states the exact consequence.
- **Provenance is distinguishable.** A new `attribution_method` column (`injected` | `observed_fingerprint`) and a distinct `matched_fingerprint` confidence keep value-derived attribution separate from injection-derived attribution, preserving the truth of `attribution.rs`'s "never reads an Authorization value" for the injection path. The constant-time compare uses `subtle::ConstantTimeEq`, and the table lookup happens on the writer thread (the forwarding path enqueues a digest), so no forwarding-path timing depends on a match.

### D6. Usage extraction is bounded, in-flight, provider-specific, and honest about gaps

A `TeeWriter` on the response relay feeds a bounded extractor (SSE incremental parser with per-event cap and dropped-oversized counting; JSON tail window) that emits ONLY model string + token counts — never body bytes; the record type has no body-capable field. The review corrected the extraction reality:

- OpenAI streaming emits usage only when the caller set `stream_options.include_usage` — which the gateway must NOT inject (the request body is streamed, not rewritten); when absent, record `usage_available=false` and surface it, never a fabricated 0.
- Anthropic SSE splits usage across `message_start` (nested `message.usage`, input + cache_read + cache_creation) and `message_delta` (output); the extractor accumulates per provider and never overwrites a populated field with null.
- gzip/deflate defeats a tail scan; when extraction is enabled for a route the gateway replaces the request `Accept-Encoding` with `identity` (a documented, deliberate wire change, acceptable on loopback dev traffic) OR gates extraction on the absence of a response `Content-Encoding` and counts those as `unsupported_shape`. The relay never decompresses (zip-bomb surface).
- The model string is the first free-form body-derived value in the schema, so it is capped (128 bytes) and charset-filtered (`[A-Za-z0-9._:@/-]`); a violation stores NULL + a `model_rejected` counter, never a truncated attacker string. It is treated as user data (can embed org/deployment/fine-tune names) subject to retention and delete-all.

Extracted usage is written to `gateway_usage_events` (raw, 7-day) and rolled into `gateway_usage_daily` (~90-day), NEVER `usage_snapshots` (prevents double-counting with admin sync, whose `totals()` sums all sources), and always labeled locally-observed with `estimated_cost_micros` via the pricing tables.

### D7. Observation persistence never blocks or fails forwarding

One dedicated writer thread, bounded `sync_channel`, `try_send` with drop-and-count (deviating from observe's blocking sink because "forwarding continues when persistence fails" is immutable and outranks "capture every event"). Events flow through the existing funnel (`sanitize_path` → `ObservedRequest`, `observation_source='gateway'`) with the captured `at` timestamp (already a funnel parameter), one session per (boot × linked project); the writer calls `sweep_orphaned_sessions` at boot, drives `aggregate::roll_up` + `retention::sweep` on a timer (no vault needed), and re-rolls the batch's hour range after each flush so the shared roll-up watermark cannot permanently exclude late-flushed events. Retention is extended to the new gateway tables; uninstall enumerates and deletes them. The request head and transiently-read credential value live only in `Zeroizing` buffers (a gateway-local head reader, since observe's `wire` buffers are plain unzeroized `Vec`s) for one exchange — SI-7 is stated as best-effort (defeated by swap/core dumps), not absolute.

### D8. Service lifecycle: per-user, consent-first, reality-gated per platform

`tethra gateway enable` (CLI) or a one-action desktop consent screen installs a per-user service. Corrections from the review:

- **macOS:** copy the binary by a FRESH byte-write (not `fs::copy`, which propagates `com.apple.quarantine`) + explicit `xattr -d` + an exec probe BEFORE writing the plist; if the probe is Gatekeeper-killed, `enable` fails honestly and points to foreground `tethra gateway serve` (alias: `run`). LaunchAgent with `KeepAlive={Crashed:true}` (crash-only, so a clean exit is terminal), stop/uninstall via `launchctl bootout gui/$UID/<label>`, restart via `kickstart -k`, never `launchctl disable`; detect absence of a GUI session. Disclose the Background-Task-Management / Login-Items entry on the consent screen.
- **The service gets `--data-dir <resolved>` in its argv**, resolved at enable time — launchd/systemd/Task Scheduler inherit no shell env, so `TETHRA_DIR` would otherwise silently drift the vault.
- **Never exit on bind failure:** the process retries bind with capped backoff and reports "degraded: port held" via status — KeepAlive respawn of a fast-exiting process is a crash loop on macOS and a permanent-fail on systemd's start-rate limit. Default the port to a random persisted high port (not fixed 8787, which is pre-squattable and collides with RStudio Server).
- **Linux:** systemd user unit (`WantedBy=default.target`); status reports linger state honestly (the unit stops at logout without `enable-linger`, which is not auto-run).
- **Windows:** foreground `tethra gateway serve` (alias: `run`) ONLY in v1; `enable` prints "not yet supported on Windows" (the platform has never been executed — KNOWN_CONFLICTS C13). A later scheduled-task implementation uses `Register-ScheduledTask`/COM (not `schtasks.exe`), a windowless launcher shim, and `%LOCALAPPDATA%` (not roaming), with `SO_EXCLUSIVEADDRUSE` on the listener (std sets neither reuse option on Windows, so a live loopback listener is hijackable).
- **Upgrade:** a version handshake on every desktop/CLI start; on mismatch, re-copy + rewrite the service definition + kickstart + prune old versioned copies — otherwise the old binary runs forever in silent `SchemaTooNew`-degraded persistence.
- **Disable/uninstall** is a single ordered manifest: stop/bootout/unregister → remove plist/unit(+wants symlink+daemon-reload)/task → **restore every linked project's `.env`** (default on; `--keep-env` escape) → delete `<data-dir>/bin` (all versions) + logs → keep DB rows. *(Disabling must not brick linked apps — that would resurrect ADR 0014's exact objection.)*

### D9. `.env` onboarding is lossless, disclosed, and proxy-safe

Rewrites via `EnvDocument` + `envgov::atomic_write` with a diff shown UNMASKED for the gateway line (it is non-secret; masking would hide the very port/slug the user must verify) and confirmation. Provider-native variable names with the correct per-provider base path (`OPENAI_BASE_URL=…/openai/v1`, `ANTHROPIC_BASE_URL=…/anthropic` — the `/v1` asymmetry is real and manifest-declared), plus known aliases (`OPENAI_API_BASE` for litellm/aider). The same write adds/extends `NO_PROXY`/`no_proxy` to cover loopback (else an ambient `HTTP_PROXY` sends the plaintext-loopback credential to a corporate proxy), and the link flow warns when `HTTP_PROXY` is set. A Tethra marker comment carries remediation text; `generate_example` skips gateway-marked lines (an empty `OPENAI_BASE_URL` in a committed `.env.example` breaks teammates). Unlink and disable restore the recorded prior value. New drift rules: gateway URL present but service disabled / no matching link / slug≠project / no_proxy missing.

### D10. Manifest additive `[gateway]` section

`origins`, `base_path`, `env_vars` (the variable names to write), and usage-shape hints, validated explicitly in `validate_manifest` (unknown TOML keys are silently ignored today). Providers with no fixed origin (Supabase) use custom-origin registration (D3) instead.

### D11. Local reachability and its honest residuals

Loopback bind only; reject any accepted connection whose peer is not loopback. No client auth token (SDKs cannot send one; requests carry the caller's own credential; the gateway grants no privilege — it forwards only to registered public origins). Listener trust is established by a per-boot 128-bit nonce written 0600 and echoed on a reserved probe path (the "verify PID + binary path" idea is unimplementable on macOS from an unprivileged process and TOCTOU regardless). Documented residuals, now in the threat model: any same-user process can forward through it (equivalent to direct provider access — but this DOES bypass per-application, not per-user, egress controls, stated honestly); a multi-user port-squat window (mitigated by random port + nonce + EADDRINUSE-is-a-hard-failure); credentials cross loopback in cleartext.

## Alternatives considered

- **Port-per-provider** — same trust properties, N ports and N configs, port-registry churn; no advantage over one path-prefixed port. Rejected.
- **Host-header routing** — an SDK cannot send a provider Host to a loopback base URL without rewriting the URL anyway; strictly worse than a path prefix. Rejected.
- **Explicit HTTP_PROXY configuration** — ambient (affects every process) or per-run (that is exactly `tethra run`/observe); CONNECT tunnels hide metadata without MITM. Rejected for this use case; observe remains for the per-run case.
- **The existing TLS interception proxy (observe)** — per-run, needs CA trust and runtime cooperation, and correctly dies on vault lock. It answers a different question (observe a process that cannot be repointed). The gateway SUPPLEMENTS it; neither deletes nor disables the other.
- **SDK / library instrumentation** — per-language, per-library install; violates the "no SDK in every project" product objective. Rejected.
- **Provider-side usage sync (ADR 0011)** — already shipped; account-level, delayed, needs an admin credential, but the only source for remote/production coverage. Kept as a separate, differently-labeled evidence class; never summed with gateway data.
- **Key-brokering gateway** (client sends a placeholder, gateway injects the real key) — requires decryptable credentials while forwarding, which violates the immutable "vault not required to complete a request" and "forward while locked". Rejected for v1; a possible future opt-in unlocked-only mode.
- **eBPF/pcap passive capture** — large privilege and platform surface, no per-request attribution without payload inspection. Rejected.

## Security implications

The gateway is the first Tethra component that (a) terminates client connections carrying live third-party credentials and (b) may hold a vault-derived key in a long-lived process. Its invariants (`SECURITY_INVARIANTS.md`) and threat model (`THREAT_MODEL.md`) are written to that stakes level: no credential/body/prompt/query/cookie ever persisted or logged (structural + raw-file canaries incl. the fingerprint key, argv, and environ); two-phase SSRF on every connection; origins never obeyed from the DB; the matching key scoped, authenticated-channel-only, and default-OFF while locked; request-smuggling rejected not normalized; browser writes rejected; everything bounded. The residuals it does NOT close (same-user reach, cleartext loopback, per-application egress bypass, port-squat window, SIGKILL leaving the key resident) are documented, not hidden. The malware-as-the-user adversary remains out of scope repo-wide; where the gateway would widen that adversary's reach, the widening is analyzed explicitly (`THREAT_MODEL.md` GW-3/GW-6/GW-7).

## Dependency choice

Target zero net-new third-party crates: rustls+ring+webpki-roots, httparse, socket2, rusqlite (bundled), base64, time, serde, zeroize, blake3, subtle are all already in the workspace lockfile via core and observe. `socket2` (already transitive) becomes a direct dependency of the gateway crate for `SO_EXCLUSIVEADDRUSE` on Windows and loopback peer checks — a direct-dep entry, no new supply-chain surface. The Unix-domain-socket control channel uses `std::os::unix::net`. No Tokio, no Hyper, no new TLS or HTTP stack.

## Coverage limitations

The gateway sees only traffic whose base URL was repointed at it, from processes on this machine that load the variable into their environment. It does not see production/remote traffic, tools that ignore the base-URL variable or construct their own URLs, hardcoded endpoints, containerized runs (127.0.0.1 is the container's own loopback — a documented v1 non-goal), or providers without a linked route. Absence of recorded traffic is never evidence of absence of traffic. Provider-side sync remains the only account-level and remote source. Product copy states this wherever coverage is shown; the release classification is Experimental/Internal-alpha with a proof list before any public claim, mirroring the observe rollout gate.

## Reversal and migration

The feature is additive and reversible. Migration v13 adds tables only; existing migrations are immutable. Backup v2 restore rebuilds the new tables structurally. Disabling restores every rewritten `.env`; uninstall removes all service artifacts and (optionally) the gateway data, leaving the vault and every other feature untouched. Because no feature depends on the gateway, it can be removed entirely by reverting the additive crate/CLI/desktop changes and dropping the v13 tables in a future migration without affecting the rest of the product. **Production implementation has NOT begun** and is gated on this ADR plus the staged plan in `IMPLEMENTATION_PLAN.md`; Stage 2 (the forwarding core) must be adversarially re-reviewed before any persistence or attribution surface is built.

## Amendments from the final independent audit (2026-07-26)

The Phase-1 body above records the design as it was decided. Several of its
statements were superseded by implementation or found false by the final
independent audit. They are left in place — rewriting a decision record to
pretend it always said the right thing destroys the audit trail — and
corrected here. Where a gate document and this ADR disagree, the gate document
plus ADR 0020/0021 are authoritative.

- **D3 (custom-origin routes).** The MAC now binds `route_prefix` as well
  (v2 domain string), and the verification key is actually installed into a
  running gateway — before remediation `RouteState::set_mac_key` had no
  callers, so every custom-origin route was permanently 503. Full lifecycle:
  **ADR 0021**.
- **D5 (matching key).** "Dropped on lock, default OFF while locked,
  TTL-bounded" was designed here and implemented nowhere. All three now hold,
  and the TTL this ADR deferred is decided. Full lifecycle and reasoning:
  **ADR 0020**.
- **D5 (control channel), line 53.** "peer-euid == our-uid check
  (LOCAL_PEERCRED/SO_PEERCRED)" — not implemented, and not implementable
  without `unsafe` or a new dependency this ADR rules out. The gate is
  filesystem permissions re-checked on every accept (HANDOFF_PHASE_2 D3,
  SECURITY_INVARIANTS SI-21).
- **D1/D2 (observe reuse).** `observe::wire` and `observe::relay` are FORKED,
  not reused unchanged, for stated security reasons (gateway ARCHITECTURE,
  "Forked from observe").
- **Line 41 ("the service only READS").** True of configuration only: the
  service's writer thread writes counters, usage rows, and retention deletes.
- **Line 70 ("uninstall enumerates and deletes them").** Uninstall keeps
  recorded history by design; `observe delete-all` is what clears the gateway
  tables — and until remediation it did not reach them at all.
- **Line 77 ("`--data-dir <resolved>`").** The path was not absolutized until
  remediation; it now is, at the single entry point in both frontends.
- **Line 80 (Windows `enable` "not yet supported").** `enable` registers an
  HKCU `Run` value; the platform remains compile-validated only.
- **Line 121 ("production implementation has NOT begun").** Superseded by the
  Phase 3 amendments below.

## Phase 3 amendments (productization)

Recorded 2026-07-26 at the end of the productization phase. The sentence
"Production implementation has NOT begun" above is retained as the Phase 1
record and is superseded: Phase 2 shipped the core (see
`docs/gateway/HANDOFF_PHASE_2.md`, including its deviations D1–D7) and
Phase 3 shipped the productization (`docs/gateway/IMPLEMENTATION_STATUS.md`).
Deviations this phase, each preserving the underlying product goal:

- **O5 (Windows) — mechanism code ships, platform stays unvalidated.** The
  per-user HKCU `Run`-value lifecycle is implemented via `reg.exe`
  (no new dependencies, no elevation, visible in Task Manager → Startup),
  compiled and unit-tested on Windows CI — but the platform has still never
  executed a gateway, every status surface reports
  `RegisteredButNeverValidated`, and foreground `tethra gateway serve`
  remains the supported Windows mode. This ships the mechanism O5 deferred
  while keeping O5's honesty: no Windows behavior is claimed validated.
- **No `.env` backup file.** D9's restore guarantee is implemented from the
  recorded prior state in `gateway_project_links.prior_env_json`
  (versioned JSON, captured before any write) plus the atomic
  same-directory temp-file write — deliberately NOT a `.env.bak` sibling: a
  copy of a secrets file under a name no `.gitignore` covers is a leak
  primitive. Restore honors user edits (a value changed after linking is
  left alone and reported), and a failed file keeps the link row for retry.
- **D11 realized as challenge–response.** The reserved probe path is
  `GET /_tethra/probe?c=<hex>`, answered with
  `keyed_hash(derive_key("tethra gateway listener probe v1", nonce), challenge)`.
  The caller (who can read the 0600 nonce file) verifies the proof, so
  listener identity is provable without the nonce — a live control
  capability — ever crossing the unauthenticated TCP socket. Status,
  doctor, link-time probes, and the Windows stop path all verify identity
  this way before trusting the port.
- **`ACCEPT_POLL` 50 ms → 5 ms, on measurement.** The non-blocking accept
  loop's 50 ms shutdown-flag wake added ~25 ms average (up to 50 ms) to
  every fresh connection: measured churn overhead was +47 ms/connection
  and concurrent p99 55 ms. At 5 ms, churn overhead fell to
  +1.7 ms/connection and throughput tripled, with no measurable idle cost
  (`docs/gateway/PERFORMANCE_RESULTS.md`).
- **Custom-only `[gateway]` manifests (C11).** `supabase.toml` declares
  `origins = []` with `env_vars = ["SUPABASE_URL"]`: the `.env` metadata is
  declarative while route registration for such providers is refused by
  `add_manifest_route` and pointed at the MAC'd custom-origin flow. The
  manifest validator accepts empty origins only when env metadata exists.
- **Foreign-install refusal.** `install` refuses to replace a service
  definition whose `--data-dir` names a DIFFERENT data directory unless
  `--force`: the per-user login slot is a shared resource between vaults,
  and silently stealing it would break the other vault's gateway at the
  next login.
- **D4 resolved.** The shipped verb is `serve`; `run` is a full clap alias
  of the same command, so both documented names mean the same thing.
