# Local Gateway — Phase 1 (Architecture) Handoff

This records the state at the end of the architecture phase: what was decided,
what was proven, every adversarial finding and its resolution, and the exact
next step. Production implementation has NOT begun and is gated on this
handoff plus `IMPLEMENTATION_PLAN.md`.

## Base and branch

- Base commit: `origin/main` @ `5efec9b` (PR #13 runtime observability MERGED
  into main; this work is NOT stacked on PR #13).
- Branch / worktree: `feat/local-gateway` at
  `/Users/arnavtaduvayi/Documents/APItrack/API-Tracker-local-gateway`.
- No other developer's worktree was touched; PR #13 was not modified.

## Selected architecture (one line)

An OPTIONAL, loopback-only, path-prefix reverse gateway in a new
`crates/gateway`, forwarding pass-through credentials to registered provider
origins over verified rustls, recording metadata + bounded usage through the
existing runtime funnel, working while the vault is locked because it holds no
vault key material. Full rationale: ADR 0019.

## Feasibility questions and evidence

The spike `experiments/gateway-spike` (NOT a workspace member; not built by
CI; 11 passing tests; fmt + clippy clean) answers, with runnable evidence:

| Question | Result | Test |
|---|---|---|
| Blocking forwarder streams SSE incrementally, no body buffering | YES | `sse_streams_incrementally_and_usage_extracts` (timing-asserted) |
| Headers / status / provider errors / chunked framing preserved verbatim | YES | `provider_errors_headers_and_chunked_framing_preserved` |
| Request bodies stream upstream without buffering | YES | `request_body_streams_upstream_incrementally` |
| `Expect: 100-continue` interim relayed | YES | `expect_100_continue_interim_relayed` |
| Coalesced `100 Continue` + final in one segment does not hang | YES (blocker fix) | `coalesced_100_continue_does_not_hang` |
| Bounded usage extraction from SSE, never retaining the body | YES | `sse_streams_...`, `sse_extractor_is_bounded_under_pathological_input` (10 MiB event) |
| Observation queue never blocks forwarding (drop-and-count) | YES | `observation_queue_never_blocks_forwarding` (timing-asserted) |
| Forwarding works with no database / no vault | YES (by construction) | every forwarding test runs with no DB |
| Attribution with only the keyed fingerprint key, 5 states, zeroized | YES | `fingerprint_attribution_states_match_core` (byte-identical to `core::reuse::fingerprint`) |
| `Authorization: Bearer <key>` matches a bare-value fingerprint | YES (correctness fix) | Bearer-stripping assertions |
| SSRF policy rejects unsafe route origins | YES | `route_validation_blocks_unsafe_origins` |
| Request-smuggling shapes (TE+CL, dup CL, bare-LF, non-chunked TE) rejected | YES (hardening) | `framing_validator_rejects_smuggling_shapes` |

The spike is illustrative, not production: it deliberately does NOT implement
per-(connection,route) upstream mapping, the two-phase connect-time SSRF check,
zeroized head buffers, or the Unix-socket control channel — those are design
requirements recorded in ADR 0019 for the production crate, several of them
BECAUSE the spike's simplifications were what the adversarial review exploited.

## Adversarial review — findings and resolutions

Six independent perspectives (HTTP correctness, local security/SSRF, credential
privacy/vault crypto, desktop product, cross-platform lifecycle, repo
consistency) attacked the design. Every finding was incorporated. Blockers and
highs:

**Blockers (design was changed; would have shipped a defect):**
- Cross-route credential leak (1:1 upstream mapping vs per-request routing) →
  per-(connection,route) upstream, dial after head parse. ADR D2.
- Coalesced 100-continue hang (no seedable response-head reader) → seedable
  reader; spike-proven. ADR D2.
- Route-row-tampering credential theft (free-form origins in a same-uid DB) →
  origins never stored in / obeyed from the DB (manifest lookup + MAC'd custom
  origins, not forwarded while locked-since-boot). ADR D3.
- Post-DNS SSRF gap (`check_authority` doesn't classify DNS names) → two-phase
  `resolve_validated` on every connect. ADR D3.
- Key-handoff over unauthenticated loopback TCP → Unix socket, peer-uid,
  write-only, off the forwarding listener; never TCP/argv/env. ADR D5, SI-21.
- Vault-wide fingerprint table = online oracle → table scoped to linked,
  non-password-locked projects; references collapsed to root. ADR D5, SI-9.

**Highs (must-change; folded into the docs):**
- Upstream teardown mismatch; UntilClose / truncation connection-terminal;
  response-side hop-by-hop + `Set-Cookie` + `Access-Control-*` strip; cookie
  strip both directions; framing validation + header regeneration; bare-LF
  rejection; three timeout budgets — ADR D2, ARCHITECTURE lifecycle.
- `text/plain` no-cors write primitive → Sec-Fetch-*/Origin/Referer + credential
  gating, no row for rejected — ADR D2, SI-4.
- Windows loopback hijack → `SO_EXCLUSIVEADDRUSE`; PID-identity check
  unimplementable → per-boot nonce; fixed port → random persisted — ADR D8/D11,
  O3.
- Auth header value ≠ credential value (would always report `unmatched`) →
  scheme-strip; spike-proven — ADR D5.
- Reference records force permanent `ambiguous_duplicate`; rotated version
  mislabeled `unmatched` → root resolution + `matched_old_version` — ADR D5.
- Default-ON matching toggle + false "strictly weaker" claim → default OFF,
  TTL-bounded, retracted claim — ADR D5, THREAT_MODEL GW-6, O2.
- Raw-head buffers not zeroized → gateway-local `Zeroizing` reader; SI-7 stated
  best-effort — ADR D7, SI-7.
- macOS quarantine crash loop → fresh byte-write + de-quarantine + exec probe;
  data-dir drift → `--data-dir` argv; disable strands linked `.env`s → restore
  on disable; upgrade orphans service → version handshake — ADR D8.
- `/v1` base-path asymmetry; silent no-coverage (env not loaded) → keyless
  probe + "no traffic since link"; locked desktop has no status surface →
  lock-screen status strip + gateway commands never return `vault_locked` —
  ADR D9, PRODUCT_BEHAVIOR, THREAT_MODEL GW-13.
- `db::open` not schema-checked → `db::open_at_current_version`; gateway tables
  have no retention → extended sweep + 90-day rollup; roll-up watermark race →
  `reroll_hours` after flush — ADR D3/D6/D7, KNOWN_CONFLICTS C15–C17.

**Mediums/lows incorporated:** model-string hardening; gzip defeats extraction;
per-provider usage accumulation; HTTP_PROXY cleartext capture → NO_PROXY in
`.env`; egress-control bypass claim corrected; multiple-TE / LF-chunk framing;
HTTP/1.0 client 505; SIGTERM key-clear handler; canary extended to the key +
WAL + argv/environ; `subtle::ConstantTimeEq` + lookup off the hot path;
attribution provenance column; container non-goal; SDK variable coverage;
unmasked gateway diff; `.env.example` propagation; systemd linger; launchd
KeepAlive=Crashed; ordered uninstall manifest; Windows cut to foreground v1;
BTM Login-Items disclosure; macOS 15 Gatekeeper doc update.

**Self-correction:** an earlier draft claimed `migration_safety.rs` "greps a
fixed count" — it does not (it iterates `MIGRATIONS` dynamically). Corrected in
TEST_PLAN, IMPLEMENTATION_PLAN, KNOWN_CONFLICTS C18; the v12→v13 test goes IN
that file.

## Dependencies proposed

Zero net-new third-party crates. `socket2` (already a transitive lockfile dep)
becomes a direct dep of the gateway crate for `SO_EXCLUSIVEADDRUSE` / loopback
peer checks; the control channel uses `std::os::unix::net`. No Tokio, Hyper,
or new TLS/HTTP stack.

## Documents produced

`docs/gateway/`: PRODUCT_BEHAVIOR, ARCHITECTURE, IMPLEMENTATION_PLAN,
SECURITY_INVARIANTS, PRIVACY_MODEL, THREAT_MODEL, TEST_PLAN, KNOWN_CONFLICTS,
OPEN_DECISIONS, this HANDOFF. ADRs: `0018-runtime-observability-storage.md`
(backfilled — resolves three dangling references) and `0019-local-gateway.md`.

## Remaining external blockers

- Code signing / notarization for macOS (the relocated binary is unsigned;
  launchd execution on a quarantined alpha install must be validated at Stage 6
  — until then, foreground mode is the honest fallback). This is the only hard
  external dependency; it does not block Stages 1–5.
- Windows execution evidence (the platform has never been run) — v1 ships
  foreground-only on Windows, so this blocks only the later scheduled-task work.

## Stage-by-stage plan (summary; full detail in IMPLEMENTATION_PLAN.md)

0. Architecture (this phase) — DONE.
1. Crate skeleton + v13 migration + route store + CI wiring.
2. Forwarding core (security-critical; adversarially re-reviewed before Stage 3).
3. Route table wiring + `.env` onboarding.
4. Observation + bounded usage extraction + scoped attribution.
5. Desktop + CLI surfaces.
6. Service lifecycle (staged, reality-gated per platform).
7. Docs / honesty amendments / release classification.

## Exact next commit expected

Stage 1, commit 1: create `crates/gateway` (`api-tracker-gateway`) with
`#![forbid(unsafe_code)]`, add it to workspace members AND to the `ci.yml`
clippy/test `-p` lists and the Windows job in the SAME commit, duplicate the
`no_insecure_verifier` grep guard scoped to `crates/gateway/src`, and land the
v13 append-only migration (`gateway_*` tables, STRICT) with its upgrade test in
`crates/core/tests/migration_safety.rs`. No listener, no network surface yet.
