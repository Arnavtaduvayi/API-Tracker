# Local Gateway — Implementation Plan

Stage-by-stage build order for the production feature, AFTER this architecture
phase. Each stage is independently commit-able, leaves the tree green, and
ships its tests. No stage begins broad production implementation in the
current (architecture) session. Ordering is chosen so the security-critical
core (forwarding, bounds, SSRF, no-persistence) is proven before any
persistence, attribution, or lifecycle surface exists.

Conventions bound by the repo: `#![forbid(unsafe_code)]`; fmt + clippy `-D
warnings`; add the crate to `ci.yml` `-p` lists and the Windows job in the
SAME commit that creates it (else zero coverage — the observe crate's
documented failure mode); duplicate the `no_insecure_verifier` grep guard
scoped to the new crate; MSRV 1.85; `rust-version.workspace`; near-zero new
dependencies.

## Stage 0 — Architecture (this session) — DONE

Docs under `docs/gateway/`, ADR 0018 backfill + ADR 0019, the isolated
feasibility spike (`experiments/gateway-spike`, 11 tests; deleted after its coverage was superseded). No production crate at that point.

## Stage 1 — Crate skeleton, schema, config (no listener yet)

- Create `crates/gateway` (`api-tracker-gateway`), add to workspace members,
  `ci.yml` `-p` lists, Windows job, `no_insecure_verifier` guard.
- v13 append-only migration: `gateway_config`, `gateway_routes`,
  `gateway_project_links`, `gateway_usage_events`, `gateway_usage_daily`
  (90-day rollup), `gateway_route_counters` (STRICT). The v12→v13
  populated-upgrade test goes IN `migration_safety.rs` (it iterates
  `MIGRATIONS` dynamically — no fixed count); gateway-behavior tests get
  their own file.
- `gateway_routes` stores provider_id + link only; upstream origins are NOT
  stored here (they are looked up from the on-disk manifest, or MAC-verified
  for custom origins) — see ADR 0019 D3.
- A `db::open_at_current_version` helper (open + assert
  `user_version == current_schema_version`, else persistence-degraded) —
  `db::open` alone does NOT check the schema. Migration v13 is applied only
  by the CLI/desktop enable/unlock flow, never by the background service.
- `ObservationSource::Gateway` variant; audit all `from_db` call sites.
- Route-store CRUD in the crate: origin validation (https/443/SSRF via
  `observe::policy`), manifest `[gateway]` origins + custom origins.
- **Exit:** migrate up/down clean, backup-v2 round-trip, route validation
  tests green. No network surface yet.

## Stage 2 — Forwarding core (the security-critical heart)

- Head read + validate (Host gate, smuggling reject: TE+CL, dup CL,
  obs-fold), head rewrite (prefix strip, hop-by-hop, Host), 1:1 upstream TLS
  (reuse `observe::tls` upstream), streaming relay (reuse `observe::relay`),
  100-continue, 1xx loop, keep-alive carryover, connection cap + 503,
  Slowloris deadline, WebSocket/CONNECT/absolute-form rejection.
- Bind loopback only; `tethra gateway run` foreground command.
- **Exit:** TEST_PLAN §1, §2, §3 green (promote the spike's HTTP tests to
  production; delete the spike once equivalents exist). *(Done: the
  production equivalents landed in Phase 2 and the spike was deleted during
  audit remediation.)* Forwarding works with
  NO database (SI-11/13). This is the stage that must be adversarially
  re-reviewed before proceeding.

## Stage 3 — Route table wiring + `.env` onboarding

- In-memory validated route table; `data_version` polling; last-known-good on
  DB unavailable/`SchemaTooNew`.
- `tethra gateway route add/list/remove`, project linking with `link_slug`.
- `.env` rewrite via `EnvDocument` + `envgov::atomic_write` +
  `render_diff` (masked) + confirm; provider-native var names; marker
  comment; unlink restores recorded prior value.
- **Exit:** TEST_PLAN §3, §10 green, including `tethra run` composition.

## Stage 4 — Observation, usage extraction, attribution

- Writer thread: bounded queue, try_send drop-and-count, short-lived
  connections, self-driven roll_up/retention timer; session per (boot ×
  link).
- Funnel integration (sanitize → ObservedRequest → insert with captured
  `at`); route-counter fallback for unlinked traffic.
- Bounded usage extractor (SSE + JSON tail), provider-scoped, model-string
  hardening; write `gateway_usage_events` (never `usage_snapshots`); cost via
  `pricing::estimate_token_cost_as_of`.
- Matching-only fingerprint attribution, five states, key handoff over the
  same-uid-authenticated control channel, `Zeroizing`, toggle.
- **Exit:** TEST_PLAN §4, §5, §6 (canaries!), §7 green.

## Stage 5 — Desktop + CLI surfaces

- Tauri commands (generate_handler + api.ts + types.ts), non-vault-gated
  status/health, reauth for consequential actions, gateway activity view
  (mirrors ApiActivityView), route-link UI (mirrors ProviderConnectionPanel
  explicit-consent), consent screen (discloses service, recording, toggle).
- Health probing in Rust (WebView CSP blocks loopback fetch).
- **Exit:** manual UX walkthrough; status truthful while locked.

## Stage 6 — Service lifecycle (staged per platform, gated by reality)

- macOS LaunchAgent + relocated-copy install; **gate:** validate a
  quarantined unsigned-alpha install actually runs under launchd
  (KNOWN_CONFLICTS C12) before claiming it works; else foreground-only +
  honest consent copy.
- Linux systemd user unit.
- Windows scheduled task behind `--experimental`, labeled (never executed on
  Windows — C13); foreground primary.
- Upgrade/repair/uninstall completeness; `status` truthfulness.
- **Exit:** TEST_PLAN §9 green per platform where execution evidence exists;
  documented limitations where it does not.

## Stage 7 — Docs, honesty amendments, release classification

- Amend `THREAT_MODEL.md` (fourth egress category), `RUNTIME_OBSERVABILITY.md`
  ("no bodies anywhere" → scoped to observe), `FEATURE_MATRIX.md` ("no OS
  service" → consented optional service), `PRODUCT_SPEC.md` if needed.
- Release classification (Experimental/Internal-alpha) with a proof list,
  mirroring the observe rollout gate; unsigned-state honesty in any
  service-install UI.

## Sequencing rationale

Security core (Stage 2) precedes all persistence and attribution so a defect
there is caught before any data or credential-matching surface exists.
Lifecycle (Stage 6) is last and reality-gated because it is the least
certain (unsigned alpha, never-run Windows) and the most reversible to defer
to foreground-only.
