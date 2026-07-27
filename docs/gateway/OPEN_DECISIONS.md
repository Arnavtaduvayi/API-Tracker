# Local Gateway — Open Decisions

Decisions deliberately NOT finalized in the architecture phase. Each has an
owner-moment (the stage in IMPLEMENTATION_PLAN.md where it must be closed), a
default, and the evidence that would change the default. Nothing here blocks
starting Stage 1.

## O1. Does gateway-observed spend feed budget/alert rules?

Provider-reported usage drives budgets today (`usage_snapshots`); gateway
usage is a separate, locally-observed series (KNOWN_CONFLICTS C8).
**Default:** v1 displays gateway spend estimates but does NOT feed budget
alert rules (avoids double-alerting and precision laundering).
**Close at:** Stage 5 (UI). Changes if users need budget alerts without an
admin credential — then a rule can opt into the gateway series explicitly,
labeled as an estimate.

## O2. Default state of the locked-vault matching key toggle

PRIVACY_MODEL §4: the in-memory fingerprint key enables credential matching
while the vault is locked; retaining it is a consented, revocable, disclosed
weakening of ADR 0005's locked-vault posture.
**Default:** ship the toggle default-OFF for v1 (attribution while locked
degrades to `unavailable_no_key`); flip to default-ON only with user
feedback that the degraded state is confusing in practice.
**Close at:** Stage 4 (attribution). The adversarial privacy review argued
default-OFF is the honest reading of ADR 0005; the counterargument (the same
attacker already reads live headers in gateway memory) covers observed
credentials only, not the whole vault's fingerprints.

## O3. Port default — RESOLVED to random persisted high port

The adversarial review showed a fixed 8787 is pre-squattable before Tethra is
even installed (and collides with RStudio Server), and that "verify listener
identity by PID + binary path" is unimplementable on macOS from an
unprivileged process and TOCTOU regardless.
**Resolved:** a random high port chosen at enable time and persisted in
`gateway_config`; listener trust uses a per-boot 128-bit nonce (written 0600,
echoed on a reserved probe path) that status / link / `.env`-write re-verify;
`EADDRINUSE` at startup is a hard failure shown red in status, and the process
retries bind with backoff rather than exiting. Recorded in ADR 0019 D8/D11.

## O4. Non-streaming JSON usage extraction: tail-window size and shape set

SSE extraction is spike-proven. For non-streamed JSON responses the plan is a
bounded tail-window scan (usage objects sit at the end of OpenAI/Anthropic
response bodies).
**Default:** 64 KiB tail window, OpenAI + Anthropic chat shapes only; all
other shapes record counts without usage.
**Close at:** Stage 4, with fixture-driven tests against recorded real
response shapes (fixtures, never live calls).

## O5. Windows service mechanism

Scheduled task at logon vs manual instructions.
**Default:** ship `tethra gateway run` (foreground) as the only supported
Windows mode in v1; the scheduled-task installer lands behind an
`--experimental` flag, honestly labeled (platform has never been executed —
KNOWN_CONFLICTS C13).
**Close at:** Stage 6, only with real Windows execution evidence.

## O6. Desktop live-activity refresh

The desktop is poll-only today (30s); a "live" gateway feed would introduce
the app's first event-push pattern.
**Default:** reuse polling (5–30s tiers) in v1; no event push.
**Close at:** Stage 5.

## O7. Per-link path slugs vs bare provider prefixes as the written default

Both forms route (`/p/<link-slug>/openai/...` and `/openai/...`).
**Default:** the `.env` writer always emits the link-scoped form (exact
project attribution); bare prefixes exist for hand-configured clients and
are surfaced as "unlinked traffic".
**Close at:** Stage 3, after checking real SDK URL-join behavior against the
two-segment prefix (product challenge flagged URL-normalization risk).

## O8. HTTP/2 upstream

rustls ALPN is pinned to http/1.1 end to end (matches observe). Providers all
accept 1.1 today.
**Default:** keep 1.1; revisit only if a routed provider degrades 1.1
service.
**Close at:** revisit post-v1; requires a real protocol need, not
speculation.

## O10. Desktop binary delivery: Tauri externalBin vs CLI-first

The review flagged that D8's "desktop enable copies `tethra-gateway`"
contradicts the absence of any Tauri `externalBin` entry today — inside the
shipped `.app` there is no `tethra-gateway` binary to copy.
**Default:** v1 desktop enable requires the CLI archive present (locates
`tethra-gateway` on PATH / known layout) and says so honestly when absent;
bundling `tethra-gateway` as an `externalBin` (inheriting the app's
quarantine state) is deferred until the signing path exists.
**Close at:** Stage 5/6. Changes if `externalBin` bundling lands earlier.

## O11. Manifest base-path and variable set per provider

The `/v1` placement differs per SDK (OpenAI joins base + `/chat/completions`
so its base must end `/v1`; Anthropic sends `/v1/messages` so its base must
NOT include `/v1`), and some tools use a different variable
(`OPENAI_API_BASE`).
**Default:** the manifest `[gateway]` section declares `base_path` and the full
`env_vars` list to write per provider; the `.env` writer emits all of them.
**Close at:** Stage 3, with per-SDK URL-join integration tests.

## O9. Backup inclusion of gateway tables

Backup v2 restores rebuild schema via migrations, so v13 tables restore
structurally; whether gateway metadata rows belong IN backups (they are
operational, high-churn) or are excluded like other derived data.
**Default:** include (matches every other operational table; simplest honest
story).
**Close at:** Stage 1 (migration), aligned with ADR 0015 semantics.

## O2 (match-while-locked) — RESOLVED, and now actually implemented

The toggle defaults OFF, as decided. What was NOT decided here, and was left
open, is what "ON" should mean over time. **Decision (ADR 0020):** ON grants
retention bounded by the locking session's `auto_lock_minutes`, hard-capped at
8 hours; it is never indefinite. Enabling is reauth-gated; disabling drops any
resident key immediately.

Note for the record: until the Phase 5 audit remediation this toggle had **no
consumer anywhere in the code**. It was a stored column that every document
described as a working control. Reasoning, rejected alternatives, and the
lifecycle table are in ADR 0020.

## O6 (custom-route verification key delivery) — RESOLVED

Not previously tracked as an open decision, which is part of why it was missed:
ADR 0019 D3 specified the MAC and the trust model but never said how the
verification key reaches a running gateway. It reached it nowhere, so every
custom-origin route was permanently unavailable.

**Decision (ADR 0021):** the key is pushed over the authenticated control
channel from every flow that has an unlocked vault and could precede a
custom-route request — route add (the only minting site), vault unlock, route
enable, and foreground `serve`. It is not reauth-gated (it verifies route
integrity only and cannot decrypt or confirm anything about a credential), and
it is NOT dropped on vault lock, because dropping it would stop forwarding for
custom routes and break forward-while-locked.
