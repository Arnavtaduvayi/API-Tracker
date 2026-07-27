# ADR 0022: Zero-friction API tracking (standard authorization, automatic setup, bundled helper)

Status: accepted (2026-07-27) — architecture phase; implementation follows
`docs/activity-onboarding/IMPLEMENTATION_PLAN.md`.

Amends the product surface built on ADR 0019 (local gateway), ADR 0020
(matching-key lifecycle), ADR 0021 (route-key lifecycle). Changes no
security mechanism from those ADRs.

## Context

The Local Gateway (PR #15, merged into `main` at `0e6764b`) is technically
complete but ships as a separate sub-product: enabling tracking requires a
separately installed CLI, ~12 steps across four sub-tabs using internal
vocabulary (routes, prefixes, origins, links, matching keys), hand-typed
paths, an undiscoverable attribution step, no restart guidance, no
verification that traffic actually flows, and three disconnected activity
surfaces. The packaged `Tethra.app` contains no helper binary at all, so a
fresh install cannot perform the product's primary advertised function
(`docs/activity-onboarding/CURRENT_UX_AUDIT.md` has the full evidence).

The product's primary value is a central view of API activity. The
gateway is infrastructure for that value, not a feature the user should
assemble.

## Decisions

### D1. Standard tracking authorization

Enabling tracking is one consent with one disclosure (service install,
route creation, previewed env edits, metadata recording — with the
never-recorded list — and credential attribution). Accepting it authorizes
all subcomponents; there are no further per-subcomponent consent prompts.
Two interactions are deliberately retained: the environment-file diff
(explicit approval of file writes, digest-bound as today) and one master
password entry for the matching key. The consent file list moves into the
primary card (retiring accepted-risk #5 of the Phase-5 audit).

### D2. Automatic route management

Routes become derived configuration. Detected manifest providers get their
route created or reused automatically (`add_manifest_route`); users never
see prefixes or type known origins. Custom-origin providers (Supabase
pattern) get their origin inferred from the project's own declared
base-URL variable when unambiguous, confirmed by the user verbatim, and
validated by the unchanged `validate_origin` + SSRF policy + MAC binding.
Arbitrary request-selected destinations remain impossible (SI-2/SI-3
untouched). Ambiguous or uninferable origins ask exactly one question.

### D3. Automatic attribution authorization

Attribution is part of tracking, not a separate feature. The Start-
tracking flow carries the ADR 0020 reauth (one password field); declining
degrades to attribution-off, never blocks tracking. Runtime degradation
(vault lock, TTL expiry) renders as "Credential attribution paused —
traffic is still recorded" with an in-app resume action. Key lifecycle,
scoping, drop-on-lock, and the 8-hour keep-while-locked cap are unchanged.
The app never instructs shell exports.

### D4. Bundled helper (closes OPEN_DECISIONS O10)

The desktop app bundles the CLI binary as a Tauri sidecar (`externalBin`);
`locate_cli` prefers the bundled copy, keeping every existing fallback and
the exec probe. Bundling does not wait for code signing: the quarantine
concern O10 named is already mitigated (fresh_byte_write + xattr strip +
exec probe + honest failure), and when the service cannot install on
unsigned builds the app offers a foreground fallback ("track while the
app is open") using the existing `serve` path. Signing/notarization remain
a release blocker for public builds and the one external dependency.

### D5. Selected-folder provider detection

A new detection layer fuses existing signals (stackdetect, envgov
discovery, scanner name/value rules, provider manifests, assigned
credentials) over one user-selected folder into per-provider confidence
(Confirmed/Likely/Possible) × configurability (Automatic/NeedsOrigin
Confirm/NeedsOriginInput/Unsupported). Hard bounds: selected folder only,
canonicalized, root/home refusal, depth ≤ 6, per-file byte caps, no
symlink escape, parse-only, no network, value-free evidence. One narrow
value-read exception: manifest-declared non-secret base-URL variables may
be read to infer a custom origin, which is then fully validated and
explicitly confirmed. Confirmed+Automatic providers configure with zero
interaction; unsupported providers are listed honestly and never block
supported ones.

### D6. One-click desktop orchestration

The desktop's primary action is `Track API activity`: folder picker →
bounded scan → one review screen (detections, diff, disclosure, optional
password) → orchestrated apply with per-step honest reporting → restart
guidance only when needed → verification → dashboard. Implemented by a new
`crates/tracking` crate composing the existing public APIs (lifecycle,
routes, envlink, control, doctor, vault) — chosen over placing
orchestration in `crates/gateway` (preserves the audited forwarding
crate's boundary) or per-app (desktop/CLI must share logic, CLAUDE.md).

### D7. One-command CLI orchestration

`tethra track .` drives the identical engine: resolve/create project →
detect → combined plan + diff → one confirmation → apply → verify → live
status; `--project`, `--dry-run`, `--yes`, `track status`, `track undo`.
It prompts for the master password itself and never prints shell-export
instructions. Exit codes distinguish verified (0), configured-but-
unverified (2), error (1).

### D8. First-request verification and the tracking state model

"Tracking active" is claimed only when a real request from the project is
recorded (`observation_source='gateway'`, at/after apply). A persisted
state machine (`tracking_setups`, migration v15 — additive, SI-17) spans
not_configured → scanning → ready_to_configure → applying →
awaiting_restart → awaiting_first_request → traffic_observed /
partially_observed / needs_attention / unsupported, and is re-derived on
read so a stale row can never overclaim. The synthetic keyless probe
(path proof) is kept separate from the traffic proof. Timeout leads to a
ranked, evidence-based diagnosis (restart, Docker, loader absent,
override, drift, gateway health, bypass, none-found), never a blank
screen.

### D9. Relationship to existing low-level gateway commands

`tethra gateway …` and the current Gateway view survive unchanged as the
expert/diagnostic surface, moved under Advanced. The orchestrator writes
only through their underlying APIs, so hand-made and automatic
configuration remain interoperable (existing routes/links are detected
and reused, never duplicated).

### D10. Privacy and security implications

No invariant of SI-1..SI-21 changes; the forwarding engine, control
plane, key lifecycles, and recording allowlist are untouched. New surface
is limited to: bounded folder reading (D5's bounds, test-pinned), one
confirmed origin inference (validated as today's manual entry is), a
second executable in the app bundle (same code, same signing status,
reduces today's PATH/symlink exposure), and an additive plaintext table
whose contents carry no SECRET values — the one non-secret value they do
carry is a user-approved custom origin, which undo needs and which the user
was shown verbatim before approving it (audit finding `ZFT-047`)
(consistent with the existing
metadata-unencrypted trade-off). Consent consolidation reduces prompts
without reducing disclosure. Full reconciliation:
`docs/activity-onboarding/SECURITY_AND_PRIVACY.md`.

## Alternatives considered

* **Keep the CLI-install prerequisite** (status quo O10): rejected — it
  makes the packaged product unable to deliver its primary function and
  provably drives symlink-into-repo workarounds.
* **Desktop-embedded gateway thread instead of a service/sidecar**:
  rejected — tracking would stop when the app closes; the LaunchAgent
  model already exists, is audited, and is what the fallback degrades
  *from*, not *to*.
* **Orchestrator inside `crates/gateway`**: rejected to keep the
  security-audited crate free of product orchestration.
* **Silent rollback on partial apply**: rejected — honest partial reports
  with offered undo preserve evidence and match the repo's failure-
  semantics conventions.
* **Auto-configuring Likely detections without a review screen**:
  rejected — two-signal Confirmed is the bar for zero-interaction changes
  to a user's files.

## Security implications

See D10 and `SECURITY_AND_PRIVACY.md`. Residual risks accepted and
disclosed: loopback port usable by any local process (GW-11), matching-key
memory oracle while attribution is on (GW-6), user-confirmable bad custom
origin (equivalent to today's manual form). Process finding recorded:
PR #15 merged without the independent re-audit its own docs required
(O-22-9) — corrected in the records, escalated to the owner.

## Future limitations

Only manifest providers are trackable (Stripe/GitHub detected-but-
unsupported until manifest expansion, O-22-1); Docker/remote projects are
diagnosed, not supported; Windows remains foreground-only and
never-executed-on-Windows until validated; detection reads root manifests
only (O-22-6); cost stays a labeled lower bound.
