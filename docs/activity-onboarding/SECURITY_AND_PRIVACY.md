# Security and Privacy — Reconciliation with the Existing Model

The redesign changes **consent packaging and orchestration**, not security
mechanics. This document walks every affected invariant and states exactly
what changes (usually: nothing) and what is newly introduced.

Reference: `docs/gateway/SECURITY_INVARIANTS.md` (SI-1..SI-21),
`docs/gateway/THREAT_MODEL.md` (GW-1..13), ADRs 0019/0020/0021,
root `THREAT_MODEL.md`.

## 1. Invariants — line by line

| Invariant | Status under the redesign |
|---|---|
| SI-1 loopback-only listener | Unchanged. The orchestrator never opens sockets; `server::BIND_IP` stays a hard-coded constant. |
| SI-2 no open relay | Unchanged. Routes are still the only forwarding source. |
| SI-3 registered origins only | Unchanged. Auto-created routes are manifest routes (compiled-in trust root) or MAC'd custom origins from a **user-confirmed** inferred value validated by `routes::validate_origin` + SSRF policy. Detection never lowers validation. |
| SI-4/4a slugs, browser rejection, no cookie relay | Unchanged (forwarding engine untouched). |
| SI-5/6 TLS verification, no client MITM | Unchanged. |
| SI-7/8 no credential/authorization storage | Unchanged; `ExchangeRecord` shape untouched. |
| SI-9 matching-only key, scoped matcher | Unchanged mechanics; consent packaging changes (see §2). |
| SI-10 no cookies/query/bodies stored | Unchanged. |
| SI-11/12/13 forwarding independent of vault lock and persistence | Unchanged; the "attribution paused" UX (Journey B) is the honest rendering of exactly this behavior. |
| SI-14 bounded queues/parsers | Unchanged. |
| SI-15 smuggling rejected | Unchanged. |
| SI-16 no unrelated file access | **Extended, not weakened**: `envlink` still touches only planned files; the new detection layer reads only the user-selected folder under hard bounds (see §3). |
| SI-17 append-only migrations | Followed: v15 is additive (`tracking_setups`). |
| SI-18/19 supplements proxy; claims match coverage | Unchanged; `traffic_observed` strengthens SI-19 by making the product claim *require* observed coverage. |
| SI-20 no unsafe | The tracking crate adopts `#![forbid(unsafe_code)]`. |
| SI-21 key only via authenticated control channel | Unchanged; the orchestrator uses `control::send` like the CLI does. Windows still refuses. |

## 2. Consent: what "one disclosure" does and does not change

**Today**: service install consent (consent card) and attribution consent
(separate reauth dialog) are two independent opt-ins; routes and links are
implicit in their forms.

**After**: one Start-tracking disclosure covers service install, route
creation, env edits (still individually previewed as a diff), metadata
recording, and attribution — because a user who downloads an API-activity
tracker and selects a folder to track has expressed exactly this intent.
What is deliberately **kept** as extra interaction:

* The env-file diff (approval of writes to the user's files stays
  explicit; the digest-bound plan/apply from `envlink` is untouched).
* The master-password entry for the matching key. ADR 0020's reauth
  requirement is honored verbatim — the password field moves *into* the
  Start-tracking confirmation instead of a later dialog. Skipping it skips
  attribution only. The audit event (`gateway_matching_key_pushed`) and
  drop-on-lock semantics are unchanged, as is the off-by-default,
  8-hour-capped keep-while-locked toggle (which stays in Advanced with its
  own reauth).

The disclosure's file list moves into the primary card — this also retires
accepted-risk #5 from `docs/gateway/audit/REMEDIATION.md` ("the consent
file list is behind Learn more").

Residual risks stated at consent time, carried over verbatim: loopback
port usable by any local program (GW-11); standing local egress relay;
matching-key-resident memory oracle while attribution is on (GW-6).

## 3. New attack/exposure surface introduced by this redesign

Honest enumeration — the redesign is not risk-free:

1. **Folder scanning.** New code reads project files. Bounds (pinned by
   tests, `TEST_PLAN.md` §3): selected folder only, canonicalized;
   refusal of `/` and home roots; depth ≤ 6; per-file byte caps; no
   symlink following; parse-only (no execution, no interpolation); no
   network; evidence carries names, never values. Threat considered: a
   malicious repo crafted to blow up detection → mitigated by the same
   bounded parsers the scanner already uses; a malicious `.env` value
   cannot influence anything except the one confirmed-origin rule below.
2. **Origin inference from a project file value** (the single value-read,
   `AUTOMATIC_PROVIDER_DETECTION.md` §5). A hostile repo could plant
   `SUPABASE_URL=https://attacker.example` hoping the user confirms a
   route to it. Mitigations: full `validate_origin` + SSRF policy; the
   origin is displayed verbatim with "traffic will be forwarded only to
   this exact address"; it requires an explicit checkbox (never part of
   Confirmed auto-config); and the existing MAC binding means later DB
   tampering still cannot redirect it. Residual: a user can confirm a bad
   origin they didn't read — equivalent to today's manual origin form, so
   no regression, but now reachable from a scan. Accepted, documented.
3. **Bundled helper.** The app bundle now carries a second executable.
   Same code, same signing status as the app itself; discovery prefers
   the bundle path, reducing today's exposure to PATH-hijack/symlink
   drift (the observed `~/.local/bin` symlink pattern is strictly worse).
   Exec probe before registration is retained.
4. **Auto-created routes.** Route creation without a per-route form does
   not change what routes *can* be (manifest/MAC'd only), only who types
   them. The route audit events (`gateway_route_added`) still fire per
   route, so the audit trail granularity is unchanged.
5. **Foreground fallback** spawns the helper as a child — the same
   `serve` path a CLI user runs today; no elevation, no new mode.

## 4. Privacy posture

* Recording allowlist unchanged (`docs/gateway/PRIVACY_MODEL.md`): the
  orchestrator adds **no** new persisted wire-derived data.
* `tracking_setups.detection_json` stores provider ids, confidence,
  evidence *kinds*, and file *paths* — no env values, no secrets. File
  paths already appear in `project_repos`/`gateway_project_links`; no new
  class of data at rest. The vault-metadata-unencrypted trade-off in the
  root `THREAT_MODEL.md` applies as-is.
* Nothing is uploaded anywhere; detection and verification are entirely
  local (the only network act remains the keyless probe through the local
  gateway to the registered provider).
* Consent language commits only to what the allowlist enforces
  ("metadata such as…never bodies/keys/prompts") — same claims as today,
  one screen earlier.

## 5. Things this redesign must not do (checked in review)

* No route to an origin that skipped `validate_origin` + policy checks.
* No matching-key push without the master password entry in that flow.
* No `.env` write without a previewed, digest-matched plan.
* No whole-disk or home-directory scan, ever, under any flag.
* No new plaintext storage of anything `prior_value_is_recordable` would
  refuse today.
* No weakening of the Windows refusal (no attribution without the
  authenticated channel).
* No silent rollback that destroys evidence of a partial apply.

## 6. Open security questions

Carried in `OPEN_DECISIONS.md`: O-22-2 (should `track` auto-repair a
version-drifted service binary without an extra confirmation), O-22-3
(attribution password UX for the CLI `--yes` path), O-22-9 (the PR #15
merge-without-re-audit governance gap — a process finding, not a code
finding, but it belongs on the security record).
