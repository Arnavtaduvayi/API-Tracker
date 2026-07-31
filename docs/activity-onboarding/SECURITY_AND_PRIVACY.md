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

Residual risks stated at consent time, carried over verbatim (CORRECTED — see below): loopback
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
   Confirmed auto-config); and the MAC binding means a later edit to the
   stored origin STOPS the route (`MacMismatch`) rather than redirecting
   it. That binding is not unconditional: nulling the four custom columns
   together downgrades the row onto the unauthenticated built-in path,
   where the destination is chosen by `provider_id` — see "the
   local-database attacker" below. Residual: a user can confirm a bad
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


## Correction (2026-07-27): attribution disclosure and origin approval

The independent audit of PR #16 found two claims on this page that the
implementation did not meet. Both are now true; the record of what was wrong
is kept here rather than quietly edited away.

**The attribution disclosure was NOT carried over verbatim (`ZFT-013`).**
This page claimed the residual risks were "stated at consent time, carried
over verbatim: … matching-key-resident memory oracle while attribution is on
(GW-6)". The Advanced push-key dialog did that properly. The primary Track
flow, the dashboard resume dialog and the CLI step line authorized the same
capability with only *"Label traffic with which stored credential was used
(recommended)"*. Consent consolidation had moved the password field but not
the ADR-0020 disclosure copy. All three surfaces now carry it: the oracle
while the key is resident, the scope, and that the key is dropped on stop,
revoke and lock.

**The disclosed scope was too narrow (`ZFT-020`).** `PRODUCT_BEHAVIOR.md`
called it a "narrowly scoped matching capability". It is not narrow: the key
pushed to the gateway is the **vault-wide fingerprint key**, and the matcher
covers **every gateway-linked project**, not just the one being set up. The
mechanism is unchanged and was always what ADR 0020 describes; the wording
was wrong, and the consent copy now says vault-wide at the point of consent.

**A custom origin required an explicit checkbox — and there was none
(`ZFT-004`).** This page promised that a repository-derived route origin
"requires an **explicit checkbox** (never part of Confirmed auto-config)".
The CLI had no checkbox and the desktop shipped it pre-checked with the
origin pre-filled, so a repository containing no secrets at all could cause
a MAC'd, enabled route to an attacker-chosen host. The promise is now
implemented as written: default off, per destination, with the full
disclosure, and `--yes` refuses rather than granting it. See ADR 0024.


## Correction (2026-07-27, final re-audit): scanner execution and restore records

The final independent re-audit of PR #16 found two further claims on this
page and its neighbours that the implementation did not meet. Both are now
true. As above, what was wrong is kept on the record rather than edited away.

**"No project-controlled code executes during scanning or setup" was false
(`RA-001`, CRITICAL).** The claim held for the *automatic detection* path,
which genuinely spawns nothing (ADR 0023). It did not hold for the paths that
still run `git`. `crates/core/src/gitrepo.rs` protected those with an
enumeration of configuration keys known to launch a program, and the
enumeration omitted `log.showSignature` and `gpg.<format>.program`. A
repository shipping

```text
[log]
	showSignature = true
[gpg]
	program = ./payload.sh
```

plus any commit carrying a `gpgsig` header executed its own binary as the
user on the next `git log -p`. The signature did not have to be valid — Git
pattern-matches the header and hands the blob to the configured program.

The trigger was this PR's own primary journey: selecting a folder registers it
as a monitored repository, and the desktop's background timer then reaches
`git log -p` with **no user interaction at all**. ADR 0023 had said sandboxing
was "worth revisiting if history traversal ever moves onto an automatic path";
it had already moved there.

The fix is structural rather than another key. Every isolated Git invocation
now runs against a **sealed Git directory** (ADR 0027) that contains only
Tethra's own configuration plus a pointer at the repository's object store, so
repository configuration is not part of the repository Git reads — not for
keys anyone thought of, and not for keys a future Git adds. The enumeration is
kept as an independent second layer and is no longer load-bearing.

Note for anyone auditing this: the isolation is asserted **on its own**, with
no `-c` overrides in play, by `sealing_alone_closes_every_vector`. The
previous canary suite's arming threshold of `armed.len() >= 2` of ten vectors
— which allowed eight canaries to be permanently inert while the suite stayed
green, and is how this class stayed invisible — is gone. Every vector declared
reachable must arm, and every excused one must carry a specific measured
reason.

**"Only non-secret configuration is recorded" was false (`RA-006`, HIGH).**
Undo records what an environment variable held before Tethra rewrote it, in
`gateway_project_links.prior_env_json` — a plaintext column of a database
opened with no `PRAGMA key`, readable by any process running as the user, any
file-level backup, and any disk image. What went in was decided by a **shape
predicate**, and the predicate admitted values the codebase's *own*
`looks_like_key_material` flagged as key material: an `sk-proj-…` key, an
`AKIA…:…` pair, and a JWT — the shape of `SUPABASE_SERVICE_ROLE_KEY`, a full
RLS-bypassing admin credential for a provider in this very catalog. The
leaking case was silent; only the *withheld* case raised a warning.

The two predicates contradicting each other on the same input was the real
signal: the design required a correct answer to "is this string a secret?",
and that question does not have one. So the question is gone. Every recorded
prior value is now sealed under a vault-wrapped key (ADR 0028), bound by
associated data to its link, file and variable. Only structure stays in the
clear. Without a key the value is withheld, never written in the clear.

This also made undo *more* capable: values the old design refused to record —
a base URL with userinfo, one carrying a key in its query string — now restore
byte-for-byte.

**Two related honesty gaps closed at the same time.** `scrub_stored_prior_env_once`
had three call sites, all in the CLI, so a GUI-only user — the persona this PR
exists for — never ran it and a leak written by an earlier build persisted.
The scrub now runs at unlock, which is the only moment a key is definitionally
available. And `gateway unlink` no longer reports `complete: true` after a
`PriorNotRecorded` outcome (`RA-013`).

---

## Where the security-sensitive service behaviour is now proven

Every claim in this document that depends on a **running, login-registered**
gateway used to rest on in-process suites plus one developer-machine run. The
scope that exercises the real thing —
`tracking_validate_macos.sh --scope full --require-service` — had never been
observed passing anywhere, because its own precondition is a machine with no
installed Tethra gateway.

It now runs on a disposable hosted macOS runner on every PR
(`.github/workflows/packaged-service-macos.yml`), and these properties are
asserted against a real per-user LaunchAgent rather than a foreground child:

* **Service identity.** The label is derived by the product from the data
  directory (ADR 0026), so an isolated run cannot name the production service.
  CI asserts the recorded label is non-empty, is not
  `dev.api-tracker.gateway`, and sits inside the namespaced family.
* **Process identity.** The running service must execute the exact program its
  own owned plist declares — read with `PlistBuddy`, pid taken from
  `launchctl print` for the owned label, compared against `ps -o comm=`.
  Identity, never a name pattern: matching by name is what makes a
  `pkill -f tethra` reach a user's real gateway.
* **Helper provenance.** The service runs a copy of the **shipped** binary:
  the plist points inside this run's data directory, and that copy is proven
  byte-identical to the helper inside the `.app`.
* **Control-channel access control.** The control endpoint is a Unix socket at
  `$TETHRA_DIR/gateway.sock` with mode `0600`; an endpoint that exists but is
  world-readable fails the check.
* **Verification cannot be forged.** A fully valid gateway observation for the
  right provider host, inserted with a timestamp before `applied_at`, does not
  verify anything — asserted with an armed-control check proving the forgery
  was really inserted. Only a real request through the service verifies.
* **Privacy at rest, with a live service.** Neither the credential value nor an
  unrelated env canary appears anywhere in the isolated data directory or the
  shared one. Both greps are proven falsifiable first.
* **Teardown.** The service, its definition, its launchd registration, the
  installed helper, the control socket, the control nonce and the pid file are
  all removed — verified from outside the script, after its `EXIT` trap ran.

The lifecycle verbs (install → stop → restart → uninstall, with vault
lock/unlock and credential attribution) are covered by
`gateway_validate_macos.sh` in the same clean room: 50 required checks enforced
as an equality of exact check IDENTITIES rather than only of counts
(`VAL-05-R`), plus up to 15 environment-dependent ones declared and validated
separately, 0 failed,
including the isolation invariant that the production plist is exactly as the
run found it and the production label was never registered by it.

**What this does not cover:** the desktop GUI is not click-driven; Windows and
Linux are not covered; the bundle is unsigned; and provider *acceptance* is
not proven — routes use fake keys, so a `401` proves the path and nothing
about a real credential.

Full record, including the three harness defects the first real runs exposed:
`audit/SERVICE_VALIDATION_EVIDENCE.md`.


## Correction (2026-07-28, post-final-re-audit): the local-database attacker

The fresh independent re-audit raised two non-blocking security findings. Both
are now stated here rather than only in an audit report, because a threat model
that lives in a findings file is not a threat model.

### An attacker with local write access to `vault.db` is EXPLICITLY out of scope

`SEC-01`: a route's `provider_id` is not bound into authenticated state, so
editing it in the database redirects a credential to a **different shipped
manifest provider**. The audit confirmed by upstream fingerprint that an OpenAI
credential reached `api.anthropic.com` after
`UPDATE gateway_routes SET provider_id='anthropic' WHERE route_prefix='openai'`.

This is accepted, and the exclusion is deliberate. `THREAT_MODEL.md` already
records that metadata edits are not cryptographically detected; this states the
consequence in the specific case, and why the obvious fix was not treated as a
boundary:

* The capability required is **local write access to the vault database**. An
  attacker who has it can equally replace the Tethra binary, rewrite the
  LaunchAgent definition to run their own program, or read the running
  process's memory. The credential is reachable by simpler routes than a
  provider-id swap.
* Extending the route MAC to cover `(route_prefix, provider_id)` is a small
  change and would raise the cost of that one path. It would **not** make the
  product resistant to a local-write attacker, and shipping it as though it did
  would be the more dangerous outcome.

**Why custom-origin protection does not extend to this.** The custom-origin MAC
exists for a different adversary: a *repository* that names a destination
(`ZFT-004`, `ZFT-012`). Its job is to bind "the user approved this exact host"
so that repository content cannot become authorization. A built-in provider's
origin is not user-approved data at all — it comes from a compiled-in manifest —
so there was no approval to bind. The two protections answer different
questions, and the pinning test's name reads broader than its scope.

**What is therefore NOT claimed anywhere in this product:** that Tethra detects
or resists tampering with its own database by software already running as your
user. It does not.

### Connection slot exhaustion is bounded, not eliminated

`SEC-02` began as: the head phase always had an absolute deadline; the request
**body** phase had only a per-read idle timeout, so a client that completed its
head and then dribbled bytes held one of `MAX_CONNECTIONS` (128) slots
indefinitely.

**The first fix was incomplete, and this section claimed more than it
delivered (`NEW-48`).** `CLIENT_BODY_DEADLINE` (300s) does bound one request
body — but it was computed inside the per-request handler, which runs once per
keep-alive iteration, so every budget was re-armed on each request. A client
that kept *completing* slow work was never idle and never out of time. The
audit measured one connection holding one slot for **422 seconds** across
twenty slow bodies, and it could have gone on indefinitely. The "≈360s" figure
this section used to state was not a loose bound; there was no bound.

Fixed properly: a **per-connection** budget, charged cumulatively across every
request the connection serves and never renewed.

* `CLIENT_CONNECTION_TIME_BUDGET` (600s) — cumulative **client-paced** time:
  idling between requests, reading a head, reading a body.
* `CLIENT_CONNECTION_MAX_AGE` (3600s) — the age past which the connection
  serves no NEW request. Enforced between exchanges, never mid-exchange.
* `MAX_REQUESTS_PER_CONNECTION` (10 000) — belt and braces; forces periodic
  reconnection so the connection cap can rebalance across clients.
* The existing per-request deadlines and idle timeouts are unchanged.

Upstream-paced time — connecting to the provider, waiting for its response
head, streaming its response body — is deliberately **not** charged, because
the destination comes from the route table and never from the request, so a
client cannot lengthen it. That is what lets a long model completion stream to
the end. Request-upload limits and response-stream limits are different
questions and are still answered differently.

Residual, stated honestly and this time measured: the budget is observed
*between* phases, so residency overshoots it by at most one in-flight idle
budget — 120s if the wait for the next head was running, 60s if the body relay
was. **The true bound is 720s, not 600s and not 360s.** 128 clients can occupy
every slot for up to that long, and can renew by reconnecting roughly every
twelve minutes, each new connection subject to the 15s first-head deadline. The
gateway is loopback-only, fails closed with 503 rather than queueing, and
recovers on its own. Availability only — no credential and no observation is
affected, and an attacker able to open loopback connections is already running
on your machine.
