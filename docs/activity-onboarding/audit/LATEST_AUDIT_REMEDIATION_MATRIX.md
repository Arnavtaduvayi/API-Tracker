# Latest-audit remediation matrix

Remediation of the fresh final independent audit of PR #16.

```text
Audit:           docs/activity-onboarding/audit/opus-fresh-final-20260729/
                 (copied here byte-identical from audit/pr16-fresh-final-20260729
                  @ ec14d66429621a8378b66d3b5e1caee4c3d0e6d8; never edited)
Audited head:    0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b
Audit verdict:   REMEDIATION REQUIRED — 3 merge blockers, 54 findings
PR:              #16, OPEN and unmerged. It is still open, and this
                 remediation does not claim merge readiness.
```

Every finding in `findings.json` has a row here, plus the fifteen prior
findings the audit rechecked and the fourteen it reviewed as deferred. Nothing
is silently downgraded: where this pass disagrees with the audit's severity or
disposition, the row says so and gives the reason.

## How to read a disposition

| Disposition | Means |
| --- | --- |
| **FIXED** | Behaviour changed, and a named test fails if the change is reverted. |
| **FIXED (docs)** | A written claim was false or overstated and is now accurate. Where the claim can be re-broken by editing a file, a committed test asserts its absence. |
| **DEFERRED — disclosed** | Reproduces, not fixed, and now stated in a user-facing document rather than only in an audit file. |
| **ACCEPTED RISK** | Requires an adversary the threat model excludes, and the exclusion is disclosed accurately. |
| **OWNER DECISION** | A repository or account setting this branch cannot and should not change on the owner's behalf. |

---

## The three merge blockers

### `NEW-01` / `VER-02` — `tethra track` claimed verification from a liveness-blind state

| | |
| --- | --- |
| **Severity** | high-medium · **merge blocking** |
| **Reproduction** | `tethra track .`, let one real request be observed, then stop the gateway (or delete the route, or delete the project link) before the next poll. |
| **What happened** | `apps/cli/src/track_cmd.rs` printed `✓ Tracking verified` and returned exit 0 whenever `verify::check_traffic` reported `Observed`. `check_traffic` switches on the cached `tracking_setups.state` column after a `GatewayLiveness::Unknown` refresh, and the derived ladder never consults liveness, route presence or link presence. A script gating on `tethra track` was told yes while every request the user's application made was failing. |
| **Root cause** | Three surfaces asked the same question — core, desktop, CLI — and each rebuilt the probe-then-derive rule locally. The CLI's copy was missing. `track status`, 200 lines below in the same file, stated the correct rule and carried a comment saying why. |
| **Fix** | The rule was **moved**, not restated a fourth time. `crates/tracking/src/health.rs` is now the one place that answers "is tracking working right now?": `probe_liveness` → `state::refresh_with` → `CurrentHealth`. The CLI's verify loop, `track status`, and the desktop's `tracking_status` / `tracking_list` commands all resolve through it. `verify::check_traffic` keeps its job (deciding when to keep waiting) and now carries a doc comment saying, in terms, that it is not a health check. |
| **Tests** | `apps/cli/tests/track_verify_health.rs` — ten tests driving the REAL `tethra` binary. Layer A drives the verify loop against a live foreground gateway (dead gateway after historical traffic; removed route; removed link; fresh valid traffic with every dependency healthy; attribution paused while forwarding is healthy). Layer B drives `track status` against a synthesised configured setup with no gateway process (dead gateway after historical success; a newer failure over an older observation; a stale observation; a previous session's traffic; the `--json` shape). |
| **Mutation / negative control** | `fresh_traffic_with_every_dependency_healthy_is_verified_and_exits_zero` is the anti-vacuity control: a "fix" that reported failure unconditionally satisfies every other test in the file and breaks the product. `status_reports_a_stale_observation_as_history_not_health` kills the "gate on `observed_ever` rather than `fresh`" mutation, which none of the audit's own eight scenarios reaches. |
| **Residual risk** | The CLI's verify loop cannot be reached in a test without a live gateway, so Layer A needs a foreground `tethra gateway serve` child. That child binds its own port under its own data directory and installs no launchd job, but it does mean the suite is process-dependent and slower than the rest. |
| **Not installing a service** | `plan::plan` emits `ServiceAction::AlreadyRunning` when a verified listener already answers, so apply never reaches the service-lifecycle step. No test in this suite issues a `launchctl` verb. |

### `NEW-37` — the default dashboard fabricated a zero

| | |
| --- | --- |
| **Severity** | high · **merge blocking** |
| **Reproduction** | Track a project using a provider whose manifest declares `usage_shape = ""` (cohere, google-gemini, langsmith, replicate, supabase), make real requests, open the default Activity view. |
| **What happened** | `DashboardView.tsx` rendered `{summary.input_tokens} / {summary.output_tokens}` and `${cost}` unconditionally, so a user saw `0 / 0` tokens and `$0.0000` after traffic that succeeded. `usage_event_count` — the field that distinguishes "no usage was reported" from "usage was reported as zero" — exists on the DTO and appeared nowhere in the file. This PR made Activity the default view. |
| **Root cause** | The invariant is stated three times in the repository (`PRODUCT_BEHAVIOR.md`, `COVERAGE_LIMITATIONS.md`, ADR 0019) and implemented once, in `GatewayView.tsx`. It was a per-component guard rather than a shared rule, so a new component simply did not have it. |
| **Fix** | A shared availability helper now expresses the full vocabulary — known zero, known nonzero, unknown, unavailable, not supported, stale, partial — and every surface that renders or aggregates tokens and cost goes through it, including `GatewayView`, whose correct-but-local guard was refactored onto the shared rule. Aggregation reports a total as partial, naming how many records contributed, rather than summing unknowns as zero and understating it. |
| **Tests** | See `LATEST_AUDIT_REMEDIATION_EVIDENCE.md` for the executed vitest list, including the explicit regression test that fails if `null` renders as `0` or `$0.0000`. |
| **Mutation / negative control** | Reverting the `DashboardView` guard to unconditional rendering fails a named test. |
| **Rust side** | The frontend could only *reconstruct* completeness, because the Rust totals folded every `Option` with `unwrap_or(0)` and discarded the residual count. `crates/core/src/usage.rs` now counts residuals additively beside every sum (no sum changed meaning) and carries the same availability vocabulary, so the CLI's `usage` output — which the brief names explicitly — no longer prints `Input tokens: 0` for a month that reported none. `crates/core/src/pricing.rs` no longer returns a fabricated `$0.00` estimate for a record that prices nothing, and marks an estimate incomplete when a dimension had usage but no price. `crates/core/src/budget.rs` was the one place this was more than a display defect: the over-budget alert was fed from the understated sum, so an under-counted total silently suppressed a real overrun. It is now three-valued — a floor ABOVE the budget still proves an overrun, a floor BELOW it proves nothing unless it is also the total, and that third case raises its own named alert instead of reporting "under budget". |
| **Residual risk** | Three, all found BY this remediation rather than by the audit, and all disclosed in `KNOWN_LIMITATIONS.md` under "Usage and cost completeness". (1) A partially-priced estimate knows it is partial, but `usage_snapshots` has no column for that fact, so the writers drop it at the storage boundary and a later read counts the row as fully costed — a floor presented as a total. Closing it needs an additive migration and is the top follow-up. (2) `gateway_usage_daily` stores zero both for a priced-at-zero request and an unpriced one, so a genuinely free model reads as "cost not reported"; the error direction is always toward understating certainty. (3) The vocabulary is richer than every source can populate — `stale` is derivable only where a provider timestamp exists, and a surface that cannot tell `unknown` from `unavailable` says `unknown`, which is the weaker and therefore honest choice. |

### `NEW-49` — shipping documents denied a limitation the product had accepted

| | |
| --- | --- |
| **Severity** | high · **merge blocking** |
| **Reproduction** | `UPDATE gateway_routes SET provider_id='anthropic' WHERE route_prefix='openai'`, then send a request to `/openai/*`. The OpenAI credential reaches `api.anthropic.com`. |
| **What happened** | `docs/gateway/SECURITY.md` carried a heading asserting that editing the database could not repoint a credential, and concluded the same in its body. `docs/gateway/ARCHITECTURE.md` made the same assertion unqualified, and a **shipped UI string** in `GatewayView.tsx` claimed integrity protection against database tampering with no counterpart for built-in routes. (The retired wording is quoted verbatim in the audit's own `findings.json`, which is preserved unedited; it is deliberately not requoted here, because `crates/gateway/tests/documentation_claims.rs` scans this repository for exactly those phrases and a matrix that reprinted them would reintroduce the claim it is recording the removal of.) |
| **Root cause** | `crates/gateway/src/routes.rs` resolves a manifest route through `providers::find(&provider_id)` with `provider_id` read straight from the untrusted row; `route_mac` is verified only for custom rows. That is `SEC-01`, whose disposition is accepted risk — and accepted risk depends on honest disclosure. The correct disclosure existed in exactly one file and was contradicted in three shipping places. A prior remediation matrix recorded this work as already complete; it was not. |
| **Disposition chosen** | **Option B — correct the claim.** Option A (authenticated binding for built-in rows) was rejected on evidence, not preference: the route MAC key is wrapped under the vault key, so the running gateway holds it only when an unlocked session pushed it. Requiring a MAC on built-in routes would make every route unforwardable whenever the vault is locked — which is the normal state for a background service, and is precisely the zero-friction behaviour this PR exists to deliver. It would also need a CHECK-rebuilding migration the migration mechanism cannot express, and it would not move the boundary: an adversary who can write `vault.db` can also replace the binary or the compiled-in manifests. |
| **Fix** | Every false or overstated claim corrected repo-wide, in the two documents, the UI string, and the further places the sweep found. Each now states what custom-origin MAC protection does prevent (an edited stored origin stops the route rather than redirecting it; no free-form destination can be injected) and what it does not (an attacker with local database write access may reassign a built-in route to a different **trusted built-in** origin, and may strip a custom route's authenticated columns to downgrade it to the unauthenticated path). The distinction between arbitrary custom-destination injection and reassignment among trusted built-in origins is preserved — flattening it would be its own dishonesty. |
| **Tests** | `crates/gateway/tests/documentation_claims.rs` walks the repository and fails if the known false claim returns; it also asserts the PRESENCE of the correcting statement, so deleting the section rather than correcting it fails too. The independent audit artifacts under `docs/activity-onboarding/audit/opus-fresh-final-*/` are excluded from the sweep and left byte-identical — they are historical evidence, and a remediation that edited them would be tampering with the record. `crates/gateway/tests/routes.rs` gains the known-provider-id case (`NEW-50`), which pins the accepted risk so it cannot change silently. |
| **Mutation / negative control** | Reintroducing the false heading fails a named test in `documentation_claims.rs`. |
| **Residual risk** | `SEC-01` itself is unchanged and remains accepted. The `route_kind` hardening the investigation identified (fail closed when a row registered as custom has had its authenticated columns stripped) is deliberately **not** bundled here: it is a partial mitigation, it is itself unauthenticated, and bundling a partial mitigation into a truthfulness fix is how the original overstatement happened. It is recorded as a follow-up. |

---

## Findings the brief required fixing

| ID | Sev | Blocking | Disposition | Residual risk |
| --- | --- | --- | --- | --- |
| `VAL-05-R` | medium | no | **FIXED** — every scope's required check set is identity-bound, generated from the harness sources, compared as an exact set equality | The identity is a check's static label prefix, so an editor who changes a check's BODY while keeping its label is invisible to the manifest — a source diff, visible in review, that no manifest can close. Regenerating and getting the diff approved is likewise not blocked. The mechanism converts a silent swap into a named, two-sided diff; it does not replace review. |
| `NEW-48` / `SEC-02` | medium | no | **FIXED** — a per-connection budget, charged cumulatively and never renewed, plus a maximum connection age and a request cap. `SEC-02`'s previous **FIXED** was incomplete and is re-dispositioned in `POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md` | The honest worst case is **720 s**, not the 600 s the budget names and not the ~360 s three documents used to state: the budget is observed between phases and overshoots by one in-flight idle budget. Upstream-paced time is deliberately uncharged, which is what keeps streaming working and is the largest uncharged surface in the design. Long-lived pooled connections now close after 600 s of cumulative idle rather than 120 s of continuous idle. |
| `NEW-02` | medium | no | **FIXED** — the install primitive validates, reserves the port, persists configuration and the service definition, then starts and verifies, rolling back coherently | Desktop and CLI onboarding are asserted at the primitive both now call, not by driving each caller's UI. One spec test did not fail under the ordering mutation (moving the code moved the stage emission with it); the two observation tests are what pin the happens-before, and that is recorded rather than glossed. |
| `NEW-03` | medium | no | **FIXED** — ownership needs four independent terms, none of which is the plist's existence; an unproven job is left registered, reported, and turned into a non-zero exit | `launchctl print`'s output format is unversioned. `job_data_dir` fails **closed**, so a future macOS that renamed the arguments block would turn every bootout into a refusal — a leak, not a wrongful removal, and loudly reported. |
| `NEW-05` | low-medium | no | **FIXED** — `REFRESH_CAS_ATTEMPTS` cannot be lowered to 2 or to 1 without failing named tests | The seam that makes contention deterministic is a thread-local hook gated behind `cfg(any(test, feature = "test-hooks"))`, off by default, reached from integration tests through a self dev-dependency. A release build does not compile it. |
| `VAL-03` / `VAL-05` mutation gaps | — | no | **FIXED** — a committed control proves the exact-set-equality comparison is what refuses a renamed check, and five product mutants for this audit's findings are now in `scripts/mutation_checks.sh` | Two sibling `NEW-43` tests survive the `bucket()` mutant because they derive from the same call it changes. They are structural guards against the two classifications being split apart again, not tests of the precedence, and the test file says so. |

Detail for each is in `LATEST_AUDIT_REMEDIATION_EVIDENCE.md`.

---

## Every remaining finding

Severity and blocking status are the audit's. "Disposition" is this pass's.

| ID | Sev | Blocking | Disposition | Note |
| --- | --- | --- | --- | --- |
| `NEW-04` | medium | no | **FIXED** | `TETHRA_VALIDATE_LIB_ONLY=1` refuses when the script is executed rather than sourced, so the two CI gates that assert "no artifact" cannot pass vacuously. |
| `NEW-06` | low | no | **FIXED (docs)** | `KNOWN_LIMITATIONS.md` now carries the `ENC-02` entry, including that `undo` reports "Restored" for a line it deleted. |
| `NEW-07` | low | no | **FIXED** | `tethra unlock` and `track`'s interactive password fallback both run the legacy re-seal. They were the only two successful-unlock paths that did not. |
| `NEW-08` | low | no | **DEFERRED — disclosed** | `checkpoint_truncate` still swallows errors after `COMMIT`. Recorded in `KNOWN_LIMITATIONS.md`. |
| `NEW-09` | medium | no | **DEFERRED — disclosed** | The origin-approval MAC binds the vault, not the project, so a second repository inherits an approval under `--yes`. |
| `NEW-10` | medium | no | **DEFERRED — disclosed** | `origin::list` and `origin::revoke` have no production callers: approvals are permanent and invisible. |
| `NEW-11` | low-medium | no | **DEFERRED — disclosed** | CLI and desktop still differ on `PreviouslyApproved` handling; the desktop re-asks, the CLI does not. |
| `NEW-12` | low | no | **FIXED** | `--allow-origin` now says the approval is remembered for the vault. |
| `NEW-13` | info | no | **DEFERRED** | No cross-vault MAC replay test. The binding itself is sound (`vault_id` is in the length-prefixed message). |
| `NEW-14` | low | no | **DEFERRED — disclosed** | `BadHostname`/`BadPort` are still reported with the loopback/private/link-local/cloud-metadata wording. Disclosed under "Destination approvals" in `KNOWN_LIMITATIONS.md`. |
| `NEW-15` | low | no | **FIXED** | `OriginTrust::may_configure_without_asking` now has the production caller its doc comment claimed. |
| `NEW-16` | info | no | **DEFERRED — disclosed** | `ExistingOriginKept` is still suppressed when a manifest route pre-exists. |
| `NEW-17` | low | no | **FIXED (docs)** | The ownership suite no longer claims it never calls `launchctl`. |
| `NEW-18` | low | no | **FIXED** | The ownership floor is no longer an equality with zero headroom. |
| `NEW-19` | low | no | **FIXED** | The ownership test no longer leaks `/tmp/tethra-track-val-$$`. |
| `NEW-20` | low | no | **FIXED** | `ci_service_preconditions.sh` globs `/private/tmp/tethra-gw-val-*`. |
| `NEW-21` | low | no | **FIXED** | The gateway harness teardown emits positive cleanup evidence. |
| `NEW-22` | info | no | **FIXED (docs)** | `CONTRIBUTING.md` now says `cargo test` and `cargo clippy` — not only `cargo build --release` — fail on a clean checkout until the sidecar is staged. |
| `NEW-23` | info | no | **FIXED (docs)** | The handoff's "fourteen deferred findings" now names `ENC-02` as the fifteenth. |
| `NEW-24` | info | no | **FIXED (docs)** | `REPO-01` is recorded as a decision not taken, not a block: the credential in use reports `"admin": true` (re-verified in this pass). |
| `NEW-25` | low | no | **OWNER DECISION** | Secret scanning, push protection and Dependabot are confirmed `disabled` on this public repository. Left to the owner: push protection and branch protection both change how the owner's own pushes behave. |
| `NEW-26` | low | no | **FIXED** | The counted check inside a nested loop no longer makes the gateway harness's required total data-dependent. |
| `NEW-27` | low | no | **FIXED** | The required gateway check behind `if command -v python3` no longer has an emitting-nothing else branch. |
| `NEW-28` | high | no | **DEFERRED — disclosed** | Two projects linking one `.env` destroys the user's original value and reports it restored. Reachable only through deliberate `--project` overrides — the CLI refuses the implicit form — and no credential reaches a wrong origin (an unknown slug 404s). The audit calls it the closest non-blocking call in the audit, and this pass agrees; it is disclosed rather than fixed because the correct fix changes link-plan semantics, which is not a change to make in a remediation pass. |
| `NEW-29` | low-medium | no | **FIXED** | `.*.api-tracker-tmp-*` is git-ignored, and the orphan sweep is reachable from the link and unlink paths rather than only from export cleanup. |
| `NEW-30` | low | no | **FIXED** | The partial-apply screen now wires the `tracking_undo` command the dashboard already used, and reports the returned report honestly (complete vs incomplete, restored files, removed vs kept routes) rather than claiming an affordance it did not offer. |
| `NEW-31` | medium | no | **FIXED** | `record_applied` carries the `row_version` CAS predicate every other health write already had. |
| `NEW-32` | medium | no | **FIXED** | A failed apply no longer erases route provenance, so the retry's undo does not strand routes with a false reason. |
| `NEW-33` | medium | no | **FIXED** | `apply`'s `fail!` macro no longer swallows illegal-transition errors and lose the persisted failure record. |
| `NEW-34` | medium | no | **FIXED** | Undo performs its CAS before the destructive work, and the report is no longer suppressed. |
| `NEW-35` | low | no | **FIXED** | `TrackingState::Applying` fell through `refresh_once`'s watchable set into `health_without_evidence`, so an interrupted apply read as "waiting for the first request". It has its own `CurrentHealth::ApplyIncomplete` now, so every consumer of the shared sentence — CLI, Tauri, frontend — describes it the same way, rather than the desktop patching the symptom locally. |
| `NEW-36` | low | no | **FIXED** | PATH stripping emits a PASS line, so it has positive evidence in the artifact. |
| `NEW-38` | high | no | **FIXED** | A failed `providerGet` no longer renders as a definitive negative capability claim on the surface whose purpose is capability honesty. |
| `NEW-39` | medium | no | **FIXED** | The Advanced route form gives the eight affected providers their real reason. |
| `NEW-40` | medium | no | **FIXED (docs)** | `IMPLEMENTATION_STATUS.md`'s stale numbers replaced with measured ones, and pointed at `PACKAGED_VALIDATION.md` as the authority for validation counts. |
| `NEW-41` | medium | no | **FIXED** | Four UI surfaces no longer render a failed load as an empty result. |
| `NEW-42` | medium | no | **FIXED** | `track` on a machine with no vault names the real problem and says `tethra init`. |
| `NEW-43` | medium | no | **FIXED** | One precedence, `ProviderDetection::bucket()`, carried through the CLI rows, the Tauri DTO and the frontend's section filters. The frontend previously grouped on `configurability` while the headline ranked confidence first, so a low-confidence provider rendered under "Tethra knows where these go". |
| `NEW-44` | medium | no | **FIXED** | The superseded fake scale test no longer ships. |
| `NEW-45` | low | no | **FIXED (docs)** | `RELEASE_NOTES.md` no longer claims Anthropic per-key **cost** sync; Anthropic's cost API has no per-key grouping. |
| `NEW-46` | low | no | **FIXED (docs)** | `FEATURE_MATRIX.md` says 21 embedded manifests, which is the measured count. |
| `NEW-47` | low | no | **FIXED** | "Nothing resolves relative to the repository" was a comment on a `cp -R` step that could not fail. It is now a gate: `strings` for the repository root, `otool -L` for non-system dylibs, and a full detection run under `env -i` with `cwd=/`. The audit had verified the property holds; the point is that nothing was checking. |
| `NEW-50` | low | no | **FIXED** | `routes.rs` now tests a KNOWN provider id, pinning the accepted `SEC-01` behaviour rather than only the unknown-id path that fails closed. |
| `NEW-51` | low | no | **FIXED** | `SEC-02` has integration coverage; deleting the wiring now fails named tests. |
| `NEW-52` | low | no | **FIXED** | A deadline/budget expiry is recorded distinguishably from a client disconnect. |
| `NEW-53` | low | no | **FIXED** | The sweep is recursive and bounded. The mutation control is two-sided: with a canary planted in `<data-dir>/logs/gateway.log` the new test fails, and restoring the old one-level `read_dir` makes it pass **green with a live credential on disk** — the vacuity reproduced on demand. |
| `NEW-54` | low | no | **FIXED** | Slow request body is no longer the only attack class with unit-only coverage. |

---

## Prior findings the audit rechecked

| ID | Audit status | Now |
| --- | --- | --- |
| `VAL-01` | fixed | Unchanged, and strengthened: the trusted set is now identities, not counts. |
| `VAL-02` | fixed | Unchanged. |
| `VAL-03` | fixed, executed in CI | Unchanged; the missing mutation control is added. |
| `VAL-04` | fixed | Unchanged. |
| `VAL-05` | not fixed, accurately disclosed | **Superseded by `VAL-05-R`.** |
| `VER-01` | fixed | Unchanged; `NEW-31` closes the one writer that lacked the predicate. |
| `VER-02` | open at the CLI | **FIXED** (= `NEW-01`). |
| `ENC-01` | fixed | Unchanged; `NEW-07` closes the two residual call sites. |
| `ENC-02` | unresolved | **DEFERRED — now disclosed** (= `NEW-06`). The previous pass deferred it without a user-facing disclosure, which was the part that was wrong. |
| `ORG-01` | fixed, mutation-proved | Unchanged. |
| `SEC-01` | accepted | **ACCEPTED RISK**, and the acceptance now rests on an honest disclosure (= `NEW-49`). The audit's own recheck said no user-facing claim asserted protection that does not exist; three did. |
| `SEC-02` | fixed | **Was PARTIAL, now FIXED** under a per-connection policy (= `NEW-48`). The previous "fixed" bounded a request, not a connection. |
| `ZFT-006` | fixed | Unchanged; now also pinned at the CLI, Tauri and frontend boundaries. |
| `ZFT-010` | fixed | Unchanged; `NEW-44` removes the superseded fake. |
| `REPO-01` | unchanged | **OWNER DECISION** (= `NEW-24`). |

## The fourteen deferred findings

`ENC-03` `ENC-04` `VAL-06` `VAL-07` `VAL-08` `VAL-09` `VAL-10` `VAL-11`
`ORG-02` `VER-04` `GIT-01` `CON-01` `CON-02` `CON-03` — plus `ENC-02`, which
the previous handoff omitted from its own enumeration (`NEW-23`), making
fifteen.

All fifteen reproduce at this head. None is merge-blocking. The audit found
four of them **understated** — `GIT-01`, `ENC-04`, `ORG-02`, `CON-03` — and
one pair that compounds, `VAL-07` + `VAL-08`. Their disclosures are corrected
in `KNOWN_LIMITATIONS.md`; the findings themselves remain deferred.

---

## Where the commits are

The commits for this remediation are listed in
`LATEST_AUDIT_REMEDIATION_EVIDENCE.md` under "Commits", with the executed
output that justifies each. They are grouped by finding rather than by file,
so a reviewer can read one blocker's change without reading the rest.

## Corrections to earlier records

A remediation that only added rows would leave the earlier records wrong.
These were corrected in place, with the original text preserved where it is
load-bearing:

* `POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md` — the `SEC-01` row recorded the
  documentation work as **done**; three shipping places still carried the
  claim (`NEW-49`). The `SEC-02` row is re-dispositioned from **FIXED** to
  incomplete-and-superseded, and the disposition tally corrected from 10 to 9.
  The `REPO-01` row said *blocked on admin access*; the credential in use
  reports `"admin": true` (`NEW-24`). The `VER-01` row implied
  `record_applied` was a guarded writer; it advanced the row version without
  predicating on it (`NEW-31`).
* `POST_FINAL_REAUDIT_EVIDENCE.md` — the `SEC-02` mutation guard is annotated
  with why it could not have caught `NEW-48`, and the "not covered" note about
  apply-vs-apply is annotated with what was hiding in that gap.
* `NEXT_INDEPENDENT_REAUDIT_HANDOFF.md` — "fourteen deferred findings" now
  names `ENC-02` as the fifteenth (`NEW-23`), and `REPO-01` is reframed as a
  decision not taken.

The independent audit artifacts themselves are never edited.

## What this remediation deliberately did not do

* It did not implement authenticated binding for built-in routes (`NEW-49`
  Option A). The reason is recorded above and is a product-behaviour reason,
  not a scheduling one.
* It did not change repository or account settings (`REPO-01`, `NEW-25`).
* It did not change link-plan semantics to fix `NEW-28`.
* It did not merge PR #16, and it does not claim merge readiness. A fresh
  independent re-audit is still required — see `NEXT_FRESH_AUDIT_HANDOFF.md`,
  which names exactly what to reproduce.
