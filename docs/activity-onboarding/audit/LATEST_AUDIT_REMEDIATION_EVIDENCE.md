# Latest-audit remediation evidence

Executed evidence for the remediation of
`docs/activity-onboarding/audit/opus-fresh-final-20260729/`.

Every number below was produced by running the command beside it. Where a
claim is *not* executed evidence — because it needs a clean-room macOS runner,
or because it is an argument rather than a measurement — it says so in the
same sentence. That distinction is the one `NEW-40` found broken in
`IMPLEMENTATION_STATUS.md`, and repeating it here would be the same defect in
a new file.

```text
Remediating:   0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b (the audited head)
Branch:        feat/zero-friction-api-tracking
PR:            #16 — OPEN, unmerged
Machine:       macOS 25.5.0, aarch64, carrying a LIVE production gateway
```

## Safety: the production gateway was not touched

The machine this was remediated on runs `dev.api-tracker.gateway` as a live
LaunchAgent. `launchctl` addresses `gui/<uid>`, which no `HOME` redirection
isolates, so "run it under a temp HOME" is not a safety measure — that is how
a previous audit stopped this machine's real service.

```text
plist sha256   0143dd24972c97743b2fc8ca929ab6c341805fd00f0f794d22e41741813ea5db
               (identical before and after; the value the audit recorded)
PID            22276 (unchanged)
launchctl registrations for the label family: 7, unchanged
launchctl write verbs issued by this remediation: 0
validation harnesses run in a mode that starts/installs/stops a service: 0
```

The six pre-existing orphaned namespaced registrations the audit observed were
left in place. So were the thirteen pre-existing `/tmp/tethra-track-val-*`
leftovers from earlier audit runs. Removing them is an operator action, and
`ci_service_preconditions.sh` correctly refuses to run the service scope while
they are present — which is why that script exits non-zero on this machine and
why that is the script working rather than failing.

---

## `NEW-01` / `VER-02` — the CLI's verification claim

**Reproduced first.** Before any fix, `apps/cli/src/track_cmd.rs` gated
`✓ Tracking verified` and `Ok(())` on `verify::check_traffic`, which switches
on the cached `tracking_setups.state` column after a
`GatewayLiveness::Unknown` refresh.

**Fix.** `crates/tracking/src/health.rs` — one resolver: probe liveness,
then `state::refresh_with`, then `CurrentHealth`. Used by the CLI verify loop,
`track status`, and the desktop's `tracking_status` / `tracking_list`.
`verify::check_traffic` keeps its job — deciding whether to keep waiting — and
now documents, in terms, that it is not a health check.

```text
$ cargo test -p api-tracker-cli --test track_verify_health -- --test-threads=1
running 10 tests
  historical_traffic_with_a_dead_gateway_is_never_reported_as_verified ..... ok
  a_removed_route_is_never_reported_as_verified ........................... ok
  a_removed_project_link_is_never_reported_as_verified .................... ok
  fresh_traffic_with_every_dependency_healthy_is_verified_and_exits_zero .. ok
  attribution_paused_while_forwarding_is_healthy_still_verifies ........... ok
  status_reports_a_dead_gateway_after_historical_success .................. ok
  status_reports_a_newer_failure_over_an_older_observation ................ ok
  status_reports_a_stale_observation_as_history_not_health ................ ok
  status_does_not_carry_a_previous_sessions_traffic_into_a_new_one ........ ok
  status_json_separates_current_health_from_history ...................... ok
test result: ok. 10 passed; 0 failed
```

Layer A (the first five) drives the REAL `tethra` binary through its verify
loop against a live **foreground** gateway. No launchd job is installed:
`plan::plan` emits `ServiceAction::AlreadyRunning` when a verified listener
already answers, so apply never reaches the service-lifecycle step. Layer B
drives `track status` against a synthesised configured setup with no gateway
process at all.

**The anti-vacuity control is
`fresh_traffic_with_every_dependency_healthy_is_verified_and_exits_zero`.** A
"fix" that reported failure unconditionally satisfies every other test in the
file and destroys the product.

**What the audit's own eight scenarios do not reach:**
`status_reports_a_stale_observation_as_history_not_health` — an observation
older than the freshness window is history, not health. That case kills a
"gate on `observed_ever` rather than `fresh`" mutation which none of the eight
would catch.

**A pacing seam, and its bound.** The CLI reads `TETHRA_TRACK_POLL_SECS` and
`TETHRA_TRACK_WAIT_SECS` so a failure case does not sit through the real
two-minute window. They change the cadence and never the decision, and no
crate under `crates/` reads them — the derivation this loop depends on has no
test seam of any kind.

---

## `NEW-37` — unknown is not zero

**Frontend.** One shared owner, `apps/desktop/src/usage.ts`, expressing
known (with covered/total, so a known zero stays expressible), partial, stale,
unknown, unsupported and unavailable. Every surface calls it, including
`GatewayView`, whose correct-but-local guard was refactored onto the shared
rule so the two cannot drift.

Executed from `apps/desktop`:

```text
npx tsc --noEmit         PASS
npm run lint             PASS
npm run format:check     PASS
npx vitest run           PASS — 17 files, 165 tests
```

**Mutation control, executed.** Reverting `DashboardView.tsx` to unconditional
rendering: **4 failed, 21 passed**, the named failure being
`DashboardView never fabricates a zero (NEW-37) > does not render 0 tokens or
$0.0000 when no response carried usage`. Restored; 25/25 green.

The three other failures under that mutation are worth naming, because they
pin the *opposite* error: `still shows a measured zero, because hiding a
measurement is a different lie`, `labels a total folded over some unknown
records as partial`, and `does not invent an estimate for tokens it could not
price`.

**Rust side.**

```text
$ API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-core --test usage_availability
test result: ok. 21 passed; 0 failed
$ API_TRACKER_INSECURE_FAST_KDF=1 cargo test -p api-tracker-cli  --test usage_availability
test result: ok. 12 passed; 0 failed
```

`absent_usage_is_never_rendered_as_zero_or_zero_dollars` is the explicit
regression test the brief asks for, and it does not only check the six lines it
names — it walks every measurement line, so a regression cannot hide in one the
test forgot to enumerate.

**Mutation control (a), executed.** Reverting the six CLI header lines to
unconditional rendering: **5 failed, 7 passed**, with the regression test
printing exactly the defect —

```text
fabricated a zero: 'Requests:       0' appeared in:
  Snapshots:      2
  Requests:       0
  Input tokens:   0
  Reported cost:  $0.00 (provider-reported)
  Estimated cost: $0.00 (estimated locally …)
```

**Mutation control (b), executed.** Reverting the budget verdict to
two-valued — "not over means under", the shape that suppressed real alerts —
fails `budget_over_partial_data_cannot_be_evaluated`,
`budget_incompleteness_raises_a_named_alert_instead_of_silence` and, at the CLI,
`budget_over_partial_data_refuses_to_claim_under_budget`, which caught the
mutated binary printing `STATUS: under budget` for a project whose costs were
1-of-4 covered.

Honestly recorded: both mutations were narrow single-site reverts, so they
evidence those two sites and no more. And
`a_period_with_no_usage_at_all_does_not_alert` fails under mutation (b) on its
*status* assertion, not its alert assertion — it is a guard against alert noise
rather than a mutation detector, and the test file says so.

**What had no call sites.** The brief asks about charts, tooltips and
CSV/export paths. There are none in this repository — that is a measurement,
not an omission.

---

## `NEW-49` / `SEC-01` — the database-tampering claim

**Reproduced.** `UPDATE gateway_routes SET provider_id='anthropic' WHERE
route_prefix='openai'` sends the OpenAI credential to `api.anthropic.com`.
`crates/gateway/src/routes.rs` resolves a manifest route through
`providers::find(&provider_id)` with `provider_id` read straight from the
untrusted row.

**Option A rejected on evidence.** The route MAC key is wrapped under the
vault key, so a running gateway holds it only when an unlocked session pushed
it. Requiring a MAC on built-in routes would make every route unforwardable
whenever the vault is locked — the normal state for a background service, and
the zero-friction behaviour this PR exists to deliver. It would also need a
CHECK-rebuilding migration the migration mechanism cannot express, and it
would not move the boundary: an adversary who can write `vault.db` can replace
the binary or the compiled-in manifests.

**Option B executed.** Corrected in `docs/gateway/SECURITY.md` (heading and
body), `docs/gateway/ARCHITECTURE.md` (including a stale MAC-input list that
omitted `route_prefix`), `docs/gateway/USER_GUIDE.md`,
`docs/gateway/TEST_PLAN.md`, `docs/gateway/THREAT_MODEL.md` (GW-3 relabelled
`DEFENDED` → `PARTIAL`), the root `THREAT_MODEL.md`, `CHANGELOG.md`, four
handoff/plan documents, ADRs 0019 and 0021 (superseding notes, not rewrites),
source comments in `routes.rs`, `db.rs`, `crypto.rs`, `vault.rs`, and the
shipped `GatewayView` UI string.

**A remaining overstatement the test found, not a human.**
`docs/activity-onboarding/SECURITY_AND_PRIVACY.md:81` asserted the MAC binding
as an unqualified defence against a later database edit. It is not one: it does
not survive a row downgrade — nulling the four custom columns moves the row
onto the unauthenticated built-in path. Corrected. (The retired sentence is not
requoted here, for the same reason the matrix does not requote the retired
heading: this scanner reads this repository.)

```text
$ cargo test -p api-tracker-gateway --test documentation_claims
running 5 tests
  new49_sec01_no_heading_claims_that_tampering_cannot_redirect_credentials . ok
  new49_sec01_no_document_asserts_the_retired_absolute_guarantee ........... ok
  new49_sec01_the_gateway_security_doc_still_states_the_correction ......... ok
  new49_sec01_the_scanner_matches_the_historical_claims ................... ok
  new49_sec01_the_scanner_reads_a_non_empty_inventory ..................... ok
test result: ok. 5 passed; 0 failed
```

**Mutation control, executed and independently repeated.** Reintroducing the
retired heading into `docs/gateway/SECURITY.md`:

```text
test new49_sec01_no_heading_claims_that_tampering_cannot_redirect_credentials ... FAILED
test result: FAILED. 4 passed; 1 failed
```

Restored: 5 passed. The scanner also carries its own in-test negative control
(`the_scanner_matches_the_historical_claims`) proving the deny list flags the
historical wording and does **not** flag the corrected wording — so the guard
cannot push an author toward deleting the disclosure instead of stating it —
and a walk control (`reads_a_non_empty_inventory`) against the classic
wrong-root failure.

The independent audit artifacts under `docs/activity-onboarding/audit/` are
excluded from the sweep and left byte-identical. They are the record; a
remediation that edited them would be tampering with it.

---

## `VAL-05-R` — exact check identities

**Reproduced.** Rebuilding a genuine `full:service` document and renaming one
required `APPLY` check — every count untouched — was **accepted** at the
audited head, exactly as the audit's forgery case `2b` reported. The same edit
to a `SERVICE` row was refused, because `SERVICE` was the only group with any
identity binding at all. A `full:foreground` document with all 57 check names
fabricated was also accepted.

**Fix.** The manifest now names the exact required check set for every scope,
and the validator requires set equality in both directions.

```text
$ python3 -c "import json;m=json.load(open('scripts/validation_manifest.json'));…"
full:foreground   expected_total=58  required=58  optional=0
full:service      expected_total=64  required=64  optional=0
gateway:lifecycle expected_total=50  required=50  optional=15
offline:none      expected_total=21  required=21  optional=0
selfcheck:none    expected_total=5   required=5   optional=0
```

`gateway:lifecycle` is new: `gateway_validate_macos.sh` previously had no
register, no per-check identity and no machine-readable result at all — only
an in-script `REQUIRED_CHECKS=50` equality.

The totals moved by one from the audit's numbers (63 → 64, 57 → 58, 20 → 21)
because `NEW-36` turned the PATH-stripping assertion, which previously emitted
only negative evidence, into a counted `BUNDLE` check.

Executed, independently re-run after the agent that wrote it reported:

```text
$ bash scripts/validation_manifest_check.sh     === MANIFEST CHECK RESULT: 38 passed, 0 failed ===
$ bash scripts/validation_asserter_tests.sh     === ASSERTER FORGERY RESULT: 59 passed, 0 failed ===
$ bash scripts/validation_harness_mutants.sh    === HARNESS MUTATION RESULT: 8 killed, 0 survived ===
$ bash scripts/validation_manifest_mutants.sh   === MANIFEST MUTATION RESULT: 8 killed, 0 survived ===
$ bash scripts/validation_ownership_tests.sh    === OWNERSHIP TEST RESULT: 53 passed, 0 failed ===
$ python3 scripts/gen_validation_manifest.py --check
  validation_manifest.json is exactly what the harness sources produce
```

**The auditor's own suite, replayed.** `forge_results_json.py` pointed at the
remediated validator and manifest with a freshly generated base document:

* **verbatim: 29/30.** Case `2b` — the single leak at the audited head — is
  now REFUSED. The one case that does not behave is case 20, "wrong schema
  version", which asserts `tethra.validation.results/2` must be refused. The
  remediation deliberately bumped the results schema to `/2` as a hard cut
  against pre-remediation artifacts, so the auditor's chosen "wrong" value is
  now the correct one. That is a stale constant in the test, not a leak.
* **adapted: 30/30.** The only edit is case 20's constant, `/2` → `/1` (the
  now-superseded schema), preserving the case's intent. Independently
  confirmed the intent holds: a document declaring
  `tethra.validation.results/999` is refused.

**Mutation control, committed.** `validation_asserter_tests.sh` runs a
sed-mutated copy of the validator with the exact-set-equality block deleted
against the case-`2b` document and requires it to **accept** — proving the new
test is not vacuous. Two guards keep that control honest: a mutation that
fails to apply is a FAIL, and a mutant that refuses even a genuine document is
a FAIL.

**The gateway scope's first real CI run found a defect in this work, and it is
worth recording because of WHERE it was.** On `37d4582` the packaged
service-lifecycle job ran the gateway harness against the new validator. Every
one of the 50 required identities matched — `required check SET equality: 50/50
declared checks executed, 0 unrecognised rows` — and the job still failed:

```text
=== SERVICE SCOPE ASSERTION FAILED ===
  - group 'REPAIR' ran but the manifest does not declare it for gateway:lifecycle
```

`REPAIR` stages a repair only when the run reaches a state that needs one, so
it has **no required checks** and therefore no entry in the manifest's
required-count table — which the validator was using as the set of KNOWN
groups. A group can legitimately consist entirely of optional checks; that is
what optional means.

The local suite had not caught it because its synthesised documents built the
group breakdown from required rows only, so a wholly-optional group never
appeared in a test document at all. That is the same defect class this whole
finding is about — a check that cannot fail — one level up, in the test
harness. Both are fixed: the synthesiser now mirrors what the harnesses emit
(one entry per group that ran, `executed` counting required rows only), and
two committed cases pin both sides of the distinction — a group the manifest
names nowhere is still refused, and a failure inside a wholly-optional group is
still refused. The asserter suite is 61 assertions, up from 59.

Verified by reproduction rather than by reasoning: the pre-fix validator,
given the genuine document, prints the exact CI error; the fixed one accepts it
and prints `50/50 required checks passed in gateway:lifecycle`.

**And its second real run found a second one, in the same place.** With the
group fix in, the gateway scope's assertion passed — and the job failed one
step later, at the clean-room precondition between the two service runs:

```text
FAIL   a stale test namespace ALREADY exists:
       /private/tmp/tethra-gw-val-11458-976f0948.ledger.checks.tsv
=== PRECONDITIONS FAILED (1) — refusing to run the service scope ===
```

The check register is written beside the ownership ledger, and teardown swept
the ledger but not the register. The register is new in this pass, so the leak
is new in this pass — and it was caught by `NEW-20`, the precondition glob for
`/private/tmp/tethra-gw-val-*` added in this same pass. A new check found a new
leak on its first opportunity, which is the whole argument for adding it.

Fixed by sweeping both. The tracking harness has no equivalent leak: it writes
its register inside a directory teardown already removes.

**End to end, not only synthetic.** A real `--scope selfcheck` run with
`TETHRA_VALIDATION_RESULTS_JSON` set validates as `5/5 required checks passed
in selfcheck:none`. That is the proof the generated label prefixes match the
labels the harness emits at runtime, not merely its source text. The gateway
document has **not** yet been produced by a real run — that needs a clean-room
runner, and the first CI execution is its real proof.

---

## `SEC-02` / `NEW-48` — per-connection resource limits

**Reproduced.** The deadline was computed inside `handle_request`, which runs
once per keep-alive iteration, so every budget was re-armed per request. The
audit's 422-second single-slot residency was not a loose bound; there was no
bound.

**The limits now.**

| Constant | Value | Bounds |
| --- | --- | --- |
| `CLIENT_HEAD_DEADLINE` | 15 s | one request head |
| `CLIENT_BODY_DEADLINE` | 300 s | one request body |
| `CLIENT_BODY_IDLE_TIMEOUT` | 60 s | the gap between two body reads |
| `CLIENT_KEEPALIVE_IDLE` | 120 s | the gap between two requests |
| `CLIENT_CONNECTION_TIME_BUDGET` | 600 s | **cumulative client-paced time per connection, never renewed** |
| `CLIENT_CONNECTION_MAX_AGE` | 3600 s | the age past which no NEW request is served |
| `MAX_REQUESTS_PER_CONNECTION` | 10 000 | requests on one keep-alive connection |
| `MAX_CONNECTIONS` | 128 | concurrent connections; further ones get 503 |

Only client-paced time is charged. Upstream-paced time is not, because the
destination comes from the route table and never from the request — which is
what lets a long model completion stream to the end.

**The honest bound is 720 s, not 600.** The budget is observed between phases,
so residency overshoots by at most one in-flight idle budget: 120 s if the
wait for the next head was running, 60 s if the body relay was. The head
deadline is deliberately not clamped to the remaining budget, because clamping
could expire mid-head and turn a legitimately arriving request into a spurious
400. Every document now states 720 s.

```text
$ cargo test -p api-tracker-gateway --test connection_limits    14/14 PASS
$ cargo test -p api-tracker-gateway --test routes               12/12 PASS
$ cargo clippy -p api-tracker-gateway --all-targets -- -D warnings   clean
```

**Mutation control 1 — the `NEW-51` scenario, executed.** Deleting the
per-connection wiring while KEEPING `ConnBudget`, `ConnLimits` and
`DeadlineReader`: **6 named tests failed**, including
`slow_bodies_on_one_connection_cannot_renew_the_connection_budget` ("it served
10, which is the unbounded-residency behaviour NEW-48 measured") and
`a_body_cut_by_the_connection_budget_is_recorded_apart_from_its_own_deadline`.

On the first pass of that mutation the slot test *passed*, because its bound
was the per-request deadline the mutation keeps. The test was changed so only
the per-connection wiring can release the slot, and re-run. `NEW-51` is
therefore closed by construction rather than by assertion — and the way it was
closed is itself the lesson `NEW-51` teaches.

**Mutation control 2 — implementing the budget the WRONG way, executed.** A
wall-clock lifetime that also charges and enforces the response-streaming
phase: **2 named tests failed**,
`a_streaming_response_outlives_the_connection_time_budget_and_the_maximum_age`
and `upstream_paced_time_is_not_charged_to_the_connection_budget`. That is the
guard the shipped design lacked: the SSE-truncation failure mode is now loud.

**`NEW-52`.** A body cut short by the budget is recorded distinguishably from
a client that went away. `ClientBodyIdleTimeout` is inferred from
`ErrorKind::TimedOut`/`WouldBlock` on the client read; reads from and writes to
the upstream cannot be misfiled, because only the client-side
`DeadlineReader` reports a stop.

**`NEW-50`.** `crates/gateway/tests/routes.rs` now tests a KNOWN provider id.
It documents that changing `provider_id` on a built-in row DOES redirect the
route — pinning the accepted `SEC-01` risk so it cannot change silently. It is
named and commented so nobody reads it as asserting a desirable property.

---

## `NEW-03` — bootout ownership without a plist

**The defect.** The guard was `$HOME`-keyed; `bootout` addresses `gui/<uid>`.
With the plist absent, the guard was skipped.

**Fix.** Both harnesses route every `launchctl` call through an injectable
`LAUNCHCTL` seam. `job_data_dir()` reads `--data-dir` out of
`launchctl print gui/<uid>/<label>` — the same namespace `bootout` addresses,
unaffected by `$HOME`, surviving the plist's deletion — and fails **closed**
on unparsable output. `job_is_ours()` requires four independent terms: not the
production label; the label is in the `<production>.<12 hex>` family; the
ledger row's own recorded data directory equals `$DIR`; and launchd's own
record names `$DIR`. `ledger_add` now carries `$DIR` as its proof term; it
previously carried nothing.

Cleanup has three distinguishable outcomes: not registered (a no-op, not a
failure), proven (bootout), and unproven (**left registered**, reported, and
counted). Unproven refusals become a non-zero exit through the EXIT trap,
because `ci_service_cleanup_check.sh` structurally cannot see this class — its
precondition goes GREEN when a job is wrongly removed.

```text
$ bash scripts/validation_ownership_tests.sh
=== OWNERSHIP TEST RESULT: 53 passed, 0 failed ===
```

Up from 29. The tests simulate every launchd state through the stub, so the
suite issues no `launchctl` write verb on a developer machine.

**Mutation control, committed.** Section 6b reverts the guard to the
audited-head `$HOME`-keyed form in a temp copy and replays the
foreign-job test against it. Measured: the mutant **does** emit
`bootout gui/501/dev.api-tracker.gateway.aaaaaaaaaaaa`. A sed that fails to
apply is reported as a hard failure with an explicit "the whole of section 6's
evidence is void" message.

**Adjacent, deliberately not changed.** `ServiceManager::ensure_ours` in
`crates/gateway/src/lifecycle/mod.rs` has the same *shape*
(`DefinitionState::Absent => return Ok(())`). In practice it is protected by
ordering and by the label deriving from its own owned data directory. It is
not the `NEW-03` finding; it is recorded here as a follow-up rather than left
unsaid.

---

## `NEW-02` — gateway install ordering

**Root cause, confirmed.** `install` ran before `save_config`, the plist
carried no `--port`, the service read `store::port_hint` (which swallowed
every failure into `None`) and bound port 0.

**Fix.** `crates/gateway/src/lifecycle/provision.rs` — the ordered primitive:
validate the plan → reserve the port → persist config → persist the definition
→ install/start → verify the service reads the intended configuration → roll
back coherently. Callers no longer have to remember the sequence.

```text
$ cargo test -p api-tracker-gateway --test lifecycle_provision   20/20 PASS
$ cargo test -p api-tracker-gateway --test doctor                 7/7  PASS
$ cargo test -p api-tracker-cli --test gateway_cli               11/11 PASS
```

The provision suite's `SpyRunner` samples `store::port_state` at **every** OS
interaction — the mock IS the service's boot-time read — so
`no_os_interaction_precedes_the_port_commit` is an assertion about the whole
sequence rather than about one call. No launchd verb is ever really issued.

**Mutation control, executed.** Restoring the OLD ordering (start-then-persist)
in `provision.rs`: **4 of 20 failed**, including
`install_commits_the_port_before_the_service_is_registered_or_started` — *"a
service booting at this instant would have read NoneYet and bound a DIFFERENT
ephemeral port (NEW-02); left: NoneYet, right: Persisted(45001)"* — and
`no_os_interaction_precedes_the_port_commit`. Restored: 20/20.

Honestly recorded: `install_reports_its_stages_in_the_specified_order` did
**not** fail under that mutation, because moving the code also moved the stage
emission. It is a spec test, not the control; the two observation tests are
what pin the happens-before.

**A second finding, and the doctor.** `doctor` now reports `port_drift` when
`config.port != gateway_status.port` — the divergence that made the original
CI failure "unexplained". Mutation control: disabling the comparison fails
`port_drift_is_an_error_and_names_both_ports` while the negative control
`no_port_drift_when_the_live_port_is_the_configured_one` still passes, proving
the finding is driven by the comparison and not by the presence of a gateway.

---

## `NEW-05` — the CAS retry, and the seam that made it testable

**Reproduced.** `REFRESH_CAS_ATTEMPTS: 3 → 1` left all 158 tracking tests
green.

```text
$ cargo test -p api-tracker-tracking --test verification_cas_retry    5/5 PASS
$ cargo test -p api-tracker-tracking --test transaction_recovery     10/10 PASS
$ cargo test -p api-tracker-tracking            158 before → 176 after
```

**Mutation controls, executed, in both directions.**

* `3 → 1`: **5 failed, 0 passed** in `verification_cas_retry`; the other 171
  tests stayed green, so the mutant is detected by exactly the intended file.
* `3 → 2`: **2 failed**, `a_refresh_persists_its_correction_after_two_consecutive_conflicts`
  and `sustained_conflict_reports_the_truth_writes_nothing_and_makes_exactly_three_attempts`.

Both directions are pinned: the constant cannot be lowered to 1 **or** to 2.

**The seam, and its bound.** Forcing a conflict at a chosen attempt needs a
hook between the read and the compare-and-swap. It is a thread-local callback
gated behind `cfg(any(test, feature = "test-hooks"))`, with the feature off by
default and reached from integration tests through the crate's self
dev-dependency. `cargo build --release -p api-tracker-tracking` does not
compile it. A settable callback inside the writer that decides whether a
tracking setup is healthy is not something a shipped binary should carry.

**`NEW-31`/`NEW-32`/`NEW-33`/`NEW-34`, each with a control.**

| Mutation | Named failure |
| --- | --- |
| remove `AND row_version = ?5` from the completed-apply branch | `a_second_applys_plan_summary_cannot_overwrite_the_one_that_won` |
| replace the `record_routes_created` call with `Ok(())` | 3 tests, incl. `a_retry_after_a_failed_apply_still_attributes_the_routes_to_this_setup` |
| restore `_ => break` in the `fail!` transition loop | `a_failure_that_cannot_be_recorded_is_reported_instead_of_swallowed` |
| delete undo's early `row_version` comparison | `a_stale_undo_refuses_before_it_destroys_a_live_setup` |

**`NEW-43`, with an honest caveat.** Removing the `confidence < Likely` guard
from `bucket()` fails `a_low_confidence_provider_is_never_labelled_as_needing_approval`.
Two sibling tests **survived** that mutant, because they derive from the same
`bucket()` call the mutation changed — they are structural guards against the
two classifications being split apart again, not tests of the precedence.
That is stated in a comment inside the test file rather than left for a reader
to discover.

**Committed, so they run rather than being reported.** Five of these mutants
are now in `scripts/mutation_checks.sh`:
`refresh-retries-a-lost-compare-and-swap`,
`record-applied-predicates-on-the-row-it-read`,
`a-failed-apply-still-records-what-it-created`,
`undo-checks-the-row-version-before-it-destroys`,
`row-labels-use-the-headline-precedence`. Each was executed and each was
killed.

---

## CI, on the exact head

Six of six, on `1e3c164`, after three rounds in which CI found what the local
suites could not. The runs before it are not evidence about this head and are
not quoted as such; what each of them found is recorded above.

```text
Rust (core + CLI)                  pass   5m21s
Rust core (Windows)                pass  10m53s
Desktop frontend                   pass     49s
Desktop backend (macOS)            pass   2m31s
Packaged app + validation (macOS)  pass   7m31s
Packaged macOS service lifecycle   pass   9m09s
```

**The artifacts, not only the status.** Every scope that emits a results
document was bound by exact check IDENTITY, in a real run, with nothing
unrecognised:

```text
gateway:lifecycle   register: 50 required checks (7 optional), 0 not passed
                    SET equality: 50/50 declared executed, 0 unrecognised rows
full:service        register: 64 required checks (0 optional), 0 not passed
                    SET equality: 64/64 declared executed, 0 unrecognised rows
offline:none        SET equality: 21/21 declared executed, 0 unrecognised rows
```

and the gates around them:

```text
validation_manifest.json is exactly what the harness sources produce
MANIFEST CHECK RESULT:     38 passed, 0 failed
MANIFEST MUTATION RESULT:   8 killed, 0 survived
HARNESS MUTATION RESULT:    8 killed, 0 survived
ASSERTER FORGERY RESULT:   61 passed, 0 failed
OWNERSHIP TEST RESULT:     53 passed, 0 failed
PACKAGED TRACKING VALIDATION (selfcheck): 5/5
PACKAGED TRACKING VALIDATION (offline):  21/21
PASS: the bundled helper read 21 embedded manifests under env -i with cwd=/
```

That last line is `NEW-47`: what used to be a comment claiming a `cp` proved
self-containment is now a measurement.

## A process incident, recorded because it affects how the numbers were taken

Parts of this remediation ran concurrently in one working tree. Twice, a tool
that takes a backup and restores it on exit — `scripts/mutation_checks.sh`, and
a hand-rolled equivalent — restored its snapshot over another writer's
uncommitted edits to `crates/tracking/src/{state,apply}.rs`. Both were caught
within about a minute and restored from a second backup, and the tree was
re-verified: `cargo check --workspace --all-targets` clean, and the specific
work at risk (`record_applied`'s `AND row_version = ?5` predicate,
`record_routes_created`, `PlanSummary::apply_completed`,
`CurrentHealth::ApplyIncomplete`) confirmed present afterwards.

Two consequences for the evidence in this file:

* **The mutation-suite run taken during that window is discarded.** It reported
  19 skipped and 1 survivor, which are collision artefacts and not measurements.
  The authoritative run is the one taken on a quiet tree, reported above.
* **A `cargo test --workspace --all-targets` run taken during the same window
  reported three `apps/cli/tests/gateway_cli.rs` failures**, all with
  `this vault uses database schema v19, but this build supports up to v18` —
  the signature of a `tethra` binary rebuilt from a partially-restored tree
  mid-run. On a quiet tree that suite is 11/11. The workspace numbers quoted
  here are from the quiet-tree run.

The lesson is the same one this codebase keeps relearning in a different form:
a measurement taken while the thing being measured is moving is not a
measurement. It is recorded here rather than quietly re-run, because a
remediation that hid its own bad run would be doing what `NEW-40` is about.

## What is argued rather than measured

Stated plainly, because the whole point of `NEW-40` is that a document which
mixes the two is not evidence at all.

* **The gateway packaged-validation results document.** Its schema, register
  and gate were exercised against synthetic documents built from the manifest.
  No real run has produced one; that needs a clean-room macOS runner.
* **`full:service`, `full:foreground` and `gateway:lifecycle` identity
  binding.** Rests on source-derived prefixes plus synthetic documents. The
  `selfcheck:none` scope WAS validated end to end on a real run, which is what
  proves the extraction matches runtime labels; the other scopes cannot run on
  a machine carrying a live gateway.
* **Desktop onboarding and CLI onboarding install ordering.** Asserted at the
  primitive both callers now use, not by driving each caller's UI.
* **`NEW-28`, `NEW-09`, `NEW-10`, `NEW-11`, `ENC-02`, `NEW-08`, `NEW-14`,
  `NEW-16`, `NEW-47`.** Reproduced by the audit, not fixed, now disclosed. No
  test pins them, by construction — a test that pinned them would be pinning a
  defect.
