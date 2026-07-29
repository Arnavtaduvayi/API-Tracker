# Handoff to the next independent auditor

You are auditing `feat/zero-friction-api-tracking` after the remediation of
`audit/pr16-fresh-final-20260729`. This file exists to make your job harder,
not easier: it names what was fixed, what was **not**, and where a
plausible-looking fix could still be hollow.

Do not treat anything below as verified because it is written down. Every
claim here is falsifiable and most of them tell you exactly how.

```text
Previous audit:  docs/activity-onboarding/audit/opus-fresh-final-20260729/
                 (copied here byte-identical from the audit branch and never
                  edited — 3 merge blockers, 54 findings)
Audited head:    0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b
This head:       see `git rev-parse HEAD`
PR:              #16 — OPEN, unmerged. This remediation does not claim merge
                 readiness.
```

## Reproduce these nine things first

The remediation claims each of them. Each is stated so you can falsify it
without reading the diff.

### 1. Exact manifest identity substitution (`VAL-05-R`)

The previous validator bound how MANY required checks ran, not WHICH.
Renaming one `APPLY` check inside a genuine 63-check results document was
**accepted** — the audit's own forgery case `2b`.

Take a genuine results document. Rename one required check's identity so the
totals are untouched: `executed_total` still 63, every group still at its
declared count, 63 distinct names, all `pass`. It must now be **refused**.
Then do the same to a `full:foreground` document (57 checks, previously 0 of
them identity-bound), an `offline:none` document (20), and the gateway
packaged-validation document (which previously had no register and no
machine-readable result at all).

Then attack the mechanism rather than the instance:

* substitute a required check for another valid-looking one;
* keep the total correct and change the identity SET;
* duplicate one identity and drop another, same total;
* replace a required identity with an unknown one;
* mark a required check skipped, or informational;
* submit the right document under the wrong scope, the wrong mode, the wrong
  commit, or the wrong namespace;
* submit a previous run's results;
* submit an empty file, a truncated file, and a whitespace-only file;
* submit an `offline` document as `service` evidence.

**Then ask the harder question.** The trusted set is generated from the
harness source and checked into the repository. So: can the generator be made
to emit a weaker manifest? Can a check be added, or renamed, without the
generated manifest changing? Does the drift check actually run in CI, on this
head, and does it fail when the manifest is edited by hand? Is there any path
by which the expected set is derived from the document under validation —
directly or through a shared helper?

### 2. CLI false verification (`NEW-01` / `VER-02`)

`tethra track` printed `✓ Tracking verified` and exited 0 from a cached state
column that survives the gateway being stopped, the route being deleted and
the link being deleted.

Reproduce the original defect first — confirm it is gone rather than moved.
Then, against the real binary:

* historical traffic, dead gateway;
* historical traffic, missing route;
* historical traffic, removed link;
* a successful setup followed by a failed repair;
* a stale verification session;
* a current failure after a historical success;
* fresh valid traffic with every dependency healthy (this must SUCCEED — a
  remediation that reported failure unconditionally would satisfy every other
  case);
* attribution paused while forwarding is healthy (this must also succeed, and
  must disclose the pause).

The claim is that there is now ONE resolver — `crates/tracking/src/health.rs`
— and that core, CLI, Tauri and the frontend all go through it. Test that
claim: is there any surface that still reconstructs the rule? Grep for
`refresh_with`, for `check_traffic`, and for anything that decides present
health from `setup.state`. `verify::check_traffic` still exists and still
switches on the cached column, deliberately; find out whether any caller uses
it to make a claim rather than to decide whether to keep waiting.

Note the pacing seam: the CLI reads `TETHRA_TRACK_POLL_SECS` and
`TETHRA_TRACK_WAIT_SECS`. Check that they cannot change the DECISION, only
the cadence — and that no crate under `crates/` reads them.

### 3. Unknown token/cost rendering (`NEW-37`)

The default Activity view rendered `0 / 0` tokens and `$0.0000` after traffic
that succeeded, for the five routable providers that report no usage at all.

Track a project on `cohere`, `google-gemini`, `langsmith`, `replicate` or
`supabase`, make real requests, and look at every surface: the dashboard, the
gateway activity tab, the usage view, provider connections, and the CLI's
`usage` output. Then look for the case the remediation might have got
backwards: a request that genuinely reported **zero** tokens must still show
zero. Hiding a measurement is a different lie from inventing one.

Aggregation is the part most likely to be hollow. A total folded over a mix
of known and unknown records must not present itself as complete. Check the
budget alert path in particular: an understated total can suppress a real
over-budget alert, which is a correctness defect and not a display one.

### 4. Database-tampering documentation (`NEW-49` / `SEC-01`)

`docs/gateway/SECURITY.md` carried a heading asserting that editing the
database could not repoint a credential. It can:
`UPDATE gateway_routes SET provider_id='anthropic' WHERE route_prefix='openai'`
sends the OpenAI credential to `api.anthropic.com`.

Option A (authenticated binding for built-in rows) was **rejected**, with
reasons recorded in `LATEST_AUDIT_REMEDIATION_MATRIX.md`. Judge that
reasoning yourself: the load-bearing claim is that the route MAC key is
wrapped under the vault key, so requiring a MAC on built-in routes would make
every route unforwardable whenever the vault is locked — which is the normal
state for a background service. If that is wrong, the disposition is wrong.

Then check the disclosure. `crates/gateway/tests/documentation_claims.rs`
scans the repository for the retired claims and asserts the correcting
statement is still present. Attack it: is the deny list narrow enough to walk
around with a paraphrase? Does the walk actually cover the whole tree — try
planting a claim in a directory it might skip. Does it exclude the historical
audit artifacts (it should — they are evidence) and nothing else? Is the
*presence* assertion strong enough that deleting the section fails?

And check the distinction the fix is required to preserve: arbitrary
custom-destination injection and reassignment among trusted built-in origins
are different, and a document that flattens them is dishonest in the other
direction.

### 5. Connection slot exhaustion (`SEC-02` / `NEW-48`)

The previous fix bounded a REQUEST body at 300 s and three documents stated a
~360 s worst case. The deadline was computed inside the per-request handler,
which runs once per keep-alive iteration, so every budget was re-armed on
each request: the audit held one of 128 slots for **422 s** across twenty slow
bodies on one connection, and could have held it indefinitely.

Reproduce that. Then measure the new bound and check the number the documents
state — the claim is **720 s**, not 600 s, because the budget is observed
between phases and overshoots by at most one in-flight idle budget. If your
measurement disagrees with 720 s, the documents are wrong again.

Then test the thing the fix must NOT do: a streaming response after the
request body has completed must run to the end. Upstream-paced time is
deliberately uncharged. Try to use that: can a client make the gateway spend
uncharged time on its behalf? The destination comes from the route table, not
the request — check whether that is actually true on every path.

Also: never-ending request body; slow but active upload; idle connection;
repeated keep-alive requests; maximum connection age; slot exhaustion; slot
recovery; clean interruption observation; client disconnect; upstream
disconnect. And confirm that a body cut short by the budget is recorded
distinguishably from a client that went away (`NEW-52`) — the previous pass
recorded them identically.

The mutation control to re-run: delete the per-connection wiring and confirm
named tests fail. `NEW-51` was exactly this gap — deleting the SEC-02 wiring
left both shipped tests green, because they exercised the reader and the
defect lived in the loop around it.

### 6. Bootout ownership without a plist (`NEW-03`)

The validation cleanup's ownership guard was `$HOME`-keyed while
`launchctl bootout` addresses `gui/<uid>`, which no `HOME` redirection
isolates. When the plist was absent the guard was skipped, so an **unproven**
job could be booted out.

Construct: an owned loaded job with the plist present; an owned loaded job
with the plist removed; a **foreign** loaded job with a matching-looking
label; a stale ledger; a corrupt ledger; a missing plist AND a missing
ledger; PID reuse; cleanup after a partial installation. In every case where
ownership cannot be proven, the job must be left untouched and the run must
report failure — and the refusal path must be side-effect-free.

The production label `dev.api-tracker.gateway` must be exempt from every
control action. Try to defeat that exemption.

Note for your own safety: this machine carries a live production gateway.
The remediation's tests drive an injectable `launchctl` so they can simulate
every launchd state without issuing a write verb. Check that the injection
point cannot be reached in production.

### 7. Gateway install ordering (`NEW-02`)

`tethra gateway install` persisted the selected port AFTER starting the
service, so the service read a null port hint and bound port 0 — the root
cause of the one unexplained packaged-link CI failure, which the previous
remediation mis-classified as a harness reliability defect.

The claim is that the install primitive is now intrinsically correct
regardless of caller ordering: validate → reserve port → persist config →
persist definition → install/start → verify → roll back. Test the primitive,
not the journey: direct `gateway install`; desktop onboarding; CLI
onboarding; a crash before config persistence; a crash after config but
before service start; a start failure; a port conflict; concurrent installs;
a retry after a partial install; an existing valid install; repair; uninstall.

Then check the harness assertion the previous pass relied on. The audit found
the documented rule-out of a port mismatch **circular** — it compared a shell
variable with itself. Confirm that is no longer true.

Repeat the formerly flaky packaged-link scenario enough times to convince
yourself the race is removed rather than hidden. A single green run is not
evidence about a race.

### 8. CAS retry behaviour (`NEW-05`)

`REFRESH_CAS_ATTEMPTS: 3 → 1` survived all 158 tracking tests. Re-run that
mutation, and `3 → 2`. Both must now fail named tests.

Then check the seam that made this testable. It is a thread-local hook
invoked between the read and the compare-and-swap, gated behind
`cfg(any(test, feature = "test-hooks"))` with the feature off by default and
reached from integration tests through a self dev-dependency. Confirm a
release build does not compile it — and that nothing in a shipped binary can
install a callback inside the writer that decides whether a tracking setup is
healthy.

### 9. Every latest blocker

`NEW-01`, `NEW-37`, `NEW-49`. Reproduce each original defect before reading
the fix, then attack the fix.

## What is NOT fixed

Each of these reproduces at this head. Each is now disclosed to users rather
than only to an audit file — check that the disclosure is where a user would
find it, and that it is accurate.

* **`NEW-28`** — two projects linking one `.env` destroys the user's original
  value and reports every outcome as "Restored". The audit calls it the
  closest non-blocking call in the audit, and this pass agrees. Reachable
  only through deliberate `--project` overrides; no credential reaches a
  wrong origin. Deferred because the correct fix changes link-plan semantics.
* **`ENC-02`** — a tampered restore record makes `undo` delete the user's
  line and report it restored. Now in `KNOWN_LIMITATIONS.md`; the previous
  pass deferred it with no user-facing disclosure at all.
* **`SEC-01`** — accepted risk, and the acceptance now rests on a disclosure
  that is finally accurate. If you think the disclosure is still overstated
  anywhere, that is a blocker again.
* **`NEW-09`, `NEW-10`, `NEW-11`** — the origin-approval MAC binds the vault
  and not the project, approvals are permanent and invisible (no production
  caller for `list` or `revoke`), and the CLI and desktop disagree about
  re-asking. Three findings that compound: attack them together.
* **`NEW-08`, `NEW-14`, `NEW-16`, `NEW-47`** — see the matrix.
* **`REPO-01` / `NEW-25`** — branch protection and four free GitHub security
  features are off on this public credential-manager repository. Confirmed
  disabled in this pass. They are **owner decisions**, not blocks: the
  credential in use has `admin: true`, which corrects the previous handoff's
  "blocked on admin access". Push protection and branch protection change how
  the owner's own pushes behave, which is not a change a remediation branch
  should make on someone's behalf.

## The defect class this codebase keeps producing

Four consecutive audits have found the same thing wearing different clothes:

> a check that has never executed anywhere is indistinguishable, from the
> outside, from a check that always passes.

This audit added two more instances, and both are worth internalising because
they are subtler than the earlier ones:

* **`NEW-51`** — the SEC-02 mutation guard was a unit test on the reader, and
  the reader was correct. The defect lived in the loop around it, so deleting
  the entire wiring left the guard green. *A mutation control that does not
  exercise the layer where the defect can live proves nothing.*
* **`NEW-05`** — a constant nothing contended for. Three attempts and one
  attempt were indistinguishable because no test created enough contention to
  need a second.

Hunt this class first. The remediation added mutation checks for each fix and
they are recorded in `LATEST_AUDIT_REMEDIATION_EVIDENCE.md` — but a mutation
check written by the person doing the fixing is exactly the thing you should
distrust. Re-run them, and then write the ones they did not think of.

## Where a plausible-looking fix could still be hollow

1. **The generated manifest.** It converts a silent swap into a visible,
   named, two-sided diff. It does not and cannot stop a reviewer who approves
   that diff. Ask what would happen if the harness and the manifest were
   changed in the same commit.
2. **The connection budget.** Only client-paced time is charged. That is what
   keeps streaming working, and it is also the largest uncharged surface in
   the design.
3. **The health resolver.** One resolver is only one rule if every surface
   uses it. Grep, do not trust.
4. **The usage availability helper.** The frontend reconstructs completeness
   in one place from a second read, because the Rust totals did not carry it.
   If those two reads can ever cover different scopes, the availability
   judgement drifts.
5. **The documentation-consistency test.** A string scanner is a blunt
   instrument. Paraphrase the claim and see whether it survives.

## Do not

* Do not run `--scope full` in either validation harness on a developer
  machine. There is a live production gateway on the machine this was
  remediated on, and `launchctl` addresses `gui/<uid>`, which no `HOME`
  redirection isolates. Use isolated macOS CI.
* Do not treat a green CI run as evidence about a race.
* Do not treat this handoff as a checklist. It is a list of the places the
  remediation believes it is strong; the interesting findings will be
  elsewhere.
