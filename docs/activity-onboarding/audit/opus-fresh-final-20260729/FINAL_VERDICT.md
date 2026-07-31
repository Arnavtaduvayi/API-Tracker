# Final verdict — fresh final audit of PR #16

```
Audited head:   0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b
PR state:       OPEN, unmerged, MERGEABLE, 6/6 checks SUCCESS on the exact head
Audit branch:   audit/pr16-fresh-final-20260729 (fresh worktree)
Verdict:        REMEDIATION REQUIRED — 3 merge blockers
```

## The decision

**Do not merge yet.** Three defects block, and they are the same kind of
defect three times: the product **states something it has not established** —
a verification claim, a usage figure, and a security guarantee — and in every
case the correct version already exists elsewhere in the same repository.
None is deep. All three are small, localized fixes.

Everything else this audit examined held up, and much of it held up under
attack I designed myself rather than re-running the remediation's own checks.

### `NEW-01` — `tethra track` claims verification from a liveness-blind state

`apps/cli/src/track_cmd.rs:745,758` print `✓ Tracking verified` and return
`Ok(())` (exit 0) whenever `verify::check_traffic` returns `Observed`.
`check_traffic` (`crates/tracking/src/verify.rs:139-155`) switches on the
cached `setup.state` column after a `GatewayLiveness::Unknown` refresh, and the
`derived` ladder (`state.rs:937-951`) never consults liveness or route presence.

The same file states the opposite rule 200 lines later, for `track status`
(`:993-999`):

> Exit 0 only for a present-tense success. "Verified previously" is
> deliberately a non-zero exit: a script that gates on tracking working must
> not be told yes while the service is down.

And the desktop fixed exactly this defect, naming it
(`TrackFlow.tsx:394-400`): *"gating the headline on it let 'verified
previously, gateway down' render as an unqualified 'Tracking verified' —
ZFT-005 closed on the dashboard but still open on this screen."* The desktop
gates on `currently_working` and carries a regression test. The CLI — the
documented fallback in the supported journey — has neither, and
`apps/cli/tests/track.rs`'s ten tests all stop at the unconfigured path.

**Fix:** gate `:745`/`:758` on
`refresh_with(conn, &setup, liveness).current.is_currently_working()`, as
`status()` already does, and add a CLI regression test.

### `NEW-37` — the default dashboard fabricates a zero

`DashboardView.tsx:290-296` renders tokens and cost unconditionally.
`usage_event_count` exists on the DTO and appears nowhere in that file. Five of
the thirteen routable providers declare `usage_shape = ""`, so a user tracking
Gemini, Cohere, Replicate, LangSmith or Supabase sees `0 / 0` tokens and
`$0.0000` after traffic that succeeded.

The repository states the invariant three times — `PRODUCT_BEHAVIOR.md:272`,
`COVERAGE_LIMITATIONS.md:42`, `ADR 0019:61` — and implements it correctly at
`GatewayView.tsx:1281-1288`. `CLAUDE.md` lists *"Provider capabilities must be
represented honestly"* among the requirements that may not be silently
changed. This PR made Activity the default view.

**Fix:** apply the `GatewayView` guard in `DashboardView`, and assert the
`usage_event_count == 0` case — `DashboardView.test.tsx:65` already sets it.

### `NEW-49` — shipping documents deny a limitation the product has accepted

`crates/gateway/src/routes.rs:628-650` resolves a manifest route through
`providers::find(&provider_id)` with `provider_id` read straight from the
untrusted database row; `route_mac` is verified only for custom rows. So
`UPDATE gateway_routes SET provider_id='anthropic' WHERE route_prefix='openai'`
sends the OpenAI credential to `api.anthropic.com`. That is SEC-01, and its
disposition is **accepted risk** — reasonably so, because it needs local write
access to `vault.db`.

Accepted risk depends on honest disclosure. The disclosure is correct in
exactly one file (`SECURITY_AND_PRIVACY.md:306-327`) and contradicted in three
shipping places:

* `docs/gateway/SECURITY.md:40-47` — heading *"Why database tampering cannot
  redirect your credentials"*, concluding *"A same-user process editing SQLite
  cannot make `/openai/...` (with your key attached) go **anywhere else**."*
* `docs/gateway/ARCHITECTURE.md:121-123` — same claim, unqualified.
* `apps/desktop/src/components/GatewayView.tsx:830-832` — a **shipped UI
  string** asserting integrity protection against database tampering, with no
  counterpart for built-in routes.

`SECURITY_AND_PRIVACY.md:337-339` states the correct position, so the
repository contradicts itself, and
`POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md:182` records this work as already
complete. A security product that ships a `SECURITY.md` promising a property
it has formally accepted it does not have should not merge on that basis.

**Fix:** correct the two documents and the UI string to match
`SECURITY_AND_PRIVACY.md:306-327`, and add a test for the *known*-provider-id
case — `routes.rs:74` currently tests only an unknown id, which fails closed.

## Against the seventeen approval criteria

| # | Criterion | Verdict |
| --- | --- | --- |
| 1 | Exact check identities validated, not only counts | **Partial** — 9 of 63 service-scope checks are identity-bound; 54 are count-bound, and 0 of 57 in `full:foreground`. Real, accurately disclosed by the remediation, confirmed by my own forgery suite (`VAL-05-R`). Not blocking. |
| 2 | Forged and incomplete results cannot pass | **Met** — 29 of 30 independent vectors refused, including every class the brief enumerates. |
| 3 | Every required check meaningful and falsifiable | **Met** for what I could test — 4 primitive mutants caught, 8 harness mutants killed, ZFT-006 core mutants M2/M3 killed. One coverage gap (`NEW-05`). |
| 4 | Verification concurrency cannot erase newer failures | **Met** — CAS sound; no stale writer can erase a newer failure, generation or session. |
| 5 | ZFT-006 caught at all relevant product boundaries | **Not met** → `NEW-01`. |
| 6 | Desktop-only legacy migration real and safe | **Met** — transactional, idempotent, resumable, plaintext removed only after the sealed replacement commits; `vault_unlock` reaches it on every successful path. |
| 7 | ENC-02 resolved or shown non-blocking | **Shown non-blocking** — mechanism confirmed end to end; requires a local-write adversary the threat model excludes; no shipping document makes a protection claim it disproves. |
| 8 | `--yes` cannot approve custom origins | **Met** — and proved load-bearing: removing the refusal fails 6 of 11 tests and reproduces ZFT-004 with an enabled MAC'd route to the attacker host. |
| 9 | Service ownership and cleanup isolated | **Met** for the product; one harness-only gap (`NEW-03`). No ownership decision for `rm -f` comes from a glob. |
| 10 | Intermittent packaged-link failure understood or harmless with safe recovery | **Understood** → `NEW-02`. Root-caused to install-ordering in `tethra gateway install`; the supported journey orders correctly; safe non-destructive recovery exists but is mis-signposted. |
| 11 | Transactions and crash recovery safe | **Mostly** — one silent-corruption path (`NEW-28`) reachable only by a deliberate two-project-one-folder configuration the CLI otherwise refuses. Closest non-blocking call in this audit. |
| 12 | Clean packaged journey works | **Met** — verified from the exact-head CI artifact, verb by verb. |
| 13 | Gateway security intact | **Partial** — 313 gateway tests pass and every attack class but one has real driven coverage; but SEC-02 bounds a request rather than a connection (`NEW-48`, measured 422 s on one slot), and SEC-01's accepted-risk disclosure is contradicted by shipping documents (`NEW-49`, blocking). |
| 14 | Privacy canaries pass | **Met** at crate and packaged level; two harness-side qualifications (`VAL-07`+`VAL-08`) and one filesystem gap (`NEW-29`). |
| 15 | Deferred findings accurately classified | **Mostly** — all 14 reproduce; four are understated; one pair compounds; none blocks. |
| 16 | All six CI checks pass on the exact audited head | **Met** — verified via the check-runs API against `head_sha=0c3b7d6f…`. |
| 17 | No new merge-blocking defect | **Not met** — two. |

## What this audit did that the previous one could not

* Ran the **exact-head service-lifecycle CI artifact** and confirmed the
  evidence commit is `refs/pull/16/merge`, whose tree is byte-identical to the
  PR head. Every lifecycle verb — including `repair`, previously never run —
  executed.
* Wrote an **independent forgery suite** from the real artifact rather than
  re-running the remediation's.
* **Mutated the validator's own primitives**, including reintroducing the
  REM-002 subshell defect and confirming the probe reports the exact
  `malformed(+0p/+0f)` signature that catches it.
* **Mutated the ZFT-006 core** and confirmed M2/M3 are killed by named tests
  while `REFRESH_CAS_ATTEMPTS` is unpinned.
* **Mutated the `--yes` refusal** and confirmed 6 of 11 tests fail and ZFT-004
  reappears in the database.
* Independently re-derived every headline count rather than copying it.

## Corrections to the record

1. The nondeterministic packaged-link failure is **a product defect**, not
   *"a HARNESS reliability defect"* (`POST_FINAL_REAUDIT_EVIDENCE.md:511-513`).
   The documented rule-out of a port mismatch is circular — it compares a shell
   variable with itself.
2. `REPO-01` is not *"blocked on admin access"*: the credential in use already
   has `admin: true`. It is a decision not taken.
3. The handoff enumerates **14** deferred findings; the matrix defers **15**.
   The omitted one is `ENC-02` — the matrix's own "highest-value remaining
   non-blocker".
4. `IMPLEMENTATION_STATUS.md` claims *"every claim below is executed
   evidence"* while carrying at least five stale numbers, one of which is the
   defective pre-`ZFT-VAL-4` count the harness header itself calls out.

## Recommended order of work

1. `NEW-01`, `NEW-37`, `NEW-49` — the three blockers. All small; all need a
   test.
2. `NEW-48` — re-disposition SEC-02 to PARTIAL, hoist the deadline to a
   per-connection budget, correct the three documents stating a ~360 s bound.
3. `NEW-02` (install ordering + a `doctor` finding for port divergence) and
   `NEW-28` (warn when another link already covers the file).
4. `NEW-31` (add the CAS predicate to `record_applied`), `NEW-34` (CAS before
   destroy in undo), `NEW-38` (do not render a swallowed error as a capability).
5. Documentation: `NEW-40`, `NEW-06`, `NEW-45`, `NEW-46`, and the four
   understated deferrals (`GIT-01`, `ENC-04`, `ORG-02`, `CON-03`).
5. Governance, before or after merge — branch protection, and the four free
   GitHub security features that are currently off (`NEW-25`).

## Safety statement

The live production gateway `dev.api-tracker.gateway` was **not touched**.

```
plist sha256   0143dd24972c97743b2fc8ca929ab6c341805fd00f0f794d22e41741813ea5db  (before and after)
plist mtime    Jul 27 09:15:20 2026, 996 bytes, mode 600                          (unchanged)
PID            22276                                                              (unchanged)
launchctl write verbs issued by this audit: 0
service-mode validation scripts executed:   0
```

Six pre-existing orphaned namespaced registrations were observed in `gui/501`
at the **start** of this audit and left in place; they are documented in
`SERVICE_LIFECYCLE_EVIDENCE.md` and were not created by it.

The implementation branch is unchanged at `0c3b7d6f…` and **PR #16 was not
merged**. All audit artifacts are committed to
`audit/pr16-fresh-final-20260729` only.
