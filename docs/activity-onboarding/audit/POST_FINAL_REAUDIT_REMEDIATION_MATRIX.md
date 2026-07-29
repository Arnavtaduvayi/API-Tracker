# Post-final-re-audit remediation matrix

Every finding from `audit/opus-fresh-final-20260728` (28 total, 9 merge
blocking), with what was done about it.

```text
Audit:          docs/activity-onboarding/audit/opus-fresh-final-20260728/
Audit branch:   audit/pr16-fresh-final-reaudit @ baa0239   (unchanged)
Audited head:   cac469e3497e5ba905c9e26d31d43c4b989594c5
Implementation: feat/zero-friction-api-tracking
PR:             #16 — OPEN, unmerged
```

The original audit reports are preserved byte-for-byte. Nothing in this
directory edits them.

## Legend

**Disposition** is one of: `FIXED` (remediated and mutation-checked),
`PARTIAL` (materially improved, residue named), `ACCEPTED` (evaluated, no
change, reasoning recorded), `DEFERRED` (not addressed in this pass).

`Mutation` names the change that, applied to the fixed code, makes the new
tests fail. A fix without one is a fix nothing is guarding — which is the
defect class most of this audit is about, so an empty cell is a finding in
itself and is called out as such.

---

## The nine merge blockers

### VAL-01 — CI service-scope asserter accepts a run that executed zero checks

| | |
|---|---|
| **Severity** | critical |
| **Merge blocking** | yes |
| **Reproduction** | `python3 scripts/ci_assert_service_results.py <audit>/repro/repro_asserter_accepts_zero_checks.json` → `SERVICE SCOPE COMPLETED: 0/0 checks passed in full:service`, exit 0. Reproduced verbatim at the audited head. |
| **Root cause** | `expected_total`, every `groups[].expected` and every check name were read **from the file being validated**. The gate proved internal self-consistency and nothing else. |
| **Fix** | `scripts/validation_manifest.json` (new, committed) holds the required total, per-group counts, the nine SERVICE checks by name, and required provenance facts. The validator takes `--scope`, `--mode` and `--commit` as arguments supplied by the workflow. Nothing about acceptance is read from the artifact. The harness additionally emits `commit` and `service_created_by_this_run`. |
| **Tests** | `scripts/validation_asserter_tests.sh` — 33 assertions. One genuine result accepted; 32 documents refused, including the audit's own artifact replayed verbatim. `scripts/validation_manifest_check.sh` — 37 assertions proving the manifest against the harness's own group table and every named check against a real call site. Both wired into `ci.yml`. |
| **Mutation** | Restoring the self-reported-count behaviour (`expected = r.get("expected_total")`, group sizes from the file) makes the "self-consistent result containing only the SERVICE group" forgery pass. That document is internally perfect — every count agrees, all nine required SERVICE checks present and passing, provenance true, label namespaced, commit correct — and is caught **solely** by the manifest. |
| **Disposition** | **FIXED** |
| **Residual risk** | Check identity is a committed static label prefix, not a per-check ID. A check renamed *and* the manifest updated in the same commit passes review, not the gate. Per-check IDs are the stronger form and are named in the handoff. |
| **Commit** | `2aa6ec1` |

### VER-01 — stale in-memory handle plus an ordinary observation erases a live failure

| | |
|---|---|
| **Severity** | high |
| **Merge blocking** | yes |
| **Reproduction** | Two connections on one `vault.db`: read a setup, record a failure from the other connection, then refresh from the first. At the audited head the failure is nulled and the report is `VerifiedAndActive`. |
| **Root cause** | `failure_is_newer` was computed from the caller's in-memory `attention_at`, and `write_derived` committed with `UPDATE … WHERE id = ?1` — a blind write with no predicate on what the row looked like when the decision was made. A lost update across transactions; WAL and `busy_timeout` do not help. |
| **Fix** | Migration v19 adds `tracking_setups.row_version`. All health writes funnel through one guarded statement (`cas_write_health`) requiring the row to still be at the version its caller read. `refresh_with` answers a conflict by re-reading and re-deriving (three attempts, then it reports without writing — deterministic). `transition` deliberately does not retry: its legality check encodes an intent that must be re-judged. `record_applied`, the undo artifact clear and the re-apply upsert all advance the version. The two write-once watermarks gain `IS NULL` predicates. |
| **Tests** | `crates/tracking/tests/verification_concurrency.rs` — 12 tests, two connections on one database: stale-handle erasure, failure racing a refresh, two refreshes racing, gateway death, route removal, link removal, setup-generation change, old verification session, desktop+CLI together, refused stale transition, version advance. Barriers or hand-sequenced interleavings; no sleeps. |
| **Mutation** | Removing the CAS predicate (`WHERE id = ?1`, parameter dropped so it still compiles) fails 5 tests including the headline reproduction. |
| **Disposition** | **FIXED** |
| **Residual risk** | Under sustained contention the third attempt reports without writing, so a cached correction can lag by one read. Safe by construction (it never overwrites) and it converges on the next call. |
| **Follow-up found while writing the handoff** | `apply.rs`'s failure path called `transition` with `let _ =`. With the CAS in place a concurrent write in the re-read → transition window would make that a no-op, trading the pre-CAS defect (force the write, clobber newer state) for its mirror image: silently losing the record that an apply failed — ZFT-006 by omission rather than by overwrite. The failure path now retries on conflict, because "this apply failed" is unconditional and a conflict means only "say it again", never "reconsider". Pinned by `an_apply_failure_is_recorded_even_when_the_row_moved_first`. The three other production `transition` callers propagate with `?`, which is loud and correct. |
| **Commit** | `bf17ce9` |

### VER-02 — the literal ZFT-006 regression survives all tests

| | |
|---|---|
| **Severity** | high |
| **Merge blocking** | yes |
| **Reproduction** | Replace `keep_reason` with `None`; `cargo test -p api-tracker-tracking` → 152 tests, 0 failures. Reproduced at the audited head. |
| **Root cause** | The preservation clause was guarded by a second, **unreachable** copy of the same question: `next == NeedsAttention` could only be true when `failure_is_newer` had already forced it, and that forcing made `next == setup.state`, which short-circuits the write. An unreachable guard is indistinguishable from a broken one. |
| **Fix** | The duplication is collapsed to the one reachable decision — `write_derived` now takes `preserve_failure` and the caller passes `failure_is_newer` — so there is a single expression to test. The overclaiming downgrade also stops replacing a specific recorded reason with a generic one. |
| **Tests** | `crates/tracking/tests/zft006_regression.rs` — 5 tests on observable product behaviour: a verified project, a failed re-run, historical traffic preserved, current status failed, history separately visible, reason preserved; repeated reads; a v15-upgraded row; traffic from the previous session; and a control proving a genuinely resolved failure IS cleared. |
| **Mutation** | Two, both killed. Forcing `failure_is_newer` false (the literal v15 clause — promote on any traffic) fails `a_failed_re_run_is_never_reported_as_verified`. Dropping the preserved reason fails `an_upgraded_v15_row_does_not_lose_its_failure_on_the_first_refresh`. Both survived the entire suite at the audited head. |
| **Disposition** | **FIXED** at the core tracking layer |
| **Residual risk** | Coverage is at the core layer. CLI status output, the Tauri command boundary and the UI state mapping are **not** separately pinned; they render from the same `TrackingStatusReport` this suite asserts on, so a divergence would be in the rendering rather than the decision. Named in the handoff. |
| **Commit** | `bf17ce9` |

### VAL-02 — dead field extractor on the service ownership path

| | |
|---|---|
| **Severity** | high |
| **Merge blocking** | yes |
| **Reproduction** | `printf '{\n  "definition_path": "/x"\n}' \| sed -n 's/.*"definition_path":"\([^"]*\)".*/\1/p'` → 0 lines. The product renders with `to_string_pretty`, which emits a space after the colon. |
| **Root cause** | The expression required no space, so it never matched a byte on any run, and every run fell through to `ls "$LA_DIR/dev.api-tracker.gateway".*.plist` — a glob that matches a second environment's live agent as well as this run's. Both ledger rows bounding cleanup's `bootout` and `rm -f` derived from it. |
| **Fix** | `product_status_field` parses the product's JSON exactly (python3, now a preflight precondition). **The glob fallback is removed**: a product that cannot name what it installed means this run does not know what it owns, and the honest outcome is a failed check with an empty ledger. The ledger records the product-reported label as the proof term. |
| **Tests** | `scripts/validation_ownership_tests.sh` — 29 assertions, wired into CI, driving the real primitives through a new library mode against a fake `$HOME`. Current run cleans its own resources; a name-identical pre-existing plist stays byte-identical; empty, missing and corrupt ledgers remove nothing; a forged ledger cannot reach the production definition, `$HOME` or `/`; the audited head's exact sed extracts nothing. |
| **Mutation** | Restoring the dead sed and the glob fails 4 assertions and the count floor. |
| **Disposition** | **FIXED** |
| **Residual risk** | The ownership path itself still executes only under `--scope full --mode service`, which cannot run on a developer machine. The library-mode seam is what makes its primitives testable without one; the end-to-end path remains CI-only. |
| **Commit** | `b656c0e` |

### VAL-03 — two of the 63 service-mode checks cannot fail

| | |
|---|---|
| **Severity** | high |
| **Merge blocking** | yes |
| **Reproduction** | Source review: `[ ! -f "$PLIST" ]` tests the legacy path preflight already proved absent and ADR 0026 means the product can never write; `[ "$INSTALLED_LABEL" != "$LEGACY_LABEL" ]` compares `basename` of a glob that mandates a suffix, and the `none` fallback also passes. |
| **Root cause** | Both asserted properties adjacent to, but not the same as, the ones their labels claim. |
| **Fix** | The dry-run check compares `la_digest()` — the whole LaunchAgents directory, as its foreground twin does — so a namespaced install breaks it. The label check asserts the **product-reported** label and the three properties that make it namespaced: not the global label, derived from it, non-empty installation id, and equal to the plist's basename. |
| **Tests** | Covered by `validation_ownership_tests.sh` (the resolution path) and by the harness's own inventory gate. Both checks now depend on values the product supplies rather than on a pattern this script chose. |
| **Mutation** | The VAL-02 mutation (glob restored) also breaks the label check's premise, and fails the ownership suite. |
| **Disposition** | **FIXED** |
| **Residual risk** | Neither rewritten check has been *executed* — `--mode service` runs only in CI. Their failure modes are argued from source, not observed. The first CI run on this head is the first execution. |
| **Commit** | `b656c0e` |

### VAL-04 — gateway_validate negative controls certify primitives they never call

| | |
|---|---|
| **Severity** | high |
| **Merge blocking** | yes |
| **Reproduction** | Source review: the `assert_db` control calls `db` and compares inline; the `assert_status` control re-implements its python inline. With `assert_db(){ ok "$2"; }` the control still passes while real assertions flip FAIL→PASS. |
| **Root cause** | A control that does not call the thing it certifies is certifying nothing. |
| **Fix** | `probe_primitive` runs the real primitive exactly as production does and observes its verdict by detaching the tally. `assert_db` is exercised against false, empty, erroring **and true** queries; `assert_status` against a stopped gateway **and** a property that is never true, so "consults its argument" is checked as well as "rejects an absent gateway". |
| **Tests** | The controls are themselves the test, and they now execute the production functions. |
| **Mutation** | `probe_primitive`'s semantics were mutation-checked against a stand-in harness: with the primitive neutered to `ok "$2"`, the false-query probe reads `pass`, which is exactly what the control tests for. The first CI run to execute the real script also proved the controls are load-bearing — they failed, because the first version ran each primitive inside a command substitution and a subshell's tally increments never reach the parent. |
| **Disposition** | **FIXED** |
| **Residual risk** | `gateway_validate_macos.sh` still has no mutation suite of its own — the sibling script's `validation_harness_mutants.sh` has no counterpart here, so these controls guard the two primitives and nothing guards the controls. |
| **Commit** | `aaa1c13` |

### VAL-05 — the documented "56 checks" is machine-dependent and gated only by a floor of 32

| | |
|---|---|
| **Severity** | high |
| **Merge blocking** | yes |
| **Reproduction** | `MIN_CHECKS=32` against a 56 quoted as fixed in `SECURITY_AND_PRIVACY.md`, `KNOWN_LIMITATIONS.md` and `PACKAGED_VALIDATION.md`. 24 checks can vanish with zero failures and exit 0. |
| **Root cause** | No inventory, no required-vs-optional split, and a floor where an equality was claimed. The apparatus built for `tracking_validate_macos.sh` was never applied here. |
| **Fix** | The three machine-dependent sites the audit named — `node` presence (1 check), the repair staging block (5), the port re-check (1) — now route through `opt_ok`/`opt_bad`, which tally exactly as `ok`/`bad` do **and** record that the check was environment-dependent. Everything else is REQUIRED, and the gate is now an **equality** on the required count: `pass + fail - optional == 50`. A required check that stops running fails with both numbers printed, whatever the optional ones did. |
| **How 50 was derived** | Measured, not guessed. The packaged macOS job on `141152d` executed 57 checks with node present, the repair block taken and `PORT` set: 57 − 1 − 5 − 1 = 50. The gate prints `required N/50   optional M   total T` on every run, so a wrong constant is a loud failure carrying its own correction. |
| **Tests** | The gate is the test. It executes only on the packaged macOS CI runner — this script installs a LaunchAgent, and `launchctl` addresses `gui/<uid>` regardless of `$HOME`, so it cannot run beside the production gateway on a developer machine. |
| **Mutation** | Not independently mutation-checked. Removing a required check would fail the equality by construction; that has not been demonstrated on a runner. |
| **Disposition** | **FIXED** — with the constant pending confirmation by the first CI run that executes it |
| **Residual risk** | The equality binds the required *count*, not required *identities*: this script still has no register, no per-check IDs and no machine-readable output, so a required check swapped for a different one keeps the count. That is strictly weaker than `tracking_validate_macos.sh`'s per-group table plus fail-closed enumerator, and it is the first item in the handoff. |
| **Commit** | `aaa1c13`, then the equality gate in this pass |

### ENC-01 — legacy-plaintext scrub never runs for a GUI-only user

| | |
|---|---|
| **Severity** | medium |
| **Merge blocking** | yes |
| **Reproduction** | `grep -rn 'scrub' apps/desktop/ --include='*.rs' --include='*.ts' --include='*.tsx'` → no output. Reproduced at the audited head. |
| **Root cause** | ADR 0028 stated the scrub runs in "`Ctx::unlocked`, and the desktop's unlocked commands". The desktop call site did not exist, so the persona the ADR names as the reason the feature exists kept `RA-006` plaintext in `vault.db` indefinitely. |
| **Fix** | Both front ends call one shared function, `envlink::upgrade_restore_records` — the desktop from `vault_unlock`, the CLI from `Ctx::unlocked`. The migration is transactional (rewrites and marker commit together), idempotent, marker-guarded, resumable, records version and row count in `vault_meta`, checkpoints and truncates the WAL after committing, and surfaces failure as an error **code** at both call sites without blocking the command. ADR 0028 corrected. |
| **Tests** | `crates/gateway/tests/legacy_rollback_migration.rs` — 9 tests. A pre-v16 record carrying a JWT-shaped canary is proved readable in raw bytes first, migrated, then `vault.db`, `-wal` and `-shm` are swept and must be clean. Also: undo still opens the sealed value; repeated passes are no-ops; a locked start changes nothing and does not claim completion; an interrupted pass covers both rows on resume; corrupt and newer-build rows are left byte-identical; a negative control proves the sweep can find a planted needle. |
| **Mutation** | Deleting the desktop call site fails `both_front_ends_call_the_shared_migration`. |
| **Disposition** | **FIXED** |
| **Residual risk** | `secure_delete` covers freed pages inside the database file and the checkpoint covers the WAL. Neither reaches free space elsewhere on the volume, a filesystem snapshot, a Time Machine copy, or a backup taken before the upgrade. Stated in ADR 0028 and `KNOWN_LIMITATIONS.md`. The desktop call site is asserted by source inspection, not by driving the Tauri command. |
| **Commit** | `75b8db3` |

### ORG-01 — the `--yes` origin refusal (ZFT-004's fix) has zero test coverage

| | |
|---|---|
| **Severity** | medium |
| **Merge blocking** | yes |
| **Reproduction** | `grep -rn 'allow-origin\|allow_origin\|does not approve' apps/cli/tests/` → nothing. Reproduced at the audited head. |
| **Root cause** | The refusal branch is ZFT-004's entire enforcement point. The library test whose name reads as if it covers this calls `Selections::defaults()` directly and never executes the CLI branch. |
| **Fix** | 11 integration tests driving the real binary. Also fixed while writing them: `args_allows`'s doc comment claimed `https://H/` matched, which `origin::canonicalize` has never accepted — so a user who copied the destination with its trailing slash was told "NOT approved" for the destination they had just named. `validate_allow_origins` now rejects an unusable value up front with an actionable message. |
| **Tests** | `apps/cli/tests/track_origin_refusal.rs`: one custom origin; several; a repository disguising a custom destination as a built-in provider (`OPENAI_BASE_URL` pointing away from OpenAI must not inherit openai's automatic treatment); non-interactive stdin; built-ins still configured while a custom destination is refused; canonicalization equivalents and five near-misses; malformed `--allow-origin`; no approval record persisted; no credential value on the refusal path. Each asserts the database directly: zero approved origins, zero routes, no route at the host, empty LaunchAgents. |
| **Mutation** | Replacing the refusal with `selections.approve_origin(...)` fails 6 of the 11. |
| **Disposition** | **FIXED** |
| **Residual risk** | Every fixture declares only repository-chosen destinations so the run exits before apply step 1, and therefore before `EnsureService` could reach launchd. A mixed built-in/custom repository driven **through** apply is exercised only on the CI runner. "Changed previously approved origin" is covered at the library layer (`origin_trust.rs`), not the CLI, because persisting an approval requires a completed apply. |
| **Commit** | `8628802` |

---

## The two non-blocking security findings

### SEC-01 — a `provider_id` swap redirects a credential to another built-in origin

| | |
|---|---|
| **Severity** | medium · **Merge blocking** no |
| **Reproduction** | `UPDATE gateway_routes SET provider_id='anthropic' WHERE route_prefix='openai'`, then `GET /openai/v1/models`. The audit confirmed by upstream fingerprint that the OpenAI credential reached `api.anthropic.com`. |
| **Root cause** | The route MAC covers custom origins; a shipped-manifest route's `provider_id` is not bound into authenticated state. |
| **Disposition** | **ACCEPTED**, threat model made explicit |
| **Reasoning** | The attacker required is one with **local database write access**. `THREAT_MODEL.md` already documents that metadata edits are not cryptographically detected, and an attacker who can write `vault.db` can also replace the binary, edit the plist, or read the process's memory — the credential is reachable by simpler means than a route swap. Extending the MAC to `(route_prefix, provider_id)` is a genuinely small change, but it is not a *boundary*: it raises the cost of one path out of many available to the same attacker, and presenting it as a defence would overstate what local-DB tamper resistance this product has. |
| **Action taken** | `SECURITY_AND_PRIVACY.md` now states the exclusion explicitly, explains why custom-origin MAC protection does not extend to built-in provider-id tampering, and no user-facing claim implies DB tamper resistance beyond what exists. |
| **Residual risk** | An attacker with local write access to `vault.db` can redirect a credential to another **shipped-manifest** provider. Custom origins remain MAC-protected. |
| **Commit** | this pass (documentation) |

### SEC-02 — request bodies lack an absolute deadline, allowing slot exhaustion

| | |
|---|---|
| **Severity** | medium · **Merge blocking** no |
| **Reproduction** | Complete headers with `Content-Length`, then dribble 1 byte every 5s: still open after 162s. |
| **Root cause** | The head phase had `CLIENT_HEAD_DEADLINE`; the body phase had only a 60-second per-read idle timeout, which bounds the gap between reads and not the total. |
| **Fix** | `stream::DeadlineReader` wraps the client for the **request body only** and refuses past `CLIENT_BODY_DEADLINE` (300s). Response streaming is deliberately untouched — a long model response is a legitimate long-lived read, and bounding it would break streaming completions. |
| **Tests** | Two deterministic unit tests in `crates/gateway/src/stream.rs`, including a control proving the wrapper is not simply refusing everything. |
| **Mutation** | The control test is the mutation guard: a wrapper that refuses everything fails it. |
| **Disposition** | **FIXED** |
| **Residual risk** | The check happens **between** reads, so the true bound is the deadline plus one idle timeout (≈360s worst case), not 300s exactly. Stated in the code and in `KNOWN_LIMITATIONS.md`. Making it exact needs a non-blocking rewrite of the relay for no additional safety. 128 clients can still occupy all slots for up to that bound; the gateway fails closed with 503 and recovers. |
| **Commit** | `aaa1c13` |

---

## The remaining seventeen

| ID | Sev | Blocking | Finding | Disposition | Detail |
|---|---|---|---|---|---|
| `ENC-02` | medium | no | Dropping the `sealed` field silently empties the user's `.env` while reporting `complete:true` | **DEFERRED** | Requires a `had_prior` flag or a MAC over `prior_env_json`. The attacker is the gateway compartment (opens `vault.db` read-write, key withheld) — the same local-write attacker as `SEC-01`, and destructive rather than exfiltrating. Not addressed in this pass; recorded in the handoff as the highest-value remaining non-blocker. |
| `VAL-06` | medium | no | The check enumerator is not fail-closed as its header claims | **DEFERRED** | Ten shapes miscount without an error. Contained by the runtime per-group equality gate, which turns each into a loud `INCONCLUSIVE` rather than a false green. The header claim is still broader than the behaviour. |
| `VAL-07` | medium | no | REM-004 privacy exclusion is a whole directory, not the helper binary | **DEFERRED** | `grep -v "^$DIR/bin/"` excludes every file in the directory while the soundness argument covers exactly one. Cannot mask a per-run leak — the fake-key and canary sweeps do cover `$DIR/bin`. |
| `VAL-08` | medium | no | REM-003 helper provenance is an unanchored substring grep | **DEFERRED** | Nothing ties `ProgramArguments[0]` to the installed helper. The byte-identity half is sound and cannot pass without a real bundled helper. |
| `ORG-02` | low | no | `*.localhost` is offered for approval and disclosed as "a public internet address" | **DEFERRED** | RFC 6761 reserves the TLD. Contained by the post-DNS filter, so no credential reaches loopback; the harm is a false disclosure and a route that can never work. |
| `VER-03` | low | no | RFC 3339 UTC offsets are admissible where byte order is assumed | **ACCEPTED** | Requires direct DB write access. The only production writers emit `Z` (`clock::now_rfc3339`). Grants no capability beyond what DB write already grants. |
| `VER-04` | low | no | Retention can strand the rowid watermark | **DEFERRED** | Fails closed (reports waiting-for-first-request), availability only, bounded not permanent. |
| `GIT-01` | low | no | `write_alternates` truncates the chain silently instead of refusing | **DEFERRED** | Inconsistent with every other bound in the module, which refuse loudly. No configuration authority is gained. |
| `ENC-03` | low | no | AAD colon-joins unescaped fields, allowing a delimiter collision | **DEFERRED** | Confined to one (vault, link). `plan_digest` in the same file already length-prefixes and is the model for the fix. |
| `ENC-04` | low | no | `prior_value_is_recordable` is dead code, still `pub`, and misdescribed by ADR 0028 | **DEFERRED** | ADR 0028 was corrected for `ENC-01` in this pass; this specific claim ("gates display, never storage") was not revisited and the function was not removed. |
| `CON-01` | low | no | `track undo` reports "Tracking stopped" while a concurrent apply leaves tracking on | **DEFERRED** | No corruption, but a false success claim in a product whose verification design exists to avoid exactly that. The `VER-01` CAS makes the underlying state consistent; the *reporting* is unchanged. |
| `CON-02` | low | no | Concurrent first-time setups surface a raw driver error | **DEFERRED** | `UNIQUE constraint failed: projects.name` reaches the user verbatim. Serialization is accidental rather than designed. |
| `CON-03` | low | no | Tauri command inventory is stale: 64 of 201 commands un-inventoried | **DEFERRED** | The 64 missing are exactly this PR's surface. The commands were audited by source; no bypass was found. Regenerating the inventory in CI is the fix. |
| `VAL-09` | low | no | The REM-005 remediation note misstates why the old gate failed | **DEFERRED** | It failed for one reason (pretty-printing), not the two claimed. Note untouched. |
| `VAL-10` | low | no | The duplicate-name detector keys on group+name | **DEFERRED** | A name reused across two groups is invisible to the harness. The CI asserter now rejects global duplicates for `full:service`; the offline job still has no asserter. |
| `VAL-11` | low | no | Weak or overclaiming assertions in both validation scripts | **DEFERRED** | Non-emptiness-only checks, `COUNT(*)>=1` for "recorded history was KEPT", labels claiming a locked vault when nothing locks one. |
| `REPO-01` | info | no | `main` has no branch protection and no rulesets | **BLOCKED — external** | A repository setting, not a code change. Requires admin access to the GitHub repository; cannot be done from this branch. Compounds `VAL-01`: a required check is a convention until it is enforced. |

---

## Summary

| Disposition | Count | IDs |
|---|---|---|
| FIXED | 10 | `VAL-01` `VAL-02` `VAL-03` `VAL-04` `VAL-05` `VER-01` `VER-02` `ENC-01` `ORG-01` `SEC-02` (`SEC-02` non-blocking) |
| PARTIAL | 0 | — |
| ACCEPTED | 2 | `SEC-01` `VER-03` |
| DEFERRED | 15 | `ENC-02` `ENC-03` `ENC-04` `VAL-06` `VAL-07` `VAL-08` `VAL-09` `VAL-10` `VAL-11` `ORG-02` `VER-04` `GIT-01` `CON-01` `CON-02` `CON-03` |
| BLOCKED (external) | 1 | `REPO-01` |

**Merge blockers: 9 of 9 fixed**, with `VAL-05`'s required-count constant awaiting
confirmation from the first CI run that executes it, and its residue (no
per-check identities in the gateway script) recorded.

Every one of the 28 findings has a disposition. Nothing here should be read as
a merge recommendation — a fresh independent auditor makes that call, and the
fifteen deferred findings plus `VAL-05`'s residue are stated so they can.
