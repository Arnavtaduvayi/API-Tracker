# Remediation evidence

Executed evidence for the remediation of PR #16 against the independent
audit `audit/fable-zft-independent-20260727` (`4edd6a0`), which audited
`24acc470`.

This file records **what was run and what it printed**, not what was
intended. Where something was not run, that is stated rather than omitted.

---

## 1. The CRITICAL, reproduced and then closed

### Before (audited head `24acc470`, release build)

Built from the audit worktree, whose `crates/` and `apps/` are byte-identical
to the audited head (`git diff --stat 24acc470 HEAD -- crates apps` → empty):

```text
$ mkdir hostile && cd hostile
$ printf '#!/bin/sh\necho "PAYLOAD EXECUTED argv=$#" >> …/PWNED.txt\n' > payload.sh
$ chmod 755 payload.sh
$ git init -q . && git config core.fsmonitor "$PWD/payload.sh"
$ printf 'OPENAI_API_KEY=sk-proj-RCEPROBE…\n' > .env
$ echo '{"dependencies":{"openai":"^4"}}' > package.json
$ tethra track "$PWD" --dry-run

Scanned: …/hostile  (this folder only; nothing executed or uploaded)
Detected:
  openai      confirmed   Found OPENAI_API_KEY in .env (value not read); …
Dry run: nothing was changed.

$ cat PWNED.txt
PAYLOAD EXECUTED argv=2
PAYLOAD EXECUTED argv=2
PAYLOAD EXECUTED argv=2
PAYLOAD EXECUTED argv=2
```

Instrumenting the payload to record its parent identified the exact
invocations, which the audit had inferred:

```text
argv=2 1785180497401201000
  …/git -C …/hostile ls-files --error-unmatch -- .env
argv=2 1785180497622257000
  …/git -C …/hostile check-ignore -q -- .env
  (repeated once each — two probes per discovered .env file)
```

Two corrections to the audit's own account, neither weakening it:

* the trigger is `ls-files --error-unmatch` and `check-ignore` only —
  `rev-parse` and `log` did not fire the hook;
* the hook fires when git runs from a working directory **outside** the
  scanned repository (which is how the product invokes it) and stays quiet
  when run from inside it. A control test written the wrong way round would
  have proved nothing. `tests/git_execution_canaries.rs` therefore sets an
  explicit `current_dir` outside the fixture, and the product's own
  `spawn_git` does the same.

### After (this branch, same fixture, same binary path)

```text
$ tethra track "$PWD" --dry-run
Scanned: …/hostile  (this folder only; nothing executed or uploaded)
Recognised:
  openai      confirmed   Found OPENAI_API_KEY in .env (value not read); …
Dry run: nothing was changed.

$ cat PWNED.txt
cat: …/PWNED.txt: No such file or directory
```

Detection is unchanged; nothing executed.

### The control that keeps this honest

`each_canary_is_armed_against_unhardened_git` runs the **unprotected**
equivalent against the same fixture and **requires the canary to fire**. A
suite whose canaries had quietly stopped being reachable would fail here
rather than reporting all green.

Two failures found while writing it, both fixed in the test rather than
worked around:

* the fixture must `git add` + `git commit` before arming, or
  `core.fsmonitor` is never consulted and the whole file is vacuous;
* the tests must be serialized — two of them mutate process-wide
  environment variables (`HOME`, `GIT_CONFIG_*`), and cargo runs tests as
  threads of one process, so without a lock those mutations leaked into the
  control and silently disarmed it.

---

## 2. The origin-trust reproduction

### Before

```text
$ echo '{"dependencies":{"@supabase/supabase-js":"^2.39.0"}}' > package.json
$ echo 'SUPABASE_URL=https://attacker-controlled.example.com' > .env.development
$ tethra track . --dry-run
Will do:
  2. create routes: supabase → https://attacker-controlled.example.com
```

The fixture contains **no secrets at all**.

### After

The same fixture, same command: the destination appears under
*"Destinations read from this project (not from Tethra)"* with its full
disclosure and is **not** configured. `--yes` reports:

```text
    → NOT approved: --yes does not approve a project-chosen destination.
      Re-run interactively, or pass --allow-origin https://attacker-controlled.example.com:443
```

`crates/tracking/tests/origin_trust.rs::a_yes_run_cannot_route_to_an_unapproved_repository_origin`
asserts both halves: the attacker's host appears in no planned action, and
the SAME fixture with an explicit approval DOES plan the route — so the
assertion is about authorization, not about having broken the feature.

---

## 3. Mutation checks

`scripts/mutation_checks.sh` removes each protection from the production
source, runs the test that claims to cover it, and requires that test to
**fail**. Restoration runs from an EXIT trap.

**Result: 18 checks, 18 killed, 0 surviving mutants, 0 skipped.**

The first run found **three surviving mutants and one skipped check**. All
four were real gaps, and all four are now closed:

| Mutant | Why it survived | What closed it |
|---|---|---|
| `stackdetect-refuses-symlinks` | `tests/bounds.rs` covered a symlinked `.env` only, then certified the broader bound | new `tests/scan_bounds.rs` covers a symlinked `package.json`, `requirements.txt`, `pyproject.toml` and marker file |
| `env-size-cap-precedes-the-read` | the oversized test exercised the OTHER reader, which did check its cap | `scan_bounds.rs` asserts `entry_count == 0`, which can only hold if the bytes were never parsed |
| `repair-does-not-force-past-the-ownership-refusal` | no test covered `repair`'s force flag at all | `service_namespace.rs::repair_refuses_a_slot_that_belongs_to_another_installation`, with a control that repair on our own slot still works |
| `destructive-verbs-prove-ownership` (skipped) | the anchor text did not match the source | anchor corrected; the mutant now kills |

One further mutant was rewritten rather than accepted: the first
`scan-uses-gitsafe-not-git` mutation routed through the **hardened** runner,
so the canary correctly stayed quiet and the mutant survived *for the right
reason* — which made the check meaningless. It now injects a raw, unhardened
`Command::new("git")`, exactly the pre-remediation code, and kills.

---

## 4. Adversarial verification of the parallel workstreams

Two workstreams were implemented by independent agents and then attacked by
independent verifiers instructed to refute them. Both verifiers returned
**DEFECTIVE**, and their findings were acted on rather than filed.

### Service namespacing — four ways back into ZFT-014

| Defect found | Status |
|---|---|
| `repair()` hardcoded `force = true`, bypassing the ownership refusal — and repair is on the automatic `track` path | fixed: `repair` no longer forces |
| `start()` and `register()` had no ownership proof; macOS `start` falls back to `register`, which bootstraps a plist into the live session | fixed: `ensure_ours` on both, all three platforms |
| an **unparseable** definition was treated as absent and silently overwritten | fixed: unparseable is foreign, refuses without `--force` |
| a failed migration left the new plist beside the legacy one; launchd loads both at login | fixed: install rolls the new definition back |
| `plan()` never consulted `matches_data_dir`, so a foreign slot fell through to repair-or-start | fixed: hard stop naming the other data directory |
| `disable()` discarded the `stop()` error, hiding the ownership refusal | fixed: recorded in notes |

### Provider coverage — the counts hold, the wiring did not

The verifier independently re-derived the counts (21 / 13 / 8) and confirmed
every base-URL variable against official SDK source. It also found the
change was **inert**: `MANIFEST_SOURCES` is a hand-written `include_str!`
array, so `providers::manifests()` still returned 5 while all 21 files
existed on disk — and the new conformance test read the *directory*, so it
reported 11 passed against a catalog the binary never loaded.

Fixed: all 21 registered, `stackdetect` dependency maps, `LOCKFILE_NEEDLES`
and `provider_template` extended so the new manifests are reachable, and
`cargo run -- provider list` verified to print 21 rows.

The verifier's remaining test-gap findings are recorded as follow-ups in
`RE_AUDIT_HANDOFF.md` — in particular that
`embedded_catalog_agrees_with_the_manifest_directory` checks embedded →
disk but not disk → embedded, which is exactly the direction that would
have caught the inert state.

---

## 5. What was NOT executed

Stated plainly so a re-auditor does not have to infer it:

* **No real service was installed, started, stopped or booted out** at any
  point in this remediation, on this machine or in CI. The audit's own run
  took down the user's production gateway; every service test here runs
  against a mock `CommandRunner` in temporary directories.
* **`ZFT-014` was reproduced by source analysis, not live**, for the same
  reason.
* The packaged macOS validation's LaunchAgent lifecycle is covered in
  `PACKAGED_VALIDATION.md`, including what CI does and does not execute.
