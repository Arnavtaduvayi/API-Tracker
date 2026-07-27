# Remediation handoff — PR #16 after the independent audit

Read `audit/REMEDIATION_MATRIX.md` for the per-finding detail,
`audit/REMEDIATION_EVIDENCE.md` for what was actually executed, and
`audit/RE_AUDIT_HANDOFF.md` if you are the next auditor.

This page is the orientation: what changed, why, and what to distrust.

---

## The shape of the problem

The audit's own summary is worth keeping: *"a strong implementation with a
specific and correctable class of failures"*. The supported journey worked —
packaged app, no CLI on PATH, four in-app steps to verified activity, bulk
multi-provider configuration, no manual route creation, gateway enforcement
intact at 269/269. None of that was undone.

The failures clustered in four places, and each had the same shape: **a
promise in a document that the code did not keep.**

| The promise | What the code did |
|---|---|
| "Parse-only: nothing is executed" | scanning a folder ran attacker code four times, during `--dry-run` |
| "requires an explicit checkbox (never part of Confirmed auto-config)" | there was no checkbox, and the desktop shipped it pre-checked |
| "a stale row can never overclaim `traffic_observed`" | killing the gateway left it claiming verified |
| "one login slot per user" | a second Tethra environment took down the first |

That pattern is why this remediation puts so much weight on mutation
testing. A test that passes is not evidence; a test that **fails when you
remove the protection** is.

---

## What changed, in one paragraph each

**Scanning no longer runs anything the project controls** (ADR 0023). A new
`core::gitsafe` answers the questions detection needs — is this inside a
work tree, is this file tracked, is it ignored — by reading `.git/index` and
the ignore files directly. The automatic path spawns no subprocess. Where
git is still genuinely needed (the deliberate secret scanner, the pre-commit
hook, the history probe) it runs under `-c` overrides for every config key
that names a program, a scrubbed environment, and a controlled working
directory.

**Repository content is evidence, never authorization** (ADR 0024). Origins
from a compiled-in manifest stay automatic — that is what keeps setup to
four clicks. Origins read from the project require an explicit per-origin
decision that defaults to no, in both frontends, built from one shared Rust
description so they cannot drift. `--yes` refuses them.

**"Verified" describes the present** (ADR 0025). Each apply opens a
verification session; only observations from the current session verify the
current setup. Present-tense success additionally needs a recent
observation, a live route, a live link, and a gateway that answers *now*.
History lives in its own type and renders under its own heading, so "first
verified: July 27" can be shown without implying anything about today.

**One service slot per data directory** (ADR 0026). Service names are
namespaced by the canonicalized data directory, and every verb that touches
the OS proves the definition belongs to this installation first.

---

## What to distrust in this remediation

Written here rather than buried, because the audit's central lesson was that
confident documentation is where defects hide.

1. **The provider catalog's honesty is unverifiable by CI.** 21 manifests,
   13 trackable. Every base-URL variable was checked against the SDK's own
   source and the source recorded in a comment — but nothing in the test
   suite can tell a fabricated variable name from a real one. A fourteenth
   added carelessly would pass every test.
2. **The hardened-git key list is an enumeration.** It covers every
   documented execution surface today. A future git version could add one.
   This is why the path that matters spawns nothing at all.
3. **`--scope full` packaged validation has not been run for this branch.**
   It refuses to run on a machine with a Tethra gateway installed, and this
   one has one. CI runs `--scope offline` (20 checks) against a real `.app`
   and says exactly that.
4. **Windows service support is compile-validated only** — as it was before.
5. **Three ZFT-009 desktop actions were deliberately not built** rather than
   added as dead buttons. `KNOWN_LIMITATIONS.md` names them.
6. **Two parallel workstreams were implemented by agents and then found
   DEFECTIVE by adversarial verifiers** — the service namespacing in four
   ways, the provider catalog by being entirely inert. Both were fixed, but
   the lesson is that this branch's newest code has had one round of
   adversarial review, not years of use.

---

## Numbers

Every one is measured from the final commit; none is carried over.

```text
Rust workspace tests           1133 passed, 0 failed
Desktop vitest                   91 passed, 0 failed (11 files)
Smoke suite                     140 passed, 0 failed
Mutation checks (product)        21 killed, 0 survivors, 0 skipped
Mutation checks (harness)         8 killed, 0 survived
Packaged validation (offline)    20 passed, 0 failed
Packaged validation (selfcheck)   5 passed, 0 failed
Provider manifests                21 total, 13 trackable, 8 unsupported
clippy +1.97.0 --all-targets -D warnings   clean
cargo fmt --all --check                    clean
eslint / tsc / vite build                  clean
```

`--scope full` (57 or 60 checks) was NOT run — see above.

---

## Where the audit itself was wrong

Recorded because a re-auditor will otherwise re-derive it:

* `ZFT-033` — the marker comment is emitted once per **written variable**,
  not "twice per file". Worse than reported.
* `ZFT-042` — a stale plist does not crash-loop; the service exits cleanly
  and `KeepAlive={Crashed:true}` treats that as terminal. The defect is an
  orphaned Login Item, which is still real.
* `ZFT-014` — the title said "any existing gateway service"; reaching it
  from `track` needs the repair branch or a start fallback. But the surface
  was *wider* than described: `gateway stop`/`uninstall`/`install --force`
  gated only on `installed`, and `uninstall` deleted another environment's
  definition.
* `ZFT-001` — the trigger is `ls-files` and `check-ignore`, confirmed, but
  only when git runs from a working directory outside the repository. A
  control test written the other way round proves nothing.

---

## What has NOT been decided

Whether this is ready to merge. PR #16 is open and unmerged deliberately.
That decision belongs to a fresh independent audit of the exact remote head,
briefed by `audit/RE_AUDIT_HANDOFF.md`.
