# Packaged macOS service-lifecycle evidence

The authoritative execution of `--scope full --require-service`, and of the
gateway lifecycle verbs, on a disposable clean-room runner.

This page exists because that scope had **never been observed passing
anywhere**. Its own precondition is a machine with no installed Tethra
gateway; the developer machine carries a live production one, and running it
there is how `REM-001` was found — a redirected `$HOME` does not isolate
launchd, and the run booted the user's real gateway out of `gui/<uid>`.

Nothing here is a re-description of an earlier run. Every number below comes
from a named GitHub Actions run whose logs and machine-readable results are
attached to that run as an artifact.

---

## 1. The premise that had to be checked first

The previous CI configuration retired this scope with a technical claim:

> a hosted runner has no login session to register into, `launchctl bootstrap
> gui/<uid>` behaves differently under Actions than on a real desktop

**That claim is false, and it had never been measured.** Run
[`30323981718`](https://github.com/Arnavtaduvayi/API-Tracker/actions/runs/30323981718)
was a throwaway probe that measured it:

```text
whoami:               runner            uid: 501       HOME: /Users/runner
launchctl managername Aqua                             <- a real GUI login session
launchctl print gui/501                                exit 0
  creator            = loginwindow[162]
  session            = Aqua
launchctl bootstrap gui/501 <plist>                    exit 0
  -> THE AGENT RAN (marker written; state = running; pid 1817)
launchctl kickstart -k gui/501/<label>                 exit 0
launchctl bootout   gui/501/<label>                    exit 0, no residue
launchctl bootstrap user/501 <plist>                   exit 5 (Input/output error)
curl https://api.openai.com/v1/models                  401
```

`loginwindow` and `WindowServer` are both running on the image. The `gui`
domain is the right one and works; only the `user` domain refuses.

This matters more than the missing coverage did. A gap somebody can see gets
closed; a **wrong reason** for not testing survives, because it looks like a
decision that has already been made. The claim is corrected in `ci.yml`.

---

## 2. Runner and environment

| Field | Value |
|---|---|
| Runner image | `macos-26-arm64` (`macos-latest`), image version `20260720.0258.1` |
| macOS version | 26.4, build `25E246` |
| Architecture | `arm64` (Darwin 25.4.0, `RELEASE_ARM64_VMAPPLE`) |
| User / uid | `runner` / 501 |
| `HOME` | `/Users/runner` |
| launchd session | `Aqua` (`gui/501`, created by `loginwindow`) |
| Runner version | 2.336.0, Azure region `westus` |

The runner is destroyed after the job. It is not "a machine we cleaned"; it
is a machine that never had Tethra on it.

---

## 3. The authoritative run

Two runs are recorded. The second is the one that matters for PR #16, because
it ran on the **exact PR head**; the first is kept because it is the run whose
numbers §4 quotes and because deleting the working history would be the same
dishonesty this page exists to avoid.

The job runs on **every** head, so the authoritative answer for whatever the
head is when you read this comes from `gh pr checks 16`, not from a hash typed
here. Three runs are named below because each says something the others do not.

```text
Workflow:   Packaged macOS service lifecycle
            .github/workflows/packaged-service-macos.yml

--- the last CODE change on this branch ----------------------------------
Run ID:     30328567106
Commit:     3f7bff90  (feat/zero-friction-api-tracking, PR #16)
Result:     tracking  63 passed, 0 failed (63/63)  verdict PASS, 0 skipped
            lifecycle 56 passed, 0 failed   <- `repair` added here (was 51)
            cleanup   VERIFIED

              == 22b. Repair: damage an OWNED resource and re-align ==
                PASS  the installed helper was removed
                        (damage staged: tethra-gateway-0.1.0)
                PASS  gateway repair completed
                PASS  repair restored the installed helper binary
                PASS  the gateway is serving again after repair
                PASS  repair did not touch the production label

--- the previous code head, all six checks green -------------------------
Run ID:     30327487534
Commit:     9bbe3b10
Label:      dev.api-tracker.gateway.6b44b8d8867e
Result:     tracking 63/63, lifecycle 51/51, cleanup verified,
            all 6 required PR checks green

--- the first head to carry the finished evidence ------------------------
Run ID:     30326526816     duration 11m52s
Commit:     bf421b9f
Label:      dev.api-tracker.gateway.6c7a0d0c85df
Result:     identical: 63/63, 51/51, cleanup verified, 6/6 checks green
            (lifecycle was 51 here: `repair` was added afterwards)

--- the development run whose detail §4 quotes ---------------------------
Run ID:     30325704492
Commit:     b92c8e09        (branch ci/service-lifecycle-dev)
Label:      dev.api-tracker.gateway.39d11f8db375
Result:     identical: 63/63, 51/51, cleanup verified
```

Any commit after `9bbe3b10` on this branch is documentation only — this file
included. Those commits get their own run of the same required job, linked
from the PR; naming their hashes here would be a hash chasing its own tail,
because writing the hash changes it.

Note the three labels all differ (`6b44b8d8867e`, `6c7a0d0c85df`,
`39d11f8db375`) and none is the production label. They are derived from each
run's own data directory (`/tmp/tethra-track-val-<pid>`), which is what makes
the namespace run-specific rather than merely test-specific — and three
independent runs producing three different labels is that property observed
rather than argued.

The detail in the rest of this section is quoted from `30325704492`; the
PR-head run reproduces every number.

### Clean-runner preconditions — asserted, never remediated

`scripts/ci_service_preconditions.sh` is read-only by construction. It
inspects and refuses; it never removes, boots out, stops or repairs anything,
**not even to make the test runnable**. Deleting unknown pre-existing state to
force a run to continue is `REM-001` in a new costume.

```text
OK   no gateway job is registered in launchd (gui/501)
OK   no gateway LaunchAgent plist exists under /Users/runner/Library/LaunchAgents
OK   no gateway process is running
OK   no installed gateway helper (no ~/Library/Application Support/api-tracker/bin)
OK   no shared data directory at ~/Library/Application Support/api-tracker
OK   no control endpoint at ~/Library/Application Support/api-tracker/gateway.sock
OK   no vault database (and therefore no route state)
OK   no stale /tmp/tethra-track-val-* namespace
OK   no tethra CLI on PATH
OK   the gui/501 launchd domain exists (session: Aqua)
=== PRECONDITIONS PASSED — this is a clean room ===
```

The launchd check asks **launchd**, not the filesystem. The plist globs are
keyed on `$HOME`; `launchctl` is not — it addresses `gui/<uid>`, which no
`HOME` redirection isolates. Checking only the filesystem is exactly how
`REM-001` walked past a `$HOME`-keyed interlock while the damage landed on the
real service.

### Service namespace

```text
Data directory:  /tmp/tethra-track-val-13774          (per-run, per-pid)
Service label:   dev.api-tracker.gateway.39d11f8db375
Definition:      /Users/runner/Library/LaunchAgents/
                   dev.api-tracker.gateway.39d11f8db375.plist
Control socket:  $TETHRA_DIR/gateway.sock             (mode 0600)
```

The label is not invented by the harness. The product derives it (ADR 0026:
`installation_id` = first 12 hex of `blake3::derive_key` over the canonical
data directory), so it is **test-specific by construction** — the production
label `dev.api-tracker.gateway` is unreachable from an isolated data
directory. `scripts/ci_assert_service_results.py` turns that design property
into a checked one: the recorded label must be non-empty, must not equal the
production label, and must sit inside the `dev.api-tracker.gateway.*` family.

### Checks executed and passed

```text
=== PACKAGED TRACKING VALIDATION (scope=full, mode=service): 63 passed, 0 failed (63/63 checks) ===

verdict          PASS
scope / mode     full / service
executed         63       expected 63
passed           63       failed 0       skipped 0     duplicate names 0
```

| Group | Executed / declared | Failed |
|---|---|---|
| HARNESS | 5 / 5 | 0 |
| BUNDLE | 5 / 5 | 0 |
| FIXTURE | 3 / 3 | 0 |
| DRYRUN | 6 / 6 | 0 |
| **SERVICE** | **9 / 9** | 0 |
| APPLY | 9 / 9 | 0 |
| NEGATIVE | 8 / 8 | 0 |
| TRAFFIC | 5 / 5 | 0 |
| PRIVACY | 5 / 5 | 0 |
| IDEMPOTENCE | 4 / 4 | 0 |
| UNDO | 4 / 4 | 0 |

No check is skipped, and none is informational: the harness has no "skip"
state at all — a check either executes and is counted, or the run is
`INCONCLUSIVE` and nothing from it is quotable.

### Service installation, process and control identity

The nine SERVICE checks, verbatim from `results.json`:

```text
pass  the dry run installed no LaunchAgent
pass  the apply installed a real LaunchAgent
        (resolved: ~/Library/LaunchAgents/dev.api-tracker.gateway.39d11f8db375.plist)
pass  the installed LaunchAgent declares its own namespaced label
pass  the label is namespaced per data directory, not the global one
pass  the LaunchAgent runs the helper the product installed in this run's
        data directory, not a developer CLI
pass  the installed helper is byte-identical to the in-bundle helper
        (the service runs the shipped program)
pass  launchd loaded the namespaced service
        gui/501/dev.api-tracker.gateway.39d11f8db375
pass  the running service (pid 14042) executes the program its own plist declares
pass  the service exposes its control endpoint at $TETHRA_DIR/gateway.sock, mode 0600
```

Process identity is **identity, never a pattern**: the plist's
`ProgramArguments[0]` is read with `PlistBuddy`, the pid is read from
`launchctl print` for the owned label, and `ps -o comm=` must return that
exact program. Matching by name is what makes a `pkill -f tethra` reach a
user's production gateway; an assertion built the same way would certify the
wrong process just as happily.

### Traffic, verification and undo

Unchanged in structure from the foreground scope and passing here against a
**real login-registered service** rather than a foreground child:

* a forged pre-apply gateway observation does not verify anything (8 NEGATIVE
  checks, including the armed-control assertion that the forgery was really
  inserted);
* one real request to `api.openai.com` with a fake key returns `401` through
  the gateway, and only then does `track status` exit 0;
* neither the credential value nor the unrelated env canary appears anywhere
  in the isolated data directory or the shared one;
* `track undo` restores the `.env` byte for byte (`cmp`, not string equality).

### Lifecycle verbs

`scripts/gateway_validate_macos.sh`, in the same clean room, immediately
before the bundle build:

```text
=== PACKAGED MACOS RESULT: 56 passed, 0 failed ===

== 22b. Repair: damage an OWNED resource and re-align the installation ==
  PASS  the installed helper was removed (damage staged: tethra-gateway-0.1.0)
  PASS  gateway repair completed
  PASS  repair restored the installed helper binary
  PASS  the gateway is serving again after repair
  PASS  repair did not touch the production label
```

Covering install → bootstrap → push-key → attribution → vault lock/unlock →
**stop** → doctor → **restart** → **repair** → unlink → **uninstall** →
verification that the plist, launchd registration, control socket, control
nonce and service binaries are all gone → ordinary networking unaffected →
negative controls → and the isolation invariant:

```text
PASS  the production plist is exactly as this run found it (absent)
PASS  the production label was never registered in gui/501 by this run
```

The previous handoff recorded "I did not run
`scripts/gateway_validate_macos.sh` against the real `$HOME`" as an explicit
gap. That gap is closed here rather than by reimplementing the same lifecycle
inside the tracking harness, because two harnesses asserting the same
property is how they drift.

**`repair` was added while writing this page.** The brief asks for stop,
start, restart, status, repair and uninstall *where supported*; `gateway
repair` is supported — `install(force = false)` underneath: re-copy the
binary, rewrite the definition for this data directory, re-register, restart —
and the script called `doctor` but never the repair `doctor` hints at.
Recording the lifecycle as covered while that verb had never executed would
have been `REM-003` again, in the page claiming to have found it. The damage
is staged against a resource this run owns (the installed helper under
`$TETHRA_DIR/bin`), and the check asserts repair restored it, the gateway
serves again, and the **production label was not registered** — the last
mattering because repair takes the install path, which is where a slot
takeover would happen if ownership were not proven first.

### Cleanup

Verified from **outside** the script, after its `EXIT` trap had already run.
A claim made by the thing under test is the weakest kind of evidence, so the
clean-room preconditions are simply re-asserted:

```text
OK   no gateway job is registered in launchd (gui/501)
OK   no gateway LaunchAgent plist exists
OK   no gateway process is running
OK   no installed gateway helper
OK   no shared data directory
OK   no control endpoint
OK   no vault database
OK   no stale /tmp/tethra-track-val-* namespace
=== CLEANUP VERIFIED: the machine is as clean after the run as before ===
```

**Remaining artifacts: none.** The clean room is byte-for-byte a clean room
again — every resource created (data directory, snapshot directory, ownership
ledger, LaunchAgent definition, launchd registration, installed helper,
control socket, control nonce, pid file) was removed.

---

## 4. Failure reproductions fixed

Every one of these was found **by the new job**, on a clean runner, and none
could have been found anywhere else, because the scope had never run.

### `REM-003` — a check that had never executed, asserting something the product does not do

```text
FAIL  the installed LaunchAgent runs the bundled helper, not a developer CLI
```

The plist never names the bundle path. `gateway install` deliberately copies
the running CLI to `<data-dir>/bin/tethra-gateway-<version>` and points the
plist there, so the login item survives the `.app` being moved, updated or
deleted. The check was written blind against a scope nobody could run.

Replaced by two assertions that are each stronger than the one they replace:
the plist runs the copy installed inside **this run's** data directory, and
that copy is **byte-identical** to the in-bundle helper. Provenance is proven
rather than inferred from a path.

### `REM-004` — the privacy header sweep matched the product's own binary

```text
FAIL  no authorization header line and no bearer token is stored
        — hits: /tmp/tethra-track-val-19180/bin/tethra-gateway-0.1.0
```

A compiled forwarding proxy necessarily carries the literal strings
`authorization:` and `Bearer ` as its own constants. In service mode that
binary lands inside `$TETHRA_DIR`; foreground mode never produces it, which is
why no previous run saw this.

Excluded from the **header sweep only**. The exclusion is sound because of an
assertion, not an assumption: the binary is now proven byte-identical to the
shipped one, so it cannot hold anything captured at runtime. It is narrow: the
two per-run needles (the fake key and the unrelated env canary) still sweep
that directory, and they are the ones that could only appear there by capture.

### `REM-005` — an assertion gated on a field its command never emits

The gateway lifecycle script reported, in the same step:

```text
PASS  matching key pushed (attribution enabled)
SKIP  attribution distinctness: no matching key resident (push-key needs a TTY)
FAIL  attribution distinctness NOT verified (no matching key)
```

Two contradictory claims, one of which blamed a TTY that had demonstrably
worked. Adding a diagnostic settled it:

```text
spawn .../tethra gateway push-key
Master password:
credential-matching key installed          <- it worked, every time
```

The gate was:

```sh
"$CLI" --json gateway status | grep -q '"matching_key_present":true'
```

`--json gateway status` emits the **doctor** document — `overall`,
`findings[]`, and a `service` object — and has never carried
`matching_key_present`; that field lives on the control-channel status
(`crates/gateway/src/control.rs`). The grep could not match for two
independent reasons: the field is absent, and the document is pretty-printed
while the pattern has no space.

So the else-branch fired on **every run for the whole life of the check**. A
gate that is always false does not protect an assertion, it deletes it — the
`ZFT-VAL-7` shape inverted: instead of a check that cannot fail, a check that
cannot run. The gate is removed; the two assertions are unconditional and are
themselves the ground truth about whether the key is resident.

Note the shape of the original `PASS`: it was `expect ... && ok "matching key
pushed"`, which asserts that **expect** ran to eof — a statement about the
harness, not the product. It is now the product's own success line.

### `REM-006` — the `RA-004` evidence was not reproducible

`FINAL_REMEDIATION_EVIDENCE.md` §`RA-004` quotes sha256 pairs, a `launchctl`
invocation log and a four-row mutation table. **The harness that produced them
was never committed.** The strongest safety claim in the remediation rested on
output nobody could regenerate, which is the same defect class as an uncounted
check: a claim whose control cannot be re-run is a claim, not evidence.

`scripts/service_cleanup_safety.sh` is that harness, committed. See §6.

---

## 5. Trap ordering and the ownership ledger, applied consistently

`gateway_validate_macos.sh` already had the right model.
`tracking_validate_macos.sh` did not: it armed `trap cleanup EXIT` **before**
its mode preconditions ran, so a refusal fired a destructive teardown. One
script having the safe design is not the same as the design being the house
style, so the model is now applied to both.

The order is now, in `tracking_validate_macos.sh`:

1. parse arguments
2. resolve the test namespace
3. clean-runner preconditions
4. prove the namespace is non-production
5. initialise the ownership ledger
6. **only then** register cleanup
7. create resources
8. run validation
9. clean only owned resources
10. verify complete cleanup

Teardown is ledger-driven and re-proves ownership before acting: a plist is
removed only while it still declares the recorded label **and** points at this
run's data directory; a launchd job is booted out only under a recorded label
that is never the production one; a process is signalled only when that pid
still runs that binary; an `rm -rf` is bounded by a `/tmp/tethra-track-val-*`
prefix guard so a truncated ledger cannot widen it. A recorded resource that
stops proving ownership is **left in place and reported** — a visible stray
file is a far smaller harm than deleting a file we can no longer prove we
wrote.

A new invariant runs on every exit, including refusals:

```text
production definition unchanged (996-bytes mtime=1785158120 mode=600)
```

Snapshotted before the trap is armed and compared after teardown. If a run
ever creates, moves or replaces the user's live plist, the two differ. This is
the check that would have caught `REM-001` from inside the script rather than
from the user noticing their gateway had stopped.

---

## 6. `RA-004`: the two layers, measured separately

`scripts/service_cleanup_safety.sh`. A fake `$HOME` with a decoy production
plist, and a shimmed `launchctl` that **records intent and performs nothing** —
shimming matters, because `bootout` addresses the live `gui/<uid>` domain
regardless of `$HOME`, so a fake `HOME` alone would not protect a real gateway.

```text
== tracking_validate_macos.sh — P1/P4: a refusal is inert ==
    exit code:       1
    decoy before:    99faa047…  size=334 mtime=1785207716 mode=600
    decoy after:     99faa047…  size=334 mtime=1785207716 mode=600
    launchctl calls: list                       (read-only; no destructive verb)
  PASS  P1: the run REFUSED rather than proceeding beside an existing agent
  PASS  P4: the pre-existing production plist is byte-identical after the refusal
  PASS  P4: no destructive launchctl verb was attempted on the refusal path
  PASS  P1: the refusal created no isolated data directory (no trap was ever armed)

== tracking_validate_macos.sh — P5: an owned cleanup completes ==
  PASS  P5: the owned run completed (exit 0)
  PASS  P5: every directory the owned run created was removed

== tracking_validate_macos.sh — P2/P3: defeating the layers, one at a time ==
  PASS  P2: with the ORDERING layer defeated, the ledger alone still protected the plist
        (reported as measured: this mutation does NOT kill, because the two
         layers are independently sufficient. See P3.)
  PASS  P3: with BOTH layers defeated, the pre-existing plist was destroyed
            decoy after: absent

== gateway_validate_macos.sh — P1/P4: a refusal is inert ==
  PASS  P1: the run REFUSED (exit 2) beside a pre-existing production agent
  PASS  P4: the pre-existing production plist is byte-identical after the refusal
  PASS  P4: no destructive launchctl verb was attempted on the refusal path

=== SERVICE CLEANUP SAFETY: 11 passed, 0 failed ===
```

**The honest reading, unchanged from the previous remediation's negative
result:** defeating the trap ordering *alone* does not kill, because the
ledger independently prevents the damage. That is now a mechanical, repeatable
observation rather than a sentence in a report. `P3` is what makes the whole
harness non-vacuous: with both layers gone the decoy is destroyed, so the
harness demonstrably **can** see the danger it claims to be absent.

Two independently sufficient layers is a defensible design. It is *not*
defensible to present either single mutation as a kill, and this file does
not.

---

## 7. Count integrity

No total is typed anywhere. `group_size()` declares one number per group,
`expected_total()` sums them, and `enumerate_checks()` re-derives the same
totals by reading the script's own conditionals and aborts unless the two
agree — a self-test that runs in CI at `--scope selfcheck`.

```text
check inventory (summed from the group table, proved against this file):
  selfcheck:none    5 checks
  offline:none     20 checks
  full:foreground  57 checks
  full:service     63 checks
```

`full:service` moved from 59 to 63 in this work. It was **not** edited to
match a result: `group_size(SERVICE)` went 5 → 9 and the enumerator
independently re-derived 63 from the source, which is the self-test proving
that adding checks cannot leave a stale expected total. `RA-003` was the
opposite case — 60 typed against 59 real checks, making the mode unpassable
with every assertion green.

Additions in this work:

* every counted check records its group, verdict and **name** in a register;
* two checks may not share a name — a duplicate is a hard failure, because it
  makes "which check stopped running?" unanswerable;
* the run emits machine-readable `results.json`, and CI asserts against
  **that**, not against the exit status. `scripts/ci_assert_service_results.py`
  requires the exact scope and mode, per-group counts, `failed`/`skipped`/
  `duplicate_names` all zero, the `SERVICE` group present by name, every
  register row `pass`, and a namespaced service label.

That asserter is itself proven non-vacuous: pointed at a `--scope selfcheck`
result it refuses, naming scope, mode, the missing SERVICE group and the
absent service label. A job asserting `grep "0 failed"` would have accepted it.

---

## 8. What a green check here does NOT claim

* The desktop GUI is not click-driven. Nothing here exercises the React
  surface.
* Windows and Linux packaging are not covered. This is a macOS harness.
* The app is unsigned; no signing identity exists on a hosted runner, and the
  alpha ships unsigned (`docs/PACKAGING.md`).
* Provider acceptance is not proven. Routes point at real origins with fake
  keys, so a `401` proves DNS → gateway → TLS → provider and nothing about a
  real credential.
* One green run is one green run. The scope is now repeatable on every PR,
  which is the point; it is not yet a long baseline.

---

## 9. Reproducing this

```bash
gh run view     30326526816 --log          # the PR-head run
gh run download 30326526816 -n packaged-macos-service-lifecycle
gh run view     30325704492 --log          # the run §4 quotes in detail
gh run download 30325704492 -n packaged-macos-service-lifecycle
```

The artifact contains `service-lifecycle.log`, `gateway-lifecycle.log`,
`cleanup.log` and `results.json`, retained 30 days.

To reproduce on a clean macOS machine with **no** Tethra installed:

```bash
bash scripts/ci_service_preconditions.sh          # must pass, or stop
bash scripts/bundle_cli.sh
bash scripts/gateway_validate_macos.sh            # 56 checks
cd apps/desktop && npm ci && npm run tauri build -- --bundles app && cd -
cp -R target/release/bundle/macos/Tethra.app /tmp/packaged/
TETHRA_VALIDATION_RESULTS_JSON=/tmp/results.json \
  bash scripts/tracking_validate_macos.sh --scope full --require-service \
    /tmp/packaged/Tethra.app                      # 63 checks
bash scripts/ci_assert_service_results.sh /tmp/results.json
bash scripts/ci_service_cleanup_check.sh
```

**Do not run the last block on a machine with a live Tethra gateway.** It
refuses, by design — and `scripts/service_cleanup_safety.sh` is the executable
proof that the refusal is inert. Run that first if you want to satisfy
yourself before trusting the refusal.
