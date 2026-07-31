# Validation Integrity — Independent Audit of PR #16

Question: is this PR's evidence real, or can the validation pass vacuously?

**Answer, in two parts.** The validation *script* is substantially real — I could
not construct a scenario where the feature is broken yet it reports success. But
the *standing* of that evidence is much weaker than the PR presents: CI runs
neither the packaged validation nor the smoke suite, the one recorded run used
the self-weakened foreground mode, and 4 of the 42 counted checks cannot fail.

---

## 1. What CI actually runs

```
$ grep -rn "tracking_validate\|smoke.sh\|bundle_cli" .github/workflows/
ci.yml:118       run: bash scripts/bundle_cli.sh
release.yml:109  run: bash scripts/bundle_cli.sh
```

`scripts/tracking_validate_macos.sh` and `scripts/smoke.sh` appear **nowhere** in
any workflow. The only script CI executes is `bundle_cli.sh`.

CI jobs in full: `rust` (fmt, clippy, tests for five crates, ubuntu),
`rust-windows` (tests for three crates + `cargo build -p api-tracker-cli`),
`frontend` (format, lint, typecheck, test, build), `desktop`
(**clippy only** — no `cargo test -p api-tracker-desktop`, no `tauri build`).

**CI never builds a packaged app on any platform.**

**`ZFT-VAL-1` (HIGH):** the headline "42 checks" is a single developer-machine
run, not repeatable PR evidence. What CI *does* enforce from this PR is the 9
`track.rs` tests (dry-run / no-detection / undo-noop paths only) plus the tracking
crate's 54 tests — which are genuinely strong — on both ubuntu and Windows.

**Current CI status, checked directly:** all four checks **pass** on the audited
head `24acc470` (run 30292334837). That is real and current.

**But `ZFT-VAL-2` (LOW):** `HANDOFF_PHASE_2.md:71` claims *"Eight commits, each
independently green."* The list beneath it has **seven** items, and the branch's
real run history shows the first five pushed heads (`6decca5`, `ef3d26b`,
`93ccd59`, `802e569`, `9cb0233`) all **failed** CI on the Windows job. "Green" can
only mean local macOS gates — the exact blind spot the branch's own Windows
home-scan defect proves is insufficient. The commit that "corrected the commit
count" changed "Five" to "Eight" over a 7-item list.

---

## 2. Assertion classification — `scripts/tracking_validate_macos.sh`

Mechanics are honest scaffolding: `set -uo pipefail` (deliberately no `set -e` —
failures are counted, not aborted); `assert_db` **fails closed** on empty result,
missing DB or SQL error; there is **no** `|| true`, no `set +e`, no trailing
`exit 0`; the exit status is `[ "$fail" -eq 0 ]` and the EXIT trap preserves it.

Of the 42 counted checks in the documented (foreground) run: **~31 REAL, 7 WEAK,
4 VACUOUS.**

### The four that cannot fail

| Line | Quoted | Why vacuous |
|---|---|---|
| 100 | `ok "pre-existing user state is left untouched (foreground mode)"` | A pass awarded for *entering the weaker mode*. Asserts nothing. |
| 133 | `ok "fixture project written with a fake key and a canary value"` | Unconditional; no write verification. Also advertises a canary that is never checked (below). |
| 164 | `ok "the dry run installed no service (foreground mode)"` | Unconditional. Nothing is checked — not even that the pre-existing plist is unmodified. |
| 207 | `ok "applied_at recorded ($APPLIED)"` | Unconditional — passes on empty. The comment above it (line 205) promises *"Forge an OLD event (before applied_at): must not verify the setup"* — **there is no forging code.** |

### The seven weak ones

* **118** — `[ -n "$APP_VER" ]` only. The header claims a *"version-matched
  helper"*; nothing ever compares `APP_VER` to anything. (`ZFT-VAL-3`)
* **177** — `grep -qi "route"` passes on any occurrence, including inside an error.
* **239-246** — WAL and SHM canary checks are **silently skipped** (`continue`,
  not even a SKIP line) when absent. The claimed total of 42 depends on both
  existing.
* **247-250** — `grep -rq "$FAKE_KEY" "$DIR/logs" || ok` passes **identically**
  when `$DIR/logs` does not exist. Broken logging ⇒ vacuous pass. Also misses
  `$DIR/serve.log`, the foreground gateway's captured output.
* **252-255** — case-sensitive literal `"Authorization"`; lowercase header storage
  would false-pass.
* **261-263** — idempotence: the second run's **exit code is never checked**. A
  re-run that crashes instantly also "changes nothing" and passes all three
  idempotence checks.
* **216-220** — a 403 counts as "path proven end to end", but the gateway
  synthesizes its own 403 for browser-looking requests. Individually
  overclaiming; backstopped in ensemble because local refusals write no
  observation row.

### The parts that are genuinely strong

* **A true negative control (lines 196-203).** After `track --yes` and before any
  request it asserts `state != 'traffic_observed'`, `first_traffic_at IS NULL`,
  and `track status` exit 2 — then the positive flip only after the observed
  curl. This is a real control, not a skip.
* **PATH is genuinely stripped** (`export PATH="/usr/bin:/bin:/usr/sbin:/sbin"`)
  with a fatal `exit 1` if any `tethra` resolves, and every invocation uses the
  explicit in-bundle path. **No fallback to `target/release/tethra` or a PATH
  `tethra` exists anywhere in the script.**
* **Clean environment**: `TETHRA_DIR=/tmp/tethra-track-val-$$`, fresh per PID,
  `rm -rf` in the trap; a stale directory makes `init` fail loudly, so leftovers
  cannot satisfy assertions.
* Exact exit-code assertions (2 then 0), on-disk `.env` content, exact-count DB
  rows, byte-compare undo, and a lossless-rewrite proof
  (`grep -q "^# A comment that must survive verbatim"`).

**I could not construct a scenario where the feature is broken and the script
still passes.** A stub binary or a dead gateway fails at multiple independent
points.

---

## 3. The anti-vacuity floor is coarse

```sh
MIN_CHECKS=30; total=$((pass+fail))
if [ "$total" -lt "$MIN_CHECKS" ]; then echo "...VACUOUS..."; exit 1; fi
```

It counts `pass+fail`, so it detects only *"checks did not run"* (gross
truncation), never *"checks cannot fail"*. The 4 unconditional passes and 7 weak
checks all sail under it. The real defense is the ensemble of fail-closed
assertions, not the floor.

---

## 4. The two modes — the number self-launders

The script installs a real LaunchAgent in service mode; **when one already
exists, it switches to foreground mode** rather than clobbering it.

This is a workaround for `ZFT-014` (fixed LaunchAgent label), not a test mode.
Its practical consequence: **on any machine where Tethra has ever been installed
— including the author's — every run is foreground mode.** I confirmed this
machine has `dev.api-tracker.gateway` installed and loaded.

In foreground mode:
* LaunchAgent registration is **entirely unexercised**;
* one service assertion becomes an uncounted SKIP;
* another becomes an unconditional pass (line 164);
* **the total stays 42.**

So "42/42 passed" is numerically indistinguishable between the strong and weak
modes. The prose discloses the degradation
(`PACKAGED_VALIDATION.md:64-84` states LaunchAgent registration was not exercised
in that run); the number does not, and `IMPLEMENTATION_STATUS.md`'s capability row
reads *"Setup with no external CLI — done — 42/42 checks"* with no qualifier.

**`ZFT-VAL-4` (MEDIUM-HIGH):** the packaged **service** path — the one that runs
on a real user's machine at login — has been validated by neither CI nor the
recorded run. **Remediation:** report per-mode totals (e.g. "39/39 + 3 SKIPPED"),
and add a macOS CI job that builds the bundle and runs the script (forced
foreground mode is CI-compatible).

---

## 5. The privacy canary that is never checked

`CANARY="TETHRA-CANARY-$$-MUST-NEVER-PERSIST"` (line 44) is written into the
fixture `.env` (line 126), advertised in the pass message at line 133 — and
**never searched for** in the DB, WAL, SHM or logs. Only `FAKE_KEY` is grepped.
The "unrelated env value never persists" property is untested. (`ZFT-VAL-5`)

`FAKE_KEY` itself *is* a good canary: distinctive, genuinely present in the
`.env` that `track` parses, and sent in the curl Authorization header through the
gateway — so its greps are falsifiable.

---

## 6. `scripts/smoke.sh` — offline tracking section

13 checks, all REAL. Runs the **development** binary in a fresh `mktemp` vault,
which is appropriate for smoke and makes no packaged claim. Assertions are
specific strings (*"Dry run: nothing was changed."*, *"not configured"*,
*"nothing to undo"*, *"No trackable APIs detected"*), byte-compares on disk, exact
exit code 2 twice, no-key-leak and no-print-export negatives, and a genuine
no-project-created check. No vacuous patterns found. I re-ran the whole suite:
**138 passed, 0 failed**, matching the claim.

---

## 7. `apps/cli/tests/track.rs` — 9 tests, run by CI

Isolation is genuine (`env_clear()` + fake `HOME` + temp `TETHRA_DIR`), so
lifecycle code cannot see the real LaunchAgents directory.

| Test | Class |
|---|---|
| `dry_run_shows_the_plan_and_writes_nothing` | REAL |
| `no_detection_exits_2_with_honest_guidance` | REAL |
| `track_never_prints_shell_export_choreography` | REAL (bounded to 3 needles) |
| `no_secret_value_appears_in_track_output` | REAL — the key is in the fixture, so falsifiable |
| `status_and_undo_are_honest_when_nothing_is_configured` | REAL |
| `ambiguous_folder_registration_is_an_explicit_error` | REAL |
| `explicit_project_selects_the_named_one` | WEAK — only one project exists |
| `track_json_status_shape_is_stable` | **MISNAMED** — asserts only exit code 2; **no JSON is asserted anywhere** |
| `track_help_documents_the_one_command_flow` | WEAK (help-text presence) |

The file's header honestly scopes itself to dry-run / no-detection / undo-noop
paths; the apply engine's CI coverage genuinely lives in
`crates/tracking/tests/plan_apply.rs` and `state.rs`.

---

## 8. Claimed counts vs measured

Every number I could independently re-derive **matched**:

| Claim | Measured |
|---|---|
| tracking crate 53 → 54 tests | **54** (bounds 10, detect 12, diagnose 7, plan_apply 16, state 9) |
| Rust workspace 1004 | **1005** (PR body predates the final test; docs were updated, the PR body was not) |
| core 533 / gateway 269 / cli 86 / observe 63 | **exact match** |
| 24 new vitest cases; 65 total | **exact match** (TrackFlow 14, DashboardView 10) |
| smoke 138 checks | **exact match** |
| 6-test helper-discovery suite | **exact match** |
| 9 CLI track tests; 10 diagnosis ids; 17 UI cases | **exact match** |
| 20/20 deterministic 304 runs | **re-ran 20×: 20/20, ~0.03 s each** |
| app-bundle byte sizes 16580864 / 11935184 | **exact match, to the byte** |
| "mutation-verified" home-refusal fix | **verified** — the test exists, its panic string matches the quoted failure, and the CI history corroborates the Windows-caught story |

The negative-space claims are also consistently honest: *"not executed"*,
*"not claimed"*, *"GUI not click-driven"*, *"no approval claimed"*, and a
CI-corroborated confession of a real security defect they found and fixed.

**Where self-reporting fails is narrative, not arithmetic:**

* **`ZFT-VAL-6` (MEDIUM)** — the *"30-provider-scale test"*
  (`plan_apply.rs:657`) writes 26 `SERVICE_i_URL` variables that match no
  manifest and produce **zero** detections (its own comment concedes this). It is
  a 4-provider test with a 30-variable `.env`. Nothing exercises 30 providers.
* `PACKAGED_VALIDATION.md:41-52` group table sums to **40**, not the stated 42.
* *"byte for byte"* undo in the packaged script uses `[ "$(cat a)" = "$b" ]`,
  which strips trailing newlines — blind to trailing-newline drift. (The exact
  property is separately pinned in-crate, so the product is fine; the label
  overstates the *script*.)
* *"CI clippy pins `+1.97.0`"* (`HANDOFF_PHASE_2.md:118`) — `ci.yml` uses
  `toolchain: stable`; only the *action* is SHA-pinned.
* *"Final head `4e3cc98`"* — the actual head is `24acc470`, the commit that added
  that correction. CI did pass on `24acc470`, so the substance survives.
* *"closes O10"* — the mechanism genuinely ships, but
  `docs/gateway/OPEN_DECISIONS.md:87` still presents O10 as open with the
  superseded default, while three other gateway docs got dated corrections.
* `DETECTION_COVERAGE.md:71` *"every one of these is a test, not a promise"* —
  the symlink bound's test is `#[cfg(unix)]`, so it is not pinned on Windows,
  the exact platform where this branch just proved platform-conditional bounds
  fail silently.
* `TROUBLESHOOTING.md` implies the built-in diagnosis automates all eight listed
  causes; it automates six ("wrong folder" and "proxy bypass" have no check).

---

## 9. Bottom line

Treat `tracking_validate_macos.sh` as a **credible local harness** whose core
positive/negative traffic-verification story would genuinely catch a broken
feature. Do **not** accept "42/42 packaged checks" as standing evidence: it is
unrepeated, un-CI'd, mode-degraded, padded by four free passes, and two of its
advertised extras (the forged-event control and the canary) are not implemented.

The single most valuable missing confirmation is a run in **service** mode on a
machine with no pre-existing LaunchAgent — the one configuration the recorded
evidence never touched, and the one every real user will be in. That run is
currently impossible to perform safely on a developer machine because of
`ZFT-014`.
