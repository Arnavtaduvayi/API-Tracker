# Implementation status — zero-friction API tracking

Branch `feat/zero-friction-api-tracking`, based on `main` @ `0e6764b`.
Every claim below is executed evidence; anything not executed is labeled.

## What works end to end

| Capability | Status | Evidence |
|---|---|---|
| Packaged app ships its helper | **done** | `Tethra.app/Contents/MacOS/{api-tracker-desktop,tethra}`; `PACKAGED_VALIDATION.md` |
| Setup with no external CLI | **done** | packaged run with `PATH` stripped, 42/42 checks |
| One-screen desktop flow | **done** | `TrackFlow.tsx`, 14 vitest cases |
| `tethra track .` fallback | **done** | clean-vault run below: 2 commands total |
| Automatic provider detection | **done** | `crates/tracking/src/detect.rs`, 12 + 10 tests |
| Bulk multi-provider setup | **done** | one plan, one apply; 30-provider-scale test |
| Automatic route management | **done** | create / reuse / re-enable, per-provider, no forms |
| Attribution inside tracking | **done** | one password field in Start-tracking; degrades, never blocks |
| First-request verification | **done** | negative control + positive flip, both executed |
| Ranked diagnosis | **done** | `diagnose.rs`, 7 tests, 10 stable ids |
| Undo | **done** | byte-for-byte restore, executed twice |
| Idempotent re-run | **done** | no duplicate rows, no second file write |
| Migration of manual setups | **done** | route reuse / link slug reuse; `MIGRATION.md` |
| Dashboard-first navigation | **done** | `DashboardView.tsx`, 10 vitest cases |
| Foreground fallback | **done** | offered on blocked install; exercised in validation |

## Test counts (executed on this machine)

```text
Rust workspace (5 crates)               1005 passed, 0 failed
  api-tracker-core                         533
  api-tracker-gateway                      269   (+6 new: helper discovery)
  api-tracker-cli                           86   (+9 new: track suite)
  api-tracker-observe                       63
  api-tracker-tracking (new crate)          54
Frontend vitest                           65 passed, 0 failed, 0 errors
  of which TrackFlow (new)                 14
  of which DashboardView (new)             10
scripts/smoke.sh                         138 passed, 0 failed
scripts/tracking_validate_macos.sh        42 passed, 0 failed (foreground mode)
```

Gates run clean: `cargo fmt --all --check`, `cargo clippy` (pinned
1.97.0) across all five library crates and the desktop backend with
`-D warnings`, `tsc --noEmit`, `eslint`, `prettier --check`,
`vite build`, and a full `tauri build --bundles app`.

## Manual pressure test

### Terminal fallback — executed, clean vault

```text
cmd 1  tethra init
cmd 2  tethra track .        (--yes; non-interactive)
       [user restarts the app and makes one request]
       tethra track status  -> tracking verified — traffic observed
```

Counted:

| Metric | Count |
|---|---|
| Setup commands beyond `track` | **0** |
| Manual route creation | **0** |
| Manual link/env editing | **0** |
| Separate attribution step | **0** |
| Shell-export choreography | **0** |
| Provider-by-provider forms | **0** |

`track` printed the detection, the exact diff, and one confirmation, then
did everything else. Undo restored `.env` to its original bytes.

### Desktop journey — counted from the implemented flow

```text
screen 1  Activity (empty)          click 1: Track API activity
screen 2  native folder picker      click 2: choose folder, click 3: Open
screen 3  review (detections, diff, disclosure, optional password)
                                    click 4: Start tracking
screen 4  applying → waiting        [user restarts app, makes one request]
screen 5  Tracking verified         click 5: Open dashboard
```

| Metric | Count |
|---|---|
| Screens | 5 |
| Clicks | 5 |
| Terminal commands | **0** |
| Password prompts | 1 (optional — skippable, tracking still works) |
| Manual provider selection for confirmed providers | **0** |
| Manual route creation | **0** |
| Separate attribution setup | **0** |
| Moments requiring internal gateway knowledge | **0** |

**Honesty note on this table:** the GUI click-through could not be
automated in this environment (no display access to drive or capture the
window). The packaged app was launched from the bundle with a clean data
directory and came up on its first-run screen; the counts above are read
from the implemented flow, and every underlying operation in it was
executed end to end through the same commands the UI calls — the 42-check
packaged validation and the clean-vault fallback run above. A human
click-through remains worth doing before release, and is scripted in the
manual UI test plan.

## Deliberately not done

* Provider-manifest expansion for Stripe/GitHub (O-22-1) — requires
  verifying each SDK's real env-var behavior against official docs.
* Source-import and nested-manifest detection (O-22-6).
* Docker/remote tracking — diagnosed, not supported.
* Linux and Windows packaged runs — not executed, not claimed.
* Code signing — external credentials required.
* `observed_api_services` seeding from detection (O-22-10) — deferred.

## Open decisions closed by this milestone

* **O10** (gateway) — the desktop now bundles its helper.
* **O-22-2** — version drift is repaired inside apply as a named,
  reported step rather than a silent action or an extra prompt.
* **O-22-3** — `--yes` includes attribution only when `TETHRA_PASSWORD`
  is set, otherwise skips it with a printed note; it never prompts and
  never fails over the absence.
* **O-22-5** — one tracking setup per (project, folder); selecting a
  monorepo sub-package works today.

---

# Post-audit remediation status (2026-07-27)

The independent audit of PR #16 (`24acc470`) returned
**REMEDIATION REQUIRED**: 64 findings, 15 merge-blocking. This section
records what is true after the remediation. Per-finding detail is in
`audit/REMEDIATION_MATRIX.md`; what was actually executed is in
`audit/REMEDIATION_EVIDENCE.md`.

## Works end to end

* The supported desktop journey is unchanged in shape and still works:
  open, add a credential, **Track API activity**, pick a folder, review one
  screen, **Start tracking**, restart, make a request, see activity. Zero
  terminal commands.
* Provider coverage is 21 manifests, 13 trackable — 11 configured
  automatically and 2 needing one destination confirmation.
* Scanning a folder executes nothing the folder controls.
* A destination read from project content is never configured without an
  explicit per-destination decision that defaults to off.
* "Tracking verified" describes the present; history is shown separately.
* Two Tethra installations coexist without either being able to stop,
  replace or reconfigure the other.
* Unknown credentials are listed and counted, never dropped.

## Partially implemented, and said so

* **Three ZFT-009 in-app actions were not built** rather than added as dead
  buttons: a durable *mark as ignored* (needs a store in a crate the desktop
  does not own), *request provider support* (clipboard-only; an outbound
  call would breach local-first), and an *add this API* form for an
  unrecognised credential (could create a route but never wire the app to
  it). `KNOWN_LIMITATIONS.md` names all three.
* **ZFT-029** gained a per-project dimension; the per-provider dimension the
  finding's title also names was not built, and the per-project query lives
  in the desktop crate rather than `gateway::store`.
* **The `--scope full` packaged validation (57 / 60 checks) has never been
  executed on any machine.** Its `$LABEL`-unbound crash and legacy-path
  defects are fixed, but the fixes are reviewed rather than run: this
  machine has a Tethra gateway and the interlock correctly refuses. CI runs
  `--scope offline` (20 checks) against a real `.app`.
* **The new Tauri command layer has no automated test.** The structural
  guarantee it carries — the IPC boundary cannot choose a destination — is
  verified by reading.

## Not started, and not claimed

* Windows and Linux packaged install-and-track lifecycles.
* Code signing and notarization.
* Per-provider activity attribution.

## Numbers at the final commit

```text
Rust workspace           1133 passed, 0 failed
Desktop vitest             91 passed, 0 failed
Smoke suite               140 passed, 0 failed
Packaged validation        20 passed, 0 failed  (--scope offline)
Harness self-check          5 passed, 0 failed
Product mutants            21 killed, 0 survived
Harness mutants             8 killed, 0 survived
Provider manifests         21 total, 13 trackable, 8 unsupported
```

## What has not been decided

Merge readiness. PR #16 is open and unmerged. That decision belongs to a
fresh independent audit briefed by `audit/RE_AUDIT_HANDOFF.md`, which lists
by name everything the remediation's own adversarial reviewers found and
did not close.
