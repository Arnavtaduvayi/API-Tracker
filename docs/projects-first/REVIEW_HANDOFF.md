# Review handoff

Branch: `feat/projects-first-live-activity`
Base: `main` @ `b6f6692` (PR #16 merge commit, verified from git)

## What changed

| Area | Files |
|---|---|
| Schema v20 | `crates/core/src/db.rs` |
| Linkage + detections | `crates/core/src/projectlink.rs` (new) |
| Bounded project reads | `crates/core/src/projectactivity.rs` (new) |
| Cost with coverage | `crates/core/src/projectcost.rs` (new) |
| Pricing metadata + batch lookup | `crates/core/src/pricing.rs` |
| Projects-first facade | `crates/tracking/src/project.rs` (new) |
| 11 commands | `apps/desktop/src-tauri/src/main.rs` |
| Project page | `ProjectTracking.tsx`, `ProjectActivity.tsx`, `ActivityChart.tsx` (new) |
| Shared refresh | `apps/desktop/src/useLiveRefresh.ts` (new) |
| Availability helpers | `apps/desktop/src/usage.ts` |
| Navigation | `apps/desktop/src/App.tsx` |

## Local validation — measured, on this branch's head

```text
cargo fmt --all --check                                    PASS (exit 0)
cargo +1.97.0 clippy --workspace --all-targets -D warnings PASS (exit 0)
cargo test --workspace --all-targets                       PASS 1449 passed / 0 failed
                                                                (97 test binaries)
cargo build --workspace --release                           PASS (exit 0)
bash scripts/smoke.sh                                       PASS 140 passed / 0 failed

npm ci                    (locked install)                  PASS
npm run format:check                                        PASS
npm run lint                                                PASS
npm run typecheck                                           PASS
npm test                                                    PASS 235 passed / 21 files
npm run build             (tsc --noEmit && vite build)      PASS
cargo build -p api-tracker-desktop  (Tauri backend)         PASS
```

Two prerequisites, both documented rather than worked around:

* `cargo build --release -p api-tracker-cli && bash scripts/bundle_cli.sh` must
  run first, or `tauri-build` refuses before anything compiles (CONTRIBUTING,
  `NEW-22`/`ZFT-045`).
* `target/` held artifacts from a previous checkout path
  (`~/Documents/GitHub/API-Tracker`), which made `tauri-build` read plugin
  permissions from a directory that no longer exists. Cleared with
  `cargo clean -p tauri -p api-tracker-desktop …` for both profiles. A local
  cache artifact, not a source problem.

## Not executed here, and why

**The packaged pressure test.** It installs a login-scoped helper, and a live
production gateway (`dev.api-tracker.gateway`) occupies that slot on this machine.
`NEXT_FRESH_AUDIT_HANDOFF.md` forbids running either validation harness in
service mode on a developer machine. No shell-harness check was added or changed,
so the validation manifest, its mutation suites and the three exact-assertion-count
gates are untouched — deliberately, since adding a check requires regenerating
the manifest and satisfying four separate shape constraints.

**Live provider traffic end to end.** Same reason. Every activity path is covered
by tests that seed observations directly.

## Please look hardest at

1. **The consent gate.** `crates/tracking/src/project.rs` `link_digest` and
   `confirm_link`. The digest binds the decisions, not the envlink plan digest,
   because the latter embeds a per-link CSPRNG slug and would reject every
   confirmation. Question worth asking: is there an apply-relevant decision the
   digest does not cover? It currently covers port, service actions, route
   prefixes + provider ids + creates-flag, and per-file (path, exists, changed).
2. **`derive_detections`.** `credential_candidates` means "credentials the project
   already holds", which I initially read as "variables found in the project". A
   test caught it. Worth confirming the corrected reading against `detect.rs`.
3. **Cost coverage arithmetic** in `projectcost.rs`: which bucket a group lands in
   when tokens are known but the model is not, versus usage never reported. The
   two are different and are counted differently.
4. **The refresh loop's stale-response guard.** `useLiveRefresh.ts` uses a
   monotonic `applied` sequence. The test drives out-of-order settlement, but it
   cannot easily force a genuinely superseded response to land, because the
   overlap guard prevents two concurrent fetches. That is a real gap in the test,
   not in the code — the guard is what makes the race hard to stage.
5. **Whether `overview` is on any hot path.** It resolves health, which
   compare-and-swaps. It is called on page open, after a change, and from
   `ProjectDetail`'s effect. If a future caller puts it on a timer, that is a
   write storm.

## Security reconciliation

| Invariant | Status |
|---|---|
| Sealed, non-executing project scanning | unchanged; fingerprint walk is stat-only and refuses symlinks |
| Loopback-only gateway | unchanged |
| Registered upstream origins | unchanged |
| Explicit custom-origin approval | unchanged; a repo-discovered destination yields no plan and no approval |
| No open relay | unchanged |
| No payload persistence | unchanged; no new column can hold one |
| No authorization/header/query persistence | unchanged |
| Encrypted rollback data | unchanged |
| Current-health verification | unchanged; one resolver, never read from the cached column |
| Service namespace and ownership | unchanged; no lifecycle code touched |
| Exact validation check identity | unchanged; no harness check added |
| Safe install ordering | unchanged; apply step order untouched |
| Connection resource bounds | unchanged; new reads are bounded and capped |
| No production gateway interaction from tests | preserved; mocked ops throughout |
| No whole-computer scanning | unchanged; root/home/`/Users` still refused |
| No arbitrary project code execution | unchanged |
| SI-19 local vs provider-reported never summed | preserved and newly pinned by a test |

New secret-handling surface: `detected_credentials`, which has no column capable
of holding a value, swept by a canary test over every column of every row.

## Follow-ups (not blocking)

* Scope destination approvals per project — changes the MAC message, ADR-level.
* Surface provider-reported cost beside the local estimate on the project page,
  clearly separated.
* Populate `ttfb_ms` for the intercept path.
* Support several folders per project for monorepos.
* A reviewed, explicit secure-import path for a detected credential's value, if
  one can be built without this layer reading a value.
* Consider whether the first backoff step should exceed the normal interval; it
  currently equals it, so one transient failure does not slow anything down.
