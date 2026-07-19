# Phase 2 Fix Verification Matrix

Per-finding disposition for every claimed Phase 2 fix, verified by attacking the code at `260e47e`, not by trusting the Phase 2 report. Baseline is `033f747` (merged PR #9).

**Legend:** FIXED · PARTIALLY FIXED · NOT FIXED · REGRESSION · INCONCLUSIVE. "Blocks PR #10" is the only merge-gate column.

| Finding(s) | Verdict | Blocks PR #10 |
|---|---|---|
| PI-02 / CONC-11 / CLI-03 / RA-1 — process identity before termination | **FIXED** | No |
| Migration v11 — `proc_identity` column | **FIXED** (see MIGRATION_V11_REVIEW.md) | No |
| GScan-01 / GScan-02 — git hook truthfulness & scan-first chaining | **FIXED** | No |
| CONC-06 / GScan-03 / CONC-05 — bounded git execution & streaming history | **FIXED** | No |
| DEST-01 / DEST-02 / DEST-03 / DEST-04 — destination drift/targeting truth | **FIXED** | No |
| OBS-004 — malformed expiration isolation | **FIXED** | No |
| M-6 — CI action SHA pinning & least-privilege | **FIXED** | No |
| Tauri direct-command authorization harness (+ `provider_admin_disconnect` core reauth) | **FIXED** (adequate; 5 documented gaps) | No |
| React security-workflow tests (+ IPC-05 `safeExternalUrl`) | **FIXED** (IPC-05 solid; test-count inflated, 3 coverage holes — RA2-5) | No |
| RA-4 — Windows env-var casing scrub | **FIXED** | No |
| IPC-05 — `docs_url` scheme validation | **FIXED** | No |

---

## PI-02 / CONC-11 / CLI-03 / RA-1 — verify process identity before termination — FIXED

- **Vulnerable behavior (baseline):** `terminate_process_session` signalled a recorded PID after only a `pid <= 0` guard; a dead launcher leaves the row open, the OS recycles the PID, and the next `access kill` / `access end --kill` signals an unrelated process. `access end --kill` additionally spawned `kill <pid>` inline, bypassing every guard (RA-1).
- **Changed files/symbols:** `inject.rs` (`probe_process_identity`, `IdentityProbe`, `TerminationOutcome`, `terminate_verified`, `set_session_pid` identity capture, `ProcessSession.proc_identity`); `vault.rs::terminate_process_session` (single routing + audit + row-close); `db.rs` migration v11; `access_cmd.rs` (`kill` + `end --kill` route through the vault); `main.rs::access_session_kill`; `types.ts`/`AccessView.tsx`.
- **Intended invariant:** a recorded PID is signalled ONLY when the launch identity (start-time + executable, platform-prefixed) still matches immediately before signalling; a stale/recycled/tampered/identity-less record is refused; an exited process is reported truthfully; every request is audited.
- **Baseline failure evidence:** `evidence/pi02_baseline_fail.log.txt` — the stale-PID test killed the decoy at `033f747`.
- **Tests at 260e47e:** `pi02_process_identity` 10/10; `access_end_kill_guard` 1/1; `observability` termination test **strengthened** to assert `TerminationOutcome::Signalled`.
- **Independent proof:** I inventoried every termination entry point. `terminate_pid` (legacy, no identity check) has **zero production callers**. `terminate_verified` has exactly one production caller — `vault.terminate_process_session` — through which all three recorded-session paths route (`access kill`, `access end --kill`, desktop `access_session_kill`). The duration-limit auto-kill (`run_cmd.rs:122`) uses `Child::kill()`+`Child::wait()` on the live handle (a *stronger* primitive; no recycled-PID risk). `sweep_dead_sessions` only closes rows, never signals. The migration harness proved a NULL-identity (pre-v11) row is refused.
- **Edge cases:** `pid<=0`, reused PID (real recycle simulated by capturing a dead process's identity then waiting for the wall-clock second to advance), fabricated identity, tampered record naming PID 1, cross-platform (`win:`) identity on Unix, already-exited (row closed), matching live process (signalled + audited), descendants (survive — PI-03 documented), concurrent exit during verify (kill fails → re-probe → AlreadyExited).
- **Compatibility:** additive migration; pre-v11 rows refused (safe). FE `TerminationOutcome` tagged-enum matches the Rust serde tags.
- **New failure modes:** none. Fails **closed** (uncertainty → refuse). Residual **check-to-signal TOCTOU** is honestly documented and **not** claimed eliminated (would require pidfd/Job objects); the window is milliseconds and requires same-PID recycling in that window.

## GScan-01 / GScan-02 — git hook truthfulness & scan-first chaining — FIXED

- **Vulnerable behavior:** install/status hard-coded `.git/hooks/pre-commit`, ignoring `core.hooksPath`, so with husky/global hooks git ran a different file while status said `Installed` (GScan-01); force-chain appended the API Tracker block *after* a foreign hook, so an early `exit`/`exec` skipped the scan while status said "chained" (GScan-02).
- **Changed files/symbols:** `hooks.rs` (rewrite: `effective_hook_path`, `HookState{Overridden,Unsupported,...}`, `status` with `active`+`detail`, `chain_ours_first`, `strip_our_block`, `is_managed_only`, relocation/removal), `gitrepo.rs::config_get`, `scan_cmd.rs` (surface `active`/`detail`), `types.ts`/`ScanView.tsx`.
- **Intended invariant:** status never claims protection git will not run; when chaining, the scan runs BEFORE any pre-existing hook; foreign semantics preserved; unsupported configs refused/described honestly; hook content injection-safe.
- **Baseline evidence:** `evidence/gscan_baseline_fail.log.txt` — 9/10 property tests fail at `033f747`.
- **Tests at 260e47e:** `gscan_hooks` 12/12 (each a REAL `git commit` with a stub `api-tracker` recording whether the scan ran).
- **Independent proof:** `config_get` uses `git config --get core.hooksPath` — the **merged/effective** value across scopes, failing loud on non-"unset" errors (not silently defaulting). `chain_ours_first` keeps the foreign shebang on line 1 and inserts our POSIX block ahead of foreign content; the test asserts `find(SENTINEL) < find("echo existing-hook")`. `active` is true only when our block sits in the file git uses AND it is executable. Injection safety: the repo path enters the hook only as a runtime `"$(git rev-parse --show-toplevel)"` command substitution — never interpolated at install time — so spaces/quotes/`$()` in the path or hooksPath cannot inject.
- **Edge cases:** local & global hooksPath, relative (resolved against worktree top per githooks(5)) & absolute, spaces, husky layout, `exit`/`exec` foreign hooks, binary/unreadable hook (refused as `Unsupported`, not corrupted), non-executable hook (reported inactive), repeat install (idempotent + canonicalizes old append-style to scan-first), uninstall restores foreign, repo moved (runtime toplevel resolution), hooksPath set after install (reports `Overridden`).
- **Compatibility:** FE `HookState` gains `overridden`/`unsupported`; `HookStatus` gains `hooks_path_override`/`active`/`detail` — all matched in `types.ts`.
- **New failure modes:** none. Symlinked hook paths follow the link on read/write (user's own repo; local-first threat model). Windows hook inertness (`is_executable` returns `true`) is a documented limitation.

## CONC-06 / GScan-03 / CONC-05 — bounded git execution & streaming history — FIXED

- **Vulnerable behavior:** every git subprocess used blocking `Command::output()` with no timeout (a hung git wedged the monitor and the desktop, which held the vault mutex across the scan — CONC-06); `git log -p` was buffered whole then copied into a `String`, so a large/crafted history could exhaust memory (GScan-03/CONC-05).
- **Changed files/symbols:** `gitrepo.rs` (`GitLimits`, `ChildGuard`, `run_git_bounded`, `pump_stdout`/`pump_stderr`, `stream_log_units`, `LogStreamParser`, `range_added_units*`/`history_added_units*`, `collect_full_repo_scan`, `run_git_probe`); `vault.rs` (`scan_history`→`ScanOutcome`, `scan_units` public, `reverify_repo_exposure_collected`, coverage-gap alert); `envgov.rs` (probes via `run_git_probe`); `scan_cmd.rs` (coverage warnings); `main.rs` (collect-outside-lock, `ScanPathReport`); `types.ts`/`ScanView.tsx`.
- **Intended invariant:** every git subprocess has a timeout and is killed+reaped on violation; history streams under per-line/per-unit/total-retained/duration caps; any limit → INCOMPLETE COVERAGE, never a clean scan; redaction preserved; vault mutex not held over the long collection.
- **Baseline evidence:** `evidence/conc06_baseline_fail.log.txt` — `scan_history` still blocked on a hung git after 5 s.
- **Tests at 260e47e:** `gitbound_scanning` 10/10 (hang/flood/slow-secret/bigline `sh` stubs + real repos; `assert_stub_reaped` proves the child PID is gone via `probe_process_identity`; memory asserted via `retained <= max_output_bytes`).
- **Independent proof:** I inventoried every git spawn. All repository/network-touching calls route through `run_git_bounded`/`stream_log_units` (including envgov via `run_git_probe`); the only unbounded call is `git_available`'s `git --version`, which performs no repo/network I/O and cannot hang on a dead mount (recorded as RA2-3, Info). Memory is bounded by the `sync_channel(16)`×64 KB backpressure + `max_line_bytes` + 5 MB/unit + 64 MB total-retained + a 200 K-line reconstruction cap. `complete = complete && warnings.is_empty()` forces incomplete on any truncation. `reverify_repo_exposure_collected` resolves exposure/coverage-gap alerts only when `count == 0 && coverage_complete`; the incremental monitor raises a persistent `RepoScanCoverageGap` on partial/failed ranges (excluded from auto-resolve, clears only on a complete clean re-verify). Desktop `scan_path`/`scan_reverify` collect OUTSIDE `with_vault`, running only `scan_units`/reverify under the lock.
- **Edge cases:** no-output hang (timeout), slow/endless output (wall-clock bound), oversized line (truncate + skip-to-newline, later findings survive), oversized unit (truncate + warning), byte cap, retained cap, timeout-with-partial-findings (returned + incomplete), real large blob, 60-commit repo (complete, 60 units), incomplete incremental → persistent alert, incomplete reverify → never clean.
- **Compatibility / mutex:** the desktop no longer holds the vault mutex across git; the collect-then-match split introduces no lost-update (the scan only reads the repo and writes findings/alerts under the lock atomically); a slightly-stale repo snapshot is inherent to any point-in-time scan and re-checked on the next run.
- **New failure modes:** none. Reader/stderr threads are detached but terminate on child exit / receiver drop; `ChildGuard` double-`wait` is harmless.

## DEST-01 / DEST-02 / DEST-03 / DEST-04 — destination truthfulness — FIXED

- **Vulnerable behavior:** GitHub/AWS `exists()` collapsed 401/403/429/500/timeout into `Some(false)`="missing" → false drift → destructive re-writes (DEST-01); Vercel matched env vars by key only, ignoring targets → `exists`/`delete` could confirm/destroy the wrong same-key variable (DEST-02); `destination_drift_check` silently skipped un-buildable adapters and re-presented stale drift as fresh (DEST-03); `execute_step` stamped a step verified even on `missing`/`unknown` (DEST-04).
- **Changed files/symbols:** `destinations.rs` (GitHub/AWS `exists`+`delete`, `VercelDestination::resolve_env_identity`+`exists`+`delete`, `record_verify`, `DriftCheckOutcome`); `vault.rs` (`execute_step` verify honesty, `destination_drift_check`); `destination_cmd.rs`; `main.rs`; `types.ts`/`DestinationsView.tsx`.
- **Intended invariant:** auth/transport/server errors are `unknown`, never `missing`; identity = key + exact targets + custom-env context; delete fails safe on ambiguity or other-target-only match; an unqueryable destination is explicit not-checked; `last_verified_at` never advances on `unknown`; existence-only stays distinct from value read-back.
- **Baseline evidence:** `evidence/dest_baseline_fail.log.txt` — 12 tests fail (missing-on-error, key-only match, verified-on-failure).
- **Tests at 260e47e:** `destinations::tests` 11 new (in the 505/0 run); `dest_truthfulness` 5/5.
- **Independent proof:** GitHub/AWS `exists` map only 2xx→present and 404/RNFE→absent; 401/403→`ProviderAuth`, everything else (incl. malformed 400 JSON, 429, 500, transport)→typed `Provider` error "existence is undetermined". Vercel `resolve_env_identity` sorts and compares the exact target set, excludes custom-environment scope, returns unique-id / other-targets / absent / ambiguity-error; `delete` refuses an other-targets-only match and treats list→delete 404 as already-gone. `record_verify` updates only `drift` (not `last_verified_at`) when `drift=="unknown"`. `execute_step` stamps verified only for `in_sync`/`present_unverifiable`. `destination_drift_check` records un-buildable adapters in a `skipped` map and emits `DriftCheckOutcome{checked:false,check_error}`. The `dest_truthfulness` tests use an **empty** `MockHttpClient` where relevant so a bypass would error differently, and prove a second failed check keeps the prior `last_verified_at` unchanged.
- **Edge cases:** 404/401/403/429/500/timeout/malformed-JSON; same key across production/preview/development; custom-environment identity; ambiguous (duplicate) identity; stale-id list→delete race; other-target refusal; drift after prior success/failure; sync step never verified on existence-check failure; no secret/token in any error.
- **New failure modes:** target-ordering is handled by sorting both sides (order-independent by construction). **Vercel pagination is not followed** (RA2-1, Low, pre-existing, fails safe).

## OBS-004 — malformed expiration isolation — FIXED

- **Vulnerable behavior:** `credential_model` parsed `provider_expires_at` (stored verbatim from sync) with `?`-propagating parse and `list_credentials` collected into a `Result`, so one unparseable value failed EVERY listing/detail/alert/monitor vault-wide.
- **Changed files/symbols:** `vault.rs` (`parse_optional_ts_lenient`, `credential_model`); `status.rs` (`expiration_unparseable` input + explicit `Unknown` finding); `model.rs` (`expires_at_invalid`/`provider_expires_at_invalid`); `monitor.rs` (fixture); `render.rs`; `types.ts`/`CredentialDetail.tsx`.
- **Intended invariant:** expiration parsed per credential; one bad value cannot break unrelated listings; raw value preserved; no fabricated date; status/alerts fail locally; no secret leak.
- **Baseline evidence:** `evidence/obs004_baseline_fail.log.txt` — one malformed value fails the listing with `InvalidInput`.
- **Tests at 260e47e:** `obs004_expiration_isolation` 5/5.
- **Independent proof:** `parse_optional_ts_lenient` returns `(None,true)` on a bad value (no `?`, no fabrication); `credential_model` uses it for `expires_at`/`provider_expires_at` while keeping `created_at` strict; the invalid flags are **derived at model construction, not stored** (no migration/backup impact). `Credential` is `Serialize`-only → no deserialization back-compat risk; the two new `boolean` FE fields are non-optional and mirrored in `types.ts`. CLI renders "(INVALID …)" via `sanitize()`; `CredentialDetail.tsx` renders the invalid state.
- **Edge cases:** invalid RFC3339, empty (→None, not invalid), extreme date, huge year, non-ASCII digits (`١٤٤٥`); listing/detail/status/monitor survive; later valid sync clears the flag+finding; user-entered `expires_at` column isolated too.
- **New failure modes:** none.

## M-6 — CI action SHA pinning & least privilege — FIXED

- **Vulnerable behavior:** third-party actions referenced by mutable tags (`@v4`, `@stable`) — a compromised action account could re-point them at malicious code on a workflow that can publish releases with `contents: write`.
- **Changed files:** `.github/workflows/ci.yml`, `release.yml`.
- **Independent proof (programmatic + manual cross-check):** all 23 `uses:` refs are full 40-hex SHAs with adjacent version comments; no `@vN`/`@main`/`@master`/`@stable` ref and no `pull_request_target` anywhere; `dtolnay/rust-toolchain` is SHA-pinned with an explicit `toolchain: stable`; ci.yml is workflow-level `contents: read` (no job elevates); release.yml is `contents: read` by default with `contents: write` only on the `desktop` and `cli-release` jobs; release.yml has no `pull_request` trigger (only tag-push + `workflow_dispatch`), so a forked PR cannot reach the write jobs — and GitHub caps forked-PR tokens at read-only regardless. A documented SHA-update process is present in both files.
- **Limitation:** SHA↔upstream-tag correspondence cannot be verified offline; recorded as a manual step (the SHA/version pairs are tabulated for a human/online check).
- **New failure modes:** none. Pinning removes the retroactive-tamper vector, not trust in the action's code at that SHA (documented).

## Tauri authorization harness (+ `provider_admin_disconnect` core reauth) — FIXED (adequate)

- **Gap fixed:** the 137-command Tauri layer had no Rust authz tests; `provider_admin_disconnect` enforced reauth only in the wrapper (the IPC-01/02 pattern), so a direct core call bypassed it.
- **Changed files/symbols:** `vault.rs::provider_admin_disconnect` (now `verify_master_password(master_password)?` then DELETE); `main.rs`/`provider_cmd.rs` (pass the password through); `openai_sync`/`rotation_access` (signature update); `tauri_command_authz.rs` (18 tests); `tauri_command_inventory.json`.
- **Independent proof:** inventory reconciliation confirmed **137 `#[tauri::command]` fns = 137 `generate_handler!` entries = 137 inventory entries**, identical sets, no registered-but-uninventoried command, no stale/fabricated entry (8 commands carry `#[allow(clippy::too_many_arguments)]` between the attribute and `fn`, correctly counted). The 18 tests invoke the **real** `UnlockedVault` methods (not mocks of authorization), asserting `WrongPassword` on wrong reauth, success on correct, state survival (credential survives failed-auth delete; old value intact after failed replace), clean `NotFound` on malformed IDs, no-secret-leak on both error-format forms, and — via an **empty** `MockHttpClient` + `last_request().is_none()` — that reauth precedes any provider/destination mutation. `provider_admin_disconnect` core reauth verified (wrong pw → refused, still connected; the CLI/Tauri wrappers can no longer bypass it).
- **Documented residual (non-blocking):** 5 security-relevant commands remain `not_covered` — `provider_admin_connect`/`provider_admin_test`/`backup_create` (wrapper reauth, RA-P2-1) and structural-gated `template_apply`/`env_import`. All honestly inventoried; none is an active bypass.

## React security tests (+ IPC-05 `safeExternalUrl`) — FIXED (IPC-05 solid; RA2-5 coverage gaps)

- **Gap fixed:** no React component tests; IPC-05 (`docs_url` rendered as a clickable `href` with no scheme validation).
- **Changed files/symbols:** `utils.ts::safeExternalUrl`; `CredentialDetail.tsx` (safe anchor); `vitest.config.ts`/`package.json`/`test/setup.ts`; 7 test files (32 tests).
- **Independent proof:** `safeExternalUrl` parses with `new URL()` (normalizes embedded/leading control chars per WHATWG) and allow-lists only `http:`/`https:`/`mailto:` on the canonical `protocol`; `safeUrl.test.ts` covers mixed-case + whitespace-padded `javascript:`, `data:`/`file:`/`vbscript:`, relative/malformed/empty/null. `CredentialDetail.tsx` renders unsafe schemes as inert `(not a safe link)` text and safe ones as `<a rel="noreferrer">`; the component test scans **every** `a[href]` and asserts none contains `javascript:`. An adversarial read of all 32 tests confirmed the mocking seam is correct (real components; only `../api`/`invoke` mocked), no fake timers, no missing awaits; the genuine security properties are established against user-visible DOM.
- **Documented residual (RA2-5, non-blocking):** the "32 tests" headline is inflated (~16–19 carry security weight; 8 util, 5 IPC contract-pins); three coverage holes (reveal auto-hide timer, `EnvView` error path, replace-value dialog clearing) and a missing pre-reauth ordering assert in the delete test. All three untested behaviors exist and are correct in production.

## RA-4 — Windows env-var casing scrub — FIXED

- **Vulnerable behavior:** `scrub_own_env` matched the `API_TRACKER_` prefix case-sensitively; on Windows (case-insensitive env lookups) a variable like `Api_Tracker_Password` evaded the scrub yet could be read by the app and leak to a child.
- **Changed files/symbols:** `inject.rs` (`env_name_is_scrubbed(name, case_insensitive)`, `ascii_ci_eq`/`ascii_ci_starts_with`, `scrub_own_env` passes `cfg!(windows)`).
- **Independent proof:** byte-level ASCII-case-insensitive comparison when the flag is set; the child-safe allowlist is matched with the same case sensitivity; non-UTF-8 names cannot dodge (byte matching). Unit tests exercise both modes directly: `env_name_is_scrubbed(_, true)` scrubs `API_TRACKER_SESSION`/`api_tracker_session`/`Api_Tracker_New_Password`/`API_TRACKER_NEW_PASSWORD` and preserves child-safe under any casing; `env_name_is_scrubbed(_, false)` scrubs only the exact-case prefix and leaves differently-cased names untouched.
- **Limitation:** the Windows `cfg!(windows)` runtime path compiles but is not behaviourally executed in CI; the mode is exercised directly via the helper. Unix semantics unchanged (verified).
- **New failure modes:** none.

## IPC-05 — `docs_url` scheme validation — FIXED

Covered under "React security tests" above. Allowlist scheme validator + inert rendering, tested at unit and component layers.
