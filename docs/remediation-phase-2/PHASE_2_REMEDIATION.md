# Tethra — Security Remediation Phase 2

**Model / provenance:** Claude Fable 5 (`claude-fable-5`), highest available
effort (ultracode: xhigh reasoning + dynamic workflow orchestration),
extended thinking on. No model fallback occurred.

**Branch:** `fix/security-phase-2`.
**Starting commit:** `033f747` (current `main`, merged PR #9).
**Scope:** the remaining confirmed Production/GA-gate findings from the deep
audit plus the missing authorization-focused automated-test foundations.
Production source was changed in this worktree only; neither audit evidence
worktree was touched. No real credentials, live providers, or real
destination writes were involved — all provider/destination traffic in tests
goes through `MockHttpClient` or scripted runners; all git-misbehaviour tests
use stub `git` binaries; all repositories are disposable temp dirs.

Every fix follows the same discipline: establish baseline-failure evidence at
`033f747`, add a security-property regression test, implement the fix, run the
focused test, run adjacent tests, and commit one coherent checkpoint. No PR #9
regression test was weakened.

---

## Phase 1 — PI-02 / CONC-11 / CLI-03 / RA-1: verify process identity before termination

**Root cause.** `terminate_process_session` signalled the recorded PID after
only a `pid <= 0` guard, with no check that the PID still referred to the
process launched under it. A launcher that died leaves its session row open;
the OS recycles the PID; the next `access kill` / `access end --kill` signals
whatever unrelated process now holds it. Two entry points bypassed even the
shared path: CLI `access end --kill` spawned `kill <pid>` inline (RA-1), and
nothing verified identity anywhere (PI-02).

**Security invariant.** A recorded PID is signalled ONLY when the process
identity captured at launch (platform start-time + executable) still matches
immediately before signalling. A stale row, a recycled PID, a tampered
record, or a missing identity is refused — never signalled. An already-exited
process is reported truthfully. Every request is audited.

**Design.** A single shared implementation, `inject::terminate_verified(pid,
recorded_identity)`, is the only path that may signal a recorded PID; CLI
`access kill`, CLI `access end --kill`, and the desktop `access_session_kill`
command all route through `vault.terminate_process_session`, which calls it.
Identity is captured in `set_session_pid` (called by `run` while the child
handle is still held — the only moment the PID provably refers to our child)
via `probe_process_identity`: on Unix two `LC_ALL=C ps` probes (`lstart=`,
`comm=`), on Windows a PowerShell `Get-CimInstance Win32_Process` query for
`CreationDate` + `Name`. The identity is prefixed with the platform family so
a vault carried between OSes never matches cross-platform. `terminate_verified`
re-probes and returns a truthful `TerminationOutcome` (`Refused{reason}` /
`AlreadyExited` / `Signalled` / `SignalFailed`); `AlreadyExited` closes the
row. A new migration (v11) adds `process_sessions.proc_identity TEXT`.

**Files changed.** `crates/core/src/inject.rs` (probe, outcome enum,
`terminate_verified`, `set_session_pid` identity capture, `ProcessSession`
field), `crates/core/src/vault.rs` (`terminate_process_session` routing +
outcome auditing + row-close), `crates/core/src/db.rs` (migration v11),
`apps/cli/src/access_cmd.rs` (`kill` + `end --kill` route through the vault),
`apps/desktop/src-tauri/src/main.rs` (`access_session_kill` returns the
outcome), `apps/desktop/src/{types.ts,components/AccessView.tsx}`.

**Regression tests.** `crates/core/tests/pi02_process_identity.rs` (10):
non-positive PIDs at every layer, PID reused by a different process, same PID
with a fabricated identity, already-exited (row closed), correct matching
process signalled + audited, tampered record naming a system process,
cross-platform identity, descendants NOT signalled (documented PI-03 limit),
and the probe's own not-found/unverifiable behavior.
`apps/cli/tests/access_end_kill_guard.rs` (1): `access end --kill` refuses a
stale record instead of killing blind (RA-1). The existing observability
termination test was updated to the truthful outcome type (assertion
strengthened, not loosened).

**Baseline failure evidence.** `evidence/pi02_baseline_fail.log.txt` — at
`033f747` the stale-PID test signalled and killed the unrelated decoy.

**Corrected result.** 10/10 + 1/1 pass; the decoy always survives; the audit
log records requested/refused/successful/failed termination without secrets.

**Platform limitations.** The Windows probe path compiles in CI but is not
executed there (no Windows behavioural runner); its structure mirrors Unix and
fails closed to `Unverifiable`. Start-time identity has one-second
granularity, so a same-second PID recycle of the same executable is a
documented residual the executable-name second factor narrows but cannot fully
eliminate. Only the recorded process is signalled — descendants it spawned are
not (PI-03 remains open, now tested as documented behavior).

**Residual risk.** PI-03 (descendant/process-group termination) and PI-05
(wall-clock grant expiry) remain deferred. The verify→signal window is
milliseconds; without OS process handles (pidfd / Job objects) it cannot be
zero.

---

## Phase 2 — GScan-01 / GScan-02: make git hook protection active and truthful

**Root cause.** Hook install/status hard-coded `.git/hooks/pre-commit` and
never consulted `core.hooksPath`, so with a hook manager configured (husky,
global hooks) git ran a different file while status still reported
`Installed` (GScan-01). Force-chain APPENDED the Tethra block after a
foreign hook, so an early `exit`/`exec` in the foreign hook skipped the scan
while status still said "chained" (GScan-02).

**Security invariant.** Status never claims protection git will not execute;
when chaining, the scan runs BEFORE any pre-existing hook can `exit`/`exec`;
foreign hook semantics are preserved; unsupported configurations are refused
or described honestly; hook content is injection-safe.

**Design.** `gitrepo::config_get` reads the effective `core.hooksPath` (the
merged value git itself resolves, any scope; a non-"unset" failure is a loud
error, not a silent default). `effective_hook_path` resolves the file git
will actually run (relative values against the worktree top). `install`
writes there, relocates a stale default-location install, refuses binary /
unreadable / non-executable foreign hooks, and chains our block IN FRONT via
`chain_ours_first` (foreign shebang stays line 1; our block is plain POSIX
sh). `status` reports `Absent | Installed | Foreign | ChainedIntoForeign |
Overridden | Unsupported` plus an `active` boolean and an honest `detail`.
Hook injection safety is unchanged: the repo path enters the generated script
only as a runtime `"$(git rev-parse --show-toplevel)"` command substitution,
never interpolated at install time.

**Files changed.** `crates/core/src/hooks.rs` (rewrite of status/install/
remove + new states), `crates/core/src/gitrepo.rs` (`config_get`),
`apps/cli/src/scan_cmd.rs` (surface `active`/`detail`/override),
`apps/desktop/src/{types.ts,components/ScanView.tsx}`.

**Regression tests.** `crates/core/tests/gscan_hooks.rs` (12), each a REAL
`git commit` with a stub `api-tracker` first on `PATH` that records whether the
scan ran: local `core.hooksPath` active, GLOBAL `core.hooksPath` honoured,
force-chain scans before an `exit`/`exec` foreign hook, a chained scan blocks
even a permissive foreign hook, husky-style config, idempotent repeat install,
uninstall restores the prior hook, a broken binary hook is refused not
corrupted, a stale shadowed install reports `Overridden` and re-install
relocates, a hook that lost its execute bit reports inactive, and a
hooksPath with spaces stays safe. The in-file `hooks` unit tests were updated
to assert scan-first ordering.

**Baseline failure evidence.** `evidence/gscan_baseline_fail.log.txt` — at
`033f747`, 9/10 property tests fail (hooksPath ignored; append-after-exit).

**Corrected result.** 12/12 pass; existing `scanning`/`scanning_cli` suites
still green (identical findings).

**Platform limitations.** Windows hook execution (git-for-Windows runs hooks
via `sh` regardless of an execute bit) is not behaviourally tested; the
`is_executable` inertness check is Unix-specific and returns `true` on Windows.

**Residual risk.** GScan-04 (medium-confidence high-value secrets pass the
pre-commit block) and GScan-05 (documented evasion gaps) remain deferred.

---

## Phase 3 — CONC-06 + GScan-03 / CONC-05: bound git execution and history scanning

**Root cause.** Every git subprocess used blocking `Command::output()` with no
timeout, so a hung git (dead network mount, wedged lock) wedged the monitor and
the desktop (which holds the vault mutex across a scan) forever (CONC-06).
`git log -p` output was buffered whole and copied again into a `String`, so a
large history or a crafted diff could exhaust memory (GScan-03 / CONC-05).

**Security invariant.** Every git subprocess has an explicit timeout and is
killed + reaped on violation (never orphaned); history is streamed under
explicit per-line / per-unit / total-retained / duration limits; ANY limit hit
is reported as INCOMPLETE COVERAGE and never presented as a clean/full scan;
redaction is preserved; the desktop vault mutex is not held during the long
git collection.

**Design.** A bounded runner in `gitrepo.rs` spawns git with piped stdio,
pumps stdout over a bounded channel (backpressure) on a reader thread, kills +
reaps via a `ChildGuard` (Drop) on timeout / cap / error / cancellation, and
returns a typed `GitCapture`. `GitLimits::{command,history}` carry the caps
(debug-only env overrides let tests drive them down deterministically).
`stream_log_units` parses `git log -p` line-by-line through an incremental
`LogStreamParser` that never buffers the whole stream; a truncated unit or a
cap/timeout produces a coverage warning and marks the scan incomplete.
`scan_history` returns `ScanOutcome { findings, complete, warnings }`; the
incremental monitor raises a persistent `RepoScanCoverageGap` on partial/failed
ranges; `reverify_repo_exposure` resolves alerts ONLY on a complete clean scan.
The desktop `scan_path` / `scan_reverify` commands now collect units OUTSIDE
`with_vault` and run only the fast DB-bound `scan_units` under the lock.
`envgov`'s git probes route through the same bounded runner.

**Files changed.** `crates/core/src/gitrepo.rs` (bounded runner + streaming
parser + `collect_full_repo_scan`), `crates/core/src/vault.rs`
(`scan_history` → `ScanOutcome`, `scan_units` made public,
`reverify_repo_exposure_collected`, coverage-gap honesty),
`crates/core/src/envgov.rs` (bounded probes), `apps/cli/src/scan_cmd.rs`
(coverage warnings), `apps/desktop/src-tauri/src/main.rs` (collect-outside-lock
+ `ScanPathReport`), `apps/desktop/src/{types.ts,components/ScanView.tsx}`.

**Regression tests.** `crates/core/tests/gitbound_scanning.rs` (10): hung git
times out incomplete + child reaped, short commands error loudly on timeout,
slow git yields partial findings + incomplete coverage, infinite output hits
the byte cap (bounded memory) + reaped, retained-content cap stops the scan
honestly, an oversized line is truncated but normal findings survive, a large
blob in real history truncates its unit with a warning, a many-commit
repository scans completely, an incomplete incremental scan leaves a persistent
coverage-gap alert (resolved only by a complete clean re-verify), and an
incomplete reverify never resolves alerts. The `obs001` coverage-gap helper was
updated to match by dedup identity.

**Baseline failure evidence.** `evidence/conc06_baseline_fail.log.txt` — at
`033f747`, a `scan_history` against a hung git stub is still blocked after 5s.

**Corrected result.** 10/10 pass; `scanning`/`scanning_cli`/`obs001` still
green (identical findings on normal scans).

**Platform limitations.** The Windows PowerShell path in the process probe is
unrelated here; the bounded runner is portable. Reader/stderr threads are
joined or abandoned safely on kill.

**Residual risk.** CONC-01/02 (desktop mutex breadth, auto-lock across
suspend) remain deferred; this phase removes the git-time contribution to
CONC-01 for scans but not the mutex model itself.

---

## Phase 4 — DEST-01 / DEST-02 / DEST-03: make destination drift and targeting truthful

**Root cause.** GitHub Actions and AWS `exists()` returned
`Some((200..300).contains(status))`, collapsing 401/403/429/500/timeout into
`Some(false)` = "missing" → false drift and invited destructive re-writes
(DEST-01). Vercel matched env vars by key only, ignoring the target set, so
`exists`/`delete` could confirm or delete the wrong same-key variable
(DEST-02). `destination_drift_check` silently `continue`d over un-buildable
adapters and re-presented their stale stored drift as if freshly verified, and
`execute_step` stamped a step verified even on `missing`/`unknown` (DEST-03 /
DEST-04).

**Security invariant.** Auth/transport/server errors are `unknown`, never
`missing`. A destination's identity is key + exact targets + custom-environment
context; read/verify/drift/delete target the same identity; delete fails safe
on ambiguity or another-target-only match. An unqueryable destination is an
explicit not-checked state, never re-presented as fresh. A step/drift result
is stamped verified only when verification actually succeeded; `last_verified_at`
never advances on `unknown`. Existence-only verification stays distinct from
value read-back.

**Design.** GitHub/AWS `exists()` map only definitive answers to a verdict
(2xx = present, 404 / RNFE = absent) and turn auth/throttle/server/unrecognized
responses into typed errors. Vercel gains `resolve_env_identity` (key + exact
target set, excluding custom-environment-scoped vars), returning
`Ok(Some(id))` / `Ok(None, other_targets)` / `Err(ambiguous)`; `delete` refuses
an other-targets-only match and treats a 404 between list and delete as
already-gone. `record_verify` skips advancing `last_verified_at` on `unknown`.
`execute_step` records `unknown` on a verification error (never `missing`) and
stamps verified only for `in_sync`/`present_unverifiable`.
`destination_drift_check` returns `Vec<DriftCheckOutcome>` (attachment +
`checked` + `check_error`), so a skipped attachment is explicit.

**Files changed.** `crates/core/src/destinations.rs` (adapter `exists`/`delete`,
Vercel identity, `record_verify`, `DriftCheckOutcome`),
`crates/core/src/vault.rs` (`execute_step` verify honesty, `destination_drift_check`),
`apps/cli/src/destination_cmd.rs`, `apps/desktop/src-tauri/src/main.rs`,
`apps/desktop/src/{types.ts,components/DestinationsView.tsx}`.

**Regression tests.** `crates/core/src/destinations.rs` unit tests (11 new):
GitHub/AWS `exists` never converts 401/403/429/500 into missing (only
404/RNFE = absent, 2xx = present, transport = error); Vercel identity is
key+targets, delete targets exactly its own variable, refuses another target's
variable, fails safe on ambiguity, treats custom-environment as a different
identity, tolerates absent/stale-id, and propagates list/parse failures.
`crates/core/tests/dest_truthfulness.rs` (5): auth/transport drift is
unknown-not-missing and not verified, definitive absence IS missing+verified, a
failed check preserves prior verdict history without advancing
`last_verified_at`, and a sync step is never verified when its existence check
fails. One pre-existing baseline test's unrealistic Vercel mock (a var with no
target array) was made realistic (target array added) — its intent (retry
succeeds) is preserved.

**Baseline failure evidence.** `evidence/dest_baseline_fail.log.txt` — at
`033f747`, 12 of the new tests fail (missing-on-error, key-only match,
verified-on-failure).

**Corrected result.** All new tests pass; `env_destinations` still green.

**Platform limitations.** None new. Live-provider verification of read-back /
exists semantics per provider remains out of automated scope (requires real
credentials).

**Residual risk.** DEST-04..13 (lower-severity correctness / doc issues) remain
deferred; existence-only providers (GitHub, Vercel) are labeled
`present_unverifiable`, never value-verified.

---

## Phase 5 — OBS-004: isolate malformed provider expiration values

**Root cause.** `credential_model` parsed `expires_at` / `provider_expires_at`
with `?`-propagating `parse_optional_ts`, and `list_credentials` collected into
a `Result`, so one credential's unparseable `provider_expires_at` (stored
verbatim from provider sync, no parse check) failed EVERY listing, detail view,
alert pass, and monitor run vault-wide.

**Security invariant.** Expiration is parsed per credential; one malformed
value cannot break unrelated listings; the original value is preserved for
diagnostics; the affected expiration is shown unknown/invalid without
fabricating a date; status/alerts fail locally to the affected credential; no
secret leaks in logs or errors.

**Design.** `parse_optional_ts_lenient` returns `(Option<OffsetDateTime>,
invalid_flag)`: a bad value contributes no date (no fabrication) and is
flagged. `credential_model` uses it for the four stored timestamps; the raw
string is preserved and two new `Credential` fields
(`expires_at_invalid` / `provider_expires_at_invalid`) surface the invalid
state. The status engine gains `expiration_unparseable`, emitting an explicit
`Unknown` finding ("could not be parsed … expiry is unknown") rather than
guessing. `created_at` stays strict (always Tethra-generated; a bad value
is genuine corruption). CLI and desktop render "invalid" instead of a
fabricated date.

**Files changed.** `crates/core/src/vault.rs` (`parse_optional_ts_lenient`,
`credential_model`), `crates/core/src/status.rs` (input + finding),
`crates/core/src/model.rs` (fields), `crates/core/src/monitor.rs` (test
fixture), `apps/cli/src/render.rs`, `apps/desktop/src/{types.ts,
components/CredentialDetail.tsx}`.

**Regression tests.** `crates/core/tests/obs004_expiration_isolation.rs` (5):
several malformed values (invalid RFC3339, empty, extreme date, non-ASCII
digits) each keep the whole listing working and the unrelated credential
unaffected; detail views of both the poisoned and unrelated credentials work;
a later valid sync clears the invalid flag; the monitor survives; the
user-entered `expires_at` column is isolated too.

**Baseline failure evidence.** `evidence/obs004_baseline_fail.log.txt` — at
`033f747`, one malformed `provider_expires_at` fails the entire listing with
`InvalidInput("'not-a-date' is not an RFC 3339 timestamp")`.

**Corrected result.** 5/5 pass; `observability`/`credentials`/`status` green.

**Platform limitations.** None.

**Residual risk.** OBS-002/003/005..012 (other observability correctness
items) remain as-is except OBS-003, already fixed in PR #9.

---

## Phase 6 — M-6: pin CI actions to immutable revisions

**Root cause.** `ci.yml` and `release.yml` referenced third-party actions by
mutable tags (`@v4`, `@v2`, `@v0`, `dtolnay/rust-toolchain@stable`), which a
compromised action account could re-point at malicious code — a direct
supply-chain risk on a workflow that can publish releases with
`contents: write`.

**Security invariant.** No mutable `@vN`/`@main`/`@master`/`@stable` reference
remains; each pin is a full 40-char commit SHA with an adjacent version
comment; release permissions are least-privilege per job; the SHA-update
process is documented.

**Design.** Every action pinned to its release SHA (resolved via the GitHub
API): `actions/checkout` v4.3.1, `actions/setup-node` v4.4.0,
`actions/upload-artifact` v4.6.2, `actions/download-artifact` v4.3.0,
`Swatinem/rust-cache` v2.8.1, `softprops/action-gh-release` v2.6.2,
`tauri-apps/tauri-action` v0.6.2. `dtolnay/rust-toolchain` (whose `@stable` ref
doubles as the toolchain selector) is pinned to the `stable`-branch commit with
`toolchain: stable` passed explicitly (verified the pinned `action.yml` accepts
that input). `ci.yml` gains workflow-level `permissions: contents: read`;
`release.yml` keeps `contents: read` at the workflow level with `contents:
write` only on the two jobs that attach release artifacts. A comment block in
each workflow documents the SHA-update process.

**Files changed.** `.github/workflows/ci.yml`, `.github/workflows/release.yml`.

**Regression tests.** Not unit-testable; validated by: zero mutable refs
(`grep`), all pins 40-hex, valid YAML (`yaml.safe_load`), and confirming the
pinned rust-toolchain commit's `action.yml` exposes a `toolchain` input.

**Baseline failure evidence.** N/A (supply-chain config, not runtime behavior).

**Platform limitations.** None.

**Residual risk.** SHAs must be updated deliberately (documented); a pinned
action still runs whatever code that SHA contains — pinning removes the
retroactive-tamper vector, not trust in the action itself.

---

## Phase 7 — Tauri direct-command authorization harness

**Root cause / gap.** The 137-command Tauri layer had NO Rust-side
authorization tests; direct-IPC reauth (core-enforced vs UI-only) was only
spot-verified by reading. One destructive command, `provider_admin_disconnect`,
enforced reauth only in the Tauri/CLI wrappers (the wrapper-only pattern that
made IPC-01/02 vulnerabilities), so a direct core call bypassed it.

**Security invariant.** Every destructive/secret-bearing command enforces
reauth in core (a direct `invoke` cannot bypass it); missing/incorrect reauth
is refused; correct reauth succeeds; malformed IDs/paths are refused cleanly
(no panic, no secret leak); errors are redacted; no UI sequencing is
load-bearing for authorization.

**Design.** `provider_admin_disconnect` gains a `master_password` parameter and
verifies reauth in core (matching IPC-02); the Tauri wrapper and CLI now pass it
through instead of gating in the wrapper. The harness invokes the exact core
methods each command delegates to — the backend path a hostile `invoke` reaches
— and asserts the invariant without duplicating the production rules. A
machine-readable inventory of all 137 commands records security relevance,
destructive/secret-bearing flags, reauth requirement, backend enforcement
(core / wrapper / backup_password / structural), and test status.

**Files changed.** `crates/core/src/vault.rs` (`provider_admin_disconnect`
reauth), `apps/desktop/src-tauri/src/main.rs`, `apps/cli/src/provider_cmd.rs`,
`crates/core/tests/{openai_sync,rotation_access}.rs` (signature update).

**Tests added.** `crates/core/tests/tauri_command_authz.rs` (18): credential
reveal/copy/delete/replace/versions, master-password change, project-password
set/remove, `.env.example` write (confined), plaintext export, backup restore,
destination remove + delete-secret, provider-admin disconnect (now core), all
five rotation ops, sync-plan execute, and verified temporary-access
termination. Each asserts wrong/missing/correct reauth, malformed-ID handling,
that no destination request or provider mutation happens before reauth, and no
secret in errors. Inventory: `docs/remediation-phase-2/tauri_command_inventory.json`.

**Baseline failure evidence.** The harness codifies the invariant on the fixed
code; the wrapper-only-reauth gap it closes (`provider_admin_disconnect`) is
the finding. (The IPC-01/02 fixes it also exercises were verified fixed in
PR #9.)

**Corrected result.** 18/18 pass.

**Platform limitations.** The harness tests the core backend path, which IS
what the Tauri wrapper calls; it does not spin up the Tauri runtime. Three
commands (`backup_create`, `provider_admin_connect`, `provider_admin_test`)
still enforce reauth in the wrapper (see NEW_FINDINGS RA-P2-1) and are recorded
as `not_covered_wrapper_reauth`.

**Residual risk.** The inventory explicitly does NOT claim all 137 commands are
fully secured: 97 low-relevance read/metadata commands are gated only by the
unlocked vault and are marked `not_covered`.

---

## Phase 8 — React security workflow tests

**Root cause / gap.** The React frontend had no component tests; reauth
dialogs, secret display/clearing, and the `docs_url` anchor (IPC-05: no scheme
validation) were unverified. IPC-05 was a real gap: a `javascript:`/`file:`
`docs_url` rendered as a clickable `href`.

**Security invariant.** Reauth password is cleared on success, retained on
failure; backend authorization errors are shown honestly (never silently
swallowed or faked); destructive actions require confirmation + reauth; secret
reveal/copy state clears; a `docs_url` renders as a link only for an
explicitly-safe scheme; a locked vault drops the authenticated UI (and any open
dialog's in-memory password) to the unlock screen.

**Design.** A pure `safeExternalUrl` util allows only `http`/`https`/`mailto`
and is applied to the `CredentialDetail` docs anchor (IPC-05 fix: unsafe schemes
render as inert text). Test tooling added: `@testing-library/react` +
`user-event` + `jest-dom` + `jsdom`, a `vitest.config.ts` (jsdom, globals,
setup file). Tests assert user-visible behavior and backend `invoke` payloads,
never visual implementation details.

**Files changed.** `apps/desktop/src/utils.ts` (`safeExternalUrl`),
`apps/desktop/src/components/CredentialDetail.tsx` (safe anchor),
`apps/desktop/{vitest.config.ts,package.json,src/test/setup.ts}`.

**Tests added (32).** `safeUrl.test.ts` (3, IPC-05), `api.security.test.ts` (8,
invocation payloads + honest backend errors + vault-locked propagation),
`components/ReauthDialog.test.tsx` (4, password clear-on-success /
retain-on-failure / honest error / empty-field guard / cancel),
`components/CredentialDetail.security.test.tsx` (6, reveal+clear, failed-reveal,
copy-state, delete confirm+reauth, docs_url safe/unsafe),
`App.security.test.tsx` (2, locked-vault gating + transition unmounts the
authenticated tree), `components/RotationView.security.test.tsx` (1, two-stage
confirm→reauth→rollback).

**Baseline failure evidence.** IPC-05 is confirmed by the `safeUrl` /
CredentialDetail tests: a `javascript:` value would have rendered as an `href`
before the fix; it now renders as inert text.

**Corrected result.** 32/32 pass; prettier/eslint/tsc/vite-build all clean.

**Platform limitations.** Tests run in jsdom, not a real webview; the Tauri
opener config (ProviderDetail's `openUrl` path) remains gated by the backend,
not FE-validated.

**Residual risk.** ProviderDetail passes backend-manifest URLs to `openUrl`
without FE validation (backend/opener config is the gate); low-relevance views
remain untested.

---

## Phase 9 — RA-4: scrub Tethra env vars across platforms

**Root cause.** `scrub_own_env` matched the `API_TRACKER_` prefix
case-sensitively. On Windows, env lookups are case-insensitive, so a variable
stored with unusual casing (e.g. `Api_Tracker_Password`) evaded the scrub yet
could still be read by the app via `std::env::var("API_TRACKER_PASSWORD")` and
leak to a launched child.

**Security invariant.** On Windows, ANY casing of the `API_TRACKER_` prefix is
scrubbed (and the child-safe allowlist matched case-insensitively); on Unix,
normal case-sensitive semantics are preserved (a differently-cased name is an
unrelated variable).

**Design.** A pure `env_name_is_scrubbed(name, case_insensitive)` does
ASCII-case-insensitive byte comparison when the flag is set; `scrub_own_env`
passes `cfg!(windows)`. Byte-level matching is retained so a non-UTF-8 name
cannot dodge the scrub.

**Files changed.** `crates/core/src/inject.rs`.

**Regression tests.** In-file unit tests (2):
`windows_scrub_is_case_insensitive_for_the_api_tracker_prefix` (the required
`API_TRACKER_SESSION`, `api_tracker_session`, `Api_Tracker_New_Password` all
scrubbed; child-safe survives any casing) and
`unix_scrub_preserves_case_sensitive_semantics` (exact-case scrubbed;
lowercase/mixed left untouched). The PI-01 CLI black-box test still passes.

**Baseline failure evidence.** RA-4 is a theoretical Windows-only edge; the
Unix runtime never exposed it (documented in the re-audit). The
case-sensitivity is verified directly by the two-mode helper tests.

**Corrected result.** Both pass; `run_env_scrub` green.

**Platform limitations.** The Windows case-insensitive runtime path
(`cfg!(windows)`) compiles in CI but is not behaviourally executed there; the
mode is exercised directly via the helper's `case_insensitive = true` tests.

**Residual risk.** None specific; the deny-by-default prefix scrub is now
platform-correct.

---

## Manual tests still required

- Windows behavioural execution of: the process-identity probe
  (`Get-CimInstance`), `taskkill` graceful→forceful termination, git hook
  execution via `sh`, and the case-insensitive env scrub at runtime. CI
  compiles these paths but does not execute them.
- Live-provider verification (real credentials, out of automated scope) of
  destination read-back / exists semantics per provider (GitHub Actions, AWS,
  Vercel) and the rotation lifecycle.
- Packaged Tauri app (`cargo-tauri` not installed locally): CSP / allowlist /
  opener config at runtime, and the `.app`/`.dmg` bundle.
- The manual UI test plan (UI_MAP / TEST_PLAN) should add: hook `active`/
  `Overridden` status display, destination not-checked drift rows, invalid
  expiration display, and the docs_url unsafe-scheme inert rendering.
