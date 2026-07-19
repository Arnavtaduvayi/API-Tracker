# API Tracker — Deep Technical Audit

**Baseline audited:** commit `7d81090a1068476291546963e68ca8c7de1a7145` (`7d81090`), branch `audit/deep-pressure-test`, worktree `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-deep-audit`, remote `github.com/Arnavtaduvayi/API-Tracker`. Working tree clean at start.

**Environment:** macOS 26.5 (25F71) arm64; rustc/cargo 1.96.1 (CI clippy toolchain 1.97.0); node 24.13.0, npm 11.6.2; rusqlite bundled SQLite (CLI 3.51.0); cargo-tauri not installed locally (desktop bundling not exercised here).

**Baseline test suite:** `cargo test -p api-tracker-core -p api-tracker-cli` → **398 passed, 0 failed, 0 ignored, 0 warnings** (debug build with `API_TRACKER_INSECURE_FAST_KDF=1`). A green suite is treated as necessary, not sufficient.

**Scope:** ~45,900 LOC Rust (core crate, CLI, Tauri backend), ~9,400 LOC TS/React. 136 Tauri commands, 5 provider adapters, ~10 destination adapters, a durable rotation state machine, local git scanner, `.env` governance, backup/restore, and a background monitor.

> **No product code was modified. This branch has not been merged. No release was built or published.** All findings below are recorded with file/symbol/line evidence; several are labelled *unverified* (see Method).

---

## Method & honest limitations

Two independent, complementary passes were run and reconciled:

1. **Orchestrator deep-read (this author):** full or security-critical reads of `crypto.rs`, `secret.rs`, `error.rs`, `clock.rs`, `db.rs`, `session.rs`, `inject.rs`, `http.rs`, `docwatch.rs`, `rotation.rs`, `envfile.rs`, `gitrepo.rs`, `hooks.rs`, `permissions.rs`, `notify.rs`, `backup.rs` (payload/quoting), `pricing.rs` (money math), `destinations.rs` (SigV4 + capability honesty), `scanner.rs` (redaction), `envgov.rs` (atomic write), the vault key/auth/reveal/rotation/env-export spans of `vault.rs`, the desktop state/reveal/copy/delete/reauth wiring + CSP/capabilities, the CLI reveal path, and both CI/release workflows. A full `.expose()` leak sweep was run.

2. **11-mandate adversarial workflow:** independent reviewers (crypto-vault, fs-envfile, process-inject, provider-net, destinations, rotation, ipc-frontend, git-scan, business-docs, concurrency-dos, cli), each starting from code, followed by per-finding adversarial verification.

**Limitation — the verification pass was truncated by a monthly-spend limit.** Of the workflow's agents, 59 completed and 49 aborted on the spend cap. Consequences, stated plainly:

- The **`db-migration` reviewer did not run** — that surface is covered by the orchestrator's full read of `db.rs` instead.
- **48 of the 96 findings were adversarially verified** (46 CONFIRMED, 2 REFUTED). The verifiers for the **rotation, concurrency-dos, business-docs, and fs-envfile** mandates did not run, so those findings are marked **`unverified`** below — they carry the reviewer's trace but not an independent second opinion. Where an unverified finding is High/Medium and cheaply checkable, the orchestrator re-checked it against code and says so.
- The two REFUTED findings (CRYPTO-02, IPC-03) are excluded from the counts below.

This report therefore distinguishes **CONFIRMED** (two independent reads agree), **trace-confirmed** (orchestrator re-checked an unverified finding), and **unverified** (single reviewer, plausible, not independently checked).

---

## Executive summary

The security *architecture* is strong and, in most subsystems, exemplary: `#![forbid(unsafe_code)]` core with no unsafe anywhere; Argon2id + XChaCha20-Poly1305 with per-row AAD that genuinely prevents cross-row ciphertext swaps; reauthentication enforced as a **cryptographic precondition in core** (not a UI gate); a rotation state machine with compare-and-swap transitions, an orphan-key guard, and honest 404 handling; bounded HTTP (no redirects, size/timeout/pagination caps); a `.env` parser that never executes shell; and honest capability labelling for write-only destinations and unsupported permission edits.

The defects are concentrated not in the cryptography but in **lifecycle correctness and multi-process concurrency**: a rotation that can wedge with no exit path (ROT-001), security alerts that silently self-resolve (OBS-001), and a concurrent credential-write vs project-key-rotation race that silently destroys a credential value (CRYPTO-01/CONC-03). None are remote-network vulnerabilities; the product is local-first and single-user, which bounds impact, but several undermine the product's own guarantees (data durability, exposure monitoring, honest verification).

### Severity counts (after reconciliation; 2 REFUTED excluded)

| Severity | Count | IDs (headline) |
|---|---:|---|
| **High** | 3 | ROT-001, OBS-001, CRYPTO-01 (=CONC-03) |
| **Medium** | ~24 | CONC-01/02/04/06, ROT-002/003/004/005/006/007, DEST-01/02/03, GScan-01/02/03, IPC-01, PI-01/02, OBS-002/003/004 |
| **Low** | ~40 | CLI-01/02/03, CONC-07..12, DEST-04..10, FS-01..04, IPC-02/04, NET-01, PI-03/04/05, OBS-005..012, ROT-008/009, SYNC-001/002, GScan-04, CRYPTO-03 |
| **Informational** | ~27 | CLI-04/05/06, CRYPTO-04/05, DEST-11/12/13, FS-05..09, GScan-05, INFO-01/02, IPC-05, NET-02/03/04, OBS-013/014/015, PI-06/07, ROT-010/011 |

(The Medium/Low split around the unverified rotation cluster is the orchestrator's judgement; treat ±a few as noise.)

### Suitability

| Use | Verdict |
|---|---|
| Local developer testing | **Yes** — with awareness of CRYPTO-01 (avoid concurrent desktop+CLI writes during a project-password change). |
| Private alpha | **Yes, after** the 3 High fixes and CRYPTO-01. |
| Public alpha | **Not yet** — ship after High + the concurrency/rotation Medium cluster (CONC-01/02/04, ROT-002/004/007, DEST-01/02) and the two SSRF/label doc fixes. |
| Production | **No** — pending the above plus artifact signing and unbounded-growth pruning (CONC-07). |

---

## High-severity findings

### ROT-001 — A lost revoke response or a crash after revocation permanently wedges a rotation with no exit path
*Reliability/correctness; security-adjacent (outage presented as success). `vault.rs` OLD_DISABLED arm (~7057), `rotation_revoke_old` (~7219), exits at 7343/7386/7421. Unverified by second pass; **orchestrator trace-confirmed** the two load-bearing facts below.*

- **Scenario A (lost response, no crash):** the revoke `DELETE` reaches the provider and succeeds, but the HTTP response is lost (timeout). The failure is recorded via `record_error`, appending a "step failed (retryable)" event *after* the "attempting revocation" note. `attempted_before` inspects only the **last** event, which is now always the failure, so it is permanently `false`. On retry the provider returns 404 → `CoreError::NotFound` → refused as "wrong key id". The rotation loops in `OLD_DISABLED` forever.
- **Scenario B (crash after revoke):** revoke succeeds, `old_revoked_at` is set, but the process dies before the CAS to `COMPLETED`. On restart the `OLD_DISABLED` arm **never reads `old_revoked_at`** and calls `rotation_revoke_old` again → 404 → same loop.
- **Every exit is closed:** `rotation_complete_manual` whitelists only `MANUAL_REQUIRED|GRACE_PERIOD`; `rotation_cancel` refuses (new_version set); `rotation_rollback` refuses in B (`old_revoked_at` set) and in A *restores the vault + destinations to the deleted key and reports a clean `ROLLED_BACK`* — an outage presented as success. Because the rotation stays active, `delete_credential` and `rotation_approve` both refuse: the credential can never be rotated or deleted again without hand-editing the DB.
- **Orchestrator verification:** confirmed against my earlier read that the `OLD_DISABLED` arm (7057-7077) checks only `!rot.new_value_validated` and does **not** consult `old_revoked_at`, and that `rotation_revoke_old` (7219+) has no `if rot.old_revoked_at.is_some() { return Ok(true) }` short-circuit. Both facts hold. **Confirmed real.**
- **Fix:** (1) short-circuit `rotation_revoke_old` when `old_revoked_at` is already set (idempotent completion); (2) replace the `.last()`-event `attempted_before` heuristic with a persisted `revoke_attempted_at` column or an all-events scan; (3) add a reauthenticated, `provider list-keys`-cross-checked exit from `OLD_DISABLED` (e.g. `--confirm-key-gone`).
- **Regression test:** simulate revoke returning transport-error-after-success, then 404 on retry → rotation must complete, not loop. Simulate crash after `old_revoked_at` → restart must complete.

### OBS-001 — Repo-scan exposure alerts are silently auto-resolved by the next monitor run
*Security-monitoring integrity (false assurance). `run_monitor` (~2044-2112), `scan_repos_incremental` (~5121-5153), `monitor.rs:140-150`. Unverified by second pass; trace is specific.*

- A `PossibleExposure` alert for a new-commit secret finding uses a commit-specific dedup key `repo_scan_findings:{repo}:{head_commit}`. On the next monitor run the unchanged repo is **skipped** (`Some(last) if last == &head => continue`), so that key is never re-added to `active_keys`. Because `managed_credential_kinds()` includes `PossibleExposure`, `auto_resolve_stale(&conn, &managed, &active_keys)` **resolves the still-valid exposure alert** — the leaked secret is still in git history and nothing was remediated.
- Worse, the `repo_rebaselined:{path}:{head}` warning ("commits in that range were NOT scanned") is created inside `scan_repos_incremental` and its key is *never* pushed to `active_keys`, so it is auto-resolved by the `auto_resolve_stale` call at the end of the very same run — it never survives as an open alert.
- **Impact:** a developer who leaked a secret sees the exposure alert disappear on the next cycle and reasonably concludes it was handled.
- **Fix:** give repo-scan/rebaseline alerts their own `AlertKind` excluded from auto-resolve, or keep re-adding their dedup keys while `repo_scan_state.last_findings > 0` / until acknowledged, or drop `head_commit` from the dedup key and only resolve after a clean rescan of the same range.
- **Regression test:** create an exposure alert, run the monitor again on the unchanged repo, assert the alert is still open.

### CRYPTO-01 / CONC-03 — Concurrent project-key rotation during add/replace writes ciphertext under a destroyed key (silent permanent data loss)
*Data loss. `add_credential` (~1204-1275), `replace_credential_value` (~1652-1714), `rotate_project_key`/`set_project_password` (~878-983), `project_key_for_row` (~846-870). **CONFIRMED** by the verification pass (and independently found by two reviewers).*

- The product supports concurrent desktop+CLI access (WAL is enabled "for safe concurrent access"). `add_credential`/`replace_credential_value` read the project row and derive the project key K1, encrypt under K1, and write — **all in autocommit, with no transaction spanning read→write.** If, in that window, another process runs `set_project_password`/`remove_project_password`, `rotate_project_key` generates K2, re-encrypts existing rows under K2, and **overwrites `wrapped_project_key`**, leaving K1 with no wrap anywhere. The first process then commits a value encrypted under the now-orphaned K1. The value is permanently undecryptable; the operation reports success.
- **This corrects an earlier orchestrator conclusion.** I initially judged the BLAKE3 wrap-hash freshness check in `project_key_for_row` sufficient. It is not: that check compares the cached key against the **stale `ProjectRow` snapshot** read at the top of the call, never against current DB state at write time, and vault-mode projects have no cache/guard at all. SQLite's single-writer WAL does not help — the rotation's transaction commits and releases the write lock before the first process's autocommit write acquires it, so there is no `SQLITE_BUSY`.
- **Impact:** silent, permanent loss of a credential's value (in `replace`, the *current* secret) in a documented-supported configuration. Probability is low (a millisecond-scale race requiring a concurrent password operation on the same project), which is why it is not rated Critical, but the loss is silent and irreversible.
- **Fix:** wrap the row-read, key-derivation, and credential write of `add_credential`/`replace_credential_value` in one `BEGIN IMMEDIATE` transaction, and re-read `wrapped_project_key` (re-checking the wrap hash) inside it immediately before encrypting; fail with `ProjectLocked`/retry if it changed.
- **Regression test:** two-connection harness — begin an add, commit a `set_project_password` on the same project from a second connection, complete the add, then assert the value still decrypts (currently it does not).

---

## Medium-severity findings (grouped; see the workflow journal for full per-finding detail)

**Concurrency & lifecycle**
- **CONC-01** *(CONFIRMED)* — the desktop holds one coarse `Mutex<VaultSlot>` across long synchronous network/git work; the UI and **"Lock now" are blocked for minutes**, and auto-lock is only evaluated at command entry. `main.rs:89-116,317-346`.
- **CONC-02** *(unverified; corrects an orchestrator claim)* — desktop auto-lock uses `std::time::Instant`, which does **not advance across system suspend** on the relevant platforms; the vault stays unlocked after a laptop sleep of any length. I had praised the monotonic clock as "immune to clock changes" — it is immune to wall-clock *changes* but not to *suspend*. `main.rs:95-113`.
- **CONC-04** *(CONFIRMED)* — backup is not transactional: per-table autocommit `SELECT`s can capture a cross-table-inconsistent vault (worst case, credentials whose project-key wrap is absent from the backup), and `verify` cannot detect it. `backup.rs:135-168`.
- **CONC-06** *(unverified)* — no timeout on any `git` subprocess; a hung git (repo on a dead network mount) blocks the monitor cycle and, on desktop, wedges every vault command including lock. `gitrepo.rs:21-36`.

**Rotation (unverified — the rotation verifier did not run; traces are detailed)**
- **ROT-002** — a second process observing `CREATING_IN_PROGRESS` can re-execute provider key creation → duplicate live keys, one unrecoverable.
- **ROT-003** — `rotation_cancel` can race an in-flight create and still replace the live value while reporting "cancelled before any change".
- **ROT-004** — `GRACE_PERIOD`/`OLD_DISABLED` destructive steps never re-verify the credential still holds the rotation's new version.
- **ROT-006** — rollback overwrites destinations with the plan's `from_version` even if the credential/destinations have since moved forward.
- **ROT-007** — manual destination steps are auto-skipped and counted as done; the rotation records "every destination step executed and verified" and proceeds to disable/revoke. Honesty/correctness.

**Destinations**
- **DEST-01** *(CONFIRMED)* — GitHub/AWS `exists()` conflate auth/transport/5xx with "secret absent", recording false `missing` drift. `destinations.rs:1575,1412`.
- **DEST-02** *(CONFIRMED)* — the Vercel adapter matches env vars **by key only, ignoring targets**; delete can remove a different same-key variable and `exists()` false-positives. Wrong-resource mutation. `destinations.rs:1644-1731`.
- **DEST-03** *(CONFIRMED)* — `destination_drift_check` silently skips attachments whose adapter it cannot build, re-presenting stale drift (possibly `in_sync`) as fresh. `vault.rs:6490`.

**Git scanning / hooks**
- **GScan-01** *(CONFIRMED)* — an installed hook is silently inert when `core.hooksPath` is set (husky, etc.), yet status reports `Installed`. `hooks.rs`.
- **GScan-02** *(CONFIRMED)* — force-chaining appends the scan block **after** the foreign hook; if that hook exits early or `exec`s, the scan never runs but is reported installed.
- **GScan-03 / CONC-05** *(CONFIRMED / unverified; = orchestrator M-5)* — history scanning buffers the entire `git log -p` output and all added lines with no size cap → unbounded memory on large/adversarial repos (on desktop, under the vault mutex).

**IPC / process**
- **IPC-01 / FS-09** *(CONFIRMED / unverified)* — `env_example_write` is an **arbitrary-path, arbitrary-content file overwrite** reachable over IPC, gated only by an unlocked vault (no path validation, no reauth). `main.rs:1409-1418`.
- **PI-01 / CLI-01** *(CONFIRMED)* — `api-tracker run` does not scrub `API_TRACKER_NEW_PASSWORD` from the injected child environment, leaking a master password to launched processes. `run_cmd.rs:88-101`.
- **PI-02** *(CONFIRMED; = orchestrator M-1)* — termination signals a PID recorded at spawn with no identity check; stale rows + PID reuse `SIGTERM` an unrelated same-user process. `inject.rs:271-300`.

**Business logic / observability (unverified — verifier did not run)**
- **OBS-002** — manual usage recording accepts negative token counts → negative estimated costs corrupt budget/alert accounting.
- **OBS-003** — an Anthropic bucket missing `starting_at` yields `window_start=""`, and the replace-range `DELETE` then **wipes the provider's entire synced usage history**. Data loss on a malformed provider response.
- **OBS-004** — a single unparseable provider-supplied `expires_at` breaks **every** credential listing (vault-wide feature DoS). `vault.rs:3372,1399`.

---

## Low & Informational findings (complete list, condensed)

All 40 Low and 27 Informational findings are enumerated in the audit scratch file `all_findings.tsv` and the workflow journal. The load-bearing ones:

- **NET-01** *(CONFIRMED; = orchestrator M-4)* — doc-watch URL validation permits loopback/link-local/metadata hosts (SSRF) and the doc comment misrepresents the behaviour; asymmetric with the strong `validate_webhook_url`. **NET-02** — webhooks still allow *https* to internal hosts (secret-free payload; defense-in-depth).
- **IPC-02** *(CONFIRMED; = orchestrator M-2)* — `credential_delete` is destructive with no reauth/confirmation enforced in Rust (the CLI path *does* confirm).
- **PI-05 / CONC-08** *(CONFIRMED / unverified; = orchestrator M-3)* — grant/session expiry trust wall-clock; a backward clock change re-activates expired grants and extends CLI sessions. **CONC-11 / PI-06** — the PID/kill-0 guard cluster.
- **CRYPTO-03** *(CONFIRMED)* — backup header KDF params are unauthenticated and uncapped; a crafted backup forces a huge Argon2 allocation on verify/restore (DoS). **CRYPTO-04/05** — a non-zeroized plaintext copy on the invalid-UTF-8 decrypt path; `key_wrap_mode`/project-KDF not bound into AAD (tamper→DoS, not disclosure).
- **DEST-04..10** — verified-when-`missing`, unvalidated secret-name in GitHub URL path, silent no-op on non-matching `--destination`, name-squatting half-configured destinations, understated AWS IAM/GitHub-scope docs, unimplemented AWS recovery-window restore path, manual steps auto-`skipped` while the plan reports `executed`.
- **GScan-04/05** — the pre-commit hook blocks only High-confidence findings (Supabase service-role, legacy OpenAI, Stripe test keys pass); trivial evasion gaps + fail-open hook are undocumented, so the scan is treated as a guarantee it is not.
- **CONC-07** — unbounded growth of `activity_events`, `audit_events`, resolved alerts, `notification_deliveries`, `rotation_events` (never pruned). **CONC-09/10/12** — non-atomic `session.json` rewrite, first-open migration race, non-transactional single-active-rotation check.
- **OBS-005** — `date_prefix()` byte-slices at index 10 and can panic on a multi-byte provider-controlled `window_start`. **OBS-008/011** — non-USD provider cost silently dropped from budget; imported non-USD pricing labelled USD. **OBS-013/012** — stale README/FEATURE_MATRIX claims (per-watch intervals, wrong line ranges).
- **CLI-04/05/06** — `--json` ignored by most mutating commands; sanitizer misses Unicode bidi/format chars; `run` uses `process::exit`, bypassing key zeroization on `Drop` (also **INFO-01**: a poisoned vault mutex bypasses zeroization).
- **NET-03 / OBS-015** — provider token counts summed with unchecked i64 (release profile has no overflow-checks); monetary amounts *are* guarded.
- **Orchestrator-only M-6** *(no workflow mandate covered CI)* — CI/release GitHub Actions are pinned to mutable tags (`@v4`, `@v2`, `@stable`) rather than commit SHAs; the release job holds `contents: write` + `GITHUB_TOKEN`. Positives: no `pull_request_target`, least-privilege defaults, draft+prerelease gate, fail-closed checksums.

### Two reviewer claims REFUTED by the verification pass (excluded)
- **CRYPTO-02** (live-value AAD omits `value_version` → surgical rollback) — refuted; retained versions bind the version and the live value is version-agnostic by design.
- **IPC-03** (mutex poisoning permanently disables all commands) — refuted as stated (tracked separately as INFO-01 for the zeroization-bypass aspect).

---

## Review ledger (proof of source coverage)

Every production source file was covered by at least one pass. Orchestrator personal reads are marked **[O]**; workflow mandate coverage is marked with the mandate key. Full `files_reviewed` lists per mandate are in the workflow journal.

| Area | Files | Coverage |
|---|---|---|
| Crypto/vault core | crypto, secret, error, clock, reuse, settings, model, session, backup | **[O]** + `crypto-vault` mandate (read-in-full per its coverage_notes) |
| Vault orchestration | vault.rs (8520 LOC) | **[O]** key/auth/reveal/replace/delete/rotation/env-export spans; `crypto-vault`+`rotation`+`concurrency-dos` mandates for the rest |
| Database/migrations | db, model, settings | **[O]** full read of db.rs (the `db-migration` reviewer aborted on the spend cap); model/settings via `crypto-vault` |
| Providers/network | http, connectors, openai, anthropic, providers, docwatch, notify | **[O]** http/docwatch/notify/pricing-money + `provider-net` mandate |
| Destinations | destinations, syncplan | **[O]** SigV4/honesty + `destinations` mandate |
| Rotation | rotation, syncplan | **[O]** full rotation.rs + advance/revoke/rollback glue; `rotation` mandate |
| Filesystem/env | envfile, envgov, stackdetect, gitrepo | **[O]** envfile/gitrepo/envgov-atomic + `fs-envfile` mandate |
| Process injection | inject, access | **[O]** inject.rs + `process-inject` mandate |
| Git scanning | scanner, hooks | **[O]** hooks.rs + scanner redaction; `git-scan` mandate |
| Business logic | usage, pricing, budget, status, alerts, permissions, activity, observe, monitor, audit, templates | **[O]** pricing/permissions + `business-docs` mandate |
| Desktop IPC + frontend | src-tauri/main.rs (136 cmds), api.ts, components/*.tsx, tauri.conf.json, capabilities | **[O]** state/reveal/copy/delete/reauth/CSP + `ipc-frontend` mandate |
| CLI | main, ctx, render, *_cmd | **[O]** key_cmd reveal + `cli` mandate |
| CI/release | .github/workflows/*.yml | **[O]** (no dedicated mandate) |

**Not conclusively verified:** (1) CRYPTO-01's live two-process reproduction (confirmed by trace + verifier, not by a running harness); (2) the rotation/concurrency/business-docs/fs-envfile findings whose *verifier* aborted on the spend cap (marked `unverified`); (3) exhaustive per-command reauth coverage across all 136 Tauri commands (core reauth wiring + reveal/copy/export/delete confirmed; remainder spot-checked); (4) Windows/Linux runtime behaviour of platform branches (reasoned from code + CI compile gates, not executed here); (5) live provider/destination behaviour (mocks only — see below).

**Live credentials/paid plans that would be required for further verification:** real OpenAI/Anthropic org-admin keys, a Stripe account, a Supabase org + management token, a GitHub PAT with `repo`+`workflow`, an AWS account (Secrets Manager, recovery-window behaviour), and a Vercel token — to confirm adapter semantics (esp. DEST-01/02, ROT-002 duplicate-key, OBS-003 replace-range) against real responses. `scripts/live_verify_*.sh` exist for opt-in use.

---

## Git status
- Branch `audit/deep-pressure-test` at `7d81090`; **no product source modified**; only `docs/audits/*` added. **Not merged. No release built or published.** Audit worktree left intact.
