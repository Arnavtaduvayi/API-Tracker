# Continuation Prompt — Independent Fable-Only Full Re-Audit of API Tracker

Paste the block below as the opening prompt of the next session. It is deliberately self-contained.

---

You are performing a **complete, independent, Fable-only security re-audit** of API Tracker. A prior audit was interrupted by a usage limit and produced a *mixed-confidence* finding set (46 verified, ~48 unverified). Your job is to redo the **audit** — not the product — to a durable, fully-verified standard.

## Model & provenance (do this first, every session)
1. Report the exact active model, effort, and thinking config.
2. Proceed **only** as **Fable 5 (`claude-fable-5`)** at the strongest available effort. **No silent fallback** to any other model. If Fable is unavailable or the usage budget cannot cover a durable first checkpoint, **stop and say so** before starting.
3. Re-assert this at the top of every resumed session and before any multi-agent fan-out.

## Immutable target
- Audit commit **`7d81090a1068476291546963e68ca8c7de1a7145`** only. Verify `git rev-parse HEAD` before touching anything.
- Work in the pristine worktree `/Users/arnavtaduvayi/Documents/GitHub/API-Tracker-fable-reaudit` (branch `audit/fable-independent-reaudit`). Confirm it is clean and contains **no** `docs/audits/` before you begin.
- **Do not modify production code. Do not fix, refactor, or change schemas/migrations. Do not merge or push. No product remediation. Ever, during the audit.**

## Blind-review discipline (mandatory)
- **Do the first full pass blind.** Do **not** open the prior audit's conclusions (`../API-Tracker-deep-audit/docs/audits/DEEP_TECHNICAL_AUDIT.md`, `evidence/all_findings.tsv`, `MY_FINDINGS.md`, etc.) until you have independently produced your own line-by-line ledger and your own candidate findings.
- Only **after** your blind pass, open the prior leads and perform **mandatory re-verification of every prior finding** (all 96, across CONFIRMED / REFUTED / unverified) against the actual code. Record agree / disagree / cannot-reproduce with evidence for each. Treat prior CONFIRMED findings as unproven until you re-confirm them.

## Coverage the re-audit MUST achieve
Produce a **complete line-by-line production-source review ledger** — one row per production file (`crates/core/src/*`, `apps/cli/src/*`, `apps/desktop/src-tauri/src/*`, `apps/desktop/src/**`), with purpose, security relevance, reviewed-Y/N, tests covering it, uncovered paths, and findings. "Reviewed" means read in full, not sampled.

Full-depth review of every area (no sampling):
- **Cryptography & vault** — Argon2id params, salt/nonce, AEAD AAD across *every* call site, key hierarchy/separation, project-key wrap/rewrap, master/project password change/remove, zeroization (incl. error paths), session split-token, auto-lock, downgrade/future-version refusal, timing.
- **Database, migrations & backup/restore** — every table/index/constraint/trigger, all 10 migrations (idempotent/interrupted/re-entrant), backup atomicity/consistency, force-restore collision, format-version AAD, WAL/secure_delete residue.
- **Tauri IPC** — inventory and audit **all 136 commands**: input/path validation, vault authz, **reauth enforced in Rust** (not React), output/error redaction, direct-IPC-bypass, CSP/allowlist/opener/capabilities, arbitrary-file-write primitives.
- **CLI** — every command/flag/exit-code; secret leakage via args/stdout/stderr/JSON/panic/logs; reauth/confirmation gating; ANSI/terminal-escape injection.
- **Filesystem & `.env`** — path handling (traversal/symlink/junction/UNC/case/unicode/non-UTF8), TOCTOU, atomic-write/cross-device/disk-full/crash, `.env` parsing (never executes shell), plaintext-export labeling, `.gitignore` drift.
- **Process injection & temporary access** — child-env construction & leakage (incl. `API_TRACKER_NEW_PASSWORD`), grant enforcement, PID reuse/identity/`pid<=0`, descendant termination, clock/expiry, orphan cleanup, "local expiry ≠ provider revocation" honesty.
- **Git scanning & hooks** — detection/redaction/suppression, resource bounds on adversarial repos (history buffering), `core.hooksPath`/husky inertness, force-chain ordering, fail-open, evasion gaps, over-promise.
- **Providers** (OpenAI, Anthropic, GitHub, Stripe, Supabase) — auth headers, redirect/SSRF, host validation, timeouts, size/pagination bounds, malformed/oversized JSON, 404/wrong-resource ambiguity, replace-range wipes.
- **Destinations** (local, `.env`, keychains, AWS Secrets Manager, GitHub Actions, Vercel) — auth, **capability honesty** (existence-vs-value verification), CRUD/verify/delete semantics, wrong/stale/target-mismatched resources, SigV4, recovery-window, drift-skip.
- **Rotation state machine** — every state and transition; interruption after each; idempotency; verify-before-disable-before-revoke; 404-masquerade; wedge/no-exit conditions; rollback-overwrites-newer; concurrent-plan conflicts.
- **Alerts, monitoring & notifications** — rule inputs/thresholds/dedup/**auto-resolve** (exposure alerts must not silently self-resolve), floods on import/upgrade/restore, webhook SSRF/redaction.
- **Pricing, usage, budget & templates** — reported-vs-estimated never combined, effective-dating, currency, numeric boundaries (negative/overflow/NaN/inf), template safety, stack-detection bounds.
- **Supply chain** — Rust+Node deps, lockfiles, proc-macros, GitHub Actions pinning (SHA vs mutable tag), workflow permissions, release/draft/checksum flow, `cargo audit`/`npm audit`.
- **Cross-platform** — inspect every `cfg`/platform branch; reason explicitly about Windows/Linux/macOS (paths, ACLs, keychains, signals, process trees, hooks, suspend-vs-monotonic-clock auto-lock).

## Evidence & rigor requirements
- **Concurrency testing:** build real two-process/two-connection harnesses (desktop+CLI on one vault) for the rotation-vs-write, password-change-vs-write, backup-consistency, and migration-race classes. Reproduce data-loss and false-success claims, don't just trace them.
- **Fuzzing / property tests:** the `.env` parser, pricing importer, provider-response parsers, backup parser, URL/webhook validators, git-log parser, CLI/IPC payloads. Record seed, duration, cases, crashes, corpus, repro commands.
- **Failure injection:** lost/duplicated HTTP responses, crash-after-write-before-state, disk-full, read-only FS, hung `git`, clock jumps/suspend.
- **Every finding** carries: id, title, severity, confidence, affected files/symbols/lines, preconditions, failure/attack scenario, user/security/data-loss impact, **reproduction**, existing defenses, why-insufficient, remediation, required regression test. Use only **synthetic** secrets, mocks, and disposable local resources — never real credentials or real provider calls.
- **Dual-Fable verification of every Critical or High finding:** two independent Fable verifications that each begin from the code and try to refute; a High stands only if both agree. Re-verify every prior mixed-agent finding likewise.

## Durability (because the last run was cut off)
- Bound any multi-agent fan-out; do **not** spawn an unbounded number of agents. Prefer smaller waves with **durable checkpoints written to disk after each phase** (ledger rows, per-area findings, verifier verdicts) so an interruption never loses more than one wave.
- Before any context/usage limit, write a `CONTINUATION.md` checkpoint (what's done, what's pending, next wave) to the audit branch.

## Deliverables (all required, on an audit-only branch — never on `main`)
`DEEP_TECHNICAL_AUDIT.md`, `SOURCE_REVIEW_LEDGER.md` (per-file), `FINDINGS_INDEX.md`, `THREAT_MODEL_DELTA.md`, `TEST_COVERAGE_GAPS.md`, `REMEDIATION_PLAN.md` (prioritized, with complexity + regression tests), `MANUAL_SECURITY_TESTS.md`, and a `PRIOR_FINDINGS_REVERIFICATION.md` mapping each of the 96 prior leads to your independent verdict.

## Completion gate
Do not conclude until: every production file is in the ledger; every migration/CLI-command/Tauri-command/provider/destination/rotation-transition is covered; every prior finding is re-verified; every Critical/High is dual-Fable-verified; every data-loss and secret-exposure claim is reproduced or rigorously proved; all deliverables exist and are untruncated; and no verifier category is left unfinished. Leave the worktree intact; modify/merge/publish nothing.
