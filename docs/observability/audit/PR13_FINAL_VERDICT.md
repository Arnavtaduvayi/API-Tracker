# PR #13 — Final Verdict

## Verdict: PASS

The runtime API observability change set (PR #13), after remediation of the
13-agent adversarial audit and the independent §13 re-audit, is in a genuinely
reviewable state and passes.

### Basis

1. **CI is green** on the remediated branch across all four jobs: Rust (core +
   CLI) on Linux, Rust core on Windows, Desktop backend on macOS, Desktop
   frontend. Not merely made-green — the two original CI failures were fixed at
   root cause (`cfacc81` dead-code cfg, `69fc886` Windows time-race) and every
   subsequent commit kept it green.

2. **Every confirmed audit finding is resolved.** All HIGH/CRITICAL findings are
   fixed at root cause with regression tests (see `PR13_FINDINGS_INDEX.md`).
   Confirmed MEDIUM/LOW findings are fixed or, where a full feature is out of
   scope for a draft, corrected to be honest (docs match the code). Accepted
   residuals are documented with rationale and are non-exploitable in the
   default posture (`PR13_REMEDIATION_PLAN.md`).

3. **The independent re-audit (§13) confirmed the code fixes hold** — zero
   high/critical, zero consequential regressions — and its PASS-WITH-REQUIRED-
   CHANGES items (documentation-honesty residuals + one LOW `/proc` regression)
   are all addressed (`PR13_FINAL_REAUDIT.md`).

4. **No security control was weakened to pass.** SSRF was tightened; upstream
   TLS verification is unchanged and now guarded by
   `no_insecure_verifier.rs`; the metadata-only type boundary is intact and
   reinforced (cert-bound CA AAD, argv redaction, redacting `Debug`s); no test
   was disabled, no CI job removed, no clippy weakened.

### Required before PUBLIC release (not blockers for this draft)

These are documented, honestly-disclosed follow-ups, not defects hidden behind
a green dashboard:

- **Vault-lock / auto-lock interruption of a live `run --observe`** (THREAT_MODEL
  RO-13). The CA signing key currently stays in the run process for the child's
  lifetime regardless of a lock. Implement an `on_lock`/expiry hook that shuts
  the proxy, drops the CA, and interrupts the session (`vault_locked`).
- **Automated per-runtime interception integration tests**, a negative
  upstream-TLS test, and extending the canary to raw DB/stderr/temp-file bytes
  (`PR13_TEST_COVERAGE_GAPS.md`).
- **Desktop end-to-end / packaged-app runs** and broader manual passes.

### Classification

**Experimental / internal-alpha — public-blocked**, unchanged in direction: the
correctness and security bugs that made the first cut unsafe are fixed and
regression-tested; the remaining public-release blockers are enumerated above
and in the docs, not obscured.

### Action

PR #13 is marked **ready for review** (not merged). It must NOT be merged until
the public-release follow-ups above are addressed or explicitly accepted by a
maintainer.

---

## Addendum — 2026-07-24: vault-lock follow-up now implemented

The first "Required before PUBLIC release" item above (vault-lock / auto-lock
interruption of a live `run --observe`, RO-13) has since been **implemented and
regression-tested**, not merely documented. See `PR13_VAULT_LOCK_COMPLETION.md`,
`PR13_VAULT_LOCK_REAUDIT.md`, and `PR13_VAULT_LOCK_FINAL_VERDICT.md` for the
design, independent re-audit, and verdict. The remaining public-release
follow-ups (automated per-runtime interception integration tests; a negative
upstream-TLS test; extending the canary to raw DB/stderr/temp-file bytes —
partially addressed by the new `raw_database_and_wal_never_contain_*` core test;
desktop end-to-end packaged runs) still stand.
