# PR #13 — Independent Re-Audit (§13)

An independent adversarial re-audit was run from a **fresh git worktree**
(`audit/runtime-observability-reaudit` at
`API-Tracker-observability-reaudit`, checked out at the remediated HEAD
`ce973c1`), by agents that did NOT perform the remediation. Their mandate: for
each area, independently trace the remediated code and verify every claimed fix
actually holds, and hunt for regressions the remediation introduced — trusting
the code, not the commit messages. Every candidate finding was then
adversarially re-verified (default: refuted unless a file+line proves it).

## Outcome

**Verdict: PASS WITH REQUIRED CHANGES** (1 blocking item), now fully addressed
in commit `84514ef`.

- **All code fixes hold.** Every claimed fix across all six areas was
  independently traced and confirmed present and correct.
- **Zero confirmed high/critical findings. Zero consequential code
  regressions.** The single introduced code defect was LOW (below).
- The one area with `fixesHold=false` (ca-vault-lock-session) failed **solely
  on a documentation residual**, not a broken code fix: the code correctly does
  NOT implement vault-lock teardown (that is the honest, documented behaviour),
  but one doc (manual test plan OBS-16) still made the false claim.

## Confirmed findings and their resolution (all fixed in `84514ef`)

| Sev | Finding | Resolution |
|---|---|---|
| MED (blocking) | MANUAL_OBSERVABILITY_TEST_PLAN OBS-16 still claimed a vault lock tears down interception / "decryption cannot continue" | Rewrote OBS-16 to test the honest behaviour (a lock does NOT interrupt a running run; session finalizes `completed`). |
| MED | Privacy model §6 named nonexistent `crates/observe/tests/privacy_no_leak.rs` and overclaimed its scope (DB bytes/stderr/DTOs/…) | Point to the real `proxy_integration.rs` canary and describe its actual (metadata-only) scope; note the structural guarantee. |
| MED | Docs (compat matrix, user guide, architecture) named nonexistent CLI `observe doctor` | Corrected to `observe diagnostics` (the real subcommand emitting the proxy warning). |
| LOW (regression, introduced) | Linux `pid_is_definitely_gone` treated missing `/proc/<pid>` as authoritative even when `/proc` is unmounted → could wrongly close live sessions in a `/proc`-less container | Gate on `/proc/self`; else fall back to `ps` (`pid_gone_via_ps`). |
| LOW | Privacy model §3.3 table documented the pre-remediation `is_high_entropy` rule | Updated to the current stricter rule. |
| LOW | DEVELOPER_GUIDE named a nonexistent `on_lock()` lifecycle hook | Corrected the lifecycle description. |
| LOW | Manual test plan step ran nonexistent `observe export` | Replaced with `observe show --json`. |
| INFO | `runtime_alert_baselines` still listed as schema in IMPLEMENTATION_PLAN | Marked planned/not-implemented. |
| INFO | NAT64 local-use prefix `64:ff9b:1::/48` (RFC 8215) not decoded | Broadened classifier to the whole `64:ff9b::/32`; test added. |

Additional same-class references the re-audit did not individually enumerate
(other `privacy_no_leak.rs` / `tls_*.rs` mentions in the plan/data docs) were
also corrected for consistency.

## Findings the re-audit REFUTED (verifier disagreed with the finder)

- "Privacy model §5 P9 property test not implemented" → **refuted**: P9 is
  asserted by `sanitize.rs::worked_examples_from_the_privacy_model`.

## Note on scope discipline

The re-audit confirmed the NAT64 local-use gap and the pre-existing `inject.rs`
`ps` probes are **not regressions** introduced by the remediation, consistent
with the remediation's decision to scope `inject.rs` out (it is not in this
branch's diff) and to target the dominant NAT64 well-known prefix. The one
genuinely introduced defect (Linux `/proc` liveness) was found and fixed.

See `PR13_FINAL_VERDICT.md` for the final verdict statement.
