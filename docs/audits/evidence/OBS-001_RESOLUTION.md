# OBS-001 — Resolution (Phase 5)

**Model:** Fable 5 (`claude-fable-5`). **Baseline:** `7d81090`.
**Verdict:** CONFIRMED — repository-exposure (`PossibleExposure`) alerts are silently auto-resolved when the scanner stops re-reporting the finding, with no tie to actual remediation. Evidence class: rigorous control-flow proof from source (the resolution and skip paths are literal/unconditional; deterministic by inspection). Executable double-monitor-run reproduction listed as a recommended regression test.

## Mechanism (`crates/core/src/vault.rs`, `alerts.rs`, `monitor.rs` @ 7d81090)

`run_monitor` accumulates the dedup keys of all alerts raised *this run* into `active_keys`, then at the end:
```
vault.rs:2112  auto_resolve_stale(conn, &managed, &active_keys)
```
`managed` includes `monitor::managed_credential_kinds()`, which contains **`AlertKind::PossibleExposure`** (monitor.rs:146).

`auto_resolve_stale` (alerts.rs:232-270):
```
SELECT id, dedup_key FROM alerts WHERE resolved_at IS NULL AND kind IN (managed...)
for (id,key): if !active_keys.contains(&key) { UPDATE alerts SET resolved_at = now }   // silent, unconditional
```
It resolves purely on "was this key regenerated this run?" — **no check that the exposure was rotated/revoked/scrubbed**, no audit of *why*, no notification.

The repo-scan exposure alert (vault.rs:2049-2079) has key `repo_scan_findings:{repo_path}:{head_commit}` and is added to `active_keys` **only if** `report.findings > 0` this run. Findings come from `scan_repos_incremental` (vault.rs:5093-…), which is INCREMENTAL and short-circuits:
```
5107  if !repo.exists() { continue }                       // repo unavailable -> no report
5110  let Ok(head) = head_commit(repo) else { continue }    // git failure / no commits -> no report
5123  Some(last) if last == head => continue                // nothing new -> no report
5121-5122 None => 0 (baseline only)                        // first sight -> baseline, no scan
```
Only genuinely NEW commits (`last..head`) are scanned; an already-scanned finding is never re-reported.

## Confirmed sub-cases (Phase 5 checklist)
- **No change at all:** run 1 finds a secret at head H → alert `repo_scan_findings:repo:H`, `last_scanned=H`. Run 2: `last==head` → `continue` → key not in `active_keys` → **alert auto-resolved**. The exposure alert lives exactly ONE cycle even with zero remediation. ✔
- **Secret removed from file without rotation / full-history finding absent from a working-tree scan:** the secret stays in the OLD commit's history; the new head's incremental scan reports 0 → old-head alert auto-resolves; credential never rotated. ✔
- **Repo unavailable / file deleted / repo unregistered:** `!repo.exists()` → skipped → no report → alert auto-resolved. Making the repo disappear "clears" the exposure signal. ✔
- **Git command failure / partial scan / history rewritten:** `range_added_units` err → re-baseline (advances `last_scanned` past the UNREAD range — those commits are never scanned) and raises a transient `repo_rebaselined:{path}:{head}` `PossibleExposure` (Medium, vault.rs:5135-5153) which itself auto-resolves next cycle. Silent coverage gap. ✔
- **Suppression / credential deleted-rotated-revoked / DB restore / migration:** all change whether the finding is re-produced, not whether the exposure is real — same auto-resolve path.

## Documentation vs behavior
The alert's `recommended_action` is "inspect the findings; rotate anything real and scrub history" (2069-2071) — i.e. resolution *should* follow rotation/scrub. But the CODE resolves the alert based on the scanner not re-reporting, **decoupled from any remediation**. There is no documented rule stating "an exposure alert resolves only when X"; the effective rule is "resolves next cycle unless the exact same finding at the exact same head is re-detected." This is precisely the Phase 5 anti-pattern: *a missing scanner finding is treated as the credential having become safe.*

## Final finding record
- **ID:** OBS-001.
- **Title:** Repository `PossibleExposure` alerts silently auto-resolve when the incremental scan stops re-reporting the finding (unchanged repo, secret only in older history, repo unavailable, or unreadable range) — with no link to rotation/revocation/scrub, creating false assurance that a possibly-leaked credential is safe.
- **Category:** Security observability / correctness (alert lifecycle) in a security tool.
- **Severity:** Medium (original evidence: High). Impact: High for the tool's core promise (surfacing leaked secrets) — an exposure signal disappears on its own, and can be "cleared" by removing the file or unmounting the repo. Likelihood: Certain to occur (the one-cycle lifetime is structural). Mitigants keeping it below the top tier: local-first single-user; the alert IS shown at least once; the on-demand `api-tracker scan` still finds the secret; findings are labeled best-effort. High is defensible for a security product.
- **Confidence:** High.
- **Affected symbols:** `run_monitor` (vault.rs:2036-2120), `scan_repos_incremental` (vault.rs:5093-…, skip paths 5107/5110/5123), `alerts::auto_resolve_stale` (alerts.rs:232-270), `monitor::managed_credential_kinds` (monitor.rs:140-150).
- **Expected:** an exposure alert stays open until an explicit, documented remediation rule is satisfied (credential rotated/revoked AND/OR history scrubbed AND re-scan clean), or is downgraded to "unverified/coverage-gap" — never silently resolved because the finding was not re-emitted.
- **Actual:** resolved next cycle whenever the finding isn't re-emitted, including when the repo is simply skipped.
- **Existing defenses:** the alert is created and shown once; `evidence`/`recommended_action` are honest; on-demand `scan` unaffected.
- **Recommended remediation (design only — NOT implemented):** (1) exclude `PossibleExposure` (repo-scan and per-credential) from `auto_resolve_stale`, or gate its resolution on an explicit remediation event (rotation/revocation recorded, or a fresh full-history scan returning clean for the same secret fingerprint); (2) when a registered repo is skipped (missing/unreadable/unchanged), do NOT drop its standing exposure alerts — carry them forward or mark "coverage gap: not re-verified"; (3) make the exposure dedup_key independent of `head_commit` (e.g., keyed by detected-secret fingerprint + repo) so a persistent secret keeps one stable, non-self-resolving alert; (4) record an audit/notification when a security alert is auto-resolved, with the reason.
- **Regression test (gap):** register a repo, commit a fake secret, run `run_monitor` twice → assert the `PossibleExposure` alert is still open on the second run (and only resolves after a modeled remediation).
- **Verification provenance:** Fable 5 primary review — control-flow proof from source; deterministic by inspection.
- **Related:** OBS-006 (first-connect alert flood), GScan-05 (undocumented detection-evasion gaps), CONC-07 (unbounded alert table growth).
