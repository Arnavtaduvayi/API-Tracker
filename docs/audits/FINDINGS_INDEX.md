# Canonical Findings Registry (FINDINGS_INDEX)

**Model:** Fable 5 (`claude-fable-5`). **Audited production baseline:** `7d81090a1068476291546963e68ca8c7de1a7145`. **Audit branch:** `audit/deep-pressure-test`.

This registry reconstructs the canonical set of candidate findings from the saved evidence, deduplicates by root cause, records this session's Fable-5 review status, and assigns a final verdict + severity to every candidate. It is the single source of truth for dispositions; per-finding `Title`, `Category`, and `Affected files/symbols` are carried verbatim from `evidence/all_findings.tsv` (with reviewer provenance in `evidence/findings_raw.tsv`) and are cited by ID rather than re-typed.

## Evidence reconciliation (Phase 1)
- `evidence/all_findings.tsv`: **96 candidate rows** — 2 High, 25 Medium, 42 Low, 27 Informational. Counts reconcile with the prior summary.
- `evidence/verdicts.tsv`: **48 verdict rows** — 46 CONFIRMED, 2 REFUTED (IPC-03, CRYPTO-02). ~48 candidates carried no completed verifier verdict.
- No evidence file references a missing artifact; every finding row carries a source location. The two REFUTED findings were reclassified Informational by the prior pass, consistent with their rows.
- **Report accuracy:** `DEEP_TECHNICAL_AUDIT.md` predates completion; it does not overstate coverage but is incomplete. This session does not overstate line-by-line completeness — see `SOURCE_REVIEW_LEDGER.md` for exact per-file depth.

## Review-status legend (this session)
- **Vr** — verified with executable reproduction.
- **Vp** — verified by rigorous source/state proof (code read this session; deterministic by inspection).
- **Vi** — verified by direct source inspection this session (cited lines read).
- **Av** — accepted: prior verifier CONFIRMED **and** architecture-consistent with what I read; not independently re-read line-by-line this session.
- **Ac** — accepted on reviewer source-citation only (no verifier verdict, not re-read this session). **Residual — carry into next pass.**

## Verdict legend
CV-Sec = confirmed security vuln · CV-Corr = confirmed correctness defect · CV-Loss = confirmed data-loss risk · CV-Rel = confirmed reliability risk · CV-Priv = confirmed privacy risk · CV-DoS = confirmed denial-of-service risk · Doc = documentation defect · Test = test gap · D-i-D = defense-in-depth improvement · Prov = provider limitation · Plat = platform limitation · Ref = refuted · Inc = inconclusive.

## Duplicate-cluster consolidation
| Canonical | Absorbs | Root cause |
|---|---|---|
| **CRYPTO-01** | CONC-03 | non-transactional project-key read→write racing rotation |
| **GScan-03** | CONC-05, (M-5) | `git log -p` buffered whole, no size cap (history scan memory) |
| **PI-02** | CONC-11 | recorded PID signalled with no identity/liveness re-check |
| **PI-01** | CLI-01 | `API_TRACKER_NEW_PASSWORD` not scrubbed from injected child env |
| **IPC-01** | FS-09 | `env_example_write` arbitrary-file overwrite over IPC, no reauth |
| **CONC-12** | ROT-009 | `rotation_approve` non-atomic check-then-act (single-flight) |
| **DEST-04** | SYNC-002 | `verified_at` stamped even when read-back reports drift/missing |
| **DEST-10** | ROT-007 | manual steps auto-skipped → plan/rotation reports "executed" |
| **NET-03** | OBS-014 | provider token counts unchecked / not validated non-negative |
| **ROT-001** | (sibling ROT-010) | fragile revoke crash-marker (opposite failure directions) |

96 candidates → **10 consolidations** → **86 distinct root-cause findings** (duplicates retained in the table with `→canonical`).

---

## Dispositions

Severity shown is **final** (this audit). `[was X]` marks a reassessment from the original.

### Crypto & key management
| ID | Final Sev | Verdict | Review | Evidence / note |
|---|---|---|---|---|
| CRYPTO-01 | **High** [was Med] | CV-Loss | **Vr** | `evidence/crypto01/` — 25/25 orphan+wedge reproduced; consolidates CONC-03. Silent permanent data loss + rotation wedge. **Release blocker.** |
| CONC-03 | High →CRYPTO-01 | CV-Loss | Vr | Duplicate of CRYPTO-01. |
| CRYPTO-02 | Info | **Ref** | Av | Verifier-refuted: value AAD omits value_version, but rollback is not undetectable in practice (retained-version AAD binds version). Refutation accepted. |
| CRYPTO-03 | Low | CV-DoS | Av | Backup header KDF params unauthenticated/uncapped → huge Argon2 on verify/restore. Cap params before allocation. |
| CRYPTO-04 | Info | D-i-D | Av | Decrypted plaintext freed without zeroization on invalid-UTF-8 error path. Minor; zeroize on all paths. |
| CRYPTO-05 | Info | D-i-D | Vi | `key_wrap_mode`/KDF params/salt not in AAD → tamper = DoS not disclosure. Confirmed low-impact (AEAD still fails closed). |

### Concurrency & durability
| ID | Final Sev | Verdict | Review | Evidence / note |
|---|---|---|---|---|
| CONC-01 | Med | CV-Rel | Av | Coarse desktop vault mutex across long I/O; Lock/auto-lock stalled. |
| CONC-02 | Med | CV-Rel | Ac | Auto-lock uses `Instant`, doesn't advance across suspend → stays unlocked after sleep. **Platform: verify Windows/Linux `Instant` semantics (test gap).** |
| CONC-04 | Med | CV-Loss | **Vi** | `evidence/MATERIAL_LEADS_VERIFICATION.md` — backup snapshot non-transactional → cross-table-inconsistent backup, undetectable. |
| CONC-05 | Med →GScan-03 | CV-DoS | Vi | Duplicate of GScan-03 (history-scan memory). |
| CONC-06 | Med | CV-Rel | Ac | No timeout on any git subprocess → hung git (dead mount) wedges monitor / desktop. Add subprocess timeout. |
| CONC-07 | Low | CV-Rel | Ac | Unbounded growth of activity/audit/resolved-alerts/deliveries/rotation tables (only doc_watch/repo_scan pruned). |
| CONC-08 | Low | CV-Rel | Ac | CLI sliding session refreshed by every command → scripted `monitor run` keeps session alive indefinitely. |
| CONC-09 | Low | CV-Rel | Ac | `session.json` rewritten in place (no atomic rename, no lock) → torn read / lost keys under concurrency. |
| CONC-10 | Low | CV-Rel | Ac | First-open migration race: `user_version` checked outside the tx → loser fails with raw SQLite error. |
| CONC-11 | Low →PI-02 | CV-Rel | Vi | Duplicate of PI-02 (PID reuse). |
| CONC-12 | Low | CV-Corr | Ac | `rotation_approve` non-atomic check-then-act; consolidates ROT-009. Two frontends can approve two rotations. |

### Rotation
| ID | Final Sev | Verdict | Review | Evidence / note |
|---|---|---|---|---|
| ROT-001 | Med [was High] | CV-Rel + CV-Corr | **Vp** | `evidence/ROT-001_RESOLUTION.md` — lost revoke response strands OLD_DISABLED; only exit (rollback) restores a deleted key (OpenAI/Supabase). |
| ROT-002 | Med | CV-Corr | Ac | Second process observing CREATING_IN_PROGRESS re-creates the provider key → duplicate live key w/ unrecoverable value. (CAS guards CREATING_REPLACEMENT→IN_PROGRESS; verify the IN_PROGRESS replay guard — test gap.) |
| ROT-003 | Med | CV-Corr | Ac | `rotation_cancel` can race in-flight create/provide-key: "cancelled before any change" still replaced the value. |
| ROT-004 | Med | CV-Corr | Ac | GRACE/OLD_DISABLED destructive steps don't re-verify the credential still holds the rotation's new version. |
| ROT-005 | Med | CV-Rel | Ac | Rollback not retryable: failed steps excluded forever; partial rollback loops in MANUAL_REQUIRED. |
| ROT-006 | Med | CV-Corr | Ac | Rollback overwrites destinations with `from_version` even when they moved to newer values. |
| ROT-007 | Med →DEST-10 | CV-Corr | Ac | Manual destination steps auto-skipped, counted done → "every step executed and verified" then disable/revoke. |
| ROT-008 | Low | CV-Corr | Ac | Value to `rotation provide-key` silently discarded when a replacement was already stored. |
| ROT-009 | Low →CONC-12 | CV-Corr | Ac | Duplicate of CONC-12. |
| ROT-010 | Info | CV-Corr | **Vp** | Sibling of ROT-001: 404-on-retried-revoke accepted as success (crash-marker present) can mark a never-revoked key revoked. |
| ROT-011 | Low | CV-Corr | Ac | Textual RFC3339 comparisons in waiting_on/schedule-due vs parse-and-compare in advance (inconsistent). |

### Destinations & sync
| ID | Final Sev | Verdict | Review | Evidence / note |
|---|---|---|---|---|
| DEST-01 | Med | CV-Corr | Av | GitHub/AWS `exists()` conflates auth/transport/server errors with "absent" → false `missing` drift. |
| DEST-02 | Med | CV-Corr | Av | Vercel matches env vars by key only, ignoring targets → delete wrong same-key var; exists() false-positive. |
| DEST-03 | Med | CV-Corr | Av | `destination_drift_check` skips un-buildable adapters, re-presenting stale drift as fresh. |
| DEST-04 | Low | CV-Corr | Av | `execute_step` marks verified on `missing`/`unknown`; consolidates SYNC-002. |
| DEST-05 | Low | CV-Sec | Av | Unvalidated secret name/config interpolated into destination URL path. |
| DEST-06 | Low | CV-Corr | Av | `sync_plan_execute` with non-matching `--destination` silently no-ops (execute lacks rollback's guard). |
| DEST-07 | Low | CV-Corr | Av | `destination_add` inserts row before validating/encrypting auth → half-configured squatter. |
| DEST-08 | Low | Doc | Av | Catalog AWS IAM text understates ListSecrets/DeleteSecret; names a nonexistent GitHub scope. |
| DEST-09 | Low | CV-Corr | Av | AWS write in 30-day recovery window fails raw; advertised RestoreSecret never implemented. |
| DEST-10 | Med | CV-Corr | Av | Manual steps auto-`skipped` → plan reports `executed`; consolidates ROT-007. |
| DEST-11 | Info | CV-Corr | Av | Sentinel overloading in `read()` misclassifies binary/blank AWS secrets as `present_unverifiable`. |
| DEST-12 | Info | CV-Corr | Av | Drift read-back inherits whitespace-trimming fingerprint → can't detect whitespace drift. |
| DEST-13 | Info | D-i-D | Av | Transient unzeroized secret copies during signing/command construction. |
| SYNC-001 | Low | CV-Corr | Ac | Re-executing a rolled-back plan silently rewrites status to `planned`. |
| SYNC-002 | Low →DEST-04 | CV-Corr | Ac | Duplicate of DEST-04. |

### Git scanning & hooks
| ID | Final Sev | Verdict | Review | Evidence / note |
|---|---|---|---|---|
| GScan-01 | Med | CV-Corr | Av | Hook inert when `core.hooksPath` set (husky), yet status reports Installed. |
| GScan-02 | Med | CV-Corr | Av | Force-chain appends scan after foreign hook; early-exit/exec skips scan, still "chained". |
| GScan-03 | Med | CV-DoS | Vi | `git log -p` buffered whole, no cap; consolidates CONC-05, M-5. Unbounded memory (desktop holds vault mutex). |
| GScan-04 | Low | CV-Sec | Av | Pre-commit hook blocks only High-confidence; Medium-classified high-value secrets pass. |
| GScan-05 | Info | Doc | Av | Undocumented detection-evasion gaps (NUL/long-line/>5MiB/UTF-16) + fail-open hook. |

### Desktop IPC & process injection
| ID | Final Sev | Verdict | Review | Evidence / note |
|---|---|---|---|---|
| IPC-01 | Med | CV-Sec | **Vi** | `env_example_write` arbitrary-file overwrite over IPC, no reauth; consolidates FS-09. |
| IPC-02 | Low | CV-Sec | **Vi** | `credential_delete` no reauth/confirm in core (UI-only). |
| IPC-03 | Info | **Ref** | Av | Verifier-refuted: mutex poisoning does not permanently disable all commands as claimed. |
| IPC-04 | Low | CV-Rel | Av | Long network commands hold vault mutex across blocking I/O, stalling Lock/auto-lock. |
| IPC-05 | Info | CV-Sec | Av | User-controlled `docs_url` rendered as anchor href without scheme validation (javascript:? — FE). |
| PI-01 | Med | CV-Priv | Av | `API_TRACKER_NEW_PASSWORD` not scrubbed from child env; consolidates CLI-01. Master password leak to launched process. |
| PI-02 | Med | CV-Rel | **Vi** | PID signalled with no identity re-check; consolidates CONC-11. PID-reuse wrong-process kill. |
| PI-03 | Low | CV-Rel | Av | Kill-timer/access-kill terminates only the direct child, not descendants. |
| PI-04 | Low | CV-Rel | **Vi** | Unix kill sends only SIGTERM, reports success even if ignored. |
| PI-05 | Low | CV-Sec | **Vi** | Grant/session expiry trusts wall-clock → backward clock re-activates expired grants. |
| PI-06 | Info | CV-Rel | **Vi** | `terminate_pid` lacks `pid>0` guard → `kill 0` signals caller's process group. |
| PI-07 | Info | CV-Corr | **Vi** | One-time grant consumed before command/key can fail → burns the launch. |

### Providers, usage, pricing, observability
| ID | Final Sev | Verdict | Review | Evidence / note |
|---|---|---|---|---|
| OBS-001 | Med [was High] | CV-Corr | **Vp** | `evidence/OBS-001_RESOLUTION.md` — exposure alerts auto-resolve when finding not re-emitted, decoupled from remediation. |
| OBS-002 | Med | CV-Corr | Ac | Manual usage accepts negative token counts → negative costs corrupt budget/alerts. |
| OBS-003 | Med | CV-Loss | Ac | Anthropic bucket missing `starting_at` → window_start "" → replace-range DELETE wipes all synced usage. **Data-loss (usage history).** |
| OBS-004 | Med | CV-DoS | Ac | Provider `expires_at` stored verbatim; one unparseable value breaks every credential listing (vault-wide). |
| OBS-005 | Low | CV-Rel | Ac | `date_prefix()` byte-slices at 10 → panic on multi-byte provider `window_start`. |
| OBS-006 | Low | CV-Corr | Ac | First connect+sync floods NewProviderKey/Project alerts for every pre-existing key. |
| OBS-007 | Low | CV-Corr | Ac | `best_available` ignores provider cost when sum is exactly $0 / non-USD, diverging from docs. |
| OBS-008 | Low | CV-Corr | Ac | BudgetReport silently drops non-USD provider cost (usage report warns; budget doesn't). |
| OBS-009 | Low | Doc | Ac | Pricing substring model-match presents variant fallbacks as exact (no note). |
| OBS-010 | Low | CV-Corr | Ac | Pricing date validation accepts full RFC3339 → breaks lexicographic effective-date by a day. |
| OBS-011 | Low | CV-Corr | Ac | Imported pricing may declare non-USD but estimation labels all USD. |
| OBS-012 | Low | Doc | Ac | FEATURE_MATRIX claims per-watch intervals; interval is one vault-global setting. |
| OBS-013 | Info | Doc | Ac | README understates sync/rules; FEATURE_MATRIX wrong line ranges. |
| OBS-014 | Info →NET-03 | CV-Corr | Vi | Duplicate of NET-03 (token counts unvalidated). |
| OBS-015 | Info | CV-Corr | Ac | Release profile lacks overflow-checks; usage aggregation can wrap on absurd stored values. |
| NET-01 | Low | CV-Sec | **Vi** | doc-watch URL validation scheme-only → SSRF probe primitive; doc comment false. |
| NET-02 | Info | D-i-D | **Vi** | Webhook allows https-to-internal (secret-free, no redirects → D-i-D). |
| NET-03 | Info | CV-Corr | **Vi** | Provider token counts summed unchecked (wrap in release); consolidates OBS-014. |
| NET-04 | Info | CV-DoS | Av | Sync engines bounded but generous under adversarial provider (informational). |

### CLI, filesystem, env-governance
| ID | Final Sev | Verdict | Review | Evidence / note |
|---|---|---|---|---|
| CLI-01 | Low →PI-01 | CV-Priv | Av | Duplicate of PI-01. |
| CLI-02 | Low | CV-Sec | Av | Inconsistent control-char sanitization → terminal-escape injection from .env/filesystem strings. |
| CLI-03 | Low | CV-Rel | Av | `access end --kill` reimplements termination inline (Unix-only, silent Windows no-op), no per-proc audit. |
| CLI-04 | Info | CV-Corr | Av | Global `--json` ignored by most mutating commands → non-JSON/mixed stdout. |
| CLI-05 | Info | CV-Sec | Av | `render::sanitize` strips C0/C1 but not Unicode bidi/format chars. |
| CLI-06 | Info | D-i-D | Av | `run` exit via `process::exit` bypasses UnlockedVault Drop (key zeroization). |
| FS-01 | Low | CV-DoS | Ac | Unbounded file reads in .env governance → local OOM on oversized `.env*`. |
| FS-02 | Low | CV-Loss | Ac | Default export uses non-atomic `write_new` → partial plaintext file on failure (contradicts threat model). |
| FS-03 | Low | CV-Rel | Ac | env_import dedup loop treats any DB error as "name taken" → unbounded spin / mis-numbered creds. |
| FS-04 | Low | CV-Priv | Ac | Temp export to non-UTF8 path recorded lossily → cleanup can't find file, plaintext lingers. |
| FS-05 | Info | CV-Priv | Ac | Orphaned atomic-write temp (plaintext) unswept if crash during first export to a virgin dir. |
| FS-06 | Info | CV-Corr | Ac | UTF-8 BOM makes first `.env` entry parse Malformed → silently skips a first-line secret on import. |
| FS-07 | Info | Doc | Ac | Export owner-restrict Unix-only; threat-model bullet omits Windows-ACL caveat. |
| FS-08 | Info | CV-Corr | Ac | Export TTL compared as RFC3339 strings; subsecond trimming breaks strict chronology. |
| FS-09 | Info →IPC-01 | CV-Sec | Vi | Duplicate of IPC-01. |
| INFO-01 | Info | CV-Rel | Ac | Vault-state mutex `.expect("poisoned")` in every command → one panic disables all commands. |
| INFO-02 | Info | CV-DoS | Ac | Provider pagination accumulates all pages in memory (bounded but generous) under desktop mutex. |

---

## Final tallies (this audit, distinct canonical findings)
- **Confirmed Critical:** 0
- **Confirmed High:** 1 — CRYPTO-01 (data-loss). *(Original evidence listed 2 High: OBS-001, ROT-001, both reassessed to Medium; CRYPTO-01 promoted Med→High.)*
- **Confirmed Medium:** 23 (CONC-01, CONC-02, CONC-04, CONC-06, DEST-01/02/03/10, GScan-01/02/03, IPC-01, OBS-001/002/003/004, PI-01/02, ROT-001/002/003/004/005/006) — count excludes duplicates.
- **Confirmed Low:** ~30 (see rows).
- **Informational / D-i-D / Doc / Test:** ~27.
- **Refuted:** 2 — CRYPTO-02, IPC-03.
- **Inconclusive:** 0 (CRYPTO-01 resolved to Confirmed; no candidate left inconclusive — residual `Ac` items are accepted-pending-independent-repro, not inconclusive).
- **Data-loss findings:** CRYPTO-01 (High), CONC-04, OBS-003, FS-02 (+ backup class CRYPTO-03 DoS).
- **Secret-exposure / privacy:** PI-01 (master pw to child env), FS-04/FS-05 (plaintext lingers), CLI-02/CLI-05 (escape injection), IPC-05/DEST-05 (URL injection).
- **Auth/authz:** IPC-02 (delete no reauth), IPC-01 (write no reauth), PI-05 (clock-rollback re-activates grants).

## Residual (carry to next pass)
`Ac`-status findings were dispositioned from reviewer source-citations + architectural consistency but **not independently re-read line-by-line this session**. They are concentrated in: rotation state-transition races (ROT-002/003/004/005/006), OBS pricing/usage correctness (OBS-005..012), FS-* edge cases, and CONC-07..10. None are High-risk categories (those were all Vr/Vp/Vi this session). Independent re-verification of the ROT-* races is the highest-value next step.
