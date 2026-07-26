# PR #13 — Remediation Plan & Ledger

Remediation was executed in nine coherent commits (waves), each self-contained,
tested, and clippy/fmt-clean before the next. No security control, TLS/SSRF
check, or test was disabled or weakened to make CI pass; every fix addresses a
root cause. CI was already green before remediation (the two CI failures were
fixed in `cfacc81`/`69fc886` — see `PR13_CI_FAILURE_ANALYSIS.md`); this work is
the adversarial-audit remediation on top.

| Commit | Wave | Scope |
|---|---|---|
| `c94ca98` | 1 | Proxy correctness/security: HIGH plain-HTTP relay reversal; Host-header→connect_host; header forwarding; WebSocket bidirectional relay; Slowloris/shutdown registry + head deadline; worker reaping; upstream-error classification; RequestHead redacting Debug. |
| `f0b3d6f` | 2 | SSRF: trailing-dot normalization (metadata + single-label); NAT64/6to4 embedded-IPv4 decode; 192.0.0.0/24. |
| `515e156` | 3 | Sanitizer: catch low-class opaque tokens (vowel/consonant heuristic); lower length floor; percent-encoded control redaction; de-circularize P6 with an independent Shannon oracle; byte-safe UUID scan (latent panic fix). |
| `a529d2d` | 4 | DB: HIGH roll_up NULL-brick (COALESCE); HIGH day-bucket from_day; empty-scope metrics; IMMEDIATE-txn roll_up; watermark-gated sweep; reroll_hours at finalize; inventory caps; per-cred bucket cleanup; hour_floor panic guard; drop dead runtime_alert_baselines. |
| `781049c` | 5 | Alerts: HIGH NULL-SUM crash + isolate pass; HIGH old-version/revoked session-liveness bounds; opaque-tunnel exclusion; unknown-api classification; shared-cred recency; inactive-api coverage gate; confirmed/high only. |
| `f6fc6cd` | 6 | Attribution: HIGH re-query current version; HIGH resolve reference→root; HIGH gate possible-fallback on auth; Confirmed requires auth; wire.rs detects x-api-key/x-goog-api-key/api-key presence; last_used_at confirmed/high only. |
| `b63db80` | 7 | Process/platform: HIGH wire orphan sweep + /proc liveness; argv-secret redaction; lowercase no_proxy merge; honest diagnostics; Windows .cmd/.bat/py detection; resolve_validated dual-stack fallback. |
| `a9d86d7` | 8 | CA/vault/session: MED cert-PEM-bound AAD (laundering fix, fail-closed); bounded sync_channel writer; rcgen zeroize; CertStateRow Debug elide. |
| `862cce1` | 9 | Product honesty: implement partial-coverage + Go downgrade + `observe delete-project` + `no_insecure_verifier.rs` guard; rewrite compat matrix (CRITICAL); correct corporate-proxy / cert-repair / export / pinning / QUIC / canary / vault-lock claims across 7 docs + desktop UI. |

## Rules honored (from the task brief)

- No failing test disabled, ignored, or deleted; no CI job removed; clippy not
  weakened. The only pre-existing test touched was `clienthello.rs`'s
  `nonminimal_bool` (a behavior-identical `!x.is_some()` → `x.is_none()` in the
  crate being hardened).
- No TLS validation bypassed; no certificate verification disabled; no SSRF
  restriction loosened — SSRF was *tightened* (trailing-dot, NAT64/6to4).
- No payload-retention assertion removed; the metadata-only type boundary
  (`ObservedRequest` cannot hold payload) is unchanged and now additionally
  guarded by the argv redactor and cert-bound AAD.
- Process-identity verification not weakened; the new orphan sweep is
  fail-safe (uncertainty keeps a session open).
- PR #13 remains a draft; no merge, no required-check bypass, no admin override.

## Residuals accepted for this draft (with rationale)

Tracked, non-exploitable in the default posture; see `PR13_FINDINGS_INDEX.md`
L6/L7/L10/L11/I2/I4/I6 and M25/M26:

1. **Cross-process vault-lock interruption of a live run (H12).** Correcting the
   docs is the audit's endorsed resolution for a draft; the lock-hook is
   required follow-up before public release. The CA is a per-vault local
   observation CA, Mode C is off by default.
2. **Pre-existing `inject.rs` `ps`/PowerShell identity probes (M25/M26).** Not
   in this branch's diff; modifying security-critical termination code on a
   *suspected* finding without an Alpine/Windows test bed is out of scope. The
   NEW sweep this PR adds uses `/proc` on Linux.
3. **`upstream_config` public field (L6), leaf-cache 24h expiry (L7), proxy
   token as String (L10), env-inherited token (L11), rcgen leaf-key zeroize
   (I2), first-run CA INSERT-only (I4), Proxy-* in intercept path (I6).** Each
   is availability/hardening only, with no active leak; noted for follow-up.
4. **Printable percent-encoded path secrets (L2 partial).** Encoded control
   bytes are redacted; printable `%XX` sequences are a documented residual.

## Release classification (unchanged direction)

Experimental / internal-alpha — public-blocked. The correctness and security
bugs that made the first cut unsafe to ship are fixed and regression-tested; the
remaining blockers are the vault-lock hook, broader runtime integration tests
(see `PR13_TEST_COVERAGE_GAPS.md`), and desktop end-to-end packaged runs.
