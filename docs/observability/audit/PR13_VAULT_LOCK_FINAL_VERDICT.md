# PR #13 — Vault-Lock Remediation: Final Verdict

## Verdict on the code: PASS

The vault-lock lifecycle remediation is implemented correctly and is safe:

- **Manual lock** (`api-tracker lock`, deletes the session file) and
  **auto-lock** (session-file expiry / inline-password TTL) both interrupt an
  active `run --observe`: the proxy is shut down FIRST (all decryption stops,
  the per-session token is invalidated, both sockets of every in-flight worker
  are force-closed, the port is released), the monitored child is terminated via
  the verified-identity path (PID-reuse-safe), the CA + leaf cache are cleared
  and temp trust files removed, and the session is recorded `interrupted`
  (`vault_locked` / `auto_lock`) — never relabeled completed.
- Verified by: `crates/observe/tests/lock_lifecycle.rs`, the
  `core::session::peek_state` + `LockPolicy` unit tests (which also run on the
  Windows CI job), the raw-DB/WAL privacy canary, an independent re-audit of the
  mechanism (all findings LOW/INFO, fixed), and **packaged release-binary
  validation** of both manual and auto lock (`PR13_PACKAGED_LOCK_VALIDATION.md`).
- All four GitHub CI checks are green on the final head `5dc95ed` (Linux — now
  including observe's tests, Windows, macOS backend, frontend).

Documented, honestly-scoped limitations (not blockers): descendant *process
trees* are not killed (pre-existing PI-03; safe because the proxy is down); the
desktop app cannot launch observed runs, so this is a CLI-process property; the
rcgen-Issuer leaf-key zeroize gap is the pre-existing residual I2; lock
responsiveness is bounded by a ~250 ms poll tick.

## Verdict on the required process gate: INCOMPLETE (spend-limited)

The task requires a **focused independent re-audit that returns PASS on the
final commit**. That re-audit was run but **cut off by an account spend limit**:
on the final head `5dc95ed` only 1 of 5 areas (`child-termination-pid`)
completed independently (PASS, 0 findings); the other four were independently
agent-reviewed on the immediately-prior head `1fb8a85` (all `holds=true`, only
the LOW/INFO findings that were then fixed) and re-verified on the final head by
direct code review. So the fully-independent 5-area agent re-audit of the final
commit is **incomplete** — an infrastructure blocker, not a code defect.

Update: a further attempt to complete the missing independent-agent review of
the CA/leaf-key/temp-file/privacy area (both the 5-agent workflow and a single
cheap Sonnet agent) was also blocked by the **monthly spend limit** — the agents
could not launch. That area was therefore completed by direct code review on the
final head `5dc95ed`, including the one open question (CA `Arc` drop ordering):
the proxy's `ProxyConfig` holds the `Arc<CertAuthority>`; `proxy.shutdown()` →
`stop()` joins the listener AND every worker thread before returning
(proxy.rs), so no thread retains a `ProxyConfig`/`Arc<CertAuthority>` clone
afterward, and the subsequent `drop(ca)` (session.rs:414) drops the last
`Arc<CertAuthority>` — clearing the `Mutex<CacheInner>` leaf cache and releasing
the signing key, so no new leaf can be minted after a lock. Temp PEM files are
removed by `ScopedTrust::drop` (trust.rs); `peek_state` is a pure read (no
decrypt/write/delete); the session write is atomic (temp-sibling + rename); the
raw-DB/WAL canary asserts both the structured record and raw byte-absence.

## What still closes the process gate

An **independent** party (a re-audit agent once the spend limit is lifted, or a
maintainer) should review the same surfaces on `5dc95ed`. The engineering
review is complete and every property is verified; what remains is
independence-of-reviewer on the final commit, which the spend limit prevented
from being an agent this run. Re-run:
`Workflow scriptPath pr13-vault-lock-reaudit-*.js`,
args `{"root":"…/API-Tracker-pr13-lock-audit"}`.

## PR status

PR #13 remains **open, ready for review, NOT merged**. Do not merge until the
independent re-audit of the final commit is completed (the one outstanding
gate).
