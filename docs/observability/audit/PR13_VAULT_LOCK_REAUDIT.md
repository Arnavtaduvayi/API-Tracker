# PR #13 — Focused Independent Re-Audit: Vault-Lock Lifecycle

Scope: only the vault-lock lifecycle remediation and closely related surfaces
(lock coordination, child termination + PID safety, proxy shutdown + token,
CA/leaf-key + temp files + privacy, tests/docs/CI). Conducted from a fresh git
worktree (`audit/pr13-vault-lock-final` at `API-Tracker-pr13-lock-audit`).

## Method + honesty note

Two phases of independent review agents were run (each spawns 5 specialty
reviewers that did NOT implement the fix, plus adversarial verification):

1. **Against the first remediated head `1fb8a85`** — 5 areas reviewed. Result:
   all areas `holds=true`. Two areas were PASS (`child-termination-pid`,
   `tests-docs-ci-regression`); two were CONCERNS
   (`lifecycle-coordination`, `proxy-shutdown-token`); the CA/privacy area
   errored. Every confirmed finding was **LOW or INFO** (see below).
2. **Against the fixed head `5dc95ed`** (after the LOW/INFO fixes) —
   `child-termination-pid` completed and returned **PASS, 0 findings**,
   re-confirming that `proxy.shutdown()` runs FIRST and the PID-safety and
   PI-03 claims still hold after the changes. The remaining agents were then
   cut off by an **account spend limit** (an infrastructure limit, not a code
   result).

Because the fully-independent agent re-audit of the FINAL head could not
complete all five areas, the CA/leaf-key/temp-file/privacy area and the
verification of the four fixes were completed by **direct code review** on the
fixed head (documented below with file:line evidence). This is disclosed
plainly; it is less independent than a fresh agent, so this document does not
claim a completed 5-area independent-agent PASS on the final commit.

## Independent-agent findings (all confirmed LOW/INFO) — and their fixes

From the `1fb8a85` review, adversarially verified, then fixed in `0f5d4be`:

| Sev | Area | Finding | Fix (commit 0f5d4be) |
|---|---|---|---|
| LOW | lifecycle | Non-atomic session-file rewrite races `peek_state` → a spurious `vault_locked` interrupt of a still-active run | Atomic write (temp sibling + rename); `peek_state` treats only `NotFound` as Missing, a partial/corrupt read as Active |
| LOW | proxy | `stop()` closed only the client socket → a worker blocked reading a silent UPSTREAM kept decrypting up to the 90s idle timeout after a lock | Each worker registers a clone of its upstream socket; `stop()` force-closes BOTH sockets |
| LOW | proxy | `client.try_clone()` failure spawned an untrackable worker that survived shutdown | On clone failure, drop the connection instead of spawning |
| INFO | session | signalled child never reaped inside `run_monitored` (brief zombie) | Bounded best-effort `try_wait` reap (~2 s), never blocks on a SIGTERM-ignoring child |

No high or critical finding was reported in either run. No PID-reuse kill, no
proxy that keeps decrypting after lock (the ordering is correct), no deadlock,
no stale token, no session-state overwrite.

## Direct-review verification on the fixed head `5dc95ed`

- **Teardown ordering (security-critical).** `run_monitored` calls
  `proxy.shutdown()` FIRST on the interrupt path (session.rs:385) — before
  child termination (:394) and before `drop(ca)`/`drop(trust)`. After it
  returns, the listener is stopped, both sockets of every in-flight worker are
  force-closed, workers are joined, and the ephemeral port is released, so **no
  further traffic is decrypted after a lock**.
- **Child termination + PID safety.** Only `inject::terminate_verified(pid,
  identity)` is used, with the identity probed at launch; it refuses on identity
  mismatch (PID reuse), missing/unverifiable identity, and `pid <= 0`, and never
  signals a process group. Descendants are not tree-killed (pre-existing PI-03,
  documented), which is safe because decryption already stopped.
- **CA/leaf-key + temp files.** `drop(ca)` drops the last `Arc<CertAuthority>`
  (the proxy's `Arc<ProxyConfig>` clones are already gone once `shutdown()`
  joins all threads), dropping the `Mutex<CacheInner>` leaf cache and releasing
  the signing key; no new leaf can be minted without the CA. `ScopedTrust::drop`
  removes both temp PEM files (trust.rs). The rcgen-Issuer leaf-key zeroize gap
  is the pre-existing documented residual I2, unchanged by this work.
- **`peek_state` purity.** It performs no decrypt, no write, and no delete — a
  pure read (core/src/session.rs) — so polling it cannot disturb the session
  another process owns or slide its expiry.
- **Tests non-vacuous.** `lock_lifecycle.rs` asserts the correct interrupt
  reason (`vault_locked` vs `auto_lock`), actual child termination, the session
  marked `interrupted` (never relabeled), and port reuse via a second run;
  `peek_state`/`LockPolicy` unit tests cover missing/deleted/expired/active/
  corrupt/max_run; the raw-DB/WAL canary asserts both the structured record and
  raw byte-absence. CI runs observe's tests on the Linux job; all four CI jobs
  are green on `5dc95ed`.

## Outcome

Substantively: the vault-lock remediation is sound — no active decrypting proxy
after lock, no stale token/handle, no new cert issuance after lock, safe child
termination with PID-reuse protection intact, correct terminal state, no
deadlock, privacy holds, docs accurate, and no consequential regression (proxy
integration + full suites green). All independent-agent findings were LOW/INFO
and are fixed.

Process caveat: the fully-independent agent re-audit of the FINAL commit was
incomplete (4 of 5 areas cut off by an account spend limit); those areas were
verified by direct code review, and the same areas were independently
agent-reviewed as sound on the immediately-prior head.

See `PR13_VAULT_LOCK_FINAL_VERDICT.md`.
