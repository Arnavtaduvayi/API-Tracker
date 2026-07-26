# PR #13 — Vault-Lock Lifecycle Completion Plan

Dated remediation note (supersedes the "RO-13 not implemented / documented
residual" stance recorded in the earlier audit ledger). This document plans and
records the implementation that makes **locking or auto-locking the vault stop
an active `run --observe` session** and stop any further traffic decryption with
vault-protected material.

## 1. Current behavior (verified against code at `d4bf841`)

- `api-tracker run --observe` → `run_cmd::run_observed` unlocks the vault
  (`ctx.unlocked()` — from a session token or an inline password), builds
  `RunParams`, and calls `observe::session::run_monitored`.
- `run_monitored` (crates/observe/src/session.rs) ensures the CA, opens the
  session row, starts the loopback proxy + writer thread, applies child-scoped
  trust, launches the child, then **blocks on `child.wait()` (session.rs:273)**.
- Teardown (proxy shutdown, drop CA, delete temp trust files, finalize the
  session) runs ONLY after `child.wait()` returns.
- The manual lock command (`api-tracker lock` → `session::destroy`) runs in a
  **separate process** and only deletes the on-disk session file. It cannot
  reach the running `run` process, which holds its own copy of the vault key and
  the reconstituted CA signing key in memory.
- The desktop app does **not** launch observed runs (there is no such Tauri
  command); observed runs are CLI-only. So the only process that owns a live
  proxy + CA key is the CLI `run` process.

## 2. The gap

`child.wait()` is uninterruptible. While it blocks, the proxy keeps terminating
TLS and the CA signing key stays live for the child's entire lifetime,
regardless of a manual lock or the vault's auto-lock timeout. This contradicts
the intended meaning of "lock" / "auto-lock".

## 3. Chosen design — an in-process, self-enforcing lock watch

Because the only owner of the live proxy/CA is the CLI `run` process itself, the
correct and portable mechanism is for **that process to watch for lock signals
and tear itself down** — no cross-process signalling, no `/proc`, no pidfd, works
on macOS/Linux/Windows.

`RunParams` gains a `LockPolicy`:

```
pub struct LockPolicy {
    /// Watch this session file. Missing → MANUAL lock. Present but past its
    /// recorded expiry → AUTO-lock (idle). None when the run is not under a
    /// session token.
    pub session_file: Option<PathBuf>,
    /// Hard wall-clock cap from run start (= vault auto_lock_minutes when > 0).
    /// Elapsed → AUTO-lock. Covers inline-password runs and is a backstop.
    pub max_run: Option<Duration>,
}
```

The CLI (`run_observed`) builds it: `session_file` = `vault.paths().session_path()`
when `ctx.unlocked()` returned a session token; `max_run` =
`auto_lock_minutes` (when auto-lock is enabled).

`run_monitored` replaces `child.wait()` with a **bounded poll loop** (250 ms
tick — a poll interval, not "sleep and hope"; correctness depends only on the
deterministic checks, responsiveness on the interval):

```
loop {
    if let Some(status) = child.try_wait()? { -> normal exit, break }
    match lock_policy.lock_signal(started) {
        Some(ManualLock) -> interrupt("vault_locked"); break
        Some(AutoLock)   -> interrupt("auto_lock");    break
        None -> {}
    }
    sleep(TICK)
}
```

`lock_signal` is pure and cheap: stat the session file (missing → manual; parse
its `expires_at`, `now >= expires` → auto), and compare `started.elapsed()`
against `max_run` (→ auto).

## 4. Lock ordering / teardown (shared by normal exit AND interrupt)

One teardown function, called exactly once after the loop, in this order — the
FIRST step is the security-critical one:

1. **`proxy.shutdown()`** — sets the shutdown flag, force-closes every in-flight
   client socket (implemented in the prior remediation: `stop()` calls
   `TcpStream::shutdown(Both)` on each registered client before joining
   workers), stops the listener, releases the ephemeral port. **After this
   returns, no connection is being decrypted and the per-session token is dead**
   (the proxy is gone; a replayed token has nothing to authenticate against).
2. **Terminate the child** via `inject::terminate_verified(pid, identity)` —
   verifies the recorded launch identity immediately before signalling, refuses
   on PID reuse / identity mismatch / missing identity, truthful `AlreadyExited`.
   Descendants are NOT tree-killed (pre-existing PI-03 limitation, documented);
   this is safe because step 1 already stopped all decryption, so a lingering
   descendant can only reach a dead loopback port.
3. `drop(sink)` + `writer.join()` — flush and stop the metadata writer.
4. `drop(ca)` — drops `CertAuthority`: clears the bounded leaf-cert cache and
   releases the reconstituted CA signing key (SecretBytes zeroizes; rcgen
   `zeroize` feature enabled).
5. `drop(trust)` — deletes the temp scoped-trust PEM files.
6. Finalize: normal exit → `finish_session` (completed); interrupt →
   `interrupt_session(reason)`. Both are `WHERE status='running'` compare-and-set
   → idempotent, never overwrite a terminal state.

No mutex is held across network I/O, process waits, or thread joins: the loop
owns the child and proxy handles directly; teardown transfers ownership out.

## 5. Idempotency / races

- **Concurrent lock + child exit:** the single-threaded loop checks `try_wait`
  first each tick; whichever is observed first wins; teardown runs once.
- **Repeated / partial cleanup:** `interrupt_session`/`finish_session` are
  compare-and-set on `status='running'`; a second call is a no-op. `proxy.shutdown`
  is idempotent (shutdown flag + `Option::take` on the join handle).
- **Partial startup:** the existing early-return paths (`trust_setup_failed`,
  `child_spawn_failed`) already shut the proxy and interrupt; unchanged.
- **Unlock does not reactivate:** teardown drops the proxy + token + CA; a later
  unlock starts a brand-new run with a fresh token/port/CA. Nothing survives.

## 6. Child-process policy

Fail-closed: on lock we terminate the direct child (verified). Descendants are
not tree-killed (PI-03) — documented; mitigated because decryption already
stopped at step 1. Metadata AND connection-only runs both go through
`run_monitored`, so both are interrupted on lock (coherent policy per the task's
§6; connection-only holds no CA key but still gets torn down for consistency and
to stop its opaque tunnels/session token).

## 7. Session states

New interrupt reasons: `vault_locked` (manual) and `auto_lock` (auto/idle),
alongside existing `trust_setup_failed`, `child_spawn_failed`, `launcher_gone`.
Stored in `observation_sessions.interrupt_reason` (non-secret).

## 8. Platform notes

Poll loop + `try_wait` + file-stat + `Instant` deadline are fully portable
(no signals, no `/proc`). Ctrl-C: the child is in the launcher's foreground
process group and receives SIGINT directly; its death is observed by `try_wait`
and triggers normal teardown. If the launcher is itself killed before teardown,
the proxy dies with the process (all threads exit; port released) and the
orphan-session sweep (wired into `run_monitor`) reconciles the DB row to
`launcher_gone`. Temp trust files hold only public certificate material.

## 9. Tests (see PR13_VAULT_LOCK_REAUDIT for coverage)

Deterministic observe integration tests with a long-lived synthetic child and a
short `max_run` / a deleted-or-expired session file: assert the child is
terminated, the session is `interrupted` with the right reason, the proxy port
is closed and the token rejected, the leaf cache is empty, temp files are gone,
repeated cleanup is a no-op, a completed session is not overwritten, and
connection-only follows the same rule. Plus a raw-DB/WAL privacy canary.

## 10. Explicit boundaries (honest)

- The desktop app cannot launch observed runs, so there is no desktop-owned
  observed session to interrupt; the desktop "Lock vault" affects only its own
  in-memory vault handle. This is an architectural boundary, documented, not a
  gap in this fix.
- Descendant process trees are not killed (PI-03); decryption still stops via
  proxy teardown.
- The poll tick bounds responsiveness (~250 ms), not correctness.
