# PR #13 — Packaged Vault-Lock Validation (macOS)

Real, isolated, end-to-end validation of the vault-lock lifecycle using the
**release-built** artifact against local synthetic activity, in a throwaway
vault — never the user's real vault or data directory.

## Environment

- Source commit: `1fb8a85` (feat/runtime-api-observability, the audited head).
- Platform: macOS (arm64), this machine.
- Artifact under test: the **release CLI binary**
  `target/release/api-tracker` (`cargo build --release -p api-tracker-cli`).
- Isolated workspace: `~/at-pr13-packaged-test/` and `~/at-pr13-autolock-test/`
  (created fresh, deleted after each run; `--data-dir` pointed at them).
- Synthetic only: a fake credential (`sk-fake-…`, value fed via stdin, never on
  argv), `sleep` as the monitored child, connection mode (no real provider, no
  network, no CA install).

## Important architectural boundary (why this is CLI, not GUI)

The desktop Tauri app **does not launch observed runs** — `apps/desktop/src-tauri`
exposes only read/manage `observe_*` commands and `observe diagnostics`; there is
no `run_monitored`/`RunParams` call anywhere in it (verified by grep). Observed
runs are launched exclusively by the CLI `api-tracker run --observe`, and that
CLI process is the sole owner of the live proxy + CA key. Therefore the
"lock stops the observed run" security property is a **CLI-process** property,
and the packaged artifact that must be validated for it is the release CLI
binary — which is what was tested here. A packaged-desktop-GUI "lock stops the
observed run" test is not applicable because the desktop cannot start an
observed run to stop. (The desktop's own "Lock vault" affects only its
in-memory vault handle; it owns no proxy/child.)

## 28.1 — Manual lock (PASS)

Steps (release binary, isolated vault, run under a session token):
`init` → `unlock --print-export` (session token) → `project create obs-app` →
`key add … --value-stdin` → background `run --project obs-app --credential
testkey --env TEST_KEY --observe=connection -- sleep 30` → confirm active +
capture session id → `api-tracker lock` (deletes the session file) → observe the
run.

Observed result:

```
run is active (pid 2470)
observation session: c455964f-fe5b-4179-8d74-32576d9df33a
locked
run terminated after lock
run exit code: 125 (expect 125 = interrupted)
Monitored session c455964f INTERRUPTED — the vault was locked: the observation
  proxy was shut down and the monitored process was terminated. Start a new run
  after unlocking.
status= interrupted  reason= vault_locked
no leftover run process
fresh normal run OK (exit 0)
```

Confirmed: within ~1 s of the lock the run terminated (exit 125); the session is
`interrupted / vault_locked` (never relabeled completed); no proxy/child
lingered; unlocking did not resurrect the old run; and a fresh observed run
started and finished normally afterward.

## 28.2 — Auto-lock (PASS)

Steps: `settings set auto_lock_minutes 1` → `unlock` → background `run …
--observe=connection -- sleep 300`, then leave the session untouched so its
recorded expiry elapses (no refresh).

Observed result:

```
auto_lock=1min set
run started (pid 2677); waiting for the 1-minute auto-lock (session expiry)…
run interrupted after 61s
exit=125 (expect 125)
Monitored session fb5e9e24 INTERRUPTED — the vault auto-locked: the observation
  proxy was shut down and the monitored process was terminated. Start a new run
  after unlocking.
```

Confirmed: the run self-interrupted at the auto-lock boundary (~61 s) with reason
`auto_lock` and exit 125 — no external action required.

## 28.3 — Application shutdown

Not applicable in the desktop sense (the desktop owns no observed run). For the
CLI: if the `run` launcher process is killed, its threads (including the proxy)
die with it and the port is released; the orphaned session row is later
reconciled to `launcher_gone` by the monitor's `sweep_orphaned_sessions` (wired
into `run_monitor`, covered by `observability.rs::run_monitor_sweeps_orphaned_
observation_sessions`). Normal launcher exit after the child exits finalizes the
session `completed`.

## 28.4 — Regression

- Ordinary unobserved `run` and `--observe=off`: unchanged code path (the lock
  policy is built only inside `run_observed`); covered by the existing cli/core
  suites (all green in CI). The packaged run in 28.1/28.2 also demonstrates a
  fresh normal observed run works after a lock.
- Metadata mode does not install a system certificate (Mode C is a separate,
  reauthenticated action; unchanged).
- No request/response bodies, query strings, Authorization values, or cookies
  are stored — structural (`ObservedRequest` cannot hold them) and now also
  asserted against raw DB/WAL bytes by
  `observability.rs::raw_database_and_wal_never_contain_path_or_query_canaries`.

## Cleanup

Both isolated workspaces (`~/at-pr13-packaged-test`, `~/at-pr13-autolock-test`)
were removed at the end of each run. No `.app` bundle is committed. The user's
real vault and data directory were never touched.

## Limitations (honest)

- Interactive desktop-GUI testing was not performed and is **not applicable**:
  the desktop cannot launch observed runs (documented boundary above).
- Descendant *processes* the monitored child spawns are not tree-killed (PI-03);
  decryption still stops because the proxy is shut down first. The `sleep` child
  here is the tracked pid itself, so it is terminated directly.
- The auto-lock granularity is whole minutes (the smallest configurable
  auto-lock is 1 minute), so the auto-lock demo took ~61 s; the sub-second
  trigger logic itself is covered by the deterministic automated tests.
