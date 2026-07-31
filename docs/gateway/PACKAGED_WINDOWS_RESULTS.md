# Packaged Windows validation — evidence record (Phase 3)

**Honest status: the Windows gateway lifecycle has NEVER been executed on
a Windows machine.** Windows evidence in this phase is COMPILE-VALIDATION
ONLY, and every status surface (CLI status/doctor, desktop panel, the
lifecycle module's own labels) says so.

## Evidence that DOES exist for Windows

| Aspect | Evidence | Where |
|---|---|---|
| Core + gateway crates compile and their tests run on real Windows | CI `rust-windows` job (`windows-latest`): `cargo test -p api-tracker-core -p api-tracker-gateway` | `.github/workflows/ci.yml` |
| The FULL CLI — gateway command family and the HKCU Run-key lifecycle — compiles on real Windows | CI `rust-windows` job: `cargo build -p api-tracker-cli` (added this phase) | `.github/workflows/ci.yml` |
| Run-value quoting and round-trip parsing (paths with spaces) | Platform-independent unit test | `crates/gateway/tests/lifecycle.rs` (`windows_run_value_quotes_and_round_trips_spaced_paths`) |
| The control channel is ABSENT by design on Windows (never a TCP fallback) | cfg-gated stub refuses key push; compiled in the Windows CI job | `crates/gateway/src/control.rs` (SI-21) |
| Windows CLI release archives build | `release.yml` `x86_64-pc-windows-msvc` job (tag builds) | `.github/workflows/release.yml` |

## Design shipped for Windows (unvalidated)

Per-user login start via an
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value written with
`reg.exe` (no elevation, no service manager, no new dependencies; visible
in Task Manager → Startup apps). Stop verifies the listener answers this
data directory's nonce probe before killing the recorded pid, and is a
force-kill: without the control channel there is no graceful drain on
Windows. Attribution is unavailable on Windows (key push refused rather
than falling back to TCP).

## What has NOT been validated on Windows

Everything behavioral: registry write/read/delete through `reg.exe`,
login start, the identity-probe-then-taskkill stop path, `serve
--service` under a real Windows session, `.env` linking on NTFS, and the
packaged desktop app. **Do not describe Windows lifecycle support as
working.** The supported Windows mode is foreground
`tethra gateway serve`.

## What a Windows validation session must do

On a real Windows machine: install → `reg query` shows the value →
sign-out/sign-in starts the gateway → traffic + metadata recording →
stop (identity-verified) → uninstall → no Run value, no process, no
stale files. Until then the honest label everywhere is
"compile-validated only; never executed on Windows".
