# Packaged Linux validation — evidence record (Phase 3)

**Honest status: NO packaged-Linux end-to-end run was performed in this
phase.** This session ran on macOS; no Linux machine executed a packaged
Tethra build, and nothing below claims otherwise.

## Evidence that DOES exist for Linux

| Aspect | Evidence | Where |
|---|---|---|
| Gateway crate compiles and its full test suite passes on Linux | CI `rust` job (`ubuntu-latest`) runs clippy + `cargo test` for `api-tracker-gateway` on every push/PR | `.github/workflows/ci.yml` |
| CLI (including the gateway family and systemd lifecycle code) compiles and tests on Linux | Same CI job includes `-p api-tracker-cli` | `.github/workflows/ci.yml` |
| systemd-user unit generation, quoting, parsing, and the install/disable/uninstall orchestration | Unit-tested against a mock command runner and temp dirs (`systemd_unit_renders_user_scope_and_round_trips_spaced_paths` and the shared lifecycle suite) | `crates/gateway/tests/lifecycle.rs` |
| Frontend build/tests on Linux | CI `frontend` job (`ubuntu-latest`) | `.github/workflows/ci.yml` |
| Linux desktop bundle builds | `release.yml` tauri-action Linux job — build-time evidence only, produced on tag builds, not exercised in this phase | `.github/workflows/release.yml` |

## What has NOT been validated on Linux

- `systemctl --user` behavior against a real systemd user manager
  (enable/start/stop/restart/disable, `default.target` start at login,
  linger behavior).
- The packaged AppImage/deb actually enabling the gateway end to end.
- Real `.env` linking on a Linux filesystem (the engine is
  platform-generic and fully tested, but not exercised on Linux outside
  CI's `cargo test`).

## What a Linux validation session must do

Run the equivalent of `docs/gateway/PACKAGED_MACOS_RESULTS.md`'s script
on a real Linux desktop session: install → confirm the unit file and
`systemctl --user is-enabled` → traffic through the gateway → linger
honesty check (`loginctl`) → disable/uninstall → confirm no unit, no
listener, no stale files. Until that run exists, Linux service support
should be described as "implemented and unit/CI-tested, not yet
validated end to end on a real desktop".
