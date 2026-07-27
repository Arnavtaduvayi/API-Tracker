# Packaging Plan — A Self-Sufficient Desktop App

## 1. The problem, verified on a real install

The packaged `Tethra.app` contains exactly one executable
(`Contents/MacOS/api-tracker-desktop` — verified on the installed bundle on
this machine). The gateway service *is* the CLI binary
(`lifecycle` installs a copy of it and points the LaunchAgent at the copy),
and the desktop deliberately bundles no CLI: `tauri.conf.json` has no
`externalBin`, per `docs/gateway/OPEN_DECISIONS.md` O10 ("deferred until
the signing path exists"). Net effect: **a fresh install of the advertised
product cannot perform its advertised primary function** without a manual
terminal install — or worse, the observed workaround on this machine, a
`~/.local/bin/tethra` symlink into a Git worktree's `target/release`.

This plan closes O10: the app ships its helper.

## 2. Decision: bundle the CLI as a Tauri sidecar (externalBin)

* `apps/desktop/src-tauri/tauri.conf.json` gains
  `bundle.externalBin: ["binaries/tethra"]`. Tauri expects
  target-triple-suffixed files (`binaries/tethra-aarch64-apple-darwin`,
  …) and places the binary in the app bundle
  (macOS: `Contents/MacOS/tethra`; Windows/Linux: beside the main
  executable).
* Build wiring: a small script (`scripts/bundle_cli.sh`, called before
  `tauri build` locally and in `.github/workflows/release.yml`) runs
  `cargo build --release -p api-tracker-cli` and copies
  `target/release/tethra` into `src-tauri/binaries/` with the
  target-triple name. CI's Desktop job builds the CLI first (same
  workspace, mostly cached).
* The bundled binary is byte-identical to the standalone CLI archive
  binary — one program, no new "helper-only" build flavor, so the CLI
  archive remains fully supported for terminal users and CI parity is
  trivial (same artifact, two containers).

## 3. Discovery order change (small, surgical)

`locate_cli` (`apps/desktop/src-tauri/src/main.rs:2473-2508`) currently
searches data-dir copies → PATH → `/usr/local/bin`, `/opt/homebrew/bin` →
`~/.local/bin`, `~/bin`, `~/.cargo/bin`, exec-probing each candidate
(`gateway service-probe` must print `PROBE_MARKER`). Change: **the bundled
sidecar becomes the first candidate** (resolved relative to
`std::env::current_exe()`), keeping every existing fallback and the exec
probe. Consequences:

* Fresh machine: bundled helper found → zero-terminal enable works.
* Existing dev machine: an already-installed service binary in the data
  dir still wins for repair paths (unchanged first entry), so upgrades
  keep their working copy until `repair` refreshes it.
* Version skew: `doctor`'s existing `version_mismatch` /
  `recorded_version_drift` findings surface app-vs-service drift; `track`
  runs `Lifecycle::repair` when the bundled version is newer (explicit
  step in the apply report, not silent).

Install keeps the existing hardening: `fresh_byte_write` (never `fs::copy`,
so quarantine xattrs don't propagate), `xattr -d com.apple.quarantine`,
exec probe before any registration, honest failure toward foreground mode.

## 4. Signing (external dependency, not a blocker)

Builds are unsigned (`docs/PACKAGING.md:37-40`; required Apple/Windows
credentials enumerated there, none configured). Position:

* Bundling does **not** wait for signing. O10's original rationale
  (quarantine inheritance) is already mitigated in code: the copy path
  strips quarantine and exec-probes before registering, and failure is
  honest (§5 fallback). Unsigned alpha remains unsigned-alpha quality
  either way; a separately downloaded unsigned CLI archive has strictly
  worse Gatekeeper behavior than a bundled helper copied by an app the
  user already chose to open.
* Signing + notarization remain the durable fix and a release blocker for
  any public build — tracked as the one genuinely external action in
  `HANDOFF_PHASE_1.md` (Apple Developer ID certificate, Windows
  Authenticode). The release workflow already has the hook points.

## 5. Foreground fallback when the service cannot install

If the exec probe fails (Gatekeeper on unsigned alphas) or LaunchAgent
registration is refused, the desktop offers, in the apply step's failure
slot:

```text
macOS blocked the background service (this build is unsigned).
[Track while the app is open]  — tracking runs only while Tethra is open
[How to allow the service]     — System Settings → Privacy & Security
```

"Track while the app is open" spawns the bundled helper as a child process
(`tethra gateway serve --port <persisted>`), giving full tracking with an
honest lifetime limitation surfaced in the dashboard header
("Tracking pauses when Tethra closes"). This reuses `serve` exactly as it
exists; no new gateway mode. The state model treats it as
`traffic_observed` with a `foreground` badge, and `doctor`'s existing
`running_manually` finding already describes it.

## 6. Windows and Linux

* **Linux**: sidecar bundling is identical (AppImage/deb place the helper
  beside the executable). systemd-user lifecycle is implemented but has
  never had a packaged end-to-end run (`PACKAGED_LINUX_RESULTS.md`) — the
  packaged validation script gains a Linux twin before Linux release
  claims anything (Phase 5, `TEST_PLAN.md` §8).
* **Windows**: lifecycle is compile-validated only and attribution is
  structurally unavailable (no control socket; SI-21 refuses TCP
  fallback). The bundled helper still enables the supported foreground
  mode. All existing "never executed on Windows" labeling stays until a
  real Windows validation run happens.

## 7. Uninstall story

Unchanged and already correct: `uninstall` removes service definition,
binaries dir, logs, runtime files; recorded history stays; the service
self-unloads if the data dir vanishes. The bundled sidecar is removed with
the app bundle by the OS. One addition: the Advanced uninstall screen
notes that dragging the app to Trash without disabling leaves the
LaunchAgent until self-unload triggers, with a [Disable service first]
button (this is today's behavior, now stated where the user can see it).

## 8. Size and build-time cost

The release CLI binary is a few tens of MB (stripped, `strip = true` in
the workspace release profile); acceptable for a desktop app. Release CI
gains one `cargo build -p api-tracker-cli --release` per desktop target —
mostly cache-shared with the existing workspace build.
