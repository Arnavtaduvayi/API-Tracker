# Packaged validation results

Executed evidence for the packaged desktop application. Anything not
listed as executed here is explicitly labeled as not executed.

## macOS — executed 2026-07-27

Machine: macOS 25.5.0 (Darwin), aarch64. Build:
`npx tauri build --bundles app` at branch
`feat/zero-friction-api-tracking`. Script:
`scripts/tracking_validate_macos.sh`.

### The bundle now carries its helper

```text
target/release/bundle/macos/Tethra.app/Contents/MacOS/
  api-tracker-desktop   16580864 bytes
  tethra                11935184 bytes
```

Before this milestone the bundle contained only `api-tracker-desktop`, so
a fresh install could not perform the product's primary function. It now
ships the helper the tracking service runs.

### Result

```text
=== PACKAGED TRACKING VALIDATION (foreground mode): 42 passed, 0 failed (42 checks) ===
```

Preconditions enforced by the script itself, not assumed:

* `PATH` stripped to `/usr/bin:/bin:/usr/sbin:/sbin`, then asserted that
  no `tethra` is resolvable — so only the bundled helper can satisfy the
  run.
* A throwaway `TETHRA_DIR` under `/tmp`, a fresh vault, fake credentials
  only.

What passed, grouped:

| Group | Checks | What it proves |
|---|---|---|
| Preconditions | 5 | the app carries an executable helper; it answers the exec probe and reports a version; no CLI on PATH |
| Dry run | 5 | detection works; the exact diff is shown; **no file, service, or project is created**; no key value printed |
| One-command setup | 10 | routes created automatically; `.env` repointed; comments preserved; `NO_PROXY` added; one link row; one setup row; no shell-export choreography |
| Negative control | 4 | **not** `traffic_observed` before any request; no first-traffic timestamp; `track status` exits 2 |
| Real traffic | 2 | a keyless-then-keyed request reached the real provider through the gateway (401) and was recorded as a gateway observation |
| Verification | 3 | `track status` exits 0, state becomes `traffic_observed`, first-traffic timestamp set — **only after** the observation |
| Privacy canaries | 5 | no API-key value in `vault.db`, `-wal`, `-shm`, or logs; no authorization header stored |
| Idempotence | 3 | a second run changes no file and creates no duplicate link or setup row |
| Undo | 3 | `.env` restored byte for byte; link row removed; recorded history kept |

The observed path, verbatim from the run:

```text
base URL: http://127.0.0.1:63649/p/57ba2d21…/openai/v1
provider answered: 401
```

A 401 from `api.openai.com` to a request carrying a fake key proves
DNS → gateway → TLS → provider end to end. Provider acceptance is not
required and is not claimed.

### Mode, and what was not exercised

This run used **foreground mode**. The machine already had a gateway
LaunchAgent installed for the user, and the shipping label
(`dev.api-tracker.gateway`) is fixed — installing another would have
booted out and overwritten the user's own service. The script detects
this and starts the bundled helper's own `gateway serve` instead, which
is exactly the unsigned-build fallback path.

Consequently **LaunchAgent registration was not exercised in this run**.
It remains covered by:

* the mock-runner lifecycle suite (`crates/gateway/tests/lifecycle.rs`),
  which exercises install/register/start/repair/uninstall against a
  recorded command runner;
* `scripts/gateway_validate_macos.sh`, the pre-existing service-mode
  validation.

On a machine with no pre-existing agent the same script runs in service
mode and asserts the LaunchAgent was installed. Set
`TETHRA_VALIDATE_FOREGROUND=1` to force foreground mode deliberately.

### Signing

Builds are unsigned. Gatekeeper may refuse the background service on a
fresh download; the app detects that specific failure and offers
foreground tracking with its honest limitation ("tracking pauses when
Tethra closes"). Signing and notarization remain a release blocker for
public builds and the one genuinely external dependency — Apple
Developer ID credentials are not configured in this repository.

## Linux — not executed

systemd-user lifecycle is implemented and unit-tested against the mock
runner. No packaged Linux end-to-end run has been performed, here or
previously. Sidecar bundling is configured identically (the helper lands
beside the executable in AppImage/deb), but that is a configuration
claim, not an executed one.

## Windows — not executed

Unchanged from the previous milestone: the HKCU Run-key lifecycle is
compile-validated only on a real Windows runner in CI, and has never been
executed. Credential attribution is structurally unavailable on Windows
(no control channel; SI-21 refuses a TCP fallback). The supported mode is
foreground tracking, and the app says so.
