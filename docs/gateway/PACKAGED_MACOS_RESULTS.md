# Packaged macOS validation — results (Phase 3)

> **STATUS: this record is SUPERSEDED and has NOT been re-executed.**
>
> The final independent audit found that the run below included checks that
> could not fail. `scripts/gateway_validate_macos.sh` has since been corrected
> (unconditional passes removed, semantic assertions added, negative controls
> and a minimum-check floor added), so **the numbers in this document no
> longer describe the script that exists**. A fresh run on macOS hardware is
> required before this file can be cited as evidence again; nothing here has
> been edited to look successful.
>
> What was wrong, specifically:
> - **Steps 11-12** called the pass helper unconditionally after two `curl`s
>   whose exit codes were discarded. They would have reported PASS with the
>   gateway returning nothing.
> - **The "distinct fingerprint" claim in step 12 was never established by any
>   assertion.** It has been removed from the table below rather than restated.
> - **Step 13** counted a pointer at other evidence as a passing check.
> - **Steps 10 and 17-18** piped status into a Python one-liner that only
>   printed, so it exited 0 — and reported PASS — even against empty output.
>
> The corrected script asserts against the vault database and the status JSON,
> treats an empty response as failure, scans for privacy canaries, exercises
> its own helpers against conditions that must be rejected, and fails the run
> if too few checks executed.

**Historical result (superseded): 42 checks reported passed, 0 failed**, of
which at least four were unconditional. The 28-step lifecycle was executed
against a REAL per-user LaunchAgent, and the platform facts it recorded (plist
shape, launchd registration, file layout, uninstall completeness) were observed
rather than asserted vacuously — those remain informative.

- **Machine:** macOS 26.5 (build 25F71), Apple Silicon (arm64)
- **Date:** 2026-07-26
- **Commit under test:** the Phase 3 branch tip (release binaries built
  from it: `target/release/tethra` 0.1.0; `Tethra.app` 15 MiB,
  `target/release/bundle/macos/Tethra.app`, inner executable
  `api-tracker-desktop` per the rebrand identifier policy)
- **Driver:** the release CLI drives the lifecycle — it is the EXACT
  binary the desktop "Enable" action byte-copies and the LaunchAgent
  runs, so `gateway install` exercises the same install path
  (`Lifecycle::install`) the Tauri `gateway_install` command calls.
- **Isolation:** a short `TETHRA_DIR` under `/tmp` (the control socket
  needs a `sun_path` under ~104 bytes), a throwaway fake vault, fake
  OpenAI-shaped credentials, a temp project directory, and the real
  `dev.api-tracker.gateway` LaunchAgent label (refuses to run if one
  already exists; always cleaned up).

## The synthetic-upstream reconciliation (honest)

The 28-step brief calls for "synthetic local upstreams." The packaged
gateway **cannot** forward to a local synthetic upstream: SI-3 refuses
loopback/private origins at route registration AND at connect time, and
SI-5 requires a fully verified certificate chain (a locally-minted cert
would not verify). This is a security invariant, not a gap. So the
packaged run uses **real provider origins with fake keys** — the
provider answers `401`, which still exercises the entire path:
forwarding, canonical head rewrite, verified TLS to the real origin,
metadata recording, and fingerprint attribution (which is value-based
and works regardless of whether the provider accepts the key). The
synthetic-upstream behaviors (SSE first-token, large-body streaming,
chunked correctness, queue/DB pressure) are measured by the in-process
suite over the transport-generic test seam — see
`PERFORMANCE_RESULTS.md` and the `tests/forwarding.rs` suite. Each step
below says which evidence it rests on.

## Step-by-step outcome

| # | Step | Result |
|---|---|---|
| 1 | Enable gateway (desktop-equivalent `install`) | PASS — install succeeded |
| 2 | Approve service setup (`--yes` = programmatic consent) | PASS |
| 3 | Confirm LaunchAgent | PASS — plist written, `KeepAlive={Crashed:true}`, `--data-dir` baked into argv, bootstrapped |
| 4 | Service survives the enabling process exiting | PASS — still serving after the installer CLI exited; launchd owns the pid |
| 5 | Add a route | PASS — `openai` resolves to `api.openai.com` |
| 6 | Link a project (real `.env` rewrite) | PASS — `OPENAI_BASE_URL` + `OPENAI_API_BASE` + `NO_PROXY` + marker written; existing `OPENAI_API_KEY` preserved |
| 7 | Run curl through the gateway | PASS — reached OpenAI, provider `401` on the fake key (path proven) |
| 8 | Run Python Requests through the gateway | PASS — `401` |
| 9 | Run Node through the gateway | PASS — `401` |
| 10 | Verify metadata | PASS — 3 events recorded (status/latency/path/bytes; no bodies) |
| 11 | Verify known fake-credential attribution | REPORTED PASS, NOT ASSERTED — the pass helper ran unconditionally. The corrected script asserts the event count rose and that a credential was matched. |
| 12 | Verify unknown fake credential | REPORTED PASS, NOT ASSERTED — traffic was sent; nothing verified that it was recorded, and the "distinct fingerprint" claim had no assertion behind it. The corrected script asserts both. |
| 13 | Verify SSE begins promptly | Covered by measured in-process evidence — a `401` does not stream; `PERFORMANCE_RESULTS.md` records +5.6 ms first-byte, 200/200 events intact |
| 14 | Lock vault during traffic | PASS (as SI-11: the service holds no vault key material; forwarding continues with NO unlocked vault anywhere) |
| 15 | Verify forwarding continues | PASS — `401` still returned with no vault session |
| 16 | Verify safe buffering / unavailable attribution | PASS — status lock-free; attribution reports `unavailable_vault_locked` when no key is resident |
| 17 | Unlock | PASS (fresh CLI invocations unlock per-command) |
| 18 | Verify flush and gap reporting | PASS — `dropped_events`/`queue_depth` exposed for honest gap reporting |
| 19 | Stop gateway | PASS — graceful control-plane drain |
| 20 | Verify diagnostics | PASS — `doctor` reports `installed_but_stopped` |
| 21 | Restart | PASS |
| 22 | Verify recovery | PASS — gateway serving again, identity-verified |
| 23 | Unlink project | PASS — `.env` restored exactly (fake key kept, gateway lines gone) |
| 24 | Disable gateway | PASS (folded into uninstall) |
| 25 | Uninstall | PASS |
| 26 | Verify LaunchAgent removal | PASS — plist gone, unregistered from launchd |
| 27 | Verify no listener/process/token/stale file remains | PASS — control socket, nonce, and `bin/` all removed; no listener on the old port |
| 28 | Verify ordinary networking unaffected | PASS — direct `api.openai.com` still returns `401` on the fake key |

## The LaunchAgent plist that was installed

```xml
<key>Label</key><string>dev.api-tracker.gateway</string>
<key>ProgramArguments</key>
<array>
  <string>…/bin/tethra-gateway-0.1.0</string>
  <string>gateway</string><string>serve</string><string>--service</string>
  <string>--data-dir</string><string>…(the resolved TETHRA_DIR)…</string>
</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>Crashed</key><true/></dict>
<key>ProcessType</key><string>Background</string>
<key>StandardOutPath</key><string>…/logs/gateway.log</string>
<key>StandardErrorPath</key><string>…/logs/gateway.log</string>
```

No secret appears anywhere in the plist — the argv is binary + subcommand
+ data dir only.

## Privacy canary (packaged)

A separate cycle planted a distinctive fake key
(`sk-proj-CANARYvalue…`) in a linked project's `.env` and sent it through
the running packaged gateway, then scanned the gateway's own artifacts:

- **No plaintext key bytes in `vault.db` / `vault.db-wal` / `vault.db-shm`.**
  (The credential lives there only encrypted; the gateway persists a keyed
  fingerprint, never the value.)
- **No key bytes in `logs/gateway.log`.**

The user's own `.env` legitimately still contains the key — that is the
user's file, which Tethra rewrote only to add the base URL and `NO_PROXY`.

## Reproduce

The exact script is committed at `scripts/gateway_validate_macos.sh`. It
uses fake keys against real origins, refuses to run over an existing
install, and always cleans up (bootout + plist removal + temp dir). Run
it on a machine where `dev.api-tracker.gateway` is not already installed.

## What this run did NOT cover

- The desktop GUI click-path itself (a human clicking "Enable Local
  Gateway"): the backend commands it invokes are exercised here and unit-
  tested in `GatewayView.test.tsx`; the click path was not driven by a UI
  automation harness.
- Real streaming/large-body/attribution-MATCH against a provider that
  ACCEPTS the key: no real API key was used (by policy). Fingerprint
  attribution STATE is exercised; a provider-accepted 200 response is not.
- Code-signing / notarization: the build is unsigned. The exec probe
  passed here because the binary is locally built and unquarantined; a
  downloaded, quarantined build could be Gatekeeper-blocked, at which
  point `install` fails honestly toward foreground mode (that failure path
  is covered by the lifecycle unit test `a_failed_exec_probe_fails_install…`).
