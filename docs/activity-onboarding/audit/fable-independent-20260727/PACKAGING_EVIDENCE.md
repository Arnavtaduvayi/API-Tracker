# Packaging Evidence — Independent Audit of PR #16

Host: macOS 25.5.0, `aarch64-apple-darwin`, `cargo 1.96.1`, `node 24.13.0`.
Everything below was executed in this session.

**Headline: the central packaging claim is TRUE.** The packaged desktop app ships
its own helper, uses it in preference to anything else, and works with no CLI on
PATH and the source repository deleted. The findings are peripheral.

---

## 1. Build, and what a missing sidecar does

A clean `cargo build --release --workspace` **fails loudly**:

```
error: failed to run custom build command for `api-tracker-desktop`
  resource path `binaries/tethra-aarch64-apple-darwin` doesn't exist
```

This is correct behaviour and is worth stating plainly: a fresh checkout
**cannot** silently produce a helperless app — it cannot build at all.
`binaries/` is gitignored, and `tauri_build::build()` exits 1 when `externalBin`
is unresolvable (`tauri-utils` `resources.rs:190` → `tauri-build` `lib.rs:56-84,
453-464`). CI stages the sidecar before desktop clippy (`ci.yml:117-118`).

The documented order works:

```
$ bash scripts/bundle_cli.sh
Building the CLI for aarch64-apple-darwin...
    Finished `release` profile [optimized] target(s) in 23.95s
Sidecar staged: …/binaries/tethra-aarch64-apple-darwin
Probe: OK

$ npm run tauri build -- --bundles app      → target/release/bundle/macos/Tethra.app
```

`ZFT-045` (INFO): the build-order dependency is not stated in `CONTRIBUTING.md`;
a new contributor's first `cargo build` fails with a message that does not name
`scripts/bundle_cli.sh`.

---

## 2. The bundle contains the helper — verified byte-for-byte

```
$ ls -la Tethra.app/Contents/MacOS/
-rwxr-xr-x  16580864  api-tracker-desktop
-rwxr-xr-x  11935184  tethra

$ shasum -a 256 …
cc15a1e96f1df50cd10fd8fcf774dbe2e2bdc79cb93cc7687559340712ce510b  Tethra.app/Contents/MacOS/tethra
cc15a1e96f1df50cd10fd8fcf774dbe2e2bdc79cb93cc7687559340712ce510b  target/release/tethra
cc15a1e96f1df50cd10fd8fcf774dbe2e2bdc79cb93cc7687559340712ce510b  binaries/tethra-aarch64-apple-darwin
```

Naming matches Tauri v2's convention exactly (`external_binaries` appends
`-{target_triple}`, plus `.exe` on Windows), and `bundle_cli.sh`'s default triple
comes from `rustc -vV`, which produced precisely this name.

Older worktree bundles in this repo contain only `api-tracker-desktop`,
corroborating that the sidecar is new in this milestone.

---

## 3. Works with no CLI on PATH and outside the repo

The app was copied out of the repository to simulate installation, then driven
with `env -i` and a stripped PATH:

```
$ env -i HOME=<clean> TETHRA_DIR=<clean>/data PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    <outside-repo>/Tethra.app/Contents/MacOS/tethra --version
tethra 0.1.0                                                        exit 0
```

Every user journey in `USER_JOURNEY_EVIDENCE.md` was executed this way.

**No dependence on `target/release/tethra`.** A repo-wide grep for
`target/release`, `target\release` and `CARGO_MANIFEST_DIR` returns **zero hits
in production code** — all eight hits are in test files. Resolution order
(`main.rs:2494-2525`): (1) `<exe dir>/tethra` inside the bundle, (2) files in
`<data-dir>/bin`, (3) each PATH dir, (4) `/usr/local/bin`, `/opt/homebrew/bin`,
(5) `~/.local/bin`, `~/bin`, `~/.cargo/bin`. First candidate passing
`helper_answers_probe` wins, so the bundled copy always wins when healthy.

---

## 4. Version matching — the weak spot

`helper_answers_probe` (`lifecycle/mod.rs:260-271`) checks only exit 0 plus
`stdout.contains("tethra-gateway-service-probe")`. The probe **prints** its
version (`gateway_cmd.rs:230-238`) and **no caller parses it**.

Drift is handled by comparing `service.binary_version` — parsed from the
installed **filename** `tethra-gateway-<version>` — against
`env!("CARGO_PKG_VERSION")` (`plan.rs:283-293`), scheduling `RepairService`.
But `installed_binary_path()` names the file using the *installing app's* version
regardless of the source binary (`lifecycle/mod.rs:230-232, 304, 327-329`). So if
the sidecar fails its probe and a stale genuine `tethra` on PATH wins, the
installed copy is stamped with the app's version and drift detection reports "no
drift" forever. (`ZFT-041`)

On drift the system never refuses — it warns and repairs on the next apply. Since
nothing runs repair at startup, an old-version service keeps running after an app
update until the user next uses the tracking flow.

**Corrupted / impostor helper** — `helper_discovery.rs` tests are *not* vacuous;
the negative tests assert real refusals:
`write_stub(&corrupted, "\u{0}\u{1}not an executable\u{2}", 0o755);
assert!(!helper_answers_probe(...))`, a valid script at mode `0o644` also
refused, a no-marker script refused, and *"marker printed but nonzero exit is
still a refusal"*. Two honest caveats: the version-drift test asserts
**acceptance** by design ("discovery must not hide a runnable helper"), and the
"genuine" fixture is itself a marker-printing shell script — which demonstrates
that the authenticity bar is "prints the marker". An accepted impostor is then
byte-copied to `<data-dir>/bin/` and becomes the LaunchAgent target. This sits
inside the repository's declared out-of-scope class (same-user malware,
`THREAT_MODEL.md:121,248-249`), and builds are unsigned so no signature check is
currently possible — but the gateway threat model never names the sidecar
specifically.

---

## 5. Per-user install, no elevation — clean

Greps for `sudo`, `osascript … administrator`, non-`~` `/Library/`, system
launchd domains and `/usr/local/bin` writes return **no production hits**.

* macOS: `launchctl bootstrap gui/<uid>` only; plist under
  `~/Library/LaunchAgents`, mode 0600, symlink-refusing fresh write.
* Linux: `systemctl --user` only; lingering is *reported*, never enabled.
* Windows: HKCU Run key via `reg`, explicitly "no elevation".
* CA trust: `security add-trusted-cert -r trustRoot -p ssl` **without `-d`** →
  login keychain, per-user.
* `/usr/local/bin` and `/opt/homebrew/bin` appear only as read-only probe
  candidates.

The only `sudo` in the repo is CI runner setup and a `sudo apt remove` line in
the optional `.deb` uninstall docs.

---

## 6. Path quoting — safe at every site

No shell strings anywhere. Repo-wide grep for `sh -c` / `bash -c` / `cmd /C`:
zero production hits. Every spawn is `Command::new(...).args([...])`.

* macOS plist: argv-array `ProgramArguments`, values through `xml_escape`
  (`&`, `<`, `>`) — spaces, quotes, `$`, newlines and unicode are all safe.
* systemd unit: `systemd_escape` handles `\`, `"`, `%%` and drops control chars.
* Windows Run value: quoted with trailing-backslash normalization
  (compile-validated only).
* `bundle_cli.sh`: `set -eu`, every expansion double-quoted, no `eval`.
  `bash -n` passes. (`shellcheck` is not installed on this machine; manual review
  found no word-splitting hazards.)
* `.env` link content interpolates only a `u16` port and a generated slug.

---

## 7. The LaunchAgent

`ProgramArguments = [<data-dir>/bin/tethra-gateway-<version>, gateway, serve,
--service, --data-dir, <data-dir>]` — it points at a **stable copied location
outside the .app**, so moving, updating or deleting the app does not break it.
That is the right design.

Two problems:

* **`ZFT-014` (HIGH):** `LABEL` is the fixed constant `dev.api-tracker.gateway`
  (`macos.rs:26`), and install does `bootout` → `bootstrap` on "already
  bootstrapped". One login slot per user, with no per-data-directory
  discrimination. Observed live: a real apply against an isolated data directory
  disabled this machine's running gateway serving the user's real vault. I
  restored it.
* **`ZFT-042` (LOW):** nothing removes the plist on a drag-to-Trash uninstall. If
  the data dir remains, the gateway **keeps running at every login with the app
  gone**; if the data dir is deleted, the service self-unloads but the stale
  plist remains and launchd fail-spawns each login. `PACKAGING_PLAN §7` claims
  the Advanced uninstall screen "notes that dragging the app to Trash … with a
  [Disable service first] button (this is today's behavior)" — a grep of
  `apps/desktop/src` finds **no such text or button**.

Update / repair paths exist in code (`prune_old_binaries`, `Lifecycle::repair`,
a UI Repair button, vanished-data-dir self-unload). In-app uninstall is
implemented and its dialog text is honest.

---

## 8. Cross-platform claims

| Claim | Reality |
|---|---|
| Windows behaviour validated | **No.** CI runs `cargo test` for three crates and `cargo build -p api-tracker-cli`. This is compile validation, and the repo says so loudly in code, the status enum (`RegisteredButNeverValidated`), doctor output, CI comments, and `PACKAGED_VALIDATION.md:103-109`. **Honest.** |
| Linux packaged run validated | **No** — stated verbatim as "not executed" in `PACKAGED_VALIDATION.md:95-101`. **Honest.** |
| macOS packaged validated | Manual, one local run, **foreground mode**; that run's own doc admits LaunchAgent registration was not exercised. See `VALIDATION_INTEGRITY.md`. |
| `docs/INSTALL.md:69-74` zero-CLI claim | Stated **unqualified for all platforms** while executed evidence covers macOS arm64 foreground only — `ZFT-044`. |
| `docs/PACKAGING.md:11` "macOS (arm64 + x64)" | Release desktop matrix is `[macos-latest, ubuntu-latest, windows-latest]`; `macos-latest` is arm64, there is no x64 or universal desktop job. Only the **CLI** builds `x86_64-apple-darwin`. Intel Mac users get no desktop app — `ZFT-043`. |

CI **never builds a packaged app on any platform** — the desktop job is
clippy-only. `release.yml:108-109` does correctly stage the sidecar on all three
desktop matrix entries before `tauri-action`, so no shipped platform lacks the
helper.

---

## 9. Test coverage gap

`apps/desktop/src-tauri/src/main.rs` contains **zero** tests. `helper_discovery.rs`
covers candidate-path derivation and the probe, but **nothing asserts "sidecar
beats PATH"** — a regression reordering `locate_cli` would ship undetected
(`ZFT-041` sibling). The candidate-list builder is already 90 % in the gateway
crate and could be extracted and tested there.
