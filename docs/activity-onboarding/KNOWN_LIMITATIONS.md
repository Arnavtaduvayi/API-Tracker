# Known limitations

What Tethra's API-activity tracking does **not** do, or does only under
conditions worth stating. Written to be read before you rely on something,
not after it surprises you.

Everything here is either pinned by a test or reproducible by hand. Where a
limitation came out of the independent audit of PR #16, the finding id is
given so it can be traced.

---

## Provider coverage

**21 provider manifests; 13 are trackable.** 11 are configured
automatically, 2 need one destination confirmation, and 8 are detected but
cannot be tracked because their SDK exposes no base-URL environment
variable. `docs/activity-onboarding/DETECTION_COVERAGE.md` lists all three
groups by name, and `crates/core/tests/provider_manifests.rs` asserts the
counts, so this page cannot drift from the tree without failing the build.

**A provider outside those 21 is not tracked.** Its credentials are still
*listed* — as "not recognised", with the variable name and file, counted in
the coverage headline — so a review screen never implies coverage it does
not have (`ZFT-010`). But Tethra will not route it.

**Nothing in CI can verify a manifest's honesty.** A `[gateway]` section can
name a base-URL variable no SDK actually reads; the test suite checks the
*shape* of every declaration, not whether the provider honours it. Each of
the 13 was verified against the official SDK's own source and the source
recorded in a comment. A fourteenth added without that verification would
pass every test (`ZFT-011`).

**Two providers are honestly excluded rather than half-supported.**
`aws-bedrock` can never work through a loopback route in SigV4 mode, because
the signature covers the `Host` header. `huggingface` documents
`HF_INFERENCE_ENDPOINT`, but the current client does not read it.

## Scanning

**Global git ignore rules are not consulted.** The scan reads bytes rather
than running `git` (ADR 0023), and it reads repository-local ignore sources
only: `.gitignore` files and `.git/info/exclude`. A file ignored **solely**
by your `core.excludesFile` is reported as untracked rather than ignored.
This affects a warning, not a control.

**"Is this file in git history?" is not answered automatically.** It needs
an object-database walk. Automatic scans report it as *not checked* — never
as "no". Only `tethra env discover`, which you invoke deliberately against a
folder you named, runs the hardened `git log` probe.

**A hardlink escapes the folder bound.** A hardlink inside the selected
folder pointing at a file outside it is indistinguishable from an ordinary
file at the filesystem level and is read. Symlinks are refused; hardlinks
cannot be. Only variable names and dependency names leave the parse
(`ZFT-002`).

**The hardened-git key list is an enumeration.** Where Tethra still runs
`git` — the deliberate secret scanner, the pre-commit hook, the history
probe — it overrides every configuration key currently known to name a
program. A future git version could add a new execution surface the list
does not cover. This is precisely why the *automatic* path spawns nothing
at all rather than relying on the list (`ZFT-001`).

**A truncated scan is reported, not hidden.** A folder with more than 2000
environment files, more than 20 000 directories, more than 64 MB of
readable content, or one that takes more than 20 seconds, stops early and
says so. It does not silently return a partial answer (`ZFT-028`).

## Verification and status

**"Verified and active" expires after six hours of silence.** An
observation older than that reads as *"verified previously — last observed
…"*. A genuinely idle project looks exactly like a broken one from the
outside; Tethra chooses to under-claim (ADR 0025 D3).

**`track status` exits non-zero for "verified previously".** A script that
gates on tracking working must not be told yes while the service is down.

**A bulk read cannot assert present health.** Listing setups does not probe
the gateway per row, so those reads report history and never a present-tense
success claim.

**An incomplete undo leaves routes in place.** When a setup fails before its
plan was recorded, Tethra cannot tell which routes it created from which it
reused, so it restores the environment files it can prove it changed and
**refuses to report completion**, naming what was left behind. Reviewing
those routes under Advanced → Gateway is a manual step (`ZFT-007`).

## Service and multiple environments

**Moving a data directory orphans its service definition.** The service name
derives from the canonical data-directory path, so a moved directory gets a
new identity, and nothing removes the old plist / systemd unit / registry
value — the new identity cannot prove ownership of the old name, by design.
Recovery is `tethra gateway uninstall --data-dir <old path>` (ADR 0026).

**A data directory that cannot be resolved reports the wrong service name.**
If the directory does not exist yet, or sits on an unmounted volume, the
identity falls back to the literal path, so `gateway status` can report "not
installed" for a service that is installed and running.

**Windows service support is compile-validated only.** The registry
namespacing, ownership proof and legacy migration are exercised against an
in-memory mock `reg.exe`. None of it has run on a real Windows machine, and
every status surface says so.

**Two Tethra installations coexist; they do not cooperate.** Each has its own
service name, port, socket, logs and data. Neither can stop, replace or
reconfigure the other — the attempt is refused with an error naming the
other data directory. There is no shared coordination beyond that.

## Environment files

**`.env` files are forced to owner-only permissions.** `atomic_write`
creates the replacement 0600. A `.env` that another uid legitimately needs
to read will break after Tethra edits it. This is deliberate — a file
holding credentials should not be group- or world-readable — but it is a
behaviour change on a file you own (`ZFT-038`).

**A crash mid-write can leave a temporary file.** It is created 0600 and
unlinked on every error path, and a sweeper removes stragglers older than an
hour, but the window is bounded rather than eliminated.

**A tracked `.env` will carry Tethra's loopback URL into git.** If your
`.env` is committed, the rewritten base URL and its 128-bit link slug are
committed with it. Tethra warns when the file it is about to edit is tracked;
it does not refuse.

**The marker comment is written into your source tree.** Every line Tethra
owns carries a comment above it so you can find and remove it. It is shown in
the diff before anything is written.

## Platform

**The zero-terminal claim is verified on macOS arm64.** Windows and Linux
desktop builds compile and are covered by CI, but the packaged
install-and-track lifecycle has not been executed on either. See
`PACKAGED_VALIDATION.md` for exactly what ran where (`ZFT-044`).

**No macOS x64 desktop artifact is built.** The release matrix produces
arm64 desktop artifacts only; the x64 CLI archive is built (`ZFT-043`).

**Drag-to-Trash does not remove the login item.** Deleting `Tethra.app`
leaves `~/Library/LaunchAgents/dev.api-tracker.gateway.<id>.plist`; with the
data directory still present, the gateway keeps starting at every login with
the app gone. It exits cleanly rather than crash-looping, but it is an
orphaned Login Item. `docs/INSTALL.md` documents the uninstall step
(`ZFT-042`).

**Code signing and notarization are not configured.** macOS will treat the
build as unsigned, and Gatekeeper can refuse to execute the installed
helper. Tethra detects this with an exec probe *before* pointing a service
at the binary, and falls back to foreground mode with an honest message.

## Data that is stored in plaintext

The vault's credential values are encrypted. These are not, by design:

* **An approved custom origin** — a host name you were shown verbatim and
  approved, recorded so you are not asked again, and needed by undo
  (`ZFT-047`).
* **Detection evidence** — provider ids, confidence labels, variable
  *names*, dependency names and file paths.
* **The prior state of environment variables Tethra rewrote**, so undo can
  restore them exactly. Only non-secret configuration is recorded; a value
  that does not look like non-secret configuration is deliberately not
  stored, and undo reports it as a manual step instead.
