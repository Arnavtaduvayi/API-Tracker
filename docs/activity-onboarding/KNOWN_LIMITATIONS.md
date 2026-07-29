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

**Repository configuration cannot participate in a Git read — but the
seal has edges.** Where Tethra runs `git`, it runs against a *sealed* Git
directory holding only Tethra's own configuration plus a pointer at the
repository's object store (ADR 0027). The repository's `config`,
`config.worktree`, and anything they include are structurally absent, so a
hostile repository cannot name a program for Git to run. The enumerated
`-c` overrides are kept as a second layer, no longer relied on: an
enumeration is what `RA-001` defeated, with `log.showSignature` plus
`gpg.program` executing a repository's chosen binary on `git log -p`.

Two consequences worth knowing:

* **A repository using a Git extension Tethra cannot reproduce is refused,
  not scanned.** The allowlist covers `objectFormat`, `compatObjectFormat`,
  `refStorage`, `worktreeConfig` and Git's `noop` placeholders. Anything
  else — a partial clone, a future extension — loses history scanning until
  support is added. The failure is a loud refusal; Tethra never falls back
  to running Git against the repository's own configuration.
* **`safe.directory` no longer applies.** Git's dubious-ownership check
  validates the gitdir it is pointed at, which is now Tethra's. A
  repository owned by another user is therefore read where it previously
  errored. This is a net improvement — `safe.directory` exists to prevent
  exactly the hostile-config execution that the seal makes impossible — but
  it is a behaviour change.

**A repository with more than 20 000 loose refs is refused.** Sealing copies
refs, under explicit count and byte bounds. Packed refs are one file and do
not count against it.

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

**An observation dated more than five minutes ahead of this machine's clock
is ignored.** Stored timestamps are untrusted input: they are written by
another process and read against a different clock. `RA-005` showed a
one-sided freshness window letting a future-dated row read as a present-tense
success indefinitely — and, being the largest timestamp in the table,
out-rank a failure recorded *now* and erase its reason. Observations outside
the window are excluded rather than clamped, and admissibility additionally
requires an insertion-ordered watermark that no writer's clock can influence.

Consequences:

* If your machine's clock jumps **backward** (an NTP step-back, a restored
  VM snapshot), observations written before the jump look like the future
  and stop counting. Tracking reads as *not currently verified* rather than
  claiming success from evidence it cannot place in time. It recovers on its
  own once real traffic arrives after the new clock.
* If the gateway service and the desktop app disagree about the time by more
  than five minutes, verification will not settle. That is a real
  misconfiguration, and Tethra prefers saying so to guessing.
* A failure recorded now is never erased by an anomalous observation. When
  the two cannot be ordered, the failure wins.

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

On macOS that lifecycle is now executed **with a real login-registered
service**, on a disposable hosted runner, on every PR:
`.github/workflows/packaged-service-macos.yml` runs
`--scope full --require-service` (63 checks) and
`gateway_validate_macos.sh` (56 checks on the audited CI run; the total is
machine-dependent and is gated by a floor, not an equality gate — see `VAL-05`),
and verifies teardown from outside
the script. Evidence: `audit/SERVICE_VALIDATION_EVIDENCE.md`.

**One green run is one green run.** That scope first passed on 2026-07-28
(run `30325704492`). It is repeatable and gated, but it does not yet have a
long baseline, and its first three executions each found a harness defect
(`REM-003`, `REM-004`, `REM-005`). Treat early results with the suspicion a
newly-exercised path deserves.

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

The CI service job runs against an **unsigned** bundle for the same reason:
no signing identity exists on a hosted runner. So it proves the lifecycle
works for the unsigned build a private-alpha user actually gets, and proves
nothing about Gatekeeper behaviour for a signed one.

**`NetworkClass::Restricted` is a reserved classification, not a reachable
state.** No code path produces it: `origin::describe` refuses a loopback,
private, link-local or metadata destination outright rather than describing
it, so the user is never shown a classification for a destination that could
not work. The variant is kept so the `match` stays total — a single-variant
enum would make `Public` the unconditional answer, and the day the
destination policy is relaxed the classification would silently become a
false statement instead of a compile error, which is the shape of `RA-011`.
The reservation is checked rather than asserted: `origin_trust.rs` pins that
twelve spellings of a restricted destination are refused, with a public
origin as the anti-vacuity control.

## Data that is stored in plaintext

The vault's credential values are encrypted. These are not, by design:

* **An approved custom origin** — a host name you were shown verbatim and
  approved, recorded so you are not asked again, and needed by undo
  (`ZFT-047`).
* **Detection evidence** — provider ids, confidence labels, variable
  *names*, dependency names and file paths.
* **The *structure* of what Tethra rewrote in an environment file** — which
  file, which variable, whether the file existed, and what Tethra wrote.
  The **values** are not plaintext: every recorded prior value is encrypted
  under a vault-wrapped key (ADR 0028), because the previous design decided
  what was safe to store from a value's *shape* and classified a Supabase
  service-role JWT as safe (`RA-006`).

  Consequences:

  * A user who loses their vault password loses *automatic* restore for
    links made before that point. The structural record survives, so the
    change can be undone by hand, and `unlink` says so rather than claiming
    a restore it did not perform.
  * Restore records written by builds before this change hold plaintext.
    They are re-sealed the next time the vault is unlocked — from the
    **desktop app** as well as the CLI. Until `ENC-01` that migration had no
    desktop call site at all, so a user who never opened a terminal kept the
    plaintext indefinitely; ADR 0028 claimed otherwise. Until an unlock
    happens the records remain as they were, because deleting them without a
    key would take away an undo that a later unlocked run can still preserve.

    **What the re-seal does and does not reach.** After the migration commits,
    the WAL is checkpointed and truncated, and `secure_delete` overwrites freed
    pages inside the database file. Measured: no copy of the value remains in
    `vault.db`, `vault.db-wal` or `vault.db-shm`. It does **not** reach free
    space elsewhere on the volume, a filesystem snapshot, a Time Machine copy,
    or any backup taken before the upgrade. Encrypted-at-rest storage protects
    those; this migration does not.

* **The consent diff shows a declared base URL's current value verbatim.**
  When Tethra is about to replace `OPENAI_BASE_URL`, the removed line is
  shown unmasked, because seeing exactly what is being replaced is the
  point of the approval screen (ADR 0019 D9). Every other removed value is
  masked. This is an on-screen disclosure of your own file to you; it is
  never persisted.


## Gateway availability under slow request bodies

A request **body** is bounded by an absolute deadline of 300 seconds
(`CLIENT_BODY_DEADLINE`), checked between reads — so the true worst case is
that deadline plus one 60-second idle timeout. With `MAX_CONNECTIONS` at 128, a
client opening many slow-body connections can still make the gateway
unavailable to your own applications for up to that long (`SEC-02`).

The gateway listens on loopback only, fails closed with `503` rather than
queueing without limit, and recovers by itself once the connections expire. No
credential, no observation and no stored data is affected — this is an
availability limit, stated because it is real rather than because it is
serious.

A streaming **response** is deliberately not bounded this way. A long model
completion is a legitimate long-lived read; capping it would break streaming.
