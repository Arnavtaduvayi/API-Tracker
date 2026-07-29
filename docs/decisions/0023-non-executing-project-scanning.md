# ADR 0023: Project scanning must not execute code the project controls

Status: accepted (2026-07-27) — remediation of ADR 0022 following the
independent audit of PR #16 (`ZFT-001` CRITICAL, `ZFT-002`, `ZFT-003`,
`ZFT-028`, `ZFT-040`).

Amends ADR 0022 D5 (selected-folder detection). Changes no security
mechanism in ADR 0019/0020/0021.

## Context

ADR 0022 D5 promised that detection is "parse-only: nothing is executed".
The source said so too (`detect.rs:12`), the coverage document said so
(`AUTOMATIC_PROVIDER_DETECTION.md:141`), and the banner printed to the user
during a scan said *"this folder only; nothing executed or uploaded"*.

The independent audit reproduced arbitrary code execution from a folder
scan, four times, during `--dry-run` — the mode that additionally promises
*"Dry run: nothing was changed."* We reproduced it again against a release
build before changing anything:

```text
$ git init -q . && git config core.fsmonitor "$PWD/payload.sh"
$ tethra track "$PWD" --dry-run
Scanned: …  (this folder only; nothing executed or uploaded)
$ cat PWNED.txt
PAYLOAD EXECUTED argv=2      (x4)
```

The mechanism: `envgov::discover` asked git four questions per discovered
file (`rev-parse --is-inside-work-tree`, `ls-files --error-unmatch`,
`log`, `check-ignore`). Git is not a passive reader. The **scanned
repository's own** `.git/config` can name programs git executes during
commands that look read-only — `core.fsmonitor` is consulted by `ls-files`,
`status` and `diff`; external diff drivers and `textconv` run during
`log -p` and `show`; pagers, editors, credential and askpass helpers run
when git decides it needs them. `safe.directory` does not help: it fires
only for repositories owned by a *different* user, and a repository the
user cloned or extracted is owned by the user.

In the desktop app the scan fires the instant a folder is picked, so the
trigger was **clicking a folder** — before any confirmation — and the
product's central call to action invites users to point it at project
folders, which developers routinely clone from the internet.

Three existing tests appeared to cover this. `bounds.rs:238`
`detection_source_makes_no_network_calls` is a textual `include_str!` grep
of one file; `bounds.rs:172` `env_files_are_parsed_never_executed` proves
only that the *env parser* does not shell out. Both passed while the
payload executed.

## Decision

### D1. The automatic scan path spawns no subprocess at all

Everything a scan needs to know about a repository — is this path inside a
work tree, is a file tracked, is a file ignored — is computed by reading
bytes, in a new `core::gitsafe` module:

* `.git` resolution, including a `.git` **file** containing `gitdir: <path>`
  (linked worktrees and submodules), bounded to 8 indirections;
* `.git/index`, parsed as the documented `DIRC` binary format — versions 2,
  3 and 4 (including version 4's path prefix compression and git's
  `decode_varint`), for both SHA-1 and SHA-256 object ids. The object-id
  length is not recorded in the header, so both are attempted and the
  parse is self-validating: what follows the entries must be the trailing
  checksum alone or a plausible extension header;
* an in-process `.gitignore` evaluator implementing git's precedence —
  `.git/info/exclude`, then `.gitignore` from the work-tree root down, last
  match wins, `!` negation, directory-only patterns, anchoring, `**`,
  character classes, trailing-space rules, and the rule that a file inside
  an excluded directory stays excluded.

**Why not a dependency.** `ignore` (ripgrep's crate) or `gix` would answer
the same questions. Both pull a substantial transitive tree into a crate
that is `forbid(unsafe_code)` and deliberately minimal, and neither
answers the index question we actually need without also pulling in an
object-database implementation. The reader is ~600 lines, is exercised by
a differential test against real git, and adds nothing to the lockfile.

**Why this is testable rather than asserted.** `tests/gitsafe_differential.rs`
builds repositories with the real `git` binary and requires the two
implementations to agree on tracked / ignored / untracked, nested
`.gitignore` precedence, `info/exclude`, and a version-4 index. A corrupt
index degrades to `Unknown` and says so rather than guessing.

### D2. Where git is still necessary, it runs under argument and environment isolation

The deliberate, user-invoked secret scanner (`tethra scan`, the pre-commit
hook, `tethra env discover --check-history`) genuinely needs git: history
traversal requires the object database. Those spawns now carry:

* `-c` overrides for every configuration key that names a program —
  `core.fsmonitor`, `core.hooksPath`, `core.pager`, `core.editor`,
  `sequence.editor`, `diff.external`, `credential.helper`, `core.askPass`,
  `protocol.ext.allow`, `core.gitProxy`, `core.sshCommand`. Command-line
  `-c` beats every configuration file, so this neutralizes a hostile
  repository-local config as well as a hostile global one;
* `--no-ext-diff --no-textconv` on every diff-producing command, because
  `.gitattributes` is attacker-controlled too;
* `--no-pager`, `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`,
  `GIT_CONFIG_COUNT=0`, `GIT_TERMINAL_PROMPT=0`, `GIT_OPTIONAL_LOCKS=0`;
* an environment scrubbed of the variable-shaped equivalents
  (`GIT_EXTERNAL_DIFF`, `GIT_PAGER`, `GIT_ASKPASS`, `GIT_SSH_COMMAND`, …),
  the state variables that would redirect git at another repository
  (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, …), and the dynamic-loader
  hooks (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, …);
* a controlled working directory — deliberately **not** the scanned
  repository, because a cwd inside the target changes which configuration
  git consults and would mask the very vectors the canary suite exists to
  catch (we measured this: the `core.fsmonitor` canary fires from outside
  the repository and stays quiet from inside it);
* the pre-existing timeouts, output caps, and child reaping.

`config_get` is the single documented exception: its contract is to report
the value git itself would use — including one set globally — so it runs
with the environment hardening but without the `-c` overrides and without
config-file isolation. Overriding a key and then reading it back returns
Tethra's own placeholder, which is how `hooks install` briefly tried to
write a pre-commit hook into `/dev/null`.

### D3. Every reader is bounded, and every bound is reported

Depth was the only bound. A folder can also hold unbounded files,
unbounded bytes, and take unbounded time. `DiscoveryLimits` bounds files,
directories, per-file bytes, total bytes and wall clock, and the per-file
size check happens on the **directory entry, before the file is opened** —
the previous code read a 64 MB file named `.env` in full (447 MB RSS) and
then reported `0 file(s) read`.

A truncated scan reports `DiscoveryTruncation` and is never presented as a
complete one. Every reader reports into one `ScanAccounting` whose buckets
the review screen renders, so "0 file(s) read" can no longer appear over
content that drove the plan.

### D4. Containment is checked by every reader, not by one of them

`detect::read_bounded` refused symlinks and canonicalized under the root.
`stackdetect::read_bounded` used `std::fs::metadata` — which follows
symlinks — with no containment check at all, and it is the reader for
`package.json`, `requirements.txt` and `pyproject.toml`. A symlinked
`package.json` pointing outside the folder became auto-selected providers.
Both readers now apply the same three refusals, and existence probes go
through `is_contained_file`/`is_contained_dir` because `Path::is_file`
follows symlinks too.

## Consequences

**Accepted limitations, recorded in `KNOWN_LIMITATIONS.md`:**

* The non-executing reader does not consult `core.excludesFile`, so a file
  ignored **solely** by the user's global ignore list is reported
  `Untracked` rather than `Ignored`. This affects a warning, not a control.
* It does not answer "has this file ever been committed?" — that needs an
  object-database walk. Automatic scans report `NotChecked`; only the
  explicitly invoked `tethra env discover` asks for the hardened probe.
* A **hardlink** to a file outside the folder is indistinguishable from a
  real file inside it at the filesystem level and is still read.
* The hardened runner's key list is an enumeration. A future git version
  could add a new execution surface it does not cover. This is why the
  automatic path spawns nothing at all rather than relying on it, and why
  `tests/git_execution_canaries.rs` includes
  `each_canary_is_armed_against_unhardened_git` — a control that runs the
  unprotected equivalent and **requires the canary to fire**, so the suite
  cannot pass by having quietly stopped exercising the vector.

**User-visible consequences:** none on the supported path. Detection
results are unchanged for every fixture in the suite, and the scan is
faster (one index parse instead of four process spawns per file).

## Alternatives considered

* **Harden git and keep spawning it.** Rejected as the primary control:
  it requires an open-ended enumeration to stay correct, and the
  CRITICAL finding was reachable from clicking a folder. Kept as
  defence in depth for the paths that genuinely need git.
* **Refuse to scan repositories with unusual git configuration.** Rejected:
  it makes a hostile repository's own configuration able to deny service,
  and "unusual" is not decidable without reading the config that a
  non-executing reader deliberately does not read.
* **Run git in a sandbox** (`sandbox-exec`, seccomp, a container).
  Rejected for v1: platform-specific, and the non-executing reader removes
  the need on the path that mattered. Worth revisiting if history
  traversal ever moves onto an automatic path.
