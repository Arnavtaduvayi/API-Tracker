# ADR 0027 — Repository configuration never participates in a Git read

Status: accepted
Date: 2026-07-27
Supersedes, in part: ADR 0023 §"Execution hardening"

## Context

ADR 0023 established that project *detection* runs no subprocess: `crates/core/src/gitsafe.rs`
reads `.git/index` and evaluates `.gitignore` in process. That part held. The
deliberate, user-invoked paths — the secret scanner, the history probe, and the
desktop's **background monitor** — still shell out to `git`, and ADR 0023
protected those with an enumeration: a list of `-c key=value` overrides naming
every configuration key known to turn a Git command into a program launch.

An independent re-audit of PR #16 (finding `RA-001`, CRITICAL) demonstrated that
the enumeration was incomplete, and exploitable today rather than
hypothetically:

```text
[log]
	showSignature = true
[gpg]
	program = ./payload.sh
```

A repository shipping that `.git/config`, plus any commit carrying a `gpgsig`
header, executes `payload.sh` as the user on the next `git log -p`. The
signature does not have to be valid — Git pattern-matches the header and then
hands the blob to the configured program. The auditor reproduced it twice:
against the exact hardened argv and environment, and end to end through product
code, with the canary writing `FIRED\n`.

Three properties of that failure decided this ADR:

1. **It was reachable with no user interaction.** Selecting a folder in the
   Track flow registers it as a monitored repo (`apply::ensure_project`); the
   desktop's background timer then calls `scan_repos_incremental` →
   `range_added_units` → `git log -p`. ADR 0023 said sandboxing was "worth
   revisiting if history traversal ever moves onto an automatic path". It had.
2. **The environment cannot switch repository config off.**
   `GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_SYSTEM` and `GIT_CONFIG_GLOBAL` cover the
   system and global files. The repository's own config *is* `$GIT_DIR/config`,
   and it is read because `$GIT_DIR` is the repository.
3. **An enumeration cannot be completed against a file the attacker writes.**
   Adding `log.showSignature` would have closed this instance. It would not have
   closed the next one, and the audit was right to say so.

## Decision

**Change `$GIT_DIR` instead of trying to out-argue it.**

Every isolated Git invocation runs against a *sealed Git directory*
(`crates/core/src/gitseal.rs`): a throwaway directory Tethra owns, containing
only

* a configuration file Tethra wrote,
* `objects/info/alternates` pointing at the real object store,
* copies of the refs, `HEAD`, and — for the commands that need it — the index.

Git is invoked as `git --git-dir=<sealed> …`. The repository's `config`,
`config.worktree`, and anything they `include` are not part of the repository
Git is looking at, so they cannot participate at all — not for keys we thought
of, and not for keys a future Git adds.

Objects are shared through `alternates`, which is Git's own read-only
object-sharing mechanism. The sealed directory's own `objects/` is the
*primary* (writable) store, so anything Git chooses to write lands in the
throwaway directory and never in the user's repository.

### What the seal reproduces, and what it refuses

Reproduced: `core.repositoryformatversion`, and an allowlist of `extensions.*`
keys with strictly validated values (`objectFormat` and `compatObjectFormat` ∈
{sha1, sha256}; `refStorage` ∈ {files, reftable}; `worktreeConfig`; Git's `noop`
placeholders). Linked worktrees and submodules resolve through `commondir`;
shallow clones carry their `shallow` file; `clone --shared` alternates chains
are followed.

Refused, loudly: any other `extensions.*` key, a `repositoryformatversion`
above 1, a symlinked `config`/`HEAD`/ref, and a ref set beyond the copy bounds.
A refusal is **never** retried against the repository's own configuration —
that is precisely the input this module exists to distrust — and it surfaces as
an error the caller reports as incomplete coverage.

### Two other changes fell out of it

* `repo_root` no longer spawns anything. It used
  `git rev-parse --show-toplevel`, which needs the work tree and so cannot be
  answered from a sealed directory; it now resolves in process through
  `gitsafe::discover`, which already handled `.git` files, `gitdir:` pointers
  and symlinks.
* `git_available` is bounded. It was the one unbounded spawn in the tree — a raw
  `.output()` with no timeout — so a wedged `git` on a dead network mount could
  hang Tethra at startup.

### The enumeration stays

`hardened_config()` is kept, extended (`log.showSignature`, `gpg.program`,
`gpg.<format>.program`, `gpg.ssh.allowedSignersFile`, `core.attributesFile`,
`gc.auto`, …), and demoted. It is a second, independent layer that costs
nothing, and it still covers the one read-through caller. It is **not** relied
on for completeness. `SCRUBBED_ENV` gained `GIT_EXEC_PATH` (where Git finds its
own subcommands — direct code execution), `GIT_COMMON_DIR`, `GIT_TEMPLATE_DIR`,
the `GIT_TRACE*` sinks, and three more `DYLD_*` loader hooks.

### The one documented exception

`config_get` must report the value Git itself would use — overriding a key and
then reading it back returns Tethra's own placeholder, which is how
`hooks install` once tried to write a pre-commit hook into `/dev/null`. It
therefore addresses the real repository with `-C` and leaves configuration
intact. `git config --get` reads and prints: it consults no fsmonitor and runs
no hook, filter, diff driver or signature verifier. The canary suite exercises
`config_get` against every vector for exactly this reason.

## Alternatives considered

**Add the missing keys and move on.** One line, and it closes the reproduced
vector — the auditor verified that `-c log.showSignature=false` alone stops both
the OpenPGP and the SSH variant. Rejected as the *primary* control because it
leaves the property "an attacker-written file is trusted unless we thought of
the key", which is what failed. Kept as the secondary layer.

**Copy the repository.** Correct and obviously safe, and unaffordable: a scan
would cost a full clone of the user's history.

**Symlink the object store and refs into a directory with our own config.**
O(1) instead of O(refs), and it fails: Git's repository validation rejects a
symlinked `HEAD` (`fatal: not a git repository`), measured on git 2.50.1.
Copying refs is also the safer shape — nothing can be written back through a
symlink into the user's repository.

**Sandbox the child process (seatbelt/landlock/seccomp).** Genuinely stronger,
and platform-specific, large, and hard to verify. Reconsider if Git ever needs
to be run against input we trust less than this.

## Security implications

* A hostile repository's `config`, `config.worktree`, and `include`/`includeIf`
  targets are structurally absent from the repository Git reads. This is a
  property of *where Git is pointed*, not of a list we maintain.
* `.gitattributes` inside the tree may still name a diff driver or filter, but
  the driver's *definition* lives in configuration that is now Tethra's, so the
  name resolves to nothing. `--no-ext-diff --no-textconv` remain as a third
  layer.
* Reads cannot modify the user's repository. Proven by
  `sealed_reads_never_modify_the_repository`, which digests every file under
  `.git` before and after.
* `safe.directory` no longer fires for a repository owned by another user,
  because the gitdir Git validates is ours. This is a behaviour change and a
  net improvement: `safe.directory` exists to stop exactly the hostile-config
  case that can no longer occur. Noted in `KNOWN_LIMITATIONS.md`.
* A repository using an unsupported extension loses history scanning entirely
  until support is added. That is the intended trade: an honest refusal beats a
  silent fallback to the attacker's configuration.

## How this is held

`crates/core/tests/git_isolation_canaries.rs` asserts three things per vector:

* **armed** — plain `git` running the product's own argv against the hostile
  repository *does* execute the payload;
* **sealed alone is enough** — the same argv against a sealed directory with
  **no `-c` overrides at all** does not;
* **the product is clean** — the real public functions do not, and still return
  correct results.

Every vector declared reachable must arm; the previous suite's
`armed.len() >= 2` of ten is gone, and every excused vector must carry a
specific measured reason (`every_unreachable_vector_states_a_specific_reason`).
Coverage includes `log.showSignature`, OpenPGP/SSH/X.509 verifier programs
(each with the matching signature header — Git picks the verifier from the
payload, not from `gpg.format`), repository-local config, `include.path`,
`config.worktree`, `core.fsmonitor`, textconv, diff drivers, hooks, filters,
pager, editor and credential helper, exercised across baseline scan, staged
scan, history scan, `git log -p`, the incremental range scan the background
monitor uses after `HEAD` advances, `config_get`, and `collect_full_repo_scan`.

## Future limitations

* The allowlist of reproducible `extensions.*` keys must grow as Git adds them,
  or those repositories lose history scanning. The failure mode is a refusal,
  not a compromise.
* Sealing costs one directory creation plus a bounded ref copy per invocation.
  `staged_units` builds one seal for a whole pass; a repository with more than
  `MAX_REF_FILES` loose refs is refused rather than scanned slowly.
