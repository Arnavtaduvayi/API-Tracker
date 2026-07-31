# ADR 0026: One service slot per data directory, and prove ownership before touching it

Status: accepted (2026-07-27) — remediation of ADR 0019 D8 following the
independent audit of PR #16 (`ZFT-014`).

Amends ADR 0019 D8 (per-user OS service lifecycle). Changes no forwarding
or authorization mechanism.

## Context

ADR 0019 D8 gave each platform one fixed login-start identifier:

```rust
pub const LABEL: &str = "dev.api-tracker.gateway";        // macOS
pub const UNIT_NAME: &str = "tethra-gateway.service";     // Linux
pub const VALUE_NAME: &str = "TethraGateway";             // Windows
```

The comment beside the macOS constant read *"Fixed (one login slot per
user)"*, which is a true statement about launchd and a false premise for
Tethra: a user can have more than one Tethra **data directory**, and the
product's own validation script creates one.

**This is not theoretical. It happened during the audit.** A subagent ran a
real `tethra track --yes` against an isolated data directory and it booted
out the machine's live gateway service, which was serving the user's real
vault. The auditor detected the loss and restored it manually.

The mechanism: the plist **path** derives from `$HOME`, but launchd's
domain target is the real `gui/<uid>` regardless of which `HOME` the plist
was read from. A second environment with its own `HOME` saw no plist of its
own — so `install()`'s different-data-directory refusal never fired,
because `read_definition()` returned `None` — wrote its own plist, called
`register()`, got "already bootstrapped", and took the documented
bootout-then-bootstrap path against the **other** environment's live job.

Linux and Windows have the same shape: the systemd *user* manager is
per-user, not per-`XDG_CONFIG_HOME`, and HKCU `Run` is one namespace.

An independent reproduction found the surface wider than the audit
described: `gateway stop`, `gateway uninstall` and `gateway install --force`
gated only on `status().installed` and never on `matches_data_dir`, and
`uninstall` additionally called `remove_definition()`, which **deletes**
another environment's definition file.

## Decision

### D1. Service names are namespaced by the data directory

`installation_id(data_dir)` is the first 12 hex characters of
`blake3::derive_key("tethra gateway service installation id v1", <canonical
data dir>)`. Canonicalization means `/tmp/x` and `/private/tmp/x`, or a path
reached through a symlinked home, are **one** identity rather than two
services fighting over one port.

`derive_key` rather than `hash`: the input is a filesystem path, not
credential material, and saying so in the primitive keeps the gateway
crate's blanket ban on unkeyed `blake3::hash` intact
(`tests/privacy_canaries.rs`) instead of carving an exception into a rule
that exists to stop a stolen database becoming an offline
guess-confirmation oracle.

```text
macOS    dev.api-tracker.gateway.<id>
Linux    tethra-gateway-<id>.service
Windows  TethraGateway-<id>
```

The pre-namespacing names are retained as public `LEGACY_*` constants —
migration needs them.

### D2. A name is not ownership: prove it before every destructive verb

`ServiceManager::ensure_ours(verb)` re-reads the definition it is about to
act on and requires it to point at this data directory, via `same_data_dir`
— a deliberately conservative equality (literal equality, or both paths
canonicalize to the same real directory; anything it cannot **positively**
prove equal is treated as foreign).

It guards `unregister`, `stop`, `restart`, `remove_definition`, and also
`start` and `register`. `start`/`register` are not destructive, but on
macOS `start` falls back to `register`, which `bootstrap`s a plist into the
live `gui/<uid>` domain; on Linux `register` runs `systemctl --user enable`,
creating a login-start symlink; on Windows `start` spawns the definition's
binary with its own `--data-dir`. Each is "reconfigure another
environment's service" by any reading.

A foreign definition produces an error naming both data directories. An
**absent** definition is not an error — there is nothing to destroy.

An **unparseable** definition is treated as foreign, not absent.
`reclaim_legacy` already stated this rule in as many words; `install` did
not follow it, and silently unlinked and overwrote a definition it could
not parse.

### D3. `repair` does not force

`Lifecycle::repair` called `install(binary, true)`. Repair is reached
**automatically** from the `tethra track` apply path whenever the installed
helper's version differs from the running build — no user decision behind
it. Forced, it walked past the different-data-directory refusal, wrote our
definition over the other installation's, and then, because the slot now
parsed as ours, passed the ownership proof on the way to booting that
installation's gateway out. That is the original finding, reached from the
automatic path. `repair` is now unforced, and the planner treats
`installed && !matches_data_dir` as a **hard stop** naming the other data
directory rather than falling through to repair-or-start.

### D4. Migration is one-sided, and rolls back

On install, a legacy-named definition is retired **only** when it points at
this data directory: booted out, deleted, and recorded in
`InstallReport.notes`. A legacy definition pointing elsewhere is left
completely alone and is not an error.

Ordering: after the exec probe and after writing the new definition, before
`register()`. Earlier would leave a user with no gateway after a failed
probe; later would race two definitions for one port. If migration or
registration then fails, the newly written definition is **removed** —
launchd loads every plist in `~/Library/LaunchAgents` with `RunAtLoad` at
login regardless of bootstrap state, so leaving ours beside an un-retired
legacy one would give one vault two gateways fighting over one port, with
no warning and no way back.

### D5. Status says which installation it is controlling

`ServiceStatus` carries `installation_id` and `service_name`, and the CLI
prints both, so a user with two environments can tell which launchd label,
systemd unit or registry value is being controlled. The installed helper's
version is now **measured** by running its exec probe rather than read out
of the file name this build stamped on it (`ZFT-041`), with
`binary_version_measured` saying which answer it is.

## Consequences

**Accepted limitations, recorded in `KNOWN_LIMITATIONS.md`:**

* **Moving a data directory orphans its definition.** The id derives from
  the canonical path, so a moved directory gets a new identity and nothing
  removes the old plist/unit/registry value — the new identity cannot prove
  ownership of the old name, by design. Before namespacing, the single
  global slot self-healed on the next install. `tethra gateway uninstall
  --data-dir <old path>` is the documented recovery.
* **A data directory that does not exist yet** cannot be canonicalized, so
  `installation_id` falls back to the literal path. Every install path
  creates the directory first, but a `status` call against an unresolvable
  path (unmounted volume, EACCES on a parent) reports a service name
  derived from the literal path and will say "not installed" for a service
  that is installed.
* 12 hex characters is 48 bits. A collision between two data directories on
  one machine is not a practical concern, and `ensure_ours` catches the
  consequence anyway — the colliding definition names a different data
  directory and is refused — but a collision would mean the second
  environment cannot install without `--force`.
* **Windows remains compile-validated only.** The registry namespacing,
  ownership proof and legacy reclaim are exercised against an in-memory
  mock `reg.exe`; none of it has run on a real Windows machine.

**Upgrade path for existing users:** the first `install`/`repair` after
upgrading retires the legacy service and installs the namespaced one, and
says so in its notes. A user with exactly one Tethra installation — every
existing user — sees one service before and one after.

## Alternatives considered

* **Refuse to run when a second data directory is detected.** Rejected:
  the validation script legitimately needs a second one, and refusing turns
  a testing need into a product limitation.
* **A lock file in the data directory.** Rejected: it protects against two
  processes for one directory, which was never the problem. The problem was
  two directories for one *name*.
* **Keep the global name and only add the ownership proof.** Rejected: the
  proof is necessary but not sufficient — two environments would still be
  unable to coexist, each refusing to install because the other holds the
  only slot.
