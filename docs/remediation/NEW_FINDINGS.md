# New findings recorded during remediation (out of scope)

These were noticed while fixing the confirmed release blockers. They are
**not** fixed here (scope discipline); they are recorded for a later pass.
Neither is a release blocker on its own.

## NF-1 — CLI panics on a broken output pipe (`Broken pipe (os error 32)`)

- **Where:** observed running `scripts/smoke.sh` against the release binary,
  in sections that pipe CLI stdout into `head` / `grep -q` (pricing,
  destination-catalog, template listings). The CLI writes to a closed stdout
  and panics with `failed printing to stdout: Broken pipe`.
- **Impact:** cosmetic only — the smoke suite still reports `126 passed,
  0 failed`, and the panic happens after the meaningful output is produced. No
  security impact; no secret is involved. It is a robustness/polish issue: a
  well-behaved CLI treats `EPIPE` as a clean exit rather than a panic.
- **Pre-existing:** yes — present at baseline `7d81090`, unrelated to any
  remediation change (the affected commands were not touched).
- **Suggested fix (later):** ignore `SIGPIPE`/`ErrorKind::BrokenPipe` on
  stdout writes in the CLI entry point and exit 0.

## NF-2 — `env_preview` / `env_import` read arbitrary filesystem paths

- **Where:** `crates/core/src/vault.rs` `env_preview` / `env_import` read the
  caller-supplied file with `std::fs::read_to_string(file)`; the `project`
  argument is used only to resolve mappings, not to confine the path.
- **Impact:** an unlocked-vault caller (desktop IPC or CLI) can preview/import
  from any readable path, not just the project's registered repositories.
  These paths are read-only and never write or exfiltrate (findings stay
  local), so this is a lower-severity information-surface issue than IPC-01
  (which was an arbitrary *write*, now fixed). Adjacent to IPC-01/FS-09.
- **Pre-existing:** yes — baseline behavior; not introduced here.
- **Suggested fix (later):** confine the read path to the project's registered
  repositories (canonical containment), mirroring the confinement now enforced
  on `env_example_write`, for defense in depth on the read side.
