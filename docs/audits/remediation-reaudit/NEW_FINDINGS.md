# New Findings — remediation re-audit

Findings surfaced while independently verifying PR #9 (`7d81090` → `1ec4073`). **None is
merge-blocking for the reviewed release-blocker scope.** All are pre-existing (not introduced
by the remediation) and are recorded for a follow-up pass. IDs are local to this re-audit
(`RA-n`); RA-2/RA-3 correspond to the remediation branch's own deferred NF-1/NF-2.

---

## RA-1 — `access grant end --kill` bypasses the PI-06 `pid ≤ 0` guard

- **Severity:** Info / Low. **Blocks PR #9: No.**
- **Where:** `apps/cli/src/access_cmd.rs:259` — the `end --kill` path spawns
  `std::process::Command::new("kill").arg(pid.to_string())` **directly** on a pid read from the
  database (`access_grant_end` → recorded running-process pids), instead of routing through the
  now-guarded `inject::terminate_pid`.
- **Why it matters:** the PI-06 fix added `if pid <= 0 { return false }` to `terminate_pid`,
  but this is a *second* process-termination entry point that never calls it. A corrupted /
  edited / zero pid record (the same precondition the audit cited for PI-06) would make this run
  `kill 0` (SIGTERM to the CLI's own process group) or `kill -N` (a process group). The
  re-audit brief explicitly requires "all process-termination entry points reject pid ≤ 0", so
  the PI-06 remediation is complete for the audited symbol but not for the entry-point class.
- **Not blocking because:** Info severity, pre-existing, requires DB tampering/corruption, and
  the impact is a self-directed signal on a short-lived CLI process. Normal spawned children
  always have pid > 0.
- **Recommended fix (follow-up):** route this path through `inject::terminate_pid`, or add the
  same `if pid <= 0 { continue }` guard before the spawn. (A full PI-02 fix additionally
  requires verifying spawn identity before signalling — still open.)

## RA-2 — CLI panics on a broken output pipe (= remediation NF-1)

- **Severity:** Cosmetic / robustness. **Blocks PR #9: No.**
- **Where:** the CLI entry point (`apps/cli/src/main.rs`) has no `SIGPIPE`/`ErrorKind::BrokenPipe`
  handling. Piping CLI stdout into `head`/`grep -q` (pricing, destination-catalog, template
  listings) makes a `println!` to a closed stdout panic with
  `failed printing to stdout: Broken pipe (os error 32)`.
- **Independently reproduced:** the panic fired live during `scripts/smoke.sh` on the release
  binary; the suite still reported **126 passed, 0 failed**. No secret is involved; no security
  impact.
- **Recommended fix (follow-up):** reset `SIGPIPE` to default (or catch `BrokenPipe` on stdout
  writes) in the CLI entry point and exit 0.

## RA-3 — `env_preview` / `env_import` read arbitrary filesystem paths (= remediation NF-2)

- **Severity:** Info / Low. **Blocks PR #9: No.**
- **Where:** `crates/core/src/vault.rs` — `env_preview` (`read_to_string` at ~4636) and
  `env_import` (~4682) read the caller-supplied path with no confinement; the `project` argument
  is used only to resolve mappings, not to constrain the path. Reachable from an unlocked-vault
  IPC/CLI caller.
- **Why it matters:** an information-surface issue adjacent to IPC-01. It is **read-only** (no
  write, no exfiltration — findings stay local), so it is lower severity than the
  now-fixed IPC-01 arbitrary *write*. Disclosure is limited to whether a path parses as `.env`
  and its variable-name structure (values are scanner-redacted in the preview).
- **Recommended fix (follow-up):** confine the read path to the project's registered
  repositories (canonical containment), mirroring the confinement now enforced on
  `env_example_write`.

## RA-4 — PI-01 scrub is case-sensitive; unusual-casing env vars could leak on Windows

- **Severity:** Low (theoretical). **Blocks PR #9: No.**
- **Where:** `crates/core/src/inject.rs` `scrub_own_env` matches the `API_TRACKER_` prefix by
  raw bytes (case-sensitive). Windows env lookups are case-insensitive, so a variable stored as,
  e.g., `Api_Tracker_Password` would not be scrubbed yet could still be read by the app via a
  case-insensitive `std::env::var("API_TRACKER_PASSWORD")` and thus leak to a child.
- **Why it matters / not blocking:** requires the user to have deliberately set the secret var
  with non-standard casing (all docs and the app itself use uppercase `API_TRACKER_*`); on
  Unix, env names are case-sensitive and the app reads exact names, so no exposure. Recorded for
  completeness of the "unusual casing / platform semantics" check.
- **Recommended fix (follow-up):** on Windows, uppercase-fold the name before the prefix
  comparison (matching the platform's own case-insensitive semantics).

---

## Confirmed still-open (correctly out of remediation scope)

- **PI-02 / CONC-11 (PID reuse):** the fix guards `pid ≤ 0` but adds no spawn-identity
  (start-time/cmd) check, so signalling a reused PID remains possible. The remediation does not
  claim to fix PI-02 — consistent with the audit. Remains a Production/GA blocker.
- **Production/GA blockers untouched by PR #9 (by design):** GScan-01/02, DEST-01/02/03,
  OBS-004, CONC-06, M-6, and the Tauri-command / frontend automated-test gaps. PR #9 targets the
  public-alpha blocker set only.
