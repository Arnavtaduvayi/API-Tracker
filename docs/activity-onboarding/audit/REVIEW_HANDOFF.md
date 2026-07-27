# Review handoff — zero-friction API tracking

For an independent reviewer. This document does not ask you to trust the
implementation; it tells you where to look, what is deliberately load-
bearing, and where the residual risk sits.

Branch `feat/zero-friction-api-tracking`, base `main` @ `0e6764b`.
No PR is merged. No independent approval is claimed.

## What changed, in one paragraph

A new crate (`crates/tracking`) orchestrates scan → detect → plan →
apply → verify → diagnose → undo over the existing, audited gateway APIs.
The desktop and CLI are thin callers of it. The desktop app now bundles
the CLI binary as a Tauri sidecar, so tracking no longer requires a
separately installed CLI. One migration (v15) adds a state table. The
forwarding engine, control plane, key lifecycles, and recording allowlist
are untouched.

## Where to focus review

Ranked by consequence if wrong:

1. **`crates/tracking/src/detect.rs`** — new code that reads a user's
   project files. Check the bounds: canonicalize-then-refuse for root
   and home, depth cap, byte cap, symlink refusal, parse-only, and the
   single value-read exception (§5 below). Tests:
   `crates/tracking/tests/bounds.rs`.
2. **The origin-inference rule.** A hostile repository can plant
   `SUPABASE_URL=https://attacker.example` hoping a user confirms it.
   Mitigations: full `validate_origin` + SSRF policy, verbatim display,
   explicit confirmation, MAC binding. Residual risk accepted and
   documented — but verify the rule cannot be reached for a
   secret-classified variable (test:
   `secret_classified_vars_are_never_value_read_for_origins`).
3. **`crates/tracking/src/apply.rs` ordering and failure semantics.**
   A step failure must stop the sequence, leave earlier steps in place,
   and report honestly — never silently roll back and never continue
   past a failure. Test: `a_failed_service_step_stops_the_sequence…`.
4. **`crates/tracking/src/state.rs::refresh`.** This is what makes
   "verified" mean something. It must downgrade an overclaiming row.
   Tests: `an_overclaiming_row_is_downgraded_on_refresh`,
   `pre_existing_traffic_never_verifies_a_new_setup`.
5. **`plan_link_as_provider_projected` in `crates/gateway/src/envlink.rs`.**
   The one change inside the audited gateway crate. It adds read-only
   planning entry points; `apply_link`'s digest binding and every write
   path are unchanged. Verify that the projected-content path cannot be
   reached from `apply_link`.
6. **`locate_cli` in the desktop.** The bundled sidecar is now the first
   candidate. Verify the exec probe still gates every candidate.

## Security invariants — claimed status

No invariant in `docs/gateway/SECURITY_INVARIANTS.md` changed. Specific
claims worth checking:

* **SI-2/SI-3** — auto-created routes are manifest routes (compiled-in
  trust root) or MAC'd custom origins from a user-confirmed value that
  passed the unchanged `validate_origin`. Detection never lowers
  validation; `plan()` validates the origin at review time so a bad one
  fails before apply.
* **SI-9/SI-21** — the matching key still travels only over the
  authenticated control channel, still requires the master password, and
  still drops on lock. The password field moved into the Start-tracking
  screen; the gate did not move.
* **SI-16** — `envlink` still touches only planned files. Detection
  reads only the selected folder under the bounds above.
* **SI-17** — v15 is additive.
* **SI-19** — strengthened, not weakened: the product claim now *requires*
  an observation.
* **SI-20** — the new crate is `#![forbid(unsafe_code)]`.

## A defect this process already caught

The home-directory refusal in `detect.rs` originally consulted only
`$HOME`. Windows does not set it, so on Windows a selected home
directory was **not** refused and was scanned in full — a direct
violation of "no home-directory scan, ever". It passed every macOS and
Linux run and was caught only because the new crate was added to the
Windows CI job. Fixed, with a mutation-verified negative control that
names the leaking variable.

Worth asking what else is platform-conditional in the bounds: the
symlink refusal relies on `symlink_metadata` (portable), the depth and
byte caps are arithmetic, and the root refusal uses `Path::parent`.

## Adversarial questions worth asking

* Can any code path write `traffic_observed` without a matching
  observation row? (Search for the literal; it should appear only in
  `state.rs`'s derivation and in tests.)
* Can `apply` be re-entered concurrently from desktop and CLI against the
  same setup? Both hold the DB; the desktop serializes on the vault
  mutex, the CLI is a separate process. Route/link inserts are
  `INSERT OR IGNORE` and the setup row is unique on (project, folder), so
  the failure mode is a duplicate-work error rather than corruption —
  but this is a genuine "unproven under concurrency" area.
* Does `undo` ever remove a route another project links? (Test says no —
  check the query counts links, not setups.)
* Does the chained multi-provider plan produce a diff that differs from
  what apply writes? (The idempotence test would catch drift; the digest
  check would abort. Confirm both.)
* Does anything in the new UI render a shell command where a button
  exists? (Deliberately removed from the primary flow.)

## Evidence, and its limits

Executed on the implementer's machine, macOS aarch64:

* Rust workspace (5 crates): 1005 passed, 0 failed.
* Frontend vitest: 65 passed, 0 failed, 0 unhandled errors.
* `scripts/smoke.sh`: 138 passed, 0 failed.
* `scripts/tracking_validate_macos.sh`: 42 passed, 0 failed, against the
  real `Tethra.app` bundle with `PATH` stripped so only the bundled
  helper could satisfy the run.
* Clean-vault terminal pressure test: `tethra init` + `tethra track .`
  configured a project, refused to claim verification with no traffic,
  then flipped to `traffic_observed` after one real 401 through the
  gateway; `track undo` restored `.env` byte for byte.

**Not evidence:**

* No Linux or Windows packaged run was performed.
* The LaunchAgent install path was not exercised in the packaged run (an
  existing user agent was preserved rather than clobbered); it is
  covered by the mock-runner suite and the pre-existing gateway
  validation script.
* The desktop GUI was not click-driven (no display access); the counts in
  `IMPLEMENTATION_STATUS.md` are read from the implemented flow, and
  every underlying operation was executed through the same commands the
  UI calls.
* Authoritative CI on head `cb8edac` (run 30290195444) passed all four
  checks: Desktop frontend, Desktop backend (macOS), Rust (core + CLI),
  and Rust core (Windows). The Windows job is the one that verifies the
  home-directory scan fix described above.

## Process notes

* PR #15's demanded independent re-audit remains uncommissioned
  (O-22-9). That is an owner decision; this work did not resolve it and
  does not depend on it.
* This branch does not merge anything and makes no approval claim.
