# Continuation — remediation re-audit

State at hand-off: the re-audit is **complete**. Verdict **PASS** for PR #9's reviewed
release-blocker scope. This file records what was done, what to do next, and how to reproduce.

## Done this session
- Verified worktree/commit provenance (branch `audit/remediation-reaudit`, HEAD `1ec4073`,
  baseline `7d81090` an ancestor, clean tree).
- Read the full `7d81090..1ec4073` production diff and the surrounding source for every changed
  symbol; read the authoritative deep-audit docs and the remediation report/evidence.
- Produced: `REMEDIATION_REAUDIT.md`, `FIX_VERIFICATION_MATRIX.md`, `NEW_FINDINGS.md`,
  `TEST_RESULTS.md`, and evidence under `evidence/`.
- Ran: workspace tests (413/0), each focused regression suite, clippy (0), fmt, the frontend CI
  commands, smoke (126/0). Independently reproduced CRYPTO-01 at the real baseline and
  stress-tested the fix (5 runs, ~80 races).

## What a follow-up pass should pick up (NOT blockers for PR #9)
1. **RA-1** — add a `pid <= 0` guard (or route through `inject::terminate_pid`) to
   `apps/cli/src/access_cmd.rs:259` so the `access grant end --kill` path matches the PI-06 fix.
2. **RA-3 / NF-2** — confine `env_preview` / `env_import` read paths to registered repositories,
   mirroring `env_example_write`.
3. **RA-2 / NF-1** — handle `SIGPIPE`/`BrokenPipe` in the CLI entry point.
4. **RA-4** — Windows-case-fold the `API_TRACKER_` prefix match in `scrub_own_env`.
5. **PI-02** — spawn-identity (start-time/cmd) verification before signalling; still open.
6. **Production/GA blockers outside this PR:** GScan-01/02, DEST-01/02/03, OBS-004, CONC-06,
   M-6, and the Tauri-command / frontend automated-test coverage gaps.

## Reproduce the key checks
```bash
# From the audit worktree (HEAD 1ec4073), CI toolchain:
cargo +1.97.0 test --workspace --all-targets
cargo +1.97.0 clippy --workspace --all-targets -- -D warnings
cargo +1.97.0 fmt --all --check
bash scripts/smoke.sh                              # needs: cargo +1.97.0 build --release -p api-tracker-cli
( cd apps/desktop && npm ci && npm run format:check && npm run lint \
    && npm run typecheck && npm test && npm run build )

# CRYPTO-01 deterministic race (repeat for stress):
cargo +1.97.0 test -p api-tracker-core --test crypto01_rotation_race

# Independent baseline reproduction (disposable worktree — never edit the audit worktree):
git worktree add --detach /tmp/baseline-wt 7d81090a1068476291546963e68ca8c7de1a7145
cp crates/core/tests/crypto01_rotation_race.rs /tmp/baseline-wt/crates/core/tests/
printf 'rusqlite = { version = "0.40.1", features = ["bundled"] }\n' >> /tmp/baseline-wt/crates/core/Cargo.toml
( cd /tmp/baseline-wt && cargo +1.97.0 test -p api-tracker-core --test crypto01_rotation_race )  # expect FAIL/orphan
git worktree remove --force /tmp/baseline-wt
```

## Cautions for the next auditor
- Some remediation baseline-fail logs are shim-based (IPC-01/IPC-02/CONC-04/OBS-001). They were
  validated as faithful here, but re-derive rather than trust if the fix code changes.
- The `assert_payload_consistent` backup tripwire checks project-row presence only, not
  wrap/ciphertext key-match — the real CONC-04 guarantee is the single read snapshot.
- Rotation holds SQLite's write lock across its re-encrypt loop; under heavy contention a
  concurrent writer receives a typed `Busy` (retryable, no data loss). This is by design.
- `cargo-tauri` is not installed locally; the packaged desktop app was not built (backend
  Rust compiles cleanly). A packaged/CSP/allowlist runtime check remains for a machine with the
  bundler.
