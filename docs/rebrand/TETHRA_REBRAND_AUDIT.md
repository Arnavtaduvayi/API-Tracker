# PR #12 — Tethra Rebrand: Audit and Remediation Cycle

- **Date:** 2026-07-25
- **Branch:** `release/tethra-macos-private-alpha` (PR #12)
- **Base:** `origin/main` = `f605d8f` (merge of PR #13, runtime API
  observability)
- **Audited head at completion:** `d6a0b7b`
- **Scope:** the full rename from API Tracker to Tethra — is it actually
  complete, is it compatibility-safe, and are its own claims true?

## 1. Starting position

PR #12 was an open **draft** and `CONFLICTING` against main. Its rebrand work
(9 commits) branched from `4f8c8cb`, *before* PR #13 merged, so the branch had
a complete rebrand of everything that existed at branch time and **no** rebrand
of the runtime-observability feature that landed afterwards. Left alone, the
two branches would have produced a half-renamed product: `tethra run` for the
core CLI, `api-tracker run --observe` in every observability string and doc.

Work done, in order: audit the rebrand → integrate main → extend the rebrand
over the new surfaces → remediate the findings → full validation.

## 2. Rebrand policy (as designed by the branch, verified in code)

The branch draws a deliberate line, documented in
`TETHRA_COMPATIBILITY_MATRIX.md` and confirmed correct by this audit:

- **Renamed** — everything a user reads: app/window/notification titles, DMG
  and bundle name, CLI command, help text, error strings, CLI/desktop copy,
  docs, HTTP User-Agents.
- **Preserved on purpose** — everything that identifies *data*: the
  `api-tracker` data directory, DB/session filenames, ciphertext AAD labels
  (`api-tracker:v1:…`), backup format marker, keychain/Credential Manager
  service and account defaults, webhook `source`, git-hook sentinels,
  temp-file infix, rotation key prefix, the Tauri bundle identifier, and the
  Cargo crate names.

This is the right split: renaming any preserved identifier would silently
orphan existing vaults, backups, keychain entries, hooks, or webhook filters.
Spot-checked every preserved identifier in code against the matrix — all
consistent, with the "preserved" reason stated at each site.

## 3. Integration with runtime observability

Merged `origin/main` (`f605d8f`) into the branch. Three conflicts, all
resolved so both sides' intent survives:

| File | Resolution |
|---|---|
| `apps/cli/src/run_cmd.rs` | kept the observability run branch; module doc and env-scrub comments use Tethra naming |
| `THREAT_MODEL.md` | kept the three-outbound-uses bullet including the observation proxy, with "no secret is ever sent to a Tethra-operated server" |
| `docs/FEATURE_MATRIX.md` | kept the observability audit addendum *and* the tethra/api-tracker alias note |

Then applied the branch's own policy to PR #13's surfaces: the `tethra observe`
module doc and empty-inventory hint, the `LockSignal` doc comment, the runtime
alert comment, `OBSERVE_CLIENT_TAG` (a request header → follows the product
name, matching `tethra/0.1` in the core HTTP client), the three command strings
in the desktop **API activity** screen, and command examples across
`RUNTIME_OBSERVABILITY.md`, the observability manual test plan and test data,
the observability threat model, and `PRODUCT_SPEC.md`'s CLI list.

`README.md` and `CHANGELOG.md` documented neither observability (PR #13 never
updated them) nor its rename; both now describe the feature honestly, including
its metadata-only guarantee and the vault-lock behavior.

## 4. Findings

### F1 — `api-tracker --version` reported the wrong product (Medium; fixed)

clap renders the version line from the command **name**, which was hardcoded to
`tethra`, not from the argv[0]-derived `bin_name` used for the usage line. So
the legacy binary printed:

```
$ api-tracker --version
tethra 0.1.0
```

Any script matching the product name broke — while the compatibility matrix
explicitly promised "old parsers of `api-tracker --version` unaffected". A
false compatibility claim in a rename is exactly the kind of thing that bites a
user after the release notes said it wouldn't.

**Fix:** help *and* version branding is now derived from argv[0], matched
against a fixed allowlist of the two shipped names (`main::invoked_name`). Each
entry point reports itself, so the matrix claim is now true. argv[0] is
caller-controlled — a symlink or `exec -a` can set it to arbitrary bytes,
including terminal escapes, and it reaches rendered help/version output — so an
unrecognized name falls back to `tethra` rather than being echoed. This mirrors
the existing control-character sanitization on the error path.

**Tests:** `version_line_matches_the_invoked_binary_name` (fails at baseline)
and `an_unrecognized_argv0_falls_back_to_the_product_name` (executes a copy of
the binary named with an ANSI escape and asserts neither the escape nor the
spoofed name appears).

### F2 — "byte-for-byte identical binaries" was false (Low; fixed)

`apps/cli/Cargo.toml`, `CHANGELOG.md`, `TETHRA_MIGRATION_GUIDE.md`, and
`TETHRA_REBRAND_PLAN.md` all described the two binaries as byte-identical. The
branch's own `TETHRA_MACOS_PACKAGING_RESULTS.md` records different sizes
(9,475,936 vs 9,475,952 B) and different SHA-256s. Two `[[bin]]` targets over
one source file are separate compilations, and after F1 they intentionally
differ in one observable way.

**Fix:** the program moved to `apps/cli/src/lib.rs`; both entry points
(`src/main.rs`, `src/legacy_bin.rs`) are one-line wrappers over `run_cli()`, so
they run identical code and cannot drift. Docs now say "the identical program,
each naming itself" instead of "byte-identical". This also removes the cargo
`file … found to be present in multiple build targets` warning that was emitted
on **every** build, which the repository rules forbid leaving in place.

`run_cli` returns normally rather than calling `exit(0)`, preserving the
original `fn main` semantics (notably stdout flushing).

Measured after the refactor: the two release binaries are now the same size
(10,488,976 B) but still have different SHA-256s — separate link units embed
their own name — so "the identical program, each naming itself" is the
accurate claim, and "byte-identical" would still be wrong.

### F3 — `TETHRA_REBRAND_PLAN.md` described help behavior incorrectly (Low; fixed)

The plan said the clap name "becomes `tethra` (help/usage shows the preferred
name from either binary)" — contradicting both the matrix and the actual
argv0-derived behavior. Rewritten to describe what the code does.

### F4 — ADR naming policy was undocumented (Low; fixed)

Architecture decision records in `docs/decisions/` keep the historical name
(`api-tracker unlock`, etc.) — correctly, since an ADR records a decision as it
was made and the commands it names still work under the legacy alias. But the
rebrand plan's "Historical documents" section listed audit reports, remediation
ledgers, and evidence logs without mentioning ADRs, so the largest category of
deliberately-unrenamed docs looked like an oversight. Now stated explicitly in
the plan and in the matrix's Docs row.

Two rows of the plan's own identifier table also still described the pre-fix
behavior ("both binaries print `tethra` usage", `src/main.rs` as the program);
corrected to match the code.

### F5 — Release evidence superseded by the merge (Low; fixed by disclosure)

`TETHRA_MACOS_PACKAGING_RESULTS.md`, `TETHRA_MACOS_PRIVATE_ALPHA_READINESS.md`,
and `TETHRA_MACOS_PRIVATE_ALPHA_RELEASE_NOTES.md` present verified artifacts,
checksums, and readiness evidence for commit `0972f20`. The branch has since
integrated a whole feature; those hashes no longer correspond to anything on
the branch, and the readiness inventory does not cover observability at all.

**Fix:** each document carries a banner stating the build it records, that the
branch has moved past it, and that a re-package plus re-verification is
required before release. The evidence itself is preserved — it is accurate for
the commit it describes. **This is the one open action before any release: the
macOS package must be rebuilt and re-verified.**

### Accepted, not defects

- **Historical documents keep the old name.** `UI_MAP.md`,
  `MANUAL_UI_TEST_PLAN.md`, `MANUAL_TEST_DATA.md`, `FABLE_HANDOFF.md`, the ADRs,
  and the audit ledgers describe verified pre-rename baselines. Each living one carries
  a banner that explicitly corrects the window title, CLI name, and env vars.
  Rewriting a verified baseline would falsify the record; the banner is the
  honest option.
- **`api-tracker` in keychain/AAD/hook-sentinel/webhook strings.** Preserved by
  design; every site says why. The same applies to an `api-tracker run` mention
  inside an already-shipped migration's SQL comment: migration text is never
  edited after release, and it is invisible to users.
- **Cargo crate names** (`api-tracker-core`, `-cli`, `-observe`) are internal
  identifiers, deferred by the matrix. `cargo build -p api-tracker-cli` and the
  CI job names are unchanged.

## 5. Compatibility properties verified

| Property | Result |
|---|---|
| Vault created by `tethra` opens in `api-tracker` and vice versa | PASS (compat tests, both directions) |
| `TETHRA_*` wins when both are set; legacy alone still works; empty preferred is authoritative | PASS |
| Conflicting `*_DIR` warns and never combines; matching pair is silent | PASS |
| `unlock --print-export` prints legacy line first, then `TETHRA_SESSION`; `eval` sets both | PASS |
| A stale session variable falls back to a set password variable instead of wedging | PASS |
| `run` scrubs **both** prefixes from children; `*_DIR` / `*_INSECURE_FAST_KDF` survive | PASS |
| Each entry point names itself in help and version | PASS (after F1) |
| Unrecognized argv[0] falls back without echoing caller-controlled text | PASS |
| Git hooks: new installs prefer `tethra`, fall back to `api-tracker`; legacy hooks still recognized/upgradable/removable | PASS |
| Data directory, DB/session filenames, AAD labels, backup marker unchanged | PASS |
| Vault-lock interruption of observed runs still correct after the merge | PASS (observe lock-lifecycle suite) |

## 6. Validation (this cycle, on `d6a0b7b`, macOS/aarch64)

| Command | Result |
|---|---|
| `cargo test --workspace --all-targets` | **654 passed, 0 failed** across 45 binaries (1 ignored perf bench) |
| `cargo test -p api-tracker-cli --test tethra_compat` | **15 passed** (13 pre-existing + 2 new) |
| `cargo fmt --all --check` | clean |
| `cargo +1.97.0 clippy --workspace --all-targets -- -D warnings` | clean |
| `bash scripts/smoke.sh` (release binary, production Argon2id) | **126 passed, 0 failed** — drives the `tethra` binary entirely through legacy `API_TRACKER_*` variables |
| Frontend: `format:check`, `lint`, `typecheck`, `test`, `build` | all pass; **34 tests** |
| Cargo build warnings | none (the duplicate-build-target warning is gone) |

## 7. Verdict

The rebrand is complete and compatibility-safe across both the original
surface and the runtime-observability feature that landed after the branch was
cut. Two false compatibility claims were found and fixed in the code rather
than merely reworded, each with a regression test; the remaining doc issues
were staleness, now disclosed.

**Open action before release (not a merge blocker):** re-package the macOS
build and re-run the packaging verification, since the recorded artifacts
predate the observability merge.

**REBRAND AUDIT VERDICT: PASS WITH REQUIRED CHANGES — all required changes
applied and verified on `d6a0b7b`.**
