# PR #13 — CI failure analysis

Branch `feat/runtime-api-observability`, head `afab5ea` at time of failure.
CI run `30114597596`. Two jobs failed; two passed.

| Job | OS | Result | Stage |
|---|---|---|---|
| CI / Rust (core + CLI) | ubuntu-latest | **fail** | Clippy |
| CI / Rust core (Windows) | windows-latest | **fail** | Tests |
| CI / Desktop backend (macOS) | macos-latest | pass | — |
| CI / Desktop frontend | ubuntu-latest | pass | — |

---

## Failure 1 — Linux `Rust (core + CLI)` / Clippy

- **Workflow/job:** `.github/workflows/ci.yml` → `rust` (ubuntu-latest),
  `dtolnay/rust-toolchain@… stable`.
- **Exact failing command:**
  `cargo clippy -p api-tracker-core -p api-tracker-cli --all-targets -- -D warnings`
  (checks `api-tracker-observe` too, since `api-tracker-cli` depends on it).
- **First meaningful diagnostic:**
  ```
  error: function `write_temp_cert` is never used
    --> crates/observe/src/systemtrust.rs:33:4
    = note: `-D dead-code` implied by `-D warnings`
  ```
- **Root cause:** `write_temp_cert` (a private fn) is called **only** from
  `#[cfg(target_os = "macos")] install()`. On Linux (and Windows) the
  `#[cfg(not(target_os = "macos"))]` variants of `install`/`remove`/`detect`
  do not call it, so on non-macOS targets the function is defined but never
  used → `dead_code`. **Platform-conditional dead code.**
- **Why local validation missed it:** local clippy ran on **aarch64-apple-darwin
  (macOS)**, where `write_temp_cert` is live (the macOS `install` calls it).
  `dead_code` is target-conditional; the macOS build never sees it as dead.
  Cross-clippy to Linux is not possible locally (no `x86_64-linux-gnu-gcc`, so
  `ring`/`libsqlite3-sys` cannot cross-build).
- **Classification:** production code; deterministic; platform-conditional.
- **Security impact:** none (a lint on an unused private helper).
- **Fix:** gate `write_temp_cert` with `#[cfg(target_os = "macos")]` (its only
  caller is macOS-only). `CA_CN_PREFIX` and `SystemTrustState` are `pub`, so
  they are not flagged.
- **Regression test:** a source-level guard in `crates/observe/tests/` asserting
  no macOS-only private helper leaks into the non-macOS build is impractical;
  instead the fix is confirmed by the **real Linux and Windows CI runners** (the
  authoritative cross-platform check), which are the regression signal. A
  compile note is added to the module so future macOS-only helpers are gated.

## Failure 2 — Windows `Rust core` / Tests

- **Workflow/job:** `.github/workflows/ci.yml` → `rust-windows`
  (windows-latest), `cargo test -p api-tracker-core`.
- **Exact failing test:** `openai_sync::repeated_and_overlapping_syncs_do_not_double_count`
  at `crates/core/tests/openai_sync.rs:296`.
- **Assertion:** `assert_eq!(reconciled.input_tokens, 2_000_500)` — got
  `left: 3001000`, `right: 2000500`. `3001000 = 1000500 (old) + 2000500
  (revised)`: the overlapping re-sync did **not** replace the old window's rows.
- **Root cause:** `bucket_times()` returns `(now-1800, now)` where `now =
  clock::now().unix_timestamp()` — **second-granular**. The test reads
  `bucket_times()` independently for (a) the initial `run_full_sync` and (b) the
  later "overlapping window" re-sync. `usage_sync` replaces rows for the
  **exact** window it syncs. If the two reads straddle a 1-second boundary the
  two windows differ, so the re-sync's replace-range does not delete the
  original window's rows → they are counted **plus** the revised ones. This is
  a **pre-existing time-dependency in an unrelated usage-sync test**, not in
  the observability change. It is NOT a production bug: real OpenAI usage
  buckets are stable calendar-day windows, so a real re-sync of the same day
  replaces correctly; only the test's synthetic sliding `now-1800` window is
  time-sensitive.
- **Why local validation and `main` missed it:** `main`'s Windows CI is green
  (6/6 recent runs). On fast runners (macOS/Linux, and Windows on shorter
  binaries) the two `bucket_times()` calls fall within the same second, so the
  windows match. This PR adds a 12th migration and a large new crate, which
  **slows the `openai_sync` test binary on the slower Windows runner enough to
  cross the second boundary** between the two reads — surfacing (not causing)
  the latent race. (The log even shows `ERROR: The process with PID 3228 could
  not be terminated`, an unrelated Windows artifact from a parallel test, not
  the cause.)
- **Classification:** test code; nondeterministic (time-boundary race);
  platform-timing-sensitive.
- **Security impact:** none.
- **Fix:** memoize `bucket_times()` with a process-`OnceLock`, so every call in
  the test process returns the **same** synthetic window — which is exactly
  what the "overlapping window replaces the old rows" scenario intends. No test
  asserts the window's absolute recency (all query `usage_totals("2000-01-01…")`),
  and staleness tests age `last_success_at` independently, so memoization is
  behavior-preserving.
- **Nondeterminism proof:** the two `bucket_times()` reads are separated by a
  full second `run_full_sync` (JSON parse + DB writes) plus mock construction;
  `now` is second-granular; crossing a second boundary yields different windows.
  After memoization the window is invariant across reads → deterministic. The
  memoized helper **is** the regression guard.
