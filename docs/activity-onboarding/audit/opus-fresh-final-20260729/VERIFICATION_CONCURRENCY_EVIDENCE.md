# Verification concurrency, ZFT-006 and VER-02 — independent evidence

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`.

## 1. What the compare-and-swap actually guards

`crates/tracking/src/state.rs:1052-1064` — the guard is a single monotonic
token, `WHERE id = ?1 AND row_version = ?6` (column added in migration v19,
`crates/core/src/db.rs:1165`).

Writers that bump it, and therefore refuse a stale writer:

| Writer | Site | Fields it protects |
| --- | --- | --- |
| `cas_write_health` (via `transition` `:573`, `write_derived` `:1114`) | `:1054` | `state`, `last_transition_at`, `attention_reason`, `attention_at` |
| `record_applied` | `:596` | `plan_summary_json`, `applied_at`, `applied_event_rowid` |
| `upsert_setup` ON CONFLICT | `:473` | `state`, `detection_json`, `attention_*`, `verification_session`, `config_generation`, … |
| `undo` complete-branch clear | `undo.rs:170-176` | `plan_summary_json`, `applied_at`, `first_traffic_at`, `verification_session` |

Deliberately **outside** the CAS:

* `first_traffic_at` / `first_verified_at` — write-once, guarded by `IS NULL`
  in the statement itself (`state.rs:976-991`). Sound: monotone and write-once,
  so two racing processes cannot both write.
* Route/link rows and observation rows — different tables. `row_version` says
  nothing about them.
* Gateway health — never persisted at all; it is a parameter.

### Can a stale writer erase newer truth?

| Erase a newer… | Answer | Pinned by |
| --- | --- | --- |
| failure | **No** | `verification_concurrency.rs:142,193,445` |
| setup generation | **No** | `:373` |
| verification session | **No** | `:411` |
| route/link state | **N/A** — never encoded in the persisted `state` column; re-read live on every health call (`state.rs:1176-1191`) | — |
| gateway-health result | **N/A** — never stored | — |

## 2. Is the ZFT-006 protection falsifiable? (mutation testing, executed)

I copied `crates/` to an isolated tree, kept `CARGO_TARGET_DIR` separate, and
mutated the fix's own mechanisms. Baseline: **158 passed, 0 failed**.

```
=== M2: (Some(_), None) => false   [a failure with no observations stops outranking] ===
M2: KILLED (123 passed, 1 FAILED)
    a_future_dated_observation_must_not_erase_a_current_failure

=== M3: instant_is_after inverted   [the sub-second RFC-3339 ordering fix] ===
M3: KILLED (123 passed, 1 FAILED)
    a_failure_half_a_second_newer_than_an_observation_still_wins

=== M4: REFRESH_CAS_ATTEMPTS 3 -> 1   [removes the retry bf17ce9 is built on] ===
M4: SURVIVED (158 passed, 0 failed)  <-- NOT DETECTED
```

**The literal ZFT-006 core is load-bearing and falsifiable.** M2 and M3 are
killed by named, specific tests. The committed suite is real.

**M4 is a coverage gap, not a safety hole.** No test creates enough CAS
contention to need a second attempt. The safety property still holds with one
attempt, because the exhaustion path is *report without writing* — it degrades
to a stale cached column, never to an erased failure. Recorded as `NEW-05`.

`crates/tracking/tests/zft006_regression.rs` — **5 tests, all passing**,
including `control_traffic_recorded_after_the_failure_does_clear_it`, an
anti-vacuity control that stops "never clear anything" from satisfying the
suite.

## 3. `transition`'s production callers

| # | Site | On `StateConflict` |
| --- | --- | --- |
| 1 | `apply.rs:291` (`fail!`, apply-failure path) | **Retried, bounded at 3** (`:288`), conflict → `continue` (`:297`) |
| 2 | `apply.rs:778` (success, `RecordSetup`) | Propagates `?` → a `Failed` step the user sees |
| 3 | `undo.rs:169` (complete undo) | Propagates `?` |
| 4 | `undo.rs:181` (incomplete undo) | Propagates `?` |

`db2707a`'s claim — three callers propagate, `apply.rs`'s failure path now
retries — is **accurate**. The retry is bounded.

`StateConflict` is a typed variant with a curated, SQL-free message and stable
code `state_conflict` (`crates/core/src/error.rs:61-65,142`). **No caller
surfaces it as a raw driver string.**

## 4. VER-02 across product boundaries — the finding

The remediation states VER-02 is pinned at the core layer only and asks the
auditor to check the CLI, the Tauri boundary and the UI. I checked all four.

| Layer | Verdict |
| --- | --- |
| Core (`TrackingStatusReport.current`) | **Correct**, thoroughly pinned |
| Desktop UI (React) | **Correct**, pinned by a test naming this exact defect |
| Tauri command boundary | **Faithful** (12-arm 1:1 mapping), but **no tests at all** |
| **CLI `tethra track` verify loop** | **BROKEN — see `NEW-01`** |

### The mechanism, read in source

`crates/tracking/src/verify.rs:139-155` — `check_traffic` calls
`state::refresh(...)`, then switches **solely on the cached `setup.state`
column**.

`state.rs:1015-1017` — `refresh` is `refresh_with(conn, setup, GatewayLiveness::Unknown)`
returning **only `.freshness`**, discarding `.current`. Its own doc comment
says why:

> Kept for bulk reads (lists, migrations) where probing a socket per row would
> be wrong; **the health it returns can never be a present-tense success claim.**

`state.rs:937-951` — the `derived` ladder decides `TrafficObserved` from
`observed_ever == total`. Gateway liveness and route presence are **not
inputs**. So `setup.state` stays `TrafficObserved` across a dead gateway.

`apps/cli/src/track_cmd.rs:726,745,758` — the verify loop gates its headline on
exactly that:

```rust
match verify::check_traffic(vault.connection(), &mut setup)? {
    WatchStatus::Observed { exchange, .. } => {
        …
        println!("✓ Tracking verified — {}", render::sanitize(&detail));
        return Ok(());                                    // exit 0
    }
    WatchStatus::PartiallyObserved { freshness, .. } => {
        println!("✓ Tracking verified for {}.", seen.join(", "));
        return Ok(());                                    // exit 0
    }
```

### Why this is a defect and not a judgement call

The **same file, 200 lines later**, states the opposite rule for
`track status` and implements it (`track_cmd.rs:943,993-999`):

```rust
let currently_working = report.current.is_currently_working();
…
// Exit 0 only for a present-tense success. "Verified previously" is
// deliberately a non-zero exit: a script that gates on tracking working
// must not be told yes while the service is down.
if currently_working { Ok(()) }
```

And the **desktop** fixed precisely this, with the mechanism spelled out
(`apps/desktop/src/components/TrackFlow.tsx:394-400`):

> `watch` comes from `check_traffic`, which is liveness-blind by construction
> (it passes `GatewayLiveness::Unknown`), so gating the headline on it let
> "verified previously, gateway down" render as an unqualified "Tracking
> verified" — **ZFT-005 closed on the dashboard but still open on this screen.**

The desktop gates on `status.health.currently_working` (`TrackFlow.tsx:1095`)
and carries a committed regression test
(`TrackFlow.test.tsx:650-675`, *"never claims verified when the gateway is
down, even with an observation"*). The CLI has neither.

### Test coverage for the CLI

`apps/cli/tests/track.rs` — 10 tests, all on the **unconfigured** path
(dry-run, no-detection, unconfigured status/undo, JSON shape, help). **No test
anywhere exercises `track status` or the `track` verify loop against a
configured setup.** The `"✓ Tracking verified"` line is unpinned in either
direction.

### Exposure

The verify loop runs only during a `tethra track` invocation, polling every
`POLL_INTERVAL_SECS`. The false claim requires traffic to be observed and the
gateway to become unavailable (crash, stop, route/link removal) within that
window. It is a time-bounded race, not a permanent misstatement — which is why
`NEW-01` is High-Medium and not Critical. But when it fires, the user is told
"✓ Tracking verified", exit 0, at the moment their application's API calls
have started failing, and a script gating on `tethra track` is given exactly
the answer the product's own comment says it must never be given.

## 5. Residual, non-blocking

* `refresh_with` exhaustion returns `TrackingStatusReport` with **no staleness
  marker**; `report.current` is freshly derived and honest, but `report.state`
  is the uncorrected column, and it is exported over both `--json` (`track_cmd.rs:936`)
  and the Tauri DTO (`main.rs:4096`). A consumer keying on `.state` instead of
  `.current` can read stale. Documented at `state.rs:918` but not enforced.
* `tracking_status` runs `check_traffic` (a may-write refresh) *and*
  `refresh_with(liveness)` per poll — two guarded write passes, doubling
  self-inflicted CAS contention.
* Tauri command boundary has zero tests.
