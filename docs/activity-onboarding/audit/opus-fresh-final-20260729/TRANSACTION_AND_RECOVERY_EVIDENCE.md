# Transactions, crashes and recovery — independent evidence

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`.
Executed: `cargo test -p api-tracker-tracking` → **158 passed, 0 failed**;
`cargo test -p api-tracker-gateway` → **313 passed, 0 failed, 8 ignored**
(the 8 are `perf.rs` benchmarks).

## 1. Is `apply` transactional end to end?

**No.** There is no transaction, savepoint or lock anywhere in `apply`
(`crates/tracking/src/apply.rs:251-813`). The only `BEGIN IMMEDIATE` in the
audited surface is the legacy scrub. Apply is a sequence of independently
auto-committed steps:

| # | Commit point | Source | A crash after this leaves |
| --- | --- | --- | --- |
| 1 | project row + repo path | `apply.rs:320` | orphan/adopted project row |
| 2 | `upsert_setup` — new session, `config_generation+1`, clears `plan_summary_json`/`applied_at` | `apply.rs:358`, `state.rs:453-484` | row in `applying`, prior provenance cleared |
| 3 | persisted port | `apply.rs:399` | port reserved |
| 4 | service install/start + `enabled` | `apply.rs:420,427` | service installed |
| 5 | **one commit per route** | `apply.rs:471/486/494` | routes enabled, no links |
| 6 | link row insert | `envlink.rs:599` | link row, `.env` untouched |
| 7 | `prior_env_json` restore record | `envlink.rs:620` | restore record, `.env` untouched |
| 8 | **per-file `.env` write** | `envlink.rs:632/634` | file 1 written, file 2 not |
| 9 | `record_applied` (summary, `applied_at`, watermark) | `apply.rs:773`, `state.rs:593-599` | summary present, state still `applying` |
| 10 | `transition` to end state (CAS) | `apply.rs:778` | done |

**The ordering is deliberately correct where it matters most**: the restore
record is always committed *before* the file it describes
(`envlink.rs:592-596`), so a crash between them over-describes restoration
rather than under-describing it. That is the right direction.

### Partial-apply reporting

Real, and pinned. `ApplyReport { steps, … }` (`apply.rs:78-104`) renders
per-step ✓/•/✗ at `apps/cli/src/track_cmd.rs:679-691`, followed by
*"Setup stopped at '{step}'. Completed steps are left in place; `tethra track
undo` restores everything, `tethra track doctor` diagnoses."* (exit 1). Tests
`a_failed_service_step_stops_the_sequence_and_reports_honestly` and
`a_blocked_install_is_flagged_for_the_foreground_fallback` pass.

`NEW-30` (low): the **desktop's** partial-apply screen
(`TrackFlow.tsx:1124-1169`) lists the steps and says completed steps are left
in place, but offers only "Try again" and "Back to dashboard" — **no undo
button**. Undo exists only from `DashboardView.tsx:440-452`. The PR's "offers
undo" claim is CLI-only.

## 2. Is `.env` modification atomic?

**Yes.** `crates/core/src/envgov.rs:749-785` — same-directory temp file opened
`create_new` at mode `0600`, `write_all`, `sync_all`, then `rename`. Symlinks
are refused at plan time (`envlink.rs:726-737`) and at restore time
(`:1500-1515`) precisely because `rename` would replace the link. New files use
`write_new` (`create_new` + `sync_all`) — not atomic, but the file did not
previously exist, so no user data can be lost.

**A crash mid-write cannot corrupt the user's `.env`.**

### `NEW-29` (Low-Med) — orphaned temp files carry credentials and are not git-ignored

A kill between `create_new` and `rename` leaves the temp file holding the
**complete** new `.env`, including the user's real API keys. Two gaps:

* The orphan sweep (`envgov.rs:943-978`) is only reachable from export cleanup
  (`:933`); **tracking's link paths never sweep**.
* The name is `format!(".{}.api-tracker-tmp-{}", path.file_name(), uuid)`
  (`envgov.rs:754-759`), so for `.env` it is `..env.api-tracker-tmp-<uuid>`.
  The repository's own `.gitignore` has `.env` and `.env.*` — **neither
  matches a name beginning `..env`**. `smoke.sh` asserts ".env files are
  git-ignored"; that claim has this hole.

Mitigated by mode `0600` and a narrow crash window, but notable in a
credential manager.

## 3. The thirteen scenarios

| # | Scenario | Verdict | Test? |
| --- | --- | --- | --- |
| 1 | apply vs apply | **FAIL** → `NEW-31` | none |
| 2 | apply vs undo | **FAIL** (lost failure record) → `NEW-33` | none |
| 3 | refresh vs failure recording | **PASS** | yes, green |
| 4 | refresh vs route removal | **PASS** | yes, green |
| 5 | legacy migration vs undo | **PASS** by construction | partial |
| 6 | desktop vs CLI | PASS (refresh) / FAIL (apply) | refresh only |
| 7 | two projects, one `.env` | **FAIL — silent data loss** → `NEW-28` | none |
| 8 | stale process vs newer generation | PASS (refresh) / FAIL (`record_applied`) | refresh only |
| 9 | crash after routes, before `.env` | PARTIAL FAIL | none |
| 10 | crash after `.env`, before state commit | **PASS** | yes, green |
| 11 | crash during encrypted scrub | **PASS** | yes, green |
| 12 | retry after partial failure | PARTIAL FAIL → `NEW-32` | happy path only |
| 13 | stale undo vs newer generation | **FAIL** → `NEW-34` | none |

### `NEW-28` (High, not blocking) — two projects on one `.env`

**Reachability first, because it decides the severity.** The product actively
refuses the implicit form: with two projects registered on one folder,
`tethra track <dir>` fails with *"more than one project"* and demands
`--project` (pinned by `ambiguous_folder_registration_is_an_explicit_error`,
`apps/cli/tests/track.rs:210-231`). And `apply.rs:864-885` **adopts** an
existing project by name rather than creating a duplicate. So the scenario
requires a user to deliberately create two differently-named projects on the
same folder and then run `track --project` twice.

When they do, the chain is:

1. A links → `OPENAI_BASE_URL=…/p/<slugA>/…`; A records the user's real value
   as its prior.
2. B links the same file → B's plan records **A's gateway URL** as B's prior
   (priors are keyed by `link_slug`, `envlink.rs:616`, so B cannot see A's).
   Only the generic `ExistingValueRecorded` warning appears; there is **no
   `LinkWarning` variant** for "another project already links this file"
   (`envlink.rs:289-328`).
3. A undoes → current ≠ A's `written` and ≠ A's prior → `LeftUserEdit`
   (`envlink.rs:1595`), which `outcome_is_settled` classifies as **settled**
   (`:1418`) → `complete: true`, A's link row deleted. It also restores
   `NO_PROXY` away (A created it; B recorded no prior because it already
   existed), leaving B pointed at loopback **without** `NO_PROXY`.
4. B undoes → current == B's `written` → "restores" B's prior, which is
   `…/p/<slugA>/…` — a slug whose link row no longer exists.

Final state: the user's real `https://api.openai.com/v1` is **permanently
gone**, every outcome says `Restored`, `complete: true`. `diagnose` cannot see
it — `env_drifted` iterates `report.links` (`diagnose.rs:74-96`) and there are
none left.

**Mitigation that does hold:** an unknown slug returns the same 404 as an
unknown prefix (`forward.rs:168`), so **no credential is sent to the wrong
origin** — requests simply fail locally.

**Why not blocking:** the supported journey is one project per folder; the
CLI refuses the ambiguous case and requires a deliberate `--project`
override to reach this. It is nonetheless the closest call in this audit and
should be fixed in the same pass as `NEW-01`.

### `NEW-31` (Medium) — `record_applied` is the one health write without a CAS predicate

`state.rs:593-599`:

```sql
UPDATE tracking_setups
   SET plan_summary_json = ?2, applied_at = ?3, applied_event_rowid = ?4,
       row_version = row_version + 1
 WHERE id = ?1
```

It **bumps** `row_version` (deliberately, so an in-flight refresh re-reads —
that is `VER-01` working) but carries **no `AND row_version = ?N`
predicate**, so it is last-writer-wins against a concurrent *apply*. Run A's
plan summary can land on run B's generation, after which undo acts on the
wrong `created_routes`. Every other health write goes through
`cas_write_health` (`state.rs:1043-1077`). One-line fix; everything around it
is already correct.

### `NEW-32` (Medium) — a failed apply erases route provenance

`previously_created` (`apply.rs:346-353`) reads `created_routes` from the
persisted plan summary, and a failed apply never reaches `record_applied`, so
it is empty. The successful retry therefore classifies routes its own first
attempt created as "reused", and undo strands them with the reason *"existed
before this setup (only reused)"* — factually false. This is ZFT-018's shape
reappearing through the failed-apply path;
`a_re_apply_keeps_the_first_applys_route_provenance` covers only re-apply
after a **successful** first apply. Repairable under Advanced → Gateway, but
the user is told the opposite of the truth.

### `NEW-33` (Medium) — `fail!` swallows illegal-transition errors

`apply.rs:288-305` retries `StateConflict` (bounded at 3) but `_ => break`
(`:298`) discards every other error, including `CoreError::InvalidInput` from
an illegal transition (`state.rs:561-567`). If a concurrent undo left the row
at `not_configured`, `NotConfigured → NeedsAttention` is illegal and the
failure record never reaches the row. The failure *is* returned in-process, so
the CLI still prints it — but the persisted state loses it.

### `NEW-34` (Medium) — a stale undo tears down a live setup before its CAS

`undo` does all destructive work **before** any CAS: links restored and rows
deleted (`undo.rs:97-107`), routes removed (`:111-127`), and only then
`state::transition` CAS on the stale `row_version` (`:169`). A stale undo
therefore dismantles a *newer* setup's configuration and then returns
`StateConflict`. Worse, the CLI does `track_undo::undo(…)?`
(`track_cmd.rs:1043`), so on conflict it prints **nothing** from the report —
not the restored links, not the removed routes — only a raw `state_conflict`
error, after the damage.

Partial mitigation: the next refresh sees `route_present=false` and reports
`ConfigurationChanged`. Both front ends re-read the setup immediately before
undoing (`main.rs:4226-4236`), so the window is narrow — but the ordering is
structurally wrong.

### `NEW-35` (Low) — a row stuck in `applying` reports "waiting for the first request"

`applying` is not in `refresh_once`'s watchable set (`state.rs:718-725`), so it
falls through to `health_without_evidence` (`:1133-1147`). Measured: with
liveness `Verified` or `Unknown` it renders *"waiting for the first request"*.
Every crash window in scenarios 9 and 10 is therefore mis-described — a
crashed apply tells the user to go make a request.

## 4. What is genuinely strong

* `.env` writes are atomic and symlink-safe.
* The restore record is always committed before the file it describes.
* The legacy scrub is properly transactional (`BEGIN IMMEDIATE` over the
  rewrite *and* the marker) and **defers rather than destroying undo** when no
  key is available.
* The `VER-01` CAS work on the refresh path is thorough and ships its own
  mutation control, `control_removing_the_cas_predicate_reintroduces_the_lost_update`.
* Re-running `track` converges: `apply_twice_converges_with_zero_new_rows`,
  and `merge_prior` keeps the **first** recorded prior so the original value
  survives repeated applies.
* Undo without a plan summary refuses to claim completion
  (`undo_refuses_to_report_success_when_the_plan_was_never_recorded`) and
  restores from ground truth
  (`undo_restores_links_it_finds_in_the_database_even_without_a_summary`).

## 5. Required-property matrix

| Property | Verdict |
| --- | --- |
| No silent corruption | **Fails** only in `NEW-28` (two projects, one `.env`) |
| No lost failure state | **Fails** in `NEW-33` (illegal transition swallowed) |
| No credentials sent to the wrong origin | **Holds** — unknown slug → 404 |
| No orphan route or link that cannot be repaired | **Holds** — all repairable under Advanced → Gateway, though `NEW-32` mislabels why |
| No plaintext rollback residue | **Holds** in the database; `NEW-29` is a filesystem temp-file gap |
| Recovery deterministic and user-visible | **Partial** — `NEW-34` suppresses the report, `NEW-35` mis-describes `applying` |
