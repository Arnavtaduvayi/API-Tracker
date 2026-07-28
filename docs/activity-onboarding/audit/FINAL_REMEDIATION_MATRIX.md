# Final re-audit — remediation matrix

Remediation of the independent re-audit recorded in
`docs/activity-onboarding/audit/fable-final-reaudit-20260727/`
(auditor: Claude Fable 5, max effort; audit branch `audit/fable-zft-final-20260727` @ `083d885`).

```text
Audited head:          4a89ced718754fdb1aa3383cfad426adb7c758e6
Implementation branch: feat/zero-friction-api-tracking
PR:                    #16 (OPEN, unmerged, base main) — NOT merged by this remediation
Audit artifacts:       read-only; not modified by this work
```

**This document is a remediation record, not a verdict.** Nothing here should be
read as merge readiness. A fresh independent audit is still required, and the
handoff (`FINAL_REAUDIT_HANDOFF.md`) exists to make that audit cheap to start.

---

## Runtime disclosure

```text
Model:                     claude-opus-5[1m] (Opus 5, 1M context)
Execution mode:            Claude Code CLI, interactive, ultracode orchestration enabled
Effort level:              xhigh (highest available in this session)
Fallback model:            none configured
Whether fallback occurred: no
```

---

## Merge-blocking findings

| ID | Sev | Status | Fix |
|---|---|---|---|
| `RA-001` | CRITICAL | **FIXED** | Sealed Git directories (ADR 0027) — repository configuration is structurally absent from every isolated Git read |
| `RA-002` | HIGH | **FIXED** | The NEGATIVE assertion's false premise replaced with a pre-apply baseline |
| `RA-003` | HIGH | **FIXED (structurally)** | Count gates derived from the registered checks; enumerator self-test wired into `--scope selfcheck`. The scope now reports `59/59` instead of INCONCLUSIVE. A clean *pass* still needs a machine with no installed Tethra gateway — see `REM-001` and the evidence §5 |
| `RA-004` | HIGH | **FIXED** | Refusal now precedes any trap; ownership ledger; isolated namespace |
| `RA-005` | HIGH | **FIXED** | Bounded skew window + insertion-ordered watermark; failure preservation on parsed instants |
| `RA-006` | HIGH | **FIXED** | Every recorded prior value encrypted under a vault-wrapped key (ADR 0028) |

---

### `RA-001` — repository-controlled code executes on the background monitor path

**Severity** CRITICAL · **Criterion** 1 · **Status** FIXED

**Reproduction (audit).** Ship a repository whose own `.git/config` sets
`[log] showSignature = true` and `[gpg] program = ./payload.sh`, plus a commit
carrying a fabricated `gpgsig` header. Select that folder in the Track flow and
start tracking — this registers it via `apply::ensure_project`. Push a
signed-looking commit; the victim pulls. The next desktop background monitor
tick runs `scan_repos_incremental` → `range_added_units` → `git log -p`, and the
repository's payload executes as the user with no interaction. Canary contents:
`"FIRED\n"`.

**Reproduced here before fixing.** Yes — `repro/repro_git_config_rce.sh` run
verbatim on this machine (git 2.50.1, Apple Git-155):

```text
  (no execution)    log --oneline -n 1 --all -- .env   (envgov::history_probe)
  *** EXECUTED ***  log -p --all                        (history_added_units)
        FIRED argv=--keyid-format=long --status-fd=1 --verify /var/.../.git_vtag_tmpz7Cb5j -
  *** EXECUTED ***  log -p -n 5                         (range_added_units)
  (no execution)    rev-parse HEAD / diff --cached / show HEAD:.env
```

**Root cause.** `gitrepo::hardened_config()` was an *enumeration* of 11 keys. It
omitted `log.showSignature` and `gpg.<format>.program`, and
`harden_config_sources()` neutralised the system and global configuration only.
There is no environment variable that switches off repository-local
configuration: the repository's config *is* `$GIT_DIR/config`, read because
`$GIT_DIR` is the repository. An enumeration cannot be completed against a file
the attacker writes.

**Fix.** `crates/core/src/gitseal.rs` (new) builds a **sealed Git directory**
per isolated invocation: a throwaway directory Tethra owns, holding only its own
config, `objects/info/alternates` pointing at the real object store, and copies
of refs/`HEAD`/index. Git runs as `git --git-dir=<sealed>`. Repository config,
worktree config, and their includes are not part of the repository Git reads.
Writes land in the throwaway directory, never the user's repository.
Unreproducible repository formats are **refused**, never retried against the
repository's own configuration. `repo_root` no longer spawns anything;
`git_available` is now bounded. The `-c` enumeration is kept and extended as an
independent second layer; `SCRUBBED_ENV` gained `GIT_EXEC_PATH`,
`GIT_COMMON_DIR`, `GIT_TEMPLATE_DIR`, the `GIT_TRACE*` sinks and three `DYLD_*`
hooks. Design and alternatives: ADR 0027.

**Regression test.** `crates/core/tests/git_isolation_canaries.rs` — 9 tests, 16
vectors, asserting per vector that (a) the vector arms against the product's own
argv with isolation removed, (b) the sealed directory **alone**, with no `-c`
overrides, closes it, and (c) the real product functions are clean and still
correct.

**Mutation / negative control.** The *armed* leg is the mutation: it runs the
product's exact argv against the real `.git` and requires the payload to fire.
Every vector declared reachable must arm — the previous suite's
`armed.len() >= 2` of ten is gone — and every excused vector must carry a
specific measured reason (`every_unreachable_vector_states_a_specific_reason`).
`sealed_reads_never_modify_the_repository` digests every file under `.git`
before and after.

**Residual risk.** The reproducible-`extensions.*` allowlist must grow as Git
adds extensions, or those repositories lose history scanning — a refusal, not a
compromise. `config_get` still reads the real configuration by design (it must
report the value Git would use); `git config --get` runs no hook, filter, driver
or verifier, and the canary suite exercises it against every vector.
`safe.directory` no longer fires for another user's repository, because the
gitdir Git validates is ours — noted in `KNOWN_LIMITATIONS.md`.

---

### `RA-002` — `--scope full` fails on its first-ever execution

**Severity** HIGH · **Criterion** 13 · **Status** FIXED

**Reproduction (audit).** `bash scripts/tracking_validate_macos.sh --scope full <app>` →
56 passed, 1 FAILED: *"the forged rows are gone and no pre-apply observation survives"*.

**Root cause.** The assertion's second clause required **no** observation to
predate `applied_at`. The apply's own keyless path check legitimately writes a
real gateway observation ~0.3 s earlier. The forged row *was* correctly deleted
and all four security-relevant assertions in the group passed: a harness defect
with a false premise, not a product vulnerability — but one that made the
packaged full-flow evidence unquotable.

**Fix.** `PRE_APPLY_ROWS` is captured **before** the forgery is inserted, and
the assertion now names every planted row by id and by session and compares
pre-apply rows against that baseline.

**Regression test.** The check itself, now with a true premise, plus the
enumerator self-test that keeps its group accounted for.

**Mutation.** Widening the cleanup `DELETE` to take real history fails the
assertion.

**Residual risk.** The fourth clause is a **floor** (`>= PRE_APPLY_ROWS`), not an
equality, and this is deliberate: `writer.rs` drains on a 250 ms
`recv_timeout` and commits per batch, so a legitimate observation can land
*during* the control, and an equality would trade a false premise for a flaky
one. Clauses 1–3 name every planted row explicitly, so a survivor cannot hide
under the floor.

---

### `RA-003` — `--scope full --require-service` unpassable by construction

**Severity** HIGH · **Criterion** 13 · **Status** FIXED

**Reproduction (audit).** The scope runs 59 checks against `EXPECTED=60`, so the
count-equality gate prints INCONCLUSIVE and exits 1 even with 59/59 passing.

**Root cause.** A hand-maintained per-mode total. `PACKAGED_VALIDATION.md:28`
carried the same slip (`57 − 3 + 5 = 59`, written as 60), which independently
corroborates that service mode had never completed.

**Fix.** The hardcoded table is gone. `group_size()` declares one number per
group; `scope_groups()` says which groups a tuple runs; `expected_total()` sums
them. No per-mode total exists in the file any more. Re-derived counts:

```text
common = HARNESS 5 + BUNDLE 5 + FIXTURE 3 + DRYRUN 6 + APPLY 9
       + NEGATIVE 8 + TRAFFIC 5 + PRIVACY 5 + IDEMPOTENCE 4 + UNDO 4  = 54
full:foreground = 54 + FOREGROUND 3 = 57
full:service    = 54 + SERVICE 5    = 59
offline = 20 · selfcheck = 5
```

**Regression test.** `enumerate_checks()` — an awk pass over the script itself
that attributes every counted call site to its group, resolves the
`$SCOPE`/`$MODE` guards for the tuple being enumerated, and is **fail-closed**
(a check inside a loop, a runtime branch emitting different counts, or an
uncountable invocation shape is an error, not a guess). `verify_check_inventory()`
proves the table against the source for all four tuples and runs inside the
HARNESS group, so CI's `--scope selfcheck` gates on it. A per-group runtime gate
was added alongside the total.

**Mutation.** Seven mutants, all correctly rejected: a group size off by one; a
deleted check; an added check; a check hidden behind a runtime `if`; a removed
`#@uncounted` marker; a check inside a loop; a tuple mapped to an extra group.
Separately, mutating `ok()` so one check stops bumping its group counter yields
total 5 == expected 5 yet fails the per-group gate — the compensating-drift case
the total alone cannot see.

**Residual risk.** The enumerator understands this script's idioms; a genuinely
new invocation shape is rejected rather than miscounted, which will read as a
false alarm until the shape is taught to it. That is the intended direction.

---

### `RA-004` — `gateway_validate_macos.sh` destroys a production LaunchAgent on its refusal path

**Severity** HIGH · **Criterion** 4 · **Status** FIXED

**Reproduction (audit).** Read-only; the auditor did not run it. On a machine
with `~/Library/LaunchAgents/dev.api-tracker.gateway.plist`, the script prints
REFUSING and exits 2 — firing the EXIT trap registered at `:71`, *above* the
guard at `:73-75`. `cleanup()` runs `launchctl bootout gui/$UID/<label>` and
`rm -f "$PLIST"` against the user's real, hardcoded label.

**Reproduced here before fixing.** Yes, under a fake `$HOME` with a shimmed
`launchctl`: the refusal path deleted the plist **and** attempted
`launchctl bootout gui/501/dev.api-tracker.gateway`. That second effect is worse
than reported — `bootout` addresses the live `gui/<uid>` domain regardless of
`$HOME`, so the refusal would have stopped the user's running gateway even under
a fake HOME. Only the shim prevented it.

**Fix.** Nine changes, all required by the brief: the refusal executes before any
destructive trap is registered; the run defaults to an isolated namespace whose
label comes from the product's own `installation_id` (so shell cannot drift from
the code that writes the plist); production identifiers are refused outright; an
**ownership ledger** records every file, process and label this run created, each
with re-provable evidence; cleanup is ledger-driven and existence-guarded, and
explicitly skips the production label and plist; no `pkill`/`killall`/pattern
matching exists anywhere — process identity is verified by pid plus
`ps -o comm=` prefix; pre-existing files are never deleted; repeated cleanup is
idempotent; every refusal path is read-only.

**Regression test.** A fake-`$HOME` harness with a production-like plist,
asserting sha256, size, mtime and mode are byte-identical after the refusal, that
no `launchctl` invocation was attempted, and that no scratch directory leaked.
Plus a teardown proof with a decoy plist, a decoy scratch dir and a decoy process,
and two new unconditional in-script assertions (step 31) that the production
signature is unchanged and the production label was never registered.

**Mutation — reported honestly.** Moving `trap cleanup EXIT` back above the
guard, *alone*, **still passes**: with a ledger-bounded `cleanup`, the early trap
fires against an empty ledger and does nothing. Reverting the ledger layer alone
also still passes. Reverting **both** fails (`plist: DELETED`), and so does the
real pre-fix file from `git show HEAD:` — which also records
`launchctl bootout gui/501/dev.api-tracker.gateway`. The harness therefore has
real detecting power against the historical defect; the two layers are
independent, which is why neither mutation kills on its own.

**Residual risk.** The script now requires `python3` at preflight. It is
referenced by `tracking_validate_macos.sh:936-940` as documentation, not as a
call site (no invocation exists anywhere in the repository).

---

### `RA-005` — a future-dated observation yields indefinite verification and erases a failure

**Severity** HIGH · **Criterion** 3 · **Status** FIXED

**Reproduction (audit).** `repro/verification_future.rs`, both tests failing:
an observation dated one year ahead reads `VerifiedAndActive` with `fresh:true`;
with a failure recorded now, persisted state becomes `TrafficObserved` and
`attention_reason` becomes `None`.

**Root cause.** `state.rs` bounded freshness on **one side only**
(`at >= stale_before`), and the SQL had no upper bound either. `failure_is_newer`
was a plain RFC 3339 **string** comparison, so the future event out-ranked a
failure recorded now and `write_derived` persistently nulled `attention_reason`
and `attention_at`. `verification_session` appeared in no `WHERE` clause, so
session isolation rested entirely on the timestamp watermark the forgery
defeated.

**Fix.** Three independent admissibility conditions, all required:

* `rowid > applied_event_rowid` — an **insertion-ordered** watermark
  (migration 18) captured at apply time. SQLite assigns rowids monotonically, so
  this is an ordering signal no writer's clock can influence, and it is what
  actually binds an observation to the current verification session.
* `at >= applied_at` — no back-dating into a previous session.
* `at <= now + MAX_CLOCK_SKEW_SECS` (300 s) — a documented, bounded skew window.
  Out-of-window observations are **excluded**, not clamped: a timestamp we cannot
  believe is not evidence, and rewriting it would make the stored row disagree
  with what the reader acted on.

`failure_is_newer` now compares **parsed instants**, failing closed (an
unparseable timestamp preserves the failure). This also fixes a latent sub-second
defect: `now_rfc3339` omits the fractional part when nanoseconds are zero, and
`'.'` sorts before `'Z'`, so `12:00:00.5Z` compared as *older* than `12:00:00Z`.
`verify::latest_exchange` applies the identical admissibility, so the screen
cannot quote an exchange the derivation refused to count.

**Regression test.** `crates/tracking/tests/verification_clock.rs` — 15 tests:
both audit reproductions, 1 s skew, the boundary in both directions, an excessive
future observation, a far-future observation read five times, clock rollback,
clock jump forward, a new failure after a future observation across repeated
reads, a previous-session observation, a row inserted before apply however dated,
route/link generation change, and historical-vs-current health.

**Mutation / negative control.**
`control_the_audited_head_predicate_would_have_accepted_the_future_row` asserts
the *old* one-sided predicate still accepts a year-ahead timestamp — if it ever
stops, the fixture is no longer producing a future row and the suite is vacuous.
`control_without_a_failure_an_admissible_observation_does_flip_the_state` proves
the derivation really writes `traffic_observed`, so the failure-preservation
assertions are not passing because nothing happens.

**Residual risk.** Rowids are reused without `AUTOINCREMENT` if the highest row
is deleted; retention deletes oldest-first, and the timestamp conditions are
independent belt-and-braces. Existing rows migrate with watermark 0, which admits
exactly what they admitted before — an upgrade does not retroactively
un-verify a working setup.

---

### `RA-006` — `prior_value_is_recordable` writes real secrets to a plaintext column

**Severity** HIGH · **Status** FIXED

**Reproduction (audit).** Link with `--var OPENAI_API_KEY` over
`sk-proj-AbCdEf123456.xyz789`, or any value containing a dot or a colon: written
verbatim with `prior_withheld:false` and no warning. Three test values are
flagged by the codebase's own `looks_like_key_material` yet recorded anyway,
including a JWT — the shape of `SUPABASE_SERVICE_ROLE_KEY`, a trackable
provider's RLS-bypassing admin credential. Canary recovered from raw `vault.db`
at byte offset 527996.

**Root cause.** A **shape predicate** decided what was safe to write into an
unencrypted column. The URL branch consulted `looks_like_key_material`; the
non-URL branch never did. The two predicates contradicted each other on the same
input — the signal that the design required a correct answer to "is this string
a secret?", which has no reliable answer.

**Fix.** The question is gone. Every recorded prior value is sealed with
XChaCha20-Poly1305 under a per-vault env-restore key, wrapped under the vault key
(`vault_meta.wrapped_env_restore_key`), with associated data binding each
ciphertext to `{vault_id}:{link_slug}:{path}:{key}`. Only *structure* stays in
the clear. Without a key the value is **withheld**, never written in the clear.
Legacy v1 plaintext records are re-sealed at unlock — and the keyless scrub is a
deliberate no-op, because redacting would take away an undo a later unlocked call
can preserve. Design, key custody and alternatives: ADR 0028.

**Regression test.** `crates/gateway/tests/restore_record_privacy.rs` — for ten
deliberately awkward secret shapes (API key, DB password, Supabase JWT,
connection string, authorization value, credential-bearing URL, AWS-shaped
secret whose slashes defeat entropy scoring, generic high-entropy value, a secret
under a misleading variable name, and a short value the placeholder floor waved
through), the canary appears in **no** persistence surface — main DB, WAL, SHM,
read as raw bytes — and undo restores the value byte-for-byte. Plus:
residue-after-unlink, the keyless withheld path, and transplant resistance.
`crates/core/src/envrestore.rs` carries 6 unit tests.

**Mutation / negative control.**
`control_the_disk_sweep_can_find_a_planted_needle` plants a value in
`vault_meta`, checkpoints, and requires the sweep to find it — without it, every
absence assertion would be vacuous.

**Residual risk.** A user who loses their vault password loses *automatic*
restore for links made before that point; they keep the structural record and
`unlink` says so. v1 records are re-sealed lazily at the next unlock. The consent
diff still shows a declared base URL's removed value verbatim — deliberate (the
user must see what is being replaced), on-screen only, never persisted; recorded
in `KNOWN_LIMITATIONS.md`.

---

## Found by this remediation, not by the audit

| ID | Sev | Status | Summary |
|---|---|---|---|
| `REM-001` | HIGH | **FIXED** | `tracking_validate_macos.sh --scope full --require-service` stopped this machine's live production gateway. Its interlock globs `$HOME/Library/LaunchAgents`; `launchctl` addresses `gui/<uid>`, which `$HOME` does not isolate — so redirecting `HOME` (the previous auditor's own documented technique) walks past the interlock while every `launchctl` call still lands on the user's real service. Same shape as `RA-004`, in a second script, invisible until `RA-003` was fixed and service mode could run at all. The interlock now asks launchd as well as the filesystem, verified against the exact condition that caused the damage. The user's gateway was restored from its own unmodified plist and is running; it was down for about six minutes. Full record in `FINAL_REMEDIATION_EVIDENCE.md` §4b. |

---

## Non-blocking findings

| ID | Sev | Status |
|---|---|---|
| `RA-007` | MEDIUM | see `FINAL_REMEDIATION_EVIDENCE.md` |
| `RA-008` | MEDIUM | see `FINAL_REMEDIATION_EVIDENCE.md` |
| `RA-009` | MEDIUM | see `FINAL_REMEDIATION_EVIDENCE.md` |
| `RA-010` | MEDIUM | see `FINAL_REMEDIATION_EVIDENCE.md` |
| `RA-011` | MEDIUM | see `FINAL_REMEDIATION_EVIDENCE.md` |
| `RA-012` | MEDIUM | see `FINAL_REMEDIATION_EVIDENCE.md` |
| `RA-013` | MEDIUM | see `FINAL_REMEDIATION_EVIDENCE.md` |
| `RA-014` | LOW | see `FINAL_REMEDIATION_EVIDENCE.md` |
| `RA-015` | LOW | **FIXED** — `--help` cut point computed (`awk '!/^#/ { exit }'`) instead of `sed -n '1,89p'`; every printed total reconciled with the enforced table |
| `RA-016` | LOW | **FIXED** — `DefinitionState { Absent, Present, Unparseable }`; `ensure_ours` refuses the unparseable case, matching ADR 0026 D2 and the install path's wording |
| `RA-017` | LOW | **FIXED** — `xai.toml` declares `XAI_MANAGEMENT_KEY` *and* `XAI_MANAGEMENT_API_KEY` (both are real; see evidence) |
| `RA-018` | LOW | see `FINAL_REMEDIATION_EVIDENCE.md` |
| `RA-019` | INFO | **DOCUMENTED** — `gateway_route_add` is stated in the threat model as vault-unlock-gated, not reauth-gated |

---

## Original 15 merge blockers — recheck against the new head

| ID | Audit verdict at `4a89ced` | Status now |
|---|---|---|
| `ZFT-001` scanning executed repo code | **NOT RESOLVED** (new route → `RA-001`) | **RESOLVED** via ADR 0027 |
| `ZFT-002` symlink escape in manifest reader | RESOLVED | still resolved |
| `ZFT-003` `.env` read with no size cap | RESOLVED | still resolved |
| `ZFT-004` repo content authorized a route origin | RESOLVED | still resolved (`RA-010`/`RA-011` residue addressed) |
| `ZFT-005` "verified" survived a dead gateway | RESOLVED | still resolved |
| `ZFT-006` failed re-run reported verified | **NOT RESOLVED** (via clock → `RA-005`) | **RESOLVED** via bounded freshness |
| `ZFT-007` undo reported success having done nothing | RESOLVED | still resolved |
| `ZFT-008` re-derivation skipped on missing watermark | RESOLVED | still resolved |
| `ZFT-009` unsupported dead end demanded CLI commands | RESOLVED | still resolved |
| `ZFT-010` unknown credentials silently dropped | RESOLVED | still resolved |
| `ZFT-011` three trackable providers | RESOLVED | still resolved |
| `ZFT-012` custom base URL silently re-pointed | RESOLVED (residue `RA-010`) | residue addressed |
| `ZFT-013` attribution consent under-disclosed | RESOLVED (residue `RA-012`) | residue addressed |
| `ZFT-014` one environment booted out another's service | **NOT RESOLVED** via `RA-004` | **RESOLVED** — script fixed |
| `ZFT-015` "Waiting for traffic…" after polling stopped | RESOLVED (guard absent, `RA-014`) | guard added |

The per-blocker reproductions are recorded in `FINAL_REMEDIATION_EVIDENCE.md`.

---

## What this remediation did NOT change

Preserved deliberately, and re-verified: zero-terminal packaged setup; bundled
helper independence; built-in origin automation; explicit custom-origin approval;
`--yes` refusal for untrusted origins; service namespacing; current route and
link verification; the gateway security suite; the privacy canaries; the bulk
provider workflow; byte-for-byte undo. The successful zero-friction workflow was
not redesigned.
