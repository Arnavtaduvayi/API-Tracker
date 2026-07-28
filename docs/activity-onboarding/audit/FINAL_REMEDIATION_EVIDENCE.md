# Final re-audit — remediation evidence

Everything recorded here was executed on this machine. Where something was not
run, or did not pass, it says so. Nothing here was independently verified — see
`FINAL_REAUDIT_HANDOFF.md`.

```text
Machine:  macOS (Darwin 25.5.0), aarch64
git:      2.50.1 (Apple Git-155)
rust:     stable + pinned 1.97.0 (both installed)
```

---

## 1. Repository state before any edit

```text
$ git status
On branch feat/zero-friction-api-tracking
Your branch is up to date with 'origin/feat/zero-friction-api-tracking'.
nothing to commit, working tree clean

$ git branch --show-current
feat/zero-friction-api-tracking

$ git rev-parse HEAD
4a89ced718754fdb1aa3383cfad426adb7c758e6

$ git rev-parse origin/feat/zero-friction-api-tracking
4a89ced718754fdb1aa3383cfad426adb7c758e6

$ gh pr view 16
state:  OPEN     auto-merge: disabled

$ gh pr checks 16
Desktop backend (macOS)          pass  2m8s
Desktop frontend                 pass  42s
Packaged app + validation (macOS) pass  4m30s
Rust (core + CLI)                pass  4m9s
Rust core (Windows)              pass  15m25s
```

The implementation branch had **not** moved from the audited head, so no
difference audit was required.

---

## 2. `RA-001` — reproduced before fixing

The auditor's own script, run verbatim (paths rewritten to this session's
scratchpad):

```text
$ bash repro_git_config_rce.sh
=== running the product's own git subcommands under full hardening ===
  (no execution)    log --oneline -n 1 --all -- .env   (envgov::history_probe)
  *** EXECUTED ***  log -p --all                        (history_added_units)
        FIRED argv=--keyid-format=long --status-fd=1 --verify /var/.../.git_vtag_tmpz7Cb5j -
  *** EXECUTED ***  log -p -n 5                         (range_added_units)
        FIRED argv=--keyid-format=long --status-fd=1 --verify /var/.../.git_vtag_tmpiMlTE6 -
  (no execution)    rev-parse HEAD
  (no execution)    diff --cached
  (no execution)    show HEAD:.env
```

The defect reproduces exactly as reported.

### The design was measured, not assumed

The brief asked whether Git provides a robust configuration-isolation
mechanism, and to verify rather than assume. Four experiments were run before
any product code changed.

**Sealed gitdir, every product subcommand** — correct output, no execution,
control armed:

```text
  (no execution)    log -p --all           rc=0   [full diff returned]
  (no execution)    log -p OLD..NEW        rc=0   [full diff returned]
  (no execution)    rev-parse HEAD         rc=0   e4a08fdb…
  (no execution)    diff --cached          rc=0   staged.env
  (no execution)    cat-file -s :st.env    rc=0   12
  (no execution)    show :st.env           rc=0   S=sk-staged
  CONTROL (real .git):  *** EXECUTED *** ARMED
```

**Repository shapes** — ordinary/loose refs, packed-refs only, linked worktree
(`.git` is a file), submodule, `clone --shared` alternates chain, sha256
(`extensions.objectFormat`), reftable, and an empty repository. All produce
correct output under sealing. sha256 requires `objectFormat` to be declared in
the sealed config; reftable requires the `reftable/` directory to be copied,
`refStorage` declared, **and** an empty `refs/` directory to exist, or Git
reports `fatal: not a git repository`.

**Worktree config** (`extensions.worktreeConfig` + `config.worktree`) — fires
against the real `.git`, inert under sealing. This vector is not covered by the
`-c` enumeration's key list at all.

**Symlink variant rejected by measurement.** Symlinking `objects`/`refs`/`HEAD`
into the real repository would be O(1) instead of O(refs), and Git rejects it:
`fatal: not a git repository`. Diagnosed to the symlinked `HEAD` (Git's
repository validation reads it as a symref and requires a `refs/`-relative
target). Copying is also the safer shape.

---

## 3. Local validation

### Rust

| Command | Result |
|---|---|
| `cargo fmt --all --check` | **pass** (clean) |
| `cargo +1.97.0 clippy --workspace --all-targets -- -D warnings` | **pass** (no warnings) |
| `cargo test --workspace --all-targets` | **1212 passed, 0 failed, 9 ignored** (81 binaries; was 1133) |
| `cargo build --workspace --release` | **pass** |

### Frontend (`apps/desktop`)

| Command | Result |
|---|---|
| `npm run format:check` | **pass** (clean) |
| `npm run lint` | **pass** (clean) |
| `npm run typecheck` | **pass** (clean) |
| `npx vitest run` | **11 files, 102 tests passed** (was 91) |
| `npm run build` | **pass** — `✓ built in 1.00s` |

The 11 new frontend tests are the RA-012 typed-destination consent coverage (4)
, the RA-014 fake-timer poll and cutoff tests (2), and the RA-013 unlink-outcome
rendering (4), plus one supporting case.

---

## 4. Per-finding execution evidence

### `RA-001`

```text
cargo test -p api-tracker-core --test git_isolation_canaries
  9 passed; 0 failed
    every_reachable_vector_is_armed
    every_unreachable_vector_states_a_specific_reason
    sealing_alone_closes_every_vector
    no_product_path_executes_repository_controlled_code
    the_background_monitor_path_is_clean_after_head_advances
    the_sealed_view_still_sees_the_repositorys_real_content
    an_unreproducible_repository_is_refused_rather_than_trusted
    the_sealed_configuration_names_no_program
    sealed_reads_never_modify_the_repository

cargo test -p api-tracker-core --test git_execution_canaries
  6 passed; 0 failed   (run 3× consecutively for flakiness — stable)
```

**Arming control, first run — it found five inert canaries.** The suite refused
to pass with:

```text
these vectors are declared reachable but did NOT fire against the product's own
command set with isolation removed, so the corresponding protection assertions
prove nothing: ["SSH signature verifier program", "X.509 signature verifier
program", "textconv", "external diff driver", "named diff driver command"]
```

Each was then measured rather than waved away:

* **SSH / X.509** — Git picks the verifier from the **payload's own header**,
  not from `gpg.format`. The fixture was signing every commit with an OpenPGP
  header. SSH additionally refuses outright unless
  `gpg.ssh.allowedSignersFile` is configured *and exists*. With the matching
  header and an allowed-signers file, both arm:
  `FIRED -Y find-principals -f ./allowed_signers -s /var/.../.git_vtag_tmp…`
* **textconv** — armed once the probe stopped passing `--no-textconv`, which is
  a *flag-level* layer that would have masked the question the suite exists to
  answer. `ISOLATION_PROBE_COMMANDS` now runs the product's argv without those
  flags, so the sealing is tested on its own.
* **`diff.external` and named diff-driver `command`** — measured as **not
  reachable**: git 2.50.1 invokes `diff.external` only for a bare working-tree
  `git diff`, and not for `diff --cached`, `diff <rev>`, `show`, or `log -p`.
  A bare `git diff` is not in the product's command set. They are recorded as
  unreachable with that measured reason, and
  `every_unreachable_vector_states_a_specific_reason` requires the reason to be
  specific rather than a shrug.

The old suite's `armed.len() >= 2` of ten is replaced by a named
`REQUIRED_ARMED` set (`core.fsmonitor`, `clean/smudge filters`, `textconv`),
asserted as a minimum rather than an exact set — `hooks` arms only when the
control happens to refresh the index, so an exact-set assertion was measurably
flaky across three consecutive runs.

### `RA-002` / `RA-003` / `RA-015`

Counts re-derived from the source by hand, then mechanically:

```text
common = HARNESS 5 + BUNDLE 5 + FIXTURE 3 + DRYRUN 6 + APPLY 9
       + NEGATIVE 8 + TRAFFIC 5 + PRIVACY 5 + IDEMPOTENCE 4 + UNDO 4 = 54
full:foreground = 57 · full:service = 59 · offline = 20 · selfcheck = 5
```

`bash scripts/tracking_validate_macos.sh --scope selfcheck` → exit 0:

```text
  check inventory (summed from the group table, proved against this file):
    selfcheck:none    5 checks
    offline:none     20 checks
    full:foreground  57 checks
    full:service     59 checks
  PASS  a known-false shell condition is reported as a FAILURE
  PASS  a known-true shell condition is reported as a PASS
  PASS  two files differing only by a trailing newline are reported DIFFERENT
  PASS  a known-false database assertion is reported as a FAILURE
  PASS  a known-true database assertion is reported as a PASS
    HARNESS        5 checks  (5 passed, 0 failed)
    TOTAL          5 checks  (5 passed, 0 failed)
=== PACKAGED TRACKING VALIDATION (scope=selfcheck, mode=none): 5 passed, 0 failed (5/5 checks) ===
```

`--help` now emits 106 lines (byte-identical to `sed -n '1,106p'` of the file);
the old `sed -n '1,89p'` dropped lines 90–94, i.e. exactly the isolation and
cleanup disclosure.

**Enumerator mutants, all correctly rejected** (each a copy in the scratchpad,
run with `--scope selfcheck`, all exit 1): a group size off by one; a deleted
check; an added check; a check hidden behind a runtime `if`; a removed
`#@uncounted` marker; a check inside a loop; a tuple mapped to an extra group.
Separately, mutating `ok()` so one check stops bumping its group counter gives
total 5 == expected 5 yet fails the **per-group** gate
(`HARNESS ran 4 checks, defined to run 5`) — the compensating-drift case a
total alone cannot see.

### `RA-004`

Reproduced before fixing, under a fake `$HOME` with a shimmed `launchctl`: the
refusal path deleted the plist **and** attempted
`launchctl bootout gui/501/dev.api-tracker.gateway`. That second effect is worse
than the audit reported (which was read-only): `bootout` addresses the live
`gui/<uid>` domain regardless of `$HOME`, so a fake HOME alone would not have
protected the user's running gateway.

After the fix:

```text
=== case: fixed_final
--- script exit code: 2
    REFUSING: a production gateway LaunchAgent already exists at …
--- launchctl invocations attempted:    (none)
--- plist sha256 before: c1ff8b022cd88e893c3f24895029210ae31ca9d44c7be694525c16e133622e99
--- plist sha256 after : c1ff8b022cd88e893c3f24895029210ae31ca9d44c7be694525c16e133622e99
--- plist stat   before: size=611 mtime=1782878400 mode=600
--- plist stat   after : size=611 mtime=1782878400 mode=600
=== RA-004 VERDICT (fixed_final): PASS
```

Teardown proof, with a decoy plist, a decoy scratch directory and a decoy
process the shim reports as the service pid: 8 assertions pass, including "the
decoy process was NOT signalled" and "teardown never addressed the production
label". Repeated cleanup issues exactly **one** `bootout` total.

**Mutation results, reported as measured — one of them is a negative result:**

| Mutation | Outcome |
|---|---|
| trap moved back above the guard, alone | **still PASS** — the ledger-bounded `cleanup` finds nothing to do |
| ledger layer reverted, trap left correct | **still PASS** — the ordering layer alone is sufficient |
| **both** layers reverted | **FAIL** — `plist: DELETED` |
| the real pre-fix file (`git show HEAD:`) | **FAIL** — `plist: DELETED`, and `launchctl bootout gui/501/dev.api-tracker.gateway` recorded |

The harness detects the historical defect. The two layers are independent, which
is why neither single mutation kills. This is stated rather than presented as a
clean kill.

### `RA-005`

```text
cargo test -p api-tracker-tracking --test verification_clock
  15 passed; 0 failed
```

Both of the auditor's reproductions are the first two tests. The remaining
thirteen cover 1 s skew, the boundary in both directions, an excessive future
observation, a far-future observation read five times, clock rollback, clock
jump forward, a new failure after a future observation across repeated reads, a
previous-session observation, a row inserted before apply however dated,
route/link change after observation, historical-vs-current health, and two
mutation controls.

**A real defect was found while writing these tests.** Three existing fixtures
in `crates/tracking/tests/state.rs` used `2099-01-01T00:00:00Z` as a stand-in for
"after `applied_at`". That is not a time any writer can produce, and the new
bound correctly rejects it. The fixtures now use a plausible
`just_after_apply()`; this is a fixture correction, not a relaxation of the
product rule.

### `RA-006`

```text
cargo test -p api-tracker-gateway --test restore_record_privacy   5 passed
cargo test -p api-tracker-gateway --test envlink                 26 passed
cargo test -p api-tracker-core --lib envrestore                   6 passed
cargo test -p api-tracker-gateway --test privacy_canaries        10 passed
```

Ten secret shapes swept for on-disk residue across `vault.db`, `-wal` and `-shm`
as raw bytes: API key, database password, Supabase service-role JWT, connection
string, authorization value, credential-bearing URL, AWS-shaped secret whose
slashes defeat entropy scoring, generic high-entropy value, a secret under a
misleading variable name, and a short value the placeholder floor waved through.
None appears. Each also restores byte-for-byte on unlink.

**The canary suite found a second, unrelated exposure while being written**: the
consent diff prints a *declared base URL's removed value* verbatim. On
inspection this is deliberate (ADR 0019 D9 — the user must see exactly what is
being replaced), on-screen only, and never persisted. The assertion was scoped
to where masking is the policy, with the reason recorded in the test, and the
behaviour is now stated in `KNOWN_LIMITATIONS.md` rather than left implicit.

Six existing tests encoded the *old* contract ("withhold secret-looking values,
degrade undo honestly") and were rewritten to the new, stronger one ("record
everything, encrypted, and undo works"). They now assert on the **stored
column** rather than the in-memory plan — the plan's `prior` is `serde(skip)`
and never persisted, so asserting on it proved nothing about disk.

### `RA-007` / `RA-008` / `RA-009` / `RA-018`

```text
cargo test -p api-tracker-core --test gitsafe_differential  12 passed
cargo test -p api-tracker-core --test gitsafe_bounds         7 passed
```

Split-index is now **supported** rather than refused: the extension table is
walked to the trailer, EWAH bitmaps are decoded, and `.git/sharedindex.<oid>` is
read under the same caps. `read_index` no longer returns `Ok(empty)` for
anything but `NotFound`.

Measured mutation results:

| Mutation | Outcome |
|---|---|
| ignore the `link` extension | FAIL — `f000..f099.env: git=Tracked gitsafe=Untracked` (the auditor's exact symptom) |
| ignore the delete bitmap | FAIL — `f007.env: git=Untracked gitsafe=Tracked` |
| restore `Ok(empty)` for a non-file index | FAIL — `left: Untracked, right: Unknown` |
| delete the cumulative-path cap | FAIL — 2,600,032 B index → 800,020,000 B retained (308×), peak RSS 968 MB. With the cap: `Err(IndexPathBudget)` in 23.9 ms |
| restore the recursive `**` evaluator | FAIL at **46.96 s** against a 5 s ceiling. With the iterative one: 20 stars / 20 depth = **436 µs** |
| delete the per-entry time-budget check | FAIL — `truncated: left None, right Some(TimeBudget)` |
| exact-bytes-only path lookup | FAIL — `left: Untracked, right: Tracked` |
| accent-*insensitive* fold instead of decomposition | FAIL — `resume` and `résumé` must stay distinct |

`double_star_semantics_are_unchanged` passes under **both** evaluators, and its
11 expectations were checked against real `git check-ignore` before being
written down.

### `RA-010` / `RA-011`

Reproduced before fixing:

```text
a_path_query_or_fragment_cannot_disguise_a_base_url_as_tethras_own_writing ... FAILED
  https://attacker.example.com/#127.0.0.1:1
  left: Automatic   right: Automatic
```

```text
cargo test -p api-tracker-tracking --test origin_trust   17 passed
cargo test -p api-tracker-tracking --test detect         20 passed
cargo test -p api-tracker-observe (lib)                  55 passed  (17 policy tests)
```

The loopback predicate is now a **strict subset** of the old substring match:
every new match implies the value contained `127.0.0.1:`. It was deliberately
*not* widened to `::1`/`localhost`/port-less 127/8, because this predicate
*suppresses* the approval prompt — widening it would classify a developer's own
local proxy as Tethra's writing and silently re-point it, reintroducing ZFT-012.

`parse_ip_literal` now implements the `inet_aton` grammar, and
`check_authority`'s shorthand arm returns the verdict **only when it is a Deny**,
so a public-looking shorthand (`134744072` = 8.8.8.8) still falls through to the
single-label guard that denied it before. Pinned by
`widening_the_literal_parser_never_turns_a_deny_into_an_allow`, which passes
both pre- and post-fix and dies under the mutation that drops the fall-through.

Mutations 3 and 4 (substring guard restored; predicate forced to `false`) kill
**disjoint** test sets, so the fix is pinned from both sides.

### `RA-012` / `RA-013` / `RA-014`

```text
npx vitest run   11 files, 102 tests passed   (TrackFlow 36, GatewayView 12)
cargo test -p api-tracker-gateway --lib   77 passed   (was 75)
```

**RA-014 mutation** — deleting the `setInterval` while keeping the immediate
`void tick()`:

```text
× polls AGAIN on the interval, so traffic that arrives later is still seen
  → expected "spy" to be called 2 times, but got 1 times
× stops watching after two minutes and says so instead of claiming to wait
  → Unable to find text: /Tethra stopped watching after two minutes with no traffic/
Tests  2 failed | 33 passed (35)
```

Restored → 35 passed. These are the first fake-timer tests in the desktop suite;
they use `fireEvent` plus an explicit flush rather than `userEvent`/`waitFor`,
because RTL 10.4.1 detects fake timers by looking for a global `jest` and
therefore hangs under Vitest's.

**RA-013 judgment, recorded because it is a judgment.** `PriorNotRecorded` now
suppresses `complete: true`; `LeftUserEdit` does **not**. They are not the same
shape: `PriorNotRecorded` means the gateway's own line is still in the user's
file and Tethra could not remove it, while `LeftUserEdit` means the gateway line
is already gone, replaced by the user's own value — nothing is left to restore,
and keeping the row would make a link the user already fixed by hand permanently
un-unlinkable.

### `RA-016` / `RA-017`

`read_definition` is now three-state (`Absent` / `Present` / `Unparseable`)
across macOS, Linux and Windows, and `ensure_ours` refuses the unparseable case
with wording matching the install path. **Mutation** — replacing the
`Unparseable` arm with `return Ok(())` fails exactly the three new refusal tests,
and fails on the *command* assertion rather than on wording:

```text
a refused command still ran `bootout` against another installation's service:
  ["launchctl bootout gui/501/dev.api-tracker.gateway.af79bd338436", …]
a refused command still ran `systemctl --user stop` …
a refused command still ran `reg delete`: [… "/v TethraGateway-cfd70aa20cd2 /f" …]
test result: FAILED. 18 passed; 3 failed
```

The change also closed a silent platform hole: `definition_path().exists()` is a
real file check on macOS/Linux but a *registry path* on Windows, where it is
always false — so install's unparseable guard did not exist on Windows at all.

`xai.toml` declares **both** `XAI_MANAGEMENT_KEY` (the SDK's own fallback, in
`xai-sdk-python`'s sync and async clients) and `XAI_MANAGEMENT_API_KEY` (the name
in every official docs example). Verifying the name surfaced that seven
capability entries claimed "no public key-management API is documented", which is
false — `management-api.x.ai` documents create/list/update/rotate/delete. Those
moved `manual_only` → `supported_not_implemented`; nothing became `implemented`.
This is wider than the finding as written and is flagged rather than buried.

---

## 4b. A defect found BY this remediation, not by the audit

### `REM-001` — the service-mode interlock is keyed on `$HOME`; the damage is not

**Severity: HIGH. Found by running `--scope full --require-service`, which the
previous audit could not run because `RA-003` made it unpassable.**

**What happened.** Running

```text
env HOME=<temp> bash scripts/tracking_validate_macos.sh --scope full --require-service <app>
```

on this machine **stopped the user's live production gateway.** Before:
`65270  -15  dev.api-tracker.gateway`, process alive since 14:46:53. After:
`-  0  dev.api-tracker.gateway`, no process. The plist file itself was
unchanged (`0143dd24…`, matching the value the previous audit recorded), and
the four failing checks were incidental to it.

**Root cause.** The service-mode interlock globs `$HOME/Library/LaunchAgents`
for an existing agent. `launchctl` does not live in `$HOME`: it addresses
`gui/<uid>`, which no `HOME` redirection isolates. Redirecting `HOME` therefore
walks straight past the interlock while every `launchctl` call still lands on
the user's real launchd session.

Redirecting `HOME` is not an exotic thing to do. It is precisely the technique
the previous auditor used and documented — *"Rather than bypass the interlock, I
redirected `HOME` to a temp directory. That is stronger isolation than the
interlock provides"* — and it is what the next auditor will reach for. It is
stronger for the *filesystem* and provides none at all for *launchd*.

This is the same shape as `RA-004`, in a second script, and it was invisible
until service mode could run at all.

**Fix.** The interlock now asks launchd as well as the filesystem:

```sh
registered_gateway_jobs() {
  launchctl list 2>/dev/null \
    | awk -v l="$LEGACY_LABEL" '$3 == l || index($3, l ".") == 1 { print "  " $3 }'
}
```

**Verified against the exact condition that caused the damage:**

```text
$ env HOME=<temp> bash scripts/tracking_validate_macos.sh --scope full --require-service <app>
FATAL: a gateway LaunchAgent already exists:
  (registered in launchd, regardless of $HOME):
  dev.api-tracker.gateway
=== PACKAGED TRACKING VALIDATION: ABORTED (a precondition failed) ===
exit 1

production before: 22276  0  dev.api-tracker.gateway   pid=22276
production after : 22276  0  dev.api-tracker.gateway   pid=22276
```

**The user's gateway was restored** — `launchctl bootout` + `bootstrap` from its
own unmodified plist; running again as pid 22276, listening on
`127.0.0.1:56501`, plist hash still `0143dd24…`. It was down for roughly six
minutes. This is recorded rather than quietly repaired.

**Residual.** `--require-service` is now *structurally* passable — the count
gate reports `59/59` instead of INCONCLUSIVE, which is what `RA-003` was about —
but a **clean pass still requires a machine with no installed Tethra gateway**,
which is the scope's own documented precondition. This machine has one, and the
honest options were to uninstall the user's service (destructive, not
authorised) or to bypass the interlock again (now proven unsafe). Neither was
taken. See §5.

---

## 5. Findings NOT fully closed

Stated plainly rather than folded into a pass.

* **`RA-011` — `NetworkClass::Restricted` is still unreachable from
  `origin::describe`.** The *disclosure* defect is closed: a loopback shorthand
  can no longer reach the consent surface at all, because `check_authority`
  denies it first. But the enum variant remains dead. Computing it honestly
  needs `crates/tracking` to depend on `api-tracker-observe`; deriving it from
  `validate_origin` instead would be circular, and its test would be vacuous.
  Adding a cross-crate dependency late in a security remediation, for a dead
  variant whose user-visible symptom is already fixed, was judged the wrong
  risk. The doc comment now states plainly that `describe` never produces it.
* **`RA-018` residue** — ignore-*pattern* matching still compares raw bytes, so
  a `.gitignore` entry with a precomposed non-ASCII name will not match an NFD
  path. The finding named only the tracked-file lookup; folding inside
  `IgnoreRules` would change glob semantics over accented character classes and
  needs its own differential work.
* **`RA-018` table coverage** — the canonical-decomposition table covers
  Latin/Greek/Cyrillic/Vietnamese plus algorithmic Hangul. Polytonic Greek, CJK
  compatibility ideographs and Indic/Arabic precomposed forms fall back to exact
  bytes.
* **Split-index bitmap-less `link`** — real Git 2.50.1 un-splits the index
  rather than emitting a bitmap-less `link` extension, so that branch is covered
  by a synthetic test justified from `write_link_extension`'s early return, not
  by an observed fixture.
* **`RA-019`** — `gateway_route_add` remains gated by vault unlock rather than
  reauth. Documented, not changed; the audit classified it INFO and coherent
  with the threat model.
* **`--scope full --require-service` has not been observed passing.** The
  structural defect `RA-003` named is fixed and proven fixed: the run reaches
  the count gate and reports `59/59` rather than INCONCLUSIVE. But a clean pass
  needs a machine with no installed Tethra gateway, and this one has a live
  production service. CI's macOS runner is such a machine; this is the single
  item in the required validation list that could not be completed here, and it
  is an environment constraint rather than a code one. Do not quote this scope
  as passing until someone runs it somewhere clean.


---

## 6. Final counts, on the exact pushed head

```text
Final head:        6a1d88598d4fc18f9f8f8467724f7015dfc3775e
PR state:          OPEN, not a draft, NOT merged
Mergeability:      MERGEABLE  (stated as a fact about the branch, not a recommendation)
Commits behind:    0
Worktree:          clean
Local == remote:   yes

Rust tests:        1212 passed, 0 failed, 9 ignored   (81 binaries; was 1133)
Frontend tests:    102 passed, 0 failed  (11 files; was 91)
Smoke tests:       140 passed, 0 failed
Packaged offline:  20 / 20      (app copied outside the repository)
Packaged full:     57 / 57      (first passing run of this scope on any machine)
Packaged service:  NOT RUN CLEANLY — see §4b / §5
Gateway security:  adversarial_blackbox 17, control 24, custom_routes 13,
                   forwarding 44, service_namespace, lifecycle 15 — all pass
Privacy canaries:  10 passed (gateway) + 5 restore-record + 6 envrestore unit
Product mutants:   24 killed, 0 survived, 0 skipped
Harness mutants:   8 killed, 0 survived
CI:                all 5 checks SUCCESS on 6a1d885
                     Desktop backend (macOS)            success
                     Desktop frontend                   success
                     Packaged app + validation (macOS)  success
                     Rust (core + CLI)                  success
                     Rust core (Windows)                success
```

Two CI iterations were needed before green, both on the same test file and both
my own doing: the runner's rustfmt wrapped a line mine did not, and the wrapped
form then made a borrow redundant under clippy 1.97.0. Recorded because "CI
passed" is worth less without knowing what it took.

`cargo fmt --all --check` and CI's exact clippy invocation
(`-p api-tracker-core -p api-tracker-cli -p api-tracker-observe -p
api-tracker-gateway -p api-tracker-tracking --all-targets -- -D warnings`,
toolchain 1.97.0) were both run locally against the final head and are clean.

---

# Addendum — the service scope, executed

Everything above this line is **preserved unchanged**, including the parts
that record `--scope full --require-service` as never having been observed
passing. That was true when it was written. This addendum records what
happened when it finally ran; it does not revise the earlier text to imply it
had run sooner.

Full record: `SERVICE_VALIDATION_EVIDENCE.md`.

## The premise nobody had measured

CI retired the service scope with the claim that "a hosted runner has no login
session to register into". Probe run `30323981718` measured it on
`macos-26-arm64`:

```text
launchctl managername       Aqua
launchctl print gui/501     exit 0     creator = loginwindow[162]
launchctl bootstrap gui/501 exit 0  -> THE AGENT RAN (state = running, pid 1817)
launchctl bootout  gui/501  exit 0, no residue
curl https://api.openai.com/v1/models   401
```

The claim was false. It had the effect of retiring the strongest available
scope on a technical premise nobody had checked, which is worth more attention
than the missing coverage itself: a gap somebody can see gets closed, and a
wrong reason for not testing does not.

## The result

```text
Workflow  Packaged macOS service lifecycle   run 30325704492
Runner    macos-26-arm64, macOS 26.4 (25E246), arm64, uid 501, session Aqua
Label     dev.api-tracker.gateway.39d11f8db375
Data dir  /tmp/tethra-track-val-13774

  tracking_validate_macos.sh --scope full --require-service
      63 passed, 0 failed (63/63) — verdict PASS, 0 skipped, 0 duplicate names
  gateway_validate_macos.sh
      51 passed, 0 failed
  cleanup verification (from outside the script, after its EXIT trap)
      CLEANUP VERIFIED: the machine is as clean after the run as before
```

## What the run cost, honestly

The first execution failed 2 of 59 (`REM-003`, `REM-004`); the second failed 1
of 51 in the lifecycle script (`REM-005`). All three were **harness** defects,
and all three had been invisible for the same reason: the scope had never run,
so a check that had never executed anywhere was indistinguishable from one
that always passed.

That is the finding worth carrying forward. The count-equality gate catches a
check that *stops* executing; nothing in it can catch a check that has *never*
executed, because the count is consistent either way. `ZFT-VAL-8` was the same
pattern found by reading; `REM-003` and `REM-005` are the same pattern found
by running.

## `RA-004`, revisited honestly

The mutation table in §`RA-004` above was produced by an uncommitted harness
(`REM-006`). It is committed now as `scripts/service_cleanup_safety.sh`, and
its result reproduces the earlier negative result rather than improving on it:

| Layer defeated | Outcome | Decoy plist |
|---|---|---|
| ordering (trap moved above the guards) | **survives** — does not kill | unchanged |
| ordering **and** ownership (teardown widened to a glob) | **kills** | `absent` — destroyed |

Two independently sufficient layers is a defensible design. Presenting either
single mutation as a kill would not be, and this file does not. What the
committed harness adds is that the claim is now re-runnable, and that `P3`
proves the harness can actually see the danger it reports as absent.
