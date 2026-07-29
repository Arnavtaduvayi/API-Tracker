# Deferred findings and repository controls — independent review

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`.

## 0. A counting defect in the handoff itself

`NEXT_INDEPENDENT_REAUDIT_HANDOFF.md:112-114` names **fourteen** deferred
findings. `POST_FINAL_REAUDIT_REMEDIATION_MATRIX.md` defers **fifteen**. The
one absent from the list of fourteen is **`ENC-02`** — which the same matrix
calls *"the highest-value remaining non-blocker"* (`:206`).

It is not concealed (the handoff gives ENC-02 its own §5), but a reviewer
working the enumerated list will miss the most serious item on it. Recorded as
`NEW-23`, informational — noted because miscounting is the defect class this
audit series exists to catch.

## 1. Summary

All fourteen deferrals **reproduce** at this head. None was silently fixed;
none was silently worsened. For all fourteen:

* **Regression coverage: none** (verified by sweep across `crates/*/tests`,
  `apps/cli/tests`, `scripts/*tests*.sh`).
* **User-facing disclosure: none.** None appears in `KNOWN_LIMITATIONS.md`
  (the page `README.md:256` points users to), `SECURITY.md`, `THREAT_MODEL.md`,
  `README.md`, `PRODUCT_SPEC.md` or `CHANGELOG.md`. The only record is the
  audit-internal ledger. `KNOWN_LIMITATIONS.md` names exactly two PR-#16
  finding IDs: `VAL-05` (`:191`) and `ENC-01` (`:256`).

**None is merge-blocking, alone or in combination.**

## 2. Per-finding verdicts

| ID | Deferral accurate? | Merge blocking | Note |
| --- | --- | --- | --- |
| `ENC-03` | **Risk accurate; reasoning wrong** | No | AAD colon-joins unescaped fields (`crates/core/src/crypto.rs:191-193`). The stated containment ("confined to one vault/link") is not why it is safe. It is safe because `valid_key` (`envfile.rs:109-117`) forbids `:` in keys and `link_slug` is 32 hex chars, so only `path` can contain `:` and the separators stay unambiguous. That invariant is enforced three call layers away with **no test and no comment tying them**. |
| `ENC-04` | **Understated** | No | `prior_value_is_recordable` (`envlink.rs:220`) is dead: its only call site `:1065` sits behind a guard that lines `:1058-1063` make provably false. Four documents describe it as an active control — including `SECURITY_AND_PRIVACY.md:118`, which lists it as a **review criterion**. A review gate resting on a function that never runs cannot fail. Two-line fix. |
| `VAL-06` | Accurate | No | The enumerator's header claims "deliberately fail-closed"; `close_if` (`:283-290`) accepts `if/elif` with no `else`, `close_case` (`:291-297`) accepts a 2-arm `case` with no `*)`. Contained by the runtime per-group equality gate, which turns divergence into a loud `INCONCLUSIVE`. `PACKAGED_VALIDATION.md:325` repeats the overbroad claim. |
| `VAL-07` | Accurate | No | `tracking_validate_macos.sh:1579` excludes the whole `$DIR/bin/` directory from the header sweep, not just the helper. In practice `prune_old_binaries` (`lifecycle/mod.rs:657-668`) keeps exactly one file there, so the two are extensionally equal. One-word fix. |
| `VAL-08` | **Accurate alone, understated in pair** | No | `:1369` proves helper provenance with an **unanchored whole-file `grep -qF`**, under a label claiming the LaunchAgent *runs* that helper. The anchored value exists 21 lines below (`PLIST_PROGRAM`, `:1390`) and is already used for the process check. One comparison from being real. |
| `VAL-09` | Accurate | No | The remediation note (`gateway_validate_macos.sh:598-604`) says `doctor` "has never carried a `matching_key_present` field at all". False — `control.rs:187` declares it and `doctor.rs:60` embeds the whole `control::Status`. The fix is right; the post-mortem is wrong, and is propagated to three further documents. |
| `VAL-10` | Accurate | No | Duplicate detector keys on group+name (`:1694`), so a name reused across groups is invisible. The CI asserter catches it globally for `full:service`; the offline job has no asserter. One-character fix. |
| `VAL-11` | Accurate | No | Weak/overclaiming assertions, six confirmed. Sharpest: `:1637-1638` asserts `COUNT(*)>=1` under the label *"recorded history was KEPT (undo never deletes the user's data)"* — undo could delete 99% and pass. The product claim it backs is user-facing (`track_cmd.rs:1037` "Keeps all recorded history"). The file uses a proper before/after delta three groups earlier, so the pattern exists. |
| `ORG-02` | **Accurate on exploitability, understated on honesty** | No | `*.localhost` passes `policy.rs:196` (contains a dot, doesn't end `.local`) and is disclosed to the user as *"The host is a public internet address"* (`origin.rs:165`). Containment is **structural** — `upstream.rs:84` filters resolved addresses with a hardcoded `false` allowlist, so no credential leaves. But `KNOWN_LIMITATIONS.md:220-224` states *"the user is never shown a classification for a destination that could not work"*, which is false for this spelling. One-token fix: add `.localhost` beside `.local`. |
| `VER-04` | Accurate | No | Retention (`retention.rs:31-34`) deletes rows without re-anchoring; the table is `TEXT PRIMARY KEY`, not `AUTOINCREMENT` (`db.rs:728-734`), so rowids restart and new traffic is inadmissible until they climb past `applied_event_rowid`. Fails closed to `WaitingForFirstRequest`; availability only, self-recovering. Contradicts `KNOWN_LIMITATIONS.md:118-120` ("recovers on its own once real traffic arrives"). |
| `GIT-01` | **Understated** | No | `gitseal.rs:390-392` `break`s at `MAX_ALTERNATE_HOPS = 8` then writes the partial list and returns `Ok(())` (`:419-423`). Every other bound in the file returns a loud `CoreError::InvalidInput`. The function's own comment (`:399-402`) states the requirement it breaks. Consequence: a silently incomplete history scan in a secret-scanning product. Requires an unusual chained `clone --shared` topology. ~4-line fix. |
| `CON-01` | Accurate | No | `track_cmd.rs:1066-1071` prints "Tracking stopped." from a report computed before a concurrent apply; nothing re-reads state after `reload_routes` (`:1064`). Bounded and self-correcting. |
| `CON-02` | Accurate | No | TOCTOU in `apply.rs:863-876` surfaces `database error: UNIQUE constraint failed: projects.name` verbatim (`error.rs:111` → `apply.rs:329`). Cosmetic; contradicts `PRODUCT_SPEC.md:939` "Display actionable error messages". |
| `CON-03` | **Understated (review confidence)** | No | `tauri_command_inventory.json` declares 137 commands; `main.rs:4413` registers **201**. The 64 missing are exactly this PR's `observe_*`/`gateway_*`/`tracking_*` surface. No artifact at this head answers the reauth-coverage question for the code under review. `docs/release/TETHRA_MACOS_PRIVATE_ALPHA_READINESS.md:110-111` quotes the wrong denominator. Regenerating is mechanical. |

### On `GIT-01`'s documentation contradiction

I read `KNOWN_LIMITATIONS.md:87-90` directly. The paragraph enumerates the
bounds it is about — *"more than 2000 environment files, more than 20 000
directories, more than 64 MB … or more than 20 seconds"* — and cites
`ZFT-028`. The alternates-chain cap is **not** among them. So the sentence
*"It does not silently return a partial answer"* is a general claim in a
paragraph scoped to other bounds. That makes the contradiction real but
weaker than a flat falsehood: the document does not enumerate
`MAX_ALTERNATE_HOPS` at all. Either fix the `break` or add the bound to that
list.

## 3. Combination analysis

| Pair | Compounds? | Effect |
| --- | --- | --- |
| **`VAL-07` + `VAL-08`** | **Yes — the only genuine one** | VAL-07's directory-wide exemption from the header sweep is argued sound *because* the installed helper is byte-identical to the shipped one. VAL-08 means nothing binds `ProgramArguments[0]` to that file. Together, the harness could certify "no auth headers stored" for a service running a different program out of the exempt directory. **Still harness-only**, and the per-run needle sweeps do cover `bin/`. The matrix evaluates each in isolation and never considers the interaction. |
| `CON-03` + `REPO-01` | Yes (confidence) | The stale inventory's stated fix is "regenerate in CI" — and nothing makes CI binding. |
| `ENC-03` + `ENC-02` | Notional | Restore records have neither structural integrity nor unambiguous binding, against the same local-write adversary. |
| `CON-01` + `VER-01` residue | Mild | A false success claim plus one-read staleness under contention. Bounded, self-correcting. |
| `VAL-06` + `VAL-10` + `VAL-11` | **No** | Contained by the per-group equality gate and orthogonal scopes. No path to a false green. |

## 4. REPO-01 — verified state and verdict

```
branches/main/protection  → HTTP 404 "Branch not protected"
rulesets                  → []
repo                      → public, default_branch main, archived false
```

Zero enforcement: no protection, no rulesets, no required checks, no required
reviews, no signed-commit or linear-history requirement, no force-push
restriction. `mergeStateStatus: CLEAN` here means "no blockers configured" —
it would read `UNSTABLE` and still be mergeable with every check red.

**Correction to both matrices.** They frame REPO-01 as *"BLOCKED — external …
requires admin access"*. Verified directly:

```
$ gh api repos/Arnavtaduvayi/API-Tracker --jq .permissions
{"admin":true,"maintain":true,"pull":true,"push":true,"triage":true}
```

**The credential in use already has admin.** REPO-01 is a decision not taken,
not a permission missing. Recorded as `NEW-24`. (I did not change any setting —
outside this audit's remit.)

### Verdict: governance recommendation, not a product-security merge block

1. It cannot change any property of this diff. Branch protection constrains
   *future* merges; every security property of PR #16 is in the code or it is
   not.
2. The convention held here — all six checks are green on the exact audited
   head.
3. Its compounding with VAL-01/VAL-05 is real but second-order: those fixes
   make the gate *correct*; REPO-01 means nothing makes it *binding*. A
   correct gate nobody is compelled to obey is still strictly better than the
   self-validating gate VAL-01 replaced.
4. Blocking a code diff on an org setting the same person can flip in seconds
   would protect nothing.

**Recommendation:** enable it before merging — cost is zero and the checks are
already green — requiring all six checks on `main`, dismissal of stale
approvals, and blocking force pushes. But if the choice is "merge with `main`
unprotected" versus "do not merge", the product-security answer is **merge**.

## 5. Repository controls

| Control | State |
| --- | --- |
| CODEOWNERS | **Absent** |
| `SECURITY.md` | **Present and substantive** — private GHSA reporting, response commitment, an explicit "What this does NOT protect against" section. Honest. |
| Dependabot config | **Absent** |
| Action SHA pinning | **Fully pinned — all 28 `uses:` are 40-char commit SHAs** with version comments; policy documented at `ci.yml:8-11`. Zero mutable tags. |
| Workflow permissions | `contents: read` at workflow scope in all three; escalated per-job only in `release.yml`. Triggers are `pull_request`, **not** `pull_request_target` — no fork-PR secret exposure. |

### `NEW-25` — GitHub security features are all disabled (new, not in any matrix)

```
$ gh api repos/Arnavtaduvayi/API-Tracker --jq .security_and_analysis
secret_scanning:                      disabled
secret_scanning_push_protection:      disabled
secret_scanning_validity_checks:      disabled
secret_scanning_non_provider_patterns: disabled
dependabot_security_updates:          disabled
```

All are free on public repositories and all are off, on a **public** repository
whose product is a credential manager, whose test suites deliberately plant
API-key-shaped canaries, and whose CI writes fake keys. Push protection being
off is a sharper omission than branch protection: `SECURITY.md` invites private
vulnerability reports, but nothing scans the repository itself. Not
merge-blocking; strictly cheaper and higher-value than REPO-01.

## 6. Hollow-fix spot checks

Fourteen "FIXED" claims were checked against the code at this head.
**No hollow fixes found.** Highlights:

* `VAL-05`'s `REQUIRED_CHECKS=50` was independently re-enumerated by a second
  method and came to **exactly 50 required + 7 optional**, matching the
  script's own decomposition and my own count in
  `VALIDATION_TRUST_EVIDENCE.md §3`.
* `ENC-01`: `vault_unlock` (`main.rs:243`) has exactly one `?` before the
  migration call at `:273`, so **every successful unlock reaches it** — this
  answers the handoff's own open question.
* `ORG-01`: `track_origin_refusal.rs` has exactly 11 `#[test]`.
* `SEC-02`: `CLIENT_BODY_DEADLINE = 300s` (`forward.rs:49`), wrapped at
  `:853-855`, `DeadlineReader` at `stream.rs:205-220`.

Two stale counts, both **under**-claimed: the matrix says
`verification_concurrency.rs` has 12 tests; it has 13.

## 7. Two further observations on `gateway_validate_macos.sh`

* `NEW-26` (low): `:742` emits a `bad` per (file × needle) hit inside a nested
  loop, so on a run with N canary hits the required total is data-dependent — a
  **fourth** machine-dependent site the VAL-05 fix does not name. Inert in
  practice (any such run already has `fail > 0`), but it is exactly the shape
  the sibling enumerator declares fail-closed against, and this script has no
  enumerator to catch it.
* `NEW-27` (low): `:490` wraps a *required* check (`:504`) in
  `if command -v python3` with a bare `SKIP` else-branch emitting nothing.
  Currently unreachable because python3 is a hard preflight (`:247-248`) — but
  relax that preflight and one required check silently vanishes while the
  equality gate reports the wrong diagnosis.
