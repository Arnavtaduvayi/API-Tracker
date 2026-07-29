# Service lifecycle, ownership and isolation — independent evidence

Audited head: `0c3b7d6f31c440f28a13bd8778eaa1b718c6f15b`.

## 0. Safety

This machine hosts a **live production gateway**. No `launchctl` write verb was
issued by this audit against anything. `gateway_validate_macos.sh`,
`tracking_validate_macos.sh --scope full`, `--require-service` and
`service_cleanup_safety.sh` were **not executed**. `validation_ownership_tests.sh`
was executed only with `launchctl` shimmed (see §4).

Production state, before and after:

```
plist sha256 0143dd24972c97743b2fc8ca929ab6c341805fd00f0f794d22e41741813ea5db
plist mtime  Jul 27 09:15:20 2026   size 996   mode 600
launchctl    Label = dev.api-tracker.gateway   PID = 22276
```

Byte-identical, same PID. `tracking_validate_macos.sh --scope selfcheck`
independently reported `production definition unchanged (996-bytes
mtime=1785158120 mode=600)`.

## 1. Label derivation and namespace isolation

`crates/gateway/src/lifecycle/mod.rs:85-103`:

```rust
let resolved = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
let key = blake3::derive_key("tethra gateway service installation id v1",
                             resolved.as_os_str().as_encoded_bytes());
```

A domain-separated `derive_key` over the **canonicalized** data dir, truncated
to 12 hex chars (48 bits). Label = `dev.api-tracker.gateway.<id>` (`macos.rs:40-42`).

**Can a validation run install the production label?** No — four independent
mechanisms:

* `label_for()` always appends a suffix; the bare `LEGACY_LABEL` is read only
  by `reclaim_legacy` (`macos.rs:247-271`), which acts only when
  `same_data_dir` proves it.
* `gateway_validate_macos.sh:312-333` refuses if the CLI resolves the bare
  label, if the suffix isn't `^[0-9a-f]{12}$`, or if the plist path is wrong.
* `tracking_validate_macos.sh:861-888` refuses to start if any gateway plist
  exists or any gateway job is registered.
* Cleanup hard-skips both (`:733`, `:750`).

The 48-bit id is not a collision concern at the scale involved. The real edge
is *instability*: `canonicalize` fails before the directory exists, so
`/tmp/x` and `/private/tmp/x` derive different ids pre-`mkdir`.
`gateway_validate_macos.sh:366-371` re-reads the label after `mkdir` and
aborts if it moved; `tracking_validate_macos.sh` has no such re-check but is
unaffected because it never derives the label itself — it asks the product
(`:1321-1322`).

## 2. Ownership ledger

TSV, four row kinds (`tracking:670-673`, `gateway:122-140`): `dir`, `plist`
(with the label the **product** reported), `label`, `pid` (with a binary
prefix). Written at creation, re-proved at teardown.

**Does any removal decision come from a glob or a naming resemblance?**

I swept every glob in `scripts/` and `.github/`. All three surviving
`dev.api-tracker.gateway.*.plist` globs are **detect-and-refuse**, never
remove:

* `ci_service_preconditions.sh:58` → `bad "a gateway LaunchAgent plist ALREADY exists"`
* `gateway_validate_macos.sh:279-282` → `refuse`
* `tracking_validate_macos.sh:863-887` → `die`

Removal is bounded by the ledger **plus** `plist_is_ours` (`tracking:677-683`),
which requires *content* proof — the plist must declare the recorded label AND
contain `$DIR`. The dead `sed` extractor VAL-02 found is gone, replaced by
exact JSON parsing in `product_status_field` (`:626-647`) whose failure path
returns non-zero rather than falling back to a name pattern.

**So the central requirement — "no ownership decision may come from a glob or
naming resemblance" — holds for `rm -f`.** One branch is the exception.

### `NEW-03` — the `bootout` branch skips its proof when the plist is absent

`tracking_validate_macos.sh:734-738` (same shape at `gateway:201-205`):

```bash
if [ -e "$LA_DIR/$value.plist" ] && ! plist_is_ours "$LA_DIR/$value.plist" "$value"; then
  echo "  cleanup: leaving $LA_DIR/$value.plist alone (it no longer proves it is ours)"
  continue
fi
launchctl bootout "gui/$UID_N/$value" >/dev/null 2>&1
echo "  booted out the job this run registered: gui/$UID_N/$value"
```

The proof is evaluated **only when the definition still exists at
`$LA_DIR/$value.plist`**. `$LA_DIR` is `$HOME`-keyed (`:476`); `bootout`
addresses `gui/<uid>` and is **not**. The comment three lines above even names
this asymmetry (*"`bootout` addresses the LIVE `gui/<uid>` domain regardless of
`$HOME` (REM-001)"*) — and then the guard it introduces is `$HOME`-keyed.

Under a redirected `$HOME` — exactly what `validation_ownership_tests.sh` and
`service_cleanup_safety.sh` do — the guard sees no plist, falls through, and
boots out the label unconditionally in the real session, printing "the job
**this run registered**", which may be false.

**Mitigations that hold:** the production label is explicitly exempt
(`:733`), and the loop only iterates labels **in the ledger**. In a normal run
the ledger is written by the run itself, so the set is correct by construction.
The exposure is **library mode**, where the ledger is entirely caller-supplied.

**Severity: Medium, validation-harness only.** It cannot affect the shipped
product and cannot reach the production gateway. Test 5d forges only the
legacy label, so this branch is untested.

### Live corroboration of the failure class

Observed on this machine at the *start* of this audit (i.e. pre-existing, not
created by it) — six namespaced gateway jobs registered in `gui/501` with no
plist on disk:

```
-  0  dev.api-tracker.gateway.76b3890f6f8e
-  0  dev.api-tracker.gateway.f78dc20f10ff
-  0  dev.api-tracker.gateway.340123aaf281
-  0  dev.api-tracker.gateway.39ede0626789
-  0  dev.api-tracker.gateway.99d09a5debd6
-  0  dev.api-tracker.gateway.29855e1e2c06

$ launchctl print gui/501/dev.api-tracker.gateway.76b3890f6f8e
  path = /private/var/folders/.../T/.tmpo7N3L4/home/Library/LaunchAgents/…plist
```

A `.tmpXXXX/home/…` layout: something ran a real install path with `$HOME`
redirected and left six registrations in the live session. They are inert
(no PID, exit 0) and are **not** the production gateway, which is separate and
healthy. `crates/gateway/src/lifecycle/mod.rs:35-37` claims *"`cargo test`
never installs, starts, or stops a real service"*; the residue shows the
isolation has leaked at some point in this repo's history. I left them in
place (removing them is a `launchctl` write, which is outside this audit's
remit).

### Adversarial ledger states (executed with a `launchctl` shim)

| Scenario | Behaviour |
| --- | --- |
| Empty ledger | removes nothing; never widens to a glob |
| Missing ledger | parser fails closed; removes nothing |
| Corrupt (no tabs, NULs, truncated) | `[ -n "$value" ] \|\| continue` drops every row |
| Forged → production plist/label | protected — but by the hardcoded name skips (`:733`,`:750`), not by the ownership proof |
| Forged → `dir $HOME`, `dir /` | prefix guard `:764-767` refuses |
| Name-identical foreign plist | `plist_is_ours` fails on the `$DIR` term → left byte-identical |
| Foreign process resembling ours | `proc_is_ours` `:686-692` — `kill -0` + `ps -o comm=` prefix; never `pkill -f` |
| Unparseable service definition | product `DefinitionState::Unparseable` → `ensure_ours` refuses (`mod.rs:308-315`); script fails closed |
| Stale PID / PID reuse | `proc_is_ours` re-proves pid **and** executable before signalling |

Note the forged-production case: the decoy plist is written *with `$DIR` inside
it*, so `plist_is_ours` returns **true**. The production definition survives
purely because of the name-based deny-list. The test's label claims the
ownership proof did it; the deny-list did.

### Trap ordering

Registered **after** creation in both scripts, so the risk is a **leak**, not
a wrongful delete:

```
tracking: refusals :807-888 → PROD_SIG :890 → :>LEDGER :894 → mkdir :895 → ledger_add :896-898 → trap :899
gateway:  refusals :244-333 → :>LEDGER :351 → mkdir :354 → ledger_add :358-359 → trap :360
```

Every refusal is above the trap, so "delete something it didn't create" is
structurally excluded. The 3–5 line window can leak `$DIR`; a later run's
precondition catches it. Correct trade-off.

## 3. `TETHRA_VALIDATE_LIB_ONLY=1` — the new seam

**It cannot skip a safety precondition in a real run.** The seam
(`tracking_validate_macos.sh:803-805`) sits strictly above the entire preflight
(`:807-888`), above every resource creation (`:894-898`) and above
`trap cleanup EXIT` (`:899`). Executed with the var set: `--scope selfcheck`
and `--scope full --require-service` both produced **zero `launchctl` calls and
zero scratch directories**.

Two residues:

* **`NEW-04` (Medium, CI-integrity).** `return 0 2>/dev/null || exit 0` exits
  **0 silently with no output and no `results.json`** when the script is
  *executed* rather than sourced. Two CI gates run the harness with no artifact
  assertion (`ci.yml:187`, `packaged-service-macos.yml:100`) and would pass
  vacuously if the variable were present in the environment. The main service
  step is protected — `ci_assert_service_results.sh` hard-fails on a missing
  artifact. One-line fix: refuse when `LIB_ONLY=1` and `[ "${BASH_SOURCE[0]}" = "$0" ]`.
* Library mode exposes `cleanup` — which runs `bootout` and `rm -f` — as a
  callable primitive whose whole safety boundary is caller-reassignable shell
  variables. Combined with `NEW-03`, a caller-supplied ledger yields an
  unguarded live `bootout`.

## 4. `validation_ownership_tests.sh`

Read in full first, as required. **It does issue a `launchctl` write verb**, so
it was not run unshimmed. Trace: `:50` exports a fake `$HOME` before sourcing
(good), but `:113-114` adds `plist`+`label` rows and `:247` calls `cleanup`;
`$OURS` exists and satisfies the proof, so the branch reaches
`launchctl bootout gui/501/dev.api-tracker.gateway.ours00000000` against the
**live** session. The target does not exist, so the effect is nil — but the
file header at `:31` claims *"Nothing here starts a gateway, installs a
service, or calls launchctl."* **That claim is false** (`NEW-17`, low).

Shimmed run: **29 passed, 0 failed**, matching the claimed count. Exactly one
intercepted call, as traced.

Two further residues:

* `NEW-18` (low): the floor is `MIN=29` and the run produces exactly 29 — zero
  headroom, so an added assertion silently raises the true count above a floor
  nobody updates.
* `NEW-19` (low): the test leaks `/tmp/tethra-track-val-$$` (created `:54-55`,
  never ledgered; the `EXIT` trap removes only `$WORLD`). Ten such leftovers
  were found on this machine. This is exactly what
  `ci_service_preconditions.sh:124` fails on, so running the *safe* ownership
  test poisons the precondition for the *real* service scope locally.

## 5. CI execution on the exact audited head

Artifact `packaged-macos-service-lifecycle`, run `30413771190`, commit
`3e28380f` (= `refs/pull/16/merge`, tree-identical to the PR head).

| Property | Verdict | Evidence |
| --- | --- | --- |
| Clean-room preconditions | **Partial — post-run only in the artifact** | `cleanup.log:9-28` runs all ten and prints `=== PRECONDITIONS PASSED — this is a clean room ===`. The pre-run and between-runs executions go to the job log, which is not uploaded. |
| Harness self-check | Yes | `service-lifecycle.log:7-15` — 5 HARNESS controls incl. *"a known-false shell condition is reported as a FAILURE"* |
| Real `.app` build | Yes (indirect) | `:19` Info.plist version; `:21` in-bundle helper byte-identical to the sidecar staged from source |
| Copy outside the repository | Yes (indirect) | `:2` `app: /Users/runner/work/_temp/packaged-app/Tethra.app` — under `$RUNNER_TEMP`, not the checkout |
| PATH stripping | **Not directly evidenced** | `tracking_validate_macos.sh:1126` exports a stripped PATH then `die`s — a silent precondition emitting no PASS line. Only negative evidence (the run continued). |
| Bundled-helper verification | Yes | `:18,:20,:21,:22,:113` — Mach-O arm64, measured version equals declared, byte-identity, exec probe |
| Namespaced install | Yes | `:109-111`; `results.json` `service_created_by_this_run = True` |
| launchd load | Yes | `:114` `launchd loaded the namespaced service gui/501/dev.api-tracker.gateway.ec8c71fff31b` |
| PID + executable verification | Yes | `:115` *"the running service (pid 10229) executes the program its own plist declares"* |
| Authenticated control connection | Yes | `:116` socket mode 0600; gateway `:66-67` exposes counters reachable only over the nonce-derived challenge-response (`control.rs:276-293`) |
| Stop | Yes | gateway `:70` |
| Doctor | Yes | gateway `:71-72` `doctor findings: installed_but_stopped` |
| Restart | Yes | gateway `:75-76` |
| Repair | Yes | gateway `:79-83` incl. *"repair did not touch the production label"* |
| Uninstall | Yes | gateway `:90,93-98` — plist removed, unregistered, socket, nonce, binaries |
| External cleanup verification | Yes (tracking only) | `cleanup.log:30` `=== CLEANUP VERIFIED ===` |

**Every lifecycle verb the brief asks about executed on the exact audited
code**, including `repair`, which the prior handoff recorded as never run.

Two evidence gaps:

* `NEW-20` (low): `ci_service_preconditions.sh:124` globs only
  `/tmp/tethra-track-val-*`. The gateway harness uses `/private/tmp/tethra-gw-val-*`,
  which that glob never matches — so neither the between-runs re-assert nor the
  final cleanup verification can detect a gateway-harness leak.
  `service_cleanup_safety.sh:131` already snapshots both patterns.
* `NEW-21` (low): `gateway_validate_macos.sh` teardown prints only on refusal
  branches, so `gateway-lifecycle.log` contains no cleanup section at all —
  contrast `service-lifecycle.log:195-200`. Combined with `NEW-20`, a
  gateway-harness leak is invisible in both the log and the verifier.
