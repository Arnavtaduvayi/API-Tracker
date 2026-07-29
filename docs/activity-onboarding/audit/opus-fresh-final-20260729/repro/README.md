# Reproduction scripts

Written by this audit, not by the remediation. Each is standalone and safe to
run on a machine carrying a live production gateway: none issues a `launchctl`
write verb, none starts or stops a service, and none touches
`~/Library/LaunchAgents`.

## `forge_results_json.py`

Independent forgery suite against `scripts/ci_assert_service_results.py`. Uses
the **real** exact-head CI artifact as the base document and mutates it 30
ways; every mutation must be rejected.

```
# fetch the artifact first
gh api repos/Arnavtaduvayi/API-Tracker/actions/artifacts/8709537795/zip > a.zip
unzip a.zip                      # yields results.json
# point BASE at that results.json, then:
python3 forge_results_json.py
```

Expected at this head: 29 of 30 refused; case `2b` (a non-`SERVICE` check
renamed) is **accepted** — that is finding `VAL-05-R`.

## `probe_primitive_mutation.sh`

The `VAL-04` mutation test the handoff dares an auditor to run. Extracts the
**genuine** primitive definitions verbatim from
`scripts/gateway_validate_macos.sh` — rather than re-implementing them — and
drives the real negative-control block against a throwaway sqlite database.

```
bash probe_primitive_mutation.sh
```

Expected: `M0` genuine → both controls PASS; `M1`/`M2` (neutered `assert_db`),
`M3` (neutered `assert_status`) and `M4` (the REM-002 subshell defect
reintroduced) → the controls FAIL, with `M4` producing the diagnostic
`malformed(+0p/+0f)` signature.

## `enumerate_gateway_checks.py`

Re-derives the check call sites in `scripts/gateway_validate_macos.sh`, which
has no enumerator of its own, and lists every `opt_ok`/`opt_bad` site so the
`REQUIRED_CHECKS=50` decomposition can be checked by hand.

```
python3 enumerate_gateway_checks.py
```

Expected: the only optional sites are `node` presence (1), the repair staging
block (5 when taken), and the port re-check (1) — matching the CI run's
`optional 7` and therefore `57 − 7 = 50`.

## Mutation testing of the ZFT-006 core (procedure, not a script)

Copy `crates/`, `Cargo.toml`, `Cargo.lock`, `provider-manifests/` and
`templates/` to a scratch tree, set `members = ["crates/*"]`, use a separate
`CARGO_TARGET_DIR`, and apply one mutation at a time to
`crates/tracking/src/state.rs`:

| Mutation | Result at this head |
| --- | --- |
| `(Some(_), None) => true` → `false` | **KILLED** by `a_future_dated_observation_must_not_erase_a_current_failure` |
| `instant_is_after(failed, seen)` → `!instant_is_after(…)` | **KILLED** by `a_failure_half_a_second_newer_than_an_observation_still_wins` |
| `REFRESH_CAS_ATTEMPTS: usize = 3` → `1` | **SURVIVED** — 158/158 green (finding `NEW-05`) |

Baseline for the isolated copy: 158 passed, 0 failed.
