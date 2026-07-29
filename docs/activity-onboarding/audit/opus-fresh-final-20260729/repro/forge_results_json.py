#!/usr/bin/env python3
"""Independent forgery suite against scripts/ci_assert_service_results.py.

Written fresh for the audit of PR #16 @ 0c3b7d6f. Uses the REAL CI artifact
from the exact audited head as the base document, then mutates it 20 ways.

Every mutation MUST be rejected (exit != 0). A mutation that is accepted is a
merge-blocking defect.
"""
import copy
import json
import os
import subprocess
import sys
import tempfile

VALIDATOR = "/Users/arnavtaduvayi/Documents/APItrack/audit-pr16-fresh-20260729/scripts/ci_assert_service_results.py"
MANIFEST = "/Users/arnavtaduvayi/Documents/APItrack/audit-pr16-fresh-20260729/scripts/validation_manifest.json"
BASE = "/private/tmp/claude-501/-Users-arnavtaduvayi-Documents-APItrack/ae68ff1b-a643-4913-996d-1b7aacdcf1c3/scratchpad/ci-artifact/results.json"
# The commit the CALLER requires. In CI this is $GITHUB_SHA (the pull_request
# merge commit). The genuine artifact stamps this same value.
CALLER_COMMIT = "3e28380f2caac8fb0f463c3c50eb40c0ec08aecc"

base = json.load(open(BASE))


def run(doc, scope="full", mode="service", commit=CALLER_COMMIT, raw=None):
    """Run the validator over `doc`; return (exit_code, output)."""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        if raw is not None:
            fh.write(raw)
        else:
            json.dump(doc, fh)
    try:
        p = subprocess.run(
            [sys.executable, VALIDATOR, path, "--scope", scope, "--mode", mode,
             "--commit", commit, "--manifest", MANIFEST],
            capture_output=True, text=True,
        )
        return p.returncode, (p.stdout + p.stderr)
    finally:
        os.unlink(path)


def d():
    return copy.deepcopy(base)


CASES = []


def case(name, expect_reject=True):
    def deco(fn):
        CASES.append((name, fn, expect_reject))
        return fn
    return deco


# --- control: the genuine artifact must PASS -------------------------------
@case("CONTROL genuine artifact is accepted", expect_reject=False)
def _():
    return run(d())


# --- 1. correct count, wrong check IDs (whole register renamed) ------------
@case("1  correct count but every check ID is wrong")
def _():
    x = d()
    for i, c in enumerate(x["checks"]):
        c["name"] = "totally different check %d" % i
    return run(x)


# --- 2. one required SERVICE check replaced with another -------------------
@case("2  one required SERVICE check replaced by an unrelated passing one")
def _():
    x = d()
    for c in x["checks"]:
        if c["group"] == "SERVICE" and c["name"].startswith("launchd loaded the namespaced service"):
            c["name"] = "some other service thing that passed"
            break
    return run(x)


# --- 2b. a NON-service required check replaced (the count-only groups) -----
@case("2b one APPLY check replaced by an unrelated passing one")
def _():
    x = d()
    for c in x["checks"]:
        if c["group"] == "APPLY" and c["name"].startswith("the openai route exists"):
            c["name"] = "a completely different apply assertion"
            break
    return run(x)


# --- 3. duplicate check IDs ------------------------------------------------
@case("3  duplicate check IDs (one row cloned over another)")
def _():
    x = d()
    x["checks"][5] = copy.deepcopy(x["checks"][4])
    return run(x)


# --- 4. unknown check IDs added (count inflated) ---------------------------
@case("4  unknown check ID appended")
def _():
    x = d()
    x["checks"].append({"group": "SERVICE", "name": "an invented check", "result": "pass"})
    return run(x)


# --- 5. missing required check (register short) ----------------------------
@case("5  a required SERVICE check removed entirely")
def _():
    x = d()
    x["checks"] = [c for c in x["checks"]
                   if not c["name"].startswith("the service exposes its control endpoint")]
    return run(x)


# --- 6. skipped required check --------------------------------------------
@case("6  a required check marked skipped")
def _():
    x = d()
    for c in x["checks"]:
        if c["group"] == "SERVICE":
            c["result"] = "skip"
            break
    x["skipped"] = 1
    return run(x)


# --- 7. informational substituted for a required result --------------------
@case("7  a required check downgraded to informational")
def _():
    x = d()
    for c in x["checks"]:
        if c["group"] == "SERVICE":
            c["result"] = "info"
            break
    return run(x)


# --- 8. wrong scope --------------------------------------------------------
@case("8  offline-scope result filed as full:service")
def _():
    x = d()
    x["scope"] = "offline"
    return run(x)


# --- 9. wrong mode ---------------------------------------------------------
@case("9  foreground-mode result filed as service")
def _():
    x = d()
    x["mode"] = "foreground"
    return run(x)


# --- 10. wrong commit ------------------------------------------------------
@case("10 results from a different commit")
def _():
    x = d()
    x["commit"] = "deadbeef" * 5
    return run(x)


# --- 11. wrong service namespace (production label) ------------------------
@case("11 the run installed the PRODUCTION service label")
def _():
    x = d()
    x["service_label"] = "dev.api-tracker.gateway"
    return run(x)


@case("11b service label is not a gateway label at all")
def _():
    x = d()
    x["service_label"] = "com.evil.something"
    return run(x)


@case("11c service label has an empty installation id")
def _():
    x = d()
    x["service_label"] = "dev.api-tracker.gateway."
    return run(x)


# --- 12. results from an earlier run (stale commit, valid shape) -----------
@case("12 a genuine but STALE artifact from an earlier commit")
def _():
    x = d()
    x["commit"] = "cac469e3497e5ba905c9e26d31d43c4b989594c5"  # the previously audited head
    return run(x)


# --- 13. offline results substituted for service results -------------------
@case("13 a real offline:none result substituted wholesale")
def _():
    x = {
        "schema": "tethra.validation.results/1", "scope": "offline", "mode": "none",
        "verdict": "PASS", "expected_total": 20, "executed_total": 20, "passed": 20,
        "failed": 0, "skipped": 0, "duplicate_names": 0,
        "commit": CALLER_COMMIT, "service_created_by_this_run": False,
        "groups": [{"name": g, "expected": n, "executed": n, "passed": n, "failed": 0}
                   for g, n in [("HARNESS", 5), ("BUNDLE", 5), ("FIXTURE", 3),
                                ("DRYRUN", 6), ("OFFLINE", 1)]],
        "checks": [{"group": "HARNESS", "name": "x%d" % i, "result": "pass"} for i in range(20)],
    }
    return run(x)


# --- 14. empty output ------------------------------------------------------
@case("14 empty results file")
def _():
    return run(None, raw="")


@case("14b whitespace-only results file")
def _():
    return run(None, raw="   \n\t\n")


# --- 15. truncated output --------------------------------------------------
@case("15 truncated JSON (process killed mid-write)")
def _():
    return run(None, raw=json.dumps(base)[: len(json.dumps(base)) // 2])


# --- 16. forged all-green summary (the VAL-01 original defect) -------------
@case("16 twelve-line forgery declaring its own zero criteria")
def _():
    return run(None, raw=json.dumps({
        "schema": "tethra.validation.results/1", "scope": "full", "mode": "service",
        "verdict": "PASS", "expected_total": 0, "executed_total": 0,
        "passed": 0, "failed": 0, "skipped": 0, "duplicate_names": 0,
        "commit": CALLER_COMMIT, "groups": [], "checks": [],
        "service_created_by_this_run": True,
        "service_label": "dev.api-tracker.gateway.forged123",
    }))


@case("16b forged all-green with a plausible self-declared total")
def _():
    return run(None, raw=json.dumps({
        "schema": "tethra.validation.results/1", "scope": "full", "mode": "service",
        "verdict": "PASS", "expected_total": 63, "executed_total": 63,
        "passed": 63, "failed": 0, "skipped": 0, "duplicate_names": 0,
        "commit": CALLER_COMMIT, "groups": [], "checks": [],
        "service_created_by_this_run": True,
        "service_label": "dev.api-tracker.gateway.forged123",
    }))


# --- 17. pre-existing service substituted for one created by the run -------
@case("17 the service was NOT created by this run")
def _():
    x = d()
    x["service_created_by_this_run"] = False
    return run(x)


@case("17b the required fact is absent entirely")
def _():
    x = d()
    del x["service_created_by_this_run"]
    return run(x)


# --- 18. a group silently borrows another group's rows ---------------------
@case("18 a group borrows rows from another (totals still 63)")
def _():
    x = d()
    moved = 0
    for c in x["checks"]:
        if c["group"] == "APPLY" and moved < 2:
            c["group"] = "SERVICE"
            moved += 1
    return run(x)


# --- 19. verdict flipped while failures present ---------------------------
@case("19 verdict PASS while a check failed")
def _():
    x = d()
    x["checks"][0]["result"] = "fail"
    return run(x)


@case("19b failed count non-zero")
def _():
    x = d()
    x["failed"] = 1
    return run(x)


# --- 20. schema confusion --------------------------------------------------
@case("20 wrong schema version")
def _():
    x = d()
    x["schema"] = "tethra.validation.results/2"
    return run(x)


@case("20b results file is a JSON array, not an object")
def _():
    return run(None, raw="[]")


@case("20c whole group missing from the breakdown")
def _():
    x = d()
    x["groups"] = [g for g in x["groups"] if g["name"] != "PRIVACY"]
    return run(x)


def main():
    width = max(len(n) for n, _, _ in CASES)
    bad = []
    for name, fn, expect_reject in CASES:
        rc, out = fn()
        rejected = rc != 0
        good = rejected == expect_reject
        verdict = "OK  " if good else "LEAK"
        print("%s  %-*s  rc=%d  %s" % (
            verdict, width, name, rc,
            "rejected" if rejected else "ACCEPTED"))
        if not good:
            bad.append((name, rc, out))
    print("")
    print("=" * 70)
    if bad:
        print("FORGERY SUITE FAILED: %d case(s) behaved wrongly" % len(bad))
        for name, rc, out in bad:
            print("\n--- %s (rc=%d) ---\n%s" % (name, rc, out))
        return 1
    print("FORGERY SUITE PASSED: %d/%d cases behaved correctly" % (len(CASES), len(CASES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
