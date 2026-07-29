#!/usr/bin/env python3
"""Assert a packaged-validation results file against a TRUSTED manifest.

Driven by scripts/ci_assert_service_results.sh; see that file for why this is
not a grep for "0 failed". In short: "the script exited 0" and "the full
service scope ran and passed" are different statements, and this project has
been bitten in both directions (RA-003 exited non-zero with every assertion
green; a silent downgrade to --foreground exits zero with a confident total).

VAL-01 — WHY THIS WAS REWRITTEN
===============================

The previous version read ``expected_total``, ``groups[].expected`` and every
check name **from the file it was validating**. It therefore proved only that
a results document was internally self-consistent. A twelve-line forgery
declaring zero checks produced::

    === SERVICE SCOPE COMPLETED: 0/0 checks passed in full:service ===

with exit 0, and the workflow step that justifies itself as asserting "the
full declared check count actually executed" asserted nothing of the kind.

The rule this file now follows:

    A result may REPORT what it observed.
    It may not DEFINE what is acceptable.

Everything the validator expects comes from two places the results file cannot
influence:

* ``scripts/validation_manifest.json`` — committed, reviewed, and kept in step
  with the harness's own group table by
  ``scripts/validation_manifest_check.sh``; and
* arguments supplied by the caller — ``--scope``, ``--mode``, ``--commit`` —
  which in CI come from the workflow, not from the artifact.

Deliberately plain Python so it runs on whatever interpreter a runner image
ships: no f-strings, no third-party imports, no version-gated syntax.
"""

import json
import os
import sys

DEFAULT_MANIFEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "validation_manifest.json")

# Every non-fatal condition this file can report, so a reader can see the
# whole refusal surface in one place.
USAGE = (
    "usage: ci_assert_service_results.py <results.json> "
    "[--scope SCOPE] [--mode MODE] [--commit SHA] [--manifest PATH]\n"
    "\n"
    "  --scope/--mode  what the CALLER required this run to be (default full/service).\n"
    "                  Never read from the results file.\n"
    "  --commit        the revision this evidence must be about. Defaults to\n"
    "                  $GITHUB_SHA when set; pass 'any' to skip (local use only).\n"
)


def parse_args(argv):
    opts = {
        "path": None,
        "scope": "full",
        "mode": "service",
        "commit": os.environ.get("GITHUB_SHA", "any"),
        "manifest": DEFAULT_MANIFEST,
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--"):
            name = a[2:]
            if name not in ("scope", "mode", "commit", "manifest"):
                return None, "unknown option --" + name
            i += 1
            if i >= len(argv):
                return None, "--" + name + " needs a value"
            opts[name] = argv[i]
        elif opts["path"] is None:
            opts["path"] = a
        else:
            return None, "unexpected extra argument " + repr(a)
        i += 1
    if opts["path"] is None:
        return None, "no results file given"
    return opts, None


def main(argv):
    opts, err = parse_args(argv)
    if err:
        sys.stderr.write(err + "\n" + USAGE)
        return 2

    # --- the trusted side -------------------------------------------------
    try:
        with open(opts["manifest"]) as handle:
            manifest = json.load(handle)
    except Exception as e:  # noqa: BLE001 - any failure here is fatal
        sys.stderr.write("cannot read the trusted manifest %s: %s\n" % (opts["manifest"], e))
        return 2

    key = opts["scope"] + ":" + opts["mode"]
    spec = (manifest.get("scopes") or {}).get(key)
    if not spec:
        sys.stderr.write(
            "the manifest declares no expectations for %r; refusing to certify a scope "
            "nobody wrote down\n" % key
        )
        return 2

    fails = []
    notes = []

    def line(good, text):
        print("  %-4s  %s" % ("OK" if good else "FAIL", text))

    # --- the untrusted side ----------------------------------------------
    # A truncated or non-JSON artifact is a FAILURE, never an absence of
    # evidence. The audited head would raise here and exit non-zero by
    # accident; it is stated deliberately now.
    try:
        with open(opts["path"]) as handle:
            raw = handle.read()
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("cannot read the results file %s: %s\n" % (opts["path"], e))
        return 1
    if not raw.strip():
        print("=== SERVICE SCOPE ASSERTION FAILED ===")
        print("  - the results file is empty; an absent result is not a passing one")
        return 1
    try:
        r = json.loads(raw)
    except ValueError as e:
        print("=== SERVICE SCOPE ASSERTION FAILED ===")
        print("  - the results file is not valid JSON (truncated?): %s" % e)
        return 1
    if not isinstance(r, dict):
        print("=== SERVICE SCOPE ASSERTION FAILED ===")
        print("  - the results file is not an object")
        return 1

    def want(label, got, expected):
        good = got == expected
        if not good:
            fails.append("%s: got %r, required %r" % (label, got, expected))
        line(good, "%s = %r" % (label, got))

    # Identity. `scope` and `mode` are compared against what the CALLER asked
    # for: this is what stops an `--scope offline` result (which starts no
    # gateway and installs nothing) from being filed as service evidence.
    want("schema", r.get("schema"), manifest.get("results_schema"))
    want("scope", r.get("scope"), opts["scope"])
    want("mode", r.get("mode"), opts["mode"])
    want("verdict", r.get("verdict"), "PASS")
    want("failed", r.get("failed"), 0)
    want("skipped", r.get("skipped"), 0)
    want("duplicate_names", r.get("duplicate_names"), 0)

    # Which revision this evidence is about. A results artifact kept from an
    # earlier build proves that something ran, not that THIS revision did.
    if opts["commit"] == "any":
        notes.append("commit identity not enforced (--commit any)")
        line(True, "commit = %r (not enforced)" % r.get("commit"))
    else:
        want("commit", r.get("commit"), opts["commit"])

    # --- counts, from the MANIFEST -----------------------------------------
    # `expected_total` in the results file is read for one purpose only: to
    # report whether the harness agreed. It never becomes the expectation.
    expected = spec["expected_total"]
    executed = r.get("executed_total")
    good = executed == expected
    if not good:
        fails.append(
            "executed_total %r != the manifest's required %d for %s" % (executed, expected, key)
        )
    line(good, "executed_total = %r (manifest requires %d)" % (executed, expected))

    self_declared = r.get("expected_total")
    if self_declared != expected:
        fails.append(
            "the results file declares expected_total %r, but the manifest requires %d — "
            "the harness and the manifest disagree about what this scope IS"
            % (self_declared, expected)
        )
    line(
        self_declared == expected,
        "the run's own declared total agrees with the manifest (%r)" % (self_declared,),
    )

    # --- per-group, from the MANIFEST --------------------------------------
    required_groups = spec["groups"]
    groups = r.get("groups")
    if not isinstance(groups, list) or not groups:
        fails.append("no group breakdown in the results")
        groups = []
    seen_groups = {}
    for g in groups:
        if not isinstance(g, dict):
            fails.append("a group entry is not an object")
            continue
        name = g.get("name")
        if name in seen_groups:
            fails.append("group %r appears twice in the breakdown" % name)
        seen_groups[name] = g
        if name not in required_groups:
            fails.append(
                "group %r ran but the manifest does not declare it for %s" % (name, key)
            )
            line(False, "group %-12s UNDECLARED" % (name,))
            continue
        need = required_groups[name]
        good = g.get("executed") == need and g.get("failed") == 0
        if not good:
            fails.append(
                "group %s: executed %r of the required %d, %r failed"
                % (name, g.get("executed"), need, g.get("failed"))
            )
        line(
            good,
            "group %-12s %r/%d executed, %r failed"
            % (name, g.get("executed"), need, g.get("failed")),
        )
    for name in sorted(required_groups):
        if name not in seen_groups:
            fails.append(
                "group %s is required for %s and did not run — this scope did not complete"
                % (name, key)
            )
            line(False, "group %-12s DID NOT RUN" % (name,))

    # --- the register ------------------------------------------------------
    checks = r.get("checks")
    if not isinstance(checks, list):
        fails.append("the results file carries no check register")
        checks = []
    if len(checks) != expected:
        fails.append(
            "the register holds %d checks but the manifest requires %d" % (len(checks), expected)
        )
    names = [c.get("name") for c in checks if isinstance(c, dict)]
    if len(names) != len(checks):
        fails.append("a register entry is not an object")
    if len(set(names)) != len(names):
        fails.append("duplicate check names in the register")
    notpass = [c for c in checks if not isinstance(c, dict) or c.get("result") != "pass"]
    for c in notpass:
        if isinstance(c, dict):
            fails.append("check not passed: [%s] %s" % (c.get("group"), c.get("name")))
    # An "informational" or "skipped" row is not a passed check. Requiring
    # result == "pass" for every register row is what stops one being
    # substituted for a required check.
    line(
        not notpass and len(checks) == expected,
        "register: %d named checks, %d not passed" % (len(checks), len(notpass)),
    )

    # Per-group register counts, so a group cannot borrow another's rows.
    per_group = {}
    for c in checks:
        if isinstance(c, dict):
            per_group.setdefault(c.get("group"), []).append(c.get("name"))
    for name in sorted(required_groups):
        got = len(per_group.get(name, []))
        if got != required_groups[name]:
            fails.append(
                "the register holds %d %s checks; the manifest requires %d"
                % (got, name, required_groups[name])
            )

    # --- required checks, BY NAME ------------------------------------------
    # Counting alone cannot tell a renamed check from a replaced one. Labels
    # interpolate runtime values, so the manifest holds each label's static
    # prefix and this requires a one-to-one match.
    for group, prefixes in (spec.get("required_checks") or {}).items():
        if group.startswith("_"):
            continue
        present = list(per_group.get(group, []))
        for prefix in prefixes:
            hit = None
            for candidate in present:
                if isinstance(candidate, str) and candidate.startswith(prefix):
                    hit = candidate
                    break
            if hit is None:
                fails.append(
                    "required %s check is missing: no register row begins %r" % (group, prefix)
                )
                line(False, "required %-8s %r" % (group, prefix))
            else:
                present.remove(hit)
                line(True, "required %-8s %r" % (group, prefix))
        for leftover in present:
            fails.append(
                "unrecognised %s check %r — the manifest does not declare it" % (group, leftover)
            )

    # --- required facts -----------------------------------------------------
    # "A service existed and was observed" and "this run installed, exercised
    # and removed one" are different statements, and only the second is what
    # the packaged job claims.
    for fact, need in (spec.get("required_facts") or {}).items():
        got = r.get(fact)
        good = got == need
        if not good:
            fails.append("required fact %s: got %r, required %r" % (fact, got, need))
        line(good, "fact %s = %r" % (fact, got))

    # --- namespace ----------------------------------------------------------
    production = manifest["production_label"]
    label = r.get("service_label") or ""
    if not spec.get("requires_service"):
        line(True, "service label not required for %s" % key)
    elif not label:
        fails.append(
            "no service label recorded — no LaunchAgent was resolved, so nothing "
            "about service installation is proven"
        )
        line(False, "service label = <none>")
    elif label == production:
        fails.append("the run installed the PRODUCTION service label %r" % label)
        line(False, "service label = %r" % label)
    elif not label.startswith(production + "."):
        fails.append("the service label %r is not a namespaced gateway label" % label)
        line(False, "service label = %r" % label)
    elif not label[len(production) + 1 :]:
        fails.append("the service label %r has an empty installation id" % label)
        line(False, "service label = %r" % label)
    else:
        line(True, "service label = %r (namespaced, not the production label)" % label)

    print("")
    for n in notes:
        print("  note: %s" % n)
    if fails:
        print("=== SERVICE SCOPE ASSERTION FAILED ===")
        for f in fails:
            print("  - %s" % f)
        return 1
    print(
        "=== SERVICE SCOPE COMPLETED: %d/%d required checks passed in %s ==="
        % (expected, expected, key)
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(USAGE)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
