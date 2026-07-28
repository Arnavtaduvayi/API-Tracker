#!/usr/bin/env python3
"""Assert a packaged-validation results file describes a completed SERVICE scope.

Driven by scripts/ci_assert_service_results.sh; see that file for why this is
not a grep for "0 failed". In short: "the script exited 0" and "the full
service scope ran and passed" are different statements, and this project has
been bitten in both directions (RA-003 exited non-zero with every assertion
green; a silent downgrade to --foreground exits zero with a confident total).

Deliberately plain Python so it runs on whatever interpreter a runner image
ships: no f-string nesting, no third-party imports, no version-gated syntax.
"""

import json
import sys

PRODUCTION_LABEL = "dev.api-tracker.gateway"
SCHEMA = "tethra.validation.results/1"


def main(path):
    with open(path) as handle:
        r = json.load(handle)

    fails = []

    def line(good, text):
        print("  %-4s  %s" % ("OK" if good else "FAIL", text))

    def want(label, got, expected):
        good = got == expected
        if not good:
            fails.append("%s: got %r, required %r" % (label, got, expected))
        line(good, "%s = %r" % (label, got))

    want("schema", r.get("schema"), SCHEMA)
    want("scope", r.get("scope"), "full")
    want("mode", r.get("mode"), "service")
    want("verdict", r.get("verdict"), "PASS")
    want("failed", r.get("failed"), 0)
    want("skipped", r.get("skipped"), 0)
    want("duplicate_names", r.get("duplicate_names"), 0)

    executed = r.get("executed_total")
    expected = r.get("expected_total")
    good = executed == expected
    if not good:
        fails.append("executed_total %s != expected_total %s" % (executed, expected))
    line(good, "executed_total = %s (declared %s)" % (executed, expected))

    # Every declared group must have executed its declared count. A total alone
    # hides two drifts that cancel out.
    groups = r.get("groups") or []
    if not groups:
        fails.append("no group breakdown in the results")
    for g in groups:
        good = g.get("executed") == g.get("expected") and g.get("failed") == 0
        if not good:
            fails.append(
                "group %s: executed %s of %s, %s failed"
                % (g.get("name"), g.get("executed"), g.get("expected"), g.get("failed"))
            )
        line(
            good,
            "group %-12s %s/%s executed, %s failed"
            % (g.get("name"), g.get("executed"), g.get("expected"), g.get("failed")),
        )

    # The SERVICE group is the reason this job exists. Requiring it BY NAME
    # means a future edit that drops it from scope_groups fails here, rather
    # than silently reducing what a green check means.
    if not any(g.get("name") == "SERVICE" for g in groups):
        fails.append("the SERVICE group did not run — this scope is not a service run")

    # Every check is named and accounted for.
    checks = r.get("checks") or []
    if len(checks) != executed:
        fails.append(
            "the register holds %d checks but %s executed" % (len(checks), executed)
        )
    names = [c.get("name") for c in checks]
    if len(set(names)) != len(names):
        fails.append("duplicate check names in the register")
    notpass = [c for c in checks if c.get("result") != "pass"]
    for c in notpass:
        fails.append("check not passed: [%s] %s" % (c.get("group"), c.get("name")))
    line(
        not notpass,
        "register: %d named checks, %d not passed" % (len(checks), len(notpass)),
    )

    # The run must never have touched a production identifier. The label is
    # derived by the product from the data directory (ADR 0026), so an isolated
    # run cannot produce the production name — asserting it here turns that
    # design property into a checked one.
    label = r.get("service_label") or ""
    if not label:
        fails.append(
            "no service label recorded — no LaunchAgent was resolved, so nothing "
            "about service installation is proven"
        )
        line(False, "service label = <none>")
    elif label == PRODUCTION_LABEL:
        fails.append("the run installed the PRODUCTION service label %r" % label)
        line(False, "service label = %r" % label)
    elif not label.startswith(PRODUCTION_LABEL + "."):
        fails.append("the service label %r is not a namespaced gateway label" % label)
        line(False, "service label = %r" % label)
    else:
        line(True, "service label = %r (namespaced, not the production label)" % label)

    print("")
    if fails:
        print("=== SERVICE SCOPE ASSERTION FAILED ===")
        for f in fails:
            print("  - %s" % f)
        return 1
    print(
        "=== SERVICE SCOPE COMPLETED: %s/%s checks passed in %s:%s ==="
        % (r.get("passed"), expected, r.get("scope"), r.get("mode"))
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: ci_assert_service_results.py <results.json>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
