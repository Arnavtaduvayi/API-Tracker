#!/usr/bin/env python3
"""Independently enumerate the check call sites in gateway_validate_macos.sh.

The script has NO enumerator of its own (unlike tracking_validate_macos.sh).
REQUIRED_CHECKS=50 was derived from one measured CI run. This re-derives the
number from the source and reports every conditional check site, so a reader
can see whether exactly seven checks are environment-dependent.
"""
import re
import sys

PATH = "/Users/arnavtaduvayi/Documents/APItrack/audit-pr16-fresh-20260729/scripts/gateway_validate_macos.sh"

lines = open(PATH).read().split("\n")

# Primitives that emit exactly one counted check.
REQ = ("ok", "bad")
OPT = ("opt_ok", "opt_bad")
# Helpers that internally call ok/bad exactly once.
HELPERS = ("assert_db", "assert_status")

sites = []          # (lineno, kind, depth, text)
depth = 0
stack = []
in_func = None

func_re = re.compile(r"^([a-z_][a-z0-9_]*)\(\)\s*\{")

for i, raw in enumerate(lines, 1):
    s = raw.strip()
    if not s or s.startswith("#"):
        continue
    # Track function definitions so primitive DEFINITIONS aren't counted.
    m = func_re.match(s)
    if m:
        in_func = m.group(1)
    if in_func and s == "}":
        in_func = None
        continue

    # Blank out double-quoted strings so prose can't look like code.
    blanked = re.sub(r'"[^"]*"', '""', s)

    # Conditional depth tracking (crude but reported, not trusted silently).
    if re.match(r"^(if|for|while|until|case)\b", blanked):
        depth += 1
        stack.append((i, s[:60]))
    if re.match(r"^(fi|done|esac)\b", blanked):
        if stack:
            stack.pop()
        depth = max(0, depth - 1)

    # Skip the primitive definitions themselves.
    if in_func in ("ok", "bad", "opt_ok", "opt_bad", "assert_db", "assert_status",
                   "probe_primitive", "note", "step"):
        continue

    for tok in REQ:
        for mm in re.finditer(r"(?:^|;|\bthen\b|\belse\b|&&|\|\|)\s*" + tok + r"\s+", blanked):
            sites.append((i, "required", depth, s[:90]))
    for tok in OPT:
        for mm in re.finditer(r"(?:^|;|\bthen\b|\belse\b|&&|\|\|)\s*" + tok + r"\s+", blanked):
            sites.append((i, "optional", depth, s[:90]))
    for tok in HELPERS:
        for mm in re.finditer(r"(?:^|;|\bthen\b|\belse\b|&&|\|\|)\s*" + tok + r"\s+", blanked):
            sites.append((i, "required(helper)", depth, s[:90]))

req = [s for s in sites if s[1].startswith("required")]
opt = [s for s in sites if s[1] == "optional"]

print("raw call sites found:")
print("  required-primitive sites : %d" % len([s for s in req if s[1] == "required"]))
print("  helper sites (assert_*)  : %d" % len([s for s in req if s[1] == "required(helper)"]))
print("  optional sites           : %d" % len(opt))
print("")
print("NOTE: an if/else pair emits ONE check from TWO call sites, so raw site")
print("count is an upper bound, not the executed count. Conditional sites:")
print("")
nested = [s for s in sites if s[2] > 0]
print("  sites at conditional depth > 0: %d of %d" % (len(nested), len(sites)))
print("")
print("optional (opt_ok/opt_bad) sites — the three declared machine-dependent places:")
for ln, kind, d, txt in opt:
    print("  line %4d depth=%d  %s" % (ln, d, txt))
