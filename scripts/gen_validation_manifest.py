#!/usr/bin/env python3
"""Generate scripts/validation_manifest.json FROM THE HARNESS SOURCES.

    gen_validation_manifest.py --check    regenerate in memory, diff against the
                                          committed manifest, exit 1 on drift
    gen_validation_manifest.py --write    rewrite the committed manifest

VAL-05-R — WHY THIS EXISTS
==========================

`ci_assert_service_results.py` bound check COUNTS. Of the 63 checks in
`full:service` only the 9 SERVICE ones were bound by IDENTITY; the other 54
were not, nor were any of the 57 in `full:foreground`, any of the 20 in
`offline:none`, or any of the 57 in the gateway harness, which had no register
and no manifest at all. So the auditor's forgery case 2b — rename ONE required
APPLY check to a string naming no assertion the product ever made, touching no
count — was ACCEPTED, and printed

    OK    group APPLY        9/9 executed, 0 failed
    === SERVICE SCOPE COMPLETED: 63/63 required checks passed in full:service ===

A correct count is not evidence that the correct checks ran.

The fix needs a TRUSTED statement of the exact required check set for every
scope, and a trusted statement drifts. This file is what stops it drifting: the
manifest is not maintained, it is DERIVED, and CI re-derives it and fails on any
difference. A developer who adds, removes, renames or re-groups a check runs
`--write` and the change lands as a reviewable diff naming the exact check.

WHAT COUNTS AS A CHECK'S IDENTITY — AND WHY THE LABEL, NOT AN ANNOTATION
=======================================================================

Two designs were available:

  (a) the STATIC PREFIX OF THE CHECK'S LABEL, extracted from the call site —
      the mechanism already in use for the nine SERVICE checks; or
  (b) an explicit `#@id GROUP.slug` annotation on every call site, carried
      through the register into the results document.

This file implements (a), deliberately:

  * The label is what a human reading the artifact actually sees. An `#@id` is
    a SECOND name for the same check, and nothing can keep the two honest: a
    reviewer approving `#@id APPLY.route_row_exists` on a line whose label now
    reads "a completely different apply assertion" sees a matching id and a
    green manifest. Binding the identity to the label makes case 2b — a
    rename with every count intact — a manifest diff by construction, which is
    exactly the forgery that got through.
  * (b) requires touching ~130 call sites across two harnesses and changing six
        primitive signatures. `scripts/validation_harness_mutants.sh` mutates
        five of those primitive definitions by EXACT-TEXT `sed` and reports a
        `sed` that no longer matches as a hard error, so (b) cannot be landed
        without rewriting the mutation suite in the same breath — replacing a
        proven control with an unproven one while fixing a trust defect.
  * (a)'s known weaknesses are real and are closed HERE, fail-closed, at
    generation time rather than left as hazards: a label whose static prefix is
    shorter than MIN_PREFIX characters is refused (no degenerate prefix that
    matches everything); two checks in one scope whose prefixes shadow each
    other are refused (that is what made the old validator's first-match
    assignment order-dependent); a check whose group moved is a diff.

The residual risk (a) cannot close, stated plainly: an editor who changes a
check's BODY while keeping its label. That is a source diff, visible in review,
and the manifest is deliberately unchanged by it. No manifest can close it.

INPUTS — AND THE ONE RULE THAT MUST NOT BE BROKEN
=================================================

The ONLY inputs are the two committed harness scripts. Nothing here reads a
results document, and nothing the run under test can write reaches this file.
For the tracking harness the sites come from the harness's OWN enumerator
(`--emit-check-sites`), which already refuses a check inside a loop, a runtime
conditional whose branches emit different numbers of checks, and a conditional
with no else — so a shape whose identity cannot be pinned is an error in the
harness rather than a guess here. For the gateway harness, which has no
enumerator, an equivalent fail-closed model is implemented below.

Deliberately plain Python, matching ci_assert_service_results.py: no f-strings,
no third-party imports, no version-gated syntax.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TRACKING = os.path.join(HERE, "tracking_validate_macos.sh")
GATEWAY = os.path.join(HERE, "gateway_validate_macos.sh")
MANIFEST = os.path.join(HERE, "validation_manifest.json")

MANIFEST_SCHEMA = "tethra.validation.manifest/2"
RESULTS_SCHEMA = "tethra.validation.results/2"
PRODUCTION_LABEL = "dev.api-tracker.gateway"

# A prefix shorter than this cannot identify anything: "the " would match half
# the register. A label that begins with an interpolation therefore has to be
# rewritten so its first characters are static — which is a real constraint on
# how checks are written, and the point.
MIN_PREFIX = 12

# Which argument of each primitive is the human label. This is the whole of the
# extraction contract; a primitive not named here is not a check site.
TRACKING_PRIMITIVES = {
    "ok": 1,
    "bad": 1,
    "check": 2,
    "assert_db": 2,
    "assert_same_bytes": 3,
    "selfcheck": 2,
}
GATEWAY_REQUIRED_PRIMITIVES = {
    "ok": 1,
    "bad": 1,
    "assert_db": 2,
    "assert_status": 2,
}
GATEWAY_OPTIONAL_PRIMITIVES = {
    "opt_ok": 1,
    "opt_bad": 1,
}

TRACKING_TUPLES = [
    ("selfcheck:none", []),
    ("offline:none", []),
    ("full:foreground", ["--foreground"]),
    ("full:service", ["--require-service"]),
]

SCOPE_DESCRIPTIONS = {
    "full:service": "The packaged macOS service lifecycle: installs, exercises and removes a namespaced LaunchAgent.",
    "full:foreground": "The unsigned-build fallback: a foreground gateway, no LaunchAgent. NOT a substitute for full:service.",
    "offline:none": "No gateway is started and no network request is made.",
    "selfcheck:none": "Proves only that the harness reports a deliberately-broken control as a failure.",
    "gateway:lifecycle": "The Local Gateway lifecycle verbs (install, bootstrap, stop, restart, repair, uninstall) against a REAL per-user LaunchAgent.",
}


class Abort(Exception):
    """A shape whose identity cannot be pinned. Never guessed at."""


# ---------------------------------------------------------------------------
# shell-ish parsing
# ---------------------------------------------------------------------------

def quote_mask(text):
    """True for every character that sits inside a quoted string.

    Used only to decide whether a primitive NAME occurrence is code or prose:
    the word "bad" appears inside plenty of labels and must never be mistaken
    for a call.
    """
    mask = [False] * len(text)
    i = 0
    state = None
    while i < len(text):
        c = text[i]
        if state is None:
            if c == "\\":
                i += 2
                continue
            if c == '"' or c == "'":
                state = c
                mask[i] = True
                i += 1
                continue
        elif state == '"':
            mask[i] = True
            if c == "\\":
                if i + 1 < len(text):
                    mask[i + 1] = True
                i += 2
                continue
            if c == '"':
                state = None
            i += 1
            continue
        else:  # single quotes: nothing is an escape inside them
            mask[i] = True
            if c == "'":
                state = None
            i += 1
            continue
        i += 1
    return mask


def split_words(text):
    """Split a shell fragment into words, keeping quoting information.

    Returns a list of (kind, value) where kind is 'dq' for a double-quoted
    literal, 'sq' for a single-quoted one and 'bare' otherwise. Word splitting
    stops at `;`, `&&`, `||` and `|` at depth 0, because the argument list of
    one command ends there.
    """
    words = []
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i] in " \t":
            i += 1
        if i >= n:
            break
        if text[i] == ";":
            break
        if text.startswith("&&", i) or text.startswith("||", i):
            break
        if text[i] == "|":
            break
        start = i
        kind = "bare"
        buf = []
        depth = 0
        while i < n:
            c = text[i]
            if c in " \t" and depth == 0:
                break
            if depth == 0 and (c == ";" or c == "|" or text.startswith("&&", i)):
                break
            if c == '"':
                if i == start:
                    kind = "dq"
                i += 1
                while i < n:
                    if text[i] == "\\" and i + 1 < n:
                        buf.append(text[i + 1] if text[i + 1] in '"\\$`' else "\\" + text[i + 1])
                        i += 2
                        continue
                    if text[i] == '"':
                        i += 1
                        break
                    buf.append(text[i])
                    i += 1
                continue
            if c == "'":
                if i == start:
                    kind = "sq"
                i += 1
                while i < n and text[i] != "'":
                    buf.append(text[i])
                    i += 1
                i += 1
                continue
            if text.startswith("$(", i):
                depth += 1
                buf.append(text[i])
                i += 1
                continue
            if c == "(" and depth > 0:
                depth += 1
            if c == ")" and depth > 0:
                depth -= 1
            buf.append(c)
            i += 1
        words.append((kind, "".join(buf)))
    return words


def static_prefix(literal):
    """The part of a double-quoted label that is FIXED at authoring time.

    Truncated at the first unescaped `$` or backtick, because everything after
    one is a runtime value: a pid, a path, a uid. `\\$` is a literal dollar and
    survives — that is how "…at \\$TETHRA_DIR/gateway.sock, mode 0600" keeps the
    dollar the register will actually contain.
    """
    out = []
    i = 0
    n = len(literal)
    while i < n:
        c = literal[i]
        if c == "\\" and i + 1 < n:
            nxt = literal[i + 1]
            if nxt in '$`"\\':
                out.append(nxt)
                i += 2
                continue
            out.append(c)
            i += 1
            continue
        if c == "$" or c == "`":
            break
        out.append(c)
        i += 1
    return "".join(out)


COMMAND_POSITION_ENDINGS = ("&&", "||", ";", ")", "|", "then", "else", "do", "(", "{")


def split_unquoted(text, sep):
    """Split on `sep` only where it is not inside quotes."""
    mask = quote_mask(text)
    parts = []
    start = 0
    i = 0
    while i <= len(text) - len(sep):
        if not mask[i] and text.startswith(sep, i):
            parts.append(text[start:i])
            i += len(sep)
            start = i
            continue
        i += 1
    parts.append(text[start:])
    return parts


def at_command_position(text, mask, idx):
    """Is the primitive name at `idx` an invocation rather than prose?"""
    if mask[idx]:
        return False
    before = text[:idx].rstrip()
    if not before:
        return True
    for token in COMMAND_POSITION_ENDINGS:
        if before.endswith(token):
            return True
    return False


def labels_on_line(line, primitives, what):
    """Every label a single logical line's invocations of `primitives` emit."""
    mask = quote_mask(line)
    found = []
    for name in primitives:
        arity = primitives[name]
        start = 0
        while True:
            idx = line.find(name, start)
            if idx < 0:
                break
            start = idx + 1
            end = idx + len(name)
            if idx > 0 and (line[idx - 1].isalnum() or line[idx - 1] in "_-."):
                continue
            if end < len(line) and (line[end].isalnum() or line[end] in "_-.("):
                continue
            if not at_command_position(line, mask, idx):
                continue
            words = split_words(line[end:])
            if len(words) < arity:
                raise Abort(
                    "%s: `%s` is invoked with %d argument(s) but its label is argument %d:\n    %s"
                    % (what, name, len(words), arity, line.strip())
                )
            kind, value = words[arity - 1]
            if kind != "dq":
                raise Abort(
                    "%s: `%s`'s label argument is not a double-quoted literal, so no static\n"
                    "    identity can be extracted from it:\n    %s" % (what, name, line.strip())
                )
            found.append((idx, static_prefix(value)))
    found.sort()
    return [f[1] for f in found]


# ---------------------------------------------------------------------------
# the tracking harness — sites come from its OWN enumerator
# ---------------------------------------------------------------------------

def tracking_sites(tuple_name, flags):
    scope = tuple_name.split(":")[0]
    cmd = ["bash", TRACKING, "--scope", scope] + flags + ["--emit-check-sites"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise Abort(
            "the tracking harness could not enumerate its own check sites for %s.\n"
            "This is fail-closed on purpose: a shape the enumerator cannot pin is an\n"
            "error in the harness, never a guess here.\n%s%s"
            % (tuple_name, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))
        )
    sites = []
    order = []
    for row in out.decode("utf-8", "replace").split("\n"):
        if not row.strip():
            continue
        parts = row.split("\t", 2)
        if len(parts) != 3:
            raise Abort("unparsable site row for %s: %r" % (tuple_name, row))
        seq, group, raw = parts[0], parts[1], parts[2]
        what = "%s site %s" % (tuple_name, seq)
        prefixes = labels_on_line(raw, TRACKING_PRIMITIVES, what)
        if not prefixes:
            raise Abort("%s: no label could be extracted from:\n    %s" % (what, raw.strip()))
        if seq not in sites:
            sites.append(seq)
            order.append({"seq": seq, "group": group, "labels": []})
        entry = order[sites.index(seq)]
        if entry["group"] != group:
            raise Abort(
                "%s: sibling branches of one check are in different groups (%s vs %s)"
                % (what, entry["group"], group)
            )
        for p in prefixes:
            if p not in entry["labels"]:
                entry["labels"].append(p)
    return order


def harness_counts():
    """The harness's OWN group table, read without running anything.

    Kept because it is an INDEPENDENT statement of the same numbers: the sites
    above are re-derived from the source by the enumerator, and this is the
    table the harness itself sums its totals from. Two statements that must
    agree, which is the arrangement RA-003 existed for.
    """
    script = (
        'export TETHRA_VALIDATE_LIB_ONLY=1\n'
        'export TETHRA_DIR="${TMPDIR:-/tmp}/tethra-genmanifest-$$"\n'
        '. "%s" --scope selfcheck >/dev/null 2>&1\n'
        'for t in selfcheck:none offline:none full:foreground full:service; do\n'
        '  printf "%%s\\t%%s\\t%%s\\n" "$t" TOTAL "$(expected_total "$t")"\n'
        '  for g in $(scope_groups "$t"); do\n'
        '    printf "%%s\\t%%s\\t%%s\\n" "$t" "$g" "$(group_size "$g")"\n'
        '  done\n'
        'done\n' % TRACKING
    )
    proc = subprocess.Popen(["bash", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise Abort("could not read the harness's own group table:\n" + err.decode("utf-8", "replace"))
    table = {}
    for row in out.decode("utf-8", "replace").split("\n"):
        if not row.strip():
            continue
        t, g, n = row.split("\t")
        table.setdefault(t, {})[g] = int(n)
    return table


# ---------------------------------------------------------------------------
# the gateway harness — no enumerator, so an equivalent model lives here
# ---------------------------------------------------------------------------

def open_quote(text):
    """Which quote, if any, is still open at the end of `text`."""
    i = 0
    state = None
    while i < len(text):
        c = text[i]
        if state is None:
            if c == "\\":
                i += 2
                continue
            if c == '"' or c == "'":
                state = c
        elif state == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                state = None
        else:
            if c == "'":
                state = None
        i += 1
    return state


def heredoc_terminators(text):
    """Every here-document terminator word `text` opens, in order."""
    import re

    return [m.group(2) for m in re.finditer(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", text)]


def logical_lines(path):
    """Physical lines joined into logical ones, comments and blanks dropped.

    A check's LABEL is frequently on a different physical line from the
    primitive that emits it — after a `\\` continuation, after a multi-line SQL
    string, or after a multi-line `python3 -c '…'` program. If those are not
    rejoined, the primitive and its label are never seen together and the check
    is silently absent from the manifest. Silently absent is precisely the
    failure mode this whole file exists to prevent, so the joining rules are
    explicit: backslash continuations, unbalanced quotes (double OR single,
    tracked as real quoting state rather than by counting), and here-documents,
    whose bodies are skipped entirely because they are data, not shell.
    """
    raw = open(path).read().split("\n")
    out = []
    buf = ""
    pending = 0
    terminator = None
    consumed = 0          # here-documents already skipped for the current buffer
    for n, line in enumerate(raw, 1):
        if terminator is not None:
            if line.strip() == terminator:
                terminator = None
            continue
        if not buf:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            buf = line
            pending = n
            consumed = 0
        else:
            buf = buf + " " + line
        # A here-document body is DATA, not shell: it must never be joined into
        # the logical line, and the rest of that line (typically a closing
        # `)"`) resumes after the terminator. Checked before the quote rules
        # because the opener itself is usually mid-quote.
        terms = heredoc_terminators(buf)
        if len(terms) > consumed:
            terminator = terms[consumed]
            consumed += 1
            continue
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1] + " "
            continue
        if open_quote(buf) is not None:
            continue
        out.append((pending, buf.strip()))
        buf = ""
        consumed = 0
    if buf:
        out.append((pending, buf.strip()))
    return out


class Block(object):
    def __init__(self, kind, lineno):
        self.kind = kind          # "if" | "case" | "loop"
        self.lineno = lineno
        self.branches = [[]]      # required sites, per branch
        self.optional = []        # optional sites, flattened
        self.saw_default = False


def gateway_sites():
    """Required and optional check sites in the gateway harness.

    Fail-closed in the two ways the audit found this script was not:

      * `NEW-26` — a REQUIRED check inside a loop makes the required total
        data-dependent, so it is an error here. (`opt_*` sites are excluded
        from the required equality by declaration, but a loop would still make
        them unattributable, so they are refused too.)
      * `NEW-27` — the branches of a conditional must emit the SAME number of
        required checks. An `if` with no `else`, or an `else` that only prints
        a SKIP, means a required check silently vanishes when the other arm is
        taken, and the equality gate then reports the wrong diagnosis.
    """
    lines = logical_lines(GATEWAY)
    stack = []
    group = None
    required = []          # list of {"group":…, "labels":[…]}
    optional = []
    scanning = False

    def emit_required(labels, grp, lineno):
        site = {"group": grp, "labels": list(labels), "line": lineno}
        if stack:
            stack[-1].branches[-1].append(site)
        else:
            required.append(site)

    def emit_optional(labels, grp, lineno):
        for lab in labels:
            site = {"group": grp, "labels": [lab], "line": lineno}
            if stack:
                stack[-1].optional.append(site)
            else:
                optional.append(site)

    def close_block(block, lineno):
        # An `if` with no explicit `else` has an implicit empty branch: the
        # path where nothing runs. Naming it is what turns `NEW-27` into an
        # error instead of a silent hole.
        if block.kind == "if" and len(block.branches) == 1:
            block.branches.append([])
        if block.kind == "case" and not block.saw_default:
            block.branches.append([])
        sizes = [len(b) for b in block.branches]
        if block.kind == "loop":
            total = sum(sizes)
            if total or block.optional:
                raise Abort(
                    "gateway_validate_macos.sh:%d — a counted check sits inside a loop, so the\n"
                    "    required total depends on the data (`NEW-26`). Accumulate the findings\n"
                    "    and report them with exactly one check after the loop." % block.lineno
                )
            paired = []
        else:
            if len(set(sizes)) != 1:
                raise Abort(
                    "gateway_validate_macos.sh:%d — the branches of this conditional emit\n"
                    "    different numbers of REQUIRED checks %s, so one of them makes a required\n"
                    "    check vanish (`NEW-27`). Every arm must emit the same checks, or the\n"
                    "    checks must be optional." % (block.lineno, sizes)
                )
            paired = []
            for i in range(sizes[0]):
                labels = []
                grp = block.branches[0][i]["group"]
                for b in block.branches:
                    for lab in b[i]["labels"]:
                        if lab not in labels:
                            labels.append(lab)
                paired.append({"group": grp, "labels": labels, "line": block.branches[0][i]["line"]})
        target_req = stack[-1].branches[-1] if stack else required
        target_opt = stack[-1].optional if stack else optional
        for site in paired:
            target_req.append(site)
        for site in block.optional:
            target_opt.append(site)

    for lineno, line in lines:
        head = line.split()[0] if line.split() else ""
        if not scanning:
            if head == "group":
                scanning = True
            else:
                continue
        if head == "group":
            group = line.split()[1]
            continue

        # A conditional written entirely on one line
        # (`if …; then ok "x"; else bad "y"; fi`) is a single logical check
        # with two labels, exactly like the multi-line form. It is expanded
        # here rather than pushed on the stack, because there is no later
        # `fi` line to close it.
        if head == "if" and line.rstrip().endswith("fi"):
            body = line.rstrip()[:-2].rstrip().rstrip(";")
            pieces = split_unquoted(body, "; then ")
            if len(pieces) != 2:
                raise Abort(
                    "gateway_validate_macos.sh:%d — a one-line conditional this generator\n"
                    "    cannot decompose; write it over several lines.\n    %s" % (lineno, line)
                )
            arms = split_unquoted(pieces[1], "; else ")
            if len(arms) == 1:
                arms.append("")
            if len(arms) != 2 or "; elif " in pieces[1]:
                raise Abort(
                    "gateway_validate_macos.sh:%d — a one-line conditional with an elif chain;\n"
                    "    write it over several lines.\n    %s" % (lineno, line)
                )
            what = "gateway_validate_macos.sh:%d" % lineno
            arm_req = [labels_on_line(a, GATEWAY_REQUIRED_PRIMITIVES, what) for a in arms]
            arm_opt = [labels_on_line(a, GATEWAY_OPTIONAL_PRIMITIVES, what) for a in arms]
            if len(arm_req[0]) != len(arm_req[1]):
                raise Abort(
                    "%s — the arms of this one-line conditional emit different numbers of\n"
                    "    REQUIRED checks %s (`NEW-27`)."
                    % (what, [len(arm_req[0]), len(arm_req[1])])
                )
            for i in range(len(arm_req[0])):
                labels = []
                for arm in arm_req:
                    if arm[i] not in labels:
                        labels.append(arm[i])
                if group is None:
                    raise Abort("%s — a check appears before any `group` statement" % what)
                emit_required(labels, group, lineno)
            for arm in arm_opt:
                if arm:
                    emit_optional(arm, group, lineno)
            continue

        # structure first, so a keyword line's own checks land in the right
        # branch (`else bad "…"` opens the branch it belongs to).
        rest = line
        if head in ("fi", "esac", "done"):
            if not stack:
                raise Abort("gateway_validate_macos.sh:%d — `%s` with nothing open" % (lineno, head))
            close_block(stack.pop(), lineno)
            continue
        if head in ("else", "elif"):
            if not stack:
                raise Abort("gateway_validate_macos.sh:%d — `%s` outside a conditional" % (lineno, head))
            stack[-1].branches.append([])
            rest = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
            if head == "elif":
                rest = ""
        elif head == "if":
            stack.append(Block("if", lineno))
        elif head in ("for", "while", "until") and line.rstrip().endswith("do"):
            stack.append(Block("loop", lineno))
        elif line.startswith("case ") and line.rstrip().endswith(" in"):
            stack.append(Block("case", lineno))
            continue
        elif stack and stack[-1].kind == "case" and ")" in line and not line.startswith("("):
            arm = line.split(")", 1)[0]
            if arm.strip() and " " not in arm.strip():
                stack[-1].branches.append([])
                if arm.strip() == "*":
                    stack[-1].saw_default = True
                rest = line.split(")", 1)[1]

        if not rest.strip():
            continue
        what = "gateway_validate_macos.sh:%d" % lineno
        req_labels = labels_on_line(rest, GATEWAY_REQUIRED_PRIMITIVES, what)
        opt_labels = labels_on_line(rest, GATEWAY_OPTIONAL_PRIMITIVES, what)
        if req_labels and opt_labels:
            raise Abort("%s — one line mixes required and optional checks" % what)
        if req_labels:
            if group is None:
                raise Abort("%s — a check appears before any `group` statement" % what)
            emit_required(req_labels, group, lineno)
        if opt_labels:
            if group is None:
                raise Abort("%s — a check appears before any `group` statement" % what)
            emit_optional(opt_labels, group, lineno)

    if stack:
        raise Abort(
            "gateway_validate_macos.sh — unbalanced if/case/loop nesting at end of file (%d open)"
            % len(stack)
        )
    return required, optional


def declared_required_checks():
    """The `REQUIRED_CHECKS=` constant the gateway harness enforces locally."""
    for line in open(GATEWAY).read().split("\n"):
        if line.startswith("REQUIRED_CHECKS="):
            return int(line.split("=", 1)[1].strip())
    raise Abort("gateway_validate_macos.sh declares no REQUIRED_CHECKS constant")


# ---------------------------------------------------------------------------
# assembly
# ---------------------------------------------------------------------------

def check_entry(group, labels, seen, scope):
    for lab in labels:
        if len(lab) < MIN_PREFIX:
            raise Abort(
                "%s: the check %r has a static label prefix of only %d character(s).\n"
                "    A prefix that short identifies nothing — rewrite the label so it begins\n"
                "    with at least %d characters that are fixed at authoring time, before any\n"
                "    interpolation." % (scope, lab, len(lab), MIN_PREFIX)
            )
    return {"group": group, "label_prefixes": labels}


def reject_shadowing(entries, scope):
    """No declared prefix may be a prefix of another in the same scope.

    This is the hazard the old validator carried unnamed: matching was
    `startswith` and first-match-wins, so if one required prefix were a prefix
    of another the earlier entry would consume the later one's row and produce
    a false pass. It cannot arise if it cannot be generated.
    """
    flat = []
    for i, entry in enumerate(entries):
        for lab in entry["label_prefixes"]:
            flat.append((lab, i))
    for a_lab, a_i in flat:
        for b_lab, b_i in flat:
            if a_i == b_i:
                continue
            if b_lab.startswith(a_lab):
                raise Abort(
                    "%s: the label prefix %r shadows %r — one is a prefix of the other, so\n"
                    "    a register row could be attributed to either check. Make the two labels\n"
                    "    distinguishable in their first %d static characters."
                    % (scope, a_lab, b_lab, MIN_PREFIX)
                )


def build():
    table = harness_counts()
    scopes = {}

    for tuple_name, flags in TRACKING_TUPLES:
        sites = tracking_sites(tuple_name, flags)
        entries = []
        groups = {}
        for site in sites:
            entries.append(check_entry(site["group"], site["labels"], None, tuple_name))
            groups[site["group"]] = groups.get(site["group"], 0) + 1
        reject_shadowing(entries, tuple_name)

        declared = table.get(tuple_name)
        if declared is None:
            raise Abort("the harness declares no group table for %s" % tuple_name)
        if len(entries) != declared["TOTAL"]:
            raise Abort(
                "%s: the enumerator found %d check sites but the harness's own group table\n"
                "    sums to %d. One of the two is wrong; neither is guessed at here."
                % (tuple_name, len(entries), declared["TOTAL"])
            )
        for g in groups:
            if declared.get(g) != groups[g]:
                raise Abort(
                    "%s/%s: %d sites found, the harness declares %s"
                    % (tuple_name, g, groups[g], declared.get(g))
                )
        for g in declared:
            if g == "TOTAL":
                continue
            if g not in groups:
                raise Abort("%s/%s: the harness declares the group but no site was found" % (tuple_name, g))

        scopes[tuple_name] = {
            "description": SCOPE_DESCRIPTIONS[tuple_name],
            "harness": "scripts/tracking_validate_macos.sh",
            "expected_total": len(entries),
            "requires_service": tuple_name == "full:service",
            "groups": dict((k, groups[k]) for k in sorted(groups)),
            "required_checks": entries,
            "optional_checks": [],
            "required_facts": (
                {"service_created_by_this_run": True} if tuple_name == "full:service" else {}
            ),
        }

    req_sites, opt_sites = gateway_sites()
    req_entries = [check_entry(s["group"], s["labels"], None, "gateway:lifecycle") for s in req_sites]
    opt_entries = [check_entry(s["group"], s["labels"], None, "gateway:lifecycle") for s in opt_sites]
    reject_shadowing(req_entries + opt_entries, "gateway:lifecycle")

    declared_constant = declared_required_checks()
    if declared_constant != len(req_entries):
        raise Abort(
            "gateway_validate_macos.sh declares REQUIRED_CHECKS=%d but %d required call sites\n"
            "    were found in its source. The constant is not allowed to be a number from one\n"
            "    measured run; update it (or the checks) so the two agree."
            % (declared_constant, len(req_entries))
        )

    gw_groups = {}
    for entry in req_entries:
        gw_groups[entry["group"]] = gw_groups.get(entry["group"], 0) + 1

    scopes["gateway:lifecycle"] = {
        "description": SCOPE_DESCRIPTIONS["gateway:lifecycle"],
        "harness": "scripts/gateway_validate_macos.sh",
        "expected_total": len(req_entries),
        "requires_service": True,
        "groups": dict((k, gw_groups[k]) for k in sorted(gw_groups)),
        "required_checks": req_entries,
        "optional_checks": opt_entries,
        "required_facts": {"service_created_by_this_run": True},
    }

    return {
        "_comment": [
            "TRUSTED CHECK MANIFEST — the acceptance criteria for a validation run.",
            "",
            "GENERATED. Do not edit by hand: scripts/gen_validation_manifest.py --check runs in",
            "CI and fails on any difference between this file and what the harness sources",
            "produce. Run --write after adding, removing, renaming or re-grouping a check, and",
            "review the diff — it names the exact check that moved.",
            "",
            "VAL-01: a result may REPORT what it observed; it may not DEFINE what is",
            "acceptable. Everything the validator enforces comes from this file and from",
            "arguments the caller supplies, never from the artifact under test.",
            "",
            "VAL-05-R: counts are not identities. `required_checks` is the EXACT SET a scope",
            "must execute, and the validator requires set equality in both directions — a",
            "renamed check, a substituted check, a duplicate, an unknown one, or a missing one",
            "all fail even when every count still adds up. `optional_checks` are the",
            "environment-dependent checks of the gateway harness; they are validated as a",
            "SUBSET (they may legitimately not run) and may never stand in for a required one.",
            "",
            "Each entry's identity is the STATIC PREFIX of its label — the part fixed at",
            "authoring time, before any interpolation. Several prefixes on one entry mean the",
            "check has sibling branches (an if/else pair, `A && ok .. || bad ..`, case arms)",
            "that emit one check under one of several labels.",
        ],
        "schema": MANIFEST_SCHEMA,
        "results_schema": RESULTS_SCHEMA,
        "production_label": PRODUCTION_LABEL,
        "generated_by": "scripts/gen_validation_manifest.py",
        "min_label_prefix": MIN_PREFIX,
        "scopes": dict((k, scopes[k]) for k in sorted(scopes)),
    }


def render(doc):
    # ensure_ascii=False so a label containing an em dash appears in the manifest
    # exactly as it appears in the harness — a reviewer must be able to read the
    # trusted set, and \u2014 escapes are how a substituted label hides in a diff.
    return json.dumps(doc, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def main(argv):
    mode = None
    for a in argv:
        if a in ("--check", "--write"):
            mode = a
        else:
            sys.stderr.write("usage: gen_validation_manifest.py [--check|--write]\n")
            return 2
    if mode is None:
        sys.stderr.write("usage: gen_validation_manifest.py [--check|--write]\n")
        return 2

    try:
        text = render(build())
    except Abort as e:
        sys.stderr.write("MANIFEST GENERATION REFUSED\n  %s\n" % e)
        return 1

    if mode == "--write":
        handle = open(MANIFEST, "w")
        handle.write(text)
        handle.close()
        sys.stdout.write("wrote %s\n" % MANIFEST)
        return 0

    try:
        current = open(MANIFEST).read()
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("cannot read %s: %s\n" % (MANIFEST, e))
        return 1
    if current == text:
        print("validation_manifest.json is exactly what the harness sources produce")
        return 0

    import difflib

    print("=== validation_manifest.json HAS DRIFTED from the harness sources ===")
    diff = difflib.unified_diff(
        current.split("\n"), text.split("\n"),
        fromfile="scripts/validation_manifest.json (committed)",
        tofile="scripts/gen_validation_manifest.py (derived from the harnesses)",
        lineterm="",
    )
    shown = 0
    for row in diff:
        print(row)
        shown += 1
        if shown > 400:
            print("  … diff truncated …")
            break
    print("")
    print("Run: python3 scripts/gen_validation_manifest.py --write   and review the diff.")
    print("A manifest that no longer describes the harness either demands checks nobody")
    print("runs, or — worse — blesses a smaller suite than the one the harness declares.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
