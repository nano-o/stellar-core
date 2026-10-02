#!/usr/bin/env python3
r"""Line and theorem statistics for the Isabelle theories in formal/OfferExchange.

Each non-blank line is attributed to the top-level command it belongs to:

  definition  definitional commands (definition, fun, datatype, record, ...)
  statement   a lemma/theorem/corollary up to the first proof command
  proof       from the first proof command (by, apply, proof, using, ...)
              to the next top-level command
  text        text/section/... blocks, wherever they occur (including
              indented text/txt blocks between a statement and its proof
              and inside proofs)
  comment     (* ... *) blocks, and lines that begin with \<comment>
              (in definitions too, so definition lines, like the C++ code
              lines, exclude comments; a "C++:" tag still marks the
              definition it sits in)
  header      theory/imports/begin/end and tooling glue

Definitions are then grouped into layers (see LAYERS below).  The grouping
is by name and is a hand-maintained judgement: a definition carrying a
"C++:" comment is code-level model; the other names are listed explicitly.
Anything unlisted outside the specification and test interface lands in
"property".  Re-check the lists when definitions are added.

Usage: theory_stats.py [THEORY_DIR]   (default: formal/OfferExchange)
       theory_stats.py --dump THEORY.thy   (each line with its category,
                                            for spot-checking)
"""

import collections
import glob
import os
import re
import statistics
import sys

DEF_COMMANDS = {
    "definition", "fun", "function", "primrec", "datatype", "record",
    "type_synonym", "abbreviation", "consts", "termination", "inductive",
    "typedef", "instantiation", "instance", "locale", "context",
    "overloading", "adhoc_overloading", "nonterminal", "syntax",
    "translations", "notation", "bundle", "unbundle", "declare", "lemmas",
    "named_theorems", "setup", "method", "attribute_setup", "method_setup",
    "ML", "ML_file", "code_printing", "export_code", "code_identifier",
    "value", "partial_function", "fun_cases", "interpretation",
    "global_interpretation", "sublocale", "experiment", "hide_const",
    "no_notation", "type_notation", "declaration", "simproc_setup",
}
STATEMENT_COMMANDS = {"lemma", "theorem", "corollary", "proposition",
                      "schematic_goal"}
TEXT_COMMANDS = {"text", "section", "subsection", "subsubsection", "chapter",
                 "paragraph", "txt", "text_raw", "header"}
HEADER_COMMANDS = {"theory", "imports", "begin", "end", "keywords"}
PROOF_START = re.compile(
    r"^\s*(proof|by|apply|using|unfolding|including|supply|subgoal|sorry|"
    r"oops|done|apply_end)\b|^\s*\.\.?\s*$")
COMMAND = re.compile(r"^([a-z_]+)\b")
INDENTED_TEXT = re.compile(r"^\s+(?:text|txt)\s*\\<open>")
# An Isar step keyword as a word of its own (not shows, obtains, have_foo,
# or part of a fact name such as foo.show).
ISAR_STEP = re.compile(r"(?<![A-Za-z_'.])(have|show|obtain|thus|hence)\b")
DEF_NAME = re.compile(
    r"^[a-z_]+\s+(?:\(open\)\s*)?(?:'[a-z]+\s+)?([A-Za-z_][A-Za-z_0-9]*)")

# Definition layers, by name, for definitions without a "C++:" tag.
CODE_LEVEL_PLUMBING = {
    "export_audit", "int32", "int64", "uint32", "uint128", "cxx_error",
    "cxx_result", "cxx_bind", "cxx_rounding", "exchange_rounding",
    "exchange_options", "exchange_result_v10", "make_exchange_result",
    "legacy_exchange_options", "repaired_exchange_options",
    "exchange_options_at_version", "party_state", "offer_preflight_outcome",
    "post_outcome", "cross_result_v10", "make_cross_result", "offer_request",
    "request_canonical_price_n", "request_canonical_price_d",
    "post_offer_request", "manage_buy_normalized_amount",
    "calculate_offer_value_with_exact_receive_cap",
}
INTEGER_CHARACTERIZATION = {
    "rounded_quotient", "price_error_bound_spec", "favored_seller_ok",
    "apply_price_error_thresholds_spec", "calculate_offer_value_pre",
    "exchange_v10_without_price_error_thresholds_spec", "exchange_v10_pre",
    "exchange_wheat_value_int", "exchange_sheep_value_int",
    "exchange_v10_amounts_int", "exchange_v10_amounts_int_repaired",
    "calculate_offer_amount_from_value_int",
    "exchange_v10_amounts_int_with_options", "exact_trade_value_int",
}
IDEAL_REAL = {
    "ideal_exchange_price", "ideal_wheat_offer_capacity",
    "ideal_sheep_offer_capacity", "ideal_normal_wheat_receive",
    "ideal_normal_sheep_send", "ideal_normal_wheat_stays",
    "normal_result_refines_ideal", "exchange_unconstrained_maker",
}
SCENARIO = {
    "maximum_capacity_taker", "lifecycle_trace", "lifecycle_prefix",
    "lifecycle_outcome", "run_offer_lifecycle", "post_then_cross",
    "p29_adjusted_strict_case", "migration_probe_maker",
    "small_upgrade_case", "small_buy_upgrade_case",
}
TOOLING_THEORIES = {"Timed_Methods.thy"}
SPEC_THEORY = "Offer_Exchange_Specification.thy"
TEST_THEORY = "Offer_Exchange_Test_Interface.thy"
# Theories that repeat definitions from another theory; their lines are
# reported separately so they are not double counted.
DUPLICATING_THEORIES = {"Offer_Exchange_Posting_Refinement.thy"}

UNFINISHED = []  # sorry/oops found in statements or proofs, as FILE:LINE

METHODS = ["simp", "simp_all", "auto", "linarith", "blast", "cases", "eval",
           "rule", "meson", "intro", "subst", "metis", "smt", "fastforce",
           "force", "presburger", "arith", "argo", "clarsimp", "induct"]


def classify(path):
    """Return (line counter, items, labels) for one theory.

    items: dicts with kind 'def' or 'thm', the start line, and line counts.
    labels: the category given to each line, in order (for --dump).
    """
    counts = collections.Counter()
    labels = []

    def count(label):
        counts[label] += 1
        labels.append(label)
    items = []
    mode, current = "header", None
    text_depth, comment_depth = 0, 0
    cartouche_label = "text"  # label of the lines of an open cartouche
    for number, line in enumerate(open(path).read().splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            count("blank")
            continue
        if comment_depth or (stripped.startswith("(*") and not text_depth
                             and not stripped.startswith(("(*<*)", "(*>*)"))):
            comment_depth = max(0, comment_depth + line.count("(*")
                                - line.count("*)"))
            count("comment")
            continue
        if text_depth:
            text_depth += line.count("\\<open>") - line.count("\\<close>")
            count(cartouche_label)
            continue
        if stripped.startswith("\\<comment>"):
            if mode == "definition":
                current["cxx"] |= "C++:" in line
            text_depth = line.count("\\<open>") - line.count("\\<close>")
            cartouche_label = "comment"
            count("comment")
            continue
        match = COMMAND.match(line)
        keyword = match.group(1) if match else None
        if keyword in TEXT_COMMANDS or INDENTED_TEXT.match(line):
            text_depth = line.count("\\<open>") - line.count("\\<close>")
            cartouche_label = "text"
            count("text")
            continue  # the surrounding mode resumes after the block
        if keyword in STATEMENT_COMMANDS:
            mode = "statement"
            current = {"kind": "thm", "line": number, "statement": 0,
                       "proof": 0, "head": stripped,
                       "proof_head": ""}
            items.append(current)
        elif keyword in DEF_COMMANDS:
            mode = "definition"
            name_match = DEF_NAME.match(line)
            current = {"kind": "def", "line": number, "lines": 0,
                       "command": keyword, "cxx": False,
                       "name": name_match.group(1) if name_match else keyword}
            items.append(current)
        elif keyword in HEADER_COMMANDS:
            mode = "header"
        if mode == "statement" and PROOF_START.match(line):
            mode = "proof"
        one_liner = re.search(r"\sby\s", line.split("\\<comment>")[0])
        if mode == "statement" and one_liner:
            # one-line "lemma ... by method": count it as statement
            current["proof_head"] = line[one_liner.start() + 1:].strip()
            count("statement")
            current["statement"] += 1
            mode = "proof"
            continue
        if mode in ("statement", "proof") and re.search(r"\b(sorry|oops)\b",
                                                         line):
            UNFINISHED.append(f"{os.path.basename(path)}:{number}")
        if mode == "proof":
            if current["proof"] == 0:
                current["proof_head"] = stripped
            count("proof")
            current["proof"] += 1
        elif mode == "statement":
            count("statement")
            current["statement"] += 1
        elif mode == "definition":
            count("definition")
            current["lines"] += 1
            current["cxx"] |= "C++:" in line
        else:
            count("header")
    return counts, items, labels


def layer(theory, item):
    suffix = " (repeated)" if theory in DUPLICATING_THEORIES else ""
    name = item["name"]
    if theory == SPEC_THEORY:
        return "abstract specification"
    if theory == TEST_THEORY:
        return "exported test interface"
    if item["cxx"]:
        return "code-level: one definition per C++ function" + suffix
    if name in CODE_LEVEL_PLUMBING or item["command"] in (
            "type_synonym", "datatype", "record", "named_theorems",
            "adhoc_overloading", "export_code", "hide_const"):
        return "code-level: plumbing (types, monad, records, options)" + suffix
    if name in INTEGER_CHARACTERIZATION:
        return "integer characterizations" + suffix
    if name in IDEAL_REAL:
        return "ideal real-valued exchange"
    if name in SCENARIO:
        return "scenarios and witnesses"
    return "property predicates" + suffix


def dump(path):
    """Print every line of one theory prefixed with its category."""
    _, _, labels = classify(path)
    for label, line in zip(labels, open(path).read().splitlines()):
        print(f"{label:10s} | {line}")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--dump":
        dump(sys.argv[2])
        return
    directory = sys.argv[1] if len(sys.argv) > 1 else "formal/OfferExchange"
    theories = sorted(glob.glob(os.path.join(directory, "*.thy")))
    total = collections.Counter()
    layers = collections.Counter()
    theorems = []
    proof_lines = []  # proof and statement lines, for methods and Isar steps
    tagged = []  # (theory, C++-tagged definitions), outside duplicating ones
    print("## Lines per theory\n")
    print("| Theory | total | proof | statement | definition | text | "
          "theorems | C++-tagged defs |")
    print("|---|---|---|---|---|---|---|---|")
    for path in theories:
        theory = os.path.basename(path)
        counts, items, labels = classify(path)
        total.update(counts)
        if theory not in TOOLING_THEORIES:
            proof_lines += [
                line for label, line in zip(labels, open(path).read().splitlines())
                if label in ("proof", "statement")]
        thms = [i for i in items if i["kind"] == "thm"]
        defs = [i for i in items if i["kind"] == "def"]
        theorems += [(i, theory) for i in thms]
        if theory not in TOOLING_THEORIES:
            for item in defs:
                layers[layer(theory, item)] += item["lines"]
        if theory not in DUPLICATING_THEORIES and any(d["cxx"] for d in defs):
            tagged.append((theory, [d for d in defs if d["cxx"]]))
        print(f"| {theory} | {sum(counts.values())} | {counts['proof']} | "
              f"{counts['statement']} | {counts['definition']} | "
              f"{counts['text'] + counts['comment']} | {len(thms)} | "
              f"{sum(1 for d in defs if d['cxx'])} |")
    print(f"| **all** | {sum(total.values())} | {total['proof']} | "
          f"{total['statement']} | {total['definition']} | "
          f"{total['text'] + total['comment']} | {len(theorems)} | |")
    print(f"\nNon-blank lines: {sum(total.values()) - total['blank']}; "
          f"blank: {total['blank']}; header/glue: {total['header']}.")

    print("\n## Definition lines by layer\n")
    print("(Excludes the tooling theory "
          f"{', '.join(sorted(TOOLING_THEORIES))}.)\n")
    print("| Layer | lines |")
    print("|---|---|")
    for name, lines in layers.most_common():
        print(f"| {name} | {lines} |")
    print("\n`C++:`-tagged definitions and their lines (not repeated):\n")
    for theory, defs in tagged:
        print(f"- {theory}: " + ", ".join(
            f"`{d['name']}` {d['lines']}" for d in defs))

    proofs = [t["proof"] for t, _ in theorems]
    print("\n## Theorems\n")
    print(f"- theorems (lemma/theorem/corollary): {len(theorems)}")
    print(f"- proved by a single `by eval` (concrete executable checks): "
          f"{sum(1 for t, _ in theorems if t['proof_head'] == 'by eval')}")
    print(f"- proof lines per theorem: median {statistics.median(proofs)}, "
          f"mean {statistics.mean(proofs):.1f}, max {max(proofs)}")
    print(f"- proofs of at most one line: {sum(p <= 1 for p in proofs)}; "
          f"of 100 lines or more: {sum(p >= 100 for p in proofs)}")
    print("\nLongest proofs:\n")
    for t, theory in sorted(theorems, key=lambda x: -x[0]["proof"])[:10]:
        print(f"- {t['proof']} lines: `{theory}:{t['line']}` "
              f"`{t['head'][:70]}`")

    # Only statement and proof lines, with quoted terms and trailing
    # \<comment>s removed, so prose and terms do not contribute.
    source = "\n".join(re.sub(r'"[^"]*"', '""', line.split("\\<comment>")[0])
                       for line in proof_lines)
    print("\n## Proof methods and Isar steps\n")
    print("First method of each `by M`, `by (M ...)`, `apply M`, "
          "`apply (M ...)` (a closing method, as in `by (induct x) simp_all`, "
          "is not counted):\n")
    method_counts = collections.Counter(
        re.findall(r"\b(?:by|apply)\b\s*\(?\s*([a-z_]+)", source))
    print(", ".join(f"{m} {method_counts[m]}" for m in METHODS
                    if method_counts[m]))
    steps = collections.Counter(ISAR_STEP.findall(source))
    print(f"\nIsar steps (`have`/`show`/`obtain`/`thus`/`hence` keywords, "
          f"including after `then`/`moreover`/`from ...`): "
          f"{sum(steps.values())} "
          f"({', '.join(f'{k} {v}' for k, v in steps.most_common())})")
    print(f"\n`sorry`/`oops` outside comments and prose: {len(UNFINISHED)}"
          f"{' (' + ', '.join(UNFINISHED) + ')' if UNFINISHED else ''}; "
          "the build is the authority on this.")


if __name__ == "__main__":
    main()
