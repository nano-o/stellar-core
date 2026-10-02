#!/usr/bin/env python3
"""Count the C++ lines the code-level model follows, from coverage.tsv.

For each row the script checks that the named function starts at the given
line and, by brace matching, that its body ends at the given end line (so an
edit that changes a function's length is caught), and counts

  physical lines   every line from the return-type line to the closing brace
  code lines       non-blank lines that are not // comments or ZoneScoped
  statement lines  code lines that are not just braces or "else"

over the whole function and over the modelled ranges.  A range that starts
at the name line also covers a return type on the line before, as "all"
does.  The judgement of what is modelled lives in coverage.tsv, not here.

Usage: cxx_coverage.py [SRC_DIR [TABLE]]
       (defaults: src, formal/docs/stats/coverage.tsv)
"""

import collections
import os
import re
import sys


def is_code(line):
    stripped = line.strip()
    return (bool(stripped) and not stripped.startswith("//")
            and stripped != "ZoneScoped;")


def is_statement(line):
    return is_code(line) and not re.fullmatch(r"[{};\s]*(else)?[{};\s]*",
                                              line.strip())


def extent(lines, name_line, function):
    """Return (first, last) 1-based lines of the definition starting at name_line."""
    text = lines[name_line - 1]
    if not re.match(r"^" + re.escape(function) + r"\s*\(", text):
        raise SystemExit(f"line {name_line} does not start {function}: {text!r}")
    first = name_line
    previous = lines[name_line - 2].strip() if name_line > 1 else ""
    if previous and "(" not in previous and not previous.startswith(("//", "}")):
        first = name_line - 1  # return type on its own line
    depth, opened = 0, False
    for number in range(name_line, len(lines) + 1):
        for character in lines[number - 1]:
            if character == "{":
                depth, opened = depth + 1, True
            elif character == "}":
                depth -= 1
        if opened and depth == 0:
            return first, number
    raise SystemExit(f"unterminated body for {function} at {name_line}")


def parse_ranges(spec, first, name_line, last, function):
    if spec == "all":
        return [(first, last)]
    ranges = []
    for part in spec.split(","):
        low, _, high = part.partition("-")
        low, high = int(low), int(high or low)
        if not name_line <= low <= high <= last:
            raise SystemExit(f"{function}: range {part} outside "
                             f"{name_line}-{last}")
        ranges.append((first if low == name_line else low, high))
    return ranges


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else "src"
    table = sys.argv[2] if len(sys.argv) > 2 else "formal/docs/stats/coverage.tsv"
    rows = [line.rstrip("\n").split("\t") for line in open(table)
            if line.strip() and not line.startswith("#")]
    header, rows = rows[0], rows[1:]
    cache = {}
    totals = collections.Counter()
    per_file = collections.defaultdict(collections.Counter)
    print("| C++ function | lines | code lines | modelled code lines | "
          "modelled statement lines | coverage | model |")
    print("|---|---|---|---|---|---|---|")
    for row in rows:
        record = dict(zip(header, row + [""] * (len(header) - len(row))))
        path = os.path.join(source, record["file"])
        lines = cache.setdefault(path, open(path).read().split("\n"))
        name_line = int(record["name_line"])
        first, last = extent(lines, name_line, record["function"])
        if last != int(record["end_line"]):
            raise SystemExit(f"{record['function']} at {name_line} now ends "
                             f"at {last}, not {record['end_line']}: "
                             "re-check its ranges")
        ranges = parse_ranges(record["modelled"], first, name_line, last,
                              record["function"])
        body = lines[first - 1:last]
        code = sum(map(is_code, body))
        modelled_numbers = {n for low, high in ranges
                            for n in range(low, high + 1)}
        modelled = sum(is_code(lines[n - 1]) for n in modelled_numbers)
        statements = sum(is_statement(lines[n - 1]) for n in modelled_numbers)
        full = record["modelled"] == "all"
        for counter in (totals, per_file[record["file"]]):
            counter["functions"] += 1
            counter["full" if full else "partial"] += 1
            counter["lines"] += len(body)
            counter["code"] += code
            counter["modelled"] += modelled
            counter["statements"] += statements
            counter["modelled_full" if full else "modelled_partial"] += modelled
            counter["code_partial"] += 0 if full else code
        print(f"| `{record['file']}:{first}-{last}` {record['function']} | "
              f"{len(body)} | {code} | {modelled} | {statements} | "
              f"{'full' if full else 'partial'} | {record['model']} |")
    print("\n| File | functions (full/partial) | code lines in those "
          "functions | modelled code lines | modelled statement lines | "
          "file size (lines) |")
    print("|---|---|---|---|---|---|")
    for name, counter in per_file.items():
        size = len(cache[os.path.join(source, name)])
        print(f"| {name} | {counter['functions']} ({counter['full']}/"
              f"{counter['partial']}) | {counter['code']} | "
              f"{counter['modelled']} | {counter['statements']} | {size} |")
    print(f"\nTotal: {totals['functions']} functions "
          f"({totals['full']} followed in full, {totals['partial']} in part); "
          f"{totals['lines']} physical / {totals['code']} code lines in them; "
          f"modelled code lines {totals['modelled']} "
          f"({totals['modelled_full']} in full functions, "
          f"{totals['modelled_partial']} of {totals['code_partial']} in "
          f"partial ones), of which {totals['statements']} are not just "
          "braces or `else`.")


if __name__ == "__main__":
    main()
