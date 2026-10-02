#!/usr/bin/env python3
"""Statistics about the differential tests, the C++ tests, and the build.

  - regenerates the differential corpus with formal/differential/
    generate_cases.py (deterministic, about two seconds) into a temporary
    directory and counts records per tag, by kind of case, by ledger version,
    and ERR rows;
  - counts the non-vacuity mutants run.sh applies (one perturbed result per
    tag, plus one rotated error code per tag that has ERR rows);
  - counts the committed golden subset;
  - counts the lines of the harness files;
  - diffs src/ against BASE (the commit this branch starts from) for the C++
    test additions;
  - reads the elapsed and CPU time of the last OfferExchange build from the
    Isabelle build log database, if one exists.

Case kinds are classified by keywords in the case id (see KINDS); case ids
are not uniformly structured, so this split is approximate.

Usage: test_stats.py [BASE]   (default BASE: a9d72b0ca); run from the
repository root.
"""

import collections
import glob
import lzma
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import zlib

KINDS = [  # first match wins
    ("random", r"random|biased"),
    ("exhaustive small-domain", r"small|exhaust|grid|sweep"),
    ("boundary", r"boundary|edge|max|min"),
]
HARNESS = [
    "formal/differential/generate_cases.py",
    "formal/differential/model_dispatch.ML",
    "formal/differential/run.sh",
    "formal/OfferExchange/Offer_Exchange_Test_Interface.thy",
    "formal/differential/golden/expected.tsv",
]


def kind(case_id):
    for name, pattern in KINDS:
        if re.search(pattern, case_id):
            return name
    return "named (hand-written)"


def read_corpus(path):
    schema, records, header = {}, [], []
    for line in open(path):
        fields = line.rstrip("\n").split("\t")
        if fields[0] == "#schema":
            schema[fields[1]] = (int(fields[2]), int(fields[3]))
        elif line.startswith("#"):
            header.append(line.strip())
        elif line.strip():
            records.append(fields)
    return schema, records, header


def corpus_stats():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "corpus.tsv")
        subprocess.run(["python3", "formal/differential/generate_cases.py",
                        path], check=True, stdout=subprocess.DEVNULL)
        _, records, header = read_corpus(path)
    print("## Differential corpus\n")
    print("Generator header: " + "; ".join(
        h.lstrip("# ") for h in header if "=" in h and "_count" not in h))
    by_tag = collections.defaultdict(collections.Counter)
    for fields in records:
        tag, case_id = fields[1], fields[2]
        counter = by_tag[tag]
        counter["records"] += 1
        counter[kind(case_id)] += 1
        version = re.search(r"_v(\d+)$", case_id)
        counter["v" + version.group(1) if version else "no version"] += 1
    kinds = [name for name, _ in KINDS] + ["named (hand-written)"]
    print("\n| tag | records | " + " | ".join(kinds) +
          " | v28 / v29 / unversioned |")
    print("|---|---|" + "---|" * len(kinds) + "---|")
    total = collections.Counter()
    for tag, counter in sorted(by_tag.items(), key=lambda x: -x[1]["records"]):
        total.update(counter)
        print(f"| {tag} | {counter['records']} | " +
              " | ".join(str(counter[k]) for k in kinds) +
              f" | {counter['v28']} / {counter['v29']} / "
              f"{counter['no version']} |")
    print(f"| **all ({len(by_tag)} tags)** | {total['records']} | " +
          " | ".join(str(total[k]) for k in kinds) +
          f" | {total['v28']} / {total['v29']} / "
          f"{total['no version']} |")
    print("\nLifecycle scenarios: " + ", ".join(
        f"{tag} {c['records']} records ({c['v28']} at v28, {c['v29']} at v29)"
        for tag, c in sorted(by_tag.items()) if "lifecycle" in tag) + ".")


def golden_stats():
    schema, records, _ = read_corpus("formal/differential/golden/expected.tsv")
    tags = collections.Counter(fields[1] for fields in records)
    err = collections.Counter(fields[1] for fields in records
                              if fields[schema[fields[1]][0] - 1] == "ERR")
    print(f"\nGolden subset (`formal/differential/golden/expected.tsv`): "
          f"{len(records)} records over {len(tags)} tags "
          f"({min(tags.values())}-{max(tags.values())} per tag), "
          f"{sum(err.values())} of them ERR rows.")
    # The corpus holds inputs only and the golden file is a subset, so which
    # tags get an error-code mutant is read from run.sh itself, which fixes
    # the tags without ERR rows and fails if the full run disagrees.
    run_sh = open("formal/differential/run.sh").read()
    without = re.search(r"tags_without_err_rows=\(([^)]*)\)", run_sh).group(1).split()
    with_err = len(tags) - len(without)
    print(f"\nNon-vacuity mutants in run.sh: {len(tags)} perturbed results "
          f"(one per tag) + {with_err} rotated error codes (one per tag that "
          f"produces ERR rows) = {len(tags) + with_err}.  Tags without ERR "
          f"rows (from run.sh): {', '.join(without)}.")


def harness_stats():
    print("\n## Harness and test code\n")
    print("| file | lines |")
    print("|---|---|")
    for path in HARNESS:
        print(f"| {path} | {sum(1 for _ in open(path))} |")


def cxx_test_stats(base):
    print(f"\n## C++ changes relative to {base}\n")
    stat = subprocess.run(["git", "diff", "--numstat", base, "HEAD", "--",
                           "src"], check=True, capture_output=True,
                          text=True).stdout
    print("| file | added | removed |")
    print("|---|---|---|")
    for line in stat.splitlines():
        added, removed, path = line.split("\t")
        print(f"| {path} | {added} | {removed} |")
    diff = subprocess.run(["git", "diff", base, "HEAD", "--",
                           "src/transactions/test/ExchangeTests.cpp"],
                          check=True, capture_output=True, text=True).stdout
    cases = re.findall(r'^\+TEST_CASE\("((?:[^"]|"\s*\n\+\s*")*)"', diff, re.M)
    print("\nNew `TEST_CASE`s in ExchangeTests.cpp:\n")
    for case in cases:
        print(f"- {re.sub(r'\"\s*\n\+\s*\"', '', case)}")


def build_stats():
    print("\n## Last recorded Isabelle build of the session\n")
    logs = glob.glob(os.path.expanduser(
        "~/.isabelle/*/heaps/*/log/OfferExchange.db"))
    if not logs:
        print("No build log database found under ~/.isabelle.")
        return
    path = max(logs, key=os.path.getmtime)
    row = sqlite3.connect(path).execute(
        "select session_timing from isabelle_session_info").fetchone()
    blob = row[0] if row else b""
    for decode in (lambda b: b, zlib.decompress, lzma.decompress):
        try:
            text = decode(blob).decode("utf8", "replace")
            break
        except Exception:
            text = ""
    timing = dict(re.findall(r"(threads|elapsed|cpu|gc)=([\d.]+)", text))
    print(f"From `{path}` (modified "
          f"{subprocess.run(['date', '-r', path, '+%F %T'], capture_output=True, text=True).stdout.strip()}): "
          f"elapsed {timing.get('elapsed', '?')} s, CPU {timing.get('cpu', '?')} s, "
          f"GC {timing.get('gc', '?')} s, {timing.get('threads', '?')} threads. "
          "This is whatever build ran last on this machine; rerun "
          "`isabelle build -c -D formal/OfferExchange` for a fresh figure.")


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "a9d72b0ca"
    corpus_stats()
    golden_stats()
    harness_stats()
    cxx_test_stats(base)
    build_stats()


if __name__ == "__main__":
    main()
