---
name: isabelle-differential
description: Differential-test an executable Isabelle code-level model against the implementation it models — choose the harness shape, build a corpus, run the model side through the tooling's model runner and a project dispatch ML, keep both sides honest with mutations and a golden file, and gate the run on the export check. Use when a project has an exported code-level model and needs evidence that the code it runs is the code it proved, or when asked to "add a differential test", "compare the model with the C++", or "check the export".
---

# Differential testing: a method, not a framework

The tooling ships one piece of code that is the same for every project, one
check, and this method. Everything that makes a differential test good — the
corpus, the validator, the mutation policy, the implementation adapter — is
project code that you write for the project in front of you, by copying the
worked example below and applying the rules. The relationship between a
project's harness and the tooling is copy, not depend.

## What the tooling provides

**The model runner**, `"$ISABELLE_TOOLING_ROOT/scripts/model-runner.sh"`,
owns what every project gets subtly wrong on its own: building the session,
exporting the code named by the descriptor's `export_name`, loading it into
`isabelle ML_process` together with the project's `model_dispatch` file,
line framing, failure handling, and keeping input and output rows aligned.

```bash
"$ISABELLE_TOOLING_ROOT/scripts/model-runner.sh" batch corpus.tsv model.tsv
"$ISABELLE_TOOLING_ROOT/scripts/model-runner.sh" resident   # one record per stdin line
```

Records are opaque to the runner. Each non-comment input line is handed to
`Model_Dispatch.dispatch : string -> string`, and the output line is the
input line, a tab, and the returned suffix. Blank and `#` lines are echoed
in batch mode; resident mode answers a blank line with `#`, because the
ML_process wrapper drops empty output lines. A `Model_Dispatch.Reject` is a
malformed record; batch mode aborts on it without installing an output file,
resident mode answers `#reject<TAB>LINE<TAB>MESSAGE` (and `#error…` for a
crash) after printing `#ready`. The descriptor needs `export_name` (as `isabelle export -l` lists
it) and `model_dispatch` (relative to the formal root).

**The export check**, `"$ISABELLE_TOOLING_ROOT/scripts/export-check.sh"`,
answers whether the executable model is the proved one. For every code
equation of every constant in the exported program and every fact in the
project's audit collection (`named_theorems export_audit` by default, named
by `audit_collection`), it requires no oracle in the derivation — a `sorry`
is the `skip_proof` oracle — and no dependency on an axiom declared by a
project theory unless that axiom is a definition, a typedef, or HOL's
contentless `type`-class arity. Axioms of the Isabelle distribution and
imported libraries are the trusted baseline. It also scans project sources
for `code_printing`, `code_module`, and `code_reserved` declarations that
touch a symbol of the exported program; only an explicit `--allow SYMBOL`
accepts one. Add the theorems that connect the exported definitions to what
was proved about them to the audit collection with the `[export_audit]`
attribute; declare the collection in a theory every branch imports. The
check builds the session with a heap image (`isabelle build -b`), so its
first run rebuilds once. It cannot vouch for the code generator, Poly/ML,
or the dispatch ML: those are trusted, and the last is reviewed by reading.
Run it before every differential run; a passing differential test against
an unchecked export tests a different artifact than the proofs are about.

## The dispatch ML converts and routes; it never decides

`model_dispatch.ML` is trusted semantic code. It parses a record's fields
into the exported types, checks ranges against the declared type of each
parameter, calls the exported function for the tag, and formats the result.
Lexical and representation arithmetic is allowed and expected: decimal text
to a word and back, field splitting, range checks. Domain arithmetic is not,
and neither is branching on values beyond selecting the tag's function and
reporting a parse or range failure. If a case distinction in the dispatch
mirrors one in the model, the dispatch has become a second model. A
reviewer reads the file alongside the theory's exported signatures; make
that reading short.

## Choose the harness shape by project type

- **Pure function over scalars** (the worked example): batch records, both
  sides produce result files, compare. Recommended record convention:
  `v1 <tag> <case_id> <inputs...>` in, `OK <fields...>` or `ERR <code>` out,
  one `#schema` line per tag giving the status and first result columns. The
  error code is a project-defined enumeration (`ASSERTION`, `OVERFLOW`,
  `RUNTIME` in the example), because *which* failure fires, and in what
  order, is part of the specification.
- **Stateful component:** replay a generated trace on both sides and compare
  the observable state after every step, not only at the end. Sequences come
  from a fixed seed and are committed like any corpus.
- **Parser or decoder:** byte inputs; compare accept/reject and a canonical
  re-serialization of the parsed value. This is where coverage-guided
  fuzzing pays most.

## Choose corpus sources, in tiers

1. A property-based library (Hypothesis in Python, or its equivalent) for
   boundary-biased integers, composable records, fixed seeds, and shrinking.
   Build on it rather than hand-writing biased random.
2. Hand-designed domain values: saturation points, signed extrema, the pairs
   that make a 128-bit intermediate overflow. No library supplies these; the
   example's `generate_cases.py` is essentially all of this, and its depth is
   the depth of the test.
3. Coverage-guided fuzzing (libFuzzer or AFL++ for C and C++, `cargo-fuzz`,
   Go's fuzzing, Jazzer, Atheris) as an offline campaign whose minimized
   corpus is decoded into records and committed. Guidance comes from the
   *implementation's* coverage only — Isabelle exports SML, OCaml, Haskell,
   or Scala, never something you can link into the C process. Coverage
   saturates fast on pure arithmetic, where bugs are value bugs;
   comparison-operand tracking (libFuzzer's value profile) reaches past that.

What is honestly not generic is the corpus, and therefore the depth of the
test. Say so in the project's README rather than shipping a generator that
produces a plausible-looking but shallow corpus.

## Keep the producer discipline

- Both sides produce results; neither compares internally.
- Fail closed on a missing, reordered, duplicated, or extra row, on a
  partial write, and on a harness crash mapped to a modeled result. The
  runner does this for the model side; the harness does it across records
  (duplicate case ids, schema prelude) and for the implementation side.
- Validate domain well-formedness and coverage — arity, ranges, allowed
  error codes, required branch coverage — separately from comparison, and
  never let the validator recompute the modeled function: that creates a
  second oracle and makes the mutation test circular.
- For every observed tag and status, mutate exactly one result field and
  confirm the comparison rejects it. Rotate an error code to another valid
  code rather than corrupting it, so the rejection comes from the comparison
  and not from a parse failure. A tag with no mutation is a failure, not a
  skipped check; fix the set of tags that legitimately have no `ERR` rows so
  a corpus that loses its failure coverage fails loudly.
- Commit a golden result file (a per-tag prefix is enough) as the
  no-Isabelle regression backstop, and update it only after every mutation
  has been rejected.
- Optional, project code: a shrinker that delta-debugs a disagreeing
  record's fields against the resident runner and the implementation
  adapter. Only the project knows which field reductions keep a record valid.

## Report direction carefully

Mechanically the model produces the expected values and the implementation
is checked against them, which is why the golden file is model output.
Semantically the relationship is the reverse: the implementation is the
deployed ground truth and the code-level model is the artifact on trial, so
a disagreement usually means the model is wrong. Report a disagreement by
naming both sides' values without asserting which erred. Avoid the word
"oracle" for either side; it conflates the two facts.

## Worked example: stellar-core's offer exchange

The reference harness is `formal/differential/` in the offer-exchange
project, with the Catch2 case `[isabelle-offer-exchange]` in
`src/transactions/test/ExchangeTests.cpp`:

- `generate_cases.py` — the corpus: hand-designed extrema per tag plus
  seeded random, 666,816 records over 19 tags, with a `#schema`-free input
  and unique `case_id`s.
- `model_dispatch.ML` — the dispatch: one `process_<tag>` per exported
  function, `parse_decimal`, `require_range` against the C++ widths,
  `error_name` for the three failure codes, a `dispatch` that pattern-matches
  the record arity and routes. Read it against
  `Offer_Exchange_Test_Interface.thy` to see the converts-and-routes rule
  applied.
- `run.sh` — the harness: duplicate-id check, the runner call, the
  `#schema` prelude, two 211-row lifecycle coverage checks, the C++
  comparison, one `OK` mutation and one `ERR` mutation per tag, the golden
  update gate.
- `isabelle-tooling.conf` — `export_name`, `model_dispatch`,
  `audit_collection`; `named_theorems export_audit` is declared in the
  arithmetic theory and the layered-equivalence and posting-refinement
  theorems carry `[export_audit]`.

It does not yet follow every rule above, and you should not copy the
deviation: **the Catch2 case reads the model's result file and compares
internally instead of producing its own result file.** The producer
refactor of the C++ evaluator is a deliberate, unpaid cost; a new harness
must have both sides produce.

## Order of work for a new project

1. Export check first: descriptor keys, the audit collection, a passing
   `export-check.sh`. Fix the theories, never the check.
2. Dispatch ML for one tag; `model-runner.sh resident` to try records by
   hand; then the corpus generator for that tag with its extrema.
3. Implementation adapter that *produces* a result file from the same
   corpus. Comparator, structural checks, per-tag `OK` and `ERR` mutations.
4. Widen tag by tag. Commit the golden file last.
