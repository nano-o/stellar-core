# Verification statistics

Size and coverage figures for the Isabelle/HOL model of the offer exchange,
collected for a talk. Every number here comes from `generated.md`, which the
scripts in this directory regenerate. The figures below are for commit
`e54c31586`.

| File | What it is |
|---|---|
| `collect.sh` | Runs the three scripts and writes `generated.md`. |
| `theory_stats.py` | Line, definition and theorem statistics for `formal/OfferExchange/*.thy`. |
| `coverage.tsv` | The hand-made table of which C++ lines the model follows. |
| `cxx_coverage.py` | Checks `coverage.tsv` against `src/` and counts the lines. |
| `test_stats.py` | Differential corpus, golden file, harness, C++ test diff, build time. |
| `generated.md` | Output of the above. Do not edit by hand. |

To regenerate (a few seconds, no Isabelle needed):

```bash
formal/docs/stats/collect.sh          # writes formal/docs/stats/generated.md
git diff formal/docs/stats/generated.md
```

## Headline numbers

**C++ covered.** The code-level model follows **668 lines of C++ code**
(non-blank, non-comment) in **39 functions**: 30 in full (422 lines) and 9 in
part (246 of their 682 lines). They come from seven files: `numeric.cpp`,
`ProtocolVersion.cpp`, `OfferExchange.cpp`, `TransactionUtils.cpp`,
`ManageOfferOpFrameBase.cpp`, and the ManageSell/ManageBuy frames. The
largest uncovered part is `ManageOfferOpFrameBase::doApply`: 55 of its 275
code lines are modelled (only the new-offer path that does not cross).

**Isabelle.** There are 25,485 lines in 9 theories (24,414 non-blank):

| Kind | Lines |
|---|---|
| Proofs | 13,676 |
| Theorem statements | 4,822 |
| Prose (`text` and `section` blocks, comments) | 3,094 |
| Definitions | 2,737 |

The session has **397 theorems** and no `sorry`. Of these, 42 are concrete
checks proved by `by eval` alone. The median proof is 12 lines, the mean 34,
and the longest 446. 88 proofs are one-liners and 33 run to 100 lines or
more. There are about 2,490 Isar steps. Proof methods: `simp` 1,580,
`linarith` 175, `auto` 162, `cases` 133, `blast` 118, `meson` 19, `metis` 5,
and no `smt`.

**Definition lines by layer:**

| Layer | Lines |
|---|---|
| Code-level model, one definition per C++ function (59 `C++:` tags) | 749 |
| Code-level plumbing (word types, `cxx_result` monad, records, protocol options) | 176 |
| Integer characterizations | 250 |
| Property predicates (the intended properties, as definitions) | 328 |
| Abstract specification (`Offer_Exchange_Specification.thy`) | 307 |
| Ideal real-valued exchange | 83 |
| Scenarios and witnesses | 129 |
| Exported test interface | 406 |
| Repeated in `Offer_Exchange_Posting_Refinement.thy` | 178 |

**Ratios.**
- About 20 proof lines per modelled C++ line (13,676 / 668).
- About 38 theory lines per modelled C++ line (25,485 / 668).
- The code-level definitions are about the same size as the C++ they follow
  (749 / 668 ≈ 1.1), as expected of a statement-by-statement model.

**Differential testing.**
- **667,238 records over 19 tags**. By kind, split approximately on case-id
  keywords:
  - about 415k exhaustive small-domain cases;
  - about 221k random;
  - about 30k boundary;
  - 679 hand-written.
- The ledger-versioned tags run at protocols 28 and 29 equally (212,789
  records each).
- The two lifecycle tags have 422 records each: 211 scenarios at each
  protocol.
- 35 non-vacuity mutants. That is one perturbed result per tag (19), plus one
  rotated error code per tag that produces ERR rows (16).
- The golden subset has 760 records (40 per tag).
- The harness is `generate_cases.py` (2,474 lines), `model_dispatch.ML`
  (660), `run.sh` (365) and the test-interface theory (482).

**C++ tests.** `ExchangeTests.cpp` gains 1,992 lines: five regression
`TEST_CASE`s plus the differential driver. `OfferExchange.cpp/.h` gain 32
lines, all test-only entry points under `BUILD_TESTS`.

**Build.** The last recorded `OfferExchange` build on this machine took
27 s elapsed and 136 s CPU on 8 threads. That figure is read from the
Isabelle log database; it was not re-measured.

## How the numbers are computed

### Theory lines (`theory_stats.py`)

Each line is given the category of the top-level command it belongs to:

- **statement**: a `lemma`/`theorem`/`corollary` up to its first proof
  command (`proof`, `by`, `apply`, `using`, `unfolding`, ...).
- **proof**: from there to the next top-level command.
- **definition**: `definition`, `fun`, `datatype`, `record`,
  `export_code`, ... (the list is `DEF_COMMANDS`).
- **text**: `text`/`section` blocks wherever they occur, including the
  proof-sketch `text` blocks between a statement and its proof. `(* *)`
  comments are counted with text.

Two simplifications:
- A one-line `lemma ... by m` counts as statement.
- A theorem's `proof` lines run to the next top-level command, so trailing
  `qed` lines are included.

To check the classification on any theory, run

```bash
python3 formal/docs/stats/theory_stats.py --dump formal/OfferExchange/Offer_Exchange_Lifecycle.thy | less
```

which prints every line with its category.

**Judgement call: definition layers.** A definition with a `C++:` comment is
code-level model. The other definitions are assigned by name, using the sets
`CODE_LEVEL_PLUMBING`, `INTEGER_CHARACTERIZATION`, `IDEAL_REAL` and
`SCENARIO` at the top of the script. Any definition outside those sets, the
specification theory and the test interface falls into "property
predicates". The definitions copied into `Offer_Exchange_Posting_Refinement.thy`
are reported separately as "(repeated)" so they are not counted twice.

### C++ coverage (`coverage.tsv`, `cxx_coverage.py`)

`coverage.tsv` has one row per C++ function the model follows. Each row
gives:
- the line where the function's name starts;
- `all`, or the line ranges the model follows;
- the Isabelle definitions involved;
- for partial rows, a note on what is left out.

`cxx_coverage.py` checks each row against the source and fails if a function
no longer starts where the table says, or a range falls outside the function.
It finds each body by brace matching and counts code lines (non-blank, not
`//`) over the whole function and over the modelled ranges.

**Judgement call: the ranges.** They come from reading each C++ function next
to its model definition. The script cannot check this part. What is left out
is mostly the same few things:
- loading ledger entries;
- native-asset (XLM) branches, since `party_state` models trustlines only;
- trustline authorization checks;
- sponsorship and reserves;
- for `doApply`, everything except a new offer that does not cross (the
  order-book loop `convertWithOffersAndPools`, modifying and deleting
  offers, offer IDs and results).

Signature lines and braces are counted inside the ranges.
`TrustLineWrapper::addBalance` only dispatches, so it is represented by the
`addBalance` and `addBalanceSkipAuthorization` rows it reaches. The ledger
`adjustOffer` overload is counted as full because `cross_offer_v10` writes its
steps out at both call sites.

### Tests and build (`test_stats.py`)

- **Corpus.** The script regenerates the corpus with `generate_cases.py`
  into a temporary directory (it is deterministic, with seed 1592639710) and
  counts records per tag.
- **Case kinds.** These are keyword matches on the case id (`KINDS` in the
  script). Case ids are not uniformly structured, so treat the kind split as
  approximate. The per-tag totals are exact.
- **Mutants.** The count follows `run.sh`: one perturbed result per tag, plus
  one rotated error code per tag. The exceptions are the tags listed in
  `run.sh`'s `tags_without_err_rows`, which produce no ERR rows.
- **C++ diff.** It is taken against `a9d72b0ca`, the commit this branch
  starts from (pass another base to `collect.sh` if that changes).
- **Build time.** It is read from `~/.isabelle/*/heaps/*/log/OfferExchange.db`.

## Caveats

- **Line counts are a proxy for effort.** Isabelle style puts one `have` on
  several lines, and the proofs here carry long explicit statements.
- **The C++ figure depends on the hand-made ranges** in `coverage.tsv`.
  Moving a range by a line or two changes the total by a few lines, not by
  tens.
- **Not all `C++:` tags are distinct functions.** The 59 tags count
  definitions. Several definitions follow the same function:
  - collapsed and layered forms of `bigDivideOrThrow`;
  - `_at_version` variants;
  - the copies in `Posting_Refinement`.
- **The build time is a single cached measurement.**
- **Three corrections to the first draft of these figures**, which were given
  in conversation before the scripts existed:
  - the mutant count is 35, not 38;
  - 42 theorems are proved by `by eval` alone; the 93 figure counts every
    `eval` occurrence, not theorems;
  - the C++ estimate rose from about 620 to 668 lines once every range was
    listed.
- **`formal/RESULTS.md` overstates the mutants slightly.** It says "for every
  tag, a perturbed result and a rotated error code must both be rejected".
  Three tags (`big_multiply_unsigned` and the two lifecycle tags) have no ERR
  rows, so they get only the perturbed-result mutant. That file is not
  changed here.

## Review checklist

1. Run `formal/docs/stats/collect.sh`. Check that it succeeds and that
   `git diff formal/docs/stats/generated.md` is empty at the commit above.
2. Check that every number under "Headline numbers" appears in
   `generated.md`. The ratios and the "≈" figures are derived from it.
3. Spot-check the line classifier with `--dump` on two theories. Look at
   statements followed by `text` blocks, one-line `by` lemmas, and long
   `proof ... qed` blocks.
4. For a sample of `coverage.tsv` rows, open the C++ ranges next to the named
   Isabelle definition:
   - every `all` row should be followed in full;
   - partial ranges should match what the definition does;
   - the lines left out should be ones the note names.
   The rows with the most judgement in them are `crossOfferV10`, `doApply` and
   `computeOfferExchangeParameters`.
5. Check the layer sets in `theory_stats.py` against the definitions they
   name. The `C++:` tag rule should agree with `formal/AGENTS.md`: there,
   integer characterizations are theorems *about* the model, not part of it.
