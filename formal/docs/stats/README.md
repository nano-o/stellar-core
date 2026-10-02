# Verification statistics

Size and coverage figures for the Isabelle/HOL model of the offer exchange,
collected for a talk. Every number here comes from `generated.md`, which the
scripts in this directory regenerate. The figures below are for the theories,
C++ and differential harness as of commit `bd5d2d01f`, the commit named in the
header of `generated.md`.

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

**C++ covered.** The code-level model follows **790 lines of C++ code**
(non-blank, non-comment) in **53 functions**: 38 in full (461 lines) and 15 in
part (329 of their 838 lines). 270 of the 790 are lone braces or `else`; the
other 520 are signatures, conditions and statements. They come from eight
files: `numeric.cpp`, `ProtocolVersion.cpp`, `types.cpp`, `OfferExchange.cpp`,
`TransactionUtils.cpp`, `ManageOfferOpFrameBase.cpp`, and the
ManageSell/ManageBuy frames. The largest uncovered part is
`ManageOfferOpFrameBase::doApply`: 53 of its 275 code lines are modelled
(only the new-offer path that does not cross).

**Isabelle.** There are 25,245 lines in 10 theories (24,172 non-blank):

| Kind | Lines |
|---|---|
| Proofs | 13,181 |
| Theorem statements | 3,999 |
| Prose (`text` and `section` blocks, comments) | 4,246 |
| Definitions | 2,657 |

The session has **395 theorems** and no `sorry`. (One unfinished theorem
sits inside a `(* *)` comment in `Offer_Exchange_Specification.thy`, lines
560–594. It is not part of the session, and its lines count as prose.) Of
the 395, 42 are concrete checks proved by `by eval` alone. The median proof
is 12 lines, the mean 33, and the longest 446. 94 proofs are one-liners and
29 run to 100 lines or more. There are about 2,810 Isar steps (`have` 2,014,
`show` 646, `obtain` 149). Counting the first method of each `by` or
`apply`: `simp` 1,564, `linarith` 175, `auto` 161, `cases` 128, `blast` 104,
`simp_all` 85, `meson` 19, `metis` 5, and no `smt`.

**Definition lines by layer** (comment lines excluded):

| Layer | Lines |
|---|---|
| Code-level model, one definition per C++ function (52 `C++:` tags) | 685 |
| Code-level plumbing (word types, `cxx_result` monad, records, protocol options) | 172 |
| Integer characterizations | 250 |
| Property predicates (the intended properties, as definitions) | 328 |
| Abstract specification (`Offer_Exchange_Specification.thy`) | 304 |
| Ideal real-valued exchange | 83 |
| Scenarios and witnesses | 129 |
| Exported test interface | 406 |
| Repeated in `Offer_Exchange_Posting_Refinement.thy` (7 more `C++:` tags) | 169 |

**Ratios.**
- About 17 proof lines per modelled C++ code line (13,181 / 790), or 25 per
  line that is not just a brace or `else` (13,181 / 520).
- About 32 theory lines per modelled C++ code line (25,245 / 790).
- The tagged definitions are 685 lines, against 790 lines of C++ code. About
  155 of the 685 are a second form of a function that already has one:
  - `big_divide_or_throw`, `big_divide_or_throw128` and `big_multiply`,
    beside the layered forms;
  - `offer_*_liabilities` and `manage_buy_*_liabilities`, beside their
    `_at_version` forms;
  - `preflight_offer` and `post_offer`, beside the `_core` forms;
  - `exchange_v10`, `exchange_v10_without_price_error_thresholds` and
    `adjust_offer`, beside their `_with_options` forms.

  Another 10 lines are tagged constants such as `int64_max`. The comparison
  is between line counts. It does not check that the model follows the C++
  statement by statement; that check is the review in step 4 of the
  checklist.

**Differential testing.**
- **667,238 records over 19 tags**. By kind, split approximately on case-id
  keywords:
  - about 415k exhaustive small-domain cases;
  - about 221k random;
  - about 30k boundary;
  - 679 other: hand-written cases, and generated cases whose ids carry none
    of the keywords.
- The ledger-versioned tags run at protocols 28 and 29 equally (212,789
  records each).
- The two lifecycle tags have 422 records each: 211 scenarios at each
  protocol.
- 35 non-vacuity mutants. That is one perturbed result per tag (19), plus one
  rotated error code per tag that produces ERR rows (16).
- The golden subset has 760 records (40 per tag).
- The harness is `generate_cases.py` (2,474 lines), `model_dispatch.ML`
  (660), `run.sh` (365) and the test-interface theory (482).

**C++ tests.** `ExchangeTests.cpp` gains 1,992 lines: five new `TEST_CASE`s
plus the differential driver. Two of the five are tagged `[exchange]` only,
and three are tagged `[exchangerandom]` as well. `OfferExchange.cpp/.h` gain
32 lines, all test-only entry points under `BUILD_TESTS`.

**Build.** The last recorded `OfferExchange` build on this machine took
26 s elapsed and 135 s CPU on 8 threads. That figure is read from the
Isabelle log database; it was not re-measured.

## How the numbers are computed

### Theory lines (`theory_stats.py`)

Each line is given the category of the top-level command it belongs to:

- **statement**: a `lemma`/`theorem`/`corollary` up to its first proof
  command (`proof`, `by`, `apply`, `using`, `unfolding`, ...).
- **proof**: from there to the next top-level command.
- **definition**: `definition`, `fun`, `datatype`, `record`,
  `export_code`, ... (the list is `DEF_COMMANDS`).
- **text**: `text`/`section` blocks wherever they occur. This includes the
  indented proof-sketch `text` blocks between a statement and its proof, and
  `txt` blocks inside proofs.
- **comment**: `(* *)` blocks, and lines that begin with `\<comment>`,
  wherever they occur. Inside a definition such a line still marks the
  definition as code-level if it carries the `C++:` tag. Definition lines
  therefore exclude comments, as the C++ code lines do. Comments are
  reported with text as "prose".

Two simplifications:
- A `lemma ... by m` on a single line would count as statement. The current
  theories have none.
- A theorem's `proof` lines run to the next top-level command, so trailing
  `qed` lines are included.

Proof methods and Isar steps are counted on statement and proof lines only,
with quoted terms and trailing `\<comment>`s removed:
- **Methods**: only the first method of each `by` or `apply`. The closing
  method of `by (induct x) simp_all` is not counted.
- **Isar steps**: every `have`, `show`, `obtain`, `thus` and `hence`
  keyword, wherever it stands on the line. So `then have` and
  `moreover from x have` both count.

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
- the line where the function's name starts, and the line of its closing
  brace;
- `all`, or the line ranges the model follows;
- the Isabelle definitions involved;
- for partial rows, a note on what is left out.

`cxx_coverage.py` checks each row against the source. It finds each body by
brace matching and fails if:
- a function no longer starts or ends where the table says (so an edit that
  changes a function's length is caught);
- a range falls outside the function.

It then counts two things, over the whole function and over the modelled
ranges:
- **code lines**: non-blank, not `//`, not `ZoneScoped`;
- **statement lines**: code lines that are not just braces or `else`.

**Judgement call: the ranges.** They come from reading each C++ function next
to its model definition. The script cannot check this part. What is left out
is mostly the same few things:
- loading ledger entries;
- native-asset (XLM) branches, since `party_state` models trustlines only;
- trustline authorization checks;
- `releaseAssertOrThrow` preconditions, and fast paths that no modelled
  caller reaches;
- sponsorship and reserves;
- for `doApply`, everything except a new offer that does not cross (the
  order-book loop `convertWithOffersAndPools`, modifying and deleting
  offers, the branch for an offer that does not stay, offer IDs and
  results).

Counting rules:
- **Signature lines and braces** are counted inside the ranges. A range that
  starts at the name line also takes a return type on the line before, as
  `all` does.
- **Pure dispatch is not counted.** `TrustLineWrapper` and its
  `NonIssuerImpl` only forward `addBalance`, `addBuyingLiabilities`,
  `addSellingLiabilities`, `getAvailableBalance` and `getMaxAmountReceive`.
  The `TransactionUtils.cpp` functions they reach are counted instead,
  including those functions' one-line `LedgerTxnEntry` overloads (the rows
  noted "wrapper").
- **Const copies are not counted.** `doApply` calls the
  `ConstTrustLineWrapper` copies of `canSellAtMost` and `canBuyAtMost`, and
  through them the `ConstLedgerTxnEntry` overloads of `getAvailableBalance`
  and `getMaxAmountReceive`. These are not counted a second time.
- **Liability getters have no definition.** `getBuyingLiabilities` and
  `getSellingLiabilities` correspond to the `buy_liabilities` and
  `sell_liabilities` fields of `party_state`.
- **One `all` row is restated.** `addBalanceSkipAuthorization` is restated as
  one headroom test per direction, not followed line by line: `party_state`
  has no selling liabilities on the bought asset and no limit on the sold
  one.
- **The ledger `adjustOffer` overload is counted as full**, because
  `cross_offer_v10` writes its steps out at both call sites.

### Tests and build (`test_stats.py`)

- **Corpus.** The script regenerates the corpus with `generate_cases.py`
  into a temporary directory (it is deterministic, with seed 1592639710) and
  counts records per tag.
- **Case kinds.** These are keyword matches on the case id (`KINDS` in the
  script). A case matching no keyword is "other". Case ids are not uniformly
  structured, so treat the kind split as approximate. The per-tag totals are
  exact.
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
- **A third of the modelled C++ lines are braces.** 270 of the 790 modelled
  code lines are lone braces or `else`. The statement-line figure (520) is
  the one to use where that matters.
- **Not all `C++:` tags are distinct functions.** The 52 tags (59 with the
  7 copies in `Posting_Refinement`) count definitions. Several definitions
  follow the same function:
  - collapsed and layered forms of `bigDivideOrThrow`;
  - `_at_version`, `_with_options` and `_core` variants.
- **The build time is a single cached measurement.**
- **The `eval` count is not a theorem count.** 42 theorems are proved by
  `by eval` alone, while `eval` is the first method 90 times.

## Review checklist

1. Run `formal/docs/stats/collect.sh`. Check that it succeeds and that
   `git diff formal/docs/stats/generated.md` is empty. The build line may
   differ, because it reads this machine's Isabelle log. The header names
   the last commit that touched the theories, the C++ or the harness. It
   adds "(with uncommitted changes)" when any of them is modified.
2. Check that every number under "Headline numbers" appears in
   `generated.md`. The ratios, the "about" figures and the 270 brace lines
   (790 − 520) are derived from it.
   The 155 lines of second forms are summed from the list of `C++:`-tagged
   definitions there.
3. Spot-check the line classifier with `--dump` on two theories. Look at:
   - statements followed by indented `text` blocks;
   - `\<comment>` lines inside definitions and statements;
   - long `proof ... qed` blocks.
4. For a sample of `coverage.tsv` rows, open the C++ ranges next to the named
   Isabelle definition:
   - every `all` row should be followed in full;
   - partial ranges should match what the definition does;
   - the lines left out should be ones the note names.
   The rows with the most judgement in them are `crossOfferV10`, `doApply`,
   `computeOfferExchangeParameters` and `doCheckValid`.
5. Check the layer sets in `theory_stats.py` against the definitions they
   name. The `C++:` tag rule should agree with `formal/AGENTS.md`: there,
   integer characterizations are theorems *about* the model, not part of it.
