---
name: isabelle-modeling
description: Write the code-level Isabelle/HOL model of an implementation — bit-precise, and syntactically and structurally as close to the source as possible — starting with a short conventions interview whose answers are recorded in the project's AGENTS.md as the review checklist. Use when asked to "model this function in Isabelle", to add a source file or function to an existing model, or to review a code-level model for correspondence with the code.
---

# The code-level model

A project's Isabelle session holds up to two kinds of model, and this skill
is about the first. The **code-level model** is the executable model of the
source: one definition per source function, computing on words of the
source's widths, so that a reader with the source and the theory open side by
side can confirm the correspondence function by function and say "yes, that
is the same thing." A **specification**, if the project has one, is an
abstract model written for simplicity that need not follow the source and is
connected to the code-level model by refinement proofs; keep it declarative
and never reshape it toward the code.

Two facts drive everything below. Differential testing (the
`isabelle-differential` skill) compares outputs and proofs prove what is
stated; neither can tell a model that *is* the code from one that merely
agrees with it on every input. Closeness to the source is a review property,
checked by reading, and the standard the reviewer applies is the one written
here. The evidence is a real episode: a divide helper once folded three C++
functions into one definition over unbounded integers, had a proved
characterization, passed every differential case, and was still wrong by
this standard, because the reasoning that justified the collapse was nowhere
in the model.

## 1. Interview first, then record the answers

Several representation choices are the user's, not yours. Before writing the
first definition, ask these questions together, offer the defaults below with
their reasons, and then write the answers into the `## Conventions` block of
the project's `AGENTS.md` (the template from `isabelle-setup` already has the
headings). That block is the review checklist for every later definition, so
a later reviewer reads it before reading the theory. When you are not
speaking to a live user (a non-interactive run), still write the questions
and the defaults you took into the block, mark each answer `(default; not
yet confirmed)`, and say so in your report; do not skip the block.

- **Source in scope.** Which files and functions are modelled now, and which
  callees are treated as opaque or out of scope. Names of the source files
  and functions, verbatim.
- **Detected failures.** How failures the source itself detects (assertions,
  thrown exceptions, error returns, status codes) are represented. Default: a
  lightweight result type with a status enumeration and a bind operator,
  raised in source order, so that early exits stay in place and `do` notation
  keeps the source's control flow. Name the status constructors after the
  source's failure kinds, one per kind the source distinguishes.
- **Out-parameters and unassigned values.** How an out-parameter plus Boolean
  or status return is represented. Default: a pair, with zero (or the type's
  natural default) on paths where the source leaves the out-parameter
  unassigned, and a `text` block on each such definition saying so. An
  `option` is the alternative when a caller reads the value on such a path.
- **Casts and promotions.** Every explicit cast and every implicit promotion
  is written out. A same-width cast that is the identity on bits (signed to
  unsigned at equal width) is still recorded in the accompanying text,
  because its reading changes from `sint` to `uint`. Default annotation: the
  `― ‹C++: …›` comment on the definition plus a sentence in its `text` block.
- **Unreachable defensive checks.** How checks the source can never reach
  (a `default:` on an exhaustive switch, a null check on a reference, a
  range check that an earlier guard already implies) are treated. Default:
  modelled as written, with a lemma that they are unreachable; never
  silently dropped. Decide reachability by reading the arithmetic, not by
  taking the user's or your first impression: the fixture's final
  `INT64_MAX` guard looked live to everyone and is dead.
- **Undefined behaviour.** Excluded, never modelled as a result: the source
  has no value there to correspond to. Default: state a definedness
  precondition per definition that has one (signed overflow, shift width,
  division by zero) and treat the corpus running clean under the sanitizer
  (UBSan for C and C++) as the evidence the code stays inside it.
- **Naming.** The convention mapping source names to Isabelle names
  (`bigDivideOrThrow` to `big_divide_or_throw`), argument order kept, and
  what to do about a source name that is an Isabelle keyword.

Offer these as this tooling's defaults with their reasons, not as the only
answers. When a new region of the source needs a convention the block does
not cover (a new kind of side effect, a container, a loop), ask the user
before choosing, then record the answer in the block.

## 2. The standard: bit-precise, and structurally as close as possible

The code-level model has two halves and a definition fails if it misses
either.

**Bit-precise.** It computes on the source's fixed-width types with the
source's overflow, truncation, and rounding, so every value it produces is
the value the code produces. Concretely: `int64_t` and `uint64_t` are
`64 word`, `int32_t` is `32 word`, `unsigned __int128` is `128 word`;
signedness is a reading (`sint` or `uint`), not a type; widening follows
the source's conversion rule (in C, a signed source converts by value modulo
the target width, which is `scast`; `ucast` is right for an unsigned source,
and for a signed one only where a preceding check has established
non-negativity, which the text block then says); a mixed comparison follows the
source's promotion rule (`r2 <= INT64_MAX` between `uint64_t` and `int64_t`
is unsigned in C++, so the model compares `uint r2`).

**Structurally as close as possible.** A reader with both open confirms the
correspondence line by line:

- **One definition per source function**, with the same function boundaries
  and, up to the naming convention, the same name and argument order.
  Helpers the source keeps separate stay separate; a wrapper that only turns
  a false return into an exception is still its own definition. Never fold
  several source functions into one definition, however much simpler the
  result. The fold also happens in the other direction: a helper that
  returns a Boolean keeps a Boolean result, and the caller's line that turns
  that Boolean into *its* status stays in the caller. A helper that returns
  the caller's status has absorbed one of the caller's early exits.
- **The same control flow.** Branches in source order; early exits as status
  returns through the result type and `do` notation, not restructured
  conditionals; a `switch` as a `case`; the source's temporaries as `let`
  bindings with the source's names where they are legal.
- **Failures in source order.** Assertions and exceptions are status values
  raised in the order the source checks them, because *which* failure fires
  first is part of the specification, not an implementation detail.
- **Every cast written out**, as under the interview.
- **A comment on every definition** naming the source construct it mirrors,
  in the form `― ‹C++: ‹bigDivideUnsigned› (‹util/numeric.cpp›)›` (source
  language, function, file), and a `text` block before it explaining any
  place where the correspondence is not literal: an unassigned
  out-parameter, a same-width cast, a promoted comparison, a definedness
  precondition.  Because that block precedes the declaration, refer to the
  not-yet-declared Isabelle name with `@{text f}`, not `@{const f}`; the
  latter is valid only in text after the definition.
- **Simplifications are lemmas, never definitions.** Unbounded integers, a
  fused helper, a closed form, an integer characterization: each is a lemma
  proved *about* the code-level definitions. Proofs may live entirely on the
  simplified characterization; the model may not be it. When an existing
  folded definition has to be split, keep the folded constant as a
  characterization proved equal to the layered wrapper, so nothing
  downstream moves.
- **Extractable.** Executable definitions with code equations, exported
  through one test-interface theory (below), never through `code_printing`
  shims for project constants.

A definition that is bit-precise but not structurally close fails this
standard even if every test passes and every property is proved.

### The default result type

If the interview keeps the default, this is the shape (Isabelle symbols as
ASCII escapes on disk):

```isabelle
datatype cxx_error = Cxx_Assertion_Failed | Cxx_Overflow | Cxx_Runtime_Error

datatype 'a cxx_result = Cxx_Ok 'a | Cxx_Err cxx_error

fun cxx_bind :: "'a cxx_result \<Rightarrow> ('a \<Rightarrow> 'b cxx_result) \<Rightarrow> 'b cxx_result"
  where
    "cxx_bind (Cxx_Ok x) f = f x"
  | "cxx_bind (Cxx_Err e) f = Cxx_Err e"

adhoc_overloading Monad_Syntax.bind \<rightleftharpoons> cxx_bind
```

Rename the prefix after the source language or project (`c_result`,
`fee_status`) and the constructors after the failures the source actually
distinguishes. A source that returns a status enumeration rather than
throwing needs only the enumeration as the error type. Import
`"HOL-Library.Word"` for the word types and `"HOL-Library.Monad_Syntax"` for
`do` notation.

### Worked shape

The C++ `bigDivide` asserts on its operands, casts them to unsigned, calls
`bigDivideUnsigned`, and on success compares the result with `INT64_MAX`.
Its model keeps every one of those steps as its own line:

```isabelle
definition big_divide ::
    "int64 \<Rightarrow> int64 \<Rightarrow> int64 \<Rightarrow> cxx_rounding \<Rightarrow> (bool \<times> int64) cxx_result"
  \<comment> \<open>C++: \<open>bigDivide\<close> (\<open>util/numeric.cpp\<close>)\<close>
  where
    "big_divide A B C rounding =
      (if \<not> (0 \<le> sint A \<and> 0 \<le> sint B \<and> 0 < sint C)
       then Cxx_Err Cxx_Assertion_Failed
       else do {
         (res, r2) \<leftarrow> big_divide_unsigned A B C rounding;
         if res then Cxx_Ok (uint r2 \<le> int64_max_int, r2)
         else Cxx_Ok (False, 0)
       })"
```

The `text` block above it says: the `(uint64_t)` casts are the identity on
bits and switch the reading from `sint` to `uint`, legitimate because the
assertion just established non-negativity; the `INT64_MAX` comparison is
unsigned because C++ promotes the constant; on the false branch the C++
leaves the out-parameter unassigned and the model returns zero, which the
only caller never reads.

## 3. Order of work

1. Read the source region in scope and list its functions in call order,
   bottom up. Note each cast, promotion, assertion, exception, out-parameter,
   and any operation with undefined behaviour.
2. Hold the interview (§1); write the conventions block.
3. Declare the widths, the result type, and the constants the source uses
   (`INT64_MAX` as an abbreviation over `int` and as a word), each with its
   source comment.
4. One definition per function, bottom up, each with its comment and `text`
   block, followed by two or three `by eval` examples that pin a normal
   case, a boundary, and each failure in order. `value` in the REPL is the
   quickest check that the definition executes; a definition that does not
   is not extractable.
5. Only then simplifications: the integer characterization as a lemma, with
   the no-wrap argument that justifies reading word operations as integer
   operations.
6. The test-interface theory: one transport definition per exported function
   taking and returning `integer` (via `word_of_int (int_of_integer x)` and
   `integer_of_int (sint w)` or `uint w`), so the dispatch ML converts
   decimal text to `integer` and never touches word types; a single
   `export_code ... in SML module_name ... file_prefix ...` at the end. Then
   the `isabelle-differential` skill.
7. Properties: state them over the code-level definitions (or their proved
   characterizations), try `quickcheck` and `nitpick` first, then prove
   under the `isabelle-proving` skill.

Edit theories as `isabelle-proving` says: through Isabelle/IQ in the main
worktree or ic2 in a dedicated worktree, as chosen by the invoker; on disk,
Isabelle symbols are ASCII escapes.

## 4. Reviewing a code-level model

A reviewer reads the conventions block, then the source and the theory side
by side, and for each source function checks, in this order: a definition
exists with that boundary and name; the argument order and widths match; the
branches are in source order and every early exit is a status in the order
the source checks it; every cast and promotion is written or annotated; the
out-parameter convention is followed; the definition carries its source
comment; anything not literal is explained in a `text` block; no source
function is folded into another; no simplification lives in a definition.
Then the reviewer checks the exports: every exported constant is a transport
wrapper over a code-level definition, and the export check passes. Report
per function, naming the deviation, not per file.
