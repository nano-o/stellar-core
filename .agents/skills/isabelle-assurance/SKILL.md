---
name: isabelle-assurance
description: State what a project's Isabelle work actually establishes about the code — the two questions (does the model represent the code; can claims about the model be trusted), which evidence answers which, the export link between them, the named assumptions, and the routes investigated and rejected. Use when asked "what does this prove about the code", to write or review an assurance section, to summarize the trust chain for a reviewer or auditor, or before claiming that a proved property holds of the implementation.
---

# What the work establishes, and on what it rests

"Can we trust what we say about the code?" splits into two questions that
are easy to conflate and are answered by different evidence. Every assurance
statement this tooling produces keeps them apart, names the link between
them, and lists the remainder that is assumed rather than checked. A claim of
the form "property P holds of the implementation" is never made without all
three parts.

## Question 1: does the code-level model represent the code?

Evidence, in the order a reader applies it:

- **Side-by-side review.** The code-level model is bit-precise and
  syntactically and structurally as close to the code as possible (the
  `isabelle-modeling` skill states the standard and the review procedure), so
  a reader with both open confirms the correspondence function by function.
  This is the first check, not an afterthought, and it is the only check that
  catches a model which is input-output correct on every test and still not
  the code, as a folded divide definition once was. Record who reviewed which
  functions against which source revision.
- **Differential testing.** The exported model and the real implementation
  are run over a designed corpus and their results compared, with a
  non-vacuity mutation per tag and status proving the comparison can fail
  (the `isabelle-differential` skill). Strong evidence about the inputs
  sampled and nothing about the rest; say how the corpus was built and how
  deep it is. The comparison runs the *exported* code, which is why the
  export link below matters.
- **The named remainder.** The model gives the source's fixed-width
  operations the meaning of HOL word operations. That is correct under the
  language standard only where the code has no undefined behaviour, and only
  if the compiler is correct; neither is checked mechanically here.
  Undefined behaviour is therefore outside the fidelity domain, not a
  modelled result: each definition's definedness precondition says which
  inputs are covered, and the corpus running clean under the sanitizer
  (UBSan for C and C++) is the cheap evidence that the code stays inside that
  domain. If the build does not wire the sanitizer in, say so; it is the
  cheapest missing item.

## Question 2: can our claims about the code-level model be trusted?

- **The proofs are complete and assumption-free.** The session builds
  without `quick_and_dirty`, so no `sorry` survives; the theories declare no
  `axiomatization` and no `oracle`. The export check verifies this for the
  code equations of the exported program and for the audit collection; for
  everything else `isabelle build` plus a `grep` for `sorry`,
  `axiomatization`, and `oracle` over the project theories is the check.
  After that Isabelle's kernel is the guarantee; this is ordinary Isabelle
  practice.
- **What is trusted beyond the kernel.** Evaluating the model runs code
  outside the logic: Isabelle's code generator and its representation of
  integers and strings, the Poly/ML runtime, the tooling's runner I/O loop,
  and the project's `model_dispatch.ML`. The first two are trusted components
  by Isabelle's own account. The last two are **trusted semantic code by
  decision**: small, mechanical, reviewed by reading against the exported
  signatures (the converts-and-routes rule), and exercised by every record of
  the corpus. Name them as trusted; do not describe them as verified.
- **The stated properties mean what we think.** An abstract specification
  and the refinement proof connecting the code-level model to it, `by eval`
  examples, and integer characterizations of the word-level definitions all
  answer this. They are proved claims *about* the code-level model relating
  it to simpler models; they are not evidence for Question 1.
- **`quickcheck` and `nitpick` before proving.** They find counterexamples
  to a stated property before effort is spent on a proof. They save time;
  they add no trust, and an assurance statement does not cite them.

## The link between the two questions

Differential testing runs the exported code; the proofs are about the HOL
definitions. Those are the same artifact only if the export is generated
from proved code equations rather than from `code_printing` shims that hide
a constant behind hand-written target code, and only through the trusted
components named above. If the link is broken, Question 1's evidence is
about one thing and Question 2's proofs about another, and nothing connects
them. The export check (`"$ISABELLE_TOOLING_ROOT/scripts/export-check.sh"`)
guards the part of the link that can be checked mechanically: no oracle and
no unjustified project axiom under any exported code equation or audited
fact, and no `code_printing`, `code_module`, or `code_reserved` touching a
symbol of the exported program except by explicit allowlist. Run it before
every differential run and cite its output in the statement. The dispatch ML
is the named, unchecked remainder of the link.

## The chain

If Question 1 holds, and Question 2 holds, and the link holds, then a
property proved of the code-level model holds of the code, under the
remainder's assumptions: the input is inside the definedness domain; the
compiler is correct; and the code generator, Poly/ML, the runner, and the
dispatch ML behave. Neither question alone gets there. A failure of
Question 1 is invisible to everything under Question 2, which is why the
side-by-side review is listed first.

## Routes investigated and rejected

An assurance statement says what was *not* done and why, so a reader does
not assume it was overlooked. Two routes have been measured and set aside
for fixed-width arithmetic of this kind; cite them rather than re-running
the investigation:

- **Bounded model checking or SMT equivalence of the source against the
  model** (SeaHorn, CBMC, and the like). Every query about wide arithmetic
  bottoms out in an SMT problem over 128-bit bitvectors with symbolic
  multiplication composed with symbolic division, which becomes unsolvable
  between roughly 15 and 18 bits of value width against an exponential
  curve; the production code needs 64 or 128. The universal guarantee stays
  in the Isabelle proofs. The satisfiable direction is cheap and remains a
  good corpus generator for the differential harness: a solver finds the
  input that makes a particular branch or overflow fire.
- **Compiling to WebAssembly and proving correspondence against its
  mechanized semantics.** Not blocked by the SMT wall, since Isabelle is not
  an SMT solver, but blocked by missing infrastructure; it verifies a build
  other than the one deployed, cannot represent the exception behaviour the
  corpus records, and breaks on every recompilation.

Two cheap items were recommended instead and belong in any statement's
"open items" when missing: running the corpus under UBSan, and deepening the
corpus where the model is least covered (stateful traces rather than pure
arithmetic).

## Writing the statement

Put an `## Assurance` section in the project's formal `README.md` (or a
`docs/assurance.md` it links) with exactly these parts, each a short
paragraph or a grouped list, never a wide table:

1. **Scope.** Source files and functions modelled, source revision, session
   name, Isabelle release, tooling revision from the descriptor.
2. **Question 1 evidence.** The reviewed correspondence (who, when, which
   functions); the differential run (corpus size and construction, tags,
   mutation result, golden file); the sanitizer status; the definedness
   preconditions.
3. **Question 2 evidence.** Build without `quick_and_dirty`; the export
   check's output line; the properties proved, each named with its theorem
   and stated in one English sentence; what each property is about (the
   code-level definitions, or a characterization proved equal to them).
4. **The link.** Export check passed; dispatch ML reviewed; the trusted
   components listed.
5. **Assumptions.** Definedness domain; compiler; code generator, Poly/ML,
   runner, dispatch ML; anything project-specific (an opaque callee, a
   library treated as correct).
6. **Rejected routes and open items.** The two routes above with one
   sentence each; what remains to do.

State facts and their evidence; never write "verified" for a trusted
component, "proved" for a tested claim, or "the code is correct" for "these
properties hold of the model under these assumptions". Report a differential
disagreement by naming both sides' values without asserting which erred.
