In this project we are building an Isabelle/HOL model of the stellar-core
offer-exchange lifecycle: the `exchangeV10` arithmetic and, on top of it,
posting an offer and then crossing it, with each party's balances, trustline
limits, and liabilities as explicit parameters. The goal is to state the
properties the exchange should have and prove or refute them.
`formal/RESULTS.md` summarizes what is modeled, proved and open.

Two kinds of model live in the session, and the rules below keep them apart.
The **code-level model** is the executable model of the C++ (the arithmetic,
adjustment, layered-divide, lifecycle, stored-offer, and migration
theories). The
**specification** is `Offer_Exchange_Specification.thy`: an abstract model
written for maximum simplicity that deliberately does not follow the C++,
need not be executable, and is connected to the code-level model by the
refinement proofs in `Offer_Exchange_Posting_Refinement.thy`. Keep the
specification declarative; do not reshape it toward the C++. Integer
characterizations and other simplified restatements are theorems *about* the
code-level model, not part of it.

The generic standard for the code-level model — bit-precise, and
syntactically and structurally as close to the C++ as possible; one
definition per source function; simplifications as lemmas, never
definitions; the reviewer's procedure — is the tooling's `isabelle-modeling`
skill. Read it before writing or reviewing a definition. This project's
answers to that skill's conventions interview, settled with the user, are the
review checklist below.

## Conventions

- **Source in scope:** `src/transactions/OfferExchange.cpp|.h` (exchange
  arithmetic, offer adjustment, crossing), the posting path in
  `src/transactions/ManageOfferOpFrameBase.cpp`, the liability helpers in
  `src/transactions/TransactionUtils.cpp`, and the wide arithmetic helpers of
  `src/util/numeric.cpp`. Ledger access is modelled as explicit parameters
  (balances, trustline limits, liabilities).
- **Detected failures:** the `cxx_result` monad of
  `Offer_Exchange_Arithmetic.thy` with the status enumeration
  `Cxx_Assertion_Failed`, `Cxx_Overflow`, `Cxx_Runtime_Error` (assertions,
  detected overflow, `throw std::runtime_error`), `cxx_bind` overloaded onto
  `do` notation, failures raised in the order the C++ checks them.
- **Out-parameters and unassigned values:** an out-parameter plus Boolean
  return is a pair; where the C++ leaves the out-parameter unassigned the
  model returns zero and the definition's `text` block says so
  (`big_divide_layered` is the reference).
- **Casts and promotions:** `int64` and `uint64` are `64 word`, `uint128` is
  `128 word`, `int32` is `32 word`; every cast and promotion is written out;
  a same-width signed-to-unsigned cast is the identity on bits and is
  recorded in the text because its reading changes from `sint` to `uint`;
  the unsigned comparison with a promoted `INT64_MAX` is written as
  `uint r2 ≤ int64_max_int`.
- **Unreachable defensive checks:** modelled as written.
- **Undefined behaviour:** excluded by a definedness precondition, never
  modelled as a status; the differential corpus under UBSan is the evidence
  the C++ stays inside it (UBSan is not yet wired into `configure.ac`).
- **Naming:** `camelCase` C++ names become `snake_case`
  (`bigDivideOrThrow` to `big_divide_or_throw`), argument order kept; every
  definition carries `― ‹C++: ‹bigDivideUnsigned› (‹util/numeric.cpp›)›`.
- **Project history the reviewer should know:** `big_divide_or_throw` in
  `Offer_Exchange_Arithmetic.thy` folds `bigDivideUnsigned`, `bigDivide`, and
  `bigDivideOrThrow` into one definition on unbounded integers. It is kept as
  the proved integer characterization of the layered definitions in
  `Offer_Exchange_Divide_Layered.thy`, which is the corrected shape; new
  code follows the layered theory, and the export goes through
  `Offer_Exchange_Test_Interface.thy`.

When a new region of C++ needs a convention this list does not cover (a new
kind of side effect, a container, a defensive check the C++ can never reach),
ask the user before choosing, then record the answer here.

The arithmetic layer is complete:
`formal/OfferExchange/Offer_Exchange_Arithmetic.thy` proves the contracts of
the public `exchange_v10` (characterizations, cap and sign bounds, the
`wheatStays` condition, zero results, strict-send positivity, and the
one-percent price-error bound). The lifecycle layer is
`formal/OfferExchange/Offer_Exchange_Lifecycle.thy`; its intended properties
are stated in its "Intended properties" subsection, and their status at
protocols 28 and 29 is in `formal/RESULTS.md`.

The code we are modeling is at `src/transactions/OfferExchange.cpp|.h`
(exchange arithmetic, offer adjustment, crossing), with the posting path in
`src/transactions/ManageOfferOpFrameBase.cpp` and the liability helpers in
`src/transactions/TransactionUtils.cpp`. Read
`formal/docs/offer-lifecycle.md` for a survey of the offer lifecycle, the
property catalog (P1-P10), and the known reservation failure the model
reproduces; it is the background needed to understand the lifecycle theory.

## Isabelle tooling and workflow

This checkout is bound to the Isabelle formal-modeling tooling by the
committed descriptor `isabelle-tooling.conf` at the repository root; the
tooling clone is at `$ISABELLE_TOOLING_ROOT`, and the generic Isabelle skills
are committed under `.agents/skills/`: `isabelle-setup`, `isabelle-modeling`,
`isabelle-proving`, `isabelle-differential`, and `isabelle-assurance`. Everything generic — the two
theory-editing workflows (Isabelle/IQ in the main jEdit worktree, or a native
ic2 server in a dedicated Git worktree, as chosen by the invoker), the
check-locates / REPL-iterates loop, the command timeout, prover-death
recovery, the I/Q and I/R rules, the proof discipline, the Isar pitfalls, and
the delegation protocol for the `ic2-prover` worker — lives in
`isabelle-proving`, not here. Read that skill before touching a theory.

What is specific to this project:

- The session is `OfferExchange` in `formal/OfferExchange`; the descriptor
  names it, so `"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh"` run from anywhere
  inside a checkout drives that checkout's own server, for example
  `ic2.sh check OfferExchange/Offer_Exchange_Lifecycle.thy --command-timeout 15`.
  Final validation is `isabelle build -D formal/OfferExchange` on the host,
  which also builds the document.
- `Timed_Methods.thy` wraps `auto`, `simp`, `simp_all`, `blast`, and `metis`
  with a two-second default limit (`declare [[timed_methods_timeout = 5.0]]`
  or `using [[...]]` raises it locally). Import it into theories where new
  proofs are being developed under Isabelle/IQ, and remove the import once
  they are done; importing it into established theories spuriously times out
  legitimate proofs, and a `simp_all: timeout` warning in a pre-existing proof
  is wrapper noise. Under ic2 prefer the server-side `--command-timeout`
  instead, which needs no import.
- When checking whether a proof is complete, check both for errors and for
  commands still processing.
- Setup and health: `"$ISABELLE_TOOLING_ROOT/bin/isabelle-tooling" doctor`
  from inside the checkout. It must be green before interactive work.
- Differential testing: `formal/differential/run.sh` (needs
  `ISABELLE_TOOLING_ROOT`) drives the tooling's model runner over the corpus
  from `generate_cases.py` and compares with the C++; the record semantics
  live in `formal/differential/model_dispatch.ML`, which converts and routes
  and never decides. Before changing the exported model or its code
  equations, run `"$ISABELLE_TOOLING_ROOT/scripts/export-check.sh"`; add
  theorems that connect exported definitions to what was proved to the
  `export_audit` collection. The method is the `isabelle-differential` skill.
- Worktrees need no submodule population: AutoCorrode lives in the tooling
  clone.

# C++ guidelines

- Configure and compile with sccache enabled.
- Compile with 8 worker threads at most.
