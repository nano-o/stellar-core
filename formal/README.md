# Formal model of `exchangeV10`

A bit-precise Isabelle/HOL model of
[`src/transactions/OfferExchange.cpp`](../src/transactions/OfferExchange.cpp)
and the offer lifecycle around it, together with the differential harness
that checks the model against the real C++ implementation built from this
same checkout. For what is modeled, what is proved, and what is still open,
start with [RESULTS.md](RESULTS.md).

- `OfferExchange/`: the Isabelle session, with the model, its proofs, and
  the executable test interface.
- `differential/`: the harness that compares the extracted model with
  stellar-core.
- `differential/golden/`: the committed expected-result subset, checked by
  ordinary test runs.
- `docs/`: notes on the modeled code, and `offer-exchange-theories.pdf`,
  the typeset theories.
- `RESULTS.md`: the summary of results.
- `AGENTS.md`: project-specific instructions for agents (`CLAUDE.md` is a
  symlink to it). The generic Isabelle rules come from the tooling's skills.

Nothing here is part of the stellar-core build. `formal/` is deliberately kept
out of `Makefile.am`; `differential/run.sh` is the entry point instead of a
root `make` target.

## Setting up Isabelle

This work is developed against **Isabelle2025-2**. Isabelle theories are not
portable across releases, so use that version rather than whatever is current;
a different release will generally fail to build these theories.

Isabelle/jEdit is included in every Isabelle distribution. Do not install a
separate jEdit package: installing Isabelle2025-2 supplies both the `isabelle`
command and the jEdit application used below.

Download it from <https://isabelle.in.tum.de> (mirrors:
<https://mirror.cse.unsw.edu.au/pub/isabelle>,
<https://mirror.clarkson.edu/isabelle>). The site publishes bundles for Linux,
macOS, and Windows; on x86-64 Linux:

```bash
curl -LO https://isabelle.in.tum.de/dist/Isabelle2025-2_linux.tar.gz
tar -xzf Isabelle2025-2_linux.tar.gz -C "$HOME"
```

`differential/run.sh` and the tooling invoke `isabelle` unqualified, so put it on `PATH` —
either add `$HOME/Isabelle2025-2/bin` to `PATH`, or symlink the launcher:

```bash
ln -s "$HOME/Isabelle2025-2/bin/isabelle" ~/.local/bin/isabelle
isabelle version    # expect: Isabelle2025-2
```

No Archive of Formal Proofs entry is needed. The session builds on `HOL` and
imports only theories that ship with the distribution (`HOL-Library.Word` and
`HOL-Library.Monad_Syntax` among them), and the prebuilt `HOL` heap the
harness passes to `isabelle ML_process` comes with it too — there is nothing
to bootstrap.

A LaTeX installation *is* required, because the session's `ROOT` sets
`document = pdf` and Isabelle bundles no TeX of its own. Install TeX Live
(Debian/Ubuntu: `texlive-latex-extra texlive-fonts-recommended`), or skip
document preparation when you only want the proofs checked:

```bash
isabelle build -o document_variants= -D formal/OfferExchange
```

Confirm the setup before running anything else:

```bash
isabelle build -D formal/OfferExchange
```

That builds the model, checks every proof, and writes
`OfferExchange/output/document.pdf`. It takes well under a minute on a warm
`HOL` heap.

## Setting up the Isabelle tooling

Building the session and running the differential harness need only
Isabelle and the tooling's model runner. Interactive and agent-driven work
uses the rest of the tooling. The Isabelle formal-modeling tooling is a
separate clone, kept outside every project checkout:
<https://github.com/nano-o/isabelle-formal-modeling-tooling>. Clone it with
its submodule, check out its `stable` branch, and set
`ISABELLE_TOOLING_ROOT` to its path. Then follow its README's "Setting up
the tooling clone": the I/R environment, the ic2 component, the I/Q jEdit
plugin (installed while jEdit is closed), and the I/Q token.

This checkout is bound to the tooling by the committed descriptor
`isabelle-tooling.conf` at the repository root. The descriptor names the
session, the ic2 base logic, the prover memory bound, the Isabelle release,
the exported model, and the tooling revision these artifacts were validated
against. The tooling also installed project files, which are committed too:
- the five Isabelle skills under `.agents/skills/` (Claude Code sees them
  through `.claude/skills/`);
- the `ic2-prover` worker profiles in `.claude/agents/` and `.codex/agents/`;
- the `iq` MCP server in `.mcp.json` and `.codex/config.toml`;
- a block in the root `AGENTS.md`.

`"$ISABELLE_TOOLING_ROOT/bin/isabelle-tooling" sync --check` compares them
with the pinned revision. Nothing in them names a machine path.

From anywhere inside this checkout:

```bash
"$ISABELLE_TOOLING_ROOT/bin/isabelle-tooling" doctor
```

Doctor checks the following and prints remediation commands without
running them:
- Isabelle;
- the tooling clone and its pinned AutoCorrode against the descriptor's
  `tooling_revision`;
- the project files;
- the single ic2 component registration;
- the I/Q plugin and token;
- the I/R environment.

An agent started in this checkout can also walk through the remaining setup
with the `isabelle-setup` skill.

Several agents can work in this repository at once and coordinate through
[agent-board](https://github.com/nano-o/agent-board), which this checkout
opts into with `agent-board.conf` and the files under `.agent-board/` and
`.agents/skills/agent-coordination/`. It is optional for a single human or
agent.

### Headless checking with ic2

Each Git worktree gets its own native ic2 server, named from the checkout
path and bounded by the descriptor's `ic2_max_heap`. Use it from a dedicated
worktree, never from the worktree a human has open in jEdit:

```bash
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" start --cpus 8
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" server status
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" check OfferExchange/Offer_Exchange_Arithmetic.thy --command-timeout 15
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" wait --timeout 900
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" query diagnostics OfferExchange/Offer_Exchange_Arithmetic.thy --json
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" repl-create "$PWD/formal/OfferExchange/Offer_Exchange_Arithmetic.thy:87" r87
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" stop
```

`git worktree add` is enough; nothing needs populating. The server checks
proofs, not the document: the final validation stays

```bash
isabelle build -D formal/OfferExchange
```

### Delegating an autonomous ic2 proof

Ask a coordinating agent to create a dedicated worktree and branch from a
chosen base, and to delegate the proof to the project's `ic2-prover` worker
(`ic2_prover` under Codex CLI). The worker's profile withholds I/Q, so it
cannot attach to the main worktree's jEdit. The protocol is in the
`isabelle-proving` skill: base selection, worktree placement inside the
session's allowed directories, the handoff contract, and what the
coordinator may and may not do on return. A prompt such as:

> Create a dedicated worktree and branch from `HEAD` and delegate lemma
> `NAME` in `formal/OfferExchange/FILE.thy` to the ic2 proof worker. Use ic2
> only; do not modify the main worktree or use its I/Q. Do not weaken the
> statement. Check every changed theory, inspect diagnostics and sorry
> positions, stop the server, commit on the worktree branch, and report the
> worktree path, branch, commit, diff summary, and validation results.

### Interactive human-and-agent exploration

The human and the agent share one live Isabelle/PIDE document in jEdit. jEdit
owns the theory buffers, and agents reach them only through the project's
`iq` MCP server. Launch jEdit from the tooling clone, from a terminal inside
the graphical session:

```bash
"$ISABELLE_TOOLING_ROOT/scripts/launch_jedit.sh" \
  --project formal --session OfferExchange \
  --venv "$ISABELLE_TOOLING_ROOT/.venv" \
  OfferExchange/Offer_Exchange_Lifecycle.thy
```

`-R` semantics apply: the session's requirements come from a prebuilt image
while the project theories stay editable; the first run builds that image.
Wait for the theory to finish processing and for **Plugins -> I/Q** to
appear, then start the agent host in this checkout. The launcher and the
`iq` server read the same token file, so agents never handle the token.
Agree who owns a passage before either party edits it. Agent edits appear in
the buffer and are auto-saved by I/Q, so inspect both the buffer and
`git diff`.

While working in jEdit:
- the *Output* panel shows the proof state at the cursor;
- *Query* runs `find_theorems`;
- *Sledgehammer* runs the automated provers;
- hovering a constant shows its type, and ctrl-click jumps to its
  definition.

`Timed_Methods.thy` wraps the common automation with a two-second default
limit (`declare [[timed_methods_timeout = 5.0]]` raises it). A warning such
as `auto: timeout` means the wrapper hit its limit, not that the step is
invalid.

## Protocol versions in the harness

The differential records carry a `ledger_version` field rather than exact-cap
flags. `exchange_v10`, `exchange_v10_without_price_error_thresholds`,
`adjust_offer`, `offer_selling_liabilities` and `offer_buying_liabilities` are
generated at ledger versions 28 and 29, so each pair exercises the legacy and
the repaired arithmetic against the same inputs. The `offer_amount_from_value`
tag compares the model with `calculateOfferAmountFromValue`, reached through
test-only shims compiled under `BUILD_TESTS`.

The overlay-admission filter (`offerCanClearForZero`, reached through
`ManageOfferOpFrameBase::doCheckValidForOverlay`) is not modeled, so neither
the corpus nor the modeled lifecycle has an overlay stage.

Lifecycle records carry a `ledger_version` too, and every lifecycle case is
generated at protocols 28 and 29, one row after the other. The C++ oracle
runs one long-lived application per protocol and applies each row's
transactions in the ledger its `ledger_version` names; it rejects a
lifecycle row at any other version loudly. Each row still starts and ends
within one protocol: crossing a protocol-28 offer at protocol 29 is covered
by the migration theorems, not by the corpus.

## Running the differential test

The full run generates the corpus, evaluates the exported model over it
through the Isabelle tooling's model runner, builds `stellar-core`, and
compares the two:

```
ISABELLE_TOOLING_ROOT=/path/to/isabelle-formal-modeling-tooling formal/differential/run.sh
```

The model side is split along the line the tooling draws.  The runner
(`$ISABELLE_TOOLING_ROOT/scripts/model-runner.sh`) owns the session build,
the export named by `export_name` in `isabelle-tooling.conf`, the
`isabelle ML_process` invocation, line framing, and row alignment.  This
repository owns the meaning of a record: `differential/model_dispatch.ML`,
named by `model_dispatch` in the descriptor, parses each record's fields,
checks them against their C++ ranges, calls the exported function for the
tag, and formats the result.  It converts and routes and never decides;
review it against the exported signatures in
`Offer_Exchange_Test_Interface.thy`.  Cross-record structure — unique
`case_id`s and the `#schema` prelude — stays in `run.sh`.

After the comparison, `run.sh` runs two non-vacuity checks per record tag.
It perturbs one `OK` result field and confirms the C++ comparison rejects
it. For every tag that produces `ERR` rows, it also rotates one error code
to another valid code and confirms that is rejected too. Which failure fires
is therefore part of the comparison, and a silently inert comparison cannot
masquerade as a pass. The three tags with no `ERR` rows
(`big_multiply_unsigned` and the two lifecycle tags) are fixed in the
script, so a corpus that loses its failure coverage fails rather than
skipping.

The default corpus has 667,238 records across 19 tags. Each of its two
stateful lifecycle dimensions contains 422 isolated records, 211 at each of
protocols 28 and 29. For the sell and the buy dimension at each protocol,
the script separately requires an ordinary posting rejection, a created
offer, an admissible limit change, and a positive crossing.

Before a run, check that the exported model is the proved one:

```
"$ISABELLE_TOOLING_ROOT/scripts/export-check.sh"
```

It audits every code equation of the exported program for oracles and for
project axioms that are not definitions or typedefs. It does the same for
every fact under `export_audit`, which is declared in
`Offer_Exchange_Arithmetic.thy`; the layered equivalence theorems and the
posting refinement carry that attribute. It also scans the theories for
`code_printing` overrides of exported symbols. It builds the session with a
heap image, so its first run rebuilds once.

If you already have a test-enabled binary, skip the rebuild:

```
STELLAR_CORE_BIN="$PWD/src/stellar-core" formal/differential/run.sh
```

Requires Isabelle set up as above, the tooling clone named by
`ISABELLE_TOOLING_ROOT`, plus `python3` and `rg` on `PATH`, and a
stellar-core configured with tests enabled (i.e. not `--disable-tests`).

`ISABELLE_OFFER_EXCHANGE_BUILD_OPTIONS` passes extra options to the
`isabelle build` step, for example `-o quick_and_dirty` while a theory of the
session that the exported model does not depend on still carries a `sorry`.

## The golden corpus

`differential/golden/expected.tsv` holds the first 40 records per tag from a
full run. The C++ test defaults to it when
`ISABELLE_OFFER_EXCHANGE_EXPECTED` is unset, so `stellar-core test
'[isabelle-offer-exchange]'` exercises the model's expectations with no
Isabelle installation present. That is what stops an unrelated refactor of
`OfferExchange.cpp` from silently drifting away from the verified model.

Regenerate it after any intended change to the model, from the repository root:

```
UPDATE_GOLDEN=1 formal/differential/run.sh
```

The golden file is only written after the full-corpus comparison passes, so a
committed golden is always one that both sides agreed on.

## Record format

The corpus and expected-result files are TSV, one record per line:

```
v1 <tag> <case_id> <input fields…>                       # corpus
v1 <tag> <case_id> <input fields…> OK <result fields…>   # expected, success
v1 <tag> <case_id> <input fields…> ERR <failure>         # expected, failure
```

`failure` is the C++ failure name (`ASSERTION`, `OVERFLOW`, `RUNTIME`).
Lines beginning with `#` are comments and are skipped by every consumer.

The maker-independent liability records share this input shape:

```
v1 <tag> <case_id> <price_n> <price_d> <ledger_version> <amount>
```

Here `tag` is `offer_selling_liabilities` or `offer_buying_liabilities`, and
the result is a signed decimal amount. The default corpus gives both tags
identical inputs at both ledger versions. The inputs include the complete
amount range through 101 for small prices, signed extrema, saturation
boundaries, and 10,000 deterministic biased-random cases.

The stateful lifecycle records have ten inputs after the `case_id`:

```
v1 offer_lifecycle_sell <case_id> <price_n> <price_d> <ledger_version>
   <amount> <maker_sell_balance> <maker_sell_liabilities>
   <maker_buy_limit> <maker_buy_balance> <maker_buy_liabilities>
   <new_buy_limit>
v1 offer_lifecycle_buy <case_id> <price_n> <price_d> <ledger_version>
   <buy_amount> <maker_sell_balance> <maker_sell_liabilities>
   <maker_buy_limit> <maker_buy_balance> <maker_buy_liabilities>
   <new_buy_limit>
```

Each expected row has exactly 41 fields: the 13 input fields, `OK`, and 27
values, in this order:
- stage;
- post created;
- canonical price numerator and denominator;
- posted amount;
- maker after posting;
- limit change accepted;
- resulting buy limit and capacity;
- crossing succeeded;
- wheat received;
- sheep sent;
- remaining maker offer;
- final maker;
- final taker.

Every party group uses one fixed order: `sell_balance`, `sell_liabilities`,
`buy_limit`, `buy_balance`, `buy_liabilities`.

The stable stage enum:
- `1` malformed post;
- `2` line full;
- `3` underfunded;
- `4` no offer;
- `5` invalid limit change;
- `6`/`7`/`8` posting assertion, overflow, or runtime error;
- `9`/`10`/`11` crossing assertion, overflow, or runtime error;
- `12` successful crossing.

Stage `0`, which once meant overlay rejection, is retired.

The C++ oracle works in a real application at the row's protocol, one for
protocol 28 and one for protocol 29:
- it creates reachable, isolated accounts and auxiliary offers;
- it posts the sell or buy offer;
- it applies `ChangeTrust`;
- it crosses with an exact-receive `ManageBuyOffer`.

The counterrequest uses the maker's canonical raw price. The buy operation
inverts it to the reciprocal resting price and buys the exact posted wheat
amount. The oracle asserts that the counterrequest is fully consumed, with
no residual taker offer or liabilities.

The wide-arithmetic helper records cover each C++ function in
`util/numeric.cpp` separately, matching the function-by-function model in
`Offer_Exchange_Divide_Layered.thy`:

- `big_multiply` and `big_multiply_unsigned` take `<a> <b>` and return the
  128-bit product; the signed one reports `ASSERTION` for a negative operand.
- `big_divide` and `big_divide_128` are the throwing wrappers
  `bigDivideOrThrow` and `bigDivideOrThrow128`. They return the quotient, or
  `ASSERTION` or `OVERFLOW`.
- `big_divide_nothrow`, `big_divide_unsigned`, `big_divide_128_nothrow`, and
  `big_divide_unsigned_128` are the Boolean helpers `bigDivide`,
  `bigDivideUnsigned`, `bigDivide128`, and `bigDivideUnsigned128`. Their
  result fields are the flag (`0` or `1`) and then the out-parameter. Because
  the C++ leaves the out-parameter unassigned on some failure paths, both
  sides transport zero when the flag is `0`, except for `bigDivideUnsigned`,
  which assigns it on every path past its assertion and is compared unmasked.

`run.sh` emits a `#schema <tag> <status-column> <first-value-column>` line
before the first record of each tag, derived from the record's own arity.
Consumers that need to locate the result columns read it instead of
hardcoding column numbers; the non-vacuity mutation step in `run.sh` is
currently the only such consumer. Adding an input field to a record
therefore cannot silently misdirect them.
