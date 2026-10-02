---
name: isabelle-proving
description: Editing Isabelle theories and developing proofs with this tooling — the two workflows (Isabelle/IQ in the main jEdit worktree, or a native ic2 server in a dedicated Git worktree), the check-locates / REPL-iterates loop, the command timeout, prover-death recovery, and the Isar and I/R pitfalls that cost agents hours. Use whenever a task touches a .thy file, a proof, a sorry, or an Isabelle error.
---

# Proving with Isabelle through this tooling

Two workflows exist, and the invoker chooses one; never mix them in one
worktree.

- **Isabelle/IQ in the main worktree.** A human has jEdit open on the theory.
  Agents read and edit theory buffers only through the I/Q MCP server (`iq`)
  and iterate in its I/R REPL. Never write a theory file on disk there: jEdit
  owns the buffers and a disk write desynchronizes them.
- **ic2 in a dedicated worktree.** No jEdit owns the files, so theories are
  edited directly on disk and checked through a native ic2 server that the
  worktree owns. This is the workflow for autonomous proof work and for the
  `ic2-prover` worker.

Plans and instructions must describe theory editing as "Isabelle/IQ in the
main worktree, or ic2 in a dedicated worktree, as chosen by the invoker", not
hard-code one.

## ic2: one server per worktree

Everything goes through the tooling clone's entry point, run from inside the
checkout so it resolves that checkout's descriptor and derives that
worktree's own server name:

```bash
cd <worktree>
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" start --cpus 8       # already running is success
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" server status
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" check <Session>/<Theory>.thy --command-timeout 15
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" wait --interval 15 --timeout 900
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" query diagnostics <Session>/<Theory>.thy --json
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" query sorry <Session>/<Theory>.thy --json
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" repl-create /abs/path/<Theory>.thy:LINE rLINE
"$ISABELLE_TOOLING_ROOT/scripts/ic2.sh" stop
```

- The server starts from the descriptor's `ic2_base_session` (`HOL`), never
  from the project session: as the logic, project theories would be heap
  nodes with no per-command diagnostics or `sorry` positions after edits.
- `check` returns at submission; poll with `wait`, never with the interactive
  `check attach`. `wait` exits nonzero on `failed`, `idle`, timeout, or a
  detected prover death.
- A check aborts as a whole when one command exceeds `--command-timeout`
  seconds (default 5). This is the "no proof method may run longer than a few
  seconds" rule, enforced server-side; `check status` names the culprit with
  `file:line`. Raise the limit for a check that legitimately needs it rather
  than disabling it.
- Do not re-check after every tactic edit: a check costs a client JVM, one
  more per status poll, and re-execution of everything from the edit to the
  end of the theory, and answers with a verdict, not a goal. `check` locates
  a failure and confirms a finished proof; iterate in between in an I/R REPL
  forked at the failing command. `check status` prints the exact
  `repl-create` command for a located failure; copy it. A watchdog culprit is
  not forkable (it was cancelled mid-evaluation); fix that one from the
  source.
- After a check, inspect both `query diagnostics --json` and `query sorry
  --json`. An `ok` with a remaining `sorry` is not a proof.
- Prover death: `server status` reports `state=failed` with a prover-died
  reason and an in-flight check settles as `failed reason=prover_died` (the
  descriptor's `ic2_max_heap` bounds the prover in a cgroup, so a runaway
  proof is killed rather than the host). Recover with `stop` then `start`.
  `health` shows the server's memory and CPU.
- The ic2 check validates proofs, not the session document. Final validation
  is `isabelle build -D <formal root>` on the host.

## Isabelle/IQ and the I/R REPL

- The `iq` server authenticates by itself, including after jEdit restarts:
  never read or print the I/Q token. A call failing with "I/Q did not accept
  the token" means jEdit was not started with the tooling's
  `scripts/launch_jedit.sh`; tell the human.
- I/Q may be a deferred MCP tool: search the tool registry for `list_files`
  under the `iq` server before concluding it is absent. Do
  not use `ps`, `pgrep`, or `ss` as evidence that jEdit or I/Q is missing; the
  agent shell may run in isolated PID and network namespaces.
- In a shared session, agree who owns a passage before editing it; after an
  edit, wait for PIDE processing and report diagnostics before asking the
  human to continue.
- Theory files are written in UTF-8 with Isabelle symbols as ASCII escapes
  (`\<open>...\<close>`, `\<Rightarrow>`); a raw Unicode glyph in a file is a
  malformed command to the batch prover.
- When reporting Isabelle work to the user, render those escapes as the
  corresponding Unicode mathematics whenever practical.  Show raw Isabelle
  markup only when discussing source spelling or providing an exact snippet
  to paste; this presentation rule does not change how theory files are
  written.
- REPL: `repl_connect` first. `repl_init` can import only theories in the
  daemon's initial heap (`Main` with a `HOL` heap; not `HOL-Library.Word`).
  For project or library theories, open the project theory with `open_file`
  and `view = true`, wait until it is processed with no errors, then
  `repl_init_from_source` at a completed command after the declarations you
  need, and confirm with `repl_state`.
- `repl_init_from_source` positions the REPL *after* the matched command; to
  see the goal a failing `by` faces, match the command before it.
- Initializing from a theorem statement leaves the REPL in `proof (prove)`
  mode.  Start a structured proof with `proof -` or `proof (...)` before a
  `have`; a bare `have` in `prove` mode is an illegal proof command.
- A failed `repl_step` leaves the state unchanged; do not `repl_back` after
  it. One step may contain several Isar commands, accepted or rejected as a
  unit.
- Avoid literal semicolons inside one `repl_step` payload: the I/R transport
  can misread them as an SML `unclosed string literal`. Use `bind` forms or
  nested `let` instead of `do` blocks with `;`, or split into separate steps.
  The theory file may still use `do` notation.
- `repl_sledgehammer` returns only when every prover has finished or timed
  out; keep its timeout at 5 seconds.
- For a bounded Nitpick experiment, bound both layers: set the REPL step
  timeout with `repl_timeout` and give Nitpick its own shorter
  `nitpick [timeout = N]`.  Nitpick can spend time interrupting or cleaning up
  after its internal limit; a timeout is inconclusive, not evidence for the
  conjecture.
- `write_file` can finish the edited command range while dependent commands
  later in the theory are still processing.  Before reporting the edit as
  clean, wait for whole-document status and then inspect diagnostics and
  `sorry` positions.

## Proof discipline

- Before a proof, write a proof sketch in English as a comment right after
  the statement; before a definition or lemma, an English explanation.
- No proof method with complex facts or arguments you have guessed before
  trying sledgehammer: `by (metis <hand-picked>)`, `by (rule foo [OF bar, of
  ...])`, `by (simp add: <unconfirmed lemmas>)`. Reproduce the step in a REPL,
  run sledgehammer with a 5-second timeout, and write what it found. Plain
  `simp`, `auto`, `linarith`, `eval` without guessed arguments may be tried
  directly.
- A fact just proved in the current development, or located explicitly with
  `find_theorems`, is confirmed rather than guessed.  Apply a syntactically
  matching fact directly; do not run sledgehammer as a ritual when fact
  selection is already settled.
- Shape the goal before sledgehammer: one equation or inequality over a few
  terms. Unfold with `simp only: c_def Let_def`, split cases, and hammer the
  leaves; a goal still containing the characterized constant or an `if`/`let`
  tree will time out.
- Prefer `blast`, `metis`, `presburger`, or `simp` suggestions over `smt`; if
  only `smt` comes back, use its fact list as a hint and write a short Isar
  proof.
- A suggestion is relative to the chained facts; keep them in scope (`using`)
  when copying it into the theory. If the found proof uses a library lemma
  that already states the whole step, use it directly.
- If a claim resists proof, sledgehammer it in a REPL rather than guessing
  further; isolate an intermediate `have` and hammer that.
- A method running over about 3 seconds is a failure: remove it.
- Use `text ‹...›` blocks, not `(* ... *)`, for notes; in text, refer to terms
  with `@{term "..."}` and to facts with `@{thm [source] "..."}`; bare math
  symbols or underscored names outside antiquotations break the document.
  A text block before a declaration cannot use `@{const f}` for the constant
  it is about because `f` does not exist yet; use `@{text f}` there, and use
  `@{const f}` only after the declaration.
- Fix Isabelle warnings that take a one-line change; leave the rest.
- Before finishing: `isabelle build` the session, and check that proof
  sketches still describe the proofs.

## Stating and proving a property

- State a property over the code-level definitions or over a
  characterization already proved equal to them (`isabelle-modeling`); write
  the English sentence it stands for in a `text` block right before it.
- Before proof effort on a new user-facing property, run `quickcheck` and a
  bounded `nitpick` experiment in a REPL.  A counterexample means the property
  or its precondition is wrong; fix the statement, never the model.  Do not
  repeat both tools mechanically for every routine supporting lemma.
  Quickcheck is usually cheap; Nitpick is most useful on structurally small
  finite problems.  Merely having 64- or 128-bit word types does not make its
  search tractable, and refinement statements over unbounded integers are
  often poor Nitpick targets.  Use the two timeout layers described above,
  report an inconclusive timeout, and continue with proof development.
- Prove on the simplest equal form: unfold the definition with `simp only:
  f_def Let_def`, split on the result type and the branches, discharge the
  arithmetic leaves with `sledgehammer`; a word-level goal usually needs the
  no-wrap fact (`uint`/`sint` bounds and `unat`/`uint` arithmetic lemmas)
  stated as a `have` first.
- A finished property has no `sorry`, no `oracle`, no `axiomatization` under
  it, and the session builds without `quick_and_dirty`; `query sorry` under
  ic2 and the export check confirm this for the exported program.

## Isar pitfalls

- Do not name a fact with a reserved keyword such as `prop` or `term`, or use
  the outer keyword `value` as a variable name.
- Do not name a fact `sym`; it shadows HOL's theorem.
- Do not use `quotient` as a bound term variable; Isabelle can parse it as
  quotient syntax (shown as `(//)`) and report a misleading function-type
  error.
- Names introduced by `defines` must also occur in `fixes`, or Isabelle
  reports "Extra variables on rhs".
- On a lemma with several `shows`, `[OF ..., of ...]` instantiates every
  exported fact and can report "More instantiations than variables"; split
  the lemma or use `where`.
- `fork`'s last REPL argument is a state index (`0` base, `-1` latest), not a
  subgoal number; REPL names must be fresh (`remove` first).

## Delegating autonomous proof work

When asked to take ownership of a proof job, the coordinator creates the
branch and linked worktree (inside the session's allowed directories, or asks
the human to restart with `--add-dir`), inspects the main worktree first and
asks which committed state to use if relevant uncommitted changes make the
base ambiguous (never stash, copy, or discard them), and delegates to the
`ic2-prover` worker with an absolute worktree path, the exact proof target,
the edit scope, and commit authority. The coordinator does not edit the
delegated worktree concurrently, reviews the diff and validation report on
return, verifies the worker stopped its server, and reports worktree path,
branch, and commit. It never merges, cherry-picks, or removes the worktree or
branch unless asked. Worktrees no longer need a submodule populated: the
tooling and AutoCorrode live in the tooling clone. When the checkout uses
agent-board (`agent-board.conf` at its root; the `agent-coordination`
skill, whose `references/delegation.md` has the procedure), choose the
worker's mode and state it on the brief's first line, `Mode: independent.
Handle: HANDLE.` or `Mode: supervised by HANDLE.`; a brief without one makes
an independent worker. The proof resources on the board are theory files,
proof branches (`refs/heads/<branch>`) and `token:jedit`, the human's I/Q
editing session in the main worktree, which an agent claims before editing
through I/Q there.

- **Independent**, the usual mode for an autonomous proof job: the
  coordinator registers with `hello`, creates the branch and worktree, and
  releases any setup claim. The worker claims its branch and theories under
  its own handle, commits when the brief authorizes it, and posts its
  handoff before releasing its claims with `bye`. For an authorized
  integration, the coordinator claims the destination branch under its own
  handle and guards the affected paths and refs before moving it.
- **Supervised**: the coordinator claims the worker's theories and branch
  before launching it and keeps them until the worker has stopped. The
  worker makes no board calls, commits, or ref or index changes; the
  coordinator reviews its report and commits in its worktree as
  `AGENT_BOARD_AGENT=<coordinator> git -C <worktree> commit ...`. ic2's own
  start and stop notes are allowed in either mode.
