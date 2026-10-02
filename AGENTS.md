This branch of stellar-core adds an Isabelle/HOL model of the offer exchange
under `formal/`, with proofs and differential tests against the C++; see
`formal/README.md` and `formal/RESULTS.md`. Also read `formal/AGENTS.md`.

<!-- BEGIN isabelle-tooling -->
<!-- Managed by isabelle-tooling; change it with `isabelle-tooling update`. -->
## Isabelle formal model

This repository has an Isabelle model under `formal/`; read
`formal/AGENTS.md` before working on it. The workflow is in the
`isabelle-setup`, `isabelle-modeling`, `isabelle-proving`,
`isabelle-differential` and `isabelle-assurance` skills. Start with
`isabelle-setup` until `"$ISABELLE_TOOLING_ROOT/bin/isabelle-tooling"
doctor` passes.
<!-- END isabelle-tooling -->

<!-- BEGIN agent-board -->
<!-- Managed by agent-board; change it with `agent-board update`. -->
## Coordination board

Several agents may work in this repository at once and coordinate
through `agent-board`. Unless your brief makes you a supervised worker,
read `.agents/skills/agent-coordination/SKILL.md` before your first task
here, and again after compaction or when resuming without it. Follow it
before changing shared files or refs and before delegating.

A supervised worker's brief says so and names its coordinator. It does
not use the board or the skill, stays within its assigned scope, and
makes no commits or ref or index changes; the coordinator coordinates.
<!-- END agent-board -->
