---
name: isabelle-setup
description: Set up and check the Isabelle formal-modeling tooling for a project checkout — the runtime tooling clone at the project's pin, the pinned Isabelle release, the one-time ic2/I/Q/token steps for the user to run, the project files that `isabelle-tooling init` installs, and doctor. Use when the user asks to "set up Isabelle for this project", to add formal modelling to a codebase, after changing the tooling pin, or when doctor fails.
---

# Setting up Isabelle for a project

The tooling reaches a project as committed files: this skill and the other
four under `.agents/skills/` (Claude Code sees them through
`.claude/skills/`), the `ic2-prover` worker profiles, the project's `iq` MCP
server in `.mcp.json` and `.codex/config.toml`, and a block in the root
`AGENTS.md`. `isabelle-tooling init` installed them before this session
started, pinned at the commit recorded as `tooling_revision` in
`isabelle-tooling.conf`. You never install or configure the agent host
itself. Every step below reads, runs a tooling command, or *shows* the user
a command that touches their home directory; run those only when the user
says so.

The entry point is `"$ISABELLE_TOOLING_ROOT/bin/isabelle-tooling"`, written
`isabelle-tooling` below.

## 1. The runtime tooling clone

`ISABELLE_TOOLING_ROOT` names the clone of `isabelle-formal-modeling-tooling`,
with its `AutoCorrode` submodule, at a path the user chose, never inside a
project checkout. The project's `iq` server and proof worker find the tooling
only through it.

```bash
test -x "$ISABELLE_TOOLING_ROOT/bin/isabelle-tooling" && echo ok
git -C "$ISABELLE_TOOLING_ROOT" rev-parse HEAD
```

If the variable is unset or wrong, stop and tell the user to set it in their
shell profile and restart the host session. The clone must be checked out,
clean, at the project's `tooling_revision`; one clone serves every project on
that pin, and a project on another pin fails doctor with the revision it
needs. Keep that clone at the `stable` branch and develop the tooling in a
separate worktree of it. If `AutoCorrode/ic2/etc/build.props` is missing,
the submodule is not populated: show
`git -C "$ISABELLE_TOOLING_ROOT" submodule update --init`.

## 2. Locate Isabelle

Order, fixed: `isabelle` on `PATH`, else the executable or installation named
by `ISABELLE_TOOLING_ISABELLE`. Its `isabelle version` must print the release
the descriptor names (Isabelle2025-2 unless the project says otherwise). If
none is found, **stop**: name the release and its download page,
<https://isabelle.in.tum.de>, and tell the user to unpack it where they like
and put its `bin/` on `PATH` or set `ISABELLE_TOOLING_ISABELLE`. Do not
download or install Isabelle; do not continue to later steps.

## 3. Build products inside the clone

This writes only inside the tooling clone:

```bash
"$ISABELLE_TOOLING_ROOT/scripts/setup-ir-venv.sh"   # .venv/ for the I/R bridge
```

## 4. The steps that touch the home directory (user runs them)

Show each with what it writes and how to undo it. Run one only when the user
says so.

- **Register the ic2 component and build its JAR.**
  `"$ISABELLE_TOOLING_ROOT/scripts/build-ic2.sh"` runs
  `isabelle components -u $ISABELLE_TOOLING_ROOT/AutoCorrode/ic2`, adding one
  line to `$ISABELLE_HOME_USER/etc/components`, then `isabelle scala_build`,
  which writes the JAR inside the clone. Exactly one ic2 component may be
  registered; if `isabelle components -l` already lists another `ic2`, show
  the pair `isabelle components -x OLD` then `-u NEW`. Undo: `isabelle
  components -x $ISABELLE_TOOLING_ROOT/AutoCorrode/ic2`.
- **Install the I/Q jEdit plugin** (jEdit workflow only; jEdit must be closed):
  `"$ISABELLE_TOOLING_ROOT/scripts/install-iq-plugin.sh"` writes one JAR and a
  stamp under `$ISABELLE_HOME_USER/jedit/jars/`. Undo: delete those two files.
- **Create the I/Q token** at `~/.config/isabelle-iq/auth-token`, mode 600:
  `mkdir -p ~/.config/isabelle-iq && (umask 077; openssl rand -hex 32 >
  ~/.config/isabelle-iq/auth-token)`. The jEdit launcher and the project's
  `iq` server read it; agents never do, and never print it.
- **Approve the project's configuration once per host.** Codex CLI reads
  `.codex/config.toml` only in a trusted project; Claude Code asks to approve
  the `iq` server from `.mcp.json` at the first start (or the user lists it
  in `enabledMcpjsonServers` in `.claude/settings.local.json`).

Doctor fails while an Isabelle formal-modeling plugin or its marketplace is
installed in either host, or a user-level `iq` server or `ic2-prover`
profile exists: each would duplicate a project file. It prints the command
that removes each one; show it to the user.

## 5. Starting jEdit

For the jEdit workflow, start jEdit through the tooling, never with a plain
`isabelle jedit`:

```bash
"$ISABELLE_TOOLING_ROOT/scripts/launch_jedit.sh" --project <formal root> --session <Name> --venv "$ISABELLE_TOOLING_ROOT/.venv" <Name>/<Name>.thy
```

The launcher passes I/Q the token from `~/.config/isabelle-iq/auth-token` in
`IQ_AUTH_TOKEN` and limits it to the formal root; the project's `iq` server
authenticates with the same file. A jEdit started without the launcher has a
random token, and every I/Q call then fails with "I/Q did not accept the
token".

## 6. The project files

If the checkout has no `isabelle-tooling.conf` yet, the user runs, before a
host session starts there (ask for the session name, an Isabelle identifier,
and where the formal artifacts go: default `formal/`, code at `.`):

```bash
"$ISABELLE_TOOLING_ROOT/bin/isabelle-tooling" init --session <Name> [--formal-rel formal] [--source-rel .]
```

It creates the descriptor and `<formal>/{ROOTS,AGENTS.md,README.md,
CLAUDE.md -> AGENTS.md}` and `<formal>/<Name>/{ROOT,<Name>.thy}`, installs
the project files, prints every path it touched and the `git add` command
for them, and never stages, commits or overwrites anything. The files are
committed with the project, so every clone and worktree has them.

Afterwards:

- `isabelle-tooling sync --check` checks the project files against the pin,
  read-only.
- `isabelle-tooling sync` reinstalls exactly the pinned files; it refuses
  rather than overwrite a managed file someone edited.
- `isabelle-tooling update REV` (or `update stable`) is the only command that
  moves the pin; the runtime clone must then be checked out at that
  revision.
- `isabelle-tooling remove` takes the project files out again, leaving the
  session and the instruction files.
- `isabelle-tooling skills list` and `skills show NAME` print the skills of
  the pinned revision without installing anything.

A project whose descriptor predates project files (no
`.isabelle-tooling/inventory.json`) adopts them with `update REV`. After a
sync or update, the host sees changed skills, profiles or MCP servers only in
a new session.

**Changing the tooling's skills.** In a development worktree of the tooling,
`isabelle-tooling sync --link --source <worktree>` replaces the installed
skills with symlinks into it, so an edit shows in the next session without a
reinstall. That is development state: nothing in it may be committed, doctor
fails on it without `--allow-dirty`, and `isabelle-tooling sync` restores the
copies.

## 7. Doctor, then build

```bash
"$ISABELLE_TOOLING_ROOT/bin/isabelle-tooling" doctor
isabelle build -D <formal>
```

Doctor reads only; it prints remediation commands and runs none. Fix what it
reports, in order, then rerun it. A green doctor and a building empty
session is the finished setup. Then hand over to `isabelle-modeling` (the
conventions interview comes first), `isabelle-proving`,
`isabelle-differential`, and `isabelle-assurance` for the statement of what
was established.

## Several agents: the coordination board

A project may also use agent-board, a separate tool, so that several agents
working in one repository see each other's claims. The Isabelle tooling
never installs or upgrades it. When the user wants it, show them, from the
agent-board clone's README: put `agent-board` on `PATH`, then run
`agent-board init` and optionally `agent-board install-hook` in the
project, and start a new session. With `agent-board.conf` present, doctor
also runs the board's doctor, and the proving skill and worker profiles
name the proof resources and the two delegation modes.

## What this skill never does

Install or configure Claude Code or Codex CLI, or an Isabelle plugin for
them; download Isabelle; write under `$HOME` on its own; register a
project's own AutoCorrode copy as a component; nest the tooling clone inside
a project checkout; install the coordination board.
