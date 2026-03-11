# SCP DPOR Build Integration Plan

## Goal

Define how to integrate the first DPOR-based SCP nomination experiment directly
into the `stellar-core` tree, so the harness, test cases, and build wiring
match the environment where we eventually want to use them.

More specifically, this document sets the initial plan for:

- where the DPOR code and SCP experiment should live in the repository
- how the experiment should be wired into the existing `stellar-core` test
  build
- where to place the protocol boundary between nomination and ballot behavior
- how to model the first deterministic nomination-only simulation

This document covers the in-tree build shape, the nomination protocol
boundary around `bumpState(...)`, and the initial simulation model.

## Recommendation

Keep the first integration test-only, with DPOR brought in as a pinned git
submodule:

- add DPOR as a submodule at `external/dpor` (done)
- consume DPOR headers from that submodule instead of copying them into `src/`
- do not try to embed the prototype repo's CMake build into `stellar-core`
- do not create a separate linked library for the first experiment
- compile the experiment as ordinary `stellar-core` Catch2 tests under
  `BUILD_TESTS`

This is the least risky path because `stellar-core` already builds all SCP test
logic into the main test binary, while the current DPOR engine is mostly
header-only and likely to change during early SCP experimentation.

## Why This Shape

- `stellar-core` uses autotools/automake, not CMake
- `src/Makefile.am` already gates test sources behind `BUILD_TESTS`
- `make-mks` auto-discovers files under paths containing `test` or
  `simulation`
- placing DPOR under `external/` avoids `make-mks` accidentally pulling DPOR
  sources, tests, and examples into `stellar-core`'s build
- the existing SCP test harnesses in `src/scp/test/` already provide the right
  style of deterministic driver stubs
- using a submodule keeps DPOR easy to evolve independently if SCP experiments
  expose checker bugs or missing features

## Proposed Repository Layout

Recommended first layout:

- `external/dpor/`
  - git submodule pointing at the DPOR repository
- `src/scp/test/DporNominationSimulation.h`
  - SCP-specific DPOR adapter types and replay logic
- `src/scp/test/DporNominationSimulation.cpp`
  - non-template helper code if needed
- `src/scp/test/SCPDporNominationTests.cpp`
  - Catch2 test cases for the nomination experiment

Optional later split if the harness grows:

- `src/scp/test/DporTestDriver.h`
- `src/scp/test/DporTestDriver.cpp`
- `src/scp/test/DporEnvelopeValue.h`
- `src/scp/test/DporReplay.h`

## DPOR Source Integration Strategy

For the first integration, do not copy DPOR sources into `stellar-core`.
Instead:

- add the DPOR repository as a git submodule at `external/dpor`
- include only the needed DPOR headers from `external/dpor/include/`
- keep all SCP-specific glue in `src/scp/test/`

Do not import yet:

- DPOR sources into `src/`
- prototype examples into `stellar-core` source directories
- prototype tests into `stellar-core` source directories
- the prototype repo's CMake build into `stellar-core`

Rationale:

- the nomination experiment can call the header-level DPOR engine directly
- the submodule can move independently as SCP experiments uncover checker bugs
  or missing features
- keeping the submodule outside `src/` avoids accidental source discovery by
  `make-mks`
- this keeps the initial integration independent of the prototype repo's build
  system while still making updates easy to pull in

The build should expose DPOR headers by adding:

```make
-I"$(top_srcdir)/external/dpor/include"
```

to the `src` compile flags, preferably behind `BUILD_TESTS`.

The first milestone should optimize for build simplicity and easy
cross-repository iteration, not for perfect long-term packaging.

## Build System Touch Points

The build changes should be minimal.

1. Add the DPOR submodule at `external/dpor`.
2. Add `external/dpor/include` to the `src` compile include path.
3. Add new experiment files under `src/scp/test/`.
4. Stage the new files with git.
5. Run `./make-mks` so `src/src.mk` is regenerated.
6. Re-run `./autogen.sh` if needed by the local workflow.
7. Configure and build with tests enabled.

Important detail:

- `src/Makefile.am` includes `$(SRC_TEST_CXX_FILES)` only when `BUILD_TESTS`
  is enabled
- `make-mks` classifies files under paths containing `test` or `simulation` as
  test sources
- therefore the SCP DPOR harness should live under `src/scp/test/`, not under
  production SCP directories
- and the DPOR submodule should stay under `external/`, not under `src/`

## Expected Build Commands

One-time repository setup:

```bash
cd ~/stellar-core
git submodule add <dpor-repo-url> external/dpor
git add .gitmodules external/dpor
```

Typical local loop:

```bash
cd ~/stellar-core
git submodule update --init --recursive external/dpor
git add -N src/scp/test docs/scp-dpor-build-plan.md
./make-mks
./autogen.sh
./configure --enable-tests
make -j$(nproc)
```

Test execution:

```bash
cd ~/stellar-core
src/stellar-core test '[scp][dpor]'
```

Full regression path:

```bash
cd ~/stellar-core
make check
```

## Scope Boundary For The First Experiment

The first experiment should stay narrow:

- SCP nomination only
- one fixed slot index
- deterministic quorum sets and node identities
- deterministic timer behavior
- fixed validation behavior
- stop exploration at the first transition into ballot protocol behavior

Even though the experiment is nomination-focused, it should still use the real
`SCP`, `Slot`, and `NominationProtocol` types from `stellar-core`. The harness
should not try to reimplement nomination semantics.

## Protocol Boundary Discussion

`NominationProtocol` does not end in isolation. When a new candidate set is
formed, it combines the candidate values and then calls `mSlot.bumpState(...)`,
which hands control into the ballot protocol.

That creates three possible boundaries for a "nomination-only" experiment.

### Option 1: Cut Off Before `bumpState(...)`

Shape:

- intercept or suppress the `bumpState(...)` call
- treat candidate formation as the terminal nomination outcome

Problems:

- this changes the real `stellar-core` control flow
- it requires patching or subclassing core SCP logic solely for the experiment
- it risks invalidating the exact behavior we want to model-check later in-tree

Recommendation:

- do not use this option for the first integration

### Option 2: Let `bumpState(...)` Run, But Stop At The First Ballot Output

Shape:

- run the real nomination code unchanged
- allow `mSlot.bumpState(..., false)` to execute normally
- treat the first emitted non-nomination envelope, typically the first
  `PREPARE`, as the boundary of the nomination experiment

Benefits:

- preserves the real nomination-to-ballot handoff
- avoids invasive changes to SCP core logic
- still keeps the explored state space limited to nomination plus the immediate
  transition out of nomination

Recommendation:

- use this option for the first experiment

### Option 3: Continue Exploring Ballot Protocol

Shape:

- once `bumpState(...)` fires, keep exploring all later ballot behavior

Problems:

- much larger state space
- no longer a nomination-focused experiment
- mixes two validation goals at once

Recommendation:

- defer until the nomination harness is already working

### Recommended Boundary Rule

For the first experiment, define the protocol boundary as:

- use the real `NominationProtocol`, `Slot`, and `BallotProtocol`
- allow `bumpState(..., false)` to execute normally
- stop the nomination experiment when a local node first emits a non-nomination
  SCP envelope

Operationally, that means:

- nomination envelopes remain ordinary modeled network messages
- the first `PREPARE`, `CONFIRM`, or `EXTERNALIZE` envelope is not fed back
  into the simulated network for this experiment
- instead, it marks that the node has crossed the nomination boundary

## Simulation Discussion

The simulation should follow the same high-level shape as the DPOR 2PC example,
but the interception point is `stellar::SCPDriver`, not a custom environment
interface.

### Simulation Model

Each SCP node is represented as one DPOR thread.

Each thread function should:

- reconstruct a fresh deterministic SCP node and driver from the observed trace
- call the initial nomination entry point once
- replay prior delivered envelopes and timer firings in trace order
- capture exactly one next externally visible action

As in the existing DPOR prototype, the replay callback must be deterministic
and side-effect free for the same trace and step.

### What Gets Simulated

The first experiment only needs to simulate:

- local node identity
- local quorum set and known remote quorum sets
- slot index
- previous value
- initial nomination value for each node
- emitted SCP envelopes
- nomination timer setup/cancellation
- delivery of inbound nomination envelopes

The first experiment should not try to simulate:

- overlay/network stack
- application objects
- ledger persistence
- full externalize behavior
- production `HerderSCPDriver`

### Driver Shape

The simulation driver should be a deterministic `SCPDriver` subclass that:

- stores quorum sets by hash
- returns fully validated values unless a test explicitly wants otherwise
- captures every emitted envelope
- records active timers by `(slotIndex, timerID)`
- replays timer firings synchronously from the DPOR trace
- uses deterministic node-priority and value-hash functions for predictable
  scenarios
- uses a deterministic `combineCandidates(...)` policy for the test setup

This should be modeled after the existing deterministic SCP test drivers in
`src/scp/test/SCPTests.cpp` and `src/scp/test/SCPUnitTests.cpp`.

### DPOR Event Mapping

Recommended initial event mapping:

- local nomination envelope emission -> DPOR `Send`
- waiting for an inbound compatible envelope with no timer armed -> blocking
  `Receive`
- waiting while a nomination timer is armed -> non-blocking `Receive`
- timer firing -> bottom observation on the non-blocking receive

For the first experiment, payloads should be canonicalized into a compact DPOR
value type that can represent:

- nomination envelope contents
- sender identity
- destination identity
- timer-fire observation when no envelope is delivered

### Replay Rule

For a given thread step:

1. rebuild the node from scratch
2. replay all earlier trace observations for that node
3. stop as soon as one new visible action is reached

That visible action is one of:

- emit a nomination envelope
- request the next inbound envelope
- request the next timer-or-envelope race through a non-blocking receive
- cross the nomination boundary by emitting the first non-nomination envelope

### Boundary Handling In The Simulator

When the real SCP node emits its first non-nomination envelope:

- do not model that envelope as a normal network send for the nomination-only
  experiment
- instead, mark the thread as having reached the nomination boundary and stop
  producing further events for that execution branch

This preserves the real local control flow up to the handoff without forcing
the nomination experiment to include ballot exploration.

If later we want a stronger cross-check, the simulator can optionally record
the first ballot envelope in test diagnostics, but it should still be outside
the explored message space for the first milestone.

## Test Harness Plan

Build the adapter on top of the same seams used by existing SCP tests:

- subclass `stellar::SCPDriver`
- capture `emitEnvelope(...)`
- record and replay `setupTimer(...)` and `stopTimer(...)`
- provide deterministic `getQSet(...)`
- provide deterministic hashing and candidate-combination callbacks
- instantiate real `stellar::SCP` nodes and feed them replayed envelopes

The DPOR-facing side should mirror the existing prototype structure:

- one DPOR thread per SCP node
- one trace-driven replay per thread step
- envelope delivery modeled as send/receive events
- timer firing modeled through non-blocking receive plus bottom observation

## Milestones

### Milestone 0: Build Spike

- add the DPOR submodule under `external/dpor/`
- add the DPOR include path to the `src` build
- add a trivial Catch2 smoke test that constructs a tiny DPOR program
- verify that `stellar-core` builds and the DPOR headers compile cleanly in the
  autotools environment

### Milestone 1: SCP Harness Skeleton

- add a minimal `SCPDriver` subclass for deterministic nomination tests
- instantiate a small fixed SCP node set
- confirm that the harness can reproduce one simple nomination scenario without
  DPOR

### Milestone 2: DPOR-Driven Nomination Replay

- add trace replay and single-step event capture
- encode nomination-envelope deliveries and timer firings into DPOR values
- stop at the first non-nomination output boundary

### Milestone 3: Real Test Cases

- add targeted `[scp][dpor][nomination]` tests
- start with a very small topology
- then add core5-style leader and timeout cases adapted from
  `src/scp/test/SCPTests.cpp`

## Non-Goals For The First Integration

- no standalone DPOR executable inside `stellar-core`
- no production-path changes outside test-only files
- no attempt to model full SCP ballot/externalize behavior yet
- no attempt to absorb the full DPOR repo into `src/`
- no attempt to upstream the prototype repo's full build, API, or examples

## Log

- 2026-03-11: Landed the Milestone 0 build spike by adding the test-only DPOR
  include path in `common.mk`, adding `src/scp/test/SCPDporSmokeTests.cpp`,
  and verifying `src/stellar-core test '[scp][dpor]'` passes after regenerating
  the autotools build files.
