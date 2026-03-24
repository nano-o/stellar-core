# DPOR Build Integration Plan

## Scope

This note describes a minimal, opt-in build integration for experimenting with
the DPOR model checker in `stellar-core`.

The integration should treat DPOR as a source-pinned, test-only dependency.
The important factor is not just that it is header-only; it is also that the
checker is still unstable enough that we want churn and blast radius contained.

The immediate goal is to make it possible to build and run:

- DPOR-based smoke and property tests for SCP
- a separate manual investigation runner for deeper SCP experiments

without changing the normal `stellar-core` binary or the default local build
and test pipeline.

Non-goals for this phase:

- no routing through `src/stellar-core test`
- no addition to automake `TESTS`
- no requirement that CI or routine developer workflows build or run DPOR code
- no commitment yet to the detailed full-SCP replay model

## Constraints From The Current Build

`stellar-core` is currently built with autotools, not CMake:

- [configure.ac](/home/nano/code/stellar-core/configure.ac)
- [Makefile.am](/home/nano/code/stellar-core/Makefile.am)
- [src/Makefile.am](/home/nano/code/stellar-core/src/Makefile.am)
- [make-mks](/home/nano/code/stellar-core/make-mks)

Important consequences:

- existing test sources are compiled into the main `stellar-core` binary when
  `BUILD_TESTS` is enabled
- DPOR is a header-only C++20 library
- DPOR should be treated as a source-pinned test dependency, not a system
  dependency discovered from "whatever is installed"
- `stellar-core` is still a C++17 project, and the current configure flow bakes
  `-std=c++17` into `CXX`
- the earlier `dpor-skip-ledgers-p25` integration ended up keeping reusable
  DPOR/SCP harness code under `src/scp/test/`, not in a generic `src/test/dpor`
  subtree
- that earlier branch also needed both Catch-based tests and a dedicated
  command-line investigation runner

Because of this, DPOR code should not be mixed into the existing
`stellar-core` test target. It needs its own build island with target-local
include paths and target-local C++20 flags.

## Proposed Integration

### 1. Add An Optional Configure Gate And DPOR Location

In [configure.ac](/home/nano/code/stellar-core/configure.ac):

- add `--enable-dpor`, default `no`
- make it valid only when tests are enabled, so DPOR stays behind both
  `BUILD_TESTS` and `ENABLE_DPOR`
- add `--with-dpor-dir=PATH`
- treat an in-tree pinned copy such as `external/dpor` as the primary layout
- allow a sibling checkout such as `../dpor` only as a local override
- export:
  - `DPOR_DIR`
  - `DPOR_CPPFLAGS`
  - `DPOR_CXXFLAGS`
  - automake conditional `ENABLE_DPOR`

Recommended default behavior:

- if `--with-dpor-dir` is passed, use it
- otherwise prefer `external/dpor` if present
- otherwise fall back to `../dpor`

This keeps the default build reproducible while still leaving a convenient
escape hatch for local iteration against a sibling checkout.

Configure-time checks should verify:

- the DPOR include tree exists under `$(DPOR_DIR)/include`
- a tiny translation unit including `dpor/algo/dpor.hpp` compiles using the
  same flags intended for real DPOR targets

That compile probe should use the actual target-local compatibility flags, not
just plain `-std=c++20`. In practice this may include a workaround such as
`-DFMT_CONSTEVAL=` if the same issue seen in `dpor-skip-ledgers-p25` still
applies.

Do not make DPOR a system dependency in this phase:

- no package-manager integration
- no configure-time search for an arbitrary installed DPOR
- no import of the upstream DPOR build system

### 2. Keep DPOR Sources Out Of The Main Test Source Bucket

The first reusable DPOR/SCP harness should live next to the existing SCP tests
under `src/scp/test/`, not in a new generic `src/test/dpor/` subtree.

Rationale:

- the code will sit on SCP-specific seams
- it will likely mirror and borrow patterns from `src/scp/test/SCPTests.cpp`
- the previous integration converged on `src/scp/test/`

In [make-mks](/home/nano/code/stellar-core/make-mks), explicitly carve the DPOR
files out of the normal `SRC_TEST_*` buckets instead of letting them fall into
the main `stellar-core` test binary.

Recommended generated variables:

- `SRC_DPOR_SUPPORT_CXX_FILES`
- `SRC_DPOR_SUPPORT_H_FILES`
- `SRC_DPOR_TEST_CXX_FILES`
- `SRC_DPOR_MAIN_CXX_FILES`

The exact names are flexible. The important point is that the chosen
`src/scp/test/Dpor*` and `src/scp/test/SCPDpor*` files must not remain in
`SRC_TEST_CXX_FILES`.

This is the key isolation step. Without it, any new DPOR harness file under
`src/scp/test/` will silently get compiled into the ordinary `stellar-core`
test target.

### 3. Build Shared DPOR/SCP Support With Target-Local C++20 Flags

In [src/Makefile.am](/home/nano/code/stellar-core/src/Makefile.am), build the
reusable DPOR/SCP support code separately from the main `stellar-core` sources.

That shared support will likely include:

- deterministic SCP driver/node support
- the DPOR replay adapter
- small utility helpers shared by both tests and the investigation runner

The rest of `stellar-core` should talk to this local adapter layer, not to
upstream `dpor/...` headers directly. That keeps upstream API churn localized.

The previous branch needed this split immediately, not as a later cleanup.
There are likely to be at least two DPOR-facing binaries that reuse the same
support code.

Acceptable shapes:

- a DPOR-only convenience library, if we are comfortable with
  `--enable-dpor` making `make` build that shared support
- or an equivalent shared source grouping linked only into explicit DPOR
  binaries, if stricter build avoidance is still a requirement

In either case:

- do not add DPOR sources to `stellar_core_SOURCES`
- keep direct `#include <dpor/...>` usage confined to the DPOR support layer
- compile the shared DPOR support with `$(DPOR_CXXFLAGS)`
- keep `$(DPOR_CPPFLAGS)` target-local rather than adding it to all test builds

### 4. Build Two Explicit DPOR Binaries

The build should distinguish between:

- a Catch-based DPOR test binary
- a CLI-style investigation runner for manual exploration

Recommended examples:

- `stellar-core-dpor-tests`
- `scp-dpor-investigation`

The earlier branch shows why both matter:

- Catch tests are good for smoke checks and small `verify(...)` properties
- manual investigation quickly grows CLI needs such as worker count, depth,
  communication model, scenario selection, and property toggles

If the non-goal remains "do not build DPOR code during default `make` or
`make check` flows", prefer explicit build targets such as `EXTRA_PROGRAMS`
plus direct developer invocation.

Important automake detail:

- `noinst_PROGRAMS` are built by `make all`
- `check_PROGRAMS` are built by `make check`

So `noinst_PROGRAMS` is not a build-avoidance mechanism. If we want DPOR to be
strictly explicit, `noinst_PROGRAMS` is the wrong default.

### 5. Reuse Catch For Tests, Not For Manual Investigation

The repo already vendors Catch v2 via:

- [lib/catch.hpp](/home/nano/code/stellar-core/lib/catch.hpp)
- [src/test/Catch2.h](/home/nano/code/stellar-core/src/test/Catch2.h)
- [src/test/test.cpp](/home/nano/code/stellar-core/src/test/test.cpp)

The DPOR test binary should reuse this stack rather than adding a second test
framework dependency.

Practical implication:

- give the DPOR test binary its own small Catch `main`
- reuse existing local Catch support pieces as needed
- do not try to route DPOR tests through `stellar-core test`
- keep the investigation runner as a separate non-Catch executable

Routing DPOR through the existing `test` subcommand would drag the DPOR code
back into the main binary, which defeats the C++17/C++20 separation.

### 6. Keep Manual And Smoke Runs At The Binary Level

The operational model for this phase should be explicit binary invocation.

For example:

```bash
make stellar-core-dpor-tests
./src/stellar-core-dpor-tests "[scp][dpor][smoke]"

make scp-dpor-investigation
./src/scp-dpor-investigation --workers 8 --scenario two-followers --depth 12
```

The exact target names may vary, but the workflow should stay direct.

Recommended split:

- `[scp][dpor][smoke]` for very small Catch-based runs
- `[scp][dpor][property]` for modest `verify(...)` checks
- the investigation binary for deeper scenario-driven or multi-worker searches

## Likely Source Layout

Recommended location:

- `src/scp/test/`

Reusable deterministic SCP replay support:

- `src/scp/test/DporScpNode.h`
- `src/scp/test/DporScpNode.cpp`
- `src/scp/test/ScpDporReplaySupport.h`
- `src/scp/test/ScpDporReplaySupport.cpp`

First SCP DPOR scenario module, following the `two_phase_commit_timeout/sim/`
split into DPOR types, bridge, and scenario:

- `src/scp/test/ScpDporTypes.h`
- `src/scp/test/ScpDporBridge.h`
- `src/scp/test/ScpDporThreeNodePrepareBoundaryScenario.h`

Supporting tests and runners:

- `src/scp/test/SCPDporSmokeTests.cpp`
- `src/scp/test/SCPDporTests.cpp`
- `src/scp/test/DporScpInvestigationMain.cpp`

The exact names can change, but the important build assumption is that DPOR
support should live near SCP tests while still being explicitly excluded from
the ordinary test-source buckets.

The old `dpor-skip-ledgers-p25` branch suggests that what was previously called
an "adapter" should be split more aggressively. The reusable deterministic
`SCPDriver`-backed node belongs in its own support file pair, while the
scenario-facing DPOR layer should follow the 2PC example's three-way split. The
new plan should use SCP-neutral names even if the first replay slice still
starts from SCP's current nomination entry point and initially cuts off at
`PREPARE`.

## First SCP Scenario Following The 2PC Pattern

The first concrete SCP scenario should be a small SCP replay slice that mirrors
the old branch's simplest useful replay fixture:

- 3 validators
- one homogeneous quorum set shared by all nodes
- quorum threshold 2
- fixed slot index
- deterministic leader ordering with node 0 highest in round 1
- initial values `[x, y, y]`
- initial scope stops at the first local `PREPARE` boundary, while keeping the
  support layer and scenario naming broad enough to extend into later SCP
  phases

The 2PC analogy here is about decomposition and thread-function contract, not
about implementation size. The SCP scenario should copy the `types / bridge /
scenario` split, but it should not pretend SCP replay is as lightweight as the
2PC `ReplayState`. The old SCP branch already showed that SCP needs shared
snapshot, baseline, and timer-reinstallation support.

This is the smallest scenario that still exercises:

- real early-SCP fanout to multiple receivers
- deterministic leader/follower asymmetry
- timer-versus-delivery behavior
- reconstruction of the first handoff into balloting

The choice of `[x, y, y]` is deliberate:

- `[x, x, x]` is too trivial for a first DPOR-backed SCP slice
- `[x, y, z]` adds branching without giving as clear a first expected outcome
- `[x, y, y]` creates a useful asymmetry where the distinguished leader starts
  from one value while the threshold-majority followers share another

### 1. DPOR Types File

`src/scp/test/ScpDporTypes.h` should contain only the DPOR-visible value domain
and aliases, analogous to `sim/dpor_types.hpp` in the 2PC example.

For SCP, this should likely include:

- a `ScpDporValue` type
- a `Kind` enum for at least:
  - SCP envelope delivery
  - timer-selection choices if multiple timers can fire
  - replay-only external choices such as txset download wait-time choices
- the DPOR aliases:
  - `EventLabel`
  - `SendLabel`
  - `ReceiveLabel`
  - `NondeterministicChoiceLabel`
  - `ObservedValue`
  - `ExplorationGraph`
  - `ThreadTrace`
  - `ThreadFunction`
  - `Program`

This file should not know about the concrete scenario topology. Its job is only
to define the DPOR-facing value universe.

The file should also make an explicit choice about `ScpDporValue` shape.
Initially, the simplest correct option is likely to follow the old branch and
carry:

- sender thread
- destination thread
- slot index
- either a full `SCPEnvelope` or a replay-choice payload

This is less compact than the 2PC example's 64-bit `SimValue`, but it is much
more realistic for a first SCP harness because full envelopes are easier to
debug and the old branch already proved out comparison on that shape.

Whichever representation is chosen, `ScpDporValue` must provide:

- equality comparison
- ordering for nondeterministic choice handling
- a `std::hash` specialization

This should be stated up front because DPOR uses ordering and equality on
choice values, and hashability matters for graph and test utilities.

### 2. Bridge File

`src/scp/test/ScpDporBridge.h` should contain the translation layer between SCP
objects and `ScpDporValue`, analogous to `sim/bridge.hpp` in the 2PC example.

Initially this should own:

- node-index to DPOR-thread mapping helpers
- conversion of emitted `SCPEnvelope`s into `ScpDporValue`
- conversion of replayed `ScpDporValue`s back into envelope deliveries
- encoding and decoding of timer-selection choices
- encoding and decoding of external replay choices such as txset download wait
  times
- human-readable formatting helpers for diagnostics

Conceptually, this is where the DPOR encoding lives. The rest of the SCP test
code should not manipulate the low-level DPOR value encoding directly.

The bridge should stay narrow. In particular, it should not own:

- receive-label construction
- replay-step counting
- send fanout from one emitted SCP envelope to `N - 1` peers

Those are replay-logic responsibilities of the scenario layer, even if they use
bridge helpers for encoding and destination mapping.

### 3. Scenario File

`src/scp/test/ScpDporThreeNodePrepareBoundaryScenario.h` should be the SCP
counterpart of `sim/crash_before_decision.hpp`: one self-contained scenario
module exposing `Options`, replay helpers, thread builders, and `makeProgram()`.

This scenario module should sit on top of the reusable
`DporScpNode` support layer. Historically, `dpor-skip-ledgers-p25` used a
`DporNominationNode` with the replay seam described below; the new plan should
carry that seam forward under SCP-neutral naming rather than preserve the old
nomination-specific type names.

The scenario file should own:

- an `Options` struct describing:
  - validator identities
  - quorum set
  - slot index
  - previous value
  - per-node initial values
  - boundary mode and timeout toggles
- a scenario-specific replay state wrapper for one node/thread
- the thread functions for the three validators
- a `makeProgram()` factory
- concrete prepare-boundary inspection helpers used by tests and the
  investigation runner

The scenario-specific replay state is the SCP counterpart of the 2PC example's
`ReplayState`, but it should stay focused on the scenario-level control flow:

- counting replayed and captured I/O steps
- deciding when the current thread-function call has reached its step boundary
- constructing receive labels
- queueing send fanout for newly emitted envelopes
- emitting nondeterministic choice events when the scenario requires them

### 4. Shared Replay Support

Unlike the 2PC example, SCP also needs a shared replay-support layer beneath
the scenario file. That support should live in a file such as
`ScpDporReplaySupport.h/.cpp` and own the machinery that is expensive,
cross-cutting, and reusable across multiple SCP scenarios:

- slot-state snapshots and restore
- replay baselines
- timer re-installation helpers
- thread-local replay-state caching
- any allocation-heavy or snapshot-heavy replay support needed to keep the
  thread functions deterministic and fast enough

This is the part that corresponds to the old branch's heavier machinery in
`DporNominationNode` plus the baseline-caching parts of
`DporNominationDporAdapter`.

### Deterministic SCP Interface Used By The Scenario

The old branch already identified the deterministic SCP interface the scenario
needs. The new `DporScpNode` should expose an SCP-wide replay seam modeled on
the old branch's `DporNominationNode`.

For the first implementation, that seam will probably still include a startup
helper that enters SCP through its current nomination entry point, because that
is the real entry point the old branch used. More generally, the scenario
module needs support for:

- starting SCP for one node from its configured initial state
- replaying delivered SCP envelopes
- replaying timer firings
- draining newly emitted SCP envelopes into DPOR `SendLabel`s
- checking whether the next wait is blocking or non-blocking
- replaying external choices such as txset download wait times
- detecting whether the scenario boundary has been crossed and, if so, what the
  first boundary envelope was

Historically, the branch achieved this with methods such as:

- `nominate(slotIndex, initialValue, previousValue)`
- `receiveEnvelope(...)`
- `fireTimer(slotIndex, timerID)`
- `takePendingEnvelopes()`
- `hasActiveTimer(...)` and `getTimer(...)`
- `enqueueTxSetDownloadWaitTimeChoice(...)`
- `hasCrossedNominationBoundary()` and `getNominationBoundaryEnvelope()`

The new support layer should offer the same capabilities under broader SCP
terminology in the shared support, but the scenario-facing helpers should use
concrete names that match the actual boundary they inspect. For this first
scenario, names like `hasReachedPrepareBoundary()` and
`getPrepareBoundaryEnvelope()` are clearer than a generic
`hasCrossedScenarioBoundary()`.

For performance, the scenario module may also use:

- `snapshotReplayBaseline(...)`
- `restoreReplayBaseline(...)`
- replay-timer installation helpers corresponding to the active SCP phase

but those are optimizations on top of the basic replay contract above.

### Replay Strategy

The first SCP scenario should follow the same thread-function contract as the
2PC example, while using a substantially richer replay implementation under the
hood.

For each thread-function call:

1. acquire or restore the shared replay-support state for that node
2. start SCP once for that node's configured initial state
3. replay prior observed values from the trace in order
4. after each replayed observation, drain newly emitted envelopes and queue the
   resulting sends
5. once all earlier observations are replayed, return exactly one next event:
   a send, a blocking receive, a non-blocking receive, a nondeterministic
   choice, or end-of-thread

The observation mapping should be:

- delivered envelope value -> `receiveEnvelope(...)`
- bottom on a non-blocking receive -> `fireTimer(...)`
- txset wait-time choice value -> `enqueueTxSetDownloadWaitTimeChoice(...)`

The scenario should stop producing further events once
the chosen SCP scenario boundary becomes true. Tests can then inspect the
recorded boundary envelope to verify which first ballot boundary was reached.

### Receive Matchers

Receive labels should be constructed in the scenario replay logic, not in the
bridge.

For the first SCP scenario, the receive matcher should at least:

- accept only `ScpDporValue` instances representing delivered SCP envelopes
- require `destinationThread == localThread`

It should not use `match_any_value()`. SCP needs per-destination receive
matching for correctness.

The first prepare-boundary scenario does not need to filter by ballot-envelope
type at receive time, because once a local node reaches the prepare boundary the
boundary envelope is recorded diagnostically rather than reintroduced as a
normal modeled send.

### Broadcast Fanout

One emitted SCP envelope corresponds to a broadcast to the other validators.
The scenario replay logic should therefore expand one local emission into
`N - 1` `SendLabel`s, one per destination peer.

This is an important difference from the 2PC example:

- 2PC mostly has one protocol send call per modeled send event
- SCP fanout turns one local protocol action into multiple DPOR send events

This should be called out explicitly because it materially affects exploration
size.

### Timer Model And Multiple Timers

The scenario should not assume the 2PC invariant of "at most one active timer at
a receive point". SCP may have multiple relevant timers, and the old branch
already needed timer-selection logic.

The plan for timer handling should therefore be:

- if no enabled timer is active, emit a blocking receive
- if exactly one enabled timer is active, emit a non-blocking receive and treat
  bottom as firing that timer
- if multiple enabled timers are active, first emit a
  `NondeterministicChoiceLabel` choosing which timer is the one that will fire,
  then emit the non-blocking receive whose bottom corresponds to the chosen
  timer

That implies `ScpDporValue` needs a timer-choice variant in addition to
envelope-delivery and external-choice variants.

The initial prepare-boundary scenario may happen not to exercise multiple
concurrent timers often, but the replay design should not rely on that as a
semantic invariant.

### Why This Split Is Better For SCP

The old `DporNominationDporAdapter` mixed together:

- the DPOR-visible value type
- encoding and receive-label helpers
- replay mechanics
- concrete scenario construction

The 2PC example's split is a better template for SCP because it makes it easier
to:

- add a second SCP scenario without redefining the DPOR value type
- share one bridge across early-SCP and later balloting/externalize scenarios
- keep scenario-specific assumptions, like `[x, y, y]` and the round-1 leader
  ordering, out of the reusable deterministic SCP support layer

### First Tests For This Scenario

The first tests using this scenario should stay small:

- a determinism test that the same `(trace, step)` input yields the same thread
  output every time
- a smoke test that `makeProgram()` builds and explores at least one execution
- a step-shape test that the leader first emits the expected initial SCP sends
  before waiting
- a boundary test that some explored leader path reaches a `PREPARE` boundary
- a timeout test that at least one follower path observes an initial-phase SCP
  timer firing before delivery wins

That gives the SCP harness the same "types / bridge / scenario" structure as
the 2PC example while still reusing the deterministic SCP replay seam that the
old `dpor-skip-ledgers-p25` branch already proved out.

## Harness Design Considerations That Affect Build Integration

The detailed driver design is out of scope for this phase, but a few points do
matter to the build plan.

### Reuse Existing SCP Test Infrastructure Carefully

There is already substantial SCP test support in
[src/scp/test/SCPTests.cpp](/home/nano/code/stellar-core/src/scp/test/SCPTests.cpp),
including a `TestSCP` driver built on top of:

- [src/scp/SCP.h](/home/nano/code/stellar-core/src/scp/SCP.h)
- [src/scp/SCPDriver.h](/home/nano/code/stellar-core/src/scp/SCPDriver.h)

That code is useful as a reference, but it is not yet packaged as a reusable
library component.

Implication:

- the first DPOR harness should extract or duplicate only the deterministic
  support it actually needs
- it should not depend on `SCPTests.cpp` as if it were already a reusable
  module

### Expect Some Small SCP Testability Hooks

The earlier branch did not stay completely isolated to new files. It ended up
adding a small number of testability hooks such as `friend` declarations in SCP
headers so the replay layer could inspect or snapshot internal state.

Implication:

- prefer avoiding production-path changes
- but do not write the build plan as if zero SCP-header changes are guaranteed
- allow for small, targeted test-only visibility adjustments if the replay
  layer genuinely needs them

### Shared DPOR Support Is Likely Part Of The Initial Shape

If the DPOR harness includes both Catch tests and an investigation runner, a
shared DPOR/SCP support layer is likely part of the first implementation, not a
later refactor.

A broader repo-wide library reorganization can still wait. The immediate goal is
just to avoid duplicating the adapter/node layer across multiple binaries.

## Main Risks

### C++ Standard Override And Flag Mismatch

The current build embeds `-std=c++17` in `CXX`, not just in `CXXFLAGS`.

Risks:

- per-target `..._CXXFLAGS = -std=c++20` may or may not override cleanly
- the configure probe can pass while the real target still fails if the probe
  does not use the exact same compatibility flags

Mitigation:

- verify the emitted compile command for the new DPOR targets
- make the configure probe use the same `DPOR_CXXFLAGS` as the actual target
- if needed, use a dedicated compile rule or dedicated compiler variable for
  DPOR targets

### Source Classification Drift

Because [make-mks](/home/nano/code/stellar-core/make-mks) auto-generates
[src/src.mk](/home/nano/code/stellar-core/src/src.mk), the chosen
`src/scp/test/Dpor*` and `src/scp/test/SCPDpor*` files must be explicitly
carved out there. Otherwise future files will silently get absorbed into the
normal test build.

### Accidental Workflow Expansion

Even a build-only hook into routine targets can make an experiment feel more
official than intended.

Mitigation:

- do not add DPOR binaries to automake `TESTS`
- do not use `noinst_PROGRAMS` if strict build avoidance is desired
- avoid routing the code through `stellar-core test`
- prefer explicit developer invocation

### Multi-Worker Runtime Overhead

The old branch eventually needed runtime support changes around logging because
DPOR worker-heavy runs put unusual pressure on hot paths.

Mitigation:

- treat build integration as phase 0, not the whole effort
- expect follow-on support work if multi-worker investigations are slow or noisy

## Recommended Implementation Order

1. Add `--enable-dpor`, `--with-dpor-dir`, `DPOR_CPPFLAGS`, and
   `DPOR_CXXFLAGS` in configure, and make the compile probe use those exact
   flags. Treat `external/dpor` as the default pinned source location and
   `../dpor` as an override.
2. Decide the initial `src/scp/test/Dpor*` and `src/scp/test/SCPDpor*` file
   set, then update `make-mks` to keep those files out of `SRC_TEST_*`.
3. Add the shared DPOR/SCP support build unit in `src/Makefile.am`, compiled
   with target-local C++20 flags.
4. Add an explicit Catch-based DPOR test binary and an explicit investigation
   runner binary behind `ENABLE_DPOR`.
5. Add one trivial smoke test and one trivial investigation mode to prove both
   binary paths work.
6. Inspect the emitted compile and link commands before iterating on the real
   SCP harness.
7. Only after that, start expanding the replay model, allowing small SCP-header
   testability hooks if they prove necessary.

## Summary

The right first step is not to integrate DPOR into the existing test runner.
It is to add a strictly optional DPOR build island that:

- treats DPOR as a source-pinned, test-only dependency
- is enabled only behind `BUILD_TESTS` plus `--enable-dpor`
- resolves DPOR from a pinned in-tree copy by default, with a sibling checkout
  only as an override
- keeps reusable DPOR/SCP support under `src/scp/test/` but outside the normal
  `SRC_TEST_*` buckets
- confines direct `dpor/...` includes to the local DPOR adapter/support layer
- compiles DPOR targets with their own C++20 compatibility flags
- provides two explicit entry points: Catch smoke/property tests and a CLI
  investigation runner
- stays out of `stellar-core test` and out of the default `make` / `make check`
  workflows if we keep the DPOR binaries on explicit automake targets

That gets the build-system boundary right and matches what the earlier
`dpor-skip-ledgers-p25` integration actually converged toward.
