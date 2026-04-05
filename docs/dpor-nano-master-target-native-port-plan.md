# DPOR Target-Native Port Plan For `nano-o/master`

Working plan as of 2026-04-04.

This note describes a clean target-native way to bring the current SCP DPOR
build island and investigation flow onto `nano-o/master` without rebasing or
replaying the current branch history.

It is a planning document, not a design commitment. The goal is to give an
implementation agent a concrete port sequence that starts from
`remotes/nano-o/master`, treats the current DPOR branch as reference material,
and avoids carrying over source-branch assumptions that do not belong on the
target.

## Goal

Bring the current opt-in SCP DPOR build island and investigation flow to
`nano-o/master` while preserving the same core constraints as the current tree:

- DPOR remains isolated from `stellar-core`
- DPOR tests do not route through `stellar-core test`
- DPOR target flags stay local to the DPOR binaries
- production SCP changes remain small and testability-oriented

The target outcome is feature parity with the current DPOR integration on
`skip-ledgers-p25-dpor-2` wherever the underlying SCP semantics still match.
The intended exception is the txset
waiting/download-time/skip-ledger surface, which does not apply on
`nano-o/master` and is therefore out of scope for this port.

The current branch already has a landed DPOR split (`types` / `bridge` /
`node` / `replay` / `scenario`), dedicated binaries, smoke tests, and an
investigation runner. The port should preserve that decomposition rather than
reviving the older monolithic adapter from `dpor-skip-ledgers-p25`.

## Why This Approach

The recommended strategy is not a rebase and not a literal replay of the
current commit history.

Instead:

1. start from a fresh branch off `remotes/nano-o/master`
2. re-implement the DPOR island in small target-native commits
3. use the current branch as a reference implementation and behavior spec
4. cherry-pick only when a later commit is clearly self-contained and still
   semantically correct on the target

Why this is preferable:

- the biggest mismatch is semantic, not mechanical: txset waiting /
  download-time / skip-ledger behavior does not belong on `nano-o/master`
- the current branch history is useful, but several late changes depend on
  final-state plumbing rather than on clean original commit boundaries
- the branch delta above `remotes/nano-o/master` is broader than the DPOR
  slice, so “rebase the branch” is already the wrong mental model
- a target-native port reduces the chance that waiting-specific behavior or
  build-shape assumptions apply cleanly but incorrectly

## Source And Target

### Reference branch

Current reference branch:

- `skip-ledgers-p25-dpor-2`

Reference docs:

- [`docs/dpor-integration-status.md`](./dpor-integration-status.md)
- [`docs/dpor-replay-notes.md`](./dpor-replay-notes.md)

Reference principle:

- treat the current branch as the implementation spec for the DPOR build
  island, runtime surface, and validation flow
- do not treat its commit boundaries as requirements
- do not start by replaying `git rebase --onto ...` or grouped cherry-picks
  unless a later phase identifies a clearly self-contained target-safe commit

### Target branch

Target base:

- `remotes/nano-o/master`

Implementation branch policy:

- create a fresh scratch branch directly from `remotes/nano-o/master`
- build the target-native commit series there
- keep the series small, explicit, and organized by target-side milestones

## Hard Constraints

The port should preserve the current DPOR integration constraints:

- do not add DPOR sources to `stellar_core_SOURCES`
- do not add DPOR binaries to `noinst_PROGRAMS` or automake `TESTS`
- do not route DPOR tests through `stellar-core test`
- do not add `$(DPOR_CPPFLAGS)` to global `AM_CPPFLAGS`
- use `EXTRA_PROGRAMS` for strict build-avoidance
- keep `#include <dpor/...>` confined to the support layer
- keep production SCP hooks minimal and testability-oriented
- keep the `ScpDporValue` type payload-only with `operator==`, `operator<`,
  and `std::hash`

## Target Semantic Model

The important target difference is SCP value-validation behavior around missing
txsets.

The current DPOR branch assumes a skip-ledger-aware txset waiting model:

- `SCPDriver::kAwaitingDownload`
- `getTxSetDownloadWaitTime(...)`
- `getTxSetDownloadTimeout()`
- `recordBallotBlockedOnTxSet(...)`
- `measureAndRecordBallotBlockedOnTxSet(...)`
- `makeSkipLedgerValueFromValue(...)`
- `isSkipLedgerValue(...)`
- `noteSkipValueReplaced(...)`

`nano-o/master` does not define those seams.

Instead, `HerderSCPDriver::validateValue(...)` on `nano-o/master` uses the
older model:

- known good txset => `kFullyValidatedValue`
- partially validated / insufficient-state cases may still return
  `kMaybeValidValue`
- invalid txset => `kInvalidValue`
- no dedicated txset waiting state
- no skip-ledger replacement path driven by txset download time

Target model decisions for this port:

- keep DPOR for plain SCP exploration on `nano-o/master`
- do not model txset download waiting
- do not model skip-ledger replacement
- keep only txset validity outcomes that make sense in the reduced target
  model
- do not reinterpret `kMaybeValidValue` as txset waiting
- keep the current focus on plain current-slot exploration rather than trying
  to model all target-side partial-validation cases

Reduced txset choice model for `nano-o/master`:

- keep `valid`
- keep `invalid`
- keep a reduced `nondet` that chooses between `valid` and `invalid`
- drop `waiting`
- do not add a replacement `maybe-valid` DPOR choice in this port
- drop download-time choices
- drop skip-ledger replacement behavior

Explicit reduced-driver rule:

- when the reduced DPOR model makes a txset-status choice, it should choose
  only between `SCPDriver::kFullyValidatedValue` and
  `SCPDriver::kInvalidValue`
- it should not emit `SCPDriver::kMaybeValidValue` as a DPOR choice result
- if a scenario naturally drifts into a target-side partial-validation case
  that would require `kMaybeValidValue`, treat that as out of scope for this
  port and tighten the scenario/driver model rather than expanding the DPOR
  choice set

If a future branch introduces native txset-waiting semantics, that should be
treated as separate follow-on work rather than part of this port.

## Discovery Already Resolved

The current workspace already resolved the main structural question around
snapshot/restore access:

- the private SCP state layout accessed by `DporScpNode` is compatible with
  `nano-o/master`
- the four `friend class DporScpNode` declarations are sufficient for the
  current snapshot/restore accesses
- no extra production SCP implementation seams are currently expected for
  snapshot/restore compatibility

The important remaining incompatibility is the `SCPDriver` interface and
validation model, not the private SCP state layout.

Reverification note:

- this compatibility should still be re-checked at the start of Phase 2 on the
  then-current target snapshot before the implementation agent relies on it

## Working Port Strategy

The implementation agent should follow this policy:

1. Implement from scratch on `nano-o/master` in target-native commits.
2. Copy structure and behavior from the current branch where it still applies.
3. Avoid starting with cherry-picks or rebases.
4. Only cherry-pick late, self-contained commits if they are already known to
   match target semantics.
5. Prefer a smaller, clearer commit series over preserving historical
   boundaries from the source branch.

The agent should use the current branch in three ways:

- as the reference for build-island shape
- as the reference for support-layer decomposition
- as the reference for smoke-test and investigation-runner behavior that still
  makes sense on the target

The agent should not use the current branch as authority for:

- txset waiting semantics
- skip-ledger timeout behavior
- download-time CLI or replay state
- any assumption that a historical commit boundary is automatically worth
  preserving

## Proposed Execution Phases

### Phase 0: Lock the target model and stage discovery

Before touching code, make the target model explicit:

- current-slot SCP exploration only
- no txset waiting
- no skip-ledger replacement
- no `maybe-valid` DPOR choice
- reduced txset choice model at `valid|invalid|nondet`

Early checks:

- diff [`src/scp/SCP.h`](../src/scp/SCP.h),
  [`src/scp/Slot.h`](../src/scp/Slot.h),
  [`src/scp/BallotProtocol.h`](../src/scp/BallotProtocol.h), and
  [`src/scp/NominationProtocol.h`](../src/scp/NominationProtocol.h) between
  the reference branch and `nano-o/master`
- verify whether [`common.mk`](../common.mk) needs any adaptation for the DPOR
  build island; default expectation is no
- identify the exact reduced file set to port first, before considering any
  later ergonomics work

Output of this phase:

- a fresh implementation branch from `remotes/nano-o/master`
- an explicit reduced target model
- a list of reference files and target files for Phase 1 through Phase 6

### Phase 1: Establish the build island first

Port the minimum autotools integration first:

- [`configure.ac`](../configure.ac)
- [`make-mks`](../make-mks)
- [`src/Makefile.am`](../src/Makefile.am)
- [`.gitignore`](../.gitignore)

Target outcome:

- `--enable-dpor`
- local `DPOR_CPPFLAGS` and `DPOR_CXXFLAGS`
- dedicated `EXTRA_PROGRAMS`
- no leakage into global `AM_CPPFLAGS`
- no DPOR sources in `stellar_core_SOURCES`
- direct `make -C src ...` works on a clean configured tree without requiring
  a prior top-level `make`
- the DPOR targets explicitly materialize the generated XDR / xdrquery / Rust
  bridge sources and the sibling `lib` artifacts they depend on

Critical build details to carry explicitly:

- [`make-mks`](../make-mks) must exclude `Dpor*`, `SCPDpor*`, and `ScpDpor*`
  files from `SRC_TEST_CXX_FILES`
- [`make-mks`](../make-mks) must emit the dedicated DPOR buckets used by
  [`src/Makefile.am`](../src/Makefile.am) instead of letting DPOR test files
  leak into the main test binary
- [`src/Makefile.am`](../src/Makefile.am) must wire the generated XDR headers,
  `main/StellarCoreVersion.cpp`, `main/XDRFilesSha256.cpp`,
  `util/xdrquery/XDRQueryScanner.cpp`, `util/xdrquery/XDRQueryParser.h`,
  `util/xdrquery/XDRQueryParser.cpp`, and `rust/RustBridge.h` /
  `rust/RustBridge.cpp` as DPOR prerequisites
- [`src/Makefile.am`](../src/Makefile.am) must also force the sibling build
  artifacts the DPOR targets depend on, especially `$(XDRC)`,
  `$(libsodium_LIBS)`, `$(xdrpp_LIBS)`, `$(soci_LIBS)`,
  `$(libmedida_LIBS)`, and `$(top_builddir)/lib/lib3rdparty.a`

Target `DPOR_CXXFLAGS` should include:

- `-std=c++20`
- `-DFMT_CONSTEVAL=`
- `-DSTELLAR_DISABLE_LOGGING`

Important implementation note:

- do not stop this phase at the early build-island shape from the first DPOR
  integration
- Gate 1 assumes the later `src/Makefile.am` prerequisite wiring that makes
  clean direct `make -C src stellar-core-dpor-tests
  scp-dpor-investigation` viable

Reference commits for this phase:

- `7ee78fa61` `first integration`
- `a9cbd7a67` `Fix DPOR automake helper variable names`
- `da6bd4b68` `try to fix build`

Default policy:

- implement this phase manually
- do not cherry-pick blindly

### Phase 2: Add the minimal production SCP hooks

Bring over the smallest access declarations required by `DporScpNode`:

- `friend class DporScpNode` in:
  - [`src/scp/SCP.h`](../src/scp/SCP.h)
  - [`src/scp/Slot.h`](../src/scp/Slot.h)
  - [`src/scp/BallotProtocol.h`](../src/scp/BallotProtocol.h)
  - [`src/scp/NominationProtocol.h`](../src/scp/NominationProtocol.h)

This phase is only about the SCP access surface needed for snapshot/restore.
It does not cover later production-file ports for logging elimination or
assert/abort capture.

Required re-check at phase start:

- re-verify on the target branch that the `DporScpNode` snapshot/restore logic
  still fits behind the four friend declarations without adding new production
  SCP seams

If that re-check fails:

- stop the target-native port at that point
- do not opportunistically widen production SCP APIs or make private state
  public just to keep momentum
- document the exact incompatibility and treat any broader production-hook
  change as a separate design decision

Expected outcome:

- `DporScpNode` can snapshot and restore the private SCP state it already uses
  on the reference branch
- no broader production SCP API expansion is introduced

### Phase 3: Port the reduced support layer under `src/scp/test`

Bring over the current support split, but in a reduced target-native form:

- [`src/scp/test/ScpDporTypes.h`](../src/scp/test/ScpDporTypes.h)
- [`src/scp/test/ScpDporBridge.h`](../src/scp/test/ScpDporBridge.h)
- [`src/scp/test/DporScpNode.h`](../src/scp/test/DporScpNode.h)
- [`src/scp/test/DporScpNode.cpp`](../src/scp/test/DporScpNode.cpp)
- [`src/scp/test/ScpDporReplaySupport.h`](../src/scp/test/ScpDporReplaySupport.h)
- [`src/scp/test/ScpDporReplaySupport.cpp`](../src/scp/test/ScpDporReplaySupport.cpp)
- [`src/scp/test/ScpDporDefaultScenario.h`](../src/scp/test/ScpDporDefaultScenario.h)
- [`src/scp/test/SCPDporTestMain.cpp`](../src/scp/test/SCPDporTestMain.cpp)
- [`src/scp/test/SCPDporSmokeTests.cpp`](../src/scp/test/SCPDporSmokeTests.cpp)
- [`src/scp/test/DporScpInvestigationMain.cpp`](../src/scp/test/DporScpInvestigationMain.cpp)

Reduced `ScpDporValue` shape on `nano-o/master` should be:

- envelope delivery
- timer choice
- txset status choice

Explicitly remove from the target-native implementation:

- `TxSetDownloadWaitTimeChoice`
- `waiting` txset status
- `--download-time`
- `--download-succeeds-in-round`
- wait-time replay state
- skip-ledger timeout behavior
- any node-side implementation of waiting-only `SCPDriver` seams

Implementation notes:

- `DporScpNode` should implement only the target-side `SCPDriver` interface
- the reduced txset status choice model is `valid|invalid|nondet`
- do not synthesize `kAwaitingDownload`
- do not add a `kMaybeValidValue` DPOR choice in this phase
- in practice, `nondet` in this reduced harness means
  `kFullyValidatedValue|kInvalidValue`, not
  `kFullyValidatedValue|kMaybeValidValue|kInvalidValue`

### Phase 4: Recover the core scenario surface

Get the target-adapted harness working in this order:

1. prepare-boundary exploration
2. commit-boundary exploration
3. externalize-boundary exploration
4. nomination timers
5. ballot timers
6. emitted-envelope inspection
7. `--must-externalize`
8. `--check-agreement`
9. `--init same|unique`

At this stage the runner is considered useful if it can explore plain SCP
behavior on the new base without any txset waiting or skip-ledger logic.

The critical path is steps 1 through 3. Once boundary exploration is stable,
steps 7 through 9 do not need to be treated as a strict sequence.

Reference commits for this phase:

- `7ee78fa61` `first integration`
- `9868ba7c7` `add nomination timers scenario`
- `d291329c8` `work on scenarios`
- `c978fc74b` `misc dpor investigation improvements`
- `5f36bbb8b` `Add strict must-externalize investigation check`
- `6d361c799` `Add DPOR investigation agreement check`
- `21d714776` `Add init modes to SCP DPOR investigation`

Default policy:

- use these commits as reference only
- re-implement in target-native commits rather than replaying their history

### Phase 5: Add replay and investigation ergonomics

Once the reduced harness is stable, carry over the remaining compatible
test-side ergonomics:

- replay optimization for known choices
- investigation error replay dumps
- thread-step exception wrapping into DPOR error executions
- JSON trace capture and replay

Files expected in this phase:

- [`src/scp/test/ScpDporInvestigationUtils.h`](../src/scp/test/ScpDporInvestigationUtils.h)
- [`src/scp/test/ScpDporTraceJson.h`](../src/scp/test/ScpDporTraceJson.h)
- [`src/scp/test/ScpDporTraceJson.cpp`](../src/scp/test/ScpDporTraceJson.cpp)
- updated [`src/scp/test/DporScpInvestigationMain.cpp`](../src/scp/test/DporScpInvestigationMain.cpp)
- updated [`src/scp/test/SCPDporSmokeTests.cpp`](../src/scp/test/SCPDporSmokeTests.cpp)
- updated [`src/scp/test/ScpDporDefaultScenario.h`](../src/scp/test/ScpDporDefaultScenario.h)

Recommended order within this phase:

1. port the reduced replay optimization
2. add the investigation error wrapper and replay-dump plumbing
3. add JSON trace capture and replay

Reference commits for this phase:

- `58e0c31f0` `Optimize DPOR replay for known txset choices`
- `b19d27356` `Improve DPOR investigation error replay dumps`
- `1b4a24498` `first json trace impl`
- `694754343` `fix trace-json review issues`

Implementation notes:

- these commits may need partial adaptation because the target harness has
  fewer choice types
- the later assert/abort capture work depends on the error-wrapper plumbing
  from `b19d27356` already being in place

### Phase 6: Land performance and investigation robustness work

After the reduced harness and replay ergonomics are stable, port the remaining
performance and robustness work:

- compile-time logging elimination for DPOR SCP builds
- assert/abort capture as DPOR error executions
- smoke coverage for real SCP `releaseAssert` capture

Production files touched by this phase:

- [`src/util/Logging.h`](../src/util/Logging.h)
- [`src/util/GlobalChecks.h`](../src/util/GlobalChecks.h)
- [`src/util/GlobalChecks.cpp`](../src/util/GlobalChecks.cpp)
- [`src/scp/BallotProtocol.cpp`](../src/scp/BallotProtocol.cpp)
- [`src/scp/NominationProtocol.cpp`](../src/scp/NominationProtocol.cpp)

Test-side files touched by this phase:

- [`src/scp/test/DporScpInvestigationMain.cpp`](../src/scp/test/DporScpInvestigationMain.cpp)
- [`src/scp/test/SCPDporTestMain.cpp`](../src/scp/test/SCPDporTestMain.cpp)
- [`src/scp/test/SCPDporSmokeTests.cpp`](../src/scp/test/SCPDporSmokeTests.cpp)

Expected adaptation shape:

- [`src/util/Logging.h`](../src/util/Logging.h) is largely self-contained and
  should carry the `STELLAR_DISABLE_LOGGING` compile-elision path in
  target-native form
- [`src/util/GlobalChecks.h`](../src/util/GlobalChecks.h) and
  [`src/util/GlobalChecks.cpp`](../src/util/GlobalChecks.cpp) are also largely
  self-contained and should carry `enableAssertThrowMode()` and the
  throw-or-abort dispatch in target-native form
- [`src/scp/BallotProtocol.cpp`](../src/scp/BallotProtocol.cpp) should only
  take the generic `abort()` to `dbgAbort()` changes and any target-safe
  logging-elimination cleanup; do not reintroduce waiting-specific logic
- [`src/scp/NominationProtocol.cpp`](../src/scp/NominationProtocol.cpp) needs
  target-specific adaptation for the logging-elimination cleanup

Reference commits for this phase:

- `5d35d1bd8` `compile-eliminate logging in DPOR SCP builds`
- `77946b3b7` `remove residual logging work from DPOR builds`
- `dbb0cb39c` `capture SCP assert/abort as DPOR error executions`
- `889bad4f3` `tighten DPOR releaseAssert smoke coverage`

Dependency note:

- this phase assumes Phase 5 already carried the error-execution wrapper and
  replay-dump plumbing
- before implementing this phase, quickly scan the reference branch for any
  newer DPOR-specific performance or robustness work beyond these pinned SHAs;
  use the pinned commits as the baseline, not as a claim that later relevant
  work cannot exist

## What Not To Port

Do not reintroduce waiting-specific work in this target-native port:

- `abe4e5e47` `Refactor DPOR txset status and download time flags`
- `32b3cdadd` `Add download-succeeds-in-round investigation option`
- `e84b4af85` `Restore pending txset wait-time replay state`
- `9afb5a9ea` `Latch nondeterministic txset investigation choices`
- `26476e284` `Add SCP reproducer for awaiting-to-invalid nomination`

Also do not treat the following as required code-port inputs:

- planning-only docs and dev-container commits before the first DPOR code
  integration
- non-DPOR branch divergence above `remotes/nano-o/master`

## Suggested Target-Native Commit Series

The implementation agent should prefer a compact target-native series such as:

1. build island wiring plus clean direct `make -C src ...` prerequisites
2. minimal production SCP friend hooks
3. reduced DPOR support layer scaffolding and buildable binaries
4. reduced default scenario plus prepare/commit/externalize smoke coverage
5. timer support, emitted-envelope inspection, `--must-externalize`,
   `--check-agreement`, and `--init same|unique`
6. reduced replay optimization
7. investigation error wrapper and replay-dump plumbing
8. JSON trace capture/replay
9. compile-time logging elimination for DPOR builds
10. assert/abort capture plus releaseAssert smoke coverage

This is a suggested shape, not a fixed requirement. The important part is to
organize by target-side milestones rather than by source-branch history.

## Validation Gates

Each phase should stop at a concrete validation point.

When running inside the current container/workspace, prefer the out-of-tree
build directory if `/home/dev/stellar-core-build/` exists. Otherwise use the
in-tree build as a fallback.

### Gate 1: Build wiring

Expected checks:

```bash
make -n -C src stellar-core-dpor-tests scp-dpor-investigation
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

Confirm:

- DPOR targets compile with C++20
- DPOR include path is local to those targets
- DPOR code is absent from `stellar-core`
- the direct `make -C src ...` entry point works on a clean configured tree
  without relying on a prior top-level `make`

### Gate 2: Reduced smoke tests

Expected checks:

```bash
./src/stellar-core-dpor-tests "[scp][dpor][smoke]"
```

Confirm:

- reduced target-adapted smoke tests pass
- no test depends on waiting/download-time semantics

### Gate 3: Reduced investigation runner

Expected checks:

```bash
./src/scp-dpor-investigation --depth 12
./src/scp-dpor-investigation --stop-on-commit --depth 16
./src/scp-dpor-investigation --stop-on-externalize --depth 16
```

Confirm:

- runner explores multiple executions
- commit and externalize boundaries are reachable
- no CLI path references waiting/download-time behavior

### Gate 4: Extended runner surface

Expected checks:

```bash
./src/scp-dpor-investigation --must-externalize --depth 16
./src/scp-dpor-investigation --check-agreement --depth 16
./src/scp-dpor-investigation --init unique --depth 16
```

Confirm:

- `--must-externalize` works with reduced target semantics
- agreement checks work with the reduced harness
- alternate init modes work without reintroducing waiting-specific logic

### Gate 5: Replay and trace ergonomics

Expected checks:

- replay optimization smoke coverage
- investigation-style error-execution smoke coverage
- JSON trace write/load/replay smoke coverage

Confirm:

- replay still works with the reduced choice set
- the runner can dump replay lead-ins for error executions
- trace JSON reflects the reduced scenario options and value types

### Gate 6: Performance and robustness

Expected checks:

- build output still shows local DPOR C++20 flags including
  `-DSTELLAR_DISABLE_LOGGING`
- smoke coverage for real SCP `releaseAssert` capture passes
- investigation runner exits nonzero with a replayable captured error path

Confirm:

- logging-elimination work is restored
- assert/abort capture is active in both DPOR binaries
- no waiting-specific production logic was reintroduced as part of the
  robustness work

## Definition Of Done

The target-native port is complete when:

- the DPOR build island exists on `nano-o/master`
- the reduced support split is in place
- the reduced default scenario supports boundary exploration, timers,
  `--must-externalize`, agreement checks, and init modes
- replay and JSON trace capture work for the reduced choice set
- logging-elimination and assert/abort capture are restored
- smoke tests and runner validation pass without any waiting/download-time
  semantics

## Follow-Through

When the port lands:

- update [`docs/dpor-integration-status.md`](./dpor-integration-status.md) so
  it reflects the target-native `nano-o/master` integration rather than the
  current source-branch semantics
- update [`docs/dpor-replay-notes.md`](./dpor-replay-notes.md) if replay or
  trace-capture behavior differs materially in the reduced target harness

## Initial Recommendation

The first implementation attempt should optimize for a working target-native
port, not for preserving the current branch’s history.

That means:

- start from `remotes/nano-o/master`
- establish the build island first
- port only the minimal SCP access declarations first
- port the split DPOR harness as a reduced target-native variant
- keep the reduced txset choice model at `valid|invalid|nondet`
- drop waiting/download-time/skip-ledger behavior from this port
- recover the core runner and smoke-test surface
- add replay ergonomics next
- land performance and robustness work last

If this target-native port succeeds, any later cleanup can refine commit
boundaries, factor common code, or decide whether any self-contained
source-branch commits are worth reusing verbatim.
