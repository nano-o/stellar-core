# DPOR Integration Status

Status snapshot as of 2026-07-20 for branch `dpor-on-master`, based on
upstream `master` (`f8b9c6eb2`, which includes the merged CAP-0083
empty-tx-set feature), against DPOR library commit `d2c06e7` (functionally
identical to the `b238b19` pin previously recorded here; the commits in
between are comment/doc-only).

This branch is the port of the DPOR work from `skip-ledgers-p26-dpor` onto
master. The old branch's 18 skip-ledgers feature commits were dropped
(superseded by master's CAP-0083 merge); only the DPOR work was ported. The
port adapted the harness to master's renamed driver API:

- `makeSkipLedgerValueFromValue` / `isSkipLedgerValue` became
  `makeEmptyTxSetValueFromValue` (only present under `#ifdef CAP_0083`,
  mirroring `SCPDriver.h`) and `isEmptyTxSetValue`, with an `EMPTY:` payload
  prefix in `DporScpNode`.
- `SCPDriver::validateValue` lost the old branch's `ValidationExtraInfo`
  out-parameter, and the `kAwaitingDownload` validation level is now
  `kStructurallyValidValue` (same ordinal and semantics).
- `DporScpNode` implements master's new pure virtuals
  `isParallelTxSetDownloadEnabled()` (returns `true`) and
  `protocolAllowsEmptyTxSetValues()` (configurable, default `true`; see
  below).
- The old branch's accept-commit guard (`throwIfValueInvalidForCommit`,
  which the error-capture smoke tests used as their SCP error source) does
  not exist on master. Master's equivalent
  (`throwIfValueInvalidForConfirmCommit`) fires at confirm-commit, where the
  harness's txset-status latch makes it unreachable: peers' CONFIRM
  envelopes are rejected while a value is only structurally valid, so a
  node can never ratify commit on a value it has not resolved as valid.
  The error-capture smoke tests instead disallow empty-tx-set values via
  the new `mProtocolAllowsEmptyTxSetValues` scenario option, which makes
  SCP's `releaseAssert(protocolAllowsEmptyTxSetValues())` fire
  deterministically once a ballot envelope validates as only structurally
  valid.
- Note: without `--enable-next-protocol-version-unsafe-for-production`
  (which defines `CAP_0083` globally), master compiles out
  `BallotProtocol::maybeReplaceValueWithEmptyTxSet`, so the empty-tx-set
  replacement path is inert in the default DPOR build. The current
  scenarios do not depend on it. Do not add `-DCAP_0083` to only the DPOR
  target flags: the DPOR binaries link non-DPOR objects from the normal
  build, and `CAP_0083` changes the `SCPDriver` vtable layout.

This note describes how DPOR is currently integrated into `stellar-core`. The
short version is that DPOR now exists as an opt-in SCP-only build island with
dedicated binaries, a split support layer (`types` / `bridge` / `node` /
`replay` / `scenario`), and a configurable three- or four-node scenario that can
explore prepare, commit, timer, and txset-wait behavior. It is still isolated
from the main `stellar-core` binary and from `stellar-core test`, but it is not
yet a large SCP property suite.

The DPOR library now partitions maximal executions into `Full` (every thread
completed) and `Blocked` (at least one thread ended waiting on a blocking
receive that no message can satisfy); previously both were classified `Full`.
The harness treats the union as "maximal" wherever it checks complete
interleavings (`isMaximalExecution` in
[`src/scp/test/ScpDporInvestigationUtils.h`](../src/scp/test/ScpDporInvestigationUtils.h)),
so `--must-externalize` and `--check-agreement` coverage is unchanged. The
library also introduced a typed exception hierarchy (`dpor/errors.hpp`), a
`format_graph` helper (`dpor/model/format.hpp`), and an `on_fatal_error`
diagnostic hook; the harness's existing exception-to-`ErrorLabel` wrapping
already matches the new error-reporting contract, and the investigation runner
wires `on_fatal_error` to dump the in-progress execution graph on fatal
library or harness errors.

## Build integration

- [`configure.ac`](../configure.ac) adds `--enable-dpor`,
  `--with-dpor-dir`, `DPOR_DIR`, `DPOR_CPPFLAGS`, `DPOR_CXXFLAGS`, the
  `ENABLE_DPOR` automake conditional, and a compile probe for
  `<dpor/algo/dpor.hpp>`.
- Configure looks for DPOR in `external/dpor` first and `../dpor` second. The
  default DPOR target flags are `-std=c++20 -DFMT_CONSTEVAL=
  -DSTELLAR_DISABLE_LOGGING`.
- The checked-in build still requires tests to remain enabled.
  `--disable-tests --enable-dpor` errors out in `configure.ac`, and the DPOR
  programs are declared under `if BUILD_TESTS` in
  [`src/Makefile.am`](../src/Makefile.am).
- [`make-mks`](../make-mks) excludes `Dpor*`, `SCPDpor*`, and `ScpDpor*` files
  from `SRC_TEST_*` and emits dedicated `SRC_DPOR_SUPPORT_*`,
  `SRC_DPOR_TEST_CXX_FILES`, and `SRC_DPOR_MAIN_CXX_FILES` buckets.
- [`src/Makefile.am`](../src/Makefile.am) defines two dedicated
  `EXTRA_PROGRAMS` behind `ENABLE_DPOR`:
  - `stellar-core-dpor-tests`
  - `scp-dpor-investigation`
- Those targets get `$(DPOR_CPPFLAGS)` and `$(DPOR_CXXFLAGS)` locally. DPOR is
  not added to global `AM_CPPFLAGS`, and no DPOR sources are added to
  `stellar_core_SOURCES`.
- The DPOR binaries rebuild a small SCP subset under C++20
  (`BallotProtocol.cpp`, `LocalNode.cpp`, `NominationProtocol.cpp`,
  `QuorumSetUtils.cpp`, `SCP.cpp`, `SCPDriver.cpp`, and `Slot.cpp`) and link
  the rest of their object graph through `STELLAR_CORE_DPOR_LINK_OBJECTS`.
  This keeps DPOR opt-in, but it still reuses a large portion of the normal
  `stellar-core` object graph.
- Because `stellar-core-dpor-tests` still links that shared object graph, any
  process-wide runtime switch enabled by its custom main also applies to the
  non-DPOR test objects linked into the same binary. In particular, the current
  assert-throw mode used for DPOR error-capture is process-wide within
  `stellar-core-dpor-tests`; it is not yet scoped only to the DPOR smoke code.
- The DPOR targets also force the generated XDR / xdrquery / Rust bridge
  sources and the sibling `lib` build artifacts they rely on (`xdrc`,
  `libxdrpp`, `libsodium`, and the local static archives), so a clean
  `make -C src ...` build does not depend on a prior top-level `make`.
- The practical build entry point in this tree is:

  ```bash
  make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
  ```

## Support layer

- [`src/scp/test/ScpDporTypes.h`](../src/scp/test/ScpDporTypes.h) defines
  `ScpDporValue` and the DPOR aliases. The value kinds are:
  - envelope delivery
  - timer choice
  - txset validation-status choice
  - txset download wait-time choice
- `ScpDporValue` provides `operator==`, `operator<`, and `std::hash`, and it
  remains payload-only.
- [`src/scp/test/ScpDporBridge.h`](../src/scp/test/ScpDporBridge.h) owns the
  encode/decode helpers and pretty-printing between SCP objects and
  `ScpDporValue`.
- [`src/scp/test/DporScpNode.h`](../src/scp/test/DporScpNode.h) and
  [`src/scp/test/DporScpNode.cpp`](../src/scp/test/DporScpNode.cpp) implement
  the deterministic `SCPDriver` used by DPOR. The node snapshots and restores
  slot state, tracks emitted envelopes, tracks timers and timer-set counts,
  exposes boundary detection, and surfaces txset validation-status and
  wait-time nondeterminism to the scenario layer.
- [`src/scp/test/ScpDporReplaySupport.h`](../src/scp/test/ScpDporReplaySupport.h)
  and
  [`src/scp/test/ScpDporReplaySupport.cpp`](../src/scp/test/ScpDporReplaySupport.cpp)
  provide stored baselines, thread-local cached nodes, and replay helpers for
  observed traces, including hidden txset status and wait-time choices. Replay
  semantics are also described in
  [`docs/dpor-replay-notes.md`](./dpor-replay-notes.md).
- [`src/scp/test/ScpDporTraceJson.h`](../src/scp/test/ScpDporTraceJson.h) and
  [`src/scp/test/ScpDporTraceJson.cpp`](../src/scp/test/ScpDporTraceJson.cpp)
  serialize versioned, pretty-printed replay bundles for debugger-oriented
  replay. Each bundle stores the effective default-scenario options, the
  communication model, terminal metadata (including failure text and focus
  node/thread), and one exact `ThreadTrace` per thread.
- [`src/scp/test/ScpDporDefaultScenario.h`](../src/scp/test/ScpDporDefaultScenario.h)
  is the current default scenario layer. It currently builds a three- or
  four-validator, single-slot SCP program and can inspect both boundary state
  and replay traces.
- Production SCP changes are still small. The main hooks are `friend class
  DporScpNode` in:
  - [`src/scp/SCP.h`](../src/scp/SCP.h)
  - [`src/scp/Slot.h`](../src/scp/Slot.h)
  - [`src/scp/BallotProtocol.h`](../src/scp/BallotProtocol.h)
  - [`src/scp/NominationProtocol.h`](../src/scp/NominationProtocol.h)

## Runtime surface

- The checked-in runtime surface is still centered on one scenario class, but
  that scenario is configurable rather than fixed.
- [`src/scp/test/ScpDporDefaultScenario.h`](../src/scp/test/ScpDporDefaultScenario.h)
  currently supports:
  - stopping at prepare boundaries, commit-phase boundaries, or
    externalize boundaries
  - nomination and balloting timer enablement
  - nomination and balloting round caps
  - nomination-timer and balloting-timer firing caps
  - timer-set limits
  - txset download wait-time modes: `below`, `above`, and `nondet`
  - txset validation-status modes: `valid`, `waiting`, `invalid`, and `nondet`
    - in `valid` mode, status choices explore `waiting` and `valid`
    - in `invalid` mode, status choices explore `waiting` and `invalid`
    - in `nondet` mode, status choices explore `valid`, `waiting`, and
      `invalid`
    - in the branching modes above, status choices reoccur only while the last
      result for a value is `waiting`; once a value resolves to `valid` or
      `invalid`, later queries on that node reuse the same result without
      another DPOR choice
  - nomination-only forced waiting for txset validation, so nomination-path
    queries return `waiting` without consuming a txset-status choice while
    ballot-path validation still follows the configured status mode
  - in `nondet` wait-time mode, choices reoccur only while the last wait-time
    result for a value is still below the download timeout; once a value times
    out, later queries on that node reuse the timed-out result without another
    DPOR choice
  - forcing later txset validation calls to return `valid` after a node emits
    its first `PREPARE` in a configured ballot round
  - disallowing empty-tx-set values (`mProtocolAllowsEmptyTxSetValues =
    false`), which makes SCP's
    `releaseAssert(protocolAllowsEmptyTxSetValues())` fire once a ballot
    envelope validates as only structurally valid; the error-capture smoke
    tests use this as their deterministic SCP error source (there is no
    investigation-runner flag for it yet)
  - custom timeout parameters for nomination and balloting
- [`src/scp/test/DporScpInvestigationMain.cpp`](../src/scp/test/DporScpInvestigationMain.cpp)
  exposes that surface through flags such as:
  - `--stop-on-prepare`
  - `--stop-on-commit`
  - `--stop-on-externalize`
  - `--must-externalize`
    - maximal (full or blocked) executions require an `EXTERNALIZE` envelope
      from every node, and a failing execution dumps its replay trace; the
      failure message names the terminal kind that triggered it
  - `--check-agreement`
    - maximal (full or blocked) executions require all observed `EXTERNALIZE`
      envelopes to agree on the externalized value, and a failing execution
      dumps its replay trace
  - `--with-nomination-timers`
  - `--with-balloting-timers`
  - `--nodes 3|4` / `--validators 3|4`
    - the four-node configuration uses a 3-of-4 quorum set on every node
  - `--init same|unique`
  - `--max-nomination-round`
  - `--max-balloting-round`
  - `--max-nomination-timers-round`
  - `--max-balloting-timers-round`
  - `--download-time`
  - `--txset-status`
  - `--nomination-always-waiting`
  - `--download-succeeds-in-round`
  - `--fifo`
  - `--parallel` / `--workers`
  - `--print-stats`
  - `--fail-on-first-terminal`
  - `--trace-dir DIR`
    - directory for auto-named JSON trace files written when the runner stops
      on a captured failure path
  - `--replay-trace-json`
  - `--replay-node N|all`
    - default replay scope is the stored focus node; `all` replays every node
      in focus-first order
- Both DPOR binaries enable assert-throw mode at startup
  (`enableAssertThrowMode()` in `src/util/GlobalChecks.h`), so SCP
  `releaseAssert` and `dbgAbort` failures are captured as DPOR error executions
  with file:line context rather than aborting the process.
- The investigation runner now wraps thread-step exceptions as DPOR error
  executions, dumps replay lead-ins for all scenario threads with the failing
  thread first, can fail fast on the first terminal execution for smoke-test
  workflows, can write the first captured terminal execution as a structured
  JSON artifact into `--trace-dir` (default `dpor-traces`), prints the chosen
  path as `trace-json=...`, can reload that artifact for deterministic replay
  without rerunning DPOR, and exits nonzero with the original exception
  message.
- The summary line and `--print-stats` progress lines report the blocked
  count (`blocked=` / `blocked_executions=`) alongside full, error, and
  depth-limit counts, and trace bundles serialize the `blocked` terminal kind.
- The investigation runner registers the library's `on_fatal_error` hook and
  prints the fatal exception message plus a `format_graph` rendering of the
  in-progress execution graph to stderr before the exception propagates.
- The persisted artifact stores exact per-thread observed traces rather than a
  full schedule. Deeper traces with many envelope deliveries can grow
  noticeably because the envelope payloads are persisted as exact base64 XDR.
  Reload uses the stored scenario options and thread traces with the existing
  harness replay seam rather than reconstructing a DPOR schedule.
- [`src/scp/test/SCPDporSmokeTests.cpp`](../src/scp/test/SCPDporSmokeTests.cpp)
  contains DPOR smoke tests. The checked-in coverage exercises:
  - deterministic first-step generation
  - initial envelope fanout
  - prepare-boundary discovery
  - commit-boundary exploration
  - externalize-boundary exploration
  - nomination-timer firing caps and round boundaries
  - balloting-round boundaries
  - replay-trace inspection
  - emitted-envelope inspection for missing externalize
  - maximal-execution (full or blocked) externalization agreement checks
  - follower timer-before-delivery behavior
  - txset status-choice restore and preload behavior
  - txset wait-time restore and preload behavior
  - txset status latch-once-resolved replay behavior
  - nomination-only forced waiting for txset validation
  - `download-succeeds-in-round` forcing later txset validation to `valid`
  - investigation-style wrapping of thread exceptions into inspectable DPOR
    error executions
  - replay-trace inspection preserving the lead-in when SCP throws during
    replay
  - JSON round-trips for scenario options and raw per-thread traces
  - trace-bundle write/load/replay of a captured error execution
  - capturing an SCP `releaseAssert` as a DPOR error execution with file:line
    context

## Verification in this workspace

I verified the current state directly in this tree (branch `dpor-on-master`,
DPOR library `d2c06e7`), after confirming a normal (non-DPOR) configure and
build stays clean with no DPOR sources or symbols in `stellar-core`:

- `./src/scp-dpor-investigation --depth 12` reported
  `kind=all-explored executions=17 full=0 blocked=0 error=0 depth-limit=17`.
- `./src/scp-dpor-investigation --stop-on-commit --depth 16` reported
  `kind=all-explored executions=34 full=0 blocked=0 error=0 depth-limit=34`.
- `./src/scp-dpor-investigation --stop-on-externalize --depth 16` reported
  `kind=all-explored executions=34 full=0 blocked=0 error=0 depth-limit=34`.
- `./src/scp-dpor-investigation --stop-on-commit --with-balloting-timers
  --max-balloting-timers-round 0 --depth 16` reported
  `kind=all-explored executions=34 full=0 blocked=0 error=0 depth-limit=34`.
  (These three counts were 38 on the old skip-ledgers base; the smaller
  tree is expected from master's evolved ballot-phase validation and the
  empty-tx-set replacement path being compiled out without `CAP_0083`.)
- `./src/scp-dpor-investigation --txset-status waiting --download-time below
  --depth 12` reported
  `kind=all-explored executions=3 full=0 blocked=0 error=0 depth-limit=3`.
- `./src/scp-dpor-investigation --txset-status nondet --download-time nondet
  --depth 12` reported
  `kind=all-explored executions=40 full=0 blocked=1 error=0 depth-limit=39`.
- `./src/scp-dpor-investigation --check-agreement --txset-status nondet
  --download-time nondet --depth 12` reported
  `kind=all-explored executions=40 full=0 blocked=1 error=0 depth-limit=39`.
- `./src/scp-dpor-investigation --parallel --workers 4 --txset-status nondet
  --download-time nondet --depth 12` reported the same counts as the
  sequential run.
- `./src/scp-dpor-investigation --download-succeeds-in-round 1 --depth 12`
  reported
  `kind=all-explored executions=17 full=0 blocked=0 error=0 depth-limit=17`.
- `./src/scp-dpor-investigation --fifo --depth 12` reported
  `kind=all-explored executions=17 full=0 blocked=0 error=0 depth-limit=17`.
- `./src/scp-dpor-investigation --nodes 4 --depth 12` reported
  `kind=all-explored executions=6 full=0 blocked=0 error=0 depth-limit=6`.
- `./src/scp-dpor-investigation --fail-on-first-terminal --trace-dir ...
  --depth 12` dumped replay traces for the first terminal execution, wrote a
  `trace-json=...` artifact that reloaded and replayed cleanly with
  `--replay-trace-json ... --replay-node all`, reported
  `kind=stopped executions=1 full=0 blocked=0 error=0 depth-limit=1`, and
  exited nonzero with `error: stopped at first terminal execution because
  --fail-on-first-terminal was set for smoke testing`.
- `./src/scp-dpor-investigation --stop-on-prepare --must-externalize
  --depth 20` exited nonzero with
  `error: full execution missing EXTERNALIZE envelope from node-index=0
  thread=0`, dumped the failing replay trace, and reported
  `kind=stopped executions=1 full=1 blocked=0 error=0 depth-limit=0`.
  (On the old base the first full execution appeared later, after 10
  depth-limited executions.)
- `./src/scp-dpor-investigation --must-externalize --txset-status nondet
  --download-time nondet --depth 12` exited nonzero with
  `error: blocked execution missing EXTERNALIZE envelope from node-index=0
  thread=0`, wrote a trace bundle with `terminal-kind=blocked`, and that
  bundle reloaded and replayed cleanly with
  `--replay-trace-json ... --replay-node all`.
- `./src/stellar-core-dpor-tests "[scp][dpor][smoke]"` passed with 202
  assertions in 30 test cases.

## Current limitations

- DPOR is still isolated from the main binary and from `stellar-core test`, but
  it remains nested under the test build and still reuses a large portion of
  the normal object graph.
- The checked-in exploration model is still a small single-slot SCP harness
  with three- and four-node configurations. There is not yet a broader family
  of scenarios or a multi-slot / ledger-closing model.
- Trace JSON load validates the artifact schema and per-trace invariants, but
  some default-scenario semantic checks are still deferred until replay builds
  `ScpDporDefaultScenario` from the stored options rather than being enforced
  entirely inside `loadTraceBundle()`.
- DPOR still depends on `BUILD_TESTS`; `--disable-tests --enable-dpor` is not
  supported.
