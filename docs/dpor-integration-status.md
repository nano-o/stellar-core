# DPOR Integration Status

Status snapshot as of 2026-04-04 for branch `skip-ledgers-p25-dpor-2`.

This note describes how DPOR is currently integrated into `stellar-core`. The
short version is that DPOR now exists as an opt-in SCP-only build island with
dedicated binaries, a split support layer (`types` / `bridge` / `node` /
`replay` / `scenario`), and a configurable three-node scenario that can explore
prepare, commit, timer, and txset-wait behavior. It is still isolated from the
main `stellar-core` binary and from `stellar-core test`, but it is not yet a
large SCP property suite.

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
  serialize exact `ThreadTrace` bundles, scenario options, and terminal
  metadata as pretty-printed JSON for debugger-oriented replay.
- [`src/scp/test/ScpDporDefaultScenario.h`](../src/scp/test/ScpDporDefaultScenario.h)
  is the current default scenario layer. It currently builds a three-validator,
  single-slot SCP program and can inspect both boundary state and replay
  traces.
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
    - in `nondet` mode, status choices reoccur only while the last result for a
      value is `waiting`; once a value resolves to `valid` or `invalid`, later
      queries on that node reuse the same result without another DPOR choice
    - in `nondet` wait-time mode, choices reoccur only while the last wait-time
      result for a value is still below the skip threshold; once a value times
      out, later queries on that node reuse the timed-out result without
      another DPOR choice
  - forcing later txset validation calls to return `valid` after a node emits
    its first `PREPARE` in a configured ballot round
  - custom timeout parameters for nomination and balloting
- [`src/scp/test/DporScpInvestigationMain.cpp`](../src/scp/test/DporScpInvestigationMain.cpp)
  exposes that surface through flags such as:
  - `--stop-on-prepare`
  - `--stop-on-commit`
  - `--stop-on-externalize`
  - `--must-externalize`
    - full executions require an `EXTERNALIZE` envelope from every node, and a
      failing execution dumps its replay trace
  - `--check-agreement`
    - full executions require all observed `EXTERNALIZE` envelopes to agree on
      the externalized value, and a failing execution dumps its replay trace
  - `--with-nomination-timers`
  - `--with-balloting-timers`
  - `--init same|unique`
  - `--max-nomination-round`
  - `--max-balloting-round`
  - `--max-nomination-timers-round`
  - `--max-balloting-timers-round`
  - `--download-time`
  - `--txset-status`
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
  without running DPOR, and exits nonzero with the original exception message.
- The persisted artifact stores exact per-thread observed traces rather than a
  full schedule. Deeper traces with many envelope deliveries can grow
  noticeably because the envelope payloads are persisted as exact base64 XDR.
- [`src/scp/test/SCPDporSmokeTests.cpp`](../src/scp/test/SCPDporSmokeTests.cpp)
  currently contains 26 smoke tests. The checked-in coverage exercises:
  - deterministic first-step generation
  - initial envelope fanout
  - prepare-boundary discovery
  - commit-boundary exploration
  - externalize-boundary exploration
  - nomination-timer firing caps and round boundaries
  - balloting-round boundaries
  - replay-trace inspection
  - emitted-envelope inspection for missing externalize
  - full-execution externalization agreement checks
  - follower timer-before-delivery behavior
  - txset status-choice restore and preload behavior
  - txset wait-time restore and preload behavior
  - txset status latch-once-resolved replay behavior
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

I verified the current state directly in this tree:

- `make -n -C src stellar-core-dpor-tests scp-dpor-investigation` shows the
  DPOR targets compiling with `-I.../external/dpor/include -std=c++20
  -DFMT_CONSTEVAL=`.
- `./src/scp-dpor-investigation --depth 12` reported
  `kind=all-explored executions=3 full=0 error=0 depth-limit=3`.
- `./src/scp-dpor-investigation --stop-on-commit --depth 16` reported
  `kind=all-explored executions=10 full=0 error=0 depth-limit=10`.
- `./src/scp-dpor-investigation --stop-on-externalize --depth 16` reported
  `kind=all-explored executions=10 full=0 error=0 depth-limit=10`.
- `./src/scp-dpor-investigation --stop-on-commit --with-balloting-timers
  --max-balloting-timers-round 0 --depth 16` reported
  `kind=all-explored executions=10 full=0 error=0 depth-limit=10`.
- `./src/scp-dpor-investigation --txset-status waiting --download-time below
  --depth 12` reported
  `kind=all-explored executions=3 full=0 error=0 depth-limit=3`.
- `./src/scp-dpor-investigation --txset-status nondet --download-time nondet
  --depth 12` reported
  `kind=all-explored executions=40 full=1 error=0 depth-limit=39`.
- `./src/scp-dpor-investigation --check-agreement --txset-status nondet
  --download-time nondet --depth 12` reported
  `kind=all-explored executions=40 full=1 error=0 depth-limit=39`.
- `./src/scp-dpor-investigation --download-succeeds-in-round 1 --depth 12`
  reported `kind=all-explored executions=3 full=0 error=0 depth-limit=3`.
- `./src/scp-dpor-investigation --fail-on-first-terminal --depth 12` dumped
  replay traces for the first terminal execution, reported
  `kind=stopped executions=1 full=0 error=0 depth-limit=1`, and exited with
  `error: stopped at first terminal execution because
  --fail-on-first-terminal was set for smoke testing`.
- `./src/scp-dpor-investigation --stop-on-prepare --must-externalize
  --depth 12` exited with
  `error: full execution missing EXTERNALIZE envelope from node-index=0
  thread=0`, dumped the failing replay trace, and reported
  `kind=stopped executions=4 full=1 error=0 depth-limit=3`.
- `./src/stellar-core-dpor-tests "[scp][dpor][smoke]"` passed with 97
  assertions in 22 test cases.
- `./src/stellar-core-dpor-tests "scp dpor exploration finds a commit boundary"`
  passed after increasing that test's exploration depth to 60.
- `./src/stellar-core-dpor-tests "scp dpor exploration finds an externalize
  boundary"` passed.

## Current limitations

- DPOR is still isolated from the main binary and from `stellar-core test`, but
  it remains nested under the test build and still reuses a large portion of
  the normal object graph.
- The checked-in exploration model is still a three-node, single-slot SCP
  harness. There is not yet a broader family of scenarios or a multi-slot /
  ledger-closing model.
- Trace JSON load validates the artifact schema and per-trace invariants, but
  some default-scenario semantic checks are still deferred until replay builds
  `ScpDporDefaultScenario` from the stored options rather than being enforced
  entirely inside `loadTraceBundle()`.
- DPOR still depends on `BUILD_TESTS`; `--disable-tests --enable-dpor` is not
  supported.
