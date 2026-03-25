# DPOR Integration Status

Status snapshot as of 2026-03-25 for branch `skip-ledgers-p25-dpor-2`.

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
- Despite the current wording in [`DPOR.md`](../DPOR.md), the checked-in build
  still requires tests to remain enabled. `--disable-tests --enable-dpor`
  errors out in `configure.ac`, and the DPOR programs are declared under
  `if BUILD_TESTS` in [`src/Makefile.am`](../src/Makefile.am).
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
- The practical build entry point in this tree is:

  ```bash
  make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
  ```

## Support layer

- [`src/scp/test/ScpDporTypes.h`](../src/scp/test/ScpDporTypes.h) defines
  `ScpDporValue` and the DPOR aliases. The value kinds are:
  - envelope delivery
  - timer choice
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
  exposes boundary detection, and surfaces txset wait-time nondeterminism to
  the scenario layer.
- [`src/scp/test/ScpDporReplaySupport.h`](../src/scp/test/ScpDporReplaySupport.h)
  and
  [`src/scp/test/ScpDporReplaySupport.cpp`](../src/scp/test/ScpDporReplaySupport.cpp)
  provide stored baselines, thread-local cached nodes, and replay helpers for
  observed traces, including hidden txset wait-time choices. Replay semantics
  are also described in
  [`docs/dpor-replay-notes.md`](./dpor-replay-notes.md).
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
  - stopping at prepare boundaries or commit boundaries
  - nomination and balloting timer enablement
  - nomination and balloting round caps
  - timer-set limits
  - txset download wait-time modes: `always-valid`, `always-waiting`, and
    `nondet`
  - custom timeout parameters for nomination and balloting
- [`src/scp/test/DporScpInvestigationMain.cpp`](../src/scp/test/DporScpInvestigationMain.cpp)
  exposes that surface through flags such as:
  - `--stop-on-prepare`
  - `--stop-on-commit`
  - `--with-nomination-timers`
  - `--with-balloting-timers`
  - `--max-nomination-round`
  - `--max-balloting-round`
  - `--download-time`
  - `--fifo`
  - `--parallel` / `--workers`
  - `--print-stats`
  - `--dump-initial-steps`
  - `--dump-terminal-trace`
  - `--dump-terminal-replay-trace`
- `--scenario prepare-boundary|commit-boundary|nomination-timers` still exists
  as a compatibility shim, but the runner is now primarily flag-driven.
- [`src/scp/test/SCPDporSmokeTests.cpp`](../src/scp/test/SCPDporSmokeTests.cpp)
  currently contains 11 smoke tests. The checked-in coverage exercises:
  - deterministic first-step generation
  - initial envelope fanout
  - prepare-boundary discovery
  - commit-boundary exploration
  - nomination-timer and balloting-round boundaries
  - replay-trace inspection
  - follower timer-before-delivery behavior
  - txset wait-time restore and preload behavior

## Verification in this workspace

I verified the current state directly in this tree:

- `make -n -C src stellar-core-dpor-tests scp-dpor-investigation` shows the
  DPOR targets compiling with `-I.../external/dpor/include -std=c++20
  -DFMT_CONSTEVAL=`.
- `./src/scp-dpor-investigation --depth 12` reported
  `kind=all-explored executions=3 full=0 error=0 depth-limit=3`.
- `./src/scp-dpor-investigation --stop-on-commit --depth 16` reported
  `kind=all-explored executions=10 full=0 error=0 depth-limit=10`.
- `./src/stellar-core-dpor-tests "scp dpor exploration finds a commit boundary"`
  passed after increasing that test's exploration depth to 60.
- `./src/stellar-core-dpor-tests "[scp][dpor][smoke]"` passed with 42
  assertions in 11 test cases.

## Current limitations

- DPOR is still isolated from the main binary and from `stellar-core test`, but
  it remains nested under the test build and still reuses a large portion of
  the normal object graph.
- The checked-in exploration model is still a three-node, single-slot SCP
  harness. There is not yet a broader family of scenarios or a multi-slot /
  ledger-closing model.
- [`DPOR.md`](../DPOR.md) says DPOR no longer depends on `BUILD_TESTS`, but the
  actual build system still does.
