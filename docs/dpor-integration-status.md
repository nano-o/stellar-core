# DPOR Integration Status

Status snapshot as of 2026-07-23 for branch `dpor-on-master`, based on
upstream `master` (`f8b9c6eb2`, which includes the merged CAP-0083
empty-tx-set feature), against DPOR library commit `d2c06e7` (functionally
identical to the `b238b19` pin previously recorded here; the commits in
between are comment/doc-only).

The DPOR build now targets **post-CAP-0083 (empty-tx-set) `stellar-core`
only**. It must be configured with
`--enable-next-protocol-version-unsafe-for-production` so that `CAP_0083` is
defined globally and the empty-tx-set code path is compiled in. The earlier
pre-CAP-0083 build shape (with `CAP_0083` compiled out) is no longer a
supported configuration. The scenario layer models both CAP-0083 replacement
routes and keeps outright SCP-value invalidity separate from txset status.

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
  `protocolAllowsEmptyTxSetValues()` (always `true` in normal scenarios).
- The old branch's accept-commit guard (`throwIfValueInvalidForCommit`,
  which the error-capture smoke tests used as their SCP error source) does
  not exist on master. Master's equivalent
  (`throwIfValueInvalidForConfirmCommit`) fires at confirm-commit, where the
  harness's txset-status latch makes it unreachable: peers' CONFIRM
  envelopes are rejected while a value is only structurally valid, so a
  node can never ratify commit on a value it has not resolved as valid.
  The error-capture smoke tests instead use an explicitly test-only protocol
  gate fault injection, which makes
  SCP's `releaseAssert(protocolAllowsEmptyTxSetValues())` fire
  deterministically once a ballot envelope validates as only structurally
  valid. Normal scenarios do not expose or toggle this fault.
- Build target: the DPOR build targets post-CAP-0083 `stellar-core` only and
  is configured with `--enable-next-protocol-version-unsafe-for-production`,
  which defines `CAP_0083` globally. With `CAP_0083` defined,
  `BallotProtocol::maybeReplaceValueWithEmptyTxSet` and the rest of the
  empty-tx-set path are compiled in rather than stubbed out. `CAP_0083` must
  stay global: the DPOR binaries link non-DPOR objects from the normal build,
  and `CAP_0083` changes the `SCPDriver` vtable layout, so a
  DPOR-target-only `-DCAP_0083` would produce a silent vtable/ODR mismatch,
  not a build error. The configure flag routes the define through the global
  `AM_CPPFLAGS`, which the DPOR targets inherit
  (`..._CPPFLAGS = $(AM_CPPFLAGS) $(DPOR_CPPFLAGS)`), keeping the rebuilt SCP
  subset and the linked objects consistent. Do not hand-add `-DCAP_0083` to
  `DPOR_CXXFLAGS`.

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
- `external/dpor` is a submodule pinned to CPP-DPOR commit `d2c06e7`. The
  `--with-dpor-dir` override remains available for development against another
  checkout.
- Configure rejects `--enable-dpor` unless the next-protocol option is active,
  enforcing the post-CAP-0083 vtable/build contract.
- The required configure invocation for the DPOR build (post-CAP-0083 target)
  is:

  ```bash
  ./configure --enable-dpor \
    --enable-next-protocol-version-unsafe-for-production \
    CC=clang-20 CXX=clang++-20
  ```
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
- Those targets get `$(DPOR_CPPFLAGS)` and `$(DPOR_CXXFLAGS)` locally, and
  because they are declared as `..._CPPFLAGS = $(AM_CPPFLAGS) $(DPOR_CPPFLAGS)`
  they also inherit the global `AM_CPPFLAGS`. DPOR's own flags are not added to
  global `AM_CPPFLAGS`, and no DPOR sources are added to
  `stellar_core_SOURCES`. `CAP_0083` is deliberately the exception: it is a
  whole-build feature define that lives in global `AM_CPPFLAGS` (via the
  configure flag) precisely so the DPOR and non-DPOR objects agree on the
  `SCPDriver` vtable.
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

### Building with Namespace-backed sccache

Use `--enable-nsc-sccache` to cache the whole build, including the normal
C/C++ object graph, the DPOR-specific C++20 objects, and Rust compilation. It
implies `--enable-sccache`; do not combine it with `--enable-ccache`.

First authenticate `nsc` and confirm that the `sccache` selected from `PATH`
was built with WebDAV support:

```bash
nsc auth check-login
sccache --help | sed -n '/Enabled features:/,$p'
```

Then configure and build:

```bash
./autogen.sh
./configure --enable-dpor \
  --enable-next-protocol-version-unsafe-for-production \
  --enable-nsc-sccache \
  CC=clang-20 CXX=clang++-20
make -C lib -j"$(nproc)"
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
```

Configure runs `nsc cache sccache setup --cache_name stellar`, restarts the
`sccache` daemon with the resulting WebDAV credentials, and fails if
`sccache -s` does not report a WebDAV cache location. If stopping the daemon
reports a protocol-decoding error after upgrading `sccache`, an older daemon
is still running; stop it with the client version that started it (or terminate
it after confirming no build is active), then rerun configure.

## Support layer

- [`src/scp/test/ScpDporTypes.h`](../src/scp/test/ScpDporTypes.h) defines
  `ScpDporValue` and the DPOR aliases. The value kinds are:
  - envelope
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
  - txset validation-status modes: `valid`, `downloading`, `invalid`, and
    `nondet`
    - in `valid` mode, status choices explore `downloading` and `valid`
    - in `invalid` mode, status choices explore `downloading` and `invalid`
    - in `nondet` mode, status choices explore `valid`, `downloading`, and
      `invalid`
    - in the branching modes above, status choices reoccur only while the last
      result for a value is `downloading`; once a value resolves to `valid` or
      `invalid`, later queries on that node reuse the same result without
      another DPOR choice
    - `invalid` means a downloaded-invalid txset: validation remains
      structurally valid, the download wait hook returns no value, and SCP
      immediately ballots on the derived empty-tx-set value
  - nomination-only forced downloading for txset validation, so
    nomination-path queries return structurally valid without consuming a
    txset-status choice while
    ballot-path validation still follows the configured status mode
  - in `nondet` wait-time mode, choices reoccur only while the last wait-time
    result for a value is still below the download timeout; once a value times
    out, later queries on that node reuse the timed-out result without another
    DPOR choice
  - forcing later txset validation calls for that ballot value to return
    `valid` after a node emits its first non-empty `PREPARE` in a configured
    ballot round; resolution is isolated per value
  - deterministic per-node outright-invalid value sets, kept separate from
    txset status so malformed values are rejected without empty-txset
    replacement
  - an explicitly test-only protocol-gate fault injection, which makes SCP's
    `releaseAssert(protocolAllowsEmptyTxSetValues())` fire once a ballot
    envelope validates as only structurally valid; the error-capture smoke
    tests use this as their deterministic SCP error source, and the
    investigation runner does not expose it
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
  - `--nomination-always-downloading`
    - `--nomination-always-waiting` remains a compatibility alias
  - `--invalid-proposer N`
    - with unique initial values, every other node rejects proposer `N`'s
      value as outright invalid while the proposer can still emit it
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
  - nomination-only forced downloading for txset validation
  - `download-succeeds-in-round` forcing later txset validation to `valid`
  - investigation-style wrapping of thread exceptions into inspectable DPOR
    error executions
  - replay-trace inspection preserving the lead-in when SCP throws during
    replay
  - JSON version-2 round-trips for scenario options, per-node
    outright-invalid mappings, and raw per-thread traces
  - explicit rejection of semantically incompatible version-1 traces
  - timeout-driven and downloaded-invalid empty-txset replacement
  - outright-invalid nomination and ballot rejection without replacement
  - empty-txset nomination-versus-ballot validation
  - per-value txset download resolution
  - trace-bundle write/load/replay of a captured error execution
  - capturing an SCP `releaseAssert` as a DPOR error execution with file:line
    context

## Verification in this workspace

Verified directly in this tree with the post-CAP-0083 configure and build:

- `make -C src -j8 stellar-core-dpor-tests scp-dpor-investigation` completed;
  emitted DPOR compile lines contained global `-DCAP_0083` plus target-local
  `-std=c++20 -DFMT_CONSTEVAL= -DSTELLAR_DISABLE_LOGGING`.
- A disposable clean configure with `--enable-dpor` but without
  `--enable-next-protocol-version-unsafe-for-production` failed with
  `--enable-dpor requires
  --enable-next-protocol-version-unsafe-for-production`.
- `./src/stellar-core-dpor-tests "[scp][dpor][smoke]"` passed with 251
  assertions in 39 test cases.
- `./src/scp-dpor-investigation --txset-status invalid --stop-on-prepare
  --depth 12` reported
  `kind=all-explored executions=16 full=0 blocked=0 error=0 depth-limit=16`.
- `./src/scp-dpor-investigation --txset-status downloading --download-time
  above --stop-on-prepare --depth 12` reported
  `kind=all-explored executions=4 full=0 blocked=1 error=0 depth-limit=3`.
- `./src/scp-dpor-investigation --txset-status downloading --download-time
  below --depth 12` reported
  `kind=all-explored executions=3 full=0 blocked=0 error=0 depth-limit=3`.
- `./src/scp-dpor-investigation --init unique --invalid-proposer 0 --depth 12`
  reported
  `kind=all-explored executions=1 full=0 blocked=1 error=0 depth-limit=0`.
- `./src/scp-dpor-investigation --txset-status nondet --download-time nondet
  --depth 12` reported
  `kind=all-explored executions=46 full=0 blocked=0 error=0 depth-limit=46`.
- The same nondeterministic command with `--parallel --workers 4` reported
  identical counts.
- `--txset-status waiting` and `--nomination-always-waiting` remain accepted as
  CLI compatibility aliases, while `--invalid-proposer 0` without
  `--init unique` fails with the intended validation error.
- `--fail-on-first-terminal --trace-dir ... --txset-status invalid --depth 12`
  wrote a version-2 trace bundle, and
  `--replay-trace-json ... --replay-node all` reloaded and replayed every node
  successfully.

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
