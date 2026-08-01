# DPOR Integration Status

Status snapshot as of 2026-07-31 for branch `dpor-on-master` at `4c89f7a03`,
rebased onto upstream `master` (`4c0d88c75`), with `external/dpor` pinned to
DPOR library commit `febae6f`.

The DPOR build targets **post-CAP-0083 (empty-tx-set) `stellar-core`**, which
is now simply `master`: upstream's "Ungate CAP-0083 and CAP-0085, bump to
protocol 28" (#5397) removed the `CAP_0083` automake conditional, the
`-DCAP_0083` define, and every `#ifdef CAP_0083` guard, so the empty-tx-set
code path is compiled in unconditionally. `--enable-dpor` therefore no longer
requires `--enable-next-protocol-version-unsafe-for-production`, and
`configure` no longer enforces that pairing; the pre-CAP-0083 build shape is
not merely unsupported but no longer expressible. The scenario layer models
CAP-0083 timeout replacement and keeps outright SCP-value invalidity separate
from txset status.

This branch is the port of the DPOR work from `skip-ledgers-p26-dpor` onto
master. The old branch's 18 skip-ledgers feature commits were dropped
(superseded by master's CAP-0083 merge); only the DPOR work was ported. The
port adapted the harness to master's renamed driver API:

- `makeSkipLedgerValueFromValue` / `isSkipLedgerValue` became
  `makeEmptyTxSetValueFromValue` and `isEmptyTxSetValue`, with an `EMPTY:`
  payload prefix in `DporScpNode`. Both are now unconditional pure virtuals in
  `SCPDriver.h`; the `#ifdef CAP_0083` that once wrapped the first one was
  removed when upstream ungated CAP-0083.
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
- Build target: the DPOR build targets post-CAP-0083 `stellar-core`, which is
  now plain `master` — `BallotProtocol::maybeReplaceValueWithEmptyTxSet` and
  the rest of the empty-tx-set path are compiled in unconditionally, with no
  configure flag required. The invariant that motivated the old
  `--enable-next-protocol-version-unsafe-for-production` requirement still
  applies to any **future** protocol define that alters the `SCPDriver` vtable:
  it must be routed through the global `AM_CPPFLAGS`, which the DPOR targets
  inherit (`..._CPPFLAGS = $(AM_CPPFLAGS) $(DPOR_CPPFLAGS)`), and never added
  to `DPOR_CXXFLAGS` alone. The DPOR binaries link non-DPOR objects from the
  normal build, so a DPOR-target-only vtable-affecting define produces a silent
  vtable/ODR mismatch rather than a build error.

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
- `external/dpor` is a submodule pinned to CPP-DPOR commit `febae6f`. The
  `--with-dpor-dir` override remains available for development against another
  checkout.
- Configure no longer couples `--enable-dpor` to the next-protocol option.
  That check existed only to guarantee `CAP_0083` was defined; with CAP-0083
  ungated upstream there is nothing left to enforce.
- The configure invocation for the DPOR build is:

  ```bash
  ./configure --enable-dpor --enable-nsc-sccache CC=clang-20 CXX=clang++-20
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
  `stellar_core_SOURCES`. Whole-build feature defines that affect the
  `SCPDriver` vtable are the deliberate exception to that isolation: they must
  live in global `AM_CPPFLAGS` precisely so the DPOR and non-DPOR objects
  agree on the vtable. `CAP_0083` used to be one; upstream has since ungated
  it, so there is currently no such define in play.
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
  remains payload-only. Envelope values share an immutable envelope payload
  with a precomputed content digest, so copying a graph value is normally a
  reference-count increment rather than a deep copy. A null payload retains
  the old semantics of a default-constructed inline envelope for equality,
  ordering, and hashing.
- [`src/scp/test/ScpDporBridge.h`](../src/scp/test/ScpDporBridge.h) owns the
  encode/decode helpers and pretty-printing between SCP objects and
  `ScpDporValue`.
- [`src/scp/test/DporScpNode.h`](../src/scp/test/DporScpNode.h) and
  [`src/scp/test/DporScpNode.cpp`](../src/scp/test/DporScpNode.cpp) implement
  the deterministic `SCPDriver` used by DPOR. The node snapshots and restores
  slot state, tracks pending and optionally recorded emitted envelopes, tracks
  timers and timer-set counts, exposes boundary detection, and surfaces txset
  validation-status and wait-time nondeterminism to the scenario layer.
  Repeated restores reuse immutable wrapped baseline values keyed by a snapshot
  identity, and quorum-set lookup has a single-entry memo invalidated by
  `storeQuorumSet()`.
- [`src/scp/test/ScpDporReplaySupport.h`](../src/scp/test/ScpDporReplaySupport.h)
  and
  [`src/scp/test/ScpDporReplaySupport.cpp`](../src/scp/test/ScpDporReplaySupport.cpp)
  provide stored baselines, per-worker caches of partially replayed nodes, and
  replay helpers for observed traces, including hidden txset status and
  wait-time choices. Valid replay cursors resume the longest matching consumed
  prefix and memoize the label at their stopping step; a partially applied
  nondeterministic-choice step deliberately invalidates its cursor. Replay
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
  - txset validation-status modes: `always-valid`,
    `downloading-then-valid`, and `always-downloading`
    - `always-valid` and `always-downloading` return their named status
      deterministically without a DPOR choice
    - in `downloading-then-valid` mode, status choices explore `downloading`
      and `valid`
    - choices reoccur only while the last result for a value is `downloading`;
      once a value resolves to `valid`, later queries on that node reuse the
      same result without another DPOR choice
    - downloaded-invalid txsets are not modeled, so a downloading status stays
      eligible for a download wait time rather than resolving to a missing
      wait time
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
  - `--invalid-proposer N`
    - with unique initial values, every other node rejects proposer `N`'s
      value as outright invalid while the proposer can still emit it
  - `--download-succeeds-in-round`
  - `--fifo`
  - `--parallel` / `--workers`
    - the runner defaults to **one worker**, and parallel exploration is
      selected only when `--workers > 1`; `--workers 0` takes the serial
      `verify()` path rather than the engine's `hardware_concurrency()`
      default. Only `--parallel` selects host concurrency.
    - the serial default is deliberate and stays: making ordinary debugger and
      smoke-test invocations parallel would change event ordering and fail-fast
      behavior for every existing workflow
    - prefer an explicit `--workers N`. See
      [Parallel scaling](#parallel-scaling) for what to set it to.
  - `--print-stats`
  - `--fail-on-first-blocked`
    - continues past full executions, then stops at the first blocked
      execution, writes a JSON trace focused on the first blocked node, dumps
      replay traces, and exits nonzero
    - also exits nonzero, with a diagnostic naming the depth and the
      depth-limit count, if no blocked execution is found at all -- that run
      captured nothing and must not look like a pass
  - `--fail-on-first-terminal`
    - likewise exits nonzero if no terminal execution is found
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
  thread first, can fail fast on either the first blocked execution or the
  first terminal execution, can write the first captured terminal execution
  as a structured JSON artifact into `--trace-dir` (default `dpor-traces`),
  prints the chosen path as `trace-json=...`, can reload that artifact for
  deterministic replay without rerunning DPOR, and exits nonzero with the
  recorded failure message.
- The summary line and `--print-stats` progress lines report the blocked
  count (`blocked=` / `blocked_executions=`) alongside full, error, and
  depth-limit counts, and trace bundles serialize the `blocked` terminal kind.
- A node's first boundary envelope is fanned out before its scenario thread
  stops. This is especially important at the externalize boundary: peers can
  consume the `EXTERNALIZE` message needed to finish instead of becoming
  artificially blocked after the sender reaches its local boundary.
- The investigation runner registers the library's `on_fatal_error` hook and
  prints the fatal exception message plus a `format_graph` rendering of the
  in-progress execution graph to stderr before the exception propagates.
- The persisted artifact stores exact per-thread observed traces rather than a
  full schedule. Deeper traces with many envelope deliveries can grow
  noticeably because the envelope payloads are persisted as exact base64 XDR.
  Reload uses the stored scenario options and thread traces with the existing
  harness replay seam rather than reconstructing a DPOR schedule.
- [`src/scp/test/bench-dpor.sh`](../src/scp/test/bench-dpor.sh) is the checked-in
  performance and correctness harness. Its `check` mode prints exact final
  execution counts for 13 scenarios; those lines are a semantic fingerprint
  and must match byte-for-byte across a performance-only change. `bench` times
  four terminating workloads, and `head` reports throughput over a time-boxed
  externalize-boundary run.
- [`src/scp/test/SCPDporSmokeTests.cpp`](../src/scp/test/SCPDporSmokeTests.cpp)
  contains DPOR smoke tests. The checked-in coverage exercises:
  - deterministic first-step generation
  - payload-less envelope value equality, ordering, and hash compatibility
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
  - JSON version-4 round-trips for scenario options, per-node
    outright-invalid mappings, and raw per-thread traces
  - explicit rejection of semantically incompatible version-1 through
    version-3 traces
  - timeout-driven empty-txset replacement
  - outright-invalid nomination and ballot rejection without replacement
  - empty-txset nomination-versus-ballot validation
  - per-value txset download resolution
  - trace-bundle write/load/replay of a captured error execution
  - capturing an SCP `releaseAssert` as a DPOR error execution with file:line
    context

## Performance status

Commit `4c89f7a03`, together with the pinned engine commit `5f48e8b`, removes
the dominant replay and graph-materialization costs without changing the
explored execution set. On the three-node FIFO externalize workload used by
`bench-dpor.sh head` (`downloading-then-valid`, nomination forced downloading,
nondeterministic download time, depth 200, eight workers), paired same-session
medians moved from about 14.5k to about 140k executions/second. Parallel CPU
utilization remained about 782% out of 800%.

The headline improvement combines two layers: prefix-resuming SCP replay and
shared envelope payloads in stellar-core, plus masked FIFO tiebreaking, cheaper
restriction/revisit paths, CSR PORF adjacency, flat vector clocks, and reusable
scratch storage in the engine. Throughput measurements are machine-sensitive;
the execution-count fingerprint is not and must remain exact.

### Parallel scaling

Two engine scheduler changes (see
[docs/dpor-parallel-scaling-plan.md](dpor-parallel-scaling-plan.md)) removed a
pathology in which more workers made exploration *slower*. Measured on
`addict-glad-64ta` (16 physical cores / 32 logical, SMT2), paired same-session
medians, with the 13-scenario `bench-dpor.sh check` fingerprint byte-identical
across all three engines:

S1 — send-heavy (`--txset-status always-valid --download-time below
--stop-on-externalize --depth 200`, 5,600,446 executions):

| workers | before | + wake fix | final |
|---|---|---|---|
| 1 | 169.1s (1.00x) | 172.9s | 168.0s |
| 8 | 35.3s (4.79x) | 34.0s (4.98x) | 31.2s (5.42x) |
| 16 | 23.4s (7.23x) | 21.7s (7.78x) | 19.3s (8.76x) |
| 32 | 26.8s (**6.31x**) | 18.7s (9.02x) | 16.0s (**10.60x**) |

S2 — reads-from/ND-heavy (`--txset-status downloading-then-valid
--nomination-always-downloading --download-time nondet --stop-on-externalize
--depth 56`, 1,278,277 executions):

| workers | before | + wake fix | final |
|---|---|---|---|
| 1 | 21.5s (1.00x) | 21.5s | 21.4s |
| 8 | 8.6s (2.51x) | 8.2s (2.63x) | 4.4s (4.90x) |
| 16 | 10.8s (1.99x) | 6.8s (3.16x) | 2.6s (8.13x) |
| 32 | 34.7s (**0.62x**) | 6.8s (3.14x) | 1.9s (**11.11x**) |

Speedups are against the pre-change binary at one worker; the `w=1` column
doubles as a control, since `--workers 1` takes the serial `verify()` path that
none of these changes touch. Both scenarios now improve monotonically through
32 workers, and SMT contributes a further 17-21% beyond the 16 physical cores,
so **there is no longer a knee to avoid**:

- Pass an explicit `--workers N`. Set `N` to the logical CPU count for the
  fastest wall-clock, or to the physical core count to leave headroom for other
  work on a shared machine.
- The old interim guidance of `--workers 8` is obsolete; it was a workaround for
  the scheduler pathology, not a property of the workload.

`bench-dpor.sh scale` is an opt-in regression check for exactly this. It is not
part of any default run, and it only asserts on one machine shape (16 usable
SMT2 physical cores presenting 32 logical CPUs, with a CPU bandwidth quota
covering all 32), which it constructs with an affinity mask rather than merely
requiring. Everywhere else it prints the curve and asserts nothing.

## Verification in this workspace

The build shape was verified with a clean reconfigure after rebasing onto
`4c0d88c75` (upstream post-CAP-0083-ungating master). The runtime suites and
execution fingerprint were rerun at `4c89f7a03` with the optimized `5f48e8b`
engine:

- `./configure --enable-dpor --enable-nsc-sccache CC=clang-20 CXX=clang++-20`
  (no next-protocol flag), `make clean`, `make -C lib`, then
  `make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation`
  completed. Emitted DPOR compile lines carry target-local
  `-std=c++20 -DFMT_CONSTEVAL= -DSTELLAR_DISABLE_LOGGING`, contain no
  `-DCAP_0083` anywhere in the build, and pick up master's new global
  `-DXDRPP_STRONG_ORDER=1`.
- `./src/stellar-core-dpor-tests "[scp][dpor][smoke]"` passed with 246
  assertions in 42 test cases.
- `./src/stellar-core-dpor-tests "[scp]"` passed with 1,607,931 assertions in
  52 test cases.
- The standalone DPOR suite passed 279/279 tests in the current engine
  checkout, including the follow-up sparse ordered-import regressions.
- `./src/scp/test/bench-dpor.sh check` reproduced the complete 13-scenario
  execution-count fingerprint exactly.
- `./src/scp-dpor-investigation --txset-status always-valid --depth 6`
  reported
  `kind=all-explored executions=1 full=0 blocked=0 error=0 depth-limit=1`.
- `./src/scp-dpor-investigation --txset-status downloading-then-valid
  --depth 6` reported
  `kind=all-explored executions=3 full=0 blocked=0 error=0 depth-limit=3`.
- `./src/scp-dpor-investigation --txset-status always-downloading
  --download-time above --stop-on-prepare --depth 12` reported
  `kind=all-explored executions=4 full=0 blocked=0 error=0 depth-limit=4`.

  > This entry previously recorded
  > `executions=4 full=0 blocked=1 error=0 depth-limit=3`. That number was
  > stale rather than changed by the rebase: "refine DPOR investigation
  > scenarios" made the runner broadcast boundary envelopes before stopping,
  > which lengthens every `--stop-on-prepare` execution, but it renamed
  > `--txset-status downloading` to `always-downloading` without re-running
  > this case. The extra boundary broadcasts push the formerly-blocked
  > execution past a depth-12 cap, so it is now classified `depth-limit`
  > instead of `blocked`. Upstream's only SCP changes in this range were the
  > removal of `#ifdef CAP_0083` guards, which were no-ops in a build that
  > already defined `CAP_0083`.

- In that same scenario, blocked executions first appear at `--depth 18`
  (`blocked=2`). Depths 13-17 report `blocked=0`. For reference:
  `--depth 20` gives
  `executions=55 full=4 blocked=2 error=0 depth-limit=49`, and `--depth 24`
  gives `executions=83 full=46 blocked=4 error=0 depth-limit=33`. Any
  blocked-execution check on this scenario needs depth >= 18.
- `./src/scp-dpor-investigation --txset-status always-downloading
  --download-time below --depth 12` reported
  `kind=all-explored executions=3 full=0 blocked=0 error=0 depth-limit=3`.
- `./src/scp-dpor-investigation --init unique --invalid-proposer 0 --depth 12`
  reported
  `kind=all-explored executions=1 full=0 blocked=1 error=0 depth-limit=0`.
- The obsolete `--txset-status valid`, `downloading`, `invalid`, `waiting`,
  `downloading-then-invalid`, and `nondet` values are rejected with
  `error: unknown txset-status mode: ...`; `--nomination-always-waiting` exits
  nonzero as an unknown flag; and `--invalid-proposer 0` without
  `--init unique` fails with
  `error: --invalid-proposer requires unique initial values; use --init unique`.
- `--fail-on-first-terminal --trace-dir ... --txset-status
  downloading-then-valid --depth 12` reported `terminal-kind=error
  node-index=0 thread=0` and `kind=stopped executions=1`, exited 1, and wrote
  a version-4 trace; `--replay-trace-json ... --replay-node all` reloaded and
  replayed every node successfully (exit 0).
- `--fail-on-first-blocked --trace-dir ... --txset-status always-downloading
  --download-time above --stop-on-prepare --depth 20` reported
  `terminal-kind=blocked leader-boundary=true` and
  `kind=stopped executions=52 full=2 blocked=1 error=0 depth-limit=49`, exited
  1, and wrote a version-4 trace focused on the first blocked node;
  `--replay-trace-json ... --replay-node all` replayed every node
  successfully (exit 0).
- At the previously documented `--depth 12` that same invocation finds no
  blocked execution. It now reports
  `error: --fail-on-first-blocked was set but no matching execution was found
  in 4 executions at --depth 12, so no trace was captured; 4 execution(s) hit
  the depth limit, so a greater --depth may reach a blocked execution` and
  exits 1. Previously it exited 0, which made a too-shallow depth
  indistinguishable from a clean run -- see "Capture modes fail when they
  capture nothing" below.

### Capture modes fail when they capture nothing

`--fail-on-first-blocked` and `--fail-on-first-terminal` are capture tools:
each stops at the first matching execution, writes its JSON trace, and exits
nonzero. If exploration completes without ever matching, nothing is written --
and the runner used to exit 0, which is indistinguishable from a clean run. A
depth too shallow to reach the target state therefore turned the whole check
into a silent no-op.

Both modes now exit 1 with an explicit diagnostic when they match nothing,
naming the flag, the execution count, and the depth; the blocked variant also
reports how many executions hit the depth limit, since that is the usual
reason a blocked execution is out of reach. Runs with no capture flag are
unaffected and still exit 0.

The depth budget itself is pinned by the smoke test `scp dpor stop-on-prepare
reaches a blocked execution`, which asserts that the stop-on-prepare scenario
finds no blocked execution at depth 12 (only depth-limited ones) and does find
one at depth 18. That guards against the failure mode that produced the stale
number above: boundary-envelope broadcasting lengthened these executions, and
nothing caught that the documented depth had stopped reaching the blocked
state.

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
