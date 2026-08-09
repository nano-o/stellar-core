# DPOR Integration Status

Status snapshot as of 2026-08-09 for branch `dpor-on-master`, with
`external/dpor` pinned to DPOR library commit `b439a72`. Entries below that
quote an earlier engine pin are dated verification records, not stale claims
about the current pin.

The engine at this pin has been through the simplification refactoring
(batches 0-7; see `external/dpor/docs/simplification_refactoring_progress.md`).
Two changes there are visible from this repo:

- `VerifyResult` reports its per-kind terminal counts through a `terminals`
  member — `result.terminals.full()`, `.blocked()`, `.error()`,
  `.depth_limit()`, `.thread_event_limit()` — instead of five separate
  `*_executions_explored` fields. The DPOR harness and the `configure.ac`
  probe were updated with it.
- `dpor/algo/dpor.hpp` is now the entry point only; the implementation lives
  under `dpor/algo/detail/` and the public types in
  `dpor/algo/verify_result.hpp`. Including `dpor/algo/dpor.hpp` is still all a
  consumer needs, so the include in the harness is unchanged.

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
so `--must-externalize` and `--check-agreement` coverage is unchanged.
`DepthLimit` and the newer `ThreadEventLimit` are outside that union by
construction, which is what keeps a truncated branch from being mistaken for a
complete interleaving. The
library also introduced a typed exception hierarchy (`dpor/errors.hpp`), a
`format_graph` helper (`dpor/model/format.hpp`), and an `on_fatal_error`
diagnostic hook; the harness's existing exception-to-`ErrorLabel` wrapping
already matches the new error-reporting contract, and the investigation runner
wires `on_fatal_error` to dump the in-progress execution graph on fatal
library or harness errors.

## Build integration

- [`configure.ac`](../configure.ac) adds `--enable-dpor`,
  `--with-dpor-dir`, `DPOR_DIR`, `DPOR_CPPFLAGS`, `DPOR_CXXFLAGS`, the
  `ENABLE_DPOR` automake conditional, and two compile probes: one that builds
  `<dpor/algo/dpor.hpp>` with the configured target flags, and one that
  `static_assert`s on `dpor::algo::TerminalExecutionKind::Blocked` and reads
  `VerifyResult::terminals` so an engine checkout that predates the
  blocked-execution API, the per-thread event bound, or the `terminals`
  breakdown fails configure with an explicit message pointing at the pinned
  submodule revision.
- Configure looks for DPOR in `external/dpor` first and `../dpor` second. The
  default DPOR target flags are `-std=c++20 -DFMT_CONSTEVAL=
  -DSTELLAR_DISABLE_LOGGING`.
- `external/dpor` is a submodule pinned to CPP-DPOR commit `b439a72`. Earlier pins sat on the `dpor-perf` branch, off
  `main`, so that branch was the only thing keeping them fetchable; `main` has
  since been fast-forwarded onto that line, and `dpor-perf` is now a stale
  pointer at the older `febae6f`. The `--with-dpor-dir` override remains
  available for development against another checkout.
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
  nondeterministic-choice step deliberately invalidates its cursor. The cache
  retains 64 partially replayed nodes per validator and worker by default; the
  investigation runner can override that operational capacity without changing
  the trace or scenario semantics. Replay semantics are also described in
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
    - a value's status is decided at most once per external event, so the
      several `validateValue` calls SCP makes for one value while handling a
      single envelope or timer firing share one answer and one DPOR choice
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
  - in `nondet` wait-time mode, a value's wait time is likewise decided at most
    once per external event, and choices reoccur only while the last wait-time
    result for a value is still below the download timeout; once a value times
    out, later queries on that node reuse the timed-out result without another
    DPOR choice
  - forcing txset validation calls for that ballot value to return `valid`
    from the next external event onward, after a node emits its first
    non-empty `PREPARE` in a configured ballot round; resolution is isolated
    per value, and the deferral by one event is what keeps a download that
    completes mid-handler from flipping a verdict inside the handler that
    caused it
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
  - either check exits **2** with an `inconclusive:` message when the run had
    no maximal execution at all, since neither check then evaluated anything.
    Exit 2 is distinct from the exit 1 used for a genuine violation, and a real
    violation returns 1 first, so exit 2 only ever means "never evaluated". See
    [Property checks are inconclusive, not passing, when nothing was
    maximal](#property-checks-are-inconclusive-not-passing-when-nothing-was-maximal)
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
  - `--replay-slots-per-node N`
    - positive per-validator, per-worker replay-cache capacity; defaults to 64
    - this is an investigation/performance option, not a scenario option, and
      therefore is not serialized in replay traces
    - a measured 1/4/8/16/32/64 sweep retained the default: smaller values can
      lower RSS but did not improve absolute executions/s; see
      [the scaling plan](dpor-parallel-scaling-plan.md#follow-up-phase-9-bound-replay-working-set--measured-no-default-change)
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
  - `--depth N`
    - bounds DPOR **search-tree** depth, not event-graph size: ordinary forward
      steps and backward revisits both consume it, and a backward revisit
      builds a child with *fewer* events than its parent at depth+1. It is also
      a single budget shared across all nodes, so it grows with the number of
      interleavings rather than with how far any node got.
  - `--thread-event-depth N|-1`
    - bounds the events any single node may contribute -- a per-node step
      budget rather than a search-tree budget. Each node is capped
      independently, so reaching the cap on one node does not truncate the
      others. Reaches the engine as `DporConfigT::max_thread_events`.
    - executions the cap may have truncated are published as the
      `thread-event-limit` terminal kind, counted in `thread-event-limit=` /
      `thread_event_limit_executions=`, and excluded from `isMaximalExecution`,
      so `--must-externalize` and `--check-agreement` skip them rather than
      failing on a truncated run.
    - the kind is conservative: it means the engine *declined to ask* at least
      one node whether it had a further event, so it reads "may be truncated",
      not "was truncated". A node that would naturally have finished at exactly
      step N is indistinguishable from a truncated one without making the call
      the bound exists to avoid.
    - setting the flag raises `--depth` to 1000 unless `--depth` is also
      passed, because the default `--depth 12` would otherwise truncate first.
      `-1` means unlimited and, since the raise keys on the option being set,
      leaves `--depth` alone; an A/B between the two should pass `--depth`
      explicitly. `0` is rejected -- it would mean no node ever runs.
    - interaction to know about: an execution with both a capped node and a
      blocked node is now `thread-event-limit`, not `blocked`, so
      `--fail-on-first-blocked` combined with a cap can find nothing.
    - operational, not a scenario option: it is not serialized in replay traces.
  - engine and diagnostic tuning knobs that do not change the explored
    execution set: `--max-queued-tasks`, `--sync-steps`,
    `--split-poll-interval-steps`, `--progress-counter-flush-interval`,
    `--progress-poll-interval-steps`, and `--serialize-terminal-callbacks`
    (which runs terminal observer bodies under one mutex to isolate callback
    concurrency). The first five reach the engine only through
    `ParallelVerifyOptions`, so they are inert on the serial path. Like
    `--replay-slots-per-node`, these are operational rather than scenario
    options and are not serialized in replay traces.
  - `--help` / `-h` prints the full current surface, including the plural
    aliases accepted for the four `--max-*-round` flags
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
- Both lines also report the per-thread event bound's two keys, unconditionally
  and whether or not `--thread-event-depth` was passed:
  `thread-event-limit=` / `thread_event_limit_executions=` and
  `max-thread-event-depth=` / `max_thread_event_depth=`. The maximum is taken
  over *published terminal executions*, not over every transient graph, so
  under an early stop it is only a whole-space maximum if exploration ran to
  completion. Engine-injected `Block` events count toward it, so a node that
  blocks at step N-1 reports N; the bound is therefore never exceeded. On
  `--workers N` runs the progress-line value lags by up to
  `--progress-counter-flush-interval` terminals per worker -- the same caveat
  `counts_exact=false` already signals for the counts -- while the summary
  value is exact.
  Reading it without a bound set is the way to pick one: an unbounded run
  reports how deep the deepest node actually got.
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
  - txset wait-time latch-once-timed-out behavior, a wait time answered before
    validation, and repeated wait-time queries answered consistently
  - one txset status choice per value per external event, replay rejection of a
    txset choice the event never requests, and rejection of replay snapshots
    taken inside an external event or after an implicit txset decision
  - nomination-only forced downloading for txset validation
  - `download-succeeds-in-round` forcing later txset validation to `valid`, and
    its deferral of that resolution to the next external event
  - configurable replay-cache capacity
  - four-validator configuration and the same/unique initial-value presets
  - absence of error executions under bounded eventually-valid txsets
  - identification of the first blocked node
  - rejection of malformed outright-invalid scenario mappings and of trace
    bundles naming removed txset status modes
  - investigation-style wrapping of thread exceptions into inspectable DPOR
    error executions
  - replay-trace inspection preserving the lead-in when SCP throws during
    replay
  - JSON version-8 round-trips for scenario options, per-node
    outright-invalid mappings, and positional raw per-node traces
  - explicit rejection of every non-version-8 trace bundle
  - timeout-driven empty-txset replacement
  - outright-invalid nomination and ballot rejection without replacement
  - empty-txset nomination-versus-ballot validation
  - per-value txset download resolution
  - trace-bundle write/load/replay of a captured error execution
  - capturing an SCP `releaseAssert` as a DPOR error execution with file:line
    context

## Performance status

Commit `4c89f7a03`, together with engine commit `5f48e8b` (the pin at the time,
since superseded by `23e1998` and then the current `febae6f`), removes the
dominant replay and graph-materialization costs without changing the explored
execution set. On the three-node FIFO externalize workload used by
`bench-dpor.sh head` (`downloading-then-valid`, nomination forced downloading,
nondeterministic download time, depth 200, eight workers), paired same-session
medians moved from about 14.5k to about 140k executions/second. Parallel CPU
utilization remained about 782% out of 800%.

The headline improvement combines two layers: prefix-resuming SCP replay and
shared envelope payloads in stellar-core, plus masked FIFO tiebreaking, cheaper
restriction/revisit paths, CSR PORF adjacency, flat vector clocks, and reusable
scratch storage in the engine. Throughput measurements are machine-sensitive;
the execution-count fingerprint is not and must remain exact.

### Per-event txset decisions

Scoping the modeled txset status and download wait time to one external event
cut the state space of the nondeterministic scenarios rather than the cost per
execution. `bench-dpor.sh check`, before and after:

| scenario | before | after |
|---|---|---|
| C1 | 1336 | 460 |
| C3 | 704 | 250 |
| C6 | 10954 | 3346 |
| CA | 704 | 250 |
| CB | 90530 | 83846 |
| CC | 90208 | 45381 |

The other seven scenarios use only deterministic txset modes and are
byte-identical. That split is the point: the reduction comes from removing
branch points a single handler cannot actually take, not from exploring less of
the protocol.

Wall clock, medians of five alternating runs in one session at `--workers 8`,
with a byte-identical copy of the baseline binary run as a control to establish
the noise floor (its ratios are in parentheses):

| scenario | before | after | ratio |
|---|---|---|---|
| 3-node FIFO externalize, depth 56 | 4.448 s | 2.764 s | 0.62x (control 0.94x) |
| CC, depth 46 | 0.337 s | 0.174 s | 0.52x (control 1.00x) |
| CB, depth 40 | 0.154 s | 0.133 s | 0.86x (control 1.00x) |

Deterministic scenarios show no measurable change: over nine alternating runs
each, C5, C7, CD and C4 came in at 1.01x, 1.03x, 1.01x and 0.91x, all inside
the 0.91x-1.06x band the identical-binary control produced on the same runs.
The per-event decision adds a map lookup per driver call and saves nothing when
nothing branches, so "no measurable change" is the expected result there rather
than a null finding.

### Parallel scaling

Two engine scheduler changes (see
[docs/dpor-parallel-scaling-plan.md](dpor-parallel-scaling-plan.md)) removed a
pathology in which more workers made exploration *slower*. Measured on
`addict-glad-64ta` (16 physical cores / 32 logical, SMT2), paired same-session
medians, with the 13-scenario `bench-dpor.sh check` fingerprint byte-identical
across all three engines:

S1 — send-heavy (`--txset-status always-valid --download-time below
--stop-on-externalize --depth 200`, 5,600,446 executions — still exact today,
since S1 uses only deterministic txset modes):

| workers | before | + wake fix | final |
|---|---|---|---|
| 1 | 169.1s (1.00x) | 172.9s | 168.0s |
| 8 | 35.3s (4.79x) | 34.0s (4.98x) | 31.2s (5.42x) |
| 16 | 23.4s (7.23x) | 21.7s (7.78x) | 19.3s (8.76x) |
| 32 | 26.8s (**6.31x**) | 18.7s (9.02x) | 16.0s (**10.60x**) |

S2 — reads-from/ND-heavy (`--txset-status downloading-then-valid
--nomination-always-downloading --download-time nondet --stop-on-externalize
--depth 56`, 1,278,277 executions **when this was measured**; per-event txset
scoping later cut the same invocation to 837,558, so the absolute times in the
S2 table no longer reproduce, even though the engine-to-engine comparison they
encode still holds):

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

Re-run on 2026-08-05 on the same host with `REPS=5`, after per-event txset
scoping shrank S2: 837,558 executions at every worker count, medians 13.35s /
2.82s / 1.44s / 1.18s at 1 / 8 / 16 / 32 workers (11.31x at 32), gate `PASS` on
both its primary and secondary margins. Those wall-clock numbers are not
comparable to the S2 table above — the workload is about a third smaller — but
the conclusion the table exists to record, monotone improvement through 32
workers, is unchanged.

## Verification in this workspace

The build shape was verified with a clean reconfigure after rebasing onto
`4c0d88c75` (upstream post-CAP-0083-ungating master). The runtime suites and
execution fingerprint were rerun after per-event txset scoping landed, against
the pinned `febae6f` engine. Every count, exit code and message quoted below was
re-verified on 2026-08-05 at `adafc40c6` on `addict-glad-64ta` and reproduced
exactly, the one exception being the standalone-engine test count, which was
stale and is corrected below. The clean-rebuild bullet was not re-run from
scratch; it was checked against the configured build's flags
(`DPOR_CXXFLAGS`, no `-DCAP_0083`, global `-DXDRPP_STRONG_ORDER=1`):

- `./configure --enable-dpor --enable-nsc-sccache CC=clang-20 CXX=clang++-20`
  (no next-protocol flag), `make clean`, `make -C lib`, then
  `make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation`
  completed. Emitted DPOR compile lines carry target-local
  `-std=c++20 -DFMT_CONSTEVAL= -DSTELLAR_DISABLE_LOGGING`, contain no
  `-DCAP_0083` anywhere in the build, and pick up master's new global
  `-DXDRPP_STRONG_ORDER=1`.
- `./src/stellar-core-dpor-tests "[scp][dpor][smoke]"` passed with 312
  assertions in 55 test cases. (Was 266 in 52 before the per-thread event
  bound added three.)
- `./src/stellar-core-dpor-tests "[scp]"` passed with 1,607,997 assertions in
  65 test cases.
- The standalone DPOR suite passed 300/300 tests in the engine checkout under
  the `debug`, `asan` and `tsan` presets, including the follow-up sparse
  ordered-import regressions. (This entry previously read 290/290 at engine
  commit `febae6f`; the per-thread event bound added the remaining 10.
  `bench-release` registers none.)
- `./src/scp/test/bench-dpor.sh check` reproduced the seven deterministic
  scenarios byte-identically and the six nondeterministic ones at their new,
  lower counts; see "Per-event txset decisions" above for the table. Adding the
  per-thread event bound left all 13 lines unchanged except for the two
  appended keys, and added a 14th (`CE`).
- `./src/scp-dpor-investigation --txset-status always-valid --depth 6`
  reported
  `kind=all-explored executions=1 full=0 blocked=0 error=0 depth-limit=1`.
- `./src/scp-dpor-investigation --txset-status downloading-then-valid
  --depth 6` reported
  `kind=all-explored executions=2 full=0 blocked=0 error=0 depth-limit=2`.
  This was `executions=3` before per-event txset scoping; the removed execution
  was a duplicate status branch inside one handler.
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
  a current-version trace; `--replay-trace-json ... --replay-node all`
  reloaded and
  replayed every node successfully (exit 0).
- `--fail-on-first-blocked --trace-dir ... --txset-status always-downloading
  --download-time above --stop-on-prepare --depth 20` reported
  `terminal-kind=blocked leader-boundary=true` and
  `kind=stopped executions=52 full=2 blocked=1 error=0 depth-limit=49`, exited
  1, and wrote a current-version trace focused on the first blocked node;
  `--replay-trace-json ... --replay-node all` replayed every node
  successfully (exit 0).
- Behavior preservation across per-event txset scoping was checked directly
  rather than inferred from aggregate counts, because a lower `full=` can mean
  either "duplicate branches removed" or "coverage lost":
  - Download blocking at the commit boundary is byte-identical.
    `--nodes 3 --fifo --txset-status always-downloading --stop-on-commit
    --depth 60` still gives
    `executions=35904 full=0 blocked=8613 error=0 depth-limit=27291` for
    `--download-time below` and
    `executions=26409 full=12760 blocked=0 error=0 depth-limit=13649` for
    `above`. A node that never times out still stalls; one that always times
    out still replaces the tx set and proceeds. The prepare boundary does not
    discriminate here -- it gives `16/12/4` for both -- because it stops before
    full validation matters.
  - The blocked executions C1 and C3 capture under `--fail-on-first-blocked`
    are the same routes as before: same blocking node index, same thread, and
    replay dumps that differ only by the removal of three (C1) and five (C3)
    duplicate `txset-status(downloading)` choices.
  - `--must-externalize --check-agreement` on the externalize-boundary variants
    of C1 and C6 at `--depth 50` pass with `blocked=0`, over `full=821` and
    `full=355634` maximal executions respectively. The `blocked=` count matters:
    `--must-externalize` only checks quiesced runs. A run in which nothing at
    all was maximal no longer passes silently -- see
    [Property checks are inconclusive, not passing, when nothing was
    maximal](#property-checks-are-inconclusive-not-passing-when-nothing-was-maximal).
  - A captured bundle reports version 8 and round-trips through
    `--replay-node all`. As an approved simplification exception, the reader is
    v8-only with no converter: every older bundle is rejected with a generic
    recapture message. Version 8 stores positional per-node traces and omits
    derivable observation-count and focus-thread fields.
- At the previously documented `--depth 12` that same invocation finds no
  blocked execution. It now reports
  `error: --fail-on-first-blocked was set but no matching execution was found
  in 4 executions at --depth 12, so no trace was captured; 4 execution(s) hit
  the depth limit, so a greater --depth may reach a blocked execution` and
  exits 1. Previously it exited 0, which made a too-shallow depth
  indistinguishable from a clean run -- see "Capture modes fail when they
  capture nothing" below.

### Per-thread event bound

Measured on `addict-glad-64ta` at the engine commit that introduced
`max_thread_events`. Every line below was reproduced in this workspace.

The bound bites and displaces depth-limit truncation entirely:

| invocation | result |
|---|---|
| `--depth 30 --stop-on-prepare` | `executions=94 full=87 blocked=4 depth-limit=3 thread-event-limit=0 max-thread-event-depth=8` |
| `--stop-on-prepare --thread-event-depth 8` | `executions=94 full=80 blocked=4 depth-limit=0 thread-event-limit=10 max-thread-event-depth=8` |
| `--stop-on-prepare --thread-event-depth 7` | `executions=94 full=6 blocked=4 depth-limit=0 thread-event-limit=84` |
| `--stop-on-prepare --thread-event-depth 6` | `executions=74 full=0 blocked=4 depth-limit=0 thread-event-limit=70` |
| `--thread-event-depth 3` | `executions=6 full=0 blocked=0 depth-limit=0 thread-event-limit=6 max-thread-event-depth=3` |

The first two rows are the point of the feature: the same 94 executions, with
the three that `--depth 30` silently truncated now attributed to a per-node
budget you chose, and seven more honestly reported as possibly truncated rather
than counted as complete interleavings.

The four-node case from the motivating example is more sobering, and the plan's
estimate for it was wrong. `--nodes 4 --depth 40 --stop-on-prepare` gives
46164 executions, all `depth-limit`, and reports
`max-thread-event-depth=14` -- i.e. nodes need 14 events. Under the bound:

| cap | result |
|---|---|
| 8 | `executions=227520` all thread-event-limit |
| 9 | `executions=4166876` all thread-event-limit |
| 10 | `executions=84043840` all thread-event-limit |
| 11 | `executions=1310133288 blocked=13104` |

So the first maximal executions appear at `--thread-event-depth 11`, not 8 as
the plan estimated, and the count is enormous by then. What the bound buys here
is not free coverage; it is a truthful answer -- `max-thread-event-depth`
tells you 14 is required, and `thread-event-limit=` tells you when you have
not got there -- where `--depth` gave a number with no interpretation.

Property checks:

- `--stop-on-prepare --check-agreement --thread-event-depth 8` exits 0 over
  `full=80 blocked=4`, so the check was not vacuous.
- `--stop-on-prepare --must-externalize --thread-event-depth 8` exits 1 with
  `full execution missing EXTERNALIZE envelope from node-index=0 thread=0`: a
  genuine violation still wins over the inconclusive path.
- `--stop-on-externalize --must-externalize --thread-event-depth 6` exits 2:
  all 210 executions sat at the bound, so nothing was evaluated.

A gotcha worth knowing: under a fixed `--depth`, a *tighter* per-node cap can
*increase* the number of terminal executions, because shorter executions leave
more search-tree budget for interleavings that used to be cut off. On the
`bench` S3 scenario (`--nodes 3 --txset-status always-valid --download-time
below --stop-on-commit --depth 46`), unbounded gives 2,000,256 executions while
`--thread-event-depth 14` gives 5,965,899. That is not an inconsistency: the
bound is equivalent to a wrapped program at the *same* `--depth`, not to the
unbounded run.

Cost, measured back to back in one session on `addict-glad-64ta`, medians of
five. The `bench` S4 scenario explores exactly 128,750 terminal executions both
unbounded and at `--thread-event-depth 17`, so that pair isolates the bound's
own cost on identical work -- and 116,860 of those terminals sit at the bound,
so the skip fires often:

| S4 | unbounded | `--thread-event-depth 17` | ratio |
|---|---|---|---|
| `--workers 1` | 3.40 s | 2.20 s | 0.65x |
| `--workers 8` | 0.75 s | 0.51 s | 0.68x |

That is the expected direction: the skip happens before `thread_trace_into()`
and before the thread-function call, which in this harness is
`captureNextEvent` -> `acquireReplayState` -> possibly a partial SCP node
replay.

With the bound *off*, the change is not measurable. `bench` was run three times
each for the pre-change binary, a byte-identical copy of it, and the new binary,
alternating arms within one session:

- serial (`W="--workers 1"`): every scenario within 0.6% of baseline
  (S1 1.000x, S2 0.995x, S3 0.999x, S4 0.994x). The unconditional
  O(thread-count) per-terminal scan for `max-thread-event-depth` does not show
  up here.
- parallel (default `--workers 8`): S1 1.00x, S2 1.05x, S3 1.02x, S4 1.07x --
  all inside the identical-binary control's own 0.96x-1.10x spread on the same
  runs, so the noise floor swallows them. Reporting these as a regression would
  be reporting the machine.
- `--print-stats 1` is the only configuration in which `flush_local_counts`
  runs mid-exploration, so it is the only one that exercises the shared-atomic
  fold at all. On S4 at `--workers 8`, medians of five: baseline 0.78 s off /
  0.77 s on, new binary 0.75 s off / 0.77 s on. No measurable difference in
  either binary.
- `bench-dpor.sh scale` ran in **gated** mode (32 usable logical CPUs over 16
  SMT2 cores, no cgroup quota) and passed both assertions, with the execution
  count identical at every worker point: 837558 executions; medians 13.33 s at
  1 worker, 2.70 s at 8 (4.94x), 1.56 s at 16 (8.54x), 1.22 s at 32 (10.93x).
  So the shorter branches a bound produces did not disturb parallel scaling.

Strict parsing, all exit 1 with the named argument in the message:
`--thread-event-depth 5x`, `--thread-event-depth -2`,
`--thread-event-depth 0` ("requires a value greater than 0"),
`--sync-steps -1`, `--depth -1`, `--max-queued-tasks 7q`,
`--max-nomination-round 3z`. `--thread-event-depth -1 --stop-on-prepare` is
accepted and behaves as unbounded with `--depth` left at 12
(`executions=4 depth-limit=4 thread-event-limit=0`).

The configure-time API probe was confirmed to reject an older checkout: with
`external/dpor` at the previous pin, `configure` fails with
`the DPOR checkout at ... is too old (missing
dpor::algo::TerminalExecutionKind::ThreadEventLimit and/or
DporConfigT::max_thread_events)` rather than failing later in the build.

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

### Property checks are inconclusive, not passing, when nothing was maximal

`--must-externalize` and `--check-agreement` only inspect maximal executions.
That is correct -- neither property is meaningful on a branch the engine
truncated -- but it used to mean a run in which *every* execution was excluded
exited 0, indistinguishable from a real pass. `--stop-on-prepare` already
reached that state easily, and a per-node cap makes it easier still: with
`--stop-on-externalize --must-externalize --thread-event-depth 6`, all 210
executions sit at the bound and nothing is checked.

Maximal executions are exactly `full + blocked`, both of which the library
already reports, so the runner now returns exit 2 with an `inconclusive:`
message when a check was requested and that sum is zero. The message names the
requested flag, the total explored, and how many executions hit `--depth` or
sat at `--thread-event-depth`. Exit 2 is distinct from the exit 1 used for a
genuine violation, and a real violation returns 1 before this check runs, so
exit 2 unambiguously means "the property was never evaluated". No
`bench-dpor.sh` scenario uses either flag, so no fingerprint moves.

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
- `--nomination-always-downloading` breaks the per-event tx-set invariant on
  purpose. Modeled tx-set status and download wait time are otherwise decided
  at most once per value per external event, but this flag forces
  nomination-phase validation to `downloading` without consulting or writing
  that decision. Because `NominationProtocol::processEnvelope` can call
  `Slot::bumpState` synchronously, one `receiveEnvelope` of a `NOMINATE`
  message can run nomination validation (forced `downloading`) and then
  balloting validation, which may choose `valid` for the same value. The flag
  is a branch-saving knob rather than a model of fetcher state, and memoizing
  it would stop balloting from ever branching in an event that began with a
  nomination validation — exactly what the scenarios using the flag exist to
  explore. The clean fix is to make tx-set availability its own event source
  per (node, value), at which point the flag becomes an initial-state fact
  instead of a per-call override.
