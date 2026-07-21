# DPOR concurrency code review — findings

Source: deep review of the DPOR engine (`external/dpor`, rev `9345ead`) and the
stellar-core integration (`src/scp/test/`), done 2026-06-09 while investigating
the "memory corruption after hours" crashes of `scp-dpor-investigation`.

**Context:** none of these findings explain the crashes. Forensic analysis of
`core.scp-dpor-invest.171086.1778194026` showed a direct `call` instruction
landing 0x12 bytes past its read-only, hard-coded target — hardware-level
instruction-stream corruption (i7-12700K on old microcode 0x3e, non-ECC RAM),
not a software race. See memory note `dpor-crash-diagnosis-hardware`. The
items below are real but lesser issues (hang risk, latent footguns,
robustness) worth fixing on their own merits.

Findings 1, 3, and 5 are in the upstream CPP-DPOR repo (`nano-o/CPP-DPOR`);
fixes belong there. Findings 2 and 4 are in stellar-core.

---

## 1. Lost-wakeup risk in `ParallelExecutor` stop/exception paths (upstream)

**Where:** `external/dpor/include/dpor/algo/dpor.hpp:1357-1361`
(`request_stop`) and `:1363-1372` (`record_exception`).

**What:** both store `stop_requested_` and call `queue_cv_.notify_all()`
without holding `queue_mutex_` (`record_exception` holds `publication_mutex_`,
which is not the mutex the waiters use). A worker evaluating the wait
predicate in `worker_loop` (`dpor.hpp:1203-1206`) can read the flag as false,
then the store + notify can both happen before the waiter actually blocks —
the notification is lost.

**Impact:** latent hang at stop time. In the *current* call graph it is
rescued by accident: `request_stop`/`record_exception` are only reached from
worker context, and the same worker subsequently takes `queue_mutex_` in its
loop-exit path and does another `notify_all`, which wakes any stragglers. The
bug becomes live if a stop is ever requested from a non-worker context, or if
the loop-exit notify is refactored away.

**Fix:** hold `queue_mutex_` while storing `stop_requested_` (or at least
around the `notify_all`). The store is rare (stop/exception), so there is no
performance concern.

## 2. Thread-local node cache keyed by raw `this` — ABA-fragile (stellar-core)

**Where:** `src/scp/test/ScpDporReplaySupport.cpp:15-27` (cache entry +
`threadLocalReplayStateCache`), `:130-146` (`acquireNode`), `:148-152`
(`clearThreadLocalCacheForCurrentThread`).

**What:** `acquireNode` keys cached `DporScpNode`s by the
`ScpDporReplaySupport const*` pointer. Entries for a destroyed support object
linger in the per-thread cache with a dangling (compared-only, never
dereferenced) key. If a new support is later allocated at the same address —
likely, since allocations are same-sized, and routine for stack temporaries
like the one `inspectPrepareBoundary` creates
(`ScpDporDefaultScenario.h:262-272`) — a stale entry matches and returns a
node built from the *wrong* scenario's validators/qset/config.

**Current safety is load-bearing coincidence:** every replay entry point
(`makeProgram`, `replayTrace`, `inspectThreadReplayTrace`) calls
`clearThreadLocalCacheForCurrentThread()` first, and the hot path
(`captureNextEvent`) only ever uses the long-lived `self` scenario copy. Any
new caller that skips the clear, or any change to scenario lifetimes, silently
produces wrong exploration results (not a crash — the node itself is owned by
the cache).

**Fix:** key the cache by a stable identity instead of the address — e.g. a
`static std::atomic<uint64_t>` counter stamped into each
`ScpDporReplaySupport` at construction — or hold the support via
`std::weak_ptr` and require shared ownership. Then the entry-point clears
become an optimization rather than a correctness requirement.

## 3. `thread_local WorkerState` shared across executor instances (upstream)

**Where:** `external/dpor/include/dpor/algo/dpor.hpp:1250-1263`
(`WorkerState`, `worker_state()`).

**What:** the per-worker counters/stop-cache live in a function-local
`thread_local`, so there is one instance per *(ValueT, OS thread)*, shared by
**all** `ParallelExecutor<ValueT>` instances that ever run on that thread. It
works today because each worker flushes and resets on loop exit
(`flush_worker_state`, `dpor.hpp:1284-1290`) and `verify_parallel` calls
never nest or overlap. Nested verifies (e.g. a terminal callback that runs
another exploration), or two executors sharing a thread pool, would mix
counters across runs and leak a stale `cached_stop`.

**Fix:** make `WorkerState` per-executor — e.g. a worker-index-addressed
`std::vector<WorkerState>` member (workers know their index), or a
`thread_local std::unordered_map<ParallelExecutor*, WorkerState>`.

## 4. `ReplayDebugRecordingGuard` can write through a dangling reference (stellar-core)

**Where:** `src/scp/test/ScpDporDefaultScenario.h:321-338`
(`inspectThreadReplayTrace`).

**What:** the guard captures `DporScpNode& mNode`, whose storage is owned by
the thread-local cache, and writes `setReplayDebugRecordingEnabled(false)` in
its destructor. If anything between guard construction and destruction calls
`clearThreadLocalCacheForCurrentThread()` on the same thread (today nothing
does), the destructor is a use-after-free write. Same hazard pattern for any
future helper that holds a node reference across a call that might clear the
cache.

**Fix:** either make the cache entries `shared_ptr<DporScpNode>` and have the
guard (and `acquireNode` callers generally) hold a `shared_ptr`, or assert/
document that cache clears are forbidden while a node reference is live.

## 5. Blocked-receive reschedule turns wrapped errors into fatal `logic_error` (upstream + harness interaction)

**Where:** `external/dpor/include/dpor/algo/dpor.hpp:1636-1656`
(`find_blocked_receive_reschedule_child`) together with
`src/scp/test/ScpDporInvestigationUtils.h:26-66`
(`wrapProgramExceptionsAsErrorExecutions`).

**What:** the investigation harness wraps thread functions so exceptions
become `ErrorLabel` returns, which `compute_next_event` handles by publishing
an inspectable error execution. But when the *reschedule* path re-queries a
previously blocked thread, an `ErrorLabel` (or `nullopt`) return hits the
`throw std::logic_error("blocked thread did not produce a receive after
unblocking")` checks instead. That exception propagates out of the worker into
`record_exception` and aborts the whole verify with no replay trace — exactly
the failure mode the wrapper exists to avoid.

**Fix:** in `find_blocked_receive_reschedule_child`, treat an `ErrorLabel`
result like `compute_next_event` does (surface it as an error execution for
that thread) rather than throwing.

---

## Constraints verified during review (preserve these)

Not bugs — invariants the current design depends on. Worth keeping in mind
when extending the harness:

- **Terminal-execution callbacks run concurrently** on worker threads,
  outside any engine lock, and with the default `sync_steps=512` they can
  still fire *after* another callback returned `Stop`
  (`dpor.hpp:196-204`). The investigation main handles this correctly with
  `terminalExecutionMutex` + the `dumpedTerminalExecution`/`failureMessage`
  latches (`DporScpInvestigationMain.cpp:1235-1394`); any new callback state
  must stay behind that mutex.
- **The `TerminalExecutionT::graph` reference is only valid during the
  callback.** On the error path the engine rolls the graph back immediately
  after publishing (`dpor.hpp:1839-1845`). Callbacks must copy what they need
  (as `makeTraceBundle` does today), never retain the reference.
- **Thread functions are invoked concurrently from all workers** and must
  stay deterministic and effectively stateless. `captureNextEvent` satisfies
  this via the per-thread node cache plus a full `restoreBaseline` at every
  call; the shared scenario state (`mOptions`, `mScenarioBaselines`,
  `mReplaySupport` baselines) is read-only after construction and must remain
  so.
- **Graphs are thread-confined.** Cross-thread handoff happens only by move
  through the task queue under `queue_mutex_`; the `mutable
  shared_ptr<PorfCache>` (`exploration_graph.hpp:557`) is shared between
  graph *copies* but the cache object is immutable once published and
  enqueued tasks carry a null/fresh cache. Don't add code that shares a live
  graph (or its porf cache) across threads by reference.
