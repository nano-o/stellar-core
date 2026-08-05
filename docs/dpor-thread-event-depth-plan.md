# Plan: `--thread-event-depth` bound and max-per-thread-event-depth stat

Status: proposed, not implemented. Revised after two review rounds; the full
review and response history is preserved at the end of this document.

## For reviewers

Settled across two review rounds, and not worth re-litigating unless something new
turns up:

- the bound and its terminal accounting live in the DPOR library, not the harness;
- classification keys off a per-call cap-suppression signal from
  `compute_next_event`, **not** off a `thread_event_count >= cap` scan;
- the parallel maximum is folded in `flush_local_counts`, never per terminal;
- enforcement sits in `compute_next_event`, not at frame entry.

Disproven in round one and corrected below: the earlier claim that a capped thread
can never carry a trailing `Block`. It can — a thread at `step == cap - 1` that
returns an unsatisfiable blocking receive gets a synthesized `Block` as its `cap`th
event. That is what killed the count-based classification.

What is worth attacking now:

1. **The exploration-equivalence claim.** The bound is claimed to be exactly
   equivalent to wrapping every thread function as
   `f'(trace, step) = step >= N ? nullopt : f(trace, step)` — a legal
   `ThreadFunctionT` — so the engine-side skip computes the same `next_P(G)`
   without paying for the call. The differential test under *Library tests* is what
   establishes it; check that it really covers backward restriction and blocked
   rescheduling, since a graph restricted by a revisit can drop a capped thread
   below the bound and re-enable it.
2. **The suppression signal's lifetime.** It must be constructed fresh on every
   `compute_next_event` call, ignored when a next event or a blocked-reschedule
   child is found, and read only on the final no-next/no-reschedule path.
3. **Terminal-kind precedence** — `DepthLimit > Error > ThreadEventLimit > Blocked
   > Full` — falls out of existing control flow rather than being chosen. Confirm
   that is the intended order.
4. **The `-1` spelling** is recognized only in the `--thread-event-depth` branch
   and maps to an absent optional. Confirm it has not leaked into the shared parser
   and that no `SIZE_MAX` encoding survives.

Line numbers are against `dpor-on-master` at `49dbbf9cc` with `external/dpor` at
`febae6f`.

## Context

`scp-dpor-investigation`'s `--depth N` sets `DporConfigT::max_depth`, which bounds
**DPOR search-tree depth**, not event-graph size. `dpor_tree_depth` lives on the
exploration frame (`external/dpor/include/dpor/algo/dpor.hpp:1247`, `:1938`) and is
incremented by ordinary forward steps *and* by backward revisits — and a backward
revisit builds its child with `restrict_masked`, i.e. **fewer** events than the
parent at depth+1. So depth and event count diverge badly, and `--depth` is a
global budget shared across all nodes.

Measured on this tree (`--enable-dpor`, binaries already built):

| Invocation | Result |
|---|---|
| `--depth 10` | `executions=3 full=0 blocked=0 error=0 depth-limit=3` |
| `--depth 30 --stop-on-prepare` | `executions=94 full=87 blocked=4 error=0 depth-limit=3` |
| `--nodes 4 --depth 40 --stop-on-prepare` | `executions=46164 full=0 blocked=0 error=0 depth-limit=46164` in 0.24s |

That last row is the usability problem: 46k executions, every one truncated, no
coverage at all — and nothing in the output says "you learned nothing here"
except a `depth-limit` count you have to think about. There is no way to say
"let each validator take at most K protocol steps".

Wanted:
1. `--thread-event-depth N` — bound the events any single thread may contribute.
2. Report the max per-thread event depth actually reached, so you can tell whether
   a bound bit and pick one.

## Decision: this belongs in the DPOR library, not the harness

A harness-only version is possible: `ThreadFunctionT` is
`(trace, step) -> optional<EventLabel>` where **`step` is already that thread's
event count** (`algo/program.hpp:139-153`, computed at `dpor.hpp:481` as
`graph.thread_event_count(tid)`), so `ScpDporDefaultScenario::captureNextEvent`
could return `std::nullopt` when `step >= N`. That is sound — the cutoff is a pure
function of `step`, which satisfies the determinism contract including the
blocked-reschedule re-ask at `dpor.hpp:2141-2169` (it asks with `step = count-1`,
strictly below the capping step).

It is nonetheless the wrong home, for one decisive reason: **a retired thread makes
DPOR classify the execution as `Full`/`Blocked`, i.e. maximal — which is a lie.**
Everything downstream keys off that. `isMaximalExecution()`
(`ScpDporInvestigationUtils.h:36-41`) is exactly `is_full_execution() ||
is_blocked_execution()`, and `findNodeMissingExternalize`
(`DporScpInvestigationMain.cpp:825-828`) already uses it to skip truncated runs.
So the harness-only route forces us to:

- invent a `thread-event-limit=` counter by hand, populated from the heuristic
  `thread_event_count(tid) >= cap` — which is ambiguous, because a trailing
  engine-injected `Block` event also counts, so a thread that blocked at step
  `N-1` is indistinguishable from one capped at `N`;
- hand-gate `--must-externalize` and `--check-agreement` on that heuristic;
- repeat both in every future scenario, since the skill's premise is that
  engineers add scenarios. A per-thread event bound is a generic model-checking
  knob, not an SCP concept — it belongs next to `max_depth`.

Adding `TerminalExecutionKind::ThreadEventLimit` makes `isMaximalExecution()`
return false for truncated runs *for free*, deletes the heuristic, and gives the
counter and the stat first-class homes alongside `depth_limit_executions_explored`.
Net harness code is **smaller** than the harness-only design, and the scenario file
is untouched.

Note the two routes are observationally identical in *what gets explored* — the
engine-side skip computes the same `next_P(G)` as the wrapped thread function, just
without paying for the call. The terminal classification is the only real semantic
difference, and it is the entire point.

Cost: an `external/dpor` change plus a pin bump. The submodule is clean at
`febae6f` on local branch `parallel-scaling`, which equals `origin/dpor-perf`, so
the push is a fast-forward. The library is explicitly a prototype with "no
backward-compatibility commitment" (`external/dpor/AGENTS.md:172-177`).

Settled by prior design decisions: capped executions counted separately and
excluded from property checks; `--depth` raised implicitly when the new flag is
used; stat printed in both summary and progress lines; the flag is an
investigation-only knob, **not** part of serialized scenario `Options`, so
`ScpDporDefaultScenario::Options` is untouched. The trace bundle does change: a new
`terminal.kind` spelling widens the serialized value domain, so new bundles are
written as version 7 while the reader keeps accepting version 6.

---

## Part 1 — `external/dpor/include/dpor/algo/dpor.hpp`

**Config.** In `DporConfigT` (`:216-241`), beside `max_depth`:
```cpp
  // Bounds the events any single thread may contribute. Unlike max_depth this
  // is a per-thread event-graph bound, not a search-tree bound. 0 = unlimited.
  std::size_t max_thread_events{0};
```

**New terminal kind.** Add `ThreadEventLimit` to `TerminalExecutionKind` (`:54`)
and extend the comment block at `:47-53`, mirroring the existing `DepthLimit`
wording ("not a maximal execution, and it keeps that kind even if some thread
happens to be blocked at the cutoff"). Add
`is_thread_event_limit_execution()` to `TerminalExecutionT` (`:97-122`) and note
the kind in the `TerminalExecutionObserverT` comment (`:124-128`).

**Enforcement** — one skip in `compute_next_event` (`:460-512`), which gains a
`std::size_t max_thread_events` parameter and returns a small result struct rather
than a bare optional:
```cpp
template <typename ValueT>
struct NextEventResultT {
  std::optional<std::pair<model::ThreadId, model::EventLabelT<ValueT>>> next;
  // True iff some nonterminated thread was skipped because it sat at the bound,
  // so the engine never asked whether it had a further event. Meaningful only
  // when `next` is empty.
  bool suppressed_by_thread_event_limit{false};
};
```
The skip goes **after** the existing terminated-thread check at `:466`. That order
is load-bearing — see *Classification* below:
```cpp
    if (graph.thread_is_terminated(tid)) {
      continue;
    }
    if (max_thread_events != 0 && graph.thread_event_count(tid) >= max_thread_events) {
      result.suppressed_by_thread_event_limit = true;
      continue;
    }
```
`thread_event_count` is O(1) (`model/exploration_graph.hpp:351`), and this skips
*before* the `thread_trace_into` copy and the thread-function call, so a capped
thread costs one comparison. Update the call site at `:2344` to pass
`config_.max_thread_events`.

Carrying the flag inside the returned struct, rather than through an out-param, is
what keeps its lifetime correct: it is constructed fresh per call so it cannot go
stale, and it is only ever read on the one path described below. A
blocked-reschedule child or a normal next event discards it implicitly.

Enforce it here — **not** as a `max_depth`-style frame-entry check at `:2337`.
A frame-entry check would kill the whole branch as soon as the *first* thread
reaches the cap; the requirement is that each thread is capped independently.

**Classification** at `:2359-2363`, reached only when `compute_next_event` found
nothing *and* `find_blocked_receive_reschedule_child` produced no child:
```cpp
      const auto kind = next.suppressed_by_thread_event_limit
                            ? TerminalExecutionKind::ThreadEventLimit
                        : graph.has_blocked_thread() ? TerminalExecutionKind::Blocked
                                                     : TerminalExecutionKind::Full;
```
Only one new free helper is needed next to `compute_next_event`:
`max_thread_event_depth(graph, thread_ids)`, a `max` over `thread_event_count`,
used for the stat. There is deliberately **no** `has_thread_at_event_limit`: a
`thread_event_count >= cap` scan is the very heuristic the library route exists to
eliminate, and it gets the blocked case wrong.

Why the check order matters. A thread at `step == cap - 1` that returns an
unsatisfiable blocking receive gets a synthesized `Block` as its `cap`th event, so
`thread_event_count == cap` with a trailing `Block`. On the next
`compute_next_event` that thread is caught by the terminated check *first*, so it
never sets the suppression flag, and the execution classifies as `Blocked` —
correctly. The blocked-reschedule path (`:2346-2357`,
`find_blocked_receive_reschedule_child` at `:2110-2183`) then needs **no** change:
it re-asks at `step = thread_event_count - 1 == cap - 1`, still under the bound, so
the replacement receive fits. A backward revisit that restricts the graph likewise
lowers the count and re-enables the thread on its own.

**Contract for `ThreadEventLimit`**, to be stated in the header comment: *the engine
declined to ask at least one thread whether it had a further event, because that
thread was at the bound.* It is deliberately conservative — a thread whose function
would have returned `nullopt` at exactly `step == cap` is indistinguishable from a
genuinely truncated one without asking, and is classified `ThreadEventLimit`. So
the kind means "this execution may be truncated", not "this execution was
truncated", and the docs, counter description and capture hints must not claim
otherwise.

**Counters and stat.** `VerifyResult` (`:57-78`) gains
`thread_event_limit_executions_explored` and `max_thread_event_depth_reached`;
`ProgressSnapshot` (`:80-93`) gains `thread_event_limit_executions` and
`max_thread_event_depth`. Then thread them through the existing plumbing:

- `increment_terminal_counts` (`:330-346`) — new case.
- Sequential: `SequentialExecutor::publish_terminal_execution` (`:1308-1315`)
  folds the per-execution max; `make_progress_snapshot` (`:1342-1354`) copies it.
- Parallel: `WorkerState` (`:1730-1741`) gains a local counter and a local max;
  `increment_local_terminal_counts` (`:1748-1769`); `flush_local_counts`
  (`:1783-1803`) folds via a CAS loop; new atomics beside `:1882-1885`;
  `run()` aggregation at `:1426-1442` where `executions_explored` becomes the sum
  of **five** kinds, not four; `make_progress_snapshot` (`:1827-1849`).

Invariant to hold and document: `max_thread_event_depth_reached <= max_thread_events`
when the bound is set. It counts engine-injected `Block` events, so a thread that
blocks at step `cap-1` also reports `cap` — the bound is never *exceeded*, which is
the property that matters. That `Block` inflation affects only the stat, never
classification, which reads the suppression flag rather than the count.

Define the stat precisely: it is the maximum over **published terminal executions**,
not a high-water mark over every transient graph. Under early stop those coincide
only if exploration ran to completion.

### Performance

**Default (bound off): one predictable compare per thread per frame entry, plus an
unconditional per-terminal scan.** `max_thread_events` is constant for the run, so
`max_thread_events != 0` is perfectly predicted; and the `thread_event_count(tid)`
load it guards reads `thread_state_[idx].event_count`, the same cache line
`thread_is_terminated(tid)` touched one line earlier. Dropping
`has_thread_at_event_limit` removes what would otherwise have been a second scan.

The stat is not free, though, and an earlier draft of this plan understated it:
`max_thread_event_depth(graph, thread_ids)` runs for **every** published terminal
execution, bound set or not — O(thread-count) O(1) loads, 3-4 here, at the full
terminal rate. That is the one bound-off cost the back-to-back unbounded benchmarks
below have to measure rather than assume.

**Parallel mode is the real risk.** Two facts make a naive stat fold expensive:

1. The parallel executor deliberately keeps **no shared-atomic traffic on the
   terminal path** — counts land in a `thread_local WorkerState` (`:1730-1741`) and
   reach the shared atomics only via `flush_local_counts` (`:1783-1803`).
2. That mid-run flush is gated on `config_.on_progress` (`:1765-1768`). **Without
   `--print-stats`, workers never touch the shared counters until end of run.**

So a `compare_exchange` on `max_thread_event_depth_reached` per published terminal
would take a path that currently has *zero* cross-core traffic and give it a
contended RMW on one shared line, at the ~190k terminals/sec measured above across
up to 32 workers. Avoid it: keep `local_max_thread_event_depth` in `WorkerState`,
update it with a plain non-atomic compare-and-assign, and fold it into the shared
atomic **only inside `flush_local_counts`**, via a relaxed CAS loop (C++20
`std::atomic` has no `fetch_max` — that is C++26). Shared traffic then rides the
cache lines that function already dirties, at ~1/1024 of the terminal rate, and the
loop effectively never spins because the max stabilizes early. The new
`thread_event_limit` counter is just a fifth counter in the same pattern.

Consequence, mirroring existing behavior rather than adding a new caveat class:
under `--print-stats` the progress line's `max_thread_event_depth` lags by up to
`progress_counter_flush_interval` terminals per worker — exactly what
`counts_exact=false` already signals for the counts. The final `VerifyResult` value
is exact.

**Where not to compute it.** Maintaining the max incrementally in
`ExplorationGraphT::add_event` looks cheaper but is wrong and slower: the graph
supports `rollback`, `undo_last_event_append` and `restrict_from_keep_mask`, so a
running max needs recomputation on every removal (or degenerates into a
high-water mark that is simply wrong after a restrict) — and `add_event` is far
hotter than terminal publication. Compute it once per published terminal over
`thread_ids` (3-4 O(1) loads here).

**With the bound on, it is a net speedup.** The skip fires *before*
`thread_trace_into(tid, trace)` and before the thread-function call — which in this
harness is `captureNextEvent` → `acquireReplayState` → possibly a partial SCP node
replay. That dwarfs the comparison.

**Second-order parallel effect to measure, not assume.** Capping threads shortens
executions, so terminals-per-unit-of-tree-work rises — the publication path gets
relatively hotter exactly in the new flag's own workload, which is the second
reason the deferred flush matters. Shallower trees also mean less work per branch,
which interacts with `spawn_depth_cutoff` and `should_split_to_idle_worker`, so
parallel scaling under a small cap could get *worse*. `bench-dpor.sh scale` is the
tool for that.

### Library tests

`external/dpor/tests/dpor_test.cpp`: mirror the `max_depth` cases at `:1019-1045`
and the parallel variant at `:3190-3216`, then add the tests that actually carry
the design.

**Differential equivalence** — the load-bearing one. Compare the set of terminal
graph signatures produced by `max_thread_events = N` against the same program whose
thread functions are explicitly wrapped as `step >= N ? nullopt : f(trace, step)`,
deliberately ignoring the expected terminal-kind difference. Run it in both
sequential and parallel modes, and include a program that forces a backward revisit
to restrict a capped thread below the bound, so the re-enable path is exercised.
Mirroring the simple `max_depth` tests would touch neither restriction nor blocked
rescheduling, which is exactly where the equivalence could fail.

The wrapped program is an ordinary program, so it can also go through the exhaustive
oracle (`tests/support/oracle_core.hpp:146,243`). An earlier draft claimed the bound
had to be excluded from oracle-backed coverage; that is withdrawn.

**Classification cases**, each of which the count-based heuristic would have gotten
wrong or ambiguous:
- a `Block` synthesized as a thread's `cap`th event → `Blocked`, not
  `ThreadEventLimit`;
- that same block rescheduled once a compatible send appears → the replacement
  receive fits at `step = cap - 1`;
- a program that naturally completes after exactly `cap` events →
  `ThreadEventLimit` under the conservative contract. This is intended, so pin it
  with a test to stop it being "fixed" later;
- terminal-kind precedence `DepthLimit > Error > ThreadEventLimit > Blocked > Full`,
  including the simultaneous depth/thread-limit and error/thread-limit cases. That
  order is a consequence of `max_depth` being checked before `compute_next_event`
  and `Error` immediately after it, not a deliberate choice — so it needs pinning
  rather than assuming.

## Part 2 — `src/scp/test/DporScpInvestigationMain.cpp`

No scenario, `Options` or bridge changes, and `make-mks` / `src/Makefile.am` need
nothing since only existing files are edited. `configure.ac` **does** change — see
the API-probe subsection at the end of this part. An earlier draft claimed no
build-wiring changes were needed; that was wrong.

- `CommandLineOptions` (`:40-84`): `std::optional<std::size_t> mThreadEventDepth;`
  plus `bool mDepthExplicit{false};`.
- `parseOptions` (`:1065-1292`): new block after the `--depth` block at `:1119-1123`.
  Use `parsePositiveSizeValue(arg, argv[++i])` (`:447`) for the numeric case — 0
  would mean no thread ever runs — and handle the literal `-1` in **this branch
  only**, before calling the parser, by leaving `mThreadEventDepth` unset. Set
  `mDepthExplicit = true` inside the `--depth` block.
- **Implicit `--depth` raise**, in the post-parse section at `:1279-1291`, mirroring
  the `DEFAULT_MAX_NOMINATION_TIMERS_ROUND` pattern already there: when
  `mThreadEventDepth` is set and `--depth` was not passed, raise `mDepth` to a new
  named constant `DEFAULT_DEPTH_WITH_THREAD_EVENT_DEPTH = 1000`, commented as
  tracking the library's `DporConfigT::max_depth` default. An explicit `--depth`
  always wins. Without this, `--thread-event-depth 6` under the default
  `--depth 12` is still dominated by `depth-limit` truncation.
- `printUsage` (`:190-346`): entry right after the `--depth` entry at `:227-228`,
  documenting both the per-thread semantics and the conditional `--depth` default
  (the `--max-nomination-timers-round` entry at `:249-255` is the precedent for
  describing a conditional default).
- `terminalExecutionKindName` (`:173-188`): new case → `"thread-event-limit"`.
- Config wiring (`:1318-1336`):
  `config.max_thread_events = options.mThreadEventDepth.value_or(0);`
- Summary line (`:1584-1592`): append `" thread-event-limit="` and
  `" max-thread-event-depth="`, printed unconditionally.
- `printProgressSnapshot` (`:629-652`): append `thread_event_limit_executions=`
  and `max_thread_event_depth=`.
- Capture-mode diagnostic (`:1602-1620`): alongside the existing
  `depth_limit_executions_explored > 0` hint, add one for
  `thread_event_limit_executions_explored > 0` suggesting a larger
  `--thread-event-depth`.

### Strict integer parsing

`parseSizeValue` (`:433`) delegates to `std::stoull` without checking the consumed
length or rejecting a leading minus. Verified on this toolchain:
`std::stoull("-1")` returns `18446744073709551615` and `std::stoull("5x")` returns
`5`, neither throwing. Every option routed through it inherits that — `--sync-steps`,
`--max-queued-tasks`, both polling/flush intervals, `--invalid-proposer`,
`--replay-node`, and `--replay-slots-per-node` via `parsePositiveSizeValue`.

Make it a strict unsigned parser: reject any leading minus, reject trailing
characters, reject overflow. Do **not** teach it a `-1` sentinel — that would give
seven unrelated options a new and mostly unsafe meaning, and would make the
legitimate decimal `18446744073709551615` indistinguishable from "unlimited". The
`-1` spelling for `--thread-event-depth` is handled in that option's own parse
branch and represented as an *absent optional*, never as `SIZE_MAX`, so nothing
downstream has to decode a sentinel.

Consequence worth documenting: because the implicit `--depth` raise keys on the
option being set, `--thread-event-depth -1` correctly leaves `--depth` at its
default of 12, while `--thread-event-depth 8` raises it. An A/B between the two
should pass `--depth` explicitly.

### Property checks: inconclusive when nothing maximal was inspected

`findNodeMissingExternalize` (`:820-828`) and `findAgreementFailure` already gate on
`isMaximalExecution`, which excludes the new kind, so neither needs a code change to
avoid false failures. `findErrorExecution` correctly stays ungated: an error is a
real bug regardless of truncation.

But a clean exit 0 from `--must-externalize` currently cannot be distinguished from
"every execution was excluded and nothing was checked" — the failure mode already
reachable today via `--stop-on-prepare`, and noted at
`docs/dpor-integration-status.md:661`. A per-thread cap makes it far easier to hit.

The fix needs no counter and no hot-path work, because the library already reports
exactly the quantity in question: maximal executions are `Full` plus `Blocked`. After
the run, before returning success:

```cpp
if ((options.mMustExternalize || options.mCheckAgreement) &&
    result.full_executions_explored + result.blocked_executions_explored == 0)
{
    // inconclusive: no maximal execution existed, so no property was evaluated
    return 2;
}
```

Exit 2 is distinct from the exit 1 already used for genuine failures (`:1596`,
`:1619`, `:1626`), so scripts can tell "property violated" from "property never
evaluated". This only fires on an otherwise-clean run: a real violation returns 1
first. `bench-dpor.sh` uses neither flag in any scenario, so no fingerprint is
affected.

### Trace bundle: write version 7, keep reading version 6

`src/scp/test/ScpDporTraceJson.cpp` needs the new spelling in **both** directions of
the `terminal.kind` string mapping (read side at `:495`). The key set is unchanged,
but the serialized *value domain* of `terminal.kind` widens, so an older reader will
reject a new bundle. Set `TRACE_BUNDLE_VERSION = 7` for bundles we write, and accept
both 6 and 7 on read.

Do **not** add 6 to the incompatible-version rejection ladder: versions 1-5 are
rejected for documented semantic incompatibilities, whereas a v6 bundle carries the
same scenario options and trace semantics and its terminal kinds are a strict subset
of the v7 enum. Invalidating every saved debugging artifact for a purely additive
change is not warranted.

### `configure.ac` API probe

`configure.ac` carries a DPOR API probe that `static_assert`s on
`TerminalExecutionKind::Blocked` and errors with "the DPOR checkout at $DPOR_DIR is
too old ... update it to commit b238b19 or later". Left alone, an older checkout
passed via `--with-dpor-dir` would configure successfully and then fail deep in the
build once the harness referenced `max_thread_events` and `ThreadEventLimit`.

Extend the probe to compile both new API elements, update the minimum-commit hint to
the new `external/dpor` pin, and mirror the requirement in
`docs/dpor-integration-status.md`. Verification must therefore include `autogen.sh`
and a fresh `configure`, not just an incremental `make`.

## Part 3 — tests, bench, docs

`src/scp/test/SCPDporSmokeTests.cpp` — model on the depth-budget test at
`:998-1041` ("scp dpor stop-on-prepare reaches a blocked execution"), which is the
existing precedent for asserting on result stats:
- with `config.max_thread_events = 3`: `depth_limit_executions_explored == 0`,
  `thread_event_limit_executions_explored > 0`,
  `max_thread_event_depth_reached == 3`, and an exact `executions_explored`
  fingerprint;
- on an unbounded terminating scenario, `max_thread_event_depth_reached` equals the
  observed value (pins the stat itself);
- a `ThreadEventLimit` terminal makes `isMaximalExecution()` false — the
  regression guard for property-check exclusion;
- a **version-6 replay regression**: an existing v6 bundle still loads and replays
  under the new reader, alongside a **version-7 round-trip** carrying a
  `thread-event-limit` terminal kind through `toJson` → `traceBundleFromJson` →
  replay;
- **parser cases** for the tightened `parseSizeValue`: zero, a leading minus,
  trailing characters, overflow, and a missing value, plus `--thread-event-depth -1`
  leaving the option unset and `-1` still being rejected by every other option that
  uses the shared helper.

The `--must-externalize` inconclusive path is a runner-level behavior, so it is
covered by the shell verification below rather than by a Catch case (the
investigation main is not linked into `stellar-core-dpor-tests`).

`src/scp/test/bench-dpor.sh` — `check` mode (`:210-224`) prints `tail -1` of each
run as a byte-for-byte fingerprint, so all 13 lines must be re-recorded once. Add
one `--thread-event-depth` scenario. Two parser constraints to verify rather than
assume: `scale` mode's `sed -n 's/.*executions=\([0-9]*\).*/\1/p'` (`:325`) is
greedy and takes the **last** `executions=` on the line — the new hyphenated
summary keys are safe, but the underscored *progress* key
`thread_event_limit_executions=` does end in `executions=`, so confirm `scale`
never runs with `--print-stats` (or rename that key). `head` mode (`:233-246`) is
key-based and tolerates appended keys.

Docs (existing files only): `docs/dpor-integration-status.md` CLI surface
(`:324-358`), summary/progress line contents (`:368-375`), and the recorded
fingerprints (`:586-621`); `docs/dpor-investigation-scenarios.md` (`:1-13`,
`:330-358`); and the `--depth` note in `CLAUDE.md` / `AGENTS.md`, which should now
distinguish search-tree depth from per-thread event depth. Also note the
interaction that `--fail-on-first-blocked` combined with a cap may find nothing,
because an execution with both a capped and a blocked thread is now
`ThreadEventLimit` rather than `Blocked`.

## Verification

Library first, standalone (`external/dpor/AGENTS.md:77-90`):
```bash
cd external/dpor
cmake --preset debug && cmake --build --preset debug && ctest --preset debug
cmake --preset asan  && cmake --build --preset asan  && ctest --preset asan
scripts/run_tsan.sh
```

Then the harness. The API probe changed, so this needs a fresh configure rather
than an incremental build:
```bash
./autogen.sh
./configure --enable-dpor --enable-nsc-sccache CC=clang-20 CXX=clang++-20
make -C lib -j"$(nproc)"
make -C src -j"$(nproc)" stellar-core-dpor-tests scp-dpor-investigation
./src/stellar-core-dpor-tests "[scp][dpor][smoke]"
./src/scp-dpor-investigation --help | grep -A2 thread-event-depth
```
Also confirm the probe actually rejects an old checkout — point
`--with-dpor-dir` at a pre-change `external/dpor` and check that `configure` fails
with the updated minimum-commit message instead of failing later in the build.

Behavioral checks, against the numbers in Context:
```bash
# bound bites, is reported, and displaces depth-limit truncation
./src/scp-dpor-investigation --thread-event-depth 3
#   expect depth-limit=0, thread-event-limit>0, max-thread-event-depth=3

# the case that motivated this: real coverage instead of 46164 truncated runs
./src/scp-dpor-investigation --nodes 4 --stop-on-prepare --thread-event-depth 8
#   expect depth-limit=0 and a nonzero full=

# unbounded runs are unchanged except for the two new keys
./src/scp-dpor-investigation --depth 30 --stop-on-prepare
#   expect executions=94 full=87 blocked=4 error=0 depth-limit=3
#          thread-event-limit=0 max-thread-event-depth=<observed>

# property checks are not spuriously failed by truncation -- and the check is
# not vacuous: assert it actually inspected maximal executions
./src/scp-dpor-investigation --stop-on-externalize --must-externalize \
    --thread-event-depth 6
#   expect exit 0 AND full + blocked > 0 on the summary line

# the new inconclusive path: a cap tight enough that nothing is maximal
./src/scp-dpor-investigation --stop-on-externalize --must-externalize \
    --thread-event-depth 2
#   expect exit 2, full=0 blocked=0, and a message saying no property was evaluated

# strict parsing
./src/scp-dpor-investigation --thread-event-depth 5x    # expect exit 1, parse error
./src/scp-dpor-investigation --thread-event-depth -2    # expect exit 1, parse error
./src/scp-dpor-investigation --sync-steps -1            # expect exit 1: no sentinel here
./src/scp-dpor-investigation --thread-event-depth -1 --stop-on-prepare
#   expect the unbounded result, i.e. thread-event-limit=0 and --depth left at 12

# progress line carries both keys
./src/scp-dpor-investigation --nodes 4 --stop-on-prepare --print-stats 1 \
    --thread-event-depth 12 | grep '^progress' | head -1
```

Fingerprint:
```bash
src/scp/test/bench-dpor.sh check   # re-record the 13 lines, diff deliberately
```

Performance. `bench-dpor.sh` already appends `W=${W:---workers 8}` to every
scenario (`:21`, `:29-32`), so `bench` / `check` / `head` all exercise the parallel
path by default. Keep a copy of the pre-change binary and measure back to back in
one session, medians of several runs:
```bash
# noise floor first: pre-change binary against a copy of itself
BIN=/path/to/baseline      src/scp/test/bench-dpor.sh bench
BIN=/path/to/baseline-copy src/scp/test/bench-dpor.sh bench

W="--workers 1" src/scp/test/bench-dpor.sh bench   # serial: the compute_next_event compare
                src/scp/test/bench-dpor.sh bench   # parallel: the terminal-path fold
                src/scp/test/bench-dpor.sh scale   # per-worker scaling; counts must stay identical
```
Also time one scenario with and without `--print-stats 1` — that is the only
configuration in which `flush_local_counts` runs mid-exploration, so it is the one
that exercises the shared-atomic fold at all. And with the flag on, confirm the
*expected speedup* rather than merely the absence of a regression.

This host is `addict-glad-64ta`, not `pop-os-desktop`, so the 20%-noise rule does
not apply — the floor has to be measured with the identical-binary control above
before any delta is believed.

Submodule mechanics, last: commit on top of `febae6f`, push to `origin dpor-perf`
(fast-forward from local `parallel-scaling`), then bump the `external/dpor` pin in
a stellar-core commit with `git -c commit.gpgsign=false`. Confirm before pushing to
the public repo, since that is outward-facing.

## Review

Verdict: **changes requested before implementation**. Putting the bound and its
terminal accounting in the DPOR library is the right architectural direction,
and deferring the parallel maximum fold to `flush_local_counts` preserves the
current terminal-path synchronization shape. The following issues should be
resolved in the plan first.

1. **Blocking: `ThreadEventLimit` does not yet have an unambiguous meaning.**
   The claim that a capped thread cannot carry a trailing `Block` is false. At
   `step == cap - 1`, `compute_next_event` may receive an unsatisfied blocking
   receive and synthesize a `Block`; `handle_enter_frame` then adds that as the
   thread's `cap`th event. The plan itself acknowledges this at lines 182-185.
   Such a block must remain eligible for blocked-receive rescheduling: removing
   it drops the thread back to `cap - 1`, so the replacement receive still fits
   under the bound.

   More generally, `has_thread_at_event_limit(count >= cap)` is the same
   heuristic the library design says it eliminates. It cannot distinguish:

   - a thread for which the cap suppresses another event;
   - a thread whose function would naturally return `nullopt` at exactly
     `step == cap`; or
   - a thread whose `cap`th event is an engine-injected terminal `Block`.

   Choose and document one contract. If `ThreadEventLimit` conservatively means
   "the graph reached the cap and the engine did not ask whether the thread had
   another event", then it is not proof that the execution was truncated and
   the current "not maximal" / "bound bit" wording must be softened. If it is
   intended to mean that the bound actually suppressed an event, the engine
   must query or cache the thread result at the cap; event count alone cannot
   establish that. In either case, remove the incorrect blocked-reschedule
   rationale and add tests for a block created at `cap`, its reschedule after a
   compatible send, and a program that naturally completes after exactly
   `cap` events.

2. **High: the configure-time DPOR API probe must be updated.**
   `configure.ac:568-583` currently accepts any checkout with
   `TerminalExecutionKind::Blocked`. After this change, an older checkout passed
   through `--with-dpor-dir` will configure successfully and fail later when the
   harness refers to `max_thread_events` and `ThreadEventLimit`. Extend the probe
   to compile both new API elements, update the minimum-commit error message and
   integration-status documentation, and include `autogen.sh` plus a fresh
   configure in verification. The statement that no configure/build wiring
   changes are needed is therefore incorrect.

3. **High: the property-check verification can pass vacuously.**
   The proposed `--must-externalize ... --thread-event-depth 6` check only expects
   exit 0. If every execution is `ThreadEventLimit`, `isMaximalExecution` skips
   every check and the command still exits 0. That recreates the exact
   "46k truncated executions, no coverage" usability problem motivating this
   feature. At minimum, verification must assert `full + blocked > 0`; preferably
   the runner should report an inconclusive/nonzero result when
   `--must-externalize` or the current maximal-only `--check-agreement` checks no
   maximal execution. The existing smoke tests provide the right precedent by
   asserting `maximalExecutionsChecked > 0`.

4. **High: the load-bearing exploration-equivalence claim needs a direct test.**
   Mirroring the simple `max_depth` test does not exercise backward restriction
   or blocked rescheduling. Compare the terminal graph-signature set from
   `max_thread_events = N` with the set from the same program whose thread
   functions are explicitly wrapped with `step >= N ? nullopt : f(...)`, while
   deliberately ignoring the expected terminal-kind difference. Run that
   differential in sequential and parallel modes and include a program that
   forces a backward revisit to reduce a capped thread below the limit. A wrapped
   program can also be fed to the existing exhaustive oracle, so the bound need
   not be excluded categorically from oracle-backed coverage.

5. **Medium: terminal-kind precedence is unspecified.** The existing
   `max_depth` check runs before `compute_next_event`, while an `Error` is
   published immediately after it is returned. Consequently `DepthLimit` wins
   when the frame depth is already exhausted, `Error` wins when an uncapped
   thread returns one, and `ThreadEventLimit` is considered only on the
   no-next-event path. Document and test the simultaneous depth/thread-limit and
   error/thread-limit cases; otherwise the new counter and capture hints can be
   surprising when the maximum-depth stat equals the cap but the terminal is
   counted under another kind.

6. **Medium: the trace-version decision needs a compatibility rationale and a
   test.** The operational flag is correctly absent from scenario `Options`, but
   `terminal.kind` is part of the serialized schema's value domain. An older
   version-6 reader will reject a new version-6 bundle containing
   `thread-event-limit`; an unchanged key set does not make that forward
   compatible. Either bump the version, or explicitly define this as an allowed
   additive enum extension and accept the old-reader limitation. In both cases,
   add a JSON round-trip/replay test for the new terminal kind.

7. **Medium: `parsePositiveSizeValue` is not actually a strict positive-integer
   validator.** It delegates to `std::stoull` without checking the consumed
   length; `-1` and values with trailing junk can be accepted. Tighten the shared
   parser or add a strict parser for this option, with cases for zero, a leading
   minus, trailing characters, overflow, and a missing value.

8. **Low: define the maximum stat as a maximum over published terminal
   executions.** That is what the proposed terminal-time fold computes; it is
   not necessarily a high-water mark over every transient graph when parallel
   exploration stops early. Also revise the bound-off performance description:
   in addition to the predictable comparison in `compute_next_event`, the new
   unconditional stat performs an O(thread-count) scan for every published
   terminal. The planned back-to-back unbounded benchmarks are sufficient to
   measure that cost.

END REVIEW

## Response to review

Verdict accepted: changes requested. Findings 1, 3, 4, 5 and 8 are correct as
written. Findings 2, 6 and 7 were checked against the tree and confirmed. The
plan body above has **not** yet been revised — this section records the
disposition and the resulting delta.

### Checkable findings, verified

- **Finding 2 confirmed.** `configure.ac` does carry a DPOR API probe that
  `static_assert`s on `TerminalExecutionKind::Blocked` and errors with "update it
  to commit b238b19 or later". The plan's claim that no configure/build wiring
  changes are needed was wrong: an older `--with-dpor-dir` checkout would
  configure clean and then fail at compile time with confusing errors.
- **Finding 7 confirmed.** On this toolchain `std::stoull("-1")` returns
  `18446744073709551615` and `std::stoull("5x")` returns `5`. Neither throws, and
  `parseSizeValue` checks neither the consumed length nor a leading minus.
- **Finding 3's precedent confirmed.** `maximalExecutionsChecked > 0` exists at
  `SCPDporSmokeTests.cpp:1299`/`:1336` and `:1351`/`:1381`.

### Finding 1: accepted, with a better fix than either proposed contract

The review is right and the plan was wrong. A thread at `step == cap - 1` that
returns an unsatisfiable blocking receive receives a synthesized `Block` as its
`cap`th event, so `thread_event_count == cap` with a trailing `Block`. The
"a capped thread can never carry a trailing `Block`" rationale is false, and it
contradicted the plan's own note that `Block` events count toward the total.

The fix is not to choose between the two contracts using `count >= cap`. Instead:

- `has_thread_at_event_limit` is dropped entirely, along with its scan.
- `compute_next_event` gains an out-param, set when it skips a thread *because of
  the cap*, with that check placed **after** the existing `thread_is_terminated`
  check.
- Classification becomes
  `suppressed ? ThreadEventLimit : has_blocked_thread() ? Blocked : Full`.

This is exact rather than heuristic, and the blocked-at-`cap-1` case resolves
correctly for free: that thread's `cap`th event is a `Block`, so it is terminated,
so the terminated check skips it before the cap check is reached and the flag is
never set — it classifies as `Blocked`. The blocked-receive reschedule then
re-asks it at `step = cap - 1`, still under the bound, so that path genuinely needs
no change (but for a different reason than the plan gave).

One ambiguity the review names does survive: a thread whose function would
naturally return `nullopt` at exactly `step == cap` cannot be distinguished from a
capped one without asking. The conservative contract is therefore adopted
verbatim: **`ThreadEventLimit` means the engine declined to ask at least one thread
whether it had another event, because that thread was at the bound.** It is not
proof of truncation, and the "not maximal" / "the bound bit" wording in the plan
body will be softened accordingly.

### Decisions taken

- **Finding 6 — bump the version.** `TRACE_BUNDLE_VERSION` goes 6 → 7, the
  rejection ladder extends to v6, the new kind spelling lands in both directions,
  and a round-trip plus replay test is added. Consequence to accept and document:
  any bundle already sitting in `dpor-traces/` stops loading.
- **Finding 7 — tighten the shared parser, keep `-1` as "no limit".**
  `parseSizeValue` rejects trailing junk, non-numeric input and overflow, and `-1`
  becomes an explicit unlimited sentinel rather than the wrap-around accident it is
  today. Other negatives are rejected; `0` remains an error through
  `parsePositiveSizeValue`. This applies to every option using the shared helper,
  which is a fix for each of them. One wrinkle: `-1` → `SIZE_MAX` would put the
  engine on the `max_thread_events != 0` path and pay the comparison per thread per
  frame entry for a bound that can never fire, so the harness normalizes it to the
  library's `0`-means-unlimited when assigning `config.max_thread_events`, keeping
  the fast path intact. Parser tests cover zero, `-1`, other negatives, trailing
  characters, overflow and a missing value.
- **Finding 3 — not fixed, recorded instead.** The runner keeps its current
  behavior; the vacuous-pass sharp edge is documented as a known issue. One
  exception, which is not a fix to the finding: the plan's own verification step
  (`--must-externalize --thread-event-depth 6`, expect exit 0) is vacuous for
  exactly the reason given and proves nothing as written, so it gains a
  `full + blocked > 0` assertion.

### Resulting delta to the plan body

1. Replace `has_thread_at_event_limit` with the `compute_next_event` out-param;
   reorder so the cap check follows the terminated check (finding 1).
2. Remove the false blocked-reschedule rationale; substitute the correct one, and
   restate the `ThreadEventLimit` contract conservatively (finding 1).
3. Extend the `configure.ac` API probe to compile `max_thread_events` and
   `ThreadEventLimit`, update the minimum-commit error message and the
   integration-status docs, and add `autogen.sh` plus a fresh configure to
   verification. Retract the "no build wiring changes" claim (finding 2).
4. Add the differential equivalence test: compare terminal graph-signature sets
   between `max_thread_events = N` and the same program explicitly wrapped as
   `step >= N ? nullopt : f(...)`, ignoring the expected terminal-kind difference,
   in both sequential and parallel modes, including a program that forces a
   backward revisit to drop a capped thread below the bound. The wrapped program
   is a plain program, so it can also go through the exhaustive oracle — the
   "exclude the bound from oracle-backed coverage" caveat is withdrawn (finding 4).
5. Document and test terminal-kind precedence:
   `DepthLimit > Error > ThreadEventLimit > Blocked > Full`, which follows from
   `max_depth` being checked before `compute_next_event` and `Error` immediately
   after it (finding 5).
6. Add tests for a `Block` created at `cap`, its reschedule after a compatible
   send, and a program that naturally completes after exactly `cap` events
   (finding 1).
7. Trace bundle version bump and tests as decided above (finding 6).
8. Parser tightening and `-1` sentinel as decided above (finding 7).
9. Restate the stat as a maximum over *published terminal executions*, not a
   high-water mark over every transient graph, and correct the bound-off cost
   description to include the unconditional O(thread-count) per-terminal scan
   (finding 8).

<!-- END RESPONSE -->

## Review of response

Verdict: **partially accepted; changes still requested**. The response fixes the
core event-limit classification problem and satisfactorily addresses the
configure probe, equivalence coverage, terminal precedence, and stat definition.
Two proposed dispositions introduce avoidable compatibility problems, and the
vacuous property result remains an open high-priority usability issue.

1. **Accepted: the cap-suppression signal is the right classification input.**
   Setting a per-call signal only when `compute_next_event` skips a
   nonterminated thread because it is at the cap correctly handles the trailing
   `Block` case. A `Block` added as event `cap` is skipped by the terminated check,
   remains eligible for rescheduling at `step == cap - 1`, and is classified
   `Blocked` if no other thread was actually suppressed. A restricted revisit
   that lowers the count naturally re-enables the thread. This preserves the
   terminal graph set of the explicitly wrapped program.

   The adopted conservative contract also resolves the exact-length completion
   case: it is intentionally `ThreadEventLimit` because the engine declined to
   ask at `step == cap`, even though the function might have returned `nullopt`.
   The implementation must reset the signal for every `compute_next_event` call
   (a small result struct would make that harder to misuse), discard it when a
   normal next event or blocked-reschedule child is found, and consult it only on
   the final no-next/no-reschedule path. The proposed tests cover the important
   cases.

2. **High: do not make `-1` a sentinel in the shared size parser.**
   `parseSizeValue` is also used by `--max-queued-tasks`, `--sync-steps`, both
   polling/flush intervals, `--invalid-proposer`, and `--replay-node`;
   `parsePositiveSizeValue` additionally feeds `--replay-slots-per-node`.
   Teaching the shared parser that `-1` means `SIZE_MAX` silently gives all of
   those unrelated options a new and often unsafe meaning. It also makes the
   legitimate decimal value `SIZE_MAX` indistinguishable from the sentinel, so
   the proposed thread-depth normalization would turn that explicit finite bound
   into unlimited exploration.

   Make the shared parser a strict unsigned-integer parser that rejects every
   leading minus and trailing character. The new option already has an unlimited
   representation: omit it, yielding `config.max_thread_events = 0`. If an
   explicit `-1` spelling is still considered necessary, recognize that literal
   only in the `--thread-event-depth` branch and represent it as an absent
   optional; do not route it through `parseSizeValue` or encode it as `SIZE_MAX`.

3. **Medium: a version bump need not invalidate compatible version-6 traces.**
   Version-6 bundles contain the same scenario options and trace semantics that
   version 7 would consume; their terminal kinds are a strict subset of the new
   enum. This differs from versions 1-5, which are rejected for documented
   semantic incompatibilities. Invalidating every existing debugger artifact is
   therefore unnecessary.

   Either retain version 6 and define the new enum spelling as an additive
   extension, or write version 7 while continuing to load version 6. The latter
   gives old readers an honest incompatibility signal for new bundles without
   sacrificing backward compatibility in the new reader. Add both a version-6
   replay regression and a version-7 `thread-event-limit` round-trip/replay test;
   do not add version 6 to the incompatible-version rejection ladder without a
   semantic reason.

4. **High and still open: documenting the vacuous property pass does not resolve
   it.** Adding `full + blocked > 0` to this plan's verification prevents the test
   itself from being vacuous, but users can still run `--must-externalize` or the
   current maximal-only `--check-agreement`, check only the zero exit status, and
   receive no indication that every execution was excluded. That is the same
   failure mode identified in the motivating example.

   The preferred fix remains to track whether either property inspected a
   maximal execution and return a distinct inconclusive/nonzero result when it
   inspected none. If that is deliberately deferred, keep Finding 3 explicitly
   open in the revised plan body, describe the runner behavior as a known
   limitation rather than a resolved finding, and avoid claiming that the new
   counter by itself prevents no-coverage conclusions.

Subject to those points, the remaining response items are accepted. In
particular, updating the configure probe and minimum commit, differentially
checking the bounded engine against a wrapped program (including revisits and
the oracle), testing the stated terminal-kind precedence, and accounting for the
unconditional terminal-time stat scan are appropriate revisions.

END REVIEW

## Response to review round two

All four points accepted. The plan body above has now been **revised in place**, so
it no longer contradicts these responses; the reviews and responses remain below as
the audit trail.

1. **Signal lifetime — adopted, with the suggested result struct.** The suppression
   flag now lives in a `NextEventResultT` returned by `compute_next_event` rather
   than in an out-param, which makes the required discipline structural: it is
   constructed fresh per call so it cannot go stale, a normal next event or a
   blocked-reschedule child discards it implicitly, and it is read on exactly one
   path. The exact-length completion case is documented as intentionally
   `ThreadEventLimit` and pinned by a test so it is not later "fixed".

2. **`-1` in the shared parser — withdrawn.** The point about
   `18446744073709551615` being indistinguishable from the sentinel is decisive: the
   proposed normalization would have converted an explicit finite bound into
   unlimited exploration, which is precisely the class of bug the tightening exists
   to remove. `parseSizeValue` becomes a strict unsigned parser rejecting every
   leading minus and trailing character, with no sentinel. The `-1` spelling is
   recognized only in the `--thread-event-depth` branch and represented as an absent
   optional, so no `SIZE_MAX` encoding exists anywhere and the other seven options
   using the helper are unaffected. Documented consequence: `-1` leaves `--depth` at
   its default, since the implicit raise keys on the option being set.

3. **Versioning — write 7, keep loading 6.** Taking the second of the two offered
   options. Version 6 is not added to the rejection ladder, which is reserved for
   the documented semantic incompatibilities of versions 1-5. Both a version-6
   replay regression and a version-7 `thread-event-limit` round-trip are in the test
   list.

4. **Vacuous property pass — fixed, not deferred.** Reversing the earlier decision
   to leave it open. The fix turned out to need neither a new counter nor any
   hot-path work: maximal executions are exactly `full + blocked`, which
   `VerifyResult` already reports, so the runner returns a distinct exit 2 when
   `--must-externalize` or `--check-agreement` was requested and that sum is zero.
   Exit 2 is distinguishable from the exit 1 used for genuine violations, and since
   a real violation returns 1 first, the inconclusive path only fires on an
   otherwise-clean run. No `bench-dpor.sh` scenario uses either flag, so no
   fingerprint moves. This also closes the pre-existing
   `--stop-on-prepare --must-externalize` version of the same trap, recorded at
   `docs/dpor-integration-status.md:661`.

<!-- END RESPONSE -->

