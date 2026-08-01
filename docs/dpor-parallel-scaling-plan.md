# DPOR parallel exploration: scaling analysis and plan

Status: **implemented**. Phases 0, 1, 3, 4 and 5 landed; Phase 2 was correctly
skipped because its entry gate did not pass. See "Outcome" immediately below
for what was measured; the analysis that follows is preserved as the record of
why the work was done, and its numbers are the *pre-change* baseline.
Date: 2026-07-31, implemented 2026-08-01.
Scope: `verify_parallel()` work scheduling in the pinned `external/dpor`
submodule (commit `23e1998`), as exercised by `scp-dpor-investigation`.

## Outcome

All measurements below are paired same-session medians on `addict-glad-64ta`
(the same 16-physical/32-logical SMT2 host used for the original analysis), with
the 13-scenario `bench-dpor.sh check` fingerprint byte-identical before and
after, and every engine execution-set test green.

| Phase | Result |
|---|---|
| 0 — operational guidance | Done, documentation only, as decided. The guidance changed: after Phases 1 and 3 there is no knee, so "use `--workers 8`" is obsolete. |
| 1 — remove the broadcast | **Landed and decisive.** D1 confirmed. |
| 2 — distributed queues | **Not done: entry gate failed.** Correct per the plan. |
| 3 — ND/receive splitting (Design A) | **Landed.** 2PC showed no regression; S2 improved 2.6x. |
| 4 — gates and defaults | `min_fanout` **removed** (option (b)). Queue budget and `sync_steps` re-checked, defaults kept. |
| 5 — scaling regression check | `bench-dpor.sh scale` added, opt-in, gated on the constructed reference shape. |

**Phase 1** was a falsification test for D1 and D1 survived it. At 32 workers on
S2: futex calls 5,682,256 -> 329,119 (17x), CPUs utilized 3.68 -> 12.43,
context switches 11.9M -> 1.2M, system time 62.9s -> 28.8s, wall 34.7s -> 6.8s.
S2 at 32 workers went from 1.6x *slower* than one worker to 3.1x faster.

**Phase 2's entry gate did not pass**, so it was not attempted. Of the three
conditions required, (a) `worker_loop_impl`-minus-`process_task` fell from 43%
to ~20% of cycles and (b) system time fell from 46% to 31% of total CPU — both
reduced but arguably still material — while (c) "scaling still degrades before
physical-core count" became plainly false: both scenarios improve monotonically
from 1 to 8 to 16 workers. The plan required all three, so the remaining ceiling
was re-evaluated against F7 instead.

**F7 turned out to be two different things.** On S1 the end-of-run occupancy
collapse was largely a *contention artifact*: post-Phase-1 the queue stays at
60-64/64 with 25-32/32 workers active for the whole run, where the pre-fix
binary repeatedly drained to `queued=0/64` with 4-16/32 active. But S2 — which
the original analysis never checked for starvation — starves badly, sitting at
`queued=0/64` with 4-20/32 active for most of its run. That is why S2 plateaued
at 3.2x while S1 reached 9.2x, and it is what made Phase 3 worth doing. Phase 3
should therefore be read as targeting S2, not S1 as originally written.

**Phase 3 cleared the 2PC bar that sank the two earlier prototypes.** At 8
workers, 11 alternated repetitions gave send-only 7619ms versus splitting
7752ms (1.018x) — while a *copy of the send-only binary measured against itself
in the same session* came out at 0.966x, a larger deviation than the change
being tested. Splitting was slower in 5 of 11 paired repetitions, and execution
counts were identical (7,262,928) at every worker count. An earlier version of
the gate did regress 2PC by ~7%, but the cause was the gate itself calling
`can_spawn()` (and through it `stop_requested()`) on every ND and receive
frame, not the splitting: splits fired only ~1,000 times against 7.26M
executions. Reordering the gate so the shared stop flag is only touched after
the idle check passes removed it.

Final scaling, speedups against the pre-change binary at one worker:

| | w=1 | w=8 | w=16 | w=32 |
|---|---|---|---|---|
| S1 before | 1.00x | 4.79x | 7.23x | 6.31x |
| S1 after | 1.00x | 5.17x | 8.35x | **9.83x** |
| S2 before | 1.00x | 2.51x | 1.99x | 0.62x |
| S2 after | 1.00x | 4.32x | 7.08x | **8.31x** |

Still short of the ~16x physical-core ceiling, so there is headroom left; the
next lever is no longer contention (D1, fixed) or the spawn-site restriction
(D2, addressed), and would need fresh profiling to identify.

**Phase 4 defaults.** `min_fanout` was removed outright — option (b). It passed
a literal `2` at its only call site, so it had exactly two reachable behaviours
("spawn at send revisits" and "never spawn"), and option (a) was rejected on
inspection rather than on taste: a send revisit with a single child is still
worth handing off because the owning worker keeps the forward continuation, so
gating on the cheap upper bound would only lose parallelism. `max_workers = 1`
remains the way to explore serially.

Of the remaining knobs, only one default moved, and only where the measurement
was consistent:

| Knob | Sweep result | Decision |
|---|---|---|
| `split_poll_interval_steps` | S2 2.49s -> 2.05s, S1 16.59s -> 15.67s, 2PC 7284ms -> 6871ms at interval 1 | **default 64 -> 1** |
| `max_queued_tasks` (`2 * workers`) | 0-12% better at 128-256, non-monotonic past 256, and inside S1's noise | unchanged |
| `sync_steps` | flat from 128 to 512 (2.64s vs 2.65s); strict mode 2.82s | unchanged at 512 |
| `progress_poll_interval_steps` | no effect unless `on_progress` is set, since `maybe_report_progress()` returns immediately otherwise | unchanged |

Raising `max_queued_tasks` is worth trying by hand on a starved workload, but
the signal was not stable enough to move a default that affects everyone: RSS
was flat (218-232 MB on S2, 386-408 MB on S1) across budgets from 64 to 1024,
so the ceiling is not memory, and the wall-clock effect did not survive
repetition cleanly.

Read alongside **`external/dpor/docs/parallel_exploration_implementation.md`**,
which is the engine's own design record for this subsystem. That document
predates this one and explains why the current policy is what it is; several
alternatives proposed below have already been tried and rejected there, and
this plan is written to respect that history rather than relitigate it.

## TL;DR

Parallel exploration does not scale, and past a knee it actively regresses.
On the benchmark machine the second scenario below is **1.6x slower at
`--workers 32` than at `--workers 1`**.

The cause is not work starvation and not memory allocation. It is the
scheduler's synchronisation: a single global task queue guarded by one mutex,
plus a `notify_all()` broadcast on *every* task completion. Cost is O(workers)
per completed task against a fixed amount of useful work, so total overhead
grows as O(workers x tasks). Measured system time grows as O(workers^2).

A second effect caps the achievable speedup even once synchronisation is fixed:
tasks are generated at exactly one place in the algorithm (send backward
revisits), so subtrees that branch only on reads-from choice or nondeterministic
choice cannot be split. Unlike the first problem, **this one is a known,
deliberate, benchmarked design decision** — see "Prior art" below. The plan
treats it as a tradeoff to be re-measured after the contention fix, not as a
defect.

## Measurement setup

- Host `addict-glad-64ta`: AMD EPYC, **16 physical cores / 32 logical
  (SMT2)**, 1 NUMA node, 32 MiB L3. Ubuntu 24.04. Virtualised, so mild
  run-to-run variance is expected.
- Binary: in-tree `./src/scp-dpor-investigation`, built with
  `--enable-dpor --enable-nsc-sccache`, `clang++-20`.
- Because the host is SMT2, **linear scaling to 32 was never achievable**. A
  realistic ceiling is ~16x from physical cores plus a modest SMT gain.
- Every run recorded here reported **identical aggregate terminal-execution
  counts** at every worker count, so the wall-clock comparisons are between runs
  doing the same amount of work by that measure. Equal aggregate counts do not
  by themselves establish that the same execution *set* was explored — see
  "Validation requirements" — but no discrepancy would explain a 4x wall-clock
  difference.

Scenarios (abbreviated S1 and S2 throughout):

```
# S1 - 5,600,446 executions (all full)
--nodes 3 --fifo --txset-status always-valid --download-time below \
  --stop-on-externalize --depth 200

# S2 - the user-supplied scenario, depth-bounded to 56 so it terminates
#      quickly enough to sweep. 1,278,277 executions
#      (43,605 full, 1,234,672 depth-limit)
--nodes 3 --fifo --txset-status downloading-then-valid \
  --nomination-always-downloading --download-time nondet \
  --stop-on-externalize --depth 56
```

S2 at the originally requested `--depth 200` does not terminate within 10
minutes at any worker count and was reduced to depth 56 purely to make a
scaling sweep affordable. The depth bound changes the tree size, not the
branching structure being studied.

## How work is scheduled today

All scheduling lives in `ParallelExecutor`
(`external/dpor/include/dpor/algo/dpor.hpp:1349`).

- `run()` (`:1374`) starts `max_workers` OS threads (thread 0 is the caller)
  and seeds the system with **exactly one task**: the empty graph at depth 0.
- A task (`ExplorationTask`) is a fully-owned `ExplorationGraphT` plus a DPOR
  tree depth and a mode (`Visit` / `VisitIfConsistent`).
- Workers pull from a **single shared FIFO `std::queue`** behind one
  `queue_mutex_` and one `queue_cv_`. A dequeued task is explored depth-first
  to exhaustion (`process_task` -> `DepthFirstExplorer::run`) before the worker
  returns for more.
- Termination: `search_complete_` is set when the queue is empty and
  `active_workers_ == 0`.
- Engine default worker count is `std::thread::hardware_concurrency()`
  (`resolve_max_workers`, `:1555`); default queue budget is `2 * workers`
  (`resolve_max_queued_tasks`, `:1563`). Note these are the *engine's*
  defaults for a zero-valued option, not the CLI's — see Phase 0.

### Where parallel tasks come from

`DepthFirstExplorer` (`:2106`) has exactly three branching frame kinds:

| Frame kind | Enumerates | Handler | Can spawn a task? |
|---|---|---|---|
| `ResumeNd` | nondeterministic choice alternatives | `:2358` | **No** |
| `ResumeReceive` | reads-from source alternatives | `:2388` | **No** |
| `ResumeSendRevisits` | backward-revisit children of a send | `:2426` | **Yes** |

`try_enqueue_owned_task` (defined `:1825`) has **exactly one call site in the
entire engine**: `:2443`, inside `handle_resume_send_revisits_frame`.
`can_spawn` likewise has one call site, `:2343`.

ND and rf-choice branches push frames into the *current* exploration context and
are explored inline by the owning worker using checkpoint/rollback on a single
graph. A backward revisit, by contrast, already materialises an owned graph via
`restrict_masked`, so handing it off costs only a move.

### Prior art: the send-only policy is deliberate

`external/dpor/docs/parallel_exploration_implementation.md` documents this as a
considered decision, not an omission:

- On the 4-participant no-crash 2PC timeout benchmark, restricting parallelism
  to send branches was **neutral to ~8% faster** across 1-20 workers versus also
  enqueuing ND/receive siblings, at identical execution counts (7,262,928).
- Two ND/receive enqueue prototypes were built and rejected. An exact-reservation
  variant regressed the 2PC benchmark from 12,815 ms to 17,183 ms (default queue
  budget). A follow-up hard-reservation variant still regressed it to 16,673 ms.
- An `enqueue_budget` mechanism existed to bound ND/receive copies and was
  removed in favour of the simpler send-only policy.
- The doc's own conclusion: "the eager reserved-enqueue shape itself appears to
  pay remote copy/materialize/scheduling cost before the local work-first path
  can make progress."

Two observations that this plan rests on, both of which must be tested rather
than assumed:

1. Those experiments ran at up to 8 and 20 workers **against the contended
   scheduler described below**. Adding enqueues to a scheduler whose cost is
   O(workers) per task makes contention worse, so the measured regression may be
   partly an artifact of the bottleneck this plan fixes first. That is a
   hypothesis, not a conclusion.
2. Both rejected prototypes were **eager** — they reserved and materialised
   siblings whether or not any worker was idle. A starvation-triggered split
   pays the copy only when the pool has nothing to do, which is a different cost
   profile. Also different: the 2PC benchmark may simply not exhibit the
   end-of-run starvation tail that F7 documents for S1.

Neither observation licenses skipping the 2PC no-regression check in Phase 3.

### Secondary gates

- `can_spawn(frame.dpor_tree_depth + 1U, 2)` at `:2343` passes the **literal
  constant `2`** as the fanout, as both the comment at `:246` and the engine doc
  state explicitly. `min_fanout` is therefore an on/off switch, not a tunable.
- Queue overflow is handled by exploring inline; the queue is only a backlog
  buffer, and workers always prefer local work over waiting for queue space.
- `worker_loop_impl` calls `queue_cv_.notify_all()` **unconditionally after
  every task completion** (`:1642`).

## Findings

### F1. Scaling is sublinear, and inverts past a knee

S1 (5,600,446 executions; 2 reps at w>=8, median):

| workers | wall | speedup |
|---|---|---|
| 1 | 168.22s | 1.00x |
| 2 | 99.35s | 1.69x |
| 4 | 57.48s | 2.93x |
| 8 | 34.41s | 4.89x |
| **16** | **22.43s** | **7.50x** |
| 24 | 21.68s | 7.76x |
| 32 | 26.00s | 6.47x |

S2 (1,278,277 executions; 2-3 reps each, within-point spread <=3%):

| workers | wall | speedup |
|---|---|---|
| 1 | 21.52s | 1.00x |
| 2 | 16.67s | 1.29x |
| 4 | 11.66s | 1.85x |
| **8** | **8.56s** | **2.51x** |
| 16 | 11.16s | 1.93x |
| 24 | 22.04s | 0.98x |
| 32 | 35.40s | **0.61x** |

S2 peaks at 8 workers and then degrades monotonically; at 32 workers it is
slower than sequential. Efficiency is already falling at w=2 and w=4, where SMT
is not yet in play, so the decay is not an SMT artifact.

Caveat on noise: the S1 w=24 point had a 16% spread between its two reps
(20.07s / 23.30s), the widest observed. S2 points were tight (<=3%), and the S2
trend spans 4x, far outside noise.

### F2. System time grows as O(workers^2)

S2, `/usr/bin/time`:

| workers | wall | user | **sys** | total CPU | maxRSS |
|---|---|---|---|---|---|
| 1 | 21.46s | 21.45s | **0.01s** | 21.5s | 29 MB |
| 4 | 11.38s | 38.86s | **1.01s** | 39.9s | 81 MB |
| 8 | 8.36s | 46.24s | **4.11s** | 50.4s | 122 MB |
| 16 | 11.18s | 56.62s | **15.90s** | 72.5s | 179 MB |
| 24 | 22.05s | 65.38s | **36.11s** | 101.5s | 236 MB |
| 32 | 36.62s | 73.33s | **62.13s** | 135.5s | 285 MB |

Each doubling of workers multiplies system time by ~3.9x. At 32 workers the run
spends 135.5s of CPU to perform 21.5s of sequential work — 6.3x amplification,
46% of it in the kernel. S1 shows the same shape (w=1: 0.00s sys; w=16: 9.34s;
w=32: 175.00s).

### F3. Workers thrash rather than compute

`perf stat`, S2:

| | context switches | cpu-migrations | page-faults | **CPUs utilized** |
|---|---|---|---|---|
| w=8 | 911,041 (17.5K/s) | 115 | 26,445 | **5.85** |
| w=32 | 13,017,680 (91.5K/s) | 226,990 | 66,995 | **3.47** |

Quadrupling worker count *reduced* achieved CPU utilisation from 5.85 to 3.47
and increased CPU migrations by 1,974x.

### F4. The contention is futex, overwhelmingly

`strace -c -f`, S2 at depth 48:

| | futex calls | futex errors | time in futex | share of syscall time |
|---|---|---|---|---|
| w=8 | 487,444 | 62,131 | 25.9s | 99.99% |
| w=32 | 5,726,369 | 854,038 | 1,546s | 100.00% |

No other syscall registers above 0.01%.

### F5. Profile: 43% of cycles are scheduling, not exploring

`perf record`, S2 at w=32, children percentages:

```
99.44%  ParallelExecutor::worker_loop()
99.30%   ParallelExecutor::worker_loop_impl()
56.60%    ParallelExecutor::process_task()          <-- actual exploration
56.52%     DepthFirstExplorer::run_loop()
36.68%      DepthFirstExplorer::handle_enter_frame()
27.87%       compute_next_event()
26.67%        invoke_user_code() -> SCP model callback
```

Only 56.6% of cycles are inside `process_task`. The remaining ~43% is burned in
`worker_loop_impl` itself — spinning on the queue mutex and cycling through
condvar wakeups. Blocked threads consume no cycles, so this is real CPU burn.

### F6. Allocation is NOT the bottleneck (hypothesis refuted)

Swapping glibc malloc for tcmalloc via `LD_PRELOAD` changes nothing:

| | glibc | tcmalloc |
|---|---|---|
| S2 w=8 | 8.77s | 8.28s |
| S2 w=32 | 35.94s | **37.05s** (slightly worse) |

This line of optimisation should be dropped.

### F7. A starvation tail from the single spawn site

Separate from the contention story, S1 at w=32 with `--print-stats 3` shows
`queued_tasks` pinned at its 64-task cap for the first two thirds of the run,
then occupancy collapsing to `active_workers=1/32` and `2/32` for long stretches
near the end while the queue sits empty.

That is the expected consequence of the send-only spawn policy: once a worker is
inside a subtree that branches only on rf-choice or ND, it generates no tasks,
and the other workers have nothing to take. This does not explain F1's
*inversion* (idle workers are cheap) but it does cap achievable speedup. The
2PC benchmark used in the engine's prior evaluation does not appear to exhibit
this tail, which may be why the tradeoff measured favourably there.

## Root cause

**D1 — synchronisation cost is O(workers) per task.** One global mutex serialises
every enqueue and dequeue, and `notify_all()` on every task completion wakes
O(W) threads that contend for that lock and mostly return to sleep. The wait
predicate can only newly become true via `search_complete_`; enqueues already
call `notify_one` separately (`:1528`), so the broadcast is nearly all waste.
Because overhead scales with task *turnover*, S2 — whose 1.23M depth-limit
cutoffs mean many small tasks — degrades far worse than S1's fatter subtrees.

**D2 — work can only be split at backward revisits.** A deliberate policy with a
real benchmark behind it, which nonetheless caps speedup on SCP-shaped
workloads (F7). Addressed only after D1, and only if re-measurement justifies it.

## Validation requirements (all phases)

Aggregate terminal counts are **not** a sufficient correctness guard: a
scheduler bug can omit one execution and duplicate another while leaving every
per-kind count unchanged. The engine already has the right tool — tests that
compare exact **graph-signature sets** against both sequential exploration and
the oracle (`external/dpor/tests/dpor_test.cpp:2602`, "verify_parallel matches
sequential and oracle execution sets on mixed branching").

Every upstream phase must satisfy, before the submodule pin moves:

- Full engine test suite green (`ctest --preset debug`).
- Exact execution-**set** equality (not just counts) vs sequential and oracle,
  across worker counts including 1 and an over-subscribed value.
- Focused pure-ND, pure-receive, and nested mixed-branch programs.
- Tiny-queue (`max_queued_tasks = 1`), stop-requested, exception-propagation,
  and repeated-quiescence tests.
- ASAN clean, and **repeated** TSAN runs for Phases 2 and 3
  (`scripts/run_tsan.sh`), per `external/dpor/AGENTS.md`.

The 13-scenario `bench-dpor.sh check` fingerprint in this repo remains valuable
as a downstream integration check and must match exactly, but it is the last
gate, not the only one.

## Plan

The engine lives in a separate repository (`git@github.com:nano-o/CPP-DPOR.git`,
branch `main`), pinned here as `external/dpor`. Each phase lands upstream first,
then the submodule pin is bumped in this repo.

### Phase 0 — operational guidance (this repo, minimal change)

Correcting an earlier draft of this document: the runner already defaults to
**one worker** (`src/scp/test/DporScpInvestigationMain.cpp:44`), and parallel
exploration is selected only when `mWorkers > 1` (`:1535`), so `--workers 0`
takes the serial `verify()` path and never reaches the engine's
`hardware_concurrency()` default. Only `--parallel` selects host concurrency.

**Decision: documentation only. No code change in Phase 0.**

- **Do not change the serial default.** Making ordinary debugger and smoke-test
  invocations parallel would alter event ordering and fail-fast behaviour for
  every existing workflow. The 1-worker default is correct and stays.
- **Leave `--parallel` as it is** and document that an explicit `--workers` is
  preferred, with the measured knee. Auto-detecting physical cores is rejected
  here as not worth its platform complexity: `hardware_concurrency()` ignores
  both CPU affinity and cgroup quota; correct core identity requires
  `(physical_package_id, core_id)` pairs from
  `/sys/devices/system/cpu/*/topology/`, since `core_id` is only unique within a
  package; and affinity alone still misses bandwidth quotas such as cgroup v2
  `cpu.max`. That is a lot of platform-specific code to make one convenience
  flag marginally better, and it would need revisiting after Phases 1-2 move the
  knee anyway.
- Interim guidance for users: `--workers 8` for S2-shaped workloads,
  `--workers 16` for S1-shaped ones.

If a future phase does want auto-detection, it should be specified against
those three sources explicitly rather than reaching for `hardware_concurrency()`.

### Phase 1 — remove the broadcast

In `worker_loop_impl` (`:1608`), replace the unconditional
`queue_cv_.notify_all()` at `:1642` with a notify that fires only when
`search_complete_` was just set. Keep the `notify_all` in `request_stop` and
`record_exception`, which genuinely must wake everyone.

```cpp
bool became_complete = false;
{
  std::lock_guard lock(queue_mutex_);
  --active_workers_;
  if (!stop_requested_.load(std::memory_order_acquire) && task_queue_.empty() &&
      active_workers_ == 0) {
    search_complete_ = true;
    became_complete = true;
  }
}
if (became_complete) {
  queue_cv_.notify_all();
}
```

Acceptance criteria — **all measured by building the pre-change and post-change
binaries and running them alternately in one session on one machine**, taking
medians. The absolute numbers in this document are context for what to expect,
not baselines to compare against; they were measured on a different build at a
different time:
- Full validation set above, including a repeated-quiescence test (workers must
  still reliably exit when the last task drains).
- S2 at w=32 no longer slower than the *same binary* at w=1.
- S2 w=32 system time falls substantially versus the pre-change binary.
- futex call count at w=32 drops by at least an order of magnitude versus the
  pre-change binary.

This phase is cheap enough to run purely as a falsification test for D1. If the
futex count does not collapse, D1 is wrong and Phase 2 should not proceed on the
strength of this document.

### Phase 2 — reduce global-queue contention (conditional)

**Entry gate: re-profile after Phase 1 and only proceed if the queue lock is
still material.** Phase 1 may resolve most of D1 on its own — the broadcast is
the O(workers) term, while the mutex itself is only contended in proportion to
task turnover. Replacing a working scheduler with distributed deques carries
real correctness risk (see the termination-detection risk below), and that risk
is only worth taking against demonstrated residual cost. Concretely, proceed
only if, on the post-Phase-1 binary at w=32:

- `worker_loop_impl`-minus-`process_task` remains a significant share of cycles
  (today 43%), **and**
- system time remains a significant share of total CPU (today 46%), **and**
- scaling still degrades before physical-core count.

If Phase 1 clears those, stop here and re-evaluate against F7 instead — the
remaining ceiling is then D2, not contention.

Goal: remove the single mutex from the common path. **The synchronisation design
is not yet selected**; the following must be pinned down before implementation,
because the obvious sketch does not typecheck against real primitives:

- **Deque primitive.** "Owner works one end lock-free while thieves take the
  other" is only true of a specific algorithm. Name it — Chase-Lev work-stealing
  deque is the standard choice — and specify its memory ordering, or fall back
  to a mutex-per-worker-deque, which is far simpler and may well be sufficient
  once the broadcast is gone.
- **Wake protocol.** `std::condition_variable::notify_one()` wakes an
  *unspecified* waiter and cannot target a chosen idle worker. Directed wakeup
  requires per-worker wait primitives (a `std::binary_semaphore` or a per-worker
  condvar plus an idle registry). Choose one.
- **Publication ordering.** Define the happens-before edge between a task's
  graph becoming visible and its slot becoming visible to a thief.
- **Quiescence.** The current invariant (`queue empty && active_workers_ == 0`
  under one lock) does not survive distributed deques. Specify a real
  termination-detection protocol and prove it cannot deadlock or exit early.

Acceptance criteria:
- Full validation set, with repeated TSAN.
- Context switches per execution roughly flat in worker count (today: 14.3x
  increase from w=8 to w=32).
- `CPUs utilized` tracks `min(workers, physical cores)` instead of falling.
- S1 and S2 both improve monotonically to 16 workers.

### Phase 3 — evaluate splitting at ND / receive frames

Only after Phase 1 and, if its entry gate passed, Phase 2 — that is, on top of
whatever the final contention fix turns out to be. This explicitly re-opens a
settled decision, so it must clear a higher bar.

**Two earlier drafts of this document were wrong here; both corrections shape
the design below.**

*First error — rolling a copy back to an ancestor checkpoint cannot work.*
`ExplorationGraphT`'s copy constructor
(`external/dpor/include/dpor/model/exploration_graph.hpp:104`) deliberately does
not copy `event_undo_log_`/`rf_undo_log_`, and `operator=` calls
`clear_worker_local_history()`. `rollback()` (`:154`) throws
`precondition_error` when the checkpoint's undo size exceeds the log, so on a
fresh copy it would either throw or silently leave descendant events in place.

*Second error — a "resume-range task" does not fit the existing dispatch.*
`frame.mode` is read in exactly one place, `handle_enter_frame` (`:2237`); no
`Resume*` handler reads it at all. And `process_task` (`:1646`) routes every
task through `visit_impl`/`visit_if_consistent_impl`, which each build a fresh
`DepthFirstExplorer` and start from a single **`Enter`** frame. Enqueueing a
rolled-back parent graph as a task would therefore make the remote worker
**re-explore the entire parent subtree**, not the transferred range — silent
duplication, not a speedup. The previous draft's "must carry a resumable frame"
and its remote-frame field table were solving a problem created by that
mis-design.

#### Design A — one alternative per task (the prototype)

Split at the point where `handle_resume_nd_frame` (`:2358`) and
`handle_resume_receive_frame` (`:2388`) have just called
`graph.rollback(frame.checkpoint)`, so the graph is in the parent state. Then,
for a **single** transferred alternative, do locally exactly what the handler
would have done, on a copy:

| Alternative | Apply to the copy | Enqueue as |
|---|---|---|
| ND choice `i` | `add_event(thread_id, nd_label with value = choices[i])` | `{graph, depth+1, Visit}` |
| Receive candidate `i` | `recv = add_event(thread_id, label)`; `set_reads_from(recv, candidate[i])` | `{graph, depth+1, VisitIfConsistent}` |
| Receive bottom (`flag`) | `recv = add_event(thread_id, label)`; `set_reads_from_bottom(recv)` | `{graph, depth+1, VisitIfConsistent}` |

The modes match what the local handlers already push — `Visit` for ND (`:2385`),
`VisitIfConsistent` for both receive forms (`:2408`, `:2418`) — so the remote
`Enter` frame performs the identical consistency check the local child would
have. **No new task variant, no `run_from_frame()`, no resumable frame, and no
checkpoint to re-derive**: `run()` creates the task's `Enter` frame and
`handle_enter_frame` takes its own checkpoint when it needs one.

Cost: one graph copy per transferred alternative rather than per transferred
range. Acceptable because splitting only happens under starvation, and it keeps
the first prototype inside existing, already-tested machinery.

- Gate on starvation: publish an idle-worker count as a relaxed atomic and
  consult it batched, the way `sync_steps` already batches stop checks, so the
  common path stays free and the copy is paid only when the pool is idle.
- **Ownership transfer must be exact.** Mirror the existing
  `try_enqueue_owned_task` discipline (engine doc, "Ownership Invariant"):
  attempt the enqueue, and advance the local cursor past that alternative
  **only on success**. The same rule governs `flag`, the non-blocking bottom
  alternative (`:2413`), which is consumed exactly once (`frame.flag = false`
  then explored): clear it locally only once a handoff carrying it has
  succeeded. If both sides keep it the bottom branch runs twice; if neither
  does it is lost. Either error can hide inside equal aggregate counts if some
  other alternative is miscounted the opposite way — which is precisely why the
  guard must be execution-**set** equality.

#### Design B — range tasks (only if A proves worthwhile)

Amortising one copy over N alternatives requires real new machinery, and should
not be attempted before Design A has demonstrated a win:

- an explicit resume-task variant carrying `{kind, thread_id, label, candidate
  sub-range, flag ownership, depth}`, and
- a `run_from_frame()` entry point that seeds `contexts_` with that resume frame
  instead of an `Enter` frame.

Note that in this design the **handler**, not `task.mode`, must apply
`VisitIfConsistent` to each child it creates: the resume frame itself sits at an
already-consistent parent, and `Resume*` handlers ignore `mode` entirely.

- **Stealing an ancestor frame remains out of scope** for both designs. It needs
  prefix materialization (replay or an explicit snapshot mechanism) and should
  be designed separately if Phase 3 proves worthwhile.

Acceptance criteria:
- Full validation set, with repeated TSAN.
- Targeted pure-ND and pure-receive workloads demonstrating the new spawn sites
  actually activate (assert on a spawn counter, not just on wall-clock).
- **No regression on the 4-participant 2PC timeout benchmark** at 1-20 workers.
  Measure send-only versus ND/receive splitting **as two builds of the same
  contention-fixed baseline commit — post-Phase-1, plus Phase 2 only if its
  entry gate passed — run alternately in one session on one machine**. The
  12,815 ms / 17,183 ms / 16,673 ms figures in the engine doc were produced by
  the old scheduler and are context for the expected effect size, not a baseline
  to compare a new binary against. This is the check that the earlier rejected
  prototypes failed.
- S1 at w=16 no longer shows the end-of-run occupancy collapse (F7).
- **S1 speedup improves, measured as a paired comparison** between the send-only
  and Design A builds of the same contention-fixed baseline, run alternately in
  one session, with the improvement significant against the measured noise
  floor. The 7.5x plateau in F1 is *not* the target: it was measured on the
  pre-Phase-1 build, so Phase 1 alone may clear it, and a Design A build could
  sit above 7.5x while still being a regression against its own send-only
  baseline.

If the 2PC benchmark regresses again once the contention fix is in place, the
send-only policy is vindicated under low contention too, and Phase 3 should be
abandoned rather than tuned.

### Phase 4 — gates and defaults

- **`min_fanout` needs a decision, not a patch.** True revisit fanout is not
  cheaply available: `next_backward_revisit_child` filters candidates lazily by
  compatibility, PORF reachability, and the revisit condition, so
  `receives_in_destination(send_id).size()` is only an upper bound and the exact
  count costs most of the revisit work twice. Pick one: (a) use the upper bound
  as an explicit estimate and rename the option accordingly, (b) drop the option
  since it is effectively a boolean today, or (c) eagerly enumerate and accept
  the cost. Do not describe this as "passing the real fanout".
- Separately: `can_spawn` only *gates* spawning. Any preference for
  high-fanout or shallow split points is a distinct scheduling policy and needs
  its own design and its own measurement.
- Revisit the `2 * workers` queue budget once Phase 2 lands.
- Re-tune `sync_steps` and `progress_poll_interval_steps` against the new
  contention profile.

### Phase 5 — scaling regression check (opt-in)

A naive "assert monotonic improvement at 1/8/16 workers" would be both flaky and
useless: it contradicts this document's own same-session-median requirement, and
S1 already improves monotonically through 16 workers, so today's broken code
would pass it.

Instead add an **opt-in scale mode** to `src/scp/test/bench-dpor.sh`, not part
of the default run:

- Pin the **S2** command exactly (it is the one that inverts).
- Alternate repeated runs across worker counts within one session; report
  medians.
- Establish the machine's noise floor first by measuring one binary several
  times, and set the failure threshold above it.

**Eligibility.** Every assertion below is a *performance* claim, and performance
claims are only meaningful relative to the machine. There are two traps here,
and an earlier draft of this document fell into both:

- Too loose in one direction: a correct scheduler running 32 threads on a 4-CPU
  box can legitimately lose to sequential through oversubscription alone.
- Too loose in the other, and worse: **a weak eligibility bar lets the gate pass
  on today's broken code.** With a 16-CPU floor and worker points derived as
  `N`, `N/4`, `N/2`, the gates reduce to w16-vs-w1 and w4-vs-w8 — and the
  measurements in F1 pass both (w16 is 1.93x faster than w1; w8 beats w4). The
  inversion only becomes material at w24-w32. An eligibility rule must be tight
  enough to *reach the worker counts where the pathology appears*, or the
  regression check is decorative.

Therefore:

- **Assert only on the exact reference shape — a lower bound is not enough.**
  "At least 32 logical / 16 physical" is the wrong quantifier: a 32-core non-SMT
  host, or any larger machine, hands w=32 far more physical hardware than the
  16-core SMT2 host where the pathology was measured, so today's scheduler could
  pass there too. The gate requires **exactly 16 usable physical cores
  presenting 32 logical CPUs (SMT2)**.
- **Construct that shape with an affinity mask rather than merely requiring
  it.** Group CPUs by `(physical_package_id, core_id)` from
  `/sys/devices/system/cpu/*/topology/` — `core_id` alone is not unique across
  packages — pick 16 cores that expose exactly two siblings, and pin the run to
  both siblings of each. This makes *larger* SMT2 machines eligible by
  construction instead of excluding them, so tightening the rule widens coverage
  rather than shrinking it.
- **The effective CPU bandwidth quota must cover all 32 of those logical
  CPUs.** cgroup v2 `cpu.max` is invisible to `sched_getaffinity`; a 32-CPU mask
  under a quota worth 8 CPUs is oversubscription in disguise, and would
  reproduce the very confound this eligibility rule exists to exclude.
- On the reference shape, run **fixed** worker points **1 / 8 / 16 / 32**, not
  fractions of `N`. The pathology was demonstrated at those points; derived
  points silently move the gate off them.
- **Anything that cannot be constrained to that shape runs in reporting-only
  mode** — non-SMT2 topologies, fewer than 16 full cores after affinity, or an
  insufficient quota. Print the curve and assert nothing. A gate that runs
  everywhere and fails for environmental reasons trains people to ignore it; one
  that runs everywhere and *passes* for environmental reasons is worse.

Given eligibility, assert only what has been demonstrated to be broken:

- **Primary gate: w=32 must not be materially slower than w=1.** This is the
  established pathology — 0.61x today.
- **Secondary gate: improvement from w=8 to w=16**, i.e. scaling through
  physical-core count, with tolerance above the measured noise floor.

Deliberately *not* asserted: that w=32 beats w=8. On an SMT2 host that compares
SMT-shared cores against unshared ones, and a memory-bandwidth-bound exploration
workload can fail it with a perfectly correct scheduler.

## Risks

- **Correctness is the hard constraint.** Both D1 and D2 fixes change the order
  in which subtrees are claimed. Soundness does not depend on order, but the
  guard must be exact execution-set equality plus sanitizers, not counts.
- Phase 3 **Design A** changes neither `ExplorationTask` nor the resume path —
  that is the point of it. Its real risks are narrower: cursor and `flag`
  ownership across a failed handoff, and preserving `VisitIfConsistent` on
  receive children so inconsistent graphs are never explored.
- Phase 3 **Design B** is the one that changes `ExplorationTask`'s shape and
  adds a resume entry point. Treat it as a separate, later risk decision; it is
  not on the path unless Design A first shows a win.
- Phase 2's termination protocol is the highest-risk single item: an early exit
  silently drops executions, and the count-based fingerprint would catch it only
  by luck.
- `--workers N` progress lines report `counts_exact=false` mid-run by design;
  only the final summary is exact. Never use progress lines as a fingerprint.
- Benchmarks here come from a virtualised SMT2 host. Re-measure old and new
  binaries back to back in the same session and take medians; do not compare
  against numbers in this document measured hours or days earlier.

## Reproducing

```bash
# scaling sweep
for w in 1 2 4 8 16 24 32; do
  ./src/scp-dpor-investigation --nodes 3 --fifo \
    --txset-status downloading-then-valid --nomination-always-downloading \
    --download-time nondet --stop-on-externalize --depth 56 --workers $w
done

# user/sys split
/usr/bin/time -f 'wall=%es user=%Us sys=%Ss maxrss=%MkB' \
  ./src/scp-dpor-investigation ... --workers 32

# contention
perf stat -e task-clock,context-switches,cpu-migrations,page-faults ./src/... --workers 32
strace -c -f -o /tmp/st.txt ./src/... --workers 32     # use --depth 48; strace is slow
perf record -F 99 -g --call-graph=fp ./src/... --workers 32 && perf report --stdio

# occupancy over time
./src/scp-dpor-investigation ... --workers 32 --print-stats 1
```

`perf` on this host needs the version shim
(`/usr/lib/linux-tools/*/perf` linked to `/usr/local/bin/perf`) because the
container reports a kernel newer than the packaged tools.
