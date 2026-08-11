# Seeded Exhaustive Branch Ordering Plan

## Status

Implemented and verified on 2026-08-11. CPP-DPOR commit `0b2b788` provides the
engine API and traversal semantics; stellar-core pins that commit and exposes
the runner/trace integration; bristlecone commit `c62c555` carries the matching
Rust/C ABI, CLI, provenance, tests, documentation, and coordinated pin.

This document records the smaller first step toward better bug finding than the
branch-sampling designs in `dpor-branch-sampling-plan.md`,
`dpor-branch-sampling-v2-plan.md`, and
`dpor-branch-sampling-simplified-plan.md`.

The sampling documents remain design history and possible follow-up work; this
implementation does not require their sampling, weighting, estimation, or
campaign machinery.

The findings from the 2026-08-07 review and the 2026-08-11 post-simplification
review have been incorporated into this plan. The latter refreshes the engine
layout, consumer landing work, and trace compatibility assumptions after the
CPP-DPOR simplification refactoring and the Stellar trace-v8 migration.

## Goal

Add deterministic, seed-controlled randomization of the order in which
CPP-DPOR explores sibling branches, and expose it through both active
investigation integrations: `scp-dpor-investigation` and `bristlecone-dpor`, in
sequential and parallel modes.

The feature is exhaustive: it changes traversal order but never deliberately
discards a consistent child. Its purpose is to make independently seeded,
early-stopped or time-bounded investigations reach different parts of the
bounded DPOR tree instead of repeatedly following the engine's fixed default
order.

The initial feature should be small enough to implement and validate without:

- a consistency-verdict pass over all children;
- branch retention percentages;
- terminal weights or execution-count estimates;
- new terminal or result kinds;
- a sampled parallel executor; or
- a campaign driver.

## What the feature does and does not mean

A seeded run pseudo-randomly permutes the raw sibling slots at each branch
frame. If a frame has `n` consistent children, each child should have the same
pseudo-random chance of appearing first under the implementation's seeded
permutation model. Invalid or inconsistent raw slots are skipped through the
same deferred checks the engine uses today.

This is not uniform sampling of terminal executions. In a random first descent,
a terminal reached through frames of widths `n1, n2, ...` has selection measure
proportional to `1 / (n1 * n2 * ...)`, not `1 / terminal_count`. A small subtree
and a million-leaf subtree that are siblings each appear first about half the
time, rather than in proportion to their leaf counts. Depth-first traversal can
also spend a long time exhausting the first selected subtree before returning
to its siblings.

Consequently:

- a completed run remains an exhaustive result with the same proof meaning as
  today;
- a stopped or externally time-bounded run is only a bug-finding attempt, not a
  coverage or correctness claim;
- multiple seeds diversify traversal prefixes but do not produce independent
  or uniformly distributed terminal samples;
- randomization can improve or worsen time-to-first-failure for one seed, so it
  should be used as a small seed sweep rather than trusted as one lucky order;
  and
- if measurements show that seeded DFS still gets trapped in large subtrees,
  branch sampling or a population/frontier traversal remains a possible
  follow-up.

Public help and documentation must use terms such as "seeded branch order" or
"randomized traversal order", never "uniform execution sampling" or
"coverage percentage".

## User-visible semantics

- With no branch-order configuration, CPP-DPOR behavior, execution order,
  output, counters, and performance-sensitive paths remain unchanged.
- Supplying a branch-order seed enables exhaustive seeded ordering. Seed zero
  is a valid seed; absence of the option is the only disabled state.
- A completed seeded run returns the existing `AllExplored` result and has the
  same terminal signature set, terminal-kind counts, and maximum reached thread
  depth as the corresponding unseeded run.
- Bounds retain their current meanings. Reordering does not turn a
  `DepthLimit` or `ThreadEventLimit` execution into a maximal execution.
- For a fixed CPP-DPOR revision, program, configuration, bounds, and seed, a
  sequential run produces the same terminal order on repeated runs.
- `verify_parallel()` accepts the same option. The seed deterministically
  defines each frame's sibling priority and each child's descendant ordering,
  independent of which worker receives the child.
- Parallel terminal callback order remains unspecified because workers race.
  A parallel early-stop run can therefore capture different first failures on
  repeated runs even with the same seed. Reproduction of a captured failure
  uses its saved replay trace, not an assumption about parallel callback order.
- `verify_parallel()` with one worker must match sequential terminal order for
  the same seed, as it does without the feature today.
- Progress and split counters keep their existing meanings. No randomization
  counters or result kinds are added.
- Seed behavior is revision-scoped. The same seed need not preserve its exact
  order after the engine's branch representation or mixer changes.

## Scope

In scope:

- seeded ordering of nondeterministic-choice siblings;
- seeded ordering of receive-source siblings, including nonblocking bottom;
- seeded ordering of send backward-revisit siblings, including the ordinary
  send continuation;
- deterministic path-key propagation through sequential and parallel
  exploration;
- runner CLI, summary output, and trace provenance;
- Bristlecone's Rust/C++ ABI, CLI, run record, and trace provenance;
- focused CPP-DPOR correctness tests, stellar-core smoke checks, and
  performance measurements in both consumers; and
- updates to CPP-DPOR's public API/architecture documentation and both
  integrations' user/replay documentation after the feature lands.

Out of scope:

- randomizing `compute_next_event()` thread selection;
- changing blocked-receive rescheduling into a new sibling set;
- randomizing consistency predicates or any user callback;
- pruning, keeping, or otherwise skipping consistent children;
- statistical weights, population estimates, or coverage claims;
- an execution-count or wall-clock stopping option;
- a multi-seed campaign driver;
- permanent cross-version seed compatibility; and
- weighted branch priorities based on protocol semantics.

Runnable-thread selection and blocked-thread rescheduling are part of the
current algorithm's deterministic construction, not exposed sibling frames.
Changing them is a separate algorithmic change and must not be smuggled into
this traversal-order feature.

## Existing engine shape

`external/dpor/include/dpor/algo/dpor.hpp` is now the public entry point only.
The simplification refactoring split the implementation into:

- `algo/verify_result.hpp` for public result, observer, configuration, and
  parallel-option types;
- `algo/detail/support.hpp` for shared algorithm helpers and executor scratch;
- `algo/detail/sequential.hpp` for `ExplorationTask` and the sequential
  executor;
- `algo/detail/parallel.hpp` for the task queue and parallel executor; and
- `algo/detail/explorer.hpp` for typed exploration frames, owned/borrowed graph
  contexts, backward revisits, blocked-receive rescheduling, and the iterative
  DFS handlers.

The explorer represents the three branch families as resumable typed frame
payloads:

- `ResumeNd` walks the deduplicated ND choice vector;
- `ResumeReceive` walks compatible unread send IDs, then explores bottom for a
  nonblocking receive; and
- `ResumeSendRevisits` walks destination receive IDs through
  `next_backward_revisit_child()`, then explores the fresh-send continuation.

The parallel executor already hands owned branch graphs to a bounded FIFO work
queue. Send revisits may be offered eagerly because the graph has already been
materialized. ND and receive alternatives are copied only when another worker
is idle, because earlier eager-copy prototypes regressed throughput.

`ExplorationContext` now owns or borrows its graph exclusively by construction,
and `ExplorationScratch<ValueT>` belongs to the sequential executor or to a
parallel worker. New revisit helpers must accept that scratch explicitly rather
than allocating per candidate or introducing hidden mutable scratch.

The missing pieces are:

1. a stable, path-local source of pseudo-random permutations that does not
   depend on worker scheduling;
2. an explicit representation of bottom and continuation as sibling slots;
3. an exact receive-slot backward-revisit helper, because the current helper
   only scans forward from a cursor; and
4. a send frame that can return from a continuation and resume later revisit
   siblings. The current continuation is always last and converts the frame to
   `ExitLinearChild`, so that return path is not exercised; and
5. seeded-only frame/task state that preserves the simplification refactoring's
   typed-payload, rollback, ownership, and exception-safety invariants without
   imposing allocation, mixing, or slot-vector work on an unseeded run.

## CPP-DPOR public API

Add a small public option in `dpor::algo`, in `algo/verify_result.hpp` beside
`DporConfigT`:

```cpp
struct BranchOrderOptions
{
    std::uint64_t seed{0};
};
```

`DporConfigT` gains:

```cpp
std::optional<BranchOrderOptions> branch_order{};
```

A struct is preferable to a bare optional integer because it gives a clear
enabled state and leaves room for a future explicitly versioned ordering
algorithm without conflating absence with seed zero.

No field is added to `ParallelVerifyOptions`: the selected order is part of
the logical exploration configuration and must mean the same thing for
`verify()` and `verify_parallel()`.

Do not add a new `VerifyResultKind`, `ProgressState`, terminal field, or
counter. Every consistent branch is still explored when the run completes.

## Deterministic ordering algorithm

### Requirements

The ordering implementation must:

- use only fixed-width integer operations;
- avoid `std::hash`, pointer values, `ValueT` serialization, worker IDs,
  scheduler timing, and global counters;
- avoid shared mutable RNG state and locks;
- give each logical child the same descendant order whether it stays local or
  is handed to another worker;
- perform no graph copies or consistency checks merely to choose an order;
- leave the disabled hot path free of mixing and shuffling work; and
- define its exact revision-local behavior in deterministic unit tests.

### Path key

Carry a 64-bit path key in every seeded logical frame state and owned
`ExplorationTask`. Start from a fixed root constant. Derive a child key from:

1. the parent path key;
2. a fixed transition-domain tag;
3. the event's thread ID and next per-thread event index, when applicable; and
4. the stable logical sibling slot, for a branching transition.

Advance the key through deterministic transitions as well as branching ones:
ordinary sends, blocks, send continuations, backward-revisit children, receive
and ND children, and blocked-receive rescheduling. Advancing only at branch
frames would make unrelated frames with the same local slot numbering reuse
permutations too often. An empty `ChoiceRequest` is not a transition: the
current action/event API rejects it as a user callback contract error, and
`std::nullopt` is how a thread terminates.

Send exploration uses an explicit two-level transition. Adding the ordinary
send advances the parent key once, with the deterministic-event tag, to the
`ResumeSendRevisits` frame key. Each raw sibling then derives its child key from
that frame key with either the `SendBackwardRevisit` tag plus target receive ID
or the distinguished `SendContinuation` tag. Selecting the continuation must
not apply the ordinary-send transition a second time.

A blocked-receive reschedule removes an engine-injected block instead of adding
an event. Extend `BlockedReceiveRescheduleResult` to report the unblocked
thread ID, and derive that transition's key from the reschedule domain tag,
that thread ID, and its event count in the parent graph before the block is
removed. Do not use the first ready thread's scan position or another
implementation-order value as its identity.

Use separate domain tags for at least:

- deterministic event;
- ND choice;
- receive from send;
- receive bottom;
- send backward revisit;
- send continuation; and
- blocked-receive reschedule.

The path key affects ordering only. A collision may correlate permutations but
must never merge graphs, skip consistency checks, or alter the execution set.

### Frame permutation

At creation of a seeded sibling frame:

1. construct a vector of stable raw sibling slots;
2. initialize a small local 64-bit generator from the configured seed, the
   frame's path key, and a frame-kind domain tag;
3. apply an explicit Fisher-Yates shuffle; and
4. consume slots in the resulting order through the existing resumable frame.

Use a fixed integer mixer/generator implemented in a focused header such as
`algo/detail/branch_order.hpp`, such as a documented SplitMix64 sequence with
fixed constants. Do not use `std::shuffle` or `std::uniform_int_distribution`,
whose exact mappings are not required to be stable across standard-library
implementations.

For Fisher-Yates index selection, use rejection before modulo reduction so the
bounded integer choice has no modulo bias relative to the generator stream.
For a bound `b`, reject generated words below `(-b) % b`, then use `word % b`.
The exact mixer, domains, byte/integer combination order, and a few golden
permutations become revision-local test fixtures, not a permanent public wire
format.

The feature makes a deterministic pseudorandom approximation to a uniform
permutation. It does not need the cryptographic PRF or statistical contract
that branch sampling and unbiased estimation would require.

### Stable raw slots

Represent distinguished alternatives with a typed slot kind rather than
sentinel event IDs, so a future wider `EventId` cannot collide with them.

Use these logical identities:

- ND choice: its position in the deduplicated choice vector before shuffling;
- receive from send: the source send's event ID in the parent graph;
- receive bottom: a distinguished `ReceiveBottom` slot;
- send backward revisit: the target receive's event ID in the parent graph;
  and
- send continuation: a distinguished `SendContinuation` slot.

No `ValueT` hash or comparison beyond the existing ND deduplication is needed.

### Deferred consistency

Do not add the sampling plan's validate-then-select pass. Shuffle raw slots,
materialize at most the child the engine is about to explore or hand off, and
retain the current `VisitIfConsistent` checks.

The set of valid/consistent children is a deterministic function of the parent
graph. Therefore, a pseudorandom permutation of raw slots induces the same
relative pseudorandom order on the consistent subset after invalid slots are
skipped. No eager verdict pass is needed merely to avoid bias among the
surviving children.

### Shared branch execution plumbing

Seeded and unseeded traversal must differ only in how they select the next raw
slot. Factor child materialization, `Visit` versus `VisitIfConsistent` mode,
path-key derivation, split eligibility, cursor advancement after a successful
handoff, and local descent into shared per-frame helpers used by both modes.

The disabled path may retain its allocation-free direct cursor and its exact
current slot order. Once it selects a slot, however, it must enter the same
materialization and dispatch code as a seeded frame. For send revisits,
`next_backward_revisit_child()` should scan by repeatedly invoking the same
exact-slot helper used by seeded order. Do not maintain two semantic
implementations merely to keep the no-seed ordering path fast.

Frame-lifecycle fast paths are the permitted divergence: the unseeded send may
still convert to `ExitLinearChild`, and the unseeded receive may retain its
bottom-last flag. Slot evaluation, child materialization, task mode, consistency
mode, split eligibility, and handoff accounting are the shared semantic layer.
Likewise, path-key derivation may be exposed through shared helpers, but the
unseeded dispatch must never call those helpers or perform their mixing work.

### Seeded-only state placement

Preserve the typed-frame and ownership boundaries introduced by the
simplification refactoring:

- `Enter` and each seeded resume payload carry the path key for the graph state
  they represent; `ExitLinearChild` needs no key because it has no sibling to
  resume;
- ND and receive permutation vectors live in their existing heap-owned typed
  payloads and are constructed only when `config.branch_order` is present;
- `ResumeSendRevisits` carries a nullable
  `std::unique_ptr<SeededSendState>` member containing the send slot vector and
  post-send checkpoint. It is null when ordering is disabled. Prefer this over
  adding a new frame-variant alternative: it preserves the frame-kind set,
  variant-index assertions, `kind()` mapping, and existing unwind switch while
  imposing only the dormant pointer on the unseeded frame; and
- an unseeded task/frame performs no key derivation, RNG initialization,
  shuffle, or permutation allocation. If carrying a dormant task discriminator
  changes a common type's size, record the before/after size and confirm the
  disabled benchmark remains within the established noise floor.

Value-bearing payloads must retain the current strong exception-safety rule:
construct a complete payload before changing the active frame alternative, and
install rollback-bearing frame state before mutating the graph. Keep
`ExplorationContext`'s exclusive owned/borrowed graph representation; seeded
metadata travels with the context's frames or queued task, never in the graph
itself or in shared executor state.

## Engine changes by frame type

### Nondeterministic choices

Keep `erase_duplicate_nd_choices()` before constructing the slot vector.
Store shuffled indices rather than rearranging `ValueT` objects, so the stable
slot used for child-key derivation remains available and expensive payloads
are not moved repeatedly.

For each slot:

- build the existing ND event with the selected value;
- derive the child path key from the stable slot;
- use the current idle-worker split gate in parallel mode; and
- otherwise descend in place.

When randomization is disabled, retain the current direct vector cursor and do
not allocate an index permutation.

### Receive alternatives

For seeded frames, construct one slot vector containing all compatible unread
send IDs and, for a nonblocking receive, one explicit bottom slot. This removes
the current special rule that bottom is always explored last.

Each receive-from-send slot retains `VisitIfConsistent`. The bottom slot also
retains `VisitIfConsistent`; randomization must not create a shortcut around
the communication-model checks.

The parallel split rule becomes "offer a slot only when at least one raw slot
remains local." Bottom may now be handed to an idle worker when it is not the
last remaining slot. Advance the cursor only after a successful handoff, just
as for current receive-source splits, so no branch can be lost or duplicated.

When randomization is disabled, preserve the current source order, bottom-last
handling, and no-bottom-split behavior exactly.

The shared split gate can still use "at least one raw slot remains local" in
both modes: in the unseeded bottom-last order, bottom counts as remaining local
work, so the last send may be offered while bottom itself, being last, can never
be handed off. This is equivalent to the current behavior without a separate
disabled-mode gate.

### Send revisits and continuation

First factor the current revisit logic into an exact-slot helper:

```cpp
std::optional<ExplorationGraphT<ValueT>>
backward_revisit_child_for_receive(parent, send_id, receive_id,
                                   communication_model, scratch);
```

It evaluates one target receive against the same compatibility, `porf`,
revisit-condition, deleted-set, restriction, remapping, and reads-from rebinding
rules used today. Its real signature takes the executor-owned
`ExplorationScratch<ValueT>&`; do not add a one-shot allocation or `thread_local`
fallback on this hot path. Keep `next_backward_revisit_child()` as the unseeded
scanning wrapper over the exact-slot helper, passing the same scratch, so the
default path and detail-level callers do not change behavior.

For a seeded send frame, build a slot vector containing every destination
receive candidate plus the explicit continuation. Iterate one raw slot at a
time:

- a revisit slot calls the exact-slot helper and silently advances if invalid;
- a valid revisit retains `VisitIfConsistent` and the existing owned-graph
  handoff behavior;
- the continuation retains plain `Visit`, relying on the documented
  fresh-send consistency invariant for `Async` and `FifoP2P`; and
- advancing the continuation does not destroy the resume frame.

If the continuation is explored locally before later slots, push its `Enter`
frame above `ResumeSendRevisits`. Give the send frame two distinct checkpoints:

- the existing pre-send checkpoint remains in `frame.checkpoint`; stop and
  exception unwind, as well as final frame completion, roll back to it; and
- a new `post_send_checkpoint`, captured immediately after adding the fresh
  send, is the seeded frame's resume point.

At the start of every seeded send-frame resumption, roll the graph back to
`post_send_checkpoint` before examining the next slot. This makes the cleanup
mechanism explicit rather than relying only on an induction that every child
frame happened to restore its entry state. In debug builds, also assert after
that rollback that the saved send ID is live and is still a send. A rollback
after an owned revisit or an already-clean continuation is intentionally a
near-free no-op.

Keep the current unconditional live-send validation at the start of the send
resume handler. The debug-only assertion above is an additional check after the
new post-send rollback, not a replacement for the unconditional corruption
guard.

Only the seeded send payload needs `post_send_checkpoint` and alternate-order
slot storage. Keep the ordinary inline `ResumeSendRevisits` payload and its
scan-then-`ExitLinearChild` lifecycle intact, or use an equivalently cheap typed
representation demonstrated by frame-size inspection and the disabled
benchmark.

Once every slot has been consumed, roll back to the pre-send checkpoint and
pop the resume frame. `unwind_one_step()` must continue using the pre-send
checkpoint for `ResumeSendRevisits`, so stopping or throwing while the
continuation is active removes the send along with the rest of the frame.

In parallel mode, a continuation with later raw slots may be copied and handed
to a genuinely idle worker; do not copy it merely because the queue has spare
capacity. If no worker is idle or handoff fails, explore it locally. Valid
revisit graphs retain their current eager handoff policy because their graph
materialization cost has already been paid. This keeps branch priority useful
without reviving the known eager-copy regression for in-place children.

Rename or generalize the current ND/receive-specific idle-split predicate when
reusing it for a continuation, including its comments. Do not count a
continuation handoff as an ND or receive split merely to avoid adding a new
counter; the existing split totals must retain their present meanings.

When randomization is disabled, preserve the current scan-valid-revisits-then-
continuation path, including its existing `ExitLinearChild` handling.

## Parallel integration

Extend `ExplorationTask` with the seeded child path key. The root task receives
the fixed root key, and every enqueue site moves or copies the key paired with
its graph. `DepthFirstExplorer::run()`, `push_owned_context()`, and nested
`Enter` frames receive the corresponding key.

Do not put an RNG in `WorkerState`. Worker-local RNG streams would make a
subtree's order depend on which worker happened to claim it, while a shared RNG
would add contention and make ordering scheduler-dependent.

The existing queue, wake protocol, queue budget, spawn-depth cutoff, stop
polling, and terminal counter aggregation remain unchanged. In a multi-worker
run, "branch order" means the order in which a frame offers or locally enters
siblings. It cannot mean a total order of completed callbacks once siblings
run concurrently.

Parallel early-stop documentation and trace output must record enough context
to avoid promising exact rediscovery from the seed alone. The saved per-thread
trace remains the authoritative reproduction artifact.

Continuation handoffs deliberately have no dedicated counter in the initial
release. Measure their effect indirectly through existing progress snapshots
(`active_workers` and `queued_tasks`), wall-clock time, and throughput. If that
is insufficient to diagnose a measured utilization problem, a separate
continuation-split counter may be proposed later; do not overload the ND or
receive counters.

## Stop and bound behavior

Randomization must not change precedence or classification:

1. `DepthLimit` remains checked before computing the next event;
2. an emitted `ErrorLabel` still produces `Error` immediately;
3. `ThreadEventLimit` remains distinct from maximal executions;
4. blocked and full maximal executions keep their existing distinction; and
5. callback stop still produces `Stopped`.

The seeded path key is traversal metadata, not graph state. It must not appear
in execution signatures or alter the per-thread observations used for replay;
the user-supplied seed may appear only as bundle provenance.

On stop or exception, the current iterative unwind must discard seeded slot
vectors and roll graphs back exactly as it does for existing resume frames.
Add explicit tests for stopping while a send continuation has returned to a
frame with later revisit slots.

## `scp-dpor-investigation` integration

Add:

```text
--branch-order-seed N
```

Parse the full unsigned 64-bit range strictly. The help text should say that
the option exhaustively changes sibling priority, works with `--workers`, and
does not uniformly sample executions.

Store the value as `std::optional<std::uint64_t>` in `CommandLineOptions` and
map it to `config.branch_order`. Do not make it a `ParallelVerifyOptions`
field.

Reject `--branch-order-seed` together with `--replay-trace-json` using a clear
invalid-option diagnostic. Replay does not invoke DPOR, so accepting the seed
there would create a silent no-op. The seed stored inside a trace remains
provenance only and does not need to be supplied when replaying that trace.

With no option, preserve current output byte-for-byte. With the option, print
and flush this machine-readable provenance line immediately before exploration,
so a log retains the seed even if an external time limit terminates the process
before its final summary:

```text
branch-order-seed=1234 workers=4
```

Here `workers` is the effective runner worker count after resolving
`--parallel`. Test this line exactly. Do not change `kind=`: a completed seeded
run is still `all-explored`, and an early-stopped seeded run is still `stopped`.

The option composes with all current exploration scenario, bound, property,
capture, FIFO, and worker settings. Replay is the explicit exception above. No
batch mode is added initially; engineers can run a small seed loop around the
existing binary.

## Stellar trace provenance

Add optional seeded-order provenance to `TraceBundle`, serialized under an
optional top-level exploration object, for example:

```json
"exploration": {
  "branch_order_seed": 1234,
  "workers": 4
}
```

Pass it through every investigation-runner capture path. A trace captured
without seeded ordering omits the object so current output remains unchanged.

This metadata explains how the execution was discovered; it is not required to
replay the saved per-thread traces. Loading a bundle without it must continue
to work, and replay must not re-run DPOR merely to honor it.

Stellar trace bundles have a deliberate version-8-only compatibility line;
versions 1 through 7 are rejected and must remain rejected with the current
recapture diagnostic. Keep schema version 8. The current parser reads members
by name and ignores unknown top-level members, so an older v8 reader tolerates
the optional `exploration` object and a current reader continues to accept
bundles without it. Add round-trip tests for present and absent metadata plus a
checked-in/current v8 bundle without the object. Do not restore v6/v7
compatibility or bump the schema as part of this feature.

Round-trip tests must distinguish an absent `branch_order_seed` (disabled) from
a present value of zero (enabled with seed zero), and must cover
`UINT64_MAX` through the `Json::UInt64` writer and reader.

Do not imply that seed plus worker count guarantees the same first parallel
callback; the stored trace is what guarantees replay.

## `bristlecone-dpor` integration

Expose the same engine configuration through Bristlecone rather than leaving a
new public engine feature unreachable from the other active investigation
consumer.

Add `--branch-order-seed N` to the shared exploration arguments. Store it as
`Option<u64>` in Rust `RunOptions`; absence disables ordering and `Some(0)`
enables seed zero. Clap's parser must accept the complete `u64` range and reject
negative, overflowing, and trailing-character forms. Replay and translation
commands do not share exploration arguments and therefore must not accept the
option.

Forward it through the POD C ABI without using zero as a sentinel:

- append an explicit enabled byte, seven bytes of named zero-initialized
  padding, and a `uint64_t` seed after the current `BcRunOptions` fields. Do not
  consume `reserved0`, `reserved1`, or `reserved2`: preserving the entire old
  struct as a prefix makes the ABI extension and old-artifact interpretation
  explicit;
- mirror the fields in Rust `BcRunOptions` and update both sides' size,
  alignment, offset, default-value, and runtime cross-check tests; and
- in `dpor_bridge.cpp`, set `config.branch_order` only when enabled, before
  choosing `verify()` or `verify_parallel()`.

Record `branch_order_seed: Option<u64>` in Bristlecone's `RunRecord` and in its
expanded run/report output. The value is discovery provenance, not replay input.
Use `#[serde(default, skip_serializing_if = "Option::is_none")]` so a no-seed
bundle remains byte-shape compatible. Keep the current trace schema version only
if this preserves reading an existing version-2 bundle without the field and
older version-2 readers tolerate the extra member; otherwise bump the schema
explicitly and add the normal compatibility diagnostic. Test absent, zero, and
`u64::MAX`.

The Bristlecone bridge compiles the header-only engine directly and enforces two
pin records. Advance `dpor/external/dpor` and
`EXPECTED_ENGINE_REVISION` atomically after the candidate engine passes the
package/allowlist gate through `BRISTLECONE_DPOR_DIR`. A no-seed run must retain
its existing output, assurance class, exact terminal set, and known-defect
allowlist.

## Implementation phases

### Phase 1: behavior-preserving send foundation

In CPP-DPOR:

- factor the exact-slot backward-revisit helper;
- make a send continuation able to return to `ResumeSendRevisits` and leave
  later siblings available;
- add the distinct post-send resume checkpoint, roll back to it on every
  alternate-order resumption, preserve the pre-send checkpoint for unwind, and
  add the debug assertion on the live send; and
- add a detail-level test hook or fixture that forces continuation first and
  middle without exposing a public runtime option yet.

Keep production traversal order unchanged. Verify under alternate test order
that execution signature sets match the exhaustive oracle with no duplicates,
under both `Async` and `FifoP2P` where applicable.

Land this as a separate behavior-preserving CPP-DPOR commit if practical. This
isolates the deepest correctness assumption before adding pseudo-random order
and parallel path metadata.

### Phase 2: seeded ordering in CPP-DPOR

Add the public option, fixed integer generator, unbiased Fisher-Yates helper,
typed raw slots, path-key propagation, seeded ND/receive/send handlers, and
parallel task integration.

Keep disabled handlers on their present allocation-free direct cursors, but
share child materialization, task modes, handoff accounting, and local descent
with seeded handlers. Add no result or statistics surface.

Update CPP-DPOR's `README.md`, `docs/api.md`, and `docs/architecture.md` with the
public configuration, reproducibility scope, exhaustive semantics, and parallel
callback-order limitation. Keep `dpor/algo/dpor.hpp` as the sole consumer entry
point even though the new implementation is split across detail headers.

### Phase 3: stellar-core runner and trace integration

Update the submodule pin, extend the configure-time minimum-version compile
probe to reference `BranchOrderOptions` and `DporConfigT::branch_order`, add
the runner option and provenance output, and add optional trace metadata.

Extend the old-API failure message's existing feature list with
`BranchOrderOptions` and `DporConfigT::branch_order`, and append the new minimum
CPP-DPOR commit that contains branch ordering. Do not replace the useful
feature-level diagnostic with only a commit ID. Preserve the current
distinction between "the DPOR headers do not compile" and "the checkout
compiles but its API is too old."

Update `docs/dpor-integration-status.md` and `docs/dpor-replay-notes.md` after
the code and observed behavior are final. Do not describe seed ordering as a
sampling or proof mode.

### Phase 4: Bristlecone ABI, runner, and trace integration

Against the candidate engine checkout, add the Rust option and CLI, extend the
POD ABI on both sides, forward `config.branch_order`, record optional run
provenance, and update help/user documentation. Run ABI layout/default tests,
existing trace compatibility tests, serial/parallel exact-set tests, and the
known-defect allowlist gate before advancing either pin record.

Update the Bristlecone gitlink and `EXPECTED_ENGINE_REVISION` in the same
consumer commit. Do not add an engine compatibility shim merely to split the
consumer migration.

### Phase 5: empirical evaluation

Use seeded runs to answer two separate questions:

1. Correctness: does every completed seed preserve the exact exhaustive
   fingerprint?
2. Usefulness: do different seeds materially diversify early terminal traces
   and time-to-first interesting execution on representative SCP and
   Bristlecone scenarios?

Only after those measurements decide whether the branch-sampling design is
still justified.

## CPP-DPOR tests

Keep the simplification refactoring's behavioral test split:

- generator, core ordering, raw-slot, and oracle tests in `dpor_test.cpp`;
- bound equivalence and terminal-kind tests in `dpor_bounds_test.cpp`;
- `FifoP2P` cases in `dpor_fifo_paper_test.cpp`;
- worker, queue, handoff, one-worker-order, and stop races in
  `dpor_parallel_test.cpp`;
- deep iterative/unwind coverage in `dpor_deep_test.cpp`;
- randomized oracle-backed coverage in `dpor_stress_test.cpp`; and
- throwing payload, callback exception, and fatal-graph coverage in
  `errors_test.cpp`.

Add these focused cases in the appropriate targets and helper fixtures:

- absent configuration preserves the existing sequential terminal order;
- seed zero is enabled and repeatable;
- the same seed repeats the same sequential signature vector;
- selected known seeds produce different orders on a mixed branching fixture;
- golden Fisher-Yates permutations catch accidental generator or reduction
  changes;
- blocked-receive rescheduling derives repeatable child keys from the
  unblocked thread ID and its parent-graph event count;
- an ordinary send advances to its frame key exactly once, and revisit and
  continuation child keys derive from that frame key rather than reapplying
  the ordinary-send transition;
- ND choices all remain present exactly once after seeded ordering;
- receive bottom appears first, middle, and last for selected seeds;
- inconsistent receive-source slots are skipped without changing the relative
  seeded order of consistent slots;
- send continuation appears first, middle, and last for selected seeds;
- returning from an early continuation still explores every later valid
  revisit exactly once;
- every seeded send resumption restores the explicit post-send checkpoint,
  while stop and exception unwind restore the pre-send checkpoint;
- invalid revisit slots do not consume or duplicate another slot;
- seeded traversal matches the exhaustive oracle and has no duplicate
  signatures on ND-only, receive-only, send-revisit-heavy, and nested mixed
  programs;
- bounded seeded runs match the unseeded bounded signature set and terminal
  kinds;
- callback stop is sticky from every frame type, including after an early send
  continuation;
- `verify_parallel(..., max_workers=1)` exactly matches seeded sequential
  order;
- seeded parallel runs match the sequential/oracle signature set across
  multiple worker counts and tiny queue budgets;
- forced ND, receive, bottom, revisit, and continuation handoffs neither lose
  nor duplicate work; and
- exception and fatal-error reporting retain the correct in-progress graph.

Do not use probabilistic assertions. Pick fixed seeds with golden expected
orders, and test exhaustive equality separately.

Run `external/dpor/scripts/gate.sh full`,
`external/dpor/scripts/gate.sh stress`, and
`external/dpor/scripts/gate.sh axes` after the engine changes. The parallel
tests are required under TSAN because the main architectural reason for
path-local state is to avoid shared RNG races. The stress gate is required
because path metadata now travels through every queue and handoff path.

## stellar-core validation

Add or extend tests for:

- strict `--branch-order-seed` parsing, including 0, `UINT64_MAX`, overflow,
  negative input, and trailing characters;
- rejection of `--branch-order-seed` combined with `--replay-trace-json`;
- absent-option output compatibility;
- conditional seed provenance output;
- trace JSON round trips with the seed absent, seed zero present, and
  `UINT64_MAX` present;
- loading an existing/current version-8 bundle without exploration metadata;
- retaining the explicit rejection and recapture diagnostic for versions 1
  through 7;
- seeded capture followed by ordinary trace replay;
- the default scenario's completed terminal counts matching without a seed
  and for several fixed seeds; and
- sequential and multi-worker seeded runs producing the same final signature
  set on a tractable scenario.

Run at minimum:

```bash
# Expected exit 0.
./src/stellar-core-dpor-tests "[scp][dpor][smoke]"

# Expected exit 0.
./src/scp-dpor-investigation --branch-order-seed 0 --depth 12

# Expected exit 0.
./src/scp-dpor-investigation --branch-order-seed 1 --workers 4 --depth 12

# Expected exit 1: this mode deliberately reports the captured terminal.
./src/scp-dpor-investigation --branch-order-seed 2 \
  --fail-on-first-terminal --trace-dir "$PWD/dpor-traces" --depth 12

# Expected exit 0, using the PATH printed by the preceding capture.
./src/scp-dpor-investigation --replay-trace-json PATH --replay-node all

# Expected exit 0.
src/scp/test/bench-dpor.sh check
```

The exact `bench-dpor.sh check` fingerprint must remain unchanged for the
default run. Completed seeded runs must have the same exact counts; order is
not part of that fingerprint.

Also run the current integration gates rather than relying only on the manual
commands above:

```bash
src/scp/test/dpor-gate.sh smoke
src/scp/test/dpor-gate.sh check
src/scp/test/dpor-gate.sh full
```

## Bristlecone validation

Add or extend tests for:

- Rust `Option<u64>` and C ABI enabled/seed defaults, including disabled versus
  enabled-zero and `u64::MAX`;
- C/Rust ABI size, alignment, offset, and runtime layout agreement;
- CLI parsing and help text, with replay/translate unable to accept the
  exploration-only option;
- bridge forwarding to `DporConfigT::branch_order` in sequential and parallel
  modes;
- unchanged no-seed output, assurance classification, terminal counts,
  signatures, and known-defect allowlist;
- repeated same-seed serial terminal order and different fixed-seed orders on
  the synthetic ABI model;
- completed seeded serial and multi-worker runs matching the unseeded exact
  signature set on tractable FBA and Simplex scenarios;
- trace/run-record round trips with the seed absent, zero, and `u64::MAX`, plus
  loading an existing version-2 bundle without the field; and
- seeded failure capture followed by ordinary replay without consulting the
  seed.

Before changing the pin, test the candidate engine directly:

```bash
cd ../bristlecone
BRISTLECONE_DPOR_DIR="$OLDPWD/external/dpor" ./dpor/scripts/gate.sh test
```

After advancing the gitlink and `EXPECTED_ENGINE_REVISION`, run the same gate
against the pinned submodule and verify `cargo run -p bristlecone-dpor -- build`
reports matching effective and expected revisions.

## Performance validation

Measure two costs separately:

- disabled overhead: the default binary with no seed must remain at baseline;
- enabled overhead: seeded ordering pays `O(width)` slot storage and shuffle
  work per branch frame but should not add eager consistency checks or routine
  graph copies.

For CPP-DPOR, compare the existing 2PC benchmark back to back for:

- sequential unseeded versus sequential seeded;
- `verify_parallel()` with one worker, unseeded versus seeded; and
- multi-worker unseeded versus seeded with the same worker and queue settings.

For stellar-core, run `bench-dpor.sh bench` and `bench-dpor.sh head` back to
back with unseeded and several fixed seeded orders. Confirm that any throughput
change is an ordering effect rather than lost work by checking exact completed
execution counts on terminating scenarios.

For Bristlecone, run its documented bounded `dpor/scripts/gate.sh bench` regime
back to back with no seed and several fixed seeds, in serial, parallel-one-worker,
and the representative multi-worker configuration. Keep bridge measurement
disabled for throughput runs, and compare exact signatures separately on the
tractable terminating scenarios.

Because continuation handoffs have no initial counter, assess them through
`--print-stats` worker/queue snapshots plus wall-clock and throughput results.
Do not claim an exact continuation-split count from those indirect measures.

Preserve the current lazy-copy policy. In particular, never eagerly copy every
ND or receive child merely to make parallel order look more global. If seeded
continuation splitting regresses the default or seeded benchmark, retain local
continuation descent and document the parallel utilization tradeoff before
considering a broader scheduler redesign.

Follow the host-specific noise rules in the repository instructions. On
`pop-os-desktop`, do not interpret changes below 20 percent as speedups or
regressions. On quieter hardware, establish the noise floor with repeated
baseline runs and compare medians back to back.

## Landing sequence

1. Land the behavior-preserving exact-slot and resumable-continuation work in
   CPP-DPOR with oracle and alternate-order tests.
2. Land seeded ordering and parallel path-key propagation in CPP-DPOR, including
   public API and architecture documentation.
3. Run CPP-DPOR full, stress, axes, and back-to-back benchmark gates.
4. Build and gate both consumers against that candidate engine checkout before
   moving either gitlink.
5. In stellar-core, update `external/dpor` and the configure-time API probe,
   preserving separate compile-failure and too-old-API diagnostics; add the CLI,
   output, v8 provenance, and compatibility tests.
6. In Bristlecone, add the Rust option/CLI, C ABI forwarding, run-record
   provenance, and compatibility tests; then update the gitlink and
   `EXPECTED_ENGINE_REVISION` atomically.
7. Run Stellar smoke/full/fingerprint/replay gates and Bristlecone's pinned
   package/allowlist, ABI, exact-set, and replay gates.
8. Run all three repositories' back-to-back performance measurements.
9. Publish the engine commit first so both gitlinks are reachable, then publish
   the two consumer commits.
10. Update CPP-DPOR, Stellar, and Bristlecone user/integration/replay documents
    with landed behavior and verified commands.

## Acceptance criteria

The initial feature is complete when:

- no-seed behavior and output remain unchanged;
- all three real sibling families include every alternative, including bottom
  and continuation, in seeded ordering;
- the same sequential seed is reproducible within the documented revision
  scope;
- different selected seeds demonstrably diversify traversal on branch-rich
  engine fixtures, at least one SCP investigation scenario, and at least one
  Bristlecone scenario;
- every completed seeded run matches the unseeded/oracle execution signature
  set with no duplicates;
- multi-worker seeded runs preserve the same exhaustive set across worker and
  queue configurations;
- parallel code contains no shared mutable RNG and passes TSAN;
- a captured trace records the optional seed and replays without depending on
  it;
- Stellar replay rejects a command-line branch-order seed, while Bristlecone's
  replay/translate parsers do not expose the exploration-only option, so neither
  can silently ignore it;
- Stellar keeps its v8-only trace line and Bristlecone preserves or explicitly
  versions its existing trace compatibility contract;
- both consumers pass their candidate-engine and pinned-engine gates, and both
  pin records in Bristlecone agree;
- default and seeded performance have been measured under the repository's
  benchmark rules; and
- user-facing text clearly states that seeded DFS is not uniform sampling of
  executions and that an incomplete run proves nothing.

## Reconsidering sampling later

After landing, evaluate a small fixed seed matrix on representative SCP and
Bristlecone scenarios. Record first interesting terminal signature, terminals
reached by a fixed external time limit, worker utilization, and overlap between
seeds.

Revisit branch sampling or a population/frontier traversal only if one or more
of these remain true:

- most seeds spend their budget in the same large subtree;
- early terminal sets have very high overlap despite different per-frame
  orders;
- important wide communication frames are still reached too rarely;
- users need estimates of the unexplored bounded tree; or
- pruning is required to reach protocol depth that exhaustive seeded DFS
  cannot reach in practical time.

That decision should be based on measured bug-finding behavior. Seeded branch
ordering deliberately provides no estimator or coverage statistic from which
those conclusions could otherwise be inferred.

## Plan refresh — 2026-08-11

Verdict: **ready to implement against the post-simplification engine**, subject
to the gates and cross-repository landing order above.

This refresh preserves the 2026-08-07 algorithm review and incorporates the
subsequent repository changes:

1. the monolithic engine references now follow the
   `verify_result`/`support`/`sequential`/`parallel`/`explorer` split;
2. exact backward-revisit materialization explicitly uses executor-owned
   `ExplorationScratch`;
3. seeded-only storage follows the typed-frame, exclusive-context-ownership,
   and throwing-payload exception-safety rules;
4. empty choice requests are contract errors, not path-key transitions;
5. Stellar provenance stays on the deliberate v8-only trace line; and
6. Bristlecone receives a coordinated Rust option, POD ABI mapping, provenance,
   candidate-engine gate, and atomic two-record pin update.

The old review's minor clarifications are now requirements in the main text:
frame-lifecycle fast paths may differ while branch semantics stay shared, the
receive split gate is common, disabled dispatch performs no key work, and the
existing unconditional live-send guard remains in place.

## Review — 2026-08-11

### Verdict

Accurate against the code it describes and ready to implement as staged. Every
engine-shape, consumer-surface, and tooling claim checked below was verified
against engine commit `f54b793` (the revision both consumers currently pin),
the stellar-core investigation runner, and the Bristlecone checkout at
`/workspaces/bristlecone`. No claim contradicted the tree.

### Claims verified against the code

Engine (`external/dpor/include/dpor/algo/`):

- The `verify_result`/`support`/`sequential`/`parallel`/`explorer` split, the
  three resumable frame payloads, the `unique_ptr` rule for `ValueT`-bearing
  payloads, and `ExplorationContext`'s exclusive owned/borrowed graph variant
  all match `detail/explorer.hpp`.
- The continuation is indeed always last and converts the frame to
  `ExitLinearChild` (`handle_resume_send_revisits_frame`), so the
  return-to-later-siblings path the plan builds in Phase 1 is genuinely
  unexercised today.
- `next_backward_revisit_child()` scans forward from `start_receive_index`;
  the exact-slot helper is a real missing piece, not a refactor of existing
  capability.
- `BlockedReceiveRescheduleResult` carries only `kind` and `graph`; the
  unblocked-thread-ID extension is genuinely needed for the reschedule key.
- Bottom is a `bottom_branch_pending` flag, deliberately last and never split;
  the bottom child already uses `VisitIfConsistent`, so the plan's "no shortcut
  around consistency" rule preserves current behavior.
- Revisit children are offered eagerly under `can_spawn()` while ND/receive
  alternatives are gated on `idle_workers_`, exactly as the plan's handoff
  policy assumes, and the `nd_splits`/`receive_splits` counters are the only
  split accounting.
- The receive split-gate equivalence argument checks out: the current
  `keeps_local_work = next_candidate + 1 < size || bottom_branch_pending` is
  precisely "at least one raw slot remains local" under bottom-last order.
- One-worker parity is preserved behavior, not new work: `max_workers_ <= 1`
  short-circuits `can_spawn()`, `should_split_to_idle_worker()`, and
  `try_enqueue()`, so a one-worker parallel run already explores in exact
  sequential order.
- `erase_duplicate_nd_choices()` runs before frame construction, empty choice
  requests are rejected upstream, and scratch is executor-owned (sequential
  member / parallel `thread_local` `WorkerState`), matching the plan's
  scratch-threading requirement.
- The rejection-before-modulo formula is the standard unbiased bounded-integer
  construction and is stated correctly.
- `scripts/gate.sh` has the `full`, `stress`, and `axes` modes the plan
  requires, `run_tsan.sh` exists, and the seven test files named in the test
  plan all exist under `tests/`. `README.md`, `docs/api.md`, and
  `docs/architecture.md` exist for the Phase 2 documentation work.

stellar-core:

- `TRACE_BUNDLE_VERSION` is 8 and `traceBundleFromJson` rejects every other
  version with the recapture diagnostic the plan says must be retained.
- The runner has `CommandLineOptions` with the `std::optional` style the new
  seed option copies, plus `--workers`, `--parallel`, and `--replay-trace-json`
  for the composition and rejection rules.
- The configure probe exists with distinct "headers do not compile" and
  "checkout too old" diagnostics; the too-old message currently names required
  API features. `src/scp/test/dpor-gate.sh` has `smoke`/`check`/`full`.

Bristlecone:

- `BcRunOptions` is a POD mirrored in Rust and C with layout tests; Rust
  `RunOptions`/`RunRecord` exist; `TRACE_SCHEMA_VERSION` is 2 with an explicit
  incompatible-version rejection test; the two-record pin
  (gitlink + `EXPECTED_ENGINE_REVISION`) is real; `dpor/scripts/gate.sh` has
  `test` and `bench` modes and honors `BRISTLECONE_DPOR_DIR`; the allowlist
  gate and the `build` subcommand (`Command::Build`) exist; replay and
  translate are separate commands that do not share exploration arguments.

### Findings

1. **The v8 conditional resolves definitively: keep schema 8.** The plan
   hedges ("if the optional field is accepted by the current parser").
   Verified: `traceBundleFromJson` reads members by name and ignores unknown
   top-level members — `communication_model` is already optional via
   `isMember` — so an older v8 reader tolerates the `exploration` object and
   absent metadata stays readable. No schema bump is needed; the round-trip
   tests remain worthwhile as regression guards.

2. **The deepest assumption is structurally sound, and the plan stages it
   correctly.** Sibling-order independence of the DPOR tree holds because
   every frame's child set is a function of that node's graph alone (ND
   choices post-dedup, compatible unread sends captured at frame creation,
   `receives_in_destination` captured at send time, reschedule a deterministic
   graph function) and siblings are separated by rollback. Tree depths are
   likewise structural, so bound classifications cannot shift under
   reordering. The plan rightly refuses to rest on this argument and proves it
   empirically in Phase 1 before adding any randomness; keep that ordering.

3. **Prefer the nullable indirection for seeded send state.** The plan allows
   either "a seeded-only payload or indirection". A sixth variant alternative
   would churn the `ExplorationFrameKind` ↔ variant-index `static_assert`s,
   `kind()`, `rollback_checkpoint()`, and every frame switch; a
   `unique_ptr`-style seeded-state member inside `ResumeSendRevisits`
   (null when unseeded, 8 bytes) preserves the frame-kind set and the existing
   unwind path untouched. Recommend the plan name that as the default choice.

4. **Make the two-level send key scheme explicit.** The intended reading —
   the send's event addition advances the parent key to the frame key with the
   deterministic-event tag, and each slot (revisit, continuation) then derives
   its child key from the frame key with its slot tag — is coherent, but the
   text's flat transition list ("ordinary sends, … send continuations")
   admits a double-advance reading. Either is correct; the golden permutation
   fixtures will freeze whichever is implemented, so one clarifying sentence
   now avoids a confusing test archaeology later.

5. **Pin the ABI extension layout decision.** "Reserved bytes kept
   deterministic" leaves open whether the enabled byte occupies existing
   reserved space (`reserved0`/`reserved1`/`reserved2`) or new fields are
   appended with fresh explicit padding. The layout tests will catch drift
   either way, but the plan should state the choice — appending both fields
   with explicit padding is the simpler story for readers of old artifacts.

6. **Probe message style.** The current too-old diagnostic names missing API
   features, not commits. Phase 3 asks for the minimum commit to be named;
   keep the feature-list style (add `BranchOrderOptions` /
   `DporConfigT::branch_order` to the list) and append the commit, rather than
   replacing one with the other.

7. **Housekeeping, outside this plan:** both consumers currently pin the same
   engine commit `f54b793`, which makes the coordinated-advance story in the
   landing sequence start from a common base — but the repository
   instructions still describe the pin as `562f5be`. Worth refreshing when the
   pin next moves.

### Nits

- Filename says "randomized", title and body say "seeded". The body's own
  terminology rule ("seeded branch order", never sampling language) is
  followed consistently; the filename mismatch is harmless.
- The "bottom/continuation first, middle, last" test cases require hunting for
  seeds that produce those placements on a fixture; that is a fixture-search
  chore, and the revision-local scoping of seeds already covers the
  brittleness concern.

END REVIEW
