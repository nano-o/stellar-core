# DPOR Replay Notes

This note captures the current behavior of the SCP DPOR investigation runner
and the replay-support layer.

It is descriptive, not a design commitment.

## `scp-dpor-investigation --dump-terminal-trace`

The `--dump-terminal-trace` mode stops after the first terminal execution.
The callback in
[`src/scp/test/DporScpInvestigationMain.cpp`](../src/scp/test/DporScpInvestigationMain.cpp)
returns `TerminalExecutionAction::Stop`, so DPOR prints the first terminal
execution it encounters and then stops exploring.

Without `--dump-terminal-trace`, the default three-node prepare-boundary
scenario currently explores four executions at sufficiently large depth.

The printed "trace" is not a full per-thread step log. It uses
`execution.graph.thread_trace(...)`, which contains only:

- values observed by receives
- nondeterministic choice values

It does not include:

- sends
- local state transitions
- internal SCP work performed while handling a receive or timer firing

This is why the terminal dump can look much shorter than the actual execution.

## Scenario Start State

The three-node prepare-boundary scenario does not start from empty nodes.

`ScpDporReplaySupport::rebuildBaselines()` constructs a fresh `DporScpNode` for
each validator, calls `nominate(...)`, then snapshots the resulting node state
and any already-emitted envelopes.

This means exploration starts from a post-nomination baseline:

- local nomination state already exists
- initial nomination envelopes may already be pending for delivery

In the default scenario, only the round leader has initial outgoing nomination
messages, so the followers can begin at a blocking receive.

## Why The Scenario Stops "Early"

The current scenario ends when a node reaches the configured replay boundary,
not when SCP fully runs to externalize.

For the default configuration:

- boundary mode is `Prepare`
- the prepare boundary is the first `SCP_ST_PREPARE` with ballot counter
  `>= 1`

Once a node reaches that boundary, the scenario stops producing further events
for that thread.

So a terminal execution in this runner means "all scenario threads reached
their local stop condition", not "the model checker consumed the entire depth
budget" and not "SCP externalized".

## Why A Follower Can Reach `PREPARE` After One Observed Envelope

A follower can appear to receive only one envelope in the terminal dump and
still reach a boundary `PREPARE`.

That is possible because the dump omits:

- the follower's existing local nomination state from the baseline
- any sends emitted while handling the receive
- intermediate internal SCP transitions

So "one observed envelope" is not "one fact total". The node may already have
its own nomination state in memory before that receive is replayed.

Also, thread 0's single observed envelope in the default terminal trace is not
the first nomination emitted by a peer. It is already a later peer `NOMINATE`
that reflects earlier off-screen work.

## Replay Support: Baselines, Cache, And Checkpoints

`ScpDporReplaySupport` uses three different forms of saved state.

### 1. Stored Node Baselines

`mReplayBaselines` stores immutable per-node starting points for replay.

Each `NodeBaseline` contains:

- `mNodeState`: a full `DporScpNode::ReplayBaseline`
- `mInitialPendingEnvelopes`: envelopes emitted during initial nomination

`mNodeState` includes:

- slot nomination state
- slot ballot state
- emitted envelopes
- installed timers
- timer set counts
- txset wait-time call count
- replay-boundary state

These baselines are built once when `ScpDporReplaySupport` is constructed.

### 2. Thread-Local Cached Nodes

`acquireNode()` keeps a thread-local cache of live `DporScpNode` objects,
keyed by:

- `ScpDporReplaySupport*`
- `nodeIndex`

The cache is only a performance optimization. It avoids reconstructing a fresh
`DporScpNode` object graph for every replay query.

The cached node is not trusted to hold the correct replay state between calls.
Before use, callers restore it back to the appropriate stored baseline.

### 3. Per-Call Replay Checkpoints

Inside `replayObservation()`, the code snapshots the node state immediately
before replaying the current observed event.

That checkpoint is used only within the current call. It exists so the replay
layer can retry the same observed event from the same starting state if replay
discovers an additional hidden choice while executing that event.

This checkpoint is more local than the stored node baseline. Restoring from the
stored baseline would also be correct, but it would require replaying the whole
prefix again.

## Why `getTxSetDownloadWaitTime()` Uses Exception + Retry

`getTxSetDownloadWaitTime()` can be reached deep inside ordinary SCP handling
of a receive or timer firing.

At that point, the replay layer is already in the middle of "execute this one
observed event". The current `SCPDriver` interface returns only an
`optional<milliseconds>` value, so there is no explicit "pause and request a
DPOR choice" channel at that seam.

The current mechanism is:

1. Start replaying one observed event.
2. If SCP asks for a txset wait-time choice and none has been preloaded,
   `DporScpNode` throws `TxSetDownloadWaitTimeChoiceRequired`.
3. `replayObservation()` catches it.
4. If the trace does not already contain the choice, replay returns a pending
   DPOR nondeterministic choice event.
5. Once a choice is available, replay restores the per-call checkpoint,
   preloads the chosen wait time, and replays the same observed event again.

The retry is necessary because the first attempt may already have partially
mutated SCP state before discovering the hidden choice.

## Relation To Timers And Emitted Envelopes

`setupTimer()` and `emitEnvelope()` are handled differently from
`getTxSetDownloadWaitTime()`.

They are side effects of finishing the current SCP step:

- `emitEnvelope()` records the emitted envelope, and the scenario later turns
  pending envelopes into future DPOR send events
- `setupTimer()` records timer state, and the scenario later exposes enabled
  timers as future timer-choice / timer-firing behavior

They do not require the current step to suspend and ask DPOR for a new choice.
That is why they do not need the exception/checkpoint mechanism.

## On Modeling `getTxSetDownloadWaitTime()` As A DPOR Choice

Yes, it is sensible to treat the return value of
`getTxSetDownloadWaitTime()` as a DPOR nondeterministic choice.

In practice, the current code already does that once the need for the choice is
discovered. The awkward part is not whether it is a DPOR event; the awkward
part is that SCP discovers it in the middle of executing another event.

So:

- making txset wait time a first-class DPOR choice is compatible with the
  current replay model
- it does not by itself remove the need for rollback/retry
- removing rollback/retry would require a more explicit resumable/effectful
  execution interface at the `SCPDriver` seam

## Working Mental Model

The simplest way to think about the current replay loop is:

- stored baselines define the starting point for replay
- cached nodes are reusable scratch objects
- each observed event is replayed from a per-call checkpoint
- if replay discovers a hidden txset choice mid-step, it rewinds to that
  checkpoint and reruns the same step with the choice preloaded

