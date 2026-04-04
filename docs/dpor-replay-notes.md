# DPOR Replay Notes

This note captures the current behavior of the SCP DPOR investigation runner
and the replay-support layer.

It is descriptive, not a design commitment.

## `scp-dpor-investigation --fail-on-first-terminal`

The `--fail-on-first-terminal` mode is a smoke-test command.
The callback in
[`src/scp/test/DporScpInvestigationMain.cpp`](../src/scp/test/DporScpInvestigationMain.cpp)
returns `TerminalExecutionAction::Stop` at the first terminal execution it
encounters, rewrites that terminal as a runner failure, dumps replay traces in
focus-first order, and exits nonzero.

Without `--fail-on-first-terminal`, the default scenario explores a small
number of executions at sufficiently large depth (the exact count depends on
DPOR dynamics and scenario configuration).

This mode is intentionally a fail-fast runner check rather than a general
terminal-capture workflow. For debugger-oriented capture and later replay, use
the JSON trace flow described below.

## JSON Trace Capture And Replay

`scp-dpor-investigation` persists the first captured terminal execution as a
structured JSON artifact into `--trace-dir` (default `dpor-traces`), prints
the chosen path as `trace-json=...`, and can reload that artifact later with
`--replay-trace-json PATH`.

The persisted replay input is not a full schedule. It stores:

- the effective `ScpDporDefaultScenario::Options`
- terminal metadata such as terminal kind, failure message, and focus thread
- one raw `ThreadTrace` per thread

This matches the existing replay seam:

- DPOR produces `execution.graph.thread_trace(threadId)`
- the SCP harness reconstructs human-meaningful replay steps by feeding that
  trace into `inspectThreadReplayTrace(...)`

The JSON trace therefore preserves the exact per-thread observed-value input
needed for debugger-oriented replay without encoding DPOR reads-from edges or
global insertion order.

Replay defaults to the stored `focus_node_index`. `--replay-node N` overrides
that to one node, and `--replay-node all` replays every node in focus-first
order.

Because envelope deliveries are stored as exact base64 XDR payloads, traces
with many delivered envelopes can grow noticeably faster than timer-heavy or
choice-heavy traces.

`loadTraceBundle()` validates the JSON schema, trace payloads, thread coverage,
and focus metadata, but some default-scenario semantic checks are still
deferred until replay constructs `ScpDporDefaultScenario` from the stored
options. In practice, malformed scenario shapes still fail early on replay, but
not all option-level constraints are enforced by JSON load alone.

## Scenario Start State

The default scenario does not start from empty nodes.

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

## Replay Support: Baselines, Cache, And Choice Decoding

`ScpDporReplaySupport` uses three mechanisms for managing replay state.

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
- per-value txset status history
- pending txset wait-time eligibility from prior `waiting` results
- per-value txset wait-time history
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

### 3. Upfront Choice Decoding

Before replaying an observed event, `replayObservation()` calls
`decodeKnownTxSetChoices()` to scan the trace for any nondeterministic choice
entries (txset status choices and txset download wait-time choices) that
immediately follow the current observed event.

If known choices exist, they are preloaded into the node via
`enqueueTxSetStatusChoices()` and `enqueueTxSetDownloadWaitTimeChoices()`
before replay begins. This allows the event to be replayed in a single pass
without checkpointing or retrying.

If SCP discovers a choice that was not already in the trace (i.e. a new
nondeterministic branch), the node throws an exception and
`replayObservation()` returns a pending DPOR event without retrying. See
below.

## Why Txset Choices Use Exception + Pending Return

`getTxSetDownloadWaitTime()` and the txset status callback can be reached deep
inside ordinary SCP handling of a receive or timer firing.

At that point, the replay layer is already in the middle of "execute this one
observed event". The current `SCPDriver` interface returns only a value, so
there is no explicit "pause and request a DPOR choice" channel at that seam.

The current mechanism is:

1. Before replaying, `decodeKnownTxSetChoices()` scans the trace for choice
   entries that follow the current observed event. Known choices are preloaded
   into the node.
2. Start replaying one observed event.
3. If SCP asks for a txset choice (status or wait-time) and none has been
   preloaded, `DporScpNode` throws `TxSetStatusChoiceRequired` or
   `TxSetDownloadWaitTimeChoiceRequired`.
4. `replayObservation()` catches the exception.
5. If the trace does not already contain the choice, replay returns a pending
   DPOR nondeterministic choice event (no retry, no checkpoint restore).
6. On the next call, the choice will be present in the trace and preloaded
   upfront, so replay succeeds in a single pass.

Earlier versions of this code used a per-call checkpoint and retry loop:
snapshot before replay, catch the exception, restore the checkpoint, preload
the choice, and replay the same event again. That mechanism was replaced by
upfront choice decoding, which avoids the snapshot/restore cost entirely.

## Relation To Timers And Emitted Envelopes

`setupTimer()` and `emitEnvelope()` are handled differently from
`getTxSetDownloadWaitTime()`.

They are side effects of finishing the current SCP step:

- `emitEnvelope()` records the emitted envelope, and the scenario later turns
  pending envelopes into future DPOR send events
- `setupTimer()` records timer state, and the scenario later exposes enabled
  timers as future timer-choice / timer-firing behavior

They do not require the current step to suspend and ask DPOR for a new choice.
That is why they do not need the exception mechanism.

## On Modeling Txset Choices As DPOR Choices

Both the txset download wait time and the txset status callback are modeled as
DPOR nondeterministic choices.

The awkward part is not whether they are DPOR events; the awkward part is that
SCP discovers the need for a choice in the middle of executing another event.

The upfront-decoding approach sidesteps this for known choices: if a choice is
already in the trace, it is preloaded before replay begins, and SCP never
needs to pause. The exception path only fires when a genuinely new choice is
discovered, in which case replay returns a pending event and the next call
replays the event with the choice preloaded.

## Working Mental Model

The simplest way to think about the current replay loop is:

- stored baselines define the starting point for replay
- cached nodes are reusable scratch objects
- before replaying an observed event, known txset choices from the trace are
  decoded and preloaded into the node
- if replay discovers a new txset choice mid-step, the node throws an
  exception and replay returns a pending DPOR event; on the next call the
  choice is in the trace and gets preloaded upfront
