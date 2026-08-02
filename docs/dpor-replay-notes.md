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

## `scp-dpor-investigation --fail-on-first-blocked`

The `--fail-on-first-blocked` mode continues past full, error-free executions
and stops at the first blocked execution. It writes the blocked execution's
JSON replay bundle to `--trace-dir`, focuses the bundle on the first node whose
thread ended at an unsatisfied blocking receive, dumps replay traces, and exits
nonzero. The bundle preserves `blocked` as its terminal kind rather than
rewriting it as an error execution.

If exploration finishes without reaching any blocked execution, the mode wrote
no bundle, so it also exits nonzero and says so, reporting the execution count,
the `--depth` used, and how many executions hit the depth limit. Treat that as
"the depth was too shallow to reach a blocked execution", not as a pass. The
depth needed depends on the scenario: with `--stop-on-prepare
--txset-status always-downloading --download-time above`, boundary envelopes
are broadcast before a boundary thread stops, which lengthens every execution
enough that blocked executions only appear from `--depth 18`. `--depth 12`
explores nothing but depth-limited executions there.

## JSON Trace Capture And Replay

`scp-dpor-investigation` persists the first captured terminal execution as a
structured JSON artifact into `--trace-dir` (default `dpor-traces`), prints
the chosen path as `trace-json=...`, and can reload that artifact later with
`--replay-trace-json PATH`.

The persisted replay input is not a full schedule. It stores:

- the effective `ScpDporDefaultScenario::Options`
- terminal metadata such as terminal kind, failure message, and focus thread
- one raw `ThreadTrace` per thread

Trace bundles use schema version 6. Version 6 stores the txset-status modes as
`always-valid`, `downloading-then-valid`, or `always-downloading`, and txset
status choices can contain only `valid` or `downloading`. It records at most
one txset status choice and one txset wait-time choice per value per external
event.

Version-5 bundles are rejected because they recorded a choice per `SCPDriver`
call rather than per external event. Such a bundle carries choices the current
model never asks for, and replay rejects the leftovers rather than letting a
later event consume one.

Version-4 bundles are rejected because `--download-succeeds-in-round` used to
take effect in the same event that emitted the triggering `PREPARE`, and now
takes effect from the next event onward. No measured scenario changed its
execution count across that shift, but a version-4 trace was captured under
different semantics and is not guaranteed to replay the same way.

Version-2 and version-3 bundles are rejected before their scenario options or
trace observations are parsed because they may contain the removed
downloaded-invalid status or nondeterministic status mode. Replaying either
under the reduced current model would change the explored behavior.

Version-1 bundles are rejected before scenario options or trace observations
are parsed. Their `invalid` status meant outright SCP-value invalidity, so
loading them under any later schema would replay a different protocol
execution.

This matches the existing replay seam:

- DPOR produces `execution.graph.thread_trace(threadId)`
- the SCP harness reconstructs human-meaningful replay steps by feeding that
  trace into `inspectThreadReplayTrace(...)`

The JSON trace therefore preserves the exact per-thread observed-value input
needed for debugger-oriented replay without encoding DPOR reads-from edges or
global insertion order.

Consequently this format does not import `ExecutionGraphT` event ids and does
not call the engine's `add_event_with_index()` API. That API's monotonic
per-thread index requirement protects low-level graph importers but does not
change the SCP trace schema or ordinary model-checking replay.

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

Once a node reaches that boundary, the scenario broadcasts the envelope that
reached it and then stops producing further events for that thread. Envelopes
emitted after the boundary are suppressed.

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

## Replay Support: Baselines, Prefix Cursors, And Choice Decoding

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
- per-value txset wait-time history
- per-value txset wait-time call counts
- per-value successful txset downloads
- per-value txset downloads that completed during the running event and are
  promoted when the next event opens
- replay-boundary state

The configured per-node outright-invalid value sets are immutable scenario
configuration rather than mutable replay state. Loading a version-6 bundle
reconstructs those sets before baselines are built.

These baselines are built once when `ScpDporReplaySupport` is constructed.
Each snapshot receives a content identity that is preserved by copies. A
`DporScpNode` uses that identity to reuse the immutable SCP value and envelope
wrappers built for repeated restores of the same baseline. The identity is a
counter rather than a baseline address because baselines are copied and moved;
equal snapshot copies must share the cache key even when their addresses do
not.

### 2. Thread-Local Prefix-Resume Cache

Exploration calls `acquireReplayState(nodeIndex, trace, step)`, which keeps a
thread-local bucket of partially replayed `DporScpNode` objects for each
validator. Each `ScpDporReplaySupport` construction or copy has a distinct
generation, so stale cache entries cannot be reused by a later scenario even
if an object address is recycled.

Each cache entry contains a node and a `ReplayCursor`. A valid cursor records:

- the exact observed trace prefix already consumed
- the pending-send vector and its next unread position
- the DPOR event count reached by that prefix
- the currently selected timer, if any
- the event label published at the stopping step

`mValid` is the sole resume certificate. When it is true, the node state is
exactly the stored baseline plus `mConsumedTrace`, and all scenario-loop fields
in the cursor describe that same point. When it is false, the cache makes no
claim about the node and will not resume it.

The cache selects the valid entry with the longest consumed prefix that the
incoming trace extends and that has not passed `step`. Replay continues from
there instead of restoring the baseline and replaying the whole trace. If the
previous call stopped at exactly the requested step, its memoized label is
returned directly. Depth-first siblings commonly share such prefixes, so this
changes repeated thread-function evaluation from quadratic replay toward the
amount of newly appended trace work.

Up to 64 entries are retained per validator per worker thread. If no prefix
matches, a new entry is allocated until that limit; after that, the
least-recently-used entry is invalidated and restored to the baseline. The
limit is only a performance policy and does not change replay semantics.

`captureNextEvent()` invalidates the selected cursor before advancing it and
marks it valid only at a publish point. Every published send, receive, timer
choice, completion, or error label depends only on the consumed prefix, never
on the unconsumed trace suffix. If replay discovers a new nondeterministic
choice part-way through an envelope, or throws before reaching a publish
point, the node is mid-step and the cursor remains invalid. The next call must
therefore restore a baseline rather than resume that partial state.

Inspection paths still use `acquireNode()`, clear the current thread's cache,
and restore the requested baseline explicitly. Prefix cursors are an
exploration optimization, not persisted replay data.

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

The choice queues are append-only with a persistent read index, so the
symmetric failure also has to be caught: a trace supplying a choice the
replayed event never asks for would leave it for some later event to consume
silently. After an observed event replays to completion,
`replayObservation()` checks `DporScpNode::hasUnconsumedTxSetChoices()` and
throws. The existing check in the other direction -- a trace that omits a
choice the event does ask for -- lives in the exception handlers.

## External Event Scoping

`DporScpNode::ExternalEventScope` scopes one external event: a single call that
drives SCP from outside, plus everything SCP does synchronously inside it.
`nominate`, `startBalloting`, `receiveEnvelope`, `setStateFromEnvelope`, and
`fireTimer` (around its callback) each open one. The scope is public so tests
can open an event explicitly; direct driver calls made outside any scope form
one implicit event that is reset whenever a real scope opens or closes.

Two pieces of state hang off it:

- the per-event txset decisions, cleared when the outermost scope opens and
  again when it closes. Within one event, a given value's modeled status and
  download wait time are each decided at most once, so repeated `SCPDriver`
  callbacks inside one handler observe one consistent snapshot. Distinct values
  still branch independently, and both answers can still change at the next
  event boundary.
- deferred download success. `--download-succeeds-in-round` fires from
  `emitEnvelope()`, i.e. mid-handler; the value is recorded as pending and
  promoted when the next event opens, so a completion cannot flip a verdict
  part-way through the handler that caused it.

`--nomination-always-downloading` is a deliberate exception: it forces
nomination-phase validation without consulting or writing the per-event
decision, so a nomination and a balloting validation of the same value in one
event can still disagree. That is a known modeling wart, kept because
memoizing it would stop balloting from ever branching in an event that began
with a nomination validation.

Snapshotting or restoring a replay baseline is only legal at an event
boundary. `snapshotReplayBaseline()` throws if a scope is open **or** if the
per-event decisions hold anything, and `restoreReplayBaseline()` throws if a
scope is open. The decisions are deliberately not part of `ReplayBaseline` --
they belong to an event, not to a resumable state -- and those checks are what
keep the omission from becoming a silent correctness hole.

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

- `emitEnvelope()` always updates boundary/download state and queues the
  envelope for the scenario to turn into future DPOR send events
- `setupTimer()` records timer state, and the scenario later exposes enabled
  timers as future timer-choice / timer-firing behavior

They do not require the current step to suspend and ask DPOR for a new choice.
That is why they do not need the exception mechanism.

The separate emitted-envelope history is not read by exploration, so
`captureNextEvent()` disables recording it to avoid deep-copying every emitted
envelope. Replay inspection, boundary inspection, and other diagnostic paths
re-enable the history before restoring and running a node. Replay-debug events
are likewise constructed only while debug recording is enabled. Neither
optimization suppresses pending sends, boundary detection, download-success
tracking, or timer state.

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
- valid prefix cursors certify the exact state of cached nodes and allow replay
  to resume from the longest matching trace prefix
- labels memoized at a cursor's stopping step depend only on that consumed
  prefix
- before replaying an observed event, known txset choices from the trace are
  decoded and preloaded into the node
- if replay discovers a new txset choice mid-step, the node throws an
  exception and replay returns a pending DPOR event while leaving the cursor
  invalid; on the next call the choice is in the trace, the node is restored,
  and the choice gets preloaded upfront
