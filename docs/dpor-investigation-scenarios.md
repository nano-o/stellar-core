# DPOR investigation scenarios

At a high level, the model-checker runs the SCP state machine of a few
nodes (3 by default) in a simulated environment. The model-checker
calls the SCP API and intercepting all calls from SCP. It collects all
messages sent  and tries all (up do `--depth` and other boundaries or
fail-fast options) possible non-equivalent message delivery
interleavings. But it can also non-deterministically respond to
certain call and try all possible choices. For example, to exercise
the effect of parallel txset downloading on the SCP state machine, we
can  instruct the model-checker to respond to `validateValue()` and
`getTxSetDownloadWaitTime()` non-deterministically and explore all
cases.

A scenario determines how the nodes are started, which message
interleavings are tried, what methods return non-deterministically and
what constraints are placed on that, any stopping condition, etc.

For now there is only one `ScpDporDefaultScenario`. However, it has
several configurable parameters.

The scenario runs 3 nodes by default with a 2-out-of-3 qset. Using
`--nodes 4` switches to 4 nodes and a 3-out-of-4 qset.

The scenario assumes empty-txset support (CAP 83). That support is
unconditional on current `master`; there is no separate DPOR feature define or
next-protocol configure requirement.

The scenario explores SCP behavior in a single slot (slot `0`). It
starts each node by calling `SCP::nominate()` and then lets the slot
execution unfold. It does not cover behaviors where a validator
creates or starts a slot because it receives envelopes for that slot
before calling nominate(), and it does not cover starting a slot after
a restart using `SCP::setStateFromEnvelope()`.

By default, node 0 receives nomination value "x" in `SCP::nominate()`,
and every other node receives "y". The `--init` flag changes this
behavior: with `--init same`, every node receives "x"; with `--init
unique`, nodes receive "x0", "x1", "x2", and optionally "x3".

After nodes are started, they run nomination and balloting. By
default,  messaging is asynchronous but reliable: messages can be
arbitrarily reordered and delayed, but every message that can be
received is eventually delivered (in a maximal execution). The flag
`--fifo` instead forces FIFO delivery of messages on each
point-to-point link; this reduces the search  space a lot, but also
reduces coverage (if there's an issue that happens only when messages
are reordered, it will be missed).

The mutually exclusive `--stop-on-prepare`, `--stop-on-commit`, and
`--stop-on-externalize` options stop each node when it emits the
corresponding boundary envelope (`CONFIRM` or `EXTERNALIZE` for the
commit boundary). The boundary envelope is still broadcast to peers
before that node stops; any envelopes it emits after reaching the
boundary are suppressed.

By default, timers never fire. To enable timers firing during
nomination, use option `--with-nomination-timers`. By default, the
nomination timer will only fire in round 1, taking the node to round
2, and so round 3 will never be reached. To change this, use
`--max-nomination-timers-round N`, which will permit timers firing up
to in round `N`. A related option is `--max-nomination-round N`, which
will stop any node that tries to install a nomination timer for a
round strictly greater than `N`.

To enable timers firing during balloting, use option
`--with-balloting-timers`. By default, the balloting timer can fire in
any round. With `--max-balloting-timers-round N`, balloting timers are
permitted to fire only up to round `N`. With `--max-balloting-round
N`, which will stop any node that tries to install a ballot timer for
a round strictly greater than `N`. 

The model checker can exercise txset validation status and download
timing. `--txset-status` controls values returned by
`validateValue()`, while `--download-time` independently controls
`getTxSetDownloadWaitTime()`.

By default, ordinary non-empty values are validated as
`kFullyValidatedValue`.

- With `always-valid`, `validateValue()` deterministically returns
  `kFullyValidatedValue` (that's the default).
- With `downloading-then-valid`, each unresolved value may initially
  return `kStructurallyValidValue` zero or more times and may later
  return `kFullyValidatedValue`. Once it returns fully validated, that
  result is latched for that node and value.
- With `always-downloading`, `validateValue()` deterministically
  returns `kStructurallyValidValue`, and the value remains eligible
  for download-wait handling.

To focus on balloting, use `--nomination-always-downloading` to force
nomination-time validation to return `kStructurallyValidValue`
deterministically.  Non-nomination validation still follows the
selected `--txset-status` mode.

For `getTxSetDownloadWaitTime()`, `--download-time below` is the
default, so an applicable `getTxSetDownloadWaitTime()` call returns a
duration below the timeout. `getTxSetDownloadWaitTime()` does not ever
resolve to a missing wait time. With `--download-time above`, an
applicable call returns a duration above the timeout. With
`--download-time nondet`, each applicable call may return a duration
below or above the timeout while the last result is below; once it
returns a duration above the timeout, that result is latched. It may
remain below the timeout throughout an explored execution.

Finally, `--download-succeeds-in-round N` models a successful download
tied to ballot progress. When a node emits a `PREPARE` whose ballot
counter is exactly `N` and whose ballot value is non-empty, that value
is marked as downloaded at that node. Later non-nomination validation
of that value returns `kFullyValidatedValue`, regardless of the
selected `--txset-status` mode, and download-wait handling is no
longer applicable to it. The result is scoped to that node and exact
value: it does not resolve another value or the same value at another
node.  The nomination-only override described above still takes
precedence for nomination-time validation.

## Native SCP API boundary

The investigation harness simulates the environment around the
production SCP implementation; it calls "native" SCP methods and
intercepts calls from SCP to its environment. It does not contain a
second implementation of SCP.

Each modeled validator is a
[`DporScpNode`](../src/scp/test/DporScpNode.h). A `DporScpNode`:

- owns a real [`SCP`](../src/scp/SCP.h) instance;
- implements [`SCPDriver`](../src/scp/SCPDriver.h); and
- passes itself to the `SCP` constructor as that instance's driver.

The scenario determines the order of external events. All protocol
transitions caused by those events run in the native `SCP`, `Slot`,
`NominationProtocol`, and `BallotProtocol` code.

### Calls from the harness into native SCP

The current investigation scenario enters native SCP in three ways:

- Starting a validator with `SCP::nominate(...)`

  `ScpDporReplaySupport::rebuildBaselines()` calls
  `SCP::nominate(...)`, buffers any emitted envelope, and remembers
  any timers set. Exploration can later begin from this saved
  baseline.

- Deliver a message: `SCP::receiveEnvelope(...)`

  A DPOR receive observation is decoded to the exact `SCPEnvelope` and
  delivered directly to the receiving node.

- Fire a timer: callback previously supplied to
  `SCPDriver::setupTimer(...)`

  The harness stores the callback and invokes it only when DPOR selects
  that timer. Nomination timers re-enter
  `Slot::nominate(..., timedout=true)`, and ballot timers re-enter
  `BallotProtocol::ballotProtocolTimerExpired()`.

`DporScpNode` wraps the first two calls to adapt raw `Value` and
 `SCPEnvelope` objects to the wrapper types expected by `SCP`
 (`ValueWrapperPtr` and `SCPEnvelopeWrapperPtr`). Timer callbacks
 originate in native SCP and are merely retained by the harness; the
 harness does not reimplement the timeout transition.

Envelope delivery goes directly to `SCP::receiveEnvelope(...)`, bypassing
`PendingEnvelopes` and the production overlay/download pipeline. Consequently,
`SCPDriver::isEnvelopeReady(...)` is implemented by `DporScpNode` but is not
called during current DPOR exploration.

`DporScpNode` also has adapters for starting balloting directly and restoring
state from an envelope. The default scenario used by
`scp-dpor-investigation` does not call either adapter; balloting begins through
the native nomination-to-ballot transition.

### Calls intercepted through `SCPDriver`

While processing an entry-point call, native SCP calls its `SCPDriver`.
Because the installed driver is `DporScpNode`, these calls cross back into the
harness:

- `emitEnvelope(...)`

  Detects configured stopping boundaries and queues the native envelope for
  the scenario to fan out as later DPOR send events. Inspection and replay
  paths also record an emitted-envelope history; ordinary exploration disables
  that separate history because it never reads it.

- `setupTimer(...)`, `stopTimer(...)`

  Records or removes native timer callbacks. Enabled callbacks become
  possible DPOR timer firings rather than wall-clock work.

- `validateValue(...)`

  Supplies the modeled transaction-set validation result. A result may
  be fixed or selected through a DPOR choice, depending on scenario
  options.

- `getTxSetDownloadWaitTime(...)`, `getTxSetDownloadTimeout()`

  Supplies the modeled transaction-set download state and timeout
  boundary. A nondeterministic wait time is exposed as a DPOR choice.

- `getQSet(...)`

  Resolves quorum-set hashes from the deterministic quorum-set store
  attached to the modeled node.

- `signEnvelope(...)`

  Is a no-op. Cryptographic transport authentication is outside this
  model's boundary.

- `getHashOf(...)`, `computeHashNode(...)`, `computeValueHash(...)`,
  `combineCandidates(...)`

  Make quorum-set hashing, nomination leaders, value ordering, and
  composite candidates deterministic and configurable for replay.

- `computeTimeout(...)`

  Returns the scenario's deterministic nomination or ballot timeout for
  the requested round.

- `hasUpgrades(...)`, `stripAllUpgrades(...)`,
  `getUpgradeNominationTimeoutLimit()`

  Model values as having no upgrades and leave nomination upgrade
  handling effectively disabled.

- `isEmptyTxSetValue(...)`, `protocolAllowsEmptyTxSetValues()`

  Supply the empty-transaction-set policy used by native ballot
  processing. `makeEmptyTxSetValueFromValue(...)` is also supplied.

- `isParallelTxSetDownloadEnabled()`

  Satisfies the driver contract and returns `true`; the SCP-only code
  exercised here does not call this method directly.

`DporScpNode` does not override every driver method that native SCP uses. The
remaining calls retain their standard `SCPDriver` behavior:

- `wrapValue(...)` and `wrapEnvelope(...)` create the normal wrappers;
- `extractValidValue(...)` returns no replacement value;
- `getNodeWeight(...)` performs the production quorum-set weight calculation;
- value and node formatting helpers retain their standard implementations; and
- the test-only nomination emit delay is zero.

Monitoring callbacks such as `valueExternalized(...)`,
`startedBallotProtocol(...)`, and `acceptedCommit(...)` remain the default
no-ops. The investigation checks externalization and agreement by inspecting
native emitted envelopes, not by intercepting the
`valueExternalized(...)` notification.

`emitEnvelope(...)` and timer installation are completed side effects of the
current native SCP step. The scenario turns their recorded results into later
DPOR events. Transaction-set status and wait-time choices are different:
native SCP can request them in the middle of processing an envelope or timer.
When a choice is not already present in the replay trace, `DporScpNode`
unwinds the call with a harness-specific exception so the replay layer can
return a pending DPOR choice. The selected value is preloaded before the
native step is replayed. See
[`dpor-replay-notes.md`](./dpor-replay-notes.md) for the detailed replay
protocol.


## DPOR events

The model-checker core works on graphs of DPOR events and supports 5
types of events: send, receive, non-deterministic choice, block, and
error, where a receive may be blocking or non-blocking. The first
three types are produced by a scenario, and the last two (block and
error) are inserted by the model checker.

The possible events are:

- Send (`SendLabel`)

  A modeled node sends an exact `SCPEnvelope` to one other node. The
  payload is a `ScpDporValue` of kind
  `ScpDporValue::Kind::Envelope`. Broadcasting one native envelope therefore
  produces one send event per receiving node, but those values share one
  immutable in-memory envelope payload and its precomputed content digest.
  This representation does not change equality, ordering, hashing, or the XDR
  stored in a version-4 trace.

- Receive (`ReceiveLabel`)

  A receive accepts envelope-delivery values for the scenario's slot.
  It is blocking when the node has no enabled timer. When a timer can
  fire, it is non-blocking: it can either receive an envelope or
  observe bottom. Observing bottom causes the replay layer to fire the
  selected timer. Timer firing is therefore not a separate event
  label.

- Nondeterministic choice (`NondeterministicChoiceLabel`)

  The scenario produces three kinds of choice:

  - a timer choice selects which timer may fire when more than one is
    enabled;
  - a transaction-set status choice selects `valid` or `downloading`,
    as allowed by the scenario configuration; and
  - a transaction-set download wait-time choice selects a duration
    below or above the download timeout.

- Block (`BlockLabel`)

  The DPOR core inserts this event when a blocking receive has no
  compatible unread send. Scenario thread functions do not return
  block events themselves.

- Error (`ErrorLabel`)

  The investigation wrapper converts an exception from a scenario
  thread into an error event containing the thread, step, and exception
  message.

Initial nomination, `SCPDriver::emitEnvelope(...)`, and timer
installation are not themselves DPOR events. They update the saved or
replayed node state; the scenario subsequently exposes their effects as
send, receive, or choice events.

## Correctness fingerprint and benchmarking

[`src/scp/test/bench-dpor.sh`](../src/scp/test/bench-dpor.sh) drives the
repeatable investigation workloads and can be invoked from any directory:

```bash
./src/scp/test/bench-dpor.sh check
./src/scp/test/bench-dpor.sh bench
./src/scp/test/bench-dpor.sh head
```

- `check` prints exact final execution counts for 13 scenarios. Treat its
  complete output as a semantic fingerprint: a performance-only change must
  not alter any line.
- `bench` times four terminating scenarios and reports the best of three runs.
- `head` time-boxes the three-node FIFO externalize workload and reports its
  steady-window and overall execution rates.

The script defaults to `src/scp-dpor-investigation`, eight workers, and a
60-second `head` window. Use `BIN` for an out-of-tree binary, `W` to replace
the worker arguments, and `SECS` to change the `head` duration. It exits
nonzero if any scenario process fails, including a `head` run that emits no
progress sample.

Final summary counts are exact even when parallel progress lines say
`counts_exact=false`. Performance measurements are noisier: compare old and
new binaries back to back in one session, preferably on terminating workloads.
On the shared `pop-os-desktop` host, differences below 20% are noise.

The optional restriction-based oracle for the masked FIFO tiebreaker is
documented in [`dpor-build.md`](./dpor-build.md#differentially-checking-the-masked-fifo-tiebreaker).
