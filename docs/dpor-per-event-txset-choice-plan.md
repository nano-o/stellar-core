# DPOR Per-Event Tx-Set Choice Scoping Plan

Status: **implemented.** Revision 6, after five design reviews; see
[Review disposition](#review-disposition) for what changed during design, and
[Implementation notes](#implementation-notes) at the end for the two places
where the plan's predictions did not survive contact with measurement.

Baseline: branch `dpor-on-master` at `b784d2f25`, `external/dpor` pinned at
`febae6f`. Fingerprint captured with `src/scp/test/bench-dpor.sh check` on this
binary (see [Part 6](#part-6--validation)).

## Goal

Make the modeled tx-set validity status and download wait time **stable within
a single external event**. Today every `SCPDriver` callback that lands on a
value whose download is still in flight opens a fresh DPOR branch point, even
when several such calls happen inside one `receiveEnvelope`.

Two separable motivations, worth keeping distinct because they justify
different amounts of confidence:

- **Fidelity (strong).** Repeated `validateValue(v, nomination)` calls with
  identical arguments inside one handler cannot disagree in production. The
  model letting them disagree explores states the real system cannot reach.
- **Abstraction (weaker, deliberate).** Repeated `getTxSetDownloadWaitTime(v)`
  inside one handler *can* in principle straddle the timeout in production,
  because the clock advances continuously. Pinning it per event is a modeling
  choice — a defensible one, since the wait is only ever consumed as the
  predicate `waitingTime < timeout` and the model already latches the
  above-timeout case — but it is not a behavior-preserving correction.

Both cut the dominant source of state-space blowup in the nondeterministic
tx-set scenarios.

Non-goal: changing *which* behaviors are modeled. Downloads must still be able
to complete, and waits must still be able to cross the timeout — at event
boundaries.

## Part 1 — What production actually does

### `validateValue` is a pure query (strong claim)

`HerderSCPDriver::validateValue`
([`HerderSCPDriver.cpp:593`](../src/herder/HerderSCPDriver.cpp)) →
`validateValueAgainstLocalState` (`:398`) → `mPendingEnvelopes.getTxSet(txSetHash)`
plus the LCL header.

`kStructurallyValidValue` is returned on **two** paths, not one:

- the tx set is absent — `getTxSet` returned null (`:461-472`);
- the tx set is present but fails `checkAndCacheTxSetValid` (`:481-488`).

Both collapse to the model's `Downloading` status. The DPOR harness models only
the first, which is a pre-existing coverage gap, not something this change
touches — but Part 1 must not claim the mapping is exact.

The inputs to that verdict are the fetcher's tracker map and
`mPendingEnvelopes`'s tx-set cache. Several paths mutate them — `fetch` creates
trackers ([`ItemFetcher.cpp:32`](../src/overlay/ItemFetcher.cpp)), the arrival
path `recvTxSet` resolves them, `stopFetchingOutsideRange` erases them (`:139`)
— so the property that matters is not "one writer" but **serialization**: every
mutation path runs on the main thread as its own callback, and none can run
re-entrantly inside `Slot::processEnvelope`. The one plausible re-entry,
`emitEnvelope`, goes `HerderSCPDriver::emitEnvelope` →
`HerderImpl::emitEnvelope` → `persistSCPState` + `broadcast`, and touches no
fetcher state. Tx-set validity is itself memoized (`checkAndCacheTxSetValid`).

### The nomination flag is not inert

The verdict is *not* a function of `value` alone. After
`validateValueAgainstLocalState` returns, `extractValidUpgrades(b, nomination)`
(`:611`) drops upgrades that fail `Upgrades::isValid`, which applies an extra
`isValidForNomination` check only when `nomination` is true
([`Upgrades.cpp:698-702`](../src/herder/Upgrades.cpp)). Any drop turns the
verdict into `kInvalidValue` (`:612-619`). So a value carrying an upgrade can be
fully valid for balloting and invalid for nomination.

The precise production invariant is therefore:

> Within one handler, repeated `validateValue` calls with identical
> `(value, nomination)` arguments return identical verdicts; across differing
> `nomination`, the **tx-set-derived component** of the verdict is still stable,
> and only upgrade filtering may differ.

Keying the harness memo on `Value` alone (§3.1) stays sound, and stays sound
even if upgrades are eventually modeled. Tx-set availability is phase-independent
— it is a property of the fetcher, not of who is asking — so the shared status
memo is correctly keyed on `Value`. Upgrade filtering is a separate, phase-
dependent stage that belongs *outside* that memo; only a memo over the complete
verdict would need the phase flag. Today the question does not arise:
`DporScpNode::hasUpgrades` returns `false` and `stripAllUpgrades` is the
identity.

### `getTxSetDownloadWaitTime` reads a live clock (weaker claim)

`HerderSCPDriver::getTxSetDownloadWaitTime` (`:1139`) →
`PendingEnvelopes::getTxSetWaitingTime`
([`PendingEnvelopes.cpp:881`](../src/herder/PendingEnvelopes.cpp)) →
`ItemFetcher::getWaitingTime`
([`ItemFetcher.cpp:98`](../src/overlay/ItemFetcher.cpp)) → `Tracker::getDuration`
([`Tracker.cpp:273`](../src/overlay/Tracker.cpp)) →
`LogSlowExecution::checkElapsedTime`
([`LogSlowExecution.cpp:41`](../src/util/LogSlowExecution.cpp)), i.e.
`system_clock::now() - mStart`.

The clock advances between calls. With `TX_SET_DOWNLOAD_TIMEOUT` defaulting to
**5000 ms** ([`Config.cpp:260`](../src/main/Config.cpp)) — the model uses
1000 ms, `DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS` — a handler would
have to sit exactly on the boundary for two calls to disagree. Unlikely, but
not impossible, and not "measure-zero". Treat per-event pinning here as an
abstraction we are choosing, on the grounds that a mid-handler timeout flip
carries no protocol meaning that an event-boundary flip does not.

### Why the fidelity claim matters

`BallotProtocol::processEnvelope` gates the entire envelope on the *first*
verdict (`statementValidationLevel`,
[`BallotProtocol.cpp:189`](../src/scp/BallotProtocol.cpp)); the same value is
then validated again downstream in the same handler:

| call site | file:line |
|---|---|
| `statementValidationLevel` (once per envelope, over the statement's value set) | `BallotProtocol.cpp:2142` |
| `setConfirmPrepared` (gates vote-to-commit) | `BallotProtocol.cpp:1164` |
| `maybeReplaceValueWithEmptyTxSet` (+ the only `getTxSetDownloadWaitTime` call) | `BallotProtocol.cpp:387`, `:401` |
| `throwIfValueInvalidForConfirmCommit` | `BallotProtocol.cpp:1440` |
| `NominationProtocol::validateValue` | `NominationProtocol.cpp:362`, `:447` |

Letting these disagree admits an envelope as fully validated that then takes
the "blocked on tx set" path two frames deeper — a state production cannot
produce.

## Part 2 — What the model does today

`DporScpNode` latches only monotone/terminal outcomes:

| outcome | latched today? | where |
|---|---|---|
| status `Valid` | yes, across events | `DporScpNode.cpp:884` |
| download-succeeded | yes | `mTxSetDownloadsSucceeded`, `:877` |
| wait time ≥ timeout | yes | `:773` |
| status `Downloading` | **no — fresh branch every call** | `:892` |
| wait time < timeout | **no — fresh branch every call** | `:779` |

Documented in the `--txset-status` / `--download-time` help text
([`DporScpInvestigationMain.cpp:285`](../src/scp/test/DporScpInvestigationMain.cpp))
and asserted by `SCPDporSmokeTests.cpp:1758-1763`.

### Observed cost

Trace captured with
`--nodes 3 --fifo --txset-status downloading-then-valid --nomination-always-downloading --download-time nondet --stop-on-externalize --depth 30 --fail-on-first-terminal`.
Thread 2's recorded event sequence:

```
ENV, ENV, txset_status, ENV, txset_status, txset_wait_time, txset_status, txset_status
```

Four choice events inside the handler for the third envelope — three status
choices, all answering `downloading`. Each is an independent branch point, each
consumes a step of the depth budget (`ScpDporReplaySupport.cpp:326`), and —
because a choice is raised by exception from mid-handler and invalidates the
replay cursor (`ScpDporDefaultScenario.h:944`) — each forces the handler to be
re-executed from the baseline. A handler with K choices runs K+1 times per path.

Executions, all-explored, `--nodes 3 --fifo --nomination-always-downloading
--stop-on-externalize`:

| depth | `always-valid` / `below` | `downloading-then-valid` / `nondet` |
|---|---|---|
| 18 | 8 | 33 |
| 20 | 9 | 73 |
| 22 | 12 | 104 |
| 24 | 23 | 131 |

Some of that gap is legitimate modeling. The intra-handler multiplier is not.

### A second defect: the pending-download counter

`mPendingTxSetDownloadStatusCounts` (`DporScpNode.h:389`) pairs verdicts to
wait-time queries by counting: `validateValue` increments on every `Downloading`
verdict (`:901`), `getTxSetDownloadWaitTime` decrements (`:748`) and returns
`nullopt` at zero (`:740`).

Only `maybeReplaceValueWithEmptyTxSet` pairs the two 1:1.
`statementValidationLevel` and `setConfirmPrepared` increment with no matching
query, so counts leak forward across events; conversely a value validated once
but queried twice reports "no download in progress", driving SCP down the
drop-the-tx-set path at `BallotProtocol.cpp:414` for a reason production would
never produce.

## Part 3 — The change

### 3.0 The invariant, stated precisely

> Within one external event, for a given non-empty `Value v` that reaches the
> modeled tx-set-status path: all balloting-phase (`nomination == false`)
> `validateValue(v)` answers agree, and all `getTxSetDownloadWaitTime(v)`
> answers agree. When `--nomination-always-downloading` is **off**,
> nomination-phase answers agree with balloting-phase answers as well.

The invariant governs the **tx-set-status decision**, not the complete
validation answer. Two earlier stages legitimately answer per phase and are
outside its scope, because they never consult download state:

- outright-invalid values (`DporScpNode.cpp:862`);
- empty-tx-set values, which return `kInvalidValue` during nomination and
  `kFullyValidatedValue` during balloting (`:868-872`) — a phase split that
  exists with or without the §3.5 forcing knob, and that mirrors production
  (`HerderSCPDriver.cpp:430-450`).

Both short-circuit before the memo, so neither reads nor writes it. The one
carve-out that *does* touch the modeled path is §3.5. Distinct values in one
event still branch independently — correct, they are distinct downloads.

### 3.1 Event scope

Split across two commits: the guard itself lands in commit 2, because §3.4's
deferred download success is promoted by it; the decision map lands in
commit 3.

An RAII guard entered by the five entry points that drive SCP from outside:

| entry point | `DporScpNode.cpp` |
|---|---|
| `nominate` | `:190` |
| `startBalloting` | `:197` |
| `receiveEnvelope` | `:204` |
| `setStateFromEnvelope` | `:210` |
| `fireTimer` | `:247` (around the `cb()` call at `:268`) |

The guard clears the per-event map on **both** outermost entry and outermost
exit (depth 0→1 and 1→0). Clearing only on entry would leave a finished event's
decisions readable by a subsequent direct driver call, which is exactly the
ambiguity the smoke tests would trip over. None of the five currently nest —
`fireTimer`'s callback calls `Slot::nominate`, not `DporScpNode::nominate` —
but the depth counter makes that a checked property.

Expose the guard type publicly so tests can open an event explicitly. Make it
non-copyable and non-movable: a copied guard would decrement the depth twice
and clear the map mid-event. Direct driver calls made outside any guard form
one implicit event, reset whenever any guard opens or closes. Tests that
exercise per-event behavior must use an explicit guard rather than relying on
the implicit scope.

**Snapshots are only valid at event boundaries.** Because the memo is
deliberately absent from `ReplayBaseline` (Part 4), a snapshot taken while it is
populated — inside a guard, or during an implicit event that has already
answered a call — silently drops it, and restoring can then answer differently.
Enforce the contract rather than documenting it. Both checks throw
`std::logic_error`, not an assert: neither `DporScpNode.cpp` nor
`ScpDporReplaySupport.cpp` uses `releaseAssert` or `assert` today, and every
existing invariant in them is a throw. Matching that keeps the checks
non-elidable in every build.

The two checks land in **different commits**, because one of them names state
that does not exist yet:

| check | commit |
|---|---|
| `snapshotReplayBaseline` rejects `mExternalEventDepth != 0` | 2 (with the guard) |
| `restoreReplayBaseline` rejects `mExternalEventDepth != 0` | 2 (with the guard) |
| `snapshotReplayBaseline` rejects a non-empty `mTxSetDecisionsThisEvent` | 3 (with the map) |

The map-empty check is the one that bites, and so is the smoke-test
restructuring it forces: several tests snapshot after a bare `validateValue`
call, e.g. `SCPDporSmokeTests.cpp:1738-1739` and `:1756-1757`, which sit in an
implicit event at depth 0 with a populated map. Those must wrap the preceding
calls in an explicit guard so the implicit event is closed before the snapshot.
Both the check and that restructuring belong to commit 3; the depth checks in
commit 2 are inert for tests that only call driver methods directly.

New state, replacing `mPendingTxSetDownloadStatusCounts`:

```cpp
struct TxSetEventDecision
{
    std::optional<DporScpTxSetStatus> mStatus;
    bool mWaitTimeDecided{false};
    std::optional<std::chrono::milliseconds> mWaitTime;
};

std::uint32_t mExternalEventDepth{0};
mutable std::map<Value, TxSetEventDecision> mTxSetDecisionsThisEvent;
```

Keyed on `Value` alone, not `(Value, nomination)`: in production the nomination
flag changes only the empty-tx-set early-outs and upgrade extraction, never the
fetcher lookup.

### 3.2 `validateValue` (`DporScpNode.cpp:860`)

1. `isOutrightInvalidValue` / `isEmptyTxSetValue` early-outs — unchanged, pure.
2. `nomination && mNominationAlwaysDownloadingTxSetStatus` (`:873`) — unchanged,
   before the memo, neither reading nor writing it. See §3.5.
3. `mTxSetDownloadsSucceeded` early-out — unchanged.
4. **New:** if `mTxSetDecisionsThisEvent[value].mStatus` is set, return it.
5. Existing cross-event `Valid` latch (`:884`), else consume a choice.
6. Record into `mLastTxSetStatusByValue` (cross-event latch, unchanged) **and**
   the event decision.

### 3.3 `getTxSetDownloadWaitTime` (`DporScpNode.cpp:727`)

1. Early-outs at `:729` — unchanged, pure.
2. **New:** if `mWaitTimeDecided` for this value this event, return the
   memoized answer, including a memoized `nullopt`.
3. **Changed gate:** in nondeterministic-status mode, return `nullopt` unless
   the status decided for this value is `Downloading`. Read the event decision
   first; if unset, fall back to `mLastTxSetStatusByValue` **and write the
   fallback into the event decision**, so a wait query that runs before any
   validation in the event still pins the event's status. This replaces the
   counter at `:737-750`.

   **Every gated `nullopt` return must set `mWaitTimeDecided = true` with
   `mWaitTime` empty**, including the case where neither the event decision nor
   `mLastTxSetStatusByValue` has any status to fall back on. Otherwise a wait
   query that precedes all validation returns `nullopt` without recording
   anything, a later `validateValue` in the same event chooses `Downloading`,
   and the next wait query branches — two different answers in one event, which
   is exactly what §3.0 forbids. Memoizing the status fallback alone does not
   cover this, because in the no-history case there is no status to memoize.

   In practice this whole branch should be unreachable —
   `maybeReplaceValueWithEmptyTxSet` always validates (`:387`) before querying
   (`:401`), and it is the only caller — so add a comment saying so. But the
   memo must be correct without relying on that call order, since the order is
   a property of production code the harness does not own.
4. Above-timeout latch (`:773`) — unchanged.
5. Consume a choice, or index the configured sequence; memoize the answer.

Two deliberate consequences:

- `mTxSetDownloadWaitTimeCallCountsByValue` (index into a configured
  multi-entry `mTxSetDownloadWaitTimes`) advances once per event rather than
  once per call. Only reachable from direct `Configuration` use in tests — the
  scenario's `below`/`above` modes configure a single element and `nondet` takes
  the nondeterministic path (`ScpDporDefaultScenario.h:582-599`).
- The `UseTxSetDownloadWaitTime` replay-debug event (`:760`) is recorded on
  every call that **returns a wait time**, memo hits included, so investigation
  output continues to show what SCP actually observed. Memo hits that return
  `nullopt` record nothing, matching today's behavior, where only `recordWaitTime`
  emits the event. This is required, not stylistic: the formatter dereferences
  `event.mWaitTime` unconditionally
  ([`DporScpInvestigationMain.cpp:720`](../src/scp/test/DporScpInvestigationMain.cpp)),
  so a null-valued event would crash the investigation runner. It also keeps the
  existing `countWaitTimeDebugEvents` assertion at `SCPDporSmokeTests.cpp:1559`
  meaningful.

### 3.4 Download success must defer to the next event

`emitEnvelope` calls `markTxSetDownloadSucceeded` mid-handler
(`DporScpNode.cpp:835`) when `--download-succeeds-in-round` is armed. Erasing
the event decision there — as revision 1 of this plan proposed — lets a later
`validateValue` in the same event flip to `Valid`, reintroducing exactly the
mid-event flip this change exists to remove.

Instead, defer: `markTxSetDownloadSucceeded` records the value in a new
`mPendingTxSetDownloadsSucceeded` set, and the event guard promotes that set
into `mTxSetDownloadsSucceeded` (erasing the value's entries in the status and
wait-time maps, as `:1333` does today) at the **start of the next event**. A
download that completes during event N is observable from the start of event
N+1.

Unlike the event memo, this pending set **must** be serialized into
`ReplayBaseline` (`DporScpNode.h:171`) and cleared in `clearReplayState`
(`:1313`): a snapshot taken between the emit and the next event would otherwise
lose it. Net baseline size is unchanged, since
`mPendingTxSetDownloadStatusCounts` is removed.

This shifts the meaning of `--download-succeeds-in-round N` by one event.
Scenario CA moves; the help text at `DporScpInvestigationMain.cpp` should say
"from the next event onward" rather than "later".

### 3.5 The nomination override is an explicit carve-out

`--nomination-always-downloading` forces nomination-phase validation to
`Downloading` without consuming a choice. It is a branch-saving forcing knob,
not a model of fetcher state.

It genuinely breaks the per-event invariant: `NominationProtocol::processEnvelope`
can call `mSlot.bumpState(...)` synchronously
([`NominationProtocol.cpp:521`](../src/scp/NominationProtocol.cpp)), so one
`receiveEnvelope` of a NOMINATE message runs nomination validation (forced
`Downloading`) and then balloting validation, which may choose `Valid`. With
the harness's default `combineCandidates` returning the first candidate
verbatim (`DporScpNode.cpp:990`), the composite is one of the nominated values,
so this is a same-value conflict, not a different-value one.

Memoizing the override into the balloting phase would remove the conflict but
destroy the flag: balloting would never branch in any event that began with a
nomination validation, which is precisely what scenarios C1/C6/CB/CC exist to
explore. So the override stays exempt, the invariant in §3.0 is narrowed to say
so, and a smoke test pins the exemption rather than leaving it implicit.

Recorded as a known modeling wart in `docs/dpor-integration-status.md`. The
clean fix belongs with the follow-up in Part 7 item 4: if tx-set availability
becomes its own event source, the flag can become an initial-state fact instead
of a per-call override.

### 3.6 What does not change

- Cross-event behavior: a download can still complete, and a wait can still
  cross the timeout, at the first relevant call of any later event.
- The `Valid` latch, the download-succeeded latch, the above-timeout latch.
- Deterministic modes (`always-valid`, `always-downloading`, `below`, `above`)
  request no choices today and must request none after.

## Part 4 — Interaction with the replay machinery

**Snapshots.** `mTxSetDecisionsThisEvent` needs no `ReplayBaseline` field
*given* the event-boundary runtime checks in §3.1 — without them the omission
is a silent correctness hole. The decisive check is the map-empty one, and it
lands in the same commit as the map itself (commit 3), so the map is never
present without the check that protects it. Commit 2's event-depth checks are
the weaker half: useful on their own, but they cannot catch a snapshot taken at
depth 0 during an implicit event.
`mPendingTxSetDownloadsSucceeded` does need a field (§3.4). Both are cleared in
`clearReplayState`.

**Re-execution determinism.** After a choice exception the handler is re-run
from the cursor/baseline with the choice preloaded
(`ScpDporReplaySupport.cpp:320-324`). Clearing at entry makes the re-run
rebuild the identical memo from the identical preloaded queue, preserving the
property the cursor memo depends on (`ScpDporDefaultScenario.h:814-819`).

**New invariant to enforce.** `mPendingTxSetStatusChoices` /
`mPendingTxSetDownloadWaitTimeChoices` are append-only queues with a persistent
read index. If a trace supplies a choice the re-execution no longer requests,
the queue desynchronizes and a later event silently consumes a stale choice.
There is a guard for the opposite direction only (`ScpDporReplaySupport.cpp:335`).
Add the symmetric check: after `replayOneObservedValue` returns normally, verify
both queues are fully consumed.

Two implementation constraints:

- **Throw, do not assert.** Use `throw std::logic_error(...)` with a message
  mirroring the existing "trace omits a txset status choice before the next
  observed event" at `:335`. This is trace-driven input validation on the same
  footing as its sibling, and an elidable assert would let a desynchronized
  queue through in exactly the builds where it matters.
- **Replay support cannot see the queues.** Both the vectors and their read
  indices are private, and `DporScpNode` declares no `friend`
  (`DporScpNode.h:386-394`). Add a minimal public const query —
  `bool hasUnconsumedTxSetChoices() const` — rather than exposing the indices
  or granting friendship. A boolean is all the check needs.

**Trace bundles need two version bumps, not one.** Two separate commits change
how a stored trace replays, and each must leave the tree self-consistent
(`ScpDporTraceJson.h:17`, validated at `ScpDporTraceJson.cpp:551` and `:1002`):

| commit | breaking change | version |
|---|---|---|
| 2 | `--download-succeeds-in-round` shifts by one event (§3.4), so a v4 trace replays differently | 4 → **5** |
| 3 | per-call choices become per-event; the queue runtime check rejects the leftovers a v5 trace still carries | 5 → **6** |

Collapsing commits 2 and 3 into one bump is the alternative, but it also
collapses the CA fingerprint delta into a single unattributable number
(Part 6), which is the thing the split exists to avoid. Two bumps cost a
constant and a message.

Reject superseded versions explicitly, following the pattern for 1-3 at
`ScpDporTraceJson.cpp:989-1001`. While there, fix the existing v1-v3 messages:
they instruct the user to "capture a version 4 trace" and go stale on every
bump. Replace the version-specific advice with "capture a fresh trace with the
current binary" in all of them.

No migration: bundles are ad-hoc debugging artifacts written to `dpor-traces/`,
none are checked in, and a mechanical migration would have to guess which of
several recorded choices the memo now answers.

## Part 5 — Files touched

| file | change |
|---|---|
| `src/scp/test/DporScpNode.h` | event guard (public), `TxSetEventDecision`, `mPendingTxSetDownloadsSucceeded` (member + `ReplayBaseline` field), drop `mPendingTxSetDownloadStatusCounts` |
| `src/scp/test/DporScpNode.cpp` | entry-point guards; `validateValue` / `getTxSetDownloadWaitTime` memo; counter removal; deferred download success; `clearReplayState`, `markTxSetDownloadSucceeded`, snapshot/restore |
| `src/scp/test/ScpDporReplaySupport.cpp` | fully-consumed-queue runtime check |
| `src/scp/test/ScpDporTraceJson.h` / `.cpp` | `TRACE_BUNDLE_VERSION` 4→5 (commit 2) then 5→6 (commit 3); explicit rejection of each superseded version; version-agnostic v1-v3 messages |
| `src/scp/test/SCPDporSmokeTests.cpp` | see below, incl. trace-version tests bumped alongside each version change |
| `src/scp/test/DporScpInvestigationMain.cpp` | help text: `--txset-status` (`:290`), `--download-time` (`:285`), `--download-succeeds-in-round` |
| `docs/dpor-replay-notes.md` | `:166` lists "pending txset wait-time eligibility from prior `downloading` results" — the removed counter; replace with the pending-success set. Also `:57` ("Trace bundles use schema version 4") and `:181` ("Loading a version-4 bundle") must track each bump |
| `docs/dpor-integration-status.md` | `:394` ("JSON version-4 round-trips") and `:395-396` ("rejection of ... version-1 through version-3") must track each bump; plus the new choice granularity and the §3.5 carve-out as a known wart |
| `src/scp/test/bench-dpor.sh` | no change; re-capture fingerprint |

No production SCP files change. No build-system change.

### Smoke tests

- `SCPDporSmokeTests.cpp:1714` "latches txset status once a value is resolved" —
  `:1758-1763` asserts a re-branch on the second call. Split into same-event
  (now latched) and next-event (still branches), using explicit event guards.
- `:1766` "can model eventual valid txset resolution" — `:1794-1796` likewise.
- `:1562` "latches txset wait-time once a value times out" — add a same-event
  repeat assertion; note this test uses the deterministic status gate
  (`mTxSetStatus = Downloading`, `mNondeterministicTxSetStatus` false).
- `:1843` "download-succeeds-in-round forces later txset validation valid" —
  `:1868-1872` calls `emitEnvelope` then expects `validateValue` to return
  `kFullyValidatedValue` immediately. Under §3.4 that must move to the next
  event; wrap in explicit guards.
- `:1889` "replay reuses a latched txset status" — the double `validateValue`
  at `:1917-1918` is inside one timer callback and should now need one trace
  entry; `mConsumedTraceEntries` stays 2.
- New: one `receiveEnvelope` that previously produced ≥2 status choices for one
  value now produces exactly 1 (count `TxSetStatusChoiceRequired` throws).
- New: counter-leak case — validate a value twice, then query the wait time
  twice in one event; both queries return the same answer rather than the
  second reporting "no download in progress".
- New: the §3.5 carve-out — with the override on, nomination returns
  `Downloading` and a balloting call in the same event may still choose `Valid`.
- New: wait-before-validation. In one event, query the wait time for a value
  with no recorded status (expect `nullopt`), then `validateValue` choosing
  `Downloading`, then query the wait time again. The second query must return
  `nullopt` from the memo rather than opening a branch. Without the
  gated-`nullopt` memoization in §3.3 step 3 this test fails, and nothing else
  in the suite catches it.
- New: superseded bundles are rejected. Because each bump must leave its own
  commit self-consistent, the test moves with it — commit 2 asserts v4 is
  rejected and v5 loads; commit 3 asserts **both v4 and v5** are rejected and v6
  loads. Final state: current version 6, two rejected predecessors.

The new replay invariants need direct coverage; version rejection does not
exercise any of them, since a bundle can carry the current version and still
violate them:

- **Deferred success survives a snapshot** (commit 2). Arm
  `--download-succeeds-in-round`, emit the triggering PREPARE, snapshot while
  the promotion is still pending, restore, then open the next event and assert
  the value is now treated as downloaded. This is the only test that covers the
  new `ReplayBaseline` field; without it the field can be dropped and every
  other test still passes.
- **Snapshot/restore inside an event is rejected** (commit 2). Open an explicit
  guard, call `snapshotReplayBaseline` and `restoreReplayBaseline`, expect
  `std::logic_error` from each.
- **Snapshot after an implicit choice is rejected** (commit 3). Call
  `validateValue` outside any guard so the memo is populated at depth 0, then
  expect `snapshotReplayBaseline` to throw. This is the check that catches the
  silent-memo-loss hole, and it is invisible to the depth check alone.
- **A well-formed v6 bundle with a leftover choice is rejected** (commit 3).
  Take a valid trace, append one extra `txset_status` entry to an event that
  now needs only one, and expect the queue-consumption `std::logic_error` —
  not a version error. This is the desynchronization case the version bump
  cannot catch, because the bundle is current and structurally valid.

## Part 6 — Validation

### Fingerprint split

Of the 13 `bench-dpor.sh check` scenarios, 7 use only deterministic tx-set modes
and **must stay byte-identical**; 6 use `downloading-then-valid` and/or `nondet`
and are expected to move. Baseline on `b784d2f25`:

| must not move | baseline |
|---|---|
| C2 | `executions=1304 full=1009 blocked=295 error=0 depth-limit=0` |
| C4 | `executions=16 full=12 blocked=4 error=0 depth-limit=0` |
| C5 | `executions=128750 full=128750 blocked=0 error=0 depth-limit=0` |
| C7 | `executions=217791 full=11019 blocked=144 error=0 depth-limit=206628` |
| C8 | `executions=1304 full=1009 blocked=295 error=0 depth-limit=0` |
| C9 | `executions=16 full=12 blocked=4 error=0 depth-limit=0` |
| CD | `executions=306003 full=25771 blocked=0 error=0 depth-limit=280232` |

| expected to move | baseline |
|---|---|
| C1 | `executions=1336 full=1092 blocked=244 error=0 depth-limit=0` |
| C3 | `executions=704 full=552 blocked=152 error=0 depth-limit=0` |
| C6 | `executions=10954 full=10614 blocked=340 error=0 depth-limit=0` |
| CA | `executions=704 full=552 blocked=152 error=0 depth-limit=0` |
| CB | `executions=90530 full=0 blocked=0 error=0 depth-limit=90530` |
| CC | `executions=90208 full=9 blocked=0 error=0 depth-limit=90199` |

C4 is the sharpest of the seven: `always-downloading` + `above` exercises the
downloading path end to end with no choices at all, so it isolates the counter
removal from the memoization. CA additionally moves for the §3.4 deferral, so
it is the one scenario where two independent changes overlap — land them in
separate commits (Part 8) so each delta is attributable.

### Targeted behavioral assertions

Aggregate counts cannot show behavior preservation: a nonzero `blocked=` could
come from an unrelated blocking route, and removing impossible duplicate
branches can legitimately lower `full=`. So assert the specific behaviors
directly, each as a scenario that must still be reachable:

1. **Timeout replacement.** A wait ≥ timeout leads to an empty-tx-set value
   being proposed. Assert an emitted ballot value equals
   `makeEmptyTxSetValueFromValue(v)` — the pattern already used at
   `SCPDporSmokeTests.cpp:1556`. Also reachable at scenario level via C4.
2. **Download blocking — at the commit boundary, not prepare.** The prepare
   boundary does not discriminate: measured on `b784d2f25`,
   `--nodes 3 --fifo --txset-status always-downloading --stop-on-prepare
   --depth 200` gives `executions=16 full=12 blocked=4` for **both** `below`
   and `above`, because the run stops before full validation matters. Use
   `--stop-on-commit --depth 60`, where they separate cleanly:

   | `--download-time` | measured on `b784d2f25` |
   |---|---|
   | `below` | `executions=35904 full=0 blocked=8613 error=0 depth-limit=27291` |
   | `above` | `executions=26409 full=12760 blocked=0 error=0 depth-limit=13649` |

   `below` must keep `full=0` with a large `blocked=`, and `above` must keep
   `blocked=0` with a large `full=`. That pair is the real assertion: a node
   that never times out stalls, and one that always times out replaces the tx
   set and proceeds. Note the `CLAUDE.md` guidance that
   `--fail-on-first-blocked --download-time above` needs `--depth 18`, not 12,
   applies to **`--stop-on-prepare`**; it does not transfer to the commit
   boundary used here, where that configuration has no blocked executions at
   all (`blocked=0` above) and so has nothing for it to capture.
3. **Eventual validity — as a smoke test, not a trace check.** A tx-set choice
   value carries only slot and status, never the affected `Value`
   (`makeTxSetStatusChoiceValue`, `ScpDporBridge.h:62`), which the captured
   trace in Part 2 confirms. So "a `downloading` choice followed by a `valid`
   choice on the same node" cannot establish that both concerned the same
   value. Assert it directly instead: a smoke test that takes one value
   `Downloading` in event N and `Valid` in event N+1, and a scenario-level
   check that C1/C6 keep `full=` > 0.
4. **Per-event choice count.** Smoke test: drive one `receiveEnvelope` that
   previously produced 3 status choices and assert it now produces 1 per
   distinct value.
5. **Blocked routes are the same routes.** For C1 and C3, capture a blocked
   execution before and after and confirm the blocking receive is at the same
   protocol point, rather than only comparing `blocked=` counts.

### Other gates

- `--must-externalize` and `--check-agreement` on C1 and C6, checking the
  `blocked=` count before trusting a pass (`--must-externalize` only checks
  quiesced runs).
- Replay round-trip: capture with `--fail-on-first-terminal --trace-dir`, then
  `--replay-trace-json PATH --replay-node all`. Confirm the bundle reports
  version 6 and that saved v4 and v5 bundles are both rejected.
- Throughput: old and new back to back in one session, median of several runs,
  noise floor established first with a copy of the baseline binary
  (`CLAUDE.md`). Prefer terminating scenarios (C1, C3, C6, CA) over `bench head`.
  Expected: real speedup on the six, no measurable change on the seven.
- `stellar-core-dpor-tests "[scp][dpor][smoke]"` green; `stellar-core`
  unaffected (no production file changes).

## Part 7 — Risks and open questions

1. **Coverage loss is the real risk, not correctness.** Mitigated by the
   targeted assertions above rather than by aggregate counts. If a behavior does
   disappear, the right response is to add it back as an explicit event, not to
   restore per-call branching.
2. **Is a mid-handler flip ever real?** Part 1 argues no for `validateValue`
   on the current `SCPDriver` surface, and "unlikely but possible" for the wait
   time. It would become reachable if a future callback synchronously drained
   overlay work. Put a comment at the memo site so a later change trips over the
   assumption.
3. **The §3.5 carve-out is a known unfaithfulness** that this change documents
   rather than fixes. It predates the change.
4. **Follow-up, out of scope.** Model tx-set availability as its own external
   event source per (node, value) — a transition DPOR can commute against
   unrelated deliveries — instead of a choice raised from inside a callback,
   which can never be commuted. This plan is a prerequisite, not a substitute:
   it establishes that a handler observes one consistent snapshot.
5. **Deterministic-mode drift.** Per-event advance of
   `mTxSetDownloadWaitTimeCallCountsByValue` changes multi-entry configured
   sequences. Only tests reach it; C4 pins the single-entry case.

## Part 8 — Sequencing

Four commits. Each must be independently verifiable *and* internally
self-consistent — a commit that changes user-visible semantics or the trace
schema carries its own help text and schema documentation. Only cross-cutting
results wait for the end.

1. **Counter removal.** Replace `mPendingTxSetDownloadStatusCounts` with a read
   of `mLastTxSetStatusByValue` — **not** the event decision, which does not
   exist until commit 3. Precisely: in nondeterministic-status mode,
   `getTxSetDownloadWaitTime` returns `nullopt` unless
   `mLastTxSetStatusByValue` holds `Downloading` for the value; no entry means
   no download in progress, matching today's "count absent → `nullopt`". All 13
   fingerprint lines unchanged, C4 especially.
   Docs: `docs/dpor-replay-notes.md:166`, which describes the removed counter
   as part of the baseline contents and is wrong the moment this lands.
2. **Event guard + deferred download success** (§3.1 guard half, §3.4). The
   guard must land here, not in commit 3: deferred success is promoted by the
   guard, so the two cannot be separated. Includes the RAII type (non-copyable,
   non-movable), entry-point wrapping, the public test scope, the two
   event-depth checks, and the two commit-2 replay tests.
   Trace version 4 → 5, with the v4 rejection message and the version-agnostic
   rewrite of the v1-v3 messages. Docs: `--download-succeeds-in-round` help
   text ("from the next event onward"), the replay-notes description of the new
   pending-success baseline field, and the version references that go stale on
   this bump — `docs/dpor-replay-notes.md:57`, `:181` and
   `docs/dpor-integration-status.md:394-396`. Only CA moves; record the delta.
3. **Per-event memoization** (§3.1 map half, §3.2, §3.3, §3.5). The event
   decision map on top of commit 2's guard, the map-empty snapshot check and
   the smoke-test restructuring it forces, `hasUnconsumedTxSetChoices` and the
   queue-consumption check, and the two commit-3 replay tests. Trace version
   5 → 6. Docs: `--txset-status` / `--download-time` help text, the §3.5
   carve-out recorded as a known wart, and the same version references bumped
   again. All six nondeterministic fingerprint lines may move here, CA
   included — it takes a second, independent delta on top of commit 2's, so
   record the two separately rather than reporting one combined change.
4. **Results and summary only.** Refreshed `bench-dpor.sh check` fingerprint,
   throughput measurements, and the `docs/dpor-integration-status.md` summary
   of the new choice granularity. Nothing here is needed to make commits 1-3
   coherent on their own.

## Review disposition

Revision 2 responds to the design review of revision 1. All six findings were
confirmed against the code and accepted.

| finding | disposition |
|---|---|
| High — nomination override breaks the invariant (`NominationProtocol.cpp:521`) | Accepted, narrowed rather than memoized: §3.0 + §3.5, with the rationale that memoizing would defeat C1/C6/CB/CC. Verified the harness's default `combineCandidates` returns a candidate verbatim, so it is a same-value conflict. |
| High — mid-event download success | Accepted, deferred to the next event: §3.4. Also added the `ReplayBaseline` field the deferral requires. |
| High — v4 replay bundles break silently | Accepted: version bump to 5 with explicit v4 rejection, Part 4; trace JSON files and `docs/dpor-replay-notes.md:166` added to Part 5. |
| Medium — event state survives the event | Accepted: clear on outermost exit too, and a public guard type for tests, §3.1. |
| Medium — wait query does not pin status | Accepted: fallback writes into the event decision, §3.3 step 3, with a note that the path should be unreachable today. |
| Medium — Part 1 overstates production equivalence | Accepted: `kStructurallyValidValue` has two sources (`HerderSCPDriver.cpp:481`); production timeout is 5000 ms (`Config.cpp:260`) vs the model's 1000 ms; wait-time pinning reframed as an abstraction, not a soundness correction. |
| Medium — aggregate counts do not prove preservation | Accepted: five targeted behavioral assertions, Part 6. |

Revision 3 responds to the second review. All five findings confirmed and
accepted.

| finding | disposition |
|---|---|
| Medium — snapshots need an enforced event-boundary contract | Accepted: `snapshotReplayBaseline` asserts depth 0 **and** an empty memo, `restoreReplayBaseline` asserts depth 0, guard is non-copyable and non-movable (§3.1). Part 4 now states that the asserts and the omitted `ReplayBaseline` field ship together. Identified the smoke tests this forces to restructure (`SCPDporSmokeTests.cpp:1738-1739`, `:1756-1757`). |
| Medium — production `validateValue` invariant too broad | Accepted: new Part 1 subsection. Verified `Upgrades::isValid` gates `isValidForNomination` on the flag (`Upgrades.cpp:698-702`) and that a dropped upgrade forces `kInvalidValue` (`HerderSCPDriver.cpp:612-619`). Invariant restated over identical `(value, nomination)` plus a stable tx-set-derived component. `Value`-only keying justified by `hasUpgrades` returning `false` and `stripAllUpgrades` being the identity, with the future constraint noted. |
| Medium — commits leave incompatible trace versions | Accepted, two bumps rather than merging the commits: v5 in commit 2, v6 in commit 3, with the rationale that merging would collapse the CA delta. Also fixes the stale v1-v3 messages that say "capture a version 4 trace". |
| Medium — two validation checks not discriminating | Accepted, both measured on `b784d2f25`. Prepare boundary gives `16/12/4` for both `below` and `above`; `--stop-on-commit --depth 60` separates them (`full=0 blocked=8613` vs `full=12760 blocked=0`), and those figures are now the gate. Eventual validity moved to a direct same-value smoke test, since `makeTxSetStatusChoiceValue` (`ScpDporBridge.h:62`) records no `Value`. |
| Low — debug recording for memoized `nullopt` | Accepted: record only when a wait time exists, matching today's `recordWaitTime`. Confirmed the formatter dereferences `event.mWaitTime` unconditionally (`DporScpInvestigationMain.cpp:720`), so this is crash-avoidance, not style. |

Revision 4 responds to the third review. All five findings confirmed and
accepted.

| finding | disposition |
|---|---|
| Medium — commit 2 depends on commit 3's guard | Accepted: the guard, entry-point wrapping, public test scope, snapshot asserts and forced smoke-test restructuring all move to commit 2; commit 3 adds only the decision map and memoization. Noted at the head of §3.1 and in Part 4. |
| Medium — stale version-5 references in the final state | Accepted: files table, smoke tests and replay validation now end at v6. Version tests move with each bump — commit 2 rejects v4, commit 3 rejects v4 and v5. |
| Medium — §3.0 conflates full verdict with tx-set status | Accepted: invariant restricted to non-empty values reaching the modeled path, with the two short-circuiting stages named (`DporScpNode.cpp:862`, `:868-872`). The empty-tx-set phase split is independent of the §3.5 knob and mirrors production. Also corrected the future-upgrade advice: tx-set availability is phase-independent, so the status memo stays keyed on `Value`; upgrade filtering belongs outside it, and only a full-verdict memo would need the phase flag. |
| Low — "mutated only by tx-set arrival" | Accepted: `fetch` creates trackers (`ItemFetcher.cpp:32`) and `stopFetchingOutsideRange` erases them (`:139`). Reworded around serialization and non-re-entrancy rather than a single writer. |
| Low — `--fail-on-first-blocked` depth note | Accepted: stated explicitly that the `--depth 18` guidance is about `--stop-on-prepare` and does not transfer to the commit boundary, which has `blocked=0` for `above`. |

Revision 5 responds to the fourth review. All three findings and the
implementation clarification confirmed and accepted.

| finding | disposition |
|---|---|
| Medium — commit 2 references commit 3 state | Accepted: §3.1 now splits the checks by commit in a table. Commit 2 gets the two event-depth checks; the map-empty check and the smoke-test restructuring it forces move to commit 3, alongside the map itself. Part 4 and Part 8 updated to match. |
| Medium — new replay invariants need direct tests | Accepted: four tests added to Part 5, each assigned to its commit — deferred success surviving a snapshot (the only coverage of the new `ReplayBaseline` field), snapshot/restore inside an event, snapshot after an implicit choice, and a well-formed v6 bundle carrying a leftover choice. Noted why version rejection cannot substitute: such a bundle is current and structurally valid. |
| Medium — per-commit docs postponed to commit 4 | Accepted: help text and schema documentation move into the commits that change the behavior they describe. `docs/dpor-replay-notes.md:166` moves to commit 1, since the counter it describes disappears there. Commit 4 keeps only the refreshed fingerprint, throughput results, and the integration-status summary. |
| Clarification (rev 5) — throw rather than assert; queues are private | Accepted, and generalized: **all** the new checks throw `std::logic_error`, because neither `DporScpNode.cpp` nor `ScpDporReplaySupport.cpp` uses `releaseAssert` or `assert` anywhere today — every existing invariant in them is a throw. Confirmed `DporScpNode` declares no `friend` and the queues and indices are private (`DporScpNode.h:386-394`); the plan now names a minimal public `bool hasUnconsumedTxSetChoices() const` instead of exposing indices or granting friendship. |

Revision 6 responds to the fifth review. All five findings confirmed and
accepted.

| finding | disposition |
|---|---|
| Medium — gate-produced `nullopt` not memoized | Accepted: §3.3 step 3 now requires **every** gated `nullopt` return to set `mWaitTimeDecided` with an empty `mWaitTime`, explicitly including the no-history case where there is no status to memoize — the gap memoizing the status fallback alone leaves open. New wait-before-validation test in Part 5, noted as the only thing in the suite that catches it. |
| Medium — current-status docs cannot wait for commit 4 | Accepted: `docs/dpor-integration-status.md:394-396` and `docs/dpor-replay-notes.md:57`, `:181` carry explicit version references and now track each bump in commits 2 and 3. Added to the files table and both commit descriptions. |
| Low — Part 4 contradicts the corrected snapshot split | Accepted: paragraph rewritten. The decisive map-empty check lands with the map in commit 3; commit 2's depth checks are the weaker half and cannot catch a depth-0 snapshot during an implicit event. "Assertion" replaced with "runtime check" in the files table and the version table, consistent with everything throwing. |
| Low — commit 1's transitional algorithm underspecified | Accepted: commit 1 reads `mLastTxSetStatusByValue`, not the event decision, which does not exist yet. No entry means no download in progress, matching today's "count absent → `nullopt`". |
| Low — CA may move in both semantic commits | Accepted: commit 3 now says all six nondeterministic lines may move, with CA taking a second independent delta to be recorded separately rather than combined. |

## Implementation notes

Landed as four commits on `dpor-on-master`, in the order Part 8 specified. Two
predictions did not survive measurement, and one detail was underspecified.

**Commit 2 moved nothing, not just CA.** Part 8 expected the §3.4 deferral to
shift CA. It shifts nothing: `--stop-on-prepare` makes the boundary the very
`PREPARE` at counter 1 that also marks the download succeeded, so the thread
stops and CA never validates again. CA's baseline is identical to C3's for that
reason — the flag is inert in that scenario. At the commit boundary, where
`--download-succeeds-in-round 1` does change behavior (33569 executions with
the flag versus 36624 without, at `--stop-on-commit --depth 46`), the deferral
is also byte-identical, because SCP validates before it emits. The mid-event
flip the deferral removes is unreachable in the modeled scenarios today rather
than merely unobserved; the smoke tests pin it at unit level.

The version 4 → 5 bump was kept anyway. It guards a real semantics change
against traces captured under the old one, and "unobservable in the
configurations measured" is not "unobservable". Its message says *may* replay
differently rather than *does*.

**CA takes its whole delta in commit 3**, 704 → 250, identical to C3's, for the
same reason.

**The choice-count test needed a different event.** Part 5 asked for a
`receiveEnvelope` that previously produced three status choices. A peer
`PREPARE` delivered to a node that has already balloted produces exactly one
before and after, because `BallotProtocol::processEnvelope` gates on the first
verdict and a `downloading` verdict stops the ballot paths that would validate
again. The event that does exercise it is `nominate` with a threshold-1 quorum
set, which drives straight into balloting: measured at **7** status choices
with the per-event decision bypassed, and 1 with it in place. A node that has
never nominated is a bad fixture here for an unrelated reason — the ballot
protocol then validates an empty `Value`, which the model treats as a second,
distinct download.

Deterministic scenarios show no measurable throughput change (1.01x, 1.03x,
1.01x, 0.91x for C5, C7, CD, C4, against a 0.91x-1.06x identical-binary control
band). The per-event decision adds a map lookup per driver call and saves
nothing where nothing branches, so that is the expected result rather than a
null finding.
