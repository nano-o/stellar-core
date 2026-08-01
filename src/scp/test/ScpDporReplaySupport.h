// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "scp/test/DporScpNode.h"
#include "scp/test/ScpDporBridge.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace stellar::scpdpor
{

class ScpDporReplaySupport
{
  public:
    // Partially replayed nodes retained per validator and worker thread.
    // Depth-first backtracking makes a modest cache effective, while a larger
    // cache increases the linear prefix scan on every acquire. The
    // investigation runner exposes this default for workload-specific sweeps.
    static constexpr std::size_t DEFAULT_REPLAY_SLOTS_PER_NODE = 64;

    struct NodeBaseline
    {
        DporScpNode::ReplayBaseline mNodeState;
        std::vector<SCPEnvelope> mInitialPendingEnvelopes;
    };

    struct ReplayObservationProgress
    {
        std::size_t mConsumedTraceEntries{0};
        std::size_t mConsumedStepCount{0};
        std::optional<EventLabel> mPendingEvent;
        bool mObservedBottom{false};
    };

    // DPOR asks a thread function for event `step` given the whole trace, so a
    // naive scenario replays the trace from the baseline on every call, which
    // is quadratic in the trace length and dominates exploration cost. The
    // cursor lets a caller resume an already-replayed prefix instead: it
    // records the trace entries the cached node has consumed together with the
    // scenario-side loop state, so a call whose trace extends that prefix
    // continues from where the previous call stopped. `mLabel` additionally
    // memoizes the answer for the exact step the previous call stopped at,
    // which is the common case when DPOR polls the other threads.
    //
    // `mValid` is the single authority: it is true only when the cached node's
    // state is exactly "baseline plus mConsumedTrace" and the loop state below
    // matches. Any partial replay (a required nondeterministic choice, or a
    // thrown replay error) must leave it false.
    struct ReplayCursor
    {
        bool mValid{false};
        std::vector<ObservedValue> mConsumedTrace;
        std::vector<SendLabel> mPendingSends;
        std::size_t mNextPendingSend{0};
        std::size_t mEventCount{0};
        std::optional<int> mSelectedTimerID;
        std::optional<EventLabel> mLabel;

        void
        consume(ObservedValue const& observed)
        {
            mConsumedTrace.push_back(observed);
        }

        void
        reset(std::vector<SendLabel> const& initialPendingSends)
        {
            mValid = false;
            mConsumedTrace.clear();
            mPendingSends = initialPendingSends;
            mNextPendingSend = 0;
            mEventCount = 0;
            mSelectedTimerID.reset();
            mLabel.reset();
        }
    };


    struct ReplayState
    {
        DporScpNode& mNode;
        ReplayCursor& mCursor;
    };

    ScpDporReplaySupport(std::vector<SecretKey> validators, SCPQuorumSet qSet,
                         uint64_t slotIndex, Value previousValue,
                         std::vector<Value> initialValues,
                         DporScpNode::Configuration config = {},
                         std::size_t replaySlotsPerNode =
                             DEFAULT_REPLAY_SLOTS_PER_NODE);

    // Copies get a fresh generation so they never adopt thread-local cached
    // nodes that were created for the source object.
    ScpDporReplaySupport(ScpDporReplaySupport const& other);

    ScpDporReplaySupport&
    operator=(ScpDporReplaySupport const&) = delete;

    std::size_t
    size() const;

    NodeBaseline const&
    getNodeBaseline(std::size_t nodeIndex) const;

    DporScpNode&
    acquireNode(std::size_t nodeIndex) const;

    // Picks the cached node whose already-replayed prefix best matches
    // `trace`: the longest valid prefix that `trace` extends and that has not
    // yet passed `step`. Exploration is depth-first with backtracking, so
    // keeping several partially-replayed nodes per validator lets a call that
    // follows a rollback resume from a shared ancestor prefix instead of
    // replaying from the baseline. When nothing matches, the
    // least-recently-used node is returned with an invalid cursor and the
    // caller is expected to restore the baseline into it.
    ReplayState
    acquireReplayState(std::size_t nodeIndex, ThreadTrace const& trace,
                       std::size_t step) const;

    static void
    clearThreadLocalCacheForCurrentThread();

    void
    restoreBaseline(DporScpNode& node, std::size_t nodeIndex) const;

    ReplayObservationProgress
    replayObservation(DporScpNode& node, std::size_t nodeIndex,
                      ThreadTrace const& trace, std::size_t observedIndex,
                      std::optional<int> selectedTimerID) const;

  private:
    void
    initializeNode(DporScpNode& node, std::size_t nodeIndex) const;

    void
    restoreNodeBaseline(DporScpNode& node, std::size_t nodeIndex,
                        DporScpNode::ReplayBaseline const& baseline) const;

    void
    replayOneObservedValue(DporScpNode& node, ObservedValue const& observed,
                           std::optional<int> selectedTimerID) const;

    EventLabel
    makeTxSetStatusChoiceEvent(
        std::vector<DporScpTxSetStatus> const& statuses) const;

    EventLabel
    makeTxSetDownloadWaitTimeChoiceEvent(
        std::vector<std::chrono::milliseconds> const& waitTimes) const;

    void
    rebuildBaselines();

    std::vector<SecretKey> mValidators;
    SCPQuorumSet mQSet;
    uint64_t mSlotIndex;
    Value mPreviousValue;
    std::vector<Value> mInitialValues;
    DporScpNode::Configuration mConfig;
    std::size_t mReplaySlotsPerNode;
    std::vector<NodeBaseline> mReplayBaselines;
    // Process-unique identity used to key the thread-local node cache; unlike
    // the object's address, it is never reused after destruction.
    uint64_t mGeneration;
};

} // namespace stellar::scpdpor
