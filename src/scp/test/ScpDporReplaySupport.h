// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "scp/test/DporScpNode.h"
#include "scp/test/ScpDporBridge.h"

#include <memory>
#include <optional>
#include <vector>

namespace stellar::scpdpor
{

class ScpDporReplaySupport
{
  public:
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

    ScpDporReplaySupport(std::vector<SecretKey> validators, SCPQuorumSet qSet,
                         uint64_t slotIndex, Value previousValue,
                         std::vector<Value> initialValues,
                         DporScpNode::Configuration config = {});

    std::size_t
    size() const;

    NodeBaseline const&
    getNodeBaseline(std::size_t nodeIndex) const;

    DporScpNode&
    acquireNode(std::size_t nodeIndex) const;

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
    std::vector<NodeBaseline> mReplayBaselines;
};

} // namespace stellar::scpdpor
