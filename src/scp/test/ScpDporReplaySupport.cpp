// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/ScpDporReplaySupport.h"

#include <vector>

namespace stellar::scpdpor
{

namespace
{

struct ReplayStateCacheEntry
{
    ScpDporReplaySupport const* mSupport{};
    std::size_t mNodeIndex{};
    std::unique_ptr<DporScpNode> mNode;
};

std::vector<ReplayStateCacheEntry>&
threadLocalReplayStateCache()
{
    static thread_local std::vector<ReplayStateCacheEntry> cache;
    return cache;
}

void
enqueueTxSetDownloadWaitTimeChoices(
    DporScpNode& node,
    std::vector<std::chrono::milliseconds> const& waitTimes)
{
    for (auto const& waitTime : waitTimes)
    {
        node.enqueueTxSetDownloadWaitTimeChoice(waitTime);
    }
}

std::vector<std::chrono::milliseconds>
decodeKnownTxSetDownloadWaitTimeChoices(ThreadTrace const& trace,
                                        std::size_t observedIndex)
{
    std::vector<std::chrono::milliseconds> waitTimes;
    for (std::size_t choiceIndex = observedIndex + 1; choiceIndex < trace.size();
         ++choiceIndex)
    {
        auto const& choiceObserved = trace.at(choiceIndex);
        if (choiceObserved.is_bottom())
        {
            break;
        }

        auto const& choiceValue = choiceObserved.value();
        if (!isTxSetDownloadWaitTimeChoiceValue(choiceValue))
        {
            break;
        }

        waitTimes.push_back(decodeTxSetDownloadWaitTimeChoice(choiceValue));
    }
    return waitTimes;
}

} // namespace

ScpDporReplaySupport::ScpDporReplaySupport(
    std::vector<SecretKey> validators, SCPQuorumSet qSet, uint64_t slotIndex,
    Value previousValue, std::vector<Value> initialValues,
    DporScpNode::Configuration config)
    : mValidators(std::move(validators))
    , mQSet(std::move(qSet))
    , mSlotIndex(slotIndex)
    , mPreviousValue(std::move(previousValue))
    , mInitialValues(std::move(initialValues))
    , mConfig(std::move(config))
{
    if (mValidators.empty())
    {
        throw std::invalid_argument("validators must not be empty");
    }
    if (mValidators.size() != mInitialValues.size())
    {
        throw std::invalid_argument(
            "initialValues must match validator count");
    }
    rebuildBaselines();
}

std::size_t
ScpDporReplaySupport::size() const
{
    return mValidators.size();
}

ScpDporReplaySupport::NodeBaseline const&
ScpDporReplaySupport::getNodeBaseline(std::size_t nodeIndex) const
{
    return mReplayBaselines.at(nodeIndex);
}

DporScpNode&
ScpDporReplaySupport::acquireNode(std::size_t nodeIndex) const
{
    auto& cache = threadLocalReplayStateCache();
    for (auto& entry : cache)
    {
        if (entry.mSupport == this && entry.mNodeIndex == nodeIndex)
        {
            return *entry.mNode;
        }
    }

    cache.push_back(ReplayStateCacheEntry{
        this, nodeIndex,
        std::make_unique<DporScpNode>(mValidators.at(nodeIndex), mQSet, mConfig)});
    return *cache.back().mNode;
}

void
ScpDporReplaySupport::clearThreadLocalCacheForCurrentThread()
{
    threadLocalReplayStateCache().clear();
}

void
ScpDporReplaySupport::restoreBaseline(DporScpNode& node,
                                      std::size_t nodeIndex) const
{
    restoreNodeBaseline(node, nodeIndex,
                        mReplayBaselines.at(nodeIndex).mNodeState);
}

ScpDporReplaySupport::ReplayObservationProgress
ScpDporReplaySupport::replayObservation(DporScpNode& node,
                                        std::size_t nodeIndex,
                                        ThreadTrace const& trace,
                                        std::size_t observedIndex,
                                        std::optional<int> selectedTimerID) const
{
    static_cast<void>(nodeIndex);

    if (observedIndex >= trace.size())
    {
        throw std::out_of_range("observed trace index out of range");
    }

    auto const& observed = trace.at(observedIndex);
    auto const observedBottom = observed.is_bottom();
    auto const chosenWaitTimes =
        decodeKnownTxSetDownloadWaitTimeChoices(trace, observedIndex);

    enqueueTxSetDownloadWaitTimeChoices(node, chosenWaitTimes);
    try
    {
        replayOneObservedValue(node, observed, selectedTimerID);
        return ReplayObservationProgress{
            .mConsumedTraceEntries = 1 + chosenWaitTimes.size(),
            .mConsumedStepCount = chosenWaitTimes.size(),
            .mObservedBottom = observedBottom,
        };
    }
    catch (DporScpNode::TxSetDownloadWaitTimeChoiceRequired const& e)
    {
        auto const choiceIndex = observedIndex + 1 + chosenWaitTimes.size();
        if (choiceIndex < trace.size())
        {
            throw std::logic_error(
                "trace omits a txset wait-time choice before the next observed event");
        }

        return ReplayObservationProgress{
            .mConsumedTraceEntries = 1 + chosenWaitTimes.size(),
            .mConsumedStepCount = chosenWaitTimes.size(),
            .mPendingEvent = makeTxSetDownloadWaitTimeChoiceEvent(e.getChoices()),
            .mObservedBottom = observedBottom,
        };
    }
}

void
ScpDporReplaySupport::initializeNode(DporScpNode& node,
                                     std::size_t nodeIndex) const
{
    node.nominate(mSlotIndex, mInitialValues.at(nodeIndex), mPreviousValue);
}

void
ScpDporReplaySupport::restoreNodeBaseline(
    DporScpNode& node, std::size_t nodeIndex,
    DporScpNode::ReplayBaseline const& baseline) const
{
    node.restoreReplayBaseline(baseline);
    for (auto const& timer : baseline.mTimers)
    {
        switch (timer.mTimerID)
        {
        case Slot::NOMINATION_TIMER:
            node.installNominationReplayTimer(timer.mSlotIndex, timer.mTimeout,
                                              mInitialValues.at(nodeIndex),
                                              mPreviousValue);
            break;
        case Slot::BALLOT_PROTOCOL_TIMER:
            node.installBallotingReplayTimer(timer.mSlotIndex, timer.mTimeout);
            break;
        default:
            throw std::logic_error("unknown replay timer id");
        }
    }
}

void
ScpDporReplaySupport::replayOneObservedValue(
    DporScpNode& node, ObservedValue const& observed,
    std::optional<int> selectedTimerID) const
{
    if (observed.is_bottom())
    {
        if (!selectedTimerID)
        {
            throw std::logic_error(
                "trace requested bottom without a selected timer");
        }
        if (!node.fireTimer(mSlotIndex, *selectedTimerID))
        {
            throw std::logic_error(
                "trace requested a timer firing without an active timer");
        }
        return;
    }

    auto const& value = observed.value();
    if (!isEnvelopeValue(value))
    {
        throw std::logic_error(
            "replay expected an SCP envelope delivery value");
    }
    if (value.mSlotIndex != mSlotIndex)
    {
        throw std::logic_error("trace delivered an envelope for the wrong slot");
    }
    node.receiveEnvelope(decodeEnvelope(value));
}

EventLabel
ScpDporReplaySupport::makeTxSetDownloadWaitTimeChoiceEvent(
    std::vector<std::chrono::milliseconds> const& waitTimes) const
{
    std::vector<ScpDporValue> choices;
    choices.reserve(waitTimes.size());
    for (auto const& waitTime : waitTimes)
    {
        choices.push_back(
            makeTxSetDownloadWaitTimeChoiceValue(mSlotIndex, waitTime));
    }
    if (choices.empty())
    {
        throw std::logic_error("txset wait-time choices must not be empty");
    }

    return EventLabel{NondeterministicChoiceLabel{.value = choices.front(),
                                                  .choices = std::move(choices)}};
}

void
ScpDporReplaySupport::rebuildBaselines()
{
    std::vector<NodeBaseline> replayBaselines;
    replayBaselines.reserve(mValidators.size());

    for (std::size_t nodeIndex = 0; nodeIndex < mValidators.size();
         ++nodeIndex)
    {
        DporScpNode node(mValidators.at(nodeIndex), mQSet, mConfig);
        initializeNode(node, nodeIndex);

        NodeBaseline baseline;
        baseline.mInitialPendingEnvelopes = node.takePendingEnvelopes();
        baseline.mNodeState = node.snapshotReplayBaseline(mSlotIndex);
        replayBaselines.push_back(std::move(baseline));
    }

    mReplayBaselines = std::move(replayBaselines);
}

} // namespace stellar::scpdpor
