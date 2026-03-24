// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/ScpDporReplaySupport.h"

#include <unordered_map>

namespace stellar::scpdpor
{

namespace
{

struct ReplayStateCacheKey
{
    ScpDporReplaySupport const* mSupport{};
    std::size_t mNodeIndex{};

    bool
    operator==(ReplayStateCacheKey const& other) const
    {
        return mSupport == other.mSupport && mNodeIndex == other.mNodeIndex;
    }
};

struct ReplayStateCacheKeyHasher
{
    std::size_t
    operator()(ReplayStateCacheKey const& key) const noexcept
    {
        auto value = std::hash<void const*>{}(key.mSupport);
        value ^= std::hash<std::size_t>{}(key.mNodeIndex) + 0x9e3779b9 +
                 (value << 6) + (value >> 2);
        return value;
    }
};

} // namespace

ScpDporReplaySupport::ReplayState::ReplayState(
    SecretKey const& secretKey, SCPQuorumSet const& qSet,
    DporScpNode::Configuration const& config)
    : mNode(secretKey, qSet, config)
{
}

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
    static thread_local std::unordered_map<
        ReplayStateCacheKey, std::unique_ptr<ReplayState>,
        ReplayStateCacheKeyHasher>
        cache;

    ReplayStateCacheKey const key{this, nodeIndex};
    auto it = cache.find(key);
    if (it == cache.end())
    {
        it = cache
                 .emplace(key, std::make_unique<ReplayState>(
                                   mValidators.at(nodeIndex), mQSet, mConfig))
                 .first;
    }
    return it->second->mNode;
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
    if (observedIndex >= trace.size())
    {
        throw std::out_of_range("observed trace index out of range");
    }

    auto const& observed = trace.at(observedIndex);
    auto const observedBottom = observed.is_bottom();
    auto const replayBaseline = node.snapshotReplayBaseline(mSlotIndex);
    std::vector<std::chrono::milliseconds> chosenWaitTimes;

    auto const restoreReplayCheckpoint = [&]() {
        restoreNodeBaseline(node, nodeIndex, replayBaseline);
        for (auto const& waitTime : chosenWaitTimes)
        {
            node.enqueueTxSetDownloadWaitTimeChoice(waitTime);
        }
    };

    while (true)
    {
        restoreReplayCheckpoint();
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
            auto const choiceIndex =
                observedIndex + 1 + chosenWaitTimes.size();
            if (choiceIndex >= trace.size())
            {
                return ReplayObservationProgress{
                    .mConsumedTraceEntries = 1 + chosenWaitTimes.size(),
                    .mConsumedStepCount = chosenWaitTimes.size(),
                    .mPendingEvent =
                        makeTxSetDownloadWaitTimeChoiceEvent(e.getChoices()),
                    .mObservedBottom = observedBottom,
                };
            }

            auto const& choiceObserved = trace.at(choiceIndex);
            if (choiceObserved.is_bottom())
            {
                throw std::logic_error(
                    "trace contains bottom where a txset wait-time choice was required");
            }

            auto const& choiceValue = choiceObserved.value();
            if (!isTxSetDownloadWaitTimeChoiceValue(choiceValue))
            {
                throw std::logic_error(
                    "trace entry is not a txset wait-time choice");
            }

            auto const waitTime = decodeTxSetDownloadWaitTimeChoice(choiceValue);
            if (std::find(e.getChoices().begin(), e.getChoices().end(),
                          waitTime) == e.getChoices().end())
            {
                throw std::logic_error(
                    "trace chose an unsupported txset wait time");
            }

            chosenWaitTimes.push_back(waitTime);
        }
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
