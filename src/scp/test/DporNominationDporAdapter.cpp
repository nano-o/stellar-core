// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationDporAdapter.h"

#include "scp/Slot.h"

#include <limits>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace stellar
{

namespace
{

using ThreadId = dpor::model::ThreadId;

ThreadId
toThreadID(std::size_t nodeIndex)
{
    if (nodeIndex > std::numeric_limits<ThreadId>::max())
    {
        throw std::out_of_range("node index does not fit in DPOR thread id");
    }
    return static_cast<ThreadId>(nodeIndex);
}

DporNominationDporAdapter::ReceiveLabel
makeReceiveLabel(ThreadId destinationThread, bool nonBlocking)
{
    auto matcher = [destinationThread](DporNominationValue const& value) {
        return value.mDestinationThread == destinationThread;
    };

    if (nonBlocking)
    {
        return dpor::model::make_nonblocking_receive_label<DporNominationValue>(
            std::move(matcher));
    }
    return dpor::model::make_receive_label<DporNominationValue>(
        std::move(matcher));
}

void
updateMax(std::atomic<std::uint64_t>& target, std::uint64_t value)
{
    auto current = target.load(std::memory_order_relaxed);
    while (current < value &&
           !target.compare_exchange_weak(current, value,
                                         std::memory_order_relaxed))
    {
    }
}

struct ReplayStateCacheKey
{
    DporNominationDporAdapter const* mAdapter{};
    std::size_t mNodeIndex{};
    std::size_t mGeneration{};

    bool
    operator==(ReplayStateCacheKey const& other) const = default;
};

struct ReplayStateCacheKeyHasher
{
    std::size_t
    operator()(ReplayStateCacheKey const& key) const noexcept
    {
        auto value = std::hash<void const*>{}(key.mAdapter);
        value ^= std::hash<std::size_t>{}(key.mNodeIndex) + 0x9e3779b9 +
                 (value << 6) + (value >> 2);
        value ^= std::hash<std::size_t>{}(key.mGeneration) + 0x9e3779b9 +
                 (value << 6) + (value >> 2);
        return value;
    }
};

}

DporNominationDporAdapter::ReplayState::ReplayState(SecretKey const& secretKey,
                                                    SCPQuorumSet const& qSet,
                                                    DporNominationNode::
                                                        Configuration const&
                                                            config)
    : mNode(secretKey, qSet, config)
{
}

DporNominationDporAdapter::DporNominationDporAdapter(
    std::vector<SecretKey> const& validators, SCPQuorumSet const& qSet,
    uint64_t slotIndex, Value const& previousValue,
    std::vector<Value> const& initialValues,
    DporNominationNode::Configuration const& config,
    InitialStateMode initialStateMode)
    : mValidators(validators)
    , mQSet(qSet)
    , mSlotIndex(slotIndex)
    , mPreviousValue(previousValue)
    , mInitialValues(initialValues)
    , mConfig(config)
    , mInitialStateMode(initialStateMode)
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

    rebuildReplayBaselines();
}

std::size_t
DporNominationDporAdapter::size() const
{
    return mValidators.size();
}

ThreadId
DporNominationDporAdapter::toThreadID(std::size_t nodeIndex)
{
    return stellar::toThreadID(nodeIndex);
}

void
DporNominationDporAdapter::setValueHash(
    std::function<uint64(Value const&)> const& fn)
{
    mConfig.mValueHash = fn;
    rebuildReplayBaselines();
}

void
DporNominationDporAdapter::setCombineCandidates(
    std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const&
        fn)
{
    mConfig.mCombineCandidates = fn;
    rebuildReplayBaselines();
}

void
DporNominationDporAdapter::setReplayMetrics(
    std::shared_ptr<ReplayMetrics> metrics)
{
    mReplayMetrics = std::move(metrics);
}

void
DporNominationDporAdapter::setTimeoutModes(bool enableNominationTimeouts,
                                           bool enableBallotingTimeouts)
{
    mEnableNominationTimeouts = enableNominationTimeouts;
    mEnableBallotingTimeouts = enableBallotingTimeouts;
}

std::optional<int>
DporNominationDporAdapter::selectEnabledTimerID(
    DporNominationNode const& node) const
{
    auto hasFirableTimer = [&](int timerID) {
        auto timer = node.getTimer(mSlotIndex, timerID);
        return timer && static_cast<bool>(timer->mCallback);
    };

    auto const nominationTimerEnabled =
        mEnableNominationTimeouts &&
        hasFirableTimer(Slot::NOMINATION_TIMER);
    auto const ballotingTimerEnabled =
        mEnableBallotingTimeouts &&
        hasFirableTimer(Slot::BALLOT_PROTOCOL_TIMER);

    if (nominationTimerEnabled && ballotingTimerEnabled)
    {
        // If both phases are live, follow the more advanced phase.
        return Slot::BALLOT_PROTOCOL_TIMER;
    }

    if (nominationTimerEnabled)
    {
        return Slot::NOMINATION_TIMER;
    }
    if (ballotingTimerEnabled)
    {
        return Slot::BALLOT_PROTOCOL_TIMER;
    }
    return std::nullopt;
}

void
DporNominationDporAdapter::initializeNode(ReplayState& state,
                                          std::size_t nodeIndex) const
{
    auto const& initialValue = mInitialValues.at(nodeIndex);
    switch (mInitialStateMode)
    {
    case InitialStateMode::Nomination:
        state.mNode.nominate(mSlotIndex, initialValue, mPreviousValue);
        break;
    case InitialStateMode::Balloting:
        state.mNode.startBalloting(mSlotIndex, initialValue);
        break;
    }
    queuePendingEnvelopeSends(state, nodeIndex);
}

void
DporNominationDporAdapter::restoreBaseline(ReplayState& state,
                                           std::size_t nodeIndex) const
{
    auto const& baseline = mReplayBaselines.at(nodeIndex);
    state.mNode.restoreReplayBaseline(baseline.mNodeState);
    state.mPendingSends = baseline.mPendingSends;

    for (auto const& timer : baseline.mNodeState.mTimers)
    {
        switch (timer.mTimerID)
        {
        case Slot::NOMINATION_TIMER:
            state.mNode.installNominationReplayTimer(
                timer.mSlotIndex, timer.mTimeout, mInitialValues.at(nodeIndex),
                mPreviousValue);
            break;
        case Slot::BALLOT_PROTOCOL_TIMER:
            state.mNode.installBallotingReplayTimer(timer.mSlotIndex,
                                                    timer.mTimeout);
            break;
        default:
            throw std::logic_error("unknown replay timer id");
        }
    }
}

DporNominationDporAdapter::ReplayState&
DporNominationDporAdapter::acquireReplayState(std::size_t nodeIndex) const
{
    static thread_local std::unordered_map<
        ReplayStateCacheKey, std::unique_ptr<ReplayState>,
        ReplayStateCacheKeyHasher>
        cache;

    ReplayStateCacheKey const key{this, nodeIndex, mReplayCacheGeneration};
    auto it = cache.find(key);
    if (it == cache.end())
    {
        it = cache
                 .emplace(key, std::make_unique<ReplayState>(
                                   mValidators.at(nodeIndex), mQSet, mConfig))
                 .first;
    }
    return *it->second;
}

void
DporNominationDporAdapter::rebuildReplayBaselines()
{
    auto savedReplayMetrics = std::move(mReplayMetrics);
    mReplayMetrics.reset();

    std::vector<ReplayBaseline> replayBaselines;
    replayBaselines.reserve(mValidators.size());
    for (std::size_t nodeIndex = 0; nodeIndex < mValidators.size();
         ++nodeIndex)
    {
        ReplayState state(mValidators.at(nodeIndex), mQSet, mConfig);
        initializeNode(state, nodeIndex);
        replayBaselines.push_back(ReplayBaseline{
            .mNodeState = state.mNode.snapshotReplayBaseline(mSlotIndex),
            .mPendingSends = state.mPendingSends,
        });
    }

    mReplayBaselines = std::move(replayBaselines);
    ++mReplayCacheGeneration;
    mReplayMetrics = std::move(savedReplayMetrics);
}

void
DporNominationDporAdapter::replayObservation(DporNominationNode& node,
                                             std::size_t nodeIndex,
                                             ObservedValue const& observed) const
{
    auto const localThread = toThreadID(nodeIndex);
    if (observed.is_bottom())
    {
        auto const timerID = selectEnabledTimerID(node);
        if (!timerID)
        {
            throw std::logic_error(
                "trace requested a timer firing without an active enabled "
                "timer");
        }
        if (!node.fireTimer(mSlotIndex, *timerID))
        {
            throw std::logic_error(
                "trace requested a timer firing without an active enabled "
                "timer");
        }
        return;
    }

    auto const& delivery = observed.value();
    if (delivery.mDestinationThread != localThread)
    {
        throw std::logic_error(
            "trace delivered an envelope to the wrong thread");
    }
    if (delivery.mSlotIndex != mSlotIndex)
    {
        throw std::logic_error("trace delivered an envelope for the wrong slot");
    }
    node.receiveEnvelope(delivery.mEnvelope);
}

void
DporNominationDporAdapter::discardPendingEnvelopes(DporNominationNode& node) const
{
    static_cast<void>(node.takePendingEnvelopes());
}

void
DporNominationDporAdapter::queuePendingEnvelopeSends(
    ReplayState& state, std::size_t senderIndex) const
{
    auto pendingEnvelopes = state.mNode.takePendingEnvelopes();
    if (mReplayMetrics && !pendingEnvelopes.empty())
    {
        mReplayMetrics->mQueuedNominationEnvelopeCount.fetch_add(
            pendingEnvelopes.size(), std::memory_order_relaxed);
    }

    auto const senderThread = toThreadID(senderIndex);
    for (auto const& envelope : pendingEnvelopes)
    {
        for (std::size_t receiverIndex = 0; receiverIndex < mValidators.size();
             ++receiverIndex)
        {
            if (receiverIndex == senderIndex)
            {
                continue;
            }
            auto const receiverThread = toThreadID(receiverIndex);
            if (mReplayMetrics)
            {
                mReplayMetrics->mQueuedSendCount.fetch_add(
                    1, std::memory_order_relaxed);
            }
            state.mPendingSends.push_back(
                SendLabel{
                    .destination = receiverThread,
                    .value = DporNominationValue{
                        .mSenderThread = senderThread,
                        .mDestinationThread = receiverThread,
                        .mSlotIndex = mSlotIndex,
                        .mEnvelope = envelope,
                    },
                });
        }
    }
}

std::optional<DporNominationDporAdapter::EventLabel>
DporNominationDporAdapter::captureNextEvent(std::size_t nodeIndex,
                                            ThreadTrace const& trace,
                                            std::size_t step) const
{
    if (nodeIndex >= mValidators.size())
    {
        throw std::out_of_range("node index out of range");
    }

    if (mReplayMetrics)
    {
        mReplayMetrics->mCaptureNextEventCalls.fetch_add(
            1, std::memory_order_relaxed);
    }

    auto& state = acquireReplayState(nodeIndex);
    restoreBaseline(state, nodeIndex);

    std::size_t eventCount = 0;
    std::size_t observedCount = 0;
    auto const localThread = toThreadID(nodeIndex);
    auto finish = [&](std::optional<EventLabel> event)
        -> std::optional<EventLabel> {
        recordReplayObservationCount(observedCount);
        return event;
    };

    while (true)
    {
        if (!state.mPendingSends.empty())
        {
            auto nextSend = EventLabel{state.mPendingSends.front()};
            state.mPendingSends.pop_front();
            if (eventCount == step)
            {
                return finish(nextSend);
            }
            ++eventCount;
            continue;
        }

        if (state.mNode.hasCrossedNominationBoundary())
        {
            return finish(std::nullopt);
        }

        auto const enabledTimerID = selectEnabledTimerID(state.mNode);
        auto nextReceive =
            EventLabel{makeReceiveLabel(localThread,
                                        static_cast<bool>(enabledTimerID))};
        if (eventCount == step)
        {
            return finish(nextReceive);
        }
        ++eventCount;

        if (observedCount >= trace.size())
        {
            throw std::logic_error(
                "trace does not contain enough observations to replay the "
                "requested step");
        }

        replayObservation(state.mNode, nodeIndex, trace.at(observedCount));
        ++observedCount;

        queuePendingEnvelopeSends(state, nodeIndex);
    }
}

void
DporNominationDporAdapter::recordReplayObservationCount(
    std::size_t replayedObservationCount) const
{
    if (!mReplayMetrics)
    {
        return;
    }

    auto const count = static_cast<std::uint64_t>(replayedObservationCount);
    mReplayMetrics->mReplayedObservationCountTotal.fetch_add(
        count, std::memory_order_relaxed);
    updateMax(mReplayMetrics->mMaxReplayedObservationCount, count);
}

DporNominationDporAdapter::Program
DporNominationDporAdapter::makeProgram() const
{
    Program program;
    auto self = std::make_shared<DporNominationDporAdapter const>(*this);
    for (std::size_t nodeIndex = 0; nodeIndex < mValidators.size(); ++nodeIndex)
    {
        program.threads[toThreadID(nodeIndex)] =
            [self, nodeIndex](
                ThreadTrace const& trace,
                std::size_t step) -> std::optional<EventLabel> {
            return self->captureNextEvent(nodeIndex, trace, step);
        };
    }
    return program;
}

void
DporNominationDporAdapter::replayTraceForBoundaryInspection(
    ReplayState& state, std::size_t nodeIndex, ThreadTrace const& trace) const
{
    restoreBaseline(state, nodeIndex);
    state.mPendingSends.clear();

    for (std::size_t observedIndex = 0; observedIndex < trace.size();
         ++observedIndex)
    {
        if (state.mNode.hasCrossedNominationBoundary())
        {
            break;
        }

        replayObservation(state.mNode, nodeIndex, trace.at(observedIndex));
        discardPendingEnvelopes(state.mNode);
    }
}

DporNominationDporAdapter::BoundaryInspection
DporNominationDporAdapter::inspectNominationBoundary(
    std::size_t nodeIndex, ThreadTrace const& trace) const
{
    if (nodeIndex >= mValidators.size())
    {
        throw std::out_of_range("node index out of range");
    }

    auto& state = acquireReplayState(nodeIndex);
    replayTraceForBoundaryInspection(state, nodeIndex, trace);

    BoundaryInspection inspection;
    inspection.mReachedBoundary = state.mNode.hasCrossedNominationBoundary();
    if (auto const* boundaryEnvelope = state.mNode.getNominationBoundaryEnvelope())
    {
        inspection.mBoundaryEnvelope = *boundaryEnvelope;
    }
    return inspection;
}

bool
DporNominationDporAdapter::hasReachedNominationBoundary(
    std::size_t nodeIndex, ThreadTrace const& trace) const
{
    return inspectNominationBoundary(nodeIndex, trace).mReachedBoundary;
}

std::optional<SCPEnvelope>
DporNominationDporAdapter::getNominationBoundaryEnvelope(
    std::size_t nodeIndex, ThreadTrace const& trace) const
{
    return inspectNominationBoundary(nodeIndex, trace).mBoundaryEnvelope;
}

}
