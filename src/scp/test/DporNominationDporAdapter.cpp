// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationDporAdapter.h"

#include "scp/Slot.h"

#include <limits>
#include <memory>
#include <stdexcept>
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

void
requireNominationEnvelope(SCPEnvelope const& envelope)
{
    if (envelope.statement.pledges.type() != SCP_ST_NOMINATE)
    {
        throw std::logic_error("DPOR replay only accepts nomination envelopes");
    }
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
    DporNominationNode::Configuration const& config)
    : mValidators(validators)
    , mQSet(qSet)
    , mSlotIndex(slotIndex)
    , mPreviousValue(previousValue)
    , mInitialValues(initialValues)
    , mConfig(config)
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
DporNominationDporAdapter::setPriorityLookup(
    std::function<uint64(NodeID const&)> const& fn)
{
    mConfig.mPriorityLookup = fn;
}

void
DporNominationDporAdapter::setValueHash(
    std::function<uint64(Value const&)> const& fn)
{
    mConfig.mValueHash = fn;
}

void
DporNominationDporAdapter::setCombineCandidates(
    std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const&
        fn)
{
    mConfig.mCombineCandidates = fn;
}

void
DporNominationDporAdapter::setReplayMetrics(
    std::shared_ptr<ReplayMetrics> metrics)
{
    mReplayMetrics = std::move(metrics);
}

void
DporNominationDporAdapter::initializeNode(ReplayState& state,
                                          std::size_t nodeIndex) const
{
    state.mNode.nominate(mSlotIndex, mInitialValues.at(nodeIndex),
                         mPreviousValue);
    queuePendingNominationSends(state, nodeIndex);
}

void
DporNominationDporAdapter::replayObservation(DporNominationNode& node,
                                             std::size_t nodeIndex,
                                             ObservedValue const& observed) const
{
    auto const localThread = toThreadID(nodeIndex);
    if (observed.is_bottom())
    {
        if (!node.fireTimer(mSlotIndex, Slot::NOMINATION_TIMER))
        {
            throw std::logic_error(
                "trace requested a timer firing without an active nomination "
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
    requireNominationEnvelope(delivery.mEnvelope);
    node.receiveEnvelope(delivery.mEnvelope);
}

void
DporNominationDporAdapter::discardPendingEnvelopes(DporNominationNode& node) const
{
    static_cast<void>(node.takePendingEnvelopes());
}

void
DporNominationDporAdapter::queuePendingNominationSends(
    ReplayState& state, std::size_t senderIndex) const
{
    auto pendingEnvelopes = state.mNode.takePendingEnvelopes();
    if (state.mNode.hasCrossedNominationBoundary() && !pendingEnvelopes.empty())
    {
        throw std::logic_error(
            "nomination replay does not support pending nomination sends after "
            "crossing the nomination boundary");
    }

    if (mReplayMetrics && !pendingEnvelopes.empty())
    {
        mReplayMetrics->mQueuedNominationEnvelopeCount.fetch_add(
            pendingEnvelopes.size(), std::memory_order_relaxed);
    }

    auto const senderThread = toThreadID(senderIndex);
    for (auto const& envelope : pendingEnvelopes)
    {
        requireNominationEnvelope(envelope);
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

    ReplayState state(mValidators.at(nodeIndex), mQSet, mConfig);
    initializeNode(state, nodeIndex);

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

        auto const hasNominationTimer =
            state.mNode.hasActiveTimer(mSlotIndex, Slot::NOMINATION_TIMER);
        auto nextReceive =
            EventLabel{makeReceiveLabel(localThread, hasNominationTimer)};
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

        replayObservation(state.mNode, nodeIndex, trace.at(observedCount++));

        queuePendingNominationSends(state, nodeIndex);
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
    initializeNode(state, nodeIndex);
    discardPendingEnvelopes(state.mNode);

    for (auto const& observed : trace)
    {
        if (state.mNode.hasCrossedNominationBoundary())
        {
            break;
        }

        replayObservation(state.mNode, nodeIndex, observed);
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

    ReplayState state(mValidators.at(nodeIndex), mQSet, mConfig);
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
