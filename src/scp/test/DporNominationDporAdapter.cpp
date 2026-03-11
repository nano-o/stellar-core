// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationDporAdapter.h"

#include "scp/Slot.h"

#include <deque>
#include <limits>
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

struct ThreadReplayState
{
    ThreadReplayState(SecretKey const& secretKey, SCPQuorumSet const& qSet)
        : mNode(secretKey, qSet)
    {
    }

    DporNominationNode mNode;
    std::deque<DporNominationDporAdapter::SendLabel> mPendingSends;
};

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
        return value.mDestinationThread == destinationThread &&
               value.mEnvelope.statement.pledges.type() == SCP_ST_NOMINATE;
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
queuePendingNominationSends(ThreadReplayState& state, std::size_t senderIndex,
                            uint64_t slotIndex, std::size_t validatorCount)
{
    auto pendingEnvelopes = state.mNode.takePendingEnvelopes();
    if (state.mNode.hasCrossedNominationBoundary() && !pendingEnvelopes.empty())
    {
        throw std::logic_error(
            "nomination replay does not support pending nomination sends after "
            "crossing the nomination boundary");
    }

    auto const senderThread = toThreadID(senderIndex);
    for (auto const& envelope : pendingEnvelopes)
    {
        requireNominationEnvelope(envelope);
        for (std::size_t receiverIndex = 0; receiverIndex < validatorCount;
             ++receiverIndex)
        {
            if (receiverIndex == senderIndex)
            {
                continue;
            }
            auto const receiverThread = toThreadID(receiverIndex);
            state.mPendingSends.push_back(
                DporNominationDporAdapter::SendLabel{
                    .destination = receiverThread,
                    .value = DporNominationValue{
                        .mSenderThread = senderThread,
                        .mDestinationThread = receiverThread,
                        .mSlotIndex = slotIndex,
                        .mEnvelope = envelope,
                    },
                });
        }
    }
}

}

DporNominationDporAdapter::DporNominationDporAdapter(
    std::vector<SecretKey> const& validators, SCPQuorumSet const& qSet,
    uint64_t slotIndex, Value const& previousValue,
    std::vector<Value> const& initialValues)
    : mValidators(validators)
    , mQSet(qSet)
    , mSlotIndex(slotIndex)
    , mPreviousValue(previousValue)
    , mInitialValues(initialValues)
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
    mPriorityLookup = fn;
}

void
DporNominationDporAdapter::setValueHash(
    std::function<uint64(Value const&)> const& fn)
{
    mValueHash = fn;
}

void
DporNominationDporAdapter::setCombineCandidates(
    std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const&
        fn)
{
    mCombineCandidates = fn;
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

    ThreadReplayState state(mValidators.at(nodeIndex), mQSet);
    if (mPriorityLookup)
    {
        state.mNode.setPriorityLookup(mPriorityLookup);
    }
    if (mValueHash)
    {
        state.mNode.setValueHash(mValueHash);
    }
    if (mCombineCandidates)
    {
        state.mNode.setCombineCandidates(mCombineCandidates);
    }

    state.mNode.nominate(mSlotIndex, mInitialValues.at(nodeIndex),
                         mPreviousValue);
    queuePendingNominationSends(state, nodeIndex, mSlotIndex, mValidators.size());

    std::size_t eventCount = 0;
    std::size_t observedCount = 0;
    auto const localThread = toThreadID(nodeIndex);

    while (true)
    {
        if (!state.mPendingSends.empty())
        {
            auto nextSend = EventLabel{state.mPendingSends.front()};
            state.mPendingSends.pop_front();
            if (eventCount == step)
            {
                return nextSend;
            }
            ++eventCount;
            continue;
        }

        if (state.mNode.hasCrossedNominationBoundary())
        {
            return std::nullopt;
        }

        auto const hasNominationTimer =
            state.mNode.hasActiveTimer(mSlotIndex, Slot::NOMINATION_TIMER);
        auto nextReceive =
            EventLabel{makeReceiveLabel(localThread, hasNominationTimer)};
        if (eventCount == step)
        {
            return nextReceive;
        }
        ++eventCount;

        if (observedCount >= trace.size())
        {
            throw std::logic_error(
                "trace does not contain enough observations to replay the "
                "requested step");
        }

        auto const& observed = trace.at(observedCount++);
        if (observed.is_bottom())
        {
            if (!hasNominationTimer)
            {
                throw std::logic_error(
                    "bottom observation without an active nomination timer");
            }
            if (!state.mNode.fireTimer(mSlotIndex, Slot::NOMINATION_TIMER))
            {
                throw std::logic_error(
                    "failed to fire the active nomination timer");
            }
        }
        else
        {
            auto const& delivery = observed.value();
            if (delivery.mDestinationThread != localThread)
            {
                throw std::logic_error(
                    "trace delivered an envelope to the wrong thread");
            }
            if (delivery.mSlotIndex != mSlotIndex)
            {
                throw std::logic_error(
                    "trace delivered an envelope for the wrong slot");
            }
            requireNominationEnvelope(delivery.mEnvelope);
            state.mNode.receiveEnvelope(delivery.mEnvelope);
        }

        queuePendingNominationSends(state, nodeIndex, mSlotIndex,
                                    mValidators.size());
    }
}

DporNominationDporAdapter::Program
DporNominationDporAdapter::makeProgram() const
{
    Program program;
    for (std::size_t nodeIndex = 0; nodeIndex < mValidators.size(); ++nodeIndex)
    {
        program.threads[toThreadID(nodeIndex)] =
            [adapter = *this, nodeIndex](
                ThreadTrace const& trace,
                std::size_t step) -> std::optional<EventLabel> {
            return adapter.captureNextEvent(nodeIndex, trace, step);
        };
    }
    return program;
}

std::optional<SCPEnvelope>
DporNominationDporAdapter::getNominationBoundaryEnvelope(
    std::size_t nodeIndex, ThreadTrace const& trace) const
{
    if (nodeIndex >= mValidators.size())
    {
        throw std::out_of_range("node index out of range");
    }

    DporNominationNode node(mValidators.at(nodeIndex), mQSet);
    if (mPriorityLookup)
    {
        node.setPriorityLookup(mPriorityLookup);
    }
    if (mValueHash)
    {
        node.setValueHash(mValueHash);
    }
    if (mCombineCandidates)
    {
        node.setCombineCandidates(mCombineCandidates);
    }

    node.nominate(mSlotIndex, mInitialValues.at(nodeIndex), mPreviousValue);
    static_cast<void>(node.takePendingEnvelopes());

    auto const localThread = toThreadID(nodeIndex);
    for (auto const& observed : trace)
    {
        if (node.hasCrossedNominationBoundary())
        {
            break;
        }

        if (observed.is_bottom())
        {
            if (!node.fireTimer(mSlotIndex, Slot::NOMINATION_TIMER))
            {
                throw std::logic_error(
                    "trace requested a timer firing without an active "
                    "nomination timer");
            }
        }
        else
        {
            auto const& delivery = observed.value();
            if (delivery.mDestinationThread != localThread)
            {
                throw std::logic_error(
                    "trace delivered an envelope to the wrong thread");
            }
            if (delivery.mSlotIndex != mSlotIndex)
            {
                throw std::logic_error(
                    "trace delivered an envelope for the wrong slot");
            }
            requireNominationEnvelope(delivery.mEnvelope);
            node.receiveEnvelope(delivery.mEnvelope);
        }
        static_cast<void>(node.takePendingEnvelopes());
    }

    auto const* boundaryEnvelope = node.getNominationBoundaryEnvelope();
    if (!boundaryEnvelope)
    {
        return std::nullopt;
    }
    return *boundaryEnvelope;
}

}
