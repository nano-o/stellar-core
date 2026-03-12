// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationDporAdapter.h"

#include "scp/Slot.h"

#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
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

std::string
formatEnvelopeSummary(SCPEnvelope const& envelope)
{
    std::ostringstream out;
    switch (envelope.statement.pledges.type())
    {
    case SCP_ST_NOMINATE:
    {
        auto const& nomination = envelope.statement.pledges.nominate();
        out << "nom(v=" << nomination.votes.size()
            << ",a=" << nomination.accepted.size() << ")";
        break;
    }
    case SCP_ST_PREPARE:
    {
        auto const& prepare = envelope.statement.pledges.prepare();
        out << "prepare(b=" << prepare.ballot.counter << ")";
        break;
    }
    case SCP_ST_CONFIRM:
    {
        auto const& confirm = envelope.statement.pledges.confirm();
        out << "confirm(b=" << confirm.ballot.counter << ")";
        break;
    }
    case SCP_ST_EXTERNALIZE:
    {
        auto const& externalize = envelope.statement.pledges.externalize();
        out << "externalize(b=" << externalize.commit.counter << ")";
        break;
    }
    default:
        out << "stmt(" << static_cast<int>(envelope.statement.pledges.type())
            << ")";
        break;
    }
    return out.str();
}

std::string
formatTracePrefix(DporNominationDporAdapter::ThreadTrace const& trace,
                  std::size_t replayedObservationCount)
{
    std::ostringstream out;
    bool first = true;
    auto const prefixSize = std::min(replayedObservationCount, trace.size());
    for (std::size_t i = 0; i < prefixSize; ++i)
    {
        if (!first)
        {
            out << ", ";
        }
        first = false;

        auto const& observed = trace.at(i);
        if (observed.is_bottom())
        {
            out << "timer";
            continue;
        }

        auto const& delivery = observed.value();
        out << "recv<-" << delivery.mSenderThread << ":"
            << formatEnvelopeSummary(delivery.mEnvelope);
    }

    if (first)
    {
        out << "start";
    }
    return out.str();
}

std::string
formatTimerSummary(DporNominationNode const& node, uint64_t slotIndex)
{
    std::ostringstream out;
    auto appendTimer = [&](char const* label, int timerID) {
        auto timer = node.getTimer(slotIndex, timerID);
        if (!timer || !timer->mCallback)
        {
            return;
        }
        if (out.tellp() > 0)
        {
            out << ", ";
        }
        out << label << "=" << timer->mTimeout.count() << "ms";
    };

    appendTimer("nomination", Slot::NOMINATION_TIMER);
    appendTimer("ballot", Slot::BALLOT_PROTOCOL_TIMER);
    if (out.tellp() == 0)
    {
        out << "none";
    }
    return out.str();
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
DporNominationDporAdapter::setTimeoutModes(bool enableNominationTimeouts,
                                           bool enableBallotingTimeouts)
{
    mEnableNominationTimeouts = enableNominationTimeouts;
    mEnableBallotingTimeouts = enableBallotingTimeouts;
}

std::optional<int>
DporNominationDporAdapter::selectEnabledTimerID(
    DporNominationNode const& node, std::size_t nodeIndex,
    ThreadTrace const& trace, std::size_t replayedObservationCount) const
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
        std::ostringstream out;
        out << "DPOR replay does not support simultaneous nomination and "
               "balloting timer bottoms"
            << " node=" << nodeIndex
            << " active_timers=[" << formatTimerSummary(node, mSlotIndex)
            << "]"
            << " replayed_trace=[" 
            << formatTracePrefix(trace, replayedObservationCount) << "]";
        throw std::logic_error(out.str());
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
    state.mNode.nominate(mSlotIndex, mInitialValues.at(nodeIndex),
                         mPreviousValue);
    queuePendingEnvelopeSends(state, nodeIndex);
}

void
DporNominationDporAdapter::replayObservation(DporNominationNode& node,
                                             std::size_t nodeIndex,
                                             ObservedValue const& observed,
                                             ThreadTrace const& trace,
                                             std::size_t replayedObservationCount) const
{
    auto const localThread = toThreadID(nodeIndex);
    if (observed.is_bottom())
    {
        auto const timerID =
            selectEnabledTimerID(node, nodeIndex, trace,
                                 replayedObservationCount);
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

        auto const enabledTimerID =
            selectEnabledTimerID(state.mNode, nodeIndex, trace, observedCount);
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

        replayObservation(state.mNode, nodeIndex, trace.at(observedCount), trace,
                          observedCount);
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
    initializeNode(state, nodeIndex);
    discardPendingEnvelopes(state.mNode);

    for (std::size_t observedIndex = 0; observedIndex < trace.size();
         ++observedIndex)
    {
        if (state.mNode.hasCrossedNominationBoundary())
        {
            break;
        }

        replayObservation(state.mNode, nodeIndex, trace.at(observedIndex),
                          trace, observedIndex);
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
