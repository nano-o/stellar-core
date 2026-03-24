// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
#include "scp/Slot.h"
#include "scp/test/ScpDporReplaySupport.h"

#include <algorithm>
#include <deque>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace stellar::scpdpor
{

class ScpDporThreeNodePrepareBoundaryScenario
{
  public:
    struct Options
    {
        std::vector<SecretKey> mValidators;
        SCPQuorumSet mQuorumSet;
        uint64_t mSlotIndex{0};
        Value mPreviousValue;
        std::vector<Value> mInitialValues;
        DporScpNode::BoundaryMode mBoundaryMode{
            DporScpNode::BoundaryMode::Prepare};
        uint32_t mPrepareBoundaryCounter{
            DporScpNode::DEFAULT_PREPARE_BOUNDARY_COUNTER};
        bool mEnableNominationTimeouts{true};
        bool mEnableBallotingTimeouts{false};
        bool mAwaitTxSetDownloads{false};
        uint32_t mInitialNominationTimeoutMS{1000};
        uint32_t mIncrementNominationTimeoutMS{1000};
        uint32_t mInitialBallotTimeoutMS{1000};
        uint32_t mIncrementBallotTimeoutMS{1000};
    };

    struct BoundaryInspection
    {
        bool mReachedBoundary{false};
        std::optional<SCPEnvelope> mBoundaryEnvelope;
    };

    explicit ScpDporThreeNodePrepareBoundaryScenario(
        Options options = makeDefaultOptions())
        : mOptions(std::move(options))
        , mReplaySupport(mOptions.mValidators, mOptions.mQuorumSet,
                         mOptions.mSlotIndex, mOptions.mPreviousValue,
                         mOptions.mInitialValues,
                         buildNodeConfiguration(mOptions))
    {
        if (mOptions.mValidators.size() != 3)
        {
            throw std::invalid_argument(
                "three-node scenario requires exactly 3 validators");
        }
        if (mOptions.mInitialValues.size() != mOptions.mValidators.size())
        {
            throw std::invalid_argument(
                "initialValues must match validator count");
        }

        mScenarioBaselines.reserve(mOptions.mValidators.size());
        for (std::size_t nodeIndex = 0; nodeIndex < mOptions.mValidators.size();
             ++nodeIndex)
        {
            ScenarioBaseline baseline;
            std::deque<SendLabel> pendingSends;
            auto const& nodeBaseline = mReplaySupport.getNodeBaseline(nodeIndex);
            for (auto const& envelope : nodeBaseline.mInitialPendingEnvelopes)
            {
                fanOutEnvelope(pendingSends, nodeIndex, envelope);
            }
            baseline.mInitialPendingSends.assign(pendingSends.begin(),
                                                 pendingSends.end());
            mScenarioBaselines.push_back(std::move(baseline));
        }
    }

    static Options
    makeDefaultOptions()
    {
        Options options;
        options.mValidators = {SecretKey::pseudoRandomForTestingFromSeed(1000),
                               SecretKey::pseudoRandomForTestingFromSeed(1001),
                               SecretKey::pseudoRandomForTestingFromSeed(1002)};
        options.mQuorumSet.threshold = 2;
        for (auto const& validator : options.mValidators)
        {
            options.mQuorumSet.validators.push_back(validator.getPublicKey());
        }
        options.mPreviousValue = makeValue("prev");
        options.mInitialValues = {makeValue("x"), makeValue("y"),
                                  makeValue("y")};
        options.mEnableNominationTimeouts = false;
        return options;
    }

    Program
    makeProgram() const
    {
        Program program;
        auto self =
            std::make_shared<ScpDporThreeNodePrepareBoundaryScenario const>(
                *this);
        for (std::size_t nodeIndex = 0; nodeIndex < mOptions.mValidators.size();
             ++nodeIndex)
        {
            auto const threadID = threadIdForNodeIndex(nodeIndex);
            program.threads[threadID] = [self, nodeIndex](
                                            ThreadTrace const& trace,
                                            std::size_t step)
                -> std::optional<EventLabel> {
                return self->captureNextEvent(nodeIndex, trace, step);
            };
        }
        return program;
    }

    BoundaryInspection
    inspectPrepareBoundary(std::size_t nodeIndex, ThreadTrace const& trace) const
    {
        auto& node = mReplaySupport.acquireNode(nodeIndex);
        mReplaySupport.restoreBaseline(node, nodeIndex);

        std::optional<int> selectedTimerID;
        for (std::size_t observedIndex = 0; observedIndex < trace.size();)
        {
            if (node.hasReachedPrepareBoundary())
            {
                break;
            }

            auto const& observed = trace.at(observedIndex);
            if (!observed.is_bottom() && isTimerChoiceValue(observed.value()))
            {
                auto const activeTimers = enabledTimerIDs(node);
                auto const timerID = decodeTimerChoice(observed.value());
                if (std::find(activeTimers.begin(), activeTimers.end(),
                              timerID) == activeTimers.end())
                {
                    throw std::logic_error(
                        "trace selected a timer that is not active");
                }
                selectedTimerID = timerID;
                ++observedIndex;
                continue;
            }

            auto const activeTimers = enabledTimerIDs(node);
            auto timerToFire = selectedTimerID;
            if (!timerToFire && activeTimers.size() == 1)
            {
                timerToFire = activeTimers.front();
            }

            auto replayed = mReplaySupport.replayObservation(
                node, nodeIndex, trace, observedIndex, timerToFire);
            if (replayed.mPendingEvent)
            {
                break;
            }

            observedIndex += replayed.mConsumedTraceEntries;
            static_cast<void>(node.takePendingEnvelopes());
            updateSelectedTimerAfterObservation(node, replayed, selectedTimerID);
        }

        BoundaryInspection inspection;
        inspection.mReachedBoundary = node.hasReachedPrepareBoundary();
        if (auto const* envelope = node.getPrepareBoundaryEnvelope())
        {
            inspection.mBoundaryEnvelope = *envelope;
        }
        return inspection;
    }

    bool
    hasReachedPrepareBoundary(std::size_t nodeIndex,
                              ThreadTrace const& trace) const
    {
        return inspectPrepareBoundary(nodeIndex, trace).mReachedBoundary;
    }

    std::optional<SCPEnvelope>
    getPrepareBoundaryEnvelope(std::size_t nodeIndex,
                               ThreadTrace const& trace) const
    {
        return inspectPrepareBoundary(nodeIndex, trace).mBoundaryEnvelope;
    }

    Options const&
    options() const
    {
        return mOptions;
    }

  private:
    struct ScenarioBaseline
    {
        std::vector<SendLabel> mInitialPendingSends;
    };

    static Value
    makeValue(std::string_view bytes)
    {
        Value value;
        value.insert(value.end(), bytes.begin(), bytes.end());
        return value;
    }

    static DporScpNode::Configuration
    buildNodeConfiguration(Options const& options)
    {
        DporScpNode::Configuration config;
        for (std::size_t nodeIndex = 0; nodeIndex < options.mValidators.size();
             ++nodeIndex)
        {
            config.mNodeIndexMap[options.mValidators.at(nodeIndex).getPublicKey()] =
                nodeIndex + 1;
        }
        config.mBoundaryMode = options.mBoundaryMode;
        config.mPrepareBoundaryCounter = options.mPrepareBoundaryCounter;
        config.mAwaitTxSetDownloads = options.mAwaitTxSetDownloads;
        config.mInitialNominationTimeoutMS =
            options.mInitialNominationTimeoutMS;
        config.mIncrementNominationTimeoutMS =
            options.mIncrementNominationTimeoutMS;
        config.mInitialBallotTimeoutMS = options.mInitialBallotTimeoutMS;
        config.mIncrementBallotTimeoutMS = options.mIncrementBallotTimeoutMS;
        return config;
    }

    std::vector<int>
    enabledTimerIDs(DporScpNode const& node) const
    {
        std::vector<int> timers;
        auto const hasFirableTimer = [&](int timerID) {
            auto const timer = node.getTimer(mOptions.mSlotIndex, timerID);
            return timer && static_cast<bool>(timer->mCallback);
        };

        if (mOptions.mEnableNominationTimeouts &&
            hasFirableTimer(Slot::NOMINATION_TIMER))
        {
            timers.push_back(Slot::NOMINATION_TIMER);
        }
        if (mOptions.mEnableBallotingTimeouts &&
            hasFirableTimer(Slot::BALLOT_PROTOCOL_TIMER))
        {
            timers.push_back(Slot::BALLOT_PROTOCOL_TIMER);
        }
        return timers;
    }

    ReceiveLabel
    makeReceiveLabel(std::size_t) const
    {
        auto const matcher = [slotIndex = mOptions.mSlotIndex](
                                 ScpDporValue const& value) {
            return isEnvelopeValue(value) && value.mSlotIndex == slotIndex;
        };
        return dpor::model::make_receive_label<ScpDporValue>(matcher);
    }

    ReceiveLabel
    makeNonBlockingReceiveLabel(std::size_t) const
    {
        auto const matcher = [slotIndex = mOptions.mSlotIndex](
                                 ScpDporValue const& value) {
            return isEnvelopeValue(value) && value.mSlotIndex == slotIndex;
        };
        return dpor::model::make_nonblocking_receive_label<ScpDporValue>(
            matcher);
    }

    void
    fanOutEnvelope(std::deque<SendLabel>& pendingSends, std::size_t senderIndex,
                   SCPEnvelope const& envelope) const
    {
        for (std::size_t receiverIndex = 0;
             receiverIndex < mOptions.mValidators.size(); ++receiverIndex)
        {
            if (receiverIndex == senderIndex)
            {
                continue;
            }
            pendingSends.push_back(
                SendLabel{.destination = threadIdForNodeIndex(receiverIndex),
                          .value = makeEnvelopeValue(mOptions.mSlotIndex,
                                                     envelope)});
        }
    }

    void
    queuePendingEnvelopeSends(std::deque<SendLabel>& pendingSends,
                              DporScpNode& node,
                              std::size_t senderIndex) const
    {
        for (auto const& envelope : node.takePendingEnvelopes())
        {
            fanOutEnvelope(pendingSends, senderIndex, envelope);
        }
    }

    void
    updateSelectedTimerAfterObservation(
        DporScpNode const& node,
        ScpDporReplaySupport::ReplayObservationProgress const& replayed,
        std::optional<int>& selectedTimerID) const
    {
        if (!selectedTimerID)
        {
            return;
        }
        if (replayed.mObservedBottom)
        {
            selectedTimerID.reset();
            return;
        }

        auto const timer = node.getTimer(mOptions.mSlotIndex, *selectedTimerID);
        if (!timer || !timer->mCallback)
        {
            selectedTimerID.reset();
        }
    }

    std::optional<EventLabel>
    captureNextEvent(std::size_t nodeIndex, ThreadTrace const& trace,
                     std::size_t step) const
    {
        auto& node = mReplaySupport.acquireNode(nodeIndex);
        mReplaySupport.restoreBaseline(node, nodeIndex);

        std::deque<SendLabel> pendingSends(
            mScenarioBaselines.at(nodeIndex).mInitialPendingSends.begin(),
            mScenarioBaselines.at(nodeIndex).mInitialPendingSends.end());
        std::size_t eventCount = 0;
        std::size_t observedCount = 0;
        std::optional<int> selectedTimerID;

        while (true)
        {
            if (!pendingSends.empty())
            {
                auto nextSend = EventLabel{pendingSends.front()};
                pendingSends.pop_front();
                if (eventCount == step)
                {
                    return nextSend;
                }
                ++eventCount;
                continue;
            }

            if (node.hasReachedPrepareBoundary())
            {
                return std::nullopt;
            }

            auto const activeTimers = enabledTimerIDs(node);
            if (!selectedTimerID && activeTimers.size() > 1)
            {
                std::vector<ScpDporValue> choices;
                choices.reserve(activeTimers.size());
                for (auto const timerID : activeTimers)
                {
                    choices.push_back(
                        makeTimerChoiceValue(mOptions.mSlotIndex, timerID));
                }

                if (eventCount == step)
                {
                    return EventLabel{NondeterministicChoiceLabel{
                        .value = choices.front(), .choices = std::move(choices)}};
                }
                ++eventCount;

                if (observedCount >= trace.size() || trace.at(observedCount).is_bottom())
                {
                    throw std::logic_error(
                        "trace does not contain a timer-choice observation");
                }

                auto const& observedValue = trace.at(observedCount).value();
                if (!isTimerChoiceValue(observedValue))
                {
                    throw std::logic_error(
                        "trace entry is not a timer-choice value");
                }
                auto const timerID = decodeTimerChoice(observedValue);
                if (std::find(activeTimers.begin(), activeTimers.end(),
                              timerID) == activeTimers.end())
                {
                    throw std::logic_error(
                        "trace selected a timer that is not active");
                }
                selectedTimerID = timerID;
                ++observedCount;
                continue;
            }

            auto const nonBlocking =
                selectedTimerID.has_value() || activeTimers.size() == 1;
            auto receiveEvent = EventLabel{nonBlocking
                                               ? makeNonBlockingReceiveLabel(
                                                     nodeIndex)
                                               : makeReceiveLabel(nodeIndex)};
            if (eventCount == step)
            {
                return receiveEvent;
            }
            ++eventCount;

            if (observedCount >= trace.size())
            {
                throw std::logic_error(
                    "trace does not contain enough observations to replay the requested step");
            }

            auto timerToFire = selectedTimerID;
            if (!timerToFire && activeTimers.size() == 1)
            {
                timerToFire = activeTimers.front();
            }

            auto replayed = mReplaySupport.replayObservation(
                node, nodeIndex, trace, observedCount, timerToFire);
            if (replayed.mPendingEvent)
            {
                eventCount += replayed.mConsumedStepCount;
                if (eventCount == step)
                {
                    return replayed.mPendingEvent;
                }
                throw std::logic_error(
                    "trace does not contain enough observations to replay the requested step");
            }

            observedCount += replayed.mConsumedTraceEntries;
            eventCount += replayed.mConsumedStepCount;
            queuePendingEnvelopeSends(pendingSends, node, nodeIndex);
            updateSelectedTimerAfterObservation(node, replayed, selectedTimerID);
        }
    }

    Options mOptions;
    ScpDporReplaySupport mReplaySupport;
    std::vector<ScenarioBaseline> mScenarioBaselines;
};

} // namespace stellar::scpdpor
