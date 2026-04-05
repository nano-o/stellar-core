// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
#include "scp/Slot.h"
#include "scp/test/ScpDporReplaySupport.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace stellar::scpdpor
{

class ScpDporDefaultScenario
{
  public:
    enum class TxSetStatusMode : std::uint8_t
    {
        Valid,
        Invalid,
        Nondeterministic
    };

    enum class InitialValueMode : std::uint8_t
    {
        Same,
        Unique
    };

    struct Options
    {
        std::vector<SecretKey> mValidators;
        SCPQuorumSet mQuorumSet;
        uint64_t mSlotIndex{0};
        Value mPreviousValue;
        std::vector<Value> mInitialValues;
        bool mStopOnPrepare{false};
        bool mStopOnCommit{false};
        bool mStopOnExternalize{false};
        uint32_t mPrepareBoundaryCounter{
            DporScpNode::DEFAULT_PREPARE_BOUNDARY_COUNTER};
        std::optional<uint32_t> mMaxNominationRound;
        std::optional<uint32_t> mMaxBallotingRound;
        std::optional<uint32_t> mMaxNominationTimersRound;
        std::optional<uint32_t> mMaxBallotingTimersRound;
        std::optional<uint32_t> mNominationTimerSetLimit;
        bool mEnableNominationTimeouts{false};
        bool mEnableBallotingTimeouts{false};
        TxSetStatusMode mTxSetStatusMode{TxSetStatusMode::Valid};
        uint32_t mInitialNominationTimeoutMS{1000};
        uint32_t mIncrementNominationTimeoutMS{1000};
        uint32_t mInitialBallotTimeoutMS{1000};
        uint32_t mIncrementBallotTimeoutMS{1000};

        bool operator==(Options const& other) const = default;
    };

    struct BoundaryInspection
    {
        bool mReachedBoundary{false};
        std::optional<SCPEnvelope> mBoundaryEnvelope;
    };

    struct EmittedEnvelopeInspection
    {
        std::vector<SCPEnvelope> mEmittedEnvelopes;
    };

    struct ThreadReplayTraceStep
    {
        enum class Kind : std::uint8_t
        {
            Send,
            Receive,
            NondeterministicChoice
        };

        Kind mKind{Kind::Send};
        std::optional<SendLabel> mSend;
        std::optional<ReceiveLabel> mReceive;
        std::optional<NondeterministicChoiceLabel> mChoice;
        std::optional<ObservedValue> mObservedValue;
        std::vector<ObservedValue> mNestedChoices;
        std::vector<DporScpNode::ReplayDebugEvent> mSideEffects;
    };

    struct ThreadReplayTraceInspection
    {
        std::vector<ThreadReplayTraceStep> mSteps;
        bool mReachedBoundary{false};
        std::optional<SCPEnvelope> mBoundaryEnvelope;
        std::optional<std::string> mReplayErrorMessage;
    };

    explicit ScpDporDefaultScenario(Options options = makeDefaultOptions())
        : mOptions(std::move(options))
        , mReplaySupport(mOptions.mValidators, mOptions.mQuorumSet,
                         mOptions.mSlotIndex, mOptions.mPreviousValue,
                         mOptions.mInitialValues,
                         buildNodeConfiguration(mOptions))
    {
        if (mOptions.mValidators.size() != 3)
        {
            throw std::invalid_argument(
                "default scenario currently requires exactly 3 validators");
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
            auto const& nodeBaseline = mReplaySupport.getNodeBaseline(nodeIndex);
            baseline.mInitialPendingSends.reserve(
                nodeBaseline.mInitialPendingEnvelopes.size() *
                (mOptions.mValidators.size() - 1));
            for (auto const& envelope : nodeBaseline.mInitialPendingEnvelopes)
            {
                fanOutEnvelope(baseline.mInitialPendingSends, nodeIndex,
                               envelope);
            }
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
        return options;
    }

    static std::vector<Value>
    makeInitialValues(InitialValueMode mode, std::size_t validatorCount)
    {
        std::vector<Value> values;
        values.reserve(validatorCount);
        switch (mode)
        {
        case InitialValueMode::Same:
            for (std::size_t nodeIndex = 0; nodeIndex < validatorCount;
                 ++nodeIndex)
            {
                values.push_back(makeValue("x"));
            }
            return values;
        case InitialValueMode::Unique:
            for (std::size_t nodeIndex = 0; nodeIndex < validatorCount;
                 ++nodeIndex)
            {
                auto const valueName = std::string("x") +
                                       std::to_string(nodeIndex);
                values.push_back(makeValue(std::string_view(valueName)));
            }
            return values;
        }
        throw std::logic_error("unknown initial value mode");
    }

    Program
    makeProgram() const
    {
        ScpDporReplaySupport::clearThreadLocalCacheForCurrentThread();

        Program program;
        auto self = std::make_shared<ScpDporDefaultScenario const>(*this);
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
    inspectBoundary(std::size_t nodeIndex, ThreadTrace const& trace) const
    {
        auto const replayInspection = replayTrace(nodeIndex, trace, true, true);
        BoundaryInspection inspection;
        inspection.mReachedBoundary = replayInspection.mReachedBoundary;
        inspection.mBoundaryEnvelope = replayInspection.mBoundaryEnvelope;
        return inspection;
    }

    BoundaryInspection
    inspectPrepareBoundary(std::size_t nodeIndex, ThreadTrace const& trace) const
    {
        auto prepareOptions = mOptions;
        prepareOptions.mStopOnPrepare = true;
        prepareOptions.mMaxNominationRound.reset();
        prepareOptions.mMaxBallotingRound.reset();
        return ScpDporDefaultScenario(std::move(prepareOptions))
            .inspectBoundary(nodeIndex, trace);
    }

    bool
    hasReachedBoundary(std::size_t nodeIndex, ThreadTrace const& trace) const
    {
        return inspectBoundary(nodeIndex, trace).mReachedBoundary;
    }

    std::optional<SCPEnvelope>
    getBoundaryEnvelope(std::size_t nodeIndex, ThreadTrace const& trace) const
    {
        return inspectBoundary(nodeIndex, trace).mBoundaryEnvelope;
    }

    std::vector<SCPEnvelope>
    getEmittedEnvelopes(std::size_t nodeIndex, ThreadTrace const& trace) const
    {
        return inspectEmittedEnvelopes(nodeIndex, trace).mEmittedEnvelopes;
    }

    EmittedEnvelopeInspection
    inspectEmittedEnvelopes(std::size_t nodeIndex,
                            ThreadTrace const& trace) const
    {
        auto replayInspection = replayTrace(nodeIndex, trace, false, false);
        EmittedEnvelopeInspection inspection;
        inspection.mEmittedEnvelopes =
            std::move(replayInspection.mEmittedEnvelopes);
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

    ThreadReplayTraceInspection
    inspectThreadReplayTrace(std::size_t nodeIndex,
                             ThreadTrace const& trace) const
    {
        ScpDporReplaySupport::clearThreadLocalCacheForCurrentThread();

        auto& node = mReplaySupport.acquireNode(nodeIndex);
        struct ReplayDebugRecordingGuard
        {
            DporScpNode& mNode;

            explicit ReplayDebugRecordingGuard(DporScpNode& node)
                : mNode(node)
            {
                mNode.setReplayDebugRecordingEnabled(true);
            }

            ~ReplayDebugRecordingGuard()
            {
                mNode.setReplayDebugRecordingEnabled(false);
            }
        } guard(node);
        mReplaySupport.restoreBaseline(node, nodeIndex);

        auto pendingSends = mScenarioBaselines.at(nodeIndex).mInitialPendingSends;
        std::size_t nextPendingSend = 0;
        std::size_t observedCount = 0;
        std::optional<int> selectedTimerID;
        ThreadReplayTraceInspection inspection;

        while (true)
        {
            while (nextPendingSend < pendingSends.size())
            {
                inspection.mSteps.push_back(ThreadReplayTraceStep{
                    .mKind = ThreadReplayTraceStep::Kind::Send,
                    .mSend = pendingSends.at(nextPendingSend++)});
            }

            if (node.hasReachedBoundary() || observedCount >= trace.size())
            {
                break;
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

                auto const& observed = trace.at(observedCount);
                if (observed.is_bottom())
                {
                    throw std::logic_error(
                        "trace does not contain a timer-choice observation");
                }
                auto const& observedValue = observed.value();
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

                inspection.mSteps.push_back(ThreadReplayTraceStep{
                    .mKind = ThreadReplayTraceStep::Kind::NondeterministicChoice,
                    .mChoice = NondeterministicChoiceLabel{
                        .value = choices.front(), .choices = std::move(choices)},
                    .mObservedValue = observed});
                selectedTimerID = timerID;
                ++observedCount;
                continue;
            }

            auto const nonBlocking =
                selectedTimerID.has_value() || activeTimers.size() == 1;
            auto timerToFire = selectedTimerID;
            if (!timerToFire && activeTimers.size() == 1)
            {
                timerToFire = activeTimers.front();
            }

            ThreadReplayTraceStep step;
            step.mKind = ThreadReplayTraceStep::Kind::Receive;
            step.mReceive = nonBlocking ? makeNonBlockingReceiveLabel(nodeIndex)
                                        : makeReceiveLabel(nodeIndex);
            step.mObservedValue = trace.at(observedCount);

            ScpDporReplaySupport::ReplayObservationProgress replayed;
            try
            {
                replayed = mReplaySupport.replayObservation(
                    node, nodeIndex, trace, observedCount, timerToFire);
            }
            catch (std::exception const& ex)
            {
                appendNestedChoiceObservations(step, trace, observedCount);
                step.mSideEffects = node.takeReplayDebugEvents();
                inspection.mSteps.push_back(std::move(step));
                inspection.mReplayErrorMessage = ex.what();
                break;
            }

            for (std::size_t i = 1; i < replayed.mConsumedTraceEntries; ++i)
            {
                step.mNestedChoices.push_back(trace.at(observedCount + i));
            }
            step.mSideEffects = node.takeReplayDebugEvents();
            inspection.mSteps.push_back(std::move(step));

            if (replayed.mPendingEvent)
            {
                break;
            }

            observedCount += replayed.mConsumedTraceEntries;
            queuePendingEnvelopeSends(pendingSends, node, nodeIndex);
            updateSelectedTimerAfterObservation(node, replayed, selectedTimerID);
        }

        inspection.mReachedBoundary = node.hasReachedBoundary();
        if (auto const* envelope = node.getBoundaryEnvelope())
        {
            inspection.mBoundaryEnvelope = *envelope;
        }
        return inspection;
    }

    Options const&
    options() const
    {
        return mOptions;
    }

  private:
    struct ReplayInspection
    {
        bool mReachedBoundary{false};
        std::optional<SCPEnvelope> mBoundaryEnvelope;
        std::vector<SCPEnvelope> mEmittedEnvelopes;
    };

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
        auto const envelopeBoundaryModes =
            static_cast<int>(options.mStopOnPrepare) +
            static_cast<int>(options.mStopOnCommit) +
            static_cast<int>(options.mStopOnExternalize);
        if (envelopeBoundaryModes > 1)
        {
            throw std::invalid_argument(
                "prepare, commit, and externalize boundaries are mutually "
                "exclusive");
        }
        for (std::size_t nodeIndex = 0; nodeIndex < options.mValidators.size();
             ++nodeIndex)
        {
            config.mNodeIndexMap[options.mValidators.at(nodeIndex).getPublicKey()] =
                nodeIndex + 1;
        }
        if (options.mStopOnExternalize)
        {
            config.mBoundaryMode = DporScpNode::BoundaryMode::Externalize;
        }
        else if (options.mStopOnCommit)
        {
            config.mBoundaryMode = DporScpNode::BoundaryMode::Commit;
        }
        else if (options.mStopOnPrepare)
        {
            config.mBoundaryMode = DporScpNode::BoundaryMode::Prepare;
        }
        else
        {
            config.mBoundaryMode = DporScpNode::BoundaryMode::None;
        }
        config.mPrepareBoundaryCounter = options.mPrepareBoundaryCounter;
        config.mMaxNominationRound = options.mMaxNominationRound;
        config.mMaxBallotingRound = options.mMaxBallotingRound;
        config.mNominationTimerSetLimit = options.mNominationTimerSetLimit;
        config.mInitialNominationTimeoutMS =
            options.mInitialNominationTimeoutMS;
        config.mIncrementNominationTimeoutMS =
            options.mIncrementNominationTimeoutMS;
        config.mInitialBallotTimeoutMS = options.mInitialBallotTimeoutMS;
        config.mIncrementBallotTimeoutMS = options.mIncrementBallotTimeoutMS;
        switch (options.mTxSetStatusMode)
        {
        case TxSetStatusMode::Valid:
            config.mTxSetStatus = DporScpTxSetStatus::Valid;
            break;
        case TxSetStatusMode::Invalid:
            config.mTxSetStatus = DporScpTxSetStatus::Invalid;
            break;
        case TxSetStatusMode::Nondeterministic:
            config.mTxSetStatus = DporScpTxSetStatus::Valid;
            config.mNondeterministicTxSetStatus = true;
            break;
        }
        return config;
    }

    std::vector<int>
    enabledTimerIDs(DporScpNode const& node) const
    {
        std::vector<int> timers;
        auto const hasFirableTimer = [&](int timerID) {
            auto const timer = node.getTimer(mOptions.mSlotIndex, timerID);
            return timer && static_cast<bool>(timer->mCallback) &&
                   isTimerEnabledForExploration(node, *timer);
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
    fanOutEnvelope(std::vector<SendLabel>& pendingSends,
                   std::size_t senderIndex,
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
    queuePendingEnvelopeSends(std::vector<SendLabel>& pendingSends,
                              DporScpNode& node,
                              std::size_t senderIndex) const
    {
        for (auto const& envelope : node.takePendingEnvelopes())
        {
            fanOutEnvelope(pendingSends, senderIndex, envelope);
        }
    }

    bool
    isTimerEnabledForExploration(DporScpNode const& node,
                                 DporScpNode::TimerState const& timer) const
    {
        switch (timer.mTimerID)
        {
        case Slot::NOMINATION_TIMER:
            return !mOptions.mMaxNominationTimersRound ||
                   node.inferNominationRound(timer.mTimeout) <=
                       *mOptions.mMaxNominationTimersRound;
        case Slot::BALLOT_PROTOCOL_TIMER:
            return !mOptions.mMaxBallotingTimersRound ||
                   node.inferBallotingRound(timer.mTimeout) <=
                       *mOptions.mMaxBallotingTimersRound;
        default:
            return true;
        }
    }

    static void
    appendNestedChoiceObservations(ThreadReplayTraceStep& step,
                                   ThreadTrace const& trace,
                                   std::size_t observedIndex)
    {
        for (std::size_t choiceIndex = observedIndex + 1;
             choiceIndex < trace.size(); ++choiceIndex)
        {
            auto const& observed = trace.at(choiceIndex);
            if (observed.is_bottom())
            {
                break;
            }

            if (!isTxSetStatusChoiceValue(observed.value()))
            {
                break;
            }
            step.mNestedChoices.push_back(observed);
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
        if (!timer || !timer->mCallback ||
            !isTimerEnabledForExploration(node, *timer))
        {
            selectedTimerID.reset();
        }
    }

    ReplayInspection
    replayTrace(std::size_t nodeIndex, ThreadTrace const& trace,
                bool stopAtBoundary, bool allowPendingEvent) const
    {
        ScpDporReplaySupport::clearThreadLocalCacheForCurrentThread();

        auto& node = mReplaySupport.acquireNode(nodeIndex);
        mReplaySupport.restoreBaseline(node, nodeIndex);

        std::optional<int> selectedTimerID;
        for (std::size_t observedIndex = 0; observedIndex < trace.size();)
        {
            if (stopAtBoundary && node.hasReachedBoundary())
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
                if (allowPendingEvent)
                {
                    break;
                }
                throw std::logic_error(
                    "trace replay ended before resolving a pending event");
            }

            observedIndex += replayed.mConsumedTraceEntries;
            static_cast<void>(node.takePendingEnvelopes());
            updateSelectedTimerAfterObservation(node, replayed, selectedTimerID);
        }

        ReplayInspection inspection;
        inspection.mReachedBoundary = node.hasReachedBoundary();
        if (auto const* envelope = node.getBoundaryEnvelope())
        {
            inspection.mBoundaryEnvelope = *envelope;
        }
        inspection.mEmittedEnvelopes = node.getEmittedEnvelopes();
        return inspection;
    }

    std::optional<EventLabel>
    captureNextEvent(std::size_t nodeIndex, ThreadTrace const& trace,
                     std::size_t step) const
    {
        auto& node = mReplaySupport.acquireNode(nodeIndex);
        mReplaySupport.restoreBaseline(node, nodeIndex);

        auto pendingSends = mScenarioBaselines.at(nodeIndex).mInitialPendingSends;
        std::size_t nextPendingSend = 0;
        std::size_t eventCount = 0;
        std::size_t observedCount = 0;
        std::optional<int> selectedTimerID;

        while (true)
        {
            if (nextPendingSend < pendingSends.size())
            {
                auto nextSend = EventLabel{pendingSends.at(nextPendingSend++)};
                if (eventCount == step)
                {
                    return nextSend;
                }
                ++eventCount;
                continue;
            }

            if (node.hasReachedBoundary())
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
