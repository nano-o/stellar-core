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
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace stellar::scpdpor
{

class ScpDporDefaultScenario
{
  public:
    static constexpr std::size_t DEFAULT_VALIDATOR_COUNT = 3;
    static constexpr std::size_t MIN_VALIDATOR_COUNT = 3;
    static constexpr std::size_t MAX_VALIDATOR_COUNT = 4;

    enum class DownloadTimeMode : std::uint8_t
    {
        BelowThreshold,
        AboveThreshold,
        Nondeterministic
    };

    enum class TxSetStatusMode : std::uint8_t
    {
        AlwaysValid,
        DownloadingThenValid,
        AlwaysDownloading
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
        DownloadTimeMode mDownloadTimeMode{DownloadTimeMode::BelowThreshold};
        TxSetStatusMode mTxSetStatusMode{TxSetStatusMode::AlwaysValid};
        bool mNominationAlwaysDownloading{false};
        bool mInjectEmptyTxSetProtocolGateFailureForTesting{false};
        std::vector<std::vector<Value>> mOutrightInvalidValuesByNode;
        std::optional<uint32_t> mDownloadSucceedsInRound;
        uint32_t mInitialNominationTimeoutMS{1000};
        uint32_t mIncrementNominationTimeoutMS{1000};
        uint32_t mInitialBallotTimeoutMS{1000};
        uint32_t mIncrementBallotTimeoutMS{1000};

        bool operator==(Options const& other) const = default;
    };

    struct ReplayInspection
    {
        bool mReachedBoundary{false};
        std::optional<SCPEnvelope> mBoundaryEnvelope;
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

    explicit ScpDporDefaultScenario(
        Options options = makeDefaultOptions(DEFAULT_VALIDATOR_COUNT),
        std::size_t replaySlotsPerNode =
            ScpDporReplaySupport::DEFAULT_REPLAY_SLOTS_PER_NODE)
        : mOptions(std::move(options))
        , mReplaySupport(mOptions.mValidators, mOptions.mQuorumSet,
                         mOptions.mSlotIndex, mOptions.mPreviousValue,
                         mOptions.mInitialValues,
                         buildNodeConfiguration(mOptions), replaySlotsPerNode)
    {
        if (!isSupportedValidatorCount(mOptions.mValidators.size()))
        {
            throw std::invalid_argument(
                "default scenario currently supports 3 or 4 validators");
        }
        if (mOptions.mInitialValues.size() != mOptions.mValidators.size())
        {
            throw std::invalid_argument(
                "initialValues must match validator count");
        }

        mInitialPendingSendsByNode.reserve(mOptions.mValidators.size());
        for (std::size_t nodeIndex = 0; nodeIndex < mOptions.mValidators.size();
             ++nodeIndex)
        {
            std::vector<SendLabel> initialPendingSends;
            auto const& nodeBaseline =
                mReplaySupport.getNodeBaseline(nodeIndex);
            initialPendingSends.reserve(
                nodeBaseline.mInitialPendingEnvelopes.size() *
                (mOptions.mValidators.size() - 1));
            for (auto const& envelope : nodeBaseline.mInitialPendingEnvelopes)
            {
                fanOutEnvelope(initialPendingSends, nodeIndex, envelope);
            }
            mInitialPendingSendsByNode.push_back(
                std::move(initialPendingSends));
        }
    }

    static Options
    makeDefaultOptions(std::size_t validatorCount = DEFAULT_VALIDATOR_COUNT)
    {
        Options options;
        if (!isSupportedValidatorCount(validatorCount))
        {
            throw std::invalid_argument(
                "default scenario validator count must be 3 or 4");
        }

        options.mValidators.reserve(validatorCount);
        for (std::size_t nodeIndex = 0; nodeIndex < validatorCount; ++nodeIndex)
        {
            options.mValidators.push_back(
                SecretKey::pseudoRandomForTestingFromSeed(1000 + nodeIndex));
        }

        options.mQuorumSet.threshold =
            static_cast<uint32_t>(validatorCount - 1);
        for (auto const& validator : options.mValidators)
        {
            options.mQuorumSet.validators.push_back(validator.getPublicKey());
        }
        options.mPreviousValue = makeValue("prev");
        options.mInitialValues.reserve(validatorCount);
        options.mInitialValues.push_back(makeValue("x"));
        for (std::size_t nodeIndex = 1; nodeIndex < validatorCount; ++nodeIndex)
        {
            options.mInitialValues.push_back(makeValue("y"));
        }
        return options;
    }

    static bool
    isSupportedValidatorCount(std::size_t validatorCount)
    {
        return validatorCount >= MIN_VALIDATOR_COUNT &&
               validatorCount <= MAX_VALIDATOR_COUNT;
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
                auto const valueName =
                    std::string("x") + std::to_string(nodeIndex);
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
            program.threads[threadID] =
                [self,
                 nodeIndex](ThreadTrace const& trace,
                            std::size_t step) -> std::optional<EventLabel> {
                return self->captureNextEvent(nodeIndex, trace, step);
            };
        }
        return program;
    }

    ReplayInspection
    inspectBoundary(std::size_t nodeIndex, ThreadTrace const& trace) const
    {
        return replayTrace(nodeIndex, trace, true, true);
    }

    ReplayInspection
    inspectPrepareBoundary(std::size_t nodeIndex,
                           ThreadTrace const& trace) const
    {
        auto prepareOptions = mOptions;
        prepareOptions.mStopOnPrepare = true;
        prepareOptions.mMaxNominationRound.reset();
        prepareOptions.mMaxBallotingRound.reset();
        return ScpDporDefaultScenario(std::move(prepareOptions))
            .inspectBoundary(nodeIndex, trace);
    }

    ReplayInspection
    inspectEmittedEnvelopes(std::size_t nodeIndex,
                            ThreadTrace const& trace) const
    {
        return replayTrace(nodeIndex, trace, false, false);
    }

    ThreadReplayTraceInspection
    inspectThreadReplayTrace(std::size_t nodeIndex,
                             ThreadTrace const& trace) const
    {
        ScpDporReplaySupport::clearThreadLocalCacheForCurrentThread();

        auto& node = mReplaySupport.acquireNode(nodeIndex);
        node.setEmittedEnvelopeRecordingEnabled(true);
        struct ReplayDebugRecordingGuard
        {
            DporScpNode& mNode;

            explicit ReplayDebugRecordingGuard(DporScpNode& node) : mNode(node)
            {
                mNode.setReplayDebugRecordingEnabled(true);
            }

            ~ReplayDebugRecordingGuard()
            {
                mNode.setReplayDebugRecordingEnabled(false);
            }
        } guard(node);
        mReplaySupport.restoreBaseline(node, nodeIndex);

        auto pendingSends = mInitialPendingSendsByNode.at(nodeIndex);
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
                auto choices = makeTimerChoices(activeTimers);
                auto const& observed = trace.at(observedCount);
                auto const timerID =
                    decodeAndValidateTimerChoice(observed, activeTimers);

                inspection.mSteps.push_back(ThreadReplayTraceStep{
                    .mKind =
                        ThreadReplayTraceStep::Kind::NondeterministicChoice,
                    .mChoice =
                        NondeterministicChoiceLabel{.value = choices.front(),
                                                    .choices =
                                                        std::move(choices)},
                    .mObservedValue = observed});
                selectedTimerID = timerID;
                ++observedCount;
                continue;
            }

            auto const timerToFire =
                resolveTimerToFire(selectedTimerID, activeTimers);

            ThreadReplayTraceStep step;
            step.mKind = ThreadReplayTraceStep::Kind::Receive;
            step.mReceive = makeReceiveLabel(timerToFire.has_value());
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
            updateSelectedTimerAfterObservation(node, replayed,
                                                selectedTimerID);
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
            config.mNodeIndexMap[options.mValidators.at(nodeIndex)
                                     .getPublicKey()] = nodeIndex + 1;
        }
        if (!options.mOutrightInvalidValuesByNode.empty() &&
            options.mOutrightInvalidValuesByNode.size() !=
                options.mValidators.size())
        {
            throw std::invalid_argument(
                "outright-invalid value lists must match validator count");
        }
        for (std::size_t nodeIndex = 0;
             nodeIndex < options.mOutrightInvalidValuesByNode.size();
             ++nodeIndex)
        {
            auto const& values =
                options.mOutrightInvalidValuesByNode.at(nodeIndex);
            std::set<Value> uniqueValues(values.begin(), values.end());
            if (uniqueValues.size() != values.size())
            {
                throw std::invalid_argument(
                    "outright-invalid value lists must not contain duplicates");
            }
            config.mOutrightInvalidValuesByNode.emplace(
                options.mValidators.at(nodeIndex).getPublicKey(),
                std::move(uniqueValues));
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
        config.mNominationAlwaysDownloadingTxSetStatus =
            options.mNominationAlwaysDownloading;
        config.mInjectEmptyTxSetProtocolGateFailureForTesting =
            options.mInjectEmptyTxSetProtocolGateFailureForTesting;
        switch (options.mTxSetStatusMode)
        {
        case TxSetStatusMode::AlwaysValid:
            config.mTxSetStatus = DporScpTxSetStatus::Valid;
            break;
        case TxSetStatusMode::DownloadingThenValid:
            config.mTxSetStatus = DporScpTxSetStatus::Valid;
            config.mNondeterministicTxSetStatus = true;
            config.mSupportedTxSetStatusChoices = {
                DporScpTxSetStatus::Downloading, DporScpTxSetStatus::Valid};
            break;
        case TxSetStatusMode::AlwaysDownloading:
            config.mTxSetStatus = DporScpTxSetStatus::Downloading;
            break;
        }
        config.mDownloadSucceedsInBallotRound =
            options.mDownloadSucceedsInRound;
        switch (options.mDownloadTimeMode)
        {
        case DownloadTimeMode::BelowThreshold:
            config.mTxSetDownloadWaitTimes = {std::chrono::milliseconds(
                DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1)};
            break;
        case DownloadTimeMode::AboveThreshold:
            config.mTxSetDownloadWaitTimes = {std::chrono::milliseconds(
                DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS + 1)};
            break;
        case DownloadTimeMode::Nondeterministic:
            config.mTxSetDownloadWaitTimes = {
                std::chrono::milliseconds(
                    DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1),
                std::chrono::milliseconds(
                    DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS + 1)};
            config.mNondeterministicTxSetDownloadWaitTime = true;
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

    std::vector<ScpDporValue>
    makeTimerChoices(std::vector<int> const& activeTimers) const
    {
        std::vector<ScpDporValue> choices;
        choices.reserve(activeTimers.size());
        for (auto const timerID : activeTimers)
        {
            choices.push_back(
                makeTimerChoiceValue(mOptions.mSlotIndex, timerID));
        }
        return choices;
    }

    static int
    decodeAndValidateTimerChoice(ObservedValue const& observed,
                                 std::vector<int> const& activeTimers)
    {
        if (observed.is_bottom())
        {
            throw std::logic_error(
                "trace does not contain a timer-choice observation");
        }
        auto const& observedValue = observed.value();
        if (!isTimerChoiceValue(observedValue))
        {
            throw std::logic_error("trace entry is not a timer-choice value");
        }
        auto const timerID = decodeTimerChoice(observedValue);
        if (std::find(activeTimers.begin(), activeTimers.end(), timerID) ==
            activeTimers.end())
        {
            throw std::logic_error("trace selected a timer that is not active");
        }
        return timerID;
    }

    static std::optional<int>
    resolveTimerToFire(std::optional<int> const& selectedTimerID,
                       std::vector<int> const& activeTimers)
    {
        if (selectedTimerID)
        {
            return selectedTimerID;
        }
        return activeTimers.size() == 1
                   ? std::optional<int>{activeTimers.front()}
                   : std::nullopt;
    }

    ReceiveLabel
    makeReceiveLabel(bool nonBlocking) const
    {
        auto const matcher =
            [slotIndex = mOptions.mSlotIndex](ScpDporValue const& value) {
                return isEnvelopeValue(value) && value.mSlotIndex == slotIndex;
            };
        return nonBlocking
                   ? dpor::model::make_nonblocking_receive_label<ScpDporValue>(
                         matcher)
                   : dpor::model::make_receive_label<ScpDporValue>(matcher);
    }

    void
    fanOutEnvelope(std::vector<SendLabel>& pendingSends,
                   std::size_t senderIndex, SCPEnvelope const& envelope) const
    {
        // One shared payload for every receiver: the fan-out copies only a
        // refcount instead of deep-copying the envelope per destination.
        auto const value = makeEnvelopeValue(mOptions.mSlotIndex, envelope);
        for (std::size_t receiverIndex = 0;
             receiverIndex < mOptions.mValidators.size(); ++receiverIndex)
        {
            if (receiverIndex == senderIndex)
            {
                continue;
            }
            pendingSends.push_back(
                SendLabel{.destination = threadIdForNodeIndex(receiverIndex),
                          .value = value});
        }
    }

    void
    queuePendingEnvelopeSends(std::vector<SendLabel>& pendingSends,
                              DporScpNode& node, std::size_t senderIndex) const
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

            auto const& value = observed.value();
            if (!isTxSetStatusChoiceValue(value) &&
                !isTxSetDownloadWaitTimeChoiceValue(value))
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
        node.setEmittedEnvelopeRecordingEnabled(true);
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
                selectedTimerID =
                    decodeAndValidateTimerChoice(observed, activeTimers);
                ++observedIndex;
                continue;
            }

            auto const activeTimers = enabledTimerIDs(node);
            auto const timerToFire =
                resolveTimerToFire(selectedTimerID, activeTimers);

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
            updateSelectedTimerAfterObservation(node, replayed,
                                                selectedTimerID);
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

    // Every label this returns is a function of the node state reached by
    // consuming `trace[0, observedCount)` only -- never of the trace beyond
    // that point -- which is what makes both the resume and the memo below
    // sound. The one exception is the nondeterministic-choice event surfaced
    // by `replayObservation`, which is raised from inside a partially applied
    // envelope; that path deliberately leaves the cursor invalid.
    std::optional<EventLabel>
    captureNextEvent(std::size_t nodeIndex, ThreadTrace const& trace,
                     std::size_t step) const
    {
        // A valid cursor here is guaranteed to have consumed a prefix of
        // `trace` and to have stopped at or before `step`.
        auto replayState =
            mReplaySupport.acquireReplayState(nodeIndex, trace, step);
        auto& node = replayState.mNode;
        auto& cursor = replayState.mCursor;
        node.setEmittedEnvelopeRecordingEnabled(false);

        if (cursor.mValid && cursor.mEventCount == step)
        {
            return cursor.mLabel;
        }

        if (!cursor.mValid)
        {
            mReplaySupport.restoreBaseline(node, nodeIndex);
            cursor.reset(mInitialPendingSendsByNode.at(nodeIndex));
        }
        cursor.mValid = false;

        auto const publish =
            [&cursor](
                std::optional<EventLabel> label) -> std::optional<EventLabel> {
            cursor.mLabel = std::move(label);
            cursor.mValid = true;
            return cursor.mLabel;
        };

        while (true)
        {
            if (cursor.mNextPendingSend < cursor.mPendingSends.size())
            {
                if (cursor.mEventCount == step)
                {
                    return publish(EventLabel{
                        cursor.mPendingSends.at(cursor.mNextPendingSend)});
                }
                ++cursor.mNextPendingSend;
                ++cursor.mEventCount;
                continue;
            }

            if (node.hasReachedBoundary())
            {
                return publish(std::nullopt);
            }

            auto const activeTimers = enabledTimerIDs(node);
            if (!cursor.mSelectedTimerID && activeTimers.size() > 1)
            {
                auto choices = makeTimerChoices(activeTimers);

                if (cursor.mEventCount == step)
                {
                    return publish(EventLabel{NondeterministicChoiceLabel{
                        .value = choices.front(),
                        .choices = std::move(choices)}});
                }
                ++cursor.mEventCount;

                auto const observedCount = cursor.mConsumedTrace.size();
                if (observedCount >= trace.size())
                {
                    throw std::logic_error(
                        "trace does not contain a timer-choice observation");
                }

                cursor.mSelectedTimerID = decodeAndValidateTimerChoice(
                    trace.at(observedCount), activeTimers);
                cursor.consume(trace.at(observedCount));
                continue;
            }

            auto const timerToFire =
                resolveTimerToFire(cursor.mSelectedTimerID, activeTimers);
            if (cursor.mEventCount == step)
            {
                return publish(
                    EventLabel{makeReceiveLabel(timerToFire.has_value())});
            }
            ++cursor.mEventCount;

            auto const observedCount = cursor.mConsumedTrace.size();
            if (observedCount >= trace.size())
            {
                throw std::logic_error(
                    "trace does not contain enough observations to replay the "
                    "requested step");
            }

            auto replayed = mReplaySupport.replayObservation(
                node, nodeIndex, trace, observedCount, timerToFire);
            if (replayed.mPendingEvent)
            {
                // The node stopped part-way through an envelope, so the cursor
                // cannot describe its state; leave it invalid so the next call
                // replays from the baseline.
                cursor.mEventCount += replayed.mConsumedTraceEntries - 1;
                if (cursor.mEventCount == step)
                {
                    return replayed.mPendingEvent;
                }
                throw std::logic_error(
                    "trace does not contain enough observations to replay the "
                    "requested step");
            }

            for (std::size_t i = 0; i < replayed.mConsumedTraceEntries; ++i)
            {
                cursor.consume(trace.at(observedCount + i));
            }
            cursor.mEventCount += replayed.mConsumedTraceEntries - 1;
            queuePendingEnvelopeSends(cursor.mPendingSends, node, nodeIndex);
            updateSelectedTimerAfterObservation(node, replayed,
                                                cursor.mSelectedTimerID);
        }
    }

    Options mOptions;
    ScpDporReplaySupport mReplaySupport;
    std::vector<std::vector<SendLabel>> mInitialPendingSendsByNode;
};

} // namespace stellar::scpdpor
