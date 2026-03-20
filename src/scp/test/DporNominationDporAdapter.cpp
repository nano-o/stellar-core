// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationDporAdapter.h"

#include "scp/BallotProtocol.h"
#include "scp/QuorumSetUtils.h"
#include "scp/Slot.h"

#include <algorithm>
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

constexpr std::uint8_t kBallotPhaseConfirm = 1;
constexpr std::uint8_t kBallotPhaseExternalize = 2;

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
        return value.mKind == DporNominationValue::Kind::Envelope &&
               value.mDestinationThread == destinationThread;
    };

    if (nonBlocking)
    {
        return dpor::model::make_nonblocking_receive_label<DporNominationValue>(
            std::move(matcher));
    }
    return dpor::model::make_receive_label<DporNominationValue>(
        std::move(matcher));
}

DporNominationValue
makeTxSetDownloadWaitTimeChoiceValue(std::chrono::milliseconds waitTime)
{
    DporNominationValue value;
    value.mKind = DporNominationValue::Kind::TxSetDownloadWaitTimeChoice;
    value.mTxSetDownloadWaitTimeMilliseconds = waitTime.count();
    return value;
}

bool
isTxSetDownloadWaitTimeChoiceValue(DporNominationValue const& value)
{
    return value.mKind ==
           DporNominationValue::Kind::TxSetDownloadWaitTimeChoice;
}

std::chrono::milliseconds
getTxSetDownloadWaitTimeChoice(DporNominationValue const& value)
{
    if (!isTxSetDownloadWaitTimeChoiceValue(value))
    {
        throw std::logic_error(
            "value is not a txset download wait time choice");
    }
    return std::chrono::milliseconds{
        value.mTxSetDownloadWaitTimeMilliseconds};
}

DporNominationDporAdapter::EventLabel
makeTxSetDownloadWaitTimeChoiceEvent(
    std::vector<std::chrono::milliseconds> const& waitTimes)
{
    std::vector<DporNominationValue> choices;
    choices.reserve(waitTimes.size());
    for (auto const& waitTime : waitTimes)
    {
        choices.push_back(makeTxSetDownloadWaitTimeChoiceValue(waitTime));
    }
    if (choices.empty())
    {
        throw std::logic_error(
            "nondeterministic txset download wait time choices are empty");
    }

    return DporNominationDporAdapter::EventLabel{
        dpor::model::NondeterministicChoiceLabelT<DporNominationValue>{
            .value = choices.front(),
            .choices = std::move(choices),
        }};
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
    operator==(ReplayStateCacheKey const& other) const
    {
        return mAdapter == other.mAdapter &&
               mNodeIndex == other.mNodeIndex &&
               mGeneration == other.mGeneration;
    }
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

int
compareBallots(SCPBallot const& lhs, SCPBallot const& rhs)
{
    if (lhs.counter < rhs.counter)
    {
        return -1;
    }
    if (rhs.counter < lhs.counter)
    {
        return 1;
    }
    if (lhs.value < rhs.value)
    {
        return -1;
    }
    if (rhs.value < lhs.value)
    {
        return 1;
    }
    return 0;
}

bool
areBallotsCompatible(SCPBallot const& lhs, SCPBallot const& rhs)
{
    return lhs.value == rhs.value;
}

bool
areBallotsLessAndCompatible(SCPBallot const& lhs, SCPBallot const& rhs)
{
    return compareBallots(lhs, rhs) <= 0 && areBallotsCompatible(lhs, rhs);
}

bool
areBallotsLessAndIncompatible(SCPBallot const& lhs, SCPBallot const& rhs)
{
    return compareBallots(lhs, rhs) <= 0 && !areBallotsCompatible(lhs, rhs);
}

template <typename ValueContainer>
bool
isStrictlySorted(ValueContainer const& values)
{
    return std::adjacent_find(values.begin(), values.end(),
                              [](Value const& lhs, Value const& rhs) {
                                  return !(lhs < rhs);
                              }) == values.end();
}

std::optional<std::string>
checkNominationStatementSane(SCPStatement const& statement)
{
    auto const& nomination = statement.pledges.nominate();
    if ((nomination.votes.size() + nomination.accepted.size()) == 0)
    {
        return "nomination statement is empty";
    }
    if (!isStrictlySorted(nomination.votes))
    {
        return "nomination votes are not strictly sorted";
    }
    if (!isStrictlySorted(nomination.accepted))
    {
        return "nomination accepted values are not strictly sorted";
    }
    return std::nullopt;
}

std::optional<std::string>
checkBallotStatementSane(DporNominationNode const& node,
                         SCPStatement const& statement)
{
    auto const qSetHash =
        BallotProtocol::getCompanionQuorumSetHashFromStatement(statement);
    auto const qSet = node.getStoredQuorumSet(qSetHash);
    if (!qSet)
    {
        return "ballot statement references an unknown quorum set";
    }

    char const* errString = nullptr;
    if (!isQuorumSetSane(*qSet, false, errString))
    {
        if (errString != nullptr)
        {
            return std::string("ballot statement references an invalid quorum "
                               "set: ") +
                   errString;
        }
        return "ballot statement references an invalid quorum set";
    }

    switch (statement.pledges.type())
    {
    case SCP_ST_PREPARE:
    {
        auto const& prepare = statement.pledges.prepare();
        if (prepare.ballot.counter == 0)
        {
            return "prepare statement ballot counter is zero";
        }
        if (prepare.preparedPrime && prepare.prepared &&
            !areBallotsLessAndIncompatible(*prepare.preparedPrime,
                                           *prepare.prepared))
        {
            return "prepare statement preparedPrime is not below prepared and "
                   "incompatible";
        }
        if (prepare.nH != 0 &&
            (!prepare.prepared || prepare.nH > prepare.prepared->counter))
        {
            return "prepare statement nH exceeds prepared";
        }
        if (prepare.nC != 0 &&
            (prepare.nH == 0 || prepare.ballot.counter < prepare.nH ||
             prepare.nH < prepare.nC))
        {
            return "prepare statement violates nC <= nH <= ballot.counter";
        }
        return std::nullopt;
    }
    case SCP_ST_CONFIRM:
    {
        auto const& confirm = statement.pledges.confirm();
        if (confirm.ballot.counter == 0)
        {
            return "confirm statement ballot counter is zero";
        }
        if (confirm.nH > confirm.ballot.counter ||
            confirm.nCommit > confirm.nH)
        {
            return "confirm statement violates nCommit <= nH <= ballot.counter";
        }
        return std::nullopt;
    }
    case SCP_ST_EXTERNALIZE:
    {
        auto const& externalize = statement.pledges.externalize();
        if (externalize.commit.counter == 0)
        {
            return "externalize statement commit counter is zero";
        }
        if (externalize.nH < externalize.commit.counter)
        {
            return "externalize statement violates commit.counter <= nH";
        }
        return std::nullopt;
    }
    default:
        return "ballot statement has an unknown pledge type";
    }
}

std::optional<std::string>
checkEnvelopeStatementSane(DporNominationNode const& node,
                           SCPEnvelope const& envelope)
{
    auto const& statement = envelope.statement;
    if (statement.pledges.type() == SCP_ST_NOMINATE)
    {
        return checkNominationStatementSane(statement);
    }
    return checkBallotStatementSane(node, statement);
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
DporNominationDporAdapter::setInvariantCheck(
    DporNominationNode::InvariantCheck const& fn)
{
    mConfig.mInvariantCheck = fn;
    rebuildReplayBaselines();
}

void
DporNominationDporAdapter::enableBuiltInSCPInvariantChecks(bool enable)
{
    mEnableBuiltInSCPInvariantChecks = enable;
    rebuildReplayBaselines();
}

std::optional<std::string>
DporNominationDporAdapter::checkBuiltInSCPInvariantViolation(
    DporNominationNode const& node,
    DporNominationNode::InvariantCheckContext const& context)
{
    if (context.mEvent ==
        DporNominationNode::InvariantCheckEvent::EnvelopeReceive)
    {
        if (!context.mEnvelope)
        {
            return "envelope receive invariant check is missing the envelope";
        }
        if (auto violation = checkEnvelopeStatementSane(node, *context.mEnvelope))
        {
            return violation;
        }
    }

    auto const replayBaseline = node.snapshotReplayBaseline(context.mSlotIndex);
    if (!replayBaseline.mSlotState)
    {
        return "slot state is missing during invariant evaluation";
    }

    auto const& slot = *replayBaseline.mSlotState;
    auto const& nomination = slot.mNominationState;
    auto const& ballot = slot.mBallotState;
    auto const nominationTimerActive =
        node.hasActiveTimer(context.mSlotIndex, Slot::NOMINATION_TIMER);
    auto const ballotTimerActive =
        node.hasActiveTimer(context.mSlotIndex, Slot::BALLOT_PROTOCOL_TIMER);

    if (ballot.mCurrentMessageLevel != 0)
    {
        return "ballot recursion level did not unwind to zero";
    }

    if (nomination.mNominationStarted && nomination.mPreviousValue.empty())
    {
        return "nomination started without a previous value";
    }

    if (!nomination.mCandidates.empty())
    {
        if (!nomination.mLatestCompositeCandidate)
        {
            return "nomination candidates exist without a composite candidate";
        }
        if (nominationTimerActive)
        {
            return "nomination timer remained active after a candidate was "
                   "ratified";
        }
    }

    if (ballot.mPhase > kBallotPhaseExternalize)
    {
        return "ballot phase snapshot is out of range";
    }

    if ((ballot.mPhase == kBallotPhaseConfirm ||
         ballot.mPhase == kBallotPhaseExternalize) &&
        (!ballot.mCurrentBallot || !ballot.mPrepared || !ballot.mCommit ||
         !ballot.mHighBallot))
    {
        return "confirm or externalize phase is missing required ballot state";
    }

    if (ballot.mCurrentBallot && ballot.mCurrentBallot->counter == 0)
    {
        return "current ballot counter is zero";
    }

    if (ballot.mPrepared && ballot.mPreparedPrime &&
        !areBallotsLessAndIncompatible(*ballot.mPreparedPrime,
                                       *ballot.mPrepared))
    {
        return "preparedPrime is not below prepared and incompatible";
    }

    if (ballot.mHighBallot)
    {
        if (!ballot.mCurrentBallot)
        {
            return "high ballot is set without a current ballot";
        }
        if (!areBallotsLessAndCompatible(*ballot.mHighBallot,
                                         *ballot.mCurrentBallot))
        {
            return "high ballot is not below the current ballot and "
                   "compatible";
        }
    }

    if (ballot.mCommit)
    {
        if (!ballot.mCurrentBallot || !ballot.mHighBallot)
        {
            return "commit ballot is set without current and high ballots";
        }
        if (!areBallotsLessAndCompatible(*ballot.mCommit, *ballot.mHighBallot))
        {
            return "commit ballot is not below the high ballot and "
                   "compatible";
        }
        if (!areBallotsLessAndCompatible(*ballot.mHighBallot,
                                         *ballot.mCurrentBallot))
        {
            return "high ballot is not below the current ballot and "
                   "compatible";
        }
    }

    if (ballotTimerActive)
    {
        if (!ballot.mCurrentBallot)
        {
            return "ballot timer is active without a current ballot";
        }
        if (!ballot.mHeardFromQuorum)
        {
            return "ballot timer is active without having heard from quorum";
        }
    }

    if (ballot.mPhase == kBallotPhaseExternalize)
    {
        if (nomination.mNominationStarted)
        {
            return "nomination remained started after externalize";
        }
        if (ballotTimerActive)
        {
            return "ballot timer remained active after externalize";
        }
    }

    return std::nullopt;
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
        maybeRecordInvariantViolation(
            state,
            DporNominationNode::InvariantCheckContext{
                .mEvent = DporNominationNode::InvariantCheckEvent::
                    InitialNomination,
                .mSlotIndex = mSlotIndex,
            });
        break;
    case InitialStateMode::Balloting:
        state.mNode.startBalloting(mSlotIndex, initialValue);
        maybeRecordInvariantViolation(
            state,
            DporNominationNode::InvariantCheckContext{
                .mEvent = DporNominationNode::InvariantCheckEvent::
                    InitialBalloting,
                .mSlotIndex = mSlotIndex,
            });
        break;
    }
    queuePendingEnvelopeSends(state, nodeIndex);
}

void
DporNominationDporAdapter::restoreBaseline(ReplayState& state,
                                           std::size_t nodeIndex) const
{
    auto const& baseline = mReplayBaselines.at(nodeIndex);
    restoreNodeBaseline(state, nodeIndex, baseline.mNodeState);
    state.mPendingSends = baseline.mPendingSends;
    state.mPendingInvariantViolation = baseline.mPendingInvariantViolation;
}

void
DporNominationDporAdapter::restoreNodeBaseline(
    ReplayState& state, std::size_t nodeIndex,
    DporNominationNode::ReplayBaseline const& baseline) const
{
    state.mNode.restoreReplayBaseline(baseline);
    for (auto const& timer : baseline.mTimers)
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
            .mPendingInvariantViolation = state.mPendingInvariantViolation,
        });
    }

    mReplayBaselines = std::move(replayBaselines);
    ++mReplayCacheGeneration;
    mReplayMetrics = std::move(savedReplayMetrics);
}

void
DporNominationDporAdapter::replayObservation(ReplayState& state,
                                             std::size_t nodeIndex,
                                             ObservedValue const& observed) const
{
    auto& node = state.mNode;
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
        maybeRecordInvariantViolation(
            state,
            DporNominationNode::InvariantCheckContext{
                .mEvent = DporNominationNode::InvariantCheckEvent::TimerFire,
                .mSlotIndex = mSlotIndex,
                .mTimerID = *timerID,
            });
        return;
    }

    auto const& delivery = observed.value();
    if (isTxSetDownloadWaitTimeChoiceValue(delivery))
    {
        throw std::logic_error(
            "trace contains an unexpected txset download wait time choice");
    }
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
    maybeRecordInvariantViolation(
        state,
        DporNominationNode::InvariantCheckContext{
            .mEvent = DporNominationNode::InvariantCheckEvent::EnvelopeReceive,
            .mSlotIndex = mSlotIndex,
            .mEnvelope = delivery.mEnvelope,
        });
}

DporNominationDporAdapter::ReplayObservationProgress
DporNominationDporAdapter::replayObservation(ReplayState& state,
                                             std::size_t nodeIndex,
                                             ThreadTrace const& trace,
                                             std::size_t observedIndex) const
{
    if (observedIndex >= trace.size())
    {
        throw std::out_of_range("observed trace index out of range");
    }

    auto const applyWithMaybeChoice =
        [&](auto&& applyObservation) -> ReplayObservationProgress {
        auto const replayBaseline = state.mNode.snapshotReplayBaseline(mSlotIndex);
        auto const pendingInvariantViolation = state.mPendingInvariantViolation;
        std::vector<std::chrono::milliseconds> chosenWaitTimes;

        auto const restoreReplayCheckpoint = [&]() {
            restoreNodeBaseline(state, nodeIndex, replayBaseline);
            state.mPendingInvariantViolation = pendingInvariantViolation;
            for (auto const& waitTime : chosenWaitTimes)
            {
                state.mNode.enqueueTxSetDownloadWaitTimeChoice(waitTime);
            }
        };

        while (true)
        {
            restoreReplayCheckpoint();
            try
            {
                applyObservation();
                return ReplayObservationProgress{
                    .mConsumedTraceEntries = 1 + chosenWaitTimes.size(),
                    .mConsumedStepCount = chosenWaitTimes.size()};
            }
            catch (DporNominationNode::TxSetDownloadWaitTimeChoiceRequired
                       const& e)
            {
                auto const choiceIndex =
                    observedIndex + 1 + chosenWaitTimes.size();
                if (choiceIndex >= trace.size())
                {
                    return ReplayObservationProgress{
                        .mConsumedTraceEntries = 1 + chosenWaitTimes.size(),
                        .mConsumedStepCount = chosenWaitTimes.size(),
                        .mPendingEvent = makeTxSetDownloadWaitTimeChoiceEvent(
                            e.getChoices())};
                }

                auto const& choiceObserved = trace.at(choiceIndex);
                if (choiceObserved.is_bottom())
                {
                    throw std::logic_error(
                        "trace contains bottom where a txset download wait "
                        "time choice was required");
                }

                auto const& choiceValue = choiceObserved.value();
                if (!isTxSetDownloadWaitTimeChoiceValue(choiceValue))
                {
                    throw std::logic_error(
                        "trace entry is not a txset download wait time "
                        "choice");
                }

                auto const waitTime =
                    getTxSetDownloadWaitTimeChoice(choiceValue);
                if (std::find(e.getChoices().begin(), e.getChoices().end(),
                              waitTime) == e.getChoices().end())
                {
                    throw std::logic_error(
                        "trace chose an unsupported txset download wait "
                        "time");
                }

                chosenWaitTimes.push_back(waitTime);
            }
        }
    };

    auto const& observed = trace.at(observedIndex);
    return applyWithMaybeChoice(
        [&]() { replayObservation(state, nodeIndex, observed); });
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

void
DporNominationDporAdapter::maybeRecordInvariantViolation(
    ReplayState& state,
    DporNominationNode::InvariantCheckContext const& context) const
{
    if (state.mPendingInvariantViolation)
    {
        return;
    }

    state.mPendingInvariantViolation =
        evaluateInvariantViolation(state.mNode, context);
}

std::optional<std::string>
DporNominationDporAdapter::evaluateInvariantViolation(
    DporNominationNode const& node,
    DporNominationNode::InvariantCheckContext const& context) const
{
    if (mEnableBuiltInSCPInvariantChecks)
    {
        if (auto violation =
                checkBuiltInSCPInvariantViolation(node, context))
        {
            return violation;
        }
    }

    if (mConfig.mInvariantCheck)
    {
        return mConfig.mInvariantCheck(node, context);
    }
    return std::nullopt;
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
        if (state.mPendingInvariantViolation)
        {
            if (eventCount == step)
            {
                return finish(EventLabel{dpor::model::ErrorLabel{}});
            }
            throw std::logic_error(
                "trace advanced past a pending invariant error");
        }

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

        auto replayed =
            replayObservation(state, nodeIndex, trace, observedCount);
        if (replayed.mPendingEvent)
        {
            eventCount += replayed.mConsumedStepCount;
            if (eventCount == step)
            {
                return finish(replayed.mPendingEvent);
            }
            throw std::logic_error(
                "trace does not contain enough observations to replay the "
                "requested step");
        }

        observedCount += replayed.mConsumedTraceEntries;
        eventCount += replayed.mConsumedStepCount;

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

    for (std::size_t observedIndex = 0; observedIndex < trace.size();)
    {
        if (state.mNode.hasCrossedNominationBoundary())
        {
            break;
        }

        auto replayed =
            replayObservation(state, nodeIndex, trace, observedIndex);
        if (replayed.mPendingEvent)
        {
            break;
        }

        observedIndex += replayed.mConsumedTraceEntries;
        discardPendingEnvelopes(state.mNode);
        if (state.mPendingInvariantViolation)
        {
            break;
        }
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
