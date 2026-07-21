// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporScpNode.h"

#include "crypto/SHA.h"
#include "scp/LocalNode.h"
#include "scp/Slot.h"
#include "xdrpp/marshal.h"

#include <algorithm>
#include <limits>
#include <string>

namespace stellar
{

namespace
{

Hash
getQSetHash(SCPQuorumSet const& qSet)
{
    return sha256(xdr::xdr_to_opaque(qSet));
}

uint64
defaultValueHash(Value const& value)
{
    auto const digest = sha256(xdr::xdr_to_opaque(value));
    uint64 hash = 0;
    for (size_t i = 0; i < sizeof(hash); ++i)
    {
        hash = (hash << 8) | digest[i];
    }
    return hash;
}

std::vector<DporScpTxSetStatus> const&
allTxSetStatusChoices()
{
    static std::vector<DporScpTxSetStatus> const supportedChoices{
        DporScpTxSetStatus::Valid, DporScpTxSetStatus::Waiting,
        DporScpTxSetStatus::Invalid};
    return supportedChoices;
}

DporScpTxSetStatus
consumeTxSetStatusChoice(
    std::vector<DporScpTxSetStatus> const& pendingChoices,
    std::size_t& nextChoice,
    std::vector<DporScpTxSetStatus> const& supportedChoices)
{
    if (supportedChoices.empty())
    {
        throw std::logic_error("supported txset status choices must not be empty");
    }
    if (nextChoice >= pendingChoices.size())
    {
        throw DporScpNode::TxSetStatusChoiceRequired(supportedChoices);
    }

    auto const status = pendingChoices.at(nextChoice++);
    if (std::find(supportedChoices.begin(), supportedChoices.end(), status) ==
        supportedChoices.end())
    {
        throw std::logic_error("preloaded txset status choice is not supported");
    }
    return status;
}

std::vector<std::chrono::milliseconds>
supportedTxSetDownloadWaitTimeChoices(
    std::vector<std::chrono::milliseconds> const& waitTimes)
{
    if (waitTimes.size() < 2 || waitTimes.front() == waitTimes.at(1))
    {
        return {};
    }
    return {waitTimes.front(), waitTimes.at(1)};
}

SCPDriver::ValidationLevel
validationLevelForTxSetStatus(DporScpTxSetStatus status)
{
    switch (status)
    {
    case DporScpTxSetStatus::Valid:
        return SCPDriver::kFullyValidatedValue;
    case DporScpTxSetStatus::Waiting:
        return SCPDriver::kStructurallyValidValue;
    case DporScpTxSetStatus::Invalid:
        return SCPDriver::kInvalidValue;
    }
    throw std::logic_error("unknown txset status");
}

} // namespace

DporScpNode::TxSetDownloadWaitTimeChoiceRequired::
    TxSetDownloadWaitTimeChoiceRequired(
        std::vector<std::chrono::milliseconds> choices)
    : std::runtime_error("txset download wait time choice is required")
    , mChoices(std::move(choices))
{
}

std::vector<std::chrono::milliseconds> const&
DporScpNode::TxSetDownloadWaitTimeChoiceRequired::getChoices() const
{
    return mChoices;
}

DporScpNode::TxSetStatusChoiceRequired::TxSetStatusChoiceRequired(
    std::vector<DporScpTxSetStatus> choices)
    : std::runtime_error("txset status choice is required")
    , mChoices(std::move(choices))
{
}

std::vector<DporScpTxSetStatus> const&
DporScpNode::TxSetStatusChoiceRequired::getChoices() const
{
    return mChoices;
}

DporScpNode::DporScpNode(SecretKey const& secretKey,
                         SCPQuorumSet const& localQSet)
    : DporScpNode(secretKey, localQSet, Configuration{})
{
}

DporScpNode::DporScpNode(SecretKey const& secretKey,
                         SCPQuorumSet const& localQSet,
                         Configuration const& config)
    : mSecretKey(secretKey)
    , mSCP(*this, mSecretKey.getPublicKey(), true, localQSet)
    , mValueHash(defaultValueHash)
{
    storeQuorumSet(localQSet);
    storeQuorumSet(mSCP.getLocalNode()->getQuorumSet());
    applyConfiguration(config);
}

NodeID const&
DporScpNode::getNodeID() const
{
    return mSecretKey.getPublicKey();
}

SCP&
DporScpNode::getSCP()
{
    return mSCP;
}

SCP const&
DporScpNode::getSCP() const
{
    return mSCP;
}

void
DporScpNode::storeQuorumSet(SCPQuorumSet const& qSet)
{
    mQuorumSets[getQSetHash(qSet)] = std::make_shared<SCPQuorumSet>(qSet);
}

SCPQuorumSetPtr
DporScpNode::getStoredQuorumSet(Hash const& qSetHash) const
{
    auto const it = mQuorumSets.find(qSetHash);
    if (it == mQuorumSets.end())
    {
        return nullptr;
    }
    return it->second;
}

bool
DporScpNode::nominate(uint64 slotIndex, Value const& value,
                      Value const& previousValue)
{
    return mSCP.nominate(slotIndex, wrapValue(value), previousValue);
}

bool
DporScpNode::startBalloting(uint64 slotIndex, Value const& value)
{
    auto slot = mSCP.getSlot(slotIndex, true);
    return slot->bumpState(value, true);
}

SCP::EnvelopeState
DporScpNode::receiveEnvelope(SCPEnvelope const& envelope)
{
    return mSCP.receiveEnvelope(wrapEnvelope(envelope));
}

void
DporScpNode::setStateFromEnvelope(uint64 slotIndex, SCPEnvelope const& envelope)
{
    mSCP.setStateFromEnvelope(slotIndex, wrapEnvelope(envelope));
}

std::vector<SCPEnvelope>
DporScpNode::takePendingEnvelopes()
{
    auto pending = std::move(mPendingEnvelopes);
    mPendingEnvelopes.clear();
    return pending;
}

std::vector<SCPEnvelope> const&
DporScpNode::getEmittedEnvelopes() const
{
    return mEmittedEnvelopes;
}

bool
DporScpNode::hasActiveTimer(uint64 slotIndex, int timerID) const
{
    return findTimer(slotIndex, timerID) != nullptr;
}

std::optional<DporScpNode::TimerState>
DporScpNode::getTimer(uint64 slotIndex, int timerID) const
{
    auto const* timer = findTimer(slotIndex, timerID);
    if (!timer)
    {
        return std::nullopt;
    }
    return *timer;
}

bool
DporScpNode::fireTimer(uint64 slotIndex, int timerID)
{
    auto const it = std::find_if(
        mTimers.begin(), mTimers.end(),
        [slotIndex, timerID](TimerState const& timer) {
            return timer.mSlotIndex == slotIndex && timer.mTimerID == timerID;
        });
    if (it == mTimers.end())
    {
        return false;
    }

    auto cb = it->mCallback;
    recordReplayDebugEvent(ReplayDebugEvent{
        .mKind = ReplayDebugEvent::Kind::FireTimer,
        .mSlotIndex = slotIndex,
        .mTimerID = timerID,
        .mTimeout = it->mTimeout});
    mTimers.erase(it);
    if (cb)
    {
        cb();
    }
    return true;
}

void
DporScpNode::enqueueTxSetStatusChoice(DporScpTxSetStatus status)
{
    mPendingTxSetStatusChoices.push_back(status);
}

void
DporScpNode::enqueueTxSetDownloadWaitTimeChoice(
    std::chrono::milliseconds waitTime)
{
    mPendingTxSetDownloadWaitTimeChoices.push_back(waitTime);
}

void
DporScpNode::setReplayDebugRecordingEnabled(bool enabled)
{
    mReplayDebugRecordingEnabled = enabled;
    if (!enabled)
    {
        mReplayDebugEvents.clear();
    }
}

std::vector<DporScpNode::ReplayDebugEvent>
DporScpNode::takeReplayDebugEvents()
{
    auto events = std::move(mReplayDebugEvents);
    mReplayDebugEvents.clear();
    return events;
}

DporScpNode::ReplayBaseline
DporScpNode::snapshotReplayBaseline(uint64 slotIndex) const
{
    ReplayBaseline baseline;

    auto slot = const_cast<SCP&>(mSCP).getSlot(slotIndex, false);
    if (slot)
    {
        SlotStateSnapshot slotSnapshot;
        slotSnapshot.mSlotIndex = slot->mSlotIndex;
        slotSnapshot.mFullyValidated = slot->mFullyValidated;
        slotSnapshot.mGotVBlocking = slot->mGotVBlocking;

        slotSnapshot.mStatementsHistory.reserve(slot->mStatementsHistory.size());
        for (auto const& historicalStatement : slot->mStatementsHistory)
        {
            slotSnapshot.mStatementsHistory.push_back(
                HistoricalStatementSnapshot{
                    .mWhen = historicalStatement.mWhen,
                    .mStatement = historicalStatement.mStatement,
                    .mValidated = historicalStatement.mValidated,
                });
        }

        auto const snapshotValueSet = [](ValueWrapperPtrSet const& values) {
            std::vector<Value> snapshot;
            snapshot.reserve(values.size());
            for (auto const& value : values)
            {
                snapshot.push_back(value->getValue());
            }
            return snapshot;
        };

        auto const snapshotEnvelopeMap = [](auto const& envelopes) {
            std::vector<SCPEnvelope> snapshot;
            snapshot.reserve(envelopes.size());
            for (auto const& [nodeID, envelope] : envelopes)
            {
                static_cast<void>(nodeID);
                snapshot.push_back(envelope->getEnvelope());
            }
            return snapshot;
        };

        auto const& nomination = slot->mNominationProtocol;
        slotSnapshot.mNominationState.mRoundNumber = nomination.mRoundNumber;
        slotSnapshot.mNominationState.mVotes =
            snapshotValueSet(nomination.mVotes);
        slotSnapshot.mNominationState.mAccepted =
            snapshotValueSet(nomination.mAccepted);
        slotSnapshot.mNominationState.mCandidates =
            snapshotValueSet(nomination.mCandidates);
        slotSnapshot.mNominationState.mLatestNominations =
            snapshotEnvelopeMap(nomination.mLatestNominations);
        if (nomination.mLastEnvelope)
        {
            slotSnapshot.mNominationState.mLastEnvelope =
                nomination.mLastEnvelope->getEnvelope();
        }
        slotSnapshot.mNominationState.mRoundLeaders.assign(
            nomination.mRoundLeaders.begin(), nomination.mRoundLeaders.end());
        slotSnapshot.mNominationState.mNominationStarted =
            nomination.mNominationStarted;
        if (nomination.mLatestCompositeCandidate)
        {
            slotSnapshot.mNominationState.mLatestCompositeCandidate =
                nomination.mLatestCompositeCandidate->getValue();
        }
        slotSnapshot.mNominationState.mPreviousValue = nomination.mPreviousValue;
        slotSnapshot.mNominationState.mTimerExpCount =
            nomination.mTimerExpCount;

        auto const snapshotBallot =
            [](BallotProtocol::SCPBallotWrapperUPtr const& ballot)
            -> std::optional<SCPBallot> {
            if (!ballot)
            {
                return std::nullopt;
            }
            return ballot->getBallot();
        };

        auto const& ballot = slot->mBallotProtocol;
        slotSnapshot.mBallotState.mHeardFromQuorum = ballot.mHeardFromQuorum;
        slotSnapshot.mBallotState.mCurrentBallot =
            snapshotBallot(ballot.mCurrentBallot);
        slotSnapshot.mBallotState.mPrepared =
            snapshotBallot(ballot.mPrepared);
        slotSnapshot.mBallotState.mPreparedPrime =
            snapshotBallot(ballot.mPreparedPrime);
        slotSnapshot.mBallotState.mHighBallot =
            snapshotBallot(ballot.mHighBallot);
        slotSnapshot.mBallotState.mCommit = snapshotBallot(ballot.mCommit);
        slotSnapshot.mBallotState.mLatestEnvelopes =
            snapshotEnvelopeMap(ballot.mLatestEnvelopes);
        slotSnapshot.mBallotState.mPhase =
            static_cast<std::uint8_t>(ballot.mPhase);
        if (ballot.mValueOverride)
        {
            slotSnapshot.mBallotState.mValueOverride =
                ballot.mValueOverride->getValue();
        }
        slotSnapshot.mBallotState.mCurrentMessageLevel =
            ballot.mCurrentMessageLevel;
        slotSnapshot.mBallotState.mTimerExpCount = ballot.mTimerExpCount;
        if (ballot.mLastEnvelope)
        {
            slotSnapshot.mBallotState.mLastEnvelope =
                ballot.mLastEnvelope->getEnvelope();
        }
        if (ballot.mLastEnvelopeEmit)
        {
            slotSnapshot.mBallotState.mLastEnvelopeEmit =
                ballot.mLastEnvelopeEmit->getEnvelope();
        }

        baseline.mSlotState = std::move(slotSnapshot);
    }

    baseline.mEmittedEnvelopes = mEmittedEnvelopes;
    baseline.mTimers.reserve(mTimers.size());
    for (auto const& timer : mTimers)
    {
        baseline.mTimers.push_back(
            ReplayTimerSnapshot{.mSlotIndex = timer.mSlotIndex,
                                .mTimerID = timer.mTimerID,
                                .mTimeout = timer.mTimeout});
    }
    baseline.mTimerSetCounts.reserve(mTimerSetCounts.size());
    for (auto const& count : mTimerSetCounts)
    {
        baseline.mTimerSetCounts.push_back(
            ReplayTimerSetCountSnapshot{.mSlotIndex = count.mSlotIndex,
                                        .mTimerID = count.mTimerID,
                                        .mCount = count.mCount});
    }
    baseline.mLastTxSetStatusByValue = mLastTxSetStatusByValue;
    baseline.mPendingTxSetDownloadStatusCounts =
        mPendingTxSetDownloadStatusCounts;
    baseline.mLastTxSetDownloadWaitTimeByValue =
        mLastTxSetDownloadWaitTimeByValue;
    baseline.mTxSetDownloadWaitTimeCallCount =
        mTxSetDownloadWaitTimeCallCount;
    baseline.mTxSetDownloadSucceeded = mTxSetDownloadSucceeded;
    baseline.mHasReachedBoundary = mHasReachedBoundary;
    baseline.mBoundaryEnvelope = mBoundaryEnvelope;
    return baseline;
}

void
DporScpNode::restoreReplayBaseline(ReplayBaseline const& baseline)
{
    clearReplayState();

    if (baseline.mSlotState)
    {
        auto const& slotSnapshot = *baseline.mSlotState;
        auto slot = mSCP.getSlot(slotSnapshot.mSlotIndex, true);

        slot->mFullyValidated = slotSnapshot.mFullyValidated;
        slot->mGotVBlocking = slotSnapshot.mGotVBlocking;
        slot->mStatementsHistory.clear();
        slot->mStatementsHistory.reserve(slotSnapshot.mStatementsHistory.size());
        for (auto const& historicalStatement :
             slotSnapshot.mStatementsHistory)
        {
            slot->mStatementsHistory.push_back(Slot::HistoricalStatement{
                .mWhen = historicalStatement.mWhen,
                .mStatement = historicalStatement.mStatement,
                .mValidated = historicalStatement.mValidated,
            });
        }

        auto const restoreValueSet = [this](std::vector<Value> const& values) {
            ValueWrapperPtrSet restored;
            for (auto const& value : values)
            {
                restored.emplace(wrapValue(value));
            }
            return restored;
        };

        auto const restoreEnvelopeMap =
            [this](std::vector<SCPEnvelope> const& envelopes) {
                std::map<NodeID, SCPEnvelopeWrapperPtr> restored;
                for (auto const& envelope : envelopes)
                {
                    restored[envelope.statement.nodeID] =
                        wrapEnvelope(envelope);
                }
                return restored;
            };

        auto& nomination = slot->mNominationProtocol;
        nomination.mRoundNumber = slotSnapshot.mNominationState.mRoundNumber;
        nomination.mVotes =
            restoreValueSet(slotSnapshot.mNominationState.mVotes);
        nomination.mAccepted =
            restoreValueSet(slotSnapshot.mNominationState.mAccepted);
        nomination.mCandidates =
            restoreValueSet(slotSnapshot.mNominationState.mCandidates);
        nomination.mLatestNominations = restoreEnvelopeMap(
            slotSnapshot.mNominationState.mLatestNominations);
        nomination.mLastEnvelope.reset();
        if (slotSnapshot.mNominationState.mLastEnvelope)
        {
            nomination.mLastEnvelope =
                wrapEnvelope(*slotSnapshot.mNominationState.mLastEnvelope);
        }
        nomination.mRoundLeaders = std::set<NodeID>(
            slotSnapshot.mNominationState.mRoundLeaders.begin(),
            slotSnapshot.mNominationState.mRoundLeaders.end());
        nomination.mNominationStarted =
            slotSnapshot.mNominationState.mNominationStarted;
        nomination.mLatestCompositeCandidate.reset();
        if (slotSnapshot.mNominationState.mLatestCompositeCandidate)
        {
            auto const& latestCompositeCandidate =
                *slotSnapshot.mNominationState.mLatestCompositeCandidate;
            for (auto const& candidate : nomination.mCandidates)
            {
                if (candidate->getValue() == latestCompositeCandidate)
                {
                    nomination.mLatestCompositeCandidate = candidate;
                    break;
                }
            }
            if (!nomination.mLatestCompositeCandidate)
            {
                nomination.mLatestCompositeCandidate =
                    wrapValue(latestCompositeCandidate);
            }
        }
        nomination.mPreviousValue = slotSnapshot.mNominationState.mPreviousValue;
        nomination.mTimerExpCount =
            slotSnapshot.mNominationState.mTimerExpCount;

        auto const restoreBallot =
            [&slot](std::optional<SCPBallot> const& ballot)
            -> BallotProtocol::SCPBallotWrapperUPtr {
            if (!ballot)
            {
                return nullptr;
            }
            return slot->mBallotProtocol.makeBallot(*ballot);
        };

        auto& ballot = slot->mBallotProtocol;
        ballot.mHeardFromQuorum = slotSnapshot.mBallotState.mHeardFromQuorum;
        ballot.mCurrentBallot =
            restoreBallot(slotSnapshot.mBallotState.mCurrentBallot);
        ballot.mPrepared = restoreBallot(slotSnapshot.mBallotState.mPrepared);
        ballot.mPreparedPrime =
            restoreBallot(slotSnapshot.mBallotState.mPreparedPrime);
        ballot.mHighBallot =
            restoreBallot(slotSnapshot.mBallotState.mHighBallot);
        ballot.mCommit = restoreBallot(slotSnapshot.mBallotState.mCommit);
        ballot.mLatestEnvelopes =
            restoreEnvelopeMap(slotSnapshot.mBallotState.mLatestEnvelopes);
        ballot.mPhase = static_cast<BallotProtocol::SCPPhase>(
            slotSnapshot.mBallotState.mPhase);
        ballot.mValueOverride.reset();
        if (slotSnapshot.mBallotState.mValueOverride)
        {
            ballot.mValueOverride =
                wrapValue(*slotSnapshot.mBallotState.mValueOverride);
        }
        ballot.mCurrentMessageLevel =
            slotSnapshot.mBallotState.mCurrentMessageLevel;
        ballot.mTimerExpCount = slotSnapshot.mBallotState.mTimerExpCount;
        ballot.mLastEnvelope.reset();
        if (slotSnapshot.mBallotState.mLastEnvelope)
        {
            ballot.mLastEnvelope =
                wrapEnvelope(*slotSnapshot.mBallotState.mLastEnvelope);
        }
        ballot.mLastEnvelopeEmit.reset();
        if (slotSnapshot.mBallotState.mLastEnvelopeEmit)
        {
            ballot.mLastEnvelopeEmit =
                wrapEnvelope(*slotSnapshot.mBallotState.mLastEnvelopeEmit);
        }
    }

    mEmittedEnvelopes = baseline.mEmittedEnvelopes;
    for (auto const& timerSetCount : baseline.mTimerSetCounts)
    {
        mTimerSetCounts.push_back(TimerSetCountEntry{
            .mSlotIndex = timerSetCount.mSlotIndex,
            .mTimerID = timerSetCount.mTimerID,
            .mCount = timerSetCount.mCount});
    }
    mLastTxSetStatusByValue = baseline.mLastTxSetStatusByValue;
    mPendingTxSetDownloadStatusCounts =
        baseline.mPendingTxSetDownloadStatusCounts;
    mLastTxSetDownloadWaitTimeByValue =
        baseline.mLastTxSetDownloadWaitTimeByValue;
    mTxSetDownloadWaitTimeCallCount =
        baseline.mTxSetDownloadWaitTimeCallCount;
    mTxSetDownloadSucceeded = baseline.mTxSetDownloadSucceeded;
    mHasReachedBoundary = baseline.mHasReachedBoundary;
    mBoundaryEnvelope = baseline.mBoundaryEnvelope;
}

void
DporScpNode::installNominationReplayTimer(
    uint64 slotIndex, std::chrono::milliseconds timeout, Value const& value,
    Value const& previousValue)
{
    auto slot = mSCP.getSlot(slotIndex, true);
    auto wrappedValue = wrapValue(value);
    setTimer(TimerState{slotIndex, Slot::NOMINATION_TIMER, timeout,
                        [slot, wrappedValue, previousValue]() {
                            slot->nominate(wrappedValue, previousValue, true);
                        }});
}

void
DporScpNode::installBallotingReplayTimer(
    uint64 slotIndex, std::chrono::milliseconds timeout)
{
    auto slot = mSCP.getSlot(slotIndex, true);
    setTimer(TimerState{slotIndex, Slot::BALLOT_PROTOCOL_TIMER, timeout,
                        [slot]() {
                            slot->getBallotProtocol().ballotProtocolTimerExpired();
                        }});
}

bool
DporScpNode::hasReachedBoundary() const
{
    return mHasReachedBoundary;
}

bool
DporScpNode::hasReachedPrepareBoundary() const
{
    return mBoundaryEnvelope &&
           mBoundaryEnvelope->statement.pledges.type() == SCP_ST_PREPARE;
}

SCPEnvelope const*
DporScpNode::getBoundaryEnvelope() const
{
    return mBoundaryEnvelope ? &*mBoundaryEnvelope : nullptr;
}

SCPEnvelope const*
DporScpNode::getPrepareBoundaryEnvelope() const
{
    return hasReachedPrepareBoundary() ? getBoundaryEnvelope() : nullptr;
}

void
DporScpNode::signEnvelope(SCPEnvelope&)
{
}

SCPQuorumSetPtr
DporScpNode::getQSet(Hash const& qSetHash)
{
    auto const it = mQuorumSets.find(qSetHash);
    if (it == mQuorumSets.end())
    {
        return nullptr;
    }
    return it->second;
}

bool
DporScpNode::isEnvelopeReady(SCPEnvelope const&) const
{
    // The DPOR model delivers envelopes directly to SCP, bypassing
    // PendingEnvelopes, so this SCPDriver hook is not called during DPOR
    // exploration. If that changes, readiness should be modeled in the
    // scenario layer rather than as an independent nondeterministic choice.
    return true;
}

std::optional<std::chrono::milliseconds>
DporScpNode::getTxSetDownloadWaitTime(Value const& value) const
{
    if (mTxSetDownloadSucceeded)
    {
        return std::nullopt;
    }

    if (mNondeterministicTxSetStatus)
    {
        auto const it = mPendingTxSetDownloadStatusCounts.find(value);
        if (it == mPendingTxSetDownloadStatusCounts.end())
        {
            return std::nullopt;
        }
        if (it->second <= 1)
        {
            mPendingTxSetDownloadStatusCounts.erase(it);
        }
        else
        {
            --mPendingTxSetDownloadStatusCounts[value];
        }
    }
    else if (mTxSetStatus != DporScpTxSetStatus::Waiting)
    {
        return std::nullopt;
    }

    auto const recordWaitTime = [this, &value](
                                    std::chrono::milliseconds waitTime) {
        mLastTxSetDownloadWaitTimeByValue[value] = waitTime;
        ++mTxSetDownloadWaitTimeCallCount;
        recordReplayDebugEvent(ReplayDebugEvent{
            .mKind = ReplayDebugEvent::Kind::UseTxSetDownloadWaitTime,
            .mWaitTime = waitTime});
        return waitTime;
    };

    auto const timeout = getTxSetDownloadTimeout();
    auto const supportedChoices =
        supportedTxSetDownloadWaitTimeChoices(mTxSetDownloadWaitTimes);
    if (mNondeterministicTxSetDownloadWaitTime && !supportedChoices.empty())
    {
        auto const lastWaitTimeIt =
            mLastTxSetDownloadWaitTimeByValue.find(value);
        if (lastWaitTimeIt != mLastTxSetDownloadWaitTimeByValue.end() &&
            lastWaitTimeIt->second >= timeout)
        {
            return recordWaitTime(lastWaitTimeIt->second);
        }

        if (mNextPendingTxSetDownloadWaitTimeChoice >=
            mPendingTxSetDownloadWaitTimeChoices.size())
        {
            throw TxSetDownloadWaitTimeChoiceRequired(supportedChoices);
        }

        auto const waitTime = mPendingTxSetDownloadWaitTimeChoices.at(
            mNextPendingTxSetDownloadWaitTimeChoice++);
        if (std::find(supportedChoices.begin(), supportedChoices.end(),
                      waitTime) == supportedChoices.end())
        {
            throw std::logic_error(
                "preloaded txset wait-time choice is not supported");
        }
        return recordWaitTime(waitTime);
    }

    if (mTxSetDownloadWaitTimes.empty())
    {
        return recordWaitTime(timeout);
    }

    auto index = mTxSetDownloadWaitTimeCallCount;
    if (index >= mTxSetDownloadWaitTimes.size())
    {
        index = mTxSetDownloadWaitTimes.size() - 1;
    }
    return recordWaitTime(mTxSetDownloadWaitTimes[index]);
}

std::chrono::milliseconds
DporScpNode::getTxSetDownloadTimeout() const
{
    return std::chrono::milliseconds{DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS};
}

void
DporScpNode::emitEnvelope(SCPEnvelope const& envelope)
{
    auto const alreadyReachedBoundary = mHasReachedBoundary;
    auto const reachesBoundaryNow =
        !alreadyReachedBoundary && isEnvelopeBoundaryForMode(envelope);

    if (reachesBoundaryNow)
    {
        mHasReachedBoundary = true;
        if (!mBoundaryEnvelope)
        {
            mBoundaryEnvelope = envelope;
        }
    }

    mEmittedEnvelopes.push_back(envelope);
    if (shouldMarkTxSetDownloadSucceeded(envelope))
    {
        markTxSetDownloadSucceeded();
    }
    recordReplayDebugEvent(
        ReplayDebugEvent{.mKind = ReplayDebugEvent::Kind::EmitEnvelope,
                         .mEnvelope = envelope,
                         .mBoundary = reachesBoundaryNow});
    if (!alreadyReachedBoundary && !reachesBoundaryNow)
    {
        mPendingEnvelopes.push_back(envelope);
    }
}

SCPDriver::ValidationLevel
DporScpNode::validateValue(uint64, Value const& value, bool nomination) const
{
    if (isEmptyTxSetValue(value))
    {
        return SCPDriver::kFullyValidatedValue;
    }
    if (nomination && mNominationAlwaysWaitingTxSetStatus)
    {
        return SCPDriver::kStructurallyValidValue;
    }
    if (mTxSetDownloadSucceeded)
    {
        return SCPDriver::kFullyValidatedValue;
    }
    DporScpTxSetStatus status = mTxSetStatus;
    if (mNondeterministicTxSetStatus)
    {
        auto const lastStatusIt = mLastTxSetStatusByValue.find(value);
        if (lastStatusIt != mLastTxSetStatusByValue.end() &&
            lastStatusIt->second != DporScpTxSetStatus::Waiting)
        {
            status = lastStatusIt->second;
        }
        else
        {
            status = consumeTxSetStatusChoice(mPendingTxSetStatusChoices,
                                              mNextPendingTxSetStatusChoice,
                                              mSupportedTxSetStatusChoices);
        }
    }

    mLastTxSetStatusByValue[value] = status;
    if (status == DporScpTxSetStatus::Waiting)
    {
        ++mPendingTxSetDownloadStatusCounts[value];
    }
    else
    {
        mPendingTxSetDownloadStatusCounts.erase(value);
    }
    return validationLevelForTxSetStatus(status);
}

#ifdef CAP_0083
Value
DporScpNode::makeEmptyTxSetValueFromValue(Value const& value) const
{
    Value emptyTxSetValue;
    emptyTxSetValue.resize(6 + value.size());
    emptyTxSetValue[0] = 'E';
    emptyTxSetValue[1] = 'M';
    emptyTxSetValue[2] = 'P';
    emptyTxSetValue[3] = 'T';
    emptyTxSetValue[4] = 'Y';
    emptyTxSetValue[5] = ':';
    std::copy(value.begin(), value.end(), emptyTxSetValue.begin() + 6);
    return emptyTxSetValue;
}
#endif // CAP_0083

bool
DporScpNode::isEmptyTxSetValue(Value const& value) const
{
    return value.size() >= 6 && value[0] == 'E' && value[1] == 'M' &&
           value[2] == 'P' && value[3] == 'T' && value[4] == 'Y' &&
           value[5] == ':';
}

bool
DporScpNode::isParallelTxSetDownloadEnabled() const
{
    return true;
}

bool
DporScpNode::protocolAllowsEmptyTxSetValues() const
{
    return mProtocolAllowsEmptyTxSetValues;
}

Hash
DporScpNode::getHashOf(std::vector<xdr::opaque_vec<>> const& vals) const
{
    SHA256 hasher;
    for (auto const& val : vals)
    {
        hasher.add(val);
    }
    return hasher.finish();
}

uint64
DporScpNode::computeHashNode(uint64 slotIndex, Value const& prev,
                             bool isPriority, int32_t roundNumber,
                             NodeID const& nodeID)
{
    if (!mNodeIndexMap.empty())
    {
        if (!isPriority)
        {
            return 0;
        }
        auto const it = mNodeIndexMap.find(nodeID);
        if (it != mNodeIndexMap.end())
        {
            auto const numNodes = static_cast<uint64>(mNodeIndexMap.size());
            auto const normalizedRound =
                static_cast<uint64>(std::max(roundNumber, 1));
            auto const selectedIndex = ((normalizedRound - 1) % numNodes) + 1;
            return it->second == selectedIndex
                       ? std::numeric_limits<uint64>::max()
                       : 0;
        }
    }
    return SCPDriver::computeHashNode(slotIndex, prev, isPriority, roundNumber,
                                      nodeID);
}

uint64
DporScpNode::computeValueHash(uint64, Value const&, int32_t,
                              Value const& value)
{
    return mValueHash(value);
}

ValueWrapperPtr
DporScpNode::combineCandidates(uint64 slotIndex,
                               ValueWrapperPtrSet const& candidates)
{
    if (mCombineCandidates)
    {
        return mCombineCandidates(slotIndex, candidates);
    }
    if (candidates.empty())
    {
        throw std::runtime_error("combineCandidates called with no candidates");
    }
    return *candidates.begin();
}

bool
DporScpNode::hasUpgrades(Value const&)
{
    return false;
}

ValueWrapperPtr
DporScpNode::stripAllUpgrades(Value const& value)
{
    return wrapValue(value);
}

uint32_t
DporScpNode::getUpgradeNominationTimeoutLimit() const
{
    return std::numeric_limits<uint32_t>::max();
}

uint32_t
DporScpNode::inferNominationRound(std::chrono::milliseconds timeout) const
{
    return inferTimeoutRound(timeout, mInitialNominationTimeoutMS,
                             mIncrementNominationTimeoutMS, "nomination");
}

uint32_t
DporScpNode::inferBallotingRound(std::chrono::milliseconds timeout) const
{
    return inferTimeoutRound(timeout, mInitialBallotTimeoutMS,
                             mIncrementBallotTimeoutMS, "balloting");
}

uint32_t
DporScpNode::inferTimeoutRound(std::chrono::milliseconds timeout,
                               uint32_t initialTimeoutMS,
                               uint32_t incrementTimeoutMS,
                               char const* timerName) const
{
    auto const timeoutMS = timeout.count();
    if (timeoutMS < static_cast<int64_t>(initialTimeoutMS))
    {
        throw std::logic_error(std::string(timerName) +
                               " timer timeout is below the configured "
                               "initial value");
    }

    if (incrementTimeoutMS == 0)
    {
        if (timeoutMS != static_cast<int64_t>(initialTimeoutMS))
        {
            throw std::logic_error(
                std::string(timerName) +
                " timer timeout does not match the configured constant "
                "timeout");
        }
        return 1;
    }

    auto const deltaMS = timeoutMS - static_cast<int64_t>(initialTimeoutMS);
    auto const incrementMS = static_cast<int64_t>(incrementTimeoutMS);
    if ((deltaMS % incrementMS) != 0)
    {
        throw std::logic_error(
            std::string(timerName) +
            " timer timeout does not match the configured round schedule");
    }

    return 1 + static_cast<uint32_t>(deltaMS / incrementMS);
}

void
DporScpNode::setupTimer(uint64 slotIndex, int timerID,
                        std::chrono::milliseconds timeout,
                        std::function<void()> cb)
{
    if (!cb)
    {
        recordReplayDebugEvent(
            ReplayDebugEvent{.mKind = ReplayDebugEvent::Kind::StopTimer,
                             .mSlotIndex = slotIndex,
                             .mTimerID = timerID});
        clearTimer(slotIndex, timerID);
        return;
    }

    if (timerID == Slot::NOMINATION_TIMER && mMaxNominationRound &&
        inferNominationRound(timeout) > *mMaxNominationRound)
    {
        mHasReachedBoundary = true;
    }
    if (timerID == Slot::BALLOT_PROTOCOL_TIMER && mMaxBallotingRound &&
        inferBallotingRound(timeout) > *mMaxBallotingRound)
    {
        mHasReachedBoundary = true;
    }

    auto* setCountEntry = findTimerSetCount(slotIndex, timerID);
    if (!setCountEntry)
    {
        mTimerSetCounts.push_back(
            TimerSetCountEntry{.mSlotIndex = slotIndex, .mTimerID = timerID});
        setCountEntry = &mTimerSetCounts.back();
    }
    auto const setCount = ++setCountEntry->mCount;
    auto const timerSetLimit = [&]() -> std::optional<uint32_t> {
        if (timerID == Slot::NOMINATION_TIMER)
        {
            return mNominationTimerSetLimit;
        }
        if (timerID == Slot::BALLOT_PROTOCOL_TIMER)
        {
            return mBallotingTimerSetLimit;
        }
        return std::nullopt;
    }();

    if (timerSetLimit && setCount >= *timerSetLimit)
    {
        recordReplayDebugEvent(
            ReplayDebugEvent{.mKind = ReplayDebugEvent::Kind::StopTimer,
                             .mSlotIndex = slotIndex,
                             .mTimerID = timerID});
        clearTimer(slotIndex, timerID);
        return;
    }

    recordReplayDebugEvent(
        ReplayDebugEvent{.mKind = ReplayDebugEvent::Kind::SetupTimer,
                         .mSlotIndex = slotIndex,
                         .mTimerID = timerID,
                         .mTimeout = timeout});
    setTimer(TimerState{slotIndex, timerID, timeout, std::move(cb)});
}

void
DporScpNode::stopTimer(uint64 slotIndex, int timerID)
{
    recordReplayDebugEvent(
        ReplayDebugEvent{.mKind = ReplayDebugEvent::Kind::StopTimer,
                         .mSlotIndex = slotIndex,
                         .mTimerID = timerID});
    clearTimer(slotIndex, timerID);
}

std::chrono::milliseconds
DporScpNode::computeTimeout(uint32 roundNumber, bool isNomination)
{
    auto const initialTimeoutMS =
        isNomination ? mInitialNominationTimeoutMS : mInitialBallotTimeoutMS;
    auto const incrementTimeoutMS = isNomination
                                        ? mIncrementNominationTimeoutMS
                                        : mIncrementBallotTimeoutMS;
    return std::chrono::milliseconds(initialTimeoutMS +
                                     (roundNumber - 1) * incrementTimeoutMS);
}

void
DporScpNode::applyConfiguration(Configuration const& config)
{
    mNodeIndexMap = config.mNodeIndexMap;
    if (config.mValueHash)
    {
        mValueHash = config.mValueHash;
    }
    if (config.mCombineCandidates)
    {
        mCombineCandidates = config.mCombineCandidates;
    }
    mPrepareBoundaryCounter =
        std::max<uint32_t>(1, config.mPrepareBoundaryCounter);
    mBoundaryMode = config.mBoundaryMode;
    mMaxNominationRound = config.mMaxNominationRound;
    mMaxBallotingRound = config.mMaxBallotingRound;
    mTxSetStatus = config.mTxSetStatus;
    mNondeterministicTxSetStatus = config.mNondeterministicTxSetStatus;
    mNominationAlwaysWaitingTxSetStatus =
        config.mNominationAlwaysWaitingTxSetStatus;
    mProtocolAllowsEmptyTxSetValues = config.mProtocolAllowsEmptyTxSetValues;
    mSupportedTxSetStatusChoices.clear();
    if (mNondeterministicTxSetStatus)
    {
        mSupportedTxSetStatusChoices = config.mSupportedTxSetStatusChoices;
        if (mSupportedTxSetStatusChoices.empty())
        {
            auto const& defaultChoices = allTxSetStatusChoices();
            mSupportedTxSetStatusChoices.assign(defaultChoices.begin(),
                                                defaultChoices.end());
        }

        auto const& allChoices = allTxSetStatusChoices();
        for (auto const status : mSupportedTxSetStatusChoices)
        {
            if (std::find(allChoices.begin(), allChoices.end(), status) ==
                allChoices.end())
            {
                throw std::logic_error(
                    "configured txset status choice is not supported");
            }
        }
    }
    mDownloadSucceedsInBallotRound = config.mDownloadSucceedsInBallotRound;
    mInitialNominationTimeoutMS = config.mInitialNominationTimeoutMS;
    mIncrementNominationTimeoutMS = config.mIncrementNominationTimeoutMS;
    mInitialBallotTimeoutMS = config.mInitialBallotTimeoutMS;
    mIncrementBallotTimeoutMS = config.mIncrementBallotTimeoutMS;

    auto const nodeWaitTimesIt =
        config.mTxSetDownloadWaitTimesByNode.find(getNodeID());
    if (nodeWaitTimesIt != config.mTxSetDownloadWaitTimesByNode.end())
    {
        mTxSetDownloadWaitTimes = nodeWaitTimesIt->second;
    }
    else
    {
        mTxSetDownloadWaitTimes = config.mTxSetDownloadWaitTimes;
    }
    mNondeterministicTxSetDownloadWaitTime =
        config.mNondeterministicTxSetDownloadWaitTime;
    mNominationTimerSetLimit = config.mNominationTimerSetLimit;
    mBallotingTimerSetLimit = config.mBallotingTimerSetLimit;
}

DporScpNode::TimerState*
DporScpNode::findTimer(uint64 slotIndex, int timerID)
{
    auto const it = std::find_if(
        mTimers.begin(), mTimers.end(),
        [slotIndex, timerID](TimerState const& timer) {
            return timer.mSlotIndex == slotIndex && timer.mTimerID == timerID;
        });
    return it == mTimers.end() ? nullptr : &*it;
}

DporScpNode::TimerState const*
DporScpNode::findTimer(uint64 slotIndex, int timerID) const
{
    auto const it = std::find_if(
        mTimers.begin(), mTimers.end(),
        [slotIndex, timerID](TimerState const& timer) {
            return timer.mSlotIndex == slotIndex && timer.mTimerID == timerID;
        });
    return it == mTimers.end() ? nullptr : &*it;
}

void
DporScpNode::setTimer(TimerState timer)
{
    if (auto* existing = findTimer(timer.mSlotIndex, timer.mTimerID))
    {
        *existing = std::move(timer);
        return;
    }
    mTimers.push_back(std::move(timer));
}

void
DporScpNode::clearTimer(uint64 slotIndex, int timerID)
{
    auto const it = std::find_if(
        mTimers.begin(), mTimers.end(),
        [slotIndex, timerID](TimerState const& timer) {
            return timer.mSlotIndex == slotIndex && timer.mTimerID == timerID;
        });
    if (it != mTimers.end())
    {
        mTimers.erase(it);
    }
}

DporScpNode::TimerSetCountEntry*
DporScpNode::findTimerSetCount(uint64 slotIndex, int timerID)
{
    auto const it = std::find_if(
        mTimerSetCounts.begin(), mTimerSetCounts.end(),
        [slotIndex, timerID](TimerSetCountEntry const& entry) {
            return entry.mSlotIndex == slotIndex && entry.mTimerID == timerID;
        });
    return it == mTimerSetCounts.end() ? nullptr : &*it;
}

void
DporScpNode::recordReplayDebugEvent(ReplayDebugEvent event) const
{
    if (!mReplayDebugRecordingEnabled)
    {
        return;
    }
    mReplayDebugEvents.push_back(std::move(event));
}

void
DporScpNode::clearReplayState()
{
    auto const slotToKeep = std::numeric_limits<uint64>::max();
    mSCP.purgeSlotsOutsideRange(1, std::nullopt, slotToKeep);
    mSCP.purgeSlotsOutsideRange(std::nullopt, 0, slotToKeep);
    mEmittedEnvelopes.clear();
    mPendingEnvelopes.clear();
    mTimers.clear();
    mTimerSetCounts.clear();
    mPendingTxSetStatusChoices.clear();
    mNextPendingTxSetStatusChoice = 0;
    mLastTxSetStatusByValue.clear();
    mPendingTxSetDownloadStatusCounts.clear();
    mLastTxSetDownloadWaitTimeByValue.clear();
    mPendingTxSetDownloadWaitTimeChoices.clear();
    mNextPendingTxSetDownloadWaitTimeChoice = 0;
    mTxSetDownloadWaitTimeCallCount = 0;
    mReplayDebugEvents.clear();
    mTxSetDownloadSucceeded = false;
    mHasReachedBoundary = false;
    mBoundaryEnvelope.reset();
}

void
DporScpNode::markTxSetDownloadSucceeded()
{
    if (mTxSetDownloadSucceeded)
    {
        return;
    }

    mTxSetDownloadSucceeded = true;
    mPendingTxSetStatusChoices.clear();
    mNextPendingTxSetStatusChoice = 0;
    mLastTxSetStatusByValue.clear();
    mPendingTxSetDownloadStatusCounts.clear();
    mLastTxSetDownloadWaitTimeByValue.clear();
    mPendingTxSetDownloadWaitTimeChoices.clear();
    mNextPendingTxSetDownloadWaitTimeChoice = 0;
}

bool
DporScpNode::shouldMarkTxSetDownloadSucceeded(
    SCPEnvelope const& envelope) const
{
    return !mTxSetDownloadSucceeded && mDownloadSucceedsInBallotRound &&
           envelope.statement.pledges.type() == SCP_ST_PREPARE &&
           envelope.statement.pledges.prepare().ballot.counter ==
               *mDownloadSucceedsInBallotRound;
}

bool
DporScpNode::isEnvelopeBoundaryForMode(SCPEnvelope const& envelope) const
{
    auto const type = envelope.statement.pledges.type();
    switch (mBoundaryMode)
    {
    case BoundaryMode::None:
        return false;
    case BoundaryMode::Prepare:
        return type == SCP_ST_PREPARE &&
               envelope.statement.pledges.prepare().ballot.counter >=
                   mPrepareBoundaryCounter;
    case BoundaryMode::Commit:
        return type == SCP_ST_CONFIRM || type == SCP_ST_EXTERNALIZE;
    case BoundaryMode::Externalize:
        return type == SCP_ST_EXTERNALIZE;
    case BoundaryMode::NominationRound:
        if (type != SCP_ST_NOMINATE)
        {
            return false;
        }
        if (!mMaxNominationRound)
        {
            throw std::logic_error(
                "nomination-round boundary requires max nomination rounds");
        }
        return getNominationRoundForEnvelope(envelope) > *mMaxNominationRound;
    }
    throw std::logic_error("unknown replay boundary mode");
}

uint32_t
DporScpNode::getNominationRoundForEnvelope(SCPEnvelope const& envelope) const
{
    if (envelope.statement.pledges.type() != SCP_ST_NOMINATE)
    {
        throw std::logic_error(
            "nomination round requested for non-nomination envelope");
    }

    auto slot =
        const_cast<SCP&>(mSCP).getSlot(envelope.statement.slotIndex, false);
    if (!slot)
    {
        throw std::logic_error(
            "nomination-round boundary requires local slot state");
    }
    return static_cast<uint32_t>(
        std::max<int32_t>(slot->mNominationProtocol.mRoundNumber, 0));
}

} // namespace stellar
