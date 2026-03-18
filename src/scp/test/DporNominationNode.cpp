// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationNode.h"

#include "crypto/SHA.h"
#include "scp/LocalNode.h"
#include "scp/Slot.h"
#include "xdrpp/marshal.h"

#include <limits>
#include <stdexcept>

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
    auto digest = sha256(xdr::xdr_to_opaque(value));
    uint64 hash = 0;
    for (size_t i = 0; i < sizeof(hash); ++i)
    {
        hash = (hash << 8) | digest[i];
    }
    return hash;
}

}

DporNominationNode::TxSetDownloadWaitTimeChoiceRequired::
    TxSetDownloadWaitTimeChoiceRequired(
        std::vector<std::chrono::milliseconds> choices)
    : std::runtime_error("txset download wait time choice is required")
    , mChoices(std::move(choices))
{
}

std::vector<std::chrono::milliseconds> const&
DporNominationNode::TxSetDownloadWaitTimeChoiceRequired::getChoices() const
{
    return mChoices;
}

DporNominationNode::DporNominationNode(SecretKey const& secretKey,
                                       SCPQuorumSet const& localQSet)
    : DporNominationNode(secretKey, localQSet, Configuration{})
{
}

DporNominationNode::DporNominationNode(SecretKey const& secretKey,
                                       SCPQuorumSet const& localQSet,
                                       Configuration const& config)
    : mSecretKey(secretKey)
    , mSCP(*this, mSecretKey.getPublicKey(), true, localQSet)
    , mValueHash(defaultValueHash)
{
    // Register both the caller-provided qset and the LocalNode-normalized form,
    // because emitted envelopes carry the normalized hash while future
    // heterogeneous tests may still want access to the original shape.
    storeQuorumSet(localQSet);
    storeQuorumSet(mSCP.getLocalNode()->getQuorumSet());
    applyConfiguration(config);
}

NodeID const&
DporNominationNode::getNodeID() const
{
    return mSecretKey.getPublicKey();
}

SCP&
DporNominationNode::getSCP()
{
    return mSCP;
}

SCP const&
DporNominationNode::getSCP() const
{
    return mSCP;
}

void
DporNominationNode::storeQuorumSet(SCPQuorumSet const& qSet)
{
    mQuorumSets[getQSetHash(qSet)] = std::make_shared<SCPQuorumSet>(qSet);
}

SCPQuorumSetPtr
DporNominationNode::getStoredQuorumSet(Hash const& qSetHash) const
{
    auto it = mQuorumSets.find(qSetHash);
    if (it == mQuorumSets.end())
    {
        return nullptr;
    }
    return it->second;
}

bool
DporNominationNode::nominate(uint64 slotIndex, Value const& value,
                             Value const& previousValue)
{
    return mSCP.nominate(slotIndex, wrapValue(value), previousValue);
}

bool
DporNominationNode::startBalloting(uint64 slotIndex, Value const& value)
{
    auto slot = mSCP.getSlot(slotIndex, true);
    return slot->bumpState(value, true);
}

SCP::EnvelopeState
DporNominationNode::receiveEnvelope(SCPEnvelope const& envelope)
{
    return mSCP.receiveEnvelope(wrapEnvelope(envelope));
}

void
DporNominationNode::setStateFromEnvelope(uint64 slotIndex,
                                         SCPEnvelope const& envelope)
{
    mSCP.setStateFromEnvelope(slotIndex, wrapEnvelope(envelope));
}

std::vector<SCPEnvelope>
DporNominationNode::takePendingEnvelopes()
{
    auto pending = std::move(mPendingEnvelopes);
    mPendingEnvelopes.clear();
    return pending;
}

std::vector<SCPEnvelope> const&
DporNominationNode::getEmittedEnvelopes() const
{
    return mEmittedEnvelopes;
}

std::vector<SCPEnvelope>
DporNominationNode::getLatestMessagesSend(uint64 slotIndex)
{
    return mSCP.getLatestMessagesSend(slotIndex);
}

std::set<NodeID>
DporNominationNode::getNominationLeaders(uint64 slotIndex)
{
    auto slot = mSCP.getSlot(slotIndex, false);
    if (!slot)
    {
        return {};
    }
    return slot->getNominationLeaders();
}

void
DporNominationNode::setValueHash(std::function<uint64(Value const&)> const& fn)
{
    mValueHash = fn;
}

void
DporNominationNode::setCombineCandidates(
    std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const& fn)
{
    mCombineCandidates = fn;
}

void
DporNominationNode::applyConfiguration(Configuration const& config)
{
    mNominationRoundBoundary =
        config.mNominationRoundBoundary == 0
            ? DEFAULT_NOMINATION_ROUND_BOUNDARY
            : config.mNominationRoundBoundary;
    mBallotingBoundary = config.mBallotingBoundary == 0
                             ? DEFAULT_BALLOTING_BOUNDARY
                             : config.mBallotingBoundary;
    mBoundaryMode = config.mBoundaryMode;
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
    mNondeterministicTxSetDownloadWaitTimeAfterFirstCall =
        config.mNondeterministicTxSetDownloadWaitTimeAfterFirstCall;
    mNominationTimerSetLimit = config.mNominationTimerSetLimit;
    mBallotingTimerSetLimit = config.mBallotingTimerSetLimit;

    mNodeIndexMap = config.mNodeIndexMap;
    if (config.mValueHash)
    {
        setValueHash(config.mValueHash);
    }
    if (config.mCombineCandidates)
    {
        setCombineCandidates(config.mCombineCandidates);
    }
}

void
DporNominationNode::clearReplayState()
{
    mSCP.purgeSlots(std::numeric_limits<uint64>::max(),
                    std::numeric_limits<uint64>::max());
    mEmittedEnvelopes.clear();
    mPendingEnvelopes.clear();
    mTimers.clear();
    mTimerSetCountByKey.clear();
    mNominationRoundBySlot.clear();
    mPendingTxSetDownloadWaitTimeChoices.clear();
    mTxSetDownloadWaitTimeCallCount = 0;
    mHasCrossedNominationBoundary = false;
    mNominationBoundaryEnvelope.reset();
}

uint32_t
DporNominationNode::inferNominationRound(
    std::chrono::milliseconds timeout) const
{
    // Boundary tracking derives the round from this driver's deterministic
    // timeout schedule instead of relying on SCP to call computeTimeout() and
    // setupTimer() in lockstep. If the timeout formula changes, fail loudly.
    auto const timeoutMS = timeout.count();
    if (timeoutMS < static_cast<int64_t>(mInitialNominationTimeoutMS))
    {
        throw std::logic_error(
            "nomination timer timeout is below the configured initial value");
    }

    if (mIncrementNominationTimeoutMS == 0)
    {
        if (timeoutMS != static_cast<int64_t>(mInitialNominationTimeoutMS))
        {
            throw std::logic_error(
                "nomination timer timeout does not match the configured "
                "constant timeout");
        }
        return 1;
    }

    auto const deltaMS =
        timeoutMS - static_cast<int64_t>(mInitialNominationTimeoutMS);
    auto const incrementMS = static_cast<int64_t>(mIncrementNominationTimeoutMS);
    if ((deltaMS % incrementMS) != 0)
    {
        throw std::logic_error(
            "nomination timer timeout does not match the configured round "
            "schedule");
    }

    return 1 + static_cast<uint32_t>(deltaMS / incrementMS);
}

bool
DporNominationNode::isRoundBoundaryNominationEnvelope(
    SCPEnvelope const& envelope) const
{
    if (envelope.statement.pledges.type() != SCP_ST_NOMINATE)
    {
        return false;
    }

    auto const it = mNominationRoundBySlot.find(envelope.statement.slotIndex);
    return it != mNominationRoundBySlot.end() &&
           it->second >= mNominationRoundBoundary;
}

bool
DporNominationNode::isEnvelopeBoundaryForMode(SCPEnvelope const& envelope) const
{
    auto const type = envelope.statement.pledges.type();
    if (type == SCP_ST_NOMINATE)
    {
        return false;
    }

    switch (mBoundaryMode)
    {
    case BoundaryMode::Prepare:
        return type == SCP_ST_PREPARE &&
               envelope.statement.pledges.prepare().ballot.counter >=
                   mBallotingBoundary;
    case BoundaryMode::Commit:
        return type == SCP_ST_CONFIRM || type == SCP_ST_EXTERNALIZE;
    }
    throw std::logic_error("unknown replay boundary mode");
}

bool
DporNominationNode::hasActiveTimer(uint64 slotIndex, int timerID) const
{
    return mTimers.find({slotIndex, timerID}) != mTimers.end();
}

std::optional<DporNominationNode::TimerState>
DporNominationNode::getTimer(uint64 slotIndex, int timerID) const
{
    auto it = mTimers.find({slotIndex, timerID});
    if (it == mTimers.end())
    {
        return std::nullopt;
    }
    return it->second;
}

bool
DporNominationNode::fireTimer(uint64 slotIndex, int timerID)
{
    auto it = mTimers.find({slotIndex, timerID});
    if (it == mTimers.end())
    {
        return false;
    }

    auto cb = it->second.mCallback;
    mTimers.erase(it);
    if (cb)
    {
        cb();
    }
    return true;
}

void
DporNominationNode::enqueueTxSetDownloadWaitTimeChoice(
    std::chrono::milliseconds waitTime)
{
    mPendingTxSetDownloadWaitTimeChoices.push_back(waitTime);
}

DporNominationNode::ReplayBaseline
DporNominationNode::snapshotReplayBaseline(uint64 slotIndex) const
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
    for (auto const& [key, timer] : mTimers)
    {
        static_cast<void>(key);
        baseline.mTimers.push_back(
            ReplayTimerSnapshot{.mSlotIndex = timer.mSlotIndex,
                                .mTimerID = timer.mTimerID,
                                .mTimeout = timer.mTimeout});
    }
    baseline.mTimerSetCounts.reserve(mTimerSetCountByKey.size());
    for (auto const& [key, count] : mTimerSetCountByKey)
    {
        baseline.mTimerSetCounts.push_back(
            ReplayTimerSetCountSnapshot{.mSlotIndex = key.first,
                                        .mTimerID = key.second,
                                        .mCount = count});
    }
    baseline.mNominationRounds.reserve(mNominationRoundBySlot.size());
    for (auto const& [snapshotSlotIndex, round] : mNominationRoundBySlot)
    {
        baseline.mNominationRounds.push_back(
            ReplayNominationRoundSnapshot{.mSlotIndex = snapshotSlotIndex,
                                          .mRound = round});
    }
    baseline.mTxSetDownloadWaitTimeCallCount =
        mTxSetDownloadWaitTimeCallCount;
    baseline.mHasCrossedNominationBoundary = mHasCrossedNominationBoundary;
    baseline.mNominationBoundaryEnvelope = mNominationBoundaryEnvelope;
    return baseline;
}

void
DporNominationNode::restoreReplayBaseline(ReplayBaseline const& baseline)
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
        mTimerSetCountByKey[{timerSetCount.mSlotIndex, timerSetCount.mTimerID}] =
            timerSetCount.mCount;
    }
    for (auto const& nominationRound : baseline.mNominationRounds)
    {
        mNominationRoundBySlot[nominationRound.mSlotIndex] =
            nominationRound.mRound;
    }
    mTxSetDownloadWaitTimeCallCount =
        baseline.mTxSetDownloadWaitTimeCallCount;
    mHasCrossedNominationBoundary = baseline.mHasCrossedNominationBoundary;
    mNominationBoundaryEnvelope = baseline.mNominationBoundaryEnvelope;
}

void
DporNominationNode::installNominationReplayTimer(
    uint64 slotIndex, std::chrono::milliseconds timeout, Value const& value,
    Value const& previousValue)
{
    auto slot = mSCP.getSlot(slotIndex, true);
    auto wrappedValue = wrapValue(value);
    mTimers[{slotIndex, Slot::NOMINATION_TIMER}] =
        TimerState{slotIndex, Slot::NOMINATION_TIMER, timeout,
                   [slot, wrappedValue, previousValue]() {
                       slot->nominate(wrappedValue, previousValue, true);
                   }};
}

void
DporNominationNode::installBallotingReplayTimer(
    uint64 slotIndex, std::chrono::milliseconds timeout)
{
    auto slot = mSCP.getSlot(slotIndex, true);
    mTimers[{slotIndex, Slot::BALLOT_PROTOCOL_TIMER}] =
        TimerState{slotIndex, Slot::BALLOT_PROTOCOL_TIMER, timeout,
                   [slot]() {
                       slot->getBallotProtocol().ballotProtocolTimerExpired();
                   }};
}

bool
DporNominationNode::hasCrossedNominationBoundary() const
{
    return mHasCrossedNominationBoundary;
}

SCPEnvelope const*
DporNominationNode::getNominationBoundaryEnvelope() const
{
    return mNominationBoundaryEnvelope ? &*mNominationBoundaryEnvelope
                                       : nullptr;
}

void
DporNominationNode::signEnvelope(SCPEnvelope&)
{
}

SCPQuorumSetPtr
DporNominationNode::getQSet(Hash const& qSetHash)
{
    auto it = mQuorumSets.find(qSetHash);
    if (it == mQuorumSets.end())
    {
        return nullptr;
    }
    return it->second;
}

std::optional<std::chrono::milliseconds>
DporNominationNode::getTxSetDownloadWaitTime(Value const&) const
{
    if (mNondeterministicTxSetDownloadWaitTimeAfterFirstCall &&
        mTxSetDownloadWaitTimeCallCount >= 1 &&
        mTxSetDownloadWaitTimes.size() >= 2 &&
        mTxSetDownloadWaitTimes.front() != mTxSetDownloadWaitTimes.at(1))
    {
        if (mPendingTxSetDownloadWaitTimeChoices.empty())
        {
            throw TxSetDownloadWaitTimeChoiceRequired(
                {mTxSetDownloadWaitTimes.front(),
                 mTxSetDownloadWaitTimes.at(1)});
        }

        auto const waitTime = mPendingTxSetDownloadWaitTimeChoices.front();
        mPendingTxSetDownloadWaitTimeChoices.pop_front();
        ++mTxSetDownloadWaitTimeCallCount;
        return waitTime;
    }

    if (mTxSetDownloadWaitTimes.empty())
    {
        return getTxSetDownloadTimeout();
    }

    auto index = mTxSetDownloadWaitTimeCallCount;
    if (index >= mTxSetDownloadWaitTimes.size())
    {
        index = mTxSetDownloadWaitTimes.size() - 1;
    }
    ++mTxSetDownloadWaitTimeCallCount;
    return mTxSetDownloadWaitTimes[index];
}

std::chrono::milliseconds
DporNominationNode::getTxSetDownloadTimeout() const
{
    return std::chrono::milliseconds{DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS};
}

void
DporNominationNode::emitEnvelope(SCPEnvelope const& envelope)
{
    auto const isRoundBoundaryNomination =
        isRoundBoundaryNominationEnvelope(envelope);
    auto const isModeBoundaryEnvelope = isEnvelopeBoundaryForMode(envelope);
    auto const alreadyCrossedBoundary = mHasCrossedNominationBoundary;
    auto const crossesBoundaryNow =
        !alreadyCrossedBoundary &&
        (isRoundBoundaryNomination || isModeBoundaryEnvelope);

    if (crossesBoundaryNow)
    {
        mHasCrossedNominationBoundary = true;
    }

    // Two boundary triggers matter here:
    // 1. the first envelope that matches the configured replay boundary mode
    //    (PREPARE at the configured ballot boundary by default, COMMIT-side
    //    handoff in ballot mode)
    // 2. the first nomination envelope emitted once the boundary round has
    //    been armed
    // The round boundary can also be reached earlier in setupTimer() before
    // any envelope is emitted, so we keep a separate boolean boundary flag and
    // still capture the first round-boundary nomination envelope later when it
    // appears for diagnostics.
    auto const shouldCaptureBoundaryEnvelope =
        !mNominationBoundaryEnvelope &&
        (crossesBoundaryNow || isRoundBoundaryNomination);
    if (shouldCaptureBoundaryEnvelope)
    {
        mNominationBoundaryEnvelope = envelope;
    }

    mEmittedEnvelopes.push_back(envelope);
    if (!alreadyCrossedBoundary && !crossesBoundaryNow)
    {
        mPendingEnvelopes.push_back(envelope);
    }
}

SCPDriver::ValidationLevel
DporNominationNode::validateValue(uint64, Value const& value, bool)
{
    if (isSkipLedgerValue(value))
    {
        return SCPDriver::kFullyValidatedValue;
    }
    return SCPDriver::kAwaitingDownload;
}

Value
DporNominationNode::makeSkipLedgerValueFromValue(Value const& value) const
{
    Value skipValue;
    skipValue.resize(5 + value.size());
    skipValue[0] = 'S';
    skipValue[1] = 'K';
    skipValue[2] = 'I';
    skipValue[3] = 'P';
    skipValue[4] = ':';
    std::copy(value.begin(), value.end(), skipValue.begin() + 5);
    return skipValue;
}

bool
DporNominationNode::isSkipLedgerValue(Value const& value) const
{
    return value.size() >= 5 && value[0] == 'S' && value[1] == 'K' &&
           value[2] == 'I' && value[3] == 'P' && value[4] == ':';
}

Hash
DporNominationNode::getHashOf(
    std::vector<xdr::opaque_vec<>> const& vals) const
{
    SHA256 hasher;
    for (auto const& val : vals)
    {
        hasher.add(val);
    }
    return hasher.finish();
}

uint64
DporNominationNode::computeHashNode(uint64 slotIndex, Value const& prev,
                                    bool isPriority, int32_t roundNumber,
                                    NodeID const& nodeID)
{
    if (!mNodeIndexMap.empty())
    {
        if (!isPriority)
        {
            // All nodes pass the weight check.
            return 0;
        }
        auto it = mNodeIndexMap.find(nodeID);
        if (it != mNodeIndexMap.end())
        {
            auto const numNodes = static_cast<uint64>(mNodeIndexMap.size());
            auto const normalizedRound =
                static_cast<uint64>(std::max(roundNumber, 1));
            auto const selectedIndex =
                ((normalizedRound - 1) % numNodes) + 1;
            return it->second == selectedIndex
                       ? std::numeric_limits<uint64>::max()
                       : 0;
        }
    }
    return SCPDriver::computeHashNode(slotIndex, prev, isPriority, roundNumber,
                                      nodeID);
}

uint64
DporNominationNode::computeValueHash(uint64, Value const&, int32_t,
                                     Value const& value)
{
    return mValueHash(value);
}

ValueWrapperPtr
DporNominationNode::combineCandidates(uint64 slotIndex,
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
DporNominationNode::hasUpgrades(Value const&)
{
    return false;
}

ValueWrapperPtr
DporNominationNode::stripAllUpgrades(Value const& value)
{
    return wrapValue(value);
}

uint32_t
DporNominationNode::getUpgradeNominationTimeoutLimit() const
{
    return std::numeric_limits<uint32_t>::max();
}

void
DporNominationNode::setupTimer(uint64 slotIndex, int timerID,
                               std::chrono::milliseconds timeout,
                               std::function<void()> cb)
{
    auto const key = TimerKey{slotIndex, timerID};

    if (!cb)
    {
        mTimers.erase(key);
        return;
    }

    if (timerID == Slot::NOMINATION_TIMER)
    {
        auto const roundNumber = inferNominationRound(timeout);
        mNominationRoundBySlot[slotIndex] = roundNumber;
        if (roundNumber >= mNominationRoundBoundary)
        {
            mHasCrossedNominationBoundary = true;
        }
    }

    auto const setCount = ++mTimerSetCountByKey[key];

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
        mTimers.erase(key);
        return;
    }

    mTimers[key] = TimerState{slotIndex, timerID, timeout, cb};
}

void
DporNominationNode::stopTimer(uint64 slotIndex, int timerID)
{
    mTimers.erase({slotIndex, timerID});
}

std::chrono::milliseconds
DporNominationNode::computeTimeout(uint32 roundNumber, bool isNomination)
{
    auto const initialTimeoutMS =
        isNomination ? mInitialNominationTimeoutMS : mInitialBallotTimeoutMS;
    auto const incrementTimeoutMS = isNomination
                                        ? mIncrementNominationTimeoutMS
                                        : mIncrementBallotTimeoutMS;
    return std::chrono::milliseconds(initialTimeoutMS +
                                     (roundNumber - 1) * incrementTimeoutMS);
}

}
