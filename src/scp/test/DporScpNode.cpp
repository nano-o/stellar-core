// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporScpNode.h"

#include "crypto/SHA.h"
#include "scp/LocalNode.h"
#include "scp/Slot.h"
#include "xdrpp/marshal.h"

#include <algorithm>
#include <atomic>
#include <limits>
#include <string>
#include <string_view>

namespace stellar
{

namespace
{

constexpr std::string_view EMPTY_TX_SET_PREFIX{"EMPTY:"};

template <typename Range>
auto
findSlotTimer(Range& values, uint64 slotIndex, int timerID)
{
    return std::find_if(
        values.begin(), values.end(), [slotIndex, timerID](auto const& value) {
            return value.mSlotIndex == slotIndex && value.mTimerID == timerID;
        });
}

Hash
getQSetHash(SCPQuorumSet const& qSet)
{
    return sha256(xdr::xdr_to_opaque(qSet));
}

uint64
nextReplayBaselineSnapshotId()
{
    static std::atomic<uint64> counter{0};
    return ++counter;
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
        DporScpTxSetStatus::Valid, DporScpTxSetStatus::Downloading};
    return supportedChoices;
}

template <typename ChoiceRequired, typename T>
T
consumeChoice(std::vector<T> const& pendingChoices, std::size_t& nextChoice,
              std::vector<T> const& supportedChoices,
              std::string_view emptyMessage, std::string_view invalidMessage)
{
    if (supportedChoices.empty())
    {
        throw std::logic_error(std::string(emptyMessage));
    }
    if (nextChoice >= pendingChoices.size())
    {
        throw ChoiceRequired(supportedChoices);
    }

    auto const choice = pendingChoices.at(nextChoice++);
    if (std::find(supportedChoices.begin(), supportedChoices.end(), choice) ==
        supportedChoices.end())
    {
        throw std::logic_error(std::string(invalidMessage));
    }
    return choice;
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
    case DporScpTxSetStatus::Downloading:
        return SCPDriver::kStructurallyValidValue;
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

DporScpNode::ExternalEventScope::ExternalEventScope(DporScpNode& node)
    : mNode(node)
{
    if (mNode.mExternalEventDepth++ == 0)
    {
        mNode.beginExternalEvent();
    }
}

DporScpNode::ExternalEventScope::~ExternalEventScope()
{
    if (--mNode.mExternalEventDepth == 0)
    {
        mNode.endExternalEvent();
    }
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
    mLastQSetLookup.reset();
}

bool
DporScpNode::nominate(uint64 slotIndex, Value const& value,
                      Value const& previousValue)
{
    ExternalEventScope event(*this);
    return mSCP.nominate(slotIndex, wrapValue(value), previousValue);
}

bool
DporScpNode::startBalloting(uint64 slotIndex, Value const& value)
{
    ExternalEventScope event(*this);
    auto slot = mSCP.getSlot(slotIndex, true);
    return slot->bumpState(value, true);
}

SCP::EnvelopeState
DporScpNode::receiveEnvelope(SCPEnvelope const& envelope)
{
    ExternalEventScope event(*this);
    return mSCP.receiveEnvelope(wrapEnvelope(envelope));
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
    auto const it = findSlotTimer(mTimers, slotIndex, timerID);
    if (it == mTimers.end())
    {
        return false;
    }

    auto cb = it->mCallback;
    recordReplayDebugEvent(
        ReplayDebugEvent{.mKind = ReplayDebugEvent::Kind::FireTimer,
                         .mSlotIndex = slotIndex,
                         .mTimerID = timerID,
                         .mTimeout = it->mTimeout});
    mTimers.erase(it);
    if (cb)
    {
        ExternalEventScope event(*this);
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

bool
DporScpNode::hasUnconsumedTxSetChoices() const
{
    return mNextPendingTxSetStatusChoice < mPendingTxSetStatusChoices.size() ||
           mNextPendingTxSetDownloadWaitTimeChoice <
               mPendingTxSetDownloadWaitTimeChoices.size();
}

void
DporScpNode::setEmittedEnvelopeRecordingEnabled(bool enabled)
{
    mEmittedEnvelopeRecordingEnabled = enabled;
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
    if (mExternalEventDepth != 0)
    {
        throw std::logic_error(
            "replay baseline snapshot requested inside an external event");
    }
    // The per-event decisions are not part of the baseline, so a snapshot
    // taken while they hold anything -- inside an implicit event that has
    // already answered a call -- would silently drop them, and restoring could
    // then answer differently.
    if (!mTxSetDecisionsThisEvent.empty())
    {
        throw std::logic_error("replay baseline snapshot requested after a "
                               "txset decision in the current event");
    }

    // Identity for the wrapped-form cache in restoreReplayBaseline().
    ReplayBaseline baseline;

    auto slot = const_cast<SCP&>(mSCP).getSlot(slotIndex, false);
    if (slot)
    {
        SlotStateSnapshot slotSnapshot;
        slotSnapshot.mSlotIndex = slot->mSlotIndex;
        slotSnapshot.mFullyValidated = slot->mFullyValidated;
        slotSnapshot.mGotVBlocking = slot->mGotVBlocking;

        slotSnapshot.mStatementsHistory.reserve(
            slot->mStatementsHistory.size());
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
        slotSnapshot.mNominationState.mPreviousValue =
            nomination.mPreviousValue;
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
        slotSnapshot.mBallotState.mPrepared = snapshotBallot(ballot.mPrepared);
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
    baseline.mTimerSetCounts = mTimerSetCounts;
    baseline.mLastTxSetStatusByValue = mLastTxSetStatusByValue;
    baseline.mLastTxSetDownloadWaitTimeByValue =
        mLastTxSetDownloadWaitTimeByValue;
    baseline.mTxSetDownloadWaitTimeCallCountsByValue =
        mTxSetDownloadWaitTimeCallCountsByValue;
    baseline.mTxSetDownloadsSucceeded = mTxSetDownloadsSucceeded;
    baseline.mPendingTxSetDownloadsSucceeded = mPendingTxSetDownloadsSucceeded;
    baseline.mHasReachedBoundary = mHasReachedBoundary;
    baseline.mBoundaryEnvelope = mBoundaryEnvelope;
    baseline.mSnapshotId = nextReplayBaselineSnapshotId();
    return baseline;
}

void
DporScpNode::restoreReplayBaseline(ReplayBaseline const& baseline)
{
    if (mExternalEventDepth != 0)
    {
        throw std::logic_error(
            "replay baseline restore requested inside an external event");
    }

    clearReplayState();

    if (baseline.mSlotState)
    {
        auto const& slotSnapshot = *baseline.mSlotState;
        auto slot = mSCP.getSlot(slotSnapshot.mSlotIndex, true);

        slot->mFullyValidated = slotSnapshot.mFullyValidated;
        slot->mGotVBlocking = slotSnapshot.mGotVBlocking;
        slot->mStatementsHistory.clear();
        // Headroom, not the exact snapshot size: replay appends to this vector
        // as it processes envelopes, and an exact reserve made every one of
        // those appends reallocate.
        slot->mStatementsHistory.reserve(
            slotSnapshot.mStatementsHistory.size() + 32);
        for (auto const& historicalStatement : slotSnapshot.mStatementsHistory)
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

        // Rebuild the wrapped forms only when this is a different snapshot; the
        // wrappers are immutable, so a repeat restore just re-shares them.
        if (baseline.mSnapshotId == 0 ||
            mWrappedBaseline.mSnapshotId != baseline.mSnapshotId)
        {
            auto const& nominationState = slotSnapshot.mNominationState;
            auto const& ballotState = slotSnapshot.mBallotState;

            mWrappedBaseline = WrappedBaseline{};
            mWrappedBaseline.mVotes = restoreValueSet(nominationState.mVotes);
            mWrappedBaseline.mAccepted =
                restoreValueSet(nominationState.mAccepted);
            mWrappedBaseline.mCandidates =
                restoreValueSet(nominationState.mCandidates);
            mWrappedBaseline.mRoundLeaders =
                std::set<NodeID>(nominationState.mRoundLeaders.begin(),
                                 nominationState.mRoundLeaders.end());
            mWrappedBaseline.mLatestNominations =
                restoreEnvelopeMap(nominationState.mLatestNominations);
            mWrappedBaseline.mLatestEnvelopes =
                restoreEnvelopeMap(ballotState.mLatestEnvelopes);
            if (nominationState.mLastEnvelope)
            {
                mWrappedBaseline.mNominationLastEnvelope =
                    wrapEnvelope(*nominationState.mLastEnvelope);
            }
            if (nominationState.mLatestCompositeCandidate)
            {
                auto const& composite =
                    *nominationState.mLatestCompositeCandidate;
                for (auto const& candidate : mWrappedBaseline.mCandidates)
                {
                    if (candidate->getValue() == composite)
                    {
                        mWrappedBaseline.mLatestCompositeCandidate = candidate;
                        break;
                    }
                }
                if (!mWrappedBaseline.mLatestCompositeCandidate)
                {
                    mWrappedBaseline.mLatestCompositeCandidate =
                        wrapValue(composite);
                }
            }
            if (ballotState.mValueOverride)
            {
                mWrappedBaseline.mValueOverride =
                    wrapValue(*ballotState.mValueOverride);
            }
            if (ballotState.mLastEnvelope)
            {
                mWrappedBaseline.mBallotLastEnvelope =
                    wrapEnvelope(*ballotState.mLastEnvelope);
            }
            if (ballotState.mLastEnvelopeEmit)
            {
                mWrappedBaseline.mBallotLastEnvelopeEmit =
                    wrapEnvelope(*ballotState.mLastEnvelopeEmit);
            }
            mWrappedBaseline.mSnapshotId = baseline.mSnapshotId;
        }

        auto& nomination = slot->mNominationProtocol;
        nomination.mRoundNumber = slotSnapshot.mNominationState.mRoundNumber;
        nomination.mVotes = mWrappedBaseline.mVotes;
        nomination.mAccepted = mWrappedBaseline.mAccepted;
        nomination.mCandidates = mWrappedBaseline.mCandidates;
        nomination.mLatestNominations = mWrappedBaseline.mLatestNominations;
        nomination.mLastEnvelope = mWrappedBaseline.mNominationLastEnvelope;
        nomination.mRoundLeaders = mWrappedBaseline.mRoundLeaders;
        nomination.mNominationStarted =
            slotSnapshot.mNominationState.mNominationStarted;
        nomination.mLatestCompositeCandidate =
            mWrappedBaseline.mLatestCompositeCandidate;
        nomination.mPreviousValue =
            slotSnapshot.mNominationState.mPreviousValue;
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
        ballot.mLatestEnvelopes = mWrappedBaseline.mLatestEnvelopes;
        ballot.mPhase = static_cast<BallotProtocol::SCPPhase>(
            slotSnapshot.mBallotState.mPhase);
        ballot.mValueOverride = mWrappedBaseline.mValueOverride;
        ballot.mCurrentMessageLevel =
            slotSnapshot.mBallotState.mCurrentMessageLevel;
        ballot.mTimerExpCount = slotSnapshot.mBallotState.mTimerExpCount;
        ballot.mLastEnvelope = mWrappedBaseline.mBallotLastEnvelope;
        ballot.mLastEnvelopeEmit = mWrappedBaseline.mBallotLastEnvelopeEmit;
    }

    mEmittedEnvelopes = baseline.mEmittedEnvelopes;
    mTimerSetCounts = baseline.mTimerSetCounts;
    mLastTxSetStatusByValue = baseline.mLastTxSetStatusByValue;
    mLastTxSetDownloadWaitTimeByValue =
        baseline.mLastTxSetDownloadWaitTimeByValue;
    mTxSetDownloadWaitTimeCallCountsByValue =
        baseline.mTxSetDownloadWaitTimeCallCountsByValue;
    mTxSetDownloadsSucceeded = baseline.mTxSetDownloadsSucceeded;
    mPendingTxSetDownloadsSucceeded = baseline.mPendingTxSetDownloadsSucceeded;
    mHasReachedBoundary = baseline.mHasReachedBoundary;
    mBoundaryEnvelope = baseline.mBoundaryEnvelope;
}

void
DporScpNode::installNominationReplayTimer(uint64 slotIndex,
                                          std::chrono::milliseconds timeout,
                                          Value const& value,
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
DporScpNode::installBallotingReplayTimer(uint64 slotIndex,
                                         std::chrono::milliseconds timeout)
{
    auto slot = mSCP.getSlot(slotIndex, true);
    setTimer(
        TimerState{slotIndex, Slot::BALLOT_PROTOCOL_TIMER, timeout, [slot]() {
                       slot->getBallotProtocol().ballotProtocolTimerExpired();
                   }});
}

bool
DporScpNode::hasReachedBoundary() const
{
    return mHasReachedBoundary;
}

SCPEnvelope const*
DporScpNode::getBoundaryEnvelope() const
{
    return mBoundaryEnvelope ? &*mBoundaryEnvelope : nullptr;
}

void
DporScpNode::signEnvelope(SCPEnvelope&)
{
}

SCPQuorumSetPtr
DporScpNode::getQSet(Hash const& qSetHash)
{
    // SCP asks for the quorum set on every envelope, and every validator in
    // these scenarios shares one; a single-entry memo turns a 32-byte-key map
    // lookup per envelope into a pointer compare.
    if (mLastQSetLookup && mLastQSetLookupHash == qSetHash)
    {
        return mLastQSetLookup;
    }

    auto const it = mQuorumSets.find(qSetHash);
    if (it == mQuorumSets.end())
    {
        return nullptr;
    }
    mLastQSetLookupHash = qSetHash;
    mLastQSetLookup = it->second;
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
    if (isOutrightInvalidValue(value) || isEmptyTxSetValue(value) ||
        mTxSetDownloadsSucceeded.contains(value))
    {
        return std::nullopt;
    }

    auto const recordWaitTimeDebugEvent =
        [this](std::chrono::milliseconds waitTime) {
            recordReplayDebugEvent(ReplayDebugEvent{
                .mKind = ReplayDebugEvent::Kind::UseTxSetDownloadWaitTime,
                .mWaitTime = waitTime});
        };

    {
        auto const decisionIt = mTxSetDecisionsThisEvent.find(value);
        if (decisionIt != mTxSetDecisionsThisEvent.end() &&
            decisionIt->second.mWaitTimeDecided)
        {
            // Recorded on every call that returns a wait time, memo hits
            // included, so investigation output still shows what SCP observed.
            // A memoized nullopt records nothing, matching the behavior before
            // the memo, where only a produced wait time emitted an event --
            // and the investigation formatter dereferences mWaitTime
            // unconditionally.
            if (decisionIt->second.mWaitTime)
            {
                recordWaitTimeDebugEvent(*decisionIt->second.mWaitTime);
            }
            return decisionIt->second.mWaitTime;
        }
    }

    // Every gated nullopt is memoized, the no-recorded-status case included.
    // Without that, a wait query preceding all validation in an event answers
    // "no download in progress", a later validateValue chooses Downloading,
    // and the next query branches -- two answers to one question inside one
    // event.
    auto const decideNoWaitTime =
        [this, &value]() -> std::optional<std::chrono::milliseconds> {
        auto& decision = mTxSetDecisionsThisEvent[value];
        decision.mWaitTimeDecided = true;
        decision.mWaitTime.reset();
        return std::nullopt;
    };

    if (mNondeterministicTxSetStatus)
    {
        // A wait time only exists while a download is in progress, and the
        // event's own status decides that. maybeReplaceValueWithEmptyTxSet(),
        // the only caller, always validates before it queries, so falling back
        // to the cross-event status should be unreachable -- but that call
        // order belongs to production code the harness does not own, so the
        // fallback pins the event's status rather than answering past it.
        auto const eventStatus =
            [this, &value]() -> std::optional<DporScpTxSetStatus> {
            auto const decisionIt = mTxSetDecisionsThisEvent.find(value);
            if (decisionIt != mTxSetDecisionsThisEvent.end() &&
                decisionIt->second.mStatus)
            {
                return decisionIt->second.mStatus;
            }
            auto const lastStatusIt = mLastTxSetStatusByValue.find(value);
            if (lastStatusIt == mLastTxSetStatusByValue.end())
            {
                return std::nullopt;
            }
            mTxSetDecisionsThisEvent[value].mStatus = lastStatusIt->second;
            return lastStatusIt->second;
        }();

        if (eventStatus != DporScpTxSetStatus::Downloading)
        {
            return decideNoWaitTime();
        }
    }
    else if (mTxSetStatus != DporScpTxSetStatus::Downloading)
    {
        return decideNoWaitTime();
    }

    auto const recordWaitTime = [this, &value, &recordWaitTimeDebugEvent](
                                    std::chrono::milliseconds waitTime) {
        mLastTxSetDownloadWaitTimeByValue[value] = waitTime;
        ++mTxSetDownloadWaitTimeCallCountsByValue[value];
        auto& decision = mTxSetDecisionsThisEvent[value];
        decision.mWaitTimeDecided = true;
        decision.mWaitTime = waitTime;
        recordWaitTimeDebugEvent(waitTime);
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

        auto const waitTime =
            consumeChoice<TxSetDownloadWaitTimeChoiceRequired>(
                mPendingTxSetDownloadWaitTimeChoices,
                mNextPendingTxSetDownloadWaitTimeChoice, supportedChoices,
                "supported txset wait-time choices must not be empty",
                "preloaded txset wait-time choice is not supported");
        return recordWaitTime(waitTime);
    }

    if (mTxSetDownloadWaitTimes.empty())
    {
        return recordWaitTime(timeout);
    }

    auto index = mTxSetDownloadWaitTimeCallCountsByValue[value];
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
        mBoundaryEnvelope = envelope;
    }

    if (mEmittedEnvelopeRecordingEnabled)
    {
        mEmittedEnvelopes.push_back(envelope);
    }
    if (auto const value = txSetDownloadSucceededValue(envelope))
    {
        markTxSetDownloadSucceeded(*value);
    }
    // Guarded rather than left to recordReplayDebugEvent(): building the event
    // deep-copies the envelope, and exploration emits envelopes constantly with
    // recording off.
    if (mReplayDebugRecordingEnabled)
    {
        recordReplayDebugEvent(
            ReplayDebugEvent{.mKind = ReplayDebugEvent::Kind::EmitEnvelope,
                             .mEnvelope = envelope,
                             .mBoundary = reachesBoundaryNow});
    }
    // The envelope that reaches the boundary is still a protocol message and
    // must be delivered to peers. The scenario drains pending sends before it
    // stops a boundary thread. Suppress only envelopes emitted after the
    // boundary.
    if (!alreadyReachedBoundary)
    {
        mPendingEnvelopes.push_back(envelope);
    }
}

SCPDriver::ValidationLevel
DporScpNode::validateValue(uint64, Value const& value, bool nomination) const
{
    if (isOutrightInvalidValue(value))
    {
        recordReplayDebugEvent(ReplayDebugEvent{
            .mKind = ReplayDebugEvent::Kind::RejectOutrightInvalidValue});
        return SCPDriver::kInvalidValue;
    }
    if (isEmptyTxSetValue(value))
    {
        return nomination ? SCPDriver::kInvalidValue
                          : SCPDriver::kFullyValidatedValue;
    }
    if (nomination && mNominationAlwaysDownloadingTxSetStatus)
    {
        // Deliberately exempt from the per-event decision below. This is a
        // branch-saving forcing knob, not a model of fetcher state: memoizing
        // it would stop balloting from ever branching in an event that began
        // with a nomination validation, which is exactly what the flag exists
        // to explore. See docs/dpor-integration-status.md for the wart.
        return SCPDriver::kStructurallyValidValue;
    }
    if (mTxSetDownloadsSucceeded.contains(value))
    {
        return SCPDriver::kFullyValidatedValue;
    }
    {
        // Repeated validateValue calls with the same arguments inside one
        // handler cannot disagree in production: the fetcher state they read
        // is only mutated by other main-thread callbacks, and none can run
        // re-entrantly inside Slot::processEnvelope. If a future SCPDriver
        // callback synchronously drains overlay work, this assumption is what
        // it breaks.
        auto const decisionIt = mTxSetDecisionsThisEvent.find(value);
        if (decisionIt != mTxSetDecisionsThisEvent.end() &&
            decisionIt->second.mStatus)
        {
            return validationLevelForTxSetStatus(*decisionIt->second.mStatus);
        }
    }
    DporScpTxSetStatus status = mTxSetStatus;
    if (mNondeterministicTxSetStatus)
    {
        auto const lastStatusIt = mLastTxSetStatusByValue.find(value);
        if (lastStatusIt != mLastTxSetStatusByValue.end() &&
            lastStatusIt->second != DporScpTxSetStatus::Downloading)
        {
            status = lastStatusIt->second;
        }
        else
        {
            status = consumeChoice<TxSetStatusChoiceRequired>(
                mPendingTxSetStatusChoices, mNextPendingTxSetStatusChoice,
                mSupportedTxSetStatusChoices,
                "supported txset status choices must not be empty",
                "preloaded txset status choice is not supported");
        }
    }

    mLastTxSetStatusByValue[value] = status;
    mTxSetDecisionsThisEvent[value].mStatus = status;
    return validationLevelForTxSetStatus(status);
}

Value
DporScpNode::makeEmptyTxSetValueFromValue(Value const& value) const
{
    Value emptyTxSetValue;
    emptyTxSetValue.reserve(EMPTY_TX_SET_PREFIX.size() + value.size());
    emptyTxSetValue.insert(emptyTxSetValue.end(), EMPTY_TX_SET_PREFIX.begin(),
                           EMPTY_TX_SET_PREFIX.end());
    emptyTxSetValue.insert(emptyTxSetValue.end(), value.begin(), value.end());
    return emptyTxSetValue;
}

bool
DporScpNode::isEmptyTxSetValue(Value const& value) const
{
    return hasEmptyTxSetValuePrefix(value);
}

bool
DporScpNode::hasEmptyTxSetValuePrefix(Value const& value)
{
    return value.size() >= EMPTY_TX_SET_PREFIX.size() &&
           std::equal(EMPTY_TX_SET_PREFIX.begin(), EMPTY_TX_SET_PREFIX.end(),
                      value.begin());
}

bool
DporScpNode::isParallelTxSetDownloadEnabled() const
{
    return true;
}

bool
DporScpNode::protocolAllowsEmptyTxSetValues() const
{
    return !mInjectEmptyTxSetProtocolGateFailureForTesting;
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
DporScpNode::computeValueHash(uint64, Value const&, int32_t, Value const& value)
{
    return defaultValueHash(value);
}

ValueWrapperPtr
DporScpNode::combineCandidates(uint64, ValueWrapperPtrSet const& candidates)
{
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
        mTimerSetCounts.push_back(ReplayTimerSetCountSnapshot{
            .mSlotIndex = slotIndex, .mTimerID = timerID});
        setCountEntry = &mTimerSetCounts.back();
    }
    auto const setCount = ++setCountEntry->mCount;
    auto const timerSetLimit = timerID == Slot::NOMINATION_TIMER
                                   ? mNominationTimerSetLimit
                                   : std::nullopt;

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
    auto const incrementTimeoutMS = isNomination ? mIncrementNominationTimeoutMS
                                                 : mIncrementBallotTimeoutMS;
    return std::chrono::milliseconds(initialTimeoutMS +
                                     (roundNumber - 1) * incrementTimeoutMS);
}

void
DporScpNode::applyConfiguration(Configuration const& config)
{
    mNodeIndexMap = config.mNodeIndexMap;
    mPrepareBoundaryCounter =
        std::max<uint32_t>(1, config.mPrepareBoundaryCounter);
    mBoundaryMode = config.mBoundaryMode;
    mMaxNominationRound = config.mMaxNominationRound;
    mMaxBallotingRound = config.mMaxBallotingRound;
    mTxSetStatus = config.mTxSetStatus;
    mNondeterministicTxSetStatus = config.mNondeterministicTxSetStatus;
    mNominationAlwaysDownloadingTxSetStatus =
        config.mNominationAlwaysDownloadingTxSetStatus;
    mInjectEmptyTxSetProtocolGateFailureForTesting =
        config.mInjectEmptyTxSetProtocolGateFailureForTesting;
    mOutrightInvalidValues.clear();
    auto const invalidValuesIt =
        config.mOutrightInvalidValuesByNode.find(getNodeID());
    if (invalidValuesIt != config.mOutrightInvalidValuesByNode.end())
    {
        mOutrightInvalidValues = invalidValuesIt->second;
    }
    mSupportedTxSetStatusChoices.clear();
    if (mNondeterministicTxSetStatus)
    {
        mSupportedTxSetStatusChoices =
            config.mSupportedTxSetStatusChoices.empty()
                ? allTxSetStatusChoices()
                : config.mSupportedTxSetStatusChoices;

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

    mTxSetDownloadWaitTimes = config.mTxSetDownloadWaitTimes;
    mNondeterministicTxSetDownloadWaitTime =
        config.mNondeterministicTxSetDownloadWaitTime;
    mNominationTimerSetLimit = config.mNominationTimerSetLimit;
}

DporScpNode::TimerState*
DporScpNode::findTimer(uint64 slotIndex, int timerID)
{
    auto const it = findSlotTimer(mTimers, slotIndex, timerID);
    return it == mTimers.end() ? nullptr : &*it;
}

DporScpNode::TimerState const*
DporScpNode::findTimer(uint64 slotIndex, int timerID) const
{
    auto const it = findSlotTimer(mTimers, slotIndex, timerID);
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
    auto const it = findSlotTimer(mTimers, slotIndex, timerID);
    if (it != mTimers.end())
    {
        mTimers.erase(it);
    }
}

DporScpNode::ReplayTimerSetCountSnapshot*
DporScpNode::findTimerSetCount(uint64 slotIndex, int timerID)
{
    auto const it = findSlotTimer(mTimerSetCounts, slotIndex, timerID);
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
    // One traversal: everything below slot 1 and above slot 0, i.e. every slot.
    mSCP.purgeSlotsOutsideRange(1, 0, slotToKeep);
    mEmittedEnvelopes.clear();
    mPendingEnvelopes.clear();
    mTimers.clear();
    mTimerSetCounts.clear();
    mPendingTxSetStatusChoices.clear();
    mNextPendingTxSetStatusChoice = 0;
    mLastTxSetStatusByValue.clear();
    mTxSetDecisionsThisEvent.clear();
    mLastTxSetDownloadWaitTimeByValue.clear();
    mPendingTxSetDownloadWaitTimeChoices.clear();
    mNextPendingTxSetDownloadWaitTimeChoice = 0;
    mTxSetDownloadWaitTimeCallCountsByValue.clear();
    mReplayDebugEvents.clear();
    mTxSetDownloadsSucceeded.clear();
    mPendingTxSetDownloadsSucceeded.clear();
    mHasReachedBoundary = false;
    mBoundaryEnvelope.reset();
}

void
DporScpNode::beginExternalEvent()
{
    // Cleared on entry as well as exit: direct driver calls made outside any
    // scope form one implicit event, and opening a real one must not inherit
    // its decisions.
    mTxSetDecisionsThisEvent.clear();

    for (auto const& value : mPendingTxSetDownloadsSucceeded)
    {
        if (!mTxSetDownloadsSucceeded.insert(value).second)
        {
            continue;
        }

        mLastTxSetStatusByValue.erase(value);
        mLastTxSetDownloadWaitTimeByValue.erase(value);
        mTxSetDownloadWaitTimeCallCountsByValue.erase(value);
    }
    mPendingTxSetDownloadsSucceeded.clear();
}

void
DporScpNode::endExternalEvent()
{
    // Leaving a finished event's decisions readable by a subsequent direct
    // driver call would make "which event is this?" ambiguous.
    mTxSetDecisionsThisEvent.clear();
}

void
DporScpNode::markTxSetDownloadSucceeded(Value const& value)
{
    // Deferred to the start of the next external event rather than applied
    // here: emitEnvelope() runs mid-handler, and promoting immediately would
    // let a later validateValue() in the same handler flip from Downloading to
    // Valid -- a mid-event change of mind that production cannot produce.
    if (mTxSetDownloadsSucceeded.contains(value))
    {
        return;
    }
    mPendingTxSetDownloadsSucceeded.insert(value);
}

std::optional<Value>
DporScpNode::txSetDownloadSucceededValue(SCPEnvelope const& envelope) const
{
    if (!mDownloadSucceedsInBallotRound ||
        envelope.statement.pledges.type() != SCP_ST_PREPARE)
    {
        return std::nullopt;
    }

    auto const& ballot = envelope.statement.pledges.prepare().ballot;
    if (ballot.counter != *mDownloadSucceedsInBallotRound ||
        isEmptyTxSetValue(ballot.value) ||
        mTxSetDownloadsSucceeded.contains(ballot.value))
    {
        return std::nullopt;
    }
    return ballot.value;
}

bool
DporScpNode::isOutrightInvalidValue(Value const& value) const
{
    return mOutrightInvalidValues.contains(value);
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
    }
    throw std::logic_error("unknown replay boundary mode");
}

} // namespace stellar
