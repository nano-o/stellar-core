// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
#include "scp/SCP.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace stellar
{

class DporScpNode : public SCPDriver
{
  public:
    enum class BoundaryMode : std::uint8_t
    {
        Prepare,
        Commit
    };

    class TxSetDownloadWaitTimeChoiceRequired : public std::runtime_error
    {
      public:
        explicit TxSetDownloadWaitTimeChoiceRequired(
            std::vector<std::chrono::milliseconds> choices);

        std::vector<std::chrono::milliseconds> const&
        getChoices() const;

      private:
        std::vector<std::chrono::milliseconds> mChoices;
    };

    static constexpr uint32_t DEFAULT_PREPARE_BOUNDARY_COUNTER = 1;
    static constexpr uint32_t DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS = 1000;

    struct Configuration
    {
        std::map<NodeID, std::size_t> mNodeIndexMap;
        std::function<uint64(Value const&)> mValueHash;
        std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)>
            mCombineCandidates;
        uint32_t mPrepareBoundaryCounter{DEFAULT_PREPARE_BOUNDARY_COUNTER};
        BoundaryMode mBoundaryMode{BoundaryMode::Prepare};
        bool mAwaitTxSetDownloads{false};
        std::vector<std::chrono::milliseconds> mTxSetDownloadWaitTimes;
        std::map<NodeID, std::vector<std::chrono::milliseconds>>
            mTxSetDownloadWaitTimesByNode;
        bool mNondeterministicTxSetDownloadWaitTimeAfterFirstCall{false};
        std::optional<uint32_t> mNominationTimerSetLimit;
        std::optional<uint32_t> mBallotingTimerSetLimit;
        uint32_t mInitialNominationTimeoutMS{1000};
        uint32_t mIncrementNominationTimeoutMS{1000};
        uint32_t mInitialBallotTimeoutMS{1000};
        uint32_t mIncrementBallotTimeoutMS{1000};
    };

    struct TimerState
    {
        uint64 mSlotIndex{};
        int mTimerID{};
        std::chrono::milliseconds mTimeout{};
        std::function<void()> mCallback;
    };

    struct HistoricalStatementSnapshot
    {
        std::time_t mWhen{};
        SCPStatement mStatement;
        bool mValidated{};
    };

    struct NominationStateSnapshot
    {
        int32_t mRoundNumber{};
        std::vector<Value> mVotes;
        std::vector<Value> mAccepted;
        std::vector<Value> mCandidates;
        std::vector<SCPEnvelope> mLatestNominations;
        std::optional<SCPEnvelope> mLastEnvelope;
        std::vector<NodeID> mRoundLeaders;
        bool mNominationStarted{};
        std::optional<Value> mLatestCompositeCandidate;
        Value mPreviousValue;
        uint32_t mTimerExpCount{};
    };

    struct BallotStateSnapshot
    {
        bool mHeardFromQuorum{};
        std::optional<SCPBallot> mCurrentBallot;
        std::optional<SCPBallot> mPrepared;
        std::optional<SCPBallot> mPreparedPrime;
        std::optional<SCPBallot> mHighBallot;
        std::optional<SCPBallot> mCommit;
        std::vector<SCPEnvelope> mLatestEnvelopes;
        std::uint8_t mPhase{};
        std::optional<Value> mValueOverride;
        int mCurrentMessageLevel{};
        uint32_t mTimerExpCount{};
        std::optional<SCPEnvelope> mLastEnvelope;
        std::optional<SCPEnvelope> mLastEnvelopeEmit;
    };

    struct SlotStateSnapshot
    {
        uint64 mSlotIndex{};
        bool mFullyValidated{};
        bool mGotVBlocking{};
        std::vector<HistoricalStatementSnapshot> mStatementsHistory;
        NominationStateSnapshot mNominationState;
        BallotStateSnapshot mBallotState;
    };

    struct ReplayTimerSnapshot
    {
        uint64 mSlotIndex{};
        int mTimerID{};
        std::chrono::milliseconds mTimeout{};
    };

    struct ReplayTimerSetCountSnapshot
    {
        uint64 mSlotIndex{};
        int mTimerID{};
        uint32_t mCount{};
    };

    struct ReplayBaseline
    {
        std::optional<SlotStateSnapshot> mSlotState;
        std::vector<SCPEnvelope> mEmittedEnvelopes;
        std::vector<ReplayTimerSnapshot> mTimers;
        std::vector<ReplayTimerSetCountSnapshot> mTimerSetCounts;
        std::size_t mTxSetDownloadWaitTimeCallCount{};
        bool mHasReachedBoundary{};
        std::optional<SCPEnvelope> mBoundaryEnvelope;
    };

    explicit DporScpNode(SecretKey const& secretKey,
                         SCPQuorumSet const& localQSet);

    explicit DporScpNode(SecretKey const& secretKey,
                         SCPQuorumSet const& localQSet,
                         Configuration const& config);

    NodeID const&
    getNodeID() const;

    SCP&
    getSCP();

    SCP const&
    getSCP() const;

    void
    storeQuorumSet(SCPQuorumSet const& qSet);

    SCPQuorumSetPtr
    getStoredQuorumSet(Hash const& qSetHash) const;

    bool
    nominate(uint64 slotIndex, Value const& value, Value const& previousValue);

    bool
    startBalloting(uint64 slotIndex, Value const& value);

    SCP::EnvelopeState
    receiveEnvelope(SCPEnvelope const& envelope);

    void
    setStateFromEnvelope(uint64 slotIndex, SCPEnvelope const& envelope);

    std::vector<SCPEnvelope>
    takePendingEnvelopes();

    std::vector<SCPEnvelope> const&
    getEmittedEnvelopes() const;

    bool
    hasActiveTimer(uint64 slotIndex, int timerID) const;

    std::optional<TimerState>
    getTimer(uint64 slotIndex, int timerID) const;

    bool
    fireTimer(uint64 slotIndex, int timerID);

    void
    enqueueTxSetDownloadWaitTimeChoice(std::chrono::milliseconds waitTime);

    ReplayBaseline
    snapshotReplayBaseline(uint64 slotIndex) const;

    void
    restoreReplayBaseline(ReplayBaseline const& baseline);

    void
    installNominationReplayTimer(uint64 slotIndex,
                                 std::chrono::milliseconds timeout,
                                 Value const& value,
                                 Value const& previousValue);

    void
    installBallotingReplayTimer(uint64 slotIndex,
                                std::chrono::milliseconds timeout);

    bool
    hasReachedBoundary() const;

    bool
    hasReachedPrepareBoundary() const;

    SCPEnvelope const*
    getBoundaryEnvelope() const;

    SCPEnvelope const*
    getPrepareBoundaryEnvelope() const;

    void
    signEnvelope(SCPEnvelope& envelope) override;
    SCPQuorumSetPtr
    getQSet(Hash const& qSetHash) override;
    std::optional<std::chrono::milliseconds>
    getTxSetDownloadWaitTime(Value const& value) const override;
    std::chrono::milliseconds
    getTxSetDownloadTimeout() const override;
    void
    emitEnvelope(SCPEnvelope const& envelope) override;
    ValidationLevel
    validateValue(uint64 slotIndex, Value const& value,
                  bool nomination) override;
    Value
    makeSkipLedgerValueFromValue(Value const& value) const override;
    bool
    isSkipLedgerValue(Value const& value) const override;
    Hash
    getHashOf(std::vector<xdr::opaque_vec<>> const& vals) const override;
    uint64
    computeHashNode(uint64 slotIndex, Value const& prev, bool isPriority,
                    int32_t roundNumber, NodeID const& nodeID) override;
    uint64
    computeValueHash(uint64 slotIndex, Value const& prev, int32_t roundNumber,
                     Value const& value) override;
    ValueWrapperPtr
    combineCandidates(uint64 slotIndex,
                      ValueWrapperPtrSet const& candidates) override;
    bool
    hasUpgrades(Value const& value) override;
    ValueWrapperPtr
    stripAllUpgrades(Value const& value) override;
    uint32_t
    getUpgradeNominationTimeoutLimit() const override;
    void
    setupTimer(uint64 slotIndex, int timerID,
               std::chrono::milliseconds timeout,
               std::function<void()> cb) override;
    void
    stopTimer(uint64 slotIndex, int timerID) override;
    std::chrono::milliseconds
    computeTimeout(uint32 roundNumber, bool isNomination) override;

  private:
    struct TimerSetCountEntry
    {
        uint64 mSlotIndex{};
        int mTimerID{};
        uint32_t mCount{};
    };

    void
    applyConfiguration(Configuration const& config);

    TimerState*
    findTimer(uint64 slotIndex, int timerID);

    TimerState const*
    findTimer(uint64 slotIndex, int timerID) const;

    void
    setTimer(TimerState timer);

    void
    clearTimer(uint64 slotIndex, int timerID);

    TimerSetCountEntry*
    findTimerSetCount(uint64 slotIndex, int timerID);

    void
    clearReplayState();

    bool
    isEnvelopeBoundaryForMode(SCPEnvelope const& envelope) const;

    SecretKey mSecretKey;
    SCP mSCP;
    std::map<NodeID, std::size_t> mNodeIndexMap;
    std::function<uint64(Value const&)> mValueHash;
    std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)>
        mCombineCandidates;
    uint32_t mPrepareBoundaryCounter{DEFAULT_PREPARE_BOUNDARY_COUNTER};
    BoundaryMode mBoundaryMode{BoundaryMode::Prepare};
    bool mAwaitTxSetDownloads{false};
    uint32_t mInitialNominationTimeoutMS{1000};
    uint32_t mIncrementNominationTimeoutMS{1000};
    uint32_t mInitialBallotTimeoutMS{1000};
    uint32_t mIncrementBallotTimeoutMS{1000};
    std::vector<std::chrono::milliseconds> mTxSetDownloadWaitTimes;
    bool mNondeterministicTxSetDownloadWaitTimeAfterFirstCall{false};
    mutable std::vector<std::chrono::milliseconds>
        mPendingTxSetDownloadWaitTimeChoices;
    mutable std::size_t mNextPendingTxSetDownloadWaitTimeChoice{0};
    mutable std::size_t mTxSetDownloadWaitTimeCallCount{0};
    std::optional<uint32_t> mNominationTimerSetLimit;
    std::optional<uint32_t> mBallotingTimerSetLimit;

    std::map<Hash, SCPQuorumSetPtr> mQuorumSets;
    std::vector<SCPEnvelope> mEmittedEnvelopes;
    std::vector<SCPEnvelope> mPendingEnvelopes;
    std::vector<TimerState> mTimers;
    std::vector<TimerSetCountEntry> mTimerSetCounts;
    bool mHasReachedBoundary{false};
    std::optional<SCPEnvelope> mBoundaryEnvelope;
};

} // namespace stellar
