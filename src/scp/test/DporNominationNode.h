// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
#include "scp/SCP.h"

#include <chrono>
#include <cstddef>
#include <ctime>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace stellar
{

// Deterministic SCPDriver-backed test node shared by both the live nomination
// harness and the DPOR replay adapter. This is the reusable replay-relevant
// layer; it runs real SCP logic, records emitted envelopes and timers, and
// exposes direct inspection/manipulation hooks for tests and replay.
class DporNominationNode : public SCPDriver
{
  public:
    enum class InitialStateMode : std::uint8_t
    {
        Nomination,
        Balloting
    };

    enum class BoundaryMode : std::uint8_t
    {
        Prepare,
        Commit
    };

    // Default replay/test cutoff for nomination-only exploration.
    static constexpr uint32_t DEFAULT_NOMINATION_ROUND_BOUNDARY = 2;
    static constexpr uint32_t DEFAULT_BALLOTING_BOUNDARY = 1;
    static constexpr BoundaryMode DEFAULT_BOUNDARY_MODE =
        BoundaryMode::Prepare;

    struct Configuration
    {
        Configuration()
            : mNominationRoundBoundary(DEFAULT_NOMINATION_ROUND_BOUNDARY)
            , mBallotingBoundary(DEFAULT_BALLOTING_BOUNDARY)
            , mBoundaryMode(DEFAULT_BOUNDARY_MODE)
        {
        }

        // Node-to-index map for deterministic modulo-based leader rotation.
        // When set, exactly one 1-based node index wins each round with max
        // priority: ((roundNumber - 1) % numNodes) + 1.
        std::map<NodeID, std::size_t> mNodeIndexMap;
        std::function<uint64(NodeID const&)> mPriorityLookup;
        std::function<uint64(Value const&)> mValueHash;
        std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)>
            mCombineCandidates;
        uint32_t mNominationRoundBoundary;
        uint32_t mBallotingBoundary;
        BoundaryMode mBoundaryMode;
        std::optional<uint32_t> mNominationTimerSetLimit;
        std::optional<uint32_t> mBallotingTimerSetLimit;
    };

    struct TimerState
    {
        uint64 mSlotIndex;
        int mTimerID;
        std::chrono::milliseconds mTimeout;
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

    struct ReplayNominationRoundSnapshot
    {
        uint64 mSlotIndex{};
        uint32_t mRound{};
    };

    struct ReplayBaseline
    {
        std::optional<SlotStateSnapshot> mSlotState;
        std::vector<SCPEnvelope> mEmittedEnvelopes;
        std::vector<ReplayTimerSnapshot> mTimers;
        std::vector<ReplayTimerSetCountSnapshot> mTimerSetCounts;
        std::vector<ReplayNominationRoundSnapshot> mNominationRounds;
        bool mHasCrossedNominationBoundary{};
        std::optional<SCPEnvelope> mNominationBoundaryEnvelope;
    };

    explicit DporNominationNode(SecretKey const& secretKey,
                                SCPQuorumSet const& localQSet);

    explicit DporNominationNode(SecretKey const& secretKey,
                                SCPQuorumSet const& localQSet,
                                Configuration const& config);

    NodeID const&
    getNodeID() const;

    SCP&
    getSCP();

    SCP const&
    getSCP() const;

    void storeQuorumSet(SCPQuorumSet const& qSet);

    bool nominate(uint64 slotIndex, Value const& value,
                  Value const& previousValue);

    bool startBalloting(uint64 slotIndex, Value const& value);

    SCP::EnvelopeState receiveEnvelope(SCPEnvelope const& envelope);

    void setStateFromEnvelope(uint64 slotIndex, SCPEnvelope const& envelope);

    std::vector<SCPEnvelope> takePendingEnvelopes();

    std::vector<SCPEnvelope> const&
    getEmittedEnvelopes() const;

    std::vector<SCPEnvelope> getLatestMessagesSend(uint64 slotIndex);

    std::set<NodeID> getNominationLeaders(uint64 slotIndex);

    void setPriorityLookup(std::function<uint64(NodeID const&)> const& fn);

    void setValueHash(std::function<uint64(Value const&)> const& fn);

    void setCombineCandidates(
        std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const&
            fn);

    bool hasActiveTimer(uint64 slotIndex, int timerID) const;

    std::optional<TimerState> getTimer(uint64 slotIndex, int timerID) const;

    bool fireTimer(uint64 slotIndex, int timerID);

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

    bool hasCrossedNominationBoundary() const;

    SCPEnvelope const* getNominationBoundaryEnvelope() const;

    // SCPDriver hooks used by the embedded SCP instance.
    void signEnvelope(SCPEnvelope& envelope) override;
    SCPQuorumSetPtr getQSet(Hash const& qSetHash) override;
    std::optional<std::chrono::milliseconds>
    getTxSetDownloadWaitTime(Value const& value) const override;
    std::chrono::milliseconds getTxSetDownloadTimeout() const override;
    void emitEnvelope(SCPEnvelope const& envelope) override;
    ValidationLevel validateValue(uint64 slotIndex, Value const& value,
                                  bool nomination) override;
    Value makeSkipLedgerValueFromValue(Value const& value) const override;
    bool isSkipLedgerValue(Value const& value) const override;
    Hash getHashOf(std::vector<xdr::opaque_vec<>> const& vals) const override;
    uint64 computeHashNode(uint64 slotIndex, Value const& prev,
                           bool isPriority, int32_t roundNumber,
                           NodeID const& nodeID) override;
    uint64 computeValueHash(uint64 slotIndex, Value const& prev,
                            int32_t roundNumber, Value const& value) override;
    ValueWrapperPtr combineCandidates(
        uint64 slotIndex, ValueWrapperPtrSet const& candidates) override;
    bool hasUpgrades(Value const& value) override;
    ValueWrapperPtr stripAllUpgrades(Value const& value) override;
    uint32_t getUpgradeNominationTimeoutLimit() const override;
    void setupTimer(uint64 slotIndex, int timerID,
                    std::chrono::milliseconds timeout,
                    std::function<void()> cb) override;
    void stopTimer(uint64 slotIndex, int timerID) override;
    std::chrono::milliseconds computeTimeout(uint32 roundNumber,
                                             bool isNomination) override;

  private:
    using TimerKey = std::pair<uint64, int>;

    void applyConfiguration(Configuration const& config);
    void clearReplayState();
    uint32_t
    inferNominationRound(std::chrono::milliseconds timeout) const;
    bool isRoundBoundaryNominationEnvelope(SCPEnvelope const& envelope) const;
    bool isEnvelopeBoundaryForMode(SCPEnvelope const& envelope) const;

    SecretKey mSecretKey;
    SCP mSCP;
    std::map<NodeID, std::size_t> mNodeIndexMap;
    std::function<uint64(NodeID const&)> mPriorityLookup;
    std::function<uint64(Value const&)> mValueHash;
    std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)>
        mCombineCandidates;
    uint32_t mNominationRoundBoundary{DEFAULT_NOMINATION_ROUND_BOUNDARY};
    uint32_t mBallotingBoundary{DEFAULT_BALLOTING_BOUNDARY};
    BoundaryMode mBoundaryMode{DEFAULT_BOUNDARY_MODE};
    uint32_t mInitialNominationTimeoutMS{1000};
    uint32_t mIncrementNominationTimeoutMS{1000};
    uint32_t mInitialBallotTimeoutMS{1000};
    uint32_t mIncrementBallotTimeoutMS{1000};
    std::optional<uint32_t> mNominationTimerSetLimit;
    std::optional<uint32_t> mBallotingTimerSetLimit;

    std::map<Hash, SCPQuorumSetPtr> mQuorumSets;
    std::vector<SCPEnvelope> mEmittedEnvelopes;
    std::vector<SCPEnvelope> mPendingEnvelopes;
    std::map<TimerKey, TimerState> mTimers;
    std::map<TimerKey, uint32_t> mTimerSetCountByKey;
    std::map<uint64, uint32_t> mNominationRoundBySlot;
    bool mHasCrossedNominationBoundary{false};
    std::optional<SCPEnvelope> mNominationBoundaryEnvelope;
};

}
