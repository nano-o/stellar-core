// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
#include "scp/SCP.h"

#include <chrono>
#include <cstddef>
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

        std::function<uint64(NodeID const&)> mPriorityLookup;
        std::function<uint64(Value const&)> mValueHash;
        std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)>
            mCombineCandidates;
        uint32_t mNominationRoundBoundary;
        uint32_t mBallotingBoundary;
        BoundaryMode mBoundaryMode;
    };

    struct TimerState
    {
        uint64 mSlotIndex;
        int mTimerID;
        std::chrono::milliseconds mTimeout;
        std::function<void()> mCallback;
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

    bool hasCrossedNominationBoundary() const;

    SCPEnvelope const* getNominationBoundaryEnvelope() const;

    // SCPDriver hooks used by the embedded SCP instance.
    void signEnvelope(SCPEnvelope& envelope) override;
    SCPQuorumSetPtr getQSet(Hash const& qSetHash) override;
    void emitEnvelope(SCPEnvelope const& envelope) override;
    ValidationLevel validateValue(uint64 slotIndex, Value const& value,
                                  bool nomination) override;
    Hash getHashOf(std::vector<xdr::opaque_vec<>> const& vals) const override;
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
    uint32_t
    inferNominationRound(std::chrono::milliseconds timeout) const;
    bool isRoundBoundaryNominationEnvelope(SCPEnvelope const& envelope) const;
    bool isEnvelopeBoundaryForMode(SCPEnvelope const& envelope) const;

    SecretKey mSecretKey;
    SCP mSCP;
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

    std::map<Hash, SCPQuorumSetPtr> mQuorumSets;
    std::vector<SCPEnvelope> mEmittedEnvelopes;
    std::vector<SCPEnvelope> mPendingEnvelopes;
    std::map<TimerKey, TimerState> mTimers;
    std::map<uint64, uint32_t> mNominationRoundBySlot;
    bool mHasCrossedNominationBoundary{false};
    std::optional<SCPEnvelope> mNominationBoundaryEnvelope;
};

}
