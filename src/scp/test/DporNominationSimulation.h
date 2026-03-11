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
#include <string>
#include <utility>
#include <vector>

namespace stellar
{

class DporNominationNode : public SCPDriver
{
  public:
    struct TimerState
    {
        uint64 mSlotIndex;
        int mTimerID;
        std::chrono::milliseconds mTimeout;
        std::function<void()> mCallback;
    };

    explicit DporNominationNode(SecretKey const& secretKey,
                                SCPQuorumSet const& localQSet);

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

    SecretKey mSecretKey;
    SCP mSCP;
    std::map<Hash, SCPQuorumSetPtr> mQuorumSets;
    std::vector<SCPEnvelope> mEmittedEnvelopes;
    std::vector<SCPEnvelope> mPendingEnvelopes;
    std::map<TimerKey, TimerState> mTimers;
    std::function<uint64(Value const&)> mValueHash;
    std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)>
        mCombineCandidates;
    std::optional<SCPEnvelope> mNominationBoundaryEnvelope;
    uint32_t mInitialNominationTimeoutMS{1000};
    uint32_t mIncrementNominationTimeoutMS{1000};
    uint32_t mInitialBallotTimeoutMS{1000};
    uint32_t mIncrementBallotTimeoutMS{1000};
};

class DporNominationSimulation
{
  public:
    explicit DporNominationSimulation(std::vector<SecretKey> const& validators,
                                      SCPQuorumSet const& qSet);

    static std::vector<SecretKey>
    makeValidatorSecretKeys(std::string const& seedPrefix, std::size_t count);

    static std::vector<NodeID>
    getNodeIDs(std::vector<SecretKey> const& validators);

    static SCPQuorumSet makeQuorumSet(std::vector<NodeID> const& nodeIDs,
                                      uint32_t threshold);

    std::size_t
    size() const;

    DporNominationNode&
    getNode(std::size_t index);

    DporNominationNode const&
    getNode(std::size_t index) const;

    void setPriorityLookup(std::function<uint64(NodeID const&)> const& fn);

    void setValueHash(std::function<uint64(Value const&)> const& fn);

    void setCombineCandidates(
        std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const&
            fn);

    std::size_t broadcastPendingEnvelopesOnce();

  private:
    std::vector<std::unique_ptr<DporNominationNode>> mNodes;
};

}
