// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationNode.h"

#include "crypto/SHA.h"
#include "scp/LocalNode.h"
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

DporNominationNode::DporNominationNode(SecretKey const& secretKey,
                                       SCPQuorumSet const& localQSet)
    : mSecretKey(secretKey)
    , mSCP(*this, mSecretKey.getPublicKey(), true, localQSet)
    , mValueHash(defaultValueHash)
{
    // Register both the caller-provided qset and the LocalNode-normalized form,
    // because emitted envelopes carry the normalized hash while future
    // heterogeneous tests may still want access to the original shape.
    storeQuorumSet(localQSet);
    storeQuorumSet(mSCP.getLocalNode()->getQuorumSet());
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

bool
DporNominationNode::nominate(uint64 slotIndex, Value const& value,
                             Value const& previousValue)
{
    return mSCP.nominate(slotIndex, wrapValue(value), previousValue);
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
    return mSCP.getNominationLeaders(slotIndex);
}

void
DporNominationNode::setPriorityLookup(
    std::function<uint64(NodeID const&)> const& fn)
{
    SCPDriver::setPriorityLookup(fn);
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

bool
DporNominationNode::hasCrossedNominationBoundary() const
{
    return mNominationBoundaryEnvelope.has_value();
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

void
DporNominationNode::emitEnvelope(SCPEnvelope const& envelope)
{
    auto const crossesBoundary =
        envelope.statement.pledges.type() != SCP_ST_NOMINATE;
    if (!mNominationBoundaryEnvelope && crossesBoundary)
    {
        mNominationBoundaryEnvelope = envelope;
    }
    mEmittedEnvelopes.push_back(envelope);
    if (!crossesBoundary)
    {
        mPendingEnvelopes.push_back(envelope);
    }
}

SCPDriver::ValidationLevel
DporNominationNode::validateValue(uint64, Value const&, bool)
{
    return SCPDriver::kFullyValidatedValue;
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
    mTimers[{slotIndex, timerID}] = TimerState{slotIndex, timerID, timeout, cb};
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
