// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SHA.h"
#include "scp/QuorumSetUtils.h"
#include "scp/test/DporNominationDporAdapter.h"
#include "test/Catch2.h"
#include "util/Logging.h"
#include "xdrpp/marshal.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace stellar
{

namespace dpor_nomination_test
{

constexpr uint64_t kSlotIndex = 0;
constexpr uint64_t kTopLeaderPriority = std::numeric_limits<uint64_t>::max();

class ScopedPartitionLogLevel
{
  public:
    ScopedPartitionLogLevel(char const* partition, LogLevel level)
        : mPartition(Logging::normalizePartition(partition))
        , mPreviousLevel(Logging::getLogLevel(mPartition))
    {
        Logging::setLogLevel(level, mPartition.c_str());
        // Install a null logger so that the cached LogPtr itself returns
        // false from should_log(), avoiding any mutex acquisition in the
        // CLOG macros' fast path during concurrent DPOR replay.
        Logging::installNullLoggerForPartition(mPartition);
    }

    ScopedPartitionLogLevel(ScopedPartitionLogLevel const&) = delete;
    ScopedPartitionLogLevel&
    operator=(ScopedPartitionLogLevel const&) = delete;

    ~ScopedPartitionLogLevel()
    {
        Logging::restoreLoggerForPartition(mPartition);
        Logging::setLogLevel(mPreviousLevel, mPartition.c_str());
    }

  private:
    std::string mPartition;
    LogLevel mPreviousLevel;
};

inline Value
makeValue(std::string const& label)
{
    return xdr::xdr_to_opaque(sha256(label));
}

inline Hash
getNormalizedQSetHash(SCPQuorumSet qSet)
{
    // SCP statements hash the LocalNode-normalized quorum set, which may
    // differ from a plain hash of the caller-provided XDR shape.
    normalizeQSet(qSet);
    return sha256(xdr::xdr_to_opaque(qSet));
}

inline DporNominationNode::Configuration
makeTopLeaderConfiguration(std::vector<NodeID> const& nodeIDs,
                           std::size_t leaderIndex,
                           uint32_t nominationRoundBoundary =
                               DporNominationNode::
                                   DEFAULT_NOMINATION_ROUND_BOUNDARY)
{
    DporNominationNode::Configuration config;
    config.mNominationRoundBoundary = nominationRoundBoundary;
    auto sharedNodeIDs = std::make_shared<std::vector<NodeID> const>(nodeIDs);
    config.mPriorityLookup = [sharedNodeIDs, leaderIndex](NodeID const& nodeID) {
        return nodeID == sharedNodeIDs->at(leaderIndex) ? kTopLeaderPriority
                                                        : 1;
    };
    return config;
}

inline DporNominationDporAdapter::SendLabel const&
requireSend(DporNominationDporAdapter::EventLabel const& label)
{
    auto const* send =
        std::get_if<DporNominationDporAdapter::SendLabel>(&label);
    REQUIRE(send != nullptr);
    return *send;
}

inline DporNominationDporAdapter::ReceiveLabel const&
requireReceive(DporNominationDporAdapter::EventLabel const& label)
{
    auto const* receive =
        std::get_if<DporNominationDporAdapter::ReceiveLabel>(&label);
    REQUIRE(receive != nullptr);
    return *receive;
}

inline void
requireNominationEnvelope(SCPEnvelope const& envelope, NodeID const& nodeID,
                          Hash const& qSetHash, uint64 slotIndex,
                          std::vector<Value> votes,
                          std::vector<Value> accepted)
{
    std::sort(votes.begin(), votes.end());
    std::sort(accepted.begin(), accepted.end());

    REQUIRE(envelope.statement.nodeID == nodeID);
    REQUIRE(envelope.statement.slotIndex == slotIndex);
    REQUIRE(envelope.statement.pledges.type() == SCP_ST_NOMINATE);

    auto const& nomination = envelope.statement.pledges.nominate();
    REQUIRE(nomination.quorumSetHash == qSetHash);
    REQUIRE(std::vector<Value>(nomination.votes.begin(), nomination.votes.end()) ==
            votes);
    REQUIRE(std::vector<Value>(nomination.accepted.begin(),
                               nomination.accepted.end()) == accepted);
}

inline void
requirePrepareEnvelope(SCPEnvelope const& envelope, NodeID const& nodeID,
                       Hash const& qSetHash, uint64 slotIndex,
                       SCPBallot const& ballot)
{
    REQUIRE(envelope.statement.nodeID == nodeID);
    REQUIRE(envelope.statement.slotIndex == slotIndex);
    REQUIRE(envelope.statement.pledges.type() == SCP_ST_PREPARE);

    auto const& prepare = envelope.statement.pledges.prepare();
    REQUIRE(prepare.quorumSetHash == qSetHash);
    REQUIRE(prepare.ballot == ballot);
}

}

}
