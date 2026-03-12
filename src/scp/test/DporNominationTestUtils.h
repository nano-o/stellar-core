// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SHA.h"
#include "scp/LocalNode.h"
#include "scp/test/DporNominationNode.h"
#include "test/Catch2.h"
#include "xdrpp/marshal.h"

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

namespace stellar
{

namespace dpor_nomination_test
{

constexpr uint64_t kSlotIndex = 0;
constexpr uint64_t kTopLeaderPriority = std::numeric_limits<uint64_t>::max();

inline Value
makeValue(std::string const& label)
{
    return xdr::xdr_to_opaque(sha256(label));
}

inline Hash
getNormalizedQSetHash(SecretKey const& secretKey, SCPQuorumSet const& qSet)
{
    DporNominationNode node(secretKey, qSet);
    return node.getSCP().getLocalNode()->getQuorumSetHash();
}

inline DporNominationNode::Configuration
makeTopLeaderConfiguration(std::vector<NodeID> const& nodeIDs,
                           std::size_t leaderIndex)
{
    DporNominationNode::Configuration config;
    config.mPriorityLookup = [nodeIDs, leaderIndex](NodeID const& nodeID) {
        return nodeID == nodeIDs.at(leaderIndex) ? kTopLeaderPriority : 1;
    };
    return config;
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
