// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationSimulation.h"

#include "crypto/SHA.h"
#include "scp/Slot.h"
#include "test/Catch2.h"
#include "xdrpp/marshal.h"

#include <algorithm>

namespace stellar
{

namespace
{

Value
makeValue(std::string const& label)
{
    return xdr::xdr_to_opaque(sha256(label));
}

void
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

void
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

TEST_CASE("dpor nomination harness reproduces a simple leader scenario",
          "[scp][dpor][nomination]")
{
    auto validators =
        DporNominationSimulation::makeValidatorSecretKeys("dpor-nomination-", 4);
    auto nodeIDs = DporNominationSimulation::getNodeIDs(validators);
    auto qSet = DporNominationSimulation::makeQuorumSet(nodeIDs, 3);

    auto previousValue = makeValue("previous");
    auto xValue = makeValue("x");
    auto yValue = makeValue("y");

    DporNominationSimulation simulation(validators, qSet);
    simulation.setPriorityLookup([&](NodeID const& nodeID) {
        return nodeID == nodeIDs[0] ? UINT64_MAX : 1;
    });

    auto localQSetHash = [&](std::size_t index) {
        return simulation.getNode(index).getSCP().getLocalNode()->getQuorumSetHash();
    };

    REQUIRE(simulation.size() == 4);

    REQUIRE(simulation.getNode(0).nominate(0, xValue, previousValue));
    REQUIRE_FALSE(simulation.getNode(1).nominate(0, yValue, previousValue));
    REQUIRE_FALSE(simulation.getNode(2).nominate(0, yValue, previousValue));
    REQUIRE_FALSE(simulation.getNode(3).nominate(0, yValue, previousValue));

    REQUIRE(simulation.getNode(1).hasActiveTimer(0, Slot::NOMINATION_TIMER));
    REQUIRE(simulation.getNode(2).hasActiveTimer(0, Slot::NOMINATION_TIMER));
    REQUIRE(simulation.getNode(3).hasActiveTimer(0, Slot::NOMINATION_TIMER));

    auto const& leaderEnvelopes = simulation.getNode(0).getEmittedEnvelopes();
    REQUIRE(leaderEnvelopes.size() == 1);
    requireNominationEnvelope(leaderEnvelopes[0], nodeIDs[0], localQSetHash(0), 0,
                              {xValue}, {});

    REQUIRE(simulation.broadcastPendingEnvelopesOnce() == 3);

    for (std::size_t i = 1; i < simulation.size(); ++i)
    {
        auto const& peerEnvelopes = simulation.getNode(i).getEmittedEnvelopes();
        REQUIRE(peerEnvelopes.size() == 1);
        requireNominationEnvelope(peerEnvelopes[0], nodeIDs[i], localQSetHash(i), 0,
                                  {xValue}, {});
    }

    REQUIRE(simulation.broadcastPendingEnvelopesOnce() == 9);

    auto const& leaderUpdates = simulation.getNode(0).getEmittedEnvelopes();
    REQUIRE(leaderUpdates.size() >= 2);
    requireNominationEnvelope(leaderUpdates[1], nodeIDs[0], localQSetHash(0), 0,
                              {xValue}, {xValue});

    REQUIRE(simulation.broadcastPendingEnvelopesOnce() > 0);

    auto const* boundaryEnvelope =
        simulation.getNode(0).getNominationBoundaryEnvelope();
    REQUIRE(simulation.getNode(0).hasCrossedNominationBoundary());
    REQUIRE(boundaryEnvelope != nullptr);
    requirePrepareEnvelope(*boundaryEnvelope, nodeIDs[0], localQSetHash(0), 0,
                           SCPBallot{1, xValue});
    REQUIRE_FALSE(
        simulation.getNode(0).hasActiveTimer(0, Slot::NOMINATION_TIMER));
}

}
