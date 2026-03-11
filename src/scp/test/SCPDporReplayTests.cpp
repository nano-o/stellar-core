// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationDporAdapter.h"
#include "scp/test/DporNominationSimulation.h"

#include "crypto/SHA.h"
#include "scp/LocalNode.h"
#include "test/Catch2.h"
#include "xdrpp/marshal.h"

#include <algorithm>
#include <limits>
#include <string>

namespace stellar
{

namespace
{

using ThreadId = dpor::model::ThreadId;

Value
makeValue(std::string const& label)
{
    return xdr::xdr_to_opaque(sha256(label));
}

Hash
getNormalizedQSetHash(SecretKey const& secretKey, SCPQuorumSet const& qSet)
{
    DporNominationNode node(secretKey, qSet);
    return node.getSCP().getLocalNode()->getQuorumSetHash();
}

struct ReplayFixture
{
    std::vector<SecretKey> mValidators;
    std::vector<NodeID> mNodeIDs;
    SCPQuorumSet mQSet;
    Hash mQSetHash;
    Value mPreviousValue;
    Value mXValue;
    Value mYValue;
    DporNominationDporAdapter mAdapter;

    ReplayFixture()
        : mValidators(DporNominationSimulation::makeValidatorSecretKeys(
              "dpor-replay-", 3))
        , mNodeIDs(DporNominationSimulation::getNodeIDs(mValidators))
        , mQSet(DporNominationSimulation::makeQuorumSet(mNodeIDs, 2))
        , mQSetHash(getNormalizedQSetHash(mValidators[0], mQSet))
        , mPreviousValue(makeValue("previous"))
        , mXValue(makeValue("x"))
        , mYValue(makeValue("y"))
        , mAdapter(mValidators, mQSet, 0, mPreviousValue,
                   std::vector<Value>{mXValue, mYValue, mYValue})
    {
        // These Milestone 2 replay checks stay below candidate combination, so
        // the node driver's default combineCandidates implementation is enough.
        mAdapter.setPriorityLookup([nodeIDs = mNodeIDs](NodeID const& nodeID) {
            return nodeID == nodeIDs[0] ? std::numeric_limits<uint64_t>::max()
                                        : 1;
        });
    }
};

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

DporNominationDporAdapter::SendLabel const&
requireSend(DporNominationDporAdapter::EventLabel const& label)
{
    auto const* send =
        std::get_if<DporNominationDporAdapter::SendLabel>(&label);
    REQUIRE(send != nullptr);
    return *send;
}

DporNominationDporAdapter::ReceiveLabel const&
requireReceive(DporNominationDporAdapter::EventLabel const& label)
{
    auto const* receive =
        std::get_if<DporNominationDporAdapter::ReceiveLabel>(&label);
    REQUIRE(receive != nullptr);
    return *receive;
}

void
deliverAndRecordTraceForThread(
    DporNominationSimulation& simulation, ThreadId destinationThread,
    DporNominationDporAdapter::ThreadTrace& trace)
{
    for (std::size_t senderIndex = 0; senderIndex < simulation.size();
         ++senderIndex)
    {
        for (auto const& envelope :
             simulation.getNode(senderIndex).takePendingEnvelopes())
        {
            for (std::size_t receiverIndex = 0; receiverIndex < simulation.size();
                 ++receiverIndex)
            {
                if (receiverIndex == senderIndex)
                {
                    continue;
                }

                if (DporNominationDporAdapter::toThreadID(receiverIndex) ==
                    destinationThread)
                {
                    trace.emplace_back(DporNominationValue{
                        .mSenderThread =
                            DporNominationDporAdapter::toThreadID(senderIndex),
                        .mDestinationThread = destinationThread,
                        .mSlotIndex = envelope.statement.slotIndex,
                        .mEnvelope = envelope,
                    });
                }

                simulation.getNode(receiverIndex).receiveEnvelope(envelope);
            }
        }
    }
}

}

TEST_CASE("dpor nomination replay captures stepwise send fanout and replay",
          "[scp][dpor][nomination][replay]")
{
    ReplayFixture fixture;
    auto program = fixture.mAdapter.makeProgram();

    auto leaderStep0 = program.threads.at(0)({}, 0);
    REQUIRE(leaderStep0.has_value());
    auto const& leaderSend0 = requireSend(*leaderStep0);
    REQUIRE(leaderSend0.destination == 1);
    REQUIRE(leaderSend0.value.mSenderThread == 0);
    REQUIRE(leaderSend0.value.mDestinationThread == 1);
    REQUIRE(leaderSend0.value.mSlotIndex == 0);
    requireNominationEnvelope(leaderSend0.value.mEnvelope, fixture.mNodeIDs[0],
                              fixture.mQSetHash, 0, {fixture.mXValue}, {});

    auto leaderStep1 = program.threads.at(0)({}, 1);
    REQUIRE(leaderStep1.has_value());
    auto const& leaderSend1 = requireSend(*leaderStep1);
    REQUIRE(leaderSend1.destination == 2);
    requireNominationEnvelope(leaderSend1.value.mEnvelope, fixture.mNodeIDs[0],
                              fixture.mQSetHash, 0, {fixture.mXValue}, {});

    auto leaderStep2 = program.threads.at(0)({}, 2);
    REQUIRE(leaderStep2.has_value());
    auto const& leaderReceive = requireReceive(*leaderStep2);
    REQUIRE(leaderReceive.is_nonblocking());

    auto followerStep0 = program.threads.at(1)({}, 0);
    REQUIRE(followerStep0.has_value());
    REQUIRE(requireReceive(*followerStep0).is_nonblocking());

    DporNominationDporAdapter::ThreadTrace followerTrace;
    followerTrace.emplace_back(leaderSend0.value);

    auto followerStep1 = program.threads.at(1)(followerTrace, 1);
    REQUIRE(followerStep1.has_value());
    auto const& followerSend = requireSend(*followerStep1);
    REQUIRE(followerSend.destination == 0);
    REQUIRE(followerSend.value.mSenderThread == 1);
    REQUIRE(followerSend.value.mDestinationThread == 0);
    requireNominationEnvelope(followerSend.value.mEnvelope, fixture.mNodeIDs[1],
                              fixture.mQSetHash, 0, {fixture.mXValue},
                              {fixture.mXValue});
}

TEST_CASE("dpor nomination replay detects the first ballot boundary",
          "[scp][dpor][nomination][replay]")
{
    auto validators = DporNominationSimulation::makeValidatorSecretKeys(
        "dpor-replay-boundary-", 4);
    auto nodeIDs = DporNominationSimulation::getNodeIDs(validators);
    auto qSet = DporNominationSimulation::makeQuorumSet(nodeIDs, 3);
    auto previousValue = makeValue("previous-boundary");
    auto xValue = makeValue("x-boundary");
    auto yValue = makeValue("y-boundary");

    DporNominationDporAdapter adapter(validators, qSet, 0, previousValue,
                                      std::vector<Value>{xValue, yValue,
                                                         yValue, yValue});
    adapter.setPriorityLookup([nodeIDs](NodeID const& nodeID) {
        return nodeID == nodeIDs[0] ? std::numeric_limits<uint64_t>::max() : 1;
    });

    DporNominationSimulation simulation(validators, qSet);
    simulation.setPriorityLookup([nodeIDs](NodeID const& nodeID) {
        return nodeID == nodeIDs[0] ? std::numeric_limits<uint64_t>::max() : 1;
    });

    REQUIRE(simulation.getNode(0).nominate(0, xValue, previousValue));
    REQUIRE_FALSE(simulation.getNode(1).nominate(0, yValue, previousValue));
    REQUIRE_FALSE(simulation.getNode(2).nominate(0, yValue, previousValue));
    REQUIRE_FALSE(simulation.getNode(3).nominate(0, yValue, previousValue));

    DporNominationDporAdapter::ThreadTrace leaderTrace;
    deliverAndRecordTraceForThread(simulation, 0, leaderTrace);
    deliverAndRecordTraceForThread(simulation, 0, leaderTrace);
    deliverAndRecordTraceForThread(simulation, 0, leaderTrace);
    REQUIRE(simulation.getNode(0).hasCrossedNominationBoundary());

    auto boundaryEnvelope = adapter.getNominationBoundaryEnvelope(0, leaderTrace);
    REQUIRE(boundaryEnvelope.has_value());
    REQUIRE(boundaryEnvelope->statement.nodeID == nodeIDs[0]);
    REQUIRE(boundaryEnvelope->statement.pledges.type() == SCP_ST_PREPARE);
}

}
