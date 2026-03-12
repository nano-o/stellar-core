// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationDporAdapter.h"
#include "scp/test/DporNominationSanityCheckHarness.h"
#include "scp/test/DporNominationTestUtils.h"

#include "test/Catch2.h"

namespace stellar
{

namespace
{

using ThreadId = dpor::model::ThreadId;
using namespace dpor_nomination_test;

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
        : mValidators(DporNominationSanityCheckHarness::makeValidatorSecretKeys(
              "dpor-replay-", 3))
        , mNodeIDs(DporNominationSanityCheckHarness::getNodeIDs(mValidators))
        , mQSet(
              DporNominationSanityCheckHarness::makeQuorumSet(mNodeIDs, 2))
        , mQSetHash(getNormalizedQSetHash(mValidators[0], mQSet))
        , mPreviousValue(makeValue("previous"))
        , mXValue(makeValue("x"))
        , mYValue(makeValue("y"))
        , mAdapter(mValidators, mQSet, kSlotIndex, mPreviousValue,
                   std::vector<Value>{mXValue, mYValue, mYValue},
                   makeTopLeaderConfiguration(mNodeIDs, 0))
    {
        // These Milestone 2 replay checks stay below candidate combination, so
        // the node driver's default combineCandidates implementation is enough.
    }
};

void
deliverAndRecordTraceForThread(
    DporNominationSanityCheckHarness& sanityCheckHarness,
    ThreadId destinationThread,
    DporNominationDporAdapter::ThreadTrace& trace)
{
    for (std::size_t senderIndex = 0; senderIndex < sanityCheckHarness.size();
         ++senderIndex)
    {
        for (auto const& envelope :
             sanityCheckHarness.getNode(senderIndex).takePendingEnvelopes())
        {
            for (std::size_t receiverIndex = 0;
                 receiverIndex < sanityCheckHarness.size();
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

                sanityCheckHarness.getNode(receiverIndex).receiveEnvelope(
                    envelope);
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
    REQUIRE(leaderSend0.value.mSlotIndex == kSlotIndex);
    requireNominationEnvelope(leaderSend0.value.mEnvelope, fixture.mNodeIDs[0],
                              fixture.mQSetHash, kSlotIndex,
                              {fixture.mXValue}, {});

    auto leaderStep1 = program.threads.at(0)({}, 1);
    REQUIRE(leaderStep1.has_value());
    auto const& leaderSend1 = requireSend(*leaderStep1);
    REQUIRE(leaderSend1.destination == 2);
    requireNominationEnvelope(leaderSend1.value.mEnvelope, fixture.mNodeIDs[0],
                              fixture.mQSetHash, kSlotIndex,
                              {fixture.mXValue}, {});

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
                              fixture.mQSetHash, kSlotIndex, {fixture.mXValue},
                              {fixture.mXValue});
}

TEST_CASE("dpor nomination replay detects the first ballot boundary",
          "[scp][dpor][nomination][replay]")
{
    auto validators = DporNominationSanityCheckHarness::makeValidatorSecretKeys(
        "dpor-replay-boundary-", 4);
    auto nodeIDs = DporNominationSanityCheckHarness::getNodeIDs(validators);
    auto qSet = DporNominationSanityCheckHarness::makeQuorumSet(nodeIDs, 3);
    auto previousValue = makeValue("previous-boundary");
    auto xValue = makeValue("x-boundary");
    auto yValue = makeValue("y-boundary");

    auto config = makeTopLeaderConfiguration(nodeIDs, 0);

    DporNominationDporAdapter adapter(validators, qSet, kSlotIndex,
                                      previousValue,
                                      std::vector<Value>{xValue, yValue,
                                                         yValue, yValue},
                                      config);

    // This bootstrap cross-check still uses the live harness to generate a
    // trace for the replay adapter. The harness itself is sanity-checked in
    // SCPDporNominationTests.cpp; later verify()-driven milestone 3 tests
    // should reduce reliance on harness-generated traces.
    DporNominationSanityCheckHarness sanityCheckHarness(validators, qSet,
                                                        config);

    REQUIRE(
        sanityCheckHarness.getNode(0).nominate(kSlotIndex, xValue,
                                               previousValue));
    REQUIRE_FALSE(
        sanityCheckHarness.getNode(1).nominate(kSlotIndex, yValue,
                                               previousValue));
    REQUIRE_FALSE(
        sanityCheckHarness.getNode(2).nominate(kSlotIndex, yValue,
                                               previousValue));
    REQUIRE_FALSE(
        sanityCheckHarness.getNode(3).nominate(kSlotIndex, yValue,
                                               previousValue));

    DporNominationDporAdapter::ThreadTrace leaderTrace;
    // First pass delivers the leader's initial nomination, the second pass
    // delivers the followers' nomination echoes, and the third pass lets the
    // leader observe the quorum-supported accepted state and cross the
    // nomination boundary.
    constexpr std::size_t kBoundaryTraceDeliveryPasses = 3;
    for (std::size_t i = 0; i < kBoundaryTraceDeliveryPasses; ++i)
    {
        deliverAndRecordTraceForThread(sanityCheckHarness, 0, leaderTrace);
    }
    REQUIRE(sanityCheckHarness.getNode(0).hasCrossedNominationBoundary());

    auto boundaryEnvelope = adapter.getNominationBoundaryEnvelope(0, leaderTrace);
    REQUIRE(boundaryEnvelope.has_value());
    REQUIRE(boundaryEnvelope->statement.nodeID == nodeIDs[0]);
    REQUIRE(boundaryEnvelope->statement.pledges.type() == SCP_ST_PREPARE);
}

}
