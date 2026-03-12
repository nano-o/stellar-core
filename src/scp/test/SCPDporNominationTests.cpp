// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationSanityCheckHarness.h"
#include "scp/test/DporNominationTestUtils.h"

#include "scp/Slot.h"
#include "test/Catch2.h"

namespace stellar
{

namespace
{

using namespace dpor_nomination_test;

}

TEST_CASE("dpor nomination harness reproduces a simple leader scenario",
          "[scp][dpor][nomination]")
{
    auto validators =
        DporNominationSanityCheckHarness::makeValidatorSecretKeys(
            "dpor-nomination-", 4);
    auto nodeIDs = DporNominationSanityCheckHarness::getNodeIDs(validators);
    auto qSet = DporNominationSanityCheckHarness::makeQuorumSet(nodeIDs, 3);

    auto previousValue = makeValue("previous");
    auto xValue = makeValue("x");
    auto yValue = makeValue("y");
    auto config = makeTopLeaderConfiguration(nodeIDs, 0);

    DporNominationSanityCheckHarness sanityCheckHarness(validators, qSet, config);

    auto localQSetHash = [&](std::size_t index) {
        return sanityCheckHarness.getNode(index)
            .getSCP()
            .getLocalNode()
            ->getQuorumSetHash();
    };

    REQUIRE(sanityCheckHarness.size() == 4);

    REQUIRE(sanityCheckHarness.getNode(0).nominate(kSlotIndex, xValue,
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

    REQUIRE(
        sanityCheckHarness.getNode(1).hasActiveTimer(kSlotIndex,
                                                     Slot::NOMINATION_TIMER));
    REQUIRE(
        sanityCheckHarness.getNode(2).hasActiveTimer(kSlotIndex,
                                                     Slot::NOMINATION_TIMER));
    REQUIRE(
        sanityCheckHarness.getNode(3).hasActiveTimer(kSlotIndex,
                                                     Slot::NOMINATION_TIMER));

    auto const& leaderEnvelopes =
        sanityCheckHarness.getNode(0).getEmittedEnvelopes();
    REQUIRE(leaderEnvelopes.size() == 1);
    requireNominationEnvelope(leaderEnvelopes[0], nodeIDs[0], localQSetHash(0),
                              kSlotIndex, {xValue}, {});

    constexpr std::size_t kLeaderFanoutDeliveries = 3;
    REQUIRE(sanityCheckHarness.broadcastPendingEnvelopesOnce() ==
            kLeaderFanoutDeliveries);

    for (std::size_t i = 1; i < sanityCheckHarness.size(); ++i)
    {
        auto const& peerEnvelopes =
            sanityCheckHarness.getNode(i).getEmittedEnvelopes();
        REQUIRE(peerEnvelopes.size() == 1);
        requireNominationEnvelope(peerEnvelopes[0], nodeIDs[i], localQSetHash(i),
                                  kSlotIndex, {xValue}, {});
    }

    // Three peers each fan out a single nomination to the other three nodes.
    constexpr std::size_t kFollowerEchoDeliveries = 9;
    REQUIRE(sanityCheckHarness.broadcastPendingEnvelopesOnce() ==
            kFollowerEchoDeliveries);

    auto const& leaderUpdates =
        sanityCheckHarness.getNode(0).getEmittedEnvelopes();
    REQUIRE(leaderUpdates.size() >= 2);
    requireNominationEnvelope(leaderUpdates[1], nodeIDs[0], localQSetHash(0),
                              kSlotIndex, {xValue}, {xValue});

    REQUIRE(sanityCheckHarness.broadcastPendingEnvelopesOnce() > 0);

    auto const* boundaryEnvelope =
        sanityCheckHarness.getNode(0).getNominationBoundaryEnvelope();
    REQUIRE(sanityCheckHarness.getNode(0).hasCrossedNominationBoundary());
    REQUIRE(boundaryEnvelope != nullptr);
    requirePrepareEnvelope(*boundaryEnvelope, nodeIDs[0], localQSetHash(0),
                           kSlotIndex, SCPBallot{1, xValue});
    REQUIRE(sanityCheckHarness.getNode(0).takePendingEnvelopes().empty());
    REQUIRE_FALSE(
        sanityCheckHarness.getNode(0).hasActiveTimer(kSlotIndex,
                                                     Slot::NOMINATION_TIMER));
}

}
