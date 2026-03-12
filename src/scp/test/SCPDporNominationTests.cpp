// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationSanityCheckHarness.h"
#include "scp/test/DporNominationTestUtils.h"

#include "scp/Slot.h"
#include "test/Catch2.h"

#include <dpor/algo/dpor.hpp>

#include <algorithm>
#include <optional>
#include <vector>

namespace stellar
{

namespace
{

using namespace dpor_nomination_test;
using VerifyConfig = dpor::algo::DporConfigT<DporNominationValue>;
using VerifyResultKind = dpor::algo::VerifyResultKind;

constexpr std::size_t kSmallTopologyValidatorCount = 3;
constexpr std::size_t kSmallTopologyThreshold = 2;
constexpr std::size_t kLeaderIndex = 0;
constexpr std::size_t kFirstFollowerIndex = 1;
// The current DPOR API exposes a depth budget but no execution-count budget.
// Keep this just high enough for the 3-node topology to cover multiple
// timeout-versus-delivery races and fail fast if branching grows unexpectedly.
constexpr std::size_t kNominationVerifyMaxDepth = 16;

struct SmallTopologyVerifyFixture
{
    std::vector<SecretKey> mValidators;
    std::vector<NodeID> mNodeIDs;
    SCPQuorumSet mQSet;
    Value mPreviousValue;
    Value mXValue;
    Value mYValue;
    DporNominationDporAdapter mAdapter;

    SmallTopologyVerifyFixture()
        : mValidators(DporNominationSanityCheckHarness::makeValidatorSecretKeys(
              "dpor-nomination-verify-", kSmallTopologyValidatorCount))
        , mNodeIDs(DporNominationSanityCheckHarness::getNodeIDs(mValidators))
        , mQSet(DporNominationSanityCheckHarness::makeQuorumSet(
              mNodeIDs, kSmallTopologyThreshold))
        , mPreviousValue(makeValue("previous-verify"))
        , mXValue(makeValue("x-verify"))
        , mYValue(makeValue("y-verify"))
        , mAdapter(mValidators, mQSet, kSlotIndex, mPreviousValue,
                   std::vector<Value>{mXValue, mYValue, mYValue},
                   makeTopLeaderConfiguration(mNodeIDs, kLeaderIndex))
    {
    }
};

struct ThreadExecutionSummary
{
    DporNominationDporAdapter::ThreadTrace mTrace;
    std::size_t mTimerBottomCount{0};
    bool mReachedBoundary{false};
    std::optional<SCPEnvelope> mBoundaryEnvelope;
};

struct ExecutionSummary
{
    std::vector<ThreadExecutionSummary> mThreads;
};

struct VerifyExplorationSummary
{
    dpor::algo::VerifyResult mVerifyResult;
    std::vector<ExecutionSummary> mExecutions;
};

ExecutionSummary
summarizeExecution(
    SmallTopologyVerifyFixture const& fixture,
    dpor::model::ExplorationGraphT<DporNominationValue> const& graph)
{
    ExecutionSummary summary;
    summary.mThreads.reserve(fixture.mAdapter.size());

    for (std::size_t nodeIndex = 0; nodeIndex < fixture.mAdapter.size();
         ++nodeIndex)
    {
        auto trace =
            graph.thread_trace(DporNominationDporAdapter::toThreadID(nodeIndex));
        auto const timerBottomCount =
            static_cast<std::size_t>(std::count_if(
                trace.begin(), trace.end(),
                [](auto const& observed) { return observed.is_bottom(); }));
        auto const boundaryInspection =
            fixture.mAdapter.inspectNominationBoundary(nodeIndex, trace);

        ThreadExecutionSummary threadSummary;
        threadSummary.mTrace = std::move(trace);
        threadSummary.mTimerBottomCount = timerBottomCount;
        threadSummary.mReachedBoundary = boundaryInspection.mReachedBoundary;
        threadSummary.mBoundaryEnvelope =
            boundaryInspection.mBoundaryEnvelope;
        summary.mThreads.push_back(std::move(threadSummary));
    }

    return summary;
}

VerifyExplorationSummary
exploreExecutions(SmallTopologyVerifyFixture const& fixture)
{
    VerifyExplorationSummary summary;

    VerifyConfig config;
    config.program = fixture.mAdapter.makeProgram();
    config.max_depth = kNominationVerifyMaxDepth;
    config.on_execution = [&summary, &fixture](auto const& graph) {
        summary.mExecutions.push_back(summarizeExecution(fixture, graph));
    };

    summary.mVerifyResult = dpor::algo::verify(config);
    return summary;
}

bool
traceStartsWithTimerBottom(DporNominationDporAdapter::ThreadTrace const& trace)
{
    return !trace.empty() && trace.front().is_bottom();
}

bool
traceStartsWithDeliveryFrom(DporNominationDporAdapter::ThreadTrace const& trace,
                            dpor::model::ThreadId senderThread)
{
    return !trace.empty() && !trace.front().is_bottom() &&
           trace.front().value().mSenderThread == senderThread;
}

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

TEST_CASE("dpor nomination verify explores delivery-versus-timeout races",
          "[scp][dpor][nomination]")
{
    SmallTopologyVerifyFixture fixture;
    auto const exploration = exploreExecutions(fixture);

    REQUIRE(exploration.mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    REQUIRE_FALSE(exploration.mExecutions.empty());

    bool sawFollowerTimeoutBeforeDelivery = false;
    bool sawFollowerDeliveryBeforeTimeout = false;
    auto const leaderThread =
        DporNominationDporAdapter::toThreadID(kLeaderIndex);

    for (auto const& execution : exploration.mExecutions)
    {
        for (std::size_t followerIndex = kFirstFollowerIndex;
             followerIndex < execution.mThreads.size(); ++followerIndex)
        {
            auto const& trace = execution.mThreads[followerIndex].mTrace;
            sawFollowerTimeoutBeforeDelivery |=
                traceStartsWithTimerBottom(trace);
            sawFollowerDeliveryBeforeTimeout |=
                traceStartsWithDeliveryFrom(trace, leaderThread);
        }
    }

    REQUIRE(sawFollowerTimeoutBeforeDelivery);
    REQUIRE(sawFollowerDeliveryBeforeTimeout);
}

TEST_CASE("dpor nomination verify terminates timeout-heavy executions at the "
          "round boundary", "[scp][dpor][nomination]")
{
    SmallTopologyVerifyFixture fixture;
    auto const exploration = exploreExecutions(fixture);

    REQUIRE(exploration.mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);

    bool sawTimerDrivenBoundary = false;
    bool sawBoundaryReachedBeforeAnyBoundaryEnvelope = false;
    // Round 1 starts from the initial nominate() call, so only two timer
    // bottoms are needed to reach the round-3 boundary.
    constexpr std::size_t kTimeoutBottomsToReachRoundBoundary =
        DporNominationNode::NOMINATION_ROUND_BOUNDARY - 1;

    for (auto const& execution : exploration.mExecutions)
    {
        for (auto const& threadSummary : execution.mThreads)
        {
            if (!threadSummary.mReachedBoundary ||
                threadSummary.mTimerBottomCount <
                    kTimeoutBottomsToReachRoundBoundary)
            {
                continue;
            }

            sawTimerDrivenBoundary = true;
            // The round boundary is marked as soon as round 3 is armed. Some
            // timeout-only executions stop there without ever emitting another
            // nomination or ballot envelope, so diagnostics legitimately have
            // no boundary envelope to report.
            sawBoundaryReachedBeforeAnyBoundaryEnvelope |=
                !threadSummary.mBoundaryEnvelope.has_value();
        }
    }

    REQUIRE(sawTimerDrivenBoundary);
    REQUIRE(sawBoundaryReachedBeforeAnyBoundaryEnvelope);
}

}
