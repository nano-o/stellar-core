// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationSanityCheckHarness.h"
#include "scp/test/DporNominationInvestigation.h"
#include "scp/test/DporNominationTestUtils.h"

#include "scp/Slot.h"
#include "test/Catch2.h"
#include "util/Logging.h"

#include <dpor/algo/dpor.hpp>

#include <algorithm>
#include <optional>
#include <sstream>
#include <string>
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
// Keep this just high enough for the 3-node topology to cover the prepare
// boundary and the timer-versus-delivery races without masking state-space
// growth.
constexpr std::size_t kNominationVerifyMaxDepth = 16;
constexpr std::size_t kRound3NominationVerifyMaxDepth = 32;

struct SmallTopologyVerifyFixture
{
    std::vector<SecretKey> mValidators;
    std::vector<NodeID> mNodeIDs;
    SCPQuorumSet mQSet;
    std::vector<Hash> mQSetHashes;
    uint32_t mNominationRoundBoundary;
    Value mPreviousValue;
    Value mXValue;
    Value mYValue;
    DporNominationDporAdapter mAdapter;

    explicit SmallTopologyVerifyFixture(
        bool fixedTopLeader,
        uint32_t nominationRoundBoundary =
            DporNominationNode::DEFAULT_NOMINATION_ROUND_BOUNDARY)
        : mValidators(DporNominationSanityCheckHarness::makeValidatorSecretKeys(
              "dpor-nomination-verify-", kSmallTopologyValidatorCount))
        , mNodeIDs(DporNominationSanityCheckHarness::getNodeIDs(mValidators))
        , mQSet(DporNominationSanityCheckHarness::makeQuorumSet(
              mNodeIDs, kSmallTopologyThreshold))
        , mQSetHashes([&]() {
            std::vector<Hash> hashes;
            hashes.reserve(mValidators.size());
            auto const qSetHash = getNormalizedQSetHash(mQSet);
            for (std::size_t i = 0; i < mValidators.size(); ++i)
            {
                hashes.push_back(qSetHash);
            }
            return hashes;
        }())
        , mNominationRoundBoundary(nominationRoundBoundary)
        , mPreviousValue(makeValue("previous-verify"))
        , mXValue(makeValue("x-verify"))
        , mYValue(makeValue("y-verify"))
        , mAdapter(mValidators, mQSet, kSlotIndex, mPreviousValue,
                   std::vector<Value>{mXValue, mYValue, mYValue},
                   [&]() {
                       if (fixedTopLeader)
                       {
                           return makeTopLeaderConfiguration(
                               mNodeIDs, kLeaderIndex,
                               nominationRoundBoundary);
                       }
                       DporNominationNode::Configuration config;
                       config.mNominationRoundBoundary =
                           nominationRoundBoundary;
                       return config;
                   }())
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

template <typename Fixture>
ExecutionSummary
summarizeExecution(
    Fixture const& fixture,
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

template <typename Fixture>
VerifyExplorationSummary
exploreExecutions(Fixture const& fixture, bool blockingReceivesOnly = false,
                  std::size_t maxDepth = kNominationVerifyMaxDepth)
{
    VerifyExplorationSummary summary;

    VerifyConfig config;
    config.program = fixture.mAdapter.makeProgram();
    if (blockingReceivesOnly)
    {
        config.program.threads.for_each_assigned(
            [&](auto tid, auto const& threadFn) {
                config.program.threads[tid] =
                    [threadFn](auto const& trace,
                               std::size_t step) -> std::optional<
                        DporNominationDporAdapter::EventLabel> {
                    auto next = threadFn(trace, step);
                    if (!next)
                    {
                        return std::nullopt;
                    }

                    auto const* receive =
                        std::get_if<DporNominationDporAdapter::ReceiveLabel>(
                            &*next);
                    if (receive == nullptr || receive->is_blocking())
                    {
                        return next;
                    }

                    return DporNominationDporAdapter::EventLabel{
                        dpor::model::make_receive_label<DporNominationValue>(
                            receive->matches)};
                };
            });
    }
    config.max_depth = maxDepth;
    config.on_execution = [&summary, &fixture](auto const& graph) {
        summary.mExecutions.push_back(summarizeExecution(fixture, graph));
    };

    summary.mVerifyResult = dpor::algo::verify(config);
    LOG_INFO(DEFAULT_LOG, "DPOR executions explored: {}",
             summary.mVerifyResult.executions_explored);
    return summary;
}

VerifyExplorationSummary
exploreFourNodeLeaderConvergenceExecutions(
    dpor_nomination_investigation::ThresholdFixture const& fixture)
{
    VerifyExplorationSummary summary;

    VerifyConfig config;
    config.program =
        dpor_nomination_investigation::makeBoundedProgram(
            fixture,
            dpor_nomination_investigation::makeLeaderConvergenceStopSteps(
                fixture.mValidatorCount));
    config.max_depth = dpor_nomination_investigation::kMaxDepth;
    config.on_execution = [&summary, &fixture](auto const& graph) {
        summary.mExecutions.push_back(summarizeExecution(fixture, graph));
    };

    summary.mVerifyResult = dpor::algo::verify(config);
    LOG_INFO(DEFAULT_LOG, "DPOR executions explored: {}",
             summary.mVerifyResult.executions_explored);
    return summary;
}

bool
traceStartsWithTimerBottom(DporNominationDporAdapter::ThreadTrace const& trace)
{
    return !trace.empty() && trace.front().is_bottom();
}

bool
traceStartsWithDelivery(DporNominationDporAdapter::ThreadTrace const& trace)
{
    return !trace.empty() && !trace.front().is_bottom();
}

std::string
formatEnvelopeSummary(SCPEnvelope const& envelope)
{
    std::ostringstream out;
    switch (envelope.statement.pledges.type())
    {
    case SCP_ST_NOMINATE:
    {
        auto const& nomination = envelope.statement.pledges.nominate();
        out << "nom(v=" << nomination.votes.size()
            << ",a=" << nomination.accepted.size() << ")";
        break;
    }
    case SCP_ST_PREPARE:
    {
        auto const& prepare = envelope.statement.pledges.prepare();
        out << "prepare(b=" << prepare.ballot.counter << ")";
        break;
    }
    default:
        out << "stmt(" << static_cast<int>(envelope.statement.pledges.type())
            << ")";
        break;
    }
    return out.str();
}

std::string
formatTraceSummary(DporNominationDporAdapter::ThreadTrace const& trace)
{
    std::ostringstream out;
    bool first = true;
    for (auto const& observed : trace)
    {
        if (!first)
        {
            out << ", ";
        }
        first = false;

        if (observed.is_bottom())
        {
            out << "timer";
            continue;
        }

        auto const& delivery = observed.value();
        out << "recv<-" << delivery.mSenderThread << ":"
            << formatEnvelopeSummary(delivery.mEnvelope);
    }

    if (first)
    {
        out << "start";
    }
    return out.str();
}

void
logExploredExecutions(VerifyExplorationSummary const& exploration)
{
    for (std::size_t executionIndex = 0;
         executionIndex < exploration.mExecutions.size(); ++executionIndex)
    {
        auto const& execution = exploration.mExecutions[executionIndex];
        LOG_INFO(DEFAULT_LOG, "DPOR execution {}:", executionIndex + 1);
        for (std::size_t nodeIndex = 0; nodeIndex < execution.mThreads.size();
             ++nodeIndex)
        {
            auto const& threadSummary = execution.mThreads[nodeIndex];
            auto boundary =
                threadSummary.mBoundaryEnvelope
                    ? formatEnvelopeSummary(*threadSummary.mBoundaryEnvelope)
                    : std::string("none");
            LOG_INFO(DEFAULT_LOG,
                     "  n{} trace=[{}] boundary_reached={} boundary={}",
                     nodeIndex, formatTraceSummary(threadSummary.mTrace),
                     threadSummary.mReachedBoundary, boundary);
        }
    }
}

void
requireTimeoutBoundaryExploration(
    VerifyExplorationSummary const& exploration, uint32_t nominationRoundBoundary)
{
    bool sawTimerDrivenBoundary = false;
    bool sawBoundaryReachedBeforeAnyBoundaryEnvelope = false;
    // Round 1 starts from the initial nominate() call, so only N-1 timer
    // bottoms are needed to reach the configured round-N boundary.
    auto const timeoutBottomsToReachRoundBoundary =
        static_cast<std::size_t>(nominationRoundBoundary - 1);

    for (auto const& execution : exploration.mExecutions)
    {
        for (auto const& threadSummary : execution.mThreads)
        {
            if (!threadSummary.mReachedBoundary ||
                threadSummary.mTimerBottomCount <
                    timeoutBottomsToReachRoundBoundary)
            {
                continue;
            }

            sawTimerDrivenBoundary = true;
            // The round boundary is marked as soon as the configured boundary
            // round is armed. Some timeout-only executions stop there without
            // ever emitting another nomination or ballot envelope, so
            // diagnostics legitimately have no boundary envelope to report.
            sawBoundaryReachedBeforeAnyBoundaryEnvelope |=
                !threadSummary.mBoundaryEnvelope.has_value();
        }
    }

    REQUIRE(sawTimerDrivenBoundary);
    REQUIRE(sawBoundaryReachedBeforeAnyBoundaryEnvelope);
}

}

TEST_CASE("dpor nomination harness reproduces a simple leader scenario",
          "[scp][dpor][nomination]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);
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

TEST_CASE("dpor nomination verify explores the 3-validator milestone-3 "
          "topology", "[scp][dpor][nomination]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);
    SmallTopologyVerifyFixture fixture(true);
    auto const exploration = exploreExecutions(fixture, true);
    logExploredExecutions(exploration);

    REQUIRE(exploration.mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    REQUIRE_FALSE(exploration.mExecutions.empty());

    bool sawPrepareBoundary = false;

    for (auto const& execution : exploration.mExecutions)
    {
        for (std::size_t nodeIndex = 0; nodeIndex < execution.mThreads.size();
             ++nodeIndex)
        {
            auto const& threadSummary = execution.mThreads[nodeIndex];
            auto const& boundaryEnvelope = threadSummary.mBoundaryEnvelope;
            if (!boundaryEnvelope)
            {
                continue;
            }

            sawPrepareBoundary = true;
            requirePrepareEnvelope(*boundaryEnvelope, fixture.mNodeIDs[nodeIndex],
                                   fixture.mQSetHashes[nodeIndex], kSlotIndex,
                                   SCPBallot{1, fixture.mXValue});
        }
    }

    REQUIRE(sawPrepareBoundary);
}

TEST_CASE("dpor nomination verify can reach a 4-validator threshold-3 "
          "prepare boundary", "[scp][dpor][nomination]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);
    dpor_nomination_investigation::ThresholdFixture fixture;
    auto const exploration = exploreFourNodeLeaderConvergenceExecutions(fixture);

    REQUIRE(exploration.mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    REQUIRE_FALSE(exploration.mExecutions.empty());

    bool sawLeaderPrepareBoundary = false;

    for (auto const& execution : exploration.mExecutions)
    {
        auto const& leaderSummary = execution.mThreads[kLeaderIndex];
        if (!leaderSummary.mReachedBoundary)
        {
            continue;
        }

        // This reduced 4-node program stops followers after the minimum
        // accepted-update work needed to keep the search tractable. Some
        // executions therefore terminate before the leader receives enough
        // follow-up confirmations to prepare. The useful invariant here is
        // that any leader boundary reached in this topology is PREPARE(1, v1).
        sawLeaderPrepareBoundary = true;
        REQUIRE(leaderSummary.mBoundaryEnvelope.has_value());
        requirePrepareEnvelope(*leaderSummary.mBoundaryEnvelope,
                               fixture.mNodeIDs[kLeaderIndex],
                               fixture.mQSetHashes[kLeaderIndex], kSlotIndex,
                               SCPBallot{1,
                                         fixture.mInitialValues[kLeaderIndex]});
    }

    REQUIRE(sawLeaderPrepareBoundary);
}

TEST_CASE("dpor nomination investigation reports 4-node runtime growth",
          "[.][dpor][investigation]")
{
    auto const workers = std::size_t{8};
    auto const results =
        dpor_nomination_investigation::runFourNodeRuntimeGrowthInvestigation(
            workers);

    for (auto const& result : results)
    {
        CAPTURE(result.mScenario.mName);

        LOG_INFO(DEFAULT_LOG,
                 "DPOR 4-node investigation '{}' workers={} depth={} "
                 "stop_steps=[{},{},{},{}] result={} executions={} "
                 "elapsed_ms={}",
                 result.mScenario.mName, workers, result.mScenario.mMaxDepth,
                 result.mScenario.mStopSteps[0],
                 result.mScenario.mStopSteps[1],
                 result.mScenario.mStopSteps[2],
                 result.mScenario.mStopSteps[3],
                 dpor_nomination_investigation::verifyResultKindName(
                     result.mVerifyResult.kind),
                 result.mVerifyResult.executions_explored,
                 result.mElapsed.count());

        REQUIRE(result.mVerifyResult.kind != VerifyResultKind::ErrorFound);
        REQUIRE(result.mVerifyResult.executions_explored > 0);
    }
}

TEST_CASE("dpor nomination verify explores delivery-versus-timeout races",
          "[scp][dpor][nomination]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);
    // Timeout coverage must use the default round-varying leader selection.
    // A fixed top leader is sufficient for the message-only milestone-3 test,
    // but it makes timed-out nomination rounds fast-timeout forever inside
    // updateRoundLeaders().
    SmallTopologyVerifyFixture fixture(false);
    auto const exploration = exploreExecutions(fixture);

    REQUIRE(exploration.mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    REQUIRE_FALSE(exploration.mExecutions.empty());

    bool sawFollowerTimeoutBeforeDelivery = false;
    bool sawFollowerDeliveryBeforeTimeout = false;

    for (auto const& execution : exploration.mExecutions)
    {
        for (std::size_t followerIndex = kFirstFollowerIndex;
             followerIndex < execution.mThreads.size(); ++followerIndex)
        {
            auto const& trace = execution.mThreads[followerIndex].mTrace;
            sawFollowerTimeoutBeforeDelivery |=
                traceStartsWithTimerBottom(trace);
            sawFollowerDeliveryBeforeTimeout |=
                traceStartsWithDelivery(trace);
        }
    }

    REQUIRE(sawFollowerTimeoutBeforeDelivery);
    REQUIRE(sawFollowerDeliveryBeforeTimeout);
}

TEST_CASE("dpor nomination verify terminates timeout-heavy executions at the "
          "round boundary", "[scp][dpor][nomination]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);
    SmallTopologyVerifyFixture fixture(false);
    auto const exploration = exploreExecutions(fixture);

    REQUIRE(exploration.mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    requireTimeoutBoundaryExploration(exploration,
                                      fixture.mNominationRoundBoundary);
}

TEST_CASE("dpor nomination verify terminates timeout-heavy executions at the "
          "round-3 boundary", "[scp][dpor][nomination]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);
    SmallTopologyVerifyFixture fixture(false, 3);
    auto const exploration =
        exploreExecutions(fixture, false, kRound3NominationVerifyMaxDepth);

    REQUIRE(exploration.mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    requireTimeoutBoundaryExploration(exploration,
                                      fixture.mNominationRoundBoundary);
}

}
