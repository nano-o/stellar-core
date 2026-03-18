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
constexpr std::size_t kFirstFollowerIndex = 1;
// The current DPOR API exposes a depth budget but no execution-count budget.
// Keep this just high enough for the 3-node topology to cover the prepare
// boundary and the timer-versus-delivery races without masking state-space
// growth.
constexpr std::size_t kNominationVerifyMaxDepth = 64;
constexpr std::size_t kRound3NominationVerifyMaxDepth = 128;

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
                       DporNominationNode::Configuration config;
                       config.mNodeIndexMap = makeNodeIndexMap(mNodeIDs);
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
DporNominationDporAdapter const&
getAdapter(Fixture const& fixture)
{
    return fixture.mAdapter;
}

DporNominationDporAdapter const&
getAdapter(DporNominationDporAdapter const& adapter)
{
    return adapter;
}

template <typename Fixture>
ExecutionSummary
summarizeExecution(
    Fixture const& fixture,
    dpor::model::ExplorationGraphT<DporNominationValue> const& graph)
{
    auto const& adapter = getAdapter(fixture);
    ExecutionSummary summary;
    summary.mThreads.reserve(adapter.size());

    for (std::size_t nodeIndex = 0; nodeIndex < adapter.size();
         ++nodeIndex)
    {
        auto trace =
            graph.thread_trace(DporNominationDporAdapter::toThreadID(nodeIndex));
        auto const timerBottomCount =
            static_cast<std::size_t>(std::count_if(
                trace.begin(), trace.end(),
                [](auto const& observed) { return observed.is_bottom(); }));
        auto const boundaryInspection =
            adapter.inspectNominationBoundary(nodeIndex, trace);

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
    auto const& adapter = getAdapter(fixture);
    VerifyExplorationSummary summary;

    VerifyConfig config;
    config.program = adapter.makeProgram();
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

SCPEnvelope
makeTestExternalizeEnvelope(NodeID const& nodeID, Hash const& qSetHash,
                            uint64 slotIndex, SCPBallot const& ballot,
                            uint32 nH)
{
    SCPEnvelope envelope;
    envelope.statement.nodeID = nodeID;
    envelope.statement.slotIndex = slotIndex;
    envelope.statement.pledges.type(SCP_ST_EXTERNALIZE);
    auto& ext = envelope.statement.pledges.externalize();
    ext.commit = ballot;
    ext.nH = nH;
    ext.commitQuorumSetHash = qSetHash;
    return envelope;
}

SCPEnvelope
makeTestPrepareEnvelope(NodeID const& nodeID, Hash const& qSetHash,
                        uint64 slotIndex, SCPBallot const& ballot,
                        std::optional<SCPBallot> prepared = std::nullopt,
                        std::optional<SCPBallot> preparedPrime = std::nullopt)
{
    SCPEnvelope envelope;
    envelope.statement.nodeID = nodeID;
    envelope.statement.slotIndex = slotIndex;
    envelope.statement.pledges.type(SCP_ST_PREPARE);
    auto& prepare = envelope.statement.pledges.prepare();
    prepare.ballot = ballot;
    prepare.quorumSetHash = qSetHash;
    prepare.nC = 0;
    prepare.nH = 0;
    if (prepared)
    {
        prepare.prepared.activate() = *prepared;
    }
    if (preparedPrime)
    {
        prepare.preparedPrime.activate() = *preparedPrime;
    }
    return envelope;
}

Value
makeSkipValue(Value const& value)
{
    Value skipValue;
    skipValue.resize(5 + value.size());
    skipValue[0] = 'S';
    skipValue[1] = 'K';
    skipValue[2] = 'I';
    skipValue[3] = 'P';
    skipValue[4] = ':';
    std::copy(value.begin(), value.end(), skipValue.begin() + 5);
    return skipValue;
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
        if (delivery.mKind ==
            DporNominationValue::Kind::TxSetDownloadWaitTimeChoice)
        {
            out << "nd-wait="
                << delivery.mTxSetDownloadWaitTimeMilliseconds << "ms";
        }
        else
        {
            out << "recv<-" << delivery.mSenderThread << ":"
                << formatEnvelopeSummary(delivery.mEnvelope);
        }
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
    DporNominationNode::Configuration config;
    config.mNodeIndexMap = makeNodeIndexMap(nodeIDs);

    DporNominationSanityCheckHarness sanityCheckHarness(validators, qSet, config);

    auto localQSetHash = [&](std::size_t index) {
        return sanityCheckHarness.getNode(index)
            .getSCP()
            .getLocalNode()
            ->getQuorumSetHash();
    };

    REQUIRE(sanityCheckHarness.size() == 4);

    // With modulo leader selection at round 1, only node 0 (1-based index 1)
    // is leader.
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

    // Non-leaders arm a nomination timer.
    REQUIRE(
        sanityCheckHarness.getNode(1).hasActiveTimer(kSlotIndex,
                                                     Slot::NOMINATION_TIMER));
    REQUIRE(
        sanityCheckHarness.getNode(2).hasActiveTimer(kSlotIndex,
                                                     Slot::NOMINATION_TIMER));
    REQUIRE(
        sanityCheckHarness.getNode(3).hasActiveTimer(kSlotIndex,
                                                     Slot::NOMINATION_TIMER));

    // The single leader emitted a nomination envelope.
    auto const& leader0Envelopes =
        sanityCheckHarness.getNode(0).getEmittedEnvelopes();
    REQUIRE(leader0Envelopes.size() == 1);
    requireNominationEnvelope(leader0Envelopes[0], nodeIDs[0], localQSetHash(0),
                              kSlotIndex, {xValue}, {});

    // One leader fans out to 3 peers.
    constexpr std::size_t kLeaderFanoutDeliveries = 3;
    REQUIRE(sanityCheckHarness.broadcastPendingEnvelopesOnce() ==
            kLeaderFanoutDeliveries);

    // Continue delivering until the leader crosses the nomination boundary.
    while (!sanityCheckHarness.getNode(0).hasCrossedNominationBoundary())
    {
        if (sanityCheckHarness.broadcastPendingEnvelopesOnce() == 0)
        {
            break;
        }
    }

    auto const* boundaryEnvelope =
        sanityCheckHarness.getNode(0).getNominationBoundaryEnvelope();
    REQUIRE(sanityCheckHarness.getNode(0).hasCrossedNominationBoundary());
    REQUIRE(boundaryEnvelope != nullptr);
    REQUIRE(boundaryEnvelope->statement.pledges.type() == SCP_ST_PREPARE);
}

TEST_CASE("dpor nomination verify explores the 3-validator milestone-3 "
          "topology", "[scp][dpor][nomination]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);
    SmallTopologyVerifyFixture fixture;
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
            REQUIRE(boundaryEnvelope->statement.pledges.type() == SCP_ST_PREPARE);
            REQUIRE(boundaryEnvelope->statement.pledges.prepare().ballot.counter == 1);
        }
    }

    REQUIRE(sawPrepareBoundary);
}

TEST_CASE("dpor nomination verify can reach a prepare boundary with "
          "nomination-only 3 validators",
          "[scp][dpor][nomination]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);
    constexpr std::size_t kValidatorCount = 3;
    auto const kThreshold =
        dpor_nomination_investigation::computeTwoThirdsThreshold(
            kValidatorCount);
    auto validators =
        DporNominationSanityCheckHarness::makeValidatorSecretKeys(
            "dpor-nomination-boundary-", kValidatorCount);
    auto nodeIDs = DporNominationSanityCheckHarness::getNodeIDs(validators);
    auto qSet =
        DporNominationSanityCheckHarness::makeQuorumSet(nodeIDs, kThreshold);
    auto previousValue = makeValue("previous-boundary");
    std::vector<Value> initialValues;
    for (std::size_t i = 0; i < kValidatorCount; ++i)
    {
        initialValues.push_back(
            makeValue("v" + std::to_string(i + 1) + "-boundary"));
    }

    DporNominationNode::Configuration config;
    config.mNodeIndexMap = makeNodeIndexMap(nodeIDs);

    DporNominationDporAdapter adapter(validators, qSet, kSlotIndex,
                                      previousValue, initialValues, config);
    auto const exploration = exploreExecutions(adapter);

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
            if (!threadSummary.mBoundaryEnvelope ||
                threadSummary.mBoundaryEnvelope->statement.pledges.type() !=
                    SCP_ST_PREPARE)
            {
                continue;
            }

            sawPrepareBoundary = true;
        }
    }

    REQUIRE(sawPrepareBoundary);
}

TEST_CASE("dpor nomination investigation reports 4-node runtime growth",
          "[.][dpor][investigation]")
{
    auto const workers = std::size_t{8};
    auto const results =
        dpor_nomination_investigation::runFourNodeRuntimeGrowthInvestigation(
            workers, std::nullopt, std::nullopt, true);

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

TEST_CASE("dpor nomination investigation supports fifo p2p mode",
          "[scp][dpor][investigation][fifo_p2p]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const communicationModel = dpor::model::CommunicationModel::FifoP2P;
    auto const results =
        dpor_nomination_investigation::runRuntimeGrowthInvestigation(
            1, std::size_t{1},
            dpor_nomination_investigation::InvestigationScenario::Id::
                UnrestrictedFollowers,
            true, kSmallTopologyValidatorCount,
            dpor_nomination_investigation::TimeoutSettings{},
            dpor_nomination_investigation::TimerSetLimitSettings{}, false,
            false, false, false, false, communicationModel);

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().mVerifyResult.kind !=
            VerifyResultKind::ErrorFound);
    REQUIRE(results.front().mVerifyResult.executions_explored > 0);

    std::ostringstream out;
    dpor_nomination_investigation::printInvestigationResults(
        out, results, 1, kSmallTopologyValidatorCount, true,
        dpor_nomination_investigation::TimeoutSettings{},
        dpor_nomination_investigation::TimerSetLimitSettings{}, false, false,
        false, false, false, communicationModel);

    REQUIRE(out.str().find("communication_model=fifo_p2p") !=
            std::string::npos);
}

TEST_CASE("dpor nomination investigation can bound timeout-driven unbounded "
          "searches with timer limits", "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const results =
        dpor_nomination_investigation::runRuntimeGrowthInvestigation(
            1, std::size_t{0},
            dpor_nomination_investigation::InvestigationScenario::Id::
                UnrestrictedFollowers,
            true,
            kSmallTopologyValidatorCount,
            dpor_nomination_investigation::TimeoutSettings{
                .mNomination = true},
            dpor_nomination_investigation::TimerSetLimitSettings{
                .mNomination = 2});

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    REQUIRE(results.front().mVerifyResult.executions_explored > 0);
}

TEST_CASE("dpor nomination investigation treats depth as a per-thread cutoff",
          "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const results =
        dpor_nomination_investigation::runRuntimeGrowthInvestigation(
            1, std::size_t{1},
            dpor_nomination_investigation::InvestigationScenario::Id::
                UnrestrictedFollowers,
            true, kSmallTopologyValidatorCount);

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    REQUIRE(results.front().mVerifyResult.executions_explored > 0);
}

TEST_CASE("dpor nomination investigation does not use a global dpor depth cap",
          "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const results =
        dpor_nomination_investigation::runRuntimeGrowthInvestigation(
            1, std::size_t{10},
            dpor_nomination_investigation::InvestigationScenario::Id::
                UnrestrictedFollowers,
            false, kSmallTopologyValidatorCount);

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    REQUIRE(results.front().mVerifyResult.executions_explored > 0);
}

TEST_CASE("dpor nomination investigation can detect terminal deadlocks",
          "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const results =
        dpor_nomination_investigation::runRuntimeGrowthInvestigation(
            1, std::size_t{1},
            dpor_nomination_investigation::InvestigationScenario::Id::
                UnrestrictedFollowers,
            true, kSmallTopologyValidatorCount,
            dpor_nomination_investigation::TimeoutSettings{},
            dpor_nomination_investigation::TimerSetLimitSettings{}, true);

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().mVerifyResult.kind ==
            VerifyResultKind::ErrorFound);
    REQUIRE(results.front().mVerifyResult.executions_explored == 1);
    REQUIRE(results.front().mVerifyResult.message.find("deadlock: thread ") !=
            std::string::npos);
}

TEST_CASE("dpor nomination investigation deadlock check accepts full step "
          "cutoffs", "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const results =
        dpor_nomination_investigation::runRuntimeGrowthInvestigation(
            1, std::size_t{1},
            dpor_nomination_investigation::InvestigationScenario::Id::
                UnrestrictedFollowers,
            true, kSmallTopologyValidatorCount,
            dpor_nomination_investigation::TimeoutSettings{},
            dpor_nomination_investigation::TimerSetLimitSettings{}, true);

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    REQUIRE(results.front().mVerifyResult.executions_explored > 0);
}

TEST_CASE("dpor nomination investigation deadlock check treats unbounded step "
          "limits as unreached", "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const results =
        dpor_nomination_investigation::runRuntimeGrowthInvestigation(
            1, std::size_t{0},
            dpor_nomination_investigation::InvestigationScenario::Id::
                UnrestrictedFollowers,
            true, kSmallTopologyValidatorCount,
            dpor_nomination_investigation::TimeoutSettings{},
            dpor_nomination_investigation::TimerSetLimitSettings{}, true);

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().mVerifyResult.kind ==
            VerifyResultKind::ErrorFound);
    REQUIRE(results.front().mVerifyResult.executions_explored == 1);
    REQUIRE(results.front().mVerifyResult.message.find(
                "without reaching an unbounded step limit") !=
            std::string::npos);
}

TEST_CASE("dpor nomination investigation termination check ignores "
          "step-limited executions", "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const results =
        dpor_nomination_investigation::runRuntimeGrowthInvestigation(
            1, std::size_t{10},
            dpor_nomination_investigation::InvestigationScenario::Id::
                UnrestrictedFollowers,
            true, kSmallTopologyValidatorCount,
            dpor_nomination_investigation::TimeoutSettings{},
            dpor_nomination_investigation::TimerSetLimitSettings{}, false,
            true);

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    REQUIRE(results.front().mVerifyResult.executions_explored > 0);
}

TEST_CASE("dpor nomination investigation termination check detects "
          "unbounded terminal executions without externalize",
          "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const results =
        dpor_nomination_investigation::runRuntimeGrowthInvestigation(
            1, std::size_t{0},
            dpor_nomination_investigation::InvestigationScenario::Id::
                UnrestrictedFollowers,
            true, kSmallTopologyValidatorCount,
            dpor_nomination_investigation::TimeoutSettings{},
            dpor_nomination_investigation::TimerSetLimitSettings{}, false,
            true);

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().mVerifyResult.kind ==
            VerifyResultKind::ErrorFound);
    REQUIRE(results.front().mVerifyResult.executions_explored == 1);
    REQUIRE(results.front().mVerifyResult.message.find(
                "termination: reached terminal execution without externalize") !=
            std::string::npos);
}

TEST_CASE("dpor nomination investigation can start directly in balloting with "
          "a threshold split", "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const scenarios =
        dpor_nomination_investigation::selectedRuntimeGrowthScenarios(
            kSmallTopologyValidatorCount,
            dpor_nomination_investigation::InvestigationScenario::Id::
                ThresholdSplitBalloting);
    REQUIRE(scenarios.size() == 1);

    auto const& scenario = scenarios.front();
    REQUIRE(scenario.mInitialStateMode ==
            DporNominationDporAdapter::InitialStateMode::Balloting);
    REQUIRE(scenario.mInitialValuePattern ==
            dpor_nomination_investigation::InitialValuePattern::
                ThresholdSplitXY);
    REQUIRE(scenario.mPerNodeTxSetDownloadWaitTimes.size() ==
            kSmallTopologyValidatorCount);

    dpor_nomination_investigation::ThresholdFixture fixture(
        kSmallTopologyValidatorCount, false,
        dpor_nomination_investigation::TimerSetLimitSettings{},
        scenario.mInitialValuePattern, scenario.mInitialStateMode,
        scenario.mTxSetDownloadWaitTimes,
        scenario.mPerNodeTxSetDownloadWaitTimes);

    for (std::size_t nodeIndex = 0; nodeIndex < fixture.mValidatorCount;
         ++nodeIndex)
    {
        auto next = fixture.mAdapter.captureNextEvent(nodeIndex, {}, 0);
        REQUIRE(next.has_value());

        auto const& send = requireSend(*next);
        auto const& expectedValue =
            nodeIndex < fixture.mThreshold ? fixture.mThresholdXValue
                                           : fixture.mThresholdYValue;
        requirePrepareEnvelope(send.value.mEnvelope,
                               fixture.mNodeIDs.at(nodeIndex),
                               fixture.mQSetHashes.at(nodeIndex), kSlotIndex,
                               SCPBallot(1, expectedValue));
    }
}

TEST_CASE("dpor nomination invariant checks turn initial replay violations "
          "into error events",
          "[scp][dpor][investigation][invariant]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    dpor_nomination_investigation::ThresholdFixture fixture(
        kSmallTopologyValidatorCount, false,
        dpor_nomination_investigation::TimerSetLimitSettings{},
        dpor_nomination_investigation::InitialValuePattern::ThresholdSplitXY,
        DporNominationDporAdapter::InitialStateMode::Balloting);

    fixture.mAdapter.setInvariantCheck(
        [](DporNominationNode const&,
           DporNominationNode::InvariantCheckContext const& context)
            -> std::optional<std::string> {
            if (context.mEvent ==
                DporNominationNode::InvariantCheckEvent::InitialBalloting)
            {
                return "reject initial prepare replay";
            }
            return std::nullopt;
        });

    for (std::size_t nodeIndex = 0; nodeIndex < fixture.mValidatorCount;
         ++nodeIndex)
    {
        auto next = fixture.mAdapter.captureNextEvent(nodeIndex, {}, 0);
        REQUIRE(next.has_value());
        static_cast<void>(requireError(*next));
    }

    VerifyConfig config;
    config.program = fixture.mAdapter.makeProgram();
    auto const result = dpor::algo::verify(config);
    REQUIRE(result.kind == VerifyResultKind::ErrorFound);
    REQUIRE(result.executions_explored == 1);
}

TEST_CASE("dpor nomination investigation threshold-split balloting only "
          "switches x nodes to skip on ballot 2 timeout",
          "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const scenarios =
        dpor_nomination_investigation::selectedRuntimeGrowthScenarios(
            kSmallTopologyValidatorCount,
            dpor_nomination_investigation::InvestigationScenario::Id::
                ThresholdSplitBalloting);
    REQUIRE(scenarios.size() == 1);

    auto const& scenario = scenarios.front();
    dpor_nomination_investigation::ThresholdFixture fixture(
        kSmallTopologyValidatorCount, false,
        dpor_nomination_investigation::TimerSetLimitSettings{},
        scenario.mInitialValuePattern, scenario.mInitialStateMode,
        scenario.mTxSetDownloadWaitTimes,
        scenario.mPerNodeTxSetDownloadWaitTimes);
    fixture.mAdapter.setTimeoutModes(false, true);

    for (std::size_t nodeIndex = 0; nodeIndex < fixture.mValidatorCount;
         ++nodeIndex)
    {
        auto const& expectedValue =
            nodeIndex < fixture.mThreshold ? fixture.mThresholdXValue
                                           : fixture.mThresholdYValue;

        auto firstSend = fixture.mAdapter.captureNextEvent(nodeIndex, {}, 0);
        REQUIRE(firstSend.has_value());
        requirePrepareEnvelope(requireSend(*firstSend).value.mEnvelope,
                               fixture.mNodeIDs.at(nodeIndex),
                               fixture.mQSetHashes.at(nodeIndex), kSlotIndex,
                               SCPBallot(1, expectedValue));

        auto receive = fixture.mAdapter.captureNextEvent(nodeIndex, {}, 2);
        REQUIRE(receive.has_value());
        REQUIRE(requireReceive(*receive).is_nonblocking());

        DporNominationDporAdapter::ThreadTrace trace{
            DporNominationDporAdapter::ObservedValue::bottom()};
        auto secondSend =
            fixture.mAdapter.captureNextEvent(nodeIndex, trace, 3);
        REQUIRE(secondSend.has_value());
        auto const expectedSecondBallotValue =
            nodeIndex < fixture.mThreshold ? makeSkipValue(expectedValue)
                                           : expectedValue;
        requirePrepareEnvelope(requireSend(*secondSend).value.mEnvelope,
                               fixture.mNodeIDs.at(nodeIndex),
                               fixture.mQSetHashes.at(nodeIndex), kSlotIndex,
                               SCPBallot(2, expectedSecondBallotValue));
    }
}

TEST_CASE("dpor nomination investigation threshold-split balloting can "
          "branch ballot-2 skip timeout nondeterministically",
          "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const scenarios =
        dpor_nomination_investigation::selectedRuntimeGrowthScenarios(
            kSmallTopologyValidatorCount,
            dpor_nomination_investigation::InvestigationScenario::Id::
                ThresholdSplitBalloting);
    REQUIRE(scenarios.size() == 1);

    auto const& scenario = scenarios.front();
    dpor_nomination_investigation::ThresholdFixture fixture(
        kSmallTopologyValidatorCount, false,
        dpor_nomination_investigation::TimerSetLimitSettings{},
        scenario.mInitialValuePattern, scenario.mInitialStateMode,
        scenario.mTxSetDownloadWaitTimes,
        scenario.mPerNodeTxSetDownloadWaitTimes, true);
    fixture.mAdapter.setTimeoutModes(false, true);

    auto const belowThresholdWait =
        static_cast<int64_t>(DporNominationNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS) -
        1;
    auto const aboveThresholdWait =
        static_cast<int64_t>(DporNominationNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS) +
        1;

    for (std::size_t nodeIndex = 0; nodeIndex < fixture.mValidatorCount;
         ++nodeIndex)
    {
        auto firstSend = fixture.mAdapter.captureNextEvent(nodeIndex, {}, 0);
        REQUIRE(firstSend.has_value());

        DporNominationDporAdapter::ThreadTrace trace{
            DporNominationDporAdapter::ObservedValue::bottom()};

        auto nextEvent = fixture.mAdapter.captureNextEvent(nodeIndex, trace, 3);
        REQUIRE(nextEvent.has_value());

        if (nodeIndex < fixture.mThreshold)
        {
            auto const* choice =
                std::get_if<dpor::model::NondeterministicChoiceLabelT<
                    DporNominationValue>>(&*nextEvent);
            REQUIRE(choice != nullptr);
            REQUIRE(choice->choices.size() == 2);
            REQUIRE(choice->choices.at(0).mKind ==
                    DporNominationValue::Kind::TxSetDownloadWaitTimeChoice);
            REQUIRE(choice->choices.at(1).mKind ==
                    DporNominationValue::Kind::TxSetDownloadWaitTimeChoice);
            REQUIRE(choice->choices.at(0).mTxSetDownloadWaitTimeMilliseconds ==
                    belowThresholdWait);
            REQUIRE(choice->choices.at(1).mTxSetDownloadWaitTimeMilliseconds ==
                    aboveThresholdWait);

            auto belowTrace = trace;
            belowTrace.emplace_back(choice->choices.at(0));
            auto belowSend =
                fixture.mAdapter.captureNextEvent(nodeIndex, belowTrace, 4);
            REQUIRE(belowSend.has_value());
            requirePrepareEnvelope(requireSend(*belowSend).value.mEnvelope,
                                   fixture.mNodeIDs.at(nodeIndex),
                                   fixture.mQSetHashes.at(nodeIndex),
                                   kSlotIndex,
                                   SCPBallot(2, fixture.mThresholdXValue));

            auto aboveTrace = trace;
            aboveTrace.emplace_back(choice->choices.at(1));
            auto aboveSend =
                fixture.mAdapter.captureNextEvent(nodeIndex, aboveTrace, 4);
            REQUIRE(aboveSend.has_value());
            requirePrepareEnvelope(
                requireSend(*aboveSend).value.mEnvelope,
                fixture.mNodeIDs.at(nodeIndex),
                fixture.mQSetHashes.at(nodeIndex), kSlotIndex,
                SCPBallot(2, makeSkipValue(fixture.mThresholdXValue)));
        }
        else
        {
            requirePrepareEnvelope(requireSend(*nextEvent).value.mEnvelope,
                                   fixture.mNodeIDs.at(nodeIndex),
                                   fixture.mQSetHashes.at(nodeIndex),
                                   kSlotIndex,
                                   SCPBallot(2, fixture.mThresholdYValue));
        }
    }
}

TEST_CASE("dpor nomination invariant checks surface receive-time violations "
          "before later local sends",
          "[scp][dpor][investigation][invariant]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    dpor_nomination_investigation::ThresholdFixture fixture(
        kSmallTopologyValidatorCount, false,
        dpor_nomination_investigation::TimerSetLimitSettings{},
        dpor_nomination_investigation::InitialValuePattern::ThresholdSplitXY,
        DporNominationDporAdapter::InitialStateMode::Balloting);

    fixture.mAdapter.setInvariantCheck(
        [](DporNominationNode const&,
           DporNominationNode::InvariantCheckContext const& context)
            -> std::optional<std::string> {
            if (context.mEvent ==
                DporNominationNode::InvariantCheckEvent::EnvelopeReceive)
            {
                return "reject receive replay";
            }
            return std::nullopt;
        });

    auto leaderSendToFollower = fixture.mAdapter.captureNextEvent(0, {}, 0);
    REQUIRE(leaderSendToFollower.has_value());
    auto const& send = requireSend(*leaderSendToFollower);
    REQUIRE(send.destination == DporNominationDporAdapter::toThreadID(1));

    auto followerReceive = fixture.mAdapter.captureNextEvent(1, {}, 2);
    REQUIRE(followerReceive.has_value());
    static_cast<void>(requireReceive(*followerReceive));

    DporNominationDporAdapter::ThreadTrace trace{send.value};
    auto error = fixture.mAdapter.captureNextEvent(1, trace, 3);
    REQUIRE(error.has_value());
    static_cast<void>(requireError(*error));
}

TEST_CASE("dpor nomination built-in SCP invariants reject malformed received "
          "ballot statements",
          "[scp][dpor][investigation][invariant]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    dpor_nomination_investigation::ThresholdFixture fixture(
        kSmallTopologyValidatorCount, false,
        dpor_nomination_investigation::TimerSetLimitSettings{},
        dpor_nomination_investigation::InitialValuePattern::ThresholdSplitXY,
        DporNominationDporAdapter::InitialStateMode::Balloting);
    fixture.mAdapter.enableBuiltInSCPInvariantChecks();

    auto leaderSendToFollower = fixture.mAdapter.captureNextEvent(0, {}, 0);
    REQUIRE(leaderSendToFollower.has_value());
    auto malformedDelivery = requireSend(*leaderSendToFollower).value;
    auto& prepare = malformedDelivery.mEnvelope.statement.pledges.prepare();
    prepare.nC = 1;
    prepare.nH = 0;

    auto followerReceive = fixture.mAdapter.captureNextEvent(1, {}, 2);
    REQUIRE(followerReceive.has_value());
    static_cast<void>(requireReceive(*followerReceive));

    DporNominationDporAdapter::ThreadTrace trace{malformedDelivery};
    auto error = fixture.mAdapter.captureNextEvent(1, trace, 3);
    REQUIRE(error.has_value());
    static_cast<void>(requireError(*error));
}

TEST_CASE("dpor nomination built-in SCP invariants catch nomination still "
          "running after externalize",
          "[scp][dpor][investigation][invariant]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto validators = DporNominationSanityCheckHarness::makeValidatorSecretKeys(
        "dpor-builtin-scp-invariants-", 1);
    auto nodeIDs = DporNominationSanityCheckHarness::getNodeIDs(validators);
    auto const qSet =
        DporNominationSanityCheckHarness::makeQuorumSet(nodeIDs, 1);
    auto const qSetHash = getNormalizedQSetHash(qSet);
    auto const previousValue = makeValue("builtin-prev");
    auto const xValue = makeValue("builtin-x");

    DporNominationNode node(validators.front(), qSet);
    REQUIRE(node.nominate(kSlotIndex, xValue, previousValue));

    node.setStateFromEnvelope(
        kSlotIndex, makeTestExternalizeEnvelope(node.getNodeID(), qSetHash,
                                                kSlotIndex,
                                                SCPBallot(1, xValue), 1));

    auto const violation =
        DporNominationDporAdapter::checkBuiltInSCPInvariantViolation(
            node, DporNominationNode::InvariantCheckContext{
                      .mEvent =
                          DporNominationNode::InvariantCheckEvent::
                              InitialNomination,
                      .mSlotIndex = kSlotIndex,
                  });
    REQUIRE(violation.has_value());
    REQUIRE(violation->find("nomination remained started after externalize") !=
            std::string::npos);
}

TEST_CASE("dpor nomination built-in SCP invariants accept the baseline small "
          "topology exploration",
          "[scp][dpor][investigation][invariant]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    SmallTopologyVerifyFixture fixture;
    fixture.mAdapter.enableBuiltInSCPInvariantChecks();

    auto const result = exploreExecutions(fixture);
    REQUIRE(result.mVerifyResult.kind != VerifyResultKind::ErrorFound);
}

TEST_CASE("dpor nomination investigation falsy-1 detects skip prepare after "
          "non-skip in the same ballot counter",
          "[scp][dpor][investigation]")
{
    SmallTopologyVerifyFixture fixture;
    dpor::model::ExplorationGraphT<DporNominationValue> graph;

    auto const destination = DporNominationDporAdapter::toThreadID(1);
    auto const thread0 = DporNominationDporAdapter::toThreadID(0);

    static_cast<void>(graph.add_event(
        thread0,
        DporNominationDporAdapter::EventLabel{
            DporNominationDporAdapter::SendLabel{
                .destination = destination,
                .value = DporNominationValue{
                    .mSenderThread = thread0,
                    .mDestinationThread = destination,
                    .mSlotIndex = kSlotIndex,
                    .mEnvelope = makeTestPrepareEnvelope(
                        fixture.mNodeIDs.at(0), fixture.mQSetHashes.at(0),
                        kSlotIndex, SCPBallot(1, fixture.mXValue)),
                },
            }}));
    static_cast<void>(graph.add_event(
        thread0,
        DporNominationDporAdapter::EventLabel{
            DporNominationDporAdapter::SendLabel{
                .destination = destination,
                .value = DporNominationValue{
                    .mSenderThread = thread0,
                    .mDestinationThread = destination,
                    .mSlotIndex = kSlotIndex,
                    .mEnvelope = makeTestPrepareEnvelope(
                        fixture.mNodeIDs.at(0), fixture.mQSetHashes.at(0),
                        kSlotIndex,
                        SCPBallot(1, makeSkipValue(fixture.mXValue))),
                },
            }}));

    auto const falsy1 =
        dpor_nomination_investigation::
            findFalsy1SkipPrepareAfterNonSkipSameBallot(
                graph, kSmallTopologyValidatorCount);
    REQUIRE(falsy1.has_value());
    REQUIRE(falsy1->find("falsy-1: thread 0") != std::string::npos);
    REQUIRE(falsy1->find("counter=1") != std::string::npos);
}

TEST_CASE("dpor nomination investigation falsy-1 detects non-skip prepare "
          "with same-counter prepared skip",
          "[scp][dpor][investigation]")
{
    SmallTopologyVerifyFixture fixture;
    dpor::model::ExplorationGraphT<DporNominationValue> graph;

    auto const destination = DporNominationDporAdapter::toThreadID(1);
    auto const thread0 = DporNominationDporAdapter::toThreadID(0);

    static_cast<void>(graph.add_event(
        thread0,
        DporNominationDporAdapter::EventLabel{
            DporNominationDporAdapter::SendLabel{
                .destination = destination,
                .value = DporNominationValue{
                    .mSenderThread = thread0,
                    .mDestinationThread = destination,
                    .mSlotIndex = kSlotIndex,
                    .mEnvelope = makeTestPrepareEnvelope(
                        fixture.mNodeIDs.at(0), fixture.mQSetHashes.at(0),
                        kSlotIndex, SCPBallot(2, fixture.mYValue),
                        SCPBallot(2, makeSkipValue(fixture.mXValue))),
                },
            }}));

    auto const falsy1 =
        dpor_nomination_investigation::
            findFalsy1SkipPrepareAfterNonSkipSameBallot(
                graph, kSmallTopologyValidatorCount);
    REQUIRE(falsy1.has_value());
    REQUIRE(falsy1->find("falsy-1: thread 0") != std::string::npos);
    REQUIRE(falsy1->find("prepared=") != std::string::npos);
    REQUIRE(falsy1->find("counter=2") != std::string::npos);
}

TEST_CASE("dpor nomination investigation threshold-split balloting triggers "
          "falsy-1",
          "[scp][dpor][investigation]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    auto const results =
        dpor_nomination_investigation::runRuntimeGrowthInvestigation(
            1, std::size_t{10},
            dpor_nomination_investigation::InvestigationScenario::Id::
                ThresholdSplitBalloting,
            false, kSmallTopologyValidatorCount,
            dpor_nomination_investigation::TimeoutSettings{
                .mBalloting = true},
            dpor_nomination_investigation::TimerSetLimitSettings{}, false,
            false, false, false, false,
            dpor::model::CommunicationModel::Async, true);

    REQUIRE(results.size() == 1);
    REQUIRE(results.front().mVerifyResult.kind ==
            VerifyResultKind::ErrorFound);
    REQUIRE(results.front().mVerifyResult.executions_explored > 0);
    REQUIRE(results.front().mVerifyResult.message.find("falsy-1: thread ") !=
            std::string::npos);
    REQUIRE(results.front().mVerifyResult.message.find("prepared=") !=
            std::string::npos);
}

TEST_CASE("dpor nomination investigation can detect divergent externalize "
          "values from the terminal graph", "[scp][dpor][investigation]")
{
    SmallTopologyVerifyFixture fixture;
    dpor::model::ExplorationGraphT<DporNominationValue> graph;

    auto const destination = DporNominationDporAdapter::toThreadID(2);
    auto const thread0 = DporNominationDporAdapter::toThreadID(0);
    auto const thread1 = DporNominationDporAdapter::toThreadID(1);

    static_cast<void>(graph.add_event(
        thread0,
        DporNominationDporAdapter::EventLabel{
            DporNominationDporAdapter::SendLabel{
                .destination = destination,
                .value = DporNominationValue{
                    .mSenderThread = thread0,
                    .mDestinationThread = destination,
                    .mSlotIndex = kSlotIndex,
                    .mEnvelope = makeTestExternalizeEnvelope(
                        fixture.mNodeIDs.at(0), fixture.mQSetHashes.at(0),
                        kSlotIndex, SCPBallot(1, fixture.mXValue), 1),
                },
            }}));
    static_cast<void>(graph.add_event(
        thread1,
        DporNominationDporAdapter::EventLabel{
            DporNominationDporAdapter::SendLabel{
                .destination = destination,
                .value = DporNominationValue{
                    .mSenderThread = thread1,
                    .mDestinationThread = destination,
                    .mSlotIndex = kSlotIndex,
                    .mEnvelope = makeTestExternalizeEnvelope(
                        fixture.mNodeIDs.at(1), fixture.mQSetHashes.at(1),
                        kSlotIndex, SCPBallot(1, fixture.mYValue), 1),
                },
            }}));

    auto const divergence =
        dpor_nomination_investigation::findExternalizeDivergence(
            graph, kSmallTopologyValidatorCount);
    REQUIRE(divergence.has_value());
    REQUIRE(divergence->find("externalize divergence: thread 0") !=
            std::string::npos);
    REQUIRE(divergence->find("thread 1") != std::string::npos);
}

TEST_CASE("dpor nomination investigation can detect an externalize send from "
          "the terminal graph", "[scp][dpor][investigation]")
{
    SmallTopologyVerifyFixture fixture;
    dpor::model::ExplorationGraphT<DporNominationValue> graph;

    auto const destination = DporNominationDporAdapter::toThreadID(2);
    auto const thread0 = DporNominationDporAdapter::toThreadID(0);

    static_cast<void>(graph.add_event(
        thread0,
        DporNominationDporAdapter::EventLabel{
            DporNominationDporAdapter::SendLabel{
                .destination = destination,
                .value = DporNominationValue{
                    .mSenderThread = thread0,
                    .mDestinationThread = destination,
                    .mSlotIndex = kSlotIndex,
                    .mEnvelope = makeTestExternalizeEnvelope(
                        fixture.mNodeIDs.at(0), fixture.mQSetHashes.at(0),
                        kSlotIndex, SCPBallot(1, fixture.mXValue), 1),
                },
            }}));

    auto const externalize = dpor_nomination_investigation::findExternalize(
        graph, kSmallTopologyValidatorCount);
    REQUIRE(externalize.has_value());
    REQUIRE(externalize->find("externalize: thread 0") != std::string::npos);
}

TEST_CASE("dpor nomination verify explores delivery-versus-timeout races",
          "[scp][dpor][nomination]")
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);
    SmallTopologyVerifyFixture fixture;
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
    SmallTopologyVerifyFixture fixture;
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
    SmallTopologyVerifyFixture fixture(3);
    auto const exploration =
        exploreExecutions(fixture, false, kRound3NominationVerifyMaxDepth);

    REQUIRE(exploration.mVerifyResult.kind ==
            VerifyResultKind::AllExecutionsExplored);
    requireTimeoutBoundaryExploration(exploration,
                                      fixture.mNominationRoundBoundary);
}

}
