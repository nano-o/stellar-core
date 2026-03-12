// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SHA.h"
#include "scp/QuorumSetUtils.h"
#include "scp/test/DporNominationDporAdapter.h"
#include "scp/test/DporNominationSanityCheckHarness.h"
#include "util/Logging.h"
#include "xdrpp/marshal.h"

#include <dpor/algo/dpor.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace stellar
{

namespace dpor_nomination_investigation
{

constexpr uint64_t kSlotIndex = 0;
constexpr uint64_t kTopLeaderPriority = std::numeric_limits<uint64_t>::max();
constexpr std::size_t kDefaultValidatorCount = 4;
constexpr std::size_t kLeaderIndex = 0;
constexpr std::size_t kUnlimitedProgressStep =
    std::numeric_limits<std::size_t>::max();
constexpr std::size_t kFollowerStopAfterInitialEchoStep = 4;
constexpr std::size_t kFollowerStopAfterAcceptedEchoStep = 8;
constexpr std::size_t kFollowerStopAfterSecondPeerReceiveStep = 12;
constexpr std::size_t kMaxDepth = 128;
using ProgressSteps = std::vector<std::size_t>;

class ScopedPartitionLogLevel
{
  public:
    ScopedPartitionLogLevel(char const* partition, LogLevel level)
        : mPartition(Logging::normalizePartition(partition))
        , mPreviousLevel(Logging::getLogLevel(mPartition))
    {
        Logging::setLogLevel(level, mPartition.c_str());
    }

    ScopedPartitionLogLevel(ScopedPartitionLogLevel const&) = delete;
    ScopedPartitionLogLevel&
    operator=(ScopedPartitionLogLevel const&) = delete;

    ~ScopedPartitionLogLevel()
    {
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

inline std::size_t
computeTwoThirdsThreshold(std::size_t validatorCount)
{
    if (validatorCount == 0)
    {
        throw std::invalid_argument("validatorCount must be positive");
    }
    return (2 * validatorCount + 2) / 3;
}

inline DporNominationNode::Configuration
makeTopLeaderConfiguration(std::vector<NodeID> const& nodeIDs,
                           std::size_t leaderIndex,
                           uint32_t nominationRoundBoundary =
                               DporNominationNode::
                                   DEFAULT_NOMINATION_ROUND_BOUNDARY)
{
    DporNominationNode::Configuration config;
    auto sharedNodeIDs = std::make_shared<std::vector<NodeID> const>(nodeIDs);
    config.mPriorityLookup = [sharedNodeIDs, leaderIndex](NodeID const& nodeID) {
        return nodeID == sharedNodeIDs->at(leaderIndex) ? kTopLeaderPriority
                                                        : 1;
    };
    config.mNominationRoundBoundary = nominationRoundBoundary;
    return config;
}

struct ThresholdFixture
{
    std::size_t mValidatorCount;
    std::size_t mThreshold;
    std::vector<SecretKey> mValidators;
    std::vector<NodeID> mNodeIDs;
    SCPQuorumSet mQSet;
    std::vector<Hash> mQSetHashes;
    Value mPreviousValue;
    std::vector<Value> mInitialValues;
    uint32_t mNominationRoundBoundary;
    DporNominationDporAdapter mAdapter;

    explicit ThresholdFixture(
        std::size_t validatorCount = kDefaultValidatorCount,
        bool fixedTopLeader = true,
        uint32_t nominationRoundBoundary =
            DporNominationNode::DEFAULT_NOMINATION_ROUND_BOUNDARY)
        : mValidatorCount(validatorCount)
        , mThreshold(computeTwoThirdsThreshold(validatorCount))
        , mValidators(DporNominationSanityCheckHarness::makeValidatorSecretKeys(
              "dpor-nomination-verify-" + std::to_string(validatorCount) +
                  "node-",
              validatorCount))
        , mNodeIDs(DporNominationSanityCheckHarness::getNodeIDs(mValidators))
        , mQSet(DporNominationSanityCheckHarness::makeQuorumSet(mNodeIDs,
                                                                mThreshold))
        , mQSetHashes([&]() {
            std::vector<Hash> hashes;
            hashes.reserve(mValidators.size());

            SCPQuorumSet normalizedQSet = mQSet;
            normalizeQSet(normalizedQSet);
            auto const qSetHash = sha256(xdr::xdr_to_opaque(normalizedQSet));

            for (std::size_t i = 0; i < mValidators.size(); ++i)
            {
                hashes.push_back(qSetHash);
            }
            return hashes;
        }())
        , mPreviousValue(makeValue("previous-verify-" +
                                   std::to_string(validatorCount) + "node"))
        , mInitialValues([&]() {
            std::vector<Value> values;
            values.reserve(validatorCount);
            for (std::size_t i = 0; i < validatorCount; ++i)
            {
                values.push_back(
                    makeValue("v" + std::to_string(i + 1) + "-verify"));
            }
            return values;
        }())
        , mNominationRoundBoundary(nominationRoundBoundary)
        , mAdapter(mValidators, mQSet, kSlotIndex, mPreviousValue,
                   mInitialValues, [&]() {
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
        if (mValidatorCount < 2)
        {
            throw std::invalid_argument(
                "investigation benchmark requires at least 2 validators");
        }
    }
};

inline DporNominationDporAdapter::Program
makeBoundedProgram(ThresholdFixture const& fixture,
                   ProgressSteps const& stopSteps, bool allowTimeouts = false)
{
    if (stopSteps.size() != fixture.mValidatorCount)
    {
        throw std::invalid_argument(
            "stopSteps must match the validator count");
    }

    auto program = fixture.mAdapter.makeProgram();
    program.threads.for_each_assigned(
        [&](auto tid, auto const& threadFn) {
            auto const nodeIndex = static_cast<std::size_t>(tid);
            program.threads[tid] =
                [threadFn, stopSteps, nodeIndex, allowTimeouts](
                    auto const& trace,
                    std::size_t step) -> std::optional<
                        DporNominationDporAdapter::EventLabel> {
                if (step >= stopSteps.at(nodeIndex))
                {
                    return std::nullopt;
                }

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

                if (allowTimeouts)
                {
                    return next;
                }

                return DporNominationDporAdapter::EventLabel{
                    dpor::model::make_receive_label<DporNominationValue>(
                        receive->matches)};
            };
        });
    return program;
}

struct InvestigationScenario
{
    enum class Id
    {
        TwoFollowersAccepted,
        AllFollowersAcceptedOnce,
        Largest,
        UnrestrictedFollowers
    };

    Id mId;
    std::string mName;
    ProgressSteps mStopSteps;
    std::size_t mMaxDepth;
    bool mIncludeInDefaultRuns{true};
};

struct ReplayMetricsSnapshot
{
    std::uint64_t mCaptureNextEventCalls{0};
    std::uint64_t mReplayedObservationCountTotal{0};
    std::uint64_t mMaxReplayedObservationCount{0};
    std::uint64_t mQueuedNominationEnvelopeCount{0};
    std::uint64_t mQueuedSendCount{0};
};

struct ReceiveBranchMetrics
{
    mutable std::mutex mMutex;
    std::uint64_t mReceiveEvents{0};
    std::uint64_t mCompatibleUnreadSendTotal{0};
    std::uint64_t mReceiveBranchTotal{0};
    std::uint64_t mMaxCompatibleUnreadSends{0};
    std::uint64_t mNonblockingReceiveEvents{0};
};

struct ReceiveBranchMetricsSnapshot
{
    std::uint64_t mReceiveEvents{0};
    std::uint64_t mCompatibleUnreadSendTotal{0};
    std::uint64_t mReceiveBranchTotal{0};
    std::uint64_t mMaxCompatibleUnreadSends{0};
    std::uint64_t mNonblockingReceiveEvents{0};
};

struct InvestigationResult
{
    InvestigationScenario mScenario;
    dpor::algo::VerifyResult mVerifyResult;
    std::chrono::milliseconds mElapsed;
    ReplayMetricsSnapshot mReplayMetrics;
    ReceiveBranchMetricsSnapshot mReceiveBranchMetrics;
};

inline char const*
verifyResultKindName(dpor::algo::VerifyResultKind kind)
{
    switch (kind)
    {
    case dpor::algo::VerifyResultKind::AllExecutionsExplored:
        return "all-explored";
    case dpor::algo::VerifyResultKind::ErrorFound:
        return "error";
    case dpor::algo::VerifyResultKind::DepthLimitReached:
        return "depth-limit";
    }
    return "unknown";
}

inline char const*
scenarioName(InvestigationScenario::Id id)
{
    switch (id)
    {
    case InvestigationScenario::Id::TwoFollowersAccepted:
        return "two-followers";
    case InvestigationScenario::Id::AllFollowersAcceptedOnce:
        return "all-followers-once";
    case InvestigationScenario::Id::Largest:
        return "largest";
    case InvestigationScenario::Id::UnrestrictedFollowers:
        return "unrestricted-followers";
    }
    return "unknown";
}

inline ReplayMetricsSnapshot
snapshotReplayMetrics(DporNominationDporAdapter::ReplayMetrics const& metrics)
{
    return ReplayMetricsSnapshot{
        .mCaptureNextEventCalls =
            metrics.mCaptureNextEventCalls.load(std::memory_order_relaxed),
        .mReplayedObservationCountTotal = metrics.mReplayedObservationCountTotal
                                              .load(std::memory_order_relaxed),
        .mMaxReplayedObservationCount = metrics.mMaxReplayedObservationCount
                                            .load(std::memory_order_relaxed),
        .mQueuedNominationEnvelopeCount =
            metrics.mQueuedNominationEnvelopeCount.load(
                std::memory_order_relaxed),
        .mQueuedSendCount =
            metrics.mQueuedSendCount.load(std::memory_order_relaxed),
    };
}

inline ReceiveBranchMetricsSnapshot
snapshotReceiveBranchMetrics(ReceiveBranchMetrics const& metrics)
{
    std::lock_guard<std::mutex> lock(metrics.mMutex);
    return ReceiveBranchMetricsSnapshot{
        .mReceiveEvents = metrics.mReceiveEvents,
        .mCompatibleUnreadSendTotal = metrics.mCompatibleUnreadSendTotal,
        .mReceiveBranchTotal = metrics.mReceiveBranchTotal,
        .mMaxCompatibleUnreadSends = metrics.mMaxCompatibleUnreadSends,
        .mNonblockingReceiveEvents = metrics.mNonblockingReceiveEvents,
    };
}

inline std::string
formatAverage(std::uint64_t numerator, std::uint64_t denominator)
{
    std::ostringstream out;
    out.setf(std::ios::fixed);
    out.precision(2);
    auto const average =
        denominator == 0 ? 0.0
                         : static_cast<double>(numerator) /
                               static_cast<double>(denominator);
    out << average;
    return out.str();
}

inline std::vector<InvestigationScenario>
runtimeGrowthScenarios(std::size_t validatorCount)
{
    auto makeFollowerStopSteps = [&](std::size_t followerStep) {
        ProgressSteps steps(validatorCount, followerStep);
        steps.at(kLeaderIndex) = kUnlimitedProgressStep;
        return steps;
    };

    return {
        {InvestigationScenario::Id::TwoFollowersAccepted,
         "two followers accepted, remaining followers vote-only witnesses",
         [&]() {
             auto steps = makeFollowerStopSteps(kFollowerStopAfterInitialEchoStep);
             auto const followersWithAcceptedEcho = std::min<std::size_t>(
                 2, validatorCount > 0 ? validatorCount - 1 : 0);
             for (std::size_t followerIndex = 1;
                  followerIndex <= followersWithAcceptedEcho; ++followerIndex)
             {
                 steps.at(followerIndex) =
                     kFollowerStopAfterAcceptedEchoStep;
             }
             return steps;
         }(),
         kMaxDepth},
        {InvestigationScenario::Id::AllFollowersAcceptedOnce,
         "all followers accepted once",
         makeFollowerStopSteps(kFollowerStopAfterAcceptedEchoStep),
         kMaxDepth},
        {InvestigationScenario::Id::Largest,
         "all followers accept and take one more peer receive",
         makeFollowerStopSteps(kFollowerStopAfterSecondPeerReceiveStep),
         kMaxDepth / 4, true},
        {InvestigationScenario::Id::UnrestrictedFollowers,
         "followers unrestricted like the leader",
         ProgressSteps(validatorCount, kUnlimitedProgressStep),
         kMaxDepth / 8, false},
    };
}

inline ProgressSteps
makeLeaderConvergenceStopSteps(std::size_t validatorCount)
{
    for (auto const& scenario : runtimeGrowthScenarios(validatorCount))
    {
        if (scenario.mId == InvestigationScenario::Id::TwoFollowersAccepted)
        {
            return scenario.mStopSteps;
        }
    }
    throw std::logic_error("leader convergence scenario is missing");
}

inline std::vector<InvestigationScenario>
selectedRuntimeGrowthScenarios(
    std::size_t validatorCount,
    std::optional<InvestigationScenario::Id> scenarioFilter)
{
    auto scenarios = runtimeGrowthScenarios(validatorCount);
    if (!scenarioFilter)
    {
        std::vector<InvestigationScenario> selected;
        for (auto const& scenario : scenarios)
        {
            if (scenario.mIncludeInDefaultRuns)
            {
                selected.push_back(scenario);
            }
        }
        return selected;
    }

    std::vector<InvestigationScenario> selected;
    for (auto const& scenario : scenarios)
    {
        if (scenario.mId == *scenarioFilter)
        {
            selected.push_back(scenario);
        }
    }
    return selected;
}

inline std::vector<InvestigationResult>
runRuntimeGrowthInvestigation(
    std::size_t workers = 8,
    std::optional<std::size_t> depthOverride = std::nullopt,
    std::optional<uint32_t> boundaryOverride = std::nullopt,
    std::optional<InvestigationScenario::Id> scenarioFilter =
        std::nullopt,
    std::size_t validatorCount = kDefaultValidatorCount,
    bool allowTimeouts = false)
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);
    ThresholdFixture fixture(
        validatorCount,
        !allowTimeouts,
        boundaryOverride.value_or(
            DporNominationNode::DEFAULT_NOMINATION_ROUND_BOUNDARY));

    dpor::algo::ParallelVerifyOptions options;
    options.max_workers = workers;

    std::vector<InvestigationResult> results;
    for (auto scenario :
         selectedRuntimeGrowthScenarios(validatorCount, scenarioFilter))
    {
        if (depthOverride)
        {
            scenario.mMaxDepth = *depthOverride == 0
                                     ? std::numeric_limits<std::size_t>::max()
                                     : *depthOverride;
        }

        auto replayMetrics =
            std::make_shared<DporNominationDporAdapter::ReplayMetrics>();
        auto receiveBranchMetrics = std::make_shared<ReceiveBranchMetrics>();
        fixture.mAdapter.setReplayMetrics(replayMetrics);

        dpor::algo::DporConfigT<DporNominationValue> config;
        config.program =
            makeBoundedProgram(fixture, scenario.mStopSteps, allowTimeouts);
        config.max_depth = scenario.mMaxDepth;
        config.on_receive_branches =
            [receiveBranchMetrics](dpor::model::ThreadId,
                                   std::size_t compatibleUnreadSends,
                                   bool isNonBlocking) {
                std::lock_guard<std::mutex> lock(receiveBranchMetrics->mMutex);
                receiveBranchMetrics->mReceiveEvents++;
                receiveBranchMetrics->mCompatibleUnreadSendTotal +=
                    compatibleUnreadSends;
                receiveBranchMetrics->mReceiveBranchTotal +=
                    compatibleUnreadSends + (isNonBlocking ? 1 : 0);
                receiveBranchMetrics->mMaxCompatibleUnreadSends =
                    std::max(receiveBranchMetrics->mMaxCompatibleUnreadSends,
                             static_cast<std::uint64_t>(compatibleUnreadSends));
                if (isNonBlocking)
                {
                    receiveBranchMetrics->mNonblockingReceiveEvents++;
                }
            };

        auto const start = std::chrono::steady_clock::now();
        auto const verifyResult = dpor::algo::verify_parallel(config, options);
        auto const elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);

        fixture.mAdapter.setReplayMetrics(nullptr);

        results.push_back(InvestigationResult{
            .mScenario = scenario,
            .mVerifyResult = verifyResult,
            .mElapsed = elapsed,
            .mReplayMetrics = snapshotReplayMetrics(*replayMetrics),
            .mReceiveBranchMetrics =
                snapshotReceiveBranchMetrics(*receiveBranchMetrics),
        });
    }
    return results;
}

inline std::vector<InvestigationResult>
runFourNodeRuntimeGrowthInvestigation(
    std::size_t workers = 8,
    std::optional<std::size_t> depthOverride = std::nullopt,
    std::optional<uint32_t> boundaryOverride = std::nullopt,
    std::optional<InvestigationScenario::Id> scenarioFilter =
        std::nullopt)
{
    return runRuntimeGrowthInvestigation(workers, depthOverride,
                                         boundaryOverride, scenarioFilter,
                                         kDefaultValidatorCount, false);
}

inline std::string
formatStopSteps(ProgressSteps const& stopSteps)
{
    std::ostringstream out;
    out << '[';
    for (std::size_t i = 0; i < stopSteps.size(); ++i)
    {
        if (i != 0)
        {
            out << ',';
        }
        out << stopSteps[i];
    }
    out << ']';
    return out.str();
}

inline void
printInvestigationResults(std::ostream& out,
                          std::vector<InvestigationResult> const& results,
                          std::size_t workers,
                          uint32_t nominationRoundBoundary,
                          std::size_t validatorCount,
                          bool allowTimeouts)
{
    auto const threshold = computeTwoThirdsThreshold(validatorCount);
    for (auto const& result : results)
    {
        out << "DPOR nomination investigation '" << result.mScenario.mName
            << "' scenario=" << scenarioName(result.mScenario.mId)
            << " num_nodes=" << validatorCount
            << " threshold=" << threshold
            << " timeouts=" << (allowTimeouts ? "on" : "off")
            << " workers=" << workers
            << " boundary=" << nominationRoundBoundary
            << " depth=";
        if (result.mScenario.mMaxDepth ==
            std::numeric_limits<std::size_t>::max())
        {
            out << "unbounded";
        }
        else
        {
            out << result.mScenario.mMaxDepth;
        }
        out
            << " stop_steps=" << formatStopSteps(result.mScenario.mStopSteps)
            << " result=" << verifyResultKindName(result.mVerifyResult.kind)
            << " executions=" << result.mVerifyResult.executions_explored
            << " elapsed_ms=" << result.mElapsed.count()
            << " capture_calls="
            << result.mReplayMetrics.mCaptureNextEventCalls
            << " avg_replayed_observations="
            << formatAverage(
                   result.mReplayMetrics.mReplayedObservationCountTotal,
                   result.mReplayMetrics.mCaptureNextEventCalls)
            << " max_replayed_observations="
            << result.mReplayMetrics.mMaxReplayedObservationCount
            << " queued_envelopes="
            << result.mReplayMetrics.mQueuedNominationEnvelopeCount
            << " queued_sends=" << result.mReplayMetrics.mQueuedSendCount
            << " avg_sends_per_envelope="
            << formatAverage(result.mReplayMetrics.mQueuedSendCount,
                             result.mReplayMetrics.mQueuedNominationEnvelopeCount)
            << " receive_events="
            << result.mReceiveBranchMetrics.mReceiveEvents
            << " avg_compatible_unread_sends="
            << formatAverage(
                   result.mReceiveBranchMetrics.mCompatibleUnreadSendTotal,
                   result.mReceiveBranchMetrics.mReceiveEvents)
            << " max_compatible_unread_sends="
            << result.mReceiveBranchMetrics.mMaxCompatibleUnreadSends
            << " total_receive_branches="
            << result.mReceiveBranchMetrics.mReceiveBranchTotal
            << '\n';
    }
}

}

}
