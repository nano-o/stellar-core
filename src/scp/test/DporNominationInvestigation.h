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
#include <atomic>
#include <chrono>
#include <cstddef>
#include <iomanip>
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

struct TimeoutSettings
{
    bool mNomination{false};
    bool mBalloting{false};
};

struct TimerSetLimitSettings
{
    std::optional<uint32_t> mNomination;
    std::optional<uint32_t> mBalloting;
};

constexpr uint32_t kDisabledNominationRoundBoundary =
    std::numeric_limits<uint32_t>::max();
constexpr uint32_t kDisabledBallotingBoundary =
    std::numeric_limits<uint32_t>::max();

class ScopedPartitionLogLevel
{
  public:
    ScopedPartitionLogLevel(char const* partition, LogLevel level)
        : mPartition(Logging::normalizePartition(partition))
        , mPreviousLevel(Logging::getLogLevel(mPartition))
    {
        Logging::setLogLevel(level, mPartition.c_str());
        // Install a null logger so hot CLOG checks short-circuit without
        // touching the real partition logger during DPOR replay.
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
                           bool nominationOnly = false)
{
    DporNominationNode::Configuration config;
    auto sharedNodeIDs = std::make_shared<std::vector<NodeID> const>(nodeIDs);
    config.mPriorityLookup = [sharedNodeIDs, leaderIndex](NodeID const& nodeID) {
        return nodeID == sharedNodeIDs->at(leaderIndex) ? kTopLeaderPriority
                                                        : 1;
    };
    config.mBoundaryMode = DporNominationNode::BoundaryMode::Prepare;
    config.mBallotingBoundary = nominationOnly
                                    ? DporNominationNode::DEFAULT_BALLOTING_BOUNDARY
                                    : kDisabledBallotingBoundary;
    config.mNominationRoundBoundary = kDisabledNominationRoundBoundary;
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
    bool mNominationOnly;
    TimerSetLimitSettings mTimerSetLimitSettings;
    DporNominationDporAdapter mAdapter;

    explicit ThresholdFixture(
        std::size_t validatorCount = kDefaultValidatorCount,
        bool fixedTopLeader = true,
        bool nominationOnly = false,
        TimerSetLimitSettings timerSetLimitSettings = {})
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
        , mNominationOnly(nominationOnly)
        , mTimerSetLimitSettings(timerSetLimitSettings)
        , mAdapter(mValidators, mQSet, kSlotIndex, mPreviousValue,
                   mInitialValues, [&]() {
                       if (fixedTopLeader)
                       {
                           auto config =
                               makeTopLeaderConfiguration(mNodeIDs,
                                                          kLeaderIndex,
                                                          nominationOnly);
                           config.mNominationTimerSetLimit =
                               timerSetLimitSettings.mNomination;
                           config.mBallotingTimerSetLimit =
                               timerSetLimitSettings.mBalloting;
                           return config;
                       }
                       DporNominationNode::Configuration config;
                       config.mNominationRoundBoundary =
                           kDisabledNominationRoundBoundary;
                       config.mBallotingBoundary = nominationOnly
                                                       ? DporNominationNode::
                                                             DEFAULT_BALLOTING_BOUNDARY
                                                       : kDisabledBallotingBoundary;
                       config.mBoundaryMode =
                           DporNominationNode::BoundaryMode::Prepare;
                       config.mNominationTimerSetLimit =
                           timerSetLimitSettings.mNomination;
                       config.mBallotingTimerSetLimit =
                           timerSetLimitSettings.mBalloting;
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
                   ProgressSteps const& stopSteps)
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
                [threadFn, stopSteps, nodeIndex](
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
                return next;
            };
        });
    return program;
}

inline std::size_t
mergeStepLimit(std::size_t lhs, std::size_t rhs)
{
    if (lhs == kUnlimitedProgressStep)
    {
        return rhs;
    }
    if (rhs == kUnlimitedProgressStep)
    {
        return lhs;
    }
    return std::min(lhs, rhs);
}

inline ProgressSteps
applyPerThreadDepthLimit(ProgressSteps stopSteps,
                         std::size_t perThreadDepthLimit)
{
    for (auto& stopStep : stopSteps)
    {
        stopStep = mergeStepLimit(stopStep, perThreadDepthLimit);
    }
    return stopSteps;
}

struct InvestigationScenario
{
    enum class Id
    {
        TwoFollowersAccepted,
        AllFollowersAcceptedOnce,
        AllFollowersSecondPeerReceive,
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

struct DeadlockCheckState
{
    std::atomic<bool> mFound{false};
    mutable std::mutex mMutex;
    std::string mMessage;
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
    case InvestigationScenario::Id::AllFollowersSecondPeerReceive:
        return "all-followers-second-peer-receive";
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

inline std::string
formatStepCounts(std::vector<std::size_t> const& stepCounts)
{
    std::ostringstream out;
    out << '[';
    for (std::size_t i = 0; i < stepCounts.size(); ++i)
    {
        if (i != 0)
        {
            out << ',';
        }
        out << stepCounts[i];
    }
    out << ']';
    return out.str();
}

template <typename GraphT>
inline bool
isErrorExecution(GraphT const& graph, std::size_t validatorCount)
{
    for (std::size_t nodeIndex = 0; nodeIndex < validatorCount; ++nodeIndex)
    {
        auto const tid = DporNominationDporAdapter::toThreadID(nodeIndex);
        auto const lastEventID = graph.last_event_id(tid);
        if (lastEventID != GraphT::kNoSource &&
            dpor::model::is_error(graph.event(lastEventID)))
        {
            return true;
        }
    }
    return false;
}

template <typename GraphT>
inline std::optional<std::string>
findTerminalDeadlock(GraphT const& graph, ProgressSteps const& stopSteps)
{
    if (isErrorExecution(graph, stopSteps.size()))
    {
        return std::nullopt;
    }

    std::vector<std::size_t> stepCounts;
    stepCounts.reserve(stopSteps.size());
    for (std::size_t nodeIndex = 0; nodeIndex < stopSteps.size(); ++nodeIndex)
    {
        auto const tid = DporNominationDporAdapter::toThreadID(nodeIndex);
        stepCounts.push_back(graph.thread_event_count(tid));
    }

    for (std::size_t nodeIndex = 0; nodeIndex < stopSteps.size(); ++nodeIndex)
    {
        auto const stopStep = stopSteps.at(nodeIndex);
        if (stopStep == kUnlimitedProgressStep)
        {
            continue;
        }
        auto const stepCount = stepCounts.at(nodeIndex);
        if (stepCount < stopStep)
        {
            std::ostringstream out;
            out << "deadlock: thread " << nodeIndex << " stopped at step "
                << stepCount << " before limit " << stopStep
                << " thread_steps=" << formatStepCounts(stepCounts);
            return out.str();
        }
    }

    return std::nullopt;
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
         kMaxDepth,
         true},
        {InvestigationScenario::Id::AllFollowersAcceptedOnce,
         "all followers accepted once",
         makeFollowerStopSteps(kFollowerStopAfterAcceptedEchoStep),
         kMaxDepth,
         true},
        {InvestigationScenario::Id::AllFollowersSecondPeerReceive,
         "all followers accept and take one more peer receive",
         makeFollowerStopSteps(kFollowerStopAfterSecondPeerReceiveStep),
         kMaxDepth / 4,
         true},
        {InvestigationScenario::Id::UnrestrictedFollowers,
         "followers unrestricted like the leader",
         ProgressSteps(validatorCount, kUnlimitedProgressStep),
         kMaxDepth / 8,
         false},
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
    std::optional<InvestigationScenario::Id> scenarioFilter =
        std::nullopt,
    bool nominationOnly = false,
    std::size_t validatorCount = kDefaultValidatorCount,
    TimeoutSettings timeoutSettings = {},
    TimerSetLimitSettings timerSetLimitSettings = {},
    bool checkDeadlock = false)
{
    ScopedPartitionLogLevel quietSCP("SCP", LogLevel::LVL_WARNING);

    dpor::algo::ParallelVerifyOptions options;
    options.max_workers = workers;

    std::vector<InvestigationResult> results;
    for (auto scenario :
         selectedRuntimeGrowthScenarios(validatorCount, scenarioFilter))
    {
        auto perThreadDepthLimit = scenario.mMaxDepth;
        if (depthOverride)
        {
            perThreadDepthLimit = *depthOverride == 0
                                      ? kUnlimitedProgressStep
                                      : *depthOverride;
        }
        scenario.mMaxDepth = perThreadDepthLimit;
        scenario.mStopSteps =
            applyPerThreadDepthLimit(scenario.mStopSteps, perThreadDepthLimit);

        ThresholdFixture fixture(
            validatorCount, !timeoutSettings.mNomination, nominationOnly,
            timerSetLimitSettings);
        fixture.mAdapter.setTimeoutModes(timeoutSettings.mNomination,
                                         timeoutSettings.mBalloting);

        auto replayMetrics =
            std::make_shared<DporNominationDporAdapter::ReplayMetrics>();
        auto receiveBranchMetrics = std::make_shared<ReceiveBranchMetrics>();
        auto deadlockCheckState = std::make_shared<DeadlockCheckState>();
        fixture.mAdapter.setReplayMetrics(replayMetrics);

        dpor::algo::DporConfigT<DporNominationValue> config;
        config.program = makeBoundedProgram(fixture, scenario.mStopSteps);
        config.max_depth = std::numeric_limits<std::size_t>::max();
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
        if (checkDeadlock)
        {
            config.on_execution =
                [deadlockCheckState, stopSteps = scenario.mStopSteps](
                    auto const& graph) {
                    if (deadlockCheckState->mFound.load(
                            std::memory_order_relaxed))
                    {
                        return;
                    }

                    auto deadlock = findTerminalDeadlock(graph, stopSteps);
                    if (!deadlock)
                    {
                        return;
                    }

                    std::lock_guard<std::mutex> lock(deadlockCheckState->mMutex);
                    if (deadlockCheckState->mFound.load(
                            std::memory_order_relaxed))
                    {
                        return;
                    }
                    deadlockCheckState->mMessage = std::move(*deadlock);
                    deadlockCheckState->mFound.store(true,
                                                     std::memory_order_relaxed);
                };
        }

        auto const start = std::chrono::steady_clock::now();
        auto verifyResult = dpor::algo::verify_parallel(config, options);
        auto const elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);

        fixture.mAdapter.setReplayMetrics(nullptr);

        if (checkDeadlock &&
            deadlockCheckState->mFound.load(std::memory_order_relaxed) &&
            verifyResult.kind != dpor::algo::VerifyResultKind::ErrorFound)
        {
            verifyResult.kind = dpor::algo::VerifyResultKind::ErrorFound;
            std::lock_guard<std::mutex> lock(deadlockCheckState->mMutex);
            verifyResult.message = deadlockCheckState->mMessage;
        }

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
    std::optional<InvestigationScenario::Id> scenarioFilter =
        std::nullopt,
    bool nominationOnly = false,
    TimeoutSettings timeoutSettings = {},
    TimerSetLimitSettings timerSetLimitSettings = {},
    bool checkDeadlock = false)
{
    return runRuntimeGrowthInvestigation(workers, depthOverride,
                                         scenarioFilter, nominationOnly,
                                         kDefaultValidatorCount,
                                         timeoutSettings,
                                         timerSetLimitSettings,
                                         checkDeadlock);
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
                          std::size_t validatorCount,
                          bool nominationOnly,
                          TimeoutSettings timeoutSettings,
                          TimerSetLimitSettings timerSetLimitSettings = {},
                          bool checkDeadlock = false)
{
    auto const threshold = computeTwoThirdsThreshold(validatorCount);
    for (auto const& result : results)
    {
        out << "DPOR nomination investigation '" << result.mScenario.mName
            << "' scenario=" << scenarioName(result.mScenario.mId)
            << " num_nodes=" << validatorCount
            << " threshold=" << threshold
            << " nomination_only="
            << (nominationOnly ? "on" : "off")
            << " nomination_timeouts="
            << (timeoutSettings.mNomination ? "on" : "off")
            << " balloting_timeouts="
            << (timeoutSettings.mBalloting ? "on" : "off")
            << " deadlock=" << (checkDeadlock ? "on" : "off")
            << " prepare_boundary="
            << (nominationOnly ? "1" : "off")
            << " nomination_timer_limit=";
        if (timerSetLimitSettings.mNomination)
        {
            out << *timerSetLimitSettings.mNomination;
        }
        else
        {
            out << "off";
        }
        out << " balloting_timer_limit=";
        if (timerSetLimitSettings.mBalloting)
        {
            out << *timerSetLimitSettings.mBalloting;
        }
        else
        {
            out << "off";
        }
        out
            << " workers=" << workers
            << " depth_per_thread=";
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
            << result.mReceiveBranchMetrics.mReceiveBranchTotal;
        if (!result.mVerifyResult.message.empty())
        {
            out << " message=" << std::quoted(result.mVerifyResult.message);
        }
        out << '\n';
    }
}

}

}
