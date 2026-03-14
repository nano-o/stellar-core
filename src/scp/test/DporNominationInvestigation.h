// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "scp/QuorumSetUtils.h"
#include "scp/test/DporNominationDporAdapter.h"
#include "scp/test/DporNominationSanityCheckHarness.h"
#include "scp/test/DporNominationTestUtils.h"
#include "util/Logging.h"
#include "xdrpp/marshal.h"

#include <dpor/algo/dpor.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <iomanip>
#include <iostream>
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

enum class InitialValuePattern : std::uint8_t
{
    UniquePerNode,
    ThresholdSplitXY
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

struct ThresholdFixture
{
    std::size_t mValidatorCount;
    std::size_t mThreshold;
    std::vector<SecretKey> mValidators;
    std::vector<NodeID> mNodeIDs;
    SCPQuorumSet mQSet;
    std::vector<Hash> mQSetHashes;
    Value mPreviousValue;
    Value mThresholdXValue;
    Value mThresholdYValue;
    std::vector<Value> mInitialValues;
    InitialValuePattern mInitialValuePattern;
    DporNominationDporAdapter::InitialStateMode mInitialStateMode;
    bool mNominationOnly;
    TimerSetLimitSettings mTimerSetLimitSettings;
    DporNominationDporAdapter mAdapter;

    explicit ThresholdFixture(
        std::size_t validatorCount = kDefaultValidatorCount,
        bool nominationOnly = false,
        TimerSetLimitSettings timerSetLimitSettings = {},
        InitialValuePattern initialValuePattern =
            InitialValuePattern::UniquePerNode,
        DporNominationDporAdapter::InitialStateMode initialStateMode =
            DporNominationDporAdapter::InitialStateMode::Nomination)
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
        , mThresholdXValue(makeValue("x-verify-" + std::to_string(validatorCount) +
                                     "node-threshold-split"))
        , mThresholdYValue(makeValue("y-verify-" + std::to_string(validatorCount) +
                                     "node-threshold-split"))
        , mInitialValues([&]() {
            std::vector<Value> values;
            values.reserve(validatorCount);
            if (initialValuePattern == InitialValuePattern::ThresholdSplitXY)
            {
                for (std::size_t i = 0; i < validatorCount; ++i)
                {
                    values.push_back(i < mThreshold ? mThresholdXValue
                                                    : mThresholdYValue);
                }
                return values;
            }

            for (std::size_t i = 0; i < validatorCount; ++i)
            {
                values.push_back(
                    makeValue("v" + std::to_string(i + 1) + "-verify"));
            }
            return values;
        }())
        , mInitialValuePattern(initialValuePattern)
        , mInitialStateMode(initialStateMode)
        , mNominationOnly(nominationOnly)
        , mTimerSetLimitSettings(timerSetLimitSettings)
        , mAdapter(mValidators, mQSet, kSlotIndex, mPreviousValue,
                   mInitialValues, [&]() {
                       DporNominationNode::Configuration config;
                       config.mNodeIndexMap =
                           dpor_nomination_test::makeNodeIndexMap(mNodeIDs);
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
                   }(),
                   initialStateMode)
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
        UnrestrictedFollowers,
        ThresholdSplitBalloting
    };

    Id mId;
    std::string mName;
    ProgressSteps mStopSteps;
    std::size_t mMaxDepth;
    bool mIncludeInDefaultRuns{true};
    DporNominationDporAdapter::InitialStateMode mInitialStateMode{
        DporNominationDporAdapter::InitialStateMode::Nomination};
    InitialValuePattern mInitialValuePattern{
        InitialValuePattern::UniquePerNode};
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

struct TerminalCheckState
{
    std::atomic<std::size_t> mTerminalExecutions{0};
    std::atomic<bool> mFound{false};
    mutable std::mutex mMutex;
    std::string mMessage;
};

class TerminalCheckError : public std::runtime_error
{
  public:
    explicit TerminalCheckError(std::string const& message)
        : std::runtime_error(message)
    {
    }
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
    case InvestigationScenario::Id::ThresholdSplitBalloting:
        return "threshold-split-balloting";
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

inline std::string
formatValueAbbrev(Value const& value)
{
    return hexAbbrev(ByteSlice(value.data(), value.size()));
}

inline bool
isDporSkipValue(Value const& value)
{
    return value.size() >= 5 && value[0] == 'S' && value[1] == 'K' &&
           value[2] == 'I' && value[3] == 'P' && value[4] == ':';
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
        auto const stepCount = stepCounts.at(nodeIndex);
        if (stopStep != kUnlimitedProgressStep && stepCount >= stopStep)
        {
            continue;
        }

        std::ostringstream out;
        out << "deadlock: thread " << nodeIndex << " stopped at step "
            << stepCount;
        if (stopStep == kUnlimitedProgressStep)
        {
            out << " without reaching an unbounded step limit";
        }
        else
        {
            out << " before limit " << stopStep;
        }
        out << " thread_steps=" << formatStepCounts(stepCounts);
        return out.str();
    }

    return std::nullopt;
}

template <typename GraphT>
inline std::optional<std::string>
findTerminationWithoutExternalize(GraphT const& graph,
                                  ProgressSteps const& stopSteps)
{
    if (isErrorExecution(graph, stopSteps.size()))
    {
        return std::nullopt;
    }

    for (std::size_t eventID = 0; eventID < graph.event_count(); ++eventID)
    {
        auto const* send = dpor::model::as_send(graph.event(eventID));
        if (send == nullptr)
        {
            continue;
        }

        auto const& envelope = send->value.mEnvelope;
        if (envelope.statement.pledges.type() == SCP_ST_EXTERNALIZE)
        {
            return std::nullopt;
        }
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
        if (stopStep != kUnlimitedProgressStep &&
            stepCounts.at(nodeIndex) >= stopStep)
        {
            return std::nullopt;
        }
    }

    std::ostringstream out;
    out << "termination: reached terminal execution without externalize"
        << " thread_steps=" << formatStepCounts(stepCounts);
    return out.str();
}

template <typename GraphT>
inline std::optional<std::string>
findExternalizeDivergence(GraphT const& graph, std::size_t validatorCount)
{
    if (isErrorExecution(graph, validatorCount))
    {
        return std::nullopt;
    }

    std::map<dpor::model::ThreadId, Value> externalizedByThread;
    for (std::size_t eventID = 0; eventID < graph.event_count(); ++eventID)
    {
        auto const* send = dpor::model::as_send(graph.event(eventID));
        if (send == nullptr)
        {
            continue;
        }

        auto const& envelope = send->value.mEnvelope;
        if (envelope.statement.pledges.type() != SCP_ST_EXTERNALIZE)
        {
            continue;
        }

        auto const thread = graph.event(eventID).thread;
        auto const& value = envelope.statement.pledges.externalize().commit.value;
        auto [it, inserted] = externalizedByThread.try_emplace(thread, value);
        if (!inserted && it->second != value)
        {
            std::ostringstream out;
            out << "externalize divergence: thread " << thread
                << " externalized both " << formatValueAbbrev(it->second)
                << " and " << formatValueAbbrev(value);
            return out.str();
        }
    }

    if (externalizedByThread.size() < 2)
    {
        return std::nullopt;
    }

    auto const first = externalizedByThread.begin();
    for (auto it = std::next(first); it != externalizedByThread.end(); ++it)
    {
        if (it->second == first->second)
        {
            continue;
        }

        std::ostringstream out;
        out << "externalize divergence: thread " << first->first
            << " externalized " << formatValueAbbrev(first->second)
            << " while thread " << it->first << " externalized "
            << formatValueAbbrev(it->second);
        return out.str();
    }

    return std::nullopt;
}

template <typename GraphT>
inline std::optional<std::string>
findExternalize(GraphT const& graph, std::size_t validatorCount)
{
    if (isErrorExecution(graph, validatorCount))
    {
        return std::nullopt;
    }

    for (std::size_t eventID = 0; eventID < graph.event_count(); ++eventID)
    {
        auto const* send = dpor::model::as_send(graph.event(eventID));
        if (send == nullptr)
        {
            continue;
        }

        auto const& envelope = send->value.mEnvelope;
        if (envelope.statement.pledges.type() != SCP_ST_EXTERNALIZE)
        {
            continue;
        }

        std::ostringstream out;
        out << "externalize: thread " << graph.event(eventID).thread
            << " externalized "
            << formatValueAbbrev(
                   envelope.statement.pledges.externalize().commit.value);
        return out.str();
    }

    return std::nullopt;
}

template <typename GraphT>
inline std::optional<std::string>
findSkipExternalize(GraphT const& graph, std::size_t validatorCount)
{
    if (isErrorExecution(graph, validatorCount))
    {
        return std::nullopt;
    }

    for (std::size_t eventID = 0; eventID < graph.event_count(); ++eventID)
    {
        auto const* send = dpor::model::as_send(graph.event(eventID));
        if (send == nullptr)
        {
            continue;
        }

        auto const& envelope = send->value.mEnvelope;
        if (envelope.statement.pledges.type() != SCP_ST_EXTERNALIZE)
        {
            continue;
        }

        auto const& value = envelope.statement.pledges.externalize().commit.value;
        if (!isDporSkipValue(value))
        {
            continue;
        }

        std::ostringstream out;
        out << "skip externalize: thread " << graph.event(eventID).thread
            << " externalized " << formatValueAbbrev(value);
        return out.str();
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
         false,
         DporNominationDporAdapter::InitialStateMode::Nomination,
         InitialValuePattern::UniquePerNode},
        {InvestigationScenario::Id::ThresholdSplitBalloting,
         "start directly in balloting with threshold nodes on x and the "
         "rest on y",
         ProgressSteps(validatorCount, kUnlimitedProgressStep),
         kMaxDepth / 8,
         false,
         DporNominationDporAdapter::InitialStateMode::Balloting,
         InitialValuePattern::ThresholdSplitXY},
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
    bool checkDeadlock = false,
    bool checkTermination = false,
    bool checkExternalize = false,
    bool checkExternalizeDivergence = false,
    bool printSkipExternalize = false)
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
            validatorCount, nominationOnly,
            timerSetLimitSettings, scenario.mInitialValuePattern,
            scenario.mInitialStateMode);
        fixture.mAdapter.setTimeoutModes(timeoutSettings.mNomination,
                                         timeoutSettings.mBalloting);

        auto replayMetrics =
            std::make_shared<DporNominationDporAdapter::ReplayMetrics>();
        auto receiveBranchMetrics = std::make_shared<ReceiveBranchMetrics>();
        auto terminalCheckState = std::make_shared<TerminalCheckState>();
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
        if (checkDeadlock || checkTermination || checkExternalize ||
            checkExternalizeDivergence ||
            printSkipExternalize)
        {
            auto const hasTerminalChecks =
                checkDeadlock || checkTermination || checkExternalize ||
                checkExternalizeDivergence;
            if (hasTerminalChecks)
            {
                config.on_terminal_execution = [terminalCheckState]() {
                    terminalCheckState->mTerminalExecutions.fetch_add(
                        1, std::memory_order_relaxed);
                };
            }

            auto handleTerminalChecks =
                [terminalCheckState, stopSteps = scenario.mStopSteps,
                 validatorCount, checkDeadlock, checkTermination,
                 checkExternalize, checkExternalizeDivergence](auto const& graph) {
                    if (terminalCheckState->mFound.load(
                            std::memory_order_relaxed))
                    {
                        return;
                    }

                    std::optional<std::string> error;
                    if (checkTermination)
                    {
                        error =
                            findTerminationWithoutExternalize(graph, stopSteps);
                    }
                    if (!error && checkExternalize)
                    {
                        error = findExternalize(graph, validatorCount);
                    }
                    if (!error && checkExternalizeDivergence)
                    {
                        error = findExternalizeDivergence(graph, validatorCount);
                    }
                    if (!error && checkDeadlock)
                    {
                        error = findTerminalDeadlock(graph, stopSteps);
                    }
                    if (!error)
                    {
                        return;
                    }

                    std::lock_guard<std::mutex> lock(terminalCheckState->mMutex);
                    if (terminalCheckState->mFound.load(
                            std::memory_order_relaxed))
                    {
                        return;
                    }
                    terminalCheckState->mMessage = std::move(*error);
                    terminalCheckState->mFound.store(true,
                                                     std::memory_order_relaxed);
                    throw TerminalCheckError(terminalCheckState->mMessage);
                };

            if (printSkipExternalize)
            {
                auto executionPrintMutex = std::make_shared<std::mutex>();
                if (hasTerminalChecks)
                {
                    config.on_execution =
                        [executionPrintMutex, scenarioID = scenario.mId,
                         validatorCount, handleTerminalChecks](
                            auto const& graph) {
                            auto skipExternalizeMessage =
                                findSkipExternalize(graph, validatorCount);
                            if (skipExternalizeMessage)
                            {
                                std::lock_guard<std::mutex> lock(
                                    *executionPrintMutex);
                                std::cerr << "["
                                          << scenarioName(scenarioID) << "] "
                                          << *skipExternalizeMessage << '\n';
                            }
                            handleTerminalChecks(graph);
                        };
                }
                else
                {
                    config.on_execution =
                        [executionPrintMutex, scenarioID = scenario.mId,
                         validatorCount](auto const& graph) {
                            auto skipExternalizeMessage =
                                findSkipExternalize(graph, validatorCount);
                            if (!skipExternalizeMessage)
                            {
                                return;
                            }
                            std::lock_guard<std::mutex> lock(
                                *executionPrintMutex);
                            std::cerr << "[" << scenarioName(scenarioID)
                                      << "] " << *skipExternalizeMessage
                                      << '\n';
                        };
                }
            }
            else if (hasTerminalChecks)
            {
                config.on_execution =
                    [handleTerminalChecks](auto const& graph) {
                        handleTerminalChecks(graph);
                    };
            }
        }

        auto const start = std::chrono::steady_clock::now();
        dpor::algo::VerifyResult verifyResult;
        try
        {
            verifyResult = dpor::algo::verify_parallel(config, options);
        }
        catch (TerminalCheckError const& e)
        {
            verifyResult.kind = dpor::algo::VerifyResultKind::ErrorFound;
            verifyResult.message = e.what();
            verifyResult.executions_explored =
                terminalCheckState->mTerminalExecutions.load(
                    std::memory_order_relaxed);
        }
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
    std::optional<InvestigationScenario::Id> scenarioFilter =
        std::nullopt,
    bool nominationOnly = false,
    TimeoutSettings timeoutSettings = {},
    TimerSetLimitSettings timerSetLimitSettings = {},
    bool checkDeadlock = false,
    bool checkTermination = false,
    bool checkExternalize = false,
    bool checkExternalizeDivergence = false,
    bool printSkipExternalize = false)
{
    return runRuntimeGrowthInvestigation(workers, depthOverride,
                                         scenarioFilter, nominationOnly,
                                         kDefaultValidatorCount,
                                         timeoutSettings,
                                         timerSetLimitSettings,
                                         checkDeadlock,
                                         checkTermination,
                                         checkExternalize,
                                         checkExternalizeDivergence,
                                         printSkipExternalize);
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
                          bool checkDeadlock = false,
                          bool checkTermination = false,
                          bool checkExternalize = false,
                          bool checkExternalizeDivergence = false,
                          bool printSkipExternalize = false)
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
            << " termination=" << (checkTermination ? "on" : "off")
            << " externalize=" << (checkExternalize ? "on" : "off")
            << " externalize_divergence="
            << (checkExternalizeDivergence ? "on" : "off")
            << " print_skip_externalize="
            << (printSkipExternalize ? "on" : "off")
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
