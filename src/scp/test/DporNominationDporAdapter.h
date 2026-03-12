// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
// This adapter depends only on the reusable node/driver layer. The optional
// DporNominationSanityCheckHarness helper is intentionally outside the replay
// dependency path.
#include "scp/test/DporNominationNode.h"

#include <dpor/algo/program.hpp>
#include <dpor/model/event.hpp>

#include <atomic>
#include <deque>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace stellar
{

struct DporNominationValue
{
    dpor::model::ThreadId mSenderThread{};
    dpor::model::ThreadId mDestinationThread{};
    uint64_t mSlotIndex{};
    SCPEnvelope mEnvelope;

    auto
    operator<=>(DporNominationValue const& other) const = default;

    bool
    operator==(DporNominationValue const& other) const = default;
};

// DPOR-facing replay adapter for nomination. Each thread query
// rebuilds fresh local SCP state from the initial inputs and the supplied
// per-thread trace, then returns the next deterministic event label. This does
// not drive a live DporNominationSanityCheckHarness instance; tests may use
// that helper to produce traces, but DPOR replay remains independent.
class DporNominationDporAdapter
{
  public:
    using EventLabel = dpor::model::EventLabelT<DporNominationValue>;
    using SendLabel = dpor::model::SendLabelT<DporNominationValue>;
    using ReceiveLabel = dpor::model::ReceiveLabelT<DporNominationValue>;
    using ObservedValue = dpor::model::ObservedValueT<DporNominationValue>;
    using ThreadTrace = dpor::algo::ThreadTraceT<DporNominationValue>;
    using Program = dpor::algo::ProgramT<DporNominationValue>;

    struct BoundaryInspection
    {
        bool mReachedBoundary{false};
        std::optional<SCPEnvelope> mBoundaryEnvelope;
    };

    struct ReplayMetrics
    {
        std::atomic<std::uint64_t> mCaptureNextEventCalls{0};
        std::atomic<std::uint64_t> mReplayedObservationCountTotal{0};
        std::atomic<std::uint64_t> mMaxReplayedObservationCount{0};
        std::atomic<std::uint64_t> mQueuedNominationEnvelopeCount{0};
        std::atomic<std::uint64_t> mQueuedSendCount{0};
    };

    DporNominationDporAdapter(std::vector<SecretKey> const& validators,
                              SCPQuorumSet const& qSet, uint64_t slotIndex,
                              Value const& previousValue,
                              std::vector<Value> const& initialValues,
                              DporNominationNode::Configuration const& config =
                                  {});

    std::size_t
    size() const;

    static dpor::model::ThreadId
    toThreadID(std::size_t nodeIndex);

    void setPriorityLookup(std::function<uint64(NodeID const&)> const& fn);

    void setValueHash(std::function<uint64(Value const&)> const& fn);

    void setCombineCandidates(
        std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const&
            fn);

    void
    setReplayMetrics(std::shared_ptr<ReplayMetrics> metrics);

    void
    setTimeoutModes(bool enableNominationTimeouts,
                    bool enableBallotingTimeouts);

    std::optional<EventLabel>
    captureNextEvent(std::size_t nodeIndex, ThreadTrace const& trace,
                     std::size_t step) const;

    Program
    makeProgram() const;

    BoundaryInspection
    inspectNominationBoundary(std::size_t nodeIndex,
                              ThreadTrace const& trace) const;

    bool
    hasReachedNominationBoundary(std::size_t nodeIndex,
                                 ThreadTrace const& trace) const;

    std::optional<SCPEnvelope>
    getNominationBoundaryEnvelope(std::size_t nodeIndex,
                                  ThreadTrace const& trace) const;

  private:
    struct ReplayState
    {
        explicit ReplayState(SecretKey const& secretKey,
                             SCPQuorumSet const& qSet,
                             DporNominationNode::Configuration const& config);

        DporNominationNode mNode;
        std::deque<SendLabel> mPendingSends;
    };

    void initializeNode(ReplayState& state, std::size_t nodeIndex) const;

    void replayObservation(DporNominationNode& node, std::size_t nodeIndex,
                           ObservedValue const& observed) const;

    void discardPendingEnvelopes(DporNominationNode& node) const;

    void queuePendingEnvelopeSends(ReplayState& state,
                                   std::size_t senderIndex) const;

    void replayTraceForBoundaryInspection(ReplayState& state,
                                          std::size_t nodeIndex,
                                          ThreadTrace const& trace) const;

    std::optional<int>
    selectEnabledTimerID(DporNominationNode const& node) const;

    void recordReplayObservationCount(std::size_t replayedObservationCount) const;

    std::vector<SecretKey> mValidators;
    SCPQuorumSet mQSet;
    uint64_t mSlotIndex;
    Value mPreviousValue;
    std::vector<Value> mInitialValues;
    DporNominationNode::Configuration mConfig;
    bool mEnableNominationTimeouts{true};
    bool mEnableBallotingTimeouts{false};
    std::shared_ptr<ReplayMetrics> mReplayMetrics;
};

}
