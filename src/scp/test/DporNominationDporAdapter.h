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
#include <string>
#include <vector>

namespace stellar
{

struct DporNominationValue
{
    enum class Kind : std::uint8_t
    {
        Envelope,
        TxSetDownloadWaitTimeChoice
    };

    dpor::model::ThreadId mSenderThread{};
    dpor::model::ThreadId mDestinationThread{};
    uint64_t mSlotIndex{};
    SCPEnvelope mEnvelope;
    Kind mKind{Kind::Envelope};
    int64_t mTxSetDownloadWaitTimeMilliseconds{0};

    bool
    operator==(DporNominationValue const& other) const
    {
        if (mKind != other.mKind)
        {
            return false;
        }
        if (mKind == Kind::TxSetDownloadWaitTimeChoice)
        {
            return mTxSetDownloadWaitTimeMilliseconds ==
                   other.mTxSetDownloadWaitTimeMilliseconds;
        }
        return mSenderThread == other.mSenderThread &&
               mDestinationThread == other.mDestinationThread &&
               mSlotIndex == other.mSlotIndex &&
                mEnvelope == other.mEnvelope;
    }

    bool
    operator<(DporNominationValue const& other) const
    {
        if (mKind != other.mKind)
        {
            return mKind < other.mKind;
        }
        if (mKind == Kind::TxSetDownloadWaitTimeChoice)
        {
            return mTxSetDownloadWaitTimeMilliseconds <
                   other.mTxSetDownloadWaitTimeMilliseconds;
        }
        if (mSenderThread != other.mSenderThread)
        {
            return mSenderThread < other.mSenderThread;
        }
        if (mDestinationThread != other.mDestinationThread)
        {
            return mDestinationThread < other.mDestinationThread;
        }
        if (mSlotIndex != other.mSlotIndex)
        {
            return mSlotIndex < other.mSlotIndex;
        }
        return mEnvelope < other.mEnvelope;
    }
};

// DPOR-facing replay adapter for nomination. Each thread query
// rebuilds fresh local SCP state from the initial inputs and the supplied
// per-thread trace, then returns the next deterministic event label. This does
// not drive a live DporNominationSanityCheckHarness instance; tests may use
// that helper to produce traces, but DPOR replay remains independent.
class DporNominationDporAdapter
{
  public:
    using InitialStateMode = DporNominationNode::InitialStateMode;
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
                                  {},
                              InitialStateMode initialStateMode =
                                  InitialStateMode::Nomination);

    std::size_t
    size() const;

    static dpor::model::ThreadId
    toThreadID(std::size_t nodeIndex);

    void setValueHash(std::function<uint64(Value const&)> const& fn);

    void setCombineCandidates(
        std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const&
            fn);

    void
    setInvariantCheck(DporNominationNode::InvariantCheck const& fn);

    void
    enableBuiltInSCPInvariantChecks(bool enable = true);

    static std::optional<std::string>
    checkBuiltInSCPInvariantViolation(
        DporNominationNode const& node,
        DporNominationNode::InvariantCheckContext const& context);

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
        std::optional<std::string> mPendingInvariantViolation;
    };

    struct ReplayBaseline
    {
        DporNominationNode::ReplayBaseline mNodeState;
        std::deque<SendLabel> mPendingSends;
        std::optional<std::string> mPendingInvariantViolation;
    };

    void initializeNode(ReplayState& state, std::size_t nodeIndex) const;
    void restoreNodeBaseline(
        ReplayState& state, std::size_t nodeIndex,
        DporNominationNode::ReplayBaseline const& baseline) const;
    void restoreBaseline(ReplayState& state, std::size_t nodeIndex) const;
    ReplayState& acquireReplayState(std::size_t nodeIndex) const;
    void rebuildReplayBaselines();

    void replayObservation(ReplayState& state, std::size_t nodeIndex,
                           ObservedValue const& observed) const;

    struct ReplayObservationProgress
    {
        std::size_t mConsumedTraceEntries{0};
        std::size_t mConsumedStepCount{0};
        std::optional<EventLabel> mPendingEvent;
    };

    ReplayObservationProgress
    replayObservation(ReplayState& state, std::size_t nodeIndex,
                      ThreadTrace const& trace,
                      std::size_t observedIndex) const;

    void discardPendingEnvelopes(DporNominationNode& node) const;

    void queuePendingEnvelopeSends(ReplayState& state,
                                   std::size_t senderIndex) const;

    void maybeRecordInvariantViolation(
        ReplayState& state,
        DporNominationNode::InvariantCheckContext const& context) const;

    std::optional<std::string> evaluateInvariantViolation(
        DporNominationNode const& node,
        DporNominationNode::InvariantCheckContext const& context) const;

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
    InitialStateMode mInitialStateMode{InitialStateMode::Nomination};
    bool mEnableBuiltInSCPInvariantChecks{false};
    bool mEnableNominationTimeouts{true};
    bool mEnableBallotingTimeouts{false};
    std::shared_ptr<ReplayMetrics> mReplayMetrics;
    std::vector<ReplayBaseline> mReplayBaselines;
    std::size_t mReplayCacheGeneration{0};
};

}
