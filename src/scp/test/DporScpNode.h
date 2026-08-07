// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
#include "scp/SCP.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace stellar
{

enum class DporScpTxSetStatus : std::uint8_t
{
    Valid,
    Downloading
};

class DporScpNode : public SCPDriver
{
  public:
    enum class BoundaryMode : std::uint8_t
    {
        None,
        Prepare,
        Commit,
        Externalize
    };

    class TxSetDownloadWaitTimeChoiceRequired : public std::runtime_error
    {
      public:
        explicit TxSetDownloadWaitTimeChoiceRequired(
            std::vector<std::chrono::milliseconds> choices);

        std::vector<std::chrono::milliseconds> const& getChoices() const;

      private:
        std::vector<std::chrono::milliseconds> mChoices;
    };

    class TxSetStatusChoiceRequired : public std::runtime_error
    {
      public:
        explicit TxSetStatusChoiceRequired(
            std::vector<DporScpTxSetStatus> choices);

        std::vector<DporScpTxSetStatus> const& getChoices() const;

      private:
        std::vector<DporScpTxSetStatus> mChoices;
    };

    // Scopes one external event: a single call that drives SCP from outside,
    // plus everything SCP does synchronously inside it. The five entry points
    // below open one; tests that need to exercise per-event behavior must open
    // one explicitly rather than relying on the implicit event that direct
    // driver calls made outside any scope form.
    //
    // Replay baselines may only be snapshotted or restored at an event
    // boundary, i.e. with no scope open.
    class ExternalEventScope
    {
      public:
        explicit ExternalEventScope(DporScpNode& node);
        ~ExternalEventScope();

        // Copying or moving would run the exit path twice and end the event
        // while it is still running.
        ExternalEventScope(ExternalEventScope const&) = delete;
        ExternalEventScope& operator=(ExternalEventScope const&) = delete;
        ExternalEventScope(ExternalEventScope&&) = delete;
        ExternalEventScope& operator=(ExternalEventScope&&) = delete;

      private:
        DporScpNode& mNode;
    };

    static constexpr uint32_t DEFAULT_PREPARE_BOUNDARY_COUNTER = 1;
    static constexpr uint32_t DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS = 1000;

    struct Configuration
    {
        std::map<NodeID, std::size_t> mNodeIndexMap;
        uint32_t mPrepareBoundaryCounter{DEFAULT_PREPARE_BOUNDARY_COUNTER};
        BoundaryMode mBoundaryMode{BoundaryMode::None};
        std::optional<uint32_t> mMaxNominationRound;
        std::optional<uint32_t> mMaxBallotingRound;
        DporScpTxSetStatus mTxSetStatus{DporScpTxSetStatus::Valid};
        bool mNondeterministicTxSetStatus{false};
        bool mNominationAlwaysDownloadingTxSetStatus{false};
        bool mInjectEmptyTxSetProtocolGateFailureForTesting{false};
        std::vector<DporScpTxSetStatus> mSupportedTxSetStatusChoices;
        std::map<NodeID, std::set<Value>> mOutrightInvalidValuesByNode;
        std::optional<uint32_t> mDownloadSucceedsInBallotRound;
        std::vector<std::chrono::milliseconds> mTxSetDownloadWaitTimes;
        bool mNondeterministicTxSetDownloadWaitTime{false};
        std::optional<uint32_t> mNominationTimerSetLimit;
        uint32_t mInitialNominationTimeoutMS{1000};
        uint32_t mIncrementNominationTimeoutMS{1000};
        uint32_t mInitialBallotTimeoutMS{1000};
        uint32_t mIncrementBallotTimeoutMS{1000};
    };

    struct TimerState
    {
        uint64 mSlotIndex{};
        int mTimerID{};
        std::chrono::milliseconds mTimeout{};
        std::function<void()> mCallback;
    };

    struct HistoricalStatementSnapshot
    {
        std::time_t mWhen{};
        SCPStatement mStatement;
        bool mValidated{};
    };

    struct NominationStateSnapshot
    {
        int32_t mRoundNumber{};
        std::vector<Value> mVotes;
        std::vector<Value> mAccepted;
        std::vector<Value> mCandidates;
        std::vector<SCPEnvelope> mLatestNominations;
        std::optional<SCPEnvelope> mLastEnvelope;
        std::vector<NodeID> mRoundLeaders;
        bool mNominationStarted{};
        std::optional<Value> mLatestCompositeCandidate;
        Value mPreviousValue;
        uint32_t mTimerExpCount{};
    };

    struct BallotStateSnapshot
    {
        bool mHeardFromQuorum{};
        std::optional<SCPBallot> mCurrentBallot;
        std::optional<SCPBallot> mPrepared;
        std::optional<SCPBallot> mPreparedPrime;
        std::optional<SCPBallot> mHighBallot;
        std::optional<SCPBallot> mCommit;
        std::vector<SCPEnvelope> mLatestEnvelopes;
        std::uint8_t mPhase{};
        std::optional<Value> mValueOverride;
        int mCurrentMessageLevel{};
        uint32_t mTimerExpCount{};
        std::optional<SCPEnvelope> mLastEnvelope;
        std::optional<SCPEnvelope> mLastEnvelopeEmit;
    };

    struct SlotStateSnapshot
    {
        uint64 mSlotIndex{};
        bool mFullyValidated{};
        bool mGotVBlocking{};
        std::vector<HistoricalStatementSnapshot> mStatementsHistory;
        NominationStateSnapshot mNominationState;
        BallotStateSnapshot mBallotState;
    };

    struct ReplayTimerSnapshot
    {
        uint64 mSlotIndex{};
        int mTimerID{};
        std::chrono::milliseconds mTimeout{};
    };

    struct ReplayTimerSetCountSnapshot
    {
        uint64 mSlotIndex{};
        int mTimerID{};
        uint32_t mCount{};
    };

    struct ReplayBaseline
    {
        // Identity of the snapshot's contents, assigned by
        // snapshotReplayBaseline(). Copies share it, because they are equal.
        // Zero means "not produced by snapshotReplayBaseline", which suppresses
        // the wrapped-form cache below.
        uint64 mSnapshotId{0};
        std::optional<SlotStateSnapshot> mSlotState;
        std::vector<SCPEnvelope> mEmittedEnvelopes;
        std::vector<ReplayTimerSnapshot> mTimers;
        std::vector<ReplayTimerSetCountSnapshot> mTimerSetCounts;
        std::map<Value, DporScpTxSetStatus> mLastTxSetStatusByValue;
        std::map<Value, std::chrono::milliseconds>
            mLastTxSetDownloadWaitTimeByValue;
        std::map<Value, std::size_t> mTxSetDownloadWaitTimeCallCountsByValue;
        std::set<Value> mTxSetDownloadsSucceeded;
        std::set<Value> mPendingTxSetDownloadsSucceeded;
        bool mHasReachedBoundary{};
        std::optional<SCPEnvelope> mBoundaryEnvelope;
    };

    struct ReplayDebugEvent
    {
        enum class Kind : std::uint8_t
        {
            EmitEnvelope,
            SetupTimer,
            StopTimer,
            FireTimer,
            UseTxSetDownloadWaitTime,
            RejectOutrightInvalidValue
        };

        Kind mKind{Kind::EmitEnvelope};
        uint64 mSlotIndex{};
        int mTimerID{};
        std::chrono::milliseconds mTimeout{};
        std::optional<SCPEnvelope> mEnvelope;
        std::optional<std::chrono::milliseconds> mWaitTime;
        bool mBoundary{false};
    };

    explicit DporScpNode(SecretKey const& secretKey,
                         SCPQuorumSet const& localQSet);

    explicit DporScpNode(SecretKey const& secretKey,
                         SCPQuorumSet const& localQSet,
                         Configuration const& config);

    // mSCP holds a reference back to this driver and shares slots via
    // shared_ptr; a copy would silently alias the original's state.
    DporScpNode(DporScpNode const&) = delete;
    DporScpNode& operator=(DporScpNode const&) = delete;

    NodeID const& getNodeID() const;

    SCP& getSCP();

    SCP const& getSCP() const;

    void storeQuorumSet(SCPQuorumSet const& qSet);

    bool nominate(uint64 slotIndex, Value const& value,
                  Value const& previousValue);

    bool startBalloting(uint64 slotIndex, Value const& value);

    SCP::EnvelopeState receiveEnvelope(SCPEnvelope const& envelope);

    std::vector<SCPEnvelope> takePendingEnvelopes();

    std::vector<SCPEnvelope> const& getEmittedEnvelopes() const;

    std::optional<TimerState> getTimer(uint64 slotIndex, int timerID) const;

    bool fireTimer(uint64 slotIndex, int timerID);

    void enqueueTxSetStatusChoice(DporScpTxSetStatus status);

    void enqueueTxSetDownloadWaitTimeChoice(std::chrono::milliseconds waitTime);

    // True when a preloaded txset choice was never asked for. A trace that
    // supplies more choices than the replayed event requests desynchronizes
    // the append-only choice queues, so replay checks this rather than letting
    // a later event silently consume a stale choice.
    bool hasUnconsumedTxSetChoices() const;

    void setReplayDebugRecordingEnabled(bool enabled);

    // Exploration never reads the emitted-envelope log -- only the inspection
    // and replay entry points do -- and appending to it deep-copies an envelope
    // per emission. Callers that only need boundary state can switch it off.
    void setEmittedEnvelopeRecordingEnabled(bool enabled);

    std::vector<ReplayDebugEvent> takeReplayDebugEvents();

    ReplayBaseline snapshotReplayBaseline(uint64 slotIndex) const;

    void restoreReplayBaseline(ReplayBaseline const& baseline);

    void installNominationReplayTimer(uint64 slotIndex,
                                      std::chrono::milliseconds timeout,
                                      Value const& value,
                                      Value const& previousValue);

    void installBallotingReplayTimer(uint64 slotIndex,
                                     std::chrono::milliseconds timeout);

    uint32_t inferNominationRound(std::chrono::milliseconds timeout) const;

    uint32_t inferBallotingRound(std::chrono::milliseconds timeout) const;

    bool hasReachedBoundary() const;

    SCPEnvelope const* getBoundaryEnvelope() const;

    void signEnvelope(SCPEnvelope& envelope) override;
    SCPQuorumSetPtr getQSet(Hash const& qSetHash) override;
    bool isEnvelopeReady(SCPEnvelope const& envelope) const override;
    std::optional<std::chrono::milliseconds>
    getTxSetDownloadWaitTime(Value const& value) const override;
    std::chrono::milliseconds getTxSetDownloadTimeout() const override;
    void emitEnvelope(SCPEnvelope const& envelope) override;
    ValidationLevel validateValue(uint64 slotIndex, Value const& value,
                                  bool nomination) const override;
    Value makeEmptyTxSetValueFromValue(Value const& value) const override;
    bool isEmptyTxSetValue(Value const& value) const override;
    static bool hasEmptyTxSetValuePrefix(Value const& value);
    bool isParallelTxSetDownloadEnabled() const override;
    bool protocolAllowsEmptyTxSetValues() const override;
    Hash getHashOf(std::vector<xdr::opaque_vec<>> const& vals) const override;
    uint64 computeHashNode(uint64 slotIndex, Value const& prev, bool isPriority,
                           int32_t roundNumber, NodeID const& nodeID) override;
    uint64 computeValueHash(uint64 slotIndex, Value const& prev,
                            int32_t roundNumber, Value const& value) override;
    ValueWrapperPtr
    combineCandidates(uint64 slotIndex,
                      ValueWrapperPtrSet const& candidates) override;
    bool hasUpgrades(Value const& value) override;
    ValueWrapperPtr stripAllUpgrades(Value const& value) override;
    uint32_t getUpgradeNominationTimeoutLimit() const override;
    void setupTimer(uint64 slotIndex, int timerID,
                    std::chrono::milliseconds timeout,
                    std::function<void()> cb) override;
    void stopTimer(uint64 slotIndex, int timerID) override;
    std::chrono::milliseconds computeTimeout(uint32 roundNumber,
                                             bool isNomination) override;

  private:
    // What the modeled tx-set state answered for one value during the event
    // currently running. Both answers are pinned once made, so repeated
    // callbacks inside a single handler observe one consistent snapshot the
    // way production does.
    struct TxSetEventDecision
    {
        std::optional<DporScpTxSetStatus> mStatus;
        bool mWaitTimeDecided{false};
        std::optional<std::chrono::milliseconds> mWaitTime;
    };

    void applyConfiguration(Configuration const& config);

    TimerState* findTimer(uint64 slotIndex, int timerID);

    TimerState const* findTimer(uint64 slotIndex, int timerID) const;

    void setTimer(TimerState timer);

    void clearTimer(uint64 slotIndex, int timerID);

    ReplayTimerSetCountSnapshot* findTimerSetCount(uint64 slotIndex,
                                                   int timerID);

    void recordReplayDebugEvent(ReplayDebugEvent event) const;

    void clearReplayState();

    void beginExternalEvent();

    void endExternalEvent();

    void markTxSetDownloadSucceeded(Value const& value);

    std::optional<Value>
    txSetDownloadSucceededValue(SCPEnvelope const& envelope) const;

    bool isOutrightInvalidValue(Value const& value) const;

    bool isEnvelopeBoundaryForMode(SCPEnvelope const& envelope) const;

    uint32_t inferTimeoutRound(std::chrono::milliseconds timeout,
                               uint32_t initialTimeoutMS,
                               uint32_t incrementTimeoutMS,
                               char const* timerName) const;

    SecretKey mSecretKey;
    SCP mSCP;
    std::map<NodeID, std::size_t> mNodeIndexMap;
    uint32_t mPrepareBoundaryCounter{DEFAULT_PREPARE_BOUNDARY_COUNTER};
    BoundaryMode mBoundaryMode{BoundaryMode::None};
    std::optional<uint32_t> mMaxNominationRound;
    std::optional<uint32_t> mMaxBallotingRound;
    DporScpTxSetStatus mTxSetStatus{DporScpTxSetStatus::Valid};
    bool mNondeterministicTxSetStatus{false};
    bool mNominationAlwaysDownloadingTxSetStatus{false};
    bool mInjectEmptyTxSetProtocolGateFailureForTesting{false};
    std::vector<DporScpTxSetStatus> mSupportedTxSetStatusChoices;
    std::set<Value> mOutrightInvalidValues;
    std::optional<uint32_t> mDownloadSucceedsInBallotRound;
    std::set<Value> mTxSetDownloadsSucceeded;
    // Downloads that completed during the event still running. Promoted into
    // mTxSetDownloadsSucceeded when the next event opens, so a completion can
    // never flip a verdict part-way through the handler that caused it.
    std::set<Value> mPendingTxSetDownloadsSucceeded;
    std::uint32_t mExternalEventDepth{0};
    // Deliberately absent from ReplayBaseline: it is scoped to one event, and
    // snapshotReplayBaseline() refuses to run while it holds anything, so it
    // can never be silently dropped by a snapshot.
    mutable std::map<Value, TxSetEventDecision> mTxSetDecisionsThisEvent;
    uint32_t mInitialNominationTimeoutMS{1000};
    uint32_t mIncrementNominationTimeoutMS{1000};
    uint32_t mInitialBallotTimeoutMS{1000};
    uint32_t mIncrementBallotTimeoutMS{1000};
    std::vector<std::chrono::milliseconds> mTxSetDownloadWaitTimes;
    bool mNondeterministicTxSetDownloadWaitTime{false};
    mutable std::vector<DporScpTxSetStatus> mPendingTxSetStatusChoices;
    mutable std::size_t mNextPendingTxSetStatusChoice{0};
    mutable std::map<Value, DporScpTxSetStatus> mLastTxSetStatusByValue;
    mutable std::map<Value, std::chrono::milliseconds>
        mLastTxSetDownloadWaitTimeByValue;
    mutable std::vector<std::chrono::milliseconds>
        mPendingTxSetDownloadWaitTimeChoices;
    mutable std::size_t mNextPendingTxSetDownloadWaitTimeChoice{0};
    mutable std::map<Value, std::size_t>
        mTxSetDownloadWaitTimeCallCountsByValue;
    bool mReplayDebugRecordingEnabled{false};
    bool mEmittedEnvelopeRecordingEnabled{true};
    mutable std::vector<ReplayDebugEvent> mReplayDebugEvents;
    std::optional<uint32_t> mNominationTimerSetLimit;

    // Restoring a baseline used to rebuild every SCP value/envelope wrapper it
    // mentions, and a node restores the same baseline over and over during
    // exploration. The wrappers are immutable, so they are built once per
    // snapshot identity and reused.
    struct WrappedBaseline
    {
        uint64 mSnapshotId{0};
        ValueWrapperPtrSet mVotes;
        ValueWrapperPtrSet mAccepted;
        ValueWrapperPtrSet mCandidates;
        std::set<NodeID> mRoundLeaders;
        std::map<NodeID, SCPEnvelopeWrapperPtr> mLatestNominations;
        std::map<NodeID, SCPEnvelopeWrapperPtr> mLatestEnvelopes;
        SCPEnvelopeWrapperPtr mNominationLastEnvelope;
        ValueWrapperPtr mLatestCompositeCandidate;
        ValueWrapperPtr mValueOverride;
        SCPEnvelopeWrapperPtr mBallotLastEnvelope;
        SCPEnvelopeWrapperPtr mBallotLastEnvelopeEmit;
    };

    WrappedBaseline mWrappedBaseline;

    std::map<Hash, SCPQuorumSetPtr> mQuorumSets;
    mutable Hash mLastQSetLookupHash{};
    mutable SCPQuorumSetPtr mLastQSetLookup;
    std::vector<SCPEnvelope> mEmittedEnvelopes;
    std::vector<SCPEnvelope> mPendingEnvelopes;
    std::vector<TimerState> mTimers;
    std::vector<ReplayTimerSetCountSnapshot> mTimerSetCounts;
    bool mHasReachedBoundary{false};
    std::optional<SCPEnvelope> mBoundaryEnvelope;
};

} // namespace stellar
