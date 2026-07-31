// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/ScpDporReplaySupport.h"

#include <algorithm>
#include <atomic>
#include <iterator>
#include <vector>

namespace stellar::scpdpor
{

namespace
{

uint64_t
nextReplaySupportGeneration()
{
    static std::atomic<uint64_t> generationCounter{0};
    return ++generationCounter;
}

// Number of partially-replayed nodes kept per validator, per worker thread.
// Depth-first exploration backtracks a few events at a time, so a handful of
// slots captures almost all of the reuse; beyond that the per-call prefix scan
// costs more than the replays it saves.
constexpr std::size_t REPLAY_SLOTS_PER_NODE = 64;

struct ReplayStateCacheEntry
{
    uint64_t mGeneration{};
    std::size_t mNodeIndex{};
    std::unique_ptr<DporScpNode> mNode;
    ScpDporReplaySupport::ReplayCursor mCursor;
    uint64_t mLastUsed{0};
};

uint64_t&
threadLocalReplayClock()
{
    static thread_local uint64_t clock{0};
    return clock;
}

// Slots are bucketed by validator index so selecting one only scans that
// validator's slots rather than every cached node on the thread.
struct NodeSlotBucket
{
    uint64_t mGeneration{0};
    std::vector<ReplayStateCacheEntry> mSlots;
};

std::vector<NodeSlotBucket>&
threadLocalReplayStateCache()
{
    static thread_local std::vector<NodeSlotBucket> buckets;
    return buckets;
}

NodeSlotBucket&
bucketFor(uint64_t generation, std::size_t nodeIndex)
{
    auto& buckets = threadLocalReplayStateCache();
    if (nodeIndex >= buckets.size())
    {
        buckets.resize(nodeIndex + 1);
    }
    auto& bucket = buckets[nodeIndex];
    if (bucket.mGeneration != generation)
    {
        bucket.mSlots.clear();
        bucket.mGeneration = generation;
    }
    return bucket;
}

void
enqueueTxSetStatusChoices(DporScpNode& node,
                          std::vector<DporScpTxSetStatus> const& statuses)
{
    for (auto const status : statuses)
    {
        node.enqueueTxSetStatusChoice(status);
    }
}

void
enqueueTxSetDownloadWaitTimeChoices(
    DporScpNode& node,
    std::vector<std::chrono::milliseconds> const& waitTimes)
{
    for (auto const& waitTime : waitTimes)
    {
        node.enqueueTxSetDownloadWaitTimeChoice(waitTime);
    }
}

struct KnownTxSetChoices
{
    std::vector<DporScpTxSetStatus> mStatuses;
    std::vector<std::chrono::milliseconds> mWaitTimes;
    std::size_t mTraceEntries{};
};

KnownTxSetChoices
decodeKnownTxSetChoices(ThreadTrace const& trace, std::size_t observedIndex)
{
    KnownTxSetChoices decoded;
    for (std::size_t choiceIndex = observedIndex + 1; choiceIndex < trace.size();
         ++choiceIndex)
    {
        auto const& choiceObserved = trace.at(choiceIndex);
        if (choiceObserved.is_bottom())
        {
            break;
        }

        auto const& choiceValue = choiceObserved.value();
        if (isTxSetStatusChoiceValue(choiceValue))
        {
            decoded.mStatuses.push_back(decodeTxSetStatusChoice(choiceValue));
            ++decoded.mTraceEntries;
            continue;
        }
        if (isTxSetDownloadWaitTimeChoiceValue(choiceValue))
        {
            decoded.mWaitTimes.push_back(
                decodeTxSetDownloadWaitTimeChoice(choiceValue));
            ++decoded.mTraceEntries;
            continue;
        }
        break;
    }
    return decoded;
}

} // namespace

ScpDporReplaySupport::ScpDporReplaySupport(
    std::vector<SecretKey> validators, SCPQuorumSet qSet, uint64_t slotIndex,
    Value previousValue, std::vector<Value> initialValues,
    DporScpNode::Configuration config)
    : mValidators(std::move(validators))
    , mQSet(std::move(qSet))
    , mSlotIndex(slotIndex)
    , mPreviousValue(std::move(previousValue))
    , mInitialValues(std::move(initialValues))
    , mConfig(std::move(config))
    , mGeneration(nextReplaySupportGeneration())
{
    if (mValidators.empty())
    {
        throw std::invalid_argument("validators must not be empty");
    }
    if (mValidators.size() != mInitialValues.size())
    {
        throw std::invalid_argument(
            "initialValues must match validator count");
    }
    rebuildBaselines();
}

ScpDporReplaySupport::ScpDporReplaySupport(ScpDporReplaySupport const& other)
    : mValidators(other.mValidators)
    , mQSet(other.mQSet)
    , mSlotIndex(other.mSlotIndex)
    , mPreviousValue(other.mPreviousValue)
    , mInitialValues(other.mInitialValues)
    , mConfig(other.mConfig)
    , mReplayBaselines(other.mReplayBaselines)
    , mGeneration(nextReplaySupportGeneration())
{
}

std::size_t
ScpDporReplaySupport::size() const
{
    return mValidators.size();
}

ScpDporReplaySupport::NodeBaseline const&
ScpDporReplaySupport::getNodeBaseline(std::size_t nodeIndex) const
{
    return mReplayBaselines.at(nodeIndex);
}

namespace
{

ReplayStateCacheEntry&
acquireCacheEntry(uint64_t generation, std::size_t nodeIndex,
                  SecretKey const& validator, SCPQuorumSet const& qSet,
                  DporScpNode::Configuration const& config)
{
    auto& bucket = bucketFor(generation, nodeIndex);
    if (bucket.mSlots.empty())
    {
        bucket.mSlots.push_back(ReplayStateCacheEntry{
            generation, nodeIndex,
            std::make_unique<DporScpNode>(validator, qSet, config),
            {},
            0});
    }
    return bucket.mSlots.front();
}

} // namespace

DporScpNode&
ScpDporReplaySupport::acquireNode(std::size_t nodeIndex) const
{
    return *acquireCacheEntry(mGeneration, nodeIndex, mValidators.at(nodeIndex),
                              mQSet, mConfig)
                .mNode;
}

ScpDporReplaySupport::ReplayState
ScpDporReplaySupport::acquireReplayState(std::size_t nodeIndex,
                                         ThreadTrace const& trace,
                                         std::size_t step) const
{
    auto& slots = bucketFor(mGeneration, nodeIndex).mSlots;

    ReplayStateCacheEntry* best = nullptr;
    ReplayStateCacheEntry* leastRecentlyUsed = nullptr;
    std::size_t bestEventCount = 0;

    for (auto& entry : slots)
    {
        if (!leastRecentlyUsed || entry.mLastUsed < leastRecentlyUsed->mLastUsed)
        {
            leastRecentlyUsed = &entry;
        }

        auto const& cursor = entry.mCursor;
        if (!cursor.mValid || cursor.mEventCount > step ||
            cursor.mConsumedTrace.size() > trace.size())
        {
            continue;
        }
        if (best && cursor.mEventCount <= bestEventCount)
        {
            continue;
        }
        // Compared back-to-front: after a rollback the traces diverge near
        // their tail, so this rejects a stale cursor immediately instead of
        // walking the whole shared prefix first.
        if (!std::equal(cursor.mConsumedTrace.rbegin(),
                        cursor.mConsumedTrace.rend(),
                        std::make_reverse_iterator(
                            trace.begin() +
                            static_cast<std::ptrdiff_t>(
                                cursor.mConsumedTrace.size()))))
        {
            continue;
        }
        best = &entry;
        bestEventCount = cursor.mEventCount;
    }

    auto* chosen = best;
    if (!chosen)
    {
        if (slots.size() < REPLAY_SLOTS_PER_NODE)
        {
            slots.push_back(ReplayStateCacheEntry{
                mGeneration, nodeIndex,
                std::make_unique<DporScpNode>(mValidators.at(nodeIndex), mQSet,
                                              mConfig),
                {},
                0});
            chosen = &slots.back();
        }
        else
        {
            chosen = leastRecentlyUsed;
            chosen->mCursor.mValid = false;
        }
    }

    chosen->mLastUsed = ++threadLocalReplayClock();
    return ReplayState{*chosen->mNode, chosen->mCursor};
}

void
ScpDporReplaySupport::clearThreadLocalCacheForCurrentThread()
{
    threadLocalReplayStateCache().clear();
}

void
ScpDporReplaySupport::restoreBaseline(DporScpNode& node,
                                      std::size_t nodeIndex) const
{
    restoreNodeBaseline(node, nodeIndex,
                        mReplayBaselines.at(nodeIndex).mNodeState);
}

ScpDporReplaySupport::ReplayObservationProgress
ScpDporReplaySupport::replayObservation(DporScpNode& node,
                                        std::size_t nodeIndex,
                                        ThreadTrace const& trace,
                                        std::size_t observedIndex,
                                        std::optional<int> selectedTimerID) const
{
    static_cast<void>(nodeIndex);

    if (observedIndex >= trace.size())
    {
        throw std::out_of_range("observed trace index out of range");
    }

    auto const& observed = trace.at(observedIndex);
    auto const observedBottom = observed.is_bottom();
    auto const chosenTxSetChoices =
        decodeKnownTxSetChoices(trace, observedIndex);

    enqueueTxSetStatusChoices(node, chosenTxSetChoices.mStatuses);
    enqueueTxSetDownloadWaitTimeChoices(node, chosenTxSetChoices.mWaitTimes);
    try
    {
        replayOneObservedValue(node, observed, selectedTimerID);
        return ReplayObservationProgress{
            .mConsumedTraceEntries = 1 + chosenTxSetChoices.mTraceEntries,
            .mConsumedStepCount = chosenTxSetChoices.mTraceEntries,
            .mObservedBottom = observedBottom,
        };
    }
    catch (DporScpNode::TxSetStatusChoiceRequired const& e)
    {
        auto const choiceIndex =
            observedIndex + 1 + chosenTxSetChoices.mTraceEntries;
        if (choiceIndex < trace.size())
        {
            throw std::logic_error(
                "trace omits a txset status choice before the next observed event");
        }

        return ReplayObservationProgress{
            .mConsumedTraceEntries = 1 + chosenTxSetChoices.mTraceEntries,
            .mConsumedStepCount = chosenTxSetChoices.mTraceEntries,
            .mPendingEvent = makeTxSetStatusChoiceEvent(e.getChoices()),
            .mObservedBottom = observedBottom,
        };
    }
    catch (DporScpNode::TxSetDownloadWaitTimeChoiceRequired const& e)
    {
        auto const choiceIndex =
            observedIndex + 1 + chosenTxSetChoices.mTraceEntries;
        if (choiceIndex < trace.size())
        {
            throw std::logic_error(
                "trace omits a txset wait-time choice before the next observed event");
        }

        return ReplayObservationProgress{
            .mConsumedTraceEntries = 1 + chosenTxSetChoices.mTraceEntries,
            .mConsumedStepCount = chosenTxSetChoices.mTraceEntries,
            .mPendingEvent = makeTxSetDownloadWaitTimeChoiceEvent(e.getChoices()),
            .mObservedBottom = observedBottom,
        };
    }
}

void
ScpDporReplaySupport::initializeNode(DporScpNode& node,
                                     std::size_t nodeIndex) const
{
    node.nominate(mSlotIndex, mInitialValues.at(nodeIndex), mPreviousValue);
}

void
ScpDporReplaySupport::restoreNodeBaseline(
    DporScpNode& node, std::size_t nodeIndex,
    DporScpNode::ReplayBaseline const& baseline) const
{
    node.restoreReplayBaseline(baseline);
    for (auto const& timer : baseline.mTimers)
    {
        switch (timer.mTimerID)
        {
        case Slot::NOMINATION_TIMER:
            node.installNominationReplayTimer(timer.mSlotIndex, timer.mTimeout,
                                              mInitialValues.at(nodeIndex),
                                              mPreviousValue);
            break;
        case Slot::BALLOT_PROTOCOL_TIMER:
            node.installBallotingReplayTimer(timer.mSlotIndex, timer.mTimeout);
            break;
        default:
            throw std::logic_error("unknown replay timer id");
        }
    }
}

void
ScpDporReplaySupport::replayOneObservedValue(
    DporScpNode& node, ObservedValue const& observed,
    std::optional<int> selectedTimerID) const
{
    if (observed.is_bottom())
    {
        if (!selectedTimerID)
        {
            throw std::logic_error(
                "trace requested bottom without a selected timer");
        }
        if (!node.fireTimer(mSlotIndex, *selectedTimerID))
        {
            throw std::logic_error(
                "trace requested a timer firing without an active timer");
        }
        return;
    }

    auto const& value = observed.value();
    if (!isEnvelopeValue(value))
    {
        throw std::logic_error(
            "replay expected an SCP envelope delivery value");
    }
    if (value.mSlotIndex != mSlotIndex)
    {
        throw std::logic_error("trace delivered an envelope for the wrong slot");
    }
    node.receiveEnvelope(decodeEnvelope(value));
}

EventLabel
ScpDporReplaySupport::makeTxSetStatusChoiceEvent(
    std::vector<DporScpTxSetStatus> const& statuses) const
{
    std::vector<ScpDporValue> choices;
    choices.reserve(statuses.size());
    for (auto const status : statuses)
    {
        choices.push_back(makeTxSetStatusChoiceValue(mSlotIndex, status));
    }
    if (choices.empty())
    {
        throw std::logic_error("txset status choices must not be empty");
    }

    return EventLabel{NondeterministicChoiceLabel{.value = choices.front(),
                                                  .choices = std::move(choices)}};
}

EventLabel
ScpDporReplaySupport::makeTxSetDownloadWaitTimeChoiceEvent(
    std::vector<std::chrono::milliseconds> const& waitTimes) const
{
    std::vector<ScpDporValue> choices;
    choices.reserve(waitTimes.size());
    for (auto const& waitTime : waitTimes)
    {
        choices.push_back(
            makeTxSetDownloadWaitTimeChoiceValue(mSlotIndex, waitTime));
    }
    if (choices.empty())
    {
        throw std::logic_error("txset wait-time choices must not be empty");
    }

    return EventLabel{NondeterministicChoiceLabel{.value = choices.front(),
                                                  .choices = std::move(choices)}};
}

void
ScpDporReplaySupport::rebuildBaselines()
{
    std::vector<NodeBaseline> replayBaselines;
    replayBaselines.reserve(mValidators.size());

    for (std::size_t nodeIndex = 0; nodeIndex < mValidators.size();
         ++nodeIndex)
    {
        auto baselineConfig = mConfig;
        // Keep the replay baseline stable; hidden txset choices are exposed
        // during trace replay rather than while constructing the baseline.
        baselineConfig.mNondeterministicTxSetStatus = false;
        baselineConfig.mNondeterministicTxSetDownloadWaitTime = false;

        DporScpNode node(mValidators.at(nodeIndex), mQSet, baselineConfig);
        initializeNode(node, nodeIndex);

        NodeBaseline baseline;
        baseline.mInitialPendingEnvelopes = node.takePendingEnvelopes();
        baseline.mNodeState = node.snapshotReplayBaseline(mSlotIndex);
        replayBaselines.push_back(std::move(baseline));
    }

    mReplayBaselines = std::move(replayBaselines);
}

} // namespace stellar::scpdpor
