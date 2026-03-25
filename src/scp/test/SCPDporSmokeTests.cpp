// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/ScpDporThreeNodePrepareBoundaryScenario.h"
#include "test/Catch2.h"

#include <algorithm>

namespace stellar::scpdpor
{

namespace
{

Program
limitThreadSteps(Program program, std::vector<std::size_t> const& limits)
{
    for (std::size_t nodeIndex = 0; nodeIndex < limits.size(); ++nodeIndex)
    {
        auto const tid = threadIdForNodeIndex(nodeIndex);
        auto const threadFn = program.threads.at(tid);
        auto const limit = limits.at(nodeIndex);
        program.threads[tid] = [threadFn, limit](ThreadTrace const& trace,
                                                 std::size_t step)
            -> std::optional<EventLabel> {
            if (step >= limit)
            {
                return std::nullopt;
            }
            return threadFn(trace, step);
        };
    }
    return program;
}

bool
sameEventLabel(std::optional<EventLabel> const& lhs,
               std::optional<EventLabel> const& rhs)
{
    if (!lhs || !rhs)
    {
        return lhs.has_value() == rhs.has_value();
    }

    if (auto const* lhsSend = std::get_if<SendLabel>(&*lhs))
    {
        auto const* rhsSend = std::get_if<SendLabel>(&*rhs);
        return rhsSend != nullptr && lhsSend->destination == rhsSend->destination &&
               lhsSend->value == rhsSend->value;
    }
    if (auto const* lhsReceive = std::get_if<ReceiveLabel>(&*lhs))
    {
        auto const* rhsReceive = std::get_if<ReceiveLabel>(&*rhs);
        return rhsReceive != nullptr &&
               lhsReceive->mode == rhsReceive->mode;
    }
    if (auto const* lhsChoice = std::get_if<NondeterministicChoiceLabel>(&*lhs))
    {
        auto const* rhsChoice = std::get_if<NondeterministicChoiceLabel>(&*rhs);
        return rhsChoice != nullptr && lhsChoice->value == rhsChoice->value &&
               lhsChoice->choices == rhsChoice->choices;
    }
    return std::holds_alternative<dpor::model::ErrorLabel>(*lhs) ==
           std::holds_alternative<dpor::model::ErrorLabel>(*rhs);
}

SendLabel
requireSendLabel(std::optional<EventLabel> const& event)
{
    REQUIRE(event.has_value());
    auto const* send = std::get_if<SendLabel>(&*event);
    REQUIRE(send != nullptr);
    return *send;
}

ReceiveLabel
requireReceiveLabel(std::optional<EventLabel> const& event)
{
    REQUIRE(event.has_value());
    auto const* receive = std::get_if<ReceiveLabel>(&*event);
    REQUIRE(receive != nullptr);
    return *receive;
}

} // namespace

TEST_CASE("scp dpor scenario is deterministic", "[scp][dpor][smoke]")
{
    ScpDporThreeNodePrepareBoundaryScenario scenario;
    auto program = scenario.makeProgram();
    auto const& leader = program.threads.at(threadIdForNodeIndex(0));

    REQUIRE(sameEventLabel(leader({}, 0), leader({}, 0)));
    REQUIRE(sameEventLabel(leader({}, 1), leader({}, 1)));
    REQUIRE(sameEventLabel(leader({}, 2), leader({}, 2)));
}

TEST_CASE("scp dpor leader initially sends to both followers then waits",
          "[scp][dpor][smoke]")
{
    ScpDporThreeNodePrepareBoundaryScenario scenario;
    auto program = scenario.makeProgram();
    auto const& leader = program.threads.at(threadIdForNodeIndex(0));

    auto const& firstSend = requireSendLabel(leader({}, 0));
    REQUIRE(firstSend.destination == threadIdForNodeIndex(1));
    REQUIRE(isEnvelopeValue(firstSend.value));
    REQUIRE(decodeEnvelope(firstSend.value).statement.pledges.type() ==
            SCP_ST_NOMINATE);

    auto const& secondSend = requireSendLabel(leader({}, 1));
    REQUIRE(secondSend.destination == threadIdForNodeIndex(2));
    REQUIRE(isEnvelopeValue(secondSend.value));
    REQUIRE(decodeEnvelope(secondSend.value).statement.pledges.type() ==
            SCP_ST_NOMINATE);

    auto const& receive = requireReceiveLabel(leader({}, 2));
    REQUIRE(receive.is_blocking());
}

TEST_CASE("scp dpor smoke explore reaches a terminal execution",
          "[scp][dpor][smoke]")
{
    ScpDporThreeNodePrepareBoundaryScenario scenario;
    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 6;
    config.on_terminal_execution = [](auto const&) {
        return dpor::algo::TerminalExecutionAction::Stop;
    };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.executions_explored == 1);
}

TEST_CASE("scp dpor exploration finds a prepare boundary",
          "[scp][dpor][smoke]")
{
    ScpDporThreeNodePrepareBoundaryScenario scenario;
    bool foundPrepareBoundary = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 12;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const leaderTrace =
                execution.graph.thread_trace(threadIdForNodeIndex(0));
            auto inspection = scenario.inspectPrepareBoundary(0, leaderTrace);
            if (inspection.mReachedBoundary && inspection.mBoundaryEnvelope &&
                inspection.mBoundaryEnvelope->statement.pledges.type() ==
                    SCP_ST_PREPARE &&
                inspection.mBoundaryEnvelope->statement.pledges.prepare()
                        .ballot.counter >= 1)
            {
                foundPrepareBoundary = true;
                return dpor::algo::TerminalExecutionAction::Stop;
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    static_cast<void>(dpor::algo::verify(config));
    REQUIRE(foundPrepareBoundary);
}

TEST_CASE("scp dpor exploration finds a commit boundary",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporThreeNodePrepareBoundaryScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mStopOnCommit = true;
    ScpDporThreeNodePrepareBoundaryScenario scenario(std::move(options));
    bool foundCommitBoundary = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 60;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const leaderTrace =
                execution.graph.thread_trace(threadIdForNodeIndex(0));
            auto inspection = scenario.inspectBoundary(0, leaderTrace);
            if (inspection.mReachedBoundary && inspection.mBoundaryEnvelope)
            {
                auto const type =
                    inspection.mBoundaryEnvelope->statement.pledges.type();
                if (type == SCP_ST_CONFIRM || type == SCP_ST_EXTERNALIZE)
                {
                    foundCommitBoundary = true;
                    return dpor::algo::TerminalExecutionAction::Stop;
                }
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    static_cast<void>(dpor::algo::verify(config));
    REQUIRE(foundCommitBoundary);
}

TEST_CASE("scp dpor replay detects the timer-driven round boundary",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporThreeNodePrepareBoundaryScenario::makeDefaultOptions();
    options.mEnableNominationTimeouts = true;
    options.mMaxNominationRound = 1;
    ScpDporThreeNodePrepareBoundaryScenario scenario(std::move(options));
    ThreadTrace leaderTrace;
    leaderTrace.emplace_back(ObservedValue::bottom());

    auto const inspection = scenario.inspectBoundary(0, leaderTrace);
    REQUIRE(inspection.mReachedBoundary);
    REQUIRE_FALSE(inspection.mBoundaryEnvelope.has_value());
}

TEST_CASE("scp dpor node detects the balloting round boundary",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporThreeNodePrepareBoundaryScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mMaxBallotingRound = 1;

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    node.setupTimer(options.mSlotIndex, Slot::BALLOT_PROTOCOL_TIMER,
                    node.computeTimeout(2, false), []() {});

    REQUIRE(node.hasReachedBoundary());
    REQUIRE_FALSE(node.getBoundaryEnvelope());
}

TEST_CASE("scp dpor replay trace captures follower emitted envelopes",
          "[scp][dpor][smoke]")
{
    ScpDporThreeNodePrepareBoundaryScenario scenario;
    std::vector<ThreadTrace> threadTraces(
        scenario.options().mValidators.size());
    bool capturedTrace = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 12;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            if (!execution.is_full_execution())
            {
                return dpor::algo::TerminalExecutionAction::Continue;
            }

            for (std::size_t nodeIndex = 0;
                 nodeIndex < scenario.options().mValidators.size();
                 ++nodeIndex)
            {
                threadTraces.at(nodeIndex) = execution.graph.thread_trace(
                    threadIdForNodeIndex(nodeIndex));
            }
            capturedTrace = true;
            return dpor::algo::TerminalExecutionAction::Stop;
        };

    static_cast<void>(dpor::algo::verify(config));
    REQUIRE(capturedTrace);

    bool sawFollowerEmitNominate = false;
    bool sawBoundaryPrepare = false;
    for (std::size_t nodeIndex = 0;
         nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
    {
        auto inspection =
            scenario.inspectThreadReplayTrace(nodeIndex, threadTraces.at(nodeIndex));
        REQUIRE(!inspection.mSteps.empty());

        for (auto const& step : inspection.mSteps)
        {
            for (auto const& effect : step.mSideEffects)
            {
                if (nodeIndex > 0 &&
                    effect.mKind ==
                        DporScpNode::ReplayDebugEvent::Kind::EmitEnvelope &&
                    effect.mEnvelope &&
                    effect.mEnvelope->statement.pledges.type() ==
                        SCP_ST_NOMINATE)
                {
                    sawFollowerEmitNominate = true;
                }
                if (effect.mKind ==
                        DporScpNode::ReplayDebugEvent::Kind::EmitEnvelope &&
                    effect.mBoundary && effect.mEnvelope &&
                    effect.mEnvelope->statement.pledges.type() ==
                        SCP_ST_PREPARE)
                {
                    sawBoundaryPrepare = true;
                }
            }
        }
    }

    REQUIRE(sawFollowerEmitNominate);
    REQUIRE(sawBoundaryPrepare);
}

TEST_CASE("scp dpor exploration finds a follower timer firing before delivery",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporThreeNodePrepareBoundaryScenario::makeDefaultOptions();
    options.mEnableNominationTimeouts = true;
    ScpDporThreeNodePrepareBoundaryScenario scenario(std::move(options));
    bool foundFollowerTimeout = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program =
        limitThreadSteps(scenario.makeProgram(), std::vector<std::size_t>{1, 1, 1});
    config.max_depth = 3;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const followerTrace =
                execution.graph.thread_trace(threadIdForNodeIndex(1));
            for (auto const& observed : followerTrace)
            {
                if (observed.is_bottom())
                {
                    foundFollowerTimeout = true;
                    return dpor::algo::TerminalExecutionAction::Stop;
                }
                if (isEnvelopeValue(observed.value()))
                {
                    break;
                }
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    static_cast<void>(dpor::algo::verify(config));
    REQUIRE(foundFollowerTimeout);
}

TEST_CASE("scp dpor node restores txset wait-time choices from the first call",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporThreeNodePrepareBoundaryScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mAwaitTxSetDownloads = true;
    config.mTxSetDownloadWaitTimes = {
        std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1),
        std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS + 1)};
    config.mNondeterministicTxSetDownloadWaitTime = true;

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');

    auto const belowTimeout = config.mTxSetDownloadWaitTimes.at(0);
    auto const aboveTimeout = config.mTxSetDownloadWaitTimes.at(1);

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(value),
                      DporScpNode::TxSetDownloadWaitTimeChoiceRequired);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetDownloadWaitTimeChoice(belowTimeout);
    node.enqueueTxSetDownloadWaitTimeChoice(aboveTimeout);
    REQUIRE(node.getTxSetDownloadWaitTime(value) == belowTimeout);
    REQUIRE(node.getTxSetDownloadWaitTime(value) == aboveTimeout);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetDownloadWaitTimeChoice(aboveTimeout);
    REQUIRE(node.getTxSetDownloadWaitTime(value) == aboveTimeout);
    REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(value),
                      DporScpNode::TxSetDownloadWaitTimeChoiceRequired);
}

TEST_CASE(
    "scp dpor replay preloads known txset wait-time choices from the first query",
    "[scp][dpor][smoke]")
{
    auto const validator = SecretKey::pseudoRandomForTestingFromSeed(2000);

    SCPQuorumSet qSet;
    qSet.threshold = 1;
    qSet.validators.push_back(validator.getPublicKey());

    Value previousValue;
    previousValue.push_back('p');
    Value initialValue;
    initialValue.push_back('x');

    DporScpNode::Configuration config;
    config.mAwaitTxSetDownloads = true;
    config.mTxSetDownloadWaitTimes = {
        std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1),
        std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS + 1)};
    config.mNondeterministicTxSetDownloadWaitTime = true;

    auto const belowTimeout = config.mTxSetDownloadWaitTimes.at(0);
    auto const aboveTimeout = config.mTxSetDownloadWaitTimes.at(1);

    auto replayConfig = config;
    replayConfig.mNondeterministicTxSetDownloadWaitTime = false;

    std::vector<SecretKey> validators{validator};
    std::vector<Value> initialValues{initialValue};
    ScpDporReplaySupport replaySupport(validators, qSet, 0, previousValue,
                                       initialValues, replayConfig);
    DporScpNode node(validator, qSet, config);

    std::vector<std::chrono::milliseconds> seenWaitTimes;
    node.setupTimer(0, Slot::NOMINATION_TIMER, std::chrono::milliseconds(10),
                    [&node, &seenWaitTimes, initialValue]() {
                        auto const first =
                            node.getTxSetDownloadWaitTime(initialValue);
                        REQUIRE(first.has_value());
                        seenWaitTimes.push_back(*first);

                        auto const second =
                            node.getTxSetDownloadWaitTime(initialValue);
                        REQUIRE(second.has_value());
                        seenWaitTimes.push_back(*second);
                    });

    ThreadTrace trace;
    trace.emplace_back(ObservedValue::bottom());
    trace.emplace_back(
        makeTxSetDownloadWaitTimeChoiceValue(0, belowTimeout));
    trace.emplace_back(
        makeTxSetDownloadWaitTimeChoiceValue(0, aboveTimeout));
    trace.emplace_back(ObservedValue::bottom());

    auto const progress =
        replaySupport.replayObservation(node, 0, trace, 0,
                                        std::optional<int>{
                                            Slot::NOMINATION_TIMER});

    REQUIRE(progress.mConsumedTraceEntries == 3);
    REQUIRE(progress.mConsumedStepCount == 2);
    REQUIRE_FALSE(progress.mPendingEvent.has_value());
    REQUIRE(progress.mObservedBottom);

    std::vector<std::chrono::milliseconds> const expectedWaitTimes{
        belowTimeout, aboveTimeout};
    REQUIRE(seenWaitTimes == expectedWaitTimes);
}

} // namespace stellar::scpdpor
