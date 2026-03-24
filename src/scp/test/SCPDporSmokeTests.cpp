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

TEST_CASE("scp dpor node restores txset wait-time choices in order",
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
    config.mNondeterministicTxSetDownloadWaitTimeAfterFirstCall = true;

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');

    auto const belowTimeout = config.mTxSetDownloadWaitTimes.at(0);
    auto const aboveTimeout = config.mTxSetDownloadWaitTimes.at(1);

    REQUIRE(node.getTxSetDownloadWaitTime(value) == belowTimeout);
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

} // namespace stellar::scpdpor
