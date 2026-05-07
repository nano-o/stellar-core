// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/ScpDporDefaultScenario.h"
#include "scp/test/ScpDporInvestigationUtils.h"
#include "scp/test/ScpDporTraceJson.h"
#include "test/Catch2.h"

#include <algorithm>
#include <filesystem>
#include <optional>
#include <stdexcept>

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

std::vector<DporScpTxSetStatus>
requireTxSetStatusChoices(DporScpNode& node, uint64 slotIndex,
                          Value const& value)
{
    try
    {
        static_cast<void>(node.validateValue(slotIndex, value, false));
    }
    catch (DporScpNode::TxSetStatusChoiceRequired const& e)
    {
        return e.getChoices();
    }
    FAIL("expected txset status choice");
    return {};
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

std::vector<Value>
requireNominateVotes(std::optional<EventLabel> const& event)
{
    auto const send = requireSendLabel(event);
    auto const envelope = decodeEnvelope(send.value);
    REQUIRE(envelope.statement.pledges.type() == SCP_ST_NOMINATE);

    auto const& nominate = envelope.statement.pledges.nominate();
    return std::vector<Value>(nominate.votes.begin(), nominate.votes.end());
}

bool
hasExternalizeEnvelope(std::vector<SCPEnvelope> const& envelopes)
{
    return std::any_of(envelopes.begin(), envelopes.end(),
                       [](SCPEnvelope const& envelope) {
                           return envelope.statement.pledges.type() ==
                                  SCP_ST_EXTERNALIZE;
                       });
}

std::optional<Value>
findExternalizedValue(std::vector<SCPEnvelope> const& envelopes)
{
    for (auto const& envelope : envelopes)
    {
        if (envelope.statement.pledges.type() == SCP_ST_EXTERNALIZE)
        {
            return envelope.statement.pledges.externalize().commit.value;
        }
    }
    return std::nullopt;
}

bool
hasTxSetStatusObservation(
    ScpDporDefaultScenario::ThreadReplayTraceInspection const& inspection,
    uint64 slotIndex, DporScpTxSetStatus status)
{
    auto const expected =
        ObservedValue{makeTxSetStatusChoiceValue(slotIndex, status)};
    for (auto const& step : inspection.mSteps)
    {
        if (step.mObservedValue && *step.mObservedValue == expected)
        {
            return true;
        }
        if (std::find(step.mNestedChoices.begin(), step.mNestedChoices.end(),
                      expected) != step.mNestedChoices.end())
        {
            return true;
        }
    }
    return false;
}

bool
fullExecutionExternalizedValuesAgree(
    ScpDporDefaultScenario const& scenario,
    dpor::algo::TerminalExecutionT<ScpDporValue> const& execution)
{
    if (!execution.is_full_execution())
    {
        return true;
    }

    std::optional<Value> referenceValue;
    for (std::size_t nodeIndex = 0;
         nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
    {
        auto const trace =
            execution.graph.thread_trace(threadIdForNodeIndex(nodeIndex));
        auto const inspection = scenario.inspectEmittedEnvelopes(nodeIndex, trace);
        auto const externalizedValue =
            findExternalizedValue(inspection.mEmittedEnvelopes);
        if (!externalizedValue)
        {
            continue;
        }
        if (!referenceValue)
        {
            referenceValue = *externalizedValue;
            continue;
        }
        if (*externalizedValue != *referenceValue)
        {
            return false;
        }
    }
    return true;
}

std::filesystem::path
traceJsonTempPath(std::string_view name)
{
    return std::filesystem::temp_directory_path() /
           std::filesystem::path(std::string(name) + ".json");
}

} // namespace

TEST_CASE("scp dpor scenario is deterministic", "[scp][dpor][smoke]")
{
    ScpDporDefaultScenario scenario;
    auto program = scenario.makeProgram();
    auto const& leader = program.threads.at(threadIdForNodeIndex(0));

    REQUIRE(sameEventLabel(leader({}, 0), leader({}, 0)));
    REQUIRE(sameEventLabel(leader({}, 1), leader({}, 1)));
    REQUIRE(sameEventLabel(leader({}, 2), leader({}, 2)));
}

TEST_CASE("scp dpor leader initially sends to both followers then waits",
          "[scp][dpor][smoke]")
{
    ScpDporDefaultScenario scenario;
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

TEST_CASE("scp dpor nomination timer round cap disables later timer firings",
          "[scp][dpor][smoke]")
{
    auto enabledOptions = ScpDporDefaultScenario::makeDefaultOptions();
    enabledOptions.mEnableNominationTimeouts = true;
    ScpDporDefaultScenario enabledScenario(std::move(enabledOptions));
    auto enabledProgram = enabledScenario.makeProgram();
    auto const& enabledLeader =
        enabledProgram.threads.at(threadIdForNodeIndex(0));

    auto const enabledReceive = requireReceiveLabel(enabledLeader({}, 2));
    REQUIRE(enabledReceive.is_nonblocking());

    auto cappedOptions = ScpDporDefaultScenario::makeDefaultOptions();
    cappedOptions.mEnableNominationTimeouts = true;
    cappedOptions.mMaxNominationTimersRound = 0;
    ScpDporDefaultScenario cappedScenario(std::move(cappedOptions));
    auto cappedProgram = cappedScenario.makeProgram();
    auto const& cappedLeader = cappedProgram.threads.at(threadIdForNodeIndex(0));

    auto const cappedReceive = requireReceiveLabel(cappedLeader({}, 2));
    REQUIRE(cappedReceive.is_blocking());
}

TEST_CASE("scp dpor scenario supports same and unique initial value presets",
          "[scp][dpor][smoke]")
{
    auto sameOptions = ScpDporDefaultScenario::makeDefaultOptions();
    sameOptions.mInitialValues = ScpDporDefaultScenario::makeInitialValues(
        ScpDporDefaultScenario::InitialValueMode::Same,
        sameOptions.mValidators.size());
    ScpDporDefaultScenario sameScenario(std::move(sameOptions));
    auto sameProgram = sameScenario.makeProgram();
    auto const& sameLeader = sameProgram.threads.at(threadIdForNodeIndex(0));
    auto const sameVotes = requireNominateVotes(sameLeader({}, 0));
    REQUIRE(sameVotes.size() == 1);
    REQUIRE(sameVotes.front() == sameScenario.options().mInitialValues.at(0));
    REQUIRE(sameScenario.options().mInitialValues.at(0) ==
            sameScenario.options().mInitialValues.at(1));
    REQUIRE(sameScenario.options().mInitialValues.at(1) ==
            sameScenario.options().mInitialValues.at(2));

    auto uniqueOptions = ScpDporDefaultScenario::makeDefaultOptions();
    uniqueOptions.mInitialValues = ScpDporDefaultScenario::makeInitialValues(
        ScpDporDefaultScenario::InitialValueMode::Unique,
        uniqueOptions.mValidators.size());
    ScpDporDefaultScenario uniqueScenario(std::move(uniqueOptions));
    auto uniqueProgram = uniqueScenario.makeProgram();
    auto const& uniqueLeader =
        uniqueProgram.threads.at(threadIdForNodeIndex(0));
    auto const uniqueVotes = requireNominateVotes(uniqueLeader({}, 0));
    REQUIRE(uniqueVotes.size() == 1);
    REQUIRE(uniqueVotes.front() == uniqueScenario.options().mInitialValues.at(0));
    REQUIRE(uniqueScenario.options().mInitialValues.at(0) !=
            uniqueScenario.options().mInitialValues.at(1));
    REQUIRE(uniqueScenario.options().mInitialValues.at(1) !=
            uniqueScenario.options().mInitialValues.at(2));
    REQUIRE(uniqueVotes.front() != sameVotes.front());
}

TEST_CASE("scp dpor trace json round-trips scenario options",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mStopOnCommit = true;
    options.mMaxNominationRound = 2;
    options.mMaxBallotingRound = 3;
    options.mMaxNominationTimersRound = 4;
    options.mMaxBallotingTimersRound = 5;
    options.mNominationTimerSetLimit = 6;
    options.mEnableNominationTimeouts = true;
    options.mEnableBallotingTimeouts = true;
    options.mDownloadTimeMode =
        ScpDporDefaultScenario::DownloadTimeMode::Nondeterministic;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::Nondeterministic;
    options.mNominationAlwaysWaiting = true;
    options.mDownloadSucceedsInRound = 7;
    options.mInitialNominationTimeoutMS = 1200;
    options.mIncrementNominationTimeoutMS = 1300;
    options.mInitialBallotTimeoutMS = 1400;
    options.mIncrementBallotTimeoutMS = 1500;

    auto const roundTripped = optionsFromJson(toJson(options));

    REQUIRE(roundTripped == options);
}

TEST_CASE("scp dpor trace json round-trips thread traces",
          "[scp][dpor][smoke]")
{
    ScpDporDefaultScenario scenario;
    auto program = scenario.makeProgram();
    auto const& leader = program.threads.at(threadIdForNodeIndex(0));
    auto const firstSend = requireSendLabel(leader({}, 0));

    ThreadTrace trace;
    trace.push_back(ObservedValue::bottom());
    trace.push_back(ObservedValue{firstSend.value});
    trace.push_back(ObservedValue{makeTimerChoiceValue(
        scenario.options().mSlotIndex, Slot::NOMINATION_TIMER)});
    trace.push_back(ObservedValue{makeTxSetDownloadWaitTimeChoiceValue(
        scenario.options().mSlotIndex, std::chrono::milliseconds(1500))});
    trace.push_back(ObservedValue{makeTxSetStatusChoiceValue(
        scenario.options().mSlotIndex, DporScpTxSetStatus::Invalid)});

    auto const roundTripped = threadTraceFromJson(toJson(trace));

    REQUIRE(roundTripped == trace);
}

TEST_CASE("scp dpor smoke explore reaches a terminal execution",
          "[scp][dpor][smoke]")
{
    ScpDporDefaultScenario scenario;
    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 6;
    config.on_terminal_execution = [](auto const&) {
        return dpor::algo::TerminalExecutionAction::Stop;
    };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.executions_explored == 1);
}

TEST_CASE("scp dpor investigation wraps thread throws as error executions",
          "[scp][dpor][smoke]")
{
    Program program;
    auto const tid = threadIdForNodeIndex(0);
    program.threads[tid] = [](ThreadTrace const&, std::size_t)
        -> std::optional<EventLabel> {
        throw std::runtime_error("boom");
    };
    program = wrapProgramExceptionsAsErrorExecutions(std::move(program));

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = std::move(program);
    config.max_depth = 1;

    std::optional<InvestigationErrorExecution> errorExecution;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            errorExecution = findErrorExecution(1, execution);
            REQUIRE(errorExecution.has_value());
            return dpor::algo::TerminalExecutionAction::Stop;
        };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.error_executions_explored == 1);
    REQUIRE(errorExecution.has_value());
    REQUIRE(errorExecution->mNodeIndex == 0);
    REQUIRE(errorExecution->mThreadID == tid);
    REQUIRE(errorExecution->mMessage.find("step=0") != std::string::npos);
    REQUIRE(errorExecution->mMessage.find("boom") != std::string::npos);
}

TEST_CASE("scp dpor replay trace keeps the lead-in to an SCP exception",
          "[scp][dpor][smoke]")
{
    std::string const expectedError =
        "SCP forced commit on locally-invalid value";
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::Nondeterministic;
    ScpDporDefaultScenario scenario(std::move(options));

    std::optional<InvestigationErrorExecution> errorExecution;
    std::optional<ScpDporDefaultScenario::ThreadReplayTraceInspection>
        replayInspection;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = wrapProgramExceptionsAsErrorExecutions(
        scenario.makeProgram());
    config.max_depth = 50;
    config.communication_model = dpor::model::CommunicationModel::FifoP2P;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto candidate = findErrorExecution(
                scenario.options().mValidators.size(), execution);
            if (!candidate ||
                candidate->mMessage.find(expectedError) == std::string::npos)
            {
                return dpor::algo::TerminalExecutionAction::Continue;
            }

            auto const trace =
                execution.graph.thread_trace(candidate->mThreadID);
            replayInspection = scenario.inspectThreadReplayTrace(
                candidate->mNodeIndex, trace);
            errorExecution = std::move(candidate);
            return dpor::algo::TerminalExecutionAction::Stop;
        };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.error_executions_explored >= 1);
    REQUIRE(errorExecution.has_value());
    REQUIRE(errorExecution->mMessage.find(expectedError) != std::string::npos);
    REQUIRE(replayInspection.has_value());
    REQUIRE(!replayInspection->mSteps.empty());
    REQUIRE(hasTxSetStatusObservation(*replayInspection,
                                      scenario.options().mSlotIndex,
                                      DporScpTxSetStatus::Invalid));
    REQUIRE(replayInspection->mReplayErrorMessage.has_value());
    REQUIRE(replayInspection->mReplayErrorMessage->find(
                expectedError) != std::string::npos);
}

TEST_CASE("scp dpor trace json writes loads and replays an error execution",
          "[scp][dpor][smoke]")
{
    std::string const expectedError =
        "SCP forced commit on locally-invalid value";
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::Nondeterministic;
    ScpDporDefaultScenario scenario(std::move(options));

    std::optional<TraceBundle> bundle;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = wrapProgramExceptionsAsErrorExecutions(
        scenario.makeProgram());
    config.max_depth = 50;
    config.communication_model = dpor::model::CommunicationModel::FifoP2P;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const errorExecution = findErrorExecution(
                scenario.options().mValidators.size(), execution);
            if (!errorExecution ||
                errorExecution->mMessage.find(expectedError) ==
                    std::string::npos)
            {
                return dpor::algo::TerminalExecutionAction::Continue;
            }

            bundle = makeTraceBundle(
                scenario, execution, config.communication_model,
                TerminalMeta{
                    .mKind = execution.kind,
                    .mFailureMessage = errorExecution->mMessage,
                    .mFocusNodeIndex = errorExecution->mNodeIndex,
                    .mFocusThreadID = errorExecution->mThreadID});
            return dpor::algo::TerminalExecutionAction::Stop;
        };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.error_executions_explored >= 1);
    REQUIRE(bundle.has_value());

    auto const path = traceJsonTempPath("scp-dpor-trace-json-error");
    std::filesystem::remove(path);
    writeTraceBundle(path, *bundle);
    auto const loaded = loadTraceBundle(path);
    std::filesystem::remove(path);

    REQUIRE(loaded.mVersion == 1);
    REQUIRE(loaded.mOptions == bundle->mOptions);
    REQUIRE(loaded.mCommunicationModel == bundle->mCommunicationModel);
    REQUIRE(loaded.mTerminal.mKind == bundle->mTerminal.mKind);
    REQUIRE(loaded.mTerminal.mFailureMessage == bundle->mTerminal.mFailureMessage);
    REQUIRE(loaded.mTerminal.mFocusNodeIndex == bundle->mTerminal.mFocusNodeIndex);
    REQUIRE(loaded.mTerminal.mFocusThreadID == bundle->mTerminal.mFocusThreadID);
    REQUIRE(loaded.mTerminal.mFailureMessage);
    REQUIRE(loaded.mTerminal.mFailureMessage->find(expectedError) !=
            std::string::npos);
    REQUIRE(loaded.mThreadTraces.size() == bundle->mThreadTraces.size());
    for (std::size_t i = 0; i < bundle->mThreadTraces.size(); ++i)
    {
        REQUIRE(loaded.mThreadTraces.at(i).mThreadID ==
                bundle->mThreadTraces.at(i).mThreadID);
        REQUIRE(loaded.mThreadTraces.at(i).mTrace ==
                bundle->mThreadTraces.at(i).mTrace);
    }

    ScpDporDefaultScenario loadedScenario(loaded.mOptions);
    auto const inspection = loadedScenario.inspectThreadReplayTrace(
        loaded.mTerminal.mFocusNodeIndex,
        loaded.mThreadTraces.at(loaded.mTerminal.mFocusNodeIndex).mTrace);

    REQUIRE(!inspection.mSteps.empty());
    REQUIRE(hasTxSetStatusObservation(inspection, loaded.mOptions.mSlotIndex,
                                      DporScpTxSetStatus::Invalid));
    REQUIRE(inspection.mReplayErrorMessage.has_value());
    REQUIRE(inspection.mReplayErrorMessage->find(
                expectedError) != std::string::npos);
}

TEST_CASE("scp dpor captures forced invalid commit as an error execution",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::Nondeterministic;
    ScpDporDefaultScenario scenario(std::move(options));

    std::string const expectedError =
        "SCP forced commit on locally-invalid value";
    bool capturedInvalidCommitError = false;
    std::string capturedMessage;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = wrapProgramExceptionsAsErrorExecutions(
        scenario.makeProgram());
    config.max_depth = 50;
    config.communication_model = dpor::model::CommunicationModel::FifoP2P;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const errorExecution = findErrorExecution(
                scenario.options().mValidators.size(), execution);
            if (errorExecution &&
                errorExecution->mMessage.find(expectedError) !=
                    std::string::npos)
            {
                capturedInvalidCommitError = true;
                capturedMessage = errorExecution->mMessage;
                return dpor::algo::TerminalExecutionAction::Stop;
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    auto const result = dpor::algo::verify(config);
    (void)result;

    REQUIRE(capturedInvalidCommitError);
    REQUIRE(capturedMessage.find(expectedError) != std::string::npos);
    REQUIRE(capturedMessage.find("setAcceptCommit") != std::string::npos);
}

TEST_CASE("scp dpor exploration finds a prepare boundary",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::Nondeterministic;
    ScpDporDefaultScenario scenario(std::move(options));
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
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mStopOnCommit = true;
    ScpDporDefaultScenario scenario(std::move(options));
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

TEST_CASE("scp dpor exploration finds an externalize boundary",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mStopOnExternalize = true;
    ScpDporDefaultScenario scenario(std::move(options));
    bool foundExternalizeBoundary = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 60;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const leaderTrace =
                execution.graph.thread_trace(threadIdForNodeIndex(0));
            auto inspection = scenario.inspectBoundary(0, leaderTrace);
            if (inspection.mReachedBoundary && inspection.mBoundaryEnvelope &&
                inspection.mBoundaryEnvelope->statement.pledges.type() ==
                    SCP_ST_EXTERNALIZE)
            {
                foundExternalizeBoundary = true;
                return dpor::algo::TerminalExecutionAction::Stop;
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    static_cast<void>(dpor::algo::verify(config));
    REQUIRE(foundExternalizeBoundary);
}

TEST_CASE("scp dpor replay detects the timer-driven round boundary",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mEnableNominationTimeouts = true;
    options.mMaxNominationRound = 1;
    ScpDporDefaultScenario scenario(std::move(options));
    ThreadTrace leaderTrace;
    leaderTrace.emplace_back(ObservedValue::bottom());

    auto const inspection = scenario.inspectBoundary(0, leaderTrace);
    REQUIRE(inspection.mReachedBoundary);
    REQUIRE_FALSE(inspection.mBoundaryEnvelope.has_value());
}

TEST_CASE("scp dpor node detects the balloting round boundary",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mMaxBallotingRound = 1;

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    node.setupTimer(options.mSlotIndex, Slot::BALLOT_PROTOCOL_TIMER,
                    node.computeTimeout(2, false), []() {});

    REQUIRE(node.hasReachedBoundary());
    REQUIRE_FALSE(node.getBoundaryEnvelope());
}

TEST_CASE("scp dpor replay trace captures emitted envelopes",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = true;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::Nondeterministic;
    ScpDporDefaultScenario scenario(std::move(options));
    bool sawEmittedEnvelope = false;
    bool sawBoundaryPrepare = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 12;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            bool executionSawEmittedEnvelope = false;
            bool executionSawBoundaryPrepare = false;
            for (std::size_t nodeIndex = 0;
                 nodeIndex < scenario.options().mValidators.size();
                 ++nodeIndex)
            {
                auto inspection = scenario.inspectThreadReplayTrace(
                    nodeIndex,
                    execution.graph.thread_trace(threadIdForNodeIndex(nodeIndex)));
                REQUIRE(!inspection.mSteps.empty());

                for (auto const& step : inspection.mSteps)
                {
                    for (auto const& effect : step.mSideEffects)
                    {
                        if (effect.mKind ==
                                DporScpNode::ReplayDebugEvent::Kind::EmitEnvelope &&
                            effect.mEnvelope)
                        {
                            executionSawEmittedEnvelope = true;
                        }
                        if (effect.mKind ==
                                DporScpNode::ReplayDebugEvent::Kind::EmitEnvelope &&
                            effect.mBoundary && effect.mEnvelope &&
                            effect.mEnvelope->statement.pledges.type() ==
                                SCP_ST_PREPARE)
                        {
                            executionSawBoundaryPrepare = true;
                        }
                    }
                }
            }

            if (executionSawEmittedEnvelope && executionSawBoundaryPrepare)
            {
                sawEmittedEnvelope = true;
                sawBoundaryPrepare = true;
                return dpor::algo::TerminalExecutionAction::Stop;
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    static_cast<void>(dpor::algo::verify(config));
    REQUIRE(sawEmittedEnvelope);
    REQUIRE(sawBoundaryPrepare);
}

TEST_CASE("scp dpor emitted envelopes expose missing externalize",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::Nondeterministic;
    ScpDporDefaultScenario scenario(std::move(options));
    std::size_t fullExecutionsChecked = 0;
    bool foundMissingExternalize = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 12;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            if (!execution.is_full_execution())
            {
                return dpor::algo::TerminalExecutionAction::Continue;
            }

            ++fullExecutionsChecked;
            for (std::size_t nodeIndex = 0;
                 nodeIndex < scenario.options().mValidators.size();
                 ++nodeIndex)
            {
                auto const trace = execution.graph.thread_trace(
                    threadIdForNodeIndex(nodeIndex));
                auto const inspection =
                    scenario.inspectEmittedEnvelopes(nodeIndex, trace);
                if (!hasExternalizeEnvelope(inspection.mEmittedEnvelopes))
                {
                    foundMissingExternalize = true;
                    return dpor::algo::TerminalExecutionAction::Stop;
                }
            }

            return dpor::algo::TerminalExecutionAction::Continue;
        };

    static_cast<void>(dpor::algo::verify(config));

    REQUIRE(fullExecutionsChecked > 0);
    REQUIRE(foundMissingExternalize);
}

TEST_CASE("scp dpor full executions keep externalized values in agreement",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::Nondeterministic;
    options.mDownloadTimeMode =
        ScpDporDefaultScenario::DownloadTimeMode::Nondeterministic;
    ScpDporDefaultScenario scenario(std::move(options));
    std::size_t fullExecutionsChecked = 0;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 12;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            if (!execution.is_full_execution())
            {
                return dpor::algo::TerminalExecutionAction::Continue;
            }

            ++fullExecutionsChecked;
            REQUIRE(fullExecutionExternalizedValuesAgree(scenario, execution));
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.full_executions_explored > 0);
    REQUIRE(fullExecutionsChecked == result.full_executions_explored);
}

TEST_CASE("scp dpor exploration finds a follower timer firing before delivery",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mEnableNominationTimeouts = true;
    ScpDporDefaultScenario scenario(std::move(options));
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

TEST_CASE("scp dpor node latches txset wait-time once a value times out",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mTxSetStatus = DporScpTxSetStatus::Waiting;
    config.mTxSetDownloadWaitTimes = {
        std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1),
        std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS + 1)};
    config.mNondeterministicTxSetDownloadWaitTime = true;

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');
    Value otherValue;
    otherValue.push_back('y');

    auto const belowTimeout = config.mTxSetDownloadWaitTimes.at(0);
    auto const aboveTimeout = config.mTxSetDownloadWaitTimes.at(1);

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(value),
                      DporScpNode::TxSetDownloadWaitTimeChoiceRequired);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetDownloadWaitTimeChoice(aboveTimeout);
    REQUIRE(node.getTxSetDownloadWaitTime(value) == aboveTimeout);
    auto const aboveCheckpoint = node.snapshotReplayBaseline(options.mSlotIndex);
    REQUIRE(node.getTxSetDownloadWaitTime(value) == aboveTimeout);

    node.restoreReplayBaseline(aboveCheckpoint);
    REQUIRE(node.getTxSetDownloadWaitTime(value) == aboveTimeout);
    REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(otherValue),
                      DporScpNode::TxSetDownloadWaitTimeChoiceRequired);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetDownloadWaitTimeChoice(belowTimeout);
    REQUIRE(node.getTxSetDownloadWaitTime(value) == belowTimeout);
    REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(value),
                      DporScpNode::TxSetDownloadWaitTimeChoiceRequired);
    auto const belowCheckpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    node.restoreReplayBaseline(belowCheckpoint);
    REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(value),
                      DporScpNode::TxSetDownloadWaitTimeChoiceRequired);
}

TEST_CASE(
    "scp dpor replay restores pending txset wait-time eligibility",
    "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;
    config.mTxSetDownloadWaitTimes = {std::chrono::milliseconds(
        DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1)};

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');

    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Waiting);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kAwaitingDownload);

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);
    node.restoreReplayBaseline(checkpoint);

    auto const waitTime = node.getTxSetDownloadWaitTime(value);
    REQUIRE(waitTime.has_value());
    REQUIRE(*waitTime == config.mTxSetDownloadWaitTimes.at(0));
}

TEST_CASE(
    "scp dpor replay reuses a latched txset wait-time once a value times out",
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
    config.mTxSetStatus = DporScpTxSetStatus::Waiting;
    config.mTxSetDownloadWaitTimes = {
        std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1),
        std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS + 1)};
    config.mNondeterministicTxSetDownloadWaitTime = true;

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
    trace.emplace_back(makeTxSetDownloadWaitTimeChoiceValue(0, aboveTimeout));
    trace.emplace_back(ObservedValue::bottom());

    auto const progress =
        replaySupport.replayObservation(node, 0, trace, 0,
                                        std::optional<int>{
                                            Slot::NOMINATION_TIMER});

    REQUIRE(progress.mConsumedTraceEntries == 2);
    REQUIRE(progress.mConsumedStepCount == 1);
    REQUIRE_FALSE(progress.mPendingEvent.has_value());
    REQUIRE(progress.mObservedBottom);

    std::vector<std::chrono::milliseconds> const expectedWaitTimes{
        aboveTimeout, aboveTimeout};
    REQUIRE(seenWaitTimes == expectedWaitTimes);
}

TEST_CASE("scp dpor node latches txset status once a value is resolved",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');
    Value otherValue;
    otherValue.push_back('y');

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, value, false),
                      DporScpNode::TxSetStatusChoiceRequired);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Valid);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kFullyValidatedValue);
    auto const validCheckpoint = node.snapshotReplayBaseline(options.mSlotIndex);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kFullyValidatedValue);

    node.restoreReplayBaseline(validCheckpoint);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kFullyValidatedValue);
    REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, otherValue, false),
                      DporScpNode::TxSetStatusChoiceRequired);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Invalid);
    REQUIRE(node.validateValue(options.mSlotIndex, otherValue, false) ==
            SCPDriver::kInvalidValue);
    REQUIRE(node.validateValue(options.mSlotIndex, otherValue, false) ==
            SCPDriver::kInvalidValue);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Waiting);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kAwaitingDownload);
    auto const waitingCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);
    REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, value, false),
                      DporScpNode::TxSetStatusChoiceRequired);

    node.restoreReplayBaseline(waitingCheckpoint);
    REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, value, false),
                      DporScpNode::TxSetStatusChoiceRequired);
}

TEST_CASE("scp dpor node can model eventual valid txset resolution",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mTxSetStatus = DporScpTxSetStatus::Valid;
    config.mNondeterministicTxSetStatus = true;
    config.mSupportedTxSetStatusChoices = {DporScpTxSetStatus::Waiting,
                                           DporScpTxSetStatus::Valid};

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    REQUIRE(requireTxSetStatusChoices(node, options.mSlotIndex, value) ==
            config.mSupportedTxSetStatusChoices);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Waiting);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kAwaitingDownload);
    auto const waitingCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);
    REQUIRE(requireTxSetStatusChoices(node, options.mSlotIndex, value) ==
            config.mSupportedTxSetStatusChoices);

    node.restoreReplayBaseline(waitingCheckpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Valid);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kFullyValidatedValue);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kFullyValidatedValue);
}

TEST_CASE("scp dpor node can model eventual invalid txset resolution",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mTxSetStatus = DporScpTxSetStatus::Invalid;
    config.mNondeterministicTxSetStatus = true;
    config.mSupportedTxSetStatusChoices = {DporScpTxSetStatus::Waiting,
                                           DporScpTxSetStatus::Invalid};

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    REQUIRE(requireTxSetStatusChoices(node, options.mSlotIndex, value) ==
            config.mSupportedTxSetStatusChoices);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Waiting);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kAwaitingDownload);
    auto const waitingCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);
    REQUIRE(requireTxSetStatusChoices(node, options.mSlotIndex, value) ==
            config.mSupportedTxSetStatusChoices);

    node.restoreReplayBaseline(waitingCheckpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Invalid);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kInvalidValue);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kInvalidValue);
}

TEST_CASE("scp dpor node can force waiting txset status during nomination",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mTxSetStatus = DporScpTxSetStatus::Valid;
    config.mNondeterministicTxSetStatus = true;
    config.mNominationAlwaysWaitingTxSetStatus = true;
    config.mSupportedTxSetStatusChoices = {DporScpTxSetStatus::Waiting,
                                           DporScpTxSetStatus::Valid};

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');

    REQUIRE(node.validateValue(options.mSlotIndex, value, true) ==
            SCPDriver::kAwaitingDownload);
    REQUIRE(requireTxSetStatusChoices(node, options.mSlotIndex, value) ==
            config.mSupportedTxSetStatusChoices);

    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Valid);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kFullyValidatedValue);
    REQUIRE(node.validateValue(options.mSlotIndex, value, true) ==
            SCPDriver::kAwaitingDownload);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kFullyValidatedValue);
}

TEST_CASE(
    "scp dpor download-succeeds-in-round forces later txset validation valid",
    "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;
    config.mDownloadSucceedsInBallotRound = 1;

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');

    REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, value, false),
                      DporScpNode::TxSetStatusChoiceRequired);

    SCPEnvelope prepareEnvelope;
    prepareEnvelope.statement.slotIndex = options.mSlotIndex;
    prepareEnvelope.statement.nodeID =
        options.mValidators.at(0).getPublicKey();
    prepareEnvelope.statement.pledges.type(SCP_ST_PREPARE);
    prepareEnvelope.statement.pledges.prepare().ballot.counter = 1;
    prepareEnvelope.statement.pledges.prepare().ballot.value = value;
    node.emitEnvelope(prepareEnvelope);

    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kFullyValidatedValue);

    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Invalid);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kFullyValidatedValue);

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);
    node.restoreReplayBaseline(checkpoint);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kFullyValidatedValue);
}

TEST_CASE(
    "scp dpor replay reuses a latched txset status once a value is resolved",
    "[scp][dpor][smoke]")
{
    auto const validator = SecretKey::pseudoRandomForTestingFromSeed(2001);

    SCPQuorumSet qSet;
    qSet.threshold = 1;
    qSet.validators.push_back(validator.getPublicKey());

    Value previousValue;
    previousValue.push_back('p');
    Value initialValue;
    initialValue.push_back('x');

    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;

    std::vector<SecretKey> validators{validator};
    std::vector<Value> initialValues{initialValue};
    ScpDporReplaySupport replaySupport(validators, qSet, 0, previousValue,
                                       initialValues, config);
    DporScpNode node(validator, qSet, config);

    std::vector<SCPDriver::ValidationLevel> seenStatuses;
    node.setupTimer(0, Slot::NOMINATION_TIMER, std::chrono::milliseconds(10),
                    [&node, &seenStatuses, initialValue]() {
                        seenStatuses.push_back(
                            node.validateValue(0, initialValue, false));
                        seenStatuses.push_back(
                            node.validateValue(0, initialValue, false));
                    });

    ThreadTrace trace;
    trace.emplace_back(ObservedValue::bottom());
    trace.emplace_back(
        makeTxSetStatusChoiceValue(0, DporScpTxSetStatus::Invalid));
    trace.emplace_back(ObservedValue::bottom());

    auto const progress =
        replaySupport.replayObservation(node, 0, trace, 0,
                                        std::optional<int>{
                                            Slot::NOMINATION_TIMER});

    REQUIRE(progress.mConsumedTraceEntries == 2);
    REQUIRE(progress.mConsumedStepCount == 1);
    REQUIRE_FALSE(progress.mPendingEvent.has_value());
    REQUIRE(progress.mObservedBottom);

    std::vector<SCPDriver::ValidationLevel> const expectedStatuses{
        SCPDriver::kInvalidValue, SCPDriver::kInvalidValue};
    REQUIRE(seenStatuses == expectedStatuses);
}

} // namespace stellar::scpdpor
