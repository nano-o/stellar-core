// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/SHA.h"
#include "scp/test/ScpDporDefaultScenario.h"
#include "scp/test/ScpDporInvestigationUtils.h"
#include "scp/test/ScpDporTraceJson.h"
#include "test/Catch2.h"
#include "xdrpp/marshal.h"

#include <algorithm>
#include <filesystem>
#include <functional>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>
#include <utility>

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
        program.threads[tid] =
            [threadFn, limit](ThreadTrace const& trace,
                              std::size_t step) -> std::optional<EventLabel> {
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
        return rhsSend != nullptr &&
               lhsSend->destination == rhsSend->destination &&
               lhsSend->value == rhsSend->value;
    }
    if (auto const* lhsReceive = std::get_if<ReceiveLabel>(&*lhs))
    {
        auto const* rhsReceive = std::get_if<ReceiveLabel>(&*rhs);
        return rhsReceive != nullptr && lhsReceive->mode == rhsReceive->mode;
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
    return std::any_of(
        envelopes.begin(), envelopes.end(), [](SCPEnvelope const& envelope) {
            return envelope.statement.pledges.type() == SCP_ST_EXTERNALIZE;
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

std::vector<Value>
collectExternalizedValues(
    ScpDporDefaultScenario const& scenario,
    dpor::algo::TerminalExecutionT<ScpDporValue> const& execution)
{
    std::vector<Value> externalizedValues;
    for (std::size_t nodeIndex = 0;
         nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
    {
        auto const trace =
            execution.graph.thread_trace(threadIdForNodeIndex(nodeIndex));
        auto const inspection =
            scenario.inspectEmittedEnvelopes(nodeIndex, trace);
        auto const externalizedValue =
            findExternalizedValue(inspection.mEmittedEnvelopes);
        if (externalizedValue)
        {
            externalizedValues.push_back(*externalizedValue);
        }
    }
    return externalizedValues;
}

Value
makeTestValue(std::string_view bytes)
{
    Value value;
    value.insert(value.end(), bytes.begin(), bytes.end());
    return value;
}

Value const&
requireBallotValue(std::vector<SCPEnvelope> const& envelopes)
{
    for (auto const& envelope : envelopes)
    {
        switch (envelope.statement.pledges.type())
        {
        case SCP_ST_PREPARE:
            return envelope.statement.pledges.prepare().ballot.value;
        case SCP_ST_CONFIRM:
            return envelope.statement.pledges.confirm().ballot.value;
        case SCP_ST_EXTERNALIZE:
            return envelope.statement.pledges.externalize().commit.value;
        default:
            break;
        }
    }
    FAIL("no ballot-phase envelope was emitted");
    throw std::logic_error("unreachable");
}

std::size_t
countWaitTimeDebugEvents(
    std::vector<DporScpNode::ReplayDebugEvent> const& events)
{
    return static_cast<std::size_t>(
        std::count_if(events.begin(), events.end(), [](auto const& event) {
            return event.mKind == DporScpNode::ReplayDebugEvent::Kind::
                                      UseTxSetDownloadWaitTime;
        }));
}

bool
isTestEmptyTxSetValue(Value const& value)
{
    static std::string const prefix = "EMPTY:";
    return value.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), value.begin());
}

bool
hasReplayDebugEvent(
    ScpDporDefaultScenario::ThreadReplayTraceInspection const& inspection,
    DporScpNode::ReplayDebugEvent::Kind kind)
{
    for (auto const& step : inspection.mSteps)
    {
        if (std::any_of(
                step.mSideEffects.begin(), step.mSideEffects.end(),
                [kind](auto const& effect) { return effect.mKind == kind; }))
        {
            return true;
        }
    }
    return false;
}

SCPEnvelope
makeTestNominateEnvelope(NodeID const& nodeID, Hash const& qSetHash,
                         uint64 slotIndex, Value const& value)
{
    SCPEnvelope envelope;
    envelope.statement.nodeID = nodeID;
    envelope.statement.slotIndex = slotIndex;
    envelope.statement.pledges.type(SCP_ST_NOMINATE);
    auto& nomination = envelope.statement.pledges.nominate();
    nomination.quorumSetHash = qSetHash;
    nomination.votes.emplace_back(value);
    return envelope;
}

SCPEnvelope
makeTestPrepareEnvelope(NodeID const& nodeID, Hash const& qSetHash,
                        uint64 slotIndex, SCPBallot const& ballot,
                        std::optional<SCPBallot> const& prepared = std::nullopt)
{
    SCPEnvelope envelope;
    envelope.statement.nodeID = nodeID;
    envelope.statement.slotIndex = slotIndex;
    envelope.statement.pledges.type(SCP_ST_PREPARE);
    auto& prepare = envelope.statement.pledges.prepare();
    prepare.quorumSetHash = qSetHash;
    prepare.ballot = ballot;
    if (prepared)
    {
        prepare.prepared.activate() = *prepared;
    }
    return envelope;
}

SCPEnvelope
makeTestExternalizeEnvelope(NodeID const& nodeID, Hash const& qSetHash,
                            uint64 slotIndex, SCPBallot const& ballot)
{
    SCPEnvelope envelope;
    envelope.statement.nodeID = nodeID;
    envelope.statement.slotIndex = slotIndex;
    envelope.statement.pledges.type(SCP_ST_EXTERNALIZE);
    auto& externalize = envelope.statement.pledges.externalize();
    externalize.commit = ballot;
    externalize.nH = ballot.counter;
    externalize.commitQuorumSetHash = qSetHash;
    return envelope;
}

// Owns a temp file path unique to this process, so concurrent test runs on
// one machine cannot race on the same file; removes it on scope exit even
// when the test body throws.
struct TraceJsonTempFile
{
    std::filesystem::path mPath;

    explicit TraceJsonTempFile(std::string_view name)
        : mPath(std::filesystem::temp_directory_path() /
                std::filesystem::path(std::string(name) + "-" +
                                      std::to_string(::getpid()) + ".json"))
    {
        std::filesystem::remove(mPath);
    }

    ~TraceJsonTempFile()
    {
        std::error_code ec;
        std::filesystem::remove(mPath, ec);
    }
};

} // namespace

TEST_CASE("scp dpor value hashing agrees with equality on empty envelopes",
          "[scp][dpor][smoke]")
{
    // A value with no shared payload compares equal to one carrying a
    // default-constructed envelope, so it has to hash and order like one too.
    ScpDporValue withoutPayload;
    REQUIRE(withoutPayload.mKind == ScpDporValue::Kind::Envelope);
    REQUIRE_FALSE(static_cast<bool>(withoutPayload.mEnvelope));

    auto const withPayload = makeEnvelopeValue(0, SCPEnvelope{});
    REQUIRE(static_cast<bool>(withPayload.mEnvelope));

    REQUIRE(withoutPayload == withPayload);
    REQUIRE(withoutPayload.envelopeDigest() == withPayload.envelopeDigest());
    REQUIRE(std::hash<ScpDporValue>{}(withoutPayload) ==
            std::hash<ScpDporValue>{}(withPayload));
    REQUIRE_FALSE(withoutPayload < withPayload);
    REQUIRE_FALSE(withPayload < withoutPayload);
}

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

TEST_CASE("scp dpor default scenario supports four validators",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions(4);

    REQUIRE(options.mValidators.size() == 4);
    REQUIRE(options.mQuorumSet.threshold == 3);
    REQUIRE(options.mQuorumSet.validators.size() == 4);
    for (auto const& validator : options.mValidators)
    {
        auto const publicKey = validator.getPublicKey();
        REQUIRE(std::find(options.mQuorumSet.validators.begin(),
                          options.mQuorumSet.validators.end(),
                          publicKey) != options.mQuorumSet.validators.end());
    }

    REQUIRE(options.mInitialValues.size() == 4);
    REQUIRE(options.mInitialValues.at(0) != options.mInitialValues.at(1));
    REQUIRE(options.mInitialValues.at(1) == options.mInitialValues.at(2));
    REQUIRE(options.mInitialValues.at(2) == options.mInitialValues.at(3));

    ScpDporDefaultScenario scenario(options);
    auto program = scenario.makeProgram();
    REQUIRE(program.threads.size() == 4);

    std::optional<std::size_t> initialSender;
    for (std::size_t nodeIndex = 0; nodeIndex < options.mValidators.size();
         ++nodeIndex)
    {
        auto const& thread =
            program.threads.at(threadIdForNodeIndex(nodeIndex));
        auto const firstEvent = thread({}, 0);
        if (firstEvent && std::holds_alternative<SendLabel>(*firstEvent))
        {
            initialSender = nodeIndex;
            break;
        }
    }
    REQUIRE(initialSender);

    auto const& sender =
        program.threads.at(threadIdForNodeIndex(*initialSender));
    std::set<dpor::model::ThreadId> destinations;
    for (std::size_t step = 0; step < options.mValidators.size() - 1; ++step)
    {
        auto const send = requireSendLabel(sender({}, step));
        destinations.insert(send.destination);
    }
    REQUIRE(destinations.size() == options.mValidators.size() - 1);
    REQUIRE(!destinations.contains(threadIdForNodeIndex(*initialSender)));

    auto const receive =
        requireReceiveLabel(sender({}, options.mValidators.size() - 1));
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
    auto const& cappedLeader =
        cappedProgram.threads.at(threadIdForNodeIndex(0));

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
    REQUIRE(uniqueVotes.front() ==
            uniqueScenario.options().mInitialValues.at(0));
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
        ScpDporDefaultScenario::TxSetStatusMode::DownloadingThenValid;
    options.mNominationAlwaysDownloading = true;
    options.mInjectEmptyTxSetProtocolGateFailureForTesting = true;
    options.mOutrightInvalidValuesByNode.resize(options.mValidators.size());
    options.mOutrightInvalidValuesByNode.at(1).push_back(
        options.mInitialValues.at(0));
    options.mDownloadSucceedsInRound = 7;
    options.mInitialNominationTimeoutMS = 1200;
    options.mIncrementNominationTimeoutMS = 1300;
    options.mInitialBallotTimeoutMS = 1400;
    options.mIncrementBallotTimeoutMS = 1500;

    auto const roundTripped = optionsFromJson(toJson(options));

    REQUIRE(roundTripped == options);

    auto const fourNodeOptions = ScpDporDefaultScenario::makeDefaultOptions(4);
    REQUIRE(optionsFromJson(toJson(fourNodeOptions)) == fourNodeOptions);

    using TxSetStatusMode = ScpDporDefaultScenario::TxSetStatusMode;
    std::vector<std::pair<TxSetStatusMode, std::string>> const statusModes{
        {TxSetStatusMode::AlwaysValid, "always-valid"},
        {TxSetStatusMode::DownloadingThenValid, "downloading-then-valid"},
        {TxSetStatusMode::AlwaysDownloading, "always-downloading"}};
    for (auto const& [mode, name] : statusModes)
    {
        options.mTxSetStatusMode = mode;
        auto const encoded = toJson(options);
        REQUIRE(encoded["txset_status_mode"].asString() == name);
        REQUIRE(optionsFromJson(encoded).mTxSetStatusMode == mode);
    }
}

TEST_CASE("scp dpor rejects malformed outright-invalid scenario mappings",
          "[scp][dpor][smoke]")
{
    auto wrongSize = ScpDporDefaultScenario::makeDefaultOptions();
    wrongSize.mOutrightInvalidValuesByNode.resize(1);
    REQUIRE_THROWS_AS(ScpDporDefaultScenario(std::move(wrongSize)),
                      std::invalid_argument);

    auto duplicate = ScpDporDefaultScenario::makeDefaultOptions();
    duplicate.mOutrightInvalidValuesByNode.resize(duplicate.mValidators.size());
    duplicate.mOutrightInvalidValuesByNode.at(0) = {
        duplicate.mInitialValues.at(0), duplicate.mInitialValues.at(0)};
    REQUIRE_THROWS_AS(ScpDporDefaultScenario(std::move(duplicate)),
                      std::invalid_argument);
}

TEST_CASE("scp dpor trace json rejects removed txset status modes",
          "[scp][dpor][smoke]")
{
    for (auto const version : {2, 3})
    {
        Json::Value root(Json::objectValue);
        root["version"] = version;
        REQUIRE_THROWS_WITH(
            traceBundleFromJson(root),
            Catch::Contains("removed downloaded-invalid or nondeterministic"));
    }
}

TEST_CASE("scp dpor trace json round-trips thread traces", "[scp][dpor][smoke]")
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
        scenario.options().mSlotIndex, DporScpTxSetStatus::Downloading)});

    auto const roundTripped = threadTraceFromJson(toJson(trace));

    REQUIRE(roundTripped == trace);
}

TEST_CASE("scp dpor trace json rejects pre-CAP version one",
          "[scp][dpor][smoke]")
{
    Json::Value root(Json::objectValue);
    root["version"] = 1;

    REQUIRE_THROWS_WITH(
        traceBundleFromJson(root),
        Catch::Contains("version 1 uses incompatible pre-CAP-0083"));
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
    program.threads[tid] = [](ThreadTrace const&,
                              std::size_t) -> std::optional<EventLabel> {
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

TEST_CASE("scp dpor investigation identifies the first blocked node",
          "[scp][dpor][smoke]")
{
    Program program;
    auto const tid = threadIdForNodeIndex(0);
    program.threads[tid] = [](ThreadTrace const&,
                              std::size_t) -> std::optional<EventLabel> {
        auto matcher = [](ScpDporValue const&) { return true; };
        return EventLabel{
            dpor::model::make_receive_label<ScpDporValue>(matcher)};
    };

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = std::move(program);
    config.max_depth = 2;

    std::optional<InvestigationBlockedExecution> blockedExecution;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto candidate = findBlockedExecution(1, execution);
            if (candidate)
            {
                blockedExecution = candidate;
                return dpor::algo::TerminalExecutionAction::Stop;
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.blocked_executions_explored == 1);
    REQUIRE(blockedExecution.has_value());
    REQUIRE(blockedExecution->mNodeIndex == 0);
    REQUIRE(blockedExecution->mThreadID == tid);
}

TEST_CASE("scp dpor replay trace keeps the lead-in to an SCP exception",
          "[scp][dpor][smoke]")
{
    // With empty-tx-set values disallowed by the driver, SCP's
    // releaseAssert(protocolAllowsEmptyTxSetValues()) fires as soon as a
    // ballot envelope validates as only structurally valid (txset
    // Downloading).
    std::string const expectedError = "protocolAllowsEmptyTxSetValues()";
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::DownloadingThenValid;
    options.mInjectEmptyTxSetProtocolGateFailureForTesting = true;
    ScpDporDefaultScenario scenario(std::move(options));

    std::optional<InvestigationErrorExecution> errorExecution;
    std::optional<ScpDporDefaultScenario::ThreadReplayTraceInspection>
        replayInspection;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program =
        wrapProgramExceptionsAsErrorExecutions(scenario.makeProgram());
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
            replayInspection =
                scenario.inspectThreadReplayTrace(candidate->mNodeIndex, trace);
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
                                      DporScpTxSetStatus::Downloading));
    REQUIRE(replayInspection->mReplayErrorMessage.has_value());
    REQUIRE(replayInspection->mReplayErrorMessage->find(expectedError) !=
            std::string::npos);
}

TEST_CASE("scp dpor trace json writes loads and replays an error execution",
          "[scp][dpor][smoke]")
{
    std::string const expectedError = "protocolAllowsEmptyTxSetValues()";
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::DownloadingThenValid;
    options.mInjectEmptyTxSetProtocolGateFailureForTesting = true;
    ScpDporDefaultScenario scenario(std::move(options));

    std::optional<TraceBundle> bundle;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program =
        wrapProgramExceptionsAsErrorExecutions(scenario.makeProgram());
    config.max_depth = 50;
    config.communication_model = dpor::model::CommunicationModel::FifoP2P;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const errorExecution = findErrorExecution(
                scenario.options().mValidators.size(), execution);
            if (!errorExecution || errorExecution->mMessage.find(
                                       expectedError) == std::string::npos)
            {
                return dpor::algo::TerminalExecutionAction::Continue;
            }

            bundle = makeTraceBundle(
                scenario, execution, config.communication_model,
                TerminalMeta{.mKind = execution.kind,
                             .mFailureMessage = errorExecution->mMessage,
                             .mFocusNodeIndex = errorExecution->mNodeIndex,
                             .mFocusThreadID = errorExecution->mThreadID});
            return dpor::algo::TerminalExecutionAction::Stop;
        };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.error_executions_explored >= 1);
    REQUIRE(bundle.has_value());

    TraceJsonTempFile tempFile("scp-dpor-trace-json-error");
    writeTraceBundle(tempFile.mPath, *bundle);
    auto const loaded = loadTraceBundle(tempFile.mPath);

    REQUIRE(loaded.mVersion == TRACE_BUNDLE_VERSION);
    REQUIRE(loaded.mOptions == bundle->mOptions);
    REQUIRE(loaded.mCommunicationModel == bundle->mCommunicationModel);
    REQUIRE(loaded.mTerminal.mKind == bundle->mTerminal.mKind);
    REQUIRE(loaded.mTerminal.mFailureMessage ==
            bundle->mTerminal.mFailureMessage);
    REQUIRE(loaded.mTerminal.mFocusNodeIndex ==
            bundle->mTerminal.mFocusNodeIndex);
    REQUIRE(loaded.mTerminal.mFocusThreadID ==
            bundle->mTerminal.mFocusThreadID);
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
                                      DporScpTxSetStatus::Downloading));
    REQUIRE(inspection.mReplayErrorMessage.has_value());
    REQUIRE(inspection.mReplayErrorMessage->find(expectedError) !=
            std::string::npos);
}

TEST_CASE("scp dpor captures an SCP releaseAssert as an error execution",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::DownloadingThenValid;
    options.mInjectEmptyTxSetProtocolGateFailureForTesting = true;
    ScpDporDefaultScenario scenario(std::move(options));

    std::string const expectedError = "protocolAllowsEmptyTxSetValues()";
    bool capturedInvalidCommitError = false;
    std::string capturedMessage;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program =
        wrapProgramExceptionsAsErrorExecutions(scenario.makeProgram());
    config.max_depth = 50;
    config.communication_model = dpor::model::CommunicationModel::FifoP2P;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const errorExecution = findErrorExecution(
                scenario.options().mValidators.size(), execution);
            if (errorExecution && errorExecution->mMessage.find(
                                      expectedError) != std::string::npos)
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
    REQUIRE(capturedMessage.find("BallotProtocol.cpp") != std::string::npos);
}

TEST_CASE("scp dpor exploration finds a prepare boundary", "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = true;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::DownloadingThenValid;
    ScpDporDefaultScenario scenario(std::move(options));
    bool foundPrepareBoundary = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    // Reaching the boundary also fans the boundary envelope out to both peers.
    config.max_depth = 14;
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

TEST_CASE("scp dpor exploration witnesses timeout empty-txset replacement",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = true;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::AlwaysDownloading;
    options.mDownloadTimeMode =
        ScpDporDefaultScenario::DownloadTimeMode::AboveThreshold;
    ScpDporDefaultScenario scenario(std::move(options));
    bool foundReplacement = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 12;
    config.communication_model = dpor::model::CommunicationModel::FifoP2P;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            for (std::size_t nodeIndex = 0;
                 nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
            {
                auto const inspection = scenario.inspectThreadReplayTrace(
                    nodeIndex, execution.graph.thread_trace(
                                   threadIdForNodeIndex(nodeIndex)));
                if (inspection.mBoundaryEnvelope &&
                    inspection.mBoundaryEnvelope->statement.pledges.type() ==
                        SCP_ST_PREPARE &&
                    isTestEmptyTxSetValue(
                        inspection.mBoundaryEnvelope->statement.pledges
                            .prepare()
                            .ballot.value) &&
                    hasReplayDebugEvent(inspection,
                                        DporScpNode::ReplayDebugEvent::Kind::
                                            UseTxSetDownloadWaitTime))
                {
                    foundReplacement = true;
                    return dpor::algo::TerminalExecutionAction::Stop;
                }
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    auto const result = dpor::algo::verify(config);
    REQUIRE(result.error_executions_explored == 0);
    REQUIRE(foundReplacement);
}

TEST_CASE("scp dpor stop-on-prepare reaches a blocked execution",
          "[scp][dpor][smoke]")
{
    // Pins the depth budget the stop-on-prepare scenario needs to reach a
    // blocked execution. Boundary envelopes are broadcast before a boundary
    // thread stops, which lengthens every execution here, so a depth that is
    // merely enough to reach the boundary is not enough to reach the blocking
    // receive beyond it. Without this test a too-shallow depth silently
    // explores only depth-limited executions and finds nothing.
    auto makeScenarioOptions = []() {
        auto options = ScpDporDefaultScenario::makeDefaultOptions();
        options.mStopOnPrepare = true;
        options.mTxSetStatusMode =
            ScpDporDefaultScenario::TxSetStatusMode::AlwaysDownloading;
        options.mDownloadTimeMode =
            ScpDporDefaultScenario::DownloadTimeMode::AboveThreshold;
        return options;
    };

    // At depth 12 every execution is cut off by the depth limit before it can
    // block, so a blocked-execution check there is vacuous.
    {
        ScpDporDefaultScenario scenario(makeScenarioOptions());
        dpor::algo::DporConfigT<ScpDporValue> config;
        config.program = scenario.makeProgram();
        config.max_depth = 12;
        auto const result = dpor::algo::verify(config);
        REQUIRE(result.blocked_executions_explored == 0);
        REQUIRE(result.depth_limit_executions_explored > 0);
        REQUIRE(result.error_executions_explored == 0);
    }

    // Depth 18 is the smallest budget that actually reaches a blocked
    // execution, and it is what any blocked-execution workflow must use.
    {
        ScpDporDefaultScenario scenario(makeScenarioOptions());
        dpor::algo::DporConfigT<ScpDporValue> config;
        config.program = scenario.makeProgram();
        config.max_depth = 18;
        auto const result = dpor::algo::verify(config);
        REQUIRE(result.blocked_executions_explored > 0);
        REQUIRE(result.error_executions_explored == 0);
    }
}

TEST_CASE("scp dpor exploration witnesses outright-invalid proposer rejection",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mInitialValues = ScpDporDefaultScenario::makeInitialValues(
        ScpDporDefaultScenario::InitialValueMode::Unique,
        options.mValidators.size());
    options.mOutrightInvalidValuesByNode.resize(options.mValidators.size());
    options.mOutrightInvalidValuesByNode.at(1).push_back(
        options.mInitialValues.at(0));
    options.mOutrightInvalidValuesByNode.at(2).push_back(
        options.mInitialValues.at(0));
    ScpDporDefaultScenario scenario(std::move(options));
    bool foundRejection = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 12;
    config.communication_model = dpor::model::CommunicationModel::FifoP2P;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            for (std::size_t nodeIndex = 1;
                 nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
            {
                auto const inspection = scenario.inspectThreadReplayTrace(
                    nodeIndex, execution.graph.thread_trace(
                                   threadIdForNodeIndex(nodeIndex)));
                if (hasReplayDebugEvent(inspection,
                                        DporScpNode::ReplayDebugEvent::Kind::
                                            RejectOutrightInvalidValue))
                {
                    foundRejection = true;
                    return dpor::algo::TerminalExecutionAction::Stop;
                }
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    auto const result = dpor::algo::verify(config);
    REQUIRE(result.error_executions_explored == 0);
    REQUIRE(foundRejection);
}

TEST_CASE("scp dpor bounded eventually-valid txsets have no error executions",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::DownloadingThenValid;
    options.mDownloadTimeMode =
        ScpDporDefaultScenario::DownloadTimeMode::Nondeterministic;
    ScpDporDefaultScenario scenario(std::move(options));

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program =
        wrapProgramExceptionsAsErrorExecutions(scenario.makeProgram());
    config.max_depth = 12;

    auto const result = dpor::algo::verify(config);
    REQUIRE(result.error_executions_explored == 0);
}

TEST_CASE("scp dpor exploration finds a commit boundary", "[scp][dpor][smoke]")
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

TEST_CASE("scp dpor node queues its first boundary envelope for broadcast",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mBoundaryMode = DporScpNode::BoundaryMode::Externalize;

    auto const& validator = options.mValidators.at(0);
    DporScpNode node(validator, options.mQuorumSet, config);
    SCPBallot ballot{1, options.mInitialValues.at(0)};
    auto const envelope = makeTestExternalizeEnvelope(
        validator.getPublicKey(),
        sha256(xdr::xdr_to_opaque(options.mQuorumSet)), options.mSlotIndex,
        ballot);

    node.emitEnvelope(envelope);

    REQUIRE(node.hasReachedBoundary());
    REQUIRE(node.getBoundaryEnvelope() != nullptr);
    REQUIRE(*node.getBoundaryEnvelope() == envelope);
    auto const pending = node.takePendingEnvelopes();
    REQUIRE(pending.size() == 1);
    REQUIRE(pending.front() == envelope);

    node.emitEnvelope(envelope);
    REQUIRE(node.takePendingEnvelopes().empty());
}

TEST_CASE("scp dpor replay trace captures emitted envelopes",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = true;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::DownloadingThenValid;
    ScpDporDefaultScenario scenario(std::move(options));
    bool sawEmittedEnvelope = false;
    bool sawBoundaryPrepare = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 12;
    config.on_terminal_execution = [&](dpor::algo::TerminalExecutionT<
                                       ScpDporValue> const& execution) {
        bool executionSawEmittedEnvelope = false;
        bool executionSawBoundaryPrepare = false;
        for (std::size_t nodeIndex = 0;
             nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
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
    options.mStopOnPrepare = true;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::DownloadingThenValid;
    ScpDporDefaultScenario scenario(std::move(options));
    std::size_t maximalExecutionsChecked = 0;
    bool foundMissingExternalize = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 20;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            if (!isMaximalExecution(execution))
            {
                return dpor::algo::TerminalExecutionAction::Continue;
            }

            ++maximalExecutionsChecked;
            for (std::size_t nodeIndex = 0;
                 nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
            {
                auto const trace = execution.graph.thread_trace(
                    threadIdForNodeIndex(nodeIndex));
                auto const inspection =
                    scenario.inspectEmittedEnvelopes(nodeIndex, trace);
                // Require some emitted envelopes so an inspection regression
                // that drops all envelopes cannot masquerade as a genuine
                // missing externalize.
                if (!inspection.mEmittedEnvelopes.empty() &&
                    !hasExternalizeEnvelope(inspection.mEmittedEnvelopes))
                {
                    foundMissingExternalize = true;
                    return dpor::algo::TerminalExecutionAction::Stop;
                }
            }

            return dpor::algo::TerminalExecutionAction::Continue;
        };

    static_cast<void>(dpor::algo::verify(config));

    REQUIRE(maximalExecutionsChecked > 0);
    REQUIRE(foundMissingExternalize);
}

TEST_CASE("scp dpor maximal executions keep externalized values in agreement",
          "[scp][dpor][smoke]")
{
    // Externalize needs far more depth than the exploration-sweep tests use,
    // so bound the sweep by stopping once the agreement comparison has
    // genuinely run on an execution where several nodes externalized; the
    // final REQUIRE guards against the check regressing into vacuity.
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mStopOnExternalize = true;
    ScpDporDefaultScenario scenario(std::move(options));
    std::size_t maximalExecutionsChecked = 0;
    bool comparedMultipleExternalizedValues = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 150;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            if (!isMaximalExecution(execution))
            {
                return dpor::algo::TerminalExecutionAction::Continue;
            }

            ++maximalExecutionsChecked;
            auto const externalizedValues =
                collectExternalizedValues(scenario, execution);
            for (auto const& externalizedValue : externalizedValues)
            {
                REQUIRE(externalizedValue == externalizedValues.front());
            }
            if (externalizedValues.size() >= 2)
            {
                comparedMultipleExternalizedValues = true;
                return dpor::algo::TerminalExecutionAction::Stop;
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    static_cast<void>(dpor::algo::verify(config));

    REQUIRE(maximalExecutionsChecked > 0);
    REQUIRE(comparedMultipleExternalizedValues);
}

TEST_CASE("scp dpor exploration finds a follower timer firing before delivery",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mEnableNominationTimeouts = true;
    ScpDporDefaultScenario scenario(std::move(options));
    bool foundFollowerTimeout = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = limitThreadSteps(scenario.makeProgram(),
                                      std::vector<std::size_t>{1, 1, 1});
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

TEST_CASE("scp dpor node separates outright invalidity from txset status",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();
    auto const value = makeTestValue("x");
    auto const otherValue = makeTestValue("y");

    for (auto const status :
         {DporScpTxSetStatus::Valid, DporScpTxSetStatus::Downloading})
    {
        DporScpNode::Configuration config;
        config.mTxSetStatus = status;
        config
            .mOutrightInvalidValuesByNode[options.mValidators.at(0)
                                              .getPublicKey()]
            .insert(value);
        DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);

        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kInvalidValue);
    }

    DporScpNode::Configuration nondeterministicConfig;
    nondeterministicConfig.mNondeterministicTxSetStatus = true;
    nondeterministicConfig
        .mOutrightInvalidValuesByNode[options.mValidators.at(0).getPublicKey()]
        .insert(value);
    DporScpNode nondeterministicNode(
        options.mValidators.at(0), options.mQuorumSet, nondeterministicConfig);
    REQUIRE(nondeterministicNode.validateValue(
                options.mSlotIndex, value, false) == SCPDriver::kInvalidValue);
    REQUIRE_THROWS_AS(nondeterministicNode.validateValue(options.mSlotIndex,
                                                         otherValue, false),
                      DporScpNode::TxSetStatusChoiceRequired);

    auto const emptyValue =
        nondeterministicNode.makeEmptyTxSetValueFromValue(otherValue);
    REQUIRE(nondeterministicNode.validateValue(options.mSlotIndex, emptyValue,
                                               false) ==
            SCPDriver::kFullyValidatedValue);
    REQUIRE(nondeterministicNode.validateValue(options.mSlotIndex, emptyValue,
                                               true) ==
            SCPDriver::kInvalidValue);

    DporScpNode::Configuration malformedEmptyConfig;
    malformedEmptyConfig
        .mOutrightInvalidValuesByNode[options.mValidators.at(0).getPublicKey()]
        .insert(emptyValue);
    DporScpNode malformedEmptyNode(options.mValidators.at(0),
                                   options.mQuorumSet, malformedEmptyConfig);
    REQUIRE(malformedEmptyNode.validateValue(options.mSlotIndex, emptyValue,
                                             false) ==
            SCPDriver::kInvalidValue);
}

TEST_CASE("scp dpor rejects outright-invalid peer values without replacement",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();
    auto const& localKey = options.mValidators.at(0);
    auto const& peerKey = options.mValidators.at(1);
    auto const invalidValue = makeTestValue("invalid");
    auto const validValue = makeTestValue("valid");
    auto const qSetHash = sha256(xdr::xdr_to_opaque(options.mQuorumSet));

    DporScpNode::Configuration config;
    config.mOutrightInvalidValuesByNode[localKey.getPublicKey()].insert(
        invalidValue);

    SECTION("nomination vote")
    {
        SCPQuorumSet nominationQSet;
        nominationQSet.threshold = 2;
        nominationQSet.validators.push_back(localKey.getPublicKey());
        nominationQSet.validators.push_back(peerKey.getPublicKey());
        auto const nominationQSetHash =
            sha256(xdr::xdr_to_opaque(nominationQSet));
        DporScpNode node(localKey, nominationQSet, config);
        node.setReplayDebugRecordingEnabled(true);
        REQUIRE(node.nominate(options.mSlotIndex, validValue,
                              makeTestValue("previous")));
        node.takeReplayDebugEvents();
        auto const emittedBefore = node.getEmittedEnvelopes().size();
        auto envelope =
            makeTestNominateEnvelope(peerKey.getPublicKey(), nominationQSetHash,
                                     options.mSlotIndex, invalidValue);
        envelope.statement.pledges.nominate().accepted.emplace_back(
            invalidValue);

        // Nomination envelopes containing invalid values are themselves sane,
        // but the invalid value must not be adopted or replaced.
        REQUIRE(node.receiveEnvelope(envelope) == SCP::EnvelopeState::VALID);
        REQUIRE(node.getEmittedEnvelopes().size() == emittedBefore);
        auto const debugEvents = node.takeReplayDebugEvents();
        REQUIRE(std::any_of(
            debugEvents.begin(), debugEvents.end(), [](auto const& event) {
                return event.mKind == DporScpNode::ReplayDebugEvent::Kind::
                                          RejectOutrightInvalidValue;
            }));
    }

    SECTION("prepare ballot")
    {
        DporScpNode node(localKey, options.mQuorumSet, config);
        auto const envelope = makeTestPrepareEnvelope(
            peerKey.getPublicKey(), qSetHash, options.mSlotIndex,
            SCPBallot{1, invalidValue});

        REQUIRE(node.receiveEnvelope(envelope) == SCP::EnvelopeState::INVALID);
        REQUIRE(node.getEmittedEnvelopes().empty());
    }

    SECTION("prepared ballot")
    {
        DporScpNode node(localKey, options.mQuorumSet, config);
        auto const envelope = makeTestPrepareEnvelope(
            peerKey.getPublicKey(), qSetHash, options.mSlotIndex,
            SCPBallot{2, validValue}, SCPBallot{1, invalidValue});

        REQUIRE(node.receiveEnvelope(envelope) == SCP::EnvelopeState::INVALID);
        REQUIRE(node.getEmittedEnvelopes().empty());
    }
}

TEST_CASE("scp dpor post-CAP txset replacement distinguishes timeout routes",
          "[scp][dpor][smoke]")
{
    auto const validator = SecretKey::pseudoRandomForTestingFromSeed(2100);
    SCPQuorumSet qSet;
    qSet.threshold = 1;
    qSet.validators.push_back(validator.getPublicKey());
    auto const value = makeTestValue("x");

    DporScpNode::Configuration config;
    config.mTxSetDownloadWaitTimes = {std::chrono::milliseconds(
        DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1)};

    SECTION("downloading below timeout keeps the original value")
    {
        config.mTxSetStatus = DporScpTxSetStatus::Downloading;
        DporScpNode node(validator, qSet, config);
        node.setReplayDebugRecordingEnabled(true);

        REQUIRE(node.startBalloting(0, value));
        REQUIRE(requireBallotValue(node.getEmittedEnvelopes()) == value);
        REQUIRE(countWaitTimeDebugEvents(node.takeReplayDebugEvents()) == 1);
    }

    SECTION("downloading above timeout replaces with an empty value")
    {
        config.mTxSetStatus = DporScpTxSetStatus::Downloading;
        config.mTxSetDownloadWaitTimes = {std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS + 1)};
        DporScpNode node(validator, qSet, config);
        node.setReplayDebugRecordingEnabled(true);

        REQUIRE(node.startBalloting(0, value));
        REQUIRE(requireBallotValue(node.getEmittedEnvelopes()) ==
                node.makeEmptyTxSetValueFromValue(value));
        REQUIRE(countWaitTimeDebugEvents(node.takeReplayDebugEvents()) == 1);
    }
}

TEST_CASE("scp dpor node latches txset wait-time once a value times out",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mTxSetStatus = DporScpTxSetStatus::Downloading;
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
    auto const chosenAboveWaitTime = node.getTxSetDownloadWaitTime(value);
    REQUIRE(chosenAboveWaitTime == aboveTimeout);
    auto const aboveCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);
    auto const latchedAboveWaitTime = node.getTxSetDownloadWaitTime(value);
    REQUIRE(latchedAboveWaitTime == aboveTimeout);

    node.restoreReplayBaseline(aboveCheckpoint);
    auto const restoredAboveWaitTime = node.getTxSetDownloadWaitTime(value);
    REQUIRE(restoredAboveWaitTime == aboveTimeout);
    REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(otherValue),
                      DporScpNode::TxSetDownloadWaitTimeChoiceRequired);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetDownloadWaitTimeChoice(belowTimeout);
    auto const chosenBelowWaitTime = node.getTxSetDownloadWaitTime(value);
    REQUIRE(chosenBelowWaitTime == belowTimeout);
    REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(value),
                      DporScpNode::TxSetDownloadWaitTimeChoiceRequired);
    auto const belowCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);

    node.restoreReplayBaseline(belowCheckpoint);
    REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(value),
                      DporScpNode::TxSetDownloadWaitTimeChoiceRequired);
}

TEST_CASE("scp dpor replay restores pending txset wait-time eligibility",
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

    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);
    auto const waitingLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(waitingLevel == SCPDriver::kStructurallyValidValue);

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
    config.mTxSetStatus = DporScpTxSetStatus::Downloading;
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

    auto const progress = replaySupport.replayObservation(
        node, 0, trace, 0, std::optional<int>{Slot::NOMINATION_TIMER});

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
    auto const chosenValidLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(chosenValidLevel == SCPDriver::kFullyValidatedValue);
    auto const validCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);
    auto const latchedValidLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(latchedValidLevel == SCPDriver::kFullyValidatedValue);

    node.restoreReplayBaseline(validCheckpoint);
    auto const restoredValidLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(restoredValidLevel == SCPDriver::kFullyValidatedValue);
    REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, otherValue, false),
                      DporScpNode::TxSetStatusChoiceRequired);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);
    auto const chosenWaitingLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(chosenWaitingLevel == SCPDriver::kStructurallyValidValue);
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
    config.mSupportedTxSetStatusChoices = {DporScpTxSetStatus::Downloading,
                                           DporScpTxSetStatus::Valid};

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    auto const initialChoices =
        requireTxSetStatusChoices(node, options.mSlotIndex, value);
    REQUIRE(initialChoices == config.mSupportedTxSetStatusChoices);

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);
    auto const waitingLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(waitingLevel == SCPDriver::kStructurallyValidValue);
    auto const waitingCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);
    auto const rebranchedChoices =
        requireTxSetStatusChoices(node, options.mSlotIndex, value);
    REQUIRE(rebranchedChoices == config.mSupportedTxSetStatusChoices);

    node.restoreReplayBaseline(waitingCheckpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Valid);
    auto const resolvedLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(resolvedLevel == SCPDriver::kFullyValidatedValue);
    auto const latchedLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(latchedLevel == SCPDriver::kFullyValidatedValue);
}

TEST_CASE("scp dpor node can force downloading txset status during nomination",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mTxSetStatus = DporScpTxSetStatus::Valid;
    config.mNondeterministicTxSetStatus = true;
    config.mNominationAlwaysDownloadingTxSetStatus = true;
    config.mSupportedTxSetStatusChoices = {DporScpTxSetStatus::Downloading,
                                           DporScpTxSetStatus::Valid};

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    Value value;
    value.push_back('x');

    auto const nominationLevel =
        node.validateValue(options.mSlotIndex, value, true);
    REQUIRE(nominationLevel == SCPDriver::kStructurallyValidValue);
    auto const ballotingChoices =
        requireTxSetStatusChoices(node, options.mSlotIndex, value);
    REQUIRE(ballotingChoices == config.mSupportedTxSetStatusChoices);

    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Valid);
    auto const ballotingLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(ballotingLevel == SCPDriver::kFullyValidatedValue);
    auto const repeatedNominationLevel =
        node.validateValue(options.mSlotIndex, value, true);
    REQUIRE(repeatedNominationLevel == SCPDriver::kStructurallyValidValue);
    auto const latchedBallotingLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(latchedBallotingLevel == SCPDriver::kFullyValidatedValue);
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
    Value otherValue;
    otherValue.push_back('y');

    REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, value, false),
                      DporScpNode::TxSetStatusChoiceRequired);

    SCPEnvelope prepareEnvelope;
    prepareEnvelope.statement.slotIndex = options.mSlotIndex;
    prepareEnvelope.statement.nodeID = options.mValidators.at(0).getPublicKey();
    prepareEnvelope.statement.pledges.type(SCP_ST_PREPARE);
    prepareEnvelope.statement.pledges.prepare().ballot.counter = 1;
    prepareEnvelope.statement.pledges.prepare().ballot.value = value;
    node.emitEnvelope(prepareEnvelope);

    auto const downloadedLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(downloadedLevel == SCPDriver::kFullyValidatedValue);
    REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, otherValue, false),
                      DporScpNode::TxSetStatusChoiceRequired);

    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);
    auto const otherValueLevel =
        node.validateValue(options.mSlotIndex, otherValue, false);
    REQUIRE(otherValueLevel == SCPDriver::kStructurallyValidValue);
    REQUIRE(node.getTxSetDownloadWaitTime(otherValue).has_value());

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);
    node.restoreReplayBaseline(checkpoint);
    auto const restoredLevel =
        node.validateValue(options.mSlotIndex, value, false);
    REQUIRE(restoredLevel == SCPDriver::kFullyValidatedValue);
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
    node.setupTimer(
        0, Slot::NOMINATION_TIMER, std::chrono::milliseconds(10),
        [&node, &seenStatuses, initialValue]() {
            seenStatuses.push_back(node.validateValue(0, initialValue, false));
            seenStatuses.push_back(node.validateValue(0, initialValue, false));
        });

    ThreadTrace trace;
    trace.emplace_back(ObservedValue::bottom());
    trace.emplace_back(
        makeTxSetStatusChoiceValue(0, DporScpTxSetStatus::Valid));
    trace.emplace_back(ObservedValue::bottom());

    auto const progress = replaySupport.replayObservation(
        node, 0, trace, 0, std::optional<int>{Slot::NOMINATION_TIMER});

    REQUIRE(progress.mConsumedTraceEntries == 2);
    REQUIRE(progress.mConsumedStepCount == 1);
    REQUIRE_FALSE(progress.mPendingEvent.has_value());
    REQUIRE(progress.mObservedBottom);

    std::vector<SCPDriver::ValidationLevel> const expectedStatuses{
        SCPDriver::kFullyValidatedValue, SCPDriver::kFullyValidatedValue};
    REQUIRE(seenStatuses == expectedStatuses);
}

} // namespace stellar::scpdpor
