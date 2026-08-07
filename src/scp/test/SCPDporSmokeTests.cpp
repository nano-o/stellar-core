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

struct ExplorationOutcome
{
    dpor::algo::VerifyResult mResult;
    bool mFound{};
};

struct SingleNodeReplayHarness
{
    static SCPQuorumSet
    makeQuorumSet(SecretKey const& validator)
    {
        SCPQuorumSet qSet;
        qSet.threshold = 1;
        qSet.validators.push_back(validator.getPublicKey());
        return qSet;
    }

    SecretKey mValidator;
    SCPQuorumSet mQSet;
    Value mPreviousValue{makeTestValue("p")};
    Value mInitialValue{makeTestValue("x")};
    ScpDporReplaySupport mReplaySupport;
    DporScpNode mNode;

    SingleNodeReplayHarness(
        uint64_t seed, DporScpNode::Configuration const& nodeConfig,
        std::optional<DporScpNode::Configuration> replayConfig = std::nullopt)
        : mValidator(SecretKey::pseudoRandomForTestingFromSeed(seed))
        , mQSet(makeQuorumSet(mValidator))
        , mReplaySupport(std::vector<SecretKey>{mValidator}, mQSet, 0,
                         mPreviousValue, std::vector<Value>{mInitialValue},
                         replayConfig ? *replayConfig : nodeConfig)
        , mNode(mValidator, mQSet, nodeConfig)
    {
    }
};

template <typename Predicate>
ExplorationOutcome
explorationFinds(ScpDporDefaultScenario const& scenario, std::size_t maxDepth,
                 Predicate predicate,
                 dpor::model::CommunicationModel communicationModel =
                     dpor::model::CommunicationModel::Async)
{
    ExplorationOutcome outcome;
    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = maxDepth;
    config.communication_model = communicationModel;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            outcome.mFound = predicate(execution);
            return outcome.mFound
                       ? dpor::algo::TerminalExecutionAction::Stop
                       : dpor::algo::TerminalExecutionAction::Continue;
        };
    outcome.mResult = dpor::algo::verify(config);
    return outcome;
}

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

TEST_CASE("scp dpor replay cache capacity is configurable",
          "[scp][dpor][smoke]")
{
    REQUIRE_THROWS_AS(
        ScpDporDefaultScenario(ScpDporDefaultScenario::makeDefaultOptions(), 0),
        std::invalid_argument);

    ScpDporDefaultScenario scenario(
        ScpDporDefaultScenario::makeDefaultOptions(), 1);
    auto program = scenario.makeProgram();
    REQUIRE(program.threads.at(threadIdForNodeIndex(0))({}, 0).has_value());
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

TEST_CASE("scp dpor trace json rejects unsupported bundle versions",
          "[scp][dpor][smoke]")
{
    for (auto const version : {1, 2, 3, 4, 5, 6, 7, 9})
    {
        Json::Value root(Json::objectValue);
        root["version"] = version;
        REQUIRE_THROWS_WITH(
            traceBundleFromJson(root),
            Catch::Contains("unsupported trace bundle version " +
                            std::to_string(version) + " (supported: 8)"));
    }
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
    REQUIRE(errorExecution->mMessage.find("BallotProtocol.cpp") !=
            std::string::npos);
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
                             .mFocusNodeIndex = errorExecution->mNodeIndex});
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
    REQUIRE(loaded.mTerminal.mFailureMessage);
    REQUIRE(loaded.mTerminal.mFailureMessage->find(expectedError) !=
            std::string::npos);
    REQUIRE(loaded.mThreadTraces.size() == bundle->mThreadTraces.size());
    for (std::size_t i = 0; i < bundle->mThreadTraces.size(); ++i)
    {
        REQUIRE(loaded.mThreadTraces.at(i) == bundle->mThreadTraces.at(i));
    }

    ScpDporDefaultScenario loadedScenario(loaded.mOptions);
    auto const inspection = loadedScenario.inspectThreadReplayTrace(
        loaded.mTerminal.mFocusNodeIndex,
        loaded.mThreadTraces.at(loaded.mTerminal.mFocusNodeIndex));

    REQUIRE(!inspection.mSteps.empty());
    REQUIRE(hasTxSetStatusObservation(inspection, loaded.mOptions.mSlotIndex,
                                      DporScpTxSetStatus::Downloading));
    REQUIRE(inspection.mReplayErrorMessage.has_value());
    REQUIRE(inspection.mReplayErrorMessage->find(expectedError) !=
            std::string::npos);
}

TEST_CASE("scp dpor exploration finds a prepare boundary", "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = true;
    options.mTxSetStatusMode =
        ScpDporDefaultScenario::TxSetStatusMode::DownloadingThenValid;
    ScpDporDefaultScenario scenario(std::move(options));
    // Reaching the boundary also fans the boundary envelope out to both peers.
    auto const outcome = explorationFinds(
        scenario, 14,
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const leaderTrace =
                execution.graph.thread_trace(threadIdForNodeIndex(0));
            auto inspection = scenario.inspectPrepareBoundary(0, leaderTrace);
            return inspection.mReachedBoundary &&
                   inspection.mBoundaryEnvelope &&
                   inspection.mBoundaryEnvelope->statement.pledges.type() ==
                       SCP_ST_PREPARE &&
                   inspection.mBoundaryEnvelope->statement.pledges.prepare()
                           .ballot.counter >= 1;
        });
    REQUIRE(outcome.mFound);
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
    auto const outcome = explorationFinds(
        scenario, 12,
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
                    DporScpNode::hasEmptyTxSetValuePrefix(
                        inspection.mBoundaryEnvelope->statement.pledges
                            .prepare()
                            .ballot.value) &&
                    hasReplayDebugEvent(inspection,
                                        DporScpNode::ReplayDebugEvent::Kind::
                                            UseTxSetDownloadWaitTime))
                {
                    return true;
                }
            }
            return false;
        },
        dpor::model::CommunicationModel::FifoP2P);
    REQUIRE(outcome.mResult.error_executions_explored == 0);
    REQUIRE(outcome.mFound);
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

TEST_CASE("scp dpor thread-event depth bounds each validator independently",
          "[scp][dpor][smoke]")
{
    // The per-thread event bound is what --depth cannot express: --depth is a
    // single search-tree budget shared by every node, so a scenario that needs
    // deep interleavings of shallow node histories can only be reached by
    // raising --depth until the tree explodes. Pins that the bound bites, that
    // it displaces depth-limit truncation entirely, and that the reported
    // maximum equals the bound.
    ScpDporDefaultScenario scenario(
        ScpDporDefaultScenario::makeDefaultOptions());

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 1000;
    config.max_thread_events = 3;

    std::size_t observedTerminals = 0;
    std::size_t maximalExecutionsSeen = 0;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            ++observedTerminals;
            if (isMaximalExecution(execution))
            {
                ++maximalExecutionsSeen;
            }
            for (std::size_t nodeIndex = 0;
                 nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
            {
                REQUIRE(execution.graph.thread_event_count(
                            threadIdForNodeIndex(nodeIndex)) <= 3);
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.error_executions_explored == 0);
    REQUIRE(result.depth_limit_executions_explored == 0);
    REQUIRE(result.thread_event_limit_executions_explored > 0);
    REQUIRE(result.max_thread_event_depth_reached == 3);
    // Exact fingerprint: a change here means the bounded exploration changed.
    REQUIRE(result.executions_explored == 6);
    REQUIRE(result.thread_event_limit_executions_explored == 6);
    REQUIRE(observedTerminals == result.executions_explored);
    // A truncated execution is not maximal, so property checks skip it. This
    // is the regression guard for --must-externalize / --check-agreement.
    REQUIRE(maximalExecutionsSeen == 0);
}

TEST_CASE(
    "scp dpor reports the per-thread event depth an unbounded run reaches",
    "[scp][dpor][smoke]")
{
    // Pins the stat itself, independently of any bound: recompute it from the
    // published graphs and require the engine's value to agree. This is what
    // tells an engineer which --thread-event-depth would actually be enough.
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = true;
    ScpDporDefaultScenario scenario(std::move(options));

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 30;

    std::size_t observedMaxThreadEventDepth = 0;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            for (std::size_t nodeIndex = 0;
                 nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
            {
                observedMaxThreadEventDepth =
                    std::max(observedMaxThreadEventDepth,
                             execution.graph.thread_event_count(
                                 threadIdForNodeIndex(nodeIndex)));
            }
            return dpor::algo::TerminalExecutionAction::Continue;
        };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.thread_event_limit_executions_explored == 0);
    REQUIRE(result.max_thread_event_depth_reached ==
            observedMaxThreadEventDepth);
    REQUIRE(result.max_thread_event_depth_reached == 8);
}

TEST_CASE("scp dpor trace json round-trips a thread-event-limit terminal",
          "[scp][dpor][smoke]")
{
    // Check both directions of the serialized terminal-kind mapping in a
    // complete v8 bundle.
    auto scenarioOptions = ScpDporDefaultScenario::makeDefaultOptions();
    scenarioOptions.mStopOnPrepare = true;
    ScpDporDefaultScenario scenario(std::move(scenarioOptions));

    std::optional<TraceBundle> bundle;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    config.max_depth = 1000;
    config.max_thread_events = 3;
    config.on_terminal_execution =
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            if (!execution.is_thread_event_limit_execution())
            {
                return dpor::algo::TerminalExecutionAction::Continue;
            }
            bundle =
                makeTraceBundle(scenario, execution, config.communication_model,
                                TerminalMeta{.mKind = execution.kind,
                                             .mFailureMessage = std::nullopt,
                                             .mFocusNodeIndex = 0});
            return dpor::algo::TerminalExecutionAction::Stop;
        };

    static_cast<void>(dpor::algo::verify(config));
    REQUIRE(bundle.has_value());
    REQUIRE(bundle->mVersion == TRACE_BUNDLE_VERSION);
    REQUIRE(bundle->mTerminal.mKind ==
            dpor::algo::TerminalExecutionKind::ThreadEventLimit);

    auto const json = toJson(*bundle);
    REQUIRE(json["version"].asUInt64() ==
            static_cast<uint64_t>(TRACE_BUNDLE_VERSION));
    REQUIRE(json["terminal"]["kind"].asString() == "thread-event-limit");
    REQUIRE_FALSE(json["terminal"].isMember("focus_thread_id"));
    REQUIRE(json["thread_traces"].isArray());
    REQUIRE(json["thread_traces"][0].isArray());

    auto const reloaded = traceBundleFromJson(json);
    REQUIRE(reloaded.mVersion == TRACE_BUNDLE_VERSION);
    REQUIRE(reloaded.mTerminal.mKind == bundle->mTerminal.mKind);
    REQUIRE(reloaded.mThreadTraces.size() == bundle->mThreadTraces.size());

    ScpDporDefaultScenario reloadedScenario(reloaded.mOptions);
    auto const inspection = reloadedScenario.inspectThreadReplayTrace(
        reloaded.mTerminal.mFocusNodeIndex,
        reloaded.mThreadTraces.at(reloaded.mTerminal.mFocusNodeIndex));
    REQUIRE(!inspection.mSteps.empty());
    REQUIRE(!inspection.mReplayErrorMessage.has_value());

    auto withoutCommunicationModel = json;
    withoutCommunicationModel.removeMember("communication_model");
    REQUIRE(
        traceBundleFromJson(withoutCommunicationModel).mCommunicationModel ==
        dpor::model::CommunicationModel::Async);
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
    auto const outcome = explorationFinds(
        scenario, 12,
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
                    return true;
                }
            }
            return false;
        },
        dpor::model::CommunicationModel::FifoP2P);
    REQUIRE(outcome.mResult.error_executions_explored == 0);
    REQUIRE(outcome.mFound);
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
    auto const outcome = explorationFinds(
        scenario, 60,
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const leaderTrace =
                execution.graph.thread_trace(threadIdForNodeIndex(0));
            auto inspection = scenario.inspectBoundary(0, leaderTrace);
            if (inspection.mReachedBoundary && inspection.mBoundaryEnvelope)
            {
                auto const type =
                    inspection.mBoundaryEnvelope->statement.pledges.type();
                return type == SCP_ST_CONFIRM || type == SCP_ST_EXTERNALIZE;
            }
            return false;
        });
    REQUIRE(outcome.mFound);
}

TEST_CASE("scp dpor exploration finds an externalize boundary",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mStopOnPrepare = false;
    options.mStopOnExternalize = true;
    ScpDporDefaultScenario scenario(std::move(options));
    auto const outcome = explorationFinds(
        scenario, 60,
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            auto const leaderTrace =
                execution.graph.thread_trace(threadIdForNodeIndex(0));
            auto inspection = scenario.inspectBoundary(0, leaderTrace);
            return inspection.mReachedBoundary &&
                   inspection.mBoundaryEnvelope &&
                   inspection.mBoundaryEnvelope->statement.pledges.type() ==
                       SCP_ST_EXTERNALIZE;
        });
    REQUIRE(outcome.mFound);
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
    auto const outcome = explorationFinds(
        scenario, 20,
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            if (!isMaximalExecution(execution))
            {
                return false;
            }

            ++maximalExecutionsChecked;
            auto const check = findNodeMissingExternalize(scenario, execution);
            if (check.mMissingNodeIndex)
            {
                // Require some emitted envelopes so an inspection regression
                // that drops all envelopes cannot masquerade as a genuine
                // missing externalize.
                REQUIRE(check.mEmittedEnvelopeCount > 0);
                return true;
            }
            return false;
        });

    REQUIRE(maximalExecutionsChecked > 0);
    REQUIRE(outcome.mFound);
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
    auto const outcome = explorationFinds(
        scenario, 150,
        [&](dpor::algo::TerminalExecutionT<ScpDporValue> const& execution) {
            if (!isMaximalExecution(execution))
            {
                return false;
            }

            ++maximalExecutionsChecked;
            auto const check = findAgreementFailure(scenario, execution);
            REQUIRE_FALSE(check.mFailure.has_value());
            return check.mExternalizedValueCount >= 2;
        });

    REQUIRE(maximalExecutionsChecked > 0);
    REQUIRE(outcome.mFound);
}

TEST_CASE("scp dpor exploration finds a follower timer firing before delivery",
          "[scp][dpor][smoke]")
{
    auto options = ScpDporDefaultScenario::makeDefaultOptions();
    options.mEnableNominationTimeouts = true;
    ScpDporDefaultScenario scenario(std::move(options));
    bool foundFollowerTimeout = false;

    dpor::algo::DporConfigT<ScpDporValue> config;
    config.program = scenario.makeProgram();
    for (std::size_t nodeIndex = 0;
         nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
    {
        auto const threadID = threadIdForNodeIndex(nodeIndex);
        auto const threadFn = config.program.threads.at(threadID);
        config.program.threads[threadID] =
            [threadFn](ThreadTrace const& trace,
                       std::size_t step) -> std::optional<EventLabel> {
            return step == 0 ? threadFn(trace, step) : std::nullopt;
        };
    }
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
    auto const value = makeTestValue("x");
    auto const otherValue = makeTestValue("y");

    auto const belowTimeout = config.mTxSetDownloadWaitTimes.at(0);
    auto const aboveTimeout = config.mTxSetDownloadWaitTimes.at(1);

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(value),
                          DporScpNode::TxSetDownloadWaitTimeChoiceRequired);
    }

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetDownloadWaitTimeChoice(aboveTimeout);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.getTxSetDownloadWaitTime(value) == aboveTimeout);
        // Same event: pinned rather than re-chosen.
        REQUIRE(node.getTxSetDownloadWaitTime(value) == aboveTimeout);
    }
    auto const aboveCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);
    {
        // Next event: still above the timeout, because that latch is
        // cross-event.
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.getTxSetDownloadWaitTime(value) == aboveTimeout);
    }

    node.restoreReplayBaseline(aboveCheckpoint);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.getTxSetDownloadWaitTime(value) == aboveTimeout);
        REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(otherValue),
                          DporScpNode::TxSetDownloadWaitTimeChoiceRequired);
    }

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetDownloadWaitTimeChoice(belowTimeout);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.getTxSetDownloadWaitTime(value) == belowTimeout);
        // Same event: pinned, so no second branch.
        REQUIRE(node.getTxSetDownloadWaitTime(value) == belowTimeout);
    }
    {
        // Next event: a below-timeout wait is not latched, so it branches.
        DporScpNode::ExternalEventScope event(node);
        REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(value),
                          DporScpNode::TxSetDownloadWaitTimeChoiceRequired);
    }
    auto const belowCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);

    node.restoreReplayBaseline(belowCheckpoint);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE_THROWS_AS(node.getTxSetDownloadWaitTime(value),
                          DporScpNode::TxSetDownloadWaitTimeChoiceRequired);
    }
}

TEST_CASE("scp dpor replay restores txset wait-time eligibility",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;
    config.mTxSetDownloadWaitTimes = {std::chrono::milliseconds(
        DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1)};

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    auto const value = makeTestValue("x");

    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kStructurallyValidValue);
    }

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);
    node.restoreReplayBaseline(checkpoint);

    DporScpNode::ExternalEventScope event(node);
    auto const waitTime = node.getTxSetDownloadWaitTime(value);
    REQUIRE(waitTime.has_value());
    REQUIRE(*waitTime == config.mTxSetDownloadWaitTimes.at(0));
}

TEST_CASE("scp dpor pins a txset wait-time answered before validation",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;
    config.mTxSetDownloadWaitTimes = {
        std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1),
        std::chrono::milliseconds(
            DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS + 1)};
    config.mNondeterministicTxSetDownloadWaitTime = true;

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    auto const value = makeTestValue("x");

    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);

    DporScpNode::ExternalEventScope event(node);
    // Nothing has been validated yet, so there is no download in progress to
    // wait on. That answer is memoized even though there is no status behind
    // it.
    REQUIRE_FALSE(node.getTxSetDownloadWaitTime(value).has_value());
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kStructurallyValidValue);
    // Answering differently now -- or opening a wait-time branch -- would be
    // exactly the mid-event flip the per-event decision exists to prevent.
    REQUIRE_FALSE(node.getTxSetDownloadWaitTime(value).has_value());
}

TEST_CASE("scp dpor answers repeated txset wait-time queries consistently",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;
    config.mTxSetDownloadWaitTimes = {std::chrono::milliseconds(
        DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1)};

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    node.setReplayDebugRecordingEnabled(true);
    auto const value = makeTestValue("x");

    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);

    DporScpNode::ExternalEventScope event(node);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kStructurallyValidValue);

    // One verdict, two queries. The removed pairing counter decremented per
    // query, so the second one reported "no download in progress" and drove
    // SCP down the drop-the-tx-set path.
    auto const first = node.getTxSetDownloadWaitTime(value);
    auto const second = node.getTxSetDownloadWaitTime(value);
    REQUIRE(first.has_value());
    REQUIRE(second == first);

    // Memo hits still record what SCP observed, so investigation output is
    // unchanged.
    REQUIRE(countWaitTimeDebugEvents(node.takeReplayDebugEvents()) == 2);
}

TEST_CASE(
    "scp dpor replay reuses a latched txset wait-time once a value times out",
    "[scp][dpor][smoke]")
{
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
    SingleNodeReplayHarness harness(2000, config, replayConfig);
    auto& node = harness.mNode;
    auto const& initialValue = harness.mInitialValue;

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

    auto const progress = harness.mReplaySupport.replayObservation(
        node, 0, trace, 0, std::optional<int>{Slot::NOMINATION_TIMER});

    REQUIRE(progress.mConsumedTraceEntries == 2);
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
    auto const value = makeTestValue("x");
    auto const otherValue = makeTestValue("y");

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, value, false),
                          DporScpNode::TxSetStatusChoiceRequired);
    }

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Valid);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kFullyValidatedValue);
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kFullyValidatedValue);
    }
    auto const validCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kFullyValidatedValue);
    }

    node.restoreReplayBaseline(validCheckpoint);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kFullyValidatedValue);
        // A distinct value is a distinct download, so it still branches.
        REQUIRE_THROWS_AS(
            node.validateValue(options.mSlotIndex, otherValue, false),
            DporScpNode::TxSetStatusChoiceRequired);
    }

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kStructurallyValidValue);
        // Same event: pinned rather than re-branched.
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kStructurallyValidValue);
    }
    auto const waitingCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);
    {
        // Next event: downloading is not latched, so it branches again.
        DporScpNode::ExternalEventScope event(node);
        REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, value, false),
                          DporScpNode::TxSetStatusChoiceRequired);
    }

    node.restoreReplayBaseline(waitingCheckpoint);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, value, false),
                          DporScpNode::TxSetStatusChoiceRequired);
    }
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
    auto const value = makeTestValue("x");

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    {
        DporScpNode::ExternalEventScope event(node);
        auto const initialChoices =
            requireTxSetStatusChoices(node, options.mSlotIndex, value);
        REQUIRE(initialChoices == config.mSupportedTxSetStatusChoices);
    }

    node.restoreReplayBaseline(checkpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kStructurallyValidValue);
    }
    auto const waitingCheckpoint =
        node.snapshotReplayBaseline(options.mSlotIndex);
    {
        DporScpNode::ExternalEventScope event(node);
        auto const rebranchedChoices =
            requireTxSetStatusChoices(node, options.mSlotIndex, value);
        REQUIRE(rebranchedChoices == config.mSupportedTxSetStatusChoices);
    }

    node.restoreReplayBaseline(waitingCheckpoint);
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Valid);
    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kFullyValidatedValue);
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kFullyValidatedValue);
    }
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
    auto const value = makeTestValue("x");

    // Everything below happens inside one event. The forcing knob is exempt
    // from the per-event decision on purpose, so nomination can answer
    // downloading while balloting answers valid for the same value in the same
    // event. Memoizing the override would stop balloting from ever branching
    // after a nomination validation, which is what this flag exists to
    // explore. Recorded as a known wart in docs/dpor-integration-status.md.
    DporScpNode::ExternalEventScope event(node);

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
    auto const value = makeTestValue("x");
    auto const otherValue = makeTestValue("y");

    auto const prepareEnvelope =
        makeTestPrepareEnvelope(options.mValidators.at(0).getPublicKey(),
                                sha256(xdr::xdr_to_opaque(options.mQuorumSet)),
                                options.mSlotIndex, SCPBallot{1, value});

    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, value, false),
                          DporScpNode::TxSetStatusChoiceRequired);
        node.emitEnvelope(prepareEnvelope);
        // The download completes mid-event, so it stays unobservable until the
        // next event opens.
        REQUIRE_THROWS_AS(node.validateValue(options.mSlotIndex, value, false),
                          DporScpNode::TxSetStatusChoiceRequired);
    }

    {
        DporScpNode::ExternalEventScope event(node);
        auto const downloadedLevel =
            node.validateValue(options.mSlotIndex, value, false);
        REQUIRE(downloadedLevel == SCPDriver::kFullyValidatedValue);
        REQUIRE_THROWS_AS(
            node.validateValue(options.mSlotIndex, otherValue, false),
            DporScpNode::TxSetStatusChoiceRequired);

        node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);
        auto const otherValueLevel =
            node.validateValue(options.mSlotIndex, otherValue, false);
        REQUIRE(otherValueLevel == SCPDriver::kStructurallyValidValue);
        REQUIRE(node.getTxSetDownloadWaitTime(otherValue).has_value());
    }

    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);
    node.restoreReplayBaseline(checkpoint);
    {
        DporScpNode::ExternalEventScope event(node);
        auto const restoredLevel =
            node.validateValue(options.mSlotIndex, value, false);
        REQUIRE(restoredLevel == SCPDriver::kFullyValidatedValue);
    }
}

TEST_CASE("scp dpor defers txset download success to the next event",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;
    config.mDownloadSucceedsInBallotRound = 1;

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    auto const value = makeTestValue("x");

    auto const prepareEnvelope =
        makeTestPrepareEnvelope(options.mValidators.at(0).getPublicKey(),
                                sha256(xdr::xdr_to_opaque(options.mQuorumSet)),
                                options.mSlotIndex, SCPBallot{1, value});

    {
        DporScpNode::ExternalEventScope event(node);
        node.emitEnvelope(prepareEnvelope);
    }

    // Snapshotting between the emitting event and the next one is the only
    // window in which the promotion lives solely in the pending set, so this
    // is what pins it to the replay baseline.
    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);
    node.restoreReplayBaseline(checkpoint);

    {
        DporScpNode::ExternalEventScope event(node);
        REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
                SCPDriver::kFullyValidatedValue);
    }
}

TEST_CASE("scp dpor rejects replay snapshots taken inside an external event",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet);
    auto const checkpoint = node.snapshotReplayBaseline(options.mSlotIndex);

    DporScpNode::ExternalEventScope event(node);
    REQUIRE_THROWS_AS(node.snapshotReplayBaseline(options.mSlotIndex),
                      std::logic_error);
    REQUIRE_THROWS_AS(node.restoreReplayBaseline(checkpoint), std::logic_error);
}

TEST_CASE("scp dpor rejects replay snapshots after an implicit txset decision",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();

    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;

    DporScpNode node(options.mValidators.at(0), options.mQuorumSet, config);
    auto const value = makeTestValue("x");

    // No scope is open, so this call sits in the implicit event at depth 0.
    // The event-depth check cannot see it; only the decision map can.
    node.enqueueTxSetStatusChoice(DporScpTxSetStatus::Downloading);
    REQUIRE(node.validateValue(options.mSlotIndex, value, false) ==
            SCPDriver::kStructurallyValidValue);

    REQUIRE_THROWS_AS(node.snapshotReplayBaseline(options.mSlotIndex),
                      std::logic_error);

    // Opening and closing a real event resets the implicit one.
    {
        DporScpNode::ExternalEventScope event(node);
    }
    REQUIRE_NOTHROW(node.snapshotReplayBaseline(options.mSlotIndex));
}

TEST_CASE("scp dpor asks for one txset status choice per value per event",
          "[scp][dpor][smoke]")
{
    auto const options = ScpDporDefaultScenario::makeDefaultOptions();
    auto const& localKey = options.mValidators.at(0);
    auto const& peerKey = options.mValidators.at(1);
    auto const value = makeTestValue("x");
    auto const previousValue = makeTestValue("previous");

    SCPQuorumSet qSet;
    qSet.threshold = 1;
    qSet.validators.push_back(localKey.getPublicKey());
    qSet.validators.push_back(peerKey.getPublicKey());

    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;
    // Below the download timeout, so maybeReplaceValueWithEmptyTxSet keeps the
    // value instead of dropping the tx set. Keeping it is what lets the ballot
    // protocol validate the same value again later in this one event.
    config.mTxSetDownloadWaitTimes = {std::chrono::milliseconds(
        DporScpNode::DEFAULT_TX_SET_DOWNLOAD_TIMEOUT_MS - 1)};

    // Nominating with a threshold-1 quorum set drives the node straight into
    // balloting, so this single event runs nomination validation and then
    // several ballot-protocol validations of the same value.
    //
    // Mirror what replay does with a required choice: it unwinds the handler,
    // and the event is re-run from scratch with the accumulated answers
    // preloaded. Each round therefore consumes exactly one more choice, so the
    // round count is the number of choices this one event asks for. Answering
    // `downloading` every time is what makes the count meaningful -- `valid`
    // would latch across events and hide a repeat behind the cross-event
    // latch.
    std::vector<DporScpTxSetStatus> answers;
    std::size_t rounds = 0;
    while (true)
    {
        DporScpNode node(localKey, qSet, config);
        for (auto const answer : answers)
        {
            node.enqueueTxSetStatusChoice(answer);
        }
        try
        {
            // Deliberately not inside REQUIRE: Catch would absorb the choice
            // exception and report it as an unexpected failure.
            auto const nominated =
                node.nominate(options.mSlotIndex, value, previousValue);
            REQUIRE(nominated);
            break;
        }
        catch (DporScpNode::TxSetStatusChoiceRequired const&)
        {
            answers.push_back(DporScpTxSetStatus::Downloading);
            ++rounds;
            REQUIRE(rounds < 8);
        }
    }

    // Measured at 7 with the per-event decision bypassed: nomination
    // validation branched, and then the ballot protocol branched again on the
    // same value, six more times, inside this one handler.
    REQUIRE(rounds == 1);
}

TEST_CASE("scp dpor replay rejects a txset choice the event never requests",
          "[scp][dpor][smoke]")
{
    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;
    SingleNodeReplayHarness harness(2002, config);
    auto& node = harness.mNode;
    auto const& initialValue = harness.mInitialValue;

    node.setupTimer(
        0, Slot::NOMINATION_TIMER, std::chrono::milliseconds(10),
        [&node, initialValue]() {
            static_cast<void>(node.validateValue(0, initialValue, false));
            static_cast<void>(node.validateValue(0, initialValue, false));
        });

    // A structurally valid, current-version trace can still be stale: this one
    // records a choice per driver call, and the second one is never requested.
    // The version check cannot catch that, so replay has to.
    ThreadTrace trace;
    trace.emplace_back(ObservedValue::bottom());
    trace.emplace_back(
        makeTxSetStatusChoiceValue(0, DporScpTxSetStatus::Downloading));
    trace.emplace_back(
        makeTxSetStatusChoiceValue(0, DporScpTxSetStatus::Downloading));
    trace.emplace_back(ObservedValue::bottom());

    REQUIRE_THROWS_WITH(
        harness.mReplaySupport.replayObservation(
            node, 0, trace, 0, std::optional<int>{Slot::NOMINATION_TIMER}),
        Catch::Contains("does not request"));
}

TEST_CASE(
    "scp dpor replay reuses a latched txset status once a value is resolved",
    "[scp][dpor][smoke]")
{
    DporScpNode::Configuration config;
    config.mNondeterministicTxSetStatus = true;
    SingleNodeReplayHarness harness(2001, config);
    auto& node = harness.mNode;
    auto const& initialValue = harness.mInitialValue;

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

    auto const progress = harness.mReplaySupport.replayObservation(
        node, 0, trace, 0, std::optional<int>{Slot::NOMINATION_TIMER});

    REQUIRE(progress.mConsumedTraceEntries == 2);
    REQUIRE_FALSE(progress.mPendingEvent.has_value());
    REQUIRE(progress.mObservedBottom);

    std::vector<SCPDriver::ValidationLevel> const expectedStatuses{
        SCPDriver::kFullyValidatedValue, SCPDriver::kFullyValidatedValue};
    REQUIRE(seenStatuses == expectedStatuses);
}

} // namespace stellar::scpdpor
