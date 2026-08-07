// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/ScpDporTraceJson.h"

#include "crypto/KeyUtils.h"
#include "lib/json/json.h"
#include "scp/LocalNode.h"
#include "scp/test/ScpDporBridge.h"
#include "util/Decoder.h"

#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <xdrpp/marshal.h>

namespace stellar::scpdpor
{

namespace
{

template <typename T>
std::string
formatWithStream(T const& value)
{
    std::ostringstream out;
    out << value;
    return out.str();
}

Json::Value const&
requireObject(Json::Value const& value, std::string const& context)
{
    if (!value.isObject())
    {
        throw std::invalid_argument(context + " must be a JSON object");
    }
    return value;
}

Json::Value const&
requireArray(Json::Value const& value, std::string const& context)
{
    if (!value.isArray())
    {
        throw std::invalid_argument(context + " must be a JSON array");
    }
    return value;
}

Json::Value const&
requireMember(Json::Value const& object, char const* name,
              std::string const& context)
{
    requireObject(object, context);
    if (!object.isMember(name))
    {
        throw std::invalid_argument(context + " is missing field '" + name +
                                    "'");
    }
    return object[name];
}

std::string
requireString(Json::Value const& value, std::string const& context)
{
    if (!value.isString())
    {
        throw std::invalid_argument(context + " must be a string");
    }
    return value.asString();
}

bool
requireBool(Json::Value const& value, std::string const& context)
{
    if (!value.isBool())
    {
        throw std::invalid_argument(context + " must be a bool");
    }
    return value.asBool();
}

uint64_t requireUint64(Json::Value const& value, std::string const& context);

uint32_t
requireUint32(Json::Value const& value, std::string const& context)
{
    auto const parsed = requireUint64(value, context);
    if (parsed > std::numeric_limits<uint32_t>::max())
    {
        throw std::invalid_argument(context + " is out of uint32 range");
    }
    return static_cast<uint32_t>(parsed);
}

uint64_t
requireUint64(Json::Value const& value, std::string const& context)
{
    if (!value.isIntegral())
    {
        throw std::invalid_argument(context + " must be an unsigned integer");
    }
    if ((value.isInt() || value.isInt64()) && value.asInt64() < 0)
    {
        throw std::invalid_argument(context +
                                    " must be a non-negative integer");
    }
    return value.asUInt64();
}

int64_t
requireInt64(Json::Value const& value, std::string const& context)
{
    if (!value.isIntegral())
    {
        throw std::invalid_argument(context + " must be a signed integer");
    }
    if ((value.isUInt() || value.isUInt64()) &&
        value.asUInt64() >
            static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
    {
        throw std::invalid_argument(context + " is out of int64 range");
    }
    return value.asInt64();
}

std::optional<uint32_t>
requireOptionalUint32(Json::Value const& value, std::string const& context)
{
    if (value.isNull())
    {
        return std::nullopt;
    }
    return requireUint32(value, context);
}

Json::Value
toJsonOptionalUint32(std::optional<uint32_t> value)
{
    if (!value)
    {
        return Json::Value(Json::nullValue);
    }
    return Json::Value(static_cast<Json::UInt64>(*value));
}

} // namespace

std::string_view
downloadTimeModeName(ScpDporDefaultScenario::DownloadTimeMode mode)
{
    switch (mode)
    {
    case ScpDporDefaultScenario::DownloadTimeMode::BelowThreshold:
        return "below";
    case ScpDporDefaultScenario::DownloadTimeMode::AboveThreshold:
        return "above";
    case ScpDporDefaultScenario::DownloadTimeMode::Nondeterministic:
        return "nondet";
    }
    throw std::logic_error("unknown download-time mode");
}

ScpDporDefaultScenario::DownloadTimeMode
parseDownloadTimeMode(std::string_view mode)
{
    using DownloadTimeMode = ScpDporDefaultScenario::DownloadTimeMode;
    if (mode == downloadTimeModeName(DownloadTimeMode::BelowThreshold))
    {
        return DownloadTimeMode::BelowThreshold;
    }
    if (mode == downloadTimeModeName(DownloadTimeMode::AboveThreshold))
    {
        return DownloadTimeMode::AboveThreshold;
    }
    if (mode == downloadTimeModeName(DownloadTimeMode::Nondeterministic))
    {
        return DownloadTimeMode::Nondeterministic;
    }
    throw std::invalid_argument("unknown download-time mode: " +
                                std::string(mode));
}

std::string_view
txSetStatusModeName(ScpDporDefaultScenario::TxSetStatusMode mode)
{
    switch (mode)
    {
    case ScpDporDefaultScenario::TxSetStatusMode::AlwaysValid:
        return "always-valid";
    case ScpDporDefaultScenario::TxSetStatusMode::DownloadingThenValid:
        return "downloading-then-valid";
    case ScpDporDefaultScenario::TxSetStatusMode::AlwaysDownloading:
        return "always-downloading";
    }
    throw std::logic_error("unknown txset-status mode");
}

ScpDporDefaultScenario::TxSetStatusMode
parseTxSetStatusMode(std::string_view mode)
{
    using TxSetStatusMode = ScpDporDefaultScenario::TxSetStatusMode;
    if (mode == txSetStatusModeName(TxSetStatusMode::AlwaysValid))
    {
        return TxSetStatusMode::AlwaysValid;
    }
    if (mode == txSetStatusModeName(TxSetStatusMode::DownloadingThenValid))
    {
        return TxSetStatusMode::DownloadingThenValid;
    }
    if (mode == txSetStatusModeName(TxSetStatusMode::AlwaysDownloading))
    {
        return TxSetStatusMode::AlwaysDownloading;
    }
    throw std::invalid_argument("unknown txset-status mode: " +
                                std::string(mode));
}

std::string_view
terminalKindName(dpor::algo::TerminalExecutionKind kind)
{
    switch (kind)
    {
    case dpor::algo::TerminalExecutionKind::Full:
        return "full";
    case dpor::algo::TerminalExecutionKind::Blocked:
        return "blocked";
    case dpor::algo::TerminalExecutionKind::Error:
        return "error";
    case dpor::algo::TerminalExecutionKind::DepthLimit:
        return "depth-limit";
    case dpor::algo::TerminalExecutionKind::ThreadEventLimit:
        return "thread-event-limit";
    }
    throw std::logic_error("unknown terminal execution kind");
}

dpor::algo::TerminalExecutionKind
parseTerminalKind(std::string_view kind)
{
    if (kind == terminalKindName(dpor::algo::TerminalExecutionKind::Full))
    {
        return dpor::algo::TerminalExecutionKind::Full;
    }
    if (kind == terminalKindName(dpor::algo::TerminalExecutionKind::Blocked))
    {
        return dpor::algo::TerminalExecutionKind::Blocked;
    }
    if (kind == terminalKindName(dpor::algo::TerminalExecutionKind::Error))
    {
        return dpor::algo::TerminalExecutionKind::Error;
    }
    if (kind == terminalKindName(dpor::algo::TerminalExecutionKind::DepthLimit))
    {
        return dpor::algo::TerminalExecutionKind::DepthLimit;
    }
    if (kind ==
        terminalKindName(dpor::algo::TerminalExecutionKind::ThreadEventLimit))
    {
        return dpor::algo::TerminalExecutionKind::ThreadEventLimit;
    }
    throw std::invalid_argument("unknown terminal kind: " + std::string(kind));
}

std::string_view
communicationModelName(dpor::model::CommunicationModel model)
{
    switch (model)
    {
    case dpor::model::CommunicationModel::Async:
        return "async";
    case dpor::model::CommunicationModel::FifoP2P:
        return "fifo";
    }
    throw std::logic_error("unknown communication model");
}

dpor::model::CommunicationModel
parseCommunicationModel(std::string_view model)
{
    if (model == communicationModelName(dpor::model::CommunicationModel::Async))
    {
        return dpor::model::CommunicationModel::Async;
    }
    if (model ==
        communicationModelName(dpor::model::CommunicationModel::FifoP2P))
    {
        return dpor::model::CommunicationModel::FifoP2P;
    }
    throw std::invalid_argument("unknown communication model: " +
                                std::string(model));
}

namespace
{

// Encode-side counterparts of parseTimerID/parseTxSetStatus. Unlike the
// diagnostic timerName/txSetStatusName helpers, these throw on values the
// parser would reject, so an unreplayable trace fails at dump time instead of
// load time.
std::string
encodeTimerID(int timerID)
{
    switch (timerID)
    {
    case Slot::NOMINATION_TIMER:
        return "nomination";
    case Slot::BALLOT_PROTOCOL_TIMER:
        return "ballot";
    }
    throw std::invalid_argument("unsupported timer id in trace value: " +
                                std::to_string(timerID));
}

std::string
encodeTxSetStatus(DporScpTxSetStatus status)
{
    switch (status)
    {
    case DporScpTxSetStatus::Valid:
        return "valid";
    case DporScpTxSetStatus::Downloading:
        return "downloading";
    }
    throw std::invalid_argument("unsupported txset status in trace value: " +
                                std::to_string(static_cast<unsigned>(status)));
}

int
parseTimerID(std::string_view name)
{
    if (name == "nomination")
    {
        return Slot::NOMINATION_TIMER;
    }
    if (name == "ballot")
    {
        return Slot::BALLOT_PROTOCOL_TIMER;
    }
    throw std::invalid_argument("unknown timer choice: " + std::string(name));
}

DporScpTxSetStatus
parseTxSetStatus(std::string_view value)
{
    if (value == "valid")
    {
        return DporScpTxSetStatus::Valid;
    }
    if (value == "downloading")
    {
        return DporScpTxSetStatus::Downloading;
    }
    throw std::invalid_argument("unknown txset status value: " +
                                std::string(value));
}

std::string
encodeBytes(std::vector<uint8_t> const& bytes)
{
    return decoder::encode_b64(bytes);
}

template <typename T>
T
decodeBytes(std::string const& encoded, std::string const& context)
{
    T bytes;
    try
    {
        decoder::decode_b64(encoded, bytes);
    }
    catch (std::exception const& ex)
    {
        throw std::invalid_argument(context +
                                    " is not valid base64: " + ex.what());
    }
    // The vendored decoder skips invalid characters; canonical re-encoding
    // catches both those and malformed padding.
    if (encodeBytes(bytes) != encoded)
    {
        throw std::invalid_argument(context + " is not valid base64");
    }
    return bytes;
}

Json::Value
toJsonValueBytes(Value const& value)
{
    return Json::Value(encodeBytes(value));
}

Value
valueBytesFromJson(Json::Value const& value, std::string const& context)
{
    return decodeBytes<Value>(requireString(value, context), context);
}

Json::Value
toJson(TerminalMeta const& terminal)
{
    Json::Value root(Json::objectValue);
    root["kind"] = std::string(terminalKindName(terminal.mKind));
    if (terminal.mFailureMessage)
    {
        root["failure_message"] = *terminal.mFailureMessage;
    }
    else
    {
        root["failure_message"] = Json::Value(Json::nullValue);
    }
    root["focus_node_index"] =
        static_cast<Json::UInt64>(terminal.mFocusNodeIndex);
    return root;
}

TerminalMeta
terminalMetaFromJson(Json::Value const& value)
{
    auto const& object = requireObject(value, "terminal");

    TerminalMeta terminal;
    terminal.mKind = parseTerminalKind(requireString(
        requireMember(object, "kind", "terminal"), "terminal.kind"));

    auto const& failureMessage =
        requireMember(object, "failure_message", "terminal");
    if (!failureMessage.isNull())
    {
        terminal.mFailureMessage =
            requireString(failureMessage, "terminal.failure_message");
    }

    terminal.mFocusNodeIndex = static_cast<std::size_t>(
        requireUint64(requireMember(object, "focus_node_index", "terminal"),
                      "terminal.focus_node_index"));
    return terminal;
}

void
validateTraceBundle(TraceBundle const& bundle)
{
    auto const validatorCount = bundle.mOptions.mValidators.size();
    if (bundle.mThreadTraces.size() != validatorCount)
    {
        throw std::invalid_argument(
            "thread_traces count must match validator count");
    }
    if (bundle.mTerminal.mFocusNodeIndex >= validatorCount)
    {
        throw std::invalid_argument("focus_node_index is out of range");
    }
}

} // namespace

Json::Value
toJson(ScpDporValue const& value)
{
    Json::Value root(Json::objectValue);
    root["slot_index"] = static_cast<Json::UInt64>(value.mSlotIndex);

    switch (value.mKind)
    {
    case ScpDporValue::Kind::Envelope:
        root["kind"] = "envelope";
        root["envelope_xdr"] =
            encodeBytes(xdr::xdr_to_opaque(value.envelope()));
        root["annotation"] = formatWithStream(value);
        return root;
    case ScpDporValue::Kind::TimerChoice:
        root["kind"] = "timer";
        root["timer"] = encodeTimerID(value.mTimerID);
        return root;
    case ScpDporValue::Kind::TxSetDownloadWaitTimeChoice:
        root["kind"] = "txset_wait_time";
        root["milliseconds"] =
            static_cast<Json::Int64>(value.mDurationMilliseconds);
        return root;
    case ScpDporValue::Kind::TxSetStatusChoice:
        root["kind"] = "txset_status";
        root["value"] = encodeTxSetStatus(
            static_cast<DporScpTxSetStatus>(value.mTxSetStatus));
        return root;
    }
    throw std::logic_error("unknown ScpDporValue kind");
}

ScpDporValue
scpDporValueFromJson(Json::Value const& value)
{
    auto const& object = requireObject(value, "ScpDporValue");
    auto const kind = requireString(
        requireMember(object, "kind", "ScpDporValue"), "ScpDporValue.kind");
    auto const slotIndex =
        requireUint64(requireMember(object, "slot_index", "ScpDporValue"),
                      "ScpDporValue.slot_index");

    if (kind == "envelope")
    {
        auto const bytes = decodeBytes<std::vector<uint8_t>>(
            requireString(requireMember(object, "envelope_xdr", "ScpDporValue"),
                          "ScpDporValue.envelope_xdr"),
            "ScpDporValue.envelope_xdr");
        SCPEnvelope envelope;
        try
        {
            xdr::xdr_from_opaque(bytes, envelope);
        }
        catch (std::exception const& ex)
        {
            throw std::invalid_argument("ScpDporValue.envelope_xdr is not "
                                        "valid SCPEnvelope XDR: " +
                                        std::string(ex.what()));
        }
        return makeEnvelopeValue(slotIndex, envelope);
    }
    if (kind == "timer")
    {
        return makeTimerChoiceValue(
            slotIndex, parseTimerID(requireString(
                           requireMember(object, "timer", "ScpDporValue"),
                           "ScpDporValue.timer")));
    }
    if (kind == "txset_wait_time")
    {
        return makeTxSetDownloadWaitTimeChoiceValue(
            slotIndex,
            std::chrono::milliseconds(requireInt64(
                requireMember(object, "milliseconds", "ScpDporValue"),
                "ScpDporValue.milliseconds")));
    }
    if (kind == "txset_status")
    {
        return makeTxSetStatusChoiceValue(
            slotIndex, parseTxSetStatus(requireString(
                           requireMember(object, "value", "ScpDporValue"),
                           "ScpDporValue.value")));
    }

    throw std::invalid_argument("unknown ScpDporValue.kind: " + kind);
}

Json::Value
toJson(ObservedValue const& observed)
{
    if (observed.is_bottom())
    {
        return Json::Value(Json::nullValue);
    }
    return toJson(observed.value());
}

ObservedValue
observedValueFromJson(Json::Value const& value)
{
    if (value.isNull())
    {
        return ObservedValue::bottom();
    }
    return ObservedValue{scpDporValueFromJson(value)};
}

Json::Value
toJson(ThreadTrace const& trace)
{
    Json::Value root(Json::arrayValue);
    for (auto const& observed : trace)
    {
        root.append(toJson(observed));
    }
    return root;
}

ThreadTrace
threadTraceFromJson(Json::Value const& value)
{
    auto const& array = requireArray(value, "thread trace");
    ThreadTrace trace;
    trace.reserve(array.size());
    for (auto const& observed : array)
    {
        trace.push_back(observedValueFromJson(observed));
    }
    return trace;
}

Json::Value
toJson(ScpDporDefaultScenario::Options const& options)
{
    Json::Value root(Json::objectValue);

    auto& validators = root["validators"];
    validators = Json::Value(Json::arrayValue);
    for (auto const& validator : options.mValidators)
    {
        validators.append(validator.getStrKeySeed().value);
    }

    root["quorum_set"] = LocalNode::toJson(
        options.mQuorumSet,
        std::function<std::string(NodeID const&)>(
            [](NodeID const& nodeID) { return KeyUtils::toStrKey(nodeID); }));
    root["slot_index"] = static_cast<Json::UInt64>(options.mSlotIndex);
    root["previous_value"] = toJsonValueBytes(options.mPreviousValue);

    auto& initialValues = root["initial_values"];
    initialValues = Json::Value(Json::arrayValue);
    for (auto const& initialValue : options.mInitialValues)
    {
        initialValues.append(toJsonValueBytes(initialValue));
    }

    root["stop_on_prepare"] = options.mStopOnPrepare;
    root["stop_on_commit"] = options.mStopOnCommit;
    root["stop_on_externalize"] = options.mStopOnExternalize;
    root["prepare_boundary_counter"] =
        static_cast<Json::UInt64>(options.mPrepareBoundaryCounter);
    root["max_nomination_round"] =
        toJsonOptionalUint32(options.mMaxNominationRound);
    root["max_balloting_round"] =
        toJsonOptionalUint32(options.mMaxBallotingRound);
    root["max_nomination_timers_round"] =
        toJsonOptionalUint32(options.mMaxNominationTimersRound);
    root["max_balloting_timers_round"] =
        toJsonOptionalUint32(options.mMaxBallotingTimersRound);
    root["nomination_timer_set_limit"] =
        toJsonOptionalUint32(options.mNominationTimerSetLimit);
    root["enable_nomination_timeouts"] = options.mEnableNominationTimeouts;
    root["enable_balloting_timeouts"] = options.mEnableBallotingTimeouts;
    root["download_time_mode"] =
        std::string(downloadTimeModeName(options.mDownloadTimeMode));
    root["txset_status_mode"] =
        std::string(txSetStatusModeName(options.mTxSetStatusMode));
    root["nomination_always_downloading"] =
        options.mNominationAlwaysDownloading;
    root["inject_empty_tx_set_protocol_gate_failure_for_testing"] =
        options.mInjectEmptyTxSetProtocolGateFailureForTesting;
    auto& outrightInvalidValuesByNode = root["outright_invalid_values_by_node"];
    outrightInvalidValuesByNode = Json::Value(Json::arrayValue);
    for (auto const& invalidValues : options.mOutrightInvalidValuesByNode)
    {
        Json::Value encodedValues(Json::arrayValue);
        for (auto const& invalidValue : invalidValues)
        {
            encodedValues.append(toJsonValueBytes(invalidValue));
        }
        outrightInvalidValuesByNode.append(std::move(encodedValues));
    }
    root["download_succeeds_in_round"] =
        toJsonOptionalUint32(options.mDownloadSucceedsInRound);
    root["initial_nomination_timeout_ms"] =
        static_cast<Json::UInt64>(options.mInitialNominationTimeoutMS);
    root["increment_nomination_timeout_ms"] =
        static_cast<Json::UInt64>(options.mIncrementNominationTimeoutMS);
    root["initial_ballot_timeout_ms"] =
        static_cast<Json::UInt64>(options.mInitialBallotTimeoutMS);
    root["increment_ballot_timeout_ms"] =
        static_cast<Json::UInt64>(options.mIncrementBallotTimeoutMS);
    return root;
}

ScpDporDefaultScenario::Options
optionsFromJson(Json::Value const& value)
{
    auto const& object = requireObject(value, "scenario.options");

    ScpDporDefaultScenario::Options options;

    auto const& validators =
        requireArray(requireMember(object, "validators", "scenario.options"),
                     "scenario.options.validators");
    options.mValidators.reserve(validators.size());
    for (auto const& validator : validators)
    {
        options.mValidators.push_back(SecretKey::fromStrKeySeed(
            requireString(validator, "scenario.options.validators[]")));
    }

    options.mQuorumSet = LocalNode::fromJson(
        requireMember(object, "quorum_set", "scenario.options"));
    options.mSlotIndex =
        requireUint64(requireMember(object, "slot_index", "scenario.options"),
                      "scenario.options.slot_index");
    options.mPreviousValue = valueBytesFromJson(
        requireMember(object, "previous_value", "scenario.options"),
        "scenario.options.previous_value");

    auto const& initialValues = requireArray(
        requireMember(object, "initial_values", "scenario.options"),
        "scenario.options.initial_values");
    options.mInitialValues.reserve(initialValues.size());
    for (auto const& initialValue : initialValues)
    {
        options.mInitialValues.push_back(valueBytesFromJson(
            initialValue, "scenario.options.initial_values[]"));
    }

    options.mStopOnPrepare = requireBool(
        requireMember(object, "stop_on_prepare", "scenario.options"),
        "scenario.options.stop_on_prepare");
    options.mStopOnCommit =
        requireBool(requireMember(object, "stop_on_commit", "scenario.options"),
                    "scenario.options.stop_on_commit");
    options.mStopOnExternalize = requireBool(
        requireMember(object, "stop_on_externalize", "scenario.options"),
        "scenario.options.stop_on_externalize");
    options.mPrepareBoundaryCounter = requireUint32(
        requireMember(object, "prepare_boundary_counter", "scenario.options"),
        "scenario.options.prepare_boundary_counter");
    options.mMaxNominationRound = requireOptionalUint32(
        requireMember(object, "max_nomination_round", "scenario.options"),
        "scenario.options.max_nomination_round");
    options.mMaxBallotingRound = requireOptionalUint32(
        requireMember(object, "max_balloting_round", "scenario.options"),
        "scenario.options.max_balloting_round");
    options.mMaxNominationTimersRound = requireOptionalUint32(
        requireMember(object, "max_nomination_timers_round",
                      "scenario.options"),
        "scenario.options.max_nomination_timers_round");
    options.mMaxBallotingTimersRound = requireOptionalUint32(
        requireMember(object, "max_balloting_timers_round", "scenario.options"),
        "scenario.options.max_balloting_timers_round");
    options.mNominationTimerSetLimit = requireOptionalUint32(
        requireMember(object, "nomination_timer_set_limit", "scenario.options"),
        "scenario.options.nomination_timer_set_limit");
    options.mEnableNominationTimeouts = requireBool(
        requireMember(object, "enable_nomination_timeouts", "scenario.options"),
        "scenario.options.enable_nomination_timeouts");
    options.mEnableBallotingTimeouts = requireBool(
        requireMember(object, "enable_balloting_timeouts", "scenario.options"),
        "scenario.options.enable_balloting_timeouts");
    options.mDownloadTimeMode = parseDownloadTimeMode(requireString(
        requireMember(object, "download_time_mode", "scenario.options"),
        "scenario.options.download_time_mode"));
    options.mTxSetStatusMode = parseTxSetStatusMode(requireString(
        requireMember(object, "txset_status_mode", "scenario.options"),
        "scenario.options.txset_status_mode"));
    options.mNominationAlwaysDownloading =
        requireBool(requireMember(object, "nomination_always_downloading",
                                  "scenario.options"),
                    "scenario.options.nomination_always_downloading");
    options.mInjectEmptyTxSetProtocolGateFailureForTesting = requireBool(
        requireMember(object,
                      "inject_empty_tx_set_protocol_gate_failure_for_testing",
                      "scenario.options"),
        "scenario.options."
        "inject_empty_tx_set_protocol_gate_failure_for_testing");

    auto const& outrightInvalidValuesByNode =
        requireArray(requireMember(object, "outright_invalid_values_by_node",
                                   "scenario.options"),
                     "scenario.options.outright_invalid_values_by_node");
    if (!outrightInvalidValuesByNode.empty() &&
        outrightInvalidValuesByNode.size() != validators.size())
    {
        throw std::invalid_argument(
            "scenario.options.outright_invalid_values_by_node must be empty "
            "or match validator count");
    }
    options.mOutrightInvalidValuesByNode.reserve(
        outrightInvalidValuesByNode.size());
    for (auto const& invalidValuesValue : outrightInvalidValuesByNode)
    {
        auto const& invalidValues =
            requireArray(invalidValuesValue,
                         "scenario.options.outright_invalid_values_by_node[]");
        std::vector<Value> decodedValues;
        std::set<Value> uniqueValues;
        decodedValues.reserve(invalidValues.size());
        for (auto const& invalidValue : invalidValues)
        {
            auto decoded = valueBytesFromJson(
                invalidValue,
                "scenario.options.outright_invalid_values_by_node[][]");
            if (!uniqueValues.insert(decoded).second)
            {
                throw std::invalid_argument(
                    "scenario.options.outright_invalid_values_by_node[] "
                    "contains duplicate values");
            }
            decodedValues.push_back(std::move(decoded));
        }
        options.mOutrightInvalidValuesByNode.push_back(
            std::move(decodedValues));
    }
    options.mDownloadSucceedsInRound = requireOptionalUint32(
        requireMember(object, "download_succeeds_in_round", "scenario.options"),
        "scenario.options.download_succeeds_in_round");
    options.mInitialNominationTimeoutMS =
        requireUint32(requireMember(object, "initial_nomination_timeout_ms",
                                    "scenario.options"),
                      "scenario.options.initial_nomination_timeout_ms");
    options.mIncrementNominationTimeoutMS =
        requireUint32(requireMember(object, "increment_nomination_timeout_ms",
                                    "scenario.options"),
                      "scenario.options.increment_nomination_timeout_ms");
    options.mInitialBallotTimeoutMS = requireUint32(
        requireMember(object, "initial_ballot_timeout_ms", "scenario.options"),
        "scenario.options.initial_ballot_timeout_ms");
    options.mIncrementBallotTimeoutMS =
        requireUint32(requireMember(object, "increment_ballot_timeout_ms",
                                    "scenario.options"),
                      "scenario.options.increment_ballot_timeout_ms");
    return options;
}

Json::Value
toJson(TraceBundle const& bundle)
{
    Json::Value root(Json::objectValue);
    root["version"] = static_cast<Json::UInt64>(bundle.mVersion);

    auto& scenario = root["scenario"];
    scenario = Json::Value(Json::objectValue);
    scenario["kind"] = "default";
    scenario["options"] = toJson(bundle.mOptions);

    root["terminal"] = toJson(bundle.mTerminal);
    root["communication_model"] =
        std::string(communicationModelName(bundle.mCommunicationModel));

    auto& threadTraces = root["thread_traces"];
    threadTraces = Json::Value(Json::arrayValue);
    for (auto const& trace : bundle.mThreadTraces)
    {
        threadTraces.append(toJson(trace));
    }

    return root;
}

TraceBundle
traceBundleFromJson(Json::Value const& value)
{
    auto const& object = requireObject(value, "trace bundle");

    TraceBundle bundle;
    auto const version =
        requireUint64(requireMember(object, "version", "trace bundle"),
                      "trace bundle.version");
    if (version > static_cast<uint64_t>(std::numeric_limits<int>::max()))
    {
        throw std::invalid_argument("trace bundle.version is out of range");
    }
    bundle.mVersion = static_cast<int>(version);
    if (bundle.mVersion != TRACE_BUNDLE_VERSION)
    {
        throw std::invalid_argument(
            "unsupported trace bundle version " +
            std::to_string(bundle.mVersion) +
            " (supported: 8); capture a fresh trace with the current binary");
    }

    auto const& scenario =
        requireObject(requireMember(object, "scenario", "trace bundle"),
                      "trace bundle.scenario");
    auto const scenarioKind =
        requireString(requireMember(scenario, "kind", "trace bundle.scenario"),
                      "trace bundle.scenario.kind");
    if (scenarioKind != "default")
    {
        throw std::invalid_argument("unsupported scenario kind: " +
                                    scenarioKind);
    }
    bundle.mOptions = optionsFromJson(
        requireMember(scenario, "options", "trace bundle.scenario"));
    bundle.mTerminal =
        terminalMetaFromJson(requireMember(object, "terminal", "trace bundle"));
    if (object.isMember("communication_model"))
    {
        bundle.mCommunicationModel = parseCommunicationModel(requireString(
            object["communication_model"], "trace bundle.communication_model"));
    }

    auto const& threadTraces =
        requireArray(requireMember(object, "thread_traces", "trace bundle"),
                     "trace bundle.thread_traces");
    bundle.mThreadTraces.reserve(threadTraces.size());
    for (auto const& trace : threadTraces)
    {
        bundle.mThreadTraces.push_back(threadTraceFromJson(trace));
    }

    validateTraceBundle(bundle);
    return bundle;
}

TraceBundle
makeTraceBundle(ScpDporDefaultScenario const& scenario,
                dpor::algo::TerminalExecutionT<ScpDporValue> const& execution,
                dpor::model::CommunicationModel communicationModel,
                TerminalMeta terminal)
{
    TraceBundle bundle;
    bundle.mOptions = scenario.options();
    bundle.mCommunicationModel = communicationModel;
    bundle.mTerminal = std::move(terminal);
    bundle.mThreadTraces.reserve(scenario.options().mValidators.size());
    for (std::size_t nodeIndex = 0;
         nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
    {
        bundle.mThreadTraces.push_back(
            execution.graph.thread_trace(threadIdForNodeIndex(nodeIndex)));
    }
    return bundle;
}

void
writeTraceBundle(std::filesystem::path const& path, TraceBundle const& bundle)
{
    Json::StyledWriter writer;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        throw std::runtime_error("failed to open trace json for write: " +
                                 path.string());
    }
    out << writer.write(toJson(bundle));
    out.flush();
    if (!out)
    {
        throw std::runtime_error("failed to write trace json: " +
                                 path.string());
    }
}

TraceBundle
loadTraceBundle(std::filesystem::path const& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        throw std::runtime_error("failed to open trace json for read: " +
                                 path.string());
    }

    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(in, root))
    {
        throw std::runtime_error("failed to parse trace json " + path.string() +
                                 ": " + reader.getFormattedErrorMessages());
    }

    return traceBundleFromJson(root);
}

} // namespace stellar::scpdpor
