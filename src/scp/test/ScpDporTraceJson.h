// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "lib/json/json.h"
#include "scp/test/ScpDporDefaultScenario.h"

#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

namespace stellar::scpdpor
{

// Version 8 deliberately starts a new, v8-only compatibility line: thread
// traces are positional and derivable metadata is no longer serialized.
inline constexpr int TRACE_BUNDLE_VERSION = 8;

struct TerminalMeta
{
    dpor::algo::TerminalExecutionKind mKind{
        dpor::algo::TerminalExecutionKind::Full};
    std::optional<std::string> mFailureMessage;
    std::size_t mFocusNodeIndex{};
};

struct TraceBundle
{
    int mVersion{TRACE_BUNDLE_VERSION};
    ScpDporDefaultScenario::Options mOptions;
    dpor::model::CommunicationModel mCommunicationModel{
        dpor::model::CommunicationModel::Async};
    TerminalMeta mTerminal;
    // Positional by node index; node N's trace is at index N.
    std::vector<ThreadTrace> mThreadTraces;
};

std::string_view
downloadTimeModeName(ScpDporDefaultScenario::DownloadTimeMode mode);

ScpDporDefaultScenario::DownloadTimeMode
parseDownloadTimeMode(std::string_view mode);

std::string_view
txSetStatusModeName(ScpDporDefaultScenario::TxSetStatusMode mode);

ScpDporDefaultScenario::TxSetStatusMode
parseTxSetStatusMode(std::string_view mode);

std::string_view terminalKindName(dpor::algo::TerminalExecutionKind kind);

dpor::algo::TerminalExecutionKind parseTerminalKind(std::string_view kind);

std::string_view communicationModelName(dpor::model::CommunicationModel model);

dpor::model::CommunicationModel parseCommunicationModel(std::string_view model);

Json::Value toJson(ScpDporValue const& value);

ScpDporValue scpDporValueFromJson(Json::Value const& value);

Json::Value toJson(ObservedValue const& observed);

ObservedValue observedValueFromJson(Json::Value const& value);

Json::Value toJson(ThreadTrace const& trace);

ThreadTrace threadTraceFromJson(Json::Value const& value);

Json::Value toJson(ScpDporDefaultScenario::Options const& options);

ScpDporDefaultScenario::Options optionsFromJson(Json::Value const& value);

Json::Value toJson(TraceBundle const& bundle);

TraceBundle traceBundleFromJson(Json::Value const& value);

TraceBundle
makeTraceBundle(ScpDporDefaultScenario const& scenario,
                dpor::algo::TerminalExecutionT<ScpDporValue> const& execution,
                dpor::model::CommunicationModel communicationModel,
                TerminalMeta terminal);

void writeTraceBundle(std::filesystem::path const& path,
                      TraceBundle const& bundle);

TraceBundle loadTraceBundle(std::filesystem::path const& path);

} // namespace stellar::scpdpor
