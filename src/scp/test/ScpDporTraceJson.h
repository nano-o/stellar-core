// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "lib/json/json.h"
#include "scp/test/ScpDporDefaultScenario.h"

#include <filesystem>
#include <optional>
#include <vector>

namespace stellar::scpdpor
{

inline constexpr int TRACE_BUNDLE_VERSION = 2;

struct TerminalMeta
{
    dpor::algo::TerminalExecutionKind mKind{
        dpor::algo::TerminalExecutionKind::Full};
    std::optional<std::string> mFailureMessage;
    std::size_t mFocusNodeIndex{};
    dpor::model::ThreadId mFocusThreadID{};
};

struct ThreadTraceRecord
{
    dpor::model::ThreadId mThreadID{};
    ThreadTrace mTrace;
};

struct TraceBundle
{
    int mVersion{TRACE_BUNDLE_VERSION};
    ScpDporDefaultScenario::Options mOptions;
    dpor::model::CommunicationModel mCommunicationModel{
        dpor::model::CommunicationModel::Async};
    TerminalMeta mTerminal;
    std::vector<ThreadTraceRecord> mThreadTraces;
};

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
