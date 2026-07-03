// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "scp/test/ScpDporBridge.h"

#include <exception>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace stellar::scpdpor
{

struct InvestigationErrorExecution
{
    std::size_t mNodeIndex{};
    dpor::model::ThreadId mThreadID{};
    std::string mMessage;
};

// Full and Blocked partition the maximal executions: Full means every thread
// completed, Blocked means at least one thread ended waiting on a blocking
// receive no message can satisfy. Checks over complete interleavings (missing
// externalize, agreement) must consider both kinds.
inline bool
isMaximalExecution(
    dpor::algo::TerminalExecutionT<ScpDporValue> const& execution)
{
    return execution.is_full_execution() || execution.is_blocked_execution();
}

inline Program
wrapProgramExceptionsAsErrorExecutions(Program program)
{
    std::vector<dpor::model::ThreadId> threadIDs;
    threadIDs.reserve(program.threads.size());
    program.threads.for_each_assigned(
        [&](dpor::model::ThreadId threadID, ThreadFunction const&) {
            threadIDs.push_back(threadID);
        });

    for (auto const threadID : threadIDs)
    {
        auto wrappedThread = std::move(program.threads[threadID]);
        program.threads[threadID] =
            [threadID, wrappedThread = std::move(wrappedThread)](
                ThreadTrace const& trace, std::size_t step)
                -> std::optional<EventLabel> {
                try
                {
                    return wrappedThread(trace, step);
                }
                catch (std::exception const& ex)
                {
                    std::ostringstream message;
                    message << "thread=" << threadID << " step=" << step
                            << " exception=" << ex.what();
                    return EventLabel{
                        dpor::model::ErrorLabel{.message = message.str()}};
                }
                catch (...)
                {
                    std::ostringstream message;
                    message << "thread=" << threadID << " step=" << step
                            << " exception=<unknown>";
                    return EventLabel{
                        dpor::model::ErrorLabel{.message = message.str()}};
                }
            };
    }
    return program;
}

inline std::optional<InvestigationErrorExecution>
findErrorExecution(
    std::size_t validatorCount,
    dpor::algo::TerminalExecutionT<ScpDporValue> const& execution)
{
    if (!execution.is_error_execution())
    {
        return std::nullopt;
    }

    for (std::size_t nodeIndex = 0; nodeIndex < validatorCount; ++nodeIndex)
    {
        auto const threadID = threadIdForNodeIndex(nodeIndex);
        auto const lastEventID = execution.graph.last_event_id(threadID);
        if (lastEventID == ExplorationGraph::kNoSource)
        {
            continue;
        }

        auto const* error =
            dpor::model::as_error(execution.graph.event(lastEventID));
        if (error != nullptr)
        {
            return InvestigationErrorExecution{.mNodeIndex = nodeIndex,
                                               .mThreadID = threadID,
                                               .mMessage = error->message};
        }
    }

    return std::nullopt;
}

} // namespace stellar::scpdpor
