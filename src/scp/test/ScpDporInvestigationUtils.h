// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "scp/test/ScpDporDefaultScenario.h"

#include <exception>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
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

struct InvestigationBlockedExecution
{
    std::size_t mNodeIndex{};
    dpor::model::ThreadId mThreadID{};
};

struct LastEventThread
{
    std::size_t mNodeIndex{};
    dpor::model::ThreadId mThreadID{};
};

struct AgreementFailure
{
    std::size_t mReferenceNodeIndex{};
    std::size_t mConflictingNodeIndex{};
};

struct MissingExternalizeResult
{
    std::optional<std::size_t> mMissingNodeIndex;
    std::size_t mEmittedEnvelopeCount{};
};

struct AgreementResult
{
    std::optional<AgreementFailure> mFailure;
    std::size_t mExternalizedValueCount{};
};

// Full and Blocked partition the maximal executions: Full means every thread
// completed, Blocked means at least one thread ended waiting on a blocking
// receive no message can satisfy. Checks over complete interleavings (missing
// externalize, agreement) must consider both kinds. DepthLimit and
// ThreadEventLimit are excluded for free: both mark executions the engine may
// have truncated, so a property that holds only for complete interleavings
// cannot be concluded from them.
inline bool
isMaximalExecution(
    dpor::algo::TerminalExecutionT<ScpDporValue> const& execution)
{
    return execution.is_full_execution() || execution.is_blocked_execution();
}

inline Program
wrapProgramExceptionsAsErrorExecutions(Program program)
{
    // Collect first, then rewrap: set_thread() mutates the registration the
    // iteration is walking.
    std::vector<std::pair<dpor::model::ThreadId, ThreadFunction>> registered;
    registered.reserve(program.thread_count());
    program.for_each_thread(
        [&](dpor::model::ThreadId threadID, ThreadFunction const& fn) {
            registered.emplace_back(threadID, fn);
        });

    for (auto& [threadID, wrappedThread] : registered)
    {
        program.set_thread(
            threadID,
            [threadID = threadID, wrappedThread = std::move(wrappedThread)](
                ThreadTrace const& trace,
                std::size_t step) -> std::optional<ThreadAction> {
            auto makeError = [&](std::string_view exception) {
                std::ostringstream message;
                message << "thread=" << threadID << " step=" << step
                        << " exception=" << exception;
                return ThreadAction{
                    dpor::model::ErrorLabel{.message = message.str()}};
            };
            try
            {
                return wrappedThread(trace, step);
            }
            catch (std::exception const& ex)
            {
                return makeError(ex.what());
            }
            catch (...)
            {
                return makeError("<unknown>");
            }
            });
    }
    return program;
}

template <typename Predicate>
std::optional<LastEventThread>
findLastEventThread(
    std::size_t validatorCount,
    dpor::algo::TerminalExecutionT<ScpDporValue> const& execution,
    Predicate predicate)
{
    for (std::size_t nodeIndex = 0; nodeIndex < validatorCount; ++nodeIndex)
    {
        auto const threadID = threadIdForNodeIndex(nodeIndex);
        auto const lastEventID = execution.graph.last_event_id(threadID);
        if (lastEventID != ExplorationGraph::kNoSource &&
            predicate(execution.graph.event(lastEventID)))
        {
            return LastEventThread{nodeIndex, threadID};
        }
    }
    return std::nullopt;
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

    auto const found = findLastEventThread(
        validatorCount, execution, [](ExplorationGraph::Event const& event) {
            return dpor::model::as_error(event);
        });
    if (!found)
    {
        return std::nullopt;
    }
    auto const lastEventID = execution.graph.last_event_id(found->mThreadID);
    auto const* error =
        dpor::model::as_error(execution.graph.event(lastEventID));
    return InvestigationErrorExecution{found->mNodeIndex, found->mThreadID,
                                       error->message};
}

inline std::optional<InvestigationBlockedExecution>
findBlockedExecution(
    std::size_t validatorCount,
    dpor::algo::TerminalExecutionT<ScpDporValue> const& execution)
{
    if (!execution.is_blocked_execution())
    {
        return std::nullopt;
    }

    auto const found = findLastEventThread(
        validatorCount, execution, [](ExplorationGraph::Event const& event) {
            return dpor::model::as_block(event);
        });
    if (!found)
    {
        return std::nullopt;
    }
    return InvestigationBlockedExecution{found->mNodeIndex, found->mThreadID};
}

inline std::optional<Value>
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

inline MissingExternalizeResult
findNodeMissingExternalize(
    ScpDporDefaultScenario const& scenario,
    dpor::algo::TerminalExecutionT<ScpDporValue> const& execution)
{
    MissingExternalizeResult result;
    if (!isMaximalExecution(execution))
    {
        return result;
    }

    for (std::size_t nodeIndex = 0;
         nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
    {
        auto const trace =
            execution.graph.thread_trace(threadIdForNodeIndex(nodeIndex));
        auto const inspection =
            scenario.inspectEmittedEnvelopes(nodeIndex, trace);
        result.mEmittedEnvelopeCount += inspection.mEmittedEnvelopes.size();
        if (!findExternalizedValue(inspection.mEmittedEnvelopes))
        {
            result.mMissingNodeIndex = nodeIndex;
            break;
        }
    }
    return result;
}

inline AgreementResult
findAgreementFailure(
    ScpDporDefaultScenario const& scenario,
    dpor::algo::TerminalExecutionT<ScpDporValue> const& execution)
{
    AgreementResult result;
    if (!isMaximalExecution(execution))
    {
        return result;
    }

    std::optional<std::pair<std::size_t, Value>> reference;
    for (std::size_t nodeIndex = 0;
         nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
    {
        auto const trace =
            execution.graph.thread_trace(threadIdForNodeIndex(nodeIndex));
        auto const inspection =
            scenario.inspectEmittedEnvelopes(nodeIndex, trace);
        auto const externalizedValue =
            findExternalizedValue(inspection.mEmittedEnvelopes);
        if (!externalizedValue)
        {
            continue;
        }
        ++result.mExternalizedValueCount;
        if (!reference)
        {
            reference.emplace(nodeIndex, *externalizedValue);
        }
        else if (*externalizedValue != reference->second)
        {
            result.mFailure = AgreementFailure{reference->first, nodeIndex};
            break;
        }
    }
    return result;
}

} // namespace stellar::scpdpor
