// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/ScpDporThreeNodePrepareBoundaryScenario.h"
#include "util/Logging.h"

#include <cstdlib>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <type_traits>

namespace
{

struct CommandLineOptions
{
    std::size_t mWorkers{1};
    std::size_t mDepth{12};
    std::optional<std::size_t> mDumpInitialSteps;
    bool mDumpTerminalTrace{false};
    bool mDumpTerminalReplayTrace{false};
    dpor::model::CommunicationModel mCommunicationModel{
        dpor::model::CommunicationModel::Async};
};

void
printUsage(char const* argv0)
{
    std::cerr << "Usage: " << argv0
              << " [--workers N] [--depth N] [--fifo]"
              << " [--dump-initial-steps N] [--dump-terminal-trace]"
              << " [--dump-terminal-replay-trace]\n";
}

template <typename T>
std::string
formatWithStream(T const& value)
{
    std::ostringstream out;
    out << value;
    return out.str();
}

std::string
formatObservedValue(stellar::scpdpor::ObservedValue const& observed)
{
    return observed.is_bottom() ? std::string("<bottom>")
                                : formatWithStream(observed.value());
}

void
printEventLabel(std::ostream& out, stellar::scpdpor::EventLabel const& event)
{
    std::visit(
        [&](auto const& label) {
            using Label = std::decay_t<decltype(label)>;
            if constexpr (std::is_same_v<Label, stellar::scpdpor::SendLabel>)
            {
                out << "send(dst=" << label.destination
                    << ", value=" << label.value << ")";
            }
            else if constexpr (std::is_same_v<Label,
                                              stellar::scpdpor::ReceiveLabel>)
            {
                out << "receive(nonblocking="
                    << (label.is_nonblocking() ? "true" : "false") << ")";
            }
            else if constexpr (std::is_same_v<
                                   Label,
                                   stellar::scpdpor::NondeterministicChoiceLabel>)
            {
                out << "choice(count=" << label.choices.size()
                    << ", first=" << label.value << ")";
            }
            else if constexpr (std::is_same_v<Label, dpor::model::BlockLabel>)
            {
                out << "block";
            }
            else if constexpr (std::is_same_v<Label, dpor::model::ErrorLabel>)
            {
                out << "error(message=" << label.message << ")";
            }
        },
        event);
}

void
printReplayDebugEvent(std::ostream& out, uint64_t slotIndex,
                      stellar::DporScpNode::ReplayDebugEvent const& event)
{
    using ReplayDebugEvent = stellar::DporScpNode::ReplayDebugEvent;

    switch (event.mKind)
    {
    case ReplayDebugEvent::Kind::EmitEnvelope:
        out << "emit(";
        if (event.mBoundary)
        {
            out << "boundary=true, ";
        }
        out << "value="
            << stellar::scpdpor::makeEnvelopeValue(slotIndex, *event.mEnvelope)
            << ")";
        return;
    case ReplayDebugEvent::Kind::SetupTimer:
        out << "setup-timer(slot=" << event.mSlotIndex
            << ", id=" << stellar::scpdpor::timerName(event.mTimerID)
            << ", ms=" << event.mTimeout.count() << ")";
        return;
    case ReplayDebugEvent::Kind::StopTimer:
        out << "stop-timer(slot=" << event.mSlotIndex
            << ", id=" << stellar::scpdpor::timerName(event.mTimerID) << ")";
        return;
    case ReplayDebugEvent::Kind::FireTimer:
        out << "fire-timer(slot=" << event.mSlotIndex
            << ", id=" << stellar::scpdpor::timerName(event.mTimerID)
            << ", ms=" << event.mTimeout.count() << ")";
        return;
    case ReplayDebugEvent::Kind::UseTxSetDownloadWaitTime:
        out << "txset-wait(ms=" << event.mWaitTime->count() << ")";
        return;
    }
}

void
printThreadReplayTrace(
    std::ostream& out, uint64_t slotIndex,
    stellar::scpdpor::ScpDporThreeNodePrepareBoundaryScenario::
        ThreadReplayTraceInspection const& inspection)
{
    for (std::size_t stepIndex = 0; stepIndex < inspection.mSteps.size();
         ++stepIndex)
    {
        auto const& step = inspection.mSteps.at(stepIndex);
        out << "  step=" << stepIndex << " ";
        switch (step.mKind)
        {
        case stellar::scpdpor::ScpDporThreeNodePrepareBoundaryScenario::
            ThreadReplayTraceStep::Kind::Send:
            printEventLabel(out, stellar::scpdpor::EventLabel{*step.mSend});
            break;
        case stellar::scpdpor::ScpDporThreeNodePrepareBoundaryScenario::
            ThreadReplayTraceStep::Kind::NondeterministicChoice:
            printEventLabel(out, stellar::scpdpor::EventLabel{*step.mChoice});
            out << " selected=" << formatObservedValue(*step.mObservedValue);
            break;
        case stellar::scpdpor::ScpDporThreeNodePrepareBoundaryScenario::
            ThreadReplayTraceStep::Kind::Receive:
            printEventLabel(out, stellar::scpdpor::EventLabel{*step.mReceive});
            out << " observed=" << formatObservedValue(*step.mObservedValue);
            break;
        }
        out << "\n";

        for (auto const& choice : step.mNestedChoices)
        {
            out << "    choice=" << formatObservedValue(choice) << "\n";
        }
        for (auto const& effect : step.mSideEffects)
        {
            out << "    effect=";
            printReplayDebugEvent(out, slotIndex, effect);
            out << "\n";
        }
    }

    out << "  reached-boundary="
        << (inspection.mReachedBoundary ? "true" : "false") << "\n";
    if (inspection.mBoundaryEnvelope)
    {
        out << "  boundary="
            << stellar::scpdpor::makeEnvelopeValue(slotIndex,
                                                   *inspection.mBoundaryEnvelope)
            << "\n";
    }
}

CommandLineOptions
parseOptions(char const* argv0, int argc, char* argv[])
{
    CommandLineOptions options;
    for (int i = 1; i < argc; ++i)
    {
        std::string_view arg(argv[i]);
        if (arg == "--help" || arg == "-h")
        {
            printUsage(argv0);
            std::exit(0);
        }
        if (arg == "--fifo")
        {
            options.mCommunicationModel =
                dpor::model::CommunicationModel::FifoP2P;
            continue;
        }
        if (arg == "--workers" && i + 1 < argc)
        {
            options.mWorkers =
                static_cast<std::size_t>(std::stoull(argv[++i]));
            continue;
        }
        if (arg == "--depth" && i + 1 < argc)
        {
            options.mDepth =
                static_cast<std::size_t>(std::stoull(argv[++i]));
            continue;
        }
        if (arg == "--dump-initial-steps" && i + 1 < argc)
        {
            options.mDumpInitialSteps =
                static_cast<std::size_t>(std::stoull(argv[++i]));
            continue;
        }
        if (arg == "--dump-terminal-trace")
        {
            options.mDumpTerminalTrace = true;
            continue;
        }
        if (arg == "--dump-terminal-replay-trace")
        {
            options.mDumpTerminalReplayTrace = true;
            continue;
        }
        throw std::invalid_argument("unknown or incomplete argument: " +
                                    std::string(arg));
    }
    return options;
}

} // namespace

int
main(int argc, char* argv[])
{
    try
    {
        stellar::Logging::init();
        stellar::Logging::setFmt("<dpor>");
        stellar::Logging::setLogLevel(stellar::LogLevel::LVL_WARNING, nullptr);

        auto const options = parseOptions(argv[0], argc, argv);
        stellar::scpdpor::ScpDporThreeNodePrepareBoundaryScenario scenario;
        if (options.mDumpInitialSteps)
        {
            auto const program = scenario.makeProgram();
            for (std::size_t nodeIndex = 0; nodeIndex < scenario.options().mValidators.size();
                 ++nodeIndex)
            {
                auto const tid = stellar::scpdpor::threadIdForNodeIndex(nodeIndex);
                auto const& thread = program.threads.at(tid);
                std::cout << "thread=" << tid << "\n";
                for (std::size_t step = 0; step < *options.mDumpInitialSteps; ++step)
                {
                    std::cout << "  step=" << step << " ";
                    try
                    {
                        auto event = thread({}, step);
                        if (event)
                        {
                            printEventLabel(std::cout, *event);
                        }
                        else
                        {
                            std::cout << "<end>";
                            std::cout << "\n";
                            break;
                        }
                    }
                    catch (std::exception const& ex)
                    {
                        std::cout << "error(" << ex.what() << ")";
                        std::cout << "\n";
                        break;
                    }
                    std::cout << "\n";
                }
            }
            return 0;
        }

        dpor::algo::DporConfigT<stellar::scpdpor::ScpDporValue> config;
        config.program = scenario.makeProgram();
        config.max_depth = options.mDepth;
        config.communication_model = options.mCommunicationModel;
        if (options.mDumpTerminalTrace || options.mDumpTerminalReplayTrace)
        {
            config.on_terminal_execution =
                [&](dpor::algo::TerminalExecutionT<
                        stellar::scpdpor::ScpDporValue> const& execution) {
                    auto const leaderTrace = execution.graph.thread_trace(
                        stellar::scpdpor::threadIdForNodeIndex(0));
                    auto const boundary =
                        scenario.inspectPrepareBoundary(0, leaderTrace);

                    std::cout << "terminal-kind="
                              << (execution.is_full_execution()
                                      ? "full"
                                      : execution.is_error_execution()
                                            ? "error"
                                            : "depth-limit")
                              << " leader-boundary="
                              << (boundary.mReachedBoundary ? "true" : "false")
                              << "\n";

                    for (std::size_t nodeIndex = 0;
                         nodeIndex < scenario.options().mValidators.size();
                         ++nodeIndex)
                    {
                        auto const tid =
                            stellar::scpdpor::threadIdForNodeIndex(nodeIndex);
                        if (options.mDumpTerminalTrace)
                        {
                            auto const trace = execution.graph.thread_trace(tid);
                            std::cout << "thread=" << tid << "\n";
                            for (std::size_t i = 0; i < trace.size(); ++i)
                            {
                                std::cout << "  obs=" << i << " ";
                                if (trace.at(i).is_bottom())
                                {
                                    std::cout << "<bottom>";
                                }
                                else
                                {
                                    std::cout << trace.at(i).value();
                                }
                                std::cout << "\n";
                            }
                        }
                        if (options.mDumpTerminalReplayTrace)
                        {
                            auto const trace = execution.graph.thread_trace(tid);
                            auto inspection =
                                scenario.inspectThreadReplayTrace(nodeIndex,
                                                                  trace);
                            std::cout << "thread=" << tid << " replay\n";
                            printThreadReplayTrace(std::cout,
                                                   scenario.options().mSlotIndex,
                                                   inspection);
                        }
                    }
                    return dpor::algo::TerminalExecutionAction::Stop;
                };
        }

        auto const result = options.mWorkers > 1
                                ? dpor::algo::verify_parallel(
                                      config,
                                      {.max_workers = options.mWorkers})
                                : dpor::algo::verify(config);

        std::cout << "kind="
                  << (result.all_explored() ? "all-explored" : "stopped")
                  << " executions=" << result.executions_explored
                  << " full=" << result.full_executions_explored
                  << " error=" << result.error_executions_explored
                  << " depth-limit=" << result.depth_limit_executions_explored
                  << "\n";
        return 0;
    }
    catch (std::exception const& ex)
    {
        std::cerr << "error: " << ex.what() << "\n";
        return 1;
    }
}
