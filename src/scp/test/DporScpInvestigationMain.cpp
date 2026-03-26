// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/ScpDporDefaultScenario.h"
#include "util/Logging.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <string_view>
#include <type_traits>

namespace
{

struct CommandLineOptions
{
    std::size_t mWorkers{1};
    std::size_t mDepth{12};
    std::optional<uint32_t> mMaxNominationRound;
    std::optional<uint32_t> mMaxBallotingRound;
    std::optional<uint32_t> mMaxNominationTimersRound;
    std::optional<uint32_t> mMaxBallotingTimersRound;
    bool mStopOnPrepare{false};
    bool mStopOnCommit{false};
    bool mStopOnExternalize{false};
    bool mWithNominationTimers{false};
    bool mWithBallotingTimers{false};
    stellar::scpdpor::ScpDporDefaultScenario::DownloadTimeMode
        mDownloadTimeMode{
            stellar::scpdpor::ScpDporDefaultScenario::DownloadTimeMode::
                BelowThreshold};
    stellar::scpdpor::ScpDporDefaultScenario::TxSetStatusMode
        mTxSetStatusMode{
            stellar::scpdpor::ScpDporDefaultScenario::TxSetStatusMode::Valid};
    std::optional<std::size_t> mDumpInitialSteps;
    std::optional<std::chrono::seconds> mPrintStatsInterval;
    bool mDumpTerminalTrace{false};
    bool mDumpTerminalReplayTrace{false};
    dpor::model::CommunicationModel mCommunicationModel{
        dpor::model::CommunicationModel::Async};
};

std::size_t
defaultParallelWorkers();

std::string_view
downloadTimeModeName(
    stellar::scpdpor::ScpDporDefaultScenario::DownloadTimeMode mode);

std::string_view
txSetStatusModeName(
    stellar::scpdpor::ScpDporDefaultScenario::TxSetStatusMode mode);

std::string_view
communicationModelName(dpor::model::CommunicationModel model);

std::size_t
defaultParallelWorkers()
{
    auto const concurrency = std::thread::hardware_concurrency();
    return concurrency == 0 ? 2u : static_cast<std::size_t>(concurrency);
}

std::string_view
downloadTimeModeName(
    stellar::scpdpor::ScpDporDefaultScenario::DownloadTimeMode mode)
{
    using DownloadTimeMode =
        stellar::scpdpor::ScpDporDefaultScenario::DownloadTimeMode;
    switch (mode)
    {
    case DownloadTimeMode::BelowThreshold:
        return "below";
    case DownloadTimeMode::AboveThreshold:
        return "above";
    case DownloadTimeMode::Nondeterministic:
        return "nondet";
    }
    throw std::logic_error("unknown download-time mode");
}

std::string_view
txSetStatusModeName(
    stellar::scpdpor::ScpDporDefaultScenario::TxSetStatusMode mode)
{
    using TxSetStatusMode =
        stellar::scpdpor::ScpDporDefaultScenario::TxSetStatusMode;
    switch (mode)
    {
    case TxSetStatusMode::Valid:
        return "valid";
    case TxSetStatusMode::Waiting:
        return "waiting";
    case TxSetStatusMode::Invalid:
        return "invalid";
    case TxSetStatusMode::Nondeterministic:
        return "nondet";
    }
    throw std::logic_error("unknown txset-status mode");
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

void
printUsage(char const* argv0)
{
    auto const defaults = CommandLineOptions{};

    std::cerr << "Usage: " << argv0 << " [options]\n\n"
              << "Options:\n"
              << "  --workers N\n"
              << "      Worker count (default: " << defaults.mWorkers << ")\n"
              << "  --parallel\n"
              << "      Use the host parallelism shortcut"
              << " (default: off; this machine: "
              << defaultParallelWorkers() << " workers)\n"
              << "  --depth N\n"
              << "      DPOR max depth (default: " << defaults.mDepth
              << ")\n"
              << "  --max-nomination-round N"
              << " | --max-nomination-rounds N\n"
              << "      Stop when nomination round reaches N"
              << " (default: disabled)\n"
              << "  --max-balloting-round N"
              << " | --max-balloting-rounds N\n"
              << "      Stop when balloting round reaches N"
              << " (default: disabled)\n"
              << "  --max-nomination-timers-round N"
              << " | --max-nomination-timers-rounds N\n"
              << "      Only fire nomination timers in rounds <= N"
              << " (default: disabled)\n"
              << "  --max-balloting-timers-round N"
              << " | --max-balloting-timers-rounds N\n"
              << "      Only fire balloting timers for ballot numbers <= N"
              << " (default: disabled)\n"
              << "  --stop-on-prepare\n"
              << "      Stop at the prepare boundary (default: off)\n"
              << "  --stop-on-commit\n"
              << "      Stop at the commit-phase boundary"
              << " (CONFIRM or EXTERNALIZE; default: off)\n"
              << "  --stop-on-externalize\n"
              << "      Stop at the externalize boundary (default: off)\n"
              << "  --with-nomination-timers\n"
              << "      Enable nomination timers (default: "
              << (defaults.mWithNominationTimers ? "on" : "off") << ")\n"
              << "  --with-balloting-timers\n"
              << "      Enable balloting timers (default: "
              << (defaults.mWithBallotingTimers ? "on" : "off") << ")\n"
              << "  --download-time below|above|nondet\n"
              << "      Tx-set download wait-time mode relative to the"
              << " skip threshold (default: "
              << downloadTimeModeName(defaults.mDownloadTimeMode) << ")\n"
              << "  --txset-status valid|waiting|invalid|nondet\n"
              << "      Tx-set validation status mode (default: "
              << txSetStatusModeName(defaults.mTxSetStatusMode) << ")\n"
              << "  --fifo\n"
              << "      Use FIFO point-to-point delivery"
              << " (default communication model: "
              << communicationModelName(defaults.mCommunicationModel)
              << ")\n"
              << "  --print-stats N\n"
              << "      Print progress every N seconds"
              << " (default: disabled)\n"
              << "  --dump-initial-steps N\n"
              << "      Dump the first N thread steps and exit"
              << " (default: disabled)\n"
              << "  --dump-terminal-trace\n"
              << "      Dump the first terminal execution trace"
              << " (default: off)\n"
              << "  --dump-terminal-replay-trace\n"
              << "      Dump replay traces for the dumped terminal execution"
              << " (default: off)\n"
              << "  --help, -h\n"
              << "      Show this help message\n";
}

stellar::scpdpor::ScpDporDefaultScenario::DownloadTimeMode
parseDownloadTimeMode(std::string_view value)
{
    using DownloadTimeMode =
        stellar::scpdpor::ScpDporDefaultScenario::DownloadTimeMode;

    if (value == "nondet")
    {
        return DownloadTimeMode::Nondeterministic;
    }
    if (value == "below")
    {
        return DownloadTimeMode::BelowThreshold;
    }
    if (value == "above")
    {
        return DownloadTimeMode::AboveThreshold;
    }
    throw std::invalid_argument("unknown download-time mode: " +
                                std::string(value));
}

stellar::scpdpor::ScpDporDefaultScenario::TxSetStatusMode
parseTxSetStatusMode(std::string_view value)
{
    using TxSetStatusMode =
        stellar::scpdpor::ScpDporDefaultScenario::TxSetStatusMode;

    if (value == "valid")
    {
        return TxSetStatusMode::Valid;
    }
    if (value == "waiting")
    {
        return TxSetStatusMode::Waiting;
    }
    if (value == "invalid")
    {
        return TxSetStatusMode::Invalid;
    }
    if (value == "nondet")
    {
        return TxSetStatusMode::Nondeterministic;
    }
    throw std::invalid_argument("unknown txset-status mode: " +
                                std::string(value));
}

uint32_t
parseUint32Value(std::string_view arg, std::string_view value)
{
    auto const parsed = std::stoull(std::string(value));
    if (parsed > static_cast<unsigned long long>(
                     std::numeric_limits<uint32_t>::max()))
    {
        throw std::invalid_argument(std::string(arg) + " value out of range");
    }
    return static_cast<uint32_t>(parsed);
}

stellar::scpdpor::ScpDporDefaultScenario
makeScenario(CommandLineOptions const& options)
{
    auto const envelopeBoundaryModes =
        static_cast<int>(options.mStopOnPrepare) +
        static_cast<int>(options.mStopOnCommit) +
        static_cast<int>(options.mStopOnExternalize);
    if (envelopeBoundaryModes > 1)
    {
        throw std::invalid_argument(
            "--stop-on-prepare, --stop-on-commit, and "
            "--stop-on-externalize are mutually exclusive");
    }

    auto scenarioOptions =
        stellar::scpdpor::ScpDporDefaultScenario::makeDefaultOptions();
    scenarioOptions.mStopOnPrepare = options.mStopOnPrepare;
    scenarioOptions.mStopOnCommit = options.mStopOnCommit;
    scenarioOptions.mStopOnExternalize = options.mStopOnExternalize;
    scenarioOptions.mMaxNominationRound = options.mMaxNominationRound;
    scenarioOptions.mMaxBallotingRound = options.mMaxBallotingRound;
    scenarioOptions.mMaxNominationTimersRound =
        options.mMaxNominationTimersRound;
    scenarioOptions.mMaxBallotingTimersRound =
        options.mMaxBallotingTimersRound;
    scenarioOptions.mEnableNominationTimeouts = options.mWithNominationTimers;
    scenarioOptions.mEnableBallotingTimeouts = options.mWithBallotingTimers;
    scenarioOptions.mDownloadTimeMode = options.mDownloadTimeMode;
    scenarioOptions.mTxSetStatusMode = options.mTxSetStatusMode;
    return stellar::scpdpor::ScpDporDefaultScenario(
        std::move(scenarioOptions));
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

std::chrono::seconds
parsePositiveSecondsValue(std::string_view arg, std::string_view value)
{
    auto const parsed = std::stoull(std::string(value));
    if (parsed == 0)
    {
        throw std::invalid_argument(std::string(arg) +
                                    " requires a value greater than 0");
    }
    if (parsed > static_cast<unsigned long long>(
                     std::numeric_limits<std::chrono::seconds::rep>::max()))
    {
        throw std::invalid_argument(std::string(arg) + " value out of range");
    }
    return std::chrono::seconds(
        static_cast<std::chrono::seconds::rep>(parsed));
}

std::string_view
progressStateName(dpor::algo::ProgressState state)
{
    switch (state)
    {
    case dpor::algo::ProgressState::Running:
        return "running";
    case dpor::algo::ProgressState::Stopped:
        return "stopped";
    case dpor::algo::ProgressState::AllExplored:
        return "all-explored";
    }
    throw std::logic_error("unknown progress state");
}

void
printProgressSnapshot(std::ostream& out,
                      dpor::algo::ProgressSnapshot const& snapshot)
{
    auto const elapsedMS =
        std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(
            snapshot.elapsed);

    std::ostringstream line;
    line << "progress"
         << " state=" << progressStateName(snapshot.state)
         << " elapsed_ms=" << std::fixed << std::setprecision(3)
         << elapsedMS.count()
         << " terminal_executions=" << snapshot.terminal_executions
         << " full_executions=" << snapshot.full_executions
         << " error_executions=" << snapshot.error_executions
         << " depth_limit_executions=" << snapshot.depth_limit_executions
         << " active_workers=" << snapshot.active_workers << "/"
         << snapshot.max_workers << " queued_tasks=" << snapshot.queued_tasks
         << "/" << snapshot.max_queued_tasks << " counts_exact="
         << std::boolalpha << snapshot.counts_exact;
    out << line.str() << "\n" << std::flush;
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
    stellar::scpdpor::ScpDporDefaultScenario::
        ThreadReplayTraceInspection const& inspection)
{
    for (std::size_t stepIndex = 0; stepIndex < inspection.mSteps.size();
         ++stepIndex)
    {
        auto const& step = inspection.mSteps.at(stepIndex);
        out << "  step=" << stepIndex << " ";
        switch (step.mKind)
        {
        case stellar::scpdpor::ScpDporDefaultScenario::
            ThreadReplayTraceStep::Kind::Send:
            printEventLabel(out, stellar::scpdpor::EventLabel{*step.mSend});
            break;
        case stellar::scpdpor::ScpDporDefaultScenario::
            ThreadReplayTraceStep::Kind::NondeterministicChoice:
            printEventLabel(out, stellar::scpdpor::EventLabel{*step.mChoice});
            out << " selected=" << formatObservedValue(*step.mObservedValue);
            break;
        case stellar::scpdpor::ScpDporDefaultScenario::
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
        if (arg == "--parallel")
        {
            options.mWorkers = defaultParallelWorkers();
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
        if ((arg == "--max-nomination-round" ||
             arg == "--max-nomination-rounds") &&
            i + 1 < argc)
        {
            options.mMaxNominationRound =
                parseUint32Value(arg, argv[++i]);
            continue;
        }
        if ((arg == "--max-balloting-round" ||
             arg == "--max-balloting-rounds") &&
            i + 1 < argc)
        {
            options.mMaxBallotingRound =
                parseUint32Value(arg, argv[++i]);
            continue;
        }
        if ((arg == "--max-nomination-timers-round" ||
             arg == "--max-nomination-timers-rounds") &&
            i + 1 < argc)
        {
            options.mMaxNominationTimersRound =
                parseUint32Value(arg, argv[++i]);
            continue;
        }
        if ((arg == "--max-balloting-timers-round" ||
             arg == "--max-balloting-timers-rounds") &&
            i + 1 < argc)
        {
            options.mMaxBallotingTimersRound =
                parseUint32Value(arg, argv[++i]);
            continue;
        }
        if (arg == "--stop-on-prepare")
        {
            options.mStopOnPrepare = true;
            continue;
        }
        if (arg == "--stop-on-commit")
        {
            options.mStopOnCommit = true;
            continue;
        }
        if (arg == "--stop-on-externalize")
        {
            options.mStopOnExternalize = true;
            continue;
        }
        if (arg == "--with-nomination-timers")
        {
            options.mWithNominationTimers = true;
            continue;
        }
        if (arg == "--with-balloting-timers")
        {
            options.mWithBallotingTimers = true;
            continue;
        }
        if (arg == "--download-time" && i + 1 < argc)
        {
            options.mDownloadTimeMode = parseDownloadTimeMode(argv[++i]);
            continue;
        }
        if (arg == "--txset-status" && i + 1 < argc)
        {
            options.mTxSetStatusMode = parseTxSetStatusMode(argv[++i]);
            continue;
        }
        if (arg == "--dump-initial-steps" && i + 1 < argc)
        {
            options.mDumpInitialSteps =
                static_cast<std::size_t>(std::stoull(argv[++i]));
            continue;
        }
        if (arg == "--print-stats" && i + 1 < argc)
        {
            options.mPrintStatsInterval =
                parsePositiveSecondsValue(arg, argv[++i]);
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
        auto scenario = makeScenario(options);
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
        if (options.mPrintStatsInterval)
        {
            config.progress_report_interval =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    *options.mPrintStatsInterval);
            config.on_progress =
                [](dpor::algo::ProgressSnapshot const& snapshot) {
                    if (snapshot.state == dpor::algo::ProgressState::Running)
                    {
                        printProgressSnapshot(std::cout, snapshot);
                    }
                };
        }
        if (options.mDumpTerminalTrace || options.mDumpTerminalReplayTrace)
        {
            config.on_terminal_execution =
                [&](dpor::algo::TerminalExecutionT<
                        stellar::scpdpor::ScpDporValue> const& execution) {
                    auto const leaderTrace = execution.graph.thread_trace(
                        stellar::scpdpor::threadIdForNodeIndex(0));
                    auto const boundary =
                        scenario.inspectBoundary(0, leaderTrace);

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
