// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/ScpDporDefaultScenario.h"
#include "scp/test/ScpDporInvestigationUtils.h"
#include "scp/test/ScpDporTraceJson.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

namespace
{

// When nomination timers are enabled on the command line, cap the nomination
// timer at this round by default. Without a cap, a single node re-arms its
// nomination timer every round; because only one timer is then active the
// firing is a deterministic non-blocking receive rather than a branch point,
// so DPOR marches that lone execution straight to --depth instead of
// exploring. The explicit --max-nomination-timers-round flag overrides this.
constexpr uint32_t DEFAULT_MAX_NOMINATION_TIMERS_ROUND = 1;

struct CommandLineOptions
{
    std::optional<stellar::scpdpor::ScpDporDefaultScenario::InitialValueMode>
        mInitMode;
    std::size_t mWorkers{1};
    std::size_t mDepth{12};
    std::size_t mValidatorCount{
        stellar::scpdpor::ScpDporDefaultScenario::DEFAULT_VALIDATOR_COUNT};
    std::size_t mReplaySlotsPerNode{
        stellar::scpdpor::ScpDporReplaySupport::DEFAULT_REPLAY_SLOTS_PER_NODE};
    std::optional<std::size_t> mMaxQueuedTasks;
    std::optional<std::size_t> mSyncSteps;
    std::optional<std::size_t> mSplitPollIntervalSteps;
    std::optional<std::size_t> mProgressCounterFlushInterval;
    std::optional<std::size_t> mProgressPollIntervalSteps;
    std::optional<uint32_t> mMaxNominationRound;
    std::optional<uint32_t> mMaxBallotingRound;
    std::optional<uint32_t> mMaxNominationTimersRound;
    std::optional<uint32_t> mMaxBallotingTimersRound;
    bool mStopOnPrepare{false};
    bool mStopOnCommit{false};
    bool mStopOnExternalize{false};
    bool mWithNominationTimers{false};
    bool mWithBallotingTimers{false};
    bool mMustExternalize{false};
    bool mCheckAgreement{false};
    stellar::scpdpor::ScpDporDefaultScenario::DownloadTimeMode
        mDownloadTimeMode{stellar::scpdpor::ScpDporDefaultScenario::
                              DownloadTimeMode::BelowThreshold};
    stellar::scpdpor::ScpDporDefaultScenario::TxSetStatusMode mTxSetStatusMode{
        stellar::scpdpor::ScpDporDefaultScenario::TxSetStatusMode::AlwaysValid};
    bool mNominationAlwaysDownloading{false};
    std::optional<std::size_t> mInvalidProposerIndex;
    std::optional<uint32_t> mDownloadSucceedsInRound;
    bool mFailOnFirstBlocked{false};
    bool mFailOnFirstTerminal{false};
    bool mSerializeTerminalCallbacks{false};
    std::optional<std::chrono::seconds> mPrintStatsInterval;
    std::string mTraceDir{"dpor-traces"};
    std::optional<std::string> mReplayTraceJsonPath;
    std::optional<std::size_t> mReplayNodeIndex;
    bool mReplayAllNodes{false};
    dpor::model::CommunicationModel mCommunicationModel{
        dpor::model::CommunicationModel::Async};
};

std::size_t defaultParallelWorkers();

std::string_view
initModeName(stellar::scpdpor::ScpDporDefaultScenario::InitialValueMode mode);

std::string_view downloadTimeModeName(
    stellar::scpdpor::ScpDporDefaultScenario::DownloadTimeMode mode);

std::string_view txSetStatusModeName(
    stellar::scpdpor::ScpDporDefaultScenario::TxSetStatusMode mode);

std::string_view communicationModelName(dpor::model::CommunicationModel model);

std::string_view
terminalExecutionKindName(dpor::algo::TerminalExecutionKind kind);

std::size_t
defaultParallelWorkers()
{
    auto const concurrency = std::thread::hardware_concurrency();
    return concurrency == 0 ? 2u : static_cast<std::size_t>(concurrency);
}

std::string_view
initModeName(stellar::scpdpor::ScpDporDefaultScenario::InitialValueMode mode)
{
    using InitialValueMode =
        stellar::scpdpor::ScpDporDefaultScenario::InitialValueMode;
    switch (mode)
    {
    case InitialValueMode::Same:
        return "same";
    case InitialValueMode::Unique:
        return "unique";
    }
    throw std::logic_error("unknown init mode");
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
    case TxSetStatusMode::AlwaysValid:
        return "always-valid";
    case TxSetStatusMode::DownloadingThenValid:
        return "downloading-then-valid";
    case TxSetStatusMode::AlwaysDownloading:
        return "always-downloading";
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

std::string_view
terminalExecutionKindName(dpor::algo::TerminalExecutionKind kind)
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
    }
    throw std::logic_error("unknown terminal execution kind");
}

void
printUsage(char const* argv0)
{
    auto const defaults = CommandLineOptions{};
    auto const parallelDefaults = dpor::algo::ParallelVerifyOptions{};

    std::cerr << "Usage: " << argv0 << " [options]\n\n"
              << "Options:\n"
              << "  --workers N\n"
              << "      Worker count (default: " << defaults.mWorkers << ")\n"
              << "  --parallel\n"
              << "      Use the host parallelism shortcut"
              << " (default: off; this machine: " << defaultParallelWorkers()
              << " workers)\n"
              << "  --max-queued-tasks N\n"
              << "      Parallel worker queue budget; 0 uses DPOR default"
              << " (default: " << parallelDefaults.max_queued_tasks << ")\n"
              << "  --sync-steps N\n"
              << "      Parallel stop/progress synchronization interval;"
              << " 0 enables strict stop checks"
              << " (default: " << parallelDefaults.sync_steps << ")\n"
              << "  --split-poll-interval-steps N\n"
              << "      Check the idle-worker count every N nondeterministic"
              << " or receive branches before offering one alternative to a"
              << " parked worker; 0 or 1 checks every branch"
              << " (default: " << parallelDefaults.split_poll_interval_steps
              << ")\n"
              << "  --progress-counter-flush-interval N\n"
              << "      Flush worker-local progress counters after N terminal"
              << " executions; 0 uses DPOR default"
              << " (default: "
              << parallelDefaults.progress_counter_flush_interval << ")\n"
              << "  --progress-poll-interval-steps N\n"
              << "      Poll the progress clock every N progress checkpoints;"
              << " 0 or 1 polls every checkpoint"
              << " (default: " << parallelDefaults.progress_poll_interval_steps
              << ")\n"
              << "  --depth N\n"
              << "      DPOR max depth (default: " << defaults.mDepth << ")\n"
              << "  --nodes N | --validators N\n"
              << "      Validator count, currently 3 or 4; 4 uses a"
              << " 3-of-4 quorum set on every node"
              << " (default: " << defaults.mValidatorCount << ")\n"
              << "  --replay-slots-per-node N\n"
              << "      Partially replayed SCP nodes cached per validator and"
              << " worker thread; must be positive"
              << " (default: " << defaults.mReplaySlotsPerNode << ")\n"
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
              << "      Only fire nomination timers in rounds <= N;"
              << " with --with-nomination-timers this defaults to "
              << DEFAULT_MAX_NOMINATION_TIMERS_ROUND
              << " to bound the otherwise-unbounded nomination-round timer"
              << " loop (default without nomination timers: disabled)\n"
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
              << "  --must-externalize\n"
              << "      Require every maximal (full or blocked) execution to"
              << " include an EXTERNALIZE envelope from every node;"
              << " dumps replay trace on failure"
              << " (default: off)\n"
              << "  --check-agreement\n"
              << "      Require every maximal (full or blocked) execution's"
              << " EXTERNALIZE envelopes to agree on the externalized value;"
              << " dumps replay trace on failure"
              << " (default: off)\n"
              << "  --with-nomination-timers\n"
              << "      Enable nomination timers; caps nomination timers at"
              << " round " << DEFAULT_MAX_NOMINATION_TIMERS_ROUND
              << " unless --max-nomination-timers-round overrides (default: "
              << (defaults.mWithNominationTimers ? "on" : "off") << ")\n"
              << "  --with-balloting-timers\n"
              << "      Enable balloting timers (default: "
              << (defaults.mWithBallotingTimers ? "on" : "off") << ")\n"
              << "  --init same|unique\n"
              << "      Override initial nomination values across validators;"
              << " omitting the flag preserves the scenario default"
              << " (default override: disabled)\n"
              << "  --download-time below|above|nondet\n"
              << "      Tx-set download wait-time mode relative to the"
              << " download timeout; nondet re-chooses while below-threshold"
              << " and latches once timed out (default: "
              << downloadTimeModeName(defaults.mDownloadTimeMode) << ")\n"
              << "  --txset-status always-valid|downloading-then-valid"
              << "|always-downloading\n"
              << "      Tx-set status mode; downloading-then-valid explores"
              << " {downloading,valid}. Branching repeats only while"
              << " downloading and latches once valid;"
              << " always-valid and always-downloading do not branch"
              << " (default: " << txSetStatusModeName(defaults.mTxSetStatusMode)
              << ")\n"
              << "  --nomination-always-downloading\n"
              << "      Force nomination-time tx-set validation to return"
              << " downloading without consuming a tx-set-status branch"
              << " (default: "
              << (defaults.mNominationAlwaysDownloading ? "on" : "off") << ")\n"
              << "  --invalid-proposer N\n"
              << "      Treat proposer N's unique initial value as outright"
              << " invalid at every other node; requires --init unique"
              << " (default: disabled)\n"
              << "  --download-succeeds-in-round N\n"
              << "      Once a node emits its first PREPARE in ballot N,"
              << " tx-set validation returns valid from the next event onward"
              << " (default: disabled)\n"
              << "  --fifo\n"
              << "      Use FIFO point-to-point delivery"
              << " (default communication model: "
              << communicationModelName(defaults.mCommunicationModel) << ")\n"
              << "  --print-stats N\n"
              << "      Print progress every N seconds"
              << " (default: disabled)\n"
              << "  --fail-on-first-blocked\n"
              << "      Stop at the first blocked execution, write its JSON"
              << " trace, dump replay traces, and fail the command."
              << " Also fails if no blocked execution is found, since that"
              << " captures nothing (default: off)\n"
              << "  --fail-on-first-terminal\n"
              << "      Smoke-test mode: stop at the first terminal"
              << " execution, dump replay traces, and fail the command."
              << " Also fails if no terminal execution is found"
              << " (default: off)\n"
              << "  --serialize-terminal-callbacks\n"
              << "      Diagnostic mode: run terminal observer bodies under"
              << " one mutex to isolate callback concurrency"
              << " (default: off)\n"
              << "  --trace-dir DIR\n"
              << "      Directory for JSON trace files written on error"
              << " (default: " << defaults.mTraceDir << ")\n"
              << "  --replay-trace-json PATH\n"
              << "      Load PATH and replay its stored thread traces"
              << " instead of running DPOR (default: disabled)\n"
              << "  --replay-node N|all\n"
              << "      In replay mode, replay node N or all nodes"
              << " in focus-first order"
              << " (default replay scope: stored focus node)\n"
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

    if (value == "always-valid")
    {
        return TxSetStatusMode::AlwaysValid;
    }
    if (value == "downloading-then-valid")
    {
        return TxSetStatusMode::DownloadingThenValid;
    }
    if (value == "always-downloading")
    {
        return TxSetStatusMode::AlwaysDownloading;
    }
    throw std::invalid_argument("unknown txset-status mode: " +
                                std::string(value));
}

stellar::scpdpor::ScpDporDefaultScenario::InitialValueMode
parseInitMode(std::string_view value)
{
    using InitialValueMode =
        stellar::scpdpor::ScpDporDefaultScenario::InitialValueMode;

    if (value == initModeName(InitialValueMode::Same))
    {
        return InitialValueMode::Same;
    }
    if (value == initModeName(InitialValueMode::Unique))
    {
        return InitialValueMode::Unique;
    }
    throw std::invalid_argument("unknown init mode: " + std::string(value));
}

uint32_t
parseUint32Value(std::string_view arg, std::string_view value)
{
    auto const parsed = std::stoull(std::string(value));
    if (parsed >
        static_cast<unsigned long long>(std::numeric_limits<uint32_t>::max()))
    {
        throw std::invalid_argument(std::string(arg) + " value out of range");
    }
    return static_cast<uint32_t>(parsed);
}

uint32_t
parsePositiveUint32Value(std::string_view arg, std::string_view value)
{
    auto const parsed = parseUint32Value(arg, value);
    if (parsed == 0)
    {
        throw std::invalid_argument(std::string(arg) +
                                    " requires a value greater than 0");
    }
    return parsed;
}

std::size_t
parseSizeValue(std::string_view arg, std::string_view value)
{
    try
    {
        return static_cast<std::size_t>(std::stoull(std::string(value)));
    }
    catch (std::exception const& ex)
    {
        throw std::invalid_argument(
            std::string(arg) + " requires an unsigned integer: " + ex.what());
    }
}

std::size_t
parsePositiveSizeValue(std::string_view arg, std::string_view value)
{
    auto const parsed = parseSizeValue(arg, value);
    if (parsed == 0)
    {
        throw std::invalid_argument(std::string(arg) +
                                    " requires a value greater than 0");
    }
    return parsed;
}

std::size_t
parseValidatorCountValue(std::string_view arg, std::string_view value)
{
    auto const validatorCount = parseSizeValue(arg, value);
    if (!stellar::scpdpor::ScpDporDefaultScenario::isSupportedValidatorCount(
            validatorCount))
    {
        throw std::invalid_argument(
            std::string(arg) + " currently supports only 3 or 4 validators");
    }
    return validatorCount;
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
        stellar::scpdpor::ScpDporDefaultScenario::makeDefaultOptions(
            options.mValidatorCount);
    if (options.mInitMode)
    {
        scenarioOptions.mInitialValues =
            stellar::scpdpor::ScpDporDefaultScenario::makeInitialValues(
                *options.mInitMode, scenarioOptions.mValidators.size());
    }
    if (options.mInvalidProposerIndex)
    {
        auto const proposerIndex = *options.mInvalidProposerIndex;
        if (proposerIndex >= scenarioOptions.mValidators.size())
        {
            throw std::invalid_argument(
                "--invalid-proposer is outside the validator range");
        }
        std::set<stellar::Value> uniqueInitialValues(
            scenarioOptions.mInitialValues.begin(),
            scenarioOptions.mInitialValues.end());
        if (uniqueInitialValues.size() != scenarioOptions.mInitialValues.size())
        {
            throw std::invalid_argument(
                "--invalid-proposer requires unique initial values; use "
                "--init unique");
        }
        scenarioOptions.mOutrightInvalidValuesByNode.resize(
            scenarioOptions.mValidators.size());
        for (std::size_t nodeIndex = 0;
             nodeIndex < scenarioOptions.mValidators.size(); ++nodeIndex)
        {
            if (nodeIndex != proposerIndex)
            {
                scenarioOptions.mOutrightInvalidValuesByNode.at(nodeIndex)
                    .push_back(
                        scenarioOptions.mInitialValues.at(proposerIndex));
            }
        }
    }
    scenarioOptions.mStopOnPrepare = options.mStopOnPrepare;
    scenarioOptions.mStopOnCommit = options.mStopOnCommit;
    scenarioOptions.mStopOnExternalize = options.mStopOnExternalize;
    scenarioOptions.mMaxNominationRound = options.mMaxNominationRound;
    scenarioOptions.mMaxBallotingRound = options.mMaxBallotingRound;
    scenarioOptions.mMaxNominationTimersRound =
        options.mMaxNominationTimersRound;
    scenarioOptions.mMaxBallotingTimersRound = options.mMaxBallotingTimersRound;
    scenarioOptions.mEnableNominationTimeouts = options.mWithNominationTimers;
    scenarioOptions.mEnableBallotingTimeouts = options.mWithBallotingTimers;
    scenarioOptions.mDownloadTimeMode = options.mDownloadTimeMode;
    scenarioOptions.mTxSetStatusMode = options.mTxSetStatusMode;
    scenarioOptions.mNominationAlwaysDownloading =
        options.mNominationAlwaysDownloading;
    scenarioOptions.mDownloadSucceedsInRound = options.mDownloadSucceedsInRound;
    return stellar::scpdpor::ScpDporDefaultScenario(
        std::move(scenarioOptions), options.mReplaySlotsPerNode);
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

std::vector<std::size_t>
focusFirstNodeOrder(std::size_t validatorCount, std::size_t focusNodeIndex)
{
    if (focusNodeIndex >= validatorCount)
    {
        throw std::out_of_range("focus node index is out of range");
    }

    std::vector<std::size_t> order;
    order.reserve(validatorCount);
    order.push_back(focusNodeIndex);
    for (std::size_t nodeIndex = 0; nodeIndex < validatorCount; ++nodeIndex)
    {
        if (nodeIndex != focusNodeIndex)
        {
            order.push_back(nodeIndex);
        }
    }
    return order;
}

stellar::scpdpor::ThreadTrace const&
findThreadTrace(stellar::scpdpor::TraceBundle const& bundle,
                dpor::model::ThreadId threadID)
{
    auto const it =
        std::find_if(bundle.mThreadTraces.begin(), bundle.mThreadTraces.end(),
                     [threadID](auto const& record) {
                         return record.mThreadID == threadID;
                     });
    if (it == bundle.mThreadTraces.end())
    {
        throw std::logic_error("missing thread trace for requested thread");
    }
    return it->mTrace;
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
    return std::chrono::seconds(static_cast<std::chrono::seconds::rep>(parsed));
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
         << " blocked_executions=" << snapshot.blocked_executions
         << " error_executions=" << snapshot.error_executions
         << " depth_limit_executions=" << snapshot.depth_limit_executions
         << " active_workers=" << snapshot.active_workers << "/"
         << snapshot.max_workers << " queued_tasks=" << snapshot.queued_tasks
         << "/" << snapshot.max_queued_tasks
         << " counts_exact=" << std::boolalpha << snapshot.counts_exact;
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
            else if constexpr (std::is_same_v<Label,
                                              stellar::scpdpor::
                                                  NondeterministicChoiceLabel>)
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
    case ReplayDebugEvent::Kind::RejectOutrightInvalidValue:
        out << "reject-outright-invalid-value";
        return;
    }
}

void
printThreadReplayTrace(
    std::ostream& out, uint64_t slotIndex,
    stellar::scpdpor::ScpDporDefaultScenario::ThreadReplayTraceInspection const&
        inspection)
{
    for (std::size_t stepIndex = 0; stepIndex < inspection.mSteps.size();
         ++stepIndex)
    {
        auto const& step = inspection.mSteps.at(stepIndex);
        out << "  step=" << stepIndex << " ";
        switch (step.mKind)
        {
        case stellar::scpdpor::ScpDporDefaultScenario::ThreadReplayTraceStep::
            Kind::Send:
            printEventLabel(out, stellar::scpdpor::EventLabel{*step.mSend});
            break;
        case stellar::scpdpor::ScpDporDefaultScenario::ThreadReplayTraceStep::
            Kind::NondeterministicChoice:
            printEventLabel(out, stellar::scpdpor::EventLabel{*step.mChoice});
            out << " selected=" << formatObservedValue(*step.mObservedValue);
            break;
        case stellar::scpdpor::ScpDporDefaultScenario::ThreadReplayTraceStep::
            Kind::Receive:
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
    if (inspection.mReplayErrorMessage)
    {
        out << "  replay-error=" << *inspection.mReplayErrorMessage << "\n";
    }
    if (inspection.mBoundaryEnvelope)
    {
        out << "  boundary="
            << stellar::scpdpor::makeEnvelopeValue(
                   slotIndex, *inspection.mBoundaryEnvelope)
            << "\n";
    }
}

bool
isExternalizeEnvelope(stellar::SCPEnvelope const& envelope)
{
    return envelope.statement.pledges.type() == stellar::SCP_ST_EXTERNALIZE;
}

struct ExternalizedValueRecord
{
    std::size_t mNodeIndex{};
    stellar::Value mValue;
};

struct AgreementFailure
{
    ExternalizedValueRecord mReference;
    ExternalizedValueRecord mConflicting;
};

std::optional<stellar::Value>
findExternalizedValue(std::vector<stellar::SCPEnvelope> const& envelopes)
{
    for (auto const& envelope : envelopes)
    {
        if (isExternalizeEnvelope(envelope))
        {
            return envelope.statement.pledges.externalize().commit.value;
        }
    }
    return std::nullopt;
}

std::optional<std::size_t>
findNodeMissingExternalize(
    stellar::scpdpor::ScpDporDefaultScenario const& scenario,
    dpor::algo::TerminalExecutionT<stellar::scpdpor::ScpDporValue> const&
        execution)
{
    if (!stellar::scpdpor::isMaximalExecution(execution))
    {
        return std::nullopt;
    }

    for (std::size_t nodeIndex = 0;
         nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
    {
        auto const trace = execution.graph.thread_trace(
            stellar::scpdpor::threadIdForNodeIndex(nodeIndex));
        auto const inspection =
            scenario.inspectEmittedEnvelopes(nodeIndex, trace);
        auto const hasExternalize =
            std::any_of(inspection.mEmittedEnvelopes.begin(),
                        inspection.mEmittedEnvelopes.end(),
                        [](stellar::SCPEnvelope const& envelope) {
                            return isExternalizeEnvelope(envelope);
                        });
        if (!hasExternalize)
        {
            return nodeIndex;
        }
    }
    return std::nullopt;
}

std::optional<AgreementFailure>
findAgreementFailure(
    stellar::scpdpor::ScpDporDefaultScenario const& scenario,
    dpor::algo::TerminalExecutionT<stellar::scpdpor::ScpDporValue> const&
        execution)
{
    if (!stellar::scpdpor::isMaximalExecution(execution))
    {
        return std::nullopt;
    }

    std::optional<ExternalizedValueRecord> reference;
    for (std::size_t nodeIndex = 0;
         nodeIndex < scenario.options().mValidators.size(); ++nodeIndex)
    {
        auto const trace = execution.graph.thread_trace(
            stellar::scpdpor::threadIdForNodeIndex(nodeIndex));
        auto const inspection =
            scenario.inspectEmittedEnvelopes(nodeIndex, trace);
        auto const externalizedValue =
            findExternalizedValue(inspection.mEmittedEnvelopes);
        if (!externalizedValue)
        {
            continue;
        }

        ExternalizedValueRecord current{nodeIndex, *externalizedValue};
        if (!reference)
        {
            reference = std::move(current);
            continue;
        }

        if (current.mValue != reference->mValue)
        {
            return AgreementFailure{*reference, std::move(current)};
        }
    }

    return std::nullopt;
}

void
dumpTerminalExecution(std::ostream& out,
                      stellar::scpdpor::ScpDporDefaultScenario const& scenario,
                      stellar::scpdpor::TraceBundle const& bundle,
                      bool dumpReplayTrace)
{
    auto const& leaderTrace =
        findThreadTrace(bundle, stellar::scpdpor::threadIdForNodeIndex(0));
    auto const boundary = scenario.inspectBoundary(0, leaderTrace);

    out << "terminal-kind=" << terminalExecutionKindName(bundle.mTerminal.mKind)
        << " leader-boundary=" << (boundary.mReachedBoundary ? "true" : "false")
        << "\n";

    if (!dumpReplayTrace)
    {
        return;
    }

    for (auto const nodeIndex :
         focusFirstNodeOrder(scenario.options().mValidators.size(),
                             bundle.mTerminal.mFocusNodeIndex))
    {
        auto const tid = stellar::scpdpor::threadIdForNodeIndex(nodeIndex);
        auto const& trace = findThreadTrace(bundle, tid);
        auto inspection = scenario.inspectThreadReplayTrace(nodeIndex, trace);
        out << "thread=" << tid << " replay\n";
        printThreadReplayTrace(out, scenario.options().mSlotIndex, inspection);
    }
}

void
dumpErrorExecution(std::ostream& out,
                   stellar::scpdpor::ScpDporDefaultScenario const& scenario,
                   stellar::scpdpor::TraceBundle const& bundle)
{
    out << "terminal-kind=error"
        << " node-index=" << bundle.mTerminal.mFocusNodeIndex
        << " thread=" << bundle.mTerminal.mFocusThreadID << "\n";

    auto dumpThreadReplay = [&](std::size_t nodeIndex) {
        auto const threadID = stellar::scpdpor::threadIdForNodeIndex(nodeIndex);
        auto const& trace = findThreadTrace(bundle, threadID);
        out << "thread=" << threadID << " replay\n";
        try
        {
            auto const inspection =
                scenario.inspectThreadReplayTrace(nodeIndex, trace);
            printThreadReplayTrace(out, scenario.options().mSlotIndex,
                                   inspection);
        }
        catch (std::exception const& ex)
        {
            out << "  replay-dump-error=" << ex.what() << "\n";
        }
    };

    for (auto const nodeIndex :
         focusFirstNodeOrder(scenario.options().mValidators.size(),
                             bundle.mTerminal.mFocusNodeIndex))
    {
        dumpThreadReplay(nodeIndex);
    }
}

std::filesystem::path
generateTraceFilePath(std::string const& traceDir)
{
    namespace fs = std::filesystem;
    fs::create_directories(traceDir);

    auto const now = std::chrono::system_clock::now();
    auto const timeT = std::chrono::system_clock::to_time_t(now);
    auto const ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch()) %
                    1000;

    struct tm timeBuf{};
    gmtime_r(&timeT, &timeBuf);

    std::ostringstream filename;
    filename << "trace-" << std::put_time(&timeBuf, "%Y%m%d-%H%M%S") << "-"
             << std::setfill('0') << std::setw(3) << ms.count() << ".json";
    return fs::path(traceDir) / filename.str();
}

void
writeTraceBundleToTraceDir(std::string const& traceDir,
                           stellar::scpdpor::TraceBundle const& bundle)
{
    auto const path = generateTraceFilePath(traceDir);
    stellar::scpdpor::writeTraceBundle(path, bundle);
    std::cout << "trace-json=" << path.string() << "\n" << std::flush;
}

std::vector<std::size_t>
replayNodeOrder(CommandLineOptions const& options,
                stellar::scpdpor::TraceBundle const& bundle)
{
    auto const validatorCount = bundle.mOptions.mValidators.size();
    if (options.mReplayAllNodes)
    {
        return focusFirstNodeOrder(validatorCount,
                                   bundle.mTerminal.mFocusNodeIndex);
    }
    if (options.mReplayNodeIndex)
    {
        if (*options.mReplayNodeIndex >= validatorCount)
        {
            throw std::invalid_argument("--replay-node is out of range");
        }
        return {*options.mReplayNodeIndex};
    }
    return {bundle.mTerminal.mFocusNodeIndex};
}

void
dumpReplayBundle(std::ostream& out, CommandLineOptions const& options,
                 stellar::scpdpor::ScpDporDefaultScenario const& scenario,
                 stellar::scpdpor::TraceBundle const& bundle)
{
    if (bundle.mTerminal.mKind == dpor::algo::TerminalExecutionKind::Error)
    {
        out << "terminal-kind=error"
            << " node-index=" << bundle.mTerminal.mFocusNodeIndex
            << " thread=" << bundle.mTerminal.mFocusThreadID << "\n";
    }
    else
    {
        auto const& leaderTrace =
            findThreadTrace(bundle, stellar::scpdpor::threadIdForNodeIndex(0));
        auto const boundary = scenario.inspectBoundary(0, leaderTrace);
        out << "terminal-kind="
            << terminalExecutionKindName(bundle.mTerminal.mKind)
            << " leader-boundary="
            << (boundary.mReachedBoundary ? "true" : "false") << "\n";
    }
    if (bundle.mTerminal.mFailureMessage)
    {
        out << "failure-message=" << *bundle.mTerminal.mFailureMessage << "\n";
    }

    for (auto const nodeIndex : replayNodeOrder(options, bundle))
    {
        auto const threadID = stellar::scpdpor::threadIdForNodeIndex(nodeIndex);
        auto const& trace = findThreadTrace(bundle, threadID);
        auto const inspection =
            scenario.inspectThreadReplayTrace(nodeIndex, trace);
        out << "thread=" << threadID << " replay\n";
        printThreadReplayTrace(out, scenario.options().mSlotIndex, inspection);
    }
}

std::string
failOnFirstBlockedFailureMessage(
    stellar::scpdpor::InvestigationBlockedExecution const& blocked)
{
    std::ostringstream message;
    message << "stopped at first blocked execution because "
            << "--fail-on-first-blocked was set"
            << " (node-index=" << blocked.mNodeIndex
            << " thread=" << blocked.mThreadID << ")";
    return message.str();
}

std::string
failOnFirstTerminalFailureMessage()
{
    return "stopped at first terminal execution because "
           "--fail-on-first-terminal was set for smoke testing";
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
            options.mWorkers = static_cast<std::size_t>(std::stoull(argv[++i]));
            continue;
        }
        if (arg == "--max-queued-tasks" && i + 1 < argc)
        {
            options.mMaxQueuedTasks = parseSizeValue(arg, argv[++i]);
            continue;
        }
        if (arg == "--sync-steps" && i + 1 < argc)
        {
            options.mSyncSteps = parseSizeValue(arg, argv[++i]);
            continue;
        }
        if (arg == "--split-poll-interval-steps" && i + 1 < argc)
        {
            options.mSplitPollIntervalSteps = parseSizeValue(arg, argv[++i]);
            continue;
        }
        if (arg == "--progress-counter-flush-interval" && i + 1 < argc)
        {
            options.mProgressCounterFlushInterval =
                parseSizeValue(arg, argv[++i]);
            continue;
        }
        if (arg == "--progress-poll-interval-steps" && i + 1 < argc)
        {
            options.mProgressPollIntervalSteps = parseSizeValue(arg, argv[++i]);
            continue;
        }
        if (arg == "--depth" && i + 1 < argc)
        {
            options.mDepth = static_cast<std::size_t>(std::stoull(argv[++i]));
            continue;
        }
        if ((arg == "--nodes" || arg == "--validators") && i + 1 < argc)
        {
            options.mValidatorCount = parseValidatorCountValue(arg, argv[++i]);
            continue;
        }
        if (arg == "--replay-slots-per-node" && i + 1 < argc)
        {
            options.mReplaySlotsPerNode =
                parsePositiveSizeValue(arg, argv[++i]);
            continue;
        }
        if ((arg == "--max-nomination-round" ||
             arg == "--max-nomination-rounds") &&
            i + 1 < argc)
        {
            options.mMaxNominationRound = parseUint32Value(arg, argv[++i]);
            continue;
        }
        if ((arg == "--max-balloting-round" ||
             arg == "--max-balloting-rounds") &&
            i + 1 < argc)
        {
            options.mMaxBallotingRound = parseUint32Value(arg, argv[++i]);
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
            options.mMaxBallotingTimersRound = parseUint32Value(arg, argv[++i]);
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
        if (arg == "--must-externalize")
        {
            options.mMustExternalize = true;
            continue;
        }
        if (arg == "--check-agreement")
        {
            options.mCheckAgreement = true;
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
        if (arg == "--init" && i + 1 < argc)
        {
            options.mInitMode = parseInitMode(argv[++i]);
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
        if (arg == "--nomination-always-downloading")
        {
            options.mNominationAlwaysDownloading = true;
            continue;
        }
        if (arg == "--invalid-proposer" && i + 1 < argc)
        {
            options.mInvalidProposerIndex = parseSizeValue(arg, argv[++i]);
            continue;
        }
        if (arg == "--download-succeeds-in-round" && i + 1 < argc)
        {
            options.mDownloadSucceedsInRound =
                parsePositiveUint32Value(arg, argv[++i]);
            continue;
        }
        if (arg == "--print-stats" && i + 1 < argc)
        {
            options.mPrintStatsInterval =
                parsePositiveSecondsValue(arg, argv[++i]);
            continue;
        }
        if (arg == "--fail-on-first-terminal")
        {
            options.mFailOnFirstTerminal = true;
            continue;
        }
        if (arg == "--fail-on-first-blocked")
        {
            options.mFailOnFirstBlocked = true;
            continue;
        }
        if (arg == "--serialize-terminal-callbacks")
        {
            options.mSerializeTerminalCallbacks = true;
            continue;
        }
        if (arg == "--trace-dir" && i + 1 < argc)
        {
            options.mTraceDir = argv[++i];
            continue;
        }
        if (arg == "--replay-trace-json" && i + 1 < argc)
        {
            options.mReplayTraceJsonPath = argv[++i];
            continue;
        }
        if (arg == "--replay-node" && i + 1 < argc)
        {
            std::string_view value(argv[++i]);
            if (value == "all")
            {
                options.mReplayAllNodes = true;
                options.mReplayNodeIndex.reset();
            }
            else
            {
                options.mReplayAllNodes = false;
                options.mReplayNodeIndex = parseSizeValue(arg, value);
            }
            continue;
        }
        throw std::invalid_argument("unknown or incomplete argument: " +
                                    std::string(arg));
    }
    if ((options.mReplayAllNodes || options.mReplayNodeIndex) &&
        !options.mReplayTraceJsonPath)
    {
        throw std::invalid_argument(
            "--replay-node requires --replay-trace-json");
    }
    // Bound the nomination-round timer loop by default when nomination timers
    // are enabled; an explicit --max-nomination-timers-round wins.
    if (options.mWithNominationTimers && !options.mMaxNominationTimersRound)
    {
        options.mMaxNominationTimersRound = DEFAULT_MAX_NOMINATION_TIMERS_ROUND;
    }
    return options;
}

} // namespace

int
main(int argc, char* argv[])
{
    try
    {
        stellar::enableAssertThrowMode();
        stellar::Logging::init();
        stellar::Logging::setFmt("<dpor>");
        stellar::Logging::setLogLevel(stellar::LogLevel::LVL_WARNING, nullptr);

        auto const options = parseOptions(argv[0], argc, argv);
        if (options.mReplayTraceJsonPath)
        {
            auto const bundle = stellar::scpdpor::loadTraceBundle(
                *options.mReplayTraceJsonPath);
            auto const scenario = stellar::scpdpor::ScpDporDefaultScenario(
                bundle.mOptions, options.mReplaySlotsPerNode);
            dumpReplayBundle(std::cout, options, scenario, bundle);
            return 0;
        }

        auto scenario = makeScenario(options);
        dpor::algo::DporConfigT<stellar::scpdpor::ScpDporValue> config;
        config.program =
            stellar::scpdpor::wrapProgramExceptionsAsErrorExecutions(
                scenario.makeProgram());
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
        std::recursive_mutex terminalExecutionMutex;
        bool dumpedTerminalExecution = false;
        std::optional<std::string> failureMessage;
        config
            .on_terminal_execution = [&](dpor::algo::TerminalExecutionT<
                                         stellar::scpdpor::ScpDporValue> const&
                                             execution) {
            std::unique_lock<std::recursive_mutex> serializedCallbackGuard;
            if (options.mSerializeTerminalCallbacks)
            {
                serializedCallbackGuard =
                    std::unique_lock<std::recursive_mutex>(
                        terminalExecutionMutex);
            }

            auto const errorExecution = stellar::scpdpor::findErrorExecution(
                scenario.options().mValidators.size(), execution);
            if (errorExecution)
            {
                std::lock_guard<std::recursive_mutex> guard(
                    terminalExecutionMutex);
                if (!failureMessage)
                {
                    failureMessage = errorExecution->mMessage;
                }
                if (!dumpedTerminalExecution)
                {
                    auto const bundle = stellar::scpdpor::makeTraceBundle(
                        scenario, execution, options.mCommunicationModel,
                        stellar::scpdpor::TerminalMeta{
                            .mKind = execution.kind,
                            .mFailureMessage = errorExecution->mMessage,
                            .mFocusNodeIndex = errorExecution->mNodeIndex,
                            .mFocusThreadID = errorExecution->mThreadID});
                    writeTraceBundleToTraceDir(options.mTraceDir, bundle);
                    dumpErrorExecution(std::cout, scenario, bundle);
                    dumpedTerminalExecution = true;
                }
                return dpor::algo::TerminalExecutionAction::Stop;
            }

            if (options.mMustExternalize)
            {
                auto const missingNodeIndex =
                    findNodeMissingExternalize(scenario, execution);
                if (missingNodeIndex)
                {
                    std::lock_guard<std::recursive_mutex> guard(
                        terminalExecutionMutex);
                    if (!failureMessage)
                    {
                        std::ostringstream message;
                        message
                            << terminalExecutionKindName(execution.kind)
                            << " execution missing EXTERNALIZE"
                            << " envelope from node-index=" << *missingNodeIndex
                            << " thread="
                            << stellar::scpdpor::threadIdForNodeIndex(
                                   *missingNodeIndex);
                        failureMessage = message.str();
                    }
                    if (!dumpedTerminalExecution)
                    {
                        auto const bundle = stellar::scpdpor::makeTraceBundle(
                            scenario, execution, options.mCommunicationModel,
                            stellar::scpdpor::TerminalMeta{
                                .mKind = execution.kind,
                                .mFailureMessage = failureMessage,
                                .mFocusNodeIndex = *missingNodeIndex,
                                .mFocusThreadID =
                                    stellar::scpdpor::threadIdForNodeIndex(
                                        *missingNodeIndex)});
                        writeTraceBundleToTraceDir(options.mTraceDir, bundle);
                        dumpTerminalExecution(std::cout, scenario, bundle,
                                              true);
                        dumpedTerminalExecution = true;
                    }
                    return dpor::algo::TerminalExecutionAction::Stop;
                }
            }

            if (options.mCheckAgreement)
            {
                auto const agreementFailure =
                    findAgreementFailure(scenario, execution);
                if (agreementFailure)
                {
                    std::lock_guard<std::recursive_mutex> guard(
                        terminalExecutionMutex);
                    if (!failureMessage)
                    {
                        std::ostringstream message;
                        message
                            << terminalExecutionKindName(execution.kind)
                            << " execution has conflicting"
                            << " EXTERNALIZE values between"
                            << " node-index="
                            << agreementFailure->mReference.mNodeIndex
                            << " thread="
                            << stellar::scpdpor::threadIdForNodeIndex(
                                   agreementFailure->mReference.mNodeIndex)
                            << " and node-index="
                            << agreementFailure->mConflicting.mNodeIndex
                            << " thread="
                            << stellar::scpdpor::threadIdForNodeIndex(
                                   agreementFailure->mConflicting.mNodeIndex);
                        failureMessage = message.str();
                    }
                    if (!dumpedTerminalExecution)
                    {
                        auto const bundle = stellar::scpdpor::makeTraceBundle(
                            scenario, execution, options.mCommunicationModel,
                            stellar::scpdpor::TerminalMeta{
                                .mKind = execution.kind,
                                .mFailureMessage = failureMessage,
                                .mFocusNodeIndex =
                                    agreementFailure->mConflicting.mNodeIndex,
                                .mFocusThreadID =
                                    stellar::scpdpor::threadIdForNodeIndex(
                                        agreementFailure->mConflicting
                                            .mNodeIndex)});
                        writeTraceBundleToTraceDir(options.mTraceDir, bundle);
                        dumpTerminalExecution(std::cout, scenario, bundle,
                                              true);
                        dumpedTerminalExecution = true;
                    }
                    return dpor::algo::TerminalExecutionAction::Stop;
                }
            }

            if (options.mFailOnFirstBlocked)
            {
                auto const blockedExecution =
                    stellar::scpdpor::findBlockedExecution(
                        scenario.options().mValidators.size(), execution);
                if (blockedExecution)
                {
                    std::lock_guard<std::recursive_mutex> guard(
                        terminalExecutionMutex);
                    if (!failureMessage)
                    {
                        failureMessage =
                            failOnFirstBlockedFailureMessage(*blockedExecution);
                    }
                    if (!dumpedTerminalExecution)
                    {
                        auto const bundle = stellar::scpdpor::makeTraceBundle(
                            scenario, execution, options.mCommunicationModel,
                            stellar::scpdpor::TerminalMeta{
                                .mKind = execution.kind,
                                .mFailureMessage = failureMessage,
                                .mFocusNodeIndex = blockedExecution->mNodeIndex,
                                .mFocusThreadID = blockedExecution->mThreadID});
                        writeTraceBundleToTraceDir(options.mTraceDir, bundle);
                        dumpTerminalExecution(std::cout, scenario, bundle,
                                              true);
                        dumpedTerminalExecution = true;
                    }
                    return dpor::algo::TerminalExecutionAction::Stop;
                }
            }

            if (options.mFailOnFirstTerminal)
            {
                std::lock_guard<std::recursive_mutex> guard(
                    terminalExecutionMutex);
                if (!failureMessage)
                {
                    failureMessage = failOnFirstTerminalFailureMessage();
                }
                if (!dumpedTerminalExecution)
                {
                    auto const bundle = stellar::scpdpor::makeTraceBundle(
                        scenario, execution, options.mCommunicationModel,
                        stellar::scpdpor::TerminalMeta{
                            .mKind = dpor::algo::TerminalExecutionKind::Error,
                            .mFailureMessage = failureMessage,
                            .mFocusNodeIndex = 0,
                            .mFocusThreadID =
                                stellar::scpdpor::threadIdForNodeIndex(0)});
                    writeTraceBundleToTraceDir(options.mTraceDir, bundle);
                    dumpErrorExecution(std::cout, scenario, bundle);
                }
                dumpedTerminalExecution = true;
                return dpor::algo::TerminalExecutionAction::Stop;
            }

            return dpor::algo::TerminalExecutionAction::Continue;
        };
        config.on_fatal_error =
            [](dpor::algo::FatalErrorContextT<
                stellar::scpdpor::ScpDporValue> const& context) {
                std::string message = "<unknown exception>";
                try
                {
                    std::rethrow_exception(context.exception);
                }
                catch (std::exception const& ex)
                {
                    message = ex.what();
                }
                catch (...)
                {
                }
                std::cerr
                    << "fatal-error: " << message << "\n"
                    << dpor::model::format_graph(
                           context.graph,
                           [](stellar::scpdpor::ScpDporValue const& value) {
                               std::ostringstream out;
                               out << value;
                               return out.str();
                           })
                    << std::flush;
            };

        dpor::algo::ParallelVerifyOptions parallelOptions;
        parallelOptions.max_workers = options.mWorkers;
        if (options.mMaxQueuedTasks)
        {
            parallelOptions.max_queued_tasks = *options.mMaxQueuedTasks;
        }
        if (options.mSyncSteps)
        {
            parallelOptions.sync_steps = *options.mSyncSteps;
        }
        if (options.mSplitPollIntervalSteps)
        {
            parallelOptions.split_poll_interval_steps =
                *options.mSplitPollIntervalSteps;
        }
        if (options.mProgressCounterFlushInterval)
        {
            parallelOptions.progress_counter_flush_interval =
                *options.mProgressCounterFlushInterval;
        }
        if (options.mProgressPollIntervalSteps)
        {
            parallelOptions.progress_poll_interval_steps =
                *options.mProgressPollIntervalSteps;
        }

        auto const result =
            options.mWorkers > 1
                ? dpor::algo::verify_parallel(config, parallelOptions)
                : dpor::algo::verify(config);

        std::cout << "kind="
                  << (result.all_explored() ? "all-explored" : "stopped")
                  << " executions=" << result.executions_explored
                  << " full=" << result.full_executions_explored
                  << " blocked=" << result.blocked_executions_explored
                  << " error=" << result.error_executions_explored
                  << " depth-limit=" << result.depth_limit_executions_explored
                  << "\n"
                  << std::flush;
        if (failureMessage)
        {
            std::cout << "error: " << *failureMessage << "\n" << std::flush;
            return 1;
        }
        // A capture mode that never fired explored the whole space without
        // finding what it was asked to stop on, so it wrote no trace. Exiting 0
        // there is indistinguishable from a clean run, which lets a too-shallow
        // --depth silently turn the check into a no-op.
        if (options.mFailOnFirstBlocked || options.mFailOnFirstTerminal)
        {
            char const* const requested = options.mFailOnFirstBlocked
                                              ? "--fail-on-first-blocked"
                                              : "--fail-on-first-terminal";
            std::cout << "error: " << requested
                      << " was set but no matching execution was found in "
                      << result.executions_explored << " executions at --depth "
                      << options.mDepth << ", so no trace was captured";
            if (options.mFailOnFirstBlocked &&
                result.depth_limit_executions_explored > 0)
            {
                std::cout << "; " << result.depth_limit_executions_explored
                          << " execution(s) hit the depth limit, so a greater"
                             " --depth may reach a blocked execution";
            }
            std::cout << "\n" << std::flush;
            return 1;
        }
        return 0;
    }
    catch (std::exception const& ex)
    {
        std::cerr << "error: " << ex.what() << "\n";
        return 1;
    }
}
