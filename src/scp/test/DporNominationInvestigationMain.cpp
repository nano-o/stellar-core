// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationInvestigation.h"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string_view>

namespace
{

using namespace stellar::dpor_nomination_investigation;

struct CommandLineOptions
{
    std::size_t mWorkers = 8;
    std::size_t mNumNodes = kDefaultValidatorCount;
    bool mNominationOnly = false;
    bool mCheckDeadlock = false;
    bool mCheckTermination = false;
    bool mCheckExternalize = false;
    bool mCheckExternalizeDivergence = false;
    bool mPrintSkipExternalize = false;
    TimeoutSettings mTimeoutSettings;
    TimerSetLimitSettings mTimerSetLimitSettings;
    std::optional<std::size_t> mDepthOverride;
    std::optional<InvestigationScenario::Id> mScenario;
};

void
printUsage(char const* argv0)
{
    std::cerr << "Usage: " << argv0
              << " [--workers N] [--num-nodes N] [--depth N]"
                 " [--nomination-only]"
                 " [--deadlock]"
                 " [--termination]"
                 " [--externalize]"
                 " [--externalize-divergence]"
                 " [--print-skip-externalize]"
                 " [--nomination-timer-limit N]"
                 " [--balloting-timer-limit N]"
                 " [--scenario ID] [--nomination-timeouts]"
                 " [--balloting-timeouts]\n"
              << "Scenarios: 1|two-followers, 2|all-followers-once, "
                 "3|all-followers-second-peer-receive, "
                 "4|unrestricted-followers, "
                 "5|threshold-split-balloting\n"
              << "--depth limits each thread to N steps (0 = unbounded)\n"
              << "--deadlock fails if a terminal execution leaves any thread "
                 "short of its step limit (unbounded counts as unreached)\n"
              << "--termination fails if a terminal execution contains no "
                 "EXTERNALIZE message\n"
              << "--externalize fails if a terminal execution contains any "
                 "EXTERNALIZE message\n"
              << "--externalize-divergence fails if a terminal execution has "
                 "two nodes externalize different values\n"
              << "--print-skip-externalize prints when an explored execution "
                 "contains a skip EXTERNALIZE message\n"
              << "--nomination-only stops exploration at the first "
                 "PREPARE(1) boundary\n";
}

uint32_t
parseUint32Value(std::string_view arg, std::string_view value)
{
    auto const parsed = std::stoull(std::string(value));
    if (parsed > std::numeric_limits<uint32_t>::max())
    {
        throw std::invalid_argument("value out of range: " +
                                    std::string(arg));
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

InvestigationScenario::Id
parseScenarioValue(std::string_view value)
{
    if (value == "1" || value == "two-followers")
    {
        return InvestigationScenario::Id::TwoFollowersAccepted;
    }
    if (value == "2" || value == "all-followers-once")
    {
        return InvestigationScenario::Id::AllFollowersAcceptedOnce;
    }
    if (value == "3" || value == "all-followers-second-peer-receive" ||
        value == "largest")
    {
        return InvestigationScenario::Id::AllFollowersSecondPeerReceive;
    }
    if (value == "4" || value == "unrestricted-followers")
    {
        return InvestigationScenario::Id::UnrestrictedFollowers;
    }
    if (value == "5" || value == "threshold-split-balloting")
    {
        return InvestigationScenario::Id::ThresholdSplitBalloting;
    }
    throw std::invalid_argument("unknown scenario: " + std::string(value));
}

std::size_t
parseNumNodesValue(std::string_view arg, std::string_view value)
{
    auto const parsed = std::stoull(std::string(value));
    if (parsed < 2)
    {
        throw std::invalid_argument(std::string(arg) +
                                    " requires at least 2 validators");
    }
    return static_cast<std::size_t>(parsed);
}

bool
startsWith(std::string_view value, std::string_view prefix)
{
    return value.size() >= prefix.size() &&
           value.compare(0, prefix.size(), prefix) == 0;
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
        if (arg == "--nomination-timeouts")
        {
            options.mTimeoutSettings.mNomination = true;
            continue;
        }
        if (arg == "--nomination-only")
        {
            options.mNominationOnly = true;
            continue;
        }
        if (arg == "--deadlock")
        {
            options.mCheckDeadlock = true;
            continue;
        }
        if (arg == "--termination")
        {
            options.mCheckTermination = true;
            continue;
        }
        if (arg == "--externalize")
        {
            options.mCheckExternalize = true;
            continue;
        }
        if (arg == "--externalize-divergence")
        {
            options.mCheckExternalizeDivergence = true;
            continue;
        }
        if (arg == "--print-skip-externalize")
        {
            options.mPrintSkipExternalize = true;
            continue;
        }
        if (arg == "--balloting-timeouts")
        {
            options.mTimeoutSettings.mBalloting = true;
            continue;
        }
        if (arg == "--workers")
        {
            if (i + 1 >= argc)
            {
                throw std::invalid_argument("--workers requires a value");
            }
            options.mWorkers =
                static_cast<std::size_t>(std::stoull(argv[++i]));
            continue;
        }
        if (startsWith(arg, "--workers="))
        {
            options.mWorkers = static_cast<std::size_t>(
                std::stoull(std::string(arg.substr(std::string_view("--workers=").size()))));
            continue;
        }
        if (arg == "--depth")
        {
            if (i + 1 >= argc)
            {
                throw std::invalid_argument("--depth requires a value");
            }
            options.mDepthOverride =
                static_cast<std::size_t>(std::stoull(argv[++i]));
            continue;
        }
        if (startsWith(arg, "--depth="))
        {
            options.mDepthOverride = static_cast<std::size_t>(std::stoull(
                std::string(arg.substr(std::string_view("--depth=").size()))));
            continue;
        }
        if (arg == "--num-nodes")
        {
            if (i + 1 >= argc)
            {
                throw std::invalid_argument("--num-nodes requires a value");
            }
            options.mNumNodes =
                parseNumNodesValue(arg, std::string_view(argv[++i]));
            continue;
        }
        if (startsWith(arg, "--num-nodes="))
        {
            options.mNumNodes = parseNumNodesValue(
                arg, arg.substr(std::string_view("--num-nodes=").size()));
            continue;
        }
        if (arg == "--nomination-timer-limit")
        {
            if (i + 1 >= argc)
            {
                throw std::invalid_argument(
                    "--nomination-timer-limit requires a value");
            }
            options.mTimerSetLimitSettings.mNomination =
                parsePositiveUint32Value(arg, std::string_view(argv[++i]));
            continue;
        }
        if (startsWith(arg, "--nomination-timer-limit="))
        {
            options.mTimerSetLimitSettings.mNomination =
                parsePositiveUint32Value(
                    arg, arg.substr(std::string_view(
                                        "--nomination-timer-limit=").size()));
            continue;
        }
        if (arg == "--balloting-timer-limit")
        {
            if (i + 1 >= argc)
            {
                throw std::invalid_argument(
                    "--balloting-timer-limit requires a value");
            }
            options.mTimerSetLimitSettings.mBalloting =
                parsePositiveUint32Value(arg, std::string_view(argv[++i]));
            continue;
        }
        if (startsWith(arg, "--balloting-timer-limit="))
        {
            options.mTimerSetLimitSettings.mBalloting =
                parsePositiveUint32Value(
                    arg, arg.substr(std::string_view(
                                        "--balloting-timer-limit=").size()));
            continue;
        }
        if (arg == "--scenario")
        {
            if (i + 1 >= argc)
            {
                throw std::invalid_argument("--scenario requires a value");
            }
            options.mScenario = parseScenarioValue(argv[++i]);
            continue;
        }
        if (startsWith(arg, "--scenario="))
        {
            options.mScenario = parseScenarioValue(
                arg.substr(std::string_view("--scenario=").size()));
            continue;
        }
        throw std::invalid_argument("unknown argument: " + std::string(arg));
    }
    return options;
}

}

int
main(int argc, char* argv[])
{
    try
    {
        auto const options = parseOptions(argv[0], argc, argv);
        auto const results = runRuntimeGrowthInvestigation(
            options.mWorkers, options.mDepthOverride,
            options.mScenario, options.mNominationOnly,
            options.mNumNodes, options.mTimeoutSettings,
            options.mTimerSetLimitSettings, options.mCheckDeadlock,
            options.mCheckTermination,
            options.mCheckExternalize,
            options.mCheckExternalizeDivergence,
            options.mPrintSkipExternalize);
        printInvestigationResults(std::cout, results, options.mWorkers,
                                  options.mNumNodes,
                                  options.mNominationOnly,
                                  options.mTimeoutSettings,
                                  options.mTimerSetLimitSettings,
                                  options.mCheckDeadlock,
                                  options.mCheckTermination,
                                  options.mCheckExternalize,
                                  options.mCheckExternalizeDivergence,
                                  options.mPrintSkipExternalize);

        for (auto const& result : results)
        {
            if (result.mVerifyResult.kind ==
                dpor::algo::VerifyResultKind::ErrorFound)
            {
                return 1;
            }
        }
        return 0;
    }
    catch (std::invalid_argument const& e)
    {
        std::cerr << e.what() << '\n';
        printUsage(argv[0]);
        return 2;
    }
    catch (std::exception const& e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
