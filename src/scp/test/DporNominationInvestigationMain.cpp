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
    bool mAllowTimeouts = false;
    std::optional<std::size_t> mDepthOverride;
    std::optional<uint32_t> mBoundaryOverride;
    std::optional<InvestigationScenario::Id> mScenario;
};

void
printUsage(char const* argv0)
{
    std::cerr << "Usage: " << argv0
              << " [--workers N] [--num-nodes N] [--depth N] [--boundary N]"
                 " [--scenario ID] [--timeouts]\n"
              << "Scenarios: 1|two-followers, 2|all-followers-once, "
                 "3|largest, 4|unrestricted-followers, 5|commit-boundary\n";
}

uint32_t
parseBoundaryValue(std::string_view arg, std::string_view value)
{
    auto const parsed = std::stoull(std::string(value));
    if (parsed > std::numeric_limits<uint32_t>::max())
    {
        throw std::invalid_argument("boundary out of range: " +
                                    std::string(arg));
    }
    return static_cast<uint32_t>(parsed);
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
    if (value == "3" || value == "largest")
    {
        return InvestigationScenario::Id::Largest;
    }
    if (value == "4" || value == "unrestricted-followers")
    {
        return InvestigationScenario::Id::UnrestrictedFollowers;
    }
    if (value == "5" || value == "commit-boundary")
    {
        return InvestigationScenario::Id::CommitBoundary;
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
        if (arg == "--timeouts")
        {
            options.mAllowTimeouts = true;
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
        if (arg.starts_with("--workers="))
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
        if (arg.starts_with("--depth="))
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
        if (arg.starts_with("--num-nodes="))
        {
            options.mNumNodes = parseNumNodesValue(
                arg, arg.substr(std::string_view("--num-nodes=").size()));
            continue;
        }
        if (arg == "--boundary")
        {
            if (i + 1 >= argc)
            {
                throw std::invalid_argument("--boundary requires a value");
            }
            options.mBoundaryOverride =
                parseBoundaryValue(arg, std::string_view(argv[++i]));
            continue;
        }
        if (arg.starts_with("--boundary="))
        {
            options.mBoundaryOverride = parseBoundaryValue(
                arg, arg.substr(std::string_view("--boundary=").size()));
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
        if (arg.starts_with("--scenario="))
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
        auto const nominationRoundBoundary =
            options.mBoundaryOverride.value_or(
                stellar::DporNominationNode::DEFAULT_NOMINATION_ROUND_BOUNDARY);
        auto const results = runRuntimeGrowthInvestigation(
            options.mWorkers, options.mDepthOverride,
            options.mBoundaryOverride, options.mScenario,
            options.mNumNodes, options.mAllowTimeouts);
        printInvestigationResults(std::cout, results, options.mWorkers,
                                  nominationRoundBoundary,
                                  options.mNumNodes,
                                  options.mAllowTimeouts);

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
    catch (std::exception const& e)
    {
        std::cerr << e.what() << '\n';
        printUsage(argv[0]);
        return 2;
    }
}
