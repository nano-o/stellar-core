// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "test/test.h"
#include "util/GlobalChecks.h"

namespace stellar
{
namespace
{
CommandLineArgs
makeArgs(int argc, char* const* argv)
{
    CommandLineArgs args;
    args.mExeName = argc > 0 ? argv[0] : "stellar-core-dpor-tests";
    args.mCommandName = "test";
    args.mCommandDescription =
        "Run DPOR smoke tests for SCP integration.";
    for (int i = 1; i < argc; ++i)
    {
        args.mArgs.emplace_back(argv[i]);
    }
    return args;
}
} // namespace

} // namespace stellar

int
main(int argc, char* const* argv)
{
    stellar::enableAssertThrowMode();
    return stellar::runTest(stellar::makeArgs(argc, argv));
}
