// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "GlobalChecks.h"
#include "Backtrace.h"

#ifdef _WIN32
#include <Windows.h>
#endif
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <stdexcept>
#include <string>
#include <thread>

namespace stellar
{
static std::thread::id mainThread = std::this_thread::get_id();

// Write-once before threads.  When true, assert/abort helpers throw
// std::runtime_error instead of aborting the process.
static bool gAssertThrowMode = false;

bool
threadIsMain()
{
    return mainThread == std::this_thread::get_id();
}

void
enableAssertThrowMode()
{
    gAssertThrowMode = true;
}

static void
platformAbort()
{
#ifdef _WIN32
    DebugBreak();
#else
    std::abort();
#endif
}

// Undef the macro so we can define the out-of-line implementation.
#undef dbgAbort

void
dbgAbortImpl(char const* file, int line)
{
    std::fprintf(stderr, "dbgAbort at %s:%d\n", file, line);
    std::fflush(stderr);
    printCurrentBacktrace();
    if (gAssertThrowMode)
    {
        throw std::runtime_error(
            std::string("dbgAbort at ") + file + ":" + std::to_string(line));
    }
    platformAbort();
    std::abort();
}

void
printErrorAndAbort(char const* s1)
{
    std::fprintf(stderr, "%s\n", s1);
    std::fflush(stderr);
    printCurrentBacktrace();
    if (gAssertThrowMode)
    {
        throw std::runtime_error(s1);
    }
    platformAbort();
    std::abort();
}

void
printErrorAndAbort(char const* s1, char const* s2)
{
    std::fprintf(stderr, "%s%s\n", s1, s2);
    std::fflush(stderr);
    printCurrentBacktrace();
    if (gAssertThrowMode)
    {
        throw std::runtime_error(std::string(s1) + s2);
    }
    platformAbort();
    std::abort();
}

void
printAssertFailureAndAbort(char const* s1, char const* file, int line)
{
    std::fprintf(stderr, "%s at %s:%d\n", s1, file, line);
    std::fflush(stderr);
    printCurrentBacktrace();
    if (gAssertThrowMode)
    {
        throw std::runtime_error(
            std::string(s1) + " at " + file + ":" + std::to_string(line));
    }
    platformAbort();
    std::abort();
}

void
printAssertFailureAndThrow(char const* s1, char const* file, int line)
{
    std::fprintf(stderr, "%s at %s:%d\n", s1, file, line);
    std::fflush(stderr);
    printCurrentBacktrace();
    throw std::runtime_error(
        std::string(s1) + " at " + file + ":" + std::to_string(line));
}
}
