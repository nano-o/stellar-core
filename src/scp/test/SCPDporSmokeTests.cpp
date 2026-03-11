// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "test/Catch2.h"

#include <dpor/algo/dpor.hpp>

namespace stellar
{

TEST_CASE("dpor smoke test", "[scp][dpor]")
{
    using dpor::algo::DporConfig;
    using dpor::algo::ThreadTrace;
    using dpor::algo::VerifyResultKind;
    using dpor::model::EventLabel;
    using dpor::model::SendLabel;

    DporConfig config;
    config.program.threads[1] = [](ThreadTrace const&,
                                   std::size_t step) -> std::optional<EventLabel> {
        if (step == 0)
        {
            return SendLabel{.destination = 2, .value = "hello"};
        }
        return std::nullopt;
    };
    config.program.threads[2] = [](ThreadTrace const&,
                                   std::size_t) -> std::optional<EventLabel> {
        return std::nullopt;
    };

    auto const result = dpor::algo::verify(config);

    REQUIRE(result.kind == VerifyResultKind::AllExecutionsExplored);
    REQUIRE(result.executions_explored == 1);
}

}
