// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ledger/LedgerTxn.h"
#include "ledger/TrustLineWrapper.h"
#include "ledger/test/LedgerTestUtils.h"
#include "main/Application.h"
#include "main/Config.h"
#include "test/Catch2.h"
#include "test/TestAccount.h"
#include "test/TestUtils.h"
#include "test/TxTests.h"
#include "test/test.h"
#include "transactions/EventManager.h"
#include "transactions/OfferExchange.h"
#include "transactions/TransactionFrame.h"
#include "transactions/TransactionUtils.h"
#include "util/ProtocolVersion.h"
#include "util/numeric128.h"
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include <fmt/format.h>
#include <random>

using namespace stellar;
using namespace stellar::txtest;

TEST_CASE("Exchange", "[exchange]")
{
    enum ReducedCheckV2
    {
        REDUCED_CHECK_V2_RELAXED,
        REDUCED_CHECK_V2_STRICT
    };

    auto compare = [](ExchangeResult const& x, ExchangeResult const& y) {
        REQUIRE(x.type() == ExchangeResultType::NORMAL);
        REQUIRE(x.reduced == y.reduced);
        REQUIRE(x.numWheatReceived == y.numWheatReceived);
        REQUIRE(x.numSheepSend == y.numSheepSend);
    };
    auto validateV2 = [&compare](int64_t wheatToReceive, Price price,
                                 int64_t maxWheatReceive, int64_t maxSheepSend,
                                 ExchangeResult const& expected,
                                 ReducedCheckV2 reducedCheck =
                                     REDUCED_CHECK_V2_STRICT) {
        auto actualV2 =
            exchangeV2(wheatToReceive, price, maxWheatReceive, maxSheepSend);
        compare(actualV2, expected);
        REQUIRE(actualV2.numWheatReceived >= 0);
        REQUIRE(price.n >= 0);
        REQUIRE(expected.numSheepSend >= 0);
        REQUIRE(price.d >= 0);
        REQUIRE(uint128_t{static_cast<uint64_t>(actualV2.numWheatReceived)} *
                    uint128_t{static_cast<uint32_t>(price.n)} <=
                uint128_t{static_cast<uint64_t>(expected.numSheepSend)} *
                    uint128_t{static_cast<uint32_t>(price.d)});
        REQUIRE(actualV2.numSheepSend <= maxSheepSend);
        if (reducedCheck == REDUCED_CHECK_V2_RELAXED)
        {
            REQUIRE(actualV2.numWheatReceived <= wheatToReceive);
        }
        else
        {
            if (actualV2.reduced)
            {
                REQUIRE(actualV2.numWheatReceived < wheatToReceive);
            }
            else
            {
                REQUIRE(actualV2.numWheatReceived == wheatToReceive);
            }
        }
    };
    auto validateV3 = [&compare](int64_t wheatToReceive, Price price,
                                 int64_t maxWheatReceive, int64_t maxSheepSend,
                                 ExchangeResult const& expected) {
        auto actualV3 =
            exchangeV3(wheatToReceive, price, maxWheatReceive, maxSheepSend);
        compare(actualV3, expected);
        REQUIRE(actualV3.numWheatReceived >= 0);
        REQUIRE(price.n >= 0);
        REQUIRE(expected.numSheepSend >= 0);
        REQUIRE(price.d >= 0);
        REQUIRE(uint128_t{static_cast<uint64_t>(actualV3.numWheatReceived)} *
                    uint128_t{static_cast<uint32_t>(price.n)} <=
                uint128_t{static_cast<uint64_t>(expected.numSheepSend)} *
                    uint128_t{static_cast<uint32_t>(price.d)});
        REQUIRE(actualV3.numSheepSend <= maxSheepSend);
        if (actualV3.reduced)
        {
            REQUIRE(actualV3.numWheatReceived < wheatToReceive);
        }
        else
        {
            REQUIRE(actualV3.numWheatReceived == wheatToReceive);
        }
    };
    auto validate = [&validateV2, &validateV3](
                        int64_t wheatToReceive, Price price,
                        int64_t maxWheatReceive, int64_t maxSheepSend,
                        ExchangeResult const& expected,
                        ReducedCheckV2 reducedCheck = REDUCED_CHECK_V2_STRICT) {
        validateV2(wheatToReceive, price, maxWheatReceive, maxSheepSend,
                   expected, reducedCheck);
        validateV3(wheatToReceive, price, maxWheatReceive, maxSheepSend,
                   expected);
    };

    SECTION("normal prices")
    {
        SECTION("no limits")
        {
            SECTION("1000")
            {
                validate(1000, Price{3, 2}, INT64_MAX, INT64_MAX,
                         {1000, 1500, false});
                validate(1000, Price{1, 1}, INT64_MAX, INT64_MAX,
                         {1000, 1000, false});
                validateV2(1000, Price{2, 3}, INT64_MAX, INT64_MAX,
                           {999, 666, false}, REDUCED_CHECK_V2_RELAXED);
                validateV3(1000, Price{2, 3}, INT64_MAX, INT64_MAX,
                           {1000, 667, false});
            }

            SECTION("999")
            {
                validateV2(999, Price{3, 2}, INT64_MAX, INT64_MAX,
                           {998, 1498, false}, REDUCED_CHECK_V2_RELAXED);
                validateV3(999, Price{3, 2}, INT64_MAX, INT64_MAX,
                           {999, 1499, false});
                validate(999, Price{1, 1}, INT64_MAX, INT64_MAX,
                         {999, 999, false});
                validate(999, Price{2, 3}, INT64_MAX, INT64_MAX,
                         {999, 666, false});
            }

            SECTION("1")
            {
                REQUIRE(
                    exchangeV2(0, Price{3, 2}, INT64_MAX, INT64_MAX).type() ==
                    ExchangeResultType::BOGUS);
                REQUIRE(
                    exchangeV3(0, Price{3, 2}, INT64_MAX, INT64_MAX).type() ==
                    ExchangeResultType::BOGUS);
                validate(1, Price{1, 1}, INT64_MAX, INT64_MAX, {1, 1, false});
                REQUIRE(
                    exchangeV2(1, Price{2, 3}, INT64_MAX, INT64_MAX).type() ==
                    ExchangeResultType::BOGUS);
                validateV3(1, Price{2, 3}, INT64_MAX, INT64_MAX, {1, 1, false});
            }

            SECTION("0")
            {
                REQUIRE(
                    exchangeV2(0, Price{3, 2}, INT64_MAX, INT64_MAX).type() ==
                    ExchangeResultType::BOGUS);
                REQUIRE(
                    exchangeV2(0, Price{1, 1}, INT64_MAX, INT64_MAX).type() ==
                    ExchangeResultType::BOGUS);
                REQUIRE(
                    exchangeV2(0, Price{2, 3}, INT64_MAX, INT64_MAX).type() ==
                    ExchangeResultType::BOGUS);
            }
        }

        SECTION("send limits")
        {
            SECTION("1000 limited to 500")
            {
                validate(1000, Price{3, 2}, INT64_MAX, 750, {500, 750, true});
                validate(1000, Price{1, 1}, INT64_MAX, 500, {500, 500, true});
                validate(1000, Price{2, 3}, INT64_MAX, 333, {499, 333, true});
            }

            SECTION("999 limited to 499")
            {
                validate(999, Price{3, 2}, INT64_MAX, 749, {499, 749, true});
                validate(999, Price{1, 1}, INT64_MAX, 499, {499, 499, true});
                validate(999, Price{2, 3}, INT64_MAX, 333, {499, 333, true});
            }

            SECTION("20 limited to 10")
            {
                validate(20, Price{3, 2}, INT64_MAX, 15, {10, 15, true});
                validate(20, Price{1, 1}, INT64_MAX, 10, {10, 10, true});
                validate(20, Price{2, 3}, INT64_MAX, 7, {10, 7, true});
            }

            SECTION("2 limited to 1")
            {
                validate(2, Price{3, 2}, INT64_MAX, 2, {1, 2, true});
                validate(2, Price{1, 1}, INT64_MAX, 1, {1, 1, true});
                validateV2(2, Price{2, 3}, INT64_MAX, 1, {1, 1, false},
                           REDUCED_CHECK_V2_RELAXED);
                validateV3(2, Price{2, 3}, INT64_MAX, 1, {1, 1, true});
            }
        }

        SECTION("receive limits")
        {
            SECTION("1000 limited to 500")
            {
                validate(1000, Price{3, 2}, 500, INT64_MAX, {500, 750, true});
                validate(1000, Price{1, 1}, 500, INT64_MAX, {500, 500, true});
                validateV2(1000, Price{2, 3}, 500, INT64_MAX, {499, 333, true});
                validateV3(1000, Price{2, 3}, 500, INT64_MAX, {500, 334, true});
            }

            SECTION("999 limited to 499")
            {
                validateV2(999, Price{3, 2}, 499, INT64_MAX, {498, 748, true});
                validateV3(999, Price{3, 2}, 499, INT64_MAX, {499, 749, true});
                validate(999, Price{1, 1}, 499, INT64_MAX, {499, 499, true});
                validateV2(999, Price{2, 3}, 499, INT64_MAX, {498, 332, true});
                validateV3(999, Price{2, 3}, 499, INT64_MAX, {499, 333, true});
            }

            SECTION("20 limited to 10")
            {
                validate(20, Price{3, 2}, 10, INT64_MAX, {10, 15, true});
                validate(20, Price{1, 1}, 10, INT64_MAX, {10, 10, true});
                validateV2(20, Price{2, 3}, 10, INT64_MAX, {9, 6, true});
                validateV3(20, Price{2, 3}, 10, INT64_MAX, {10, 7, true});
            }

            SECTION("2 limited to 1")
            {
                REQUIRE(exchangeV2(2, Price{3, 2}, 1, INT64_MAX).type() ==
                        ExchangeResultType::REDUCED_TO_ZERO);
                validateV3(2, Price{3, 2}, 1, INT64_MAX, {1, 2, true});
                validate(2, Price{1, 1}, 1, INT64_MAX, {1, 1, true});
                REQUIRE(exchangeV2(2, Price{2, 3}, 1, INT64_MAX).type() ==
                        ExchangeResultType::REDUCED_TO_ZERO);
                validateV3(2, Price{2, 3}, 1, INT64_MAX, {1, 1, true});
            }
        }
    }

    SECTION("extra big prices")
    {
        SECTION("no limits")
        {
            validate(1000, Price{INT32_MAX, 1}, INT64_MAX, INT64_MAX,
                     {1000, 1000ull * INT32_MAX, false});
            validate(999, Price{INT32_MAX, 1}, INT64_MAX, INT64_MAX,
                     {999, 999ull * INT32_MAX, false});
            validate(1, Price{INT32_MAX, 1}, INT64_MAX, INT64_MAX,
                     {1, INT32_MAX, false});
            REQUIRE(exchangeV2(2, Price{2, 3}, 1, INT64_MAX).type() ==
                    ExchangeResultType::REDUCED_TO_ZERO);
            validateV3(2, Price{2, 3}, 1, INT64_MAX, {1, 1, true});
        }

        SECTION("send limits")
        {
            SECTION("750")
            {
                REQUIRE(exchangeV2(1000, Price{INT32_MAX, 1}, INT64_MAX, 750)
                            .type() == ExchangeResultType::REDUCED_TO_ZERO);
                REQUIRE(exchangeV3(1000, Price{INT32_MAX, 1}, INT64_MAX, 750)
                            .type() == ExchangeResultType::REDUCED_TO_ZERO);
                REQUIRE(exchangeV2(999, Price{INT32_MAX, 1}, INT64_MAX, 750)
                            .type() == ExchangeResultType::REDUCED_TO_ZERO);
                REQUIRE(exchangeV3(999, Price{INT32_MAX, 1}, INT64_MAX, 750)
                            .type() == ExchangeResultType::REDUCED_TO_ZERO);
                REQUIRE(
                    exchangeV2(1, Price{INT32_MAX, 1}, INT64_MAX, 750).type() ==
                    ExchangeResultType::REDUCED_TO_ZERO);
                REQUIRE(
                    exchangeV3(1, Price{INT32_MAX, 1}, INT64_MAX, 750).type() ==
                    ExchangeResultType::REDUCED_TO_ZERO);
                REQUIRE(
                    exchangeV2(0, Price{INT32_MAX, 1}, INT64_MAX, 750).type() ==
                    ExchangeResultType::BOGUS);
                REQUIRE(
                    exchangeV3(0, Price{INT32_MAX, 1}, INT64_MAX, 750).type() ==
                    ExchangeResultType::BOGUS);
            }

            SECTION("INT32_MAX")
            {
                validate(1000, Price{INT32_MAX, 1}, INT64_MAX, INT32_MAX,
                         {1, INT32_MAX, true});
                validate(999, Price{INT32_MAX, 1}, INT64_MAX, INT32_MAX,
                         {1, INT32_MAX, true});
                validate(1, Price{INT32_MAX, 1}, INT64_MAX, INT32_MAX,
                         {1, INT32_MAX, false});
                REQUIRE(exchangeV2(0, Price{INT32_MAX, 1}, INT64_MAX, INT32_MAX)
                            .type() == ExchangeResultType::BOGUS);
                REQUIRE(exchangeV3(0, Price{INT32_MAX, 1}, INT64_MAX, INT32_MAX)
                            .type() == ExchangeResultType::BOGUS);
            }

            SECTION("750 * INT32_MAX")
            {
                validate(1000, Price{INT32_MAX, 1}, INT64_MAX,
                         750ull * INT32_MAX, {750, 750ull * INT32_MAX, true});
                validate(999, Price{INT32_MAX, 1}, INT64_MAX,
                         750ull * INT32_MAX, {750, 750ull * INT32_MAX, true});
                validate(1, Price{INT32_MAX, 1}, INT64_MAX, 750ull * INT32_MAX,
                         {1, INT32_MAX, false});
                REQUIRE(exchangeV2(0, Price{INT32_MAX, 1}, INT64_MAX,
                                   750ull * INT32_MAX)
                            .type() == ExchangeResultType::BOGUS);
                REQUIRE(exchangeV3(0, Price{INT32_MAX, 1}, INT64_MAX,
                                   750ull * INT32_MAX)
                            .type() == ExchangeResultType::BOGUS);
            }
        }

        SECTION("receive limits")
        {
            SECTION("750")
            {
                validate(1000, Price{INT32_MAX, 1}, 750, INT64_MAX,
                         {750, 750ull * INT32_MAX, true});
                validate(999, Price{INT32_MAX, 1}, 750, INT64_MAX,
                         {750, 750ull * INT32_MAX, true});
                validate(1, Price{INT32_MAX, 1}, 750, INT64_MAX,
                         {1, INT32_MAX, false});
                REQUIRE(
                    exchangeV2(0, Price{INT32_MAX, 1}, 750, INT64_MAX).type() ==
                    ExchangeResultType::BOGUS);
                REQUIRE(
                    exchangeV3(0, Price{INT32_MAX, 1}, 750, INT64_MAX).type() ==
                    ExchangeResultType::BOGUS);
            }

            SECTION("INT32_MAX")
            {
                validate(1000, Price{INT32_MAX, 1}, INT32_MAX, INT64_MAX,
                         {1000, 1000ull * INT32_MAX, false});
                validate(999, Price{INT32_MAX, 1}, INT32_MAX, INT64_MAX,
                         {999, 999ull * INT32_MAX, false});
                validate(1, Price{INT32_MAX, 1}, INT32_MAX, INT64_MAX,
                         {1, INT32_MAX, false});
                REQUIRE(exchangeV2(0, Price{INT32_MAX, 1}, INT32_MAX, INT64_MAX)
                            .type() == ExchangeResultType::BOGUS);
                REQUIRE(exchangeV3(0, Price{INT32_MAX, 1}, INT32_MAX, INT64_MAX)
                            .type() == ExchangeResultType::BOGUS);
            }
        }
    }

    SECTION("extra small prices")
    {
        SECTION("no limits")
        {
            validate(1000ull * INT32_MAX, Price{1, INT32_MAX}, INT64_MAX,
                     INT64_MAX, {1000ull * INT32_MAX, 1000, false});
            validate(999ull * INT32_MAX, Price{1, INT32_MAX}, INT64_MAX,
                     INT64_MAX, {999ull * INT32_MAX, 999, false});
            validate(INT32_MAX, Price{1, INT32_MAX}, INT64_MAX, INT64_MAX,
                     {INT32_MAX, 1, false});
            REQUIRE(exchangeV2(0, Price{1, INT32_MAX}, INT64_MAX, INT64_MAX)
                        .type() == ExchangeResultType::BOGUS);
            REQUIRE(exchangeV3(0, Price{1, INT32_MAX}, INT64_MAX, INT64_MAX)
                        .type() == ExchangeResultType::BOGUS);
        }

        SECTION("send limits")
        {
            SECTION("750")
            {
                validate(1000ull * INT32_MAX, Price{1, INT32_MAX}, INT64_MAX,
                         750, {750ull * INT32_MAX, 750, true});
                validate(999ull * INT32_MAX, Price{1, INT32_MAX}, INT64_MAX,
                         750, {750ull * INT32_MAX, 750, true});
                validate(INT32_MAX, Price{1, INT32_MAX}, INT64_MAX, 750,
                         {INT32_MAX, 1, false});
                REQUIRE(
                    exchangeV2(0, Price{1, INT32_MAX}, INT64_MAX, 750).type() ==
                    ExchangeResultType::BOGUS);
                REQUIRE(
                    exchangeV3(0, Price{1, INT32_MAX}, INT64_MAX, 750).type() ==
                    ExchangeResultType::BOGUS);
            }

            SECTION("INT32_MAX")
            {
                validate(1000ull * INT32_MAX, Price{1, INT32_MAX}, INT64_MAX,
                         INT32_MAX, {1000ull * INT32_MAX, 1000, false});
                validate(999ull * INT32_MAX, Price{1, INT32_MAX}, INT64_MAX,
                         INT32_MAX, {999ull * INT32_MAX, 999, false});
                validate(INT32_MAX, Price{1, INT32_MAX}, INT64_MAX, INT32_MAX,
                         {INT32_MAX, 1, false});
                REQUIRE(exchangeV2(0, Price{1, INT32_MAX}, INT64_MAX, INT32_MAX)
                            .type() == ExchangeResultType::BOGUS);
                REQUIRE(exchangeV3(0, Price{1, INT32_MAX}, INT64_MAX, INT32_MAX)
                            .type() == ExchangeResultType::BOGUS);
            }
        }

        SECTION("receive limits")
        {
            SECTION("750")
            {
                REQUIRE(exchangeV2(1000ull * INT32_MAX, Price{1, INT32_MAX},
                                   750, INT64_MAX)
                            .type() == ExchangeResultType::REDUCED_TO_ZERO);
                validateV3(1000ull * INT32_MAX, Price{1, INT32_MAX}, 750,
                           INT64_MAX, {750, 1, true});
                REQUIRE(exchangeV2(999ull * INT32_MAX, Price{1, INT32_MAX}, 750,
                                   INT64_MAX)
                            .type() == ExchangeResultType::REDUCED_TO_ZERO);
                validateV3(999ull * INT32_MAX, Price{1, INT32_MAX}, 750,
                           INT64_MAX, {750, 1, true});
                REQUIRE(
                    exchangeV2(INT32_MAX, Price{1, INT32_MAX}, 750, INT64_MAX)
                        .type() == ExchangeResultType::REDUCED_TO_ZERO);
                validateV3(INT32_MAX, Price{1, INT32_MAX}, 750, INT64_MAX,
                           {750, 1, true});
                REQUIRE(exchangeV2(750, Price{1, INT32_MAX}, 750, INT64_MAX)
                            .type() == ExchangeResultType::BOGUS);
                validateV3(750, Price{1, INT32_MAX}, 750, INT64_MAX,
                           {750, 1, false});
            }

            SECTION("INT32_MAX")
            {
                validate(1000ull * INT32_MAX, Price{1, INT32_MAX},
                         750ull * INT32_MAX, INT64_MAX,
                         {750ull * INT32_MAX, 750, true});
                validate(999ull * INT32_MAX, Price{1, INT32_MAX},
                         750ull * INT32_MAX, INT64_MAX,
                         {750ull * INT32_MAX, 750, true});
                validate(INT32_MAX, Price{1, INT32_MAX}, 750ull * INT32_MAX,
                         INT64_MAX, {INT32_MAX, 1, false});
                REQUIRE(exchangeV2(750, Price{1, INT32_MAX}, 750ull * INT32_MAX,
                                   INT64_MAX)
                            .type() == ExchangeResultType::BOGUS);
                validateV3(750, Price{1, INT32_MAX}, 750ull * INT32_MAX,
                           INT64_MAX, {750, 1, false});
            }

            SECTION("750 * INT32_MAX")
            {
                validate(1000ull * INT32_MAX, Price{1, INT32_MAX},
                         750ull * INT32_MAX, INT64_MAX,
                         {750ull * INT32_MAX, 750, true});
                validate(999ull * INT32_MAX, Price{1, INT32_MAX},
                         750ull * INT32_MAX, INT64_MAX,
                         {750ull * INT32_MAX, 750, true});
                validate(INT32_MAX, Price{1, INT32_MAX}, 750ull * INT32_MAX,
                         INT64_MAX, {INT32_MAX, 1, false});
                REQUIRE(exchangeV2(750, Price{1, INT32_MAX}, 750ull * INT32_MAX,
                                   INT64_MAX)
                            .type() == ExchangeResultType::BOGUS);
                validateV3(750, Price{1, INT32_MAX}, 750ull * INT32_MAX,
                           INT64_MAX, {750, 1, false});
            }
        }
    }

    SECTION("exchange with big limits")
    {
        SECTION("INT32_MAX send")
        {
            validate(INT32_MAX, Price{3, 2}, INT64_MAX, INT32_MAX,
                     {1431655764, INT32_MAX, true});
            validate(INT32_MAX, Price{1, 1}, INT64_MAX, INT32_MAX,
                     {INT32_MAX, INT32_MAX, false});
            validateV2(INT32_MAX, Price{2, 3}, INT64_MAX, INT32_MAX,
                       {INT32_MAX - 1, 1431655764, false},
                       REDUCED_CHECK_V2_RELAXED);
            validateV3(INT32_MAX, Price{2, 3}, INT64_MAX, INT32_MAX,
                       {INT32_MAX, 1431655765, false});
            validate(INT32_MAX, Price{1, INT32_MAX}, INT64_MAX, INT32_MAX,
                     {INT32_MAX, 1, false});
            validate(INT32_MAX, Price{INT32_MAX, 1}, INT64_MAX, INT32_MAX,
                     {1, INT32_MAX, true});
            validate(INT32_MAX, Price{INT32_MAX, INT32_MAX}, INT64_MAX,
                     INT32_MAX, {INT32_MAX, INT32_MAX, false});
        }

        SECTION("INT32_MAX receive")
        {
            validateV2(INT32_MAX, Price{3, 2}, INT32_MAX, INT64_MAX,
                       {INT32_MAX - 1, 3221225470, false},
                       REDUCED_CHECK_V2_RELAXED);
            validateV3(INT32_MAX, Price{3, 2}, INT32_MAX, INT64_MAX,
                       {INT32_MAX, 3221225471, false});
            validate(INT32_MAX, Price{1, 1}, INT32_MAX, INT64_MAX,
                     {INT32_MAX, INT32_MAX, false});
            validateV2(INT32_MAX, Price{2, 3}, INT32_MAX, INT64_MAX,
                       {INT32_MAX - 1, 1431655764, false},
                       REDUCED_CHECK_V2_RELAXED);
            validateV3(INT32_MAX, Price{2, 3}, INT32_MAX, INT64_MAX,
                       {INT32_MAX, 1431655765, false});
            validate(INT32_MAX, Price{1, INT32_MAX}, INT32_MAX, INT64_MAX,
                     {INT32_MAX, 1, false});
            validate(INT32_MAX, Price{INT32_MAX, 1}, INT32_MAX, INT64_MAX,
                     {INT32_MAX, 4611686014132420609, false});
            validate(INT32_MAX, Price{INT32_MAX, INT32_MAX}, INT32_MAX,
                     INT64_MAX, {INT32_MAX, INT32_MAX, false});
        }

        SECTION("INT64_MAX")
        {
            validateV2(INT64_MAX, Price{3, 2}, INT64_MAX, INT64_MAX,
                       {6148914691236517204, INT64_MAX, false},
                       REDUCED_CHECK_V2_RELAXED);
            validateV3(INT64_MAX, Price{3, 2}, INT64_MAX, INT64_MAX,
                       {6148914691236517204, INT64_MAX, true});
            validate(INT64_MAX, Price{1, 1}, INT64_MAX, INT64_MAX,
                     {INT64_MAX, INT64_MAX, false});
            validateV2(INT64_MAX, Price{2, 3}, INT64_MAX, INT64_MAX,
                       {INT64_MAX - 1, 6148914691236517204, false},
                       REDUCED_CHECK_V2_RELAXED);
            validateV3(INT64_MAX, Price{2, 3}, INT64_MAX, INT64_MAX,
                       {INT64_MAX, 6148914691236517205, false});
            validateV2(INT64_MAX, Price{1, INT32_MAX}, INT64_MAX, INT64_MAX,
                       {INT64_MAX - 1, 4294967298, false},
                       REDUCED_CHECK_V2_RELAXED);
            validateV3(INT64_MAX, Price{1, INT32_MAX}, INT64_MAX, INT64_MAX,
                       {INT64_MAX, 4294967299, false});
            validateV2(INT64_MAX, Price{INT32_MAX, 1}, INT64_MAX, INT64_MAX,
                       {4294967298, INT64_MAX, false},
                       REDUCED_CHECK_V2_RELAXED);
            validateV3(INT64_MAX, Price{INT32_MAX, 1}, INT64_MAX, INT64_MAX,
                       {4294967298, INT64_MAX, true});
            validate(INT64_MAX, Price{INT32_MAX, INT32_MAX}, INT64_MAX,
                     INT64_MAX, {INT64_MAX, INT64_MAX, false});
        }
    }
}

TEST_CASE("ExchangeV10", "[exchange]")
{
    SECTION("Limited by maxWheatSend and maxSheepSend")
    {
        auto checkExchangeV10 = [](Price const& p, int64_t maxWheatSend,
                                   int64_t maxSheepSend, int64_t wheatReceive,
                                   int64_t sheepSend) {
            auto res = exchangeV10(Config::CURRENT_LEDGER_PROTOCOL_VERSION, p,
                                   maxWheatSend, INT64_MAX, maxSheepSend,
                                   INT64_MAX, RoundingType::NORMAL);
            REQUIRE(res.wheatStays ==
                    (maxWheatSend * p.n > maxSheepSend * p.d));
            REQUIRE(res.numWheatReceived == wheatReceive);
            REQUIRE(res.numSheepSend == sheepSend);
            if (res.wheatStays)
            {
                REQUIRE(sheepSend * p.d >= wheatReceive * p.n);
            }
            else
            {
                REQUIRE(sheepSend * p.d <= wheatReceive * p.n);
            }
        };

        SECTION("price > 1")
        {
            // Exact boundary
            checkExchangeV10(Price{3, 2}, 3000, 4501, 3000, 4500);
            checkExchangeV10(Price{3, 2}, 3000, 4500, 3000, 4500);
            checkExchangeV10(Price{3, 2}, 3000, 4499, 2999, 4499);

            // Boundary between two values
            checkExchangeV10(Price{3, 2}, 2999, 4499, 2999, 4498);
            checkExchangeV10(Price{3, 2}, 2999, 4498, 2998, 4497);
        }

        SECTION("price < 1")
        {
            // Exact boundary
            checkExchangeV10(Price{2, 3}, 3000, 2001, 3000, 2000);
            checkExchangeV10(Price{2, 3}, 3000, 2000, 3000, 2000);
            checkExchangeV10(Price{2, 3}, 3000, 1999, 2998, 1999);

            // Boundary between two values
            checkExchangeV10(Price{2, 3}, 2999, 2000, 2999, 1999);
            checkExchangeV10(Price{2, 3}, 2999, 1999, 2998, 1999);
        }
    }

    SECTION("Limited by maxWheatReceive and maxSheepReceive")
    {
        auto checkExchangeV10 =
            [](Price const& p, int64_t maxWheatReceive, int64_t maxSheepReceive,
               int64_t wheatReceive, int64_t sheepSend,
               ProtocolVersion protocolVersion = static_cast<ProtocolVersion>(
                   Config::CURRENT_LEDGER_PROTOCOL_VERSION)) {
                auto res = exchangeV10(static_cast<uint32_t>(protocolVersion),
                                       p, INT64_MAX, maxWheatReceive, INT64_MAX,
                                       maxSheepReceive, RoundingType::NORMAL);
                REQUIRE(res.wheatStays ==
                        (maxSheepReceive * p.d > maxWheatReceive * p.n));
                REQUIRE(res.numWheatReceived == wheatReceive);
                REQUIRE(res.numSheepSend == sheepSend);
                if (res.wheatStays)
                {
                    REQUIRE(sheepSend * p.d >= wheatReceive * p.n);
                }
                else
                {
                    REQUIRE(sheepSend * p.d <= wheatReceive * p.n);
                }
            };

        SECTION("price > 1")
        {
            // Exact boundary
            checkExchangeV10(Price{3, 2}, 3000, 4501, 3000, 4500);
            checkExchangeV10(Price{3, 2}, 3000, 4500, 3000, 4500);
            checkExchangeV10(Price{3, 2}, 3000, 4499, 2999, 4498);

            // Boundary between two values
            checkExchangeV10(Price{3, 2}, 2999, 4499, 2999, 4499);

            // Starting from protocol 29 the taken offer amount is computed
            // without a rounding error, so we send 1 sheep more than before (
            // full amount available).
            checkExchangeV10(Price{3, 2}, 2999, 4498, 2998, 4497,
                             ProtocolVersion::V_28);
            checkExchangeV10(Price{3, 2}, 2999, 4498, 2999, 4498,
                             ProtocolVersion::V_29);
        }

        SECTION("price < 1")
        {
            // Exact boundary
            checkExchangeV10(Price{2, 3}, 3000, 2001, 3000, 2000);
            checkExchangeV10(Price{2, 3}, 3000, 2000, 3000, 2000);
            checkExchangeV10(Price{2, 3}, 3000, 1999, 2999, 1999);

            // Boundary between two values
            checkExchangeV10(Price{2, 3}, 2999, 2000, 2998, 1999);
            checkExchangeV10(Price{2, 3}, 2999, 1999, 2999, 1999);
        }
    }

    SECTION("Limited by maxWheatSend and maxWheatReceive")
    {
        auto checkExchangeV10 = [](Price const& p, int64_t maxWheatSend,
                                   int64_t maxWheatReceive,
                                   int64_t wheatReceive, int64_t sheepSend) {
            auto res = exchangeV10(Config::CURRENT_LEDGER_PROTOCOL_VERSION, p,
                                   maxWheatSend, maxWheatReceive, INT64_MAX,
                                   INT64_MAX, RoundingType::NORMAL);
            REQUIRE(res.wheatStays == (maxWheatSend > maxWheatReceive));
            REQUIRE(res.numWheatReceived == wheatReceive);
            REQUIRE(res.numSheepSend == sheepSend);
            if (res.wheatStays)
            {
                REQUIRE(sheepSend * p.d >= wheatReceive * p.n);
            }
            else
            {
                REQUIRE(sheepSend * p.d <= wheatReceive * p.n);
            }
        };

        SECTION("price > 1")
        {
            // Exact boundary (boundary between values impossible in this case)
            checkExchangeV10(Price{3, 2}, 3000, 3001, 3000, 4500);
            checkExchangeV10(Price{3, 2}, 3000, 3000, 3000, 4500);
            checkExchangeV10(Price{3, 2}, 3000, 2999, 2999, 4499);
        }

        SECTION("price < 1")
        {
            // Exact boundary (boundary between values impossible in this case)
            checkExchangeV10(Price{2, 3}, 3000, 3001, 3000, 2000);
            checkExchangeV10(Price{2, 3}, 3000, 3000, 3000, 2000);
            checkExchangeV10(Price{2, 3}, 3000, 2999, 2998, 1999);
        }
    }

    SECTION("Limited by maxSheepSend and maxSheepReceive")
    {
        auto checkExchangeV10 = [](Price const& p, int64_t maxSheepSend,
                                   int64_t maxSheepReceive,
                                   int64_t wheatReceive, int64_t sheepSend) {
            auto res = exchangeV10(Config::CURRENT_LEDGER_PROTOCOL_VERSION, p,
                                   INT64_MAX, INT64_MAX, maxSheepSend,
                                   maxSheepReceive, RoundingType::NORMAL);
            REQUIRE(res.wheatStays == (maxSheepReceive > maxSheepSend));
            REQUIRE(res.numWheatReceived == wheatReceive);
            REQUIRE(res.numSheepSend == sheepSend);
            if (res.wheatStays)
            {
                REQUIRE(sheepSend * p.d >= wheatReceive * p.n);
            }
            else
            {
                REQUIRE(sheepSend * p.d <= wheatReceive * p.n);
            }
        };

        SECTION("price > 1")
        {
            // Exact boundary (boundary between values impossible in this case)
            checkExchangeV10(Price{3, 2}, 4500, 4501, 3000, 4500);
            checkExchangeV10(Price{3, 2}, 4500, 4500, 3000, 4500);
            checkExchangeV10(Price{3, 2}, 4500, 4499, 2999, 4498);
        }

        SECTION("price < 1")
        {
            // Exact boundary (boundary between values impossible in this case)
            checkExchangeV10(Price{2, 3}, 2000, 2001, 3000, 2000);
            checkExchangeV10(Price{2, 3}, 2000, 2000, 3000, 2000);
            checkExchangeV10(Price{2, 3}, 2000, 1999, 2999, 1999);
        }
    }

    SECTION("Threshold")
    {
        auto checkExchangeV10 = [](Price const& p, int64_t maxWheatSend,
                                   int64_t maxWheatReceive,
                                   int64_t wheatReceive, int64_t sheepSend) {
            auto res = exchangeV10(Config::CURRENT_LEDGER_PROTOCOL_VERSION, p,
                                   maxWheatSend, maxWheatReceive, INT64_MAX,
                                   INT64_MAX, RoundingType::NORMAL);
            REQUIRE(res.wheatStays == (maxWheatSend > maxWheatReceive));
            REQUIRE(res.numWheatReceived == wheatReceive);
            REQUIRE(res.numSheepSend == sheepSend);
            if (res.wheatStays)
            {
                REQUIRE(sheepSend * p.d >= wheatReceive * p.n);
            }
            else
            {
                REQUIRE(sheepSend * p.d <= wheatReceive * p.n);
            }
        };

        // Exchange nothing if thresholds exceeded
        checkExchangeV10(Price{3, 2}, 28, 27, 0, 0);
        checkExchangeV10(Price{3, 2}, 28, 26, 26, 39);

        // Thresholds not exceeded for sufficiently large offers
        checkExchangeV10(Price{3, 2}, 52, 51, 51, 77);
        checkExchangeV10(Price{3, 2}, 52, 50, 50, 75);
    }

    SECTION("Rounding for PATH_PAYMENT_STRICT_RECEIVE")
    {
        auto check = [](Price const& p, int64_t maxWheatSend,
                        int64_t maxWheatReceive, RoundingType round,
                        int64_t wheatReceive, int64_t sheepSend) {
            auto res = exchangeV10(Config::CURRENT_LEDGER_PROTOCOL_VERSION, p,
                                   maxWheatSend, maxWheatReceive, INT64_MAX,
                                   INT64_MAX, round);
            REQUIRE(res.wheatStays == (maxWheatSend > maxWheatReceive));
            REQUIRE(res.numWheatReceived == wheatReceive);
            REQUIRE(res.numSheepSend == sheepSend);
        };

        SECTION("no thresholding")
        {
            check(Price{3, 2}, 28, 27, RoundingType::NORMAL, 0, 0);
            check(Price{3, 2}, 28, 27,
                  RoundingType::PATH_PAYMENT_STRICT_RECEIVE, 27, 41);
        }

        SECTION("result is unchanged if wheat is more valuable")
        {
            check(Price{3, 2}, 150, 101, RoundingType::NORMAL, 101, 152);
            check(Price{3, 2}, 150, 101,
                  RoundingType::PATH_PAYMENT_STRICT_RECEIVE, 101, 152);
        }

        SECTION("transfer can increase if sheep is more valuable")
        {
            check(Price{2, 3}, 150, 101, RoundingType::NORMAL, 100, 67);
            check(Price{2, 3}, 150, 101,
                  RoundingType::PATH_PAYMENT_STRICT_RECEIVE, 101, 68);
        }
    }

    SECTION("Rounding for PATH_PAYMENT_STRICT_SEND")
    {
        auto check = [](Price const& p, int64_t maxWheatSend,
                        int64_t maxWheatReceive, int64_t maxSheepSend,
                        RoundingType round, int64_t wheatReceive,
                        int64_t sheepSend) {
            auto res = exchangeV10(Config::CURRENT_LEDGER_PROTOCOL_VERSION, p,
                                   maxWheatSend, maxWheatReceive, maxSheepSend,
                                   INT64_MAX, round);
            // This is not generally true, but it is a simple interface for what
            // we need to test.
            if (maxWheatReceive == INT64_MAX)
            {
                REQUIRE(res.wheatStays);
            }
            else
            {
                REQUIRE(res.wheatStays ==
                        bigMultiply(maxWheatSend, p.n) >
                            std::min(bigMultiply(maxSheepSend, p.d),
                                     bigMultiply(maxWheatReceive, p.n)));
            }
            REQUIRE(res.numWheatReceived == wheatReceive);
            REQUIRE(res.numSheepSend == sheepSend);
        };

        SECTION("no thresholding")
        {
            check(Price{3, 2}, 28, INT64_MAX, 41, RoundingType::NORMAL, 0, 0);
            check(Price{3, 2}, 28, INT64_MAX, 41,
                  RoundingType::PATH_PAYMENT_STRICT_SEND, 27, 41);
        }

        SECTION("transfer can increase if wheat is more valuable")
        {
            REQUIRE(adjustOffer(Config::CURRENT_LEDGER_PROTOCOL_VERSION,
                                Price{3, 2}, 97, INT64_MAX) == 97);
            check(Price{3, 2}, 97, INT64_MAX, 145, RoundingType::NORMAL, 96,
                  144);
            check(Price{3, 2}, 97, INT64_MAX, 145,
                  RoundingType::PATH_PAYMENT_STRICT_SEND, 96, 145);
        }

        SECTION("transfer can increase if sheep is more valuable")
        {
            check(Price{2, 3}, 97, 95, INT64_MAX, RoundingType::NORMAL, 94, 63);
            check(Price{2, 3}, 97, 95, INT64_MAX,
                  RoundingType::PATH_PAYMENT_STRICT_SEND, 95, INT64_MAX);
        }

        SECTION("can send nonzero while receiving zero")
        {
            check(Price{2, 1}, 1, INT64_MAX, 1, RoundingType::NORMAL, 0, 0);
            check(Price{2, 1}, 1, INT64_MAX, 1,
                  RoundingType::PATH_PAYMENT_STRICT_SEND, 0, 1);
        }
    }
}

// Protocol 29 changes the amount block of exchangeV10 for the branch where the
// wheat offer does not stay and wheat is the more valuable asset: it divides
// the relaxed value from calculateOfferAmountFromValue instead of the plain
// wheat value. That branch is reachable in both strict rounding modes, and the
// enlarged amount pair it returns can miss the one-sided price error bound that
// strict modes enforce with a throw rather than by zeroing the trade.
//
// The consequence is that the "the wheat offer has been adjusted at this
// protocol version" precondition of exchangeV10 became load-bearing at protocol
// 29 in a way it was not at protocol 28. Calling exchangeV10 directly with a
// wheat offer that is not a protocol-29 adjustOffer fixed point can turn a
// protocol-28 success into a protocol-29 throw. crossOfferV10 does not do that:
// it calls adjustOffer at the current ledger version immediately before
// exchangeV10, and the second section below is a bounded check that no such
// input survives that call.
TEST_CASE("ExchangeV10 strict modes require an offer adjusted at the current "
          "protocol version",
          "[exchange]")
{
    // A wheat offer of 3 at price 3/2 whose seller can receive at most 4 sheep.
    Price const p{3, 2};
    int64_t const maxWheatSend = 3;
    int64_t const maxWheatReceive = 3;
    int64_t const maxSheepSend = 4;
    int64_t const maxSheepReceive = 4;

    auto const v28 = static_cast<uint32_t>(ProtocolVersion::V_28);
    auto const v29 = static_cast<uint32_t>(ProtocolVersion::V_29);

    SECTION("an unadjusted offer succeeds at protocol 28 and throws at 29")
    {
        for (auto round : {RoundingType::PATH_PAYMENT_STRICT_SEND,
                           RoundingType::PATH_PAYMENT_STRICT_RECEIVE})
        {
            // wheatValue = min(3*3, 4*2) = 8, sheepValue = min(4*2, 3*3) = 8,
            // so the wheat offer does not stay, and wheat is more valuable.

            // Protocol 28 divides the plain wheat value: wheatReceive =
            // floor(8/3) = 2 and sheepSend = floor(2*3/2) = 3. Two wheat for
            // three sheep is exactly price 3/2, so the bound is met.
            auto res28 = exchangeV10(v28, p, maxWheatSend, maxWheatReceive,
                                     maxSheepSend, maxSheepReceive, round);
            REQUIRE(!res28.wheatStays);
            REQUIRE(res28.numWheatReceived == 2);
            REQUIRE(res28.numSheepSend == 3);

            // Protocol 29 divides the relaxed value:
            // calculateOfferAmountFromValue gives wheatReceive = floor(min(3*3,
            // 4*2 + 1)/3) = 3 and sheepSend = floor(3*3/2) = 4. The amount
            // block itself is happy: both amounts are still within every cap.
            auto before = exchangeV10WithoutPriceErrorThresholds(
                v29, p, maxWheatSend, maxWheatReceive, maxSheepSend,
                maxSheepReceive, round);
            REQUIRE(!before.wheatStays);
            REQUIRE(before.numWheatReceived == 3);
            REQUIRE(before.numSheepSend == 4);

            // But three wheat at price 3/2 is worth four and a half sheep, so
            // paying four underpays the wheat seller by more than one percent,
            // and the strict-mode threshold pass throws instead of zeroing the
            // trade the way NORMAL would.
            REQUIRE(!checkPriceErrorBound(p, before.numWheatReceived,
                                          before.numSheepSend, true));
            REQUIRE_THROWS_AS(exchangeV10(v29, p, maxWheatSend, maxWheatReceive,
                                          maxSheepSend, maxSheepReceive, round),
                              std::runtime_error);
        }
    }

    SECTION("NORMAL rounding is unaffected")
    {
        // NORMAL applies the same bound but zeroes the trade instead of
        // throwing, so the same input is merely a no-op at protocol 29.
        auto res28 =
            exchangeV10(v28, p, maxWheatSend, maxWheatReceive, maxSheepSend,
                        maxSheepReceive, RoundingType::NORMAL);
        REQUIRE(res28.numWheatReceived == 2);
        REQUIRE(res28.numSheepSend == 3);

        auto res29 =
            exchangeV10(v29, p, maxWheatSend, maxWheatReceive, maxSheepSend,
                        maxSheepReceive, RoundingType::NORMAL);
        REQUIRE(res29.numWheatReceived == 0);
        REQUIRE(res29.numSheepSend == 0);
    }

    SECTION("the offer above is not adjusted at protocol 29")
    {
        // This is why crossOfferV10 never presents it. At protocol 28 the
        // offer rests at 2; at protocol 29 adjustOffer deletes it outright, so
        // maxWheatSend = 3 with maxSheepReceive = 4 is not a state the
        // crossing path can reach.
        REQUIRE(adjustOffer(v28, p, maxWheatSend, maxSheepReceive) == 2);
        REQUIRE(adjustOffer(v29, p, maxWheatSend, maxSheepReceive) == 0);
    }

    SECTION("no adjusted offer reaches the throw")
    {
        // Bounded confirmation of the claim in the comment above: over every
        // small price and cap combination whose wheat offer is already a
        // protocol-29 adjustOffer fixed point -- which is exactly what
        // crossOfferV10 passes to exchangeV10 -- neither strict mode throws.
        // Counted rather than asserted per call, to keep this a handful of
        // Catch2 assertions rather than millions of them.
        int64_t const bound = 12;
        size_t fixedPoints = 0;
        size_t calls = 0;
        size_t throws = 0;
        for (int32_t priceN = 1; priceN <= bound; ++priceN)
        {
            for (int32_t priceD = 1; priceD <= bound; ++priceD)
            {
                Price const price{priceN, priceD};
                for (int64_t wheatSend = 1; wheatSend <= bound; ++wheatSend)
                {
                    for (int64_t sheepReceive = 1; sheepReceive <= bound;
                         ++sheepReceive)
                    {
                        if (adjustOffer(v29, price, wheatSend, sheepReceive) !=
                            wheatSend)
                        {
                            continue;
                        }
                        ++fixedPoints;
                        for (int64_t wheatReceive = 1; wheatReceive <= bound;
                             ++wheatReceive)
                        {
                            for (int64_t sheepSend = 1; sheepSend <= bound;
                                 ++sheepSend)
                            {
                                for (auto round :
                                     {RoundingType::PATH_PAYMENT_STRICT_SEND,
                                      RoundingType::
                                          PATH_PAYMENT_STRICT_RECEIVE})
                                {
                                    ++calls;
                                    try
                                    {
                                        exchangeV10(v29, price, wheatSend,
                                                    wheatReceive, sheepSend,
                                                    sheepReceive, round);
                                    }
                                    catch (std::runtime_error const&)
                                    {
                                        ++throws;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Pin the search space so it cannot silently shrink, then state the
        // result: 2959 of the 12^4 price and cap combinations are protocol-29
        // adjustment fixed points, and none of the 852192 strict-mode calls
        // they generate throws.
        REQUIRE(fixedPoints == 2959);
        REQUIRE(calls == 852192);
        REQUIRE(throws == 0);
    }
}

TEST_CASE("Adjust Offer", "[exchange]")
{
    auto checkAdjustOffer =
        [](Price const& p, int64_t maxWheatSend, int64_t maxSheepReceive,
           int64_t expectedAmount,
           ProtocolVersion protocolVersion = static_cast<ProtocolVersion>(
               Config::CURRENT_LEDGER_PROTOCOL_VERSION)) {
            int64_t adjAmount =
                adjustOffer(static_cast<uint32_t>(protocolVersion), p,
                            maxWheatSend, maxSheepReceive);
            REQUIRE(adjAmount == expectedAmount);
        };

    SECTION("Limits")
    {
        SECTION("price > 1")
        {
            SECTION("limited by maxWheatSend")
            {
                checkAdjustOffer(Price{1, 1000}, 2001, INT64_MAX, 2000);
                checkAdjustOffer(Price{1, 1000}, 2000, INT64_MAX, 2000);
                checkAdjustOffer(Price{1, 1000}, 1999, INT64_MAX, 1000);
            }

            SECTION("limited (or not) by maxSheepReceive")
            {
                checkAdjustOffer(Price{1, 1000}, 2000, 3, 2000);
                checkAdjustOffer(Price{1, 1000}, 2000, 2, 2000);
                checkAdjustOffer(Price{1, 1000}, 2000, 1, 1000);
            }
        }

        SECTION("price < 1")
        {
            SECTION("limited by maxWheatSend")
            {
                checkAdjustOffer(Price{1000, 1}, 401, INT64_MAX, 401);
                checkAdjustOffer(Price{1000, 1}, 400, INT64_MAX, 400);
                checkAdjustOffer(Price{1000, 1}, 399, INT64_MAX, 399);
            }

            SECTION("limited (or not) by maxSheepReceive")
            {
                checkAdjustOffer(Price{1000, 1}, 400, 400 * 1000 + 1, 400);
                checkAdjustOffer(Price{1000, 1}, 400, 400 * 1000, 400);
                checkAdjustOffer(Price{1000, 1}, 400, 400 * 1000 - 1, 399);
            }
        }
    }

    SECTION("Adjusting offer again has no effect")
    {
        auto checkAdjustOfferTwice =
            [&](Price const& p, int64_t maxWheatSend, int64_t maxSheepReceive,
                int64_t expectedAmount,
                ProtocolVersion protocolVersion = static_cast<ProtocolVersion>(
                    Config::CURRENT_LEDGER_PROTOCOL_VERSION)) {
                checkAdjustOffer(p, maxWheatSend, maxSheepReceive,
                                 expectedAmount, protocolVersion);
                checkAdjustOffer(p, expectedAmount, maxSheepReceive,
                                 expectedAmount, protocolVersion);
            };

        SECTION("price > 1")
        {
            SECTION("limited by maxWheatSend")
            {
                checkAdjustOfferTwice(Price{7, 3}, 429, INT64_MAX, 429);
                checkAdjustOfferTwice(Price{7, 3}, 428, INT64_MAX, 428);
                checkAdjustOfferTwice(Price{7, 3}, 427, INT64_MAX, 427);
            }

            SECTION("limited (or not) by maxSheepReceive")
            {
                checkAdjustOfferTwice(Price{7, 3}, 428, 999, 428);
                checkAdjustOfferTwice(Price{7, 3}, 428, 997, 427);

                // Starting from protocol 29 the taken offer amount is computed
                // without a rounding error, so we send 1 wheat more than
                // before (full amount available).
                checkAdjustOfferTwice(Price{7, 3}, 428, 998, 427,
                                      ProtocolVersion::V_28);
                checkAdjustOfferTwice(Price{7, 3}, 428, 998, 428,
                                      ProtocolVersion::V_29);
            }
        }

        SECTION("price < 1")
        {
            SECTION("limited by maxWheatSend")
            {
                checkAdjustOfferTwice(Price{3, 7}, 1001, INT64_MAX, 1001);
                checkAdjustOfferTwice(Price{3, 7}, 1000, INT64_MAX, 999);
                checkAdjustOfferTwice(Price{3, 7}, 999, INT64_MAX, 999);
            }

            SECTION("limited (or not) by maxSheepReceive")
            {
                checkAdjustOfferTwice(Price{3, 7}, 1000, 429, 999);
                checkAdjustOfferTwice(Price{3, 7}, 1000, 428, 999);
                checkAdjustOfferTwice(Price{3, 7}, 1000, 427, 997);
            }
        }
    }

    SECTION("Thresholds")
    {
        // Thresholds effect some small offers but not all
        checkAdjustOffer(Price{3, 2}, 29, INT64_MAX, 0);
        checkAdjustOffer(Price{3, 2}, 28, INT64_MAX, 28);
        checkAdjustOffer(Price{3, 2}, 27, INT64_MAX, 0);
        checkAdjustOffer(Price{3, 2}, 26, INT64_MAX, 26);

        // Thresholds don't effect sufficiently large offers
        checkAdjustOffer(Price{3, 2}, 51, INT64_MAX, 51);
        checkAdjustOffer(Price{3, 2}, 50, INT64_MAX, 50);
    }
}

TEST_CASE("Check price error bounds", "[exchange]")
{
    auto validateBounds = [](Price const& p, int64_t wheatReceive,
                             int64_t sheepSendHigh, int64_t sheepSendLow,
                             bool canFavorWheat) {
        REQUIRE(checkPriceErrorBound(p, wheatReceive, sheepSendHigh + 1,
                                     canFavorWheat) == canFavorWheat);
        REQUIRE(checkPriceErrorBound(p, wheatReceive, sheepSendHigh,
                                     canFavorWheat));
        REQUIRE(
            checkPriceErrorBound(p, wheatReceive, sheepSendLow, canFavorWheat));
        REQUIRE(!checkPriceErrorBound(p, wheatReceive, sheepSendLow - 1,
                                      canFavorWheat));
    };

    for (bool canFavorWheat : {false, true})
    {
        SECTION(canFavorWheat ? "can favor wheat" : "cannot favor wheat")
        {
            // No rounding
            validateBounds(Price{1, 1}, 1000, 1010, 990, canFavorWheat);
            // No rounding on boundary, p > 1
            validateBounds(Price{5, 2}, 1000, 2525, 2475, canFavorWheat);
            // No rounding on boundary, p < 1
            validateBounds(Price{2, 5}, 1000, 404, 396, canFavorWheat);
            // Rounding on boundary, p > 1
            validateBounds(Price{7, 3}, 1000, 2356, 2310, canFavorWheat);
            // Rounding on boundary, p > 1
            validateBounds(Price{3, 7}, 1000, 432, 425, canFavorWheat);
        }
    }
}

TEST_CASE("getPoolWithdrawalAmount", "[exchange]")
{
    REQUIRE(getPoolWithdrawalAmount(5, 10, 6) == 3);
    REQUIRE(getPoolWithdrawalAmount(4, 5, 9) == 7);
    REQUIRE(getPoolWithdrawalAmount(INT64_MAX, INT64_MAX, INT64_MAX) ==
            INT64_MAX);
}

TEST_CASE("Exchange with liquidity pools", "[exchange]")
{
    auto validate = [](int64_t reservesToPool, int64_t maxSendToPool,
                       int64_t reservesFromPool, int64_t maxReceiveFromPool,
                       int32_t feeInBps, RoundingType round, bool success,
                       int64_t expToPool, int64_t expFromPool) {
        int64_t toPool = 0;
        int64_t fromPool = 0;
        bool res = exchangeWithPool(reservesToPool, maxSendToPool, toPool,
                                    reservesFromPool, maxReceiveFromPool,
                                    fromPool, feeInBps, round);
        REQUIRE(res == success);
        if (res)
        {
            REQUIRE(toPool == expToPool);
            REQUIRE(fromPool == expFromPool);
        }
    };

    RoundingType const send = RoundingType::PATH_PAYMENT_STRICT_SEND;
    RoundingType const recv = RoundingType::PATH_PAYMENT_STRICT_RECEIVE;

    SECTION("Error conditions")
    {
        // feeBps < 0
        REQUIRE_THROWS(
            validate(100, 50, 100, INT64_MAX, -1, send, false, 0, 0));
        REQUIRE_THROWS(
            validate(100, INT64_MAX, 100, 50, -1, recv, false, 0, 0));

        // feeBps == maxBps
        REQUIRE_THROWS(
            validate(100, 50, 100, INT64_MAX, 10000, send, false, 0, 0));
        REQUIRE_THROWS(
            validate(100, INT64_MAX, 100, 50, 10000, recv, false, 0, 0));

        // feeBps > maxBps
        REQUIRE_THROWS(
            validate(100, 50, 100, INT64_MAX, INT32_MAX, send, false, 0, 0));
        REQUIRE_THROWS(
            validate(100, INT64_MAX, 100, 50, INT32_MAX, recv, false, 0, 0));

        // Strict send with bounded receive
        REQUIRE_THROWS(
            validate(100, 50, 100, INT64_MAX - 1, 0, send, false, 0, 0));
        REQUIRE_THROWS(validate(100, 50, 100, 0, 0, send, false, 0, 0));

        // Strict receive with bounded send
        REQUIRE_THROWS(
            validate(100, INT64_MAX - 1, 100, 50, 0, recv, false, 0, 0));
        REQUIRE_THROWS(validate(100, 0, 100, 50, 0, recv, false, 0, 0));

        // Not path payment
        REQUIRE_THROWS(
            validate(100, 50, 100, 50, 0, RoundingType::NORMAL, false, 0, 0));
    }

    SECTION("strict send failure cases")
    {
        // Sending maxSendToPool would overflow the reserve: low reserves but
        // high maxSend
        validate(100, INT64_MAX - 100, 100, INT64_MAX, 0, send, true,
                 INT64_MAX - 100, 99);
        validate(100, INT64_MAX - 99, 100, INT64_MAX, 0, send, false, 0, 0);

        // Sending maxSendToPool would overflow the reserve: high reserves but
        // low maxSend
        validate(INT64_MAX - 100, 100, INT64_MAX - 100, INT64_MAX, 0, send,
                 true, 100, 99);
        validate(INT64_MAX - 99, 100, INT64_MAX - 100, INT64_MAX, 0, send,
                 false, 0, 0);

        // As far as I can tell, the hugeDivide can never fail.

        // fromPool = 0
        validate(100, 2, 100, INT64_MAX, 0, send, true, 2, 1);
        validate(100, 1, 100, INT64_MAX, 0, send, false, 0, 0);
    }

    SECTION("strict receive failure cases")
    {
        // Receiving maxReceiveFromPool would deplete the reserves entirely: low
        // reserves and low maxReceive
        validate(100, INT64_MAX, 100, 99, 0, recv, true, 9900, 99);
        validate(100, INT64_MAX, 100, 100, 0, recv, false, 0, 0);

        // Receiving maxReceiveFromPool would deplete the reserves entirely:
        // high reserves and high maxReceive
        validate(100, INT64_MAX, INT64_MAX / 100, INT64_MAX / 100 - 1, 0, recv,
                 true, INT64_MAX - 107, INT64_MAX / 100 - 1);
        validate(100, INT64_MAX, INT64_MAX / 100, INT64_MAX / 100, 0, recv,
                 false, 0, 0);

        // If fromPool = k*(maxBps - feeBps) and reservesFromPool = fromPool + 1
        // then
        //     (reservesToPool * fromPool) / (maxBps - feeBps)
        //         = k * reservesToPool
        // so if k = 101 and reservesToPool = INT64_MAX / 100 then
        // B / C > INT64_MAX in the hugeDivide.
        validate(INT64_MAX / 100, INT64_MAX, 101 * 10000 + 1, 101 * 10000, 0,
                 recv, false, 0, 0);

        // If fromPool = maxBps - feeBps and reservesFromPool = fromPool + 1
        // then
        //      toPool = maxBps * reservesToPool
        // so if reservesToPool = INT64_MAX / 100 then the hugeDivide overflows.
        validate(INT64_MAX / 100, INT64_MAX, 10000 + 1, 10000, 0, recv, false,
                 0, 0);

        // Pool receives more than it has available reserves for
        validate(INT64_MAX - 100, INT64_MAX, INT64_MAX / 2, 49, 0, recv, true,
                 98, 49);
        validate(INT64_MAX - 100, INT64_MAX, INT64_MAX / 2, 50, 0, recv, false,
                 0, 0);
    }

    SECTION("No fees")
    {
        SECTION("Strict send")
        {
            // Works exactly
            validate(100, 100, 100, INT64_MAX, 0, send, true, 100, 50);

            // Requires sending
            validate(100, 50, 100, INT64_MAX, 0, send, true, 50, 33);

            // Sending 0
            validate(100, 0, 100, INT64_MAX, 0, send, false, 0, 0);

            // Sending too much
            validate(100, INT64_MAX - 99, 100, INT64_MAX, 0, send, false, 0, 0);
        }

        SECTION("Strict receive")
        {
            // Works exactly
            validate(100, INT64_MAX, 100, 50, 0, recv, true, 100, 50);

            // Requires recving
            validate(100, INT64_MAX, 100, 33, 0, recv, true, 50, 33);

            // Receiving 0
            validate(100, INT64_MAX, 100, 0, 0, recv, true, 0, 0);

            // Receiving too much
            validate(100, INT64_MAX, 100, 100, 0, recv, false, 0, 0);
        }
    }

    SECTION("30 bps fee actually charges 30 bps")
    {
        // These test cases look weird because they actually charge 31 bps
        // instead of 30 bps. But this is expected, because you pay fees on
        // the fees you provided: I want to send 10000 after fees, so I send
        // 100030.... but that doesn't work because 0.997 * 10030 = 9999.910
        // is too low.

        SECTION("Strict send")
        {
            // With no fee, sending 10000 would receive 10000. So to receive
            // 1000 we need to send ceil(10000 / 0.997) = 10031.
            validate(10000, 10031, 20000, INT64_MAX, 30, send, true, 10031,
                     10000);
        }

        SECTION("Strict receive")
        {
            // With no fee, sending 10000 would receive 10000. So to send
            // ceil(10000 / 0.997) = 10031 we need to receive 10000.
            validate(10000, INT64_MAX, 20000, 10000, 30, recv, true, 10031,
                     10000);
        }
    }
}

// ============================================================================
// Randomized verification of the rounding/liability invariants that are only
// argued informally in the (long) comments in OfferExchange.cpp.
//
// The claims under test are:
//   (1) exchangeV10 never throws, for any non-negative int64 inputs. The
//       internal "out of bounds" checks and the bigDivideOrThrow128 calls are
//       claimed to be unreachable.
//   (2) The party whose offer stays on the book is never disfavored.
//   (3) With the trustline limit set to the absolute minimum that can still
//       back the offer (buying headroom == the offer's buying liabilities,
//       wheat balance == the offer's selling liabilities), a crossing still
//       succeeds, and the *re-derived* liabilities of the residual offer fit
//       in what is left. This is the floor/ceil reconciliation: liabilities
//       are always computed with floor, but a crossing may pay out a ceil.
// ============================================================================

namespace
{

int64_t
randAmount(std::mt19937_64& gen)
{
    switch (std::uniform_int_distribution<int>(0, 5)(gen))
    {
    case 0:
        // Tiny offers: where the 1% price error threshold bites.
        return std::uniform_int_distribution<int64_t>(0, 40)(gen);
    case 1:
        return std::uniform_int_distribution<int64_t>(0, 10000)(gen);
    case 2:
        // Realistic stroop amounts.
        return std::uniform_int_distribution<int64_t>(1, 10000000000000LL)(gen);
    case 3:
        return std::uniform_int_distribution<int64_t>(0, INT64_MAX)(gen);
    case 4:
        // Saturating: forces the min() in calculateOfferValue to bind on the
        // other term and stresses bigDivideOrThrow128.
        return INT64_MAX - std::uniform_int_distribution<int64_t>(0, 8)(gen);
    default:
        return INT64_MAX;
    }
}

int32_t
randPriceComponent(std::mt19937_64& gen)
{
    switch (std::uniform_int_distribution<int>(0, 4)(gen))
    {
    case 0:
        return std::uniform_int_distribution<int32_t>(1, 12)(gen);
    case 1:
        return std::uniform_int_distribution<int32_t>(1, 1000)(gen);
    case 2:
        return std::uniform_int_distribution<int32_t>(1, INT32_MAX)(gen);
    case 3:
        return INT32_MAX - std::uniform_int_distribution<int32_t>(0, 4)(gen);
    default:
        return 1;
    }
}

Price
randPrice(std::mt19937_64& gen)
{
    Price p;
    p.n = randPriceComponent(gen);
    p.d = randPriceComponent(gen);
    return p;
}

// Mirrors getOfferBuyingLiabilities/getOfferSellingLiabilities in
// TransactionUtils.cpp and the identical helpers in LiabilitiesMatchOffers.cpp.
struct OfferLiabilities
{
    int64_t selling;
    int64_t buying;
};

OfferLiabilities
offerLiabilities(uint32_t ledgerVersion, Price const& p, int64_t amount)
{
    auto res = exchangeV10WithoutPriceErrorThresholds(
        ledgerVersion, p, amount, INT64_MAX, INT64_MAX, INT64_MAX,
        RoundingType::NORMAL);
    return OfferLiabilities{res.numWheatReceived, res.numSheepSend};
}

std::string
describe(Price const& p, int64_t maxWheatSend, int64_t maxWheatReceive,
         int64_t maxSheepSend, int64_t maxSheepReceive, RoundingType round)
{
    return fmt::format(
        FMT_STRING("price={}/{} maxWheatSend={} maxWheatReceive={} "
                   "maxSheepSend={} maxSheepReceive={} round={}"),
        p.n, p.d, maxWheatSend, maxWheatReceive, maxSheepSend, maxSheepReceive,
        static_cast<int>(round));
}
}

TEST_CASE("ExchangeV10 randomized bounds", "[exchange][exchangerandom]")
{
    uint32_t const ledgerVersion = GENERATE(
        static_cast<uint32_t>(ProtocolVersion::V_28),
        static_cast<uint32_t>(ProtocolVersion::V_29));
    INFO("ledgerVersion=" << ledgerVersion);
    std::mt19937_64 gen(20260806);
    RoundingType const rounds[] = {RoundingType::NORMAL,
                                   RoundingType::PATH_PAYMENT_STRICT_SEND,
                                   RoundingType::PATH_PAYMENT_STRICT_RECEIVE};

    size_t const ITERATIONS = 300000;
    for (size_t i = 0; i < ITERATIONS; ++i)
    {
        auto p = randPrice(gen);
        int64_t maxWheatSend = randAmount(gen);
        int64_t maxWheatReceive = randAmount(gen);
        int64_t maxSheepSend = randAmount(gen);
        int64_t maxSheepReceive = randAmount(gen);
        auto round = rounds[std::uniform_int_distribution<int>(0, 2)(gen)];

        // crossOfferV10 always calls adjustOffer immediately before
        // exchangeV10, with exactly these two limits. The path payment
        // rounding modes rely on that: applyPriceErrorThresholds throws
        // "exceeded price error bound" for an unadjusted offer that cannot be
        // crossed within 1%. Model the same precondition here.
        maxWheatSend = adjustOffer(ledgerVersion, p, maxWheatSend, maxSheepReceive);

        // PATH_PAYMENT_STRICT_SEND asserts that it is never invoked in a
        // situation where no crossing should occur.
        if (round == RoundingType::PATH_PAYMENT_STRICT_SEND &&
            (maxSheepSend == 0 || maxSheepReceive == 0 || maxWheatSend == 0))
        {
            continue;
        }

        auto ctx = describe(p, maxWheatSend, maxWheatReceive, maxSheepSend,
                            maxSheepReceive, round);
        INFO(ctx);

        ExchangeResultV10 res;
        REQUIRE_NOTHROW(res = exchangeV10(ledgerVersion, p, maxWheatSend,
                                          maxWheatReceive, maxSheepSend,
                                          maxSheepReceive, round));

        // (1) Limits are respected.
        REQUIRE(res.numWheatReceived >= 0);
        REQUIRE(res.numWheatReceived <=
                std::min(maxWheatSend, maxWheatReceive));
        REQUIRE(res.numSheepSend >= 0);
        REQUIRE(res.numSheepSend <= std::min(maxSheepSend, maxSheepReceive));

        // (2) The offer that stays is never disfavored.
        if (res.numWheatReceived > 0 && res.numSheepSend > 0)
        {
            auto wheatValue = bigMultiply(res.numWheatReceived, p.n);
            auto sheepValue = bigMultiply(res.numSheepSend, p.d);
            if (res.wheatStays)
            {
                REQUIRE(sheepValue >= wheatValue);
            }
            else
            {
                REQUIRE(sheepValue <= wheatValue);
            }
        }

        // (3) wheatStays agrees with the exact comparison of offer values.
        auto wv = std::min(bigMultiply(maxWheatSend, p.n),
                           bigMultiply(maxSheepReceive, p.d));
        auto sv = std::min(bigMultiply(maxSheepSend, p.d),
                           bigMultiply(maxWheatReceive, p.n));
        REQUIRE(res.wheatStays == (wv > sv));

        // (4) Zero-consistency, and the 1% bound for NORMAL.
        if (round != RoundingType::PATH_PAYMENT_STRICT_SEND)
        {
            REQUIRE((res.numWheatReceived == 0) == (res.numSheepSend == 0));
        }
        if (round == RoundingType::NORMAL && res.numWheatReceived > 0)
        {
            REQUIRE(checkPriceErrorBound(p, res.numWheatReceived,
                                         res.numSheepSend, false));
        }
    }
}

TEST_CASE("Liabilities survive crossing at minimum limits",
          "[exchange][exchangerandom]")
{
    uint32_t const ledgerVersion = GENERATE(
        static_cast<uint32_t>(ProtocolVersion::V_28),
        static_cast<uint32_t>(ProtocolVersion::V_29));
    INFO("ledgerVersion=" << ledgerVersion);
    std::mt19937_64 gen(987654321);
    RoundingType const rounds[] = {RoundingType::NORMAL,
                                   RoundingType::PATH_PAYMENT_STRICT_SEND,
                                   RoundingType::PATH_PAYMENT_STRICT_RECEIVE};

    size_t const ITERATIONS = 300000;
    size_t crossings = 0;
    size_t ceilCrossings = 0;
    size_t tightBuying = 0;
    size_t shrunkAtMinLimit = 0;
    size_t evaporatedAtMinLimit = 0;
    size_t postShrinkTight = 0;
    size_t postShrinkGenerous = 0;
    size_t overPaidVsProRata = 0;
    for (size_t i = 0; i < ITERATIONS; ++i)
    {
        auto p = randPrice(gen);

        // An offer as it exists on the book: adjustOffer has been applied, so
        // amount == its own selling liabilities.
        int64_t storedAmount = adjustOffer(ledgerVersion, p, randAmount(gen), INT64_MAX);
        if (storedAmount == 0)
        {
            continue;
        }
        auto liab = offerLiabilities(ledgerVersion, p, storedAmount);
        REQUIRE(liab.selling == storedAmount);

        // The absolute minimum backing that is still legal for this offer:
        //   wheat balance == selling liabilities (so canSellAtMost == amount
        //     once releaseLiabilities has run)
        //   sheep limit == buying liabilities and sheep balance == 0 (so
        //     canBuyAtMost == buying liabilities). This is exactly
        //     getMinimumLimit(), the smallest limit ChangeTrust will accept.
        int64_t const maxSheepReceive = liab.buying;

        // crossOfferV10 re-adjusts the offer against the seller's actual
        // capacity before crossing it. The comment there claims this "should
        // have no effect" as of protocol 10 -- track whether that holds when
        // the limit is exactly minimal.
        int64_t const amount =
            adjustOffer(ledgerVersion, p, storedAmount, maxSheepReceive);
        if (amount != storedAmount)
        {
            ++shrunkAtMinLimit;
            if (amount == 0)
            {
                ++evaporatedAtMinLimit;
            }
        }
        int64_t const maxWheatSend = amount;

        // The taker is unconstrained by the offer's own accounting.
        int64_t maxWheatReceive = randAmount(gen);
        int64_t maxSheepSend = randAmount(gen);
        auto round = rounds[std::uniform_int_distribution<int>(0, 2)(gen)];
        if (round == RoundingType::PATH_PAYMENT_STRICT_SEND &&
            (maxSheepSend == 0 || maxSheepReceive == 0 || maxWheatSend == 0))
        {
            continue;
        }

        INFO(describe(p, maxWheatSend, maxWheatReceive, maxSheepSend,
                      maxSheepReceive, round));
        INFO(fmt::format(
            FMT_STRING("storedAmount={} adjustedAmount={} sellingLiab={} "
                       "buyingLiab={}"),
            storedAmount, amount, liab.selling, liab.buying));

        ExchangeResultV10 res;
        REQUIRE_NOTHROW(res = exchangeV10(ledgerVersion, p, maxWheatSend,
                                          maxWheatReceive, maxSheepSend,
                                          maxSheepReceive, round));
        int64_t const wr = res.numWheatReceived;
        int64_t const ss = res.numSheepSend;

        // The crossing never pays out more sheep than were ever reserved as
        // buying liabilities, even though ss may have been produced by a ceil
        // while the reservation was produced by a floor.
        REQUIRE(ss <= liab.buying);
        REQUIRE(wr <= amount);

        if (wr == 0 && ss == 0)
        {
            continue;
        }
        ++crossings;
        if (ss == maxSheepReceive)
        {
            ++tightBuying;
        }
        if (bigMultiply(ss, p.d) > bigMultiply(wr, p.n))
        {
            // Wheat was strictly favored: a ceil (or equivalent) happened.
            ++ceilCrossings;
        }

        if (!res.wheatStays)
        {
            // Offer is fully taken; all liabilities are released.
            continue;
        }

        // This mirrors crossOfferV10: balances have moved, then the residual
        // offer is re-adjusted against what is left, then liabilities are
        // re-acquired from scratch.
        int64_t remainingWheat = amount - wr;
        int64_t remainingBuyingHeadroom = maxSheepReceive - ss;
        REQUIRE(remainingBuyingHeadroom >= 0);

        int64_t newAmount =
            adjustOffer(ledgerVersion, p, remainingWheat, remainingBuyingHeadroom);
        auto newLiab = offerLiabilities(ledgerVersion, p, newAmount);

        // adjustOffer never grows the offer.
        REQUIRE(newAmount <= remainingWheat);

        // Is the post-trade shrink an artifact of the minimum limit, or is it
        // inherent? Compare against the same offer re-adjusted with unlimited
        // buying headroom: any shrink that survives that is caused by the
        // crossing having rounded sheep *up* in the maker's favour, not by the
        // tight limit.
        if (newAmount < remainingWheat)
        {
            ++postShrinkTight;
        }
        if (adjustOffer(ledgerVersion, p, remainingWheat, INT64_MAX) < remainingWheat)
        {
            ++postShrinkGenerous;
        }
        // How much of the reservation did the crossing actually consume,
        // versus the exact pro-rata share it would have consumed with no
        // rounding at all?
        if (bigMultiply(ss, p.d) > bigMultiply(wr, p.n))
        {
            ++overPaidVsProRata;
        }
        // The offer is still a fixed point, so amount == selling liabilities.
        REQUIRE(newLiab.selling == newAmount);
        REQUIRE(adjustOffer(ledgerVersion, p, newAmount, remainingBuyingHeadroom) ==
                newAmount);

        // THE two invariants that LiabilitiesMatchOffers enforces, at the
        // tightest possible limits:
        //   wheat: balance (== amount - wr) >= selling liabilities
        //   sheep: balance (== ss) + buying liabilities <= limit (==
        //   liab.buying)
        REQUIRE(newLiab.selling <= remainingWheat);
        REQUIRE(newLiab.buying <= remainingBuyingHeadroom);
    }

    // Make sure the random inputs actually exercised the interesting paths.
    INFO(fmt::format(FMT_STRING("crossings={} ceilCrossings={} tightBuying={} "
                                "shrunkAtMinLimit={} evaporatedAtMinLimit={} "
                                "postShrinkTight={} postShrinkGenerous={} "
                                "overPaidVsProRata={}"),
                     crossings, ceilCrossings, tightBuying, shrunkAtMinLimit,
                     evaporatedAtMinLimit, postShrinkTight, postShrinkGenerous,
                     overPaidVsProRata));
    REQUIRE(crossings > ITERATIONS / 10);
    REQUIRE(ceilCrossings > 1000);
    REQUIRE(tightBuying > 1000);
    // Before protocol 29, the "should have no effect" adjustOffer inside
    // crossOfferV10 does have an effect once the trustline limit is exactly
    // getMinimumLimit(). From protocol 29 on it genuinely has none.
    if (protocolVersionStartsFrom(ledgerVersion, ProtocolVersion::V_29))
    {
        REQUIRE(shrunkAtMinLimit == 0);
        REQUIRE(evaporatedAtMinLimit == 0);
    }
    else
    {
        REQUIRE(shrunkAtMinLimit > 0);
    }
    // The post-trade re-adjustment is a separate mechanism that absorbs the
    // ROUND_UP a partial fill grants the maker, and it survives the fix.
    REQUIRE(postShrinkGenerous > 0);
}

// The randomized test above shows that crossOfferV10's second adjustOffer is
// not a no-op when the buying trustline sits at exactly getMinimumLimit(). The
// offer's buying liabilities are floor(amount * n / d), so reserving exactly
// that much headroom leaves min(amount * n, headroom * d) == headroom * d,
// which is strictly less than amount * n whenever d does not divide amount * n.
// The offer is therefore re-adjusted down by up to one unit of wheat, and an
// offer selling a single unit is removed entirely.
TEST_CASE("Offer shrinks at minimum trustline limit", "[exchange]")
{
    // 1 wheat costs floor(2147483647 / 663) == 3239040 sheep.
    Price const p{2147483647, 663};

    uint32_t const legacy = static_cast<uint32_t>(ProtocolVersion::V_28);
    uint32_t const repaired = static_cast<uint32_t>(ProtocolVersion::V_29);

    // The booked liabilities are computed against INT64_MAX receive caps,
    // where the retained saturation clamp makes both protocols agree. This is
    // what lets protocol 29 activate without rewriting any stored offer.
    auto legacyLiab = offerLiabilities(legacy, p, 1);
    auto repairedLiab = offerLiabilities(repaired, p, 1);
    REQUIRE(legacyLiab.selling == 1);
    REQUIRE(legacyLiab.buying == 3239040);
    REQUIRE(repairedLiab.selling == legacyLiab.selling);
    REQUIRE(repairedLiab.buying == legacyLiab.buying);

    // With unlimited buying headroom, the offer is a fixed point under both.
    REQUIRE(adjustOffer(legacy, p, 1, INT64_MAX) == 1);
    REQUIRE(adjustOffer(repaired, p, 1, INT64_MAX) == 1);

    // With headroom equal to the offer's own buying liabilities -- the
    // smallest limit that ChangeTrust accepts -- the offer evaporates before
    // protocol 29 and survives from protocol 29 on.
    REQUIRE(adjustOffer(legacy, p, 1, legacyLiab.buying) == 0);
    REQUIRE(adjustOffer(repaired, p, 1, repairedLiab.buying) == 1);

    // One extra stroop of headroom was enough to keep it alive even before.
    REQUIRE(adjustOffer(legacy, p, 1, legacyLiab.buying + 1) == 1);
    REQUIRE(adjustOffer(repaired, p, 1, repairedLiab.buying + 1) == 1);

    // Larger offers lost a unit rather than evaporating; from protocol 29 on
    // they keep their full amount.
    for (int64_t amount : {2, 3, 17, 1000})
    {
        auto l = offerLiabilities(legacy, p, amount);
        REQUIRE(l.selling == amount);
        REQUIRE(offerLiabilities(repaired, p, amount).buying == l.buying);
        REQUIRE(adjustOffer(legacy, p, amount, l.buying) == amount - 1);
        REQUIRE(adjustOffer(repaired, p, amount, l.buying) == amount);
    }

    // A zero-amount offer combined with PATH_PAYMENT_STRICT_SEND is the one
    // combination that throws rather than returning an empty exchange. That is
    // unchanged by protocol 29, which does not touch the strict-send branch.
    for (uint32_t ledgerVersion : {legacy, repaired})
    {
        REQUIRE_NOTHROW(exchangeV10(ledgerVersion, p, 0, INT64_MAX, INT64_MAX,
                                    3239040, RoundingType::NORMAL));
        REQUIRE_NOTHROW(
            exchangeV10(ledgerVersion, p, 0, INT64_MAX, INT64_MAX, 3239040,
                        RoundingType::PATH_PAYMENT_STRICT_RECEIVE));
        REQUIRE_THROWS_AS(
            exchangeV10(ledgerVersion, p, 0, INT64_MAX, INT64_MAX, 3239040,
                        RoundingType::PATH_PAYMENT_STRICT_SEND),
            std::runtime_error);
    }
}

// The overlay-admission filter (offerCanClearForZero, reached through
// ManageOfferOpFrameBase::doCheckValidForOverlay) is not modeled, so no test
// here compares it against the model. It needs its own model, proof plan,
// differential dimension, and review.

TEST_CASE("Buying liability versus the capacity a crossing needs",
          "[exchange][exchangerandom]")
{
    uint32_t const ledgerVersion = GENERATE(
        static_cast<uint32_t>(ProtocolVersion::V_28),
        static_cast<uint32_t>(ProtocolVersion::V_29));
    INFO("ledgerVersion=" << ledgerVersion);
    std::mt19937_64 gen(24681357);

    size_t const ITERATIONS = 300000;
    size_t fractionalAboveOne = 0;
    size_t fractionalAtMostOne = 0;
    size_t exactRatio = 0;
    size_t shortByOne = 0;
    size_t noShortfall = 0;
    size_t evaporated = 0;
    size_t evaporatedWithAmountAboveOne = 0;
    int64_t maxEvaporatedAmount = 0;

    for (size_t i = 0; i < ITERATIONS; ++i)
    {
        auto p = randPrice(gen);

        // A resting offer, i.e. already a fixed point of adjustOffer.
        int64_t A = adjustOffer(ledgerVersion, p, randAmount(gen), INT64_MAX);
        if (A == 0)
        {
            continue;
        }
        auto liab = offerLiabilities(ledgerVersion, p, A);
        REQUIRE(liab.selling == A);
        int64_t const L = liab.buying;

        // Skip offers so large that A * n / d saturates, where the liability
        // is clamped rather than being a true floor.
        uint128_t prod = bigMultiply(A, p.n);
        int64_t floorAnd, ceilAnd;
        if (!bigDivide128(floorAnd, prod, p.d, ROUND_DOWN) ||
            !bigDivide128(ceilAnd, prod, p.d, ROUND_UP))
        {
            continue;
        }

        INFO(fmt::format(FMT_STRING("price={}/{} amount={} L={} floor={} "
                                    "ceil={}"),
                         p.n, p.d, A, L, floorAnd, ceilAnd));

        // The booked buying liability is exactly floor(A * n / d).
        REQUIRE(L == floorAnd);

        bool const isFractional = (ceilAnd != floorAnd);
        if (!isFractional)
        {
            ++exactRatio;
        }
        else if (p.n > p.d)
        {
            ++fractionalAboveOne;
        }
        else
        {
            ++fractionalAtMostOne;
        }

        // Capacity equal to ceil(A * n / d) always keeps the offer whole.
        REQUIRE(adjustOffer(ledgerVersion, p, A, ceilAnd) == A);

        // The question: does capacity equal to the booked liability L suffice?
        int64_t const atBookedCapacity = adjustOffer(ledgerVersion, p, A, L);
        if (atBookedCapacity == A)
        {
            ++noShortfall;
        }
        else
        {
            ++shortByOne;
            // The shortfall is exactly one stroop of capacity, and it only
            // happens when the price is above 1 and the product is fractional.
            REQUIRE(isFractional);
            REQUIRE(p.n > p.d);
            REQUIRE(ceilAnd == L + 1);
            // The shortfall costs one unit of wheat -- unless dropping that
            // unit pushes the remaining trade outside the 1% price error
            // threshold, in which case applyPriceErrorThresholds zeroes it and
            // the whole offer is destroyed.
            REQUIRE((atBookedCapacity == A - 1 || atBookedCapacity == 0));
            if (atBookedCapacity == 0)
            {
                ++evaporated;
                if (A > 1)
                {
                    ++evaporatedWithAmountAboveOne;
                    maxEvaporatedAmount = std::max(maxEvaporatedAmount, A);
                }
            }
        }
    }

    INFO(fmt::format(
        FMT_STRING("fractionalAboveOne={} fractionalAtMostOne={} "
                   "exactRatio={} shortByOne={} noShortfall={} evaporated={} "
                   "evaporatedWithAmountAboveOne={} maxEvaporatedAmount={}"),
        fractionalAboveOne, fractionalAtMostOne, exactRatio, shortByOne,
        noShortfall, evaporated, evaporatedWithAmountAboveOne,
        maxEvaporatedAmount));

    REQUIRE(fractionalAtMostOne > 0);
    if (protocolVersionStartsFrom(ledgerVersion, ProtocolVersion::V_29))
    {
        // The whole point of protocol 29: the booked liability is exactly the
        // capacity a crossing needs, for every price and every amount.
        REQUIRE(shortByOne == 0);
        REQUIRE(evaporated == 0);
        REQUIRE(noShortfall > 0);
        return;
    }
    REQUIRE(shortByOne > 0);
    // The characterization is exact: the booked liability is one short of the
    // required capacity precisely when the price is above 1 and A * n / d is
    // fractional. Prices at or below 1 are never short, because there the
    // offer amount is itself derived with a ROUND_UP and already absorbs the
    // fractional part.
    REQUIRE(shortByOne == fractionalAboveOne);
    // Offers considerably larger than a single unit are destroyed outright,
    // because dropping one unit can push the rest outside the 1% threshold.
    REQUIRE(evaporatedWithAmountAboveOne > 0);
    REQUIRE(maxEvaporatedAmount > 10);
}

TEST_CASE("Isabelle offer-exchange differential", "[isabelle-offer-exchange]")
{
    // Without the environment override this checks the committed golden
    // subset, so an ordinary test run catches C++ drift from the verified
    // Isabelle model without needing Isabelle installed. The full corpus is
    // supplied by formal/differential/run.sh. The golden path is tried both
    // from the repository root and from src/, since tests are run from both.
    std::string expectedPath;
    if (auto const* fromEnv = std::getenv("ISABELLE_OFFER_EXCHANGE_EXPECTED"))
    {
        expectedPath = fromEnv;
    }
    else
    {
        static char const* const candidates[] = {
            "formal/differential/golden/expected.tsv",
            "../formal/differential/golden/expected.tsv"};
        for (auto const* candidate : candidates)
        {
            if (std::filesystem::exists(candidate))
            {
                expectedPath = candidate;
                break;
            }
        }
        INFO("no golden corpus found relative to the working directory; "
             "run formal/differential/run.sh or set "
             "ISABELLE_OFFER_EXCHANGE_EXPECTED");
        REQUIRE(!expectedPath.empty());
    }

    std::ifstream expectedRows(expectedPath);
    REQUIRE(expectedRows.good());

    // Lifecycle rows run real transactions, so they need a ledger at the
    // row's protocol. They use fresh accounts and issuer-scoped assets per
    // row, so no order book or liabilities leak between records.
    //
    // The lifecycle corpus is generated at protocols 28 and 29, so there is
    // one long-lived application per protocol, each with its own clock,
    // config instance and in-memory database, and each row runs against the
    // application its ledger_version names. A row at any other version fails
    // loudly rather than being compared against the wrong ledger.
    auto const lifecycleLegacyVersion =
        static_cast<uint32_t>(ProtocolVersion::V_28);
    auto const lifecycleRepairedVersion =
        static_cast<uint32_t>(ProtocolVersion::V_29);
    auto makeLifecycleConfig = [](int instanceNumber, uint32_t ledgerVersion) {
        auto config = getTestConfig(instanceNumber, Config::TESTDB_IN_MEMORY);
        config.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION = ledgerVersion;
        config.LEDGER_PROTOCOL_VERSION = ledgerVersion;
        return config;
    };
    VirtualClock lifecycleLegacyClock;
    auto lifecycleLegacyApp = createTestApplication(
        lifecycleLegacyClock, makeLifecycleConfig(0, lifecycleLegacyVersion));
    VirtualClock lifecycleRepairedClock;
    auto lifecycleRepairedApp = createTestApplication(
        lifecycleRepairedClock,
        makeLifecycleConfig(1, lifecycleRepairedVersion));
    for (auto const& [app, version] :
         {std::make_pair(lifecycleLegacyApp, lifecycleLegacyVersion),
          std::make_pair(lifecycleRepairedApp, lifecycleRepairedVersion)})
    {
        LedgerTxn ltx(app->getLedgerTxnRoot());
        REQUIRE(ltx.loadHeader().current().ledgerVersion == version);
    }

    std::size_t lifecycleIndex = 0;
    struct LifecycleCoverage
    {
        std::string tag;
        uint32_t ledgerVersion{0};
        std::size_t records{0};
        bool postingRejected{false};
        bool offerCreated{false};
        bool limitChanged{false};
        bool positiveCross{false};
    };
    // One entry per (operation, protocol) pair, so a stage covered only at one
    // protocol cannot make the other look complete. The index is
    // 2 * isBuy + (protocol is 29).
    std::array<LifecycleCoverage, 4> lifecycleCoverage{
        LifecycleCoverage{"offer_lifecycle_sell", lifecycleLegacyVersion},
        LifecycleCoverage{"offer_lifecycle_sell", lifecycleRepairedVersion},
        LifecycleCoverage{"offer_lifecycle_buy", lifecycleLegacyVersion},
        LifecycleCoverage{"offer_lifecycle_buy", lifecycleRepairedVersion}};

    std::unordered_set<std::string> caseIds;
    std::string line;
    std::size_t lineNumber = 0;
    std::size_t recordCount = 0;

    while (std::getline(expectedRows, line))
    {
        ++lineNumber;
        if (line.empty() || line.front() == '#')
        {
            continue;
        }

        std::vector<std::string> fields;
        std::istringstream row(line);
        std::string field;
        while (std::getline(row, field, '\t'))
        {
            fields.emplace_back(std::move(field));
        }

        CAPTURE(lineNumber);
        REQUIRE(fields.size() >= 5);
        REQUIRE(fields[0] == "v1");
        REQUIRE(!fields[2].empty());
        REQUIRE(caseIds.emplace(fields[2]).second);

        auto parseInt64 = [&](std::string const& text, char const* fieldName) {
            std::size_t parsed = 0;
            int64_t value = 0;
            try
            {
                value = std::stoll(text, &parsed, 10);
            }
            catch (std::exception const& exception)
            {
                FAIL("invalid " << fieldName << " in case " << fields[2] << ": "
                                << exception.what());
            }
            REQUIRE(parsed == text.size());
            return value;
        };

        auto parseUint64 = [&](std::string const& text, char const* fieldName) {
            REQUIRE(!text.empty());
            REQUIRE(text.front() != '-');
            std::size_t parsed = 0;
            uint64_t value = 0;
            try
            {
                value = std::stoull(text, &parsed, 10);
            }
            catch (std::exception const& exception)
            {
                FAIL("invalid " << fieldName << " in case " << fields[2] << ": "
                                << exception.what());
            }
            REQUIRE(parsed == text.size());
            return value;
        };

        auto parseInt32 = [&](std::string const& text, char const* fieldName) {
            auto const value = parseInt64(text, fieldName);
            REQUIRE(value >= std::numeric_limits<int32_t>::min());
            REQUIRE(value <= std::numeric_limits<int32_t>::max());
            return static_cast<int32_t>(value);
        };
        auto parseBool = [&](std::string const& text, char const* fieldName) {
            if (text == "0")
            {
                return false;
            }
            if (text == "1")
            {
                return true;
            }
            FAIL("invalid " << fieldName << " in case " << fields[2] << ": "
                            << text);
            return false;
        };
        auto parseRounding = [&](std::string const& text) {
            if (text == "DOWN")
            {
                return ROUND_DOWN;
            }
            if (text == "UP")
            {
                return ROUND_UP;
            }
            FAIL("invalid rounding in case " << fields[2] << ": " << text);
            return ROUND_DOWN;
        };
        auto parseExchangeRounding = [&](std::string const& text) {
            if (text == "NORMAL")
            {
                return RoundingType::NORMAL;
            }
            if (text == "STRICT_SEND")
            {
                return RoundingType::PATH_PAYMENT_STRICT_SEND;
            }
            if (text == "STRICT_RECEIVE")
            {
                return RoundingType::PATH_PAYMENT_STRICT_RECEIVE;
            }
            FAIL("invalid exchange rounding in case " << fields[2] << ": "
                                                      << text);
            return RoundingType::NORMAL;
        };
        auto parseUint128 = [&](std::string const& text,
                                char const* fieldName) {
            REQUIRE(!text.empty());
            uint128_t value{uint64_t{0}};
            uint128_t const ten{uint64_t{10}};
            auto const maximum = uint128_max();
            for (auto const character : text)
            {
                REQUIRE(character >= '0');
                REQUIRE(character <= '9');
                uint128_t const digit{static_cast<uint64_t>(character - '0')};
                REQUIRE(value <= (maximum - digit) / ten);
                value = value * ten + digit;
            }
            CAPTURE(fieldName);
            return value;
        };

        std::string actualStatus;
        std::string actualValue;
        std::string expectedStatus;
        std::string expectedValue;

        if (fields[1] == "offer_value")
        {
            REQUIRE(fields.size() == 9);
            auto const priceN = parseInt32(fields[3], "price_n");
            auto const priceD = parseInt32(fields[4], "price_d");
            auto const maxSend = parseInt64(fields[5], "max_send");
            auto const maxReceive = parseInt64(fields[6], "max_receive");
            expectedStatus = fields[7];
            expectedValue = fields[8];
            try
            {
                auto const value = calculateOfferValueForTesting(
                    priceN, priceD, maxSend, maxReceive);
                std::ostringstream serialized;
                serialized << value;
                actualStatus = "OK";
                actualValue = serialized.str();
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                actualValue = "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(priceN, priceD, maxSend, maxReceive);
        }
        else if (fields[1] == "offer_amount_from_value")
        {
            REQUIRE(fields.size() == 9);
            auto const priceN = parseInt32(fields[3], "price_n");
            auto const priceD = parseInt32(fields[4], "price_d");
            auto const maxSend = parseInt64(fields[5], "max_send");
            auto const maxReceive = parseInt64(fields[6], "max_receive");
            expectedStatus = fields[7];
            expectedValue = fields[8];
            try
            {
                actualValue = std::to_string(calculateOfferAmountFromValueForTesting(
                    priceN, priceD, maxSend, maxReceive));
                actualStatus = "OK";
            }
            catch (std::overflow_error const&)
            {
                actualStatus = "ERR";
                actualValue = "OVERFLOW";
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                actualValue = "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(priceN, priceD, maxSend, maxReceive);
        }
        else if (fields[1] == "big_multiply")
        {
            REQUIRE(fields.size() == 7);
            auto const a = parseInt64(fields[3], "a");
            auto const b = parseInt64(fields[4], "b");
            expectedStatus = fields[5];
            expectedValue = fields[6];
            try
            {
                auto const value = bigMultiply(a, b);
                std::ostringstream serialized;
                serialized << value;
                actualStatus = "OK";
                actualValue = serialized.str();
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                actualValue = "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(a, b);
        }
        else if (fields[1] == "price_error_bound")
        {
            REQUIRE(fields.size() == 10);
            auto const priceN = parseInt32(fields[3], "price_n");
            auto const priceD = parseInt32(fields[4], "price_d");
            auto const wheatReceive = parseInt64(fields[5], "wheat_receive");
            auto const sheepSend = parseInt64(fields[6], "sheep_send");
            auto const canFavorWheat = parseBool(fields[7], "can_favor_wheat");
            expectedStatus = fields[8];
            expectedValue = fields[9];
            try
            {
                auto const value =
                    checkPriceErrorBound(Price{priceN, priceD}, wheatReceive,
                                         sheepSend, canFavorWheat);
                actualStatus = "OK";
                actualValue = value ? "1" : "0";
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                actualValue = "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(priceN, priceD, wheatReceive, sheepSend, canFavorWheat);
        }
        else if (fields[1] == "big_divide")
        {
            REQUIRE(fields.size() == 9);
            auto const a = parseInt64(fields[3], "A");
            auto const b = parseInt64(fields[4], "B");
            auto const c = parseInt64(fields[5], "C");
            auto const rounding = parseRounding(fields[6]);
            expectedStatus = fields[7];
            expectedValue = fields[8];
            try
            {
                auto const value = bigDivideOrThrow(a, b, c, rounding);
                actualStatus = "OK";
                actualValue = std::to_string(value);
            }
            catch (std::overflow_error const&)
            {
                actualStatus = "ERR";
                actualValue = "OVERFLOW";
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                actualValue = "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(a, b, c, rounding);
        }
        else if (fields[1] == "big_divide_128")
        {
            REQUIRE(fields.size() == 8);
            auto const a = parseUint128(fields[3], "a");
            auto const b = parseInt64(fields[4], "B");
            auto const rounding = parseRounding(fields[5]);
            expectedStatus = fields[6];
            expectedValue = fields[7];
            try
            {
                auto const value = bigDivideOrThrow128(a, b, rounding);
                actualStatus = "OK";
                actualValue = std::to_string(value);
            }
            catch (std::overflow_error const&)
            {
                actualStatus = "ERR";
                actualValue = "OVERFLOW";
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                actualValue = "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(a, b, rounding);
        }
        else if (fields[1] == "big_multiply_unsigned")
        {
            REQUIRE(fields.size() == 7);
            auto const a = parseUint64(fields[3], "a");
            auto const b = parseUint64(fields[4], "b");
            expectedStatus = fields[5];
            expectedValue = fields[6];
            std::ostringstream serialized;
            serialized << bigMultiplyUnsigned(a, b);
            actualStatus = "OK";
            actualValue = serialized.str();
            CAPTURE(a, b);
        }
        else if (fields[1] == "big_divide_unsigned")
        {
            // bigDivideUnsigned assigns its out-parameter on every path past
            // the assertion, so both the flag and the value are compared.
            REQUIRE((fields.size() == 9 || fields.size() == 10));
            auto const a = parseUint64(fields[3], "A");
            auto const b = parseUint64(fields[4], "B");
            auto const c = parseUint64(fields[5], "C");
            auto const rounding = parseRounding(fields[6]);
            expectedStatus = fields[7];
            if (expectedStatus == "OK")
            {
                REQUIRE(fields.size() == 10);
                expectedValue = fields[8] + '\t' + fields[9];
            }
            else
            {
                REQUIRE(fields.size() == 9);
                expectedValue = fields[8];
            }
            try
            {
                uint64_t result = 0;
                bool const ok = bigDivideUnsigned(result, a, b, c, rounding);
                actualStatus = "OK";
                actualValue =
                    std::string(ok ? "1" : "0") + '\t' + std::to_string(result);
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                actualValue = "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(a, b, c, rounding);
        }
        else if (fields[1] == "big_divide_nothrow")
        {
            // bigDivide leaves its out-parameter unassigned when the unsigned
            // helper reports failure, so the value is compared only when the
            // flag is true; the model transports zero otherwise.
            REQUIRE((fields.size() == 9 || fields.size() == 10));
            auto const a = parseInt64(fields[3], "A");
            auto const b = parseInt64(fields[4], "B");
            auto const c = parseInt64(fields[5], "C");
            auto const rounding = parseRounding(fields[6]);
            expectedStatus = fields[7];
            if (expectedStatus == "OK")
            {
                REQUIRE(fields.size() == 10);
                expectedValue = fields[8] + '\t' + fields[9];
            }
            else
            {
                REQUIRE(fields.size() == 9);
                expectedValue = fields[8];
            }
            try
            {
                int64_t result = 0;
                bool const ok = bigDivide(result, a, b, c, rounding);
                actualStatus = "OK";
                actualValue = std::string(ok ? "1" : "0") + '\t' +
                              std::to_string(ok ? result : int64_t{0});
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                actualValue = "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(a, b, c, rounding);
        }
        else if (fields[1] == "big_divide_unsigned_128")
        {
            // bigDivideUnsigned128 leaves its out-parameter unassigned when
            // the round-up guard fires, so the value is compared only when
            // the flag is true; the model transports zero otherwise.
            REQUIRE((fields.size() == 8 || fields.size() == 9));
            auto const a = parseUint128(fields[3], "a");
            auto const b = parseUint64(fields[4], "B");
            auto const rounding = parseRounding(fields[5]);
            expectedStatus = fields[6];
            if (expectedStatus == "OK")
            {
                REQUIRE(fields.size() == 9);
                expectedValue = fields[7] + '\t' + fields[8];
            }
            else
            {
                REQUIRE(fields.size() == 8);
                expectedValue = fields[7];
            }
            try
            {
                uint64_t result = 0;
                bool const ok = bigDivideUnsigned128(result, a, b, rounding);
                actualStatus = "OK";
                actualValue = std::string(ok ? "1" : "0") + '\t' +
                              std::to_string(ok ? result : uint64_t{0});
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                actualValue = "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(a, b, rounding);
        }
        else if (fields[1] == "big_divide_128_nothrow")
        {
            // bigDivide128 leaves its out-parameter unassigned when the
            // unsigned helper reports failure, so the value is compared only
            // when the flag is true; the model transports zero otherwise.
            REQUIRE((fields.size() == 8 || fields.size() == 9));
            auto const a = parseUint128(fields[3], "a");
            auto const b = parseInt64(fields[4], "B");
            auto const rounding = parseRounding(fields[5]);
            expectedStatus = fields[6];
            if (expectedStatus == "OK")
            {
                REQUIRE(fields.size() == 9);
                expectedValue = fields[7] + '\t' + fields[8];
            }
            else
            {
                REQUIRE(fields.size() == 8);
                expectedValue = fields[7];
            }
            try
            {
                int64_t result = 0;
                bool const ok = bigDivide128(result, a, b, rounding);
                actualStatus = "OK";
                actualValue = std::string(ok ? "1" : "0") + '\t' +
                              std::to_string(ok ? result : int64_t{0});
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                actualValue = "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(a, b, rounding);
        }
        else if (fields[1] == "apply_price_error_thresholds")
        {
            REQUIRE((fields.size() == 11 || fields.size() == 13));
            auto const priceN = parseInt32(fields[3], "price_n");
            auto const priceD = parseInt32(fields[4], "price_d");
            auto const wheatReceive = parseInt64(fields[5], "wheat_receive");
            auto const sheepSend = parseInt64(fields[6], "sheep_send");
            auto const wheatStays = parseBool(fields[7], "wheat_stays");
            auto const rounding = parseExchangeRounding(fields[8]);
            expectedStatus = fields[9];
            if (expectedStatus == "OK")
            {
                REQUIRE(fields.size() == 13);
                expectedValue =
                    fields[10] + '\t' + fields[11] + '\t' + fields[12];
            }
            else
            {
                REQUIRE(fields.size() == 11);
                expectedValue = fields[10];
            }
            try
            {
                auto const value = applyPriceErrorThresholds(
                    Price{priceN, priceD}, wheatReceive, sheepSend, wheatStays,
                    rounding);
                actualStatus = "OK";
                actualValue = std::to_string(value.numWheatReceived) + '\t' +
                              std::to_string(value.numSheepSend) + '\t' +
                              (value.wheatStays ? "1" : "0");
            }
            catch (std::runtime_error const&)
            {
                actualStatus = "ERR";
                auto const arithmeticAssertion = wheatReceive > 0 &&
                                                 sheepSend > 0 &&
                                                 (priceN < 0 || priceD < 0);
                actualValue = arithmeticAssertion ? "ASSERTION" : "RUNTIME";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(priceN, priceD, wheatReceive, sheepSend, wheatStays,
                    rounding);
        }
        else if (fields[1] == "exchange_v10_without_price_error_thresholds" ||
                 fields[1] == "exchange_v10")
        {
            REQUIRE((fields.size() == 13 || fields.size() == 15));
            auto const priceN = parseInt32(fields[3], "price_n");
            auto const priceD = parseInt32(fields[4], "price_d");
            auto const maxWheatSend = parseInt64(fields[5], "max_wheat_send");
            auto const maxWheatReceive =
                parseInt64(fields[6], "max_wheat_receive");
            auto const maxSheepSend = parseInt64(fields[7], "max_sheep_send");
            auto const maxSheepReceive =
                parseInt64(fields[8], "max_sheep_receive");
            auto const rounding = parseExchangeRounding(fields[9]);
            auto const ledgerVersion = static_cast<uint32_t>(
                parseInt64(fields[10], "ledger_version"));
            expectedStatus = fields[11];
            if (expectedStatus == "OK")
            {
                REQUIRE(fields.size() == 15);
                expectedValue =
                    fields[12] + '\t' + fields[13] + '\t' + fields[14];
            }
            else
            {
                REQUIRE(fields.size() == 13);
                expectedValue = fields[12];
            }
            try
            {
                auto const value =
                    fields[1] == "exchange_v10"
                        ? exchangeV10(ledgerVersion, Price{priceN, priceD},
                                      maxWheatSend, maxWheatReceive,
                                      maxSheepSend, maxSheepReceive, rounding)
                        : exchangeV10WithoutPriceErrorThresholds(
                              ledgerVersion, Price{priceN, priceD},
                              maxWheatSend, maxWheatReceive, maxSheepSend,
                              maxSheepReceive, rounding);
                actualStatus = "OK";
                actualValue = std::to_string(value.numWheatReceived) + '\t' +
                              std::to_string(value.numSheepSend) + '\t' +
                              (value.wheatStays ? "1" : "0");
            }
            catch (std::overflow_error const&)
            {
                actualStatus = "ERR";
                actualValue = "OVERFLOW";
            }
            catch (std::runtime_error const& exception)
            {
                actualStatus = "ERR";
                std::string const message{exception.what()};
                auto const boundsFailure =
                    message == "wheatReceive out of bounds" ||
                    message == "sheepSend out of bounds";
                auto const thresholdFailure =
                    fields[1] == "exchange_v10" &&
                    (message == "favored sheep when wheat stays" ||
                     message == "favored wheat when sheep stays" ||
                     message == "exceeded price error bound" ||
                     message == "invalid amount of sheep sent");
                actualValue =
                    boundsFailure || thresholdFailure ? "RUNTIME" : "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(priceN, priceD, maxWheatSend, maxWheatReceive, maxSheepSend,
                    maxSheepReceive, rounding, ledgerVersion);
        }
        else if (fields[1] == "adjust_offer")
        {
            REQUIRE(fields.size() == 10);
            auto const priceN = parseInt32(fields[3], "price_n");
            auto const priceD = parseInt32(fields[4], "price_d");
            auto const maxWheatSend = parseInt64(fields[5], "max_wheat_send");
            auto const maxSheepReceive =
                parseInt64(fields[6], "max_sheep_receive");
            auto const ledgerVersion = static_cast<uint32_t>(
                parseInt64(fields[7], "ledger_version"));
            expectedStatus = fields[8];
            expectedValue = fields[9];
            try
            {
                auto const value =
                    adjustOffer(ledgerVersion, Price{priceN, priceD},
                                maxWheatSend, maxSheepReceive);
                actualStatus = "OK";
                actualValue = std::to_string(value);
            }
            catch (std::overflow_error const&)
            {
                actualStatus = "ERR";
                actualValue = "OVERFLOW";
            }
            catch (std::runtime_error const& exception)
            {
                actualStatus = "ERR";
                std::string const message{exception.what()};
                auto const boundsFailure =
                    message == "wheatReceive out of bounds" ||
                    message == "sheepSend out of bounds";
                auto const thresholdFailure =
                    message == "favored sheep when wheat stays" ||
                    message == "favored wheat when sheep stays" ||
                    message == "exceeded price error bound" ||
                    message == "invalid amount of sheep sent";
                actualValue =
                    boundsFailure || thresholdFailure ? "RUNTIME" : "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(priceN, priceD, maxWheatSend, maxSheepReceive,
                    ledgerVersion);
        }
        else if (fields[1] == "offer_selling_liabilities" ||
                 fields[1] == "offer_buying_liabilities")
        {
            REQUIRE(fields.size() == 9);
            auto const priceN = parseInt32(fields[3], "price_n");
            auto const priceD = parseInt32(fields[4], "price_d");
            auto const ledgerVersion = static_cast<uint32_t>(
                parseInt64(fields[5], "ledger_version"));
            auto const amount = parseInt64(fields[6], "amount");
            expectedStatus = fields[7];
            expectedValue = fields[8];
            try
            {
                auto const value = exchangeV10WithoutPriceErrorThresholds(
                    ledgerVersion, Price{priceN, priceD}, amount, INT64_MAX,
                    INT64_MAX, INT64_MAX, RoundingType::NORMAL);
                actualStatus = "OK";
                actualValue =
                    std::to_string(fields[1] == "offer_selling_liabilities"
                                       ? value.numWheatReceived
                                       : value.numSheepSend);
            }
            catch (std::overflow_error const&)
            {
                actualStatus = "ERR";
                actualValue = "OVERFLOW";
            }
            catch (std::runtime_error const& exception)
            {
                actualStatus = "ERR";
                std::string const message{exception.what()};
                auto const boundsFailure =
                    message == "wheatReceive out of bounds" ||
                    message == "sheepSend out of bounds";
                actualValue = boundsFailure ? "RUNTIME" : "ASSERTION";
            }
            catch (std::exception const& exception)
            {
                FAIL("unexpected exception in case " << fields[2] << ": "
                                                     << exception.what());
            }
            catch (...)
            {
                FAIL("unexpected non-standard exception in case " << fields[2]);
            }
            CAPTURE(priceN, priceD, amount);
        }
        else if (fields[1] == "offer_lifecycle_sell" ||
                 fields[1] == "offer_lifecycle_buy")
        {
            // Input has 13 fields. It is followed by OK and the fixed 27-value
            // lifecycle suffix documented by Offer_Exchange_Test_Interface.
            REQUIRE(fields.size() == 41);
            bool const isBuy = fields[1] == "offer_lifecycle_buy";
            auto const priceN = parseInt32(fields[3], "price_n");
            auto const priceD = parseInt32(fields[4], "price_d");
            auto const ledgerVersion = static_cast<uint32_t>(
                parseInt64(fields[5], "ledger_version"));
            INFO("the lifecycle oracle runs protocol-28 and protocol-29 "
                 "ledgers only");
            REQUIRE((ledgerVersion == lifecycleLegacyVersion ||
                     ledgerVersion == lifecycleRepairedVersion));
            bool const isRepaired = ledgerVersion == lifecycleRepairedVersion;
            auto& coverage =
                lifecycleCoverage[(isBuy ? 2 : 0) + (isRepaired ? 1 : 0)];
            REQUIRE(coverage.ledgerVersion == ledgerVersion);
            auto const& lifecycleApp =
                isRepaired ? lifecycleRepairedApp : lifecycleLegacyApp;
            auto const lifecycleRoot = lifecycleApp->getRoot();
            auto const amount = parseInt64(fields[6], "amount");
            auto const makerSellBalance =
                parseInt64(fields[7], "maker_sell_balance");
            auto const makerSellLiabilities =
                parseInt64(fields[8], "maker_sell_liabilities");
            auto const makerBuyLimit = parseInt64(fields[9], "maker_buy_limit");
            auto const makerBuyBalance =
                parseInt64(fields[10], "maker_buy_balance");
            auto const makerBuyLiabilities =
                parseInt64(fields[11], "maker_buy_liabilities");
            auto const newBuyLimit = parseInt64(fields[12], "new_buy_limit");
            expectedStatus = fields[13];

            auto joinValues = [](std::vector<std::string> const& values) {
                std::ostringstream stream;
                for (std::size_t i = 0; i < values.size(); ++i)
                {
                    if (i != 0)
                    {
                        stream << '\t';
                    }
                    stream << values[i];
                }
                return stream.str();
            };
            expectedValue = joinValues(
                std::vector<std::string>(fields.begin() + 14, fields.end()));

            ++lifecycleIndex;
            auto const accountPrefix =
                "lc" + std::to_string(lifecycleIndex) + "_";
            auto const txFee = lifecycleApp->getLedgerManager().getLastTxFee();
            auto const accountBalance =
                lifecycleApp->getLedgerManager().getLastMinBalance(12) +
                1000 * txFee;
            auto issuer =
                lifecycleRoot->create(accountPrefix + "issuer", accountBalance);
            auto maker =
                lifecycleRoot->create(accountPrefix + "maker", accountBalance);
            auto taker =
                lifecycleRoot->create(accountPrefix + "taker", accountBalance);
            auto const selling = issuer.asset("SELL");
            auto const buying = issuer.asset("BUYY");
            auto const auxiliarySelling = issuer.asset("AUXS");
            auto const auxiliaryBuying = issuer.asset("AUXB");

            maker.changeTrust(selling, INT64_MAX);
            if (makerSellBalance > 0)
            {
                issuer.pay(maker, selling, makerSellBalance);
            }
            if (makerBuyLimit > 0)
            {
                maker.changeTrust(buying, makerBuyLimit);
            }
            if (makerBuyBalance > 0)
            {
                issuer.pay(maker, buying, makerBuyBalance);
            }

            // Materialize requested pre-existing liabilities through real,
            // isolated auxiliary offers rather than raw ledger mutation.
            if (makerSellLiabilities > 0)
            {
                maker.changeTrust(auxiliaryBuying, INT64_MAX);
                maker.manageOffer(0, selling, auxiliaryBuying, Price{1, 1},
                                  makerSellLiabilities);
            }
            if (makerBuyLiabilities > 0)
            {
                maker.changeTrust(auxiliarySelling, INT64_MAX);
                issuer.pay(maker, auxiliarySelling, makerBuyLiabilities);
                maker.manageOffer(0, auxiliarySelling, buying, Price{1, 1},
                                  makerBuyLiabilities);
            }

            taker.changeTrust(selling, INT64_MAX);
            taker.changeTrust(buying, INT64_MAX);
            issuer.pay(taker, buying, INT64_MAX);

            // Party groups always use this order: sell balance, sell
            // liabilities, buy limit, buy balance, buy liabilities.
            auto readParty = [&](TestAccount const& account,
                                 Asset const& sellAsset,
                                 Asset const& buyAsset) {
                std::array<int64_t, 5> state{};
                LedgerTxn ltx(lifecycleApp->getLedgerTxnRoot());
                auto header = ltx.loadHeader();
                auto sellLine = stellar::loadTrustLine(
                    ltx, account.getPublicKey(), sellAsset);
                REQUIRE(sellLine);
                state[0] = sellLine.getBalance();
                state[1] = sellLine.getSellingLiabilities(header);
                auto buyLine = stellar::loadTrustLine(
                    ltx, account.getPublicKey(), buyAsset);
                if (buyLine)
                {
                    state[3] = buyLine.getBalance();
                    state[4] = buyLine.getBuyingLiabilities(header);
                    state[2] = state[3] + state[4] +
                               buyLine.getMaxAmountReceive(header);
                }
                return state;
            };
            auto const initialMaker = readParty(maker, selling, buying);
            REQUIRE(initialMaker[0] == makerSellBalance);
            REQUIRE(initialMaker[1] == makerSellLiabilities);
            REQUIRE(initialMaker[2] == makerBuyLimit);
            REQUIRE(initialMaker[3] == makerBuyBalance);
            REQUIRE(initialMaker[4] == makerBuyLiabilities);

            auto makeSuffix = [](int stage) {
                std::vector<std::string> suffix(27, "0");
                suffix[0] = std::to_string(stage);
                return suffix;
            };
            auto fillParty = [](std::vector<std::string>& suffix,
                                std::size_t offset,
                                std::array<int64_t, 5> const& state) {
                for (std::size_t i = 0; i < state.size(); ++i)
                {
                    suffix[offset + i] = std::to_string(state[i]);
                }
            };
            auto finishLifecycle = [&](std::vector<std::string> const& suffix) {
                ++coverage.records;
                coverage.postingRejected =
                    coverage.postingRejected ||
                    (suffix[0] >= "1" && suffix[0] <= "4");
                coverage.offerCreated =
                    coverage.offerCreated || suffix[1] == "1";
                coverage.limitChanged =
                    coverage.limitChanged || suffix[10] == "1";
                coverage.positiveCross =
                    coverage.positiveCross ||
                    (suffix[13] == "1" && suffix[14] != "0" &&
                     suffix[15] != "0");
                actualStatus = "OK";
                actualValue = joinValues(suffix);
            };

            Operation const offerOperation =
                isBuy ? manageBuyOffer(0, selling, buying,
                                       Price{priceN, priceD}, amount)
                      : manageOffer(0, selling, buying, Price{priceN, priceD},
                                    amount);
            auto offerTx = maker.tx({offerOperation});
            // No overlay-admission check here. stellar-core's pre-protocol-29
            // overlay filter is not modeled, and the model does not gate on
            // one, so the comparison is over posting and crossing.
            {
                int64_t expectedOfferID;
                {
                    LedgerTxn ltx(lifecycleApp->getLedgerTxnRoot());
                    expectedOfferID = ltx.loadHeader().current().idPool + 1;
                }
                bool const applied = applyCheck(offerTx, *lifecycleApp);
                auto suffix = makeSuffix(0);

                bool postSucceeded = false;
                if (isBuy)
                {
                    auto const code = offerTx->getResult()
                                          .result.results()[0]
                                          .tr()
                                          .manageBuyOfferResult()
                                          .code();
                    if (code == MANAGE_BUY_OFFER_SUCCESS)
                    {
                        postSucceeded = true;
                    }
                    else if (code == MANAGE_BUY_OFFER_LINE_FULL)
                    {
                        suffix[0] = "2";
                    }
                    else if (code == MANAGE_BUY_OFFER_UNDERFUNDED)
                    {
                        suffix[0] = "3";
                    }
                    else if (code == MANAGE_BUY_OFFER_MALFORMED)
                    {
                        suffix[0] = "1";
                    }
                    else
                    {
                        FAIL("unexpected ManageBuyOffer result in case "
                             << fields[2] << ": " << code);
                    }
                }
                else
                {
                    auto const code = offerTx->getResult()
                                          .result.results()[0]
                                          .tr()
                                          .manageSellOfferResult()
                                          .code();
                    if (code == MANAGE_SELL_OFFER_SUCCESS)
                    {
                        postSucceeded = true;
                    }
                    else if (code == MANAGE_SELL_OFFER_LINE_FULL)
                    {
                        suffix[0] = "2";
                    }
                    else if (code == MANAGE_SELL_OFFER_UNDERFUNDED)
                    {
                        suffix[0] = "3";
                    }
                    else if (code == MANAGE_SELL_OFFER_MALFORMED)
                    {
                        suffix[0] = "1";
                    }
                    else
                    {
                        FAIL("unexpected ManageSellOffer result in case "
                             << fields[2] << ": " << code);
                    }
                }
                REQUIRE(applied == postSucceeded);

                LedgerEntry postedEntry;
                bool offerCreated = false;
                if (postSucceeded)
                {
                    LedgerTxn ltx(lifecycleApp->getLedgerTxnRoot());
                    auto offer = stellar::loadOffer(ltx, maker.getPublicKey(),
                                                    expectedOfferID);
                    offerCreated = static_cast<bool>(offer);
                    if (offerCreated)
                    {
                        postedEntry = offer.current();
                    }
                }

                if (!postSucceeded)
                {
                    finishLifecycle(suffix);
                }
                else if (!offerCreated)
                {
                    suffix[0] = "4";
                    finishLifecycle(suffix);
                }
                else
                {
                    auto const& postedOffer = postedEntry.data.offer();
                    auto const makerAfterPost =
                        readParty(maker, selling, buying);
                    suffix[1] = "1";
                    suffix[2] = std::to_string(postedOffer.price.n);
                    suffix[3] = std::to_string(postedOffer.price.d);
                    suffix[4] = std::to_string(postedOffer.amount);
                    fillParty(suffix, 5, makerAfterPost);

                    auto changeTrustTx =
                        maker.tx({changeTrust(buying, newBuyLimit)});
                    bool const limitChanged =
                        applyCheck(changeTrustTx, *lifecycleApp);
                    suffix[11] = std::to_string(newBuyLimit);
                    if (!limitChanged)
                    {
                        suffix[0] = "5";
                        finishLifecycle(suffix);
                    }
                    else
                    {
                        auto const makerAfterLimit =
                            readParty(maker, selling, buying);
                        suffix[10] = "1";
                        suffix[12] = std::to_string(makerAfterLimit[2] -
                                                    makerAfterLimit[3] -
                                                    makerAfterLimit[4]);

                        // Buy exactly the resting wheat amount.  ManageBuy
                        // inverts this raw price, so the actual counteroffer
                        // has the reciprocal canonical price.  Exact receive
                        // also ensures the counterrequest is fully consumed;
                        // a ceil-sized ManageSell request can cross the maker
                        // yet leave a one-unit taker offer and liabilities.
                        auto counterTx = taker.tx({manageBuyOffer(
                            0, buying, selling, postedOffer.price,
                            postedOffer.amount)});
                        // No overlay-admission check on the counteroffer
                        // either.  The model does not filter, so it builds
                        // counteroffers that stellar-core's pre-protocol-29
                        // overlay filter would refuse; that filter is out of
                        // scope here.  Successful application below is the
                        // property this row actually compares.
                        bool const crossed =
                            applyCheck(counterTx, *lifecycleApp);
                        REQUIRE(crossed);
                        auto const& counterResult = counterTx->getResult()
                                                        .result.results()[0]
                                                        .tr()
                                                        .manageBuyOfferResult();
                        REQUIRE(counterResult.code() ==
                                MANAGE_BUY_OFFER_SUCCESS);
                        REQUIRE(counterResult.success().offer.effect() ==
                                MANAGE_OFFER_DELETED);
                        REQUIRE(!counterResult.success().offersClaimed.empty());
                        REQUIRE(lifecycleApp->getLedgerTxnRoot()
                                    .getOffersByAccountAndAsset(
                                        taker.getPublicKey(), buying)
                                    .empty());

                        auto const finalMaker =
                            readParty(maker, selling, buying);
                        auto const finalTaker =
                            readParty(taker, buying, selling);
                        REQUIRE(finalTaker[1] == 0);
                        REQUIRE(finalTaker[4] == 0);
                        int64_t remaining = 0;
                        {
                            LedgerTxn ltx(lifecycleApp->getLedgerTxnRoot());
                            auto offer = stellar::loadOffer(
                                ltx, maker.getPublicKey(), expectedOfferID);
                            if (offer)
                            {
                                remaining = offer.current().data.offer().amount;
                            }
                        }
                        suffix[0] = "12";
                        suffix[13] = "1";
                        suffix[14] =
                            std::to_string(makerAfterLimit[0] - finalMaker[0]);
                        suffix[15] =
                            std::to_string(finalMaker[3] - makerAfterLimit[3]);
                        suffix[16] = std::to_string(remaining);
                        fillParty(suffix, 17, finalMaker);
                        fillParty(suffix, 22, finalTaker);
                        finishLifecycle(suffix);
                    }
                }
            }
            CAPTURE(isBuy, priceN, priceD, amount, makerSellBalance,
                    makerSellLiabilities, makerBuyLimit, makerBuyBalance,
                    makerBuyLiabilities, newBuyLimit);
        }
        else
        {
            FAIL("unsupported differential record tag: " << fields[1]);
        }

        CAPTURE(fields[1], fields[2]);
        INFO("model result: " << expectedStatus << ' ' << expectedValue);
        INFO("C++ result: " << actualStatus << ' ' << actualValue);
        REQUIRE(actualStatus == expectedStatus);
        REQUIRE(actualValue == expectedValue);
        ++recordCount;
    }

    REQUIRE(recordCount > 0);
    for (auto const& coverage : lifecycleCoverage)
    {
        // Ad-hoc focused expected files may contain only one trace.  The
        // committed golden and generated corpus both carry at least 20 rows
        // per lifecycle tag and protocol and must cover all four stages.
        if (coverage.records < 20)
        {
            continue;
        }
        CAPTURE(coverage.tag, coverage.ledgerVersion, coverage.records);
        REQUIRE(coverage.postingRejected);
        REQUIRE(coverage.offerCreated);
        REQUIRE(coverage.limitChanged);
        REQUIRE(coverage.positiveCross);
    }
}
