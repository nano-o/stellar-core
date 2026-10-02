#!/usr/bin/env python3
"""Generate deterministic exchangeV10-helper differential-test inputs."""

from __future__ import annotations

import argparse
import itertools
import random
from dataclasses import dataclass
from pathlib import Path


INT32_MIN = -(2**31)
INT32_MAX = 2**31 - 1
INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
UINT128_MAX = 2**128 - 1
DEFAULT_SEED = 0x5EEDC0DE
DEFAULT_RANDOM_COUNT = 10_000
LIFECYCLE_RANDOM_COUNT = 200


@dataclass(frozen=True)
class OfferValueCase:
    case_id: str
    price_n: int
    price_d: int
    max_send: int
    max_receive: int

    def row(self) -> str:
        fields = (
            "v1",
            "offer_value",
            self.case_id,
            str(self.price_n),
            str(self.price_d),
            str(self.max_send),
            str(self.max_receive),
        )
        return "\t".join(fields)


@dataclass(frozen=True)
class BigMultiplyCase:
    case_id: str
    a: int
    b: int

    def row(self) -> str:
        return "\t".join(("v1", "big_multiply", self.case_id,
                          str(self.a), str(self.b)))


@dataclass(frozen=True)
class PriceErrorBoundCase:
    case_id: str
    price_n: int
    price_d: int
    wheat_receive: int
    sheep_send: int
    can_favor_wheat: bool

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "price_error_bound",
                self.case_id,
                str(self.price_n),
                str(self.price_d),
                str(self.wheat_receive),
                str(self.sheep_send),
                "1" if self.can_favor_wheat else "0",
            )
        )


@dataclass(frozen=True)
class BigDivideCase:
    case_id: str
    a: int
    b: int
    c: int
    rounding: str

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "big_divide",
                self.case_id,
                str(self.a),
                str(self.b),
                str(self.c),
                self.rounding,
            )
        )


@dataclass(frozen=True)
class BigDivide128Case:
    case_id: str
    a: int
    b: int
    rounding: str

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "big_divide_128",
                self.case_id,
                str(self.a),
                str(self.b),
                self.rounding,
            )
        )


@dataclass(frozen=True)
class BigMultiplyUnsignedCase:
    case_id: str
    a: int
    b: int

    def row(self) -> str:
        return "\t".join(("v1", "big_multiply_unsigned", self.case_id,
                          str(self.a), str(self.b)))


@dataclass(frozen=True)
class BigDivideUnsignedCase:
    """bigDivideUnsigned: unsigned operands, Boolean flag plus out-parameter."""

    case_id: str
    a: int
    b: int
    c: int
    rounding: str

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "big_divide_unsigned",
                self.case_id,
                str(self.a),
                str(self.b),
                str(self.c),
                self.rounding,
            )
        )


@dataclass(frozen=True)
class BigDivideNothrowCase:
    """bigDivide: the no-throw signed wrapper, Boolean flag plus out-parameter."""

    case_id: str
    a: int
    b: int
    c: int
    rounding: str

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "big_divide_nothrow",
                self.case_id,
                str(self.a),
                str(self.b),
                str(self.c),
                self.rounding,
            )
        )


@dataclass(frozen=True)
class BigDivideUnsigned128Case:
    """bigDivideUnsigned128: 128-bit numerator, unsigned 64-bit divisor."""

    case_id: str
    a: int
    b: int
    rounding: str

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "big_divide_unsigned_128",
                self.case_id,
                str(self.a),
                str(self.b),
                self.rounding,
            )
        )


@dataclass(frozen=True)
class BigDivide128NothrowCase:
    """bigDivide128: the no-throw signed wrapper of the 128-bit family."""

    case_id: str
    a: int
    b: int
    rounding: str

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "big_divide_128_nothrow",
                self.case_id,
                str(self.a),
                str(self.b),
                self.rounding,
            )
        )


@dataclass(frozen=True)
class ApplyPriceErrorThresholdsCase:
    case_id: str
    price_n: int
    price_d: int
    wheat_receive: int
    sheep_send: int
    wheat_stays: bool
    rounding: str

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "apply_price_error_thresholds",
                self.case_id,
                str(self.price_n),
                str(self.price_d),
                str(self.wheat_receive),
                str(self.sheep_send),
                "1" if self.wheat_stays else "0",
                self.rounding,
            )
        )


# The two ledger versions the protocol mapping distinguishes.
LEGACY_LEDGER_VERSION = 28
REPAIRED_LEDGER_VERSION = 29
# Lifecycle rows need a real ledger at their protocol; see the note in
# generate_offer_lifecycle_cases.
LIFECYCLE_LEDGER_VERSIONS = (LEGACY_LEDGER_VERSION, REPAIRED_LEDGER_VERSION)


@dataclass(frozen=True)
class OfferAmountFromValueCase:
    case_id: str
    price_n: int
    price_d: int
    max_send: int
    max_receive: int

    def row(self) -> str:
        fields = (
            "v1",
            "offer_amount_from_value",
            self.case_id,
            str(self.price_n),
            str(self.price_d),
            str(self.max_send),
            str(self.max_receive),
        )
        return "\t".join(fields)


@dataclass(frozen=True)
class ExchangeV10WithoutPriceErrorThresholdsCase:
    case_id: str
    price_n: int
    price_d: int
    max_wheat_send: int
    max_wheat_receive: int
    max_sheep_send: int
    max_sheep_receive: int
    rounding: str
    ledger_version: int

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "exchange_v10_without_price_error_thresholds",
                self.case_id,
                str(self.price_n),
                str(self.price_d),
                str(self.max_wheat_send),
                str(self.max_wheat_receive),
                str(self.max_sheep_send),
                str(self.max_sheep_receive),
                self.rounding,
                str(self.ledger_version),
            )
        )


@dataclass(frozen=True)
class ExchangeV10Case:
    case_id: str
    price_n: int
    price_d: int
    max_wheat_send: int
    max_wheat_receive: int
    max_sheep_send: int
    max_sheep_receive: int
    rounding: str
    ledger_version: int

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "exchange_v10",
                self.case_id,
                str(self.price_n),
                str(self.price_d),
                str(self.max_wheat_send),
                str(self.max_wheat_receive),
                str(self.max_sheep_send),
                str(self.max_sheep_receive),
                self.rounding,
                str(self.ledger_version),
            )
        )


@dataclass(frozen=True)
class AdjustOfferCase:
    case_id: str
    price_n: int
    price_d: int
    max_wheat_send: int
    max_sheep_receive: int
    ledger_version: int

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                "adjust_offer",
                self.case_id,
                str(self.price_n),
                str(self.price_d),
                str(self.max_wheat_send),
                str(self.max_sheep_receive),
                str(self.ledger_version),
            )
        )


@dataclass(frozen=True)
class AdjustmentPriceAmountCase:
    tag: str
    case_id: str
    price_n: int
    price_d: int
    amount: int
    ledger_version: int = 0

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                self.tag,
                self.case_id,
                str(self.price_n),
                str(self.price_d),
                str(self.ledger_version),
                str(self.amount),
            )
        )


@dataclass(frozen=True)
class OfferLifecycleCase:
    tag: str
    case_id: str
    price_n: int
    price_d: int
    ledger_version: int
    amount: int
    maker_sell_balance: int
    maker_sell_liabilities: int
    maker_buy_limit: int
    maker_buy_balance: int
    maker_buy_liabilities: int
    new_buy_limit: int

    def row(self) -> str:
        return "\t".join(
            (
                "v1",
                self.tag,
                self.case_id,
                str(self.price_n),
                str(self.price_d),
                str(self.ledger_version),
                str(self.amount),
                str(self.maker_sell_balance),
                str(self.maker_sell_liabilities),
                str(self.maker_buy_limit),
                str(self.maker_buy_balance),
                str(self.maker_buy_liabilities),
                str(self.new_buy_limit),
            )
        )


DifferentialCase = (
    OfferValueCase
    | OfferAmountFromValueCase
    | BigMultiplyCase
    | PriceErrorBoundCase
    | BigDivideCase
    | BigDivide128Case
    | BigMultiplyUnsignedCase
    | BigDivideUnsignedCase
    | BigDivideNothrowCase
    | BigDivideUnsigned128Case
    | BigDivide128NothrowCase
    | ApplyPriceErrorThresholdsCase
    | ExchangeV10WithoutPriceErrorThresholdsCase
    | ExchangeV10Case
    | AdjustOfferCase
    | AdjustmentPriceAmountCase
    | OfferLifecycleCase
)


def generate_offer_value_cases(
    seed: int, random_count: int
) -> list[OfferValueCase]:
    cases: list[OfferValueCase] = []
    case_ids: set[str] = set()

    def add(
        case_id: str,
        price_n: int,
        price_d: int,
        max_send: int,
        max_receive: int,
    ) -> None:
        if case_id in case_ids:
            raise ValueError(f"duplicate case_id: {case_id}")
        case_ids.add(case_id)
        cases.append(
            OfferValueCase(
                case_id, price_n, price_d, max_send, max_receive
            )
        )

    add("regression_example", 3, 2, 10, 10)
    add("regression_both_zero", 0, 0, 0, 0)
    add("regression_send_limited", 7, 3, 4, 100)
    add("regression_receive_limited", 7, 3, 100, 4)

    add("negative_price_n", -1, 2, 10, 10)
    add("negative_price_d", 3, -1, 10, 10)
    add("negative_max_send", 3, 2, -1, 10)
    add("negative_max_receive", 3, 2, 10, -1)

    for price_n in range(9):
        for price_d in range(9):
            for max_send in range(33):
                for max_receive in range(33):
                    add(
                        f"small_pn{price_n}_pd{price_d}"
                        f"_send{max_send}_recv{max_receive}",
                        price_n,
                        price_d,
                        max_send,
                        max_receive,
                    )

    equality_parameters = [
        (3, 2, 5),
        (17, 11, 1_000),
        (INT32_MAX, INT32_MAX - 1, 2),
        (1, INT32_MAX, 1),
    ]
    for index, (price_n, price_d, scale) in enumerate(equality_parameters):
        max_send = price_d * scale
        max_receive = price_n * scale
        add(
            f"equality_{index}_exact",
            price_n,
            price_d,
            max_send,
            max_receive,
        )
        if max_receive > 0:
            add(
                f"equality_{index}_receive_below",
                price_n,
                price_d,
                max_send,
                max_receive - 1,
            )
        if max_receive < INT64_MAX:
            add(
                f"equality_{index}_receive_above",
                price_n,
                price_d,
                max_send,
                max_receive + 1,
            )

    price_boundaries = [0, 1, 2, INT32_MAX - 1, INT32_MAX]
    amount_boundaries = [0, 1, 2, INT64_MAX - 1, INT64_MAX]
    for pn_index, price_n in enumerate(price_boundaries):
        for pd_index, price_d in enumerate(price_boundaries):
            for send_index, max_send in enumerate(amount_boundaries):
                for receive_index, max_receive in enumerate(amount_boundaries):
                    add(
                        f"boundary_pn{pn_index}_pd{pd_index}"
                        f"_send{send_index}_recv{receive_index}",
                        price_n,
                        price_d,
                        max_send,
                        max_receive,
                    )

    rng = random.Random(seed)
    near_price_max = [INT32_MAX - offset for offset in range(5)]
    near_amount_max = [INT64_MAX - offset for offset in range(5)]

    for index in range(random_count):
        pattern = index % 6
        if pattern == 0:
            price_n = rng.choice(price_boundaries)
            price_d = rng.choice(price_boundaries)
            max_send = rng.choice(amount_boundaries)
            max_receive = rng.choice(amount_boundaries)
        elif pattern == 1:
            price_n = rng.randrange(0, 1_001)
            price_d = rng.randrange(0, 1_001)
            max_send = 0 if rng.randrange(2) == 0 else rng.randrange(0, 1_001)
            max_receive = (
                0 if rng.randrange(2) == 0 else rng.randrange(0, 1_001)
            )
        elif pattern in (2, 3):
            price_n = rng.randrange(1, 100_001)
            price_d = rng.randrange(1, 100_001)
            scale_limit = INT64_MAX // max(price_n, price_d)
            scale = rng.randrange(0, min(scale_limit, 10**9) + 1)
            max_send = price_d * scale
            max_receive = price_n * scale
            if pattern == 3:
                delta = rng.choice((-1, 1))
                adjusted = max_receive + delta
                if 0 <= adjusted <= INT64_MAX:
                    max_receive = adjusted
        elif pattern == 4:
            price_n = rng.choice(near_price_max)
            price_d = rng.choice(near_price_max)
            max_send = rng.choice(near_amount_max)
            max_receive = rng.choice(near_amount_max)
        else:
            price_n = rng.randrange(0, INT32_MAX + 1)
            price_d = rng.randrange(0, INT32_MAX + 1)
            max_send = rng.randrange(0, INT64_MAX + 1)
            max_receive = rng.randrange(0, INT64_MAX + 1)

        add(
            f"random_{index:05d}",
            price_n,
            price_d,
            max_send,
            max_receive,
        )

    return cases


def generate_big_multiply_cases(
    seed: int, random_count: int
) -> list[BigMultiplyCase]:
    cases: list[BigMultiplyCase] = []

    def add(case_id: str, a: int, b: int) -> None:
        cases.append(BigMultiplyCase(case_id, a, b))

    add("bigmul_zero", 0, 0)
    add("bigmul_one", 1, 1)
    add("bigmul_over_64_bits", 2**62, 5)
    add("bigmul_max_product", INT64_MAX, INT64_MAX)
    add("bigmul_negative_a", -1, 1)
    add("bigmul_negative_b", 1, -1)
    add("bigmul_negative_both", -1, -1)

    boundaries = [
        INT64_MIN,
        INT64_MIN + 1,
        -1,
        0,
        1,
        2,
        2**32,
        INT64_MAX - 1,
        INT64_MAX,
    ]
    for a_index, a in enumerate(boundaries):
        for b_index, b in enumerate(boundaries):
            add(f"bigmul_boundary_a{a_index}_b{b_index}", a, b)

    rng = random.Random(seed ^ 0xB16B00B5)
    near_max = [INT64_MAX - offset for offset in range(8)]
    for index in range(random_count):
        pattern = index % 5
        if pattern == 0:
            a = rng.choice(boundaries)
            b = rng.choice(boundaries)
        elif pattern == 1:
            a = rng.randrange(0, 1_000_001)
            b = rng.randrange(0, 1_000_001)
        elif pattern == 2:
            a = rng.choice(near_max)
            b = rng.choice(near_max)
        elif pattern == 3:
            a = -rng.randrange(1, INT64_MAX + 1)
            b = rng.randrange(0, INT64_MAX + 1)
        else:
            a = rng.randrange(0, INT64_MAX + 1)
            b = rng.randrange(0, INT64_MAX + 1)
        add(f"bigmul_random_{index:05d}", a, b)

    return cases


def generate_price_error_bound_cases(
    seed: int, random_count: int
) -> list[PriceErrorBoundCase]:
    cases: list[PriceErrorBoundCase] = []

    def add(
        case_id: str,
        price_n: int,
        price_d: int,
        wheat_receive: int,
        sheep_send: int,
        can_favor_wheat: bool,
    ) -> None:
        cases.append(
            PriceErrorBoundCase(
                case_id,
                price_n,
                price_d,
                wheat_receive,
                sheep_send,
                can_favor_wheat,
            )
        )

    for can_favor_wheat in (False, True):
        mode = "favor" if can_favor_wheat else "symmetric"
        add(f"priceerr_{mode}_zero", 0, 0, 0, 0, can_favor_wheat)
        add(f"priceerr_{mode}_equal", 7, 7, 11, 11, can_favor_wheat)
        add(
            f"priceerr_{mode}_threshold_low_exact",
            1,
            1,
            100,
            99,
            can_favor_wheat,
        )
        add(
            f"priceerr_{mode}_threshold_low_minus_one",
            1,
            1,
            100,
            98,
            can_favor_wheat,
        )
        add(
            f"priceerr_{mode}_threshold_low_plus_one",
            1,
            1,
            100,
            100,
            can_favor_wheat,
        )
        add(
            f"priceerr_{mode}_threshold_high_exact",
            1,
            1,
            100,
            101,
            can_favor_wheat,
        )
        add(
            f"priceerr_{mode}_threshold_high_plus_one",
            1,
            1,
            100,
            102,
            can_favor_wheat,
        )
        add(
            f"priceerr_{mode}_asymmetric_far",
            1,
            1,
            100,
            1_000_000,
            can_favor_wheat,
        )

    add("priceerr_negative_price_n", -1, 1, 1, 1, False)
    add("priceerr_negative_price_d", 1, -1, 1, 1, False)
    add("priceerr_negative_wheat", 1, 1, -1, 1, False)
    add("priceerr_negative_sheep", 1, 1, 1, -1, False)

    price_boundaries = [INT32_MIN, -1, 0, 1, INT32_MAX]
    amount_boundaries = [INT64_MIN, -1, 0, 1, INT64_MAX]
    for n_index, price_n in enumerate(price_boundaries):
        for d_index, price_d in enumerate(price_boundaries):
            for wheat_index, wheat_receive in enumerate(amount_boundaries):
                for sheep_index, sheep_send in enumerate(amount_boundaries):
                    for can_favor_wheat in (False, True):
                        mode = 1 if can_favor_wheat else 0
                        add(
                            f"priceerr_boundary_n{n_index}_d{d_index}"
                            f"_w{wheat_index}_s{sheep_index}_f{mode}",
                            price_n,
                            price_d,
                            wheat_receive,
                            sheep_send,
                            can_favor_wheat,
                        )

    rng = random.Random(seed ^ 0xC0FFEE10)
    near_price_max = [INT32_MAX - offset for offset in range(8)]
    near_amount_max = [INT64_MAX - offset for offset in range(8)]
    for index in range(random_count):
        pattern = index % 6
        can_favor_wheat = bool(rng.randrange(2))
        if pattern == 0:
            price_n = rng.choice(price_boundaries)
            price_d = rng.choice(price_boundaries)
            wheat_receive = rng.choice(amount_boundaries)
            sheep_send = rng.choice(amount_boundaries)
        elif pattern == 1:
            price_n = rng.randrange(0, 10_001)
            price_d = rng.randrange(0, 10_001)
            wheat_receive = rng.randrange(0, 1_000_001)
            sheep_send = rng.randrange(0, 1_000_001)
        elif pattern in (2, 3):
            price_n = rng.randrange(1, 100_001)
            price_d = rng.randrange(1, 100_001)
            wheat_receive = rng.randrange(0, 10**12 + 1)
            target = price_n * wheat_receive
            baseline = target // price_d
            error = max(1, target // (100 * price_d))
            sheep_send = baseline + (error if pattern == 2 else -error)
            sheep_send += rng.choice((-1, 0, 1))
            sheep_send = min(INT64_MAX, max(0, sheep_send))
        elif pattern == 4:
            price_n = rng.choice(near_price_max)
            price_d = rng.choice(near_price_max)
            wheat_receive = rng.choice(near_amount_max)
            sheep_send = rng.choice(near_amount_max)
        else:
            price_n = rng.randrange(INT32_MIN, INT32_MAX + 1)
            price_d = rng.randrange(INT32_MIN, INT32_MAX + 1)
            wheat_receive = rng.randrange(INT64_MIN, INT64_MAX + 1)
            sheep_send = rng.randrange(INT64_MIN, INT64_MAX + 1)

        add(
            f"priceerr_random_{index:05d}",
            price_n,
            price_d,
            wheat_receive,
            sheep_send,
            can_favor_wheat,
        )

    return cases


def generate_big_divide_cases(
    seed: int, random_count: int
) -> list[BigDivideCase]:
    cases: list[BigDivideCase] = []

    def add(case_id: str, a: int, b: int, c: int, rounding: str) -> None:
        cases.append(BigDivideCase(case_id, a, b, c, rounding))

    for rounding in ("DOWN", "UP"):
        mode = rounding.lower()
        add(f"bigdiv_{mode}_zero", 0, 0, 1, rounding)
        add(f"bigdiv_{mode}_exact", 10, 2, 5, rounding)
        add(f"bigdiv_{mode}_remainder", 10, 1, 3, rounding)
        add(f"bigdiv_{mode}_max_exact", INT64_MAX, 2, 2, rounding)
        add(
            f"bigdiv_{mode}_max_plus_one",
            INT64_MAX,
            INT64_MAX,
            INT64_MAX - 1,
            rounding,
        )
    add("bigdiv_assert_negative_a", -1, 1, 1, "DOWN")
    add("bigdiv_assert_negative_b", 1, -1, 1, "UP")
    add("bigdiv_assert_zero_c", 1, 1, 0, "DOWN")
    add("bigdiv_assert_negative_c", 1, 1, -1, "UP")

    boundaries = [
        INT64_MIN,
        -1,
        0,
        1,
        2,
        3,
        INT64_MAX - 1,
        INT64_MAX,
    ]
    for a_index, a in enumerate(boundaries):
        for b_index, b in enumerate(boundaries):
            for c_index, c in enumerate(boundaries):
                for rounding in ("DOWN", "UP"):
                    mode = 0 if rounding == "DOWN" else 1
                    add(
                        f"bigdiv_boundary_a{a_index}_b{b_index}"
                        f"_c{c_index}_r{mode}",
                        a,
                        b,
                        c,
                        rounding,
                    )

    rng = random.Random(seed ^ 0xD1A1DE00)
    nonnegative_boundaries = [0, 1, 2, 3, INT64_MAX - 1, INT64_MAX]
    for index in range(random_count):
        pattern = index % 6
        rounding = "DOWN" if rng.randrange(2) == 0 else "UP"
        if pattern == 0:
            a = rng.choice(boundaries)
            b = rng.choice(boundaries)
            c = rng.choice(boundaries)
        elif pattern == 1:
            a = rng.randrange(0, 1_000_001)
            b = rng.randrange(0, 1_000_001)
            c = rng.randrange(1, 1_000_001)
        elif pattern == 2:
            quotient = rng.randrange(0, INT64_MAX + 1)
            c = rng.randrange(1, 1_000_001)
            b = rng.randrange(1, 1_000_001)
            a = min(INT64_MAX, (quotient * c) // b)
        elif pattern == 3:
            a = rng.choice([INT64_MAX - offset for offset in range(8)])
            b = rng.choice([INT64_MAX - offset for offset in range(8)])
            c = rng.choice(nonnegative_boundaries[1:])
        elif pattern == 4:
            a = -rng.randrange(1, INT64_MAX + 1)
            b = rng.randrange(INT64_MIN, INT64_MAX + 1)
            c = rng.randrange(INT64_MIN, INT64_MAX + 1)
        else:
            a = rng.randrange(0, INT64_MAX + 1)
            b = rng.randrange(0, INT64_MAX + 1)
            c = rng.randrange(1, INT64_MAX + 1)
        add(f"bigdiv_random_{index:05d}", a, b, c, rounding)

    return cases


def generate_big_divide128_cases(
    seed: int, random_count: int
) -> list[BigDivide128Case]:
    cases: list[BigDivide128Case] = []

    def add(case_id: str, a: int, b: int, rounding: str) -> None:
        cases.append(BigDivide128Case(case_id, a, b, rounding))

    for rounding in ("DOWN", "UP"):
        mode = rounding.lower()
        add(f"bigdiv128_{mode}_zero", 0, 1, rounding)
        add(f"bigdiv128_{mode}_exact", 20, 5, rounding)
        add(f"bigdiv128_{mode}_remainder", 10, 3, rounding)
        add(
            f"bigdiv128_{mode}_max_exact",
            INT64_MAX * 2,
            2,
            rounding,
        )
        add(
            f"bigdiv128_{mode}_max_minus_remainder",
            INT64_MAX * 2 - 1,
            2,
            rounding,
        )
        add(
            f"bigdiv128_{mode}_max_plus_one",
            (INT64_MAX + 1) * 2,
            2,
            rounding,
        )
    add("bigdiv128_assert_zero_b", 1, 0, "DOWN")
    add("bigdiv128_assert_negative_b", 1, -1, "UP")
    add("bigdiv128_round_up_guard", UINT128_MAX, 2, "UP")
    add("bigdiv128_round_up_guard_edge", UINT128_MAX - 1, 2, "UP")

    a_boundaries = [
        0,
        1,
        2,
        2**64 - 1,
        2**64,
        2**127,
        UINT128_MAX - 1,
        UINT128_MAX,
    ]
    b_boundaries = [INT64_MIN, -1, 0, 1, 2, 3, INT64_MAX]
    for a_index, a in enumerate(a_boundaries):
        for b_index, b in enumerate(b_boundaries):
            for rounding in ("DOWN", "UP"):
                mode = 0 if rounding == "DOWN" else 1
                add(
                    f"bigdiv128_boundary_a{a_index}_b{b_index}_r{mode}",
                    a,
                    b,
                    rounding,
                )

    rng = random.Random(seed ^ 0x128D1A1D)
    near_uint128_max = [UINT128_MAX - offset for offset in range(16)]
    for index in range(random_count):
        pattern = index % 6
        rounding = "DOWN" if rng.randrange(2) == 0 else "UP"
        if pattern == 0:
            a = rng.choice(a_boundaries)
            b = rng.choice(b_boundaries)
        elif pattern == 1:
            a = rng.randrange(0, 10**18 + 1)
            b = rng.randrange(1, 1_000_001)
        elif pattern == 2:
            b = rng.randrange(1, INT64_MAX + 1)
            quotient = rng.choice(
                [0, 1, 2, INT64_MAX - 1, INT64_MAX, INT64_MAX + 1]
            )
            remainder = rng.randrange(0, min(b, 1_000_000))
            a = min(UINT128_MAX, quotient * b + remainder)
        elif pattern == 3:
            a = rng.choice(near_uint128_max)
            b = rng.randrange(1, INT64_MAX + 1)
        elif pattern == 4:
            a = rng.randrange(0, UINT128_MAX + 1)
            b = rng.choice([INT64_MIN, -1, 0])
        else:
            a = rng.randrange(0, UINT128_MAX + 1)
            b = rng.randrange(1, INT64_MAX + 1)
        add(f"bigdiv128_random_{index:05d}", a, b, rounding)

    return cases


UINT64_MAX = 2**64 - 1


def generate_big_multiply_unsigned_cases(
    seed: int, random_count: int
) -> list[BigMultiplyUnsignedCase]:
    cases: list[BigMultiplyUnsignedCase] = []

    def add(case_id: str, a: int, b: int) -> None:
        cases.append(BigMultiplyUnsignedCase(case_id, a, b))

    add("bigmulu_zero", 0, 0)
    add("bigmulu_one", 1, 1)
    add("bigmulu_over_64_bits", 2**62, 5)
    add("bigmulu_signed_max_product", INT64_MAX, INT64_MAX)
    add("bigmulu_max_product", UINT64_MAX, UINT64_MAX)
    add("bigmulu_high_bit", 2**63, 2)

    boundaries = [
        0,
        1,
        2,
        2**32,
        INT64_MAX,
        2**63,
        UINT64_MAX - 1,
        UINT64_MAX,
    ]
    for a_index, a in enumerate(boundaries):
        for b_index, b in enumerate(boundaries):
            add(f"bigmulu_boundary_a{a_index}_b{b_index}", a, b)

    rng = random.Random(seed ^ 0xB16B0055)
    near_max = [UINT64_MAX - offset for offset in range(8)]
    for index in range(random_count):
        pattern = index % 4
        if pattern == 0:
            a = rng.choice(boundaries)
            b = rng.choice(boundaries)
        elif pattern == 1:
            a = rng.randrange(0, 1_000_001)
            b = rng.randrange(0, 1_000_001)
        elif pattern == 2:
            a = rng.choice(near_max)
            b = rng.choice(near_max)
        else:
            a = rng.randrange(0, UINT64_MAX + 1)
            b = rng.randrange(0, UINT64_MAX + 1)
        add(f"bigmulu_random_{index:05d}", a, b)

    return cases


def generate_big_divide_unsigned_cases(
    seed: int, random_count: int
) -> list[BigDivideUnsignedCase]:
    cases: list[BigDivideUnsignedCase] = []

    def add(case_id: str, a: int, b: int, c: int, rounding: str) -> None:
        cases.append(BigDivideUnsignedCase(case_id, a, b, c, rounding))

    for rounding in ("DOWN", "UP"):
        mode = rounding.lower()
        add(f"bigdivu_{mode}_zero", 0, 0, 1, rounding)
        add(f"bigdivu_{mode}_exact", 10, 2, 5, rounding)
        add(f"bigdivu_{mode}_remainder", 10, 1, 3, rounding)
        add(f"bigdivu_{mode}_fits_64", UINT64_MAX, 1, 1, rounding)
        add(f"bigdivu_{mode}_just_over_64", UINT64_MAX, 2, 1, rounding)
        add(f"bigdivu_{mode}_max_product", UINT64_MAX, UINT64_MAX, 1, rounding)
        add(f"bigdivu_{mode}_max_product_max_divisor",
            UINT64_MAX, UINT64_MAX, UINT64_MAX, rounding)
    add("bigdivu_assert_zero_c", 1, 1, 0, "DOWN")
    add("bigdivu_assert_zero_c_up", UINT64_MAX, UINT64_MAX, 0, "UP")

    boundaries = [0, 1, 2, 3, INT64_MAX, 2**63, UINT64_MAX - 1, UINT64_MAX]
    for a_index, a in enumerate(boundaries):
        for b_index, b in enumerate(boundaries):
            for c_index, c in enumerate(boundaries):
                for rounding in ("DOWN", "UP"):
                    mode = 0 if rounding == "DOWN" else 1
                    add(
                        f"bigdivu_boundary_a{a_index}_b{b_index}"
                        f"_c{c_index}_r{mode}",
                        a,
                        b,
                        c,
                        rounding,
                    )

    rng = random.Random(seed ^ 0xD1A1DE55)
    for index in range(random_count):
        pattern = index % 6
        rounding = "DOWN" if rng.randrange(2) == 0 else "UP"
        if pattern == 0:
            a = rng.choice(boundaries)
            b = rng.choice(boundaries)
            c = rng.choice(boundaries)
        elif pattern == 1:
            a = rng.randrange(0, 1_000_001)
            b = rng.randrange(0, 1_000_001)
            c = rng.randrange(1, 1_000_001)
        elif pattern == 2:
            # Quotients straddling the 64-bit boundary.
            quotient = rng.choice(
                [UINT64_MAX - 1, UINT64_MAX, UINT64_MAX + 1, UINT64_MAX + 2]
            )
            c = rng.randrange(1, 1_000_001)
            b = rng.randrange(1, 1_000_001)
            a = min(UINT64_MAX, (quotient * c) // b)
        elif pattern == 3:
            a = rng.choice([UINT64_MAX - offset for offset in range(8)])
            b = rng.choice([UINT64_MAX - offset for offset in range(8)])
            c = rng.choice(boundaries[1:])
        elif pattern == 4:
            a = rng.randrange(0, UINT64_MAX + 1)
            b = rng.randrange(0, UINT64_MAX + 1)
            c = 0
        else:
            a = rng.randrange(0, UINT64_MAX + 1)
            b = rng.randrange(0, UINT64_MAX + 1)
            c = rng.randrange(1, UINT64_MAX + 1)
        add(f"bigdivu_random_{index:05d}", a, b, c, rounding)

    return cases


def generate_big_divide_nothrow_cases(
    seed: int, random_count: int
) -> list[BigDivideNothrowCase]:
    # The no-throw signed wrapper takes exactly the inputs of the throwing
    # one, so it reuses that corpus under its own tag and case ids.
    return [
        BigDivideNothrowCase(
            f"nothrow_{case.case_id}", case.a, case.b, case.c, case.rounding
        )
        for case in generate_big_divide_cases(seed, random_count)
    ]


def generate_big_divide_unsigned128_cases(
    seed: int, random_count: int
) -> list[BigDivideUnsigned128Case]:
    cases: list[BigDivideUnsigned128Case] = []

    def add(case_id: str, a: int, b: int, rounding: str) -> None:
        cases.append(BigDivideUnsigned128Case(case_id, a, b, rounding))

    for rounding in ("DOWN", "UP"):
        mode = rounding.lower()
        add(f"bigdivu128_{mode}_zero", 0, 1, rounding)
        add(f"bigdivu128_{mode}_exact", 20, 5, rounding)
        add(f"bigdivu128_{mode}_remainder", 10, 3, rounding)
        add(f"bigdivu128_{mode}_fits_64", UINT64_MAX, 1, rounding)
        add(f"bigdivu128_{mode}_just_over_64", UINT64_MAX + 1, 1, rounding)
        add(f"bigdivu128_{mode}_max_divisor", UINT128_MAX, UINT64_MAX, rounding)
    add("bigdivu128_assert_zero_b", 1, 0, "DOWN")
    add("bigdivu128_assert_zero_b_up", UINT128_MAX, 0, "UP")
    add("bigdivu128_round_up_guard", UINT128_MAX, 2, "UP")
    add("bigdivu128_round_up_guard_edge", UINT128_MAX - 1, 2, "UP")
    add("bigdivu128_round_up_guard_divisor_one", UINT128_MAX, 1, "UP")
    add("bigdivu128_round_up_guard_max_divisor",
        UINT128_MAX - UINT64_MAX + 2, UINT64_MAX, "UP")

    a_boundaries = [
        0,
        1,
        2,
        2**64 - 1,
        2**64,
        2**127,
        UINT128_MAX - 1,
        UINT128_MAX,
    ]
    b_boundaries = [0, 1, 2, 3, INT64_MAX, 2**63, UINT64_MAX]
    for a_index, a in enumerate(a_boundaries):
        for b_index, b in enumerate(b_boundaries):
            for rounding in ("DOWN", "UP"):
                mode = 0 if rounding == "DOWN" else 1
                add(
                    f"bigdivu128_boundary_a{a_index}_b{b_index}_r{mode}",
                    a,
                    b,
                    rounding,
                )

    rng = random.Random(seed ^ 0x128D1A55)
    near_uint128_max = [UINT128_MAX - offset for offset in range(16)]
    for index in range(random_count):
        pattern = index % 6
        rounding = "DOWN" if rng.randrange(2) == 0 else "UP"
        if pattern == 0:
            a = rng.choice(a_boundaries)
            b = rng.choice(b_boundaries)
        elif pattern == 1:
            a = rng.randrange(0, 10**18 + 1)
            b = rng.randrange(1, 1_000_001)
        elif pattern == 2:
            b = rng.randrange(1, UINT64_MAX + 1)
            quotient = rng.choice(
                [0, 1, 2, UINT64_MAX - 1, UINT64_MAX, UINT64_MAX + 1]
            )
            remainder = rng.randrange(0, min(b, 1_000_000))
            a = min(UINT128_MAX, quotient * b + remainder)
        elif pattern == 3:
            # Near the top of the 128-bit range, where the round-up guard
            # decides between an early false and a wrapping numerator.
            a = rng.choice(near_uint128_max)
            b = rng.randrange(1, UINT64_MAX + 1)
        elif pattern == 4:
            a = rng.randrange(0, UINT128_MAX + 1)
            b = 0
        else:
            a = rng.randrange(0, UINT128_MAX + 1)
            b = rng.randrange(1, UINT64_MAX + 1)
        add(f"bigdivu128_random_{index:05d}", a, b, rounding)

    return cases


def generate_big_divide128_nothrow_cases(
    seed: int, random_count: int
) -> list[BigDivide128NothrowCase]:
    # Same inputs as the throwing 128-bit wrapper, under its own tag.
    return [
        BigDivide128NothrowCase(
            f"nothrow_{case.case_id}", case.a, case.b, case.rounding
        )
        for case in generate_big_divide128_cases(seed, random_count)
    ]


def generate_apply_price_error_thresholds_cases(
    seed: int, random_count: int
) -> list[ApplyPriceErrorThresholdsCase]:
    cases: list[ApplyPriceErrorThresholdsCase] = []

    def add(
        case_id: str,
        price_n: int,
        price_d: int,
        wheat_receive: int,
        sheep_send: int,
        wheat_stays: bool,
        rounding: str,
    ) -> None:
        cases.append(
            ApplyPriceErrorThresholdsCase(
                case_id,
                price_n,
                price_d,
                wheat_receive,
                sheep_send,
                wheat_stays,
                rounding,
            )
        )

    roundings = ("NORMAL", "STRICT_SEND", "STRICT_RECEIVE")
    for rounding in roundings:
        mode = rounding.lower()
        for wheat_stays in (False, True):
            stays = 1 if wheat_stays else 0
            prefix = f"apply_{mode}_stays{stays}"

            add(f"{prefix}_equal", 1, 1, 100, 100, wheat_stays, rounding)
            add(
                f"{prefix}_invalid_direction",
                1,
                1,
                100 if wheat_stays else 100,
                99 if wheat_stays else 101,
                wheat_stays,
                rounding,
            )
            add(
                f"{prefix}_threshold_exact",
                1,
                1,
                100,
                101 if wheat_stays else 99,
                wheat_stays,
                rounding,
            )
            add(
                f"{prefix}_threshold_outside",
                1,
                1,
                100,
                102 if wheat_stays else 98,
                wheat_stays,
                rounding,
            )
            add(
                f"{prefix}_zero_wheat",
                1,
                1,
                0,
                7,
                wheat_stays,
                rounding,
            )
            add(
                f"{prefix}_negative_wheat",
                1,
                1,
                -1,
                7,
                wheat_stays,
                rounding,
            )
            add(
                f"{prefix}_zero_sheep",
                1,
                1,
                7,
                0,
                wheat_stays,
                rounding,
            )
            add(
                f"{prefix}_negative_sheep",
                1,
                1,
                7,
                -1,
                wheat_stays,
                rounding,
            )
            add(
                f"{prefix}_both_zero",
                1,
                1,
                0,
                0,
                wheat_stays,
                rounding,
            )
            add(
                f"{prefix}_negative_price_n",
                -1,
                1,
                1,
                1,
                wheat_stays,
                rounding,
            )
            add(
                f"{prefix}_negative_price_d",
                1,
                -1,
                1,
                1,
                wheat_stays,
                rounding,
            )

    price_boundaries = [INT32_MIN, -1, 0, 1, INT32_MAX]
    amount_boundaries = [INT64_MIN, -1, 0, 1, INT64_MAX]
    for n_index, price_n in enumerate(price_boundaries):
        for d_index, price_d in enumerate(price_boundaries):
            for wheat_index, wheat_receive in enumerate(amount_boundaries):
                for sheep_index, sheep_send in enumerate(amount_boundaries):
                    for wheat_stays in (False, True):
                        for rounding_index, rounding in enumerate(roundings):
                            add(
                                f"apply_boundary_n{n_index}_d{d_index}"
                                f"_w{wheat_index}_s{sheep_index}"
                                f"_t{int(wheat_stays)}_r{rounding_index}",
                                price_n,
                                price_d,
                                wheat_receive,
                                sheep_send,
                                wheat_stays,
                                rounding,
                            )

    rng = random.Random(seed ^ 0xA9911E10)
    near_price_max = [INT32_MAX - offset for offset in range(8)]
    near_amount_max = [INT64_MAX - offset for offset in range(8)]
    signed_amount_boundaries = [INT64_MIN, -1, 0, 1, INT64_MAX]
    for index in range(random_count):
        pattern = index % 7
        rounding = rng.choice(roundings)
        wheat_stays = bool(rng.randrange(2))
        if pattern == 0:
            price_n = rng.choice(price_boundaries)
            price_d = rng.choice(price_boundaries)
            wheat_receive = rng.choice(signed_amount_boundaries)
            sheep_send = rng.choice(signed_amount_boundaries)
        elif pattern == 1:
            price_n = rng.randrange(1, 100_001)
            price_d = rng.randrange(1, 100_001)
            scale = rng.randrange(1, 1_000_001)
            wheat_receive = price_d * scale
            sheep_send = price_n * scale
        elif pattern == 2:
            price_n = 1
            price_d = 1
            wheat_receive = rng.randrange(1, 10**12 + 1)
            delta = max(1, wheat_receive // 100)
            if wheat_stays:
                sheep_send = min(INT64_MAX, wheat_receive + delta + 1)
            else:
                sheep_send = max(1, wheat_receive - delta - 1)
        elif pattern == 3:
            price_n = rng.randrange(1, 1_000_001)
            price_d = rng.randrange(1, 1_000_001)
            wheat_receive = rng.randrange(1, 10**12 + 1)
            baseline = (wheat_receive * price_n) // price_d
            if wheat_stays:
                sheep_send = max(1, baseline - rng.randrange(1, 1000))
            else:
                sheep_send = min(INT64_MAX, baseline + rng.randrange(1, 1000))
        elif pattern == 4:
            price_n = rng.choice(near_price_max)
            price_d = rng.choice(near_price_max)
            wheat_receive = rng.choice(near_amount_max)
            sheep_send = rng.choice(near_amount_max)
        elif pattern == 5:
            price_n = rng.randrange(0, INT32_MAX + 1)
            price_d = rng.randrange(0, INT32_MAX + 1)
            wheat_receive = rng.randrange(1, INT64_MAX + 1)
            sheep_send = rng.randrange(1, INT64_MAX + 1)
        else:
            price_n = rng.randrange(INT32_MIN, INT32_MAX + 1)
            price_d = rng.randrange(INT32_MIN, INT32_MAX + 1)
            wheat_receive = rng.randrange(INT64_MIN, INT64_MAX + 1)
            sheep_send = rng.randrange(INT64_MIN, INT64_MAX + 1)

        add(
            f"apply_random_{index:05d}",
            price_n,
            price_d,
            wheat_receive,
            sheep_send,
            wheat_stays,
            rounding,
        )

    return cases


def generate_exchange_v10_without_price_error_thresholds_cases(
    seed: int, random_count: int
) -> list[ExchangeV10WithoutPriceErrorThresholdsCase]:
    cases: list[ExchangeV10WithoutPriceErrorThresholdsCase] = []

    # Every input is emitted once per exactReceiveCap value, as an `_x0`/`_x1`
    # pair differing only in that flag, so any divergence introduced by the
    # exact-receive-cap path shows up as a difference within a pair.
    def add(
        case_id: str,
        price_n: int,
        price_d: int,
        max_wheat_send: int,
        max_wheat_receive: int,
        max_sheep_send: int,
        max_sheep_receive: int,
        rounding: str,
    ) -> None:
        for ledger_version in (LEGACY_LEDGER_VERSION, REPAIRED_LEDGER_VERSION):
            cases.append(
                ExchangeV10WithoutPriceErrorThresholdsCase(
                    f"{case_id}_v{ledger_version}",
                    price_n,
                    price_d,
                    max_wheat_send,
                    max_wheat_receive,
                    max_sheep_send,
                    max_sheep_receive,
                    rounding,
                    ledger_version,
                )
            )

    # One readable regression for each calculation branch in lines 655--690.
    add("without_wheat_stays_strict_send", 3, 2, 100, 100, 10, 100,
        "STRICT_SEND")
    add("without_wheat_stays_wheat_more", 3, 2, 100, 100, 10, 100,
        "NORMAL")
    add("without_wheat_stays_strict_receive", 2, 3, 100, 100, 10, 100,
        "STRICT_RECEIVE")
    add("without_wheat_stays_sheep_more", 2, 3, 100, 100, 10, 100,
        "NORMAL")
    add("without_sheep_stays_wheat_more", 3, 2, 10, 100, 100, 100,
        "NORMAL")
    add("without_sheep_stays_sheep_more", 2, 3, 10, 100, 100, 100,
        "NORMAL")

    roundings = ("NORMAL", "STRICT_SEND", "STRICT_RECEIVE")
    for rounding in roundings:
        mode = rounding.lower()
        add(f"without_{mode}_all_zero", 1, 1, 0, 0, 0, 0, rounding)
        add(f"without_{mode}_unit", 1, 1, 1, 1, 1, 1, rounding)
        add(f"without_{mode}_exact_division", 7, 3, 30, 70, 70, 30,
            rounding)
        add(f"without_{mode}_remainder_division", 7, 3, 31, 71, 69, 29,
            rounding)
        for delta in (-1, 0, 1):
            sheep_limit = 100 + delta
            add(
                f"without_{mode}_value_delta_{delta + 1}",
                1,
                1,
                100,
                sheep_limit,
                sheep_limit,
                100,
                rounding,
            )

    # This Cartesian boundary set remains small enough to review and exercises
    # zero, unit, near-maximum, and maximum amounts at extreme positive prices.
    price_pairs = (
        (1, 1),
        (2, 1),
        (1, 2),
        (INT32_MAX, 1),
        (1, INT32_MAX),
        (INT32_MAX, INT32_MAX),
    )
    amount_boundaries = (0, 1, INT64_MAX - 1, INT64_MAX)
    for price_index, (price_n, price_d) in enumerate(price_pairs):
        for amount_index, amounts in enumerate(
            itertools.product(amount_boundaries, repeat=4)
        ):
            for rounding_index, rounding in enumerate(roundings):
                add(
                    f"without_boundary_p{price_index}_a{amount_index}"
                    f"_r{rounding_index}",
                    price_n,
                    price_d,
                    *amounts,
                    rounding,
                )

    invalid_prices = (INT32_MIN, -1, 0)
    for index, invalid_price in enumerate(invalid_prices):
        for rounding_index, rounding in enumerate(roundings):
            add(
                f"without_invalid_price_n_{index}_r{rounding_index}",
                invalid_price, 1, 1, 1, 1, 1, rounding,
            )
            add(
                f"without_invalid_price_d_{index}_r{rounding_index}",
                1, invalid_price, 1, 1, 1, 1, rounding,
            )

    for amount_index, invalid_amount in enumerate((INT64_MIN, -1)):
        for field_index in range(4):
            amounts = [1, 1, 1, 1]
            amounts[field_index] = invalid_amount
            for rounding_index, rounding in enumerate(roundings):
                add(
                    f"without_invalid_amount_{amount_index}_f{field_index}"
                    f"_r{rounding_index}",
                    1,
                    1,
                    *amounts,
                    rounding,
                )

    # The rounding logic's interesting behavior is densest at small numbers,
    # so sweep every price in {1..3}^2 against every amount combination in
    # {0..6}^4 under all three roundings, exhaustively.
    for price_n in range(1, 4):
        for price_d in range(1, 4):
            for amounts in itertools.product(range(7), repeat=4):
                for rounding_index, rounding in enumerate(roundings):
                    add(
                        f"without_small_pn{price_n}_pd{price_d}"
                        f"_ws{amounts[0]}_wr{amounts[1]}"
                        f"_ss{amounts[2]}_sr{amounts[3]}"
                        f"_r{rounding_index}",
                        price_n,
                        price_d,
                        *amounts,
                        rounding,
                    )

    rng = random.Random(seed ^ 0xE10A10F0)
    for index in range(random_count):
        pattern = index % 13
        rounding = rng.choice(roundings)
        if pattern == 0:
            # Force wheatValue > sheepValue and the strict-send branch.
            price_n = rng.randrange(1, 1_000_001)
            price_d = rng.randrange(1, 1_000_001)
            high = rng.randrange(10**15, 10**16)
            max_wheat_send = high
            max_wheat_receive = high
            max_sheep_send = rng.randrange(1, 1_000_001)
            max_sheep_receive = high
            rounding = "STRICT_SEND"
        elif pattern in (1, 4):
            # price.n > price.d, with either seller staying.
            price_n = rng.randrange(2, 1_000_001)
            price_d = rng.randrange(1, price_n)
            high = rng.randrange(10**15, 10**16)
            low = rng.randrange(1, 1_000_001)
            if pattern == 1:
                max_wheat_send, max_wheat_receive = high, high
                max_sheep_send, max_sheep_receive = low, high
            else:
                max_wheat_send, max_wheat_receive = low, high
                max_sheep_send, max_sheep_receive = high, high
        elif pattern in (2, 3, 5):
            # price.n <= price.d. Patterns 2 and 3 split NORMAL from
            # STRICT_RECEIVE; pattern 5 makes sheep stay.
            price_d = rng.randrange(1, 1_000_001)
            price_n = rng.randrange(1, price_d + 1)
            high = rng.randrange(10**15, 10**16)
            low = rng.randrange(1, 1_000_001)
            if pattern in (2, 3):
                max_wheat_send, max_wheat_receive = high, high
                max_sheep_send, max_sheep_receive = low, high
                rounding = "NORMAL" if pattern == 2 else "STRICT_RECEIVE"
            else:
                max_wheat_send, max_wheat_receive = low, high
                max_sheep_send, max_sheep_receive = high, high
        elif pattern == 6:
            # Exact equality and its two adjacent values at price 1:1.
            price_n = price_d = 1
            wheat_value = rng.randrange(1, 10**15)
            sheep_value = max(0, wheat_value + rng.choice((-1, 0, 1)))
            max_wheat_send = max_sheep_receive = wheat_value
            max_wheat_receive = max_sheep_send = sheep_value
        elif pattern == 7:
            price_n = rng.randrange(1, INT32_MAX + 1)
            price_d = rng.randrange(1, INT32_MAX + 1)
            max_wheat_send = rng.randrange(0, 10**12 + 1)
            max_wheat_receive = rng.randrange(0, 10**12 + 1)
            max_sheep_send = rng.randrange(0, 10**12 + 1)
            max_sheep_receive = rng.randrange(0, 10**12 + 1)
        elif pattern == 8:
            price_n = INT32_MAX - rng.randrange(8)
            price_d = INT32_MAX - rng.randrange(8)
            max_wheat_send = INT64_MAX - rng.randrange(16)
            max_wheat_receive = INT64_MAX - rng.randrange(16)
            max_sheep_send = INT64_MAX - rng.randrange(16)
            max_sheep_receive = INT64_MAX - rng.randrange(16)
        elif pattern == 9:
            price_n = rng.randrange(1, 1_000_001)
            price_d = rng.randrange(1, 1_000_001)
            amounts = [rng.randrange(0, 10**9 + 1) for _ in range(4)]
            amounts[rng.randrange(4)] = 0
            (max_wheat_send, max_wheat_receive,
             max_sheep_send, max_sheep_receive) = amounts
        elif pattern == 10:
            price_n = rng.choice((INT32_MIN, -1, 0))
            price_d = rng.randrange(1, INT32_MAX + 1)
            max_wheat_send = rng.randrange(0, 10**12 + 1)
            max_wheat_receive = rng.randrange(0, 10**12 + 1)
            max_sheep_send = rng.randrange(0, 10**12 + 1)
            max_sheep_receive = rng.randrange(0, 10**12 + 1)
        elif pattern == 11:
            price_n = rng.randrange(1, INT32_MAX + 1)
            price_d = rng.randrange(1, INT32_MAX + 1)
            amounts = [rng.randrange(0, 10**12 + 1) for _ in range(4)]
            amounts[rng.randrange(4)] = rng.randrange(INT64_MIN, 0)
            (max_wheat_send, max_wheat_receive,
             max_sheep_send, max_sheep_receive) = amounts
        else:
            price_n = rng.randrange(INT32_MIN, INT32_MAX + 1)
            price_d = rng.randrange(INT32_MIN, INT32_MAX + 1)
            max_wheat_send = rng.randrange(INT64_MIN, INT64_MAX + 1)
            max_wheat_receive = rng.randrange(INT64_MIN, INT64_MAX + 1)
            max_sheep_send = rng.randrange(INT64_MIN, INT64_MAX + 1)
            max_sheep_receive = rng.randrange(INT64_MIN, INT64_MAX + 1)

        add(
            f"without_random_{index:05d}",
            price_n,
            price_d,
            max_wheat_send,
            max_wheat_receive,
            max_sheep_send,
            max_sheep_receive,
            rounding,
        )

    return cases


def generate_exchange_v10_cases(
    seed: int, random_count: int
) -> list[ExchangeV10Case]:
    cases = [
        ExchangeV10Case(
            f"exchange_{case.case_id}",
            case.price_n,
            case.price_d,
            case.max_wheat_send,
            case.max_wheat_receive,
            case.max_sheep_send,
            case.max_sheep_receive,
            case.rounding,
            case.ledger_version,
        )
        for case in generate_exchange_v10_without_price_error_thresholds_cases(
            seed, random_count
        )
    ]

    def add(
        case_id: str,
        price_n: int,
        price_d: int,
        max_wheat_send: int,
        max_wheat_receive: int,
        max_sheep_send: int,
        max_sheep_receive: int,
        rounding: str,
    ) -> None:
        for ledger_version in (LEGACY_LEDGER_VERSION, REPAIRED_LEDGER_VERSION):
            cases.append(
                ExchangeV10Case(
                    f"{case_id}_v{ledger_version}",
                    price_n,
                    price_d,
                    max_wheat_send,
                    max_wheat_receive,
                    max_sheep_send,
                    max_sheep_receive,
                    rounding,
                    ledger_version,
                )
            )

    # Threshold-focused cases distinguish the final composition from its
    # pre-threshold caller.
    add("exchange_normal_positive_kept", 1, 1, 100, 100, 100, 100,
        "NORMAL")
    add("exchange_normal_price_error_zeroed", 2, 3, 2, 100, 100, 100,
        "NORMAL")
    add("exchange_strict_receive_positive_kept", 1, 1, 100, 100, 100, 100,
        "STRICT_RECEIVE")
    add("exchange_strict_receive_price_error", 2, 3, 2, 100, 100, 100,
        "STRICT_RECEIVE")
    add("exchange_normal_zero_amounts", 1, 1, 0, 0, 0, 0, "NORMAL")
    add("exchange_strict_receive_zero_amounts", 1, 1, 0, 0, 0, 0,
        "STRICT_RECEIVE")
    add("exchange_strict_send_zero_wheat_positive_sheep", 3, 2, 10, 10, 1,
        10, "STRICT_SEND")
    add("exchange_strict_send_zero_sheep_error", 3, 2, 10, 10, 0, 10,
        "STRICT_SEND")

    return cases


def generate_offer_amount_from_value_cases(
    seed: int, random_count: int
) -> list[OfferAmountFromValueCase]:
    cases: list[OfferAmountFromValueCase] = []
    case_ids: set[str] = set()

    def add(
        case_id: str,
        price_n: int,
        price_d: int,
        max_send: int,
        max_receive: int,
    ) -> None:
        if case_id in case_ids:
            raise ValueError(f"duplicate case_id: {case_id}")
        case_ids.add(case_id)
        cases.append(
            OfferAmountFromValueCase(
                case_id, price_n, price_d, max_send, max_receive
            )
        )

    add("exact_regression_example", 3, 2, 10, 10)
    add("exact_regression_both_zero", 0, 0, 0, 0)
    add("exact_regression_send_limited", 7, 3, 4, 100)
    add("exact_regression_receive_limited", 7, 3, 100, 4)

    # The receive-side relaxation adds priceD - 1 before the caller rounds
    # down; priceD = 0 makes the C++ cast chain produce 2^64 - 1 before the
    # INT64_MAX * priceD = 0 clamp erases it again.
    add("exact_priced_zero_landmine", 3, 0, 10, 10)
    add("exact_priced_zero_send_zero", 3, 0, 0, 10)

    # An INT64_MAX receive cap must clamp back to the plain offer value so
    # unlimited counterparties keep adjusted offers as fixed points.
    add("exact_receive_int64_max", 3, 2, 100, INT64_MAX)
    add("exact_receive_int64_max_minus_one", 3, 2, 100, INT64_MAX - 1)
    add("exact_receive_int64_max_steep", INT32_MAX, 663, 1000, INT64_MAX)
    add("exact_both_int64_max", 3, 2, INT64_MAX, INT64_MAX)

    add("exact_negative_price_n", -1, 2, 10, 10)
    add("exact_negative_price_d", 3, -1, 10, 10)
    add("exact_negative_max_send", 3, 2, -1, 10)
    add("exact_negative_max_receive", 3, 2, 10, -1)

    for price_n in range(9):
        for price_d in range(9):
            for max_send in range(17):
                for max_receive in range(17):
                    add(
                        f"exact_small_pn{price_n}_pd{price_d}"
                        f"_send{max_send}_recv{max_receive}",
                        price_n,
                        price_d,
                        max_send,
                        max_receive,
                    )

    # Around an exact multiple of the price the relaxed cap admits one more
    # fractional lot than the plain value; probe the multiple and both
    # neighbors.
    equality_parameters = [
        (3, 2, 5),
        (17, 11, 1_000),
        (INT32_MAX, INT32_MAX - 1, 2),
        (1, INT32_MAX, 1),
    ]
    for index, (price_n, price_d, scale) in enumerate(equality_parameters):
        max_send = price_d * scale
        max_receive = price_n * scale
        add(
            f"exact_equality_{index}_exact",
            price_n,
            price_d,
            max_send,
            max_receive,
        )
        if max_receive > 0:
            add(
                f"exact_equality_{index}_receive_below",
                price_n,
                price_d,
                max_send,
                max_receive - 1,
            )
        if max_receive < INT64_MAX:
            add(
                f"exact_equality_{index}_receive_above",
                price_n,
                price_d,
                max_send,
                max_receive + 1,
            )

    price_boundaries = [0, 1, 2, INT32_MAX - 1, INT32_MAX]
    amount_boundaries = [0, 1, 2, INT64_MAX - 1, INT64_MAX]
    for pn_index, price_n in enumerate(price_boundaries):
        for pd_index, price_d in enumerate(price_boundaries):
            for send_index, max_send in enumerate(amount_boundaries):
                for receive_index, max_receive in enumerate(amount_boundaries):
                    add(
                        f"exact_boundary_pn{pn_index}_pd{pd_index}"
                        f"_send{send_index}_recv{receive_index}",
                        price_n,
                        price_d,
                        max_send,
                        max_receive,
                    )

    rng = random.Random(seed ^ 0x0FFE2CAB)
    for index in range(random_count):
        pattern = index % 6
        if pattern == 0:
            price_n = rng.choice(price_boundaries)
            price_d = rng.choice(price_boundaries)
            max_send = rng.choice(amount_boundaries)
            max_receive = rng.choice(amount_boundaries)
        elif pattern == 1:
            price_n = rng.randrange(0, 1_001)
            price_d = rng.randrange(0, 1_001)
            max_send = rng.randrange(0, 1_001)
            max_receive = rng.randrange(0, 1_001)
        elif pattern == 2:
            # Small denominators maximize the relative effect of the
            # priceD - 1 addend.
            price_n = rng.randrange(1, 1_000_001)
            price_d = rng.randrange(0, 3)
            max_send = rng.randrange(0, 10**12 + 1)
            max_receive = rng.randrange(0, 10**12 + 1)
        elif pattern == 3:
            # Receive caps at or near INT64_MAX exercise the clamp boundary.
            price_n = rng.randrange(1, INT32_MAX + 1)
            price_d = rng.randrange(1, INT32_MAX + 1)
            max_send = rng.randrange(0, 10**12 + 1)
            max_receive = INT64_MAX - rng.randrange(16)
        elif pattern == 4:
            price_n = rng.randrange(1, INT32_MAX + 1)
            price_d = rng.randrange(1, INT32_MAX + 1)
            max_send = rng.randrange(0, 10**12 + 1)
            max_receive = rng.randrange(0, 10**12 + 1)
        else:
            price_n = rng.randrange(INT32_MIN, INT32_MAX + 1)
            price_d = rng.randrange(INT32_MIN, INT32_MAX + 1)
            max_send = rng.randrange(INT64_MIN, INT64_MAX + 1)
            max_receive = rng.randrange(INT64_MIN, INT64_MAX + 1)
        add(
            f"exact_random_{index:05d}",
            price_n,
            price_d,
            max_send,
            max_receive,
        )

    return cases


def generate_adjust_offer_cases(
    seed: int, random_count: int
) -> list[AdjustOfferCase]:
    cases: list[AdjustOfferCase] = []
    case_ids: set[str] = set()

    # As with the exchange-level tags, every input is emitted once per
    # exactReceiveCap value as an `_x0`/`_x1` pair differing only in the
    # flag.
    def add(
        case_id: str,
        price_n: int,
        price_d: int,
        max_wheat_send: int,
        max_sheep_receive: int,
    ) -> None:
        for ledger_version in (LEGACY_LEDGER_VERSION, REPAIRED_LEDGER_VERSION):
            paired_id = f"{case_id}_v{ledger_version}"
            if paired_id in case_ids:
                raise ValueError(f"duplicate case_id: {paired_id}")
            case_ids.add(paired_id)
            cases.append(
                AdjustOfferCase(
                    paired_id,
                    price_n,
                    price_d,
                    max_wheat_send,
                    max_sheep_receive,
                    ledger_version,
                )
            )

    # The named regressions replay TEST_CASE("Adjust Offer") from
    # src/transactions/test/ExchangeTests.cpp.
    add("adjust_limits_low_price_above", 1, 1000, 2001, INT64_MAX)
    add("adjust_limits_low_price_exact", 1, 1000, 2000, INT64_MAX)
    add("adjust_limits_low_price_below", 1, 1000, 1999, INT64_MAX)
    add("adjust_limits_low_price_recv3", 1, 1000, 2000, 3)
    add("adjust_limits_low_price_recv2", 1, 1000, 2000, 2)
    add("adjust_limits_low_price_recv1", 1, 1000, 2000, 1)
    add("adjust_limits_high_price_above", 1000, 1, 401, INT64_MAX)
    add("adjust_limits_high_price_exact", 1000, 1, 400, INT64_MAX)
    add("adjust_limits_high_price_below", 1000, 1, 399, INT64_MAX)
    add("adjust_limits_high_price_recv_above", 1000, 1, 400, 400_001)
    add("adjust_limits_high_price_recv_exact", 1000, 1, 400, 400_000)
    add("adjust_limits_high_price_recv_below", 1000, 1, 400, 399_999)
    add("adjust_idempotent_wheat_more", 7, 3, 1000, INT64_MAX)
    add("adjust_idempotent_sheep_more", 3, 7, 1000, INT64_MAX)
    add("adjust_idempotent_sheep_more_again", 3, 7, 999, INT64_MAX)
    for amount in (26, 27, 28, 29, 50, 51):
        add(f"adjust_threshold_{amount}", 3, 2, amount, INT64_MAX)

    # The steep-price witnesses from TEST_CASE("Offer shrinks at minimum
    # trustline limit"): a receive cap of exactly the offer's own buying
    # liabilities floor(amount * n / d) shrinks the offer without the
    # exact-receive-cap fix and keeps it whole with it.
    steep_n, steep_d = INT32_MAX, 663
    for amount in (1, 2, 3, 17, 1000):
        liability = amount * steep_n // steep_d
        add(f"adjust_steep_{amount}_unlimited", steep_n, steep_d, amount,
            INT64_MAX)
        add(f"adjust_steep_{amount}_at_liability", steep_n, steep_d, amount,
            liability)
        add(f"adjust_steep_{amount}_below_liability", steep_n, steep_d,
            amount, liability - 1)
        add(f"adjust_steep_{amount}_above_liability", steep_n, steep_d,
            amount, liability + 1)

    add("adjust_zero_amount", 3, 2, 0, INT64_MAX)
    add("adjust_zero_receive", 3, 2, 100, 0)
    add("adjust_both_int64_max", 3, 2, INT64_MAX, INT64_MAX)
    add("adjust_priced_zero_landmine", 5, 0, 10, 10)
    add("adjust_price_n_zero", 0, 5, 10, 10)
    add("adjust_negative_price_n", -1, 2, 10, 10)
    add("adjust_negative_price_d", 3, -1, 10, 10)
    add("adjust_negative_amount", 3, 2, -1, 10)
    add("adjust_negative_receive", 3, 2, 10, -1)
    add("adjust_int64_min_amount", 3, 2, INT64_MIN, 10)

    # The 1% threshold and both rounding branches are densest at small
    # numbers: sweep small prices against small amounts and a small set of
    # receive caps, exhaustively.
    receive_caps = tuple(range(9)) + (INT64_MAX,)
    for price_n in range(1, 4):
        for price_d in range(1, 4):
            for amount in range(64):
                for cap_index, cap in enumerate(receive_caps):
                    add(
                        f"adjust_small_pn{price_n}_pd{price_d}"
                        f"_a{amount}_c{cap_index}",
                        price_n,
                        price_d,
                        amount,
                        cap,
                    )

    rng = random.Random(seed ^ 0xAD005FE2)
    for index in range(random_count):
        pattern = index % 7
        if pattern == 0:
            # Unlimited counterparty at moderate prices.
            price_n = rng.randrange(1, 1_000_001)
            price_d = rng.randrange(1, 1_000_001)
            max_wheat_send = rng.randrange(0, 10**12 + 1)
            max_sheep_receive = INT64_MAX
        elif pattern == 1:
            # A receive cap at the offer's own buying liabilities, the
            # region the exact-receive-cap fix changes.
            price_n = rng.randrange(1, INT32_MAX + 1)
            price_d = rng.randrange(1, INT32_MAX + 1)
            max_wheat_send = rng.randrange(1, 10**12 + 1)
            liability = max_wheat_send * price_n // price_d
            max_sheep_receive = min(
                INT64_MAX, max(0, liability + rng.choice((-1, 0, 1)))
            )
        elif pattern == 2:
            price_n = INT32_MAX - rng.randrange(8)
            price_d = rng.randrange(1, 1_001)
            max_wheat_send = rng.randrange(0, 10**6 + 1)
            max_sheep_receive = rng.randrange(0, 10**15 + 1)
        elif pattern == 3:
            price_n = rng.randrange(1, INT32_MAX + 1)
            price_d = rng.randrange(1, INT32_MAX + 1)
            max_wheat_send = INT64_MAX - rng.randrange(16)
            max_sheep_receive = INT64_MAX - rng.randrange(16)
        elif pattern == 4:
            price_n = rng.randrange(1, 1_000_001)
            price_d = rng.randrange(1, 1_000_001)
            amounts = [rng.randrange(0, 10**9 + 1) for _ in range(2)]
            amounts[rng.randrange(2)] = 0
            max_wheat_send, max_sheep_receive = amounts
        elif pattern == 5:
            price_n = rng.choice((INT32_MIN, -1, 0, 1))
            price_d = rng.choice((INT32_MIN, -1, 0, 1))
            max_wheat_send = rng.randrange(-4, 10**6 + 1)
            max_sheep_receive = rng.randrange(-4, 10**6 + 1)
        else:
            price_n = rng.randrange(INT32_MIN, INT32_MAX + 1)
            price_d = rng.randrange(INT32_MIN, INT32_MAX + 1)
            max_wheat_send = rng.randrange(INT64_MIN, INT64_MAX + 1)
            max_sheep_receive = rng.randrange(INT64_MIN, INT64_MAX + 1)
        add(
            f"adjust_random_{index:05d}",
            price_n,
            price_d,
            max_wheat_send,
            max_sheep_receive,
        )

    return cases


def generate_adjustment_price_amount_cases(
    seed: int, random_count: int
) -> list[AdjustmentPriceAmountCase]:
    # The overlay-admission filter (offerCanClearForZero) is not modeled, so
    # there are no request-level overlay tags.
    tags = (
        "offer_selling_liabilities",
        "offer_buying_liabilities",
    )
    cases: list[AdjustmentPriceAmountCase] = []
    case_ids: set[str] = set()

    # Both projections have the same price-and-amount transport shape. Feed
    # them the same inputs so any disagreement is attributable to the modeled
    # operation rather than to different corpus coverage, and emit each at both
    # protocol versions so the proved version-independence is also tested.
    def add(case_id: str, price_n: int, price_d: int, amount: int) -> None:
        for tag in tags:
            for ledger_version in (
                LEGACY_LEDGER_VERSION,
                REPAIRED_LEDGER_VERSION,
            ):
                tagged_id = f"{tag}_{case_id}_v{ledger_version}"
                if tagged_id in case_ids:
                    raise ValueError(f"duplicate case_id: {tagged_id}")
                case_ids.add(tagged_id)
                cases.append(
                    AdjustmentPriceAmountCase(
                        tag, tagged_id, price_n, price_d, amount,
                        ledger_version
                    )
                )

    # Regression and adjacency cases from the focused C++ pre-pre-flight
    # tests, plus the offer-only filter's documented examples.
    add("unit", 1, 1, 1)
    add("reservation_anomaly", 101, 100, 1)
    add("reservation_anomaly_next", 101, 100, 2)
    add("raw_sell_anomaly", 101, 100, 3)
    add("fractional_bad", 5, 3, 20)
    add("fractional_bad_next", 5, 3, 21)
    add("raw_buy_anomaly", 100, 101, 3)
    add("raw_buy_anomaly_next", 100, 101, 4)
    add("low_price_unit", 1, 2, 1)
    add("steep_saturated", INT32_MAX, 1, INT64_MAX)
    add("near_unit_max", INT32_MAX, INT32_MAX - 1, INT64_MAX)
    add("zero_price_n", 0, 1, 1)
    add("zero_price_d", 1, 0, 1)
    add("negative_price_n", -1, 1, 1)
    add("negative_price_d", 1, -1, 1)
    add("zero_amount", 1, 1, 0)
    add("negative_amount", 1, 1, -1)
    add("minimum_amount", 1, 1, INT64_MIN)

    # Small amounts contain every zero-clear witness (the bad predicate is
    # bounded by 100) and densely cover both price-ordering branches.
    for price_n in range(9):
        for price_d in range(9):
            for amount in range(102):
                add(
                    f"small_pn{price_n}_pd{price_d}_a{amount}",
                    price_n,
                    price_d,
                    amount,
                )

    price_boundaries = (
        INT32_MIN,
        -1,
        0,
        1,
        2,
        INT32_MAX - 1,
        INT32_MAX,
    )
    amount_boundaries = (
        INT64_MIN,
        -1,
        0,
        1,
        2,
        99,
        100,
        101,
        INT64_MAX - 1,
        INT64_MAX,
    )
    for pn_index, price_n in enumerate(price_boundaries):
        for pd_index, price_d in enumerate(price_boundaries):
            for amount_index, amount in enumerate(amount_boundaries):
                add(
                    f"boundary_pn{pn_index}_pd{pd_index}_a{amount_index}",
                    price_n,
                    price_d,
                    amount,
                )

    rng = random.Random(seed ^ 0xAD1F57AB)
    for index in range(random_count):
        pattern = index % 7
        if pattern == 0:
            price_n = rng.randrange(1, 1_001)
            price_d = rng.randrange(1, 1_001)
            amount = rng.randrange(1, 1_001)
        elif pattern == 1:
            # Bias toward the zero-clear boundary and its adjacent amount.
            price_d = rng.randrange(1, 10_001)
            price_n = price_d + rng.randrange(1, 101)
            amount = rng.randrange(1, 102)
        elif pattern == 2:
            price_n = INT32_MAX - rng.randrange(16)
            price_d = rng.randrange(1, 1_001)
            amount = INT64_MAX - rng.randrange(32)
        elif pattern == 3:
            price_n = rng.choice(price_boundaries)
            price_d = rng.choice(price_boundaries)
            amount = rng.choice(amount_boundaries)
        elif pattern == 4:
            price_n = rng.randrange(1, INT32_MAX + 1)
            price_d = rng.randrange(1, INT32_MAX + 1)
            amount = rng.randrange(1, INT64_MAX + 1)
        elif pattern == 5:
            price_n = rng.randrange(1, 17)
            price_d = rng.randrange(1, 17)
            amount = rng.randrange(0, 10**12 + 1)
        else:
            price_n = rng.randrange(INT32_MIN, INT32_MAX + 1)
            price_d = rng.randrange(INT32_MIN, INT32_MAX + 1)
            amount = rng.randrange(INT64_MIN, INT64_MAX + 1)
        add(f"random_{index:05d}", price_n, price_d, amount)

    return cases


def generate_offer_lifecycle_cases(seed: int) -> list[OfferLifecycleCase]:
    """Generate isolated, reachable lifecycle states at protocols 28 and 29.

    Positive-price liability estimates mirror the operation-level caps only
    to choose useful reachable balances.  The expected outcomes themselves
    always come from the extracted Isabelle lifecycle and the production C++
    transaction path.
    """

    cases: list[OfferLifecycleCase] = []
    case_ids: set[str] = set()

    def request_liabilities(
        is_buy: bool, price_n: int, price_d: int, amount: int
    ) -> tuple[int, int]:
        if price_n <= 0 or price_d <= 0 or amount <= 0:
            return (0, 0)
        if not is_buy:
            selling = amount
            buying = (amount * price_n + price_d - 1) // price_d
            return (min(INT64_MAX, selling), min(INT64_MAX, buying))

        wheat_value = min(INT64_MAX * price_d, amount * price_n)
        if price_d > price_n:
            selling = wheat_value // price_d
            buying = selling * price_d // price_n
        else:
            buying = wheat_value // price_n
            selling = (buying * price_n + price_d - 1) // price_d
        return (min(INT64_MAX, selling), min(INT64_MAX, buying))

    def add(
        is_buy: bool,
        name: str,
        price_n: int,
        price_d: int,
        amount: int,
        maker_sell_balance: int,
        maker_sell_liabilities: int,
        maker_buy_limit: int,
        maker_buy_balance: int,
        maker_buy_liabilities: int,
        new_buy_limit: int,
    ) -> None:
        tag = "offer_lifecycle_buy" if is_buy else "offer_lifecycle_sell"
        values = (
            amount,
            maker_sell_balance,
            maker_sell_liabilities,
            maker_buy_limit,
            maker_buy_balance,
            maker_buy_liabilities,
            new_buy_limit,
        )
        # Lifecycle rows run real transactions, so they need a ledger at the
        # row's protocol. Each case is generated at protocols 28 and 29, one
        # row after the other, and the C++ oracle runs one long-lived ledger
        # per protocol and picks it from the row's ledger_version.
        for ledger_version in LIFECYCLE_LEDGER_VERSIONS:
            case_id = f"{tag}_{name}_v{ledger_version}"
            if case_id in case_ids:
                raise ValueError(f"duplicate case_id: {case_id}")
            if any(value < 0 or value > INT64_MAX for value in values):
                raise ValueError(f"unreachable lifecycle state in {case_id}")
            case_ids.add(case_id)
            cases.append(
                OfferLifecycleCase(
                    tag,
                    case_id,
                    price_n,
                    price_d,
                    ledger_version,
                    amount,
                    maker_sell_balance,
                    maker_sell_liabilities,
                    maker_buy_limit,
                    maker_buy_balance,
                    maker_buy_liabilities,
                    new_buy_limit,
                )
            )

    def add_mode(
        is_buy: bool,
        name: str,
        price_n: int,
        price_d: int,
        amount: int,
        mode: str,
        pre_sell: int = 0,
        pre_buy: int = 0,
        buy_balance: int = 0,
    ) -> None:
        selling, buying = request_liabilities(
            is_buy, price_n, price_d, amount
        )
        available_sell = selling
        available_buy = buying
        if mode == "underfunded":
            available_sell = max(0, selling - 1)
        elif mode == "line_full":
            available_buy = max(0, buying - 1)

        maker_sell_balance = min(INT64_MAX, pre_sell + available_sell)
        # A credit-asset selling trustline may have a zero balance, but the
        # production operation rejects it as underfunded before reaching a
        # mathematically zero selling-liability/no-offer case.  Give precisely
        # those zero-liability fixtures one unit so the requested later stage
        # is reachable.
        if selling == 0 and maker_sell_balance == 0:
            maker_sell_balance = 1
        maker_buy_limit = min(
            INT64_MAX, buy_balance + pre_buy + available_buy
        )
        # A limit-zero credit trustline does not exist.  Retain zero available
        # capacity for an explicit line-full fixture by filling a unit line;
        # otherwise create the smallest positive empty line, which lets a
        # zero-liability request reach the ordinary no-offer adjustment.
        if maker_buy_limit == 0:
            if mode == "line_full":
                buy_balance = 1
            maker_buy_limit = 1
        minimum_new_limit = min(
            INT64_MAX, max(1, buy_balance + pre_buy + buying)
        )
        if mode == "invalid_limit":
            new_buy_limit = max(0, minimum_new_limit - 1)
        elif mode == "one_above":
            new_buy_limit = min(INT64_MAX, minimum_new_limit + 1)
        elif mode == "headroom":
            new_buy_limit = min(INT64_MAX, minimum_new_limit + 1000)
        else:
            new_buy_limit = minimum_new_limit
        add(
            is_buy,
            name,
            price_n,
            price_d,
            amount,
            maker_sell_balance,
            min(pre_sell, maker_sell_balance),
            maker_buy_limit,
            buy_balance,
            min(pre_buy, max(0, maker_buy_limit - buy_balance)),
            new_buy_limit,
        )

    # Named regressions and adjacent requests.  The two clear-for-zero
    # states are the ones stellar-core's overlay filter refuses before
    # protocol 29; the model does not filter, so here they exercise posting.
    add_mode(False, "clear_for_zero_101_100_a2", 101, 100, 2, "headroom")
    add_mode(True, "clear_for_zero_100_101_a3", 100, 101, 3, "headroom")
    add_mode(False, "adjacent_accept_101_100_a3", 101, 100, 3, "minimum")
    add_mode(True, "adjacent_accept_100_101_a4", 100, 101, 4, "minimum")

    for is_buy in (False, True):
        operation = "buy" if is_buy else "sell"
        for mode in (
            "minimum",
            "one_above",
            "headroom",
            "underfunded",
            "line_full",
            "invalid_limit",
        ):
            add_mode(is_buy, f"{operation}_unit_{mode}", 1, 1, 4, mode)
        add_mode(
            is_buy,
            f"{operation}_preexisting_liabilities",
            3,
            2,
            7,
            "minimum",
            pre_sell=2,
            pre_buy=3,
            buy_balance=1,
        )
        # A zero buying-liability edge reaches the ordinary no-offer branch
        # from a positive raw request.
        add_mode(
            is_buy,
            f"{operation}_zero_value_edge",
            1,
            INT32_MAX,
            1,
            "minimum",
        )
        add_mode(
            is_buy,
            f"{operation}_int32_boundary",
            INT32_MAX,
            INT32_MAX - 1,
            1000,
            "headroom",
        )

    prices = (
        (1, 1),
        (2, 1),
        (1, 2),
        (101, 100),
        (100, 101),
        (5, 3),
        (3, 5),
        (INT32_MAX, INT32_MAX - 1),
    )
    amounts = (1, 2, 3, 4, 20, 21, 99, 100, 101, 102, 1000)
    modes = (
        "minimum",
        "one_above",
        "headroom",
        "underfunded",
        "line_full",
        "invalid_limit",
    )
    rng = random.Random(seed ^ 0x1ECAC7E)
    for is_buy in (False, True):
        for index in range(LIFECYCLE_RANDOM_COUNT):
            price_n, price_d = prices[index % len(prices)]
            amount = amounts[(index // len(prices)) % len(amounts)]
            mode = modes[(index // (len(prices) * len(amounts))) % len(modes)]
            name = f"biased_{index:03d}"
            # Reserve the final deterministic row for the signed amount
            # saturation boundary required by the lifecycle corpus.  Reusing
            # a biased-row slot preserves exactly 211 records per direction.
            if index == LIFECYCLE_RANDOM_COUNT - 1:
                price_n, price_d = (1, 1)
                amount = INT64_MAX
                mode = "minimum"
                name = "int64_amount_boundary"
            preexisting = index % 17 == 0
            add_mode(
                is_buy,
                name,
                price_n,
                price_d,
                amount,
                mode,
                pre_sell=rng.randrange(1, 4) if preexisting else 0,
                pre_buy=rng.randrange(1, 4) if preexisting else 0,
                buy_balance=rng.randrange(0, 3) if preexisting else 0,
            )

    return cases


def generate_cases(seed: int, random_count: int) -> list[DifferentialCase]:
    cases: list[DifferentialCase] = []
    case_ids: set[str] = set()
    groups: list[list[DifferentialCase]] = [
        list(generate_offer_value_cases(seed, random_count)),
        list(
            generate_offer_amount_from_value_cases(seed, random_count)
        ),
        list(generate_big_multiply_cases(seed, random_count)),
        list(generate_price_error_bound_cases(seed, random_count)),
        list(generate_big_divide_cases(seed, random_count)),
        list(generate_big_divide128_cases(seed, random_count)),
        list(generate_big_multiply_unsigned_cases(seed, random_count)),
        list(generate_big_divide_unsigned_cases(seed, random_count)),
        list(generate_big_divide_nothrow_cases(seed, random_count)),
        list(generate_big_divide_unsigned128_cases(seed, random_count)),
        list(generate_big_divide128_nothrow_cases(seed, random_count)),
        list(generate_apply_price_error_thresholds_cases(seed, random_count)),
        list(
            generate_exchange_v10_without_price_error_thresholds_cases(
                seed, random_count
            )
        ),
        list(generate_exchange_v10_cases(seed, random_count)),
        list(generate_adjust_offer_cases(seed, random_count)),
        list(generate_adjustment_price_amount_cases(seed, random_count)),
        list(generate_offer_lifecycle_cases(seed)),
    ]
    for group in groups:
        for case in group:
            if case.case_id in case_ids:
                raise ValueError(f"duplicate case_id: {case.case_id}")
            case_ids.add(case.case_id)
            cases.append(case)
    return cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=DEFAULT_SEED)
    parser.add_argument(
        "--random-count", type=int, default=DEFAULT_RANDOM_COUNT
    )
    arguments = parser.parse_args()

    if arguments.random_count < 10_000:
        parser.error("--random-count must be at least 10000")

    cases = generate_cases(arguments.seed, arguments.random_count)
    tag_counts: dict[str, int] = {}
    for case in cases:
        tag = case.row().split("\t", 2)[1]
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
    header = [
        "# Isabelle/stellar-core exchangeV10-helper differential corpus",
        f"# seed={arguments.seed}",
        f"# random_count_per_tag={arguments.random_count}",
        f"# record_count={len(cases)}",
        *(f"# {tag}_count={count}" for tag, count in tag_counts.items()),
    ]
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        "\n".join(header + [case.row() for case in cases]) + "\n",
        encoding="ascii",
        newline="\n",
    )


if __name__ == "__main__":
    main()
