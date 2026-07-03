// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "scp/SCPDriver.h"

#include <dpor/algo/dpor.hpp>
#include <dpor/algo/program.hpp>
#include <dpor/model/event.hpp>
#include <dpor/model/exploration_graph.hpp>
#include <dpor/model/format.hpp>

#include <cstdint>
#include <functional>
#include <xdrpp/marshal.h>

namespace stellar::scpdpor
{

struct ScpDporValue
{
    enum class Kind : std::uint8_t
    {
        EnvelopeDelivery = 0,
        TimerChoice = 1,
        TxSetDownloadWaitTimeChoice = 2,
        TxSetStatusChoice = 3
    };

    Kind mKind{Kind::EnvelopeDelivery};
    uint64_t mSlotIndex{};
    SCPEnvelope mEnvelope{};
    int mTimerID{};
    int64_t mDurationMilliseconds{};
    std::uint8_t mTxSetStatus{};

    bool
    operator==(ScpDporValue const& other) const
    {
        if (mKind != other.mKind || mSlotIndex != other.mSlotIndex)
        {
            return false;
        }

        switch (mKind)
        {
        case Kind::EnvelopeDelivery:
            return mEnvelope == other.mEnvelope;
        case Kind::TimerChoice:
            return mTimerID == other.mTimerID;
        case Kind::TxSetDownloadWaitTimeChoice:
            return mDurationMilliseconds == other.mDurationMilliseconds;
        case Kind::TxSetStatusChoice:
            return mTxSetStatus == other.mTxSetStatus;
        }
        return false;
    }

    bool
    operator<(ScpDporValue const& other) const
    {
        if (mKind != other.mKind)
        {
            return mKind < other.mKind;
        }
        if (mSlotIndex != other.mSlotIndex)
        {
            return mSlotIndex < other.mSlotIndex;
        }

        switch (mKind)
        {
        case Kind::EnvelopeDelivery:
            return mEnvelope < other.mEnvelope;
        case Kind::TimerChoice:
            return mTimerID < other.mTimerID;
        case Kind::TxSetDownloadWaitTimeChoice:
            return mDurationMilliseconds < other.mDurationMilliseconds;
        case Kind::TxSetStatusChoice:
            return mTxSetStatus < other.mTxSetStatus;
        }
        return false;
    }
};

using EventLabel = dpor::model::EventLabelT<ScpDporValue>;
using SendLabel = dpor::model::SendLabelT<ScpDporValue>;
using ReceiveLabel = dpor::model::ReceiveLabelT<ScpDporValue>;
using NondeterministicChoiceLabel =
    dpor::model::NondeterministicChoiceLabelT<ScpDporValue>;
using ObservedValue = dpor::model::ObservedValueT<ScpDporValue>;
using ExplorationGraph = dpor::model::ExplorationGraphT<ScpDporValue>;
using ThreadTrace = dpor::algo::ThreadTraceT<ScpDporValue>;
using ThreadFunction = dpor::algo::ThreadFunctionT<ScpDporValue>;
using Program = dpor::algo::ProgramT<ScpDporValue>;

} // namespace stellar::scpdpor

namespace std
{

template <>
struct hash<stellar::scpdpor::ScpDporValue>
{
    // Not noexcept: hashing envelopes serializes them via xdr_to_opaque,
    // which allocates.
    std::size_t
    operator()(stellar::scpdpor::ScpDporValue const& value) const
    {
        std::size_t result =
            std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(value.mKind));
        result ^= std::hash<uint64_t>{}(value.mSlotIndex) + 0x9e3779b9 +
                  (result << 6) + (result >> 2);

        switch (value.mKind)
        {
        case stellar::scpdpor::ScpDporValue::Kind::EnvelopeDelivery:
        {
            auto const opaque = xdr::xdr_to_opaque(value.mEnvelope);
            for (auto const byte : opaque)
            {
                result ^= std::hash<std::uint8_t>{}(byte) + 0x9e3779b9 +
                          (result << 6) + (result >> 2);
            }
            break;
        }
        case stellar::scpdpor::ScpDporValue::Kind::TimerChoice:
            result ^= std::hash<int>{}(value.mTimerID) + 0x9e3779b9 +
                      (result << 6) + (result >> 2);
            break;
        case stellar::scpdpor::ScpDporValue::Kind::TxSetDownloadWaitTimeChoice:
            result ^= std::hash<int64_t>{}(value.mDurationMilliseconds) +
                      0x9e3779b9 + (result << 6) + (result >> 2);
            break;
        case stellar::scpdpor::ScpDporValue::Kind::TxSetStatusChoice:
            result ^= std::hash<std::uint8_t>{}(value.mTxSetStatus) +
                      0x9e3779b9 + (result << 6) + (result >> 2);
            break;
        }
        return result;
    }
};

} // namespace std
