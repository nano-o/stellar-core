// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "scp/Slot.h"
#include "scp/test/DporScpNode.h"
#include "scp/test/ScpDporTypes.h"

#include <chrono>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <xdrpp/printer.h>

namespace stellar::scpdpor
{

inline dpor::model::ThreadId
threadIdForNodeIndex(std::size_t nodeIndex)
{
    if (nodeIndex > std::numeric_limits<dpor::model::ThreadId>::max())
    {
        throw std::out_of_range("node index does not fit in DPOR thread id");
    }
    return static_cast<dpor::model::ThreadId>(nodeIndex);
}

inline ScpDporValue
makeEnvelopeValue(uint64_t slotIndex, SCPEnvelope const& envelope)
{
    ScpDporValue value;
    value.mKind = ScpDporValue::Kind::Envelope;
    value.mSlotIndex = slotIndex;
    value.mEnvelope = envelope;
    return value;
}

inline ScpDporValue
makeTimerChoiceValue(uint64_t slotIndex, int timerID)
{
    ScpDporValue value;
    value.mKind = ScpDporValue::Kind::TimerChoice;
    value.mSlotIndex = slotIndex;
    value.mTimerID = timerID;
    return value;
}

inline ScpDporValue
makeTxSetDownloadWaitTimeChoiceValue(uint64_t slotIndex,
                                     std::chrono::milliseconds waitTime)
{
    ScpDporValue value;
    value.mKind = ScpDporValue::Kind::TxSetDownloadWaitTimeChoice;
    value.mSlotIndex = slotIndex;
    value.mDurationMilliseconds = waitTime.count();
    return value;
}

inline ScpDporValue
makeTxSetStatusChoiceValue(uint64_t slotIndex, DporScpTxSetStatus status)
{
    ScpDporValue value;
    value.mKind = ScpDporValue::Kind::TxSetStatusChoice;
    value.mSlotIndex = slotIndex;
    value.mTxSetStatus = static_cast<std::uint8_t>(status);
    return value;
}

inline bool
isEnvelopeValue(ScpDporValue const& value)
{
    return value.mKind == ScpDporValue::Kind::Envelope;
}

inline bool
isTimerChoiceValue(ScpDporValue const& value)
{
    return value.mKind == ScpDporValue::Kind::TimerChoice;
}

inline bool
isTxSetDownloadWaitTimeChoiceValue(ScpDporValue const& value)
{
    return value.mKind == ScpDporValue::Kind::TxSetDownloadWaitTimeChoice;
}

inline bool
isTxSetStatusChoiceValue(ScpDporValue const& value)
{
    return value.mKind == ScpDporValue::Kind::TxSetStatusChoice;
}

inline SCPEnvelope const&
decodeEnvelope(ScpDporValue const& value)
{
    if (!isEnvelopeValue(value))
    {
        throw std::logic_error("value does not encode an SCP envelope");
    }
    return value.mEnvelope;
}

inline int
decodeTimerChoice(ScpDporValue const& value)
{
    if (!isTimerChoiceValue(value))
    {
        throw std::logic_error("value does not encode a timer choice");
    }
    return value.mTimerID;
}

inline std::chrono::milliseconds
decodeTxSetDownloadWaitTimeChoice(ScpDporValue const& value)
{
    if (!isTxSetDownloadWaitTimeChoiceValue(value))
    {
        throw std::logic_error(
            "value does not encode a txset download wait time choice");
    }
    return std::chrono::milliseconds(value.mDurationMilliseconds);
}

inline DporScpTxSetStatus
decodeTxSetStatusChoice(ScpDporValue const& value)
{
    if (!isTxSetStatusChoiceValue(value))
    {
        throw std::logic_error("value does not encode a txset status choice");
    }

    switch (static_cast<DporScpTxSetStatus>(value.mTxSetStatus))
    {
    case DporScpTxSetStatus::Valid:
    case DporScpTxSetStatus::Downloading:
    case DporScpTxSetStatus::Invalid:
        return static_cast<DporScpTxSetStatus>(value.mTxSetStatus);
    }
    throw std::logic_error("value does not encode a supported txset status");
}

inline char const*
timerName(int timerID)
{
    switch (timerID)
    {
    case Slot::NOMINATION_TIMER:
        return "nomination";
    case Slot::BALLOT_PROTOCOL_TIMER:
        return "ballot";
    default:
        return "unknown";
    }
}

inline char const*
txSetStatusName(DporScpTxSetStatus status)
{
    switch (status)
    {
    case DporScpTxSetStatus::Valid:
        return "valid";
    case DporScpTxSetStatus::Downloading:
        return "downloading";
    case DporScpTxSetStatus::Invalid:
        return "invalid";
    }
    return "unknown";
}

inline std::ostream&
operator<<(std::ostream& out, ScpDporValue const& value)
{
    switch (value.mKind)
    {
    case ScpDporValue::Kind::Envelope:
        return out << "env(slot=" << value.mSlotIndex << ", "
                   << xdr::xdr_to_string(value.mEnvelope.statement, "statement")
                   << ")";
    case ScpDporValue::Kind::TimerChoice:
        return out << "timer(slot=" << value.mSlotIndex
                   << ", id=" << timerName(value.mTimerID) << ")";
    case ScpDporValue::Kind::TxSetDownloadWaitTimeChoice:
        return out << "txset-wait(slot=" << value.mSlotIndex
                   << ", ms=" << value.mDurationMilliseconds << ")";
    case ScpDporValue::Kind::TxSetStatusChoice:
        return out << "txset-status(slot=" << value.mSlotIndex << ", value="
                   << txSetStatusName(
                          static_cast<DporScpTxSetStatus>(value.mTxSetStatus))
                   << ")";
    }
    return out << "<unknown>";
}

} // namespace stellar::scpdpor
