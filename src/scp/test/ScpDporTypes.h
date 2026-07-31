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
#include <memory>
#include <utility>
#include <xdrpp/marshal.h>

namespace stellar::scpdpor
{

// Envelopes are the payload of almost every DPOR value, and DPOR copies values
// constantly: every graph restriction, rf-rewrite and thread-trace
// materialization deep-copies each event label. An SCPEnvelope holds several
// heap-allocated XDR vectors, so storing it by value made those copies the
// single largest cost in exploration. Values therefore share one immutable
// envelope instance and copy only a refcount.
// FNV-1a over the envelope's XDR encoding. Equal envelopes always produce equal
// digests, which is what lets the digest short-circuit equality and back
// std::hash.
inline std::size_t
computeEnvelopeDigest(SCPEnvelope const& envelope)
{
    auto const opaque = xdr::xdr_to_opaque(envelope);
    std::size_t digest = 0xcbf29ce484222325ULL;
    for (auto const byte : opaque)
    {
        digest = (digest ^ byte) * 0x100000001b3ULL;
    }
    return digest;
}

struct ScpDporEnvelopePayload
{
    SCPEnvelope mEnvelope;
    // Content digest, computed once. Values that share a payload compare by
    // pointer, but re-deriving a node's state produces a fresh payload for an
    // envelope the exploration graph already holds, so equal-but-distinct
    // payloads do occur and were being compared field by field through the XDR
    // structure. The digest rejects unequal ones without that walk.
    std::size_t mDigest{0};

    explicit ScpDporEnvelopePayload(SCPEnvelope envelope)
        : mEnvelope(std::move(envelope)), mDigest(computeEnvelopeDigest(mEnvelope))
    {
    }
};

using ScpDporEnvelopePtr = std::shared_ptr<ScpDporEnvelopePayload const>;

struct ScpDporValue
{
    enum class Kind : std::uint8_t
    {
        Envelope = 0,
        TimerChoice = 1,
        TxSetDownloadWaitTimeChoice = 2,
        TxSetStatusChoice = 3
    };

    Kind mKind{Kind::Envelope};
    uint64_t mSlotIndex{};
    ScpDporEnvelopePtr mEnvelope;
    int mTimerID{};
    int64_t mDurationMilliseconds{};
    std::uint8_t mTxSetStatus{};

    // A value that carries no payload behaves exactly like one carrying a
    // default-constructed envelope, so equality and ordering keep the
    // semantics they had when the envelope was stored inline.
    SCPEnvelope const&
    envelope() const
    {
        static SCPEnvelope const emptyEnvelope{};
        return mEnvelope ? mEnvelope->mEnvelope : emptyEnvelope;
    }

    // A value with no payload compares equal to one carrying a
    // default-constructed envelope, so it must hash like one too: this returns
    // that envelope's digest rather than zero.
    std::size_t
    envelopeDigest() const
    {
        if (mEnvelope)
        {
            return mEnvelope->mDigest;
        }
        static std::size_t const emptyEnvelopeDigest =
            computeEnvelopeDigest(SCPEnvelope{});
        return emptyEnvelopeDigest;
    }

    bool
    operator==(ScpDporValue const& other) const
    {
        if (mKind != other.mKind || mSlotIndex != other.mSlotIndex)
        {
            return false;
        }

        switch (mKind)
        {
        case Kind::Envelope:
            if (mEnvelope == other.mEnvelope)
            {
                return true;
            }
            if (mEnvelope && other.mEnvelope &&
                mEnvelope->mDigest != other.mEnvelope->mDigest)
            {
                return false;
            }
            return envelope() == other.envelope();
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
        case Kind::Envelope:
            return mEnvelope != other.mEnvelope &&
                   envelope() < other.envelope();
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
    // Envelope payloads carry a precomputed content digest, so this never
    // serializes.
    std::size_t
    operator()(stellar::scpdpor::ScpDporValue const& value) const
    {
        std::size_t result =
            std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(value.mKind));
        result ^= std::hash<uint64_t>{}(value.mSlotIndex) + 0x9e3779b9 +
                  (result << 6) + (result >> 2);

        switch (value.mKind)
        {
        case stellar::scpdpor::ScpDporValue::Kind::Envelope:
            result ^= value.envelopeDigest() + 0x9e3779b9 + (result << 6) +
                      (result >> 2);
            break;
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
