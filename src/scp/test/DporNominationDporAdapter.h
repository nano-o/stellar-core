// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
#include "scp/test/DporNominationSimulation.h"

#include <dpor/algo/program.hpp>
#include <dpor/model/event.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace stellar
{

struct DporNominationValue
{
    dpor::model::ThreadId mSenderThread{};
    dpor::model::ThreadId mDestinationThread{};
    uint64_t mSlotIndex{};
    SCPEnvelope mEnvelope;

    bool
    operator==(DporNominationValue const& other) const = default;
};

class DporNominationDporAdapter
{
  public:
    using EventLabel = dpor::model::EventLabelT<DporNominationValue>;
    using SendLabel = dpor::model::SendLabelT<DporNominationValue>;
    using ReceiveLabel = dpor::model::ReceiveLabelT<DporNominationValue>;
    using ObservedValue = dpor::model::ObservedValueT<DporNominationValue>;
    using ThreadTrace = dpor::algo::ThreadTraceT<DporNominationValue>;
    using Program = dpor::algo::ProgramT<DporNominationValue>;

    DporNominationDporAdapter(std::vector<SecretKey> const& validators,
                              SCPQuorumSet const& qSet, uint64_t slotIndex,
                              Value const& previousValue,
                              std::vector<Value> const& initialValues);

    std::size_t
    size() const;

    static dpor::model::ThreadId
    toThreadID(std::size_t nodeIndex);

    void setPriorityLookup(std::function<uint64(NodeID const&)> const& fn);

    void setValueHash(std::function<uint64(Value const&)> const& fn);

    void setCombineCandidates(
        std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const&
            fn);

    std::optional<EventLabel>
    captureNextEvent(std::size_t nodeIndex, ThreadTrace const& trace,
                     std::size_t step) const;

    Program
    makeProgram() const;

    std::optional<SCPEnvelope>
    getNominationBoundaryEnvelope(std::size_t nodeIndex,
                                  ThreadTrace const& trace) const;

  private:
    std::vector<SecretKey> mValidators;
    SCPQuorumSet mQSet;
    uint64_t mSlotIndex;
    Value mPreviousValue;
    std::vector<Value> mInitialValues;
    std::function<uint64(NodeID const&)> mPriorityLookup;
    std::function<uint64(Value const&)> mValueHash;
    std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)>
        mCombineCandidates;
};

}
