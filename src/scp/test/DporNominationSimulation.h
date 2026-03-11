// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "crypto/SecretKey.h"
#include "scp/test/DporNominationNode.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace stellar
{

// Concrete in-memory nomination harness built from live DporNominationNode
// instances. Tests use this to execute real SCP behavior, deliver envelopes in
// controlled rounds, and capture traces or boundary envelopes. This is not the
// DPOR interface; it is a sanity-check helper layered on top of the reusable
// DporNominationNode driver.
class DporNominationSimulation
{
  public:
    explicit DporNominationSimulation(std::vector<SecretKey> const& validators,
                                      SCPQuorumSet const& qSet);

    static std::vector<SecretKey>
    makeValidatorSecretKeys(std::string const& seedPrefix, std::size_t count);

    static std::vector<NodeID>
    getNodeIDs(std::vector<SecretKey> const& validators);

    static SCPQuorumSet makeQuorumSet(std::vector<NodeID> const& nodeIDs,
                                      uint32_t threshold);

    std::size_t
    size() const;

    DporNominationNode&
    getNode(std::size_t index);

    DporNominationNode const&
    getNode(std::size_t index) const;

    void setPriorityLookup(std::function<uint64(NodeID const&)> const& fn);

    void setValueHash(std::function<uint64(Value const&)> const& fn);

    void setCombineCandidates(
        std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const&
            fn);

    std::size_t broadcastPendingEnvelopesOnce();

  private:
    std::vector<std::unique_ptr<DporNominationNode>> mNodes;
};

}
