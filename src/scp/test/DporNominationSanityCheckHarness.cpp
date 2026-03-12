// Copyright 2024 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "scp/test/DporNominationSanityCheckHarness.h"

#include "crypto/SHA.h"

#include <deque>
#include <stdexcept>

namespace stellar
{

DporNominationSanityCheckHarness::DporNominationSanityCheckHarness(
    std::vector<SecretKey> const& validators, SCPQuorumSet const& qSet,
    DporNominationNode::Configuration const& config)
{
    if (validators.empty())
    {
        throw std::invalid_argument("validators must not be empty");
    }

    mNodes.reserve(validators.size());
    for (auto const& validator : validators)
    {
        mNodes.emplace_back(
            std::make_unique<DporNominationNode>(validator, qSet, config));
    }
}

std::vector<SecretKey>
DporNominationSanityCheckHarness::makeValidatorSecretKeys(
    std::string const& seedPrefix, std::size_t count)
{
    std::vector<SecretKey> validators;
    validators.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
    {
        validators.emplace_back(
            SecretKey::fromSeed(sha256(seedPrefix + std::to_string(i))));
    }
    return validators;
}

std::vector<NodeID>
DporNominationSanityCheckHarness::getNodeIDs(
    std::vector<SecretKey> const& validators)
{
    std::vector<NodeID> nodeIDs;
    nodeIDs.reserve(validators.size());
    for (auto const& validator : validators)
    {
        nodeIDs.push_back(validator.getPublicKey());
    }
    return nodeIDs;
}

SCPQuorumSet
DporNominationSanityCheckHarness::makeQuorumSet(
    std::vector<NodeID> const& nodeIDs, uint32_t threshold)
{
    SCPQuorumSet qSet;
    qSet.threshold = threshold;
    for (auto const& nodeID : nodeIDs)
    {
        qSet.validators.push_back(nodeID);
    }
    return qSet;
}

std::size_t
DporNominationSanityCheckHarness::size() const
{
    return mNodes.size();
}

DporNominationNode&
DporNominationSanityCheckHarness::getNode(std::size_t index)
{
    return *mNodes.at(index);
}

DporNominationNode const&
DporNominationSanityCheckHarness::getNode(std::size_t index) const
{
    return *mNodes.at(index);
}

void
DporNominationSanityCheckHarness::setPriorityLookup(
    std::function<uint64(NodeID const&)> const& fn)
{
    for (auto& node : mNodes)
    {
        node->setPriorityLookup(fn);
    }
}

void
DporNominationSanityCheckHarness::setValueHash(
    std::function<uint64(Value const&)> const& fn)
{
    for (auto& node : mNodes)
    {
        node->setValueHash(fn);
    }
}

void
DporNominationSanityCheckHarness::setCombineCandidates(
    std::function<ValueWrapperPtr(uint64, ValueWrapperPtrSet const&)> const& fn)
{
    for (auto& node : mNodes)
    {
        node->setCombineCandidates(fn);
    }
}

void
DporNominationSanityCheckHarness::applyConfiguration(
    DporNominationNode::Configuration const& config)
{
    for (auto& node : mNodes)
    {
        node->applyConfiguration(config);
    }
}

std::size_t
DporNominationSanityCheckHarness::broadcastPendingEnvelopesOnce()
{
    using Delivery = std::pair<std::size_t, SCPEnvelope>;

    std::deque<Delivery> pending;
    for (std::size_t sender = 0; sender < mNodes.size(); ++sender)
    {
        for (auto& envelope : mNodes[sender]->takePendingEnvelopes())
        {
            pending.emplace_back(sender, envelope);
        }
    }

    std::size_t deliveries = 0;
    while (!pending.empty())
    {
        auto [sender, envelope] = pending.front();
        pending.pop_front();

        for (std::size_t receiver = 0; receiver < mNodes.size(); ++receiver)
        {
            if (receiver == sender)
            {
                continue;
            }
            mNodes[receiver]->receiveEnvelope(envelope);
            ++deliveries;
        }
    }

    return deliveries;
}

}
