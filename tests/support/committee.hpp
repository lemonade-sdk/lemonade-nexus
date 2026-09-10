#pragma once

// One epoch's committee at one population: real vote keys, real signatures,
// real three-chain commit proofs. Shared by the cross-population measurements
// and the authority-chain tests, which build several of these in sequence.

#include <LemonadeNexus/Security/Consensus/CommitProof.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>

#include <cstdint>
#include <map>
#include <vector>

namespace committee_test {

using namespace nexus::security;
namespace constants = nexus::security::constants;

struct Committee {
    /// `seed` offsets the node identities, so two committees can share or
    /// disjoin membership as a test chooses. Vote keys are always fresh per
    /// construction, which is the per-epoch key rule.
    Committee(std::size_t size, EpochId epoch, NetworkId network, uint8_t seed = 1)
        : epoch(epoch), network(network) {
        for (std::size_t i = 0; i < size; ++i) {
            NodeId id;
            id.bytes.fill(static_cast<uint8_t>(seed + i));
            members.push_back(id);
            keys[id] = make_epoch_vote_key(epoch, id);
            pubs[id] = keys[id].public_key;
        }
        quorum = constants::consensus_quorum(size);
    }

    [[nodiscard]] QuorumCertificate certify(const Proposal& proposal) const {
        const Digest digest = proposal_digest(proposal);
        QuorumCertificate qc{};
        qc.qc_format_version = constants::kQcFormatVersion;
        qc.consensus_ruleset = constants::kConsensusRulesetVersion;
        qc.network_id = network;
        qc.epoch = epoch;
        qc.height = proposal.height;
        qc.view = proposal.view;
        qc.proposal_digest = digest;
        // Exactly the quorum signs, so the proof carries no slack an attacker
        // could trim from.
        std::size_t signed_count = 0;
        for (const auto& node : members) {
            if (signed_count == quorum) break;
            Vote vote{};
            vote.consensus_ruleset = constants::kConsensusRulesetVersion;
            vote.network_id = network;
            vote.epoch = epoch;
            vote.height = proposal.height;
            vote.view = proposal.view;
            vote.proposal_digest = digest;
            vote.voter = node;
            const auto signing = vote_signing_digest(vote);
            crypto_sign_detached(vote.signature.data(), nullptr, signing.data(),
                                 signing.size(), keys.at(node).private_key.data());
            qc.signers.push_back({node, vote.signature});
            ++signed_count;
        }
        return qc;
    }

    /// A real three-chain proof over a block carrying `transitions`.
    [[nodiscard]] CommitProof prove(const Digest& transitions, Height base = 20) const {
        CommitProof proof;
        Digest parent{};
        QuorumCertificate justify{};
        justify.qc_format_version = constants::kQcFormatVersion;
        justify.consensus_ruleset = constants::kConsensusRulesetVersion;
        justify.network_id = network;
        justify.epoch = epoch;
        for (uint8_t i = 0; i < 3; ++i) {
            Proposal proposal{};
            proposal.security_ruleset = constants::kSecurityRulesetVersion;
            proposal.consensus_ruleset = constants::kConsensusRulesetVersion;
            proposal.network_id = network;
            proposal.epoch = epoch;
            proposal.height = base + i;
            proposal.view = base + i;
            proposal.leader = members.front();
            proposal.parent_digest = parent;
            proposal.transitions_digest = i == 0 ? transitions : Digest{};
            proof.chain.push_back({proposal, justify});
            parent = proposal_digest(proposal);
            justify = certify(proposal);
        }
        proof.certifying = justify;
        return proof;
    }

    EpochId epoch{};
    NetworkId network{};
    std::vector<NodeId> members;
    std::map<NodeId, EpochVoteKey> keys;
    std::map<NodeId, nexus::crypto::Ed25519PublicKey> pubs;
    std::size_t quorum{};
};

}  // namespace committee_test
