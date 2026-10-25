#pragma once

// An authority chain whose members are real node identities: every member's
// NodeId is an Ed25519 public key whose private key the test holds, so the
// test can sign Tier 1 endpoint proofs as that member. Genesis signs Epoch 1;
// each later epoch is a finalized handoff with a real three-chain proof signed
// by the previous epoch's vote keys. Shared by the membership verifier tests
// and the SDK Tier 1 directory tests.

#include "support/committee.hpp"

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Epoch/AuthorityChain.hpp>
#include <LemonadeNexus/Security/Epoch/AuthorityChainPage.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Membership.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Transport/AuthorityChainCodec.hpp>

#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <variant>
#include <vector>

namespace tier1_chain_test {

using namespace nexus::security;
namespace constants = nexus::security::constants;
using nexus::crypto::Ed25519Keypair;
using nexus::crypto::Ed25519PublicKey;

inline Ed25519Keypair new_identity() {
    Ed25519Keypair kp{};
    crypto_sign_keypair(kp.public_key.data(), kp.private_key.data());
    return kp;
}

/// One epoch: a committee whose members are the given identities.
struct IdentityEpoch {
    committee_test::Committee committee;
    std::map<NodeId, Ed25519Keypair> identities;

    IdentityEpoch(EpochId epoch, NetworkId network, const std::vector<Ed25519Keypair>& members)
        : committee(0, epoch, network) {
        for (const auto& kp : members) {
            NodeId id;
            id.bytes = kp.public_key;
            committee.members.push_back(id);
            committee.keys[id] = make_epoch_vote_key(epoch, id);
            committee.pubs[id] = committee.keys[id].public_key;
            identities[id] = kp;
        }
        // Certificates list signers in node order, as consensus does.
        std::sort(committee.members.begin(), committee.members.end());
        committee.quorum = constants::consensus_quorum(members.size());
    }
};

struct Chain {
    Ed25519Keypair genesis{};
    NetworkId network{};
    BootstrapCertificate certificate;
    std::vector<std::pair<NodeId, Ed25519PublicKey>> founders;
    std::vector<IdentityEpoch> epochs;        // epochs[0] is Epoch 1
    std::vector<EpochHandoffProofMsg> links;  // links[i] hands epoch i+1 to i+2
    std::vector<VerifiedEpochAuthority> authorities;

    /// `rosters[i]` are the members of epoch i + 1.
    static Chain make(const std::vector<std::vector<Ed25519Keypair>>& rosters,
                      const Ed25519Keypair& genesis_key = new_identity()) {
        Chain chain;
        chain.genesis = genesis_key;
        chain.network = derive_network_id(chain.genesis.public_key,
                                          constants::kSecurityRulesetVersion,
                                          constants::kConsensusRulesetVersion);
        for (std::size_t i = 0; i < rosters.size(); ++i) {
            chain.epochs.emplace_back(EpochId{static_cast<uint64_t>(i + 1)}, chain.network, rosters[i]);
        }
        const auto& first = chain.epochs.front().committee;
        BootstrapCertificate& c = chain.certificate;
        c.network_id = chain.network;
        c.epoch = 1;
        c.tier1_set_digest = Tier1Set::from_nodes(first.members)->digest();
        c.authority_threshold = constants::authority_threshold(first.members.size());
        c.authority_public_key.fill(0x91);
        c.dkg_transcript_digest.fill(0xD1);
        c.attestation_root.fill(0xA1);
        c.founding_eligibility_digest.fill(0xE1);
        std::map<NodeId, Ed25519PublicKey> keys;
        for (const auto& node : first.members) {
            keys[node] = first.pubs.at(node);
            chain.founders.emplace_back(node, first.pubs.at(node));
        }
        c.vote_key_set_digest = vote_key_set_digest(keys);
        c.security_ruleset = constants::kSecurityRulesetVersion;
        c.consensus_ruleset = constants::kConsensusRulesetVersion;
        const Digest digest = bootstrap_certificate_signing_digest(c);
        crypto_sign_detached(c.genesis_signature.data(), nullptr, digest.data(), digest.size(),
                             chain.genesis.private_key.data());

        auto one = verify_epoch_one_authority(c, chain.genesis.public_key, chain.founders);
        if (!one) throw std::runtime_error("test chain: Epoch 1 does not verify");
        chain.authorities.push_back(*one);
        for (std::size_t i = 1; i < chain.epochs.size(); ++i) {
            const auto& next = chain.epochs[i].committee;
            EpochHandoff h;
            h.network_id = chain.network;
            h.from_epoch = next.epoch - 1;
            h.to_epoch = next.epoch;
            h.plan_digest.fill(static_cast<uint8_t>(0x30 + i));
            h.previous_anchor = chain.authorities.back().anchor_digest;
            h.members = next.members;
            for (const auto& node : next.members) {
                h.incarnations[node] = 1;
                h.vote_keys[node] = next.pubs.at(node);
            }
            // Never the certificate's 0x91: a group key lives one epoch.
            h.group_public_key.fill(static_cast<uint8_t>(0xB0 + i));
            h.dkg_transcript_digest.fill(static_cast<uint8_t>(0xD0 + i));
            h.key_generation = KeyGeneration(next.epoch.underlying());
            h.attestation_root.fill(static_cast<uint8_t>(0xA0 + i));
            h.security_ruleset = constants::kSecurityRulesetVersion;
            h.consensus_ruleset = constants::kConsensusRulesetVersion;
            EpochHandoffProofMsg link{h, chain.epochs[i - 1].committee.prove(
                                             epoch_handoff_digest(h))};
            auto advanced = advance_epoch_authority(chain.authorities.back(), link.handoff,
                                                    link.proof);
            auto* verified = std::get_if<VerifiedEpochAuthority>(&advanced);
            if (verified == nullptr) {
                throw std::runtime_error(
                    "test chain: a link does not verify: " +
                    std::to_string(static_cast<int>(std::get<HandoffChainFailure>(advanced))));
            }
            chain.authorities.push_back(*verified);
            chain.links.push_back(std::move(link));
        }
        return chain;
    }

    /// The page a server holding the first `known_epochs` epochs answers
    /// after `have_epoch`, exactly as SecurityDriver::authority_chain_page
    /// builds it. nullopt when it has nothing to add.
    [[nodiscard]] std::optional<AuthorityChainPage> page_after(uint64_t have_epoch,
                                                               std::size_t known_epochs) const {
        AuthorityChainPage page;
        uint64_t next_from = have_epoch;
        if (have_epoch == 0) {
            page.has_base = true;
            page.base_certificate = certificate;
            page.base_vote_keys = founders;
            next_from = 1;
        }
        for (const auto& link : links) {
            if (page.links.size() >= constants::kMaxHandoffChainLinks) break;
            if (link.handoff.to_epoch.underlying() > known_epochs) break;
            if (link.handoff.from_epoch.underlying() != next_from) continue;
            page.links.push_back(link);
            ++next_from;
        }
        if (!page.has_base && page.links.empty()) return std::nullopt;
        return page;
    }

    [[nodiscard]] std::optional<AuthorityChainPage> page_after(uint64_t have_epoch) const {
        return page_after(have_epoch, epochs.size());
    }

    [[nodiscard]] const VerifiedEpochAuthority& latest() const { return authorities.back(); }
};

}  // namespace tier1_chain_test
