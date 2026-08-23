#include <LemonadeNexus/Security/Genesis/GenesisService.hpp>

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>

#include <algorithm>
#include <vector>

namespace nexus::security {

GenesisService::GenesisService(NetworkId network_id) : network_id_(network_id) {}

bool GenesisService::admit_candidate(const NodeId& node) {
    if (finalized_) {
        return false;
    }
    return candidates_.insert(node).second;
}

bool GenesisService::record_verdict(const AttestationVerdict& verdict) {
    if (finalized_) {
        return false;
    }
    if (!candidates_.contains(verdict.node_id)) {
        return false;
    }
    verdicts_[verdict.node_id] = verdict;
    return true;
}

bool GenesisService::quorum_ready() const {
    std::size_t qualifying = 0;
    for (const auto& [node, verdict] : verdicts_) {
        if (verdict.passed) {
            ++qualifying;
        }
    }
    return qualifying >= constants::kBootstrapThreshold;
}

std::optional<Tier1Set> GenesisService::founding_set() const {
    std::vector<NodeId> qualifying;
    for (const auto& [node, verdict] : verdicts_) {
        if (verdict.passed) {
            qualifying.push_back(node);
        }
    }
    if (qualifying.size() < constants::kBootstrapThreshold) {
        return std::nullopt;
    }
    // verdicts_ iterates in NodeId order, so the first threshold entries are
    // already the lowest identities.
    qualifying.resize(constants::kBootstrapThreshold);
    return Tier1Set::from_nodes(std::move(qualifying));
}

std::optional<BootstrapCertificate> GenesisService::finalize_epoch_one(
    const crypto::Ed25519PublicKey& epoch_one_authority_key,
    const Digest& dkg_transcript_digest,
    const Digest& attestation_root,
    const crypto::Ed25519PrivateKey& genesis_private_key) {
    if (finalized_) {
        return std::nullopt;
    }
    const auto founders = founding_set();
    if (!founders.has_value()) {
        return std::nullopt;
    }

    BootstrapCertificate certificate;
    certificate.network_id = network_id_;
    certificate.epoch = 1;
    certificate.tier1_set_digest = founders->digest();
    certificate.authority_threshold =
        constants::authority_threshold(constants::kBootstrapThreshold);
    certificate.authority_public_key = epoch_one_authority_key;
    certificate.dkg_transcript_digest = dkg_transcript_digest;
    certificate.attestation_root = attestation_root;
    certificate.security_ruleset = constants::kSecurityRulesetVersion;
    certificate.consensus_ruleset = constants::kConsensusRulesetVersion;

    const Digest digest = bootstrap_certificate_signing_digest(certificate);
    if (crypto_sign_detached(certificate.genesis_signature.data(), nullptr, digest.data(),
                             digest.size(), genesis_private_key.data()) != 0) {
        return std::nullopt;
    }

    // Genesis unilateral authority ends here, permanently.
    finalized_ = true;
    return certificate;
}

}  // namespace nexus::security
