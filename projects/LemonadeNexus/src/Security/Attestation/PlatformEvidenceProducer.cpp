#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>

#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <string>
#include <utility>

namespace nexus::security {

PlatformEvidenceProducer::PlatformEvidenceProducer(EvidenceProducerSources sources)
    : sources_(std::move(sources)) {}

bool PlatformEvidenceProducer::platform_available() const {
#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
    return true;
#else
    return false;
#endif
}

SnpVtpmEvidence PlatformEvidenceProducer::platform_bundle(const Digest& nonce) const {
    // The challenge digest is the quote nonce, so one quote binds the node
    // identity, the incarnation, the epoch and the policy (architecture 5.5).
    EvidenceProduceConfig config;
    config.cache_dir = sources_.cache_directory;
    config.identity_pubkey.assign(sources_.identity.public_key.begin(),
                                  sources_.identity.public_key.end());

    // A build without the TPM stack has a stub that refuses with a reason.
    std::string why;
    if (auto bundle = produce_snp_vtpm_evidence(config, nonce, &why)) {
        return std::move(*bundle);
    }

    // An empty bundle claims nothing. The verifier fails it, which is the
    // correct outcome for a host that cannot prove its platform.
    spdlog::debug("[producer] no platform evidence: {}", why);
    return {};
}

std::optional<AttestationEvidence> PlatformEvidenceProducer::produce(
    const AttestationChallenge& challenge) {
    // A challenge for another identity is never answered.
    if (challenge.node_id.bytes != sources_.identity.public_key ||
        challenge.node_key != sources_.identity.public_key) {
        spdlog::debug("[producer] challenge addresses another identity; not answered");
        return std::nullopt;
    }

    // No vote key, no attestation. Nothing is fabricated.
    std::optional<crypto::Ed25519PublicKey> vote_key;
    if (sources_.vote_key_for_epoch) {
        vote_key = sources_.vote_key_for_epoch(challenge.epoch);
    }
    if (!vote_key) {
        spdlog::debug("[producer] no vote key for epoch {}; not answered", challenge.epoch);
        return std::nullopt;
    }

    AttestationEvidence evidence;
    evidence.challenge_digest = challenge_digest(challenge);
    evidence.node_id.bytes = sources_.identity.public_key;
    evidence.incarnation = challenge.incarnation;
    evidence.security_ruleset = constants::kSecurityRulesetVersion;
    evidence.consensus_ruleset = constants::kConsensusRulesetVersion;
    evidence.epoch_vote_key = *vote_key;
    evidence.platform = platform_bundle(evidence.challenge_digest);

    // Sign last. The identity binds the vote key and every other field
    // above, the platform bundle included (architecture 11.2).
    const Digest digest = evidence_signing_digest(evidence);
    crypto_sign_detached(evidence.identity_signature.data(), nullptr, digest.data(),
                         digest.size(), sources_.identity.private_key.data());
    return evidence;
}

}  // namespace nexus::security
