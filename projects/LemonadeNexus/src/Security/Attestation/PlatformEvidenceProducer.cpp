#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>

#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <algorithm>
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

PlatformEvidence PlatformEvidenceProducer::platform_bundle(const AttestationChallenge& challenge,
                                                            const Digest& nonce) const {
    // A privileged helper, when configured. It gets the challenge — the identity
    // PUBLIC key and nothing that could sign on this node's behalf. It derives
    // the quote nonce itself; `nonce` is what we independently expect, and the
    // source must refuse evidence bound to anything else.
    if (sources_.platform_source) {
        (void)nonce;
        return sources_.platform_source(challenge);
    }

    std::string why;
    if (challenge.profile_id == AttestationProfileId::SnpSvsmVtpm) {
        SnpSvsmEvidenceProduceConfig config;
        config.cache_dir = sources_.cache_directory;
        config.identity_pubkey.assign(sources_.identity.public_key.begin(),
                                      sources_.identity.public_key.end());
        if (auto bundle = produce_snp_svsm_vtpm_evidence(config, nonce, &why)) {
            return PlatformEvidence{std::move(*bundle)};
        }
        spdlog::debug("[producer] no SVSM platform evidence: {}", why);
        return PlatformEvidence{SnpSvsmVtpmEvidence{}};
    }

    // The challenge digest is the quote nonce, so one quote binds the node
    // identity, the incarnation, the epoch and the policy (architecture 9).
    EvidenceProduceConfig config;
    config.cache_dir = sources_.cache_directory;
    config.identity_pubkey.assign(sources_.identity.public_key.begin(),
                                  sources_.identity.public_key.end());

    // A build without the TPM stack has a stub that refuses with a reason.
    if (auto bundle = produce_snp_vtpm_evidence(config, nonce, &why)) {
        return PlatformEvidence{std::move(*bundle)};
    }

    // An empty bundle claims nothing. The verifier fails it, which is the
    // correct outcome for a host that cannot prove its platform.
    spdlog::debug("[producer] no platform evidence: {}", why);
    return PlatformEvidence{SnpVtpmEvidence{}};
}

std::optional<AttestationEvidence> PlatformEvidenceProducer::produce(
    const AttestationChallenge& challenge) {
    // A challenge for another identity is never answered.
    if (challenge.node_id.bytes != sources_.identity.public_key ||
        challenge.node_key != sources_.identity.public_key) {
        spdlog::debug("[producer] challenge addresses another identity; not answered");
        return std::nullopt;
    }

    // This producer builds one evidence format. A challenge naming any other
    // profile goes unanswered rather than being answered with the wrong shape.
    if (challenge.profile_id != kTier1AttestationProfileId ||
        challenge.profile_ruleset != kAttestationProfileRulesetVersion) {
        spdlog::debug("[producer] challenge names profile {} ruleset {}; not answered",
                      attestation_profile_id_name(challenge.profile_id),
                      challenge.profile_ruleset);
        return std::nullopt;
    }

    // No vote key, no attestation. Nothing is fabricated.
    std::optional<crypto::Ed25519PublicKey> vote_key;
    if (sources_.vote_key_for_epoch) {
        vote_key = sources_.vote_key_for_epoch(challenge.epoch);
    }
    if (!vote_key) {
        spdlog::debug("[producer] no vote key for epoch {}; not answered", challenge.epoch.underlying());
        return std::nullopt;
    }

    AttestationEvidence evidence;
    evidence.network_id = challenge.network_id;
    evidence.challenge_digest = challenge_digest(challenge);
    evidence.node_id.bytes = sources_.identity.public_key;
    evidence.incarnation = challenge.incarnation;
    evidence.epoch = challenge.epoch;
    evidence.security_ruleset = constants::kSecurityRulesetVersion;
    evidence.consensus_ruleset = constants::kConsensusRulesetVersion;
    evidence.profile_id = challenge.profile_id;
    evidence.profile_ruleset = challenge.profile_ruleset;
    evidence.purpose = challenge.purpose;
    evidence.context_digest = challenge.context_digest;
    evidence.ima_mode = challenge.ima_mode;
    evidence.epoch_vote_key = *vote_key;
    evidence.platform = platform_bundle(challenge, evidence.challenge_digest);
    if (auto* svsm = std::get_if<SnpSvsmVtpmEvidence>(&evidence.platform)) {
        if (challenge.purpose == AttestationPurpose::PlatformEnrollment) {
            // Enrollment proves the fresh dual report and public EK/AK only;
            // IMA is transferred after activation under a normal challenge.
            svsm->ima_binary_log.clear();
        } else if (challenge.ima_mode == ImaEvidenceMode::Resume &&
                   !sources_.platform_source) {
            const auto current = parse_ima_binary(svsm->ima_binary_log);
            if (!current || challenge.ima_prior_event_count > current->entries.size()) {
                return std::nullopt;
            }
            // One prefix replay yields the checkpoint state and the suffix cut.
            std::array<uint8_t, 32> zero{};
            const auto prior = replay_ima_binary_prefix(
                *current, challenge.ima_prior_event_count, 0, zero);
            if (!prior || !std::ranges::equal(prior->state.pcr10,
                                               challenge.ima_prior_pcr10))
                return std::nullopt;
            for (const auto& expected : challenge.ima_checkpoint_paths) {
                const auto found = std::find_if(prior->state.paths.begin(),
                                                prior->state.paths.end(),
                    [&expected](const auto& path) { return path.path == expected.path; });
                if (found == prior->state.paths.end() || found->sha256 != expected.sha256)
                    return std::nullopt;
            }
            if (prior->wire_end > svsm->ima_binary_log.size()) {
                spdlog::debug("[producer] verifier checkpoint is not a prefix of this boot");
                return std::nullopt;
            }
            svsm->ima_binary_log.erase(
                svsm->ima_binary_log.begin(),
                svsm->ima_binary_log.begin() + static_cast<std::ptrdiff_t>(prior->wire_end));
        }
        evidence.ima_bytes = svsm->ima_binary_log.size();
        evidence.ima_digest = raw_ima_digest(svsm->ima_binary_log);
    }

    // Sign last. The identity binds the vote key and every other field
    // above, the platform bundle included (architecture 18).
    const Digest digest = evidence_signing_digest(evidence);
    crypto_sign_detached(evidence.identity_signature.data(), nullptr, digest.data(),
                         digest.size(), sources_.identity.private_key.data());
    return evidence;
}

std::optional<SvsmAkActivationResponseMessage> PlatformEvidenceProducer::activate(
    const SvsmAkActivationOfferMessage& offer) {
    if (offer.network_id == NetworkId{} || offer.subject_node.bytes != sources_.identity.public_key ||
        offer.subject_key != sources_.identity.public_key ||
        offer.profile_id != AttestationProfileId::SnpSvsmVtpm ||
        offer.profile_ruleset != kAttestationProfileRulesetVersion ||
        offer.activation.enrollment_context != svsm_ak_activation_offer_context(offer)) {
        return std::nullopt;
    }
    if (!sources_.activation_source) {
        spdlog::debug("[producer] SVSM AK activation refused: no activation source wired");
        return std::nullopt;
    }
    std::string failure;
    // The daemon owns the TPM; this process holds no TPM device and no root.
    auto secret = sources_.activation_source(offer.ek_public, offer.ak_public,
                                             offer.activation.credential_blob,
                                             offer.activation.encrypted_secret, &failure);
    if (!secret) {
        spdlog::debug("[producer] SVSM AK activation refused: {}", failure);
        return std::nullopt;
    }
    SvsmAkActivationResponseMessage response;
    response.network_id = offer.network_id;
    response.subject_node = offer.subject_node;
    response.incarnation = offer.incarnation;
    response.epoch = offer.epoch;
    response.profile_id = offer.profile_id;
    response.profile_ruleset = offer.profile_ruleset;
    response.observer = offer.observer;
    response.activation_context = offer.activation.enrollment_context;
    response.activated_secret = std::move(*secret);
    const Digest digest = svsm_ak_activation_response_digest(response);
    crypto_sign_detached(response.identity_signature.data(), nullptr, digest.data(), digest.size(),
                         sources_.identity.private_key.data());
    return response;
}

}  // namespace nexus::security
