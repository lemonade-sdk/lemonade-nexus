#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>

namespace nexus::security {

AttestationService::AttestationService(NetworkId network_id, LinuxAttestationProfile profile,
                                       AmdRevocationSource revocation)
    : network_id_(network_id),
      profile_(std::move(profile)),
      policy_digest_(profile_digest(profile_)),
      verifier_(profile_, std::move(revocation)) {}

std::optional<AttestationChallenge> AttestationService::create_challenge(
    const NodeId& node, const crypto::Ed25519PublicKey& node_key,
    IncarnationId incarnation, EpochId epoch, AttestationPurpose purpose,
    const Digest& context) {
    // A final challenge with no bound context would recreate the reusable
    // attestation this binding exists to remove; an eligibility challenge with
    // a caller-chosen context would let the caller relabel one.
    if (purpose == AttestationPurpose::FinalEpochReadiness && context == Digest{}) {
        return std::nullopt;
    }
    if (purpose == AttestationPurpose::Eligibility && context != Digest{}) {
        return std::nullopt;
    }
    auto& used = attempts_[{epoch, node, purpose}];
    const uint32_t limit = purpose == AttestationPurpose::FinalEpochReadiness
                               ? constants::kMaxFinalAttestAttemptsPerEpoch
                               : constants::kMaxTier1AttestAttemptsPerEpoch;
    if (used >= limit) {
        return std::nullopt;
    }
    ++used;

    AttestationChallenge challenge;
    challenge.network_id = network_id_;
    randombytes_buf(challenge.nonce.data(), challenge.nonce.size());
    challenge.node_id = node;
    challenge.node_key = node_key;
    challenge.incarnation = incarnation;
    challenge.epoch = epoch;
    challenge.security_ruleset = constants::kSecurityRulesetVersion;
    challenge.consensus_ruleset = constants::kConsensusRulesetVersion;
    // The challenge names the profile. A candidate answers under this one or it
    // answers nothing: there is no negotiation and no weaker second choice.
    challenge.profile_id = kTier1AttestationProfileId;
    challenge.profile_ruleset = kAttestationProfileRulesetVersion;
    challenge.policy_digest = policy_digest_;
    challenge.purpose = purpose;
    challenge.context_digest =
        purpose == AttestationPurpose::Eligibility
            ? eligibility_attestation_context(network_id_, epoch, node, incarnation)
            : context;

    // A new challenge replaces any unanswered one: only the latest is live.
    pending_[node] = challenge;
    return challenge;
}

AttestationVerdict AttestationService::receive_evidence(const AttestationEvidence& evidence) {
    AttestationVerdict rejected;
    rejected.node_id = evidence.node_id;
    rejected.incarnation = evidence.incarnation;
    rejected.epoch = evidence.epoch;
    rejected.purpose = evidence.purpose;
    rejected.context_digest = evidence.context_digest;
    rejected.policy_digest = policy_digest_;
    rejected.failure = AttestationFailure::ChallengeMismatch;

    const auto pending = pending_.find(evidence.node_id);
    if (pending == pending_.end()) {
        return rejected;
    }

    // The challenge is one-shot, but only a bundle that actually answers it may
    // consume it. A stale or hostile bundle that names the right node otherwise
    // cancels the live challenge, and the honest answer that follows then finds
    // nothing pending. Match first, consume second.
    if (evidence.challenge_digest != challenge_digest(pending->second)) {
        return rejected;
    }
    const AttestationChallenge challenge = pending->second;
    pending_.erase(pending);

    AttestationVerdict verdict = verifier_.examine(challenge, evidence);
    verdicts_[evidence.node_id] = verdict;
    return verdict;
}

std::optional<AttestationVerdict> AttestationService::verdict(const NodeId& node) const {
    const auto it = verdicts_.find(node);
    if (it == verdicts_.end()) {
        return std::nullopt;
    }
    return it->second;
}

uint32_t AttestationService::attempts(const NodeId& node, EpochId epoch,
                                      AttestationPurpose purpose) const {
    const auto it = attempts_.find({epoch, node, purpose});
    return it == attempts_.end() ? 0 : it->second;
}

}  // namespace nexus::security
