#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>

namespace nexus::security {

AttestationService::AttestationService(LinuxAttestationProfile profile)
    : profile_(std::move(profile)), policy_digest_(profile_digest(profile_)) {}

std::optional<AttestationChallenge> AttestationService::create_challenge(
    const NodeId& node, const crypto::Ed25519PublicKey& node_key,
    IncarnationId incarnation, EpochId epoch) {
    auto& used = attempts_[{epoch, node}];
    if (used >= constants::kMaxTier1AttestAttemptsPerEpoch) {
        return std::nullopt;
    }
    ++used;

    AttestationChallenge challenge;
    randombytes_buf(challenge.nonce.data(), challenge.nonce.size());
    challenge.node_id = node;
    challenge.node_key = node_key;
    challenge.incarnation = incarnation;
    challenge.epoch = epoch;
    challenge.security_ruleset = constants::kSecurityRulesetVersion;
    challenge.policy_digest = policy_digest_;

    // A new challenge replaces any unanswered one: only the latest is live.
    pending_[node] = challenge;
    return challenge;
}

AttestationVerdict AttestationService::receive_evidence(const AttestationEvidence& evidence) {
    const auto pending = pending_.find(evidence.node_id);
    if (pending == pending_.end()) {
        AttestationVerdict verdict;
        verdict.node_id = evidence.node_id;
        verdict.incarnation = evidence.incarnation;
        verdict.policy_digest = policy_digest_;
        verdict.passed = false;
        verdict.failure = AttestationFailure::ChallengeMismatch;
        return verdict;
    }
    const AttestationChallenge challenge = pending->second;
    pending_.erase(pending);

    AttestationVerdict verdict = verifier_.examine(challenge, evidence, profile_);
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

uint32_t AttestationService::attempts(const NodeId& node, EpochId epoch) const {
    const auto it = attempts_.find({epoch, node});
    return it == attempts_.end() ? 0 : it->second;
}

}  // namespace nexus::security
