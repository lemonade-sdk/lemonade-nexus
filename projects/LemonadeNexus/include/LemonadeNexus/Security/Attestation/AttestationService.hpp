#pragma once

// The challenge and evidence exchange (class structure 11, architecture 9).
//
// The service issues one-shot challenges, runs the verifier on the evidence
// that answers them, and keeps the latest verdict per node. It applies the
// per-node, per-epoch attestation budget. It does not decide eligibility and
// it does not select Tier 1 members; the verdict flows to the policy and the
// epoch layers.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <utility>

namespace nexus::security {

class AttestationService {
public:
    /// `network_id` is stated, never defaulted: an all-zero network is a real
    /// value, and a service that silently used one would accept a challenge
    /// from any mesh that did the same.
    AttestationService(NetworkId network_id, LinuxAttestationProfile profile,
                       AmdRevocationSource revocation = {});

    [[nodiscard]] const NetworkId& network_id() const { return network_id_; }

    /// Issues a fresh challenge for one attempt. Returns nullopt when the
    /// node spent its attestation budget for this epoch.
    ///
    /// The purpose decides the context: Eligibility computes its canonical
    /// context here and `context` must stay empty; FinalEpochReadiness must
    /// supply the plan-bound context and an empty one is refused. There is no
    /// unbound final challenge.
    [[nodiscard]] std::optional<AttestationChallenge> create_challenge(
        const NodeId& node, const crypto::Ed25519PublicKey& node_key,
        IncarnationId incarnation, EpochId epoch, AttestationPurpose purpose,
        const Digest& context = {});

    /// Examines evidence against the pending challenge for its node. The
    /// challenge is consumed: a second answer to the same challenge fails.
    [[nodiscard]] AttestationVerdict receive_evidence(const AttestationEvidence& evidence);

    [[nodiscard]] std::optional<AttestationVerdict> verdict(const NodeId& node) const;

    [[nodiscard]] const LinuxAttestationProfile& profile() const { return profile_; }
    [[nodiscard]] const Digest& policy_digest() const { return policy_digest_; }

    [[nodiscard]] uint32_t attempts(const NodeId& node, EpochId epoch) const;

private:
    NetworkId network_id_;
    LinuxAttestationProfile profile_;
    Digest policy_digest_;
    AttestationVerifier verifier_;

    std::map<NodeId, AttestationChallenge> pending_;
    std::map<NodeId, AttestationVerdict> verdicts_;
    std::map<std::pair<EpochId, NodeId>, uint32_t> attempts_;
};

}  // namespace nexus::security
