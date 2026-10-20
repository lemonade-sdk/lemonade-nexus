#pragma once

// The challenge and evidence exchange (class structure 11, architecture 9).
//
// The service issues one-shot challenges, runs the verifier on the evidence
// that answers them, and keeps the latest verdict per node. It applies the
// per-node, per-epoch attestation budget. It does not decide eligibility and
// it does not select Tier 1 members; the verdict flows to the policy and the
// epoch layers.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationState.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Attestation/SvsmAkEnrollment.hpp>

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <tuple>
#include <utility>

namespace nexus::security {

class AttestationService {
public:
    /// `network_id` is stated, never defaulted: an all-zero network is a real
    /// value, and a service that silently used one would accept a challenge
    /// from any mesh that did the same.
    AttestationService(NetworkId network_id, LinuxAttestationProfile profile,
                       AmdRevocationSource revocation = {},
                       std::filesystem::path state_directory = {});

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

    /// Enrollment evidence creates exactly one short-lived activation offer.
    /// Ordinary evidence returns nullopt here and is handled by receive_evidence.
    [[nodiscard]] std::optional<SvsmAkActivationOfferMessage> receive_enrollment_evidence(
        const AttestationEvidence& evidence, const NodeId& observer);

    /// Complete one live activation, persist it, and issue the deferred normal
    /// challenge.  No challenge is returned unless the durable record exists.
    [[nodiscard]] std::optional<AttestationChallenge> receive_activation_response(
        const SvsmAkActivationResponseMessage& response);

    [[nodiscard]] std::optional<AttestationChallenge> pending_challenge(
        const NodeId& node) const;

    /// Frees the attempt budget for one subject. Only the lifecycle driver's
    /// paced bootstrap retries call this; the budget still caps each burst.
    void reset_attempts(EpochId epoch, const NodeId& node) { attempts_.erase({epoch, node}); }

    [[nodiscard]] std::optional<AttestationVerdict> verdict(const NodeId& node) const;

    [[nodiscard]] const LinuxAttestationProfile& profile() const { return profile_; }
    [[nodiscard]] const Digest& policy_digest() const { return policy_digest_; }

    /// Eligibility challenges issued for one node and epoch.
    [[nodiscard]] uint32_t attempts(const NodeId& node, EpochId epoch) const;

    /// Final-readiness challenges issued for one node under one plan-bound
    /// context. The bucket dies with its attempt: a replacement plan carries
    /// a fresh one, so exhaustion fails an attempt, never an identity.
    [[nodiscard]] uint32_t final_attempts(const NodeId& node, const Digest& context) const;

private:
    NetworkId network_id_;
    LinuxAttestationProfile profile_;
    Digest policy_digest_;
    // Declared before verifier_: verifier_ is initialized from both.
    AmdRevocationSource revocation_;
    AttestationVerifier verifier_;
    AttestationCheckpointStore checkpoints_;
    SvsmActivationStore activations_;

    struct DeferredChallenge {
        AttestationPurpose purpose{AttestationPurpose::Eligibility};
        Digest context{};
        EpochId epoch{};
    };
    struct PendingActivation {
        std::optional<SvsmAkActivationExchange> exchange;
        Digest enrollment_evidence_digest{};
        std::string ak_spki_b64;
        DeferredChallenge deferred;
    };

    std::map<NodeId, AttestationChallenge> pending_;
    std::map<NodeId, DeferredChallenge> deferred_;
    std::map<NodeId, PendingActivation> pending_activations_;
    std::map<NodeId, AttestationVerdict> verdicts_;
    std::map<std::pair<EpochId, NodeId>, uint32_t> attempts_;
    /// Keyed by the plan-bound context, so each attempt is its own bucket.
    /// Size-capped: a pruned stale bucket could only re-open a superseded
    /// attempt's budget, whose challenges no current context accepts.
    std::map<std::pair<NodeId, Digest>, uint32_t> final_attempts_;

    [[nodiscard]] AttestationChallenge make_challenge(
        const NodeId& node, const crypto::Ed25519PublicKey& node_key,
        IncarnationId incarnation, EpochId epoch, AttestationPurpose purpose,
        const Digest& context);
};

}  // namespace nexus::security
