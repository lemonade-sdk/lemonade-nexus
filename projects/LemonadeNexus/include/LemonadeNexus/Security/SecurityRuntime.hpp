#pragma once

// The owner of the security services (class structure 3).
//
// The runtime owns service lifetimes and connects them at epoch boundaries.
// It implements no algorithm: it does not decide eligibility, does not vote,
// and does not create signature shares. Transport wiring (gossip routing) is
// the caller's job; every method here is an in-process step of the protocol.

#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>
#include <LemonadeNexus/Security/Authority/AuthorityService.hpp>
#include <LemonadeNexus/Security/Authority/NonceCommitmentStore.hpp>
#include <LemonadeNexus/Security/Consensus/ConsensusStore.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffService.hpp>
#include <LemonadeNexus/Security/Epoch/EpochManager.hpp>
#include <LemonadeNexus/Security/Epoch/EpochStore.hpp>
#include <LemonadeNexus/Security/Epoch/NextEpochPlan.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>

namespace nexus::security {

struct SecurityRuntimeConfig {
    NodeId self;
    /// The mesh this runtime belongs to. Bound into every attestation challenge
    /// so evidence cannot cross networks.
    NetworkId network_id{};
    std::filesystem::path consensus_directory;
    LinuxAttestationProfile profile;

    /// Supplies the cached AMD CRL and the current time to the attestation
    /// providers. Unset means no revocation data, which fails new Tier 1
    /// attestation closed under a profile that requires the check.
    AmdRevocationSource amd_revocation;

    /// Passed to every epoch's consensus service. It answers whether a proposed
    /// transition is one this node also arrived at, so a handoff gathers its
    /// quorum only from nodes that independently agree. Unset refuses every
    /// non-empty transition.
    std::function<bool(const Digest& transitions_digest)> transition_validator;
};

class SecurityRuntime {
public:
    explicit SecurityRuntime(SecurityRuntimeConfig config);

    [[nodiscard]] AttestationService& attestation() { return attestation_; }
    [[nodiscard]] AuthorityService& authority() { return authority_; }
    [[nodiscard]] NonceCommitmentStore& commitments() { return commitments_; }
    [[nodiscard]] EpochManager* epochs() { return epochs_ ? &*epochs_ : nullptr; }
    [[nodiscard]] const EpochManager* epochs() const { return epochs_ ? &*epochs_ : nullptr; }
    [[nodiscard]] HotStuffService* consensus() { return consensus_.get(); }
    [[nodiscard]] const NodeId& self() const { return config_.self; }

    /// Enters Epoch 1 from a Genesis-signed bootstrap certificate. The
    /// certificate must verify under the pinned genesis key and must name the
    /// founders, the threshold, and the DKG outcome this node holds. A node
    /// outside the founding set adopts the epoch without a share and without
    /// consensus.
    [[nodiscard]] bool adopt_epoch_one(const BootstrapCertificate& certificate,
                                       const crypto::Ed25519PublicKey& genesis_public_key,
                                       Tier1Set founders,
                                       std::map<NodeId, crypto::Ed25519PublicKey> vote_keys,
                                       std::optional<DkgResult> own_dkg,
                                       std::optional<EpochVoteKey> own_vote_key);

    /// Re-enters a stored epoch after a restart. Consensus resumes from the
    /// durable safety state and stays unsynced until a certified view floor
    /// arrives (architecture 19). The FROST share died with the process,
    /// so authority signing stays unavailable until the next epoch (12.11).
    [[nodiscard]] bool restore_epoch(StoredEpoch stored,
                                     std::optional<EpochVoteKey> own_vote_key);

    /// Activates the prepared next epoch: the EpochManager transition must be
    /// Ready and authorized. Installs the new share and restarts consensus
    /// under the new vote keys; the old share and vote key die here.
    [[nodiscard]] bool activate_next_epoch(std::optional<DkgResult> own_dkg,
                                           std::optional<EpochVoteKey> own_vote_key,
                                           const Digest& previous_checkpoint);

    /// Enters an epoch this node was selected into without having been in the
    /// one before it — the newcomer activation path. The caller has already
    /// verified the finalized handoff proof; this installs exactly what the
    /// handoff names and refuses anything that disagrees with the DKG outcome
    /// this node holds. Before this call the node had no epoch state at all,
    /// so there is no old role to overlap with.
    [[nodiscard]] bool adopt_epoch_from_handoff(const EpochHandoff& handoff,
                                                std::optional<DkgResult> own_dkg,
                                                std::optional<EpochVoteKey> own_vote_key,
                                                const Digest& previous_checkpoint);

private:
    [[nodiscard]] bool start_consensus(EpochVoteKey own_vote_key, const Digest& previous_checkpoint);
    [[nodiscard]] AuthorityEpochContext authority_context() const;

    SecurityRuntimeConfig config_;

    AttestationService attestation_;
    NonceCommitmentStore commitments_;
    AuthorityService authority_;
    FileConsensusStore consensus_store_;

    std::optional<EpochManager> epochs_;
    std::unique_ptr<HotStuffService> consensus_;
};

}  // namespace nexus::security
