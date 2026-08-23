#pragma once

// The temporary bootstrap authority.
//
// Genesis introduces candidates, records their attestation verdicts, and — when
// the bootstrap threshold of qualifying participants exists — signs exactly one
// bootstrap certificate over the finalized Epoch 1 state. Then Genesis
// authority ends permanently: the service refuses every later mutation.
//
// Genesis keeps no preauthorized list. A candidate qualifies only through a
// passing attestation verdict; Genesis cannot waive a prerequisite.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <map>
#include <optional>
#include <set>

namespace nexus::security {

class GenesisService {
public:
    explicit GenesisService(NetworkId network_id);

    /// Introduces a candidate to the pre-quorum mesh. Returns false for a
    /// duplicate or after finalization.
    [[nodiscard]] bool admit_candidate(const NodeId& node);

    /// Records the latest attestation verdict for an admitted candidate. A
    /// verdict for an unknown candidate is refused: introduction comes first.
    [[nodiscard]] bool record_verdict(const AttestationVerdict& verdict);

    /// True when at least kBootstrapThreshold admitted candidates hold a
    /// passing verdict.
    [[nodiscard]] bool quorum_ready() const;

    /// The founding Tier 1 set: the kBootstrapThreshold qualifying candidates
    /// with the lowest node identities. Sorting by identity keeps the choice
    /// deterministic when more than the threshold qualify.
    [[nodiscard]] std::optional<Tier1Set> founding_set() const;

    /// Signs the one bootstrap certificate and ends Genesis authority.
    /// Returns nullopt when the quorum is not ready or Genesis already
    /// finalized.
    [[nodiscard]] std::optional<BootstrapCertificate> finalize_epoch_one(
        const crypto::Ed25519PublicKey& epoch_one_authority_key,
        const Digest& dkg_transcript_digest,
        const Digest& attestation_root,
        const crypto::Ed25519PrivateKey& genesis_private_key);

    [[nodiscard]] bool finalized() const { return finalized_; }

private:
    NetworkId network_id_;
    std::set<NodeId> candidates_;
    std::map<NodeId, AttestationVerdict> verdicts_;
    bool finalized_ = false;
};

}  // namespace nexus::security
