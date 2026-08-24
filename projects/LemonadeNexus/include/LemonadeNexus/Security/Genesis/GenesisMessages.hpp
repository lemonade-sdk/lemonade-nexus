#pragma once

// Bootstrap-flow messages between Genesis and the founding participants.
//
// Genesis names the founders it verified; each founder attests the DKG
// transcript it observed under its own identity key; Genesis signs the one
// bootstrap certificate only when all founders attested the same transcript
// and the same group key (architecture 12.7, 18).

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <utility>
#include <vector>

namespace nexus::security {

struct GenesisFounding {
    EpochId epoch = 1;
    /// Each founder with the epoch vote key its passing evidence bound.
    std::vector<std::pair<NodeId, crypto::Ed25519PublicKey>> members;
    Digest attestation_root{};
};

struct DkgTranscriptAttest {
    EpochId epoch = 0;
    Digest participant_set_digest{};
    Digest transcript_digest{};
    crypto::Ed25519PublicKey group_public_key{};
    NodeId node;
    crypto::Ed25519Signature identity_signature{};
};

[[nodiscard]] inline Digest dkg_transcript_attest_digest(const DkgTranscriptAttest& attest) {
    CanonicalEncoder encoder("lemonade-nexus/dkg-transcript-attest:v1");
    encoder.add_u64(attest.epoch);
    encoder.add_bytes(attest.participant_set_digest);
    encoder.add_bytes(attest.transcript_digest);
    encoder.add_bytes(attest.group_public_key);
    encoder.add_bytes(attest.node.bytes);
    return encoder.digest();
}

}  // namespace nexus::security
