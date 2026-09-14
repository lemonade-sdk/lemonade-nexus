#pragma once

// One live incarnation of a node identity (architecture 23).
//
// A snapshot restore can create two live copies of one old node state. The
// mesh allows only one current incarnation for a node identity, so a
// restored copy cannot act as a second voter — the quorum certificate counts
// unique node identities.
//
// The exact rule for replacing an active incarnation is an open architecture
// item (23.B). This header records the state and deliberately does not
// invent that rule.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

namespace nexus::security {

struct IncarnationState {
    NodeId node_id{};
    IncarnationId incarnation{};
    crypto::Ed25519PublicKey incarnation_key{};
    Digest attestation_digest{};
    EpochId observed_epoch{};
};

}  // namespace nexus::security
