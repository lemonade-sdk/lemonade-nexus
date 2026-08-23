#pragma once

// The only shape the epoch FROST key ever signs.
//
// Nexus has no sign-arbitrary-bytes interface. An authority signature exists
// only for a typed object that binds the network, the epoch, the key
// generation, and the finalized consensus certificate that authorized it.
// Construct this type only from finalized consensus state.

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>

namespace nexus::security {

// The operation set is protocol-controlled. A new operation kind is a
// deterministic security-rule change and needs a new security ruleset.
enum class AuthorityOperation : uint16_t {
    EpochTransition = 1,
    Checkpoint = 2,
};

struct AuthorityObject {
    NetworkId network_id{};
    EpochId epoch = 0;
    KeyGeneration key_generation = 0;

    AuthorityOperation operation = AuthorityOperation::EpochTransition;
    OperationId operation_id = 0;

    Digest previous_state_digest{};
    Digest finalized_state_digest{};
    Digest consensus_certificate_digest{};
};

[[nodiscard]] inline Digest authority_object_digest(const AuthorityObject& object) {
    CanonicalEncoder encoder("lemonade-nexus/authority-object:v1");
    encoder.add_bytes(object.network_id);
    encoder.add_u64(object.epoch);
    encoder.add_u64(object.key_generation);
    encoder.add_u16(static_cast<uint16_t>(object.operation));
    encoder.add_u64(object.operation_id);
    encoder.add_bytes(object.previous_state_digest);
    encoder.add_bytes(object.finalized_state_digest);
    encoder.add_bytes(object.consensus_certificate_digest);
    return encoder.digest();
}

}  // namespace nexus::security
