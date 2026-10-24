#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

namespace nexus::security {

bool block_payload_kind_known(uint16_t kind) {
    return kind == static_cast<uint16_t>(BlockPayloadKind::TreeBatch) ||
           kind == static_cast<uint16_t>(BlockPayloadKind::StorageHolderPlan) ||
           kind == static_cast<uint16_t>(BlockPayloadKind::StorageKeyRotation) ||
           kind == static_cast<uint16_t>(BlockPayloadKind::UpgradeProgress);
}

Digest block_payload_digest(const BlockPayload& payload) {
    CanonicalEncoder encoder(constants::kBftProtocolDomain);
    encoder.add_string("block-payload");
    encoder.add_u16(static_cast<uint16_t>(payload.kind));
    encoder.add_bytes(payload.body);
    return encoder.digest();
}

}  // namespace nexus::security
