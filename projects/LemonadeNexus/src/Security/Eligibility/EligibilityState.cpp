#include <LemonadeNexus/Security/Eligibility/EligibilityState.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include <algorithm>

namespace nexus::security {

namespace {

inline constexpr std::string_view kClaimsDomain = "lemonade-nexus/platform-claims:v1";
inline constexpr std::string_view kStateDomain = "lemonade-nexus/eligibility-state:v1";
inline constexpr std::string_view kCommitmentDomain = "lemonade-nexus/eligibility-commit:v1";

void add_flag(CanonicalEncoder& encoder, bool value) {
    encoder.add_u16(value ? 1 : 0);
}

}  // namespace

uint32_t objective_fault_bit(ObjectiveFault fault) {
    return 1u << static_cast<uint32_t>(fault);
}

Digest platform_claims_digest(const VerifiedPlatformClaims& claims) {
    // An incomplete or inconsistent claim set proves nothing, and the ways it
    // can be incomplete differ between verifiers. Collapsing all of them to a
    // zero digest is what keeps two honest nodes in agreement about a candidate
    // they both refused.
    if (!platform_claims_are_consistent(claims) || !all_platform_claims_proved(claims)) {
        return Digest{};
    }
    CanonicalEncoder encoder(kClaimsDomain);
    encode_platform_claims(encoder, claims);
    return encoder.digest();
}

Digest eligibility_state_digest(const EligibilityState& state) {
    CanonicalEncoder encoder(kStateDomain);
    encoder.add_bytes(state.network_id);
    encoder.add_u64(state.epoch);
    encoder.add_u64(state.next_epoch);
    encoder.add_u16(state.security_ruleset);
    encoder.add_u16(state.consensus_ruleset);
    encoder.add_bytes(state.observer_set);
    encoder.add_u64(state.quorum);
    encoder.add_u64(state.records.size());
    // Records arrive sorted by subject; a caller that reordered them would
    // produce a different digest and simply fail to agree with anyone.
    for (const auto& record : state.records) {
        encoder.add_bytes(record.subject.bytes);
        encoder.add_u64(record.incarnation);
        add_flag(encoder, record.uptime_valid);
        add_flag(encoder, record.mesh_health_valid);
        add_flag(encoder, record.certificate_valid);
        encoder.add_bytes(record.platform_claims);
        encoder.add_u32(record.faults);
        add_flag(encoder, record.eligible);
    }
    return encoder.digest();
}

Digest eligibility_commitment_digest(const EligibilityState& state) {
    CanonicalEncoder encoder(kCommitmentDomain);
    encoder.add_bytes(state.network_id);
    encoder.add_u64(state.epoch);
    encoder.add_u64(state.next_epoch);
    encoder.add_bytes(eligibility_state_digest(state));
    return encoder.digest();
}

std::vector<NodeId> eligible_nodes(const EligibilityState& state) {
    std::vector<NodeId> nodes;
    for (const auto& record : state.records) {
        if (record.eligible) {
            nodes.push_back(record.subject);
        }
    }
    std::sort(nodes.begin(), nodes.end());
    return nodes;
}

}  // namespace nexus::security
