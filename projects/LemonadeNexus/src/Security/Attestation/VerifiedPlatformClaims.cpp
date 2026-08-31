#include <LemonadeNexus/Security/Attestation/VerifiedPlatformClaims.hpp>

namespace nexus::security {

namespace {

struct ClaimField {
    PlatformClaim claim;
    bool VerifiedPlatformClaims::* field;
};

constexpr ClaimField kRequired[] = {
    {PlatformClaim::HardwareConfidentiality,
     &VerifiedPlatformClaims::hardware_confidentiality_valid},
    {PlatformClaim::PlatformIdentity, &VerifiedPlatformClaims::platform_identity_valid},
    {PlatformClaim::EvidenceFreshness, &VerifiedPlatformClaims::evidence_freshness_valid},
    {PlatformClaim::NodeIdentityBinding, &VerifiedPlatformClaims::node_identity_binding_valid},
    {PlatformClaim::IncarnationBinding, &VerifiedPlatformClaims::incarnation_binding_valid},
    {PlatformClaim::EpochBinding, &VerifiedPlatformClaims::epoch_binding_valid},
    {PlatformClaim::SecurityRulesetBinding,
     &VerifiedPlatformClaims::security_ruleset_binding_valid},
    {PlatformClaim::BootIntegrity, &VerifiedPlatformClaims::boot_integrity_valid},
    {PlatformClaim::RuntimeIntegrity, &VerifiedPlatformClaims::runtime_integrity_valid},
    {PlatformClaim::Tcb, &VerifiedPlatformClaims::tcb_valid},
    {PlatformClaim::AttestationProfile, &VerifiedPlatformClaims::attestation_profile_valid},
};

// Every claim, in declaration order. One list defines the digest order and the
// wire bit order, so the two can never drift apart.
constexpr bool VerifiedPlatformClaims::* kAllClaims[] = {
    &VerifiedPlatformClaims::hardware_confidentiality_valid,
    &VerifiedPlatformClaims::platform_identity_valid,
    &VerifiedPlatformClaims::evidence_freshness_valid,
    &VerifiedPlatformClaims::node_identity_binding_valid,
    &VerifiedPlatformClaims::incarnation_binding_valid,
    &VerifiedPlatformClaims::epoch_binding_valid,
    &VerifiedPlatformClaims::security_ruleset_binding_valid,
    &VerifiedPlatformClaims::boot_integrity_valid,
    &VerifiedPlatformClaims::runtime_integrity_valid,
    &VerifiedPlatformClaims::tcb_valid,
    &VerifiedPlatformClaims::attestation_profile_valid,
    &VerifiedPlatformClaims::ima_anchored,
    &VerifiedPlatformClaims::binary_approved,
    &VerifiedPlatformClaims::runtime_profile_enforced,
};

static_assert(sizeof(kAllClaims) / sizeof(kAllClaims[0]) == 14,
              "kPlatformClaimBitMask names exactly these claims");

}  // namespace

void encode_platform_claims(CanonicalEncoder& encoder, const VerifiedPlatformClaims& claims) {
    encoder.add_u16(static_cast<uint16_t>(claims.profile_id));
    encoder.add_u16(claims.profile_ruleset);
    for (const auto field : kAllClaims) {
        encoder.add_u16(claims.*field ? 1 : 0);
    }
}

uint16_t platform_claim_bits(const VerifiedPlatformClaims& claims) {
    uint16_t bits = 0;
    uint16_t position = 0;
    for (const auto field : kAllClaims) {
        if (claims.*field) {
            bits |= static_cast<uint16_t>(1u << position);
        }
        ++position;
    }
    return bits;
}

VerifiedPlatformClaims platform_claims_from_bits(AttestationProfileId profile_id,
                                                  AttestationProfileRuleset profile_ruleset,
                                                  uint16_t bits) {
    VerifiedPlatformClaims claims;
    claims.profile_id = profile_id;
    claims.profile_ruleset = profile_ruleset;
    uint16_t position = 0;
    for (const auto field : kAllClaims) {
        claims.*field = (bits & static_cast<uint16_t>(1u << position)) != 0;
        ++position;
    }
    return claims;
}

std::string_view platform_claim_name(PlatformClaim claim) {
    switch (claim) {
        case PlatformClaim::HardwareConfidentiality: return "hardware confidentiality";
        case PlatformClaim::PlatformIdentity:        return "platform identity";
        case PlatformClaim::EvidenceFreshness:       return "evidence freshness";
        case PlatformClaim::NodeIdentityBinding:     return "node identity binding";
        case PlatformClaim::IncarnationBinding:      return "incarnation binding";
        case PlatformClaim::EpochBinding:            return "epoch binding";
        case PlatformClaim::SecurityRulesetBinding:  return "security ruleset binding";
        case PlatformClaim::BootIntegrity:           return "boot integrity";
        case PlatformClaim::RuntimeIntegrity:        return "runtime integrity";
        case PlatformClaim::Tcb:                     return "platform TCB";
        case PlatformClaim::AttestationProfile:      return "attestation profile";
    }
    return "unknown claim";
}

std::vector<PlatformClaim> missing_platform_claims(const VerifiedPlatformClaims& claims) {
    std::vector<PlatformClaim> missing;
    for (const auto& entry : kRequired) {
        if (!(claims.*entry.field)) {
            missing.push_back(entry.claim);
        }
    }
    return missing;
}

bool all_platform_claims_proved(const VerifiedPlatformClaims& claims) {
    for (const auto& entry : kRequired) {
        if (!(claims.*entry.field)) {
            return false;
        }
    }
    return true;
}

bool platform_claims_are_consistent(const VerifiedPlatformClaims& claims) {
    const bool anonymous = claims.profile_id == AttestationProfileId::Unknown ||
                           claims.profile_ruleset == 0;
    if (anonymous) {
        // Nothing identified itself, so nothing ran. Any true claim here came
        // from somewhere other than a verifier step.
        for (const auto& entry : kRequired) {
            if (claims.*entry.field) {
                return false;
            }
        }
        return !claims.ima_anchored && !claims.binary_approved &&
               !claims.runtime_profile_enforced;
    }
    const bool runtime_steps =
        claims.ima_anchored && claims.binary_approved && claims.runtime_profile_enforced;
    return claims.runtime_integrity_valid == runtime_steps;
}

}  // namespace nexus::security
