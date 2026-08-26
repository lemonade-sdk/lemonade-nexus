#include <LemonadeNexus/Security/Policy/Tier1Evidence.hpp>

namespace nexus::security {

Tier1EvidenceState tier1_evidence_state(const AttestationVerdict& verdict,
                                         const Tier1MeshFacts& facts) {
    Tier1EvidenceState state;

    // --- what a platform provider proved -------------------------------------
    // Each comes from a claim a verifier step produced. None is inferred from
    // verdict.passed, so a verdict that stopped early — or one that somehow
    // passed with nothing behind it — leaves the later prerequisites false.
    //
    // Claims a provider could not have produced are refused wholesale: an
    // object whose claims contradict its own structure is a bug, not a proof.
    const VerifiedPlatformClaims& claims = verdict.claims;
    if (!platform_claims_are_consistent(claims)) {
        return state;
    }

    state.platform_profile_valid = claims.attestation_profile_valid &&
                                   claims.security_ruleset_binding_valid;
    state.node_identity_valid    = claims.node_identity_binding_valid;
    state.snp_valid              = claims.hardware_confidentiality_valid;
    state.tcb_valid              = claims.tcb_valid;
    state.vtpm_valid             = claims.platform_identity_valid;
    state.quote_fresh            = claims.evidence_freshness_valid;
    state.boot_state_valid       = claims.boot_integrity_valid;
    state.binary_valid           = claims.binary_approved;
    state.ima_valid              = claims.ima_anchored;
    state.runtime_profile_valid  = claims.runtime_profile_enforced;

    // --- what only the mesh knows --------------------------------------------
    state.certificate_valid = facts.certificate_valid;
    state.uptime_valid      = facts.uptime_valid;
    state.mesh_health_valid = facts.mesh_health_valid;

    // A verdict for another epoch or another incarnation is stale. Two things
    // must hold: the evidence bound the value it answered for, and that value
    // is the one the mesh currently considers live. An absent current value
    // proves nothing, so it leaves the prerequisite false.
    state.epoch_current = claims.epoch_binding_valid && facts.current_epoch.has_value() &&
                          verdict.epoch == *facts.current_epoch;
    state.incarnation_current = claims.incarnation_binding_valid &&
                                facts.current_incarnation.has_value() &&
                                verdict.incarnation == *facts.current_incarnation;

    return state;
}

Tier1Eligibility tier1_eligibility(const AttestationVerdict& verdict,
                                    const Tier1MeshFacts& facts) {
    return Tier1EligibilityPolicy::evaluate(tier1_evidence_state(verdict, facts));
}

std::string_view tier1_prerequisite_name(Tier1Prerequisite prerequisite) {
    switch (prerequisite) {
        case Tier1Prerequisite::PlatformProfile:        return "approved platform profile";
        case Tier1Prerequisite::PlatformTcb:            return "platform TCB floor";
        case Tier1Prerequisite::NodeIdentity:           return "node identity";
        case Tier1Prerequisite::Certificate:            return "transport certificate";
        case Tier1Prerequisite::ConfidentialCompute:    return "SEV-SNP platform";
        case Tier1Prerequisite::Vtpm:                   return "vTPM bound to the SNP report";
        case Tier1Prerequisite::AttestationFreshness:   return "fresh quote";
        case Tier1Prerequisite::BootState:              return "boot measurement";
        case Tier1Prerequisite::NexusBinary:            return "approved binary";
        case Tier1Prerequisite::RuntimeMeasurements:    return "IMA anchoring";
        case Tier1Prerequisite::RuntimeSecurityProfile: return "runtime security profile";
        case Tier1Prerequisite::Uptime:                 return "uptime";
        case Tier1Prerequisite::MeshHealth:             return "mesh health";
        case Tier1Prerequisite::Incarnation:            return "current incarnation";
        case Tier1Prerequisite::Epoch:                  return "current epoch";
    }
    return "unknown prerequisite";
}

}  // namespace nexus::security
