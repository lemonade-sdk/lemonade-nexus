#include <LemonadeNexus/Security/Policy/Tier1Evidence.hpp>

namespace nexus::security {

Tier1EvidenceState tier1_evidence_state(const AttestationVerdict& verdict,
                                         const Tier1MeshFacts& facts) {
    Tier1EvidenceState state;

    // --- what the attestation chain proved -----------------------------------
    // Each comes from the link that actually ran. None is inferred from
    // verdict.passed, so a verdict that stopped early leaves the later
    // prerequisites false.
    state.node_identity_valid    = verdict.links.identity_signature_valid;
    state.snp_valid              = verdict.links.snp_signature_valid &&
                                   verdict.links.snp_policy_valid;
    state.vtpm_valid             = verdict.links.vtpm_bound;
    state.quote_fresh            = verdict.links.quote_fresh;
    state.boot_state_valid       = verdict.links.boot_state_valid;
    state.binary_valid           = verdict.links.binary_approved;
    state.ima_valid              = verdict.links.ima_anchored;
    state.runtime_profile_valid  = verdict.links.runtime_profile_valid;

    // --- what only the mesh knows --------------------------------------------
    state.certificate_valid = facts.certificate_valid;
    state.uptime_valid      = facts.uptime_valid;
    state.mesh_health_valid = facts.mesh_health_valid;

    // A verdict for another epoch or another incarnation is stale. An absent
    // current value proves nothing, so it leaves the prerequisite false.
    state.epoch_current =
        facts.current_epoch.has_value() && verdict.epoch == *facts.current_epoch;
    state.incarnation_current =
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
