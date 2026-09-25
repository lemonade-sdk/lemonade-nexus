#include <LemonadeNexus/Security/Policy/Tier1Eligibility.hpp>

namespace nexus::security {

namespace {

struct PrerequisiteCheck {
    Tier1Prerequisite prerequisite;
    bool Tier1EvidenceState::* field;
};

constexpr PrerequisiteCheck kChecks[] = {
    {Tier1Prerequisite::PlatformProfile, &Tier1EvidenceState::platform_profile_valid},
    {Tier1Prerequisite::NodeIdentity, &Tier1EvidenceState::node_identity_valid},
    {Tier1Prerequisite::Certificate, &Tier1EvidenceState::certificate_valid},
    {Tier1Prerequisite::ConfidentialCompute, &Tier1EvidenceState::snp_valid},
    {Tier1Prerequisite::PlatformTcb, &Tier1EvidenceState::tcb_valid},
    {Tier1Prerequisite::Vtpm, &Tier1EvidenceState::vtpm_valid},
    {Tier1Prerequisite::AttestationFreshness, &Tier1EvidenceState::quote_fresh},
    {Tier1Prerequisite::BootState, &Tier1EvidenceState::boot_state_valid},
    {Tier1Prerequisite::NexusBinary, &Tier1EvidenceState::binary_valid},
    {Tier1Prerequisite::RuntimeMeasurements, &Tier1EvidenceState::ima_valid},
    {Tier1Prerequisite::RuntimeSecurityProfile, &Tier1EvidenceState::runtime_profile_valid},
    {Tier1Prerequisite::Uptime, &Tier1EvidenceState::uptime_valid},
    {Tier1Prerequisite::MeshHealth, &Tier1EvidenceState::mesh_health_valid},
    {Tier1Prerequisite::Incarnation, &Tier1EvidenceState::incarnation_current},
    {Tier1Prerequisite::Epoch, &Tier1EvidenceState::epoch_current},
};

}  // namespace

Tier1Eligibility Tier1EligibilityPolicy::evaluate(const Tier1EvidenceState& state) {
    for (const auto& check : kChecks) {
        if (!(state.*check.field)) {
            return Tier1Eligibility::Ineligible;
        }
    }
    return Tier1Eligibility::Eligible;
}

std::vector<Tier1Prerequisite> Tier1EligibilityPolicy::failed_prerequisites(
    const Tier1EvidenceState& state) {
    std::vector<Tier1Prerequisite> failed;
    for (const auto& check : kChecks) {
        if (!(state.*check.field)) {
            failed.push_back(check.prerequisite);
        }
    }
    return failed;
}

}  // namespace nexus::security
