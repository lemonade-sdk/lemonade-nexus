#include <LemonadeNexus/Security/Policy/Tier1Eligibility.hpp>

#include <gtest/gtest.h>

using nexus::security::Tier1Eligibility;
using nexus::security::Tier1EligibilityPolicy;
using nexus::security::Tier1EvidenceState;
using nexus::security::Tier1Prerequisite;

namespace {

Tier1EvidenceState all_valid() {
    Tier1EvidenceState state;
    state.platform_profile_valid = true;
    state.node_identity_valid = true;
    state.certificate_valid = true;
    state.snp_valid = true;
    state.tcb_valid = true;
    state.vtpm_valid = true;
    state.quote_fresh = true;
    state.boot_state_valid = true;
    state.binary_valid = true;
    state.ima_valid = true;
    state.runtime_profile_valid = true;
    state.uptime_valid = true;
    state.mesh_health_valid = true;
    state.incarnation_current = true;
    state.epoch_current = true;
    return state;
}

struct FieldCase {
    Tier1Prerequisite prerequisite;
    bool Tier1EvidenceState::* field;
};

constexpr FieldCase kFields[] = {
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

TEST(Tier1Eligibility, AllPrerequisitesPassGivesEligible) {
    EXPECT_EQ(Tier1EligibilityPolicy::evaluate(all_valid()), Tier1Eligibility::Eligible);
    EXPECT_TRUE(Tier1EligibilityPolicy::failed_prerequisites(all_valid()).empty());
}

TEST(Tier1Eligibility, DefaultStateIsIneligible) {
    // Fail closed: evidence that was never collected is failed evidence.
    const Tier1EvidenceState state;
    EXPECT_EQ(Tier1EligibilityPolicy::evaluate(state), Tier1Eligibility::Ineligible);
    EXPECT_EQ(Tier1EligibilityPolicy::failed_prerequisites(state).size(), 15u);
}

TEST(Tier1Eligibility, AnySingleFailedPrerequisiteGivesIneligible) {
    for (const auto& field_case : kFields) {
        Tier1EvidenceState state = all_valid();
        state.*field_case.field = false;
        EXPECT_EQ(Tier1EligibilityPolicy::evaluate(state), Tier1Eligibility::Ineligible);

        const auto failed = Tier1EligibilityPolicy::failed_prerequisites(state);
        ASSERT_EQ(failed.size(), 1u);
        EXPECT_EQ(failed[0], field_case.prerequisite);
    }
}

TEST(Tier1Eligibility, EvaluationIsDeterministic) {
    Tier1EvidenceState state = all_valid();
    state.snp_valid = false;
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(Tier1EligibilityPolicy::evaluate(state), Tier1Eligibility::Ineligible);
    }
}

}  // namespace
