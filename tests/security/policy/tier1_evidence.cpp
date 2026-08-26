// The bridge from one attestation verdict to a Tier 1 decision.
//
// The property under test is that Tier 1 is decided from named prerequisites,
// never from AttestationVerdict::passed. A verdict that passed the platform
// chain still has to clear the facts only the mesh knows, and a prerequisite
// with no producer keeps a node ineligible.

#include <LemonadeNexus/Security/Policy/Tier1Evidence.hpp>

#include <gtest/gtest.h>

#include <algorithm>

using nexus::security::AttestationFailure;
using nexus::security::AttestationVerdict;
using nexus::security::Tier1Eligibility;
using nexus::security::Tier1EligibilityPolicy;
using nexus::security::Tier1EvidenceState;
using nexus::security::Tier1MeshFacts;
using nexus::security::Tier1Prerequisite;
using nexus::security::tier1_eligibility;
using nexus::security::tier1_evidence_state;
using nexus::security::tier1_prerequisite_name;

namespace {

/// A verdict with every attestation link proved.
AttestationVerdict complete_verdict() {
    AttestationVerdict verdict;
    verdict.passed = true;
    verdict.failure = AttestationFailure::None;
    verdict.epoch = 7;
    verdict.incarnation = 3;
    verdict.links.identity_signature_valid = true;
    verdict.links.snp_signature_valid = true;
    verdict.links.snp_policy_valid = true;
    verdict.links.vtpm_bound = true;
    verdict.links.quote_fresh = true;
    verdict.links.boot_state_valid = true;
    verdict.links.ima_anchored = true;
    verdict.links.binary_approved = true;
    verdict.links.runtime_profile_valid = true;
    return verdict;
}

/// The facts the mesh supplies, all satisfied and matching the verdict.
Tier1MeshFacts complete_facts() {
    Tier1MeshFacts facts;
    facts.certificate_valid = true;
    facts.uptime_valid = true;
    facts.mesh_health_valid = true;
    facts.current_epoch = 7;
    facts.current_incarnation = 3;
    return facts;
}

bool fails(const AttestationVerdict& verdict, const Tier1MeshFacts& facts,
           Tier1Prerequisite prerequisite) {
    const auto failed =
        Tier1EligibilityPolicy::failed_prerequisites(tier1_evidence_state(verdict, facts));
    return std::find(failed.begin(), failed.end(), prerequisite) != failed.end();
}

}  // namespace

TEST(Tier1Evidence, EverythingProvedIsEligible) {
    EXPECT_EQ(tier1_eligibility(complete_verdict(), complete_facts()),
              Tier1Eligibility::Eligible);
}

// The headline property: passing the platform chain is not the Tier 1 decision.
TEST(Tier1Evidence, APassedVerdictAloneIsNotEnough) {
    AttestationVerdict verdict = complete_verdict();
    ASSERT_TRUE(verdict.passed);

    // Default mesh facts: no certificate, no uptime, no mesh health, and no
    // current epoch or incarnation to compare against.
    EXPECT_EQ(tier1_eligibility(verdict, Tier1MeshFacts{}), Tier1Eligibility::Ineligible);
}

// A verdict that never ran a link leaves it false, so `passed` cannot be used
// to infer a prerequisite the chain did not actually prove.
TEST(Tier1Evidence, NoPrerequisiteIsInferredFromPassed) {
    AttestationVerdict verdict;
    verdict.passed = true;          // claims success, proves nothing
    verdict.epoch = 7;
    verdict.incarnation = 3;

    const Tier1EvidenceState state = tier1_evidence_state(verdict, complete_facts());
    EXPECT_FALSE(state.node_identity_valid);
    EXPECT_FALSE(state.snp_valid);
    EXPECT_FALSE(state.vtpm_valid);
    EXPECT_FALSE(state.quote_fresh);
    EXPECT_FALSE(state.boot_state_valid);
    EXPECT_FALSE(state.binary_valid);
    EXPECT_FALSE(state.ima_valid);
    EXPECT_FALSE(state.runtime_profile_valid);
    EXPECT_EQ(Tier1EligibilityPolicy::evaluate(state), Tier1Eligibility::Ineligible);
}

TEST(Tier1Evidence, EveryAttestationLinkIsSeparatelyRequired) {
    const auto facts = complete_facts();
    {
        auto v = complete_verdict(); v.links.identity_signature_valid = false;
        EXPECT_TRUE(fails(v, facts, Tier1Prerequisite::NodeIdentity));
    }
    {   // Either half of the SNP proof is enough to lose it.
        auto v = complete_verdict(); v.links.snp_signature_valid = false;
        EXPECT_TRUE(fails(v, facts, Tier1Prerequisite::ConfidentialCompute));
        v = complete_verdict(); v.links.snp_policy_valid = false;
        EXPECT_TRUE(fails(v, facts, Tier1Prerequisite::ConfidentialCompute));
    }
    {
        auto v = complete_verdict(); v.links.vtpm_bound = false;
        EXPECT_TRUE(fails(v, facts, Tier1Prerequisite::Vtpm));
    }
    {
        auto v = complete_verdict(); v.links.quote_fresh = false;
        EXPECT_TRUE(fails(v, facts, Tier1Prerequisite::AttestationFreshness));
    }
    {
        auto v = complete_verdict(); v.links.boot_state_valid = false;
        EXPECT_TRUE(fails(v, facts, Tier1Prerequisite::BootState));
    }
    {
        auto v = complete_verdict(); v.links.binary_approved = false;
        EXPECT_TRUE(fails(v, facts, Tier1Prerequisite::NexusBinary));
    }
    {
        auto v = complete_verdict(); v.links.ima_anchored = false;
        EXPECT_TRUE(fails(v, facts, Tier1Prerequisite::RuntimeMeasurements));
    }
    {
        auto v = complete_verdict(); v.links.runtime_profile_valid = false;
        EXPECT_TRUE(fails(v, facts, Tier1Prerequisite::RuntimeSecurityProfile));
    }
}

TEST(Tier1Evidence, EveryMeshFactIsSeparatelyRequired) {
    const auto verdict = complete_verdict();
    {
        auto f = complete_facts(); f.certificate_valid = false;
        EXPECT_TRUE(fails(verdict, f, Tier1Prerequisite::Certificate));
    }
    {
        auto f = complete_facts(); f.uptime_valid = false;
        EXPECT_TRUE(fails(verdict, f, Tier1Prerequisite::Uptime));
    }
    {
        auto f = complete_facts(); f.mesh_health_valid = false;
        EXPECT_TRUE(fails(verdict, f, Tier1Prerequisite::MeshHealth));
    }
}

// A verdict from another epoch or another incarnation is stale. It cannot
// confer Tier 1 even though every attestation link in it held.
TEST(Tier1Evidence, StaleEpochOrIncarnationLosesEligibility) {
    const auto verdict = complete_verdict();
    {
        auto f = complete_facts(); f.current_epoch = verdict.epoch + 1;
        EXPECT_TRUE(fails(verdict, f, Tier1Prerequisite::Epoch));
        EXPECT_EQ(tier1_eligibility(verdict, f), Tier1Eligibility::Ineligible);
    }
    {
        auto f = complete_facts(); f.current_incarnation = verdict.incarnation + 1;
        EXPECT_TRUE(fails(verdict, f, Tier1Prerequisite::Incarnation));
    }
}

// An absent current epoch or incarnation proves nothing, so it must not read as
// a match. This is the difference between "unknown" and "equal".
TEST(Tier1Evidence, AbsentCurrentEpochOrIncarnationFailsClosed) {
    const auto verdict = complete_verdict();
    {
        auto f = complete_facts(); f.current_epoch.reset();
        EXPECT_TRUE(fails(verdict, f, Tier1Prerequisite::Epoch));
    }
    {
        auto f = complete_facts(); f.current_incarnation.reset();
        EXPECT_TRUE(fails(verdict, f, Tier1Prerequisite::Incarnation));
    }
    {   // Zero is a real value, not "unknown": a verdict for epoch 0 against a
        // current epoch of 0 matches.
        auto v = complete_verdict(); v.epoch = 0; v.incarnation = 0;
        auto f = complete_facts(); f.current_epoch = 0; f.current_incarnation = 0;
        EXPECT_EQ(tier1_eligibility(v, f), Tier1Eligibility::Eligible);
    }
}

// Uptime and mesh health have no producer in the tree yet. This test exists to
// fail if one is ever wired in without being reflected here.
TEST(Tier1Evidence, UnproducedPrerequisitesKeepANodeIneligible) {
    auto facts = complete_facts();
    facts.uptime_valid = false;
    facts.mesh_health_valid = false;
    EXPECT_EQ(tier1_eligibility(complete_verdict(), facts), Tier1Eligibility::Ineligible);
}

TEST(Tier1Evidence, EveryPrerequisiteNamesItself) {
    for (const auto p : {Tier1Prerequisite::NodeIdentity, Tier1Prerequisite::Certificate,
                         Tier1Prerequisite::ConfidentialCompute, Tier1Prerequisite::Vtpm,
                         Tier1Prerequisite::AttestationFreshness, Tier1Prerequisite::BootState,
                         Tier1Prerequisite::NexusBinary, Tier1Prerequisite::RuntimeMeasurements,
                         Tier1Prerequisite::RuntimeSecurityProfile, Tier1Prerequisite::Uptime,
                         Tier1Prerequisite::MeshHealth, Tier1Prerequisite::Incarnation,
                         Tier1Prerequisite::Epoch}) {
        EXPECT_FALSE(tier1_prerequisite_name(p).empty());
        EXPECT_NE(tier1_prerequisite_name(p), "unknown prerequisite");
    }
}
