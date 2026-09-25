// The bridge from one attestation verdict to a Tier 1 decision.
//
// The property under test is that Tier 1 is decided from named prerequisites,
// never from AttestationVerdict::passed. A verdict that passed the platform
// chain still has to clear the facts only the mesh knows, and a prerequisite
// with no producer keeps a node ineligible.

#include <LemonadeNexus/Security/Policy/Tier1Evidence.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <utility>

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

/// A verdict with every platform claim proved by an approved provider.
AttestationVerdict complete_verdict() {
    AttestationVerdict verdict;
    verdict.passed = true;
    verdict.failure = AttestationFailure::None;
    verdict.epoch = 7;
    verdict.incarnation = 3;
    verdict.claims.profile_id = nexus::security::kTier1AttestationProfileId;
    verdict.claims.profile_ruleset = nexus::security::kAttestationProfileRulesetVersion;
    verdict.claims.hardware_confidentiality_valid = true;
    verdict.claims.platform_identity_valid = true;
    verdict.claims.evidence_freshness_valid = true;
    verdict.claims.node_identity_binding_valid = true;
    verdict.claims.incarnation_binding_valid = true;
    verdict.claims.epoch_binding_valid = true;
    verdict.claims.security_ruleset_binding_valid = true;
    verdict.claims.boot_integrity_valid = true;
    verdict.claims.tcb_valid = true;
    verdict.claims.attestation_profile_valid = true;
    verdict.claims.ima_anchored = true;
    verdict.claims.binary_approved = true;
    verdict.claims.runtime_profile_enforced = true;
    verdict.claims.runtime_integrity_valid = true;
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

TEST(Tier1Evidence, EveryPlatformClaimIsSeparatelyRequired) {
    const auto facts = complete_facts();
    struct Case {
        const char* label;
        bool nexus::security::VerifiedPlatformClaims::* claim;
        Tier1Prerequisite prerequisite;
    };
    using Claims = nexus::security::VerifiedPlatformClaims;
    const Case cases[] = {
        {"profile", &Claims::attestation_profile_valid, Tier1Prerequisite::PlatformProfile},
        {"ruleset", &Claims::security_ruleset_binding_valid,
         Tier1Prerequisite::PlatformProfile},
        {"identity", &Claims::node_identity_binding_valid, Tier1Prerequisite::NodeIdentity},
        {"snp", &Claims::hardware_confidentiality_valid,
         Tier1Prerequisite::ConfidentialCompute},
        {"tcb", &Claims::tcb_valid, Tier1Prerequisite::PlatformTcb},
        {"vtpm", &Claims::platform_identity_valid, Tier1Prerequisite::Vtpm},
        {"freshness", &Claims::evidence_freshness_valid,
         Tier1Prerequisite::AttestationFreshness},
        {"boot", &Claims::boot_integrity_valid, Tier1Prerequisite::BootState},
        {"epoch binding", &Claims::epoch_binding_valid, Tier1Prerequisite::Epoch},
        {"incarnation binding", &Claims::incarnation_binding_valid,
         Tier1Prerequisite::Incarnation},
    };
    for (const auto& entry : cases) {
        auto v = complete_verdict();
        v.claims.*entry.claim = false;
        EXPECT_TRUE(fails(v, facts, entry.prerequisite)) << entry.label;
        EXPECT_EQ(tier1_eligibility(v, facts), Tier1Eligibility::Ineligible) << entry.label;
    }
}

// The three runtime prerequisites are separate. One composite runtime claim
// cannot tell them apart, so each sub-fact is dropped with the composite.
TEST(Tier1Evidence, EachRuntimeStepIsSeparatelyRequired) {
    const auto facts = complete_facts();
    using Claims = nexus::security::VerifiedPlatformClaims;
    const std::pair<bool Claims::*, Tier1Prerequisite> steps[] = {
        {&Claims::ima_anchored, Tier1Prerequisite::RuntimeMeasurements},
        {&Claims::binary_approved, Tier1Prerequisite::NexusBinary},
        {&Claims::runtime_profile_enforced, Tier1Prerequisite::RuntimeSecurityProfile},
    };
    for (const auto& [field, prerequisite] : steps) {
        auto v = complete_verdict();
        v.claims.*field = false;
        v.claims.runtime_integrity_valid = false;  // the conjunction follows
        EXPECT_TRUE(fails(v, facts, prerequisite));
        EXPECT_EQ(tier1_eligibility(v, facts), Tier1Eligibility::Ineligible);
    }
}

// A provider that reports runtime integrity without the steps behind it is
// broken, not persuasive. Its whole claim set is refused rather than trusted
// in part.
TEST(Tier1Evidence, InconsistentClaimsProveNothing) {
    auto v = complete_verdict();
    v.claims.ima_anchored = false;  // runtime_integrity_valid stays true

    const Tier1EvidenceState state = tier1_evidence_state(v, complete_facts());
    EXPECT_EQ(Tier1EligibilityPolicy::failed_prerequisites(state).size(), 15u);
    EXPECT_EQ(Tier1EligibilityPolicy::evaluate(state), Tier1Eligibility::Ineligible);
}

// Claims with no provider behind them are claims from nowhere.
TEST(Tier1Evidence, ClaimsWithoutAProviderProveNothing) {
    auto v = complete_verdict();
    v.claims.profile_id = nexus::security::AttestationProfileId::Unknown;

    const Tier1EvidenceState state = tier1_evidence_state(v, complete_facts());
    EXPECT_EQ(Tier1EligibilityPolicy::evaluate(state), Tier1Eligibility::Ineligible);
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
    for (const auto p : {Tier1Prerequisite::PlatformProfile, Tier1Prerequisite::PlatformTcb,
                         Tier1Prerequisite::NodeIdentity, Tier1Prerequisite::Certificate,
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

// --- the mesh/platform split -----------------------------------------------

// A platform provider proves what its hardware attests. How a node has behaved
// on the mesh is not that, and no provider may supply it. VerifiedPlatformClaims
// carries no field for either fact, so this is a structural property; the test
// pins the consequence.
TEST(Tier1Evidence, NoProviderCanSupplyAMeshFact) {
    const AttestationVerdict verdict = complete_verdict();

    Tier1MeshFacts without_uptime = complete_facts();
    without_uptime.uptime_valid = false;
    EXPECT_TRUE(fails(verdict, without_uptime, Tier1Prerequisite::Uptime));
    EXPECT_EQ(tier1_eligibility(verdict, without_uptime), Tier1Eligibility::Ineligible);

    Tier1MeshFacts without_health = complete_facts();
    without_health.mesh_health_valid = false;
    EXPECT_TRUE(fails(verdict, without_health, Tier1Prerequisite::MeshHealth));
    EXPECT_EQ(tier1_eligibility(verdict, without_health), Tier1Eligibility::Ineligible);

    Tier1MeshFacts without_certificate = complete_facts();
    without_certificate.certificate_valid = false;
    EXPECT_TRUE(fails(verdict, without_certificate, Tier1Prerequisite::Certificate));
}

// Runtime integrity does not rest on the self-reported no_new_privs and seccomp
// fields. They count only alongside an IMA log anchored in a quoted PCR and a
// binary on the approved release list, so a process claiming a hardened runtime
// while its binary is unmeasured proves nothing.
TEST(Tier1Evidence, ASelfReportedRuntimeProfileIsNotTheTrustBasis) {
    AttestationVerdict verdict = complete_verdict();
    verdict.claims.ima_anchored = false;
    verdict.claims.binary_approved = false;
    verdict.claims.runtime_integrity_valid = false;
    ASSERT_TRUE(verdict.claims.runtime_profile_enforced);

    const Tier1EvidenceState state = tier1_evidence_state(verdict, complete_facts());
    EXPECT_TRUE(state.runtime_profile_valid);
    EXPECT_FALSE(state.ima_valid);
    EXPECT_FALSE(state.binary_valid);
    EXPECT_EQ(Tier1EligibilityPolicy::evaluate(state), Tier1Eligibility::Ineligible);
}

// A root-signed transport certificate is a mesh membership fact: it says the
// peer is an authenticated server this deployment's root vouched for. It is one
// of fifteen prerequisites and it implies none of the others, so on its own it
// confers no eligibility and therefore no authority.
TEST(Tier1Evidence, ACertificateAloneConfersNothing) {
    AttestationVerdict nothing_proved;
    nothing_proved.passed = true;
    Tier1MeshFacts facts;
    facts.certificate_valid = true;

    const Tier1EvidenceState state = tier1_evidence_state(nothing_proved, facts);
    EXPECT_TRUE(state.certificate_valid);
    EXPECT_EQ(Tier1EligibilityPolicy::evaluate(state), Tier1Eligibility::Ineligible);

    // Every other prerequisite is still outstanding.
    const auto failed = Tier1EligibilityPolicy::failed_prerequisites(state);
    EXPECT_EQ(failed.size(), 14u);
    EXPECT_TRUE(std::find(failed.begin(), failed.end(), Tier1Prerequisite::Certificate) ==
                failed.end());

    // And removing it from an otherwise complete state is what makes it a
    // prerequisite rather than a formality.
    auto without = complete_facts();
    without.certificate_valid = false;
    EXPECT_EQ(tier1_eligibility(complete_verdict(), without), Tier1Eligibility::Ineligible);
}
