#pragma once

// The security contract every Tier 1-capable provider must satisfy.
//
// Providers verify different evidence formats. What they must not differ on is
// the set of ways a candidate can fail: a bundle for another network, another
// node, another epoch or another challenge is refused by all of them, and a
// claim none of them proved is carried by none of them.
//
// The harness asserts claims and failures only. It never asserts eligibility —
// the provider proves claims and Tier1EligibilityPolicy combines them, so
// duplicating the policy here would let a provider test disagree with the
// policy about who is eligible.

#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>

#include <gtest/gtest.h>

#include <functional>
#include <optional>
#include <string>

namespace nexus_test {

/// One provider under test, described by what it needs rather than by how it
/// works. A new provider supplies these four things and inherits the contract.
struct ConformanceSubject {
    std::string name;
    nexus::security::AttestationProfileId profile_id{};

    /// A verifier holding the compiled provider set this subject belongs to.
    std::function<nexus::security::AttestationVerifier()> verifier;

    /// A challenge this subject's profile would issue.
    std::function<nexus::security::AttestationChallenge()> challenge;

    /// A well-formed answer to that challenge, signed. It need not pass the
    /// platform chain — the contract is about refusals, not about a passing
    /// bundle, which off-platform tests cannot build anyway.
    std::function<nexus::security::AttestationEvidence(
        const nexus::security::AttestationChallenge&)> answer;

    /// Re-signs after a test mutates the bundle.
    std::function<void(nexus::security::AttestationEvidence&)> resign;
};

/// Every refusal the contract requires, plus the claim rules. Call once per
/// Tier 1-capable provider.
inline void run_provider_conformance(const ConformanceSubject& subject) {
    using namespace nexus::security;
    const auto label = [&subject](const char* what) {
        return subject.name + ": " + what;
    };

    const AttestationChallenge base = subject.challenge();
    const AttestationVerifier verifier = subject.verifier();

    const auto examine = [&](const AttestationChallenge& challenge,
                             const AttestationEvidence& evidence) {
        return verifier.examine(challenge, evidence);
    };

    // Readiness runs before any binding check, so a provider that cannot decide
    // answers everything the same way. That is the contract for it: refuse, and
    // prove nothing. The per-binding failures below are only observable once a
    // provider is ready.
    const PlatformEvidenceProvider* provider = verifier.provider_for(subject.profile_id);
    ASSERT_NE(provider, nullptr) << label("provider present");
    const std::optional<AttestationFailure> refusal = provider->readiness();

    // --- a profile nothing implements --------------------------------------
    {
        AttestationChallenge unknown = base;
        unknown.profile_id = AttestationProfileId::Unknown;
        AttestationEvidence evidence = subject.answer(unknown);
        const auto verdict = examine(unknown, evidence);
        EXPECT_FALSE(verdict.passed) << label("unknown profile");
        EXPECT_EQ(verdict.failure, AttestationFailure::ProviderUnknown)
            << label("unknown profile");
    }

    // --- the bindings every profile shares ---------------------------------
    struct Case {
        const char* what;
        std::function<void(AttestationEvidence&)> mutate;
        AttestationFailure expected;
    };
    const Case cases[] = {
        {"wrong network",
         [](AttestationEvidence& e) { e.network_id[0] ^= 1; },
         AttestationFailure::NetworkMismatch},
        {"wrong security ruleset",
         [](AttestationEvidence& e) { e.security_ruleset += 1; },
         AttestationFailure::RulesetMismatch},
        {"wrong consensus ruleset",
         [](AttestationEvidence& e) { e.consensus_ruleset += 1; },
         AttestationFailure::RulesetMismatch},
        {"wrong profile ruleset",
         [](AttestationEvidence& e) { e.profile_ruleset += 1; },
         AttestationFailure::ProfileRulesetMismatch},
        {"wrong epoch",
         [](AttestationEvidence& e) { e.epoch += 1; },
         AttestationFailure::EpochMismatch},
        {"wrong challenge",
         [](AttestationEvidence& e) { e.challenge_digest[0] ^= 1; },
         AttestationFailure::ChallengeMismatch},
        {"wrong node",
         [](AttestationEvidence& e) { e.node_id.bytes[0] ^= 1; },
         AttestationFailure::IdentityMismatch},
        {"wrong incarnation",
         [](AttestationEvidence& e) { e.incarnation += 1; },
         AttestationFailure::IncarnationStale},
    };
    for (const auto& entry : cases) {
        AttestationEvidence evidence = subject.answer(base);
        entry.mutate(evidence);
        subject.resign(evidence);
        const auto verdict = examine(base, evidence);
        EXPECT_FALSE(verdict.passed) << label(entry.what);
        EXPECT_EQ(verdict.failure, refusal.value_or(entry.expected)) << label(entry.what);
        EXPECT_TRUE(platform_claims_are_consistent(verdict.claims)) << label(entry.what);
    }

    // --- unproved claims stay unproved -------------------------------------
    // A bundle this provider cannot fully verify must not carry the claims it
    // never reached. Which claim survives depends on where the chain stopped;
    // what the contract fixes is that an unreached step leaves its claim false
    // and that the whole verdict is refused.
    {
        AttestationEvidence evidence = subject.answer(base);
        const auto verdict = examine(base, evidence);
        if (!verdict.passed) {
            EXPECT_FALSE(all_platform_claims_proved(verdict.claims)) << label("claims");
        }
        // Whatever a provider returns, it must be self-consistent: runtime
        // integrity is exactly its three steps, and no claim is set by a
        // provider that never identified itself.
        EXPECT_TRUE(platform_claims_are_consistent(verdict.claims))
            << label("claim consistency");
    }

    // --- not ready proves nothing ------------------------------------------
    if (refusal.has_value()) {
        AttestationEvidence evidence = subject.answer(base);
        const auto verdict = examine(base, evidence);
        EXPECT_EQ(verdict.failure, *refusal) << label("not ready");
        EXPECT_EQ(missing_platform_claims(verdict.claims).size(), 11u)
            << label("not ready proves nothing");
    }
}

}  // namespace nexus_test
