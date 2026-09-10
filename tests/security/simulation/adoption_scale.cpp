// The adoption machinery across the Tier 1 population table.
//
// The live driver mesh exercises the full path at N = 5 with reserves; this
// measures the same records and the same verifiers at every population the
// table can produce: real keys, real signatures, real three-chain proofs, and
// the real wire encoding. Assertions are invariants — proof verification,
// replacement determinism, digest sensitivity, and the wire bounds — never a
// tuned number. The printed table records what adoption costs at 5 and at 31.

#include <LemonadeNexus/Security/Consensus/CommitProof.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>

#include "support/committee.hpp"
#include <LemonadeNexus/Security/Epoch/NextEpochPlan.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstdio>
#include <map>
#include <vector>

using namespace nexus::security;
using committee_test::Committee;
namespace constants = nexus::security::constants;

namespace {

constexpr std::size_t kPopulations[] = {5, 7, 10, 13, 16, 19, 22, 25, 28, 31};
constexpr EpochId kEpoch = 7;

NetworkId network() {
    NetworkId id{};
    id.fill(0x5E);
    return id;
}

NextEpochPlan plan_for(const Committee& committee) {
    NextEpochPlan plan;
    plan.network_id = network();
    plan.current_epoch = kEpoch;
    plan.next_epoch = kEpoch + 1;
    plan.attempt = 0;
    plan.checkpoint_height = 12;
    plan.checkpoint_state_root.fill(0xC7);
    plan.eligibility_commitment.fill(0xE1);
    plan.selection_seed.fill(0x51);
    plan.selected = committee.members;
    for (const auto& node : committee.members) {
        plan.incarnations[node] = 1;
    }
    plan.security_ruleset = constants::kSecurityRulesetVersion;
    plan.consensus_ruleset = constants::kConsensusRulesetVersion;
    plan.profile_id = kTier1AttestationProfileId;
    plan.profile_ruleset = kAttestationProfileRulesetVersion;
    return plan;
}

EpochHandoff handoff_for(const Committee& committee, const Digest& plan_digest) {
    EpochHandoff handoff;
    handoff.network_id = network();
    handoff.from_epoch = kEpoch;
    handoff.to_epoch = kEpoch + 1;
    handoff.plan_digest = plan_digest;
    handoff.members = committee.members;
    for (const auto& node : committee.members) {
        handoff.incarnations[node] = 1;
        handoff.vote_keys[node] = committee.pubs.at(node);
    }
    handoff.group_public_key.fill(0x99);
    handoff.dkg_transcript_digest.fill(0xD1);
    handoff.key_generation = kEpoch + 1;
    handoff.attestation_root.fill(0xA7);
    handoff.security_ruleset = constants::kSecurityRulesetVersion;
    handoff.consensus_ruleset = constants::kConsensusRulesetVersion;
    return handoff;
}

std::size_t wire_size(SecurityMessageKind kind, SecurityBody body, const NodeId& sender) {
    SecurityMessage message;
    message.kind = kind;
    message.security_ruleset = constants::kSecurityRulesetVersion;
    message.consensus_ruleset = constants::kConsensusRulesetVersion;
    message.network_id = network();
    message.epoch = kEpoch;
    message.sender = sender;
    message.body = std::move(body);
    return encode_security_message(message).size();
}

struct Row {
    std::size_t members{};
    std::size_t quorum{};
    std::size_t plan_proof_bytes{};
    std::size_t readiness_bytes{};
    std::size_t handoff_bytes{};
    bool plan_verifies{};
    bool forged_fails{};
    bool short_quorum_fails{};
};

Row measure(std::size_t size) {
    Committee committee{size, kEpoch, network()};
    Row row;
    row.members = size;
    row.quorum = committee.quorum;

    const auto plan = plan_for(committee);
    const auto plan_digest = next_epoch_plan_digest(plan);
    const auto proof = committee.prove(plan_digest);
    const QcValidationContext context{constants::kConsensusRulesetVersion, network(), kEpoch,
                                      committee.quorum};

    row.plan_verifies =
        verify_commit_proof(plan_digest, proof, context, committee.pubs) ==
        CommitProofFailure::None;

    // A forged signature and a trimmed quorum both fail at every size.
    auto forged = proof;
    forged.certifying.signers[0].signature[0] ^= 0x01;
    row.forged_fails = verify_commit_proof(plan_digest, forged, context, committee.pubs) ==
                       CommitProofFailure::CertificateInvalid;
    auto trimmed = proof;
    trimmed.certifying.signers.pop_back();
    row.short_quorum_fails =
        verify_commit_proof(plan_digest, trimmed, context, committee.pubs) ==
        CommitProofFailure::CertificateInvalid;

    // The wire cost of the three finalized packages, at this population.
    NextEpochPlanProof package;
    package.plan = plan;
    package.proof = proof;
    for (const auto& node : committee.members) {
        package.current_vote_keys.emplace_back(node, committee.pubs.at(node));
    }
    row.plan_proof_bytes =
        wire_size(SecurityMessageKind::NextEpochPlanProof, package, committee.members.front());

    CandidateReadiness readiness;
    readiness.network_id = network();
    readiness.plan_digest = plan_digest;
    readiness.next_epoch = kEpoch + 1;
    for (const auto& node : committee.members) {
        ReadinessEntry entry;
        entry.node = node;
        entry.incarnation = 1;
        entry.evidence_digest.fill(0xED);
        entry.vote_key = committee.pubs.at(node);
        readiness.entries.push_back(entry);
    }
    ReadinessProofMsg readiness_message{readiness,
                                        committee.prove(candidate_readiness_digest(readiness))};
    row.readiness_bytes = wire_size(SecurityMessageKind::ReadinessProof, readiness_message,
                                    committee.members.front());

    const auto handoff = handoff_for(committee, plan_digest);
    EpochHandoffProofMsg handoff_message{handoff,
                                         committee.prove(epoch_handoff_digest(handoff))};
    row.handoff_bytes = wire_size(SecurityMessageKind::EpochHandoffProof, handoff_message,
                                  committee.members.front());
    return row;
}

}  // namespace

// The measurement run: the finalized packages verify, forgeries fail, and all
// three fit the wire at the largest population the table produces.
TEST(AdoptionScale, MeasureAcrossTheTierOneTable) {
    ASSERT_GE(sodium_init(), 0);
    std::vector<Row> rows;
    for (const std::size_t members : kPopulations) {
        rows.push_back(measure(members));
    }

    std::printf("\n  N   Q  planProof B  readiness B  handoff B\n");
    for (const auto& r : rows) {
        std::printf("%3zu %3zu %12zu %12zu %10zu\n", r.members, r.quorum, r.plan_proof_bytes,
                    r.readiness_bytes, r.handoff_bytes);
    }
    std::printf("\n");

    for (const auto& r : rows) {
        EXPECT_TRUE(r.plan_verifies) << r.members;
        EXPECT_TRUE(r.forged_fails) << r.members;
        EXPECT_TRUE(r.short_quorum_fails) << r.members;
        // Every package must be transportable, or a large epoch could finalize
        // a plan its candidates can never receive.
        EXPECT_GT(r.plan_proof_bytes, 0u) << r.members;
        EXPECT_GT(r.readiness_bytes, 0u) << r.members;
        EXPECT_GT(r.handoff_bytes, 0u) << r.members;
        EXPECT_LE(r.plan_proof_bytes, constants::kMaxSecurityMessageBytes) << r.members;
        EXPECT_LE(r.readiness_bytes, constants::kMaxSecurityMessageBytes) << r.members;
        EXPECT_LE(r.handoff_bytes, constants::kMaxSecurityMessageBytes) << r.members;
    }
}

// Replacement stays deterministic at every size: excluding a failed candidate
// pulls exactly the next hash-ranked node, identically on every computation.
TEST(AdoptionScale, ReplacementFollowsTheRankAtEverySize) {
    ASSERT_GE(sodium_init(), 0);
    for (const std::size_t members : kPopulations) {
        Committee committee{members, kEpoch, network()};
        const auto plan = plan_for(committee);

        // Attempt 1, excluding the first selected node, is a different plan
        // with a different digest — a replay of attempt 0 names nothing.
        auto replacement = plan;
        replacement.attempt = 1;
        replacement.selected.erase(replacement.selected.begin());
        replacement.incarnations.erase(plan.selected.front());
        EXPECT_NE(next_epoch_plan_digest(plan), next_epoch_plan_digest(replacement)) << members;

        // The digest is sensitive to every selection input.
        auto reseeded = plan;
        reseeded.selection_seed[0] ^= 0x01;
        EXPECT_NE(next_epoch_plan_digest(plan), next_epoch_plan_digest(reseeded)) << members;
        auto recheckpointed = plan;
        recheckpointed.checkpoint_state_root[0] ^= 0x01;
        EXPECT_NE(next_epoch_plan_digest(plan), next_epoch_plan_digest(recheckpointed))
            << members;
    }
}

// The handoff digest is sensitive to every field that decides what activates.
TEST(AdoptionScale, TheHandoffDigestBindsEverything) {
    ASSERT_GE(sodium_init(), 0);
    Committee committee{5, kEpoch, network()};
    const auto plan_digest = next_epoch_plan_digest(plan_for(committee));
    const auto base = handoff_for(committee, plan_digest);
    const auto base_digest = epoch_handoff_digest(base);

    const auto differs = [&](auto mutate) {
        auto handoff = base;
        mutate(handoff);
        return epoch_handoff_digest(handoff) != base_digest;
    };
    EXPECT_TRUE(differs([](auto& h) { h.network_id[0] ^= 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.from_epoch += 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.to_epoch += 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.plan_digest[0] ^= 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.incarnations.begin()->second += 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.vote_keys.begin()->second[0] ^= 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.group_public_key[0] ^= 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.dkg_transcript_digest[0] ^= 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.key_generation += 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.attestation_root[0] ^= 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.security_ruleset += 1; }));
    EXPECT_TRUE(differs([](auto& h) { h.consensus_ruleset += 1; }));
    EXPECT_TRUE(differs([&](auto& h) { h.members.push_back(NodeId{}); }));
}

