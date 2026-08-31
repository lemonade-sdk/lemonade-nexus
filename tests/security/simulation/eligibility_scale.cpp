// The eligibility rules across the whole Tier 1 population table.
//
// scale.cpp measures what consensus costs. This measures what eligibility
// costs: for every population the table can produce, how many witnesses each
// kind of subject needs, how many are actually reachable as members go away,
// and which scenarios leave the mesh unable to rotate.
//
// The distinction the table records is between safety and liveness. A fact that
// cannot form is liveness unavailable — nothing rotates, the current epoch runs
// on, and no threshold moves. A fact that forms without its witnesses would be
// a safety failure, and the assertions here are only ever about that: no
// scenario may produce a fact below its bar, and no bar may fall to where the
// Byzantine set alone could reach it.
//
// The rules under test are the production ones. Nothing is simulated except who
// is online and what they saw.

#include <LemonadeNexus/Security/Eligibility/EligibilityLedger.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstdio>
#include <string>
#include <vector>

using namespace nexus::security;
namespace constants = nexus::security::constants;

namespace {

constexpr std::size_t kPopulations[] = {5, 7, 10, 13, 16, 19, 22, 25, 28, 31};
constexpr EpochId kEpoch = 4;

struct Node {
    nexus::crypto::Ed25519Keypair identity;
    NodeId id;
};

Node make_node(uint8_t seed_byte) {
    Node node;
    std::array<uint8_t, crypto_sign_SEEDBYTES> seed{};
    seed.fill(seed_byte);
    crypto_sign_seed_keypair(node.identity.public_key.data(), node.identity.private_key.data(),
                             seed.data());
    node.id.bytes = node.identity.public_key;
    return node;
}

NetworkId network() {
    NetworkId id{};
    id.fill(0x5E);
    return id;
}

Digest digest_of(uint8_t byte) {
    Digest value{};
    value.fill(byte);
    return value;
}

VerifiedPlatformClaims proved_claims() {
    VerifiedPlatformClaims claims;
    claims.profile_id = kTier1AttestationProfileId;
    claims.profile_ruleset = kAttestationProfileRulesetVersion;
    claims.hardware_confidentiality_valid = true;
    claims.platform_identity_valid = true;
    claims.evidence_freshness_valid = true;
    claims.node_identity_binding_valid = true;
    claims.incarnation_binding_valid = true;
    claims.epoch_binding_valid = true;
    claims.security_ruleset_binding_valid = true;
    claims.boot_integrity_valid = true;
    claims.tcb_valid = true;
    claims.attestation_profile_valid = true;
    claims.ima_anchored = true;
    claims.binary_approved = true;
    claims.runtime_profile_enforced = true;
    claims.runtime_integrity_valid = true;
    return claims;
}

/// One mesh at one population: real identities, the real context, the real
/// ledger. `online` names the members that still observe.
struct Mesh {
    explicit Mesh(std::size_t members) {
        for (std::size_t i = 0; i < members; ++i) {
            nodes.push_back(make_node(static_cast<uint8_t>(i + 1)));
        }
        // The Tier 2 candidate: authenticated, outside the committee.
        candidate = make_node(0xF0);
        std::vector<NodeId> ids;
        for (const auto& node : nodes) ids.push_back(node.id);
        context = established_fact_context(network(), kEpoch, ids);
    }

    [[nodiscard]] EligibilityObservation attestation(const Node& observer, const NodeId& subject,
                                                      uint8_t seed, Height height,
                                                      IncarnationId incarnation = 1) const {
        EligibilityObservation observation;
        observation.network_id = network();
        observation.epoch = kEpoch;
        observation.subject = subject;
        observation.subject_incarnation = incarnation;
        observation.kind = ObservationKind::Attestation;
        observation.attestation_digest = digest_of(seed);
        observation.claims = proved_claims();
        observation.height = height;
        observation.state_reference = digest_of(0xC0);
        return sign_observation(observation, observer.identity);
    }

    [[nodiscard]] EligibilityObservation participation(const Node& observer,
                                                        const NodeId& subject, Height height,
                                                        IncarnationId incarnation = 1) const {
        EligibilityObservation observation;
        observation.network_id = network();
        observation.epoch = kEpoch;
        observation.subject = subject;
        observation.subject_incarnation = incarnation;
        observation.kind = ObservationKind::Participation;
        observation.height = height;
        observation.state_reference = digest_of(0xC0);
        return sign_observation(observation, observer.identity);
    }

    /// Every online member states both facts about `subject`.
    void observe(EligibilityLedger& ledger, const NodeId& subject, std::size_t online,
                 Height base, IncarnationId incarnation = 1) const {
        for (std::size_t i = 0; i < online; ++i) {
            if (nodes[i].id == subject) continue;
            for (uint8_t round = 0; round < constants::kMinContinuityObservations; ++round) {
                (void)ledger.record(attestation(nodes[i], subject,
                                                static_cast<uint8_t>(0x20 + round),
                                                base + round, incarnation),
                                    context);
            }
            (void)ledger.record(
                participation(nodes[i], subject, base + constants::kMinContinuityObservations,
                              incarnation),
                context);
        }
    }

    std::vector<Node> nodes;
    Node candidate;
    MeshFactContext context;
};

struct Row {
    std::size_t members{};
    std::size_t faults{};
    std::size_t quorum{};
    std::size_t member_bar{};
    std::size_t candidate_bar{};
    // Whether each fact still forms with 0, 1, f and f+1 members offline.
    bool member_all_online{};
    bool member_one_offline{};
    bool member_f_offline{};
    bool member_f_plus_one_offline{};
    bool candidate_all_online{};
    bool candidate_f_offline{};
    bool candidate_f_plus_one_offline{};
    // Scenario outcomes at this population.
    bool survives_attestation_expiry{};
    bool survives_participation_loss{};
    bool survives_candidate_restart{};
    bool survives_objective_fault{};
};

/// True when the subject holds both mesh facts with `online` members observing.
bool facts_hold(const Mesh& mesh, const NodeId& subject, std::size_t online,
                IncarnationId incarnation = 1) {
    EligibilityLedger ledger;
    mesh.observe(ledger, subject, online, 100, incarnation);
    const auto evidence = ledger.evaluate(subject, incarnation, mesh.context);
    return evidence.uptime_valid && evidence.mesh_health_valid;
}

Row measure(std::size_t members) {
    Mesh mesh{members};
    Row row;
    row.members = members;
    row.faults = constants::max_byzantine_faults(members);
    row.quorum = constants::consensus_quorum(members);
    row.member_bar = witness_threshold(mesh.context, mesh.nodes.front().id);
    row.candidate_bar = witness_threshold(mesh.context, mesh.candidate.id);

    const NodeId member = mesh.nodes.front().id;
    // The subject is nodes[0], so "online" counts from the front and always
    // includes it; the witnesses are the online members other than the subject.
    row.member_all_online = facts_hold(mesh, member, members);
    row.member_one_offline = facts_hold(mesh, member, members - 1);
    row.member_f_offline = facts_hold(mesh, member, members - row.faults);
    row.member_f_plus_one_offline =
        row.faults + 1 < members && facts_hold(mesh, member, members - row.faults - 1);

    // The candidate is not one of the members, so every online member can
    // witness it: it needs the full quorum and exactly the quorum remains.
    row.candidate_all_online = facts_hold(mesh, mesh.candidate.id, members);
    row.candidate_f_offline = facts_hold(mesh, mesh.candidate.id, members - row.faults);
    row.candidate_f_plus_one_offline =
        row.faults + 1 < members && facts_hold(mesh, mesh.candidate.id, members - row.faults - 1);

    // Attestation expiry: observations belong to an epoch and are dropped at
    // the boundary, so nothing carries into the next one.
    {
        EligibilityLedger ledger;
        mesh.observe(ledger, member, members, 100);
        ledger.expire_before(kEpoch + 1);
        row.survives_attestation_expiry =
            ledger.evaluate(member, 1, mesh.context).uptime_valid;
    }
    // Participation loss: continuity alone is not health.
    {
        EligibilityLedger ledger;
        for (std::size_t i = 0; i < members; ++i) {
            if (mesh.nodes[i].id == member) continue;
            for (uint8_t round = 0; round < constants::kMinContinuityObservations; ++round) {
                (void)ledger.record(mesh.attestation(mesh.nodes[i], member,
                                                     static_cast<uint8_t>(0x30 + round),
                                                     200 + round),
                                    mesh.context);
            }
        }
        const auto evidence = ledger.evaluate(member, 1, mesh.context);
        row.survives_participation_loss = evidence.mesh_health_valid;
    }
    // Candidate restart: a new incarnation is a different live node, so
    // continuity starts again rather than carrying over.
    {
        EligibilityLedger ledger;
        mesh.observe(ledger, member, members, 100, 1);
        mesh.observe(ledger, member, members, 300, 2);
        row.survives_candidate_restart = ledger.evaluate(member, 1, mesh.context).uptime_valid;
    }
    // Objective fault: proved misbehavior denies health outright.
    {
        EligibilityLedger ledger;
        mesh.observe(ledger, member, members, 100);
        ledger.record_fault(member, ObjectiveFault::Equivocation);
        row.survives_objective_fault =
            ledger.evaluate(member, 1, mesh.context).mesh_health_valid;
    }
    return row;
}

const char* yes_no(bool value) { return value ? "yes" : "no"; }

void print_table(const std::vector<Row>& rows) {
    std::printf(
        "\n  N   f   Q  memBar  candBar | member facts: all  -1   -f  -(f+1) | "
        "candidate: all   -f  -(f+1) | expiry  partLoss  restart  fault\n");
    for (const auto& r : rows) {
        std::printf(
            "%3zu %3zu %3zu %7zu %8zu | %16s %4s %4s %7s | %13s %4s %7s | %6s %9s %8s %6s\n",
                    r.members, r.faults, r.quorum, r.member_bar, r.candidate_bar,
                    yes_no(r.member_all_online), yes_no(r.member_one_offline),
                    yes_no(r.member_f_offline), yes_no(r.member_f_plus_one_offline),
                    yes_no(r.candidate_all_online), yes_no(r.candidate_f_offline),
                    yes_no(r.candidate_f_plus_one_offline),
                    yes_no(r.survives_attestation_expiry),
                    yes_no(r.survives_participation_loss),
                    yes_no(r.survives_candidate_restart), yes_no(r.survives_objective_fault));
    }
    std::printf("\n");
}

}  // namespace

// The measurement run. Every assertion is an invariant; the liveness columns
// are recorded rather than compared against a tuned value.
TEST(EligibilityScale, MeasureAcrossTheTierOneTable) {
    ASSERT_GE(sodium_init(), 0);
    std::vector<Row> rows;
    for (const std::size_t members : kPopulations) {
        rows.push_back(measure(members));
    }
    print_table(rows);

    for (const auto& r : rows) {
        // The bar is never something the Byzantine set alone could reach.
        EXPECT_GT(r.member_bar, r.faults) << r.members;
        EXPECT_GT(r.candidate_bar, r.faults) << r.members;

        // A member is excluded from its own committee; a candidate is not part
        // of it and gets no discount.
        EXPECT_EQ(r.member_bar, r.quorum - 1) << r.members;
        EXPECT_EQ(r.candidate_bar, r.quorum) << r.members;

        // Liveness: a member stays provable while the mesh has its consensus
        // quorum, which is what the whole rule exists for.
        EXPECT_TRUE(r.member_all_online) << r.members;
        EXPECT_TRUE(r.member_one_offline) << r.members;
        EXPECT_TRUE(r.member_f_offline) << r.members;
        EXPECT_TRUE(r.candidate_all_online) << r.members;
        // A candidate needs the full quorum, but it is not one of the members
        // spending a witness on itself, so the quorum that remains is exactly
        // enough. Both kinds of subject stay provable while consensus has its
        // quorum, which is the property the rule was fixed to give.
        EXPECT_TRUE(r.candidate_f_offline) << r.members;

        // Safety: below the quorum nothing forms. Liveness is unavailable and
        // the mesh simply does not rotate.
        EXPECT_FALSE(r.member_f_plus_one_offline) << r.members;
        EXPECT_FALSE(r.candidate_f_plus_one_offline) << r.members;

        // Every fact expires, is separate from the other, restarts with a new
        // incarnation, and is denied outright by proved misbehavior.
        EXPECT_FALSE(r.survives_attestation_expiry) << r.members;
        EXPECT_FALSE(r.survives_participation_loss) << r.members;
        EXPECT_FALSE(r.survives_candidate_restart) << r.members;
        EXPECT_FALSE(r.survives_objective_fault) << r.members;
    }
}

// N = 5 is the tightest population and the one the rule was fixed for: four
// members must remain provable, and three must not.
TEST(EligibilityScale, FiveIsTheTightCase) {
    ASSERT_GE(sodium_init(), 0);
    Mesh mesh{5};
    const NodeId member = mesh.nodes.front().id;
    EXPECT_EQ(witness_threshold(mesh.context, member), 3u);
    EXPECT_EQ(witness_threshold(mesh.context, mesh.candidate.id), 4u);

    EXPECT_TRUE(facts_hold(mesh, member, 5)) << "all five";
    EXPECT_TRUE(facts_hold(mesh, member, 4)) << "one offline, still a HotStuff quorum";
    EXPECT_FALSE(facts_hold(mesh, member, 3)) << "two offline, below quorum";

    // The candidate needs all four remaining members rather than three,
    // because it spends no witness on itself. Same boundary, different reason.
    EXPECT_TRUE(facts_hold(mesh, mesh.candidate.id, 5));
    EXPECT_TRUE(facts_hold(mesh, mesh.candidate.id, 4)) << "one offline";
    EXPECT_FALSE(facts_hold(mesh, mesh.candidate.id, 3)) << "two offline";
}

// An observer restart cannot replay its old statements: height is monotonic per
// observer and subject, so a rewind buys nothing at any population.
TEST(EligibilityScale, AnObserverRestartReplaysNothing) {
    ASSERT_GE(sodium_init(), 0);
    for (const std::size_t members : kPopulations) {
        Mesh mesh{members};
        EligibilityLedger ledger;
        const NodeId subject = mesh.nodes.back().id;
        ASSERT_EQ(ledger.record(mesh.attestation(mesh.nodes[0], subject, 0x41, 900), mesh.context),
                  ObservationOutcome::Accepted)
            << members;
        EXPECT_EQ(ledger.record(mesh.attestation(mesh.nodes[0], subject, 0x42, 900), mesh.context),
                  ObservationOutcome::NotNewerThanHeld)
            << members;
        EXPECT_EQ(ledger.record(mesh.attestation(mesh.nodes[0], subject, 0x42, 500), mesh.context),
                  ObservationOutcome::NotNewerThanHeld)
            << members;
        EXPECT_EQ(ledger.record(mesh.attestation(mesh.nodes[0], subject, 0x42, 901), mesh.context),
                  ObservationOutcome::Accepted)
            << members;
    }
}
