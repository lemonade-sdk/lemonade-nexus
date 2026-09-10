#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Consensus/Quorum.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>

namespace constants = nexus::security::constants;
using nexus::security::Digest;
using nexus::security::NodeId;
using nexus::security::Proposal;
using nexus::security::QcSigner;
using nexus::security::QuorumCertificate;
using nexus::security::TimeoutCertificate;
using nexus::security::TimeoutSigner;
using nexus::security::TimeoutVote;
using nexus::security::Vote;

namespace {

[[nodiscard]] Digest filled_digest(uint8_t value) {
    Digest digest{};
    digest.fill(value);
    return digest;
}

[[nodiscard]] NodeId filled_node(uint8_t value) {
    NodeId node{};
    node.bytes.fill(value);
    return node;
}

[[nodiscard]] Proposal base_proposal() {
    Proposal proposal{};
    proposal.security_ruleset = constants::kSecurityRulesetVersion;
    proposal.consensus_ruleset = constants::kConsensusRulesetVersion;
    proposal.network_id = filled_digest(0x01);
    proposal.epoch = 7;
    proposal.height = 100;
    proposal.view = 12;
    proposal.leader = filled_node(0x02);
    proposal.parent_digest = filled_digest(0x03);
    proposal.justify_qc_digest = filled_digest(0x04);
    proposal.previous_state_root = filled_digest(0x05);
    proposal.proposed_state_root = filled_digest(0x06);
    proposal.transitions_digest = filled_digest(0x07);
    proposal.timestamp_hint = 1724400000;
    return proposal;
}

TEST(ConsensusTypes, ProposalDigestIsDeterministic) {
    EXPECT_EQ(nexus::security::proposal_digest(base_proposal()),
              nexus::security::proposal_digest(base_proposal()));
}

TEST(ConsensusTypes, ProposalDigestSensitiveToEveryField) {
    struct FieldMutation {
        const char* name;
        void (*mutate)(Proposal&);
    };
    // One mutation per declared field; every one must change the digest.
    const FieldMutation mutations[] = {
        {"security_ruleset", [](Proposal& p) { p.security_ruleset += 1; }},
        {"consensus_ruleset", [](Proposal& p) { p.consensus_ruleset += 1; }},
        {"network_id", [](Proposal& p) { p.network_id[0] ^= 0xFF; }},
        {"epoch", [](Proposal& p) { p.epoch += 1; }},
        {"height", [](Proposal& p) { p.height += 1; }},
        {"view", [](Proposal& p) { p.view += 1; }},
        {"leader", [](Proposal& p) { p.leader.bytes[0] ^= 0xFF; }},
        {"parent_digest", [](Proposal& p) { p.parent_digest[0] ^= 0xFF; }},
        {"justify_qc_digest", [](Proposal& p) { p.justify_qc_digest[0] ^= 0xFF; }},
        {"previous_state_root", [](Proposal& p) { p.previous_state_root[0] ^= 0xFF; }},
        {"proposed_state_root", [](Proposal& p) { p.proposed_state_root[0] ^= 0xFF; }},
        {"transitions_digest", [](Proposal& p) { p.transitions_digest[0] ^= 0xFF; }},
        {"timestamp_hint", [](Proposal& p) { p.timestamp_hint += 1; }},
    };

    const Digest base = nexus::security::proposal_digest(base_proposal());
    for (const auto& mutation : mutations) {
        Proposal mutated = base_proposal();
        mutation.mutate(mutated);
        EXPECT_NE(nexus::security::proposal_digest(mutated), base) << mutation.name;
    }
}

TEST(ConsensusTypes, VoteOverloadMatchesExplicitArguments) {
    Vote vote{};
    vote.consensus_ruleset = constants::kConsensusRulesetVersion;
    vote.network_id = filled_digest(0x01);
    vote.epoch = 7;
    vote.height = 100;
    vote.view = 12;
    vote.proposal_digest = filled_digest(0x08);
    vote.voter = filled_node(0x09);

    EXPECT_EQ(nexus::security::vote_signing_digest(vote),
              nexus::security::vote_signing_digest(
                  vote.consensus_ruleset, vote.network_id, vote.epoch, vote.height,
                  vote.view, vote.proposal_digest, vote.voter));
}

TEST(ConsensusTypes, TimeoutVoteOverloadMatchesExplicitArguments) {
    TimeoutVote vote{};
    vote.consensus_ruleset = constants::kConsensusRulesetVersion;
    vote.network_id = filled_digest(0x01);
    vote.epoch = 7;
    vote.view = 12;
    vote.high_qc_digest = filled_digest(0x0A);
    vote.voter = filled_node(0x0B);

    EXPECT_EQ(nexus::security::timeout_vote_signing_digest(vote),
              nexus::security::timeout_vote_signing_digest(
                  vote.consensus_ruleset, vote.network_id, vote.epoch, vote.view,
                  vote.high_qc_digest, vote.voter));
}

TEST(ConsensusTypes, KindStringSeparatesMessageKinds) {
    // Overlapping field values must never collide across message kinds.
    const Proposal proposal = base_proposal();
    const Digest proposal_d = nexus::security::proposal_digest(proposal);

    const Digest vote_d = nexus::security::vote_signing_digest(
        proposal.consensus_ruleset, proposal.network_id, proposal.epoch,
        proposal.height, proposal.view, proposal.parent_digest, proposal.leader);

    const Digest timeout_d = nexus::security::timeout_vote_signing_digest(
        proposal.consensus_ruleset, proposal.network_id, proposal.epoch,
        proposal.view, proposal.parent_digest, proposal.leader);

    EXPECT_NE(vote_d, proposal_d);
    EXPECT_NE(timeout_d, proposal_d);
    EXPECT_NE(timeout_d, vote_d);
}

TEST(ConsensusTypes, QcDigestIndependentOfSignerOrder) {
    QuorumCertificate certificate{};
    certificate.qc_format_version = constants::kQcFormatVersion;
    certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
    certificate.network_id = filled_digest(0x01);
    certificate.epoch = 7;
    certificate.height = 100;
    certificate.view = 12;
    certificate.proposal_digest = filled_digest(0x08);
    for (uint8_t i = 1; i <= 4; ++i) {
        QcSigner signer{};
        signer.node_id = filled_node(i);
        signer.signature.fill(static_cast<uint8_t>(i + 0x40));
        certificate.signers.push_back(signer);
    }

    QuorumCertificate shuffled = certificate;
    std::reverse(shuffled.signers.begin(), shuffled.signers.end());
    EXPECT_EQ(nexus::security::qc_digest(certificate), nexus::security::qc_digest(shuffled));

    // The signer set is still part of the digest.
    QuorumCertificate fewer = certificate;
    fewer.signers.pop_back();
    EXPECT_NE(nexus::security::qc_digest(certificate), nexus::security::qc_digest(fewer));

    QuorumCertificate other_header = certificate;
    other_header.view += 1;
    EXPECT_NE(nexus::security::qc_digest(certificate),
              nexus::security::qc_digest(other_header));
}

TEST(ConsensusTypes, TimeoutCertificateDigestIndependentOfSignerOrder) {
    TimeoutCertificate certificate{};
    certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
    certificate.network_id = filled_digest(0x01);
    certificate.epoch = 7;
    certificate.view = 12;
    for (uint8_t i = 1; i <= 4; ++i) {
        TimeoutSigner signer{};
        signer.node_id = filled_node(i);
        signer.high_qc_digest = filled_digest(static_cast<uint8_t>(i + 0x20));
        signer.signature.fill(static_cast<uint8_t>(i + 0x40));
        certificate.signers.push_back(signer);
    }

    TimeoutCertificate shuffled = certificate;
    std::reverse(shuffled.signers.begin(), shuffled.signers.end());
    EXPECT_EQ(nexus::security::timeout_certificate_digest(certificate),
              nexus::security::timeout_certificate_digest(shuffled));

    TimeoutCertificate other_high_qc = certificate;
    other_high_qc.signers[0].high_qc_digest[0] ^= 0xFF;
    EXPECT_NE(nexus::security::timeout_certificate_digest(certificate),
              nexus::security::timeout_certificate_digest(other_high_qc));
}

TEST(ConsensusTypes, QuorumClassMirrorsCompiledFormulas) {
    for (std::size_t n = 0; n <= 40; ++n) {
        EXPECT_EQ(nexus::security::Quorum::max_byzantine_faults(n),
                  constants::max_byzantine_faults(n));
        EXPECT_EQ(nexus::security::Quorum::consensus_quorum(n),
                  constants::consensus_quorum(n));
        EXPECT_EQ(nexus::security::Quorum::authority_threshold(n),
                  constants::authority_threshold(n));
    }
}

}  // namespace
