// The authority chain across the whole Tier 1 population table.
//
// One chain climbs every table step — 5, 7, 10, ... 31 — with real keys and
// real three-chain proofs at every link, so growth, shrink, and page limits
// are exercised at every population the protocol can produce. Assertions are
// invariants: the genuine chain walks, every broken input is refused by name
// (expected fail-closed), a stale page merely fails to advance (liveness,
// never authority), and no forged input ever advances anything (safety).

#include <LemonadeNexus/Security/Epoch/AuthorityChain.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstdio>
#include <memory>
#include <vector>

#include "support/committee.hpp"

using namespace nexus::security;
using committee_test::Committee;
namespace constants = nexus::security::constants;

namespace {

constexpr std::size_t kTable[] = {5, 7, 10, 13, 16, 19, 22, 25, 28, 31};

NetworkId chain_network() {
    NetworkId id{};
    id.fill(0xC4);
    return id;
}

struct ChainFixture {
    nexus::crypto::Ed25519Keypair genesis{};
    BootstrapCertificate certificate;
    std::vector<std::unique_ptr<Committee>> committees;  // committees[i] runs epoch i+1
    std::vector<EpochHandoffProofMsg> links;             // links[i]: epoch i+1 -> i+2
    VerifiedEpochAuthority base;

    ChainFixture() {
        crypto_sign_keypair(genesis.public_key.data(), genesis.private_key.data());
        for (std::size_t i = 0; i < std::size(kTable); ++i) {
            committees.push_back(std::make_unique<Committee>(
                kTable[i], static_cast<EpochId>(i + 1), chain_network(),
                static_cast<uint8_t>(1 + 40 * i)));
        }

        const Committee& founders = *committees.front();
        certificate.network_id = chain_network();
        certificate.epoch = 1;
        certificate.tier1_set_digest = Tier1Set::from_nodes(founders.members)->digest();
        certificate.authority_threshold = constants::authority_threshold(founders.members.size());
        certificate.authority_public_key.fill(0x91);
        certificate.dkg_transcript_digest.fill(0xD1);
        certificate.attestation_root.fill(0xA1);
        certificate.founding_eligibility_digest.fill(0xE1);
        std::map<NodeId, nexus::crypto::Ed25519PublicKey> keys;
        for (const auto& node : founders.members) keys[node] = founders.pubs.at(node);
        certificate.vote_key_set_digest = vote_key_set_digest(keys);
        certificate.security_ruleset = constants::kSecurityRulesetVersion;
        certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
        const Digest digest = bootstrap_certificate_signing_digest(certificate);
        crypto_sign_detached(certificate.genesis_signature.data(), nullptr, digest.data(),
                             digest.size(), genesis.private_key.data());

        std::vector<std::pair<NodeId, nexus::crypto::Ed25519PublicKey>> listing;
        for (const auto& node : founders.members) {
            listing.emplace_back(node, founders.pubs.at(node));
        }
        base = *verify_epoch_one_authority(certificate, genesis.public_key, listing);

        Digest previous_anchor = base.anchor_digest;
        for (std::size_t i = 0; i + 1 < committees.size(); ++i) {
            const Committee& from = *committees[i];
            const Committee& to = *committees[i + 1];
            EpochHandoff handoff;
            handoff.network_id = chain_network();
            handoff.from_epoch = from.epoch;
            handoff.to_epoch = to.epoch;
            handoff.plan_digest.fill(static_cast<uint8_t>(0x30 + i));
            handoff.previous_anchor = previous_anchor;
            handoff.members = to.members;
            for (const auto& node : to.members) {
                handoff.incarnations[node] = 1;
                handoff.vote_keys[node] = to.pubs.at(node);
            }
            handoff.group_public_key.fill(static_cast<uint8_t>(0x90 + i));
            handoff.dkg_transcript_digest.fill(static_cast<uint8_t>(0xD0 + i));
            handoff.key_generation = to.epoch;
            handoff.attestation_root.fill(static_cast<uint8_t>(0xA0 + i));
            handoff.security_ruleset = constants::kSecurityRulesetVersion;
            handoff.consensus_ruleset = constants::kConsensusRulesetVersion;
            const CommitProof proof = from.prove(epoch_handoff_digest(handoff));
            links.push_back({handoff, proof});
            previous_anchor = epoch_handoff_digest(handoff);
        }
    }
};

std::size_t page_wire_size(const AuthorityChainPage& page, const NodeId& sender) {
    SecurityMessage message;
    message.kind = SecurityMessageKind::AuthorityChainPage;
    message.security_ruleset = constants::kSecurityRulesetVersion;
    message.consensus_ruleset = constants::kConsensusRulesetVersion;
    message.network_id = chain_network();
    message.epoch = 1;
    message.sender = sender;
    message.body = page;
    return encode_security_message(message).size();
}

}  // namespace

// The genuine chain walks every table step, and every page a serving node
// could build stays inside the envelope bound.
TEST(ChainScale, TheChainClimbsTheWholeTableInBoundedPages) {
    ASSERT_GE(sodium_init(), 0);
    ChainFixture fixture;

    std::printf("\n  epoch    N -> N'    page B\n");
    VerifiedEpochAuthority authority = fixture.base;
    std::size_t walked = 0;
    for (std::size_t i = 0; i < fixture.links.size(); i += constants::kMaxHandoffChainLinks) {
        AuthorityChainPage page;
        if (i == 0) {
            page.has_base = true;
            page.base_certificate = fixture.certificate;
            for (const auto& node : fixture.committees.front()->members) {
                page.base_vote_keys.emplace_back(node,
                                                 fixture.committees.front()->pubs.at(node));
            }
        }
        for (std::size_t j = i;
             j < fixture.links.size() && j < i + constants::kMaxHandoffChainLinks; ++j) {
            page.links.push_back(fixture.links[j]);
        }
        const std::size_t bytes =
            page_wire_size(page, fixture.committees.front()->members.front());
        ASSERT_GT(bytes, 0u);
        ASSERT_LE(bytes, constants::kMaxSecurityMessageBytes);

        for (const auto& link : page.links) {
            const auto advanced = advance_epoch_authority(authority, link.handoff, link.proof);
            const auto* next = std::get_if<VerifiedEpochAuthority>(&advanced);
            ASSERT_NE(next, nullptr) << "genuine link refused at epoch " << authority.epoch;
            std::printf("  %5llu %4zu -> %-4zu %9zu\n",
                        (unsigned long long)link.handoff.from_epoch,
                        authority.members.size(), next->members.size(), bytes);
            authority = *next;
            ++walked;
        }
    }
    std::printf("\n");
    EXPECT_EQ(walked, fixture.links.size());
    EXPECT_EQ(authority.epoch, fixture.committees.size());
    EXPECT_EQ(authority.members.size(), kTable[std::size(kTable) - 1]);
    EXPECT_EQ(authority.consensus_quorum, constants::consensus_quorum(31));
}

// Hostile chain input at every population: each break is refused by name
// (expected fail-closed), and no mutation ever advances the walk (safety).
// A page holding only history the walker already has advances nothing and
// costs nothing but the read (liveness only).
TEST(ChainScale, EveryBrokenLinkFailsClosedAtEveryStep) {
    ASSERT_GE(sodium_init(), 0);
    ChainFixture fixture;

    VerifiedEpochAuthority authority = fixture.base;
    for (const auto& link : fixture.links) {
        const auto refusal = [&](const EpochHandoff& handoff,
                                 const CommitProof& proof) -> HandoffChainFailure {
            const auto result = advance_epoch_authority(authority, handoff, proof);
            const auto* failure = std::get_if<HandoffChainFailure>(&result);
            return failure != nullptr ? *failure : HandoffChainFailure::None;
        };

        // A fork: same transition, different content.
        auto forked = link.handoff;
        forked.group_public_key[0] ^= 0x01;
        EXPECT_EQ(refusal(forked, link.proof), HandoffChainFailure::ProofInvalid);

        // A gap or reorder: any link that is not the exact next transition.
        auto skipped = link.handoff;
        skipped.from_epoch += 1;
        skipped.to_epoch += 1;
        EXPECT_EQ(refusal(skipped, link.proof), HandoffChainFailure::WrongEpochs);

        // Broken predecessor linkage.
        auto unchained = link.handoff;
        unchained.previous_anchor[0] ^= 0x01;
        EXPECT_EQ(refusal(unchained, link.proof), HandoffChainFailure::LinkageBroken);

        // A trimmed quorum on an otherwise genuine link.
        auto trimmed = link.proof;
        trimmed.certifying.signers.pop_back();
        EXPECT_EQ(refusal(link.handoff, trimmed), HandoffChainFailure::ProofInvalid);

        // A stale link (the one just consumed) is a reorder, not a rewind.
        const auto advanced = advance_epoch_authority(authority, link.handoff, link.proof);
        const auto* next = std::get_if<VerifiedEpochAuthority>(&advanced);
        ASSERT_NE(next, nullptr);
        EXPECT_EQ(refusal(link.handoff, link.proof), HandoffChainFailure::None)
            << "consuming a link must not mutate the held authority";
        authority = *next;
        const auto replay = advance_epoch_authority(authority, link.handoff, link.proof);
        const auto* replay_failure = std::get_if<HandoffChainFailure>(&replay);
        ASSERT_NE(replay_failure, nullptr);
        EXPECT_EQ(*replay_failure, HandoffChainFailure::WrongEpochs);
    }
}
